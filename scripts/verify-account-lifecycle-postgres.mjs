import assert from 'node:assert/strict';
import { spawn, execFile } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { promisify } from 'node:util';
import { setTimeout as delay } from 'node:timers/promises';
import test, { before, after } from 'node:test';

// Run only against an explicitly selected disposable, loopback PostgreSQL instance.
assert.equal(process.env.CONTEXT_RELAY_DISPOSABLE_POSTGRES, '1');
assert.ok(['127.0.0.1', '::1', 'localhost'].includes(process.env.PGHOST));
assert.ok(!process.env.PGHOSTADDR || ['127.0.0.1', '::1'].includes(process.env.PGHOSTADDR));
assert.ok(!process.env.PGSERVICE && !process.env.PGSERVICEFILE);
assert.ok(process.env.PGDATABASE);
const psql = process.env.CONTEXT_RELAY_PSQL ?? 'psql';
const args = ['-X', '-qAt', '-v', 'ON_ERROR_STOP=1'];
const run = promisify(execFile);
async function sql(query, application = 'context-relay-lifecycle-test') {
  const result = await run(psql, [...args, '-c', query], {
    env: { ...process.env, PGAPPNAME: application, PGOPTIONS: '-c statement_timeout=15000 -c lock_timeout=10000' },
    timeout: 20000, windowsHide: true,
  });
  return result.stdout.trim();
}
const id = () => randomUUID().replace(/^(.{14})./, (_, prefix) => `${prefix}7`);

// Supabase's postgres role is not a superuser. Fixture administration needs
// temporary owner membership; RPC assertions still explicitly SET ROLE service_role.
let fixtureAuthority = false;
let previousGrant;
before(async () => {
  previousGrant = JSON.parse(await sql(`select coalesce((select json_build_object(
    'admin', admin_option, 'inherit', inherit_option, 'set', set_option)
    from pg_auth_members where roleid='context_relay_rls_owner'::regrole
      and member=current_user::regrole and grantor=current_user::regrole), 'null'::json)`));
  await sql('grant context_relay_rls_owner to current_user with inherit true, set true granted by current_user');
  fixtureAuthority = true;
});
after(async () => {
  if (fixtureAuthority) await sql(previousGrant
    ? `grant context_relay_rls_owner to current_user with admin ${previousGrant.admin},
        inherit ${previousGrant.inherit}, set ${previousGrant.set} granted by current_user`
    : 'revoke context_relay_rls_owner from current_user granted by current_user');
});

async function fixture() {
  const user = randomUUID(), session = randomUUID(), account = id(), device = id(), workspace = id();
  await sql(`
    insert into auth.users (id) values ('${user}');
    insert into auth.sessions (id, user_id) values ('${session}', '${user}');
    insert into public.accounts (id, owner_user_id) values ('${account}', '${user}');
    insert into public.device_bindings (account_id, auth_user_id, session_id, device_id, state)
      values ('${account}', '${user}', '${session}', '${device}', 'active');
    insert into public.device_certificates (id, account_id, workspace_id, control_epoch, device_id,
      request_nonce, issuer_kind, issuer_recovery_public_key, issuer_signing_public_key,
      device_signing_public_key, device_wrapping_public_key, signature)
      values ('${id()}', '${account}', '${workspace}', 0, '${device}',
        decode(repeat('01',32),'hex'), 'recovery_root', decode(repeat('02',32),'hex'),
        decode(repeat('03',32),'hex'), decode(repeat('04',32),'hex'),
        decode(repeat('05',32),'hex'), decode(repeat('06',64),'hex'));`);
  const request = (action, requestId, credential = 'floor(extract(epoch from clock_timestamp()))::bigint') =>
    `set role service_role; select public.service_${action}_account_deletion_for_session(
      '${user}', '${session}', '${workspace}', ${credential}, decode('${requestId}', 'hex'));`;
  return {
    account, session, user, workspace, request,
    call: async (action, requestId) => JSON.parse(await sql(request(action, requestId))),
    state: () => sql(`select deletion_state from public.accounts where id='${account}'`),
    async cleanup() {
      await sql(`delete from public.accounts where id='${account}';
        delete from auth.sessions where id='${session}'; delete from auth.users where id='${user}';`);
    },
  };
}

async function holdLock(query) {
  const child = spawn(psql, args, { env: process.env, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
  let output = '', error = '';
  child.stdout.on('data', chunk => { output += chunk; });
  child.stderr.on('data', chunk => { error += chunk; });
  const finished = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('exit', code => code === 0 ? resolve() : reject(new Error(error || `psql exited ${code}`)));
  });
  // Attach immediately so a startup failure cannot become an unhandled rejection.
  finished.catch(() => {});
  child.stdin.write(`begin; set local idle_in_transaction_session_timeout='20s'; ${query}; select 'lock-held';\n`);
  const deadline = Date.now() + 10000;
  while (!output.includes('lock-held')) {
    if (child.exitCode !== null || Date.now() > deadline) {
      child.kill();
      await finished.catch(() => {});
      throw new Error(error || 'Lock holder did not become ready');
    }
    await delay(20);
  }
  return async () => { child.stdin.end('commit;\n'); await finished; };
}

async function waitUntilBlocked(application) {
  const deadline = Date.now() + 7000;
  while (Date.now() < deadline) {
    if (await sql(`select exists(select 1 from pg_stat_activity
      where application_name='${application}' and wait_event_type='Lock')`) === 't') return;
    await delay(20);
  }
  throw new Error('Lifecycle request did not reach the expected lock');
}

for (const [first, second, expected] of [['begin', 'cancel', 'active'], ['cancel', 'begin', 'pending_delete']]) {
  test(`replayed ${first} preserves the later ${second} and returns current state`, async () => {
    const f = await fixture();
    try {
      if (first === 'cancel') await f.call('begin', '00'.repeat(32));
      await f.call(first, '01'.repeat(32));
      await f.call(second, '02'.repeat(32));
      assert.equal((await f.call(first, '01'.repeat(32))).state, expected);
      assert.equal(await f.state(), expected);
    } finally { await f.cleanup(); }
  });
}

test('stale credentials, foreign workspaces and deleted sessions cannot mutate an account', async () => {
  const f = await fixture();
  try {
    await assert.rejects(sql(f.request('begin', '04'.repeat(32),
      'floor(extract(epoch from clock_timestamp()))::bigint - 301')), /fresh_auth_required/);
    await assert.rejects(sql(f.request('begin', '04'.repeat(32)).replace(f.workspace, id())), /revoked/);
    await sql(`delete from auth.sessions where id='${f.session}'`);
    await assert.rejects(f.call('begin', '04'.repeat(32)), /revoked/);
    assert.equal(await f.state(), 'active');
    assert.equal(await sql(`select count(*) from context_relay_private.account_lifecycle_receipts
      where account_id='${f.account}'`), '0');
  } finally { await f.cleanup(); }
});

test('a receipt cannot authorize the opposite action and legacy service calls are denied', async () => {
  const f = await fixture();
  try {
    await f.call('begin', '05'.repeat(32));
    await assert.rejects(f.call('cancel', '05'.repeat(32)), /conflict/);
    for (const action of ['begin', 'cancel']) {
      await assert.rejects(sql(`set role service_role;
        select public.service_${action}_account_deletion('${f.account}');`), /permission denied/);
    }
    assert.equal(await f.state(), 'pending_delete');
  } finally { await f.cleanup(); }
});

test('stale control epochs are rejected and the request budget rolls back refused mutations', async () => {
  const f = await fixture();
  try {
    await sql(`update public.accounts set control_epoch=1 where id='${f.account}'`);
    await assert.rejects(f.call('begin', '06'.repeat(32)), /revoked/);
    await sql(`update public.accounts set control_epoch=0 where id='${f.account}';
      insert into context_relay_private.account_lifecycle_rate_limits
        values ('${f.account}', clock_timestamp(), 30);`);
    await assert.rejects(f.call('begin', '06'.repeat(32)), /rate_limited/);
    assert.equal(await f.state(), 'active');
    assert.equal(await sql(`select count(*) from context_relay_private.account_lifecycle_receipts
      where account_id='${f.account}'`), '0');
  } finally { await f.cleanup(); }
});

for (const authority of ['binding', 'auth_session']) for (const lock of ['account', 'auth_session']) {
  test(`${authority} expiry is rechecked after waiting on the ${lock} lock`, async () => {
    const f = await fixture();
    let release;
    let outcome;
    try {
      const table = authority === 'binding' ? 'public.device_bindings' : 'auth.sessions';
      const expiry = authority === 'binding' ? 'expires_at' : 'not_after';
      const where = authority === 'binding' ? `account_id='${f.account}'` : `id='${f.session}'`;
      await sql(`update ${table} set ${expiry}=clock_timestamp()+interval '2 seconds' where ${where}`);
      release = await holdLock(lock === 'account'
        ? `select id from public.accounts where id='${f.account}' for update`
        : `select id from auth.sessions where id='${f.session}' for update`);
      const application = `lifecycle-wait-${randomUUID()}`;
      outcome = sql(f.request('begin', '03'.repeat(32)), application)
        .then(value => ({ value }), error => ({ error }));
      await waitUntilBlocked(application);
      await sql(`select pg_sleep(greatest(0, extract(epoch from ${expiry}-clock_timestamp())+0.1))
        from ${table} where ${where}`);
      await release(); release = null;
      const result = await outcome;
      assert.ok(result.error, `Expired authority was accepted: ${result.value}`);
      assert.match(result.error.stderr, /revoked/);
      assert.equal(await f.state(), 'active');
      assert.equal(await sql(`select count(*) from context_relay_private.account_lifecycle_receipts
        where account_id='${f.account}'`), '0');
    } finally {
      if (release) await release();
      if (outcome) await outcome;
      await f.cleanup();
    }
  });
}

test('credential freshness is rechecked after an account lock wait', async () => {
  const f = await fixture();
  let release, outcome;
  try {
    const authenticatedAt = await sql('select floor(extract(epoch from clock_timestamp()))::bigint - 299');
    release = await holdLock(`select id from public.accounts where id='${f.account}' for update`);
    const application = `lifecycle-wait-${randomUUID()}`;
    outcome = sql(f.request('begin', '07'.repeat(32), authenticatedAt), application)
      .then(value => ({ value }), error => ({ error }));
    await waitUntilBlocked(application);
    await sql(`select pg_sleep(greatest(0, ${authenticatedAt} + 301.1 - extract(epoch from clock_timestamp())))`);
    await release(); release = null;
    const result = await outcome;
    assert.ok(result.error, `Stale credentials were accepted: ${result.value}`);
    assert.match(result.error.stderr, /fresh_auth_required/);
    assert.equal(await f.state(), 'active');
  } finally {
    if (release) await release();
    if (outcome) await outcome;
    await f.cleanup();
  }
});
