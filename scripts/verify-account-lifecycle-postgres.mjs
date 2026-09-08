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

async function enrollmentFixture() {
  const user = randomUUID(), session = randomUUID(), operation = id();
  await sql(`insert into auth.users(id) values ('${user}');
    insert into auth.sessions(id,user_id) values ('${session}','${user}');`);
  const request = (reservation = operation) => `set role service_role;
    select public.service_reserve_enrollment_for_session('${user}','${session}',
      '${reservation}','${id()}','${id()}',decode(repeat('42',32),'hex'));`;
  return { user, session, request,
    cleanup: () => sql(`delete from public.accounts where owner_user_id='${user}';
      delete from auth.sessions where id='${session}';
      delete from auth.users where id='${user}';`) };
}

// Synthetic decoded fields exercise the SQL transaction, not Edge cryptography.
function enrollmentCommit(f, reservation, certificate = id()) {
  return `set role service_role; select public.service_commit_enrollment_for_session(
    '${f.user}','${f.session}','${reservation.reservationId}',decode('${reservation.nonce}','hex'),
    '${reservation.accountId}','${reservation.workspaceId}','${id()}','${id()}','${certificate}','${id()}',
    decode(repeat('43',32),'hex'),decode(repeat('44',32),'hex'),decode(repeat('45',32),'hex'),
    decode(repeat('46',32),'hex'),decode(repeat('47',32),'hex'),decode(repeat('48',64),'hex'),
    decode(repeat('49',80),'hex'),decode('010203','hex'));`;
}

async function pairingDecisionFixture() {
  const f = await enrollmentFixture(), joining = randomUUID(), pairing = id(), child = id(), certificate = id();
  const reservation = JSON.parse(await sql(f.request()));
  await sql(enrollmentCommit(f, reservation));
  const device = await sql(`select device_id from public.device_bindings where session_id='${f.session}'`);
  await sql(`set role service_role; select public.service_create_pairing_invite('${f.user}','${f.session}',
    '${reservation.workspaceId}','${device}','${pairing}',decode(repeat('42',32),'hex'));`);
  await sql(`insert into auth.sessions(id,user_id) values ('${joining}','${f.user}')`);
  await sql(`set role service_role; select public.service_resolve_pairing_code('${f.user}','${joining}',decode(repeat('42',32),'hex'));`);
  const receipt = JSON.parse(await sql(`set role service_role; select public.service_submit_pairing_request('${f.user}','${joining}','${pairing}',
    decode('010203','hex'),decode(repeat('51',32),'hex'),decode(repeat('52',32),'hex'));`));
  const decide = (action = 'approve', payload = '040506') => `set role service_role; select public.service_decide_pairing_request(
    '${f.user}','${f.session}','${reservation.workspaceId}','${device}','${pairing}',decode('${receipt.requestDigest}','hex'),
    '${action}',1,1,${action === 'approve' ? `decode('${payload}','hex'),'${certificate}','${child}',decode(repeat('53',32),'hex'),decode(repeat('54',64),'hex')` : 'null,null,null,null,null'});`;
  return { ...f, joining, pairing, child, certificate, reservation, decide,
    result: `set role service_role; select public.service_pairing_result_for_session('${f.user}','${joining}','${pairing}',decode('${receipt.requestDigest}','hex'));`,
    cleanup: async () => { await sql(`delete from auth.sessions where id='${joining}'`); await f.cleanup(); } };
}

for (const action of ['approve','reject']) test(`pairing ${action} commits one durable decision without reactivating trust`, async () => {
  const f = await pairingDecisionFixture();
  try {
    assert.deepEqual(JSON.parse(await sql(f.result)), { status: 'pending' });
    await assert.rejects(sql(f.decide(action).replace(',1,1,', ',2,1,')), /pairing_conflict/);
    await assert.rejects(sql(f.decide(action).replace(f.session, f.joining)), /pairing_denied/);
    const receipt = JSON.parse(await sql(f.decide(action)));
    assert.equal(receipt.decision, action === 'approve' ? 'approved' : 'rejected');
    assert.deepEqual(JSON.parse(await sql(f.decide(action))), receipt);
    assert.equal(await sql(`select count(*) from public.device_bindings where session_id='${f.joining}'`), action === 'approve' ? '1' : '0');
    const result = JSON.parse(await sql(f.result));
    assert.equal(result.status, receipt.decision);
    assert.deepEqual(result.receipt, receipt);
    await sql(`update context_relay_private.pairing_invites set created_at=statement_timestamp()-interval '10 minutes',
      expires_at=statement_timestamp() where id='${f.pairing}'`);
    assert.deepEqual(JSON.parse(await sql(f.decide(action))), receipt);
    assert.deepEqual(JSON.parse(await sql(f.result)), result);
    if (action === 'approve') {
      assert.equal(result.canonicalApprovedPayload, '040506');
      await assert.rejects(sql(f.decide('approve','040507')), /pairing_conflict/);
      await sql(`update public.device_bindings set state='revoked',revoked_at=clock_timestamp(),cutoff_device_sequence=0,
        cutoff_hash=decode(repeat('00',32),'hex'),cutoff_signature=decode(repeat('00',64),'hex') where session_id='${f.joining}'`);
      assert.deepEqual(JSON.parse(await sql(f.decide(action))), receipt);
      assert.equal(await sql(`select state from public.device_bindings where session_id='${f.joining}'`), 'revoked');
    }
    await assert.rejects(sql(f.decide(action === 'approve' ? 'reject' : 'approve')), /pairing_conflict/);
    for (const role of ['anon','authenticated']) await assert.rejects(sql(f.decide(action).replace('set role service_role',`set role ${role}`)), /permission denied/);
    await assert.rejects(sql(f.result.replace(f.joining, f.session)), /pairing_denied/);
  } finally { await f.cleanup(); }
});

test('competing pairing decisions publish only one result', async () => {
  const f = await pairingDecisionFixture();
  try {
    const results = await Promise.allSettled([sql(f.decide('approve')), sql(f.decide('reject'))]);
    assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
    assert.match(results.find(result => result.status === 'rejected').reason.stderr, /pairing_conflict/);
    const receipt = JSON.parse(results.find(result => result.status === 'fulfilled').value);
    assert.deepEqual(JSON.parse(await sql(f.result)).receipt, receipt);
    assert.equal(await sql(`select count(*) from public.device_bindings where session_id='${f.joining}'`), receipt.decision === 'approved' ? '1' : '0');
  } finally { await f.cleanup(); }
});

test('pairing approval rolls back all writes after joining-session expiry during certificate insertion', async () => {
  const f = await pairingDecisionFixture(), other = await fixture();
  let release, outcome;
  try {
    await sql(`update public.device_certificates set id='${f.certificate}' where account_id='${other.account}';
      update auth.sessions set not_after=clock_timestamp()+interval '2 seconds' where id='${f.joining}'`);
    release = await holdLock(`delete from public.device_certificates where id='${f.certificate}'`);
    const application = `pairing-decision-${randomUUID()}`;
    outcome = sql(f.decide(), application).then(value => ({ value }), error => ({ error }));
    await waitUntilBlocked(application);
    await sql(`select pg_sleep(greatest(0,extract(epoch from not_after-clock_timestamp())+0.1)) from auth.sessions where id='${f.joining}'`);
    await release(); release = null;
    assert.match((await outcome).error?.stderr ?? '', /pairing_denied/);
    assert.equal(await sql(`select count(*) from public.device_certificates where id='${f.certificate}'`), '0');
    assert.equal(await sql(`select count(*) from public.device_bindings where session_id='${f.joining}'`), '0');
    assert.equal(await sql(`select state='pending' and decision_receipt is null from context_relay_private.pairing_invites where id='${f.pairing}'`), 't');
    assert.equal(await sql(`select state='pending' and decided_at is null from public.pairing_requests where id='${f.pairing}'`), 't');
  } finally {
    if (release) await release();
    if (outcome) await outcome;
    await f.cleanup(); await other.cleanup();
  }
});

test('pairing requests retain exact bytes and original-session receipts without granting trust', async () => {
  const f = await enrollmentFixture(), joining = randomUUID();
  try {
    const reservation = JSON.parse(await sql(f.request()));
    await sql(enrollmentCommit(f, reservation));
    const device = await sql(`select device_id from public.device_bindings where session_id='${f.session}'`);
    const pairing = id();
    await sql(`set role service_role; select public.service_create_pairing_invite('${f.user}','${f.session}',
      '${reservation.workspaceId}','${device}','${pairing}',decode(repeat('42',32),'hex'));`);
    await sql(`insert into auth.sessions(id,user_id) values ('${joining}','${f.user}')`);
    const fetch = `set role service_role; select public.service_pairing_request_for_approver('${f.user}','${f.session}',
      '${reservation.workspaceId}','${device}','${pairing}');`;
    assert.equal(JSON.parse(await sql(fetch)), null);
    // Synthetic decoded fields exercise SQL admission; Edge verifies canonical signatures/proofs.
    const submit = (payload = '010203', session = joining) => `set role service_role;
      select public.service_submit_pairing_request('${f.user}','${session}','${pairing}',decode('${payload}','hex'),
        decode(repeat('51',32),'hex'),decode(repeat('52',32),'hex'));`;
    await assert.rejects(sql(submit()), /pairing_denied/);
    await sql(`set role service_role; select public.service_resolve_pairing_code('${f.user}','${joining}',decode(repeat('42',32),'hex'));`);
    const results = await Promise.all([sql(submit()).then(JSON.parse), sql(submit()).then(JSON.parse)]);
    assert.deepEqual(results[0], results[1]);
    const receipt = results[0];
    assert.equal(receipt.pairingId, pairing);
    assert.equal(receipt.requestDigest, await sql(`select encode(sha256(decode('010203','hex')),'hex')`));
    const stored = JSON.parse(await sql(fetch));
    assert.deepEqual(stored, { ...receipt, canonicalRequest: '010203', accountId: reservation.accountId, workspaceId: reservation.workspaceId });
    await assert.rejects(sql(submit('010204')), /pairing_conflict/);
    await assert.rejects(sql(submit('010203', f.session)), /pairing_denied/);
    await assert.rejects(sql(submit('00'.repeat(8193))), /invalid_pairing_request/);
    await assert.rejects(sql(submit().replace("repeat('52'", "repeat('51'")), /invalid_pairing_request/);
    for (const role of ['anon','authenticated']) await assert.rejects(sql(submit().replace('set role service_role',`set role ${role}`)), /permission denied/);
    assert.equal(await sql(`select count(*) from public.device_bindings where session_id='${joining}'`), '0');
    await sql(`set role service_role; select public.service_control_pairing_invite('${f.user}','${f.session}',
      '${reservation.workspaceId}','${device}','${pairing}','cancel');`);
    assert.deepEqual(JSON.parse(await sql(submit())), receipt);
    await assert.rejects(sql(fetch), /pairing_canceled/);
    assert.equal(await sql(`select state from public.pairing_requests where id='${pairing}'`), 'cancelled');
  } finally {
    await sql(`delete from auth.sessions where id='${joining}'`);
    await f.cleanup();
  }
});

test('pairing request insertion rolls back when the joining session expires during a request-row wait', async () => {
  const f = await enrollmentFixture(), other = await fixture(), joining = randomUUID();
  let release, outcome;
  try {
    const reservation = JSON.parse(await sql(f.request()));
    await sql(enrollmentCommit(f, reservation));
    const device = await sql(`select device_id from public.device_bindings where session_id='${f.session}'`);
    const pairing = id();
    await sql(`set role service_role; select public.service_create_pairing_invite('${f.user}','${f.session}',
      '${reservation.workspaceId}','${device}','${pairing}',decode(repeat('42',32),'hex'));`);
    await sql(`insert into auth.sessions(id,user_id) values ('${joining}','${f.user}')`);
    await sql(`set role service_role; select public.service_resolve_pairing_code('${f.user}','${joining}',decode(repeat('42',32),'hex'));`);
    await sql(`insert into public.pairing_requests(id,account_id,workspace_id,request_payload,request_digest,
      requester_signing_public_key,requester_wrapping_public_key,code_digest,expires_at)
      values('${pairing}','${other.account}','${other.workspace}',decode('01','hex'),decode(repeat('00',32),'hex'),
        decode(repeat('51',32),'hex'),decode(repeat('52',32),'hex'),decode(repeat('00',32),'hex'),clock_timestamp()+interval '10 minutes');`);
    // A colliding legacy row cannot be read or canceled through another account's invite.
    assert.equal(JSON.parse(await sql(`set role service_role; select public.service_pairing_request_for_approver('${f.user}','${f.session}',
      '${reservation.workspaceId}','${device}','${pairing}');`)), null);
    await sql(`set role service_role; select public.service_control_pairing_invite('${f.user}','${f.session}',
      '${reservation.workspaceId}','${device}','${pairing}','cancel');`);
    assert.equal(await sql(`select state from public.pairing_requests where id='${pairing}'`), 'pending');
    await sql(`update context_relay_private.pairing_invites set state='pending' where id='${pairing}';
      update auth.sessions set not_after=clock_timestamp()+interval '2 seconds' where id='${joining}'`);
    release = await holdLock(`delete from public.pairing_requests where id='${pairing}'`);
    const application = `pairing-request-${randomUUID()}`;
    outcome = sql(`set role service_role; select public.service_submit_pairing_request('${f.user}','${joining}','${pairing}',
      decode('010203','hex'),decode(repeat('51',32),'hex'),decode(repeat('52',32),'hex'));`, application)
      .then(value => ({ value }), error => ({ error }));
    await waitUntilBlocked(application);
    await sql(`select pg_sleep(greatest(0,extract(epoch from not_after-clock_timestamp())+0.1)) from auth.sessions where id='${joining}'`);
    await release(); release = null;
    assert.match((await outcome).error?.stderr ?? '', /pairing_denied/);
    assert.equal(await sql(`select count(*) from public.pairing_requests where id='${pairing}'`), '0');
    assert.equal(await sql(`select count(*) from public.device_bindings where session_id='${joining}'`), '0');
  } finally {
    if (release) await release();
    if (outcome) await outcome;
    await sql(`delete from auth.sessions where id='${joining}'`);
    await f.cleanup(); await other.cleanup();
  }
});

test('pairing cancellation is final, owner-session-bound and survives its original expiry', async () => {
  const f = await enrollmentFixture(), joining = randomUUID();
  try {
    const reservation = JSON.parse(await sql(f.request()));
    await sql(enrollmentCommit(f, reservation));
    const device = await sql(`select device_id from public.device_bindings where session_id='${f.session}'`);
    const pairing = id();
    const invite = JSON.parse(await sql(`set role service_role; select public.service_create_pairing_invite('${f.user}','${f.session}',
      '${reservation.workspaceId}','${device}','${pairing}',decode(repeat('42',32),'hex'));`));
    const control = (action, session = f.session) => `set role service_role;
      select public.service_control_pairing_invite('${f.user}','${session}','${reservation.workspaceId}','${device}','${pairing}','${action}');`;
    await sql(`insert into auth.sessions(id,user_id) values ('${joining}','${f.user}')`);
    assert.deepEqual(JSON.parse(await sql(control('status'))), { ...invite, state: 'pending' });
    await assert.rejects(sql(control('cancel', joining)), /pairing_denied/);
    await assert.rejects(sql(control('approve')), /invalid_pairing_request/);
    const canceled = { ...invite, state: 'canceled' };
    assert.deepEqual(await Promise.all([sql(control('cancel')).then(JSON.parse), sql(control('cancel')).then(JSON.parse)]), [canceled, canceled]);
    assert.deepEqual(JSON.parse(await sql(control('status'))), canceled);
    const lookup = `set role service_role; select public.service_resolve_pairing_code('${f.user}','${joining}',decode(repeat('42',32),'hex'));`;
    assert.deepEqual(JSON.parse(await sql(lookup)), { status: 'canceled' });
    await sql(`update context_relay_private.pairing_invites set created_at=statement_timestamp()-interval '10 minutes',
      expires_at=statement_timestamp() where id='${pairing}'`);
    assert.equal(JSON.parse(await sql(control('cancel'))).state, 'canceled');
    assert.deepEqual(JSON.parse(await sql(lookup)), { status: 'canceled' });
    for (const role of ['anon','authenticated']) await assert.rejects(sql(control('status').replace('set role service_role', `set role ${role}`)), /permission denied/);
    await sql(`update context_relay_private.pairing_invites set state='pending' where id='${pairing}'`);
    await assert.rejects(sql(control('cancel')), /pairing_expired/);
    assert.equal(await sql(`select state from context_relay_private.pairing_invites where id='${pairing}'`), 'pending');
    // Synthetic terminal states check cancellation arbitration; approval admission is separate.
    for (const [state, error] of [['approved', /pairing_conflict/], ['rejected', /pairing_rejected/]]) {
      await sql(`update context_relay_private.pairing_invites set state='${state}' where id='${pairing}'`);
      await assert.rejects(sql(control('cancel')), error);
      assert.equal(JSON.parse(await sql(control('status'))).state, state);
    }
    await sql(`update public.recovery_roots set revoked_at=clock_timestamp() where account_id='${reservation.accountId}'`);
    await assert.rejects(sql(control('status')), /pairing_denied/);
  } finally {
    await sql(`delete from auth.sessions where id='${joining}'`);
    await f.cleanup();
  }
});

test('pairing cancellation rechecks issuer binding expiry after an account lock wait', async () => {
  const f = await enrollmentFixture();
  let release, outcome;
  try {
    const reservation = JSON.parse(await sql(f.request()));
    await sql(enrollmentCommit(f, reservation));
    const device = await sql(`select device_id from public.device_bindings where session_id='${f.session}'`);
    const pairing = id();
    await sql(`set role service_role; select public.service_create_pairing_invite('${f.user}','${f.session}',
      '${reservation.workspaceId}','${device}','${pairing}',decode(repeat('42',32),'hex'));`);
    await sql(`update public.device_bindings set expires_at=clock_timestamp()+interval '2 seconds' where session_id='${f.session}'`);
    release = await holdLock(`select id from public.accounts where id='${reservation.accountId}' for update`);
    const application = `pairing-cancel-${randomUUID()}`;
    outcome = sql(`set role service_role; select public.service_control_pairing_invite('${f.user}','${f.session}',
      '${reservation.workspaceId}','${device}','${pairing}','cancel');`, application)
      .then(value => ({ value }), error => ({ error }));
    await waitUntilBlocked(application);
    await sql(`select pg_sleep(greatest(0,extract(epoch from expires_at-clock_timestamp())+0.1)) from public.device_bindings where session_id='${f.session}'`);
    await release(); release = null;
    assert.match((await outcome).error?.stderr ?? '', /pairing_denied/);
    assert.equal(await sql(`select state from context_relay_private.pairing_invites where id='${pairing}'`), 'pending');
  } finally {
    if (release) await release();
    if (outcome) await outcome;
    await f.cleanup();
  }
});

test('pairing lookup reserves one session and persists the fifth failed guess', async () => {
  const f = await enrollmentFixture(), other = await enrollmentFixture();
  const sessions = [randomUUID(), randomUUID(), randomUUID()];
  try {
    const reservation = JSON.parse(await sql(f.request()));
    await sql(enrollmentCommit(f, reservation));
    const device = await sql(`select device_id from public.device_bindings where session_id='${f.session}'`);
    const pairing = id();
    await sql(`insert into auth.sessions(id,user_id) values ${sessions.map(session => `('${session}','${f.user}')`).join(',')}`);
    await sql(`set role service_role; select public.service_create_pairing_invite('${f.user}','${f.session}',
      '${reservation.workspaceId}','${device}','${pairing}',decode(repeat('42',32),'hex'));`);
    const lookup = (session, digest = '42', user = f.user) => `set role service_role;
      select public.service_resolve_pairing_code('${user}','${session}',decode(repeat('${digest}',32),'hex'));`;
    const foreign = JSON.parse(await sql(lookup(other.session, '42', other.user)));
    assert.deepEqual(foreign, { status: 'invalid' });
    const results = await Promise.all(sessions.slice(0, 2).map(session => sql(lookup(session)).then(JSON.parse)));
    assert.equal(results.filter(result => result.status === 'located').length, 1);
    const winner = sessions[results.findIndex(result => result.status === 'located')];
    assert.deepEqual(JSON.parse(await sql(lookup(winner))), { status: 'located', pairingId: pairing });
    const guesses = await Promise.all(Array.from({ length: 8 }, () => sql(lookup(sessions[2], '43')).then(JSON.parse)));
    assert.equal(guesses.filter(result => result.status === 'invalid').length, 4);
    assert.equal(guesses.filter(result => result.status === 'exhausted').length, 4);
    assert.deepEqual(JSON.parse(await sql(lookup(sessions[2]))), { status: 'exhausted' });
    assert.equal(await sql(`select failed_attempts from context_relay_private.pairing_lookup_sessions where session_id='${sessions[2]}'`), '5');
    await sql(`update context_relay_private.pairing_invites set created_at=statement_timestamp()-interval '10 minutes',
      expires_at=statement_timestamp() where id='${pairing}'`);
    assert.deepEqual(JSON.parse(await sql(lookup(winner))), { status: 'expired' });
    for (const role of ['anon', 'authenticated']) await assert.rejects(sql(lookup(winner).replace('set role service_role', `set role ${role}`)), /permission denied/);
    await assert.rejects(sql(lookup(winner, '42', other.user)), /pairing_denied/);
    assert.equal(await sql(`select has_table_privilege('service_role','context_relay_private.pairing_lookup_sessions','select')`), 'f');
  } finally {
    await sql(`delete from auth.sessions where id in (${sessions.map(session => `'${session}'`).join(',')})`);
    await f.cleanup(); await other.cleanup();
  }
});

test('pairing lookup rolls back reservation when Auth expires during an account lock wait', async () => {
  const f = await enrollmentFixture(), joining = randomUUID();
  let release, outcome;
  try {
    const reservation = JSON.parse(await sql(f.request()));
    await sql(enrollmentCommit(f, reservation));
    const device = await sql(`select device_id from public.device_bindings where session_id='${f.session}'`);
    const pairing = id();
    await sql(`set role service_role; select public.service_create_pairing_invite('${f.user}','${f.session}',
      '${reservation.workspaceId}','${device}','${pairing}',decode(repeat('42',32),'hex'));`);
    await sql(`insert into auth.sessions(id,user_id,not_after) values ('${joining}','${f.user}',clock_timestamp()+interval '2 seconds')`);
    release = await holdLock(`select id from public.accounts where id='${reservation.accountId}' for update`);
    const application = `pairing-lookup-${randomUUID()}`;
    outcome = sql(`set role service_role; select public.service_resolve_pairing_code('${f.user}','${joining}',decode(repeat('42',32),'hex'));`, application)
      .then(value => ({ value }), error => ({ error }));
    await waitUntilBlocked(application);
    await sql(`select pg_sleep(greatest(0,extract(epoch from not_after-clock_timestamp())+0.1)) from auth.sessions where id='${joining}'`);
    await release(); release = null;
    assert.match((await outcome).error?.stderr ?? '', /pairing_denied/);
    assert.equal(await sql(`select located_session_id is null from context_relay_private.pairing_invites where id='${pairing}'`), 't');
    assert.equal(await sql(`select count(*) from context_relay_private.pairing_lookup_sessions where session_id='${joining}'`), '0');
  } finally {
    if (release) await release();
    if (outcome) await outcome;
    await sql(`delete from auth.sessions where id='${joining}'`);
    await f.cleanup();
  }
});

test('pairing invites require live device authority and preserve exact bounded retries', async () => {
  const f = await enrollmentFixture();
  try {
    const reservation = JSON.parse(await sql(f.request()));
    await sql(enrollmentCommit(f, reservation));
    const device = await sql(`select device_id from public.device_bindings where session_id='${f.session}'`);
    const pairing = id();
    const create = (operation = pairing, digest = '42', session = f.session) => `set role service_role;
      select public.service_create_pairing_invite('${f.user}','${session}','${reservation.workspaceId}',
        '${device.trim()}','${operation}',decode(repeat('${digest}',32),'hex'));`;
    const invite = JSON.parse(await sql(create()));
    assert.equal(invite.pairingId, pairing);
    assert.equal(BigInt(invite.expiresAt) - BigInt(invite.createdAt), 600000n);
    assert.deepEqual(JSON.parse(await sql(create())), invite);
    await assert.rejects(sql(create(pairing, '43')), /pairing_conflict/);
    await assert.rejects(sql(create(pairing, '42', randomUUID())), /pairing_denied/);
    const competing = await Promise.allSettled(Array.from({ length: 8 }, (_, index) => sql(create(id(), (0x50 + index).toString(16)))));
    assert.equal(competing.filter(result => result.status === 'fulfilled').length, 5);
    for (const result of competing.filter(result => result.status === 'rejected')) assert.match(result.reason.message, /pairing_rate_limited/);
    await assert.rejects(sql(create(id(), '60')), /pairing_rate_limited/);
    await sql(`update context_relay_private.pairing_invites set created_at=created_at-interval '11 minutes', expires_at=expires_at-interval '11 minutes' where id='${pairing}'`);
    await assert.rejects(sql(create()), /pairing_expired/);
    assert.equal(await sql(`select has_table_privilege('service_role','context_relay_private.pairing_invites','select')`), 'f');
    assert.equal(await sql(`select has_function_privilege('authenticated','public.service_create_pairing_invite(uuid,uuid,uuid,uuid,uuid,bytea)','execute')`), 'f');
  } finally { await f.cleanup(); }
});

test('pairing invite insertion rolls back if Auth expires during a unique-index wait', async () => {
  const f = await enrollmentFixture(), other = await enrollmentFixture();
  let release, outcome;
  const pairing = id();
  try {
    const requests = [];
    for (const [index, item] of [other, f].entries()) {
      const reservation = JSON.parse(await sql(item.request()));
      await sql(enrollmentCommit(item, reservation));
      const device = await sql(`select device_id from public.device_bindings where session_id='${item.session}'`);
      requests.push(`set role service_role; select public.service_create_pairing_invite('${item.user}','${item.session}',
        '${reservation.workspaceId}','${device.trim()}','${index === 0 ? id() : pairing}',decode(repeat('42',32),'hex'));`);
    }
    const existing = JSON.parse(await sql(requests[0]));
    await sql(`update auth.sessions set not_after=clock_timestamp()+interval '2 seconds' where id='${f.session}'`);
    release = await holdLock(`delete from context_relay_private.pairing_invites where id='${existing.pairingId}'`);
    const application = `pairing-insert-${randomUUID()}`;
    outcome = sql(requests[1], application).then(value => ({ value }), error => ({ error }));
    await waitUntilBlocked(application);
    await sql(`select pg_sleep(greatest(0,extract(epoch from not_after-clock_timestamp())+0.1)) from auth.sessions where id='${f.session}'`);
    await release(); release = null;
    assert.match((await outcome).error?.stderr ?? '', /pairing_denied/);
    assert.equal(await sql(`select count(*) from context_relay_private.pairing_invites where id='${pairing}'`), '0');
  } finally { if (release) await release(); if (outcome) await outcome; await f.cleanup(); await other.cleanup(); }
});

test('recovery snapshot allows a fresh owner session without granting device trust', async () => {
  const f = await enrollmentFixture(), other = await enrollmentFixture(), fresh = randomUUID();
  const snapshot = (user = f.user, session = fresh) => `set role service_role;
    select public.service_recovery_snapshot_for_session('${user}','${session}');`;
  try {
    const reservation = JSON.parse(await sql(f.request()));
    const receipt = JSON.parse(await sql(enrollmentCommit(f, reservation)));
    await sql(`insert into auth.sessions(id,user_id) values ('${fresh}','${f.user}');`);
    const value = JSON.parse(await sql(snapshot()));
    assert.deepEqual(value, { accountId: reservation.accountId, workspaceId: reservation.workspaceId,
      canonicalRecord: '010203', canonicalRecordSha256: receipt.canonicalRecordSha256,
      registeredAtMs: receipt.registeredAtMs, recoveryGeneration: '0' });
    assert.equal(await sql(`select count(*) from public.device_bindings where session_id='${fresh}'`), '0');
    assert.equal(JSON.parse(await sql(snapshot(other.user, other.session))), null);
    await assert.rejects(sql(snapshot(f.user, other.session)), /enrollment_session_denied/);
    for (const role of ['anon', 'authenticated']) {
      await assert.rejects(sql(snapshot().replace('set role service_role', `set role ${role}`)), /permission denied/);
    }
    await sql(`update public.recovery_roots set revoked_at=clock_timestamp() where account_id='${reservation.accountId}'`);
    assert.equal(JSON.parse(await sql(snapshot())), null);
    await sql(`update public.recovery_roots set revoked_at=null where account_id='${reservation.accountId}';
      update public.accounts set deletion_state='pending_delete', deletion_requested_at=clock_timestamp(),
        deletion_scheduled_for=clock_timestamp()+interval '1 day' where id='${reservation.accountId}'`);
    assert.equal(JSON.parse(await sql(snapshot())), null);
    await sql(`update auth.sessions set not_after=clock_timestamp()-interval '1 second' where id='${fresh}'`);
    await assert.rejects(sql(snapshot()), /enrollment_session_denied/);
  } finally {
    await sql(`delete from auth.sessions where id='${fresh}'`);
    await f.cleanup(); await other.cleanup();
  }
});

for (const lock of ['account', 'root']) {
  test(`recovery snapshot rechecks session expiry after the ${lock} lock`, async () => {
    const f = await enrollmentFixture();
    let release, outcome;
    try {
      const reservation = JSON.parse(await sql(f.request()));
      await sql(enrollmentCommit(f, reservation));
      await sql(`update auth.sessions set not_after=clock_timestamp()+interval '2 seconds' where id='${f.session}'`);
      release = await holdLock(lock === 'account'
        ? `select id from public.accounts where id='${reservation.accountId}' for update`
        : `select id from public.recovery_roots where account_id='${reservation.accountId}' for update`);
      const application = `snapshot-wait-${randomUUID()}`;
      outcome = sql(`set role service_role; select public.service_recovery_snapshot_for_session('${f.user}','${f.session}')`, application)
        .then(value => ({ value }), error => ({ error }));
      await waitUntilBlocked(application);
      await sql(`select pg_sleep(greatest(0, extract(epoch from not_after-clock_timestamp())+0.1)) from auth.sessions where id='${f.session}'`);
      await release(); release = null;
      const result = await outcome;
      assert.ok(result.error, `Expired session received a snapshot: ${result.value}`);
      assert.match(result.error.stderr, /enrollment_session_denied/);
    } finally {
      if (release) await release();
      if (outcome) await outcome;
      await f.cleanup();
    }
  });
}

async function restoreFixture() {
  const f = await enrollmentFixture();
  const reservation = JSON.parse(await sql(f.request()));
  const receipt = JSON.parse(await sql(enrollmentCommit(f, reservation)));
  const session = randomUUID(), restore = id(), device = id(), certificate = id();
  await sql(`insert into auth.sessions(id,user_id) values ('${session}','${f.user}')`);
  const request = `set role service_role; select public.service_commit_recovery_for_session(
    '${f.user}','${session}','${restore}','${receipt.enrollmentId}','${receipt.recoveryRootId}',
    '${reservation.accountId}','${reservation.workspaceId}','${certificate}','${device}',0,
    decode('${receipt.canonicalRecordSha256}','hex'),decode('040506','hex'),
    decode(repeat('61',32),'hex'),decode(repeat('62',32),'hex'),decode(repeat('63',32),'hex'),decode(repeat('64',64),'hex'));`;
  return { ...f, reservation, receipt, session, restore, device, certificate, request,
    projection: `set role service_role; select public.service_recovery_claim_for_session('${f.user}','${session}','${restore}');`,
    cleanup: async () => { await sql(`delete from auth.sessions where id='${session}'`); await f.cleanup(); } };
}

test('restore admission is atomic, session-bound and idempotent without reactivating a revoked binding', async () => {
  const f = await restoreFixture();
  try {
    assert.equal(JSON.parse(await sql(f.projection)),null);
    const receipt = JSON.parse(await sql(f.request));
    assert.equal(receipt.acceptedGeneration,'1');
    assert.equal(receipt.restoreId,f.restore);
    assert.deepEqual(JSON.parse(await sql(f.request)),receipt);
    assert.deepEqual(JSON.parse(await sql(f.projection)),{ canonicalClaim:'040506', receipt });
    assert.equal(await sql(`select recovery_generation from public.recovery_roots where id='${f.receipt.recoveryRootId}'`),'1');
    for (const role of ['anon','authenticated']) await assert.rejects(sql(f.request.replace('set role service_role',`set role ${role}`)),/permission denied/);
    await assert.rejects(sql(f.request.replace("decode('040506'","decode('040507'")),/recovery_conflict/);
    await assert.rejects(sql(f.request.replace(f.session,randomUUID())),/enrollment_session_denied/);
    await sql(`update public.device_bindings set state='revoked',revoked_at=clock_timestamp(),cutoff_device_sequence=0,
      cutoff_hash=decode(repeat('00',32),'hex'),cutoff_signature=decode(repeat('00',64),'hex') where session_id='${f.session}'`);
    assert.deepEqual(JSON.parse(await sql(f.request)),receipt);
    assert.equal(await sql(`select state from public.device_bindings where session_id='${f.session}'`),'revoked');
  } finally { await f.cleanup(); }
});

test('competing restores consume one generation and exact retries retain their original receipt', async () => {
  const f = await restoreFixture(), session = randomUUID();
  let release, pending;
  try {
    await sql(`insert into auth.sessions(id,user_id) values ('${session}','${f.user}')`);
    const alternate = f.request.replace(f.session,session).replace(f.restore,id()).replace(f.certificate,id()).replace(f.device,id()).replace("decode('040506'","decode('040607'");
    const requests = [f.request,alternate];
    release = await holdLock(`select id from public.recovery_roots where id='${f.receipt.recoveryRootId}' for update`);
    const applications = [0,1].map(()=>`restore-compete-${randomUUID()}`);
    pending = Promise.allSettled(requests.map((request,index)=>sql(request,applications[index])));
    await Promise.all(applications.map(waitUntilBlocked));
    await release(); release=null;
    const results = await pending;
    assert.equal(results.filter(result=>result.status==='fulfilled').length,1);
    const failed = results.findIndex(result=>result.status==='rejected');
    assert.match(results[failed].reason.stderr,/recovery_conflict/);
    const won = 1-failed, receipt = JSON.parse(results[won].value);
    assert.equal(receipt.acceptedGeneration,'1');
    assert.equal(await sql(`select count(*) from public.device_bindings where session_id in ('${f.session}','${session}')`),'1');
    assert.equal(JSON.parse(await sql(requests[failed].replace(',0,',',1,'))).acceptedGeneration,'2');
    assert.deepEqual(JSON.parse(await sql(requests[won])),receipt);
    assert.equal(await sql(`select recovery_generation from public.recovery_roots where id='${f.receipt.recoveryRootId}'`),'2');
    assert.equal(JSON.parse(await sql(f.projection.replace(f.session,session))),null);
  } finally { if(release) await release(); if(pending) await pending; await sql(`delete from auth.sessions where id='${session}'`); await f.cleanup(); }
});

test('restore admission rolls back when session expiry occurs during certificate insertion', async () => {
  const f = await restoreFixture(), other = await fixture(); let release, outcome;
  try {
    await sql(`update public.device_certificates set id='${f.certificate}' where account_id='${other.account}';
      update auth.sessions set not_after=clock_timestamp()+interval '2 seconds' where id='${f.session}'`);
    release = await holdLock(`delete from public.device_certificates where id='${f.certificate}'`);
    const application = `restore-insert-${randomUUID()}`;
    outcome = sql(f.request,application).then(value=>({value}),error=>({error}));
    await waitUntilBlocked(application);
    await sql(`select pg_sleep(greatest(0,extract(epoch from not_after-clock_timestamp())+0.1)) from auth.sessions where id='${f.session}'`);
    await release(); release=null;
    assert.match((await outcome).error?.stderr ?? '',/enrollment_session_denied/);
    assert.equal(await sql(`select count(*) from public.device_certificates where id='${f.certificate}'`),'0');
    assert.equal(await sql(`select count(*) from public.device_bindings where session_id='${f.session}'`),'0');
    assert.equal(await sql(`select count(*) from context_relay_private.recovery_commits where restore_id='${f.restore}'`),'0');
    assert.equal(await sql(`select recovery_generation from public.recovery_roots where id='${f.receipt.recoveryRootId}'`),'0');
  } finally { if(release) await release(); if(outcome) await outcome; await f.cleanup(); await other.cleanup(); }
});

test('revoked roots, deleting accounts and wrong owners cannot admit a restore', async () => {
  const f = await restoreFixture(), other = await enrollmentFixture();
  try {
    await assert.rejects(sql(f.request.replace(f.user,other.user).replace(f.session,other.session)),/recovery_denied/);
    await assert.rejects(sql(f.request.replace(f.receipt.canonicalRecordSha256,'00'.repeat(32))),/recovery_conflict/);
    await sql(`update public.recovery_roots set revoked_at=clock_timestamp() where id='${f.receipt.recoveryRootId}'`);
    await assert.rejects(sql(f.request),/recovery_denied/);
    await sql(`update public.recovery_roots set revoked_at=null where id='${f.receipt.recoveryRootId}';
      update public.accounts set deletion_state='pending_delete',deletion_requested_at=clock_timestamp(),
        deletion_scheduled_for=clock_timestamp()+interval '1 day' where id='${f.reservation.accountId}'`);
    await assert.rejects(sql(f.request),/recovery_denied/);
    assert.equal(await sql(`select count(*) from public.device_certificates where id='${f.certificate}'`),'0');
    assert.equal(await sql(`select recovery_generation from public.recovery_roots where id='${f.receipt.recoveryRootId}'`),'0');
  } finally { await f.cleanup(); await other.cleanup(); }
});

for (const lock of ['account','root']) {
  test(`restore admission rechecks session expiry after the ${lock} lock`, async () => {
    const f = await restoreFixture(); let release, outcome;
    try {
      await sql(`update auth.sessions set not_after=clock_timestamp()+interval '2 seconds' where id='${f.session}'`);
      release = await holdLock(lock==='account'
        ? `select id from public.accounts where id='${f.reservation.accountId}' for update`
        : `select id from public.recovery_roots where id='${f.receipt.recoveryRootId}' for update`);
      const application = `restore-wait-${randomUUID()}`;
      outcome = sql(f.request,application).then(value=>({value}),error=>({error}));
      await waitUntilBlocked(application);
      await sql(`select pg_sleep(greatest(0,extract(epoch from not_after-clock_timestamp())+0.1)) from auth.sessions where id='${f.session}'`);
      await release(); release=null;
      assert.match((await outcome).error?.stderr ?? '',/enrollment_session_denied/);
      assert.equal(await sql(`select recovery_generation from public.recovery_roots where id='${f.receipt.recoveryRootId}'`),'0');
      assert.equal(await sql(`select count(*) from public.device_bindings where session_id='${f.session}'`),'0');
    } finally { if(release) await release(); if(outcome) await outcome; await f.cleanup(); }
  });
}

test('expired enrollment renewal rotates only the challenge and preserves committed receipts', async () => {
  const f = await enrollmentFixture();
  try {
    const previous = JSON.parse(await sql(f.request()));
    const renew = `set role service_role; select public.service_renew_enrollment_for_session(
      '${f.user}','${f.session}','${previous.reservationId}',decode(repeat('51',32),'hex'));`;
    assert.deepEqual(JSON.parse(await sql(renew)), previous);
    await sql(`update context_relay_private.enrollment_reservations set expires_at=clock_timestamp()-interval '1 second' where auth_user_id='${f.user}'`);
    const next = JSON.parse(await sql(renew));
    for (const key of ['reservationId','accountId','workspaceId']) assert.equal(next[key],previous[key]);
    assert.notEqual(next.nonce,previous.nonce);
    assert.deepEqual(JSON.parse(await sql(renew.replace("repeat('51'", "repeat('52'"))),next);
    await assert.rejects(sql(renew.replace('set role service_role','set role authenticated')), /permission denied/);
    await assert.rejects(sql(renew.replace(f.session,randomUUID())), /enrollment_reservation_denied/);
    await assert.rejects(sql(enrollmentCommit(f,previous)), /enrollment_reservation_denied/);
    assert.equal(await sql(`select request_count from context_relay_private.enrollment_reservations where auth_user_id='${f.user}'`),'2');
    await sql(`update context_relay_private.enrollment_reservations set request_count=6, expires_at=clock_timestamp()-interval '1 second' where auth_user_id='${f.user}'`);
    await assert.rejects(sql(renew), /enrollment_rate_limited/);
    await sql(`update context_relay_private.enrollment_reservations set request_count=2, expires_at=to_timestamp(${next.expiresAt}::numeric/1000) where auth_user_id='${f.user}'`);
    const committed = JSON.parse(await sql(enrollmentCommit(f,next)));
    assert.deepEqual(JSON.parse(await sql(renew)),next);
    assert.deepEqual(JSON.parse(await sql(`set role service_role; select public.service_enrollment_status_for_session('${f.user}','${f.session}','${next.reservationId}');`)).receipt,committed);
  } finally { await f.cleanup(); }
});

test('enrollment commit is atomic, exact on retry, and rejects changed records', async () => {
  const first = await enrollmentFixture(), second = await enrollmentFixture();
  try {
    const reservation = JSON.parse(await sql(first.request()));
    const certificate = id();
    const request = enrollmentCommit(first, reservation, certificate);
    const receipt = JSON.parse(await sql(request));
    assert.deepEqual(JSON.parse(await sql(request)), receipt);
    const statusRequest = `set role service_role; select public.service_enrollment_status_for_session(
      '${first.user}','${first.session}','${reservation.reservationId}');`;
    await sql(`update context_relay_private.enrollment_reservations set expires_at=clock_timestamp()-interval '1 second'
      where auth_user_id='${first.user}'`);
    assert.deepEqual(JSON.parse(await sql(statusRequest)).receipt, receipt);
    await assert.rejects(sql(statusRequest.replace(first.session, second.session)), /enrollment_reservation_denied/);
    await assert.rejects(sql(statusRequest.replace('set role service_role', 'set role authenticated')), /permission denied/);
    await assert.rejects(sql(request.replace("decode('010203'", "decode('010204'")), /enrollment_conflict/);
    assert.equal(await sql(`select count(*) from public.device_bindings
      where auth_user_id='${first.user}' and state='active'`), '1');
    assert.equal(await sql(`select control_epoch||':'||key_epoch from public.accounts
      where id='${reservation.accountId}'`), '1:1');
    const other = JSON.parse(await sql(second.request()));
    await assert.rejects(sql(enrollmentCommit(second, other, certificate)), /duplicate key/);
    assert.equal(await sql(`select count(*) from public.accounts where owner_user_id='${second.user}'`), '0');
    assert.equal(await sql(`select count(*) from public.recovery_roots where account_id='${other.accountId}'`), '0');
    assert.equal(await sql(`select count(*) from context_relay_private.enrollment_commits
      where auth_user_id='${second.user}'`), '0');
    await sql(`delete from auth.sessions where id='${first.session}'`);
    await assert.rejects(sql(statusRequest), /enrollment_session_denied/);
  } finally { await first.cleanup(); await second.cleanup(); }
});

test('concurrent enrollment retries retain one challenge and deny a competing operation', async () => {
  const f = await enrollmentFixture();
  let release, outcome;
  try {
    release = await holdLock(f.request());
    const application = `enrollment-conflict-${randomUUID()}`;
    outcome = sql(f.request(), application).then(value => ({ value }), error => ({ error }));
    await waitUntilBlocked(application);
    await release(); release = null;
    const reply = await outcome;
    assert.ifError(reply.error);
    assert.deepEqual(JSON.parse(reply.value), JSON.parse(await sql(f.request())));
    await assert.rejects(sql(f.request(id())), /enrollment_in_progress/);
    assert.equal(await sql(`select request_count from context_relay_private.enrollment_reservations
      where auth_user_id='${f.user}'`), '1');
    assert.equal(await sql(`select count(*) from public.accounts where owner_user_id='${f.user}'`), '0');
  } finally {
    if (release) await release();
    if (outcome) await outcome;
    await f.cleanup();
  }
});

test('enrollment commit rolls back when the session expires during an insert wait', async () => {
  const f = await enrollmentFixture();
  let release, outcome;
  try {
    const reservation = JSON.parse(await sql(f.request()));
    await sql(`update auth.sessions set not_after=clock_timestamp()+interval '2 seconds' where id='${f.session}'`);
    release = await holdLock(`select id from auth.users where id='${f.user}' for update`);
    const application = `enrollment-insert-${randomUUID()}`;
    outcome = sql(enrollmentCommit(f, reservation), application).then(value => ({ value }), error => ({ error }));
    await waitUntilBlocked(application);
    await sql(`select pg_sleep(greatest(0, extract(epoch from not_after-clock_timestamp())+0.1))
      from auth.sessions where id='${f.session}'`);
    await release(); release = null;
    const result = await outcome;
    assert.ok(result.error, `Expired session committed: ${result.value}`);
    assert.match(result.error.stderr, /enrollment_session_denied/);
    assert.equal(await sql(`select count(*) from public.accounts where owner_user_id='${f.user}'`), '0');
    assert.equal(await sql(`select count(*) from context_relay_private.enrollment_commits where auth_user_id='${f.user}'`), '0');
  } finally {
    if (release) await release();
    if (outcome) await outcome;
    await f.cleanup();
  }
});

for (const lock of ['reservation', 'auth_session']) {
  test(`enrollment rechecks session expiry after the ${lock} lock`, async () => {
    const f = await enrollmentFixture();
    let release, outcome;
    try {
      const original = await sql(f.request());
      await sql(`update auth.sessions set not_after=clock_timestamp()+interval '2 seconds'
        where id='${f.session}'`);
      release = await holdLock(lock === 'reservation'
        ? `select auth_user_id from context_relay_private.enrollment_reservations where auth_user_id='${f.user}' for update`
        : `select id from auth.sessions where id='${f.session}' for update`);
      const application = `enrollment-wait-${randomUUID()}`;
      outcome = sql(f.request(), application).then(value => ({ value }), error => ({ error }));
      await waitUntilBlocked(application);
      await sql(`select pg_sleep(greatest(0, extract(epoch from not_after-clock_timestamp())+0.1))
        from auth.sessions where id='${f.session}'`);
      await release(); release = null;
      const result = await outcome;
      assert.ok(result.error, `Expired session accepted: ${result.value}`);
      assert.match(result.error.stderr, /enrollment_session_denied/);
      assert.equal(await sql(`select account_id from context_relay_private.enrollment_reservations
        where auth_user_id='${f.user}'`), JSON.parse(original).accountId);
    } finally {
      if (release) await release();
      if (outcome) await outcome;
      await f.cleanup();
    }
  });
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
