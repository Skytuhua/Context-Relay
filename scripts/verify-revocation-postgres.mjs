import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { promisify } from 'node:util';
import test, {before,after} from 'node:test';

import { createSupabasePairingDependencies } from '../supabase/functions/pairing/adapter.mjs';
import { createPairingEdgeHandler } from '../supabase/functions/pairing/core.mjs';

assert.equal(process.env.CONTEXT_RELAY_DISPOSABLE_POSTGRES, '1');
assert.ok(['127.0.0.1', '::1', 'localhost'].includes(process.env.PGHOST));
assert.ok(!process.env.PGHOSTADDR || ['127.0.0.1', '::1'].includes(process.env.PGHOSTADDR));
assert.ok(!process.env.PGSERVICE && !process.env.PGSERVICEFILE);
assert.ok(process.env.PGDATABASE);
const psql = process.env.CONTEXT_RELAY_PSQL ?? 'psql';
const run = promisify(execFile);
async function sql(query) {
  const result = await run(psql, ['-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-c', query], {
    env: { ...process.env, PGOPTIONS: '-c statement_timeout=15000 -c lock_timeout=10000' },
    timeout: 20000,
    windowsHide: true,
  });
  return result.stdout.trim();
}

// Supabase's migration/test principal is not a PostgreSQL superuser. Borrow
// fixture-owner membership only for this script, preserving its previous grant.
let previousFixtureGrant;
let fixtureAuthorityAcquired=false;
before(async()=>{
  previousFixtureGrant=JSON.parse(await sql(`select coalesce((select json_build_object(
    'admin',admin_option,'inherit',inherit_option,'set',set_option)
    from pg_auth_members where roleid='context_relay_rls_owner'::regrole
      and member=current_user::regrole and grantor=current_user::regrole),'null'::json)`));
  await sql('grant context_relay_rls_owner to current_user with inherit true,set true granted by current_user');
  fixtureAuthorityAcquired=true;
});
after(async()=>{
  if(fixtureAuthorityAcquired) await sql(previousFixtureGrant
    ? `grant context_relay_rls_owner to current_user with admin ${previousFixtureGrant.admin},inherit ${previousFixtureGrant.inherit},set ${previousFixtureGrant.set} granted by current_user`
    : 'revoke context_relay_rls_owner from current_user granted by current_user');
});
const fixture = JSON.parse(readFileSync(new URL('../crates/core/tests/fixtures/device-revocation-v1.json', import.meta.url), 'utf8'));
const account = fixture.trusted.accountId;
const workspace = fixture.trusted.workspaceId;
const device = fixture.trusted.issuerDeviceId;
const certificate = fixture.trusted.activeMembers[0].canonicalCertificate;
const certificateId = '018f22e2-79b0-7cc8-98c4-dc0c0c073990';
const object = fixture.object;
const signature = object.slice(494, 622);
assert.equal(signature.length, 128);

async function setup() {
  const user = randomUUID(), session = randomUUID();
  await sql(`
    delete from public.accounts where id='${account}';
    insert into auth.users(id) values('${user}');
    insert into auth.sessions(id,user_id) values('${session}','${user}');
    insert into public.accounts(id,owner_user_id,control_epoch,key_epoch) values('${account}','${user}',1,1);
    insert into public.recovery_roots(id,account_id,signing_public_key,wrapping_public_key,encrypted_recovery_metadata)
      values('${fixture.trusted.recoveryRootId}','${account}',decode(repeat('02',32),'hex'),
        decode('${fixture.trusted.recoveryWrappingKey}','hex'),decode('01','hex'));
    -- This synthetic pre-history fixture supplies its own membership head below.
    -- Disable only fixture initialization inside this single SQL transaction.
    alter table context_relay_private.enrollment_commits disable trigger initialize_enrollment_membership;
    insert into context_relay_private.enrollment_commits(
      auth_user_id,account_id,reservation_id,session_id,canonical_record,receipt
    ) values ('${user}','${account}','${fixture.operationId}','${session}',decode('01','hex'),
      jsonb_build_object('recoveryRootId','${fixture.trusted.recoveryRootId}'));
    alter table context_relay_private.enrollment_commits enable trigger initialize_enrollment_membership;
    insert into public.device_certificates(id,account_id,workspace_id,control_epoch,request_nonce,device_id,
      issuer_kind,issuer_recovery_public_key,issuer_signing_public_key,device_signing_public_key,
      device_wrapping_public_key,signature)
      values('${certificateId}','${account}','${workspace}',1,decode(repeat('01',32),'hex'),'${device}',
        'recovery_root',decode(repeat('02',32),'hex'),decode(repeat('03',32),'hex'),
        decode('${fixture.trusted.issuerSigningKey}','hex'),decode(repeat('04',32),'hex'),decode(repeat('05',64),'hex'));
    insert into public.device_bindings(account_id,auth_user_id,session_id,device_id,state)
      values('${account}','${user}','${session}','${device}','active');
    insert into context_relay_private.membership_heads(workspace_id,account_id,enrollment_sha256,genesis_sha256,
      state_sha256,control_epoch,key_epoch) values('${workspace}','${account}',sha256(decode('01','hex')),
      decode(repeat('07',32),'hex'),decode('${fixture.receipt.parent.stateSha256}','hex'),1,1);
    insert into context_relay_private.membership_members values('${workspace}','${device}','${certificateId}',
      decode('${certificate}','hex'),decode(repeat('07',32),'hex'),true);`);
  return { user, session };
}
async function cleanup({user, session}) {
  await sql(`delete from public.accounts where id='${account}';
    delete from auth.sessions where id='${session}'; delete from auth.users where id='${user}';`);
}
function publish(auth, parent = fixture.receipt.parent.stateSha256) {
  return `set role service_role; select public.service_publish_revocation(
    '${auth.user}','${auth.session}','${workspace}','${device}','${fixture.operationId}','${device}',1,1,0,
    decode(repeat('00',32),'hex'),decode('${parent}','hex'),
    decode('${fixture.receipt.successor.stateSha256}','hex'),decode('${fixture.objectSha256}','hex'),
    decode('${signature}','hex'),decode('${object}','hex'))`;
}

test('revocation publication atomically commits exact membership, cutoff, binding and receipt state', async () => {
  let auth = await setup();
  try {
    const receipt = JSON.parse(await sql(publish(auth)));
    assert.deepEqual(receipt, fixture.receipt);
    assert.equal(await sql(`select control_epoch||':'||key_epoch||':'||encode(state_sha256,'hex')
      from context_relay_private.membership_heads where workspace_id='${workspace}'`),
      `2:2:${fixture.receipt.successor.stateSha256}`);
    assert.equal(await sql(`select control_epoch||':'||key_epoch from public.accounts where id='${account}'`), '2:2');
    assert.equal(await sql(`select active from context_relay_private.membership_members where workspace_id='${workspace}'`), 'f');
    assert.equal(await sql(`select state||':'||cutoff_device_sequence||':'||encode(cutoff_hash,'hex')||':'||encode(cutoff_signature,'hex')
      from public.device_bindings where account_id='${account}'`), `revoked:0:${'00'.repeat(32)}:${signature}`);
    assert.equal(await sql(`select encode(canonical_object,'hex') from context_relay_private.membership_events
      where event_id='${fixture.operationId}'`), object);
  } finally { await cleanup(auth); }

  auth = await setup();
  try {
    await assert.rejects(sql(publish(auth, fixture.receipt.parent.stateSha256.slice(0, 62) + '01')), /pairing_conflict/);
    assert.equal(await sql(`select control_epoch||':'||key_epoch||':'||encode(state_sha256,'hex')
      from context_relay_private.membership_heads where workspace_id='${workspace}'`),
      `1:1:${fixture.receipt.parent.stateSha256}`);
    assert.equal(await sql(`select count(*) from context_relay_private.device_revocation_receipts
      where operation_id='${fixture.operationId}'`), '0');
    assert.equal(await sql(`select state from public.device_bindings where account_id='${account}'`), 'active');
  } finally { await cleanup(auth); }
});

test('HTTP handler publishes revocation and denies further authority to a self-revoked device', async () => {
  const auth = await setup();
  const rpcFailures = [];
  const createClient = () => ({
    auth: {
      getClaims: async () => ({
        data: { claims: { sub: auth.user, session_id: auth.session } },
        error: null,
      }),
    },
    rpc: async (name, args) => {
      assert.match(name, /^service_[a-z0-9_]+$/);
      const literal = value => value === null
        ? 'null'
        : typeof value === 'number'
          ? String(value)
          : `'${String(value).replaceAll("'", "''")}'`;
      const parameters = Object.entries(args).map(([key, value]) => {
        assert.match(key, /^p_[a-z0-9_]+$/);
        return `${key}=>${literal(value)}`;
      }).join(',');
      try {
        return {
          data: JSON.parse(await sql(`begin;set local role service_role;
            select to_jsonb(public.${name}(${parameters}));commit;`)),
          error: null,
        };
      } catch (error) {
        rpcFailures.push({ name, error: error.stderr ?? error.message });
        const match = error.stderr?.match(/ERROR:\s+(\w+)/);
        return { data: null, error: { message: match?.[1] ?? 'transient' } };
      }
    },
  });
  const handler = createPairingEdgeHandler(createSupabasePairingDependencies({
    createClient,
    env: {
      SUPABASE_URL: 'https://example.supabase.co',
      SUPABASE_PUBLISHABLE_KEY: 'sb_publishable_test',
      CONTEXT_RELAY_SUPABASE_SECRET_KEY: 'sb_secret_test',
      CONTEXT_RELAY_PAIRING_PEPPER: '73'.repeat(32),
    },
  }));
  const post = async (path, body, expectedStatus=200) => {
    const response = await handler(new Request(`https://example.supabase.co/functions/v1/${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer synthetic' },
      body: JSON.stringify({ v: 1, ...body }),
    }));
    const result = await response.json();
    assert.equal(response.status, expectedStatus, JSON.stringify({ result, rpcFailures }));
    return result;
  };
  const scope = { workspaceId: workspace, deviceId: device };
  try {
    const context = await post('pairing', {
      action: 'revocation_context',
      ...scope,
      targetDeviceId: device,
    });
    assert.deepEqual(context.endpoint, fixture.receipt.parent);
    assert.equal(context.targetDeviceId, device);

    const published = await post('pairing/revocation-publish', {
      action: 'publish_revocation',
      ...scope,
      object,
    });
    assert.deepEqual(published.receipt, fixture.receipt);

    const result = await post('pairing', {
      action: 'revocation_result',
      ...scope,
      operationId: fixture.operationId,
      objectSha256: fixture.objectSha256,
    },403);
    assert.deepEqual(result, {v:1,error:"pairing_denied"});
    assert.equal(rpcFailures.length,1);
    assert.equal(rpcFailures[0].name,"service_revocation_result");
  } finally {
    await cleanup(auth);
  }
});
