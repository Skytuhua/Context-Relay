import assert from 'node:assert/strict';
import test from 'node:test';
import { createSupabasePairingDependencies } from './adapter.mjs';
import {readFileSync} from 'node:fs';
const publicFixture=JSON.parse(readFileSync(new URL('../../../crates/core/tests/fixtures/hosted-pairing-approval-v2.json',import.meta.url),'utf8'));

const identity = { userId:'01900000-0000-7000-8000-000000000001', sessionId:'01900000-0000-7000-8000-000000000002' };
const scope = {workspaceId:publicFixture.trusted.workspaceId,deviceId:publicFixture.trusted.issuerDeviceId};
const pairingId = '01900000-0000-7000-8000-000000000005';
const bytes = value => new Uint8Array(32).fill(value);
function fixture() {
  const calls = [];
  let result = { data:{ status:'pending' }, error:null };
  const env = { SUPABASE_URL:'https://example.supabase.co', SUPABASE_PUBLISHABLE_KEY:'sb_publishable_test',
    CONTEXT_RELAY_SUPABASE_SECRET_KEY:'sb_secret_test', CONTEXT_RELAY_PAIRING_PEPPER:'42'.repeat(32) };
  const createClient = () => ({ auth:{ getClaims:async token => {
    assert.equal(token, 'test-token'); return {data:{claims:{sub:identity.userId,session_id:identity.sessionId}},error:null};
  } }, rpc:async (name,args) => { calls.push({name,args});
    if(name==='service_recovery_snapshot_for_session') return {data:{accountId:publicFixture.trusted.accountId,workspaceId:scope.workspaceId,
      canonicalRecord:publicFixture.canonicalEnrollment,canonicalRecordSha256:publicFixture.trusted.enrollmentSha256},error:null};
    return result; } });
  return { calls, env, createClient, dependencies:createSupabasePairingDependencies({createClient,env}),
    result: value => { result = value; } };
}

test('pairing adapter uses verified identity and stores only keyed locator digests', async () => {
  const f = fixture();
  assert.deepEqual(await f.dependencies.authenticate('test-token'), identity);
  const invite = await f.dependencies.create(identity,scope);
  assert.match(invite.code,/^[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}$/);
  const creation = f.calls.find(call=>call.name==='service_create_pairing_invite');
  assert.equal(creation.name,'service_create_pairing_invite');
  assert.equal(creation.args.p_auth_user_id,identity.userId);
  assert.equal(creation.args.p_session_id,identity.sessionId);
  assert.equal(creation.args.p_workspace_id,scope.workspaceId);
  assert.equal(creation.args.p_device_id,scope.deviceId);
  assert.match(creation.args.p_pairing_id,/^[0-9a-f-]{14}7[0-9a-f-]{21}$/);
  assert.match(creation.args.p_code_digest,/^\\x[0-9a-f]{64}$/);
  assert.equal(JSON.stringify(creation).includes(invite.code),false);
  await f.dependencies.resolve(identity,invite.code);
  assert.equal(f.calls.at(-1).args.p_code_digest,creation.args.p_code_digest);
  await assert.rejects(f.dependencies.resolve(identity,'bad-code'));
  assert.equal(f.calls.filter(call=>call.name==='service_resolve_pairing_code').length,1);
  assert.throws(()=>createSupabasePairingDependencies({createClient:f.createClient,env:{...f.env,CONTEXT_RELAY_PAIRING_PEPPER:''}}),/configuration_error/);
});

test('creation re-verifies the exact committed enrollment before idempotent initialization',async()=>{
  const f=fixture();await f.dependencies.create(identity,scope);
  assert.deepEqual(f.calls.map(call=>call.name),['service_recovery_snapshot_for_session','service_initialize_committed_membership','service_create_pairing_invite']);
  assert.equal(f.calls[1].args.p_enrollment_sha256,'\\x'+publicFixture.trusted.enrollmentSha256);
  assert.equal(f.calls[1].args.p_workspace_id,scope.workspaceId);
});

test('pairing adapter maps verified request and approval fields to bounded service operations', async () => {
  const f = fixture();
  const request = { pairingId, canonicalRequest:new Uint8Array([1,2,3]), requestDigest:bytes(3), signingPublicKey:bytes(1), wrappingPublicKey:bytes(2) };
  await f.dependencies.submit(identity,request);
  assert.equal(f.calls.at(-1).args.p_canonical_request,'\\x010203');
  assert.equal(f.calls.at(-1).args.p_signing_key,'\\x'+'01'.repeat(32));
  await f.dependencies.control(identity,scope,pairingId,'cancel');
  assert.equal(f.calls.at(-1).args.p_action,'cancel');
  await assert.rejects(f.dependencies.control(identity,scope,pairingId,'approve'),/invalid_request/);
  await f.dependencies.verificationContext(identity,scope,pairingId);
  assert.equal(f.calls.at(-1).name,'service_pairing_verification_context');
  const approval = { canonicalApprovedPayload:new Uint8Array([4,5,6]),certificateId:pairingId,
    child:{deviceId:pairingId,requestNonce:bytes(4),signature:new Uint8Array(64)} };
  await f.dependencies.decide(identity,scope,request,{controlEpoch:1,keyEpoch:2},approval);
  assert.equal(f.calls.at(-1).args.p_approved_payload,'\\x040506');
  assert.equal(f.calls.at(-1).args.p_key_epoch,2);
  assert.equal(f.calls.at(-1).args.p_action,'approve');
  await f.dependencies.decide(identity,scope,request,{controlEpoch:1,keyEpoch:2},null);
  assert.equal(f.calls.at(-1).args.p_action,'reject');
  assert.equal(f.calls.at(-1).args.p_signature,null);
  await f.dependencies.result(identity,pairingId,request.requestDigest);
  assert.equal(f.calls.at(-1).name,'service_pairing_result_for_session');
  f.result({data:null,error:null});
  assert.equal(await f.dependencies.request(identity,scope,pairingId),null);
  await assert.rejects(f.dependencies.result(identity,pairingId,request.requestDigest),/transient/);
  f.result({data:null,error:{message:'pairing_expired'}});
  await assert.rejects(f.dependencies.request(identity,scope,pairingId),/pairing_expired/);
  f.result({data:null,error:{message:'private-provider-detail'}});
  await assert.rejects(f.dependencies.request(identity,scope,pairingId), error=>error.code==='transient'&&!error.message.includes('private-provider-detail'));
});

test('pairing adapter forwards exact membership addresses and verified V2 CAS inputs',async()=>{
  const f=fixture();
  await f.dependencies.membershipObject(identity,pairingId,'03'.repeat(32),'04'.repeat(32),'membership_event');
  assert.equal(f.calls.at(-1).name,'service_pairing_membership_object');
  assert.equal(f.calls.at(-1).args.p_request_digest,'\\x'+'03'.repeat(32));
  assert.equal(f.calls.at(-1).args.p_address,'\\x'+'04'.repeat(32));
  f.result({data:null,error:null});
  assert.equal(await f.dependencies.membershipObject(identity,pairingId,'03'.repeat(32),'04'.repeat(32),'membership_event'),null);
  f.result({data:{},error:null});
  const request={pairingId,requestDigest:bytes(3)};
  const approval={version:2,canonicalApprovedPayload:bytes(4),certificateId:pairingId,previousStateSha256:bytes(5),enrollmentSha256:bytes(6),membershipSignature:new Uint8Array(64),
    child:{deviceId:pairingId,requestNonce:bytes(7),signature:new Uint8Array(64),canonical:bytes(8)}};
  await f.dependencies.decide(identity,scope,request,{controlEpoch:1,keyEpoch:1,stateSha256:'05'.repeat(32),enrollmentSha256:'06'.repeat(32)},approval);
  assert.equal(f.calls.at(-1).name,'service_decide_pairing_request_v2');
  assert.equal(f.calls.at(-1).args.p_previous_state_sha256,'\\x'+'05'.repeat(32));
  assert.equal(f.calls.at(-1).args.p_canonical_certificate,'\\x'+'08'.repeat(32));
  await f.dependencies.acceptedMembershipObject(identity,scope,'event','09'.repeat(32));
  assert.equal(f.calls.at(-1).name,'service_membership_object');
  assert.equal(f.calls.at(-1).args.p_address,'\\x'+'09'.repeat(32));
  await f.dependencies.revocationContext(identity,scope,pairingId);
  assert.equal(f.calls.at(-1).args.p_target_device_id,pairingId);
  await f.dependencies.revocationVerificationContext(identity,scope);
  assert.equal(f.calls.at(-1).name,'service_revocation_verification_context');
  await f.dependencies.revocationResult(identity,scope,pairingId,'0a'.repeat(32));
  assert.equal(f.calls.at(-1).args.p_object_sha256,'\\x'+'0a'.repeat(32));
  await f.dependencies.publishRevocation(identity,scope,{operationId:pairingId,targetDeviceId:pairingId,controlEpoch:1,keyEpoch:1,
    cutoffSequence:'0',cutoffSha256:bytes(0),previousStateSha256:bytes(1),successorSha256:bytes(2),objectSha256:bytes(3),
    signature:new Uint8Array(64),canonicalObject:new Uint8Array([4,5])});
  assert.equal(f.calls.at(-1).name,'service_publish_revocation');
  assert.equal(f.calls.at(-1).args.p_canonical_object,'\\x0405');
  assert.equal(f.calls.at(-1).args.p_signature,'\\x'+'00'.repeat(64));
});
