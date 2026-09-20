import assert from 'node:assert/strict';
import test from 'node:test';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {readFile} from 'node:fs/promises';
import {randomUUID,createPrivateKey,createPublicKey,sign,createHash} from 'node:crypto';
import {verifyRecoveryRecord} from '../supabase/functions/enrollment/record.mjs';
import {verifyRecoveryClaim} from '../supabase/functions/enrollment/restore.mjs';
import {createSupabaseEnrollmentDependencies} from '../supabase/functions/enrollment/adapter.mjs';
import {createEnrollmentEdgeHandler} from '../supabase/functions/enrollment/core.mjs';
import {verifyPairingRequest} from '../supabase/functions/pairing/crypto.mjs';
import {verifyPairingApproval} from '../supabase/functions/pairing/approval.mjs';
import {createSupabasePairingDependencies} from '../supabase/functions/pairing/adapter.mjs';
import {createPairingEdgeHandler} from '../supabase/functions/pairing/core.mjs';
import {createPairingLocator} from '../supabase/functions/pairing/locator.mjs';

assert.equal(process.env.CONTEXT_RELAY_DISPOSABLE_POSTGRES,'1');
assert.ok(['127.0.0.1','::1','localhost'].includes(process.env.PGHOST));
assert.ok(!process.env.PGHOSTADDR || ['127.0.0.1','::1','localhost'].includes(process.env.PGHOSTADDR));
assert.ok(!process.env.PGSERVICE && !process.env.PGSERVICEFILE);
assert.ok(process.env.PGDATABASE);
const run=promisify(execFile), psql=process.env.CONTEXT_RELAY_PSQL??'psql';
async function sql(text) {
  const result=await run(psql,['-X','-w','-qAt','-v','ON_ERROR_STOP=1','-c',text],{windowsHide:true,timeout:20000,
    env:{...process.env,PGOPTIONS:'-c statement_timeout=15000 -c lock_timeout=10000'}});
  return result.stdout.replace(/\r\n/g,'\n').trim();
}
const fixture=JSON.parse(await readFile(new URL('../crates/core/tests/fixtures/hosted-pairing-approval-v2.json',import.meta.url),'utf8'));
const record=await verifyRecoveryRecord(Buffer.from(fixture.canonicalEnrollment,'hex'));
const request=await verifyPairingRequest(Buffer.from(fixture.canonicalRequest,'hex'));
const approval=await verifyPairingApproval(Buffer.from(fixture.canonicalApprovedPayload,'hex'),request.canonicalRequest,
  fixture.trusted,Buffer.from(fixture.membershipSignature,'hex'));
const hex=b=>Buffer.from(b).toString('hex');
const b=b=>`decode('${hex(b)}','hex')`;
const uuid=()=>randomUUID().replace(/^(.{14})./,'$17');
function enrollment(canonical=record.canonicalRecord,source=record,user=randomUUID()) {
  const record=source,session=randomUUID(),reservation=uuid();
  const start=`begin;insert into auth.users(id) values('${user}');insert into auth.sessions(id,user_id) values('${session}','${user}');set local role service_role;
    select public.service_reserve_enrollment_for_session('${user}','${session}','${reservation}','${record.accountId}','${record.workspaceId}',decode(repeat('42',32),'hex'));`;
  const commit=`select public.service_commit_enrollment_for_session('${user}','${session}','${reservation}',decode(repeat('42',32),'hex'),
    '${record.accountId}','${record.workspaceId}','${record.enrollmentId}','${record.recoveryRootId}','${record.certificateId}','${record.deviceId}',
    ${b(record.requestNonce)},${b(record.recoverySigningKey)},${b(record.recoveryWrappingKey)},${b(record.deviceSigningKey)},${b(record.deviceWrappingKey)},${b(record.certificateSignature)},${b(record.encryptedMetadata)},${b(canonical)});`;
  return {user,session,start,commit};
}

async function recoveryFixture(){
  const vector=JSON.parse(await readFile(new URL('../crates/core/tests/fixtures/hosted-recovery-claim-v2.json',import.meta.url),'utf8'));
  const root=await verifyRecoveryRecord(Buffer.from(vector.canonicalRecord,'hex'));
  const claim=await verifyRecoveryClaim(Buffer.from(vector.canonicalClaim,'hex'),root.canonicalRecord,
    {authUserId:vector.authUserId,sessionId:vector.sessionId},Buffer.from(vector.proof,'hex'));
  const f=enrollment(root.canonicalRecord,root,vector.authUserId);
  // The rotated parent is a cryptographically verified Rust fixture. This is
  // server transaction coverage; live revocation publication is a separate gate.
  const setup=`${f.start}${f.commit}reset role;
    insert into auth.sessions(id,user_id) values('${vector.sessionId}','${f.user}');
    update public.accounts set control_epoch=2,key_epoch=2 where id='${root.accountId}';
    update context_relay_private.membership_heads set state_sha256=${b(claim.previousStateSha256)},control_epoch=2,key_epoch=2 where workspace_id='${root.workspaceId}';
    update context_relay_private.membership_members set active=false where workspace_id='${root.workspaceId}';set local role service_role;`;
  const call=`public.service_commit_recovery_v2_for_session('${f.user}','${vector.sessionId}','${claim.restoreId}','${claim.enrollmentId}','${claim.recoveryRootId}',
    '${claim.accountId}','${claim.workspaceId}','${claim.certificateId}','${claim.deviceId}',${claim.expectedRecoveryGeneration},
    ${b(claim.canonicalRecordSha256)},${b(claim.canonicalClaim)},${b(claim.requestNonce)},${b(claim.deviceSigningKey)},${b(claim.deviceWrappingKey)},${b(claim.certificateSignature)},
    ${claim.controlEpoch},${claim.keyEpoch},${b(claim.previousStateSha256)},${b(claim.canonicalCertificate)},${b(claim.rootSignature)})`;
  const successor=createHash('sha256').update(Buffer.from('context-relay/recovery-membership-add/v1\0')).update(claim.canonicalClaim).digest('hex');
  return {f,root,claim,vector,setup,call,successor};
}
test('root recovery V2 atomically adds exact signed public history at the current parent and generation',async()=>{
  const {root,claim,setup,call,successor}=await recoveryFixture();
  const out=await sql(`${setup}select ${call}->>'canonicalClaimSha256';select ${call}->>'acceptedGeneration';reset role;
    select encode(state_sha256,'hex') from context_relay_private.membership_heads where workspace_id='${root.workspaceId}';
    select count(*) from context_relay_private.membership_events where event_id='${claim.restoreId}';
    select active from context_relay_private.membership_members where device_id='${root.deviceId}';rollback;`);
  assert.deepEqual(out.split('\n').slice(-5),[createHash('sha256').update(claim.canonicalClaim).digest('hex'),'1',successor,'1','f']);
});

test('root recovery V2 rejects stale parent and generation without a partial admission',async()=>{
  const {root,claim,setup,call}=await recoveryFixture();
  for(const change of [
    `update context_relay_private.membership_heads set state_sha256=decode(repeat('ab',32),'hex') where workspace_id='${root.workspaceId}'`,
    `update public.recovery_roots set recovery_generation=1 where id='${root.recoveryRootId}'`
  ]){
    const out=await sql(`${setup}reset role;${change};set local role service_role;
      do $$begin begin perform ${call};raise exception 'stale recovery accepted';exception when serialization_failure then if SQLERRM <> 'recovery_publication_rejected' then raise; end if;end;end$$;reset role;
      select (select count(*) from context_relay_private.recovery_commits where restore_id='${claim.restoreId}')+
        (select count(*) from public.device_certificates where id='${claim.certificateId}')+
        (select count(*) from context_relay_private.membership_members where device_id='${claim.deviceId}')+
        (select count(*) from context_relay_private.membership_events where event_id='${claim.restoreId}');rollback;`);
    assert.equal(out.split('\n').at(-1),'0');
  }
});

test('root recovery V2 event failure rolls back certificate binding generation and head',async()=>{
  const {root,claim,vector,setup,call}=await recoveryFixture();
  const out=await sql(`${setup}reset role;
    create function context_relay_private.task5_reject_recovery_event() returns trigger language plpgsql as $$begin raise exception using errcode='23514',message='forced recovery event failure';end;$$;
    create trigger task5_reject_recovery_event before insert on context_relay_private.membership_events for each row execute function context_relay_private.task5_reject_recovery_event();set local role service_role;
    do $$begin begin perform ${call};raise exception 'event failure accepted';exception when check_violation then null;end;end$$;reset role;
    select encode(state_sha256,'hex') from context_relay_private.membership_heads where workspace_id='${root.workspaceId}';
    select recovery_generation from public.recovery_roots where id='${root.recoveryRootId}';
    select (select count(*) from public.device_certificates where id='${claim.certificateId}')+
      (select count(*) from public.device_bindings where session_id='${vector.sessionId}')+
      (select count(*) from context_relay_private.membership_members where device_id='${claim.deviceId}')+
      (select count(*) from context_relay_private.recovery_commits where restore_id='${claim.restoreId}');rollback;`);
  assert.deepEqual(out.split('\n').slice(-3),[vector.parentStateSha256,'0','0']);
});

test('root recovery V2 receipt retries require current recipient and original live session',async()=>{
  const {root,claim,vector,setup,call}=await recoveryFixture();
  for(const change of [
    `update context_relay_private.membership_members set active=false where device_id='${claim.deviceId}'`,
    `delete from auth.sessions where id='${vector.sessionId}'`,
    `update public.recovery_roots set revoked_at=clock_timestamp() where id='${root.recoveryRootId}'`
  ]){
    const out=await sql(`${setup}select ${call};reset role;${change};set local role service_role;
      do $$begin begin perform ${call};raise exception 'inactive receipt accepted';exception when insufficient_privilege then null;end;end$$;reset role;
      select count(*) from context_relay_private.recovery_commits where restore_id='${claim.restoreId}';rollback;`);
    assert.equal(out.split('\n').at(-1),'1');
  }
});

test('recovery addressed public history requires a live owner session but no surviving device binding',async()=>{
  const f=enrollment(),p=pairing(f),session=randomUUID(),otherUser=randomUUID(),otherSession=randomUUID();
  const endpoint=`public.service_recovery_membership_endpoint('${f.user}','${session}','${record.workspaceId}',decode('${fixture.trusted.enrollmentSha256}','hex'))`;
  const object=address=>`public.service_recovery_membership_event('${f.user}','${session}','${record.workspaceId}',decode('${fixture.trusted.enrollmentSha256}','hex'),decode('${address}','hex'))`;
  const out=await sql(`${p.setup}${p.decide}reset role;insert into auth.sessions(id,user_id) values('${session}','${f.user}');
    insert into auth.users(id) values('${otherUser}');insert into auth.sessions(id,user_id) values('${otherSession}','${otherUser}');
    update context_relay_private.membership_members set active=false where workspace_id='${record.workspaceId}';
    update public.device_bindings set state='revoked',revoked_at=clock_timestamp(),cutoff_device_sequence=0,
      cutoff_hash=decode(repeat('01',32),'hex'),cutoff_signature=decode(repeat('01',64),'hex') where account_id='${record.accountId}';
    select (select count(*) from context_relay_private.membership_members where workspace_id='${record.workspaceId}' and active)+
      (select count(*) from public.device_bindings where account_id='${record.accountId}' and state='active');set local role service_role;
    select ${endpoint}->>'stateSha256';select ${object(hex(approval.successorSha256))};select ${object('ab'.repeat(32))} is null;reset role;
    set local role service_role;
    do $$begin
      begin perform ${endpoint.replaceAll(f.user,otherUser).replaceAll(session,otherSession)};raise exception 'wrong owner accepted';exception when insufficient_privilege then null;end;
      begin perform ${object(hex(approval.successorSha256)).replaceAll(f.user,otherUser).replaceAll(session,otherSession)};raise exception 'wrong object owner accepted';exception when insufficient_privilege then null;end;
      begin perform ${endpoint.replaceAll(fixture.trusted.enrollmentSha256,'ab'.repeat(32))};raise exception 'wrong pin accepted';exception when serialization_failure then null;end;
      begin perform ${object(hex(approval.successorSha256)).replaceAll(record.workspaceId,uuid())};raise exception 'wrong workspace accepted';exception when serialization_failure then null;end;
    end$$;reset role;
    delete from auth.sessions where id='${session}';set local role service_role;
    do $$begin
      begin perform ${endpoint};raise exception 'dead recovery session accepted';exception when insufficient_privilege then null;end;
      begin perform ${object(hex(approval.successorSha256))};raise exception 'dead object session accepted';exception when insufficient_privilege then null;end;
    end$$;rollback;`);
  assert.deepEqual(out.split('\n').slice(-4),['0',hex(approval.successorSha256),fixture.membershipObject,'t']);
  for(const role of ['anon','authenticated','service_role'])assert.equal(await sql(`select has_function_privilege('${role}','context_relay_private.lock_recovery_membership(uuid,uuid,uuid,bytea)','execute')`),'f');
});

test('recovery HTTP handler and production adapter use real PostgreSQL V2 CAS and addressed reads',async()=>{
  const {root,claim,vector,setup,successor}=await recoveryFixture();
  const calls=[],failures=[];
  // Supabase Auth verification and SDK transport are explicit local stubs;
  // cryptographic verification and every service-role SQL transaction are real.
  const createClient=()=>({auth:{getClaims:async()=>({data:{claims:{sub:vector.authUserId,session_id:vector.sessionId}},error:null})},rpc:async(name,args)=>{
    assert.match(name,/^service_[a-z0-9_]+$/);calls.push(name);
    const literal=value=>value===null?'null':typeof value==='number'?String(value):`'${String(value).replaceAll("'","''")}'`;
    const parameters=Object.entries(args).map(([key,value])=>{assert.match(key,/^p_[a-z0-9_]+$/);return `${key}=>${literal(value)}`;}).join(',');
    try{return {data:JSON.parse(await sql(`begin;set local role service_role;select coalesce(to_jsonb(public.${name}(${parameters})),'null'::jsonb);commit;`)),error:null};}
    catch(error){failures.push({name,message:error.stderr});return {data:null,error:{message:error.stderr?.match(/ERROR:\s+(\w+)/)?.[1]??'transient'}};}
  }});
  const handler=createEnrollmentEdgeHandler(createSupabaseEnrollmentDependencies({createClient,env:{SUPABASE_URL:'https://example.supabase.co',SUPABASE_PUBLISHABLE_KEY:'sb_publishable_test',CONTEXT_RELAY_SUPABASE_SECRET_KEY:'sb_secret_test'}}));
  async function post(body,expected=200){
    const response=await handler(new Request('https://example.supabase.co/functions/v1/enrollment',{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer local-auth-stub'},body:JSON.stringify({v:1,...body})}));
    const result=await response.json();assert.equal(response.status,expected,JSON.stringify({result,failures}));return result;
  }
  try{
    await sql(`${setup}commit;`);
    const receipt=await post({action:'restore',claim:vector.canonicalClaim,proof:vector.proof});
    const retry=await post({action:'restore',claim:vector.canonicalClaim,proof:vector.proof});
    assert.deepEqual(retry.receipt,receipt.receipt);
    const status=await post({action:'restore_status',restoreId:claim.restoreId});
    assert.equal(status.projection.canonicalClaim,vector.canonicalClaim);
    const scope={workspaceId:root.workspaceId,enrollmentSha256:hex(claim.canonicalRecordSha256)};
    assert.equal((await post({action:'recovery_membership_endpoint',...scope})).endpoint.stateSha256,successor);
    const expected=Buffer.concat([Buffer.from('context-relay/public-membership-event/v1\0'),Buffer.of(2),Buffer.alloc(4),Buffer.from([0,0,0,64]),Buffer.from(claim.rootSignature),Buffer.alloc(4),
      (()=>{const length=Buffer.alloc(4);length.writeUInt32BE(claim.canonicalClaim.length);return length;})(),Buffer.from(claim.canonicalClaim)]);
    assert.equal((await post({action:'recovery_membership_event',...scope,successorSha256:successor})).object,hex(expected));
    assert.equal((await post({action:'recovery_membership_event',...scope,successorSha256:'ab'.repeat(32)})).object,null);
    const committed=calls.filter(name=>name==='service_commit_recovery_v2_for_session').length;
    await post({action:'restore',claim:vector.canonicalClaim,proof:'00'.repeat(64)},400);
    assert.equal(calls.filter(name=>name==='service_commit_recovery_v2_for_session').length,committed);
    assert.equal(calls.includes('service_commit_recovery_for_session'),false);
  }finally{
    await sql(`delete from public.accounts where id='${root.accountId}' and owner_user_id='${vector.authUserId}';delete from auth.sessions where user_id='${vector.authUserId}';delete from auth.users where id='${vector.authUserId}';`);
  }
});
test('real enrollment atomically creates the exact independently computed canonical genesis anchor',async()=>{
  const f=enrollment();
  const output=await sql(`${f.start}${f.commit} reset role;
    do $$ begin if to_regclass('context_relay_private.membership_heads') is null then raise exception 'committed enrollment has no public membership anchor';end if;end $$;
    select encode(h.state_sha256,'hex')||':'||encode(m.canonical_certificate,'hex') from context_relay_private.membership_heads h
      join context_relay_private.membership_members m using(workspace_id) where h.workspace_id='${record.workspaceId}'; rollback;`);
  assert.equal(output.split('\n').at(-1),`${fixture.trusted.stateSha256}:${fixture.trusted.issuerCertificate}`);
});
test('unsupported canonical enrollment version is rejected atomically by the SQL extraction gate',async()=>{
  const bad=Buffer.from(record.canonicalRecord);bad[2]=2;
  const f=enrollment(bad);
  await assert.rejects(sql(`${f.start}${f.commit} rollback;`),/invalid_pairing_request/);
  assert.equal(await sql(`select count(*) from public.accounts where id='${record.accountId}'`),'0');
});

test('initializer failure rolls back account, root, certificate, binding and receipt within the enrollment call',async()=>{
  const bad=Buffer.from(record.canonicalRecord);bad[164]=0xa8;
  const f=enrollment(bad);
  const output=await sql(`${f.start}
    do $$ begin
      begin ${f.commit.replace(/^select /,'perform ')} raise exception 'invalid extraction accepted';
      exception when invalid_parameter_value then null; end;
    end $$; reset role;
    select (select count(*) from public.accounts where id='${record.accountId}')+
      (select count(*) from public.recovery_roots where account_id='${record.accountId}')+
      (select count(*) from public.device_certificates where account_id='${record.accountId}')+
      (select count(*) from public.device_bindings where account_id='${record.accountId}')+
      (select count(*) from context_relay_private.enrollment_commits where auth_user_id='${f.user}')+
      (select count(*) from context_relay_private.membership_heads where account_id='${record.accountId}'); rollback;`);
  assert.equal(output.split('\n').at(-1),'0');
});

test('exact initialization preserves a descendant head and inactive genesis member',async()=>{
  const f=enrollment();
  const output=await sql(`${f.start}${f.commit}${f.commit} reset role;
    update context_relay_private.membership_heads set state_sha256=decode(repeat('ab',32),'hex'),control_epoch=2,key_epoch=2;
    update context_relay_private.membership_members set active=false;
    select encode((context_relay_private.initialize_committed_membership('${f.user}')).state_sha256,'hex');
    select active from context_relay_private.membership_members where workspace_id='${record.workspaceId}'; rollback;`);
  assert.deepEqual(output.split('\n').slice(-2),['ab'.repeat(32),'f']);
});

test('conflicting pinned genesis and altered receipt cannot reinitialize existing history',async()=>{
  const f=enrollment();
  const output=await sql(`${f.start}${f.commit} reset role;
    update context_relay_private.membership_heads set enrollment_sha256=decode(repeat('ab',32),'hex');
    do $$ begin begin perform context_relay_private.initialize_committed_membership('${f.user}');
      raise exception 'conflicting pin accepted'; exception when serialization_failure then null;end;end $$;
    update context_relay_private.membership_heads set enrollment_sha256=decode('${fixture.trusted.enrollmentSha256}','hex');
    update context_relay_private.enrollment_commits set receipt=receipt-'workspaceId' where auth_user_id='${f.user}';
    do $$ begin begin perform context_relay_private.initialize_committed_membership('${f.user}');
      raise exception 'missing scope accepted'; exception when serialization_failure then null;end;end $$;
    select count(*) from context_relay_private.membership_heads;rollback;`);
  assert.equal(output.split('\n').at(-1),'1');
});

test('the private initializer is not directly executable by service or authenticated callers',async()=>{
  for(const role of ['service_role','authenticated','anon']) {
    assert.equal(await sql(`select has_function_privilege('${role}','context_relay_private.initialize_committed_membership(uuid)','execute')`),'f');
  }
});

test('membership endpoint requires the exact active bound device and a live session',async()=>{
  const f=enrollment();
  const call=`public.service_membership_endpoint('${f.user}','${f.session}','${record.workspaceId}','${record.deviceId}')`;
  const output=await sql(`${f.start}${f.commit} select ${call}->>'stateSha256'; reset role;
    update public.device_bindings set state='revoked',revoked_at=clock_timestamp(),cutoff_device_sequence=0,
      cutoff_hash=decode(repeat('01',32),'hex'),cutoff_signature=decode(repeat('01',64),'hex') where session_id='${f.session}';set local role service_role;
    do $$ begin begin perform ${call}; raise exception 'revoked binding accepted';exception when insufficient_privilege then null;end;end $$;reset role;
    update public.device_bindings set state='active',revoked_at=null,cutoff_device_sequence=null,cutoff_hash=null,cutoff_signature=null where session_id='${f.session}';
    update context_relay_private.membership_members set active=false;set local role service_role;
    do $$ begin begin perform ${call}; raise exception 'inactive member accepted';exception when insufficient_privilege then null;end;end $$;reset role;
    update context_relay_private.membership_members set active=true;
    delete from auth.sessions where id='${f.session}';set local role service_role;
    do $$ begin begin perform ${call}; raise exception 'dead session accepted';exception when insufficient_privilege then null;end;end $$;rollback;`);
  assert.equal(output.split('\n').at(-1),fixture.trusted.stateSha256);
});

test('explicit reverified enrollment initialization binds the committed pin and cannot reactivate a device',async()=>{
  const f=enrollment();
  const call=pin=>`public.service_initialize_committed_membership('${f.user}','${f.session}','${record.workspaceId}',decode('${pin}','hex'))`;
  const output=await sql(`${f.start}${f.commit} select ${call(fixture.trusted.enrollmentSha256)}->>'stateSha256';
    do $$ begin begin perform ${call('00'.repeat(32))}; raise exception 'wrong pin accepted';exception when serialization_failure then null;end;end $$;reset role;
    update context_relay_private.membership_members set active=false;set local role service_role;
    select ${call(fixture.trusted.enrollmentSha256)}->>'stateSha256';reset role;
    select active from context_relay_private.membership_members;rollback;`);
  assert.deepEqual(output.split('\n').slice(-2),[fixture.trusted.stateSha256,'f']);
});

function pairing(f) {
  const joinSession=randomUUID(),locator=b(Buffer.alloc(32,0x61));
  const setup=`${f.start}${f.commit}reset role;insert into auth.sessions(id,user_id) values('${joinSession}','${f.user}');set local role service_role;
    select public.service_create_pairing_invite('${f.user}','${f.session}','${record.workspaceId}','${record.deviceId}','${request.pairingId}',${locator});
    select public.service_resolve_pairing_code('${f.user}','${joinSession}',${locator});
    select public.service_submit_pairing_request('${f.user}','${joinSession}','${request.pairingId}',${b(request.canonicalRequest)},${b(request.signingPublicKey)},${b(request.wrappingPublicKey)});`;
  const decide=`select public.service_decide_pairing_request_v2('${f.user}','${f.session}','${record.workspaceId}','${record.deviceId}','${request.pairingId}',
    ${b(request.requestDigest)},'approve',1,1,${b(approval.canonicalApprovedPayload)},'${approval.certificateId}','${request.deviceId}',
    ${b(request.requestNonce)},${b(approval.child.signature)},${b(approval.previousStateSha256)},${b(approval.enrollmentSha256)},
    ${b(approval.membershipSignature)},${b(approval.child.canonical)});`;
  return {setup,decide,joinSession};
}

test('V2 approval atomically publishes exact public ADD bytes and admits the child as a current approver',async()=>{
  const f=enrollment(),p=pairing(f);
  const output=await sql(`${p.setup}${p.decide}${p.decide}
    select public.service_create_pairing_invite('${f.user}','${p.joinSession}','${record.workspaceId}','${request.deviceId}','${uuid()}',${b(Buffer.alloc(32,0x62))});reset role;
    select encode(h.state_sha256,'hex')||':'||encode(e.canonical_object,'hex') from context_relay_private.membership_heads h
      join context_relay_private.membership_events e using(workspace_id) where e.event_id='${request.pairingId}';
    select count(*) from context_relay_private.membership_members;rollback;`);
  assert.deepEqual(output.split('\n').slice(-2),[`${hex(approval.successorSha256)}:${fixture.membershipObject}`,'2']);
});

test('addressed V2 history and result bind the original recipient, request, pin and live membership',async()=>{
  const f=enrollment(),p=pairing(f);
  const object=(session,kind,address)=>`public.service_pairing_membership_object('${f.user}','${session}','${request.pairingId}',${b(request.requestDigest)},'${kind}',${b(address)})`;
  const output=await sql(`${p.setup}${p.decide}
    select public.service_pairing_verification_context('${f.user}','${f.session}','${record.workspaceId}','${record.deviceId}','${request.pairingId}')->'trusted'->>'stateSha256';
    select ${object(p.joinSession,'membership_enrollment',approval.enrollmentSha256)};
    select ${object(p.joinSession,'membership_event',approval.successorSha256)};
    select ${object(p.joinSession,'membership_event',Buffer.alloc(32,0x12))} is null;
    do $$ begin begin perform ${object(f.session,'membership_event',approval.successorSha256)};
      raise exception 'wrong recipient accepted';exception when insufficient_privilege then null;end;end $$;
    select public.service_pairing_result_for_session('${f.user}','${p.joinSession}','${request.pairingId}',${b(request.requestDigest)})->>'membershipSignature';
    reset role;update context_relay_private.membership_members set active=false where device_id='${request.deviceId}';set local role service_role;
    do $$ begin begin perform ${object(p.joinSession,'membership_event',approval.successorSha256)};
      raise exception 'inactive recipient accepted';exception when insufficient_privilege then null;end;end $$;rollback;`);
  assert.deepEqual(output.split('\n').slice(-5),[fixture.trusted.stateSha256,fixture.canonicalEnrollment,fixture.membershipObject,'t',fixture.membershipSignature]);
});

test('stale parent and failed public event insert leave certificate, binding, head and receipt unchanged',async()=>{
  for(const fault of ['stale','insert']) {
    const f=enrollment(),p=pairing(f);
    const inject=fault==='stale'?`update context_relay_private.membership_heads set state_sha256=decode(repeat('bc',32),'hex');`
      :`alter table context_relay_private.membership_events add constraint task5_forced_insert_failure check(false) not valid;`;
    const output=await sql(`${p.setup} reset role;${inject}set local role service_role;
      do $$ begin begin ${p.decide.replace(/^select /,'perform ')} raise exception 'fault accepted';
        exception when ${fault==='stale'?'serialization_failure':'check_violation'} then null;end;end $$;reset role;
      select (select count(*) from public.device_certificates)||':'||(select count(*) from public.device_bindings)||':'||
        (select count(*) from context_relay_private.membership_members)||':'||(select count(*) from context_relay_private.membership_events)||':'||
        (select state from context_relay_private.pairing_invites where id='${request.pairingId}')||':'||
        (select decision_receipt is null from context_relay_private.pairing_invites where id='${request.pairingId}');rollback;`);
    assert.equal(output.split('\n').at(-1),'1:1:1:0:pending:true');
  }
});

test('stored V2 approval receipts require current issuer membership and live original Auth',async()=>{
  const f=enrollment(),p=pairing(f);
  const output=await sql(`${p.setup}${p.decide}reset role;
    update context_relay_private.membership_members set active=false where device_id='${record.deviceId}';set local role service_role;
    do $$ begin begin ${p.decide.replace(/^select /,'perform ')} raise exception 'inactive issuer receipt accepted';
      exception when insufficient_privilege then null;end;end $$;reset role;
    update context_relay_private.membership_members set active=true where device_id='${record.deviceId}';
    delete from auth.sessions where id='${f.session}';set local role service_role;
    do $$ begin begin ${p.decide.replace(/^select /,'perform ')} raise exception 'dead Auth receipt accepted';
      exception when insufficient_privilege then null;end;end $$;reset role;
    select count(*) from context_relay_private.membership_events;rollback;`);
  assert.equal(output.split('\n').at(-1),'1');
});

test('concurrent initialization is idempotent; orphan certificate commit rolls back while full account deletion succeeds',async()=>{
  const f=enrollment();
  try {
    await sql(`${f.start}${f.commit}commit;`);
    const call=`begin;set local role service_role;select public.service_initialize_committed_membership('${f.user}','${f.session}',
      '${record.workspaceId}',decode('${fixture.trusted.enrollmentSha256}','hex'))->>'stateSha256';commit;`;
    assert.deepEqual(await Promise.all([sql(call),sql(call)]),[fixture.trusted.stateSha256,fixture.trusted.stateSha256]);
    assert.equal(await sql('select count(*) from context_relay_private.membership_heads'),'1');
    await assert.rejects(sql(`begin;delete from public.device_certificates where id='${record.certificateId}';commit;`),/membership_members_certificate_id_fkey/);
    assert.equal(await sql(`select count(*) from public.device_certificates where id='${record.certificateId}'`),'1');
  } finally {
    await sql(`delete from public.accounts where id='${record.accountId}' and owner_user_id='${f.user}';delete from auth.sessions where user_id='${f.user}';delete from auth.users where id='${f.user}';`);
  }
  assert.equal(await sql(`select (select count(*) from public.accounts where id='${record.accountId}')+
    (select count(*) from context_relay_private.membership_heads where workspace_id='${record.workspaceId}')+
    (select count(*) from context_relay_private.membership_members where workspace_id='${record.workspaceId}')`),'0');
});

test('HTTP handler and production pairing adapter execute V2 approval and addressed reads through PostgreSQL',async()=>{
  const f=enrollment(),joinSession=randomUUID(),pepper=Buffer.alloc(32,0x73),locator=await createPairingLocator(pepper);
  const scope={workspaceId:record.workspaceId,deviceId:record.deviceId};
  const claims={issuer:{sub:f.user,session_id:f.session},joiner:{sub:f.user,session_id:joinSession}};
  const rpcFailures=[];
  // Only external Auth-claims acquisition is stubbed. Every privileged RPC below
  // runs under service_role against the disposable PostgreSQL database.
  const createClient=()=>({auth:{getClaims:async token=>({data:{claims:claims[token]},error:null})},rpc:async(name,args)=>{
    assert.match(name,/^service_[a-z0-9_]+$/);
    const literal=value=>value===null?'null':typeof value==='number'?String(value):`'${String(value).replaceAll("'","''")}'`;
    const params=Object.entries(args).map(([key,value])=>{assert.match(key,/^p_[a-z0-9_]+$/);return `${key}=>${literal(value)}`;}).join(',');
    try {return {data:JSON.parse(await sql(`begin;set local role service_role;select to_jsonb(public.${name}(${params}));commit;`)),error:null};}
    catch(error){rpcFailures.push({name,error:error.stderr??error.message});const match=error.stderr?.match(/ERROR:\s+(\w+)/);return {data:null,error:{message:match?.[1]??'transient'}};}
  }});
  const handler=createPairingEdgeHandler(createSupabasePairingDependencies({createClient,env:{SUPABASE_URL:'https://example.supabase.co',
    SUPABASE_PUBLISHABLE_KEY:'sb_publishable_test',CONTEXT_RELAY_SUPABASE_SECRET_KEY:'sb_secret_test',CONTEXT_RELAY_PAIRING_PEPPER:hex(pepper)}}));
  async function post(token,body) {
    const response=await handler(new Request('https://example.supabase.co/functions/v1/pairing',{method:'POST',headers:{'content-type':'application/json',authorization:`Bearer ${token}`},body:JSON.stringify({v:1,...body})}));
    const result=await response.json();assert.equal(response.status,200,JSON.stringify({result,rpcFailures}));return result;
  }
  const uuidBytes=value=>Buffer.from(value.replaceAll('-',''),'hex');
  function proof(seed,session,operation,canonical,v2=false) {
    const key=createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),Buffer.alloc(32,seed)]),format:'der',type:'pkcs8'});
    const expected=operation==='request'?request.signingPublicKey:Buffer.from(fixture.trusted.issuerSigningKey,'hex');
    assert.deepEqual(createPublicKey(key).export({format:'der',type:'spki'}).subarray(-32),Buffer.from(expected));
    return hex(sign(null,Buffer.concat([Buffer.from(`context-relay/hosted-pairing-${operation}-proof/v${v2?2:1}\0`),uuidBytes(f.user),uuidBytes(session),
      ...(v2?[Buffer.from(request.requestDigest)]:[]),createHash('sha256').update(canonical).digest(),...(v2?[Buffer.from(approval.membershipSignature)]:[])]),key));
  }
  try {
    await sql(`${f.start}${f.commit}reset role;insert into auth.sessions(id,user_id) values('${joinSession}','${f.user}');set local role service_role;
      select public.service_create_pairing_invite('${f.user}','${f.session}','${record.workspaceId}','${record.deviceId}','${request.pairingId}',${b(locator.digest)});commit;`);
    await post('issuer',{action:'membership_endpoint',...scope});
    const resolved=await post('joiner',{action:'resolve',code:locator.code});assert.equal(resolved.result.pairingId,request.pairingId);
    await post('joiner',{action:'submit',canonicalRequest:fixture.canonicalRequest,proof:proof(0x42,joinSession,'request',request.canonicalRequest)});
    await post('issuer',{action:'approve',...scope,pairingId:request.pairingId,canonicalApprovedPayload:fixture.canonicalApprovedPayload,
      membershipSignature:fixture.membershipSignature,proof:proof(0x41,f.session,'approval',approval.canonicalApprovedPayload,true)});
    const result=await post('joiner',{action:'result',pairingId:request.pairingId,requestDigest:hex(request.requestDigest)});
    assert.equal(result.result.membershipSignature,fixture.membershipSignature);
    const object=await post('joiner',{action:'membership_event',pairingId:request.pairingId,requestDigest:hex(request.requestDigest),address:hex(approval.successorSha256)});
    assert.equal(object.object,fixture.membershipObject);
  } finally {
    await sql(`delete from public.accounts where id='${record.accountId}' and owner_user_id='${f.user}';delete from auth.sessions where user_id='${f.user}';delete from auth.users where id='${f.user}';`);
  }
});

// Model the committed epoch transition while retaining the immutable certificate.
test('surviving membership authorizes sync and pending-delete cancellation after epoch advancement',async()=>{
  const f=enrollment();
  const out=await sql(`${f.start}${f.commit}reset role;
    update public.accounts set control_epoch=2,key_epoch=2 where id='${record.accountId}';
    update context_relay_private.membership_heads set control_epoch=2,key_epoch=2 where workspace_id='${record.workspaceId}';
    set local role service_role;
    select public.service_sync_identity_context('${f.user}','${f.session}','${record.workspaceId}','${record.deviceId}')->>'controlEpoch';
    reset role;update public.accounts set deletion_state='pending_delete',deletion_requested_at=clock_timestamp(),deletion_scheduled_for=clock_timestamp()+interval '1 day' where id='${record.accountId}';
    select context_relay_private.locked_account_lifecycle_context('${f.user}','${f.session}','${record.workspaceId}')->>'deviceId';rollback;`);
  assert.deepEqual(out.split('\n').slice(-2),['2',record.deviceId]);
});

for(const [name,change] of [
  ['inactive member',`update context_relay_private.membership_members set active=false where workspace_id='${record.workspaceId}'`],
  ['mismatched head',`update context_relay_private.membership_heads set control_epoch=2 where workspace_id='${record.workspaceId}'`],
  ['missing member',`delete from context_relay_private.membership_members where workspace_id='${record.workspaceId}'`],
]) test(`membership authority denies ${name} despite active binding`,async()=>{
  const f=enrollment();
  await sql(`${f.start}${f.commit}reset role;${change};set local role service_role;
    do $$begin begin perform public.service_sync_identity_context('${f.user}','${f.session}','${record.workspaceId}','${record.deviceId}');
      raise exception 'invalid authority accepted';exception when invalid_authorization_specification then null;end;end$$;
    reset role;do $$begin begin perform context_relay_private.locked_account_lifecycle_context('${f.user}','${f.session}','${record.workspaceId}');
      raise exception 'invalid lifecycle authority accepted';exception when invalid_authorization_specification then null;end;end$$;rollback;`);
});
for(const expired of [false,true]) test(`sync denies ${expired?'expired':'deleted'} Auth session`,async()=>{
  const f=enrollment();
  await sql(`${f.start}${f.commit}reset role;${expired?`update auth.sessions set not_after=clock_timestamp()-interval '1 second'`:'delete from auth.sessions'} where id='${f.session}';set local role service_role;
    do $$begin begin perform public.service_sync_identity_context('${f.user}','${f.session}','${record.workspaceId}','${record.deviceId}');
      raise exception 'dead session accepted';exception when invalid_authorization_specification then null;end;end$$;rollback;`);
});
