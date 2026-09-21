import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { decodeRecoveryClaim, verifyRecoveryClaim } from "../../supabase/functions/enrollment/restore.mjs";
import {createSupabaseEnrollmentDependencies} from "../../supabase/functions/enrollment/adapter.mjs";
import {createEnrollmentEdgeHandler} from "../../supabase/functions/enrollment/core.mjs";

// Public/encrypted output of the actual Rust rotated-root recovery flow.
const fixture=JSON.parse(readFileSync(new URL("../../crates/core/tests/fixtures/hosted-recovery-claim-v2.json",import.meta.url),"utf8"));
const bytes=value=>Buffer.from(value,"hex");
const claim=bytes(fixture.canonicalClaim),record=bytes(fixture.canonicalRecord),proof=bytes(fixture.proof);
const identity={authUserId:fixture.authUserId,sessionId:fixture.sessionId};

test("root recovery V2 verifies exact rotated parent, original session and canonical certificate",async()=>{
  const verified=await verifyRecoveryClaim(claim,record,identity,proof);
  assert.equal(verified.version,2);
  assert.equal(verified.controlEpoch,2);
  assert.equal(verified.keyEpoch,2);
  assert.deepEqual(Buffer.from(verified.previousStateSha256),bytes(fixture.parentStateSha256));
  assert.equal(verified.canonicalCertificate[0],0xa9);
  assert.deepEqual(Buffer.from(verified.canonicalClaim),claim);
  await assert.rejects(verifyRecoveryClaim(claim,record,{...identity,sessionId:identity.authUserId},proof));
});

test("root recovery V2 rejects every truncation, unsupported version and signed-field mutation",async()=>{
  for(let end=0;end<claim.length;end++)assert.throws(()=>decodeRecoveryClaim(claim.subarray(0,end)));
  const trailing=Buffer.concat([claim,Buffer.of(0)]);assert.throws(()=>decodeRecoveryClaim(trailing));
  const unsupported=Buffer.from(claim);unsupported[2]=3;assert.throws(()=>decodeRecoveryClaim(unsupported));
  const decoded=decodeRecoveryClaim(claim);
  for(const name of ["previousStateSha256","canonicalRecordSha256","rootSignature","certificateSignature","ephemeralKey"]){
    const changed=Buffer.from(claim),offset=claim.indexOf(decoded[name]);assert.ok(offset>=0);changed[offset]^=1;
    await assert.rejects(verifyRecoveryClaim(changed,record,identity,proof));
  }
});

test("hosted adapter forwards exact V2 parent epochs certificate and root signature to the V2 CAS",async()=>{
  const calls=[];
  const dependencies=createSupabaseEnrollmentDependencies({
    env:{SUPABASE_URL:"https://example.supabase.co",SUPABASE_PUBLISHABLE_KEY:"sb_publishable_test",CONTEXT_RELAY_SUPABASE_SECRET_KEY:"sb_secret_test"},
    createClient:()=>({rpc:async(name,args)=>{calls.push({name,args});return {data:{},error:null};}})
  });
  const verified=await verifyRecoveryClaim(claim,record,identity,proof);
  await dependencies.restore({userId:identity.authUserId,sessionId:identity.sessionId},verified);
  assert.equal(calls[0].name,"service_commit_recovery_v2_for_session");
  assert.equal(calls[0].args.p_parent_sha256,"\\x"+fixture.parentStateSha256);
  assert.equal(calls[0].args.p_control_epoch,2);
  assert.equal(calls[0].args.p_key_epoch,2);
  assert.equal(calls[0].args.p_canonical_certificate,"\\x"+Buffer.from(verified.canonicalCertificate).toString("hex"));
  assert.equal(calls[0].args.p_root_signature,"\\x"+Buffer.from(verified.rootSignature).toString("hex"));
});

test("recovery HTTP actions validate exact owner scope and addressed missing public evidence",async()=>{
  const parsed=decodeRecoveryClaim(claim),calls=[];
  const scope={workspaceId:parsed.workspaceId,enrollmentSha256:Buffer.from(parsed.canonicalRecordSha256).toString("hex")};
  const handler=createEnrollmentEdgeHandler({
    authenticate:async()=>({userId:identity.authUserId,sessionId:identity.sessionId}),
    recoveryMembershipEndpoint:async(who,address)=>{calls.push({who,address});return {stateSha256:fixture.parentStateSha256,controlEpoch:2,keyEpoch:2};},
    recoveryMembershipEvent:async(who,address)=>{calls.push({who,address});return null;},
  });
  const post=body=>handler(new Request("https://example.test/enrollment",{method:"POST",headers:{"content-type":"application/json",authorization:"Bearer test"},body:JSON.stringify({v:1,...body})}));
  const response=await post({action:"recovery_membership_endpoint",...scope});
  assert.equal(response.status,200);
  assert.equal((await response.json()).endpoint.stateSha256,fixture.parentStateSha256);
  const missing=await post({action:"recovery_membership_event",...scope,successorSha256:"ab".repeat(32)});
  assert.equal(missing.status,200);assert.equal((await missing.json()).object,null);
  assert.equal(calls[0].who.sessionId,identity.sessionId);
  assert.equal((await post({action:"recovery_membership_event",...scope,successorSha256:"bad"})).status,400);
  assert.equal(calls.length,2);
});


test("terminal publication rejection requires verified V2 input and preserves other errors",async()=>{
  const parsed=decodeRecoveryClaim(claim);
  let failure="recovery_publication_rejected", calls=0;
  const handler=createEnrollmentEdgeHandler({
    authenticate:async()=>({userId:identity.authUserId,sessionId:identity.sessionId}),
    snapshot:async()=>({accountId:parsed.accountId,workspaceId:parsed.workspaceId,
      canonicalRecord:fixture.canonicalRecord,canonicalRecordSha256:Buffer.from(parsed.canonicalRecordSha256).toString("hex"),
      registeredAtMs:"1",recoveryGeneration:"0"}),
    restore:async()=>{calls++;throw Object.assign(new Error(failure),{code:failure});},
  });
  const post=(proofValue=fixture.proof)=>handler(new Request("https://example.test/enrollment",{method:"POST",
    headers:{"content-type":"application/json",authorization:"Bearer test"},
    body:JSON.stringify({v:1,action:"restore",claim:fixture.canonicalClaim,proof:proofValue})}));
  for(const [code,status] of [["recovery_publication_rejected",409],["recovery_conflict",409],["recovery_denied",403],["transient",503]]) {
    failure=code;const response=await post();assert.equal(response.status,status);
    assert.deepEqual(await response.json(),{v:1,error:code});
  }
  const before=calls;failure="recovery_publication_rejected";
  const malformed=await post("00".repeat(64));assert.equal(malformed.status,400);
  assert.deepEqual(await malformed.json(),{v:1,error:"invalid_request"});assert.equal(calls,before);
});
