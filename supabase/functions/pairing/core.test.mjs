import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { createPairingEdgeHandler } from './core.mjs';
import { createSupabasePairingDependencies } from './adapter.mjs';
import { verifyPairingRequest } from './crypto.mjs';

const fixture = JSON.parse(await readFile(new URL('../../../crates/core/tests/fixtures/hosted-pairing-approval-v1.json',import.meta.url),'utf8'));
const canonicalRequest = (await readFile(new URL('../../../crates/core/tests/fixtures/hosted-pairing-request-v1.hex',import.meta.url),'utf8')).trim();
const request = await verifyPairingRequest(Uint8Array.from(Buffer.from(canonicalRequest,'hex')));
const digest = Buffer.from(request.requestDigest).toString('hex');
const scope = { workspaceId:fixture.trusted.workspaceId,deviceId:fixture.trusted.issuerDeviceId,pairingId:request.pairingId };
const requestReceipt = {pairingId:request.pairingId,requestDigest:digest,requestedAt:'1000'};
const decisionReceipt = {pairingId:request.pairingId,requestDigest:digest,decision:'approved',
  approvedPayloadDigest:Buffer.from(await crypto.subtle.digest('SHA-256',Buffer.from(fixture.canonicalApprovedPayload,'hex'))).toString('hex'),decidedAt:'2000'};
function harness() {
  const calls = [];
  const dependencies = {
    authenticate:async ()=>({userId:fixture.proofs.authUserId,sessionId:fixture.proofs.sessionId}),
    verificationContext:async ()=>({canonicalRequest,trusted:{...fixture.trusted}}),
    submit:async (identity,verified)=>{ calls.push({action:'submit',identity,verified}); return {...requestReceipt}; },
    decide:async (identity,providedScope,verified,trusted,approval)=>{
      calls.push({action:'decide',identity,verified,trusted,approval,providedScope});
      return approval ? {...decisionReceipt} : {...decisionReceipt,decision:'rejected',approvedPayloadDigest:null};
    },
    request:async ()=>({...requestReceipt,canonicalRequest,accountId:fixture.trusted.accountId,workspaceId:scope.workspaceId}),
    result:async ()=>({status:'approved',canonicalApprovedPayload:fixture.canonicalApprovedPayload,receipt:{...decisionReceipt}}),
    create:async ()=>({pairingId:scope.pairingId,createdAt:'1000',expiresAt:'601000',code:'01234-56789'}),
    control:async (_identity,_scope,_id,action)=>({pairingId:scope.pairingId,createdAt:'1000',expiresAt:'601000',state:action==='cancel'?'canceled':'pending'}),
    resolve:async ()=>({status:'located',pairingId:scope.pairingId}),
  };
  const handler = createPairingEdgeHandler(dependencies);
  const call = body => handler(new Request('https://example.test/pairing',{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer token'},body:JSON.stringify({v:1,...body})}));
  return {calls,dependencies,handler,call};
}

test('HTTP pairing validates the frozen request and approval proofs before admission', async () => {
  const h = harness();
  assert.equal((await h.call({action:'submit',canonicalRequest,proof:fixture.proofs.request})).status,200);
  assert.equal(h.calls[0].identity.sessionId,fixture.proofs.sessionId);
  assert.equal(h.calls[0].verified.pairingId,scope.pairingId);
  const approval = {action:'approve',...scope,canonicalApprovedPayload:fixture.canonicalApprovedPayload,proof:fixture.proofs.approval};
  assert.equal((await h.call(approval)).status,200);
  assert.equal(h.calls.at(-1).approval.child.deviceId,request.deviceId);
  const count = h.calls.length;
  for (const body of [{...approval,proof:fixture.proofs.request},{...approval,canonicalApprovedPayload:fixture.canonicalApprovedPayload.slice(0,-2)+'00'},
    {action:'submit',canonicalRequest,proof:'00'.repeat(64)},{...approval,accountId:fixture.trusted.accountId}]) {
    assert.equal((await h.call(body)).status,400);
  }
  h.dependencies.authenticate=async ()=>({userId:fixture.proofs.authUserId,sessionId:'550e8400-e29b-41d4-a716-446655440002'});
  assert.equal((await h.call(approval)).status,400);
  assert.equal(h.calls.length,count);
});

test('HTTP pairing handles provider operations and rejects malformed or mismatched responses', async () => {
  const h = harness();
  for (const body of [{action:'create',workspaceId:scope.workspaceId,deviceId:scope.deviceId},
    {action:'resolve',code:'01234-56789'},{action:'status',...scope},{action:'cancel',...scope},{action:'request',...scope},
    {action:'reject',...scope,requestDigest:digest},{action:'result',pairingId:scope.pairingId,requestDigest:digest}]) {
    const response = await h.call(body); assert.equal(response.status,200); assert.equal(response.headers.get('cache-control'),'no-store');
  }
  h.dependencies.request=async ()=>null;
  assert.deepEqual(await (await h.call({action:'request',...scope})).json(),{v:1,request:null});
  h.dependencies.submit=async ()=>({...requestReceipt,requestDigest:'00'.repeat(32)});
  assert.equal((await h.call({action:'submit',canonicalRequest,proof:fixture.proofs.request})).status,409);
  h.dependencies.result=async ()=>({status:'approved',canonicalApprovedPayload:fixture.canonicalApprovedPayload,receipt:{...decisionReceipt,approvedPayloadDigest:'00'.repeat(32)}});
  assert.equal((await h.call({action:'result',pairingId:scope.pairingId,requestDigest:digest})).status,409);
  h.dependencies.resolve=async ()=>{throw new Error('private-provider-secret');};
  const failure = await h.call({action:'resolve',code:'01234-56789'});
  assert.equal(failure.status,503); assert.equal((await failure.text()).includes('private-provider-secret'),false);
});

test('HTTP pairing rejects unauthenticated, oversized and unknown requests before mutations', async () => {
  const h = harness();
  assert.equal((await h.handler(new Request('https://example.test/pairing'))).status,405);
  assert.equal((await h.handler(new Request('https://example.test/pairing',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({v:1,action:'resolve',code:'01234-56789'})}))).status,401);
  assert.equal((await h.call({action:'submit',canonicalRequest:'00'.repeat(8193),proof:fixture.proofs.request})).status,400);
  assert.equal((await h.call({action:'submit',canonicalRequest:'00'.repeat(70000),proof:fixture.proofs.request})).status,413);
  assert.equal((await h.call({action:'__proto__'})).status,400);
  assert.equal(h.calls.length,0);
});

test('composed HTTP and Supabase adapter pass only verified approval fields to the commit RPC', async () => {
  const calls=[];
  const dependencies=createSupabasePairingDependencies({env:{SUPABASE_URL:'https://example.supabase.co',
    SUPABASE_PUBLISHABLE_KEY:'sb_publishable_test',CONTEXT_RELAY_SUPABASE_SECRET_KEY:'sb_secret_test',CONTEXT_RELAY_PAIRING_PEPPER:'42'.repeat(32)},
    createClient:()=>({auth:{getClaims:async()=>({error:null,data:{claims:{sub:fixture.proofs.authUserId,session_id:fixture.proofs.sessionId}}})},
      rpc:async(name,args)=>{calls.push({name,args}); return {error:null,data:name==='service_pairing_verification_context'
        ? {canonicalRequest,trusted:{...fixture.trusted}} : {...decisionReceipt}};}})});
  const handler=createPairingEdgeHandler(dependencies);
  const send=proof=>handler(new Request('https://example.test/pairing',{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer test'},
    body:JSON.stringify({v:1,action:'approve',...scope,canonicalApprovedPayload:fixture.canonicalApprovedPayload,proof})}));
  assert.equal((await send(fixture.proofs.approval)).status,200);
  assert.deepEqual(calls.map(call=>call.name),['service_pairing_verification_context','service_decide_pairing_request']);
  const args=calls[1].args;
  assert.equal(args.p_auth_user_id,fixture.proofs.authUserId);
  assert.equal(args.p_session_id,fixture.proofs.sessionId);
  assert.equal(args.p_child_device_id,request.deviceId);
  assert.equal(args.p_control_epoch,fixture.trusted.controlEpoch);
  assert.equal(args.p_key_epoch,fixture.trusted.keyEpoch);
  assert.equal(args.p_approved_payload,'\\x'+fixture.canonicalApprovedPayload);
  assert.equal((await send(fixture.proofs.request)).status,400);
  assert.equal(calls.filter(call=>call.name==='service_decide_pairing_request').length,1);
});
