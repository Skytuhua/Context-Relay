import test from 'node:test';
import assert from 'node:assert/strict';
import { createPairingEdgeHandler } from './core.mjs';

const identity={userId:'550e8400-e29b-41d4-a716-446655440000',sessionId:'550e8400-e29b-41d4-a716-446655440001'};
const workspaceId='018f22e2-79b0-7cc8-98c4-dc0c0c073981';
const deviceId='018f22e2-79b0-7cc8-98c4-dc0c0c073982';
const pairingId='018f22e2-79b0-7cc8-98c4-dc0c0c073983';
const address='12'.repeat(32),requestDigest='34'.repeat(32);
function harness() {
  const calls=[];
  const dependencies={
    authenticate:async()=>identity,
    membershipEndpoint:async (...args)=>{calls.push(args);return {stateSha256:address,controlEpoch:2,keyEpoch:2};},
    membershipObject:async (...args)=>{calls.push(args);return null;},
  };
  const handler=createPairingEdgeHandler(dependencies);
  const call=body=>handler(new Request('https://example.test/pairing',{method:'POST',headers:{'content-type':'application/json',authorization:'Bearer test'},body:JSON.stringify({v:1,...body})}));
  return {calls,dependencies,call};
}
test('addressed membership inventory binds live identity and scope; missing remains explicit',async()=>{
  const h=harness();
  const head=await h.call({action:'membership_endpoint',workspaceId,deviceId});
  assert.equal(head.status,200);
  assert.deepEqual(await head.json(),{v:1,endpoint:{stateSha256:address,controlEpoch:2,keyEpoch:2}});
  assert.deepEqual(h.calls[0],[identity,{workspaceId,deviceId}]);
  for(const action of ['membership_enrollment','membership_event']) {
    const result=await h.call({action,pairingId,requestDigest,address});
    assert.equal(result.status,200);
    assert.deepEqual(await result.json(),{v:1,object:null});
    assert.deepEqual(h.calls.at(-1),[identity,pairingId,requestDigest,address,action]);
  }
  h.dependencies.membershipObject=async()=>{throw Object.assign(new Error('pairing_denied'),{code:'pairing_denied'});};
  assert.equal((await h.call({action:'membership_event',pairingId,requestDigest,address})).status,403);
});
test('membership inventory rejects malformed addresses and unbounded provider bytes',async()=>{
  const h=harness();
  assert.equal((await h.call({action:'membership_event',pairingId,requestDigest,address:'12',endpoint:address})).status,400);
  assert.equal(h.calls.length,0);
  h.dependencies.membershipObject=async()=> '00'.repeat(16*1024*1024+1);
  assert.equal((await h.call({action:'membership_event',pairingId,requestDigest,address})).status,400);
  h.dependencies.membershipEndpoint=async()=>({stateSha256:address,controlEpoch:0,keyEpoch:2});
  assert.equal((await h.call({action:'membership_endpoint',workspaceId,deviceId})).status,400);
});
