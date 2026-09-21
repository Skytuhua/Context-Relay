import { readBoundedBody } from '../account-lifecycle/core.mjs';
import { exact, uuid, hex, timestamp } from '../enrollment/core.mjs';
import { verifyPairingRequest } from './crypto.mjs';
import { verifyPairingApproval } from './approval.mjs';
import { verifyPairingDeviceProof } from './proof.mjs';
import { verifyRevocationObject } from './revocation.mjs';

const MAX_BYTES = 68 * 1024;
const REVOCATION_BYTES = 16_778_878;
const codes = {auth_required:401,invalid_request:400,invalid_pairing_request:400,request_too_large:413,
  method_not_allowed:405,pairing_denied:403,pairing_conflict:409,pairing_expired:410,
  pairing_canceled:409,pairing_rejected:409,pairing_rate_limited:429};
const fail = code => { throw Object.assign(new Error(code),{code}); };
const response = (status,body) => new Response(JSON.stringify(body),{status,headers:{'content-type':'application/json','cache-control':'no-store'}});
const toHex = bytes => Array.from(bytes,byte=>byte.toString(16).padStart(2,'0')).join('');
const digest = async bytes => toHex(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)));
const scoped = ['workspaceId','deviceId','pairingId'];
const fields = {create:['workspaceId','deviceId'],resolve:['code'],status:scoped,cancel:scoped,request:scoped,
  submit:['canonicalRequest','proof'],approve:[...scoped,'canonicalApprovedPayload','proof'],
  reject:[...scoped,'requestDigest'],result:['pairingId','requestDigest'],
  membership_endpoint:['workspaceId','deviceId'],
  membership_object:['workspaceId','deviceId','kind','address'],
  revocation_context:['workspaceId','deviceId','targetDeviceId'],
  revocation_result:['workspaceId','deviceId','operationId','objectSha256'],
  publish_revocation:['workspaceId','deviceId','object'],
  membership_enrollment:['pairingId','requestDigest','address'],
  membership_event:['pairingId','requestDigest','address']};
const locator = value => {
  if (typeof value !== 'string' || !/^[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}$/.test(value)) fail('invalid_request');
  return value;
};
async function verified(operation) { try { return await operation(); } catch { fail('invalid_request'); } }
function invite(value,pairingId,created=false) {
  if (!exact(value,['pairingId','createdAt','expiresAt',created?'code':'state'])) fail('invalid_request');
  uuid(value.pairingId); timestamp(value.createdAt); timestamp(value.expiresAt);
  if ((pairingId && value.pairingId!==pairingId) || BigInt(value.expiresAt)-BigInt(value.createdAt)!==600000n) fail('pairing_conflict');
  if (created) locator(value.code);
  else if (!['pending','canceled','approved','rejected'].includes(value.state)) fail('invalid_request');
  return {...value};
}
function receipt(value,pairingId,requestDigest,decision) {
  if (!exact(value,decision ? ['pairingId','requestDigest','decision','approvedPayloadDigest','decidedAt'] : ['pairingId','requestDigest','requestedAt'])) fail('invalid_request');
  uuid(value.pairingId); hex(value.requestDigest,32); timestamp(value[decision?'decidedAt':'requestedAt']);
  if (value.pairingId!==pairingId || value.requestDigest!==requestDigest) fail('pairing_conflict');
  if (decision) {
    if (value.decision!==decision) fail('pairing_conflict');
    if (decision==='approved') hex(value.approvedPayloadDigest,32);
    else if (value.approvedPayloadDigest!==null) fail('invalid_request');
  }
  return {...value};
}
async function context(value,scope,pairingId) {
  const v2=Object.hasOwn(value?.trusted??{},'stateSha256');
  if (!exact(value,['canonicalRequest','trusted']) || !exact(value.trusted,
    ['accountId','workspaceId','controlEpoch','keyEpoch','issuerDeviceId','issuerCertificateId','issuerSigningKey',...(v2?['issuerCertificate','stateSha256','enrollmentSha256']:['recoverySigningKey'])])) fail('invalid_request');
  const trusted = {...value.trusted};
  for (const key of ['accountId','workspaceId','issuerDeviceId','issuerCertificateId']) uuid(trusted[key]);
  for (const key of ['controlEpoch','keyEpoch']) if (!Number.isInteger(trusted[key]) || trusted[key]<1 || trusted[key]>0xffffffff) fail('invalid_request');
  hex(trusted.issuerSigningKey,32);
  if(v2) {hex(trusted.issuerCertificate,1,16384);hex(trusted.stateSha256,32);hex(trusted.enrollmentSha256,32);}
  else hex(trusted.recoverySigningKey,32);
  if (trusted.workspaceId!==scope.workspaceId || trusted.issuerDeviceId!==scope.deviceId) fail('pairing_conflict');
  const request = await verified(()=>verifyPairingRequest(hex(value.canonicalRequest,1,8192)));
  if (request.pairingId!==pairingId) fail('pairing_conflict');
  return {trusted,request};
}

export function createPairingEdgeHandler(dependencies) {
  return async request => {
    try {
      if (request.method!=='POST') fail('method_not_allowed');
      if (request.headers.get('content-type')?.split(';',1)[0].trim()!=='application/json') fail('invalid_request');
      const publication=new URL(request.url).pathname.endsWith('/revocation-publish');
      const requestLimit=publication?REVOCATION_BYTES:MAX_BYTES;
      const length=request.headers.get('content-length');
      if (length!==null) {
        if (!/^(0|[1-9][0-9]*)$/.test(length)) fail('invalid_request');
        if (BigInt(length)>BigInt(requestLimit)) fail('request_too_large');
      }
      let body;
      try { body=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(await readBoundedBody(request,requestLimit))); }
      catch (error) { fail(error?.code==='request_too_large' ? error.code : 'invalid_request'); }
      if (!body || body.v!==1 || typeof body.action!=='string' || !Object.hasOwn(fields,body.action)
        || !exact(body,['v','action',...fields[body.action],...(body.action==='approve' && Object.hasOwn(body,'membershipSignature')?['membershipSignature']:[])])) fail('invalid_request');
      if(publication!==(body.action==='publish_revocation')) fail('invalid_request');
      const scope=Object.hasOwn(body,'workspaceId') ? {workspaceId:uuid(body.workspaceId),deviceId:uuid(body.deviceId)} : null;
      const pairingId=Object.hasOwn(body,'pairingId') ? uuid(body.pairingId) : null;
      const requestDigest=Object.hasOwn(body,'requestDigest') ? toHex(hex(body.requestDigest,32)) : null;
      const canonical=body.action==='submit' ? hex(body.canonicalRequest,1,8192)
        : body.action==='approve' ? hex(body.canonicalApprovedPayload,1,32768) : null;
      const proof=canonical ? hex(body.proof,64) : null;
      const membershipSignature=Object.hasOwn(body,'membershipSignature')?hex(body.membershipSignature,64):undefined;
      if (body.action==='resolve') locator(body.code);
      const authorization=request.headers.get('authorization');
      if (authorization===null || !/^Bearer [^\s]+$/.test(authorization)) fail('auth_required');
      const authenticated=await dependencies.authenticate(authorization.slice(7));
      const identity={userId:uuid(authenticated.userId,'[1-8]'),sessionId:uuid(authenticated.sessionId,'[1-8]')};
      const proofContext={authUserId:identity.userId,sessionId:identity.sessionId};
      if (body.action==='membership_endpoint') {
        const endpoint=await dependencies.membershipEndpoint(identity,scope);
        if (!exact(endpoint,['stateSha256','controlEpoch','keyEpoch'])) fail('invalid_request');
        hex(endpoint.stateSha256,32);
        if (endpoint.stateSha256==='00'.repeat(32)) fail('invalid_request');
        for(const key of ['controlEpoch','keyEpoch']) if(!Number.isInteger(endpoint[key]) || endpoint[key]<1 || endpoint[key]>0xffffffff) fail('invalid_request');
        return response(200,{v:1,endpoint:{...endpoint}});
      }
      if(body.action==='membership_object') {
        if(!['enrollment','event'].includes(body.kind)) fail('invalid_request');
        const address=toHex(hex(body.address,32));
        const object=await dependencies.acceptedMembershipObject(identity,scope,body.kind,address);
        if(object!==null) hex(object,1,16*1024*1024);
        return response(200,{v:1,object});
      }
      if(body.action==='revocation_context') {
        const targetDeviceId=uuid(body.targetDeviceId);
        const value=await dependencies.revocationContext(identity,scope,targetDeviceId);
        if(!exact(value,['endpoint','targetDeviceId','head'])||value.targetDeviceId!==targetDeviceId
          ||!exact(value.head,['sequence','canonicalSha256'])) fail('invalid_request');
        hex(value.endpoint.stateSha256,32);hex(value.head.canonicalSha256,32);timestamp(value.head.sequence);
        if(value.endpoint.stateSha256==='00'.repeat(32)) fail('invalid_request');
        for(const key of ['controlEpoch','keyEpoch']) if(!Number.isInteger(value.endpoint[key])||value.endpoint[key]<1||value.endpoint[key]>0xffffffff) fail('invalid_request');
        if((value.head.sequence==='0')!==(value.head.canonicalSha256==='00'.repeat(32))) fail('invalid_request');
        return response(200,{v:1,...value});
      }
      if(body.action==='revocation_result') {
        const operationId=uuid(body.operationId),objectSha256=toHex(hex(body.objectSha256,32));
        const value=await dependencies.revocationResult(identity,scope,operationId,objectSha256);
        return response(200,{v:1,receipt:revocationReceipt(value,operationId,objectSha256)});
      }
      if(body.action==='publish_revocation') {
        const object=hex(body.object,319,8388927);
        const trusted=await dependencies.revocationVerificationContext(identity,scope);
        const parsed=await verified(()=>verifyRevocationObject(object,trusted));
        const value=await dependencies.publishRevocation(identity,scope,parsed);
        if(value===null) fail('pairing_conflict');
        return response(200,{v:1,receipt:revocationReceipt(value,parsed.operationId,toHex(parsed.objectSha256))});
      }
      if (body.action==='membership_enrollment' || body.action==='membership_event') {
        const address=toHex(hex(body.address,32));
        const object=await dependencies.membershipObject(identity,pairingId,requestDigest,address,body.action);
        if(object!==null) hex(object,1,16*1024*1024);
        return response(200,{v:1,object});
      }
      if (body.action==='create') return response(200,{v:1,invite:invite(await dependencies.create(identity,scope),null,true)});
      if (body.action==='status' || body.action==='cancel') {
        const value=invite(await dependencies.control(identity,scope,pairingId,body.action),pairingId);
        if (body.action==='cancel' && value.state!=='canceled') fail('pairing_conflict');
        return response(200,{v:1,invite:value});
      }
      if (body.action==='resolve') {
        const value=await dependencies.resolve(identity,body.code);
        if (!exact(value,value?.status==='located'?['status','pairingId']:['status'])) fail('invalid_request');
        if (value.status==='located') uuid(value.pairingId);
        else if (!['invalid','exhausted','expired','canceled','rejected','conflict'].includes(value.status)) fail('invalid_request');
        return response(200,{v:1,result:{...value}});
      }
      if (body.action==='submit') {
        const value=await verified(()=>verifyPairingRequest(canonical));
        await verified(()=>verifyPairingDeviceProof(proofContext,'request',canonical,value.signingPublicKey,proof));
        return response(200,{v:1,receipt:receipt(await dependencies.submit(identity,value),value.pairingId,toHex(value.requestDigest))});
      }
      if (body.action==='approve' || body.action==='reject') {
        const {trusted,request:stored}=await context(await dependencies.verificationContext(identity,scope,pairingId),scope,pairingId);
        let approval=null;
        if (body.action==='approve') {
          if(Object.hasOwn(trusted,'stateSha256') !== (membershipSignature!==undefined)) fail('pairing_conflict');
          approval=await verified(()=>verifyPairingApproval(canonical,stored.canonicalRequest,trusted,membershipSignature));
          await verified(()=>verifyPairingDeviceProof(proofContext,'approval',canonical,hex(trusted.issuerSigningKey,32),proof,membershipSignature===undefined?undefined:{membershipSignature,requestDigest:stored.requestDigest}));
        } else if (requestDigest!==toHex(stored.requestDigest)) fail('pairing_conflict');
        const decision=approval ? 'approved' : 'rejected';
        const value=receipt(await dependencies.decide(identity,scope,stored,trusted,approval),pairingId,toHex(stored.requestDigest),decision);
        if (approval && value.approvedPayloadDigest!==toHex(approval.approvedPayloadDigest)) fail('pairing_conflict');
        return response(200,{v:1,receipt:value});
      }
      if (body.action==='request') {
        const value=await dependencies.request(identity,scope,pairingId);
        if (value===null) return response(200,{v:1,request:null});
        if (!exact(value,['pairingId','accountId','workspaceId','canonicalRequest','requestDigest','requestedAt'])) fail('invalid_request');
        uuid(value.accountId); uuid(value.workspaceId);
        if (value.workspaceId!==scope.workspaceId) fail('pairing_conflict');
        const stored=await verified(()=>verifyPairingRequest(hex(value.canonicalRequest,1,8192)));
        if (stored.pairingId!==pairingId) fail('pairing_conflict');
        receipt({pairingId:value.pairingId,requestDigest:value.requestDigest,requestedAt:value.requestedAt},pairingId,toHex(stored.requestDigest));
        return response(200,{v:1,request:{...value}});
      }
      const value=await dependencies.result(identity,pairingId,hex(requestDigest,32));
      const state=value?.status;
      if (state==='pending' || state==='canceled') {
        if (!exact(value,['status'])) fail('invalid_request');
      } else if (state==='approved' || state==='rejected') {
        if (!exact(value,state==='approved'?['status','canonicalApprovedPayload','receipt',...(Object.hasOwn(value,'membershipSignature')?['membershipSignature']:[])]:['status','receipt'])) fail('invalid_request');
        if(Object.hasOwn(value,'membershipSignature')) hex(value.membershipSignature,64);
        receipt(value.receipt,pairingId,requestDigest,state);
        if (state==='approved' && await digest(hex(value.canonicalApprovedPayload,1,32768))!==value.receipt.approvedPayloadDigest) fail('pairing_conflict');
      } else fail('invalid_request');
      return response(200,{v:1,result:{...value}});
    } catch (error) {
      const code=Object.hasOwn(codes,error?.code) ? error.code : 'transient';
      return response(codes[code]??503,{v:1,error:code});
    }
  };
}

function revocationReceipt(value,operationId,objectSha256) {
  if(value===null) return null;
  if(!exact(value,['operationId','objectSha256','parent','successor'])||value.operationId!==operationId||value.objectSha256!==objectSha256) fail('pairing_conflict');
  for(const endpoint of [value.parent,value.successor]) {
    if(!exact(endpoint,['stateSha256','controlEpoch','keyEpoch'])) fail('invalid_request');
    hex(endpoint.stateSha256,32);
    if(endpoint.stateSha256==='00'.repeat(32)) fail('invalid_request');
    for(const key of ['controlEpoch','keyEpoch']) if(!Number.isInteger(endpoint[key])||endpoint[key]<1||endpoint[key]>0xffffffff) fail('invalid_request');
  }
  return {...value,parent:{...value.parent},successor:{...value.successor}};
}
