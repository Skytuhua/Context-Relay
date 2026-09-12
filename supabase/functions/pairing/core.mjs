import { readBoundedBody } from '../account-lifecycle/core.mjs';
import { exact, uuid, hex, timestamp } from '../enrollment/core.mjs';
import { verifyPairingRequest } from './crypto.mjs';
import { verifyPairingApproval } from './approval.mjs';
import { verifyPairingDeviceProof } from './proof.mjs';

const MAX_BYTES = 68 * 1024;
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
  reject:[...scoped,'requestDigest'],result:['pairingId','requestDigest']};
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
  if (!exact(value,['canonicalRequest','trusted']) || !exact(value.trusted,
    ['accountId','workspaceId','controlEpoch','keyEpoch','issuerDeviceId','issuerCertificateId','issuerSigningKey','recoverySigningKey'])) fail('invalid_request');
  const trusted = {...value.trusted};
  for (const key of ['accountId','workspaceId','issuerDeviceId','issuerCertificateId']) uuid(trusted[key]);
  for (const key of ['controlEpoch','keyEpoch']) if (!Number.isInteger(trusted[key]) || trusted[key]<1 || trusted[key]>0xffffffff) fail('invalid_request');
  hex(trusted.issuerSigningKey,32); hex(trusted.recoverySigningKey,32);
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
      const length=request.headers.get('content-length');
      if (length!==null) {
        if (!/^(0|[1-9][0-9]*)$/.test(length)) fail('invalid_request');
        if (BigInt(length)>BigInt(MAX_BYTES)) fail('request_too_large');
      }
      let body;
      try { body=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(await readBoundedBody(request,MAX_BYTES))); }
      catch (error) { fail(error?.code==='request_too_large' ? error.code : 'invalid_request'); }
      if (!body || body.v!==1 || typeof body.action!=='string' || !Object.hasOwn(fields,body.action)
        || !exact(body,['v','action',...fields[body.action]])) fail('invalid_request');
      const scope=Object.hasOwn(body,'workspaceId') ? {workspaceId:uuid(body.workspaceId),deviceId:uuid(body.deviceId)} : null;
      const pairingId=Object.hasOwn(body,'pairingId') ? uuid(body.pairingId) : null;
      const requestDigest=Object.hasOwn(body,'requestDigest') ? toHex(hex(body.requestDigest,32)) : null;
      const canonical=body.action==='submit' ? hex(body.canonicalRequest,1,8192)
        : body.action==='approve' ? hex(body.canonicalApprovedPayload,1,32768) : null;
      const proof=canonical ? hex(body.proof,64) : null;
      if (body.action==='resolve') locator(body.code);
      const authorization=request.headers.get('authorization');
      if (authorization===null || !/^Bearer [^\s]+$/.test(authorization)) fail('auth_required');
      const authenticated=await dependencies.authenticate(authorization.slice(7));
      const identity={userId:uuid(authenticated.userId,'[1-8]'),sessionId:uuid(authenticated.sessionId,'[1-8]')};
      const proofContext={authUserId:identity.userId,sessionId:identity.sessionId};
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
          approval=await verified(()=>verifyPairingApproval(canonical,stored.canonicalRequest,trusted));
          await verified(()=>verifyPairingDeviceProof(proofContext,'approval',canonical,hex(trusted.issuerSigningKey,32),proof));
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
        if (!exact(value,state==='approved'?['status','canonicalApprovedPayload','receipt']:['status','receipt'])) fail('invalid_request');
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
