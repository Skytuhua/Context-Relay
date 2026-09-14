import { createSupabaseSessionClients } from '../account-lifecycle/adapter.mjs';
import { authenticateSupabaseSession, bytea, uuid, uuid7 } from '../enrollment/adapter.mjs';
import { createPairingLocator, pairingLocatorDigest } from './locator.mjs';
import {verifyRecoveryRecord} from '../enrollment/record.mjs';

const safeCodes = new Set(['invalid_pairing_request','pairing_denied','pairing_conflict',
  'pairing_expired','pairing_canceled','pairing_rejected','pairing_rate_limited']);
const failure = (code='transient') => Object.assign(new Error(code),{code});
const authority = (scope,pairingId) => ({p_workspace_id:uuid(scope.workspaceId,'7'),p_device_id:uuid(scope.deviceId,'7'),
  ...(pairingId === undefined ? {} : {p_pairing_id:uuid(pairingId,'7')})});
const hexBytes=(value,min,max=min)=>{
  if(typeof value!=='string'||value.length<min*2||value.length>max*2||value.length%2!==0||!/^[0-9a-f]+$/.test(value)) throw failure('invalid_pairing_request');
  return Uint8Array.from(value.match(/../g),byte=>Number.parseInt(byte,16));
};

export function createSupabasePairingDependencies({createClient,env}) {
  if (typeof env?.CONTEXT_RELAY_PAIRING_PEPPER !== 'string' || !/^[0-9a-f]{64}$/.test(env.CONTEXT_RELAY_PAIRING_PEPPER)) throw failure('configuration_error');
  const pepper = Uint8Array.from(env.CONTEXT_RELAY_PAIRING_PEPPER.match(/../g),byte=>Number.parseInt(byte,16));
  const {authClient,serviceClient} = createSupabaseSessionClients({createClient,env});
  async function rpc(name,identity,parameters) {
    const args = {...parameters,p_auth_user_id:uuid(identity.userId),p_session_id:uuid(identity.sessionId)};
    let result;
    try { result = await serviceClient.rpc(name,args); } catch { throw failure(); }
    if (result?.error) throw failure(safeCodes.has(result.error.message) ? result.error.message : 'transient');
    if (result?.error !== null || result.data === undefined
      || (result.data === null && !['service_pairing_request_for_approver','service_pairing_membership_object'].includes(name))) throw failure();
    return result.data;
  }
  async function initialize(identity,scope) {
    const snapshot=await rpc('service_recovery_snapshot_for_session',identity,{});
    const canonical=hexBytes(snapshot?.canonicalRecord,1,32768);
    let record;
    try {record=await verifyRecoveryRecord(canonical);} catch {throw failure('pairing_conflict');}
    const pin=new Uint8Array(await crypto.subtle.digest('SHA-256',canonical));
    const expected=hexBytes(snapshot.canonicalRecordSha256,32);
    if(record.accountId!==snapshot.accountId||record.workspaceId!==snapshot.workspaceId||record.workspaceId!==scope.workspaceId
      ||pin.some((byte,index)=>byte!==expected[index])) throw failure('pairing_conflict');
    await rpc('service_initialize_committed_membership',identity,{p_workspace_id:uuid(scope.workspaceId,'7'),p_enrollment_sha256:bytea(pin)});
  }
  return {
    authenticate(token) { return authenticateSupabaseSession(authClient,token); },
    async create(identity,scope) {
      await initialize(identity,scope);
      const locator = await createPairingLocator(pepper);
      const result = await rpc('service_create_pairing_invite',identity,
        {...authority(scope),p_pairing_id:uuid7(),p_code_digest:bytea(locator.digest)});
      return {...result,code:locator.code};
    },
    async resolve(identity,code) {
      return rpc('service_resolve_pairing_code',identity,{p_code_digest:bytea(await pairingLocatorDigest(pepper,code))});
    },
    async control(identity,scope,pairingId,action) {
      if (action !== 'status' && action !== 'cancel') throw failure('invalid_request');
      return rpc('service_control_pairing_invite',identity,{...authority(scope,pairingId),p_action:action});
    },
    async request(identity,scope,pairingId) {
      return rpc('service_pairing_request_for_approver',identity,authority(scope,pairingId));
    },
    async verificationContext(identity,scope,pairingId) {
      return rpc('service_pairing_verification_context',identity,authority(scope,pairingId));
    },
    async membershipEndpoint(identity,scope) {
      await initialize(identity,scope);
      return rpc('service_membership_endpoint',identity,authority(scope));
    },
    async membershipObject(identity,pairingId,requestDigest,address,kind) {
      if(!['membership_enrollment','membership_event'].includes(kind)) throw failure('invalid_pairing_request');
      return rpc('service_pairing_membership_object',identity,{p_pairing_id:uuid(pairingId,'7'),
        p_request_digest:bytea(hexBytes(requestDigest,32)),p_address:bytea(hexBytes(address,32)),p_kind:kind});
    },
    async submit(identity,request) {
      return rpc('service_submit_pairing_request',identity,{p_pairing_id:uuid(request.pairingId,'7'),
        p_canonical_request:bytea(request.canonicalRequest),p_signing_key:bytea(request.signingPublicKey),
        p_wrapping_key:bytea(request.wrappingPublicKey)});
    },
    async decide(identity,scope,request,trusted,approval) {
      const v2=Object.hasOwn(trusted,'stateSha256');
      if(approval!==null && v2!==(approval.version===2)) throw failure('pairing_conflict');
      return rpc(v2?'service_decide_pairing_request_v2':'service_decide_pairing_request',identity,{...authority(scope,request.pairingId),
        p_request_digest:bytea(request.requestDigest),p_action:approval === null ? 'reject' : 'approve',
        p_control_epoch:trusted.controlEpoch,p_key_epoch:trusted.keyEpoch,
        p_approved_payload:approval === null ? null : bytea(approval.canonicalApprovedPayload),
        p_certificate_id:approval?.certificateId ?? null,p_child_device_id:approval?.child.deviceId ?? null,
        p_request_nonce:approval === null ? null : bytea(approval.child.requestNonce),
        p_signature:approval === null ? null : bytea(approval.child.signature),
        ...(v2?{p_previous_state_sha256:bytea(hexBytes(trusted.stateSha256,32)),p_enrollment_sha256:bytea(hexBytes(trusted.enrollmentSha256,32)),
          p_membership_signature:approval===null?null:bytea(approval.membershipSignature),p_canonical_certificate:approval===null?null:bytea(approval.child.canonical)}:{})});
    },
    async result(identity,pairingId,digest) {
      return rpc('service_pairing_result_for_session',identity,{p_pairing_id:uuid(pairingId,'7'),p_request_digest:bytea(digest)});
    },
  };
}
