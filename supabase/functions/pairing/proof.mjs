import { verifyEd25519Strict } from '../enrollment/crypto.mjs';

const invalid = () => new Error('invalid_pairing_proof');
function uuid(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value)) throw invalid();
  return Uint8Array.from(value.replaceAll('-', '').match(/../g), byte => Number.parseInt(byte, 16));
}

// The caller must first validate the canonical request/approval and select its
// device key from verified state. Proof verification does not grant authority.
export async function verifyPairingDeviceProof(context, operation, canonical, deviceKey, signature, v2) {
  try {
    const limit = operation === 'request' ? 8192 : operation === 'approval' ? 32768 : 0;
    if (!(canonical instanceof Uint8Array) || canonical.length === 0 || canonical.length > limit
      || !(deviceKey instanceof Uint8Array) || deviceKey.length !== 32
      || !(signature instanceof Uint8Array) || signature.length !== 64) throw invalid();
    canonical = Uint8Array.from(canonical);
    deviceKey = Uint8Array.from(deviceKey);
    signature = Uint8Array.from(signature);
    if(v2!==undefined && (operation!=='approval' || !(v2.requestDigest instanceof Uint8Array) || v2.requestDigest.length!==32 || !(v2.membershipSignature instanceof Uint8Array) || v2.membershipSignature.length!==64)) throw invalid();
    if(v2!==undefined) v2={requestDigest:Uint8Array.from(v2.requestDigest),membershipSignature:Uint8Array.from(v2.membershipSignature)};
    const prefix = Uint8Array.from([...new TextEncoder().encode(`context-relay/hosted-pairing-${operation}-proof/v${v2===undefined?1:2}\0`),
      ...uuid(context.authUserId), ...uuid(context.sessionId)]);
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', canonical));
    await verifyEd25519Strict(deviceKey, signature, Uint8Array.from([...prefix,...(v2?.requestDigest??[]), ...digest,...(v2?.membershipSignature??[])]));
  } catch { throw invalid(); }
}
