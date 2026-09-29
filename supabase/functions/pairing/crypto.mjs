import { CanonicalReader } from '../sync/core.mjs';
import { readUuid7 } from '../enrollment/record.mjs';
import { verifyEd25519Strict, validateWrappingKey } from '../enrollment/crypto.mjs';

const DOMAIN = new TextEncoder().encode('context-relay/pairing-request/v1\0');
const invalid = () => new Error('invalid_pairing_request');

// Structural decoding grants no authority. The caller must verify the signature
// and bind the request to a live server-selected invite and authenticated session.
export function decodePairingRequest(input) {
  try {
    if (!(input instanceof Uint8Array) || input.length === 0 || input.length > 8192) throw invalid();
    const canonicalRequest = Uint8Array.from(input);
    const reader = new CanonicalReader(canonicalRequest);
    reader.expectMap(9);
    reader.expectUnsigned(0); reader.expectUnsigned(1);
    reader.expectUnsigned(1); const pairingId = readUuid7(reader);
    reader.expectUnsigned(2); const requestNonce = reader.fixedBytes(32);
    reader.expectUnsigned(3); const deviceId = readUuid7(reader);
    reader.expectUnsigned(4); const deviceName = reader.text(512);
    reader.expectUnsigned(5); const platform = Number(reader.unsigned(1n));
    reader.expectUnsigned(6); const signingPublicKey = reader.fixedBytes(32);
    reader.expectUnsigned(7); const wrappingPublicKey = reader.fixedBytes(32);
    const signatureOffset = reader.position;
    reader.expectUnsigned(8); const signature = reader.fixedBytes(64);
    if (reader.position !== canonicalRequest.length) throw invalid();
    const signingPreimage = new Uint8Array(DOMAIN.length + signatureOffset);
    signingPreimage.set(DOMAIN);
    signingPreimage.set(canonicalRequest.subarray(0, signatureOffset), DOMAIN.length);
    signingPreimage[DOMAIN.length] = 0xa8;
    return { canonicalRequest, signingPreimage, pairingId, requestNonce, deviceId,
      deviceName, platform, signingPublicKey, wrappingPublicKey, signature };
  } catch { throw invalid(); }
}

export async function verifyPairingRequest(input) {
  try {
    const request = decodePairingRequest(input);
    if (request.signingPublicKey.every((byte, index) => byte === request.wrappingPublicKey[index])) throw invalid();
    await verifyEd25519Strict(request.signingPublicKey, request.signature, request.signingPreimage);
    await validateWrappingKey(request.wrappingPublicKey);
    const requestDigest = new Uint8Array(await crypto.subtle.digest('SHA-256', request.canonicalRequest));
    return { ...request, requestDigest };
  } catch { throw invalid(); }
}
