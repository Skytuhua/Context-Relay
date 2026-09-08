import { CanonicalReader } from "../sync/core.mjs";
import { verifyEd25519Strict, validateWrappingKey } from "./crypto.mjs";
import { readUuid7, verifyRecoveryCertificate, verifyRecoveryRecord } from "./record.mjs";

import { verifyRecoveryDeviceProof } from "./proof.mjs";

const DOMAIN = new TextEncoder().encode("context-relay/recovery-device-claim/v1\0");
const equal = (a, b) => a.length === b.length && a.every((byte, index) => byte === b[index]);
const invalid = () => new Error("invalid_recovery_claim");

// This verifies the signed claim, not live session authority or generation CAS.
export async function verifyRecoveryClaim(input, rootInput, context, proof) {
  try {
    const claim = decodeRecoveryClaim(input);
    context = { authUserId: context.authUserId, sessionId: context.sessionId };
    if (!(proof instanceof Uint8Array) || proof.length !== 64) throw invalid();
    proof = Uint8Array.from(proof);
    const root = await verifyRecoveryRecord(rootInput);
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", root.canonicalRecord));
    if (claim.enrollmentId !== root.enrollmentId || claim.recoveryRootId !== root.recoveryRootId
      || claim.accountId !== root.accountId || claim.workspaceId !== root.workspaceId
      || !equal(claim.canonicalRecordSha256, digest)
      || !equal(claim.recoverySigningKey, root.recoverySigningKey)
      || claim.deviceId === root.deviceId || claim.certificateId === root.certificateId) throw invalid();
    await verifyRecoveryCertificate(claim);
    await verifyEd25519Strict(root.recoverySigningKey, claim.rootSignature, claim.signingPreimage);
    await validateWrappingKey(claim.deviceWrappingKey);
    await validateWrappingKey(claim.ephemeralKey);
    await verifyRecoveryDeviceProof(context, claim.canonicalClaim, claim.deviceSigningKey, proof);
    return claim;
  } catch { throw invalid(); }
}

export function decodeRecoveryClaim(input) {
  try {
    if (!(input instanceof Uint8Array) || input.length === 0 || input.length > 32768) throw invalid();
    const canonicalClaim = Uint8Array.from(input);
    const reader = new CanonicalReader(canonicalClaim);
    reader.expectMap(15);
    reader.expectUnsigned(0); reader.expectUnsigned(1);
    reader.expectUnsigned(1); const restoreId = readUuid7(reader);
    reader.expectUnsigned(2); const enrollmentId = readUuid7(reader);
    reader.expectUnsigned(3); const recoveryRootId = readUuid7(reader);
    reader.expectUnsigned(4); const accountId = readUuid7(reader);
    reader.expectUnsigned(5); const workspaceId = readUuid7(reader);
    reader.expectUnsigned(6); const canonicalRecordSha256 = reader.fixedBytes(32);
    reader.expectUnsigned(7); const expectedRecoveryGeneration = reader.unsigned(9223372036854775806n).toString();
    reader.expectUnsigned(8); const certificateId = readUuid7(reader);
    reader.expectUnsigned(9); reader.expectMap(9);
    reader.expectUnsigned(0); reader.expectMap(2);
    reader.expectUnsigned(0); reader.expectUnsigned(0);
    reader.expectUnsigned(1); const recoverySigningKey = reader.fixedBytes(32);
    reader.expectUnsigned(1); const certificateAccount = readUuid7(reader);
    reader.expectUnsigned(2); const certificateWorkspace = readUuid7(reader);
    reader.expectUnsigned(3); reader.expectUnsigned(1);
    reader.expectUnsigned(4); const requestNonce = reader.fixedBytes(32);
    reader.expectUnsigned(5); const deviceId = readUuid7(reader);
    reader.expectUnsigned(6); const deviceSigningKey = reader.fixedBytes(32);
    reader.expectUnsigned(7); const deviceWrappingKey = reader.fixedBytes(32);
    reader.expectUnsigned(8); const certificateSignature = reader.fixedBytes(64);
    reader.expectUnsigned(10); const deviceName = reader.text(256);
    reader.expectUnsigned(11); const platform = Number(reader.unsigned(1n));
    reader.expectUnsigned(12); reader.expectUnsigned(1);
    reader.expectUnsigned(13); const envelopeOffset = reader.position; reader.expectMap(3);
    reader.expectUnsigned(0); const ephemeralKey = reader.fixedBytes(32);
    reader.expectUnsigned(1); const nonce = reader.fixedBytes(24);
    reader.expectUnsigned(2); const ciphertext = reader.byteString(32768);
    const deviceMaterialEnvelope = canonicalClaim.subarray(envelopeOffset, reader.position);
    const signatureOffset = reader.position;
    reader.expectUnsigned(14); const rootSignature = reader.fixedBytes(64);
    if (reader.position !== canonicalClaim.length || ciphertext.length < 16 || deviceName.trim() === ""
      || certificateAccount !== accountId || certificateWorkspace !== workspaceId
      || equal(deviceSigningKey, deviceWrappingKey)) throw invalid();
    const signingPreimage = new Uint8Array(DOMAIN.length + signatureOffset);
    signingPreimage.set(DOMAIN);
    signingPreimage.set(canonicalClaim.subarray(0, signatureOffset), DOMAIN.length);
    signingPreimage[DOMAIN.length] = 0xae; // The 14 unsigned fields.
    return { canonicalClaim, signingPreimage, restoreId, enrollmentId, recoveryRootId,
      accountId, workspaceId, canonicalRecordSha256, expectedRecoveryGeneration, certificateId,
      recoverySigningKey, requestNonce, deviceId, deviceSigningKey, deviceWrappingKey,
      certificateSignature, deviceName, platform, ephemeralKey, nonce, ciphertext,
      deviceMaterialEnvelope, rootSignature };
  } catch { throw invalid(); }
}
