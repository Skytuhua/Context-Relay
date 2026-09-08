import { CanonicalReader } from "../sync/core.mjs";
import { verifyEd25519Strict, validateWrappingKey } from "./crypto.mjs";
import { verifyEnrollmentDeviceProof } from "./proof.mjs";

const DOMAIN = new TextEncoder().encode("context-relay/recovery-enrollment-record/v1\0");
const hex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
function invalid() { return new Error("invalid_enrollment_record"); }
function id(reader) {
  const bytes = reader.fixedBytes(16);
  if (bytes[6] >> 4 !== 7 || bytes[8] >> 6 !== 2) throw invalid();
  const value = hex(bytes);
  return `${value.slice(0, 8)}-${value.slice(8, 12)}-${value.slice(12, 16)}-${value.slice(16, 20)}-${value.slice(20)}`;
}

// Cryptographic verification does not authorize enrollment. The service must
// still bind this result to a live, unexpired reservation and commit atomically.
export async function verifyEnrollmentRecord(input, context, proof) {
  try {
    const record = decodeEnrollmentRecord(input);
    if (!(context.nonce instanceof Uint8Array) || context.nonce.length !== 32
      || !(proof instanceof Uint8Array) || proof.length !== 64) throw invalid();
    context = { reservationId: context.reservationId, authUserId: context.authUserId,
      sessionId: context.sessionId, nonce: Uint8Array.from(context.nonce) };
    proof = Uint8Array.from(proof);
    const uuidBytes = value => Uint8Array.from(value.replaceAll("-", "").match(/../g), byte => Number.parseInt(byte, 16));
    const certificatePreimage = Uint8Array.from([
      ...new TextEncoder().encode("context-relay/device-certificate/v1\0"), 0,
      ...record.recoverySigningKey, ...uuidBytes(record.accountId), ...uuidBytes(record.workspaceId),
      0, 0, 0, 1, ...record.requestNonce, ...uuidBytes(record.deviceId),
      ...record.deviceSigningKey, ...record.deviceWrappingKey,
    ]);
    await verifyEd25519Strict(record.recoverySigningKey, record.certificateSignature, certificatePreimage);
    await verifyEd25519Strict(record.recoverySigningKey, record.rootSignature, record.signingPreimage);
    for (const key of [record.recoveryWrappingKey, record.deviceWrappingKey, record.ephemeralKey]) {
      await validateWrappingKey(key);
    }
    await verifyEnrollmentDeviceProof(context, record.canonicalRecord, record.deviceSigningKey, proof);
    return record;
  } catch { throw invalid(); }
}

// Structural decoding only: neither these fields nor their signatures confer
// authority until cryptographic verification and live reservation checks succeed.
export function decodeEnrollmentRecord(input) {
  try {
    if (!(input instanceof Uint8Array) || input.length === 0 || input.length > 32768) throw invalid();
    const canonicalRecord = Uint8Array.from(input);
    const reader = new CanonicalReader(canonicalRecord);
    reader.expectMap(14);
    reader.expectUnsigned(0); reader.expectUnsigned(1);
    reader.expectUnsigned(1); const enrollmentId = id(reader);
    reader.expectUnsigned(2); const recoveryRootId = id(reader);
    reader.expectUnsigned(3); const accountId = id(reader);
    reader.expectUnsigned(4); const workspaceId = id(reader);
    reader.expectUnsigned(5); const recoverySigningKey = reader.fixedBytes(32);
    reader.expectUnsigned(6); const recoveryWrappingKey = reader.fixedBytes(32);
    reader.expectUnsigned(7); const certificateId = id(reader);
    reader.expectUnsigned(8); reader.expectMap(9);
    reader.expectUnsigned(0); reader.expectMap(2);
    reader.expectUnsigned(0); reader.expectUnsigned(0);
    reader.expectUnsigned(1); const issuerKey = reader.fixedBytes(32);
    reader.expectUnsigned(1); const certificateAccount = id(reader);
    reader.expectUnsigned(2); const certificateWorkspace = id(reader);
    reader.expectUnsigned(3); reader.expectUnsigned(1);
    reader.expectUnsigned(4); const requestNonce = reader.fixedBytes(32);
    reader.expectUnsigned(5); const deviceId = id(reader);
    reader.expectUnsigned(6); const deviceSigningKey = reader.fixedBytes(32);
    reader.expectUnsigned(7); const deviceWrappingKey = reader.fixedBytes(32);
    reader.expectUnsigned(8); const certificateSignature = reader.fixedBytes(64);
    reader.expectUnsigned(9); const deviceName = reader.text(256);
    reader.expectUnsigned(10); const platform = Number(reader.unsigned(1n));
    reader.expectUnsigned(11); reader.expectUnsigned(1);
    reader.expectUnsigned(12); reader.expectMap(3);
    reader.expectUnsigned(0); const ephemeralKey = reader.fixedBytes(32);
    reader.expectUnsigned(1); const nonce = reader.fixedBytes(24);
    reader.expectUnsigned(2); const ciphertext = reader.byteString(32768);
    const signatureOffset = reader.position;
    reader.expectUnsigned(13); const rootSignature = reader.fixedBytes(64);
    if (reader.position !== canonicalRecord.length || ciphertext.length < 16
      || certificateAccount !== accountId || certificateWorkspace !== workspaceId
      || hex(issuerKey) !== hex(recoverySigningKey)
      || hex(recoverySigningKey) === hex(recoveryWrappingKey)
      || hex(deviceSigningKey) === hex(deviceWrappingKey)) throw invalid();
    const signingPreimage = new Uint8Array(DOMAIN.length + signatureOffset);
    signingPreimage.set(DOMAIN);
    signingPreimage.set(canonicalRecord.subarray(0, signatureOffset), DOMAIN.length);
    signingPreimage[DOMAIN.length] = 0xad; // Canonical map of the 13 unsigned fields.
    return { canonicalRecord, signingPreimage, enrollmentId, recoveryRootId,
      accountId, workspaceId, recoverySigningKey, recoveryWrappingKey, certificateId,
      requestNonce, deviceId, deviceSigningKey, deviceWrappingKey, certificateSignature,
      deviceName, platform, ephemeralKey, nonce, ciphertext, rootSignature };
  } catch {
    throw invalid();
  }
}
