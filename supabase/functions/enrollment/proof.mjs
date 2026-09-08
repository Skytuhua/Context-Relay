import { verifyEd25519Strict } from "./crypto.mjs";

const DOMAIN = new TextEncoder().encode("context-relay/hosted-enrollment-device-proof/v1\0");

function invalid() {
  return Object.assign(new Error("invalid_enrollment_proof"), { code: "invalid_enrollment_proof" });
}

function uuid(value, version) {
  if (typeof value !== "string" || !new RegExp(`^[0-9a-f]{8}-[0-9a-f]{4}-${version}[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).test(value)) throw invalid();
  return Uint8Array.from(value.replaceAll("-", "").match(/../g), byte => Number.parseInt(byte, 16));
}

function bytes(value, length) {
  if (!(value instanceof Uint8Array) || value.length !== length) throw invalid();
  return value;
}

// Call only after validating the canonical record and extracting its certified
// device key, and checking the reservation against the verified live Auth session.
export async function verifyEnrollmentDeviceProof(context, canonicalRecord, deviceKey, signature) {
  if (!(canonicalRecord instanceof Uint8Array) || canonicalRecord.length === 0 || canonicalRecord.length > 32 * 1024) throw invalid();
  const parts = [DOMAIN, uuid(context.reservationId, "7"), uuid(context.authUserId, "[1-8]"),
    uuid(context.sessionId, "[1-8]"), bytes(context.nonce, 32),
    new Uint8Array(await crypto.subtle.digest("SHA-256", canonicalRecord))];
  const preimage = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) { preimage.set(part, offset); offset += part.length; }
  try {
    await verifyEd25519Strict(bytes(deviceKey, 32), bytes(signature, 64), preimage);
  } catch {
    throw invalid();
  }
}

// Exact claim retries are idempotent; user/session binding prevents a copied
// root-signed claim from enrolling a different authenticated session.
export async function verifyRecoveryDeviceProof(context, canonicalClaim, deviceKey, signature) {
  if (!(canonicalClaim instanceof Uint8Array) || canonicalClaim.length === 0 || canonicalClaim.length > 32768) throw invalid();
  canonicalClaim = Uint8Array.from(canonicalClaim);
  deviceKey = Uint8Array.from(bytes(deviceKey, 32));
  signature = Uint8Array.from(bytes(signature, 64));
  const parts = [new TextEncoder().encode("context-relay/hosted-recovery-device-proof/v1\0"),
    uuid(context.authUserId, "[1-8]"), uuid(context.sessionId, "[1-8]")];
  parts.push(new Uint8Array(await crypto.subtle.digest("SHA-256", canonicalClaim)));
  const preimage = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) { preimage.set(part, offset); offset += part.length; }
  await verifyEd25519Strict(deviceKey, signature, preimage);
}
