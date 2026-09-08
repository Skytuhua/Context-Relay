import { readBoundedBody } from "../account-lifecycle/core.mjs";
import { decodeEnrollmentRecord, verifyEnrollmentRecord } from "./record.mjs";

const MAX_BYTES = 68 * 1024;
const headers = { "content-type": "application/json", "cache-control": "no-store" };
const codes = { auth_required: 401, invalid_request: 400, request_too_large: 413,
  method_not_allowed: 405, enrollment_session_denied: 403, enrollment_reservation_denied: 403,
  enrollment_reservation_expired: 403, enrollment_requires_pairing: 409,
  enrollment_conflict: 409, enrollment_in_progress: 409, enrollment_rate_limited: 429 };
const fail = code => { throw Object.assign(new Error(code), { code }); };
const response = (status, body) => new Response(JSON.stringify(body), { status, headers });
const exact = (value, keys) => value !== null && typeof value === "object" && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
function uuid(value, version = "7") {
  if (typeof value !== "string" || !new RegExp(`^[0-9a-f]{8}-[0-9a-f]{4}-${version}[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).test(value)) fail("invalid_request");
  return value;
}
function hex(value, minimum, maximum = minimum) {
  if (typeof value !== "string" || value.length < minimum * 2 || value.length > maximum * 2
    || value.length % 2 !== 0 || !/^[0-9a-f]+$/.test(value)) fail("invalid_request");
  return Uint8Array.from(value.match(/../g), byte => Number.parseInt(byte, 16));
}
function timestamp(value) {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]{0,18})$/.test(value)
    || BigInt(value) > 9223372036854775807n) fail("invalid_request");
  return value;
}
function receipt(value) {
  if (!exact(value, ["enrollmentId", "recoveryRootId", "accountId", "workspaceId",
    "genesisCertificateId", "canonicalRecordSha256", "registeredAtMs"])) fail("invalid_request");
  for (const key of ["enrollmentId", "recoveryRootId", "accountId", "workspaceId", "genesisCertificateId"]) uuid(value[key]);
  hex(value.canonicalRecordSha256, 32); timestamp(value.registeredAtMs);
  return { ...value };
}
function reservation(value, reservationId, withReceipt) {
  const keys = ["reservationId", "accountId", "workspaceId", "nonce", "expiresAt"];
  if (withReceipt) keys.push("receipt");
  if (!exact(value, keys) || value.reservationId !== reservationId) fail("invalid_request");
  uuid(value.accountId); uuid(value.workspaceId); hex(value.nonce, 32); timestamp(value.expiresAt);
  const result = { ...value };
  if (withReceipt && result.receipt !== null) {
    result.receipt = receipt(result.receipt);
    if (result.receipt.accountId !== result.accountId || result.receipt.workspaceId !== result.workspaceId) fail("invalid_request");
  }
  return result;
}

async function snapshot(value) {
  if (value === null) return null;
  if (!exact(value, ["accountId", "workspaceId", "canonicalRecord", "canonicalRecordSha256",
    "registeredAtMs", "recoveryGeneration"])) fail("invalid_request");
  value = { ...value };
  uuid(value.accountId); uuid(value.workspaceId);
  timestamp(value.registeredAtMs); timestamp(value.recoveryGeneration);
  hex(value.canonicalRecordSha256, 32);
  const bytes = hex(value.canonicalRecord, 1, 32768);
  let record;
  try { record = decodeEnrollmentRecord(bytes); } catch { fail("invalid_request"); }
  const digest = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)), byte => byte.toString(16).padStart(2, "0")).join("");
  if (record.accountId !== value.accountId || record.workspaceId !== value.workspaceId
    || digest !== value.canonicalRecordSha256) fail("invalid_request");
  return { ...value };
}

export function createEnrollmentEdgeHandler(dependencies) {
  return async request => {
    try {
      if (request.method !== "POST") fail("method_not_allowed");
      if (request.headers.get("content-type")?.split(";", 1)[0].trim() !== "application/json") fail("invalid_request");
      const length = request.headers.get("content-length");
      if (length !== null) {
        if (!/^(0|[1-9][0-9]*)$/.test(length)) fail("invalid_request");
        if (BigInt(length) > BigInt(MAX_BYTES)) fail("request_too_large");
      }
      let body;
      try { body = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await readBoundedBody(request, MAX_BYTES))); }
      catch (error) { fail(error?.code === "request_too_large" ? error.code : "invalid_request"); }
      if (!body || body.v !== 1 || !["reserve", "renew", "status", "commit", "snapshot"].includes(body.action)
        || !exact(body, body.action === "snapshot" ? ["v", "action"] : body.action === "commit" ? ["v", "action", "reservationId", "record", "proof"] : ["v", "action", "reservationId"])) fail("invalid_request");
      const operation = body.action === "snapshot" ? null : uuid(body.reservationId);
      const canonical = body.action === "commit" ? hex(body.record, 1, 32768) : null;
      const proof = body.action === "commit" ? hex(body.proof, 64) : null;
      const authorization = request.headers.get("authorization");
      if (authorization === null || !/^Bearer [^\s]+$/.test(authorization)) fail("auth_required");
      const authenticated = await dependencies.authenticate(authorization.slice(7));
      const identity = { userId: uuid(authenticated.userId, "[1-8]"), sessionId: uuid(authenticated.sessionId, "[1-8]") };
      if (body.action === "snapshot") {
        return response(200, { v: 1, snapshot: await snapshot(await dependencies.snapshot(identity)) });
      }
      if (body.action === "reserve" || body.action === "renew") {
        const result = reservation(await dependencies[body.action](identity, operation), operation, false);
        return response(200, { v: 1, reservation: result });
      }
      const status = reservation(await dependencies.status(identity, operation), operation, true);
      if (body.action === "status") return response(200, { v: 1, reservation: status });
      let verified;
      try {
        verified = await verifyEnrollmentRecord(canonical, { reservationId: operation,
          authUserId: identity.userId, sessionId: identity.sessionId, nonce: hex(status.nonce, 32) }, proof);
      } catch { fail("invalid_request"); }
      if (verified.accountId !== status.accountId || verified.workspaceId !== status.workspaceId) fail("invalid_request");
      const result = receipt(await dependencies.commit(identity, operation, hex(status.nonce, 32), verified));
      const digest = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", canonical)), byte => byte.toString(16).padStart(2, "0")).join("");
      if (result.enrollmentId !== verified.enrollmentId || result.recoveryRootId !== verified.recoveryRootId
        || result.accountId !== verified.accountId || result.workspaceId !== verified.workspaceId
        || result.genesisCertificateId !== verified.certificateId || result.canonicalRecordSha256 !== digest) fail("enrollment_conflict");
      return response(200, { v: 1, receipt: result });
    } catch (error) {
      const code = Object.hasOwn(codes, error?.code) ? error.code : "transient";
      return response(codes[code] ?? 503, { v: 1, error: code });
    }
  };
}
