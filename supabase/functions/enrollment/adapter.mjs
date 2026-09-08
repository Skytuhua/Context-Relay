import { createSupabaseSessionClients } from "../account-lifecycle/adapter.mjs";

const safeCodes = new Set(["enrollment_session_denied", "enrollment_reservation_denied",
  "enrollment_reservation_expired", "enrollment_requires_pairing", "enrollment_conflict",
  "enrollment_in_progress", "enrollment_rate_limited"]);
function failure(code = "transient") { return Object.assign(new Error(code), { code }); }
function uuid(value, version = "[1-8]") {
  if (typeof value !== "string" || !new RegExp(`^[0-9a-f]{8}-[0-9a-f]{4}-${version}[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).test(value)) throw failure("invalid_request");
  return value;
}
const hex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
const bytea = bytes => "\\x" + hex(bytes);
function uuid7() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let time = BigInt(Date.now());
  for (let index = 5; index >= 0; index--) { bytes[index] = Number(time & 255n); time >>= 8n; }
  bytes[6] = (bytes[6] & 15) | 112; bytes[8] = (bytes[8] & 63) | 128;
  const value = hex(bytes);
  return `${value.slice(0,8)}-${value.slice(8,12)}-${value.slice(12,16)}-${value.slice(16,20)}-${value.slice(20)}`;
}

export function createSupabaseEnrollmentDependencies({ createClient, env }) {
  const { authClient, serviceClient } = createSupabaseSessionClients({ createClient, env });
  async function rpc(name, identity, operation, parameters = {}) {
    const args = { p_auth_user_id: uuid(identity.userId), p_session_id: uuid(identity.sessionId),
      ...parameters };
    if (operation !== undefined) args.p_reservation_id = uuid(operation, "7");
    let result;
    try { result = await serviceClient.rpc(name, args); } catch { throw failure(); }
    if (result?.error) throw failure(safeCodes.has(result.error.message) ? result.error.message : "transient");
    if (result?.error !== null || (result.data === null && operation !== undefined) || result.data === undefined) throw failure();
    return result.data;
  }
  return {
    async authenticate(token) {
      try {
        const result = await authClient.auth.getClaims(token);
        if (result?.error !== null || !result?.data?.claims) throw failure();
        return { userId: uuid(result.data.claims.sub), sessionId: uuid(result.data.claims.session_id) };
      } catch { throw failure("auth_required"); }
    },
    snapshot(identity) { return rpc("service_recovery_snapshot_for_session", identity); },
    reserve(identity, operation) {
      return rpc("service_reserve_enrollment_for_session", identity, operation, {
        p_account_id: uuid7(), p_workspace_id: uuid7(), p_nonce: bytea(crypto.getRandomValues(new Uint8Array(32))),
      });
    },
    status(identity, operation) { return rpc("service_enrollment_status_for_session", identity, operation); },
    renew(identity, operation) {
      return rpc("service_renew_enrollment_for_session", identity, operation, {
        p_nonce: bytea(crypto.getRandomValues(new Uint8Array(32))),
      });
    },
    commit(identity, operation, nonce, record) {
      return rpc("service_commit_enrollment_for_session", identity, operation, {
        p_nonce: bytea(nonce), p_account_id: record.accountId, p_workspace_id: record.workspaceId,
        p_enrollment_id: record.enrollmentId, p_root_id: record.recoveryRootId,
        p_certificate_id: record.certificateId, p_device_id: record.deviceId,
        p_request_nonce: bytea(record.requestNonce), p_root_signing_key: bytea(record.recoverySigningKey),
        p_root_wrapping_key: bytea(record.recoveryWrappingKey), p_device_signing_key: bytea(record.deviceSigningKey),
        p_device_wrapping_key: bytea(record.deviceWrappingKey), p_certificate_signature: bytea(record.certificateSignature),
        p_encrypted_metadata: bytea(record.encryptedMetadata), p_canonical_record: bytea(record.canonicalRecord),
      });
    },
  };
}
