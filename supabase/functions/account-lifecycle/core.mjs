export const MAX_ACCOUNT_LIFECYCLE_REQUEST_BYTES = 16 * 1024;

const SEVEN_DAYS_MS = 7n * 24n * 60n * 60n * 1_000n;
const MAX_SIGNED_MS = 9_223_372_036_854_775_807n;
const JSON_HEADERS = Object.freeze({
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
});
const textDecoder = new TextDecoder("utf-8", { fatal: true });

class AccountLifecycleEdgeError extends Error {
  constructor(status, code) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

function response(status, body) {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
}

function safeError(error) {
  if (error instanceof AccountLifecycleEdgeError) {
    return response(error.status, { v: 1, error: error.code });
  }
  const code = typeof error?.code === "string" ? error.code : "";
  if (code === "auth_required") return response(401, { v: 1, error: code });
  if (code === "fresh_auth_required" || code === "revoked") {
    return response(403, { v: 1, error: code });
  }
  if (code === "invalid_request") return response(400, { v: 1, error: code });
  if (code === "conflict") return response(409, { v: 1, error: code });
  if (code === "rate_limited") return response(429, { v: 1, error: code });
  if (code === "configuration_error") return response(503, { v: 1, error: code });
  return response(503, { v: 1, error: "transient" });
}

function ownKeysExactly(value, expected) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const keys = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return keys.length === wanted.length && keys.every((key, index) => key === wanted[index]);
}

function strictAuthorization(request) {
  const header = request.headers.get("authorization");
  if (header === null || !/^Bearer [^\s]+$/.test(header)) {
    throw new AccountLifecycleEdgeError(401, "auth_required");
  }
  return header.slice("Bearer ".length);
}

async function readBoundedBody(request) {
  if (request.body === null) return new Uint8Array();
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) {
        throw new AccountLifecycleEdgeError(400, "invalid_request");
      }
      total += value.length;
      if (total > MAX_ACCOUNT_LIFECYCLE_REQUEST_BYTES) {
        try {
          await reader.cancel();
        } catch {
          // The byte limit stays authoritative even when the peer cannot be cancelled.
        }
        throw new AccountLifecycleEdgeError(413, "request_too_large");
      }
      chunks.push(value);
    }
  } catch (error) {
    if (error instanceof AccountLifecycleEdgeError) throw error;
    throw new AccountLifecycleEdgeError(400, "invalid_request");
  } finally {
    reader.releaseLock();
  }
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.length;
  }
  return body;
}

function workspaceId(value) {
  if (
    typeof value !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value)
  ) {
    throw new AccountLifecycleEdgeError(400, "invalid_request");
  }
  return value;
}

async function readRequest(request) {
  if (request.method !== "POST") {
    throw new AccountLifecycleEdgeError(405, "method_not_allowed");
  }
  const contentType = request.headers.get("content-type")?.split(";", 1)[0]?.trim();
  if (contentType !== "application/json") {
    throw new AccountLifecycleEdgeError(400, "invalid_request");
  }
  const contentLength = request.headers.get("content-length");
  if (contentLength !== null) {
    if (!/^(0|[1-9][0-9]*)$/.test(contentLength)) {
      throw new AccountLifecycleEdgeError(400, "invalid_request");
    }
    if (BigInt(contentLength) > BigInt(MAX_ACCOUNT_LIFECYCLE_REQUEST_BYTES)) {
      throw new AccountLifecycleEdgeError(413, "request_too_large");
    }
  }
  const bytes = await readBoundedBody(request);
  let body;
  try {
    body = JSON.parse(textDecoder.decode(bytes));
  } catch {
    throw new AccountLifecycleEdgeError(400, "invalid_request");
  }
  if (
    body === null || typeof body !== "object" || body.v !== 1 ||
    !["status", "begin_deletion", "cancel_deletion"].includes(body.action) ||
    !ownKeysExactly(body, body.action === "status"
      ? ["v", "action", "workspaceId"]
      : ["v", "action", "workspaceId", "requestId"])
  ) {
    throw new AccountLifecycleEdgeError(400, "invalid_request");
  }
  if (body.action !== "status" && (typeof body.requestId !== "string" || !/^[0-9a-f]{64}$/.test(body.requestId))) {
    throw new AccountLifecycleEdgeError(400, "invalid_request");
  }
  return { action: body.action, workspaceId: workspaceId(body.workspaceId), requestId: body.requestId };
}

function canonicalMs(value) {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) return null;
  const parsed = BigInt(value);
  return parsed <= MAX_SIGNED_MS ? parsed : null;
}

function exactProjection(value) {
  if (
    !ownKeysExactly(value, ["state", "requestedAtMs", "purgeDeadlineMs"]) ||
    !["active", "pending_delete", "purged"].includes(value.state)
  ) {
    throw new AccountLifecycleEdgeError(503, "transient");
  }
  if (value.state !== "pending_delete") {
    if (value.requestedAtMs !== null || value.purgeDeadlineMs !== null) {
      throw new AccountLifecycleEdgeError(503, "transient");
    }
    return value;
  }
  const requestedAt = canonicalMs(value.requestedAtMs);
  const purgeDeadline = canonicalMs(value.purgeDeadlineMs);
  if (
    requestedAt === null ||
    purgeDeadline === null ||
    requestedAt + SEVEN_DAYS_MS !== purgeDeadline
  ) {
    throw new AccountLifecycleEdgeError(503, "transient");
  }
  return value;
}

export function createAccountLifecycleEdgeHandler(dependencies) {
  if (
    dependencies === null ||
    typeof dependencies !== "object" ||
    typeof dependencies.authenticate !== "function" ||
    typeof dependencies.transition !== "function"
  ) {
    throw new TypeError("invalid account-lifecycle Edge dependencies");
  }

  return async function handleAccountLifecycleRequest(request) {
    try {
      const body = await readRequest(request);
      const token = strictAuthorization(request);
      const identity = await dependencies.authenticate(token, {
        requireFreshCredential: body.action !== "status",
      });
      if (
        identity === null ||
        typeof identity !== "object" ||
        typeof identity.userId !== "string" ||
        typeof identity.sessionId !== "string"
      ) {
        throw new AccountLifecycleEdgeError(401, "auth_required");
      }
      const projection = exactProjection(
        await dependencies.transition(identity, body.action, body.workspaceId, body.requestId),
      );
      return response(200, { v: 1, ...projection });
    } catch (error) {
      return safeError(error);
    }
  };
}
