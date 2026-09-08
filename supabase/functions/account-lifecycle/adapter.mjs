const MAX_FRESH_CREDENTIAL_AGE_SECONDS = 300;
const SAFE_PROVIDER_CODES = new Set([
  "auth_required",
  "fresh_auth_required",
  "revoked",
  "invalid_request",
  "conflict",
  "configuration_error",
  "rate_limited",
]);
const CLIENT_OPTIONS = Object.freeze({
  auth: Object.freeze({
    persistSession: false,
    autoRefreshToken: false,
    detectSessionInUrl: false,
  }),
});
const RPC_NAMES = Object.freeze({
  status: "service_account_deletion_status_for_session",
  begin_deletion: "service_begin_account_deletion_for_session",
  cancel_deletion: "service_cancel_account_deletion_for_session",
});

function providerError(error, fallback = "transient") {
  const message = typeof error?.message === "string" ? error.message : "";
  const code = SAFE_PROVIDER_CODES.has(message) ? message : fallback;
  return Object.assign(new Error(code), { code });
}

function requiredEnvironment(env, name) {
  const value = env?.[name];
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value) {
    throw providerError(null, "configuration_error");
  }
  return value;
}

function projectUrl(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw providerError(null, "configuration_error");
  }
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== "" ||
    (url.pathname !== "" && url.pathname !== "/")
  ) {
    throw providerError(null, "configuration_error");
  }
  return url.origin;
}

function uuid(value) {
  if (
    typeof value !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value)
  ) {
    throw providerError(null, "auth_required");
  }
  return value;
}

function workspaceId(value) {
  if (
    typeof value !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value)
  ) {
    throw providerError(null, "invalid_request");
  }
  return value;
}

function requireFreshOAuth(claims, nowSeconds) {
  const entry = Array.isArray(claims.amr) ? claims.amr[0] : null;
  if (
    entry === null ||
    typeof entry !== "object" ||
    entry.method !== "oauth" ||
    !Number.isSafeInteger(entry.timestamp) ||
    !Number.isSafeInteger(nowSeconds)
  ) {
    throw providerError(null, "fresh_auth_required");
  }
  const age = nowSeconds - entry.timestamp;
  if (age < 0 || age > MAX_FRESH_CREDENTIAL_AGE_SECONDS) {
    throw providerError(null, "fresh_auth_required");
  }
  return entry.timestamp;
}

function exactProjection(value) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    !["active", "pending_delete", "purged"].includes(value.state) ||
    !Object.hasOwn(value, "requestedAtMs") ||
    !Object.hasOwn(value, "purgeDeadlineMs") ||
    Object.keys(value).length !== 3 ||
    (value.requestedAtMs !== null && typeof value.requestedAtMs !== "string") ||
    (value.purgeDeadlineMs !== null && typeof value.purgeDeadlineMs !== "string")
  ) {
    throw providerError(null);
  }
  return {
    state: value.state,
    requestedAtMs: value.requestedAtMs,
    purgeDeadlineMs: value.purgeDeadlineMs,
  };
}

export function createSupabaseAccountLifecycleDependencies({
  createClient,
  env,
  nowSeconds = () => Math.floor(Date.now() / 1_000),
}) {
  if (typeof createClient !== "function" || typeof nowSeconds !== "function") {
    throw providerError(null, "configuration_error");
  }
  const url = projectUrl(requiredEnvironment(env, "SUPABASE_URL"));
  const publishableKey = requiredEnvironment(env, "SUPABASE_PUBLISHABLE_KEY");
  const secretKey = requiredEnvironment(env, "CONTEXT_RELAY_SUPABASE_SECRET_KEY");
  const authClient = createClient(url, publishableKey, CLIENT_OPTIONS);
  const serviceClient = createClient(url, secretKey, CLIENT_OPTIONS);

  return {
    async authenticate(token, { requireFreshCredential }) {
      let result;
      try {
        result = await authClient.auth.getClaims(token);
      } catch (error) {
        throw providerError(error, "auth_required");
      }
      if (result?.error !== null || result?.data?.claims === undefined) {
        throw providerError(result?.error, "auth_required");
      }
      const claims = result.data.claims;
      const identity = {
        userId: uuid(claims.sub),
        sessionId: uuid(claims.session_id),
      };
      if (requireFreshCredential === true) {
        identity.credentialAuthenticatedAtSeconds = requireFreshOAuth(claims, nowSeconds());
      }
      else if (requireFreshCredential !== false) throw providerError(null, "invalid_request");
      return identity;
    },

    async transition(identity, action, requestedWorkspaceId, requestId) {
      if (!Object.hasOwn(RPC_NAMES, action)) throw providerError(null, "invalid_request");
      const name = RPC_NAMES[action];
      const parameters = {
        p_auth_user_id: uuid(identity.userId),
        p_session_id: uuid(identity.sessionId),
        p_workspace_id: workspaceId(requestedWorkspaceId),
      };
      if (action !== "status") {
        if (!Number.isSafeInteger(identity.credentialAuthenticatedAtSeconds)) {
          throw providerError(null, "fresh_auth_required");
        }
        parameters.p_credential_authenticated_at_seconds = identity.credentialAuthenticatedAtSeconds;
        if (typeof requestId !== "string" || !/^[0-9a-f]{64}$/.test(requestId)) {
          throw providerError(null, "invalid_request");
        }
        parameters.p_request_id = `\\x${requestId}`;
      }
      let result;
      try {
        result = await serviceClient.rpc(name, parameters);
      } catch (error) {
        throw providerError(error);
      }
      if (result?.error !== null) throw providerError(result?.error);
      return exactProjection(result?.data);
    },
  };
}
