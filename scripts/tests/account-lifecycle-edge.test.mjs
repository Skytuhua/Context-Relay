import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";

const coreModule = import("../../supabase/functions/account-lifecycle/core.mjs").catch(() => ({}));
const adapterModule = import("../../supabase/functions/account-lifecycle/adapter.mjs").catch(() => ({}));

const USER_ID = "018f22e2-79b0-7cc8-98c4-dc0c0c073980";
const SESSION_ID = "018f22e2-79b0-7cc8-98c4-dc0c0c07398a";
const WORKSPACE_ID = "018f22e2-79b0-7cc8-98c4-dc0c0c073982";
const REQUESTED_AT_MS = "1786320000000";
const PURGE_DEADLINE_MS = "1786924800000";
const REQUEST_ID = "a7".repeat(32);

async function loadCore() {
  const module = await coreModule;
  assert.equal(
    typeof module.createAccountLifecycleEdgeHandler,
    "function",
    "the account-lifecycle Edge core must expose a tested handler factory",
  );
  return module;
}

async function loadAdapter() {
  const module = await adapterModule;
  assert.equal(
    typeof module.createSupabaseAccountLifecycleDependencies,
    "function",
    "the account-lifecycle Supabase adapter must be present",
  );
  return module;
}

function request(body, authorization = "Bearer signed-jwt") {
  return new Request("https://fixture.invalid/functions/v1/account-lifecycle", {
    method: "POST",
    headers: {
      authorization,
      "content-type": "application/json",
    },
    body: JSON.stringify(body.action === "status" ? body : { requestId: REQUEST_ID, ...body }),
  });
}

test("the handler derives ownership from verified claims and returns only an exact projection", async () => {
  const { createAccountLifecycleEdgeHandler } = await loadCore();
  const calls = [];
  const handler = createAccountLifecycleEdgeHandler({
    async authenticate(token, options) {
      calls.push(["authenticate", token, options]);
      return { userId: USER_ID, sessionId: SESSION_ID };
    },
    async transition(identity, action, workspaceId, requestId) {
      calls.push(["transition", identity, action, workspaceId, requestId]);
      return {
        state: "pending_delete",
        requestedAtMs: REQUESTED_AT_MS,
        purgeDeadlineMs: PURGE_DEADLINE_MS,
      };
    },
  });

  const response = await handler(
    request({ v: 1, action: "begin_deletion", workspaceId: WORKSPACE_ID }),
  );

  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    v: 1,
    state: "pending_delete",
    requestedAtMs: REQUESTED_AT_MS,
    purgeDeadlineMs: PURGE_DEADLINE_MS,
  });
  assert.deepEqual(calls, [
    ["authenticate", "signed-jwt", { requireFreshCredential: true }],
    [
      "transition",
      { userId: USER_ID, sessionId: SESSION_ID },
      "begin_deletion",
      WORKSPACE_ID,
      REQUEST_ID,
    ],
  ]);
  assert.ok(!JSON.stringify(calls).includes("accountId"));
});

test("status needs a current session but not a fresh credential event", async () => {
  const { createAccountLifecycleEdgeHandler } = await loadCore();
  const calls = [];
  const handler = createAccountLifecycleEdgeHandler({
    async authenticate(_token, options) {
      calls.push(options);
      return { userId: USER_ID, sessionId: SESSION_ID };
    },
    async transition() {
      return { state: "active", requestedAtMs: null, purgeDeadlineMs: null };
    },
  });

  const response = await handler(request({ v: 1, action: "status", workspaceId: WORKSPACE_ID }));
  assert.equal(response.status, 200);
  assert.deepEqual(calls, [{ requireFreshCredential: false }]);
});

test("invalid and oversized bodies are rejected before authentication", async () => {
  const { createAccountLifecycleEdgeHandler, MAX_ACCOUNT_LIFECYCLE_REQUEST_BYTES } =
    await loadCore();
  let authenticationCalls = 0;
  const handler = createAccountLifecycleEdgeHandler({
    async authenticate() {
      authenticationCalls += 1;
      return { userId: USER_ID, sessionId: SESSION_ID };
    },
    async transition() {
      throw new Error("unreachable");
    },
  });

  const forged = await handler(
    request({
      v: 1,
      action: "begin_deletion",
      workspaceId: WORKSPACE_ID,
      accountId: USER_ID,
    }),
  );
  assert.equal(forged.status, 400);

  const oversized = await handler(
    new Request("https://fixture.invalid/functions/v1/account-lifecycle", {
      method: "POST",
      headers: { authorization: "Bearer signed-jwt", "content-type": "application/json" },
      body: "x".repeat(MAX_ACCOUNT_LIFECYCLE_REQUEST_BYTES + 1),
    }),
  );
  assert.equal(oversized.status, 413);
  assert.equal(authenticationCalls, 0);
});

test("provider text and malformed projections never cross the Edge boundary", async () => {
  const { createAccountLifecycleEdgeHandler } = await loadCore();
  const handler = createAccountLifecycleEdgeHandler({
    async authenticate() {
      return { userId: USER_ID, sessionId: SESSION_ID };
    },
    async transition() {
      return {
        state: "pending_delete",
        requestedAtMs: REQUESTED_AT_MS,
        purgeDeadlineMs: "1786320000001",
        providerSecret: "provider-detail-canary",
      };
    },
  });

  const response = await handler(
    request({ v: 1, action: "cancel_deletion", workspaceId: WORKSPACE_ID }),
  );
  assert.equal(response.status, 503);
  const text = await response.text();
  assert.equal(text, '{"v":1,"error":"transient"}');
  assert.ok(!text.includes("provider-detail-canary"));
});

function adapterHarness({ amr, rpcData, rpcError = null, nowSeconds = 1_786_320_200 } = {}) {
  const calls = [];
  const authClient = {
    auth: {
      async getClaims(token) {
        calls.push(["getClaims", token]);
        return {
          data: { claims: { sub: USER_ID, session_id: SESSION_ID, amr } },
          error: null,
        };
      },
    },
  };
  const serviceClient = {
    async rpc(name, parameters) {
      calls.push(["rpc", name, parameters]);
      return { data: rpcData, error: rpcError };
    },
  };
  const createClient = (url, key, options) => {
    calls.push(["createClient", url, key, options]);
    return key === "publishable-fixture" ? authClient : serviceClient;
  };
  return {
    calls,
    createClient,
    env: {
      SUPABASE_URL: "https://fixture.supabase.co",
      SUPABASE_PUBLISHABLE_KEY: "publishable-fixture",
      CONTEXT_RELAY_SUPABASE_SECRET_KEY: "secret-fixture",
    },
    nowSeconds: () => nowSeconds,
  };
}

test("fresh lifecycle mutations use signed OAuth AMR time rather than JWT refresh time", async () => {
  const { createSupabaseAccountLifecycleDependencies } = await loadAdapter();
  const current = adapterHarness({
    amr: [{ method: "oauth", timestamp: 1_786_320_000 }],
  });
  const dependencies = createSupabaseAccountLifecycleDependencies(current);

  assert.deepEqual(
    await dependencies.authenticate("signed-jwt", { requireFreshCredential: true }),
    { userId: USER_ID, sessionId: SESSION_ID, credentialAuthenticatedAtSeconds: 1_786_320_000 },
  );
  assert.deepEqual(current.calls.find(([name]) => name === "getClaims"), [
    "getClaims",
    "signed-jwt",
  ]);

  for (const amr of [
    [{ method: "oauth", timestamp: 1_786_319_899 }],
    [{ method: "token_refresh", timestamp: 1_786_320_199 }],
    [],
    [{ method: "oauth", timestamp: 1_786_320_201 }],
    [{ method: "oauth", timestamp: "1786320000" }],
  ]) {
    const stale = adapterHarness({ amr });
    const staleDependencies = createSupabaseAccountLifecycleDependencies(stale);
    await assert.rejects(
      staleDependencies.authenticate("signed-jwt", { requireFreshCredential: true }),
      (error) => error?.code === "fresh_auth_required",
    );
  }
});

test("the adapter sends only verified user, session, and workspace to service-only RPCs", async () => {
  const { createSupabaseAccountLifecycleDependencies } = await loadAdapter();
  const harness = adapterHarness({
    amr: [{ method: "oauth", timestamp: 1_786_320_000 }],
    rpcData: {
      state: "pending_delete",
      requestedAtMs: REQUESTED_AT_MS,
      purgeDeadlineMs: PURGE_DEADLINE_MS,
    },
  });
  const dependencies = createSupabaseAccountLifecycleDependencies(harness);

  assert.deepEqual(
    await dependencies.transition(
      { userId: USER_ID, sessionId: SESSION_ID, credentialAuthenticatedAtSeconds: 1_786_320_000 },
      "begin_deletion",
      WORKSPACE_ID,
      REQUEST_ID,
    ),
    {
      state: "pending_delete",
      requestedAtMs: REQUESTED_AT_MS,
      purgeDeadlineMs: PURGE_DEADLINE_MS,
    },
  );
  assert.deepEqual(harness.calls.find(([name]) => name === "rpc"), [
    "rpc",
    "service_begin_account_deletion_for_session",
    {
      p_auth_user_id: USER_ID,
      p_session_id: SESSION_ID,
      p_workspace_id: WORKSPACE_ID,
      p_credential_authenticated_at_seconds: 1_786_320_000,
      p_request_id: `\\x${REQUEST_ID}`,
    },
  ]);
  assert.ok(!JSON.stringify(harness.calls).includes("account_id"));
});

test("the tested lifecycle entrypoint and both test suites are included in Supabase CI", async () => {
  const entry = await readFile(new URL("../../supabase/functions/account-lifecycle/index.ts", import.meta.url), "utf8");
  const config = await readFile(new URL("../../supabase/config.toml", import.meta.url), "utf8");
  const workflow = await readFile(new URL("../../.github/workflows/supabase.yml", import.meta.url), "utf8");
  assert.match(entry, /npm:@supabase\/supabase-js@2\.112\.0/);
  assert.match(entry, /createSupabaseAccountLifecycleDependencies/);
  assert.match(entry, /createAccountLifecycleEdgeHandler/);
  assert.match(entry, /Deno\.serve\(handler\)/);
  assert.doesNotMatch(entry, /console\.|SUPABASE_SERVICE_ROLE_KEY/);
  assert.match(config, /\[functions\.account-lifecycle\]\s*verify_jwt\s*=\s*false/);
  assert.match(workflow, /node --test scripts\/tests\/account-lifecycle-\*\.test\.mjs/);
});
