import assert from "node:assert/strict";
import test from "node:test";

const adapterModule = import("../../supabase/functions/sync/adapter.mjs").catch(() => ({}));

const USER_ID = "018f22e2-79b0-7cc8-98c4-dc0c0c073980";
const SESSION_ID = "018f22e2-79b0-7cc8-98c4-dc0c0c07398a";
const ACCOUNT_ID = "018f22e2-79b0-7cc8-98c4-dc0c0c073981";
const WORKSPACE_ID = "018f22e2-79b0-7cc8-98c4-dc0c0c073982";
const DEVICE_ID = "018f22e2-79b0-7cc8-98c4-dc0c0c073983";
const OPERATION_ID = "018f22e2-79b0-7cc8-98c4-dc0c0c073985";

async function loadAdapter() {
  const module = await adapterModule;
  assert.equal(
    typeof module.createSupabaseSyncDependencies,
    "function",
    "the sync Edge Supabase adapter must be present",
  );
  return module;
}

function harness(rpcFailure = null) {
  const calls = [];
  const authClient = {
    auth: {
      getClaims: async (token) => {
        calls.push(["getClaims", token]);
        return { data: { claims: { sub: USER_ID, session_id: SESSION_ID } }, error: null };
      },
    },
  };
  const serviceClient = {
    rpc: async (name, parameters) => {
      calls.push(["rpc", name, parameters]);
      if (rpcFailure?.name === name) {
        return { data: null, error: { message: rpcFailure.message } };
      }
      if (name === "service_sync_identity_context") {
        return {
          data: {
            accountId: ACCOUNT_ID,
            workspaceId: WORKSPACE_ID,
            deviceId: DEVICE_ID,
            certificateId: "018f22e2-79b0-7cc8-98c4-dc0c0c07398b",
            controlEpoch: 17,
            keyEpoch: 23,
            signingPublicKey: "07".repeat(32),
            certificateChain: [],
            recoverySigningPublicKey: "06".repeat(32),
          },
          error: null,
        };
      }
      if (name === "service_append_sync_operations") {
        return { data: { accepted: [OPERATION_ID], duplicates: [] }, error: null };
      }
      if (name === "service_append_sync_checkpoint") {
        return { data: { canonicalHash: "04".repeat(32), duplicate: false }, error: null };
      }
      if (name === "service_sync_session_context") {
        return {
          data: {
            accountId: ACCOUNT_ID,
            workspaceId: WORKSPACE_ID,
            deviceId: DEVICE_ID,
            certificateId: "018f22e2-79b0-7cc8-98c4-dc0c0c07398b",
            controlEpoch: 17,
            keyEpoch: 23,
            signingPublicKey: "07".repeat(32),
            certificateChain: [],
            recoverySigningPublicKey: "06".repeat(32),
          },
          error: null,
        };
      }
      if (name === "service_reserve_blob_upload_for_session") {
        return {
          data: {
            storageId: parameters.p_storage_id,
            paths: [
              `${ACCOUNT_ID}/${parameters.p_storage_id}/00000000.bin`,
              `${ACCOUNT_ID}/${parameters.p_storage_id}/00000001.bin`,
            ],
            expiresAt: parameters.p_expires_at,
          },
          error: null,
        };
      }
      if (name === "service_finalize_blob_upload_for_session") {
        return { data: { storageId: parameters.p_storage_id, state: "finalized" }, error: null };
      }
      if (name === "service_release_blob_upload_for_session") {
        return { data: { storageId: parameters.p_storage_id, state: "cancelled" }, error: null };
      }
      if (name === "service_send_sync_hint") {
        return { data: { sent: true }, error: null };
      }
      throw new Error(`unexpected RPC ${name}`);
    },
  };
  const createClient = (url, key, options) => {
    calls.push(["createClient", url, key, options]);
    if (key === "publishable-fixture") return authClient;
    if (key === "secret-fixture") return serviceClient;
    throw new Error("unexpected key");
  };
  const env = {
    SUPABASE_URL: "https://fixture.supabase.co",
    SUPABASE_PUBLISHABLE_KEY: "publishable-fixture",
    CONTEXT_RELAY_SUPABASE_SECRET_KEY: "secret-fixture",
  };
  return { calls, createClient, env };
}

test("the adapter creates isolated no-session auth and service clients from server env", async () => {
  const { createSupabaseSyncDependencies } = await loadAdapter();
  const { calls, createClient, env } = harness();
  createSupabaseSyncDependencies({ createClient, env });

  const clients = calls.filter(([name]) => name === "createClient");
  assert.equal(clients.length, 2);
  assert.deepEqual(
    clients.map(([, url, key]) => [url, key]),
    [
      [env.SUPABASE_URL, env.SUPABASE_PUBLISHABLE_KEY],
      [env.SUPABASE_URL, env.CONTEXT_RELAY_SUPABASE_SECRET_KEY],
    ],
  );
  for (const [, , , options] of clients) {
    assert.deepEqual(options.auth, {
      persistSession: false,
      autoRefreshToken: false,
      detectSessionInUrl: false,
    });
  }
});

test("authentication derives only verified sub and session_id claims", async () => {
  const { createSupabaseSyncDependencies } = await loadAdapter();
  const { calls, createClient, env } = harness();
  const dependencies = createSupabaseSyncDependencies({ createClient, env });

  assert.deepEqual(await dependencies.authenticate("signed-jwt"), {
    userId: USER_ID,
    sessionId: SESSION_ID,
  });
  assert.deepEqual(calls.find(([name]) => name === "getClaims"), ["getClaims", "signed-jwt"]);
});

test("identity lookup binds verified claims to the requested route and decodes no secrets", async () => {
  const { createSupabaseSyncDependencies } = await loadAdapter();
  const { calls, createClient, env } = harness();
  const dependencies = createSupabaseSyncDependencies({ createClient, env });
  const identity = { userId: USER_ID, sessionId: SESSION_ID };
  const route = { accountId: ACCOUNT_ID, workspaceId: WORKSPACE_ID, deviceId: DEVICE_ID };

  const context = await dependencies.loadIdentityContext(identity, route);

  assert.deepEqual(calls.find((call) => call[1] === "service_sync_identity_context"), [
    "rpc",
    "service_sync_identity_context",
    {
      p_auth_user_id: USER_ID,
      p_session_id: SESSION_ID,
      p_workspace_id: WORKSPACE_ID,
      p_device_id: DEVICE_ID,
    },
  ]);
  assert.deepEqual(context.signingPublicKey, new Uint8Array(32).fill(7));
  assert.equal(context.authenticatedUserId, USER_ID);
  assert.equal(context.authenticatedSessionId, SESSION_ID);
  assert.ok(!JSON.stringify(context).includes(env.CONTEXT_RELAY_SUPABASE_SECRET_KEY));
});

test("append sends only verified routing metadata, ciphertext, signature, and canonical hash", async () => {
  const { createSupabaseSyncDependencies } = await loadAdapter();
  const { calls, createClient, env } = harness();
  const dependencies = createSupabaseSyncDependencies({ createClient, env });
  const context = {
    authenticatedUserId: USER_ID,
    authenticatedSessionId: SESSION_ID,
  };
  const operation = {
    operationId: OPERATION_ID,
    accountId: ACCOUNT_ID,
    workspaceId: WORKSPACE_ID,
    projectId: null,
    recordId: "018f22e2-79b0-7cc8-98c4-dc0c0c073984",
    recordKind: "memory",
    mutationKind: "tombstone",
    deviceId: DEVICE_ID,
    schemaVersion: 1,
    deviceSequence: "1",
    causalFrontier: [],
    controlEpoch: 17,
    keyEpoch: 23,
    previousDeviceHash: new Uint8Array(32),
    nonce: new Uint8Array(24).fill(13),
    ciphertext: new Uint8Array([1, 2, 3]),
    ciphertextHash: new Uint8Array(32).fill(4),
    blobRefs: [],
    createdHlc: { physicalMs: "1", logical: 0, node: DEVICE_ID },
    signature: new Uint8Array(64).fill(5),
    canonicalSha256: new Uint8Array(32).fill(6),
    canonicalBytes: new Uint8Array([99]),
    signingPreimage: new Uint8Array([98]),
  };

  assert.deepEqual(await dependencies.appendOperations(context, [operation]), {
    accepted: [OPERATION_ID],
    duplicates: [],
  });
  const call = calls.find((entry) => entry[1] === "service_append_sync_operations");
  assert.equal(call[2].p_auth_user_id, USER_ID);
  assert.equal(call[2].p_session_id, SESSION_ID);
  assert.deepEqual(Object.keys(call[2].p_operations[0]).sort(), [
    "accountId",
    "blobRefs",
    "canonicalSha256",
    "causalFrontier",
    "ciphertextBase64",
    "ciphertextHash",
    "controlEpoch",
    "createdHlc",
    "deviceId",
    "deviceSequence",
    "keyEpoch",
    "mutationKind",
    "nonce",
    "operationId",
    "previousDeviceHash",
    "projectId",
    "recordId",
    "recordKind",
    "schemaVersion",
    "signature",
    "workspaceId",
  ]);
  assert.equal(call[2].p_operations[0].ciphertextBase64, "AQID");
  assert.equal(call[2].p_operations[0].canonicalSha256, "06".repeat(32));
  assert.ok(!JSON.stringify(call).includes("canonicalBytes"));
  assert.ok(!JSON.stringify(call).includes("signingPreimage"));
});

test("checkpoint append sends only verified canonical fields through the sealed service RPC", async () => {
  const { createSupabaseSyncDependencies } = await loadAdapter();
  const { calls, createClient, env } = harness();
  const dependencies = createSupabaseSyncDependencies({ createClient, env });
  const context = {
    authenticatedUserId: USER_ID,
    authenticatedSessionId: SESSION_ID,
  };
  const checkpoint = {
    schemaVersion: 2,
    accountId: ACCOUNT_ID,
    workspaceId: WORKSPACE_ID,
    previousCheckpointHash: new Uint8Array(32).fill(1),
    causalFrontier: [{ deviceId: DEVICE_ID, sequence: "7" }],
    stateHash: new Uint8Array(32).fill(2),
    keyEpoch: 23,
    creatorDeviceId: DEVICE_ID,
    createdHlc: { physicalMs: "1", logical: 2, node: DEVICE_ID },
    signature: new Uint8Array(64).fill(3),
    canonicalSha256: new Uint8Array(32).fill(4),
    canonicalBytes: new Uint8Array([99]),
    signingPreimage: new Uint8Array([98]),
  };

  assert.deepEqual(await dependencies.appendCheckpoint(context, checkpoint), {
    canonicalHash: new Uint8Array(32).fill(4),
    duplicate: false,
  });
  const call = calls.find((entry) => entry[1] === "service_append_sync_checkpoint");
  assert.equal(call[2].p_auth_user_id, USER_ID);
  assert.equal(call[2].p_session_id, SESSION_ID);
  assert.equal(call[2].p_checkpoint.schemaVersion, 2);
  assert.equal(call[2].p_checkpoint.accountId, ACCOUNT_ID);
  assert.equal(call[2].p_checkpoint.workspaceId, WORKSPACE_ID);
  assert.equal(call[2].p_checkpoint.creatorDeviceId, DEVICE_ID);
  assert.equal(call[2].p_checkpoint.canonicalSha256, "04".repeat(32));
  assert.ok(!JSON.stringify(call).includes("canonicalBytes"));
  assert.ok(!JSON.stringify(call).includes("signingPreimage"));
});

test("blob orchestration derives the device from the verified session and uses service-only RPCs", async () => {
  const { createSupabaseSyncDependencies } = await loadAdapter();
  const { calls, createClient, env } = harness();
  const dependencies = createSupabaseSyncDependencies({ createClient, env });
  const identity = { userId: USER_ID, sessionId: SESSION_ID };
  const storageId = "018f22e2-79b0-7cc8-98c4-dc0c0c07398c";
  const expiresAt = "2026-08-10T09:00:00.000Z";

  const context = await dependencies.loadSessionContext(identity, {
    workspaceId: WORKSPACE_ID,
  });
  assert.equal(context.deviceId, DEVICE_ID);
  const reservation = await dependencies.reserveBlob(context, {
    storageId,
    ciphertextSha256: new Uint8Array(32).fill(12),
    partSizes: [3, 4],
    expiresAt,
  });
  assert.deepEqual(reservation.paths, [
    `${ACCOUNT_ID}/${storageId}/00000000.bin`,
    `${ACCOUNT_ID}/${storageId}/00000001.bin`,
  ]);
  assert.deepEqual(await dependencies.finalizeBlob(identity, storageId), {
    storageId,
    state: "finalized",
  });
  assert.deepEqual(await dependencies.releaseBlob(identity, storageId), {
    storageId,
    state: "cancelled",
  });

  const sessionContext = calls.find((entry) => entry[1] === "service_sync_session_context");
  assert.deepEqual(sessionContext[2], {
    p_auth_user_id: USER_ID,
    p_session_id: SESSION_ID,
    p_workspace_id: WORKSPACE_ID,
  });
  const reserve = calls.find((entry) => entry[1] === "service_reserve_blob_upload_for_session");
  assert.equal(reserve[2].p_auth_user_id, USER_ID);
  assert.equal(reserve[2].p_session_id, SESSION_ID);
  assert.equal(reserve[2].p_workspace_id, WORKSPACE_ID);
  assert.equal(reserve[2].p_storage_id, storageId);
  assert.equal(reserve[2].p_ciphertext_sha256, `\\x${"0c".repeat(32)}`);
  assert.deepEqual(reserve[2].p_part_sizes, [3, 4]);
});

test("pull hints use only the separate post-commit service RPC", async () => {
  const { createSupabaseSyncDependencies } = await loadAdapter();
  const { calls, createClient, env } = harness();
  const dependencies = createSupabaseSyncDependencies({ createClient, env });

  await dependencies.broadcastPullNow(ACCOUNT_ID);
  assert.deepEqual(calls.find((entry) => entry[1] === "service_send_sync_hint"), [
    "rpc",
    "service_send_sync_hint",
    { p_account_id: ACCOUNT_ID },
  ]);
});

test("database integrity and conflict failures are classified without provider text", async () => {
  const { createSupabaseSyncDependencies } = await loadAdapter();
  const operation = {
    operationId: OPERATION_ID,
    accountId: ACCOUNT_ID,
    workspaceId: WORKSPACE_ID,
    projectId: null,
    recordId: "018f22e2-79b0-7cc8-98c4-dc0c0c073984",
    recordKind: "memory",
    mutationKind: "tombstone",
    deviceId: DEVICE_ID,
    schemaVersion: 1,
    deviceSequence: "2",
    causalFrontier: [],
    controlEpoch: 17,
    keyEpoch: 23,
    previousDeviceHash: new Uint8Array(32),
    nonce: new Uint8Array(24),
    ciphertext: new Uint8Array([1]),
    ciphertextHash: new Uint8Array(32),
    blobRefs: [],
    createdHlc: { physicalMs: "1", logical: 0, node: DEVICE_ID },
    signature: new Uint8Array(64),
    canonicalSha256: new Uint8Array(32),
  };
  const identity = {
    authenticatedUserId: USER_ID,
    authenticatedSessionId: SESSION_ID,
  };
  const integrityHarness = harness({
    name: "service_append_sync_operations",
    message: "device_hash_mismatch",
  });
  const integrity = createSupabaseSyncDependencies({
    createClient: integrityHarness.createClient,
    env: integrityHarness.env,
  });
  await assert.rejects(
    integrity.appendOperations(identity, [operation]),
    (error) => error.code === "integrity_quarantined" && error.message === error.code,
  );

  const conflictHarness = harness({
    name: "service_reserve_blob_upload_for_session",
    message: "blob_storage_conflict",
  });
  const conflict = createSupabaseSyncDependencies({
    createClient: conflictHarness.createClient,
    env: conflictHarness.env,
  });
  await assert.rejects(
    conflict.reserveBlob(
      {
        authenticatedUserId: USER_ID,
        authenticatedSessionId: SESSION_ID,
        workspaceId: WORKSPACE_ID,
      },
      {
        storageId: OPERATION_ID,
        ciphertextSha256: new Uint8Array(32),
        partSizes: [1],
        expiresAt: "2026-08-10T09:00:00.000Z",
      },
    ),
    (error) => error.code === "conflict" && error.message === error.code,
  );
});
