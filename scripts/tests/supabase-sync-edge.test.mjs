import assert from "node:assert/strict";
import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";

const coreModule = import("../../supabase/functions/sync/core.mjs").catch(() => ({}));

const ACCOUNT_ID = "018f22e2-79b0-7cc8-98c4-dc0c0c073981";
const WORKSPACE_ID = "018f22e2-79b0-7cc8-98c4-dc0c0c073982";
const DEVICE_ID = "018f22e2-79b0-7cc8-98c4-dc0c0c073983";
const OPERATION_ID = "018f22e2-79b0-7cc8-98c4-dc0c0c073985";

async function loadCore() {
  const module = await coreModule;
  assert.equal(
    typeof module.createSyncEdgeHandler,
    "function",
    "the sync Edge core must expose createSyncEdgeHandler",
  );
  return module;
}

async function fixtureEnvelope() {
  const hex = (
    await readFile(
      new URL("../../crates/core/tests/fixtures/signed-sync-operation-v1.hex", import.meta.url),
      "utf8",
    )
  ).replaceAll(/\s/g, "");
  return Buffer.from(hex, "hex");
}

function privateKeyFromSeed(seed) {
  const pkcs8Prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  return createPrivateKey({
    key: Buffer.concat([pkcs8Prefix, Buffer.alloc(32, seed)]),
    format: "der",
    type: "pkcs8",
  });
}

function rawPublicKey(privateKey) {
  const spki = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  return Buffer.from(spki).subarray(-32);
}

function fixturePublicKey() {
  return rawPublicKey(privateKeyFromSeed(7));
}

function uuidBytes(value) {
  return Buffer.from(value.replaceAll("-", ""), "hex");
}

function cborHead(major, value) {
  if (value < 24) return Buffer.from([(major << 5) | value]);
  if (value <= 0xff) return Buffer.from([(major << 5) | 24, value]);
  if (value <= 0xffff) {
    const output = Buffer.alloc(3);
    output[0] = (major << 5) | 25;
    output.writeUInt16BE(value, 1);
    return output;
  }
  const output = Buffer.alloc(5);
  output[0] = (major << 5) | 26;
  output.writeUInt32BE(value, 1);
  return output;
}

function cborUnsigned(value) {
  return cborHead(0, value);
}

function cborBytes(value) {
  return Buffer.concat([cborHead(2, value.length), Buffer.from(value)]);
}

function cborArray(values) {
  return Buffer.concat([cborHead(4, values.length), ...values]);
}

function cborMap(entries) {
  return Buffer.concat([
    cborHead(5, entries.length),
    ...entries.flatMap(([key, value]) => [cborUnsigned(key), value]),
  ]);
}

function fixtureCheckpointEnvelope() {
  const creatorPrivateKey = privateKeyFromSeed(7);
  const entries = [
    [0, cborUnsigned(2)],
    [1, cborBytes(uuidBytes(ACCOUNT_ID))],
    [2, cborBytes(uuidBytes(WORKSPACE_ID))],
    [3, cborBytes(Buffer.alloc(32, 9))],
    [4, cborArray([cborArray([cborBytes(uuidBytes(DEVICE_ID)), cborUnsigned(7)])])],
    [5, cborBytes(Buffer.alloc(32, 10))],
    [6, cborUnsigned(23)],
    [7, cborBytes(uuidBytes(DEVICE_ID))],
    [
      8,
      cborMap([
        [0, cborUnsigned(1)],
        [1, cborUnsigned(2)],
        [2, cborBytes(uuidBytes(DEVICE_ID))],
      ]),
    ],
  ];
  const signingPreimage = cborMap(entries);
  return cborMap([
    ...entries,
    [9, cborBytes(sign(null, signingPreimage, creatorPrivateKey))],
  ]);
}

function fixtureCertificateContext() {
  const recoveryPrivateKey = privateKeyFromSeed(6);
  const recoveryPublicKey = rawPublicKey(recoveryPrivateKey);
  const signingPublicKey = fixturePublicKey();
  const requestNonce = Buffer.alloc(32, 3);
  const wrappingPublicKey = Buffer.alloc(32, 9);
  const controlEpoch = Buffer.alloc(4);
  controlEpoch.writeUInt32BE(17);
  const preimage = Buffer.concat([
    Buffer.from("context-relay/device-certificate/v1\0", "utf8"),
    Buffer.from([0]),
    recoveryPublicKey,
    uuidBytes(ACCOUNT_ID),
    uuidBytes(WORKSPACE_ID),
    controlEpoch,
    requestNonce,
    uuidBytes(DEVICE_ID),
    signingPublicKey,
    wrappingPublicKey,
  ]);
  return {
    accountId: ACCOUNT_ID,
    workspaceId: WORKSPACE_ID,
    deviceId: DEVICE_ID,
    certificateId: "018f22e2-79b0-7cc8-98c4-dc0c0c07398b",
    controlEpoch: 17,
    keyEpoch: 23,
    signingPublicKey,
    recoverySigningPublicKey: recoveryPublicKey.toString("hex"),
    certificateChain: [
      {
        certificateId: "018f22e2-79b0-7cc8-98c4-dc0c0c07398b",
        accountId: ACCOUNT_ID,
        workspaceId: WORKSPACE_ID,
        controlEpoch: 17,
        requestNonce: requestNonce.toString("hex"),
        deviceId: DEVICE_ID,
        issuerKind: "recovery_root",
        issuerDeviceId: null,
        issuerRecoveryPublicKey: recoveryPublicKey.toString("hex"),
        issuerSigningPublicKey: recoveryPublicKey.toString("hex"),
        deviceSigningPublicKey: signingPublicKey.toString("hex"),
        deviceWrappingPublicKey: wrappingPublicKey.toString("hex"),
        signature: sign(null, preimage, recoveryPrivateKey).toString("hex"),
      },
    ],
  };
}

function request(body, headers = {}) {
  return new Request("https://example.invalid/functions/v1/sync", {
    method: "POST",
    headers: {
      authorization: "Bearer fixture.jwt.token",
      "content-type": "application/json",
      ...headers,
    },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

function dependencies(overrides = {}) {
  const calls = [];
  return {
    calls,
    deps: {
      authenticate: async (token) => {
        calls.push(["authenticate", token]);
        return {
          userId: "018f22e2-79b0-7cc8-98c4-dc0c0c073980",
          sessionId: "018f22e2-79b0-7cc8-98c4-dc0c0c07398a",
        };
      },
      loadIdentityContext: async (identity, route) => {
        calls.push(["loadIdentityContext", identity, route]);
        return fixtureCertificateContext();
      },
      loadSessionContext: async (identity, route) => {
        calls.push(["loadSessionContext", identity, route]);
        return fixtureCertificateContext();
      },
      appendOperations: async (context, operations) => {
        calls.push(["appendOperations", context, operations]);
        return { accepted: [OPERATION_ID], duplicates: [] };
      },
      appendCheckpoint: async (context, checkpoint) => {
        calls.push(["appendCheckpoint", context, checkpoint]);
        return { canonicalHash: checkpoint.canonicalSha256, duplicate: false };
      },
      reserveBlob: async (context, reservation) => {
        calls.push(["reserveBlob", context, reservation]);
        return {
          storageId: reservation.storageId,
          paths: reservation.partSizes.map(
            (_, index) =>
              `${context.accountId}/${reservation.storageId}/${String(index).padStart(8, "0")}.bin`,
          ),
          expiresAt: reservation.expiresAt,
        };
      },
      finalizeBlob: async (identity, storageId) => {
        calls.push(["finalizeBlob", identity, storageId]);
        return { storageId, state: "finalized" };
      },
      releaseBlob: async (identity, storageId) => {
        calls.push(["releaseBlob", identity, storageId]);
        return { storageId, state: "cancelled" };
      },
      broadcastPullNow: async (accountId) => {
        calls.push(["broadcastPullNow", accountId]);
      },
      ...overrides,
    },
  };
}

test("the Task 16 sync Edge core is present", async () => {
  await loadCore();
});

test("oversized requests are rejected before authentication or decode", async () => {
  const { createSyncEdgeHandler, MAX_SYNC_REQUEST_BYTES } = await loadCore();
  const { deps, calls } = dependencies();
  const handler = createSyncEdgeHandler(deps);
  const response = await handler(
    request("x", { "content-length": String(MAX_SYNC_REQUEST_BYTES + 1) }),
  );

  assert.equal(response.status, 413);
  assert.deepEqual(await response.json(), { v: 1, error: "request_too_large" });
  assert.deepEqual(calls, []);
});

test("chunked oversized requests stop reading at the cap before authentication", async () => {
  const { createSyncEdgeHandler } = await loadCore();
  const { deps, calls } = dependencies();
  const handler = createSyncEdgeHandler(deps);
  let pulls = 0;
  let cancelled = false;
  const body = new ReadableStream({
    pull(controller) {
      pulls += 1;
      controller.enqueue(new Uint8Array(1024 * 1024));
      if (pulls === 12) controller.close();
    },
    cancel() {
      cancelled = true;
    },
  });
  const response = await handler(
    new Request("https://example.invalid/functions/v1/sync", {
      method: "POST",
      headers: {
        authorization: "Bearer fixture.jwt.token",
        "content-type": "application/json",
      },
      body,
      duplex: "half",
    }),
  );

  assert.equal(response.status, 413);
  assert.deepEqual(await response.json(), { v: 1, error: "request_too_large" });
  assert.equal(cancelled, true);
  assert.ok(pulls < 12, `the handler consumed all ${pulls} chunks`);
  assert.deepEqual(calls, []);
});

test("operation push JSON is strict and rejects client ownership fields", async () => {
  const { createSyncEdgeHandler } = await loadCore();
  const { deps, calls } = dependencies();
  const handler = createSyncEdgeHandler(deps);
  const response = await handler(
    request({
      v: 1,
      action: "push_operations",
      operations: [],
      accountId: ACCOUNT_ID,
    }),
  );

  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), { v: 1, error: "invalid_request" });
  assert.deepEqual(calls, []);
});

test("the Rust operation vector is verified before append and hinted only after commit", async () => {
  const { createSyncEdgeHandler } = await loadCore();
  const { deps, calls } = dependencies();
  const handler = createSyncEdgeHandler(deps);
  const envelope = await fixtureEnvelope();
  const response = await handler(
    request({
      v: 1,
      action: "push_operations",
      operations: [envelope.toString("base64url")],
    }),
  );

  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    v: 1,
    accepted: [OPERATION_ID],
    duplicates: [],
  });
  assert.deepEqual(
    calls.map(([name]) => name),
    ["authenticate", "loadIdentityContext", "appendOperations", "broadcastPullNow"],
  );
  const appended = calls.find(([name]) => name === "appendOperations")[2][0];
  assert.equal(appended.operationId, OPERATION_ID);
  assert.equal(appended.accountId, ACCOUNT_ID);
  assert.equal(appended.workspaceId, WORKSPACE_ID);
  assert.equal(appended.deviceId, DEVICE_ID);
  assert.deepEqual(appended.canonicalBytes, new Uint8Array(envelope));
});

test("duplicate operation identifiers are rejected before hosted mutation", async () => {
  const { createSyncEdgeHandler } = await loadCore();
  const { deps, calls } = dependencies();
  const handler = createSyncEdgeHandler(deps);
  const envelope = await fixtureEnvelope();
  const encoded = envelope.toString("base64url");
  const response = await handler(
    request({ v: 1, action: "push_operations", operations: [encoded, encoded] }),
  );

  assert.equal(response.status, 422);
  assert.deepEqual(await response.json(), { v: 1, error: "invalid_envelope" });
  assert.deepEqual(
    calls.map(([name]) => name),
    ["authenticate"],
  );
});

test("an untrusted operation receipt cannot inject identifiers or secret text", async () => {
  const { createSyncEdgeHandler } = await loadCore();
  const secretCanary = "provider-secret-canary";
  const { deps, calls } = dependencies({
    appendOperations: async (context, operations) => {
      calls.push(["appendOperations", context, operations]);
      return { accepted: [secretCanary], duplicates: [] };
    },
  });
  const handler = createSyncEdgeHandler(deps);
  const envelope = await fixtureEnvelope();
  const response = await handler(
    request({
      v: 1,
      action: "push_operations",
      operations: [envelope.toString("base64url")],
    }),
  );
  const body = await response.text();

  assert.equal(response.status, 503);
  assert.deepEqual(JSON.parse(body), { v: 1, error: "transient" });
  assert.ok(!body.includes(secretCanary));
  assert.deepEqual(
    calls.map(([name]) => name),
    ["authenticate", "loadIdentityContext", "appendOperations"],
  );
});

test("signature failure is fail-closed before append and never echoes the envelope", async () => {
  const { createSyncEdgeHandler } = await loadCore();
  const { deps, calls } = dependencies();
  const handler = createSyncEdgeHandler(deps);
  const envelope = await fixtureEnvelope();
  envelope[envelope.length - 1] ^= 1;
  const encoded = envelope.toString("base64url");
  const response = await handler(
    request({ v: 1, action: "push_operations", operations: [encoded] }),
  );
  const body = await response.text();

  assert.equal(response.status, 422);
  assert.deepEqual(JSON.parse(body), { v: 1, error: "invalid_envelope" });
  assert.ok(!body.includes(encoded));
  assert.deepEqual(
    calls.map(([name]) => name),
    ["authenticate", "loadIdentityContext"],
  );
});

test("a database certificate chain is verified before operation authority", async () => {
  const { createSyncEdgeHandler } = await loadCore();
  const context = fixtureCertificateContext();
  context.certificateChain[0].signature = `${"00".repeat(63)}01`;
  const { deps, calls } = dependencies({
    loadIdentityContext: async (identity, route) => {
      calls.push(["loadIdentityContext", identity, route]);
      return context;
    },
  });
  const handler = createSyncEdgeHandler(deps);
  const envelope = await fixtureEnvelope();
  const response = await handler(
    request({
      v: 1,
      action: "push_operations",
      operations: [envelope.toString("base64url")],
    }),
  );

  assert.equal(response.status, 422);
  assert.deepEqual(await response.json(), { v: 1, error: "invalid_envelope" });
  assert.deepEqual(
    calls.map(([name]) => name),
    ["authenticate", "loadIdentityContext"],
  );
});

test("a canonical signed checkpoint v2 is verified, appended, and hinted after commit", async () => {
  const { createSyncEdgeHandler } = await loadCore();
  const { deps, calls } = dependencies();
  const handler = createSyncEdgeHandler(deps);
  const checkpoint = fixtureCheckpointEnvelope();
  const canonicalHash = createHash("sha256").update(checkpoint).digest("hex");
  const response = await handler(
    request({
      v: 1,
      action: "push_checkpoint",
      checkpoint: checkpoint.toString("base64url"),
    }),
  );

  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    v: 1,
    canonicalHash,
    duplicate: false,
  });
  assert.deepEqual(
    calls.map(([name]) => name),
    ["authenticate", "loadIdentityContext", "appendCheckpoint", "broadcastPullNow"],
  );
  const appended = calls.find(([name]) => name === "appendCheckpoint")[2];
  assert.equal(appended.schemaVersion, 2);
  assert.equal(appended.accountId, ACCOUNT_ID);
  assert.equal(appended.workspaceId, WORKSPACE_ID);
  assert.equal(appended.creatorDeviceId, DEVICE_ID);
  assert.equal(Buffer.from(appended.canonicalSha256).toString("hex"), canonicalHash);
  assert.deepEqual(appended.canonicalBytes, new Uint8Array(checkpoint));
});

test("a Realtime hint failure cannot erase a committed checkpoint receipt", async () => {
  const { createSyncEdgeHandler } = await loadCore();
  const checkpoint = fixtureCheckpointEnvelope();
  const canonicalHash = createHash("sha256").update(checkpoint).digest("hex");
  const { deps, calls } = dependencies({
    broadcastPullNow: async (accountId) => {
      calls.push(["broadcastPullNow", accountId]);
      throw new Error("provider response must stay private");
    },
  });
  const handler = createSyncEdgeHandler(deps);
  const response = await handler(
    request({
      v: 1,
      action: "push_checkpoint",
      checkpoint: checkpoint.toString("base64url"),
    }),
  );

  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    v: 1,
    canonicalHash,
    duplicate: false,
  });
  assert.deepEqual(
    calls.map(([name]) => name),
    ["authenticate", "loadIdentityContext", "appendCheckpoint", "broadcastPullNow"],
  );
});

test("blob reservation derives ownership from the verified session and returns exact upload paths", async () => {
  const { createSyncEdgeHandler } = await loadCore();
  const { deps, calls } = dependencies();
  const handler = createSyncEdgeHandler(deps);
  const storageId = "018f22e2-79b0-7cc8-98c4-dc0c0c07398c";
  const expiresAt = "2026-08-10T09:00:00.000Z";
  const response = await handler(
    request({
      v: 1,
      action: "reserve_blob",
      workspaceId: WORKSPACE_ID,
      storageId,
      ciphertextSha256: Buffer.alloc(32, 12).toString("base64url"),
      partSizes: [3, 4],
      expiresAt,
    }),
  );

  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    v: 1,
    storageId,
    paths: [
      `${ACCOUNT_ID}/${storageId}/00000000.bin`,
      `${ACCOUNT_ID}/${storageId}/00000001.bin`,
    ],
    expiresAt,
  });
  assert.deepEqual(
    calls.map(([name]) => name),
    ["authenticate", "loadSessionContext", "reserveBlob"],
  );
});

test("blob reservation rejects client-supplied account or device ownership", async () => {
  const { createSyncEdgeHandler } = await loadCore();
  const { deps, calls } = dependencies();
  const handler = createSyncEdgeHandler(deps);
  const response = await handler(
    request({
      v: 1,
      action: "reserve_blob",
      accountId: ACCOUNT_ID,
      deviceId: DEVICE_ID,
      workspaceId: WORKSPACE_ID,
      storageId: "018f22e2-79b0-7cc8-98c4-dc0c0c07398c",
      ciphertextSha256: Buffer.alloc(32, 12).toString("base64url"),
      partSizes: [3],
      expiresAt: "2026-08-10T09:00:00.000Z",
    }),
  );

  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), { v: 1, error: "invalid_request" });
  assert.deepEqual(calls, []);
});

test("blob finalize and release bind only the verified session to the opaque storage id", async () => {
  const { createSyncEdgeHandler } = await loadCore();
  const { deps, calls } = dependencies();
  const handler = createSyncEdgeHandler(deps);
  const storageId = "018f22e2-79b0-7cc8-98c4-dc0c0c07398c";

  const finalized = await handler(
    request({ v: 1, action: "finalize_blob", storageId }),
  );
  assert.equal(finalized.status, 200);
  assert.deepEqual(await finalized.json(), { v: 1, storageId, state: "finalized" });

  const released = await handler(
    request({ v: 1, action: "release_blob", storageId }),
  );
  assert.equal(released.status, 200);
  assert.deepEqual(await released.json(), { v: 1, storageId, state: "cancelled" });
  assert.deepEqual(
    calls.map(([name]) => name),
    ["authenticate", "finalizeBlob", "authenticate", "releaseBlob"],
  );
});

test("a verified but revoked session is denied with the stable non-retryable class", async () => {
  const { createSyncEdgeHandler } = await loadCore();
  const revoked = Object.assign(new Error("provider detail must stay private"), {
    code: "revoked",
  });
  const { deps, calls } = dependencies({
    authenticate: async (token) => {
      calls.push(["authenticate", token]);
      throw revoked;
    },
  });
  const handler = createSyncEdgeHandler(deps);
  const response = await handler(
    request({ v: 1, action: "finalize_blob", storageId: OPERATION_ID }),
  );
  const body = await response.text();

  assert.equal(response.status, 403);
  assert.deepEqual(JSON.parse(body), { v: 1, error: "revoked" });
  assert.ok(!body.includes(revoked.message));
  assert.deepEqual(calls.map(([name]) => name), ["authenticate"]);
});
