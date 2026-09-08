import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { createEnrollmentEdgeHandler } from "../../supabase/functions/enrollment/core.mjs";
import { decodeRecoveryClaim } from "../../supabase/functions/enrollment/restore.mjs";
import { decodeEnrollmentRecord } from "../../supabase/functions/enrollment/record.mjs";
const fixtures = new URL("../../crates/core/tests/fixtures/", import.meta.url);
const vector = JSON.parse(readFileSync(new URL("hosted-enrollment-proof-v1.json", fixtures)));
const record = readFileSync(new URL("recovery-enrollment-record-v1.hex", fixtures), "utf8").trim();
const decoded = decodeEnrollmentRecord(Buffer.from(record, "hex"));
const body = { v: 1, action: "commit", reservationId: vector.reservationId, record, proof: vector.signature };
function setup() {
  const calls = [];
  const reservation = { reservationId: vector.reservationId, accountId: decoded.accountId,
    workspaceId: decoded.workspaceId, nonce: vector.nonce, expiresAt: "9999999999999" };
  const receipt = { enrollmentId: decoded.enrollmentId, recoveryRootId: decoded.recoveryRootId,
    accountId: decoded.accountId, workspaceId: decoded.workspaceId, genesisCertificateId: decoded.certificateId,
    canonicalRecordSha256: createHash("sha256").update(Buffer.from(record, "hex")).digest("hex"), registeredAtMs: "123" };
  const dependencies = {
    async authenticate() { calls.push("auth"); return { userId: vector.authUserId, sessionId: vector.sessionId }; },
    async reserve() { calls.push("reserve"); return reservation; },
    async renew() { calls.push("renew"); return reservation; },
    async status() { calls.push("status"); return { ...reservation, receipt: null }; },
    async commit(identity, operation, nonce, verified) {
      calls.push("commit");
      assert.equal(identity.userId, vector.authUserId); assert.equal(operation, vector.reservationId);
      assert.equal(Buffer.from(nonce).toString("hex"), vector.nonce);
      assert.equal(Buffer.from(verified.canonicalRecord).toString("hex"), record);
      return receipt;
    },
  };
  return { calls, dependencies, receipt, handler: createEnrollmentEdgeHandler(dependencies) };
}
const request = value => new Request("https://example.test/enrollment", { method: "POST",
  headers: { "content-type": "application/json", authorization: "Bearer synthetic" }, body: JSON.stringify(value) });
test("enrollment commits only a verified canonical record and returns its exact receipt", async () => {
  const f = setup();
  const result = await f.handler(request(body));
  assert.equal(result.status, 200);
  assert.deepEqual(await result.json(), { v: 1, receipt: f.receipt });
  assert.deepEqual(f.calls, ["auth", "status", "commit"]);
});
test("invalid proof, client ownership fields and oversized streaming bodies cannot commit", async () => {
  for (const value of [{ ...body, proof: "00".repeat(64) }, { ...body, userId: vector.authUserId }]) {
    const f = setup(); assert.equal((await f.handler(request(value))).status, 400);
    assert.ok(!f.calls.includes("commit"));
  }
  const f = setup();
  const oversized = request("x".repeat(70 * 1024));
  assert.equal((await f.handler(oversized)).status, 413);
  assert.deepEqual(f.calls, []);
});
test("reserve/status use verified identity and closed provider projections", async () => {
  for (const action of ["reserve", "renew", "status"]) {
    const f = setup();
    assert.equal((await f.handler(request({ v: 1, action, reservationId: vector.reservationId }))).status, 200);
    assert.deepEqual(f.calls, ["auth", action]);
  }
  const f = setup(); f.dependencies.status = async () => { throw new Error("private provider detail"); };
  assert.deepEqual(await (await f.handler(request(body))).json(), { v: 1, error: "transient" });
});
test("a forged commit receipt cannot substitute account identity", async () => {
  const f = setup(); f.dependencies.commit = async () => ({ ...f.receipt, accountId: decoded.enrollmentId });
  const result = await f.handler(request(body));
  assert.equal(result.status, 409);
  assert.deepEqual(await result.json(), { v: 1, error: "enrollment_conflict" });
});

test("snapshot reads only verified owner identity and validates the stored projection", async () => {
  const f = setup();
  const snapshot = { accountId: decoded.accountId, workspaceId: decoded.workspaceId,
    canonicalRecord: record, canonicalRecordSha256: f.receipt.canonicalRecordSha256,
    registeredAtMs: "123", recoveryGeneration: "0" };
  f.dependencies.snapshot = async identity => {
    assert.deepEqual(identity, { userId: vector.authUserId, sessionId: vector.sessionId });
    return snapshot;
  };
  const body = { v: 1, action: "snapshot" };
  assert.deepEqual(await (await f.handler(request(body))).json(), { v: 1, snapshot });
  for (const extra of [{ accountId: decoded.accountId }, { reservationId: vector.reservationId }]) {
    assert.equal((await f.handler(request({ ...body, ...extra }))).status, 400);
  }
  for (const change of [{ canonicalRecordSha256: "00".repeat(32) }, { accountId: decoded.enrollmentId },
    { recoveryGeneration: "-1" }, { secret: "private" }]) {
    f.dependencies.snapshot = async () => ({ ...snapshot, ...change });
    assert.equal((await f.handler(request(body))).status, 400);
  }
  f.dependencies.snapshot = async () => null;
  assert.deepEqual(await (await f.handler(request(body))).json(), { v: 1, snapshot: null });
});

test("restore admission uses the stored root, exact device proof and checked receipt", async () => {
  const vector = JSON.parse(readFileSync(new URL("hosted-recovery-proof-v1.json", fixtures)));
  const claim = readFileSync(new URL("recovery-device-claim-v1.hex", fixtures), "utf8").trim();
  const decodedClaim = decodeRecoveryClaim(Buffer.from(claim,"hex")), f = setup();
  const receipt = { restoreId:decodedClaim.restoreId,enrollmentId:decodedClaim.enrollmentId,
    recoveryRootId:decodedClaim.recoveryRootId,accountId:decodedClaim.accountId,workspaceId:decodedClaim.workspaceId,
    certificateId:decodedClaim.certificateId,canonicalRecordSha256:f.receipt.canonicalRecordSha256,
    canonicalClaimSha256:createHash("sha256").update(Buffer.from(claim,"hex")).digest("hex"),acceptedGeneration:"1",acceptedAtMs:"123" };
  f.dependencies.authenticate = async () => ({ userId:vector.authUserId,sessionId:vector.sessionId });
  f.dependencies.snapshot = async () => ({ accountId:decoded.accountId,workspaceId:decoded.workspaceId,
    canonicalRecord:record,canonicalRecordSha256:f.receipt.canonicalRecordSha256,registeredAtMs:"123",recoveryGeneration:"0" });
  let commits=0;
  f.dependencies.restore = async (identity, verified) => {
    commits++; assert.equal(identity.sessionId,vector.sessionId);
    assert.equal(Buffer.from(verified.canonicalClaim).toString("hex"),claim); return receipt;
  };
  const body = {v:1,action:"restore",claim,proof:vector.signature};
  assert.deepEqual(await (await f.handler(request(body))).json(),{v:1,receipt});
  for (const changed of [{...body,proof:"00".repeat(64)},{...body,accountId:decoded.accountId}]) {
    assert.equal((await f.handler(request(changed))).status,400);
  }
  assert.equal(commits,1);
  f.dependencies.restore = async () => ({...receipt,acceptedGeneration:"2"});
  assert.equal((await f.handler(request(body))).status,409);
  f.dependencies.restoreStatus = async () => ({canonicalClaim:claim,receipt});
  assert.deepEqual(await (await f.handler(request({v:1,action:"restore_status",restoreId:decodedClaim.restoreId}))).json(),
    {v:1,projection:{canonicalClaim:claim,receipt}});
  f.dependencies.restoreStatus = async () => null;
  assert.deepEqual(await (await f.handler(request({v:1,action:"restore_status",restoreId:decodedClaim.restoreId}))).json(),{v:1,projection:null});
  f.dependencies.restoreStatus = async () => ({canonicalClaim:claim,receipt:{...receipt,canonicalClaimSha256:"00".repeat(32)}});
  assert.equal((await f.handler(request({v:1,action:"restore_status",restoreId:decodedClaim.restoreId}))).status,409);
  f.dependencies.snapshot = async () => null;
  assert.equal((await f.handler(request(body))).status,403);
  assert.equal(commits,1);
});
