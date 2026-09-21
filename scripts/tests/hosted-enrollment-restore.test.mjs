import test from "node:test";
import assert from "node:assert/strict";
import { createHash, createPrivateKey, hkdfSync, pbkdf2Sync, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { decodeRecoveryClaim, verifyRecoveryClaim } from "../../supabase/functions/enrollment/restore.mjs";
const fixtures = new URL("../../crates/core/tests/fixtures/", import.meta.url);
const bytes = name => Buffer.from(readFileSync(new URL(name, fixtures), "utf8").trim(), "hex");
const claim = bytes("recovery-device-claim-v1.hex"), root = bytes("recovery-enrollment-record-v1.hex");

test("recovery claim name uses the shared Rust-compatible text rules", () => {
  const original = Buffer.from(decodeRecoveryClaim(claim).deviceName);
  const offset = claim.indexOf(original);
  assert.ok(offset > 0 && original.length < 24);
  for (const name of ["\ufeff", "\ufeffLaptop"]) {
    const value = Buffer.from(name);
    const changed = Buffer.concat([claim.subarray(0, offset - 1), Buffer.of(0x60 + value.length), value, claim.subarray(offset + original.length)]);
    assert.equal(decodeRecoveryClaim(changed).deviceName, name);
  }
});

const context = { authUserId: "550e8400-e29b-41d4-a716-446655440000", sessionId: "550e8400-e29b-41d4-a716-446655440001" };
const key = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.alloc(32, 0x66)]), format: "der", type: "pkcs8" });
function proof(input) {
  return sign(null, Buffer.concat([Buffer.from("context-relay/hosted-recovery-device-proof/v1\0"),
    Buffer.from(context.authUserId.replaceAll("-", ""), "hex"), Buffer.from(context.sessionId.replaceAll("-", ""), "hex"),
    createHash("sha256").update(input).digest()]), key);
}
const verify = (input, rootInput) => verifyRecoveryClaim(input, rootInput, context, proof(input));

test("hosted recovery proof consumes the shared native vector", async () => {
  const vector = JSON.parse(readFileSync(new URL("hosted-recovery-proof-v1.json", fixtures)));
  assert.equal(proof(claim).toString("hex"), vector.signature);
  assert.equal((await verifyRecoveryClaim(claim, root, vector, Buffer.from(vector.signature, "hex"))).restoreId,
    decodeRecoveryClaim(claim).restoreId);
});

test("hosted restore verifier agrees with the frozen Rust claim and signing preimage", async () => {
  const decoded = await verify(claim, root);
  assert.deepEqual(Buffer.from(decoded.canonicalClaim), claim);
  assert.deepEqual(Buffer.from(decoded.signingPreimage), bytes("recovery-device-claim-signing-preimage-v1.hex"));
  assert.equal(decoded.expectedRecoveryGeneration, "0");
  const owned = Buffer.from(claim), pending = verify(owned, root);
  owned.fill(0);
  assert.deepEqual(Buffer.from((await pending).canonicalClaim), claim);
});

test("hosted restore rejects malformed encoding and altered signatures or record binding", async () => {
  for (let end = 0; end < claim.length; end++) assert.throws(() => decodeRecoveryClaim(claim.subarray(0, end)));
  for (const value of [Buffer.concat([claim, Buffer.from([0])]), Buffer.alloc(32769),
    Buffer.concat([Buffer.from([0xb8,15]),claim.subarray(1)])]) assert.throws(() => decodeRecoveryClaim(value));
  const decoded = decodeRecoveryClaim(claim);
  for (const field of ["rootSignature", "certificateSignature", "canonicalRecordSha256", "deviceWrappingKey", "ephemeralKey"]) {
    const changed = Buffer.from(claim), offset = claim.indexOf(decoded[field]);
    assert.ok(offset >= 0); changed[offset] ^= 1;
    await assert.rejects(verify(changed, root), /invalid_recovery_claim/);
  }
  const badRoot = Buffer.from(root); badRoot[badRoot.length-1] ^= 1;
  await assert.rejects(verify(claim, badRoot), /invalid_recovery_claim/);
});

test("restore requires the certified device's proof over the exact claim and Auth session", async () => {
  await assert.rejects(verifyRecoveryClaim(claim, root, context, Buffer.alloc(64)));
  await assert.rejects(verifyRecoveryClaim(claim, root, { ...context, sessionId: context.authUserId }, proof(claim)));
  await assert.rejects(verifyRecoveryClaim(claim, root, { ...context, authUserId: context.sessionId }, proof(claim)));
});

test("a valid outer signature cannot hide an invalid certificate or wrapping key", async () => {
  const seed = pbkdf2Sync([...Array(23).fill("abandon"), "art"].join(" "), "mnemonic", 2048, 64, "sha512");
  const rootKey = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.from(hkdfSync("sha256", seed, "context-relay/recovery/v1", "context-relay/recovery/signing/v1", 32))]), format: "der", type: "pkcs8" });
  const decoded = decodeRecoveryClaim(claim);
  for (const field of ["certificateSignature", "ephemeralKey", "canonicalRecordSha256"]) {
    const changed = Buffer.from(claim), offset = claim.indexOf(decoded[field]);
    assert.ok(offset >= 0); changed.fill(0, offset, offset+decoded[field].length);
    changed.set(sign(null, decodeRecoveryClaim(changed).signingPreimage, rootKey), changed.length-64);
    await assert.rejects(verify(changed, root), /invalid_recovery_claim/);
  }
});
