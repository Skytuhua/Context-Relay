import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { verifyEnrollmentDeviceProof } from "../../supabase/functions/enrollment/proof.mjs";

const root = new URL("../../crates/core/tests/fixtures/", import.meta.url);
const vector = JSON.parse(readFileSync(new URL("hosted-enrollment-proof-v1.json", root)));
const record = Buffer.from(readFileSync(new URL("recovery-enrollment-record-v1.hex", root), "utf8").trim(), "hex");
const key = Buffer.from(vector.publicKey, "hex");
const signature = Buffer.from(vector.signature, "hex");
const context = { ...vector, nonce: Buffer.from(vector.nonce, "hex") };

test("enrollment device proof matches the frozen Rust-checked vector and rejects substitutions", async () => {
  await verifyEnrollmentDeviceProof(context, record, key, signature);
  for (const field of ["reservationId", "authUserId", "sessionId"]) {
    await assert.rejects(verifyEnrollmentDeviceProof({ ...context, [field]: "018f22e2-79b0-7cc8-98c4-dc0c0c073989" }, record, key, signature));
  }
  await assert.rejects(verifyEnrollmentDeviceProof({ ...context, nonce: Buffer.alloc(32, 8) }, record, key, signature));
  const changed = Buffer.from(record); changed[changed.length - 1] ^= 1;
  await assert.rejects(verifyEnrollmentDeviceProof(context, changed, key, signature));
  for (const bad of [Buffer.alloc(0), Buffer.alloc(32 * 1024 + 1)]) {
    await assert.rejects(verifyEnrollmentDeviceProof(context, bad, key, signature));
  }
  await assert.rejects(verifyEnrollmentDeviceProof(context, record, Buffer.alloc(31), signature));
  await assert.rejects(verifyEnrollmentDeviceProof(context, record, key, Buffer.alloc(64)));
});
