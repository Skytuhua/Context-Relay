import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { verifyEd25519Strict, validateWrappingKey } from "../../supabase/functions/enrollment/crypto.mjs";

const vector = JSON.parse(readFileSync(new URL("../../crates/core/tests/fixtures/hosted-enrollment-proof-v1.json", import.meta.url)));
const bytes = value => Buffer.from(value, "hex");
test("strict Ed25519 accepts the independent vector and rejects weak/noncanonical points", async () => {
  await verifyEd25519Strict(bytes(vector.publicKey), bytes(vector.signature), bytes(vector.preimage));
  const noncanonical = bytes(vector.signature);
  let scalar = BigInt("0x" + Buffer.from(noncanonical.subarray(32)).reverse().toString("hex"))
    + (1n << 252n) + 27742317777372353535851937790883648493n;
  for (let index = 32; index < 64; index++) { noncanonical[index] = Number(scalar & 255n); scalar >>= 8n; }
  await assert.rejects(verifyEd25519Strict(bytes(vector.publicKey), noncanonical, bytes(vector.preimage)));
  for (const point of ["01" + "00".repeat(31), "00".repeat(32), "ec" + "ff".repeat(30) + "7f",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "ed" + "ff".repeat(30) + "7f"]) {
    for (const sign of [0, 128]) {
      const key = bytes(point); key[31] |= sign;
      await assert.rejects(verifyEd25519Strict(key, bytes(vector.signature), bytes(vector.preimage)));
      const signature = bytes(vector.signature); signature.set(key);
      await assert.rejects(verifyEd25519Strict(bytes(vector.publicKey), signature, bytes(vector.preimage)));
    }
  }
});
test("X25519 rejects non-contributory public keys", async () => {
  const base = Buffer.alloc(32); base[0] = 9;
  await validateWrappingKey(base);
  for (const low of [0, 1]) {
    const key = Buffer.alloc(32); key[0] = low;
    await assert.rejects(validateWrappingKey(key));
  }
  await assert.rejects(validateWrappingKey(Buffer.alloc(31)));
});
