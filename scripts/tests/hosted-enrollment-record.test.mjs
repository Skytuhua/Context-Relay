import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash, createPrivateKey, createPublicKey, hkdfSync, pbkdf2Sync, sign } from "node:crypto";
import { decodeEnrollmentRecord, verifyEnrollmentRecord } from "../../supabase/functions/enrollment/record.mjs";
import { CanonicalReader } from "../../supabase/functions/sync/core.mjs";

const fixtures = new URL("../../crates/core/tests/fixtures/", import.meta.url);
const record = Buffer.from(readFileSync(new URL("recovery-enrollment-record-v1.hex", fixtures), "utf8").trim(), "hex");

test("hosted verification requires valid record, certificate and device signatures", async () => {
  const vector = JSON.parse(readFileSync(new URL("hosted-enrollment-proof-v1.json", fixtures)));
  const context = { ...vector, nonce: Buffer.from(vector.nonce, "hex") };
  const proof = Buffer.from(vector.signature, "hex");
  const verified = await verifyEnrollmentRecord(record, context, proof);
  assert.equal(verified.deviceId, "018f22e2-79b0-7cc8-98c4-dc0c0c07398b");
  const changed = Buffer.from(record); changed[changed.length - 1] ^= 1;
  await assert.rejects(verifyEnrollmentRecord(changed, context, proof));
  await assert.rejects(verifyEnrollmentRecord(record, context, Buffer.alloc(64)));
  const input = Buffer.from(record);
  const pending = verifyEnrollmentRecord(input, context, proof);
  input.fill(0); context.nonce.fill(0); context.sessionId = "changed"; proof.fill(0);
  assert.deepEqual(Buffer.from((await pending).canonicalRecord), record);
});

test("valid outer signatures cannot conceal a bad certificate or wrapping key", async () => {
  const vector = JSON.parse(readFileSync(new URL("hosted-enrollment-proof-v1.json", fixtures)));
  const context = { ...vector, nonce: Buffer.from(vector.nonce, "hex") };
  const privateKey = seed => createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(seed)]), format: "der", type: "pkcs8" });
  // The existing fixture uses the public BIP39 zero-entropy test vector.
  const seed = pbkdf2Sync([...Array(23).fill("abandon"), "art"].join(" "), "mnemonic", 2048, 64, "sha512");
  const rootKey = privateKey(hkdfSync("sha256", seed, "context-relay/recovery/v1", "context-relay/recovery/signing/v1", 32));
  const deviceKey = privateKey(Buffer.alloc(32, 0x11));
  const decoded = decodeEnrollmentRecord(record);
  assert.deepEqual(createPublicKey(rootKey).export({ format: "der", type: "spki" }).subarray(-32), Buffer.from(decoded.recoverySigningKey));
  for (const field of ["certificateSignature", "recoveryWrappingKey", "ephemeralKey"]) {
    const changed = Buffer.from(record);
    const offset = record.indexOf(decoded[field]);
    assert.ok(offset >= 0);
    changed.fill(0, offset, offset + decoded[field].length);
    const parsed = decodeEnrollmentRecord(changed);
    changed.set(sign(null, parsed.signingPreimage, rootKey), changed.length - 64);
    const proofPreimage = Buffer.concat([Buffer.from(vector.preimage, "hex").subarray(0, -32), createHash("sha256").update(changed).digest()]);
    await assert.rejects(verifyEnrollmentRecord(changed, context, sign(null, proofPreimage, deviceKey)));
  }
});

test("hosted decoder agrees with the canonical Rust record and signing preimage", () => {
  const decoded = decodeEnrollmentRecord(record);
  assert.equal(decoded.accountId, "018f22e2-79b0-7cc8-98c4-dc0c0c07398f");
  assert.equal(decoded.workspaceId, "018f22e2-79b0-7cc8-98c4-dc0c0c07398e");
  const metadata = new CanonicalReader(decoded.encryptedMetadata);
  metadata.expectMap(3);
  metadata.expectUnsigned(0); assert.deepEqual(metadata.fixedBytes(32), decoded.ephemeralKey);
  metadata.expectUnsigned(1); assert.deepEqual(metadata.fixedBytes(24), decoded.nonce);
  metadata.expectUnsigned(2); assert.deepEqual(metadata.byteString(32768), decoded.ciphertext);
  assert.equal(metadata.position, decoded.encryptedMetadata.length);
  assert.equal(Buffer.from(decoded.signingPreimage).toString("hex"), readFileSync(new URL("recovery-enrollment-signing-preimage-v1.hex", fixtures), "utf8").trim());
  const input = Buffer.from(record);
  const owned = decodeEnrollmentRecord(input);
  input.fill(0);
  assert.deepEqual(Buffer.from(owned.canonicalRecord), record);
});

test("hosted decoder rejects truncation, trailing data and noncanonical record structure", () => {
  for (let length = 0; length < record.length; length++) assert.throws(() => decodeEnrollmentRecord(record.subarray(0, length)));
  assert.throws(() => decodeEnrollmentRecord(Buffer.concat([record, Buffer.from([0])])));
  assert.throws(() => decodeEnrollmentRecord(Buffer.alloc(32769)));
  for (const prefix of [[0xbf], [0xb8, 14], [0xae, 0x18, 0], [0xae, 1]]) {
    assert.throws(() => decodeEnrollmentRecord(Buffer.concat([Buffer.from(prefix), record.subarray(prefix.length === 1 ? 1 : 2)])));
  }
});

test("hosted decoder rejects scope/key mismatches and malformed UTF-8", () => {
  const decoded = decodeEnrollmentRecord(record);
  const account = Buffer.from(decoded.accountId.replaceAll("-", ""), "hex");
  const firstAccount = record.indexOf(account);
  const certificateAccount = record.indexOf(account, firstAccount + 16);
  assert.ok(certificateAccount > firstAccount);
  const mismatched = Buffer.from(record); mismatched[certificateAccount + 15] ^= 1;
  assert.throws(() => decodeEnrollmentRecord(mismatched));
  const invalidId = Buffer.from(record); invalidId[firstAccount + 6] = 0;
  assert.throws(() => decodeEnrollmentRecord(invalidId));
  const repeatedKey = Buffer.from(record);
  repeatedKey.set(decoded.recoverySigningKey, record.indexOf(decoded.recoveryWrappingKey));
  assert.throws(() => decodeEnrollmentRecord(repeatedKey));
  const invalidText = Buffer.from(record); invalidText[record.indexOf(Buffer.from(decoded.deviceName))] = 0xff;
  assert.throws(() => decodeEnrollmentRecord(invalidText));
});
