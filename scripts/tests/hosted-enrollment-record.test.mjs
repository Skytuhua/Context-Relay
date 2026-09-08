import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { decodeEnrollmentRecord } from "../../supabase/functions/enrollment/record.mjs";

const fixtures = new URL("../../crates/core/tests/fixtures/", import.meta.url);
const record = Buffer.from(readFileSync(new URL("recovery-enrollment-record-v1.hex", fixtures), "utf8").trim(), "hex");

test("hosted decoder agrees with the canonical Rust record and signing preimage", () => {
  const decoded = decodeEnrollmentRecord(record);
  assert.equal(decoded.accountId, "018f22e2-79b0-7cc8-98c4-dc0c0c07398f");
  assert.equal(decoded.workspaceId, "018f22e2-79b0-7cc8-98c4-dc0c0c07398e");
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
