import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { generateKeyPairSync, sign } from 'node:crypto';
import test from 'node:test';
import { decodePairingRequest, verifyPairingRequest } from './crypto.mjs';
import { CanonicalReader } from '../sync/core.mjs';

const fixture = Buffer.from((await readFile(new URL('../../../crates/protocol/tests/fixtures/pairing-request-v1.hex', import.meta.url), 'utf8')).trim(), 'hex');
const preimage = Buffer.from((await readFile(new URL('../../../crates/protocol/tests/fixtures/pairing-request-signing-preimage-v1.hex', import.meta.url), 'utf8')).trim(), 'hex');

test('canonical text preserves BOM and follows Rust Unicode whitespace', () => {
  for (const value of ['\ufeff', '\ufeffLaptop', '\u0085Laptop']) {
    const bytes = Buffer.from(value);
    const reader = new CanonicalReader(Buffer.concat([Buffer.of(0x60 + bytes.length), bytes]));
    assert.equal(reader.text(512), value);
  }
  for (const value of ['\u0085', '\u2003', ' \t']) {
    const bytes = Buffer.from(value);
    const reader = new CanonicalReader(Buffer.concat([Buffer.of(0x60 + bytes.length), bytes]));
    assert.throws(() => reader.text(512));
  }
});

test('the signed hosted fixture is shared with the Rust crypto verifier', async () => {
  const bytes = Buffer.from((await readFile(new URL('../../../crates/core/tests/fixtures/hosted-pairing-request-v1.hex', import.meta.url), 'utf8')).trim(), 'hex');
  const request = await verifyPairingRequest(bytes);
  assert.equal(request.deviceName, 'new laptop');
  assert.deepEqual(Buffer.from(request.canonicalRequest), bytes);
});

test('pairing request matches the frozen Rust canonical preimage', () => {
  const request = decodePairingRequest(fixture);
  assert.deepEqual(Buffer.from(request.signingPreimage), preimage);
  assert.equal(request.deviceName, 'new laptop');
  assert.equal(request.platform, 1);
  assert.equal(request.pairingId, '018f22e2-79b0-7cc8-98c4-dc0c0c07398f');
});

test('signed request verifies and rejects tampering and invalid encodings', async () => {
  const signing = generateKeyPairSync('ed25519');
  const wrapping = generateKeyPairSync('x25519');
  const bytes = Buffer.from(fixture);
  const signingOffset = bytes.indexOf(Buffer.alloc(32, 3));
  const wrappingOffset = bytes.indexOf(Buffer.alloc(32, 4));
  signing.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).copy(bytes, signingOffset);
  wrapping.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).copy(bytes, wrappingOffset);
  sign(null, decodePairingRequest(bytes).signingPreimage, signing.privateKey).copy(bytes, bytes.length - 64);
  const verified = await verifyPairingRequest(bytes);
  assert.deepEqual(Buffer.from(verified.canonicalRequest), bytes);
  for (const offset of [10, 30, 60, 82, signingOffset, wrappingOffset, bytes.length - 1]) {
    const changed = Buffer.from(bytes); changed[offset] ^= 1;
    await assert.rejects(verifyPairingRequest(changed), /invalid_pairing_request/);
  }
  for (const changed of [Buffer.concat([bytes, Buffer.of(0)]), bytes.subarray(0, -1),
    Buffer.concat([Buffer.of(0xb8, 9), bytes.subarray(1)]), Buffer.alloc(8193), Buffer.alloc(0)]) {
    await assert.rejects(verifyPairingRequest(changed), /invalid_pairing_request/);
  }
  const weak = Buffer.from(bytes); weak.fill(0, wrappingOffset, wrappingOffset + 32);
  sign(null, decodePairingRequest(weak).signingPreimage, signing.privateKey).copy(weak, weak.length - 64);
  await assert.rejects(verifyPairingRequest(weak), /invalid_pairing_request/);
  const retained = Buffer.from(verified.canonicalRequest);
  bytes.fill(0);
  assert.deepEqual(Buffer.from(verified.canonicalRequest), retained);
});
