import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { verifyPairingApproval } from './approval.mjs';
import { verifyPairingRequest } from './crypto.mjs';
import { verifyPairingDeviceProof } from './proof.mjs';

const fixtures = new URL('../../../crates/core/tests/fixtures/', import.meta.url);
const fixture = JSON.parse(readFileSync(new URL('hosted-pairing-approval-v1.json', fixtures), 'utf8'));
const approved = Buffer.from(fixture.canonicalApprovedPayload, 'hex');
const request = Buffer.from(readFileSync(new URL('hosted-pairing-request-v1.hex', fixtures), 'utf8').trim(), 'hex');

test('Rust-frozen request and approval possession proofs verify at the Edge', async () => {
  const signed = await verifyPairingRequest(request);
  const approval = await verifyPairingApproval(approved, request, fixture.trusted);
  await verifyPairingDeviceProof(fixture.proofs, 'request', request, signed.signingPublicKey, Buffer.from(fixture.proofs.request, 'hex'));
  await verifyPairingDeviceProof(fixture.proofs, 'approval', approved, approval.issuer.signingKey, Buffer.from(fixture.proofs.approval, 'hex'));
  await assert.rejects(verifyPairingDeviceProof(fixture.proofs, 'approval', approved, approval.issuer.signingKey, Buffer.from(fixture.proofs.request, 'hex')));
});

test('Rust-generated approval verifies only against the selected authority and request', async () => {
  const result = await verifyPairingApproval(approved, request, fixture.trusted);
  assert.equal(result.issuer.deviceId, fixture.trusted.issuerDeviceId);
  assert.equal(result.child.accountId, fixture.trusted.accountId);
  for (const key of Object.keys(fixture.trusted)) {
    const changed = { ...fixture.trusted, [key]: typeof fixture.trusted[key] === 'number' ? fixture.trusted[key] + 1 : 'invalid' };
    await assert.rejects(verifyPairingApproval(approved, request, changed), /invalid_pairing_approval/);
  }
  for (const value of [Buffer.concat([approved, Buffer.of(0)]), approved.subarray(0, -1), Buffer.alloc(32769)]) {
    await assert.rejects(verifyPairingApproval(value, request, fixture.trusted), /invalid_pairing_approval/);
  }
  const changed = Buffer.from(approved);
  const keyOffset = changed.indexOf(Buffer.from(fixture.trusted.issuerSigningKey, 'hex'));
  assert.ok(keyOffset > 0);
  changed[keyOffset] ^= 1;
  await assert.rejects(verifyPairingApproval(changed, request, fixture.trusted), /invalid_pairing_approval/);
  for (const signature of [result.issuer.signature, result.child.signature]) {
    const invalidSignature = Buffer.from(approved);
    const offset = invalidSignature.indexOf(Buffer.from(signature));
    assert.ok(offset > 0);
    invalidSignature[offset] ^= 1;
    await assert.rejects(verifyPairingApproval(invalidSignature, request, fixture.trusted), /invalid_pairing_approval/);
  }
  const changedRequest = Buffer.from(request); changedRequest[30] ^= 1;
  await assert.rejects(verifyPairingApproval(approved, changedRequest, fixture.trusted), /invalid_pairing_approval/);
});

test('approval verification snapshots caller-owned data before asynchronous verification', async () => {
  const payload = Buffer.from(approved), signedRequest = Buffer.from(request);
  const trusted = { ...fixture.trusted };
  const pending = verifyPairingApproval(payload, signedRequest, trusted);
  payload.fill(0); signedRequest.fill(0); trusted.accountId = 'changed';
  const result = await pending;
  assert.deepEqual(Buffer.from(result.canonicalApprovedPayload), approved);
  assert.equal(result.child.accountId, fixture.trusted.accountId);
});
