import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {verifyPairingApproval} from './approval.mjs';
import {verifyPairingDeviceProof} from './proof.mjs';
const fixture=JSON.parse(readFileSync(new URL('../../../crates/core/tests/fixtures/hosted-pairing-approval-v2.json',import.meta.url),'utf8'));
const bytes=key=>Buffer.from(fixture[key],'hex');
test('real Rust V2 approval binds accepted parent, enrollment, exact issuer and ADD signature',async()=>{
  const approved=await verifyPairingApproval(bytes('canonicalApprovedPayload'),bytes('canonicalRequest'),fixture.trusted,bytes('membershipSignature'));
  assert.equal(Buffer.from(approved.previousStateSha256).toString('hex'),fixture.trusted.stateSha256);
  assert.equal(approved.issuerCertificateId,fixture.trusted.issuerCertificateId);
  for(const key of Object.keys(fixture.trusted)) {
    const changed={...fixture.trusted,[key]:typeof fixture.trusted[key]==='number'?fixture.trusted[key]+1:'invalid'};
    await assert.rejects(verifyPairingApproval(bytes('canonicalApprovedPayload'),bytes('canonicalRequest'),changed,bytes('membershipSignature')),/invalid_pairing_approval/);
  }
  const signature=bytes('membershipSignature');signature[0]^=1;
  await assert.rejects(verifyPairingApproval(bytes('canonicalApprovedPayload'),bytes('canonicalRequest'),fixture.trusted,signature),/invalid_pairing_approval/);
  await assert.rejects(verifyPairingApproval(bytes('canonicalApprovedPayload'),bytes('canonicalRequest'),fixture.trusted),/invalid_pairing_approval/);
  for(const canonical of [Buffer.concat([bytes('canonicalApprovedPayload'),Buffer.of(0)]),Buffer.alloc(32769)]) {
    await assert.rejects(verifyPairingApproval(canonical,bytes('canonicalRequest'),fixture.trusted,bytes('membershipSignature')),/invalid_pairing_approval/);
  }
});
test('V2 hosted possession proof binds detached signature and original request',async()=>{
  const approved=await verifyPairingApproval(bytes('canonicalApprovedPayload'),bytes('canonicalRequest'),fixture.trusted,bytes('membershipSignature'));
  const binding={requestDigest:approved.requestDigest,membershipSignature:bytes('membershipSignature')};
  const proof=Buffer.from(fixture.proofs.approval,'hex');
  const key=Buffer.from(fixture.trusted.issuerSigningKey,'hex');
  await verifyPairingDeviceProof(fixture.proofs,'approval',bytes('canonicalApprovedPayload'),key,proof,binding);
  await assert.rejects(verifyPairingDeviceProof(fixture.proofs,'approval',bytes('canonicalApprovedPayload'),key,proof,{...binding,requestDigest:Buffer.alloc(32)}),/invalid_pairing_proof/);
  await assert.rejects(verifyPairingDeviceProof(fixture.proofs,'approval',bytes('canonicalApprovedPayload'),key,proof,{...binding,membershipSignature:Buffer.alloc(64)}),/invalid_pairing_proof/);
});
