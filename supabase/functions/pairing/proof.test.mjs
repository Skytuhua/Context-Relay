import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { verifyPairingDeviceProof } from './proof.mjs';

test('pairing proofs bind operation, authenticated user, session, payload and device key', async () => {
  const context = { authUserId: '550e8400-e29b-41d4-a716-446655440000', sessionId: '550e8400-e29b-41d4-a716-446655440001' };
  const keys = generateKeyPairSync('ed25519');
  const publicKey = keys.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const payload = Buffer.from('canonical payload is validated by the caller');
  for (const operation of ['request', 'approval']) {
    const preimage = Buffer.concat([Buffer.from(`context-relay/hosted-pairing-${operation}-proof/v1\0`),
      Buffer.from(context.authUserId.replaceAll('-', ''), 'hex'), Buffer.from(context.sessionId.replaceAll('-', ''), 'hex'),
      createHash('sha256').update(payload).digest()]);
    const signature = sign(null, preimage, keys.privateKey);
    await verifyPairingDeviceProof(context, operation, payload, publicKey, signature);
    for (const changed of [{ ...context, sessionId: context.authUserId }, { ...context, authUserId: context.sessionId }]) {
      await assert.rejects(verifyPairingDeviceProof(changed, operation, payload, publicKey, signature));
    }
    await assert.rejects(verifyPairingDeviceProof(context, operation === 'request' ? 'approval' : 'request', payload, publicKey, signature));
    await assert.rejects(verifyPairingDeviceProof(context, operation, Buffer.concat([payload, Buffer.of(0)]), publicKey, signature));
    await assert.rejects(verifyPairingDeviceProof(context, operation, payload, new Uint8Array(32), signature));
    await assert.rejects(verifyPairingDeviceProof(context, operation, new Uint8Array(operation === 'request' ? 8193 : 32769), publicKey, signature));
    const copied = Buffer.from(payload), proof = Buffer.from(signature), key = Buffer.from(publicKey), identity = { ...context };
    const pending = verifyPairingDeviceProof(identity, operation, copied, key, proof);
    copied.fill(0); proof.fill(0); key.fill(0); identity.sessionId = 'changed';
    await pending;
  }
  await assert.rejects(verifyPairingDeviceProof(context, 'cancel', payload, publicKey, new Uint8Array(64)));
});
