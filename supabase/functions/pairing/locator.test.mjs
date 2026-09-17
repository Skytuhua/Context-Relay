import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { createPairingLocator, pairingLocatorDigest } from './locator.mjs';

test('pairing locator uses the frozen format and a keyed lookup digest', async () => {
  const pepper = new Uint8Array(32).fill(0x42);
  const code = '01234-ABCDE';
  const expected = createHmac('sha256', pepper).update(code.replace('-', '')).digest();
  assert.deepEqual(Buffer.from(await pairingLocatorDigest(pepper, code)), expected);
  const generated = await createPairingLocator(pepper);
  assert.match(generated.code, /^[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}$/);
  assert.deepEqual(Buffer.from(generated.digest), createHmac('sha256', pepper).update(generated.code.replace('-', '')).digest());
  for (const invalid of ['01234-abcde', '01234-ABCDI', '01234ABCDE', ' 01234-ABCDE', '01234-ABCDE\n']) {
    await assert.rejects(pairingLocatorDigest(pepper, invalid), /invalid_pairing_locator/);
  }
  await assert.rejects(pairingLocatorDigest(new Uint8Array(31), code));
  const mutable = new Uint8Array(pepper);
  const pending = pairingLocatorDigest(mutable, code); mutable.fill(0);
  assert.deepEqual(Buffer.from(await pending), expected);
});
