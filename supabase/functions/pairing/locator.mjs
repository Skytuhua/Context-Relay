const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const invalid = () => new Error('invalid_pairing_locator');

// A locator carries no device authority. Persist only this keyed digest, never
// the returned raw code. The server-owned pepper is not a client configuration.
export async function pairingLocatorDigest(pepper, code) {
  if (!(pepper instanceof Uint8Array) || pepper.length !== 32 || typeof code !== 'string'
    || code.length !== 11 || !/^[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}$/.test(code)) throw invalid();
  const secret = Uint8Array.from(pepper);
  try {
    const key = await crypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(code.replace('-', ''))));
  } catch { throw invalid(); }
  finally { secret.fill(0); }
}

export async function createPairingLocator(pepper) {
  // Ten independent uniform five-bit symbols give exactly 50 random bits.
  const symbols = Array.from(crypto.getRandomValues(new Uint8Array(10)), byte => ALPHABET[byte & 31]).join('');
  const code = `${symbols.slice(0, 5)}-${symbols.slice(5)}`;
  return { code, digest: await pairingLocatorDigest(pepper, code) };
}
