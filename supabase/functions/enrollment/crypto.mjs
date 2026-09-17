const invalid = () => new Error("invalid_enrollment_crypto");
const hex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
// Compressed y coordinates of dalek's EIGHT_TORSION, ignoring the x sign bit.
const WEAK_Y = new Set(["00".repeat(32), "01" + "00".repeat(31), "ec" + "ff".repeat(30) + "7f",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"]);
function fixed(bytes, length) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== length) throw invalid();
  return bytes;
}
function point(bytes) {
  const y = Uint8Array.from(fixed(bytes, 32)); y[31] &= 0x7f;
  if (BigInt("0x" + hex(Uint8Array.from(y).reverse())) >= (1n << 255n) - 19n || WEAK_Y.has(hex(y))) throw invalid();
}

export async function verifyEd25519Strict(publicKey, signature, message) {
  try {
    publicKey = Uint8Array.from(fixed(publicKey, 32));
    signature = Uint8Array.from(fixed(signature, 64));
    point(publicKey); point(signature.subarray(0, 32));
    const key = await crypto.subtle.importKey("raw", publicKey, "Ed25519", false, ["verify"]);
    if (!await crypto.subtle.verify("Ed25519", key, signature, message)) throw invalid();
  } catch { throw invalid(); }
}

export async function validateWrappingKey(publicKey) {
  try {
    const key = await crypto.subtle.importKey("raw", fixed(publicKey, 32), "X25519", false, []);
    // Public, fixed validation scalar, matching Rust's contributory-key check.
    const encoded = Uint8Array.from([0x30,0x2e,0x02,0x01,0,0x30,0x05,0x06,0x03,0x2b,0x65,0x6e,0x04,0x22,0x04,0x20,...new Uint8Array(32).fill(0x42)]);
    const probe = await crypto.subtle.importKey("pkcs8", encoded, "X25519", false, ["deriveBits"]);
    const result = new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: key }, probe, 256));
    if (!result.some(byte => byte !== 0)) throw invalid();
  } catch { throw invalid(); }
}
