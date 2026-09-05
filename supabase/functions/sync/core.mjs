export const MAX_SYNC_REQUEST_BYTES = 8 * 1024 * 1024;
export const MAX_SYNC_OPERATIONS = 256;

const MAX_OPERATION_BYTES = 5 * 1024 * 1024;
const MAX_CIPHERTEXT_BYTES = 4 * 1024 * 1024;
const MAX_BLOB_BYTES = 500 * 1024 * 1024;
const MAX_PROTOCOL_ITEMS = 10_000;
const MAX_TITLE_BYTES = 512;
const JSON_HEADERS = Object.freeze({
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
});
const RECORD_KINDS = Object.freeze([
  "memory",
  "memory_candidate",
  "task",
  "secret_ref",
  "instruction",
  "component",
  "project",
]);
const MUTATION_KINDS = Object.freeze(["upsert", "tombstone"]);
const textDecoder = new TextDecoder("utf-8", { fatal: true });
const textEncoder = new TextEncoder();
const CERTIFICATE_DOMAIN = textEncoder.encode("context-relay/device-certificate/v1\0");

class SyncEdgeError extends Error {
  constructor(status, code) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

class CanonicalReader {
  constructor(bytes) {
    this.bytes = bytes;
    this.position = 0;
  }

  readByte() {
    if (this.position >= this.bytes.length) throw invalidEnvelope();
    return this.bytes[this.position++];
  }

  readLength(major) {
    const first = this.readByte();
    if (first >> 5 !== major) throw invalidEnvelope();
    const additional = first & 0x1f;
    if (additional < 24) return BigInt(additional);
    if (additional === 24) {
      const value = BigInt(this.readByte());
      if (value < 24n) throw invalidEnvelope();
      return value;
    }
    if (additional === 25) {
      const value = BigInt(this.readUnsignedBytes(2));
      if (value <= 0xffn) throw invalidEnvelope();
      return value;
    }
    if (additional === 26) {
      const value = BigInt(this.readUnsignedBytes(4));
      if (value <= 0xffffn) throw invalidEnvelope();
      return value;
    }
    if (additional === 27) {
      const value = this.readBigUnsignedBytes(8);
      if (value <= 0xffff_ffffn) throw invalidEnvelope();
      return value;
    }
    throw invalidEnvelope();
  }

  readUnsignedBytes(length) {
    let value = 0;
    for (let index = 0; index < length; index += 1) {
      value = value * 256 + this.readByte();
    }
    return value;
  }

  readBigUnsignedBytes(length) {
    let value = 0n;
    for (let index = 0; index < length; index += 1) {
      value = value * 256n + BigInt(this.readByte());
    }
    return value;
  }

  unsigned(maximum = 0xffff_ffff_ffff_ffffn) {
    const value = this.readLength(0);
    if (value > maximum) throw invalidEnvelope();
    return value;
  }

  expectUnsigned(expected) {
    if (this.unsigned(255n) !== BigInt(expected)) throw invalidEnvelope();
  }

  expectMap(length) {
    if (this.readLength(5) !== BigInt(length)) throw invalidEnvelope();
  }

  expectArray(length) {
    if (this.readLength(4) !== BigInt(length)) throw invalidEnvelope();
  }

  arrayLength(maximum) {
    const length = this.readLength(4);
    if (length > BigInt(maximum)) throw invalidEnvelope();
    return Number(length);
  }

  byteString(maximum = MAX_OPERATION_BYTES) {
    const length = this.readLength(2);
    if (length > BigInt(maximum)) throw invalidEnvelope();
    const end = this.position + Number(length);
    if (end > this.bytes.length) throw invalidEnvelope();
    const value = this.bytes.subarray(this.position, end);
    this.position = end;
    return value;
  }

  fixedBytes(length) {
    const value = this.byteString(length);
    if (value.length !== length) throw invalidEnvelope();
    return value;
  }

  text(maximum) {
    const length = this.readLength(3);
    if (length > BigInt(maximum)) throw invalidEnvelope();
    const end = this.position + Number(length);
    if (end > this.bytes.length) throw invalidEnvelope();
    let value;
    try {
      value = textDecoder.decode(this.bytes.subarray(this.position, end));
    } catch {
      throw invalidEnvelope();
    }
    this.position = end;
    if (value.trim().length === 0) throw invalidEnvelope();
    return value;
  }

  nullableUuid() {
    if (this.bytes[this.position] === 0xf6) {
      this.position += 1;
      return null;
    }
    return uuid(this.fixedBytes(16));
  }
}

function invalidEnvelope() {
  return new SyncEdgeError(422, "invalid_envelope");
}

function response(status, body) {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
}

function safeError(error) {
  if (error instanceof SyncEdgeError) return response(error.status, { v: 1, error: error.code });
  const code = typeof error?.code === "string" ? error.code : "";
  if (code === "auth_required") return response(401, { v: 1, error: code });
  if (code === "revoked") return response(403, { v: 1, error: code });
  if (code === "quota_blocked") return response(409, { v: 1, error: code });
  if (code === "conflict") return response(409, { v: 1, error: code });
  if (code === "integrity_quarantined") return response(422, { v: 1, error: code });
  if (code === "configuration_error") return response(503, { v: 1, error: code });
  return response(503, { v: 1, error: "transient" });
}

function ownKeysExactly(value, expected) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const keys = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return keys.length === wanted.length && keys.every((key, index) => key === wanted[index]);
}

function strictAuthorization(request) {
  const header = request.headers.get("authorization");
  if (header === null || !/^Bearer [^\s]+$/.test(header)) {
    throw new SyncEdgeError(401, "auth_required");
  }
  return header.slice("Bearer ".length);
}

async function readBoundedBody(request) {
  if (request.body === null) return new Uint8Array();
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) {
        throw new SyncEdgeError(400, "invalid_request");
      }
      total += value.length;
      if (total > MAX_SYNC_REQUEST_BYTES) {
        try {
          await reader.cancel();
        } catch {
          // The size limit remains authoritative even if the peer cannot be cancelled cleanly.
        }
        throw new SyncEdgeError(413, "request_too_large");
      }
      chunks.push(value);
    }
  } catch (error) {
    if (error instanceof SyncEdgeError) throw error;
    throw new SyncEdgeError(400, "invalid_request");
  } finally {
    reader.releaseLock();
  }
  return concatenate(chunks);
}

async function readRequest(request) {
  if (request.method !== "POST") throw new SyncEdgeError(405, "method_not_allowed");
  const contentLength = request.headers.get("content-length");
  if (contentLength !== null) {
    if (!/^(0|[1-9][0-9]*)$/.test(contentLength)) {
      throw new SyncEdgeError(400, "invalid_request");
    }
    if (BigInt(contentLength) > BigInt(MAX_SYNC_REQUEST_BYTES)) {
      throw new SyncEdgeError(413, "request_too_large");
    }
  }
  const bytes = await readBoundedBody(request);
  let body;
  try {
    body = JSON.parse(textDecoder.decode(bytes));
  } catch {
    throw new SyncEdgeError(400, "invalid_request");
  }
  if (body === null || typeof body !== "object" || Array.isArray(body) || body.v !== 1) {
    throw new SyncEdgeError(400, "invalid_request");
  }
  if (body.action === "push_operations") {
    if (
      !ownKeysExactly(body, ["v", "action", "operations"]) ||
      !Array.isArray(body.operations) ||
      body.operations.length === 0 ||
      body.operations.length > MAX_SYNC_OPERATIONS
    ) {
      throw new SyncEdgeError(400, "invalid_request");
    }
  } else if (body.action === "push_checkpoint") {
    if (
      !ownKeysExactly(body, ["v", "action", "checkpoint"]) ||
      typeof body.checkpoint !== "string"
    ) {
      throw new SyncEdgeError(400, "invalid_request");
    }
  } else if (body.action === "reserve_blob") {
    if (
      !ownKeysExactly(body, [
        "v",
        "action",
        "workspaceId",
        "storageId",
        "ciphertextSha256",
        "partSizes",
        "expiresAt",
      ]) ||
      typeof body.workspaceId !== "string" ||
      typeof body.storageId !== "string" ||
      typeof body.ciphertextSha256 !== "string" ||
      !Array.isArray(body.partSizes) ||
      typeof body.expiresAt !== "string"
    ) {
      throw new SyncEdgeError(400, "invalid_request");
    }
  } else if (body.action === "finalize_blob" || body.action === "release_blob") {
    if (
      !ownKeysExactly(body, ["v", "action", "storageId"]) ||
      typeof body.storageId !== "string"
    ) {
      throw new SyncEdgeError(400, "invalid_request");
    }
  } else {
    throw new SyncEdgeError(400, "invalid_request");
  }
  return body;
}

function strictBase64Url(value) {
  if (typeof value !== "string" || value.length === 0 || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw invalidEnvelope();
  }
  const standard = value.replaceAll("-", "+").replaceAll("_", "/");
  const padding = (4 - (standard.length % 4)) % 4;
  let decoded;
  try {
    const binary = atob(`${standard}${"=".repeat(padding)}`);
    decoded = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    throw invalidEnvelope();
  }
  let decodedBinary = "";
  for (let offset = 0; offset < decoded.length; offset += 0x8000) {
    decodedBinary += String.fromCharCode(...decoded.subarray(offset, offset + 0x8000));
  }
  const canonical = btoa(decodedBinary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
  if (decoded.length > MAX_OPERATION_BYTES || canonical !== value) {
    throw invalidEnvelope();
  }
  return decoded;
}

function uuid(bytes) {
  if (bytes.length !== 16 || bytes[6] >> 4 !== 7 || (bytes[8] & 0xc0) !== 0x80) {
    throw invalidEnvelope();
  }
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function uuidStringBytes(value) {
  if (
    typeof value !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value)
  ) {
    throw invalidEnvelope();
  }
  return hexBytes(value.replaceAll("-", ""), 16);
}

function hexBytes(value, length) {
  if (typeof value !== "string" || !new RegExp(`^[0-9a-f]{${length * 2}}$`).test(value)) {
    throw invalidEnvelope();
  }
  const bytes = new Uint8Array(length);
  for (let index = 0; index < length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function u32be(value) {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff_ffff) throw invalidEnvelope();
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, false);
  return bytes;
}

function concatenate(parts) {
  const length = parts.reduce((total, part) => total + part.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function compareBytes(left, right) {
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return 0;
}

function readFrontier(reader) {
  const length = reader.arrayLength(MAX_PROTOCOL_ITEMS);
  const entries = [];
  let previous = null;
  for (let index = 0; index < length; index += 1) {
    reader.expectArray(2);
    const deviceBytes = reader.fixedBytes(16);
    if (previous !== null && compareBytes(previous, deviceBytes) >= 0) throw invalidEnvelope();
    previous = deviceBytes;
    entries.push({ deviceId: uuid(deviceBytes), sequence: reader.unsigned().toString() });
  }
  return entries;
}

function readBlobs(reader) {
  const length = reader.arrayLength(MAX_PROTOCOL_ITEMS);
  const blobs = [];
  for (let index = 0; index < length; index += 1) {
    reader.expectMap(3);
    reader.expectUnsigned(0);
    const digest = reader.fixedBytes(32);
    reader.expectUnsigned(1);
    const ciphertextBytes = reader.unsigned(BigInt(MAX_BLOB_BYTES));
    if (ciphertextBytes === 0n) throw invalidEnvelope();
    reader.expectUnsigned(2);
    const storageId = reader.text(MAX_TITLE_BYTES);
    blobs.push({ digest, ciphertextBytes: ciphertextBytes.toString(), storageId });
  }
  return blobs;
}

function readHlc(reader) {
  reader.expectMap(3);
  reader.expectUnsigned(0);
  const physicalMs = reader.unsigned().toString();
  reader.expectUnsigned(1);
  const logical = Number(reader.unsigned(0xffff_ffffn));
  reader.expectUnsigned(2);
  const node = uuid(reader.fixedBytes(16));
  return { physicalMs, logical, node };
}

function decodeCheckpoint(canonicalBytes) {
  if (canonicalBytes.length === 0 || canonicalBytes.length > MAX_OPERATION_BYTES) {
    throw invalidEnvelope();
  }
  const reader = new CanonicalReader(canonicalBytes);
  reader.expectMap(10);
  reader.expectUnsigned(0);
  const schemaVersion = Number(reader.unsigned(0xffffn));
  if (schemaVersion !== 2) throw invalidEnvelope();
  reader.expectUnsigned(1);
  const accountId = uuid(reader.fixedBytes(16));
  reader.expectUnsigned(2);
  const workspaceId = uuid(reader.fixedBytes(16));
  reader.expectUnsigned(3);
  const previousCheckpointHash = reader.fixedBytes(32);
  reader.expectUnsigned(4);
  const causalFrontier = readFrontier(reader);
  reader.expectUnsigned(5);
  const stateHash = reader.fixedBytes(32);
  reader.expectUnsigned(6);
  const keyEpoch = Number(reader.unsigned(0xffff_ffffn));
  reader.expectUnsigned(7);
  const creatorDeviceId = uuid(reader.fixedBytes(16));
  reader.expectUnsigned(8);
  const createdHlc = readHlc(reader);
  const signatureKeyOffset = reader.position;
  reader.expectUnsigned(9);
  const signature = reader.fixedBytes(64);
  if (reader.position !== canonicalBytes.length) throw invalidEnvelope();
  const signingPreimage = new Uint8Array(signatureKeyOffset);
  signingPreimage[0] = 0xa9;
  signingPreimage.set(canonicalBytes.subarray(1, signatureKeyOffset), 1);
  return {
    schemaVersion,
    accountId,
    workspaceId,
    previousCheckpointHash,
    causalFrontier,
    stateHash,
    keyEpoch,
    creatorDeviceId,
    createdHlc,
    signature,
    signingPreimage,
    canonicalBytes,
  };
}

function decodeOperation(canonicalBytes) {
  if (canonicalBytes.length === 0 || canonicalBytes.length > MAX_OPERATION_BYTES) {
    throw invalidEnvelope();
  }
  const reader = new CanonicalReader(canonicalBytes);
  reader.expectMap(20);
  reader.expectUnsigned(0);
  const schemaVersion = Number(reader.unsigned(0xffffn));
  if (schemaVersion !== 1) throw invalidEnvelope();
  reader.expectUnsigned(1);
  const operationId = uuid(reader.fixedBytes(16));
  reader.expectUnsigned(2);
  const accountId = uuid(reader.fixedBytes(16));
  reader.expectUnsigned(3);
  const workspaceId = uuid(reader.fixedBytes(16));
  reader.expectUnsigned(4);
  const projectId = reader.nullableUuid();
  reader.expectUnsigned(5);
  const recordId = uuid(reader.fixedBytes(16));
  reader.expectUnsigned(6);
  const recordKind = RECORD_KINDS[Number(reader.unsigned(6n))];
  reader.expectUnsigned(7);
  const mutationKind = MUTATION_KINDS[Number(reader.unsigned(1n))];
  reader.expectUnsigned(8);
  const deviceId = uuid(reader.fixedBytes(16));
  reader.expectUnsigned(9);
  const deviceSequence = reader.unsigned().toString();
  reader.expectUnsigned(10);
  const causalFrontier = readFrontier(reader);
  reader.expectUnsigned(11);
  const controlEpoch = Number(reader.unsigned(0xffff_ffffn));
  reader.expectUnsigned(12);
  const keyEpoch = Number(reader.unsigned(0xffff_ffffn));
  reader.expectUnsigned(13);
  const previousDeviceHash = reader.fixedBytes(32);
  reader.expectUnsigned(14);
  const nonce = reader.fixedBytes(24);
  reader.expectUnsigned(15);
  const ciphertext = reader.byteString(MAX_CIPHERTEXT_BYTES);
  reader.expectUnsigned(16);
  const ciphertextHash = reader.fixedBytes(32);
  reader.expectUnsigned(17);
  const blobRefs = readBlobs(reader);
  reader.expectUnsigned(18);
  const createdHlc = readHlc(reader);
  const signatureKeyOffset = reader.position;
  reader.expectUnsigned(19);
  const signature = reader.fixedBytes(64);
  if (reader.position !== canonicalBytes.length) throw invalidEnvelope();
  const signingPreimage = new Uint8Array(signatureKeyOffset);
  signingPreimage[0] = 0xb3;
  signingPreimage.set(canonicalBytes.subarray(1, signatureKeyOffset), 1);
  return {
    schemaVersion,
    operationId,
    accountId,
    workspaceId,
    projectId,
    recordId,
    recordKind,
    mutationKind,
    deviceId,
    deviceSequence,
    causalFrontier,
    controlEpoch,
    keyEpoch,
    previousDeviceHash,
    nonce,
    ciphertext,
    ciphertextHash,
    blobRefs,
    createdHlc,
    signature,
    signingPreimage,
    canonicalBytes,
  };
}

function equalBytes(left, right) {
  if (!(right instanceof Uint8Array) || left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left[index] ^ right[index];
  return difference === 0;
}

function validateContext(context, operation) {
  if (
    context === null ||
    typeof context !== "object" ||
    context.accountId !== operation.accountId ||
    context.workspaceId !== operation.workspaceId ||
    context.deviceId !== operation.deviceId ||
    context.controlEpoch !== operation.controlEpoch ||
    context.keyEpoch !== operation.keyEpoch ||
    typeof context.certificateId !== "string" ||
    !(context.signingPublicKey instanceof Uint8Array) ||
    context.signingPublicKey.length !== 32
  ) {
    throw invalidEnvelope();
  }
}

async function verifyEd25519(publicKey, signature, message) {
  let key;
  try {
    key = await crypto.subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, [
      "verify",
    ]);
  } catch {
    throw invalidEnvelope();
  }
  if (!(await crypto.subtle.verify({ name: "Ed25519" }, key, signature, message))) {
    throw invalidEnvelope();
  }
}

async function verifyCertificateChain(context) {
  if (
    context === null ||
    typeof context !== "object" ||
    !Array.isArray(context.certificateChain) ||
    context.certificateChain.length === 0 ||
    context.certificateChain.length > 64
  ) {
    throw invalidEnvelope();
  }
  const recoverySigningPublicKey = hexBytes(context.recoverySigningPublicKey, 32);
  const certificates = context.certificateChain.map((certificate) => {
    if (
      !ownKeysExactly(certificate, [
        "certificateId",
        "accountId",
        "workspaceId",
        "controlEpoch",
        "requestNonce",
        "deviceId",
        "issuerKind",
        "issuerDeviceId",
        "issuerRecoveryPublicKey",
        "issuerSigningPublicKey",
        "deviceSigningPublicKey",
        "deviceWrappingPublicKey",
        "signature",
      ]) ||
      (certificate.issuerKind !== "device" && certificate.issuerKind !== "recovery_root")
    ) {
      throw invalidEnvelope();
    }
    uuidStringBytes(certificate.certificateId);
    const accountId = uuidStringBytes(certificate.accountId);
    const workspaceId = uuidStringBytes(certificate.workspaceId);
    const deviceId = uuidStringBytes(certificate.deviceId);
    const requestNonce = hexBytes(certificate.requestNonce, 32);
    const issuerSigningPublicKey = hexBytes(certificate.issuerSigningPublicKey, 32);
    const deviceSigningPublicKey = hexBytes(certificate.deviceSigningPublicKey, 32);
    const deviceWrappingPublicKey = hexBytes(certificate.deviceWrappingPublicKey, 32);
    const signature = hexBytes(certificate.signature, 64);
    const issuerDeviceId =
      certificate.issuerDeviceId === null
        ? null
        : uuidStringBytes(certificate.issuerDeviceId);
    const issuerRecoveryPublicKey =
      certificate.issuerRecoveryPublicKey === null
        ? null
        : hexBytes(certificate.issuerRecoveryPublicKey, 32);
    return {
      ...certificate,
      accountIdBytes: accountId,
      workspaceIdBytes: workspaceId,
      deviceIdBytes: deviceId,
      requestNonceBytes: requestNonce,
      issuerSigningPublicKeyBytes: issuerSigningPublicKey,
      deviceSigningPublicKeyBytes: deviceSigningPublicKey,
      deviceWrappingPublicKeyBytes: deviceWrappingPublicKey,
      signatureBytes: signature,
      issuerDeviceIdBytes: issuerDeviceId,
      issuerRecoveryPublicKeyBytes: issuerRecoveryPublicKey,
    };
  });

  const leaf = certificates[0];
  if (
    leaf.certificateId !== context.certificateId ||
    leaf.accountId !== context.accountId ||
    leaf.workspaceId !== context.workspaceId ||
    leaf.deviceId !== context.deviceId ||
    leaf.controlEpoch !== context.controlEpoch ||
    !equalBytes(leaf.deviceSigningPublicKeyBytes, context.signingPublicKey)
  ) {
    throw invalidEnvelope();
  }

  const seenDevices = new Set();
  for (let index = 0; index < certificates.length; index += 1) {
    const certificate = certificates[index];
    if (
      certificate.accountId !== context.accountId ||
      certificate.workspaceId !== context.workspaceId ||
      certificate.controlEpoch !== context.controlEpoch ||
      seenDevices.has(certificate.deviceId)
    ) {
      throw invalidEnvelope();
    }
    seenDevices.add(certificate.deviceId);

    let issuerPrefix;
    let verificationKey;
    if (certificate.issuerKind === "recovery_root") {
      if (
        index !== certificates.length - 1 ||
        certificate.issuerDeviceIdBytes !== null ||
        certificate.issuerRecoveryPublicKeyBytes === null ||
        !equalBytes(certificate.issuerRecoveryPublicKeyBytes, recoverySigningPublicKey) ||
        !equalBytes(certificate.issuerSigningPublicKeyBytes, recoverySigningPublicKey)
      ) {
        throw invalidEnvelope();
      }
      issuerPrefix = concatenate([new Uint8Array([0]), recoverySigningPublicKey]);
      verificationKey = recoverySigningPublicKey;
    } else {
      const issuer = certificates[index + 1];
      if (
        issuer === undefined ||
        certificate.issuerDeviceIdBytes === null ||
        certificate.issuerRecoveryPublicKeyBytes !== null ||
        certificate.issuerDeviceId !== issuer.deviceId ||
        !equalBytes(certificate.issuerSigningPublicKeyBytes, issuer.deviceSigningPublicKeyBytes)
      ) {
        throw invalidEnvelope();
      }
      issuerPrefix = concatenate([
        new Uint8Array([1]),
        certificate.issuerDeviceIdBytes,
        certificate.issuerSigningPublicKeyBytes,
      ]);
      verificationKey = certificate.issuerSigningPublicKeyBytes;
    }

    const preimage = concatenate([
      CERTIFICATE_DOMAIN,
      issuerPrefix,
      certificate.accountIdBytes,
      certificate.workspaceIdBytes,
      u32be(certificate.controlEpoch),
      certificate.requestNonceBytes,
      certificate.deviceIdBytes,
      certificate.deviceSigningPublicKeyBytes,
      certificate.deviceWrappingPublicKeyBytes,
    ]);
    await verifyEd25519(verificationKey, certificate.signatureBytes, preimage);
  }
}

async function verifyOperation(operation, context) {
  validateContext(context, operation);
  const actualCiphertextHash = new Uint8Array(await crypto.subtle.digest("SHA-256", operation.ciphertext));
  if (!equalBytes(actualCiphertextHash, operation.ciphertextHash)) throw invalidEnvelope();
  await verifyEd25519(context.signingPublicKey, operation.signature, operation.signingPreimage);
  return {
    ...operation,
    certificateId: context.certificateId,
    canonicalSha256: new Uint8Array(await crypto.subtle.digest("SHA-256", operation.canonicalBytes)),
  };
}

async function verifyCheckpoint(checkpoint, context) {
  if (
    context === null ||
    typeof context !== "object" ||
    context.accountId !== checkpoint.accountId ||
    context.workspaceId !== checkpoint.workspaceId ||
    context.deviceId !== checkpoint.creatorDeviceId ||
    context.keyEpoch !== checkpoint.keyEpoch ||
    !(context.signingPublicKey instanceof Uint8Array) ||
    context.signingPublicKey.length !== 32
  ) {
    throw invalidEnvelope();
  }
  await verifyEd25519(context.signingPublicKey, checkpoint.signature, checkpoint.signingPreimage);
  return {
    ...checkpoint,
    canonicalSha256: new Uint8Array(
      await crypto.subtle.digest("SHA-256", checkpoint.canonicalBytes),
    ),
  };
}

function digestHex(value) {
  if (!(value instanceof Uint8Array) || value.length !== 32) throw invalidEnvelope();
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function blobReservation(body) {
  uuidStringBytes(body.workspaceId);
  uuidStringBytes(body.storageId);
  const ciphertextSha256 = strictBase64Url(body.ciphertextSha256);
  if (ciphertextSha256.length !== 32) throw new SyncEdgeError(400, "invalid_request");
  if (body.partSizes.length === 0 || body.partSizes.length > 16) {
    throw new SyncEdgeError(400, "invalid_request");
  }
  let total = 0;
  for (const size of body.partSizes) {
    if (!Number.isInteger(size) || size <= 0 || size > 33_554_432) {
      throw new SyncEdgeError(400, "invalid_request");
    }
    total += size;
  }
  if (total > MAX_BLOB_BYTES) throw new SyncEdgeError(400, "invalid_request");
  const expires = new Date(body.expiresAt);
  if (!Number.isFinite(expires.getTime()) || expires.toISOString() !== body.expiresAt) {
    throw new SyncEdgeError(400, "invalid_request");
  }
  return {
    workspaceId: body.workspaceId,
    storageId: body.storageId,
    ciphertextSha256,
    partSizes: [...body.partSizes],
    expiresAt: body.expiresAt,
  };
}

function exactBlobTransition(value, storageId, expectedState) {
  if (
    value === null ||
    typeof value !== "object" ||
    !ownKeysExactly(value, ["storageId", "state"]) ||
    value.storageId !== storageId ||
    value.state !== expectedState
  ) {
    throw new SyncEdgeError(503, "transient");
  }
  return value;
}

function exactOperationReceipt(value, operations) {
  if (
    value === null ||
    typeof value !== "object" ||
    !ownKeysExactly(value, ["accepted", "duplicates"]) ||
    !Array.isArray(value.accepted) ||
    !Array.isArray(value.duplicates)
  ) {
    throw new SyncEdgeError(503, "transient");
  }
  const expected = new Set(operations.map((operation) => operation.operationId));
  const returned = [...value.accepted, ...value.duplicates];
  if (expected.size !== operations.length || returned.length !== operations.length) {
    throw new SyncEdgeError(503, "transient");
  }
  for (const operationId of returned) {
    if (typeof operationId !== "string" || !expected.delete(operationId)) {
      throw new SyncEdgeError(503, "transient");
    }
  }
  if (expected.size !== 0) throw new SyncEdgeError(503, "transient");
  return { accepted: [...value.accepted], duplicates: [...value.duplicates] };
}

export function createSyncEdgeHandler(dependencies) {
  const required = [
    "authenticate",
    "loadIdentityContext",
    "appendOperations",
    "appendCheckpoint",
    "loadSessionContext",
    "reserveBlob",
    "finalizeBlob",
    "releaseBlob",
    "broadcastPullNow",
  ];
  if (
    dependencies === null ||
    typeof dependencies !== "object" ||
    required.some((name) => typeof dependencies[name] !== "function")
  ) {
    throw new TypeError("invalid sync Edge dependencies");
  }

  return async function handleSyncRequest(request) {
    try {
      const body = await readRequest(request);
      const token = strictAuthorization(request);
      let identity;
      try {
        identity = await dependencies.authenticate(token);
      } catch (error) {
        if (error?.code === "revoked") throw new SyncEdgeError(403, "revoked");
        throw new SyncEdgeError(401, "auth_required");
      }
      if (
        identity === null ||
        typeof identity !== "object" ||
        typeof identity.userId !== "string" ||
        typeof identity.sessionId !== "string"
      ) {
        throw new SyncEdgeError(401, "auth_required");
      }
      if (body.action === "reserve_blob") {
        const reservation = blobReservation(body);
        const context = await dependencies.loadSessionContext(identity, {
          workspaceId: reservation.workspaceId,
        });
        await verifyCertificateChain(context);
        const ticket = await dependencies.reserveBlob(context, reservation);
        const expectedPaths = reservation.partSizes.map(
          (_, index) =>
            `${context.accountId}/${reservation.storageId}/${String(index).padStart(8, "0")}.bin`,
        );
        if (
          ticket === null ||
          typeof ticket !== "object" ||
          !ownKeysExactly(ticket, ["storageId", "paths", "expiresAt"]) ||
          ticket.storageId !== reservation.storageId ||
          ticket.expiresAt !== reservation.expiresAt ||
          !Array.isArray(ticket.paths) ||
          ticket.paths.length !== expectedPaths.length ||
          ticket.paths.some((path, index) => path !== expectedPaths[index])
        ) {
          throw new SyncEdgeError(503, "transient");
        }
        return response(200, { v: 1, ...ticket });
      }
      if (body.action === "finalize_blob") {
        uuidStringBytes(body.storageId);
        const result = exactBlobTransition(
          await dependencies.finalizeBlob(identity, body.storageId),
          body.storageId,
          "finalized",
        );
        return response(200, { v: 1, ...result });
      }
      if (body.action === "release_blob") {
        uuidStringBytes(body.storageId);
        const result = exactBlobTransition(
          await dependencies.releaseBlob(identity, body.storageId),
          body.storageId,
          "cancelled",
        );
        return response(200, { v: 1, ...result });
      }
      if (body.action === "push_checkpoint") {
        const checkpoint = decodeCheckpoint(strictBase64Url(body.checkpoint));
        const context = await dependencies.loadIdentityContext(identity, {
          accountId: checkpoint.accountId,
          workspaceId: checkpoint.workspaceId,
          deviceId: checkpoint.creatorDeviceId,
        });
        await verifyCertificateChain(context);
        const verified = await verifyCheckpoint(checkpoint, context);
        const receipt = await dependencies.appendCheckpoint(context, verified);
        if (
          receipt === null ||
          typeof receipt !== "object" ||
          typeof receipt.duplicate !== "boolean" ||
          !(receipt.canonicalHash instanceof Uint8Array) ||
          !equalBytes(receipt.canonicalHash, verified.canonicalSha256)
        ) {
          throw new SyncEdgeError(503, "transient");
        }
        try {
          await dependencies.broadcastPullNow(context.accountId);
        } catch {
          // Realtime is a pull hint only; the committed receipt remains authoritative.
        }
        return response(200, {
          v: 1,
          canonicalHash: digestHex(receipt.canonicalHash),
          duplicate: receipt.duplicate,
        });
      }

      const decoded = body.operations.map((encoded) => decodeOperation(strictBase64Url(encoded)));
      const first = decoded[0];
      if (new Set(decoded.map((operation) => operation.operationId)).size !== decoded.length) {
        throw invalidEnvelope();
      }
      if (
        decoded.some(
          (operation) =>
            operation.accountId !== first.accountId ||
            operation.workspaceId !== first.workspaceId ||
            operation.deviceId !== first.deviceId,
        )
      ) {
        throw invalidEnvelope();
      }
      const context = await dependencies.loadIdentityContext(identity, {
        accountId: first.accountId,
        workspaceId: first.workspaceId,
        deviceId: first.deviceId,
      });
      await verifyCertificateChain(context);
      const verified = [];
      for (const operation of decoded) verified.push(await verifyOperation(operation, context));
      const receipt = exactOperationReceipt(
        await dependencies.appendOperations(context, verified),
        verified,
      );
      try {
        await dependencies.broadcastPullNow(context.accountId);
      } catch {
        // Realtime is a pull hint only; the committed receipt remains authoritative.
      }
      return response(200, {
        v: 1,
        accepted: receipt.accepted,
        duplicates: receipt.duplicates,
      });
    } catch (error) {
      return safeError(error);
    }
  };
}
