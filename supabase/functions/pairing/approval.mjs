import { CanonicalReader } from '../sync/core.mjs';
import { readUuid7 } from '../enrollment/record.mjs';
import { verifyEd25519Strict, validateWrappingKey } from '../enrollment/crypto.mjs';
import { verifyPairingRequest } from './crypto.mjs';

const invalid = () => new Error('invalid_pairing_approval');
const hex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
const uuidBytes = value => Uint8Array.from(value.replaceAll('-', '').match(/../g), byte => Number.parseInt(byte, 16));
const equal = (a, b) => hex(a) === hex(b);
const digest = async bytes => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));

function certificate(reader, kind) {
  const start=reader.position;
  reader.expectMap(9);
  reader.expectUnsigned(0);
  if (kind===undefined) kind=reader.bytes[reader.position]===0xa2?0:1;
  reader.expectMap(kind === 0 ? 2 : 3);
  reader.expectUnsigned(0); reader.expectUnsigned(kind);
  reader.expectUnsigned(1);
  const issuerDeviceId = kind === 1 ? readUuid7(reader) : null;
  if (kind === 1) reader.expectUnsigned(2);
  const issuerKey = reader.fixedBytes(32);
  reader.expectUnsigned(1); const accountId = readUuid7(reader);
  reader.expectUnsigned(2); const workspaceId = readUuid7(reader);
  reader.expectUnsigned(3); const controlEpoch = Number(reader.unsigned(0xffffffffn));
  reader.expectUnsigned(4); const requestNonce = reader.fixedBytes(32);
  reader.expectUnsigned(5); const deviceId = readUuid7(reader);
  reader.expectUnsigned(6); const signingKey = reader.fixedBytes(32);
  reader.expectUnsigned(7); const wrappingKey = reader.fixedBytes(32);
  reader.expectUnsigned(8); const signature = reader.fixedBytes(64);
  if (controlEpoch === 0 || equal(signingKey, wrappingKey)) throw invalid();
  const epoch = new Uint8Array(4); new DataView(epoch.buffer).setUint32(0, controlEpoch);
  const preimage = Uint8Array.from([
    ...new TextEncoder().encode('context-relay/device-certificate/v1\0'), kind,
    ...(issuerDeviceId === null ? [] : uuidBytes(issuerDeviceId)), ...issuerKey,
    ...uuidBytes(accountId), ...uuidBytes(workspaceId), ...epoch, ...requestNonce,
    ...uuidBytes(deviceId), ...signingKey, ...wrappingKey,
  ]);
  return { canonical:reader.bytes.slice(start,reader.position),issuerDeviceId, issuerKey, accountId, workspaceId, controlEpoch,
    requestNonce, deviceId, signingKey, wrappingKey, signature, preimage };
}

// trusted must come from server-selected active authority. This checks public
// cryptography only; admission also requires live Auth/device proof and atomic
// state checks. Ciphertext integrity is established by the joining device.
export async function verifyPairingApproval(input, requestInput, trusted, membershipSignature) {
  if(membershipSignature!==undefined) return verifyV2(input,requestInput,trusted,membershipSignature);
  try {
    if (!(input instanceof Uint8Array) || input.length === 0 || input.length > 32768) throw invalid();
    const canonicalApprovedPayload = Uint8Array.from(input);
    trusted = { ...trusted };
    const reader = new CanonicalReader(canonicalApprovedPayload);
    reader.expectMap(6);
    reader.expectUnsigned(0); reader.expectUnsigned(1);
    reader.expectUnsigned(1); reader.expectMap(7);
    reader.expectUnsigned(0); reader.expectUnsigned(1);
    reader.expectUnsigned(1); const pairingId = readUuid7(reader);
    reader.expectUnsigned(2); const requestDigest = reader.fixedBytes(32);
    reader.expectUnsigned(3); const certificateId = readUuid7(reader);
    reader.expectUnsigned(4); const child = certificate(reader, 1);
    reader.expectUnsigned(5); const keyEpoch = Number(reader.unsigned(0xffffffffn));
    reader.expectUnsigned(6); reader.expectMap(3);
    reader.expectUnsigned(0); const ephemeralKey = reader.fixedBytes(32);
    reader.expectUnsigned(1); const nonce = reader.fixedBytes(24);
    reader.expectUnsigned(2); const ciphertext = reader.byteString(16384);
    reader.expectUnsigned(2); const issuerCertificateId = readUuid7(reader);
    reader.expectUnsigned(3); const issuer = certificate(reader, 0);
    reader.expectUnsigned(4); const issuerDeviceName = reader.text(256);
    reader.expectUnsigned(5); const issuerPlatform = Number(reader.unsigned(1n));
    if (reader.position !== canonicalApprovedPayload.length || keyEpoch === 0 || ciphertext.length < 16
      || issuerCertificateId === certificateId || issuerCertificateId !== trusted.issuerCertificateId
      || issuer.deviceId !== trusted.issuerDeviceId || hex(issuer.signingKey) !== trusted.issuerSigningKey
      || hex(issuer.issuerKey) !== trusted.recoverySigningKey || issuer.accountId !== trusted.accountId
      || issuer.workspaceId !== trusted.workspaceId || issuer.controlEpoch !== trusted.controlEpoch
      || keyEpoch !== trusted.keyEpoch || child.accountId !== issuer.accountId
      || child.workspaceId !== issuer.workspaceId || child.controlEpoch !== issuer.controlEpoch
      || child.issuerDeviceId !== issuer.deviceId || !equal(child.issuerKey, issuer.signingKey)) throw invalid();
    const request = await verifyPairingRequest(requestInput);
    if (pairingId !== request.pairingId || !equal(requestDigest, request.requestDigest)
      || child.deviceId !== request.deviceId || issuer.deviceId === request.deviceId
      || !equal(child.requestNonce, request.requestNonce) || !equal(child.signingKey, request.signingPublicKey)
      || !equal(child.wrappingKey, request.wrappingPublicKey)) throw invalid();
    await verifyEd25519Strict(issuer.issuerKey, issuer.signature, issuer.preimage);
    await verifyEd25519Strict(issuer.signingKey, child.signature, child.preimage);
    await validateWrappingKey(issuer.wrappingKey);
    await validateWrappingKey(ephemeralKey);
    return { canonicalApprovedPayload, approvedPayloadDigest: await digest(canonicalApprovedPayload),
      pairingId, requestDigest, certificateId, issuerCertificateId, child, issuer,
      keyEpoch, ephemeralKey, nonce, ciphertext, issuerDeviceName, issuerPlatform };
  } catch { throw invalid(); }
}

async function verifyV2(input,requestInput,trusted,membershipSignature) {
  try {
    if (!(input instanceof Uint8Array) || input.length===0 || input.length>32768
      || !(requestInput instanceof Uint8Array) || requestInput.length===0 || requestInput.length>8192
      || !(membershipSignature instanceof Uint8Array) || membershipSignature.length!==64) throw invalid();
    const canonicalApprovedPayload=Uint8Array.from(input);
    requestInput=Uint8Array.from(requestInput);membershipSignature=Uint8Array.from(membershipSignature);trusted={...trusted};
    const r=new CanonicalReader(canonicalApprovedPayload);
    r.expectMap(8);r.expectUnsigned(0);r.expectUnsigned(2);
    r.expectUnsigned(1);const grantStart=r.position;r.expectMap(7);
    r.expectUnsigned(0);r.expectUnsigned(2);
    r.expectUnsigned(1);const pairingId=readUuid7(r);
    r.expectUnsigned(2);const requestDigest=r.fixedBytes(32);
    r.expectUnsigned(3);const certificateId=readUuid7(r);
    r.expectUnsigned(4);const child=certificate(r,1);
    r.expectUnsigned(5);const keyEpoch=Number(r.unsigned(0xffffffffn));
    r.expectUnsigned(6);r.expectMap(3);
    r.expectUnsigned(0);const ephemeralKey=r.fixedBytes(32);
    r.expectUnsigned(1);const nonce=r.fixedBytes(24);
    r.expectUnsigned(2);const ciphertext=r.byteString(16384);
    if(r.position-grantStart>16384) throw invalid();
    r.expectUnsigned(2);const issuerCertificateId=readUuid7(r);
    r.expectUnsigned(3);const issuer=certificate(r);
    r.expectUnsigned(4);const issuerDeviceName=r.text(256);
    r.expectUnsigned(5);const issuerPlatform=Number(r.unsigned(1n));
    r.expectUnsigned(6);const previousStateSha256=r.fixedBytes(32);
    r.expectUnsigned(7);const enrollmentSha256=r.fixedBytes(32);
    if(r.position!==canonicalApprovedPayload.length || !issuerDeviceName.trim() || ciphertext.length<16
      || keyEpoch===0 || keyEpoch!==trusted.keyEpoch || child.controlEpoch!==trusted.controlEpoch
      || issuer.controlEpoch>child.controlEpoch || hex(issuer.canonical)!==trusted.issuerCertificate
      || issuerCertificateId!==trusted.issuerCertificateId || certificateId===issuerCertificateId
      || issuer.accountId!==trusted.accountId || issuer.workspaceId!==trusted.workspaceId
      || issuer.deviceId!==trusted.issuerDeviceId || hex(issuer.signingKey)!==trusted.issuerSigningKey
      || hex(previousStateSha256)!==trusted.stateSha256 || hex(enrollmentSha256)!==trusted.enrollmentSha256
      || previousStateSha256.every(b=>b===0) || enrollmentSha256.every(b=>b===0)
      || child.accountId!==issuer.accountId || child.workspaceId!==issuer.workspaceId
      || child.issuerDeviceId!==issuer.deviceId || !equal(child.issuerKey,issuer.signingKey)) throw invalid();
    const request=await verifyPairingRequest(requestInput);
    if(pairingId!==request.pairingId || !equal(requestDigest,request.requestDigest)
      || child.deviceId!==request.deviceId || issuer.deviceId===request.deviceId
      || !equal(child.requestNonce,request.requestNonce) || !equal(child.signingKey,request.signingPublicKey)
      || !equal(child.wrappingKey,request.wrappingPublicKey)) throw invalid();
    await verifyEd25519Strict(issuer.issuerKey,issuer.signature,issuer.preimage);
    await verifyEd25519Strict(issuer.signingKey,child.signature,child.preimage);
    await validateWrappingKey(issuer.wrappingKey);await validateWrappingKey(ephemeralKey);
    const be32=n=>{const b=new Uint8Array(4);new DataView(b.buffer).setUint32(0,n);return b;};
    const approvedPayloadDigest=await digest(canonicalApprovedPayload);
    const statement=Uint8Array.from([...new TextEncoder().encode('context-relay/device-membership-add/v1\0'),0,1,
      ...uuidBytes(pairingId),...uuidBytes(issuer.accountId),...uuidBytes(issuer.workspaceId),...previousStateSha256,
      ...be32(child.controlEpoch),...be32(keyEpoch),...uuidBytes(issuer.deviceId),...uuidBytes(certificateId),
      ...await digest(child.canonical),...approvedPayloadDigest]);
    await verifyEd25519Strict(issuer.signingKey,membershipSignature,statement);
    const successorSha256=await digest(Uint8Array.from([...new TextEncoder().encode('context-relay/membership-control-state/v1\0'),...statement,...membershipSignature]));
    return {version:2,canonicalApprovedPayload,approvedPayloadDigest,pairingId,requestDigest,certificateId,
      issuerCertificateId,child,issuer,keyEpoch,ephemeralKey,nonce,ciphertext,issuerDeviceName,issuerPlatform,
      previousStateSha256,enrollmentSha256,membershipSignature,statement,successorSha256};
  } catch {throw invalid();}
}
