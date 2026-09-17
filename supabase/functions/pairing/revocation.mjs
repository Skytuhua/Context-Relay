import { verifyEd25519Strict, validateWrappingKey } from '../enrollment/crypto.mjs';

const EVENT_DOMAIN = new TextEncoder().encode('context-relay/public-membership-event/v1\0');
const STATEMENT_DOMAIN = new TextEncoder().encode('context-relay/device-revocation/v1\0');
const TRANSITION_DOMAIN = new TextEncoder().encode('context-relay/device-revocation-transition/v1\0');
const SUCCESSOR_DOMAIN = new TextEncoder().encode('context-relay/revocation-control-state/v1\0');
const invalid = () => new Error('invalid_revocation');
const hex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
const unhex = value => Uint8Array.from(value.match(/../g), byte=>Number.parseInt(byte,16));
const equal = (a,b) => a.length===b.length && a.every((byte,index)=>byte===b[index]);
const digest = async bytes => new Uint8Array(await crypto.subtle.digest('SHA-256',bytes));
const uuid = bytes => {
  const value=hex(bytes);const text=`${value.slice(0,8)}-${value.slice(8,12)}-${value.slice(12,16)}-${value.slice(16,20)}-${value.slice(20)}`;
  if(!/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(text)) throw invalid();
  return text;
};
class Reader {
  constructor(bytes){this.bytes=bytes;this.position=0;}
  take(n){if(!Number.isSafeInteger(n)||n<0||this.position+n>this.bytes.length) throw invalid();const value=this.bytes.slice(this.position,this.position+n);this.position+=n;return value;}
  u32(){const value=new DataView(this.take(4).buffer).getUint32(0);return value;}
  u64(){const value=new DataView(this.take(8).buffer).getBigUint64(0);if(value>0x7fffffffffffffffn) throw invalid();return value;}
  sized(max){const n=this.u32();if(n>max) throw invalid();return this.take(n);}
}
function endpoint(value) {
  if(!value||typeof value!=='object'||Object.keys(value).sort().join(',')!=='controlEpoch,keyEpoch,stateSha256'
    ||typeof value.stateSha256!=='string'||!/^[0-9a-f]{64}$/.test(value.stateSha256)||/^0+$/.test(value.stateSha256)
    ||!Number.isInteger(value.controlEpoch)||value.controlEpoch<1||value.controlEpoch>0xffffffff
    ||!Number.isInteger(value.keyEpoch)||value.keyEpoch<1||value.keyEpoch>0xffffffff) throw invalid();
  return {...value};
}

// The accepted-member certificate bytes come from the locked server history.
// Exact roster comparison avoids a second certificate-chain implementation here;
// the signed history remains the authority for those immutable certificates.
export async function verifyRevocationObject(input,trusted) {
  try {
    if(!(input instanceof Uint8Array)||input.length<319||input.length>8388927) throw invalid();
    const object=Uint8Array.from(input),r=new Reader(object);
    if(!equal(r.take(EVENT_DOMAIN.length),EVENT_DOMAIN)||r.take(1)[0]!==0) throw invalid();
    const statement=r.sized(197),signature=r.sized(64),request=r.sized(0),transition=r.sized(8388608);
    if(request.length!==0||r.position!==object.length||object.length!==transition.length+319) throw invalid();
    const s=new Reader(statement);
    if(!equal(s.take(STATEMENT_DOMAIN.length),STATEMENT_DOMAIN)||new DataView(s.take(2).buffer).getUint16(0)!==1) throw invalid();
    const operationId=uuid(s.take(16)),accountId=uuid(s.take(16)),workspaceId=uuid(s.take(16));
    const issuerDeviceId=uuid(s.take(16)),targetDeviceId=uuid(s.take(16));
    const controlEpoch=s.u32(),keyEpoch=s.u32(),cutoffSequence=s.u64();
    const cutoffSha256=s.take(32),transitionSha256=s.take(32);
    if(s.position!==statement.length||controlEpoch<1||controlEpoch>=0xffffffff||keyEpoch<1||keyEpoch>=0xffffffff
      ||(cutoffSequence===0n)!==cutoffSha256.every(byte=>byte===0)||!equal(await digest(transition),transitionSha256)) throw invalid();
    const accepted=endpoint(trusted?.endpoint);
    if(accountId!==trusted.accountId||workspaceId!==trusted.workspaceId||issuerDeviceId!==trusted.issuerDeviceId
      ||(trusted.targetDeviceId!==null&&trusted.targetDeviceId!==undefined&&targetDeviceId!==trusted.targetDeviceId)
      ||controlEpoch!==accepted.controlEpoch||keyEpoch!==accepted.keyEpoch) throw invalid();
    const t=new Reader(transition);
    if(!equal(t.take(TRANSITION_DOMAIN.length),TRANSITION_DOMAIN)) throw invalid();
    const previousStateSha256=t.take(32),nextControl=t.u32(),nextKey=t.u32(),keyMaterialSha256=t.take(32),count=t.u32();
    if(!equal(previousStateSha256,unhex(accepted.stateSha256))
      ||nextControl!==controlEpoch+1||nextKey!==keyEpoch+1||keyMaterialSha256.every(byte=>byte===0)
      ||count>4096||!Array.isArray(trusted.activeMembers)||trusted.activeMembers.length!==count+1) throw invalid();
    const survivors=trusted.activeMembers.filter(member=>member.deviceId!==targetDeviceId);
    if(survivors.length!==count||!trusted.activeMembers.some(member=>member.deviceId===targetDeviceId)) throw invalid();
    for(let index=0;index<count;index++) {
      const certificate=t.sized(512),expected=survivors[index];
      if(!expected||hex(certificate)!==expected.canonicalCertificate) throw invalid();
      await validateWrappingKey(t.take(32));t.take(24);const ciphertext=t.sized(1024);
      if(ciphertext.length<16) throw invalid();
    }
    const recoveryRootId=uuid(t.take(16)),recoveryWrappingKey=t.take(32);
    await validateWrappingKey(recoveryWrappingKey);await validateWrappingKey(t.take(32));t.take(24);
    const recoveryCiphertext=t.sized(1024);
    if(recoveryCiphertext.length<16||t.position!==transition.length||recoveryRootId!==trusted.recoveryRootId
      ||hex(recoveryWrappingKey)!==trusted.recoveryWrappingKey) throw invalid();
    await verifyEd25519Strict(unhex(trusted.issuerSigningKey),signature,statement);
    const successorSha256=await digest(Uint8Array.from([...SUCCESSOR_DOMAIN,...statement,...signature]));
    return {operationId,accountId,workspaceId,issuerDeviceId,targetDeviceId,controlEpoch,keyEpoch,
      cutoffSequence:cutoffSequence.toString(),cutoffSha256,transitionSha256,previousStateSha256,
      successorSha256,signature,objectSha256:await digest(object),canonicalObject:object};
  } catch {throw invalid();}
}
