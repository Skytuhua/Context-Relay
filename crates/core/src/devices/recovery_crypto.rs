use std::{fmt, str::FromStr};

use context_relay_protocol::{
    AccountId, DeviceCertificateId, DeviceId, Ed25519PublicKeyBytes, Ed25519SignatureBytes,
    NativePlatform, RecoveryEnrollmentId, RecoveryRootId, Sha256Digest, WorkspaceId,
    X25519PublicKeyBytes,
};
use minicbor::{Decoder, Encoder};
use rand_core::{CryptoRng, OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::{
    crypto::{
        CertificateIssuerV1, CryptoError, DeviceCertificateV1, DeviceKeys, RecoveryKeys,
        WrappedKeyEnvelope, validate_ed25519_public_key, validate_x25519_public_key,
        verify_enrollment_record_signature, wrap_secret_with_rng,
    },
    devices::crypto::{
        PairingKeyBundle, certificate_digest, decode_certificate_v1, decode_native_platform,
        decode_pairing_key_bundle_v1, decode_wrapped_envelope_with_limit, encode_certificate_v1,
        encode_native_platform, encode_pairing_key_bundle_v1, encode_wrapped_envelope,
    },
};

pub const RECOVERY_ENROLLMENT_SCHEMA_VERSION: u16 = 1;
pub const MAX_RECOVERY_ENROLLMENT_RECORD_BYTES: usize = 32 * 1024;
pub const MAX_RECOVERY_DEVICE_NAME_BYTES: usize = 256;

const RECOVERY_ENROLLMENT_SIGNING_DOMAIN: &[u8] = b"context-relay/recovery-enrollment-record/v1\0";
const RECOVERY_METADATA_AAD_DOMAIN: &[u8] = b"context-relay/recovery-metadata/v1\0";
const DEVICE_WORKSPACE_MATERIAL_AAD_DOMAIN: &[u8] = b"context-relay/device-workspace-material/v1\0";
const MIN_WRAPPED_CIPHERTEXT_BYTES: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RecoveryEnrollmentCryptoError {
    #[error("invalid recovery enrollment record")]
    InvalidRecord,
    #[error("recovery enrollment cryptography failed")]
    Crypto(#[source] CryptoError),
}

impl From<CryptoError> for RecoveryEnrollmentCryptoError {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RecoveryEnrollmentRecordV1 {
    pub schema_version: u16,
    pub enrollment_id: RecoveryEnrollmentId,
    pub recovery_root_id: RecoveryRootId,
    pub account_id: AccountId,
    pub workspace_id: WorkspaceId,
    pub recovery_signing_public_key: Ed25519PublicKeyBytes,
    pub recovery_wrapping_public_key: X25519PublicKeyBytes,
    pub genesis_certificate_id: DeviceCertificateId,
    pub genesis_certificate: DeviceCertificateV1,
    pub device_name: String,
    pub device_platform: NativePlatform,
    pub key_epoch: u32,
    pub encrypted_recovery_metadata: WrappedKeyEnvelope,
    pub recovery_root_signature: Ed25519SignatureBytes,
}

impl fmt::Debug for RecoveryEnrollmentRecordV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryEnrollmentRecordV1")
            .field("schema_version", &self.schema_version)
            .field("enrollment_id", &self.enrollment_id)
            .field("recovery_root_id", &self.recovery_root_id)
            .field("account_id", &self.account_id)
            .field("workspace_id", &self.workspace_id)
            .field("genesis_certificate_id", &self.genesis_certificate_id)
            .field("device_name", &self.device_name)
            .field("device_platform", &self.device_platform)
            .field("key_epoch", &self.key_epoch)
            .field("keys_certificate_envelope_and_signature", &"[REDACTED]")
            .finish()
    }
}

pub struct RecoveryEnrollmentArtifacts {
    pub record: RecoveryEnrollmentRecordV1,
    pub canonical_record: Vec<u8>,
    pub canonical_record_sha256: Sha256Digest,
    pub device_material_envelope: WrappedKeyEnvelope,
    pub device_material_envelope_sha256: Sha256Digest,
}

impl fmt::Debug for RecoveryEnrollmentArtifacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryEnrollmentArtifacts")
            .field("enrollment_id", &self.record.enrollment_id)
            .field("recovery_root_id", &self.record.recovery_root_id)
            .field("canonical_record_sha256", &self.canonical_record_sha256)
            .field(
                "canonical_record_and_device_material_envelope",
                &"[REDACTED]",
            )
            .finish()
    }
}

pub struct RecoveryEnrollmentBuildRequest<'a> {
    pub enrollment_id: RecoveryEnrollmentId,
    pub recovery_root_id: RecoveryRootId,
    pub certificate_id: DeviceCertificateId,
    pub certificate: DeviceCertificateV1,
    pub device_name: String,
    pub device_platform: NativePlatform,
    pub recovery_keys: &'a RecoveryKeys,
    pub device_keys: &'a DeviceKeys,
    pub material: &'a PairingKeyBundle,
}

impl fmt::Debug for RecoveryEnrollmentBuildRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryEnrollmentBuildRequest")
            .field("enrollment_id", &self.enrollment_id)
            .field("recovery_root_id", &self.recovery_root_id)
            .field("certificate_id", &self.certificate_id)
            .field("device_name", &self.device_name)
            .field("device_platform", &self.device_platform)
            .field("certificate_keys_and_material", &"[REDACTED]")
            .finish()
    }
}

/// Builds the signed recovery record and the first device's sealed workspace material.
///
/// Caller-controlled wrapping randomness is unavailable in normal builds.
#[cfg_attr(
    not(feature = "test-support"),
    doc = r#"
```compile_fail
use context_relay_core::devices::recovery_crypto::build_recovery_enrollment_artifacts_with_rng;
```
"#
)]
pub fn build_recovery_enrollment_artifacts(
    request: RecoveryEnrollmentBuildRequest<'_>,
) -> Result<RecoveryEnrollmentArtifacts, RecoveryEnrollmentCryptoError> {
    build_recovery_enrollment_artifacts_inner(request, &mut OsRng)
}

#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn build_recovery_enrollment_artifacts_with_rng<R: CryptoRng + RngCore>(
    request: RecoveryEnrollmentBuildRequest<'_>,
    rng: &mut R,
) -> Result<RecoveryEnrollmentArtifacts, RecoveryEnrollmentCryptoError> {
    build_recovery_enrollment_artifacts_inner(request, rng)
}

pub(crate) fn build_recovery_enrollment_artifacts_inner<R: CryptoRng + RngCore>(
    request: RecoveryEnrollmentBuildRequest<'_>,
    rng: &mut R,
) -> Result<RecoveryEnrollmentArtifacts, RecoveryEnrollmentCryptoError> {
    let RecoveryEnrollmentBuildRequest {
        enrollment_id,
        recovery_root_id,
        certificate_id,
        certificate,
        device_name,
        device_platform,
        recovery_keys,
        device_keys,
        material,
    } = request;
    validate_builder_bindings(
        &certificate,
        &device_name,
        recovery_keys,
        device_keys,
        material,
    )?;

    let mut record = RecoveryEnrollmentRecordV1 {
        schema_version: RECOVERY_ENROLLMENT_SCHEMA_VERSION,
        enrollment_id,
        recovery_root_id,
        account_id: certificate.account_id,
        workspace_id: certificate.workspace_id,
        recovery_signing_public_key: recovery_keys.signing_public_key(),
        recovery_wrapping_public_key: recovery_keys.wrapping_public_key(),
        genesis_certificate_id: certificate_id,
        genesis_certificate: certificate,
        device_name,
        device_platform,
        key_epoch: material.key_epoch(),
        encrypted_recovery_metadata: WrappedKeyEnvelope {
            ephemeral_public_key: recovery_keys.wrapping_public_key(),
            nonce: context_relay_protocol::XChaChaNonce([0; 24]),
            ciphertext: vec![0; MIN_WRAPPED_CIPHERTEXT_BYTES],
        },
        recovery_root_signature: Ed25519SignatureBytes([0; 64]),
    };

    let certificate_sha256 = certificate_digest(&record.genesis_certificate)?;
    let plaintext = encode_pairing_key_bundle_v1(material)?;
    let recovery_aad = recovery_metadata_aad(&record, certificate_sha256);
    record.encrypted_recovery_metadata = wrap_secret_with_rng(
        record.recovery_wrapping_public_key,
        plaintext.as_slice(),
        &recovery_aad,
        rng,
    )?;
    let preimage = encode_recovery_enrollment_signing_preimage_v1(&record)?;
    record.recovery_root_signature = recovery_keys.sign_enrollment_record(&preimage);
    let canonical_record = encode_recovery_enrollment_record_v1(&record)?;
    let canonical_record_sha256 = digest(&canonical_record);

    let device_id = record.genesis_certificate.device_id;
    let device_aad =
        device_workspace_material_aad(&record, certificate_sha256, device_id, device_keys);
    let device_material_envelope = wrap_secret_with_rng(
        device_keys.wrapping_public_key(),
        plaintext.as_slice(),
        &device_aad,
        rng,
    )?;
    validate_envelope_shape(&device_material_envelope)?;
    let device_material_envelope_sha256 = digest(&encode_recovery_device_envelope_v1(
        &device_material_envelope,
    )?);

    Ok(RecoveryEnrollmentArtifacts {
        record,
        canonical_record,
        canonical_record_sha256,
        device_material_envelope,
        device_material_envelope_sha256,
    })
}

pub fn encode_recovery_enrollment_record_v1(
    record: &RecoveryEnrollmentRecordV1,
) -> Result<Vec<u8>, RecoveryEnrollmentCryptoError> {
    validate_record(record, true)?;
    let mut encoder = Encoder::new(Vec::with_capacity(1024));
    encode_record_map(&mut encoder, record, true)?;
    let output = encoder.into_writer();
    if output.len() > MAX_RECOVERY_ENROLLMENT_RECORD_BYTES {
        return Err(RecoveryEnrollmentCryptoError::InvalidRecord);
    }
    Ok(output)
}

pub fn decode_recovery_enrollment_record_v1(
    input: &[u8],
) -> Result<RecoveryEnrollmentRecordV1, RecoveryEnrollmentCryptoError> {
    if input.len() > MAX_RECOVERY_ENROLLMENT_RECORD_BYTES {
        return Err(RecoveryEnrollmentCryptoError::InvalidRecord);
    }
    let mut decoder = Decoder::new(input);
    require_map(&mut decoder, 14)?;
    expect_key(&mut decoder, 0)?;
    let schema_version = decoder.u16().map_err(dec)?;
    expect_key(&mut decoder, 1)?;
    let enrollment_id = decode_id(read_fixed::<16>(&mut decoder)?)?;
    expect_key(&mut decoder, 2)?;
    let recovery_root_id = decode_id(read_fixed::<16>(&mut decoder)?)?;
    expect_key(&mut decoder, 3)?;
    let account_id = decode_id(read_fixed::<16>(&mut decoder)?)?;
    expect_key(&mut decoder, 4)?;
    let workspace_id = decode_id(read_fixed::<16>(&mut decoder)?)?;
    expect_key(&mut decoder, 5)?;
    let recovery_signing_public_key = Ed25519PublicKeyBytes(read_fixed::<32>(&mut decoder)?);
    expect_key(&mut decoder, 6)?;
    let recovery_wrapping_public_key = X25519PublicKeyBytes(read_fixed::<32>(&mut decoder)?);
    expect_key(&mut decoder, 7)?;
    let genesis_certificate_id = decode_id(read_fixed::<16>(&mut decoder)?)?;
    expect_key(&mut decoder, 8)?;
    let genesis_certificate = decode_certificate_v1(&mut decoder)?;
    expect_key(&mut decoder, 9)?;
    let device_name = decoder.str().map_err(dec)?.to_owned();
    expect_key(&mut decoder, 10)?;
    let device_platform = decode_native_platform(decoder.u8().map_err(dec)?)?;
    expect_key(&mut decoder, 11)?;
    let key_epoch = decoder.u32().map_err(dec)?;
    expect_key(&mut decoder, 12)?;
    let encrypted_recovery_metadata =
        decode_wrapped_envelope_with_limit(&mut decoder, MAX_RECOVERY_ENROLLMENT_RECORD_BYTES)?;
    expect_key(&mut decoder, 13)?;
    let recovery_root_signature = Ed25519SignatureBytes(read_fixed::<64>(&mut decoder)?);
    if decoder.position() != input.len() {
        return Err(RecoveryEnrollmentCryptoError::InvalidRecord);
    }

    let record = RecoveryEnrollmentRecordV1 {
        schema_version,
        enrollment_id,
        recovery_root_id,
        account_id,
        workspace_id,
        recovery_signing_public_key,
        recovery_wrapping_public_key,
        genesis_certificate_id,
        genesis_certificate,
        device_name,
        device_platform,
        key_epoch,
        encrypted_recovery_metadata,
        recovery_root_signature,
    };
    validate_record(&record, true)?;
    if encode_recovery_enrollment_record_v1(&record)?.as_slice() != input {
        return Err(RecoveryEnrollmentCryptoError::InvalidRecord);
    }
    Ok(record)
}

pub fn encode_recovery_enrollment_signing_preimage_v1(
    record: &RecoveryEnrollmentRecordV1,
) -> Result<Vec<u8>, RecoveryEnrollmentCryptoError> {
    validate_record(record, false)?;
    let mut encoder = Encoder::new(Vec::with_capacity(1024));
    encode_record_map(&mut encoder, record, false)?;
    let map = encoder.into_writer();
    if RECOVERY_ENROLLMENT_SIGNING_DOMAIN.len() + map.len() > MAX_RECOVERY_ENROLLMENT_RECORD_BYTES {
        return Err(RecoveryEnrollmentCryptoError::InvalidRecord);
    }
    let mut preimage = Vec::with_capacity(RECOVERY_ENROLLMENT_SIGNING_DOMAIN.len() + map.len());
    preimage.extend_from_slice(RECOVERY_ENROLLMENT_SIGNING_DOMAIN);
    preimage.extend_from_slice(&map);
    Ok(preimage)
}

pub fn open_recovery_metadata(
    record: &RecoveryEnrollmentRecordV1,
    recovery_keys: &RecoveryKeys,
) -> Result<PairingKeyBundle, RecoveryEnrollmentCryptoError> {
    validate_record(record, true)?;
    if recovery_keys.signing_public_key() != record.recovery_signing_public_key
        || recovery_keys.wrapping_public_key() != record.recovery_wrapping_public_key
    {
        return Err(RecoveryEnrollmentCryptoError::InvalidRecord);
    }
    let certificate_sha256 = certificate_digest(&record.genesis_certificate)?;
    let aad = recovery_metadata_aad(record, certificate_sha256);
    let plaintext = recovery_keys.unwrap_secret(&record.encrypted_recovery_metadata, &aad)?;
    let material = decode_pairing_key_bundle_v1(plaintext.expose())?;
    validate_opened_material(record, &material)?;
    Ok(material)
}

pub fn open_device_workspace_material(
    record: &RecoveryEnrollmentRecordV1,
    envelope: &WrappedKeyEnvelope,
    device_id: DeviceId,
    device_keys: &DeviceKeys,
) -> Result<PairingKeyBundle, RecoveryEnrollmentCryptoError> {
    validate_record(record, true)?;
    validate_envelope_shape(envelope)?;
    let certificate = &record.genesis_certificate;
    if device_id != certificate.device_id
        || device_keys.signing_public_key() != certificate.signing_public_key
        || device_keys.wrapping_public_key() != certificate.wrapping_public_key
    {
        return Err(RecoveryEnrollmentCryptoError::InvalidRecord);
    }
    let certificate_sha256 = certificate_digest(certificate)?;
    let aad = device_workspace_material_aad(record, certificate_sha256, device_id, device_keys);
    let plaintext = device_keys.unwrap_secret(envelope, &aad)?;
    let material = decode_pairing_key_bundle_v1(plaintext.expose())?;
    validate_opened_material(record, &material)?;
    Ok(material)
}

fn validate_builder_bindings(
    certificate: &DeviceCertificateV1,
    device_name: &str,
    recovery_keys: &RecoveryKeys,
    device_keys: &DeviceKeys,
    material: &PairingKeyBundle,
) -> Result<(), RecoveryEnrollmentCryptoError> {
    if certificate.account_id != material.account_id()
        || certificate.workspace_id != material.workspace_id()
        || certificate.control_epoch != 1
        || material.control_epoch() != 1
        || material.key_epoch() != 1
        || certificate.signing_public_key != device_keys.signing_public_key()
        || certificate.wrapping_public_key != device_keys.wrapping_public_key()
        || recovery_keys.signing_public_key().0 == recovery_keys.wrapping_public_key().0
        || device_keys.signing_public_key().0 == device_keys.wrapping_public_key().0
        || device_name.trim().is_empty()
        || device_name.len() > MAX_RECOVERY_DEVICE_NAME_BYTES
    {
        return Err(RecoveryEnrollmentCryptoError::InvalidRecord);
    }
    certificate.verify_genesis(recovery_keys.signing_public_key())?;
    validate_ed25519_public_key(certificate.signing_public_key)?;
    validate_x25519_public_key(certificate.wrapping_public_key)?;
    Ok(())
}

fn validate_record(
    record: &RecoveryEnrollmentRecordV1,
    verify_record_signature: bool,
) -> Result<(), RecoveryEnrollmentCryptoError> {
    if record.schema_version != RECOVERY_ENROLLMENT_SCHEMA_VERSION
        || record.genesis_certificate.control_epoch != 1
        || record.key_epoch != 1
        || record.device_name.trim().is_empty()
        || record.device_name.len() > MAX_RECOVERY_DEVICE_NAME_BYTES
        || record.account_id != record.genesis_certificate.account_id
        || record.workspace_id != record.genesis_certificate.workspace_id
        || record.recovery_signing_public_key.0 == record.recovery_wrapping_public_key.0
        || record.genesis_certificate.signing_public_key.0
            == record.genesis_certificate.wrapping_public_key.0
    {
        return Err(RecoveryEnrollmentCryptoError::InvalidRecord);
    }
    let CertificateIssuerV1::RecoveryRoot(issuer_key) = record.genesis_certificate.issuer else {
        return Err(RecoveryEnrollmentCryptoError::InvalidRecord);
    };
    if issuer_key != record.recovery_signing_public_key {
        return Err(RecoveryEnrollmentCryptoError::InvalidRecord);
    }
    validate_ed25519_public_key(record.recovery_signing_public_key)?;
    validate_x25519_public_key(record.recovery_wrapping_public_key)?;
    validate_ed25519_public_key(record.genesis_certificate.signing_public_key)?;
    validate_x25519_public_key(record.genesis_certificate.wrapping_public_key)?;
    record
        .genesis_certificate
        .verify_genesis(record.recovery_signing_public_key)?;
    validate_envelope_shape(&record.encrypted_recovery_metadata)?;

    if verify_record_signature {
        let preimage = encode_recovery_enrollment_signing_preimage_v1(record)?;
        verify_enrollment_record_signature(
            record.recovery_signing_public_key,
            &preimage,
            record.recovery_root_signature,
        )?;
    }
    Ok(())
}

fn validate_envelope_shape(
    envelope: &WrappedKeyEnvelope,
) -> Result<(), RecoveryEnrollmentCryptoError> {
    if envelope.ciphertext.len() < MIN_WRAPPED_CIPHERTEXT_BYTES
        || envelope.ciphertext.len() > MAX_RECOVERY_ENROLLMENT_RECORD_BYTES
    {
        return Err(RecoveryEnrollmentCryptoError::InvalidRecord);
    }
    validate_x25519_public_key(envelope.ephemeral_public_key)?;
    Ok(())
}

fn validate_opened_material(
    record: &RecoveryEnrollmentRecordV1,
    material: &PairingKeyBundle,
) -> Result<(), RecoveryEnrollmentCryptoError> {
    if material.account_id() != record.account_id
        || material.workspace_id() != record.workspace_id
        || material.control_epoch() != record.genesis_certificate.control_epoch
        || material.key_epoch() != record.key_epoch
    {
        return Err(RecoveryEnrollmentCryptoError::InvalidRecord);
    }
    Ok(())
}

fn encode_record_map(
    encoder: &mut Encoder<Vec<u8>>,
    record: &RecoveryEnrollmentRecordV1,
    include_signature: bool,
) -> Result<(), RecoveryEnrollmentCryptoError> {
    encoder
        .map(if include_signature { 14 } else { 13 })
        .map_err(enc)?;
    key(encoder, 0)?;
    encoder.u16(record.schema_version).map_err(enc)?;
    key(encoder, 1)?;
    bytes(encoder, record.enrollment_id.as_bytes())?;
    key(encoder, 2)?;
    bytes(encoder, record.recovery_root_id.as_bytes())?;
    key(encoder, 3)?;
    bytes(encoder, record.account_id.as_bytes())?;
    key(encoder, 4)?;
    bytes(encoder, record.workspace_id.as_bytes())?;
    key(encoder, 5)?;
    bytes(encoder, &record.recovery_signing_public_key.0)?;
    key(encoder, 6)?;
    bytes(encoder, &record.recovery_wrapping_public_key.0)?;
    key(encoder, 7)?;
    bytes(encoder, record.genesis_certificate_id.as_bytes())?;
    key(encoder, 8)?;
    encode_certificate_v1(encoder, &record.genesis_certificate)?;
    key(encoder, 9)?;
    encoder.str(&record.device_name).map_err(enc)?;
    key(encoder, 10)?;
    encoder
        .u8(encode_native_platform(record.device_platform))
        .map_err(enc)?;
    key(encoder, 11)?;
    encoder.u32(record.key_epoch).map_err(enc)?;
    key(encoder, 12)?;
    encode_wrapped_envelope(encoder, &record.encrypted_recovery_metadata)?;
    if include_signature {
        key(encoder, 13)?;
        bytes(encoder, &record.recovery_root_signature.0)?;
    }
    Ok(())
}

fn recovery_metadata_aad(
    record: &RecoveryEnrollmentRecordV1,
    certificate_sha256: Sha256Digest,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(RECOVERY_METADATA_AAD_DOMAIN.len() + 184);
    aad.extend_from_slice(RECOVERY_METADATA_AAD_DOMAIN);
    append_common_aad(&mut aad, record, certificate_sha256);
    aad
}

fn device_workspace_material_aad(
    record: &RecoveryEnrollmentRecordV1,
    certificate_sha256: Sha256Digest,
    device_id: DeviceId,
    device_keys: &DeviceKeys,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(DEVICE_WORKSPACE_MATERIAL_AAD_DOMAIN.len() + 264);
    aad.extend_from_slice(DEVICE_WORKSPACE_MATERIAL_AAD_DOMAIN);
    append_common_aad(&mut aad, record, certificate_sha256);
    aad.extend_from_slice(device_id.as_bytes());
    aad.extend_from_slice(&device_keys.signing_public_key().0);
    aad.extend_from_slice(&device_keys.wrapping_public_key().0);
    aad
}

fn append_common_aad(
    aad: &mut Vec<u8>,
    record: &RecoveryEnrollmentRecordV1,
    certificate_sha256: Sha256Digest,
) {
    aad.extend_from_slice(record.enrollment_id.as_bytes());
    aad.extend_from_slice(record.recovery_root_id.as_bytes());
    aad.extend_from_slice(record.account_id.as_bytes());
    aad.extend_from_slice(record.workspace_id.as_bytes());
    aad.extend_from_slice(&record.recovery_signing_public_key.0);
    aad.extend_from_slice(&record.recovery_wrapping_public_key.0);
    aad.extend_from_slice(record.genesis_certificate_id.as_bytes());
    aad.extend_from_slice(&certificate_sha256.0);
    aad.extend_from_slice(&record.genesis_certificate.control_epoch.to_be_bytes());
    aad.extend_from_slice(&record.key_epoch.to_be_bytes());
}

pub(crate) fn encode_recovery_device_envelope_v1(
    envelope: &WrappedKeyEnvelope,
) -> Result<Vec<u8>, RecoveryEnrollmentCryptoError> {
    validate_envelope_shape(envelope)?;
    let mut encoder = Encoder::new(Vec::with_capacity(256));
    encode_wrapped_envelope(&mut encoder, envelope)?;
    Ok(encoder.into_writer())
}

pub(crate) fn decode_recovery_device_envelope_v1(
    input: &[u8],
) -> Result<WrappedKeyEnvelope, RecoveryEnrollmentCryptoError> {
    if input.len() > MAX_RECOVERY_ENROLLMENT_RECORD_BYTES {
        return Err(RecoveryEnrollmentCryptoError::InvalidRecord);
    }
    let mut decoder = Decoder::new(input);
    let envelope =
        decode_wrapped_envelope_with_limit(&mut decoder, MAX_RECOVERY_ENROLLMENT_RECORD_BYTES)?;
    if decoder.position() != input.len()
        || encode_recovery_device_envelope_v1(&envelope)?.as_slice() != input
    {
        return Err(RecoveryEnrollmentCryptoError::InvalidRecord);
    }
    Ok(envelope)
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest(Sha256::digest(bytes).into())
}

fn decode_id<T: FromStr>(bytes: [u8; 16]) -> Result<T, RecoveryEnrollmentCryptoError> {
    let value = format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    );
    value
        .parse()
        .map_err(|_| RecoveryEnrollmentCryptoError::InvalidRecord)
}

fn key(encoder: &mut Encoder<Vec<u8>>, value: u8) -> Result<(), RecoveryEnrollmentCryptoError> {
    encoder.u8(value).map(|_| ()).map_err(enc)
}

fn bytes(
    encoder: &mut Encoder<Vec<u8>>,
    value: &[u8],
) -> Result<(), RecoveryEnrollmentCryptoError> {
    encoder.bytes(value).map(|_| ()).map_err(enc)
}

fn expect_key(
    decoder: &mut Decoder<'_>,
    expected: u8,
) -> Result<(), RecoveryEnrollmentCryptoError> {
    (decoder.u8().map_err(dec)? == expected)
        .then_some(())
        .ok_or(RecoveryEnrollmentCryptoError::InvalidRecord)
}

fn require_map(
    decoder: &mut Decoder<'_>,
    expected: u64,
) -> Result<(), RecoveryEnrollmentCryptoError> {
    (decoder.map().map_err(dec)? == Some(expected))
        .then_some(())
        .ok_or(RecoveryEnrollmentCryptoError::InvalidRecord)
}

fn read_fixed<const N: usize>(
    decoder: &mut Decoder<'_>,
) -> Result<[u8; N], RecoveryEnrollmentCryptoError> {
    decoder
        .bytes()
        .map_err(dec)?
        .try_into()
        .map_err(|_| RecoveryEnrollmentCryptoError::InvalidRecord)
}

fn enc(_: minicbor::encode::Error<std::convert::Infallible>) -> RecoveryEnrollmentCryptoError {
    RecoveryEnrollmentCryptoError::InvalidRecord
}

fn dec(_: minicbor::decode::Error) -> RecoveryEnrollmentCryptoError {
    RecoveryEnrollmentCryptoError::InvalidRecord
}
