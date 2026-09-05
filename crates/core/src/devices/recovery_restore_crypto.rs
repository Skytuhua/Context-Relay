use std::{fmt, str::FromStr};

use context_relay_protocol::{
    AccountId, DeviceCertificateId, DeviceId, Ed25519SignatureBytes, NativePlatform,
    PairingRequestNonce, RecoveryEnrollmentId, RecoveryRestoreId, RecoveryRootId, Sha256Digest,
    WorkspaceId,
};
use minicbor::{Decoder, Encoder};
use rand_core::{CryptoRng, OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::{
    crypto::{
        CertificateFieldsV1, CertificateIssuerV1, CryptoError, DeviceCertificateV1, DeviceKeys,
        RecoveryKeys, RecoveryPhrase, WrappedKeyEnvelope, validate_ed25519_public_key,
        validate_x25519_public_key, verify_signature, wrap_secret_with_rng,
    },
    devices::{
        crypto::{
            PairingKeyBundle, certificate_digest, decode_certificate_v1, decode_native_platform,
            decode_pairing_key_bundle_v1, decode_wrapped_envelope_with_limit,
            encode_certificate_v1, encode_native_platform, encode_pairing_key_bundle_v1,
            encode_wrapped_envelope,
        },
        recovery_crypto::{
            MAX_RECOVERY_DEVICE_NAME_BYTES, RecoveryEnrollmentCryptoError,
            RecoveryEnrollmentRecordV1, decode_recovery_enrollment_record_v1,
            encode_recovery_enrollment_record_v1, open_recovery_metadata,
        },
    },
};

pub const RECOVERY_DEVICE_CLAIM_SCHEMA_VERSION: u16 = 1;
pub const MAX_RECOVERY_DEVICE_CLAIM_BYTES: usize = 32 * 1024;

const RECOVERY_DEVICE_CLAIM_SIGNING_DOMAIN: &[u8] = b"context-relay/recovery-device-claim/v1\0";
const RECOVERED_DEVICE_MATERIAL_AAD_DOMAIN: &[u8] = b"context-relay/recovered-device-material/v1\0";
const MIN_WRAPPED_CIPHERTEXT_BYTES: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryRestoreCryptoError {
    InvalidRecovery,
}

impl fmt::Display for RecoveryRestoreCryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("recovery authentication failed")
    }
}

impl std::error::Error for RecoveryRestoreCryptoError {}

impl From<CryptoError> for RecoveryRestoreCryptoError {
    fn from(_: CryptoError) -> Self {
        Self::InvalidRecovery
    }
}

impl From<RecoveryEnrollmentCryptoError> for RecoveryRestoreCryptoError {
    fn from(_: RecoveryEnrollmentCryptoError) -> Self {
        Self::InvalidRecovery
    }
}

pub struct AuthenticatedRecoveryRoot {
    record: RecoveryEnrollmentRecordV1,
    canonical_record_sha256: Sha256Digest,
    recovery_keys: RecoveryKeys,
    material: PairingKeyBundle,
}

impl fmt::Debug for AuthenticatedRecoveryRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedRecoveryRoot")
            .field("enrollment_id", &self.record.enrollment_id)
            .field("recovery_root_id", &self.record.recovery_root_id)
            .field("canonical_record_sha256", &self.canonical_record_sha256)
            .field("recovery_keys_and_workspace_material", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RecoveryDeviceClaimV1 {
    pub schema_version: u16,
    pub restore_id: RecoveryRestoreId,
    pub enrollment_id: RecoveryEnrollmentId,
    pub recovery_root_id: RecoveryRootId,
    pub account_id: AccountId,
    pub workspace_id: WorkspaceId,
    pub canonical_record_sha256: Sha256Digest,
    pub expected_recovery_generation: u64,
    pub certificate_id: DeviceCertificateId,
    pub certificate: DeviceCertificateV1,
    pub device_name: String,
    pub device_platform: NativePlatform,
    pub key_epoch: u32,
    pub device_material_envelope: WrappedKeyEnvelope,
    pub recovery_root_signature: Ed25519SignatureBytes,
}

impl fmt::Debug for RecoveryDeviceClaimV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryDeviceClaimV1")
            .field("schema_version", &self.schema_version)
            .field("restore_id", &self.restore_id)
            .field("enrollment_id", &self.enrollment_id)
            .field("recovery_root_id", &self.recovery_root_id)
            .field("account_id", &self.account_id)
            .field("workspace_id", &self.workspace_id)
            .field("canonical_record_sha256", &self.canonical_record_sha256)
            .field(
                "expected_recovery_generation",
                &self.expected_recovery_generation,
            )
            .field("certificate_id", &self.certificate_id)
            .field("device_name", &self.device_name)
            .field("device_platform", &self.device_platform)
            .field("key_epoch", &self.key_epoch)
            .field("certificate_envelope_and_signature", &"[REDACTED]")
            .finish()
    }
}

pub struct RecoveryDeviceClaimArtifacts {
    pub claim: RecoveryDeviceClaimV1,
    pub canonical_claim: Vec<u8>,
    pub canonical_claim_sha256: Sha256Digest,
}

impl fmt::Debug for RecoveryDeviceClaimArtifacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryDeviceClaimArtifacts")
            .field("restore_id", &self.claim.restore_id)
            .field("canonical_claim_sha256", &self.canonical_claim_sha256)
            .field("canonical_claim", &"[REDACTED]")
            .finish()
    }
}

pub fn authenticate_recovery_root(
    canonical_record: &[u8],
    expected_sha256: Sha256Digest,
    phrase: RecoveryPhrase,
) -> Result<AuthenticatedRecoveryRoot, RecoveryRestoreCryptoError> {
    if digest(canonical_record) != expected_sha256 {
        return Err(RecoveryRestoreCryptoError::InvalidRecovery);
    }
    let record = decode_recovery_enrollment_record_v1(canonical_record)?;
    let recovery_keys = RecoveryKeys::derive(&phrase)?;
    drop(phrase);
    if recovery_keys.signing_public_key() != record.recovery_signing_public_key
        || recovery_keys.wrapping_public_key() != record.recovery_wrapping_public_key
    {
        return Err(RecoveryRestoreCryptoError::InvalidRecovery);
    }
    let material = open_recovery_metadata(&record, &recovery_keys)?;
    Ok(AuthenticatedRecoveryRoot {
        record,
        canonical_record_sha256: expected_sha256,
        recovery_keys,
        material,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn build_recovery_device_claim(
    authority: AuthenticatedRecoveryRoot,
    restore_id: RecoveryRestoreId,
    expected_recovery_generation: u64,
    certificate_id: DeviceCertificateId,
    request_nonce: PairingRequestNonce,
    device_id: DeviceId,
    device_name: String,
    device_platform: NativePlatform,
    device_keys: &DeviceKeys,
) -> Result<RecoveryDeviceClaimArtifacts, RecoveryRestoreCryptoError> {
    build_recovery_device_claim_inner(
        authority,
        restore_id,
        expected_recovery_generation,
        certificate_id,
        request_nonce,
        device_id,
        device_name,
        device_platform,
        device_keys,
        &mut OsRng,
    )
}

#[cfg(feature = "test-support")]
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn build_recovery_device_claim_with_rng<R: CryptoRng + RngCore>(
    authority: AuthenticatedRecoveryRoot,
    restore_id: RecoveryRestoreId,
    expected_recovery_generation: u64,
    certificate_id: DeviceCertificateId,
    request_nonce: PairingRequestNonce,
    device_id: DeviceId,
    device_name: String,
    device_platform: NativePlatform,
    device_keys: &DeviceKeys,
    rng: &mut R,
) -> Result<RecoveryDeviceClaimArtifacts, RecoveryRestoreCryptoError> {
    build_recovery_device_claim_inner(
        authority,
        restore_id,
        expected_recovery_generation,
        certificate_id,
        request_nonce,
        device_id,
        device_name,
        device_platform,
        device_keys,
        rng,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_recovery_device_claim_inner<R: CryptoRng + RngCore>(
    authority: AuthenticatedRecoveryRoot,
    restore_id: RecoveryRestoreId,
    expected_recovery_generation: u64,
    certificate_id: DeviceCertificateId,
    request_nonce: PairingRequestNonce,
    device_id: DeviceId,
    device_name: String,
    device_platform: NativePlatform,
    device_keys: &DeviceKeys,
    rng: &mut R,
) -> Result<RecoveryDeviceClaimArtifacts, RecoveryRestoreCryptoError> {
    let AuthenticatedRecoveryRoot {
        record,
        canonical_record_sha256,
        recovery_keys,
        material,
    } = authority;
    validate_builder_identity(
        &record,
        restore_id,
        expected_recovery_generation,
        certificate_id,
        device_id,
        &device_name,
        device_keys,
    )?;

    let certificate = DeviceCertificateV1::issue_genesis(
        CertificateFieldsV1 {
            account_id: record.account_id,
            workspace_id: record.workspace_id,
            control_epoch: material.control_epoch(),
            request_nonce,
            device_id,
            signing_public_key: device_keys.signing_public_key(),
            wrapping_public_key: device_keys.wrapping_public_key(),
        },
        &recovery_keys,
    )?;
    let mut claim = RecoveryDeviceClaimV1 {
        schema_version: RECOVERY_DEVICE_CLAIM_SCHEMA_VERSION,
        restore_id,
        enrollment_id: record.enrollment_id,
        recovery_root_id: record.recovery_root_id,
        account_id: record.account_id,
        workspace_id: record.workspace_id,
        canonical_record_sha256,
        expected_recovery_generation,
        certificate_id,
        certificate,
        device_name,
        device_platform,
        key_epoch: material.key_epoch(),
        device_material_envelope: WrappedKeyEnvelope {
            ephemeral_public_key: device_keys.wrapping_public_key(),
            nonce: context_relay_protocol::XChaChaNonce([0; 24]),
            ciphertext: vec![0; MIN_WRAPPED_CIPHERTEXT_BYTES],
        },
        recovery_root_signature: Ed25519SignatureBytes([0; 64]),
    };

    let aad = recovered_device_material_aad(&claim)?;
    let plaintext = encode_pairing_key_bundle_v1(&material)?;
    claim.device_material_envelope = wrap_secret_with_rng(
        device_keys.wrapping_public_key(),
        plaintext.as_slice(),
        &aad,
        rng,
    )?;
    let preimage = encode_recovery_device_claim_signing_preimage_v1(&claim)?;
    claim.recovery_root_signature = recovery_keys.sign_restore_claim(&preimage);
    verify_recovery_device_claim(&record, &claim)?;
    let canonical_claim = encode_recovery_device_claim_v1(&claim)?;
    let canonical_claim_sha256 = digest(&canonical_claim);
    Ok(RecoveryDeviceClaimArtifacts {
        claim,
        canonical_claim,
        canonical_claim_sha256,
    })
}

pub fn encode_recovery_device_claim_v1(
    claim: &RecoveryDeviceClaimV1,
) -> Result<Vec<u8>, RecoveryRestoreCryptoError> {
    validate_claim_shape(claim, true)?;
    let mut encoder = Encoder::new(Vec::with_capacity(1024));
    encode_claim_map(&mut encoder, claim, true)?;
    let output = encoder.into_writer();
    if output.len() > MAX_RECOVERY_DEVICE_CLAIM_BYTES {
        return Err(RecoveryRestoreCryptoError::InvalidRecovery);
    }
    Ok(output)
}

pub fn decode_recovery_device_claim_v1(
    input: &[u8],
) -> Result<RecoveryDeviceClaimV1, RecoveryRestoreCryptoError> {
    if input.len() > MAX_RECOVERY_DEVICE_CLAIM_BYTES {
        return Err(RecoveryRestoreCryptoError::InvalidRecovery);
    }
    let mut decoder = Decoder::new(input);
    require_map(&mut decoder, 15)?;
    expect_key(&mut decoder, 0)?;
    let schema_version = decoder.u16().map_err(dec)?;
    expect_key(&mut decoder, 1)?;
    let restore_id = decode_id(read_fixed::<16>(&mut decoder)?)?;
    expect_key(&mut decoder, 2)?;
    let enrollment_id = decode_id(read_fixed::<16>(&mut decoder)?)?;
    expect_key(&mut decoder, 3)?;
    let recovery_root_id = decode_id(read_fixed::<16>(&mut decoder)?)?;
    expect_key(&mut decoder, 4)?;
    let account_id = decode_id(read_fixed::<16>(&mut decoder)?)?;
    expect_key(&mut decoder, 5)?;
    let workspace_id = decode_id(read_fixed::<16>(&mut decoder)?)?;
    expect_key(&mut decoder, 6)?;
    let canonical_record_sha256 = Sha256Digest(read_fixed::<32>(&mut decoder)?);
    expect_key(&mut decoder, 7)?;
    let expected_recovery_generation = decoder.u64().map_err(dec)?;
    expect_key(&mut decoder, 8)?;
    let certificate_id = decode_id(read_fixed::<16>(&mut decoder)?)?;
    expect_key(&mut decoder, 9)?;
    let certificate = decode_certificate_v1(&mut decoder)?;
    expect_key(&mut decoder, 10)?;
    let device_name = decoder.str().map_err(dec)?.to_owned();
    expect_key(&mut decoder, 11)?;
    let device_platform = decode_native_platform(decoder.u8().map_err(dec)?)?;
    expect_key(&mut decoder, 12)?;
    let key_epoch = decoder.u32().map_err(dec)?;
    expect_key(&mut decoder, 13)?;
    let device_material_envelope =
        decode_wrapped_envelope_with_limit(&mut decoder, MAX_RECOVERY_DEVICE_CLAIM_BYTES)?;
    expect_key(&mut decoder, 14)?;
    let recovery_root_signature = Ed25519SignatureBytes(read_fixed::<64>(&mut decoder)?);
    if decoder.position() != input.len() {
        return Err(RecoveryRestoreCryptoError::InvalidRecovery);
    }
    let claim = RecoveryDeviceClaimV1 {
        schema_version,
        restore_id,
        enrollment_id,
        recovery_root_id,
        account_id,
        workspace_id,
        canonical_record_sha256,
        expected_recovery_generation,
        certificate_id,
        certificate,
        device_name,
        device_platform,
        key_epoch,
        device_material_envelope,
        recovery_root_signature,
    };
    validate_claim_shape(&claim, true)?;
    if encode_recovery_device_claim_v1(&claim)?.as_slice() != input {
        return Err(RecoveryRestoreCryptoError::InvalidRecovery);
    }
    Ok(claim)
}

pub fn encode_recovery_device_claim_signing_preimage_v1(
    claim: &RecoveryDeviceClaimV1,
) -> Result<Vec<u8>, RecoveryRestoreCryptoError> {
    validate_claim_shape(claim, false)?;
    let mut encoder = Encoder::new(Vec::with_capacity(1024));
    encode_claim_map(&mut encoder, claim, false)?;
    let map = encoder.into_writer();
    if RECOVERY_DEVICE_CLAIM_SIGNING_DOMAIN.len() + map.len() > MAX_RECOVERY_DEVICE_CLAIM_BYTES {
        return Err(RecoveryRestoreCryptoError::InvalidRecovery);
    }
    let mut preimage = Vec::with_capacity(RECOVERY_DEVICE_CLAIM_SIGNING_DOMAIN.len() + map.len());
    preimage.extend_from_slice(RECOVERY_DEVICE_CLAIM_SIGNING_DOMAIN);
    preimage.extend_from_slice(&map);
    Ok(preimage)
}

pub fn verify_recovery_device_claim(
    record: &RecoveryEnrollmentRecordV1,
    claim: &RecoveryDeviceClaimV1,
) -> Result<(), RecoveryRestoreCryptoError> {
    let canonical_record = encode_recovery_enrollment_record_v1(record)?;
    validate_claim_shape(claim, true)?;
    let CertificateIssuerV1::RecoveryRoot(issuer_key) = claim.certificate.issuer else {
        return Err(RecoveryRestoreCryptoError::InvalidRecovery);
    };
    if claim.enrollment_id != record.enrollment_id
        || claim.recovery_root_id != record.recovery_root_id
        || claim.account_id != record.account_id
        || claim.workspace_id != record.workspace_id
        || claim.canonical_record_sha256 != digest(&canonical_record)
        || issuer_key != record.recovery_signing_public_key
        || claim.certificate.control_epoch != record.genesis_certificate.control_epoch
        || claim.key_epoch != record.key_epoch
        || claim.certificate.device_id == record.genesis_certificate.device_id
        || claim.certificate_id == record.genesis_certificate_id
    {
        return Err(RecoveryRestoreCryptoError::InvalidRecovery);
    }
    Ok(())
}

pub fn open_recovered_device_material(
    record: &RecoveryEnrollmentRecordV1,
    claim: &RecoveryDeviceClaimV1,
    device_keys: &DeviceKeys,
) -> Result<PairingKeyBundle, RecoveryRestoreCryptoError> {
    verify_recovery_device_claim(record, claim)?;
    if claim.certificate.signing_public_key != device_keys.signing_public_key()
        || claim.certificate.wrapping_public_key != device_keys.wrapping_public_key()
    {
        return Err(RecoveryRestoreCryptoError::InvalidRecovery);
    }
    let aad = recovered_device_material_aad(claim)?;
    let plaintext = device_keys.unwrap_secret(&claim.device_material_envelope, &aad)?;
    let material = decode_pairing_key_bundle_v1(plaintext.expose())?;
    if material.account_id() != claim.account_id
        || material.workspace_id() != claim.workspace_id
        || material.control_epoch() != claim.certificate.control_epoch
        || material.key_epoch() != claim.key_epoch
    {
        return Err(RecoveryRestoreCryptoError::InvalidRecovery);
    }
    Ok(material)
}

fn validate_builder_identity(
    record: &RecoveryEnrollmentRecordV1,
    restore_id: RecoveryRestoreId,
    expected_recovery_generation: u64,
    certificate_id: DeviceCertificateId,
    device_id: DeviceId,
    device_name: &str,
    device_keys: &DeviceKeys,
) -> Result<(), RecoveryRestoreCryptoError> {
    let identifiers = [
        *restore_id.as_bytes(),
        *certificate_id.as_bytes(),
        *device_id.as_bytes(),
        *record.enrollment_id.as_bytes(),
        *record.recovery_root_id.as_bytes(),
        *record.genesis_certificate_id.as_bytes(),
        *record.genesis_certificate.device_id.as_bytes(),
    ];
    for (index, value) in identifiers.iter().enumerate() {
        if identifiers[..index].contains(value) {
            return Err(RecoveryRestoreCryptoError::InvalidRecovery);
        }
    }
    if expected_recovery_generation >= i64::MAX as u64
        || device_name.trim().is_empty()
        || device_name.len() > MAX_RECOVERY_DEVICE_NAME_BYTES
        || device_keys.signing_public_key().0 == device_keys.wrapping_public_key().0
    {
        return Err(RecoveryRestoreCryptoError::InvalidRecovery);
    }
    validate_ed25519_public_key(device_keys.signing_public_key())?;
    validate_x25519_public_key(device_keys.wrapping_public_key())?;
    Ok(())
}

fn validate_claim_shape(
    claim: &RecoveryDeviceClaimV1,
    verify_claim_signature: bool,
) -> Result<(), RecoveryRestoreCryptoError> {
    if claim.schema_version != RECOVERY_DEVICE_CLAIM_SCHEMA_VERSION
        || claim.expected_recovery_generation >= i64::MAX as u64
        || claim.certificate.control_epoch == 0
        || claim.key_epoch == 0
        || claim.device_name.trim().is_empty()
        || claim.device_name.len() > MAX_RECOVERY_DEVICE_NAME_BYTES
        || claim.account_id != claim.certificate.account_id
        || claim.workspace_id != claim.certificate.workspace_id
        || claim.certificate.signing_public_key.0 == claim.certificate.wrapping_public_key.0
        || claim.device_material_envelope.ciphertext.len() < MIN_WRAPPED_CIPHERTEXT_BYTES
        || claim.device_material_envelope.ciphertext.len() > MAX_RECOVERY_DEVICE_CLAIM_BYTES
    {
        return Err(RecoveryRestoreCryptoError::InvalidRecovery);
    }
    let CertificateIssuerV1::RecoveryRoot(root_key) = claim.certificate.issuer else {
        return Err(RecoveryRestoreCryptoError::InvalidRecovery);
    };
    validate_ed25519_public_key(root_key)?;
    validate_ed25519_public_key(claim.certificate.signing_public_key)?;
    validate_x25519_public_key(claim.certificate.wrapping_public_key)?;
    validate_x25519_public_key(claim.device_material_envelope.ephemeral_public_key)?;
    claim.certificate.verify_genesis(root_key)?;
    if verify_claim_signature {
        let preimage = encode_recovery_device_claim_signing_preimage_v1(claim)?;
        verify_signature(root_key, &preimage, claim.recovery_root_signature)?;
    }
    Ok(())
}

fn recovered_device_material_aad(
    claim: &RecoveryDeviceClaimV1,
) -> Result<Vec<u8>, RecoveryRestoreCryptoError> {
    let certificate_sha256 = certificate_digest(&claim.certificate)?;
    let mut aad = Vec::with_capacity(RECOVERED_DEVICE_MATERIAL_AAD_DOMAIN.len() + 268);
    aad.extend_from_slice(RECOVERED_DEVICE_MATERIAL_AAD_DOMAIN);
    aad.extend_from_slice(claim.restore_id.as_bytes());
    aad.extend_from_slice(claim.enrollment_id.as_bytes());
    aad.extend_from_slice(claim.recovery_root_id.as_bytes());
    aad.extend_from_slice(claim.account_id.as_bytes());
    aad.extend_from_slice(claim.workspace_id.as_bytes());
    aad.extend_from_slice(&claim.canonical_record_sha256.0);
    aad.extend_from_slice(&claim.expected_recovery_generation.to_be_bytes());
    aad.extend_from_slice(claim.certificate_id.as_bytes());
    aad.extend_from_slice(&certificate_sha256.0);
    aad.extend_from_slice(&claim.certificate.control_epoch.to_be_bytes());
    aad.extend_from_slice(&claim.key_epoch.to_be_bytes());
    aad.extend_from_slice(claim.certificate.device_id.as_bytes());
    aad.extend_from_slice(&claim.certificate.signing_public_key.0);
    aad.extend_from_slice(&claim.certificate.wrapping_public_key.0);
    Ok(aad)
}

fn encode_claim_map(
    encoder: &mut Encoder<Vec<u8>>,
    claim: &RecoveryDeviceClaimV1,
    include_signature: bool,
) -> Result<(), RecoveryRestoreCryptoError> {
    encoder
        .map(if include_signature { 15 } else { 14 })
        .map_err(enc)?;
    key(encoder, 0)?;
    encoder.u16(claim.schema_version).map_err(enc)?;
    key(encoder, 1)?;
    bytes(encoder, claim.restore_id.as_bytes())?;
    key(encoder, 2)?;
    bytes(encoder, claim.enrollment_id.as_bytes())?;
    key(encoder, 3)?;
    bytes(encoder, claim.recovery_root_id.as_bytes())?;
    key(encoder, 4)?;
    bytes(encoder, claim.account_id.as_bytes())?;
    key(encoder, 5)?;
    bytes(encoder, claim.workspace_id.as_bytes())?;
    key(encoder, 6)?;
    bytes(encoder, &claim.canonical_record_sha256.0)?;
    key(encoder, 7)?;
    encoder
        .u64(claim.expected_recovery_generation)
        .map_err(enc)?;
    key(encoder, 8)?;
    bytes(encoder, claim.certificate_id.as_bytes())?;
    key(encoder, 9)?;
    encode_certificate_v1(encoder, &claim.certificate)?;
    key(encoder, 10)?;
    encoder.str(&claim.device_name).map_err(enc)?;
    key(encoder, 11)?;
    encoder
        .u8(encode_native_platform(claim.device_platform))
        .map_err(enc)?;
    key(encoder, 12)?;
    encoder.u32(claim.key_epoch).map_err(enc)?;
    key(encoder, 13)?;
    encode_wrapped_envelope(encoder, &claim.device_material_envelope)?;
    if include_signature {
        key(encoder, 14)?;
        bytes(encoder, &claim.recovery_root_signature.0)?;
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest(Sha256::digest(bytes).into())
}

fn decode_id<T: FromStr>(bytes: [u8; 16]) -> Result<T, RecoveryRestoreCryptoError> {
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
        .map_err(|_| RecoveryRestoreCryptoError::InvalidRecovery)
}

fn key(encoder: &mut Encoder<Vec<u8>>, value: u8) -> Result<(), RecoveryRestoreCryptoError> {
    encoder.u8(value).map(|_| ()).map_err(enc)
}

fn bytes(encoder: &mut Encoder<Vec<u8>>, value: &[u8]) -> Result<(), RecoveryRestoreCryptoError> {
    encoder.bytes(value).map(|_| ()).map_err(enc)
}

fn expect_key(decoder: &mut Decoder<'_>, expected: u8) -> Result<(), RecoveryRestoreCryptoError> {
    (decoder.u8().map_err(dec)? == expected)
        .then_some(())
        .ok_or(RecoveryRestoreCryptoError::InvalidRecovery)
}

fn require_map(decoder: &mut Decoder<'_>, expected: u64) -> Result<(), RecoveryRestoreCryptoError> {
    (decoder.map().map_err(dec)? == Some(expected))
        .then_some(())
        .ok_or(RecoveryRestoreCryptoError::InvalidRecovery)
}

fn read_fixed<const N: usize>(
    decoder: &mut Decoder<'_>,
) -> Result<[u8; N], RecoveryRestoreCryptoError> {
    decoder
        .bytes()
        .map_err(dec)?
        .try_into()
        .map_err(|_| RecoveryRestoreCryptoError::InvalidRecovery)
}

fn enc(_: minicbor::encode::Error<std::convert::Infallible>) -> RecoveryRestoreCryptoError {
    RecoveryRestoreCryptoError::InvalidRecovery
}

fn dec(_: minicbor::decode::Error) -> RecoveryRestoreCryptoError {
    RecoveryRestoreCryptoError::InvalidRecovery
}
