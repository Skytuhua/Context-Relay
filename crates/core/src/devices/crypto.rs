use std::{fmt, str::FromStr};

use context_relay_protocol::{
    AccountId, DeviceCertificateId, DeviceId, Ed25519PublicKeyBytes, Ed25519SignatureBytes,
    NativePlatform, PAIRING_SCHEMA_VERSION, PairingId, PairingRequestNonce, PairingRequestV1,
    Sha256Digest, WorkspaceId, X25519PublicKeyBytes, XChaChaNonce, encode_pairing_request_v1,
};
use minicbor::{Decoder, Encoder};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    crypto::{
        CertificateFieldsV1, CertificateIssuerV1, CryptoError, DeviceCertificateV1, DeviceKeys,
        WrappedKeyEnvelope, validate_x25519_public_key, verify_pairing_request_signature,
        wrap_secret,
    },
    sync::SyncScope,
};

pub const PAIRING_GRANT_SCHEMA_VERSION: u16 = 1;
pub const MAX_PAIRING_GRANT_BYTES: usize = 16 * 1024;
pub const PAIRING_APPROVED_PAYLOAD_SCHEMA_VERSION: u16 = 1;
pub const MAX_PAIRING_APPROVED_PAYLOAD_BYTES: usize = 32 * 1024;
pub const MAX_PAIRING_ISSUER_DEVICE_NAME_BYTES: usize = 256;

const PAIRING_FINGERPRINT_DOMAIN: &[u8] = b"context-relay/pairing-key-fingerprint/v1\0";
const ED25519_KEY_TAG: &[u8] = b"ed25519\0";
const X25519_KEY_TAG: &[u8] = b"x25519\0";
const PAIRING_GRANT_AAD_DOMAIN: &[u8] = b"context-relay/pairing-grant-aad/v1\0";
const PAIRING_SAFETY_DOMAIN: &[u8] = b"context-relay/pairing-safety/v1\0";
const KEY_BUNDLE_SCHEMA_VERSION: u16 = 1;
const MIN_WRAPPED_CIPHERTEXT_BYTES: usize = 16;

#[derive(Clone, Eq, PartialEq)]
pub struct SignedPairingRequest {
    request: PairingRequestV1,
    canonical_bytes: Vec<u8>,
    digest: Sha256Digest,
}

impl SignedPairingRequest {
    pub fn build(
        pairing_id: PairingId,
        device_id: DeviceId,
        device_name: impl Into<String>,
        platform: NativePlatform,
        keys: &DeviceKeys,
    ) -> Result<Self, CryptoError> {
        let mut nonce = [0_u8; 32];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| CryptoError::RandomnessUnavailable)?;
        let mut request = PairingRequestV1 {
            schema_version: PAIRING_SCHEMA_VERSION,
            pairing_id,
            request_nonce: PairingRequestNonce(nonce),
            device_id,
            device_name: device_name.into(),
            platform,
            signing_public_key: keys.signing_public_key(),
            wrapping_public_key: keys.wrapping_public_key(),
            signature: Ed25519SignatureBytes([0; 64]),
        };
        keys.sign_pairing_request(&mut request)?;
        verify_pairing_request(&request)
    }

    pub fn request(&self) -> &PairingRequestV1 {
        &self.request
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    pub fn fingerprint(&self) -> Sha256Digest {
        pairing_request_fingerprint(&self.request)
    }
}

impl fmt::Debug for SignedPairingRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedPairingRequest")
            .field("pairing_id", &self.request.pairing_id)
            .field("device_id", &self.request.device_id)
            .field("device_name", &self.request.device_name)
            .field("platform", &self.request.platform)
            .field("digest", &self.digest)
            .field("cryptographic_material", &"[REDACTED]")
            .finish()
    }
}

pub fn verify_pairing_request(
    request: &PairingRequestV1,
) -> Result<SignedPairingRequest, CryptoError> {
    verify_pairing_request_signature(request)?;
    let canonical_bytes =
        encode_pairing_request_v1(request).map_err(|_| CryptoError::InvalidProtocolValue)?;
    let digest = digest(&canonical_bytes);
    Ok(SignedPairingRequest {
        request: request.clone(),
        canonical_bytes,
        digest,
    })
}

pub fn pairing_request_fingerprint(request: &PairingRequestV1) -> Sha256Digest {
    let mut hash = Sha256::new();
    hash.update(PAIRING_FINGERPRINT_DOMAIN);
    hash.update(ED25519_KEY_TAG);
    hash.update(request.signing_public_key.0);
    hash.update(X25519_KEY_TAG);
    hash.update(request.wrapping_public_key.0);
    Sha256Digest(hash.finalize().into())
}

pub struct PairingKeyBundle {
    account_id: AccountId,
    workspace_id: WorkspaceId,
    control_epoch: u32,
    key_epoch: u32,
    workspace_root_key: Zeroizing<[u8; 32]>,
    active_epoch_key: Zeroizing<[u8; 32]>,
}

impl PairingKeyBundle {
    pub fn new(
        scope: SyncScope,
        control_epoch: u32,
        key_epoch: u32,
        workspace_root_key: [u8; 32],
        active_epoch_key: [u8; 32],
    ) -> Result<Self, CryptoError> {
        if control_epoch == 0 || key_epoch == 0 {
            return Err(CryptoError::InvalidProtocolValue);
        }
        Ok(Self {
            account_id: scope.account_id,
            workspace_id: scope.workspace_id,
            control_epoch,
            key_epoch,
            workspace_root_key: Zeroizing::new(workspace_root_key),
            active_epoch_key: Zeroizing::new(active_epoch_key),
        })
    }

    pub const fn account_id(&self) -> AccountId {
        self.account_id
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn control_epoch(&self) -> u32 {
        self.control_epoch
    }

    pub const fn key_epoch(&self) -> u32 {
        self.key_epoch
    }

    pub fn workspace_root_key(&self) -> &[u8; 32] {
        &self.workspace_root_key
    }

    pub fn active_epoch_key(&self) -> &[u8; 32] {
        &self.active_epoch_key
    }
}

impl fmt::Debug for PairingKeyBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingKeyBundle")
            .field("account_id", &self.account_id)
            .field("workspace_id", &self.workspace_id)
            .field("control_epoch", &self.control_epoch)
            .field("key_epoch", &self.key_epoch)
            .field("secret_keys", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingGrantApproval {
    pub request_digest: Sha256Digest,
    pub certificate_id: DeviceCertificateId,
    pub scope: SyncScope,
    pub control_epoch: u32,
    pub issuer_certificate: DeviceCertificateV1,
}

#[derive(Clone, Eq, PartialEq)]
pub struct PairingGrant {
    pub schema_version: u16,
    pub pairing_id: PairingId,
    pub request_digest: Sha256Digest,
    pub certificate_id: DeviceCertificateId,
    pub certificate: DeviceCertificateV1,
    pub key_epoch: u32,
    pub wrapped_key_bundle: WrappedKeyEnvelope,
}

impl fmt::Debug for PairingGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingGrant")
            .field("schema_version", &self.schema_version)
            .field("pairing_id", &self.pairing_id)
            .field("request_digest", &self.request_digest)
            .field("certificate_id", &self.certificate_id)
            .field("key_epoch", &self.key_epoch)
            .field("certificate_and_envelope", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PairingApprovedPayloadV1 {
    pub schema_version: u16,
    pub grant: PairingGrant,
    pub issuer_certificate_id: DeviceCertificateId,
    pub issuer_certificate: DeviceCertificateV1,
    pub issuer_device_name: String,
    pub issuer_platform: NativePlatform,
}

impl fmt::Debug for PairingApprovedPayloadV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingApprovedPayloadV1")
            .field("schema_version", &self.schema_version)
            .field("pairing_id", &self.grant.pairing_id)
            .field("request_digest", &self.grant.request_digest)
            .field("issuer_certificate_id", &self.issuer_certificate_id)
            .field("issuer_device_name", &self.issuer_device_name)
            .field("issuer_platform", &self.issuer_platform)
            .field("certificates_and_envelope", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct PairingSafetyNumber(String);

impl PairingSafetyNumber {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PairingSafetyNumber {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingSafetyNumber([REDACTED])")
    }
}

impl fmt::Display for PairingSafetyNumber {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct UnconfirmedPairingGrant {
    approved_payload: PairingApprovedPayloadV1,
    canonical_bytes: Vec<u8>,
    transcript_digest: Sha256Digest,
    safety_number: PairingSafetyNumber,
}

impl UnconfirmedPairingGrant {
    #[cfg(feature = "test-support")]
    pub fn approved_payload(&self) -> &PairingApprovedPayloadV1 {
        &self.approved_payload
    }

    #[cfg(not(feature = "test-support"))]
    pub(crate) fn approved_payload(&self) -> &PairingApprovedPayloadV1 {
        &self.approved_payload
    }

    #[cfg(feature = "test-support")]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    #[cfg(not(feature = "test-support"))]
    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    #[cfg(feature = "test-support")]
    pub const fn transcript_digest(&self) -> Sha256Digest {
        self.transcript_digest
    }

    #[cfg(not(feature = "test-support"))]
    pub(crate) const fn transcript_digest(&self) -> Sha256Digest {
        self.transcript_digest
    }

    #[cfg(feature = "test-support")]
    pub const fn safety_number(&self) -> &PairingSafetyNumber {
        &self.safety_number
    }

    #[cfg(not(feature = "test-support"))]
    pub(crate) const fn safety_number(&self) -> &PairingSafetyNumber {
        &self.safety_number
    }
}

impl fmt::Debug for UnconfirmedPairingGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnconfirmedPairingGrant")
            .field("pairing_id", &self.approved_payload.grant.pairing_id)
            .field(
                "request_digest",
                &self.approved_payload.grant.request_digest,
            )
            .field(
                "approved_payload_transcript_and_safety_number",
                &"[REDACTED]",
            )
            .finish()
    }
}

pub struct ConfirmedPairingApproval {
    unconfirmed: UnconfirmedPairingGrant,
    key_bundle: PairingKeyBundle,
}

impl ConfirmedPairingApproval {
    #[cfg(feature = "test-support")]
    pub fn approved_payload(&self) -> &PairingApprovedPayloadV1 {
        self.unconfirmed.approved_payload()
    }

    #[cfg(not(feature = "test-support"))]
    pub(crate) fn approved_payload(&self) -> &PairingApprovedPayloadV1 {
        self.unconfirmed.approved_payload()
    }

    #[cfg(feature = "test-support")]
    pub fn canonical_bytes(&self) -> &[u8] {
        self.unconfirmed.canonical_bytes()
    }

    #[cfg(not(feature = "test-support"))]
    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        self.unconfirmed.canonical_bytes()
    }

    #[cfg(feature = "test-support")]
    pub const fn transcript_digest(&self) -> Sha256Digest {
        self.unconfirmed.transcript_digest()
    }

    #[cfg(not(feature = "test-support"))]
    pub(crate) const fn transcript_digest(&self) -> Sha256Digest {
        self.unconfirmed.transcript_digest()
    }

    #[cfg(feature = "test-support")]
    pub const fn safety_number(&self) -> &PairingSafetyNumber {
        self.unconfirmed.safety_number()
    }

    #[cfg(feature = "test-support")]
    pub const fn key_bundle(&self) -> &PairingKeyBundle {
        &self.key_bundle
    }

    #[cfg(not(feature = "test-support"))]
    pub(crate) const fn key_bundle(&self) -> &PairingKeyBundle {
        &self.key_bundle
    }

    pub(crate) fn into_key_bundle(self) -> PairingKeyBundle {
        self.key_bundle
    }
}

impl fmt::Debug for ConfirmedPairingApproval {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfirmedPairingApproval")
            .field("pairing_id", &self.approved_payload().grant.pairing_id)
            .field(
                "request_digest",
                &self.approved_payload().grant.request_digest,
            )
            .field("approved_payload_transcript_safety_and_keys", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingConfirmationError {
    SafetyNumberMismatch,
    Crypto(CryptoError),
}

impl fmt::Display for PairingConfirmationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SafetyNumberMismatch => "pairing safety number mismatch",
            Self::Crypto(_) => "pairing approval authentication failed",
        })
    }
}

impl std::error::Error for PairingConfirmationError {}

pub fn build_pairing_grant(
    signed_request: &SignedPairingRequest,
    approval: &PairingGrantApproval,
    issuer_keys: &DeviceKeys,
    bundle: &PairingKeyBundle,
) -> Result<PairingGrant, CryptoError> {
    require_exact_signed_request(signed_request)?;
    if approval.request_digest != signed_request.digest
        || approval.scope.account_id != bundle.account_id
        || approval.scope.workspace_id != bundle.workspace_id
        || approval.control_epoch != bundle.control_epoch
        || approval.control_epoch == 0
        || approval.issuer_certificate.account_id != approval.scope.account_id
        || approval.issuer_certificate.workspace_id != approval.scope.workspace_id
        || approval.issuer_certificate.control_epoch != approval.control_epoch
        || approval.issuer_certificate.signing_public_key != issuer_keys.signing_public_key()
    {
        return Err(CryptoError::AuthenticationFailed);
    }
    validate_genesis_issuer_certificate(&approval.issuer_certificate)?;

    let request = signed_request.request();
    if approval.issuer_certificate.device_id == request.device_id {
        return Err(CryptoError::AuthenticationFailed);
    }
    let certificate = DeviceCertificateV1::issue_by_device(
        CertificateFieldsV1 {
            account_id: approval.scope.account_id,
            workspace_id: approval.scope.workspace_id,
            control_epoch: approval.control_epoch,
            request_nonce: request.request_nonce,
            device_id: request.device_id,
            signing_public_key: request.signing_public_key,
            wrapping_public_key: request.wrapping_public_key,
        },
        approval.issuer_certificate.device_id,
        issuer_keys,
    )?;
    let certificate_digest = certificate_digest(&certificate)?;
    let aad = grant_aad(
        request.pairing_id,
        signed_request.digest,
        approval.certificate_id,
        certificate_digest,
        approval.scope,
        approval.control_epoch,
        bundle.key_epoch,
    );
    let mut plaintext = encode_pairing_key_bundle_v1(bundle)?;
    let wrapped = wrap_secret(request.wrapping_public_key, &plaintext, &aad);
    plaintext.zeroize();
    let wrapped_key_bundle = wrapped?;

    Ok(PairingGrant {
        schema_version: PAIRING_GRANT_SCHEMA_VERSION,
        pairing_id: request.pairing_id,
        request_digest: signed_request.digest,
        certificate_id: approval.certificate_id,
        certificate,
        key_epoch: bundle.key_epoch,
        wrapped_key_bundle,
    })
}

pub fn build_pairing_approved_payload_v1(
    signed_request: &SignedPairingRequest,
    grant: PairingGrant,
    issuer_certificate_id: DeviceCertificateId,
    issuer_certificate: DeviceCertificateV1,
    issuer_device_name: impl Into<String>,
    issuer_platform: NativePlatform,
) -> Result<PairingApprovedPayloadV1, CryptoError> {
    let payload = PairingApprovedPayloadV1 {
        schema_version: PAIRING_APPROVED_PAYLOAD_SCHEMA_VERSION,
        grant,
        issuer_certificate_id,
        issuer_certificate,
        issuer_device_name: issuer_device_name.into(),
        issuer_platform,
    };
    validate_approved_payload_bindings(&payload, signed_request)?;
    encode_pairing_approved_payload_v1(&payload)?;
    Ok(payload)
}

#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn inspect_pairing_approval(
    canonical_approved_payload: &[u8],
    signed_request: &SignedPairingRequest,
) -> Result<UnconfirmedPairingGrant, CryptoError> {
    inspect_pairing_approval_inner(canonical_approved_payload, signed_request)
}

#[cfg(not(feature = "test-support"))]
pub(crate) fn inspect_pairing_approval(
    canonical_approved_payload: &[u8],
    signed_request: &SignedPairingRequest,
) -> Result<UnconfirmedPairingGrant, CryptoError> {
    inspect_pairing_approval_inner(canonical_approved_payload, signed_request)
}

fn inspect_pairing_approval_inner(
    canonical_approved_payload: &[u8],
    signed_request: &SignedPairingRequest,
) -> Result<UnconfirmedPairingGrant, CryptoError> {
    require_exact_signed_request(signed_request)?;
    let approved_payload = decode_pairing_approved_payload_v1(canonical_approved_payload)?;
    validate_approved_payload_bindings(&approved_payload, signed_request)?;
    let transcript_digest = pairing_approval_transcript_digest(
        signed_request.request().pairing_id,
        signed_request.digest,
        canonical_approved_payload,
    );
    let safety_number = PairingSafetyNumber(format_safety_number(transcript_digest));
    Ok(UnconfirmedPairingGrant {
        approved_payload,
        canonical_bytes: canonical_approved_payload.to_vec(),
        transcript_digest,
        safety_number,
    })
}

#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn confirm_and_open_pairing_approval(
    unconfirmed: &UnconfirmedPairingGrant,
    entered_safety_number: &str,
    signed_request: &SignedPairingRequest,
    joiner_keys: &DeviceKeys,
) -> Result<ConfirmedPairingApproval, PairingConfirmationError> {
    confirm_and_open_pairing_approval_inner(
        unconfirmed,
        entered_safety_number,
        signed_request,
        joiner_keys,
    )
}

#[cfg(not(feature = "test-support"))]
pub(crate) fn confirm_and_open_pairing_approval(
    unconfirmed: &UnconfirmedPairingGrant,
    entered_safety_number: &str,
    signed_request: &SignedPairingRequest,
    joiner_keys: &DeviceKeys,
) -> Result<ConfirmedPairingApproval, PairingConfirmationError> {
    confirm_and_open_pairing_approval_inner(
        unconfirmed,
        entered_safety_number,
        signed_request,
        joiner_keys,
    )
}

fn confirm_and_open_pairing_approval_inner(
    unconfirmed: &UnconfirmedPairingGrant,
    entered_safety_number: &str,
    signed_request: &SignedPairingRequest,
    joiner_keys: &DeviceKeys,
) -> Result<ConfirmedPairingApproval, PairingConfirmationError> {
    let reverified = inspect_pairing_approval_inner(unconfirmed.canonical_bytes(), signed_request)
        .map_err(PairingConfirmationError::Crypto)?;
    if reverified.transcript_digest != unconfirmed.transcript_digest
        || reverified.approved_payload != unconfirmed.approved_payload
        || !exact_safety_number_matches(entered_safety_number, reverified.safety_number.as_str())
    {
        return Err(PairingConfirmationError::SafetyNumberMismatch);
    }
    let key_bundle = verify_and_open_pairing_grant(
        &reverified.approved_payload.grant,
        signed_request,
        &reverified.approved_payload.issuer_certificate,
        joiner_keys,
    )
    .map_err(PairingConfirmationError::Crypto)?;
    Ok(ConfirmedPairingApproval {
        unconfirmed: reverified,
        key_bundle,
    })
}

fn verify_and_open_pairing_grant(
    grant: &PairingGrant,
    signed_request: &SignedPairingRequest,
    issuer_certificate: &DeviceCertificateV1,
    joiner_keys: &DeviceKeys,
) -> Result<PairingKeyBundle, CryptoError> {
    require_exact_signed_request(signed_request)?;
    let request = signed_request.request();
    if grant.schema_version != PAIRING_GRANT_SCHEMA_VERSION
        || grant.pairing_id != request.pairing_id
        || grant.request_digest != signed_request.digest
        || joiner_keys.signing_public_key() != request.signing_public_key
        || joiner_keys.wrapping_public_key() != request.wrapping_public_key
    {
        return Err(CryptoError::AuthenticationFailed);
    }

    let certificate = &grant.certificate;
    if issuer_certificate.account_id != certificate.account_id
        || issuer_certificate.workspace_id != certificate.workspace_id
        || issuer_certificate.control_epoch != certificate.control_epoch
        || certificate.control_epoch == 0
        || grant.key_epoch == 0
        || certificate.request_nonce != request.request_nonce
        || certificate.device_id != request.device_id
        || certificate.signing_public_key != request.signing_public_key
        || certificate.wrapping_public_key != request.wrapping_public_key
    {
        return Err(CryptoError::AuthenticationFailed);
    }
    validate_x25519_public_key(issuer_certificate.wrapping_public_key)?;
    let issuer = CertificateIssuerV1::Device {
        device_id: issuer_certificate.device_id,
        signing_public_key: issuer_certificate.signing_public_key,
    };
    certificate.verify_issued_by(&issuer)?;

    let scope = SyncScope {
        account_id: certificate.account_id,
        workspace_id: certificate.workspace_id,
    };
    let certificate_digest = certificate_digest(certificate)?;
    let aad = grant_aad(
        grant.pairing_id,
        grant.request_digest,
        grant.certificate_id,
        certificate_digest,
        scope,
        certificate.control_epoch,
        grant.key_epoch,
    );
    let plaintext = joiner_keys.unwrap_secret(&grant.wrapped_key_bundle, &aad)?;
    let bundle = decode_pairing_key_bundle_v1(plaintext.expose())?;
    if bundle.account_id != scope.account_id
        || bundle.workspace_id != scope.workspace_id
        || bundle.control_epoch != certificate.control_epoch
        || bundle.key_epoch != grant.key_epoch
    {
        return Err(CryptoError::AuthenticationFailed);
    }
    Ok(bundle)
}

pub fn encode_pairing_grant_v1(grant: &PairingGrant) -> Result<Vec<u8>, CryptoError> {
    validate_grant_shape(grant)?;
    let mut encoder = Encoder::new(Vec::new());
    encode_pairing_grant(&mut encoder, grant)?;
    let output = encoder.into_writer();
    if output.len() > MAX_PAIRING_GRANT_BYTES {
        return Err(CryptoError::InvalidProtocolValue);
    }
    Ok(output)
}

pub fn decode_pairing_grant_v1(input: &[u8]) -> Result<PairingGrant, CryptoError> {
    if input.len() > MAX_PAIRING_GRANT_BYTES {
        return Err(CryptoError::InvalidProtocolValue);
    }
    let mut decoder = Decoder::new(input);
    let grant = decode_pairing_grant(&mut decoder)?;
    if decoder.position() != input.len() {
        return Err(CryptoError::InvalidProtocolValue);
    }
    validate_grant_shape(&grant)?;
    if encode_pairing_grant_v1(&grant)?.as_slice() != input {
        return Err(CryptoError::InvalidProtocolValue);
    }
    Ok(grant)
}

pub fn encode_pairing_approved_payload_v1(
    payload: &PairingApprovedPayloadV1,
) -> Result<Vec<u8>, CryptoError> {
    validate_approved_payload_shape(payload)?;
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(6).map_err(enc)?;
    key(&mut encoder, 0)?;
    encoder.u16(payload.schema_version).map_err(enc)?;
    key(&mut encoder, 1)?;
    encode_pairing_grant(&mut encoder, &payload.grant)?;
    key(&mut encoder, 2)?;
    bytes(&mut encoder, payload.issuer_certificate_id.as_bytes())?;
    key(&mut encoder, 3)?;
    encode_certificate_v1(&mut encoder, &payload.issuer_certificate)?;
    key(&mut encoder, 4)?;
    encoder.str(&payload.issuer_device_name).map_err(enc)?;
    key(&mut encoder, 5)?;
    encoder
        .u8(encode_native_platform(payload.issuer_platform))
        .map_err(enc)?;
    let output = encoder.into_writer();
    if output.len() > MAX_PAIRING_APPROVED_PAYLOAD_BYTES {
        return Err(CryptoError::InvalidProtocolValue);
    }
    Ok(output)
}

pub fn decode_pairing_approved_payload_v1(
    input: &[u8],
) -> Result<PairingApprovedPayloadV1, CryptoError> {
    if input.len() > MAX_PAIRING_APPROVED_PAYLOAD_BYTES {
        return Err(CryptoError::InvalidProtocolValue);
    }
    let mut decoder = Decoder::new(input);
    require_map(&mut decoder, 6)?;
    expect_key(&mut decoder, 0)?;
    let schema_version = decoder.u16().map_err(dec)?;
    expect_key(&mut decoder, 1)?;
    let grant = decode_pairing_grant(&mut decoder)?;
    expect_key(&mut decoder, 2)?;
    let issuer_certificate_id = decode_id(read_fixed::<16>(&mut decoder)?)?;
    expect_key(&mut decoder, 3)?;
    let issuer_certificate = decode_certificate_v1(&mut decoder)?;
    expect_key(&mut decoder, 4)?;
    let issuer_device_name = decoder.str().map_err(dec)?.to_owned();
    expect_key(&mut decoder, 5)?;
    let issuer_platform = decode_native_platform(decoder.u8().map_err(dec)?)?;
    if decoder.position() != input.len() {
        return Err(CryptoError::InvalidProtocolValue);
    }
    let payload = PairingApprovedPayloadV1 {
        schema_version,
        grant,
        issuer_certificate_id,
        issuer_certificate,
        issuer_device_name,
        issuer_platform,
    };
    validate_approved_payload_shape(&payload)?;
    if encode_pairing_approved_payload_v1(&payload)?.as_slice() != input {
        return Err(CryptoError::InvalidProtocolValue);
    }
    Ok(payload)
}

fn encode_pairing_grant(
    encoder: &mut Encoder<Vec<u8>>,
    grant: &PairingGrant,
) -> Result<(), CryptoError> {
    encoder.map(7).map_err(enc)?;
    key(encoder, 0)?;
    encoder.u16(grant.schema_version).map_err(enc)?;
    key(encoder, 1)?;
    bytes(encoder, grant.pairing_id.as_bytes())?;
    key(encoder, 2)?;
    bytes(encoder, &grant.request_digest.0)?;
    key(encoder, 3)?;
    bytes(encoder, grant.certificate_id.as_bytes())?;
    key(encoder, 4)?;
    encode_certificate_v1(encoder, &grant.certificate)?;
    key(encoder, 5)?;
    encoder.u32(grant.key_epoch).map_err(enc)?;
    key(encoder, 6)?;
    encode_wrapped_envelope(encoder, &grant.wrapped_key_bundle)
}

fn decode_pairing_grant(decoder: &mut Decoder<'_>) -> Result<PairingGrant, CryptoError> {
    require_map(decoder, 7)?;
    expect_key(decoder, 0)?;
    let schema_version = decoder.u16().map_err(dec)?;
    expect_key(decoder, 1)?;
    let pairing_id = decode_id(read_fixed::<16>(decoder)?)?;
    expect_key(decoder, 2)?;
    let request_digest = Sha256Digest(read_fixed::<32>(decoder)?);
    expect_key(decoder, 3)?;
    let certificate_id = decode_id(read_fixed::<16>(decoder)?)?;
    expect_key(decoder, 4)?;
    let certificate = decode_certificate_v1(decoder)?;
    expect_key(decoder, 5)?;
    let key_epoch = decoder.u32().map_err(dec)?;
    expect_key(decoder, 6)?;
    let wrapped_key_bundle = decode_wrapped_envelope(decoder)?;
    let grant = PairingGrant {
        schema_version,
        pairing_id,
        request_digest,
        certificate_id,
        certificate,
        key_epoch,
        wrapped_key_bundle,
    };
    validate_grant_shape(&grant)?;
    Ok(grant)
}

pub(crate) fn encode_device_certificate_v1(
    certificate: &DeviceCertificateV1,
) -> Result<Vec<u8>, CryptoError> {
    let mut encoder = Encoder::new(Vec::new());
    encode_certificate_v1(&mut encoder, certificate)?;
    Ok(encoder.into_writer())
}

pub(crate) fn decode_device_certificate_v1(
    input: &[u8],
) -> Result<DeviceCertificateV1, CryptoError> {
    let mut decoder = Decoder::new(input);
    let certificate = decode_certificate_v1(&mut decoder)?;
    if decoder.position() != input.len()
        || encode_device_certificate_v1(&certificate)?.as_slice() != input
    {
        return Err(CryptoError::InvalidProtocolValue);
    }
    Ok(certificate)
}

fn require_exact_signed_request(request: &SignedPairingRequest) -> Result<(), CryptoError> {
    let verified = verify_pairing_request(request.request())?;
    if verified.digest != request.digest || verified.canonical_bytes != request.canonical_bytes {
        return Err(CryptoError::AuthenticationFailed);
    }
    Ok(())
}

fn validate_grant_shape(grant: &PairingGrant) -> Result<(), CryptoError> {
    if grant.schema_version != PAIRING_GRANT_SCHEMA_VERSION
        || grant.key_epoch == 0
        || grant.certificate.control_epoch == 0
        || grant.wrapped_key_bundle.ciphertext.len() < MIN_WRAPPED_CIPHERTEXT_BYTES
        || grant.wrapped_key_bundle.ciphertext.len() > MAX_PAIRING_GRANT_BYTES
    {
        return Err(CryptoError::InvalidProtocolValue);
    }
    Ok(())
}

fn validate_approved_payload_shape(payload: &PairingApprovedPayloadV1) -> Result<(), CryptoError> {
    if payload.schema_version != PAIRING_APPROVED_PAYLOAD_SCHEMA_VERSION
        || payload.issuer_device_name.trim().is_empty()
        || payload.issuer_device_name.len() > MAX_PAIRING_ISSUER_DEVICE_NAME_BYTES
    {
        return Err(CryptoError::InvalidProtocolValue);
    }
    validate_grant_shape(&payload.grant)
}

fn validate_genesis_issuer_certificate(
    certificate: &DeviceCertificateV1,
) -> Result<(), CryptoError> {
    if certificate.control_epoch == 0 {
        return Err(CryptoError::AuthenticationFailed);
    }
    let CertificateIssuerV1::RecoveryRoot(recovery_public_key) = &certificate.issuer else {
        return Err(CryptoError::AuthenticationFailed);
    };
    certificate.verify_genesis(*recovery_public_key)?;
    validate_x25519_public_key(certificate.wrapping_public_key)
}

fn validate_approved_payload_bindings(
    payload: &PairingApprovedPayloadV1,
    signed_request: &SignedPairingRequest,
) -> Result<(), CryptoError> {
    validate_approved_payload_shape(payload)?;
    require_exact_signed_request(signed_request)?;
    validate_genesis_issuer_certificate(&payload.issuer_certificate)?;

    let grant = &payload.grant;
    let request = signed_request.request();
    let child = &grant.certificate;
    let issuer = &payload.issuer_certificate;
    if payload.issuer_certificate_id == grant.certificate_id
        || grant.pairing_id != request.pairing_id
        || grant.request_digest != signed_request.digest
        || issuer.device_id == request.device_id
        || issuer.account_id != child.account_id
        || issuer.workspace_id != child.workspace_id
        || issuer.control_epoch != child.control_epoch
        || child.request_nonce != request.request_nonce
        || child.device_id != request.device_id
        || child.signing_public_key != request.signing_public_key
        || child.wrapping_public_key != request.wrapping_public_key
    {
        return Err(CryptoError::AuthenticationFailed);
    }
    let expected_child_issuer = CertificateIssuerV1::Device {
        device_id: issuer.device_id,
        signing_public_key: issuer.signing_public_key,
    };
    child.verify_issued_by(&expected_child_issuer)
}

fn pairing_approval_transcript_digest(
    pairing_id: PairingId,
    request_digest: Sha256Digest,
    canonical_approved_payload: &[u8],
) -> Sha256Digest {
    let approved_payload_digest = Sha256::digest(canonical_approved_payload);
    let mut hash = Sha256::new();
    hash.update(PAIRING_SAFETY_DOMAIN);
    hash.update(pairing_id.as_bytes());
    hash.update(request_digest.0);
    hash.update(approved_payload_digest);
    Sha256Digest(hash.finalize().into())
}

fn format_safety_number(transcript_digest: Sha256Digest) -> String {
    let mut output = String::with_capacity(24);
    for (index, group) in transcript_digest.0[..10].chunks_exact(2).enumerate() {
        if index != 0 {
            output.push('-');
        }
        output.push_str(&format!("{:02X}{:02X}", group[0], group[1]));
    }
    output
}

fn exact_safety_number_matches(entered: &str, expected: &str) -> bool {
    let entered = entered.as_bytes();
    let expected = expected.as_bytes();
    let mut difference = entered.len() ^ expected.len();
    for (index, expected_byte) in expected.iter().copied().enumerate() {
        difference |= usize::from(entered.get(index).copied().unwrap_or_default() ^ expected_byte);
    }
    difference == 0
}

pub(crate) const fn encode_native_platform(platform: NativePlatform) -> u8 {
    match platform {
        NativePlatform::Windows => 0,
        NativePlatform::Macos => 1,
    }
}

pub(crate) const fn decode_native_platform(value: u8) -> Result<NativePlatform, CryptoError> {
    match value {
        0 => Ok(NativePlatform::Windows),
        1 => Ok(NativePlatform::Macos),
        _ => Err(CryptoError::InvalidProtocolValue),
    }
}

pub(crate) fn certificate_digest(
    certificate: &DeviceCertificateV1,
) -> Result<Sha256Digest, CryptoError> {
    let mut encoder = Encoder::new(Vec::new());
    encode_certificate_v1(&mut encoder, certificate)?;
    Ok(digest(&encoder.into_writer()))
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest(Sha256::digest(bytes).into())
}

fn grant_aad(
    pairing_id: PairingId,
    request_digest: Sha256Digest,
    certificate_id: DeviceCertificateId,
    certificate_digest: Sha256Digest,
    scope: SyncScope,
    control_epoch: u32,
    key_epoch: u32,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(PAIRING_GRANT_AAD_DOMAIN.len() + 152);
    aad.extend_from_slice(PAIRING_GRANT_AAD_DOMAIN);
    aad.extend_from_slice(pairing_id.as_bytes());
    aad.extend_from_slice(&request_digest.0);
    aad.extend_from_slice(certificate_id.as_bytes());
    aad.extend_from_slice(&certificate_digest.0);
    aad.extend_from_slice(scope.account_id.as_bytes());
    aad.extend_from_slice(scope.workspace_id.as_bytes());
    aad.extend_from_slice(&control_epoch.to_be_bytes());
    aad.extend_from_slice(&key_epoch.to_be_bytes());
    aad
}

pub(crate) fn encode_pairing_key_bundle_v1(
    bundle: &PairingKeyBundle,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    // The fixed v1 bundle is at most 123 bytes. Preallocating its complete buffer prevents a
    // reallocation from leaving a stale plaintext copy before the returned allocation is zeroized.
    let mut encoder = Encoder::new(Vec::with_capacity(128));
    encoder.map(7).map_err(enc)?;
    key(&mut encoder, 0)?;
    encoder.u16(KEY_BUNDLE_SCHEMA_VERSION).map_err(enc)?;
    key(&mut encoder, 1)?;
    bytes(&mut encoder, bundle.account_id.as_bytes())?;
    key(&mut encoder, 2)?;
    bytes(&mut encoder, bundle.workspace_id.as_bytes())?;
    key(&mut encoder, 3)?;
    encoder.u32(bundle.control_epoch).map_err(enc)?;
    key(&mut encoder, 4)?;
    encoder.u32(bundle.key_epoch).map_err(enc)?;
    key(&mut encoder, 5)?;
    bytes(&mut encoder, &bundle.workspace_root_key[..])?;
    key(&mut encoder, 6)?;
    bytes(&mut encoder, &bundle.active_epoch_key[..])?;
    Ok(Zeroizing::new(encoder.into_writer()))
}

pub(crate) fn decode_pairing_key_bundle_v1(input: &[u8]) -> Result<PairingKeyBundle, CryptoError> {
    let mut decoder = Decoder::new(input);
    require_map(&mut decoder, 7)?;
    expect_key(&mut decoder, 0)?;
    if decoder.u16().map_err(dec)? != KEY_BUNDLE_SCHEMA_VERSION {
        return Err(CryptoError::InvalidProtocolValue);
    }
    expect_key(&mut decoder, 1)?;
    let account_id = decode_id(read_fixed::<16>(&mut decoder)?)?;
    expect_key(&mut decoder, 2)?;
    let workspace_id = decode_id(read_fixed::<16>(&mut decoder)?)?;
    expect_key(&mut decoder, 3)?;
    let control_epoch = decoder.u32().map_err(dec)?;
    expect_key(&mut decoder, 4)?;
    let key_epoch = decoder.u32().map_err(dec)?;
    expect_key(&mut decoder, 5)?;
    let workspace_root_key = read_fixed::<32>(&mut decoder)?;
    expect_key(&mut decoder, 6)?;
    let active_epoch_key = read_fixed::<32>(&mut decoder)?;
    if decoder.position() != input.len() {
        return Err(CryptoError::InvalidProtocolValue);
    }
    let bundle = PairingKeyBundle::new(
        SyncScope {
            account_id,
            workspace_id,
        },
        control_epoch,
        key_epoch,
        workspace_root_key,
        active_epoch_key,
    )?;
    let canonical = encode_pairing_key_bundle_v1(&bundle)?;
    if canonical.as_slice() != input {
        return Err(CryptoError::InvalidProtocolValue);
    }
    Ok(bundle)
}

pub(crate) fn encode_certificate_v1(
    encoder: &mut Encoder<Vec<u8>>,
    certificate: &DeviceCertificateV1,
) -> Result<(), CryptoError> {
    encoder.map(9).map_err(enc)?;
    key(encoder, 0)?;
    encode_issuer(encoder, &certificate.issuer)?;
    key(encoder, 1)?;
    bytes(encoder, certificate.account_id.as_bytes())?;
    key(encoder, 2)?;
    bytes(encoder, certificate.workspace_id.as_bytes())?;
    key(encoder, 3)?;
    encoder.u32(certificate.control_epoch).map_err(enc)?;
    key(encoder, 4)?;
    bytes(encoder, &certificate.request_nonce.0)?;
    key(encoder, 5)?;
    bytes(encoder, certificate.device_id.as_bytes())?;
    key(encoder, 6)?;
    bytes(encoder, &certificate.signing_public_key.0)?;
    key(encoder, 7)?;
    bytes(encoder, &certificate.wrapping_public_key.0)?;
    key(encoder, 8)?;
    bytes(encoder, &certificate.signature.0)
}

pub(crate) fn decode_certificate_v1(
    decoder: &mut Decoder<'_>,
) -> Result<DeviceCertificateV1, CryptoError> {
    require_map(decoder, 9)?;
    expect_key(decoder, 0)?;
    let issuer = decode_issuer(decoder)?;
    expect_key(decoder, 1)?;
    let account_id = decode_id(read_fixed::<16>(decoder)?)?;
    expect_key(decoder, 2)?;
    let workspace_id = decode_id(read_fixed::<16>(decoder)?)?;
    expect_key(decoder, 3)?;
    let control_epoch = decoder.u32().map_err(dec)?;
    expect_key(decoder, 4)?;
    let request_nonce = PairingRequestNonce(read_fixed::<32>(decoder)?);
    expect_key(decoder, 5)?;
    let device_id = decode_id(read_fixed::<16>(decoder)?)?;
    expect_key(decoder, 6)?;
    let signing_public_key = Ed25519PublicKeyBytes(read_fixed::<32>(decoder)?);
    expect_key(decoder, 7)?;
    let wrapping_public_key = X25519PublicKeyBytes(read_fixed::<32>(decoder)?);
    expect_key(decoder, 8)?;
    let signature = Ed25519SignatureBytes(read_fixed::<64>(decoder)?);
    Ok(DeviceCertificateV1 {
        issuer,
        account_id,
        workspace_id,
        control_epoch,
        request_nonce,
        device_id,
        signing_public_key,
        wrapping_public_key,
        signature,
    })
}

fn encode_issuer(
    encoder: &mut Encoder<Vec<u8>>,
    issuer: &CertificateIssuerV1,
) -> Result<(), CryptoError> {
    match issuer {
        CertificateIssuerV1::RecoveryRoot(key_bytes) => {
            encoder.map(2).map_err(enc)?;
            key(encoder, 0)?;
            encoder.u8(0).map_err(enc)?;
            key(encoder, 1)?;
            bytes(encoder, &key_bytes.0)
        }
        CertificateIssuerV1::Device {
            device_id,
            signing_public_key,
        } => {
            encoder.map(3).map_err(enc)?;
            key(encoder, 0)?;
            encoder.u8(1).map_err(enc)?;
            key(encoder, 1)?;
            bytes(encoder, device_id.as_bytes())?;
            key(encoder, 2)?;
            bytes(encoder, &signing_public_key.0)
        }
    }
}

fn decode_issuer(decoder: &mut Decoder<'_>) -> Result<CertificateIssuerV1, CryptoError> {
    let size = decoder
        .map()
        .map_err(dec)?
        .ok_or(CryptoError::InvalidProtocolValue)?;
    expect_key(decoder, 0)?;
    match decoder.u8().map_err(dec)? {
        0 if size == 2 => {
            expect_key(decoder, 1)?;
            Ok(CertificateIssuerV1::RecoveryRoot(Ed25519PublicKeyBytes(
                read_fixed::<32>(decoder)?,
            )))
        }
        1 if size == 3 => {
            expect_key(decoder, 1)?;
            let device_id = decode_id(read_fixed::<16>(decoder)?)?;
            expect_key(decoder, 2)?;
            let signing_public_key = Ed25519PublicKeyBytes(read_fixed::<32>(decoder)?);
            Ok(CertificateIssuerV1::Device {
                device_id,
                signing_public_key,
            })
        }
        _ => Err(CryptoError::InvalidProtocolValue),
    }
}

pub(crate) fn encode_wrapped_envelope(
    encoder: &mut Encoder<Vec<u8>>,
    envelope: &WrappedKeyEnvelope,
) -> Result<(), CryptoError> {
    encoder.map(3).map_err(enc)?;
    key(encoder, 0)?;
    bytes(encoder, &envelope.ephemeral_public_key.0)?;
    key(encoder, 1)?;
    bytes(encoder, &envelope.nonce.0)?;
    key(encoder, 2)?;
    bytes(encoder, &envelope.ciphertext)
}

pub(crate) fn decode_wrapped_envelope(
    decoder: &mut Decoder<'_>,
) -> Result<WrappedKeyEnvelope, CryptoError> {
    decode_wrapped_envelope_with_limit(decoder, MAX_PAIRING_GRANT_BYTES)
}

pub(crate) fn decode_wrapped_envelope_with_limit(
    decoder: &mut Decoder<'_>,
    max_ciphertext_bytes: usize,
) -> Result<WrappedKeyEnvelope, CryptoError> {
    require_map(decoder, 3)?;
    expect_key(decoder, 0)?;
    let ephemeral_public_key = X25519PublicKeyBytes(read_fixed::<32>(decoder)?);
    expect_key(decoder, 1)?;
    let nonce = XChaChaNonce(read_fixed::<24>(decoder)?);
    expect_key(decoder, 2)?;
    let ciphertext = decoder.bytes().map_err(dec)?;
    if ciphertext.len() < MIN_WRAPPED_CIPHERTEXT_BYTES || ciphertext.len() > max_ciphertext_bytes {
        return Err(CryptoError::InvalidProtocolValue);
    }
    let ciphertext = ciphertext.to_vec();
    Ok(WrappedKeyEnvelope {
        ephemeral_public_key,
        nonce,
        ciphertext,
    })
}

fn decode_id<T: FromStr>(bytes: [u8; 16]) -> Result<T, CryptoError> {
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
    value.parse().map_err(|_| CryptoError::InvalidProtocolValue)
}

fn key(encoder: &mut Encoder<Vec<u8>>, value: u8) -> Result<(), CryptoError> {
    encoder.u8(value).map(|_| ()).map_err(enc)
}

fn bytes(encoder: &mut Encoder<Vec<u8>>, value: &[u8]) -> Result<(), CryptoError> {
    encoder.bytes(value).map(|_| ()).map_err(enc)
}

fn expect_key(decoder: &mut Decoder<'_>, expected: u8) -> Result<(), CryptoError> {
    (decoder.u8().map_err(dec)? == expected)
        .then_some(())
        .ok_or(CryptoError::InvalidProtocolValue)
}

fn require_map(decoder: &mut Decoder<'_>, expected: u64) -> Result<(), CryptoError> {
    (decoder.map().map_err(dec)? == Some(expected))
        .then_some(())
        .ok_or(CryptoError::InvalidProtocolValue)
}

fn read_fixed<const N: usize>(decoder: &mut Decoder<'_>) -> Result<[u8; N], CryptoError> {
    decoder
        .bytes()
        .map_err(dec)?
        .try_into()
        .map_err(|_| CryptoError::InvalidProtocolValue)
}

fn enc(_: minicbor::encode::Error<std::convert::Infallible>) -> CryptoError {
    CryptoError::InvalidProtocolValue
}

fn dec(_: minicbor::decode::Error) -> CryptoError {
    CryptoError::InvalidProtocolValue
}
