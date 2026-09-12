//! Parent-bound pairing primitives. Caller must authenticate complete history and admission IDs.
use super::*;
use crate::devices::revocation_crypto::{
    RevocationControlState, RevocationTransitionV1, VerifiedRevocationControl,
};

#[derive(Clone, Eq, PartialEq)]
pub struct PairingGrantV2 {
    pub schema_version: u16,
    pub pairing_id: PairingId,
    pub request_digest: Sha256Digest,
    pub certificate_id: DeviceCertificateId,
    pub certificate: DeviceCertificateV1,
    pub key_epoch: u32,
    pub wrapped_key_bundle: WrappedKeyEnvelope,
}

impl fmt::Debug for PairingGrantV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingGrantV2")
            .field("schema_version", &self.schema_version)
            .field("pairing_id", &self.pairing_id)
            .field("request_digest", &self.request_digest)
            .field("certificate_id", &self.certificate_id)
            .field("key_epoch", &self.key_epoch)
            .field("certificate_and_envelope", &"[REDACTED]")
            .finish()
    }
}

pub fn encode_pairing_grant_v2(grant: &PairingGrantV2) -> Result<Vec<u8>, CryptoError> {
    validate_grant_v2_shape(grant)?;
    let mut encoder = Encoder::new(Vec::new());
    encode_pairing_grant(&mut encoder, grant)?;
    let output = encoder.into_writer();
    if output.len() > MAX_PAIRING_GRANT_BYTES {
        return Err(CryptoError::InvalidProtocolValue);
    }
    Ok(output)
}

pub fn decode_pairing_grant_v2(input: &[u8]) -> Result<PairingGrantV2, CryptoError> {
    if input.len() > MAX_PAIRING_GRANT_BYTES {
        return Err(CryptoError::InvalidProtocolValue);
    }
    let mut decoder = Decoder::new(input);
    let grant = decode_pairing_grant(&mut decoder)?;
    if decoder.position() != input.len() {
        return Err(CryptoError::InvalidProtocolValue);
    }
    validate_grant_v2_shape(&grant)?;
    if encode_pairing_grant_v2(&grant)?.as_slice() != input {
        return Err(CryptoError::InvalidProtocolValue);
    }
    Ok(grant)
}

fn encode_pairing_grant(
    encoder: &mut Encoder<Vec<u8>>,
    grant: &PairingGrantV2,
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

fn decode_pairing_grant(decoder: &mut Decoder<'_>) -> Result<PairingGrantV2, CryptoError> {
    require_map(decoder, 7)?;
    expect_key(decoder, 0)?;
    let schema_version = decoder.u16().map_err(dec)?;
    if schema_version != 2 {
        return Err(CryptoError::InvalidProtocolValue);
    }
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
    let grant = PairingGrantV2 {
        schema_version,
        pairing_id,
        request_digest,
        certificate_id,
        certificate,
        key_epoch,
        wrapped_key_bundle,
    };
    validate_grant_v2_shape(&grant)?;
    Ok(grant)
}

#[derive(Clone, Eq, PartialEq)]
pub struct PairingApprovedPayloadV2 {
    pub schema_version: u16,
    pub grant: PairingGrantV2,
    pub issuer_certificate_id: DeviceCertificateId,
    pub issuer_certificate: DeviceCertificateV1,
    pub issuer_device_name: String,
    pub issuer_platform: NativePlatform,
    pub previous_state_sha256: Sha256Digest,
    pub enrollment_record_sha256: Sha256Digest,
}

/// Explicit caller-authenticated inputs, not a trust token. The caller must replay
/// pinned enrollment and complete history to this parent, including admission IDs.
/// If present, latest_rotation must belong to that history; the private proof
/// authenticates its statement and the transition digest is checked here.
pub struct PairingParentV2<'a> {
    pub state: RevocationControlState<'a>,
    pub issuer_certificate_id: DeviceCertificateId,
    pub enrollment_record_sha256: Sha256Digest,
    pub latest_rotation: Option<(&'a VerifiedRevocationControl, &'a RevocationTransitionV1)>,
}

fn validate_grant_v2_shape(grant: &PairingGrantV2) -> Result<(), CryptoError> {
    if grant.schema_version != 2
        || grant.key_epoch == 0
        || grant.certificate.control_epoch == 0
        || !(MIN_WRAPPED_CIPHERTEXT_BYTES..=MAX_PAIRING_GRANT_BYTES)
            .contains(&grant.wrapped_key_bundle.ciphertext.len())
    {
        return Err(CryptoError::InvalidProtocolValue);
    }
    Ok(())
}

pub fn encode_pairing_approved_payload_v2(
    payload: &PairingApprovedPayloadV2,
) -> Result<Vec<u8>, CryptoError> {
    if payload.schema_version != 2
        || payload.previous_state_sha256.0 == [0; 32]
        || payload.enrollment_record_sha256.0 == [0; 32]
        || payload.issuer_device_name.trim().is_empty()
        || payload.issuer_device_name.len() > MAX_PAIRING_ISSUER_DEVICE_NAME_BYTES
    {
        return Err(CryptoError::InvalidProtocolValue);
    }
    // Enforce the nested limit as well as the total payload limit.
    encode_pairing_grant_v2(&payload.grant)?;
    let mut e = Encoder::new(Vec::new());
    e.map(8).map_err(enc)?;
    key(&mut e, 0)?;
    e.u16(2).map_err(enc)?;
    key(&mut e, 1)?;
    encode_pairing_grant(&mut e, &payload.grant)?;
    key(&mut e, 2)?;
    bytes(&mut e, payload.issuer_certificate_id.as_bytes())?;
    key(&mut e, 3)?;
    encode_certificate_v1(&mut e, &payload.issuer_certificate)?;
    key(&mut e, 4)?;
    e.str(&payload.issuer_device_name).map_err(enc)?;
    key(&mut e, 5)?;
    e.u8(encode_native_platform(payload.issuer_platform))
        .map_err(enc)?;
    key(&mut e, 6)?;
    bytes(&mut e, &payload.previous_state_sha256.0)?;
    key(&mut e, 7)?;
    bytes(&mut e, &payload.enrollment_record_sha256.0)?;
    let output = e.into_writer();
    if output.len() > MAX_PAIRING_APPROVED_PAYLOAD_BYTES {
        return Err(CryptoError::InvalidProtocolValue);
    }
    Ok(output)
}

pub fn decode_pairing_approved_payload_v2(
    input: &[u8],
) -> Result<PairingApprovedPayloadV2, CryptoError> {
    if input.len() > MAX_PAIRING_APPROVED_PAYLOAD_BYTES {
        return Err(CryptoError::InvalidProtocolValue);
    }
    let mut d = Decoder::new(input);
    require_map(&mut d, 8)?;
    expect_key(&mut d, 0)?;
    let schema_version = d.u16().map_err(dec)?;
    if schema_version != 2 {
        return Err(CryptoError::InvalidProtocolValue);
    }
    expect_key(&mut d, 1)?;
    let start = d.position();
    let grant = decode_pairing_grant(&mut d)?;
    if d.position() - start > MAX_PAIRING_GRANT_BYTES {
        return Err(CryptoError::InvalidProtocolValue);
    }
    expect_key(&mut d, 2)?;
    let issuer_certificate_id = decode_id(read_fixed::<16>(&mut d)?)?;
    expect_key(&mut d, 3)?;
    let issuer_certificate = decode_certificate_v1(&mut d)?;
    expect_key(&mut d, 4)?;
    let issuer_device_name = d.str().map_err(dec)?.to_owned();
    expect_key(&mut d, 5)?;
    let issuer_platform = decode_native_platform(d.u8().map_err(dec)?)?;
    expect_key(&mut d, 6)?;
    let previous_state_sha256 = Sha256Digest(read_fixed(&mut d)?);
    expect_key(&mut d, 7)?;
    let enrollment_record_sha256 = Sha256Digest(read_fixed(&mut d)?);
    let payload = PairingApprovedPayloadV2 {
        schema_version,
        grant,
        issuer_certificate_id,
        issuer_certificate,
        issuer_device_name,
        issuer_platform,
        previous_state_sha256,
        enrollment_record_sha256,
    };
    if d.position() != input.len() || encode_pairing_approved_payload_v2(&payload)? != input {
        return Err(CryptoError::InvalidProtocolValue);
    }
    Ok(payload)
}

// These public bindings do not establish historical issuer authority. They are
// sufficient to ensure the independently confirmed artifact answers this request.
fn validate_request_bindings_v2(
    p: &PairingApprovedPayloadV2,
    request: &SignedPairingRequest,
) -> Result<(), CryptoError> {
    require_exact_signed_request(request)?;
    let r = request.request();
    let child = &p.grant.certificate;
    let issuer = &p.issuer_certificate;
    if p.issuer_certificate_id == p.grant.certificate_id
        || issuer.device_id == child.device_id
        || p.grant.pairing_id != r.pairing_id
        || p.grant.request_digest != request.digest()
        || child.request_nonce != r.request_nonce
        || child.device_id != r.device_id
        || child.signing_public_key != r.signing_public_key
        || child.wrapping_public_key != r.wrapping_public_key
        || issuer.account_id != child.account_id
        || issuer.workspace_id != child.workspace_id
        || issuer.control_epoch == 0
        || issuer.control_epoch > child.control_epoch
    {
        return Err(CryptoError::AuthenticationFailed);
    }
    validate_x25519_public_key(issuer.wrapping_public_key)?;
    child.verify_issued_by(&CertificateIssuerV1::Device {
        device_id: issuer.device_id,
        signing_public_key: issuer.signing_public_key,
    })
}

/// Validate public admission bindings against explicitly authenticated history.
/// This does not verify a membership event signature or prove successful opening.
pub fn inspect_pairing_approval_v2(
    payload_bytes: &[u8],
    request: &SignedPairingRequest,
    parent: &PairingParentV2<'_>,
) -> Result<PairingApprovedPayloadV2, CryptoError> {
    let p = decode_pairing_approved_payload_v2(payload_bytes)?;
    validate_request_bindings_v2(&p, request)?;
    let s = &parent.state;
    let issuer = &p.issuer_certificate;
    let child = &p.grant.certificate;
    if s.control_epoch == 0
        || s.key_epoch == 0
        || s.state_sha256.0 == [0; 32]
        || s.active_devices.is_empty()
        || s.active_devices.len() >= 4096
        || p.previous_state_sha256 != s.state_sha256
        || p.enrollment_record_sha256 != parent.enrollment_record_sha256
        || p.issuer_certificate_id != parent.issuer_certificate_id
        || s.active_devices.get(&issuer.device_id) != Some(issuer)
        || s.active_devices.contains_key(&child.device_id)
        || child.account_id != s.scope.account_id
        || child.workspace_id != s.scope.workspace_id
        || child.control_epoch != s.control_epoch
        || p.grant.key_epoch != s.key_epoch
    {
        return Err(CryptoError::AuthenticationFailed);
    }
    for (id, cert) in s.active_devices {
        if *id != cert.device_id
            || cert.account_id != s.scope.account_id
            || cert.workspace_id != s.scope.workspace_id
            || cert.control_epoch == 0
            || cert.control_epoch > s.control_epoch
        {
            return Err(CryptoError::AuthenticationFailed);
        }
        crate::crypto::validate_ed25519_public_key(cert.signing_public_key)?;
        validate_x25519_public_key(cert.wrapping_public_key)?;
    }
    Ok(p)
}

fn grant_aad_v2(p: &PairingApprovedPayloadV2) -> Result<Vec<u8>, CryptoError> {
    let g = &p.grant;
    let c = &g.certificate;
    let mut aad = b"context-relay/pairing-grant-aad/v2\0".to_vec();
    aad.extend_from_slice(g.pairing_id.as_bytes());
    aad.extend_from_slice(&g.request_digest.0);
    aad.extend_from_slice(g.certificate_id.as_bytes());
    aad.extend_from_slice(&certificate_digest(c)?.0);
    aad.extend_from_slice(c.account_id.as_bytes());
    aad.extend_from_slice(c.workspace_id.as_bytes());
    aad.extend_from_slice(&c.control_epoch.to_be_bytes());
    aad.extend_from_slice(&g.key_epoch.to_be_bytes());
    aad.extend_from_slice(&p.previous_state_sha256.0);
    aad.extend_from_slice(&p.enrollment_record_sha256.0);
    aad.extend_from_slice(p.issuer_certificate_id.as_bytes());
    aad.extend_from_slice(&certificate_digest(&p.issuer_certificate)?.0);
    Ok(aad)
}

fn safety_number_v2(p: &PairingApprovedPayloadV2, canonical: &[u8]) -> PairingSafetyNumber {
    let mut h = Sha256::new();
    h.update(b"context-relay/pairing-safety/v2\0");
    h.update(p.grant.pairing_id.as_bytes());
    h.update(p.grant.request_digest.0);
    h.update(Sha256::digest(canonical));
    PairingSafetyNumber(format_safety_number(Sha256Digest(h.finalize().into())))
}

fn check_bundle(
    bundle: &PairingKeyBundle,
    parent: &PairingParentV2<'_>,
) -> Result<(), CryptoError> {
    let s = &parent.state;
    if bundle.account_id != s.scope.account_id
        || bundle.workspace_id != s.scope.workspace_id
        || bundle.control_epoch != s.control_epoch
        || bundle.key_epoch != s.key_epoch
        || bundle.enrollment_record_sha256 != Some(parent.enrollment_record_sha256)
        || parent.enrollment_record_sha256.0 == [0; 32]
    {
        return Err(CryptoError::AuthenticationFailed);
    }
    match parent.latest_rotation {
        None if s.control_epoch == 1 && s.key_epoch == 1 => Ok(()),
        Some((verified, transition)) => {
            let rotation = verified.state();
            if rotation.scope != s.scope
                || rotation.control_epoch != s.control_epoch
                || rotation.key_epoch != s.key_epoch
                || rotation.recovery_root_id != s.recovery_root_id
                || rotation.recovery_wrapping_public_key != s.recovery_wrapping_public_key
                || verified.statement().transition_sha256 != transition.digest()?
                || transition.control_epoch != s.control_epoch
                || transition.key_epoch != s.key_epoch
            {
                return Err(CryptoError::AuthenticationFailed);
            }
            if !key_material_matches(bundle, transition.key_material_sha256)? {
                return Err(CryptoError::AuthenticationFailed);
            }
            Ok(())
        }
        None => Err(CryptoError::AuthenticationFailed),
    }
}

// Content comparison only; check_bundle authenticates the commitment first.
fn key_material_matches(
    bundle: &PairingKeyBundle,
    commitment: Sha256Digest,
) -> Result<bool, CryptoError> {
    let unpinned = PairingKeyBundle::new(
        SyncScope {
            account_id: bundle.account_id,
            workspace_id: bundle.workspace_id,
        },
        bundle.control_epoch,
        bundle.key_epoch,
        *bundle.workspace_root_key(),
        *bundle.active_epoch_key(),
    )?;
    Ok(digest(&encode_pairing_key_bundle(bundle)?) == commitment
        || digest(&encode_pairing_key_bundle(&unpinned)?) == commitment)
}

/// Approver output. Display safety_number only on the approving trusted path for
/// this exact durably selected payload. Never send it as joining-side confirmation.
pub struct BuiltPairingApprovalV2 {
    pub payload: PairingApprovedPayloadV2,
    pub safety_number: PairingSafetyNumber,
}

#[allow(clippy::too_many_arguments)]
pub fn build_pairing_approval_v2(
    request: &SignedPairingRequest,
    parent: &PairingParentV2<'_>,
    issuer_device_id: DeviceId,
    issuer_keys: &DeviceKeys,
    certificate_id: DeviceCertificateId,
    issuer_device_name: impl Into<String>,
    issuer_platform: NativePlatform,
    bundle: &PairingKeyBundle,
) -> Result<BuiltPairingApprovalV2, CryptoError> {
    require_exact_signed_request(request)?;
    check_bundle(bundle, parent)?;
    let issuer = parent
        .state
        .active_devices
        .get(&issuer_device_id)
        .ok_or(CryptoError::AuthenticationFailed)?;
    if issuer.signing_public_key != issuer_keys.signing_public_key()
        || issuer.wrapping_public_key != issuer_keys.wrapping_public_key()
    {
        return Err(CryptoError::AuthenticationFailed);
    }
    let r = request.request();
    let certificate = DeviceCertificateV1::issue_by_device(
        CertificateFieldsV1 {
            account_id: parent.state.scope.account_id,
            workspace_id: parent.state.scope.workspace_id,
            control_epoch: parent.state.control_epoch,
            request_nonce: r.request_nonce,
            device_id: r.device_id,
            signing_public_key: r.signing_public_key,
            wrapping_public_key: r.wrapping_public_key,
        },
        issuer_device_id,
        issuer_keys,
    )?;
    let mut payload = PairingApprovedPayloadV2 {
        schema_version: 2,
        grant: PairingGrantV2 {
            schema_version: 2,
            pairing_id: r.pairing_id,
            request_digest: request.digest(),
            certificate_id,
            certificate,
            key_epoch: parent.state.key_epoch,
            wrapped_key_bundle: WrappedKeyEnvelope {
                ephemeral_public_key: r.wrapping_public_key,
                nonce: XChaChaNonce([0; 24]),
                ciphertext: vec![0; 16],
            },
        },
        issuer_certificate_id: parent.issuer_certificate_id,
        issuer_certificate: issuer.clone(),
        issuer_device_name: issuer_device_name.into(),
        issuer_platform,
        previous_state_sha256: parent.state.state_sha256,
        enrollment_record_sha256: parent.enrollment_record_sha256,
    };
    let plaintext = encode_pairing_key_bundle(bundle)?;
    payload.grant.wrapped_key_bundle =
        wrap_secret(r.wrapping_public_key, &plaintext, &grant_aad_v2(&payload)?)?;
    let canonical = encode_pairing_approved_payload_v2(&payload)?;
    inspect_pairing_approval_v2(&canonical, request, parent)?;
    let safety_number = safety_number_v2(&payload, &canonical);
    Ok(BuiltPairingApprovalV2 {
        payload,
        safety_number,
    })
}

/// Independent comparison and decryption proof, conditional on caller-authenticated
/// parent/history inputs. No membership-event signature or full-history proof is
/// supplied by this token; integration must verify those before durable admission.
pub struct OpenedPairingApprovalV2 {
    payload: PairingApprovedPayloadV2,
    key_bundle: PairingKeyBundle,
}
impl OpenedPairingApprovalV2 {
    pub fn payload(&self) -> &PairingApprovedPayloadV2 {
        &self.payload
    }
    pub fn key_bundle(&self) -> &PairingKeyBundle {
        &self.key_bundle
    }
}

/// Exact independently confirmed transcript and pins, not membership authority or
/// proof of decryption. Constructed only by confirm_pairing_transcript_v2; the
/// joining path never exposes its computed expected safety number.
pub struct ConfirmedV2Transcript {
    canonical_bytes: Vec<u8>,
    payload: PairingApprovedPayloadV2,
}
impl ConfirmedV2Transcript {
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
    pub fn payload(&self) -> &PairingApprovedPayloadV2 {
        &self.payload
    }
    pub fn enrollment_record_sha256(&self) -> Sha256Digest {
        self.payload.enrollment_record_sha256
    }
    pub fn previous_state_sha256(&self) -> Sha256Digest {
        self.payload.previous_state_sha256
    }
}

/// Native joining phase one. The number must be independently read on the
/// approving device; a number delivered with provider evidence is not confirmation.
/// The coordinator owns attempt/expiry limits. Use the confirmed pins to replay
/// enrollment/history before passing its private proof to the staged opener.
pub fn confirm_pairing_transcript_v2(
    canonical: &[u8],
    entered_safety_number: &str,
    request: &SignedPairingRequest,
) -> Result<ConfirmedV2Transcript, PairingConfirmationError> {
    let payload =
        decode_pairing_approved_payload_v2(canonical).map_err(PairingConfirmationError::Crypto)?;
    if !exact_safety_number_matches(
        entered_safety_number,
        safety_number_v2(&payload, canonical).as_str(),
    ) {
        return Err(PairingConfirmationError::SafetyNumberMismatch);
    }
    validate_request_bindings_v2(&payload, request).map_err(PairingConfirmationError::Crypto)?;
    Ok(ConfirmedV2Transcript {
        canonical_bytes: canonical.to_vec(),
        payload,
    })
}

/// Native joining phase two. Require history ending at the independently confirmed
/// predecessor and the exact verified membership event, then decrypt. A conditional
/// membership proof over a different supplied roster is not accepted as this
/// history's successor. This does not install keys or establish global freshness.
pub fn open_confirmed_pairing_approval_v2(
    confirmed: &ConfirmedV2Transcript,
    request: &SignedPairingRequest,
    keys: &DeviceKeys,
    history: &crate::devices::membership_crypto::VerifiedMembershipHistory,
    membership: &crate::devices::membership_crypto::VerifiedMembershipControl,
) -> Result<OpenedPairingApprovalV2, CryptoError> {
    let parent = history.pairing_parent(confirmed.payload.issuer_certificate.device_id)?;
    let payload = inspect_pairing_approval_v2(confirmed.canonical_bytes(), request, &parent)?;
    let expected = crate::devices::membership_crypto::DeviceMembershipAddStatementV1::from_approved_payload_v2(confirmed.canonical_bytes())?;
    history.ensure_new_admission(
        expected.membership_id,
        payload.grant.certificate.device_id,
        expected.certificate_id,
    )?;
    let next = membership.state();
    let current = &parent.state;
    if membership.statement() != &expected
        || next.scope != current.scope
        || next.control_epoch != current.control_epoch
        || next.key_epoch != current.key_epoch
        || next.recovery_root_id != current.recovery_root_id
        || next.recovery_wrapping_public_key != current.recovery_wrapping_public_key
        || next.active_devices.len() != current.active_devices.len() + 1
        || next
            .active_devices
            .get(&payload.grant.certificate.device_id)
            != Some(&payload.grant.certificate)
        || current
            .active_devices
            .iter()
            .any(|(id, cert)| next.active_devices.get(id) != Some(cert))
    {
        return Err(CryptoError::AuthenticationFailed);
    }
    open_pairing_payload_v2(payload, request, keys, &parent)
}

/// Compatibility path for callers that already independently authenticated their
/// parent. Fresh joiners must use the staged API to obtain pins before replay.
/// This path still does not verify a membership event or complete history itself.
pub fn confirm_and_open_pairing_approval_v2(
    canonical: &[u8],
    entered_safety_number: &str,
    request: &SignedPairingRequest,
    keys: &DeviceKeys,
    parent: &PairingParentV2<'_>,
) -> Result<OpenedPairingApprovalV2, PairingConfirmationError> {
    let confirmed = confirm_pairing_transcript_v2(canonical, entered_safety_number, request)?;
    let payload = inspect_pairing_approval_v2(confirmed.canonical_bytes(), request, parent)
        .map_err(PairingConfirmationError::Crypto)?;
    open_pairing_payload_v2(payload, request, keys, parent)
        .map_err(PairingConfirmationError::Crypto)
}

fn open_pairing_payload_v2(
    payload: PairingApprovedPayloadV2,
    request: &SignedPairingRequest,
    keys: &DeviceKeys,
    parent: &PairingParentV2<'_>,
) -> Result<OpenedPairingApprovalV2, CryptoError> {
    if keys.signing_public_key() != request.request().signing_public_key
        || keys.wrapping_public_key() != request.request().wrapping_public_key
    {
        return Err(CryptoError::AuthenticationFailed);
    }
    let plaintext =
        keys.unwrap_secret(&payload.grant.wrapped_key_bundle, &grant_aad_v2(&payload)?)?;
    let key_bundle = decode_pairing_key_bundle(plaintext.expose())?;
    check_bundle(&key_bundle, parent)?;
    Ok(OpenedPairingApprovalV2 {
        payload,
        key_bundle,
    })
}

impl fmt::Debug for PairingApprovedPayloadV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingApprovedPayloadV2")
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

#[cfg(test)]
mod tests {
    use super::*;
    fn hex(s: &str) -> Vec<u8> {
        let s = s.trim();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    #[test]
    fn rotation_commitment_accepts_both_existing_plaintext_schemas_without_repairing_a_pin() {
        let scope = SyncScope {
            account_id: "018f22e2-79b0-7cc8-98c4-dc0c0c073901".parse().unwrap(),
            workspace_id: "018f22e2-79b0-7cc8-98c4-dc0c0c073902".parse().unwrap(),
        };
        let old = PairingKeyBundle::new(scope, 2, 2, [3; 32], [4; 32]).unwrap();
        let schema1 = digest(&encode_pairing_key_bundle(&old).unwrap());
        let pinned = old
            .with_enrollment_record_sha256(Sha256Digest([5; 32]))
            .unwrap();
        let schema2 = digest(&encode_pairing_key_bundle(&pinned).unwrap());
        assert_ne!(schema1, schema2);
        assert!(key_material_matches(&pinned, schema1).unwrap());
        assert!(key_material_matches(&pinned, schema2).unwrap());
        let wrong_pin = pinned
            .with_enrollment_record_sha256(Sha256Digest([6; 32]))
            .unwrap();
        assert!(!key_material_matches(&wrong_pin, schema2).unwrap());
        let stale = PairingKeyBundle::new(scope, 2, 2, [7; 32], [8; 32])
            .unwrap()
            .with_enrollment_record_sha256(Sha256Digest([5; 32]))
            .unwrap();
        assert!(!key_material_matches(&stale, schema1).unwrap());
        assert!(!key_material_matches(&stale, schema2).unwrap());
    }
    #[test]
    fn frozen_independent_v2_transcripts_and_strict_codecs() {
        // Frozen by a separate Python stdlib writer implementing definite CBOR
        // and literal UUID/domain/BE concatenations; never produced by this codec.
        let raw = hex(include_str!(
            "../../../tests/fixtures/pairing-approved-payload-v2.hex"
        ));
        let grant_raw = hex(include_str!("../../../tests/fixtures/pairing-grant-v2.hex"));
        let p = decode_pairing_approved_payload_v2(&raw).unwrap();
        assert_eq!(p.schema_version, 2);
        assert_eq!(p.grant.certificate.control_epoch, 2);
        assert_eq!(p.issuer_certificate.control_epoch, 1);
        assert_eq!(p.previous_state_sha256, Sha256Digest([0xa1; 32]));
        assert_eq!(p.enrollment_record_sha256, Sha256Digest([0xb1; 32]));
        assert_eq!(encode_pairing_approved_payload_v2(&p).unwrap(), raw);
        assert_eq!(encode_pairing_grant_v2(&p.grant).unwrap(), grant_raw);
        assert_eq!(decode_pairing_grant_v2(&grant_raw).unwrap(), p.grant);
        assert_eq!(
            digest(&raw).0.as_slice(),
            hex("4d38b245b41a2691a829bf662d21511498ec5f9138d775a6dea733e7fbb0cff3")
        );
        let aad = grant_aad_v2(&p).unwrap();
        assert_eq!(
            aad.len(),
            b"context-relay/pairing-grant-aad/v2\0".len() + 248
        );
        assert_eq!(
            aad,
            hex(include_str!(
                "../../../tests/fixtures/pairing-grant-aad-v2.hex"
            ))
        );
        assert_eq!(
            safety_number_v2(&p, &raw).as_str(),
            "0268-A62B-9251-A678-C039"
        );
        assert!(decode_pairing_approved_payload_v1(&raw).is_err());
        assert!(decode_pairing_grant_v1(&grant_raw).is_err());
        let old = hex(include_str!("../../../tests/fixtures/pairing-grant-v1.hex"));
        assert!(decode_pairing_grant_v2(&old).is_err());
        for end in 0..raw.len() {
            assert!(decode_pairing_approved_payload_v2(&raw[..end]).is_err());
        }
        for end in 0..grant_raw.len() {
            assert!(decode_pairing_grant_v2(&grant_raw[..end]).is_err());
        }
        let mut invalid = Vec::new();
        let mut v = raw.clone();
        v.push(0);
        invalid.push(v);
        let mut v = raw.clone();
        v[2] = 1;
        invalid.push(v); // outer version
        let mut v = raw.clone();
        v[6] = 1;
        invalid.push(v); // embedded grant version
        let mut v = raw.clone();
        v.splice(2..3, [0x18, 2]);
        invalid.push(v); // non-shortest integer
        let mut v = raw.clone();
        v[0] = 0xbf;
        v.push(0xff);
        invalid.push(v); // indefinite
        let mut v = raw.clone();
        v.insert(0, 0xc0);
        invalid.push(v); // tag
        let mut v = raw.clone();
        v.truncate(v.len() - 35);
        v[0] = 0xa7;
        invalid.push(v); // absent pin
        let mut v = raw.clone();
        let len = v.len();
        v[len - 35] = 6;
        invalid.push(v); // duplicate key
        let mut v = raw.clone();
        let len = v.len();
        v[len - 35] = 8;
        invalid.push(v); // unknown key
        for v in invalid {
            assert!(decode_pairing_approved_payload_v2(&v).is_err());
        }
        let mut p = p.clone();
        p.enrollment_record_sha256 = Sha256Digest([0; 32]);
        assert!(encode_pairing_approved_payload_v2(&p).is_err());
        let mut p = decode_pairing_approved_payload_v2(&raw).unwrap();
        p.grant.wrapped_key_bundle.ciphertext = vec![0; MAX_PAIRING_GRANT_BYTES];
        assert!(encode_pairing_grant_v2(&p.grant).is_err());
        assert!(encode_pairing_approved_payload_v2(&p).is_err());
        // Raw nested grant exceeds 16 KiB although the whole payload is below 32 KiB.
        let mut e = Encoder::new(Vec::new());
        encode_pairing_grant(&mut e, &p.grant).unwrap();
        let mut oversized = raw.clone();
        oversized.splice(4..4 + grant_raw.len(), e.into_writer());
        assert!(oversized.len() < MAX_PAIRING_APPROVED_PAYLOAD_BYTES);
        assert!(decode_pairing_approved_payload_v2(&oversized).is_err());
    }
}
