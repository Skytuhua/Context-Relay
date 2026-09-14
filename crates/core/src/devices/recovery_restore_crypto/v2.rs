//! Root-authenticated recovery admission, separate from pairing confirmation.
use super::*;
use crate::devices::membership_crypto::{
    MembershipEndpoint, MembershipHistoryBudget, MembershipHistoryEvent, VerifiedMembershipHistory,
    replay_membership_history,
};
use crate::devices::revocation_crypto::{DeviceRevocationStatementV1, RevocationTransitionV1};
use crate::sync::SyncScope;
use std::collections::BTreeMap;
const RECOVERY_DEVICE_CLAIM_SCHEMA_VERSION: u16 = 2;
const RECOVERY_DEVICE_CLAIM_SIGNING_DOMAIN: &[u8] = b"context-relay/recovery-device-claim/v2\0";
const RECOVERED_DEVICE_MATERIAL_AAD_DOMAIN: &[u8] = b"context-relay/recovered-device-material/v2\0";

/// Phrase-authenticated complete candidate history and root-opened key inventory.
/// This grants neither server CAS success, installed history nor current writes.
pub struct AuthenticatedRecoveryHistory {
    root: AuthenticatedRecoveryRoot,
    history: VerifiedMembershipHistory,
    material: BTreeMap<u32, PairingKeyBundle>,
}
impl fmt::Debug for AuthenticatedRecoveryHistory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthenticatedRecoveryHistory([REDACTED])")
    }
}
impl AuthenticatedRecoveryHistory {
    pub fn history(&self) -> &VerifiedMembershipHistory {
        &self.history
    }

    /// Only this private root-opened inventory can issue retained-key provenance.
    /// Save it before dropping this authority; checkpoint and admission may arrive later.
    pub fn seal_historical_keys(
        &self,
        claim: &RecoveryDeviceClaimV2,
        recipient: &DeviceKeys,
    ) -> Result<Vec<RecoveryHistoryKeyV1>, RecoveryRestoreCryptoError> {
        verify_recovery_device_claim_v2(&self.root.record, claim, &self.history)?;
        require_recipient(claim, recipient)?;
        let claim_hash = digest(&encode_recovery_device_claim_v2(claim)?);
        self.material
            .iter()
            .filter(|(epoch, _)| **epoch < claim.key_epoch)
            .map(|(&epoch, material)| seal_history_key(claim_hash, epoch, material, recipient))
            .collect()
    }

    /// Additive native phrase repair preserves the original claim's parent and recipient.
    pub(crate) fn seal_missing_historical_keys(
        &self,
        claim: &RecoveryDeviceClaimV2,
        original_parent: &VerifiedMembershipHistory,
        lineage: &crate::devices::membership_crypto::VerifiedMembershipLineage,
        missing: &std::collections::BTreeSet<u32>,
        recipient: &DeviceKeys,
    ) -> Result<Vec<RecoveryHistoryKeyV1>, RecoveryRestoreCryptoError> {
        verify_recovery_device_claim_v2(&self.root.record, claim, original_parent)?;
        require_recipient(claim, recipient)?;
        if self.history.endpoint() != lineage.history().endpoint()
            || self.history.enrollment_record_sha256() != claim.canonical_record_sha256
        {
            return Err(RecoveryRestoreCryptoError::InvalidRecovery);
        }
        let claim_hash = digest(&encode_recovery_device_claim_v2(claim)?);
        missing
            .iter()
            .map(|&epoch| {
                if epoch == 0 || epoch >= self.history.endpoint().key_epoch {
                    return Err(RecoveryRestoreCryptoError::InvalidRecovery);
                }
                let bundle = self
                    .material
                    .get(&epoch)
                    .ok_or(RecoveryRestoreCryptoError::InvalidRecovery)?;
                let retained = seal_history_key(claim_hash, epoch, bundle, recipient)?;
                open_recovery_history_key(
                    &self.root.record,
                    claim,
                    original_parent,
                    lineage,
                    &retained,
                    recipient,
                )?;
                Ok(retained)
            })
            .collect()
    }
}

fn seal_history_key(
    claim_hash: Sha256Digest,
    epoch: u32,
    material: &PairingKeyBundle,
    recipient: &DeviceKeys,
) -> Result<RecoveryHistoryKeyV1, RecoveryRestoreCryptoError> {
    // Keep the original canonical representation before adding a native enrollment pin.
    let plain = encode_pairing_key_bundle(material)?;
    let commitment = digest(&plain);
    let aad = history_key_aad(claim_hash, epoch, commitment);
    let envelope = wrap_secret_with_rng(recipient.wrapping_public_key(), &plain, &aad, &mut OsRng)?;
    let mut signed = aad;
    signed.extend(super::super::recovery_crypto::encode_recovery_device_envelope_v1(&envelope)?);
    Ok(RecoveryHistoryKeyV1 {
        key_epoch: epoch,
        original_bundle_sha256: commitment,
        envelope,
        signature: recipient.sign_hosted_device_proof(&signed),
    })
}

#[derive(Clone)]
pub struct RecoveryHistoryKeyV1 {
    pub key_epoch: u32,
    pub original_bundle_sha256: Sha256Digest,
    pub envelope: WrappedKeyEnvelope,
    pub signature: Ed25519SignatureBytes,
}
impl fmt::Debug for RecoveryHistoryKeyV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryHistoryKeyV1([REDACTED])")
    }
}
fn require_recipient(
    claim: &RecoveryDeviceClaimV2,
    keys: &DeviceKeys,
) -> Result<(), RecoveryRestoreCryptoError> {
    if keys.signing_public_key() != claim.certificate.signing_public_key
        || keys.wrapping_public_key() != claim.certificate.wrapping_public_key
    {
        return Err(RecoveryRestoreCryptoError::InvalidRecovery);
    }
    Ok(())
}
fn history_key_aad(claim: Sha256Digest, epoch: u32, commitment: Sha256Digest) -> Vec<u8> {
    let mut aad = b"context-relay/recovery-history-key/v1\0".to_vec();
    aad.extend(claim.0);
    aad.extend(epoch.to_be_bytes());
    aad.extend(commitment.0);
    aad
}

/// Reopening requires the exact admitted R-to-D lineage and active original
/// recipient. Key inventory alone proves neither reconstructed nor installed data.
pub fn open_recovery_history_key(
    record: &RecoveryEnrollmentRecordV1,
    claim: &RecoveryDeviceClaimV2,
    original_parent: &VerifiedMembershipHistory,
    lineage: &crate::devices::membership_crypto::VerifiedMembershipLineage,
    retained: &RecoveryHistoryKeyV1,
    recipient: &DeviceKeys,
) -> Result<PairingKeyBundle, RecoveryRestoreCryptoError> {
    verify_recovery_device_claim_v2(record, claim, original_parent)?;
    require_recipient(claim, recipient)?;
    let history = lineage.history();
    if lineage.anchor()
        != (MembershipEndpoint {
            state_sha256: recovery_membership_successor(claim)?,
            control_epoch: claim.certificate.control_epoch,
            key_epoch: claim.key_epoch,
        })
        || history.enrollment_record_sha256() != claim.canonical_record_sha256
        || history.state().scope
            != (SyncScope {
                account_id: claim.account_id,
                workspace_id: claim.workspace_id,
            })
        || history
            .state()
            .active_devices
            .get(&claim.certificate.device_id)
            != Some(&claim.certificate)
        || history.admissions().get(&claim.certificate.device_id) != Some(&claim.certificate_id)
        || retained.key_epoch == 0
        || retained.key_epoch >= history.endpoint().key_epoch
        || retained.original_bundle_sha256.0 == [0; 32]
        || retained.envelope.ciphertext.len() > 512
    {
        return Err(RecoveryRestoreCryptoError::InvalidRecovery);
    }
    let aad = history_key_aad(
        digest(&encode_recovery_device_claim_v2(claim)?),
        retained.key_epoch,
        retained.original_bundle_sha256,
    );
    let mut signed = aad.clone();
    signed.extend(
        super::super::recovery_crypto::encode_recovery_device_envelope_v1(&retained.envelope)?,
    );
    verify_signature(recipient.signing_public_key(), &signed, retained.signature)?;
    let plaintext = recipient.unwrap_secret(&retained.envelope, &aad)?;
    if digest(plaintext.expose()) != retained.original_bundle_sha256 {
        return Err(RecoveryRestoreCryptoError::InvalidRecovery);
    }
    let material = decode_pairing_key_bundle(plaintext.expose())?;
    if material.account_id() != claim.account_id
        || material.workspace_id() != claim.workspace_id
        || material.key_epoch() != retained.key_epoch
        || material
            .enrollment_record_sha256()
            .is_some_and(|pin| pin != claim.canonical_record_sha256)
    {
        return Err(RecoveryRestoreCryptoError::InvalidRecovery);
    }
    if retained.key_epoch == 1 {
        if material.control_epoch() != 1 {
            return Err(RecoveryRestoreCryptoError::InvalidRecovery);
        }
    } else {
        let commitment = lineage
            .rotated_key_commitments()
            .iter()
            .find(|entry| entry.key_epoch() == retained.key_epoch)
            .ok_or(RecoveryRestoreCryptoError::InvalidRecovery)?;
        if commitment.control_epoch() != material.control_epoch()
            || commitment.key_material_sha256() != retained.original_bundle_sha256
        {
            return Err(RecoveryRestoreCryptoError::InvalidRecovery);
        }
    }
    Ok(material.with_enrollment_record_sha256(claim.canonical_record_sha256)?)
}

pub fn authenticate_recovery_history(
    root: AuthenticatedRecoveryRoot,
    events: &[MembershipHistoryEvent<'_>],
    candidate: MembershipEndpoint,
    budget: MembershipHistoryBudget,
) -> Result<AuthenticatedRecoveryHistory, RecoveryRestoreCryptoError> {
    let canonical = encode_recovery_enrollment_record_v1(&root.record)?;
    let scope = SyncScope {
        account_id: root.record.account_id,
        workspace_id: root.record.workspace_id,
    };
    let mut material = BTreeMap::from([(
        1,
        open_recovery_metadata(&root.record, &root.recovery_keys)?,
    )]);
    let history = replay_membership_history(
        &canonical,
        root.canonical_record_sha256,
        scope,
        events,
        candidate,
        budget,
        |history, event| {
            if let Some(MembershipHistoryEvent::Revocation {
                statement,
                signature,
                transition,
            }) = event
            {
                let statement = DeviceRevocationStatementV1::from_signing_preimage(statement)?;
                let transition = RevocationTransitionV1::from_canonical_bytes(transition)?;
                let previous = history
                    .latest_rotation_predecessor()
                    .ok_or(CryptoError::AuthenticationFailed)?;
                let opened = transition.open_recovery_material(
                    &statement,
                    *signature,
                    &previous,
                    &root.recovery_keys,
                )?;
                if material.insert(opened.key_epoch(), opened).is_some() {
                    return Err(CryptoError::AuthenticationFailed);
                }
            }
            Ok(())
        },
    )?;
    if material.len() != candidate.key_epoch as usize
        || !material.contains_key(&candidate.key_epoch)
    {
        return Err(RecoveryRestoreCryptoError::InvalidRecovery);
    }
    Ok(AuthenticatedRecoveryHistory {
        root,
        history,
        material,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn build_recovery_device_claim_v2(
    authority: &AuthenticatedRecoveryHistory,
    restore_id: RecoveryRestoreId,
    expected_recovery_generation: u64,
    certificate_id: DeviceCertificateId,
    request_nonce: PairingRequestNonce,
    device_id: DeviceId,
    device_name: String,
    device_platform: NativePlatform,
    device_keys: &DeviceKeys,
) -> Result<RecoveryDeviceClaimV2, RecoveryRestoreCryptoError> {
    build_recovery_device_claim_v2_inner(
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

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_recovery_device_claim_v2_inner<R: RngCore + CryptoRng>(
    authority: &AuthenticatedRecoveryHistory,
    restore_id: RecoveryRestoreId,
    expected_recovery_generation: u64,
    certificate_id: DeviceCertificateId,
    request_nonce: PairingRequestNonce,
    device_id: DeviceId,
    device_name: String,
    device_platform: NativePlatform,
    device_keys: &DeviceKeys,
    rng: &mut R,
) -> Result<RecoveryDeviceClaimV2, RecoveryRestoreCryptoError> {
    let root = &authority.root;
    validate_builder_identity(
        &root.record,
        restore_id,
        expected_recovery_generation,
        certificate_id,
        device_id,
        &device_name,
        device_keys,
    )?;
    authority.history.ensure_new_admission(
        restore_id
            .to_string()
            .parse()
            .map_err(|_| RecoveryRestoreCryptoError::InvalidRecovery)?,
        device_id,
        certificate_id,
    )?;
    let endpoint = authority.history.endpoint();
    let material = authority
        .material
        .get(&endpoint.key_epoch)
        .ok_or(RecoveryRestoreCryptoError::InvalidRecovery)?;
    let certificate = DeviceCertificateV1::issue_genesis(
        CertificateFieldsV1 {
            account_id: root.record.account_id,
            workspace_id: root.record.workspace_id,
            control_epoch: endpoint.control_epoch,
            request_nonce,
            device_id,
            signing_public_key: device_keys.signing_public_key(),
            wrapping_public_key: device_keys.wrapping_public_key(),
        },
        &root.recovery_keys,
    )?;
    let mut claim = RecoveryDeviceClaimV2 {
        schema_version: 2,
        restore_id,
        enrollment_id: root.record.enrollment_id,
        recovery_root_id: root.record.recovery_root_id,
        account_id: root.record.account_id,
        workspace_id: root.record.workspace_id,
        canonical_record_sha256: root.canonical_record_sha256,
        expected_recovery_generation,
        certificate_id,
        certificate,
        device_name,
        device_platform,
        key_epoch: endpoint.key_epoch,
        device_material_envelope: WrappedKeyEnvelope {
            ephemeral_public_key: device_keys.wrapping_public_key(),
            nonce: context_relay_protocol::XChaChaNonce([0; 24]),
            ciphertext: vec![0; 16],
        },
        previous_state_sha256: endpoint.state_sha256,
        recovery_root_signature: Ed25519SignatureBytes([0; 64]),
    };
    let plaintext = encode_pairing_key_bundle(material)?;
    claim.device_material_envelope = wrap_secret_with_rng(
        device_keys.wrapping_public_key(),
        plaintext.as_slice(),
        &recovered_device_material_aad(&claim)?,
        rng,
    )?;
    claim.recovery_root_signature = root
        .recovery_keys
        .sign_restore_claim(&encode_recovery_device_claim_signing_preimage_v2(&claim)?);
    verify_recovery_device_claim_v2(&root.record, &claim, &authority.history)?;
    Ok(claim)
}

pub fn verify_recovery_device_claim_v2(
    record: &RecoveryEnrollmentRecordV1,
    claim: &RecoveryDeviceClaimV2,
    parent: &VerifiedMembershipHistory,
) -> Result<(), RecoveryRestoreCryptoError> {
    validate_claim_shape(claim, true)?;
    let pin = digest(&encode_recovery_enrollment_record_v1(record)?);
    let state = parent.state();
    if claim.enrollment_id != record.enrollment_id
        || claim.recovery_root_id != record.recovery_root_id
        || claim.account_id != record.account_id
        || claim.workspace_id != record.workspace_id
        || state.scope.account_id != record.account_id
        || state.scope.workspace_id != record.workspace_id
        || state.recovery_root_id != record.recovery_root_id
        || state.recovery_wrapping_public_key != record.recovery_wrapping_public_key
        || parent.enrollment_record_sha256() != pin
        || claim.canonical_record_sha256 != pin
        || claim.certificate.issuer
            != CertificateIssuerV1::RecoveryRoot(record.recovery_signing_public_key)
        || claim.previous_state_sha256 != parent.endpoint().state_sha256
        || claim.certificate.control_epoch != state.control_epoch
        || claim.key_epoch != state.key_epoch
    {
        return Err(RecoveryRestoreCryptoError::InvalidRecovery);
    }
    let identifiers = [
        *claim.restore_id.as_bytes(),
        *claim.certificate_id.as_bytes(),
        *claim.certificate.device_id.as_bytes(),
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
    parent.ensure_new_admission(
        claim
            .restore_id
            .to_string()
            .parse()
            .map_err(|_| RecoveryRestoreCryptoError::InvalidRecovery)?,
        claim.certificate.device_id,
        claim.certificate_id,
    )?;
    Ok(())
}

pub fn open_recovered_device_material_v2(
    record: &RecoveryEnrollmentRecordV1,
    claim: &RecoveryDeviceClaimV2,
    parent: &VerifiedMembershipHistory,
    device_keys: &DeviceKeys,
) -> Result<PairingKeyBundle, RecoveryRestoreCryptoError> {
    verify_recovery_device_claim_v2(record, claim, parent)?;
    if claim.certificate.signing_public_key != device_keys.signing_public_key()
        || claim.certificate.wrapping_public_key != device_keys.wrapping_public_key()
    {
        return Err(RecoveryRestoreCryptoError::InvalidRecovery);
    }
    let plaintext = device_keys.unwrap_secret(
        &claim.device_material_envelope,
        &recovered_device_material_aad(claim)?,
    )?;
    let material = decode_pairing_key_bundle(plaintext.expose())?;
    if material.account_id() != claim.account_id
        || material.workspace_id() != claim.workspace_id
        || material.control_epoch() != claim.certificate.control_epoch
        || material.key_epoch() != claim.key_epoch
        || parent
            .current_rotated_key_commitment()
            .is_some_and(|commitment| commitment != digest(plaintext.expose()))
    {
        return Err(RecoveryRestoreCryptoError::InvalidRecovery);
    }
    Ok(material.with_enrollment_record_sha256(claim.canonical_record_sha256)?)
}

pub fn recovery_membership_successor(
    claim: &RecoveryDeviceClaimV2,
) -> Result<Sha256Digest, RecoveryRestoreCryptoError> {
    let canonical = encode_recovery_device_claim_v2(claim)?;
    let mut bytes = b"context-relay/recovery-membership-add/v1\0".to_vec();
    bytes.extend_from_slice(&canonical);
    Ok(digest(&bytes))
}

pub fn sign_hosted_recovery_proof_v2(
    device: &DeviceKeys,
    auth_user_id: uuid::Uuid,
    session_id: uuid::Uuid,
    claim: &RecoveryDeviceClaimV2,
) -> Result<Ed25519SignatureBytes, RecoveryRestoreCryptoError> {
    if auth_user_id.is_nil()
        || session_id.is_nil()
        || device.signing_public_key() != claim.certificate.signing_public_key
        || device.wrapping_public_key() != claim.certificate.wrapping_public_key
    {
        return Err(RecoveryRestoreCryptoError::InvalidRecovery);
    }
    let mut preimage = b"context-relay/hosted-recovery-device-proof/v2\0".to_vec();
    preimage.extend_from_slice(auth_user_id.as_bytes());
    preimage.extend_from_slice(session_id.as_bytes());
    preimage.extend_from_slice(&digest(&encode_recovery_device_claim_v2(claim)?).0);
    Ok(device.sign_hosted_device_proof(&preimage))
}

#[derive(Clone, Eq, PartialEq)]
pub struct RecoveryDeviceClaimV2 {
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
    pub previous_state_sha256: Sha256Digest,
    pub recovery_root_signature: Ed25519SignatureBytes,
}

impl fmt::Debug for RecoveryDeviceClaimV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryDeviceClaimV2")
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

pub fn encode_recovery_device_claim_v2(
    claim: &RecoveryDeviceClaimV2,
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

pub fn decode_recovery_device_claim_v2(
    input: &[u8],
) -> Result<RecoveryDeviceClaimV2, RecoveryRestoreCryptoError> {
    if input.len() > MAX_RECOVERY_DEVICE_CLAIM_BYTES {
        return Err(RecoveryRestoreCryptoError::InvalidRecovery);
    }
    let mut decoder = Decoder::new(input);
    require_map(&mut decoder, 16)?;
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
    let previous_state_sha256 = Sha256Digest(read_fixed::<32>(&mut decoder)?);
    expect_key(&mut decoder, 15)?;
    let recovery_root_signature = Ed25519SignatureBytes(read_fixed::<64>(&mut decoder)?);
    if decoder.position() != input.len() {
        return Err(RecoveryRestoreCryptoError::InvalidRecovery);
    }
    let claim = RecoveryDeviceClaimV2 {
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
        previous_state_sha256,
        recovery_root_signature,
    };
    validate_claim_shape(&claim, true)?;
    if encode_recovery_device_claim_v2(&claim)?.as_slice() != input {
        return Err(RecoveryRestoreCryptoError::InvalidRecovery);
    }
    Ok(claim)
}

pub fn encode_recovery_device_claim_signing_preimage_v2(
    claim: &RecoveryDeviceClaimV2,
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

fn validate_claim_shape(
    claim: &RecoveryDeviceClaimV2,
    verify_claim_signature: bool,
) -> Result<(), RecoveryRestoreCryptoError> {
    if claim.schema_version != RECOVERY_DEVICE_CLAIM_SCHEMA_VERSION
        || claim.previous_state_sha256.0 == [0; 32]
        || claim.canonical_record_sha256.0 == [0; 32]
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
        let preimage = encode_recovery_device_claim_signing_preimage_v2(claim)?;
        verify_signature(root_key, &preimage, claim.recovery_root_signature)?;
    }
    Ok(())
}

fn recovered_device_material_aad(
    claim: &RecoveryDeviceClaimV2,
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
    aad.extend_from_slice(&claim.previous_state_sha256.0);
    Ok(aad)
}

fn encode_claim_map(
    encoder: &mut Encoder<Vec<u8>>,
    claim: &RecoveryDeviceClaimV2,
    include_signature: bool,
) -> Result<(), RecoveryRestoreCryptoError> {
    encoder
        .map(if include_signature { 16 } else { 15 })
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
    key(encoder, 14)?;
    bytes(encoder, &claim.previous_state_sha256.0)?;
    if include_signature {
        key(encoder, 15)?;
        bytes(encoder, &claim.recovery_root_signature.0)?;
    }
    Ok(())
}
