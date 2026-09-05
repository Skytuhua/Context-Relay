use std::fmt;

use context_relay_protocol::{
    DeviceCertificateId, DeviceId, NativePlatform, PairingCode, PairingId, Sha256Digest,
    decode_pairing_request_v1,
};
use sha2::{Digest, Sha256};

use crate::{
    crypto::DeviceKeys,
    devices::{
        crypto::{
            PairingGrantApproval, PairingKeyBundle, PairingSafetyNumber, SignedPairingRequest,
            build_pairing_approved_payload_v1, build_pairing_grant,
            confirm_and_open_pairing_approval, encode_pairing_approved_payload_v1,
            inspect_pairing_approval, pairing_request_fingerprint, verify_pairing_request,
        },
        transport::{
            PairingApprovalTransport, PairingDecisionEnvelope, PairingDecisionKind, PairingInvite,
            PairingInviteStatus, PairingJoinTransport, PairingResult, PairingTransportError,
        },
    },
    sync::SyncScope,
    vault::{
        DeviceCertificateState, PairingDecisionFinalState, StoredDeviceCertificate, Vault,
        VaultError,
    },
};

/// Clock injection keeps pairing expiry and retry behavior deterministic in tests.
pub trait PairingClock: Send + Sync {
    fn now_ms(&self) -> u64;
}

pub struct WorkspacePairingMaterial {
    bundle: PairingKeyBundle,
}

impl WorkspacePairingMaterial {
    pub fn new(
        scope: SyncScope,
        control_epoch: u32,
        key_epoch: u32,
        workspace_root_key: [u8; 32],
        active_epoch_key: [u8; 32],
    ) -> Result<Self, PairingCycleError> {
        PairingKeyBundle::new(
            scope,
            control_epoch,
            key_epoch,
            workspace_root_key,
            active_epoch_key,
        )
        .map(|bundle| Self { bundle })
        .map_err(|_| PairingCycleError::Invalid)
    }

    pub const fn scope(&self) -> SyncScope {
        SyncScope {
            account_id: self.bundle.account_id(),
            workspace_id: self.bundle.workspace_id(),
        }
    }

    pub const fn control_epoch(&self) -> u32 {
        self.bundle.control_epoch()
    }

    pub const fn key_epoch(&self) -> u32 {
        self.bundle.key_epoch()
    }

    pub fn workspace_root_key(&self) -> &[u8; 32] {
        self.bundle.workspace_root_key()
    }

    pub fn active_epoch_key(&self) -> &[u8; 32] {
        self.bundle.active_epoch_key()
    }
}

impl fmt::Debug for WorkspacePairingMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkspacePairingMaterial")
            .field("scope", &self.scope())
            .field("control_epoch", &self.control_epoch())
            .field("key_epoch", &self.key_epoch())
            .field("keys", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingCycleError {
    Invalid,
    Expired,
    Canceled,
    Rejected,
    Conflict,
    Transient,
}

impl PairingCycleError {
    pub const fn safe_code(self) -> &'static str {
        match self {
            Self::Invalid => "pairing_invalid",
            Self::Expired => "pairing_expired",
            Self::Canceled => "pairing_canceled",
            Self::Rejected => "pairing_rejected",
            Self::Conflict => "pairing_conflict",
            Self::Transient => "transient",
        }
    }
}

impl fmt::Display for PairingCycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.safe_code())
    }
}

impl std::error::Error for PairingCycleError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingJoinSubmission {
    pub pairing_id: PairingId,
    pub request_digest: Sha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingRequestReview {
    pub pairing_id: PairingId,
    pub device_id: DeviceId,
    pub device_name: String,
    pub platform: NativePlatform,
    pub requested_at_ms: u64,
    pub key_fingerprint: Sha256Digest,
    pub request_digest: Sha256Digest,
}

pub struct PairingApprovalAuthority<'a> {
    pub certificate_id: DeviceCertificateId,
    pub issuer_certificate_id: DeviceCertificateId,
    pub issuer_keys: &'a DeviceKeys,
}

impl fmt::Debug for PairingApprovalAuthority<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingApprovalAuthority")
            .field("certificate_id", &self.certificate_id)
            .field("issuer_certificate_id", &self.issuer_certificate_id)
            .field("authority_and_keys", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug)]
pub enum PairingDecisionInput<'a> {
    Approve(PairingApprovalAuthority<'a>),
    Reject,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PairingDecisionStatus {
    Approved { safety_number: PairingSafetyNumber },
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedPairingDecisionStatus {
    pub request_digest: Sha256Digest,
    pub safety_number: PairingSafetyNumber,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingJoinStatus {
    Pending { pairing_id: PairingId },
    AwaitingConfirmation { pairing_id: PairingId },
    Completed { pairing_id: PairingId },
    Rejected { pairing_id: PairingId },
    Canceled { pairing_id: PairingId },
}

/// Trusted daemon-owned access to the currently active workspace key material.
///
/// This capability belongs to the coordinator's dependency root. It must never be constructed
/// from approval IPC parameters or other untrusted request data.
pub trait PairingMaterialSource: Send + Sync {
    fn current_material(
        &self,
        vault: &mut Vault,
        device_keys: &DeviceKeys,
        scope: SyncScope,
    ) -> Result<WorkspacePairingMaterial, PairingCycleError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct VaultPairingMaterialSource;

impl PairingMaterialSource for VaultPairingMaterialSource {
    fn current_material(
        &self,
        vault: &mut Vault,
        device_keys: &DeviceKeys,
        scope: SyncScope,
    ) -> Result<WorkspacePairingMaterial, PairingCycleError> {
        let material = vault
            .trusted_workspace_material(device_keys)
            .map_err(map_vault_error)?;
        if material.scope() != scope {
            return Err(PairingCycleError::Conflict);
        }
        Ok(material)
    }
}

pub struct PairingCoordinator<C, M, J, A> {
    clock: C,
    material_source: M,
    join_transport: J,
    approval_transport: A,
}

impl<
    C: PairingClock,
    M: PairingMaterialSource,
    J: PairingJoinTransport,
    A: PairingApprovalTransport,
> PairingCoordinator<C, M, J, A>
{
    /// Constructs the pairing coordinator at the trusted daemon dependency root.
    ///
    /// Authenticated transport handles are moved into the coordinator so untrusted request code
    /// cannot poll raw approved payloads or substitute a per-call transport implementation.
    pub const fn new(
        clock: C,
        material_source: M,
        join_transport: J,
        approval_transport: A,
    ) -> Self {
        Self {
            clock,
            material_source,
            join_transport,
            approval_transport,
        }
    }

    pub fn create_invite(&self) -> Result<PairingInvite, PairingCycleError> {
        self.approval_transport
            .create_invite(self.clock.now_ms())
            .map_err(map_transport_error)
    }

    pub fn invite_status(
        &self,
        pairing_id: PairingId,
    ) -> Result<PairingInviteStatus, PairingCycleError> {
        self.approval_transport
            .invite_status(pairing_id, self.clock.now_ms())
            .map_err(map_transport_error)
    }

    pub fn cancel(&self, pairing_id: PairingId) -> Result<(), PairingCycleError> {
        self.approval_transport
            .cancel(pairing_id, self.clock.now_ms())
            .map_err(map_transport_error)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn join(
        &self,
        vault: &mut Vault,
        code: &PairingCode,
        device_id: DeviceId,
        device_name: &str,
        platform: NativePlatform,
        joiner_keys: &DeviceKeys,
    ) -> Result<PairingJoinSubmission, PairingCycleError> {
        let now_ms = self.clock.now_ms();
        let pairing_id = self
            .join_transport
            .resolve_code(code, now_ms)
            .map_err(map_transport_error)?;
        let signed_request = match vault
            .stored_pairing_join(pairing_id)
            .map_err(map_vault_error)?
        {
            Some(stored) => {
                let request = decode_pairing_request_v1(&stored.canonical_request)
                    .map_err(|_| PairingCycleError::Invalid)?;
                let verified =
                    verify_pairing_request(&request).map_err(|_| PairingCycleError::Invalid)?;
                if request.device_id != device_id
                    || request.device_name != device_name
                    || request.platform != platform
                    || request.signing_public_key != joiner_keys.signing_public_key()
                    || request.wrapping_public_key != joiner_keys.wrapping_public_key()
                {
                    return Err(PairingCycleError::Conflict);
                }
                verified
            }
            None => {
                let signed = SignedPairingRequest::build(
                    pairing_id,
                    device_id,
                    device_name,
                    platform,
                    joiner_keys,
                )
                .map_err(|_| PairingCycleError::Invalid)?;
                vault
                    .store_pairing_join_request(pairing_id, signed.canonical_bytes(), now_ms)
                    .map_err(map_vault_error)?;
                signed
            }
        };
        let receipt = self
            .join_transport
            .submit_request(pairing_id, signed_request.canonical_bytes(), now_ms)
            .map_err(map_transport_error)?;
        if receipt.pairing_id != pairing_id || receipt.request_digest != signed_request.digest() {
            return Err(PairingCycleError::Conflict);
        }
        Ok(PairingJoinSubmission {
            pairing_id,
            request_digest: signed_request.digest(),
        })
    }

    pub fn request_status(
        &self,
        pairing_id: PairingId,
    ) -> Result<Option<PairingRequestReview>, PairingCycleError> {
        let Some(stored) = self
            .approval_transport
            .request(pairing_id, self.clock.now_ms())
            .map_err(map_transport_error)?
        else {
            return Ok(None);
        };
        let request = decode_pairing_request_v1(&stored.canonical_bytes)
            .map_err(|_| PairingCycleError::Invalid)?;
        let verified = verify_pairing_request(&request).map_err(|_| PairingCycleError::Invalid)?;
        if stored.pairing_id != pairing_id
            || request.pairing_id != pairing_id
            || stored.request_digest != verified.digest()
            || verified.canonical_bytes() != stored.canonical_bytes
        {
            return Err(PairingCycleError::Conflict);
        }
        Ok(Some(PairingRequestReview {
            pairing_id,
            device_id: request.device_id,
            device_name: request.device_name.clone(),
            platform: request.platform,
            requested_at_ms: stored.requested_at_ms,
            key_fingerprint: pairing_request_fingerprint(&request),
            request_digest: verified.digest(),
        }))
    }

    pub fn decide(
        &self,
        vault: &mut Vault,
        pairing_id: PairingId,
        expected_request_digest: Sha256Digest,
        decision: PairingDecisionInput<'_>,
    ) -> Result<PairingDecisionStatus, PairingCycleError> {
        let now_ms = self.clock.now_ms();
        let stored = self
            .approval_transport
            .request(pairing_id, now_ms)
            .map_err(map_transport_error)?
            .ok_or(PairingCycleError::Conflict)?;
        let request = decode_pairing_request_v1(&stored.canonical_bytes)
            .map_err(|_| PairingCycleError::Invalid)?;
        let signed_request =
            verify_pairing_request(&request).map_err(|_| PairingCycleError::Invalid)?;
        if stored.pairing_id != pairing_id
            || signed_request.digest() != expected_request_digest
            || stored.request_digest != expected_request_digest
            || signed_request.canonical_bytes() != stored.canonical_bytes
        {
            return Err(PairingCycleError::Conflict);
        }
        match decision {
            PairingDecisionInput::Reject => {
                if vault
                    .pairing_approval_transcript(pairing_id)
                    .map_err(map_vault_error)?
                    .is_some()
                {
                    return Err(PairingCycleError::Conflict);
                }
                let receipt = self
                    .approval_transport
                    .decide(
                        PairingDecisionEnvelope::reject(pairing_id, expected_request_digest),
                        now_ms,
                    )
                    .map_err(map_transport_error)?;
                if receipt.pairing_id != pairing_id
                    || receipt.request_digest != expected_request_digest
                    || receipt.decision != PairingDecisionKind::Rejected
                    || receipt.approved_payload_digest.is_some()
                {
                    return Err(PairingCycleError::Conflict);
                }
                vault
                    .finish_pairing_decision(
                        pairing_id,
                        expected_request_digest,
                        PairingDecisionFinalState::Rejected,
                        receipt.decided_at_ms,
                    )
                    .map_err(map_vault_error)?;
                Ok(PairingDecisionStatus::Rejected)
            }
            PairingDecisionInput::Approve(authority) => {
                let material = self.material_source.current_material(
                    vault,
                    authority.issuer_keys,
                    stored.scope,
                )?;
                let issuer = vault
                    .device_certificate(authority.issuer_certificate_id)
                    .map_err(map_vault_error)?
                    .ok_or(PairingCycleError::Conflict)?;
                if issuer.state != DeviceCertificateState::Active
                    || authority.issuer_keys.signing_public_key()
                        != issuer.certificate.signing_public_key
                    || authority.issuer_keys.wrapping_public_key()
                        != issuer.certificate.wrapping_public_key
                    || material.scope().account_id != issuer.certificate.account_id
                    || material.scope().workspace_id != issuer.certificate.workspace_id
                    || material.control_epoch() != issuer.certificate.control_epoch
                    || stored.scope != material.scope()
                {
                    return Err(PairingCycleError::Conflict);
                }
                if let Some(existing) = vault
                    .accepted_pairing_approval(pairing_id)
                    .map_err(map_vault_error)?
                {
                    require_existing_approval_authority(
                        &existing,
                        expected_request_digest,
                        &authority,
                        &issuer,
                        &material,
                    )?;
                    return Ok(PairingDecisionStatus::Approved {
                        safety_number: existing.approval.safety_number().clone(),
                    });
                }
                if let Some(existing) = vault
                    .pending_pairing_approvals()
                    .map_err(map_vault_error)?
                    .into_iter()
                    .find(|stored| stored.pairing_id == pairing_id)
                {
                    require_existing_approval_authority(
                        &existing,
                        expected_request_digest,
                        &authority,
                        &issuer,
                        &material,
                    )?;
                    let receipt = self
                        .approval_transport
                        .decide(
                            PairingDecisionEnvelope::approve(
                                pairing_id,
                                expected_request_digest,
                                existing.approval.canonical_bytes().to_vec(),
                            ),
                            now_ms,
                        )
                        .map_err(map_transport_error)?;
                    if receipt.pairing_id != pairing_id
                        || receipt.request_digest != expected_request_digest
                        || receipt.decision != PairingDecisionKind::Approved
                        || receipt.approved_payload_digest != Some(existing.approved_payload_sha256)
                    {
                        return Err(PairingCycleError::Conflict);
                    }
                    vault
                        .finish_pairing_approval(
                            pairing_id,
                            existing.approved_payload_sha256,
                            receipt.decided_at_ms,
                        )
                        .map_err(map_vault_error)?;
                    return Ok(PairingDecisionStatus::Approved {
                        safety_number: existing.approval.safety_number().clone(),
                    });
                }
                let grant = build_pairing_grant(
                    &signed_request,
                    &PairingGrantApproval {
                        request_digest: expected_request_digest,
                        certificate_id: authority.certificate_id,
                        scope: material.scope(),
                        control_epoch: material.control_epoch(),
                        issuer_certificate: issuer.certificate.clone(),
                    },
                    authority.issuer_keys,
                    &material.bundle,
                )
                .map_err(|_| PairingCycleError::Invalid)?;
                let payload = build_pairing_approved_payload_v1(
                    &signed_request,
                    grant,
                    authority.issuer_certificate_id,
                    issuer.certificate.clone(),
                    issuer.display.device_name.clone(),
                    issuer.display.platform,
                )
                .map_err(|_| PairingCycleError::Invalid)?;
                let canonical = encode_pairing_approved_payload_v1(&payload)
                    .map_err(|_| PairingCycleError::Invalid)?;
                let approval = inspect_pairing_approval(&canonical, &signed_request)
                    .map_err(|_| PairingCycleError::Invalid)?;
                vault
                    .prepare_pairing_approval(&signed_request, &approval, now_ms)
                    .map_err(map_vault_error)?;
                let receipt = self
                    .approval_transport
                    .decide(
                        PairingDecisionEnvelope::approve(
                            pairing_id,
                            expected_request_digest,
                            canonical.clone(),
                        ),
                        now_ms,
                    )
                    .map_err(map_transport_error)?;
                let payload_hash = Sha256Digest(Sha256::digest(&canonical).into());
                if receipt.pairing_id != pairing_id
                    || receipt.request_digest != expected_request_digest
                    || receipt.decision != PairingDecisionKind::Approved
                    || receipt.approved_payload_digest != Some(payload_hash)
                {
                    return Err(PairingCycleError::Conflict);
                }
                vault
                    .finish_pairing_approval(pairing_id, payload_hash, receipt.decided_at_ms)
                    .map_err(map_vault_error)?;
                Ok(PairingDecisionStatus::Approved {
                    safety_number: approval.safety_number().clone(),
                })
            }
        }
    }

    pub fn join_status(
        &self,
        vault: &mut Vault,
        pairing_id: PairingId,
    ) -> Result<PairingJoinStatus, PairingCycleError> {
        if vault
            .pairing_approval_transcript(pairing_id)
            .map_err(map_vault_error)?
            .filter(|stored| stored.state == crate::vault::PairingApprovalState::Completed)
            .is_some()
        {
            return Ok(PairingJoinStatus::Completed { pairing_id });
        }
        if vault
            .awaiting_pairing_confirmation(pairing_id)
            .map_err(map_vault_error)?
            .is_some()
        {
            return Ok(PairingJoinStatus::AwaitingConfirmation { pairing_id });
        }
        let stored = vault
            .stored_pairing_join(pairing_id)
            .map_err(map_vault_error)?
            .ok_or(PairingCycleError::Invalid)?;
        let result = self
            .join_transport
            .result(pairing_id, stored.request_sha256, self.clock.now_ms())
            .map_err(map_transport_error)?;
        match result {
            PairingResult::Pending => Ok(PairingJoinStatus::Pending { pairing_id }),
            PairingResult::Canceled => Ok(PairingJoinStatus::Canceled { pairing_id }),
            PairingResult::Rejected { receipt } => {
                if receipt.pairing_id != pairing_id
                    || receipt.request_digest != stored.request_sha256
                    || receipt.decision != PairingDecisionKind::Rejected
                    || receipt.approved_payload_digest.is_some()
                {
                    return Err(PairingCycleError::Conflict);
                }
                Ok(PairingJoinStatus::Rejected { pairing_id })
            }
            PairingResult::Approved(approved) => {
                let canonical_approved_payload = approved.canonical_approved_payload();
                let receipt = approved.receipt();
                let expected_hash = Sha256Digest(Sha256::digest(canonical_approved_payload).into());
                if receipt.pairing_id != pairing_id
                    || receipt.request_digest != stored.request_sha256
                    || receipt.decision != PairingDecisionKind::Approved
                    || receipt.approved_payload_digest != Some(expected_hash)
                {
                    return Err(PairingCycleError::Conflict);
                }
                let request = decode_pairing_request_v1(&stored.canonical_request)
                    .map_err(|_| PairingCycleError::Invalid)?;
                let signed_request =
                    verify_pairing_request(&request).map_err(|_| PairingCycleError::Invalid)?;
                let approval =
                    inspect_pairing_approval(canonical_approved_payload, &signed_request)
                        .map_err(|_| PairingCycleError::Invalid)?;
                vault
                    .store_awaiting_pairing_confirmation(
                        &stored.canonical_request,
                        &approval,
                        self.clock.now_ms(),
                    )
                    .map_err(map_vault_error)?;
                Ok(PairingJoinStatus::AwaitingConfirmation { pairing_id })
            }
        }
    }

    pub fn confirm_join(
        &self,
        vault: &mut Vault,
        pairing_id: PairingId,
        entered_safety_number: &str,
        joiner_keys: &DeviceKeys,
    ) -> Result<WorkspacePairingMaterial, PairingCycleError> {
        if let Some(stored) = vault
            .completed_pairing_transcript(pairing_id)
            .map_err(map_vault_error)?
        {
            if stored.approval.safety_number().as_str() != entered_safety_number {
                return Err(PairingCycleError::Invalid);
            }
            let confirmed = confirm_and_open_pairing_approval(
                &stored.approval,
                entered_safety_number,
                &stored.signed_request,
                joiner_keys,
            )
            .map_err(|_| PairingCycleError::Invalid)?;
            return Ok(WorkspacePairingMaterial {
                bundle: confirmed.into_key_bundle(),
            });
        }
        let stored = vault
            .awaiting_pairing_confirmation(pairing_id)
            .map_err(map_vault_error)?
            .ok_or(PairingCycleError::Invalid)?;
        let confirmed = confirm_and_open_pairing_approval(
            &stored.approval,
            entered_safety_number,
            &stored.signed_request,
            joiner_keys,
        )
        .map_err(|_| PairingCycleError::Invalid)?;
        vault
            .finish_confirmed_pairing_join(&confirmed, self.clock.now_ms())
            .map_err(map_vault_error)?;
        Ok(WorkspacePairingMaterial {
            bundle: confirmed.into_key_bundle(),
        })
    }

    pub fn completed_material(
        &self,
        vault: &Vault,
        pairing_id: PairingId,
        joiner_keys: &DeviceKeys,
    ) -> Result<Option<WorkspacePairingMaterial>, PairingCycleError> {
        vault
            .completed_pairing_approval(pairing_id, joiner_keys)
            .map(|value| {
                value.map(|confirmed| WorkspacePairingMaterial {
                    bundle: confirmed.into_key_bundle(),
                })
            })
            .map_err(map_vault_error)
    }

    /// Returns only the approver-visible decision projection recovered from the exact durable
    /// transcript. Joining callers are separated at the daemon boundary and never receive it.
    pub fn accepted_decision_status(
        &self,
        vault: &Vault,
        pairing_id: PairingId,
    ) -> Result<Option<AcceptedPairingDecisionStatus>, PairingCycleError> {
        vault
            .accepted_pairing_approval(pairing_id)
            .map(|stored| {
                stored.map(|stored| AcceptedPairingDecisionStatus {
                    request_digest: stored.signed_request.digest(),
                    safety_number: stored.approval.safety_number().clone(),
                })
            })
            .map_err(map_vault_error)
    }

    pub fn resume_prepared_decisions(&self, vault: &mut Vault) -> Result<usize, PairingCycleError> {
        let pending = vault.pending_pairing_approvals().map_err(map_vault_error)?;
        let mut resumed = 0;
        for stored in pending {
            let pairing_id = stored.pairing_id;
            let request_digest = stored.signed_request.digest();
            let receipt = self
                .approval_transport
                .decide(
                    PairingDecisionEnvelope::approve(
                        pairing_id,
                        request_digest,
                        stored.approval.canonical_bytes().to_vec(),
                    ),
                    self.clock.now_ms(),
                )
                .map_err(map_transport_error)?;
            if receipt.pairing_id != pairing_id
                || receipt.request_digest != request_digest
                || receipt.decision != PairingDecisionKind::Approved
                || receipt.approved_payload_digest != Some(stored.approved_payload_sha256)
            {
                return Err(PairingCycleError::Conflict);
            }
            vault
                .finish_pairing_approval(
                    pairing_id,
                    stored.approved_payload_sha256,
                    receipt.decided_at_ms,
                )
                .map_err(map_vault_error)?;
            resumed += 1;
        }
        Ok(resumed)
    }
}

fn require_existing_approval_authority(
    stored: &crate::vault::StoredPairingApproval,
    expected_request_digest: Sha256Digest,
    authority: &PairingApprovalAuthority<'_>,
    issuer: &StoredDeviceCertificate,
    material: &WorkspacePairingMaterial,
) -> Result<(), PairingCycleError> {
    let payload = stored.approval.approved_payload();
    if stored.signed_request.digest() != expected_request_digest
        || payload.grant.request_digest != expected_request_digest
        || payload.grant.certificate_id != authority.certificate_id
        || payload.issuer_certificate_id != authority.issuer_certificate_id
        || payload.issuer_certificate != issuer.certificate
        || payload.issuer_device_name != issuer.display.device_name
        || payload.issuer_platform != issuer.display.platform
        || payload.grant.certificate.account_id != material.scope().account_id
        || payload.grant.certificate.workspace_id != material.scope().workspace_id
        || payload.grant.certificate.control_epoch != material.control_epoch()
        || payload.grant.key_epoch != material.key_epoch()
        || authority.issuer_keys.signing_public_key() != issuer.certificate.signing_public_key
        || authority.issuer_keys.wrapping_public_key() != issuer.certificate.wrapping_public_key
    {
        return Err(PairingCycleError::Conflict);
    }
    Ok(())
}

fn map_transport_error(error: PairingTransportError) -> PairingCycleError {
    match error {
        PairingTransportError::Invalid
        | PairingTransportError::Exhausted
        | PairingTransportError::Unauthorized => PairingCycleError::Invalid,
        PairingTransportError::Expired => PairingCycleError::Expired,
        PairingTransportError::Canceled => PairingCycleError::Canceled,
        PairingTransportError::Rejected => PairingCycleError::Rejected,
        PairingTransportError::Conflict => PairingCycleError::Conflict,
        PairingTransportError::Transient => PairingCycleError::Transient,
    }
}

fn map_vault_error(error: VaultError) -> PairingCycleError {
    match error {
        VaultError::OperationConflict => PairingCycleError::Conflict,
        VaultError::Database(_) | VaultError::Credential(_) | VaultError::MissingKey => {
            PairingCycleError::Transient
        }
        _ => PairingCycleError::Invalid,
    }
}
