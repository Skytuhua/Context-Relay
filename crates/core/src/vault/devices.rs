use std::str::FromStr;

use context_relay_protocol::{
    DeviceCertificateId, NativePlatform, PairingId, Sha256Digest, decode_pairing_request_v1,
};
use rusqlite::{OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};

use crate::{
    crypto::{DeviceCertificateV1, DeviceKeys},
    devices::crypto::{
        ConfirmedPairingApproval, PairingGrant, SignedPairingRequest, UnconfirmedPairingGrant,
        confirm_and_open_pairing_approval, decode_device_certificate_v1, decode_pairing_grant_v1,
        encode_device_certificate_v1, encode_pairing_grant_v1, inspect_pairing_approval,
        verify_pairing_request,
    },
    sync::SyncScope,
};

use super::{CommitDisposition, Vault, VaultError};

type StoredJoinRow = (
    Vec<u8>,
    Vec<u8>,
    Option<String>,
    Option<Vec<u8>>,
    String,
    Option<i64>,
);
type StoredDecisionRow = (
    Vec<u8>,
    String,
    Option<i64>,
    Option<String>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);
type StoredApprovalTranscriptRow = (
    String,
    String,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<i64>,
    i64,
    Option<i64>,
);
type ApprovalDecisionLinkRow = (Vec<u8>, String, Vec<u8>, Vec<u8>, i64, Option<i64>, String);
type PendingPairingJoinRow = (
    Vec<u8>,
    Vec<u8>,
    Option<String>,
    Option<Vec<u8>>,
    String,
    Option<String>,
    Option<i64>,
);
type PairingJoinTranscriptRow = (
    Vec<u8>,
    Vec<u8>,
    Option<String>,
    Option<String>,
    Option<Vec<u8>>,
    String,
    i64,
    Option<i64>,
);
type ActiveCertificateRow = (
    String,
    String,
    String,
    String,
    String,
    Vec<u8>,
    Vec<u8>,
    String,
);
type DecisionCertificateRow = (Vec<u8>, Vec<u8>, String, String, String, String);
#[cfg(feature = "test-support")]
type CompletionCertificateRow = (
    Vec<u8>,
    Vec<u8>,
    String,
    String,
    String,
    String,
    String,
    String,
);
#[cfg(feature = "test-support")]
type CompletionReplayCertificateRow = (
    Vec<u8>,
    Vec<u8>,
    String,
    String,
    String,
    String,
    String,
    String,
    i64,
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceCertificateState {
    Active,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceDisplayMetadata {
    pub device_name: String,
    pub platform: NativePlatform,
}

impl DeviceDisplayMetadata {
    pub(super) fn validate(&self) -> Result<(), VaultError> {
        if self.device_name.is_empty() || self.device_name.len() > 256 {
            return Err(VaultError::Validation(
                "invalid device display name".to_owned(),
            ));
        }
        Ok(())
    }

    pub(super) const fn platform_value(&self) -> &'static str {
        match self.platform {
            NativePlatform::Windows => "windows",
            NativePlatform::Macos => "macos",
        }
    }
}

impl DeviceCertificateState {
    const fn database_value(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }

    fn parse(value: &str) -> Result<Self, VaultError> {
        match value {
            "active" => Ok(Self::Active),
            "revoked" => Ok(Self::Revoked),
            _ => Err(VaultError::Validation(
                "invalid device certificate state".to_owned(),
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredDeviceCertificate {
    pub certificate_id: DeviceCertificateId,
    pub certificate: DeviceCertificateV1,
    pub state: DeviceCertificateState,
    pub display: DeviceDisplayMetadata,
    pub stored_at_ms: u64,
    pub canonical_bytes: Vec<u8>,
    pub canonical_sha256: Sha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedPairingDecision {
    pub pairing_id: PairingId,
    pub request_digest: Sha256Digest,
    pub certificate_id: DeviceCertificateId,
    pub canonical_grant: Vec<u8>,
    pub grant_sha256: Sha256Digest,
    pub prepared_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingDecisionFinalState {
    Accepted,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredPairingJoin {
    pub pairing_id: PairingId,
    pub canonical_request: Vec<u8>,
    pub request_sha256: Sha256Digest,
    pub certificate_id: Option<DeviceCertificateId>,
    pub wrapped_key_bundle: Option<Vec<u8>>,
    pub completed: bool,
    pub stored_at_ms: u64,
    pub completed_at_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingApprovalRole {
    Approver,
    Joiner,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingApprovalState {
    Prepared,
    Accepted,
    AwaitingConfirmation,
    Completed,
    LegacyUnconfirmed,
}

#[cfg(feature = "test-support")]
#[derive(Clone, Eq, PartialEq)]
pub struct StoredPairingApproval {
    pub pairing_id: PairingId,
    pub role: PairingApprovalRole,
    pub state: PairingApprovalState,
    pub signed_request: SignedPairingRequest,
    pub approval: UnconfirmedPairingGrant,
    pub approved_payload_sha256: Sha256Digest,
    pub stored_at_ms: u64,
    pub transitioned_at_ms: Option<u64>,
}

#[cfg(not(feature = "test-support"))]
/// Opaque pairing transcript returned by the normal-build Vault API.
///
/// Safety-transcript inputs are available only to the in-crate coordinator.
///
/// ```compile_fail
/// use context_relay_core::vault::StoredPairingApproval;
///
/// fn derive_safety_input(stored: &StoredPairingApproval) {
///     let _ = stored.approved_payload_sha256;
/// }
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct StoredPairingApproval {
    pub(crate) pairing_id: PairingId,
    pub(crate) role: PairingApprovalRole,
    pub(crate) state: PairingApprovalState,
    pub(crate) signed_request: SignedPairingRequest,
    pub(crate) approval: UnconfirmedPairingGrant,
    pub(crate) approved_payload_sha256: Sha256Digest,
    pub(crate) stored_at_ms: u64,
    pub(crate) transitioned_at_ms: Option<u64>,
}

impl std::fmt::Debug for StoredPairingApproval {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoredPairingApproval")
            .field("pairing_id", &self.pairing_id)
            .field("role", &self.role)
            .field("state", &self.state)
            .field("canonical_request_approval_and_transcript", &"[REDACTED]")
            .finish()
    }
}

impl Vault {
    pub fn pairing_approval_transcript(
        &self,
        pairing_id: PairingId,
    ) -> Result<Option<StoredPairingApproval>, VaultError> {
        let row = self
            .connection
            .query_row(
                "SELECT role, state, canonical_request, request_sha256,
                        canonical_approved_payload, approved_payload_sha256,
                        transcript_sha256, issuer_certificate_id, account_id, workspace_id,
                        control_epoch, key_epoch, stored_at_ms, transitioned_at_ms
                 FROM pairing_approval_transcripts WHERE pairing_id = ?1",
                [pairing_id.to_string()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                        row.get(10)?,
                        row.get(11)?,
                        row.get(12)?,
                        row.get(13)?,
                    ))
                },
            )
            .optional()?;
        row.map(|row| decode_approval_transcript(pairing_id, row))
            .transpose()
    }

    pub fn prepare_pairing_approval(
        &mut self,
        signed_request: &SignedPairingRequest,
        approval: &UnconfirmedPairingGrant,
        prepared_at_ms: u64,
    ) -> Result<CommitDisposition, VaultError> {
        let reverified = inspect_pairing_approval(approval.canonical_bytes(), signed_request)
            .map_err(crypto_error)?;
        if &reverified != approval {
            return Err(VaultError::Validation(
                "pairing approval changed after inspection".to_owned(),
            ));
        }
        let payload = approval.approved_payload();
        let pairing_id = payload.grant.pairing_id;
        if let Some(existing) = self.pairing_approval_transcript(pairing_id)? {
            let exact = existing.role == PairingApprovalRole::Approver
                && matches!(
                    existing.state,
                    PairingApprovalState::Prepared | PairingApprovalState::Accepted
                )
                && existing.signed_request == *signed_request
                && existing.approval == *approval
                && existing.stored_at_ms == prepared_at_ms;
            return if exact {
                Ok(CommitDisposition::ExactReplay)
            } else {
                Err(VaultError::OperationConflict)
            };
        }
        let issuer_display = DeviceDisplayMetadata {
            device_name: payload.issuer_device_name.clone(),
            platform: payload.issuer_platform,
        };
        let child_display = DeviceDisplayMetadata {
            device_name: signed_request.request().device_name.clone(),
            platform: signed_request.request().platform,
        };
        issuer_display.validate()?;
        child_display.validate()?;
        let canonical_grant = encode_pairing_grant_v1(&payload.grant).map_err(crypto_error)?;
        let canonical_grant_sha256 = sha256(&canonical_grant);
        let approved_payload_sha256 = sha256(approval.canonical_bytes());
        let transaction = self.connection.transaction()?;
        ensure_active_certificate_tx(
            &transaction,
            payload.issuer_certificate_id,
            &payload.issuer_certificate,
            &issuer_display,
            prepared_at_ms,
            false,
        )?;
        ensure_active_certificate_tx(
            &transaction,
            payload.grant.certificate_id,
            &payload.grant.certificate,
            &child_display,
            prepared_at_ms,
            true,
        )?;
        let existing_decision: Option<String> = transaction
            .query_row(
                "SELECT pairing_id FROM pairing_decisions WHERE pairing_id = ?1",
                [pairing_id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        if existing_decision.is_some() {
            return conflict(transaction);
        }
        transaction.execute(
            "INSERT INTO pairing_decisions(
                pairing_id, request_digest, certificate_id, canonical_grant, grant_sha256,
                prepared_at_ms, state
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'prepared')",
            params![
                pairing_id.to_string(),
                signed_request.digest().0.as_slice(),
                payload.grant.certificate_id.to_string(),
                canonical_grant,
                canonical_grant_sha256.0.as_slice(),
                timestamp_to_db(prepared_at_ms)?,
            ],
        )?;
        transaction.execute(
            "INSERT INTO pairing_approval_transcripts(
                pairing_id, role, state, canonical_request, request_sha256,
                canonical_approved_payload, approved_payload_sha256, transcript_sha256,
                issuer_certificate_id, account_id, workspace_id, control_epoch, key_epoch,
                stored_at_ms
             ) VALUES (?1, 'approver', 'prepared', ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                pairing_id.to_string(),
                signed_request.canonical_bytes(),
                signed_request.digest().0.as_slice(),
                approval.canonical_bytes(),
                approved_payload_sha256.0.as_slice(),
                approval.transcript_digest().0.as_slice(),
                payload.issuer_certificate_id.to_string(),
                payload.grant.certificate.account_id.to_string(),
                payload.grant.certificate.workspace_id.to_string(),
                i64::from(payload.grant.certificate.control_epoch),
                i64::from(payload.grant.key_epoch),
                timestamp_to_db(prepared_at_ms)?,
            ],
        )?;
        transaction.commit()?;
        Ok(CommitDisposition::Inserted)
    }

    pub fn pending_pairing_approvals(&self) -> Result<Vec<StoredPairingApproval>, VaultError> {
        let mut statement = self.connection.prepare(
            "SELECT pairing_id FROM pairing_approval_transcripts
             WHERE role = 'approver' AND state = 'prepared' ORDER BY pairing_id",
        )?;
        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        ids.into_iter()
            .map(|value| self.validated_approver_transcript(parse_id(&value)?))
            .collect()
    }

    pub fn accepted_pairing_approval(
        &self,
        pairing_id: PairingId,
    ) -> Result<Option<StoredPairingApproval>, VaultError> {
        let Some(stored) = self.pairing_approval_transcript(pairing_id)? else {
            return Ok(None);
        };
        if stored.role != PairingApprovalRole::Approver
            || stored.state != PairingApprovalState::Accepted
        {
            return Ok(None);
        }
        self.validated_approver_transcript(pairing_id).map(Some)
    }

    pub fn finish_pairing_approval(
        &mut self,
        pairing_id: PairingId,
        approved_payload_sha256: Sha256Digest,
        accepted_at_ms: u64,
    ) -> Result<CommitDisposition, VaultError> {
        let stored = self.validated_approver_transcript(pairing_id)?;
        if stored.approved_payload_sha256 != approved_payload_sha256 {
            return Err(VaultError::OperationConflict);
        }
        match stored.state {
            PairingApprovalState::Accepted => {
                return if stored.transitioned_at_ms == Some(accepted_at_ms) {
                    Ok(CommitDisposition::ExactReplay)
                } else {
                    Err(VaultError::OperationConflict)
                };
            }
            PairingApprovalState::Prepared => {}
            _ => return Err(VaultError::OperationConflict),
        }
        let transaction = self.connection.transaction()?;
        let decision_changed = transaction.execute(
            "UPDATE pairing_decisions SET state = 'accepted', finished_at_ms = ?2
             WHERE pairing_id = ?1 AND state = 'prepared' AND finished_at_ms IS NULL",
            params![pairing_id.to_string(), timestamp_to_db(accepted_at_ms)?],
        )?;
        let transcript_changed = transaction.execute(
            "UPDATE pairing_approval_transcripts
             SET state = 'accepted', transitioned_at_ms = ?2
             WHERE pairing_id = ?1 AND role = 'approver' AND state = 'prepared'
                AND transitioned_at_ms IS NULL",
            params![pairing_id.to_string(), timestamp_to_db(accepted_at_ms)?],
        )?;
        if decision_changed != 1 || transcript_changed != 1 {
            return conflict(transaction);
        }
        transaction.commit()?;
        Ok(CommitDisposition::Inserted)
    }

    fn validated_approver_transcript(
        &self,
        pairing_id: PairingId,
    ) -> Result<StoredPairingApproval, VaultError> {
        let stored = self
            .pairing_approval_transcript(pairing_id)?
            .ok_or_else(|| VaultError::Validation("missing pairing approval".to_owned()))?;
        if stored.role != PairingApprovalRole::Approver
            || !matches!(
                stored.state,
                PairingApprovalState::Prepared | PairingApprovalState::Accepted
            )
        {
            return Err(VaultError::Validation(
                "invalid approver transcript state".to_owned(),
            ));
        }
        let decision: Option<ApprovalDecisionLinkRow> = self
            .connection
            .query_row(
                "SELECT request_digest, certificate_id, canonical_grant, grant_sha256,
                        prepared_at_ms, finished_at_ms, state
                 FROM pairing_decisions WHERE pairing_id = ?1",
                [pairing_id.to_string()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            request_digest,
            certificate_id,
            canonical_grant,
            grant_sha256,
            prepared_at_ms,
            finished_at_ms,
            decision_state,
        )) = decision
        else {
            return Err(VaultError::Validation(
                "missing pairing decision".to_owned(),
            ));
        };
        let payload = stored.approval.approved_payload();
        let expected_grant = encode_pairing_grant_v1(&payload.grant).map_err(crypto_error)?;
        let expected_state = match stored.state {
            PairingApprovalState::Prepared => "prepared",
            PairingApprovalState::Accepted => "accepted",
            _ => unreachable!("approver state was checked"),
        };
        if request_digest.as_slice() != stored.signed_request.digest().0
            || certificate_id != payload.grant.certificate_id.to_string()
            || canonical_grant != expected_grant
            || grant_sha256.as_slice() != sha256(&canonical_grant).0
            || timestamp_from_db(prepared_at_ms)? != stored.stored_at_ms
            || finished_at_ms.map(timestamp_from_db).transpose()? != stored.transitioned_at_ms
            || decision_state != expected_state
        {
            return Err(VaultError::Validation(
                "pairing decision metadata mismatch".to_owned(),
            ));
        }
        let issuer = self
            .device_certificate(payload.issuer_certificate_id)?
            .ok_or_else(|| {
                VaultError::Validation("missing pairing issuer certificate".to_owned())
            })?;
        let child = self
            .device_certificate(payload.grant.certificate_id)?
            .ok_or_else(|| {
                VaultError::Validation("missing pairing child certificate".to_owned())
            })?;
        if issuer.certificate != payload.issuer_certificate
            || issuer.state != DeviceCertificateState::Active
            || issuer.display.device_name != payload.issuer_device_name
            || issuer.display.platform != payload.issuer_platform
            || child.certificate != payload.grant.certificate
            || child.state != DeviceCertificateState::Active
            || child.display.device_name != stored.signed_request.request().device_name
            || child.display.platform != stored.signed_request.request().platform
        {
            return Err(VaultError::Validation(
                "pairing certificate graph mismatch".to_owned(),
            ));
        }
        Ok(stored)
    }

    pub fn store_awaiting_pairing_confirmation(
        &mut self,
        canonical_request: &[u8],
        approval: &UnconfirmedPairingGrant,
        stored_at_ms: u64,
    ) -> Result<CommitDisposition, VaultError> {
        let request = decode_pairing_request_v1(canonical_request)
            .map_err(|_| VaultError::Validation("invalid canonical pairing request".to_owned()))?;
        let verified = verify_pairing_request(&request).map_err(crypto_error)?;
        let reverified = inspect_pairing_approval(approval.canonical_bytes(), &verified)
            .map_err(crypto_error)?;
        let payload = reverified.approved_payload();
        if verified.canonical_bytes() != canonical_request
            || &reverified != approval
            || payload.grant.pairing_id != request.pairing_id
            || payload.grant.request_digest != verified.digest()
        {
            return Err(VaultError::Validation(
                "approval does not bind request".to_owned(),
            ));
        }
        if let Some(existing) = self.pairing_approval_transcript(request.pairing_id)? {
            let exact = existing.role == PairingApprovalRole::Joiner
                && matches!(
                    existing.state,
                    PairingApprovalState::AwaitingConfirmation | PairingApprovalState::Completed
                )
                && existing.signed_request.canonical_bytes() == canonical_request
                && existing.approval == *approval
                && existing.stored_at_ms == stored_at_ms;
            return if exact {
                Ok(CommitDisposition::ExactReplay)
            } else {
                Err(VaultError::OperationConflict)
            };
        }
        let transaction = self.connection.transaction()?;
        let stored_join: Option<PendingPairingJoinRow> = transaction
            .query_row(
                "SELECT canonical_request, request_sha256, certificate_id, wrapped_key_bundle,
                        state, issuer_certificate_id, completed_at_ms
                 FROM pairing_joins WHERE pairing_id = ?1",
                [request.pairing_id.to_string()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .optional()?;
        let Some((stored_request, request_hash, None, None, state, None, None)) = stored_join
        else {
            return conflict(transaction);
        };
        if stored_request != canonical_request
            || request_hash.as_slice() != verified.digest().0
            || state != "stored"
        {
            return conflict(transaction);
        }
        let conflicting_certificate: Option<String> = transaction
            .query_row(
                "SELECT certificate_id FROM device_certificates
                 WHERE certificate_id IN (?1, ?2)
                    OR (account_id = ?3 AND workspace_id = ?4 AND device_id IN (?5, ?6))
                 LIMIT 1",
                params![
                    payload.issuer_certificate_id.to_string(),
                    payload.grant.certificate_id.to_string(),
                    payload.grant.certificate.account_id.to_string(),
                    payload.grant.certificate.workspace_id.to_string(),
                    payload.issuer_certificate.device_id.to_string(),
                    payload.grant.certificate.device_id.to_string(),
                ],
                |row| row.get(0),
            )
            .optional()?;
        if conflicting_certificate.is_some() {
            return conflict(transaction);
        }
        let digest = sha256(approval.canonical_bytes());
        transaction.execute(
            "INSERT INTO pairing_approval_transcripts(pairing_id, role, state, canonical_request, request_sha256, canonical_approved_payload, approved_payload_sha256, transcript_sha256, issuer_certificate_id, account_id, workspace_id, control_epoch, key_epoch, stored_at_ms)
             VALUES (?1, 'joiner', 'awaiting_confirmation', ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![request.pairing_id.to_string(), canonical_request, verified.digest().0.as_slice(), approval.canonical_bytes(), digest.0.as_slice(), approval.transcript_digest().0.as_slice(), payload.issuer_certificate_id.to_string(), payload.grant.certificate.account_id.to_string(), payload.grant.certificate.workspace_id.to_string(), payload.grant.certificate.control_epoch, payload.grant.key_epoch, timestamp_to_db(stored_at_ms)?]
        )?;
        transaction.commit()?;
        Ok(CommitDisposition::Inserted)
    }

    pub fn awaiting_pairing_confirmation(
        &self,
        pairing_id: PairingId,
    ) -> Result<Option<StoredPairingApproval>, VaultError> {
        let Some(stored) = self.pairing_approval_transcript(pairing_id)? else {
            return Ok(None);
        };
        if stored.role != PairingApprovalRole::Joiner
            || stored.state != PairingApprovalState::AwaitingConfirmation
        {
            return Ok(None);
        }
        self.validated_joiner_transcript(pairing_id).map(Some)
    }

    pub fn finish_confirmed_pairing_join(
        &mut self,
        confirmed: &ConfirmedPairingApproval,
        completed_at_ms: u64,
    ) -> Result<CommitDisposition, VaultError> {
        let payload = confirmed.approved_payload();
        let pairing_id = payload.grant.pairing_id;
        let stored = self.validated_joiner_transcript(pairing_id)?;
        if stored.approval.canonical_bytes() != confirmed.canonical_bytes()
            || stored.approval.transcript_digest() != confirmed.transcript_digest()
            || stored.approval.approved_payload() != payload
            || stored.signed_request.digest() != payload.grant.request_digest
            || confirmed.key_bundle().account_id() != payload.grant.certificate.account_id
            || confirmed.key_bundle().workspace_id() != payload.grant.certificate.workspace_id
            || confirmed.key_bundle().control_epoch() != payload.grant.certificate.control_epoch
            || confirmed.key_bundle().key_epoch() != payload.grant.key_epoch
        {
            return Err(VaultError::OperationConflict);
        }
        if stored.state == PairingApprovalState::Completed {
            return if stored.transitioned_at_ms == Some(completed_at_ms) {
                Ok(CommitDisposition::ExactReplay)
            } else {
                Err(VaultError::OperationConflict)
            };
        }
        if stored.state != PairingApprovalState::AwaitingConfirmation {
            return Err(VaultError::OperationConflict);
        }
        let issuer_display = DeviceDisplayMetadata {
            device_name: payload.issuer_device_name.clone(),
            platform: payload.issuer_platform,
        };
        let child_display = DeviceDisplayMetadata {
            device_name: stored.signed_request.request().device_name.clone(),
            platform: stored.signed_request.request().platform,
        };
        let canonical_grant = encode_pairing_grant_v1(&payload.grant).map_err(crypto_error)?;
        let transaction = self.connection.transaction()?;
        ensure_active_certificate_tx(
            &transaction,
            payload.issuer_certificate_id,
            &payload.issuer_certificate,
            &issuer_display,
            completed_at_ms,
            true,
        )?;
        ensure_active_certificate_tx(
            &transaction,
            payload.grant.certificate_id,
            &payload.grant.certificate,
            &child_display,
            completed_at_ms,
            true,
        )?;
        let join_changed = transaction.execute(
            "UPDATE pairing_joins
             SET certificate_id = ?2, issuer_certificate_id = ?3, wrapped_key_bundle = ?4,
                 state = 'completed', completed_at_ms = ?5
             WHERE pairing_id = ?1 AND state = 'stored' AND certificate_id IS NULL
                AND issuer_certificate_id IS NULL AND wrapped_key_bundle IS NULL
                AND completed_at_ms IS NULL",
            params![
                pairing_id.to_string(),
                payload.grant.certificate_id.to_string(),
                payload.issuer_certificate_id.to_string(),
                canonical_grant,
                timestamp_to_db(completed_at_ms)?,
            ],
        )?;
        let transcript_changed = transaction.execute(
            "UPDATE pairing_approval_transcripts
             SET state = 'completed', transitioned_at_ms = ?2
             WHERE pairing_id = ?1 AND role = 'joiner' AND state = 'awaiting_confirmation'
                AND transitioned_at_ms IS NULL",
            params![pairing_id.to_string(), timestamp_to_db(completed_at_ms)?],
        )?;
        if join_changed != 1 || transcript_changed != 1 {
            return conflict(transaction);
        }
        transaction.commit()?;
        Ok(CommitDisposition::Inserted)
    }

    pub fn completed_pairing_approval(
        &self,
        pairing_id: PairingId,
        joiner_keys: &DeviceKeys,
    ) -> Result<Option<ConfirmedPairingApproval>, VaultError> {
        let Some(stored) = self.completed_pairing_transcript(pairing_id)? else {
            return Ok(None);
        };
        if joiner_keys.signing_public_key() != stored.signed_request.request().signing_public_key
            || joiner_keys.wrapping_public_key()
                != stored.signed_request.request().wrapping_public_key
        {
            return Err(VaultError::Validation(
                "joining device keys do not match pairing request".to_owned(),
            ));
        }
        confirm_and_open_pairing_approval(
            &stored.approval,
            stored.approval.safety_number().as_str(),
            &stored.signed_request,
            joiner_keys,
        )
        .map(Some)
        .map_err(|_| VaultError::Validation("confirmed pairing material is invalid".to_owned()))
    }

    pub fn completed_pairing_transcript(
        &self,
        pairing_id: PairingId,
    ) -> Result<Option<StoredPairingApproval>, VaultError> {
        let Some(stored) = self.pairing_approval_transcript(pairing_id)? else {
            return Ok(None);
        };
        if stored.role != PairingApprovalRole::Joiner
            || stored.state != PairingApprovalState::Completed
        {
            return Ok(None);
        }
        self.validated_joiner_transcript(pairing_id).map(Some)
    }

    fn validated_joiner_transcript(
        &self,
        pairing_id: PairingId,
    ) -> Result<StoredPairingApproval, VaultError> {
        let stored = self
            .pairing_approval_transcript(pairing_id)?
            .ok_or_else(|| VaultError::Validation("missing pairing join approval".to_owned()))?;
        if stored.role != PairingApprovalRole::Joiner
            || !matches!(
                stored.state,
                PairingApprovalState::AwaitingConfirmation | PairingApprovalState::Completed
            )
        {
            return Err(VaultError::Validation(
                "invalid joiner transcript state".to_owned(),
            ));
        }
        let join: Option<PairingJoinTranscriptRow> = self
            .connection
            .query_row(
                "SELECT canonical_request, request_sha256, certificate_id,
                        issuer_certificate_id, wrapped_key_bundle, state, stored_at_ms,
                        completed_at_ms
                 FROM pairing_joins WHERE pairing_id = ?1",
                [pairing_id.to_string()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            canonical_request,
            request_sha256,
            certificate_id,
            issuer_certificate_id,
            sealed_grant,
            join_state,
            _join_stored_at_ms,
            completed_at_ms,
        )) = join
        else {
            return Err(VaultError::Validation("missing pairing join".to_owned()));
        };
        if canonical_request != stored.signed_request.canonical_bytes()
            || request_sha256.as_slice() != stored.signed_request.digest().0
        {
            return Err(VaultError::Validation(
                "pairing join request metadata mismatch".to_owned(),
            ));
        }
        let payload = stored.approval.approved_payload();
        match stored.state {
            PairingApprovalState::AwaitingConfirmation => {
                if certificate_id.is_some()
                    || issuer_certificate_id.is_some()
                    || sealed_grant.is_some()
                    || join_state != "stored"
                    || completed_at_ms.is_some()
                    || self
                        .device_certificate(payload.issuer_certificate_id)?
                        .is_some()
                    || self
                        .device_certificate(payload.grant.certificate_id)?
                        .is_some()
                {
                    return Err(VaultError::Validation(
                        "awaiting pairing confirmation mutated trust".to_owned(),
                    ));
                }
            }
            PairingApprovalState::Completed => {
                let expected_grant =
                    encode_pairing_grant_v1(&payload.grant).map_err(crypto_error)?;
                if certificate_id.as_deref() != Some(&payload.grant.certificate_id.to_string())
                    || issuer_certificate_id.as_deref()
                        != Some(&payload.issuer_certificate_id.to_string())
                    || sealed_grant.as_deref() != Some(expected_grant.as_slice())
                    || join_state != "completed"
                    || completed_at_ms.map(timestamp_from_db).transpose()?
                        != stored.transitioned_at_ms
                {
                    return Err(VaultError::Validation(
                        "completed pairing join metadata mismatch".to_owned(),
                    ));
                }
                let issuer = self
                    .device_certificate(payload.issuer_certificate_id)?
                    .ok_or_else(|| {
                        VaultError::Validation("missing confirmed issuer certificate".to_owned())
                    })?;
                let child = self
                    .device_certificate(payload.grant.certificate_id)?
                    .ok_or_else(|| {
                        VaultError::Validation("missing confirmed child certificate".to_owned())
                    })?;
                if issuer.certificate != payload.issuer_certificate
                    || issuer.state != DeviceCertificateState::Active
                    || issuer.display.device_name != payload.issuer_device_name
                    || issuer.display.platform != payload.issuer_platform
                    || child.certificate != payload.grant.certificate
                    || child.state != DeviceCertificateState::Active
                    || child.display.device_name != stored.signed_request.request().device_name
                    || child.display.platform != stored.signed_request.request().platform
                {
                    return Err(VaultError::Validation(
                        "confirmed pairing certificate graph mismatch".to_owned(),
                    ));
                }
            }
            _ => unreachable!("joiner state was checked"),
        }
        Ok(stored)
    }

    pub fn store_device_certificate(
        &mut self,
        certificate_id: DeviceCertificateId,
        certificate: &DeviceCertificateV1,
        state: DeviceCertificateState,
        display: &DeviceDisplayMetadata,
        recorded_at_ms: u64,
    ) -> Result<CommitDisposition, VaultError> {
        display.validate()?;
        let canonical_bytes = encode_device_certificate_v1(certificate).map_err(crypto_error)?;
        let canonical_sha256 = sha256(&canonical_bytes);
        let transaction = self.connection.transaction()?;

        if let Some((account, workspace, device, stored_bytes, stored_hash, stored_state, stored_name, stored_platform, stored_at_ms)) = transaction
            .query_row(
                "SELECT account_id, workspace_id, device_id, canonical_bytes, canonical_sha256, state, device_name, platform, stored_at_ms FROM device_certificates WHERE certificate_id = ?1",
                [certificate_id.to_string()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, Vec<u8>>(3)?, row.get::<_, Vec<u8>>(4)?, row.get::<_, String>(5)?, row.get::<_, String>(6)?, row.get::<_, String>(7)?, row.get::<_, i64>(8)?)),
            )
            .optional()?
        {
            return finish_existing(
                transaction,
                account == certificate.account_id.to_string() && workspace == certificate.workspace_id.to_string()
                    && device == certificate.device_id.to_string() && stored_bytes == canonical_bytes
                    && stored_hash.as_slice() == canonical_sha256.0 && stored_state == state.database_value()
                    && stored_name == display.device_name && stored_platform == display.platform_value()
                    && timestamp_from_db(stored_at_ms)? == recorded_at_ms,
            );
        }
        let scope_conflict: Option<String> = transaction
            .query_row(
                "SELECT certificate_id FROM device_certificates
                 WHERE account_id = ?1 AND workspace_id = ?2 AND device_id = ?3",
                params![
                    certificate.account_id.to_string(),
                    certificate.workspace_id.to_string(),
                    certificate.device_id.to_string()
                ],
                |row| row.get(0),
            )
            .optional()?;
        if scope_conflict.is_some() {
            return conflict(transaction);
        }
        transaction.execute(
            "INSERT INTO device_certificates(
                certificate_id, account_id, workspace_id, device_id, device_name, platform,
                canonical_bytes, canonical_sha256, state, stored_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                certificate_id.to_string(),
                certificate.account_id.to_string(),
                certificate.workspace_id.to_string(),
                certificate.device_id.to_string(),
                display.device_name,
                display.platform_value(),
                canonical_bytes,
                canonical_sha256.0.as_slice(),
                state.database_value(),
                timestamp_to_db(recorded_at_ms)?,
            ],
        )?;
        transaction.commit()?;
        Ok(CommitDisposition::Inserted)
    }

    pub fn device_certificate(
        &self,
        certificate_id: DeviceCertificateId,
    ) -> Result<Option<StoredDeviceCertificate>, VaultError> {
        self.connection
            .query_row(
                "SELECT account_id, workspace_id, device_id, canonical_bytes, canonical_sha256, state, device_name, platform, stored_at_ms
                 FROM device_certificates WHERE certificate_id = ?1",
                [certificate_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?,
                        row.get::<_, Vec<u8>>(3)?, row.get::<_, Vec<u8>>(4)?, row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?, row.get::<_, String>(7)?, row.get::<_, i64>(8)?,
                    ))
                },
            )
            .optional()?
            .map(|(account_id, workspace_id, device_id, canonical_bytes, digest, state, device_name, platform, stored_at_ms)| {
                let canonical_sha256 = digest_from_db(digest)?;
                if sha256(&canonical_bytes) != canonical_sha256 {
                    return Err(VaultError::Validation(
                        "device certificate digest mismatch".to_owned(),
                    ));
                }
                let certificate = decode_device_certificate_v1(&canonical_bytes).map_err(crypto_error)?;
                if certificate.account_id.to_string() != account_id || certificate.workspace_id.to_string() != workspace_id || certificate.device_id.to_string() != device_id {
                    return Err(VaultError::Validation("device certificate metadata mismatch".to_owned()));
                }
                Ok(StoredDeviceCertificate {
                    certificate_id,
                    certificate,
                    state: DeviceCertificateState::parse(&state)?,
                    display: DeviceDisplayMetadata { device_name, platform: parse_platform(&platform)? },
                    stored_at_ms: timestamp_from_db(stored_at_ms)?,
                    canonical_bytes,
                    canonical_sha256,
                })
            })
            .transpose()
    }

    pub fn devices(&self, scope: SyncScope) -> Result<Vec<StoredDeviceCertificate>, VaultError> {
        let mut statement = self.connection.prepare(
            "SELECT certificate_id FROM device_certificates
             WHERE account_id = ?1 AND workspace_id = ?2 ORDER BY device_id",
        )?;
        let ids = statement
            .query_map(
                params![scope.account_id.to_string(), scope.workspace_id.to_string()],
                |row| row.get::<_, String>(0),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        ids.into_iter()
            .map(|value| {
                let certificate_id = parse_id(&value)?;
                self.device_certificate(certificate_id)?.ok_or_else(|| {
                    VaultError::Validation("missing device certificate row".to_owned())
                })
            })
            .collect()
    }

    pub fn all_devices(&self) -> Result<Vec<StoredDeviceCertificate>, VaultError> {
        let mut statement = self.connection.prepare(
            "SELECT certificate_id FROM device_certificates
             ORDER BY account_id, workspace_id, device_id, certificate_id",
        )?;
        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        ids.into_iter()
            .map(|value| {
                let certificate_id = parse_id(&value)?;
                self.device_certificate(certificate_id)?.ok_or_else(|| {
                    VaultError::Validation("missing device certificate row".to_owned())
                })
            })
            .collect()
    }

    pub fn prepare_pairing_decision(
        &mut self,
        grant: &PairingGrant,
        canonical_grant: &[u8],
        prepared_at_ms: u64,
    ) -> Result<CommitDisposition, VaultError> {
        let parsed = decode_pairing_grant_v1(canonical_grant).map_err(crypto_error)?;
        if &parsed != grant {
            return Err(VaultError::Validation(
                "pairing grant is not canonical".to_owned(),
            ));
        }
        match self.device_certificate(grant.certificate_id)? {
            Some(stored)
                if stored.certificate == grant.certificate
                    && stored.state == DeviceCertificateState::Active => {}
            _ => {
                return Err(VaultError::Validation(
                    "pairing grant certificate is not active and exact".to_owned(),
                ));
            }
        }
        let digest = sha256(canonical_grant);
        let transaction = self.connection.transaction()?;
        if let Some((stored_request, stored_certificate, stored_grant, stored_digest, state, stored_at)) =
            transaction
                .query_row(
                    "SELECT request_digest, certificate_id, canonical_grant, grant_sha256, state, prepared_at_ms
                 FROM pairing_decisions WHERE pairing_id = ?1",
                    [grant.pairing_id.to_string()],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, Option<String>>(1)?,
                            row.get::<_, Option<Vec<u8>>>(2)?,
                            row.get::<_, Option<Vec<u8>>>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, i64>(5)?,
                        ))
                    },
                )
                .optional()?
        {
            let exact = state == "prepared"
                && stored_request.as_slice() == grant.request_digest.0
                && stored_certificate.as_deref() == Some(&grant.certificate_id.to_string())
                && stored_grant.as_deref() == Some(canonical_grant)
                && stored_digest.as_deref() == Some(digest.0.as_slice())
                && timestamp_from_db(stored_at)? == prepared_at_ms;
            return finish_existing(transaction, exact);
        }
        transaction.execute(
            "INSERT INTO pairing_decisions(
                pairing_id, request_digest, certificate_id, canonical_grant, grant_sha256, state, prepared_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, 'prepared', ?6)",
            params![
                grant.pairing_id.to_string(),
                grant.request_digest.0.as_slice(),
                grant.certificate_id.to_string(),
                canonical_grant,
                digest.0.as_slice()
                , timestamp_to_db(prepared_at_ms)?
            ],
        )?;
        transaction.commit()?;
        Ok(CommitDisposition::Inserted)
    }

    pub fn pending_pairing_decisions(&self) -> Result<Vec<PreparedPairingDecision>, VaultError> {
        let mut statement = self.connection.prepare(
            "SELECT pairing_id, request_digest, certificate_id, canonical_grant, grant_sha256, prepared_at_ms
             FROM pairing_decisions WHERE state = 'prepared' ORDER BY pairing_id",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })?
            .map(|row| {
                let (
                    pairing_id,
                    request_digest,
                    certificate_id,
                    canonical_grant,
                    grant_sha256,
                    prepared_at_ms,
                ) = row?;
                let grant = decode_pairing_grant_v1(&canonical_grant).map_err(crypto_error)?;
                let grant_digest = digest_from_db(grant_sha256)?;
                let request_digest = digest_from_db(request_digest)?;
                let certificate_id = parse_id(&certificate_id)?;
                let prepared_at_ms = timestamp_from_db(prepared_at_ms)?;
                if grant.pairing_id != parse_id(&pairing_id)?
                    || grant.request_digest != request_digest
                    || grant.certificate_id != certificate_id
                    || sha256(&canonical_grant) != grant_digest
                {
                    return Err(VaultError::Validation(
                        "invalid persisted pairing decision".to_owned(),
                    ));
                }
                Ok(PreparedPairingDecision {
                    pairing_id: parse_id(&pairing_id)?,
                    request_digest,
                    certificate_id,
                    grant_sha256: grant_digest,
                    canonical_grant,
                    prepared_at_ms,
                })
            })
            .collect()
    }

    pub fn finish_pairing_decision(
        &mut self,
        pairing_id: PairingId,
        request_digest: Sha256Digest,
        final_state: PairingDecisionFinalState,
        finished_at_ms: u64,
    ) -> Result<CommitDisposition, VaultError> {
        let transaction = self.connection.transaction()?;
        let existing: Option<StoredDecisionRow> = transaction
            .query_row(
                "SELECT request_digest, state, finished_at_ms, certificate_id, canonical_grant, grant_sha256 FROM pairing_decisions WHERE pairing_id = ?1",
                [pairing_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
            )
            .optional()?;
        if let Some((stored_digest, state, _, certificate_id, canonical_grant, grant_hash)) =
            &existing
            && (state == "prepared" || state == "accepted")
        {
            let (Some(certificate_id), Some(canonical_grant), Some(grant_hash)) =
                (certificate_id, canonical_grant, grant_hash)
            else {
                return conflict(transaction);
            };
            let grant = decode_pairing_grant_v1(canonical_grant).map_err(crypto_error)?;
            if grant.pairing_id != pairing_id
                || grant.request_digest.0.as_slice() != stored_digest.as_slice()
                || grant.certificate_id.to_string() != *certificate_id
                || sha256(canonical_grant).0.as_slice() != grant_hash.as_slice()
            {
                return conflict(transaction);
            }
            let expected_certificate =
                encode_device_certificate_v1(&grant.certificate).map_err(crypto_error)?;
            let certificate_row: Option<DecisionCertificateRow> = transaction
                    .query_row(
                        "SELECT canonical_bytes, canonical_sha256, account_id, workspace_id, device_id, state FROM device_certificates WHERE certificate_id = ?1",
                        [certificate_id],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
                    ).optional()?;
            let Some((bytes, hash, account, workspace, device, state)) = certificate_row else {
                return conflict(transaction);
            };
            if bytes != expected_certificate
                || hash.as_slice() != sha256(&bytes).0
                || account != grant.certificate.account_id.to_string()
                || workspace != grant.certificate.workspace_id.to_string()
                || device != grant.certificate.device_id.to_string()
                || state != "active"
            {
                return conflict(transaction);
            }
        }
        match (existing, final_state) {
            (Some((digest, state, _, _, _, _)), PairingDecisionFinalState::Accepted)
                if digest.as_slice() == request_digest.0 && state == "prepared" =>
            {
                transaction.execute(
                    "UPDATE pairing_decisions SET state = 'accepted', finished_at_ms = ?2 WHERE pairing_id = ?1",
                    params![pairing_id.to_string(), timestamp_to_db(finished_at_ms)?],
                )?;
                transaction.commit()?;
                Ok(CommitDisposition::Inserted)
            }
            (
                Some((digest, state, Some(stored_at), _, _, _)),
                PairingDecisionFinalState::Accepted,
            ) if digest.as_slice() == request_digest.0
                && state == "accepted"
                && timestamp_from_db(stored_at)? == finished_at_ms =>
            {
                transaction.commit()?;
                Ok(CommitDisposition::ExactReplay)
            }
            (None, PairingDecisionFinalState::Rejected) => {
                transaction.execute(
                    "INSERT INTO pairing_decisions(pairing_id, request_digest, state, finished_at_ms)
                     VALUES (?1, ?2, 'rejected', ?3)",
                    params![pairing_id.to_string(), request_digest.0.as_slice(), timestamp_to_db(finished_at_ms)?],
                )?;
                transaction.commit()?;
                Ok(CommitDisposition::Inserted)
            }
            (
                Some((digest, state, Some(stored_at), _, _, _)),
                PairingDecisionFinalState::Rejected,
            ) if digest.as_slice() == request_digest.0
                && state == "rejected"
                && timestamp_from_db(stored_at)? == finished_at_ms =>
            {
                transaction.commit()?;
                Ok(CommitDisposition::ExactReplay)
            }
            _ => conflict(transaction),
        }
    }

    pub fn stored_pairing_join(
        &self,
        pairing_id: PairingId,
    ) -> Result<Option<StoredPairingJoin>, VaultError> {
        let row: Option<StoredJoinRow> = self
            .connection
            .query_row(
                "SELECT canonical_request, request_sha256, certificate_id,
                        wrapped_key_bundle, state, completed_at_ms
                 FROM pairing_joins WHERE pairing_id = ?1",
                [pairing_id.to_string()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            canonical_request,
            request_sha256,
            certificate_id,
            wrapped_key_bundle,
            state,
            completed_at_ms,
        )) = row
        else {
            return Ok(None);
        };
        let stored_at_ms: i64 = self.connection.query_row(
            "SELECT stored_at_ms FROM pairing_joins WHERE pairing_id = ?1",
            [pairing_id.to_string()],
            |row| row.get(0),
        )?;
        let request = decode_pairing_request_v1(&canonical_request)
            .map_err(|_| VaultError::Validation("invalid stored pairing request".to_owned()))?;
        let verified = verify_pairing_request(&request).map_err(crypto_error)?;
        if request.pairing_id != pairing_id
            || verified.canonical_bytes() != canonical_request
            || verified.digest().0.as_slice() != request_sha256
        {
            return Err(VaultError::Validation(
                "stored pairing request metadata mismatch".to_owned(),
            ));
        }
        let (completed, certificate_id, completed_at_ms) = match state.as_str() {
            "stored"
                if certificate_id.is_none()
                    && wrapped_key_bundle.is_none()
                    && completed_at_ms.is_none() =>
            {
                (false, None, None)
            }
            "completed"
                if certificate_id.is_some()
                    && wrapped_key_bundle.is_some()
                    && completed_at_ms.is_some() =>
            {
                let certificate_id =
                    parse_id(certificate_id.as_deref().ok_or_else(|| {
                        VaultError::Validation("missing certificate id".to_owned())
                    })?)?;
                (
                    true,
                    Some(certificate_id),
                    completed_at_ms.map(timestamp_from_db).transpose()?,
                )
            }
            _ => {
                return Err(VaultError::Validation(
                    "invalid stored pairing join state".to_owned(),
                ));
            }
        };
        Ok(Some(StoredPairingJoin {
            pairing_id,
            canonical_request,
            request_sha256: digest_from_db(request_sha256)?,
            certificate_id,
            wrapped_key_bundle,
            completed,
            stored_at_ms: timestamp_from_db(stored_at_ms)?,
            completed_at_ms,
        }))
    }

    pub fn store_pairing_join_request(
        &mut self,
        pairing_id: PairingId,
        canonical_request: &[u8],
        stored_at_ms: u64,
    ) -> Result<CommitDisposition, VaultError> {
        let request = decode_pairing_request_v1(canonical_request)
            .map_err(|_| VaultError::Validation("invalid canonical pairing request".to_owned()))?;
        let verified = verify_pairing_request(&request).map_err(crypto_error)?;
        if verified.digest() != sha256(canonical_request)
            || verified.canonical_bytes() != canonical_request
            || request.pairing_id != pairing_id
        {
            return Err(VaultError::Validation(
                "pairing request is not canonical".to_owned(),
            ));
        }
        let request_sha256 = sha256(canonical_request);
        let transaction = self.connection.transaction()?;
        if let Some((stored, digest, existing_at)) = transaction
            .query_row(
                "SELECT canonical_request, request_sha256, stored_at_ms FROM pairing_joins WHERE pairing_id = ?1",
                [pairing_id.to_string()],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, i64>(2)?)),
            )
            .optional()?
        {
            return finish_existing(
                transaction,
                stored.as_slice() == canonical_request && digest.as_slice() == request_sha256.0 && timestamp_from_db(existing_at)? == stored_at_ms,
            );
        }
        transaction.execute(
            "INSERT INTO pairing_joins(pairing_id, canonical_request, request_sha256, state, stored_at_ms)
             VALUES (?1, ?2, ?3, 'stored', ?4)",
            params![
                pairing_id.to_string(),
                canonical_request,
                request_sha256.0.as_slice(), timestamp_to_db(stored_at_ms)?
            ],
        )?;
        transaction.commit()?;
        Ok(CommitDisposition::Inserted)
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn finish_pairing_join(
        &mut self,
        pairing_id: PairingId,
        canonical_request: &[u8],
        grant: &PairingGrant,
        canonical_grant: &[u8],
        display: &DeviceDisplayMetadata,
        completed_at_ms: u64,
    ) -> Result<CommitDisposition, VaultError> {
        self.finish_pairing_join_inner(
            pairing_id,
            canonical_request,
            grant,
            canonical_grant,
            display,
            completed_at_ms,
        )
    }

    #[cfg(feature = "test-support")]
    fn finish_pairing_join_inner(
        &mut self,
        pairing_id: PairingId,
        canonical_request: &[u8],
        grant: &PairingGrant,
        canonical_grant: &[u8],
        display: &DeviceDisplayMetadata,
        completed_at_ms: u64,
    ) -> Result<CommitDisposition, VaultError> {
        display.validate()?;
        let request = decode_pairing_request_v1(canonical_request)
            .map_err(|_| VaultError::Validation("invalid canonical pairing request".to_owned()))?;
        let verified = verify_pairing_request(&request).map_err(crypto_error)?;
        let parsed_grant = decode_pairing_grant_v1(canonical_grant).map_err(crypto_error)?;
        if verified.canonical_bytes() != canonical_request
            || request.pairing_id != pairing_id
            || &parsed_grant != grant
            || grant.pairing_id != pairing_id
            || grant.request_digest != sha256(canonical_request)
            || display.device_name != request.device_name
            || display.platform != request.platform
        {
            return Err(VaultError::Validation(
                "pairing completion is not canonical".to_owned(),
            ));
        }
        let certificate = &grant.certificate;
        if certificate.request_nonce != request.request_nonce
            || certificate.device_id != request.device_id
            || certificate.signing_public_key != request.signing_public_key
            || certificate.wrapping_public_key != request.wrapping_public_key
        {
            return Err(VaultError::Validation(
                "pairing completion certificate does not bind the request".to_owned(),
            ));
        }
        let certificate_bytes = encode_device_certificate_v1(certificate).map_err(crypto_error)?;
        let certificate_hash = sha256(&certificate_bytes);
        let transaction = self.connection.transaction()?;
        let existing: Option<StoredJoinRow> = transaction
            .query_row(
                "SELECT canonical_request, request_sha256, certificate_id, wrapped_key_bundle, state, completed_at_ms
                 FROM pairing_joins WHERE pairing_id = ?1",
                [pairing_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
            )
            .optional()?;
        match existing {
            Some((request, request_hash, None, None, state, None))
                if request.as_slice() == canonical_request
                    && request_hash.as_slice() == sha256(canonical_request).0
                    && state == "stored" =>
            {
                let existing_certificate: Option<CompletionCertificateRow> = transaction
                    .query_row(
                        "SELECT canonical_bytes, canonical_sha256, account_id, workspace_id, device_id, device_name, platform, state
                         FROM device_certificates WHERE certificate_id = ?1",
                        [grant.certificate_id.to_string()],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?)),
                    )
                    .optional()?;
                if let Some((bytes, hash, account, workspace, device, name, platform, state)) =
                    existing_certificate
                {
                    if bytes != certificate_bytes
                        || hash.as_slice() != certificate_hash.0
                        || account != certificate.account_id.to_string()
                        || workspace != certificate.workspace_id.to_string()
                        || device != certificate.device_id.to_string()
                        || name != display.device_name
                        || platform != display.platform_value()
                        || state != "active"
                    {
                        return conflict(transaction);
                    }
                } else {
                    let scope_conflict: Option<String> = transaction.query_row(
                        "SELECT certificate_id FROM device_certificates WHERE account_id = ?1 AND workspace_id = ?2 AND device_id = ?3",
                        params![certificate.account_id.to_string(), certificate.workspace_id.to_string(), certificate.device_id.to_string()],
                        |row| row.get(0),
                    ).optional()?;
                    if scope_conflict.is_some() {
                        return conflict(transaction);
                    }
                    transaction.execute(
                        "INSERT INTO device_certificates(certificate_id, account_id, workspace_id, device_id, device_name, platform, canonical_bytes, canonical_sha256, state, stored_at_ms)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'active', ?9)",
                        params![grant.certificate_id.to_string(), certificate.account_id.to_string(), certificate.workspace_id.to_string(), certificate.device_id.to_string(), display.device_name, display.platform_value(), certificate_bytes, certificate_hash.0.as_slice(), timestamp_to_db(completed_at_ms)?],
                    )?;
                }
                transaction.execute(
                    "UPDATE pairing_joins
                     SET certificate_id = ?2, wrapped_key_bundle = ?3, state = 'completed', completed_at_ms = ?4
                     WHERE pairing_id = ?1",
                    params![
                        pairing_id.to_string(),
                        grant.certificate_id.to_string(),
                        canonical_grant, timestamp_to_db(completed_at_ms)?
                    ],
                )?;
                transaction.commit()?;
                Ok(CommitDisposition::Inserted)
            }
            Some((
                request,
                request_hash,
                stored_certificate,
                stored_bundle,
                state,
                Some(stored_at),
            )) if request.as_slice() == canonical_request
                && request_hash.as_slice() == sha256(canonical_request).0
                && state == "completed"
                && stored_certificate.as_deref() == Some(&grant.certificate_id.to_string())
                && stored_bundle.as_deref() == Some(canonical_grant)
                && timestamp_from_db(stored_at)? == completed_at_ms =>
            {
                let certificate_row: Option<CompletionReplayCertificateRow> = transaction
                    .query_row(
                        "SELECT canonical_bytes, canonical_sha256, account_id, workspace_id, device_id, state, device_name, platform, stored_at_ms
                         FROM device_certificates WHERE certificate_id = ?1",
                        [grant.certificate_id.to_string()],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?)),
                    )
                    .optional()?;
                let Some((
                    bytes,
                    hash,
                    account,
                    workspace,
                    device,
                    certificate_state,
                    name,
                    platform,
                    _stored_certificate_at,
                )) = certificate_row
                else {
                    return conflict(transaction);
                };
                if bytes != certificate_bytes
                    || hash.as_slice() != certificate_hash.0
                    || account != certificate.account_id.to_string()
                    || workspace != certificate.workspace_id.to_string()
                    || device != certificate.device_id.to_string()
                    || certificate_state != "active"
                    || name != display.device_name
                    || platform != display.platform_value()
                {
                    return conflict(transaction);
                }
                transaction.commit()?;
                Ok(CommitDisposition::ExactReplay)
            }
            _ => conflict(transaction),
        }
    }
}

fn decode_approval_transcript(
    pairing_id: PairingId,
    row: StoredApprovalTranscriptRow,
) -> Result<StoredPairingApproval, VaultError> {
    let (
        role,
        state,
        canonical_request,
        request_sha256,
        canonical_approved_payload,
        approved_payload_sha256,
        transcript_sha256,
        issuer_certificate_id,
        account_id,
        workspace_id,
        control_epoch,
        key_epoch,
        stored_at_ms,
        transitioned_at_ms,
    ) = row;
    let role = parse_approval_role(&role)?;
    let state = parse_approval_state(&state)?;
    if state == PairingApprovalState::LegacyUnconfirmed {
        return Err(VaultError::Validation(
            "legacy pairing transcript requires a fresh pairing".to_owned(),
        ));
    }
    let canonical_request = required_value(canonical_request, "pairing request")?;
    let request_sha256 = digest_from_db(required_value(request_sha256, "request digest")?)?;
    let canonical_approved_payload =
        required_value(canonical_approved_payload, "approved payload")?;
    let approved_payload_sha256 = digest_from_db(required_value(
        approved_payload_sha256,
        "approved payload digest",
    )?)?;
    let transcript_sha256 =
        digest_from_db(required_value(transcript_sha256, "transcript digest")?)?;
    let issuer_certificate_id: DeviceCertificateId = parse_id(&required_value(
        issuer_certificate_id,
        "issuer certificate ID",
    )?)?;
    let account_id = required_value(account_id, "pairing account")?;
    let workspace_id = required_value(workspace_id, "pairing workspace")?;
    let control_epoch = positive_epoch(control_epoch, "control epoch")?;
    let key_epoch = positive_epoch(key_epoch, "key epoch")?;
    let request = decode_pairing_request_v1(&canonical_request)
        .map_err(|_| VaultError::Validation("invalid stored pairing request".to_owned()))?;
    let signed_request = verify_pairing_request(&request).map_err(crypto_error)?;
    let approval = inspect_pairing_approval(&canonical_approved_payload, &signed_request)
        .map_err(crypto_error)?;
    let payload = approval.approved_payload();
    let state_matches_role = matches!(
        (role, state),
        (
            PairingApprovalRole::Approver,
            PairingApprovalState::Prepared | PairingApprovalState::Accepted
        ) | (
            PairingApprovalRole::Joiner,
            PairingApprovalState::AwaitingConfirmation | PairingApprovalState::Completed
        )
    );
    if !state_matches_role
        || signed_request.canonical_bytes() != canonical_request
        || request.pairing_id != pairing_id
        || signed_request.digest() != request_sha256
        || sha256(&canonical_approved_payload) != approved_payload_sha256
        || approval.transcript_digest() != transcript_sha256
        || payload.issuer_certificate_id != issuer_certificate_id
        || payload.grant.certificate.account_id.to_string() != account_id
        || payload.grant.certificate.workspace_id.to_string() != workspace_id
        || payload.grant.certificate.control_epoch != control_epoch
        || payload.grant.key_epoch != key_epoch
        || (matches!(
            state,
            PairingApprovalState::Prepared | PairingApprovalState::AwaitingConfirmation
        ) && transitioned_at_ms.is_some())
        || (matches!(
            state,
            PairingApprovalState::Accepted | PairingApprovalState::Completed
        ) && transitioned_at_ms.is_none())
    {
        return Err(VaultError::Validation(
            "stored pairing transcript metadata mismatch".to_owned(),
        ));
    }
    Ok(StoredPairingApproval {
        pairing_id,
        role,
        state,
        signed_request,
        approval,
        approved_payload_sha256,
        stored_at_ms: timestamp_from_db(stored_at_ms)?,
        transitioned_at_ms: transitioned_at_ms.map(timestamp_from_db).transpose()?,
    })
}

fn parse_approval_role(value: &str) -> Result<PairingApprovalRole, VaultError> {
    match value {
        "approver" => Ok(PairingApprovalRole::Approver),
        "joiner" => Ok(PairingApprovalRole::Joiner),
        _ => Err(VaultError::Validation(
            "invalid pairing transcript role".to_owned(),
        )),
    }
}

fn parse_approval_state(value: &str) -> Result<PairingApprovalState, VaultError> {
    match value {
        "prepared" => Ok(PairingApprovalState::Prepared),
        "accepted" => Ok(PairingApprovalState::Accepted),
        "awaiting_confirmation" => Ok(PairingApprovalState::AwaitingConfirmation),
        "completed" => Ok(PairingApprovalState::Completed),
        "legacy_unconfirmed" => Ok(PairingApprovalState::LegacyUnconfirmed),
        _ => Err(VaultError::Validation(
            "invalid pairing transcript state".to_owned(),
        )),
    }
}

fn required_value<T>(value: Option<T>, field: &str) -> Result<T, VaultError> {
    value.ok_or_else(|| VaultError::Validation(format!("missing stored {field}")))
}

fn positive_epoch(value: Option<i64>, field: &str) -> Result<u32, VaultError> {
    let value = required_value(value, field)?;
    u32::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| VaultError::Validation(format!("invalid stored {field}")))
}

pub(super) fn ensure_active_certificate_tx(
    transaction: &Transaction<'_>,
    certificate_id: DeviceCertificateId,
    certificate: &DeviceCertificateV1,
    display: &DeviceDisplayMetadata,
    stored_at_ms: u64,
    allow_insert: bool,
) -> Result<(), VaultError> {
    let canonical = encode_device_certificate_v1(certificate).map_err(crypto_error)?;
    let canonical_sha256 = sha256(&canonical);
    let existing: Option<ActiveCertificateRow> = transaction
        .query_row(
            "SELECT account_id, workspace_id, device_id, device_name, platform,
                        canonical_bytes, canonical_sha256, state
                 FROM device_certificates WHERE certificate_id = ?1",
            [certificate_id.to_string()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .optional()?;
    if let Some((account, workspace, device, name, platform, bytes, digest, state)) = existing {
        if account == certificate.account_id.to_string()
            && workspace == certificate.workspace_id.to_string()
            && device == certificate.device_id.to_string()
            && name == display.device_name
            && platform == display.platform_value()
            && bytes == canonical
            && digest.as_slice() == canonical_sha256.0
            && state == "active"
        {
            return Ok(());
        }
        return Err(VaultError::OperationConflict);
    }
    if !allow_insert {
        return Err(VaultError::OperationConflict);
    }
    let scope_conflict: Option<String> = transaction
        .query_row(
            "SELECT certificate_id FROM device_certificates
             WHERE account_id = ?1 AND workspace_id = ?2 AND device_id = ?3",
            params![
                certificate.account_id.to_string(),
                certificate.workspace_id.to_string(),
                certificate.device_id.to_string(),
            ],
            |row| row.get(0),
        )
        .optional()?;
    if scope_conflict.is_some() {
        return Err(VaultError::OperationConflict);
    }
    transaction.execute(
        "INSERT INTO device_certificates(
            certificate_id, account_id, workspace_id, device_id, device_name, platform,
            canonical_bytes, canonical_sha256, state, stored_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'active', ?9)",
        params![
            certificate_id.to_string(),
            certificate.account_id.to_string(),
            certificate.workspace_id.to_string(),
            certificate.device_id.to_string(),
            display.device_name,
            display.platform_value(),
            canonical,
            canonical_sha256.0.as_slice(),
            timestamp_to_db(stored_at_ms)?,
        ],
    )?;
    Ok(())
}

fn finish_existing(
    transaction: Transaction<'_>,
    exact: bool,
) -> Result<CommitDisposition, VaultError> {
    if exact {
        transaction.commit()?;
        Ok(CommitDisposition::ExactReplay)
    } else {
        conflict(transaction)
    }
}

fn conflict<T>(transaction: Transaction<'_>) -> Result<T, VaultError> {
    transaction.rollback()?;
    Err(VaultError::OperationConflict)
}

fn sha256(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest(Sha256::digest(bytes).into())
}

pub(super) fn digest_from_db(bytes: Vec<u8>) -> Result<Sha256Digest, VaultError> {
    bytes
        .as_slice()
        .try_into()
        .map(Sha256Digest)
        .map_err(|_| VaultError::Validation("invalid SHA-256 length".to_owned()))
}

pub(super) fn parse_id<T: FromStr>(value: &str) -> Result<T, VaultError> {
    value
        .parse()
        .map_err(|_| VaultError::Validation("invalid stored UUID".to_owned()))
}

fn crypto_error(_: crate::crypto::CryptoError) -> VaultError {
    VaultError::Validation("invalid pairing protocol value".to_owned())
}

pub(super) fn parse_platform(value: &str) -> Result<NativePlatform, VaultError> {
    match value {
        "windows" => Ok(NativePlatform::Windows),
        "macos" => Ok(NativePlatform::Macos),
        _ => Err(VaultError::Validation("invalid device platform".to_owned())),
    }
}

pub(super) fn timestamp_to_db(value: u64) -> Result<i64, VaultError> {
    value
        .try_into()
        .map_err(|_| VaultError::Validation("timestamp exceeds SQLite integer range".to_owned()))
}

pub(super) fn timestamp_from_db(value: i64) -> Result<u64, VaultError> {
    value
        .try_into()
        .map_err(|_| VaultError::Validation("invalid persisted timestamp".to_owned()))
}
