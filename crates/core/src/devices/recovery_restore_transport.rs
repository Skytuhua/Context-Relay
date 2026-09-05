use std::fmt;

use context_relay_protocol::{
    AccountId, DeviceCertificateId, RecoveryEnrollmentId, RecoveryRestoreId, RecoveryRootId,
    Sha256Digest, WorkspaceId,
};
use sha2::{Digest, Sha256};

use crate::{
    devices::{
        recovery_crypto::{
            RecoveryEnrollmentRecordV1, decode_recovery_enrollment_record_v1,
            encode_recovery_enrollment_record_v1,
        },
        recovery_restore_crypto::{
            RecoveryDeviceClaimV1, decode_recovery_device_claim_v1, verify_recovery_device_claim,
        },
        recovery_transport::RecoveryTransportError,
    },
    sync::SyncScope,
};

#[derive(Clone, Eq, PartialEq)]
pub struct RecoveryRootSnapshot {
    pub scope: SyncScope,
    pub canonical_record: Vec<u8>,
    pub canonical_record_sha256: Sha256Digest,
    pub registered_at_ms: u64,
    pub recovery_generation: u64,
}

impl RecoveryRootSnapshot {
    pub fn validate_for(
        &self,
        scope: SyncScope,
    ) -> Result<RecoveryEnrollmentRecordV1, RecoveryTransportError> {
        let record = decode_recovery_enrollment_record_v1(&self.canonical_record)
            .map_err(|_| RecoveryTransportError::Conflict)?;
        let canonical = encode_recovery_enrollment_record_v1(&record)
            .map_err(|_| RecoveryTransportError::Conflict)?;
        if self.scope != scope
            || record.account_id != scope.account_id
            || record.workspace_id != scope.workspace_id
            || self.canonical_record != canonical
            || self.canonical_record_sha256 != digest(&canonical)
            || self.recovery_generation > i64::MAX as u64
        {
            return Err(RecoveryTransportError::Conflict);
        }
        Ok(record)
    }
}

impl fmt::Debug for RecoveryRootSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryRootSnapshot")
            .field("scope", &self.scope)
            .field("canonical_record_sha256", &self.canonical_record_sha256)
            .field("canonical_record_len", &self.canonical_record.len())
            .field("registered_at_ms", &self.registered_at_ms)
            .field("recovery_generation", &self.recovery_generation)
            .field("canonical_record", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryRestoreReceipt {
    pub restore_id: RecoveryRestoreId,
    pub enrollment_id: RecoveryEnrollmentId,
    pub recovery_root_id: RecoveryRootId,
    pub account_id: AccountId,
    pub workspace_id: WorkspaceId,
    pub certificate_id: DeviceCertificateId,
    pub canonical_record_sha256: Sha256Digest,
    pub canonical_claim_sha256: Sha256Digest,
    pub accepted_generation: u64,
    pub accepted_at_ms: u64,
}

impl RecoveryRestoreReceipt {
    pub fn validate_for(
        &self,
        scope: SyncScope,
        record: &RecoveryEnrollmentRecordV1,
        canonical_claim: &[u8],
    ) -> Result<RecoveryDeviceClaimV1, RecoveryTransportError> {
        let claim = decode_recovery_device_claim_v1(canonical_claim)
            .map_err(|_| RecoveryTransportError::Conflict)?;
        verify_recovery_device_claim(record, &claim)
            .map_err(|_| RecoveryTransportError::Conflict)?;
        let canonical_record = encode_recovery_enrollment_record_v1(record)
            .map_err(|_| RecoveryTransportError::Conflict)?;
        let accepted_generation = claim
            .expected_recovery_generation
            .checked_add(1)
            .filter(|generation| *generation <= i64::MAX as u64)
            .ok_or(RecoveryTransportError::Conflict)?;
        if record.account_id != scope.account_id
            || record.workspace_id != scope.workspace_id
            || self.restore_id != claim.restore_id
            || self.enrollment_id != record.enrollment_id
            || self.recovery_root_id != record.recovery_root_id
            || self.account_id != scope.account_id
            || self.workspace_id != scope.workspace_id
            || self.certificate_id != claim.certificate_id
            || self.canonical_record_sha256 != digest(&canonical_record)
            || self.canonical_claim_sha256 != digest(canonical_claim)
            || self.accepted_generation != accepted_generation
        {
            return Err(RecoveryTransportError::Conflict);
        }
        Ok(claim)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RecoveryRestoreProjection {
    pub canonical_claim: Vec<u8>,
    pub receipt: RecoveryRestoreReceipt,
}

impl RecoveryRestoreProjection {
    pub fn validate_for(
        &self,
        scope: SyncScope,
        record: &RecoveryEnrollmentRecordV1,
    ) -> Result<RecoveryDeviceClaimV1, RecoveryTransportError> {
        self.receipt
            .validate_for(scope, record, &self.canonical_claim)
    }
}

impl fmt::Debug for RecoveryRestoreProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryRestoreProjection")
            .field("receipt", &self.receipt)
            .field("canonical_claim_len", &self.canonical_claim.len())
            .field("canonical_claim", &"[REDACTED]")
            .finish()
    }
}

/// Scope-bound provider boundary for recovery-root-signed device claims.
pub trait RecoveryRestoreTransport: Send + Sync {
    fn scope(&self) -> SyncScope;

    fn root_snapshot(&self) -> Result<Option<RecoveryRootSnapshot>, RecoveryTransportError>;

    fn submit_restore(
        &self,
        canonical_claim: &[u8],
        now_ms: u64,
    ) -> Result<RecoveryRestoreReceipt, RecoveryTransportError>;

    fn restore_claim(
        &self,
        restore_id: RecoveryRestoreId,
    ) -> Result<Option<RecoveryRestoreProjection>, RecoveryTransportError>;
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest(Sha256::digest(bytes).into())
}
