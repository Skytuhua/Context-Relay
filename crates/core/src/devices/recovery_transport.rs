use std::{error::Error, fmt};

use context_relay_protocol::{
    AccountId, DeviceCertificateId, RecoveryEnrollmentId, RecoveryRootId, Sha256Digest, WorkspaceId,
};
use sha2::{Digest, Sha256};

use crate::{
    devices::recovery_crypto::{RecoveryEnrollmentRecordV1, encode_recovery_enrollment_record_v1},
    sync::SyncScope,
};

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum RecoveryTransportError {
    Invalid,
    Conflict,
    Unauthorized,
    Transient,
}

impl RecoveryTransportError {
    pub const fn safe_code(self) -> &'static str {
        match self {
            Self::Invalid => "recovery_invalid",
            Self::Conflict => "recovery_conflict",
            Self::Unauthorized => "recovery_unauthorized",
            Self::Transient => "transient",
        }
    }
}

impl fmt::Debug for RecoveryTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.safe_code())
    }
}

impl fmt::Display for RecoveryTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.safe_code())
    }
}

impl Error for RecoveryTransportError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryRootStatus {
    pub enrollment_id: RecoveryEnrollmentId,
    pub recovery_root_id: RecoveryRootId,
    pub account_id: AccountId,
    pub workspace_id: WorkspaceId,
    pub genesis_certificate_id: DeviceCertificateId,
    pub canonical_record_sha256: Sha256Digest,
    pub registered_at_ms: u64,
}

impl RecoveryRootStatus {
    pub fn validate_for(
        &self,
        scope: SyncScope,
        record: &RecoveryEnrollmentRecordV1,
        canonical_record_sha256: Sha256Digest,
        registered_at_ms: u64,
    ) -> Result<(), RecoveryTransportError> {
        validate_projection(
            self.enrollment_id,
            self.recovery_root_id,
            self.account_id,
            self.workspace_id,
            self.genesis_certificate_id,
            self.canonical_record_sha256,
            self.registered_at_ms,
            scope,
            record,
            canonical_record_sha256,
            registered_at_ms,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryEnrollmentReceipt {
    pub enrollment_id: RecoveryEnrollmentId,
    pub recovery_root_id: RecoveryRootId,
    pub account_id: AccountId,
    pub workspace_id: WorkspaceId,
    pub genesis_certificate_id: DeviceCertificateId,
    pub canonical_record_sha256: Sha256Digest,
    pub registered_at_ms: u64,
}

impl RecoveryEnrollmentReceipt {
    pub fn validate_for(
        &self,
        scope: SyncScope,
        record: &RecoveryEnrollmentRecordV1,
        canonical_record_sha256: Sha256Digest,
        registered_at_ms: u64,
    ) -> Result<(), RecoveryTransportError> {
        validate_projection(
            self.enrollment_id,
            self.recovery_root_id,
            self.account_id,
            self.workspace_id,
            self.genesis_certificate_id,
            self.canonical_record_sha256,
            self.registered_at_ms,
            scope,
            record,
            canonical_record_sha256,
            registered_at_ms,
        )
    }

    pub const fn into_status(self) -> RecoveryRootStatus {
        RecoveryRootStatus {
            enrollment_id: self.enrollment_id,
            recovery_root_id: self.recovery_root_id,
            account_id: self.account_id,
            workspace_id: self.workspace_id,
            genesis_certificate_id: self.genesis_certificate_id,
            canonical_record_sha256: self.canonical_record_sha256,
            registered_at_ms: self.registered_at_ms,
        }
    }
}

/// Authenticated, scope-bound provider boundary for first recovery-root registration.
///
/// The deterministic in-memory provider and its captures are absent from normal builds.
#[cfg_attr(
    not(feature = "test-support"),
    doc = r#"
```compile_fail
use context_relay_core::devices::memory_recovery_transport::InMemoryRecoveryEnrollmentProvider;
```
"#
)]
pub trait RecoveryEnrollmentTransport: Send + Sync {
    fn scope(&self) -> SyncScope;

    fn root_status(&self) -> Result<Option<RecoveryRootStatus>, RecoveryTransportError>;

    fn register(
        &self,
        canonical_record: &[u8],
        now_ms: u64,
    ) -> Result<RecoveryEnrollmentReceipt, RecoveryTransportError>;
}

#[allow(clippy::too_many_arguments)]
fn validate_projection(
    enrollment_id: RecoveryEnrollmentId,
    recovery_root_id: RecoveryRootId,
    account_id: AccountId,
    workspace_id: WorkspaceId,
    genesis_certificate_id: DeviceCertificateId,
    projection_digest: Sha256Digest,
    projection_registered_at_ms: u64,
    scope: SyncScope,
    record: &RecoveryEnrollmentRecordV1,
    expected_digest: Sha256Digest,
    expected_registered_at_ms: u64,
) -> Result<(), RecoveryTransportError> {
    let canonical = encode_recovery_enrollment_record_v1(record)
        .map_err(|_| RecoveryTransportError::Conflict)?;
    let actual_digest = Sha256Digest(Sha256::digest(canonical).into());
    if actual_digest != expected_digest
        || enrollment_id != record.enrollment_id
        || recovery_root_id != record.recovery_root_id
        || account_id != scope.account_id
        || workspace_id != scope.workspace_id
        || account_id != record.account_id
        || workspace_id != record.workspace_id
        || genesis_certificate_id != record.genesis_certificate_id
        || projection_digest != expected_digest
        || projection_registered_at_ms != expected_registered_at_ms
    {
        return Err(RecoveryTransportError::Conflict);
    }
    Ok(())
}
