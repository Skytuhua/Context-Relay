use std::{error::Error, fmt, ops::RangeInclusive};

use context_relay_protocol::{
    AccountId, CheckpointV1, DeviceId, OperationId, Sha256Digest, WorkspaceId, encode_checkpoint_v1,
};
use sha2::{Digest, Sha256};

use crate::vault::SyncCursor;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncScope {
    pub account_id: AccountId,
    pub workspace_id: WorkspaceId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalOperation {
    pub operation_id: OperationId,
    pub device_id: DeviceId,
    pub device_sequence: u64,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceivedOperation {
    pub cursor: SyncCursor,
    pub operation: CanonicalOperation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PushReceipt {
    pub accepted: Vec<OperationId>,
    pub duplicates: Vec<OperationId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PullPage {
    pub rows: Vec<ReceivedOperation>,
    pub next_cursor: Option<SyncCursor>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalCheckpoint {
    pub canonical_hash: Sha256Digest,
    pub state_hash: Sha256Digest,
    pub checkpoint: CheckpointV1,
    pub bytes: Vec<u8>,
}

impl CanonicalCheckpoint {
    pub fn from_checkpoint(checkpoint: CheckpointV1) -> Result<Self, super::SyncError> {
        let bytes =
            encode_checkpoint_v1(&checkpoint).map_err(|_| super::SyncError::InvalidEnvelope)?;
        Ok(Self {
            canonical_hash: Sha256Digest(Sha256::digest(&bytes).into()),
            state_hash: checkpoint.state_hash,
            checkpoint,
            bytes,
        })
    }

    pub fn recanonicalize(&mut self) -> Result<(), super::SyncError> {
        self.bytes = encode_checkpoint_v1(&self.checkpoint)
            .map_err(|_| super::SyncError::InvalidEnvelope)?;
        self.canonical_hash = Sha256Digest(Sha256::digest(&self.bytes).into());
        self.state_hash = self.checkpoint.state_hash;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckpointReceipt {
    pub canonical_hash: Sha256Digest,
    pub duplicate: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct CheckpointCursor {
    pub received_at: String,
    pub canonical_hash: Sha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceivedCheckpoint {
    pub cursor: CheckpointCursor,
    pub checkpoint: CanonicalCheckpoint,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointPage {
    pub rows: Vec<ReceivedCheckpoint>,
    pub next_cursor: Option<CheckpointCursor>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportError {
    Offline,
    Transient,
    ProviderServer,
    AuthRequired,
    Revoked,
    QuotaBlocked,
    Integrity,
    CheckpointVersionUnsupported,
    Configuration,
}

impl TransportError {
    pub const fn safe_code(self) -> &'static str {
        match self {
            Self::Offline => "offline",
            Self::Transient | Self::ProviderServer => "transient",
            Self::AuthRequired => "auth_required",
            Self::Revoked => "revoked",
            Self::QuotaBlocked => "quota_blocked",
            Self::Integrity => "integrity_quarantined",
            Self::CheckpointVersionUnsupported | Self::Configuration => "configuration_error",
        }
    }

    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::Offline | Self::Transient | Self::ProviderServer)
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.safe_code())
    }
}

impl Error for TransportError {}

pub trait SyncTransport {
    fn push_operations(
        &mut self,
        scope: SyncScope,
        batch: &[CanonicalOperation],
    ) -> Result<PushReceipt, TransportError>;

    fn pull_operations(
        &mut self,
        scope: SyncScope,
        after: Option<&SyncCursor>,
        limit: usize,
    ) -> Result<PullPage, TransportError>;

    fn pull_device_range(
        &mut self,
        scope: SyncScope,
        device: DeviceId,
        range: RangeInclusive<u64>,
    ) -> Result<Vec<ReceivedOperation>, TransportError>;

    fn push_checkpoint(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        checkpoint: &CanonicalCheckpoint,
    ) -> Result<CheckpointReceipt, TransportError>;

    fn pull_checkpoints(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        after: Option<&CheckpointCursor>,
        limit: usize,
    ) -> Result<CheckpointPage, TransportError>;

    fn checkpoint_by_hash(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        canonical_hash: Sha256Digest,
    ) -> Result<Option<CanonicalCheckpoint>, TransportError>;
}
