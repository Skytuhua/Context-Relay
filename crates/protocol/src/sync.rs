use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    AccountId, BoundedCiphertext, DeviceId, Ed25519SignatureBytes, HybridLogicalClock,
    MAX_BATCH_OPERATIONS, MAX_BLOB_BYTES, MAX_TITLE_BYTES, OperationId, ProjectId, RecordId,
    Sha256Digest, WorkspaceId, XChaChaNonce, decimal_u64, required_text,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum RecordKind {
    Memory,
    MemoryCandidate,
    Task,
    SecretRef,
    Instruction,
    Component,
    Project,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum MutationKind {
    Upsert,
    Tombstone,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct DeviceSequence {
    pub device_id: DeviceId,
    #[serde(with = "decimal_u64")]
    #[ts(type = "DecimalU64")]
    pub sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct BlobRef {
    pub digest: Sha256Digest,
    #[serde(with = "decimal_u64")]
    #[ts(type = "DecimalU64")]
    pub ciphertext_bytes: u64,
    pub storage_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct SyncOperationV1 {
    pub schema_version: u16,
    pub operation_id: OperationId,
    pub account_id: AccountId,
    pub workspace_id: WorkspaceId,
    pub project_id: Option<ProjectId>,
    pub record_id: RecordId,
    pub record_kind: RecordKind,
    pub mutation_kind: MutationKind,
    pub device_id: DeviceId,
    #[serde(with = "decimal_u64")]
    #[ts(type = "DecimalU64")]
    pub device_sequence: u64,
    pub causal_frontier: Vec<DeviceSequence>,
    pub control_epoch: u32,
    pub key_epoch: u32,
    pub previous_device_hash: Sha256Digest,
    pub nonce: XChaChaNonce,
    pub ciphertext: BoundedCiphertext,
    pub ciphertext_hash: Sha256Digest,
    pub blob_refs: Vec<BlobRef>,
    pub created_hlc: HybridLogicalClock,
    pub signature: Ed25519SignatureBytes,
}

impl SyncOperationV1 {
    pub fn validate(&self) -> Result<(), crate::ValidationError> {
        if self.schema_version != crate::SYNC_SCHEMA_VERSION {
            return Err(crate::ValidationError::Invalid("schemaVersion"));
        }
        if self.causal_frontier.len() > MAX_BATCH_OPERATIONS {
            return Err(crate::ValidationError::TooLarge {
                field: "causalFrontier",
                limit: MAX_BATCH_OPERATIONS,
            });
        }
        if self.blob_refs.len() > MAX_BATCH_OPERATIONS {
            return Err(crate::ValidationError::TooLarge {
                field: "blobRefs",
                limit: MAX_BATCH_OPERATIONS,
            });
        }
        if self
            .causal_frontier
            .windows(2)
            .any(|pair| pair[0].device_id >= pair[1].device_id)
        {
            return Err(crate::ValidationError::Invalid("causalFrontier"));
        }
        for blob in &self.blob_refs {
            required_text(&blob.storage_id, "blobRefs.storageId", MAX_TITLE_BYTES)?;
            if blob.ciphertext_bytes == 0 || blob.ciphertext_bytes > MAX_BLOB_BYTES as u64 {
                return Err(crate::ValidationError::Invalid("blobRefs.ciphertextBytes"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct CheckpointV1 {
    pub schema_version: u16,
    pub previous_checkpoint_hash: Sha256Digest,
    pub causal_frontier: Vec<DeviceSequence>,
    pub state_hash: Sha256Digest,
    pub key_epoch: u32,
    pub creator_device: DeviceId,
    pub created_hlc: HybridLogicalClock,
    pub signature: Ed25519SignatureBytes,
}

impl CheckpointV1 {
    pub fn validate(&self) -> Result<(), crate::ValidationError> {
        if self.schema_version != crate::SYNC_SCHEMA_VERSION {
            return Err(crate::ValidationError::Invalid("schemaVersion"));
        }
        if self.causal_frontier.len() > MAX_BATCH_OPERATIONS {
            return Err(crate::ValidationError::TooLarge {
                field: "causalFrontier",
                limit: MAX_BATCH_OPERATIONS,
            });
        }
        if self
            .causal_frontier
            .windows(2)
            .any(|pair| pair[0].device_id >= pair[1].device_id)
        {
            return Err(crate::ValidationError::Invalid("causalFrontier"));
        }
        Ok(())
    }
}
