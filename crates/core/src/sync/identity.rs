use std::fmt;

use context_relay_protocol::{AccountId, DeviceId, Sha256Digest, WorkspaceId};

use crate::crypto::{ContentKey, DeviceKeys};

pub struct SyncIdentity<'a> {
    pub account_id: AccountId,
    pub workspace_id: WorkspaceId,
    pub device_id: DeviceId,
    pub control_epoch: u32,
    pub key_epoch: u32,
    pub device_keys: &'a DeviceKeys,
    pub content_key: &'a ContentKey,
}

impl fmt::Debug for SyncIdentity<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyncIdentity")
            .field("account_id", &self.account_id)
            .field("workspace_id", &self.workspace_id)
            .field("device_id", &self.device_id)
            .field("control_epoch", &self.control_epoch)
            .field("key_epoch", &self.key_epoch)
            .field("device_keys", &"[REDACTED]")
            .field("content_key", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationChainHead {
    pub sequence: u64,
    pub canonical_hash: Sha256Digest,
}
