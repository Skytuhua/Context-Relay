use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ClockError {
    #[error("clock exhausted")]
    ClockExhausted,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ValidationError {
    #[error("required field {0} is empty")]
    EmptyRequired(&'static str),
    #[error("field {field} exceeds limit {limit}")]
    TooLarge { field: &'static str, limit: usize },
    #[error("invalid field {0}")]
    Invalid(&'static str),
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProtocolError {
    #[error("protocol version unsupported")]
    ProtocolVersionUnsupported,
    #[error("invalid request")]
    InvalidRequest,
    #[error("frame too large")]
    FrameTooLarge,
    #[error("clock exhausted")]
    ClockExhausted,
    #[error("invalid canonical CBOR: {0}")]
    InvalidCbor(&'static str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    ProtocolVersionUnsupported,
    InvalidRequest,
    FrameTooLarge,
    VaultLocked,
    NotFound,
    RevisionConflict,
    ScopeDenied,
    ApprovalRequired,
    PlanChanged,
    PlanExpired,
    HarnessUnsupported,
    Conflict,
    QuotaExceeded,
    Canceled,
    Timeout,
    Busy,
    Internal,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ClientError {
    pub code: ErrorCode,
    pub message: String,
    pub field_path: Option<String>,
    pub retryable: bool,
}

impl ClientError {
    pub fn vault_locked() -> Self {
        Self {
            code: ErrorCode::VaultLocked,
            message: "The local vault is locked".into(),
            field_path: None,
            retryable: true,
        }
    }
}
