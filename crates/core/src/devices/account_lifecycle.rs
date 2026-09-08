use std::{error::Error, fmt};

use context_relay_protocol::AccountDeletionState;

pub const ACCOUNT_DELETION_GRACE_MS: u64 = 7 * 24 * 60 * 60 * 1_000;

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum AccountLifecycleTransportError {
    Invalid,
    Unavailable,
    Conflict,
    Unauthorized,
    Transient,
}

impl AccountLifecycleTransportError {
    pub const fn safe_code(self) -> &'static str {
        match self {
            Self::Invalid => "account_lifecycle_invalid",
            Self::Unavailable => "account_lifecycle_unavailable",
            Self::Conflict => "account_lifecycle_conflict",
            Self::Unauthorized => "account_lifecycle_unauthorized",
            Self::Transient => "transient",
        }
    }
}

impl fmt::Debug for AccountLifecycleTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.safe_code())
    }
}

impl fmt::Display for AccountLifecycleTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.safe_code())
    }
}

impl Error for AccountLifecycleTransportError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountDeletionProjection {
    pub state: AccountDeletionState,
    pub requested_at_ms: Option<u64>,
    pub purge_deadline_ms: Option<u64>,
}

impl AccountDeletionProjection {
    pub fn validate(&self) -> Result<(), AccountLifecycleTransportError> {
        let valid = match self.state {
            AccountDeletionState::Active | AccountDeletionState::Purged => {
                self.requested_at_ms.is_none() && self.purge_deadline_ms.is_none()
            }
            AccountDeletionState::PendingDelete => {
                let (Some(requested_at_ms), Some(purge_deadline_ms)) =
                    (self.requested_at_ms, self.purge_deadline_ms)
                else {
                    return Err(AccountLifecycleTransportError::Conflict);
                };
                requested_at_ms <= i64::MAX as u64
                    && requested_at_ms.checked_add(ACCOUNT_DELETION_GRACE_MS)
                        == Some(purge_deadline_ms)
                    && purge_deadline_ms <= i64::MAX as u64
            }
        };
        if valid {
            Ok(())
        } else {
            Err(AccountLifecycleTransportError::Conflict)
        }
    }

    pub fn export_available(&self) -> bool {
        self.state == AccountDeletionState::PendingDelete && self.validate().is_ok()
    }
}

/// Scope- and session-bound provider boundary for the seven-day account deletion lifecycle.
///
/// A concrete implementation owns its authenticated hosted session. Callers cannot supply an
/// account identifier, session identifier, transition timestamp, or provider projection.
pub trait AccountLifecycleTransport: Send + Sync {
    fn deletion_status(&self) -> Result<AccountDeletionProjection, AccountLifecycleTransportError>;

    fn begin_deletion(&self) -> Result<AccountDeletionProjection, AccountLifecycleTransportError>;

    fn cancel_deletion(&self) -> Result<AccountDeletionProjection, AccountLifecycleTransportError>;
}
