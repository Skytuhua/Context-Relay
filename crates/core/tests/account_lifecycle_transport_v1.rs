use context_relay_core::devices::account_lifecycle::{
    AccountDeletionProjection, AccountLifecycleTransportError,
};
use context_relay_protocol::AccountDeletionState;

const SEVEN_DAYS_MS: u64 = 7 * 24 * 60 * 60 * 1_000;

#[test]
fn deletion_projection_requires_an_exact_seven_day_hosted_state() {
    let pending = AccountDeletionProjection {
        state: AccountDeletionState::PendingDelete,
        requested_at_ms: Some(1_000),
        purge_deadline_ms: Some(1_000 + SEVEN_DAYS_MS),
    };
    assert_eq!(pending.validate(), Ok(()));
    assert!(pending.export_available());

    for invalid in [
        AccountDeletionProjection {
            state: AccountDeletionState::PendingDelete,
            requested_at_ms: None,
            purge_deadline_ms: Some(1_000 + SEVEN_DAYS_MS),
        },
        AccountDeletionProjection {
            state: AccountDeletionState::PendingDelete,
            requested_at_ms: Some(1_000),
            purge_deadline_ms: Some(1_000 + SEVEN_DAYS_MS - 1),
        },
        AccountDeletionProjection {
            state: AccountDeletionState::Active,
            requested_at_ms: Some(1_000),
            purge_deadline_ms: Some(1_000 + SEVEN_DAYS_MS),
        },
        AccountDeletionProjection {
            state: AccountDeletionState::Purged,
            requested_at_ms: None,
            purge_deadline_ms: Some(1_000 + SEVEN_DAYS_MS),
        },
    ] {
        assert_eq!(
            invalid.validate(),
            Err(AccountLifecycleTransportError::Conflict)
        );
        assert!(!invalid.export_available());
    }

    let active = AccountDeletionProjection {
        state: AccountDeletionState::Active,
        requested_at_ms: None,
        purge_deadline_ms: None,
    };
    assert_eq!(active.validate(), Ok(()));
    assert!(!active.export_available());

    let purged = AccountDeletionProjection {
        state: AccountDeletionState::Purged,
        requested_at_ms: None,
        purge_deadline_ms: None,
    };
    assert_eq!(purged.validate(), Ok(()));
    assert!(!purged.export_available());
}
