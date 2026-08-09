use context_relay_core::sync::{BackoffPolicy, TransportError};

#[test]
fn default_policy_uses_inclusive_full_jitter_across_large_attempts() {
    let policy = BackoffPolicy::DEFAULT;
    let cases = [
        (0, 1_000),
        (1, 2_000),
        (2, 4_000),
        (5, 32_000),
        (6, 60_000),
        (31, 60_000),
        (63, 60_000),
    ];
    for (attempt, bound) in cases {
        assert_eq!(policy.next_delay(attempt, 0), 0);
        assert_eq!(policy.next_delay(attempt, bound), bound);
        assert_eq!(policy.next_delay(attempt, bound + 1), 0);
        assert!(policy.next_delay(attempt, u64::MAX) <= bound);
    }
}

#[test]
fn overflow_and_maximum_bound_are_safe() {
    let policy = BackoffPolicy {
        base_ms: u64::MAX,
        cap_ms: u64::MAX,
    };
    for attempt in [0, 1, 31, 63, 64, u32::MAX] {
        assert_eq!(policy.next_delay(attempt, u64::MAX), u64::MAX);
        assert_eq!(policy.next_delay(attempt, 42), 42);
    }
}

#[test]
fn zero_values_are_explicitly_invalid() {
    assert!(
        BackoffPolicy {
            base_ms: 0,
            cap_ms: 1
        }
        .validate()
        .is_err()
    );
    assert!(
        BackoffPolicy {
            base_ms: 1,
            cap_ms: 0
        }
        .validate()
        .is_err()
    );
    assert_eq!(
        BackoffPolicy {
            base_ms: 0,
            cap_ms: 1
        }
        .next_delay(7, 9),
        0
    );
}

#[test]
fn only_transient_classes_are_retryable() {
    for retryable in [
        TransportError::Offline,
        TransportError::Transient,
        TransportError::ProviderServer,
    ] {
        assert!(retryable.is_retryable());
        assert_eq!(
            retryable.safe_code(),
            if retryable == TransportError::Offline {
                "offline"
            } else {
                "transient"
            }
        );
    }
    for blocked in [
        TransportError::AuthRequired,
        TransportError::Revoked,
        TransportError::QuotaBlocked,
        TransportError::Integrity,
        TransportError::Configuration,
    ] {
        assert!(!blocked.is_retryable());
    }
}
