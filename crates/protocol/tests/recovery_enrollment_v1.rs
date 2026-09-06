mod support;

use std::str::FromStr;

use context_relay_protocol::{
    ClientRole, DaemonInstanceNonce, DecimalTimestamp, DeviceId, DeviceState, DeviceSummary,
    JsonRpcRequestV1, LocalRequest, LocalResult, NativePlatform, PROTOCOL_VERSION,
    RecoveryEnrollmentChallenge, RecoveryEnrollmentComplete, RecoveryEnrollmentConfirmParams,
    RecoveryEnrollmentHostBeginResult, RecoveryEnrollmentHostConfirmResult, RecoveryEnrollmentId,
    RecoveryEnrollmentIdParams, RecoveryEnrollmentPhrase, RecoveryEnrollmentState,
    RecoveryEnrollmentStatus, RecoveryPhraseWords, RecoveryRootId, RecoveryWordConfirmation,
};
use serde_json::{Value, json};

const ENROLLMENT_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07398f";
const DEVICE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073990";

fn request(method: &str, params: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": support::ID,
        "protocol": {"major": 1, "minor": 6},
        "daemonInstanceNonce": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
        "method": method,
        "params": params,
    })
}

fn confirmations() -> Vec<RecoveryWordConfirmation> {
    [(2, "abandon"), (7, "ability"), (13, "able"), (24, "about")]
        .into_iter()
        .map(|(position, word)| RecoveryWordConfirmation {
            position,
            word: word.into(),
        })
        .collect()
}

fn device() -> DeviceSummary {
    DeviceSummary {
        device_id: DeviceId::from_str(DEVICE_ID).unwrap(),
        name: "First Mac".into(),
        platform: NativePlatform::Macos,
        state: DeviceState::Active,
        is_current: true,
    }
}

#[test]
fn enrollment_identifiers_are_distinct_strict_uuid_v7_types() {
    let enrollment = RecoveryEnrollmentId::from_str(ENROLLMENT_ID).unwrap();
    let root = RecoveryRootId::from_str(ENROLLMENT_ID).unwrap();
    assert_eq!(enrollment.to_string(), ENROLLMENT_ID);
    assert_eq!(root.to_string(), ENROLLMENT_ID);
}

#[test]
fn exact_five_recovery_enrollment_requests_are_strict() {
    let exact = [
        ("recovery_enrollment_begin", json!({})),
        ("recovery_enrollment_overview", json!({})),
        (
            "recovery_enrollment_confirm",
            json!({
                "enrollmentId": ENROLLMENT_ID,
                "confirmations": [
                    {"position": 2, "word": "abandon"},
                    {"position": 7, "word": "ability"},
                    {"position": 13, "word": "able"},
                    {"position": 24, "word": "about"},
                ],
            }),
        ),
        (
            "recovery_enrollment_status",
            json!({"enrollmentId": ENROLLMENT_ID}),
        ),
        (
            "recovery_enrollment_cancel",
            json!({"enrollmentId": ENROLLMENT_ID}),
        ),
    ];

    for (method, params) in exact {
        let decoded = serde_json::from_value::<JsonRpcRequestV1>(request(method, params)).unwrap();
        assert_eq!(decoded.protocol, PROTOCOL_VERSION);
        match (method, decoded.request) {
            ("recovery_enrollment_begin", LocalRequest::RecoveryEnrollmentBegin(_))
            | ("recovery_enrollment_overview", LocalRequest::RecoveryEnrollmentOverview(_))
            | ("recovery_enrollment_confirm", LocalRequest::RecoveryEnrollmentConfirm(_))
            | ("recovery_enrollment_status", LocalRequest::RecoveryEnrollmentStatus(_))
            | ("recovery_enrollment_cancel", LocalRequest::RecoveryEnrollmentCancel(_)) => {}
            _ => panic!("wrong request variant for {method}"),
        }
    }

    for forbidden in [
        "recoveryPhraseWords",
        "accountId",
        "workspaceId",
        "deviceId",
        "signingPublicKey",
        "wrappingPublicKey",
        "controlEpoch",
        "keyEpoch",
        "certificate",
        "unknown",
    ] {
        let mut value = request(
            "recovery_enrollment_confirm",
            json!({
                "enrollmentId": ENROLLMENT_ID,
                "confirmations": [
                    {"position": 2, "word": "abandon"},
                    {"position": 7, "word": "ability"},
                    {"position": 13, "word": "able"},
                    {"position": 24, "word": "about"},
                ],
            }),
        );
        value["params"][forbidden] = json!(true);
        assert!(
            serde_json::from_value::<JsonRpcRequestV1>(value).is_err(),
            "caller-controlled {forbidden} must be rejected"
        );
    }
}

#[test]
fn confirmation_words_require_four_sorted_unique_bounded_entries() {
    let valid = LocalRequest::RecoveryEnrollmentConfirm(RecoveryEnrollmentConfirmParams {
        enrollment_id: RecoveryEnrollmentId::from_str(ENROLLMENT_ID).unwrap(),
        confirmations: confirmations(),
    });
    valid.validate().unwrap();

    let invalid = [
        json!([
            {"position": 2, "word": "abandon"},
            {"position": 7, "word": "ability"},
            {"position": 13, "word": "able"},
        ]),
        json!([
            {"position": 2, "word": "abandon"},
            {"position": 7, "word": "ability"},
            {"position": 13, "word": "able"},
            {"position": 20, "word": "about"},
            {"position": 24, "word": "above"},
        ]),
        json!([
            {"position": 0, "word": "abandon"},
            {"position": 7, "word": "ability"},
            {"position": 13, "word": "able"},
            {"position": 24, "word": "about"},
        ]),
        json!([
            {"position": 2, "word": "abandon"},
            {"position": 7, "word": "ability"},
            {"position": 13, "word": "able"},
            {"position": 25, "word": "about"},
        ]),
        json!([
            {"position": 2, "word": "abandon"},
            {"position": 7, "word": "ability"},
            {"position": 7, "word": "able"},
            {"position": 24, "word": "about"},
        ]),
        json!([
            {"position": 2, "word": "abandon"},
            {"position": 13, "word": "ability"},
            {"position": 7, "word": "able"},
            {"position": 24, "word": "about"},
        ]),
        json!([
            {"position": 2, "word": "Abandon"},
            {"position": 7, "word": "ability"},
            {"position": 13, "word": "able"},
            {"position": 24, "word": "about"},
        ]),
        json!([
            {"position": 2, "word": ""},
            {"position": 7, "word": "ability"},
            {"position": 13, "word": "able"},
            {"position": 24, "word": "about"},
        ]),
        json!([
            {"position": 2, "word": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
            {"position": 7, "word": "ability"},
            {"position": 13, "word": "able"},
            {"position": 24, "word": "about"},
        ]),
    ];

    for confirmations in invalid {
        assert!(
            serde_json::from_value::<JsonRpcRequestV1>(request(
                "recovery_enrollment_confirm",
                json!({
                    "enrollmentId": ENROLLMENT_ID,
                    "confirmations": confirmations,
                }),
            ))
            .is_err()
        );
    }

    let mut unknown = request(
        "recovery_enrollment_confirm",
        json!({
            "enrollmentId": ENROLLMENT_ID,
            "confirmations": [
                {"position": 2, "word": "abandon", "extra": true},
                {"position": 7, "word": "ability"},
                {"position": 13, "word": "able"},
                {"position": 24, "word": "about"},
            ],
        }),
    );
    assert!(serde_json::from_value::<JsonRpcRequestV1>(unknown.clone()).is_err());
    unknown["params"]["confirmations"][0]
        .as_object_mut()
        .unwrap()
        .remove("extra");
    assert!(serde_json::from_value::<JsonRpcRequestV1>(unknown).is_ok());
}

#[test]
fn phrase_and_confirmation_debug_are_recursively_redacted() {
    let phrase = RecoveryEnrollmentPhrase {
        enrollment_id: RecoveryEnrollmentId::from_str(ENROLLMENT_ID).unwrap(),
        recovery_phrase_words: RecoveryPhraseWords::new(vec!["abandon".into(); 24]).unwrap(),
        confirmation_positions: vec![2, 7, 13, 24],
        created_at_ms: DecimalTimestamp(1),
        expires_at_ms: DecimalTimestamp(600_001),
    };
    let phrase_debug = format!("{phrase:?}");
    assert!(phrase_debug.contains("[REDACTED]"));
    for word in phrase.recovery_phrase_words.as_words() {
        assert!(!phrase_debug.contains(word));
    }

    let params = RecoveryEnrollmentConfirmParams {
        enrollment_id: phrase.enrollment_id,
        confirmations: confirmations(),
    };
    let request = LocalRequest::RecoveryEnrollmentConfirm(params.clone());
    let rpc = JsonRpcRequestV1 {
        jsonrpc: context_relay_protocol::JsonRpcVersion::V2,
        id: support::ID.parse().unwrap(),
        protocol: PROTOCOL_VERSION,
        daemon_instance_nonce: DaemonInstanceNonce::new([1; 32]),
        request,
    };
    for rendered in [format!("{params:?}"), format!("{rpc:?}")] {
        assert!(rendered.contains("[REDACTED]"));
        for word in ["abandon", "ability", "able", "about"] {
            assert!(!rendered.contains(word));
        }
    }
}

#[test]
fn enrollment_status_enforces_exact_nullability() {
    let enrollment_id = RecoveryEnrollmentId::from_str(ENROLLMENT_ID).unwrap();
    let states = [
        (
            RecoveryEnrollmentState::Idle,
            RecoveryEnrollmentStatus {
                enrollment_id: None,
                state: RecoveryEnrollmentState::Idle,
                created_at_ms: None,
                transitioned_at_ms: None,
            },
        ),
        (
            RecoveryEnrollmentState::AwaitingConfirmation,
            RecoveryEnrollmentStatus {
                enrollment_id: Some(enrollment_id),
                state: RecoveryEnrollmentState::AwaitingConfirmation,
                created_at_ms: Some(DecimalTimestamp(1)),
                transitioned_at_ms: None,
            },
        ),
        (
            RecoveryEnrollmentState::Submitting,
            RecoveryEnrollmentStatus {
                enrollment_id: Some(enrollment_id),
                state: RecoveryEnrollmentState::Submitting,
                created_at_ms: Some(DecimalTimestamp(1)),
                transitioned_at_ms: Some(DecimalTimestamp(2)),
            },
        ),
        (
            RecoveryEnrollmentState::Complete,
            RecoveryEnrollmentStatus {
                enrollment_id: Some(enrollment_id),
                state: RecoveryEnrollmentState::Complete,
                created_at_ms: Some(DecimalTimestamp(1)),
                transitioned_at_ms: Some(DecimalTimestamp(2)),
            },
        ),
        (
            RecoveryEnrollmentState::Conflict,
            RecoveryEnrollmentStatus {
                enrollment_id: Some(enrollment_id),
                state: RecoveryEnrollmentState::Conflict,
                created_at_ms: Some(DecimalTimestamp(1)),
                transitioned_at_ms: Some(DecimalTimestamp(2)),
            },
        ),
    ];

    for (state, status) in states {
        status.validate().unwrap();
        let value = serde_json::to_value(LocalResult::RecoveryEnrollmentStatus {
            status: status.clone(),
        })
        .unwrap();
        assert_eq!(
            serde_json::from_value::<LocalResult>(value).unwrap(),
            LocalResult::RecoveryEnrollmentStatus {
                status: status.clone(),
            }
        );
        assert_eq!(status.state, state);
    }

    for invalid in [
        RecoveryEnrollmentStatus {
            enrollment_id: Some(enrollment_id),
            state: RecoveryEnrollmentState::Idle,
            created_at_ms: None,
            transitioned_at_ms: None,
        },
        RecoveryEnrollmentStatus {
            enrollment_id: Some(enrollment_id),
            state: RecoveryEnrollmentState::AwaitingConfirmation,
            created_at_ms: None,
            transitioned_at_ms: None,
        },
        RecoveryEnrollmentStatus {
            enrollment_id: Some(enrollment_id),
            state: RecoveryEnrollmentState::Complete,
            created_at_ms: Some(DecimalTimestamp(1)),
            transitioned_at_ms: None,
        },
    ] {
        assert!(invalid.validate().is_err());
    }
}

#[test]
fn native_host_results_are_closed_word_free_projections() {
    let enrollment_id = RecoveryEnrollmentId::from_str(ENROLLMENT_ID).unwrap();
    let challenge = RecoveryEnrollmentChallenge {
        enrollment_id,
        confirmation_positions: vec![2, 7, 13, 24],
        created_at_ms: DecimalTimestamp(1),
        expires_at_ms: DecimalTimestamp(600_001),
    };
    let begin = RecoveryEnrollmentHostBeginResult::Challenge(challenge);
    let confirm = RecoveryEnrollmentHostConfirmResult::Complete(RecoveryEnrollmentComplete {
        enrollment_id,
        device: device(),
    });

    for value in [
        serde_json::to_value(begin).unwrap(),
        serde_json::to_value(confirm).unwrap(),
    ] {
        let encoded = serde_json::to_string(&value).unwrap();
        assert!(!encoded.contains("word"));
        assert!(!encoded.contains("phrase"));
        assert!(!encoded.contains("recoveryPhraseWords"));
    }

    let status_params = RecoveryEnrollmentIdParams { enrollment_id };
    assert_eq!(
        serde_json::to_value(status_params).unwrap(),
        json!({"enrollmentId": ENROLLMENT_ID})
    );
}

#[test]
fn phrase_and_challenge_require_the_exact_ten_minute_window() {
    let enrollment_id = RecoveryEnrollmentId::from_str(ENROLLMENT_ID).unwrap();

    for expires_at_ms in [600_000, 600_002] {
        let phrase = RecoveryEnrollmentPhrase {
            enrollment_id,
            recovery_phrase_words: RecoveryPhraseWords::new(vec!["abandon".into(); 24]).unwrap(),
            confirmation_positions: vec![2, 7, 13, 24],
            created_at_ms: DecimalTimestamp(1),
            expires_at_ms: DecimalTimestamp(expires_at_ms),
        };
        assert!(
            serde_json::to_value(LocalResult::RecoveryEnrollmentPhrase { phrase }).is_err(),
            "non-ten-minute phrase window {expires_at_ms} must fail"
        );

        let challenge = RecoveryEnrollmentHostBeginResult::Challenge(RecoveryEnrollmentChallenge {
            enrollment_id,
            confirmation_positions: vec![2, 7, 13, 24],
            created_at_ms: DecimalTimestamp(1),
            expires_at_ms: DecimalTimestamp(expires_at_ms),
        });
        assert!(
            serde_json::to_value(challenge).is_err(),
            "non-ten-minute challenge window {expires_at_ms} must fail"
        );
    }

    let exact = RecoveryEnrollmentHostBeginResult::Challenge(RecoveryEnrollmentChallenge {
        enrollment_id,
        confirmation_positions: vec![2, 7, 13, 24],
        created_at_ms: DecimalTimestamp(1),
        expires_at_ms: DecimalTimestamp(600_001),
    });
    let exact_json = serde_json::to_value(&exact).unwrap();
    assert_eq!(
        serde_json::from_value::<RecoveryEnrollmentHostBeginResult>(exact_json).unwrap(),
        exact
    );

    let invalid_json = json!({
        "kind": "challenge",
        "data": {
            "enrollmentId": ENROLLMENT_ID,
            "confirmationPositions": [2, 7, 13, 24],
            "createdAtMs": "1",
            "expiresAtMs": "600002"
        }
    });
    assert!(serde_json::from_value::<RecoveryEnrollmentHostBeginResult>(invalid_json).is_err());
}

#[test]
fn recovery_host_is_a_distinct_role() {
    assert_ne!(ClientRole::Desktop, ClientRole::DesktopRecoveryHost);
}
