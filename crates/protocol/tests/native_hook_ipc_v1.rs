use context_relay_protocol::{
    CompletionEvidenceInput, HarnessId, LocalRequest, MAX_EVIDENCE_BYTES, MAX_EVIDENCE_ITEMS,
    MAX_TITLE_BYTES, McpBinding, NativeHookEvent, NativeHookEventParams, NativePlatform, TaskId,
    WireNativeValue,
};
use serde_json::{Value, json};

const ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07398f";

fn binding() -> McpBinding {
    McpBinding {
        harness: HarnessId::Codex,
        working_directory: WireNativeValue {
            platform: NativePlatform::Macos,
            bytes: b"/workspace".to_vec(),
            display: Some("/workspace".into()),
        },
    }
}

fn request(event: NativeHookEvent) -> LocalRequest {
    LocalRequest::NativeHookEvent(NativeHookEventParams {
        binding: binding(),
        event,
        occurred_at_ms: 1_700_000_000_123,
    })
}

fn evidence() -> CompletionEvidenceInput {
    CompletionEvidenceInput {
        summary: "Focused tests passed".into(),
        kind: "test".into(),
        reference: Some("native-hook-ipc-v1".into()),
    }
}

#[test]
fn lifecycle_events_use_exact_snake_case_tags_and_decimal_timestamps() {
    let start = serde_json::to_value(request(NativeHookEvent::SessionStart {
        session_id: "session-1".into(),
    }))
    .unwrap();
    assert_eq!(
        start,
        json!({
            "method": "native_hook_event",
            "params": {
                "binding": {
                    "harness": "codex",
                    "workingDirectory": {
                        "platform": "macos",
                        "bytes": "L3dvcmtzcGFjZQ",
                        "display": "/workspace"
                    }
                },
                "event": {"kind": "session_start", "session_id": "session-1"},
                "occurredAtMs": "1700000000123"
            }
        })
    );

    let stop: LocalRequest = serde_json::from_value(json!({
        "method": "native_hook_event",
        "params": {
            "binding": start["params"]["binding"].clone(),
            "event": {"kind": "session_stop", "session_id": "session-1"},
            "occurredAtMs": "1700000000124"
        }
    }))
    .unwrap();
    assert!(matches!(
        stop,
        LocalRequest::NativeHookEvent(NativeHookEventParams {
            event: NativeHookEvent::SessionStop { .. },
            occurred_at_ms: 1_700_000_000_124,
            ..
        })
    ));
}

#[test]
fn task_evidence_round_trips_and_rejects_unknown_fields() {
    let task_id = ID.parse::<TaskId>().unwrap();
    let value = serde_json::to_value(request(NativeHookEvent::TaskEvidence {
        session_id: "session-1".into(),
        task_id,
        evidence: vec![evidence()],
    }))
    .unwrap();
    assert_eq!(value["params"]["event"]["kind"], "task_evidence");
    assert_eq!(value["params"]["event"]["session_id"], "session-1");
    assert_eq!(value["params"]["event"]["task_id"], ID);
    assert_eq!(value["params"]["event"]["evidence"][0]["kind"], "test");
    assert_eq!(
        serde_json::from_value::<LocalRequest>(value.clone()).unwrap(),
        request(NativeHookEvent::TaskEvidence {
            session_id: "session-1".into(),
            task_id,
            evidence: vec![evidence()],
        })
    );

    let mut envelope_unknown = value.clone();
    envelope_unknown["unexpected"] = Value::Bool(true);
    let mut params_unknown = value.clone();
    params_unknown["params"]["unexpected"] = Value::Bool(true);
    let mut event_unknown = value;
    event_unknown["params"]["event"]["unexpected"] = Value::Bool(true);
    for invalid in [envelope_unknown, params_unknown, event_unknown] {
        assert!(serde_json::from_value::<LocalRequest>(invalid).is_err());
    }
}

#[test]
fn hook_events_validate_session_evidence_and_native_path_bounds() {
    for session_id in [String::new(), "x".repeat(MAX_TITLE_BYTES + 1)] {
        assert!(
            request(NativeHookEvent::SessionStart { session_id })
                .validate()
                .is_err()
        );
    }

    let task_id = ID.parse::<TaskId>().unwrap();
    assert!(
        request(NativeHookEvent::TaskEvidence {
            session_id: "session-1".into(),
            task_id,
            evidence: vec![],
        })
        .validate()
        .is_err()
    );
    assert!(
        request(NativeHookEvent::TaskEvidence {
            session_id: "session-1".into(),
            task_id,
            evidence: vec![evidence(); MAX_EVIDENCE_ITEMS + 1],
        })
        .validate()
        .is_err()
    );

    let mut oversized = evidence();
    oversized.summary = "x".repeat(MAX_EVIDENCE_BYTES + 1);
    assert!(
        request(NativeHookEvent::TaskEvidence {
            session_id: "session-1".into(),
            task_id,
            evidence: vec![oversized],
        })
        .validate()
        .is_err()
    );

    let LocalRequest::NativeHookEvent(mut params) = request(NativeHookEvent::SessionStop {
        session_id: "session-1".into(),
    }) else {
        unreachable!();
    };
    params.binding.working_directory = WireNativeValue {
        platform: NativePlatform::Windows,
        bytes: vec![0],
        display: None,
    };
    assert!(LocalRequest::NativeHookEvent(params).validate().is_err());
}
