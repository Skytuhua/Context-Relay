use context_relay_protocol::{LocalRequest, LocalResult};
use serde_json::{Value, json};

fn selection() -> Value {
    json!({"projectId": null, "harness": "hermes", "hermesProfile": "default"})
}
fn id() -> &'static str {
    "018f22e2-79b0-7cc8-98c4-dc0c0c07398f"
}
fn status() -> Value {
    json!({"kind": "harness_preparation", "data": {"status": {
        "operationId": id(), "selection": selection(), "phase": "copying",
        "completedFiles": 2, "completedBytes": 65536, "error": null
    }}})
}

#[test]
fn preparation_requests_are_closed_and_bind_selection_without_paths() {
    for method in [
        "harness_prepare",
        "harness_preparation_status",
        "harness_preparation_cancel",
    ] {
        let mut request = json!({"method": method, "params": {"operationId": id()}});
        if method == "harness_prepare" {
            request["params"]["selection"] = selection();
        }
        let parsed: LocalRequest = serde_json::from_value(request.clone()).unwrap();
        parsed.validate().unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), request);
        request["params"]["executable"] = json!("untrusted.exe");
        assert!(serde_json::from_value::<LocalRequest>(request).is_err());
    }
    let request = json!({"method": "harness_prepare", "params": {"operationId": id(),
        "selection": {"projectId": null, "harness": "codex", "hermesProfile": null}}});
    assert!(
        serde_json::from_value::<LocalRequest>(request)
            .unwrap()
            .validate()
            .is_err()
    );
}

#[test]
fn preparation_status_rejects_ambiguous_terminal_states_and_invalid_counters() {
    let valid = status();
    assert_eq!(
        serde_json::to_value(serde_json::from_value::<LocalResult>(valid.clone()).unwrap())
            .unwrap(),
        valid
    );
    for (field, value) in [
        ("phase", json!("unknown")),
        ("phase", json!("failed")),
        ("completedFiles", json!(32769)),
        ("completedBytes", json!(1_073_741_825u64)),
        ("completedBytes", json!(-1)),
        ("completedFiles", json!(0.5)),
    ] {
        let mut invalid = valid.clone();
        invalid["data"]["status"][field] = value;
        assert!(
            serde_json::from_value::<LocalResult>(invalid).is_err(),
            "{field}"
        );
    }
    let mut missing = valid.clone();
    missing["data"]["status"]
        .as_object_mut()
        .unwrap()
        .remove("error");
    assert!(serde_json::from_value::<LocalResult>(missing).is_err());
    let mut failed = valid;
    failed["data"]["status"]["phase"] = json!("failed");
    failed["data"]["status"]["error"] = json!({"code": "internal", "message": "Preparation failed", "fieldPath": null, "retryable": true});
    assert!(serde_json::from_value::<LocalResult>(failed.clone()).is_ok());
    failed["data"]["status"]["phase"] = json!("ready");
    assert!(serde_json::from_value::<LocalResult>(failed).is_err());
}
