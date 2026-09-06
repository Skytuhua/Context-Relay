use context_relay_protocol::{LocalRequest, LocalResult};
use serde_json::json;

#[test]
fn tracked_execution_binds_only_original_plan_and_action() {
    for method in ["harness_execution_start", "harness_execution_status"] {
        for action in ["apply", "rollback"] {
            let mut value = json!({"method":method,"params":{
                "planId":"018f22e2-79b0-7cc8-98c4-dc0c0c07398f","action":action}});
            let parsed: LocalRequest = serde_json::from_value(value.clone()).unwrap();
            parsed.validate().unwrap();
            assert_eq!(serde_json::to_value(parsed).unwrap(), value);
            value["params"]["path"] = json!("injected.exe");
            assert!(serde_json::from_value::<LocalRequest>(value).is_err());
        }
    }
}

#[test]
fn execution_status_does_not_confuse_pending_or_unknown_with_success() {
    let current = json!({"kind":"harness_execution_current","data":{"status":null}});
    assert_eq!(
        serde_json::to_value(serde_json::from_value::<LocalResult>(current.clone()).unwrap())
            .unwrap(),
        current
    );
    assert!(
        serde_json::from_value::<LocalResult>(
            json!({"kind":"harness_execution_current","data":{}})
        )
        .is_err()
    );
    for phase in ["queued", "running", "finished", "unknown"] {
        let mut value = json!({"kind":"harness_execution","data":{"status":{
            "planId":"018f22e2-79b0-7cc8-98c4-dc0c0c07398f","action":"apply",
            "phase":phase,"error":null}}});
        assert_eq!(
            serde_json::to_value(serde_json::from_value::<LocalResult>(value.clone()).unwrap())
                .unwrap(),
            value
        );
        value["data"]["status"]["error"] = json!({"code":"internal","message":"Save was not confirmed","fieldPath":null,"retryable":false});
        assert_eq!(
            serde_json::from_value::<LocalResult>(value.clone()).is_ok(),
            phase == "finished"
        );
        value["data"]["status"]
            .as_object_mut()
            .unwrap()
            .remove("error");
        assert!(serde_json::from_value::<LocalResult>(value).is_err());
    }
}

#[test]
fn setup_history_requires_closed_bounded_records_and_an_explicit_cursor() {
    let summary = json!({"planId":"018f22e2-79b0-7cc8-98c4-dc0c0c07398f",
        "harness":"codex","harnessProfile":null,"targetScopes":[{"scope":"global"}],
        "state":"applied","createdAt":"1900000000000","expiresAt":"1900000060000"});
    let page = json!({"kind":"harness_setups","data":{"page":{"setups":[summary.clone()],"nextAfter":null}}});
    assert_eq!(
        serde_json::to_value(serde_json::from_value::<LocalResult>(page.clone()).unwrap()).unwrap(),
        page
    );
    let mut invalid = page.clone();
    invalid["data"]["page"]["setups"] = json!(vec![summary.clone(); 51]);
    assert!(serde_json::from_value::<LocalResult>(invalid).is_err());
    let mut invalid = page.clone();
    invalid["data"]["page"]
        .as_object_mut()
        .unwrap()
        .remove("nextAfter");
    assert!(serde_json::from_value::<LocalResult>(invalid).is_err());
    for (field, value) in [
        ("state", json!("connected")),
        ("createdAt", json!(123)),
        ("harnessProfile", json!("default")),
        ("targetScopes", json!([])),
        ("runtimePath", json!("private")),
    ] {
        let mut invalid = page.clone();
        invalid["data"]["page"]["setups"][0][field] = value;
        assert!(
            serde_json::from_value::<LocalResult>(invalid).is_err(),
            "{field}"
        );
    }
    for method in [
        "harness_execution_current",
        "harness_setups_list",
        "harness_setup_get",
    ] {
        let params = match method {
            "harness_execution_current" => json!({}),
            "harness_setups_list" => json!({"after":null}),
            _ => json!({"planId":summary["planId"]}),
        };
        let mut value = json!({"method":method,"params":params});
        assert!(serde_json::from_value::<LocalRequest>(value.clone()).is_ok());
        value["params"]["runtimePath"] = json!("injected");
        assert!(serde_json::from_value::<LocalRequest>(value).is_err());
    }
}
