mod support;

use context_relay_protocol::{HarnessId, LocalRequest, SetupPlan};
use serde_json::json;

#[test]
fn hermes_setup_requires_an_explicit_typed_profile() {
    let selected = serde_json::from_value::<LocalRequest>(json!({
        "method": "harness_preview",
        "params": {
            "harness": "hermes",
            "projectId": null,
            "hermesProfile": "coder"
        }
    }))
    .unwrap();
    assert!(selected.validate().is_ok());

    for params in [
        json!({"harness": "hermes", "projectId": null, "hermesProfile": null}),
        json!({"harness": "hermes", "projectId": null}),
        json!({"harness": "codex", "projectId": null, "hermesProfile": "coder"}),
    ] {
        let decoded = serde_json::from_value::<LocalRequest>(json!({
            "method": "harness_preview",
            "params": params
        }));
        assert!(decoded.is_err() || decoded.unwrap().validate().is_err());
    }
}

#[test]
fn sealed_setup_plan_binds_the_selected_hermes_profile() {
    let mut value = serde_json::to_value(support::setup_plan()).unwrap();
    value["harness"] = json!("hermes");
    value["harnessProfile"] = json!("coder");
    let selected = serde_json::from_value::<SetupPlan>(value).unwrap();
    assert_eq!(selected.harness, HarnessId::Hermes);
    assert_eq!(
        serde_json::to_value(selected).unwrap()["harnessProfile"],
        "coder"
    );
}
