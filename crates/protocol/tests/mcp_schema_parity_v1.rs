use context_relay_protocol::{
    MAX_BATCH_OPERATIONS, MAX_EVIDENCE_ITEMS, mcp_schema, validate_mcp_fixture,
};

#[test]
fn status_output_requires_a_range_containing_supported_v1() {
    let mut output = serde_json::json!({
        "protocol": {
            "min": { "major": 1, "minor": 0 },
            "max": { "major": 1, "minor": 0 }
        },
        "vault": "unlocked",
        "resolvedProject": null,
        "sync": "idle",
        "access": { "mode": "default" }
    });
    assert!(validate_mcp_fixture("context_relay_status", false, &output).is_ok());

    for protocol in [
        serde_json::json!({
            "min": { "major": 2, "minor": 0 },
            "max": { "major": 2, "minor": 0 }
        }),
        serde_json::json!({
            "min": { "major": 1, "minor": 1 },
            "max": { "major": 1, "minor": 2 }
        }),
        serde_json::json!({
            "min": { "major": 1, "minor": 1 },
            "max": { "major": 1, "minor": 0 }
        }),
    ] {
        output["protocol"] = protocol;
        assert!(
            validate_mcp_fixture("context_relay_status", false, &output).is_err(),
            "invalid status protocol range was accepted: {}",
            output["protocol"]
        );
    }
}

#[test]
fn upsert_option_pairing_and_tag_uniqueness_are_frozen() {
    let upsert = mcp_schema("context_relay_upsert_task").unwrap().input;
    assert!(upsert.get("anyOf").is_some());
    assert!(upsert.get("oneOf").is_none());
    for name in ["context_relay_remember", "context_relay_propose_memory"] {
        let schema = mcp_schema(name).unwrap().input;
        assert_eq!(schema["properties"]["tags"]["uniqueItems"], true);
        let mut value = serde_json::json!({
            "operationId":"018f22e2-79b0-7cc8-98c4-dc0c0c07398f",
            "kind":"fact","title":"title","markdown":"body","tags":["same","same"],
            "scope":{"scope":"global"}
        });
        if name == "context_relay_propose_memory" {
            value["evidenceSummary"] = "evidence".into();
        }
        assert!(validate_mcp_fixture(name, true, &value).is_err());
    }
}

#[test]
fn nested_output_bounds_and_decision_kind_match_semantic_validation() {
    let search = mcp_schema("context_relay_search").unwrap().output;
    assert_eq!(
        search["properties"]["memories"]["maxItems"],
        MAX_BATCH_OPERATIONS
    );
    assert_eq!(
        search["properties"]["instructions"]["items"]["properties"]["title"]["maxLength"],
        512
    );
    let list = mcp_schema("context_relay_list_tasks").unwrap().output;
    assert_eq!(
        list["properties"]["tasks"]["maxItems"],
        MAX_BATCH_OPERATIONS
    );
    assert_eq!(
        list["properties"]["tasks"]["items"]["properties"]["evidence"]["items"]["properties"]["reference"]
            ["oneOf"][1]["maxLength"],
        16 * 1024
    );
    let handoff = mcp_schema("context_relay_create_handoff").unwrap().output;
    assert_eq!(
        handoff["properties"]["payload"]["properties"]["decisions"]["maxItems"],
        MAX_EVIDENCE_ITEMS
    );
    assert_eq!(
        handoff["properties"]["payload"]["properties"]["decisions"]["items"]["properties"]["kind"]
            ["const"],
        "decision"
    );
}
