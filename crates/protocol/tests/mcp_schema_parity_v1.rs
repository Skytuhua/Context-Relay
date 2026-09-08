use context_relay_protocol::{
    MAX_BATCH_OPERATIONS, MAX_EVIDENCE_ITEMS, mcp_schema, validate_mcp_fixture,
};

#[test]
fn status_output_requires_the_exact_supported_local_version() {
    let mut output = serde_json::json!({
        "protocol": {
            "min": { "major": 1, "minor": 14 },
            "max": { "major": 1, "minor": 14 }
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
            "min": { "major": 1, "minor": 0 },
            "max": { "major": 1, "minor": 0 }
        }),
        serde_json::json!({
            "min": { "major": 1, "minor": 7 },
            "max": { "major": 1, "minor": 14 }
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
    let id = serde_json::json!("018f22e2-79b0-7cc8-98c4-dc0c0c07398f");
    for task in [None, Some(serde_json::Value::Null), Some(id.clone())] {
        for revision in [None, Some(serde_json::Value::Null), Some(id.clone())] {
            let mut value = serde_json::json!({"operationId":id,"title":"Task","bodyMarkdown":"Body","status":"open"});
            if let Some(task) = &task {
                value["taskId"] = task.clone();
            }
            if let Some(revision) = &revision {
                value["expectedRevision"] = revision.clone();
            }
            let paired = task.as_ref().is_some_and(|v| v.is_string())
                == revision.as_ref().is_some_and(|v| v.is_string());
            assert_eq!(
                validate_mcp_fixture("context_relay_upsert_task", true, &value).is_ok(),
                paired,
                "{value}"
            );
        }
    }
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
fn model_tool_inputs_do_not_use_unsupported_top_level_combinators() {
    // The actual Claude client drops tools with these root keywords before
    // sending the model request, even when type is explicitly object.
    for name in context_relay_protocol::MCP_TOOL_NAMES {
        let input = mcp_schema(name).unwrap().input;
        for keyword in ["anyOf", "oneOf", "allOf"] {
            assert!(input.get(keyword).is_none(), "{name}: {keyword}");
        }
    }
}

#[test]
fn handoff_requires_at_least_one_selected_record() {
    let id = serde_json::json!("018f22e2-79b0-7cc8-98c4-dc0c0c07398f");
    let decision = serde_json::json!("018f22e2-79b0-7cc8-98c4-dc0c0c073990");
    for mask in 0..8 {
        let value = serde_json::json!({"operationId":id,"summary":"Continue",
            "memoryIds":if mask & 1 != 0 { vec![id.clone()] } else { vec![] },
            "decisionIds":if mask & 2 != 0 { vec![decision.clone()] } else { vec![] },
            "taskIds":if mask & 4 != 0 { vec![id.clone()] } else { vec![] },
        });
        assert_eq!(
            validate_mcp_fixture("context_relay_create_handoff", true, &value).is_ok(),
            mask != 0,
            "{value}"
        );
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
