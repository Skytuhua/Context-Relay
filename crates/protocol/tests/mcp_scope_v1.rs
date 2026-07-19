use context_relay_protocol::{
    ListTasksInput, ProposeMemoryInput, RememberInput, SearchInput, UpsertTaskInput, mcp_schema,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

const ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07398f";
const PROJECT_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073990";

fn round_trip<T: DeserializeOwned + Serialize>(value: Value) -> Value {
    serde_json::to_value(serde_json::from_value::<T>(value).unwrap()).unwrap()
}

#[test]
fn mcp_inputs_serialize_without_caller_project_ids() {
    let values = [
        round_trip::<SearchInput>(json!({"query":"needle","scope":{"scope":"active_project"}})),
        round_trip::<RememberInput>(json!({
            "operationId": ID, "kind":"fact", "title":"Title", "markdown":"Body", "tags":[],
            "scope":{"scope":"global"}
        })),
        round_trip::<ProposeMemoryInput>(json!({
            "operationId": ID, "kind":"fact", "title":"Title", "markdown":"Body", "tags":[],
            "evidenceSummary":"Observed", "scope":{"scope":"active_project"}
        })),
        round_trip::<ListTasksInput>(json!({"status":"open"})),
        round_trip::<UpsertTaskInput>(json!({
            "operationId": ID, "title":"Task", "bodyMarkdown":"Body", "status":"open"
        })),
    ];

    for value in values {
        let encoded = value.to_string();
        assert!(!encoded.contains("projectId"), "{encoded}");
        assert!(!encoded.contains(PROJECT_ID), "{encoded}");
    }
}

#[test]
fn mcp_inputs_reject_legacy_caller_project_selectors() {
    let legacy_scope = json!({"scope":"project","projectId":PROJECT_ID});
    assert!(
        serde_json::from_value::<SearchInput>(json!({"query":"needle","scope":legacy_scope}))
            .is_err()
    );
    assert!(
        serde_json::from_value::<RememberInput>(json!({
            "operationId":ID, "kind":"fact", "title":"Title", "markdown":"Body", "tags":[],
            "scope":{"scope":"project","projectId":PROJECT_ID}
        }))
        .is_err()
    );
    assert!(serde_json::from_value::<ListTasksInput>(json!({"projectId":PROJECT_ID})).is_err());
    assert!(serde_json::from_value::<UpsertTaskInput>(json!({
        "operationId":ID, "projectId":PROJECT_ID, "title":"Task", "bodyMarkdown":"Body", "status":"open"
    })).is_err());
}

#[test]
fn mcp_scope_schemas_allow_only_global_or_active_project() {
    let search = mcp_schema("context_relay_search").unwrap().input;
    assert_eq!(
        search["properties"]["scope"]["oneOf"][1]["oneOf"][1]["properties"]["scope"]["const"],
        "active_project"
    );
    assert!(search.to_string().find("projectId").is_none());
    assert!(
        mcp_schema("context_relay_list_tasks")
            .unwrap()
            .input
            .to_string()
            .find("projectId")
            .is_none()
    );
    assert!(
        mcp_schema("context_relay_upsert_task")
            .unwrap()
            .input
            .to_string()
            .find("projectId")
            .is_none()
    );
}
