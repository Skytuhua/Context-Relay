mod support;

use context_relay_protocol::{
    JsonRpcRequestV1, MemoryRecord, ProjectIdentity, SetupPlan, SyncOperationV1, TaskRecord,
    mcp_schema,
};

#[test]
fn utf8_text_limits_and_relay_only_projects_match_the_schema() {
    let mut memory = support::memory_record();
    memory.title = "\u{00e9}".repeat(300);
    assert!(memory.validate().is_err());

    let title = &mcp_schema("context_relay_search").unwrap().output["properties"]["memories"]["items"]
        ["properties"]["title"];
    assert_eq!(title["x-utf8-maxBytes"], 512);

    let mut project = ProjectIdentity {
        project_id: support::ID.parse().unwrap(),
        github_repository_id: None,
        git_remote_fingerprint: None,
        monorepo_subdirectory: None,
        name: "Relay project".into(),
    };
    project.validate().unwrap();
    project.github_repository_id = Some(0);
    assert!(project.validate().is_err());
    project.github_repository_id = None;
    project.monorepo_subdirectory = Some("../invalid".into());
    assert!(project.validate().is_err());
    project.monorepo_subdirectory = Some("\u{00e9}".repeat(300));
    assert!(project.validate().is_err());

    let project_schema = &mcp_schema("context_relay_create_handoff").unwrap().output["properties"]
        ["payload"]["properties"]["project"]["oneOf"][1];
    assert!(project_schema.get("anyOf").is_none());
    let subdirectory = &project_schema["properties"]["monorepoSubdirectory"]["oneOf"][1];
    assert_eq!(subdirectory["x-utf8-maxBytes"], 512);
}

#[test]
fn shared_json_fixture_round_trips_through_rust() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/runtime-contracts-v1.json");
    let fixture: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(path).expect("runtime contract fixture must exist"),
    )
    .unwrap();

    for key in [
        "memory",
        "task",
        "setupPlan",
        "syncOperation",
        "memoryCreateRequest",
    ] {
        assert!(fixture.get(key).is_some(), "missing {key}");
    }

    let request: JsonRpcRequestV1 =
        serde_json::from_value(fixture["memoryCreateRequest"].clone()).unwrap();
    assert_eq!(
        serde_json::to_value(request).unwrap(),
        fixture["memoryCreateRequest"]
    );

    let memory: MemoryRecord = serde_json::from_value(fixture["memory"].clone()).unwrap();
    memory.validate().unwrap();
    assert_eq!(serde_json::to_value(memory).unwrap(), fixture["memory"]);

    let task: TaskRecord = serde_json::from_value(fixture["task"].clone()).unwrap();
    task.validate().unwrap();
    assert_eq!(serde_json::to_value(task).unwrap(), fixture["task"]);

    let plan: SetupPlan = serde_json::from_value(fixture["setupPlan"].clone()).unwrap();
    assert_eq!(serde_json::to_value(plan).unwrap(), fixture["setupPlan"]);

    let operation: SyncOperationV1 =
        serde_json::from_value(fixture["syncOperation"].clone()).unwrap();
    operation.validate().unwrap();
    assert_eq!(
        serde_json::to_value(operation).unwrap(),
        fixture["syncOperation"]
    );

    let mut malformed = fixture["syncOperation"].clone();
    malformed["previousDeviceHash"] = "00".into();
    assert!(serde_json::from_value::<SyncOperationV1>(malformed).is_err());
}
