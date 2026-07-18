use context_relay_protocol::CompleteTaskOutput;

#[test]
fn completed_task_output_fixture_round_trips() {
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/mcp-output-valid.json")).unwrap();
    let output: CompleteTaskOutput =
        serde_json::from_value(fixtures["context_relay_complete_task"].clone()).unwrap();
    output.task.validate().unwrap();
}
