use context_relay_protocol::{MCP_TOOL_NAMES, mcp_schema, validate_mcp_fixture};

#[test]
fn all_eleven_mcp_tools_have_strict_draft_2020_12_schemas_and_fixtures() {
    assert_eq!(MCP_TOOL_NAMES.len(), 11);
    let valid_input: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/mcp-valid.json")).unwrap();
    let invalid_input: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/mcp-invalid.json")).unwrap();
    let valid_output: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/mcp-output-valid.json")).unwrap();
    let invalid_output: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/mcp-output-invalid.json")).unwrap();
    for name in MCP_TOOL_NAMES {
        let schemas = mcp_schema(name).expect("accepted tool");
        for schema in [&schemas.input, &schemas.output] {
            assert_eq!(
                schema["$schema"],
                "https://json-schema.org/draft/2020-12/schema"
            );
            assert_eq!(schema["type"], "object");
            assert_eq!(schema["additionalProperties"], false);
        }
        assert!(
            validate_mcp_fixture(name, true, &valid_input[name]).is_ok(),
            "valid input: {name}"
        );
        assert!(
            validate_mcp_fixture(name, true, &invalid_input[name]).is_err(),
            "invalid input: {name}"
        );
        assert!(
            validate_mcp_fixture(name, false, &valid_output[name]).is_ok(),
            "valid output: {name}"
        );
        assert!(
            validate_mcp_fixture(name, false, &invalid_output[name]).is_err(),
            "invalid output: {name}"
        );
    }
}
