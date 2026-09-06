use context_relay_protocol::{
    HarnessId, LocalRequest, LocalResult, McpBinding, McpCallParams, NativePlatform,
    WireNativeValue,
};
use serde_json::json;

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

fn status_output() -> serde_json::Value {
    json!({
        "protocol": {
            "min": {"major": 1, "minor": 6},
            "max": {"major": 1, "minor": 6}
        },
        "vault": "unlocked",
        "resolvedProject": null,
        "sync": "offline",
        "access": {"mode": "default"}
    })
}

#[test]
fn mcp_call_validates_the_frozen_tool_input_and_output() {
    let request = LocalRequest::McpCall(McpCallParams {
        binding: binding(),
        name: "context_relay_status".into(),
        arguments: json!({}),
    });
    assert!(request.validate().is_ok());

    let result = LocalResult::McpOutput {
        name: "context_relay_status".into(),
        output: status_output(),
    };
    assert!(result.validate().is_ok());
}

#[test]
fn mcp_call_rejects_unknown_tools_native_paths_and_invalid_arguments() {
    let mut request = McpCallParams {
        binding: binding(),
        name: "not_a_context_relay_tool".into(),
        arguments: json!({}),
    };
    assert!(LocalRequest::McpCall(request.clone()).validate().is_err());

    request.name = "context_relay_status".into();
    request.binding.working_directory = WireNativeValue {
        platform: NativePlatform::Windows,
        bytes: vec![0],
        display: None,
    };
    assert!(LocalRequest::McpCall(request.clone()).validate().is_err());

    request.binding = binding();
    request.arguments = json!({"unexpected": true});
    assert!(LocalRequest::McpCall(request).validate().is_err());
}

#[test]
fn mcp_output_rejects_unknown_and_mismatched_output_names() {
    assert!(
        LocalResult::McpOutput {
            name: "not_a_context_relay_tool".into(),
            output: status_output(),
        }
        .validate()
        .is_err()
    );
    assert!(
        LocalResult::McpOutput {
            name: "context_relay_search".into(),
            output: status_output(),
        }
        .validate()
        .is_err()
    );
}

#[test]
fn mcp_envelope_uses_the_frozen_wire_tags() {
    let request = LocalRequest::McpCall(McpCallParams {
        binding: binding(),
        name: "context_relay_status".into(),
        arguments: json!({}),
    });
    let request_json = serde_json::to_value(&request).unwrap();
    assert_eq!(request_json["method"], "mcp_call");
    assert_eq!(request_json["params"]["binding"]["harness"], "codex");
    assert_eq!(
        serde_json::from_value::<LocalRequest>(request_json).unwrap(),
        request
    );

    let result = LocalResult::McpOutput {
        name: "context_relay_status".into(),
        output: status_output(),
    };
    let result_json = serde_json::to_value(&result).unwrap();
    assert_eq!(result_json["kind"], "mcp_output");
    assert_eq!(result_json["data"]["name"], "context_relay_status");
    assert_eq!(
        serde_json::from_value::<LocalResult>(result_json).unwrap(),
        result
    );
}
