mod support;

use context_relay_protocol::{
    HarnessId, HarnessParams, LocalRequest, McpBinding, NativeHookEvent, NativeHookEventParams,
    NativePlatform, PROTOCOL_VERSION, ProtocolVersion, ProtocolVersionRange, SetupPlan,
    WireNativeValue, negotiate_version,
};
use serde_json::json;

#[test]
fn opencode_is_a_closed_mcp_identity_and_export_accepts_only_a_project_id() {
    assert_eq!(
        serde_json::to_value(HarnessId::OpenCode).unwrap(),
        "opencode"
    );
    assert_eq!(
        serde_json::from_value::<HarnessId>(json!("opencode")).unwrap(),
        HarnessId::OpenCode
    );
    assert!(serde_json::from_value::<HarnessId>(json!("open_code")).is_err());
    let mut value = json!({"method":"opencode_mcp_export","params":{"projectId":support::ID}});
    let request: LocalRequest = serde_json::from_value(value.clone()).unwrap();
    assert!(request.validate().is_ok());
    assert_eq!(serde_json::to_value(request).unwrap(), value);
    value["params"]["command"] = json!("caller-supplied.exe");
    assert!(serde_json::from_value::<LocalRequest>(value).is_err());
    assert!(
        serde_json::from_value::<LocalRequest>(
            json!({"method":"opencode_mcp_export","params":{"projectId":null}})
        )
        .is_err()
    );
}

#[test]
fn opencode_cannot_become_a_managed_plan_launch_or_native_hook() {
    let mut plan = support::setup_plan();
    let mut wire = serde_json::to_value(&plan).unwrap();
    wire["harness"] = json!("opencode");
    wire["harnessProfile"] = json!(null);
    plan.harness = HarnessId::OpenCode;
    plan.harness_profile = None;
    assert!(plan.validate().is_err());
    assert!(serde_json::to_value(&plan).is_err());
    assert!(serde_json::from_value::<SetupPlan>(wire).is_err());
    assert!(
        LocalRequest::HarnessLaunchInfo(HarnessParams {
            harness: HarnessId::OpenCode,
            project_id: Some(support::ID.parse().unwrap()),
            hermes_profile: None,
        })
        .validate()
        .is_err()
    );
    assert!(
        LocalRequest::NativeHookEvent(NativeHookEventParams {
            binding: McpBinding {
                harness: HarnessId::OpenCode,
                working_directory: WireNativeValue {
                    platform: NativePlatform::Macos,
                    bytes: b"/project".to_vec(),
                    display: None
                },
            },
            event: NativeHookEvent::SessionStart {
                session_id: "session".to_owned()
            },
            occurred_at_ms: 1,
        })
        .validate()
        .is_err()
    );
}

#[test]
fn opencode_requires_the_coordinated_protocol_upgrade() {
    assert_eq!(
        PROTOCOL_VERSION,
        ProtocolVersion {
            major: 1,
            minor: 18
        }
    );
    let previous = ProtocolVersion {
        major: 1,
        minor: 17,
    };
    assert!(
        negotiate_version(
            ProtocolVersionRange {
                min: previous,
                max: previous
            },
            ProtocolVersionRange {
                min: PROTOCOL_VERSION,
                max: PROTOCOL_VERSION
            },
        )
        .is_err()
    );
}
