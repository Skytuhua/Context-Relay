use context_relay_local_ipc::role_allows;
use context_relay_protocol::{ClientRole, LocalRequest};
use serde_json::json;

#[test]
fn hosted_auth_controls_are_desktop_only() {
    let id = "019924bb-5300-7000-8000-000000000001";
    for (method, params) in [
        ("hosted_auth_status", json!({})),
        (
            "hosted_auth_start",
            json!({"operationId":id,"expectedGeneration":id}),
        ),
        ("hosted_auth_cancel", json!({"generation":id})),
        ("hosted_auth_logout", json!({"generation":id})),
    ] {
        let request: LocalRequest =
            serde_json::from_value(json!({"method":method,"params":params})).unwrap();
        assert!(role_allows(ClientRole::Desktop, &request));
        for role in [
            ClientRole::McpBridge,
            ClientRole::Installer,
            ClientRole::DesktopRecoveryHost,
        ] {
            assert!(!role_allows(role, &request), "{role:?} may invoke {method}");
        }
    }
}
