use context_relay_local_ipc::role_allows;
use context_relay_protocol::{ClientRole, LocalRequest, ProjectParams};

#[test]
fn project_configuration_export_is_desktop_only() {
    let request = LocalRequest::OpenCodeMcpExport(ProjectParams {
        project_id: "018f22e2-79b0-7cc8-98c4-dc0c0c073987".parse().unwrap(),
    });
    assert!(role_allows(ClientRole::Desktop, &request));
    for role in [
        ClientRole::McpBridge,
        ClientRole::Installer,
        ClientRole::DesktopRecoveryHost,
    ] {
        assert!(!role_allows(role, &request));
    }
}
