use context_relay_context_mcp::{Invocation, parse_harness, parse_invocation};
use context_relay_protocol::HarnessId;

#[test]
fn opencode_uses_stdio_mcp_without_enabling_lifecycle_hook_invocations() {
    let arguments = ["context-relay-context-mcp", "--harness", "opencode"];
    assert_eq!(
        parse_harness(arguments.map(Into::into)),
        Some(HarnessId::OpenCode)
    );
    assert_eq!(
        parse_invocation(arguments.map(Into::into)),
        Some(Invocation::Mcp {
            harness: HarnessId::OpenCode
        })
    );
    for event in ["session-start", "session-stop", "task-evidence"] {
        assert!(
            parse_invocation(
                ["bridge", "--hook-event", event, "--harness", "opencode"].map(Into::into)
            )
            .is_none()
        );
    }
    assert!(
        parse_invocation(["bridge", "--harness", "opencode", "--extra"].map(Into::into)).is_none()
    );
}
