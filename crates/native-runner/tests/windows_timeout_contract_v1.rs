use context_relay_native_runner::{RunLimits, SidecarCommand};

const WINDOWS_NATIVE_SOURCE: &str = include_str!("../src/launcher/windows/native.rs");

#[test]
fn windows_outer_deadline_is_bound_to_the_sealed_command_envelope() {
    let semgrep_runtime_ms =
        RunLimits::for_command(&SidecarCommand::OsemgrepScanPackage).timeout_ms();

    assert!(
        !WINDOWS_NATIVE_SOURCE.contains("const PROCESS_TIMEOUT_MS: u32 = 30_000;"),
        "Windows fixes the outer helper deadline at 30,000 ms even though the sealed Osemgrep request permits {semgrep_runtime_ms} ms before shutdown"
    );
    assert!(
        !WINDOWS_NATIVE_SOURCE.contains("for_default_sidecar"),
        "Windows must not expose a default-deadline path that bypasses the sealed request command"
    );
    assert!(
        !WINDOWS_NATIVE_SOURCE.contains("pub fn exchange(&mut self, input: &[u8])"),
        "the public running-launcher API must not accept raw bytes with an independent deadline"
    );
    assert!(
        WINDOWS_NATIVE_SOURCE
            .contains("pub fn exchange(\n        &mut self,\n        request: &HelperRunRequest,"),
        "every public running-launcher exchange must require a sealed HelperRunRequest"
    );
    assert!(
        WINDOWS_NATIVE_SOURCE.contains("WindowsProcessDeadline::for_request(request.request())"),
        "Windows must derive the outer helper deadline from the exact request it serializes"
    );
}
