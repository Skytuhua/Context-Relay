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
        WINDOWS_NATIVE_SOURCE.contains("WindowsProcessDeadline::for_request(request)"),
        "Windows must derive the outer helper deadline from the sealed RunRequest command"
    );
}
