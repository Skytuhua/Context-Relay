use std::{
    ffi::OsString,
    future::{Future, ready},
    path::Path,
    str::FromStr as _,
    sync::{Arc, Mutex},
};

use context_relay_context_mcp::{
    BridgeError, HookInvocationKind, Invocation, MAX_HOOK_INPUT_BYTES, NativeHookDaemon,
    SESSION_START_REMINDER, execute_hook, parse_harness, parse_invocation, project_hook_input,
    read_hook_input,
};
use context_relay_protocol::{
    CompletionEvidenceInput, HarnessId, LocalRequest, LocalResult, McpBinding, NativeHookEvent,
    NativeHookEventParams, NativePlatform, PROTOCOL_VERSION, ProtocolVersion, TaskId,
    WireNativeValue,
};
use serde_json::json;

fn args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

#[test]
fn exact_mcp_invocations_remain_compatible() {
    for (name, harness) in [
        ("claude-code", HarnessId::ClaudeCode),
        ("codex", HarnessId::Codex),
        ("hermes", HarnessId::Hermes),
    ] {
        let arguments = args(&["context-relay-mcp", "--harness", name]);
        assert_eq!(
            parse_invocation(arguments.clone()),
            Some(Invocation::Mcp { harness })
        );
        assert_eq!(parse_harness(arguments), Some(harness));
    }
}

#[test]
fn every_supported_hook_has_one_exact_invocation() {
    for (harness_name, harness, event_name, event) in [
        (
            "claude-code",
            HarnessId::ClaudeCode,
            "session-start",
            HookInvocationKind::SessionStart,
        ),
        (
            "claude-code",
            HarnessId::ClaudeCode,
            "session-stop",
            HookInvocationKind::SessionStop,
        ),
        (
            "claude-code",
            HarnessId::ClaudeCode,
            "task-evidence",
            HookInvocationKind::TaskEvidence,
        ),
        (
            "codex",
            HarnessId::Codex,
            "session-start",
            HookInvocationKind::SessionStart,
        ),
        (
            "codex",
            HarnessId::Codex,
            "session-stop",
            HookInvocationKind::SessionStop,
        ),
        (
            "codex",
            HarnessId::Codex,
            "task-evidence",
            HookInvocationKind::TaskEvidence,
        ),
    ] {
        let arguments = args(&[
            "context-relay-mcp",
            "--hook-event",
            event_name,
            "--harness",
            harness_name,
        ]);
        assert_eq!(
            parse_invocation(arguments.clone()),
            Some(Invocation::Hook { harness, event })
        );
        assert_eq!(parse_harness(arguments), None);
    }
}

#[test]
fn unsupported_frozen_hook_combinations_are_rejected() {
    for (harness, event) in [
        ("hermes", "session-start"),
        ("hermes", "session-stop"),
        ("hermes", "task-evidence"),
    ] {
        let arguments = args(&[
            "context-relay-mcp",
            "--hook-event",
            event,
            "--harness",
            harness,
        ]);
        assert_eq!(parse_invocation(arguments.clone()), None);
        assert_eq!(parse_harness(arguments), None);
    }
}

#[test]
fn malformed_duplicate_unknown_and_trailing_arguments_are_rejected() {
    for arguments in [
        args(&[]),
        args(&["context-relay-mcp"]),
        args(&["context-relay-mcp", "--harness"]),
        args(&["context-relay-mcp", "--harness", "codex", "trailing"]),
        args(&[
            "context-relay-mcp",
            "--harness",
            "codex",
            "--harness",
            "hermes",
        ]),
        args(&["context-relay-mcp", "--unknown", "codex"]),
        args(&["context-relay-mcp", "--harness", "unknown"]),
        args(&["context-relay-mcp", "--hook-event"]),
        args(&["context-relay-mcp", "--hook-event", "session-start"]),
        args(&[
            "context-relay-mcp",
            "--hook-event",
            "unknown",
            "--harness",
            "codex",
        ]),
        args(&[
            "context-relay-mcp",
            "--hook-event",
            "session-start",
            "--harness",
            "unknown",
        ]),
        args(&[
            "context-relay-mcp",
            "--hook-event",
            "session-start",
            "--hook-event",
            "session-stop",
        ]),
        args(&[
            "context-relay-mcp",
            "--hook-event",
            "session-start",
            "--harness",
            "codex",
            "trailing",
        ]),
        args(&[
            "context-relay-mcp",
            "--harness",
            "codex",
            "--hook-event",
            "session-start",
        ]),
    ] {
        assert_eq!(parse_invocation(arguments.clone()), None);
        assert_eq!(parse_harness(arguments), None);
    }
}

#[cfg(unix)]
#[test]
fn non_utf8_arguments_are_rejected_without_lossy_parsing() {
    use std::os::unix::ffi::OsStringExt;

    for arguments in [
        vec![
            OsString::from("context-relay-mcp"),
            OsString::from_vec(vec![0xff]),
            OsString::from("codex"),
        ],
        vec![
            OsString::from("context-relay-mcp"),
            OsString::from("--hook-event"),
            OsString::from_vec(vec![0xff]),
            OsString::from("--harness"),
            OsString::from("codex"),
        ],
        vec![
            OsString::from("context-relay-mcp"),
            OsString::from("--hook-event"),
            OsString::from("session-start"),
            OsString::from("--harness"),
            OsString::from_vec(vec![0xff]),
        ],
    ] {
        assert_eq!(parse_invocation(arguments.clone()), None);
        assert_eq!(parse_harness(arguments), None);
    }
}

const PROMPT_SENTINEL: &str = "PROMPT_SENTINEL_431d5e";
const RESPONSE_SENTINEL: &str = "RESPONSE_SENTINEL_d27ac8";
const ASSISTANT_SENTINEL: &str = "ASSISTANT_SENTINEL_81b2ff";
const TRANSCRIPT_SENTINEL: &str = "TRANSCRIPT_SENTINEL_5380af";
const TOOL_INPUT_SENTINEL: &str = "TOOL_INPUT_SENTINEL_7302c1";
const TOOL_OUTPUT_SENTINEL: &str = "TOOL_OUTPUT_SENTINEL_1f7ed0";
const UNKNOWN_SENTINEL: &str = "UNKNOWN_SENTINEL_999c20";

fn private_vendor_payload(extra: serde_json::Value) -> Vec<u8> {
    let mut payload = json!({
        "session_id": "session-allowed-17",
        "prompt": PROMPT_SENTINEL,
        "response": RESPONSE_SENTINEL,
        "last_assistant_message": ASSISTANT_SENTINEL,
        "transcript_path": format!("/must/not/be/opened/{TRANSCRIPT_SENTINEL}"),
        "tool_input": {"command": TOOL_INPUT_SENTINEL},
        "tool_output": [TOOL_OUTPUT_SENTINEL],
        "unknown_nested": {"deep": [{"value": UNKNOWN_SENTINEL}]}
    });
    payload.as_object_mut().unwrap().extend(
        extra
            .as_object()
            .expect("test extension is an object")
            .clone(),
    );
    serde_json::to_vec(&payload).unwrap()
}

fn expected_binding(harness: HarnessId, cwd: &Path) -> McpBinding {
    McpBinding {
        harness,
        working_directory: WireNativeValue {
            platform: if cfg!(windows) {
                NativePlatform::Windows
            } else {
                NativePlatform::Macos
            },
            bytes: native_path_bytes(cwd),
            display: None,
        },
    }
}

#[cfg(not(windows))]
fn native_path_bytes(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt as _;

    path.as_os_str().as_bytes().to_vec()
}

#[cfg(windows)]
fn native_path_bytes(path: &Path) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt as _;

    path.as_os_str()
        .encode_wide()
        .flat_map(u16::to_le_bytes)
        .collect()
}

fn assert_private_sentinels_absent(value: &str) {
    for sentinel in [
        PROMPT_SENTINEL,
        RESPONSE_SENTINEL,
        ASSISTANT_SENTINEL,
        TRANSCRIPT_SENTINEL,
        TOOL_INPUT_SENTINEL,
        TOOL_OUTPUT_SENTINEL,
        UNKNOWN_SENTINEL,
    ] {
        assert!(!value.contains(sentinel), "leaked {sentinel}: {value}");
    }
}

#[test]
fn lifecycle_projection_keeps_only_local_binding_session_kind_and_timestamp() {
    let cwd = Path::new("/projects/relay-allowlisted");
    let input = private_vendor_payload(json!({}));

    for (harness, event, expected_event) in [
        (
            HarnessId::ClaudeCode,
            HookInvocationKind::SessionStart,
            NativeHookEvent::SessionStart {
                session_id: "session-allowed-17".to_owned(),
            },
        ),
        (
            HarnessId::ClaudeCode,
            HookInvocationKind::SessionStop,
            NativeHookEvent::SessionStop {
                session_id: "session-allowed-17".to_owned(),
            },
        ),
        (
            HarnessId::Codex,
            HookInvocationKind::SessionStart,
            NativeHookEvent::SessionStart {
                session_id: "session-allowed-17".to_owned(),
            },
        ),
        (
            HarnessId::Codex,
            HookInvocationKind::SessionStop,
            NativeHookEvent::SessionStop {
                session_id: "session-allowed-17".to_owned(),
            },
        ),
    ] {
        let params = project_hook_input(harness, event, &input, cwd, 1_728_444_000_123).unwrap();
        assert_eq!(
            params,
            NativeHookEventParams {
                binding: expected_binding(harness, cwd),
                event: expected_event,
                occurred_at_ms: 1_728_444_000_123,
            }
        );
        let request =
            serde_json::to_string(&LocalRequest::NativeHookEvent(params.clone())).unwrap();
        assert_private_sentinels_absent(&request);
        assert_private_sentinels_absent(&format!("{params:?}"));
    }
}

#[test]
fn task_evidence_projection_keeps_only_explicit_bounded_evidence() {
    let cwd = Path::new("/projects/task-ledger");
    let task_id = TaskId::from_str("019fa3e0-1fa7-7662-b67d-f4c3d60b31c1").unwrap();
    let input = private_vendor_payload(json!({
        "task_id": task_id.to_string(),
        "task_status": "done",
        "evidence": [{
            "summary": "Focused hook tests passed",
            "kind": "test",
            "reference": "test://context-mcp/hook-v1",
            "unknown_nested": {"private": UNKNOWN_SENTINEL}
        }]
    }));

    for harness in [HarnessId::ClaudeCode, HarnessId::Codex] {
        let params = project_hook_input(
            harness,
            HookInvocationKind::TaskEvidence,
            &input,
            cwd,
            1_728_444_000_456,
        )
        .unwrap();
        assert_eq!(
            params,
            NativeHookEventParams {
                binding: expected_binding(harness, cwd),
                event: NativeHookEvent::TaskEvidence {
                    session_id: "session-allowed-17".to_owned(),
                    task_id,
                    evidence: vec![CompletionEvidenceInput {
                        summary: "Focused hook tests passed".to_owned(),
                        kind: "test".to_owned(),
                        reference: Some("test://context-mcp/hook-v1".to_owned()),
                    }],
                },
                occurred_at_ms: 1_728_444_000_456,
            }
        );
        let request =
            serde_json::to_string(&LocalRequest::NativeHookEvent(params.clone())).unwrap();
        assert_private_sentinels_absent(&request);
        assert_private_sentinels_absent(&format!("{params:?}"));
    }
}

#[test]
fn hook_input_is_size_bounded_before_json_parsing() {
    let oversized_invalid_json = vec![b'X'; MAX_HOOK_INPUT_BYTES + 1];
    let error = project_hook_input(
        HarnessId::Codex,
        HookInvocationKind::SessionStart,
        &oversized_invalid_json,
        Path::new("/projects/relay"),
        1,
    )
    .unwrap_err();

    assert_eq!(error, BridgeError::HookInputTooLarge);
    assert_private_sentinels_absent(&format!("{error:?}"));
    assert_private_sentinels_absent(error.redacted_message());
}

#[test]
fn malformed_or_incomplete_allowlisted_fields_fail_without_input_echo() {
    let task_id = "019fa3e0-1fa7-7662-b67d-f4c3d60b31c1";
    for (event, input) in [
        (HookInvocationKind::SessionStart, b"not-json".to_vec()),
        (HookInvocationKind::SessionStop, b"[]".to_vec()),
        (
            HookInvocationKind::SessionStart,
            serde_json::to_vec(&json!({"prompt": PROMPT_SENTINEL})).unwrap(),
        ),
        (
            HookInvocationKind::SessionStop,
            serde_json::to_vec(&json!({"session_id": 12, "response": RESPONSE_SENTINEL})).unwrap(),
        ),
        (
            HookInvocationKind::TaskEvidence,
            serde_json::to_vec(&json!({
                "session_id": "session",
                "task_id": "not-a-task-id",
                "evidence": [{"summary": PROMPT_SENTINEL, "kind": "test"}]
            }))
            .unwrap(),
        ),
        (
            HookInvocationKind::TaskEvidence,
            serde_json::to_vec(&json!({
                "session_id": "session",
                "task_id": task_id,
                "evidence": []
            }))
            .unwrap(),
        ),
        (
            HookInvocationKind::TaskEvidence,
            serde_json::to_vec(&json!({
                "session_id": "session",
                "task_id": task_id,
                "evidence": [{"summary": "ok", "kind": 4, "reference": null}]
            }))
            .unwrap(),
        ),
    ] {
        let error = project_hook_input(
            HarnessId::ClaudeCode,
            event,
            &input,
            Path::new("/projects/relay"),
            1,
        )
        .unwrap_err();
        assert_eq!(error, BridgeError::InvalidHookInput);
        assert_private_sentinels_absent(&format!("{error:?}"));
        assert_private_sentinels_absent(error.redacted_message());
    }
}

#[test]
fn unsupported_harness_is_rejected_by_projection_even_without_the_cli_parser() {
    let error = project_hook_input(
        HarnessId::Hermes,
        HookInvocationKind::SessionStart,
        &private_vendor_payload(json!({})),
        Path::new("/projects/relay"),
        1,
    )
    .unwrap_err();
    assert_eq!(error, BridgeError::InvalidHookInput);
}

#[derive(Clone)]
struct RecordingHookDaemon {
    calls: Arc<Mutex<Vec<NativeHookEventParams>>>,
    result: Result<LocalResult, BridgeError>,
}

impl RecordingHookDaemon {
    fn acknowledging() -> Self {
        Self {
            calls: Arc::default(),
            result: Ok(LocalResult::Empty),
        }
    }

    fn returning(result: Result<LocalResult, BridgeError>) -> Self {
        Self {
            calls: Arc::default(),
            result,
        }
    }

    fn calls(&self) -> Vec<NativeHookEventParams> {
        self.calls.lock().unwrap().clone()
    }
}

impl NativeHookDaemon for RecordingHookDaemon {
    fn native_hook(
        &self,
        params: NativeHookEventParams,
    ) -> impl Future<Output = Result<LocalResult, BridgeError>> + Send {
        self.calls.lock().unwrap().push(params);
        ready(self.result.clone())
    }
}

#[tokio::test]
async fn hook_delivery_sends_exactly_one_request_and_emits_only_the_start_reminder_after_ack() {
    let daemon = RecordingHookDaemon::acknowledging();
    let input = private_vendor_payload(json!({}));
    let output = execute_hook(
        daemon.clone(),
        HarnessId::Codex,
        HookInvocationKind::SessionStart,
        &input,
        Path::new("/projects/relay"),
        2_000,
    )
    .await
    .unwrap();

    assert_eq!(output, SESSION_START_REMINDER);
    assert!(output.len() <= 256);
    assert_eq!(daemon.calls().len(), 1);
    assert_eq!(
        daemon.calls()[0].event,
        NativeHookEvent::SessionStart {
            session_id: "session-allowed-17".to_owned()
        }
    );
    assert_private_sentinels_absent(output);
}

#[tokio::test]
async fn stop_and_task_evidence_acknowledgements_emit_no_stdout_content() {
    let task_id = TaskId::from_str("019fa3e0-1fa7-7662-b67d-f4c3d60b31c1").unwrap();
    for (event, input) in [
        (
            HookInvocationKind::SessionStop,
            private_vendor_payload(json!({})),
        ),
        (
            HookInvocationKind::TaskEvidence,
            private_vendor_payload(json!({
                "task_id": task_id.to_string(),
                "evidence": [{"summary": "Tests passed", "kind": "test"}]
            })),
        ),
    ] {
        let daemon = RecordingHookDaemon::acknowledging();
        let output = execute_hook(
            daemon.clone(),
            HarnessId::ClaudeCode,
            event,
            &input,
            Path::new("/projects/relay"),
            2_001,
        )
        .await
        .unwrap();

        assert_eq!(output, "");
        assert_eq!(daemon.calls().len(), 1);
    }
}

#[tokio::test]
async fn daemon_and_protocol_failures_are_redacted_and_never_return_a_reminder() {
    let input = private_vendor_payload(json!({}));
    let cases = [
        (
            RecordingHookDaemon::returning(Err(BridgeError::Unavailable)),
            BridgeError::Unavailable,
        ),
        (
            RecordingHookDaemon::returning(Ok(LocalResult::Health {
                protocol: ProtocolVersion {
                    major: PROTOCOL_VERSION.major,
                    minor: PROTOCOL_VERSION.minor,
                },
                vault_locked: false,
            })),
            BridgeError::Client(context_relay_protocol::ClientError {
                code: context_relay_protocol::ErrorCode::Internal,
                message: "The local service returned an invalid response".to_owned(),
                field_path: None,
                retryable: false,
            }),
        ),
    ];

    for (daemon, expected) in cases {
        let error = execute_hook(
            daemon.clone(),
            HarnessId::ClaudeCode,
            HookInvocationKind::SessionStart,
            &input,
            Path::new("/projects/relay"),
            2_002,
        )
        .await
        .unwrap_err();
        assert_eq!(error, expected);
        assert_eq!(daemon.calls().len(), 1);
        assert_private_sentinels_absent(&format!("{error:?}"));
        assert_private_sentinels_absent(error.redacted_message());
    }
}

#[tokio::test]
async fn stdin_reader_stops_at_one_byte_past_the_limit() {
    let input = vec![b'X'; MAX_HOOK_INPUT_BYTES + 512];
    let error = read_hook_input(&input[..]).await.unwrap_err();
    assert_eq!(error, BridgeError::HookInputTooLarge);
}
