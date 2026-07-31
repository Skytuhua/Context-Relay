#![cfg(all(feature = "test-support", any(windows, target_os = "macos")))]

use std::sync::Arc;

use context_relay_context_mcp::{
    BridgeError, Daemon as _, LocalDaemon, MAX_IN_FLIGHT_TOOL_CALLS, MCP_REVISION, Server,
};
use context_relay_contextd::{
    DaemonHandle, DaemonState,
    test_support::{TestDaemonConfig, TestWorkerGate},
};
use context_relay_local_ipc::{
    InstallationToken, REQUEST_TIMEOUT, RuntimeConfig, SHUTDOWN_TIMEOUT,
};
use context_relay_protocol::{
    HarnessId, McpBinding, McpCallParams, NativePlatform, RecordId, WireNativeValue,
};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream},
    task::JoinHandle,
};
use uuid::Uuid;

struct Fixture {
    _root: TempDir,
    project_root: std::path::PathBuf,
    daemon: TestDaemonConfig,
}

impl Fixture {
    fn new() -> Self {
        #[cfg(target_os = "macos")]
        let root = tempfile::tempdir_in("/tmp").unwrap();
        #[cfg(not(target_os = "macos"))]
        let root = tempfile::tempdir().unwrap();
        let project_root = root.path().join("project");
        std::fs::create_dir(&project_root).unwrap();
        let unique = Uuid::now_v7().simple().to_string();
        let suffix = format!("mcp-e2e-{}", &unique[16..]);
        let runtime = RuntimeConfig::for_test(suffix, Some(root.path().join("runtime"))).unwrap();
        let daemon = TestDaemonConfig::new(
            runtime,
            root.path().join("vault.db"),
            InstallationToken::from_bytes([0x5a; 32]),
        );
        Self {
            _root: root,
            project_root,
            daemon,
        }
    }

    fn local_daemon(&self) -> LocalDaemon {
        LocalDaemon::for_test(self.daemon.runtime(), self.daemon.installation_token())
    }

    fn binding(&self) -> McpBinding {
        McpBinding {
            harness: HarnessId::Codex,
            working_directory: wire_native_path(&self.project_root),
        }
    }
}

async fn start_daemon(
    config: &TestDaemonConfig,
) -> (
    DaemonHandle,
    JoinHandle<Result<(), context_relay_contextd::DaemonError>>,
) {
    let daemon = config.start().await.unwrap();
    let handle = daemon.handle();
    let owner = tokio::spawn(daemon.run());
    (handle, owner)
}

async fn stop_daemon(
    handle: DaemonHandle,
    owner: JoinHandle<Result<(), context_relay_contextd::DaemonError>>,
) {
    assert_eq!(handle.shutdown().await, DaemonState::Stopped);
    assert_eq!(owner.await.unwrap(), Ok(()));
}

fn record_id() -> RecordId {
    RecordId::new(Uuid::now_v7()).unwrap()
}

fn call(binding: McpBinding, name: &str, arguments: Value) -> McpCallParams {
    McpCallParams {
        binding,
        name: name.into(),
        arguments,
    }
}

fn status_call(id: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"name": "context_relay_status", "arguments": {}}
    })
}

fn remember_call(id: Value, operation_id: RecordId, title: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": "context_relay_remember",
            "arguments": {
                "operationId": operation_id,
                "kind": "note",
                "title": title,
                "markdown": "This mutation is part of a real daemon test.",
                "tags": [],
                "scope": {"scope": "global"}
            }
        }
    })
}

struct StartedServer {
    input: DuplexStream,
    output: BufReader<DuplexStream>,
    task: JoinHandle<Result<(), BridgeError>>,
}

impl StartedServer {
    async fn start(daemon: LocalDaemon, binding: McpBinding) -> Self {
        let (input, input_reader) = tokio::io::duplex(256 * 1024);
        let (output_writer, output) = tokio::io::duplex(256 * 1024);
        let task = tokio::spawn(
            Server::new(daemon, binding).run(BufReader::new(input_reader), output_writer),
        );
        let mut server = Self {
            input,
            output: BufReader::new(output),
            task,
        };
        server
            .send(json!({
                "jsonrpc": "2.0",
                "id": "initialize",
                "method": "initialize",
                "params": {
                    "protocolVersion": MCP_REVISION,
                    "capabilities": {},
                    "clientInfo": {"name": "real-daemon-test", "version": "1"}
                }
            }))
            .await;
        server
            .send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await;
        assert_eq!(server.receive().await["id"], "initialize");
        server
    }

    async fn send(&mut self, value: Value) {
        let mut bytes = serde_json::to_vec(&value).unwrap();
        bytes.push(b'\n');
        self.input.write_all(&bytes).await.unwrap();
    }

    async fn receive(&mut self) -> Value {
        let mut line = String::new();
        assert_ne!(self.output.read_line(&mut line).await.unwrap(), 0);
        assert!(line.ends_with('\n'));
        assert!(!line.contains('\r'));
        serde_json::from_str(&line).unwrap()
    }

    async fn close(mut self) {
        self.input.shutdown().await.unwrap();
        assert_eq!(self.task.await.unwrap(), Ok(()));
    }
}

#[tokio::test]
async fn authenticated_status_replay_restart_and_stdout_purity_use_real_sockets() {
    let fixture = Fixture::new();
    let local = fixture.local_daemon();
    assert_eq!(
        local
            .call(
                record_id(),
                call(fixture.binding(), "context_relay_status", json!({}))
            )
            .await,
        Err(BridgeError::Unavailable)
    );

    let (handle, owner) = start_daemon(&fixture.daemon).await;
    let status = local
        .call(
            record_id(),
            call(fixture.binding(), "context_relay_status", json!({})),
        )
        .await
        .unwrap();
    assert_eq!(status["vault"], "unlocked");

    let replay_id = record_id();
    let replay_call = call(
        fixture.binding(),
        "context_relay_remember",
        json!({
            "operationId": record_id(),
            "kind": "note",
            "title": "Idempotent replay",
            "markdown": "The exact same local request is replayed.",
            "tags": [],
            "scope": {"scope": "global"}
        }),
    );
    let first = local.call(replay_id, replay_call.clone()).await.unwrap();
    let second = local.call(replay_id, replay_call).await.unwrap();
    assert_eq!(second, first);

    let mut server = StartedServer::start(local.clone(), fixture.binding()).await;
    server.send(status_call(json!("real-status"))).await;
    let response = server.receive().await;
    assert_eq!(response["id"], "real-status");
    assert_eq!(response["result"]["structuredContent"]["vault"], "unlocked");
    server.close().await;
    stop_daemon(handle, owner).await;

    let (handle, owner) = start_daemon(&fixture.daemon).await;
    let restarted = local
        .call(
            record_id(),
            call(fixture.binding(), "context_relay_status", json!({})),
        )
        .await
        .unwrap();
    assert_eq!(restarted["vault"], "unlocked");
    stop_daemon(handle, owner).await;
}

#[tokio::test]
async fn sixty_four_real_calls_and_cancellations_fit_below_the_daemon_cap() {
    let fixture = Fixture::new();
    let gate = Arc::new(TestWorkerGate::new());
    let gated = fixture.daemon.clone().with_worker_gate(gate.clone());
    let (handle, owner) = start_daemon(&gated).await;
    let local = fixture.local_daemon();
    let mut server = StartedServer::start(local.clone(), fixture.binding()).await;

    for id in 0..MAX_IN_FLIGHT_TOOL_CALLS {
        server.send(status_call(json!(id))).await;
    }
    gate.wait_until_enqueued(MAX_IN_FLIGHT_TOOL_CALLS).await;
    assert_eq!(gate.enqueued(), MAX_IN_FLIGHT_TOOL_CALLS);
    for id in 0..MAX_IN_FLIGHT_TOOL_CALLS {
        server
            .send(json!({
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {"requestId": id}
            }))
            .await;
    }
    let all_canceled = tokio::time::timeout(
        SHUTDOWN_TIMEOUT,
        local.wait_for_test_cancels(MAX_IN_FLIGHT_TOOL_CALLS),
    )
    .await;

    gate.release();
    local
        .wait_for_test_call_completions(MAX_IN_FLIGHT_TOOL_CALLS)
        .await;
    server.close().await;
    stop_daemon(handle, owner).await;
    all_canceled.expect("the daemon connection cap must admit every cancellation");
}

#[tokio::test]
async fn queued_cancel_reaches_contextd_and_prevents_the_real_mutation() {
    let fixture = Fixture::new();
    let gate = Arc::new(TestWorkerGate::new());
    let gated = fixture.daemon.clone().with_worker_gate(gate.clone());
    let (handle, owner) = start_daemon(&gated).await;
    let local = fixture.local_daemon();
    let mut server = StartedServer::start(local.clone(), fixture.binding()).await;

    server.send(status_call(json!("blocker"))).await;
    gate.wait_until_entered().await;
    server
        .send(remember_call(
            json!("cancel-me"),
            record_id(),
            "never-execute-marker",
        ))
        .await;
    gate.wait_until_enqueued(2).await;
    server
        .send(json!({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": "cancel-me"}
        }))
        .await;
    local.wait_for_test_cancels(1).await;
    gate.release();

    assert_eq!(server.receive().await["id"], "blocker");
    server
        .send(json!({
            "jsonrpc": "2.0",
            "id": "search",
            "method": "tools/call",
            "params": {
                "name": "context_relay_search",
                "arguments": {
                    "query": "never-execute-marker",
                    "scope": {"scope": "global"},
                    "limit": 10
                }
            }
        }))
        .await;
    let search = server.receive().await;
    assert_eq!(search["id"], "search");
    assert_eq!(search["result"]["structuredContent"]["memories"], json!([]));
    server.close().await;
    stop_daemon(handle, owner).await;
}

#[tokio::test]
async fn back_to_back_cancel_before_registration_prevents_the_real_mutation() {
    let fixture = Fixture::new();
    let (handle, owner) = start_daemon(&fixture.daemon).await;
    let local = fixture.local_daemon();
    local.hold_test_calls();
    let mut server = StartedServer::start(local.clone(), fixture.binding()).await;

    server
        .send(remember_call(
            json!("cancel-before-register"),
            record_id(),
            "early-cancel-marker",
        ))
        .await;
    server
        .send(json!({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": "cancel-before-register"}
        }))
        .await;
    local.wait_for_test_cancels(1).await;
    local.release_test_calls();
    local.wait_for_test_call_completions(1).await;

    server
        .send(json!({
            "jsonrpc": "2.0",
            "id": "search-after-early-cancel",
            "method": "tools/call",
            "params": {
                "name": "context_relay_search",
                "arguments": {
                    "query": "early-cancel-marker",
                    "scope": {"scope": "global"},
                    "limit": 10
                }
            }
        }))
        .await;
    let search = server.receive().await;
    assert_eq!(search["id"], "search-after-early-cancel");
    assert_eq!(search["result"]["structuredContent"]["memories"], json!([]));
    server.close().await;
    stop_daemon(handle, owner).await;
}

#[tokio::test]
async fn real_timeout_reports_unknown_outcome_without_retrying() {
    let fixture = Fixture::new();
    let gate = Arc::new(TestWorkerGate::new());
    let gated = fixture.daemon.clone().with_worker_gate(gate.clone());
    let (handle, owner) = start_daemon(&gated).await;
    let mut server = StartedServer::start(fixture.local_daemon(), fixture.binding()).await;

    server
        .send(remember_call(
            json!("timeout"),
            record_id(),
            "unknown-outcome",
        ))
        .await;
    gate.wait_until_entered().await;
    tokio::time::pause();
    tokio::time::advance(REQUEST_TIMEOUT + std::time::Duration::from_millis(1)).await;
    let response = server.receive().await;
    assert_eq!(
        response["result"]["_meta"]["contextRelay"],
        json!({"code": "timeout", "retryable": true, "fieldPath": null})
    );
    assert_eq!(
        response["result"]["content"][0]["text"],
        "The request timed out with an unknown outcome"
    );
    assert_eq!(gate.enqueued(), 1);

    tokio::time::resume();
    gate.release();
    server.close().await;
    stop_daemon(handle, owner).await;
}

fn wire_native_path(path: &std::path::Path) -> WireNativeValue {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;

        WireNativeValue {
            platform: NativePlatform::Windows,
            bytes: path
                .as_os_str()
                .encode_wide()
                .flat_map(u16::to_le_bytes)
                .collect(),
            display: None,
        }
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::ffi::OsStrExt;

        WireNativeValue {
            platform: NativePlatform::Macos,
            bytes: path.as_os_str().as_bytes().to_vec(),
            display: None,
        }
    }
}
