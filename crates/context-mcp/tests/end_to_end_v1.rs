#![cfg(all(feature = "test-support", any(windows, target_os = "macos")))]

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use context_relay_context_mcp::{
    BridgeError, Daemon as _, HookInvocationKind, LocalDaemon, MAX_IN_FLIGHT_TOOL_CALLS,
    MCP_REVISION, SESSION_START_REMINDER, Server, execute_hook, project_hook_input,
};
use context_relay_contextd::{
    DaemonHandle, DaemonState,
    test_support::{
        TestCodexBridgeInstallEngine, TestCodexBridgeInstallRequest, TestDaemonConfig,
        TestRecordingBridgeInstallEngine, TestWorkerGate,
        test_primary_memory_instruction_component,
    },
};
use context_relay_local_ipc::{
    AuthAcceptedV1, AuthTranscriptV1, ConnectedStream, InstallationToken, REQUEST_TIMEOUT,
    RuntimeConfig, SHUTDOWN_TIMEOUT, ServerHelloV1, connect, create_proof, read_json, write_json,
};
use context_relay_protocol::{
    CandidateListParams, CandidateReviewParams, ClientError, ClientRole, DaemonInstanceNonce,
    DeviceId, ErrorCode, HarnessAccessPolicy, HarnessId, HarnessParams, HelloParams,
    HybridLogicalClock, InstallationMethod, JsonRpcErrorV1, JsonRpcRequestV1, JsonRpcSuccessV1,
    JsonRpcVersion, ListTasksOutput, LocalRequest, LocalResult, McpBinding, McpCallParams,
    MemoryCandidate, NativePlatform, OperationId, PlanParams, ProjectId, ProjectIdentity, RecordId,
    SearchOutput, Sha256Digest, TaskStatus, UpsertTaskOutput, WireNativeValue,
};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream},
    task::JoinHandle,
};
use uuid::Uuid;

struct Fixture {
    _root: TempDir,
    project_root: std::path::PathBuf,
    second_project_root: std::path::PathBuf,
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
        let second_project_root = root.path().join("second-project");
        std::fs::create_dir(&second_project_root).unwrap();
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
            second_project_root,
            daemon,
        }
    }

    fn local_daemon(&self) -> LocalDaemon {
        LocalDaemon::for_test(self.daemon.runtime(), self.daemon.installation_token())
    }

    fn binding(&self) -> McpBinding {
        self.binding_for(HarnessId::Codex, &self.project_root)
    }

    fn binding_for(&self, harness: HarnessId, root: &Path) -> McpBinding {
        McpBinding {
            harness,
            working_directory: wire_native_path(root),
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

async fn wait_for_native_candidates(config: &TestDaemonConfig, count: usize) {
    for _ in 0..120 {
        if config.native_memory_candidates().unwrap().len() == count {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("native memory candidate count did not reach {count}")
}

async fn wait_for_native_previews(config: &TestDaemonConfig, sources: &[Sha256Digest]) {
    for _ in 0..120 {
        if sources
            .iter()
            .all(|source| config.native_memory_preview_complete(*source).unwrap())
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("native memory previews did not complete")
}

fn record_id() -> RecordId {
    RecordId::new(Uuid::now_v7()).unwrap()
}

fn operation_id() -> OperationId {
    OperationId::new(Uuid::now_v7()).unwrap()
}

fn project_identity(name: &str) -> ProjectIdentity {
    ProjectIdentity {
        project_id: Uuid::now_v7().to_string().parse().unwrap(),
        github_repository_id: None,
        git_remote_fingerprint: None,
        monorepo_subdirectory: None,
        name: name.into(),
    }
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

// A failed assertion must not leave the blocking vault worker held while the
// Tokio test runtime waits for it during teardown.
struct ReleaseWorkerOnDrop(Arc<TestWorkerGate>);

impl Drop for ReleaseWorkerOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
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
        let read = tokio::time::timeout(REQUEST_TIMEOUT, self.output.read_line(&mut line))
            .await
            .expect("the MCP server must return a response before the test deadline")
            .unwrap();
        assert_ne!(read, 0);
        assert!(line.ends_with('\n'));
        assert!(!line.contains('\r'));
        serde_json::from_str(&line).unwrap()
    }

    async fn close(mut self) {
        self.input.shutdown().await.unwrap();
        assert_eq!(self.task.await.unwrap(), Ok(()));
    }
}

struct DesktopIpcClient {
    stream: ConnectedStream,
    protocol: context_relay_protocol::ProtocolVersion,
    daemon_instance_nonce: DaemonInstanceNonce,
}

impl DesktopIpcClient {
    async fn connect(config: &TestDaemonConfig) -> Self {
        let mut stream = connect(&config.runtime()).await.unwrap();
        let hello: ServerHelloV1 = read_json(&mut stream).await.unwrap();
        let client_nonce = DaemonInstanceNonce::new([0x35; 32]);
        let transcript = AuthTranscriptV1 {
            role: ClientRole::Desktop,
            client_nonce,
            server_hello: hello,
        };
        write_json(
            &mut stream,
            &JsonRpcRequestV1 {
                jsonrpc: JsonRpcVersion::V2,
                id: record_id(),
                protocol: hello.protocol,
                daemon_instance_nonce: hello.daemon_instance_nonce,
                request: LocalRequest::Hello(HelloParams {
                    client_role: ClientRole::Desktop,
                    client_nonce,
                    session_proof: create_proof(&config.installation_token(), &transcript),
                }),
            },
        )
        .await
        .unwrap();
        let _: AuthAcceptedV1 = read_json(&mut stream).await.unwrap();
        Self {
            stream,
            protocol: hello.protocol,
            daemon_instance_nonce: hello.daemon_instance_nonce,
        }
    }

    async fn call(&mut self, request: LocalRequest) -> Result<LocalResult, ClientError> {
        write_json(
            &mut self.stream,
            &JsonRpcRequestV1 {
                jsonrpc: JsonRpcVersion::V2,
                id: record_id(),
                protocol: self.protocol,
                daemon_instance_nonce: self.daemon_instance_nonce,
                request,
            },
        )
        .await
        .unwrap();
        let value: Value = read_json(&mut self.stream).await.unwrap();
        if value.get("result").is_some() {
            Ok(serde_json::from_value::<JsonRpcSuccessV1>(value)
                .unwrap()
                .result)
        } else {
            Err(serde_json::from_value::<JsonRpcErrorV1>(value)
                .unwrap()
                .error
                .data)
        }
    }

    async fn accept_only_candidate(&mut self) -> MemoryCandidate {
        let LocalResult::Candidates { candidates } = self
            .call(LocalRequest::CandidatesList(CandidateListParams {
                project_id: None,
            }))
            .await
            .unwrap()
        else {
            panic!("desktop candidate list returned the wrong result")
        };
        assert_eq!(candidates.len(), 1);
        let candidate = candidates[0].clone();
        let reviewed = self
            .call(LocalRequest::CandidateReview(CandidateReviewParams {
                candidate_id: candidate.id,
                accepted: true,
                operation_id: operation_id(),
            }))
            .await
            .unwrap();
        assert!(matches!(reviewed, LocalResult::Candidates { .. }));
        candidate
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
async fn three_harness_daemon_flow_is_scoped_idempotent_and_never_installs_a_bridge() {
    let fixture = Fixture::new();
    let primary = project_identity("primary");
    let second = project_identity("second");
    let policies = [
        (
            HarnessId::ClaudeCode,
            HarnessAccessPolicy::SelectedProject {
                project_id: primary.project_id,
                read_only: false,
            },
        ),
        (
            HarnessId::Codex,
            HarnessAccessPolicy::SelectedProject {
                project_id: primary.project_id,
                read_only: false,
            },
        ),
        (
            HarnessId::Hermes,
            HarnessAccessPolicy::SelectedProject {
                project_id: primary.project_id,
                read_only: false,
            },
        ),
    ];
    fixture
        .daemon
        .seed_mcp_project(&primary, &fixture.project_root, &policies)
        .unwrap();
    fixture
        .daemon
        .seed_mcp_project(&second, &fixture.second_project_root, &[])
        .unwrap();
    let engine = Arc::new(TestRecordingBridgeInstallEngine::default());
    let config = fixture
        .daemon
        .clone()
        .with_bridge_install_engine(engine.clone());
    let local = fixture.local_daemon();

    let (handle, owner) = start_daemon(&config).await;
    let codex = fixture.binding_for(HarnessId::Codex, &fixture.project_root);
    let claude = fixture.binding_for(HarnessId::ClaudeCode, &fixture.project_root);
    let hermes = fixture.binding_for(HarnessId::Hermes, &fixture.project_root);

    let remembered = local
        .call(
            record_id(),
            call(
                codex.clone(),
                "context_relay_remember",
                json!({
                    "operationId": record_id(),
                    "kind": "note",
                    "title": "Three harness memory",
                    "markdown": "The daemon owns scope resolution.",
                    "tags": ["acceptance"],
                    "scope": {"scope": "active_project"}
                }),
            ),
        )
        .await
        .unwrap();
    let memory_id = remembered["memory"]["id"].clone();
    let fetched = local
        .call(
            record_id(),
            call(
                claude.clone(),
                "context_relay_get",
                json!({"recordId": memory_id}),
            ),
        )
        .await
        .unwrap();
    assert_eq!(fetched["record"]["record"]["title"], "Three harness memory");
    let searched = local
        .call(
            record_id(),
            call(
                hermes.clone(),
                "context_relay_search",
                json!({
                    "query": "Three harness memory",
                    "scope": {"scope": "active_project"},
                    "limit": 10
                }),
            ),
        )
        .await
        .unwrap();
    assert_eq!(searched["memories"].as_array().unwrap().len(), 1);

    let created_task = local
        .call(
            record_id(),
            call(
                claude.clone(),
                "context_relay_upsert_task",
                json!({
                    "operationId": record_id(),
                    "taskId": null,
                    "title": "Finish the three-harness scenario",
                    "bodyMarkdown": "Complete this through Hermes.",
                    "status": "open",
                    "expectedRevision": null
                }),
            ),
        )
        .await
        .unwrap();
    let completed_task = local
        .call(
            record_id(),
            call(
                hermes.clone(),
                "context_relay_complete_task",
                json!({
                    "operationId": record_id(),
                    "taskId": created_task["task"]["id"],
                    "expectedRevision": created_task["task"]["revision"],
                    "evidence": [{"summary": "Completed through real local IPC.", "kind": "result"}]
                }),
            ),
        )
        .await
        .unwrap();
    assert_eq!(completed_task["task"]["status"], "done");
    assert_eq!(
        completed_task["task"]["evidence"][0]["summary"],
        "Completed through real local IPC."
    );

    let denied = local
        .call(
            record_id(),
            call(
                fixture.binding_for(HarnessId::Codex, &fixture.second_project_root),
                "context_relay_status",
                json!({}),
            ),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        denied,
        BridgeError::Client(ClientError {
            code: ErrorCode::ScopeDenied,
            ..
        })
    ));
    engine.assert_no_setup_calls();

    stop_daemon(handle, owner).await;
    let (handle, owner) = start_daemon(&config).await;
    let restarted = local
        .call(
            record_id(),
            call(
                claude.clone(),
                "context_relay_get",
                json!({"recordId": memory_id}),
            ),
        )
        .await
        .unwrap();
    assert_eq!(
        restarted["record"]["record"]["title"],
        "Three harness memory"
    );
    stop_daemon(handle, owner).await;

    let gate = Arc::new(TestWorkerGate::new());
    let gated = config.with_worker_gate(gate.clone());
    let (handle, owner) = start_daemon(&gated).await;
    let timeout_operation = record_id();
    let timeout_payload = json!({
        "operationId": timeout_operation,
        "kind": "note",
        "title": "One unknown outcome",
        "markdown": "The retry must replay the original write exactly once.",
        "tags": ["timeout"],
        "scope": {"scope": "active_project"}
    });
    let mut server = StartedServer::start(local.clone(), codex.clone()).await;
    server
        .send(json!({
            "jsonrpc": "2.0",
            "id": "timeout-write",
            "method": "tools/call",
            "params": {"name": "context_relay_remember", "arguments": timeout_payload}
        }))
        .await;
    gate.wait_until_entered().await;
    tokio::time::pause();
    tokio::time::advance(REQUEST_TIMEOUT + std::time::Duration::from_millis(1)).await;
    let timeout = server.receive().await;
    assert_eq!(
        timeout["result"]["_meta"]["contextRelay"],
        json!({"code": "timeout", "retryable": true, "fieldPath": null})
    );
    tokio::time::resume();
    gate.release();

    let replayed = local
        .call(
            record_id(),
            call(
                codex.clone(),
                "context_relay_remember",
                timeout_payload.clone(),
            ),
        )
        .await
        .unwrap();
    assert_eq!(replayed["memory"]["title"], "One unknown outcome");
    let matching = local
        .call(
            record_id(),
            call(
                hermes,
                "context_relay_search",
                json!({
                    "query": "One unknown outcome",
                    "scope": {"scope": "active_project"},
                    "limit": 10
                }),
            ),
        )
        .await
        .unwrap();
    assert_eq!(
        matching["memories"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|memory| memory["title"] == "One unknown outcome")
            .count(),
        1
    );
    server.close().await;
    stop_daemon(handle, owner).await;
    engine.assert_no_setup_calls();
}

#[tokio::test]
async fn production_setup_watcher_review_and_actual_mcp_form_one_chain() {
    let fixture = Fixture::new();
    let project = project_identity("authoritative native memory");
    let materialized = MaterializedCodexE2e::new(&fixture, project.project_id);
    let config = fixture
        .daemon
        .clone()
        .with_bridge_install_engine(materialized.engine.clone());
    config
        .seed_mcp_project(
            &project,
            &fixture.project_root,
            &[(HarnessId::Codex, HarnessAccessPolicy::Default)],
        )
        .unwrap();

    let (handle, owner) = start_daemon(&config).await;
    let mut desktop = DesktopIpcClient::connect(&config).await;
    let LocalResult::Plan { plan } = desktop
        .call(LocalRequest::HarnessPreview(HarnessParams {
            harness: HarnessId::Codex,
            project_id: Some(project.project_id),
            hermes_profile: None,
        }))
        .await
        .unwrap()
    else {
        panic!("real Codex setup must return a plan")
    };
    let stored = config.setup_plan_summary(&plan.plan_id).unwrap().unwrap();
    assert!(stored.previewed);
    assert_eq!(&stored.setup, plan.as_ref());
    assert_eq!(plan.adapter_version, 2);
    assert!(plan.cli_operations.is_empty());
    assert_eq!(stored.mutation_count, 3);
    assert_eq!(stored.native_memory_registrations.len(), 2);
    assert!(
        stored
            .native_memory_registrations
            .iter()
            .all(|registration| {
                materialized.sources.contains(&registration.source_id)
                    && !registration.has_last_applied_digest
            })
    );
    desktop
        .call(LocalRequest::HarnessApply(PlanParams {
            plan_id: plan.plan_id,
        }))
        .await
        .unwrap();
    wait_for_native_previews(&config, &materialized.sources).await;
    assert!(config.setup_plan_applied(&plan.plan_id).unwrap());
    assert!(
        config
            .native_transaction_committed(&format!("bridge-setup-{}", plan.plan_id))
            .unwrap()
    );
    assert!(
        std::fs::read_to_string(&materialized.config_path)
            .unwrap()
            .contains("generate_memories = false")
    );
    assert!(
        std::fs::read_to_string(&materialized.config_path)
            .unwrap()
            .contains("[mcp_servers.context-relay]")
    );
    assert!(
        std::fs::read_to_string(&materialized.instruction_path)
            .unwrap()
            .contains("context_relay_complete_task")
    );
    assert!(config.native_memory_candidates().unwrap().is_empty());
    drop(desktop);

    let native_edit = "The actual MCP bridge retrieves this reviewed setup-owned memory.\n";
    std::fs::write(&materialized.memory_path, native_edit).unwrap();
    tokio::time::sleep(Duration::from_millis(750)).await;
    wait_for_native_candidates(&config, 1).await;
    let mut desktop = DesktopIpcClient::connect(&config).await;
    let candidate = desktop.accept_only_candidate().await;
    drop(desktop);

    let mut bridge = StartedServer::start(fixture.local_daemon(), fixture.binding()).await;
    bridge
        .send(json!({
            "jsonrpc": "2.0",
            "id": "accepted-native-search",
            "method": "tools/call",
            "params": {
                "name": "context_relay_search",
                "arguments": {
                    "query": "reviewed setup-owned memory",
                    "scope": {"scope": "global"},
                    "limit": 10
                }
            }
        }))
        .await;
    let searched = bridge.receive().await;
    assert_eq!(searched["id"], "accepted-native-search");
    assert!(
        searched["result"]["structuredContent"].is_object(),
        "{searched}"
    );
    let output: SearchOutput =
        serde_json::from_value(searched["result"]["structuredContent"].clone()).unwrap();
    assert_eq!(output.memories.len(), 1, "{searched}");
    assert_eq!(output.memories[0].id, candidate.proposed_memory.id);
    assert_eq!(output.memories[0].body_markdown, native_edit);

    bridge.close().await;
    stop_daemon(handle, owner).await;
}

#[tokio::test]
async fn managed_requirements_block_production_bridge_preview_without_native_authority() {
    let fixture = Fixture::new();
    let project = project_identity("blocked managed requirements");
    let materialized =
        MaterializedCodexE2e::new_with_requirements(&fixture, project.project_id, true);
    let config = fixture
        .daemon
        .clone()
        .with_bridge_install_engine(materialized.engine.clone());
    config
        .seed_mcp_project(
            &project,
            &fixture.project_root,
            &[(HarnessId::Codex, HarnessAccessPolicy::Default)],
        )
        .unwrap();
    let before = [
        std::fs::read(&materialized.memory_path).unwrap(),
        std::fs::read(&materialized.config_path).unwrap(),
        std::fs::read(&materialized.instruction_path).unwrap(),
    ];

    let (handle, owner) = start_daemon(&config).await;
    let mut desktop = DesktopIpcClient::connect(&config).await;
    let error = desktop
        .call(LocalRequest::HarnessPreview(HarnessParams {
            harness: HarnessId::Codex,
            project_id: Some(project.project_id),
            hermes_profile: None,
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::HarnessUnsupported);
    stop_daemon(handle, owner).await;

    assert_eq!(std::fs::read(&materialized.memory_path).unwrap(), before[0]);
    assert_eq!(std::fs::read(&materialized.config_path).unwrap(), before[1]);
    assert_eq!(
        std::fs::read(&materialized.instruction_path).unwrap(),
        before[2]
    );
}

#[tokio::test]
async fn claude_and_codex_primary_instructions_complete_tasks_through_typed_mcp() {
    let fixture = Fixture::new();
    let project = project_identity("primary instruction task evidence");
    fixture
        .daemon
        .seed_mcp_project(
            &project,
            &fixture.project_root,
            &[
                (HarnessId::ClaudeCode, HarnessAccessPolicy::Default),
                (HarnessId::Codex, HarnessAccessPolicy::Default),
            ],
        )
        .unwrap();
    let config = fixture
        .daemon
        .clone()
        .with_bridge_install_engine(Arc::new(TestRecordingBridgeInstallEngine::default()));
    let (handle, owner) = start_daemon(&config).await;
    let device_id: DeviceId = record_id().to_string().parse().unwrap();

    for (harness, harness_name) in [
        (HarnessId::ClaudeCode, "claude-code"),
        (HarnessId::Codex, "codex"),
    ] {
        let instruction = test_primary_memory_instruction_component(
            harness,
            project.project_id,
            device_id,
            HybridLogicalClock::new(1_900_001_100_000, 0, device_id),
        )
        .unwrap();
        assert!(!instruction.body_markdown.contains("--hook-event"));
        assert!(!instruction.body_markdown.contains("session_id"));
        assert!(
            instruction
                .body_markdown
                .contains("typed `context_relay_complete_task` tool")
        );
        assert!(
            instruction
                .body_markdown
                .contains("current Context Relay task ID")
        );
        assert!(
            instruction
                .body_markdown
                .contains("never infer or substitute a vendor task identifier")
        );

        let binding = fixture.binding_for(harness, &fixture.project_root);
        let mut bridge = StartedServer::start(fixture.local_daemon(), binding).await;
        bridge
            .send(json!({
                "jsonrpc": "2.0",
                "id": format!("create-{harness_name}-task"),
                "method": "tools/call",
                "params": {
                    "name": "context_relay_upsert_task",
                    "arguments": {
                        "operationId": record_id(),
                        "taskId": null,
                        "title": format!("Reach {harness_name} task evidence"),
                        "bodyMarkdown": "Complete through the installed primary-memory contract.",
                        "status": "in_progress",
                        "expectedRevision": null
                    }
                }
            }))
            .await;
        let created_response = bridge.receive().await;
        let created: UpsertTaskOutput =
            serde_json::from_value(created_response["result"]["structuredContent"].clone())
                .unwrap();
        let evidence_summary = format!("Reached {harness_name} through typed MCP.");
        bridge
            .send(json!({
                "jsonrpc": "2.0",
                "id": format!("complete-{harness_name}-task"),
                "method": "tools/call",
                "params": {
                    "name": "context_relay_complete_task",
                    "arguments": {
                        "operationId": record_id(),
                        "taskId": created.task.id,
                        "expectedRevision": created.task.revision,
                        "evidence": [{
                            "summary": evidence_summary,
                            "kind": "test",
                            "reference": null
                        }]
                    }
                }
            }))
            .await;
        let completed_response = bridge.receive().await;
        assert_eq!(
            completed_response["result"]["structuredContent"]["task"]["status"],
            "done"
        );
        bridge
            .send(json!({
                "jsonrpc": "2.0",
                "id": format!("list-{harness_name}-task"),
                "method": "tools/call",
                "params": {
                    "name": "context_relay_list_tasks",
                    "arguments": {"status": "done"}
                }
            }))
            .await;
        let listed_response = bridge.receive().await;
        let listed: ListTasksOutput =
            serde_json::from_value(listed_response["result"]["structuredContent"].clone()).unwrap();
        let completed = listed
            .tasks
            .iter()
            .find(|task| task.id == created.task.id)
            .expect("current Context Relay task must be reachable after typed completion");
        assert_eq!(completed.status, TaskStatus::Done);
        assert_eq!(completed.evidence.len(), 1);
        assert_eq!(completed.evidence[0].summary, evidence_summary);
        bridge.close().await;
    }

    assert_eq!(config.native_hook_session_count().unwrap(), 0);
    stop_daemon(handle, owner).await;
}

#[tokio::test]
async fn native_hooks_persist_only_allowlisted_fields_across_every_output_boundary() {
    let fixture = Fixture::new();
    let project = project_identity("native hook privacy");
    fixture
        .daemon
        .seed_mcp_project(
            &project,
            &fixture.project_root,
            &[(HarnessId::Codex, HarnessAccessPolicy::Default)],
        )
        .unwrap();
    let config = fixture
        .daemon
        .clone()
        .with_bridge_install_engine(Arc::new(TestRecordingBridgeInstallEngine::default()));
    let (handle, owner) = start_daemon(&config).await;

    let mut bridge = StartedServer::start(fixture.local_daemon(), fixture.binding()).await;
    bridge
        .send(json!({
            "jsonrpc": "2.0",
            "id": "create-hook-task",
            "method": "tools/call",
            "params": {
                "name": "context_relay_upsert_task",
                "arguments": {
                    "operationId": record_id(),
                    "taskId": null,
                    "title": "Record allowlisted hook evidence",
                    "bodyMarkdown": "Excluded native hook fields must never persist.",
                    "status": "in_progress",
                    "expectedRevision": null
                }
            }
        }))
        .await;
    let created_response = bridge.receive().await;
    let created: UpsertTaskOutput =
        serde_json::from_value(created_response["result"]["structuredContent"].clone()).unwrap();
    bridge.close().await;

    let raw_session_bytes = b"raw native session content stays byte-for-byte unchanged\n";

    let session_id = "allowlisted-session-0198";
    let mut excluded_sentinels = Vec::new();
    let mut raw_session_fixtures = Vec::new();
    let events = [
        (HookInvocationKind::SessionStart, "START", 1_900_001_000_000),
        (
            HookInvocationKind::TaskEvidence,
            "EVIDENCE",
            1_900_001_000_100,
        ),
        (HookInvocationKind::SessionStop, "STOP", 1_900_001_000_200),
    ];
    let mut captured_stdout = Vec::new();
    let mut captured_stderr = Vec::new();
    let mut ipc_fixtures = Vec::new();
    for (event, label, now_ms) in events {
        let prompt = format!("HOOK_PROMPT_EXCLUDED_{label}_6AC9");
        let response = format!("HOOK_RESPONSE_EXCLUDED_{label}_A218");
        let assistant = format!("HOOK_ASSISTANT_EXCLUDED_{label}_44DE");
        let tool_input = format!("HOOK_TOOL_INPUT_EXCLUDED_{label}_E29B");
        let tool_output = format!("HOOK_TOOL_OUTPUT_EXCLUDED_{label}_7B11");
        let unknown = format!("HOOK_UNKNOWN_EXCLUDED_{label}_D087");
        let transcript = format!("HOOK_TRANSCRIPT_PATH_EXCLUDED_{label}_8C84");
        let raw_session_path = fixture
            ._root
            .path()
            .join(format!("raw-session-{transcript}.jsonl"));
        std::fs::write(&raw_session_path, raw_session_bytes).unwrap();
        raw_session_fixtures.push((
            raw_session_path.clone(),
            <[u8; 32]>::from(Sha256::digest(raw_session_bytes)),
        ));
        excluded_sentinels.extend([
            prompt.clone(),
            response.clone(),
            assistant.clone(),
            transcript,
            tool_input.clone(),
            tool_output.clone(),
            unknown.clone(),
        ]);
        let mut payload = json!({
            "session_id": session_id,
            "prompt": prompt,
            "response": response,
            "last_assistant_message": assistant,
            "transcript_path": raw_session_path,
            "tool_input": {"secret": tool_input},
            "tool_output": [tool_output],
            "future_unknown_field": {"nested": [unknown]}
        });
        if event == HookInvocationKind::TaskEvidence {
            payload["task_id"] = json!(created.task.id);
            payload["evidence"] = json!([{
                "summary": "Verified through the real native hook path.",
                "kind": "result",
                "reference": "context-relay://hook/privacy-acceptance"
            }]);
        }
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let projected = project_hook_input(
            HarnessId::Codex,
            event,
            &payload_bytes,
            &fixture.project_root,
            now_ms,
        )
        .unwrap();
        ipc_fixtures.push(serde_json::to_vec(&LocalRequest::NativeHookEvent(projected)).unwrap());
        match execute_hook(
            fixture.local_daemon(),
            HarnessId::Codex,
            event,
            &payload_bytes,
            &fixture.project_root,
            now_ms,
        )
        .await
        {
            Ok(stdout) => captured_stdout.push(stdout.as_bytes().to_vec()),
            Err(error) => captured_stderr.push(error.to_string().into_bytes()),
        }
    }
    assert_eq!(captured_stdout[0], SESSION_START_REMINDER.as_bytes());
    assert_eq!(captured_stdout[1], b"");
    assert_eq!(captured_stdout[2], b"");
    assert!(captured_stderr.is_empty());

    let mut bridge = StartedServer::start(fixture.local_daemon(), fixture.binding()).await;
    bridge
        .send(json!({
            "jsonrpc": "2.0",
            "id": "list-hook-task",
            "method": "tools/call",
            "params": {
                "name": "context_relay_list_tasks",
                "arguments": {"status": "done"}
            }
        }))
        .await;
    let listed_response = bridge.receive().await;
    let listed: ListTasksOutput =
        serde_json::from_value(listed_response["result"]["structuredContent"].clone()).unwrap();
    assert_eq!(listed.tasks.len(), 1);
    assert_eq!(listed.tasks[0].id, created.task.id);
    assert_eq!(listed.tasks[0].evidence.len(), 1);
    assert_eq!(
        listed.tasks[0].evidence[0].summary,
        "Verified through the real native hook path."
    );
    let listed_fixture = serde_json::to_vec(&listed).unwrap();
    bridge.close().await;
    stop_daemon(handle, owner).await;

    for (raw_session_path, raw_digest_before) in &raw_session_fixtures {
        let raw_session_after = std::fs::read(raw_session_path).unwrap();
        let raw_digest_after: [u8; 32] = Sha256::digest(&raw_session_after).into();
        assert_eq!(&raw_digest_after, raw_digest_before);
        assert_eq!(raw_session_after, raw_session_bytes);
    }

    let vault_cells = config.test_vault_plaintext_cells().unwrap();
    assert!(!vault_cells.is_empty());
    assert!(
        vault_cells
            .iter()
            .any(|cell| cell.table == "native_hook_sessions")
    );
    assert!(vault_cells.iter().any(|cell| cell.table == "tasks"));
    let native_outputs = regular_file_contents(fixture._root.path());
    let mut boundaries: Vec<(&str, &[u8])> = Vec::new();
    boundaries.extend(
        vault_cells
            .iter()
            .map(|cell| (cell.column.as_str(), cell.bytes.as_slice())),
    );
    boundaries.extend(
        native_outputs
            .iter()
            .map(|(path, bytes)| (path.as_str(), bytes.as_slice())),
    );
    boundaries.extend(
        captured_stdout
            .iter()
            .map(|bytes| ("captured stdout", bytes.as_slice())),
    );
    boundaries.extend(
        captured_stderr
            .iter()
            .map(|bytes| ("captured stderr", bytes.as_slice())),
    );
    boundaries.extend(
        ipc_fixtures
            .iter()
            .map(|bytes| ("serialized IPC fixture", bytes.as_slice())),
    );
    boundaries.push(("typed MCP task output", &listed_fixture));

    for sentinel in &excluded_sentinels {
        for (boundary, bytes) in &boundaries {
            assert_bytes_do_not_contain(bytes, sentinel, boundary);
            if let Ok(decoded) = std::str::from_utf8(bytes) {
                assert!(
                    !decoded.contains(sentinel),
                    "excluded sentinel {sentinel} leaked through decoded {boundary}"
                );
            }
        }
    }
}

#[tokio::test]
async fn sixty_four_real_calls_and_cancellations_fit_below_the_daemon_cap() {
    let fixture = Fixture::new();
    let gate = Arc::new(TestWorkerGate::new());
    let _release_worker = ReleaseWorkerOnDrop(gate.clone());
    let gated = fixture.daemon.clone().with_worker_gate(gate.clone());
    let (handle, owner) = start_daemon(&gated).await;
    let local = fixture.local_daemon();
    let mut server = StartedServer::start(local.clone(), fixture.binding()).await;

    for id in 0..MAX_IN_FLIGHT_TOOL_CALLS {
        server.send(status_call(json!(id))).await;
    }
    tokio::time::timeout(
        REQUEST_TIMEOUT,
        gate.wait_until_enqueued(MAX_IN_FLIGHT_TOOL_CALLS),
    )
    .await
    .unwrap_or_else(|_| panic!("only {} of 64 calls reached the daemon", gate.enqueued()));
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
    tokio::time::timeout(
        REQUEST_TIMEOUT,
        local.wait_for_test_call_completions(MAX_IN_FLIGHT_TOOL_CALLS),
    )
    .await
    .expect("all admitted MCP calls must complete after releasing the worker");
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

struct MaterializedCodexE2e {
    engine: Arc<TestCodexBridgeInstallEngine>,
    sources: Vec<Sha256Digest>,
    memory_path: PathBuf,
    config_path: PathBuf,
    instruction_path: PathBuf,
}

impl MaterializedCodexE2e {
    fn new(fixture: &Fixture, project_id: ProjectId) -> Self {
        Self::new_with_requirements(fixture, project_id, false)
    }

    fn new_with_requirements(
        fixture: &Fixture,
        project_id: ProjectId,
        active_requirements: bool,
    ) -> Self {
        let frozen: Value =
            serde_json::from_str(include_str!("../../core/tests/fixtures/codex-0.144.1.json"))
                .unwrap();
        let root = std::fs::canonicalize(fixture._root.path()).unwrap();
        let project_root = std::fs::canonicalize(&fixture.project_root).unwrap();
        let codex_home = root.join("codex-home");
        let home = root.join("home");
        let working_directory = project_root.join("service");
        materialize_json_substituting(
            &codex_home,
            frozen["codexHome"].as_object().unwrap(),
            &project_root,
        );
        materialize_json(
            &home.join(".agents/skills"),
            frozen["userSkills"].as_object().unwrap(),
        );
        materialize_json(&project_root, frozen["project"].as_object().unwrap());
        std::fs::create_dir_all(&working_directory).unwrap();
        let requirements = root.join("requirements.toml");
        if active_requirements {
            std::fs::write(&requirements, frozen["requirements"].as_str().unwrap()).unwrap();
        }
        let executable = test_executable(root.join(if cfg!(windows) {
            "codex-bin.exe"
        } else {
            "codex-bin"
        }));
        let bridge_path = test_executable(root.join(if cfg!(windows) {
            "context-relay-context-mcp.exe"
        } else {
            "context-relay-context-mcp"
        }));
        let lock_root = root.join("native-locks");
        std::fs::create_dir_all(&lock_root).unwrap();
        let device_id: DeviceId = record_id().to_string().parse().unwrap();
        let bridge = TestCodexBridgeInstallEngine::from_request(TestCodexBridgeInstallRequest {
            executable,
            bridge_path,
            version: "0.144.1".into(),
            installation_method: InstallationMethod::PackageManager,
            codex_home: codex_home.clone(),
            user_skills_dir: home.join(".agents/skills"),
            project_root,
            working_directory,
            requirements_paths: vec![requirements],
            project_id,
            origin_device: device_id,
            observed_hlc: HybridLogicalClock::new(1_900_000_000_000, 0, device_id),
            lock_root,
        })
        .unwrap();
        for source in &bridge.sources {
            std::fs::write(wire_path_to_path(&source.path), b"").unwrap();
        }
        Self {
            engine: bridge.engine,
            sources: bridge.sources.into_iter().map(|source| source.id).collect(),
            memory_path: codex_home.join("memories/MEMORY.md"),
            config_path: codex_home.join("config.toml"),
            instruction_path: fixture.project_root.join("AGENTS.md"),
        }
    }
}

fn materialize_json(root: &Path, files: &Map<String, Value>) {
    for (relative, contents) in files {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents.as_str().unwrap()).unwrap();
    }
}

fn materialize_json_substituting(root: &Path, files: &Map<String, Value>, project: &Path) {
    let project = project.to_string_lossy();
    for (relative, contents) in files {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let contents = contents.as_str().unwrap();
        let contents = if relative.ends_with(".toml") {
            // The quoted TOML key needs string escaping, unlike plain-text paths.
            contents.replace(
                "\"$PROJECT\"",
                &serde_json::to_string(project.as_ref()).unwrap(),
            )
        } else {
            contents.replace("$PROJECT", project.as_ref())
        };
        std::fs::write(path, contents).unwrap();
    }
}

fn test_executable(path: PathBuf) -> PathBuf {
    std::fs::write(&path, b"\x7fELFfixture executable").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    path
}

fn wire_path_to_path(path: &WireNativeValue) -> PathBuf {
    #[cfg(windows)]
    {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt as _;

        let words = path
            .bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        PathBuf::from(OsString::from_wide(&words))
    }
    #[cfg(not(windows))]
    {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt as _;

        PathBuf::from(OsString::from_vec(path.bytes.clone()))
    }
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

fn regular_file_contents(root: &Path) -> Vec<(String, Vec<u8>)> {
    fn collect(path: &Path, contents: &mut Vec<(String, Vec<u8>)>) {
        let mut entries = std::fs::read_dir(path)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let file_type = entry.file_type().unwrap();
            if file_type.is_dir() {
                collect(&entry.path(), contents);
            } else if file_type.is_file() {
                contents.push((
                    entry.path().display().to_string(),
                    std::fs::read(entry.path()).unwrap(),
                ));
            }
        }
    }

    let mut contents = Vec::new();
    collect(root, &mut contents);
    contents
}

fn assert_bytes_do_not_contain(bytes: &[u8], sentinel: &str, boundary: &str) {
    assert!(
        !bytes
            .windows(sentinel.len())
            .any(|window| window == sentinel.as_bytes()),
        "excluded sentinel {sentinel} leaked through {boundary}"
    );
}
