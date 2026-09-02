#![cfg(any(windows, target_os = "macos"))]

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use context_relay_contextd::test_support::{TestDaemonConfig, TestWorkerGate};
use context_relay_local_ipc::{
    AuthAcceptedV1, AuthTranscriptV1, ConnectedStream, InstallationToken, RuntimeConfig,
    ServerHelloV1, connect, create_proof, read_json, write_json,
};
use context_relay_protocol::{
    ClientError, ClientRole, CompletionEvidenceInput, DaemonInstanceNonce, ErrorCode,
    HarnessAccessPolicy, HarnessId, HelloParams, JsonRpcErrorV1, JsonRpcRequestV1,
    JsonRpcSuccessV1, JsonRpcVersion, LocalRequest, LocalResult, McpBinding, NativeHookEvent,
    NativeHookEventParams, NativePlatform, ProjectIdentity, ProjectParams, RecordId, TaskStatus,
    TaskUpsertParams, WireNativeValue,
};
use uuid::Uuid;

const TOKEN: [u8; 32] = [0x8b; 32];

#[tokio::test]
async fn hook_routes_through_the_worker_and_uses_the_longest_registered_project_root() {
    let root = unique_temp_path("native-hook-longest");
    let parent = root.join("project");
    let nested = parent.join("nested");
    let working = nested.join("src");
    std::fs::create_dir_all(&working).unwrap();

    let runtime = RuntimeConfig::for_test(
        &format!("native-hook-{}", unique_token()),
        Some(short_runtime_root()),
    )
    .unwrap();
    let gate = Arc::new(TestWorkerGate::new());
    let config = TestDaemonConfig::new(
        runtime.clone(),
        root.join("vault.db"),
        InstallationToken::from_bytes(TOKEN),
    )
    .with_worker_gate(gate.clone());
    let parent_project = project("018f22e2-79b0-7cc8-98c4-dc0c0c073981", "parent");
    let nested_project = project("018f22e2-79b0-7cc8-98c4-dc0c0c073982", "nested");
    config
        .seed_mcp_project(&parent_project, &parent, &[])
        .unwrap();
    let policies = [(
        HarnessId::Codex,
        HarnessAccessPolicy::SelectedProject {
            project_id: nested_project.project_id,
            read_only: false,
        },
    )];
    config
        .seed_mcp_project(&nested_project, &nested, &policies)
        .unwrap();

    let daemon = config.start().await.unwrap();
    let handle = daemon.handle();
    let owner = tokio::spawn(daemon.run());
    let mut bridge = RawClient::connect(&runtime, ClientRole::McpBridge).await;
    let request = native_hook(
        HarnessId::Codex,
        &working,
        NativeHookEvent::SessionStart {
            session_id: "session-longest".into(),
        },
        1_700_000_000_001,
    );
    let call = tokio::spawn(async move { bridge.call(request).await });

    tokio::time::timeout(std::time::Duration::from_secs(2), gate.wait_until_entered())
        .await
        .expect("native hook must enter the bounded vault worker");
    gate.release();
    assert_eq!(call.await.unwrap().unwrap(), LocalResult::Empty);

    assert_eq!(
        handle.shutdown().await,
        context_relay_contextd::DaemonState::Stopped
    );
    owner.await.unwrap().unwrap();
}

#[tokio::test]
async fn native_hook_role_authorization_is_enforced_before_routing() {
    let fixture = Fixture::start("native-hook-auth").await;
    let working = fixture.root.join("working");
    std::fs::create_dir_all(&working).unwrap();
    let request = native_hook(
        HarnessId::ClaudeCode,
        &working,
        NativeHookEvent::SessionStart {
            session_id: "session-auth".into(),
        },
        1_700_000_000_002,
    );

    let mut installer = RawClient::connect(&fixture.runtime, ClientRole::Installer).await;
    assert_eq!(
        installer.call(request.clone()).await.unwrap_err().code,
        ErrorCode::ScopeDenied
    );
    let mut bridge = RawClient::connect(&fixture.runtime, ClientRole::McpBridge).await;
    assert_eq!(
        bridge.call(request.clone()).await.unwrap(),
        LocalResult::Empty
    );
    let mut desktop = RawClient::connect(&fixture.runtime, ClientRole::Desktop).await;
    assert_eq!(desktop.call(request).await.unwrap(), LocalResult::Empty);

    fixture.stop().await;
}

#[tokio::test]
async fn no_project_match_is_an_acknowledged_no_op_and_ambiguous_roots_are_rejected() {
    let fixture = Fixture::start("native-hook-unmatched").await;
    let unmatched = fixture.root.join("unmatched");
    std::fs::create_dir_all(&unmatched).unwrap();
    let mut bridge = RawClient::connect(&fixture.runtime, ClientRole::McpBridge).await;
    assert_eq!(
        bridge
            .call(native_hook(
                HarnessId::Codex,
                &unmatched,
                NativeHookEvent::SessionStart {
                    session_id: "no-project".into()
                },
                1_700_000_000_003,
            ))
            .await
            .unwrap(),
        LocalResult::Empty
    );
    fixture.stop().await;

    let root = unique_temp_path("native-hook-ambiguous");
    let working = root.join("project");
    std::fs::create_dir_all(&working).unwrap();
    let runtime = RuntimeConfig::for_test(
        &format!("native-hook-{}", unique_token()),
        Some(short_runtime_root()),
    )
    .unwrap();
    let config = TestDaemonConfig::new(
        runtime.clone(),
        root.join("vault.db"),
        InstallationToken::from_bytes(TOKEN),
    );
    for (id, name) in [
        ("018f22e2-79b0-7cc8-98c4-dc0c0c073983", "first"),
        ("018f22e2-79b0-7cc8-98c4-dc0c0c073984", "second"),
    ] {
        config
            .seed_mcp_project(&project(id, name), &working, &[])
            .unwrap();
    }
    let daemon = config.start().await.unwrap();
    let handle = daemon.handle();
    let owner = tokio::spawn(daemon.run());
    let mut bridge = RawClient::connect(&runtime, ClientRole::McpBridge).await;
    let error = bridge
        .call(native_hook(
            HarnessId::Codex,
            &working,
            NativeHookEvent::SessionStart {
                session_id: "ambiguous".into(),
            },
            1_700_000_000_004,
        ))
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::ScopeDenied);
    assert_eq!(
        handle.shutdown().await,
        context_relay_contextd::DaemonState::Stopped
    );
    owner.await.unwrap().unwrap();
}

#[tokio::test]
async fn task_evidence_is_completed_by_the_resolved_workspace_handler() {
    let root = unique_temp_path("native-hook-task");
    let project_root = root.join("project");
    std::fs::create_dir_all(&project_root).unwrap();
    let runtime = RuntimeConfig::for_test(
        &format!("native-hook-{}", unique_token()),
        Some(short_runtime_root()),
    )
    .unwrap();
    let config = TestDaemonConfig::new(
        runtime.clone(),
        root.join("vault.db"),
        InstallationToken::from_bytes(TOKEN),
    );
    let project = project("018f22e2-79b0-7cc8-98c4-dc0c0c073985", "task project");
    config
        .seed_mcp_project(&project, &project_root, &[])
        .unwrap();
    let daemon = config.start().await.unwrap();
    let handle = daemon.handle();
    let owner = tokio::spawn(daemon.run());
    let mut desktop = RawClient::connect(&runtime, ClientRole::Desktop).await;
    let LocalResult::Tasks { tasks } = desktop
        .call(LocalRequest::TaskUpsert(TaskUpsertParams {
            operation_id: "018f22e2-79b0-7cc8-98c4-dc0c0c073986".parse().unwrap(),
            task_id: None,
            project_id: project.project_id,
            title: "Explicit daemon task".into(),
            body_markdown: "Complete through the native hook worker".into(),
            status: TaskStatus::InProgress,
            expected_revision: None,
        }))
        .await
        .unwrap()
    else {
        panic!("task upsert must return a task")
    };
    let task = tasks.into_iter().next().unwrap();

    let mut bridge = RawClient::connect(&runtime, ClientRole::McpBridge).await;
    assert_eq!(
        bridge
            .call(native_hook(
                HarnessId::ClaudeCode,
                &project_root,
                NativeHookEvent::SessionStart {
                    session_id: "daemon-task-session".into(),
                },
                1_700_000_000_004,
            ))
            .await
            .unwrap(),
        LocalResult::Empty
    );
    assert_eq!(
        bridge
            .call(native_hook(
                HarnessId::ClaudeCode,
                &project_root,
                NativeHookEvent::TaskEvidence {
                    session_id: "daemon-task-session".into(),
                    task_id: task.id,
                    evidence: vec![CompletionEvidenceInput {
                        summary: "Daemon-focused checks passed".into(),
                        kind: "test".into(),
                        reference: Some("native_hook_v1".into()),
                    }],
                },
                1_700_000_000_005,
            ))
            .await
            .unwrap(),
        LocalResult::Empty
    );
    let LocalResult::Tasks { tasks } = desktop
        .call(LocalRequest::TasksList(ProjectParams {
            project_id: project.project_id,
        }))
        .await
        .unwrap()
    else {
        panic!("task list must return tasks")
    };
    assert_eq!(tasks.len(), 1);
    assert_eq!(tasks[0].status, TaskStatus::Done);
    assert_eq!(tasks[0].evidence[0].summary, "Daemon-focused checks passed");

    assert_eq!(
        handle.shutdown().await,
        context_relay_contextd::DaemonState::Stopped
    );
    owner.await.unwrap().unwrap();
}

#[tokio::test]
async fn hook_events_enforce_the_project_read_and_write_policy_matrix() {
    struct Case {
        label: &'static str,
        policy: HarnessAccessPolicy,
        lifecycle_read: bool,
        task_write: bool,
    }

    let project_id = "018f22e2-79b0-7cc8-98c4-dc0c0c073985".parse().unwrap();
    let cases = [
        Case {
            label: "default",
            policy: HarnessAccessPolicy::Default,
            lifecycle_read: true,
            task_write: true,
        },
        Case {
            label: "read-only",
            policy: HarnessAccessPolicy::ReadOnly,
            lifecycle_read: true,
            task_write: false,
        },
        Case {
            label: "active-writable",
            policy: HarnessAccessPolicy::ActiveProjectOnly { read_only: false },
            lifecycle_read: true,
            task_write: true,
        },
        Case {
            label: "active-read-only",
            policy: HarnessAccessPolicy::ActiveProjectOnly { read_only: true },
            lifecycle_read: true,
            task_write: false,
        },
        Case {
            label: "selected-writable",
            policy: HarnessAccessPolicy::SelectedProject {
                project_id,
                read_only: false,
            },
            lifecycle_read: true,
            task_write: true,
        },
        Case {
            label: "selected-read-only",
            policy: HarnessAccessPolicy::SelectedProject {
                project_id,
                read_only: true,
            },
            lifecycle_read: true,
            task_write: false,
        },
        Case {
            label: "global-writable",
            policy: HarnessAccessPolicy::GlobalOnly { read_only: false },
            lifecycle_read: false,
            task_write: false,
        },
        Case {
            label: "global-read-only",
            policy: HarnessAccessPolicy::GlobalOnly { read_only: true },
            lifecycle_read: false,
            task_write: false,
        },
        Case {
            label: "disabled",
            policy: HarnessAccessPolicy::Disabled,
            lifecycle_read: false,
            task_write: false,
        },
    ];

    for case in cases {
        let root = unique_temp_path(case.label);
        let project_root = root.join("project");
        std::fs::create_dir_all(&project_root).unwrap();
        let runtime = RuntimeConfig::for_test(
            &format!("native-hook-{}", unique_token()),
            Some(short_runtime_root()),
        )
        .unwrap();
        let config = TestDaemonConfig::new(
            runtime.clone(),
            root.join("vault.db"),
            InstallationToken::from_bytes(TOKEN),
        );
        let project = ProjectIdentity {
            project_id,
            github_repository_id: None,
            git_remote_fingerprint: None,
            monorepo_subdirectory: None,
            name: case.label.into(),
        };
        config
            .seed_mcp_project(&project, &project_root, &[(HarnessId::Codex, case.policy)])
            .unwrap();
        let daemon = config.start().await.unwrap();
        let handle = daemon.handle();
        let owner = tokio::spawn(daemon.run());
        let mut desktop = RawClient::connect(&runtime, ClientRole::Desktop).await;
        let LocalResult::Tasks { tasks } = desktop
            .call(LocalRequest::TaskUpsert(TaskUpsertParams {
                operation_id: "018f22e2-79b0-7cc8-98c4-dc0c0c073986".parse().unwrap(),
                task_id: None,
                project_id,
                title: format!("{} task", case.label),
                body_markdown: "Policy-gated native evidence".into(),
                status: TaskStatus::InProgress,
                expected_revision: None,
            }))
            .await
            .unwrap()
        else {
            panic!("task upsert must return a task")
        };
        let task = tasks[0].clone();
        let mut bridge = RawClient::connect(&runtime, ClientRole::McpBridge).await;

        let lifecycle = bridge
            .call(native_hook(
                HarnessId::Codex,
                &project_root,
                NativeHookEvent::SessionStart {
                    session_id: format!("{}-session", case.label),
                },
                1_700_000_000_100,
            ))
            .await;
        if case.lifecycle_read {
            assert_eq!(lifecycle.unwrap(), LocalResult::Empty, "{}", case.label);
        } else {
            assert_eq!(
                lifecycle.unwrap_err().code,
                ErrorCode::ScopeDenied,
                "{}",
                case.label
            );
        }

        let evidence = bridge
            .call(native_hook(
                HarnessId::Codex,
                &project_root,
                NativeHookEvent::TaskEvidence {
                    session_id: format!("{}-session", case.label),
                    task_id: task.id,
                    evidence: vec![CompletionEvidenceInput {
                        summary: "Policy matrix evidence".into(),
                        kind: "test".into(),
                        reference: Some(case.label.into()),
                    }],
                },
                1_700_000_000_101,
            ))
            .await;
        if case.task_write {
            assert_eq!(evidence.unwrap(), LocalResult::Empty, "{}", case.label);
        } else {
            assert_eq!(
                evidence.unwrap_err().code,
                ErrorCode::ScopeDenied,
                "{}",
                case.label
            );
        }

        let LocalResult::Tasks { tasks } = desktop
            .call(LocalRequest::TasksList(ProjectParams { project_id }))
            .await
            .unwrap()
        else {
            panic!("task list must return tasks")
        };
        assert_eq!(
            tasks[0].status,
            if case.task_write {
                TaskStatus::Done
            } else {
                TaskStatus::InProgress
            },
            "{}",
            case.label
        );
        assert_eq!(
            handle.shutdown().await,
            context_relay_contextd::DaemonState::Stopped
        );
        owner.await.unwrap().unwrap();
        assert_eq!(
            config.native_hook_session_count().unwrap(),
            usize::from(case.lifecycle_read),
            "{}",
            case.label
        );
    }
}

#[tokio::test]
async fn selected_project_unmatched_hook_is_no_op_but_wrong_matched_project_is_denied() {
    let root = unique_temp_path("selected-unmatched");
    let selected_root = root.join("selected");
    let other_root = root.join("other");
    let unmatched = root.join("unmatched");
    for path in [&selected_root, &other_root, &unmatched] {
        std::fs::create_dir_all(path).unwrap();
    }
    let runtime = RuntimeConfig::for_test(
        &format!("native-hook-{}", unique_token()),
        Some(short_runtime_root()),
    )
    .unwrap();
    let config = TestDaemonConfig::new(
        runtime.clone(),
        root.join("vault.db"),
        InstallationToken::from_bytes(TOKEN),
    );
    let selected = project("018f22e2-79b0-7cc8-98c4-dc0c0c073981", "selected");
    let other = project("018f22e2-79b0-7cc8-98c4-dc0c0c073982", "other");
    config
        .seed_mcp_project(
            &selected,
            &selected_root,
            &[(
                HarnessId::Codex,
                HarnessAccessPolicy::SelectedProject {
                    project_id: selected.project_id,
                    read_only: false,
                },
            )],
        )
        .unwrap();
    config.seed_mcp_project(&other, &other_root, &[]).unwrap();
    let daemon = config.start().await.unwrap();
    let handle = daemon.handle();
    let owner = tokio::spawn(daemon.run());
    let mut bridge = RawClient::connect(&runtime, ClientRole::McpBridge).await;

    assert_eq!(
        bridge
            .call(native_hook(
                HarnessId::Codex,
                &unmatched,
                NativeHookEvent::SessionStart {
                    session_id: "unmatched-selected".into(),
                },
                1_700_000_000_200,
            ))
            .await
            .unwrap(),
        LocalResult::Empty
    );
    assert_eq!(
        bridge
            .call(native_hook(
                HarnessId::Codex,
                &other_root,
                NativeHookEvent::SessionStart {
                    session_id: "wrong-selected".into(),
                },
                1_700_000_000_201,
            ))
            .await
            .unwrap_err()
            .code,
        ErrorCode::ScopeDenied
    );
    assert_eq!(
        handle.shutdown().await,
        context_relay_contextd::DaemonState::Stopped
    );
    owner.await.unwrap().unwrap();
    assert_eq!(config.native_hook_session_count().unwrap(), 0);
}

struct Fixture {
    root: PathBuf,
    runtime: RuntimeConfig,
    handle: context_relay_contextd::DaemonHandle,
    owner: tokio::task::JoinHandle<Result<(), context_relay_contextd::DaemonError>>,
}

impl Fixture {
    async fn start(label: &str) -> Self {
        let root = unique_temp_path(label);
        let runtime = RuntimeConfig::for_test(
            &format!("native-hook-{}", unique_token()),
            Some(short_runtime_root()),
        )
        .unwrap();
        let config = TestDaemonConfig::new(
            runtime.clone(),
            root.join("vault.db"),
            InstallationToken::from_bytes(TOKEN),
        );
        let daemon = config.start().await.unwrap();
        let handle = daemon.handle();
        let owner = tokio::spawn(daemon.run());
        Self {
            root,
            runtime,
            handle,
            owner,
        }
    }

    async fn stop(self) {
        assert_eq!(
            self.handle.shutdown().await,
            context_relay_contextd::DaemonState::Stopped
        );
        self.owner.await.unwrap().unwrap();
    }
}

fn project(id: &str, name: &str) -> ProjectIdentity {
    ProjectIdentity {
        project_id: id.parse().unwrap(),
        github_repository_id: None,
        git_remote_fingerprint: None,
        monorepo_subdirectory: None,
        name: name.into(),
    }
}

fn native_hook(
    harness: HarnessId,
    working: &Path,
    event: NativeHookEvent,
    occurred_at_ms: u64,
) -> LocalRequest {
    LocalRequest::NativeHookEvent(NativeHookEventParams {
        binding: McpBinding {
            harness,
            working_directory: wire_native_path(working),
        },
        event,
        occurred_at_ms,
    })
}

fn wire_native_path(path: &Path) -> WireNativeValue {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::ffi::OsStrExt as _;

        WireNativeValue {
            platform: NativePlatform::Macos,
            bytes: path.as_os_str().as_bytes().to_vec(),
            display: Some(path.display().to_string()),
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt as _;

        WireNativeValue {
            platform: NativePlatform::Windows,
            bytes: path
                .as_os_str()
                .encode_wide()
                .flat_map(u16::to_le_bytes)
                .collect(),
            display: Some(path.display().to_string()),
        }
    }
}

struct RawClient {
    stream: ConnectedStream,
    protocol: context_relay_protocol::ProtocolVersion,
    daemon_instance_nonce: DaemonInstanceNonce,
}

impl RawClient {
    async fn connect(runtime: &RuntimeConfig, role: ClientRole) -> Self {
        let mut stream = connect(runtime).await.unwrap();
        let hello: ServerHelloV1 = read_json(&mut stream).await.unwrap();
        let client_nonce = DaemonInstanceNonce::new([0x32; 32]);
        let transcript = AuthTranscriptV1 {
            role,
            client_nonce,
            server_hello: hello,
        };
        write_json(
            &mut stream,
            &JsonRpcRequestV1 {
                jsonrpc: JsonRpcVersion::V2,
                id: RecordId::new(Uuid::now_v7()).unwrap(),
                protocol: hello.protocol,
                daemon_instance_nonce: hello.daemon_instance_nonce,
                request: LocalRequest::Hello(HelloParams {
                    client_role: role,
                    client_nonce,
                    session_proof: create_proof(&InstallationToken::from_bytes(TOKEN), &transcript),
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
                id: RecordId::new(Uuid::now_v7()).unwrap(),
                protocol: self.protocol,
                daemon_instance_nonce: self.daemon_instance_nonce,
                request,
            },
        )
        .await
        .unwrap();
        let value: serde_json::Value = read_json(&mut self.stream).await.unwrap();
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
}

fn unique_temp_path(label: &str) -> PathBuf {
    #[cfg(windows)]
    let root = std::env::temp_dir();
    #[cfg(not(windows))]
    let root = PathBuf::from("/private/tmp");
    root.join(format!("crnh-{label}-{}", unique_token()))
}

fn unique_token() -> String {
    Uuid::now_v7().simple().to_string()
}

fn short_runtime_root() -> PathBuf {
    #[cfg(windows)]
    let root = std::env::temp_dir();
    #[cfg(not(windows))]
    let root = PathBuf::from("/private/tmp");
    root.join(format!("crr-{}", unique_token()))
}
