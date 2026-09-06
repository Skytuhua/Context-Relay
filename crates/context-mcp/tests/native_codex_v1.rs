#![cfg(all(feature = "test-support", windows))]

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

use context_relay_context_mcp::{Daemon as _, LocalDaemon};
use context_relay_contextd::{DaemonState, test_support::TestDaemonConfig};
use context_relay_local_ipc::{InstallationToken, RuntimeConfig};
use context_relay_protocol::{
    HarnessAccessPolicy, HarnessId, McpBinding, McpCallParams, NativePlatform, ProjectIdentity,
    RecordId, WireNativeValue,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

// Reuse the exact stdin-gated, kill-on-close job fixture and its existing canaries.
#[path = "../../core/src/test_windows_process.rs"]
mod windows_process;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires pinned Codex 0.144.6, Node and the explicitly built test-only bridge example"]
async fn actual_codex_exchanges_memory_and_tasks_with_the_production_dispatcher() {
    const CODEX_SHA256: &str = "4b76ded066d0239115ca97473d010c92072bc5c5550a45dd7cbebe1e9eb956a7";
    let codex = PathBuf::from(env::var_os("CONTEXT_RELAY_TEST_CODEX_EXE").expect("explicit Codex"));
    let node = PathBuf::from(env::var_os("CONTEXT_RELAY_TEST_NODE_EXE").expect("explicit Node"));
    let bridge = PathBuf::from(
        env::var_os("CONTEXT_RELAY_TEST_MCP_FIXTURE_EXE").expect("explicit fixture example"),
    );
    assert_eq!(
        format!("{:x}", Sha256::digest(fs::read(&codex).unwrap())),
        CODEX_SHA256
    );
    let temp = tempfile::tempdir().unwrap();
    let physical = fs::canonicalize(temp.path()).unwrap();
    assert!(
        matches!(physical.components().next(), Some(std::path::Component::Prefix(prefix))
        if matches!(prefix.kind(), std::path::Prefix::VerbatimDisk(_)))
    );
    let root = PathBuf::from(physical.to_str().unwrap().strip_prefix(r"\\?\").unwrap());
    assert_eq!(fs::canonicalize(&root).unwrap(), physical);
    let root = root.join("MCP 測試 O’Brien & [literal]");
    fs::create_dir(&root).unwrap();
    let project_root = root.join("project");
    fs::create_dir(&project_root).unwrap();
    let home = root.join("home");
    fs::create_dir(&home).unwrap();
    let bridge_path = root.join("fixture bridge.exe");
    fs::copy(bridge, &bridge_path).unwrap();
    let suffix = format!("codex-native-{}", Uuid::now_v7().simple());
    fs::write(root.join("bridge-runtime.txt"), &suffix).unwrap();
    let runtime = RuntimeConfig::for_test(suffix, Some(root.join("runtime"))).unwrap();
    let config = TestDaemonConfig::new(
        runtime,
        root.join("vault.db"),
        InstallationToken::from_bytes([0x71; 32]),
    );
    let project = ProjectIdentity {
        project_id: Uuid::now_v7().to_string().parse().unwrap(),
        name: "Native Codex fixture".into(),
        github_repository_id: None,
        git_remote_fingerprint: None,
        monorepo_subdirectory: None,
    };
    config
        .seed_mcp_project(
            &project,
            &project_root,
            &[(
                HarnessId::Codex,
                HarnessAccessPolicy::SelectedProject {
                    project_id: project.project_id,
                    read_only: false,
                },
            )],
        )
        .unwrap();
    let hooks = context_relay_contextd::test_support::test_managed_memory_hooks(
        HarnessId::Codex,
        &wire_path(&fs::canonicalize(&bridge_path).unwrap()),
    )
    .unwrap();
    let manifest = root.join("manifest.json");
    fs::write(
        &manifest,
        serde_json::to_vec(&json!({
            "executable":codex,"sha256":CODEX_SHA256,"bridge":bridge_path,
            "bridgeSha256":format!("{:x}",Sha256::digest(fs::read(&bridge_path).unwrap())),
        "root":root,"project":project_root,"home":home,"projectId":project.project_id,
        "toolNames":context_relay_protocol::MCP_TOOL_NAMES,
            "operations":(0..8).map(|_| Uuid::now_v7().to_string()).collect::<Vec<_>>(),
            "hooks":serde_json::from_str::<Value>(&hooks[0].body_markdown).unwrap(),
        }))
        .unwrap(),
    )
    .unwrap();
    let daemon = config.start().await.unwrap();
    let handle = daemon.handle();
    let owner = tokio::spawn(daemon.run());
    let stdout = root.join("stdout");
    let stderr = root.join("stderr");
    let mut command = Command::new(node);
    command.env_clear();
    for name in ["SystemRoot", "WINDIR"] {
        if let Some(value) = env::var_os(name) {
            command.env(name, value);
        }
    }
    command
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/codex-mcp-session.mjs"))
        .arg(manifest)
        .current_dir(&root)
        .stdin(Stdio::piped())
        .stdout(fs::File::create(&stdout).unwrap())
        .stderr(fs::File::create(&stderr).unwrap());
    let outcome = tokio::task::spawn_blocking(move || {
        windows_process::run_in_owned_job(&mut command, Duration::from_secs(180))
    })
    .await;
    assert_eq!(handle.shutdown().await, DaemonState::Stopped);
    assert_eq!(owner.await.unwrap(), Ok(()));
    assert!(
        matches!(outcome, Ok(Ok(status)) if status.success()),
        "stdout: {}\nstderr: {}",
        fs::read_to_string(&stdout).unwrap(),
        fs::read_to_string(&stderr).unwrap()
    );
    println!("{}", fs::read_to_string(stdout).unwrap());

    // A new daemon instance reads the state written by the actual harness client.
    let daemon = config.start().await.unwrap();
    let handle = daemon.handle();
    let owner = tokio::spawn(daemon.run());
    let local = LocalDaemon::for_test(config.runtime(), config.installation_token());
    let binding = McpBinding {
        harness: HarnessId::Codex,
        working_directory: wire_path(&project_root),
    };
    let remembered = local.call(RecordId::new(Uuid::now_v7()).unwrap(), McpCallParams {
        binding: binding.clone(), name: "context_relay_search".into(),
        arguments: json!({"query":"Native Codex round trip", "scope":{"scope":"active_project"}, "limit":10}),
    }).await;
    let tasks = local
        .call(
            RecordId::new(Uuid::now_v7()).unwrap(),
            McpCallParams {
                binding,
                name: "context_relay_list_tasks".into(),
                arguments: json!({"status":"done"}),
            },
        )
        .await;
    assert_eq!(handle.shutdown().await, DaemonState::Stopped);
    assert_eq!(owner.await.unwrap(), Ok(()));
    assert_eq!(remembered.unwrap()["memories"].as_array().unwrap().len(), 2);
    assert_eq!(tasks.unwrap()["tasks"].as_array().unwrap().len(), 2);
}

fn wire_path(path: &Path) -> WireNativeValue {
    use std::os::windows::ffi::OsStrExt as _;
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
