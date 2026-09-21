#![cfg(all(feature = "test-support", windows))]

use context_relay_context_mcp::{Daemon as _, LocalDaemon};
use context_relay_contextd::{DaemonState, test_support::TestDaemonConfig};
use context_relay_local_ipc::{InstallationToken, RuntimeConfig};
use context_relay_protocol::{
    HarnessAccessPolicy, HarnessId, McpBinding, McpCallParams, NativePlatform, ProjectIdentity,
    RecordId, WireNativeValue,
};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use std::{
    env, fs, io::Read as _, path::Path, path::PathBuf, process::Command, process::Stdio,
    time::Duration,
};
use uuid::Uuid;

#[path = "../../contextd/tests/fixtures/bridge_image.rs"]
mod bridge_image;
#[path = "../../core/src/test_windows_process.rs"]
mod windows_process;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "explicit pinned Claude, Node and test-only bridge; synthetic profiles and loopback model"]
async fn actual_claude_exchanges_memory_and_tasks_with_the_production_dispatcher() {
    if env::var_os("CONTEXT_RELAY_NATIVE_CLAUDE_CHILD").is_none() {
        let mut command = Command::new(env::current_exe().unwrap());
        command
            .args([
                "actual_claude_exchanges_memory_and_tasks_with_the_production_dispatcher",
                "--exact",
                "--ignored",
                "--nocapture",
            ])
            .env("CONTEXT_RELAY_NATIVE_CLAUDE_CHILD", "1")
            .stdin(Stdio::piped());
        assert!(
            windows_process::run_in_owned_job(&mut command, Duration::from_secs(300))
                .unwrap()
                .success()
        );
        return;
    }
    let mut gate = String::new();
    std::io::stdin().read_to_string(&mut gate).unwrap();
    assert_eq!(gate, "run");
    const CLAUDE_SHA256: &str = "7ff0787ebdc19fc509ccea8886ebf6a53ad8213407fa3a2b7c6d1446efc419f6";
    let claude =
        PathBuf::from(env::var_os("CONTEXT_RELAY_TEST_CLAUDE_EXE").expect("explicit Claude"));
    let node = PathBuf::from(env::var_os("CONTEXT_RELAY_TEST_NODE_EXE").expect("explicit Node"));
    let bridge = PathBuf::from(
        env::var_os("CONTEXT_RELAY_TEST_MCP_FIXTURE_EXE").expect("explicit test-only bridge"),
    );
    let _claude_image = bridge_image::hold_fixture_image(&claude);
    assert_eq!(
        format!("{:x}", Sha256::digest(fs::read(&claude).unwrap())),
        CLAUDE_SHA256
    );
    let temp = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(temp.path())
        .unwrap()
        .join("Claude MCP 專案 O'Brien");
    let project_root = root.join("project");
    let home = root.join("home");
    let config_root = root.join("selected claude");
    for path in [&project_root, &home, &config_root] {
        fs::create_dir_all(path).unwrap();
    }
    fs::create_dir(home.join(".claude")).unwrap();
    fs::write(
        home.join(".claude/settings.json"),
        b"{\"ambientCanary\":true}\n",
    )
    .unwrap();
    fs::write(home.join(".claude.json"), b"{\"ambientCanary\":true}\n").unwrap();
    let bridge_path = root.join("fixture bridge.exe");
    fs::copy(bridge, &bridge_path).unwrap();
    let _bridge_image = bridge_image::hold_fixture_image(&bridge_path);
    bridge_image::identify_fixture(&bridge_path).await;
    let suffix = format!("claude-native-{}", Uuid::now_v7().simple());
    fs::write(root.join("bridge-runtime.txt"), &suffix).unwrap();
    let runtime = RuntimeConfig::for_test(suffix, Some(root.join("runtime"))).unwrap();
    let config = TestDaemonConfig::new(
        runtime,
        root.join("vault.db"),
        InstallationToken::from_bytes([0x62; 32]),
    );
    let project = ProjectIdentity {
        project_id: Uuid::now_v7().to_string().parse().unwrap(),
        name: "Native Claude fixture".into(),
        github_repository_id: None,
        git_remote_fingerprint: None,
        monorepo_subdirectory: None,
    };
    config
        .seed_mcp_project(
            &project,
            &project_root,
            &[(
                HarnessId::ClaudeCode,
                HarnessAccessPolicy::SelectedProject {
                    project_id: project.project_id,
                    read_only: false,
                },
            )],
        )
        .unwrap();
    let hooks = context_relay_contextd::test_support::test_managed_memory_hooks(
        HarnessId::ClaudeCode,
        &wire_path(&fs::canonicalize(&bridge_path).unwrap()),
    )
    .unwrap();
    let manifest = root.join("manifest.json");
    fs::write(&manifest, serde_json::to_vec(&json!({
        "executable":claude, "sha256":CLAUDE_SHA256, "bridge":bridge_path,
        "bridgeSha256":format!("{:x}",Sha256::digest(fs::read(&bridge_path).unwrap())),
        "root":root,"project":project_root,"home":home,"config":config_root,"projectId":project.project_id,
        "toolNames":context_relay_protocol::MCP_TOOL_NAMES,
        "operations":(0..4).map(|_|Uuid::now_v7().to_string()).collect::<Vec<_>>(),
        "hooks":serde_json::from_str::<serde_json::Value>(&hooks[0].body_markdown).unwrap(),
    })).unwrap()).unwrap();
    let daemon = config.start().await.unwrap();
    let handle = daemon.handle();
    let owner = tokio::spawn(daemon.run());
    let stdout = root.join("stdout");
    let stderr = root.join("stderr");
    let mut command = Command::new(node);
    command
        .env_clear()
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/claude-mcp-session.mjs"))
        .arg(manifest)
        .current_dir(&root)
        .stdin(Stdio::piped())
        .stdout(fs::File::create(&stdout).unwrap())
        .stderr(fs::File::create(&stderr).unwrap());
    for name in ["SystemRoot", "WINDIR"] {
        command.env(name, env::var_os(name).unwrap());
    }
    let output_paths = [stdout.clone(), stderr.clone()];
    let outcome = tokio::task::spawn_blocking(move || {
        windows_process::run_in_owned_job_with_output_limit(
            &mut command,
            Duration::from_secs(180),
            &[&output_paths[0], &output_paths[1]],
            65536,
        )
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
    for path in [".claude/settings.json", ".claude.json"] {
        assert_eq!(
            fs::read(home.join(path)).unwrap(),
            b"{\"ambientCanary\":true}\n"
        );
    }
    // Reopen the encrypted vault in a new daemon instance and read the records
    // produced by the actual Claude client through the same dispatcher.
    let daemon = config.start().await.unwrap();
    let handle = daemon.handle();
    let owner = tokio::spawn(daemon.run());
    let local = LocalDaemon::for_test(config.runtime(), config.installation_token());
    let binding = McpBinding {
        harness: HarnessId::ClaudeCode,
        working_directory: wire_path(&project_root),
    };
    let memory = local.call(RecordId::new(Uuid::now_v7()).unwrap(), McpCallParams {
        binding: binding.clone(), name: "context_relay_search".into(),
        arguments: json!({"query":"Native Claude round trip", "scope":{"scope":"active_project"}, "limit":10}),
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
    assert_eq!(memory.unwrap()["memories"].as_array().unwrap().len(), 1);
    assert_eq!(tasks.unwrap()["tasks"].as_array().unwrap().len(), 1);
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
