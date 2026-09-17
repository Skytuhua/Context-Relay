#![cfg(all(feature = "test-support", windows))]

use context_relay_contextd::{DaemonState, test_support::TestDaemonConfig};
use context_relay_core::hermes::python_runtime;
use context_relay_local_ipc::{InstallationToken, RuntimeConfig};
use context_relay_protocol::{HarnessAccessPolicy, HarnessId, ProjectIdentity};
use serde_json::json;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use uuid::Uuid;

#[path = "fixtures/bridge_image.rs"]
mod bridge_image;

#[test]
#[ignore = "requires an explicit Node executable; bounded-output process containment canary"]
fn native_client_output_limit_stops_a_running_writer() {
    let node = env::var_os("CONTEXT_RELAY_TEST_NODE_EXE").expect("explicit Node");
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("output");
    let mut command = Command::new(node);
    command.args(["-e", "const fs=require('fs'); if(fs.readFileSync(0,'utf8')!=='run')process.exit(1); setInterval(()=>fs.writeSync(1,'x'.repeat(4096)),1);"])
        .env_clear().stdin(Stdio::piped()).stdout(fs::File::create(&path).unwrap()).stderr(Stdio::null());
    for name in ["SystemRoot", "WINDIR"] {
        command.env(name, env::var_os(name).unwrap());
    }
    let result = windows_process::run_in_owned_job_with_output_limit(
        &mut command,
        Duration::from_secs(5),
        &[&path],
        65536,
    );
    assert_eq!(result, Err("Contained fixture exceeded output limit"));
    std::thread::sleep(Duration::from_millis(100));
    let size = fs::metadata(&path).unwrap().len();
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(
        fs::metadata(path).unwrap().len(),
        size,
        "writer survived job cleanup"
    );
}
#[path = "../../core/src/test_windows_process.rs"]
mod windows_process;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "explicit installed Hermes metadata source and test-only bridge; copied runtime, synthetic profile/IPC"]
async fn actual_hermes_client_discovers_and_uses_the_production_bridge() {
    run_native_fixture(false).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "explicit installed Hermes metadata source and test-only bridge; copied CLI, loopback model, synthetic profile/IPC"]
async fn actual_hermes_cli_conversation_uses_the_production_bridge() {
    run_native_fixture(true).await;
}

async fn run_native_fixture(model_session: bool) {
    use std::io::Read as _;
    if env::var_os("CONTEXT_RELAY_NATIVE_HERMES_CHILD").is_none() {
        let mut child = Command::new(env::current_exe().unwrap());
        child
            .args([
                if model_session {
                    "actual_hermes_cli_conversation_uses_the_production_bridge"
                } else {
                    "actual_hermes_client_discovers_and_uses_the_production_bridge"
                },
                "--exact",
                "--ignored",
                "--nocapture",
            ])
            .env("CONTEXT_RELAY_NATIVE_HERMES_CHILD", "1")
            .stdin(Stdio::piped());
        assert!(
            windows_process::run_in_owned_job(&mut child, Duration::from_secs(1800))
                .unwrap()
                .success()
        );
        return;
    }
    let mut gate = Vec::new();
    std::io::stdin().read_to_end(&mut gate).unwrap();
    assert_eq!(
        gate, b"run",
        "only the contained parent may start this fixture"
    );
    let source = PathBuf::from(
        env::var_os("CONTEXT_RELAY_HERMES_METADATA_EXE").expect("explicit Hermes source"),
    );
    let bridge = PathBuf::from(
        env::var_os("CONTEXT_RELAY_TEST_MCP_FIXTURE_EXE").expect("explicit test-only bridge"),
    );
    let temp = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(temp.path())
        .unwrap()
        .join("Hermes client 專案 O'Brien");
    fs::create_dir(&root).unwrap();
    let store = root.join("retained");
    fs::create_dir(&store).unwrap();
    println!("Passively capturing the explicitly selected Hermes runtime");
    let started = Instant::now();
    let captured = python_runtime::capture(&source, &store).unwrap();
    println!("Runtime capture verified at {:?}", started.elapsed());
    let retained = captured.retain().unwrap();
    println!("Runtime retained at {:?}", started.elapsed());
    let runtime = retained.lock().unwrap();
    println!(
        "Verified and locked {} runtime files at {:?}",
        runtime.manifest().files.len(),
        started.elapsed()
    );
    let home = root.join("home");
    let project_root = root.join("project");
    fs::create_dir(&home).unwrap();
    fs::create_dir(&project_root).unwrap();
    let bridge_path = root.join("fixture bridge.exe");
    fs::copy(bridge, &bridge_path).unwrap();
    let _bridge_image = bridge_image::hold_fixture_image(&bridge_path);
    bridge_image::identify_fixture(&bridge_path).await;
    let suffix = format!("hermes-native-{}", Uuid::now_v7().simple());
    fs::write(root.join("bridge-runtime.txt"), &suffix).unwrap();
    let ipc = RuntimeConfig::for_test(suffix, Some(root.join("runtime"))).unwrap();
    let config = TestDaemonConfig::new(
        ipc,
        root.join("vault.db"),
        InstallationToken::from_bytes([0x5a; 32]),
    );
    let project = ProjectIdentity {
        project_id: Uuid::now_v7().to_string().parse().unwrap(),
        name: "Actual Hermes client".into(),
        github_repository_id: None,
        git_remote_fingerprint: None,
        monorepo_subdirectory: None,
    };
    config
        .seed_mcp_project(
            &project,
            &project_root,
            &[(
                HarnessId::Hermes,
                HarnessAccessPolicy::SelectedProject {
                    project_id: project.project_id,
                    read_only: false,
                },
            )],
        )
        .unwrap();
    let settings = serde_yaml_ng::to_string(&json!({"mcp_servers":{"context-relay":{
        "command":bridge_path, "args":["--harness","hermes"], "enabled":true
    }}}))
    .unwrap();
    fs::write(home.join("config.yaml"), &settings).unwrap();
    fs::write(home.join(".env"), b"TOKEN=synthetic-canary-only\n").unwrap();
    let manifest = root.join("manifest.json");
    fs::write(&manifest, serde_json::to_vec(&json!({
        "runtime":runtime.root(), "home":home, "project":project_root, "projectId":project.project_id,
        "modelSession":model_session,
            "toolNames":context_relay_protocol::MCP_TOOL_NAMES, "operations":(0..3).map(|_|Uuid::now_v7().to_string()).collect::<Vec<_>>()
    })).unwrap()).unwrap();
    let daemon = config.start().await.unwrap();
    let handle = daemon.handle();
    let owner = tokio::spawn(daemon.run());
    let stdout = root.join("stdout");
    let stderr = root.join("stderr");
    let mut command = Command::new(runtime.root().join("python/python.exe"));
    command
        .args(["-I", "-S", "-B"])
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/hermes-mcp-client.py"))
        .arg(manifest)
        .current_dir(&project_root)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(fs::File::create(&stdout).unwrap())
        .stderr(fs::File::create(&stderr).unwrap());
    let system = PathBuf::from(env::var_os("SystemRoot").unwrap());
    command
        .env("SystemRoot", &system)
        .env("WINDIR", &system)
        .env("PATH", system.join("System32"))
        .env("COMSPEC", system.join("System32/cmd.exe"))
        .env("PATHEXT", ".COM;.EXE;.BAT;.CMD");
    for name in [
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMDATA",
        "TEMP",
        "TMP",
        "HERMES_HOME",
        "XDG_CONFIG_HOME",
        "XDG_CACHE_HOME",
        "XDG_DATA_HOME",
    ] {
        command.env(name, &home);
    }
    let output_paths = [stdout.clone(), stderr.clone()];
    let outcome = tokio::task::spawn_blocking(move || {
        let result = windows_process::run_in_owned_job_with_output_limit(
            &mut command,
            Duration::from_secs(90),
            &[&output_paths[0], &output_paths[1]],
            65536,
        );
        (result, runtime)
    })
    .await;
    assert_eq!(handle.shutdown().await, DaemonState::Stopped);
    assert_eq!(owner.await.unwrap(), Ok(()));
    let (result, runtime) = outcome.unwrap();
    assert!(
        fs::metadata(&stdout).unwrap().len() < 65536
            && fs::metadata(&stderr).unwrap().len() < 65536
    );
    assert!(
        matches!(result, Ok(status) if status.success()),
        "stdout: {}\nstderr: {}",
        fs::read_to_string(&stdout).unwrap(),
        fs::read_to_string(&stderr).unwrap()
    );
    runtime.verify().unwrap();
    assert_eq!(
        fs::read_to_string(home.join("config.yaml")).unwrap(),
        settings
    );
    assert_eq!(
        fs::read(home.join(".env")).unwrap(),
        b"TOKEN=synthetic-canary-only\n"
    );
    println!("{}", fs::read_to_string(stdout).unwrap());
    println!(
        "Actual Hermes MCP client round trip passed at {:?}",
        started.elapsed()
    );
}
