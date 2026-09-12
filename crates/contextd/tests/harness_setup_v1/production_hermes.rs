//! Opt-in production composition. Only disposable native settings are changed;
//! the test-only bridge uses an isolated IPC target; no ordinary daemon runs.
use super::{RawClient, TOKEN};
use context_relay_contextd::{
    bridge_install::{AdjacentBridgeLocator, ProductionBridgeInstallEngine},
    test_support::TestDaemonConfig,
};
use context_relay_local_ipc::{InstallationToken, RuntimeConfig};
use context_relay_protocol::{
    ClientRole, EmptyParams, ErrorCode, HarnessExecutionAction, HarnessExecutionParams,
    HarnessExecutionPhase, HarnessParams, HarnessPreparationIdParams, HarnessPreparationPhase,
    HarnessPrepareParams, HarnessSetupState, HarnessSetupsParams, LocalRequest, LocalResult,
    OperationId, PlanId, PlanParams, ProjectIdentity,
};
use std::{
    env, fs,
    io::Read as _,
    path::PathBuf,
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};
use uuid::Uuid;

#[path = "../../../core/src/test_windows_process.rs"]
mod test_windows_process;

#[path = "production_hermes/bridge_roundtrip.rs"]
mod bridge_roundtrip;

#[test]
fn production_child_rejects_missing_gate_before_fixture_access() {
    use std::os::windows::process::CommandExt as _;
    let output = Command::new(env::current_exe().unwrap())
        .args([
            "production_hermes::production_hermes_child",
            "--exact",
            "--ignored",
            "--nocapture",
        ])
        .env_remove("CONTEXT_RELAY_PRODUCTION_HERMES_ROOT")
        .stdin(Stdio::null())
        .creation_flags(0x0800_0000)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("only the contained parent may start this fixture")
    );
}

#[test]
#[ignore = "explicit installed Hermes source; isolated production daemon, profile, vault and native settings"]
fn installed_production_hermes_prepare_save_restart_reapply_undo() {
    let source = fs::canonicalize(
        env::var_os("CONTEXT_RELAY_HERMES_METADATA_EXE")
            .expect("select an installed Hermes launcher explicitly"),
    )
    .unwrap();
    assert_eq!(
        source
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_ascii_lowercase(),
        "hermes.exe"
    );
    let fixture = tempfile::Builder::new()
        .prefix("context-relay-production-hermes-")
        .tempdir()
        .unwrap();
    let root = fs::canonicalize(fixture.path()).unwrap();
    let home = root.join("profile 專案 O'Brien");
    fs::create_dir(&home).unwrap();
    fs::write(
        root.join("fixture-owner"),
        b"disposable production qualification\n",
    )
    .unwrap();
    let windows = PathBuf::from(env::var_os("SystemRoot").expect("Windows system root"));
    let path = env::join_paths([
        source.parent().unwrap().to_path_buf(),
        windows.join("System32"),
    ])
    .unwrap();
    let mut command = Command::new(env::current_exe().unwrap());
    command
        .args([
            "production_hermes::production_hermes_child",
            "--exact",
            "--ignored",
            "--nocapture",
        ])
        .env("CONTEXT_RELAY_PRODUCTION_HERMES_ROOT", &root)
        .env("CONTEXT_RELAY_HERMES_METADATA_EXE", &source)
        .env("HERMES_HOME", &home)
        .env("PATH", path)
        .env_remove("PYTHONHOME")
        .env_remove("PYTHONPATH")
        .stdin(Stdio::piped());
    let status = test_windows_process::run_in_owned_job(&mut command, Duration::from_secs(3600))
        .expect("whole production qualification deadline");
    assert!(
        status.success(),
        "isolated production qualification failed: {status}"
    );
}

#[tokio::test]
#[ignore = "child of installed_production_hermes_prepare_save_restart_reapply_undo only"]
async fn production_hermes_child() {
    // The parent must own the process tree before any fixture or daemon work.
    let mut gate = Vec::new();
    std::io::stdin().read_to_end(&mut gate).unwrap();
    assert_eq!(
        gate, b"run",
        "only the contained parent may start this fixture"
    );
    let root = fs::canonicalize(
        env::var_os("CONTEXT_RELAY_PRODUCTION_HERMES_ROOT").expect("disposable fixture root"),
    )
    .unwrap();
    assert!(
        root.file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("context-relay-production-hermes-")
    );
    assert_eq!(
        fs::read(root.join("fixture-owner")).unwrap(),
        b"disposable production qualification\n"
    );
    let home = root.join("profile 專案 O'Brien");
    assert_eq!(
        fs::canonicalize(env::var_os("HERMES_HOME").expect("isolated profile")).unwrap(),
        home
    );
    let project_root = root.join("project 專案 O'Brien");
    fs::create_dir(&project_root).unwrap();
    fs::create_dir(home.join("memories")).unwrap();
    let original_config = b"# keep this comment\nmodel: fixture\nmemory:\n  memory_enabled: true\n  user_profile_enabled: true\n";
    fs::write(home.join("config.yaml"), original_config).unwrap();
    fs::write(home.join("memories/MEMORY.md"), b"native memory canary\n").unwrap();
    fs::write(home.join("memories/USER.md"), b"native user canary\n").unwrap();
    fs::write(home.join(".env"), b"TOKEN=synthetic-canary-only\n").unwrap();
    let bin = root.join("fixture bin");
    fs::create_dir(&bin).unwrap();
    fs::write(
        bin.join("contextd.exe"),
        b"fixture locator only; never execute",
    )
    .unwrap();
    let bridge_path = AdjacentBridgeLocator::beside(bin.join("contextd.exe"))
        .bridge_path()
        .unwrap();
    let bridge_fixture = PathBuf::from(
        env::var_os("CONTEXT_RELAY_TEST_MCP_FIXTURE_EXE")
            .expect("explicit test-only bridge example"),
    );
    fs::copy(&bridge_fixture, &bridge_path).unwrap();
    let _bridge_image = bridge_roundtrip::hold_fixture_image(&bridge_path);
    bridge_roundtrip::identify_fixture(&bridge_path).await;
    context_relay_core::mcp::install::attest_bridge_executable(&bridge_path).unwrap();
    let suffix = format!("hermes-native-{}", Uuid::now_v7().simple());
    fs::write(bin.join("bridge-runtime.txt"), &suffix).unwrap();
    let runtime = RuntimeConfig::for_test(suffix, Some(bin.join("runtime"))).unwrap();
    let config = TestDaemonConfig::new(
        runtime.clone(),
        root.join("vault.db"),
        InstallationToken::from_bytes(TOKEN),
    )
    .with_bridge_install_engine(Arc::new(
        ProductionBridgeInstallEngine::with_daemon_executable(bin.join("contextd.exe")),
    ));
    let project = ProjectIdentity {
        project_id: Uuid::now_v7().to_string().parse().unwrap(),
        name: "Production qualification 專案".into(),
        github_repository_id: None,
        git_remote_fingerprint: None,
        monorepo_subdirectory: None,
    };
    config
        .seed_mcp_project(&project, &project_root, &[])
        .unwrap();
    let daemon = config.start().await.unwrap();
    let handle = daemon.handle();
    let run = tokio::spawn(daemon.run());
    let remembered =
        bridge_roundtrip::roundtrip(&bridge_path, &project_root, &project, None, None).await;
    println!("Isolated Hermes bridge preflight passed before runtime preparation");
    let mut client = RawClient::connect(&runtime, ClientRole::Desktop).await;
    let selection = HarnessParams {
        harness: context_relay_protocol::HarnessId::Hermes,
        project_id: Some(project.project_id),
        hermes_profile: Some("default".into()),
    };
    let LocalResult::Probe { report } = client
        .call(LocalRequest::HarnessProbe(selection.clone()))
        .await
        .unwrap()
    else {
        panic!("expected production probe")
    };
    assert_eq!(report.harness_version.as_deref(), Some("0.17.0"));
    assert!(
        report
            .policy_conflicts
            .iter()
            .any(|value| value == "python_runtime_preparation_required")
    );
    println!("Production discovery passed; beginning owned preparation");
    let preparation = HarnessPrepareParams {
        operation_id: OperationId::new(Uuid::now_v7()).unwrap(),
        selection,
    };
    tokio::time::timeout(
        Duration::from_secs(3),
        client.call(LocalRequest::HarnessPrepare(preparation.clone())),
    )
    .await
    .unwrap()
    .unwrap();
    let began = Instant::now();
    let mut last_phase = None;
    loop {
        assert!(
            began.elapsed() < Duration::from_secs(1800),
            "preparation deadline"
        );
        let LocalResult::HarnessPreparation { status } = tokio::time::timeout(
            Duration::from_secs(3),
            client.call(LocalRequest::HarnessPreparationStatus(
                HarnessPreparationIdParams {
                    operation_id: preparation.operation_id,
                },
            )),
        )
        .await
        .unwrap()
        .unwrap() else {
            panic!("expected preparation")
        };
        if last_phase != Some(status.phase) {
            println!(
                "Preparation {:?}: {} files / {} bytes at {:?}",
                status.phase,
                status.completed_files,
                status.completed_bytes,
                began.elapsed()
            );
            last_phase = Some(status.phase);
        }
        assert!(
            status.error.is_none(),
            "production preparation failed: {:?}",
            status.error
        );
        if status.phase == HarnessPreparationPhase::Ready {
            break;
        }
        assert_ne!(status.phase, HarnessPreparationPhase::Canceled);
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let plan = loop {
        match client
            .call(LocalRequest::HarnessPreparedPreview(preparation.clone()))
            .await
        {
            Ok(LocalResult::Plan { plan }) => break plan,
            Err(error)
                if matches!(error.code, ErrorCode::Timeout | ErrorCode::Busy)
                    && began.elapsed() < Duration::from_secs(2100) =>
            {
                println!(
                    "Prepared review not yet acknowledged; explicitly checking the same operation"
                );
            }
            other => panic!("prepared review: {other:?}"),
        }
    };
    assert_eq!(fs::read(home.join("config.yaml")).unwrap(), original_config);
    assert_eq!(
        fs::read_dir(&project_root).unwrap().count(),
        0,
        "preview must not write project settings"
    );
    println!("Production prepared review sealed: {}", plan.plan_id);
    tracked(
        &mut client,
        plan.plan_id,
        HarnessExecutionAction::Apply,
        HarnessSetupState::Applied,
    )
    .await;
    let saved_config = fs::read_to_string(home.join("config.yaml")).unwrap();
    bridge_roundtrip::roundtrip(
        &bridge_path,
        &project_root,
        &project,
        Some(&remembered),
        Some(&saved_config),
    )
    .await;
    println!("Saved Hermes settings and project context passed the bridge round trip");
    assert!(saved_config.contains("context-relay") && saved_config.contains("context-mcp.exe"));
    assert!(
        saved_config.contains("memory_enabled: false")
            && saved_config.contains("user_profile_enabled: false")
    );
    drop(client);
    assert_eq!(
        handle.shutdown().await,
        context_relay_contextd::DaemonState::Stopped
    );
    run.await.unwrap().unwrap();
    println!("Production save committed; reopening the daemon and vault");
    let daemon = config.start().await.unwrap();
    let handle = daemon.handle();
    let run = tokio::spawn(daemon.run());
    let restarted_config = fs::read_to_string(home.join("config.yaml")).unwrap();
    bridge_roundtrip::roundtrip(
        &bridge_path,
        &project_root,
        &project,
        Some(&remembered),
        Some(&restarted_config),
    )
    .await;
    println!("The restarted daemon returned the same saved context through the bridge");
    let mut client = RawClient::connect(&runtime, ClientRole::Desktop).await;
    assert!(matches!(
        client
            .call(LocalRequest::HarnessExecutionCurrent(EmptyParams {}))
            .await
            .unwrap(),
        LocalResult::HarnessExecutionCurrent { status: None }
    ));
    let LocalResult::HarnessSetups { page } = client
        .call(LocalRequest::HarnessSetupsList(HarnessSetupsParams {
            after: None,
        }))
        .await
        .unwrap()
    else {
        panic!("expected persisted history")
    };
    assert!(page.setups.iter().any(|entry| entry.plan_id == plan.plan_id && entry.state == HarnessSetupState::Applied));
    tracked(
        &mut client,
        plan.plan_id,
        HarnessExecutionAction::Apply,
        HarnessSetupState::Applied,
    )
    .await;
    assert_eq!(
        fs::read_to_string(home.join("config.yaml")).unwrap(),
        saved_config
    );
    tracked(
        &mut client,
        plan.plan_id,
        HarnessExecutionAction::Rollback,
        HarnessSetupState::RolledBack,
    )
    .await;
    assert_eq!(fs::read(home.join("config.yaml")).unwrap(), original_config);
    assert_eq!(
        fs::read(home.join("memories/MEMORY.md")).unwrap(),
        b"native memory canary\n"
    );
    assert_eq!(
        fs::read(home.join("memories/USER.md")).unwrap(),
        b"native user canary\n"
    );
    assert_eq!(
        fs::read(home.join(".env")).unwrap(),
        b"TOKEN=synthetic-canary-only\n"
    );
    drop(client);
    assert_eq!(
        handle.shutdown().await,
        context_relay_contextd::DaemonState::Stopped
    );
    run.await.unwrap().unwrap();
    println!(
        "Production preparation, Save, daemon restart, reapply and Undo passed at {:?}",
        began.elapsed()
    );
}

async fn tracked(
    client: &mut RawClient,
    plan_id: PlanId,
    action: HarnessExecutionAction,
    expected: HarnessSetupState,
) {
    let params = HarnessExecutionParams { plan_id, action };
    let began = Instant::now();
    tokio::time::timeout(
        Duration::from_secs(3),
        client.call(LocalRequest::HarnessExecutionStart(params.clone())),
    )
    .await
    .unwrap()
    .unwrap();
    let mut last_phase = None;
    loop {
        assert!(
            began.elapsed() < Duration::from_secs(1800),
            "execution deadline"
        );
        let LocalResult::HarnessExecution { status } = tokio::time::timeout(
            Duration::from_secs(3),
            client.call(LocalRequest::HarnessExecutionStatus(params.clone())),
        )
        .await
        .unwrap()
        .unwrap() else {
            panic!("expected execution status")
        };
        if last_phase != Some(status.phase) {
            println!(
                "Production {action:?}: {:?} at {:?}",
                status.phase,
                began.elapsed()
            );
            last_phase = Some(status.phase);
        }
        if status.phase == HarnessExecutionPhase::Finished {
            assert!(
                status.error.is_none(),
                "production execution failed: {:?}",
                status.error
            );
            break;
        }
        assert!(matches!(
            status.phase,
            HarnessExecutionPhase::Queued | HarnessExecutionPhase::Running
        ));
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let LocalResult::HarnessSetup { setup } = client
        .call(LocalRequest::HarnessSetupGet(PlanParams { plan_id }))
        .await
        .unwrap()
    else {
        panic!("expected authoritative setup")
    };
    assert_eq!(setup.state, expected);
}
