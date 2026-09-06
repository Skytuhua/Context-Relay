use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use context_relay_contextd::{
    bridge_install::{AdjacentBridgeLocator, BridgeInstallEngine},
    test_support::{TestDaemonConfig, TestNativeMemoryProbe, TestWorkerGate},
};
use context_relay_core::{
    native_memory::{
        NativeMemoryDocumentKind, NativeMemoryLimits, NativeMemoryRegistration, NativeMemorySource,
    },
    setup::BridgeLocator,
    vault::{SetupPlanAction, SetupPlanLifecycle, SetupPlanWrite, Vault},
};
use context_relay_local_ipc::{
    AuthAcceptedV1, AuthTranscriptV1, ConnectedStream, InstallationToken, RuntimeConfig,
    ServerHelloV1, connect, create_proof, read_json, write_json,
};
use context_relay_protocol::{
    ApprovalClass, CancelParams, CapabilityLevel, ClientError, ClientRole, DaemonInstanceNonce,
    DeviceId, ErrorCode, HarnessId, HarnessParams, HelloParams, InstallationMethod, JsonRpcErrorV1,
    JsonRpcRequestV1, JsonRpcSuccessV1, JsonRpcVersion, LocalRequest, LocalResult, NativePlatform,
    PlanId, PlanParams, ProbeReport, RecordId, SetupPlan, Sha256Digest, WireNativeValue,
};
use uuid::Uuid;

const TOKEN: [u8; 32] = [0x5a; 32];
const PLAN: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07398f";
const ROLLBACK_PLAN: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073990";

#[cfg(any(windows, target_os = "macos"))]
#[tokio::test]
async fn project_registration_is_desktop_only_and_keeps_identity_and_path_after_restart() {
    let engine = Arc::new(RecordingEngine::default());
    let fixture = Fixture::start("project-register", engine.clone(), None).await;
    let root = unique_temp_path("project-folder-專案");
    std::fs::create_dir_all(&root).unwrap();
    let path = native_folder(&root);
    let project = context_relay_protocol::ProjectIdentity {
        project_id: PLAN.parse().unwrap(),
        github_repository_id: None,
        git_remote_fingerprint: None,
        monorepo_subdirectory: None,
        name: "Research".into(),
    };
    let request = LocalRequest::ProjectRegister(context_relay_protocol::ProjectRegisterParams {
        project: project.clone(),
        path: path.clone(),
    });
    let mut installer = RawClient::connect(&fixture.runtime, ClientRole::Installer).await;
    assert_eq!(
        installer.call(request.clone()).await.unwrap_err().code,
        ErrorCode::ScopeDenied
    );
    let mut client = RawClient::connect(&fixture.runtime, ClientRole::Desktop).await;
    let missing = LocalRequest::ProjectRegister(context_relay_protocol::ProjectRegisterParams {
        project: project.clone(),
        path: native_folder(&root.join("does-not-exist")),
    });
    assert_eq!(
        client.call(missing).await.unwrap_err().code,
        ErrorCode::InvalidRequest
    );
    assert!(
        matches!(client.call(LocalRequest::ProjectsList(context_relay_protocol::EmptyParams {})).await.unwrap(), LocalResult::Projects { projects } if projects.is_empty())
    );
    assert_eq!(
        client.call(request.clone()).await.unwrap(),
        LocalResult::Empty
    );
    assert_eq!(client.call(request).await.unwrap(), LocalResult::Empty);
    let config = fixture.stop().await;
    config
        .with_vault(|vault| {
            assert_eq!(vault.projects()?, vec![project.clone()]);
            assert_eq!(
                vault.path(&project.project_id.to_string())?,
                Some(path.clone())
            );
            Ok(())
        })
        .unwrap();
    let fixture = Fixture::from_config(config, engine).await;
    let mut client = RawClient::connect(&fixture.runtime, ClientRole::Desktop).await;
    assert!(
        matches!(client.call(LocalRequest::ProjectsList(context_relay_protocol::EmptyParams {})).await.unwrap(), LocalResult::Projects { projects } if projects == vec![project])
    );
    fixture.stop().await;
}

#[cfg(any(windows, target_os = "macos"))]
fn native_folder(path: &Path) -> WireNativeValue {
    #[cfg(target_os = "macos")]
    use std::os::unix::ffi::OsStrExt as _;
    #[cfg(windows)]
    use std::os::windows::ffi::OsStrExt as _;
    WireNativeValue {
        #[cfg(windows)]
        platform: NativePlatform::Windows,
        #[cfg(target_os = "macos")]
        platform: NativePlatform::Macos,
        #[cfg(windows)]
        bytes: path
            .as_os_str()
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect(),
        #[cfg(target_os = "macos")]
        bytes: path.as_os_str().as_bytes().to_vec(),
        display: Some(path.display().to_string()),
    }
}

#[derive(Default)]
struct RecordingEngine {
    reconciles: AtomicUsize,
    probes: Mutex<Vec<HarnessParams>>,
    previews: Mutex<Vec<(HarnessId, Option<String>)>>,
    applied: Mutex<BTreeSet<PlanId>>,
    rolled_back: Mutex<BTreeSet<PlanId>>,
    writes: AtomicUsize,
    bridge_launches: AtomicUsize,
    fail_digest: Mutex<bool>,
    fail_reconcile: bool,
    reconcile_gate: Option<Arc<(Mutex<bool>, Condvar)>>,
}

struct RegisteringEngine {
    source: NativeMemorySource,
}

impl BridgeInstallEngine for RegisteringEngine {
    fn reconcile_after_native_recovery(
        &self,
        _vault: &mut Vault,
        _vault_path: &Path,
        _device_id: DeviceId,
    ) -> Result<(), ClientError> {
        Ok(())
    }

    fn preview(
        &self,
        _vault: &mut Vault,
        _vault_path: &Path,
        _device_id: DeviceId,
        params: HarnessParams,
    ) -> Result<SetupPlan, ClientError> {
        let mut plan = plan(params.harness);
        plan.harness_profile = params.hermes_profile;
        Ok(plan)
    }

    fn apply(
        &self,
        vault: &mut Vault,
        _vault_path: &Path,
        _device_id: DeviceId,
        params: PlanParams,
    ) -> Result<(), ClientError> {
        let approval_hash = Sha256Digest([0x31; 32]);
        let payload = b"contextd native memory registration fixture";
        vault
            .put_setup_plan(SetupPlanWrite {
                plan_id: &params.plan_id,
                schema_version: 2,
                approval_version: 2,
                approval_hash: &approval_hash,
                payload,
                created_ms: 10,
                expires_ms: 1_000_000,
            })
            .and_then(|()| {
                vault
                    .claim_setup_plan(&params.plan_id, SetupPlanAction::Apply, 11)
                    .map(|_| ())
            })
            .and_then(|()| {
                vault.finish_setup_plan_with_native_memory(
                    &params.plan_id,
                    SetupPlanLifecycle::Applied,
                    &[NativeMemoryRegistration {
                        source: self.source.clone(),
                        last_applied_digest: None,
                    }],
                )
            })
            .map_err(|_| conflict("Native memory source could not be registered"))
    }

    fn rollback(
        &self,
        vault: &mut Vault,
        _vault_path: &Path,
        _device_id: DeviceId,
        params: PlanParams,
    ) -> Result<(), ClientError> {
        let inverse_id = PlanId::from_str(ROLLBACK_PLAN).unwrap();
        let approval_hash = Sha256Digest([0x32; 32]);
        let payload = b"contextd native memory rollback fixture";
        vault
            .claim_setup_plan_rollback(
                &params.plan_id,
                SetupPlanWrite {
                    plan_id: &inverse_id,
                    schema_version: 2,
                    approval_version: 2,
                    approval_hash: &approval_hash,
                    payload,
                    created_ms: 20,
                    expires_ms: 1_000_000,
                },
                21,
            )
            .and_then(|_| {
                vault.finish_setup_plan_rollback(
                    &params.plan_id,
                    &inverse_id,
                    SetupPlanLifecycle::RolledBack,
                    SetupPlanLifecycle::Applied,
                )
            })
            .map_err(|_| conflict("Native memory source could not be unregistered"))
    }
}

impl RecordingEngine {
    fn with_reconcile_gate(gate: Arc<(Mutex<bool>, Condvar)>) -> Self {
        Self {
            reconcile_gate: Some(gate),
            ..Self::default()
        }
    }

    fn with_reconcile_failure() -> Self {
        Self {
            fail_reconcile: true,
            ..Self::default()
        }
    }
}

impl BridgeInstallEngine for RecordingEngine {
    fn probe(
        &self,
        _vault: &Vault,
        _device_id: DeviceId,
        params: HarnessParams,
    ) -> Result<ProbeReport, ClientError> {
        self.probes.lock().unwrap().push(params.clone());
        let plan = plan(params.harness);
        Ok(ProbeReport {
            codex_saved_hook_approval: None,
            executable: Some(plan.executable_path),
            executable_sha256: Some(plan.executable_hash),
            harness_version: Some("0.144.6".to_owned()),
            installation_method: InstallationMethod::Manual,
            config_roots: vec![],
            active_profile: params.hermes_profile,
            policy_conflicts: vec![],
            capability: CapabilityLevel::ImportOnly,
        })
    }

    fn reconcile_after_native_recovery(
        &self,
        _vault: &mut Vault,
        _vault_path: &Path,
        _device_id: DeviceId,
    ) -> Result<(), ClientError> {
        self.reconciles.fetch_add(1, Ordering::SeqCst);
        if self.fail_reconcile {
            return Err(conflict("Bridge setup recovery is incomplete"));
        }
        if let Some(gate) = &self.reconcile_gate {
            let (released, wake) = &**gate;
            let mut released = released.lock().unwrap();
            while !*released {
                released = wake.wait(released).unwrap();
            }
        }
        Ok(())
    }

    fn preview(
        &self,
        _vault: &mut Vault,
        _vault_path: &Path,
        _device_id: DeviceId,
        params: HarnessParams,
    ) -> Result<SetupPlan, ClientError> {
        self.previews
            .lock()
            .unwrap()
            .push((params.harness, params.hermes_profile.clone()));
        let mut plan = plan(params.harness);
        plan.harness_profile = params.hermes_profile;
        Ok(plan)
    }

    fn apply(
        &self,
        _vault: &mut Vault,
        _vault_path: &Path,
        _device_id: DeviceId,
        params: PlanParams,
    ) -> Result<(), ClientError> {
        if *self.fail_digest.lock().unwrap() {
            return Err(conflict("Bridge executable changed"));
        }
        if self.applied.lock().unwrap().insert(params.plan_id) {
            self.writes.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    }

    fn rollback(
        &self,
        _vault: &mut Vault,
        _vault_path: &Path,
        _device_id: DeviceId,
        params: PlanParams,
    ) -> Result<(), ClientError> {
        if self.rolled_back.lock().unwrap().insert(params.plan_id) {
            self.writes.fetch_add(1, Ordering::SeqCst);
        }
        Ok(())
    }
}

#[tokio::test]
async fn discovery_returns_capability_through_authenticated_ipc_without_creating_a_plan() {
    let fixture = Fixture::start("probe", Arc::new(RecordingEngine::default()), None).await;
    let mut client = RawClient::connect(&fixture.runtime, ClientRole::Desktop).await;
    for harness in [HarnessId::ClaudeCode, HarnessId::Codex, HarnessId::Hermes] {
        let params = HarnessParams {
            harness,
            project_id: None,
            hermes_profile: (harness == HarnessId::Hermes).then(|| "coder".to_owned()),
        };
        let result = client
            .call(LocalRequest::HarnessProbe(params.clone()))
            .await
            .unwrap();
        assert!(matches!(result, LocalResult::Probe { report }
            if report.capability == CapabilityLevel::ImportOnly
                && report.harness_version.as_deref() == Some("0.144.6")
                && report.active_profile == params.hermes_profile));
        assert_eq!(fixture.engine.probes.lock().unwrap().last(), Some(&params));
    }
    assert!(fixture.engine.previews.lock().unwrap().is_empty());
    assert_eq!(fixture.engine.writes.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.engine.bridge_launches.load(Ordering::SeqCst), 0);
    fixture.stop().await;
}

#[tokio::test]
async fn preview_returns_plan_for_every_harness_and_decline_does_not_write_or_launch_bridge() {
    let fixture = Fixture::start("preview", Arc::new(RecordingEngine::default()), None).await;
    let mut client = RawClient::connect(&fixture.runtime, ClientRole::Desktop).await;

    for harness in [HarnessId::ClaudeCode, HarnessId::Codex, HarnessId::Hermes] {
        let hermes_profile = (harness == HarnessId::Hermes).then(|| "coder".to_owned());
        let result = client
            .call(LocalRequest::HarnessPreview(HarnessParams {
                harness,
                project_id: None,
                hermes_profile: hermes_profile.clone(),
            }))
            .await
            .unwrap();
        assert!(matches!(result, LocalResult::Plan { plan }
            if plan.harness == harness && plan.harness_profile == hermes_profile));
    }

    assert_eq!(fixture.engine.writes.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.engine.bridge_launches.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.engine.previews.lock().unwrap().len(), 3);
    assert_eq!(
        fixture.engine.previews.lock().unwrap().as_slice(),
        [
            (HarnessId::ClaudeCode, None),
            (HarnessId::Codex, None),
            (HarnessId::Hermes, Some("coder".to_owned())),
        ]
    );
    fixture.stop().await;
}

#[tokio::test]
async fn apply_and_rollback_use_only_plan_ids_and_replay_without_another_write() {
    let engine = Arc::new(RecordingEngine::default());
    let fixture = Fixture::start("replay", engine.clone(), None).await;
    let mut client = RawClient::connect(&fixture.runtime, ClientRole::Installer).await;
    let plan_id = PlanId::from_str(PLAN).unwrap();

    assert_eq!(
        client
            .call(LocalRequest::HarnessApply(PlanParams { plan_id }))
            .await
            .unwrap(),
        LocalResult::Empty
    );
    let config = fixture.stop().await;

    let fixture = Fixture::from_config(config, engine.clone()).await;
    let mut client = RawClient::connect(&fixture.runtime, ClientRole::Installer).await;
    assert_eq!(
        client
            .call(LocalRequest::HarnessApply(PlanParams { plan_id }))
            .await
            .unwrap(),
        LocalResult::Empty
    );
    assert_eq!(
        client
            .call(LocalRequest::HarnessRollback(PlanParams { plan_id }))
            .await
            .unwrap(),
        LocalResult::Empty
    );
    let config = fixture.stop().await;

    let fixture = Fixture::from_config(config, engine).await;
    let mut client = RawClient::connect(&fixture.runtime, ClientRole::Installer).await;
    assert_eq!(
        client
            .call(LocalRequest::HarnessRollback(PlanParams { plan_id }))
            .await
            .unwrap(),
        LocalResult::Empty
    );

    assert_eq!(fixture.engine.writes.load(Ordering::SeqCst), 2);
    fixture.stop().await;
}

#[tokio::test]
async fn digest_change_rejects_apply_without_write_and_repair_stays_unsupported() {
    let engine = Arc::new(RecordingEngine::default());
    *engine.fail_digest.lock().unwrap() = true;
    let fixture = Fixture::start("digest", engine, None).await;
    let mut client = RawClient::connect(&fixture.runtime, ClientRole::Desktop).await;
    let error = client
        .call(LocalRequest::HarnessApply(PlanParams {
            plan_id: PlanId::from_str(PLAN).unwrap(),
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
    assert_eq!(fixture.engine.writes.load(Ordering::SeqCst), 0);

    let error = client
        .call(LocalRequest::HarnessRepair(HarnessParams {
            harness: HarnessId::Codex,
            project_id: None,
            hermes_profile: None,
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::HarnessUnsupported);
    fixture.stop().await;
}

#[tokio::test]
async fn setup_is_authorized_before_routing_and_canceled_queue_items_do_not_execute() {
    let engine = Arc::new(RecordingEngine::default());
    let worker_gate = Arc::new(TestWorkerGate::new());
    let fixture = Fixture::start("ordered", engine, Some(worker_gate.clone())).await;
    let mut unauthorized = RawClient::connect(&fixture.runtime, ClientRole::McpBridge).await;
    let error = unauthorized
        .call(LocalRequest::HarnessPreview(HarnessParams {
            harness: HarnessId::Codex,
            project_id: None,
            hermes_profile: None,
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::ScopeDenied);
    assert!(fixture.engine.previews.lock().unwrap().is_empty());

    let mut first = RawClient::connect(&fixture.runtime, ClientRole::Desktop).await;
    let first_call = tokio::spawn(async move {
        first
            .call(LocalRequest::HarnessPreview(HarnessParams {
                harness: HarnessId::ClaudeCode,
                project_id: None,
                hermes_profile: None,
            }))
            .await
    });
    worker_gate.wait_until_entered().await;

    let queued_id = RecordId::new(Uuid::now_v7()).unwrap();
    let mut queued = RawClient::connect(&fixture.runtime, ClientRole::Desktop).await;
    let queued_call = tokio::spawn(async move {
        queued
            .call_with_id(
                queued_id,
                LocalRequest::HarnessPreview(HarnessParams {
                    harness: HarnessId::Hermes,
                    project_id: None,
                    hermes_profile: Some("default".to_owned()),
                }),
            )
            .await
    });
    worker_gate.wait_until_enqueued(2).await;
    let mut cancel = RawClient::connect(&fixture.runtime, ClientRole::Desktop).await;
    assert_eq!(
        cancel
            .call(LocalRequest::Cancel(CancelParams {
                request_id: queued_id,
            }))
            .await
            .unwrap(),
        LocalResult::Empty
    );
    worker_gate.release();

    assert!(first_call.await.unwrap().is_ok());
    assert_eq!(
        queued_call.await.unwrap().unwrap_err().code,
        ErrorCode::Canceled
    );
    assert_eq!(
        *fixture.engine.previews.lock().unwrap(),
        vec![(HarnessId::ClaudeCode, None)]
    );
    fixture.stop().await;
}

#[tokio::test]
async fn setup_reconciliation_finishes_after_native_recovery_and_before_endpoint_bind() {
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let engine = Arc::new(RecordingEngine::with_reconcile_gate(gate.clone()));
    let root = unique_temp_path("startup");
    let runtime =
        RuntimeConfig::for_test(format!("hs-{}", unique_token()), Some(root.clone())).unwrap();
    let config = TestDaemonConfig::new(
        runtime.clone(),
        root.join("vault.db"),
        InstallationToken::from_bytes(TOKEN),
    )
    .with_bridge_install_engine(engine.clone());

    let start = tokio::spawn(async move { config.start().await });
    while engine.reconciles.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }
    assert!(!matches!(
        tokio::time::timeout(std::time::Duration::from_millis(250), connect(&runtime)).await,
        Ok(Ok(_))
    ));
    let (released, wake) = &*gate;
    *released.lock().unwrap() = true;
    wake.notify_all();
    let daemon = start.await.unwrap().unwrap();
    assert_eq!(engine.reconciles.load(Ordering::SeqCst), 1);
    drop(daemon);
}

#[tokio::test]
async fn native_memory_supervisor_starts_after_reconciliation_and_joins_on_daemon_drop() {
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let engine = Arc::new(RecordingEngine::with_reconcile_gate(gate.clone()));
    let probe = Arc::new(TestNativeMemoryProbe::default());
    let root = unique_temp_path("native-memory-lifecycle");
    let runtime =
        RuntimeConfig::for_test(format!("hs-{}", unique_token()), Some(root.clone())).unwrap();
    let config = TestDaemonConfig::new(
        runtime,
        root.join("vault.db"),
        InstallationToken::from_bytes(TOKEN),
    )
    .with_bridge_install_engine(engine.clone())
    .with_native_memory_probe(probe.clone());

    let start = tokio::spawn(async move { config.start().await });
    while engine.reconciles.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }
    assert_eq!(probe.starts(), 0);

    let (released, wake) = &*gate;
    *released.lock().unwrap() = true;
    wake.notify_all();
    let daemon = start.await.unwrap().unwrap();
    probe.wait_until_started().await;
    assert_eq!(probe.starts(), 1);

    drop(daemon);
    assert_eq!(probe.stops(), 1);
}

#[tokio::test]
async fn incomplete_setup_reconciliation_prevents_bind_and_never_executes_a_plan() {
    let engine = Arc::new(RecordingEngine::with_reconcile_failure());
    let root = unique_temp_path("reconcile-failure");
    let runtime =
        RuntimeConfig::for_test(format!("hs-{}", unique_token()), Some(root.clone())).unwrap();
    let config = TestDaemonConfig::new(
        runtime.clone(),
        root.join("vault.db"),
        InstallationToken::from_bytes(TOKEN),
    )
    .with_bridge_install_engine(engine.clone());

    assert!(matches!(
        config.start().await,
        Err(context_relay_contextd::DaemonError::Startup)
    ));
    assert!(connect(&runtime).await.is_err());
    assert_eq!(engine.reconciles.load(Ordering::SeqCst), 1);
    assert_eq!(engine.writes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn failed_startup_never_launches_native_memory_supervision() {
    let engine = Arc::new(RecordingEngine::with_reconcile_failure());
    let probe = Arc::new(TestNativeMemoryProbe::default());
    let root = unique_temp_path("native-memory-startup-failure");
    let runtime =
        RuntimeConfig::for_test(format!("hs-{}", unique_token()), Some(root.clone())).unwrap();
    let config = TestDaemonConfig::new(
        runtime,
        root.join("vault.db"),
        InstallationToken::from_bytes(TOKEN),
    )
    .with_bridge_install_engine(engine)
    .with_native_memory_probe(probe.clone());

    assert!(matches!(
        config.start().await,
        Err(context_relay_contextd::DaemonError::Startup)
    ));
    assert_eq!(probe.starts(), 0);
    assert_eq!(probe.stops(), 0);
}

#[tokio::test]
async fn setup_apply_and_rollback_refresh_the_live_descriptor_set_without_watcher_leaks() {
    let root = unique_temp_path("live-native-registration");
    std::fs::create_dir_all(&root).unwrap();
    // CI temp directories contain 8.3 short components (RUNNER~1); persisted
    // source paths must be the canonical long form the production adapters
    // produce, so canonicalize after creation exactly as
    // std::fs::canonicalize reports it.
    let root = std::fs::canonicalize(&root).unwrap();
    let memory_path = root.join("memory.md");
    std::fs::write(&memory_path, b"registered while daemon runs\n").unwrap();
    #[cfg(unix)]
    use std::os::unix::ffi::OsStrExt as _;
    #[cfg(windows)]
    use std::os::windows::ffi::OsStrExt as _;
    let source = NativeMemorySource::new(
        HarnessId::Codex,
        "0.144.1",
        context_relay_protocol::ScopeRef::Global,
        NativeMemoryDocumentKind::Agent,
        WireNativeValue {
            // The wire platform must match the encoding below: UTF-8 bytes
            // on macOS, UTF-16LE units on Windows. The previous hardcoded
            // Macos platform paired with UTF-16 bytes failed validation
            // through the embedded NUL check.
            #[cfg(unix)]
            platform: NativePlatform::Macos,
            #[cfg(windows)]
            platform: NativePlatform::Windows,
            #[cfg(unix)]
            bytes: memory_path.as_os_str().as_bytes().to_vec(),
            #[cfg(windows)]
            bytes: memory_path
                .as_os_str()
                .encode_wide()
                .flat_map(u16::to_le_bytes)
                .collect(),
            display: Some(memory_path.display().to_string()),
        },
        NativeMemoryLimits {
            max_bytes: 4_096,
            max_characters: 4_096,
        },
        true,
    )
    .unwrap();
    let runtime =
        RuntimeConfig::for_test(format!("hs-{}", unique_token()), Some(root.join("runtime")))
            .unwrap();
    let config = TestDaemonConfig::new(
        runtime.clone(),
        root.join("vault.db"),
        InstallationToken::from_bytes(TOKEN),
    )
    .with_bridge_install_engine(Arc::new(RegisteringEngine {
        source: source.clone(),
    }));
    let probe = Arc::new(TestNativeMemoryProbe::default());
    let config = config.with_native_memory_probe(probe.clone());
    let daemon = config.start().await.unwrap();
    let handle = daemon.handle();
    let running = tokio::spawn(daemon.run());
    let mut client = RawClient::connect(&runtime, ClientRole::Installer).await;

    assert_eq!(
        client
            .call(LocalRequest::HarnessApply(PlanParams {
                plan_id: PlanId::from_str(PLAN).unwrap(),
            }))
            .await
            .unwrap(),
        LocalResult::Empty
    );
    for _ in 0..80 {
        if config.native_memory_candidates().unwrap().len() == 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    assert_eq!(config.native_memory_candidates().unwrap().len(), 1);

    assert_eq!(
        client
            .call(LocalRequest::HarnessRollback(PlanParams {
                plan_id: PlanId::from_str(PLAN).unwrap(),
            }))
            .await
            .unwrap(),
        LocalResult::Empty
    );
    assert!(config.native_memory_ledger(&source.id).unwrap().is_none());

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    std::fs::write(&memory_path, b"must not be watched after rollback\n").unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(2_000)).await;
    assert_eq!(config.native_memory_candidates().unwrap().len(), 1);
    assert_eq!(probe.starts(), 1);
    assert_eq!(
        handle.shutdown().await,
        context_relay_contextd::DaemonState::Stopped
    );
    running.await.unwrap().unwrap();
    assert_eq!(probe.stops(), 1);
}

#[test]
fn adjacent_locator_attests_the_platform_named_bridge_without_launching_it() {
    let root = unique_temp_path("locator");
    std::fs::create_dir_all(&root).unwrap();
    let daemon = root.join(if cfg!(windows) {
        "contextd.exe"
    } else {
        "contextd"
    });
    std::fs::write(&daemon, b"daemon").unwrap();
    let bridge = root.join(if cfg!(windows) {
        "context-relay-context-mcp.exe"
    } else {
        "context-relay-context-mcp"
    });
    let canary = root.join("launched");
    std::fs::write(
        &bridge,
        format!("#!/bin/sh\nprintf launched > '{}'\n", canary.display()),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::set_permissions(&bridge, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    let located = AdjacentBridgeLocator::beside(&daemon).locate().unwrap();

    assert_eq!(located.path, std::fs::canonicalize(&bridge).unwrap());
    assert!(!canary.exists());
}

struct Fixture {
    handle: context_relay_contextd::DaemonHandle,
    run: tokio::task::JoinHandle<Result<(), context_relay_contextd::DaemonError>>,
    runtime: RuntimeConfig,
    engine: Arc<RecordingEngine>,
    config: TestDaemonConfig,
}

impl Fixture {
    async fn start(
        label: &str,
        engine: Arc<RecordingEngine>,
        worker_gate: Option<Arc<TestWorkerGate>>,
    ) -> Self {
        let root = unique_temp_path(label);
        let runtime =
            RuntimeConfig::for_test(format!("hs-{}", unique_token()), Some(root.clone())).unwrap();
        let mut config = TestDaemonConfig::new(
            runtime.clone(),
            root.join("vault.db"),
            InstallationToken::from_bytes(TOKEN),
        )
        .with_bridge_install_engine(engine.clone());
        if let Some(worker_gate) = worker_gate {
            config = config.with_worker_gate(worker_gate);
        }
        Self::from_config(config, engine).await
    }

    async fn from_config(config: TestDaemonConfig, engine: Arc<RecordingEngine>) -> Self {
        let runtime = config.runtime();
        let daemon = config.start().await.unwrap();
        let handle = daemon.handle();
        let run = tokio::spawn(daemon.run());
        Self {
            handle,
            run,
            runtime,
            engine,
            config,
        }
    }

    async fn stop(self) -> TestDaemonConfig {
        assert_eq!(
            self.handle.shutdown().await,
            context_relay_contextd::DaemonState::Stopped
        );
        self.run.await.unwrap().unwrap();
        self.config
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
        let client_nonce = DaemonInstanceNonce::new([0x22; 32]);
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
        self.call_with_id(RecordId::new(Uuid::now_v7()).unwrap(), request)
            .await
    }

    async fn call_with_id(
        &mut self,
        id: RecordId,
        request: LocalRequest,
    ) -> Result<LocalResult, ClientError> {
        write_json(
            &mut self.stream,
            &JsonRpcRequestV1 {
                jsonrpc: JsonRpcVersion::V2,
                id,
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

fn plan(harness: HarnessId) -> SetupPlan {
    SetupPlan {
        plan_id: PlanId::from_str(PLAN).unwrap(),
        harness,
        harness_profile: (harness == HarnessId::Hermes).then(|| "default".to_owned()),
        adapter_version: 1,
        executable_path: native_text("/fixture/harness"),
        executable_hash: Sha256Digest([1; 32]),
        harness_version: "1.0.0".into(),
        target_scopes: vec![],
        expected_native_digests: vec![],
        semantic_changes: vec![],
        cli_operations: vec![],
        package_artifacts: vec![],
        permission_delta: context_relay_protocol::PermissionDelta {
            added: vec![],
            removed: vec![],
        },
        network_delta: context_relay_protocol::NetworkDelta {
            added: vec![],
            removed: vec![],
        },
        scanner_report_hash: Sha256Digest([2; 32]),
        rulesync_version: "bridge-preview-v1".into(),
        rulesync_hash: Sha256Digest([3; 32]),
        approval_class: ApprovalClass::Active,
        expires_at: u64::MAX,
        batch_hash: Sha256Digest([4; 32]),
    }
}

fn native_text(value: &str) -> WireNativeValue {
    WireNativeValue {
        platform: NativePlatform::Macos,
        bytes: value.as_bytes().to_vec(),
        display: Some(value.into()),
    }
}

fn conflict(message: &str) -> ClientError {
    ClientError {
        code: ErrorCode::Conflict,
        message: message.into(),
        field_path: None,
        retryable: false,
    }
}

fn unique_temp_path(label: &str) -> PathBuf {
    #[cfg(windows)]
    let root = std::env::temp_dir();
    #[cfg(not(windows))]
    let root = PathBuf::from("/private/tmp");
    root.join(format!("crhs-{label}-{}", unique_token()))
}

fn unique_token() -> String {
    // The random tail of a UUIDv7 carries per-call entropy; the leading
    // characters encode only the millisecond timestamp, which collides
    // across parallel tests. Runtime suffixes name per-user global
    // singletons on Windows, so they need the tail.
    let uuid = Uuid::now_v7().simple().to_string();
    uuid[uuid.len() - 12..].to_owned()
}
