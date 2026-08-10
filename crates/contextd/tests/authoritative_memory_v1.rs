#![cfg(any(windows, target_os = "macos"))]

use std::{
    fs,
    panic::AssertUnwindSafe,
    path::{Path, PathBuf},
    str::FromStr as _,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use context_relay_contextd::{
    bridge_install::BridgeInstallEngine,
    test_support::{TestCodexBridgeInstallEngine, TestDaemonConfig},
};
use context_relay_core::{
    codex::{CodexAdapter, CodexExecutableKind, CodexLayout},
    hermes::{HermesAdapter, HermesExecutableKind, HermesLayout, HermesMemoryKind, HermesProfile},
    mcp::install::{BridgeExecutable, attest_bridge_executable},
    native_memory::{
        NativeMemoryAdapter, NativeMemoryCapabilities, NativeMemoryDisable,
        NativeMemoryDocumentKind, NativeMemorySource, PRIMARY_MEMORY_INSTRUCTIONS,
    },
    native_transaction::{
        ApprovedInput, NativeTransactionPlan, SidecarBinding,
        engine::{BoundaryError, NoFault, RestrictedExecutor, RestrictedRun},
        filesystem::OsNativeTransactionFileSystem,
        open_plan,
    },
    setup::{
        BridgeExecutionError, BridgeInstallService, BridgeLocator, BridgePlanExecutor,
        HermesMemoryExportService, NativeEngineBridgePlanExecutor, NoBridgeCliExecutor,
        RegisteredProject,
    },
    vault::{
        BeforeImagePolicy, NativeSandboxIdentity, NativeTransactionStatus, SetupPlanLifecycle,
        Vault,
    },
};
use context_relay_local_ipc::{
    AuthAcceptedV1, AuthTranscriptV1, ConnectedStream, InstallationToken, RuntimeConfig,
    ServerHelloV1, connect, create_proof, read_json, write_json,
};
use context_relay_protocol::{
    CandidateListParams, CandidateReviewParams, ClientError, ClientRole, DaemonInstanceNonce,
    DeviceId, ErrorCode, HarnessAccessPolicy, HarnessId, HarnessParams, HelloParams,
    HybridLogicalClock, InstallationMethod, JsonRpcErrorV1, JsonRpcRequestV1, JsonRpcSuccessV1,
    JsonRpcVersion, LocalRequest, LocalResult, NativePlatform, OperationId, PlanParams, ProjectId,
    ProjectIdentity, RecordId, ScopeRef, SearchParams, SetupPlan, Sha256Digest, WireNativeValue,
};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

const TOKEN: [u8; 32] = [0x74; 32];
const PROJECT_ID: &str = "019fa3e0-1fa7-7662-b67d-f4c3d60b3202";
const DEVICE_ID: &str = "019fa3e0-1fa7-7662-b67d-f4c3d60b3203";
const MANAGED_EXPORT: &[u8] =
    b"<!-- context-relay:start -->\nowned memory\n<!-- context-relay:end -->\n";

#[tokio::test]
async fn applied_setup_keeps_primary_memory_and_task_contract_alive_without_a_desktop_client() {
    let fixture = AcceptanceFixture::supported("desktop-independent");
    let daemon = fixture.config.start().await.unwrap();
    let handle = daemon.handle();
    let owner = tokio::spawn(daemon.run());
    let mut desktop = RawClient::connect(&fixture.runtime, ClientRole::Desktop).await;

    let LocalResult::Plan { plan } = desktop
        .call(LocalRequest::HarnessPreview(HarnessParams {
            harness: HarnessId::Codex,
            project_id: Some(fixture.project.project_id),
            hermes_profile: None,
        }))
        .await
        .unwrap()
    else {
        panic!("frozen supported setup must return a plan")
    };
    assert_eq!(plan.harness_version, "0.144.1");
    fixture
        .config
        .with_vault(|vault| {
            let stored = vault.setup_plan(&plan.plan_id)?.unwrap();
            assert_eq!(stored.lifecycle, SetupPlanLifecycle::Previewed);
            let opened = open_plan(&stored.payload).unwrap();
            assert_eq!(&opened.plan.setup, plan.as_ref());
            assert_eq!(opened.plan.mutations.len(), 3);
            let targets = opened
                .plan
                .mutations
                .iter()
                .map(|mutation| wire_path_to_path(&mutation.target))
                .collect::<Vec<_>>();
            assert!(targets.contains(&fixture.config_path));
            assert!(targets.contains(&fixture.instruction_path));
            assert!(targets.iter().any(|path| path.ends_with("hooks.json")));
            assert_eq!(opened.plan.native_memory_registrations.len(), 2);
            assert!(
                opened
                    .plan
                    .native_memory_registrations
                    .iter()
                    .all(|registration| registration.last_applied_digest.is_none()
                        && fixture.sources.contains(&registration.source))
            );
            for source in &fixture.sources {
                assert!(vault.native_memory_ledger(&source.id)?.is_none());
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(
        desktop
            .call(LocalRequest::HarnessApply(PlanParams {
                plan_id: plan.plan_id,
            }))
            .await
            .unwrap(),
        LocalResult::Empty
    );
    fixture
        .config
        .with_vault(|vault| {
            assert_eq!(
                vault.setup_plan(&plan.plan_id)?.unwrap().lifecycle,
                SetupPlanLifecycle::Applied
            );
            let native = vault
                .native_transaction(&format!("bridge-setup-{}", plan.plan_id))?
                .unwrap();
            assert_eq!(native.plan_id, plan.plan_id);
            assert_eq!(native.status, NativeTransactionStatus::Committed);
            for source in &fixture.sources {
                assert_eq!(
                    vault.native_memory_ledger(&source.id)?.unwrap().source,
                    Some(source.clone())
                );
            }
            Ok(())
        })
        .unwrap();
    wait_for_previews(&fixture.config, &fixture.sources).await;
    assert!(
        fixture
            .config
            .native_memory_candidates()
            .unwrap()
            .is_empty()
    );
    assert_contract_files(&fixture);

    drop(desktop);
    let native_edit = "Task 14 acceptance remembers the desktop-independent watcher.\n";
    let changed_at = Instant::now();
    fs::write(&fixture.memory_path, native_edit).unwrap();
    tokio::time::sleep(Duration::from_millis(750)).await;
    wait_for_candidate_count(&fixture.config, 1).await;
    assert!(changed_at.elapsed() >= Duration::from_millis(750));

    let mut desktop = RawClient::connect(&fixture.runtime, ClientRole::Desktop).await;
    let LocalResult::Candidates { candidates } = desktop
        .call(LocalRequest::CandidatesList(CandidateListParams {
            project_id: None,
        }))
        .await
        .unwrap()
    else {
        panic!("candidate list must return candidates")
    };
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].proposed_memory.body_markdown, native_edit);
    let accepted = desktop
        .call(LocalRequest::CandidateReview(CandidateReviewParams {
            candidate_id: candidates[0].id,
            accepted: true,
            operation_id: operation_id(),
        }))
        .await
        .unwrap();
    assert!(matches!(accepted, LocalResult::Candidates { .. }));
    let LocalResult::Memories { memories } = desktop
        .call(LocalRequest::MemorySearch(SearchParams {
            query: "desktop-independent watcher".into(),
            project_id: None,
        }))
        .await
        .unwrap()
    else {
        panic!("accepted native memory must be searchable")
    };
    assert_eq!(memories.len(), 1);
    assert_eq!(memories[0].body_markdown, native_edit);

    drop(desktop);
    assert_contract_files(&fixture);
    assert_eq!(
        handle.shutdown().await,
        context_relay_contextd::DaemonState::Stopped
    );
    owner.await.unwrap().unwrap();
}

#[tokio::test]
async fn a_managed_self_export_completes_preview_without_creating_a_candidate() {
    let materialized = MaterializedHermes::new("self-export");
    let runtime = RuntimeConfig::for_test(
        format!("am-hermes-{}", unique_runtime_fragment()),
        Some(short_runtime_root()),
    )
    .unwrap();
    let config = TestDaemonConfig::new(
        runtime,
        materialized.root.join("vault.db"),
        InstallationToken::from_bytes(TOKEN),
    );
    let mut executor_adapter = materialized.adapter.clone();
    let (plan_id, source, intended) = config
        .with_vault(|vault| {
            let setup = HermesMemoryExportService::new(vault)
                .preview(
                    &materialized.adapter,
                    HermesMemoryKind::Agent,
                    "owned memory",
                    1_900_000_000_000,
                )
                .unwrap();
            let stored = vault.setup_plan(&setup.plan_id).unwrap().unwrap();
            let opened = open_plan(&stored.payload).unwrap();
            assert_eq!(opened.plan.mutations.len(), 1);
            assert_eq!(opened.plan.native_memory_registrations.len(), 1);
            let source = opened.plan.native_memory_registrations[0].source.clone();
            assert_eq!(source.document_kind, NativeMemoryDocumentKind::Agent);
            let intended = fs::read(wire_path_to_path(&source.path)).unwrap();
            assert_ne!(
                opened.plan.native_memory_registrations[0].last_applied_digest,
                Some(Sha256Digest(Sha256::digest(&intended).into()))
            );

            let crashed = std::panic::catch_unwind(AssertUnwindSafe(|| {
                let mut executor = CrashAfterHermesExport(HermesExportExecutor {
                    adapter: &mut executor_adapter,
                    lock_root: materialized.lock_root.clone(),
                });
                let _ = HermesMemoryExportService::new(vault).apply(
                    &setup.plan_id,
                    1_900_000_000_001,
                    &mut executor,
                );
            }));
            assert!(crashed.is_err());
            assert_eq!(
                vault.setup_plan(&setup.plan_id).unwrap().unwrap().lifecycle,
                SetupPlanLifecycle::Applying
            );
            assert!(vault.native_memory_ledger(&source.id).unwrap().is_none());
            let intended = fs::read(wire_path_to_path(&source.path)).unwrap();
            assert_eq!(
                opened.plan.native_memory_registrations[0].last_applied_digest,
                Some(Sha256Digest(Sha256::digest(&intended).into()))
            );
            Ok((setup.plan_id, source, intended))
        })
        .unwrap();
    config
        .with_vault(|vault| {
            BridgeInstallService::persisted(vault)
                .reconcile_after_native_recovery()
                .unwrap();
            Ok(())
        })
        .unwrap();
    let ledger = config.native_memory_ledger(&source.id).unwrap().unwrap();
    assert_eq!(ledger.source, Some(source.clone()));
    assert_eq!(
        ledger.last_applied_digest,
        Some(Sha256Digest(Sha256::digest(&intended).into()))
    );
    assert_eq!(
        config
            .with_vault(|vault| Ok(vault.setup_plan(&plan_id)?.unwrap().lifecycle))
            .unwrap(),
        SetupPlanLifecycle::Applied
    );

    let daemon = config.start().await.unwrap();
    let handle = daemon.handle();
    let owner = tokio::spawn(daemon.run());
    wait_for_previews(&config, std::slice::from_ref(&source)).await;
    tokio::time::sleep(Duration::from_millis(1_000)).await;

    assert!(config.native_memory_candidates().unwrap().is_empty());
    assert_eq!(fs::read(&materialized.memory_path).unwrap(), intended);
    assert!(
        config
            .native_memory_ledger(&source.id)
            .unwrap()
            .unwrap()
            .initial_preview_complete
    );

    let unmanaged = "User-authored Hermes memory outside the managed fence.\n";
    let mut edited = intended.clone();
    edited.extend_from_slice(unmanaged.as_bytes());
    fs::write(&materialized.memory_path, edited).unwrap();
    tokio::time::sleep(Duration::from_millis(750)).await;
    wait_for_candidate_count(&config, 1).await;
    let candidates = config.native_memory_candidates().unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].proposed_memory.body_markdown, unmanaged);
    assert!(
        !candidates[0]
            .proposed_memory
            .body_markdown
            .contains("context-relay:start")
    );
    assert!(
        !candidates[0]
            .proposed_memory
            .body_markdown
            .contains("owned memory")
    );
    assert_eq!(
        handle.shutdown().await,
        context_relay_contextd::DaemonState::Stopped
    );
    owner.await.unwrap().unwrap();
}

#[tokio::test]
async fn import_only_codex_setup_activates_exact_watchers_without_native_mutation() {
    let materialized = MaterializedCodex::new("watch-only-daemon", "0.145.0");
    let capabilities = materialized.capabilities();
    assert!(matches!(
        capabilities.disable,
        NativeMemoryDisable::WatchOnly
    ));
    for source in &capabilities.sources {
        fs::write(wire_path_to_path(&source.path), b"").unwrap();
    }
    let config_before = fs::read(&materialized.config_path).unwrap();
    let project = ProjectIdentity {
        project_id: ProjectId::from_str(PROJECT_ID).unwrap(),
        github_repository_id: None,
        git_remote_fingerprint: None,
        monorepo_subdirectory: None,
        name: "Task 14 watch-only daemon".into(),
    };
    let runtime = RuntimeConfig::for_test(
        format!("am-watch-{}", unique_runtime_fragment()),
        Some(short_runtime_root()),
    )
    .unwrap();
    let engine = Arc::new(WatchOnlyCodexSetupEngine {
        adapter: Mutex::new(materialized.adapter.clone()),
        project_id: project.project_id,
        project_root: materialized.project_root.clone(),
    });
    let config = TestDaemonConfig::new(
        runtime.clone(),
        materialized.root.join("vault.db"),
        InstallationToken::from_bytes(TOKEN),
    )
    .with_bridge_install_engine(engine);
    config
        .seed_mcp_project(
            &project,
            &materialized.project_root,
            &[(HarnessId::Codex, HarnessAccessPolicy::Default)],
        )
        .unwrap();

    let daemon = config.start().await.unwrap();
    let handle = daemon.handle();
    let owner = tokio::spawn(daemon.run());
    let mut installer = RawClient::connect(&runtime, ClientRole::Installer).await;
    let LocalResult::Plan { plan } = installer
        .call(LocalRequest::HarnessPreview(HarnessParams {
            harness: HarnessId::Codex,
            project_id: Some(project.project_id),
            hermes_profile: None,
        }))
        .await
        .unwrap()
    else {
        panic!("import-only Codex setup must return an exact registration plan")
    };
    assert_eq!(plan.harness_version, "0.145.0");
    assert_eq!(plan.rulesync_version, "native-memory-watch-only-v1");
    assert!(plan.cli_operations.is_empty());
    installer
        .call(LocalRequest::HarnessApply(PlanParams {
            plan_id: plan.plan_id,
        }))
        .await
        .unwrap();
    wait_for_previews(&config, &capabilities.sources).await;
    assert!(config.native_memory_candidates().unwrap().is_empty());
    assert_eq!(fs::read(&materialized.config_path).unwrap(), config_before);

    let edit = "Exact import-only Codex source reached the real daemon watcher.\n";
    fs::write(
        wire_path_to_path(&capabilities.sources[0].path),
        edit.as_bytes(),
    )
    .unwrap();
    tokio::time::sleep(Duration::from_millis(750)).await;
    wait_for_candidate_count(&config, 1).await;
    assert_eq!(
        config.native_memory_candidates().unwrap()[0]
            .proposed_memory
            .body_markdown,
        edit
    );
    assert_eq!(fs::read(&materialized.config_path).unwrap(), config_before);

    installer
        .call(LocalRequest::HarnessRollback(PlanParams {
            plan_id: plan.plan_id,
        }))
        .await
        .unwrap();
    for source in &capabilities.sources {
        assert!(config.native_memory_ledger(&source.id).unwrap().is_none());
    }
    assert_eq!(fs::read(&materialized.config_path).unwrap(), config_before);
    assert_eq!(
        handle.shutdown().await,
        context_relay_contextd::DaemonState::Stopped
    );
    owner.await.unwrap().unwrap();
}

struct NeverBridgeLocator;

impl BridgeLocator for NeverBridgeLocator {
    fn locate(&self) -> Result<BridgeExecutable, ClientError> {
        Err(conflict(
            "watch-only setup unexpectedly requested a bridge executable",
        ))
    }
}

struct NeverBridgeExecutor;

impl BridgePlanExecutor for NeverBridgeExecutor {
    fn execute(
        &mut self,
        _: &mut Vault,
        _: &NativeTransactionPlan,
        _: &[u8],
        _: u64,
        _: u64,
    ) -> Result<(), BridgeExecutionError> {
        panic!("registration-only setup invoked the native executor")
    }
}

struct WatchOnlyCodexSetupEngine {
    adapter: Mutex<CodexAdapter>,
    project_id: ProjectId,
    project_root: PathBuf,
}

impl BridgeInstallEngine for WatchOnlyCodexSetupEngine {
    fn reconcile_after_native_recovery(
        &self,
        vault: &mut Vault,
        _vault_path: &Path,
        _device_id: DeviceId,
    ) -> Result<(), ClientError> {
        BridgeInstallService::persisted(vault).reconcile_after_native_recovery()
    }

    fn preview(
        &self,
        vault: &mut Vault,
        _vault_path: &Path,
        device_id: DeviceId,
        params: HarnessParams,
    ) -> Result<SetupPlan, ClientError> {
        if params.harness != HarnessId::Codex || params.project_id != Some(self.project_id) {
            return Err(conflict("Watch-only setup binding changed"));
        }
        let observed_hlc = HybridLogicalClock::new(1_900_000_000_000, 0, device_id);
        BridgeInstallService::new(
            vault,
            self.adapter.lock().unwrap().clone(),
            NeverBridgeLocator,
            device_id,
            observed_hlc,
        )
        .preview(
            Some(&RegisteredProject {
                project_id: self.project_id,
                root: wire_path(&self.project_root),
            }),
            1_900_000_000_000,
        )
    }

    fn apply(
        &self,
        vault: &mut Vault,
        _vault_path: &Path,
        _device_id: DeviceId,
        params: PlanParams,
    ) -> Result<(), ClientError> {
        BridgeInstallService::persisted(vault).apply(
            &params.plan_id,
            1_900_000_000_001,
            &mut NeverBridgeExecutor,
        )
    }

    fn rollback(
        &self,
        vault: &mut Vault,
        _vault_path: &Path,
        _device_id: DeviceId,
        params: PlanParams,
    ) -> Result<(), ClientError> {
        BridgeInstallService::persisted(vault).rollback(
            &params.plan_id,
            1_900_000_000_002,
            &mut NeverBridgeExecutor,
        )
    }
}

struct HermesExportRestricted {
    inputs: Vec<ApprovedInput>,
    sidecars: Vec<SidecarBinding>,
    run: RestrictedRun,
}

impl RestrictedExecutor for HermesExportRestricted {
    fn copy_allowlisted_inputs(&mut self, inputs: &[ApprovedInput]) -> Result<(), BoundaryError> {
        (inputs == self.inputs)
            .then_some(())
            .ok_or_else(|| BoundaryError::new("Hermes export inputs changed"))
    }

    fn create_fake_roots(&mut self) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn build_restricted_environment(&mut self) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn run_restricted_tools(
        &mut self,
        sidecars: &[SidecarBinding],
    ) -> Result<RestrictedRun, BoundaryError> {
        (sidecars == self.sidecars)
            .then(|| self.run.clone())
            .ok_or_else(|| BoundaryError::new("Hermes export sidecars changed"))
    }

    fn reject_unsafe_topology(&mut self) -> Result<(), BoundaryError> {
        Ok(())
    }
}

struct HermesExportExecutor<'a> {
    adapter: &'a mut HermesAdapter,
    lock_root: PathBuf,
}

impl BridgePlanExecutor for HermesExportExecutor<'_> {
    fn execute(
        &mut self,
        vault: &mut Vault,
        plan: &NativeTransactionPlan,
        sealed_plan: &[u8],
        created_ms: u64,
        now_ms: u64,
    ) -> Result<(), BridgeExecutionError> {
        let mut restricted = HermesExportRestricted {
            inputs: plan.staged_inputs.clone(),
            sidecars: plan.sidecars.clone(),
            run: RestrictedRun {
                staged_output_hash: plan.expected_semantic_output_hash,
                scanner_result_hash: plan.scanner_result_hash,
            },
        };
        let mut filesystem = OsNativeTransactionFileSystem::new(*plan.setup.plan_id.as_bytes());
        let mut hook = NoFault;
        let mut cli = NoBridgeCliExecutor;
        NativeEngineBridgePlanExecutor::new(
            &mut *self.adapter,
            &mut restricted,
            &mut filesystem,
            &mut hook,
            &mut cli,
            &self.lock_root,
            test_native_identity(),
            BeforeImagePolicy::default(),
            HybridLogicalClock::new(now_ms, 0, DeviceId::from_str(DEVICE_ID).unwrap()),
        )
        .execute(vault, plan, sealed_plan, created_ms, now_ms)
    }
}

struct CrashAfterHermesExport<'a>(HermesExportExecutor<'a>);

impl BridgePlanExecutor for CrashAfterHermesExport<'_> {
    fn execute(
        &mut self,
        vault: &mut Vault,
        plan: &NativeTransactionPlan,
        sealed_plan: &[u8],
        created_ms: u64,
        now_ms: u64,
    ) -> Result<(), BridgeExecutionError> {
        self.0
            .execute(vault, plan, sealed_plan, created_ms, now_ms)
            .unwrap();
        panic!("simulated exit after Hermes export native commit")
    }
}

#[test]
fn unknown_exact_codex_binding_is_watch_only_and_never_synthesizes_disable_keys() {
    let materialized = MaterializedCodex::new("unknown-binding", "0.145.0");
    let before = fs::read(&materialized.config_path).unwrap();
    let capabilities = materialized.capabilities();

    assert!(matches!(
        capabilities.disable,
        NativeMemoryDisable::WatchOnly
    ));
    assert_eq!(capabilities.sources.len(), 2);
    assert_eq!(capabilities.sources[0].adapter_version, "0.145.0");
    assert_eq!(capabilities.sources[0].scope, ScopeRef::Global);
    assert_eq!(
        capabilities.sources[0].path,
        wire_path(&materialized.codex_home.join("memories/MEMORY.md"))
    );
    assert_eq!(
        capabilities.sources[1].path,
        wire_path(&materialized.codex_home.join("memories/memory_summary.md"))
    );
    assert_eq!(fs::read(&materialized.config_path).unwrap(), before);
    let config = String::from_utf8(before).unwrap();
    assert!(config.contains("generate_memories = true"));
    assert!(config.contains("use_memories = true"));
    assert!(!config.contains("generate_memories = false"));
    assert!(!config.contains("use_memories = false"));
}

struct AcceptanceFixture {
    _materialized: MaterializedCodex,
    runtime: RuntimeConfig,
    config: TestDaemonConfig,
    project: ProjectIdentity,
    sources: Vec<NativeMemorySource>,
    memory_path: PathBuf,
    instruction_path: PathBuf,
    config_path: PathBuf,
}

impl AcceptanceFixture {
    fn supported(label: &str) -> Self {
        let materialized = MaterializedCodex::new_with_requirements(label, "0.144.1", false);
        let capabilities = materialized.capabilities();
        let NativeMemoryDisable::Supported(disable) = &capabilities.disable else {
            panic!("the frozen Codex fixture must support native-memory disable")
        };
        assert_eq!(disable.len(), 1);
        for source in &capabilities.sources {
            fs::write(wire_path_to_path(&source.path), MANAGED_EXPORT).unwrap();
        }
        let sources = capabilities.sources;
        let project = ProjectIdentity {
            project_id: ProjectId::from_str(PROJECT_ID).unwrap(),
            github_repository_id: None,
            git_remote_fingerprint: None,
            monorepo_subdirectory: None,
            name: "Task 14 acceptance".into(),
        };
        let runtime = RuntimeConfig::for_test(
            format!("am-{}", unique_runtime_fragment()),
            Some(short_runtime_root()),
        )
        .unwrap();
        let bridge_path = materialized.root.join("context-relay-context-mcp");
        fs::write(&bridge_path, b"acceptance bridge executable").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&bridge_path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let bridge = attest_bridge_executable(&bridge_path).unwrap();
        let lock_root = materialized.root.join("locks");
        fs::create_dir(&lock_root).unwrap();
        let engine = Arc::new(TestCodexBridgeInstallEngine::new(
            materialized.adapter.clone(),
            bridge,
            project.project_id,
            materialized.project_root.clone(),
            lock_root,
        ));
        let config = TestDaemonConfig::new(
            runtime.clone(),
            materialized.root.join("vault.db"),
            InstallationToken::from_bytes(TOKEN),
        )
        .with_bridge_install_engine(engine);
        config
            .seed_mcp_project(
                &project,
                &materialized.project_root,
                &[(
                    HarnessId::Codex,
                    HarnessAccessPolicy::ActiveProjectOnly { read_only: false },
                )],
            )
            .unwrap();
        Self {
            memory_path: materialized.codex_home.join("memories/MEMORY.md"),
            instruction_path: materialized.project_root.join("AGENTS.md"),
            config_path: materialized.config_path.clone(),
            _materialized: materialized,
            runtime,
            config,
            project,
            sources,
        }
    }
}

struct MaterializedCodex {
    root: PathBuf,
    codex_home: PathBuf,
    project_root: PathBuf,
    config_path: PathBuf,
    adapter: CodexAdapter,
}

impl MaterializedCodex {
    fn new(label: &str, version: &str) -> Self {
        Self::new_with_requirements(label, version, true)
    }

    fn new_with_requirements(label: &str, version: &str, active_requirements: bool) -> Self {
        let fixture: Value =
            serde_json::from_str(include_str!("../../core/tests/fixtures/codex-0.144.1.json"))
                .unwrap();
        let root = unique_temp_path(label);
        let codex_home = root.join("codex-home");
        let home = root.join("home");
        let project_root = root.join("project");
        let working_directory = project_root.join("service");
        materialize_substituting(
            &codex_home,
            fixture["codexHome"].as_object().unwrap(),
            &project_root,
        );
        materialize(
            &home.join(".agents/skills"),
            fixture["userSkills"].as_object().unwrap(),
        );
        materialize(&project_root, fixture["project"].as_object().unwrap());
        fs::create_dir_all(&working_directory).unwrap();
        let requirements = root.join("requirements.toml");
        if active_requirements {
            fs::write(&requirements, fixture["requirements"].as_str().unwrap()).unwrap();
        }
        let executable = root.join(if cfg!(windows) { "codex.exe" } else { "codex" });
        fs::write(&executable, b"\x7fELFfixture executable").unwrap();
        let project_id = ProjectId::from_str(PROJECT_ID).unwrap();
        let device_id = DeviceId::from_str(DEVICE_ID).unwrap();
        let adapter = CodexAdapter::from_layout(
            CodexLayout {
                executable,
                executable_kind: CodexExecutableKind::Native,
                version: version.into(),
                installation_method: InstallationMethod::PackageManager,
                codex_home: codex_home.clone(),
                user_skills_dir: home.join(".agents/skills"),
                project_root: project_root.clone(),
                working_directory,
                requirements_paths: vec![requirements],
            },
            project_id,
            device_id,
            HybridLogicalClock::new(1_900_000_000_000, 0, device_id),
        )
        .unwrap();
        Self {
            config_path: codex_home.join("config.toml"),
            root,
            codex_home,
            project_root,
            adapter,
        }
    }

    fn capabilities(&self) -> NativeMemoryCapabilities {
        self.adapter.native_memory_capabilities().unwrap()
    }
}

impl Drop for MaterializedCodex {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct MaterializedHermes {
    root: PathBuf,
    memory_path: PathBuf,
    lock_root: PathBuf,
    adapter: HermesAdapter,
}

impl MaterializedHermes {
    fn new(label: &str) -> Self {
        let fixture: Value =
            serde_json::from_str(include_str!("../../core/tests/fixtures/hermes-0.18.2.json"))
                .unwrap();
        let root = unique_temp_path(label);
        let default_hermes_home = root.join("hermes");
        let hermes_home = default_hermes_home.join("profiles/coder");
        let profile = fixture["profile"].as_object().unwrap();
        let mut files = profile["files"].as_object().unwrap().clone();
        files.remove("gateway.pid");
        files.remove("gateway_state.json");
        materialize(&hermes_home, &files);
        fs::write(hermes_home.join("memories/MEMORY.md"), b"").unwrap();
        let mut config = profile["configYaml"].as_str().unwrap().to_owned();
        config.push_str(fixture["nativeMemoryConfigYaml"].as_str().unwrap());
        fs::write(hermes_home.join("config.yaml"), config).unwrap();

        let project_root = root.join("project");
        let working_directory = project_root.join("service");
        materialize(&project_root, fixture["project"].as_object().unwrap());
        fs::create_dir_all(&working_directory).unwrap();
        let executable = root.join(if cfg!(windows) {
            "hermes-bin.exe"
        } else {
            "hermes-bin"
        });
        fs::write(&executable, b"\x7fELFfixture hermes executable").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let lock_root = root.join("locks");
        fs::create_dir(&lock_root).unwrap();
        let project_id = ProjectId::from_str(PROJECT_ID).unwrap();
        let device_id = DeviceId::from_str(DEVICE_ID).unwrap();
        let adapter = HermesAdapter::from_layout(
            HermesLayout {
                executable,
                executable_kind: HermesExecutableKind::Native,
                version: "0.18.2".into(),
                installation_method: InstallationMethod::PackageManager,
                default_hermes_home,
                profile: HermesProfile {
                    name: "coder".into(),
                    hermes_home: hermes_home.clone(),
                },
                project_root,
                working_directory,
            },
            project_id,
            device_id,
            HybridLogicalClock::new(1_900_000_000_000, 0, device_id),
        )
        .unwrap();
        Self {
            root,
            memory_path: hermes_home.join("memories/MEMORY.md"),
            lock_root,
            adapter,
        }
    }
}

impl Drop for MaterializedHermes {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn test_native_identity() -> NativeSandboxIdentity {
    #[cfg(windows)]
    {
        NativeSandboxIdentity::Windows {
            moniker: "context-relay.native.0123456789abcdef0123456789abcdef".to_owned(),
            sid: b"S-1-15-2-3872518810-2985098273-1912316193-2655983105-1250049442-371239648-1157085541".to_vec(),
        }
    }
    #[cfg(not(windows))]
    {
        let generation = "0123456789abcdef0123456789abcdef";
        let bundle = format!("com.contextrelay.native-runner.{generation}");
        let mut container = b"context-relay/macos-container/v1\0".to_vec();
        container.extend_from_slice(bundle.as_bytes());
        NativeSandboxIdentity::reserved_macos(generation.to_owned(), bundle, container)
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
        let client_nonce = DaemonInstanceNonce::new([0x27; 32]);
        let transcript = AuthTranscriptV1 {
            role,
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
}

async fn wait_for_previews(config: &TestDaemonConfig, sources: &[NativeMemorySource]) {
    for _ in 0..120 {
        if sources.iter().all(|source| {
            config
                .native_memory_ledger(&source.id)
                .unwrap()
                .is_some_and(|ledger| ledger.initial_preview_complete)
        }) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("authoritative memory previews did not complete")
}

async fn wait_for_candidate_count(config: &TestDaemonConfig, count: usize) {
    for _ in 0..120 {
        if config.native_memory_candidates().unwrap().len() == count {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("authoritative memory candidate count did not reach {count}")
}

fn assert_contract_files(fixture: &AcceptanceFixture) {
    let instruction = fs::read_to_string(&fixture.instruction_path).unwrap();
    assert!(instruction.contains(PRIMARY_MEMORY_INSTRUCTIONS));
    for tool in [
        "context_relay_search",
        "context_relay_remember",
        "context_relay_propose_memory",
        "context_relay_list_tasks",
        "context_relay_upsert_task",
        "context_relay_complete_task",
    ] {
        assert!(instruction.contains(tool), "missing contract tool {tool}");
    }
    let config = fs::read_to_string(&fixture.config_path).unwrap();
    assert!(config.contains("generate_memories = false"));
    assert!(config.contains("use_memories = false"));
}

fn materialize(root: &Path, files: &Map<String, Value>) {
    for (relative, body) in files {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body.as_str().unwrap()).unwrap();
    }
}

fn materialize_substituting(root: &Path, files: &Map<String, Value>, project: &Path) {
    for (relative, body) in files {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            path,
            body.as_str()
                .unwrap()
                .replace("$PROJECT", &project.to_string_lossy()),
        )
        .unwrap();
    }
}

fn wire_path(path: &Path) -> WireNativeValue {
    #[cfg(not(windows))]
    use std::os::unix::ffi::OsStrExt as _;
    #[cfg(windows)]
    use std::os::windows::ffi::OsStrExt as _;

    WireNativeValue {
        platform: if cfg!(windows) {
            NativePlatform::Windows
        } else {
            NativePlatform::Macos
        },
        #[cfg(windows)]
        bytes: path
            .as_os_str()
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect(),
        #[cfg(not(windows))]
        bytes: path.as_os_str().as_bytes().to_vec(),
        display: Some(path.display().to_string()),
    }
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

fn record_id() -> RecordId {
    RecordId::new(Uuid::now_v7()).unwrap()
}

fn operation_id() -> OperationId {
    OperationId::new(Uuid::now_v7()).unwrap()
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
    let path = root.join(format!(
        "cr-authoritative-{label}-{}",
        &Uuid::now_v7().simple().to_string()[..12]
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn short_runtime_root() -> PathBuf {
    #[cfg(windows)]
    let root = std::env::temp_dir();
    #[cfg(not(windows))]
    let root = PathBuf::from("/private/tmp");
    root.join(format!("crar-{}", unique_runtime_fragment()))
}

fn unique_runtime_fragment() -> String {
    let uuid = Uuid::now_v7().simple().to_string();
    uuid[uuid.len() - 12..].to_owned()
}
