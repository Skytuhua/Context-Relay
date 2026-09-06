//! Disposable native transaction qualification for a retained Python runtime.
//! The fixture command is inert; it tests ownership and setup, not a live LLM.
use super::*;
use crate::{
    mcp::install::{BridgeExecutable, attest_bridge_executable},
    native_transaction::{
        ApprovedInput, SidecarBinding, TransactionStep,
        engine::{FaultHook, RestrictedExecutor},
        filesystem::OsNativeTransactionFileSystem,
        open_plan,
        recovery::{OsNativeRecoveryIo, recover_native_transactions},
    },
    setup::{
        BridgeExecutionError, BridgeInstallService, BridgeLocator, BridgePlanExecutor,
        NativeEngineBridgePlanExecutor, NoBridgeCliExecutor, RegisteredProject,
    },
    vault::{
        BeforeImagePolicy, DatabaseKeyStore, NativeSandboxIdentity, SetupPlanLifecycle, Vault,
        VaultError,
    },
};
use std::sync::{Arc, Mutex, atomic::AtomicBool};
use zeroize::Zeroizing;

const NOW: u64 = 1_900_000_000_000;

#[derive(Default)]
struct Keys(Mutex<Option<Vec<u8>>>);
impl DatabaseKeyStore for Keys {
    fn load_key(&self, _: &str) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
        Ok(self.0.lock().unwrap().clone().map(Zeroizing::new))
    }
    fn store_key(&self, _: &str, key: &[u8]) -> Result<(), VaultError> {
        *self.0.lock().unwrap() = Some(key.to_vec());
        Ok(())
    }
}
struct Locator(PathBuf);
impl BridgeLocator for Locator {
    fn locate(&self) -> Result<BridgeExecutable, ClientError> {
        attest_bridge_executable(&self.0)
    }
}
struct InProcess<'a>(&'a NativeTransactionPlan);
impl RestrictedExecutor for InProcess<'_> {
    fn copy_allowlisted_inputs(&mut self, inputs: &[ApprovedInput]) -> Result<(), BoundaryError> {
        assert!(inputs.is_empty());
        Ok(())
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
        assert_eq!(sidecars, self.0.sidecars);
        Ok(RestrictedRun {
            staged_output_hash: self.0.expected_semantic_output_hash,
            scanner_result_hash: self.0.scanner_result_hash,
        })
    }
    fn reject_unsafe_topology(&mut self) -> Result<(), BoundaryError> {
        Ok(())
    }
}
struct Crash(Option<TransactionStep>);
impl FaultHook for Crash {
    fn after_step(&mut self, step: TransactionStep) -> Result<(), BoundaryError> {
        println!("Native transaction completed {step:?}");
        assert_ne!(self.0, Some(step), "injected panic at {step:?}");
        Ok(())
    }
}
struct Executor<'a> {
    store: &'a Path,
    layout: &'a HermesLayout,
    project: ProjectId,
    device: DeviceId,
    crash: Option<TransactionStep>,
    calls: usize,
    rediscover: bool,
}
impl BridgePlanExecutor for Executor<'_> {
    fn execute(
        &mut self,
        vault: &mut Vault,
        plan: &NativeTransactionPlan,
        sealed: &[u8],
        created_ms: u64,
        now_ms: u64,
    ) -> Result<(), BridgeExecutionError> {
        self.calls += 1;
        assert_eq!(&open_plan(sealed).unwrap().plan, plan);
        assert!(plan.cli_mutations.is_empty());
        assert!(plan.staged_inputs.is_empty());
        let mut other_layout = self.layout.clone();
        let other_home = self.store.join("other profile");
        other_layout.default_hermes_home = other_home.clone();
        other_layout.profile.hermes_home = other_home;
        for no_mutations in [false, true] {
            let mut candidate = plan.clone();
            if no_mutations {
                candidate.mutations.clear();
            }
            let other = HermesAdapter::from_layout(
                other_layout.clone(),
                self.project,
                self.device,
                HybridLogicalClock::new(now_ms, 0, self.device),
            )
            .unwrap();
            let error = other
                .reopen_approved_runtime(
                    &self.store.join("missing-store"),
                    &candidate,
                    Arc::new(AtomicBool::new(false)),
                )
                .unwrap_err();
            assert_eq!(
                error.message, "Hermes approved profile location changed",
                "profile drift must be rejected before opening the runtime store"
            );
        }
        let clock = HybridLogicalClock::new(now_ms, 0, self.device);
        println!(
            "Reopening approved Hermes runtime for {}",
            plan.setup.plan_id
        );
        // Reconstruct every time, including Undo, with no reused adapter owner.
        let mut adapter = if self.rediscover {
            HermesAdapter::discover_for_retained_setup(
                &self.layout.project_root,
                &self.layout.working_directory,
                &self.layout.profile.name,
                self.project,
                self.device,
                clock,
                plan,
            )
        } else {
            HermesAdapter::from_layout(self.layout.clone(), self.project, self.device, clock)
        }
        .unwrap()
        .reopen_approved_runtime(self.store, plan, Arc::new(AtomicBool::new(false)))
        .unwrap();
        adapter.qualify_retained_setup = true;
        println!("Runtime reopened; starting native transaction");
        let mut restricted = InProcess(plan);
        let mut filesystem = OsNativeTransactionFileSystem::new(*plan.setup.plan_id.as_bytes());
        NativeEngineBridgePlanExecutor::new(
            &mut adapter,
            &mut restricted,
            &mut filesystem,
            &mut Crash(self.crash),
            &mut NoBridgeCliExecutor,
            self.store,
            NativeSandboxIdentity::Windows {
                moniker: "context-relay.native.00000000000000000000000000000000".into(),
                sid: b"S-1-15-2-1-2-3-4-5-6-7".to_vec(),
            },
            BeforeImagePolicy::default(),
            clock,
        )
        .execute(vault, plan, sealed, created_ms, now_ms)
    }
}

#[test]
fn retained_native_setup_restart_reapply_undo_and_recovery() {
    let _guard = python_runtime::management_test_guard();
    for crash in [
        None,
        Some(TransactionStep::WritePayloads),
        Some(TransactionStep::CommitOwnershipAndReceipt),
    ] {
        let launcher = b"\x7fELFinert launcher; must never execute";
        let (store, runtime) = python_runtime::prepared_runtime_fixture(launcher, true);
        let executable = store.path().join("hermes.exe");
        fs::write(&executable, launcher).unwrap();
        run_case(store.path(), runtime, executable, crash, false);
    }
}

#[test]
#[ignore = "explicit installed Hermes copy; disposable profiles, vault and native settings only"]
fn installed_retained_native_setup_restart_reapply_and_undo() {
    let _guard = python_runtime::management_test_guard();
    let executable = PathBuf::from(
        env::var_os("CONTEXT_RELAY_HERMES_METADATA_EXE")
            .expect("select a Hermes installation explicitly"),
    );
    let store = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(store.path()).unwrap();
    let started = Instant::now();
    let cancel = AtomicBool::new(false);
    println!("Capturing explicit installed runtime for native setup qualification");
    let captured = python_runtime::capture_with_progress(&executable, &root, &cancel, |progress| {
        if progress.completed_files == 0 {
            println!("{:?} at {:?}", progress.phase, started.elapsed());
        }
    })
    .unwrap();
    let runtime = captured
        .prepare_owned_with_progress(&cancel, |_| {})
        .unwrap();
    println!("Prepared runtime at {:?}", started.elapsed());
    run_case(&root, runtime, executable, None, true);
    println!(
        "Native save, vault reopen, reapply and Undo passed at {:?}",
        started.elapsed()
    );
}

fn run_case(
    store: &Path,
    runtime: python_runtime::retained::PreparedRuntime,
    executable: PathBuf,
    crash: Option<TransactionStep>,
    native_readback: bool,
) {
    let root = fs::canonicalize(store).unwrap();
    let home = root.join("profile 專案 O'Brien");
    let project_root = root.join("project 專案 O'Brien");
    fs::create_dir(&home).unwrap();
    fs::create_dir(root.join("other profile")).unwrap();
    fs::write(
        root.join("other profile/config.yaml"),
        b"model: another-profile\n",
    )
    .unwrap();
    fs::create_dir(&project_root).unwrap();
    fs::create_dir(home.join("memories")).unwrap();
    fs::write(home.join("memories/MEMORY.md"), b"native memory canary\n").unwrap();
    fs::write(home.join("memories/USER.md"), b"native user canary\n").unwrap();
    fs::write(home.join(".env"), b"TOKEN=must-not-stage-env\n").unwrap();
    fs::write(home.join("config.yaml"), b"# keep this comment\nmodel: fixture\nmemory:\n  memory_enabled: true\n  user_profile_enabled: true\n").unwrap();
    let bridge = root.join("inert context-mcp.exe");
    fs::write(&bridge, b"must never launch this bridge").unwrap();
    let layout = HermesLayout {
        executable,
        executable_kind: HermesExecutableKind::Unknown,
        version: "0.17.0".into(),
        installation_method: InstallationMethod::PackageManager,
        default_hermes_home: home.clone(),
        profile: HermesProfile {
            name: "default".into(),
            hermes_home: home.clone(),
        },
        project_root: project_root.clone(),
        working_directory: project_root.clone(),
    };
    let project = "018f22e2-79b0-7cc8-98c4-dc0c0c073981".parse().unwrap();
    let device = "018f22e2-79b0-7cc8-98c4-dc0c0c073982".parse().unwrap();
    let adapter = HermesAdapter::from_layout(
        layout.clone(),
        project,
        device,
        HybridLogicalClock::new(NOW, 0, device),
    )
    .unwrap();
    assert_eq!(adapter.capability(), CapabilityLevel::ImportOnly);
    let keys = Keys::default();
    let database = root.join("vault.db");
    let mut vault = Vault::open(&database, "retained-native-setup", &keys).unwrap();
    let setup = adapter
        .into_setup_preview(runtime)
        .unwrap()
        .preview(
            &mut vault,
            Locator(bridge),
            &RegisteredProject {
                project_id: project,
                root: wire_path(&project_root),
            },
            NOW,
        )
        .unwrap();
    assert_eq!(
        fs::read_dir(&project_root).unwrap().count(),
        0,
        "preview must not create a metadata template or instruction file"
    );
    let opened = open_plan(&vault.setup_plan(&setup.plan_id).unwrap().unwrap().payload).unwrap();
    assert!(opened.plan.installed_runtime.is_some());
    assert!(!opened.plan.mutations.is_empty());
    let originals = opened
        .plan
        .mutations
        .iter()
        .map(|mutation| {
            let path = decode_wire_path(&mutation.target).unwrap();
            let state = OsNativeFileSystem::new()
                .snapshot(&path)
                .unwrap()
                .state()
                .clone();
            (path, state)
        })
        .collect::<Vec<_>>();
    let mut executor = Executor {
        store: &root,
        layout: &layout,
        project,
        device,
        crash,
        calls: 0,
        rediscover: false,
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        BridgeInstallService::persisted(&mut vault).apply(&setup.plan_id, NOW + 1, &mut executor)
    }));
    if crash.is_some() {
        assert!(result.is_err());
    } else {
        result.unwrap().unwrap();
    }
    drop(vault);
    let mut vault = Vault::open(&database, "retained-native-setup", &keys).unwrap();
    if crash.is_some() {
        let mut recovery = OsNativeRecoveryIo::new(|_, _| Ok::<(), BoundaryError>(()));
        let summary = recover_native_transactions(&mut vault, &mut recovery).unwrap();
        assert_eq!(summary.recovered(), 1);
        assert_eq!(summary.conflicts, 0);
        BridgeInstallService::persisted(&mut vault)
            .reconcile_after_native_recovery()
            .unwrap();
    }
    let committed = crash != Some(TransactionStep::WritePayloads);
    assert_eq!(
        vault.setup_plan(&setup.plan_id).unwrap().unwrap().lifecycle,
        if committed {
            SetupPlanLifecycle::Applied
        } else {
            SetupPlanLifecycle::ApplyRestored
        }
    );
    if committed {
        let config = fs::read_to_string(home.join("config.yaml")).unwrap();
        let config: JsonValue = serde_yaml_ng::from_str(&config).unwrap();
        assert_eq!(config["memory"]["memory_enabled"], false);
        assert_eq!(config["memory"]["user_profile_enabled"], false);
        assert_eq!(
            config["mcp_servers"]["context-relay"],
            serde_json::json!({
                "command": fs::canonicalize(root.join("inert context-mcp.exe")).unwrap().to_str().unwrap(),
                "args": ["--harness", "hermes"],
            })
        );
        drop(vault);
        let mut changed_layout = layout.clone();
        changed_layout.profile.hermes_home = root.join("other profile");
        reopen_in_child(&root, &changed_layout, &keys, &setup.plan_id, false, true);
        reopen_in_child(
            &root,
            &layout,
            &keys,
            &setup.plan_id,
            native_readback,
            false,
        );
        vault = Vault::open(&database, "retained-native-setup", &keys).unwrap();
    }
    for (path, state) in originals {
        assert_eq!(
            OsNativeFileSystem::new()
                .snapshot(&path)
                .unwrap()
                .state()
                .fingerprint(),
            state.fingerprint(),
            "restorable bytes and metadata: {}",
            path.display()
        );
    }
    assert!(vault.native_memory_ledgers().unwrap().is_empty());
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
        b"TOKEN=must-not-stage-env\n"
    );
}

fn reopen_in_child(
    root: &Path,
    layout: &HermesLayout,
    keys: &Keys,
    plan: &context_relay_protocol::PlanId,
    native_readback: bool,
    profile_drift: bool,
) {
    let stdout = root.join("restart.stdout");
    let stderr = root.join("restart.stderr");
    let scratch = root.join("restart-scratch");
    fs::create_dir_all(&scratch).unwrap();
    let mut command = Command::new(env::current_exe().unwrap());
    command.env_clear();
    for key in ["SystemRoot", "WINDIR"] {
        if let Some(value) = env::var_os(key) {
            command.env(key, value);
        }
    }
    command
        .args([
            "--exact",
            "hermes::native_setup_tests::retained_setup_reopen_child",
            "--ignored",
            "--nocapture",
        ])
        .env("CONTEXT_RELAY_REOPEN_STORE", root)
        .env("CONTEXT_RELAY_REOPEN_PLAN", plan.to_string())
        .env(
            "CONTEXT_RELAY_PROFILE_DRIFT",
            if profile_drift { "1" } else { "0" },
        )
        .env(
            "CONTEXT_RELAY_NATIVE_READBACK",
            if native_readback { "1" } else { "0" },
        )
        .env(
            "CONTEXT_RELAY_REOPEN_TEST_KEY",
            serde_json::to_string(&*keys.0.lock().unwrap()).unwrap(),
        )
        .env("HERMES_HOME", &layout.profile.hermes_home)
        .env("HOME", &scratch)
        .env("USERPROFILE", &scratch)
        .env("APPDATA", &scratch)
        .env("LOCALAPPDATA", &scratch)
        .env("TEMP", &scratch)
        .env("TMP", &scratch)
        .env("PATH", layout.executable.parent().unwrap())
        .current_dir(&layout.project_root)
        .stdin(Stdio::piped())
        .stdout(fs::File::create(&stdout).unwrap())
        .stderr(fs::File::create(&stderr).unwrap());
    let result =
        crate::test_windows_process::run_in_owned_job(&mut command, Duration::from_secs(1800));
    assert!(
        result.is_ok_and(|status| status.success()),
        "restart stdout: {}\nstderr: {}",
        fs::read_to_string(stdout).unwrap(),
        fs::read_to_string(stderr).unwrap()
    );
}

#[test]
#[ignore = "internal contained child; requires a disposable test vault and explicit profile"]
fn retained_setup_reopen_child() {
    let mut gate = String::new();
    std::io::stdin().read_to_string(&mut gate).unwrap();
    assert_eq!(gate, "run");
    let store = PathBuf::from(env::var_os("CONTEXT_RELAY_REOPEN_STORE").unwrap());
    let plan_id = env::var("CONTEXT_RELAY_REOPEN_PLAN")
        .unwrap()
        .parse()
        .unwrap();
    let keys = Keys(Mutex::new(
        serde_json::from_str(&env::var("CONTEXT_RELAY_REOPEN_TEST_KEY").unwrap()).unwrap(),
    ));
    let mut vault = Vault::open(&store.join("vault.db"), "retained-native-setup", &keys).unwrap();
    let opened = open_plan(&vault.setup_plan(&plan_id).unwrap().unwrap().payload).unwrap();
    let project_root = fs::canonicalize(env::current_dir().unwrap()).unwrap();
    let project = "018f22e2-79b0-7cc8-98c4-dc0c0c073981".parse().unwrap();
    let device = "018f22e2-79b0-7cc8-98c4-dc0c0c073982".parse().unwrap();
    let discovered = HermesAdapter::discover_for_retained_setup(
        &project_root,
        &project_root,
        "default",
        project,
        device,
        HybridLogicalClock::new(NOW + 2, 0, device),
        &opened.plan,
    );
    if env::var("CONTEXT_RELAY_PROFILE_DRIFT").unwrap() == "1" {
        assert_eq!(
            discovered.unwrap_err().message,
            "Hermes approved profile location changed"
        );
        return;
    }
    let adapter = discovered.unwrap();
    assert_eq!(
        adapter.layout.profile.hermes_home,
        fs::canonicalize(env::var_os("HERMES_HOME").unwrap()).unwrap()
    );
    assert_eq!(adapter.capability(), CapabilityLevel::ImportOnly);
    let mut executor = Executor {
        store: &store,
        layout: &adapter.layout,
        project,
        device,
        crash: None,
        calls: 0,
        rediscover: true,
    };
    BridgeInstallService::persisted(&mut vault)
        .apply(&plan_id, NOW + 2, &mut executor)
        .unwrap();
    assert_eq!(executor.calls, 0, "restart/reapply must not execute again");
    if env::var("CONTEXT_RELAY_NATIVE_READBACK").unwrap() == "1" {
        readback_with_native_loader(&store, &opened.plan, &adapter.layout, true);
    }
    BridgeInstallService::persisted(&mut vault)
        .rollback(&plan_id, NOW + 3, &mut executor)
        .unwrap();
    assert_eq!(
        executor.calls, 1,
        "Undo must rediscover and reopen the approved runtime"
    );
    if env::var("CONTEXT_RELAY_NATIVE_READBACK").unwrap() == "1" {
        readback_with_native_loader(&store, &opened.plan, &adapter.layout, false);
    }
}

// Test-only readback through Hermes's own configuration loader. The production
// management runner still accepts only Version and ConfigCheck. No model or MCP
// server is started, and the copied runtime remains locked through this child.
fn readback_with_native_loader(
    store: &Path,
    plan: &NativeTransactionPlan,
    layout: &HermesLayout,
    applied: bool,
) {
    use crate::native_transaction::InstalledRuntimeBinding;
    let Some(InstalledRuntimeBinding::HermesPythonV1 { runtime }) = &plan.installed_runtime else {
        panic!("runtime")
    };
    let runtime = python_runtime::retained::RetainedRuntime::open_locked(store, runtime).unwrap();
    println!("Reading native Hermes settings, applied={applied}");
    let runtime_root = runtime.root().to_owned();
    let (output, runtime) =
        context_relay_native_runner::windows_management::read_hermes_settings_for_qualification(
            &runtime_root,
            &layout.profile.hermes_home,
            runtime,
            &AtomicBool::new(false),
        )
        .unwrap();
    assert_eq!(
        output.exit_code,
        0,
        "loader stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: JsonValue = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["agentMemory"], !applied);
    assert_eq!(value["userMemory"], !applied);
    assert_eq!(
        value["server"],
        if applied {
            serde_json::json!({
                "command": fs::canonicalize(store.join("inert context-mcp.exe")).unwrap().to_str().unwrap(),
                "args": ["--harness", "hermes"],
            })
        } else {
            JsonValue::Null
        }
    );
    runtime.verify().unwrap();
}
