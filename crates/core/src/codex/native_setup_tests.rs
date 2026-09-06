//! Candidate-version qualification. Only this disposable fixture opts an
//! adapter into setup; the production version allowlist remains unchanged.
use super::*;
use crate::mcp::install::{BridgeExecutable, attest_bridge_executable};
use crate::native_transaction::{
    ApprovedInput, SidecarBinding, TransactionStep,
    engine::{FaultHook, RestrictedExecutor},
    filesystem::OsNativeTransactionFileSystem,
    open_plan,
    recovery::{OsNativeRecoveryIo, RecoverySandboxIdentity, recover_native_transactions},
};
use crate::setup::{
    BridgeExecutionError, BridgeInstallService, BridgeLocator, BridgePlanExecutor,
    NativeEngineBridgePlanExecutor, NoBridgeCliExecutor, RegisteredProject,
};
use crate::vault::{
    BeforeImagePolicy, DatabaseKeyStore, NativeSandboxIdentity, SetupPlanLifecycle, Vault,
    VaultError,
};
use std::{panic::AssertUnwindSafe, sync::Mutex};
use zeroize::Zeroizing;

const PINNED_HASH: &str = "4b76ded066d0239115ca97473d010c92072bc5c5550a45dd7cbebe1e9eb956a7";
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

#[derive(Clone)]
struct Locator(PathBuf);
impl BridgeLocator for Locator {
    fn locate(&self) -> Result<BridgeExecutable, ClientError> {
        attest_bridge_executable(&self.0)
    }
}

// Mirrors the daemon's in-process bridge validator: no staged source inputs or
// sidecar process is run. The native engine and filesystem are the real ones.
struct InProcess {
    sidecars: Vec<SidecarBinding>,
    run: RestrictedRun,
}
impl RestrictedExecutor for InProcess {
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
        assert_eq!(sidecars, self.sidecars);
        Ok(self.run.clone())
    }
    fn reject_unsafe_topology(&mut self) -> Result<(), BoundaryError> {
        Ok(())
    }
}

struct Executor<'a> {
    locks: &'a Path,
    crash: Option<TransactionStep>,
    calls: usize,
}
struct Crash(Option<TransactionStep>);
impl FaultHook for Crash {
    fn after_step(&mut self, step: TransactionStep) -> Result<(), BoundaryError> {
        assert_ne!(self.0, Some(step), "injected panic at {step:?}");
        Ok(())
    }
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
        assert!(plan.cli_mutations.is_empty());
        assert!(plan.staged_inputs.is_empty());
        assert_eq!(plan.setup.harness_version, "0.144.6");
        // Reconstruct from the persisted plan as the production daemon does.
        let projects = plan
            .setup
            .target_scopes
            .iter()
            .filter_map(|scope| {
                if let NativeScope::Project { project_id, root } = scope {
                    Some((*project_id, decode_wire_path(root).unwrap()))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(projects.len(), 1);
        let mut adapter = discover(&projects[0].1, projects[0].0, now_ms);
        let device = adapter.origin_device;
        let mut restricted = InProcess {
            sidecars: plan.sidecars.clone(),
            run: RestrictedRun {
                staged_output_hash: plan.expected_semantic_output_hash,
                scanner_result_hash: plan.scanner_result_hash,
            },
        };
        let mut filesystem = OsNativeTransactionFileSystem::new(*plan.setup.plan_id.as_bytes());
        let mut fault = Crash(self.crash);
        NativeEngineBridgePlanExecutor::new(
            &mut adapter,
            &mut restricted,
            &mut filesystem,
            &mut fault,
            &mut NoBridgeCliExecutor,
            self.locks,
            NativeSandboxIdentity::Windows {
                moniker: "context-relay.native.00000000000000000000000000000000".into(),
                sid: b"S-1-15-2-1-2-3-4-5-6-7".to_vec(),
            },
            BeforeImagePolicy::default(),
            HybridLogicalClock::new(now_ms, 0, device),
        )
        .execute(vault, plan, sealed, created_ms, now_ms)
    }
}

#[test]
#[ignore = "requires explicit pinned Codex; all profiles, keys and transactions are disposable"]
fn pinned_codex_native_setup_restart_reapply_and_undo() {
    let executable =
        PathBuf::from(env::var_os("CONTEXT_RELAY_TEST_CODEX_EXE").expect("explicit Codex"));
    if env::var_os("CONTEXT_RELAY_NATIVE_SETUP_CHILD").is_none() {
        for name in [
            "ordinary",
            "after payload 專案 O'Brien",
            "after commit ‘quoted’",
        ] {
            let outer = tempfile::tempdir().unwrap();
            let root = fs::canonicalize(outer.path()).unwrap().join(name);
            let scratch = root.join("scratch");
            let ambient = root.join("home");
            let config = root.join("custom codex");
            fs::create_dir_all(&root).unwrap();
            fs::create_dir(&scratch).unwrap();
            fs::create_dir(&ambient).unwrap();
            fs::create_dir(&config).unwrap();
            fs::create_dir(ambient.join(".codex")).unwrap();
            fs::write(ambient.join(".codex/config.toml"), b"# ambient canary\n").unwrap();
            let stdout = outer.path().join("stdout");
            let stderr = outer.path().join("stderr");
            let mut child = Command::new(env::current_exe().unwrap());
            child.env_clear();
            for key in ["SystemRoot", "WINDIR"] {
                if let Some(value) = env::var_os(key) {
                    child.env(key, value);
                }
            }
            child
                .args([
                    "--exact",
                    "codex::native_setup_tests::pinned_codex_native_setup_restart_reapply_and_undo",
                    "--ignored",
                    "--nocapture",
                ])
                .env("CONTEXT_RELAY_NATIVE_SETUP_CHILD", "1")
                .env("CONTEXT_RELAY_TEST_CODEX_EXE", &executable)
                .env("CODEX_HOME", &config)
                .env("HOME", &ambient)
                .env("USERPROFILE", &ambient)
                .env("PATH", executable.parent().unwrap())
                .env("TEMP", &scratch)
                .env("TMP", &scratch)
                .current_dir(&root)
                .stdin(Stdio::piped())
                .stdout(fs::File::create(&stdout).unwrap())
                .stderr(fs::File::create(&stderr).unwrap());
            let result =
                crate::test_windows_process::run_in_owned_job(&mut child, Duration::from_secs(180));
            assert!(
                result.is_ok_and(|status| status.success()),
                "stdout: {}\nstderr: {}",
                fs::read_to_string(&stdout).unwrap(),
                fs::read_to_string(&stderr).unwrap()
            );
            assert_eq!(
                fs::read(ambient.join(".codex/config.toml")).unwrap(),
                b"# ambient canary\n"
            );
            println!("{}", fs::read_to_string(stdout).unwrap());
        }
        return;
    }
    let mut gate = String::new();
    std::io::stdin().read_to_string(&mut gate).unwrap();
    assert_eq!(gate, "run");
    let pinned_digest: Sha256Digest =
        serde_json::from_value(Value::String(PINNED_HASH.into())).unwrap();
    let candidate = find_executable(&home_dir().unwrap()).unwrap();
    assert_eq!(
        fs::canonicalize(&candidate).unwrap(),
        fs::canonicalize(&executable).unwrap()
    );
    // Hold the read-only image and path topology through every discovery launch.
    let _pinned_image = open_verified_codex_executable(&candidate, pinned_digest).unwrap();
    let root = fs::canonicalize(env::current_dir().unwrap()).unwrap();
    let name = root.file_name().unwrap().to_str().unwrap();
    let crash = match name {
        "ordinary" => None,
        "after payload 專案 O'Brien" => Some(TransactionStep::WritePayloads),
        "after commit ‘quoted’" => Some(TransactionStep::CommitOwnershipAndReceipt),
        _ => panic!("unknown fixture case"),
    };
    run_case(&root, name, crash);
}

fn discover(project: &Path, project_id: ProjectId, now_ms: u64) -> CodexAdapter {
    let device: DeviceId = "018f22e2-79b0-7cc8-98c4-dc0c0c073982".parse().unwrap();
    let mut adapter = CodexAdapter::discover(
        project,
        project,
        project_id,
        device,
        HybridLogicalClock::new(now_ms, 0, device),
    )
    .unwrap();
    assert_eq!(adapter.layout.version, "0.144.6");
    assert_eq!(
        serde_json::to_value(adapter.executable_hash).unwrap(),
        PINNED_HASH
    );
    assert_eq!(adapter.setup_capability(), CapabilityLevel::ImportOnly);
    // Test-only candidate gate; no version spoofing or production enablement.
    adapter.qualify_01446 = true;
    assert_eq!(adapter.setup_capability(), CapabilityLevel::Full);
    adapter
}

fn run_case(root: &Path, name: &str, crash: Option<TransactionStep>) {
    let home = root.join("home");
    let config = root.join("custom codex");
    let project = root.join("project");
    let locks = root.join("vault");
    for path in [
        &home,
        &config,
        &project.join(".codex"),
        &locks,
        &config.join("memories"),
    ] {
        fs::create_dir_all(path).unwrap();
    }
    let project = fs::canonicalize(project).unwrap();
    fs::write(config.join("memories/MEMORY.md"), b"native memory canary\n").unwrap();
    fs::write(
        config.join("memories/memory_summary.md"),
        b"native summary canary\n",
    )
    .unwrap();
    let trust = serde_json::to_string(
        &dunce::simplified(&project)
            .to_string_lossy()
            .to_ascii_lowercase(),
    )
    .unwrap();
    fs::write(config.join("config.toml"), format!(
        "# preserve this comment\n[projects.{trust}]\ntrust_level = \"trusted\"\n[memories]\ngenerate_memories = true\nuse_memories = true\n"
    )).unwrap();
    fs::write(
        project.join(".codex/config.toml"),
        b"# local override\n[memories]\nuse_memories = true\n",
    )
    .unwrap();
    let bridge = root.join("context relay inert bridge.exe");
    fs::write(&bridge, b"qualification marker only; never execute").unwrap();
    let device: DeviceId = "018f22e2-79b0-7cc8-98c4-dc0c0c073982".parse().unwrap();
    let project_id = "018f22e2-79b0-7cc8-98c4-dc0c0c073981".parse().unwrap();
    let adapter = discover(&project, project_id, NOW);
    assert_eq!(
        adapter.layout.codex_home,
        fs::canonicalize(&config).unwrap()
    );
    assert_eq!(adapter.layout.user_home, fs::canonicalize(&home).unwrap());
    let keys = Keys::default();
    let database = locks.join("vault.db");
    let mut vault = Vault::open(&database, "native-setup-qualification", &keys).unwrap();
    let registered = RegisteredProject {
        project_id: adapter.project_id,
        root: wire_path(&project),
    };
    let setup = BridgeInstallService::new(
        &mut vault,
        adapter.clone(),
        Locator(bridge.clone()),
        device,
        HybridLogicalClock::new(NOW, 0, device),
    )
    .preview(Some(&registered), NOW)
    .unwrap();
    let opened = open_plan(&vault.setup_plan(&setup.plan_id).unwrap().unwrap().payload).unwrap();
    assert!(!opened.plan.mutations.is_empty());
    assert!(opened.plan.cli_mutations.is_empty());
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
        locks: &locks,
        crash,
        calls: 0,
    };
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        BridgeInstallService::persisted(&mut vault).apply(&setup.plan_id, NOW + 1, &mut executor)
    }));
    if crash.is_some() {
        assert!(result.is_err());
    } else {
        result.unwrap().unwrap();
    }
    drop(adapter);
    drop(vault);
    let mut vault = Vault::open(&database, "native-setup-qualification", &keys).unwrap();
    if crash.is_some() {
        let mut recovery = OsNativeRecoveryIo::new(|identity, _| {
            assert_eq!(
                identity,
                RecoverySandboxIdentity::Windows {
                    moniker: "context-relay.native.00000000000000000000000000000000".into(),
                    sid: "S-1-15-2-1-2-3-4-5-6-7".into(),
                }
            );
            Ok::<(), BoundaryError>(())
        });
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
    let adapter = discover(&project, project_id, NOW + 2);
    if committed {
        assert!(
            adapter
                .probe_managed_declaration(&mut CodexProcessRunner)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            adapter
                .saved_memory_hook_approval(&wire_path(&bridge))
                .unwrap()
                .session_start,
            super::hook_approval::SavedHookApproval::NeedsApproval
        );
        let mut executor = Executor {
            locks: &locks,
            crash: None,
            calls: 0,
        };
        BridgeInstallService::persisted(&mut vault)
            .apply(&setup.plan_id, NOW + 2, &mut executor)
            .unwrap();
        assert_eq!(executor.calls, 0, "reapply must not execute");
        BridgeInstallService::persisted(&mut vault)
            .rollback(&setup.plan_id, NOW + 3, &mut executor)
            .unwrap();
        assert_eq!(executor.calls, 1);
    }
    for (path, state) in originals {
        // Reading a file can advance NTFS last-access time. Compare the native
        // boundary's complete restorable content/metadata fingerprint.
        assert_eq!(
            OsNativeFileSystem::new()
                .snapshot(&path)
                .unwrap()
                .state()
                .fingerprint(),
            state.fingerprint(),
            "restorable content and metadata: {}",
            path.display()
        );
    }
    assert!(
        discover(&project, project_id, NOW + 4)
            .probe_managed_declaration(&mut CodexProcessRunner)
            .unwrap()
            .is_none()
    );
    assert!(vault.native_memory_ledgers().unwrap().is_empty());
    assert_eq!(
        fs::read(config.join("memories/MEMORY.md")).unwrap(),
        b"native memory canary\n"
    );
    assert_eq!(
        fs::read(config.join("memories/memory_summary.md")).unwrap(),
        b"native summary canary\n"
    );
    assert!(!config.join(".personality_migration").exists());
    println!("native setup/vault reopen/rediscovery/reapply/Undo: {name}");
}
