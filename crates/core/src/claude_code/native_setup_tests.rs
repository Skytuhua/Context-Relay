//! Real Windows x64 CLI qualification through the production version gate.
use super::*;
use crate::{
    mcp::install::{BridgeExecutable, attest_bridge_executable},
    native_transaction::{
        ApprovedInput, SidecarBinding, TransactionStep,
        engine::{FaultHook, RestrictedExecutor},
        filesystem::OsNativeTransactionFileSystem,
        open_plan,
        recovery::{
            CliRecoveryRestore, NativeCliRecoveryIo, OsNativeRecoveryIo, bind_cli_recovery_plan,
            recover_native_transactions_with_cli,
        },
    },
    setup::{
        BridgeExecutionError, BridgeInstallService, BridgeLocator, BridgePlanExecutor,
        NativeEngineBridgePlanExecutor, RegisteredProject,
    },
    vault::{
        BeforeImagePolicy, DatabaseKeyStore, NativeCliWalRecord, NativeSandboxIdentity,
        SetupPlanLifecycle, Vault, VaultError,
    },
};
use std::{panic::AssertUnwindSafe, sync::Mutex};
use zeroize::Zeroizing;

const PINNED_HASH: &str = "7ff0787ebdc19fc509ccea8886ebf6a53ad8213407fa3a2b7c6d1446efc419f6";
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
// Production's fixed bridge validator uses no generator or staged source inputs.
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
        assert_ne!(self.0, Some(step), "injected panic at {step:?}");
        Ok(())
    }
}
struct Executor<'a> {
    locks: &'a Path,
    crash: Option<TransactionStep>,
    calls: usize,
}
impl BridgePlanExecutor for Executor<'_> {
    fn execute(
        &mut self,
        vault: &mut Vault,
        plan: &NativeTransactionPlan,
        sealed: &[u8],
        created: u64,
        now: u64,
    ) -> Result<(), BridgeExecutionError> {
        self.calls += 1;
        assert_eq!(plan.setup.harness_version, "2.1.202");
        assert_eq!(plan.cli_mutations.len(), 1);
        assert!(plan.staged_inputs.is_empty());
        let mut adapter = discover_plan(plan, now);
        let cli_adapter = adapter.clone();
        let mut cli = cli_adapter.cli_executor();
        let mut restricted = InProcess(plan);
        let mut filesystem = OsNativeTransactionFileSystem::new(*plan.setup.plan_id.as_bytes());
        NativeEngineBridgePlanExecutor::new(
            &mut adapter,
            &mut restricted,
            &mut filesystem,
            &mut Crash(self.crash),
            &mut cli,
            self.locks,
            NativeSandboxIdentity::Windows {
                moniker: "context-relay.native.00000000000000000000000000000000".into(),
                sid: b"S-1-15-2-1-2-3-4-5-6-7".to_vec(),
            },
            BeforeImagePolicy::default(),
            HybridLogicalClock::new(now, 0, adapter_device()),
        )
        .execute(vault, plan, sealed, created, now)
    }
}
struct Recovery;
impl NativeCliRecoveryIo for Recovery {
    fn probe_cli_declaration(
        &mut self,
        sealed: &[u8],
        row: &NativeCliWalRecord,
    ) -> Result<Option<Sha256Digest>, BoundaryError> {
        let bound = bind_cli_recovery_plan(sealed, std::slice::from_ref(row))?;
        let mut adapter = discover_plan(&bound.plan, NOW + 2);
        adapter.reprobe_live_state(&bound.plan)?;
        adapter
            .cli_executor()
            .probe_cli_mutation(&bound.mutations[0])
    }
    fn restore_cli_mutation_if_matches(
        &mut self,
        sealed: &[u8],
        row: &NativeCliWalRecord,
    ) -> Result<CliRecoveryRestore, BoundaryError> {
        let bound = bind_cli_recovery_plan(sealed, std::slice::from_ref(row))?;
        let mut adapter = discover_plan(&bound.plan, NOW + 2);
        adapter.reprobe_live_state(&bound.plan)?;
        adapter
            .cli_executor()
            .restore_cli_mutation_if_matches(&bound.mutations[0])
            .map(|outcome| {
                if outcome.restored {
                    CliRecoveryRestore::Restored
                } else {
                    CliRecoveryRestore::Conflict
                }
            })
    }
    fn finish_committed_cli_mutations(
        &mut self,
        sealed: &[u8],
        rows: &[NativeCliWalRecord],
    ) -> Result<(), BoundaryError> {
        let bound = bind_cli_recovery_plan(sealed, rows)?;
        let mut adapter = discover_plan(&bound.plan, NOW + 2);
        adapter.reprobe_live_state(&bound.plan)?;
        adapter
            .cli_executor()
            .finish_committed_cli_mutations(&bound.mutations)
    }
}
fn adapter_device() -> DeviceId {
    "018f22e2-79b0-7cc8-98c4-dc0c0c073982".parse().unwrap()
}
fn discover_plan(plan: &NativeTransactionPlan, now: u64) -> ClaudeCodeAdapter {
    let projects = plan
        .setup
        .target_scopes
        .iter()
        .filter_map(|scope| match scope {
            NativeScope::Project { project_id, root } => {
                Some((*project_id, decode_wire_path(root).unwrap()))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(projects.len(), 1);
    discover(&projects[0].1, projects[0].0, now)
}
fn discover(project: &Path, id: ProjectId, now: u64) -> ClaudeCodeAdapter {
    let adapter = ClaudeCodeAdapter::discover(
        project,
        id,
        adapter_device(),
        HybridLogicalClock::new(now, 0, adapter_device()),
    )
    .unwrap();
    assert_eq!(adapter.layout.version, "2.1.202");
    assert_eq!(
        serde_json::to_value(adapter.executable_hash).unwrap(),
        PINNED_HASH
    );
    assert_eq!(adapter.capability(), CapabilityLevel::Full);
    adapter
}

#[test]
#[ignore = "explicit pinned Claude CLI; synthetic profiles, credentials and native transactions only"]
fn pinned_claude_native_setup_restart_reapply_undo_and_recovery() {
    run_native_cases(&[
        "ordinary",
        "after payload 專案 O'Brien",
        "after CLI 專案",
        "after commit ‘quoted’",
    ]);
}

#[test]
#[ignore = "explicit pinned Claude CLI; fresh synthetic settings and state files only"]
fn pinned_claude_fresh_settings_setup_restart_and_undo() {
    run_native_cases(&["fresh files"]);
}

#[test]
#[ignore = "explicit pinned Claude CLI; synthetic project without a .claude directory"]
fn pinned_claude_missing_project_directory_setup_restart_and_undo() {
    run_native_cases(&["missing project directory"]);
}

fn run_native_cases(names: &[&str]) {
    let executable =
        PathBuf::from(env::var_os("CONTEXT_RELAY_TEST_CLAUDE_EXE").expect("explicit Claude"));
    if env::var_os("CONTEXT_RELAY_CLAUDE_SETUP_CHILD").is_none() {
        for name in names {
            let outer = tempfile::tempdir().unwrap();
            let root = fs::canonicalize(outer.path()).unwrap().join(name);
            for directory in ["home/.claude", "custom claude", "scratch", "program files"] {
                fs::create_dir_all(root.join(directory)).unwrap();
            }
            fs::write(
                root.join("home/.claude/settings.json"),
                b"{\"ambientCanary\":true}\n",
            )
            .unwrap();
            fs::write(
                root.join("home/.claude.json"),
                b"{\"ambientCanary\":true}\n",
            )
            .unwrap();
            let stdout = outer.path().join("stdout");
            let stderr = outer.path().join("stderr");
            let mut child = Command::new(env::current_exe().unwrap());
            child.env_clear();
            for key in ["SystemRoot", "WINDIR"] {
                if let Some(value) = env::var_os(key) {
                    child.env(key, value);
                }
            }
            child.args(["--exact", "claude_code::native_setup_tests::pinned_claude_native_setup_restart_reapply_undo_and_recovery", "--ignored", "--nocapture"])
                .env("CONTEXT_RELAY_CLAUDE_SETUP_CHILD", "1")
                .env("CONTEXT_RELAY_TEST_CLAUDE_EXE", &executable)
                .env("CLAUDE_CONFIG_DIR", root.join("custom claude"))
                .env("HOME", root.join("home")).env("USERPROFILE", root.join("home"))
                .env("PATH", executable.parent().unwrap())
                .env("ProgramFiles", root.join("program files"))
                .env("TEMP", root.join("scratch")).env("TMP", root.join("scratch"))
                .current_dir(&root).stdin(Stdio::piped())
                .stdout(fs::File::create(&stdout).unwrap()).stderr(fs::File::create(&stderr).unwrap());
            let status =
                crate::test_windows_process::run_in_owned_job(&mut child, Duration::from_secs(240));
            assert!(
                status.is_ok_and(|status| status.success()),
                "stdout: {}\nstderr: {}",
                fs::read_to_string(&stdout).unwrap(),
                fs::read_to_string(&stderr).unwrap()
            );
            for path in ["home/.claude/settings.json", "home/.claude.json"] {
                assert_eq!(
                    fs::read(root.join(path)).unwrap(),
                    b"{\"ambientCanary\":true}\n"
                );
            }
            println!("{}", fs::read_to_string(stdout).unwrap());
        }
        return;
    }
    let mut gate = String::new();
    std::io::stdin().read_to_string(&mut gate).unwrap();
    assert_eq!(gate, "run");
    let digest: Sha256Digest = serde_json::from_value(Value::String(PINNED_HASH.into())).unwrap();
    let candidate = find_executable().unwrap();
    assert_eq!(
        fs::canonicalize(&candidate).unwrap(),
        fs::canonicalize(&executable).unwrap()
    );
    let _pinned_image = open_verified_claude_executable(&candidate, digest).unwrap();
    let root = fs::canonicalize(env::current_dir().unwrap()).unwrap();
    let crash = match root.file_name().unwrap().to_str().unwrap() {
        "ordinary" | "fresh files" | "missing project directory" => None,
        "after payload 專案 O'Brien" => Some(TransactionStep::WritePayloads),
        "after CLI 專案" => Some(TransactionStep::WriteActivationReferences),
        "after commit ‘quoted’" => Some(TransactionStep::CommitOwnershipAndReceipt),
        _ => panic!("unknown case"),
    };
    run_case(&root, crash);
}

fn run_case(root: &Path, crash: Option<TransactionStep>) {
    let config = root.join("custom claude");
    let project = root.join("project");
    let locks = root.join("vault");
    let missing_project_directory = root.file_name().unwrap() == "missing project directory";
    for path in [project.clone(), locks.clone()] {
        fs::create_dir_all(path).unwrap();
    }
    if !missing_project_directory {
        fs::create_dir(project.join(".claude")).unwrap();
    }
    let project = fs::canonicalize(project).unwrap();
    let fresh = root.file_name().unwrap() == "fresh files" || missing_project_directory;
    let state = config.join(".claude.json");
    let original_state = if fresh {
        None
    } else {
        fs::write(
            config.join("settings.json"),
            b"{\"env\":{\"CLAUDE_CODE_DISABLE_AUTO_MEMORY\":\"false\"},\"keepUser\":true}\n",
        )
        .unwrap();
        fs::write(
            project.join(".claude/settings.json"),
            b"{\"autoMemoryEnabled\":false,\"keepProject\":true}\n",
        )
        .unwrap();
        fs::write(config.join("CLAUDE.md"), b"Existing user instruction\n").unwrap();
        fs::write(&state, b"{\"keepState\":true,\"mcpServers\":{\"other\":{\"type\":\"stdio\",\"command\":\"inert-other\",\"args\":[]}}}\n").unwrap();
        Some(serde_json::from_slice::<Value>(&fs::read(&state).unwrap()).unwrap())
    };
    let bridge = root.join("inert context bridge.exe");
    fs::write(&bridge, b"qualification marker only; never execute").unwrap();
    let id: ProjectId = "018f22e2-79b0-7cc8-98c4-dc0c0c073981".parse().unwrap();
    let adapter = discover(&project, id, NOW);
    if missing_project_directory {
        let capabilities = adapter.native_memory_capabilities().unwrap();
        assert!(matches!(
            capabilities.disable,
            NativeMemoryDisable::WatchOnly
        ));
        assert!(!capabilities.sources.is_empty());
        assert!(!project.join(".claude").exists());
    }
    let keys = Keys::default();
    let database = locks.join("vault.db");
    let mut vault = Vault::open(&database, "claude-native-setup", &keys).unwrap();
    let setup = BridgeInstallService::new(
        &mut vault,
        adapter,
        Locator(bridge),
        adapter_device(),
        HybridLogicalClock::new(NOW, 0, adapter_device()),
    )
    .preview(
        Some(&RegisteredProject {
            project_id: id,
            root: wire_path(&project),
        }),
        NOW,
    )
    .unwrap();
    let opened = open_plan(&vault.setup_plan(&setup.plan_id).unwrap().unwrap().payload).unwrap();
    if missing_project_directory {
        assert!(
            !project.join(".claude").exists(),
            "preview created a directory"
        );
        assert!(!opened.plan.native_memory_registrations.is_empty());
        assert!(opened.plan.mutations.iter().all(|mutation| {
            !decode_wire_path(&mutation.target)
                .unwrap()
                .starts_with(project.join(".claude"))
        }));
    }
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
    assert!(!originals.is_empty());
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
    drop(vault);
    let mut vault = Vault::open(&database, "claude-native-setup", &keys).unwrap();
    if crash.is_some() {
        let mut recovery = OsNativeRecoveryIo::new(|identity, _| {
            assert!(
                matches!(identity, crate::native_transaction::recovery::RecoverySandboxIdentity::Windows { ref moniker, .. } if moniker == "context-relay.native.00000000000000000000000000000000")
            );
            Ok::<(), BoundaryError>(())
        });
        let summary =
            recover_native_transactions_with_cli(&mut vault, &mut recovery, &mut Recovery).unwrap();
        assert_eq!(summary.recovered(), 1);
        assert_eq!(summary.conflicts, 0);
        BridgeInstallService::persisted(&mut vault)
            .reconcile_after_native_recovery()
            .unwrap();
    }
    let committed = crash.is_none() || crash == Some(TransactionStep::CommitOwnershipAndReceipt);
    assert_eq!(
        vault.setup_plan(&setup.plan_id).unwrap().unwrap().lifecycle,
        if committed {
            SetupPlanLifecycle::Applied
        } else {
            SetupPlanLifecycle::ApplyRestored
        }
    );
    if committed {
        if missing_project_directory {
            assert!(
                !project.join(".claude").exists(),
                "setup created a directory"
            );
        }
        assert!(
            discover(&project, id, NOW + 2)
                .probe_managed_declaration()
                .unwrap()
                .is_some()
        );
        let mut executor = Executor {
            locks: &locks,
            crash: None,
            calls: 0,
        };
        BridgeInstallService::persisted(&mut vault)
            .apply(&setup.plan_id, NOW + 2, &mut executor)
            .unwrap();
        assert_eq!(executor.calls, 0);
        BridgeInstallService::persisted(&mut vault)
            .rollback(&setup.plan_id, NOW + 3, &mut executor)
            .unwrap();
        assert_eq!(executor.calls, 1);
    }
    for (path, state) in originals {
        assert_eq!(
            OsNativeFileSystem::new()
                .snapshot(&path)
                .unwrap()
                .state()
                .fingerprint(),
            state.fingerprint(),
            "{}",
            path.display()
        );
    }
    assert!(
        discover(&project, id, NOW + 4)
            .probe_managed_declaration()
            .unwrap()
            .is_none()
    );
    let final_state: Value = serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
    if let Some(original_state) = original_state {
        assert_eq!(final_state["keepState"], original_state["keepState"]);
        assert_eq!(final_state["mcpServers"], original_state["mcpServers"]);
    } else {
        assert!(final_state.get("mcpServers").is_none_or(|servers| {
            servers
                .as_object()
                .is_some_and(|servers| servers.is_empty())
        }));
        assert!(!config.join("settings.json").exists());
        assert!(!project.join(".claude/settings.json").exists());
        assert!(!project.join("CLAUDE.md").exists());
    }
    assert!(vault.native_memory_ledgers().unwrap().is_empty());
    if missing_project_directory {
        assert!(!project.join(".claude").exists(), "Undo left a directory");
    }
    println!("Real Claude native save/reopen/reapply/Undo/recovery: {crash:?}");
}
