mod support;

use std::{
    cell::RefCell,
    fs,
    path::{Path, PathBuf},
    rc::Rc,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use context_relay_core::native_transaction::{
    approval_hash_v1, approval_hash_v2,
    cli::{CliMutationOutcome, CliRestoreOutcome, NativeCliExecutor},
    engine::{
        BeforeImage, BoundaryError, CheckpointAppliedAbsence, CompensationOutcome, FaultHook,
        FrozenOutput, MutationOutcome, NativeAdapter, NativeFileSystem, NativeJournal,
        NativeTransactionEngine, RebindAppliedAbsence, RestrictedExecutor, RestrictedRun,
    },
    journal::VaultNativeJournal,
    model::{
        ApprovedCliMutation, ApprovedMutation, CanonicalCliDeclaration, MutationKind,
        NativeApplyReceipt, NativeObjectToken, NativeTransactionPlan, RestorableStateFingerprint,
        TransactionStep,
    },
};
use context_relay_native_runner::{
    NativeState, RuleSyncFeature, RuleSyncFeatures, RuleSyncTarget, RuntimeTarget, SidecarCommand,
    SidecarId,
};
use context_relay_protocol::{
    ApplyReceipt, ApprovalClass, CliOperation, DeviceId, HarnessId, HybridLogicalClock,
    NativePlatform, NativeScope, NetworkDelta, PermissionDelta, PlanId, SetupPlan, Sha256Digest,
    WireNativeValue,
};
use sha2::{Digest as _, Sha256};

use context_relay_core::vault::{
    BeforeImagePolicy, NativeCliWalState, NativeSandboxIdentity, NativeTransactionStatus, Vault,
};
use support::{MemoryKeyStore, TempVault};

const ID: &str = "01890f3e-1c2b-7a4d-8e5f-123456789abc";
const REAL_APPCONTAINER_SID: &[u8] =
    b"S-1-15-2-3872518810-2985098273-1912316193-2655983105-1250049442-371239648-1157085541";

struct TempLockRoot(PathBuf);

impl TempLockRoot {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "context-relay-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        fs::create_dir(&path).unwrap();
        Self(fs::canonicalize(path).unwrap())
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempLockRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn value(text: &str) -> WireNativeValue {
    WireNativeValue {
        platform: NativePlatform::Macos,
        bytes: text.as_bytes().to_vec(),
        display: None,
    }
}

fn declaration(harness: HarnessId, body: &str) -> CanonicalCliDeclaration {
    let canonical_body = serde_json::to_string(&serde_json::json!({
        "args": ["--harness", "codex"],
        "command": body,
        "type": "stdio",
    }))
    .unwrap();
    CanonicalCliDeclaration {
        harness,
        server_name: "context-relay".to_owned(),
        fingerprint: Sha256Digest(Sha256::digest(canonical_body.as_bytes()).into()),
        canonical_body,
    }
}

fn operation(action: &str) -> CliOperation {
    CliOperation {
        executable: value("/fixture/codex"),
        arguments: vec![value("mcp"), value(action), value("context-relay")],
        timeout_ms: 30_000,
    }
}

fn cli_mutation(index: u8) -> ApprovedCliMutation {
    ApprovedCliMutation {
        stable_id: "b5be495e-d4ee-7a2e-a29e-b589ebc5d7fd".to_owned(),
        expected: None,
        intended: Some(declaration(
            HarnessId::Codex,
            &format!("/fixture/bridge-{index}"),
        )),
        forward: vec![operation("add")],
        rollback: vec![operation("remove")],
    }
}

fn native_mutation() -> ApprovedMutation {
    let state = NativeState::absent(22, 2);
    ApprovedMutation {
        target: value("/fixture/native"),
        kind: MutationKind::ActivationReference,
        content: state.encode_v1().unwrap(),
        expected: RestorableStateFingerprint(Sha256Digest([21; 32])),
        intended: RestorableStateFingerprint(Sha256Digest(state.fingerprint())),
    }
}

fn plan(cli_count: u8, with_native: bool) -> NativeTransactionPlan {
    plan_with_approval(cli_count, with_native, if cli_count == 0 { 1 } else { 2 })
}

fn plan_with_approval(
    cli_count: u8,
    with_native: bool,
    approval_version: u32,
) -> NativeTransactionPlan {
    let cli_mutations = (0..cli_count).map(cli_mutation).collect::<Vec<_>>();
    let setup = SetupPlan {
        plan_id: PlanId::from_str(ID).unwrap(),
        harness: HarnessId::Codex,
        harness_profile: None,
        adapter_version: 1,
        executable_path: value("/fixture/codex"),
        executable_hash: Sha256Digest([1; 32]),
        harness_version: "1.0.0".to_owned(),
        target_scopes: vec![NativeScope::Global],
        expected_native_digests: vec![],
        semantic_changes: vec![],
        cli_operations: cli_mutations
            .iter()
            .flat_map(|mutation| mutation.forward.clone())
            .collect(),
        package_artifacts: vec![],
        permission_delta: PermissionDelta {
            added: vec![],
            removed: vec![],
        },
        network_delta: NetworkDelta {
            added: vec![],
            removed: vec![],
        },
        scanner_report_hash: Sha256Digest([2; 32]),
        rulesync_version: "14.0.1".to_owned(),
        rulesync_hash: Sha256Digest([3; 32]),
        approval_class: ApprovalClass::Active,
        expires_at: 2_000_000_000_000,
        batch_hash: Sha256Digest([0; 32]),
    };
    let mut plan = NativeTransactionPlan {
        setup,
        approval_version,
        helper_policy_version: 1,
        manifest_schema_version: 1,
        manifest_digest: Sha256Digest([4; 32]),
        helper_hash: Sha256Digest([5; 32]),
        sidecars: vec![context_relay_core::native_transaction::SidecarBinding {
            id: SidecarId::RuleSync,
            target: RuntimeTarget::MacosArm64,
            version: "14.0.1".to_owned(),
            closure_hash: Sha256Digest([9; 32]),
            source_bundle_hash: Sha256Digest([10; 32]),
            build_toolchain_hash: Sha256Digest([11; 32]),
            command_template_digest: Sha256Digest([12; 32]),
            command: SidecarCommand::RuleSyncGenerate {
                target: RuleSyncTarget::CodexCli,
                features: RuleSyncFeatures::new(&[RuleSyncFeature::Rules]).unwrap(),
            },
        }],
        structural_allowlist_hash: Sha256Digest([6; 32]),
        staged_inputs: vec![],
        expected_semantic_output_hash: Sha256Digest([7; 32]),
        scanner_result_hash: Sha256Digest([8; 32]),
        mutations: with_native.then(native_mutation).into_iter().collect(),
        cli_mutations,
        native_memory_registrations: vec![],
        ownership_changes: vec![],
    };
    plan.setup.batch_hash = match approval_version {
        1 => approval_hash_v1(&plan).unwrap(),
        2 => approval_hash_v2(&plan).unwrap(),
        _ => unreachable!(),
    };
    plan
}

#[derive(Clone, Copy)]
enum CommandBehavior {
    SuccessIntended,
    SuccessExpected,
    ErrorExpected,
    ErrorIntended,
    ErrorUnknown,
}

struct SharedState {
    events: Vec<String>,
    live: Vec<Option<Sha256Digest>>,
    behavior: CommandBehavior,
    validation_fails: bool,
    diverge_before_restore: bool,
    restore_errors: bool,
    rollback_commands: usize,
    entered: Vec<TransactionStep>,
}

impl SharedState {
    fn new(cli_count: usize, behavior: CommandBehavior) -> Self {
        Self {
            events: vec![],
            live: vec![None; cli_count],
            behavior,
            validation_fails: false,
            diverge_before_restore: false,
            restore_errors: false,
            rollback_commands: 0,
            entered: vec![],
        }
    }
}

type Shared = Rc<RefCell<SharedState>>;

struct Adapter {
    state: Shared,
}

impl NativeAdapter for Adapter {
    fn reprobe_live_state(&mut self, _plan: &NativeTransactionPlan) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn compare_approved_digests(
        &mut self,
        _plan: &NativeTransactionPlan,
    ) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn validate_staged_output(
        &mut self,
        plan: &NativeTransactionPlan,
        _run: &RestrictedRun,
    ) -> Result<FrozenOutput, BoundaryError> {
        Ok(FrozenOutput {
            staged_output_hash: plan.expected_semantic_output_hash,
            scanner_result_hash: plan.scanner_result_hash,
        })
    }

    fn validate_effective(
        &mut self,
        _plan: &NativeTransactionPlan,
        _receipt: &ApplyReceipt,
    ) -> Result<(), BoundaryError> {
        self.state
            .borrow_mut()
            .events
            .push("validate-effective".to_owned());
        let mut state = self.state.borrow_mut();
        if state.diverge_before_restore {
            state.live.fill(Some(Sha256Digest([99; 32])));
        }
        if state.validation_fails {
            Err(BoundaryError::new("effective validation failed"))
        } else {
            Ok(())
        }
    }
}

struct Executor;

impl RestrictedExecutor for Executor {
    fn copy_allowlisted_inputs(
        &mut self,
        _inputs: &[context_relay_core::native_transaction::ApprovedInput],
    ) -> Result<(), BoundaryError> {
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
        _sidecars: &[context_relay_core::native_transaction::SidecarBinding],
    ) -> Result<RestrictedRun, BoundaryError> {
        Ok(RestrictedRun {
            staged_output_hash: Sha256Digest([7; 32]),
            scanner_result_hash: Sha256Digest([8; 32]),
        })
    }

    fn reject_unsafe_topology(&mut self) -> Result<(), BoundaryError> {
        Ok(())
    }
}

struct CliExecutor {
    state: Shared,
}

fn expected(mutation: &ApprovedCliMutation) -> Option<Sha256Digest> {
    mutation
        .expected
        .as_ref()
        .map(|declaration| declaration.fingerprint)
}

fn intended(mutation: &ApprovedCliMutation) -> Option<Sha256Digest> {
    mutation
        .intended
        .as_ref()
        .map(|declaration| declaration.fingerprint)
}

fn mutation_index(mutation: &ApprovedCliMutation) -> usize {
    let _ = mutation;
    0
}

impl NativeCliExecutor for CliExecutor {
    fn probe_cli_mutation(
        &mut self,
        mutation: &ApprovedCliMutation,
    ) -> Result<Option<Sha256Digest>, BoundaryError> {
        Ok(self.state.borrow().live[mutation_index(mutation)])
    }

    fn compare_cli_targets(
        &mut self,
        mutations: &[ApprovedCliMutation],
    ) -> Result<(), BoundaryError> {
        self.state
            .borrow_mut()
            .events
            .push("compare-cli".to_owned());
        for mutation in mutations {
            let index = mutation_index(mutation);
            if self.state.borrow().live[index] != expected(mutation) {
                return Err(BoundaryError::new("CLI expected state mismatch"));
            }
        }
        Ok(())
    }

    fn apply_cli_mutation(
        &mut self,
        mutation: &ApprovedCliMutation,
    ) -> Result<CliMutationOutcome, BoundaryError> {
        let index = mutation_index(mutation);
        self.state
            .borrow_mut()
            .events
            .push(format!("command:{}", mutation.stable_id));
        let behavior = self.state.borrow().behavior;
        let (command_error, live) = match behavior {
            CommandBehavior::SuccessIntended => (None, intended(mutation)),
            CommandBehavior::SuccessExpected => (None, expected(mutation)),
            CommandBehavior::ErrorExpected => (
                Some(BoundaryError::new("command failed")),
                expected(mutation),
            ),
            CommandBehavior::ErrorIntended => (
                Some(BoundaryError::new("command failed")),
                intended(mutation),
            ),
            CommandBehavior::ErrorUnknown => (
                Some(BoundaryError::new("command failed")),
                Some(Sha256Digest([98; 32])),
            ),
        };
        self.state.borrow_mut().live[index] = live;
        Ok(CliMutationOutcome {
            resulting_fingerprint: live,
            command_error,
        })
    }

    fn restore_cli_mutation_if_matches(
        &mut self,
        mutation: &ApprovedCliMutation,
    ) -> Result<CliRestoreOutcome, BoundaryError> {
        let index = mutation_index(mutation);
        self.state
            .borrow_mut()
            .events
            .push(format!("restore-check:{}", mutation.stable_id));
        if self.state.borrow().restore_errors {
            return Err(BoundaryError::new("CLI restore reprobe failed"));
        }
        if self.state.borrow().live[index] != intended(mutation) {
            return Ok(CliRestoreOutcome {
                restored: false,
                resulting_fingerprint: self.state.borrow().live[index],
            });
        }
        let mut state = self.state.borrow_mut();
        state.rollback_commands += 1;
        state
            .events
            .push(format!("rollback:{}", mutation.stable_id));
        state.live[index] = expected(mutation);
        Ok(CliRestoreOutcome {
            restored: true,
            resulting_fingerprint: expected(mutation),
        })
    }

    fn finish_committed_cli_mutations(
        &mut self,
        _mutations: &[ApprovedCliMutation],
    ) -> Result<(), BoundaryError> {
        self.state.borrow_mut().events.push("finish-cli".to_owned());
        Ok(())
    }
}

struct FileSystem {
    state: Shared,
    applied: bool,
}

impl NativeFileSystem for FileSystem {
    fn create_before_images(
        &mut self,
        mutations: &[ApprovedMutation],
    ) -> Result<Vec<BeforeImage>, BoundaryError> {
        Ok(mutations
            .iter()
            .enumerate()
            .map(|(index, mutation)| BeforeImage {
                id: format!("before-{index}"),
                target: mutation.target.clone(),
                object_token: NativeObjectToken {
                    volume: vec![1],
                    object: vec![2],
                    topology: vec![3],
                },
                fingerprint: mutation.expected.clone(),
                encrypted_state: vec![4],
            })
            .collect())
    }

    fn record_native_metadata(&mut self, _images: &[BeforeImage]) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn compare_and_swap_targets(
        &mut self,
        _mutations: &[ApprovedMutation],
    ) -> Result<(), BoundaryError> {
        self.state
            .borrow_mut()
            .events
            .push("compare-native".to_owned());
        Ok(())
    }

    fn apply_mutation(
        &mut self,
        _transaction_nonce: &[u8; 16],
        mutation: &ApprovedMutation,
        persist_candidate: &mut dyn FnMut(&NativeObjectToken) -> Result<(), BoundaryError>,
    ) -> Result<MutationOutcome, BoundaryError> {
        self.state
            .borrow_mut()
            .events
            .push("apply-native".to_owned());
        let token = NativeObjectToken {
            volume: vec![5],
            object: vec![6],
            topology: vec![7],
        };
        persist_candidate(&token)?;
        self.applied = true;
        Ok(MutationOutcome {
            wrote: true,
            resulting_fingerprint: mutation.intended.clone(),
        })
    }

    fn mutation_provenance(&self, _mutation: &ApprovedMutation) -> Option<NativeObjectToken> {
        self.applied.then(|| NativeObjectToken {
            volume: vec![5],
            object: vec![6],
            topology: vec![7],
        })
    }

    fn restore_matching_applied_targets(
        &mut self,
        _transaction_nonce: &[u8; 16],
        persist_restored_candidate: &mut dyn FnMut(
            usize,
            &NativeObjectToken,
        ) -> Result<(), BoundaryError>,
        _checkpoint_applied_absence: &mut CheckpointAppliedAbsence<'_>,
        _rebind_applied_absence: &mut RebindAppliedAbsence<'_>,
    ) -> Result<CompensationOutcome, BoundaryError> {
        self.state
            .borrow_mut()
            .events
            .push("restore-native".to_owned());
        if self.applied {
            persist_restored_candidate(
                0,
                &NativeObjectToken {
                    volume: vec![8],
                    object: vec![9],
                    topology: vec![10],
                },
            )?;
        }
        Ok(CompensationOutcome::default())
    }

    fn finish_committed_targets(
        &mut self,
        _transaction_nonce: &[u8; 16],
    ) -> Result<(), BoundaryError> {
        self.state
            .borrow_mut()
            .events
            .push("finish-native".to_owned());
        Ok(())
    }
}

struct Journal {
    state: Shared,
}

impl NativeJournal for Journal {
    fn acquire_lock_and_begin(
        &mut self,
        _plan: &NativeTransactionPlan,
    ) -> Result<(), BoundaryError> {
        self.state
            .borrow_mut()
            .entered
            .push(TransactionStep::AcquireLock);
        Ok(())
    }

    fn enter_step(&mut self, step: TransactionStep) -> Result<(), BoundaryError> {
        self.state.borrow_mut().entered.push(step);
        Ok(())
    }

    fn complete_step(&mut self, _step: TransactionStep) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn put_before_images(&mut self, _images: &[BeforeImage]) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn prepare_mutation(
        &mut self,
        _index: usize,
        _mutation: &ApprovedMutation,
    ) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn mark_mutation_applied(
        &mut self,
        _index: usize,
        _mutation: &ApprovedMutation,
        _outcome: &MutationOutcome,
        _applied_token: Option<&NativeObjectToken>,
    ) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn record_mutation_candidate(
        &mut self,
        _index: usize,
        _mutation: &ApprovedMutation,
        _candidate_token: &NativeObjectToken,
    ) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn mark_mutation_conflict(
        &mut self,
        _index: usize,
        _applied_token: &NativeObjectToken,
    ) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn mark_mutation_applied_for_recovery(
        &mut self,
        _index: usize,
        _mutation: &ApprovedMutation,
        _applied_token: &NativeObjectToken,
    ) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn record_mutation_restored_candidate(
        &mut self,
        _index: usize,
        _candidate_token: &NativeObjectToken,
    ) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn checkpoint_mutation_applied_absence(
        &mut self,
        _index: usize,
        _later_index: usize,
        _expected_old_token: &NativeObjectToken,
        _new_token: &NativeObjectToken,
    ) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn rebind_mutation_applied_absence(
        &mut self,
        _index: usize,
        _later_index: usize,
        _expected_old_token: &NativeObjectToken,
        _new_token: &NativeObjectToken,
    ) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn prepare_cli_mutation(
        &mut self,
        _index: usize,
        mutation: &ApprovedCliMutation,
    ) -> Result<(), BoundaryError> {
        self.state
            .borrow_mut()
            .events
            .push(format!("wal-prepare:{}", mutation.stable_id));
        Ok(())
    }

    fn mark_cli_mutation_applied(
        &mut self,
        _index: usize,
        mutation: &ApprovedCliMutation,
    ) -> Result<(), BoundaryError> {
        self.state
            .borrow_mut()
            .events
            .push(format!("wal-applied:{}", mutation.stable_id));
        Ok(())
    }

    fn mark_cli_mutation_no_write(
        &mut self,
        _index: usize,
        mutation: &ApprovedCliMutation,
    ) -> Result<(), BoundaryError> {
        self.state
            .borrow_mut()
            .events
            .push(format!("wal-no-write:{}", mutation.stable_id));
        Ok(())
    }

    fn prepare_cli_restore(
        &mut self,
        _index: usize,
        mutation: &ApprovedCliMutation,
    ) -> Result<(), BoundaryError> {
        self.state
            .borrow_mut()
            .events
            .push(format!("wal-restore-prepare:{}", mutation.stable_id));
        Ok(())
    }

    fn mark_cli_mutation_restored(
        &mut self,
        _index: usize,
        mutation: &ApprovedCliMutation,
    ) -> Result<(), BoundaryError> {
        self.state
            .borrow_mut()
            .events
            .push(format!("wal-restored:{}", mutation.stable_id));
        Ok(())
    }

    fn mark_cli_mutation_conflict(
        &mut self,
        _index: usize,
        mutation: &ApprovedCliMutation,
    ) -> Result<(), BoundaryError> {
        self.state
            .borrow_mut()
            .events
            .push(format!("wal-conflict:{}", mutation.stable_id));
        Ok(())
    }

    fn prepare_compensation(&mut self) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn commit_native_transaction(
        &mut self,
        _plan: &NativeTransactionPlan,
        _receipt: &NativeApplyReceipt,
    ) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn finish_committed(&mut self) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn finish_compensated(
        &mut self,
        _conflict_target_sequences: &[u32],
    ) -> Result<(), BoundaryError> {
        Ok(())
    }
}

struct Hook;

impl FaultHook for Hook {
    fn after_step(&mut self, _step: TransactionStep) -> Result<(), BoundaryError> {
        Ok(())
    }
}

fn clock() -> HybridLogicalClock {
    HybridLogicalClock::new(1_900_000_000_000, 0, DeviceId::from_str(ID).unwrap())
}

fn run(
    plan: &NativeTransactionPlan,
    state: Shared,
) -> Result<NativeApplyReceipt, context_relay_core::native_transaction::engine::TransactionError> {
    let mut adapter = Adapter {
        state: state.clone(),
    };
    let mut executor = Executor;
    let mut cli = CliExecutor {
        state: state.clone(),
    };
    let mut filesystem = FileSystem {
        state: state.clone(),
        applied: false,
    };
    let mut journal = Journal {
        state: state.clone(),
    };
    let mut hook = Hook;
    NativeTransactionEngine::new_with_cli(
        &mut adapter,
        &mut executor,
        &mut filesystem,
        &mut journal,
        &mut hook,
        &mut cli,
    )
    .apply(plan, 1_900_000_000_000, clock())
}

#[test]
fn expected_state_mismatch_rejects_before_any_cli_command() {
    let plan = plan(1, false);
    let state = Rc::new(RefCell::new(SharedState::new(
        1,
        CommandBehavior::SuccessIntended,
    )));
    state.borrow_mut().live[0] = Some(Sha256Digest([91; 32]));

    assert!(run(&plan, state.clone()).is_err());
    assert!(
        !state
            .borrow()
            .events
            .iter()
            .any(|event| event.starts_with("command:"))
    );
}

#[test]
fn cli_wal_is_prepared_before_the_forward_command() {
    let plan = plan(1, false);
    let state = Rc::new(RefCell::new(SharedState::new(
        1,
        CommandBehavior::SuccessIntended,
    )));

    run(&plan, state.clone()).unwrap();
    let events = &state.borrow().events;
    let wal = events
        .iter()
        .position(|event| event.starts_with("wal-prepare:"))
        .unwrap();
    let command = events
        .iter()
        .position(|event| event.starts_with("command:"))
        .unwrap();
    assert!(wal < command);
}

#[test]
fn successful_command_still_requires_the_intended_reprobe_state() {
    let plan = plan(1, false);
    let state = Rc::new(RefCell::new(SharedState::new(
        1,
        CommandBehavior::SuccessExpected,
    )));

    assert!(run(&plan, state.clone()).is_err());
    assert!(
        state
            .borrow()
            .events
            .iter()
            .any(|event| event.starts_with("wal-conflict:"))
    );
}

#[test]
fn command_error_with_expected_state_records_no_write_without_rollback_command() {
    let plan = plan(1, false);
    let state = Rc::new(RefCell::new(SharedState::new(
        1,
        CommandBehavior::ErrorExpected,
    )));

    assert!(run(&plan, state.clone()).is_err());
    assert!(
        state
            .borrow()
            .events
            .iter()
            .any(|event| event.starts_with("wal-no-write:"))
    );
    assert_eq!(state.borrow().rollback_commands, 0);
}

#[test]
fn command_error_with_expected_state_keeps_real_wal_prepared_through_native_compensation() {
    let plan = plan(1, true);
    let state = Rc::new(RefCell::new(SharedState::new(
        1,
        CommandBehavior::ErrorExpected,
    )));
    let path = TempVault::new("native-cli-no-write");
    let lock_root = TempLockRoot::new("native-cli-no-write-lock");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), "native-cli-no-write", &keys).unwrap();
    let mut adapter = Adapter {
        state: state.clone(),
    };
    let mut executor = Executor;
    let mut cli = CliExecutor {
        state: state.clone(),
    };
    let mut filesystem = FileSystem {
        state: state.clone(),
        applied: false,
    };
    let mut hook = Hook;
    let mut journal = VaultNativeJournal::new(
        &mut vault,
        lock_root.path(),
        "native-cli-no-write-transaction",
        NativeSandboxIdentity::Windows {
            moniker: "context-relay.native.0123456789abcdef0123456789abcdef".to_owned(),
            sid: REAL_APPCONTAINER_SID.to_vec(),
        },
        b"approved cli plan".to_vec(),
        1_900_000_000_000,
        BeforeImagePolicy::new(1024, 100),
    );

    let result = NativeTransactionEngine::new_with_cli(
        &mut adapter,
        &mut executor,
        &mut filesystem,
        &mut journal,
        &mut hook,
        &mut cli,
    )
    .apply(&plan, 1_900_000_000_000, clock());
    let error = result.unwrap_err().to_string();
    drop(journal);

    let cli_wal = vault
        .native_cli_wal("native-cli-no-write-transaction")
        .unwrap();
    assert_eq!(cli_wal.len(), 1);
    assert_eq!(cli_wal[0].state, NativeCliWalState::Prepared);
    assert_eq!(
        vault
            .native_transaction("native-cli-no-write-transaction")
            .unwrap()
            .unwrap()
            .status,
        NativeTransactionStatus::Restored,
        "{error}"
    );
    assert!(
        state
            .borrow()
            .events
            .iter()
            .any(|event| event == "restore-native")
    );
}

#[test]
fn command_error_with_intended_state_is_compensated() {
    let plan = plan(1, false);
    let state = Rc::new(RefCell::new(SharedState::new(
        1,
        CommandBehavior::ErrorIntended,
    )));

    assert!(run(&plan, state.clone()).is_err());
    assert_eq!(state.borrow().rollback_commands, 1);
    assert_eq!(state.borrow().live[0], None);
}

#[test]
fn uncertain_command_with_unknown_state_marks_conflict_without_overwrite() {
    let plan = plan(1, false);
    let state = Rc::new(RefCell::new(SharedState::new(
        1,
        CommandBehavior::ErrorUnknown,
    )));

    assert!(run(&plan, state.clone()).is_err());
    assert!(
        state
            .borrow()
            .events
            .iter()
            .any(|event| event.starts_with("wal-conflict:"))
    );
    assert_eq!(state.borrow().rollback_commands, 0);
}

#[test]
fn validation_failure_restores_cli_before_native_mutations() {
    let plan = plan(1, true);
    let state = Rc::new(RefCell::new(SharedState::new(
        1,
        CommandBehavior::SuccessIntended,
    )));
    state.borrow_mut().validation_fails = true;

    assert!(run(&plan, state.clone()).is_err());
    let events = &state.borrow().events;
    let cli = events
        .iter()
        .position(|event| event.starts_with("rollback:"))
        .unwrap();
    let native = events
        .iter()
        .position(|event| event == "restore-native")
        .unwrap();
    assert!(cli < native);
}

#[test]
fn cli_compensation_restores_the_applied_mutation() {
    let plan = plan(1, false);
    let state = Rc::new(RefCell::new(SharedState::new(
        1,
        CommandBehavior::SuccessIntended,
    )));
    state.borrow_mut().validation_fails = true;

    assert!(run(&plan, state.clone()).is_err());
    let rollbacks = state
        .borrow()
        .events
        .iter()
        .filter(|event| event.starts_with("rollback:"))
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(rollbacks, ["rollback:b5be495e-d4ee-7a2e-a29e-b589ebc5d7fd"]);
}

#[test]
fn cli_compensation_does_not_overwrite_live_divergence() {
    let plan = plan(1, false);
    let state = Rc::new(RefCell::new(SharedState::new(
        1,
        CommandBehavior::SuccessIntended,
    )));
    {
        let mut state = state.borrow_mut();
        state.validation_fails = true;
        state.diverge_before_restore = true;
    }

    assert!(run(&plan, state.clone()).is_err());
    assert_eq!(state.borrow().rollback_commands, 0);
    assert!(
        state
            .borrow()
            .events
            .iter()
            .any(|event| event.starts_with("wal-conflict:"))
    );
}

#[test]
fn cli_restore_error_marks_uncertainty_and_still_restores_native_files() {
    let plan = plan(1, true);
    let state = Rc::new(RefCell::new(SharedState::new(
        1,
        CommandBehavior::SuccessIntended,
    )));
    {
        let mut state = state.borrow_mut();
        state.validation_fails = true;
        state.restore_errors = true;
    }

    assert!(run(&plan, state.clone()).is_err());
    assert!(
        state
            .borrow()
            .events
            .iter()
            .any(|event| event.starts_with("wal-conflict:"))
    );
    assert!(
        state
            .borrow()
            .events
            .iter()
            .any(|event| event == "restore-native")
    );
}

#[test]
fn real_cli_divergence_terminalizes_conflict_and_releases_cleanup() {
    let plan = plan(1, true);
    let state = Rc::new(RefCell::new(SharedState::new(
        1,
        CommandBehavior::SuccessIntended,
    )));
    {
        let mut state = state.borrow_mut();
        state.validation_fails = true;
        state.diverge_before_restore = true;
    }
    let path = TempVault::new("native-cli-divergence");
    let lock_root = TempLockRoot::new("native-cli-divergence-lock");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), "native-cli-divergence", &keys).unwrap();
    let mut adapter = Adapter {
        state: state.clone(),
    };
    let mut executor = Executor;
    let mut cli = CliExecutor {
        state: state.clone(),
    };
    let mut filesystem = FileSystem {
        state: state.clone(),
        applied: false,
    };
    let mut hook = Hook;
    let mut journal = VaultNativeJournal::new(
        &mut vault,
        lock_root.path(),
        "native-cli-divergence-transaction",
        NativeSandboxIdentity::Windows {
            moniker: "context-relay.native.0123456789abcdef0123456789abcdef".to_owned(),
            sid: REAL_APPCONTAINER_SID.to_vec(),
        },
        b"approved cli plan".to_vec(),
        1_900_000_000_000,
        BeforeImagePolicy::new(1024, 100),
    );

    let result = NativeTransactionEngine::new_with_cli(
        &mut adapter,
        &mut executor,
        &mut filesystem,
        &mut journal,
        &mut hook,
        &mut cli,
    )
    .apply(&plan, 1_900_000_000_000, clock());
    let error = result.unwrap_err().to_string();
    drop(journal);

    let snapshot = vault
        .native_transaction("native-cli-divergence-transaction")
        .unwrap()
        .unwrap();
    assert_eq!(
        snapshot.status,
        NativeTransactionStatus::Conflict,
        "{error}"
    );
    assert_eq!((snapshot.entered_step, snapshot.current_step), (20, 20));
    assert_eq!(
        vault
            .native_cli_wal("native-cli-divergence-transaction")
            .unwrap()[0]
            .state,
        NativeCliWalState::Conflict
    );
}

#[test]
fn file_only_engine_keeps_the_frozen_twenty_step_order() {
    let plan = plan(0, false);
    let state = Rc::new(RefCell::new(SharedState::new(
        0,
        CommandBehavior::SuccessIntended,
    )));
    let mut adapter = Adapter {
        state: state.clone(),
    };
    let mut executor = Executor;
    let mut filesystem = FileSystem {
        state: state.clone(),
        applied: false,
    };
    let mut journal = Journal {
        state: state.clone(),
    };
    let mut hook = Hook;

    NativeTransactionEngine::new(
        &mut adapter,
        &mut executor,
        &mut filesystem,
        &mut journal,
        &mut hook,
    )
    .apply(&plan, 1_900_000_000_000, clock())
    .unwrap();

    assert_eq!(state.borrow().entered, TransactionStep::ORDER);
    assert!(
        !state
            .borrow()
            .events
            .iter()
            .any(|event| event.contains("cli"))
    );
}

#[test]
fn file_only_hermes_plan_recomputes_its_explicit_v2_approval() {
    let mut plan = plan_with_approval(0, false, 2);
    plan.setup.harness = HarnessId::Hermes;
    plan.setup.harness_profile = Some("coder".to_owned());
    plan.setup.batch_hash = approval_hash_v2(&plan).unwrap();
    let state = Rc::new(RefCell::new(SharedState::new(
        0,
        CommandBehavior::SuccessIntended,
    )));
    let mut adapter = Adapter {
        state: state.clone(),
    };
    let mut executor = Executor;
    let mut filesystem = FileSystem {
        state: state.clone(),
        applied: false,
    };
    let mut journal = Journal {
        state: state.clone(),
    };
    let mut hook = Hook;

    NativeTransactionEngine::new(
        &mut adapter,
        &mut executor,
        &mut filesystem,
        &mut journal,
        &mut hook,
    )
    .apply(&plan, 1_900_000_000_000, clock())
    .unwrap();
}
