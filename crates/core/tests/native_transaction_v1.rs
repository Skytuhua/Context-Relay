mod support;

use std::{
    cell::{Cell, RefCell},
    fs,
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    rc::Rc,
    str::FromStr,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use context_relay_core::native_transaction::{
    approval_hash_v1,
    engine::{
        BeforeImage, BoundaryError, CheckpointAppliedAbsence, CompensationOutcome, FaultHook,
        FrozenOutput, MutationOutcome, NativeAdapter, NativeFileSystem, NativeJournal,
        NativeTransactionEngine, RebindAppliedAbsence, RestrictedExecutor, RestrictedRun,
        TransactionError,
    },
    journal::VaultNativeJournal,
    model::{
        ApprovedInput, ApprovedMutation, MutationKind, NativeApplyReceipt, NativeObjectToken,
        NativeTransactionPlan, RestorableStateFingerprint, SidecarBinding, TransactionStep,
    },
};
use context_relay_native_runner::{
    NativeState, RuleSyncFeature, RuleSyncFeatures, RuleSyncTarget, RuntimeTarget, SidecarCommand,
    SidecarId, StagePath,
};
use context_relay_protocol::{
    ApplyReceipt, ApprovalClass, DeviceId, HarnessId, HybridLogicalClock, NativePlatform,
    NativeScope, NetworkDelta, PermissionDelta, PlanId, SetupPlan, Sha256Digest, WireNativeValue,
};
use rusqlite::Connection;

use context_relay_core::vault::{
    BeforeImagePolicy, NativeSandboxIdentity, NativeTransactionStatus, NativeWalState, Vault,
};
use support::{MemoryKeyStore, TempVault};

const ID: &str = "01890f3e-1c2b-7a4d-8e5f-123456789abc";
const LOCK_CHILD_ROOT: &str = "CONTEXT_RELAY_NATIVE_LOCK_CHILD_ROOT";
const LOCK_CHILD_VAULT: &str = "CONTEXT_RELAY_NATIVE_LOCK_CHILD_VAULT";
const LOCK_CHILD_READY: &str = "CONTEXT_RELAY_NATIVE_LOCK_CHILD_READY";

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

fn sandbox_identity() -> NativeSandboxIdentity {
    NativeSandboxIdentity::Windows {
        moniker: "context-relay.native.0123456789abcdef0123456789abcdef".to_owned(),
        sid:
            b"S-1-15-2-3872518810-2985098273-1912316193-2655983105-1250049442-371239648-1157085541"
                .to_vec(),
    }
}

fn vault_journal<'a>(
    vault: &'a mut Vault,
    lock_root: &Path,
    transaction_id: &str,
) -> VaultNativeJournal<'a> {
    VaultNativeJournal::new(
        vault,
        lock_root,
        transaction_id,
        sandbox_identity(),
        b"approved plan".to_vec(),
        1_900_000_000_000,
        BeforeImagePolicy::new(1024, 100),
    )
}

fn open_keyed(path: &Path, key: &[u8; 32]) -> Connection {
    let connection = Connection::open(path).unwrap();
    // SAFETY: this is the first operation on the owned handle and the key lives
    // for the entire call.
    let result = unsafe {
        rusqlite::ffi::sqlite3_key(
            connection.handle(),
            key.as_ptr().cast(),
            key.len().try_into().unwrap(),
        )
    };
    assert_eq!(result, rusqlite::ffi::SQLITE_OK);
    connection
        .query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
        .unwrap();
    connection
}

fn native_value(path: &str) -> WireNativeValue {
    WireNativeValue {
        platform: NativePlatform::Windows,
        bytes: path.encode_utf16().flat_map(u16::to_le_bytes).collect(),
        display: None,
    }
}

fn plan() -> NativeTransactionPlan {
    let setup = SetupPlan {
        plan_id: PlanId::from_str(ID).unwrap(),
        harness: HarnessId::Codex,
        adapter_version: 1,
        executable_path: native_value(r"C:\fixture\codex.exe"),
        executable_hash: Sha256Digest([1; 32]),
        harness_version: "1.0.0".into(),
        target_scopes: vec![NativeScope::Global],
        expected_native_digests: vec![],
        semantic_changes: vec![],
        cli_operations: vec![],
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
        rulesync_version: "14.0.1".into(),
        rulesync_hash: Sha256Digest([3; 32]),
        approval_class: ApprovalClass::Passive,
        expires_at: 2_000_000_000_000,
        batch_hash: Sha256Digest([0; 32]),
    };
    let mutation = |path: &str, kind, byte| {
        let intended = NativeState::absent(u32::from(byte), 2);
        ApprovedMutation {
            target: native_value(path),
            kind,
            content: intended.encode_v1().unwrap(),
            expected: RestorableStateFingerprint(Sha256Digest([byte; 32])),
            intended: RestorableStateFingerprint(Sha256Digest(intended.fingerprint())),
        }
    };
    let mut plan = NativeTransactionPlan {
        setup,
        helper_policy_version: 1,
        manifest_schema_version: 1,
        manifest_digest: Sha256Digest([12; 32]),
        helper_hash: Sha256Digest([4; 32]),
        sidecars: vec![SidecarBinding {
            id: SidecarId::RuleSync,
            target: RuntimeTarget::WindowsX86_64,
            version: "14.0.1".into(),
            closure_hash: Sha256Digest([5; 32]),
            source_bundle_hash: Sha256Digest([6; 32]),
            build_toolchain_hash: Sha256Digest([7; 32]),
            command_template_digest: Sha256Digest([13; 32]),
            command: SidecarCommand::RuleSyncGenerate {
                target: RuleSyncTarget::CodexCli,
                features: RuleSyncFeatures::new(&[RuleSyncFeature::Rules]).unwrap(),
            },
        }],
        structural_allowlist_hash: Sha256Digest([8; 32]),
        staged_inputs: vec![ApprovedInput {
            path: StagePath::try_from("input/AGENTS.md").unwrap(),
            length: 1,
            digest: Sha256Digest([9; 32]),
        }],
        expected_semantic_output_hash: Sha256Digest([10; 32]),
        scanner_result_hash: Sha256Digest([11; 32]),
        mutations: vec![
            mutation(r"C:\fixture\payload", MutationKind::Payload, 20),
            mutation(r"C:\fixture\package", MutationKind::ExecutableDisabled, 30),
            mutation(
                r"C:\fixture\activation",
                MutationKind::ActivationReference,
                40,
            ),
        ],
        ownership_changes: vec![],
    };
    plan.setup.batch_hash = approval_hash_v1(&plan).unwrap();
    plan
}

fn clock() -> HybridLogicalClock {
    HybridLogicalClock::new(1_900_000_000_000, 0, DeviceId::from_str(ID).unwrap())
}

#[derive(Default)]
struct State {
    journal_lock_acquired: bool,
    completed: Vec<TransactionStep>,
    durable_events: Vec<String>,
    mutation_kinds: Vec<MutationKind>,
    mutation_nonces: Vec<[u8; 16]>,
    apply_calls: usize,
    live_writes: usize,
    restore_calls: usize,
    restore_nonces: Vec<[u8; 16]>,
    commits: usize,
    finalized: usize,
}

type Shared = Rc<RefCell<State>>;

struct Adapter;

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
        run: &RestrictedRun,
    ) -> Result<FrozenOutput, BoundaryError> {
        assert_eq!(run.staged_output_hash, plan.expected_semantic_output_hash);
        Ok(FrozenOutput {
            staged_output_hash: run.staged_output_hash,
            scanner_result_hash: run.scanner_result_hash,
        })
    }

    fn validate_effective(
        &mut self,
        _plan: &NativeTransactionPlan,
        _receipt: &ApplyReceipt,
    ) -> Result<(), BoundaryError> {
        Ok(())
    }
}

struct RejectingAdapter;

impl NativeAdapter for RejectingAdapter {
    fn reprobe_live_state(&mut self, _plan: &NativeTransactionPlan) -> Result<(), BoundaryError> {
        Err(BoundaryError::new("reprobe rejected"))
    }

    fn compare_approved_digests(
        &mut self,
        _plan: &NativeTransactionPlan,
    ) -> Result<(), BoundaryError> {
        unreachable!()
    }

    fn validate_staged_output(
        &mut self,
        _plan: &NativeTransactionPlan,
        _run: &RestrictedRun,
    ) -> Result<FrozenOutput, BoundaryError> {
        unreachable!()
    }

    fn validate_effective(
        &mut self,
        _plan: &NativeTransactionPlan,
        _receipt: &ApplyReceipt,
    ) -> Result<(), BoundaryError> {
        unreachable!()
    }
}

struct CountingAdapter(Rc<Cell<usize>>);

impl NativeAdapter for CountingAdapter {
    fn reprobe_live_state(&mut self, _plan: &NativeTransactionPlan) -> Result<(), BoundaryError> {
        self.0.set(self.0.get() + 1);
        Err(BoundaryError::new("adapter must not run while contended"))
    }

    fn compare_approved_digests(
        &mut self,
        _plan: &NativeTransactionPlan,
    ) -> Result<(), BoundaryError> {
        self.0.set(self.0.get() + 1);
        Err(BoundaryError::new("adapter must not run while contended"))
    }

    fn validate_staged_output(
        &mut self,
        _plan: &NativeTransactionPlan,
        _run: &RestrictedRun,
    ) -> Result<FrozenOutput, BoundaryError> {
        self.0.set(self.0.get() + 1);
        Err(BoundaryError::new("adapter must not run while contended"))
    }

    fn validate_effective(
        &mut self,
        _plan: &NativeTransactionPlan,
        _receipt: &ApplyReceipt,
    ) -> Result<(), BoundaryError> {
        self.0.set(self.0.get() + 1);
        Err(BoundaryError::new("adapter must not run while contended"))
    }
}

struct Executor {
    run: RestrictedRun,
}

impl RestrictedExecutor for Executor {
    fn copy_allowlisted_inputs(&mut self, _inputs: &[ApprovedInput]) -> Result<(), BoundaryError> {
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
        assert_eq!(sidecars.len(), 1);
        assert_eq!(sidecars[0].id, SidecarId::RuleSync);
        Ok(self.run.clone())
    }

    fn reject_unsafe_topology(&mut self) -> Result<(), BoundaryError> {
        Ok(())
    }
}

struct FileSystem {
    state: Shared,
    changed: bool,
    before_image_fault: BeforeImageFault,
    outcome_fault: OutcomeFault,
}

#[derive(Clone, Copy, Default)]
enum BeforeImageFault {
    #[default]
    None,
    Missing,
    Reordered,
    WrongTarget,
    WrongFingerprint,
}

#[derive(Clone, Copy, Default)]
enum OutcomeFault {
    #[default]
    None,
    WrongFingerprint,
}

impl NativeFileSystem for FileSystem {
    fn create_before_images(
        &mut self,
        mutations: &[ApprovedMutation],
    ) -> Result<Vec<BeforeImage>, BoundaryError> {
        let mut images = mutations
            .iter()
            .enumerate()
            .map(|(index, mutation)| BeforeImage {
                id: format!("before-{index}"),
                target: mutation.target.clone(),
                object_token: NativeObjectToken {
                    volume: vec![1],
                    object: vec![u8::try_from(index + 1).unwrap()],
                    topology: vec![2],
                },
                fingerprint: mutation.expected.clone(),
                encrypted_state: vec![1],
            })
            .collect::<Vec<_>>();
        match self.before_image_fault {
            BeforeImageFault::None => {}
            BeforeImageFault::Missing => {
                images.pop();
            }
            BeforeImageFault::Reordered => images.reverse(),
            BeforeImageFault::WrongTarget => images[0].target = native_value("wrong-target"),
            BeforeImageFault::WrongFingerprint => {
                images[0].fingerprint = RestorableStateFingerprint(Sha256Digest([99; 32]));
            }
        }
        Ok(images)
    }

    fn record_native_metadata(&mut self, _images: &[BeforeImage]) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn compare_and_swap_targets(
        &mut self,
        _mutations: &[ApprovedMutation],
    ) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn apply_mutation(
        &mut self,
        transaction_nonce: &[u8; 16],
        mutation: &ApprovedMutation,
        persist_candidate: &mut dyn FnMut(&NativeObjectToken) -> Result<(), BoundaryError>,
    ) -> Result<MutationOutcome, BoundaryError> {
        self.state.borrow_mut().apply_calls += 1;
        self.state
            .borrow_mut()
            .durable_events
            .push(format!("apply:{:?}", mutation.kind));
        self.state.borrow_mut().mutation_kinds.push(mutation.kind);
        self.state
            .borrow_mut()
            .mutation_nonces
            .push(*transaction_nonce);
        let wrote = self.changed && mutation.expected != mutation.intended;
        if wrote {
            persist_candidate(&NativeObjectToken {
                volume: vec![1; 8],
                object: vec![2; 16],
                topology: vec![3; 29],
            })?;
            self.state.borrow_mut().live_writes += 1;
        }
        Ok(MutationOutcome {
            wrote,
            resulting_fingerprint: match self.outcome_fault {
                OutcomeFault::None => mutation.intended.clone(),
                OutcomeFault::WrongFingerprint => {
                    RestorableStateFingerprint(Sha256Digest([98; 32]))
                }
            },
        })
    }

    fn mutation_provenance(&self, mutation: &ApprovedMutation) -> Option<NativeObjectToken> {
        (self.changed && mutation.expected != mutation.intended).then(|| NativeObjectToken {
            volume: vec![1; 8],
            object: vec![2; 16],
            topology: vec![3; 29],
        })
    }

    fn restore_matching_applied_targets(
        &mut self,
        transaction_nonce: &[u8; 16],
        persist_restored_candidate: &mut dyn FnMut(
            usize,
            &NativeObjectToken,
        ) -> Result<(), BoundaryError>,
        _checkpoint_applied_absence: &mut CheckpointAppliedAbsence<'_>,
        _rebind_applied_absence: &mut RebindAppliedAbsence<'_>,
    ) -> Result<CompensationOutcome, BoundaryError> {
        self.state.borrow_mut().restore_calls += 1;
        self.state
            .borrow_mut()
            .restore_nonces
            .push(*transaction_nonce);
        let applied = self.state.borrow().live_writes;
        for index in 0..applied {
            persist_restored_candidate(
                index,
                &NativeObjectToken {
                    volume: vec![4; 8],
                    object: vec![5; 16],
                    topology: vec![6; 29],
                },
            )?;
        }
        Ok(CompensationOutcome::default())
    }

    fn finish_committed_targets(
        &mut self,
        _transaction_nonce: &[u8; 16],
    ) -> Result<(), BoundaryError> {
        Ok(())
    }
}

struct CountingFileSystem(Rc<Cell<usize>>);

impl NativeFileSystem for CountingFileSystem {
    fn create_before_images(
        &mut self,
        _mutations: &[ApprovedMutation],
    ) -> Result<Vec<BeforeImage>, BoundaryError> {
        self.0.set(self.0.get() + 1);
        Err(BoundaryError::new(
            "filesystem must not run while contended",
        ))
    }

    fn record_native_metadata(&mut self, _images: &[BeforeImage]) -> Result<(), BoundaryError> {
        self.0.set(self.0.get() + 1);
        Err(BoundaryError::new(
            "filesystem must not run while contended",
        ))
    }

    fn compare_and_swap_targets(
        &mut self,
        _mutations: &[ApprovedMutation],
    ) -> Result<(), BoundaryError> {
        self.0.set(self.0.get() + 1);
        Err(BoundaryError::new(
            "filesystem must not run while contended",
        ))
    }

    fn apply_mutation(
        &mut self,
        _transaction_nonce: &[u8; 16],
        _mutation: &ApprovedMutation,
        _persist_candidate: &mut dyn FnMut(&NativeObjectToken) -> Result<(), BoundaryError>,
    ) -> Result<MutationOutcome, BoundaryError> {
        self.0.set(self.0.get() + 1);
        Err(BoundaryError::new(
            "filesystem must not run while contended",
        ))
    }

    fn restore_matching_applied_targets(
        &mut self,
        _transaction_nonce: &[u8; 16],
        _persist_restored_candidate: &mut dyn FnMut(
            usize,
            &NativeObjectToken,
        ) -> Result<(), BoundaryError>,
        _checkpoint_applied_absence: &mut CheckpointAppliedAbsence<'_>,
        _rebind_applied_absence: &mut RebindAppliedAbsence<'_>,
    ) -> Result<CompensationOutcome, BoundaryError> {
        self.0.set(self.0.get() + 1);
        Err(BoundaryError::new(
            "filesystem must not run while contended",
        ))
    }

    fn finish_committed_targets(
        &mut self,
        _transaction_nonce: &[u8; 16],
    ) -> Result<(), BoundaryError> {
        self.0.set(self.0.get() + 1);
        Err(BoundaryError::new(
            "filesystem must not run while contended",
        ))
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
        self.state.borrow_mut().journal_lock_acquired = true;
        Ok(())
    }

    fn enter_step(&mut self, step: TransactionStep) -> Result<(), BoundaryError> {
        if step == TransactionStep::AcquireLock && !self.state.borrow().journal_lock_acquired {
            return Err(BoundaryError::new(
                "profile lock acquisition was not the engine's first journal call",
            ));
        }
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
        mutation: &ApprovedMutation,
    ) -> Result<(), BoundaryError> {
        self.state
            .borrow_mut()
            .durable_events
            .push(format!("prepare:{:?}", mutation.kind));
        Ok(())
    }

    fn mark_mutation_applied(
        &mut self,
        _index: usize,
        mutation: &ApprovedMutation,
        _outcome: &MutationOutcome,
        _applied_token: Option<&NativeObjectToken>,
    ) -> Result<(), BoundaryError> {
        self.state
            .borrow_mut()
            .durable_events
            .push(format!("applied:{:?}", mutation.kind));
        Ok(())
    }

    fn record_mutation_candidate(
        &mut self,
        index: usize,
        _mutation: &ApprovedMutation,
        _candidate_token: &NativeObjectToken,
    ) -> Result<(), BoundaryError> {
        self.state
            .borrow_mut()
            .durable_events
            .push(format!("candidate:{index}"));
        Ok(())
    }

    fn mark_mutation_conflict(
        &mut self,
        index: usize,
        _applied_token: &NativeObjectToken,
    ) -> Result<(), BoundaryError> {
        self.state
            .borrow_mut()
            .durable_events
            .push(format!("conflict:{index}"));
        Ok(())
    }

    fn mark_mutation_applied_for_recovery(
        &mut self,
        index: usize,
        _mutation: &ApprovedMutation,
        _applied_token: &NativeObjectToken,
    ) -> Result<(), BoundaryError> {
        self.state
            .borrow_mut()
            .durable_events
            .push(format!("recoverable:{index}"));
        Ok(())
    }

    fn record_mutation_restored_candidate(
        &mut self,
        index: usize,
        _candidate_token: &NativeObjectToken,
    ) -> Result<(), BoundaryError> {
        self.state
            .borrow_mut()
            .durable_events
            .push(format!("restored-candidate:{index}"));
        Ok(())
    }

    fn checkpoint_mutation_applied_absence(
        &mut self,
        index: usize,
        later_index: usize,
        _expected_old_token: &NativeObjectToken,
        _new_token: &NativeObjectToken,
    ) -> Result<(), BoundaryError> {
        self.state
            .borrow_mut()
            .durable_events
            .push(format!("checkpoint:{index}:{later_index}"));
        Ok(())
    }

    fn rebind_mutation_applied_absence(
        &mut self,
        index: usize,
        later_index: usize,
        _expected_old_token: &NativeObjectToken,
        _new_token: &NativeObjectToken,
    ) -> Result<(), BoundaryError> {
        self.state
            .borrow_mut()
            .durable_events
            .push(format!("rebind:{index}:{later_index}"));
        Ok(())
    }

    fn prepare_compensation(&mut self) -> Result<(), BoundaryError> {
        self.state
            .borrow_mut()
            .durable_events
            .push("prepare-compensation".to_owned());
        Ok(())
    }

    fn commit_native_transaction(
        &mut self,
        _plan: &NativeTransactionPlan,
        _receipt: &NativeApplyReceipt,
    ) -> Result<(), BoundaryError> {
        self.state.borrow_mut().commits += 1;
        Ok(())
    }

    fn finish_committed(&mut self) -> Result<(), BoundaryError> {
        self.state.borrow_mut().finalized += 1;
        Ok(())
    }

    fn finish_compensated(
        &mut self,
        _conflict_target_sequences: &[u32],
    ) -> Result<(), BoundaryError> {
        Ok(())
    }
}

struct Hook {
    state: Shared,
    fail_after: Option<TransactionStep>,
}

struct CrashHook(TransactionStep);

impl FaultHook for CrashHook {
    fn after_step(&mut self, step: TransactionStep) -> Result<(), BoundaryError> {
        if step == self.0 {
            panic!("simulated process crash after {step:?}");
        }
        Ok(())
    }
}

impl FaultHook for Hook {
    fn after_step(&mut self, step: TransactionStep) -> Result<(), BoundaryError> {
        self.state.borrow_mut().completed.push(step);
        if self.fail_after == Some(step) {
            Err(BoundaryError::new("injected"))
        } else {
            Ok(())
        }
    }
}

fn run(
    plan: &NativeTransactionPlan,
    changed: bool,
    fail_after: Option<TransactionStep>,
    now_ms: u64,
) -> (Shared, Result<NativeApplyReceipt, TransactionError>) {
    run_with_faults(
        plan,
        changed,
        BeforeImageFault::None,
        OutcomeFault::None,
        fail_after,
        now_ms,
    )
}

fn run_with_faults(
    plan: &NativeTransactionPlan,
    changed: bool,
    before_image_fault: BeforeImageFault,
    outcome_fault: OutcomeFault,
    fail_after: Option<TransactionStep>,
    now_ms: u64,
) -> (Shared, Result<NativeApplyReceipt, TransactionError>) {
    let state = Rc::new(RefCell::new(State::default()));
    let mut adapter = Adapter;
    let mut executor = Executor {
        run: RestrictedRun {
            staged_output_hash: plan.expected_semantic_output_hash,
            scanner_result_hash: plan.scanner_result_hash,
        },
    };
    let mut filesystem = FileSystem {
        state: state.clone(),
        changed,
        before_image_fault,
        outcome_fault,
    };
    let mut journal = Journal {
        state: state.clone(),
    };
    let mut hook = Hook {
        state: state.clone(),
        fail_after,
    };
    let mut engine = NativeTransactionEngine::new(
        &mut adapter,
        &mut executor,
        &mut filesystem,
        &mut journal,
        &mut hook,
    );
    let result = engine.apply(plan, now_ms, clock());
    (state, result)
}

#[test]
fn rejects_before_images_with_wrong_count_order_target_or_fingerprint() {
    for fault in [
        BeforeImageFault::Missing,
        BeforeImageFault::Reordered,
        BeforeImageFault::WrongTarget,
        BeforeImageFault::WrongFingerprint,
    ] {
        let (state, result) = run_with_faults(
            &plan(),
            true,
            fault,
            OutcomeFault::None,
            None,
            1_900_000_000_000,
        );
        assert!(matches!(result, Err(TransactionError::BeforeImageMismatch)));
        let state = state.borrow();
        assert_eq!(state.live_writes, 0);
        assert_eq!(state.commits, 0);
        assert_eq!(state.restore_calls, 1);
    }
}

#[test]
fn engine_acquires_the_external_profile_lock_as_its_first_journal_call() {
    let (state, result) = run(&plan(), true, None, 1_900_000_000_000);
    assert!(result.is_ok());
    assert!(state.borrow().journal_lock_acquired);
}

#[test]
fn rejects_changed_mutation_outcomes_that_lie_about_write_or_fingerprint() {
    for (changed, outcome_fault) in [
        (false, OutcomeFault::None),
        (true, OutcomeFault::WrongFingerprint),
    ] {
        let (state, result) = run_with_faults(
            &plan(),
            changed,
            BeforeImageFault::None,
            outcome_fault,
            None,
            1_900_000_000_000,
        );
        assert!(matches!(
            result,
            Err(TransactionError::MutationOutcomeMismatch)
        ));
        let state = state.borrow();
        assert_eq!(state.commits, 0);
        assert_eq!(state.restore_calls, 1);
    }
}

#[test]
fn transaction_steps_are_the_exact_frozen_twenty_step_order() {
    use TransactionStep::*;

    assert_eq!(
        TransactionStep::ORDER,
        [
            AcquireLock,
            ReprobeLiveState,
            CompareApprovedDigests,
            CreateBeforeImages,
            RecordNativeMetadata,
            CopyAllowlistedInputs,
            CreateFakeRoots,
            BuildRestrictedEnvironment,
            RunRestrictedTools,
            RejectUnsafeTopology,
            ValidateStagedOutput,
            RecomputeApproval,
            CheckPlanFreshness,
            CompareAndSwapTargets,
            WritePayloads,
            InstallExecutablesDisabled,
            WriteActivationReferences,
            ValidateEffectiveConfiguration,
            CommitOwnershipAndReceipt,
            RestoreMatchingAppliedTargets,
        ]
    );

    for (index, step) in TransactionStep::ORDER.iter().enumerate() {
        assert_eq!(*step as u8, u8::try_from(index + 1).unwrap());
    }
}

#[test]
fn runs_the_exact_sequence_and_writes_roles_in_safe_order() {
    let (state, result) = run(&plan(), true, None, 1_900_000_000_000);
    let receipt = result.unwrap();
    let state = state.borrow();

    assert_eq!(state.completed, TransactionStep::ORDER);
    assert_eq!(
        state.mutation_kinds,
        [
            MutationKind::Payload,
            MutationKind::ExecutableDisabled,
            MutationKind::ActivationReference
        ]
    );
    assert_eq!(state.live_writes, 3);
    assert_eq!(state.apply_calls, 3);
    assert_eq!(
        state.mutation_nonces,
        vec![*PlanId::from_str(ID).unwrap().as_bytes(); 3]
    );
    assert_eq!(
        state.durable_events,
        [
            "prepare:Payload",
            "apply:Payload",
            "candidate:0",
            "applied:Payload",
            "prepare:ExecutableDisabled",
            "apply:ExecutableDisabled",
            "candidate:1",
            "applied:ExecutableDisabled",
            "prepare:ActivationReference",
            "apply:ActivationReference",
            "candidate:2",
            "applied:ActivationReference",
        ]
    );
    assert_eq!(state.commits, 1);
    assert_eq!(state.restore_calls, 0);
    assert_eq!(state.finalized, 1);
    assert_eq!(receipt.targets.len(), 3);
    assert_eq!(receipt.legacy.resulting_digests.len(), 3);
}

#[test]
fn every_precommit_step_failure_compensates_exactly_once() {
    for step in &TransactionStep::ORDER[..18] {
        let (state, result) = run(&plan(), true, Some(*step), 1_900_000_000_000);
        assert!(result.is_err(), "step {step:?} unexpectedly succeeded");
        let state = state.borrow();
        assert_eq!(state.commits, 0, "step {step:?}");
        assert_eq!(state.restore_calls, 1, "step {step:?}");
        assert_eq!(
            state.restore_nonces,
            vec![*PlanId::from_str(ID).unwrap().as_bytes()],
            "step {step:?}",
        );
    }
}

#[test]
fn a_fault_after_the_step_nineteen_commit_never_rolls_back_success() {
    let (state, result) = run(
        &plan(),
        true,
        Some(TransactionStep::CommitOwnershipAndReceipt),
        1_900_000_000_000,
    );
    assert!(result.is_ok());
    let state = state.borrow();
    assert_eq!(state.commits, 1);
    assert_eq!(state.restore_calls, 0);
    assert_eq!(state.finalized, 1);
}

#[test]
fn expired_plans_stop_before_any_live_write() {
    let mut expired = plan();
    expired.setup.expires_at = 1_800_000_000_000;
    expired.setup.batch_hash = approval_hash_v1(&expired).unwrap();

    let (state, result) = run(&expired, true, None, 1_900_000_000_000);
    assert!(result.is_err());
    let state = state.borrow();
    assert_eq!(state.live_writes, 0);
    assert_eq!(state.commits, 0);
    assert_eq!(state.restore_calls, 1);
}

#[test]
fn unchanged_reapply_commits_without_live_target_writes() {
    let mut unchanged = plan();
    for mutation in &mut unchanged.mutations {
        mutation.expected = mutation.intended.clone();
    }
    unchanged.setup.batch_hash = approval_hash_v1(&unchanged).unwrap();

    let (state, result) = run(&unchanged, true, None, 1_900_000_000_000);
    let receipt = result.unwrap();
    let state = state.borrow();
    assert_eq!(state.apply_calls, 3);
    assert_eq!(state.live_writes, 0);
    assert_eq!(
        state.durable_events,
        [
            "prepare:Payload",
            "apply:Payload",
            "applied:Payload",
            "prepare:ExecutableDisabled",
            "apply:ExecutableDisabled",
            "applied:ExecutableDisabled",
            "prepare:ActivationReference",
            "apply:ActivationReference",
            "applied:ActivationReference",
        ]
    );
    assert_eq!(state.commits, 1);
    assert_eq!(state.restore_calls, 0);
    assert_eq!(
        receipt.legacy.resulting_digests,
        unchanged
            .mutations
            .iter()
            .map(|mutation| mutation.intended.0)
            .collect::<Vec<_>>()
    );
}

#[test]
fn real_vault_journal_commits_unchanged_targets_without_a_live_write() {
    let mut unchanged = plan();
    for mutation in &mut unchanged.mutations {
        mutation.expected = mutation.intended.clone();
    }
    unchanged.setup.batch_hash = approval_hash_v1(&unchanged).unwrap();

    let path = TempVault::new("native-engine-vault-unchanged");
    let lock_root = TempLockRoot::new("native-engine-vault-unchanged-lock");
    fs::write(lock_root.path().join("unrelated-canary"), b"preserve").unwrap();
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), "native-engine-vault", &keys).unwrap();
    let state = Rc::new(RefCell::new(State::default()));
    let mut adapter = Adapter;
    let mut executor = Executor {
        run: RestrictedRun {
            staged_output_hash: unchanged.expected_semantic_output_hash,
            scanner_result_hash: unchanged.scanner_result_hash,
        },
    };
    let mut filesystem = FileSystem {
        state: state.clone(),
        changed: true,
        before_image_fault: BeforeImageFault::None,
        outcome_fault: OutcomeFault::None,
    };
    let mut hook = Hook {
        state: state.clone(),
        fail_after: None,
    };
    let mut journal = vault_journal(&mut vault, lock_root.path(), ID);
    let receipt = NativeTransactionEngine::new(
        &mut adapter,
        &mut executor,
        &mut filesystem,
        &mut journal,
        &mut hook,
    )
    .apply(&unchanged, 1_900_000_000_000, clock())
    .unwrap();
    let successor_path = TempVault::new("native-engine-vault-unchanged-successor");
    let successor_keys = MemoryKeyStore::default();
    let mut successor_vault = Vault::open(
        successor_path.path(),
        "native-engine-vault",
        &successor_keys,
    )
    .unwrap();
    let mut successor = vault_journal(&mut successor_vault, lock_root.path(), ID);
    successor.acquire_lock_and_begin(&unchanged).unwrap();
    assert_eq!(
        fs::read(lock_root.path().join("unrelated-canary")).unwrap(),
        b"preserve"
    );
    drop(successor);
    drop(journal);

    assert_eq!(state.borrow().apply_calls, 3);
    let snapshot = vault.native_transaction(ID).unwrap().unwrap();
    assert_eq!(snapshot.status, NativeTransactionStatus::Committed);
    assert_eq!((snapshot.entered_step, snapshot.current_step), (20, 20));
    assert_eq!(
        vault.native_receipt(&unchanged.setup.plan_id).unwrap(),
        Some(receipt)
    );
}

#[test]
fn real_vault_journal_preserves_changed_and_unchanged_state_at_every_crash_boundary() {
    for unchanged in [false, true] {
        for step in TransactionStep::ORDER {
            let mut approved = plan();
            if unchanged {
                for mutation in &mut approved.mutations {
                    mutation.expected = mutation.intended.clone();
                }
                approved.setup.batch_hash = approval_hash_v1(&approved).unwrap();
            }

            let path = TempVault::new(&format!(
                "native-engine-vault-crash-{unchanged}-{}",
                step as u8
            ));
            let lock_root = TempLockRoot::new(&format!(
                "native-engine-vault-crash-lock-{unchanged}-{}",
                step as u8
            ));
            let keys = MemoryKeyStore::default();
            let mut vault = Vault::open(path.path(), "native-engine-vault", &keys).unwrap();
            let state = Rc::new(RefCell::new(State::default()));
            let crashed = catch_unwind(AssertUnwindSafe(|| {
                let mut adapter = Adapter;
                let mut executor = Executor {
                    run: RestrictedRun {
                        staged_output_hash: approved.expected_semantic_output_hash,
                        scanner_result_hash: approved.scanner_result_hash,
                    },
                };
                let mut filesystem = FileSystem {
                    state: state.clone(),
                    changed: true,
                    before_image_fault: BeforeImageFault::None,
                    outcome_fault: OutcomeFault::None,
                };
                let mut hook = CrashHook(step);
                let mut journal = vault_journal(&mut vault, lock_root.path(), ID);
                let _ = NativeTransactionEngine::new(
                    &mut adapter,
                    &mut executor,
                    &mut filesystem,
                    &mut journal,
                    &mut hook,
                )
                .apply(&approved, 1_900_000_000_000, clock());
            }));
            assert!(crashed.is_err(), "{unchanged}: {step:?}");

            let snapshot = vault.native_transaction(ID).unwrap().unwrap();
            assert_eq!(snapshot.entered_step, step as u8, "{unchanged}: {step:?}");
            assert_eq!(snapshot.current_step, step as u8, "{unchanged}: {step:?}");
            assert_eq!(
                snapshot.status,
                if step as u8 >= TransactionStep::CommitOwnershipAndReceipt as u8 {
                    NativeTransactionStatus::Committed
                } else {
                    NativeTransactionStatus::Pending
                },
                "{unchanged}: {step:?}",
            );

            if step == TransactionStep::WriteActivationReferences {
                let wal = vault.native_wal(ID).unwrap();
                assert_eq!(wal.len(), approved.mutations.len());
                assert!(
                    wal.iter()
                        .all(|entry| entry.state == NativeWalState::Applied)
                );
                for (entry, mutation) in wal.iter().zip(&approved.mutations) {
                    let index = usize::try_from(entry.target_sequence).unwrap();
                    assert_eq!(entry.target, mutation.target);
                    assert_eq!(entry.before_image_id, format!("before-{index}"));
                    assert_eq!(entry.object_token.volume, [1]);
                    assert_eq!(
                        entry.object_token.object,
                        [u8::try_from(index + 1).unwrap()]
                    );
                    assert_eq!(entry.object_token.topology, [2]);
                }
                assert_eq!(state.borrow().apply_calls, 3);
            }
        }
    }
}

#[test]
fn real_vault_journal_compensates_a_failure_inside_an_entered_step() {
    let approved = plan();
    let path = TempVault::new("native-engine-vault-entered-failure");
    let lock_root = TempLockRoot::new("native-engine-vault-entered-failure-lock");
    fs::write(lock_root.path().join("unrelated-canary"), b"preserve").unwrap();
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), "native-engine-vault", &keys).unwrap();
    let state = Rc::new(RefCell::new(State::default()));
    let mut adapter = RejectingAdapter;
    let mut executor = Executor {
        run: RestrictedRun {
            staged_output_hash: approved.expected_semantic_output_hash,
            scanner_result_hash: approved.scanner_result_hash,
        },
    };
    let mut filesystem = FileSystem {
        state: state.clone(),
        changed: true,
        before_image_fault: BeforeImageFault::None,
        outcome_fault: OutcomeFault::None,
    };
    let mut hook = Hook {
        state: state.clone(),
        fail_after: None,
    };
    let mut journal = vault_journal(&mut vault, lock_root.path(), ID);
    let result = NativeTransactionEngine::new(
        &mut adapter,
        &mut executor,
        &mut filesystem,
        &mut journal,
        &mut hook,
    )
    .apply(&approved, 1_900_000_000_000, clock());
    let successor_path = TempVault::new("native-engine-vault-compensated-successor");
    let successor_keys = MemoryKeyStore::default();
    let mut successor_vault = Vault::open(
        successor_path.path(),
        "native-engine-vault",
        &successor_keys,
    )
    .unwrap();
    let mut successor = vault_journal(&mut successor_vault, lock_root.path(), ID);
    successor.acquire_lock_and_begin(&approved).unwrap();
    assert_eq!(
        fs::read(lock_root.path().join("unrelated-canary")).unwrap(),
        b"preserve"
    );
    drop(successor);
    drop(journal);

    assert!(matches!(result, Err(TransactionError::Boundary(_))));
    assert_eq!(state.borrow().restore_calls, 1);
    let snapshot = vault.native_transaction(ID).unwrap().unwrap();
    assert_eq!(snapshot.status, NativeTransactionStatus::Restored);
    assert_eq!((snapshot.entered_step, snapshot.current_step), (20, 20));
}

#[test]
fn contended_profile_lock_fails_before_vault_adapter_or_filesystem_work() {
    let approved = plan();
    let lock_root = TempLockRoot::new("native-profile-lock-contended");
    fs::write(lock_root.path().join("unrelated-canary"), b"preserve").unwrap();
    let holder_path = TempVault::new("native-profile-lock-holder");
    let holder_keys = MemoryKeyStore::default();
    let mut holder_vault =
        Vault::open(holder_path.path(), "native-engine-vault", &holder_keys).unwrap();
    let mut holder = vault_journal(&mut holder_vault, lock_root.path(), ID);
    holder.acquire_lock_and_begin(&approved).unwrap();

    let contender_path = TempVault::new("native-profile-lock-contender");
    let contender_keys = MemoryKeyStore::default();
    let mut contender_vault = Vault::open(
        contender_path.path(),
        "native-engine-vault",
        &contender_keys,
    )
    .unwrap();
    let adapter_calls = Rc::new(Cell::new(0));
    let filesystem_calls = Rc::new(Cell::new(0));
    let state = Rc::new(RefCell::new(State::default()));
    let mut adapter = CountingAdapter(adapter_calls.clone());
    let mut executor = Executor {
        run: RestrictedRun {
            staged_output_hash: approved.expected_semantic_output_hash,
            scanner_result_hash: approved.scanner_result_hash,
        },
    };
    let mut filesystem = CountingFileSystem(filesystem_calls.clone());
    let mut hook = Hook {
        state: state.clone(),
        fail_after: None,
    };
    let mut contender = vault_journal(&mut contender_vault, lock_root.path(), ID);
    let result = NativeTransactionEngine::new(
        &mut adapter,
        &mut executor,
        &mut filesystem,
        &mut contender,
        &mut hook,
    )
    .apply(&approved, 1_900_000_000_000, clock());

    assert!(matches!(result, Err(TransactionError::Boundary(_))));
    assert_eq!(adapter_calls.get(), 0);
    assert_eq!(filesystem_calls.get(), 0);
    assert!(state.borrow().completed.is_empty());
    drop(contender);
    assert!(contender_vault.native_transaction(ID).unwrap().is_none());
    assert_eq!(
        fs::read(lock_root.path().join("unrelated-canary")).unwrap(),
        b"preserve"
    );

    drop(holder);
    let mut retry = vault_journal(&mut contender_vault, lock_root.path(), ID);
    retry.acquire_lock_and_begin(&approved).unwrap();
}

#[test]
fn failed_vault_begin_releases_profile_lock_without_creating_transaction() {
    let approved = plan();
    let lock_root = TempLockRoot::new("native-profile-lock-begin-failure");
    let failed_path = TempVault::new("native-profile-lock-begin-failure-vault");
    let failed_keys = MemoryKeyStore::default();
    let mut failed_vault =
        Vault::open(failed_path.path(), "native-engine-vault", &failed_keys).unwrap();
    let mut failed = VaultNativeJournal::new(
        &mut failed_vault,
        lock_root.path(),
        ID,
        sandbox_identity(),
        Vec::new(),
        1_900_000_000_000,
        BeforeImagePolicy::new(1024, 100),
    );

    let error = failed.acquire_lock_and_begin(&approved).unwrap_err();
    assert!(error.to_string().contains("plan payload length"));

    let retry_path = TempVault::new("native-profile-lock-begin-failure-retry");
    let retry_keys = MemoryKeyStore::default();
    let mut retry_vault =
        Vault::open(retry_path.path(), "native-engine-vault", &retry_keys).unwrap();
    let mut retry = vault_journal(&mut retry_vault, lock_root.path(), ID);
    retry.acquire_lock_and_begin(&approved).unwrap();
    drop(retry);
    drop(failed);

    assert!(failed_vault.native_transaction(ID).unwrap().is_none());
}

#[test]
fn failed_acquire_step_terminalizes_durable_begin_and_releases_profile_lock() {
    let approved = plan();
    let lock_root = TempLockRoot::new("native-profile-lock-acquire-step-failure");
    let failed_path = TempVault::new("native-profile-lock-acquire-step-failure-vault");
    let failed_keys = MemoryKeyStore::default();
    let failed_vault =
        Vault::open(failed_path.path(), "native-engine-vault", &failed_keys).unwrap();
    drop(failed_vault);
    let raw = open_keyed(failed_path.path(), &failed_keys.key("native-engine-vault"));
    raw.execute_batch(
        "CREATE TRIGGER fail_acquire_step
         BEFORE UPDATE OF entered_step ON native_transactions
         WHEN NEW.entered_step = 1
         BEGIN
           SELECT RAISE(ABORT, 'injected acquire-lock step failure');
         END;",
    )
    .unwrap();
    drop(raw);

    let mut failed_vault =
        Vault::open(failed_path.path(), "native-engine-vault", &failed_keys).unwrap();
    let mut failed = vault_journal(&mut failed_vault, lock_root.path(), ID);
    let error = failed.acquire_lock_and_begin(&approved).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("injected acquire-lock step failure")
    );

    let retry_path = TempVault::new("native-profile-lock-acquire-step-failure-retry");
    let retry_keys = MemoryKeyStore::default();
    let mut retry_vault =
        Vault::open(retry_path.path(), "native-engine-vault", &retry_keys).unwrap();
    let mut retry = vault_journal(&mut retry_vault, lock_root.path(), ID);
    retry.acquire_lock_and_begin(&approved).unwrap();
    drop(retry);
    drop(failed);

    let snapshot = failed_vault.native_transaction(ID).unwrap().unwrap();
    assert_eq!(snapshot.status, NativeTransactionStatus::Restored);
    assert_eq!((snapshot.current_step, snapshot.entered_step), (20, 20));
    assert!(
        failed_vault
            .pending_native_transactions()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn different_profile_roots_lock_independently() {
    let approved = plan();
    let first_root = TempLockRoot::new("native-profile-lock-first");
    let second_root = TempLockRoot::new("native-profile-lock-second");
    let first_path = TempVault::new("native-profile-lock-first-vault");
    let second_path = TempVault::new("native-profile-lock-second-vault");
    let first_keys = MemoryKeyStore::default();
    let second_keys = MemoryKeyStore::default();
    let mut first_vault =
        Vault::open(first_path.path(), "native-engine-vault", &first_keys).unwrap();
    let mut second_vault =
        Vault::open(second_path.path(), "native-engine-vault", &second_keys).unwrap();
    let mut first = vault_journal(&mut first_vault, first_root.path(), ID);
    let mut second = vault_journal(&mut second_vault, second_root.path(), ID);

    first.acquire_lock_and_begin(&approved).unwrap();
    second.acquire_lock_and_begin(&approved).unwrap();
}

#[test]
fn native_profile_lock_child_holder() {
    let Some(root) = std::env::var_os(LOCK_CHILD_ROOT) else {
        return;
    };
    let vault_path = PathBuf::from(std::env::var_os(LOCK_CHILD_VAULT).unwrap());
    let ready = PathBuf::from(std::env::var_os(LOCK_CHILD_READY).unwrap());
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(&vault_path, "native-engine-vault", &keys).unwrap();
    let approved = plan();
    let mut journal = vault_journal(&mut vault, Path::new(&root), ID);
    journal.acquire_lock_and_begin(&approved).unwrap();
    fs::write(ready, b"ready").unwrap();
    loop {
        thread::sleep(Duration::from_millis(25));
    }
}

#[test]
fn another_process_contends_and_a_crash_releases_without_deleting_siblings() {
    let approved = plan();
    let lock_root = TempLockRoot::new("native-profile-lock-process");
    let canary = lock_root.path().join("unrelated-canary");
    let ready = lock_root.path().join("child-ready");
    fs::write(&canary, b"preserve").unwrap();
    let child_vault = TempVault::new("native-profile-lock-child-vault");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("native_profile_lock_child_holder")
        .arg("--nocapture")
        .env(LOCK_CHILD_ROOT, lock_root.path())
        .env(LOCK_CHILD_VAULT, child_vault.path())
        .env(LOCK_CHILD_READY, &ready)
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready.exists() {
        assert!(Instant::now() < deadline, "child did not acquire the lock");
        assert!(
            child.try_wait().unwrap().is_none(),
            "lock child exited early"
        );
        thread::sleep(Duration::from_millis(10));
    }

    let contender_path = TempVault::new("native-profile-lock-process-contender");
    let contender_keys = MemoryKeyStore::default();
    let mut contender_vault = Vault::open(
        contender_path.path(),
        "native-engine-vault",
        &contender_keys,
    )
    .unwrap();
    let mut contender = vault_journal(&mut contender_vault, lock_root.path(), ID);
    let error = contender.acquire_lock_and_begin(&approved).unwrap_err();
    assert!(error.to_string().contains("profile lock"));
    drop(contender);
    assert!(contender_vault.native_transaction(ID).unwrap().is_none());

    child.kill().unwrap();
    let _ = child.wait().unwrap();
    let retry_path = TempVault::new("native-profile-lock-process-retry");
    let retry_keys = MemoryKeyStore::default();
    let mut retry_vault =
        Vault::open(retry_path.path(), "native-engine-vault", &retry_keys).unwrap();
    let mut retry = vault_journal(&mut retry_vault, lock_root.path(), ID);
    retry.acquire_lock_and_begin(&approved).unwrap();
    assert_eq!(fs::read(canary).unwrap(), b"preserve");
}

#[cfg(unix)]
#[test]
fn symlink_profile_root_is_rejected_without_touching_the_target() {
    let approved = plan();
    let outside = TempLockRoot::new("native-profile-lock-outside");
    let canary = outside.path().join("canary");
    fs::write(&canary, b"outside").unwrap();
    let alias = outside.path().with_file_name(format!(
        "context-relay-native-profile-lock-alias-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::os::unix::fs::symlink(outside.path(), &alias).unwrap();
    let path = TempVault::new("native-profile-lock-symlink-vault");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), "native-engine-vault", &keys).unwrap();
    let mut journal = vault_journal(&mut vault, &alias, ID);

    assert!(journal.acquire_lock_and_begin(&approved).is_err());
    assert_eq!(fs::read(canary).unwrap(), b"outside");
    fs::remove_file(alias).unwrap();
}

#[cfg(windows)]
#[test]
fn held_windows_profile_root_cannot_be_renamed_or_reparse_redirected() {
    let approved = plan();
    let lock_root = TempLockRoot::new("native-profile-lock-windows-held");
    let canary = lock_root.path().join("unrelated-canary");
    fs::write(&canary, b"preserve").unwrap();
    let path = TempVault::new("native-profile-lock-windows-vault");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), "native-engine-vault", &keys).unwrap();
    let mut journal = vault_journal(&mut vault, lock_root.path(), ID);
    journal.acquire_lock_and_begin(&approved).unwrap();

    let moved = lock_root.path().with_file_name(format!(
        "context-relay-native-profile-lock-moved-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    assert!(fs::rename(lock_root.path(), moved).is_err());
    assert_eq!(fs::read(canary).unwrap(), b"preserve");
}
