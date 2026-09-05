mod support;

use std::{cell::RefCell, panic::AssertUnwindSafe, rc::Rc, str::FromStr};

use context_relay_core::{
    native_memory::{
        NativeMemoryDocumentKind, NativeMemoryLimits, NativeMemoryRegistration, NativeMemorySource,
    },
    native_transaction::{
        ApprovedCliMutation, ApprovedMutation, CanonicalCliDeclaration, MutationKind,
        NativeTransactionPlan, RestorableStateFingerprint, SidecarBinding, approval_hash_v2,
        open_plan, seal_plan, seal_reversible_plan,
    },
    setup::{BridgeExecutionError, BridgeInstallService, BridgePlanExecutor},
    vault::{NativeTransactionStatus, SetupPlanLifecycle, SetupPlanWrite, Vault},
};
use context_relay_native_runner::{
    NativeState, RuleSyncFeature, RuleSyncFeatures, RuleSyncTarget, RuntimeTarget, SidecarCommand,
    SidecarId,
};
use context_relay_protocol::{
    ApprovalClass, CliOperation, HarnessId, NativePlatform, NativeScope, NetworkDelta,
    PermissionDelta, PlanId, ScopeRef, SetupPlan, Sha256Digest, WireNativeValue,
};
use sha2::{Digest as _, Sha256};

use support::{ID_1, MemoryKeyStore, TempVault, persist_native_terminal};

const NOW_MS: u64 = 1_900_000_000_000;

#[derive(Default)]
struct RecordingExecutor {
    calls: Vec<NativeTransactionPlan>,
    sealed: Vec<Vec<u8>>,
    failure: Option<BridgeExecutionError>,
}

impl BridgePlanExecutor for RecordingExecutor {
    fn execute(
        &mut self,
        _vault: &mut Vault,
        plan: &NativeTransactionPlan,
        sealed_plan: &[u8],
        _created_ms: u64,
        _now_ms: u64,
    ) -> Result<(), BridgeExecutionError> {
        self.calls.push(plan.clone());
        self.sealed.push(sealed_plan.to_vec());
        match self.failure.take() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

struct CrashRollback {
    status: Option<NativeTransactionStatus>,
    inverse_id: Rc<RefCell<Option<PlanId>>>,
}

impl BridgePlanExecutor for CrashRollback {
    fn execute(
        &mut self,
        vault: &mut Vault,
        plan: &NativeTransactionPlan,
        sealed_plan: &[u8],
        created_ms: u64,
        _now_ms: u64,
    ) -> Result<(), BridgeExecutionError> {
        *self.inverse_id.borrow_mut() = Some(plan.setup.plan_id);
        if let Some(status) = self.status {
            persist_native_terminal(vault, plan, sealed_plan, created_ms, NOW_MS + 2, status);
        }
        panic!("simulated process exit after inverse native transaction")
    }
}

fn native_text(value: &str) -> WireNativeValue {
    WireNativeValue {
        platform: NativePlatform::Macos,
        bytes: value.as_bytes().to_vec(),
        display: Some(value.to_owned()),
    }
}

fn native_memory_source() -> NativeMemorySource {
    NativeMemorySource::new(
        HarnessId::Codex,
        "0.144.1",
        ScopeRef::Global,
        NativeMemoryDocumentKind::Agent,
        native_text("/fixture/CODEX_MEMORY.md"),
        NativeMemoryLimits {
            max_bytes: 4_096,
            max_characters: 4_096,
        },
        true,
    )
    .unwrap()
}

fn declaration(command: &str) -> CanonicalCliDeclaration {
    let canonical_body = serde_json::to_string(&serde_json::json!({
        "args": ["--harness", "codex"],
        "command": command,
        "type": "stdio",
    }))
    .unwrap();
    CanonicalCliDeclaration {
        harness: HarnessId::Codex,
        server_name: "context-relay".to_owned(),
        fingerprint: Sha256Digest(Sha256::digest(canonical_body.as_bytes()).into()),
        canonical_body,
    }
}

fn operation(arguments: &[&str]) -> CliOperation {
    CliOperation {
        executable: native_text("/fixture/codex"),
        arguments: arguments.iter().copied().map(native_text).collect(),
        timeout_ms: 30_000,
    }
}

fn plan() -> NativeTransactionPlan {
    let cli = ApprovedCliMutation {
        execution_context: None,
        stable_id: "b5be495e-d4ee-7a2e-a29e-b589ebc5d7fd".to_owned(),
        expected: Some(declaration("/opt/context-relay-old")),
        intended: Some(declaration("/opt/context-relay")),
        forward: vec![operation(&[
            "mcp",
            "add",
            "context-relay",
            "--",
            "/opt/context-relay",
        ])],
        rollback: vec![operation(&[
            "mcp",
            "add",
            "context-relay",
            "--",
            "/opt/context-relay-old",
        ])],
    };
    NativeTransactionPlan {
        setup: SetupPlan {
            plan_id: PlanId::from_str(ID_1).unwrap(),
            harness: HarnessId::Codex,
            harness_profile: None,
            adapter_version: 1,
            executable_path: native_text("/fixture/codex"),
            executable_hash: Sha256Digest([1; 32]),
            harness_version: "0.144.1".to_owned(),
            target_scopes: vec![NativeScope::Global],
            expected_native_digests: vec![],
            semantic_changes: vec![],
            cli_operations: cli.forward.clone(),
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
            rulesync_version: "bridge-preview-v1".to_owned(),
            rulesync_hash: Sha256Digest([3; 32]),
            approval_class: ApprovalClass::Active,
            expires_at: NOW_MS + 60_000,
            batch_hash: Sha256Digest([0; 32]),
        },
        approval_version: 2,
        helper_policy_version: 1,
        manifest_schema_version: 1,
        manifest_digest: Sha256Digest([4; 32]),
        helper_hash: Sha256Digest([5; 32]),
        sidecars: vec![SidecarBinding {
            id: SidecarId::RuleSync,
            target: RuntimeTarget::MacosArm64,
            version: "bridge-preview-v1".to_owned(),
            closure_hash: Sha256Digest([6; 32]),
            source_bundle_hash: Sha256Digest([7; 32]),
            build_toolchain_hash: Sha256Digest([8; 32]),
            command_template_digest: Sha256Digest([9; 32]),
            command: SidecarCommand::RuleSyncGenerate {
                target: RuleSyncTarget::CodexCli,
                features: RuleSyncFeatures::new(&[RuleSyncFeature::Mcp]).unwrap(),
            },
        }],
        structural_allowlist_hash: Sha256Digest([10; 32]),
        staged_inputs: vec![],
        expected_semantic_output_hash: Sha256Digest([11; 32]),
        scanner_result_hash: Sha256Digest([12; 32]),
        mutations: vec![],
        cli_mutations: vec![cli],
        native_memory_registrations: vec![],
        ownership_changes: vec![],
    }
}

fn persist(vault: &mut Vault, mut plan: NativeTransactionPlan) -> NativeTransactionPlan {
    let approval = approval_hash_v2(&plan).unwrap();
    plan.setup.batch_hash = approval;
    let sealed = seal_plan(&plan, approval).unwrap();
    vault
        .put_setup_plan(SetupPlanWrite {
            plan_id: &plan.setup.plan_id,
            schema_version: 1,
            approval_version: 2,
            approval_hash: &approval,
            payload: &sealed,
            created_ms: NOW_MS,
            expires_ms: plan.setup.expires_at,
        })
        .unwrap();
    plan
}

#[test]
fn successful_rollback_unregisters_the_source_owned_by_the_original_plan() {
    let path = TempVault::new("bridge-setup-rollback-native-memory-source");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), "bridge-setup-rollback-v1", &keys).unwrap();
    let descriptor = native_memory_source();
    let mut candidate = plan();
    candidate.native_memory_registrations = vec![NativeMemoryRegistration {
        source: descriptor.clone(),
        last_applied_digest: Some(Sha256Digest([71; 32])),
    }];
    let original = persist(&mut vault, candidate);
    BridgeInstallService::persisted(&mut vault)
        .apply(
            &original.setup.plan_id,
            NOW_MS + 1,
            &mut RecordingExecutor::default(),
        )
        .unwrap();
    assert!(
        vault
            .native_memory_ledger(&descriptor.id)
            .unwrap()
            .is_some()
    );

    BridgeInstallService::persisted(&mut vault)
        .rollback(
            &original.setup.plan_id,
            NOW_MS + 2,
            &mut RecordingExecutor::default(),
        )
        .unwrap();

    assert!(
        vault
            .native_memory_ledger(&descriptor.id)
            .unwrap()
            .is_none()
    );
}

#[test]
fn rollback_persists_and_applies_a_linked_exact_inverse_then_replays() {
    let path = TempVault::new("bridge-setup-rollback-inverse");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), "bridge-setup-rollback-v1", &keys).unwrap();
    let original = persist(&mut vault, plan());
    let mut apply_executor = RecordingExecutor::default();
    BridgeInstallService::persisted(&mut vault)
        .apply(&original.setup.plan_id, NOW_MS + 1, &mut apply_executor)
        .unwrap();
    let mut rollback_executor = RecordingExecutor::default();

    BridgeInstallService::persisted(&mut vault)
        .rollback(&original.setup.plan_id, NOW_MS + 2, &mut rollback_executor)
        .unwrap();

    assert_eq!(rollback_executor.calls.len(), 1);
    let inverse = &rollback_executor.calls[0];
    assert_ne!(inverse.setup.plan_id, original.setup.plan_id);
    assert_eq!(
        inverse.cli_mutations[0].expected,
        original.cli_mutations[0].intended
    );
    assert_eq!(
        inverse.cli_mutations[0].intended,
        original.cli_mutations[0].expected
    );
    assert_eq!(
        inverse.cli_mutations[0].forward,
        original.cli_mutations[0].rollback
    );
    assert_eq!(
        inverse.cli_mutations[0].rollback,
        original.cli_mutations[0].forward
    );
    assert_eq!(
        inverse.setup.cli_operations,
        inverse.cli_mutations[0].forward
    );
    let opened_inverse = open_plan(&rollback_executor.sealed[0]).unwrap();
    assert_eq!(opened_inverse.plan, *inverse);
    assert_eq!(
        opened_inverse.rollback_of_plan_id,
        Some(original.setup.plan_id)
    );
    assert_eq!(
        vault
            .setup_plan(&original.setup.plan_id)
            .unwrap()
            .unwrap()
            .lifecycle,
        SetupPlanLifecycle::RolledBack
    );
    assert_eq!(
        vault
            .setup_plan(&inverse.setup.plan_id)
            .unwrap()
            .unwrap()
            .lifecycle,
        SetupPlanLifecycle::Applied
    );

    BridgeInstallService::persisted(&mut vault)
        .rollback(&original.setup.plan_id, NOW_MS + 3, &mut rollback_executor)
        .unwrap();
    assert_eq!(
        rollback_executor.calls.len(),
        1,
        "rollback replay must not execute the inverse twice"
    );
}

#[test]
fn rollback_inverse_restores_the_exact_prior_native_state() {
    let path = TempVault::new("bridge-setup-rollback-native-state");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), "bridge-setup-rollback-v1", &keys).unwrap();
    let prior = NativeState::absent(0, 1);
    let intended = NativeState::absent(1, 1);
    let prior_bytes = prior.encode_v1().unwrap();
    let intended_bytes = intended.encode_v1().unwrap();
    let mut original = plan();
    original.setup.harness = HarnessId::Hermes;
    original.setup.harness_profile = Some("coder".to_owned());
    original.setup.executable_path = native_text("/fixture/hermes");
    original.setup.cli_operations.clear();
    original.cli_mutations.clear();
    original.sidecars[0].command = SidecarCommand::RuleSyncGenerate {
        target: RuleSyncTarget::ClaudeCode,
        features: RuleSyncFeatures::new(&[RuleSyncFeature::Mcp]).unwrap(),
    };
    original.mutations = vec![ApprovedMutation {
        target: native_text("/fixture/hermes/config.yaml"),
        kind: MutationKind::Payload,
        content: intended_bytes.clone(),
        expected: RestorableStateFingerprint(Sha256Digest(prior.fingerprint())),
        intended: RestorableStateFingerprint(Sha256Digest(intended.fingerprint())),
    }];
    let approval = approval_hash_v2(&original).unwrap();
    original.setup.batch_hash = approval;
    let sealed = seal_reversible_plan(
        &original,
        approval,
        std::slice::from_ref(&prior_bytes),
        None,
    )
    .unwrap();
    vault
        .put_setup_plan(SetupPlanWrite {
            plan_id: &original.setup.plan_id,
            schema_version: 2,
            approval_version: 2,
            approval_hash: &approval,
            payload: &sealed,
            created_ms: NOW_MS,
            expires_ms: original.setup.expires_at,
        })
        .unwrap();
    let mut apply_executor = RecordingExecutor::default();
    BridgeInstallService::persisted(&mut vault)
        .apply(&original.setup.plan_id, NOW_MS + 1, &mut apply_executor)
        .unwrap();
    let mut rollback_executor = RecordingExecutor::default();

    BridgeInstallService::persisted(&mut vault)
        .rollback(&original.setup.plan_id, NOW_MS + 2, &mut rollback_executor)
        .unwrap();

    let inverse = &rollback_executor.calls[0];
    assert_eq!(inverse.mutations.len(), 1);
    assert_eq!(inverse.mutations[0].content, prior_bytes);
    assert_eq!(
        inverse.mutations[0].expected,
        original.mutations[0].intended
    );
    assert_eq!(
        inverse.mutations[0].intended,
        original.mutations[0].expected
    );
    let opened = open_plan(&rollback_executor.sealed[0]).unwrap();
    assert_eq!(opened.native_rollback_states, vec![intended_bytes]);

    for tamper in ["target", "fingerprint", "content"] {
        let mut envelope: serde_json::Value =
            serde_json::from_slice(&rollback_executor.sealed[0]).unwrap();
        match tamper {
            "target" => {
                envelope["nativeRollbackStates"][0]["target"] =
                    serde_json::to_value(native_text("/fixture/other.yaml")).unwrap();
            }
            "fingerprint" => {
                envelope["nativeRollbackStates"][0]["expectedFingerprint"] =
                    serde_json::json!("00".repeat(32));
            }
            "content" => {
                envelope["nativeRollbackStates"][0]["content"] = serde_json::json!("");
            }
            _ => unreachable!(),
        }
        assert!(
            open_plan(&serde_json::to_vec(&envelope).unwrap()).is_err(),
            "{tamper} must remain bound to the matching native mutation"
        );
    }
}

#[test]
fn passive_hermes_inverse_preserves_an_absent_gateway_lock_binding() {
    let path = TempVault::new("bridge-setup-rollback-passive-hermes-lock");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), "bridge-setup-rollback-v1", &keys).unwrap();
    let mut original = plan();
    original.setup.harness = HarnessId::Hermes;
    original.setup.harness_profile = Some("coder".to_owned());
    original.setup.executable_path = native_text("/fixture/hermes");
    original.setup.approval_class = ApprovalClass::Passive;
    original.setup.expected_native_digests = vec![context_relay_protocol::ExpectedNativeDigest {
        target: native_text("/fixture/hermes/gateway.lock"),
        expected_digest: None,
    }];
    original.setup.cli_operations.clear();
    original.cli_mutations.clear();
    original.sidecars[0].command = SidecarCommand::RuleSyncGenerate {
        target: RuleSyncTarget::ClaudeCode,
        features: RuleSyncFeatures::new(&[RuleSyncFeature::Mcp]).unwrap(),
    };
    let original = persist(&mut vault, original);
    BridgeInstallService::persisted(&mut vault)
        .apply(
            &original.setup.plan_id,
            NOW_MS + 1,
            &mut RecordingExecutor::default(),
        )
        .unwrap();
    let mut rollback_executor = RecordingExecutor::default();

    BridgeInstallService::persisted(&mut vault)
        .rollback(&original.setup.plan_id, NOW_MS + 2, &mut rollback_executor)
        .unwrap();

    assert_eq!(
        rollback_executor.calls[0].setup.expected_native_digests[0].expected_digest, None,
        "passive apply never provisions the operational gateway lock"
    );
}

#[test]
fn rollback_records_restored_failures_and_divergence_without_replay_writes() {
    let keys = MemoryKeyStore::default();
    for (name, failure, original_lifecycle, inverse_lifecycle) in [
        (
            "bridge-setup-rollback-validation-restored",
            BridgeExecutionError::restored("rollback validation failed and was restored"),
            SetupPlanLifecycle::RollbackRestored,
            SetupPlanLifecycle::ApplyRestored,
        ),
        (
            "bridge-setup-rollback-divergence",
            BridgeExecutionError::conflict("live declaration diverged without a write"),
            SetupPlanLifecycle::Conflict,
            SetupPlanLifecycle::Conflict,
        ),
    ] {
        let path = TempVault::new(name);
        let mut vault = Vault::open(path.path(), "bridge-setup-rollback-v1", &keys).unwrap();
        let original = persist(&mut vault, plan());
        BridgeInstallService::persisted(&mut vault)
            .apply(
                &original.setup.plan_id,
                NOW_MS + 1,
                &mut RecordingExecutor::default(),
            )
            .unwrap();
        let mut executor = RecordingExecutor {
            failure: Some(failure),
            ..RecordingExecutor::default()
        };

        assert!(
            BridgeInstallService::persisted(&mut vault)
                .rollback(&original.setup.plan_id, NOW_MS + 2, &mut executor)
                .is_err()
        );
        assert_eq!(executor.calls.len(), 1);
        assert_eq!(
            vault
                .setup_plan(&original.setup.plan_id)
                .unwrap()
                .unwrap()
                .lifecycle,
            original_lifecycle
        );
        assert_eq!(
            vault
                .setup_plan(&executor.calls[0].setup.plan_id)
                .unwrap()
                .unwrap()
                .lifecycle,
            inverse_lifecycle
        );
    }
}

#[test]
fn rollback_rejects_the_wrong_lifecycle_before_persisting_or_executing_an_inverse() {
    let path = TempVault::new("bridge-setup-rollback-wrong-lifecycle");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), "bridge-setup-rollback-v1", &keys).unwrap();
    let original = persist(&mut vault, plan());
    let mut executor = RecordingExecutor::default();

    assert!(
        BridgeInstallService::persisted(&mut vault)
            .rollback(&original.setup.plan_id, NOW_MS + 1, &mut executor)
            .is_err()
    );
    assert!(executor.calls.is_empty());
    assert_eq!(
        vault
            .setup_plan(&original.setup.plan_id)
            .unwrap()
            .unwrap()
            .lifecycle,
        SetupPlanLifecycle::Previewed
    );
}

#[test]
fn rollback_reconciles_the_inverse_native_terminal_without_reexecuting() {
    let keys = MemoryKeyStore::default();
    for (name, terminal, original_lifecycle, inverse_lifecycle, succeeds) in [
        (
            "bridge-setup-rollback-reconcile-committed",
            NativeTransactionStatus::Committed,
            SetupPlanLifecycle::RolledBack,
            SetupPlanLifecycle::Applied,
            true,
        ),
        (
            "bridge-setup-rollback-reconcile-restored",
            NativeTransactionStatus::Restored,
            SetupPlanLifecycle::RollbackRestored,
            SetupPlanLifecycle::ApplyRestored,
            false,
        ),
        (
            "bridge-setup-rollback-reconcile-conflict",
            NativeTransactionStatus::Conflict,
            SetupPlanLifecycle::Conflict,
            SetupPlanLifecycle::Conflict,
            false,
        ),
    ] {
        let path = TempVault::new(name);
        let mut vault = Vault::open(path.path(), "bridge-setup-rollback-v1", &keys).unwrap();
        let original = persist(&mut vault, plan());
        BridgeInstallService::persisted(&mut vault)
            .apply(
                &original.setup.plan_id,
                NOW_MS + 1,
                &mut RecordingExecutor::default(),
            )
            .unwrap();
        let inverse_id = Rc::new(RefCell::new(None));
        let crashed = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let _ = BridgeInstallService::persisted(&mut vault).rollback(
                &original.setup.plan_id,
                NOW_MS + 2,
                &mut CrashRollback {
                    status: Some(terminal),
                    inverse_id: inverse_id.clone(),
                },
            );
        }));
        assert!(crashed.is_err());
        let inverse_id = inverse_id.borrow().unwrap();
        assert_eq!(
            vault
                .setup_plan(&original.setup.plan_id)
                .unwrap()
                .unwrap()
                .lifecycle,
            SetupPlanLifecycle::RollingBack
        );
        assert_eq!(
            vault.setup_plan(&inverse_id).unwrap().unwrap().lifecycle,
            SetupPlanLifecycle::Applying
        );
        let mut executor = RecordingExecutor::default();

        let result = BridgeInstallService::persisted(&mut vault).rollback(
            &original.setup.plan_id,
            NOW_MS + 3,
            &mut executor,
        );

        assert_eq!(result.is_ok(), succeeds, "{name}");
        assert!(executor.calls.is_empty(), "{name}: must not re-execute");
        assert_eq!(
            vault
                .setup_plan(&original.setup.plan_id)
                .unwrap()
                .unwrap()
                .lifecycle,
            original_lifecycle,
            "{name}"
        );
        assert_eq!(
            vault.setup_plan(&inverse_id).unwrap().unwrap().lifecycle,
            inverse_lifecycle,
            "{name}"
        );
    }
}

#[test]
fn rollback_does_not_reexecute_a_pending_inverse_native_outcome() {
    let keys = MemoryKeyStore::default();
    let path = TempVault::new("bridge-setup-rollback-pending-inverse");
    let mut vault = Vault::open(path.path(), "bridge-setup-rollback-v1", &keys).unwrap();
    let original = persist(&mut vault, plan());
    BridgeInstallService::persisted(&mut vault)
        .apply(
            &original.setup.plan_id,
            NOW_MS + 1,
            &mut RecordingExecutor::default(),
        )
        .unwrap();
    let inverse_id = Rc::new(RefCell::new(None));
    let _ = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let _ = BridgeInstallService::persisted(&mut vault).rollback(
            &original.setup.plan_id,
            NOW_MS + 2,
            &mut CrashRollback {
                status: Some(NativeTransactionStatus::Pending),
                inverse_id: inverse_id.clone(),
            },
        );
    }));
    let inverse_id = inverse_id.borrow().unwrap();
    let mut executor = RecordingExecutor::default();

    assert!(
        BridgeInstallService::persisted(&mut vault)
            .rollback(&original.setup.plan_id, NOW_MS + 3, &mut executor)
            .is_err()
    );
    assert!(executor.calls.is_empty());
    assert_eq!(
        vault
            .setup_plan(&original.setup.plan_id)
            .unwrap()
            .unwrap()
            .lifecycle,
        SetupPlanLifecycle::RollingBack
    );
    assert_eq!(
        vault.setup_plan(&inverse_id).unwrap().unwrap().lifecycle,
        SetupPlanLifecycle::Applying
    );
}

#[test]
fn rollback_resumes_a_claimed_inverse_when_its_native_transaction_is_missing() {
    let keys = MemoryKeyStore::default();
    let path = TempVault::new("bridge-setup-rollback-missing-inverse");
    let mut vault = Vault::open(path.path(), "bridge-setup-rollback-v1", &keys).unwrap();
    let original = persist(&mut vault, plan());
    BridgeInstallService::persisted(&mut vault)
        .apply(
            &original.setup.plan_id,
            NOW_MS + 1,
            &mut RecordingExecutor::default(),
        )
        .unwrap();
    let inverse_id = Rc::new(RefCell::new(None));
    let _ = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let _ = BridgeInstallService::persisted(&mut vault).rollback(
            &original.setup.plan_id,
            NOW_MS + 2,
            &mut CrashRollback {
                status: None,
                inverse_id: inverse_id.clone(),
            },
        );
    }));
    let inverse_id = inverse_id.borrow().unwrap();
    let mut executor = RecordingExecutor::default();

    BridgeInstallService::persisted(&mut vault)
        .rollback(&original.setup.plan_id, NOW_MS + 3, &mut executor)
        .unwrap();
    assert_eq!(executor.calls.len(), 1);
    assert_eq!(
        vault
            .setup_plan(&original.setup.plan_id)
            .unwrap()
            .unwrap()
            .lifecycle,
        SetupPlanLifecycle::RolledBack
    );
    assert_eq!(
        vault.setup_plan(&inverse_id).unwrap().unwrap().lifecycle,
        SetupPlanLifecycle::Applied
    );
}

#[test]
fn rollback_expires_a_claimed_inverse_at_the_exact_expiry_boundary() {
    let keys = MemoryKeyStore::default();
    let path = TempVault::new("bridge-setup-rollback-resume-exact-expiry");
    let mut vault = Vault::open(path.path(), "bridge-setup-rollback-v1", &keys).unwrap();
    let original = persist(&mut vault, plan());
    BridgeInstallService::persisted(&mut vault)
        .apply(
            &original.setup.plan_id,
            NOW_MS + 1,
            &mut RecordingExecutor::default(),
        )
        .unwrap();
    let inverse_id = Rc::new(RefCell::new(None));
    let _ = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let _ = BridgeInstallService::persisted(&mut vault).rollback(
            &original.setup.plan_id,
            NOW_MS + 2,
            &mut CrashRollback {
                status: None,
                inverse_id: inverse_id.clone(),
            },
        );
    }));
    let inverse_id = inverse_id.borrow().unwrap();
    let inverse_expiry = vault.setup_plan(&inverse_id).unwrap().unwrap().expires_ms;
    let mut executor = RecordingExecutor::default();

    assert!(
        BridgeInstallService::persisted(&mut vault)
            .rollback(&original.setup.plan_id, inverse_expiry, &mut executor)
            .is_err()
    );
    assert!(executor.calls.is_empty());
    assert_eq!(
        vault
            .setup_plan(&original.setup.plan_id)
            .unwrap()
            .unwrap()
            .lifecycle,
        SetupPlanLifecycle::RollbackRestored
    );
    assert_eq!(
        vault.setup_plan(&inverse_id).unwrap().unwrap().lifecycle,
        SetupPlanLifecycle::ApplyRestored
    );
}

#[test]
fn startup_reconciliation_finalizes_a_terminal_original_and_inverse_pair() {
    let keys = MemoryKeyStore::default();
    let path = TempVault::new("bridge-setup-rollback-startup-reconcile");
    let mut vault = Vault::open(path.path(), "bridge-setup-rollback-v1", &keys).unwrap();
    let descriptor = native_memory_source();
    let mut candidate = plan();
    candidate.native_memory_registrations = vec![NativeMemoryRegistration {
        source: descriptor.clone(),
        last_applied_digest: Some(Sha256Digest([72; 32])),
    }];
    let original = persist(&mut vault, candidate);
    BridgeInstallService::persisted(&mut vault)
        .apply(
            &original.setup.plan_id,
            NOW_MS + 1,
            &mut RecordingExecutor::default(),
        )
        .unwrap();
    assert!(
        vault
            .native_memory_ledger(&descriptor.id)
            .unwrap()
            .is_some()
    );
    let inverse_id = Rc::new(RefCell::new(None));
    let _ = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let _ = BridgeInstallService::persisted(&mut vault).rollback(
            &original.setup.plan_id,
            NOW_MS + 2,
            &mut CrashRollback {
                status: Some(NativeTransactionStatus::Committed),
                inverse_id: inverse_id.clone(),
            },
        );
    }));
    let inverse_id = inverse_id.borrow().unwrap();

    BridgeInstallService::persisted(&mut vault)
        .reconcile_after_native_recovery()
        .unwrap();
    let mut executor = RecordingExecutor::default();
    BridgeInstallService::persisted(&mut vault)
        .rollback(&original.setup.plan_id, NOW_MS + 3, &mut executor)
        .unwrap();

    assert!(executor.calls.is_empty());
    assert_eq!(
        vault
            .setup_plan(&original.setup.plan_id)
            .unwrap()
            .unwrap()
            .lifecycle,
        SetupPlanLifecycle::RolledBack
    );
    assert_eq!(
        vault.setup_plan(&inverse_id).unwrap().unwrap().lifecycle,
        SetupPlanLifecycle::Applied
    );
    assert!(
        vault
            .native_memory_ledger(&descriptor.id)
            .unwrap()
            .is_none()
    );
}
