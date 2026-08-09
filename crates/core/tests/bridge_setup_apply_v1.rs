mod support;

use std::{panic::AssertUnwindSafe, str::FromStr};

use context_relay_core::{
    native_memory::{
        NativeMemoryDocumentKind, NativeMemoryLedger, NativeMemoryLimits, NativeMemoryRegistration,
        NativeMemorySource,
    },
    native_transaction::{
        ApprovedCliMutation, CanonicalCliDeclaration, NativeTransactionPlan, SidecarBinding,
        approval_hash_v2, recovery::bind_cli_recovery_plan, seal_plan,
    },
    setup::{BridgeExecutionError, BridgeInstallService, BridgePlanExecutor},
    vault::{
        NativeCliWalRecord, NativeCliWalState, NativeTransactionStatus, SetupPlanAction,
        SetupPlanLifecycle, SetupPlanWrite, Vault,
    },
};
use context_relay_native_runner::{
    RuleSyncFeature, RuleSyncFeatures, RuleSyncTarget, RuntimeTarget, SidecarCommand, SidecarId,
};
use context_relay_protocol::{
    ApprovalClass, CliOperation, ErrorCode, HarnessId, NativePlatform, NativeScope, NetworkDelta,
    PermissionDelta, PlanId, ScopeRef, SetupPlan, Sha256Digest, WireNativeValue,
};
use sha2::{Digest as _, Sha256};

use support::{ID_1, ID_2, ID_3, MemoryKeyStore, TempVault, persist_native_terminal};

const NOW_MS: u64 = 1_900_000_000_000;

#[derive(Default)]
struct RecordingExecutor {
    calls: usize,
    seen_plans: Vec<NativeTransactionPlan>,
    seen_sealed: Vec<Vec<u8>>,
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
        self.calls += 1;
        self.seen_plans.push(plan.clone());
        self.seen_sealed.push(sealed_plan.to_vec());
        match self.failure.take() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

struct CrashAfterTerminal(NativeTransactionStatus);

impl BridgePlanExecutor for CrashAfterTerminal {
    fn execute(
        &mut self,
        vault: &mut Vault,
        plan: &NativeTransactionPlan,
        sealed_plan: &[u8],
        created_ms: u64,
        _now_ms: u64,
    ) -> Result<(), BridgeExecutionError> {
        persist_native_terminal(vault, plan, sealed_plan, created_ms, NOW_MS + 1, self.0);
        panic!("simulated process exit after durable native terminal state")
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

fn operation(command: &str) -> CliOperation {
    CliOperation {
        executable: native_text("/fixture/codex"),
        arguments: ["mcp", "add", "context-relay", "--", command]
            .into_iter()
            .map(native_text)
            .collect(),
        timeout_ms: 30_000,
    }
}

fn plan() -> NativeTransactionPlan {
    let cli = ApprovedCliMutation {
        stable_id: "b5be495e-d4ee-7a2e-a29e-b589ebc5d7fd".to_owned(),
        expected: None,
        intended: Some(declaration("/opt/context-relay")),
        forward: vec![operation("/opt/context-relay")],
        rollback: vec![CliOperation {
            executable: native_text("/fixture/codex"),
            arguments: ["mcp", "remove", "context-relay"]
                .into_iter()
                .map(native_text)
                .collect(),
            timeout_ms: 30_000,
        }],
    };
    NativeTransactionPlan {
        setup: SetupPlan {
            plan_id: PlanId::from_str(ID_1).unwrap(),
            harness: HarnessId::Codex,
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

fn persist(vault: &mut Vault, mut plan: NativeTransactionPlan) -> (NativeTransactionPlan, Vec<u8>) {
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
    (plan, sealed)
}

fn cli_wal(plan: &NativeTransactionPlan) -> NativeCliWalRecord {
    let mutation = &plan.cli_mutations[0];
    let target = mutation
        .expected
        .as_ref()
        .or(mutation.intended.as_ref())
        .unwrap();
    NativeCliWalRecord {
        sequence: 0,
        stable_id: mutation.stable_id.clone(),
        harness: target.harness,
        server_name: target.server_name.clone(),
        expected_declaration: mutation
            .expected
            .as_ref()
            .map(|declaration| declaration.canonical_body.as_bytes().to_vec()),
        expected_fingerprint: mutation
            .expected
            .as_ref()
            .map(|declaration| declaration.fingerprint),
        intended_declaration: mutation
            .intended
            .as_ref()
            .map(|declaration| declaration.canonical_body.as_bytes().to_vec()),
        intended_fingerprint: mutation
            .intended
            .as_ref()
            .map(|declaration| declaration.fingerprint),
        forward_operations: serde_json::to_vec(&mutation.forward).unwrap(),
        rollback_operations: serde_json::to_vec(&mutation.rollback).unwrap(),
        state: NativeCliWalState::Prepared,
    }
}

#[test]
fn cli_recovery_binding_accepts_only_exact_sealed_plan_wal_bytes() {
    let path = TempVault::new("bridge-cli-recovery-binding");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), "bridge-setup-apply-v1", &keys).unwrap();
    let (plan, sealed) = persist(&mut vault, plan());
    let exact = cli_wal(&plan);

    let bound = bind_cli_recovery_plan(&sealed, std::slice::from_ref(&exact)).unwrap();
    assert_eq!(bound.plan, plan);
    assert_eq!(bound.mutations, plan.cli_mutations);

    let mut tampered = Vec::new();
    let mut sequence = exact.clone();
    sequence.sequence = 1;
    tampered.push(sequence);
    let mut stable_id = exact.clone();
    stable_id.stable_id.push('x');
    tampered.push(stable_id);
    let mut harness = exact.clone();
    harness.harness = HarnessId::ClaudeCode;
    tampered.push(harness);
    let mut server = exact.clone();
    server.server_name.push('x');
    tampered.push(server);
    let mut declaration = exact.clone();
    declaration
        .intended_declaration
        .as_mut()
        .unwrap()
        .push(b' ');
    tampered.push(declaration);
    let mut fingerprint = exact.clone();
    fingerprint.intended_fingerprint = Some(Sha256Digest([99; 32]));
    tampered.push(fingerprint);
    let mut forward = exact.clone();
    forward.forward_operations.push(b' ');
    tampered.push(forward);
    let mut rollback = exact.clone();
    rollback.rollback_operations.push(b' ');
    tampered.push(rollback);
    for row in tampered {
        assert!(bind_cli_recovery_plan(&sealed, &[row]).is_err());
    }

    let mut approval_mismatch = sealed.clone();
    *approval_mismatch.last_mut().unwrap() ^= 1;
    assert!(bind_cli_recovery_plan(&approval_mismatch, &[exact]).is_err());
}

#[test]
fn apply_reloads_and_revalidates_the_persisted_plan_then_replays_idempotently() {
    let path = TempVault::new("bridge-setup-apply-reload");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), "bridge-setup-apply-v1", &keys).unwrap();
    let (expected, sealed) = persist(&mut vault, plan());
    let mut executor = RecordingExecutor::default();

    BridgeInstallService::persisted(&mut vault)
        .apply(&expected.setup.plan_id, NOW_MS + 1, &mut executor)
        .unwrap();

    assert_eq!(executor.calls, 1);
    assert_eq!(executor.seen_plans, vec![expected.clone()]);
    assert_eq!(executor.seen_sealed, vec![sealed]);
    assert_eq!(
        vault
            .setup_plan(&expected.setup.plan_id)
            .unwrap()
            .unwrap()
            .lifecycle,
        SetupPlanLifecycle::Applied
    );

    BridgeInstallService::persisted(&mut vault)
        .apply(&expected.setup.plan_id, NOW_MS + 2, &mut executor)
        .unwrap();
    assert_eq!(executor.calls, 1, "apply replay must not execute twice");
}

#[test]
fn expired_or_tampered_persisted_plans_never_reach_the_executor() {
    let path = TempVault::new("bridge-setup-apply-expired");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), "bridge-setup-apply-v1", &keys).unwrap();
    let (expired, _) = persist(&mut vault, plan());
    let mut executor = RecordingExecutor::default();

    assert!(
        BridgeInstallService::persisted(&mut vault)
            .apply(
                &expired.setup.plan_id,
                expired.setup.expires_at,
                &mut executor
            )
            .is_err()
    );
    assert_eq!(executor.calls, 0);
    assert_eq!(
        vault
            .setup_plan(&expired.setup.plan_id)
            .unwrap()
            .unwrap()
            .lifecycle,
        SetupPlanLifecycle::Expired
    );

    let path = TempVault::new("bridge-setup-apply-tampered");
    let mut vault = Vault::open(path.path(), "bridge-setup-apply-v1", &keys).unwrap();
    let mut candidate = plan();
    let approval = approval_hash_v2(&candidate).unwrap();
    candidate.setup.batch_hash = approval;
    let sealed = seal_plan(&candidate, approval).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&sealed).unwrap();
    value["nativePlan"]["setup"]["harnessVersion"] = serde_json::json!("tampered");
    let tampered = serde_json::to_vec(&value).unwrap();
    vault
        .put_setup_plan(SetupPlanWrite {
            plan_id: &candidate.setup.plan_id,
            schema_version: 1,
            approval_version: 2,
            approval_hash: &approval,
            payload: &tampered,
            created_ms: NOW_MS,
            expires_ms: candidate.setup.expires_at,
        })
        .unwrap();

    assert!(
        BridgeInstallService::persisted(&mut vault)
            .apply(&candidate.setup.plan_id, NOW_MS + 1, &mut executor)
            .is_err()
    );
    assert_eq!(executor.calls, 0);
    assert_eq!(
        vault
            .setup_plan(&candidate.setup.plan_id)
            .unwrap()
            .unwrap()
            .lifecycle,
        SetupPlanLifecycle::Previewed
    );
}

#[test]
fn apply_records_restored_validation_failures_and_unknown_outcome_conflicts() {
    let keys = MemoryKeyStore::default();
    for (name, failure, expected) in [
        (
            "bridge-setup-apply-validation-restored",
            BridgeExecutionError::restored("effective validation failed and was restored"),
            SetupPlanLifecycle::ApplyRestored,
        ),
        (
            "bridge-setup-apply-unknown-conflict",
            BridgeExecutionError::conflict("command outcome diverged"),
            SetupPlanLifecycle::Conflict,
        ),
    ] {
        let path = TempVault::new(name);
        let mut vault = Vault::open(path.path(), "bridge-setup-apply-v1", &keys).unwrap();
        let (candidate, _) = persist(&mut vault, plan());
        let mut executor = RecordingExecutor {
            failure: Some(failure),
            ..RecordingExecutor::default()
        };

        assert!(
            BridgeInstallService::persisted(&mut vault)
                .apply(&candidate.setup.plan_id, NOW_MS + 1, &mut executor)
                .is_err()
        );
        assert_eq!(executor.calls, 1);
        assert_eq!(
            vault
                .setup_plan(&candidate.setup.plan_id)
                .unwrap()
                .unwrap()
                .lifecycle,
            expected
        );
    }
}

#[test]
fn apply_resumes_an_already_claimed_plan_when_the_native_transaction_is_missing() {
    let path = TempVault::new("bridge-setup-apply-cas");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), "bridge-setup-apply-v1", &keys).unwrap();
    let (candidate, _) = persist(&mut vault, plan());
    vault
        .claim_setup_plan(&candidate.setup.plan_id, SetupPlanAction::Apply, NOW_MS + 1)
        .unwrap();
    let mut executor = RecordingExecutor::default();

    BridgeInstallService::persisted(&mut vault)
        .apply(&candidate.setup.plan_id, NOW_MS + 2, &mut executor)
        .unwrap();
    assert_eq!(executor.calls, 1);
    assert_eq!(
        vault
            .setup_plan(&candidate.setup.plan_id)
            .unwrap()
            .unwrap()
            .lifecycle,
        SetupPlanLifecycle::Applied
    );
}

#[test]
fn apply_expires_an_already_claimed_plan_at_the_exact_expiry_boundary() {
    let path = TempVault::new("bridge-setup-apply-resume-exact-expiry");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), "bridge-setup-apply-v1", &keys).unwrap();
    let (candidate, _) = persist(&mut vault, plan());
    vault
        .claim_setup_plan(&candidate.setup.plan_id, SetupPlanAction::Apply, NOW_MS + 1)
        .unwrap();
    let mut executor = RecordingExecutor::default();

    assert!(
        BridgeInstallService::persisted(&mut vault)
            .apply(
                &candidate.setup.plan_id,
                candidate.setup.expires_at,
                &mut executor,
            )
            .is_err()
    );
    assert_eq!(executor.calls, 0);
    assert_eq!(
        vault
            .setup_plan(&candidate.setup.plan_id)
            .unwrap()
            .unwrap()
            .lifecycle,
        SetupPlanLifecycle::ApplyRestored
    );
}

#[test]
fn apply_reconciles_durable_native_terminal_states_without_reexecuting() {
    let keys = MemoryKeyStore::default();
    for (name, terminal, expected_lifecycle, succeeds) in [
        (
            "bridge-setup-apply-reconcile-committed",
            NativeTransactionStatus::Committed,
            SetupPlanLifecycle::Applied,
            true,
        ),
        (
            "bridge-setup-apply-reconcile-restored",
            NativeTransactionStatus::Restored,
            SetupPlanLifecycle::ApplyRestored,
            false,
        ),
        (
            "bridge-setup-apply-reconcile-conflict",
            NativeTransactionStatus::Conflict,
            SetupPlanLifecycle::Conflict,
            false,
        ),
    ] {
        let path = TempVault::new(name);
        let mut vault = Vault::open(path.path(), "bridge-setup-apply-v1", &keys).unwrap();
        let (candidate, _) = persist(&mut vault, plan());
        let crashed = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let _ = BridgeInstallService::persisted(&mut vault).apply(
                &candidate.setup.plan_id,
                NOW_MS + 1,
                &mut CrashAfterTerminal(terminal),
            );
        }));
        assert!(crashed.is_err());
        assert_eq!(
            vault
                .setup_plan(&candidate.setup.plan_id)
                .unwrap()
                .unwrap()
                .lifecycle,
            SetupPlanLifecycle::Applying
        );
        let mut executor = RecordingExecutor::default();

        let result = BridgeInstallService::persisted(&mut vault).apply(
            &candidate.setup.plan_id,
            NOW_MS + 2,
            &mut executor,
        );

        assert_eq!(result.is_ok(), succeeds, "{name}");
        assert_eq!(executor.calls, 0, "{name}: must not re-execute");
        assert_eq!(
            vault
                .setup_plan(&candidate.setup.plan_id)
                .unwrap()
                .unwrap()
                .lifecycle,
            expected_lifecycle,
            "{name}"
        );
    }
}

#[test]
fn committed_apply_recovery_publishes_the_pre_execution_registration_binding() {
    let path = TempVault::new("bridge-setup-apply-native-memory-binding-recovery");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), "bridge-setup-apply-v1", &keys).unwrap();
    let descriptor = native_memory_source();
    let intended_digest = Sha256Digest([77; 32]);
    let registration = NativeMemoryRegistration {
        source: descriptor.clone(),
        last_applied_digest: Some(intended_digest),
    };
    let mut candidate = plan();
    candidate.native_memory_registrations = vec![registration.clone()];
    let (candidate, _) = persist(&mut vault, candidate);

    let mut rejected = RecordingExecutor::default();
    let error = BridgeInstallService::persisted(&mut vault)
        .apply_with_native_memory(&candidate.setup.plan_id, NOW_MS + 1, &[], &mut rejected)
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
    assert_eq!(rejected.calls, 0);

    let crashed = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let _ = BridgeInstallService::persisted(&mut vault).apply_with_native_memory(
            &candidate.setup.plan_id,
            NOW_MS + 1,
            std::slice::from_ref(&registration),
            &mut CrashAfterTerminal(NativeTransactionStatus::Committed),
        );
    }));
    assert!(crashed.is_err());
    assert!(
        vault
            .native_memory_ledger(&descriptor.id)
            .unwrap()
            .is_none()
    );
    drop(vault);

    let mut reopened = Vault::open(path.path(), "bridge-setup-apply-v1", &keys).unwrap();
    BridgeInstallService::persisted(&mut reopened)
        .reconcile_after_native_recovery()
        .unwrap();

    assert_eq!(
        reopened
            .native_memory_ledger(&descriptor.id)
            .unwrap()
            .unwrap()
            .last_applied_digest,
        Some(intended_digest)
    );
    assert_eq!(
        reopened
            .setup_plan(&candidate.setup.plan_id)
            .unwrap()
            .unwrap()
            .lifecycle,
        SetupPlanLifecycle::Applied
    );
}

#[test]
fn descriptor_replacement_recovers_and_rolls_back_without_stranding_shared_preexisting_state() {
    let path = TempVault::new("bridge-setup-descriptor-replacement-recovery");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), "bridge-setup-apply-v1", &keys).unwrap();
    let original = native_memory_source();
    let mut preexisting = NativeMemoryLedger::for_source(original.clone());
    preexisting.last_unmanaged_digest = Some(Sha256Digest([80; 32]));
    preexisting.initial_preview_complete = true;
    vault
        .put_native_memory_candidate(&preexisting, None)
        .unwrap();
    let original_registration = NativeMemoryRegistration {
        source: original.clone(),
        last_applied_digest: Some(Sha256Digest([81; 32])),
    };

    let mut first = plan();
    first.native_memory_registrations = vec![original_registration.clone()];
    let (first, _) = persist(&mut vault, first);
    BridgeInstallService::persisted(&mut vault)
        .apply(
            &first.setup.plan_id,
            NOW_MS + 1,
            &mut RecordingExecutor::default(),
        )
        .unwrap();

    let mut shared = plan();
    shared.setup.plan_id = PlanId::from_str(ID_2).unwrap();
    shared.native_memory_registrations = vec![original_registration];
    let (shared, _) = persist(&mut vault, shared);
    BridgeInstallService::persisted(&mut vault)
        .apply(
            &shared.setup.plan_id,
            NOW_MS + 2,
            &mut RecordingExecutor::default(),
        )
        .unwrap();

    let replacement = NativeMemorySource::new(
        original.harness,
        &original.adapter_version,
        original.scope.clone(),
        original.document_kind,
        original.path.clone(),
        NativeMemoryLimits {
            max_bytes: 2_048,
            max_characters: 2_048,
        },
        false,
    )
    .unwrap();
    assert_ne!(original.id, replacement.id);
    let replacement_registration = NativeMemoryRegistration {
        source: replacement.clone(),
        last_applied_digest: Some(Sha256Digest([82; 32])),
    };
    let mut changed = plan();
    changed.setup.plan_id = PlanId::from_str(ID_3).unwrap();
    changed.native_memory_registrations = vec![replacement_registration];
    let (changed, _) = persist(&mut vault, changed);
    let crashed = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let _ = BridgeInstallService::persisted(&mut vault).apply(
            &changed.setup.plan_id,
            NOW_MS + 3,
            &mut CrashAfterTerminal(NativeTransactionStatus::Committed),
        );
    }));
    assert!(crashed.is_err());
    drop(vault);

    let mut reopened = Vault::open(path.path(), "bridge-setup-apply-v1", &keys).unwrap();
    BridgeInstallService::persisted(&mut reopened)
        .reconcile_after_native_recovery()
        .unwrap();
    assert_eq!(
        reopened
            .setup_plan(&changed.setup.plan_id)
            .unwrap()
            .unwrap()
            .lifecycle,
        SetupPlanLifecycle::Applied
    );
    assert!(
        reopened
            .native_memory_ledger(&original.id)
            .unwrap()
            .is_some()
    );
    assert!(
        reopened
            .native_memory_ledger(&replacement.id)
            .unwrap()
            .is_some()
    );

    for (plan_id, now_ms) in [
        (changed.setup.plan_id, NOW_MS + 4),
        (shared.setup.plan_id, NOW_MS + 5),
        (first.setup.plan_id, NOW_MS + 6),
    ] {
        BridgeInstallService::persisted(&mut reopened)
            .rollback(&plan_id, now_ms, &mut RecordingExecutor::default())
            .unwrap();
    }

    assert!(
        reopened
            .native_memory_ledger(&replacement.id)
            .unwrap()
            .is_none()
    );
    let preserved = reopened
        .native_memory_ledger(&original.id)
        .unwrap()
        .unwrap();
    assert_eq!(
        preserved.last_unmanaged_digest,
        Some(Sha256Digest([80; 32]))
    );
    assert!(preserved.initial_preview_complete);
}

#[test]
fn startup_reconciliation_leaves_pending_or_missing_native_outcomes_unexecuted() {
    let keys = MemoryKeyStore::default();
    for (name, native_status) in [
        (
            "bridge-setup-reconcile-pending",
            Some(NativeTransactionStatus::Pending),
        ),
        ("bridge-setup-reconcile-missing", None),
    ] {
        let path = TempVault::new(name);
        let mut vault = Vault::open(path.path(), "bridge-setup-apply-v1", &keys).unwrap();
        let (candidate, sealed) = persist(&mut vault, plan());
        vault
            .claim_setup_plan(&candidate.setup.plan_id, SetupPlanAction::Apply, NOW_MS + 1)
            .unwrap();
        if let Some(status) = native_status {
            persist_native_terminal(&mut vault, &candidate, &sealed, NOW_MS, NOW_MS + 1, status);
        }

        assert!(
            BridgeInstallService::persisted(&mut vault)
                .reconcile_after_native_recovery()
                .is_err(),
            "{name}"
        );
        assert_eq!(
            vault
                .setup_plan(&candidate.setup.plan_id)
                .unwrap()
                .unwrap()
                .lifecycle,
            SetupPlanLifecycle::Applying,
            "{name}"
        );
    }
}
