mod support;

use std::{panic::AssertUnwindSafe, str::FromStr};

use context_relay_core::{
    native_transaction::{
        ApprovedCliMutation, CanonicalCliDeclaration, NativeTransactionPlan, SidecarBinding,
        approval_hash_v2, seal_plan,
    },
    setup::{BridgeExecutionError, BridgeInstallService, BridgePlanExecutor},
    vault::{NativeTransactionStatus, SetupPlanAction, SetupPlanLifecycle, SetupPlanWrite, Vault},
};
use context_relay_native_runner::{
    RuleSyncFeature, RuleSyncFeatures, RuleSyncTarget, RuntimeTarget, SidecarCommand, SidecarId,
};
use context_relay_protocol::{
    ApprovalClass, CliOperation, HarnessId, NativePlatform, NativeScope, NetworkDelta,
    PermissionDelta, PlanId, SetupPlan, Sha256Digest, WireNativeValue,
};
use sha2::{Digest as _, Sha256};

use support::{ID_1, MemoryKeyStore, TempVault, persist_native_terminal};

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
