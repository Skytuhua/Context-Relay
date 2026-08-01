//! Mutation-free preview and persistence of managed bridge installation plans.

use std::{fmt::Write as _, path::PathBuf, str::FromStr};

use context_relay_native_runner::{
    RuleSyncFeature, RuleSyncFeatures, RuleSyncTarget, RuntimeTarget, SidecarCommand, SidecarId,
};
use context_relay_protocol::{
    ApprovalClass, CapabilityLevel, ChangeClass, ClassifiedChange, ClientError, ComponentKind,
    ComponentRecord, DesiredState, DeviceId, ErrorCode, ExpectedNativeDigest, HarnessAdapter,
    HarnessId, HybridLogicalClock, ImportRequest, NativePlatform, NativeScope, PlanId,
    ProbeContext, ProjectId, ScopeRef, SemanticDiff, SetupPlan, Sha256Digest, WireNativeValue,
};
use sha2::{Digest as _, Sha256};

use crate::{
    claude_code::ClaudeCodeAdapter,
    codex::CodexAdapter,
    hermes::HermesAdapter,
    mcp::install::{
        BRIDGE_SERVER_NAME, attest_bridge_executable, bridge_component_for_attested,
        is_canonical_bridge_body,
    },
    native_memory::{
        NativeMemoryAdapter, NativeMemoryDisable, NativeMemoryRegistration, managed_memory_hooks,
        primary_memory_instruction_component,
    },
    native_transaction::{
        ApprovedCliMutation, ApprovedMutation, NativeTransactionPlan,
        REVERSIBLE_PLAN_SCHEMA_VERSION, SidecarBinding, approval_hash_v2, open_plan, seal_plan,
        seal_reversible_plan,
    },
    vault::{
        BeforeImagePolicy, NativeSandboxIdentity, NativeTransactionStatus, SetupPlanAction,
        SetupPlanClaim, SetupPlanLifecycle, SetupPlanWrite, Vault,
    },
};

pub const PREVIEW_TTL_MS: u64 = 15 * 60 * 1_000;

/// A registered project is imported for conflict detection and binds the
/// managed primary-memory instruction. The bridge itself remains global.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredProject {
    pub project_id: context_relay_protocol::ProjectId,
    pub root: WireNativeValue,
}

pub struct BridgeMutationPlan {
    pub cli: Option<ApprovedCliMutation>,
    pub native: Vec<ApprovedMutation>,
}

pub struct PrimaryMemoryMutationPlan {
    pub native: Vec<ApprovedMutation>,
    pub registrations: Vec<NativeMemoryRegistration>,
    pub semantic_changes: Vec<ClassifiedChange>,
}

impl PrimaryMemoryMutationPlan {
    fn empty() -> Self {
        Self {
            native: vec![],
            registrations: vec![],
            semantic_changes: vec![],
        }
    }
}

/// Locates the bridge executable selected by the service composition layer.
///
/// Production composition supplies a locator for the installed bridge, while
/// tests can inject a fixed identity through this boundary. Preview re-attests
/// the returned path before using that identity.
pub trait BridgeLocator {
    fn locate(&self) -> Result<crate::mcp::install::BridgeExecutable, ClientError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BridgeExecutionError {
    Restored(String),
    Conflict(String),
}

impl BridgeExecutionError {
    pub fn restored(message: impl Into<String>) -> Self {
        Self::Restored(message.into())
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::Conflict(message.into())
    }

    fn message(&self) -> &str {
        match self {
            Self::Restored(message) | Self::Conflict(message) => message,
        }
    }
}

/// Dependency-injection boundary for an already composed native transaction
/// engine. The service supplies the opened persisted plan and its exact sealed
/// bytes; callers cannot replace any approved field.
pub trait BridgePlanExecutor {
    fn execute(
        &mut self,
        vault: &mut Vault,
        plan: &NativeTransactionPlan,
        sealed_plan: &[u8],
        created_ms: u64,
        now_ms: u64,
    ) -> Result<(), BridgeExecutionError>;
}

/// Concrete production composition for the persisted-plan executor boundary.
/// It constructs the existing native transaction engine with a journal bound
/// to the exact sealed bytes supplied by the service.
pub struct NativeEngineBridgePlanExecutor<'a, A, E, F, H, C> {
    adapter: &'a mut A,
    restricted_executor: &'a mut E,
    filesystem: &'a mut F,
    hook: &'a mut H,
    cli_executor: &'a mut C,
    lock_root: PathBuf,
    identity: NativeSandboxIdentity,
    before_image_policy: BeforeImagePolicy,
    applied_hlc: HybridLogicalClock,
}

impl<'a, A, E, F, H, C> NativeEngineBridgePlanExecutor<'a, A, E, F, H, C> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        adapter: &'a mut A,
        restricted_executor: &'a mut E,
        filesystem: &'a mut F,
        hook: &'a mut H,
        cli_executor: &'a mut C,
        lock_root: impl Into<PathBuf>,
        identity: NativeSandboxIdentity,
        before_image_policy: BeforeImagePolicy,
        applied_hlc: HybridLogicalClock,
    ) -> Self {
        Self {
            adapter,
            restricted_executor,
            filesystem,
            hook,
            cli_executor,
            lock_root: lock_root.into(),
            identity,
            before_image_policy,
            applied_hlc,
        }
    }
}

impl<A, E, F, H, C> BridgePlanExecutor for NativeEngineBridgePlanExecutor<'_, A, E, F, H, C>
where
    A: crate::native_transaction::engine::NativeAdapter,
    E: crate::native_transaction::engine::RestrictedExecutor,
    F: crate::native_transaction::engine::NativeFileSystem,
    H: crate::native_transaction::engine::FaultHook,
    C: crate::native_transaction::cli::NativeCliExecutor,
{
    fn execute(
        &mut self,
        vault: &mut Vault,
        plan: &NativeTransactionPlan,
        sealed_plan: &[u8],
        created_ms: u64,
        now_ms: u64,
    ) -> Result<(), BridgeExecutionError> {
        let transaction_id = native_transaction_id(&plan.setup.plan_id);
        let result = {
            let mut journal = crate::native_transaction::journal::VaultNativeJournal::new(
                vault,
                &self.lock_root,
                &transaction_id,
                self.identity.clone(),
                sealed_plan.to_vec(),
                created_ms,
                self.before_image_policy,
            );
            if plan.cli_mutations.is_empty() {
                crate::native_transaction::engine::NativeTransactionEngine::new(
                    self.adapter,
                    self.restricted_executor,
                    self.filesystem,
                    &mut journal,
                    self.hook,
                )
                .apply(plan, now_ms, self.applied_hlc)
            } else {
                crate::native_transaction::engine::NativeTransactionEngine::new_with_cli(
                    self.adapter,
                    self.restricted_executor,
                    self.filesystem,
                    &mut journal,
                    self.hook,
                    self.cli_executor,
                )
                .apply(plan, now_ms, self.applied_hlc)
            }
        };
        match result {
            Ok(_) => Ok(()),
            Err(error) => {
                let message = error.to_string();
                match vault
                    .native_transaction(&transaction_id)
                    .ok()
                    .flatten()
                    .map(|snapshot| snapshot.status)
                {
                    Some(NativeTransactionStatus::Committed) => Ok(()),
                    Some(NativeTransactionStatus::Restored) => {
                        Err(BridgeExecutionError::Restored(message))
                    }
                    Some(NativeTransactionStatus::Conflict) => {
                        Err(BridgeExecutionError::Conflict(message))
                    }
                    _ => Err(BridgeExecutionError::Conflict(message)),
                }
            }
        }
    }
}

/// CLI placeholder for a harness whose sealed plan has no CLI mutations.
#[derive(Default)]
pub struct NoBridgeCliExecutor;

impl crate::native_transaction::cli::NativeCliExecutor for NoBridgeCliExecutor {
    fn probe_cli_mutation(
        &mut self,
        _: &ApprovedCliMutation,
    ) -> Result<
        Option<context_relay_protocol::Sha256Digest>,
        crate::native_transaction::engine::BoundaryError,
    > {
        Err(crate::native_transaction::engine::BoundaryError::new(
            "bridge plan unexpectedly contains CLI mutations",
        ))
    }

    fn compare_cli_targets(
        &mut self,
        _: &[ApprovedCliMutation],
    ) -> Result<(), crate::native_transaction::engine::BoundaryError> {
        Err(crate::native_transaction::engine::BoundaryError::new(
            "bridge plan unexpectedly contains CLI mutations",
        ))
    }

    fn apply_cli_mutation(
        &mut self,
        _: &ApprovedCliMutation,
    ) -> Result<
        crate::native_transaction::cli::CliMutationOutcome,
        crate::native_transaction::engine::BoundaryError,
    > {
        Err(crate::native_transaction::engine::BoundaryError::new(
            "bridge plan unexpectedly contains CLI mutations",
        ))
    }

    fn restore_cli_mutation_if_matches(
        &mut self,
        _: &ApprovedCliMutation,
    ) -> Result<
        crate::native_transaction::cli::CliRestoreOutcome,
        crate::native_transaction::engine::BoundaryError,
    > {
        Err(crate::native_transaction::engine::BoundaryError::new(
            "bridge plan unexpectedly contains CLI mutations",
        ))
    }

    fn finish_committed_cli_mutations(
        &mut self,
        _: &[ApprovedCliMutation],
    ) -> Result<(), crate::native_transaction::engine::BoundaryError> {
        Err(crate::native_transaction::engine::BoundaryError::new(
            "bridge plan unexpectedly contains CLI mutations",
        ))
    }
}

pub struct PersistedBridgeInstallService<'a> {
    vault: &'a mut Vault,
}

/// The narrow capability preview needs in addition to the protocol adapter.
///
/// The specific adapter owns expected-state inspection and creation of both
/// forward and rollback argv; this service never accepts either from callers.
pub trait BridgePreviewHarness: HarnessAdapter {
    fn bridge_harness(&self) -> HarnessId;

    /// The project receiving the managed primary-memory instruction. Legacy
    /// bridge-only test harnesses opt out by retaining the default `None`.
    fn bridge_project_id(&self) -> Option<ProjectId> {
        None
    }

    fn bridge_project_root(&self) -> Option<WireNativeValue> {
        None
    }

    fn bridge_requested_profile(&self) -> Option<String> {
        None
    }

    fn bridge_mutations(
        &self,
        desired: &DesiredState,
        intended: &ComponentRecord,
    ) -> Result<BridgeMutationPlan, ClientError>;

    fn primary_memory_mutations(
        &self,
        _desired: &DesiredState,
    ) -> Result<PrimaryMemoryMutationPlan, ClientError> {
        Ok(PrimaryMemoryMutationPlan::empty())
    }

    fn bridge_adapter_version(&self) -> u32 {
        1
    }
}

impl BridgePreviewHarness for ClaudeCodeAdapter {
    fn bridge_harness(&self) -> HarnessId {
        HarnessId::ClaudeCode
    }

    fn bridge_project_id(&self) -> Option<ProjectId> {
        Some(self.project_id())
    }

    fn bridge_project_root(&self) -> Option<WireNativeValue> {
        Some(self.project_root_wire())
    }

    fn bridge_mutations(
        &self,
        _: &DesiredState,
        intended: &ComponentRecord,
    ) -> Result<BridgeMutationPlan, ClientError> {
        Ok(BridgeMutationPlan {
            cli: Some(self.plan_bridge_cli_mutation(intended)?),
            native: vec![],
        })
    }

    fn primary_memory_mutations(
        &self,
        desired: &DesiredState,
    ) -> Result<PrimaryMemoryMutationPlan, ClientError> {
        let capabilities = self.native_memory_capabilities()?;
        let mut plan = primary_memory_registration_plan(&capabilities.sources);
        if let Some(instruction) = desired
            .components
            .iter()
            .find(|component| component.kind == ComponentKind::Instruction)
        {
            push_memory_mutation(
                &mut plan,
                self.plan_native_file(instruction)?,
                "primary-memory-instruction",
            );
        }
        if desired
            .components
            .iter()
            .any(|component| component.kind == ComponentKind::Hook)
        {
            push_memory_mutation(
                &mut plan,
                self.plan_native_global_settings(desired)?,
                "primary-memory-hooks",
            );
        }
        if let NativeMemoryDisable::Supported(mutations) = capabilities.disable {
            for mutation in mutations {
                push_memory_mutation(&mut plan, mutation, "native-memory-disable");
            }
        }
        Ok(plan)
    }
}

impl BridgePreviewHarness for CodexAdapter {
    fn bridge_harness(&self) -> HarnessId {
        HarnessId::Codex
    }

    fn bridge_project_id(&self) -> Option<ProjectId> {
        Some(self.project_id())
    }

    fn bridge_project_root(&self) -> Option<WireNativeValue> {
        Some(self.project_root_wire())
    }

    fn bridge_mutations(
        &self,
        _: &DesiredState,
        intended: &ComponentRecord,
    ) -> Result<BridgeMutationPlan, ClientError> {
        Ok(BridgeMutationPlan {
            cli: Some(self.plan_bridge_cli_mutation(intended)?),
            native: vec![],
        })
    }

    fn primary_memory_mutations(
        &self,
        desired: &DesiredState,
    ) -> Result<PrimaryMemoryMutationPlan, ClientError> {
        let capabilities = self.native_memory_capabilities()?;
        let mut plan = primary_memory_registration_plan(&capabilities.sources);
        if let Some(instruction) = desired
            .components
            .iter()
            .find(|component| component.kind == ComponentKind::Instruction)
        {
            push_memory_mutation(
                &mut plan,
                self.plan_native_markdown(instruction)?,
                "primary-memory-instruction",
            );
        }
        for hook in desired
            .components
            .iter()
            .filter(|component| component.kind == ComponentKind::Hook)
        {
            push_memory_mutation(
                &mut plan,
                self.plan_native_hooks_json(hook)?,
                "primary-memory-hooks",
            );
        }
        if let NativeMemoryDisable::Supported(mutations) = capabilities.disable {
            for mutation in mutations {
                push_memory_mutation(&mut plan, mutation, "native-memory-disable");
            }
        }
        Ok(plan)
    }
}

impl BridgePreviewHarness for HermesAdapter {
    fn bridge_harness(&self) -> HarnessId {
        HarnessId::Hermes
    }

    fn bridge_project_id(&self) -> Option<ProjectId> {
        Some(self.project_id())
    }

    fn bridge_project_root(&self) -> Option<WireNativeValue> {
        Some(self.project_root_wire())
    }

    fn bridge_requested_profile(&self) -> Option<String> {
        Some(self.profile_name().to_owned())
    }

    fn bridge_mutations(
        &self,
        _: &DesiredState,
        _: &ComponentRecord,
    ) -> Result<BridgeMutationPlan, ClientError> {
        Ok(BridgeMutationPlan {
            cli: None,
            native: vec![],
        })
    }

    fn primary_memory_mutations(
        &self,
        desired: &DesiredState,
    ) -> Result<PrimaryMemoryMutationPlan, ClientError> {
        let capabilities = self.native_memory_capabilities()?;
        let mut plan = primary_memory_registration_plan(&capabilities.sources);
        if let Some(instruction) = desired
            .components
            .iter()
            .find(|component| component.kind == ComponentKind::Instruction)
            && let Some(mutation) = self.plan_native_markdown(instruction)?
        {
            push_memory_mutation(&mut plan, mutation, "primary-memory-instruction");
        }
        let disable = match capabilities.disable {
            NativeMemoryDisable::Supported(mutations) => mutations,
            NativeMemoryDisable::WatchOnly | NativeMemoryDisable::Unavailable => vec![],
        };
        if let Some(mutation) = self.plan_native_config_with_memory_disable(desired, &disable)? {
            push_memory_mutation(
                &mut plan,
                mutation,
                if disable.is_empty() {
                    "primary-memory-bridge"
                } else {
                    "primary-memory-bridge-and-disable"
                },
            );
        }
        Ok(plan)
    }
}

fn primary_memory_registration_plan(
    sources: &[crate::native_memory::NativeMemorySource],
) -> PrimaryMemoryMutationPlan {
    let mut plan = PrimaryMemoryMutationPlan::empty();
    for source in sources {
        plan.registrations.push(NativeMemoryRegistration {
            source: source.clone(),
            last_applied_digest: None,
        });
        plan.semantic_changes.push(ClassifiedChange {
            class: ChangeClass::Create,
            target: format!("native-memory-source:{}", digest_text(source.id.0)),
            summary: "Register a validated native memory fallback source".to_owned(),
        });
    }
    plan
}

fn push_memory_mutation(
    plan: &mut PrimaryMemoryMutationPlan,
    mutation: ApprovedMutation,
    target: &str,
) {
    if mutation.expected == mutation.intended {
        return;
    }
    plan.native.push(mutation);
    plan.semantic_changes.push(ClassifiedChange {
        class: ChangeClass::Update,
        target: target.to_owned(),
        summary: target.to_owned(),
    });
}

pub struct BridgeInstallService<'a, H, L> {
    vault: &'a mut Vault,
    harness: H,
    bridge_locator: L,
    origin_device: DeviceId,
    observed_hlc: HybridLogicalClock,
}

impl<'a> BridgeInstallService<'a, (), ()> {
    pub fn persisted(vault: &'a mut Vault) -> PersistedBridgeInstallService<'a> {
        PersistedBridgeInstallService { vault }
    }
}

impl<H, L> BridgeInstallService<'_, H, L> {
    pub fn apply<E: BridgePlanExecutor>(
        &mut self,
        plan_id: &PlanId,
        now_ms: u64,
        executor: &mut E,
    ) -> Result<(), ClientError> {
        PersistedBridgeInstallService {
            vault: &mut *self.vault,
        }
        .apply(plan_id, now_ms, executor)
    }

    pub fn rollback<E: BridgePlanExecutor>(
        &mut self,
        original_plan_id: &PlanId,
        now_ms: u64,
        executor: &mut E,
    ) -> Result<(), ClientError> {
        PersistedBridgeInstallService {
            vault: &mut *self.vault,
        }
        .rollback(original_plan_id, now_ms, executor)
    }
}

impl PersistedBridgeInstallService<'_> {
    /// Transactional apply boundary used by Task 10 after it derives memory
    /// registrations from the opened sealed setup plan.
    pub fn finish_applied_with_native_memory(
        &mut self,
        plan_id: &PlanId,
        registrations: &[NativeMemoryRegistration],
    ) -> Result<(), ClientError> {
        self.vault
            .finish_setup_plan_with_native_memory(
                plan_id,
                SetupPlanLifecycle::Applied,
                registrations,
            )
            .map_err(|_| conflict("Persisted bridge apply cannot be finalized"))
    }

    /// Reconciles setup lifecycles after native startup recovery has made each
    /// begun transaction terminal. A missing native row is reported without
    /// executing; a subsequent explicit apply/rollback may safely resume it.
    pub fn reconcile_after_native_recovery(&mut self) -> Result<(), ClientError> {
        let incomplete = self
            .vault
            .incomplete_setup_plans()
            .map_err(|_| invalid("Incomplete bridge plans cannot be loaded"))?;
        for candidate in incomplete {
            let stored = self
                .vault
                .setup_plan(&candidate.plan_id)
                .map_err(|_| invalid("Incomplete bridge plan cannot be reloaded"))?
                .ok_or_else(|| invalid("Incomplete bridge plan disappeared"))?;
            if !matches!(
                stored.lifecycle,
                SetupPlanLifecycle::Applying | SetupPlanLifecycle::RollingBack
            ) {
                continue;
            }
            let candidate_opened = open_plan(&stored.payload)
                .map_err(|_| invalid("Incomplete bridge plan is malformed or unapproved"))?;
            if let Some(original_id) = candidate_opened.rollback_of_plan_id {
                let original = self
                    .vault
                    .setup_plan(&original_id)
                    .map_err(|_| invalid("Rollback original plan cannot be loaded"))?
                    .ok_or_else(|| invalid("Rollback original plan does not exist"))?;
                if original.lifecycle != SetupPlanLifecycle::RollingBack {
                    return Err(invalid("Rollback inverse has no active original"));
                }
                continue;
            }
            let opened = validated_original_plan(&stored, &stored.plan_id)?;
            match stored.lifecycle {
                SetupPlanLifecycle::Applying => {
                    if self.reconcile_apply_terminal(&stored)?.is_none() {
                        return Err(conflict(
                            "Bridge apply has not begun its native transaction",
                        ));
                    }
                }
                SetupPlanLifecycle::RollingBack => {
                    let (inverse, _) = self.validated_inverse_plan(&opened)?;
                    if self
                        .reconcile_rollback_terminal(&stored, &inverse)?
                        .is_none()
                    {
                        return Err(conflict(
                            "Bridge rollback has not begun its native transaction",
                        ));
                    }
                }
                _ => return Err(invalid("Incomplete bridge plan lifecycle is invalid")),
            }
        }
        Ok(())
    }

    pub fn apply<E: BridgePlanExecutor>(
        &mut self,
        plan_id: &PlanId,
        now_ms: u64,
        executor: &mut E,
    ) -> Result<(), ClientError> {
        self.apply_sealed_native_memory(plan_id, now_ms, executor)
    }

    /// Compatibility entry point for callers that already hold the previewed
    /// registrations. The opened sealed plan remains authoritative; a caller
    /// cannot add, remove, or alter a descriptor through this argument.
    pub fn apply_with_native_memory<E: BridgePlanExecutor>(
        &mut self,
        plan_id: &PlanId,
        now_ms: u64,
        registrations: &[NativeMemoryRegistration],
        executor: &mut E,
    ) -> Result<(), ClientError> {
        let stored = self
            .vault
            .setup_plan(plan_id)
            .map_err(|_| invalid("Persisted bridge plan cannot be loaded"))?
            .ok_or_else(|| invalid("Persisted bridge plan does not exist"))?;
        let opened = validated_original_plan(&stored, plan_id)?;
        if opened.plan.native_memory_registrations != registrations {
            return Err(conflict(
                "Native memory registrations differ from the persisted bridge plan",
            ));
        }
        self.apply_sealed_native_memory(plan_id, now_ms, executor)
    }

    /// Applies the exact native-memory registration set derived from the
    /// opened sealed setup plan. The binding is durable before the native
    /// executor starts, so startup recovery can finalize it.
    fn apply_sealed_native_memory<E: BridgePlanExecutor>(
        &mut self,
        plan_id: &PlanId,
        now_ms: u64,
        executor: &mut E,
    ) -> Result<(), ClientError> {
        let stored = self
            .vault
            .setup_plan(plan_id)
            .map_err(|_| invalid("Persisted bridge plan cannot be loaded"))?
            .ok_or_else(|| invalid("Persisted bridge plan does not exist"))?;
        let opened = validated_original_plan(&stored, plan_id)?;
        let registrations = &opened.plan.native_memory_registrations;
        if stored.lifecycle == SetupPlanLifecycle::Applying {
            self.vault
                .bind_setup_plan_native_memory(plan_id, registrations)
                .map_err(|_| conflict("Persisted bridge memory binding changed"))?;
            if let Some(lifecycle) = self.reconcile_apply_terminal(&stored)? {
                return apply_terminal_result(lifecycle);
            }
            if now_ms >= stored.expires_ms {
                self.vault
                    .finish_setup_plan(plan_id, SetupPlanLifecycle::ApplyRestored)
                    .map_err(|_| conflict("Expired bridge apply cannot be finalized"))?;
                return Err(conflict("Persisted bridge apply plan has expired"));
            }
            return self.execute_claimed_apply(
                &stored,
                &opened.plan,
                registrations,
                now_ms,
                executor,
            );
        }
        if stored.lifecycle == SetupPlanLifecycle::Applied {
            self.vault
                .bind_setup_plan_native_memory(plan_id, registrations)
                .map_err(|_| conflict("Persisted bridge memory binding changed"))?;
            return Ok(());
        }
        if matches!(
            stored.lifecycle,
            SetupPlanLifecycle::ApplyRestored | SetupPlanLifecycle::Conflict
        ) {
            return apply_terminal_result(stored.lifecycle);
        }
        match self
            .vault
            .claim_setup_plan(plan_id, SetupPlanAction::Apply, now_ms)
            .map_err(|_| conflict("Persisted bridge plan cannot be claimed for apply"))?
        {
            SetupPlanClaim::Replay => return Ok(()),
            SetupPlanClaim::Claimed => {}
        }
        self.execute_claimed_apply(&stored, &opened.plan, registrations, now_ms, executor)
    }

    fn execute_claimed_apply<E: BridgePlanExecutor>(
        &mut self,
        stored: &crate::vault::SetupPlanRecord,
        plan: &NativeTransactionPlan,
        registrations: &[NativeMemoryRegistration],
        now_ms: u64,
        executor: &mut E,
    ) -> Result<(), ClientError> {
        self.vault
            .bind_setup_plan_native_memory(&plan.setup.plan_id, registrations)
            .map_err(|_| conflict("Persisted bridge memory binding cannot be recorded"))?;
        match executor.execute(self.vault, plan, &stored.payload, stored.created_ms, now_ms) {
            Ok(()) => self.finish_applied_with_native_memory(&plan.setup.plan_id, registrations),
            Err(error) => {
                let lifecycle = match error {
                    BridgeExecutionError::Restored(_) => SetupPlanLifecycle::ApplyRestored,
                    BridgeExecutionError::Conflict(_) => SetupPlanLifecycle::Conflict,
                };
                self.vault
                    .finish_setup_plan(&plan.setup.plan_id, lifecycle)
                    .map_err(|_| conflict("Persisted bridge apply failure cannot be finalized"))?;
                Err(conflict_owned(error.message()))
            }
        }
    }

    pub fn rollback<E: BridgePlanExecutor>(
        &mut self,
        original_plan_id: &PlanId,
        now_ms: u64,
        executor: &mut E,
    ) -> Result<(), ClientError> {
        let stored = self
            .vault
            .setup_plan(original_plan_id)
            .map_err(|_| invalid("Persisted bridge plan cannot be loaded"))?
            .ok_or_else(|| invalid("Persisted bridge plan does not exist"))?;
        let opened = validated_original_plan(&stored, original_plan_id)?;
        if stored.lifecycle == SetupPlanLifecycle::RolledBack {
            return Ok(());
        }
        if stored.lifecycle == SetupPlanLifecycle::RollingBack {
            let (inverse_record, inverse) = self.validated_inverse_plan(&opened)?;
            if let Some(lifecycle) = self.reconcile_rollback_terminal(&stored, &inverse_record)? {
                return rollback_terminal_result(lifecycle);
            }
            if now_ms >= inverse_record.expires_ms {
                self.vault
                    .finish_setup_plan_rollback(
                        original_plan_id,
                        &inverse_record.plan_id,
                        SetupPlanLifecycle::RollbackRestored,
                        SetupPlanLifecycle::ApplyRestored,
                    )
                    .map_err(|_| conflict("Expired bridge rollback cannot be finalized"))?;
                return Err(conflict("Persisted bridge rollback plan has expired"));
            }
            return self.execute_claimed_rollback(
                &stored,
                &inverse_record,
                &inverse.plan,
                now_ms,
                executor,
            );
        }
        if matches!(
            stored.lifecycle,
            SetupPlanLifecycle::RollbackRestored | SetupPlanLifecycle::Conflict
        ) {
            return rollback_terminal_result(stored.lifecycle);
        }

        let (inverse, inverse_rollback_states) = inverse_plan(&opened, now_ms)?;
        let inverse_approval =
            approval_hash_v2(&inverse).map_err(|_| invalid("Rollback bridge plan is invalid"))?;
        let inverse_sealed = seal_reversible_plan(
            &inverse,
            inverse_approval,
            &inverse_rollback_states,
            Some(*original_plan_id),
        )
        .map_err(|_| invalid("Rollback bridge plan cannot be sealed"))?;
        match self
            .vault
            .claim_setup_plan_rollback(
                original_plan_id,
                SetupPlanWrite {
                    plan_id: &inverse.setup.plan_id,
                    schema_version: REVERSIBLE_PLAN_SCHEMA_VERSION,
                    approval_version: 2,
                    approval_hash: &inverse_approval,
                    payload: &inverse_sealed,
                    created_ms: now_ms,
                    expires_ms: inverse.setup.expires_at,
                },
                now_ms,
            )
            .map_err(|_| conflict("Rollback bridge plan cannot be persisted and claimed"))?
        {
            SetupPlanClaim::Replay => return Ok(()),
            SetupPlanClaim::Claimed => {}
        }
        let inverse_record = self
            .vault
            .setup_plan(&inverse.setup.plan_id)
            .map_err(|_| invalid("Rollback inverse plan cannot be reloaded"))?
            .ok_or_else(|| invalid("Rollback inverse plan does not exist"))?;
        self.execute_claimed_rollback(&stored, &inverse_record, &inverse, now_ms, executor)
    }

    fn execute_claimed_rollback<E: BridgePlanExecutor>(
        &mut self,
        original: &crate::vault::SetupPlanRecord,
        inverse_record: &crate::vault::SetupPlanRecord,
        inverse: &NativeTransactionPlan,
        now_ms: u64,
        executor: &mut E,
    ) -> Result<(), ClientError> {
        match executor.execute(
            self.vault,
            inverse,
            &inverse_record.payload,
            inverse_record.created_ms,
            now_ms,
        ) {
            Ok(()) => self
                .vault
                .finish_setup_plan_rollback(
                    &original.plan_id,
                    &inverse_record.plan_id,
                    SetupPlanLifecycle::RolledBack,
                    SetupPlanLifecycle::Applied,
                )
                .map_err(|_| conflict("Persisted bridge rollback cannot be finalized")),
            Err(error) => {
                let (original_lifecycle, inverse_lifecycle) = match error {
                    BridgeExecutionError::Restored(_) => (
                        SetupPlanLifecycle::RollbackRestored,
                        SetupPlanLifecycle::ApplyRestored,
                    ),
                    BridgeExecutionError::Conflict(_) => {
                        (SetupPlanLifecycle::Conflict, SetupPlanLifecycle::Conflict)
                    }
                };
                self.vault
                    .finish_setup_plan_rollback(
                        &original.plan_id,
                        &inverse_record.plan_id,
                        original_lifecycle,
                        inverse_lifecycle,
                    )
                    .map_err(|_| {
                        conflict("Persisted bridge rollback failure cannot be finalized")
                    })?;
                Err(conflict_owned(error.message()))
            }
        }
    }

    fn reconcile_apply_terminal(
        &mut self,
        stored: &crate::vault::SetupPlanRecord,
    ) -> Result<Option<SetupPlanLifecycle>, ClientError> {
        let Some(status) = native_terminal_status(self.vault, &stored.plan_id)? else {
            return Ok(None);
        };
        let lifecycle = match status {
            NativeTransactionStatus::Committed => SetupPlanLifecycle::Applied,
            NativeTransactionStatus::Restored => SetupPlanLifecycle::ApplyRestored,
            NativeTransactionStatus::Conflict => SetupPlanLifecycle::Conflict,
            NativeTransactionStatus::Pending | NativeTransactionStatus::Restoring => {
                return Err(conflict(
                    "Bridge apply native transaction recovery is incomplete",
                ));
            }
        };
        self.vault
            .finish_setup_plan(&stored.plan_id, lifecycle)
            .map_err(|_| conflict("Bridge apply lifecycle cannot be reconciled"))?;
        Ok(Some(lifecycle))
    }

    fn reconcile_rollback_terminal(
        &mut self,
        original: &crate::vault::SetupPlanRecord,
        inverse: &crate::vault::SetupPlanRecord,
    ) -> Result<Option<SetupPlanLifecycle>, ClientError> {
        let Some(status) = native_terminal_status(self.vault, &inverse.plan_id)? else {
            return Ok(None);
        };
        let (original_next, inverse_next) = match status {
            NativeTransactionStatus::Committed => {
                (SetupPlanLifecycle::RolledBack, SetupPlanLifecycle::Applied)
            }
            NativeTransactionStatus::Restored => (
                SetupPlanLifecycle::RollbackRestored,
                SetupPlanLifecycle::ApplyRestored,
            ),
            NativeTransactionStatus::Conflict => {
                (SetupPlanLifecycle::Conflict, SetupPlanLifecycle::Conflict)
            }
            NativeTransactionStatus::Pending | NativeTransactionStatus::Restoring => {
                return Err(conflict(
                    "Bridge rollback native transaction recovery is incomplete",
                ));
            }
        };
        self.vault
            .finish_setup_plan_rollback(
                &original.plan_id,
                &inverse.plan_id,
                original_next,
                inverse_next,
            )
            .map_err(|_| conflict("Bridge rollback lifecycle cannot be reconciled"))?;
        Ok(Some(original_next))
    }

    fn validated_inverse_plan(
        &self,
        original: &crate::native_transaction::OpenedPlan,
    ) -> Result<
        (
            crate::vault::SetupPlanRecord,
            crate::native_transaction::OpenedPlan,
        ),
        ClientError,
    > {
        let inverse_id = rollback_plan_id(&original.plan.setup.plan_id)?;
        let stored = self
            .vault
            .setup_plan(&inverse_id)
            .map_err(|_| invalid("Rollback inverse plan cannot be loaded"))?
            .ok_or_else(|| invalid("Rollback inverse plan does not exist"))?;
        let opened = open_plan(&stored.payload)
            .map_err(|_| invalid("Rollback inverse plan is malformed or unapproved"))?;
        let (expected, expected_rollback_states) = inverse_plan(original, stored.created_ms)?;
        if stored.schema_version != REVERSIBLE_PLAN_SCHEMA_VERSION
            || stored.schema_version != opened.schema_version
            || stored.approval_version != 2
            || stored.approval_hash != opened.plan.setup.batch_hash
            || stored.plan_id != opened.plan.setup.plan_id
            || stored.expires_ms != opened.plan.setup.expires_at
            || stored.lifecycle != SetupPlanLifecycle::Applying
            || opened.rollback_of_plan_id != Some(original.plan.setup.plan_id)
            || opened.plan != expected
            || opened.native_rollback_states != expected_rollback_states
        {
            return Err(invalid("Rollback inverse plan binding is invalid"));
        }
        Ok((stored, opened))
    }
}

fn validated_original_plan(
    stored: &crate::vault::SetupPlanRecord,
    plan_id: &PlanId,
) -> Result<crate::native_transaction::OpenedPlan, ClientError> {
    let opened = open_plan(&stored.payload)
        .map_err(|_| invalid("Persisted bridge plan is malformed or unapproved"))?;
    if stored.schema_version != opened.schema_version
        || stored.approval_version != 2
        || stored.approval_hash != opened.plan.setup.batch_hash
        || stored.plan_id != opened.plan.setup.plan_id
        || stored.expires_ms != opened.plan.setup.expires_at
        || &opened.plan.setup.plan_id != plan_id
        || opened.rollback_of_plan_id.is_some()
    {
        return Err(invalid("Persisted bridge plan binding is invalid"));
    }
    Ok(opened)
}

fn native_terminal_status(
    vault: &Vault,
    plan_id: &PlanId,
) -> Result<Option<NativeTransactionStatus>, ClientError> {
    let snapshot = vault
        .native_transaction(&native_transaction_id(plan_id))
        .map_err(|_| invalid("Bridge native transaction cannot be loaded"))?;
    match snapshot {
        Some(snapshot) if snapshot.plan_id == *plan_id => Ok(Some(snapshot.status)),
        Some(_) => Err(invalid("Bridge native transaction plan binding is invalid")),
        None => Ok(None),
    }
}

fn native_transaction_id(plan_id: &PlanId) -> String {
    format!("bridge-setup-{plan_id}")
}

fn apply_terminal_result(lifecycle: SetupPlanLifecycle) -> Result<(), ClientError> {
    match lifecycle {
        SetupPlanLifecycle::Applied => Ok(()),
        SetupPlanLifecycle::ApplyRestored => {
            Err(conflict("Bridge apply failed and restored its prior state"))
        }
        SetupPlanLifecycle::Conflict => Err(conflict("Bridge apply ended in conflict")),
        _ => Err(invalid("Bridge apply terminal lifecycle is invalid")),
    }
}

fn rollback_terminal_result(lifecycle: SetupPlanLifecycle) -> Result<(), ClientError> {
    match lifecycle {
        SetupPlanLifecycle::RolledBack => Ok(()),
        SetupPlanLifecycle::RollbackRestored => Err(conflict(
            "Bridge rollback failed and restored the applied state",
        )),
        SetupPlanLifecycle::Conflict => Err(conflict("Bridge rollback ended in conflict")),
        _ => Err(invalid("Bridge rollback terminal lifecycle is invalid")),
    }
}

fn inverse_plan(
    opened: &crate::native_transaction::OpenedPlan,
    now_ms: u64,
) -> Result<(NativeTransactionPlan, Vec<Vec<u8>>), ClientError> {
    let original = &opened.plan;
    if opened.native_rollback_states.len() != original.mutations.len() {
        return Err(invalid("Persisted bridge plan lacks exact rollback state"));
    }
    let mut inverse = original.clone();
    inverse.setup.plan_id = rollback_plan_id(&original.setup.plan_id)?;
    inverse.setup.expires_at = now_ms
        .checked_add(PREVIEW_TTL_MS)
        .ok_or_else(|| invalid("Rollback expiry is outside the supported range"))?;
    for change in &mut inverse.setup.semantic_changes {
        change.class = match change.class {
            ChangeClass::Create => ChangeClass::Remove,
            ChangeClass::Remove => ChangeClass::Create,
            ChangeClass::Enable => ChangeClass::Disable,
            ChangeClass::Disable => ChangeClass::Enable,
            ChangeClass::Update => ChangeClass::Update,
            ChangeClass::Preserve => ChangeClass::Preserve,
            ChangeClass::Conflict => {
                return Err(invalid("Rollback bridge plan contains a conflict change"));
            }
        };
    }
    for mutation in &mut inverse.cli_mutations {
        std::mem::swap(&mut mutation.expected, &mut mutation.intended);
        std::mem::swap(&mut mutation.forward, &mut mutation.rollback);
    }
    inverse.setup.cli_operations = inverse
        .cli_mutations
        .iter()
        .flat_map(|mutation| mutation.forward.clone())
        .collect();
    for ((inverse_mutation, original_mutation), rollback_state) in inverse
        .mutations
        .iter_mut()
        .zip(&original.mutations)
        .zip(&opened.native_rollback_states)
    {
        inverse_mutation.content.clone_from(rollback_state);
        inverse_mutation.expected = original_mutation.intended.clone();
        inverse_mutation.intended = original_mutation.expected.clone();
    }
    let inverse_rollback_states = original
        .mutations
        .iter()
        .map(|mutation| mutation.content.clone())
        .collect::<Vec<_>>();
    inverse.setup.batch_hash = Sha256Digest([0; 32]);
    inverse.setup.batch_hash = approval_hash_v2(&inverse)
        .map_err(|_| invalid("Rollback bridge plan approval cannot be derived"))?;
    Ok((inverse, inverse_rollback_states))
}

fn rollback_plan_id(original: &PlanId) -> Result<PlanId, ClientError> {
    let mut bytes: [u8; 32] = Sha256::digest(
        [
            b"context-relay/bridge-rollback/v1\0".as_slice(),
            original.as_bytes(),
        ]
        .concat(),
    )
    .into();
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    PlanId::from_str(&format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ))
    .map_err(|_| invalid("Rollback bridge plan identifier cannot be derived"))
}

impl<'a, H, L> BridgeInstallService<'a, H, L>
where
    H: BridgePreviewHarness,
    L: BridgeLocator,
{
    pub const PREVIEW_TTL_MS: u64 = PREVIEW_TTL_MS;

    pub fn new(
        vault: &'a mut Vault,
        harness: H,
        bridge_locator: L,
        origin_device: DeviceId,
        observed_hlc: HybridLogicalClock,
    ) -> Self {
        Self {
            vault,
            harness,
            bridge_locator,
            origin_device,
            observed_hlc,
        }
    }

    /// Builds and durably records a preview. It does not invoke any harness
    /// mutation or write its configuration.
    pub fn preview(
        &mut self,
        registered_project: Option<&RegisteredProject>,
        now_ms: u64,
    ) -> Result<SetupPlan, ClientError> {
        let located_bridge = self.bridge_locator.locate()?;
        let bridge = attest_bridge_executable(&located_bridge.path)?;
        if bridge != located_bridge {
            return Err(conflict(
                "Bridge locator returned an unattested executable identity",
            ));
        }
        let harness = self.harness.bridge_harness();
        let report = self.harness.probe(&ProbeContext {
            harness,
            requested_profile: self.harness.bridge_requested_profile(),
        })?;
        if report.capability != CapabilityLevel::Full {
            return Err(unsupported("The selected harness is import-only"));
        }
        let executable_path = report
            .executable
            .clone()
            .ok_or_else(|| unsupported("The selected harness executable is unavailable"))?;
        let executable_hash = report
            .executable_sha256
            .ok_or_else(|| unsupported("The selected harness cannot be attested"))?;
        let harness_version = report
            .harness_version
            .clone()
            .ok_or_else(|| unsupported("The selected harness version is unavailable"))?;

        let mut import_scopes = vec![NativeScope::Global];
        if let Some(project) = registered_project {
            project
                .root
                .validate()
                .map_err(|_| invalid("The registered project path is invalid"))?;
            import_scopes.push(NativeScope::Project {
                project_id: project.project_id,
                root: project.root.clone(),
            });
        }
        let imported = self.harness.import(&ImportRequest {
            scopes: import_scopes,
            include_disabled: true,
        })?;
        let intended =
            bridge_component_for_attested(harness, &bridge, self.origin_device, self.observed_hlc)?;
        let project_scope = match (
            self.harness.bridge_project_id(),
            self.harness.bridge_project_root(),
        ) {
            (Some(project_id), Some(root)) => {
                root.validate()
                    .map_err(|_| invalid("Harness project root is invalid"))?;
                if let Some(registered) = registered_project
                    && (registered.project_id != project_id
                        || registered.root.platform != root.platform
                        || registered.root.bytes != root.bytes)
                {
                    return Err(conflict(
                        "Harness project binding differs from the registered project",
                    ));
                }
                Some(NativeScope::Project { project_id, root })
            }
            (Some(project_id), None) => {
                let registered = registered_project
                    .ok_or_else(|| invalid("Harness project binding is incomplete"))?;
                if registered.project_id != project_id {
                    return Err(conflict(
                        "Harness project binding differs from the registered project",
                    ));
                }
                Some(NativeScope::Project {
                    project_id,
                    root: registered.root.clone(),
                })
            }
            (None, None) => None,
            _ => return Err(invalid("Harness project binding is incomplete")),
        };
        let mut desired_components = vec![intended.clone()];
        let mut desired_scopes = vec![NativeScope::Global];
        if let Some(NativeScope::Project { project_id, .. }) = &project_scope {
            desired_components.push(primary_memory_instruction_component(
                harness,
                *project_id,
                self.origin_device,
                self.observed_hlc,
            )?);
            desired_components.extend(managed_memory_hooks(harness, &wire_path(&bridge.path))?);
            desired_scopes.push(
                project_scope
                    .clone()
                    .ok_or_else(|| invalid("Harness project binding disappeared"))?,
            );
        }
        let desired = DesiredState {
            components: desired_components,
            scopes: desired_scopes,
        };
        // CLI harnesses capture their authoritative prior declaration here.
        // Hermes instead classifies its imported native projection first.
        let captured_mutations = match harness {
            HarnessId::ClaudeCode | HarnessId::Codex => {
                Some(self.harness.bridge_mutations(&desired, &intended)?)
            }
            HarnessId::Hermes => None,
        };
        let change = bridge_change(
            harness,
            report.active_profile.as_deref(),
            &imported.components,
            &intended,
            captured_mutations
                .as_ref()
                .and_then(|mutations| mutations.cli.as_ref()),
        )?;
        let semantic_diff = SemanticDiff {
            changes: change.into_iter().collect(),
            conflicts: vec![],
        };

        // These calls are intentionally kept in preview even though the exact
        // CLI mutation below is the authority for rollback argv.
        let _rendered = self.harness.render(&desired)?;
        let mut classified = self.harness.classify(&semantic_diff)?;
        let adapter_operations = self.harness.plan_cli_ops(&classified)?.0;
        let mut mutations = if classified.0.is_empty() {
            BridgeMutationPlan {
                cli: None,
                native: vec![],
            }
        } else {
            match captured_mutations {
                Some(mutations) => mutations,
                None => self.harness.bridge_mutations(&desired, &intended)?,
            }
        };
        let cli_mutation = mutations.cli;
        if adapter_operations
            != cli_mutation
                .as_ref()
                .map(|mutation| mutation.forward.clone())
                .unwrap_or_default()
        {
            return Err(conflict(
                "Harness CLI preview differs from its approved bridge declaration",
            ));
        }
        if harness == HarnessId::Hermes && cli_mutation.is_some() {
            return Err(conflict(
                "Hermes bridge previews cannot contain CLI mutations",
            ));
        }
        let memory = self.harness.primary_memory_mutations(&desired)?;
        mutations.native.extend(memory.native);
        classified.0.extend(memory.semantic_changes);

        let expires_at = now_ms
            .checked_add(PREVIEW_TTL_MS)
            .ok_or_else(|| invalid("Preview expiry is outside the supported range"))?;
        let plan_id = preview_plan_id(harness, &bridge.digest, now_ms)?;
        let mut setup = SetupPlan {
            plan_id,
            harness,
            adapter_version: self.harness.bridge_adapter_version(),
            executable_path,
            executable_hash,
            harness_version,
            target_scopes: desired.scopes.clone(),
            expected_native_digests: vec![ExpectedNativeDigest {
                target: wire_path(&bridge.path),
                expected_digest: Some(bridge.digest),
            }],
            approval_class: approval_class(&classified.0),
            semantic_changes: classified.0,
            cli_operations: cli_mutation
                .as_ref()
                .map(|mutation| mutation.forward.clone())
                .unwrap_or_default(),
            package_artifacts: vec![],
            permission_delta: context_relay_protocol::PermissionDelta {
                added: vec![],
                removed: vec![],
            },
            network_delta: context_relay_protocol::NetworkDelta {
                added: vec![],
                removed: vec![],
            },
            scanner_report_hash: digest(b"bridge-preview-scanner-v1"),
            rulesync_version: "bridge-preview-v1".to_owned(),
            rulesync_hash: digest(b"bridge-preview-rulesync-v1"),
            expires_at,
            batch_hash: Sha256Digest([0; 32]),
        };
        let mut plan = NativeTransactionPlan {
            setup: setup.clone(),
            approval_version: 2,
            helper_policy_version: 1,
            manifest_schema_version: 1,
            manifest_digest: digest(b"bridge-preview-manifest-v1"),
            helper_hash: digest(b"bridge-preview-helper-v1"),
            sidecars: vec![SidecarBinding {
                id: SidecarId::RuleSync,
                target: RuntimeTarget::MacosArm64,
                version: "bridge-preview-v1".to_owned(),
                closure_hash: digest(b"bridge-preview-sidecar-closure-v1"),
                source_bundle_hash: digest(b"bridge-preview-sidecar-source-v1"),
                build_toolchain_hash: digest(b"bridge-preview-sidecar-toolchain-v1"),
                command_template_digest: digest(b"bridge-preview-sidecar-command-v1"),
                command: SidecarCommand::RuleSyncGenerate {
                    target: match harness {
                        HarnessId::ClaudeCode => RuleSyncTarget::ClaudeCode,
                        HarnessId::Codex => RuleSyncTarget::CodexCli,
                        HarnessId::Hermes => RuleSyncTarget::ClaudeCode,
                    },
                    features: RuleSyncFeatures::new(&[RuleSyncFeature::Mcp])
                        .map_err(|_| invalid("Bridge preview sidecar is invalid"))?,
                },
            }],
            structural_allowlist_hash: digest(b"bridge-preview-allowlist-v1"),
            staged_inputs: vec![],
            expected_semantic_output_hash: digest(b"bridge-preview-output-v1"),
            scanner_result_hash: digest(b"bridge-preview-scanner-v1"),
            mutations: mutations.native,
            cli_mutations: cli_mutation.into_iter().collect(),
            native_memory_registrations: memory.registrations,
            ownership_changes: vec![],
        };
        let approval_hash =
            approval_hash_v2(&plan).map_err(|_| invalid("Bridge preview plan is invalid"))?;
        setup.batch_hash = approval_hash;
        plan.setup = setup.clone();
        let native_rollback_states =
            crate::native_transaction::planner::capture_native_rollback_states(&plan.mutations)
                .map_err(|_| invalid("Bridge preview rollback state cannot be sealed"))?;
        let (schema_version, sealed) = if plan.mutations.is_empty() {
            (
                crate::native_transaction::SEALED_PLAN_SCHEMA_VERSION,
                seal_plan(&plan, approval_hash),
            )
        } else {
            (
                REVERSIBLE_PLAN_SCHEMA_VERSION,
                seal_reversible_plan(&plan, approval_hash, &native_rollback_states, None),
            )
        };
        let sealed = sealed.map_err(|_| invalid("Bridge preview plan cannot be sealed"))?;
        self.vault
            .put_setup_plan(SetupPlanWrite {
                plan_id: &setup.plan_id,
                schema_version,
                approval_version: 2,
                approval_hash: &approval_hash,
                payload: &sealed,
                created_ms: now_ms,
                expires_ms: expires_at,
            })
            .map_err(|_| invalid("Bridge preview plan cannot be persisted"))?;
        Ok(setup)
    }
}

fn bridge_change(
    harness: HarnessId,
    profile: Option<&str>,
    imported: &[ComponentRecord],
    intended: &ComponentRecord,
    cli_mutation: Option<&ApprovedCliMutation>,
) -> Result<Option<ClassifiedChange>, ClientError> {
    let class = match harness {
        HarnessId::ClaudeCode | HarnessId::Codex => bridge_cli_change(cli_mutation, intended)?,
        HarnessId::Hermes => bridge_hermes_change(profile, imported, intended)?,
    };
    let target = match harness {
        HarnessId::ClaudeCode => format!("claude-mcp:global:{BRIDGE_SERVER_NAME}"),
        HarnessId::Codex => format!("codex-mcp|global|{BRIDGE_SERVER_NAME}"),
        HarnessId::Hermes => format!(
            "hermes-config|{}|mcp_servers.{BRIDGE_SERVER_NAME}",
            profile.ok_or_else(|| invalid("Hermes profile is unavailable"))?
        ),
    };
    Ok(class.map(|class| ClassifiedChange {
        class,
        target,
        summary: intended.body_markdown.clone(),
    }))
}

fn bridge_cli_change(
    cli_mutation: Option<&ApprovedCliMutation>,
    intended: &ComponentRecord,
) -> Result<Option<ChangeClass>, ClientError> {
    let mutation = cli_mutation
        .ok_or_else(|| invalid("CLI bridge preview is missing its authoritative declaration"))?;
    Ok(match &mutation.expected {
        None => Some(ChangeClass::Create),
        Some(previous) if previous.canonical_body == intended.body_markdown => None,
        Some(_) => Some(ChangeClass::Update),
    })
}

fn bridge_hermes_change(
    profile: Option<&str>,
    imported: &[ComponentRecord],
    intended: &ComponentRecord,
) -> Result<Option<ChangeClass>, ClientError> {
    let same_name = imported.iter().find(|component| {
        component.kind == ComponentKind::McpServer
            && component.scope == ScopeRef::Global
            && component.name == BRIDGE_SERVER_NAME
    });
    match same_name {
        None => Ok(Some(ChangeClass::Create)),
        Some(component) if !is_imported_hermes_bridge(profile, component) => Err(conflict(
            "An unmanaged context-relay MCP declaration already exists",
        )),
        Some(component) if component.body_markdown == intended.body_markdown => Ok(None),
        Some(component) if is_disabled_hermes_intended_bridge(component, intended) => {
            Ok(Some(ChangeClass::Enable))
        }
        Some(_) => Ok(Some(ChangeClass::Update)),
    }
}

fn is_imported_hermes_bridge(profile: Option<&str>, component: &ComponentRecord) -> bool {
    let Some(profile) = profile else {
        return false;
    };
    component.scope == ScopeRef::Global
        && component.kind == ComponentKind::McpServer
        && component.name == BRIDGE_SERVER_NAME
        && component.provenance.harness == Some(HarnessId::Hermes)
        && component.provenance.source.is_none()
        && component.metadata.len() == 4
        && metadata_value(component, "enabled")
            == Some(if component.archived { "false" } else { "true" })
        && metadata_value(component, "nativeFormat") == Some("json")
        && metadata_value(component, "profile") == Some(profile)
        && metadata_value(component, "structuralLocation")
            == Some("config:mcp_servers.context-relay")
        && is_canonical_bridge_body(HarnessId::Hermes, &component.body_markdown, true)
}

fn is_disabled_hermes_intended_bridge(
    component: &ComponentRecord,
    intended: &ComponentRecord,
) -> bool {
    if !component.archived {
        return false;
    }
    let Ok(mut body) = serde_json::from_str::<serde_json::Value>(&component.body_markdown) else {
        return false;
    };
    let Some(object) = body.as_object_mut() else {
        return false;
    };
    if object.remove("enabled") != Some(serde_json::Value::Bool(false)) {
        return false;
    }
    serde_json::to_string(&body).is_ok_and(|body| body == intended.body_markdown)
}

fn metadata_value<'a>(component: &'a ComponentRecord, key: &str) -> Option<&'a str> {
    component
        .metadata
        .iter()
        .find_map(|(candidate, value)| (candidate == key).then_some(value.as_str()))
}

fn approval_class(changes: &[ClassifiedChange]) -> ApprovalClass {
    if changes.iter().any(|change| {
        matches!(
            change.class,
            ChangeClass::Create
                | ChangeClass::Update
                | ChangeClass::Enable
                | ChangeClass::Disable
                | ChangeClass::Remove
        )
    }) {
        ApprovalClass::Active
    } else {
        ApprovalClass::Passive
    }
}

fn preview_plan_id(
    harness: HarnessId,
    bridge_digest: &Sha256Digest,
    now_ms: u64,
) -> Result<PlanId, ClientError> {
    let mut bytes: [u8; 32] = Sha256::digest(
        [
            harness_cli_name(harness).as_bytes(),
            &bridge_digest.0,
            &now_ms.to_le_bytes(),
        ]
        .concat(),
    )
    .into();
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    PlanId::from_str(&format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ))
    .map_err(|_| invalid("Bridge preview identifier cannot be derived"))
}

fn wire_path(path: &std::path::Path) -> WireNativeValue {
    let display = path.to_string_lossy().into_owned();
    #[cfg(windows)]
    let bytes = {
        use std::os::windows::ffi::OsStrExt as _;
        path.as_os_str()
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect()
    };
    #[cfg(not(windows))]
    let bytes = {
        use std::os::unix::ffi::OsStrExt as _;
        path.as_os_str().as_bytes().to_vec()
    };
    WireNativeValue {
        platform: if cfg!(windows) {
            NativePlatform::Windows
        } else {
            NativePlatform::Macos
        },
        bytes,
        display: Some(display),
    }
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest(Sha256::digest(bytes).into())
}

fn digest_text(digest: Sha256Digest) -> String {
    digest
        .0
        .iter()
        .fold(String::with_capacity(64), |mut text, byte| {
            write!(text, "{byte:02x}").expect("writing to a String cannot fail");
            text
        })
}

fn harness_cli_name(harness: HarnessId) -> &'static str {
    match harness {
        HarnessId::ClaudeCode => "claude-code",
        HarnessId::Codex => "codex",
        HarnessId::Hermes => "hermes",
    }
}

fn invalid(message: &'static str) -> ClientError {
    ClientError {
        code: ErrorCode::InvalidRequest,
        message: message.to_owned(),
        field_path: None,
        retryable: false,
    }
}

fn conflict(message: &'static str) -> ClientError {
    ClientError {
        code: ErrorCode::Conflict,
        message: message.to_owned(),
        field_path: None,
        retryable: false,
    }
}

fn conflict_owned(message: &str) -> ClientError {
    ClientError {
        code: ErrorCode::Conflict,
        message: message.to_owned(),
        field_path: None,
        retryable: false,
    }
}

fn unsupported(message: &'static str) -> ClientError {
    ClientError {
        code: ErrorCode::HarnessUnsupported,
        message: message.to_owned(),
        field_path: None,
        retryable: false,
    }
}
