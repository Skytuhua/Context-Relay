use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(not(windows))]
use context_relay_core::vault::{MacGenerationState, MacGenerationSubstate};
use context_relay_core::{
    claude_code::ClaudeCodeAdapter,
    codex::CodexAdapter,
    hermes::HermesAdapter,
    mcp::install::{BridgeExecutable, attest_bridge_executable},
    native_transaction::{
        ApprovedInput, SidecarBinding,
        engine::{BoundaryError, NoFault, RestrictedExecutor, RestrictedRun},
        filesystem::OsNativeTransactionFileSystem,
    },
    setup::{
        BridgeExecutionError, BridgeInstallService, BridgeLocator, BridgePlanExecutor,
        NativeEngineBridgePlanExecutor, NoBridgeCliExecutor, RegisteredProject,
    },
    vault::{BeforeImagePolicy, NativeSandboxIdentity, Vault},
};
use context_relay_native_runner::{
    RuleSyncFeature, RuleSyncFeatures, RuleSyncTarget, RuntimeTarget, SidecarCommand, SidecarId,
};
use context_relay_protocol::{
    ClientError, DeviceId, ErrorCode, HarnessAdapter as _, HarnessId, HarnessParams,
    HybridLogicalClock, NativePlatform, NativeScope, PlanId, PlanParams, ProbeContext, ProbeReport,
    ProjectId, SetupPlan, Sha256Digest, WireNativeValue,
};

#[cfg(not(windows))]
pub(crate) const NON_LAUNCHING_GENERATION_ID: &str = "00000000000000000000000000000000";
#[cfg(windows)]
pub(crate) const NON_LAUNCHING_WINDOWS_MONIKER: &str =
    "context-relay.native.00000000000000000000000000000000";
#[cfg(windows)]
pub(crate) const NON_LAUNCHING_WINDOWS_SID: &str = "S-1-15-2-1-2-3-4-5-6-7";

/// Ordered daemon boundary for harness setup. Implementations receive only
/// protocol DTOs; callers cannot inject paths, digests, commands, or plan
/// bodies into apply and rollback.
pub trait BridgeInstallEngine: Send + Sync {
    fn prepare(
        &self,
        _vault: &Vault,
        _vault_path: &Path,
        _device_id: DeviceId,
        _params: HarnessParams,
    ) -> Result<crate::harness_preparation::PreparationTask, ClientError> {
        Err(unsupported(
            "Background preparation is unavailable for this harness",
        ))
    }
    fn probe(
        &self,
        _vault: &Vault,
        _device_id: DeviceId,
        _params: HarnessParams,
    ) -> Result<ProbeReport, ClientError> {
        Err(unsupported("Harness discovery is unavailable"))
    }

    fn reconcile_after_native_recovery(
        &self,
        vault: &mut Vault,
        vault_path: &Path,
        device_id: DeviceId,
    ) -> Result<(), ClientError>;

    fn preview(
        &self,
        vault: &mut Vault,
        vault_path: &Path,
        device_id: DeviceId,
        params: HarnessParams,
    ) -> Result<SetupPlan, ClientError>;

    fn apply(
        &self,
        vault: &mut Vault,
        vault_path: &Path,
        device_id: DeviceId,
        params: PlanParams,
    ) -> Result<(), ClientError>;

    fn rollback(
        &self,
        vault: &mut Vault,
        vault_path: &Path,
        device_id: DeviceId,
        params: PlanParams,
    ) -> Result<(), ClientError>;
}

#[derive(Clone, Debug)]
pub struct AdjacentBridgeLocator {
    daemon_executable: PathBuf,
}

impl AdjacentBridgeLocator {
    pub fn production() -> Result<Self, ClientError> {
        std::env::current_exe()
            .map(Self::beside)
            .map_err(|_| internal("The installed bridge location is unavailable"))
    }

    pub fn beside(daemon_executable: impl Into<PathBuf>) -> Self {
        Self {
            daemon_executable: daemon_executable.into(),
        }
    }

    pub fn bridge_path(&self) -> Result<PathBuf, ClientError> {
        let parent = self
            .daemon_executable
            .parent()
            .ok_or_else(|| internal("The installed bridge location is unavailable"))?;
        Ok(parent.join(if cfg!(windows) {
            "context-relay-context-mcp.exe"
        } else {
            "context-relay-context-mcp"
        }))
    }
}

impl BridgeLocator for AdjacentBridgeLocator {
    fn locate(&self) -> Result<BridgeExecutable, ClientError> {
        attest_bridge_executable(&self.bridge_path()?)
    }
}

#[derive(Clone, Debug)]
pub struct ProductionBridgeInstallEngine {
    bridge: AdjacentBridgeLocator,
}

impl ProductionBridgeInstallEngine {
    pub fn production() -> Result<Self, ClientError> {
        Ok(Self {
            bridge: AdjacentBridgeLocator::production()?,
        })
    }

    pub fn with_daemon_executable(daemon_executable: impl Into<PathBuf>) -> Self {
        Self {
            bridge: AdjacentBridgeLocator::beside(daemon_executable),
        }
    }

    fn probe_codex(
        &self,
        adapter: &CodexAdapter,
        context: &ProbeContext,
    ) -> Result<ProbeReport, ClientError> {
        let mut report = adapter.probe(context)?;
        // Reuse this discovery's attested adapter. This reads saved user
        // settings only; never start app-server to inspect a live profile.
        report.codex_saved_hook_approval = self.bridge.locate().ok().and_then(|bridge| {
            adapter
                .saved_memory_hook_approval(&wire_native_path(&bridge.path))
                .ok()
        });
        Ok(report)
    }
}

impl BridgeInstallEngine for ProductionBridgeInstallEngine {
    fn prepare(
        &self,
        vault: &Vault,
        vault_path: &Path,
        device_id: DeviceId,
        params: HarnessParams,
    ) -> Result<crate::harness_preparation::PreparationTask, ClientError> {
        #[cfg(not(windows))]
        {
            let _ = (vault, vault_path, device_id, params);
            Err(unsupported(
                "Background preparation is unavailable on this platform",
            ))
        }
        #[cfg(windows)]
        {
            if params.harness != HarnessId::Hermes {
                return Err(unsupported(
                    "This harness does not need runtime preparation",
                ));
            }
            let binding = project_binding(vault, params.project_id)?;
            let store = canonical_lock_root(vault_path)?;
            let profile = params
                .hermes_profile
                .ok_or_else(|| invalid("Choose a Hermes profile"))?;
            let observed_hlc = HybridLogicalClock::new(now_ms()?, 0, device_id);
            Ok(Box::new(move |cancelled, report| {
                if cancelled.load(std::sync::atomic::Ordering::Acquire) {
                    return Err(crate::canceled_error());
                }
                let adapter = HermesAdapter::discover_for_preparation(
                    &binding.root,
                    &binding.root,
                    &profile,
                    binding.project_id,
                    device_id,
                    observed_hlc,
                )?;
                adapter.prepare_owned_runtime(&store, cancelled, report)
            }))
        }
    }
    fn probe(
        &self,
        vault: &Vault,
        device_id: DeviceId,
        params: HarnessParams,
    ) -> Result<ProbeReport, ClientError> {
        let binding = project_binding(vault, params.project_id)?;
        let observed_hlc = HybridLogicalClock::new(now_ms()?, 0, device_id);
        let context = ProbeContext {
            harness: params.harness,
            requested_profile: params.hermes_profile.clone(),
        };
        match params.harness {
            HarnessId::ClaudeCode => ClaudeCodeAdapter::discover(
                &binding.root,
                binding.project_id,
                device_id,
                observed_hlc,
            )
            .and_then(|adapter| adapter.probe(&context)),
            HarnessId::Codex => CodexAdapter::discover(
                &binding.root,
                &binding.root,
                binding.project_id,
                device_id,
                observed_hlc,
            )
            .and_then(|adapter| self.probe_codex(&adapter, &context)),
            HarnessId::Hermes => HermesAdapter::discover(
                &binding.root,
                &binding.root,
                params
                    .hermes_profile
                    .as_deref()
                    .ok_or_else(|| invalid("Hermes discovery requires an explicit profile"))?,
                binding.project_id,
                device_id,
                observed_hlc,
            )
            .and_then(|adapter| adapter.probe(&context)),
        }
    }

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
        let now_ms = now_ms()?;
        let HarnessParams {
            harness,
            project_id,
            hermes_profile,
        } = params;
        let binding = project_binding(vault, project_id)?;
        let observed_hlc = HybridLogicalClock::new(now_ms, 0, device_id);
        match harness {
            HarnessId::ClaudeCode => BridgeInstallService::new(
                vault,
                ClaudeCodeAdapter::discover(
                    &binding.root,
                    binding.project_id,
                    device_id,
                    observed_hlc,
                )?,
                self.bridge.clone(),
                device_id,
                observed_hlc,
            )
            .preview(binding.registered.as_ref(), now_ms),
            HarnessId::Codex => BridgeInstallService::new(
                vault,
                CodexAdapter::discover(
                    &binding.root,
                    &binding.root,
                    binding.project_id,
                    device_id,
                    observed_hlc,
                )?,
                self.bridge.clone(),
                device_id,
                observed_hlc,
            )
            .preview(binding.registered.as_ref(), now_ms),
            HarnessId::Hermes => {
                let profile = hermes_profile
                    .as_deref()
                    .ok_or_else(|| invalid("Hermes setup requires an explicit profile"))?;
                BridgeInstallService::new(
                    vault,
                    HermesAdapter::discover(
                        &binding.root,
                        &binding.root,
                        profile,
                        binding.project_id,
                        device_id,
                        observed_hlc,
                    )?,
                    self.bridge.clone(),
                    device_id,
                    observed_hlc,
                )
                .preview(binding.registered.as_ref(), now_ms)
            }
        }
    }

    fn apply(
        &self,
        vault: &mut Vault,
        vault_path: &Path,
        device_id: DeviceId,
        params: PlanParams,
    ) -> Result<(), ClientError> {
        self.execute(vault, vault_path, device_id, params.plan_id, false)
    }

    fn rollback(
        &self,
        vault: &mut Vault,
        vault_path: &Path,
        device_id: DeviceId,
        params: PlanParams,
    ) -> Result<(), ClientError> {
        self.execute(vault, vault_path, device_id, params.plan_id, true)
    }
}

impl ProductionBridgeInstallEngine {
    fn execute(
        &self,
        vault: &mut Vault,
        vault_path: &Path,
        device_id: DeviceId,
        plan_id: PlanId,
        rollback: bool,
    ) -> Result<(), ClientError> {
        let now_ms = now_ms()?;
        let mut executor = ProductionBridgePlanExecutor {
            vault_path,
            device_id,
        };
        execute_persisted(vault, &plan_id, now_ms, rollback, &mut executor)
    }
}

struct ProductionBridgePlanExecutor<'a> {
    vault_path: &'a Path,
    device_id: DeviceId,
}

impl BridgePlanExecutor for ProductionBridgePlanExecutor<'_> {
    fn verify_watch_only_registration(
        &mut self,
        plan: &context_relay_core::native_transaction::NativeTransactionPlan,
        _now_ms: u64,
    ) -> Result<(), BridgeExecutionError> {
        self.verify_registration_inner(plan)
            .map_err(|error| BridgeExecutionError::restored(error.message))
    }

    fn execute(
        &mut self,
        vault: &mut Vault,
        plan: &context_relay_core::native_transaction::NativeTransactionPlan,
        sealed_plan: &[u8],
        created_ms: u64,
        now_ms: u64,
    ) -> Result<(), BridgeExecutionError> {
        match self.execute_inner(vault, plan, sealed_plan, created_ms, now_ms) {
            Ok(()) => Ok(()),
            Err(ProductionExecutionError::Compose(error)) => {
                Err(BridgeExecutionError::conflict(error.message))
            }
            Err(ProductionExecutionError::Execute(error)) => Err(error),
        }
    }
}

enum ProductionExecutionError {
    Compose(ClientError),
    Execute(BridgeExecutionError),
}

impl From<ClientError> for ProductionExecutionError {
    fn from(error: ClientError) -> Self {
        Self::Compose(error)
    }
}

impl ProductionBridgePlanExecutor<'_> {
    fn verify_registration_inner(
        &self,
        plan: &context_relay_core::native_transaction::NativeTransactionPlan,
    ) -> Result<(), ClientError> {
        if plan.installed_runtime.is_some() {
            return Err(invalid(
                "Retained Hermes runtime registration is not connected yet",
            ));
        }
        let (root, project_id) = sealed_project_binding(plan)?;
        if plan.setup.target_scopes.iter().any(|scope| match scope {
            NativeScope::Global => false,
            NativeScope::Project { root: approved, .. } => {
                !decode_wire_path(approved).is_ok_and(|approved| approved == root)
            }
        }) {
            return Err(invalid("The approved registration project root changed"));
        }
        let observed_hlc = HybridLogicalClock::new(now_ms()?, 0, self.device_id);
        // This branch never constructs a restricted executor, native filesystem,
        // journal, CLI writer, gateway lease, or bridge executable.
        match plan.setup.harness {
            HarnessId::ClaudeCode => {
                let adapter = ClaudeCodeAdapter::discover_for_registration(
                    &root,
                    project_id,
                    self.device_id,
                    observed_hlc,
                    &plan.setup,
                )?;
                context_relay_core::setup::verify_watch_only_registration(&adapter, plan, now_ms()?)
            }
            HarnessId::Codex => {
                let adapter = CodexAdapter::discover_for_registration(
                    &root,
                    &root,
                    project_id,
                    self.device_id,
                    observed_hlc,
                    &plan.setup,
                )?;
                context_relay_core::setup::verify_watch_only_registration(&adapter, plan, now_ms()?)
            }
            HarnessId::Hermes => {
                let profile = plan
                    .setup
                    .harness_profile
                    .as_deref()
                    .ok_or_else(|| invalid("Persisted Hermes setup profile is unavailable"))?;
                let adapter = HermesAdapter::discover_for_registration(
                    &root,
                    &root,
                    profile,
                    project_id,
                    self.device_id,
                    observed_hlc,
                    &plan.setup,
                )?;
                context_relay_core::setup::verify_watch_only_registration(&adapter, plan, now_ms()?)
            }
        }
    }

    fn execute_inner(
        &mut self,
        vault: &mut Vault,
        plan: &context_relay_core::native_transaction::NativeTransactionPlan,
        sealed_plan: &[u8],
        created_ms: u64,
        now_ms: u64,
    ) -> Result<(), ProductionExecutionError> {
        if plan.installed_runtime.is_some() {
            return Err(invalid("Retained Hermes runtime execution is not connected yet").into());
        }
        let (root, project_id) = sealed_project_binding(plan)?;
        let observed_hlc = HybridLogicalClock::new(now_ms, 0, self.device_id);
        let lock_root = canonical_lock_root(self.vault_path)?;
        let identity = nonlaunching_sandbox_identity();
        let mut restricted = BridgeRestrictedExecutor::new(
            plan.setup.harness,
            plan.staged_inputs.clone(),
            plan.sidecars.clone(),
            plan.expected_semantic_output_hash,
            plan.scanner_result_hash,
        )?;
        let mut filesystem = OsNativeTransactionFileSystem::new(*plan.setup.plan_id.as_bytes());
        let mut hook = NoFault;

        let result = match plan.setup.harness {
            HarnessId::ClaudeCode => {
                let mut adapter =
                    ClaudeCodeAdapter::discover(&root, project_id, self.device_id, observed_hlc)?;
                let cli_adapter = adapter.clone();
                let mut cli = cli_adapter.cli_executor();
                let mut executor = NativeEngineBridgePlanExecutor::new(
                    &mut adapter,
                    &mut restricted,
                    &mut filesystem,
                    &mut hook,
                    &mut cli,
                    lock_root,
                    identity,
                    BeforeImagePolicy::default(),
                    observed_hlc,
                );
                executor.execute(vault, plan, sealed_plan, created_ms, now_ms)
            }
            HarnessId::Codex => {
                let mut adapter =
                    CodexAdapter::discover(&root, &root, project_id, self.device_id, observed_hlc)?;
                let cli_adapter = adapter.clone();
                let mut cli = cli_adapter.cli_executor();
                let mut executor = NativeEngineBridgePlanExecutor::new(
                    &mut adapter,
                    &mut restricted,
                    &mut filesystem,
                    &mut hook,
                    &mut cli,
                    lock_root,
                    identity,
                    BeforeImagePolicy::default(),
                    observed_hlc,
                );
                executor.execute(vault, plan, sealed_plan, created_ms, now_ms)
            }
            HarnessId::Hermes => {
                let profile = plan
                    .setup
                    .harness_profile
                    .as_deref()
                    .ok_or_else(|| invalid("Persisted Hermes setup profile is unavailable"))?;
                let mut adapter = HermesAdapter::discover(
                    &root,
                    &root,
                    profile,
                    project_id,
                    self.device_id,
                    observed_hlc,
                )?;
                let mut cli = NoBridgeCliExecutor;
                let mut executor = NativeEngineBridgePlanExecutor::new(
                    &mut adapter,
                    &mut restricted,
                    &mut filesystem,
                    &mut hook,
                    &mut cli,
                    lock_root,
                    identity,
                    BeforeImagePolicy::default(),
                    observed_hlc,
                );
                executor.execute(vault, plan, sealed_plan, created_ms, now_ms)
            }
        };
        result.map_err(ProductionExecutionError::Execute)
    }
}

pub(crate) fn sealed_project_binding(
    plan: &context_relay_core::native_transaction::NativeTransactionPlan,
) -> Result<(PathBuf, ProjectId), ClientError> {
    let mut projects = plan.setup.target_scopes.iter().filter_map(|scope| {
        if let NativeScope::Project { project_id, root } = scope {
            Some((*project_id, root))
        } else {
            None
        }
    });
    let Some((project_id, root)) = projects.next() else {
        return Ok((stable_process_root()?, global_project_id()?));
    };
    if projects.next().is_some() {
        return Err(invalid("Persisted bridge plan has ambiguous project roots"));
    }
    let decoded = decode_wire_path(root)?;
    let canonical = fs::canonicalize(decoded)
        .map_err(|_| invalid("Persisted bridge project root is unavailable"))?;
    Ok((canonical, project_id))
}

fn execute_persisted(
    vault: &mut Vault,
    plan_id: &PlanId,
    now_ms: u64,
    rollback: bool,
    executor: &mut impl context_relay_core::setup::BridgePlanExecutor,
) -> Result<(), ClientError> {
    if rollback {
        BridgeInstallService::persisted(vault).rollback(plan_id, now_ms, executor)
    } else {
        BridgeInstallService::persisted(vault).apply(plan_id, now_ms, executor)
    }
}

struct ProjectBinding {
    project_id: ProjectId,
    root: PathBuf,
    registered: Option<RegisteredProject>,
}

fn project_binding(
    vault: &Vault,
    requested: Option<ProjectId>,
) -> Result<ProjectBinding, ClientError> {
    match requested {
        Some(project_id) => {
            let wire = vault
                .path(&project_id.to_string())
                .map_err(|_| invalid("Registered project path cannot be loaded"))?
                .ok_or_else(|| not_found("Registered project path does not exist"))?;
            let root = decode_wire_path(&wire)?;
            let root = fs::canonicalize(&root)
                .map_err(|_| not_found("Registered project path does not exist"))?;
            Ok(ProjectBinding {
                project_id,
                root,
                registered: Some(RegisteredProject {
                    project_id,
                    root: wire,
                }),
            })
        }
        None => Ok(ProjectBinding {
            project_id: global_project_id()?,
            root: stable_process_root()?,
            registered: None,
        }),
    }
}

fn stable_process_root() -> Result<PathBuf, ClientError> {
    let root = std::env::current_dir()
        .map_err(|_| not_found("The harness working directory is unavailable"))?;
    fs::canonicalize(root).map_err(|_| not_found("The harness working directory is unavailable"))
}

pub(crate) fn global_project_id() -> Result<ProjectId, ClientError> {
    ProjectId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c07398f")
        .map_err(|_| internal("The global setup project binding is invalid"))
}

fn canonical_lock_root(vault_path: &Path) -> Result<PathBuf, ClientError> {
    let parent = vault_path
        .parent()
        .ok_or_else(|| internal("The native transaction root is unavailable"))?;
    fs::canonicalize(parent).map_err(|_| internal("The native transaction root is unavailable"))
}

fn now_ms() -> Result<u64, ClientError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| internal("The system clock is unavailable"))?
        .as_millis();
    u64::try_from(millis).map_err(|_| internal("The system clock is unavailable"))
}

/// Journal identity for bridge setup transactions, which validate in-process
/// and never launch a native sandbox. Recovery recognizes only this exact
/// reserved identity and therefore never mistakes a real runner generation for
/// a no-op cleanup.
pub(crate) fn nonlaunching_sandbox_identity() -> NativeSandboxIdentity {
    #[cfg(windows)]
    {
        NativeSandboxIdentity::Windows {
            moniker: NON_LAUNCHING_WINDOWS_MONIKER.to_owned(),
            sid: NON_LAUNCHING_WINDOWS_SID.as_bytes().to_vec(),
        }
    }
    #[cfg(not(windows))]
    {
        let generation_id = NON_LAUNCHING_GENERATION_ID.to_owned();
        let bundle_id = format!("com.contextrelay.native-runner.{generation_id}");
        let mut container = b"context-relay/macos-container/v1\0".to_vec();
        container.extend_from_slice(bundle_id.as_bytes());
        NativeSandboxIdentity::Macos {
            generation_id,
            bundle_id,
            container,
            guardian_pgid: None,
            bundle_root: None,
            signed_digest: None,
            container_root: None,
            substate: MacGenerationSubstate::Reserved,
            state: MacGenerationState::Poisoned,
        }
    }
}

struct BridgeRestrictedExecutor {
    inputs: Vec<ApprovedInput>,
    sidecars: Vec<SidecarBinding>,
    staged_output_hash: Sha256Digest,
    scanner_result_hash: Sha256Digest,
}

impl BridgeRestrictedExecutor {
    fn new(
        harness: HarnessId,
        inputs: Vec<ApprovedInput>,
        sidecars: Vec<SidecarBinding>,
        staged_output_hash: Sha256Digest,
        scanner_result_hash: Sha256Digest,
    ) -> Result<Self, ClientError> {
        let runtime_target = RuntimeTarget::current()
            .map_err(|_| unsupported("Persisted bridge execution is unavailable on this host"))?;
        let expected_command = SidecarCommand::RuleSyncGenerate {
            target: match harness {
                HarnessId::ClaudeCode | HarnessId::Hermes => RuleSyncTarget::ClaudeCode,
                HarnessId::Codex => RuleSyncTarget::CodexCli,
            },
            features: RuleSyncFeatures::new(&[RuleSyncFeature::Mcp])
                .map_err(|_| invalid("Persisted bridge sidecar is invalid"))?,
        };
        let valid_sidecar = matches!(sidecars.as_slice(), [sidecar]
            if sidecar.id == SidecarId::RuleSync
                && sidecar.target == runtime_target
                && sidecar.version == "bridge-preview-v1"
                && sidecar.command == expected_command);
        if !inputs.is_empty() || !valid_sidecar {
            return Err(invalid("Persisted bridge restricted plan is invalid"));
        }
        Ok(Self {
            inputs,
            sidecars,
            staged_output_hash,
            scanner_result_hash,
        })
    }
}

impl RestrictedExecutor for BridgeRestrictedExecutor {
    fn copy_allowlisted_inputs(&mut self, inputs: &[ApprovedInput]) -> Result<(), BoundaryError> {
        (inputs == self.inputs)
            .then_some(())
            .ok_or_else(|| BoundaryError::new("bridge setup staged inputs changed after approval"))
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
        if sidecars != self.sidecars {
            return Err(BoundaryError::new(
                "bridge setup sidecars changed after approval",
            ));
        }
        Ok(RestrictedRun {
            staged_output_hash: self.staged_output_hash,
            scanner_result_hash: self.scanner_result_hash,
        })
    }

    fn reject_unsafe_topology(&mut self) -> Result<(), BoundaryError> {
        Ok(())
    }
}

fn wire_native_path(path: &Path) -> WireNativeValue {
    #[cfg(windows)]
    let (platform, bytes) = {
        use std::os::windows::ffi::OsStrExt as _;
        (
            NativePlatform::Windows,
            path.as_os_str()
                .encode_wide()
                .flat_map(u16::to_le_bytes)
                .collect(),
        )
    };
    #[cfg(not(windows))]
    let (platform, bytes) = {
        use std::os::unix::ffi::OsStrExt as _;
        (NativePlatform::Macos, path.as_os_str().as_bytes().to_vec())
    };
    WireNativeValue {
        platform,
        bytes,
        display: None,
    }
}

#[cfg(windows)]
fn decode_wire_path(value: &WireNativeValue) -> Result<PathBuf, ClientError> {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt as _};

    if value.platform != NativePlatform::Windows || !value.bytes.len().is_multiple_of(2) {
        return Err(invalid("Registered project path is invalid"));
    }
    Ok(PathBuf::from(OsString::from_wide(
        &value
            .bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>(),
    )))
}

#[cfg(not(windows))]
fn decode_wire_path(value: &WireNativeValue) -> Result<PathBuf, ClientError> {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt as _};

    if value.platform != NativePlatform::Macos || value.bytes.contains(&0) {
        return Err(invalid("Registered project path is invalid"));
    }
    Ok(PathBuf::from(OsString::from_vec(value.bytes.clone())))
}

fn invalid(message: &str) -> ClientError {
    client_error(ErrorCode::InvalidRequest, message)
}

fn unsupported(message: &str) -> ClientError {
    client_error(ErrorCode::HarnessUnsupported, message)
}

fn not_found(message: &str) -> ClientError {
    client_error(ErrorCode::NotFound, message)
}

fn client_error(code: ErrorCode, message: &str) -> ClientError {
    ClientError {
        code,
        message: message.to_owned(),
        field_path: None,
        retryable: false,
    }
}

fn internal(message: &str) -> ClientError {
    ClientError {
        code: ErrorCode::Internal,
        message: message.to_owned(),
        field_path: None,
        retryable: false,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::{collections::HashMap, sync::Mutex};

    use crate::unit_test_support::{TempVault, wire_native_os};

    #[cfg(target_os = "macos")]
    use context_relay_core::native_transaction::{ApprovedCliMutation, CanonicalCliDeclaration};
    use context_relay_core::{
        native_transaction::{NativeTransactionPlan, approval_hash_v2, seal_plan},
        setup::{BridgeExecutionError, BridgePlanExecutor},
        vault::{DatabaseKeyStore, SetupPlanWrite, VaultError},
    };
    use context_relay_native_runner::{
        RuleSyncFeature, RuleSyncFeatures, RuleSyncTarget, RuntimeTarget, SidecarCommand, SidecarId,
    };
    #[cfg(target_os = "macos")]
    use context_relay_protocol::CliOperation;
    use context_relay_protocol::{
        ApprovalClass, HarnessId, NativeScope, NetworkDelta, PermissionDelta, SetupPlan,
        Sha256Digest, WireNativeValue,
    };
    #[cfg(target_os = "macos")]
    use sha2::{Digest as _, Sha256};
    use zeroize::Zeroizing;

    use super::*;

    #[test]
    fn retained_runtime_is_rejected_before_production_discovery() {
        let path = TempVault::new("retained-runtime-production-guard");
        let keys = MemoryKeyStore::default();
        let mut vault =
            Vault::open(path.path(), "retained-runtime-production-guard", &keys).unwrap();
        let mut plan = base_plan();
        plan.installed_runtime = Some(
            serde_json::from_value(serde_json::json!({
                "kind": "hermesPythonV1", "runtime": {
                    "schemaVersion": 1, "storageKey": "context-relay-hermes-runtime-Abc123",
                    "manifestIdentity": Sha256Digest([71; 32]),
                }
            }))
            .unwrap(),
        );
        let mut executor = ProductionBridgePlanExecutor {
            vault_path: path.path(),
            device_id: "018f22e2-79b0-7cc8-98c4-dc0c0c073990".parse().unwrap(),
        };
        assert!(
            executor
                .verify_registration_inner(&plan)
                .unwrap_err()
                .message
                .contains("Retained Hermes runtime registration")
        );
        match executor.execute_inner(&mut vault, &plan, &[], 1, 1) {
            Err(ProductionExecutionError::Compose(error)) => {
                assert!(error.message.contains("Retained Hermes runtime execution"))
            }
            _ => panic!("runtime must be rejected before ordinary production composition"),
        }
    }

    #[test]
    fn codex_probe_reports_saved_approvals_without_starting_another_process() {
        use context_relay_core::codex::{CodexExecutableKind, CodexLayout};
        use context_relay_protocol::{
            InstallationMethod, SavedHookApproval, SavedMemoryHookApproval,
        };

        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let home = root.join("home");
        let config = home.join(".codex");
        let project = root.join("project");
        fs::create_dir_all(&config).unwrap();
        fs::create_dir(&project).unwrap();
        let device: DeviceId = "018f22e2-79b0-7cc8-98c4-dc0c0c073982".parse().unwrap();
        let adapter = CodexAdapter::from_layout(
            CodexLayout {
                executable: std::env::current_exe().unwrap(),
                executable_kind: CodexExecutableKind::Native,
                version: "0.144.6".into(),
                installation_method: InstallationMethod::Manual,
                codex_home: config.clone(),
                user_home: home.clone(),
                user_skills_dir: home.join(".agents/skills"),
                project_root: project.clone(),
                working_directory: project,
                requirements_paths: vec![],
            },
            "018f22e2-79b0-7cc8-98c4-dc0c0c073981".parse().unwrap(),
            device,
            HybridLogicalClock::new(1, 0, device),
        )
        .unwrap();
        let engine = ProductionBridgeInstallEngine::with_daemon_executable(root.join("contextd"));
        let context = ProbeContext {
            harness: HarnessId::Codex,
            requested_profile: None,
        };
        // Without the installed adjacent bridge, approval evidence is unavailable.
        assert_eq!(
            engine
                .probe_codex(&adapter, &context)
                .unwrap()
                .codex_saved_hook_approval,
            None
        );
        let bridge = engine.bridge.bridge_path().unwrap();
        fs::write(&bridge, b"fixture only; never executed").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&bridge, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let missing = engine.probe_codex(&adapter, &context).unwrap();
        assert_eq!(
            missing.codex_saved_hook_approval,
            Some(SavedMemoryHookApproval {
                session_start: SavedHookApproval::Missing,
                stop: SavedHookApproval::Missing,
            })
        );
        assert_eq!(
            missing.capability,
            context_relay_protocol::CapabilityLevel::ImportOnly
        );
        let component = context_relay_core::native_memory::managed_memory_hooks(
            HarnessId::Codex,
            &wire_native_path(&engine.bridge.locate().unwrap().path),
        )
        .unwrap()
        .remove(0);
        let hooks = format!("{{\"hooks\":{}}}", component.body_markdown);
        fs::write(config.join("hooks.json"), &hooks).unwrap();
        let pending = engine.probe_codex(&adapter, &context).unwrap();
        assert_eq!(
            pending.codex_saved_hook_approval,
            Some(SavedMemoryHookApproval {
                session_start: SavedHookApproval::NeedsApproval,
                stop: SavedHookApproval::NeedsApproval,
            })
        );
        assert_eq!(
            fs::read_to_string(config.join("hooks.json")).unwrap(),
            hooks
        );
        assert!(!config.join(".personality_migration").exists());
        fs::write(config.join("hooks.json"), b"{malformed").unwrap();
        assert_eq!(
            engine
                .probe_codex(&adapter, &context)
                .unwrap()
                .codex_saved_hook_approval,
            None
        );
    }

    fn hidden_command(program: impl AsRef<std::ffi::OsStr>) -> std::process::Command {
        let command = std::process::Command::new(program);
        #[cfg(windows)]
        let command = {
            use std::os::windows::process::CommandExt as _;
            let mut command = command;
            command.creation_flags(0x0800_0000);
            command
        };
        command
    }

    #[test]
    fn production_registration_discovery_never_launches_approved_or_changed_harnesses() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let canary = root.join(format!("watch-canary{}", std::env::consts::EXE_SUFFIX));
        let fallback_marker = root.join("unexpected-launch-with-cleared-environment");
        let output = hidden_command(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/watch-registration-canary.rs"),
            )
            .env("CONTEXT_RELAY_TEST_WATCH_FALLBACK", &fallback_marker)
            .arg("-o")
            .arg(&canary)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let marker = root.join("positive-control");
        let output = hidden_command(&canary)
            .env("CONTEXT_RELAY_TEST_WATCH_MARKER", &marker)
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(marker.is_file(), "the canary must detect an actual launch");
        for harness in ["claude", "codex", "hermes"] {
            for change in ["unchanged", "bytes", "path", "project"] {
                let case = root.join(format!("{harness}-{change}"));
                let bin = case.join("bin");
                let other_bin = case.join("other-bin");
                let home = case.join("home");
                let user_home = PathBuf::from(home.to_str().unwrap().trim_start_matches(r"\\?\"));
                for directory in [&bin, &other_bin, &home] {
                    fs::create_dir_all(directory).unwrap();
                }
                let name = format!("{harness}{}", std::env::consts::EXE_SUFFIX);
                fs::copy(&canary, bin.join(&name)).unwrap();
                fs::copy(&canary, other_bin.join(&name)).unwrap();
                let child_marker = case.join("unexpected-launch");
                let search_path = if change == "path" { &other_bin } else { &bin };
                let search_path =
                    PathBuf::from(search_path.to_str().unwrap().trim_start_matches(r"\\?\"));
                let mut child = hidden_command(std::env::current_exe().unwrap());
                child
                    .env_clear()
                    .args([
                        "--exact",
                        "bridge_install::tests::registration_discovery_child",
                        "--ignored",
                        "--nocapture",
                    ])
                    .env("CONTEXT_RELAY_TEST_WATCH_ROOT", &case)
                    .env("CONTEXT_RELAY_TEST_WATCH_HARNESS", harness)
                    .env("CONTEXT_RELAY_TEST_WATCH_CHANGE", change)
                    .env("CONTEXT_RELAY_TEST_WATCH_MARKER", &child_marker)
                    .env("PATH", &search_path)
                    .env("HOME", &user_home)
                    .env("USERPROFILE", &user_home)
                    .env("CLAUDE_CONFIG_DIR", home.join("claude"))
                    .env("CODEX_HOME", home.join("codex"))
                    .env("HERMES_HOME", home.join("hermes"))
                    .current_dir(&case);
                for key in ["SystemRoot", "WINDIR", "TEMP", "TMP"] {
                    if let Some(value) = std::env::var_os(key) {
                        child.env(key, value);
                    }
                }
                let output = child.output().unwrap();
                assert!(
                    !child_marker.exists() && !fallback_marker.exists(),
                    "{harness}/{change} launched a harness"
                );
                assert!(
                    output.status.success(),
                    "{harness}/{change}: {}\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
    }

    #[test]
    #[ignore = "only invoked in an isolated child environment by the production registration canary"]
    fn registration_discovery_child() {
        use context_relay_core::{
            claude_code::ClaudeCodeLayout,
            codex::{CodexExecutableKind, CodexLayout},
            hermes::{HermesExecutableKind, HermesLayout, HermesProfile},
        };
        let root = PathBuf::from(std::env::var_os("CONTEXT_RELAY_TEST_WATCH_ROOT").unwrap());
        let harness = std::env::var("CONTEXT_RELAY_TEST_WATCH_HARNESS").unwrap();
        let change = std::env::var("CONTEXT_RELAY_TEST_WATCH_CHANGE").unwrap();
        let home = root.join("home");
        // Use the ordinary Windows home spelling used by the native runtime.
        let user_home = PathBuf::from(home.to_str().unwrap().trim_start_matches(r"\\?\"));
        let project = root.join("project");
        for path in [
            project.join(".claude"),
            home.join("claude"),
            home.join("codex"),
            home.join("hermes"),
        ] {
            fs::create_dir_all(path).unwrap();
        }
        fs::write(
            project.join(".claude/settings.json"),
            br#"{"autoMemoryDirectory":"~/memory"}"#,
        )
        .unwrap();
        fs::write(home.join("claude/settings.json"), b"{}").unwrap();
        fs::write(home.join("claude/.claude.json"), b"{}").unwrap();
        fs::write(home.join("codex/config.toml"), b"").unwrap();
        fs::write(home.join("hermes/config.yaml"), b"{}\n").unwrap();
        let project = fs::canonicalize(project).unwrap();
        let executable = root
            .join("bin")
            .join(format!("{harness}{}", std::env::consts::EXE_SUFFIX));
        let executable = PathBuf::from(executable.to_str().unwrap().trim_start_matches(r"\\?\"));
        let device_id = DeviceId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073990").unwrap();
        let project_id = global_project_id().unwrap();
        let now = now_ms().unwrap();
        let clock = HybridLogicalClock::new(now, 0, device_id);
        let vault_path = root.join("vault.db");
        let mut vault = Vault::open(
            &vault_path,
            "watch-production-canary",
            &MemoryKeyStore::default(),
        )
        .unwrap();
        fn preview(
            vault: &mut Vault,
            adapter: impl context_relay_core::setup::BridgePreviewHarness,
            project: &Path,
            device: DeviceId,
            clock: HybridLogicalClock,
            now: u64,
        ) -> NativeTransactionPlan {
            let setup = BridgeInstallService::new(
                vault,
                adapter,
                ProductionBridgeInstallEngine::with_daemon_executable("unused").bridge,
                device,
                clock,
            )
            .preview(
                Some(&RegisteredProject {
                    project_id: global_project_id().unwrap(),
                    root: crate::unit_test_support::wire_native_path(project),
                }),
                now,
            )
            .unwrap();
            context_relay_core::native_transaction::open_plan(
                &vault.setup_plan(&setup.plan_id).unwrap().unwrap().payload,
            )
            .unwrap()
            .plan
        }
        let installation_method = context_relay_protocol::InstallationMethod::PackageManager;
        let mut plan = match harness.as_str() {
            "claude" => preview(
                &mut vault,
                ClaudeCodeAdapter::from_layout(
                    ClaudeCodeLayout {
                        executable: executable.clone(),
                        version: "9.9.9".into(),
                        installation_method,
                        user_home,
                        config_dir: home.join("claude"),
                        state_path: home.join("claude/.claude.json"),
                        project_root: project.clone(),
                        managed_settings_paths: if cfg!(windows) {
                            vec![]
                        } else if cfg!(target_os = "macos") {
                            vec![PathBuf::from(
                                "/Library/Application Support/ClaudeCode/managed-settings.json",
                            )]
                        } else {
                            vec![PathBuf::from("/etc/claude-code/managed-settings.json")]
                        },
                    },
                    project_id,
                    device_id,
                    clock,
                )
                .unwrap(),
                &project,
                device_id,
                clock,
                now,
            ),
            "codex" => preview(
                &mut vault,
                CodexAdapter::from_layout(
                    CodexLayout {
                        executable: executable.clone(),
                        executable_kind: CodexExecutableKind::Native,
                        version: "9.9.9".into(),
                        installation_method,
                        codex_home: home.join("codex"),
                        user_home: home.clone(),
                        user_skills_dir: home.join(".agents/skills"),
                        project_root: project.clone(),
                        working_directory: project.clone(),
                        requirements_paths: vec![],
                    },
                    project_id,
                    device_id,
                    clock,
                )
                .unwrap(),
                &project,
                device_id,
                clock,
                now,
            ),
            "hermes" => preview(
                &mut vault,
                HermesAdapter::from_layout(
                    HermesLayout {
                        executable: executable.clone(),
                        executable_kind: HermesExecutableKind::Native,
                        version: "9.9.9".into(),
                        installation_method,
                        default_hermes_home: home.join("hermes"),
                        profile: HermesProfile {
                            name: "default".into(),
                            hermes_home: fs::canonicalize(home.join("hermes")).unwrap(),
                        },
                        project_root: project.clone(),
                        working_directory: project.clone(),
                    },
                    project_id,
                    device_id,
                    clock,
                )
                .unwrap(),
                &project,
                device_id,
                clock,
                now,
            ),
            _ => unreachable!(),
        };
        if change == "bytes" {
            use std::io::Write as _;
            fs::OpenOptions::new()
                .append(true)
                .open(&executable)
                .unwrap()
                .write_all(b"changed")
                .unwrap();
        }
        if change == "project" {
            // A noncanonical project claim must be rejected before discovery.
            let separator = std::path::MAIN_SEPARATOR;
            let noncanonical = PathBuf::from(format!(
                "{}{separator}..{separator}project",
                project.display()
            ));
            plan.setup.target_scopes = vec![NativeScope::Project {
                project_id,
                root: crate::unit_test_support::wire_native_path(&noncanonical),
            }];
        }
        let mut executor = ProductionBridgePlanExecutor {
            vault_path: &vault_path,
            device_id,
        };
        let result = executor.verify_watch_only_registration(&plan, now);
        if change == "unchanged" {
            result.unwrap();
        } else {
            assert!(result.is_err());
        }
    }

    #[test]
    fn cli_recovery_uses_the_sealed_project_instead_of_the_vault_directory() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let vault_root = root.join("vault");
        let project_root = root.join("project with spaces");
        fs::create_dir(&vault_root).unwrap();
        fs::create_dir(&project_root).unwrap();
        let project_id = ProjectId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073981").unwrap();
        let device_id = DeviceId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073990").unwrap();
        let recovery = crate::ProductionBridgeCliRecoveryIo {
            root: vault_root.clone(),
            project_id: global_project_id().unwrap(),
            device_id,
            observed_hlc: HybridLogicalClock::new(1, 0, device_id),
        };
        let mut plan = base_plan();
        plan.setup.target_scopes.push(NativeScope::Project {
            project_id,
            root: crate::unit_test_support::wire_native_path(&project_root),
        });
        let mut bound = context_relay_core::native_transaction::recovery::BoundCliRecoveryPlan {
            plan,
            mutations: vec![],
        };
        assert_eq!(
            recovery.project_binding(&bound).unwrap(),
            (project_root.clone(), project_id)
        );
        bound.plan.setup.target_scopes.push(NativeScope::Project {
            project_id: global_project_id().unwrap(),
            root: crate::unit_test_support::wire_native_path(&vault_root),
        });
        assert!(
            recovery.project_binding(&bound).is_err(),
            "ambiguous project scopes cannot select a recovery root"
        );
        bound.plan.setup.target_scopes = vec![NativeScope::Global];
        assert_eq!(
            recovery.project_binding(&bound).unwrap(),
            (vault_root, global_project_id().unwrap())
        );
    }

    #[test]
    fn terminal_apply_and_rollback_replay_before_any_production_composition() {
        let path = TempVault::new("task8-terminal-replay");
        let keys = MemoryKeyStore::default();
        let mut vault = Vault::open(path.path(), "task8-terminal-replay", &keys).unwrap();
        let plan = persist_plan(&mut vault);
        let mut executor = RecordingExecutor;
        BridgeInstallService::persisted(&mut vault)
            .apply(&plan.setup.plan_id, 2, &mut executor)
            .unwrap();
        let production =
            ProductionBridgeInstallEngine::with_daemon_executable("/definitely/missing/contextd");

        production
            .apply(
                &mut vault,
                Path::new("/definitely/missing/vault.db"),
                plan.setup.batch_hash_to_device_for_test(),
                PlanParams {
                    plan_id: plan.setup.plan_id,
                },
            )
            .expect("applied replay must not discover a root, lock, harness, or bridge");

        BridgeInstallService::persisted(&mut vault)
            .rollback(&plan.setup.plan_id, 3, &mut executor)
            .unwrap();
        production
            .rollback(
                &mut vault,
                Path::new("/definitely/missing/vault.db"),
                plan.setup.batch_hash_to_device_for_test(),
                PlanParams {
                    plan_id: plan.setup.plan_id,
                },
            )
            .expect("rolled-back replay must not discover a root, lock, harness, or bridge");
    }

    trait TestDevice {
        fn batch_hash_to_device_for_test(&self) -> DeviceId;
    }

    impl TestDevice for SetupPlan {
        fn batch_hash_to_device_for_test(&self) -> DeviceId {
            DeviceId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073990").unwrap()
        }
    }

    struct RecordingExecutor;

    impl BridgePlanExecutor for RecordingExecutor {
        fn execute(
            &mut self,
            _vault: &mut Vault,
            _plan: &NativeTransactionPlan,
            _sealed_plan: &[u8],
            _created_ms: u64,
            _now_ms: u64,
        ) -> Result<(), BridgeExecutionError> {
            Ok(())
        }
    }

    pub(crate) fn persist_plan(vault: &mut Vault) -> NativeTransactionPlan {
        persist_native_plan(vault, base_plan())
    }

    #[cfg(any(
        all(target_os = "macos", target_arch = "aarch64"),
        all(windows, target_arch = "x86_64")
    ))]
    #[test]
    fn restricted_bridge_plan_accepts_only_the_current_supported_runtime_target() {
        let target = RuntimeTarget::current().unwrap();
        let other = match target {
            RuntimeTarget::MacosArm64 => RuntimeTarget::WindowsX86_64,
            RuntimeTarget::WindowsX86_64 => RuntimeTarget::MacosArm64,
        };
        let plan = base_plan_for_target(target);

        assert!(
            BridgeRestrictedExecutor::new(
                plan.setup.harness,
                plan.staged_inputs.clone(),
                plan.sidecars.clone(),
                plan.expected_semantic_output_hash,
                plan.scanner_result_hash,
            )
            .is_ok()
        );

        let mut mismatched = plan;
        mismatched.sidecars[0].target = other;
        let error = BridgeRestrictedExecutor::new(
            mismatched.setup.harness,
            mismatched.staged_inputs,
            mismatched.sidecars,
            mismatched.expected_semantic_output_hash,
            mismatched.scanner_result_hash,
        )
        .err()
        .unwrap();
        assert_eq!(error.code, ErrorCode::InvalidRequest);
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn persist_claude_cli_plan(
        vault: &mut Vault,
        executable: &Path,
        bridge_executable: &Path,
        execution_context: context_relay_core::native_transaction::CliExecutionContext,
    ) -> NativeTransactionPlan {
        let mut plan = base_plan();
        plan.setup.harness = HarnessId::ClaudeCode;
        plan.setup.executable_path = native_text(executable.to_str().unwrap());
        plan.setup.executable_hash =
            Sha256Digest(Sha256::digest(fs::read(executable).unwrap()).into());
        plan.setup.harness_version = "2.1.214".into();
        let context_relay_core::native_transaction::CliExecutionContext::ClaudeCodeV2 {
            project_root,
            ..
        } = &execution_context
        else {
            panic!("fixture needs an explicit Claude context");
        };
        plan.setup.target_scopes.push(NativeScope::Project {
            project_id: global_project_id().unwrap(),
            root: project_root.clone(),
        });
        plan.sidecars[0].command = SidecarCommand::RuleSyncGenerate {
            target: RuleSyncTarget::ClaudeCode,
            features: RuleSyncFeatures::new(&[RuleSyncFeature::Mcp]).unwrap(),
        };
        let canonical_body = serde_json::to_string(&serde_json::json!({
            "args": ["--harness", "claude-code"],
            "command": bridge_executable.to_str().unwrap(),
            "type": "stdio",
        }))
        .unwrap();
        let intended = CanonicalCliDeclaration {
            harness: HarnessId::ClaudeCode,
            server_name: "context-relay".into(),
            fingerprint: Sha256Digest(Sha256::digest(canonical_body.as_bytes()).into()),
            canonical_body,
        };
        let forward = CliOperation {
            executable: plan.setup.executable_path.clone(),
            arguments: [
                "mcp",
                "add-json",
                "context-relay",
                intended.canonical_body.as_str(),
                "--scope",
                "user",
            ]
            .into_iter()
            .map(native_text)
            .collect(),
            timeout_ms: 30_000,
        };
        let rollback = CliOperation {
            executable: plan.setup.executable_path.clone(),
            arguments: ["mcp", "remove", "context-relay", "--scope", "user"]
                .into_iter()
                .map(native_text)
                .collect(),
            timeout_ms: 30_000,
        };
        plan.setup.cli_operations = vec![forward.clone()];
        plan.cli_mutations = vec![ApprovedCliMutation {
            execution_context: Some(execution_context),
            stable_id: "f4a4f9a2-0e8d-720e-8df4-a5a68da3e9c7".into(),
            expected: None,
            intended: Some(intended),
            forward: vec![forward],
            rollback: vec![rollback],
        }];
        persist_native_plan(vault, plan)
    }

    fn base_plan() -> NativeTransactionPlan {
        base_plan_for_target(RuntimeTarget::current().unwrap_or(RuntimeTarget::MacosArm64))
    }

    fn base_plan_for_target(runtime_target: RuntimeTarget) -> NativeTransactionPlan {
        NativeTransactionPlan {
            setup: SetupPlan {
                plan_id: PlanId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073991").unwrap(),
                harness: HarnessId::Codex,
                harness_profile: None,
                adapter_version: 1,
                executable_path: native_text("/definitely/missing/codex"),
                executable_hash: Sha256Digest([1; 32]),
                harness_version: "0.144.1".into(),
                target_scopes: vec![NativeScope::Global],
                expected_native_digests: vec![],
                approval_class: ApprovalClass::Active,
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
                rulesync_version: "bridge-preview-v1".into(),
                rulesync_hash: Sha256Digest([3; 32]),
                expires_at: 10,
                batch_hash: Sha256Digest([0; 32]),
            },
            approval_version: 2,
            helper_policy_version: 1,
            manifest_schema_version: 1,
            manifest_digest: Sha256Digest([4; 32]),
            helper_hash: Sha256Digest([5; 32]),
            sidecars: vec![SidecarBinding {
                id: SidecarId::RuleSync,
                target: runtime_target,
                version: "bridge-preview-v1".into(),
                closure_hash: Sha256Digest([9; 32]),
                source_bundle_hash: Sha256Digest([10; 32]),
                build_toolchain_hash: Sha256Digest([11; 32]),
                command_template_digest: Sha256Digest([12; 32]),
                command: SidecarCommand::RuleSyncGenerate {
                    target: RuleSyncTarget::CodexCli,
                    features: RuleSyncFeatures::new(&[RuleSyncFeature::Mcp]).unwrap(),
                },
            }],
            structural_allowlist_hash: Sha256Digest([6; 32]),
            staged_inputs: vec![],
            expected_semantic_output_hash: Sha256Digest([7; 32]),
            scanner_result_hash: Sha256Digest([8; 32]),
            mutations: vec![],
            cli_mutations: vec![],
            installed_runtime: None,
            native_memory_registrations: vec![],
            ownership_changes: vec![],
        }
    }

    fn persist_native_plan(
        vault: &mut Vault,
        mut plan: NativeTransactionPlan,
    ) -> NativeTransactionPlan {
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
                created_ms: 1,
                expires_ms: plan.setup.expires_at,
            })
            .unwrap();
        plan
    }

    fn native_text(value: &str) -> WireNativeValue {
        wire_native_os(std::ffi::OsStr::new(value))
    }

    #[derive(Default)]
    struct MemoryKeyStore {
        values: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl DatabaseKeyStore for MemoryKeyStore {
        fn load_key(&self, credential_id: &str) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
            Ok(self
                .values
                .lock()
                .unwrap()
                .get(credential_id)
                .cloned()
                .map(Zeroizing::new))
        }

        fn store_key(&self, credential_id: &str, key: &[u8]) -> Result<(), VaultError> {
            self.values
                .lock()
                .unwrap()
                .insert(credential_id.into(), key.to_vec());
            Ok(())
        }
    }
}
