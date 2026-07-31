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
    ClientError, DeviceId, ErrorCode, HarnessId, HarnessParams, HybridLogicalClock, NativePlatform,
    PlanId, PlanParams, ProjectId, SetupPlan, Sha256Digest, WireNativeValue,
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
}

impl BridgeInstallEngine for ProductionBridgeInstallEngine {
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
        let binding = project_binding(vault, params.project_id)?;
        let observed_hlc = HybridLogicalClock::new(now_ms, 0, device_id);
        match params.harness {
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
            HarnessId::Hermes => BridgeInstallService::new(
                vault,
                HermesAdapter::discover(
                    &binding.root,
                    &binding.root,
                    "default",
                    binding.project_id,
                    device_id,
                    observed_hlc,
                )?,
                self.bridge.clone(),
                device_id,
                observed_hlc,
            )
            .preview(binding.registered.as_ref(), now_ms),
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
    fn execute_inner(
        &mut self,
        vault: &mut Vault,
        plan: &context_relay_core::native_transaction::NativeTransactionPlan,
        sealed_plan: &[u8],
        created_ms: u64,
        now_ms: u64,
    ) -> Result<(), ProductionExecutionError> {
        let root = stable_process_root()?;
        let project_id = global_project_id()?;
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
                let mut adapter = HermesAdapter::discover(
                    &root,
                    &root,
                    "default",
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
                && sidecar.target == RuntimeTarget::MacosArm64
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
        ApprovalClass, HarnessId, NativePlatform, NativeScope, NetworkDelta, PermissionDelta,
        SetupPlan, Sha256Digest, WireNativeValue,
    };
    #[cfg(target_os = "macos")]
    use sha2::{Digest as _, Sha256};
    use zeroize::Zeroizing;

    use super::*;

    #[test]
    fn terminal_apply_and_rollback_replay_before_any_production_composition() {
        let path = unique_path("terminal-replay");
        let keys = MemoryKeyStore::default();
        let mut vault = Vault::open(&path, "task8-terminal-replay", &keys).unwrap();
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

    #[cfg(target_os = "macos")]
    pub(crate) fn persist_claude_cli_plan(
        vault: &mut Vault,
        executable: &Path,
        bridge_executable: &Path,
    ) -> NativeTransactionPlan {
        let mut plan = base_plan();
        plan.setup.harness = HarnessId::ClaudeCode;
        plan.setup.executable_path = native_text(executable.to_str().unwrap());
        plan.setup.executable_hash =
            Sha256Digest(Sha256::digest(fs::read(executable).unwrap()).into());
        plan.setup.harness_version = "2.1.214".into();
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
            stable_id: "f4a4f9a2-0e8d-720e-8df4-a5a68da3e9c7".into(),
            expected: None,
            intended: Some(intended),
            forward: vec![forward],
            rollback: vec![rollback],
        }];
        persist_native_plan(vault, plan)
    }

    fn base_plan() -> NativeTransactionPlan {
        NativeTransactionPlan {
            setup: SetupPlan {
                plan_id: PlanId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073991").unwrap(),
                harness: HarnessId::Codex,
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
                target: RuntimeTarget::MacosArm64,
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
        WireNativeValue {
            platform: NativePlatform::Macos,
            bytes: value.as_bytes().to_vec(),
            display: Some(value.into()),
        }
    }

    fn unique_path(label: &str) -> PathBuf {
        PathBuf::from("/private/tmp").join(format!(
            "context-relay-task8-{label}-{}",
            uuid::Uuid::now_v7()
        ))
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
