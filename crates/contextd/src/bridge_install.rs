use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use context_relay_core::{
    claude_code::ClaudeCodeAdapter,
    codex::CodexAdapter,
    hermes::HermesAdapter,
    mcp::install::{BridgeExecutable, attest_bridge_executable},
    native_transaction::{
        ApprovedInput, SidecarBinding,
        engine::{BoundaryError, NoFault, RestrictedExecutor, RestrictedRun},
        filesystem::OsNativeTransactionFileSystem,
        open_plan,
    },
    setup::{
        BridgeInstallService, BridgeLocator, NativeEngineBridgePlanExecutor, NoBridgeCliExecutor,
        RegisteredProject,
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
use sha2::{Digest as _, Sha256};

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
        let stored = vault
            .setup_plan(&plan_id)
            .map_err(|_| invalid("Persisted bridge plan cannot be loaded"))?
            .ok_or_else(|| invalid("Persisted bridge plan does not exist"))?;
        let opened = open_plan(&stored.payload)
            .map_err(|_| invalid("Persisted bridge plan is malformed or unapproved"))?;
        if opened.plan.setup.plan_id != plan_id || opened.rollback_of_plan_id.is_some() {
            return Err(invalid("Persisted bridge plan binding is invalid"));
        }
        let now_ms = now_ms()?;
        let root = stable_process_root()?;
        let project_id = global_project_id()?;
        let observed_hlc = HybridLogicalClock::new(now_ms, 0, device_id);
        let execution_plan_id = if rollback {
            rollback_plan_id(&plan_id)?
        } else {
            plan_id
        };
        let lock_root = canonical_lock_root(vault_path)?;
        let identity = sandbox_identity(&execution_plan_id);
        let mut restricted = BridgeRestrictedExecutor::new(
            opened.plan.setup.harness,
            opened.plan.staged_inputs.clone(),
            opened.plan.sidecars.clone(),
            opened.plan.expected_semantic_output_hash,
            opened.plan.scanner_result_hash,
        )?;
        let mut filesystem = OsNativeTransactionFileSystem::new(*execution_plan_id.as_bytes());
        let mut hook = NoFault;

        match opened.plan.setup.harness {
            HarnessId::ClaudeCode => {
                let mut adapter =
                    ClaudeCodeAdapter::discover(&root, project_id, device_id, observed_hlc)?;
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
                execute_persisted(vault, &plan_id, now_ms, rollback, &mut executor)
            }
            HarnessId::Codex => {
                let mut adapter =
                    CodexAdapter::discover(&root, &root, project_id, device_id, observed_hlc)?;
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
                execute_persisted(vault, &plan_id, now_ms, rollback, &mut executor)
            }
            HarnessId::Hermes => {
                let mut adapter = HermesAdapter::discover(
                    &root,
                    &root,
                    "default",
                    project_id,
                    device_id,
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
                execute_persisted(vault, &plan_id, now_ms, rollback, &mut executor)
            }
        }
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

fn global_project_id() -> Result<ProjectId, ClientError> {
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
    .map_err(|_| internal("Rollback bridge plan identifier cannot be derived"))
}

fn sandbox_identity(plan_id: &PlanId) -> NativeSandboxIdentity {
    let generation_id = plan_id
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    #[cfg(windows)]
    {
        NativeSandboxIdentity::Windows {
            moniker: format!("context-relay.native.{generation_id}"),
            sid: b"S-1-15-2-1-2-3-4-5-6-7".to_vec(),
        }
    }
    #[cfg(not(windows))]
    {
        let bundle_id = format!("com.contextrelay.native-runner.{generation_id}");
        let mut container = b"context-relay/macos-container/v1\0".to_vec();
        container.extend_from_slice(bundle_id.as_bytes());
        NativeSandboxIdentity::reserved_macos(generation_id, bundle_id, container)
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
