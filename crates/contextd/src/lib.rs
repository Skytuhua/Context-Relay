mod connection_check;
#[cfg(test)]
#[path = "../build.rs"]
mod hosted_build_config;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread::JoinHandle,
    time::Duration,
};

#[cfg(not(windows))]
use context_relay_core::vault::{MacGenerationState, MacGenerationSubstate};
use context_relay_core::{
    crypto::DeviceKeys,
    devices::identity::{
        DeviceIdentityStore, PlatformDeviceIdentityStore, load_or_create_device_keys,
    },
    mcp::McpWorkspace,
    native_transaction::{
        cli::NativeCliExecutor,
        engine::{BoundaryError, NativeAdapter},
        recovery::{
            BoundCliRecoveryPlan, CliRecoveryRestore, NativeCliRecoveryIo, OsNativeRecoveryIo,
            RecoveryCleanup, RecoveryOutcome, RecoverySandboxIdentity, bind_cli_recovery_plan,
            recover_native_transactions_with_cli,
        },
    },
    service::OfflineWorkspace,
    vault::{DatabaseKeyStore, NativeCliWalRecord, PlatformKeyStore, Vault, VaultError},
};
use context_relay_local_ipc::{
    AuthenticatedConnection, AuthenticatedRequest, CONNECTION_LIMIT, ConnectedStream,
    INSTALLATION_TOKEN_CREDENTIAL_ACCOUNT, INSTALLATION_TOKEN_CREDENTIAL_SERVICE,
    InstallationToken, InstanceGuard, IpcError, Listener, REQUEST_QUEUE_CAPACITY,
    RequestRegistration, RequestRegistry, RuntimeConfig, SHUTDOWN_TIMEOUT, generate_instance_nonce,
    load_installation_token, role_allows,
};
use context_relay_protocol::{
    BoundedBytes, ClientError, ClientRole, DaemonInstanceNonce, DeviceId, ErrorCode, ExportId,
    ExportPayload, HandoffPayload, HarnessId, HybridLogicalClock, LocalRequest, LocalResult,
    MAX_ARBITRARY_BYTES, MemoryKind, MemoryParams, NativePlatform, PROTOCOL_VERSION,
    ProjectPathParams, ProtocolVersionRange, ScopeRef, Sha256Digest, SyncState, VaultState,
};
use sha2::{Digest, Sha256};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch},
    task::JoinSet,
    time::timeout,
};

mod account_lifecycle;
pub mod bridge_install;
pub mod harness_preparation;
pub mod hosted_auth;
pub mod hosted_login;
mod native_memory;
mod pairing;
mod recovery_enrollment;
mod search_index;

#[cfg(test)]
pub(crate) mod unit_test_support {
    use std::{
        ffi::OsStr,
        path::{Path, PathBuf},
    };

    use context_relay_protocol::{NativePlatform, WireNativeValue};

    pub(crate) struct TempVault {
        _root: tempfile::TempDir,
        path: PathBuf,
    }

    impl TempVault {
        pub(crate) fn new(label: &str) -> Self {
            let root = tempfile::Builder::new()
                .prefix(&format!("context-relay-{label}-"))
                .tempdir()
                .expect("temporary vault directory");
            let path = root.path().join("vault.db");
            Self { _root: root, path }
        }

        pub(crate) fn path(&self) -> &Path {
            &self.path
        }
    }

    pub(crate) fn wire_native_path(path: &Path) -> WireNativeValue {
        wire_native_os(path.as_os_str())
    }

    pub(crate) fn wire_native_os(value: &OsStr) -> WireNativeValue {
        #[cfg(not(windows))]
        use std::os::unix::ffi::OsStrExt as _;
        #[cfg(windows)]
        use std::os::windows::ffi::OsStrExt as _;

        WireNativeValue {
            platform: if cfg!(windows) {
                NativePlatform::Windows
            } else {
                NativePlatform::Macos
            },
            #[cfg(not(windows))]
            bytes: value.as_bytes().to_vec(),
            #[cfg(windows)]
            bytes: value.encode_wide().flat_map(u16::to_le_bytes).collect(),
            display: value.to_str().map(str::to_owned),
        }
    }
}

use account_lifecycle::{
    AccountLifecycleService, TransportAccountLifecycleService, UnavailableAccountLifecycleTransport,
};
use bridge_install::{BridgeInstallEngine, ProductionBridgeInstallEngine};
use harness_preparation::{PreparationClient, PreparationSupervisor};
mod harness_execution;
use native_memory::{
    NativeMemorySupervisor, NativeMemoryUpdateSender, NoopLifecycleProbe,
    native_memory_update_channel,
};
use pairing::{PairingIdentity, PairingService};
use recovery_enrollment::RecoveryEnrollmentService;

pub const VAULT_CREDENTIAL_ID: &str = "vault-key-v1";
const DEVICE_IDENTITY_CREDENTIAL_ID: &str = "device-identity-v1";
const WORK_RESPONSE_TIMEOUT: Duration = Duration::from_secs(29);
const NATIVE_SANDBOX_DIRECTORY: &str = "native-sandboxes";

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum DaemonError {
    #[error("Context Relay is already running")]
    AlreadyRunning,
    #[error("Context Relay could not start")]
    Startup,
    #[error("Context Relay transport failed")]
    Transport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaemonState {
    Running,
    Draining,
    Stopped,
}

#[derive(Clone)]
pub struct DaemonHandle {
    shutdown: watch::Sender<bool>,
    state: watch::Receiver<DaemonState>,
}

impl DaemonHandle {
    pub fn state(&self) -> DaemonState {
        *self.state.borrow()
    }

    pub async fn shutdown(&self) -> DaemonState {
        self.shutdown.send_replace(true);
        let mut state = self.state.clone();
        let stopped = async {
            loop {
                let current = *state.borrow_and_update();
                if current == DaemonState::Stopped {
                    return current;
                }
                if state.changed().await.is_err() {
                    return *state.borrow();
                }
            }
        };
        match timeout(SHUTDOWN_TIMEOUT, stopped).await {
            Ok(state) => state,
            Err(_) => self.state(),
        }
    }
}

trait InstallationTokenProvider: Send + Sync {
    fn load_or_create(&self) -> Result<InstallationToken, DaemonError>;
}

trait WorkerHook: Send + Sync {
    fn before_execute(&self);

    fn after_enqueue(&self) {}

    #[cfg(test)]
    fn before_index(&self) {}

    #[cfg(test)]
    fn before_index_admission(&self) {}
}

#[cfg(test)]
type StartupRecovery = Arc<dyn Fn(&mut Vault) -> Result<(), DaemonError> + Send + Sync + 'static>;

#[derive(Default)]
struct PlatformInstallationTokenProvider;

impl InstallationTokenProvider for PlatformInstallationTokenProvider {
    fn load_or_create(&self) -> Result<InstallationToken, DaemonError> {
        match load_installation_token() {
            Ok(token) => Ok(token),
            Err(IpcError::MissingToken) => {
                let token = InstallationToken::generate().map_err(|_| DaemonError::Startup)?;
                keyring::Entry::new(
                    INSTALLATION_TOKEN_CREDENTIAL_SERVICE,
                    INSTALLATION_TOKEN_CREDENTIAL_ACCOUNT,
                )
                .map_err(|_| DaemonError::Startup)?
                .set_secret(token.as_bytes())
                .map_err(|_| DaemonError::Startup)?;
                Ok(token)
            }
            Err(_) => Err(DaemonError::Startup),
        }
    }
}

struct VaultConfig {
    search_resources: Option<PathBuf>,
    preparation: Option<PreparationClient>,
    path: PathBuf,
    credential_id: String,
    key_store: Arc<dyn DatabaseKeyStore>,
    device_id: DeviceId,
    worker_hook: Option<Arc<dyn WorkerHook>>,
    bridge_install: Arc<dyn BridgeInstallEngine>,
    native_memory_probe: Arc<dyn native_memory::LifecycleProbe>,
    native_memory_updates: Option<NativeMemoryUpdateSender>,
    pairing_service: Option<Arc<dyn PairingService>>,
    recovery_enrollment_service: Option<Arc<dyn RecoveryEnrollmentService>>,
    account_lifecycle_service: Arc<dyn AccountLifecycleService>,
    device_keys: Option<Arc<DeviceKeys>>,
    device_identity_credential_id: String,
    device_identity_store: Arc<dyn DeviceIdentityStore>,
    device_name: String,
    platform: NativePlatform,
    #[cfg(test)]
    startup_recovery: Option<StartupRecovery>,
}

impl VaultConfig {
    fn new(
        path: PathBuf,
        credential_id: impl Into<String>,
        key_store: Arc<dyn DatabaseKeyStore>,
    ) -> Self {
        Self {
            preparation: None,
            search_resources: None,
            path,
            credential_id: credential_id.into(),
            key_store,
            device_id: stable_device_id(b"context-relay-test-device"),
            worker_hook: None,
            bridge_install: Arc::new(
                ProductionBridgeInstallEngine::production()
                    .expect("the running daemon has an executable location"),
            ),
            native_memory_probe: Arc::new(NoopLifecycleProbe),
            native_memory_updates: None,
            pairing_service: None,
            recovery_enrollment_service: None,
            account_lifecycle_service: Arc::new(TransportAccountLifecycleService::new(
                UnavailableAccountLifecycleTransport,
            )),
            device_keys: None,
            device_identity_credential_id: DEVICE_IDENTITY_CREDENTIAL_ID.into(),
            device_identity_store: Arc::new(PlatformDeviceIdentityStore),
            device_name: "This device".into(),
            platform: native_platform(),
            #[cfg(test)]
            startup_recovery: None,
        }
    }

    fn with_device_id(mut self, device_id: DeviceId) -> Self {
        self.device_id = device_id;
        self
    }

    fn with_bridge_install(mut self, bridge_install: Arc<dyn BridgeInstallEngine>) -> Self {
        self.bridge_install = bridge_install;
        self
    }

    fn with_worker_hook(mut self, worker_hook: Arc<dyn WorkerHook>) -> Self {
        self.worker_hook = Some(worker_hook);
        self
    }

    fn with_native_memory_probe(mut self, probe: Arc<dyn native_memory::LifecycleProbe>) -> Self {
        self.native_memory_probe = probe;
        self
    }

    fn with_native_memory_updates(mut self, updates: NativeMemoryUpdateSender) -> Self {
        self.native_memory_updates = Some(updates);
        self
    }

    #[cfg(test)]
    fn with_pairing_service(
        mut self,
        service: Arc<dyn PairingService>,
        identity_store: Arc<dyn DeviceIdentityStore>,
        credential_id: impl Into<String>,
        device_name: impl Into<String>,
        platform: NativePlatform,
    ) -> Self {
        self.pairing_service = Some(service);
        self.device_identity_store = identity_store;
        self.device_identity_credential_id = credential_id.into();
        self.device_name = device_name.into();
        self.platform = platform;
        self
    }

    #[cfg(test)]
    fn with_recovery_enrollment_service(
        mut self,
        service: Arc<dyn RecoveryEnrollmentService>,
        identity_store: Arc<dyn DeviceIdentityStore>,
        credential_id: impl Into<String>,
        device_name: impl Into<String>,
        platform: NativePlatform,
    ) -> Self {
        self.recovery_enrollment_service = Some(service);
        self.device_identity_store = identity_store;
        self.device_identity_credential_id = credential_id.into();
        self.device_name = device_name.into();
        self.platform = platform;
        self
    }

    #[cfg(test)]
    fn with_account_lifecycle_service(mut self, service: Arc<dyn AccountLifecycleService>) -> Self {
        self.account_lifecycle_service = service;
        self
    }

    #[cfg(test)]
    fn with_startup_recovery(mut self, startup_recovery: StartupRecovery) -> Self {
        self.startup_recovery = Some(startup_recovery);
        self
    }

    fn load_device_identity(mut self) -> Result<Self, DaemonError> {
        if self.device_keys.is_none()
            && (self.pairing_service.is_some() || self.recovery_enrollment_service.is_some())
        {
            self.device_keys = Some(Arc::new(
                load_or_create_device_keys(
                    self.device_identity_store.as_ref(),
                    &self.device_identity_credential_id,
                )
                .map_err(|_| DaemonError::Startup)?,
            ));
        }
        Ok(self)
    }
}

fn recover_startup_native_transactions(
    vault: &mut Vault,
    vault_path: &Path,
    device_id: DeviceId,
) -> Result<(), DaemonError> {
    let root = vault_path
        .parent()
        .and_then(|parent| std::fs::canonicalize(parent).ok())
        .ok_or(DaemonError::Startup)?;
    let private_root = root.join(NATIVE_SANDBOX_DIRECTORY);
    let mut io = OsNativeRecoveryIo::new(|identity, outcome| {
        cleanup_recovered_sandbox(&private_root, &identity, outcome)
    });
    let project_id = bridge_install::global_project_id().map_err(|_| DaemonError::Startup)?;
    let observed_hlc = HybridLogicalClock::new(startup_now_ms()?, 0, device_id);
    let mut cli = ProductionBridgeCliRecoveryIo {
        root,
        project_id,
        device_id,
        observed_hlc,
    };
    recover_native_transactions_with_cli(vault, &mut io, &mut cli)
        .map(|_| ())
        .map_err(|_| DaemonError::Startup)
}

struct ProductionBridgeCliRecoveryIo {
    root: PathBuf,
    project_id: context_relay_protocol::ProjectId,
    device_id: DeviceId,
    observed_hlc: HybridLogicalClock,
}

impl ProductionBridgeCliRecoveryIo {
    fn project_binding(
        &self,
        bound: &BoundCliRecoveryPlan,
    ) -> Result<(PathBuf, context_relay_protocol::ProjectId), BoundaryError> {
        if bound
            .plan
            .setup
            .target_scopes
            .iter()
            .any(|scope| matches!(scope, context_relay_protocol::NativeScope::Project { .. }))
        {
            return bridge_install::sealed_project_binding(&bound.plan)
                .map_err(|error| BoundaryError::new(error.message));
        }
        Ok((self.root.clone(), self.project_id))
    }

    fn with_executor<R>(
        &self,
        bound: &BoundCliRecoveryPlan,
        operation: impl FnOnce(
            &mut dyn NativeCliExecutor,
            &[context_relay_core::native_transaction::ApprovedCliMutation],
        ) -> Result<R, BoundaryError>,
    ) -> Result<R, BoundaryError> {
        let (root, project_id) = self.project_binding(bound)?;
        match bound.plan.setup.harness {
            HarnessId::ClaudeCode => {
                let mut adapter = context_relay_core::claude_code::ClaudeCodeAdapter::discover(
                    &root,
                    project_id,
                    self.device_id,
                    self.observed_hlc,
                )
                .map_err(|error| BoundaryError::new(error.message))?;
                adapter.reprobe_live_state(&bound.plan)?;
                let mut executor = adapter.cli_executor();
                operation(&mut executor, &bound.mutations)
            }
            HarnessId::Codex => {
                let mut adapter = context_relay_core::codex::CodexAdapter::discover(
                    &root,
                    &root,
                    project_id,
                    self.device_id,
                    self.observed_hlc,
                )
                .map_err(|error| BoundaryError::new(error.message))?;
                adapter.reprobe_live_state(&bound.plan)?;
                let mut executor = adapter.cli_executor();
                operation(&mut executor, &bound.mutations)
            }
            HarnessId::Hermes => Err(BoundaryError::new(
                "Hermes plans cannot contain native CLI recovery mutations",
            )),
        }
    }
}

impl NativeCliRecoveryIo for ProductionBridgeCliRecoveryIo {
    fn probe_cli_declaration(
        &mut self,
        sealed_plan_payload: &[u8],
        wal: &NativeCliWalRecord,
    ) -> Result<Option<Sha256Digest>, BoundaryError> {
        let bound = bind_cli_recovery_plan(sealed_plan_payload, std::slice::from_ref(wal))?;
        self.with_executor(&bound, |executor, mutations| {
            executor.probe_cli_mutation(&mutations[0])
        })
    }

    fn restore_cli_mutation_if_matches(
        &mut self,
        sealed_plan_payload: &[u8],
        wal: &NativeCliWalRecord,
    ) -> Result<CliRecoveryRestore, BoundaryError> {
        let bound = bind_cli_recovery_plan(sealed_plan_payload, std::slice::from_ref(wal))?;
        self.with_executor(&bound, |executor, mutations| {
            executor
                .restore_cli_mutation_if_matches(&mutations[0])
                .map(|outcome| {
                    if outcome.restored {
                        CliRecoveryRestore::Restored
                    } else {
                        CliRecoveryRestore::Conflict
                    }
                })
        })
    }

    fn finish_committed_cli_mutations(
        &mut self,
        sealed_plan_payload: &[u8],
        wal: &[NativeCliWalRecord],
    ) -> Result<(), BoundaryError> {
        let bound = bind_cli_recovery_plan(sealed_plan_payload, wal)?;
        self.with_executor(&bound, |executor, mutations| {
            executor.finish_committed_cli_mutations(mutations)
        })
    }
}

fn startup_now_ms() -> Result<u64, DaemonError> {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| DaemonError::Startup)?
        .as_millis();
    u64::try_from(millis).map_err(|_| DaemonError::Startup)
}

#[cfg(windows)]
fn cleanup_recovered_sandbox(
    _private_root: &Path,
    identity: &RecoverySandboxIdentity,
    _outcome: RecoveryOutcome,
) -> Result<RecoveryCleanup, BoundaryError> {
    if is_nonlaunching_recovery_identity(identity) {
        return Ok(RecoveryCleanup::Cleaned);
    }
    let RecoverySandboxIdentity::Windows { moniker, sid } = identity else {
        return Err(BoundaryError::new(
            "sandbox identity does not match the current platform",
        ));
    };
    context_relay_native_runner::windows::cleanup_recovered_profile(moniker, sid)
        .map(|()| RecoveryCleanup::Cleaned)
        .map_err(|error| BoundaryError::new(error.to_string()))
}

#[cfg(target_os = "macos")]
fn cleanup_recovered_sandbox(
    private_root: &Path,
    identity: &RecoverySandboxIdentity,
    outcome: RecoveryOutcome,
) -> Result<RecoveryCleanup, BoundaryError> {
    use context_relay_native_runner::macos::{
        GenerationState, MacRecoveryCleanup, MacRecoveryIdentity, MacRecoveryOutcome,
        MacRootIdentity, cleanup_recovered_generation,
    };

    if is_nonlaunching_recovery_identity(identity) {
        return Ok(RecoveryCleanup::Cleaned);
    }

    let RecoverySandboxIdentity::Macos {
        generation_id,
        bundle_id,
        guardian_pgid,
        bundle_root,
        container_root,
        state,
        ..
    } = identity
    else {
        return Err(BoundaryError::new(
            "sandbox identity does not match the current platform",
        ));
    };
    let state = match state {
        MacGenerationState::Prepared => GenerationState::Prepared,
        MacGenerationState::Active => GenerationState::Active,
        MacGenerationState::Retired => GenerationState::Retired,
        MacGenerationState::Poisoned => GenerationState::Poisoned,
    };
    let outcome = match outcome {
        RecoveryOutcome::Committed => MacRecoveryOutcome::Committed,
        RecoveryOutcome::Restored => MacRecoveryOutcome::Restored,
        RecoveryOutcome::Conflict => MacRecoveryOutcome::Conflict,
    };
    let bundle_identity = bundle_root
        .as_deref()
        .map(MacRootIdentity::decode)
        .transpose()
        .map_err(|error| BoundaryError::new(error.to_string()))?;
    let container_identity = container_root
        .as_deref()
        .map(MacRootIdentity::decode)
        .transpose()
        .map_err(|error| BoundaryError::new(error.to_string()))?;
    cleanup_recovered_generation(
        private_root,
        &MacRecoveryIdentity::new(
            generation_id,
            bundle_id,
            *guardian_pgid,
            bundle_identity.as_ref(),
            container_identity.as_ref(),
        ),
        state,
        outcome,
    )
    .map(|cleanup| match cleanup {
        MacRecoveryCleanup::Cleaned => RecoveryCleanup::Cleaned,
        MacRecoveryCleanup::Conflict => RecoveryCleanup::Conflict,
    })
    .map_err(|error| BoundaryError::new(error.to_string()))
}

#[cfg(not(any(windows, target_os = "macos")))]
fn cleanup_recovered_sandbox(
    _private_root: &Path,
    identity: &RecoverySandboxIdentity,
    _outcome: RecoveryOutcome,
) -> Result<RecoveryCleanup, BoundaryError> {
    if is_nonlaunching_recovery_identity(identity) {
        return Ok(RecoveryCleanup::Cleaned);
    }
    Err(BoundaryError::new(
        "native recovery is unavailable on this platform",
    ))
}

#[cfg(windows)]
fn is_nonlaunching_recovery_identity(identity: &RecoverySandboxIdentity) -> bool {
    matches!(
        identity,
        RecoverySandboxIdentity::Windows { moniker, sid }
            if moniker == bridge_install::NON_LAUNCHING_WINDOWS_MONIKER
                && sid == bridge_install::NON_LAUNCHING_WINDOWS_SID
    )
}

#[cfg(not(windows))]
fn is_nonlaunching_recovery_identity(identity: &RecoverySandboxIdentity) -> bool {
    let RecoverySandboxIdentity::Macos {
        generation_id,
        bundle_id,
        container,
        guardian_pgid,
        bundle_root,
        signed_digest,
        container_root,
        substate,
        state,
    } = identity
    else {
        return false;
    };
    let expected_bundle = format!(
        "com.contextrelay.native-runner.{}",
        bridge_install::NON_LAUNCHING_GENERATION_ID
    );
    let mut expected_container = b"context-relay/macos-container/v1\0".to_vec();
    expected_container.extend_from_slice(expected_bundle.as_bytes());
    generation_id == bridge_install::NON_LAUNCHING_GENERATION_ID
        && bundle_id == &expected_bundle
        && container == &expected_container
        && guardian_pgid.is_none()
        && bundle_root.is_none()
        && signed_digest.is_none()
        && container_root.is_none()
        && *substate == MacGenerationSubstate::Reserved
        && *state == MacGenerationState::Poisoned
}

pub struct DaemonConfig {
    // None selects build configuration after the instance guard is acquired.
    hosted_auth: Option<hosted_auth::HostedAuthService>,
    runtime: RuntimeConfig,
    vault: VaultConfig,
    token_provider: Arc<dyn InstallationTokenProvider>,
}

impl DaemonConfig {
    fn new(
        runtime: RuntimeConfig,
        vault: VaultConfig,
        token_provider: Arc<dyn InstallationTokenProvider>,
    ) -> Self {
        Self {
            hosted_auth: Some(hosted_auth::HostedAuthService::disabled()),
            runtime,
            vault,
            token_provider,
        }
    }

    pub fn production() -> Result<Self, DaemonError> {
        let root = dirs::data_local_dir()
            .ok_or(DaemonError::Startup)?
            .join("Context Relay");
        let vault = VaultConfig::new(
            root.join("vault-v1.db"),
            VAULT_CREDENTIAL_ID,
            Arc::new(PlatformKeyStore::default()),
        );
        #[cfg(windows)]
        let vault = {
            let mut vault = vault;
            let executable = std::env::current_exe().map_err(|_| DaemonError::Startup)?;
            vault.search_resources = Some(search_index::resources_beside_executable(&executable)?);
            vault
        };
        let mut config = Self::new(
            RuntimeConfig::production(),
            vault,
            Arc::new(PlatformInstallationTokenProvider),
        );
        config.hosted_auth = None;
        Ok(config)
    }

    pub fn with_hosted_auth(mut self, service: hosted_auth::HostedAuthService) -> Self {
        self.hosted_auth = Some(service);
        self
    }

    #[cfg(test)]
    fn with_worker_hook(mut self, worker_hook: Arc<dyn WorkerHook>) -> Self {
        self.vault = self.vault.with_worker_hook(worker_hook);
        self
    }

    #[cfg(test)]
    fn with_startup_recovery(mut self, startup_recovery: StartupRecovery) -> Self {
        self.vault = self.vault.with_startup_recovery(startup_recovery);
        self
    }
}

pub struct Daemon {
    hosted_auth: hosted_auth::HostedAuthService,
    preparation: PreparationSupervisor,
    instance: Option<InstanceGuard>,
    listener: Option<Listener>,
    worker: VaultWorker,
    native_memory: NativeMemorySupervisor,
    token: Arc<InstallationToken>,
    instance_nonce: DaemonInstanceNonce,
    shutdown_sender: watch::Sender<bool>,
    shutdown_receiver: Option<watch::Receiver<bool>>,
    state_sender: watch::Sender<DaemonState>,
    state_receiver: watch::Receiver<DaemonState>,
}

impl Daemon {
    pub async fn start(config: DaemonConfig) -> Result<Self, DaemonError> {
        let mut instance = InstanceGuard::acquire(&config.runtime).map_err(map_guard_error)?;
        let production_hosted = config.hosted_auth.is_none();
        let hosted_auth = match config.hosted_auth {
            Some(service) => service,
            None => hosted_auth::HostedAuthService::production()
                .await
                .map_err(|_| DaemonError::Startup)?,
        };
        let token = Arc::new(config.token_provider.load_or_create()?);
        let mut vault_config = config
            .vault
            .with_device_id(stable_device_id(token.as_bytes()));
        if production_hosted
            && let (Some(owner), Some(project), Some(key)) = (
                hosted_auth.session_owner(),
                option_env!("CONTEXT_RELAY_HOSTED_URL"),
                option_env!("CONTEXT_RELAY_HOSTED_PUBLISHABLE_KEY"),
            )
        {
            let keys = Arc::new(
                load_or_create_device_keys(
                    vault_config.device_identity_store.as_ref(),
                    &vault_config.device_identity_credential_id,
                )
                .map_err(|_| DaemonError::Startup)?,
            );
            vault_config.device_keys = Some(keys.clone());
            let identity = PairingIdentity {
                device_id: vault_config.device_id,
                device_name: vault_config.device_name.clone(),
                platform: vault_config.platform,
                keys,
            };
            vault_config.pairing_service = Some(Arc::new(pairing::HostedPairingService::new(
                owner.clone(),
                project,
                key,
                identity.clone(),
            )));
            vault_config.recovery_enrollment_service = Some(Arc::new(
                recovery_enrollment::HostedRecoveryEnrollmentService::new(
                    owner, project, key, identity,
                ),
            ));
        }
        let mut vault_config = vault_config.load_device_identity()?;
        let preparation = PreparationSupervisor::spawn().map_err(|_| DaemonError::Startup)?;
        vault_config.preparation = Some(preparation.client());
        let native_memory_probe = vault_config.native_memory_probe.clone();
        let instance_nonce = generate_instance_nonce().map_err(|_| DaemonError::Startup)?;
        let (native_memory_updates, native_memory_update_receiver) = native_memory_update_channel();
        let mut worker = VaultWorker::spawn(
            vault_config
                .with_native_memory_updates(native_memory_updates)
                .with_device_id(stable_device_id(token.as_bytes())),
        )
        .await?;
        let native_memory_ledgers = worker.take_native_memory_ledgers();
        let listener =
            Listener::bind(&config.runtime, &mut instance).map_err(map_transport_error)?;
        let native_memory = NativeMemorySupervisor::spawn(
            worker.client(),
            native_memory_ledgers,
            native_memory_update_receiver,
            native_memory_probe,
        )
        .map_err(|_| DaemonError::Startup)?;
        let (shutdown_sender, shutdown_receiver) = watch::channel(false);
        let (state_sender, state_receiver) = watch::channel(DaemonState::Running);
        Ok(Self {
            hosted_auth,
            instance: Some(instance),
            preparation,
            listener: Some(listener),
            worker,
            native_memory,
            token,
            instance_nonce,
            shutdown_sender,
            shutdown_receiver: Some(shutdown_receiver),
            state_sender,
            state_receiver,
        })
    }

    pub fn handle(&self) -> DaemonHandle {
        DaemonHandle {
            shutdown: self.shutdown_sender.clone(),
            state: self.state_receiver.clone(),
        }
    }

    pub async fn run(mut self) -> Result<(), DaemonError> {
        let mut listener = self.listener.take().ok_or(DaemonError::Transport)?;
        let mut shutdown = self
            .shutdown_receiver
            .take()
            .ok_or(DaemonError::Transport)?;
        let mut worker_exit = self.worker.take_exit();
        let service = ConnectionService {
            hosted_auth: self.hosted_auth.clone(),
            execution: harness_execution::ExecutionClient::default(),
            preparation: self.preparation.client(),
            token: self.token.clone(),
            instance_nonce: self.instance_nonce,
            registry: RequestRegistry::default(),
            worker: self.worker.client(),
            shutdown: self.shutdown_sender.clone(),
        };
        let permits = Arc::new(Semaphore::new(CONNECTION_LIMIT));
        let mut connections = JoinSet::new();
        let mut terminal_error = None;

        loop {
            tokio::select! {
                biased;
                _ = &mut worker_exit => break,
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                accepted = listener.accept() => {
                    match accepted {
                        Ok(stream) => match permits.clone().try_acquire_owned() {
                            Ok(permit) => {
                                connections.spawn(serve_connection(stream, permit, service.clone()));
                            }
                            Err(_) => drop(stream),
                        },
                        Err(_) => {
                            terminal_error = Some(DaemonError::Transport);
                            break;
                        }
                    }
                }
                _ = connections.join_next(), if !connections.is_empty() => {}
            }
        }

        self.worker.close_admission();
        self.hosted_auth.shutdown().await;
        self.preparation.client().close();
        self.state_sender.send_replace(DaemonState::Draining);
        self.shutdown_sender.send_replace(true);
        while connections.join_next().await.is_some() {}
        self.native_memory.shutdown_and_join_async().await;
        self.worker.shutdown_and_join_async().await;
        self.preparation.shutdown_and_join_async().await;
        drop(listener);
        self.instance.take();
        self.state_sender.send_replace(DaemonState::Stopped);

        match terminal_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

#[derive(Clone)]
struct ConnectionService {
    hosted_auth: hosted_auth::HostedAuthService,
    execution: harness_execution::ExecutionClient,
    preparation: PreparationClient,
    token: Arc<InstallationToken>,
    instance_nonce: DaemonInstanceNonce,
    registry: RequestRegistry,
    worker: WorkerClient,
    shutdown: watch::Sender<bool>,
}

async fn serve_connection(
    stream: ConnectedStream,
    _permit: OwnedSemaphorePermit,
    service: ConnectionService,
) {
    let mut shutdown = service.shutdown.subscribe();
    if *shutdown.borrow() {
        return;
    }
    let accepted = tokio::select! {
        biased;
        _ = shutdown.changed() => return,
        result = AuthenticatedConnection::accept(
            stream,
            service.token.as_ref(),
            service.instance_nonce,
            service.registry.clone(),
        ) => result,
    };
    let Ok(mut connection) = accepted else {
        return;
    };

    loop {
        if *shutdown.borrow() {
            return;
        }
        let next = tokio::select! {
            biased;
            _ = shutdown.changed() => return,
            result = connection.next_request() => result,
        };
        let Ok(request) = next else {
            return;
        };
        match serve_request(&mut connection, &service, request).await {
            Ok(true) => {}
            Ok(false) | Err(_) => return,
        }
    }
}

async fn serve_request(
    connection: &mut AuthenticatedConnection,
    service: &ConnectionService,
    request: AuthenticatedRequest,
) -> Result<bool, IpcError> {
    let AuthenticatedRequest {
        id,
        role,
        request,
        registration,
    } = request;
    if *service.shutdown.borrow() {
        connection.respond(id, Err(busy_error())).await?;
        return Ok(false);
    }

    match route_request(role, request) {
        RoutedRequest::HostedAuth(request) => {
            let result = match begin_immediate(&registration) {
                Ok(()) => service.hosted_auth.handle(request).await,
                Err(error) => Err(error),
            };
            connection.respond(id, result).await?;
            Ok(true)
        }
        RoutedRequest::ExecutionCurrent => {
            let result =
                begin_immediate(&registration).map(|()| LocalResult::HarnessExecutionCurrent {
                    status: service.execution.current(),
                });
            connection.respond(id, result).await?;
            Ok(true)
        }
        RoutedRequest::ExecutionStart(params) => {
            let result = begin_immediate(&registration)
                .and_then(|()| service.execution.start(&service.worker, params))
                .map(|status| LocalResult::HarnessExecution { status });
            connection.respond(id, result).await?;
            Ok(true)
        }
        RoutedRequest::ExecutionStatus(params) => {
            let result = begin_immediate(&registration).map(|()| LocalResult::HarnessExecution {
                status: service.execution.status(&params),
            });
            connection.respond(id, result).await?;
            Ok(true)
        }
        RoutedRequest::PreparationStatus(params) => {
            let result = begin_immediate(&registration)
                .and_then(|()| service.preparation.status(params.operation_id))
                .map(|status| LocalResult::HarnessPreparation { status });
            connection.respond(id, result).await?;
            Ok(true)
        }
        RoutedRequest::PreparationCancel(params) => {
            let result = begin_immediate(&registration)
                .and_then(|()| service.preparation.cancel(params.operation_id))
                .map(|status| LocalResult::HarnessPreparation { status });
            connection.respond(id, result).await?;
            Ok(true)
        }
        RoutedRequest::Immediate(result) => {
            let result = begin_immediate(&registration).and(result);
            connection.respond(id, result).await?;
            Ok(true)
        }
        RoutedRequest::Health => {
            let result = begin_immediate(&registration).and_then(|()| {
                if service.worker.is_alive() {
                    let status = service.worker.status();
                    Ok(LocalResult::Health {
                        protocol: PROTOCOL_VERSION,
                        vault_locked: status.vault == VaultState::Locked,
                    })
                } else {
                    Err(service_internal_error())
                }
            });
            connection.respond(id, result).await?;
            Ok(true)
        }
        RoutedRequest::SearchIndexStatus => {
            let result = begin_immediate(&registration).and_then(|()| {
                if !service.worker.is_alive() {
                    return Err(service_internal_error());
                }
                let snapshot = service.worker.status();
                if snapshot.vault == VaultState::Locked {
                    return Err(ClientError::vault_locked());
                }
                Ok(LocalResult::SearchIndex {
                    status: snapshot.search,
                })
            });
            connection.respond(id, result).await?;
            Ok(true)
        }
        RoutedRequest::Shutdown => {
            let result = begin_immediate(&registration).map(|()| LocalResult::Empty);
            let accepted = result.is_ok();
            connection.respond(id, result).await?;
            if accepted {
                service.shutdown.send_replace(true);
                Ok(false)
            } else {
                Ok(true)
            }
        }
        RoutedRequest::Work(command) => {
            let result = match service.worker.try_submit(command, registration) {
                Ok(response) => match timeout(WORK_RESPONSE_TIMEOUT, response).await {
                    Ok(Ok(result)) => result,
                    Ok(Err(_)) => Err(service_internal_error()),
                    Err(_) => Err(work_timeout_error()),
                },
                Err(error) => Err(error),
            };
            connection.respond(id, result).await?;
            Ok(true)
        }
    }
}

fn begin_immediate(registration: &RequestRegistration) -> Result<(), ClientError> {
    if registration.begin() {
        Ok(())
    } else {
        Err(canceled_error())
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.hosted_auth.close();
        self.listener.take();
        self.preparation.client().close();
        self.native_memory.shutdown_and_join();
        self.worker.shutdown_and_join();
        self.preparation.shutdown_and_join();
        self.instance.take();
        self.state_sender.send_replace(DaemonState::Stopped);
    }
}

#[derive(Debug)]
enum RoutedRequest {
    HostedAuth(LocalRequest),
    SearchIndexStatus,
    ExecutionCurrent,
    ExecutionStart(context_relay_protocol::HarnessExecutionParams),
    ExecutionStatus(context_relay_protocol::HarnessExecutionParams),
    PreparationStatus(context_relay_protocol::HarnessPreparationIdParams),
    PreparationCancel(context_relay_protocol::HarnessPreparationIdParams),
    Immediate(Result<LocalResult, ClientError>),
    Health,
    Shutdown,
    Work(VaultCommand),
}

#[derive(Debug)]
enum VaultCommand {
    SearchIndexRetry,
    Unlock,
    ProjectPathSet(ProjectPathParams),
    MemoryGet(MemoryParams),
    Workspace(LocalRequest),
    DesktopMcp(context_relay_protocol::McpCallParams),
    Pairing(LocalRequest),
    Recovery(LocalRequest),
    HarnessSetup(LocalRequest),
    NativeMemoryObservation(context_relay_core::native_memory::ReadyNativeMemory),
    #[cfg(test)]
    TestBlock {
        entered: std::sync::mpsc::SyncSender<()>,
        release: std::sync::mpsc::Receiver<()>,
    },
}

fn route_request(role: ClientRole, request: LocalRequest) -> RoutedRequest {
    if matches!(
        &request,
        LocalRequest::HostedAuthStatus(_)
            | LocalRequest::HostedAuthStart(_)
            | LocalRequest::HostedAuthCancel(_)
            | LocalRequest::HostedAuthLogout(_)
            | LocalRequest::HarnessLaunchInfo(_)
            | LocalRequest::ConnectionCheckStart(_)
            | LocalRequest::ConnectionCheckStatus(_)
            | LocalRequest::ConnectionCheckCancel(_)
            | LocalRequest::HarnessPrepare(_)
            | LocalRequest::SearchIndexStatus(_)
            | LocalRequest::SearchIndexRetry(_)
            | LocalRequest::HarnessExecutionStart(_)
            | LocalRequest::HarnessExecutionStatus(_)
            | LocalRequest::HarnessExecutionCurrent(_)
            | LocalRequest::HarnessSetupGet(_)
            | LocalRequest::HarnessSetupsList(_)
            | LocalRequest::HarnessPreparedPreview(_)
            | LocalRequest::HarnessPreparationStatus(_)
            | LocalRequest::HarnessPreparationCancel(_)
    ) && !role_allows(role, &request)
    {
        return RoutedRequest::Immediate(Err(scope_denied_error()));
    }
    if matches!(
        &request,
        LocalRequest::RecoveryEnrollmentBegin(_)
            | LocalRequest::RecoveryRestoreBegin(_)
            | LocalRequest::RecoveryRestoreOverview(_)
            | LocalRequest::RecoveryRestoreResume(_)
            | LocalRequest::RecoveryRestoreCancel(_)
            | LocalRequest::RecoveryEnrollmentOverview(_)
            | LocalRequest::RecoveryEnrollmentConfirm(_)
            | LocalRequest::RecoveryEnrollmentStatus(_)
            | LocalRequest::RecoveryEnrollmentCancel(_)
    ) && !role_allows(role, &request)
    {
        return RoutedRequest::Immediate(Err(scope_denied_error()));
    }
    match request {
        request @ (LocalRequest::HostedAuthStatus(_)
        | LocalRequest::HostedAuthStart(_)
        | LocalRequest::HostedAuthCancel(_)
        | LocalRequest::HostedAuthLogout(_)) => RoutedRequest::HostedAuth(request),
        LocalRequest::McpCall(params) if role != ClientRole::McpBridge => {
            RoutedRequest::Work(VaultCommand::DesktopMcp(params))
        }
        LocalRequest::SearchIndexStatus(_) => RoutedRequest::SearchIndexStatus,
        LocalRequest::SearchIndexRetry(_) => RoutedRequest::Work(VaultCommand::SearchIndexRetry),
        LocalRequest::HarnessExecutionCurrent(_) => RoutedRequest::ExecutionCurrent,
        LocalRequest::HarnessExecutionStart(params) => RoutedRequest::ExecutionStart(params),
        LocalRequest::HarnessExecutionStatus(params) => RoutedRequest::ExecutionStatus(params),
        LocalRequest::HarnessPreparationStatus(params) => RoutedRequest::PreparationStatus(params),
        LocalRequest::HarnessPreparationCancel(params) => RoutedRequest::PreparationCancel(params),
        LocalRequest::Hello(_) => RoutedRequest::Immediate(Err(invalid_request_error())),
        LocalRequest::Cancel(_) => RoutedRequest::Immediate(Err(invalid_request_error())),
        LocalRequest::Shutdown(_) => RoutedRequest::Shutdown,
        LocalRequest::Health(_) => RoutedRequest::Health,
        LocalRequest::Unlock(_) => RoutedRequest::Work(VaultCommand::Unlock),
        LocalRequest::ProjectPathSet(params) => {
            RoutedRequest::Work(VaultCommand::ProjectPathSet(params))
        }
        request @ (LocalRequest::HarnessLaunchInfo(_)
        | LocalRequest::ConnectionCheckStart(_)
        | LocalRequest::ConnectionCheckStatus(_)
        | LocalRequest::ConnectionCheckCancel(_)) => {
            RoutedRequest::Work(VaultCommand::Workspace(request))
        }
        LocalRequest::MemoryGet(params) => RoutedRequest::Work(VaultCommand::MemoryGet(params)),
        request @ (LocalRequest::McpCall(_)
        | LocalRequest::NativeHookEvent(_)
        | LocalRequest::DesktopWritePrepare(_)
        | LocalRequest::DesktopWritesList(_)
        | LocalRequest::DesktopWriteGet(_)
        | LocalRequest::DesktopWriteForget(_)
        | LocalRequest::ProjectsList(_)
        | LocalRequest::ProjectUpsert(_)
        | LocalRequest::ProjectRegister(_)
        | LocalRequest::MemoryList(_)
        | LocalRequest::MemorySearch(_)
        | LocalRequest::MemoryCreate(_)
        | LocalRequest::MemoryUpdate(_)
        | LocalRequest::MemoryArchive(_)
        | LocalRequest::CandidatesList(_)
        | LocalRequest::CandidateReview(_)
        | LocalRequest::TasksList(_)
        | LocalRequest::TaskUpsert(_)
        | LocalRequest::TaskComplete(_)
        | LocalRequest::TaskTransition(_)
        | LocalRequest::HandoffCreate(_)
        | LocalRequest::AccessGet(_)
        | LocalRequest::AccessSet(_)
        | LocalRequest::SyncStatus(_)
        | LocalRequest::DevicesList(_)
        | LocalRequest::ExportRecords(_)
        | LocalRequest::ExportChunk(_)
        | LocalRequest::AccountDeletionBegin(_)
        | LocalRequest::AccountDeletionStatus(_)
        | LocalRequest::AccountDeletionCancel(_)) => {
            RoutedRequest::Work(VaultCommand::Workspace(request))
        }
        request @ (LocalRequest::HarnessProbe(_)
        | LocalRequest::HarnessSetupGet(_)
        | LocalRequest::HarnessSetupsList(_)
        | LocalRequest::HarnessPrepare(_)
        | LocalRequest::HarnessPreparedPreview(_)
        | LocalRequest::HarnessPreview(_)
        | LocalRequest::HarnessApply(_)
        | LocalRequest::HarnessRollback(_)) => {
            RoutedRequest::Work(VaultCommand::HarnessSetup(request))
        }
        LocalRequest::HarnessRepair(_)
        | LocalRequest::PackageImport(_)
        | LocalRequest::PackageExport(_) => RoutedRequest::Immediate(Err(unsupported_error(
            "The requested local adapter operation is not supported",
        ))),
        request @ (LocalRequest::PairingCreate(_)
        | LocalRequest::PairingJoin(_)
        | LocalRequest::PairingStatus(_)
        | LocalRequest::PairingDecision(_)
        | LocalRequest::PairingConfirm(_)
        | LocalRequest::PairingCancel(_)) => RoutedRequest::Work(VaultCommand::Pairing(request)),
        request @ (LocalRequest::RecoveryEnrollmentBegin(_)
        | LocalRequest::RecoveryRestoreBegin(_)
        | LocalRequest::RecoveryRestoreOverview(_)
        | LocalRequest::RecoveryRestoreResume(_)
        | LocalRequest::RecoveryRestoreCancel(_)
        | LocalRequest::RecoveryEnrollmentOverview(_)
        | LocalRequest::RecoveryEnrollmentConfirm(_)
        | LocalRequest::RecoveryEnrollmentStatus(_)
        | LocalRequest::RecoveryEnrollmentCancel(_)) => {
            RoutedRequest::Work(VaultCommand::Recovery(request))
        }
        LocalRequest::SyncRetry(_)
        | LocalRequest::DeviceRename(_)
        | LocalRequest::DeviceRevoke(_) => RoutedRequest::Immediate(Err(unsupported_error(
            "Hosted workspace configuration is not available",
        ))),
    }
}

fn invalid_request_error() -> ClientError {
    ClientError {
        code: ErrorCode::InvalidRequest,
        message: "Invalid request".into(),
        field_path: None,
        retryable: false,
    }
}

fn unavailable_error() -> ClientError {
    ClientError {
        code: ErrorCode::HarnessUnsupported,
        message: "Pairing needs the hosted device service and is not available in this build."
            .into(),
        field_path: None,
        retryable: false,
    }
}

fn scope_denied_error() -> ClientError {
    ClientError {
        code: ErrorCode::ScopeDenied,
        message: "This client is not authorized for this request".into(),
        field_path: None,
        retryable: false,
    }
}

fn unsupported_error(message: &str) -> ClientError {
    ClientError {
        code: ErrorCode::HarnessUnsupported,
        message: message.into(),
        field_path: None,
        retryable: false,
    }
}

fn busy_error() -> ClientError {
    ClientError {
        code: ErrorCode::Busy,
        message: "The local service is busy".into(),
        field_path: None,
        retryable: true,
    }
}

fn canceled_error() -> ClientError {
    ClientError {
        code: ErrorCode::Canceled,
        message: "The request was canceled".into(),
        field_path: None,
        retryable: false,
    }
}

fn service_internal_error() -> ClientError {
    ClientError {
        code: ErrorCode::Internal,
        message: "The local service is temporarily unavailable".into(),
        field_path: None,
        retryable: true,
    }
}

fn work_timeout_error() -> ClientError {
    ClientError {
        code: ErrorCode::Timeout,
        message: "The request timed out".into(),
        field_path: None,
        retryable: true,
    }
}

trait WorkAdmission: Send {
    fn begin(&self) -> bool;
    fn finished(&self, _result: &Result<LocalResult, ClientError>) {}
}

impl WorkAdmission for RequestRegistration {
    fn begin(&self) -> bool {
        RequestRegistration::begin(self)
    }
}

struct WorkItem {
    command: VaultCommand,
    admission: Box<dyn WorkAdmission>,
    response: oneshot::Sender<Result<LocalResult, ClientError>>,
}

#[derive(Clone)]
struct WorkerClient {
    sender: mpsc::WeakSender<WorkItem>,
    admission: Arc<Mutex<bool>>,
    worker_hook: Option<Arc<dyn WorkerHook>>,
    status: Arc<ServiceStatus>,
}

impl WorkerClient {
    fn is_alive(&self) -> bool {
        self.sender
            .upgrade()
            .is_some_and(|sender| !sender.is_closed())
    }

    fn status(&self) -> ServiceStatusSnapshot {
        self.status.snapshot()
    }

    fn try_submit(
        &self,
        command: VaultCommand,
        admission: impl WorkAdmission + 'static,
    ) -> Result<oneshot::Receiver<Result<LocalResult, ClientError>>, ClientError> {
        let admission_gate = self
            .admission
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let Some(sender) = self.sender.upgrade() else {
            return Err(service_internal_error());
        };
        if sender.is_closed() {
            return Err(service_internal_error());
        }
        if !*admission_gate {
            return Err(busy_error());
        }
        let (response, receiver) = oneshot::channel();
        let item = WorkItem {
            command,
            admission: Box::new(admission),
            response,
        };
        let submitted = sender.try_send(item);
        drop(admission_gate);
        match submitted {
            Ok(()) => {
                if let Some(worker_hook) = &self.worker_hook {
                    worker_hook.after_enqueue();
                }
                Ok(receiver)
            }
            Err(mpsc::error::TrySendError::Full(_)) => Err(busy_error()),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(service_internal_error()),
        }
    }
}

struct VaultWorker {
    sender: Option<mpsc::Sender<WorkItem>>,
    thread: Option<JoinHandle<()>>,
    exit: Option<oneshot::Receiver<()>>,
    admission: Arc<Mutex<bool>>,
    worker_hook: Option<Arc<dyn WorkerHook>>,
    native_memory_ledgers: Option<Vec<context_relay_core::native_memory::NativeMemoryLedger>>,
    status: Arc<ServiceStatus>,
}

#[derive(Clone, Copy)]
struct ServiceStatusSnapshot {
    vault: VaultState,
    sync: SyncState,
    search: context_relay_protocol::SearchIndexStatus,
}

struct ServiceStatus(Mutex<ServiceStatusSnapshot>);

impl ServiceStatus {
    fn new() -> Self {
        Self(Mutex::new(ServiceStatusSnapshot {
            vault: VaultState::Unlocked,
            sync: SyncState::Offline,
            search: search_index::SearchIndexJob::new(false).status,
        }))
    }

    fn snapshot(&self) -> ServiceStatusSnapshot {
        *self.0.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn set_vault(&self, vault: VaultState) {
        self.0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .vault = vault;
    }

    fn set_search(&self, search: context_relay_protocol::SearchIndexStatus) {
        self.0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .search = search;
    }
}

struct StoredExport {
    chunks: Vec<Vec<u8>>,
    total_bytes: u64,
    record_count: u32,
}

struct WorkspaceState {
    connection_check: Option<connection_check::ConnectionCheck>,
    search_index: search_index::SearchIndexJob,
    preparation: Option<PreparationClient>,
    vault: Vault,
    vault_path: PathBuf,
    device_id: DeviceId,
    exports: BTreeMap<ExportId, StoredExport>,
    bridge_install: Arc<dyn BridgeInstallEngine>,
    native_memory_updates: Option<NativeMemoryUpdateSender>,
    pairing_service: Option<Arc<dyn PairingService>>,
    recovery_enrollment_service: Option<Arc<dyn RecoveryEnrollmentService>>,
    account_lifecycle_service: Arc<dyn AccountLifecycleService>,
    pairing_identity: Option<PairingIdentity>,
}

enum VaultWorkerState {
    Locked(VaultConfig),
    Open(WorkspaceState),
}

enum WorkspaceOpenError {
    Locked,
    Fatal(DaemonError),
}

fn open_workspace(
    config: &mut VaultConfig,
) -> Result<
    (
        WorkspaceState,
        Vec<context_relay_core::native_memory::NativeMemoryLedger>,
    ),
    WorkspaceOpenError,
> {
    let parent = config
        .path
        .parent()
        .ok_or(WorkspaceOpenError::Fatal(DaemonError::Startup))?;
    std::fs::create_dir_all(parent).map_err(|_| WorkspaceOpenError::Fatal(DaemonError::Startup))?;
    let mut vault = match Vault::open(
        &config.path,
        &config.credential_id,
        config.key_store.as_ref(),
    ) {
        Ok(vault) => vault,
        Err(VaultError::MissingKey | VaultError::WrongKey | VaultError::Credential(_)) => {
            return Err(WorkspaceOpenError::Locked);
        }
        Err(_) => return Err(WorkspaceOpenError::Fatal(DaemonError::Startup)),
    };

    #[cfg(test)]
    if let Some(recovery) = &config.startup_recovery {
        recovery(&mut vault).map_err(WorkspaceOpenError::Fatal)?;
    } else {
        recover_startup_native_transactions(&mut vault, &config.path, config.device_id)
            .map_err(WorkspaceOpenError::Fatal)?;
    }
    #[cfg(not(test))]
    recover_startup_native_transactions(&mut vault, &config.path, config.device_id)
        .map_err(WorkspaceOpenError::Fatal)?;

    config
        .bridge_install
        .reconcile_after_native_recovery(&mut vault, &config.path, config.device_id)
        .map_err(|_| WorkspaceOpenError::Fatal(DaemonError::Startup))?;
    let ledgers = vault
        .native_memory_ledgers()
        .map_err(|_| WorkspaceOpenError::Fatal(DaemonError::Startup))?;
    let pairing_identity =
        if config.pairing_service.is_some() || config.recovery_enrollment_service.is_some() {
            let keys = config
                .device_keys
                .as_ref()
                .ok_or(WorkspaceOpenError::Fatal(DaemonError::Startup))?;
            if let Some(service) = &config.recovery_enrollment_service {
                service
                    .resume_prepared(&mut vault, keys)
                    .map_err(|_| WorkspaceOpenError::Fatal(DaemonError::Startup))?;
            }
            if let Some(service) = &config.pairing_service {
                service
                    .resume_prepared_decisions(&mut vault)
                    .map_err(|_| WorkspaceOpenError::Fatal(DaemonError::Startup))?;
            }
            Some(PairingIdentity {
                device_id: config.device_id,
                device_name: config.device_name.clone(),
                platform: config.platform,
                keys: config
                    .device_keys
                    .take()
                    .expect("device keys remain available until recovery succeeds"),
            })
        } else {
            None
        };
    if config.search_resources.is_some() {
        vault.prepare_semantic_search();
    }
    Ok((
        WorkspaceState {
            connection_check: None,
            search_index: search_index::SearchIndexJob::new(vault.semantic_search_enabled())
                .with_resources(config.search_resources.clone()),
            preparation: config.preparation.clone(),
            vault,
            vault_path: config.path.clone(),
            device_id: config.device_id,
            exports: BTreeMap::new(),
            bridge_install: config.bridge_install.clone(),
            native_memory_updates: config.native_memory_updates.clone(),
            pairing_service: config.pairing_service.clone(),
            recovery_enrollment_service: config.recovery_enrollment_service.clone(),
            account_lifecycle_service: config.account_lifecycle_service.clone(),
            pairing_identity,
        },
        ledgers,
    ))
}

impl VaultWorker {
    async fn spawn(config: VaultConfig) -> Result<Self, DaemonError> {
        let mut config = config.load_device_identity()?;
        let (sender, mut receiver) = mpsc::channel::<WorkItem>(REQUEST_QUEUE_CAPACITY);
        let (ready_sender, ready_receiver) = oneshot::channel();
        let (exit_sender, exit_receiver) = oneshot::channel();
        let admission = Arc::new(Mutex::new(true));
        let thread_admission = admission.clone();
        let worker_hook = config.worker_hook.clone();
        let thread_worker_hook = worker_hook.clone();
        let status = Arc::new(ServiceStatus::new());
        let worker_status = status.clone();
        let thread = std::thread::Builder::new()
            .name("context-relay-vault".into())
            .spawn(move || {
                let (state, ledgers) = match open_workspace(&mut config) {
                    Ok((workspace, ledgers)) => {
                        worker_status.set_vault(VaultState::Unlocked);
                        worker_status.set_search(workspace.search_index.status);
                        (VaultWorkerState::Open(workspace), ledgers)
                    }
                    Err(WorkspaceOpenError::Locked) => {
                        worker_status.set_vault(VaultState::Locked);
                        (VaultWorkerState::Locked(config), Vec::new())
                    }
                    Err(WorkspaceOpenError::Fatal(error)) => {
                        let _ = ready_sender.send(Err(error));
                        let _ = exit_sender.send(());
                        return;
                    }
                };
                if ready_sender.send(Ok(ledgers)).is_err() {
                    return;
                }
                run_vault_worker(
                    state,
                    &mut receiver,
                    thread_worker_hook.as_deref(),
                    &worker_status,
                    &thread_admission,
                );
                let _ = exit_sender.send(());
            })
            .map_err(|_| DaemonError::Startup)?;
        let mut worker = Self {
            sender: Some(sender),
            thread: Some(thread),
            exit: Some(exit_receiver),
            admission,
            worker_hook,
            native_memory_ledgers: None,
            status,
        };
        match ready_receiver.await {
            Ok(Ok(ledgers)) => {
                worker.native_memory_ledgers = Some(ledgers);
                Ok(worker)
            }
            Ok(Err(error)) => {
                worker.shutdown_and_join();
                Err(error)
            }
            Err(_) => {
                worker.shutdown_and_join();
                Err(DaemonError::Startup)
            }
        }
    }

    fn client(&self) -> WorkerClient {
        WorkerClient {
            sender: self
                .sender
                .as_ref()
                .expect("worker sender is available while the worker is running")
                .downgrade(),
            admission: self.admission.clone(),
            worker_hook: self.worker_hook.clone(),
            status: self.status.clone(),
        }
    }

    fn take_native_memory_ledgers(
        &mut self,
    ) -> Vec<context_relay_core::native_memory::NativeMemoryLedger> {
        self.native_memory_ledgers.take().unwrap_or_default()
    }

    fn close_admission(&self) {
        *self
            .admission
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = false;
    }

    fn take_exit(&mut self) -> oneshot::Receiver<()> {
        self.exit
            .take()
            .expect("worker exit can only be observed once")
    }

    fn shutdown_and_join(&mut self) {
        self.close_admission();
        self.sender.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }

    async fn shutdown_and_join_async(&mut self) {
        self.close_admission();
        self.sender.take();
        if let Some(thread) = self.thread.take() {
            let _ = tokio::task::spawn_blocking(move || thread.join()).await;
        }
        self.exit.take();
    }
}

fn run_vault_worker(
    mut state: VaultWorkerState,
    receiver: &mut mpsc::Receiver<WorkItem>,
    worker_hook: Option<&dyn WorkerHook>,
    status: &ServiceStatus,
    admission_gate: &Mutex<bool>,
) {
    loop {
        let item = match receiver.try_recv() {
            Ok(item) => item,
            Err(mpsc::error::TryRecvError::Disconnected) => break,
            Err(mpsc::error::TryRecvError::Empty) => {
                #[cfg(test)]
                if let Some(worker_hook) = worker_hook {
                    worker_hook.before_index_admission();
                }
                // Admit one record at a time. Never hold the admission/status lock
                // during inference; control requests and shutdown remain available.
                let gate = admission_gate
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                // try_submit uses this same gate. Recheck while holding it so a
                // request that arrived after the first check wins this turn.
                match receiver.try_recv() {
                    Ok(item) => {
                        drop(gate);
                        item
                    }
                    Err(mpsc::error::TryRecvError::Disconnected) => break,
                    Err(mpsc::error::TryRecvError::Empty) => {
                        let admitted = *gate
                            && matches!(&state, VaultWorkerState::Open(workspace) if workspace.search_index.pending());
                        drop(gate);
                        if admitted && let VaultWorkerState::Open(workspace) = &mut state {
                            #[cfg(test)]
                            if let Some(worker_hook) = worker_hook {
                                worker_hook.before_index();
                            }
                            workspace.search_index.tick(&mut workspace.vault);
                            status.set_search(workspace.search_index.status);
                            continue;
                        }
                        let Some(item) = receiver.blocking_recv() else {
                            break;
                        };
                        item
                    }
                }
            }
        };
        let WorkItem {
            command,
            admission,
            response,
        } = item;
        let result = if admission.begin() {
            if let Some(worker_hook) = worker_hook {
                worker_hook.before_execute();
            }
            execute_vault_command(&mut state, command, status)
        } else {
            Err(canceled_error())
        };
        admission.finished(&result);
        let _ = response.send(result);
        drop(admission);
        // Writes from desktop, harnesses, and native reconciliation all maintain
        // the durable queue. Recheck it after requests without rescanning records.
        if let VaultWorkerState::Open(workspace) = &mut state {
            if workspace.vault.take_semantic_search_failure() {
                workspace.search_index.fail();
                status.set_search(workspace.search_index.status);
            } else {
                workspace.search_index.wake();
            }
        }
    }
}

fn execute_vault_command(
    state: &mut VaultWorkerState,
    command: VaultCommand,
    status: &ServiceStatus,
) -> Result<LocalResult, ClientError> {
    if matches!(&command, VaultCommand::Unlock) {
        let VaultWorkerState::Locked(config) = state else {
            return Ok(LocalResult::Empty);
        };
        let (workspace, ledgers) = match open_workspace(config) {
            Ok(opened) => opened,
            Err(WorkspaceOpenError::Locked) => return Err(ClientError::vault_locked()),
            Err(WorkspaceOpenError::Fatal(_)) => return Err(service_internal_error()),
        };
        if let Some(updates) = &workspace.native_memory_updates {
            updates.send_replace(ledgers);
        }
        status.set_search(workspace.search_index.status);
        *state = VaultWorkerState::Open(workspace);
        status.set_vault(VaultState::Unlocked);
        return Ok(LocalResult::Empty);
    }

    let VaultWorkerState::Open(state) = state else {
        return Err(ClientError::vault_locked());
    };
    match command {
        VaultCommand::SearchIndexRetry => {
            state.search_index.retry();
            status.set_search(state.search_index.status);
            Ok(LocalResult::SearchIndex {
                status: state.search_index.status,
            })
        }
        VaultCommand::Unlock => unreachable!("unlock is handled before open-state dispatch"),
        VaultCommand::ProjectPathSet(params) => state
            .vault
            .put_path(&params.project_id.to_string(), &params.path)
            .map(|()| LocalResult::Empty)
            .map_err(client_error_from_vault),
        VaultCommand::MemoryGet(params) => state
            .vault
            .memory(&params.memory_id)
            .map(|memory| LocalResult::Memory { memory })
            .map_err(client_error_from_vault),
        VaultCommand::DesktopMcp(params) => execute_mcp_request(state, params, status, false),
        VaultCommand::Workspace(request) => execute_workspace_request(state, request, status),
        VaultCommand::Pairing(request) => execute_pairing_request(state, request),
        VaultCommand::Recovery(request) => execute_recovery_enrollment_request(state, request),
        VaultCommand::HarnessSetup(request) => execute_harness_setup(state, request),
        VaultCommand::NativeMemoryObservation(ready) => {
            let registered = state
                .vault
                .native_memory_ledger(&ready.source.id)
                .map_err(client_error_from_vault)?
                .and_then(|ledger| ledger.source)
                .is_some_and(|source| source == ready.source);
            if !registered {
                return Ok(LocalResult::Empty);
            }
            OfflineWorkspace::new(&mut state.vault, state.device_id)
                .reconcile_native_memory(ready)
                .map(|_| LocalResult::Empty)
        }
        #[cfg(test)]
        VaultCommand::TestBlock { entered, release } => {
            entered.send(()).map_err(|_| service_internal_error())?;
            release.recv().map_err(|_| service_internal_error())?;
            Ok(LocalResult::Empty)
        }
    }
}

fn execute_pairing_request(
    state: &mut WorkspaceState,
    request: LocalRequest,
) -> Result<LocalResult, ClientError> {
    let (Some(service), Some(identity)) = (&state.pairing_service, &state.pairing_identity) else {
        return Err(unavailable_error());
    };
    service.execute(&mut state.vault, identity, request)
}

fn execute_recovery_enrollment_request(
    state: &mut WorkspaceState,
    request: LocalRequest,
) -> Result<LocalResult, ClientError> {
    let (Some(service), Some(identity)) =
        (&state.recovery_enrollment_service, &state.pairing_identity)
    else {
        return Err(recovery_enrollment::unavailable_error());
    };
    service.execute(&mut state.vault, &identity.keys, request)
}

fn execute_harness_setup(
    state: &mut WorkspaceState,
    request: LocalRequest,
) -> Result<LocalResult, ClientError> {
    match request {
        LocalRequest::HarnessSetupGet(params) => {
            context_relay_core::setup::harness_setup(&state.vault, &params.plan_id).map(|setup| {
                LocalResult::HarnessSetup {
                    setup: Box::new(setup),
                }
            })
        }
        LocalRequest::HarnessSetupsList(params) => {
            context_relay_core::setup::harness_setups(&state.vault, params.after.as_ref())
                .map(|page| LocalResult::HarnessSetups { page })
        }
        LocalRequest::HarnessPrepare(params) => {
            let client = state
                .preparation
                .as_ref()
                .ok_or_else(service_internal_error)?;
            if let Some(status) = client.replay(&params)? {
                return Ok(LocalResult::HarnessPreparation { status });
            }
            // A rejected factory is still a resolved attempt. Publish its exact
            // identity through the owned worker so reconnecting clients can
            // distinguish terminal failure from a start awaiting admission.
            // The preparation worker redacts the error and replay retains it.
            let task = state
                .bridge_install
                .prepare(
                    &state.vault,
                    &state.vault_path,
                    state.device_id,
                    params.selection.clone(),
                )
                .unwrap_or_else(|error| Box::new(move |_, _| Err(error)));
            client
                .start(params, task)
                .map(|status| LocalResult::HarnessPreparation { status })
        }
        LocalRequest::HarnessPreparedPreview(params) => {
            let client = state
                .preparation
                .as_ref()
                .ok_or_else(service_internal_error)?;
            client
                .preview(&params, |artifact| {
                    state.bridge_install.preview_prepared(
                        &mut state.vault,
                        &state.vault_path,
                        state.device_id,
                        params.selection.clone(),
                        artifact,
                    )
                })
                .map(|plan| LocalResult::Plan {
                    plan: Box::new(plan),
                })
        }
        LocalRequest::HarnessProbe(params) => state
            .bridge_install
            .probe(&state.vault, state.device_id, params)
            .map(|report| LocalResult::Probe { report }),
        LocalRequest::HarnessPreview(params) => state
            .bridge_install
            .preview(&mut state.vault, &state.vault_path, state.device_id, params)
            .map(|plan| LocalResult::Plan {
                plan: Box::new(plan),
            }),
        LocalRequest::HarnessApply(params) => {
            state.bridge_install.apply(
                &mut state.vault,
                &state.vault_path,
                state.device_id,
                params,
            )?;
            if let Some(updates) = &state.native_memory_updates {
                let ledgers = state
                    .vault
                    .native_memory_ledgers()
                    .map_err(client_error_from_vault)?;
                updates.send_replace(ledgers);
            }
            Ok(LocalResult::Empty)
        }
        LocalRequest::HarnessRollback(params) => {
            state.bridge_install.rollback(
                &mut state.vault,
                &state.vault_path,
                state.device_id,
                params,
            )?;
            if let Some(updates) = &state.native_memory_updates {
                let ledgers = state
                    .vault
                    .native_memory_ledgers()
                    .map_err(client_error_from_vault)?;
                updates.send_replace(ledgers);
            }
            Ok(LocalResult::Empty)
        }
        _ => Err(invalid_request_error()),
    }
}

fn connection_check_status(
    state: &mut WorkspaceState,
    id: context_relay_protocol::OperationId,
) -> Result<LocalResult, ClientError> {
    let check = state
        .connection_check
        .as_mut()
        .filter(|check| check.status.check_id == id)
        .ok_or_else(record_not_found_error)?;
    let memory = state
        .vault
        .memory(&check.status.memory_id)
        .map_err(client_error_from_vault)?;
    check.refresh(memory.as_ref());
    Ok(LocalResult::ConnectionCheck {
        status: check.status.clone(),
    })
}

fn execute_mcp_request(
    state: &mut WorkspaceState,
    params: context_relay_protocol::McpCallParams,
    service_status: &ServiceStatus,
    authenticated_bridge: bool,
) -> Result<LocalResult, ClientError> {
    let name = params.name.clone();
    let binding = params.binding.clone();
    let status = service_status.snapshot();
    let output = McpWorkspace::with_service_status(
        &mut state.vault,
        state.device_id,
        status.vault,
        status.sync,
    )
    .call(params)?;
    // Only the authenticated bridge route can reach this receipt boundary. All normal
    // MCP resolution, policy, record-scope, output validation and admission checks passed.
    if authenticated_bridge && name == "context_relay_get" && state.connection_check.is_some() {
        let resolved = context_relay_core::mcp::binding::resolve_binding(&state.vault, &binding)?;
        if let Ok(context_relay_protocol::GetOutput {
            record: Some(context_relay_protocol::ReadableRecord::Memory(memory)),
        }) = serde_json::from_value(output.clone())
            && let Some(check) = &mut state.connection_check
        {
            check.observe(
                resolved.harness,
                resolved.active_project.map(|project| project.project_id),
                &memory,
            );
        }
    }
    Ok(LocalResult::McpOutput { name, output })
}
fn execute_workspace_request(
    state: &mut WorkspaceState,
    request: LocalRequest,
    service_status: &ServiceStatus,
) -> Result<LocalResult, ClientError> {
    match request {
        LocalRequest::HarnessLaunchInfo(selection) => bridge_install::launch_info(
            state.bridge_install.as_ref(),
            &state.vault,
            state.device_id,
            selection,
        )
        .map(|info| LocalResult::HarnessLaunchInfo { info }),
        LocalRequest::ConnectionCheckStart(params) => {
            LocalRequest::ConnectionCheckStart(params.clone())
                .validate()
                .map_err(|_| invalid_request_error())?;
            let note = state
                .vault
                .memory(&params.memory_id)
                .map_err(client_error_from_vault)?
                .ok_or_else(record_not_found_error)?;
            if note.revision != params.expected_revision
                || note.archived
                || note.kind != MemoryKind::Note
                || !matches!(note.scope, context_relay_protocol::ScopeRef::Project {project_id} if Some(project_id) == params.selection.project_id)
            {
                return Err(invalid_request_error());
            }
            let check = connection_check::ConnectionCheck::start(params);
            let status = check.status.clone();
            state.connection_check = Some(check);
            Ok(LocalResult::ConnectionCheck { status })
        }
        LocalRequest::ConnectionCheckCancel(params) => {
            let check = state
                .connection_check
                .as_mut()
                .filter(|check| check.status.check_id == params.check_id)
                .ok_or_else(record_not_found_error)?;
            check.cancel();
            Ok(LocalResult::ConnectionCheck {
                status: check.status.clone(),
            })
        }
        LocalRequest::ConnectionCheckStatus(params) => {
            connection_check_status(state, params.check_id)
        }
        LocalRequest::McpCall(params) => execute_mcp_request(state, params, service_status, true),
        LocalRequest::NativeHookEvent(params) => {
            let resolved = context_relay_core::mcp::binding::resolve_hook_binding(
                &state.vault,
                &params.binding,
            )?;
            let Some(_) = resolved.active_project else {
                return Ok(LocalResult::Empty);
            };
            let task_write = matches!(
                params.event,
                context_relay_protocol::NativeHookEvent::TaskEvidence { .. }
            );
            let project_id = resolved.access.require_tasks(task_write)?;
            OfflineWorkspace::new(&mut state.vault, state.device_id)
                .handle_native_hook_event(project_id, params)
                .map(|()| LocalResult::Empty)
        }
        LocalRequest::DesktopWritePrepare(params) => state
            .vault
            .prepare_desktop_write(&params.write)
            .map(|()| LocalResult::Empty)
            .map_err(client_error_from_vault),
        LocalRequest::DesktopWritesList(params) => state
            .vault
            .desktop_writes(params.after)
            .map(|page| LocalResult::DesktopWrites { page })
            .map_err(client_error_from_vault),
        LocalRequest::DesktopWriteGet(params) => state
            .vault
            .desktop_write(params.operation_id)
            .map(|write| LocalResult::DesktopWrite { write })
            .map_err(client_error_from_vault),
        LocalRequest::DesktopWriteForget(params) => state
            .vault
            .forget_desktop_write(params.operation_id)
            .map(|()| LocalResult::Empty)
            .map_err(client_error_from_vault),
        LocalRequest::ProjectsList(_) => OfflineWorkspace::new(&mut state.vault, state.device_id)
            .projects()
            .map(|projects| LocalResult::Projects { projects }),
        LocalRequest::ProjectUpsert(params) => {
            OfflineWorkspace::new(&mut state.vault, state.device_id)
                .upsert_project(params.project)
                .map(|()| LocalResult::Empty)
        }
        LocalRequest::ProjectRegister(params) => {
            OfflineWorkspace::new(&mut state.vault, state.device_id)
                .register_project(params.project, params.path)
                .map(|()| LocalResult::Empty)
        }
        LocalRequest::MemorySearch(params) => {
            OfflineWorkspace::new(&mut state.vault, state.device_id)
                .search_memories(params)
                .map(|memories| LocalResult::Memories { memories })
        }
        LocalRequest::MemoryList(params) => state
            .vault
            .memories(params.project_id, params.include_archived)
            .map_err(client_error_from_vault)
            .map(|memories| LocalResult::Memories { memories }),
        LocalRequest::MemoryCreate(params) => {
            OfflineWorkspace::new(&mut state.vault, state.device_id)
                .create_memory(params)
                .map(|memory| LocalResult::Memory {
                    memory: Some(memory),
                })
        }
        LocalRequest::MemoryUpdate(params) => {
            OfflineWorkspace::new(&mut state.vault, state.device_id)
                .update_memory(params)
                .map(|memory| LocalResult::Memory {
                    memory: Some(memory),
                })
        }
        LocalRequest::MemoryArchive(params) => {
            OfflineWorkspace::new(&mut state.vault, state.device_id)
                .archive_memory(params)
                .map(|memory| LocalResult::Memory {
                    memory: Some(memory),
                })
        }
        LocalRequest::CandidatesList(params) => {
            OfflineWorkspace::new(&mut state.vault, state.device_id)
                .candidates(params.project_id)
                .map(|candidates| LocalResult::Candidates { candidates })
        }
        LocalRequest::CandidateReview(params) => {
            OfflineWorkspace::new(&mut state.vault, state.device_id)
                .review_candidate(params)
                .map(|candidate| LocalResult::Candidates {
                    candidates: vec![candidate],
                })
        }
        LocalRequest::TasksList(params) => OfflineWorkspace::new(&mut state.vault, state.device_id)
            .tasks(params.project_id)
            .map(|tasks| LocalResult::Tasks { tasks }),
        LocalRequest::TaskUpsert(params) => {
            OfflineWorkspace::new(&mut state.vault, state.device_id)
                .upsert_task(params)
                .map(|task| LocalResult::Tasks { tasks: vec![task] })
        }
        LocalRequest::TaskComplete(params) => {
            OfflineWorkspace::new(&mut state.vault, state.device_id)
                .complete_task(params)
                .map(|task| LocalResult::Tasks { tasks: vec![task] })
        }
        LocalRequest::TaskTransition(params) => {
            OfflineWorkspace::new(&mut state.vault, state.device_id)
                .transition_task(params)
                .map(|task| LocalResult::Tasks { tasks: vec![task] })
        }
        LocalRequest::HandoffCreate(params) => create_handoff(state, params),
        LocalRequest::AccessGet(params) => OfflineWorkspace::new(&mut state.vault, state.device_id)
            .access_policy(params.harness)
            .map(|policy| LocalResult::Access { policy }),
        LocalRequest::AccessSet(params) => OfflineWorkspace::new(&mut state.vault, state.device_id)
            .set_access_policy(params.harness, &params.policy)
            .map(|()| LocalResult::Access {
                policy: params.policy,
            }),
        LocalRequest::SyncStatus(_) => {
            let status = service_status.snapshot();
            state
                .vault
                .access_policy(HarnessId::Codex)
                .map_err(client_error_from_vault)
                .map(|access| LocalResult::Status {
                    status: context_relay_protocol::StatusOutput {
                        protocol: ProtocolVersionRange {
                            min: PROTOCOL_VERSION,
                            max: PROTOCOL_VERSION,
                        },
                        vault: status.vault,
                        resolved_project: None,
                        sync: status.sync,
                        access,
                    },
                })
        }
        LocalRequest::DevicesList(_) => {
            pairing::all_device_summaries(&state.vault, state.device_id)
                .map(|devices| LocalResult::Devices { devices })
        }
        LocalRequest::ExportRecords(params) => create_encrypted_export(state, params),
        LocalRequest::ExportChunk(params) => {
            export_chunk(state, params.export_id, params.chunk_index)
        }
        request @ (LocalRequest::AccountDeletionBegin(_)
        | LocalRequest::AccountDeletionStatus(_)
        | LocalRequest::AccountDeletionCancel(_)) => {
            execute_account_lifecycle_request(state, request)
        }
        _ => Err(invalid_request_error()),
    }
}

fn create_handoff(
    state: &mut WorkspaceState,
    params: context_relay_protocol::HandoffParams,
) -> Result<LocalResult, ClientError> {
    let memories = params
        .memory_ids
        .iter()
        .map(|id| {
            state
                .vault
                .memory(id)
                .map_err(client_error_from_vault)?
                .ok_or_else(record_not_found_error)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let decisions = params
        .decision_ids
        .iter()
        .map(|id| {
            let memory = state
                .vault
                .memory(id)
                .map_err(client_error_from_vault)?
                .ok_or_else(record_not_found_error)?;
            (memory.kind == MemoryKind::Decision)
                .then_some(memory)
                .ok_or_else(invalid_request_error)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let tasks = params
        .task_ids
        .iter()
        .map(|id| {
            state
                .vault
                .task(id)
                .map_err(client_error_from_vault)?
                .ok_or_else(record_not_found_error)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let project_id = tasks.first().map(|task| task.project_id).or_else(|| {
        memories
            .iter()
            .chain(&decisions)
            .find_map(|memory| match memory.scope {
                ScopeRef::Project { project_id } => Some(project_id),
                ScopeRef::Global => None,
            })
    });
    let project = project_id
        .map(|id| {
            state
                .vault
                .projects()
                .map_err(client_error_from_vault)?
                .into_iter()
                .find(|project| project.project_id == id)
                .ok_or_else(record_not_found_error)
        })
        .transpose()?;
    let payload = HandoffPayload {
        project,
        markdown: format!("# Handoff\n\n{}", params.summary),
        memories,
        decisions,
        tasks,
        instruction_refs: Vec::new(),
    };
    payload.validate().map_err(|_| invalid_request_error())?;
    Ok(LocalResult::Handoff {
        handoff_id: params.operation_id,
        payload,
    })
}

fn create_encrypted_export(
    state: &mut WorkspaceState,
    params: context_relay_protocol::ExportParams,
) -> Result<LocalResult, ClientError> {
    if params.project_id.is_some() || !params.include_archived {
        return Err(unsupported_error(
            "Only a complete encrypted vault export is supported",
        ));
    }
    state
        .vault
        .checkpoint_wal()
        .map_err(client_error_from_vault)?;
    let bytes = std::fs::read(&state.vault_path).map_err(|_| service_internal_error())?;
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    let export_id = export_id_from_digest(digest);
    let record_count = export_record_count(&state.vault)?;
    let chunks = bytes
        .chunks(MAX_ARBITRARY_BYTES)
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    let export = StoredExport {
        total_bytes: u64::try_from(bytes.len()).map_err(|_| service_internal_error())?,
        record_count,
        chunks,
    };
    let payload = export_payload(export_id, &export, 0)?;
    state.exports.clear();
    state.exports.insert(export_id, export);
    Ok(LocalResult::Export { payload })
}

fn export_chunk(
    state: &WorkspaceState,
    export_id: ExportId,
    chunk_index: u32,
) -> Result<LocalResult, ClientError> {
    let export = state
        .exports
        .get(&export_id)
        .ok_or_else(record_not_found_error)?;
    export_payload(export_id, export, chunk_index).map(|payload| LocalResult::Export { payload })
}

fn export_payload(
    export_id: ExportId,
    export: &StoredExport,
    chunk_index: u32,
) -> Result<ExportPayload, ClientError> {
    let index = usize::try_from(chunk_index).map_err(|_| invalid_request_error())?;
    let bytes = export.chunks.get(index).ok_or_else(invalid_request_error)?;
    Ok(ExportPayload {
        export_id,
        chunk_index,
        chunk_count: u32::try_from(export.chunks.len()).map_err(|_| service_internal_error())?,
        chunk: BoundedBytes::new(bytes.clone()).map_err(|_| service_internal_error())?,
        chunk_digest: Sha256Digest(Sha256::digest(bytes).into()),
        total_bytes: export.total_bytes,
        record_count: export.record_count,
    })
}

fn export_record_count(vault: &Vault) -> Result<u32, ClientError> {
    let projects = vault.projects().map_err(client_error_from_vault)?;
    let mut count = projects.len()
        + vault
            .memories(None, true)
            .map_err(client_error_from_vault)?
            .len()
        + vault
            .candidates(None)
            .map_err(client_error_from_vault)?
            .len();
    for project in projects {
        count += vault
            .memories(Some(project.project_id), true)
            .map_err(client_error_from_vault)?
            .len();
        count += vault
            .candidates(Some(project.project_id))
            .map_err(client_error_from_vault)?
            .len();
        count += vault
            .tasks(project.project_id)
            .map_err(client_error_from_vault)?
            .len();
    }
    u32::try_from(count).map_err(|_| service_internal_error())
}

fn execute_account_lifecycle_request(
    state: &mut WorkspaceState,
    request: LocalRequest,
) -> Result<LocalResult, ClientError> {
    if matches!(
        &request,
        LocalRequest::AccountDeletionBegin(params)
            if !params.confirmation.eq_ignore_ascii_case("delete")
    ) {
        return Err(invalid_request_error());
    }
    let service = state.account_lifecycle_service.clone();
    service.execute(&mut state.vault, request)
}

fn stable_device_id(seed: &[u8]) -> DeviceId {
    let digest: [u8; 32] = Sha256::digest(seed).into();
    uuid_v7_text(digest).parse().expect("stable UUIDv7")
}

fn export_id_from_digest(digest: [u8; 32]) -> ExportId {
    uuid_v7_text(digest).parse().expect("stable UUIDv7")
}

fn uuid_v7_text(mut bytes: [u8; 32]) -> String {
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

#[cfg(windows)]
const fn native_platform() -> NativePlatform {
    NativePlatform::Windows
}

#[cfg(not(windows))]
const fn native_platform() -> NativePlatform {
    NativePlatform::Macos
}

fn record_not_found_error() -> ClientError {
    ClientError {
        code: ErrorCode::NotFound,
        message: "The requested record was not found".into(),
        field_path: None,
        retryable: false,
    }
}

impl Drop for VaultWorker {
    fn drop(&mut self) {
        self.shutdown_and_join();
    }
}

fn map_guard_error(error: IpcError) -> DaemonError {
    match error {
        IpcError::AlreadyRunning => DaemonError::AlreadyRunning,
        _ => DaemonError::Transport,
    }
}

fn map_transport_error(_: IpcError) -> DaemonError {
    DaemonError::Transport
}

pub fn client_error_from_vault(error: VaultError) -> ClientError {
    match error {
        VaultError::MissingKey | VaultError::WrongKey => ClientError::vault_locked(),
        VaultError::BudgetExceeded => ClientError {
            code: ErrorCode::QuotaExceeded,
            message: "The local storage quota is exhausted".into(),
            field_path: None,
            retryable: false,
        },
        VaultError::Validation(_) => ClientError {
            code: ErrorCode::InvalidRequest,
            message: "The request is invalid".into(),
            field_path: None,
            retryable: false,
        },
        VaultError::OperationConflict => ClientError {
            code: ErrorCode::Conflict,
            message: "The operation ID is already bound to a different mutation".into(),
            field_path: None,
            retryable: false,
        },
        VaultError::FutureSchema { .. }
        | VaultError::Migration(_)
        | VaultError::Credential(_)
        | VaultError::Security(_)
        | VaultError::SearchModel(_)
        | VaultError::Serialization(_)
        | VaultError::Database(_) => ClientError {
            code: ErrorCode::Internal,
            message: "The local service could not complete the request".into(),
            field_path: None,
            retryable: false,
        },
    }
}

#[doc(hidden)]
pub mod test_support {
    use std::{
        collections::HashMap,
        path::{Path, PathBuf},
        sync::{
            Arc, Condvar, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
    };

    #[cfg(feature = "test-support")]
    use context_relay_core::vault::TestVaultCell;
    use context_relay_core::{
        codex::CodexAdapter,
        mcp::install::BridgeExecutable,
        native_memory::{NativeMemoryLedger, NativeMemorySource, NativeMemorySourceId},
        native_transaction::{
            ApprovedInput, NativeTransactionPlan, SidecarBinding,
            engine::{
                BoundaryError, FrozenOutput, NativeAdapter, NoFault, RestrictedExecutor,
                RestrictedRun,
            },
            filesystem::OsNativeTransactionFileSystem,
            open_plan,
        },
        setup::{
            BridgeInstallService, BridgeLocator, BridgeMutationPlan, BridgePreviewHarness,
            NativeEngineBridgePlanExecutor, NoBridgeCliExecutor, PrimaryMemoryMutationPlan,
            RegisteredProject,
        },
        vault::{BeforeImagePolicy, DatabaseKeyStore, NativeSandboxIdentity, Vault, VaultError},
    };
    #[cfg(feature = "test-support")]
    use context_relay_core::{
        codex::{CodexExecutableKind, CodexLayout},
        mcp::install::attest_bridge_executable,
        native_memory::{NativeMemoryAdapter, primary_memory_instruction_component},
        vault::{NativeTransactionStatus, SetupPlanLifecycle},
    };
    use context_relay_local_ipc::{InstallationToken, RuntimeConfig};
    #[cfg(feature = "test-support")]
    use context_relay_protocol::InstallationMethod;
    use context_relay_protocol::{
        ApplyReceipt, ClassifiedChanges, CliOperations, ClientError, ComponentRecord, DesiredState,
        DeviceId, DiscoveredScopes, ErrorCode, HarnessAdapter, HarnessId, HarnessParams,
        HybridLogicalClock, ImportRequest, ImportedState, MemoryCandidate, PlanId, PlanParams,
        ProbeContext, ProbeReport, ProjectId, RenderedState, SemanticDiff, SetupPlan, Sha256Digest,
        ValidationReport, WireNativeValue,
    };
    #[cfg(any(windows, target_os = "macos"))]
    use context_relay_protocol::{HarnessAccessPolicy, ProjectIdentity};
    use tokio::sync::Notify;
    use zeroize::Zeroizing;

    use super::{
        BridgeInstallEngine, Daemon, DaemonConfig, DaemonError, InstallationTokenProvider,
        VaultConfig, WorkerHook,
    };

    #[cfg(feature = "test-support")]
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct TestNativeMemoryRegistration {
        pub source_id: Sha256Digest,
        pub has_last_applied_digest: bool,
    }

    #[cfg(feature = "test-support")]
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct TestSetupPlanSummary {
        pub previewed: bool,
        pub setup: SetupPlan,
        pub mutation_count: usize,
        pub native_memory_registrations: Vec<TestNativeMemoryRegistration>,
    }

    #[cfg(feature = "test-support")]
    pub fn test_primary_memory_instruction_component(
        harness: HarnessId,
        project_id: ProjectId,
        origin_device: DeviceId,
        created_hlc: HybridLogicalClock,
    ) -> Result<ComponentRecord, ClientError> {
        primary_memory_instruction_component(harness, project_id, origin_device, created_hlc)
    }

    #[cfg(feature = "test-support")]
    pub fn test_managed_memory_hooks(
        harness: HarnessId,
        bridge_executable: &WireNativeValue,
    ) -> Result<Vec<ComponentRecord>, ClientError> {
        context_relay_core::native_memory::managed_memory_hooks(harness, bridge_executable)
    }

    #[derive(Clone)]
    pub struct TestDaemonConfig {
        runtime: RuntimeConfig,
        vault_path: PathBuf,
        token: [u8; 32],
        keys: Arc<TestKeyStore>,
        worker_gate: Option<Arc<TestWorkerGate>>,
        bridge_install: Option<Arc<dyn BridgeInstallEngine>>,
        native_memory_probe: Option<Arc<TestNativeMemoryProbe>>,
    }

    impl TestDaemonConfig {
        pub fn new(
            runtime: RuntimeConfig,
            vault_path: PathBuf,
            installation_token: InstallationToken,
        ) -> Self {
            Self {
                runtime,
                vault_path,
                token: *installation_token.as_bytes(),
                keys: Arc::default(),
                worker_gate: None,
                bridge_install: None,
                native_memory_probe: None,
            }
        }

        pub fn runtime(&self) -> RuntimeConfig {
            self.runtime.clone()
        }

        pub fn installation_token(&self) -> InstallationToken {
            InstallationToken::from_bytes(self.token)
        }

        pub fn with_worker_gate(mut self, worker_gate: Arc<TestWorkerGate>) -> Self {
            self.worker_gate = Some(worker_gate);
            self
        }

        pub fn with_bridge_install_engine(
            mut self,
            bridge_install: Arc<dyn BridgeInstallEngine>,
        ) -> Self {
            self.bridge_install = Some(bridge_install);
            self
        }

        pub fn with_native_memory_probe(mut self, probe: Arc<TestNativeMemoryProbe>) -> Self {
            self.native_memory_probe = Some(probe);
            self
        }

        #[cfg(any(windows, target_os = "macos"))]
        pub fn seed_mcp_project(
            &self,
            project: &ProjectIdentity,
            root: &Path,
            policies: &[(HarnessId, HarnessAccessPolicy)],
        ) -> Result<(), VaultError> {
            std::fs::create_dir_all(self.vault_path.parent().expect("test vault has a parent"))
                .expect("create test vault directory");
            let canonical_root = std::fs::canonicalize(root).expect("canonical test project root");
            let mut vault = Vault::open(
                &self.vault_path,
                "context-relay-test-vault-key",
                self.keys.as_ref(),
            )?;
            vault.put_project(project)?;
            vault.put_path(
                &project.project_id.to_string(),
                &wire_native_path(&canonical_root),
            )?;
            for (harness, policy) in policies {
                vault.set_access_policy(*harness, policy)?;
            }
            Ok(())
        }

        pub fn native_hook_session_count(&self) -> Result<usize, VaultError> {
            let vault = Vault::open(
                &self.vault_path,
                "context-relay-test-vault-key",
                self.keys.as_ref(),
            )?;
            vault.native_hook_session_count()
        }

        #[cfg(feature = "test-support")]
        pub fn test_vault_plaintext_cells(&self) -> Result<Vec<TestVaultCell>, VaultError> {
            let vault = Vault::open(
                &self.vault_path,
                "context-relay-test-vault-key",
                self.keys.as_ref(),
            )?;
            vault.test_plaintext_cells()
        }

        pub fn seed_native_memory_source(
            &self,
            source: &NativeMemorySource,
            last_applied_digest: Option<Sha256Digest>,
        ) -> Result<(), VaultError> {
            std::fs::create_dir_all(self.vault_path.parent().expect("test vault has a parent"))
                .expect("create test vault directory");
            let mut vault = Vault::open(
                &self.vault_path,
                "context-relay-test-vault-key",
                self.keys.as_ref(),
            )?;
            let mut ledger = NativeMemoryLedger::for_source(source.clone());
            ledger.last_applied_digest = last_applied_digest;
            vault.put_native_memory_candidate(&ledger, None)
        }

        /// Opens the daemon's encrypted test vault with its bound key store so
        /// integration tests can exercise production core transactions before
        /// the daemon process is started.
        pub fn with_vault<T>(
            &self,
            operation: impl FnOnce(&mut Vault) -> Result<T, VaultError>,
        ) -> Result<T, VaultError> {
            std::fs::create_dir_all(self.vault_path.parent().expect("test vault has a parent"))
                .expect("create test vault directory");
            let mut vault = Vault::open(
                &self.vault_path,
                "context-relay-test-vault-key",
                self.keys.as_ref(),
            )?;
            operation(&mut vault)
        }

        pub fn native_memory_ledger(
            &self,
            source_id: &NativeMemorySourceId,
        ) -> Result<Option<NativeMemoryLedger>, VaultError> {
            let vault = Vault::open(
                &self.vault_path,
                "context-relay-test-vault-key",
                self.keys.as_ref(),
            )?;
            vault.native_memory_ledger(source_id)
        }

        #[cfg(feature = "test-support")]
        pub fn native_memory_preview_complete(
            &self,
            source_id: Sha256Digest,
        ) -> Result<bool, VaultError> {
            self.native_memory_ledger(&NativeMemorySourceId(source_id))
                .map(|ledger| ledger.is_some_and(|ledger| ledger.initial_preview_complete))
        }

        #[cfg(feature = "test-support")]
        pub fn setup_plan_summary(
            &self,
            plan_id: &PlanId,
        ) -> Result<Option<TestSetupPlanSummary>, VaultError> {
            self.with_vault(|vault| {
                let Some(stored) = vault.setup_plan(plan_id)? else {
                    return Ok(None);
                };
                let opened = open_plan(&stored.payload)
                    .map_err(|error| VaultError::Serialization(error.to_string()))?;
                Ok(Some(TestSetupPlanSummary {
                    previewed: stored.lifecycle == SetupPlanLifecycle::Previewed,
                    setup: opened.plan.setup,
                    mutation_count: opened.plan.mutations.len(),
                    native_memory_registrations: opened
                        .plan
                        .native_memory_registrations
                        .into_iter()
                        .map(|registration| TestNativeMemoryRegistration {
                            source_id: registration.source.id.0,
                            has_last_applied_digest: registration.last_applied_digest.is_some(),
                        })
                        .collect(),
                }))
            })
        }

        #[cfg(feature = "test-support")]
        pub fn setup_plan_applied(&self, plan_id: &PlanId) -> Result<bool, VaultError> {
            self.with_vault(|vault| {
                vault.setup_plan(plan_id).map(|plan| {
                    plan.is_some_and(|plan| plan.lifecycle == SetupPlanLifecycle::Applied)
                })
            })
        }

        #[cfg(feature = "test-support")]
        pub fn native_transaction_committed(
            &self,
            transaction_id: &str,
        ) -> Result<bool, VaultError> {
            self.with_vault(|vault| {
                vault.native_transaction(transaction_id).map(|transaction| {
                    transaction.is_some_and(|transaction| {
                        transaction.status == NativeTransactionStatus::Committed
                    })
                })
            })
        }

        pub fn native_memory_candidates(&self) -> Result<Vec<MemoryCandidate>, VaultError> {
            let vault = Vault::open(
                &self.vault_path,
                "context-relay-test-vault-key",
                self.keys.as_ref(),
            )?;
            vault.candidates(None)
        }

        pub async fn start(&self) -> Result<Daemon, DaemonError> {
            let mut vault = VaultConfig::new(
                self.vault_path.clone(),
                "context-relay-test-vault-key",
                self.keys.clone(),
            );
            if let Some(worker_gate) = &self.worker_gate {
                vault = vault.with_worker_hook(worker_gate.clone());
            }
            if let Some(bridge_install) = &self.bridge_install {
                vault = vault.with_bridge_install(bridge_install.clone());
            }
            if let Some(probe) = &self.native_memory_probe {
                vault = vault.with_native_memory_probe(probe.clone());
            }
            Daemon::start(DaemonConfig::new(
                self.runtime.clone(),
                vault,
                Arc::new(TestTokenProvider { token: self.token }),
            ))
            .await
        }
    }

    pub struct TestWorkerGate {
        entered: AtomicBool,
        entered_wake: Notify,
        released: Mutex<bool>,
        release_wake: Condvar,
        enqueued: AtomicUsize,
        enqueue_wake: Notify,
    }

    #[derive(Default)]
    pub struct TestNativeMemoryProbe {
        starts: AtomicUsize,
        stops: AtomicUsize,
        started_wake: Notify,
    }

    impl TestNativeMemoryProbe {
        pub fn starts(&self) -> usize {
            self.starts.load(Ordering::Acquire)
        }

        pub fn stops(&self) -> usize {
            self.stops.load(Ordering::Acquire)
        }

        pub async fn wait_until_started(&self) {
            loop {
                let notified = self.started_wake.notified();
                if self.starts() != 0 {
                    return;
                }
                notified.await;
            }
        }
    }

    impl super::native_memory::LifecycleProbe for TestNativeMemoryProbe {
        fn started(&self) {
            self.starts.fetch_add(1, Ordering::Release);
            self.started_wake.notify_waiters();
        }

        fn stopped(&self) {
            self.stops.fetch_add(1, Ordering::Release);
        }
    }

    impl TestWorkerGate {
        pub fn new() -> Self {
            Self {
                entered: AtomicBool::new(false),
                entered_wake: Notify::new(),
                released: Mutex::new(false),
                release_wake: Condvar::new(),
                enqueued: AtomicUsize::new(0),
                enqueue_wake: Notify::new(),
            }
        }

        pub async fn wait_until_entered(&self) {
            loop {
                let notified = self.entered_wake.notified();
                if self.entered.load(Ordering::Acquire) {
                    return;
                }
                notified.await;
            }
        }

        pub async fn wait_until_enqueued(&self, target: usize) {
            loop {
                let notified = self.enqueue_wake.notified();
                if self.enqueued() >= target {
                    return;
                }
                notified.await;
            }
        }

        pub fn enqueued(&self) -> usize {
            self.enqueued.load(Ordering::Acquire)
        }

        pub fn release(&self) {
            *self.released.lock().unwrap() = true;
            self.release_wake.notify_all();
        }
    }

    impl Default for TestWorkerGate {
        fn default() -> Self {
            Self::new()
        }
    }

    #[derive(Default)]
    pub struct TestRecordingBridgeInstallEngine {
        reconciles: AtomicUsize,
        previews: AtomicUsize,
        applies: AtomicUsize,
        rollbacks: AtomicUsize,
    }

    impl TestRecordingBridgeInstallEngine {
        /// Bridge installation and native mutation are reachable only through
        /// preview, apply, or rollback. Those methods record and fail on call,
        /// so zero calls proves ordinary MCP work did not enter setup.
        pub fn assert_no_setup_calls(&self) {
            assert_eq!(self.previews.load(Ordering::SeqCst), 0);
            assert_eq!(self.applies.load(Ordering::SeqCst), 0);
            assert_eq!(self.rollbacks.load(Ordering::SeqCst), 0);
        }
    }

    impl BridgeInstallEngine for TestRecordingBridgeInstallEngine {
        fn reconcile_after_native_recovery(
            &self,
            _vault: &mut Vault,
            _vault_path: &Path,
            _device_id: DeviceId,
        ) -> Result<(), ClientError> {
            self.reconciles.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn preview(
            &self,
            _vault: &mut Vault,
            _vault_path: &Path,
            _device_id: DeviceId,
            _params: HarnessParams,
        ) -> Result<SetupPlan, ClientError> {
            self.previews.fetch_add(1, Ordering::SeqCst);
            Err(unexpected_setup_call())
        }

        fn apply(
            &self,
            _vault: &mut Vault,
            _vault_path: &Path,
            _device_id: DeviceId,
            _params: PlanParams,
        ) -> Result<(), ClientError> {
            self.applies.fetch_add(1, Ordering::SeqCst);
            Err(unexpected_setup_call())
        }

        fn rollback(
            &self,
            _vault: &mut Vault,
            _vault_path: &Path,
            _device_id: DeviceId,
            _params: PlanParams,
        ) -> Result<(), ClientError> {
            self.rollbacks.fetch_add(1, Ordering::SeqCst);
            Err(unexpected_setup_call())
        }
    }

    fn unexpected_setup_call() -> ClientError {
        ClientError {
            code: ErrorCode::Internal,
            message: "unexpected bridge setup call in daemon-backed test".into(),
            field_path: None,
            retryable: false,
        }
    }

    /// Deterministic real Codex setup engine for cross-crate daemon/MCP
    /// acceptance tests. Adapter planning and native transactions are
    /// production code; only external CLI and restricted-run boundaries are
    /// represented by in-memory test state.
    #[cfg(feature = "test-support")]
    pub struct TestCodexBridgeInstallRequest {
        pub executable: PathBuf,
        pub bridge_path: PathBuf,
        pub version: String,
        pub installation_method: InstallationMethod,
        pub codex_home: PathBuf,
        pub user_home: PathBuf,
        pub user_skills_dir: PathBuf,
        pub project_root: PathBuf,
        pub working_directory: PathBuf,
        pub requirements_paths: Vec<PathBuf>,
        pub project_id: ProjectId,
        pub origin_device: DeviceId,
        pub observed_hlc: HybridLogicalClock,
        pub lock_root: PathBuf,
    }

    #[cfg(feature = "test-support")]
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct TestNativeMemorySource {
        pub id: Sha256Digest,
        pub path: WireNativeValue,
    }

    #[cfg(feature = "test-support")]
    pub struct TestCodexBridgeInstallFixture {
        pub engine: Arc<TestCodexBridgeInstallEngine>,
        pub sources: Vec<TestNativeMemorySource>,
    }

    pub struct TestCodexBridgeInstallEngine {
        harness: Mutex<TestCodexHarness>,
        bridge: BridgeExecutable,
        project_id: ProjectId,
        project_root: PathBuf,
        lock_root: PathBuf,
    }

    impl TestCodexBridgeInstallEngine {
        #[cfg(feature = "test-support")]
        pub fn from_request(
            request: TestCodexBridgeInstallRequest,
        ) -> Result<TestCodexBridgeInstallFixture, ClientError> {
            let adapter = CodexAdapter::from_layout(
                CodexLayout {
                    executable: request.executable,
                    executable_kind: CodexExecutableKind::Native,
                    version: request.version,
                    installation_method: request.installation_method,
                    codex_home: request.codex_home,
                    user_home: request.user_home,
                    user_skills_dir: request.user_skills_dir,
                    project_root: request.project_root.clone(),
                    working_directory: request.working_directory,
                    requirements_paths: request.requirements_paths,
                },
                request.project_id,
                request.origin_device,
                request.observed_hlc,
            )?;
            let sources = adapter
                .native_memory_capabilities()?
                .sources
                .into_iter()
                .map(|source| TestNativeMemorySource {
                    id: source.id.0,
                    path: source.path,
                })
                .collect();
            let bridge = attest_bridge_executable(&request.bridge_path)?;
            Ok(TestCodexBridgeInstallFixture {
                engine: Arc::new(Self::new(
                    adapter,
                    bridge,
                    request.project_id,
                    request.project_root,
                    request.lock_root,
                )),
                sources,
            })
        }

        pub fn new(
            adapter: CodexAdapter,
            bridge: BridgeExecutable,
            project_id: ProjectId,
            project_root: PathBuf,
            lock_root: PathBuf,
        ) -> Self {
            Self {
                harness: Mutex::new(TestCodexHarness { adapter }),
                bridge,
                project_id,
                project_root: std::fs::canonicalize(project_root)
                    .expect("test Codex project root is canonicalizable"),
                lock_root,
            }
        }

        fn execute(
            &self,
            vault: &mut Vault,
            device_id: DeviceId,
            plan_id: PlanId,
            rollback: bool,
        ) -> Result<(), ClientError> {
            let mut harness = self.harness.lock().unwrap();
            let stored = vault
                .setup_plan(&plan_id)
                .map_err(|_| test_conflict("Test Codex plan cannot be loaded"))?
                .ok_or_else(|| test_conflict("Test Codex plan does not exist"))?;
            let opened = open_plan(&stored.payload)
                .map_err(|_| test_conflict("Test Codex plan cannot be opened"))?;
            let mut restricted = TestCodexRestricted {
                inputs: opened.plan.staged_inputs.clone(),
                sidecars: opened.plan.sidecars.clone(),
                run: RestrictedRun {
                    staged_output_hash: opened.plan.expected_semantic_output_hash,
                    scanner_result_hash: opened.plan.scanner_result_hash,
                },
            };
            let mut filesystem = OsNativeTransactionFileSystem::new(*plan_id.as_bytes());
            let mut hook = NoFault;
            let mut cli = NoBridgeCliExecutor;
            let mut executor = NativeEngineBridgePlanExecutor::new(
                &mut *harness,
                &mut restricted,
                &mut filesystem,
                &mut hook,
                &mut cli,
                &self.lock_root,
                test_native_identity(),
                BeforeImagePolicy::default(),
                HybridLogicalClock::new(1_900_000_000_001, 0, device_id),
            );
            if rollback {
                BridgeInstallService::persisted(vault).rollback(
                    &plan_id,
                    1_900_000_000_002,
                    &mut executor,
                )
            } else {
                BridgeInstallService::persisted(vault).apply(
                    &plan_id,
                    1_900_000_000_001,
                    &mut executor,
                )
            }
        }
    }

    impl BridgeInstallEngine for TestCodexBridgeInstallEngine {
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
            if params.harness != HarnessId::Codex || params.project_id != Some(self.project_id) {
                return Err(test_conflict("Test Codex setup binding changed"));
            }
            let observed_hlc = HybridLogicalClock::new(1_900_000_000_000, 0, device_id);
            let harness = self.harness.lock().unwrap().clone();
            let project_root = harness.adapter.project_root_wire();
            assert_eq!(project_root, wire_native_path(&self.project_root));
            BridgeInstallService::new(
                vault,
                harness,
                TestFixedBridgeLocator(self.bridge.clone()),
                device_id,
                observed_hlc,
            )
            .preview(
                Some(&RegisteredProject {
                    project_id: self.project_id,
                    root: project_root,
                }),
                1_900_000_000_000,
            )
        }

        fn apply(
            &self,
            vault: &mut Vault,
            _vault_path: &Path,
            device_id: DeviceId,
            params: PlanParams,
        ) -> Result<(), ClientError> {
            self.execute(vault, device_id, params.plan_id, false)
        }

        fn rollback(
            &self,
            vault: &mut Vault,
            _vault_path: &Path,
            device_id: DeviceId,
            params: PlanParams,
        ) -> Result<(), ClientError> {
            self.execute(vault, device_id, params.plan_id, true)
        }
    }

    #[derive(Clone)]
    struct TestCodexHarness {
        adapter: CodexAdapter,
    }

    impl HarnessAdapter for TestCodexHarness {
        fn probe(&self, context: &ProbeContext) -> Result<ProbeReport, ClientError> {
            self.adapter.probe(context)
        }

        fn discover_scopes(&self, report: &ProbeReport) -> Result<DiscoveredScopes, ClientError> {
            self.adapter.discover_scopes(report)
        }

        fn import(&self, request: &ImportRequest) -> Result<ImportedState, ClientError> {
            self.adapter.import(request)
        }

        fn render(&self, desired: &DesiredState) -> Result<RenderedState, ClientError> {
            self.adapter.render(desired)
        }

        fn classify(&self, diff: &SemanticDiff) -> Result<ClassifiedChanges, ClientError> {
            self.adapter.classify(diff)
        }

        fn plan_cli_ops(&self, changes: &ClassifiedChanges) -> Result<CliOperations, ClientError> {
            self.adapter.plan_cli_ops(changes)
        }

        fn validate_effective(
            &self,
            receipt: &ApplyReceipt,
        ) -> Result<ValidationReport, ClientError> {
            HarnessAdapter::validate_effective(&self.adapter, receipt)
        }
    }

    impl BridgePreviewHarness for TestCodexHarness {
        fn bridge_adapter_version(&self) -> u32 {
            self.adapter.bridge_adapter_version()
        }

        fn bridge_harness(&self) -> HarnessId {
            HarnessId::Codex
        }

        fn bridge_setup_capability(&self) -> context_relay_protocol::CapabilityLevel {
            BridgePreviewHarness::bridge_setup_capability(&self.adapter)
        }

        fn bridge_project_id(&self) -> Option<ProjectId> {
            Some(self.adapter.project_id())
        }

        fn bridge_project_root(&self) -> Option<WireNativeValue> {
            Some(self.adapter.project_root_wire())
        }

        fn bridge_mutations(
            &self,
            desired: &DesiredState,
            intended: &ComponentRecord,
        ) -> Result<BridgeMutationPlan, ClientError> {
            self.adapter.bridge_mutations(desired, intended)
        }

        fn primary_memory_mutations(
            &self,
            desired: &DesiredState,
        ) -> Result<PrimaryMemoryMutationPlan, ClientError> {
            BridgePreviewHarness::primary_memory_mutations(&self.adapter, desired)
        }

        fn watch_only_memory_registrations(
            &self,
        ) -> Result<
            Option<Vec<context_relay_core::native_memory::NativeMemoryRegistration>>,
            ClientError,
        > {
            BridgePreviewHarness::watch_only_memory_registrations(&self.adapter)
        }
    }

    impl NativeAdapter for TestCodexHarness {
        fn reprobe_live_state(
            &mut self,
            plan: &NativeTransactionPlan,
        ) -> Result<(), BoundaryError> {
            NativeAdapter::reprobe_live_state(&mut self.adapter, plan)
        }

        fn compare_approved_digests(
            &mut self,
            plan: &NativeTransactionPlan,
        ) -> Result<(), BoundaryError> {
            NativeAdapter::compare_approved_digests(&mut self.adapter, plan)
        }

        fn verify_live_state_reservation(
            &mut self,
            plan: &NativeTransactionPlan,
        ) -> Result<(), BoundaryError> {
            NativeAdapter::verify_live_state_reservation(&mut self.adapter, plan)
        }

        fn validate_staged_output(
            &mut self,
            plan: &NativeTransactionPlan,
            run: &RestrictedRun,
        ) -> Result<FrozenOutput, BoundaryError> {
            NativeAdapter::validate_staged_output(&mut self.adapter, plan, run)
        }

        fn validate_effective(
            &mut self,
            plan: &NativeTransactionPlan,
            receipt: &ApplyReceipt,
        ) -> Result<(), BoundaryError> {
            NativeAdapter::validate_effective(&mut self.adapter, plan, receipt)
        }
    }

    #[derive(Clone)]
    struct TestFixedBridgeLocator(BridgeExecutable);

    impl BridgeLocator for TestFixedBridgeLocator {
        fn locate(&self) -> Result<BridgeExecutable, ClientError> {
            Ok(self.0.clone())
        }
    }

    struct TestCodexRestricted {
        inputs: Vec<ApprovedInput>,
        sidecars: Vec<SidecarBinding>,
        run: RestrictedRun,
    }

    impl RestrictedExecutor for TestCodexRestricted {
        fn copy_allowlisted_inputs(
            &mut self,
            inputs: &[ApprovedInput],
        ) -> Result<(), BoundaryError> {
            (inputs == self.inputs)
                .then_some(())
                .ok_or_else(|| BoundaryError::new("Test Codex inputs changed"))
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
            (sidecars == self.sidecars)
                .then(|| self.run.clone())
                .ok_or_else(|| BoundaryError::new("Test Codex sidecars changed"))
        }

        fn reject_unsafe_topology(&mut self) -> Result<(), BoundaryError> {
            Ok(())
        }
    }

    fn test_native_identity() -> NativeSandboxIdentity {
        #[cfg(windows)]
        {
            NativeSandboxIdentity::Windows {
                moniker: "context-relay.native.0123456789abcdef0123456789abcdef".to_owned(),
                sid: b"S-1-15-2-3872518810-2985098273-1912316193-2655983105-1250049442-371239648-1157085541".to_vec(),
            }
        }
        #[cfg(not(windows))]
        {
            let generation = "0123456789abcdef0123456789abcdef";
            let bundle = format!("com.contextrelay.native-runner.{generation}");
            let mut container = b"context-relay/macos-container/v1\0".to_vec();
            container.extend_from_slice(bundle.as_bytes());
            NativeSandboxIdentity::reserved_macos(generation.to_owned(), bundle, container)
        }
    }

    fn test_conflict(message: &'static str) -> ClientError {
        ClientError {
            code: ErrorCode::Conflict,
            message: message.to_owned(),
            field_path: None,
            retryable: false,
        }
    }

    impl WorkerHook for TestWorkerGate {
        fn before_execute(&self) {
            self.entered.store(true, Ordering::Release);
            self.entered_wake.notify_waiters();
            let mut released = self.released.lock().unwrap();
            while !*released {
                released = self.release_wake.wait(released).unwrap();
            }
        }

        fn after_enqueue(&self) {
            self.enqueued.fetch_add(1, Ordering::Release);
            self.enqueue_wake.notify_waiters();
        }
    }

    struct TestTokenProvider {
        token: [u8; 32],
    }

    fn wire_native_path(path: &Path) -> WireNativeValue {
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;

            WireNativeValue {
                platform: context_relay_protocol::NativePlatform::Windows,
                bytes: path
                    .as_os_str()
                    .encode_wide()
                    .flat_map(u16::to_le_bytes)
                    .collect(),
                display: path.to_str().map(str::to_owned),
            }
        }
        #[cfg(not(windows))]
        {
            use std::os::unix::ffi::OsStrExt;

            WireNativeValue {
                platform: context_relay_protocol::NativePlatform::Macos,
                bytes: path.as_os_str().as_bytes().to_vec(),
                display: path.to_str().map(str::to_owned),
            }
        }
    }

    impl InstallationTokenProvider for TestTokenProvider {
        fn load_or_create(&self) -> Result<InstallationToken, DaemonError> {
            Ok(InstallationToken::from_bytes(self.token))
        }
    }

    #[derive(Default)]
    struct TestKeyStore {
        values: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl DatabaseKeyStore for TestKeyStore {
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

#[cfg(test)]
mod tests {
    #[cfg(target_os = "macos")]
    use std::str::FromStr;
    use std::{
        collections::HashMap,
        sync::{
            Arc, Condvar, Mutex,
            atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        },
    };

    #[cfg(target_os = "macos")]
    use context_relay_core::native_transaction::{NativeApplyReceipt, TransactionStep};
    #[cfg(target_os = "macos")]
    use context_relay_core::vault::NativeCliWalWrite;
    use context_relay_core::{
        crypto::{
            CertificateFieldsV1, DeviceCertificateV1, DeviceKeys, RecoveryKeys, RecoveryPhrase,
        },
        devices::{
            account_lifecycle::{
                ACCOUNT_DELETION_GRACE_MS, AccountDeletionProjection, AccountLifecycleTransport,
                AccountLifecycleTransportError,
            },
            identity::{DeviceIdentityError, StoreIfAbsent},
            memory_transport::InMemoryPairingProvider,
            pairing::{
                PairingClock, PairingCoordinator, PairingCycleError, PairingMaterialSource,
                VaultPairingMaterialSource, WorkspacePairingMaterial,
            },
            recovery::{RecoveryEnrollmentClock, RecoveryEnrollmentCoordinator},
            recovery_crypto::decode_recovery_enrollment_record_v1,
            recovery_transport::{
                RecoveryEnrollmentReceipt, RecoveryEnrollmentTransport, RecoveryRootStatus,
                RecoveryTransportError,
            },
            transport::{
                PairingApprovalTransport, PairingDecisionEnvelope, PairingDecisionReceipt,
                PairingInviteStatus, PairingJoinTransport, PairingRequestReceipt, PairingResult,
                PairingTransportError, StoredPairingRequest,
            },
        },
        native_transaction::recovery::{OsNativeRecoveryIo, recover_native_transactions},
        sync::SyncScope,
        vault::{
            DeviceCertificateState, DeviceDisplayMetadata, NativePlanWrite,
            NativeSandboxCleanupState, NativeSandboxIdentity, NativeTransactionStatus,
            SetupPlanAction, SetupPlanLifecycle,
        },
    };
    use context_relay_local_ipc::{
        AuthAcceptedV1, AuthTranscriptV1, ConnectedStream, InstallationToken, IpcError,
        ServerHelloV1, connect, create_proof, read_json, write_json,
    };
    #[cfg(target_os = "macos")]
    use context_relay_native_runner::MacRootIdentity;
    #[cfg(target_os = "macos")]
    use context_relay_protocol::ApplyReceipt;
    use context_relay_protocol::{
        AccountDeletionState, AccountId, CancelParams, ClientRole, DecimalTimestamp,
        DeviceCertificateId, EmptyParams, HelloParams, JsonRpcErrorV1, JsonRpcRequestV1,
        JsonRpcSuccessV1, JsonRpcVersion, LocalRequest, NativePlatform, PROTOCOL_VERSION,
        PairingConfirmParams, PairingDecisionParams, PairingIdParams, PairingJoinParams,
        PairingRequestNonce, PairingState, PlanId, RecordId, RecoveryPhraseWords, Sha256Digest,
        WorkspaceId,
    };
    #[cfg(any(windows, target_os = "macos"))]
    use context_relay_protocol::{
        HarnessAccessPolicy, McpBinding, McpCallParams, ProjectId, ProjectIdentity, WireNativeValue,
    };
    use zeroize::Zeroizing;

    use super::*;

    const LIFECYCLE_BEGIN_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07a102";
    const LIFECYCLE_CANCEL_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07a103";

    #[derive(Clone)]
    struct TestAccountLifecycleTransport {
        state: Arc<Mutex<AccountDeletionState>>,
        calls: Arc<AtomicUsize>,
        operations: Arc<Mutex<Vec<context_relay_protocol::OperationId>>>,
    }

    impl TestAccountLifecycleTransport {
        fn new() -> Self {
            Self {
                state: Arc::new(Mutex::new(AccountDeletionState::Active)),
                calls: Arc::new(AtomicUsize::new(0)),
                operations: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn projection(&self) -> AccountDeletionProjection {
            let state = *self.state.lock().unwrap();
            AccountDeletionProjection {
                state,
                requested_at_ms: (state == AccountDeletionState::PendingDelete).then_some(1_000),
                purge_deadline_ms: (state == AccountDeletionState::PendingDelete)
                    .then_some(1_000 + ACCOUNT_DELETION_GRACE_MS),
            }
        }
    }

    impl AccountLifecycleTransport for TestAccountLifecycleTransport {
        fn deletion_status(
            &self,
        ) -> Result<AccountDeletionProjection, AccountLifecycleTransportError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.projection())
        }

        fn begin_deletion(
            &self,
            operation_id: context_relay_protocol::OperationId,
        ) -> Result<AccountDeletionProjection, AccountLifecycleTransportError> {
            self.operations.lock().unwrap().push(operation_id);
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut state = self.state.lock().unwrap();
            *state = AccountDeletionState::PendingDelete;
            drop(state);
            Ok(self.projection())
        }

        fn cancel_deletion(
            &self,
            operation_id: context_relay_protocol::OperationId,
        ) -> Result<AccountDeletionProjection, AccountLifecycleTransportError> {
            self.operations.lock().unwrap().push(operation_id);
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut state = self.state.lock().unwrap();
            *state = AccountDeletionState::Active;
            drop(state);
            Ok(self.projection())
        }
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[tokio::test]
    async fn second_daemon_fails_before_token_or_vault_credentials_are_touched() {
        let runtime = test_runtime("singleton-order");
        let _held = InstanceGuard::acquire(&runtime).unwrap();
        let provider = Arc::new(FixedTokenProvider::default());
        let keys = Arc::new(MemoryKeyStore::default());
        let path = unique_temp_path("singleton-order").join("vault.db");
        let config = test_config(runtime, path, keys.clone(), provider.clone());

        let result = Daemon::start(config).await;

        assert!(matches!(result, Err(DaemonError::AlreadyRunning)));
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
        assert_eq!(keys.loads.load(Ordering::SeqCst), 0);
        assert_eq!(keys.stores.load(Ordering::SeqCst), 0);
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[tokio::test]
    async fn endpoint_is_unpublished_while_vault_open_is_blocked() {
        let runtime = test_runtime("open-before-bind");
        let provider = Arc::new(FixedTokenProvider::default());
        let keys = Arc::new(MemoryKeyStore::blocking());
        let path = unique_temp_path("open-before-bind").join("vault.db");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let config = test_config(runtime.clone(), path, keys.clone(), provider);

        let inspect = async {
            keys.wait_until_load_started().await;
            let connection = connect(&runtime).await;
            keys.release_load();
            assert!(matches!(connection, Err(IpcError::EndpointNotFound)));
        };
        let (started, ()) = tokio::join!(Daemon::start(config), inspect);
        drop(started.unwrap());
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[tokio::test]
    async fn endpoint_is_unpublished_while_startup_recovery_is_blocked() {
        let runtime = test_runtime("recovery-before-bind");
        let provider = Arc::new(FixedTokenProvider::default());
        let keys = Arc::new(MemoryKeyStore::default());
        let path = unique_temp_path("recovery-before-bind").join("vault.db");
        let (entered, entered_rx) = oneshot::channel();
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let recovery_gate = gate.clone();
        let entered = Mutex::new(Some(entered));
        let recovery = Arc::new(move |_vault: &mut Vault| {
            if let Some(entered) = entered.lock().unwrap().take() {
                let _ = entered.send(());
            }
            let (released, wake) = &*recovery_gate;
            let mut released = released.lock().unwrap();
            while !*released {
                released = wake.wait(released).unwrap();
            }
            Ok(())
        });
        let config =
            test_config(runtime.clone(), path, keys, provider).with_startup_recovery(recovery);

        let inspect = async {
            entered_rx.await.unwrap();
            let connection = connect(&runtime).await;
            let (released, wake) = &*gate;
            *released.lock().unwrap() = true;
            wake.notify_all();
            assert!(matches!(connection, Err(IpcError::EndpointNotFound)));
        };
        let (started, ()) = tokio::join!(Daemon::start(config), inspect);
        drop(started.unwrap());
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[tokio::test]
    async fn startup_recovery_failure_releases_singleton_and_never_publishes_endpoint() {
        let runtime = test_runtime("recovery-failure");
        let provider = Arc::new(FixedTokenProvider::default());
        let keys = Arc::new(MemoryKeyStore::default());
        let path = unique_temp_path("recovery-failure").join("vault.db");
        let recovery = Arc::new(|_vault: &mut Vault| Err(DaemonError::Startup));
        let config =
            test_config(runtime.clone(), path, keys, provider).with_startup_recovery(recovery);

        assert!(matches!(
            Daemon::start(config).await,
            Err(DaemonError::Startup)
        ));
        assert!(matches!(
            connect(&runtime).await,
            Err(IpcError::EndpointNotFound)
        ));
        drop(InstanceGuard::acquire(&runtime).unwrap());
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[tokio::test]
    async fn startup_recovery_processes_every_pending_transaction_before_listener_bind() {
        let runtime = test_runtime("recover-all-before-bind");
        let provider = Arc::new(FixedTokenProvider::default());
        let keys = Arc::new(MemoryKeyStore::default());
        let path = unique_temp_path("recover-all-before-bind").join("vault.db");
        seed_pending_native_transactions(&path, keys.as_ref());
        let cleanups = Arc::new(AtomicUsize::new(0));
        let recovery_cleanups = cleanups.clone();
        let recovery = Arc::new(move |vault: &mut Vault| {
            let mut io = OsNativeRecoveryIo::new(|_, _| {
                recovery_cleanups.fetch_add(1, Ordering::SeqCst);
                Ok(())
            });
            recover_native_transactions(vault, &mut io)
                .map(|_| ())
                .map_err(|_| DaemonError::Startup)
        });
        let config = test_config(runtime.clone(), path.clone(), keys.clone(), provider)
            .with_startup_recovery(recovery);

        let daemon = Daemon::start(config).await.unwrap();

        assert_eq!(cleanups.load(Ordering::SeqCst), 2);
        drop(daemon);
        let vault = Vault::open(&path, "test-vault-key", keys.as_ref()).unwrap();
        assert!(vault.recoverable_native_transactions().unwrap().is_empty());
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[tokio::test]
    async fn interrupted_bridge_setup_recovers_nonlaunching_sandbox_before_listener_bind() {
        let runtime = test_runtime("nonlaunching-setup-recovery");
        let provider = Arc::new(FixedTokenProvider::default());
        let keys = Arc::new(MemoryKeyStore::default());
        let path = unique_temp_path("nonlaunching-setup-recovery").join("vault.db");
        let (plan_id, transaction_id) =
            seed_interrupted_nonlaunching_bridge_setup(&path, keys.as_ref());

        let daemon = Daemon::start(test_config(
            runtime.clone(),
            path.clone(),
            keys.clone(),
            provider,
        ))
        .await
        .expect("non-launching setup recovery must complete before listener bind");
        drop(connect(&runtime).await.expect("listener must be published"));
        drop(daemon);

        let vault = Vault::open(&path, "test-vault-key", keys.as_ref()).unwrap();
        assert_eq!(
            vault.setup_plan(&plan_id).unwrap().unwrap().lifecycle,
            SetupPlanLifecycle::ApplyRestored
        );
        let transaction = vault.native_transaction(&transaction_id).unwrap().unwrap();
        assert_eq!(transaction.status, NativeTransactionStatus::Restored);
        assert_eq!(
            transaction.sandbox_cleanup_state,
            NativeSandboxCleanupState::Cleaned
        );
        assert!(vault.recoverable_native_transactions().unwrap().is_empty());
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn interrupted_bridge_cli_wal_recovers_before_listener_bind() {
        use std::os::unix::fs::PermissionsExt as _;

        static ENVIRONMENT_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
        let _environment = ENVIRONMENT_LOCK.lock().await;
        for (label, initial, committed, lifecycle, status, final_state) in [
            (
                "cli-prepared-expected",
                "absent",
                false,
                SetupPlanLifecycle::ApplyRestored,
                NativeTransactionStatus::Restored,
                "absent",
            ),
            (
                "cli-prepared-intended",
                "present",
                false,
                SetupPlanLifecycle::ApplyRestored,
                NativeTransactionStatus::Restored,
                "absent",
            ),
            (
                "cli-committed-intended",
                "present",
                true,
                SetupPlanLifecycle::Applied,
                NativeTransactionStatus::Committed,
                "present",
            ),
        ] {
            let root = unique_temp_path(label);
            let bin = root.join("bin");
            let home = root.join("home");
            let config_root = root.join("claude-config");
            let project = root.join("project");
            let state_path = config_root.join(".claude.json");
            std::fs::create_dir_all(&bin).unwrap();
            std::fs::create_dir_all(&home).unwrap();
            std::fs::create_dir_all(&config_root).unwrap();
            std::fs::create_dir_all(&project).unwrap();
            let home = std::fs::canonicalize(home).unwrap();
            let config_root = std::fs::canonicalize(config_root).unwrap();
            let project = std::fs::canonicalize(project).unwrap();
            let executable = bin.join("claude");
            std::fs::write(
                &executable,
                format!(
                    "#!/bin/sh\ncase \"$*\" in\n  --version) printf '2.1.214 (Claude Code)\\n' ;;\n  'mcp remove context-relay --scope user') printf '{{}}' > '{}' ;;\n  *) exit 9 ;;\nesac\n",
                    state_path.display(),
                ),
            )
            .unwrap();
            std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
            let executable = std::fs::canonicalize(executable).unwrap();
            let bin = executable.parent().unwrap();
            let bridge_executable = bin.join("context-relay-context-mcp");
            let bridge_canary = root.join("bridge-launched");
            std::fs::write(
                &bridge_executable,
                format!(
                    "#!/bin/sh\nprintf launched > '{}'\n",
                    bridge_canary.display()
                ),
            )
            .unwrap();
            std::fs::set_permissions(&bridge_executable, std::fs::Permissions::from_mode(0o700))
                .unwrap();
            let bridge_executable = std::fs::canonicalize(bridge_executable).unwrap();
            let present_state = serde_json::json!({
                "mcpServers": { "context-relay": {
                    "type": "stdio",
                    "command": bridge_executable.to_str().unwrap(),
                    "args": ["--harness", "claude-code"],
                }}
            });
            let absent_state = serde_json::json!({});
            std::fs::write(
                &state_path,
                serde_json::to_vec(if initial == "present" {
                    &present_state
                } else {
                    &absent_state
                })
                .unwrap(),
            )
            .unwrap();
            let _path = EnvironmentOverride::set("PATH", bin.as_os_str());
            let _home = EnvironmentOverride::set("HOME", home.as_os_str());
            let _config = EnvironmentOverride::set("CLAUDE_CONFIG_DIR", config_root.as_os_str());

            let runtime = test_runtime(label);
            let provider = Arc::new(FixedTokenProvider::default());
            let keys = Arc::new(MemoryKeyStore::default());
            let path = root.join("vault.db");
            let (plan_id, transaction_id) = seed_interrupted_bridge_cli_setup(
                &path,
                keys.as_ref(),
                &executable,
                &bridge_executable,
                context_relay_core::native_transaction::CliExecutionContext::ClaudeCodeV2 {
                    config_dir: unit_test_support::wire_native_path(&config_root),
                    state_path: unit_test_support::wire_native_path(
                        &config_root.join(".claude.json"),
                    ),
                    project_root: unit_test_support::wire_native_path(&project),
                    user_home: unit_test_support::wire_native_path(&home),
                },
                committed,
            );

            let daemon = Daemon::start(test_config(
                runtime.clone(),
                path.clone(),
                keys.clone(),
                provider,
            ))
            .await
            .expect("approval-bound CLI WAL recovery must complete before listener bind");
            drop(connect(&runtime).await.expect("listener must be published"));
            drop(daemon);

            let vault = Vault::open(&path, "test-vault-key", keys.as_ref()).unwrap();
            assert_eq!(
                vault.setup_plan(&plan_id).unwrap().unwrap().lifecycle,
                lifecycle,
                "{label}",
            );
            let transaction = vault.native_transaction(&transaction_id).unwrap().unwrap();
            assert_eq!(transaction.status, status, "{label}");
            assert_eq!(
                transaction.sandbox_cleanup_state,
                NativeSandboxCleanupState::Cleaned,
                "{label}",
            );
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&std::fs::read(&state_path).unwrap())
                    .unwrap(),
                if final_state == "present" {
                    present_state
                } else {
                    serde_json::json!({})
                },
                "{label}",
            );
            assert!(!bridge_canary.exists(), "{label}");
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn nonlaunching_macos_cleanup_accepts_only_the_exact_reserved_identity() {
        let exact = nonlaunching_macos_recovery_identity();
        assert_eq!(
            cleanup_recovered_sandbox(
                Path::new("/definitely/missing/native-sandbox"),
                &exact,
                RecoveryOutcome::Restored,
            )
            .unwrap(),
            RecoveryCleanup::Cleaned
        );

        let RecoverySandboxIdentity::Macos {
            generation_id,
            bundle_id,
            mut container,
            guardian_pgid,
            bundle_root,
            signed_digest,
            container_root,
            substate,
            state,
        } = exact
        else {
            unreachable!()
        };
        container.push(0);
        let near_miss = RecoverySandboxIdentity::Macos {
            generation_id,
            bundle_id,
            container,
            guardian_pgid,
            bundle_root,
            signed_digest,
            container_root,
            substate,
            state,
        };
        assert_eq!(
            cleanup_recovered_sandbox(
                Path::new("/definitely/missing/native-sandbox"),
                &near_miss,
                RecoveryOutcome::Restored,
            )
            .unwrap(),
            RecoveryCleanup::Conflict
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_test_runtime_socket_path_stays_within_platform_limit() {
        let endpoint = test_runtime("recover-all-before-bind")
            .endpoint_name()
            .unwrap();

        assert!(endpoint.len() <= 103);
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn production_macos_cleanup_conflict_publishes_and_restart_is_idempotent() {
        use std::os::unix::fs::PermissionsExt;

        let runtime = test_runtime("macos-cleanup-conflict");
        let provider = Arc::new(FixedTokenProvider::default());
        let keys = Arc::new(MemoryKeyStore::default());
        let root = unique_temp_path("macos-cleanup-conflict");
        std::fs::create_dir_all(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let path = root.join("vault.db");
        let private_root = root.join(NATIVE_SANDBOX_DIRECTORY);
        std::fs::create_dir(&private_root).unwrap();
        std::fs::set_permissions(&private_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let transaction_id = uuid::Uuid::now_v7().to_string();
        let plan_id = uuid::Uuid::now_v7().to_string();
        let generation_id = uuid::Uuid::now_v7().simple().to_string();
        seed_terminal_macos_generation(
            &path,
            keys.as_ref(),
            &transaction_id,
            &plan_id,
            &generation_id,
        );

        let daemon = Daemon::start(test_config(
            runtime.clone(),
            path.clone(),
            keys.clone(),
            provider.clone(),
        ))
        .await
        .unwrap();
        drop(connect(&runtime).await.unwrap());
        drop(daemon);

        let vault = Vault::open(&path, "test-vault-key", keys.as_ref()).unwrap();
        let recovered = vault.native_transaction(&transaction_id).unwrap().unwrap();
        assert_eq!(recovered.status, NativeTransactionStatus::Restored);
        assert_eq!(
            recovered.sandbox_cleanup_state,
            NativeSandboxCleanupState::Conflict
        );
        assert_eq!((recovered.current_step, recovered.entered_step), (20, 20));
        assert!(vault.recoverable_native_transactions().unwrap().is_empty());
        drop(vault);

        let daemon = Daemon::start(test_config(
            runtime.clone(),
            path.clone(),
            keys.clone(),
            provider,
        ))
        .await
        .unwrap();
        drop(connect(&runtime).await.unwrap());
        drop(daemon);

        let vault = Vault::open(&path, "test-vault-key", keys.as_ref()).unwrap();
        assert_eq!(
            vault.native_transaction(&transaction_id).unwrap().unwrap(),
            recovered
        );
        assert!(vault.recoverable_native_transactions().unwrap().is_empty());
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[tokio::test]
    async fn invalid_vault_parent_releases_singleton_and_never_publishes_endpoint() {
        let runtime = test_runtime("open-failure");
        let provider = Arc::new(FixedTokenProvider::default());
        let keys = Arc::new(MemoryKeyStore::default());
        let parent = unique_temp_path("open-failure");
        std::fs::write(&parent, b"not a directory").unwrap();
        let path = parent.join("vault.db");
        let config = test_config(runtime.clone(), path, keys, provider);

        assert!(matches!(
            Daemon::start(config).await,
            Err(DaemonError::Startup)
        ));
        assert!(matches!(
            connect(&runtime).await,
            Err(IpcError::EndpointNotFound)
        ));
        drop(InstanceGuard::acquire(&runtime).unwrap());
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[tokio::test]
    async fn dropping_an_unrun_daemon_publishes_stopped_after_releasing_resources() {
        let runtime = test_runtime("unrun-drop-state");
        let provider = Arc::new(FixedTokenProvider::default());
        let keys = Arc::new(MemoryKeyStore::default());
        let path = unique_temp_path("unrun-drop-state").join("vault.db");
        let daemon = Daemon::start(test_config(runtime.clone(), path, keys, provider))
            .await
            .unwrap();
        let handle = daemon.handle();

        drop(daemon);

        assert_eq!(handle.state(), DaemonState::Stopped);
        assert_eq!(handle.shutdown().await, DaemonState::Stopped);
        drop(InstanceGuard::acquire(&runtime).unwrap());
    }

    #[test]
    fn required_task_7_methods_never_use_the_generic_unavailable_error() {
        let fixtures = all_request_fixtures();
        assert_eq!(fixtures.len(), 67);

        for (name, request) in fixtures {
            let routed = route_request(ClientRole::Desktop, request);
            match name {
                "Hello" | "Cancel" => assert_exact_error(routed, invalid_request_error()),
                "Shutdown" => assert!(matches!(routed, RoutedRequest::Shutdown)),
                "Health" => assert!(matches!(routed, RoutedRequest::Health)),
                "McpCall" => assert!(matches!(
                    routed,
                    RoutedRequest::Work(VaultCommand::DesktopMcp(_))
                )),
                _ => assert!(!matches!(
                    routed,
                    RoutedRequest::Immediate(Err(error)) if error == unavailable_error()
                )),
            }
        }
    }

    #[test]
    fn hosted_auth_controls_are_desktop_only_and_bypass_the_vault_worker() {
        let requests = all_request_fixtures()
            .into_iter()
            .filter(|(name, _)| name.starts_with("HostedAuth"))
            .collect::<Vec<_>>();
        assert_eq!(requests.len(), 4);
        for (_, request) in requests {
            assert!(matches!(
                route_request(ClientRole::Desktop, request.clone()),
                RoutedRequest::HostedAuth(_)
            ));
            for role in [
                ClientRole::McpBridge,
                ClientRole::Installer,
                ClientRole::DesktopRecoveryHost,
            ] {
                assert!(
                    matches!(route_request(role, request.clone()), RoutedRequest::Immediate(Err(error)) if error == scope_denied_error())
                );
            }
        }
    }

    #[test]
    fn device_pairing_commands_route_through_the_ordered_vault_worker() {
        for (name, request) in all_request_fixtures()
            .into_iter()
            .filter(|(name, _)| name.starts_with("Pairing"))
        {
            assert!(
                matches!(
                    route_request(ClientRole::Desktop, request),
                    RoutedRequest::Work(VaultCommand::Pairing(_))
                ),
                "{name} bypassed the ordered Vault worker"
            );
        }
    }

    #[test]
    fn recovery_enrollment_commands_are_role_checked_before_the_ordered_vault_worker() {
        let recovery = all_request_fixtures()
            .into_iter()
            .filter(|(name, _)| name.starts_with("Recovery"))
            .collect::<Vec<_>>();
        assert_eq!(recovery.len(), 9);

        for (name, request) in recovery {
            for role in [
                ClientRole::Desktop,
                ClientRole::DesktopRecoveryHost,
                ClientRole::McpBridge,
                ClientRole::Installer,
            ] {
                let allowed = match role {
                    ClientRole::Desktop => matches!(
                        name,
                        "RecoveryEnrollmentOverview"
                            | "RecoveryRestoreOverview"
                            | "RecoveryRestoreResume"
                            | "RecoveryRestoreCancel"
                            | "RecoveryEnrollmentStatus"
                            | "RecoveryEnrollmentCancel"
                    ),
                    ClientRole::DesktopRecoveryHost => matches!(
                        name,
                        "RecoveryEnrollmentBegin"
                            | "RecoveryRestoreBegin"
                            | "RecoveryRestoreOverview"
                            | "RecoveryRestoreResume"
                            | "RecoveryRestoreCancel"
                            | "RecoveryEnrollmentConfirm"
                            | "RecoveryEnrollmentCancel"
                    ),
                    ClientRole::McpBridge | ClientRole::Installer => false,
                };
                let routed = route_request(role, request.clone());
                if allowed {
                    assert!(
                        matches!(routed, RoutedRequest::Work(VaultCommand::Recovery(_))),
                        "{name} did not enter the Vault queue for {role:?}"
                    );
                } else {
                    assert!(
                        matches!(
                            routed,
                            RoutedRequest::Immediate(Err(ClientError {
                                code: ErrorCode::ScopeDenied,
                                ..
                            }))
                        ),
                        "{name} bypassed the role boundary for {role:?}"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn recovery_enrollment_is_stably_unavailable_without_an_injected_service() {
        let path = unique_temp_path("recovery-enrollment-unavailable").join("vault.db");
        let keys = Arc::new(MemoryKeyStore::default());
        let mut worker = VaultWorker::spawn(VaultConfig::new(path, "test-vault-key", keys))
            .await
            .unwrap();
        let error = worker
            .client()
            .try_submit(
                VaultCommand::Recovery(LocalRequest::RecoveryEnrollmentOverview(EmptyParams {})),
                TestAdmission(true),
            )
            .unwrap()
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(
            error,
            ClientError {
                code: ErrorCode::HarnessUnsupported,
                message: "Recovery setup needs the hosted workspace service and is not available in this build.".into(),
                field_path: None,
                retryable: false,
            }
        );
        worker.shutdown_and_join();
    }

    #[tokio::test]
    async fn device_pairing_is_stably_unavailable_without_an_injected_service() {
        let path = unique_temp_path("pairing-unavailable").join("vault.db");
        let keys = Arc::new(MemoryKeyStore::default());
        let mut worker = VaultWorker::spawn(VaultConfig::new(path, "test-vault-key", keys))
            .await
            .unwrap();
        let error = worker
            .client()
            .try_submit(
                VaultCommand::Pairing(LocalRequest::PairingCreate(EmptyParams {})),
                TestAdmission(true),
            )
            .unwrap()
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error, unavailable_error());
        worker.shutdown_and_join();
    }

    #[test]
    fn hosted_pairing_starts_offline_and_requires_login_before_joining() {
        use context_relay_core::auth::{
            HostedSessionOwner, LoginError, LoginStore, StoredLogin, SupabaseAuthClient,
        };
        struct NoLogin;
        impl LoginStore for NoLogin {
            fn load(&self) -> Result<Option<StoredLogin>, LoginError> {
                Ok(None)
            }
            fn save(&self, _: &StoredLogin) -> Result<(), LoginError> {
                Err(LoginError::CredentialStore)
            }
            fn clear(&self) -> Result<(), LoginError> {
                Ok(())
            }
        }
        let owner = Arc::new(HostedSessionOwner::new(
            Arc::new(
                SupabaseAuthClient::new("https://example.supabase.co", "public-test").unwrap(),
            ),
            Arc::new(NoLogin),
        ));
        let identity = PairingIdentity {
            device_id: stable_device_id(b"hosted-pairing-offline"),
            device_name: "Fresh desktop".into(),
            platform: NativePlatform::Windows,
            keys: Arc::new(DeviceKeys::generate().unwrap()),
        };
        let service = pairing::HostedPairingService::new(
            owner,
            "https://example.supabase.co",
            "public-test",
            identity.clone(),
        );
        let path = unique_temp_path("hosted-pairing-offline").join("vault.db");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut vault = Vault::open(&path, "test-vault-key", &MemoryKeyStore::default()).unwrap();
        service.resume_prepared_decisions(&mut vault).unwrap();
        assert_eq!(
            service
                .execute(
                    &mut vault,
                    &identity,
                    LocalRequest::PairingJoin(PairingJoinParams {
                        code: context_relay_protocol::PairingCode::new("ABCDE-FGHJK".into())
                            .unwrap(),
                        device_name: identity.device_name.clone(),
                    })
                )
                .unwrap_err()
                .code,
            ErrorCode::ScopeDenied
        );
        assert!(vault.all_devices().unwrap().is_empty());
        assert!(vault.pending_pairing_approvals().unwrap().is_empty());
    }

    #[test]
    fn hosted_pairing_restarts_exact_join_and_rejects_replaced_login() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use context_relay_core::{
            auth::{
                HostedSessionOwner, LoginError, LoginStore, PendingLogin, StoredLogin,
                SupabaseAuthClient,
            },
            devices::recovery::{RecoveryEnrollmentClock, SystemRecoveryEnrollmentClock},
            sync::{
                SupabaseHttpClient, SupabaseHttpError, SupabaseHttpRequest, SupabaseHttpResponse,
            },
        };
        use serde_json::{Value, json};
        use sha2::{Digest, Sha256};
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        const PROJECT: &str = "https://example.supabase.co";
        const USER: &str = "550e8400-e29b-41d4-a716-446655440000";
        const PAIRING: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074091";
        struct Login;
        impl LoginStore for Login {
            fn load(&self) -> Result<Option<StoredLogin>, LoginError> {
                Ok(None)
            }
            fn save(&self, _: &StoredLogin) -> Result<(), LoginError> {
                Ok(())
            }
            fn clear(&self) -> Result<(), LoginError> {
                Ok(())
            }
        }
        struct Http {
            now: u64,
            replaced: AtomicBool,
            lost: AtomicBool,
            calls: AtomicUsize,
            submitted: Mutex<Vec<String>>,
        }
        impl SupabaseHttpClient for Http {
            fn execute(
                &self,
                request: SupabaseHttpRequest,
            ) -> Result<SupabaseHttpResponse, SupabaseHttpError> {
                let reply = |body: Value| {
                    Ok(SupabaseHttpResponse::new(
                        200,
                        serde_json::to_vec(&body).unwrap(),
                    ))
                };
                if request.url().ends_with("/user") {
                    return reply(json!({"id":USER}));
                }
                if request.url().contains("/auth/v1/token") {
                    let session = if self.replaced.load(Ordering::SeqCst) {
                        "550e8400-e29b-41d4-a716-446655440002"
                    } else {
                        "550e8400-e29b-41d4-a716-446655440001"
                    };
                    let claims = json!({"iss":format!("{PROJECT}/auth/v1"),"aud":"authenticated","sub":USER,"session_id":session,"exp":self.now+3600});
                    return reply(
                        json!({"token_type":"bearer","access_token":format!("e30.{}.signature",URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())),"refresh_token":"synthetic-refresh"}),
                    );
                }
                assert!(request.url().ends_with("/functions/v1/pairing"));
                self.calls.fetch_add(1, Ordering::SeqCst);
                let body: Value = serde_json::from_slice(request.body()).unwrap();
                match body["action"].as_str().unwrap() {
                    "resolve" => {
                        reply(json!({"v":1,"result":{"status":"located","pairingId":PAIRING}}))
                    }
                    "submit" => {
                        let canonical = body["canonicalRequest"].as_str().unwrap();
                        self.submitted.lock().unwrap().push(canonical.into());
                        if self.lost.swap(false, Ordering::SeqCst) {
                            return Err(SupabaseHttpError::Transient);
                        }
                        let bytes: Vec<u8> = canonical
                            .as_bytes()
                            .chunks_exact(2)
                            .map(|pair| {
                                u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()
                            })
                            .collect();
                        reply(
                            json!({"v":1,"receipt":{"pairingId":PAIRING,"requestDigest":format!("{:x}",Sha256::digest(bytes)),"requestedAt":(self.now*1000).to_string()}}),
                        )
                    }
                    "result" => reply(json!({"v":1,"result":{"status":"pending"}})),
                    other => panic!("unexpected pairing action {other}"),
                }
            }
        }
        let now = SystemRecoveryEnrollmentClock.now_ms() / 1000;
        let http = Arc::new(Http {
            now,
            replaced: AtomicBool::new(false),
            lost: AtomicBool::new(true),
            calls: AtomicUsize::new(0),
            submitted: Mutex::new(Vec::new()),
        });
        let owner = Arc::new(HostedSessionOwner::new(
            Arc::new(
                SupabaseAuthClient::with_http_client(PROJECT, "public-test", http.clone()).unwrap(),
            ),
            Arc::new(Login),
        ));
        let login = || {
            let instant = std::time::Instant::now();
            let mut pending =
                PendingLogin::new(PROJECT, "127.0.0.1:41783".parse().unwrap(), instant).unwrap();
            let url = pending.authorization_url();
            let redirect = url
                .query_pairs()
                .find(|(key, _)| key == "redirect_to")
                .unwrap()
                .1
                .into_owned();
            let mut callback = url.join(&redirect).unwrap();
            callback
                .query_pairs_mut()
                .append_pair("code", "synthetic-code");
            owner
                .complete_login(
                    owner.begin_login().unwrap(),
                    pending.take_callback(&callback, instant).unwrap(),
                    now,
                )
                .unwrap();
        };
        login();
        let identity = PairingIdentity {
            device_id: stable_device_id(b"hosted-pairing-restart"),
            device_name: "Fresh desktop".into(),
            platform: NativePlatform::Windows,
            keys: Arc::new(DeviceKeys::generate().unwrap()),
        };
        let make = || {
            let mut service = pairing::HostedPairingService::new(
                owner.clone(),
                PROJECT,
                "public-test",
                identity.clone(),
            );
            service.http = Some(http.clone());
            service
        };
        let path = unique_temp_path("hosted-pairing-restart").join("vault.db");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let keys = MemoryKeyStore::default();
        let mut vault = Vault::open(&path, "test-vault-key", &keys).unwrap();
        let service = make();
        assert!(
            service
                .execute(
                    &mut vault,
                    &identity,
                    LocalRequest::PairingCreate(EmptyParams {})
                )
                .is_err()
        );
        assert_eq!(http.calls.load(Ordering::SeqCst), 0);
        let join = || {
            LocalRequest::PairingJoin(PairingJoinParams {
                code: context_relay_protocol::PairingCode::new("ABCDE-FGHJK".into()).unwrap(),
                device_name: identity.device_name.clone(),
            })
        };
        assert!(service.execute(&mut vault, &identity, join()).is_err());
        let saved = vault
            .hosted_pairing_intent(PAIRING.parse().unwrap())
            .unwrap()
            .unwrap();
        drop(vault);
        let mut vault = Vault::open(&path, "test-vault-key", &keys).unwrap();
        let service = make();
        service.resume_prepared_decisions(&mut vault).unwrap();
        assert!(matches!(
            service.execute(&mut vault, &identity, join()).unwrap(),
            LocalResult::PairingRequest {
                status: PairingState::Pending,
                ..
            }
        ));
        let requests = http.submitted.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0], requests[1]);
        drop(requests);
        let status = || {
            LocalRequest::PairingStatus(PairingIdParams {
                pairing_id: PAIRING.parse().unwrap(),
            })
        };
        assert!(service.execute(&mut vault, &identity, status()).is_ok());
        let calls = http.calls.load(Ordering::SeqCst);
        let stored = vault
            .stored_pairing_join(PAIRING.parse().unwrap())
            .unwrap()
            .unwrap();
        assert!(
            service
                .execute(
                    &mut vault,
                    &identity,
                    LocalRequest::PairingDecision(PairingDecisionParams {
                        pairing_id: PAIRING.parse().unwrap(),
                        request_digest: stored.request_sha256,
                        approve: true,
                    })
                )
                .is_err()
        );
        let mut wrong_keys = identity.clone();
        wrong_keys.keys = Arc::new(DeviceKeys::generate().unwrap());
        assert!(service.execute(&mut vault, &wrong_keys, status()).is_err());
        let mut other_project = pairing::HostedPairingService::new(
            owner.clone(),
            "https://other.supabase.co",
            "public-test",
            identity.clone(),
        );
        other_project.http = Some(http.clone());
        assert!(
            other_project
                .execute(&mut vault, &identity, status())
                .is_err()
        );
        assert_eq!(http.calls.load(Ordering::SeqCst), calls);
        owner.begin_login().unwrap();
        assert!(service.execute(&mut vault, &identity, status()).is_err());
        http.replaced.store(true, Ordering::SeqCst);
        login();
        assert!(service.execute(&mut vault, &identity, status()).is_err());
        assert_eq!(http.calls.load(Ordering::SeqCst), calls);
        assert_eq!(
            vault
                .hosted_pairing_intent(PAIRING.parse().unwrap())
                .unwrap(),
            Some(saved)
        );
        assert!(vault.all_devices().unwrap().is_empty());
    }

    #[tokio::test]
    async fn device_list_remains_visible_without_an_injected_pairing_service() {
        let path = unique_temp_path("pairing-unavailable-device-list").join("vault.db");
        let keys = Arc::new(MemoryKeyStore::default());
        let account_id = "018f22e2-79b0-7cc8-98c4-dc0c0c074201"
            .parse::<AccountId>()
            .unwrap();
        let workspace_id = "018f22e2-79b0-7cc8-98c4-dc0c0c074202"
            .parse::<WorkspaceId>()
            .unwrap();
        let certificate_id = "018f22e2-79b0-7cc8-98c4-dc0c0c074203"
            .parse::<DeviceCertificateId>()
            .unwrap();
        let device_id = stable_device_id(b"pairing-unavailable-listed-device");
        let device_keys = DeviceKeys::generate().unwrap();
        let mut recovery_words = vec!["abandon".to_owned(); 23];
        recovery_words.push("art".to_owned());
        let recovery = RecoveryKeys::derive(
            &RecoveryPhrase::from_words(RecoveryPhraseWords::new(recovery_words).unwrap()).unwrap(),
        )
        .unwrap();
        let certificate = DeviceCertificateV1::issue_genesis(
            CertificateFieldsV1 {
                account_id,
                workspace_id,
                control_epoch: 1,
                request_nonce: PairingRequestNonce([0x42; 32]),
                device_id,
                signing_public_key: device_keys.signing_public_key(),
                wrapping_public_key: device_keys.wrapping_public_key(),
            },
            &recovery,
        )
        .unwrap();
        let recovery: StartupRecovery = Arc::new(move |vault| {
            vault
                .store_device_certificate(
                    certificate_id,
                    &certificate,
                    DeviceCertificateState::Active,
                    &DeviceDisplayMetadata {
                        device_name: "Trusted Offline Mac".into(),
                        platform: NativePlatform::Macos,
                    },
                    1,
                )
                .map_err(|_| DaemonError::Startup)?;
            Ok(())
        });
        let config = VaultConfig::new(path, "test-vault-key", keys)
            .with_device_id(device_id)
            .with_startup_recovery(recovery);
        let mut worker = VaultWorker::spawn(config).await.unwrap();

        let LocalResult::Devices { devices } = worker
            .client()
            .try_submit(
                VaultCommand::Workspace(LocalRequest::DevicesList(EmptyParams {})),
                TestAdmission(true),
            )
            .unwrap()
            .await
            .unwrap()
            .unwrap()
        else {
            panic!("expected device list")
        };
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_id, device_id);
        assert_eq!(devices[0].name, "Trusted Offline Mac");
        assert_eq!(
            devices[0].state,
            context_relay_protocol::DeviceState::Active
        );
        assert!(devices[0].is_current);
        worker.shutdown_and_join();
    }

    #[tokio::test]
    async fn device_pairing_obeys_the_single_writer_queue_limit() {
        let path = unique_temp_path("pairing-queue").join("vault.db");
        let keys = Arc::new(MemoryKeyStore::default());
        let mut worker = VaultWorker::spawn(VaultConfig::new(path, "test-vault-key", keys))
            .await
            .unwrap();
        let client = worker.client();
        let (entered_sender, entered_receiver) = std::sync::mpsc::sync_channel(1);
        let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(1);
        let blocked = client
            .try_submit(
                VaultCommand::TestBlock {
                    entered: entered_sender,
                    release: release_receiver,
                },
                TestAdmission(true),
            )
            .unwrap();
        entered_receiver.recv().unwrap();

        let mut queued = Vec::with_capacity(REQUEST_QUEUE_CAPACITY);
        for _ in 0..REQUEST_QUEUE_CAPACITY {
            queued.push(
                client
                    .try_submit(
                        VaultCommand::Pairing(LocalRequest::PairingCreate(EmptyParams {})),
                        TestAdmission(true),
                    )
                    .unwrap(),
            );
        }
        let error = client
            .try_submit(
                VaultCommand::Pairing(LocalRequest::PairingCreate(EmptyParams {})),
                TestAdmission(true),
            )
            .unwrap_err();
        assert_eq!(error, busy_error());

        release_sender.send(()).unwrap();
        assert_eq!(blocked.await.unwrap().unwrap(), LocalResult::Empty);
        for response in queued {
            assert_eq!(response.await.unwrap().unwrap_err(), unavailable_error());
        }
        worker.shutdown_and_join();
    }

    #[tokio::test]
    async fn device_pairing_restart_recovers_before_admitting_the_next_command() {
        let path = unique_temp_path("pairing-restart-order").join("vault.db");
        let keys = Arc::new(MemoryKeyStore::default());
        let identities = Arc::new(MemoryDeviceIdentityStore::default());
        let service = Arc::new(ResumeBeforeExecutePairingService::default());

        for expected_resume_count in 1..=2 {
            let config = VaultConfig::new(path.clone(), "test-vault-key", keys.clone())
                .with_pairing_service(
                    service.clone(),
                    identities.clone(),
                    "pairing-restart-identity",
                    "Restarted Mac",
                    NativePlatform::Macos,
                );
            let mut worker = VaultWorker::spawn(config).await.unwrap();
            assert_eq!(
                service.resumes.load(Ordering::SeqCst),
                expected_resume_count
            );
            assert_eq!(
                worker
                    .client()
                    .try_submit(
                        VaultCommand::Pairing(LocalRequest::PairingCreate(EmptyParams {})),
                        TestAdmission(true),
                    )
                    .unwrap()
                    .await
                    .unwrap()
                    .unwrap(),
                LocalResult::Empty
            );
            worker.shutdown_and_join();
        }
    }

    #[tokio::test]
    async fn recovery_restart_resumes_before_queue_and_reuses_the_protected_identity() {
        let path = unique_temp_path("recovery-restart-order").join("vault.db");
        let keys = Arc::new(MemoryKeyStore::default());
        let identities = Arc::new(MemoryDeviceIdentityStore::default());
        let mut first_signing_key = None;

        for expected_resume_count in 1..=2 {
            let service = Arc::new(ResumeBeforeExecuteRecoveryService::default());
            let config = VaultConfig::new(path.clone(), "test-vault-key", keys.clone())
                .with_recovery_enrollment_service(
                    service.clone(),
                    identities.clone(),
                    "recovery-restart-identity",
                    "Restarted Mac",
                    NativePlatform::Macos,
                );
            let mut worker = VaultWorker::spawn(config).await.unwrap();
            assert_eq!(service.resumes.load(Ordering::SeqCst), 1);
            assert_eq!(
                worker
                    .client()
                    .try_submit(
                        VaultCommand::Recovery(LocalRequest::RecoveryEnrollmentOverview(
                            EmptyParams {},
                        )),
                        TestAdmission(true),
                    )
                    .unwrap()
                    .await
                    .unwrap()
                    .unwrap(),
                LocalResult::RecoveryEnrollmentStatus {
                    status: context_relay_protocol::RecoveryEnrollmentStatus {
                        enrollment_id: None,
                        state: context_relay_protocol::RecoveryEnrollmentState::Idle,
                        created_at_ms: None,
                        transitioned_at_ms: None,
                    },
                }
            );
            assert_eq!(service.executes.load(Ordering::SeqCst), 1);
            let signing_key = *service.signing_public_key.lock().unwrap();
            if expected_resume_count == 1 {
                first_signing_key = signing_key;
            } else {
                assert_eq!(signing_key, first_signing_key);
            }
            worker.shutdown_and_join();
        }
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[tokio::test]
    async fn transient_recovery_resume_fails_before_listener_and_releases_the_guard() {
        let runtime = test_runtime("recovery-resume-transient");
        let path = unique_temp_path("recovery-resume-transient").join("vault.db");
        let vault = VaultConfig::new(path, "test-vault-key", Arc::new(MemoryKeyStore::default()))
            .with_recovery_enrollment_service(
                Arc::new(TransientResumeRecoveryService),
                Arc::new(MemoryDeviceIdentityStore::default()),
                "recovery-resume-transient-identity",
                "Transient Mac",
                NativePlatform::Macos,
            );
        assert!(matches!(
            Daemon::start(DaemonConfig::new(
                runtime.clone(),
                vault,
                Arc::new(FixedTokenProvider::default()),
            ))
            .await,
            Err(DaemonError::Startup)
        ));
        drop(InstanceGuard::acquire(&runtime).unwrap());
        assert!(matches!(
            connect(&runtime).await,
            Err(IpcError::EndpointNotFound)
        ));
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[tokio::test]
    async fn daemon_startup_holds_guard_then_loads_identity_vault_recovery_and_pairing() {
        let runtime = test_runtime("recovery-startup-order");
        let path = unique_temp_path("recovery-startup-order").join("vault.db");
        let events = Arc::new(Mutex::new(Vec::new()));
        let identity_store = Arc::new(OrderedIdentityStore {
            values: Mutex::new(HashMap::new()),
            events: events.clone(),
            runtime: runtime.clone(),
        });
        let keys = Arc::new(OrderedKeyStore {
            value: Mutex::new(None),
            events: events.clone(),
        });
        let vault = VaultConfig::new(path, "test-vault-key", keys)
            .with_pairing_service(
                Arc::new(OrderedPairingService {
                    events: events.clone(),
                }),
                identity_store.clone(),
                "ordered-device-identity",
                "Ordered Mac",
                NativePlatform::Macos,
            )
            .with_recovery_enrollment_service(
                Arc::new(OrderedRecoveryService {
                    events: events.clone(),
                }),
                identity_store,
                "ordered-device-identity",
                "Ordered Mac",
                NativePlatform::Macos,
            );
        let daemon = Daemon::start(DaemonConfig::new(
            runtime.clone(),
            vault,
            Arc::new(FixedTokenProvider::default()),
        ))
        .await
        .unwrap();
        events.lock().unwrap().push("listener");
        assert_eq!(
            events.lock().unwrap().as_slice(),
            ["identity", "vault", "recovery", "pairing", "listener"]
        );
        drop(daemon);
        drop(InstanceGuard::acquire(&runtime).unwrap());
    }

    #[test]
    fn device_pairing_invite_status_survives_service_reconstruction_without_the_code() {
        let account_id = "018f22e2-79b0-7cc8-98c4-dc0c0c074301"
            .parse::<AccountId>()
            .unwrap();
        let workspace_id = "018f22e2-79b0-7cc8-98c4-dc0c0c074302"
            .parse::<WorkspaceId>()
            .unwrap();
        let issuer_certificate_id = "018f22e2-79b0-7cc8-98c4-dc0c0c074303"
            .parse::<DeviceCertificateId>()
            .unwrap();
        let scope = SyncScope {
            account_id,
            workspace_id,
        };
        let device_id = stable_device_id(b"pairing-invite-restart-device");
        let provider = InMemoryPairingProvider::new().unwrap();
        let clock = PairingTestClock::default();
        clock.set(1_000);
        let material_source = PairingTestMaterialSource {
            scope,
            workspace_root_key: [0x31; 32],
            active_epoch_key: [0x47; 32],
        };
        let identity = PairingIdentity {
            device_id,
            device_name: "Restarted Approver".into(),
            platform: NativePlatform::Macos,
            keys: Arc::new(DeviceKeys::generate().unwrap()),
        };
        let path = unique_temp_path("pairing-invite-restart").join("vault.db");
        let vault_keys = MemoryKeyStore::default();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut vault = Vault::open(&path, "test-vault-key", &vault_keys).unwrap();
        let service = pairing::CoordinatorPairingService::new(
            PairingCoordinator::new(
                clock.clone(),
                material_source.clone(),
                UnavailablePairingJoin,
                provider.existing_device_client(scope, device_id),
            ),
            scope,
            issuer_certificate_id,
        );
        let LocalResult::PairingInvite { invite, .. } = service
            .execute(
                &mut vault,
                &identity,
                LocalRequest::PairingCreate(EmptyParams {}),
            )
            .unwrap()
        else {
            panic!("expected pairing invite")
        };
        let raw_code = invite.code.as_str().to_owned();
        drop(service);

        let restored = pairing::CoordinatorPairingService::new(
            PairingCoordinator::new(
                clock.clone(),
                material_source.clone(),
                UnavailablePairingJoin,
                provider.existing_device_client(scope, device_id),
            ),
            scope,
            issuer_certificate_id,
        );
        let status = restored
            .execute(
                &mut vault,
                &identity,
                LocalRequest::PairingStatus(PairingIdParams {
                    pairing_id: invite.pairing_id,
                }),
            )
            .unwrap();
        let LocalResult::PairingInviteStatus {
            invite: restored_invite,
            status: PairingState::Pending,
        } = &status
        else {
            panic!("expected code-free invite status")
        };
        assert_eq!(restored_invite.pairing_id, invite.pairing_id);
        assert_eq!(restored_invite.created_at, invite.created_at);
        assert_eq!(restored_invite.expires_at, invite.expires_at);
        assert!(!serde_json::to_string(&status).unwrap().contains(&raw_code));

        assert_eq!(
            restored
                .execute(
                    &mut vault,
                    &identity,
                    LocalRequest::PairingCancel(PairingIdParams {
                        pairing_id: invite.pairing_id,
                    }),
                )
                .unwrap(),
            LocalResult::Empty
        );
        drop(restored);
        let after_cancel = pairing::CoordinatorPairingService::new(
            PairingCoordinator::new(
                clock,
                material_source,
                UnavailablePairingJoin,
                provider.existing_device_client(scope, device_id),
            ),
            scope,
            issuer_certificate_id,
        );
        assert!(matches!(
            after_cancel
                .execute(
                    &mut vault,
                    &identity,
                    LocalRequest::PairingStatus(PairingIdParams {
                        pairing_id: invite.pairing_id,
                    }),
                )
                .unwrap(),
            LocalResult::PairingInviteStatus {
                status: PairingState::Canceled,
                ..
            }
        ));
    }

    #[test]
    fn device_pairing_rejected_status_stays_terminal_after_service_reconstruction() {
        let account_id = "018f22e2-79b0-7cc8-98c4-dc0c0c074401"
            .parse::<AccountId>()
            .unwrap();
        let workspace_id = "018f22e2-79b0-7cc8-98c4-dc0c0c074402"
            .parse::<WorkspaceId>()
            .unwrap();
        let issuer_certificate_id = "018f22e2-79b0-7cc8-98c4-dc0c0c074403"
            .parse::<DeviceCertificateId>()
            .unwrap();
        let scope = SyncScope {
            account_id,
            workspace_id,
        };
        let approver_device_id = stable_device_id(b"pairing-rejected-approver");
        let joiner_device_id = stable_device_id(b"pairing-rejected-joiner");
        let provider = InMemoryPairingProvider::new().unwrap();
        let clock = PairingTestClock::default();
        clock.set(2_000);
        let material_source = PairingTestMaterialSource {
            scope,
            workspace_root_key: [0x51; 32],
            active_epoch_key: [0x61; 32],
        };
        let approver_identity = PairingIdentity {
            device_id: approver_device_id,
            device_name: "Approver".into(),
            platform: NativePlatform::Macos,
            keys: Arc::new(DeviceKeys::generate().unwrap()),
        };
        let joiner_keys = DeviceKeys::generate().unwrap();
        let approver_path = unique_temp_path("pairing-rejected-approver").join("vault.db");
        let joiner_path = unique_temp_path("pairing-rejected-joiner").join("vault.db");
        std::fs::create_dir_all(approver_path.parent().unwrap()).unwrap();
        std::fs::create_dir_all(joiner_path.parent().unwrap()).unwrap();
        let approver_store = MemoryKeyStore::default();
        let joiner_store = MemoryKeyStore::default();
        let mut approver_vault =
            Vault::open(&approver_path, "approver-vault-key", &approver_store).unwrap();
        let mut joiner_vault =
            Vault::open(&joiner_path, "joiner-vault-key", &joiner_store).unwrap();
        let service = pairing::CoordinatorPairingService::new(
            PairingCoordinator::new(
                clock.clone(),
                material_source.clone(),
                UnavailablePairingJoin,
                provider.existing_device_client(scope, approver_device_id),
            ),
            scope,
            issuer_certificate_id,
        );
        let LocalResult::PairingInvite { invite, .. } = service
            .execute(
                &mut approver_vault,
                &approver_identity,
                LocalRequest::PairingCreate(EmptyParams {}),
            )
            .unwrap()
        else {
            panic!("expected pairing invite")
        };
        let joiner = PairingCoordinator::new(
            clock.clone(),
            material_source.clone(),
            provider.join_session_client("rejected-joiner").unwrap(),
            UnavailablePairingApproval,
        );
        clock.set(2_001);
        joiner
            .join(
                &mut joiner_vault,
                &invite.code,
                joiner_device_id,
                "Rejected Joiner",
                NativePlatform::Macos,
                &joiner_keys,
            )
            .unwrap();
        let LocalResult::PairingRequest { request, .. } = service
            .execute(
                &mut approver_vault,
                &approver_identity,
                LocalRequest::PairingStatus(PairingIdParams {
                    pairing_id: invite.pairing_id,
                }),
            )
            .unwrap()
        else {
            panic!("expected pairing request")
        };
        assert!(matches!(
            service
                .execute(
                    &mut approver_vault,
                    &approver_identity,
                    LocalRequest::PairingDecision(PairingDecisionParams {
                        pairing_id: invite.pairing_id,
                        request_digest: request.request_digest,
                        approve: false,
                    }),
                )
                .unwrap(),
            LocalResult::PairingRequest {
                status: PairingState::Rejected,
                ..
            }
        ));
        drop(service);

        let restored = pairing::CoordinatorPairingService::new(
            PairingCoordinator::new(
                clock,
                material_source,
                UnavailablePairingJoin,
                provider.existing_device_client(scope, approver_device_id),
            ),
            scope,
            issuer_certificate_id,
        );
        assert!(matches!(
            restored
                .execute(
                    &mut approver_vault,
                    &approver_identity,
                    LocalRequest::PairingStatus(PairingIdParams {
                        pairing_id: invite.pairing_id,
                    }),
                )
                .unwrap(),
            LocalResult::PairingRequest {
                status: PairingState::Rejected,
                ..
            }
        ));
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[tokio::test]
    async fn device_pairing_crosses_two_authenticated_daemons_without_exposing_joiner_safety() {
        let account_id = "018f22e2-79b0-7cc8-98c4-dc0c0c074101"
            .parse::<AccountId>()
            .unwrap();
        let workspace_id = "018f22e2-79b0-7cc8-98c4-dc0c0c074102"
            .parse::<WorkspaceId>()
            .unwrap();
        let scope = SyncScope {
            account_id,
            workspace_id,
        };
        let approver_token = [0x5a; 32];
        let joiner_token = [0x6b; 32];
        let approver_device_id = stable_device_id(&approver_token);
        let joiner_device_id = stable_device_id(&joiner_token);
        let approver_runtime = test_runtime("pairing-approver");
        let joiner_runtime = test_runtime("pairing-joiner");
        let approver_path = unique_temp_path("pairing-approver").join("vault.db");
        let joiner_path = unique_temp_path("pairing-joiner").join("vault.db");
        let approver_vault_keys = Arc::new(MemoryKeyStore::default());
        let joiner_vault_keys = Arc::new(MemoryKeyStore::default());
        let approver_identity_store = Arc::new(MemoryDeviceIdentityStore::default());
        let joiner_identity_store = Arc::new(MemoryDeviceIdentityStore::default());
        let recovery_clock = PairingTestClock::default();
        recovery_clock.set(900);
        let recovery_transport = RecoveryTestTransport::new(scope);
        let recovery_service: Arc<dyn RecoveryEnrollmentService> = Arc::new(
            recovery_enrollment::CoordinatorRecoveryEnrollmentService::new(
                RecoveryEnrollmentCoordinator::new(
                    recovery_clock.clone(),
                    recovery_transport.clone(),
                ),
                approver_device_id,
                "Approving Mac",
                NativePlatform::Macos,
            ),
        );
        let recovery_daemon = Daemon::start(DaemonConfig::new(
            approver_runtime.clone(),
            VaultConfig::new(
                approver_path.clone(),
                "test-vault-key",
                approver_vault_keys.clone(),
            )
            .with_recovery_enrollment_service(
                recovery_service,
                approver_identity_store.clone(),
                "pairing-approver-identity",
                "Approving Mac",
                NativePlatform::Macos,
            ),
            Arc::new(PairingTokenProvider(approver_token)),
        ))
        .await
        .unwrap();
        let recovery_handle = recovery_daemon.handle();
        let recovery_owner = tokio::spawn(recovery_daemon.run());
        let mut recovery_host = RawClient::connect_with_token(
            &approver_runtime,
            ClientRole::DesktopRecoveryHost,
            approver_token,
        )
        .await;
        let LocalResult::RecoveryEnrollmentPhrase { phrase } = recovery_host
            .call(LocalRequest::RecoveryEnrollmentBegin(EmptyParams {}))
            .await
            .unwrap()
        else {
            panic!("expected recovery phrase")
        };
        recovery_clock.set(950);
        let confirmations = phrase
            .confirmation_positions
            .iter()
            .map(
                |position| context_relay_protocol::RecoveryWordConfirmation {
                    position: *position,
                    word: phrase.recovery_phrase_words.as_words()[usize::from(*position) - 1]
                        .clone(),
                },
            )
            .collect();
        assert!(matches!(
            recovery_host
                .call(LocalRequest::RecoveryEnrollmentConfirm(
                    context_relay_protocol::RecoveryEnrollmentConfirmParams {
                        enrollment_id: phrase.enrollment_id,
                        confirmations,
                    },
                ))
                .await
                .unwrap(),
            LocalResult::RecoveryEnrollmentComplete { .. }
        ));
        drop(recovery_host);
        assert_eq!(recovery_handle.shutdown().await, DaemonState::Stopped);
        assert_eq!(recovery_owner.await.unwrap(), Ok(()));

        let enrollment = Vault::open(
            &approver_path,
            "test-vault-key",
            approver_vault_keys.as_ref(),
        )
        .unwrap()
        .recovery_enrollment()
        .unwrap()
        .unwrap();
        let issuer_certificate_id = enrollment.record.genesis_certificate_id;
        let approver_keys = load_or_create_device_keys(
            approver_identity_store.as_ref(),
            "pairing-approver-identity",
        )
        .unwrap();

        let provider = InMemoryPairingProvider::new().unwrap();
        let clock = PairingTestClock::default();
        clock.set(1_000);
        let approver_service: Arc<dyn PairingService> =
            Arc::new(pairing::CoordinatorPairingService::new(
                PairingCoordinator::new(
                    clock.clone(),
                    VaultPairingMaterialSource,
                    UnavailablePairingJoin,
                    provider.existing_device_client(scope, approver_device_id),
                ),
                scope,
                issuer_certificate_id,
            ));
        let joiner_service: Arc<dyn PairingService> = Arc::new(
            pairing::CoordinatorPairingService::new_joiner(PairingCoordinator::new(
                clock.clone(),
                VaultPairingMaterialSource,
                provider
                    .join_session_client("contextd-joining-device")
                    .unwrap(),
                UnavailablePairingApproval,
            )),
        );
        let approver_config = DaemonConfig::new(
            approver_runtime.clone(),
            VaultConfig::new(
                approver_path.clone(),
                "test-vault-key",
                approver_vault_keys.clone(),
            )
            .with_pairing_service(
                approver_service,
                approver_identity_store.clone(),
                "pairing-approver-identity",
                "Approving Mac",
                NativePlatform::Macos,
            ),
            Arc::new(PairingTokenProvider(approver_token)),
        );
        let joiner_config = DaemonConfig::new(
            joiner_runtime.clone(),
            VaultConfig::new(
                joiner_path.clone(),
                "test-vault-key",
                joiner_vault_keys.clone(),
            )
            .with_pairing_service(
                joiner_service,
                joiner_identity_store.clone(),
                "pairing-joiner-identity",
                "Joining Mac",
                NativePlatform::Macos,
            ),
            Arc::new(PairingTokenProvider(joiner_token)),
        );
        let approver_daemon = Daemon::start(approver_config).await.unwrap();
        let approver_handle = approver_daemon.handle();
        let approver_owner = tokio::spawn(approver_daemon.run());
        let joiner_daemon = Daemon::start(joiner_config).await.unwrap();
        let joiner_handle = joiner_daemon.handle();
        let joiner_owner = tokio::spawn(joiner_daemon.run());
        let mut approver =
            RawClient::connect_with_token(&approver_runtime, ClientRole::Desktop, approver_token)
                .await;
        let mut joiner =
            RawClient::connect_with_token(&joiner_runtime, ClientRole::Desktop, joiner_token).await;

        let LocalResult::PairingInvite { invite, status } = approver
            .call(LocalRequest::PairingCreate(EmptyParams {}))
            .await
            .unwrap()
        else {
            panic!("expected pairing invite")
        };
        assert_eq!(status, PairingState::Pending);
        clock.set(1_001);
        for request in [
            LocalRequest::PairingCreate(EmptyParams {}),
            LocalRequest::PairingCancel(PairingIdParams {
                pairing_id: invite.pairing_id,
            }),
            LocalRequest::PairingStatus(PairingIdParams {
                pairing_id: invite.pairing_id,
            }),
        ] {
            assert_eq!(
                joiner.call(request).await.unwrap_err().code,
                ErrorCode::InvalidRequest
            );
        }
        let LocalResult::PairingRequest {
            request: submitted,
            status,
        } = joiner
            .call(LocalRequest::PairingJoin(PairingJoinParams {
                code: invite.code.clone(),
                device_name: "Joining Mac".into(),
            }))
            .await
            .unwrap()
        else {
            panic!("expected submitted pairing request")
        };
        assert_eq!(status, PairingState::Pending);
        assert_eq!(submitted.pairing_id, invite.pairing_id);
        assert_eq!(submitted.platform, NativePlatform::Macos);
        assert_eq!(
            joiner
                .call(LocalRequest::PairingDecision(PairingDecisionParams {
                    pairing_id: invite.pairing_id,
                    request_digest: submitted.request_digest,
                    approve: true,
                }))
                .await
                .unwrap_err()
                .code,
            ErrorCode::InvalidRequest
        );

        clock.set(1_002);
        let LocalResult::PairingRequest {
            request: review,
            status,
        } = approver
            .call(LocalRequest::PairingStatus(PairingIdParams {
                pairing_id: invite.pairing_id,
            }))
            .await
            .unwrap()
        else {
            panic!("expected approver review")
        };
        assert_eq!(status, PairingState::Pending);
        assert_eq!(review.request_digest, submitted.request_digest);
        clock.set(1_003);
        let LocalResult::PairingApproval { approval } = approver
            .call(LocalRequest::PairingDecision(PairingDecisionParams {
                pairing_id: invite.pairing_id,
                request_digest: review.request_digest,
                approve: true,
            }))
            .await
            .unwrap()
        else {
            panic!("expected approver safety number")
        };

        clock.set(1_004);
        let joiner_status = joiner
            .call(LocalRequest::PairingStatus(PairingIdParams {
                pairing_id: invite.pairing_id,
            }))
            .await
            .unwrap();
        assert!(matches!(
            joiner_status,
            LocalResult::PairingRequest {
                status: PairingState::Approved,
                ..
            }
        ));
        assert!(
            !serde_json::to_string(&joiner_status)
                .unwrap()
                .contains(approval.safety_number.as_str())
        );

        clock.set(1_005);
        let LocalResult::PairingCompletion { completion } = joiner
            .call(LocalRequest::PairingConfirm(PairingConfirmParams {
                pairing_id: invite.pairing_id,
                safety_number: approval.safety_number,
            }))
            .await
            .unwrap()
        else {
            panic!("expected atomic pairing completion")
        };
        assert_eq!(completion.device.device_id, joiner_device_id);
        assert!(completion.device.is_current);

        let mut bridge =
            RawClient::connect_with_token(&approver_runtime, ClientRole::McpBridge, approver_token)
                .await;
        assert_eq!(
            bridge
                .call(LocalRequest::PairingCreate(EmptyParams {}))
                .await
                .unwrap_err()
                .code,
            ErrorCode::ScopeDenied
        );

        drop((approver, joiner, bridge));
        assert_eq!(approver_handle.shutdown().await, DaemonState::Stopped);
        assert_eq!(joiner_handle.shutdown().await, DaemonState::Stopped);
        assert_eq!(approver_owner.await.unwrap(), Ok(()));
        assert_eq!(joiner_owner.await.unwrap(), Ok(()));

        let joiner_keys =
            load_or_create_device_keys(joiner_identity_store.as_ref(), "pairing-joiner-identity")
                .unwrap();
        let mut approver_vault = Vault::open(
            &approver_path,
            "test-vault-key",
            approver_vault_keys.as_ref(),
        )
        .unwrap();
        let joiner_vault =
            Vault::open(&joiner_path, "test-vault-key", joiner_vault_keys.as_ref()).unwrap();
        assert_eq!(approver_vault.devices(scope).unwrap().len(), 2);
        assert_eq!(joiner_vault.devices(scope).unwrap().len(), 2);
        let enrolled = approver_vault
            .enrolled_workspace_material(&approver_keys)
            .unwrap();
        let offline_service = pairing::CoordinatorPairingService::new(
            PairingCoordinator::new(
                clock.clone(),
                VaultPairingMaterialSource,
                UnavailablePairingJoin,
                UnavailablePairingApproval,
            ),
            scope,
            issuer_certificate_id,
        );
        let offline_identity = PairingIdentity {
            device_id: approver_device_id,
            device_name: "Approving Mac".into(),
            platform: NativePlatform::Macos,
            keys: Arc::new(approver_keys),
        };
        for request in [
            LocalRequest::PairingStatus(PairingIdParams {
                pairing_id: invite.pairing_id,
            }),
            LocalRequest::PairingDecision(PairingDecisionParams {
                pairing_id: invite.pairing_id,
                request_digest: review.request_digest,
                approve: true,
            }),
        ] {
            let LocalResult::PairingApproval {
                approval: offline_approval,
            } = offline_service
                .execute(&mut approver_vault, &offline_identity, request)
                .unwrap()
            else {
                panic!("expected local accepted approval")
            };
            assert_eq!(offline_approval.request, review);
        }
        let reopened = PairingCoordinator::new(
            clock,
            VaultPairingMaterialSource,
            provider
                .join_session_client("contextd-joining-device")
                .unwrap(),
            provider.existing_device_client(scope, approver_device_id),
        )
        .completed_material(&joiner_vault, invite.pairing_id, &joiner_keys)
        .unwrap()
        .unwrap();
        assert_eq!(enrolled.scope(), reopened.scope());
        assert_eq!(enrolled.control_epoch(), reopened.control_epoch());
        assert_eq!(enrolled.key_epoch(), reopened.key_epoch());
        assert_eq!(enrolled.workspace_root_key(), reopened.workspace_root_key());
        assert_eq!(enrolled.active_epoch_key(), reopened.active_epoch_key());
    }

    #[test]
    fn mcp_call_routes_through_the_ordered_vault_workspace() {
        let request = request_fixture(
            "mcp_call",
            serde_json::json!({
                "binding": {
                    "harness": "codex",
                    "workingDirectory": {
                        "platform": "macos",
                        "bytes": "L3dvcmtzcGFjZQ",
                        "display": "/workspace",
                    },
                },
                "name": "context_relay_status",
                "arguments": {},
            }),
        );

        let RoutedRequest::Work(VaultCommand::Workspace(LocalRequest::McpCall(params))) =
            route_request(ClientRole::McpBridge, request)
        else {
            panic!("MCP call did not enter the ordered vault workspace")
        };
        assert_eq!(params.name, "context_relay_status");
        assert_eq!(params.arguments, serde_json::json!({}));
    }

    #[test]
    fn native_hook_event_routes_through_the_ordered_vault_workspace() {
        let request = request_fixture(
            "native_hook_event",
            serde_json::json!({
                "binding": {
                    "harness": "codex",
                    "workingDirectory": {
                        "platform": "macos",
                        "bytes": "L3dvcmtzcGFjZQ",
                        "display": "/workspace",
                    },
                },
                "event": {"kind": "session_start", "session_id": "session-1"},
                "occurredAtMs": "1700000000123",
            }),
        );

        let RoutedRequest::Work(VaultCommand::Workspace(LocalRequest::NativeHookEvent(params))) =
            route_request(ClientRole::McpBridge, request)
        else {
            panic!("native hook event did not enter the ordered vault workspace")
        };
        assert_eq!(params.binding.harness, HarnessId::Codex);
        assert_eq!(params.occurred_at_ms, 1_700_000_000_123);
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[tokio::test]
    async fn vault_worker_executes_scoped_mcp_status_for_the_canonical_project() {
        let path = unique_temp_path("mcp-worker-status").join("vault.db");
        let keys = Arc::new(MemoryKeyStore::default());
        let root = canonical_test_directory("mcp-worker-status-project");
        let project_id = seed_mcp_project(
            &path,
            keys.as_ref(),
            &root,
            HarnessAccessPolicy::ActiveProjectOnly { read_only: true },
        );
        let mut worker = VaultWorker::spawn(VaultConfig::new(path, "test-vault-key", keys))
            .await
            .unwrap();
        let response = worker
            .client()
            .try_submit(
                routed_mcp_command(mcp_request(
                    &root,
                    "context_relay_status",
                    serde_json::json!({}),
                )),
                TestAdmission(true),
            )
            .unwrap()
            .await
            .unwrap()
            .unwrap();

        let LocalResult::McpOutput { name, output } = response else {
            panic!("expected scoped MCP output")
        };
        assert_eq!(name, "context_relay_status");
        assert_eq!(output["resolvedProject"], project_id.to_string());
        assert_eq!(
            output["access"],
            serde_json::json!({"mode": "active_project_only", "readOnly": true})
        );
        worker.shutdown_and_join();
    }

    #[tokio::test]
    async fn packaged_search_startup_keeps_keywords_when_resources_are_missing() {
        use context_relay_protocol::SearchIndexPhase;
        let path = unit_test_support::TempVault::new("missing-packaged-search");
        let keys = Arc::new(MemoryKeyStore::default());
        let mut config = VaultConfig::new(path.path().to_owned(), "test-vault-key", keys);
        config.search_resources = Some(path.path().with_file_name("absent-search-assets"));
        config.startup_recovery = Some(Arc::new(|vault| {
            let params = serde_json::from_value(serde_json::json!({
                "operationId": "018f22e2-79b0-7cc8-98c4-dc0c0c073991",
                "scope": {"scope": "global"}, "kind": "note", "title": "Vehicle",
                "bodyMarkdown": "Keep the car engine serviced.", "tags": ["uniquephonemicidentifier"]
            })).unwrap();
            OfflineWorkspace::new(vault, stable_device_id(b"packaged-search-fixture"))
                .create_memory(params)
                .unwrap();
            Ok(())
        }));
        let (mut workspace, _) =
            open_workspace(&mut config).unwrap_or_else(|_| panic!("fixture workspace"));
        assert_eq!(
            workspace.search_index.status.phase,
            SearchIndexPhase::Preparing
        );
        workspace.search_index.tick(&mut workspace.vault);
        assert_eq!(
            workspace.search_index.status.phase,
            SearchIndexPhase::Failed
        );
        assert!(!workspace.search_index.pending());
        let results = OfflineWorkspace::new(
            &mut workspace.vault,
            stable_device_id(b"packaged-search-fixture"),
        )
        .search_memories(context_relay_protocol::SearchParams {
            query: "uniquephonemicidentifier".into(),
            project_id: None,
        })
        .unwrap();
        assert_eq!(results.len(), 1);
        workspace.search_index.retry();
        assert!(workspace.search_index.pending());
        workspace.search_index.tick(&mut workspace.vault);
        assert_eq!(
            workspace.search_index.status.phase,
            SearchIndexPhase::Failed
        );
    }

    #[cfg(windows)]
    #[test]
    fn packaged_search_production_uses_resources_beside_the_executable() {
        // Construct configuration only; do not start a normal daemon or open a vault.
        let config = DaemonConfig::production().unwrap();
        assert_eq!(
            config.vault.search_resources,
            Some(
                std::env::current_exe()
                    .unwrap()
                    .canonicalize()
                    .unwrap()
                    .parent()
                    .unwrap()
                    .join("search")
            )
        );
    }

    #[tokio::test]
    #[ignore = "requires verified BGE assets and ONNX Runtime"]
    async fn real_search_worker_prepares_semantic_results_in_the_background() {
        let path = unit_test_support::TempVault::new("background-semantic-search");
        let keys = Arc::new(MemoryKeyStore::default());
        let model_directory = PathBuf::from(
            std::env::var_os("CONTEXT_RELAY_MODEL_DIR").expect("verified model directory"),
        );
        let mut config = VaultConfig::new(path.path().to_owned(), "test-vault-key", keys);
        config.startup_recovery = Some(Arc::new(move |vault| {
            let params = serde_json::from_value(serde_json::json!({
                "operationId": "018f22e2-79b0-7cc8-98c4-dc0c0c073990",
                "scope": {"scope": "global"}, "kind": "note", "title": "Vehicle",
                "bodyMarkdown": "Keep the car engine serviced and replace its oil regularly.", "tags": []
            })).unwrap();
            OfflineWorkspace::new(vault, stable_device_id(b"search-worker-fixture"))
                .create_memory(params)
                .unwrap();
            vault.enable_semantic_search(
                context_relay_core::search::PinnedModelEmbedder::load(&model_directory).unwrap(),
            );
            Ok(())
        }));
        let mut worker = VaultWorker::spawn(config).await.unwrap();
        let client = worker.client();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut found = false;
        while tokio::time::Instant::now() < deadline {
            let response = client
                .try_submit(
                    VaultCommand::Workspace(LocalRequest::MemorySearch(
                        context_relay_protocol::SearchParams {
                            query: "automobile maintenance".into(),
                            project_id: None,
                        },
                    )),
                    TestAdmission(true),
                )
                .unwrap()
                .await
                .unwrap()
                .unwrap();
            if matches!(response, LocalResult::Memories { memories } if !memories.is_empty()) {
                found = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        worker.shutdown_and_join_async().await;
        assert!(
            found,
            "the worker never prepared the queued semantic record"
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    #[allow(
        clippy::assertions_on_constants,
        reason = "ignored qualification must compile for ordinary non-static test builds"
    )]
    #[ignore = "requires explicit packaged assets and static CRT; runs only a disposable daemon"]
    async fn packaged_search_daemon_retries_missing_and_damaged_assets_over_private_ipc() {
        use context_relay_protocol::SearchIndexPhase;
        use std::os::windows::process::CommandExt;
        assert!(cfg!(target_feature = "crt-static"));
        let Some(root) = std::env::var_os("CONTEXT_RELAY_PACKAGED_DAEMON_CHILD") else {
            let root = tempfile::tempdir().unwrap();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--ignored", "--exact", "tests::packaged_search_daemon_retries_missing_and_damaged_assets_over_private_ipc", "--nocapture"])
                .env("CONTEXT_RELAY_PACKAGED_DAEMON_CHILD", root.path())
                .env("ORT_DYLIB_PATH", root.path().join("unrelated-runtime.dll"))
                .creation_flags(0x0800_0000).output().unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            root.close().unwrap();
            return;
        };
        async fn wait_phase(client: &mut RawClient, expected: SearchIndexPhase) {
            timeout(Duration::from_secs(10), async {
                loop {
                    let response = client.call(LocalRequest::SearchIndexStatus(EmptyParams {})).await.unwrap();
                    if matches!(response, LocalResult::SearchIndex { status } if status.phase == expected) { break; }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }).await.expect("search phase deadline");
        }
        async fn search(client: &mut RawClient, query: &str) -> usize {
            let response = client
                .call(LocalRequest::MemorySearch(
                    context_relay_protocol::SearchParams {
                        query: query.into(),
                        project_id: None,
                    },
                ))
                .await
                .unwrap();
            let LocalResult::Memories { memories } = response else {
                panic!("search result");
            };
            memories.len()
        }
        let root = PathBuf::from(root);
        let assets = root.join("search");
        let runtime = test_runtime("packaged-search-daemon");
        let keys = Arc::new(MemoryKeyStore::default());
        let mut config = test_config(
            runtime.clone(),
            root.join("vault.db"),
            keys.clone(),
            Arc::new(FixedTokenProvider::default()),
        );
        config.vault.search_resources = Some(assets.clone());
        config.vault.startup_recovery = Some(Arc::new(|vault| {
            let params = serde_json::from_value(serde_json::json!({
                "operationId": "018f22e2-79b0-7cc8-98c4-dc0c0c073992",
                "scope": {"scope": "global"}, "kind": "note", "title": "Vehicle",
                "bodyMarkdown": "Keep the car engine serviced and replace its oil regularly.", "tags": ["uniquephonemicidentifier"]
            })).unwrap();
            OfflineWorkspace::new(vault, stable_device_id(b"packaged-daemon-fixture"))
                .create_memory(params)
                .unwrap();
            Ok(())
        }));
        let daemon = Daemon::start(config).await.unwrap();
        let handle = daemon.handle();
        let owner = tokio::spawn(daemon.run());
        let mut desktop = RawClient::connect(&runtime, ClientRole::Desktop).await;
        wait_phase(&mut desktop, SearchIndexPhase::Failed).await;
        assert_eq!(search(&mut desktop, "uniquephonemicidentifier").await, 1);
        assert_eq!(search(&mut desktop, "unseenword").await, 0);
        for (source_env, subdirectory, manifest) in [
            (
                "CONTEXT_RELAY_MODEL_DIR",
                "model",
                include_str!("../../core/models/bge-small-en-v1.5/manifest.json"),
            ),
            (
                "CONTEXT_RELAY_RUNTIME_DIR",
                "runtime",
                include_str!("../../core/models/onnxruntime-win-x64-1.24.2/manifest.json"),
            ),
        ] {
            let source = PathBuf::from(std::env::var_os(source_env).unwrap());
            let destination = assets.join(subdirectory);
            std::fs::create_dir_all(&destination).unwrap();
            let manifest: serde_json::Value = serde_json::from_str(manifest).unwrap();
            for artifact in manifest["artifacts"].as_array().unwrap() {
                let file = artifact["file"].as_str().unwrap();
                std::fs::copy(source.join(file), destination.join(file)).unwrap();
            }
        }
        let damaged = assets.join("runtime/msvcp140_1.dll");
        let good = std::fs::read(&damaged).unwrap();
        let mut bad = good.clone();
        *bad.last_mut().unwrap() ^= 1;
        std::fs::write(&damaged, bad).unwrap();
        desktop
            .call(LocalRequest::SearchIndexRetry(EmptyParams {}))
            .await
            .unwrap();
        wait_phase(&mut desktop, SearchIndexPhase::Failed).await;
        assert_eq!(search(&mut desktop, "uniquephonemicidentifier").await, 1);
        std::fs::write(&damaged, good).unwrap();
        desktop
            .call(LocalRequest::SearchIndexRetry(EmptyParams {}))
            .await
            .unwrap();
        wait_phase(&mut desktop, SearchIndexPhase::Ready).await;
        assert_eq!(search(&mut desktop, "automobile maintenance").await, 1);
        assert_eq!(handle.shutdown().await, DaemonState::Stopped);
        owner.await.unwrap().unwrap();
        #[cfg(feature = "test-support")]
        {
            // Restart the same disposable vault with a fresh session that fails
            // its next inference. Existing vectors require no passage inference,
            // so the first interactive query exercises the worker failure path.
            let mut config = test_config(
                runtime.clone(),
                root.join("vault.db"),
                keys,
                Arc::new(FixedTokenProvider::default()),
            );
            config.vault.search_resources = Some(assets.clone());
            config.vault.startup_recovery = Some(Arc::new(move |vault| {
                let mut model =
                    context_relay_core::search::PinnedModelEmbedder::load_packaged(&assets)
                        .unwrap();
                model.fail_next_inference_for_test();
                vault.enable_semantic_search(model);
                Ok(())
            }));
            let daemon = Daemon::start(config).await.unwrap();
            let handle = daemon.handle();
            let owner = tokio::spawn(daemon.run());
            let mut desktop = RawClient::connect(&runtime, ClientRole::Desktop).await;
            wait_phase(&mut desktop, SearchIndexPhase::Ready).await;
            assert_eq!(search(&mut desktop, "engine").await, 1);
            wait_phase(&mut desktop, SearchIndexPhase::Failed).await;
            assert_eq!(search(&mut desktop, "unseenword").await, 0);
            desktop
                .call(LocalRequest::SearchIndexRetry(EmptyParams {}))
                .await
                .unwrap();
            wait_phase(&mut desktop, SearchIndexPhase::Ready).await;
            assert_eq!(search(&mut desktop, "automobile maintenance").await, 1);
            assert_eq!(handle.shutdown().await, DaemonState::Stopped);
            owner.await.unwrap().unwrap();
        }
    }

    #[test]
    fn search_progress_and_retry_are_owner_only_even_when_routed_directly() {
        for request in [
            LocalRequest::SearchIndexStatus(EmptyParams {}),
            LocalRequest::SearchIndexRetry(EmptyParams {}),
        ] {
            assert!(role_allows(ClientRole::Desktop, &request));
            for role in [
                ClientRole::McpBridge,
                ClientRole::Installer,
                ClientRole::DesktopRecoveryHost,
            ] {
                assert!(!role_allows(role, &request));
                assert!(
                    matches!(route_request(role, request.clone()), RoutedRequest::Immediate(Err(error)) if error == scope_denied_error())
                );
            }
        }
        assert!(matches!(
            route_request(
                ClientRole::Desktop,
                LocalRequest::SearchIndexStatus(EmptyParams {})
            ),
            RoutedRequest::SearchIndexStatus
        ));
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[tokio::test]
    #[ignore = "requires verified BGE assets and ONNX Runtime"]
    async fn real_search_progress_stays_responsive_and_indexing_yields_then_stops_on_shutdown() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct IndexGate {
            events: std::sync::mpsc::Sender<&'static str>,
            release: Mutex<std::sync::mpsc::Receiver<()>>,
            batches: AtomicUsize,
            admission_checks: AtomicUsize,
        }
        impl WorkerHook for IndexGate {
            fn before_index_admission(&self) {
                if self.admission_checks.fetch_add(1, Ordering::SeqCst) == 0 {
                    self.events.send("admission").unwrap();
                    self.release
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(20))
                        .unwrap();
                }
            }
            fn before_execute(&self) {
                self.events.send("request").unwrap();
            }
            fn before_index(&self) {
                self.batches.fetch_add(1, Ordering::SeqCst);
                self.events.send("index").unwrap();
                self.release
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(20))
                    .unwrap();
            }
        }
        let path = unit_test_support::TempVault::new("search-index-admission");
        let runtime = test_runtime("search-index-admission");
        let keys = Arc::new(MemoryKeyStore::default());
        let mut config = test_config(
            runtime.clone(),
            path.path().to_owned(),
            keys.clone(),
            Arc::new(FixedTokenProvider::default()),
        );
        let model_directory = PathBuf::from(
            std::env::var_os("CONTEXT_RELAY_MODEL_DIR").expect("verified model directory"),
        );
        config.vault.startup_recovery = Some(Arc::new(move |vault| {
            for index in 0..4 {
                let params = serde_json::from_value(serde_json::json!({
                    "operationId": format!("018f22e2-79b0-7cc8-98c4-dc0c0c07399{index}"),
                    "scope": {"scope": "global"}, "kind": "note", "title": "Vehicle",
                    "bodyMarkdown": "Keep the car engine serviced and replace its oil regularly.", "tags": []
                })).unwrap();
                OfflineWorkspace::new(vault, stable_device_id(b"search-admission-fixture"))
                    .create_memory(params)
                    .unwrap();
            }
            vault.enable_semantic_search(
                context_relay_core::search::PinnedModelEmbedder::load(&model_directory).unwrap(),
            );
            Ok(())
        }));
        let (events, received) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let gate = Arc::new(IndexGate {
            events,
            release: Mutex::new(released),
            batches: AtomicUsize::new(0),
            admission_checks: AtomicUsize::new(0),
        });
        config.vault.worker_hook = Some(gate.clone());
        let daemon = Daemon::start(config).await.unwrap();
        let client = daemon.worker.client();
        let handle = daemon.handle();
        let owner = tokio::spawn(daemon.run());
        assert_eq!(
            received.recv_timeout(Duration::from_secs(5)).unwrap(),
            "admission"
        );
        let raced_request = client
            .try_submit(
                VaultCommand::Workspace(LocalRequest::ProjectsList(EmptyParams {})),
                TestAdmission(true),
            )
            .unwrap();
        release.send(()).unwrap();
        assert_eq!(
            received.recv_timeout(Duration::from_secs(5)).unwrap(),
            "request",
            "a request enqueued before indexing admission must win"
        );
        raced_request.await.unwrap().unwrap();
        assert_eq!(
            received.recv_timeout(Duration::from_secs(5)).unwrap(),
            "index"
        );
        let mut desktop = RawClient::connect(&runtime, ClientRole::Desktop).await;
        let progress = timeout(
            Duration::from_secs(1),
            desktop.call(LocalRequest::SearchIndexStatus(EmptyParams {})),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            matches!(progress, LocalResult::SearchIndex { status } if status.phase == context_relay_protocol::SearchIndexPhase::Preparing)
        );
        let request = client
            .try_submit(
                VaultCommand::Workspace(LocalRequest::ProjectsList(EmptyParams {})),
                TestAdmission(true),
            )
            .unwrap();
        release.send(()).unwrap();
        assert_eq!(
            received.recv_timeout(Duration::from_secs(5)).unwrap(),
            "request",
            "queued work must precede a second inference"
        );
        assert!(matches!(
            request.await.unwrap().unwrap(),
            LocalResult::Projects { .. }
        ));
        assert_eq!(
            received.recv_timeout(Duration::from_secs(5)).unwrap(),
            "index"
        );
        // The second slice is already admitted; shutdown may finish it, but must
        // not admit either of the two remaining records.
        *client.admission.lock().unwrap() = false;
        release.send(()).unwrap();
        assert_eq!(handle.shutdown().await, DaemonState::Stopped);
        owner.await.unwrap().unwrap();
        assert_eq!(gate.batches.load(Ordering::SeqCst), 2);
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[tokio::test]
    async fn unconfigured_account_lifecycle_never_simulates_remote_deletion() {
        let path = unique_temp_path("account-lifecycle-unavailable").join("vault.db");
        let keys = Arc::new(MemoryKeyStore::default());
        let mut worker = VaultWorker::spawn(VaultConfig::new(path, "test-vault-key", keys))
            .await
            .unwrap();
        let client = worker.client();
        let requests = [
            LocalRequest::AccountDeletionBegin(context_relay_protocol::AccountDeletionParams {
                operation_id: LIFECYCLE_BEGIN_ID.parse().unwrap(),
                confirmation: "delete".into(),
            }),
            LocalRequest::AccountDeletionStatus(EmptyParams {}),
            LocalRequest::AccountDeletionCancel(context_relay_protocol::RetryParams {
                operation_id: LIFECYCLE_CANCEL_ID.parse().unwrap(),
            }),
        ];

        for request in requests {
            let error = client
                .try_submit(VaultCommand::Workspace(request), TestAdmission(true))
                .unwrap()
                .await
                .unwrap()
                .unwrap_err();
            assert_eq!(error.code, ErrorCode::HarnessUnsupported);
            assert!(!error.retryable);
            assert_eq!(
                error.message,
                "Account lifecycle needs the hosted workspace service and is not available in this build."
            );
        }
        worker.shutdown_and_join();
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[tokio::test]
    async fn connection_check_only_fresh_authenticated_bridge_note_read_verifies() {
        let runtime = test_runtime("connection-check");
        let keys = Arc::new(MemoryKeyStore::default());
        let path = unique_temp_path("connection-check").join("vault.db");
        let root = canonical_test_directory("connection-check-project");
        let project = seed_mcp_project(&path, keys.as_ref(), &root, HarnessAccessPolicy::Default);
        let daemon = Daemon::start(test_config(
            runtime.clone(),
            path,
            keys,
            Arc::new(FixedTokenProvider::default()),
        ))
        .await
        .unwrap();
        let handle = daemon.handle();
        let owner = tokio::spawn(daemon.run());
        let mut desktop = RawClient::connect(&runtime, ClientRole::Desktop).await;
        let mut bridge = RawClient::connect(&runtime, ClientRole::McpBridge).await;
        let revision = uuid::Uuid::now_v7().to_string();
        let note = desktop.call(request_fixture("memory_create", serde_json::json!({"operationId":revision,"scope":{"scope":"project","projectId":project},"kind":"note","title":"Connection check","bodyMarkdown":"Use clear language","tags":[]}))).await.unwrap();
        let LocalResult::Memory { memory: Some(note) } = note else {
            panic!("note")
        };
        let start = request_fixture(
            "connection_check_start",
            serde_json::json!({"selection":{"harness":"codex","projectId":project,"hermesProfile":null},"memoryId":note.id,"expectedRevision":note.revision}),
        );
        let read = mcp_request(
            &root,
            "context_relay_get",
            serde_json::json!({"recordId":note.id}),
        );
        bridge.call(read.clone()).await.unwrap(); // An old read cannot be reused.
        let started = desktop.call(start.clone()).await;
        assert!(
            started.is_ok(),
            "saved-note connection check must start: {started:?}"
        );
        let LocalResult::ConnectionCheck { status } = started.unwrap() else {
            panic!("check")
        };
        let status_request = request_fixture(
            "connection_check_status",
            serde_json::json!({"checkId":status.check_id}),
        );
        desktop.call(read.clone()).await.unwrap(); // Desktop MCP calls do not attest a harness.
        desktop
            .call(request_fixture(
                "memory_get",
                serde_json::json!({"memoryId":note.id}),
            ))
            .await
            .unwrap();
        bridge
            .call(mcp_request(
                &root,
                "context_relay_status",
                serde_json::json!({}),
            ))
            .await
            .unwrap();
        let LocalResult::ConnectionCheck { status } =
            desktop.call(status_request.clone()).await.unwrap()
        else {
            panic!("check")
        };
        assert_eq!(
            status.phase,
            context_relay_protocol::ConnectionCheckPhase::Waiting
        );
        let outside = canonical_test_directory("connection-check-wrong-project");
        assert!(
            bridge
                .call(mcp_request(
                    &outside,
                    "context_relay_get",
                    serde_json::json!({"recordId":note.id})
                ))
                .await
                .is_err()
        );
        let mut wrong_harness = read.clone();
        if let LocalRequest::McpCall(params) = &mut wrong_harness {
            params.binding.harness = HarnessId::ClaudeCode;
        }
        let _ = bridge.call(wrong_harness).await;
        let LocalResult::ConnectionCheck { status } =
            desktop.call(status_request.clone()).await.unwrap()
        else {
            panic!("check")
        };
        assert_eq!(
            status.phase,
            context_relay_protocol::ConnectionCheckPhase::Waiting
        );
        assert!(bridge.call(start.clone()).await.is_err());
        bridge.call(read.clone()).await.unwrap();
        let LocalResult::ConnectionCheck { status } =
            desktop.call(status_request.clone()).await.unwrap()
        else {
            panic!("check")
        };
        assert_eq!(
            status.phase,
            context_relay_protocol::ConnectionCheckPhase::Verified
        );
        assert!(status.verified_at.is_some());
        let LocalResult::ConnectionCheck { status: new } = desktop.call(start).await.unwrap()
        else {
            panic!("check")
        };
        assert_ne!(new.check_id, status.check_id);
        assert_eq!(
            new.phase,
            context_relay_protocol::ConnectionCheckPhase::Waiting
        );
        assert!(desktop.call(status_request).await.is_err());
        desktop
            .call(request_fixture(
                "connection_check_cancel",
                serde_json::json!({"checkId":new.check_id}),
            ))
            .await
            .unwrap();
        bridge.call(read).await.unwrap();
        let LocalResult::ConnectionCheck { status } = desktop
            .call(request_fixture(
                "connection_check_status",
                serde_json::json!({"checkId":new.check_id}),
            ))
            .await
            .unwrap()
        else {
            panic!("check")
        };
        assert_eq!(
            status.phase,
            context_relay_protocol::ConnectionCheckPhase::Canceled
        );
        assert_eq!(handle.shutdown().await, DaemonState::Stopped);
        assert_eq!(owner.await.unwrap(), Ok(()));
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[tokio::test]
    async fn configured_account_lifecycle_runs_only_through_the_ordered_vault_worker() {
        let path = unique_temp_path("account-lifecycle-configured").join("vault.db");
        let keys = Arc::new(MemoryKeyStore::default());
        let lifecycle = TestAccountLifecycleTransport::new();
        let config = VaultConfig::new(path, "test-vault-key", keys).with_account_lifecycle_service(
            Arc::new(TransportAccountLifecycleService::new(lifecycle.clone())),
        );
        let mut worker = VaultWorker::spawn(config).await.unwrap();
        let client = worker.client();

        let invalid = client
            .try_submit(
                VaultCommand::Workspace(LocalRequest::AccountDeletionBegin(
                    context_relay_protocol::AccountDeletionParams {
                        operation_id: LIFECYCLE_BEGIN_ID.parse().unwrap(),
                        confirmation: "not-delete".into(),
                    },
                )),
                TestAdmission(true),
            )
            .unwrap()
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(invalid.code, ErrorCode::InvalidRequest);
        assert_eq!(lifecycle.calls.load(Ordering::SeqCst), 0);

        let pending = client
            .try_submit(
                VaultCommand::Workspace(LocalRequest::AccountDeletionBegin(
                    context_relay_protocol::AccountDeletionParams {
                        operation_id: LIFECYCLE_BEGIN_ID.parse().unwrap(),
                        confirmation: "delete".into(),
                    },
                )),
                TestAdmission(true),
            )
            .unwrap()
            .await
            .unwrap()
            .unwrap();
        let LocalResult::AccountDeletion {
            state,
            purge_deadline,
            export_available,
        } = pending
        else {
            panic!("expected hosted account deletion projection")
        };
        assert_eq!(state, AccountDeletionState::PendingDelete);
        assert_eq!(
            purge_deadline,
            Some(DecimalTimestamp(1_000 + ACCOUNT_DELETION_GRACE_MS))
        );
        assert!(export_available);

        let status = client
            .try_submit(
                VaultCommand::Workspace(LocalRequest::AccountDeletionStatus(EmptyParams {})),
                TestAdmission(true),
            )
            .unwrap()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            status,
            LocalResult::AccountDeletion {
                state,
                purge_deadline,
                export_available,
            }
        );

        let active = client
            .try_submit(
                VaultCommand::Workspace(LocalRequest::AccountDeletionCancel(
                    context_relay_protocol::RetryParams {
                        operation_id: LIFECYCLE_CANCEL_ID.parse().unwrap(),
                    },
                )),
                TestAdmission(true),
            )
            .unwrap()
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            active,
            LocalResult::AccountDeletion {
                state: AccountDeletionState::Active,
                purge_deadline: None,
                export_available: false,
            }
        ));
        assert_eq!(lifecycle.calls.load(Ordering::SeqCst), 3);
        assert_eq!(
            *lifecycle.operations.lock().unwrap(),
            vec![
                LIFECYCLE_BEGIN_ID.parse().unwrap(),
                LIFECYCLE_CANCEL_ID.parse().unwrap(),
            ]
        );
        worker.shutdown_and_join();
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[tokio::test]
    async fn authenticated_bridge_executes_only_scoped_mcp_calls() {
        let runtime = test_runtime("daemon-mcp-auth");
        let provider = Arc::new(FixedTokenProvider::default());
        let keys = Arc::new(MemoryKeyStore::default());
        let path = unique_temp_path("daemon-mcp-auth").join("vault.db");
        let root = canonical_test_directory("daemon-mcp-auth-project");
        let project_id =
            seed_mcp_project(&path, keys.as_ref(), &root, HarnessAccessPolicy::Default);
        assert!(matches!(
            route_request(
                ClientRole::McpBridge,
                mcp_request(&root, "context_relay_status", serde_json::json!({}))
            ),
            RoutedRequest::Work(VaultCommand::Workspace(LocalRequest::McpCall(_)))
        ));
        let daemon = Daemon::start(test_config(runtime.clone(), path, keys, provider))
            .await
            .unwrap();
        let handle = daemon.handle();
        let owner = tokio::spawn(daemon.run());
        let mut desktop = RawClient::connect(&runtime, ClientRole::Desktop).await;
        let mut bridge = RawClient::connect(&runtime, ClientRole::McpBridge).await;

        let LocalResult::McpOutput { name, output } = bridge
            .call(mcp_request(
                &root,
                "context_relay_status",
                serde_json::json!({}),
            ))
            .await
            .unwrap()
        else {
            panic!("expected scoped MCP output")
        };
        assert_eq!(name, "context_relay_status");
        assert_eq!(output["resolvedProject"], project_id.to_string());

        assert_eq!(
            bridge
                .call(request_fixture(
                    "memory_search",
                    serde_json::json!({"query": "other project", "projectId": project_id}),
                ))
                .await
                .unwrap_err()
                .code,
            ErrorCode::ScopeDenied
        );
        assert_eq!(
            bridge
                .call(LocalRequest::SyncStatus(EmptyParams {}))
                .await
                .unwrap_err()
                .code,
            ErrorCode::ScopeDenied
        );
        assert!(matches!(
            desktop
                .call(LocalRequest::SyncStatus(EmptyParams {}))
                .await
                .unwrap(),
            LocalResult::Status { .. }
        ));

        assert_eq!(handle.shutdown().await, DaemonState::Stopped);
        assert_eq!(owner.await.unwrap(), Ok(()));
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[tokio::test]
    async fn canceled_queued_mcp_write_does_not_mutate_the_vault() {
        let runtime = test_runtime("daemon-mcp-cancel");
        let provider = Arc::new(FixedTokenProvider::default());
        let keys = Arc::new(MemoryKeyStore::default());
        let path = unique_temp_path("daemon-mcp-cancel").join("vault.db");
        let root = canonical_test_directory("daemon-mcp-cancel-project");
        let project_id =
            seed_mcp_project(&path, keys.as_ref(), &root, HarnessAccessPolicy::Default);
        let remember_arguments = serde_json::json!({
            "operationId": "018f22e2-79b0-7cc8-98c4-dc0c0c073990",
            "kind": "note",
            "title": "Canceled memory",
            "markdown": "This write must never execute.",
            "tags": [],
            "scope": {"scope": "active_project"}
        });
        let _ = routed_mcp_command(mcp_request(
            &root,
            "context_relay_remember",
            remember_arguments.clone(),
        ));
        let gate = Arc::new(BlockingWorkerHook::new());
        let config = test_config(runtime.clone(), path.clone(), keys.clone(), provider)
            .with_worker_hook(gate.clone());
        let daemon = Daemon::start(config).await.unwrap();
        let handle = daemon.handle();
        let owner = tokio::spawn(daemon.run());
        let mut active_client = RawClient::connect(&runtime, ClientRole::Desktop).await;
        let mut bridge = RawClient::connect(&runtime, ClientRole::McpBridge).await;
        let mut cancel_client = RawClient::connect(&runtime, ClientRole::Desktop).await;

        let active = tokio::spawn(async move {
            active_client
                .call(LocalRequest::SyncStatus(EmptyParams {}))
                .await
        });
        gate.wait_until_entered().await;
        let request_id = next_record_id();
        let queued_root = root.clone();
        let queued = tokio::spawn(async move {
            bridge
                .call_with_id(
                    request_id,
                    mcp_request(&queued_root, "context_relay_remember", remember_arguments),
                )
                .await
        });
        gate.wait_until_enqueued(2).await;
        assert_eq!(
            cancel_client
                .call(LocalRequest::Cancel(CancelParams { request_id }))
                .await
                .unwrap(),
            LocalResult::Empty
        );
        gate.release();

        assert!(matches!(
            active.await.unwrap(),
            Ok(LocalResult::Status { .. })
        ));
        assert_eq!(queued.await.unwrap(), Err(canceled_error()));
        assert_eq!(handle.shutdown().await, DaemonState::Stopped);
        assert_eq!(owner.await.unwrap(), Ok(()));

        let reopened = Vault::open(&path, "test-vault-key", keys.as_ref()).unwrap();
        assert!(
            reopened
                .memories(Some(project_id), false)
                .unwrap()
                .is_empty()
        );
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[tokio::test]
    async fn queued_mcp_timeout_is_retryable() {
        let runtime = test_runtime("daemon-mcp-timeout");
        let provider = Arc::new(FixedTokenProvider::default());
        let keys = Arc::new(MemoryKeyStore::default());
        let path = unique_temp_path("daemon-mcp-timeout").join("vault.db");
        let root = canonical_test_directory("daemon-mcp-timeout-project");
        seed_mcp_project(&path, keys.as_ref(), &root, HarnessAccessPolicy::Default);
        assert!(matches!(
            route_request(
                ClientRole::McpBridge,
                mcp_request(&root, "context_relay_status", serde_json::json!({}))
            ),
            RoutedRequest::Work(VaultCommand::Workspace(LocalRequest::McpCall(_)))
        ));
        let gate = Arc::new(BlockingWorkerHook::new());
        let config =
            test_config(runtime.clone(), path, keys, provider).with_worker_hook(gate.clone());
        let daemon = Daemon::start(config).await.unwrap();
        let handle = daemon.handle();
        let owner = tokio::spawn(daemon.run());
        let mut bridge = RawClient::connect(&runtime, ClientRole::McpBridge).await;
        tokio::time::pause();
        let request = tokio::spawn(async move {
            bridge
                .call(mcp_request(
                    &root,
                    "context_relay_status",
                    serde_json::json!({}),
                ))
                .await
        });
        gate.wait_until_entered().await;

        tokio::time::advance(WORK_RESPONSE_TIMEOUT + Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        let error = request.await.unwrap().unwrap_err();
        assert_eq!(error.code, ErrorCode::Timeout);
        assert!(error.retryable);

        gate.release();
        tokio::time::resume();
        assert_eq!(handle.shutdown().await, DaemonState::Stopped);
        assert_eq!(owner.await.unwrap(), Ok(()));
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[tokio::test]
    async fn bounded_worker_reports_busy_for_scoped_mcp_calls() {
        let path = unique_temp_path("worker-mcp-busy").join("vault.db");
        let keys = Arc::new(MemoryKeyStore::default());
        let root = canonical_test_directory("worker-mcp-busy-project");
        seed_mcp_project(&path, keys.as_ref(), &root, HarnessAccessPolicy::Default);
        let mut worker = VaultWorker::spawn(VaultConfig::new(path, "test-vault-key", keys))
            .await
            .unwrap();
        let client = worker.client();
        let (entered_sender, entered_receiver) = std::sync::mpsc::sync_channel(0);
        let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(0);
        let blocked = client
            .try_submit(
                VaultCommand::TestBlock {
                    entered: entered_sender,
                    release: release_receiver,
                },
                TestAdmission(true),
            )
            .unwrap();
        entered_receiver.recv().unwrap();

        let mut queued = Vec::with_capacity(REQUEST_QUEUE_CAPACITY);
        for _ in 0..REQUEST_QUEUE_CAPACITY {
            queued.push(
                client
                    .try_submit(
                        routed_mcp_command(mcp_request(
                            &root,
                            "context_relay_status",
                            serde_json::json!({}),
                        )),
                        TestAdmission(true),
                    )
                    .unwrap(),
            );
        }
        let overflow = client.try_submit(
            routed_mcp_command(mcp_request(
                &root,
                "context_relay_status",
                serde_json::json!({}),
            )),
            TestAdmission(true),
        );
        match overflow {
            Err(error) => assert_eq!(error, busy_error()),
            Ok(_) => panic!("queue overflow accepted an MCP call"),
        }

        release_sender.send(()).unwrap();
        assert_eq!(blocked.await.unwrap(), Ok(LocalResult::Empty));
        for response in queued {
            assert!(matches!(
                response.await.unwrap(),
                Ok(LocalResult::McpOutput { ref name, .. })
                    if name == "context_relay_status"
            ));
        }
        worker.shutdown_and_join();
    }

    #[tokio::test]
    async fn vault_worker_executes_real_commands_and_skips_canceled_queued_work() {
        let path = unique_temp_path("worker-commands").join("vault.db");
        let keys = Arc::new(MemoryKeyStore::default());
        let mut worker = VaultWorker::spawn(VaultConfig::new(
            path.clone(),
            "worker-commands",
            keys.clone(),
        ))
        .await
        .unwrap();
        let client = worker.client();
        let project_id = "018f22e2-79b0-7cc8-98c4-dc0c0c07398f";
        let LocalRequest::ProjectPathSet(first_path) = request_fixture(
            "project_path_set",
            serde_json::json!({
                "projectId": project_id,
                "path": {"platform": "windows", "bytes": "AQI", "display": "C:\\work"},
            }),
        ) else {
            unreachable!()
        };
        let expected_path = first_path.path.clone();
        let first = client
            .try_submit(
                VaultCommand::ProjectPathSet(first_path),
                TestAdmission(true),
            )
            .unwrap();
        assert_eq!(first.await.unwrap(), Ok(LocalResult::Empty));

        let LocalRequest::MemoryGet(memory) =
            request_fixture("memory_get", serde_json::json!({"memoryId": project_id}))
        else {
            unreachable!()
        };
        let missing = client
            .try_submit(VaultCommand::MemoryGet(memory), TestAdmission(true))
            .unwrap();
        assert_eq!(
            missing.await.unwrap(),
            Ok(LocalResult::Memory { memory: None })
        );

        let LocalRequest::ProjectPathSet(canceled_path) = request_fixture(
            "project_path_set",
            serde_json::json!({
                "projectId": "018f22e2-79b0-7cc8-98c4-dc0c0c073981",
                "path": {"platform": "windows", "bytes": "AwQ", "display": null},
            }),
        ) else {
            unreachable!()
        };
        let canceled_project = canceled_path.project_id.to_string();
        let canceled = client
            .try_submit(
                VaultCommand::ProjectPathSet(canceled_path),
                TestAdmission(false),
            )
            .unwrap();
        assert_eq!(canceled.await.unwrap(), Err(canceled_error()));

        worker.shutdown_and_join();
        let reopened = Vault::open(&path, "worker-commands", keys.as_ref()).unwrap();
        assert_eq!(reopened.path(project_id).unwrap(), Some(expected_path));
        assert_eq!(reopened.path(&canceled_project).unwrap(), None);
    }

    #[tokio::test]
    async fn vault_worker_recovers_prepared_writes_after_restart_without_applying_them() {
        let path = unique_temp_path("worker-desktop-recovery").join("vault.db");
        let keys = Arc::new(MemoryKeyStore::default());
        let id = "018f22e2-79b0-7cc8-98c4-dc0c0c073981";
        let write = serde_json::json!({"method":"memory_create","params":{
            "operationId":id,"scope":{"scope":"global"},"kind":"note",
            "title":"Retained decision","bodyMarkdown":"Original content","tags":[]
        }});
        let mut worker = VaultWorker::spawn(VaultConfig::new(
            path.clone(),
            "worker-desktop-recovery",
            keys.clone(),
        ))
        .await
        .unwrap();
        let prepared = worker
            .client()
            .try_submit(
                VaultCommand::Workspace(request_fixture(
                    "desktop_write_prepare",
                    serde_json::json!({"write":write}),
                )),
                TestAdmission(true),
            )
            .unwrap()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(prepared, LocalResult::Empty);
        let exported = worker
            .client()
            .try_submit(
                VaultCommand::Workspace(request_fixture(
                    "export_records",
                    serde_json::json!({"projectId":null,"includeArchived":true}),
                )),
                TestAdmission(true),
            )
            .unwrap()
            .await
            .unwrap()
            .unwrap();
        let LocalResult::Export { payload } = exported else {
            panic!("expected full encrypted backup")
        };
        assert_eq!(payload.record_count, 0);
        assert_eq!(payload.chunk_count, 1);
        assert!(
            !payload
                .chunk
                .as_slice()
                .windows(b"Original content".len())
                .any(|bytes| bytes == b"Original content")
        );
        let restored_path = path.parent().unwrap().join("restored-backup.db");
        std::fs::write(&restored_path, payload.chunk.as_slice()).unwrap();
        let restored_vault =
            Vault::open(&restored_path, "worker-desktop-recovery", keys.as_ref()).unwrap();
        assert!(restored_vault.memories(None, true).unwrap().is_empty());
        let pending = restored_vault
            .desktop_write(id.parse().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(serde_json::to_value(pending).unwrap(), write);
        drop(restored_vault);
        worker.shutdown_and_join();
        let mut worker = VaultWorker::spawn(VaultConfig::new(
            path.clone(),
            "worker-desktop-recovery",
            keys.clone(),
        ))
        .await
        .unwrap();
        let client = worker.client();
        let list = client
            .try_submit(
                VaultCommand::Workspace(request_fixture(
                    "desktop_writes_list",
                    serde_json::json!({"after":null}),
                )),
                TestAdmission(true),
            )
            .unwrap()
            .await
            .unwrap()
            .unwrap();
        let LocalResult::DesktopWrites { page } = list else {
            panic!("expected pending writes")
        };
        assert_eq!(page.writes.len(), 1);
        let restored = client
            .try_submit(
                VaultCommand::Workspace(request_fixture(
                    "desktop_write_get",
                    serde_json::json!({"operationId":id}),
                )),
                TestAdmission(true),
            )
            .unwrap()
            .await
            .unwrap()
            .unwrap();
        let LocalResult::DesktopWrite {
            write: Some(restored),
        } = restored
        else {
            panic!("expected recovery copy")
        };
        assert_eq!(serde_json::to_value(&restored).unwrap(), write);
        // Startup/list/get did not apply the prepared write.
        let memories = client
            .try_submit(
                VaultCommand::Workspace(request_fixture(
                    "memory_list",
                    serde_json::json!({"projectId":null,"includeArchived":true}),
                )),
                TestAdmission(true),
            )
            .unwrap()
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(memories, LocalResult::Memories { memories } if memories.is_empty()));
        let first = client
            .try_submit(
                VaultCommand::Workspace(restored.clone().into_request()),
                TestAdmission(true),
            )
            .unwrap()
            .await
            .unwrap()
            .unwrap();
        worker.shutdown_and_join();
        let mut worker =
            VaultWorker::spawn(VaultConfig::new(path, "worker-desktop-recovery", keys))
                .await
                .unwrap();
        let client = worker.client();
        let replay = client
            .try_submit(
                VaultCommand::Workspace(restored.into_request()),
                TestAdmission(true),
            )
            .unwrap()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first, replay);
        let forgotten = client
            .try_submit(
                VaultCommand::Workspace(request_fixture(
                    "desktop_write_forget",
                    serde_json::json!({"operationId":id}),
                )),
                TestAdmission(true),
            )
            .unwrap()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(forgotten, LocalResult::Empty);
        worker.shutdown_and_join();
    }

    #[tokio::test]
    async fn vault_worker_runs_the_offline_workspace_and_encrypted_export() {
        let path = unique_temp_path("worker-offline-workspace").join("vault.db");
        let keys = Arc::new(MemoryKeyStore::default());
        let mut worker =
            VaultWorker::spawn(VaultConfig::new(path, "worker-offline-workspace", keys))
                .await
                .unwrap();
        let client = worker.client();
        let project_id = "018f22e2-79b0-7cc8-98c4-dc0c0c073980";
        let memory_id = "018f22e2-79b0-7cc8-98c4-dc0c0c073981";

        for request in [
            request_fixture(
                "project_upsert",
                serde_json::json!({"project": {"projectId": project_id, "githubRepositoryId": null, "gitRemoteFingerprint": null, "monorepoSubdirectory": null, "name": "Context Relay"}}),
            ),
            request_fixture(
                "memory_create",
                serde_json::json!({"operationId": memory_id, "scope": {"scope": "project", "projectId": project_id}, "kind": "note", "title": "encrypted-canary-title", "bodyMarkdown": "body", "tags": []}),
            ),
            request_fixture(
                "task_upsert",
                serde_json::json!({"operationId": "018f22e2-79b0-7cc8-98c4-dc0c0c073982", "taskId": null, "projectId": project_id, "title": "task", "bodyMarkdown": "body", "status": "open", "expectedRevision": null}),
            ),
        ] {
            client
                .try_submit(VaultCommand::Workspace(request), TestAdmission(true))
                .unwrap()
                .await
                .unwrap()
                .unwrap();
        }

        let status = client
            .try_submit(
                VaultCommand::Workspace(request_fixture("sync_status", serde_json::json!({}))),
                TestAdmission(true),
            )
            .unwrap()
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            status,
            LocalResult::Status {
                status: context_relay_protocol::StatusOutput {
                    sync: SyncState::Offline,
                    ..
                }
            }
        ));

        let export = client
            .try_submit(
                VaultCommand::Workspace(request_fixture(
                    "export_records",
                    serde_json::json!({"projectId": null, "includeArchived": true}),
                )),
                TestAdmission(true),
            )
            .unwrap()
            .await
            .unwrap()
            .unwrap();
        let LocalResult::Export { payload } = export else {
            panic!("expected encrypted export")
        };
        assert_eq!(payload.record_count, 3);
        assert!(
            !payload
                .chunk
                .as_slice()
                .windows("encrypted-canary-title".len())
                .any(|window| window == b"encrypted-canary-title")
        );

        worker.shutdown_and_join();
    }

    #[tokio::test]
    async fn vault_worker_queue_is_bounded_and_reports_busy_without_waiting() {
        let path = unique_temp_path("worker-backpressure").join("vault.db");
        let keys = Arc::new(MemoryKeyStore::default());
        let mut worker = VaultWorker::spawn(VaultConfig::new(path, "worker-backpressure", keys))
            .await
            .unwrap();
        let client = worker.client();
        let (entered_sender, entered_receiver) = std::sync::mpsc::sync_channel(0);
        let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(0);
        let blocked = client
            .try_submit(
                VaultCommand::TestBlock {
                    entered: entered_sender,
                    release: release_receiver,
                },
                TestAdmission(true),
            )
            .unwrap();
        entered_receiver.recv().unwrap();

        let mut queued = Vec::with_capacity(REQUEST_QUEUE_CAPACITY);
        for _ in 0..REQUEST_QUEUE_CAPACITY {
            let LocalRequest::MemoryGet(memory) = request_fixture(
                "memory_get",
                serde_json::json!({"memoryId": "018f22e2-79b0-7cc8-98c4-dc0c0c07398f"}),
            ) else {
                unreachable!()
            };
            queued.push(
                client
                    .try_submit(VaultCommand::MemoryGet(memory), TestAdmission(true))
                    .unwrap(),
            );
        }
        let LocalRequest::MemoryGet(overflow) = request_fixture(
            "memory_get",
            serde_json::json!({"memoryId": "018f22e2-79b0-7cc8-98c4-dc0c0c07398f"}),
        ) else {
            unreachable!()
        };
        let overflow = client.try_submit(VaultCommand::MemoryGet(overflow), TestAdmission(true));
        match overflow {
            Err(error) => assert_eq!(error, busy_error()),
            Ok(_) => panic!("queue overflow was accepted"),
        }

        release_sender.send(()).unwrap();
        assert_eq!(blocked.await.unwrap(), Ok(LocalResult::Empty));
        for response in queued {
            assert_eq!(
                response.await.unwrap(),
                Ok(LocalResult::Memory { memory: None })
            );
        }
        worker.shutdown_and_join();
    }

    #[tokio::test]
    async fn closed_admission_rejects_work_while_the_weak_sender_is_still_live() {
        let path = unique_temp_path("worker-admission-close").join("vault.db");
        let keys = Arc::new(MemoryKeyStore::default());
        let mut worker = VaultWorker::spawn(VaultConfig::new(path, "worker-admission-close", keys))
            .await
            .unwrap();
        let client = worker.client();
        assert!(client.is_alive());

        worker.close_admission();
        assert!(client.is_alive());
        let LocalRequest::MemoryGet(memory) = request_fixture(
            "memory_get",
            serde_json::json!({"memoryId": "018f22e2-79b0-7cc8-98c4-dc0c0c07398f"}),
        ) else {
            unreachable!()
        };
        let result = client.try_submit(VaultCommand::MemoryGet(memory), TestAdmission(true));
        match result {
            Err(error) => assert_eq!(error, busy_error()),
            Ok(_) => panic!("closed admission accepted work"),
        }

        worker.shutdown_and_join();
    }

    #[tokio::test]
    async fn dead_worker_is_not_reported_as_a_later_roadmap_method() {
        let path = unique_temp_path("worker-dead-error").join("vault.db");
        let keys = Arc::new(MemoryKeyStore::default());
        let mut worker = VaultWorker::spawn(VaultConfig::new(path, "worker-dead-error", keys))
            .await
            .unwrap();
        let client = worker.client();
        worker.shutdown_and_join();
        let LocalRequest::MemoryGet(memory) = request_fixture(
            "memory_get",
            serde_json::json!({"memoryId": "018f22e2-79b0-7cc8-98c4-dc0c0c07398f"}),
        ) else {
            unreachable!()
        };

        let result = client.try_submit(VaultCommand::MemoryGet(memory), TestAdmission(true));
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("dead worker accepted work"),
        };
        assert_eq!(error, service_internal_error());
        assert_ne!(error, unavailable_error());
        assert!(error.retryable);
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[tokio::test]
    async fn locked_vault_keeps_the_authenticated_endpoint_alive_until_desktop_unlocks_it() {
        let runtime = test_runtime("daemon-locked-vault");
        let provider = Arc::new(FixedTokenProvider::default());
        let keys = Arc::new(MemoryKeyStore::default());
        let root = canonical_test_directory("daemon-locked-vault-data");
        let path = root.join("vault.db");
        drop(Vault::open(&path, "test-vault-key", keys.as_ref()).unwrap());
        keys.set_locked(true);

        let daemon = Daemon::start(test_config(runtime.clone(), path, keys.clone(), provider))
            .await
            .unwrap();
        let handle = daemon.handle();
        let owner = tokio::spawn(daemon.run());
        let mut desktop = RawClient::connect(&runtime, ClientRole::Desktop).await;
        let mut mcp = RawClient::connect(&runtime, ClientRole::McpBridge).await;

        assert_eq!(
            desktop
                .call(LocalRequest::Health(EmptyParams {}))
                .await
                .unwrap(),
            LocalResult::Health {
                protocol: PROTOCOL_VERSION,
                vault_locked: true,
            }
        );
        let locked = mcp
            .call(mcp_request(
                &root,
                "context_relay_status",
                serde_json::json!({}),
            ))
            .await
            .unwrap_err();
        assert_eq!(locked, ClientError::vault_locked());

        keys.set_locked(false);
        assert_eq!(
            desktop
                .call(LocalRequest::Unlock(EmptyParams {}))
                .await
                .unwrap(),
            LocalResult::Empty
        );
        assert_eq!(
            desktop
                .call(LocalRequest::Health(EmptyParams {}))
                .await
                .unwrap(),
            LocalResult::Health {
                protocol: PROTOCOL_VERSION,
                vault_locked: false,
            }
        );
        let LocalResult::Status { status } = desktop
            .call(LocalRequest::SyncStatus(EmptyParams {}))
            .await
            .unwrap()
        else {
            panic!("expected authoritative service status");
        };
        assert_eq!(status.vault, VaultState::Unlocked);
        assert_eq!(status.sync, SyncState::Offline);

        assert_eq!(
            desktop
                .call(LocalRequest::Shutdown(EmptyParams {}))
                .await
                .unwrap(),
            LocalResult::Empty
        );
        assert_eq!(owner.await.unwrap(), Ok(()));
        assert_eq!(handle.state(), DaemonState::Stopped);
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[tokio::test]
    async fn daemon_routes_real_and_deferred_methods_then_flushes_shutdown() {
        let runtime = test_runtime("daemon-e2e");
        let provider = Arc::new(FixedTokenProvider::default());
        let keys = Arc::new(MemoryKeyStore::default());
        let path = unique_temp_path("daemon-e2e").join("vault.db");
        let daemon = Daemon::start(test_config(runtime.clone(), path, keys, provider))
            .await
            .unwrap();
        let handle = daemon.handle();
        let owner = tokio::spawn(daemon.run());
        let mut desktop = RawClient::connect(&runtime, ClientRole::Desktop).await;
        let mut idle_mcp = RawClient::connect(&runtime, ClientRole::McpBridge).await;

        assert_eq!(
            desktop
                .call(LocalRequest::Health(EmptyParams {}))
                .await
                .unwrap(),
            LocalResult::Health {
                protocol: PROTOCOL_VERSION,
                vault_locked: false,
            }
        );
        assert_eq!(
            desktop
                .call(LocalRequest::Unlock(EmptyParams {}))
                .await
                .unwrap(),
            LocalResult::Empty
        );
        let LocalRequest::ProjectPathSet(path_set) = request_fixture(
            "project_path_set",
            serde_json::json!({
                "projectId": "018f22e2-79b0-7cc8-98c4-dc0c0c07398f",
                "path": {"platform": "windows", "bytes": "AQI", "display": null},
            }),
        ) else {
            unreachable!()
        };
        assert_eq!(
            desktop
                .call(LocalRequest::ProjectPathSet(path_set))
                .await
                .unwrap(),
            LocalResult::Empty
        );
        let mcp_memory = request_fixture(
            "memory_get",
            serde_json::json!({"memoryId": "018f22e2-79b0-7cc8-98c4-dc0c0c07398f"}),
        );
        assert_eq!(
            idle_mcp.call(mcp_memory).await.unwrap_err().code,
            ErrorCode::ScopeDenied
        );

        assert_eq!(
            desktop
                .call(LocalRequest::Shutdown(EmptyParams {}))
                .await
                .unwrap(),
            LocalResult::Empty
        );
        assert_eq!(owner.await.unwrap(), Ok(()));
        assert_eq!(handle.state(), DaemonState::Stopped);
        drop(InstanceGuard::acquire(&runtime).unwrap());
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[tokio::test]
    async fn connection_limit_drops_the_next_accepted_stream_before_handshake() {
        let runtime = test_runtime("daemon-connection-limit");
        let provider = Arc::new(FixedTokenProvider::default());
        let keys = Arc::new(MemoryKeyStore::default());
        let path = unique_temp_path("daemon-connection-limit").join("vault.db");
        let daemon = Daemon::start(test_config(runtime.clone(), path, keys, provider))
            .await
            .unwrap();
        let handle = daemon.handle();
        let owner = tokio::spawn(daemon.run());

        let mut clients = Vec::with_capacity(CONNECTION_LIMIT);
        for _ in 0..CONNECTION_LIMIT {
            clients.push(RawClient::connect(&runtime, ClientRole::Desktop).await);
        }
        let mut overflow = connect(&runtime).await.unwrap();
        let overflow_hello: Result<ServerHelloV1, IpcError> = read_json(&mut overflow).await;
        assert!(matches!(overflow_hello, Err(IpcError::Io)));

        assert_eq!(handle.shutdown().await, DaemonState::Stopped);
        assert_eq!(owner.await.unwrap(), Ok(()));
        drop(clients);
        drop(InstanceGuard::acquire(&runtime).unwrap());
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[tokio::test]
    async fn cross_connection_cancel_skips_queued_work_but_not_active_work() {
        let runtime = test_runtime("daemon-cancel-queue");
        let provider = Arc::new(FixedTokenProvider::default());
        let keys = Arc::new(MemoryKeyStore::default());
        let path = unique_temp_path("daemon-cancel-queue").join("vault.db");
        let gate = Arc::new(BlockingWorkerHook::new());
        let config = test_config(runtime.clone(), path.clone(), keys.clone(), provider)
            .with_worker_hook(gate.clone());
        let daemon = Daemon::start(config).await.unwrap();
        let handle = daemon.handle();
        let owner = tokio::spawn(daemon.run());
        let mut active_client = RawClient::connect(&runtime, ClientRole::Desktop).await;
        let mut queued_client = RawClient::connect(&runtime, ClientRole::Desktop).await;
        let mut cancel_client = RawClient::connect(&runtime, ClientRole::Desktop).await;

        let LocalRequest::ProjectPathSet(active_path) = request_fixture(
            "project_path_set",
            serde_json::json!({
                "projectId": "018f22e2-79b0-7cc8-98c4-dc0c0c07398f",
                "path": {"platform": "windows", "bytes": "AQI", "display": "C:\\active"},
            }),
        ) else {
            unreachable!()
        };
        let active_project_id = active_path.project_id.to_string();
        let expected_active_path = active_path.path.clone();
        let active_id = next_record_id();
        let active = tokio::spawn(async move {
            active_client
                .call_with_id(active_id, LocalRequest::ProjectPathSet(active_path))
                .await
        });
        gate.wait_until_entered().await;

        assert_eq!(
            cancel_client
                .call(LocalRequest::Cancel(CancelParams {
                    request_id: active_id,
                }))
                .await
                .unwrap(),
            LocalResult::Empty
        );

        let LocalRequest::ProjectPathSet(queued_path) = request_fixture(
            "project_path_set",
            serde_json::json!({
                "projectId": "018f22e2-79b0-7cc8-98c4-dc0c0c073981",
                "path": {"platform": "windows", "bytes": "AwQ", "display": "C:\\queued"},
            }),
        ) else {
            unreachable!()
        };
        let queued_project_id = queued_path.project_id.to_string();
        let queued_id = next_record_id();
        let queued = tokio::spawn(async move {
            queued_client
                .call_with_id(queued_id, LocalRequest::ProjectPathSet(queued_path))
                .await
        });
        gate.wait_until_enqueued(2).await;

        assert_eq!(
            cancel_client
                .call(LocalRequest::Cancel(CancelParams {
                    request_id: queued_id,
                }))
                .await
                .unwrap(),
            LocalResult::Empty
        );
        gate.release();

        assert_eq!(active.await.unwrap(), Ok(LocalResult::Empty));
        assert_eq!(queued.await.unwrap(), Err(canceled_error()));
        assert_eq!(handle.shutdown().await, DaemonState::Stopped);
        assert_eq!(owner.await.unwrap(), Ok(()));

        let reopened = Vault::open(&path, "test-vault-key", keys.as_ref()).unwrap();
        assert_eq!(
            reopened.path(&active_project_id).unwrap(),
            Some(expected_active_path)
        );
        assert_eq!(reopened.path(&queued_project_id).unwrap(), None);
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[tokio::test]
    async fn server_timeout_is_typed_and_work_can_commit_after_the_waiter_leaves() {
        let runtime = test_runtime("daemon-timeout");
        let provider = Arc::new(FixedTokenProvider::default());
        let keys = Arc::new(MemoryKeyStore::default());
        let path = unique_temp_path("daemon-timeout").join("vault.db");
        let gate = Arc::new(BlockingWorkerHook::new());
        let config = test_config(runtime.clone(), path.clone(), keys.clone(), provider)
            .with_worker_hook(gate.clone());
        let daemon = Daemon::start(config).await.unwrap();
        let handle = daemon.handle();
        let owner = tokio::spawn(daemon.run());
        let mut client = RawClient::connect(&runtime, ClientRole::Desktop).await;
        tokio::time::pause();
        let project_id = "018f22e2-79b0-7cc8-98c4-dc0c0c07398f";
        let LocalRequest::ProjectPathSet(path_set) = request_fixture(
            "project_path_set",
            serde_json::json!({
                "projectId": project_id,
                "path": {"platform": "windows", "bytes": "AQI", "display": null},
            }),
        ) else {
            unreachable!()
        };
        let expected_path = path_set.path.clone();
        let request =
            tokio::spawn(async move { client.call(LocalRequest::ProjectPathSet(path_set)).await });
        gate.wait_until_entered().await;

        tokio::time::advance(WORK_RESPONSE_TIMEOUT + Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(request.await.unwrap(), Err(work_timeout_error()));
        assert_eq!(handle.state(), DaemonState::Running);

        gate.release();
        assert_eq!(handle.shutdown().await, DaemonState::Stopped);
        assert_eq!(owner.await.unwrap(), Ok(()));
        let reopened = Vault::open(&path, "test-vault-key", keys.as_ref()).unwrap();
        assert_eq!(reopened.path(project_id).unwrap(), Some(expected_path));
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[tokio::test]
    async fn shutdown_deadline_detaches_while_listener_worker_and_guard_remain_owned() {
        let runtime = test_runtime("daemon-draining-owner");
        let provider = Arc::new(FixedTokenProvider::default());
        let keys = Arc::new(MemoryKeyStore::default());
        let path = unique_temp_path("daemon-draining-owner").join("vault.db");
        let daemon = Daemon::start(test_config(runtime.clone(), path, keys, provider))
            .await
            .unwrap();
        let (entered_sender, entered_receiver) = std::sync::mpsc::sync_channel(0);
        let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(0);
        let blocked = daemon
            .worker
            .client()
            .try_submit(
                VaultCommand::TestBlock {
                    entered: entered_sender,
                    release: release_receiver,
                },
                TestAdmission(true),
            )
            .unwrap();
        entered_receiver.recv().unwrap();
        let handle = daemon.handle();
        let owner = tokio::spawn(daemon.run());
        let _idle_client = RawClient::connect(&runtime, ClientRole::Desktop).await;
        let mut shutdown_client = RawClient::connect(&runtime, ClientRole::Desktop).await;
        tokio::time::pause();

        assert_eq!(
            shutdown_client
                .call(LocalRequest::Shutdown(EmptyParams {}))
                .await
                .unwrap(),
            LocalResult::Empty
        );
        let shutdown_waiter = {
            let handle = handle.clone();
            tokio::spawn(async move { handle.shutdown().await })
        };
        tokio::task::yield_now().await;
        tokio::time::advance(SHUTDOWN_TIMEOUT + Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(shutdown_waiter.await.unwrap(), DaemonState::Draining);
        assert_eq!(handle.state(), DaemonState::Draining);
        drop(handle);
        assert!(matches!(
            InstanceGuard::acquire(&runtime),
            Err(IpcError::AlreadyRunning)
        ));

        tokio::time::resume();
        release_sender.send(()).unwrap();
        assert_eq!(blocked.await.unwrap(), Ok(LocalResult::Empty));
        assert_eq!(owner.await.unwrap(), Ok(()));
        drop(InstanceGuard::acquire(&runtime).unwrap());
    }

    struct BlockingWorkerHook {
        entered: Mutex<Option<oneshot::Sender<()>>>,
        entered_receiver: Mutex<Option<oneshot::Receiver<()>>>,
        block: Arc<(Mutex<bool>, Condvar)>,
        enqueued: AtomicUsize,
        enqueue_wake: tokio::sync::Notify,
    }

    impl BlockingWorkerHook {
        fn new() -> Self {
            let (entered, entered_receiver) = oneshot::channel();
            Self {
                entered: Mutex::new(Some(entered)),
                entered_receiver: Mutex::new(Some(entered_receiver)),
                block: Arc::new((Mutex::new(false), Condvar::new())),
                enqueued: AtomicUsize::new(0),
                enqueue_wake: tokio::sync::Notify::new(),
            }
        }

        async fn wait_until_entered(&self) {
            let entered = self.entered_receiver.lock().unwrap().take().unwrap();
            entered.await.unwrap();
        }

        async fn wait_until_enqueued(&self, target: usize) {
            loop {
                let notified = self.enqueue_wake.notified();
                if self.enqueued.load(Ordering::Acquire) >= target {
                    return;
                }
                notified.await;
            }
        }

        fn release(&self) {
            let (released, wake) = &*self.block;
            *released.lock().unwrap() = true;
            wake.notify_all();
        }
    }

    impl WorkerHook for BlockingWorkerHook {
        fn before_execute(&self) {
            if let Some(entered) = self.entered.lock().unwrap().take() {
                let _ = entered.send(());
            }
            let (released, wake) = &*self.block;
            let mut released = released.lock().unwrap();
            while !*released {
                released = wake.wait(released).unwrap();
            }
        }

        fn after_enqueue(&self) {
            self.enqueued.fetch_add(1, Ordering::Release);
            self.enqueue_wake.notify_one();
        }
    }

    struct RawClient {
        stream: ConnectedStream,
        protocol: context_relay_protocol::ProtocolVersion,
        daemon_instance_nonce: DaemonInstanceNonce,
    }

    impl RawClient {
        async fn connect(runtime: &RuntimeConfig, role: ClientRole) -> Self {
            Self::connect_with_token(runtime, role, [0x5a; 32]).await
        }

        async fn connect_with_token(
            runtime: &RuntimeConfig,
            role: ClientRole,
            token_bytes: [u8; 32],
        ) -> Self {
            let mut stream = connect(runtime).await.unwrap();
            let hello: ServerHelloV1 = read_json(&mut stream).await.unwrap();
            let token = InstallationToken::from_bytes(token_bytes);
            let client_nonce = DaemonInstanceNonce::new([0x22; 32]);
            let transcript = AuthTranscriptV1 {
                role,
                client_nonce,
                server_hello: hello,
            };
            write_json(
                &mut stream,
                &JsonRpcRequestV1 {
                    jsonrpc: JsonRpcVersion::V2,
                    id: next_record_id(),
                    protocol: hello.protocol,
                    daemon_instance_nonce: hello.daemon_instance_nonce,
                    request: LocalRequest::Hello(HelloParams {
                        client_role: role,
                        client_nonce,
                        session_proof: create_proof(&token, &transcript),
                    }),
                },
            )
            .await
            .unwrap();
            let _: AuthAcceptedV1 = read_json(&mut stream).await.unwrap();
            Self {
                stream,
                protocol: hello.protocol,
                daemon_instance_nonce: hello.daemon_instance_nonce,
            }
        }

        async fn call(&mut self, request: LocalRequest) -> Result<LocalResult, ClientError> {
            let id = next_record_id();
            self.call_with_id(id, request).await
        }

        async fn call_with_id(
            &mut self,
            id: RecordId,
            request: LocalRequest,
        ) -> Result<LocalResult, ClientError> {
            write_json(
                &mut self.stream,
                &JsonRpcRequestV1 {
                    jsonrpc: JsonRpcVersion::V2,
                    id,
                    protocol: self.protocol,
                    daemon_instance_nonce: self.daemon_instance_nonce,
                    request,
                },
            )
            .await
            .unwrap();
            let value: serde_json::Value = read_json(&mut self.stream).await.unwrap();
            if value.get("result").is_some() {
                let response: JsonRpcSuccessV1 = serde_json::from_value(value).unwrap();
                assert_eq!(response.id, id);
                Ok(response.result)
            } else {
                let response: JsonRpcErrorV1 = serde_json::from_value(value).unwrap();
                assert_eq!(response.id, Some(id));
                Err(response.error.data)
            }
        }
    }

    fn next_record_id() -> RecordId {
        RecordId::new(uuid::Uuid::now_v7()).unwrap()
    }

    struct TestAdmission(bool);

    impl WorkAdmission for TestAdmission {
        fn begin(&self) -> bool {
            self.0
        }
    }

    fn assert_exact_error(routed: RoutedRequest, expected: ClientError) {
        match routed {
            RoutedRequest::Immediate(Err(error)) => assert_eq!(error, expected),
            other => panic!("expected immediate error, got {other:?}"),
        }
    }

    fn request_fixture(method: &str, params: serde_json::Value) -> LocalRequest {
        let request: LocalRequest = serde_json::from_value(serde_json::json!({
            "method": method,
            "params": params,
        }))
        .unwrap();
        request.validate().unwrap();
        request
    }

    #[cfg(any(windows, target_os = "macos"))]
    fn canonical_test_directory(label: &str) -> PathBuf {
        let path = unique_temp_path(label);
        std::fs::create_dir_all(&path).unwrap();
        std::fs::canonicalize(path).unwrap()
    }

    #[cfg(any(windows, target_os = "macos"))]
    fn wire_native_path(path: &Path) -> WireNativeValue {
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::ffi::OsStrExt;

            WireNativeValue {
                platform: NativePlatform::Macos,
                bytes: path.as_os_str().as_bytes().to_vec(),
                display: Some(path.display().to_string()),
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;

            WireNativeValue {
                platform: NativePlatform::Windows,
                bytes: path
                    .as_os_str()
                    .encode_wide()
                    .flat_map(u16::to_le_bytes)
                    .collect(),
                display: Some(path.display().to_string()),
            }
        }
    }

    #[cfg(any(windows, target_os = "macos"))]
    fn mcp_request(path: &Path, name: &str, arguments: serde_json::Value) -> LocalRequest {
        LocalRequest::McpCall(McpCallParams {
            binding: McpBinding {
                harness: HarnessId::Codex,
                working_directory: wire_native_path(path),
            },
            name: name.to_owned(),
            arguments,
        })
    }

    #[cfg(any(windows, target_os = "macos"))]
    fn routed_mcp_command(request: LocalRequest) -> VaultCommand {
        match route_request(ClientRole::McpBridge, request) {
            RoutedRequest::Work(command @ VaultCommand::Workspace(LocalRequest::McpCall(_))) => {
                command
            }
            other => panic!("expected queued MCP workspace command, got {other:?}"),
        }
    }

    #[cfg(any(windows, target_os = "macos"))]
    fn seed_mcp_project(
        path: &Path,
        keys: &dyn DatabaseKeyStore,
        root: &Path,
        policy: HarnessAccessPolicy,
    ) -> ProjectId {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut vault = Vault::open(path, "test-vault-key", keys).unwrap();
        let project_id = "018f22e2-79b0-7cc8-98c4-dc0c0c07398f".parse().unwrap();
        vault
            .put_project(&ProjectIdentity {
                project_id,
                github_repository_id: None,
                git_remote_fingerprint: None,
                monorepo_subdirectory: None,
                name: "Scoped MCP project".into(),
            })
            .unwrap();
        vault
            .put_path(&project_id.to_string(), &wire_native_path(root))
            .unwrap();
        vault.set_access_policy(HarnessId::Codex, &policy).unwrap();
        project_id
    }

    fn all_request_fixtures() -> Vec<(&'static str, LocalRequest)> {
        const ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07398f";
        let bytes32 = serde_json::to_value(DaemonInstanceNonce::new([0x11; 32]))
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned();
        let digest = "11".repeat(32);
        let empty = || serde_json::json!({});
        let harness =
            || serde_json::json!({"harness": "codex", "projectId": null, "hermesProfile": null});

        vec![
            (
                "HostedAuthStatus",
                request_fixture("hosted_auth_status", empty()),
            ),
            (
                "HostedAuthStart",
                request_fixture(
                    "hosted_auth_start",
                    serde_json::json!({"operationId": ID, "expectedGeneration": ID}),
                ),
            ),
            (
                "HostedAuthCancel",
                request_fixture("hosted_auth_cancel", serde_json::json!({"generation": ID})),
            ),
            (
                "HostedAuthLogout",
                request_fixture("hosted_auth_logout", serde_json::json!({"generation": ID})),
            ),
            (
                "DesktopWritesList",
                request_fixture("desktop_writes_list", serde_json::json!({"after": null})),
            ),
            (
                "DesktopWriteGet",
                request_fixture("desktop_write_get", serde_json::json!({"operationId": ID})),
            ),
            (
                "DesktopWriteForget",
                request_fixture(
                    "desktop_write_forget",
                    serde_json::json!({"operationId": ID}),
                ),
            ),
            (
                "DesktopWritePrepare",
                request_fixture(
                    "desktop_write_prepare",
                    serde_json::json!({"write": {"method":"memory_archive","params":{"operationId": ID,"memoryId": ID,"expectedRevision": ID}}}),
                ),
            ),
            (
                "Hello",
                request_fixture(
                    "hello",
                    serde_json::json!({"clientRole": "desktop", "clientNonce": bytes32, "sessionProof": bytes32}),
                ),
            ),
            (
                "Cancel",
                request_fixture("cancel", serde_json::json!({"requestId": ID})),
            ),
            ("Shutdown", request_fixture("shutdown", empty())),
            ("Health", request_fixture("health", empty())),
            (
                "McpCall",
                request_fixture(
                    "mcp_call",
                    serde_json::json!({
                        "binding": {
                            "harness": "codex",
                            "workingDirectory": {
                                "platform": "macos",
                                "bytes": "L3dvcmtzcGFjZQ",
                                "display": "/workspace",
                            },
                        },
                        "name": "context_relay_status",
                        "arguments": {},
                    }),
                ),
            ),
            (
                "NativeHookEvent",
                request_fixture(
                    "native_hook_event",
                    serde_json::json!({
                        "binding": {
                            "harness": "codex",
                            "workingDirectory": {
                                "platform": "macos",
                                "bytes": "L3dvcmtzcGFjZQ",
                                "display": "/workspace",
                            },
                        },
                        "event": {"kind": "session_start", "session_id": "session-1"},
                        "occurredAtMs": "1700000000123",
                    }),
                ),
            ),
            ("Unlock", request_fixture("unlock", empty())),
            ("ProjectsList", request_fixture("projects_list", empty())),
            (
                "ProjectUpsert",
                request_fixture(
                    "project_upsert",
                    serde_json::json!({"project": {"projectId": ID, "githubRepositoryId": null, "gitRemoteFingerprint": null, "monorepoSubdirectory": null, "name": "Context Relay"}}),
                ),
            ),
            (
                "ProjectRegister",
                request_fixture(
                    "project_register",
                    serde_json::json!({"project": {"projectId": ID, "githubRepositoryId": null, "gitRemoteFingerprint": null, "monorepoSubdirectory": null, "name": "Context Relay"}, "path": {"platform": "windows", "bytes": "", "display": null}}),
                ),
            ),
            (
                "ProjectPathSet",
                request_fixture(
                    "project_path_set",
                    serde_json::json!({"projectId": ID, "path": {"platform": "windows", "bytes": "", "display": null}}),
                ),
            ),
            (
                "MemoryGet",
                request_fixture("memory_get", serde_json::json!({"memoryId": ID})),
            ),
            (
                "MemoryList",
                request_fixture(
                    "memory_list",
                    serde_json::json!({"projectId": null, "includeArchived": false}),
                ),
            ),
            (
                "MemorySearch",
                request_fixture(
                    "memory_search",
                    serde_json::json!({"query": "query", "projectId": null}),
                ),
            ),
            (
                "MemoryCreate",
                request_fixture(
                    "memory_create",
                    serde_json::json!({"operationId": ID, "scope": {"scope": "global"}, "kind": "note", "title": "title", "bodyMarkdown": "body", "tags": []}),
                ),
            ),
            (
                "MemoryUpdate",
                request_fixture(
                    "memory_update",
                    serde_json::json!({"operationId": ID, "memoryId": ID, "expectedRevision": ID, "title": "updated", "bodyMarkdown": null, "tags": null}),
                ),
            ),
            (
                "MemoryArchive",
                request_fixture(
                    "memory_archive",
                    serde_json::json!({"operationId": ID, "memoryId": ID, "expectedRevision": ID}),
                ),
            ),
            (
                "CandidatesList",
                request_fixture("candidates_list", serde_json::json!({"projectId": null})),
            ),
            (
                "CandidateReview",
                request_fixture(
                    "candidate_review",
                    serde_json::json!({"candidateId": ID, "accepted": false, "operationId": ID}),
                ),
            ),
            (
                "TasksList",
                request_fixture("tasks_list", serde_json::json!({"projectId": ID})),
            ),
            (
                "TaskUpsert",
                request_fixture(
                    "task_upsert",
                    serde_json::json!({"operationId": ID, "taskId": null, "projectId": ID, "title": "task", "bodyMarkdown": "body", "status": "open", "expectedRevision": null}),
                ),
            ),
            (
                "TaskComplete",
                request_fixture(
                    "task_complete",
                    serde_json::json!({"operationId": ID, "taskId": ID, "expectedRevision": ID, "evidence": [{"summary": "done", "kind": "test", "reference": null}]}),
                ),
            ),
            (
                "TaskTransition",
                request_fixture(
                    "task_transition",
                    serde_json::json!({"operationId": ID, "taskId": ID, "expectedRevision": ID, "status": "in_progress"}),
                ),
            ),
            (
                "HandoffCreate",
                request_fixture(
                    "handoff_create",
                    serde_json::json!({"operationId": ID, "memoryIds": [ID], "decisionIds": [], "taskIds": [], "summary": "summary"}),
                ),
            ),
            ("AccessGet", request_fixture("access_get", harness())),
            (
                "AccessSet",
                request_fixture(
                    "access_set",
                    serde_json::json!({"operationId": ID, "harness": "codex", "policy": {"mode": "default"}}),
                ),
            ),
            ("HarnessProbe", request_fixture("harness_probe", harness())),
            (
                "HarnessPreparedPreview",
                request_fixture(
                    "harness_prepared_preview",
                    serde_json::json!({
                        "operationId": ID,
                        "selection": {"harness": "hermes", "projectId": null, "hermesProfile": "default"}
                    }),
                ),
            ),
            (
                "HarnessPreview",
                request_fixture("harness_preview", harness()),
            ),
            (
                "HarnessApply",
                request_fixture("harness_apply", serde_json::json!({"planId": ID})),
            ),
            (
                "HarnessRepair",
                request_fixture("harness_repair", harness()),
            ),
            (
                "HarnessRollback",
                request_fixture("harness_rollback", serde_json::json!({"planId": ID})),
            ),
            (
                "PackageImport",
                request_fixture(
                    "package_import",
                    serde_json::json!({"packageBase64url": "", "dryRun": true}),
                ),
            ),
            (
                "PackageExport",
                request_fixture(
                    "package_export",
                    serde_json::json!({"projectId": null, "includeArchived": false}),
                ),
            ),
            ("SyncStatus", request_fixture("sync_status", empty())),
            (
                "SyncRetry",
                request_fixture("sync_retry", serde_json::json!({"operationId": ID})),
            ),
            ("DevicesList", request_fixture("devices_list", empty())),
            (
                "DeviceRename",
                request_fixture(
                    "device_rename",
                    serde_json::json!({"operationId": ID, "deviceId": ID, "name": "device"}),
                ),
            ),
            (
                "DeviceRevoke",
                request_fixture("device_revoke", serde_json::json!({"deviceId": ID})),
            ),
            ("PairingCreate", request_fixture("pairing_create", empty())),
            (
                "PairingJoin",
                request_fixture(
                    "pairing_join",
                    serde_json::json!({"code": "01234-ABCDE", "deviceName": "device"}),
                ),
            ),
            (
                "PairingStatus",
                request_fixture("pairing_status", serde_json::json!({"pairingId": ID})),
            ),
            (
                "PairingDecision",
                request_fixture(
                    "pairing_decision",
                    serde_json::json!({"pairingId": ID, "requestDigest": digest, "approve": false}),
                ),
            ),
            (
                "PairingConfirm",
                request_fixture(
                    "pairing_confirm",
                    serde_json::json!({
                        "pairingId": ID,
                        "safetyNumber": "0123-4567-89AB-CDEF-0123",
                    }),
                ),
            ),
            (
                "PairingCancel",
                request_fixture("pairing_cancel", serde_json::json!({"pairingId": ID})),
            ),
            (
                "RecoveryRestoreBegin",
                request_fixture(
                    "recovery_restore_begin",
                    serde_json::json!({"recoveryPhraseWords":vec!["abandon";24]}),
                ),
            ),
            (
                "RecoveryRestoreOverview",
                request_fixture("recovery_restore_overview", empty()),
            ),
            (
                "RecoveryRestoreCancel",
                request_fixture("recovery_restore_cancel", empty()),
            ),
            (
                "RecoveryRestoreResume",
                request_fixture("recovery_restore_resume", empty()),
            ),
            (
                "RecoveryEnrollmentBegin",
                request_fixture("recovery_enrollment_begin", empty()),
            ),
            (
                "RecoveryEnrollmentOverview",
                request_fixture("recovery_enrollment_overview", empty()),
            ),
            (
                "RecoveryEnrollmentConfirm",
                request_fixture(
                    "recovery_enrollment_confirm",
                    serde_json::json!({
                        "enrollmentId": ID,
                        "confirmations": [
                            {"position": 2, "word": "abandon"},
                            {"position": 7, "word": "ability"},
                            {"position": 13, "word": "able"},
                            {"position": 24, "word": "about"},
                        ],
                    }),
                ),
            ),
            (
                "RecoveryEnrollmentStatus",
                request_fixture(
                    "recovery_enrollment_status",
                    serde_json::json!({"enrollmentId": ID}),
                ),
            ),
            (
                "RecoveryEnrollmentCancel",
                request_fixture(
                    "recovery_enrollment_cancel",
                    serde_json::json!({"enrollmentId": ID}),
                ),
            ),
            (
                "ExportRecords",
                request_fixture(
                    "export_records",
                    serde_json::json!({"projectId": null, "includeArchived": false}),
                ),
            ),
            (
                "ExportChunk",
                request_fixture(
                    "export_chunk",
                    serde_json::json!({"exportId": ID, "chunkIndex": 0}),
                ),
            ),
            (
                "AccountDeletionBegin",
                request_fixture(
                    "account_deletion_begin",
                    serde_json::json!({"operationId": ID, "confirmation": "delete"}),
                ),
            ),
            (
                "AccountDeletionStatus",
                request_fixture("account_deletion_status", empty()),
            ),
            (
                "AccountDeletionCancel",
                request_fixture(
                    "account_deletion_cancel",
                    serde_json::json!({"operationId": ID}),
                ),
            ),
        ]
    }

    fn test_runtime(label: &str) -> RuntimeConfig {
        #[cfg(target_os = "macos")]
        {
            let unique = uuid::Uuid::now_v7().simple().to_string();
            RuntimeConfig::for_test(
                format!("{label}-{}", &unique[16..]),
                Some(PathBuf::from("/tmp").join(format!("cr-ctx-{}", &unique[16..]))),
            )
            .unwrap()
        }

        #[cfg(not(target_os = "macos"))]
        {
            RuntimeConfig::for_test(
                format!("{label}-{}", uuid::Uuid::now_v7().simple()),
                Some(unique_temp_path(label)),
            )
            .unwrap()
        }
    }

    fn unique_temp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "context-relay-contextd-{label}-{}",
            uuid::Uuid::now_v7()
        ))
    }

    fn test_config(
        runtime: RuntimeConfig,
        path: PathBuf,
        keys: Arc<dyn DatabaseKeyStore>,
        provider: Arc<dyn InstallationTokenProvider>,
    ) -> DaemonConfig {
        DaemonConfig::new(
            runtime,
            VaultConfig::new(path, "test-vault-key", keys),
            provider,
        )
    }

    fn seed_pending_native_transactions(path: &std::path::Path, keys: &dyn DatabaseKeyStore) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut vault = Vault::open(path, "test-vault-key", keys).unwrap();
        for (index, (transaction_id, plan_id)) in [
            (
                "018f22e2-79b0-7cc8-98c4-dc0c0c073980",
                "018f22e2-79b0-7cc8-98c4-dc0c0c073981",
            ),
            (
                "018f22e2-79b0-7cc8-98c4-dc0c0c073982",
                "018f22e2-79b0-7cc8-98c4-dc0c0c073983",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let plan_id = plan_id.parse::<PlanId>().unwrap();
            vault
                .begin_native_transaction(
                    transaction_id,
                    NativePlanWrite {
                        plan_id: &plan_id,
                        approval_hash: &Sha256Digest([index as u8 + 1; 32]),
                        payload: b"startup-recovery-plan",
                        created_ms: index as u64 + 1,
                        expires_ms: index as u64 + 2,
                    },
                    test_sandbox_identity(index as u8 + 1),
                )
                .unwrap();
        }
    }

    #[cfg(any(windows, target_os = "macos"))]
    fn seed_interrupted_nonlaunching_bridge_setup(
        path: &Path,
        keys: &dyn DatabaseKeyStore,
    ) -> (PlanId, String) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut vault = Vault::open(path, "test-vault-key", keys).unwrap();
        let plan = bridge_install::tests::persist_plan(&mut vault);
        let plan_id = plan.setup.plan_id;
        assert_eq!(
            vault
                .claim_setup_plan(&plan_id, SetupPlanAction::Apply, 2)
                .unwrap(),
            context_relay_core::vault::SetupPlanClaim::Claimed
        );
        let stored = vault.setup_plan(&plan_id).unwrap().unwrap();
        let transaction_id = format!("bridge-setup-{plan_id}");
        vault
            .begin_native_transaction(
                &transaction_id,
                NativePlanWrite {
                    plan_id: &plan_id,
                    approval_hash: &stored.approval_hash,
                    payload: &stored.payload,
                    created_ms: stored.created_ms,
                    expires_ms: stored.expires_ms,
                },
                bridge_install::nonlaunching_sandbox_identity(),
            )
            .unwrap();
        (plan_id, transaction_id)
    }

    #[cfg(target_os = "macos")]
    fn seed_interrupted_bridge_cli_setup(
        path: &Path,
        keys: &dyn DatabaseKeyStore,
        executable: &Path,
        bridge_executable: &Path,
        execution_context: context_relay_core::native_transaction::CliExecutionContext,
        committed: bool,
    ) -> (PlanId, String) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut vault = Vault::open(path, "test-vault-key", keys).unwrap();
        let plan = bridge_install::tests::persist_claude_cli_plan(
            &mut vault,
            executable,
            bridge_executable,
            execution_context,
        );
        let plan_id = plan.setup.plan_id;
        vault
            .claim_setup_plan(&plan_id, SetupPlanAction::Apply, 2)
            .unwrap();
        let stored = vault.setup_plan(&plan_id).unwrap().unwrap();
        let transaction_id = format!("bridge-setup-{plan_id}");
        vault
            .begin_native_transaction(
                &transaction_id,
                NativePlanWrite {
                    plan_id: &plan_id,
                    approval_hash: &stored.approval_hash,
                    payload: &stored.payload,
                    created_ms: stored.created_ms,
                    expires_ms: stored.expires_ms,
                },
                bridge_install::nonlaunching_sandbox_identity(),
            )
            .unwrap();
        let mutation = &plan.cli_mutations[0];
        let target = mutation.intended.as_ref().unwrap();
        let forward = serde_json::to_vec(&mutation.forward).unwrap();
        let rollback = serde_json::to_vec(&mutation.rollback).unwrap();
        vault
            .prepare_native_cli_wal(
                &transaction_id,
                &NativeCliWalWrite {
                    sequence: 0,
                    stable_id: &mutation.stable_id,
                    harness: target.harness,
                    server_name: &target.server_name,
                    expected_declaration: None,
                    expected_fingerprint: None,
                    intended_declaration: Some(target.canonical_body.as_bytes()),
                    intended_fingerprint: Some(&target.fingerprint),
                    forward_operations: &forward,
                    rollback_operations: &rollback,
                },
            )
            .unwrap();
        if committed {
            vault
                .transition_native_cli_wal(
                    &transaction_id,
                    0,
                    context_relay_core::vault::NativeCliWalState::Applied,
                )
                .unwrap();
            for step in &TransactionStep::ORDER[..18] {
                vault.enter_native_step(&transaction_id, *step).unwrap();
                vault.complete_native_step(&transaction_id, *step).unwrap();
            }
            vault
                .enter_native_step(&transaction_id, TransactionStep::CommitOwnershipAndReceipt)
                .unwrap();
            let device_id = DeviceId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073990").unwrap();
            vault
                .commit_native_success(
                    &transaction_id,
                    &NativeApplyReceipt {
                        legacy: ApplyReceipt {
                            plan_id,
                            applied_hlc: HybridLogicalClock::new(3, 0, device_id),
                            resulting_digests: vec![],
                        },
                        targets: vec![],
                    },
                    &[],
                )
                .unwrap();
        }
        (plan_id, transaction_id)
    }

    #[cfg(target_os = "macos")]
    fn nonlaunching_macos_recovery_identity() -> RecoverySandboxIdentity {
        let generation_id = bridge_install::NON_LAUNCHING_GENERATION_ID.to_owned();
        let bundle_id = format!("com.contextrelay.native-runner.{generation_id}");
        let mut container = b"context-relay/macos-container/v1\0".to_vec();
        container.extend_from_slice(bundle_id.as_bytes());
        RecoverySandboxIdentity::Macos {
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

    #[cfg(target_os = "macos")]
    struct EnvironmentOverride {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    #[cfg(target_os = "macos")]
    impl EnvironmentOverride {
        fn set(key: &'static str, value: &std::ffi::OsStr) -> Self {
            let previous = std::env::var_os(key);
            // SAFETY: this test holds `ENVIRONMENT_LOCK` for every temporary
            // process-environment override it creates.
            unsafe { std::env::set_var(key, value) };
            Self { key, previous }
        }
    }

    #[cfg(target_os = "macos")]
    impl Drop for EnvironmentOverride {
        fn drop(&mut self) {
            // SAFETY: the owning test still holds `ENVIRONMENT_LOCK` while
            // restoring the exact prior process-environment value.
            unsafe {
                match &self.previous {
                    Some(previous) => std::env::set_var(self.key, previous),
                    None => std::env::remove_var(self.key),
                }
            }
        }
    }

    fn test_sandbox_identity(sequence: u8) -> NativeSandboxIdentity {
        #[cfg(windows)]
        {
            NativeSandboxIdentity::Windows {
                moniker: format!("context-relay.native.{sequence:032x}"),
                sid: format!("S-1-15-2-{sequence}-2-3-4-5-6-7").into_bytes(),
            }
        }
        #[cfg(target_os = "macos")]
        {
            let generation_id = format!("{sequence:032x}");
            let bundle_id = format!("com.contextrelay.native-runner.{generation_id}");
            let mut container = b"context-relay/macos-container/v1\0".to_vec();
            container.extend_from_slice(bundle_id.as_bytes());
            NativeSandboxIdentity::reserved_macos(generation_id, bundle_id, container)
        }
    }

    #[cfg(target_os = "macos")]
    fn seed_terminal_macos_generation(
        path: &std::path::Path,
        keys: &dyn DatabaseKeyStore,
        transaction_id: &str,
        plan_id: &str,
        generation_id: &str,
    ) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut vault = Vault::open(path, "test-vault-key", keys).unwrap();
        let plan_id = plan_id.parse::<PlanId>().unwrap();
        let bundle_id = format!("com.contextrelay.native-runner.{generation_id}");
        let mut container = b"context-relay/macos-container/v1\0".to_vec();
        container.extend_from_slice(bundle_id.as_bytes());
        vault
            .begin_native_transaction(
                transaction_id,
                NativePlanWrite {
                    plan_id: &plan_id,
                    approval_hash: &Sha256Digest([1; 32]),
                    payload: b"macos-startup-cleanup-conflict",
                    created_ms: 1,
                    expires_ms: 2,
                },
                NativeSandboxIdentity::reserved_macos(
                    generation_id.to_owned(),
                    bundle_id,
                    container,
                ),
            )
            .unwrap();
        vault.bind_macos_guardian(transaction_id, i32::MAX).unwrap();
        vault
            .bind_macos_bundle_root(
                transaction_id,
                &MacRootIdentity::new(1, 2, 3, 4, 5, 0o040700)
                    .unwrap()
                    .encode(),
            )
            .unwrap();
        vault
            .finalize_macos_generation(transaction_id, &Sha256Digest([2; 32]))
            .unwrap();
        vault
            .bind_macos_container_root(
                transaction_id,
                &MacRootIdentity::new(6, 7, 8, 9, 10, 0o040700)
                    .unwrap()
                    .encode(),
            )
            .unwrap();
        vault
            .transition_macos_generation(transaction_id, MacGenerationState::Poisoned)
            .unwrap();
        vault.begin_native_recovery(transaction_id).unwrap();
        vault.finish_native_recovery(transaction_id, false).unwrap();
    }

    #[derive(Default)]
    struct FixedTokenProvider {
        calls: AtomicUsize,
    }

    #[derive(Clone)]
    struct PairingTokenProvider([u8; 32]);

    impl InstallationTokenProvider for PairingTokenProvider {
        fn load_or_create(&self) -> Result<InstallationToken, DaemonError> {
            Ok(InstallationToken::from_bytes(self.0))
        }
    }

    #[derive(Default)]
    struct MemoryDeviceIdentityStore {
        values: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl DeviceIdentityStore for MemoryDeviceIdentityStore {
        fn load(
            &self,
            credential_id: &str,
        ) -> Result<Option<Zeroizing<Vec<u8>>>, DeviceIdentityError> {
            Ok(self
                .values
                .lock()
                .unwrap()
                .get(credential_id)
                .cloned()
                .map(Zeroizing::new))
        }

        fn store_if_absent(
            &self,
            credential_id: &str,
            record: &[u8],
        ) -> Result<StoreIfAbsent, DeviceIdentityError> {
            let mut values = self.values.lock().unwrap();
            if values.contains_key(credential_id) {
                return Ok(StoreIfAbsent::AlreadyExists);
            }
            values.insert(credential_id.into(), record.to_vec());
            Ok(StoreIfAbsent::Stored)
        }
    }

    #[derive(Clone, Default)]
    struct PairingTestClock(Arc<AtomicU64>);

    impl PairingTestClock {
        fn set(&self, now_ms: u64) {
            self.0.store(now_ms, Ordering::SeqCst);
        }
    }

    impl PairingClock for PairingTestClock {
        fn now_ms(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    impl RecoveryEnrollmentClock for PairingTestClock {
        fn now_ms(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    type AcceptedRecoveryRecord = Option<(Vec<u8>, RecoveryEnrollmentReceipt)>;

    #[derive(Clone)]
    struct RecoveryTestTransport {
        scope: SyncScope,
        accepted: Arc<Mutex<AcceptedRecoveryRecord>>,
    }

    impl RecoveryTestTransport {
        fn new(scope: SyncScope) -> Self {
            Self {
                scope,
                accepted: Arc::new(Mutex::new(None)),
            }
        }
    }

    impl RecoveryEnrollmentTransport for RecoveryTestTransport {
        fn scope(&self) -> SyncScope {
            self.scope
        }

        fn root_status(&self) -> Result<Option<RecoveryRootStatus>, RecoveryTransportError> {
            Ok(self
                .accepted
                .lock()
                .map_err(|_| RecoveryTransportError::Transient)?
                .as_ref()
                .map(|(_, receipt)| receipt.clone().into_status()))
        }

        fn register(
            &self,
            canonical_record: &[u8],
            now_ms: u64,
        ) -> Result<RecoveryEnrollmentReceipt, RecoveryTransportError> {
            let record = decode_recovery_enrollment_record_v1(canonical_record)
                .map_err(|_| RecoveryTransportError::Invalid)?;
            if record.account_id != self.scope.account_id
                || record.workspace_id != self.scope.workspace_id
            {
                return Err(RecoveryTransportError::Unauthorized);
            }
            let receipt = RecoveryEnrollmentReceipt {
                enrollment_id: record.enrollment_id,
                recovery_root_id: record.recovery_root_id,
                account_id: record.account_id,
                workspace_id: record.workspace_id,
                genesis_certificate_id: record.genesis_certificate_id,
                canonical_record_sha256: Sha256Digest(Sha256::digest(canonical_record).into()),
                registered_at_ms: now_ms,
            };
            let mut accepted = self
                .accepted
                .lock()
                .map_err(|_| RecoveryTransportError::Transient)?;
            if let Some((bytes, existing)) = &*accepted {
                return if bytes == canonical_record {
                    Ok(existing.clone())
                } else {
                    Err(RecoveryTransportError::Conflict)
                };
            }
            *accepted = Some((canonical_record.to_vec(), receipt.clone()));
            Ok(receipt)
        }
    }

    #[derive(Clone)]
    struct PairingTestMaterialSource {
        scope: SyncScope,
        workspace_root_key: [u8; 32],
        active_epoch_key: [u8; 32],
    }

    impl PairingMaterialSource for PairingTestMaterialSource {
        fn current_material(
            &self,
            _vault: &mut context_relay_core::vault::Vault,
            _device_keys: &DeviceKeys,
            scope: SyncScope,
        ) -> Result<WorkspacePairingMaterial, PairingCycleError> {
            if scope != self.scope {
                return Err(PairingCycleError::Conflict);
            }
            WorkspacePairingMaterial::new(
                scope,
                7,
                11,
                self.workspace_root_key,
                self.active_epoch_key,
            )
        }
    }

    #[derive(Clone, Copy)]
    struct UnavailablePairingJoin;

    impl PairingJoinTransport for UnavailablePairingJoin {
        fn resolve_code(
            &self,
            _code: &context_relay_protocol::PairingCode,
            _now_ms: u64,
        ) -> Result<context_relay_protocol::PairingId, PairingTransportError> {
            Err(PairingTransportError::Unauthorized)
        }

        fn submit_request(
            &self,
            _pairing_id: context_relay_protocol::PairingId,
            _canonical: &[u8],
            _now_ms: u64,
        ) -> Result<PairingRequestReceipt, PairingTransportError> {
            Err(PairingTransportError::Unauthorized)
        }

        fn result(
            &self,
            _pairing_id: context_relay_protocol::PairingId,
            _digest: Sha256Digest,
            _now_ms: u64,
        ) -> Result<PairingResult, PairingTransportError> {
            Err(PairingTransportError::Unauthorized)
        }
    }

    #[derive(Clone, Copy)]
    struct UnavailablePairingApproval;

    impl PairingApprovalTransport for UnavailablePairingApproval {
        fn create_invite(
            &self,
            _now_ms: u64,
        ) -> Result<context_relay_core::devices::transport::PairingInvite, PairingTransportError>
        {
            Err(PairingTransportError::Unauthorized)
        }

        fn invite_status(
            &self,
            _pairing_id: context_relay_protocol::PairingId,
            _now_ms: u64,
        ) -> Result<PairingInviteStatus, PairingTransportError> {
            Err(PairingTransportError::Unauthorized)
        }

        fn request(
            &self,
            _pairing_id: context_relay_protocol::PairingId,
            _now_ms: u64,
        ) -> Result<Option<StoredPairingRequest>, PairingTransportError> {
            Err(PairingTransportError::Unauthorized)
        }

        fn decide(
            &self,
            _envelope: PairingDecisionEnvelope,
            _now_ms: u64,
        ) -> Result<PairingDecisionReceipt, PairingTransportError> {
            Err(PairingTransportError::Unauthorized)
        }

        fn cancel(
            &self,
            _pairing_id: context_relay_protocol::PairingId,
            _now_ms: u64,
        ) -> Result<(), PairingTransportError> {
            Err(PairingTransportError::Unauthorized)
        }
    }

    #[derive(Default)]
    struct ResumeBeforeExecutePairingService {
        resumes: AtomicUsize,
        executes: AtomicUsize,
    }

    #[derive(Default)]
    struct ResumeBeforeExecuteRecoveryService {
        resumes: AtomicUsize,
        executes: AtomicUsize,
        signing_public_key: Mutex<Option<context_relay_protocol::Ed25519PublicKeyBytes>>,
    }

    impl RecoveryEnrollmentService for ResumeBeforeExecuteRecoveryService {
        fn resume_prepared(
            &self,
            _vault: &mut Vault,
            device_keys: &DeviceKeys,
        ) -> Result<(), ClientError> {
            self.resumes.fetch_add(1, Ordering::SeqCst);
            *self.signing_public_key.lock().unwrap() = Some(device_keys.signing_public_key());
            Ok(())
        }

        fn execute(
            &self,
            _vault: &mut Vault,
            device_keys: &DeviceKeys,
            request: LocalRequest,
        ) -> Result<LocalResult, ClientError> {
            let next = self.executes.fetch_add(1, Ordering::SeqCst) + 1;
            assert!(self.resumes.load(Ordering::SeqCst) >= next);
            assert_eq!(
                *self.signing_public_key.lock().unwrap(),
                Some(device_keys.signing_public_key())
            );
            match request {
                LocalRequest::RecoveryEnrollmentOverview(_) => {
                    Ok(LocalResult::RecoveryEnrollmentStatus {
                        status: context_relay_protocol::RecoveryEnrollmentStatus {
                            enrollment_id: None,
                            state: context_relay_protocol::RecoveryEnrollmentState::Idle,
                            created_at_ms: None,
                            transitioned_at_ms: None,
                        },
                    })
                }
                _ => Err(invalid_request_error()),
            }
        }
    }

    struct OrderedRecoveryService {
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    struct TransientResumeRecoveryService;

    impl RecoveryEnrollmentService for TransientResumeRecoveryService {
        fn resume_prepared(
            &self,
            _vault: &mut Vault,
            _device_keys: &DeviceKeys,
        ) -> Result<(), ClientError> {
            Err(ClientError {
                code: ErrorCode::Internal,
                message: "The recovery enrollment service is temporarily unavailable".into(),
                field_path: None,
                retryable: true,
            })
        }

        fn execute(
            &self,
            _vault: &mut Vault,
            _device_keys: &DeviceKeys,
            _request: LocalRequest,
        ) -> Result<LocalResult, ClientError> {
            panic!("startup failure must happen before recovery request dispatch")
        }
    }

    impl RecoveryEnrollmentService for OrderedRecoveryService {
        fn resume_prepared(
            &self,
            _vault: &mut Vault,
            _device_keys: &DeviceKeys,
        ) -> Result<(), ClientError> {
            self.events.lock().unwrap().push("recovery");
            Ok(())
        }

        fn execute(
            &self,
            _vault: &mut Vault,
            _device_keys: &DeviceKeys,
            _request: LocalRequest,
        ) -> Result<LocalResult, ClientError> {
            Ok(LocalResult::Empty)
        }
    }

    struct OrderedPairingService {
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    impl PairingService for OrderedPairingService {
        fn resume_prepared_decisions(&self, _vault: &mut Vault) -> Result<(), ClientError> {
            self.events.lock().unwrap().push("pairing");
            Ok(())
        }

        fn execute(
            &self,
            _vault: &mut Vault,
            _identity: &PairingIdentity,
            _request: LocalRequest,
        ) -> Result<LocalResult, ClientError> {
            Ok(LocalResult::Empty)
        }
    }

    struct OrderedIdentityStore {
        values: Mutex<HashMap<String, Vec<u8>>>,
        events: Arc<Mutex<Vec<&'static str>>>,
        runtime: RuntimeConfig,
    }

    impl DeviceIdentityStore for OrderedIdentityStore {
        fn load(
            &self,
            credential_id: &str,
        ) -> Result<Option<Zeroizing<Vec<u8>>>, DeviceIdentityError> {
            assert!(matches!(
                InstanceGuard::acquire(&self.runtime),
                Err(IpcError::AlreadyRunning)
            ));
            self.events.lock().unwrap().push("identity");
            Ok(self
                .values
                .lock()
                .unwrap()
                .get(credential_id)
                .cloned()
                .map(Zeroizing::new))
        }

        fn store_if_absent(
            &self,
            credential_id: &str,
            record: &[u8],
        ) -> Result<StoreIfAbsent, DeviceIdentityError> {
            let mut values = self.values.lock().unwrap();
            if values.contains_key(credential_id) {
                return Ok(StoreIfAbsent::AlreadyExists);
            }
            values.insert(credential_id.into(), record.to_vec());
            Ok(StoreIfAbsent::Stored)
        }
    }

    struct OrderedKeyStore {
        value: Mutex<Option<Vec<u8>>>,
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    impl DatabaseKeyStore for OrderedKeyStore {
        fn load_key(&self, _: &str) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
            self.events.lock().unwrap().push("vault");
            Ok(self.value.lock().unwrap().clone().map(Zeroizing::new))
        }

        fn store_key(&self, _: &str, key: &[u8]) -> Result<(), VaultError> {
            *self.value.lock().unwrap() = Some(key.to_vec());
            Ok(())
        }
    }

    impl PairingService for ResumeBeforeExecutePairingService {
        fn resume_prepared_decisions(&self, _vault: &mut Vault) -> Result<(), ClientError> {
            self.resumes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn execute(
            &self,
            _vault: &mut Vault,
            _identity: &PairingIdentity,
            _request: LocalRequest,
        ) -> Result<LocalResult, ClientError> {
            let next = self.executes.fetch_add(1, Ordering::SeqCst) + 1;
            assert!(
                self.resumes.load(Ordering::SeqCst) >= next,
                "pairing command executed before restart recovery"
            );
            Ok(LocalResult::Empty)
        }
    }

    impl InstallationTokenProvider for FixedTokenProvider {
        fn load_or_create(&self) -> Result<InstallationToken, DaemonError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(InstallationToken::from_bytes([0x5a; 32]))
        }
    }

    #[derive(Default)]
    struct MemoryKeyStore {
        values: Mutex<HashMap<String, Vec<u8>>>,
        loads: AtomicUsize,
        stores: AtomicUsize,
        locked: AtomicBool,
        block: Option<Arc<(Mutex<BlockState>, Condvar)>>,
        entered: Mutex<Option<oneshot::Sender<()>>>,
        entered_rx: Mutex<Option<oneshot::Receiver<()>>>,
    }

    #[derive(Default)]
    struct BlockState {
        released: bool,
    }

    impl MemoryKeyStore {
        fn set_locked(&self, locked: bool) {
            self.locked.store(locked, Ordering::SeqCst);
        }

        fn blocking() -> Self {
            let (entered, entered_rx) = oneshot::channel();
            Self {
                block: Some(Arc::new((
                    Mutex::new(BlockState::default()),
                    Condvar::new(),
                ))),
                entered: Mutex::new(Some(entered)),
                entered_rx: Mutex::new(Some(entered_rx)),
                ..Self::default()
            }
        }

        async fn wait_until_load_started(&self) {
            let entered = self.entered_rx.lock().unwrap().take().unwrap();
            entered.await.unwrap();
        }

        fn release_load(&self) {
            let Some(block) = &self.block else { return };
            let (lock, wake) = &**block;
            lock.lock().unwrap().released = true;
            wake.notify_all();
        }
    }

    impl DatabaseKeyStore for MemoryKeyStore {
        fn load_key(&self, credential_id: &str) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
            self.loads.fetch_add(1, Ordering::SeqCst);
            if self.locked.load(Ordering::SeqCst) {
                return Err(VaultError::Credential("credential store is locked".into()));
            }
            if let Some(sender) = self.entered.lock().unwrap().take() {
                let _ = sender.send(());
            }
            if let Some(block) = &self.block {
                let (lock, wake) = &**block;
                let mut state = lock.lock().unwrap();
                while !state.released {
                    state = wake.wait(state).unwrap();
                }
            }
            Ok(self
                .values
                .lock()
                .unwrap()
                .get(credential_id)
                .cloned()
                .map(Zeroizing::new))
        }

        fn store_key(&self, credential_id: &str, key: &[u8]) -> Result<(), VaultError> {
            self.stores.fetch_add(1, Ordering::SeqCst);
            if self.locked.load(Ordering::SeqCst) {
                return Err(VaultError::Credential("credential store is locked".into()));
            }
            self.values
                .lock()
                .unwrap()
                .insert(credential_id.into(), key.to_vec());
            Ok(())
        }
    }
}
