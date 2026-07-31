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
    load_installation_token,
};
use context_relay_protocol::{
    AccountDeletionState, BoundedBytes, ClientError, ClientRole, DaemonInstanceNonce, DeviceId,
    DeviceState, DeviceSummary, ErrorCode, ExportId, ExportPayload, HandoffPayload, HarnessId,
    HybridLogicalClock, LocalRequest, LocalResult, MAX_ARBITRARY_BYTES, MemoryKind, MemoryParams,
    NativePlatform, PROTOCOL_VERSION, ProjectPathParams, ProtocolVersionRange, ScopeRef,
    Sha256Digest, SyncState, VaultState,
};
use sha2::{Digest, Sha256};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch},
    task::JoinSet,
    time::timeout,
};

pub mod bridge_install;

use bridge_install::{BridgeInstallEngine, ProductionBridgeInstallEngine};

pub const VAULT_CREDENTIAL_ID: &str = "vault-key-v1";
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
    path: PathBuf,
    credential_id: String,
    key_store: Arc<dyn DatabaseKeyStore>,
    device_id: DeviceId,
    worker_hook: Option<Arc<dyn WorkerHook>>,
    bridge_install: Arc<dyn BridgeInstallEngine>,
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
            path,
            credential_id: credential_id.into(),
            key_store,
            device_id: stable_device_id(b"context-relay-test-device"),
            worker_hook: None,
            bridge_install: Arc::new(
                ProductionBridgeInstallEngine::production()
                    .expect("the running daemon has an executable location"),
            ),
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

    #[cfg(test)]
    fn with_startup_recovery(mut self, startup_recovery: StartupRecovery) -> Self {
        self.startup_recovery = Some(startup_recovery);
        self
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
    fn with_executor<R>(
        &self,
        bound: &BoundCliRecoveryPlan,
        operation: impl FnOnce(
            &mut dyn NativeCliExecutor,
            &[context_relay_core::native_transaction::ApprovedCliMutation],
        ) -> Result<R, BoundaryError>,
    ) -> Result<R, BoundaryError> {
        match bound.plan.setup.harness {
            HarnessId::ClaudeCode => {
                let mut adapter = context_relay_core::claude_code::ClaudeCodeAdapter::discover(
                    &self.root,
                    self.project_id,
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
                    &self.root,
                    &self.root,
                    self.project_id,
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
            runtime,
            vault,
            token_provider,
        }
    }

    pub fn production() -> Result<Self, DaemonError> {
        let root = dirs::data_local_dir()
            .ok_or(DaemonError::Startup)?
            .join("Context Relay");
        Ok(Self::new(
            RuntimeConfig::production(),
            VaultConfig::new(
                root.join("vault-v1.db"),
                VAULT_CREDENTIAL_ID,
                Arc::new(PlatformKeyStore::default()),
            ),
            Arc::new(PlatformInstallationTokenProvider),
        ))
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
    instance: Option<InstanceGuard>,
    listener: Option<Listener>,
    worker: VaultWorker,
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
        let token = Arc::new(config.token_provider.load_or_create()?);
        let instance_nonce = generate_instance_nonce().map_err(|_| DaemonError::Startup)?;
        let worker = VaultWorker::spawn(
            config
                .vault
                .with_device_id(stable_device_id(token.as_bytes())),
        )
        .await?;
        let listener =
            Listener::bind(&config.runtime, &mut instance).map_err(map_transport_error)?;
        let (shutdown_sender, shutdown_receiver) = watch::channel(false);
        let (state_sender, state_receiver) = watch::channel(DaemonState::Running);
        Ok(Self {
            instance: Some(instance),
            listener: Some(listener),
            worker,
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
        self.state_sender.send_replace(DaemonState::Draining);
        self.shutdown_sender.send_replace(true);
        while connections.join_next().await.is_some() {}
        self.worker.shutdown_and_join_async().await;
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
        RoutedRequest::Immediate(result) => {
            let result = begin_immediate(&registration).and(result);
            connection.respond(id, result).await?;
            Ok(true)
        }
        RoutedRequest::Health => {
            let result = begin_immediate(&registration).and_then(|()| {
                if service.worker.is_alive() {
                    Ok(LocalResult::Health {
                        protocol: PROTOCOL_VERSION,
                        vault_locked: false,
                    })
                } else {
                    Err(service_internal_error())
                }
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
        self.listener.take();
        self.worker.shutdown_and_join();
        self.instance.take();
        self.state_sender.send_replace(DaemonState::Stopped);
    }
}

#[derive(Debug)]
enum RoutedRequest {
    Immediate(Result<LocalResult, ClientError>),
    Health,
    Shutdown,
    Work(VaultCommand),
}

#[derive(Debug)]
enum VaultCommand {
    ProjectPathSet(ProjectPathParams),
    MemoryGet(MemoryParams),
    Workspace(LocalRequest),
    HarnessSetup(LocalRequest),
    #[cfg(test)]
    TestBlock {
        entered: std::sync::mpsc::SyncSender<()>,
        release: std::sync::mpsc::Receiver<()>,
    },
}

fn route_request(_role: ClientRole, request: LocalRequest) -> RoutedRequest {
    match request {
        LocalRequest::Hello(_) => RoutedRequest::Immediate(Err(invalid_request_error())),
        LocalRequest::Cancel(_) => RoutedRequest::Immediate(Err(invalid_request_error())),
        LocalRequest::Shutdown(_) => RoutedRequest::Shutdown,
        LocalRequest::Health(_) => RoutedRequest::Health,
        LocalRequest::NativeHookEvent(_) => RoutedRequest::Immediate(Err(unsupported_error(
            "Native hook event handling is not available",
        ))),
        LocalRequest::Unlock(_) => RoutedRequest::Immediate(Ok(LocalResult::Empty)),
        LocalRequest::ProjectPathSet(params) => {
            RoutedRequest::Work(VaultCommand::ProjectPathSet(params))
        }
        LocalRequest::MemoryGet(params) => RoutedRequest::Work(VaultCommand::MemoryGet(params)),
        request @ (LocalRequest::McpCall(_)
        | LocalRequest::ProjectsList(_)
        | LocalRequest::ProjectUpsert(_)
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
        request @ (LocalRequest::HarnessPreview(_)
        | LocalRequest::HarnessApply(_)
        | LocalRequest::HarnessRollback(_)) => {
            RoutedRequest::Work(VaultCommand::HarnessSetup(request))
        }
        LocalRequest::HarnessProbe(_)
        | LocalRequest::HarnessRepair(_)
        | LocalRequest::PackageImport(_)
        | LocalRequest::PackageExport(_) => RoutedRequest::Immediate(Err(unsupported_error(
            "The requested local adapter operation is not supported",
        ))),
        LocalRequest::SyncRetry(_)
        | LocalRequest::DeviceRename(_)
        | LocalRequest::DeviceRevoke(_)
        | LocalRequest::PairingCreate(_)
        | LocalRequest::PairingJoin(_)
        | LocalRequest::PairingStatus(_)
        | LocalRequest::PairingDecision(_)
        | LocalRequest::PairingCancel(_)
        | LocalRequest::RecoveryBegin(_)
        | LocalRequest::RecoveryComplete(_) => RoutedRequest::Immediate(Err(unsupported_error(
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

#[cfg(test)]
fn unavailable_error() -> ClientError {
    ClientError {
        code: ErrorCode::Internal,
        message: "This service is not available in this build".into(),
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
}

impl WorkerClient {
    fn is_alive(&self) -> bool {
        self.sender
            .upgrade()
            .is_some_and(|sender| !sender.is_closed())
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
        if !*admission_gate {
            return Err(busy_error());
        }
        let Some(sender) = self.sender.upgrade() else {
            return Err(service_internal_error());
        };
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
}

struct StoredExport {
    chunks: Vec<Vec<u8>>,
    total_bytes: u64,
    record_count: u32,
}

struct WorkspaceState {
    vault: Vault,
    vault_path: PathBuf,
    device_id: DeviceId,
    exports: BTreeMap<ExportId, StoredExport>,
    deletion: AccountDeletionState,
    bridge_install: Arc<dyn BridgeInstallEngine>,
}

impl VaultWorker {
    async fn spawn(config: VaultConfig) -> Result<Self, DaemonError> {
        let (sender, mut receiver) = mpsc::channel::<WorkItem>(REQUEST_QUEUE_CAPACITY);
        let (ready_sender, ready_receiver) = oneshot::channel();
        let (exit_sender, exit_receiver) = oneshot::channel();
        let admission = Arc::new(Mutex::new(true));
        let worker_hook = config.worker_hook.clone();
        let thread = std::thread::Builder::new()
            .name("context-relay-vault".into())
            .spawn(move || {
                let opened = config
                    .path
                    .parent()
                    .ok_or(DaemonError::Startup)
                    .and_then(|parent| {
                        std::fs::create_dir_all(parent).map_err(|_| DaemonError::Startup)
                    })
                    .and_then(|()| {
                        Vault::open(
                            &config.path,
                            &config.credential_id,
                            config.key_store.as_ref(),
                        )
                        .map_err(|_| DaemonError::Startup)
                    });
                let opened = opened.and_then(|mut vault| {
                    #[cfg(test)]
                    if let Some(recovery) = &config.startup_recovery {
                        recovery(&mut vault)?;
                    } else {
                        recover_startup_native_transactions(
                            &mut vault,
                            &config.path,
                            config.device_id,
                        )?;
                    }
                    #[cfg(not(test))]
                    recover_startup_native_transactions(
                        &mut vault,
                        &config.path,
                        config.device_id,
                    )?;
                    config
                        .bridge_install
                        .reconcile_after_native_recovery(&mut vault, &config.path, config.device_id)
                        .map_err(|_| DaemonError::Startup)?;
                    Ok(vault)
                });
                match opened {
                    Ok(vault) => {
                        if ready_sender.send(Ok(())).is_err() {
                            return;
                        }
                        run_vault_worker(
                            WorkspaceState {
                                vault,
                                vault_path: config.path,
                                device_id: config.device_id,
                                exports: BTreeMap::new(),
                                deletion: AccountDeletionState::Active,
                                bridge_install: config.bridge_install,
                            },
                            &mut receiver,
                            config.worker_hook.as_deref(),
                        );
                    }
                    Err(error) => {
                        let _ = ready_sender.send(Err(error));
                    }
                }
                let _ = exit_sender.send(());
            })
            .map_err(|_| DaemonError::Startup)?;
        let mut worker = Self {
            sender: Some(sender),
            thread: Some(thread),
            exit: Some(exit_receiver),
            admission,
            worker_hook,
        };
        match ready_receiver.await {
            Ok(Ok(())) => Ok(worker),
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
        }
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
        self.sender.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }

    async fn shutdown_and_join_async(&mut self) {
        self.sender.take();
        if let Some(thread) = self.thread.take() {
            let _ = tokio::task::spawn_blocking(move || thread.join()).await;
        }
        self.exit.take();
    }
}

fn run_vault_worker(
    mut state: WorkspaceState,
    receiver: &mut mpsc::Receiver<WorkItem>,
    worker_hook: Option<&dyn WorkerHook>,
) {
    while let Some(item) = receiver.blocking_recv() {
        let WorkItem {
            command,
            admission,
            response,
        } = item;
        let result = if admission.begin() {
            if let Some(worker_hook) = worker_hook {
                worker_hook.before_execute();
            }
            execute_vault_command(&mut state, command)
        } else {
            Err(canceled_error())
        };
        let _ = response.send(result);
        drop(admission);
    }
}

fn execute_vault_command(
    state: &mut WorkspaceState,
    command: VaultCommand,
) -> Result<LocalResult, ClientError> {
    match command {
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
        VaultCommand::Workspace(request) => execute_workspace_request(state, request),
        VaultCommand::HarnessSetup(request) => execute_harness_setup(state, request),
        #[cfg(test)]
        VaultCommand::TestBlock { entered, release } => {
            entered.send(()).map_err(|_| service_internal_error())?;
            release.recv().map_err(|_| service_internal_error())?;
            Ok(LocalResult::Empty)
        }
    }
}

fn execute_harness_setup(
    state: &mut WorkspaceState,
    request: LocalRequest,
) -> Result<LocalResult, ClientError> {
    match request {
        LocalRequest::HarnessPreview(params) => state
            .bridge_install
            .preview(&mut state.vault, &state.vault_path, state.device_id, params)
            .map(|plan| LocalResult::Plan {
                plan: Box::new(plan),
            }),
        LocalRequest::HarnessApply(params) => state
            .bridge_install
            .apply(&mut state.vault, &state.vault_path, state.device_id, params)
            .map(|()| LocalResult::Empty),
        LocalRequest::HarnessRollback(params) => state
            .bridge_install
            .rollback(&mut state.vault, &state.vault_path, state.device_id, params)
            .map(|()| LocalResult::Empty),
        _ => Err(invalid_request_error()),
    }
}

fn execute_workspace_request(
    state: &mut WorkspaceState,
    request: LocalRequest,
) -> Result<LocalResult, ClientError> {
    match request {
        LocalRequest::McpCall(params) => {
            let name = params.name.clone();
            McpWorkspace::new(&mut state.vault, state.device_id)
                .call(params)
                .map(|output| LocalResult::McpOutput { name, output })
        }
        LocalRequest::ProjectsList(_) => OfflineWorkspace::new(&mut state.vault, state.device_id)
            .projects()
            .map(|projects| LocalResult::Projects { projects }),
        LocalRequest::ProjectUpsert(params) => {
            OfflineWorkspace::new(&mut state.vault, state.device_id)
                .upsert_project(params.project)
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
        LocalRequest::SyncStatus(_) => state
            .vault
            .access_policy(HarnessId::Codex)
            .map_err(client_error_from_vault)
            .map(|access| LocalResult::Status {
                status: context_relay_protocol::StatusOutput {
                    protocol: ProtocolVersionRange {
                        min: PROTOCOL_VERSION,
                        max: PROTOCOL_VERSION,
                    },
                    vault: VaultState::Unlocked,
                    resolved_project: None,
                    sync: SyncState::Offline,
                    access,
                },
            }),
        LocalRequest::DevicesList(_) => Ok(LocalResult::Devices {
            devices: vec![DeviceSummary {
                device_id: state.device_id,
                name: "This device".into(),
                platform: native_platform(),
                state: DeviceState::Active,
                is_current: true,
            }],
        }),
        LocalRequest::ExportRecords(params) => create_encrypted_export(state, params),
        LocalRequest::ExportChunk(params) => {
            export_chunk(state, params.export_id, params.chunk_index)
        }
        LocalRequest::AccountDeletionBegin(params) => {
            if !params.confirmation.eq_ignore_ascii_case("delete") {
                return Err(invalid_request_error());
            }
            state.deletion = AccountDeletionState::PendingDelete;
            Ok(account_deletion_result(state.deletion))
        }
        LocalRequest::AccountDeletionStatus(_) => Ok(account_deletion_result(state.deletion)),
        LocalRequest::AccountDeletionCancel(_) => {
            state.deletion = AccountDeletionState::Active;
            Ok(account_deletion_result(state.deletion))
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

fn account_deletion_result(state: AccountDeletionState) -> LocalResult {
    LocalResult::AccountDeletion {
        state,
        purge_deadline: None,
        export_available: state == AccountDeletionState::PendingDelete,
    }
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

    use context_relay_core::vault::{DatabaseKeyStore, Vault, VaultError};
    use context_relay_local_ipc::{InstallationToken, RuntimeConfig};
    use context_relay_protocol::{
        ClientError, DeviceId, ErrorCode, HarnessParams, PlanParams, SetupPlan,
    };
    #[cfg(any(windows, target_os = "macos"))]
    use context_relay_protocol::{
        HarnessAccessPolicy, HarnessId, ProjectIdentity, WireNativeValue,
    };
    use tokio::sync::Notify;
    use zeroize::Zeroizing;

    use super::{
        BridgeInstallEngine, Daemon, DaemonConfig, DaemonError, InstallationTokenProvider,
        VaultConfig, WorkerHook,
    };

    #[derive(Clone)]
    pub struct TestDaemonConfig {
        runtime: RuntimeConfig,
        vault_path: PathBuf,
        token: [u8; 32],
        keys: Arc<TestKeyStore>,
        worker_gate: Option<Arc<TestWorkerGate>>,
        bridge_install: Option<Arc<dyn BridgeInstallEngine>>,
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

    #[cfg(any(windows, target_os = "macos"))]
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
                display: None,
            }
        }
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::ffi::OsStrExt;

            WireNativeValue {
                platform: context_relay_protocol::NativePlatform::Macos,
                bytes: path.as_os_str().as_bytes().to_vec(),
                display: None,
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
            atomic::{AtomicUsize, Ordering},
        },
    };

    #[cfg(target_os = "macos")]
    use context_relay_core::native_transaction::{NativeApplyReceipt, TransactionStep};
    #[cfg(target_os = "macos")]
    use context_relay_core::vault::NativeCliWalWrite;
    use context_relay_core::{
        native_transaction::recovery::{OsNativeRecoveryIo, recover_native_transactions},
        vault::{
            NativePlanWrite, NativeSandboxCleanupState, NativeSandboxIdentity,
            NativeTransactionStatus, SetupPlanAction, SetupPlanLifecycle,
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
        CancelParams, ClientRole, EmptyParams, HelloParams, JsonRpcErrorV1, JsonRpcRequestV1,
        JsonRpcSuccessV1, JsonRpcVersion, LocalRequest, PROTOCOL_VERSION, PlanId, RecordId,
        Sha256Digest,
    };
    #[cfg(any(windows, target_os = "macos"))]
    use context_relay_protocol::{
        HarnessAccessPolicy, McpBinding, McpCallParams, ProjectId, ProjectIdentity, WireNativeValue,
    };
    use zeroize::Zeroizing;

    use super::*;

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
            let state_path = root.join("live-state");
            let get_path = root.join("mcp-get.json");
            std::fs::create_dir_all(&bin).unwrap();
            std::fs::create_dir_all(&home).unwrap();
            std::fs::create_dir_all(&config_root).unwrap();
            std::fs::write(&state_path, initial).unwrap();
            let executable = bin.join("claude");
            std::fs::write(
                &executable,
                format!(
                    "#!/bin/sh\ncase \"$*\" in\n  --version) printf '2.1.214\\n' ;;\n  doctor) printf 'Claude Code diagnostics: OK\\n' ;;\n  'mcp list') if [ \"$(/bin/cat '{}')\" = present ]; then printf 'context-relay: local (stdio)\\n'; fi ;;\n  'mcp get context-relay') /bin/cat '{}' ;;\n  'mcp remove context-relay --scope user') printf absent > '{}' ;;\n  *) exit 9 ;;\nesac\n",
                    state_path.display(),
                    get_path.display(),
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
            std::fs::write(
                &get_path,
                serde_json::to_vec(&serde_json::json!({
                    "name": "context-relay",
                    "scope": "user",
                    "type": "stdio",
                    "command": bridge_executable.to_str().unwrap(),
                    "args": ["--harness", "claude-code"],
                }))
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
                std::fs::read_to_string(&state_path).unwrap(),
                final_state,
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
    async fn vault_open_failure_releases_singleton_and_never_publishes_endpoint() {
        let runtime = test_runtime("open-failure");
        let provider = Arc::new(FixedTokenProvider::default());
        let keys = Arc::new(MemoryKeyStore::default());
        let path = unique_temp_path("open-failure").join("vault.db");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, []).unwrap();
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
        assert_eq!(fixtures.len(), 49);

        for (name, request) in fixtures {
            let routed = route_request(ClientRole::Desktop, request);
            match name {
                "Hello" | "Cancel" => assert_exact_error(routed, invalid_request_error()),
                "Shutdown" => assert!(matches!(routed, RoutedRequest::Shutdown)),
                "Health" => assert!(matches!(routed, RoutedRequest::Health)),
                "McpCall" => assert!(matches!(
                    routed,
                    RoutedRequest::Work(VaultCommand::Workspace(LocalRequest::McpCall(_)))
                )),
                _ => assert!(!matches!(
                    routed,
                    RoutedRequest::Immediate(Err(error)) if error == unavailable_error()
                )),
            }
        }
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
    fn native_hook_event_is_explicitly_unsupported_until_workspace_route_exists() {
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

        let RoutedRequest::Immediate(Err(error)) = route_request(ClientRole::McpBridge, request)
        else {
            panic!("native hook event must remain an explicit interim rejection")
        };
        assert_eq!(error.code, ErrorCode::HarnessUnsupported);
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
            let mut stream = connect(runtime).await.unwrap();
            let hello: ServerHelloV1 = read_json(&mut stream).await.unwrap();
            let token = InstallationToken::from_bytes([0x5a; 32]);
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
        let harness = || serde_json::json!({"harness": "codex", "projectId": null});

        vec![
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
                    serde_json::json!({"code": "01234-ABCDE", "deviceId": ID, "deviceName": "device", "platform": "windows", "requestNonce": bytes32, "signingPublicKey": bytes32, "wrappingPublicKey": bytes32}),
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
                "PairingCancel",
                request_fixture("pairing_cancel", serde_json::json!({"pairingId": ID})),
            ),
            ("RecoveryBegin", request_fixture("recovery_begin", empty())),
            (
                "RecoveryComplete",
                request_fixture(
                    "recovery_complete",
                    serde_json::json!({"recoveryPhraseWords": vec!["word"; 24]}),
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
                    serde_json::json!({"confirmation": "delete"}),
                ),
            ),
            (
                "AccountDeletionStatus",
                request_fixture("account_deletion_status", empty()),
            ),
            (
                "AccountDeletionCancel",
                request_fixture("account_deletion_cancel", empty()),
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
        committed: bool,
    ) -> (PlanId, String) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut vault = Vault::open(path, "test-vault-key", keys).unwrap();
        let plan = bridge_install::tests::persist_claude_cli_plan(
            &mut vault,
            executable,
            bridge_executable,
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
        block: Option<Arc<(Mutex<BlockState>, Condvar)>>,
        entered: Mutex<Option<oneshot::Sender<()>>>,
        entered_rx: Mutex<Option<oneshot::Receiver<()>>>,
    }

    #[derive(Default)]
    struct BlockState {
        released: bool,
    }

    impl MemoryKeyStore {
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
            self.values
                .lock()
                .unwrap()
                .insert(credential_id.into(), key.to_vec());
            Ok(())
        }
    }
}
