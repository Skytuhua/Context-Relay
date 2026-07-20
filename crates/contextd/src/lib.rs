use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread::JoinHandle,
    time::Duration,
};

use context_relay_core::{
    native_transaction::{
        engine::BoundaryError,
        recovery::{
            OsNativeRecoveryIo, RecoveryCleanup, RecoveryOutcome, RecoverySandboxIdentity,
            recover_native_transactions,
        },
    },
    vault::{DatabaseKeyStore, PlatformKeyStore, Vault, VaultError},
};
use context_relay_local_ipc::{
    AuthenticatedConnection, AuthenticatedRequest, CONNECTION_LIMIT, ConnectedStream,
    INSTALLATION_TOKEN_CREDENTIAL_ACCOUNT, INSTALLATION_TOKEN_CREDENTIAL_SERVICE,
    InstallationToken, InstanceGuard, IpcError, Listener, REQUEST_QUEUE_CAPACITY,
    RequestRegistration, RequestRegistry, RuntimeConfig, SHUTDOWN_TIMEOUT, generate_instance_nonce,
    load_installation_token,
};
use context_relay_protocol::{
    ClientError, ClientRole, DaemonInstanceNonce, ErrorCode, LocalRequest, LocalResult,
    MemoryParams, PROTOCOL_VERSION, ProjectPathParams,
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch},
    task::JoinSet,
    time::timeout,
};

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
    worker_hook: Option<Arc<dyn WorkerHook>>,
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
            worker_hook: None,
            #[cfg(test)]
            startup_recovery: None,
        }
    }

    #[cfg(test)]
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
) -> Result<(), DaemonError> {
    let private_root = vault_path
        .parent()
        .ok_or(DaemonError::Startup)?
        .join(NATIVE_SANDBOX_DIRECTORY);
    let mut io = OsNativeRecoveryIo::new(|identity, outcome| {
        cleanup_recovered_sandbox(&private_root, &identity, outcome)
    });
    recover_native_transactions(vault, &mut io)
        .map(|_| ())
        .map_err(|_| DaemonError::Startup)
}

#[cfg(windows)]
fn cleanup_recovered_sandbox(
    _private_root: &Path,
    identity: &RecoverySandboxIdentity,
    _outcome: RecoveryOutcome,
) -> Result<RecoveryCleanup, BoundaryError> {
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
    use context_relay_core::vault::MacGenerationState;
    use context_relay_native_runner::macos::{
        GenerationState, MacRecoveryCleanup, MacRecoveryIdentity, MacRecoveryOutcome,
        MacRootIdentity, cleanup_recovered_generation,
    };

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
    _identity: &RecoverySandboxIdentity,
    _outcome: RecoveryOutcome,
) -> Result<RecoveryCleanup, BoundaryError> {
    Err(BoundaryError::new(
        "native recovery is unavailable on this platform",
    ))
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
        let worker = VaultWorker::spawn(config.vault).await?;
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
    #[cfg(test)]
    TestBlock {
        entered: std::sync::mpsc::SyncSender<()>,
        release: std::sync::mpsc::Receiver<()>,
    },
}

fn route_request(role: ClientRole, request: LocalRequest) -> RoutedRequest {
    match request {
        LocalRequest::Hello(_) => RoutedRequest::Immediate(Err(invalid_request_error())),
        LocalRequest::Cancel(_) => RoutedRequest::Immediate(Err(invalid_request_error())),
        LocalRequest::Shutdown(_) => RoutedRequest::Shutdown,
        LocalRequest::Health(_) => RoutedRequest::Health,
        LocalRequest::Unlock(_) => RoutedRequest::Immediate(Err(unavailable_error())),
        LocalRequest::ProjectsList(_) => RoutedRequest::Immediate(Err(unavailable_error())),
        LocalRequest::ProjectPathSet(params) => {
            if role == ClientRole::Desktop {
                RoutedRequest::Work(VaultCommand::ProjectPathSet(params))
            } else {
                RoutedRequest::Immediate(Err(unavailable_error()))
            }
        }
        LocalRequest::MemoryGet(params) => {
            if role == ClientRole::Desktop {
                RoutedRequest::Work(VaultCommand::MemoryGet(params))
            } else {
                RoutedRequest::Immediate(Err(unavailable_error()))
            }
        }
        LocalRequest::MemorySearch(_) => RoutedRequest::Immediate(Err(unavailable_error())),
        LocalRequest::MemoryCreate(_) => RoutedRequest::Immediate(Err(unavailable_error())),
        LocalRequest::MemoryUpdate(_) => RoutedRequest::Immediate(Err(unavailable_error())),
        LocalRequest::MemoryArchive(_) => RoutedRequest::Immediate(Err(unavailable_error())),
        LocalRequest::CandidatesList(_) => RoutedRequest::Immediate(Err(unavailable_error())),
        LocalRequest::CandidateReview(_) => RoutedRequest::Immediate(Err(unavailable_error())),
        LocalRequest::TasksList(_) => RoutedRequest::Immediate(Err(unavailable_error())),
        LocalRequest::TaskUpsert(_) => RoutedRequest::Immediate(Err(unavailable_error())),
        LocalRequest::TaskComplete(_) => RoutedRequest::Immediate(Err(unavailable_error())),
        LocalRequest::TaskTransition(_) => RoutedRequest::Immediate(Err(unavailable_error())),
        LocalRequest::HandoffCreate(_) => RoutedRequest::Immediate(Err(unavailable_error())),
        LocalRequest::AccessGet(_) => RoutedRequest::Immediate(Err(unavailable_error())),
        LocalRequest::AccessSet(_) => RoutedRequest::Immediate(Err(unavailable_error())),
        LocalRequest::HarnessProbe(_) => RoutedRequest::Immediate(Err(unavailable_error())),
        LocalRequest::HarnessPreview(_) => RoutedRequest::Immediate(Err(unavailable_error())),
        LocalRequest::HarnessApply(_) => RoutedRequest::Immediate(Err(unavailable_error())),
        LocalRequest::HarnessRepair(_) => RoutedRequest::Immediate(Err(unavailable_error())),
        LocalRequest::HarnessRollback(_) => RoutedRequest::Immediate(Err(unavailable_error())),
        LocalRequest::PackageImport(_) => RoutedRequest::Immediate(Err(unavailable_error())),
        LocalRequest::PackageExport(_) => RoutedRequest::Immediate(Err(unavailable_error())),
        LocalRequest::SyncStatus(_) => RoutedRequest::Immediate(Err(unavailable_error())),
        LocalRequest::SyncRetry(_) => RoutedRequest::Immediate(Err(unavailable_error())),
        LocalRequest::DevicesList(_) => RoutedRequest::Immediate(Err(unavailable_error())),
        LocalRequest::DeviceRename(_) => RoutedRequest::Immediate(Err(unavailable_error())),
        LocalRequest::DeviceRevoke(_) => RoutedRequest::Immediate(Err(unavailable_error())),
        LocalRequest::PairingCreate(_) => RoutedRequest::Immediate(Err(unavailable_error())),
        LocalRequest::PairingJoin(_) => RoutedRequest::Immediate(Err(unavailable_error())),
        LocalRequest::PairingStatus(_) => RoutedRequest::Immediate(Err(unavailable_error())),
        LocalRequest::PairingDecision(_) => RoutedRequest::Immediate(Err(unavailable_error())),
        LocalRequest::PairingCancel(_) => RoutedRequest::Immediate(Err(unavailable_error())),
        LocalRequest::RecoveryBegin(_) => RoutedRequest::Immediate(Err(unavailable_error())),
        LocalRequest::RecoveryComplete(_) => RoutedRequest::Immediate(Err(unavailable_error())),
        LocalRequest::ExportRecords(_) => RoutedRequest::Immediate(Err(unavailable_error())),
        LocalRequest::ExportChunk(_) => RoutedRequest::Immediate(Err(unavailable_error())),
        LocalRequest::AccountDeletionBegin(_) => RoutedRequest::Immediate(Err(unavailable_error())),
        LocalRequest::AccountDeletionStatus(_) => {
            RoutedRequest::Immediate(Err(unavailable_error()))
        }
        LocalRequest::AccountDeletionCancel(_) => {
            RoutedRequest::Immediate(Err(unavailable_error()))
        }
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
        code: ErrorCode::Internal,
        message: "This service is not available in this build".into(),
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
                        return Ok(vault);
                    }
                    recover_startup_native_transactions(&mut vault, &config.path)?;
                    Ok(vault)
                });
                match opened {
                    Ok(vault) => {
                        if ready_sender.send(Ok(())).is_err() {
                            return;
                        }
                        run_vault_worker(vault, &mut receiver, config.worker_hook.as_deref());
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
    mut vault: Vault,
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
            execute_vault_command(&mut vault, command)
        } else {
            Err(canceled_error())
        };
        let _ = response.send(result);
        drop(admission);
    }
}

fn execute_vault_command(
    vault: &mut Vault,
    command: VaultCommand,
) -> Result<LocalResult, ClientError> {
    match command {
        VaultCommand::ProjectPathSet(params) => vault
            .put_path(&params.project_id.to_string(), &params.path)
            .map(|()| LocalResult::Empty)
            .map_err(client_error_from_vault),
        VaultCommand::MemoryGet(params) => vault
            .memory(&params.memory_id)
            .map(|memory| LocalResult::Memory { memory })
            .map_err(client_error_from_vault),
        #[cfg(test)]
        VaultCommand::TestBlock { entered, release } => {
            entered.send(()).map_err(|_| service_internal_error())?;
            release.recv().map_err(|_| service_internal_error())?;
            Ok(LocalResult::Empty)
        }
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

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{
            Arc, Condvar, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    #[cfg(target_os = "macos")]
    use context_relay_core::vault::{
        MacGenerationState, NativeSandboxCleanupState, NativeTransactionStatus,
    };
    use context_relay_core::{
        native_transaction::recovery::{OsNativeRecoveryIo, recover_native_transactions},
        vault::{NativePlanWrite, NativeSandboxIdentity},
    };
    use context_relay_local_ipc::{
        AuthAcceptedV1, AuthTranscriptV1, ConnectedStream, InstallationToken, IpcError,
        ServerHelloV1, connect, create_proof, read_json, write_json,
    };
    #[cfg(target_os = "macos")]
    use context_relay_native_runner::MacRootIdentity;
    use context_relay_protocol::{
        CancelParams, ClientRole, EmptyParams, HelloParams, JsonRpcErrorV1, JsonRpcRequestV1,
        JsonRpcSuccessV1, JsonRpcVersion, LocalRequest, PROTOCOL_VERSION, PlanId, RecordId,
        Sha256Digest,
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

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_test_runtime_socket_path_stays_within_platform_limit() {
        let endpoint = test_runtime("recover-all-before-bind")
            .endpoint_name()
            .unwrap();

        assert!(endpoint.as_bytes().len() <= 103);
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
    fn routing_covers_all_45_requests_without_falling_through() {
        let fixtures = all_request_fixtures();
        assert_eq!(fixtures.len(), 45);

        for (name, request) in fixtures {
            let routed = route_request(ClientRole::Desktop, request);
            match name {
                "Hello" | "Cancel" => assert_exact_error(routed, invalid_request_error()),
                "Shutdown" => assert!(matches!(routed, RoutedRequest::Shutdown)),
                "Health" => assert!(matches!(routed, RoutedRequest::Health)),
                "ProjectPathSet" => {
                    assert!(matches!(
                        routed,
                        RoutedRequest::Work(VaultCommand::ProjectPathSet(_))
                    ))
                }
                "MemoryGet" => {
                    assert!(matches!(
                        routed,
                        RoutedRequest::Work(VaultCommand::MemoryGet(_))
                    ))
                }
                _ => assert_exact_error(routed, unavailable_error()),
            }
        }

        let memory_get = request_fixture(
            "memory_get",
            serde_json::json!({"memoryId": "018f22e2-79b0-7cc8-98c4-dc0c0c07398f"}),
        );
        assert_exact_error(
            route_request(ClientRole::McpBridge, memory_get),
            unavailable_error(),
        );
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
                .unwrap_err(),
            unavailable_error()
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
            idle_mcp.call(mcp_memory).await.unwrap_err(),
            unavailable_error()
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
            ("Unlock", request_fixture("unlock", empty())),
            ("ProjectsList", request_fixture("projects_list", empty())),
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
