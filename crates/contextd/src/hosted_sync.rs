use super::{
    ServiceStatus, VaultCommand, WorkAdmission, WorkerClient, WorkspaceState, canceled_error,
    local_sync_material, scope_denied_error, service_internal_error,
};
use context_relay_core::{
    auth::{HostedIdentity, HostedSessionOwner, LoginCancellation},
    service::sync_embedding,
    sync::{
        CheckpointBuildContext, CheckpointProgress, CheckpointRequest, CheckpointResponse,
        PreparedCheckpoint, PreparedPull, PreparedPush, PullProgress, PullRequest, PullResponse,
        PushReceipt, SupabaseTransport, SupabaseTransportConfig, SyncEngine, SyncProvider,
        SyncScope, SyncTransport, TransportError,
    },
};
use context_relay_protocol::{ClientError, LocalResult, SyncState};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{oneshot, watch};

pub(crate) struct Config {
    pub owner: Arc<HostedSessionOwner>,
    pub project: String,
    pub key: zeroize::Zeroizing<String>,
    #[cfg(test)]
    pub http: Option<Arc<dyn context_relay_core::sync::SupabaseHttpClient>>,
}

#[derive(Clone)]
pub(crate) struct Client {
    wake: watch::Sender<u64>,
    enabled: bool,
    stopped: Arc<AtomicBool>,
}
impl Client {
    pub fn retry(&self) -> Result<LocalResult, ClientError> {
        if !self.enabled {
            return Err(super::unsupported_error("Hosted sync is not configured"));
        }
        if self.stopped.load(Ordering::SeqCst) {
            return Err(canceled_error());
        }
        self.wake
            .send_modify(|value| *value = value.wrapping_add(1));
        Ok(LocalResult::Empty)
    }
}
pub(crate) struct Supervisor {
    client: Client,
    task: Option<tokio::task::JoinHandle<()>>,
}
impl Supervisor {
    pub fn spawn(worker: WorkerClient, config: Option<Config>) -> Self {
        let (wake, receiver) = watch::channel(0);
        let client = Client {
            wake,
            enabled: config.is_some(),
            stopped: Arc::new(AtomicBool::new(false)),
        };
        let stopped = client.stopped.clone();
        let task =
            config.map(|config| tokio::spawn(run(worker, Arc::new(config), receiver, stopped)));
        Self { client, task }
    }
    pub fn client(&self) -> Client {
        self.client.clone()
    }
    pub fn close(&self) {
        self.client.stopped.store(true, Ordering::SeqCst);
        if let Some(task) = &self.task {
            task.abort();
        }
    }
    pub async fn shutdown(&mut self) {
        self.close();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}
impl Drop for Supervisor {
    fn drop(&mut self) {
        self.close();
    }
}

struct Authority {
    certificates: std::sync::OnceLock<context_relay_core::sync::DeviceCertificateSnapshot>,
    authentication_changed: bool,
    change_admitted: AtomicBool,
    config: Arc<Config>,
    identity: HostedIdentity,
    generation: LoginCancellation,
    stopped: Arc<AtomicBool>,
}
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_millis().try_into().unwrap_or(u64::MAX))
        .unwrap_or(0)
}
impl Authority {
    fn check(&self) -> Result<(), ClientError> {
        if self.stopped.load(Ordering::SeqCst) {
            return Err(canceled_error());
        }
        let session = self
            .config
            .owner
            .session_for(&self.generation, self.identity, now_ms() / 1000)
            .map_err(|_| scope_denied_error())?;
        if reqwest::Url::parse(&self.config.project).ok().as_ref() != Some(session.project_url()) {
            return Err(scope_denied_error());
        }
        Ok(())
    }
    fn transport(&self) -> Result<SupabaseTransport, ClientError> {
        self.check()?;
        let session = self
            .config
            .owner
            .session_for(&self.generation, self.identity, now_ms() / 1000)
            .map_err(|_| scope_denied_error())?;
        let config = SupabaseTransportConfig::new(
            &self.config.project,
            self.config.key.to_string(),
            session.access_token(),
        )
        .map_err(|_| service_internal_error())?;
        #[cfg(test)]
        let transport = match &self.config.http {
            Some(http) => SupabaseTransport::with_http_client(config, http.clone()),
            None => SupabaseTransport::new(config),
        };
        #[cfg(not(test))]
        let transport = SupabaseTransport::new(config);
        Ok(transport
            .map_err(|_| service_internal_error())?
            .with_session_owner(
                self.config.owner.clone(),
                self.identity,
                self.generation.clone(),
            ))
    }
}
struct Admission(Arc<Authority>);
impl WorkAdmission for Admission {
    fn begin(&self) -> bool {
        self.0.check().is_ok()
    }
}

enum Step {
    Begin,
    Certificates(context_relay_core::sync::DeviceCertificateSnapshot),
    Push(PreparedPush, Result<PushReceipt, TransportError>),
    Pull(
        Box<PreparedPull>,
        PullResponse,
        context_relay_core::sync::DeviceCertificateSnapshot,
    ),
    BeginCheckpoint,
    Checkpoint(
        Box<PreparedCheckpoint>,
        CheckpointResponse,
        context_relay_core::sync::DeviceCertificateSnapshot,
    ),
    Complete(bool),
    Failed,
}
enum Progress {
    Certificates(SyncScope),
    Push(PreparedPush),
    Pull(PullProgress),
    Pushed(bool, PullProgress),
    Checkpoint(CheckpointProgress),
    Complete(bool),
    Failed,
}
pub(crate) struct Work {
    authority: Arc<Authority>,
    scope: Option<SyncScope>,
    step: Step,
    response: oneshot::Sender<Result<Progress, ClientError>>,
}
impl std::fmt::Debug for Work {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SyncWork([REDACTED])")
    }
}
impl Work {
    pub fn execute(
        self,
        state: &mut WorkspaceState,
        status: &ServiceStatus,
    ) -> Result<LocalResult, ClientError> {
        let Self {
            authority,
            scope,
            step,
            response,
        } = self;
        let result = apply(&authority, scope, step, state, status);
        if result.is_err() && authority.check().is_ok() {
            status.set_sync(SyncState::Error);
        }
        let _ = response.send(result);
        Ok(LocalResult::Empty)
    }
}
fn apply(
    authority: &Authority,
    expected_scope: Option<SyncScope>,
    step: Step,
    state: &mut WorkspaceState,
    status: &ServiceStatus,
) -> Result<Progress, ClientError> {
    authority.check()?;
    let (keys, mut material) = local_sync_material(state)?.ok_or_else(scope_denied_error)?;
    let snapshot = match &step {
        Step::Pull(_, _, snapshot) | Step::Checkpoint(_, _, snapshot) => Some(snapshot),
        _ => authority.certificates.get(),
    };
    if let Some(snapshot) = snapshot {
        material = state
            .vault
            .trusted_sync_material_with_certificates(&keys, snapshot)
            .map_err(|_| scope_denied_error())?;
    }
    let identity = material
        .local_identity(state.device_id, &keys)
        .map_err(|_| scope_denied_error())?;
    let scope = SyncScope {
        account_id: identity.account_id,
        workspace_id: identity.workspace_id,
    };
    if expected_scope.is_some_and(|expected| expected != scope) {
        return Err(scope_denied_error());
    }
    let engine = SyncEngine::new(scope, SyncProvider::Supabase);
    let failure = |_| service_internal_error();
    let progress = match step {
        Step::Begin => {
            status.set_sync(SyncState::Syncing);
            Progress::Certificates(scope)
        }
        Step::Certificates(snapshot) => {
            state
                .vault
                .trusted_sync_material_with_certificates(&keys, &snapshot)
                .map_err(|_| scope_denied_error())?
                .local_identity(state.device_id, &keys)
                .map_err(|_| scope_denied_error())?;
            authority
                .certificates
                .set(snapshot)
                .map_err(|_| scope_denied_error())?;
            if authority.authentication_changed {
                state
                    .vault
                    .unblock_scoped_outbox_after_state_change(
                        scope,
                        context_relay_core::vault::OutboxUnblockReason::AuthenticationChanged,
                        now_ms(),
                    )
                    .map_err(|_| service_internal_error())?;
            }
            authority.change_admitted.store(true, Ordering::SeqCst);
            status.set_sync(SyncState::Syncing);
            match engine
                .prepare_push(&mut state.vault, now_ms())
                .map_err(failure)?
            {
                Some(prepared) => Progress::Push(prepared),
                None => Progress::Pull(engine.prepare_pull(&state.vault).map_err(failure)?),
            }
        }
        Step::Push(prepared, receipt) => {
            let report = engine
                .finish_push(&mut state.vault, prepared, receipt, now_ms())
                .map_err(failure)?;
            Progress::Pushed(
                report.more_work,
                engine.prepare_pull(&state.vault).map_err(failure)?,
            )
        }
        Step::Pull(prepared, response, _) => {
            use context_relay_core::sync::TrustedSyncMaterial as _;
            let rows = match &response {
                PullResponse::Operations(page) => &page.rows,
                PullResponse::DeviceRange(rows) => rows,
            };
            for row in rows {
                // Missing metadata is not proof that an operation is corrupt. Keep its cursor retryable.
                material
                    .trusted_device(
                        scope.account_id,
                        scope.workspace_id,
                        row.operation.device_id,
                    )
                    .map_err(|_| scope_denied_error())?;
            }
            Progress::Pull(
                engine
                    .finish_pull(
                        &mut state.vault,
                        *prepared,
                        response,
                        &material,
                        &sync_embedding,
                        now_ms(),
                    )
                    .map_err(failure)?,
            )
        }
        Step::BeginCheckpoint => {
            Progress::Checkpoint(engine.prepare_checkpoint(&state.vault).map_err(failure)?)
        }
        Step::Checkpoint(prepared, response, _) => {
            use context_relay_core::sync::TrustedSyncMaterial as _;
            let check_creator = |checkpoint: &context_relay_core::sync::CanonicalCheckpoint| {
                material
                    .trusted_device(
                        scope.account_id,
                        scope.workspace_id,
                        checkpoint.checkpoint.creator_device,
                    )
                    .map_err(|_| scope_denied_error())
            };
            match &response {
                CheckpointResponse::ByHash(Some(checkpoint)) => {
                    check_creator(checkpoint)?;
                }
                CheckpointResponse::Page(page) => {
                    for row in &page.rows {
                        check_creator(&row.checkpoint)?;
                    }
                }
                _ => {}
            }
            let now = now_ms();
            let context = CheckpointBuildContext {
                scope,
                creator_device: state.device_id,
                active_key_epoch: identity.key_epoch,
                device_keys: &keys,
                created_hlc: context_relay_protocol::HybridLogicalClock::new(
                    now,
                    0,
                    state.device_id,
                ),
            };
            Progress::Checkpoint(
                engine
                    .finish_checkpoint(
                        &mut state.vault,
                        *prepared,
                        response,
                        &material,
                        now,
                        &context,
                    )
                    .map_err(failure)?,
            )
        }
        Step::Complete(more_work) => {
            let more_work = more_work
                || !state
                    .vault
                    .due_outbox(now_ms(), 1)
                    .map_err(|_| service_internal_error())?
                    .is_empty();
            status.set_sync(if more_work {
                SyncState::Syncing
            } else {
                SyncState::Idle
            });
            return Ok(Progress::Complete(more_work));
        }
        Step::Failed => {
            status.set_sync(SyncState::Error);
            return Ok(Progress::Failed);
        }
    };
    Ok(progress)
}

async fn submit(
    worker: &WorkerClient,
    authority: &Arc<Authority>,
    scope: Option<SyncScope>,
    step: Step,
) -> Result<Progress, ClientError> {
    let (response, receiver) = oneshot::channel();
    let completion = worker.try_submit(
        VaultCommand::Sync(Box::new(Work {
            authority: authority.clone(),
            scope,
            step,
            response,
        })),
        Admission(authority.clone()),
    )?;
    completion.await.map_err(|_| service_internal_error())??;
    receiver.await.map_err(|_| service_internal_error())?
}
async fn cycle(worker: &WorkerClient, authority: Arc<Authority>) -> Result<bool, ClientError> {
    let mut progress = submit(worker, &authority, None, Step::Begin).await?;
    let mut more_work = false;
    let mut cycle_scope = None;
    loop {
        progress = match progress {
            Progress::Certificates(scope) => {
                cycle_scope = Some(scope);
                let network_authority = authority.clone();
                let snapshot = tokio::task::spawn_blocking(move || {
                    network_authority
                        .transport()
                        .map_err(|_| TransportError::AuthRequired)?
                        .fetch_device_certificates(scope)
                })
                .await
                .map_err(|_| service_internal_error())?;
                let step = match snapshot {
                    Ok(snapshot) => Step::Certificates(snapshot),
                    Err(_) => Step::Failed,
                };
                submit(worker, &authority, Some(scope), step).await?
            }
            Progress::Failed => return Ok(false),
            Progress::Complete(more_work) => return Ok(more_work),
            Progress::Pushed(pending, pull) => {
                more_work |= pending;
                Progress::Pull(pull)
            }
            Progress::Pull(PullProgress::Complete(report)) => {
                more_work |= report.more_work;
                submit(worker, &authority, cycle_scope, Step::BeginCheckpoint).await?
            }
            Progress::Checkpoint(CheckpointProgress::Complete(report)) => {
                submit(
                    worker,
                    &authority,
                    cycle_scope,
                    Step::Complete(more_work || report.more_work),
                )
                .await?
            }
            Progress::Checkpoint(CheckpointProgress::Request(prepared)) => {
                let scope = prepared.scope();
                let network_authority = authority.clone();
                let (prepared, response) = tokio::task::spawn_blocking(move || {
                    let response = network_authority
                        .transport()
                        .map_err(|_| TransportError::AuthRequired)
                        .and_then(|mut transport| {
                            let response = match prepared.request() {
                                CheckpointRequest::ByHash(hash) => transport
                                    .checkpoint_by_hash(
                                        scope,
                                        context_relay_protocol::CHECKPOINT_SCHEMA_VERSION,
                                        *hash,
                                    )
                                    .map(|checkpoint| {
                                        CheckpointResponse::ByHash(checkpoint.map(Box::new))
                                    }),
                                CheckpointRequest::Page { after, limit } => transport
                                    .pull_checkpoints(
                                        scope,
                                        context_relay_protocol::CHECKPOINT_SCHEMA_VERSION,
                                        after.as_ref(),
                                        *limit,
                                    )
                                    .map(CheckpointResponse::Page),
                                CheckpointRequest::Push(checkpoint) => transport
                                    .push_checkpoint(
                                        scope,
                                        context_relay_protocol::CHECKPOINT_SCHEMA_VERSION,
                                        checkpoint,
                                    )
                                    .map(CheckpointResponse::Push),
                            }?;
                            let certificates = transport.fetch_device_certificates(scope)?;
                            Ok((response, certificates))
                        });
                    (prepared, response)
                })
                .await
                .map_err(|_| service_internal_error())?;
                let step = match response {
                    Ok((response, certificates)) => {
                        Step::Checkpoint(prepared, response, certificates)
                    }
                    Err(_) => Step::Failed,
                };
                submit(worker, &authority, Some(scope), step).await?
            }
            Progress::Push(prepared) => {
                let scope = prepared.scope();
                cycle_scope = Some(scope);
                let network_authority = authority.clone();
                let (prepared, receipt) = tokio::task::spawn_blocking(move || {
                    let receipt = network_authority
                        .transport()
                        .map_err(|_| TransportError::AuthRequired)
                        .and_then(|mut transport| {
                            transport.push_operations(scope, prepared.operations())
                        });
                    (prepared, receipt)
                })
                .await
                .map_err(|_| service_internal_error())?;
                submit(
                    worker,
                    &authority,
                    Some(scope),
                    Step::Push(prepared, receipt),
                )
                .await?
            }
            Progress::Pull(PullProgress::Request(prepared)) => {
                let scope = prepared.scope();
                cycle_scope = Some(scope);
                let network_authority = authority.clone();
                let (prepared, response) = tokio::task::spawn_blocking(move || {
                    let response = network_authority
                        .transport()
                        .map_err(|_| TransportError::AuthRequired)
                        .and_then(|mut transport| {
                            let response = match prepared.request() {
                                PullRequest::Operations { cursor, limit } => transport
                                    .pull_operations(scope, cursor.as_ref(), *limit)
                                    .map(PullResponse::Operations),
                                PullRequest::DeviceRange { device, range } => transport
                                    .pull_device_range(scope, *device, range.clone())
                                    .map(PullResponse::DeviceRange),
                            }?;
                            // Fetch after the page: a device may have paired while its operations were in flight.
                            let certificates = transport.fetch_device_certificates(scope)?;
                            Ok((response, certificates))
                        });
                    (prepared, response)
                })
                .await
                .map_err(|_| service_internal_error())?;
                let step = match response {
                    Ok((response, certificates)) => Step::Pull(prepared, response, certificates),
                    Err(_) => Step::Failed,
                };
                submit(worker, &authority, Some(scope), step).await?
            }
        };
    }
}
async fn run(
    worker: WorkerClient,
    config: Arc<Config>,
    mut wake: watch::Receiver<u64>,
    stopped: Arc<AtomicBool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut pending = false;
    let mut last_session = std::sync::Weak::new();
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(1)), if pending => {},
            changed = wake.changed() => if changed.is_err() { break; },
            _ = interval.tick() => {},
        }
        if stopped.load(Ordering::SeqCst) {
            break;
        }
        let Ok(generation) = config.owner.cancellation() else {
            continue;
        };
        let Ok(Some(session)) = config.owner.current_session(now_ms() / 1000) else {
            worker.status.set_sync(SyncState::Offline);
            pending = false;
            continue;
        };
        let authority = Arc::new(Authority {
            certificates: std::sync::OnceLock::new(),
            authentication_changed: !last_session.ptr_eq(&Arc::downgrade(&session)),
            change_admitted: AtomicBool::new(false),
            config: config.clone(),
            identity: *session.identity(),
            generation,
            stopped: stopped.clone(),
        });
        pending = cycle(&worker, authority.clone()).await.unwrap_or(false);
        if authority.change_admitted.load(Ordering::SeqCst) {
            last_session = Arc::downgrade(&session);
        }
        if authority.check().is_err() {
            // This supervisor has not started a replacement cycle yet.
            worker.status.set_sync(SyncState::Offline);
        }
    }
}

#[cfg(all(test, any(windows, target_os = "macos")))]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum StallAt {
    Push,
    Pull,
    Checkpoint,
}

#[cfg(all(test, any(windows, target_os = "macos")))]
pub(crate) async fn verify_stalled_worker(
    state: WorkspaceState,
    owner: Arc<HostedSessionOwner>,
    stall: StallAt,
) {
    use super::{VaultWorkerState, WorkItem, run_vault_worker};
    use context_relay_core::sync::{
        SupabaseHttpClient, SupabaseHttpError, SupabaseHttpRequest, SupabaseHttpResponse,
    };
    use std::sync::Mutex;
    struct Http {
        certificates: Vec<u8>,
        stall: StallAt,
        entered: tokio::sync::mpsc::UnboundedSender<()>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
    }
    impl SupabaseHttpClient for Http {
        fn execute(
            &self,
            request: SupabaseHttpRequest,
        ) -> Result<SupabaseHttpResponse, SupabaseHttpError> {
            assert!(request.header("authorization").is_some());
            if request.url().contains("/rest/v1/device_certificates?") {
                return Ok(SupabaseHttpResponse::new(200, self.certificates.clone()));
            }
            if self.stall != StallAt::Push && request.url().ends_with("/functions/v1/sync") {
                use base64::Engine as _;
                let body: serde_json::Value = serde_json::from_slice(request.body()).unwrap();
                assert_eq!(body["action"], "push_operations");
                let ids = body["operations"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|value| {
                        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .decode(value.as_str().unwrap())
                            .unwrap();
                        context_relay_protocol::decode_sync_operation_v1(&bytes)
                            .unwrap()
                            .operation_id
                    })
                    .collect::<Vec<_>>();
                return Ok(SupabaseHttpResponse::new(
                    200,
                    serde_json::to_vec(&serde_json::json!({"v":1,"accepted":ids,"duplicates":[]}))
                        .unwrap(),
                ));
            }
            if self.stall == StallAt::Checkpoint
                && request.url().contains("/rest/v1/sync_operations?")
            {
                return Ok(SupabaseHttpResponse::new(200, b"[]".to_vec()));
            }
            assert!(request.url().contains(match self.stall {
                StallAt::Push => "/functions/v1/sync",
                StallAt::Pull => "/rest/v1/sync_operations?",
                StallAt::Checkpoint => "/rest/v1/sync_checkpoints?",
            }));
            self.entered.send(()).unwrap();
            self.release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(20))
                .unwrap();
            Ok(SupabaseHttpResponse::new(
                401,
                br#"{"v":1,"error":"auth_required"}"#.to_vec(),
            ))
        }
    }
    let certificates = certificate_rows(&state.vault);
    let (entered, mut entries) = tokio::sync::mpsc::unbounded_channel();
    let (release, released) = std::sync::mpsc::channel();
    let config = Config {
        owner: owner.clone(),
        project: "https://example.supabase.co".into(),
        key: "public-test".to_string().into(),
        http: Some(Arc::new(Http {
            certificates: serde_json::to_vec(&certificates).unwrap(),
            stall,
            entered,
            release: Mutex::new(released),
        })),
    };
    let (sender, mut receiver) = tokio::sync::mpsc::channel::<WorkItem>(8);
    let gate = Arc::new(Mutex::new(true));
    let status = Arc::new(ServiceStatus::new());
    let client = WorkerClient {
        sender: sender.downgrade(),
        admission: gate.clone(),
        worker_hook: None,
        status: status.clone(),
    };
    let worker_gate = gate.clone();
    let worker_status = status.clone();
    let thread = std::thread::spawn(move || {
        run_vault_worker(
            VaultWorkerState::Open(state),
            &mut receiver,
            None,
            &worker_status,
            &worker_gate,
        )
    });
    let mut supervisor = Supervisor::spawn(client.clone(), Some(config));
    tokio::time::timeout(Duration::from_secs(10), entries.recv())
        .await
        .unwrap()
        .unwrap();
    struct Local;
    impl WorkAdmission for Local {
        fn begin(&self) -> bool {
            true
        }
    }
    let read = client
        .try_submit(
            VaultCommand::Workspace(context_relay_protocol::LocalRequest::MemoryList(
                context_relay_protocol::MemoryListParams {
                    project_id: None,
                    include_archived: false,
                },
            )),
            Local,
        )
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), read)
            .await
            .unwrap()
            .unwrap()
            .is_ok()
    );
    owner.suspend().unwrap();
    tokio::time::timeout(Duration::from_secs(1), supervisor.shutdown())
        .await
        .unwrap();
    assert!(supervisor.client().retry().is_err());
    // Late HTTP completion cannot publish onto the closed supervisor/vault admission.
    *gate.lock().unwrap() = false;
    drop(sender);
    thread.join().unwrap();
    release.send(()).unwrap();
}

#[cfg(all(test, any(windows, target_os = "macos")))]
fn certificate_rows(vault: &context_relay_core::vault::Vault) -> Vec<serde_json::Value> {
    vault.all_devices().unwrap().iter().map(|row| {
        use context_relay_core::crypto::CertificateIssuerV1;
        let cert = &row.certificate;
        let bytea = |bytes: &[u8]| format!("\\x{}", bytes.iter().map(|b| format!("{b:02x}")).collect::<String>());
        let (kind, device, root, issuer) = match cert.issuer {
            CertificateIssuerV1::RecoveryRoot(key) => ("recovery_root", None, Some(bytea(&key.0)), key),
            CertificateIssuerV1::Device { device_id, signing_public_key } => ("device", Some(device_id), None, signing_public_key),
        };
        serde_json::json!({"id":row.certificate_id,"account_id":cert.account_id,"workspace_id":cert.workspace_id,
            "control_epoch":cert.control_epoch,"request_nonce":bytea(&cert.request_nonce.0),"device_id":cert.device_id,
            "issuer_kind":kind,"issuer_device_id":device,"issuer_recovery_public_key":root,"issuer_signing_public_key":bytea(&issuer.0),
            "device_signing_public_key":bytea(&cert.signing_public_key.0),"device_wrapping_public_key":bytea(&cert.wrapping_public_key.0),"signature":bytea(&cert.signature.0)})
    }).collect::<Vec<_>>()
}

#[cfg(all(test, any(windows, target_os = "macos")))]
pub(crate) async fn verify_checkpoint_worker(
    state: WorkspaceState,
    owner: Arc<HostedSessionOwner>,
    previous: Option<context_relay_core::sync::CanonicalCheckpoint>,
) -> context_relay_core::sync::CanonicalCheckpoint {
    use super::{VaultWorkerState, WorkItem, run_vault_worker};
    use context_relay_core::sync::{
        CanonicalCheckpoint, SupabaseHttpClient, SupabaseHttpError, SupabaseHttpRequest,
        SupabaseHttpResponse,
    };
    use std::sync::Mutex;
    struct Http {
        scope: SyncScope,
        certificates: Vec<u8>,
        checkpoint: Mutex<Option<CanonicalCheckpoint>>,
        pushes: std::sync::atomic::AtomicUsize,
    }
    fn bytea(bytes: &[u8]) -> String {
        format!(
            "\\x{}",
            bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
        )
    }
    impl SupabaseHttpClient for Http {
        fn execute(
            &self,
            request: SupabaseHttpRequest,
        ) -> Result<SupabaseHttpResponse, SupabaseHttpError> {
            use base64::Engine as _;
            let url = reqwest::Url::parse(request.url()).unwrap();
            assert!(request.header("authorization").is_some());
            let query = url
                .query_pairs()
                .collect::<std::collections::BTreeMap<_, _>>();
            let result = match url.path() {
                "/rest/v1/device_certificates" => {
                    assert_eq!(query["account_id"], format!("eq.{}", self.scope.account_id));
                    assert_eq!(
                        query["workspace_id"],
                        format!("eq.{}", self.scope.workspace_id)
                    );
                    return Ok(SupabaseHttpResponse::new(200, self.certificates.clone()));
                }
                "/rest/v1/sync_operations" => serde_json::json!([]),
                "/functions/v1/sync" => {
                    let body: serde_json::Value = serde_json::from_slice(request.body()).unwrap();
                    assert!(request.header("idempotency-key").is_some());
                    match body["action"].as_str().unwrap() {
                        "push_operations" => {
                            let ids = body["operations"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .map(|value| {
                                    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                                        .decode(value.as_str().unwrap())
                                        .unwrap();
                                    context_relay_protocol::decode_sync_operation_v1(&bytes)
                                        .unwrap()
                                        .operation_id
                                })
                                .collect::<Vec<_>>();
                            serde_json::json!({"v":1,"accepted":ids,"duplicates":[]})
                        }
                        "push_checkpoint" => {
                            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                                .decode(body["checkpoint"].as_str().unwrap())
                                .unwrap();
                            let decoded =
                                context_relay_protocol::decode_checkpoint_v1(&bytes).unwrap();
                            assert_eq!(decoded.account_id, self.scope.account_id);
                            assert_eq!(decoded.workspace_id, self.scope.workspace_id);
                            let checkpoint = CanonicalCheckpoint::from_checkpoint(decoded).unwrap();
                            assert_eq!(checkpoint.bytes, bytes);
                            let mut stored = self.checkpoint.lock().unwrap();
                            assert!(
                                stored.is_none(),
                                "a completed checkpoint must not be published again after restart"
                            );
                            let hash = checkpoint.canonical_hash;
                            *stored = Some(checkpoint);
                            self.pushes.fetch_add(1, Ordering::SeqCst);
                            serde_json::json!({"v":1,"canonicalHash":hash,"duplicate":false})
                        }
                        other => panic!("unexpected sync action: {other}"),
                    }
                }
                "/rest/v1/sync_checkpoints" => {
                    assert_eq!(query["account_id"], format!("eq.{}", self.scope.account_id));
                    assert_eq!(
                        query["workspace_id"],
                        format!("eq.{}", self.scope.workspace_id)
                    );
                    assert_eq!(query["schema_version"], "eq.2");
                    let stored = self.checkpoint.lock().unwrap();
                    if let Some(checkpoint) = stored.as_ref() {
                        if let Some(hash) = query.get("canonical_sha256") {
                            assert_eq!(
                                *hash,
                                format!("eq.{}", bytea(&checkpoint.canonical_hash.0))
                            );
                        }
                        if let Some(after) = query.get("or") {
                            let timestamp = "2026-09-09T00:00:00.000001Z";
                            assert_eq!(
                                *after,
                                format!(
                                    "(received_at.gt.{timestamp},and(received_at.eq.{timestamp},canonical_sha256.gt.{}))",
                                    bytea(&checkpoint.canonical_hash.0)
                                )
                            );
                            serde_json::json!([])
                        } else {
                            let decoded = &checkpoint.checkpoint;
                            serde_json::json!([{
                                "account_id":decoded.account_id,"workspace_id":decoded.workspace_id,
                                "schema_version":decoded.schema_version,"previous_checkpoint_hash":bytea(&decoded.previous_checkpoint_hash.0),
                                "causal_frontier":decoded.causal_frontier,"state_hash":bytea(&decoded.state_hash.0),
                                "key_epoch":decoded.key_epoch,"creator_device_id":decoded.creator_device,"created_hlc":decoded.created_hlc,
                                "signature":bytea(&decoded.signature.0),"canonical_sha256":bytea(&checkpoint.canonical_hash.0),
                                "received_at":"2026-09-09T00:00:00.000001Z"
                            }])
                        }
                    } else {
                        serde_json::json!([])
                    }
                }
                other => panic!("unexpected sync path: {other}"),
            };
            Ok(SupabaseHttpResponse::new(
                200,
                serde_json::to_vec(&result).unwrap(),
            ))
        }
    }
    let (keys, material) = local_sync_material(&state).unwrap().unwrap();
    let identity = material.local_identity(state.device_id, &keys).unwrap();
    let scope = SyncScope {
        account_id: identity.account_id,
        workspace_id: identity.workspace_id,
    };
    let expected_pushes = usize::from(previous.is_none());
    let http = Arc::new(Http {
        scope,
        certificates: serde_json::to_vec(&certificate_rows(&state.vault)).unwrap(),
        checkpoint: Mutex::new(previous),
        pushes: std::sync::atomic::AtomicUsize::new(0),
    });
    let config = Arc::new(Config {
        owner: owner.clone(),
        project: "https://example.supabase.co".into(),
        key: "public-test".to_string().into(),
        http: Some(http.clone()),
    });
    let session = owner.current_session(now_ms() / 1000).unwrap().unwrap();
    let authority = Arc::new(Authority {
        certificates: std::sync::OnceLock::new(),
        authentication_changed: true,
        change_admitted: AtomicBool::new(false),
        config,
        identity: *session.identity(),
        generation: owner.cancellation().unwrap(),
        stopped: Arc::new(AtomicBool::new(false)),
    });
    let (sender, mut receiver) = tokio::sync::mpsc::channel::<WorkItem>(8);
    let gate = Arc::new(Mutex::new(true));
    let status = Arc::new(ServiceStatus::new());
    let client = WorkerClient {
        sender: sender.downgrade(),
        admission: gate.clone(),
        worker_hook: None,
        status: status.clone(),
    };
    let worker_gate = gate.clone();
    let worker_status = status.clone();
    let thread = std::thread::spawn(move || {
        run_vault_worker(
            VaultWorkerState::Open(state),
            &mut receiver,
            None,
            &worker_status,
            &worker_gate,
        )
    });
    let result = tokio::time::timeout(Duration::from_secs(10), cycle(&client, authority)).await;
    // Always close the actor before asserting: failed validation must release the vault too.
    *gate.lock().unwrap() = false;
    drop(sender);
    thread.join().unwrap();
    assert!(!result.unwrap().unwrap());
    assert_eq!(status.snapshot().sync, SyncState::Idle);
    assert_eq!(http.pushes.load(Ordering::SeqCst), expected_pushes);
    http.checkpoint.lock().unwrap().clone().unwrap()
}
