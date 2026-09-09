use super::{
    ServiceStatus, VaultCommand, WorkAdmission, WorkerClient, WorkspaceState, canceled_error,
    local_sync_material, scope_denied_error, service_internal_error,
};
use context_relay_core::{
    auth::{HostedIdentity, HostedSessionOwner, LoginCancellation},
    service::sync_embedding,
    sync::{
        PreparedPull, PreparedPush, PullProgress, PullRequest, PullResponse, PushReceipt,
        SupabaseTransport, SupabaseTransportConfig, SyncEngine, SyncProvider, SyncScope,
        SyncTransport, TransportError,
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
    Push(PreparedPush, Result<PushReceipt, TransportError>),
    Pull(Box<PreparedPull>, PullResponse),
    Complete(bool),
    Failed,
}
enum Progress {
    Push(PreparedPush),
    Pull(PullProgress),
    Pushed(bool, PullProgress),
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
    let (keys, material) = local_sync_material(state)?.ok_or_else(scope_denied_error)?;
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
        Step::Pull(prepared, response) => Progress::Pull(
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
        ),
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
            Progress::Failed => return Ok(false),
            Progress::Complete(more_work) => return Ok(more_work),
            Progress::Pushed(pending, pull) => {
                more_work |= pending;
                Progress::Pull(pull)
            }
            Progress::Pull(PullProgress::Complete(report)) => {
                submit(
                    worker,
                    &authority,
                    cycle_scope,
                    Step::Complete(more_work || report.more_work),
                )
                .await?
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
                        .and_then(|mut transport| match prepared.request() {
                            PullRequest::Operations { cursor, limit } => transport
                                .pull_operations(scope, cursor.as_ref(), *limit)
                                .map(PullResponse::Operations),
                            PullRequest::DeviceRange { device, range } => transport
                                .pull_device_range(scope, *device, range.clone())
                                .map(PullResponse::DeviceRange),
                        });
                    (prepared, response)
                })
                .await
                .map_err(|_| service_internal_error())?;
                let step = match response {
                    Ok(response) => Step::Pull(prepared, response),
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
pub(crate) async fn verify_stalled_worker(
    state: WorkspaceState,
    owner: Arc<HostedSessionOwner>,
    after_push: bool,
) {
    use super::{VaultWorkerState, WorkItem, run_vault_worker};
    use context_relay_core::sync::{
        SupabaseHttpClient, SupabaseHttpError, SupabaseHttpRequest, SupabaseHttpResponse,
    };
    use std::sync::Mutex;
    struct Http {
        after_push: bool,
        entered: tokio::sync::mpsc::UnboundedSender<()>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
    }
    impl SupabaseHttpClient for Http {
        fn execute(
            &self,
            request: SupabaseHttpRequest,
        ) -> Result<SupabaseHttpResponse, SupabaseHttpError> {
            assert!(request.header("authorization").is_some());
            if self.after_push && request.url().ends_with("/functions/v1/sync") {
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
            assert!(request.url().contains(if self.after_push {
                "/rest/v1/sync_operations?"
            } else {
                "/functions/v1/sync"
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
    let (entered, mut entries) = tokio::sync::mpsc::unbounded_channel();
    let (release, released) = std::sync::mpsc::channel();
    let config = Config {
        owner: owner.clone(),
        project: "https://example.supabase.co".into(),
        key: "public-test".to_string().into(),
        http: Some(Arc::new(Http {
            after_push,
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
