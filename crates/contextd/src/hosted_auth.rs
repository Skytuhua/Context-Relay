use crate::hosted_login::DaemonLogin;
use context_relay_core::auth::{HostedSessionOwner, LoginCancellation, LoginError};
use context_relay_protocol::{
    ClientError, ErrorCode, HostedAuthFailure, HostedAuthState, HostedAuthStatus, LocalRequest,
    LocalResult, OperationId,
};
use reqwest::Url;
use std::{
    sync::{Arc, Mutex, Weak},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::task::JoinHandle;

pub trait LoginBrowser: Send + Sync {
    fn open(&self, url: &Url) -> Result<(), LoginError>;
}
pub struct SystemLoginBrowser;
impl LoginBrowser for SystemLoginBrowser {
    fn open(&self, url: &Url) -> Result<(), LoginError> {
        if url.scheme() != "https"
            || url.path() != "/auth/v1/authorize"
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(LoginError::Configuration);
        }
        #[cfg(windows)]
        {
            let verb: Vec<u16> = "open\0".encode_utf16().collect();
            let target: Vec<u16> = url.as_str().encode_utf16().chain(Some(0)).collect();
            // Both strings are NUL terminated and live for this synchronous call.
            let result = unsafe {
                windows_sys::Win32::UI::Shell::ShellExecuteW(
                    std::ptr::null_mut(),
                    verb.as_ptr(),
                    target.as_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    1,
                )
            };
            if result as isize <= 32 {
                return Err(LoginError::Unavailable);
            }
            Ok(())
        }
        #[cfg(target_os = "macos")]
        {
            std::process::Command::new("/usr/bin/open")
                .arg("--")
                .arg(url.as_str())
                .status()
                .map_err(|_| LoginError::Unavailable)?
                .success()
                .then_some(())
                .ok_or(LoginError::Unavailable)
        }
        #[cfg(not(any(windows, target_os = "macos")))]
        Err(LoginError::Unavailable)
    }
}

struct State {
    status: HostedAuthStatus,
    valid_until: Option<(u64, tokio::time::Instant)>,
    start_expected: Option<OperationId>,
    pending: Option<JoinHandle<()>>,
    cancellation: Option<LoginCancellation>,
    closed: bool,
}
struct Inner {
    state: Mutex<State>,
    owner: Option<Arc<HostedSessionOwner>>,
    project: String,
    browser: Arc<dyn LoginBrowser>,
}
impl Drop for Inner {
    fn drop(&mut self) {
        if let Ok(state) = self.state.get_mut() {
            if let Some(cancellation) = state.cancellation.take() {
                cancellation.cancel();
            }
            if let Some(job) = state.pending.take() {
                job.abort();
            }
        }
        if let Some(owner) = &self.owner {
            let _ = owner.suspend();
        }
    }
}
#[derive(Clone)]
pub struct HostedAuthService(Arc<Inner>);

fn generation() -> OperationId {
    OperationId::new(uuid::Uuid::now_v7()).expect("UUIDv7")
}
fn error(code: ErrorCode, message: &str) -> ClientError {
    ClientError {
        code,
        message: message.into(),
        field_path: None,
        retryable: false,
    }
}
fn failed(error: LoginError) -> HostedAuthState {
    HostedAuthState::Failed {
        reason: match error {
            LoginError::Denied => HostedAuthFailure::Denied,
            LoginError::Expired => HostedAuthFailure::Expired,
            LoginError::CredentialStore => HostedAuthFailure::CredentialStore,
            _ => HostedAuthFailure::Unavailable,
        },
    }
}
fn now() -> Result<u64, LoginError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| LoginError::Unavailable)
}
fn publish(inner: &Weak<Inner>, generation: OperationId, phase: HostedAuthState) {
    if let Some(inner) = inner.upgrade()
        && let Ok(mut state) = inner.state.lock()
        && !state.closed
        && state.status.generation == generation
    {
        state.status.state = phase;
        state.valid_until = None;
    }
}

fn session_metadata(owner: &HostedSessionOwner) -> Result<(u64, LoginCancellation), LoginError> {
    let session = owner.current_session(now()?)?.ok_or(LoginError::Expired)?;
    Ok((session.expires_at(), owner.cancellation()?))
}

async fn maintain_session(
    weak: Weak<Inner>,
    generation: OperationId,
    owner: Arc<HostedSessionOwner>,
) {
    let initial_owner = owner.clone();
    let mut metadata = tokio::task::spawn_blocking(move || session_metadata(&initial_owner))
        .await
        .unwrap_or(Err(LoginError::Unavailable));
    loop {
        let (expires, cancellation) = match metadata {
            Ok(value) => value,
            Err(error) => {
                publish(&weak, generation, failed(error));
                return;
            }
        };
        let remaining = match now() {
            Ok(now) if now < expires => expires - now,
            _ => {
                publish(&weak, generation, failed(LoginError::Expired));
                return;
            }
        };
        let deadline =
            tokio::time::Instant::now() + Duration::from_secs(remaining.saturating_sub(1));
        {
            let Some(inner) = weak.upgrade() else {
                return;
            };
            let Ok(mut state) = inner.state.lock() else {
                return;
            };
            if state.closed || state.status.generation != generation || cancellation.is_canceled() {
                return;
            }
            state.cancellation = Some(cancellation.clone());
            state.valid_until = Some((expires, deadline));
            state.status.state = HostedAuthState::Connected {};
        }
        // Recheck wall time periodically; the monotonic deadline also prevents clock rollback
        // from extending the lifetime displayed by the daemon.
        loop {
            let wall = expires.saturating_sub(now().unwrap_or(expires));
            let monotonic = deadline
                .saturating_duration_since(tokio::time::Instant::now())
                .as_secs();
            let delay = wall.min(monotonic).saturating_sub(60).clamp(1, 30);
            tokio::time::sleep(Duration::from_secs(delay)).await;
            if now().map_or(true, |now| now.saturating_add(60) >= expires)
                || tokio::time::Instant::now() + Duration::from_secs(60) >= deadline
            {
                break;
            }
        }
        let mut retry = Duration::from_secs(5);
        loop {
            let refreshing_owner = owner.clone();
            let refreshing_cancellation = cancellation.clone();
            metadata = tokio::task::spawn_blocking(move || {
                refreshing_owner.refresh_cancellable(&refreshing_cancellation, now()?)?;
                session_metadata(&refreshing_owner)
            })
            .await
            .unwrap_or(Err(LoginError::Unavailable));
            if !matches!(metadata, Err(LoginError::Unavailable | LoginError::Busy)) {
                break;
            }
            tokio::time::sleep(retry).await;
            retry = (retry * 2).min(Duration::from_secs(60));
        }
    }
}

impl HostedAuthService {
    pub fn disabled() -> Self {
        Self::build(None, String::new(), Arc::new(SystemLoginBrowser))
    }
    pub fn enabled(
        project: String,
        owner: Arc<HostedSessionOwner>,
        browser: Arc<dyn LoginBrowser>,
    ) -> Self {
        let service = Self::build(Some(owner.clone()), project, browser);
        let weak = Arc::downgrade(&service.0);
        let mut state = service.0.state.lock().expect("new service");
        state.status.state = HostedAuthState::Restoring {};
        let generation = state.status.generation;
        state.pending = Some(tokio::spawn(async move {
            let mut retry = Duration::from_secs(5);
            loop {
                let restoring_owner = owner.clone();
                let restoring_service = weak.clone();
                let result = tokio::task::spawn_blocking(move || {
                    let cancellation = restoring_owner.cancellation()?;
                    {
                        let inner = restoring_service.upgrade().ok_or(LoginError::Canceled)?;
                        let mut state = inner.state.lock().map_err(|_| LoginError::Unavailable)?;
                        if state.closed || state.status.generation != generation {
                            return Err(LoginError::Canceled);
                        }
                        state.cancellation = Some(cancellation.clone());
                    }
                    restoring_owner.restore_cancellable(&cancellation, now()?)
                })
                .await
                .unwrap_or(Err(LoginError::Unavailable));
                match result {
                    Ok(Some(_)) => {
                        maintain_session(weak, generation, owner).await;
                        return;
                    }
                    Ok(None) => {
                        publish(
                            &weak,
                            generation,
                            HostedAuthState::SignedOut {
                                remote_revoked: None,
                            },
                        );
                        return;
                    }
                    Err(LoginError::Unavailable) => {
                        publish(&weak, generation, failed(LoginError::Unavailable));
                        tokio::time::sleep(retry).await;
                        retry = (retry * 2).min(Duration::from_secs(60));
                    }
                    Err(error) => {
                        publish(&weak, generation, failed(error));
                        return;
                    }
                }
            }
        }));
        drop(state);
        service
    }
    fn build(
        owner: Option<Arc<HostedSessionOwner>>,
        project: String,
        browser: Arc<dyn LoginBrowser>,
    ) -> Self {
        Self(Arc::new(Inner {
            owner,
            project,
            browser,
            state: Mutex::new(State {
                status: HostedAuthStatus {
                    generation: generation(),
                    state: HostedAuthState::Disabled {},
                },
                valid_until: None,
                pending: None,
                cancellation: None,
                start_expected: None,
                closed: false,
            }),
        }))
    }
    pub async fn handle(&self, request: LocalRequest) -> Result<LocalResult, ClientError> {
        if !matches!(
            &request,
            LocalRequest::HostedAuthStatus(_)
                | LocalRequest::HostedAuthStart(_)
                | LocalRequest::HostedAuthCancel(_)
                | LocalRequest::HostedAuthLogout(_)
        ) {
            return Err(error(
                ErrorCode::InvalidRequest,
                "Not a hosted sign-in request",
            ));
        }
        let mut state = self
            .0
            .state
            .lock()
            .map_err(|_| error(ErrorCode::Internal, "Hosted sign-in is unavailable"))?;
        if state.closed {
            return Err(error(
                ErrorCode::Canceled,
                "Hosted sign-in is shutting down",
            ));
        }
        if matches!(state.status.state, HostedAuthState::Connected {})
            && !state.valid_until.is_some_and(|(expires, deadline)| {
                now().is_ok_and(|now| now < expires) && tokio::time::Instant::now() < deadline
            })
        {
            state.status.state = failed(LoginError::Expired);
        }
        if matches!(request, LocalRequest::HostedAuthStatus(_)) || self.0.owner.is_none() {
            return Ok(LocalResult::HostedAuth {
                status: state.status.clone(),
            });
        }
        let owner = self.0.owner.as_ref().expect("configured owner").clone();
        let cancel_only = matches!(&request, LocalRequest::HostedAuthCancel(_));
        match request {
            LocalRequest::HostedAuthStart(params) => {
                if params.operation_id == state.status.generation
                    && state.start_expected == Some(params.expected_generation)
                {
                    return Ok(LocalResult::HostedAuth {
                        status: state.status.clone(),
                    });
                }
                if params.expected_generation != state.status.generation
                    || params.operation_id == state.status.generation
                {
                    return Err(error(
                        ErrorCode::RevisionConflict,
                        "Sign-in state changed; refresh it before retrying",
                    ));
                }
                if !matches!(
                    state.status.state,
                    HostedAuthState::SignedOut { .. } | HostedAuthState::Failed { .. }
                ) {
                    return Err(error(
                        ErrorCode::Busy,
                        "Finish the current sign-in operation first",
                    ));
                }
                if let Some(cancellation) = state.cancellation.take() {
                    cancellation.cancel();
                }
                if let Some(job) = state.pending.take() {
                    job.abort();
                }
                state.status = HostedAuthStatus {
                    generation: params.operation_id,
                    state: HostedAuthState::SigningIn {},
                };
                state.start_expected = Some(params.expected_generation);
                state.valid_until = None;
                let cancellation = LoginCancellation::default();
                state.cancellation = Some(cancellation.clone());
                let weak = Arc::downgrade(&self.0);
                let project = self.0.project.clone();
                let browser = self.0.browser.clone();
                state.pending = Some(tokio::spawn(async move {
                    let result = async {
                        let flow = DaemonLogin::begin_with_cancellation(
                            &project,
                            owner.clone(),
                            cancellation,
                        )
                        .await?;
                        flow.open_browser(move |url| browser.open(url)).await?;
                        flow.wait().await
                    }
                    .await;
                    match result {
                        Ok(_) => maintain_session(weak, params.operation_id, owner).await,
                        Err(error) => publish(&weak, params.operation_id, failed(error)),
                    }
                }));
            }
            LocalRequest::HostedAuthCancel(params) | LocalRequest::HostedAuthLogout(params) => {
                if params.generation != state.status.generation {
                    return Err(error(
                        ErrorCode::RevisionConflict,
                        "Sign-in state changed; refresh it before retrying",
                    ));
                }
                if cancel_only && !matches!(state.status.state, HostedAuthState::SigningIn {}) {
                    return Ok(LocalResult::HostedAuth {
                        status: state.status.clone(),
                    });
                }
                if matches!(state.status.state, HostedAuthState::SigningOut {}) {
                    return Ok(LocalResult::HostedAuth {
                        status: state.status.clone(),
                    });
                }
                if let Some(cancellation) = state.cancellation.take() {
                    cancellation.cancel();
                }
                if let Some(job) = state.pending.take() {
                    job.abort();
                }
                state.status.generation = generation();
                state.start_expected = None;
                state.status.state = HostedAuthState::SigningOut {};
                let generation = state.status.generation;
                let weak = Arc::downgrade(&self.0);
                state.pending = Some(tokio::spawn(async move {
                    let result = tokio::task::spawn_blocking(move || owner.logout()).await;
                    let phase = match result {
                        Ok(Ok(outcome)) => match outcome.local {
                            Ok(()) => HostedAuthState::SignedOut {
                                remote_revoked: outcome.remote.map(|result| result.is_ok()),
                            },
                            Err(error) => failed(error),
                        },
                        Ok(Err(error)) => failed(error),
                        Err(_) => failed(LoginError::Unavailable),
                    };
                    publish(&weak, generation, phase);
                }));
            }
            _ => {
                return Err(error(
                    ErrorCode::InvalidRequest,
                    "Not a hosted sign-in request",
                ));
            }
        }
        Ok(LocalResult::HostedAuth {
            status: state.status.clone(),
        })
    }
    pub async fn shutdown(&self) {
        let pending = self.stop();
        if let Some(job) = pending {
            job.abort();
            let _ = job.await;
        }
        if let Some(owner) = self.0.owner.clone() {
            let _ = tokio::task::spawn_blocking(move || owner.suspend()).await;
        }
    }
    fn stop(&self) -> Option<JoinHandle<()>> {
        self.0.state.lock().ok().and_then(|mut state| {
            state.closed = true;
            if let Some(cancellation) = state.cancellation.take() {
                cancellation.cancel();
            }
            let pending = state.pending.take();
            if let Some(job) = &pending {
                job.abort();
            }
            pending
        })
    }
    pub fn close(&self) {
        self.stop();
        if let Some(owner) = &self.0.owner {
            let _ = owner.suspend();
        }
    }
}

#[cfg(all(test, feature = "test-support"))]
mod tests {
    use super::*;
    use context_relay_core::{
        auth::{LoginStore, StoredLogin, SupabaseAuthClient},
        sync::{SupabaseHttpClient, SupabaseHttpError, SupabaseHttpRequest, SupabaseHttpResponse},
    };
    use context_relay_protocol::{EmptyParams, HostedAuthGenerationParams, HostedAuthStartParams};
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Store;
    impl LoginStore for Store {
        fn load(&self) -> Result<Option<StoredLogin>, LoginError> {
            Ok(None)
        }
        fn save(&self, _: &StoredLogin) -> Result<(), LoginError> {
            panic!("browser failure must not save credentials")
        }
        fn clear(&self) -> Result<(), LoginError> {
            Ok(())
        }
    }
    struct Http;
    impl SupabaseHttpClient for Http {
        fn execute(
            &self,
            _: SupabaseHttpRequest,
        ) -> Result<SupabaseHttpResponse, SupabaseHttpError> {
            panic!("no callback was supplied")
        }
    }
    struct Browser(AtomicUsize);
    #[derive(Default)]
    struct SavedStore(Mutex<Option<StoredLogin>>);
    impl LoginStore for SavedStore {
        fn load(&self) -> Result<Option<StoredLogin>, LoginError> {
            Ok(self.0.lock().unwrap().clone())
        }
        fn save(&self, value: &StoredLogin) -> Result<(), LoginError> {
            *self.0.lock().unwrap() = Some(value.clone());
            Ok(())
        }
        fn clear(&self) -> Result<(), LoginError> {
            *self.0.lock().unwrap() = None;
            Ok(())
        }
    }
    struct AuthHttp {
        lifetime: u64,
        fail_refresh: std::sync::atomic::AtomicBool,
        refreshes: AtomicUsize,
    }
    impl Default for AuthHttp {
        fn default() -> Self {
            Self {
                lifetime: 900,
                fail_refresh: false.into(),
                refreshes: 0.into(),
            }
        }
    }
    impl SupabaseHttpClient for AuthHttp {
        fn execute(
            &self,
            request: SupabaseHttpRequest,
        ) -> Result<SupabaseHttpResponse, SupabaseHttpError> {
            use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
            use serde_json::json;
            let user = "550e8400-e29b-41d4-a716-446655440000";
            let body = if request.url().ends_with("/user") {
                json!({"id":user})
            } else {
                let refresh = request.url().ends_with("grant_type=refresh_token");
                if refresh {
                    self.refreshes.fetch_add(1, Ordering::SeqCst);
                    if self.fail_refresh.load(Ordering::SeqCst) {
                        return Ok(SupabaseHttpResponse::new(503, Vec::new()));
                    }
                } else {
                    assert!(request.url().ends_with("grant_type=pkce"));
                }
                let lifetime = if refresh { 900 } else { self.lifetime };
                let claims = json!({"iss":"https://example.supabase.co/auth/v1","aud":"authenticated","sub":user,"session_id":"550e8400-e29b-41d4-a716-446655440001","exp":now().unwrap()+lifetime});
                let token = format!(
                    "e30.{}.signature",
                    URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
                );
                json!({"token_type":"bearer","access_token":token,"refresh_token":"synthetic-refresh"})
            };
            Ok(SupabaseHttpResponse::new(
                200,
                serde_json::to_vec(&body).unwrap(),
            ))
        }
    }
    struct CallbackBrowser;
    impl LoginBrowser for CallbackBrowser {
        fn open(&self, url: &Url) -> Result<(), LoginError> {
            use std::io::Write;
            let redirect = url
                .query_pairs()
                .find(|(key, _)| key == "redirect_to")
                .unwrap()
                .1
                .into_owned();
            let mut callback = Url::parse(&redirect).unwrap();
            callback
                .query_pairs_mut()
                .append_pair("code", "synthetic-code");
            let address = format!("127.0.0.1:{}", callback.port().unwrap());
            let mut stream = std::net::TcpStream::connect(&address).unwrap();
            write!(
                stream,
                "GET {}?{} HTTP/1.1\r\nHost: {address}\r\n\r\n",
                callback.path(),
                callback.query().unwrap()
            )
            .unwrap();
            Ok(())
        }
    }
    impl LoginBrowser for Browser {
        fn open(&self, url: &Url) -> Result<(), LoginError> {
            assert_eq!(url.path(), "/auth/v1/authorize");
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(LoginError::Unavailable)
        }
    }
    async fn settled(service: &HostedAuthService) -> HostedAuthStatus {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let LocalResult::HostedAuth { status } = service
                    .handle(LocalRequest::HostedAuthStatus(EmptyParams {}))
                    .await
                    .unwrap()
                else {
                    panic!("wrong status")
                };
                if !matches!(
                    status.state,
                    HostedAuthState::Restoring {}
                        | HostedAuthState::SigningIn {}
                        | HostedAuthState::SigningOut {}
                ) {
                    return status;
                }
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap()
    }
    #[tokio::test]
    async fn startup_restoration_retries_transient_failure_without_a_browser() {
        let project = "https://example.supabase.co";
        let http = Arc::new(AuthHttp::default());
        let store = Arc::new(SavedStore::default());
        let client = Arc::new(
            SupabaseAuthClient::with_http_client(project, "publishable-key", http.clone()).unwrap(),
        );
        let initial = HostedAuthService::enabled(
            project.into(),
            Arc::new(HostedSessionOwner::new(client.clone(), store.clone())),
            Arc::new(CallbackBrowser),
        );
        let signed_out = settled(&initial).await;
        initial
            .handle(LocalRequest::HostedAuthStart(HostedAuthStartParams {
                operation_id: generation(),
                expected_generation: signed_out.generation,
            }))
            .await
            .unwrap();
        assert!(matches!(
            settled(&initial).await.state,
            HostedAuthState::Connected {}
        ));
        initial.shutdown().await;
        http.fail_refresh.store(true, Ordering::SeqCst);
        let browser = Arc::new(Browser(AtomicUsize::new(0)));
        let service = HostedAuthService::enabled(
            project.into(),
            Arc::new(HostedSessionOwner::new(client, store.clone())),
            browser.clone(),
        );
        let offline = settled(&service).await;
        assert!(matches!(
            offline.state,
            HostedAuthState::Failed {
                reason: HostedAuthFailure::Unavailable
            }
        ));
        http.fail_refresh.store(false, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(8), async {
            while !matches!(settled(&service).await.state, HostedAuthState::Connected {}) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(browser.0.load(Ordering::SeqCst), 0);
        assert!(store.load().unwrap().is_some());
        service.shutdown().await;
    }
    #[tokio::test]
    async fn expired_session_is_not_connected_and_transient_refresh_recovers() {
        let project = "https://example.supabase.co";
        let http = Arc::new(AuthHttp {
            lifetime: 5,
            fail_refresh: true.into(),
            refreshes: 0.into(),
        });
        let store = Arc::new(SavedStore::default());
        let owner = Arc::new(HostedSessionOwner::new(
            Arc::new(
                SupabaseAuthClient::with_http_client(project, "publishable-key", http.clone())
                    .unwrap(),
            ),
            store.clone(),
        ));
        let service =
            HostedAuthService::enabled(project.into(), owner.clone(), Arc::new(CallbackBrowser));
        let initial = settled(&service).await;
        service
            .handle(LocalRequest::HostedAuthStart(HostedAuthStartParams {
                operation_id: generation(),
                expected_generation: initial.generation,
            }))
            .await
            .unwrap();
        let connected = settled(&service).await;
        assert!(matches!(connected.state, HostedAuthState::Connected {}));
        let expires = owner
            .current_session(now().unwrap())
            .unwrap()
            .unwrap()
            .expires_at();
        tokio::time::timeout(std::time::Duration::from_secs(8), async {
            while now().unwrap() < expires {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        let expired = settled(&service).await;
        assert!(matches!(
            expired.state,
            HostedAuthState::Failed {
                reason: HostedAuthFailure::Expired
            }
        ));
        assert!(http.refreshes.load(Ordering::SeqCst) > 0);
        assert!(
            owner.current_session(expires - 1).unwrap().is_none(),
            "clock rollback must not revive an expired transport session"
        );
        assert!(store.load().unwrap().is_some());
        http.fail_refresh.store(false, Ordering::SeqCst);
        tokio::time::timeout(std::time::Duration::from_secs(8), async {
            loop {
                let current = settled(&service).await;
                if matches!(current.state, HostedAuthState::Connected {}) {
                    assert_eq!(current.generation, connected.generation);
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        assert!(
            owner
                .current_session(now().unwrap())
                .unwrap()
                .unwrap()
                .expires_at()
                > expires
        );
        service.shutdown().await;
    }
    #[tokio::test]
    async fn late_cancel_preserves_connected_session_and_shutdown_preserves_credentials() {
        let project = "https://example.supabase.co";
        let store = Arc::new(SavedStore::default());
        let owner = Arc::new(HostedSessionOwner::new(
            Arc::new(
                SupabaseAuthClient::with_http_client(
                    project,
                    "publishable-key",
                    Arc::new(AuthHttp::default()),
                )
                .unwrap(),
            ),
            store.clone(),
        ));
        let service =
            HostedAuthService::enabled(project.into(), owner.clone(), Arc::new(CallbackBrowser));
        let initial = settled(&service).await;
        service
            .handle(LocalRequest::HostedAuthStart(HostedAuthStartParams {
                operation_id: generation(),
                expected_generation: initial.generation,
            }))
            .await
            .unwrap();
        let connected = settled(&service).await;
        assert!(matches!(connected.state, HostedAuthState::Connected {}));
        let result = service
            .handle(LocalRequest::HostedAuthCancel(HostedAuthGenerationParams {
                generation: connected.generation,
            }))
            .await
            .unwrap();
        assert_eq!(result, LocalResult::HostedAuth { status: connected });
        assert!(owner.current_session(now().unwrap()).unwrap().is_some());
        assert!(store.load().unwrap().is_some());
        service.shutdown().await;
        assert!(owner.current_session(now().unwrap()).unwrap().is_none());
        assert!(store.load().unwrap().is_some());
    }
    #[tokio::test]
    async fn stale_controls_and_duplicate_start_cannot_change_a_newer_attempt() {
        let project = "https://example.supabase.co";
        let owner = Arc::new(HostedSessionOwner::new(
            Arc::new(
                SupabaseAuthClient::with_http_client(project, "publishable-key", Arc::new(Http))
                    .unwrap(),
            ),
            Arc::new(Store),
        ));
        let browser = Arc::new(Browser(AtomicUsize::new(0)));
        let service = HostedAuthService::enabled(project.into(), owner, browser.clone());
        let initial = settled(&service).await;
        assert!(matches!(initial.state, HostedAuthState::SignedOut { .. }));
        let params = HostedAuthStartParams {
            operation_id: generation(),
            expected_generation: initial.generation,
        };
        service
            .handle(LocalRequest::HostedAuthStart(params.clone()))
            .await
            .unwrap();
        let failed = settled(&service).await;
        assert!(matches!(
            failed.state,
            HostedAuthState::Failed {
                reason: HostedAuthFailure::Unavailable
            }
        ));
        service
            .handle(LocalRequest::HostedAuthStart(params.clone()))
            .await
            .unwrap();
        assert_eq!(browser.0.load(Ordering::SeqCst), 1);
        let stale = service
            .handle(LocalRequest::HostedAuthLogout(HostedAuthGenerationParams {
                generation: initial.generation,
            }))
            .await
            .unwrap_err();
        assert_eq!(stale.code, ErrorCode::RevisionConflict);
        service
            .handle(LocalRequest::HostedAuthLogout(HostedAuthGenerationParams {
                generation: params.operation_id,
            }))
            .await
            .unwrap();
        let out = settled(&service).await;
        assert!(matches!(out.state, HostedAuthState::SignedOut { .. }));
        assert_ne!(out.generation, params.operation_id);
        service.shutdown().await;
        assert_eq!(
            service
                .handle(LocalRequest::HostedAuthStatus(EmptyParams {}))
                .await
                .unwrap_err()
                .code,
            ErrorCode::Canceled
        );
    }
}
