#![cfg(feature = "test-support")]
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use context_relay_contextd::hosted_login::DaemonLogin;
use context_relay_core::{
    auth::{HostedSessionOwner, LoginError, LoginStore, StoredLogin, SupabaseAuthClient},
    sync::{SupabaseHttpClient, SupabaseHttpError, SupabaseHttpRequest, SupabaseHttpResponse},
};
use serde_json::json;
use std::{
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PROJECT: &str = "https://example.supabase.co";
const USER: &str = "550e8400-e29b-41d4-a716-446655440000";
struct Store {
    value: Mutex<Option<StoredLogin>>,
    clears: tokio::sync::mpsc::UnboundedSender<()>,
}
impl LoginStore for Store {
    fn load(&self) -> Result<Option<StoredLogin>, LoginError> {
        Ok(self.value.lock().unwrap().clone())
    }
    fn save(&self, value: &StoredLogin) -> Result<(), LoginError> {
        *self.value.lock().unwrap() = Some(value.clone());
        Ok(())
    }
    fn clear(&self) -> Result<(), LoginError> {
        *self.value.lock().unwrap() = None;
        let _ = self.clears.send(());
        Ok(())
    }
}
#[derive(Default)]
struct Http {
    gate: Mutex<
        Option<(
            tokio::sync::oneshot::Sender<()>,
            std::sync::mpsc::Receiver<()>,
        )>,
    >,
}
impl SupabaseHttpClient for Http {
    fn execute(
        &self,
        request: SupabaseHttpRequest,
    ) -> Result<SupabaseHttpResponse, SupabaseHttpError> {
        let body = if request.url().ends_with("/user") {
            json!({"id":USER})
        } else {
            if let Some((started, release)) = self.gate.lock().unwrap().take() {
                started.send(()).unwrap();
                release
                    .recv_timeout(std::time::Duration::from_secs(10))
                    .unwrap();
            }
            assert!(request.url().ends_with("grant_type=pkce"));
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let claims = json!({"iss":format!("{PROJECT}/auth/v1"),"aud":"authenticated","sub":USER,"session_id":"550e8400-e29b-41d4-a716-446655440001","exp":now+900});
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
fn fixture() -> (
    Arc<HostedSessionOwner>,
    Arc<Store>,
    tokio::sync::mpsc::UnboundedReceiver<()>,
) {
    fixture_with_http(Arc::new(Http::default()))
}
fn fixture_with_http(
    http: Arc<Http>,
) -> (
    Arc<HostedSessionOwner>,
    Arc<Store>,
    tokio::sync::mpsc::UnboundedReceiver<()>,
) {
    let (clears, rx) = tokio::sync::mpsc::unbounded_channel();
    let store = Arc::new(Store {
        value: Mutex::new(None),
        clears,
    });
    let client = SupabaseAuthClient::with_http_client(PROJECT, "publishable-key", http).unwrap();
    (
        Arc::new(HostedSessionOwner::new(Arc::new(client), store.clone())),
        store,
        rx,
    )
}
fn callback(flow: &DaemonLogin) -> reqwest::Url {
    let auth = flow.authorization_url().unwrap();
    let redirect = auth
        .query_pairs()
        .find(|(key, _)| key == "redirect_to")
        .unwrap()
        .1
        .into_owned();
    reqwest::Url::parse(&redirect).unwrap()
}

#[tokio::test]
async fn loopback_completion_exchanges_and_persists_before_returning_identity() {
    let (owner, store, _) = fixture();
    let flow = DaemonLogin::begin(PROJECT, owner.clone()).await.unwrap();
    let callback = callback(&flow);
    let address = format!("127.0.0.1:{}", callback.port().unwrap());
    let worker = tokio::spawn(flow.wait());
    let mut stream = tokio::net::TcpStream::connect(&address).await.unwrap();
    stream
        .write_all(
            format!(
                "GET {}?{}&code=synthetic-code HTTP/1.1\r\nHost: {address}\r\n\r\n",
                callback.path(),
                callback.query().unwrap()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    assert!(response.starts_with("HTTP/1.1 200"));
    let identity = worker.await.unwrap().unwrap();
    assert_eq!(identity.user_id.to_string(), USER);
    assert!(store.value.lock().unwrap().is_some());
    assert!(
        owner
            .current_session(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            )
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn dropping_flow_closes_listener_and_cleans_only_its_attempt() {
    let (owner, store, mut clears) = fixture();
    let flow = DaemonLogin::begin(PROJECT, owner.clone()).await.unwrap();
    clears.recv().await.unwrap();
    let callback = callback(&flow);
    drop(flow);
    tokio::time::timeout(std::time::Duration::from_secs(5), clears.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(
        tokio::net::TcpStream::connect(("127.0.0.1", callback.port().unwrap()))
            .await
            .is_err()
    );
    assert!(store.value.lock().unwrap().is_none());
    let next = DaemonLogin::begin(PROJECT, owner).await.unwrap();
    next.cancel().await.unwrap();
}

#[test]
fn aborting_wait_during_exchange_withdraws_and_cleans_the_attempt() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let http = Arc::new(Http {
        gate: Mutex::new(Some((started_tx, release_rx))),
    });
    let (owner, store, mut clears) = fixture_with_http(http);
    runtime.block_on(async {
        let flow = DaemonLogin::begin(PROJECT, owner.clone()).await.unwrap();
        clears.recv().await.unwrap();
        let callback = callback(&flow);
        let address = format!("127.0.0.1:{}", callback.port().unwrap());
        let worker = tokio::spawn(flow.wait());
        let mut stream = tokio::net::TcpStream::connect(&address).await.unwrap();
        stream
            .write_all(
                format!(
                    "GET {}?{}&code=synthetic-code HTTP/1.1\r\nHost: {address}\r\n\r\n",
                    callback.path(),
                    callback.query().unwrap()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), started_rx)
            .await
            .unwrap()
            .unwrap();
        worker.abort();
        assert!(matches!(worker.await, Err(error) if error.is_cancelled()));
        tokio::time::timeout(std::time::Duration::from_secs(5), clears.recv())
            .await
            .unwrap()
            .unwrap();
        release_tx.send(()).unwrap();
    });
    // Drain the detached exchange before asserting that it could not publish late.
    drop(runtime);
    assert!(store.value.lock().unwrap().is_none());
    assert!(owner.current_session(0).unwrap().is_none());
}

#[test]
fn dropping_queued_begin_does_not_invalidate_a_newer_attempt() {
    use std::{future::Future, task::Poll};
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    let (owner, _, _) = fixture();
    let newer = runtime.block_on(async {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            started_tx.send(()).unwrap();
            release_rx
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap();
        });
        started_rx.await.unwrap();
        let mut pending = Box::pin(DaemonLogin::begin(PROJECT, owner.clone()));
        std::future::poll_fn(|cx| {
            assert!(pending.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(pending);
        let newer = owner.begin_login().unwrap();
        release_tx.send(()).unwrap();
        blocker.await.unwrap();
        newer
    });
    // Runtime shutdown drains detached blocking work before testing the new generation.
    drop(runtime);
    let now = std::time::Instant::now();
    let mut login = context_relay_core::auth::PendingLogin::new(
        PROJECT,
        "127.0.0.1:41783".parse().unwrap(),
        now,
    )
    .unwrap();
    let auth = login.authorization_url();
    let redirect = auth
        .query_pairs()
        .find(|(key, _)| key == "redirect_to")
        .unwrap()
        .1
        .into_owned();
    let mut callback = reqwest::Url::parse(&redirect).unwrap();
    callback
        .query_pairs_mut()
        .append_pair("code", "synthetic-code");
    let exchange = login.take_callback(&callback, now).unwrap();
    owner
        .complete_login(
            newer,
            exchange,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
}
