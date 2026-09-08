use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};

use context_relay_core::{
    devices::{
        account_lifecycle::{AccountLifecycleTransport, AccountLifecycleTransportError},
        supabase_account_lifecycle::SupabaseAccountLifecycleTransport,
    },
    sync::{
        SupabaseHttpClient, SupabaseHttpError, SupabaseHttpMethod, SupabaseHttpRequest,
        SupabaseHttpResponse, SupabaseRetryRuntime, SupabaseTransportConfig,
    },
};
use context_relay_protocol::{AccountDeletionState, WorkspaceId};

const WORKSPACE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07a101";
const ACCESS_TOKEN: &str = "task17-access-token-canary";
const PUBLISHABLE_KEY: &str = "task17-publishable-key-canary";
const SEVEN_DAYS_MS: u64 = 7 * 24 * 60 * 60 * 1_000;

#[derive(Default)]
struct TestHttp {
    requests: Mutex<Vec<SupabaseHttpRequest>>,
    responses: Mutex<VecDeque<Result<SupabaseHttpResponse, SupabaseHttpError>>>,
}

impl TestHttp {
    fn push(&self, status: u16, body: &str) {
        self.responses
            .lock()
            .unwrap()
            .push_back(Ok(SupabaseHttpResponse::new(
                status,
                body.as_bytes().to_vec(),
            )));
    }

    fn requests(&self) -> Vec<SupabaseHttpRequest> {
        self.requests.lock().unwrap().clone()
    }
}

impl SupabaseHttpClient for TestHttp {
    fn execute(
        &self,
        request: SupabaseHttpRequest,
    ) -> Result<SupabaseHttpResponse, SupabaseHttpError> {
        self.requests.lock().unwrap().push(request);
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Err(SupabaseHttpError::Transient))
    }
}

#[derive(Default)]
struct TestRetry {
    delays: Mutex<Vec<Duration>>,
}

impl SupabaseRetryRuntime for TestRetry {
    fn random_u64(&self, _attempt: u32) -> u64 {
        0
    }

    fn sleep(&self, delay: Duration) {
        self.delays.lock().unwrap().push(delay);
    }
}

#[test]
fn hosted_deletion_is_session_bound_exact_and_idempotently_retryable() {
    let http = Arc::new(TestHttp::default());
    let retry = Arc::new(TestRetry::default());
    http.push(
        200,
        r#"{"v":1,"state":"active","requestedAtMs":null,"purgeDeadlineMs":null}"#,
    );
    http.push(503, r#"{"v":1,"error":"transient"}"#);
    http.push(
        200,
        &format!(
            r#"{{"v":1,"state":"pending_delete","requestedAtMs":"1000","purgeDeadlineMs":"{}"}}"#,
            1_000 + SEVEN_DAYS_MS
        ),
    );
    http.push(
        200,
        r#"{"v":1,"state":"active","requestedAtMs":null,"purgeDeadlineMs":null}"#,
    );
    let config =
        SupabaseTransportConfig::new("https://example.supabase.co", PUBLISHABLE_KEY, ACCESS_TOKEN)
            .unwrap();
    let transport = SupabaseAccountLifecycleTransport::with_http_client_and_retry_runtime(
        config,
        WORKSPACE_ID.parse::<WorkspaceId>().unwrap(),
        http.clone(),
        retry.clone(),
    )
    .unwrap();

    assert_eq!(
        transport.deletion_status().unwrap().state,
        AccountDeletionState::Active
    );
    let pending = transport.begin_deletion().unwrap();
    assert_eq!(pending.state, AccountDeletionState::PendingDelete);
    assert_eq!(pending.requested_at_ms, Some(1_000));
    assert_eq!(pending.purge_deadline_ms, Some(1_000 + SEVEN_DAYS_MS));
    assert!(pending.export_available());
    assert_eq!(
        transport.cancel_deletion().unwrap().state,
        AccountDeletionState::Active
    );

    let requests = http.requests();
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[0].method(), SupabaseHttpMethod::Post);
    assert_eq!(
        requests[0].url(),
        "https://example.supabase.co/functions/v1/account-lifecycle"
    );
    let authorization = format!("Bearer {ACCESS_TOKEN}");
    for request in &requests {
        assert_eq!(
            request.header("authorization"),
            Some(authorization.as_str())
        );
        assert_eq!(request.header("apikey"), Some(PUBLISHABLE_KEY));
        assert!(request.timeout() <= Duration::from_secs(15));
        let body = std::str::from_utf8(request.body()).unwrap();
        assert!(body.contains(WORKSPACE_ID));
        assert!(!body.contains("accountId"));
        assert!(!body.contains("sessionId"));
    }
    assert_eq!(requests[1].body(), requests[2].body());
    assert_eq!(retry.delays.lock().unwrap().len(), 1);
    assert_eq!(
        std::str::from_utf8(requests[0].body()).unwrap(),
        format!(r#"{{"v":1,"action":"status","workspaceId":"{WORKSPACE_ID}"}}"#)
    );
    let begin: serde_json::Value = serde_json::from_slice(requests[1].body()).unwrap();
    let cancel: serde_json::Value = serde_json::from_slice(requests[3].body()).unwrap();
    assert_eq!(begin["action"], "begin_deletion");
    assert_eq!(cancel["action"], "cancel_deletion");
    for body in [&begin, &cancel] {
        let request_id = body["requestId"]
            .as_str()
            .expect("mutations need a durable request ID");
        assert_eq!(request_id.len(), 64);
        assert!(
            request_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
    }
    assert_ne!(begin["requestId"], cancel["requestId"]);
}

#[test]
fn hosted_deletion_rejects_forged_projections_and_sanitizes_provider_errors() {
    let http = Arc::new(TestHttp::default());
    http.push(
        200,
        r#"{"v":1,"state":"pending_delete","requestedAtMs":"1000","purgeDeadlineMs":"1001"}"#,
    );
    http.push(401, r#"{"v":1,"error":"auth_required"}"#);
    let config =
        SupabaseTransportConfig::new("https://example.supabase.co", PUBLISHABLE_KEY, ACCESS_TOKEN)
            .unwrap();
    let transport = SupabaseAccountLifecycleTransport::with_http_client(
        config,
        WORKSPACE_ID.parse::<WorkspaceId>().unwrap(),
        http,
    )
    .unwrap();

    assert_eq!(
        transport.deletion_status(),
        Err(AccountLifecycleTransportError::Conflict)
    );
    assert_eq!(
        transport.deletion_status(),
        Err(AccountLifecycleTransportError::Unauthorized)
    );
    let debug = format!("{transport:?}");
    assert!(!debug.contains(ACCESS_TOKEN));
    assert!(!debug.contains(PUBLISHABLE_KEY));
}
