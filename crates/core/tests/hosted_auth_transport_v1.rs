#![cfg(feature = "test-support")]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use context_relay_core::{
    auth::{PendingLogin, SupabaseAuthClient},
    sync::{SupabaseHttpClient, SupabaseHttpError, SupabaseHttpRequest, SupabaseHttpResponse},
};
use serde_json::json;
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Instant,
};

const PROJECT: &str = "https://example.supabase.co";
const USER: &str = "550e8400-e29b-41d4-a716-446655440000";
const SESSION: &str = "550e8400-e29b-41d4-a716-446655440001";
const NOW: u64 = 1_800_000_000;

struct Http {
    responses: Mutex<VecDeque<SupabaseHttpResponse>>,
    requests: Mutex<Vec<SupabaseHttpRequest>>,
}
impl SupabaseHttpClient for Http {
    fn execute(
        &self,
        request: SupabaseHttpRequest,
    ) -> Result<SupabaseHttpResponse, SupabaseHttpError> {
        self.requests.lock().unwrap().push(request);
        Ok(self
            .responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected request"))
    }
}
fn response(status: u16, value: serde_json::Value) -> SupabaseHttpResponse {
    SupabaseHttpResponse::new(status, serde_json::to_vec(&value).unwrap())
}
fn token(exp: u64) -> String {
    token_claims(
        json!({"iss":format!("{PROJECT}/auth/v1"),"aud":"authenticated","sub":USER,"session_id":SESSION,"exp":exp}),
    )
}
fn token_claims(claims: serde_json::Value) -> String {
    format!(
        "{}.{}.synthetic-signature",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256"}"#),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    )
}
fn tokens(access: &str) -> SupabaseHttpResponse {
    response(
        200,
        json!({"token_type":"bearer","access_token":access,"refresh_token":"synthetic-refresh","expires_in":900,"provider_token":"discard-provider-secret"}),
    )
}
fn exchange() -> context_relay_core::auth::LoginExchange {
    let now = Instant::now();
    let mut pending = PendingLogin::new(PROJECT, "127.0.0.1:41783".parse().unwrap(), now).unwrap();
    let auth = pending.authorization_url();
    let redirect = auth
        .query_pairs()
        .find(|(key, _)| key == "redirect_to")
        .unwrap()
        .1
        .into_owned();
    let mut callback = auth.join(&redirect).unwrap();
    callback
        .query_pairs_mut()
        .append_pair("code", "synthetic-code");
    pending.take_callback(&callback, now).unwrap()
}
fn client(project: &str, responses: Vec<SupabaseHttpResponse>) -> (SupabaseAuthClient, Arc<Http>) {
    let http = Arc::new(Http {
        responses: Mutex::new(responses.into()),
        requests: Mutex::new(vec![]),
    });
    (
        SupabaseAuthClient::with_http_client(project, "publishable-key", http.clone()).unwrap(),
        http,
    )
}

#[test]
fn pkce_exchange_checks_hosted_identity_before_returning_a_session() {
    let access = token(NOW + 900);
    let (client, http) = client(
        PROJECT,
        vec![tokens(&access), response(200, json!({"id":USER}))],
    );
    let session = client.exchange(exchange(), NOW).unwrap();
    assert_eq!(session.project_url().as_str(), format!("{PROJECT}/"));
    assert_eq!(session.identity().user_id.to_string(), USER);
    assert_eq!(session.identity().session_id.to_string(), SESSION);
    assert_eq!(session.expires_at(), NOW + 900);
    for secret in [&access, "synthetic-refresh", "discard-provider-secret"] {
        assert!(!format!("{session:?}").contains(secret));
        assert!(!format!("{client:?}").contains(secret));
    }
    let requests = http.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0].url(),
        format!("{PROJECT}/auth/v1/token?grant_type=pkce")
    );
    assert!(requests[0].header("authorization").is_none());
    assert_eq!(requests[0].header("apikey"), Some("publishable-key"));
    let body: serde_json::Value = serde_json::from_slice(requests[0].body()).unwrap();
    assert_eq!(body["auth_code"], "synthetic-code");
    assert_eq!(body["code_verifier"].as_str().unwrap().len(), 43);
    assert_eq!(requests[1].url(), format!("{PROJECT}/auth/v1/user"));
    assert_eq!(
        requests[1].header("authorization"),
        Some(format!("Bearer {access}").as_str())
    );
}

#[test]
fn wrong_project_and_invalid_provider_responses_do_not_establish_a_session() {
    let (wrong, http) = client("https://other.supabase.co", vec![]);
    assert!(wrong.exchange(exchange(), NOW).is_err());
    assert!(http.requests.lock().unwrap().is_empty());
    for responses in [
        vec![response(500, json!({"message":"private-provider-secret"}))],
        vec![tokens("invalid-jwt")],
        vec![tokens(&token(NOW))],
        vec![
            tokens(&token(NOW + 900)),
            response(401, json!({"message":"private-provider-secret"})),
        ],
        vec![
            tokens(&token(NOW + 900)),
            response(200, json!({"id":SESSION})),
        ],
        vec![SupabaseHttpResponse::new(200, vec![b'x'; 65537])],
    ] {
        let (client, _) = client(PROJECT, responses);
        let error = client.exchange(exchange(), NOW).unwrap_err();
        assert!(!format!("{error:?} {error}").contains("private-provider-secret"));
    }
}

#[test]
fn invalid_identity_claims_are_rejected_before_the_user_lookup() {
    for (field, value) in [
        ("iss", json!("https://other.supabase.co/auth/v1")),
        ("aud", json!("anon")),
        ("aud", json!(["anon"])),
        ("session_id", json!("not-a-uuid")),
        ("session_id", json!("00000000-0000-0000-0000-000000000000")),
        ("session_id", serde_json::Value::Null),
        ("sub", json!("not-a-uuid")),
        ("sub", json!("00000000-0000-0000-0000-000000000000")),
        ("sub", serde_json::Value::Null),
        ("exp", json!(NOW + 86401)),
    ] {
        let mut claims = json!({"iss":format!("{PROJECT}/auth/v1"),"aud":"authenticated","sub":USER,"session_id":SESSION,"exp":NOW + 900});
        if value.is_null() {
            claims.as_object_mut().unwrap().remove(field);
        } else {
            claims[field] = value;
        }
        let (client, http) = client(PROJECT, vec![tokens(&token_claims(claims))]);
        assert!(
            client.exchange(exchange(), NOW).is_err(),
            "accepted invalid {field}"
        );
        assert_eq!(http.requests.lock().unwrap().len(), 1);
    }
}

#[test]
fn refresh_preserves_identity_and_logout_revokes_only_that_session() {
    let renewed_access = token(NOW + 1800);
    let (client, http) = client(
        PROJECT,
        vec![
            tokens(&token(NOW + 900)),
            response(200, json!({"id":USER})),
            response(
                200,
                json!({"token_type":"bearer","access_token":renewed_access,"refresh_token":"rotated-refresh"}),
            ),
            response(200, json!({"id":USER})),
            SupabaseHttpResponse::new(204, vec![]),
        ],
    );
    let original = client.exchange(exchange(), NOW).unwrap();
    let renewed = client.refresh(&original, NOW + 900).unwrap();
    assert!(renewed.identity() == original.identity());
    assert_eq!(renewed.refresh_token(), "rotated-refresh");
    assert_eq!(original.refresh_token(), "synthetic-refresh");
    client.logout(&renewed).unwrap();
    let requests = http.requests.lock().unwrap();
    assert_eq!(requests.len(), 5);
    assert_eq!(
        requests[2].url(),
        format!("{PROJECT}/auth/v1/token?grant_type=refresh_token")
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(requests[2].body()).unwrap(),
        json!({"refresh_token":"synthetic-refresh"})
    );
    assert!(requests[2].header("authorization").is_none());
    assert_eq!(
        requests[4].url(),
        format!("{PROJECT}/auth/v1/logout?scope=local")
    );
    assert_eq!(
        requests[4].header("authorization"),
        Some(format!("Bearer {renewed_access}").as_str())
    );
    assert!(requests[4].body().is_empty());
}

#[test]
fn refresh_cannot_change_identity_and_session_operations_cannot_change_project() {
    for field in ["sub", "session_id"] {
        let mut changed = json!({"iss":format!("{PROJECT}/auth/v1"),"aud":"authenticated","sub":USER,"session_id":SESSION,"exp":NOW + 1800});
        changed[field] = json!("550e8400-e29b-41d4-a716-446655440099");
        let (client, http) = client(
            PROJECT,
            vec![
                tokens(&token(NOW + 900)),
                response(200, json!({"id":USER})),
                tokens(&token_claims(changed)),
            ],
        );
        let original = client.exchange(exchange(), NOW).unwrap();
        assert!(client.refresh(&original, NOW + 900).is_err());
        assert_eq!(http.requests.lock().unwrap().len(), 3);
        let (wrong, wrong_http) = self::client("https://other.supabase.co", vec![]);
        assert!(wrong.refresh(&original, NOW).is_err());
        assert!(wrong.logout(&original).is_err());
        assert!(wrong_http.requests.lock().unwrap().is_empty());
    }
}

#[test]
fn failed_refresh_is_not_retried_and_logout_requires_revocation_confirmation() {
    let (client, http) = client(
        PROJECT,
        vec![
            tokens(&token(NOW + 900)),
            response(200, json!({"id":USER})),
            response(500, json!({"message":"private-provider-secret"})),
            response(200, json!({})),
        ],
    );
    let original = client.exchange(exchange(), NOW).unwrap();
    assert!(client.refresh(&original, NOW + 900).is_err());
    assert_eq!(http.requests.lock().unwrap().len(), 3);
    assert_eq!(original.refresh_token(), "synthetic-refresh");
    assert!(client.logout(&original).is_err());
    assert_eq!(http.requests.lock().unwrap().len(), 4);
}

#[test]
fn stored_login_requires_fresh_hosted_verification() {
    let (client, http) = client(
        PROJECT,
        vec![
            tokens(&token(NOW + 900)),
            response(200, json!({"id":USER})),
            tokens(&token(NOW + 1800)),
            response(200, json!({"id":USER})),
        ],
    );
    let session = client.exchange(exchange(), NOW).unwrap();
    let stored = session.stored_login();
    assert!(!format!("{stored:?}").contains("synthetic-refresh"));
    let restored = client.restore(&stored, NOW + 900).unwrap();
    assert!(restored.identity() == session.identity());
    assert_eq!(http.requests.lock().unwrap().len(), 4);
    let (wrong, http) = self::client("https://other.supabase.co", vec![]);
    assert!(wrong.restore(&stored, NOW).is_err());
    assert!(http.requests.lock().unwrap().is_empty());
}
