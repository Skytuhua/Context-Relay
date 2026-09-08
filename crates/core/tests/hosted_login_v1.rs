use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use context_relay_core::auth::PendingLogin;
use reqwest::Url;
use sha2::{Digest, Sha256};

fn callback(authorization: &Url) -> Url {
    let redirect = authorization
        .query_pairs()
        .find(|(key, _)| key == "redirect_to")
        .unwrap()
        .1
        .into_owned();
    let mut callback = Url::parse(&redirect).unwrap();
    callback
        .query_pairs_mut()
        .append_pair("code", "synthetic-code");
    callback
}

#[test]
fn login_requires_its_original_callback_and_consumes_it_once() {
    let now = Instant::now();
    let address: SocketAddr = "127.0.0.1:41783".parse().unwrap();
    let mut first = PendingLogin::new("https://example.supabase.co", address, now).unwrap();
    let second = PendingLogin::new("https://example.supabase.co", address, now).unwrap();
    let authorization = first.authorization_url();
    assert_eq!(
        authorization.origin().ascii_serialization(),
        "https://example.supabase.co"
    );
    assert_eq!(authorization.path(), "/auth/v1/authorize");
    assert!(
        authorization
            .query_pairs()
            .any(|(key, value)| key == "provider" && value == "github")
    );
    assert!(
        authorization
            .query_pairs()
            .any(|(key, value)| key == "code_challenge_method" && value == "s256")
    );
    assert!(!authorization.as_str().contains("code_verifier"));
    assert!(!format!("{first:?}").contains(authorization.as_str()));

    // A callback for another attempt must not consume this attempt.
    assert!(
        first
            .take_callback(&callback(&second.authorization_url()), now)
            .is_err()
    );
    let valid = callback(&authorization);
    for changed in [
        valid.as_str().replace("127.0.0.1", "localhost"),
        valid.as_str().replace("41783", "41784"),
        format!("{}&code=second-code", valid.as_str()),
        format!("{}#access_token=unexpected", valid.as_str()),
        valid.as_str().replace("synthetic-code", ""),
        format!("{}&state=another-state", valid.as_str()),
    ] {
        assert!(
            first
                .take_callback(&Url::parse(&changed).unwrap(), now)
                .is_err()
        );
    }
    let exchange = first.take_callback(&valid, now).unwrap();
    assert!(!format!("{exchange:?}").contains("synthetic-code"));
    let body = exchange.into_body().unwrap();
    let wire: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(wire["auth_code"], "synthetic-code");
    let verifier = wire["code_verifier"].as_str().unwrap();
    assert_eq!(verifier.len(), 43);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    assert!(
        authorization
            .query_pairs()
            .any(|(key, value)| key == "code_challenge" && value == challenge)
    );
    assert!(first.take_callback(&valid, now).is_err());
}

#[test]
fn expired_login_and_untrusted_endpoints_are_rejected() {
    let now = Instant::now();
    let address = "127.0.0.1:41783".parse().unwrap();
    let mut attempt = PendingLogin::new("https://example.supabase.co", address, now).unwrap();
    let valid = callback(&attempt.authorization_url());
    assert!(
        attempt
            .take_callback(&valid, now + Duration::from_secs(300))
            .is_err()
    );
    for project in [
        "http://example.supabase.co",
        "https://user@example.supabase.co",
        "https://example.supabase.co/path",
        "https://example.supabase.co?x=y",
    ] {
        assert!(PendingLogin::new(project, address, now).is_err());
    }
    for address in ["0.0.0.0:41783", "192.0.2.1:41783", "127.0.0.1:0"] {
        assert!(
            PendingLogin::new("https://example.supabase.co", address.parse().unwrap(), now)
                .is_err()
        );
    }
}
