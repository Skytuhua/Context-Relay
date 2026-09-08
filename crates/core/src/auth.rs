//! Daemon-owned GitHub PKCE attempts. This does not enroll a trusted device.

use std::{
    fmt,
    net::SocketAddr,
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_core::{OsRng, RngCore};
use reqwest::Url;
use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LoginError {
    #[error("login configuration is invalid")]
    Configuration,
    #[error("login randomness is unavailable")]
    Random,
    #[error("login callback is invalid")]
    Callback,
    #[error("login attempt expired")]
    Expired,
}

pub struct PendingLogin {
    authorization: Url,
    callback: Url,
    state: String,
    verifier: Option<Zeroizing<String>>,
    created_at: Instant,
    expires_at: Instant,
}

impl fmt::Debug for PendingLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PendingLogin([REDACTED])")
    }
}

/// Secret exchange material; send only to the configured HTTPS Auth endpoint.
pub struct LoginExchange {
    code: Zeroizing<String>,
    verifier: Zeroizing<String>,
}

impl fmt::Debug for LoginExchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LoginExchange([REDACTED])")
    }
}

impl LoginExchange {
    pub fn into_body(self) -> Result<Zeroizing<Vec<u8>>, LoginError> {
        #[derive(Serialize)]
        struct Body<'a> {
            auth_code: &'a str,
            code_verifier: &'a str,
        }
        serde_json::to_vec(&Body {
            auth_code: &self.code,
            code_verifier: &self.verifier,
        })
        .map(Zeroizing::new)
        .map_err(|_| LoginError::Callback)
    }
}

impl PendingLogin {
    /// The daemon must bind this loopback address before opening the returned URL.
    pub fn new(project: &str, address: SocketAddr, now: Instant) -> Result<Self, LoginError> {
        let mut authorization = crate::sync::supabase::validated_project_url(project)
            .map_err(|_| LoginError::Configuration)?;
        if !address.ip().is_loopback() || address.port() == 0 {
            return Err(LoginError::Configuration);
        }
        let verifier = random_value()?;
        let state = random_value()?;
        let callback = Url::parse(&format!("http://{address}/auth/callback"))
            .map_err(|_| LoginError::Configuration)?;
        let mut redirect = callback.clone();
        redirect.query_pairs_mut().append_pair("state", &state);
        authorization.set_path("/auth/v1/authorize");
        authorization
            .query_pairs_mut()
            .append_pair("provider", "github")
            .append_pair("redirect_to", redirect.as_str())
            .append_pair("code_challenge", &challenge(&verifier))
            .append_pair("code_challenge_method", "s256");
        Ok(Self {
            authorization,
            callback,
            state: state.to_string(),
            verifier: Some(verifier),
            created_at: now,
            expires_at: now
                .checked_add(Duration::from_secs(300))
                .ok_or(LoginError::Configuration)?,
        })
    }

    pub fn authorization_url(&self) -> Url {
        self.authorization.clone()
    }

    pub fn take_callback(&mut self, url: &Url, now: Instant) -> Result<LoginExchange, LoginError> {
        if now >= self.expires_at {
            self.verifier = None;
            return Err(LoginError::Expired);
        }
        if now < self.created_at || url.as_str().len() > 4096 || url.fragment().is_some() {
            return Err(LoginError::Callback);
        }
        let mut base = url.clone();
        base.set_query(None);
        if base != self.callback {
            return Err(LoginError::Callback);
        }
        let mut state = None;
        let mut code = None;
        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "state" if state.is_none() => state = Some(value),
                "code" if code.is_none() => code = Some(value),
                _ => return Err(LoginError::Callback),
            }
        }
        if state.as_deref() != Some(self.state.as_str()) {
            return Err(LoginError::Callback);
        }
        let code = code.ok_or(LoginError::Callback)?;
        if code.is_empty() || code.len() > 1024 || !code.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(LoginError::Callback);
        }
        Ok(LoginExchange {
            code: Zeroizing::new(code.into_owned()),
            verifier: self.verifier.take().ok_or(LoginError::Callback)?,
        })
    }
}

fn random_value() -> Result<Zeroizing<String>, LoginError> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    OsRng
        .try_fill_bytes(bytes.as_mut())
        .map_err(|_| LoginError::Random)?;
    Ok(Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_ref())))
}

fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn rfc7636_s256_vector() {
        assert_eq!(
            super::challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }
}
