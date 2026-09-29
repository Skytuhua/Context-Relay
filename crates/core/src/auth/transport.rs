use std::{fmt, sync::Arc, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::Url;
use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{LoginError, LoginExchange, StoredLogin};
use crate::sync::supabase::{
    ReqwestHttpClient, SupabaseHttpClient, SupabaseHttpMethod, SupabaseHttpRequest,
    SupabaseHttpResponse, valid_header_secret, validated_project_url,
};

const MAX_AUTH_RESPONSE: usize = 64 * 1024;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct HostedIdentity {
    pub user_id: Uuid,
    pub session_id: Uuid,
}

/// Verified hosted identity and credentials; this is not device/workspace authorization.
pub struct HostedSession {
    project: Url,
    identity: HostedIdentity,
    expires_at: u64,
    access_token: Zeroizing<String>,
    refresh_token: Zeroizing<String>,
}

impl HostedSession {
    pub fn stored_login(&self) -> StoredLogin {
        StoredLogin {
            project: self.project.clone(),
            identity: self.identity,
            refresh_token: self.refresh_token.clone(),
        }
    }
    pub fn project_url(&self) -> &Url {
        &self.project
    }
    pub const fn identity(&self) -> &HostedIdentity {
        &self.identity
    }
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
    /// For daemon-owned transport and OS credential storage only, never renderer IPC.
    pub fn access_token(&self) -> &str {
        &self.access_token
    }
    /// For daemon-owned refresh and OS credential storage only, never renderer IPC.
    pub fn refresh_token(&self) -> &str {
        &self.refresh_token
    }
}

impl fmt::Debug for HostedSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HostedSession([REDACTED])")
    }
}

pub struct SupabaseAuthClient {
    project: Url,
    publishable_key: Zeroizing<String>,
    http: Arc<dyn SupabaseHttpClient>,
}

impl fmt::Debug for SupabaseAuthClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SupabaseAuthClient([REDACTED])")
    }
}

impl SupabaseAuthClient {
    pub fn new(project: &str, publishable_key: &str) -> Result<Self, LoginError> {
        Self::build(
            project,
            publishable_key,
            Arc::new(ReqwestHttpClient::new().map_err(|_| LoginError::Configuration)?),
        )
    }

    #[cfg(feature = "test-support")]
    pub fn with_http_client(
        project: &str,
        publishable_key: &str,
        http: Arc<dyn SupabaseHttpClient>,
    ) -> Result<Self, LoginError> {
        Self::build(project, publishable_key, http)
    }

    fn build(
        project: &str,
        publishable_key: &str,
        http: Arc<dyn SupabaseHttpClient>,
    ) -> Result<Self, LoginError> {
        if !valid_header_secret(publishable_key) || publishable_key.len() > 4096 {
            return Err(LoginError::Configuration);
        }
        Ok(Self {
            project: validated_project_url(project).map_err(|_| LoginError::Configuration)?,
            publishable_key: Zeroizing::new(publishable_key.to_owned()),
            http,
        })
    }

    /// Do not retry a consumed authorization code automatically after an ambiguous response.
    pub fn exchange(&self, exchange: LoginExchange, now: u64) -> Result<HostedSession, LoginError> {
        if exchange.project != self.project {
            return Err(LoginError::Configuration);
        }
        let mut body = exchange.into_body()?;
        let response = self.request(
            SupabaseHttpMethod::Post,
            "/auth/v1/token?grant_type=pkce",
            std::mem::take(&mut *body),
            None,
            200,
        )?;
        self.verify_tokens(response, now, None)
    }

    /// The caller must persist replacement credentials before publishing them.
    pub fn refresh(&self, session: &HostedSession, now: u64) -> Result<HostedSession, LoginError> {
        if session.project != self.project {
            return Err(LoginError::Configuration);
        }
        self.refresh_credentials(session.refresh_token(), session.identity, now)
    }

    /// Stored credentials are not authenticated state until renewed and verified.
    pub fn restore(&self, stored: &StoredLogin, now: u64) -> Result<HostedSession, LoginError> {
        if stored.project != self.project {
            return Err(LoginError::Configuration);
        }
        self.refresh_credentials(&stored.refresh_token, stored.identity, now)
    }

    fn refresh_credentials(
        &self,
        refresh_token: &str,
        identity: HostedIdentity,
        now: u64,
    ) -> Result<HostedSession, LoginError> {
        #[derive(Serialize)]
        struct Refresh<'a> {
            refresh_token: &'a str,
        }
        let body =
            serde_json::to_vec(&Refresh { refresh_token }).map_err(|_| LoginError::Provider)?;
        let response = self.request(
            SupabaseHttpMethod::Post,
            "/auth/v1/token?grant_type=refresh_token",
            body,
            None,
            200,
        )?;
        self.verify_tokens(response, now, Some(identity))
    }

    /// Remote revocation only; the owner must separately clear local credentials.
    pub fn logout(&self, session: &HostedSession) -> Result<(), LoginError> {
        if session.project != self.project {
            return Err(LoginError::Configuration);
        }
        self.request(
            SupabaseHttpMethod::Post,
            "/auth/v1/logout?scope=local",
            vec![],
            Some(session.access_token()),
            204,
        )?;
        Ok(())
    }

    fn verify_tokens(
        &self,
        response: SupabaseHttpResponse,
        now: u64,
        expected: Option<HostedIdentity>,
    ) -> Result<HostedSession, LoginError> {
        let tokens: TokenResponse =
            serde_json::from_slice(response.body()).map_err(|_| LoginError::Provider)?;
        if !tokens.token_type.eq_ignore_ascii_case("bearer")
            || !valid_header_secret(&tokens.access_token)
            || tokens.access_token.len() > 16384
            || !valid_header_secret(&tokens.refresh_token)
            || tokens.refresh_token.len() > 4096
        {
            return Err(LoginError::Provider);
        }
        // These claims are only metadata until /user authenticates this exact token.
        let claims = claims(&tokens.access_token)?;
        if claims.iss
            != self
                .project
                .join("/auth/v1")
                .map_err(|_| LoginError::Configuration)?
                .as_str()
            || !claims.aud.authenticated()
        {
            return Err(LoginError::Provider);
        }
        if claims.exp <= now {
            return Err(LoginError::Expired);
        }
        if claims.exp - now > 86400 {
            return Err(LoginError::Provider);
        }
        let identity = HostedIdentity {
            user_id: canonical_uuid(&claims.sub)?,
            session_id: canonical_uuid(&claims.session_id)?,
        };
        if expected.is_some_and(|expected| expected != identity) {
            return Err(LoginError::Provider);
        }
        let response = self.request(
            SupabaseHttpMethod::Get,
            "/auth/v1/user",
            vec![],
            Some(&tokens.access_token),
            200,
        )?;
        let user: User =
            serde_json::from_slice(response.body()).map_err(|_| LoginError::Provider)?;
        if canonical_uuid(&user.id)? != identity.user_id {
            return Err(LoginError::Provider);
        }
        Ok(HostedSession {
            project: self.project.clone(),
            identity,
            expires_at: claims.exp,
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
        })
    }

    fn request(
        &self,
        method: SupabaseHttpMethod,
        path: &str,
        body: Vec<u8>,
        token: Option<&str>,
        expected_status: u16,
    ) -> Result<SupabaseHttpResponse, LoginError> {
        let url = self
            .project
            .join(path)
            .map_err(|_| LoginError::Configuration)?;
        let mut headers = vec![
            ("apikey".into(), self.publishable_key.to_string()),
            ("content-type".into(), "application/json".into()),
            ("accept".into(), "application/json".into()),
        ];
        if let Some(token) = token {
            headers.push(("authorization".into(), format!("Bearer {token}")));
        }
        let request =
            SupabaseHttpRequest::new(method, url.into(), headers, Duration::from_secs(15), body)
                .with_response_limit(MAX_AUTH_RESPONSE);
        let response = self
            .http
            .execute(request)
            .map_err(|_| LoginError::Unavailable)?;
        if response.body().len() > MAX_AUTH_RESPONSE {
            return Err(LoginError::Provider);
        }
        match response.status() {
            status if status == expected_status => Ok(response),
            400 | 401 | 403 | 422 => Err(LoginError::Denied),
            _ => Err(LoginError::Unavailable),
        }
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    token_type: String,
    #[serde(deserialize_with = "secret")]
    access_token: Zeroizing<String>,
    #[serde(deserialize_with = "secret")]
    refresh_token: Zeroizing<String>,
}

pub(super) fn secret<'de, D: Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}

#[derive(Deserialize)]
struct User {
    id: String,
}

#[derive(Deserialize)]
struct Claims {
    sub: String,
    session_id: String,
    iss: String,
    aud: Audience,
    exp: u64,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}
impl Audience {
    fn authenticated(&self) -> bool {
        match self {
            Self::One(aud) => aud == "authenticated",
            Self::Many(aud) => aud.iter().any(|aud| aud == "authenticated"),
        }
    }
}

fn claims(token: &str) -> Result<Claims, LoginError> {
    let mut parts = token.split('.');
    let header = parts.next().ok_or(LoginError::Provider)?;
    let payload = parts.next().ok_or(LoginError::Provider)?;
    let signature = parts.next().ok_or(LoginError::Provider)?;
    if header.is_empty() || signature.is_empty() || parts.next().is_some() {
        return Err(LoginError::Provider);
    }
    let payload = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| LoginError::Provider)?,
    );
    serde_json::from_slice(&payload).map_err(|_| LoginError::Provider)
}

pub(super) fn canonical_uuid(value: &str) -> Result<Uuid, LoginError> {
    let id = Uuid::parse_str(value).map_err(|_| LoginError::Provider)?;
    if id.is_nil() || id.to_string() != value {
        return Err(LoginError::Provider);
    }
    Ok(id)
}
