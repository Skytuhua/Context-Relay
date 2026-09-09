use std::{fmt, sync::Arc, time::Duration};

use context_relay_protocol::{AccountDeletionState, OperationId, WorkspaceId};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    auth::{HostedIdentity, HostedSession, HostedSessionOwner, LoginCancellation},
    devices::account_lifecycle::{
        AccountDeletionProjection, AccountLifecycleTransport, AccountLifecycleTransportError,
    },
    sync::{BackoffPolicy, SupabaseTransportConfig},
};

use crate::sync::supabase::{
    ReqwestHttpClient, SupabaseHttpClient, SupabaseHttpError, SupabaseHttpMethod,
    SupabaseHttpRequest, SupabaseHttpResponse, SupabaseRetryRuntime,
};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_ATTEMPTS: usize = 3;
const MAX_RESPONSE_BYTES: usize = 16 * 1024;

struct SystemRetryRuntime;

impl SupabaseRetryRuntime for SystemRetryRuntime {
    fn random_u64(&self, _attempt: u32) -> u64 {
        let mut bytes = [0_u8; 8];
        let mut random = OsRng;
        if random.try_fill_bytes(&mut bytes).is_err() {
            return 0;
        }
        u64::from_le_bytes(bytes)
    }

    fn sleep(&self, delay: Duration) {
        std::thread::sleep(delay);
    }
}

pub struct SupabaseAccountLifecycleTransport {
    config: SupabaseTransportConfig,
    workspace_id: WorkspaceId,
    http: Arc<dyn SupabaseHttpClient>,
    retry_runtime: Arc<dyn SupabaseRetryRuntime>,
    hosted: Option<HostedAuthority>,
}

struct HostedAuthority {
    owner: Arc<HostedSessionOwner>,
    identity: HostedIdentity,
    generation: LoginCancellation,
}

impl fmt::Debug for SupabaseAccountLifecycleTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SupabaseAccountLifecycleTransport")
            .field("project_url", &self.config.project_url().as_str())
            .field("workspace_id", &self.workspace_id)
            .field("publishable_key", &"[REDACTED]")
            .field("access_token", &"[REDACTED]")
            .finish()
    }
}

impl SupabaseAccountLifecycleTransport {
    pub fn new(
        config: SupabaseTransportConfig,
        workspace_id: WorkspaceId,
    ) -> Result<Self, AccountLifecycleTransportError> {
        let http = Arc::new(
            ReqwestHttpClient::new().map_err(|_| AccountLifecycleTransportError::Invalid)?,
        );
        Ok(Self {
            config,
            workspace_id,
            http,
            retry_runtime: Arc::new(SystemRetryRuntime),
            hosted: None,
        })
    }

    #[cfg(feature = "test-support")]
    pub fn with_http_client(
        config: SupabaseTransportConfig,
        workspace_id: WorkspaceId,
        http: Arc<dyn SupabaseHttpClient>,
    ) -> Result<Self, AccountLifecycleTransportError> {
        Ok(Self {
            config,
            workspace_id,
            http,
            retry_runtime: Arc::new(SystemRetryRuntime),
            hosted: None,
        })
    }

    #[cfg(feature = "test-support")]
    pub fn with_http_client_and_retry_runtime(
        config: SupabaseTransportConfig,
        workspace_id: WorkspaceId,
        http: Arc<dyn SupabaseHttpClient>,
        retry_runtime: Arc<dyn SupabaseRetryRuntime>,
    ) -> Result<Self, AccountLifecycleTransportError> {
        Ok(Self {
            config,
            workspace_id,
            http,
            retry_runtime,
            hosted: None,
        })
    }

    /// Bind every dispatch and response to the original daemon-owned login.
    /// The current session supplies the token, including after a valid refresh.
    pub fn with_session_owner(
        mut self,
        owner: Arc<HostedSessionOwner>,
        identity: HostedIdentity,
        generation: LoginCancellation,
    ) -> Self {
        self.hosted = Some(HostedAuthority {
            owner,
            identity,
            generation,
        });
        self
    }

    fn session(
        &self,
        now: u64,
    ) -> Result<Option<Arc<HostedSession>>, AccountLifecycleTransportError> {
        self.hosted
            .as_ref()
            .map(|authority| {
                let session = authority
                    .owner
                    .session_for(&authority.generation, authority.identity, now)
                    .map_err(|_| AccountLifecycleTransportError::Unauthorized)?;
                if session.project_url() != self.config.project_url() {
                    return Err(AccountLifecycleTransportError::Unauthorized);
                }
                Ok(session)
            })
            .transpose()
    }

    fn endpoint(&self) -> Result<String, AccountLifecycleTransportError> {
        self.config
            .project_url()
            .join("/functions/v1/account-lifecycle")
            .map(String::from)
            .map_err(|_| AccountLifecycleTransportError::Invalid)
    }

    fn call(
        &self,
        action: AccountLifecycleAction,
        operation_id: Option<OperationId>,
    ) -> Result<AccountDeletionProjection, AccountLifecycleTransportError> {
        let body = serde_json::to_vec(&AccountLifecycleRequest {
            v: 1,
            action,
            workspace_id: self.workspace_id,
            // Keep one identity across retries and transport recreation. Excluding
            // the action preserves the server's bound-receipt conflict check.
            request_id: operation_id.map(|id| {
                format!(
                    "{:x}",
                    Sha256::new()
                        .chain_update(b"context-relay/account-lifecycle-request/v1\0")
                        .chain_update(id.as_bytes())
                        .finalize()
                )
            }),
        })
        .map_err(|_| AccountLifecycleTransportError::Invalid)?;
        let response = self.execute(body)?;
        let response: AccountLifecycleResponse = serde_json::from_slice(response.body())
            .map_err(|_| AccountLifecycleTransportError::Conflict)?;
        if response.v != 1 {
            return Err(AccountLifecycleTransportError::Conflict);
        }
        let projection = AccountDeletionProjection {
            state: response.state,
            requested_at_ms: parse_optional_ms(response.requested_at_ms)?,
            purge_deadline_ms: parse_optional_ms(response.purge_deadline_ms)?,
        };
        projection.validate()?;
        Ok(projection)
    }

    fn execute(
        &self,
        body: Vec<u8>,
    ) -> Result<SupabaseHttpResponse, AccountLifecycleTransportError> {
        use super::recovery::{RecoveryEnrollmentClock, SystemRecoveryEnrollmentClock};
        let now = SystemRecoveryEnrollmentClock.now_ms() / 1000;
        let started = std::time::Instant::now();
        for attempt in 0..MAX_ATTEMPTS {
            let session = self.session(now.saturating_add(started.elapsed().as_secs()))?;
            let request = SupabaseHttpRequest::new(
                SupabaseHttpMethod::Post,
                self.endpoint()?,
                vec![
                    (
                        "authorization".to_owned(),
                        format!(
                            "Bearer {}",
                            session.as_ref().map_or_else(
                                || self.config.access_token(),
                                |session| session.access_token()
                            )
                        ),
                    ),
                    (
                        "apikey".to_owned(),
                        self.config.publishable_key().to_owned(),
                    ),
                    ("content-type".to_owned(), "application/json".to_owned()),
                    ("accept".to_owned(), "application/json".to_owned()),
                ],
                REQUEST_TIMEOUT,
                body.clone(),
            )
            .with_response_limit(MAX_RESPONSE_BYTES);
            let response = self.http.execute(request);
            self.session(now.saturating_add(started.elapsed().as_secs()))?;
            let response = match response {
                Ok(response) => response,
                Err(error) => {
                    let error = match error {
                        SupabaseHttpError::Configuration => AccountLifecycleTransportError::Invalid,
                        SupabaseHttpError::Offline
                        | SupabaseHttpError::Transient
                        | SupabaseHttpError::ResponseTooLarge => {
                            AccountLifecycleTransportError::Transient
                        }
                    };
                    if error == AccountLifecycleTransportError::Transient
                        && attempt + 1 < MAX_ATTEMPTS
                    {
                        self.sleep_before_retry(attempt);
                        continue;
                    }
                    return Err(error);
                }
            };
            if response.body().len() > MAX_RESPONSE_BYTES {
                return Err(AccountLifecycleTransportError::Conflict);
            }
            if (200..300).contains(&response.status()) {
                return Ok(response);
            }
            let error = response_error(response.status(), response.body());
            if error == AccountLifecycleTransportError::Transient && attempt + 1 < MAX_ATTEMPTS {
                self.sleep_before_retry(attempt);
                continue;
            }
            return Err(error);
        }
        Err(AccountLifecycleTransportError::Transient)
    }

    fn sleep_before_retry(&self, attempt: usize) {
        let attempt = u32::try_from(attempt).unwrap_or(u32::MAX);
        let random = self.retry_runtime.random_u64(attempt);
        let delay_ms = BackoffPolicy::DEFAULT.next_delay(attempt, random);
        self.retry_runtime.sleep(Duration::from_millis(delay_ms));
    }
}

impl AccountLifecycleTransport for SupabaseAccountLifecycleTransport {
    fn deletion_status(&self) -> Result<AccountDeletionProjection, AccountLifecycleTransportError> {
        self.call(AccountLifecycleAction::Status, None)
    }

    fn begin_deletion(
        &self,
        operation_id: OperationId,
    ) -> Result<AccountDeletionProjection, AccountLifecycleTransportError> {
        self.call(AccountLifecycleAction::BeginDeletion, Some(operation_id))
    }

    fn cancel_deletion(
        &self,
        operation_id: OperationId,
    ) -> Result<AccountDeletionProjection, AccountLifecycleTransportError> {
        self.call(AccountLifecycleAction::CancelDeletion, Some(operation_id))
    }
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum AccountLifecycleAction {
    Status,
    BeginDeletion,
    CancelDeletion,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountLifecycleRequest {
    v: u8,
    action: AccountLifecycleAction,
    workspace_id: WorkspaceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AccountLifecycleResponse {
    v: u8,
    state: AccountDeletionState,
    requested_at_ms: Option<String>,
    purge_deadline_ms: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SafeErrorResponse {
    v: u8,
    error: String,
}

fn parse_optional_ms(value: Option<String>) -> Result<Option<u64>, AccountLifecycleTransportError> {
    value
        .map(|value| {
            if value.is_empty()
                || (value.len() > 1 && value.starts_with('0'))
                || !value.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(AccountLifecycleTransportError::Conflict);
            }
            value
                .parse::<u64>()
                .ok()
                .filter(|value| *value <= i64::MAX as u64)
                .ok_or(AccountLifecycleTransportError::Conflict)
        })
        .transpose()
}

fn response_error(status: u16, body: &[u8]) -> AccountLifecycleTransportError {
    let safe = serde_json::from_slice::<SafeErrorResponse>(body).ok();
    let code = safe
        .as_ref()
        .filter(|safe| safe.v == 1)
        .map(|safe| safe.error.as_str());
    match (status, code) {
        (400 | 404 | 405 | 422, _) => AccountLifecycleTransportError::Invalid,
        (401 | 403, _) => AccountLifecycleTransportError::Unauthorized,
        (409, _) => AccountLifecycleTransportError::Conflict,
        (429 | 500..=599, _) => AccountLifecycleTransportError::Transient,
        _ => AccountLifecycleTransportError::Transient,
    }
}
