use super::recovery_transport::RecoveryTransportError;
use crate::{
    auth::{HostedIdentity, HostedSessionOwner, LoginCancellation},
    sync::supabase::{
        ReqwestHttpClient, SupabaseHttpClient, SupabaseHttpMethod, SupabaseHttpRequest,
        valid_header_secret, validated_project_url,
    },
};
use context_relay_protocol::{AccountId, DecimalTimestamp, OperationId, Sha256Digest, WorkspaceId};
use serde::Deserialize;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedEnrollmentReservation {
    pub reservation_id: OperationId,
    pub account_id: AccountId,
    pub workspace_id: WorkspaceId,
    pub nonce: Sha256Digest,
    pub expires_at: DecimalTimestamp,
}

/// Daemon-owned client. Credentials are resolved afresh for each operation and
/// never persisted with the public reservation or passed to renderer IPC.
pub struct HostedEnrollmentClient {
    owner: Arc<HostedSessionOwner>,
    identity: HostedIdentity,
    generation: LoginCancellation,
    project: reqwest::Url,
    publishable_key: Zeroizing<String>,
    http: Arc<dyn SupabaseHttpClient>,
}
impl HostedEnrollmentClient {
    pub fn new(
        owner: Arc<HostedSessionOwner>,
        identity: HostedIdentity,
        generation: LoginCancellation,
        project: &str,
        publishable_key: &str,
    ) -> Result<Self, RecoveryTransportError> {
        let http = Arc::new(ReqwestHttpClient::new().map_err(|_| RecoveryTransportError::Invalid)?);
        Self::build(owner, identity, generation, project, publishable_key, http)
    }
    #[cfg(feature = "test-support")]
    pub fn with_http_client(
        owner: Arc<HostedSessionOwner>,
        identity: HostedIdentity,
        generation: LoginCancellation,
        project: &str,
        publishable_key: &str,
        http: Arc<dyn SupabaseHttpClient>,
    ) -> Result<Self, RecoveryTransportError> {
        Self::build(owner, identity, generation, project, publishable_key, http)
    }
    fn build(
        owner: Arc<HostedSessionOwner>,
        identity: HostedIdentity,
        generation: LoginCancellation,
        project: &str,
        publishable_key: &str,
        http: Arc<dyn SupabaseHttpClient>,
    ) -> Result<Self, RecoveryTransportError> {
        if !valid_header_secret(publishable_key) || publishable_key.len() > 4096 {
            return Err(RecoveryTransportError::Invalid);
        }
        Ok(Self {
            owner,
            identity,
            generation,
            project: validated_project_url(project).map_err(|_| RecoveryTransportError::Invalid)?,
            publishable_key: Zeroizing::new(publishable_key.to_owned()),
            http,
        })
    }
    pub fn reserve(
        &self,
        operation: OperationId,
        now: u64,
    ) -> Result<HostedEnrollmentReservation, RecoveryTransportError> {
        let started = Instant::now();
        let session = self
            .owner
            .session_for(&self.generation, self.identity, now)
            .map_err(|_| RecoveryTransportError::Unauthorized)?;
        if session.project_url() != &self.project {
            return Err(RecoveryTransportError::Unauthorized);
        }
        let body = serde_json::to_vec(
            &serde_json::json!({"v":1,"action":"reserve","reservationId":operation}),
        )
        .map_err(|_| RecoveryTransportError::Invalid)?;
        let request = SupabaseHttpRequest::new(
            SupabaseHttpMethod::Post,
            self.project
                .join("/functions/v1/enrollment")
                .map_err(|_| RecoveryTransportError::Invalid)?
                .into(),
            vec![
                ("content-type".into(), "application/json".into()),
                ("apikey".into(), self.publishable_key.to_string()),
                (
                    "authorization".into(),
                    format!("Bearer {}", session.access_token()),
                ),
            ],
            Duration::from_secs(15),
            body,
        )
        .with_response_limit(16 * 1024);
        let response = self
            .http
            .execute(request)
            .map_err(|_| RecoveryTransportError::Transient)?;
        let finished = now.saturating_add(started.elapsed().as_secs());
        self.owner
            .session_for(&self.generation, self.identity, finished)
            .map_err(|_| RecoveryTransportError::Unauthorized)?;
        match response.status() {
            200 => {}
            401 | 403 => return Err(RecoveryTransportError::Unauthorized),
            409 => return Err(RecoveryTransportError::Conflict),
            400..=499 if response.status() != 429 => return Err(RecoveryTransportError::Invalid),
            _ => return Err(RecoveryTransportError::Transient),
        }
        if response.body().len() > 16 * 1024 {
            return Err(RecoveryTransportError::Conflict);
        }
        let response: ReservationResponse = serde_json::from_slice(response.body())
            .map_err(|_| RecoveryTransportError::Conflict)?;
        if response.v != 1
            || response.reservation.reservation_id != operation
            || response.reservation.expires_at.0 <= finished.saturating_mul(1000)
        {
            return Err(RecoveryTransportError::Conflict);
        }
        // The server enforces its ten-minute lifetime using its own clock.
        // Comparing an upper bound to the desktop clock rejects ordinary skew.
        Ok(response.reservation)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReservationResponse {
    v: u8,
    reservation: HostedEnrollmentReservation,
}
