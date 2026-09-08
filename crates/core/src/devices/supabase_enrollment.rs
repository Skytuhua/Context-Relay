use super::{
    recovery_crypto::{
        HostedEnrollmentChallenge, decode_recovery_enrollment_record_v1,
        sign_hosted_enrollment_proof,
    },
    recovery_transport::{RecoveryEnrollmentReceipt, RecoveryTransportError},
};
use crate::{
    auth::{HostedIdentity, HostedSessionOwner, LoginCancellation},
    sync::supabase::{
        ReqwestHttpClient, SupabaseHttpClient, SupabaseHttpMethod, SupabaseHttpRequest,
        valid_header_secret, validated_project_url,
    },
};
use context_relay_protocol::{
    AccountId, DecimalTimestamp, DeviceCertificateId, OperationId, RecoveryEnrollmentId,
    RecoveryRootId, Sha256Digest, WorkspaceId,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, Deserialize)]
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
    fn call<T: serde::de::DeserializeOwned>(
        &self,
        body: serde_json::Value,
        now: u64,
    ) -> Result<(T, u64), RecoveryTransportError> {
        let started = Instant::now();
        let session = self
            .owner
            .session_for(&self.generation, self.identity, now)
            .map_err(|_| RecoveryTransportError::Unauthorized)?;
        if session.project_url() != &self.project {
            return Err(RecoveryTransportError::Unauthorized);
        }
        let body = serde_json::to_vec(&body).map_err(|_| RecoveryTransportError::Invalid)?;
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
        let response = serde_json::from_slice(response.body())
            .map_err(|_| RecoveryTransportError::Conflict)?;
        Ok((response, finished))
    }
    pub fn reserve(
        &self,
        operation: OperationId,
        now: u64,
    ) -> Result<HostedEnrollmentReservation, RecoveryTransportError> {
        let (response, finished): (ReservationResponse, _) = self.call(
            serde_json::json!({"v":1,"action":"reserve","reservationId":operation}),
            now,
        )?;
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

    pub fn status(
        &self,
        expected: &HostedEnrollmentReservation,
        now: u64,
    ) -> Result<Option<RecoveryEnrollmentReceipt>, RecoveryTransportError> {
        let (mut response, _): (StatusResponse, _) = self.call(
            serde_json::json!({"v":1,"action":"status","reservationId":expected.reservation_id}),
            now,
        )?;
        if response.v != 1 {
            return Err(RecoveryTransportError::Conflict);
        }
        let receipt = response
            .reservation
            .as_object_mut()
            .and_then(|value| value.remove("receipt"))
            .ok_or(RecoveryTransportError::Conflict)?;
        let reservation: HostedEnrollmentReservation = serde_json::from_value(response.reservation)
            .map_err(|_| RecoveryTransportError::Conflict)?;
        if reservation != *expected {
            return Err(RecoveryTransportError::Conflict);
        }
        if receipt.is_null() {
            return Ok(None);
        }
        let receipt: WireReceipt =
            serde_json::from_value(receipt).map_err(|_| RecoveryTransportError::Conflict)?;
        if receipt.account_id != expected.account_id
            || receipt.workspace_id != expected.workspace_id
        {
            return Err(RecoveryTransportError::Conflict);
        }
        Ok(Some(receipt.into_receipt()))
    }

    pub fn commit(
        &self,
        reservation: &HostedEnrollmentReservation,
        canonical: &[u8],
        device: &crate::crypto::DeviceKeys,
        now: u64,
    ) -> Result<RecoveryEnrollmentReceipt, RecoveryTransportError> {
        let record = decode_recovery_enrollment_record_v1(canonical)
            .map_err(|_| RecoveryTransportError::Invalid)?;
        if record.account_id != reservation.account_id
            || record.workspace_id != reservation.workspace_id
        {
            return Err(RecoveryTransportError::Conflict);
        }
        let proof = sign_hosted_enrollment_proof(
            device,
            &HostedEnrollmentChallenge {
                reservation_id: reservation.reservation_id,
                auth_user_id: self.identity.user_id,
                session_id: self.identity.session_id,
                nonce: reservation.nonce.0,
            },
            &record,
        )
        .map_err(|_| RecoveryTransportError::Invalid)?;
        let (response, _): (CommitResponse, _) = self.call(
            serde_json::json!({
                "v":1,"action":"commit","reservationId":reservation.reservation_id,
                "record":hex(canonical),"proof":hex(&proof.0),
            }),
            now,
        )?;
        if response.v != 1 {
            return Err(RecoveryTransportError::Conflict);
        }
        let receipt = response.receipt.into_receipt();
        receipt.validate_for(
            crate::sync::SyncScope {
                account_id: reservation.account_id,
                workspace_id: reservation.workspace_id,
            },
            &record,
            Sha256Digest(Sha256::digest(canonical).into()),
            receipt.registered_at_ms,
        )?;
        Ok(receipt)
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusResponse {
    v: u8,
    reservation: serde_json::Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommitResponse {
    v: u8,
    receipt: WireReceipt,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireReceipt {
    enrollment_id: RecoveryEnrollmentId,
    recovery_root_id: RecoveryRootId,
    account_id: AccountId,
    workspace_id: WorkspaceId,
    genesis_certificate_id: DeviceCertificateId,
    canonical_record_sha256: Sha256Digest,
    registered_at_ms: DecimalTimestamp,
}
impl WireReceipt {
    fn into_receipt(self) -> RecoveryEnrollmentReceipt {
        RecoveryEnrollmentReceipt {
            enrollment_id: self.enrollment_id,
            recovery_root_id: self.recovery_root_id,
            account_id: self.account_id,
            workspace_id: self.workspace_id,
            genesis_certificate_id: self.genesis_certificate_id,
            canonical_record_sha256: self.canonical_record_sha256,
            registered_at_ms: self.registered_at_ms.0,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReservationResponse {
    v: u8,
    reservation: HostedEnrollmentReservation,
}
