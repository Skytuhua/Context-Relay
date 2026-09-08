use super::{
    recovery::RecoveryEnrollmentClock,
    recovery_crypto::{
        HostedEnrollmentChallenge, decode_recovery_enrollment_record_v1,
        sign_hosted_enrollment_proof,
    },
    recovery_restore_crypto::{
        decode_recovery_device_claim_v1, sign_hosted_recovery_proof, verify_recovery_device_claim,
    },
    recovery_restore_transport::{
        RecoveryRestoreProjection, RecoveryRestoreReceipt, RecoveryRestoreTransport,
        RecoveryRootSnapshot,
    },
    recovery_transport::{
        RecoveryEnrollmentReceipt, RecoveryEnrollmentTransport, RecoveryRootStatus,
        RecoveryTransportError,
    },
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
    RecoveryRestoreId, RecoveryRootId, Sha256Digest, WorkspaceId,
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
impl HostedEnrollmentReservation {
    pub(crate) fn validate_renewal(&self, previous: &Self) -> Result<(), RecoveryTransportError> {
        if self.reservation_id != previous.reservation_id
            || self.account_id != previous.account_id
            || self.workspace_id != previous.workspace_id
            || self.expires_at.0 < previous.expires_at.0
            || self.expires_at.0 == 0
            || self.expires_at.0 > i64::MAX as u64
            || (self.expires_at == previous.expires_at) != (self.nonce == previous.nonce)
        {
            return Err(RecoveryTransportError::Conflict);
        }
        Ok(())
    }
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
    /// Bind recovery to the discovered root and the client's original login session.
    pub fn into_restore_transport<C: RecoveryEnrollmentClock>(
        self,
        intent: &crate::vault::HostedRestoreIntent,
        snapshot: RecoveryRootSnapshot,
        device: Arc<crate::crypto::DeviceKeys>,
        clock: C,
    ) -> Result<HostedRecoveryRestoreTransport<C>, RecoveryTransportError> {
        intent
            .validate()
            .map_err(|_| RecoveryTransportError::Invalid)?;
        if intent.user_id != self.identity.user_id
            || intent.session_id != self.identity.session_id
            || validated_project_url(&intent.project_url)
                .map_err(|_| RecoveryTransportError::Invalid)?
                != self.project
        {
            return Err(RecoveryTransportError::Unauthorized);
        }
        snapshot.validate_for(snapshot.scope)?;
        if snapshot.registered_at_ms > i64::MAX as u64 {
            return Err(RecoveryTransportError::Conflict);
        }
        Ok(HostedRecoveryRestoreTransport {
            client: self,
            snapshot,
            device,
            clock,
        })
    }
    /// Bind the coordinator to the persisted reservation and installed device keys.
    pub fn into_transport<C: RecoveryEnrollmentClock>(
        self,
        intent: &crate::vault::HostedEnrollmentIntent,
        device: Arc<crate::crypto::DeviceKeys>,
        clock: C,
    ) -> Result<HostedRecoveryEnrollmentTransport<C>, RecoveryTransportError> {
        intent
            .validate()
            .map_err(|_| RecoveryTransportError::Invalid)?;
        if intent.user_id != self.identity.user_id
            || intent.session_id != self.identity.session_id
            || validated_project_url(&intent.project_url)
                .map_err(|_| RecoveryTransportError::Invalid)?
                != self.project
        {
            return Err(RecoveryTransportError::Unauthorized);
        }
        let reservation = intent
            .reservation
            .clone()
            .ok_or(RecoveryTransportError::Invalid)?;
        Ok(HostedRecoveryEnrollmentTransport {
            client: self,
            reservation,
            device,
            clock,
        })
    }
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
        self.call_bounded(body, now, 16 * 1024)
    }
    fn call_bounded<T: serde::de::DeserializeOwned>(
        &self,
        body: serde_json::Value,
        now: u64,
        response_limit: usize,
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
        .with_response_limit(response_limit);
        let response = self
            .http
            .execute(request)
            .map_err(|_| RecoveryTransportError::Transient)?;
        let finished = now.saturating_add(started.elapsed().as_secs());
        self.owner
            .session_for(&self.generation, self.identity, finished)
            .map_err(|_| RecoveryTransportError::Unauthorized)?;
        if response.status() == 403
            && response.body().len() <= 16 * 1024
            && serde_json::from_slice::<serde_json::Value>(response.body()).ok()
                == Some(serde_json::json!({"v":1,"error":"enrollment_reservation_expired"}))
        {
            return Err(RecoveryTransportError::Expired);
        }
        match response.status() {
            200 => {}
            401 | 403 => return Err(RecoveryTransportError::Unauthorized),
            409 => return Err(RecoveryTransportError::Conflict),
            400..=499 if response.status() != 429 => return Err(RecoveryTransportError::Invalid),
            _ => return Err(RecoveryTransportError::Transient),
        }
        if response.body().len() > response_limit {
            return Err(RecoveryTransportError::Conflict);
        }
        let response = serde_json::from_slice(response.body())
            .map_err(|_| RecoveryTransportError::Conflict)?;
        Ok((response, finished))
    }
    /// Discover the owner's canonical recovery record without granting device trust.
    /// The restore coordinator must still prove possession of the recovery phrase.
    pub fn snapshot(
        &self,
        now: u64,
    ) -> Result<Option<RecoveryRootSnapshot>, RecoveryTransportError> {
        let (response, _): (SnapshotResponse, _) = self.call_bounded(
            serde_json::json!({"v":1,"action":"snapshot"}),
            now,
            68 * 1024,
        )?;
        if response.v != 1 {
            return Err(RecoveryTransportError::Conflict);
        }
        if response.snapshot.is_null() {
            return Ok(None);
        }
        let wire: WireSnapshot = serde_json::from_value(response.snapshot)
            .map_err(|_| RecoveryTransportError::Conflict)?;
        if wire.registered_at_ms.0 > i64::MAX as u64 {
            return Err(RecoveryTransportError::Conflict);
        }
        let canonical_record = decode_hex(&wire.canonical_record)?;
        let snapshot = RecoveryRootSnapshot {
            scope: crate::sync::SyncScope {
                account_id: wire.account_id,
                workspace_id: wire.workspace_id,
            },
            canonical_record,
            canonical_record_sha256: wire.canonical_record_sha256,
            registered_at_ms: wire.registered_at_ms.0,
            recovery_generation: wire.recovery_generation.0,
        };
        snapshot.validate_for(snapshot.scope)?;
        Ok(Some(snapshot))
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

    pub fn renew(
        &self,
        previous: &HostedEnrollmentReservation,
        now: u64,
    ) -> Result<HostedEnrollmentReservation, RecoveryTransportError> {
        let (response, _): (ReservationResponse, _) = self.call(
            serde_json::json!({"v":1,"action":"renew","reservationId":previous.reservation_id}),
            now,
        )?;
        if response.v != 1 {
            return Err(RecoveryTransportError::Conflict);
        }
        response.reservation.validate_renewal(previous)?;
        Ok(response.reservation)
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

pub struct HostedRecoveryRestoreTransport<C> {
    client: HostedEnrollmentClient,
    snapshot: RecoveryRootSnapshot,
    device: Arc<crate::crypto::DeviceKeys>,
    clock: C,
}

impl<C: RecoveryEnrollmentClock> RecoveryRestoreTransport for HostedRecoveryRestoreTransport<C> {
    fn scope(&self) -> crate::sync::SyncScope {
        self.snapshot.scope
    }

    fn root_snapshot(&self) -> Result<Option<RecoveryRootSnapshot>, RecoveryTransportError> {
        let snapshot = self.client.snapshot(self.clock.now_ms() / 1000)?;
        if let Some(current) = &snapshot
            && (current.scope != self.snapshot.scope
                || current.canonical_record != self.snapshot.canonical_record
                || current.canonical_record_sha256 != self.snapshot.canonical_record_sha256
                || current.registered_at_ms != self.snapshot.registered_at_ms
                || current.recovery_generation < self.snapshot.recovery_generation)
        {
            return Err(RecoveryTransportError::Conflict);
        }
        Ok(snapshot)
    }

    fn submit_restore(
        &self,
        canonical_claim: &[u8],
        _now_ms: u64,
    ) -> Result<RecoveryRestoreReceipt, RecoveryTransportError> {
        let record = self.snapshot.validate_for(self.scope())?;
        let claim = decode_recovery_device_claim_v1(canonical_claim)
            .map_err(|_| RecoveryTransportError::Invalid)?;
        verify_recovery_device_claim(&record, &claim)
            .map_err(|_| RecoveryTransportError::Invalid)?;
        let proof = sign_hosted_recovery_proof(
            &self.device,
            self.client.identity.user_id,
            self.client.identity.session_id,
            &claim,
        )
        .map_err(|_| RecoveryTransportError::Invalid)?;
        let (response, _): (RestoreResponse, _) = self.client.call(
            serde_json::json!({"v":1,"action":"restore","claim":hex(canonical_claim),"proof":hex(&proof.0)}),
            self.clock.now_ms() / 1000,
        )?;
        if response.v != 1 {
            return Err(RecoveryTransportError::Conflict);
        }
        let receipt = response.receipt.into_receipt()?;
        receipt.validate_for(self.scope(), &record, canonical_claim)?;
        Ok(receipt)
    }

    fn restore_claim(
        &self,
        restore_id: RecoveryRestoreId,
    ) -> Result<Option<RecoveryRestoreProjection>, RecoveryTransportError> {
        let (response, _): (RestoreStatusResponse, _) = self.client.call_bounded(
            serde_json::json!({"v":1,"action":"restore_status","restoreId":restore_id}),
            self.clock.now_ms() / 1000,
            68 * 1024,
        )?;
        if response.v != 1 {
            return Err(RecoveryTransportError::Conflict);
        }
        if response.projection.is_null() {
            return Ok(None);
        }
        let wire: WireRestoreProjection = serde_json::from_value(response.projection)
            .map_err(|_| RecoveryTransportError::Conflict)?;
        let projection = RecoveryRestoreProjection {
            canonical_claim: decode_hex(&wire.canonical_claim)?,
            receipt: wire.receipt.into_receipt()?,
        };
        if projection.receipt.restore_id != restore_id {
            return Err(RecoveryTransportError::Conflict);
        }
        projection.validate_for(self.scope(), &self.snapshot.validate_for(self.scope())?)?;
        Ok(Some(projection))
    }
}

pub struct HostedRecoveryEnrollmentTransport<C> {
    client: HostedEnrollmentClient,
    reservation: HostedEnrollmentReservation,
    device: Arc<crate::crypto::DeviceKeys>,
    clock: C,
}

impl<C: RecoveryEnrollmentClock> RecoveryEnrollmentTransport
    for HostedRecoveryEnrollmentTransport<C>
{
    fn scope(&self) -> crate::sync::SyncScope {
        crate::sync::SyncScope {
            account_id: self.reservation.account_id,
            workspace_id: self.reservation.workspace_id,
        }
    }
    fn root_status(&self) -> Result<Option<RecoveryRootStatus>, RecoveryTransportError> {
        // The coordinator validates this projection against its durable record.
        self.client
            .status(&self.reservation, self.clock.now_ms() / 1000)
            .map(|receipt| receipt.map(RecoveryEnrollmentReceipt::into_status))
    }
    fn register(
        &self,
        canonical_record: &[u8],
        _now_ms: u64,
    ) -> Result<RecoveryEnrollmentReceipt, RecoveryTransportError> {
        self.client.commit(
            &self.reservation,
            canonical_record,
            &self.device,
            self.clock.now_ms() / 1000,
        )
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(encoded: &str) -> Result<Vec<u8>, RecoveryTransportError> {
    if encoded.is_empty()
        || encoded.len() > 32768 * 2
        || !encoded.len().is_multiple_of(2)
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RecoveryTransportError::Conflict);
    }
    (0..encoded.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&encoded[index..index + 2], 16)
                .map_err(|_| RecoveryTransportError::Conflict)
        })
        .collect()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreResponse {
    v: u8,
    receipt: WireRestoreReceipt,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreStatusResponse {
    v: u8,
    projection: serde_json::Value,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireRestoreProjection {
    canonical_claim: String,
    receipt: WireRestoreReceipt,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireRestoreReceipt {
    restore_id: RecoveryRestoreId,
    enrollment_id: RecoveryEnrollmentId,
    recovery_root_id: RecoveryRootId,
    account_id: AccountId,
    workspace_id: WorkspaceId,
    certificate_id: DeviceCertificateId,
    canonical_record_sha256: Sha256Digest,
    canonical_claim_sha256: Sha256Digest,
    accepted_generation: DecimalTimestamp,
    accepted_at_ms: DecimalTimestamp,
}
impl WireRestoreReceipt {
    fn into_receipt(self) -> Result<RecoveryRestoreReceipt, RecoveryTransportError> {
        if self.accepted_at_ms.0 > i64::MAX as u64 {
            return Err(RecoveryTransportError::Conflict);
        }
        Ok(RecoveryRestoreReceipt {
            restore_id: self.restore_id,
            enrollment_id: self.enrollment_id,
            recovery_root_id: self.recovery_root_id,
            account_id: self.account_id,
            workspace_id: self.workspace_id,
            certificate_id: self.certificate_id,
            canonical_record_sha256: self.canonical_record_sha256,
            canonical_claim_sha256: self.canonical_claim_sha256,
            accepted_generation: self.accepted_generation.0,
            accepted_at_ms: self.accepted_at_ms.0,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotResponse {
    v: u8,
    snapshot: serde_json::Value,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireSnapshot {
    account_id: AccountId,
    workspace_id: WorkspaceId,
    canonical_record: String,
    canonical_record_sha256: Sha256Digest,
    registered_at_ms: DecimalTimestamp,
    recovery_generation: DecimalTimestamp,
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
