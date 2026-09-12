use super::{
    crypto::{
        decode_pairing_approved_payload_v1, sign_hosted_pairing_approval_proof,
        sign_hosted_pairing_request_proof, verify_pairing_request,
    },
    transport::{
        PairingApprovalTransport, PairingApprovedResult, PairingDecision, PairingDecisionEnvelope,
        PairingDecisionKind, PairingDecisionReceipt, PairingInvite, PairingInviteState,
        PairingInviteStatus, PairingJoinTransport, PairingRequestReceipt, PairingResult,
        PairingTransportError as Error, StoredPairingRequest,
    },
};
use crate::{
    auth::{HostedIdentity, HostedSessionOwner, LoginCancellation},
    crypto::DeviceKeys,
    sync::SyncScope,
    sync::supabase::{
        ReqwestHttpClient, SupabaseHttpClient, SupabaseHttpMethod, SupabaseHttpRequest,
        valid_header_secret, validated_project_url,
    },
    vault::{HostedPairingIntent, HostedPairingRole},
};
use context_relay_protocol::{
    AccountId, DecimalTimestamp, DeviceId, PairingCode, PairingId, Sha256Digest, WorkspaceId,
    decode_pairing_request_v1,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const RESPONSE_LIMIT: usize = 68 * 1024;

/// Native-only client bound to one verified login generation and device key pair.
#[derive(Clone)]
pub struct HostedPairingClient {
    owner: Arc<HostedSessionOwner>,
    identity: HostedIdentity,
    generation: LoginCancellation,
    project: reqwest::Url,
    publishable_key: Zeroizing<String>,
    keys: Arc<DeviceKeys>,
    http: Arc<dyn SupabaseHttpClient>,
}

impl HostedPairingClient {
    pub fn approval_client(
        &self,
        scope: SyncScope,
        device_id: DeviceId,
    ) -> HostedPairingApprovalClient {
        HostedPairingApprovalClient {
            client: self.clone(),
            scope,
            device_id,
        }
    }
    pub fn new(
        owner: Arc<HostedSessionOwner>,
        identity: HostedIdentity,
        generation: LoginCancellation,
        project: &str,
        publishable_key: &str,
        keys: Arc<DeviceKeys>,
    ) -> Result<Self, Error> {
        Self::build(
            owner,
            identity,
            generation,
            project,
            publishable_key,
            keys,
            Arc::new(ReqwestHttpClient::new().map_err(|_| Error::Invalid)?),
        )
    }
    #[cfg(feature = "test-support")]
    pub fn with_http_client(
        owner: Arc<HostedSessionOwner>,
        identity: HostedIdentity,
        generation: LoginCancellation,
        project: &str,
        publishable_key: &str,
        keys: Arc<DeviceKeys>,
        http: Arc<dyn SupabaseHttpClient>,
    ) -> Result<Self, Error> {
        Self::build(
            owner,
            identity,
            generation,
            project,
            publishable_key,
            keys,
            http,
        )
    }
    fn build(
        owner: Arc<HostedSessionOwner>,
        identity: HostedIdentity,
        generation: LoginCancellation,
        project: &str,
        publishable_key: &str,
        keys: Arc<DeviceKeys>,
        http: Arc<dyn SupabaseHttpClient>,
    ) -> Result<Self, Error> {
        if publishable_key.len() > 4096 || !valid_header_secret(publishable_key) {
            return Err(Error::Invalid);
        }
        Ok(Self {
            owner,
            identity,
            generation,
            keys,
            http,
            project: validated_project_url(project).map_err(|_| Error::Invalid)?,
            publishable_key: Zeroizing::new(publishable_key.to_owned()),
        })
    }
    pub fn original_intent(&self, role: HostedPairingRole) -> HostedPairingIntent {
        HostedPairingIntent {
            project_url: self.project.to_string(),
            user_id: self.identity.user_id,
            session_id: self.identity.session_id,
            role,
        }
    }
    fn call<T: serde::de::DeserializeOwned>(
        &self,
        body: serde_json::Value,
        now_ms: u64,
    ) -> Result<T, Error> {
        let started = Instant::now();
        let session = self
            .owner
            .session_for(&self.generation, self.identity, now_ms / 1000)
            .map_err(|_| Error::Unauthorized)?;
        if session.project_url() != &self.project {
            return Err(Error::Unauthorized);
        }
        let body = serde_json::to_vec(&body).map_err(|_| Error::Invalid)?;
        if body.len() > RESPONSE_LIMIT {
            return Err(Error::Invalid);
        }
        let request = SupabaseHttpRequest::new(
            SupabaseHttpMethod::Post,
            self.project
                .join("/functions/v1/pairing")
                .map_err(|_| Error::Invalid)?
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
        .with_response_limit(RESPONSE_LIMIT);
        let response = self.http.execute(request).map_err(|_| Error::Transient)?;
        let elapsed = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.owner
            .session_for(
                &self.generation,
                self.identity,
                now_ms.saturating_add(elapsed) / 1000,
            )
            .map_err(|_| Error::Unauthorized)?;
        if response.body().len() > RESPONSE_LIMIT {
            return Err(Error::Conflict);
        }
        match response.status() {
            200 => serde_json::from_slice(response.body()).map_err(|_| Error::Conflict),
            401 | 403 => Err(Error::Unauthorized),
            410 => Err(Error::Expired),
            409 => {
                let error = serde_json::from_slice::<WireError>(response.body()).ok();
                Err(
                    match error.filter(|e| e.v == 1).map(|e| e.error).as_deref() {
                        Some("pairing_canceled") => Error::Canceled,
                        Some("pairing_rejected") => Error::Rejected,
                        _ => Error::Conflict,
                    },
                )
            }
            400..=499 if response.status() != 429 => Err(Error::Invalid),
            _ => Err(Error::Transient),
        }
    }
}

pub struct HostedPairingApprovalClient {
    client: HostedPairingClient,
    scope: SyncScope,
    device_id: DeviceId,
}
impl HostedPairingApprovalClient {
    fn body(&self, action: &str, id: PairingId) -> serde_json::Value {
        serde_json::json!({"v":1,"action":action,"workspaceId":self.scope.workspace_id,"deviceId":self.device_id,"pairingId":id})
    }
    fn control(
        &self,
        action: &str,
        id: PairingId,
        now_ms: u64,
    ) -> Result<PairingInviteStatus, Error> {
        let response: InviteResponse<InviteStatus> =
            self.client.call(self.body(action, id), now_ms)?;
        let r = response.invite;
        if response.v != 1 || r.pairing_id != id {
            return Err(Error::Conflict);
        }
        invite_times(r.created_at, r.expires_at)?;
        Ok(PairingInviteStatus {
            pairing_id: id,
            created_at_ms: r.created_at.0,
            expires_at_ms: r.expires_at.0,
            state: match r.state {
                InviteState::Pending => PairingInviteState::Pending,
                InviteState::Approved => PairingInviteState::Approved,
                InviteState::Rejected => PairingInviteState::Rejected,
                InviteState::Canceled => PairingInviteState::Canceled,
            },
        })
    }
}
impl PairingApprovalTransport for HostedPairingApprovalClient {
    fn hosted_intent(&self) -> Option<HostedPairingIntent> {
        Some(self.client.original_intent(HostedPairingRole::Approve))
    }
    fn create_invite(&self, now_ms: u64) -> Result<PairingInvite, Error> {
        let response: InviteResponse<CreatedInvite> = self.client.call(
            serde_json::json!({"v":1,"action":"create",
            "workspaceId":self.scope.workspace_id,"deviceId":self.device_id}),
            now_ms,
        )?;
        let r = response.invite;
        if response.v != 1 {
            return Err(Error::Conflict);
        }
        invite_times(r.created_at, r.expires_at)?;
        Ok(PairingInvite {
            pairing_id: r.pairing_id,
            code: r.code,
            created_at_ms: r.created_at.0,
            expires_at_ms: r.expires_at.0,
        })
    }
    fn invite_status(&self, id: PairingId, now_ms: u64) -> Result<PairingInviteStatus, Error> {
        self.control("status", id, now_ms)
    }
    fn cancel(&self, id: PairingId, now_ms: u64) -> Result<(), Error> {
        if self.control("cancel", id, now_ms)?.state != PairingInviteState::Canceled {
            return Err(Error::Conflict);
        }
        Ok(())
    }
    fn request(&self, id: PairingId, now_ms: u64) -> Result<Option<StoredPairingRequest>, Error> {
        let response: RequestResponse = self.client.call(self.body("request", id), now_ms)?;
        if response.v != 1 {
            return Err(Error::Conflict);
        }
        let Some(r) = response.request else {
            return Ok(None);
        };
        if r.pairing_id != id
            || r.account_id != self.scope.account_id
            || r.workspace_id != self.scope.workspace_id
            || r.canonical_request.len() > 16384
        {
            return Err(Error::Conflict);
        }
        let canonical = decode_hex(&r.canonical_request)?;
        let request = decode_pairing_request_v1(&canonical).map_err(|_| Error::Conflict)?;
        let signed = verify_pairing_request(&request).map_err(|_| Error::Conflict)?;
        if request.pairing_id != id || signed.digest() != r.request_digest {
            return Err(Error::Conflict);
        }
        Ok(Some(StoredPairingRequest {
            pairing_id: id,
            scope: self.scope,
            canonical_bytes: canonical,
            request_digest: r.request_digest,
            requested_at_ms: timestamp(r.requested_at)?,
        }))
    }
    fn decide(
        &self,
        envelope: PairingDecisionEnvelope,
        now_ms: u64,
    ) -> Result<PairingDecisionReceipt, Error> {
        let (body, kind, hash) = match envelope.decision() {
            PairingDecision::Reject => {
                let mut body = self.body("reject", envelope.pairing_id);
                body["requestDigest"] = serde_json::json!(envelope.request_digest);
                (body, PairingDecisionKind::Rejected, None)
            }
            PairingDecision::Approve {
                canonical_approved_payload,
            } => {
                let canonical = envelope.canonical_request().ok_or(Error::Invalid)?;
                if canonical.len() > 8192 || canonical_approved_payload.len() > 32768 {
                    return Err(Error::Invalid);
                }
                let request = decode_pairing_request_v1(canonical).map_err(|_| Error::Invalid)?;
                let signed = verify_pairing_request(&request).map_err(|_| Error::Invalid)?;
                let payload = decode_pairing_approved_payload_v1(canonical_approved_payload)
                    .map_err(|_| Error::Invalid)?;
                if request.pairing_id != envelope.pairing_id
                    || signed.digest() != envelope.request_digest
                    || payload.issuer_certificate.account_id != self.scope.account_id
                    || payload.issuer_certificate.workspace_id != self.scope.workspace_id
                    || payload.issuer_certificate.device_id != self.device_id
                {
                    return Err(Error::Conflict);
                }
                let proof = sign_hosted_pairing_approval_proof(
                    &self.client.keys,
                    self.client.identity.user_id,
                    self.client.identity.session_id,
                    &signed,
                    &payload,
                )
                .map_err(|_| Error::Invalid)?;
                let mut body = self.body("approve", envelope.pairing_id);
                body["canonicalApprovedPayload"] =
                    serde_json::json!(hex(canonical_approved_payload));
                body["proof"] = serde_json::json!(hex(&proof.0));
                (
                    body,
                    PairingDecisionKind::Approved,
                    Some(Sha256Digest(
                        Sha256::digest(canonical_approved_payload).into(),
                    )),
                )
            }
        };
        let response: ReceiptResponse<DecisionReceipt> = self.client.call(body, now_ms)?;
        if response.v != 1 {
            return Err(Error::Conflict);
        }
        response
            .receipt
            .validate(envelope.pairing_id, envelope.request_digest, kind, hash)
    }
}
fn invite_times(created: DecimalTimestamp, expires: DecimalTimestamp) -> Result<(), Error> {
    if timestamp(expires)?.checked_sub(timestamp(created)?) != Some(600000) {
        return Err(Error::Conflict);
    }
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InviteResponse<T> {
    v: u8,
    invite: T,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreatedInvite {
    pairing_id: PairingId,
    created_at: DecimalTimestamp,
    expires_at: DecimalTimestamp,
    code: PairingCode,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InviteStatus {
    pairing_id: PairingId,
    created_at: DecimalTimestamp,
    expires_at: DecimalTimestamp,
    state: InviteState,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum InviteState {
    Pending,
    Approved,
    Rejected,
    Canceled,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestResponse {
    v: u8,
    #[serde(deserialize_with = "required_request")]
    request: Option<WireRequest>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireRequest {
    pairing_id: PairingId,
    account_id: AccountId,
    workspace_id: WorkspaceId,
    canonical_request: String,
    request_digest: Sha256Digest,
    requested_at: DecimalTimestamp,
}
fn required_request<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<WireRequest>, D::Error> {
    Option::<WireRequest>::deserialize(deserializer)
}

impl PairingJoinTransport for HostedPairingClient {
    fn hosted_intent(&self) -> Option<HostedPairingIntent> {
        Some(self.original_intent(HostedPairingRole::Join))
    }
    fn resolve_code(&self, code: &PairingCode, now_ms: u64) -> Result<PairingId, Error> {
        let response: ResultResponse<Locator> = self.call(
            serde_json::json!({"v":1,"action":"resolve","code":code}),
            now_ms,
        )?;
        if response.v != 1 {
            return Err(Error::Conflict);
        }
        match response.result {
            Locator::Located { pairing_id } => Ok(pairing_id),
            Locator::Invalid {} => Err(Error::Invalid),
            Locator::Exhausted {} => Err(Error::Exhausted),
            Locator::Expired {} => Err(Error::Expired),
            Locator::Canceled {} => Err(Error::Canceled),
            Locator::Rejected {} => Err(Error::Rejected),
            Locator::Conflict {} => Err(Error::Conflict),
        }
    }
    fn submit_request(
        &self,
        id: PairingId,
        canonical: &[u8],
        now_ms: u64,
    ) -> Result<PairingRequestReceipt, Error> {
        if canonical.len() > 8192 {
            return Err(Error::Invalid);
        }
        let request = decode_pairing_request_v1(canonical).map_err(|_| Error::Invalid)?;
        let signed = verify_pairing_request(&request).map_err(|_| Error::Invalid)?;
        if request.pairing_id != id || signed.canonical_bytes() != canonical {
            return Err(Error::Conflict);
        }
        let proof = sign_hosted_pairing_request_proof(
            &self.keys,
            self.identity.user_id,
            self.identity.session_id,
            &signed,
        )
        .map_err(|_| Error::Invalid)?;
        let response: ReceiptResponse<RequestReceipt> = self.call(
            serde_json::json!({"v":1,"action":"submit",
            "canonicalRequest":hex(canonical),"proof":hex(&proof.0)}),
            now_ms,
        )?;
        let r = response.receipt;
        if response.v != 1 || r.pairing_id != id || r.request_digest != signed.digest() {
            return Err(Error::Conflict);
        }
        Ok(PairingRequestReceipt {
            pairing_id: id,
            request_digest: r.request_digest,
            requested_at_ms: timestamp(r.requested_at)?,
        })
    }
    fn result(
        &self,
        id: PairingId,
        digest: Sha256Digest,
        now_ms: u64,
    ) -> Result<PairingResult, Error> {
        let response: ResultResponse<JoinResult> = self.call(
            serde_json::json!({"v":1,"action":"result",
            "pairingId":id,"requestDigest":digest}),
            now_ms,
        )?;
        if response.v != 1 {
            return Err(Error::Conflict);
        }
        match response.result {
            JoinResult::Pending {} => Ok(PairingResult::Pending),
            JoinResult::Canceled {} => Ok(PairingResult::Canceled),
            JoinResult::Rejected { receipt } => Ok(PairingResult::Rejected {
                receipt: receipt.validate(id, digest, PairingDecisionKind::Rejected, None)?,
            }),
            JoinResult::Approved {
                canonical_approved_payload,
                receipt,
            } => {
                let canonical = decode_hex(&canonical_approved_payload)?;
                let hash = Sha256Digest(Sha256::digest(&canonical).into());
                let receipt =
                    receipt.validate(id, digest, PairingDecisionKind::Approved, Some(hash))?;
                // The coordinator still verifies the complete signed approval and
                // requires human safety-number confirmation before installing trust.
                Ok(PairingResult::Approved(PairingApprovedResult::new(
                    canonical, receipt,
                )))
            }
        }
    }
}

fn timestamp(value: DecimalTimestamp) -> Result<u64, Error> {
    if value.0 > i64::MAX as u64 {
        Err(Error::Conflict)
    } else {
        Ok(value.0)
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn decode_hex(value: &str) -> Result<Vec<u8>, Error> {
    if value.is_empty()
        || value.len() > 65536
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Conflict);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|p| {
            u8::from_str_radix(std::str::from_utf8(p).map_err(|_| Error::Conflict)?, 16)
                .map_err(|_| Error::Conflict)
        })
        .collect()
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireError {
    v: u8,
    error: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultResponse<T> {
    v: u8,
    result: T,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptResponse<T> {
    v: u8,
    receipt: T,
}
#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "camelCase", deny_unknown_fields)]
enum Locator {
    Located {
        #[serde(rename = "pairingId")]
        pairing_id: PairingId,
    },
    Invalid {},
    Exhausted {},
    Expired {},
    Canceled {},
    Rejected {},
    Conflict {},
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RequestReceipt {
    pairing_id: PairingId,
    request_digest: Sha256Digest,
    requested_at: DecimalTimestamp,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DecisionReceipt {
    pairing_id: PairingId,
    request_digest: Sha256Digest,
    decision: String,
    #[serde(deserialize_with = "required_digest")]
    approved_payload_digest: Option<Sha256Digest>,
    decided_at: DecimalTimestamp,
}
impl DecisionReceipt {
    fn validate(
        self,
        id: PairingId,
        digest: Sha256Digest,
        kind: PairingDecisionKind,
        payload: Option<Sha256Digest>,
    ) -> Result<PairingDecisionReceipt, Error> {
        let name = match kind {
            PairingDecisionKind::Approved => "approved",
            PairingDecisionKind::Rejected => "rejected",
        };
        if self.pairing_id != id
            || self.request_digest != digest
            || self.decision != name
            || self.approved_payload_digest != payload
        {
            return Err(Error::Conflict);
        }
        Ok(PairingDecisionReceipt {
            pairing_id: id,
            request_digest: digest,
            decision: kind,
            approved_payload_digest: payload,
            decided_at_ms: timestamp(self.decided_at)?,
        })
    }
}
#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "camelCase", deny_unknown_fields)]
enum JoinResult {
    Pending {},
    Canceled {},
    Rejected {
        receipt: DecisionReceipt,
    },
    Approved {
        #[serde(rename = "canonicalApprovedPayload")]
        canonical_approved_payload: String,
        receipt: DecisionReceipt,
    },
}

fn required_digest<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Sha256Digest>, D::Error> {
    Option::<Sha256Digest>::deserialize(deserializer)
}
