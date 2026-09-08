use super::{
    crypto::{sign_hosted_pairing_request_proof, verify_pairing_request},
    transport::{
        PairingApprovedResult, PairingDecisionKind, PairingDecisionReceipt, PairingJoinTransport,
        PairingRequestReceipt, PairingResult, PairingTransportError as Error,
    },
};
use crate::{
    auth::{HostedIdentity, HostedSessionOwner, LoginCancellation},
    crypto::DeviceKeys,
    sync::supabase::{
        ReqwestHttpClient, SupabaseHttpClient, SupabaseHttpMethod, SupabaseHttpRequest,
        valid_header_secret, validated_project_url,
    },
    vault::{HostedPairingIntent, HostedPairingRole},
};
use context_relay_protocol::{
    DecimalTimestamp, PairingCode, PairingId, Sha256Digest, decode_pairing_request_v1,
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

impl PairingJoinTransport for HostedPairingClient {
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
