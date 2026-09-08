//! Simulated HTTP provider for composing native clients and daemon IPC. Not live service evidence.
use crate::pairing::{HostedPairingService, PairingIdentity, PairingService};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use context_relay_core::{
    auth::{
        HostedSessionOwner, LoginError, LoginStore, PendingLogin, StoredLogin, SupabaseAuthClient,
    },
    devices::{
        crypto::{
            decode_pairing_approved_payload_v1, sign_hosted_pairing_approval_proof,
            sign_hosted_pairing_request_proof, verify_pairing_request,
        },
        memory_transport::InMemoryPairingProvider,
        pairing::PairingClock,
        recovery::{RecoveryEnrollmentClock, SystemRecoveryEnrollmentClock},
        transport::{
            PairingApprovalTransport, PairingDecisionEnvelope, PairingDecisionKind,
            PairingDecisionReceipt, PairingJoinTransport, PairingResult,
        },
    },
    sync::{
        SupabaseHttpClient, SupabaseHttpError, SupabaseHttpRequest, SupabaseHttpResponse, SyncScope,
    },
};
use context_relay_protocol::{PairingId, decode_pairing_request_v1};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

const PROJECT: &str = "https://example.supabase.co";
const USER: &str = "550e8400-e29b-41d4-a716-446655440000";

pub(crate) struct Backend {
    provider: InMemoryPairingProvider,
    clock: Arc<dyn PairingClock>,
    scope: SyncScope,
    approved: Mutex<BTreeMap<PairingId, Value>>,
    pub(crate) lose_approval_response: AtomicBool,
    pub(crate) calls: AtomicUsize,
}
impl Backend {
    pub(crate) fn new(
        provider: InMemoryPairingProvider,
        clock: Arc<dyn PairingClock>,
        scope: SyncScope,
    ) -> Arc<Self> {
        Arc::new(Self {
            provider,
            clock,
            scope,
            approved: Mutex::new(BTreeMap::new()),
            lose_approval_response: AtomicBool::new(false),
            calls: AtomicUsize::new(0),
        })
    }
}

pub(crate) struct Fixture {
    pub(crate) owner: Arc<HostedSessionOwner>,
    http: Arc<Endpoint>,
}
impl Fixture {
    pub(crate) fn new(
        backend: Arc<Backend>,
        identity: PairingIdentity,
        session: &str,
        can_approve: bool,
    ) -> Self {
        struct Login;
        impl LoginStore for Login {
            fn load(&self) -> Result<Option<StoredLogin>, LoginError> {
                Ok(None)
            }
            fn save(&self, _: &StoredLogin) -> Result<(), LoginError> {
                Ok(())
            }
            fn clear(&self) -> Result<(), LoginError> {
                Ok(())
            }
        }
        let now = SystemRecoveryEnrollmentClock.now_ms() / 1000;
        let http = Arc::new(Endpoint {
            backend,
            identity,
            session: session.into(),
            can_approve,
            now,
        });
        let owner = Arc::new(HostedSessionOwner::new(
            Arc::new(
                SupabaseAuthClient::with_http_client(PROJECT, "public-test", http.clone()).unwrap(),
            ),
            Arc::new(Login),
        ));
        let instant = std::time::Instant::now();
        let mut pending =
            PendingLogin::new(PROJECT, "127.0.0.1:41783".parse().unwrap(), instant).unwrap();
        let url = pending.authorization_url();
        let redirect = url
            .query_pairs()
            .find(|(key, _)| key == "redirect_to")
            .unwrap()
            .1
            .into_owned();
        let mut callback = url.join(&redirect).unwrap();
        callback
            .query_pairs_mut()
            .append_pair("code", "synthetic-code");
        owner
            .complete_login(
                owner.begin_login().unwrap(),
                pending.take_callback(&callback, instant).unwrap(),
                now,
            )
            .unwrap();
        Self { owner, http }
    }
    pub(crate) fn service(&self) -> Arc<dyn PairingService> {
        let mut service = HostedPairingService::new(
            self.owner.clone(),
            PROJECT,
            "public-test",
            self.http.identity.clone(),
        );
        service.http = Some(self.http.clone());
        Arc::new(service)
    }
}

struct Endpoint {
    backend: Arc<Backend>,
    identity: PairingIdentity,
    session: String,
    can_approve: bool,
    now: u64,
}
impl Endpoint {
    fn token(&self) -> String {
        let claims = json!({"iss":format!("{PROJECT}/auth/v1"),"aud":"authenticated","sub":USER,"session_id":self.session,"exp":self.now+3600});
        format!(
            "e30.{}.signature",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
        )
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn unhex(value: &Value) -> Vec<u8> {
    value
        .as_str()
        .unwrap()
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn receipt(value: &PairingDecisionReceipt) -> Value {
    json!({"pairingId":value.pairing_id,"requestDigest":value.request_digest,
        "decision":match value.decision { PairingDecisionKind::Approved=>"approved",PairingDecisionKind::Rejected=>"rejected" },
        "approvedPayloadDigest":value.approved_payload_digest,"decidedAt":value.decided_at_ms.to_string()})
}
impl SupabaseHttpClient for Endpoint {
    fn execute(
        &self,
        request: SupabaseHttpRequest,
    ) -> Result<SupabaseHttpResponse, SupabaseHttpError> {
        let reply = |body: Value| {
            Ok(SupabaseHttpResponse::new(
                200,
                serde_json::to_vec(&body).unwrap(),
            ))
        };
        if request.url().contains("/auth/v1/token") {
            return reply(
                json!({"token_type":"bearer","access_token":self.token(),"refresh_token":"synthetic-refresh"}),
            );
        }
        let bearer = format!("Bearer {}", self.token());
        assert_eq!(request.header("authorization"), Some(bearer.as_str()));
        if request.url().ends_with("/auth/v1/logout?scope=local") {
            return Ok(SupabaseHttpResponse::new(204, vec![]));
        }
        if request.url().ends_with("/user") {
            return reply(json!({"id":USER}));
        }
        assert!(request.url().ends_with("/functions/v1/pairing"));
        self.backend.calls.fetch_add(1, Ordering::SeqCst);
        let body: Value = serde_json::from_slice(request.body()).unwrap();
        let now = self.backend.clock.now_ms();
        let joiner = self
            .backend
            .provider
            .join_session_client(&self.session)
            .unwrap();
        let approver = self
            .backend
            .provider
            .existing_device_client(self.backend.scope, self.identity.device_id);
        let action = body["action"].as_str().unwrap();
        if matches!(
            action,
            "create" | "status" | "request" | "approve" | "reject" | "cancel"
        ) {
            assert!(self.can_approve);
            assert_eq!(body["workspaceId"], json!(self.backend.scope.workspace_id));
            assert_eq!(body["deviceId"], json!(self.identity.device_id));
        }
        if action == "create" {
            let invite = approver.create_invite(now).unwrap();
            return reply(
                json!({"v":1,"invite":{"pairingId":invite.pairing_id,"createdAt":invite.created_at_ms.to_string(),"expiresAt":invite.expires_at_ms.to_string(),"code":invite.code}}),
            );
        }
        if action == "resolve" {
            let code = serde_json::from_value(body["code"].clone()).unwrap();
            return reply(
                json!({"v":1,"result":{"status":"located","pairingId":joiner.resolve_code(&code,now).unwrap()}}),
            );
        }
        if action == "submit" {
            let canonical = unhex(&body["canonicalRequest"]);
            let signed =
                verify_pairing_request(&decode_pairing_request_v1(&canonical).unwrap()).unwrap();
            let proof = sign_hosted_pairing_request_proof(
                &self.identity.keys,
                USER.parse().unwrap(),
                self.session.parse().unwrap(),
                &signed,
            )
            .unwrap();
            assert_eq!(body["proof"], json!(hex(&proof.0)));
            let result = joiner
                .submit_request(signed.request().pairing_id, &canonical, now)
                .unwrap();
            return reply(
                json!({"v":1,"receipt":{"pairingId":result.pairing_id,"requestDigest":result.request_digest,"requestedAt":result.requested_at_ms.to_string()}}),
            );
        }
        let id: PairingId = serde_json::from_value(body["pairingId"].clone()).unwrap();
        match action {
            "status" | "cancel" => {
                if action == "cancel" {
                    approver.cancel(id, now).unwrap();
                }
                let status = approver.invite_status(id, now).unwrap();
                reply(
                    json!({"v":1,"invite":{"pairingId":id,"createdAt":status.created_at_ms.to_string(),"expiresAt":status.expires_at_ms.to_string(),"state":format!("{:?}",status.state).to_lowercase()}}),
                )
            }
            "request" => {
                let request=approver.request(id,now).unwrap().map(|r|json!({"pairingId":id,"accountId":r.scope.account_id,"workspaceId":r.scope.workspace_id,"canonicalRequest":hex(&r.canonical_bytes),"requestDigest":r.request_digest,"requestedAt":r.requested_at_ms.to_string()}));
                reply(json!({"v":1,"request":request}))
            }
            "approve" | "reject" => {
                let stored = approver.request(id, now).unwrap().unwrap();
                let signed = verify_pairing_request(
                    &decode_pairing_request_v1(&stored.canonical_bytes).unwrap(),
                )
                .unwrap();
                let decision = if action == "approve" {
                    let canonical = unhex(&body["canonicalApprovedPayload"]);
                    let payload = decode_pairing_approved_payload_v1(&canonical).unwrap();
                    let proof = sign_hosted_pairing_approval_proof(
                        &self.identity.keys,
                        USER.parse().unwrap(),
                        self.session.parse().unwrap(),
                        &signed,
                        &payload,
                    )
                    .unwrap();
                    assert_eq!(body["proof"], json!(hex(&proof.0)));
                    PairingDecisionEnvelope::approve_request(&signed, canonical)
                } else {
                    PairingDecisionEnvelope::reject(
                        id,
                        serde_json::from_value(body["requestDigest"].clone()).unwrap(),
                    )
                };
                let decided = approver.decide(decision, now).unwrap();
                if action == "approve" {
                    let result = json!({"v":1,"result":{"status":"approved","canonicalApprovedPayload":body["canonicalApprovedPayload"],"receipt":receipt(&decided)}});
                    let mut approved = self.backend.approved.lock().unwrap();
                    if let Some(old) = approved.get(&id) {
                        assert_eq!(old, &result);
                    }
                    approved.insert(id, result);
                    if self
                        .backend
                        .lose_approval_response
                        .swap(false, Ordering::SeqCst)
                    {
                        return Err(SupabaseHttpError::Transient);
                    }
                }
                reply(json!({"v":1,"receipt":receipt(&decided)}))
            }
            "result" => {
                let digest = serde_json::from_value(body["requestDigest"].clone()).unwrap();
                match joiner.result(id, digest, now).unwrap() {
                    PairingResult::Pending => reply(json!({"v":1,"result":{"status":"pending"}})),
                    PairingResult::Canceled => reply(json!({"v":1,"result":{"status":"canceled"}})),
                    PairingResult::Rejected { receipt: r } => {
                        reply(json!({"v":1,"result":{"status":"rejected","receipt":receipt(&r)}}))
                    }
                    PairingResult::Approved(_) => {
                        reply(self.backend.approved.lock().unwrap()[&id].clone())
                    }
                }
            }
            other => panic!("unexpected pairing action {other}"),
        }
    }
}
