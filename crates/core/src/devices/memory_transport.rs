use std::{
    collections::BTreeMap,
    fmt,
    str::FromStr,
    sync::{Arc, Mutex, MutexGuard},
};

#[cfg(feature = "test-support")]
use std::collections::VecDeque;

use context_relay_protocol::{
    DeviceId, MAX_PAIRING_REQUEST_BYTES, PairingCode, PairingId, Sha256Digest,
    decode_pairing_request_v1,
};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    devices::{
        crypto::{
            MAX_PAIRING_APPROVED_PAYLOAD_BYTES, inspect_pairing_approval, verify_pairing_request,
        },
        transport::{
            PairingApprovalTransport, PairingApprovedResult, PairingDecision,
            PairingDecisionEnvelope, PairingDecisionKind, PairingDecisionReceipt, PairingInvite,
            PairingInviteState, PairingInviteStatus, PairingJoinTransport, PairingRequestReceipt,
            PairingResult, PairingTransport, PairingTransportError, StoredPairingRequest,
        },
    },
    sync::SyncScope,
};

const INVITE_LIFETIME_MS: u64 = 600_000;
const MAX_FAILED_ATTEMPTS: u8 = 5;
const MAX_SESSION_ID_BYTES: usize = 128;
const MAX_ENTROPY_RETRIES: usize = 32;
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct InMemoryPairingProvider {
    shared: Arc<SharedProvider>,
}

struct SharedProvider {
    pepper: Zeroizing<[u8; 32]>,
    state: Mutex<ProviderState>,
}

struct ProviderState {
    entropy: ProviderEntropy,
    invites: BTreeMap<PairingId, InviteRecord>,
    sessions: BTreeMap<String, JoinSession>,
}

enum ProviderEntropy {
    Os,
    #[cfg(feature = "test-support")]
    Fixed(VecDeque<[u8; 32]>),
}

#[derive(Default)]
struct JoinSession {
    failed_attempts: u8,
}

struct InviteRecord {
    scope: SyncScope,
    creating_device_id: DeviceId,
    code_hmac: [u8; 32],
    created_at_ms: u64,
    expires_at_ms: u64,
    located_session: Option<String>,
    request: Option<StoredPairingRequest>,
    terminal: TerminalState,
    expiry_reported: bool,
}

enum TerminalState {
    Active,
    Approved {
        canonical_approved_payload: Vec<u8>,
        receipt: PairingDecisionReceipt,
    },
    Rejected(PairingDecisionReceipt),
    Canceled,
    Expired,
}

#[derive(Clone)]
pub struct InMemoryPairingJoinClient {
    shared: Arc<SharedProvider>,
    session_id: Arc<str>,
}

#[derive(Clone)]
pub struct InMemoryPairingApprovalClient {
    shared: Arc<SharedProvider>,
    scope: SyncScope,
    device_id: DeviceId,
}

impl InMemoryPairingProvider {
    pub fn new() -> Result<Self, PairingTransportError> {
        let mut pepper = [0_u8; 32];
        OsRng
            .try_fill_bytes(&mut pepper)
            .map_err(|_| PairingTransportError::Transient)?;
        Ok(Self::from_parts(pepper, ProviderEntropy::Os))
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn with_test_entropy(pepper: [u8; 32], entropy: Vec<[u8; 32]>) -> Self {
        Self::from_parts(pepper, ProviderEntropy::Fixed(entropy.into()))
    }

    fn from_parts(pepper: [u8; 32], entropy: ProviderEntropy) -> Self {
        Self {
            shared: Arc::new(SharedProvider {
                pepper: Zeroizing::new(pepper),
                state: Mutex::new(ProviderState {
                    entropy,
                    invites: BTreeMap::new(),
                    sessions: BTreeMap::new(),
                }),
            }),
        }
    }

    pub fn existing_device_client(
        &self,
        scope: SyncScope,
        device_id: DeviceId,
    ) -> InMemoryPairingApprovalClient {
        InMemoryPairingApprovalClient {
            shared: Arc::clone(&self.shared),
            scope,
            device_id,
        }
    }

    pub fn join_session_client(
        &self,
        session_id: &str,
    ) -> Result<InMemoryPairingJoinClient, PairingTransportError> {
        if session_id.is_empty() || session_id.len() > MAX_SESSION_ID_BYTES {
            return Err(PairingTransportError::Unauthorized);
        }
        let mut state = lock(&self.shared)?;
        state.sessions.entry(session_id.to_owned()).or_default();
        drop(state);
        Ok(InMemoryPairingJoinClient {
            shared: Arc::clone(&self.shared),
            session_id: Arc::from(session_id),
        })
    }

    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn test_capture_bytes(&self) -> Vec<u8> {
        let Ok(state) = self.shared.state.lock() else {
            return Vec::new();
        };
        let mut capture = Vec::new();
        for (pairing_id, invite) in &state.invites {
            capture.extend_from_slice(pairing_id.as_bytes());
            capture.extend_from_slice(invite.scope.account_id.as_bytes());
            capture.extend_from_slice(invite.scope.workspace_id.as_bytes());
            capture.extend_from_slice(invite.creating_device_id.as_bytes());
            capture.extend_from_slice(&invite.code_hmac);
            capture.extend_from_slice(&invite.created_at_ms.to_be_bytes());
            capture.extend_from_slice(&invite.expires_at_ms.to_be_bytes());
            if let Some(request) = &invite.request {
                capture.extend_from_slice(&request.canonical_bytes);
                capture.extend_from_slice(&request.request_digest.0);
            }
            if let TerminalState::Approved {
                canonical_approved_payload,
                receipt,
            } = &invite.terminal
            {
                capture.extend_from_slice(canonical_approved_payload);
                capture.extend_from_slice(&receipt.request_digest.0);
                if let Some(digest) = receipt.approved_payload_digest {
                    capture.extend_from_slice(&digest.0);
                }
            }
        }
        capture
    }
}

impl PairingTransport for InMemoryPairingProvider {
    type JoinClient = InMemoryPairingJoinClient;
    type ApprovalClient = InMemoryPairingApprovalClient;

    fn join_session_client(
        &self,
        session_id: &str,
    ) -> Result<Self::JoinClient, PairingTransportError> {
        Self::join_session_client(self, session_id)
    }

    fn existing_device_client(
        &self,
        scope: SyncScope,
        device_id: DeviceId,
    ) -> Self::ApprovalClient {
        Self::existing_device_client(self, scope, device_id)
    }
}

impl PairingJoinTransport for InMemoryPairingJoinClient {
    fn resolve_code(
        &self,
        code: &PairingCode,
        now_ms: u64,
    ) -> Result<PairingId, PairingTransportError> {
        let mut state = lock(&self.shared)?;
        prune_reported_expired(&mut state);
        if state
            .sessions
            .get(self.session_id.as_ref())
            .is_none_or(|session| session.failed_attempts >= MAX_FAILED_ATTEMPTS)
        {
            return Err(PairingTransportError::Exhausted);
        }

        let matched = state.invites.iter().find_map(|(pairing_id, invite)| {
            code_matches(&self.shared.pepper, code, &invite.code_hmac).then_some(*pairing_id)
        });
        let Some(pairing_id) = matched else {
            let session = state
                .sessions
                .get_mut(self.session_id.as_ref())
                .ok_or(PairingTransportError::Transient)?;
            session.failed_attempts = session.failed_attempts.saturating_add(1);
            return Err(if session.failed_attempts >= MAX_FAILED_ATTEMPTS {
                PairingTransportError::Exhausted
            } else {
                PairingTransportError::Invalid
            });
        };

        let invite = state
            .invites
            .get_mut(&pairing_id)
            .ok_or(PairingTransportError::Transient)?;
        expire_if_due(invite, now_ms);
        require_active(invite)?;
        match invite.located_session.as_deref() {
            None => invite.located_session = Some(self.session_id.to_string()),
            Some(existing) if existing == self.session_id.as_ref() => {}
            Some(_) => return Err(PairingTransportError::Invalid),
        }
        Ok(pairing_id)
    }

    fn submit_request(
        &self,
        pairing_id: PairingId,
        canonical: &[u8],
        now_ms: u64,
    ) -> Result<PairingRequestReceipt, PairingTransportError> {
        if canonical.len() > MAX_PAIRING_REQUEST_BYTES {
            return Err(PairingTransportError::Conflict);
        }
        let request =
            decode_pairing_request_v1(canonical).map_err(|_| PairingTransportError::Conflict)?;
        let verified =
            verify_pairing_request(&request).map_err(|_| PairingTransportError::Conflict)?;
        if request.pairing_id != pairing_id || verified.canonical_bytes() != canonical {
            return Err(PairingTransportError::Conflict);
        }

        let mut state = lock(&self.shared)?;
        prune_reported_expired(&mut state);
        let invite = state
            .invites
            .get_mut(&pairing_id)
            .ok_or(PairingTransportError::Invalid)?;
        expire_if_due(invite, now_ms);
        require_join_session(invite, self.session_id.as_ref())?;
        if matches!(invite.terminal, TerminalState::Expired) {
            invite.expiry_reported = true;
            return Err(PairingTransportError::Expired);
        }

        if let Some(existing) = &invite.request {
            if existing.canonical_bytes == canonical && existing.request_digest == verified.digest()
            {
                return Ok(PairingRequestReceipt {
                    pairing_id,
                    request_digest: existing.request_digest,
                    requested_at_ms: existing.requested_at_ms,
                });
            }
            return Err(PairingTransportError::Conflict);
        }
        require_active(invite)?;
        let stored = StoredPairingRequest {
            pairing_id,
            scope: invite.scope,
            canonical_bytes: canonical.to_vec(),
            request_digest: verified.digest(),
            requested_at_ms: now_ms,
        };
        let receipt = PairingRequestReceipt {
            pairing_id,
            request_digest: stored.request_digest,
            requested_at_ms: stored.requested_at_ms,
        };
        invite.request = Some(stored);
        Ok(receipt)
    }

    fn result(
        &self,
        pairing_id: PairingId,
        digest: Sha256Digest,
        now_ms: u64,
    ) -> Result<PairingResult, PairingTransportError> {
        let mut state = lock(&self.shared)?;
        prune_reported_expired(&mut state);
        let invite = state
            .invites
            .get_mut(&pairing_id)
            .ok_or(PairingTransportError::Invalid)?;
        expire_if_due(invite, now_ms);
        require_join_session(invite, self.session_id.as_ref())?;
        let request = invite
            .request
            .as_ref()
            .ok_or(PairingTransportError::Conflict)?;
        if request.request_digest != digest {
            return Err(PairingTransportError::Conflict);
        }
        match &invite.terminal {
            TerminalState::Active => Ok(PairingResult::Pending),
            TerminalState::Approved {
                canonical_approved_payload,
                receipt,
            } => Ok(PairingResult::Approved(PairingApprovedResult::new(
                canonical_approved_payload.clone(),
                receipt.clone(),
            ))),
            TerminalState::Rejected(receipt) => Ok(PairingResult::Rejected {
                receipt: receipt.clone(),
            }),
            TerminalState::Canceled => Ok(PairingResult::Canceled),
            TerminalState::Expired => {
                invite.expiry_reported = true;
                Err(PairingTransportError::Expired)
            }
        }
    }
}

impl PairingApprovalTransport for InMemoryPairingApprovalClient {
    fn create_invite(&self, now_ms: u64) -> Result<PairingInvite, PairingTransportError> {
        let expires_at_ms = now_ms
            .checked_add(INVITE_LIFETIME_MS)
            .ok_or(PairingTransportError::Transient)?;
        let mut state = lock(&self.shared)?;
        for _ in 0..MAX_ENTROPY_RETRIES {
            let entropy = state.entropy.next()?;
            let pairing_id = pairing_id_from_entropy(now_ms, entropy)?;
            let code = code_from_entropy(entropy)?;
            let code_hmac = code_hmac(&self.shared.pepper, &code)?;
            if state.invites.contains_key(&pairing_id)
                || state
                    .invites
                    .values()
                    .any(|invite| code_matches(&self.shared.pepper, &code, &invite.code_hmac))
            {
                continue;
            }
            state.invites.insert(
                pairing_id,
                InviteRecord {
                    scope: self.scope,
                    creating_device_id: self.device_id,
                    code_hmac,
                    created_at_ms: now_ms,
                    expires_at_ms,
                    located_session: None,
                    request: None,
                    terminal: TerminalState::Active,
                    expiry_reported: false,
                },
            );
            return Ok(PairingInvite {
                pairing_id,
                code,
                created_at_ms: now_ms,
                expires_at_ms,
            });
        }
        Err(PairingTransportError::Transient)
    }

    fn invite_status(
        &self,
        pairing_id: PairingId,
        now_ms: u64,
    ) -> Result<PairingInviteStatus, PairingTransportError> {
        let mut state = lock(&self.shared)?;
        prune_reported_expired(&mut state);
        let invite = state
            .invites
            .get_mut(&pairing_id)
            .ok_or(PairingTransportError::Invalid)?;
        require_approver(invite, self.scope, self.device_id)?;
        expire_if_due(invite, now_ms);
        let status = match &invite.terminal {
            TerminalState::Active => PairingInviteState::Pending,
            TerminalState::Approved { .. } => PairingInviteState::Approved,
            TerminalState::Rejected(_) => PairingInviteState::Rejected,
            TerminalState::Canceled => PairingInviteState::Canceled,
            TerminalState::Expired => {
                invite.expiry_reported = true;
                return Err(PairingTransportError::Expired);
            }
        };
        Ok(PairingInviteStatus {
            pairing_id,
            created_at_ms: invite.created_at_ms,
            expires_at_ms: invite.expires_at_ms,
            state: status,
        })
    }

    fn request(
        &self,
        pairing_id: PairingId,
        now_ms: u64,
    ) -> Result<Option<StoredPairingRequest>, PairingTransportError> {
        let mut state = lock(&self.shared)?;
        prune_reported_expired(&mut state);
        let invite = state
            .invites
            .get_mut(&pairing_id)
            .ok_or(PairingTransportError::Invalid)?;
        require_approver(invite, self.scope, self.device_id)?;
        expire_if_due(invite, now_ms);
        if matches!(invite.terminal, TerminalState::Expired) {
            invite.expiry_reported = true;
            return Err(PairingTransportError::Expired);
        }
        if matches!(invite.terminal, TerminalState::Canceled) {
            return Err(PairingTransportError::Canceled);
        }
        Ok(invite.request.clone())
    }

    fn decide(
        &self,
        envelope: PairingDecisionEnvelope,
        now_ms: u64,
    ) -> Result<PairingDecisionReceipt, PairingTransportError> {
        let mut state = lock(&self.shared)?;
        prune_reported_expired(&mut state);
        let invite = state
            .invites
            .get_mut(&envelope.pairing_id)
            .ok_or(PairingTransportError::Invalid)?;
        require_approver(invite, self.scope, self.device_id)?;
        expire_if_due(invite, now_ms);
        let request = invite
            .request
            .as_ref()
            .ok_or(PairingTransportError::Conflict)?;
        if envelope.request_digest != request.request_digest {
            return Err(PairingTransportError::Conflict);
        }

        if matches!(invite.terminal, TerminalState::Expired) {
            invite.expiry_reported = true;
            return Err(PairingTransportError::Expired);
        }
        match &invite.terminal {
            TerminalState::Canceled => return Err(PairingTransportError::Canceled),
            TerminalState::Expired => unreachable!("expired state was handled above"),
            TerminalState::Rejected(receipt) => {
                return if matches!(envelope.decision(), PairingDecision::Reject) {
                    Ok(receipt.clone())
                } else {
                    Err(PairingTransportError::Rejected)
                };
            }
            TerminalState::Approved {
                canonical_approved_payload,
                receipt,
            } => {
                return match envelope.decision() {
                    PairingDecision::Approve {
                        canonical_approved_payload: retry,
                    } if retry == canonical_approved_payload => Ok(receipt.clone()),
                    _ => Err(PairingTransportError::Conflict),
                };
            }
            TerminalState::Active => {}
        }

        let (terminal, receipt) = match envelope.decision() {
            PairingDecision::Reject => {
                let receipt = PairingDecisionReceipt {
                    pairing_id: envelope.pairing_id,
                    request_digest: request.request_digest,
                    decision: PairingDecisionKind::Rejected,
                    approved_payload_digest: None,
                    decided_at_ms: now_ms,
                };
                (TerminalState::Rejected(receipt.clone()), receipt)
            }
            PairingDecision::Approve {
                canonical_approved_payload,
            } => {
                let approved_payload = validate_approved_payload(
                    canonical_approved_payload,
                    envelope.pairing_id,
                    request,
                    invite.scope,
                    invite.creating_device_id,
                )?;
                let approved_payload_digest =
                    Sha256Digest(Sha256::digest(canonical_approved_payload).into());
                if approved_payload.grant.request_digest != request.request_digest {
                    return Err(PairingTransportError::Conflict);
                }
                let receipt = PairingDecisionReceipt {
                    pairing_id: envelope.pairing_id,
                    request_digest: request.request_digest,
                    decision: PairingDecisionKind::Approved,
                    approved_payload_digest: Some(approved_payload_digest),
                    decided_at_ms: now_ms,
                };
                (
                    TerminalState::Approved {
                        canonical_approved_payload: canonical_approved_payload.clone(),
                        receipt: receipt.clone(),
                    },
                    receipt,
                )
            }
        };
        invite.terminal = terminal;
        Ok(receipt)
    }

    fn cancel(&self, pairing_id: PairingId, now_ms: u64) -> Result<(), PairingTransportError> {
        let mut state = lock(&self.shared)?;
        prune_reported_expired(&mut state);
        let invite = state
            .invites
            .get_mut(&pairing_id)
            .ok_or(PairingTransportError::Invalid)?;
        require_approver(invite, self.scope, self.device_id)?;
        expire_if_due(invite, now_ms);
        match invite.terminal {
            TerminalState::Active => invite.terminal = TerminalState::Canceled,
            TerminalState::Canceled => {}
            TerminalState::Rejected(_) => return Err(PairingTransportError::Rejected),
            TerminalState::Approved { .. } => return Err(PairingTransportError::Conflict),
            TerminalState::Expired => {
                invite.expiry_reported = true;
                return Err(PairingTransportError::Expired);
            }
        }
        Ok(())
    }
}

impl ProviderEntropy {
    fn next(&mut self) -> Result<[u8; 32], PairingTransportError> {
        match self {
            Self::Os => {
                let mut output = [0_u8; 32];
                OsRng
                    .try_fill_bytes(&mut output)
                    .map_err(|_| PairingTransportError::Transient)?;
                Ok(output)
            }
            #[cfg(feature = "test-support")]
            Self::Fixed(values) => values.pop_front().ok_or(PairingTransportError::Transient),
        }
    }
}

fn lock(shared: &SharedProvider) -> Result<MutexGuard<'_, ProviderState>, PairingTransportError> {
    shared
        .state
        .lock()
        .map_err(|_| PairingTransportError::Transient)
}

fn pairing_id_from_entropy(
    now_ms: u64,
    entropy: [u8; 32],
) -> Result<PairingId, PairingTransportError> {
    if now_ms >= (1_u64 << 48) {
        return Err(PairingTransportError::Transient);
    }
    let mut bytes = [0_u8; 16];
    bytes[..6].copy_from_slice(&now_ms.to_be_bytes()[2..]);
    bytes[6..].copy_from_slice(&entropy[..10]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let text = format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    );
    PairingId::from_str(&text).map_err(|_| PairingTransportError::Transient)
}

fn code_from_entropy(entropy: [u8; 32]) -> Result<PairingCode, PairingTransportError> {
    let mut source = [0_u8; 8];
    source[1..].copy_from_slice(&entropy[16..23]);
    let value = u64::from_be_bytes(source) & ((1_u64 << 50) - 1);
    let mut output = String::with_capacity(11);
    for index in 0..10 {
        if index == 5 {
            output.push('-');
        }
        let shift = 45 - index * 5;
        output.push(char::from(CROCKFORD[((value >> shift) & 31) as usize]));
    }
    PairingCode::new(output).map_err(|_| PairingTransportError::Transient)
}

fn code_hmac(pepper: &[u8; 32], code: &PairingCode) -> Result<[u8; 32], PairingTransportError> {
    let mut hmac =
        HmacSha256::new_from_slice(pepper).map_err(|_| PairingTransportError::Transient)?;
    hmac.update(&normalized_code(code));
    Ok(hmac.finalize().into_bytes().into())
}

fn code_matches(pepper: &[u8; 32], code: &PairingCode, expected: &[u8; 32]) -> bool {
    let Ok(mut hmac) = HmacSha256::new_from_slice(pepper) else {
        return false;
    };
    hmac.update(&normalized_code(code));
    hmac.verify_slice(expected).is_ok()
}

fn normalized_code(code: &PairingCode) -> [u8; 10] {
    let mut normalized = [0_u8; 10];
    for (target, byte) in normalized
        .iter_mut()
        .zip(code.as_str().bytes().filter(|byte| *byte != b'-'))
    {
        *target = byte.to_ascii_uppercase();
    }
    normalized
}

fn expire_if_due(invite: &mut InviteRecord, now_ms: u64) {
    if matches!(invite.terminal, TerminalState::Active) && now_ms >= invite.expires_at_ms {
        invite.terminal = TerminalState::Expired;
    }
}

fn require_active(invite: &mut InviteRecord) -> Result<(), PairingTransportError> {
    match invite.terminal {
        TerminalState::Active => Ok(()),
        TerminalState::Approved { .. } => Err(PairingTransportError::Conflict),
        TerminalState::Rejected(_) => Err(PairingTransportError::Rejected),
        TerminalState::Canceled => Err(PairingTransportError::Canceled),
        TerminalState::Expired => {
            invite.expiry_reported = true;
            Err(PairingTransportError::Expired)
        }
    }
}

fn prune_reported_expired(state: &mut ProviderState) {
    state.invites.retain(|_, invite| {
        !matches!(invite.terminal, TerminalState::Expired) || !invite.expiry_reported
    });
}

fn require_join_session(
    invite: &InviteRecord,
    session_id: &str,
) -> Result<(), PairingTransportError> {
    if invite.located_session.as_deref() == Some(session_id) {
        Ok(())
    } else {
        Err(PairingTransportError::Unauthorized)
    }
}

fn require_approver(
    invite: &InviteRecord,
    scope: SyncScope,
    device_id: DeviceId,
) -> Result<(), PairingTransportError> {
    if invite.scope == scope && invite.creating_device_id == device_id {
        Ok(())
    } else {
        Err(PairingTransportError::Unauthorized)
    }
}

fn validate_approved_payload(
    canonical: &[u8],
    pairing_id: PairingId,
    request: &StoredPairingRequest,
    scope: SyncScope,
    approving_device_id: DeviceId,
) -> Result<crate::devices::crypto::PairingApprovedPayloadV1, PairingTransportError> {
    if canonical.len() > MAX_PAIRING_APPROVED_PAYLOAD_BYTES {
        return Err(PairingTransportError::Conflict);
    }
    let request_value = decode_pairing_request_v1(&request.canonical_bytes)
        .map_err(|_| PairingTransportError::Conflict)?;
    let signed_request =
        verify_pairing_request(&request_value).map_err(|_| PairingTransportError::Conflict)?;
    let inspected = inspect_pairing_approval(canonical, &signed_request)
        .map_err(|_| PairingTransportError::Conflict)?;
    let payload = inspected.approved_payload();
    if payload.grant.pairing_id != pairing_id
        || payload.grant.request_digest != request.request_digest
        || payload.issuer_certificate.account_id != scope.account_id
        || payload.issuer_certificate.workspace_id != scope.workspace_id
        || payload.issuer_certificate.device_id != approving_device_id
    {
        return Err(PairingTransportError::Conflict);
    }
    Ok(payload.clone())
}

impl fmt::Debug for InMemoryPairingProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InMemoryPairingProvider([REDACTED])")
    }
}

impl fmt::Debug for InMemoryPairingJoinClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InMemoryPairingJoinClient([REDACTED])")
    }
}

impl fmt::Debug for InMemoryPairingApprovalClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InMemoryPairingApprovalClient")
            .field("scope", &self.scope)
            .field("device_id", &self.device_id)
            .finish_non_exhaustive()
    }
}
