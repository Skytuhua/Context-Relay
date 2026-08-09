use std::{error::Error, fmt};

use context_relay_protocol::{DeviceId, PairingCode, PairingId, Sha256Digest};

use crate::sync::SyncScope;

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum PairingTransportError {
    Invalid,
    Exhausted,
    Expired,
    Canceled,
    Rejected,
    Conflict,
    Unauthorized,
    Transient,
}

impl PairingTransportError {
    pub const fn safe_code(self) -> &'static str {
        match self {
            Self::Invalid => "pairing_invalid",
            Self::Exhausted => "pairing_exhausted",
            Self::Expired => "pairing_expired",
            Self::Canceled => "pairing_canceled",
            Self::Rejected => "pairing_rejected",
            Self::Conflict => "pairing_conflict",
            Self::Unauthorized => "pairing_unauthorized",
            Self::Transient => "transient",
        }
    }
}

impl fmt::Debug for PairingTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.safe_code())
    }
}

impl fmt::Display for PairingTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.safe_code())
    }
}

impl Error for PairingTransportError {}

#[derive(Clone, Eq, PartialEq)]
pub struct PairingInvite {
    pub pairing_id: PairingId,
    pub code: PairingCode,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

impl fmt::Debug for PairingInvite {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingInvite")
            .field("pairing_id", &self.pairing_id)
            .field("code", &"[REDACTED]")
            .field("created_at_ms", &self.created_at_ms)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingInviteStatus {
    pub pairing_id: PairingId,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub state: PairingInviteState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingInviteState {
    Pending,
    Approved,
    Rejected,
    Canceled,
}

#[derive(Clone, Eq, PartialEq)]
pub struct StoredPairingRequest {
    pub pairing_id: PairingId,
    pub scope: SyncScope,
    pub canonical_bytes: Vec<u8>,
    pub request_digest: Sha256Digest,
    pub requested_at_ms: u64,
}

impl fmt::Debug for StoredPairingRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredPairingRequest")
            .field("pairing_id", &self.pairing_id)
            .field("scope", &self.scope)
            .field("request_digest", &self.request_digest)
            .field("requested_at_ms", &self.requested_at_ms)
            .field("canonical_bytes", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingRequestReceipt {
    pub pairing_id: PairingId,
    pub request_digest: Sha256Digest,
    pub requested_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PairingDecisionKind {
    Approved,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PairingDecisionReceipt {
    pub pairing_id: PairingId,
    pub request_digest: Sha256Digest,
    pub decision: PairingDecisionKind,
    pub approved_payload_digest: Option<Sha256Digest>,
    pub decided_at_ms: u64,
}

#[derive(Clone, Eq, PartialEq)]
pub struct PairingDecisionEnvelope {
    pub pairing_id: PairingId,
    pub request_digest: Sha256Digest,
    decision: PairingDecision,
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) enum PairingDecision {
    Approve { canonical_approved_payload: Vec<u8> },
    Reject,
}

impl PairingDecisionEnvelope {
    pub fn approve(
        pairing_id: PairingId,
        request_digest: Sha256Digest,
        canonical_approved_payload: Vec<u8>,
    ) -> Self {
        Self {
            pairing_id,
            request_digest,
            decision: PairingDecision::Approve {
                canonical_approved_payload,
            },
        }
    }

    pub const fn reject(pairing_id: PairingId, request_digest: Sha256Digest) -> Self {
        Self {
            pairing_id,
            request_digest,
            decision: PairingDecision::Reject,
        }
    }

    pub(crate) const fn decision(&self) -> &PairingDecision {
        &self.decision
    }
}

impl fmt::Debug for PairingDecisionEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingDecisionEnvelope")
            .field("pairing_id", &self.pairing_id)
            .field("request_digest", &self.request_digest)
            .field(
                "decision",
                &match self.decision {
                    PairingDecision::Approve { .. } => "approved([REDACTED])",
                    PairingDecision::Reject => "rejected",
                },
            )
            .finish()
    }
}

/// Opaque provider approval returned to the joining coordinator.
///
/// Transport adapters may construct this value, but normal downstream callers cannot extract the
/// canonical approved payload needed to derive the joining device's expected safety number.
///
/// ```compile_fail
/// use context_relay_core::devices::transport::PairingApprovedResult;
///
/// fn expose_payload(result: &PairingApprovedResult) {
///     let _ = result.canonical_approved_payload();
/// }
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct PairingApprovedResult {
    canonical_approved_payload: Vec<u8>,
    receipt: PairingDecisionReceipt,
}

impl PairingApprovedResult {
    pub fn new(canonical_approved_payload: Vec<u8>, receipt: PairingDecisionReceipt) -> Self {
        Self {
            canonical_approved_payload,
            receipt,
        }
    }

    pub(crate) fn canonical_approved_payload(&self) -> &[u8] {
        &self.canonical_approved_payload
    }

    pub(crate) const fn receipt(&self) -> &PairingDecisionReceipt {
        &self.receipt
    }
}

impl fmt::Debug for PairingApprovedResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PairingApprovedResult")
            .field("pairing_id", &self.receipt.pairing_id)
            .field("decision", &self.receipt.decision)
            .field("decided_at_ms", &self.receipt.decided_at_ms)
            .field("canonical_approved_payload", &"[REDACTED]")
            .field("request_and_approved_payload_digests", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub enum PairingResult {
    Pending,
    Approved(PairingApprovedResult),
    Rejected { receipt: PairingDecisionReceipt },
    Canceled,
}

impl fmt::Debug for PairingResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => formatter.write_str("PairingResult::Pending"),
            Self::Approved(approved) => formatter
                .debug_struct("PairingResult::Approved")
                .field("result", approved)
                .finish(),
            Self::Rejected { receipt } => formatter
                .debug_struct("PairingResult::Rejected")
                .field("receipt", receipt)
                .finish(),
            Self::Canceled => formatter.write_str("PairingResult::Canceled"),
        }
    }
}

pub trait PairingJoinTransport: Send + Sync {
    fn resolve_code(
        &self,
        code: &PairingCode,
        now_ms: u64,
    ) -> Result<PairingId, PairingTransportError>;

    fn submit_request(
        &self,
        pairing_id: PairingId,
        canonical: &[u8],
        now_ms: u64,
    ) -> Result<PairingRequestReceipt, PairingTransportError>;

    fn result(
        &self,
        pairing_id: PairingId,
        digest: Sha256Digest,
        now_ms: u64,
    ) -> Result<PairingResult, PairingTransportError>;
}

pub trait PairingApprovalTransport: Send + Sync {
    fn create_invite(&self, now_ms: u64) -> Result<PairingInvite, PairingTransportError>;

    fn invite_status(
        &self,
        pairing_id: PairingId,
        now_ms: u64,
    ) -> Result<PairingInviteStatus, PairingTransportError>;

    fn request(
        &self,
        pairing_id: PairingId,
        now_ms: u64,
    ) -> Result<Option<StoredPairingRequest>, PairingTransportError>;

    fn decide(
        &self,
        envelope: PairingDecisionEnvelope,
        now_ms: u64,
    ) -> Result<PairingDecisionReceipt, PairingTransportError>;

    fn cancel(&self, pairing_id: PairingId, now_ms: u64) -> Result<(), PairingTransportError>;
}

pub trait PairingTransport: Send + Sync {
    type JoinClient: PairingJoinTransport;
    type ApprovalClient: PairingApprovalTransport;

    fn join_session_client(
        &self,
        session_id: &str,
    ) -> Result<Self::JoinClient, PairingTransportError>;

    fn existing_device_client(&self, scope: SyncScope, device_id: DeviceId)
    -> Self::ApprovalClient;
}
