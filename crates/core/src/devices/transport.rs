use std::{error::Error, fmt};

use super::{membership_crypto::MembershipEndpoint, membership_transport::MembershipEventObject};
use context_relay_protocol::{
    DeviceId, Ed25519SignatureBytes, OperationId, PairingCode, PairingId, Sha256Digest,
};

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MembershipObjectKind {
    Enrollment,
    Event,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceOperationHead {
    pub sequence: u64,
    pub canonical_sha256: Sha256Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceRevocationContext {
    pub endpoint: MembershipEndpoint,
    pub target_device_id: DeviceId,
    pub head: DeviceOperationHead,
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
    canonical_request: Option<Vec<u8>>,
    membership_signature: Option<Ed25519SignatureBytes>,
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
            canonical_request: None,
            membership_signature: None,
        }
    }

    pub fn approve_request(
        request: &super::crypto::SignedPairingRequest,
        canonical_approved_payload: Vec<u8>,
    ) -> Self {
        let mut envelope = Self::approve(
            request.request().pairing_id,
            request.digest(),
            canonical_approved_payload,
        );
        envelope.canonical_request = Some(request.canonical_bytes().to_vec());
        envelope
    }

    pub(crate) fn canonical_request(&self) -> Option<&[u8]> {
        self.canonical_request.as_deref()
    }

    pub fn approve_request_v2(
        request: &super::crypto::SignedPairingRequest,
        canonical: Vec<u8>,
        signature: Ed25519SignatureBytes,
    ) -> Self {
        let mut envelope = Self::approve_request(request, canonical);
        envelope.membership_signature = Some(signature);
        envelope
    }

    pub(crate) fn membership_signature(&self) -> Option<Ed25519SignatureBytes> {
        self.membership_signature
    }

    pub const fn reject(pairing_id: PairingId, request_digest: Sha256Digest) -> Self {
        Self {
            pairing_id,
            request_digest,
            decision: PairingDecision::Reject,
            canonical_request: None,
            membership_signature: None,
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
    membership_signature: Option<Ed25519SignatureBytes>,
}

impl PairingApprovedResult {
    pub fn new(canonical_approved_payload: Vec<u8>, receipt: PairingDecisionReceipt) -> Self {
        Self {
            canonical_approved_payload,
            receipt,
            membership_signature: None,
        }
    }

    pub fn new_v2(
        canonical: Vec<u8>,
        receipt: PairingDecisionReceipt,
        signature: Ed25519SignatureBytes,
    ) -> Self {
        Self {
            canonical_approved_payload: canonical,
            receipt,
            membership_signature: Some(signature),
        }
    }
    pub(crate) fn membership_signature(&self) -> Option<Ed25519SignatureBytes> {
        self.membership_signature
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
    /// Bound by the provider to this original pairing session and request.
    fn enrollment(
        &self,
        _pairing_id: PairingId,
        _request: Sha256Digest,
        _pin: Sha256Digest,
        _now_ms: u64,
    ) -> Result<Option<Vec<u8>>, PairingTransportError> {
        Err(PairingTransportError::Unauthorized)
    }
    fn membership_event(
        &self,
        _pairing_id: PairingId,
        _request: Sha256Digest,
        _address: Sha256Digest,
        _now_ms: u64,
    ) -> Result<Option<MembershipEventObject>, PairingTransportError> {
        Err(PairingTransportError::Unauthorized)
    }
    fn hosted_intent(&self) -> Option<crate::vault::HostedPairingIntent> {
        None
    }
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
    /// Initializes from committed enrollment on the server, never uploaded roster data.
    fn membership_endpoint(
        &self,
        _now_ms: u64,
    ) -> Result<MembershipEndpoint, PairingTransportError> {
        Err(PairingTransportError::Unauthorized)
    }
    fn membership_object(
        &self,
        _kind: MembershipObjectKind,
        _address: Sha256Digest,
        _now_ms: u64,
    ) -> Result<Option<Vec<u8>>, PairingTransportError> {
        Err(PairingTransportError::Unauthorized)
    }
    fn revocation_context(
        &self,
        _target: DeviceId,
        _now_ms: u64,
    ) -> Result<DeviceRevocationContext, PairingTransportError> {
        Err(PairingTransportError::Unauthorized)
    }
    fn revocation_result(
        &self,
        _operation_id: OperationId,
        _object_sha256: Sha256Digest,
        _now_ms: u64,
    ) -> Result<Option<crate::vault::DeviceRevocationReceipt>, PairingTransportError> {
        Err(PairingTransportError::Unauthorized)
    }
    fn publish_revocation(
        &self,
        _object: &MembershipEventObject,
        _now_ms: u64,
    ) -> Result<crate::vault::DeviceRevocationReceipt, PairingTransportError> {
        Err(PairingTransportError::Unauthorized)
    }
    fn hosted_intent(&self) -> Option<crate::vault::HostedPairingIntent> {
        None
    }
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

/// Fresh joining devices have no approval authority or scoped approval client.
impl<T: PairingApprovalTransport> PairingApprovalTransport for Option<T> {
    fn membership_endpoint(
        &self,
        now_ms: u64,
    ) -> Result<MembershipEndpoint, PairingTransportError> {
        self.as_ref()
            .ok_or(PairingTransportError::Unauthorized)?
            .membership_endpoint(now_ms)
    }
    fn hosted_intent(&self) -> Option<crate::vault::HostedPairingIntent> {
        self.as_ref()
            .and_then(PairingApprovalTransport::hosted_intent)
    }
    fn membership_object(
        &self,
        kind: MembershipObjectKind,
        address: Sha256Digest,
        now_ms: u64,
    ) -> Result<Option<Vec<u8>>, PairingTransportError> {
        self.as_ref()
            .ok_or(PairingTransportError::Unauthorized)?
            .membership_object(kind, address, now_ms)
    }
    fn revocation_context(
        &self,
        target: DeviceId,
        now_ms: u64,
    ) -> Result<DeviceRevocationContext, PairingTransportError> {
        self.as_ref()
            .ok_or(PairingTransportError::Unauthorized)?
            .revocation_context(target, now_ms)
    }
    fn revocation_result(
        &self,
        operation_id: OperationId,
        object_sha256: Sha256Digest,
        now_ms: u64,
    ) -> Result<Option<crate::vault::DeviceRevocationReceipt>, PairingTransportError> {
        self.as_ref()
            .ok_or(PairingTransportError::Unauthorized)?
            .revocation_result(operation_id, object_sha256, now_ms)
    }
    fn publish_revocation(
        &self,
        object: &MembershipEventObject,
        now_ms: u64,
    ) -> Result<crate::vault::DeviceRevocationReceipt, PairingTransportError> {
        self.as_ref()
            .ok_or(PairingTransportError::Unauthorized)?
            .publish_revocation(object, now_ms)
    }
    fn create_invite(&self, now_ms: u64) -> Result<PairingInvite, PairingTransportError> {
        self.as_ref()
            .ok_or(PairingTransportError::Unauthorized)?
            .create_invite(now_ms)
    }
    fn invite_status(
        &self,
        id: PairingId,
        now_ms: u64,
    ) -> Result<PairingInviteStatus, PairingTransportError> {
        self.as_ref()
            .ok_or(PairingTransportError::Unauthorized)?
            .invite_status(id, now_ms)
    }
    fn request(
        &self,
        id: PairingId,
        now_ms: u64,
    ) -> Result<Option<StoredPairingRequest>, PairingTransportError> {
        self.as_ref()
            .ok_or(PairingTransportError::Unauthorized)?
            .request(id, now_ms)
    }
    fn decide(
        &self,
        envelope: PairingDecisionEnvelope,
        now_ms: u64,
    ) -> Result<PairingDecisionReceipt, PairingTransportError> {
        self.as_ref()
            .ok_or(PairingTransportError::Unauthorized)?
            .decide(envelope, now_ms)
    }
    fn cancel(&self, id: PairingId, now_ms: u64) -> Result<(), PairingTransportError> {
        self.as_ref()
            .ok_or(PairingTransportError::Unauthorized)?
            .cancel(id, now_ms)
    }
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
