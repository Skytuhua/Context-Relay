//! Public admission authorization and bounded complete ancestry, never key activation
//! or global freshness. Enrollment pin and exact endpoint must be independently trusted.
use super::{
    crypto::{
        SignedPairingRequest, certificate_digest,
        control_v2::{
            PairingParentV2, decode_pairing_approved_payload_v2, inspect_pairing_approval_v2,
        },
    },
    recovery_crypto::decode_recovery_enrollment_record_v1,
    revocation_crypto::{
        DeviceRevocationStatementV1, RevocationControlState, RevocationTransitionV1,
        VerifiedRevocationControl, initial_revocation_control_state,
    },
};
use crate::{
    crypto::{CryptoError, DeviceCertificateV1, DeviceKeys, verify_signature},
    sync::SyncScope,
};
use context_relay_protocol::{
    AccountId, DeviceCertificateId, DeviceId, Ed25519SignatureBytes, OperationId, RecoveryRootId,
    Sha256Digest, WorkspaceId, X25519PublicKeyBytes,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const DOMAIN: &[u8] = b"context-relay/device-membership-add/v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceMembershipAddStatementV1 {
    pub schema_version: u16,
    pub membership_id: OperationId,
    pub account_id: AccountId,
    pub workspace_id: WorkspaceId,
    pub previous_state_sha256: Sha256Digest,
    pub control_epoch: u32,
    pub key_epoch: u32,
    pub issuer_device_id: DeviceId,
    pub certificate_id: DeviceCertificateId,
    pub certificate_sha256: Sha256Digest,
    pub authorization_artifact_sha256: Sha256Digest,
}

impl DeviceMembershipAddStatementV1 {
    /// Construct proposed evidence from canonical V2 bytes; this grants no authority.
    pub fn from_approved_payload_v2(canonical: &[u8]) -> Result<Self, CryptoError> {
        let p = decode_pairing_approved_payload_v2(canonical)?;
        Ok(Self {
            schema_version: 1,
            membership_id: OperationId::new(uuid::Uuid::from_bytes(*p.grant.pairing_id.as_bytes()))
                .map_err(|_| CryptoError::InvalidProtocolValue)?,
            account_id: p.grant.certificate.account_id,
            workspace_id: p.grant.certificate.workspace_id,
            previous_state_sha256: p.previous_state_sha256,
            control_epoch: p.grant.certificate.control_epoch,
            key_epoch: p.grant.key_epoch,
            issuer_device_id: p.issuer_certificate.device_id,
            certificate_id: p.grant.certificate_id,
            certificate_sha256: certificate_digest(&p.grant.certificate)?,
            authorization_artifact_sha256: Sha256Digest(Sha256::digest(canonical).into()),
        })
    }

    pub fn signing_preimage(&self) -> Result<Vec<u8>, CryptoError> {
        if self.schema_version != 1
            || self.control_epoch == 0
            || self.key_epoch == 0
            || [
                self.previous_state_sha256,
                self.certificate_sha256,
                self.authorization_artifact_sha256,
            ]
            .iter()
            .any(|h| h.0 == [0; 32])
        {
            return Err(CryptoError::InvalidProtocolValue);
        }
        let mut out = DOMAIN.to_vec();
        out.extend_from_slice(&self.schema_version.to_be_bytes());
        out.extend_from_slice(self.membership_id.as_bytes());
        out.extend_from_slice(self.account_id.as_bytes());
        out.extend_from_slice(self.workspace_id.as_bytes());
        out.extend_from_slice(&self.previous_state_sha256.0);
        out.extend_from_slice(&self.control_epoch.to_be_bytes());
        out.extend_from_slice(&self.key_epoch.to_be_bytes());
        out.extend_from_slice(self.issuer_device_id.as_bytes());
        out.extend_from_slice(self.certificate_id.as_bytes());
        out.extend_from_slice(&self.certificate_sha256.0);
        out.extend_from_slice(&self.authorization_artifact_sha256.0);
        Ok(out)
    }

    pub fn from_signing_preimage(bytes: &[u8]) -> Result<Self, CryptoError> {
        let invalid = CryptoError::InvalidProtocolValue;
        if bytes.len() != DOMAIN.len() + 186 {
            return Err(invalid);
        }
        let mut input = bytes.strip_prefix(DOMAIN).ok_or(invalid)?;
        fn take<const N: usize>(input: &mut &[u8]) -> [u8; N] {
            let (head, tail) = input.split_at(N);
            *input = tail;
            head.try_into().expect("fixed statement length checked")
        }
        let s = Self {
            schema_version: u16::from_be_bytes(take(&mut input)),
            membership_id: OperationId::new(uuid::Uuid::from_bytes(take(&mut input)))
                .map_err(|_| invalid)?,
            account_id: AccountId::new(uuid::Uuid::from_bytes(take(&mut input)))
                .map_err(|_| invalid)?,
            workspace_id: WorkspaceId::new(uuid::Uuid::from_bytes(take(&mut input)))
                .map_err(|_| invalid)?,
            previous_state_sha256: Sha256Digest(take(&mut input)),
            control_epoch: u32::from_be_bytes(take(&mut input)),
            key_epoch: u32::from_be_bytes(take(&mut input)),
            issuer_device_id: DeviceId::new(uuid::Uuid::from_bytes(take(&mut input)))
                .map_err(|_| invalid)?,
            certificate_id: DeviceCertificateId::new(uuid::Uuid::from_bytes(take(&mut input)))
                .map_err(|_| invalid)?,
            certificate_sha256: Sha256Digest(take(&mut input)),
            authorization_artifact_sha256: Sha256Digest(take(&mut input)),
        };
        if !input.is_empty() || s.signing_preimage()? != bytes {
            return Err(invalid);
        }
        Ok(s)
    }

    pub fn control_state_sha256(
        &self,
        signature: Ed25519SignatureBytes,
    ) -> Result<Sha256Digest, CryptoError> {
        let mut h = Sha256::new();
        h.update(b"context-relay/membership-control-state/v1\0");
        h.update(self.signing_preimage()?);
        h.update(signature.0);
        Ok(Sha256Digest(h.finalize().into()))
    }

    /// Proposed signed evidence; the certificate must already be authenticated.
    pub fn sign(
        &self,
        certificate: &DeviceCertificateV1,
        keys: &DeviceKeys,
    ) -> Result<Ed25519SignatureBytes, CryptoError> {
        if certificate.device_id != self.issuer_device_id
            || certificate.account_id != self.account_id
            || certificate.workspace_id != self.workspace_id
            || certificate.control_epoch == 0
            || certificate.control_epoch > self.control_epoch
            || certificate.signing_public_key != keys.signing_public_key()
            || certificate.wrapping_public_key != keys.wrapping_public_key()
        {
            return Err(CryptoError::AuthenticationFailed);
        }
        Ok(keys.sign_hosted_device_proof(&self.signing_preimage()?))
    }

    /// Conditional on this caller-authenticated parent; lifetime first-admission
    /// uniqueness is established only by verify_membership_history.
    pub fn verify_and_advance(
        &self,
        signature: Ed25519SignatureBytes,
        request: &SignedPairingRequest,
        canonical_payload: &[u8],
        parent: &PairingParentV2<'_>,
    ) -> Result<VerifiedMembershipControl, CryptoError> {
        let preimage = self.signing_preimage()?;
        let p = inspect_pairing_approval_v2(canonical_payload, request, parent)?;
        let s = &parent.state;
        if self.account_id != s.scope.account_id
            || self.workspace_id != s.scope.workspace_id
            || self.previous_state_sha256 != s.state_sha256
            || self.control_epoch != s.control_epoch
            || self.key_epoch != s.key_epoch
            || self.issuer_device_id != p.issuer_certificate.device_id
            || self.membership_id.as_bytes() != p.grant.pairing_id.as_bytes()
            || self.certificate_id != p.grant.certificate_id
            || self.certificate_sha256 != certificate_digest(&p.grant.certificate)?
            || self.authorization_artifact_sha256
                != Sha256Digest(Sha256::digest(canonical_payload).into())
        {
            return Err(CryptoError::AuthenticationFailed);
        }
        verify_signature(
            p.issuer_certificate.signing_public_key,
            &preimage,
            signature,
        )?;
        let mut state = OwnedControl::from_state(s);
        state
            .active_devices
            .insert(p.grant.certificate.device_id, p.grant.certificate);
        state.endpoint.state_sha256 = self.control_state_sha256(signature)?;
        Ok(VerifiedMembershipControl {
            statement: self.clone(),
            state,
        })
    }
}

/// Public admission proof only: no assertion of human confirmation or decryption.
pub struct VerifiedMembershipControl {
    statement: DeviceMembershipAddStatementV1,
    state: OwnedControl,
}
impl VerifiedMembershipControl {
    pub fn statement(&self) -> &DeviceMembershipAddStatementV1 {
        &self.statement
    }

    pub fn state(&self) -> RevocationControlState<'_> {
        self.state.state()
    }
}

/// Exact independently accepted endpoint. Epochs alone do not order additions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MembershipEndpoint {
    pub state_sha256: Sha256Digest,
    pub control_epoch: u32,
    pub key_epoch: u32,
}
struct OwnedControl {
    scope: SyncScope,
    endpoint: MembershipEndpoint,
    active_devices: BTreeMap<DeviceId, DeviceCertificateV1>,
    recovery_root_id: RecoveryRootId,
    recovery_wrapping_public_key: X25519PublicKeyBytes,
}
impl OwnedControl {
    fn from_state(s: &RevocationControlState<'_>) -> Self {
        Self {
            scope: s.scope,
            endpoint: MembershipEndpoint {
                state_sha256: s.state_sha256,
                control_epoch: s.control_epoch,
                key_epoch: s.key_epoch,
            },
            active_devices: s.active_devices.clone(),
            recovery_root_id: s.recovery_root_id,
            recovery_wrapping_public_key: s.recovery_wrapping_public_key,
        }
    }
    fn state(&self) -> RevocationControlState<'_> {
        RevocationControlState {
            scope: self.scope,
            state_sha256: self.endpoint.state_sha256,
            control_epoch: self.endpoint.control_epoch,
            key_epoch: self.endpoint.key_epoch,
            active_devices: &self.active_devices,
            recovery_root_id: self.recovery_root_id,
            recovery_wrapping_public_key: self.recovery_wrapping_public_key,
        }
    }
}

/// Canonical evidence, chronologically ordered. Repeated entries are invalid,
/// including retries; retry lookup belongs outside the ancestry stream.
pub enum MembershipHistoryEvent<'a> {
    PairingAdd {
        statement: &'a [u8],
        signature: Ed25519SignatureBytes,
        request: &'a SignedPairingRequest,
        approved_payload: &'a [u8],
    },
    Revocation {
        statement: &'a [u8],
        signature: Ed25519SignatureBytes,
        transition: &'a [u8],
    },
}

/// Per-call limits, not protocol lifetime limits. Bytes include enrollment, all
/// statement preimages, detached signatures, requests, payloads and transitions.
#[derive(Clone, Copy)]
pub struct MembershipHistoryBudget {
    pub max_events: usize,
    pub max_bytes: usize,
}

/// Complete only up to the independently supplied endpoint; an unknown withheld
/// newer tail or unseen fork cannot be detected by this proof.
pub struct VerifiedMembershipHistory {
    state: OwnedControl,
    enrollment_record_sha256: Sha256Digest,
    admissions: BTreeMap<DeviceId, DeviceCertificateId>,
    certificates: BTreeSet<DeviceCertificateId>,
    operations: BTreeSet<OperationId>,
    latest_rotation: Option<(VerifiedRevocationControl, RevocationTransitionV1)>,
}
impl VerifiedMembershipHistory {
    pub fn state(&self) -> RevocationControlState<'_> {
        self.state.state()
    }
    pub fn endpoint(&self) -> MembershipEndpoint {
        self.state.endpoint
    }
    pub fn admissions(&self) -> &BTreeMap<DeviceId, DeviceCertificateId> {
        &self.admissions
    }
    /// The staged opener and full replay enforce the same lifetime first-admission
    /// rules, including the shared addition/revocation operation-ID namespace.
    pub(crate) fn ensure_new_admission(
        &self,
        operation: OperationId,
        device: DeviceId,
        certificate: DeviceCertificateId,
    ) -> Result<(), CryptoError> {
        if self.operations.contains(&operation)
            || self.admissions.contains_key(&device)
            || self.certificates.contains(&certificate)
        {
            return Err(CryptoError::AuthenticationFailed);
        }
        Ok(())
    }

    /// Supplies actual authenticated parent/issuer IDs and the latest rotation
    /// from this complete history, including through later key-preserving adds.
    pub fn pairing_parent(&self, issuer: DeviceId) -> Result<PairingParentV2<'_>, CryptoError> {
        if !self.state.active_devices.contains_key(&issuer) {
            return Err(CryptoError::AuthenticationFailed);
        }
        Ok(PairingParentV2 {
            state: self.state(),
            issuer_certificate_id: *self
                .admissions
                .get(&issuer)
                .ok_or(CryptoError::AuthenticationFailed)?,
            enrollment_record_sha256: self.enrollment_record_sha256,
            latest_rotation: self.latest_rotation.as_ref().map(|(v, t)| (v, t)),
        })
    }
}

/// Verify every parent edge from root-only enrollment genesis. Never pass a pin
/// or endpoint selected solely by the same provider supplying this evidence.
/// Budget exhaustion is an error, never success with an accepted prefix.
pub fn verify_membership_history(
    canonical_enrollment: &[u8],
    independent_enrollment_pin: Sha256Digest,
    scope: SyncScope,
    events: &[MembershipHistoryEvent<'_>],
    independent_endpoint: MembershipEndpoint,
    budget: MembershipHistoryBudget,
) -> Result<VerifiedMembershipHistory, CryptoError> {
    let invalid = CryptoError::AuthenticationFailed;
    if events.len() > budget.max_events {
        return Err(CryptoError::InvalidProtocolValue);
    }
    let mut remaining = budget
        .max_bytes
        .checked_sub(canonical_enrollment.len())
        .ok_or(CryptoError::InvalidProtocolValue)?;
    // Account all input before decoding/cloning any variable-sized event.
    for event in events {
        let sizes = match event {
            MembershipHistoryEvent::PairingAdd {
                statement,
                request,
                approved_payload,
                ..
            } => [
                statement.len(),
                64,
                request.canonical_bytes().len(),
                approved_payload.len(),
            ],
            MembershipHistoryEvent::Revocation {
                statement,
                transition,
                ..
            } => [statement.len(), 64, transition.len(), 0],
        };
        for size in sizes {
            remaining = remaining
                .checked_sub(size)
                .ok_or(CryptoError::InvalidProtocolValue)?;
        }
    }
    if independent_enrollment_pin.0 == [0; 32]
        || Sha256Digest(Sha256::digest(canonical_enrollment).into()) != independent_enrollment_pin
    {
        return Err(invalid);
    }
    // Decoder verifies canonical encoding, enrollment signature and root-issued certificate.
    let record = decode_recovery_enrollment_record_v1(canonical_enrollment).map_err(|_| invalid)?;
    let genesis = BTreeMap::from([(
        record.genesis_certificate.device_id,
        record.genesis_certificate.clone(),
    )]);
    let initial =
        initial_revocation_control_state(&record, independent_enrollment_pin, scope, &genesis)?;
    let mut history = VerifiedMembershipHistory {
        state: OwnedControl::from_state(&initial),
        enrollment_record_sha256: independent_enrollment_pin,
        admissions: BTreeMap::from([(
            record.genesis_certificate.device_id,
            record.genesis_certificate_id,
        )]),
        certificates: BTreeSet::from([record.genesis_certificate_id]),
        operations: BTreeSet::new(),
        latest_rotation: None,
    };
    for event in events {
        match event {
            MembershipHistoryEvent::PairingAdd {
                statement,
                signature,
                request,
                approved_payload,
            } => {
                let s = DeviceMembershipAddStatementV1::from_signing_preimage(statement)?;
                let p = decode_pairing_approved_payload_v2(approved_payload)?;
                history.ensure_new_admission(
                    s.membership_id,
                    p.grant.certificate.device_id,
                    s.certificate_id,
                )?;
                let parent = history.pairing_parent(s.issuer_device_id)?;
                let next = s.verify_and_advance(*signature, request, approved_payload, &parent)?;
                history.operations.insert(s.membership_id);
                history.certificates.insert(s.certificate_id);
                history
                    .admissions
                    .insert(p.grant.certificate.device_id, s.certificate_id);
                history.state = next.state;
            }
            MembershipHistoryEvent::Revocation {
                statement,
                signature,
                transition,
            } => {
                let s = DeviceRevocationStatementV1::from_signing_preimage(statement)?;
                if !history.operations.insert(s.revocation_id) {
                    return Err(invalid);
                }
                let t = RevocationTransitionV1::from_canonical_bytes(transition)?;
                let next = t.verify_and_advance(&s, *signature, &history.state())?;
                history.state = OwnedControl::from_state(&next.state());
                history.latest_rotation = Some((next, t));
            }
        }
    }
    if history.endpoint() != independent_endpoint {
        return Err(invalid);
    }
    Ok(history)
}
