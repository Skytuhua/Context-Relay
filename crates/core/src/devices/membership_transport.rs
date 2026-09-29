//! Addressed public evidence. Retrieval does not accept a membership endpoint.
use context_relay_protocol::{Ed25519SignatureBytes, Sha256Digest, decode_pairing_request_v1};

use super::membership_crypto::MembershipEndpoint;
use super::{
    crypto::{SignedPairingRequest, verify_pairing_request},
    membership_crypto::{DeviceMembershipAddStatementV1, MembershipHistoryEvent},
    revocation_crypto::{DeviceRevocationStatementV1, RevocationTransitionV1},
};
use crate::crypto::CryptoError;
use crate::sync::SyncScope;
use sha2::{Digest, Sha256};

pub fn enrollment_endpoint(
    bytes: &[u8],
    pin: Sha256Digest,
    scope: SyncScope,
) -> Result<MembershipEndpoint, CryptoError> {
    if Sha256Digest(Sha256::digest(bytes).into()) != pin {
        return Err(CryptoError::AuthenticationFailed);
    }
    let record = super::recovery_crypto::decode_recovery_enrollment_record_v1(bytes)
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    let devices = std::collections::BTreeMap::from([(
        record.genesis_certificate.device_id,
        record.genesis_certificate.clone(),
    )]);
    let state =
        super::revocation_crypto::initial_revocation_control_state(&record, pin, scope, &devices)?;
    Ok(MembershipEndpoint {
        state_sha256: state.state_sha256,
        control_epoch: state.control_epoch,
        key_epoch: state.key_epoch,
    })
}

pub const MAX_MEMBERSHIP_OBJECT_BYTES: usize = 16 * 1024 * 1024;
const DOMAIN: &[u8] = b"context-relay/public-membership-event/v1\0";

/// The address is the existing signed successor-state digest. Every component is
/// canonical and immutable; callers must still replay its exact accepted parent.
#[derive(Clone, Eq, PartialEq)]
pub struct MembershipEventObject {
    pub(crate) statement: Vec<u8>,
    pub(crate) signature: Ed25519SignatureBytes,
    pub(crate) request: Option<SignedPairingRequest>,
    pub(crate) artifact: Vec<u8>,
}

impl std::fmt::Debug for MembershipEventObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MembershipEventObject([REDACTED])")
    }
}

impl MembershipEventObject {
    pub fn from_evidence(event: &MembershipHistoryEvent<'_>) -> Result<Self, CryptoError> {
        let (statement, signature, request, artifact) = match event {
            MembershipHistoryEvent::RecoveryAdd { canonical_claim } => {
                let claim = super::recovery_restore_crypto::v2::decode_recovery_device_claim_v2(
                    canonical_claim,
                )
                .map_err(|_| CryptoError::AuthenticationFailed)?;
                (
                    &[][..],
                    claim.recovery_root_signature,
                    None,
                    *canonical_claim,
                )
            }
            MembershipHistoryEvent::PairingAdd {
                statement,
                signature,
                request,
                approved_payload,
            } => (
                *statement,
                *signature,
                Some((*request).clone()),
                *approved_payload,
            ),
            MembershipHistoryEvent::Revocation {
                statement,
                signature,
                transition,
            } => (*statement, *signature, None, *transition),
        };
        if statement
            .len()
            .checked_add(artifact.len())
            .and_then(|n| n.checked_add(request.as_ref().map_or(0, |r| r.canonical_bytes().len())))
            .is_none_or(|n| n > MAX_MEMBERSHIP_OBJECT_BYTES - DOMAIN.len() - 81)
        {
            return Err(CryptoError::InvalidProtocolValue);
        }
        let object = Self {
            statement: statement.to_vec(),
            signature,
            request,
            artifact: artifact.to_vec(),
        };
        object.endpoints()?;
        Ok(object)
    }

    pub fn evidence(&self) -> MembershipHistoryEvent<'_> {
        if self.statement.is_empty() && self.request.is_none() {
            return MembershipHistoryEvent::RecoveryAdd {
                canonical_claim: &self.artifact,
            };
        }
        match &self.request {
            Some(request) => MembershipHistoryEvent::PairingAdd {
                statement: &self.statement,
                signature: self.signature,
                request,
                approved_payload: &self.artifact,
            },
            None => MembershipHistoryEvent::Revocation {
                statement: &self.statement,
                signature: self.signature,
                transition: &self.artifact,
            },
        }
    }

    pub fn endpoints(&self) -> Result<(Sha256Digest, Sha256Digest), CryptoError> {
        if self.statement.is_empty() && self.request.is_none() {
            use super::recovery_restore_crypto::v2::{
                decode_recovery_device_claim_v2, recovery_membership_successor,
            };
            let claim = decode_recovery_device_claim_v2(&self.artifact)
                .map_err(|_| CryptoError::AuthenticationFailed)?;
            if claim.recovery_root_signature != self.signature {
                return Err(CryptoError::AuthenticationFailed);
            }
            return Ok((
                claim.previous_state_sha256,
                recovery_membership_successor(&claim)
                    .map_err(|_| CryptoError::AuthenticationFailed)?,
            ));
        }
        match &self.request {
            Some(_) => {
                let s = DeviceMembershipAddStatementV1::from_signing_preimage(&self.statement)?;
                if s != DeviceMembershipAddStatementV1::from_approved_payload_v2(&self.artifact)? {
                    return Err(CryptoError::AuthenticationFailed);
                }
                Ok((
                    s.previous_state_sha256,
                    s.control_state_sha256(self.signature)?,
                ))
            }
            None => {
                let s = DeviceRevocationStatementV1::from_signing_preimage(&self.statement)?;
                let t = RevocationTransitionV1::from_canonical_bytes(&self.artifact)?;
                Ok((
                    t.previous_state_sha256,
                    s.control_state_sha256(self.signature)?,
                ))
            }
        }
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = DOMAIN.to_vec();
        out.push(if self.statement.is_empty() && self.request.is_none() {
            2
        } else {
            u8::from(self.request.is_some())
        });
        for bytes in [
            &self.statement[..],
            &self.signature.0,
            self.request
                .as_ref()
                .map_or(&[][..], |r| r.canonical_bytes()),
            &self.artifact,
        ] {
            out.extend((bytes.len() as u32).to_be_bytes());
            out.extend(bytes);
        }
        out
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        fn take<'a>(input: &mut &'a [u8], n: usize) -> Result<&'a [u8], CryptoError> {
            let (head, tail) = input
                .split_at_checked(n)
                .ok_or(CryptoError::InvalidProtocolValue)?;
            *input = tail;
            Ok(head)
        }
        fn field<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], CryptoError> {
            let n = u32::from_be_bytes(take(input, 4)?.try_into().unwrap()) as usize;
            take(input, n)
        }
        if bytes.len() > MAX_MEMBERSHIP_OBJECT_BYTES {
            return Err(CryptoError::InvalidProtocolValue);
        }
        let mut input = bytes;
        if take(&mut input, DOMAIN.len())? != DOMAIN {
            return Err(CryptoError::InvalidProtocolValue);
        }
        let kind = take(&mut input, 1)?[0];
        let statement = field(&mut input)?;
        let signature = Ed25519SignatureBytes(
            field(&mut input)?
                .try_into()
                .map_err(|_| CryptoError::InvalidProtocolValue)?,
        );
        let request_bytes = field(&mut input)?;
        let request = match kind {
            0 if request_bytes.is_empty() && !statement.is_empty() => None,
            2 if request_bytes.is_empty() && statement.is_empty() => None,
            1 => Some(verify_pairing_request(
                &decode_pairing_request_v1(request_bytes)
                    .map_err(|_| CryptoError::InvalidProtocolValue)?,
            )?),
            _ => return Err(CryptoError::InvalidProtocolValue),
        };
        let artifact = field(&mut input)?;
        if !input.is_empty() {
            return Err(CryptoError::InvalidProtocolValue);
        }
        let event = match &request {
            None if kind == 2 => MembershipHistoryEvent::RecoveryAdd {
                canonical_claim: artifact,
            },
            Some(request) => MembershipHistoryEvent::PairingAdd {
                statement,
                signature,
                request,
                approved_payload: artifact,
            },
            None => MembershipHistoryEvent::Revocation {
                statement,
                signature,
                transition: artifact,
            },
        };
        let object = Self::from_evidence(&event)?;
        if object.canonical_bytes() != bytes {
            return Err(CryptoError::InvalidProtocolValue);
        }
        Ok(object)
    }
}
