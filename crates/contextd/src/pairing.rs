#![cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "the hosted pairing adapter is not configured in this build"
    )
)]

use std::str::FromStr;

use context_relay_core::{
    crypto::DeviceKeys,
    devices::{
        crypto::{pairing_request_fingerprint, verify_pairing_request},
        pairing::{
            PairingApprovalAuthority, PairingClock, PairingCoordinator, PairingCycleError,
            PairingDecisionInput, PairingDecisionStatus, PairingJoinStatus, PairingMaterialSource,
            PairingRequestReview,
        },
        transport::{
            PairingApprovalTransport, PairingInvite, PairingInviteState, PairingInviteStatus,
            PairingJoinTransport,
        },
    },
    sync::SyncScope,
    vault::{DeviceCertificateState, Vault},
};
use context_relay_protocol::{
    ClientError, DecimalTimestamp, DeviceCertificateId, DeviceId, DeviceState, DeviceSummary,
    ErrorCode, LocalRequest, LocalResult, NativePlatform, PairingApprovalInfo,
    PairingCompletionInfo, PairingId, PairingInviteInfo, PairingInviteStatusInfo,
    PairingRequestInfo, PairingSafetyNumber, PairingState, decode_pairing_request_v1,
};
use sha2::{Digest, Sha256};

pub(crate) struct PairingIdentity {
    pub(crate) device_id: DeviceId,
    pub(crate) device_name: String,
    pub(crate) platform: NativePlatform,
    pub(crate) keys: DeviceKeys,
}

pub(crate) trait PairingService: Send + Sync {
    fn resume_prepared_decisions(&self, vault: &mut Vault) -> Result<(), ClientError>;

    fn execute(
        &self,
        vault: &mut Vault,
        identity: &PairingIdentity,
        request: LocalRequest,
    ) -> Result<LocalResult, ClientError>;
}

pub(crate) struct CoordinatorPairingService<C, M, J, A> {
    coordinator: PairingCoordinator<C, M, J, A>,
    scope: SyncScope,
    issuer_certificate_id: DeviceCertificateId,
}

impl<C, M, J, A> CoordinatorPairingService<C, M, J, A> {
    pub(crate) fn new(
        coordinator: PairingCoordinator<C, M, J, A>,
        scope: SyncScope,
        issuer_certificate_id: DeviceCertificateId,
    ) -> Self {
        Self {
            coordinator,
            scope,
            issuer_certificate_id,
        }
    }
}

impl<
    C: PairingClock,
    M: PairingMaterialSource,
    J: PairingJoinTransport,
    A: PairingApprovalTransport,
> PairingService for CoordinatorPairingService<C, M, J, A>
{
    fn resume_prepared_decisions(&self, vault: &mut Vault) -> Result<(), ClientError> {
        self.coordinator
            .resume_prepared_decisions(vault)
            .map(|_| ())
            .map_err(pairing_error)
    }

    fn execute(
        &self,
        vault: &mut Vault,
        identity: &PairingIdentity,
        request: LocalRequest,
    ) -> Result<LocalResult, ClientError> {
        match request {
            LocalRequest::PairingCreate(_) => {
                let invite = self.coordinator.create_invite().map_err(pairing_error)?;
                Ok(invite_result(&invite, PairingState::Pending))
            }
            LocalRequest::PairingJoin(params) => {
                if params.device_name != identity.device_name {
                    return Err(pairing_invalid());
                }
                let submission = self
                    .coordinator
                    .join(
                        vault,
                        &params.code,
                        identity.device_id,
                        &identity.device_name,
                        identity.platform,
                        &identity.keys,
                    )
                    .map_err(pairing_error)?;
                let request = stored_join_review(vault, submission.pairing_id)?;
                Ok(request_result(request, PairingState::Pending))
            }
            LocalRequest::PairingStatus(params) => self.status(vault, identity, params.pairing_id),
            LocalRequest::PairingDecision(params) => {
                let review = self
                    .coordinator
                    .request_status(params.pairing_id)
                    .map_err(pairing_error)?
                    .ok_or_else(pairing_not_found)?;
                if review.request_digest != params.request_digest {
                    return Err(pairing_conflict());
                }
                let decision = if params.approve {
                    PairingDecisionInput::Approve(PairingApprovalAuthority {
                        certificate_id: child_certificate_id(params.pairing_id, self.scope),
                        issuer_certificate_id: self.issuer_certificate_id,
                        issuer_keys: &identity.keys,
                    })
                } else {
                    PairingDecisionInput::Reject
                };
                match self
                    .coordinator
                    .decide(vault, params.pairing_id, params.request_digest, decision)
                    .map_err(pairing_error)?
                {
                    PairingDecisionStatus::Approved { safety_number } => {
                        Ok(LocalResult::PairingApproval {
                            approval: PairingApprovalInfo {
                                request: request_info(review),
                                safety_number: PairingSafetyNumber::new(
                                    safety_number.as_str().to_owned(),
                                )
                                .map_err(|_| pairing_invalid())?,
                            },
                        })
                    }
                    PairingDecisionStatus::Rejected => {
                        Ok(request_result(review, PairingState::Rejected))
                    }
                }
            }
            LocalRequest::PairingConfirm(params) => {
                let material = self
                    .coordinator
                    .confirm_join(
                        vault,
                        params.pairing_id,
                        params.safety_number.as_str(),
                        &identity.keys,
                    )
                    .map_err(pairing_error)?;
                completion_result(
                    vault,
                    material.scope(),
                    params.pairing_id,
                    identity.device_id,
                )
            }
            LocalRequest::PairingCancel(params) => {
                self.coordinator
                    .cancel(params.pairing_id)
                    .map_err(pairing_error)?;
                Ok(LocalResult::Empty)
            }
            _ => Err(pairing_invalid()),
        }
    }
}

impl<
    C: PairingClock,
    M: PairingMaterialSource,
    J: PairingJoinTransport,
    A: PairingApprovalTransport,
> CoordinatorPairingService<C, M, J, A>
{
    fn status(
        &self,
        vault: &mut Vault,
        identity: &PairingIdentity,
        pairing_id: PairingId,
    ) -> Result<LocalResult, ClientError> {
        if vault
            .stored_pairing_join(pairing_id)
            .map_err(|_| pairing_invalid())?
            .is_some()
        {
            let review = stored_join_review(vault, pairing_id)?;
            return match self
                .coordinator
                .join_status(vault, pairing_id)
                .map_err(pairing_error)?
            {
                PairingJoinStatus::Pending { .. } => {
                    Ok(request_result(review, PairingState::Pending))
                }
                PairingJoinStatus::AwaitingConfirmation { .. } => {
                    Ok(request_result(review, PairingState::Approved))
                }
                PairingJoinStatus::Completed { .. } => completion_result(
                    vault,
                    self.coordinator
                        .completed_material(vault, pairing_id, &identity.keys)
                        .map_err(pairing_error)?
                        .ok_or_else(pairing_not_found)?
                        .scope(),
                    pairing_id,
                    identity.device_id,
                ),
                PairingJoinStatus::Rejected { .. } => {
                    Ok(request_result(review, PairingState::Rejected))
                }
                PairingJoinStatus::Canceled { .. } => {
                    Ok(request_result(review, PairingState::Canceled))
                }
            };
        }

        if let Some(accepted) = self
            .coordinator
            .accepted_decision_status(vault, pairing_id)
            .map_err(pairing_error)?
        {
            let review = self
                .coordinator
                .request_status(pairing_id)
                .map_err(pairing_error)?
                .ok_or_else(pairing_not_found)?;
            if review.request_digest != accepted.request_digest {
                return Err(pairing_conflict());
            }
            return Ok(LocalResult::PairingApproval {
                approval: PairingApprovalInfo {
                    request: request_info(review),
                    safety_number: PairingSafetyNumber::new(
                        accepted.safety_number.as_str().to_owned(),
                    )
                    .map_err(|_| pairing_invalid())?,
                },
            });
        }

        let invite = self
            .coordinator
            .invite_status(pairing_id)
            .map_err(pairing_error)?;
        match invite.state {
            PairingInviteState::Pending => {
                if let Some(review) = self
                    .coordinator
                    .request_status(pairing_id)
                    .map_err(pairing_error)?
                {
                    Ok(request_result(review, PairingState::Pending))
                } else {
                    Ok(invite_status_result(invite, PairingState::Pending))
                }
            }
            PairingInviteState::Rejected => {
                let review = self
                    .coordinator
                    .request_status(pairing_id)
                    .map_err(pairing_error)?
                    .ok_or_else(pairing_not_found)?;
                Ok(request_result(review, PairingState::Rejected))
            }
            PairingInviteState::Canceled => {
                Ok(invite_status_result(invite, PairingState::Canceled))
            }
            PairingInviteState::Approved => Err(pairing_conflict()),
        }
    }
}

fn invite_status_result(invite: PairingInviteStatus, status: PairingState) -> LocalResult {
    LocalResult::PairingInviteStatus {
        invite: PairingInviteStatusInfo {
            pairing_id: invite.pairing_id,
            created_at: DecimalTimestamp(invite.created_at_ms),
            expires_at: DecimalTimestamp(invite.expires_at_ms),
        },
        status,
    }
}

fn stored_join_review(
    vault: &Vault,
    pairing_id: PairingId,
) -> Result<PairingRequestReview, ClientError> {
    let stored = vault
        .stored_pairing_join(pairing_id)
        .map_err(|_| pairing_invalid())?
        .ok_or_else(pairing_not_found)?;
    let request =
        decode_pairing_request_v1(&stored.canonical_request).map_err(|_| pairing_invalid())?;
    let verified = verify_pairing_request(&request).map_err(|_| pairing_invalid())?;
    if verified.digest() != stored.request_sha256 {
        return Err(pairing_conflict());
    }
    let key_fingerprint = pairing_request_fingerprint(&request);
    Ok(PairingRequestReview {
        pairing_id,
        device_id: request.device_id,
        device_name: request.device_name,
        platform: request.platform,
        requested_at_ms: stored.stored_at_ms,
        key_fingerprint,
        request_digest: verified.digest(),
    })
}

fn request_info(review: PairingRequestReview) -> PairingRequestInfo {
    PairingRequestInfo {
        pairing_id: review.pairing_id,
        device_name: review.device_name,
        platform: review.platform,
        requested_at: DecimalTimestamp(review.requested_at_ms),
        key_fingerprint: review.key_fingerprint,
        request_digest: review.request_digest,
    }
}

fn request_result(review: PairingRequestReview, status: PairingState) -> LocalResult {
    LocalResult::PairingRequest {
        request: request_info(review),
        status,
    }
}

fn invite_result(invite: &PairingInvite, status: PairingState) -> LocalResult {
    LocalResult::PairingInvite {
        invite: PairingInviteInfo {
            pairing_id: invite.pairing_id,
            code: invite.code.clone(),
            created_at: DecimalTimestamp(invite.created_at_ms),
            expires_at: DecimalTimestamp(invite.expires_at_ms),
        },
        status,
    }
}

fn completion_result(
    vault: &Vault,
    scope: SyncScope,
    pairing_id: PairingId,
    current_device_id: DeviceId,
) -> Result<LocalResult, ClientError> {
    let device = device_summaries(vault, scope, current_device_id)?
        .into_iter()
        .find(|device| device.device_id == current_device_id)
        .ok_or_else(pairing_not_found)?;
    Ok(LocalResult::PairingCompletion {
        completion: PairingCompletionInfo { pairing_id, device },
    })
}

fn device_summaries(
    vault: &Vault,
    scope: SyncScope,
    current_device_id: DeviceId,
) -> Result<Vec<DeviceSummary>, ClientError> {
    Ok(vault
        .devices(scope)
        .map_err(|_| pairing_invalid())?
        .into_iter()
        .map(|stored| DeviceSummary {
            device_id: stored.certificate.device_id,
            name: stored.display.device_name,
            platform: stored.display.platform,
            state: match stored.state {
                DeviceCertificateState::Active => DeviceState::Active,
                DeviceCertificateState::Revoked => DeviceState::Revoked,
            },
            is_current: stored.certificate.device_id == current_device_id,
        })
        .collect())
}

pub(crate) fn all_device_summaries(
    vault: &Vault,
    current_device_id: DeviceId,
) -> Result<Vec<DeviceSummary>, ClientError> {
    Ok(vault
        .all_devices()
        .map_err(|_| pairing_invalid())?
        .into_iter()
        .map(|stored| DeviceSummary {
            device_id: stored.certificate.device_id,
            name: stored.display.device_name,
            platform: stored.display.platform,
            state: match stored.state {
                DeviceCertificateState::Active => DeviceState::Active,
                DeviceCertificateState::Revoked => DeviceState::Revoked,
            },
            is_current: stored.certificate.device_id == current_device_id,
        })
        .collect())
}

fn child_certificate_id(pairing_id: PairingId, scope: SyncScope) -> DeviceCertificateId {
    let mut hash = Sha256::new();
    hash.update(b"context-relay/pairing-child-certificate/v1\0");
    hash.update(pairing_id.as_bytes());
    hash.update(scope.account_id.as_bytes());
    hash.update(scope.workspace_id.as_bytes());
    DeviceCertificateId::from_str(&super::uuid_v7_text(hash.finalize().into()))
        .expect("domain-separated child certificate ID is UUIDv7")
}

fn pairing_error(error: PairingCycleError) -> ClientError {
    let (code, message, retryable) = match error {
        PairingCycleError::Invalid => (
            ErrorCode::InvalidRequest,
            "The pairing request is invalid",
            false,
        ),
        PairingCycleError::Expired => {
            (ErrorCode::Conflict, "The pairing invite has expired", false)
        }
        PairingCycleError::Canceled => (
            ErrorCode::Canceled,
            "The pairing invite was canceled",
            false,
        ),
        PairingCycleError::Rejected => (
            ErrorCode::Conflict,
            "The pairing request was rejected",
            false,
        ),
        PairingCycleError::Conflict => (ErrorCode::Conflict, "The pairing request changed", false),
        PairingCycleError::Transient => (
            ErrorCode::Internal,
            "The pairing service is temporarily unavailable",
            true,
        ),
    };
    ClientError {
        code,
        message: message.into(),
        field_path: None,
        retryable,
    }
}

fn pairing_invalid() -> ClientError {
    pairing_error(PairingCycleError::Invalid)
}

fn pairing_conflict() -> ClientError {
    pairing_error(PairingCycleError::Conflict)
}

fn pairing_not_found() -> ClientError {
    ClientError {
        code: ErrorCode::NotFound,
        message: "The pairing request was not found".into(),
        field_path: None,
        retryable: false,
    }
}
