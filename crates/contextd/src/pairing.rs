use std::str::FromStr;
use std::sync::Arc;

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
            MembershipObjectKind, PairingApprovalTransport, PairingInvite, PairingInviteState,
            PairingInviteStatus, PairingJoinTransport, PairingTransportError,
        },
    },
    sync::SyncScope,
    vault::{
        DeviceCertificateState, DeviceRevocationCoordination, DeviceRevocationDisposition,
        DeviceRevocationIntent, StoredRevocationControl, Vault,
    },
};
use context_relay_protocol::{
    ClientError, DecimalTimestamp, DeviceCertificateId, DeviceId, DeviceRevocationAccess,
    DeviceRevocationOutcome, DeviceRevocationStatus, DeviceRevocationSummary, DeviceState,
    DeviceSummary, ErrorCode, LocalRequest, LocalResult, NativePlatform, PairingApprovalInfo,
    PairingCompletionInfo, PairingId, PairingInviteInfo, PairingInviteStatusInfo,
    PairingRequestInfo, PairingSafetyNumber, PairingState, RecoveryHistoryEndpoint, Sha256Digest,
    decode_pairing_request_v1,
};
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub(crate) struct PairingIdentity {
    pub(crate) device_id: DeviceId,
    pub(crate) device_name: String,
    pub(crate) platform: NativePlatform,
    pub(crate) keys: std::sync::Arc<DeviceKeys>,
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

pub(crate) struct HostedPairingService {
    owner: Arc<context_relay_core::auth::HostedSessionOwner>,
    project: String,
    publishable_key: zeroize::Zeroizing<String>,
    identity: PairingIdentity,
    #[cfg(test)]
    pub(crate) http: Option<Arc<dyn context_relay_core::sync::SupabaseHttpClient>>,
}

struct HostedPairingClock;
impl PairingClock for HostedPairingClock {
    fn now_ms(&self) -> u64 {
        use context_relay_core::devices::recovery::{
            RecoveryEnrollmentClock, SystemRecoveryEnrollmentClock,
        };
        SystemRecoveryEnrollmentClock.now_ms()
    }
}

impl HostedPairingService {
    pub(crate) fn new(
        owner: Arc<context_relay_core::auth::HostedSessionOwner>,
        project: &str,
        publishable_key: &str,
        identity: PairingIdentity,
    ) -> Self {
        Self {
            owner,
            project: project.into(),
            publishable_key: zeroize::Zeroizing::new(publishable_key.into()),
            identity,
            #[cfg(test)]
            http: None,
        }
    }

    fn client(
        &self,
        identity: context_relay_core::auth::HostedIdentity,
    ) -> Result<context_relay_core::devices::supabase_pairing::HostedPairingClient, ClientError>
    {
        use context_relay_core::devices::supabase_pairing::HostedPairingClient;
        let generation = self
            .owner
            .cancellation()
            .map_err(|_| pairing_login_required())?;
        #[cfg(test)]
        if let Some(http) = &self.http {
            return HostedPairingClient::with_http_client(
                self.owner.clone(),
                identity,
                generation,
                &self.project,
                &self.publishable_key,
                self.identity.keys.clone(),
                http.clone(),
            )
            .map_err(|_| pairing_invalid());
        }
        HostedPairingClient::new(
            self.owner.clone(),
            identity,
            generation,
            &self.project,
            &self.publishable_key,
            self.identity.keys.clone(),
        )
        .map_err(|_| pairing_invalid())
    }

    fn authority(
        &self,
        vault: &Vault,
    ) -> Result<Option<(SyncScope, DeviceCertificateId)>, ClientError> {
        let mut roots = vault
            .all_devices()
            .map_err(|_| pairing_invalid())?
            .into_iter()
            .filter(|stored| {
                stored.certificate.device_id == self.identity.device_id
                    && stored.state == DeviceCertificateState::Active
            });
        let Some(root) = roots.next() else {
            return Ok(None);
        };
        if roots.next().is_some()
            || root.certificate.signing_public_key != self.identity.keys.signing_public_key()
            || root.certificate.wrapping_public_key != self.identity.keys.wrapping_public_key()
        {
            return Err(pairing_conflict());
        }
        let material = vault
            .trusted_workspace_material(&self.identity.keys)
            .map_err(|_| pairing_conflict())?;
        let scope = material.scope();
        if root.certificate.account_id != scope.account_id
            || root.certificate.workspace_id != scope.workspace_id
            || root.certificate.control_epoch != material.control_epoch()
        {
            return Err(pairing_conflict());
        }
        Ok(Some((scope, root.certificate_id)))
    }

    fn original_revocation_access(
        &self,
        vault: &Vault,
        stored: &DeviceRevocationIntent,
        now_ms: u64,
    ) -> DeviceRevocationAccess {
        let current = self
            .owner
            .current_session(now_ms / 1000)
            .ok()
            .flatten()
            .map(|session| *session.identity());
        let authority = self
            .authority(vault)
            .ok()
            .flatten()
            .is_some_and(|(scope, _)| {
                scope.account_id == stored.statement.account_id
                    && scope.workspace_id == stored.statement.workspace_id
            });
        if authority
            && stored.project_url == self.project
            && current.is_some_and(|identity| {
                identity.user_id == stored.user_id && identity.session_id == stored.session_id
            })
        {
            DeviceRevocationAccess::Ready
        } else {
            DeviceRevocationAccess::OriginalAuthRequired
        }
    }

    fn revocation_status(
        &self,
        vault: &Vault,
        stored: DeviceRevocationCoordination,
        now_ms: u64,
    ) -> DeviceRevocationStatus {
        let outcome = match stored.disposition {
            DeviceRevocationDisposition::Prepared => DeviceRevocationOutcome::Prepared {},
            DeviceRevocationDisposition::Submitting => DeviceRevocationOutcome::Submitting {},
            DeviceRevocationDisposition::Unconfirmed => DeviceRevocationOutcome::Unconfirmed {},
            DeviceRevocationDisposition::Accepted(receipt) => DeviceRevocationOutcome::Accepted {
                accepted_endpoint: RecoveryHistoryEndpoint {
                    state_sha256: receipt.successor.state_sha256,
                    control_epoch: receipt.successor.control_epoch,
                    key_epoch: receipt.successor.key_epoch,
                },
            },
            DeviceRevocationDisposition::Conflict => DeviceRevocationOutcome::Conflict {},
            DeviceRevocationDisposition::CanceledBeforeSend => {
                DeviceRevocationOutcome::CanceledBeforeSend {}
            }
        };
        DeviceRevocationStatus {
            operation_id: stored.intent.statement.revocation_id,
            device_id: stored.intent.statement.target_device_id,
            send_canceled: stored.send_canceled,
            access: self.original_revocation_access(vault, &stored.intent, now_ms),
            outcome,
        }
    }

    fn revocation_client(
        &self,
        stored: Option<&DeviceRevocationIntent>,
        now_ms: u64,
    ) -> Result<context_relay_core::devices::supabase_pairing::HostedPairingClient, ClientError>
    {
        use context_relay_core::auth::HostedIdentity;
        let identity = if let Some(stored) = stored {
            if stored.project_url != self.project {
                return Err(pairing_conflict());
            }
            HostedIdentity {
                user_id: stored.user_id,
                session_id: stored.session_id,
            }
        } else {
            *self
                .owner
                .current_session(now_ms / 1000)
                .map_err(|_| pairing_login_required())?
                .ok_or_else(pairing_login_required)?
                .identity()
        };
        self.client(identity)
    }

    fn reconcile_membership(
        &self,
        vault: &mut Vault,
        client: &impl PairingApprovalTransport,
        remote: context_relay_core::devices::membership_crypto::MembershipEndpoint,
        now_ms: u64,
    ) -> Result<(), ClientError> {
        use context_relay_core::devices::{
            membership_crypto::MembershipHistoryBudget, membership_transport::MembershipEventObject,
        };
        const BUDGET: MembershipHistoryBudget = MembershipHistoryBudget {
            max_events: 4096,
            max_bytes: 64 * 1024 * 1024,
        };
        let local = vault
            .accepted_membership_history(BUDGET)
            .map_err(|_| pairing_conflict())?
            .ok_or_else(pairing_conflict)?
            .endpoint();
        if local == remote {
            return Ok(());
        }
        let mut address = remote.state_sha256;
        let mut objects = Vec::new();
        let mut bytes = 0usize;
        while address != local.state_sha256 {
            if objects.len() >= BUDGET.max_events {
                return Err(pairing_conflict());
            }
            let raw = client
                .membership_object(MembershipObjectKind::Event, address, now_ms)
                .map_err(revocation_transport_error)?
                .ok_or_else(pairing_conflict)?;
            bytes = bytes
                .checked_add(raw.len())
                .filter(|value| *value <= BUDGET.max_bytes)
                .ok_or_else(pairing_conflict)?;
            let object = MembershipEventObject::from_canonical_bytes(&raw)
                .map_err(|_| pairing_conflict())?;
            let (parent, successor) = object.endpoints().map_err(|_| pairing_conflict())?;
            if successor != address {
                return Err(pairing_conflict());
            }
            address = parent;
            objects.push(object);
        }
        objects.reverse();
        let evidence = objects
            .iter()
            .map(|object| object.evidence())
            .collect::<Vec<_>>();
        vault
            .accept_membership_extension(local, remote, &evidence, BUDGET)
            .map_err(|_| pairing_conflict())?;
        vault
            .activate_current_membership_material(
                remote,
                self.identity.device_id,
                &self.identity.keys,
                BUDGET,
            )
            .map_err(|_| pairing_conflict())
    }

    fn revocation_object(
        intent: &DeviceRevocationIntent,
    ) -> Result<context_relay_core::devices::membership_transport::MembershipEventObject, ClientError>
    {
        use context_relay_core::devices::{
            membership_crypto::MembershipHistoryEvent, membership_transport::MembershipEventObject,
        };
        let statement = intent
            .statement
            .signing_preimage()
            .map_err(|_| pairing_conflict())?;
        let transition = intent
            .transition
            .canonical_bytes()
            .map_err(|_| pairing_conflict())?;
        MembershipEventObject::from_evidence(&MembershipHistoryEvent::Revocation {
            statement: &statement,
            signature: intent.signature,
            transition: &transition,
        })
        .map_err(|_| pairing_conflict())
    }

    fn apply_revocation_receipt(
        &self,
        vault: &mut Vault,
        intent: &DeviceRevocationIntent,
        receipt: &context_relay_core::vault::DeviceRevocationReceipt,
    ) -> Result<(), ClientError> {
        use context_relay_core::devices::membership_crypto::MembershipHistoryBudget;
        const BUDGET: MembershipHistoryBudget = MembershipHistoryBudget {
            max_events: 4096,
            max_bytes: 64 * 1024 * 1024,
        };
        vault
            .accept_device_revocation_receipt(intent.statement.revocation_id, receipt)
            .map_err(|_| pairing_conflict())?;
        let object = Self::revocation_object(intent)?;
        let history = vault
            .accepted_membership_history(BUDGET)
            .map_err(|_| pairing_conflict())?
            .ok_or_else(pairing_conflict)?;
        let record = StoredRevocationControl {
            statement: intent.statement.clone(),
            transition: intent.transition.clone(),
            signature: intent.signature,
        };
        let mut activation_endpoint = history.endpoint();
        if history.endpoint() == receipt.parent {
            vault
                .commit_device_revocation_control(&record, &history.state())
                .map_err(|_| pairing_conflict())?;
            vault
                .accept_membership_extension(
                    receipt.parent,
                    receipt.successor,
                    &[object.evidence()],
                    BUDGET,
                )
                .map_err(|_| pairing_conflict())?;
            activation_endpoint = receipt.successor;
        } else if history.endpoint() != receipt.successor {
            let canonical = object.canonical_bytes();
            let (_, events, _) = vault
                .accepted_membership_objects(BUDGET)
                .map_err(|_| pairing_conflict())?
                .ok_or_else(pairing_conflict)?;
            if !events
                .iter()
                .any(|event| event.canonical_bytes() == canonical)
                || vault
                    .device_revocation_control(
                        history.state().scope,
                        intent.transition.control_epoch,
                    )
                    .map_err(|_| pairing_conflict())?
                    .as_ref()
                    != Some(&record)
            {
                return Err(pairing_conflict());
            }
        }
        if intent.statement.target_device_id != self.identity.device_id {
            vault
                .activate_current_membership_material(
                    activation_endpoint,
                    self.identity.device_id,
                    &self.identity.keys,
                    BUDGET,
                )
                .map_err(|_| pairing_conflict())?;
        }
        Ok(())
    }

    fn resume_accepted_revocations(&self, vault: &mut Vault) -> Result<(), ClientError> {
        let mut after = None;
        let mut count = 0usize;
        loop {
            let ids = vault
                .device_revocation_intent_ids(after)
                .map_err(|_| pairing_conflict())?;
            if ids.is_empty() {
                return Ok(());
            }
            count = count.checked_add(ids.len()).ok_or_else(pairing_conflict)?;
            if count > 4096 {
                return Err(pairing_conflict());
            }
            for id in &ids {
                let stored = vault
                    .device_revocation_coordination(*id)
                    .map_err(|_| pairing_conflict())?
                    .ok_or_else(pairing_conflict)?;
                if let DeviceRevocationDisposition::Accepted(receipt) = stored.disposition {
                    self.apply_revocation_receipt(vault, &stored.intent, &receipt)?;
                }
            }
            after = ids.last().copied();
        }
    }

    fn reconcile_revocation_result(
        &self,
        vault: &mut Vault,
        intent: &DeviceRevocationIntent,
        now_ms: u64,
    ) -> Result<(), ClientError> {
        let object = Self::revocation_object(intent)?;
        let object_sha256 = Sha256Digest(Sha256::digest(object.canonical_bytes()).into());
        let client = self.revocation_client(Some(intent), now_ms)?;
        let approval = client.approval_client(
            SyncScope {
                account_id: intent.statement.account_id,
                workspace_id: intent.statement.workspace_id,
            },
            intent.statement.issuer_device_id,
        );
        match approval.revocation_result(intent.statement.revocation_id, object_sha256, now_ms) {
            Ok(Some(receipt)) => self.apply_revocation_receipt(vault, intent, &receipt),
            Ok(None) => Ok(()),
            Err(PairingTransportError::Conflict | PairingTransportError::Invalid) => vault
                .mark_device_revocation_conflict(intent.statement.revocation_id)
                .map(|_| ())
                .map_err(|_| pairing_conflict()),
            Err(error) => Err(revocation_transport_error(error)),
        }
    }

    fn publish_revocation_intent(
        &self,
        vault: &mut Vault,
        intent: &DeviceRevocationIntent,
        now_ms: u64,
    ) -> Result<(), ClientError> {
        let client = self.revocation_client(Some(intent), now_ms)?;
        let approval = client.approval_client(
            SyncScope {
                account_id: intent.statement.account_id,
                workspace_id: intent.statement.workspace_id,
            },
            intent.statement.issuer_device_id,
        );
        vault
            .begin_device_revocation_submission(intent.statement.revocation_id)
            .map_err(|_| pairing_conflict())?;
        let object = Self::revocation_object(intent)?;
        match approval.publish_revocation(&object, now_ms) {
            Ok(receipt) => self.apply_revocation_receipt(vault, intent, &receipt),
            Err(PairingTransportError::Conflict | PairingTransportError::Invalid) => vault
                .mark_device_revocation_conflict(intent.statement.revocation_id)
                .map(|_| ())
                .map_err(|_| pairing_conflict()),
            Err(_) => vault
                .mark_device_revocation_unconfirmed(intent.statement.revocation_id)
                .map(|_| ())
                .map_err(|_| pairing_conflict()),
        }
    }

    fn execute_revocation(
        &self,
        vault: &mut Vault,
        request: LocalRequest,
    ) -> Result<LocalResult, ClientError> {
        use context_relay_core::devices::{
            membership_crypto::MembershipHistoryBudget,
            revocation_crypto::{DeviceRevocationStatementV1, RevocationTransitionV1},
        };
        const BUDGET: MembershipHistoryBudget = MembershipHistoryBudget {
            max_events: 4096,
            max_bytes: 64 * 1024 * 1024,
        };
        let now_ms = HostedPairingClock.now_ms();
        if let LocalRequest::DeviceRevocationIntents(params) = request {
            let mut intents = Vec::new();
            for id in vault
                .device_revocation_intent_ids(params.after)
                .map_err(|_| pairing_conflict())?
            {
                let stored = vault
                    .device_revocation_coordination(id)
                    .map_err(|_| pairing_conflict())?
                    .ok_or_else(pairing_conflict)?;
                let status = self.revocation_status(vault, stored, now_ms);
                intents.push(DeviceRevocationSummary {
                    operation_id: status.operation_id,
                    device_id: status.device_id,
                    send_canceled: status.send_canceled,
                    access: status.access,
                    outcome: status.outcome,
                });
            }
            return Ok(LocalResult::DeviceRevocationIntents { intents });
        }
        let (id, target, action) = match request {
            LocalRequest::DeviceRevoke(params) => {
                (params.operation_id, Some(params.device_id), "send")
            }
            LocalRequest::DeviceRevocationStatus(params) => (params.operation_id, None, "status"),
            LocalRequest::DeviceRevocationCancel(params) => (params.operation_id, None, "cancel"),
            _ => return Err(pairing_invalid()),
        };
        let mut stored = vault
            .device_revocation_coordination(id)
            .map_err(|_| pairing_conflict())?;
        if let Some(existing) = &stored {
            if target.is_some_and(|target| target != existing.intent.statement.target_device_id) {
                return Err(pairing_conflict());
            }
        } else if let Some(target) = target {
            let hosted = *self
                .owner
                .current_session(now_ms / 1000)
                .map_err(|_| pairing_login_required())?
                .ok_or_else(pairing_login_required)?
                .identity();
            let (scope, certificate_id) =
                self.authority(vault)?.ok_or_else(pairing_login_required)?;
            let client = self.revocation_client(None, now_ms)?;
            let approval = client.approval_client(scope, self.identity.device_id);
            let context = approval
                .revocation_context(target, now_ms)
                .map_err(revocation_transport_error)?;
            self.reconcile_membership(vault, &approval, context.endpoint, now_ms)?;
            let history = vault
                .accepted_membership_history(BUDGET)
                .map_err(|_| pairing_conflict())?
                .ok_or_else(pairing_conflict)?;
            let state = history.state();
            if history.endpoint() != context.endpoint
                || history.admissions().get(&self.identity.device_id) != Some(&certificate_id)
            {
                return Err(pairing_conflict());
            }
            let local_head = vault
                .device_head(scope.workspace_id, target)
                .map_err(|_| pairing_conflict())?;
            if match local_head {
                None => context.head.sequence != 0,
                Some(head) => {
                    head.sequence != context.head.sequence
                        || head.canonical_hash != context.head.canonical_sha256
                }
            } {
                return Err(ClientError {
                    code: ErrorCode::Conflict,
                    message: "Sync the target device history before revoking it".into(),
                    field_path: None,
                    retryable: true,
                });
            }
            let issuer = state
                .active_devices
                .get(&self.identity.device_id)
                .cloned()
                .ok_or_else(pairing_conflict)?;
            let statement = DeviceRevocationStatementV1 {
                schema_version: 1,
                revocation_id: id,
                account_id: scope.account_id,
                workspace_id: scope.workspace_id,
                issuer_device_id: self.identity.device_id,
                target_device_id: target,
                control_epoch: state.control_epoch,
                key_epoch: state.key_epoch,
                cutoff_sequence: context.head.sequence,
                cutoff_hash: context.head.canonical_sha256,
                transition_sha256: Sha256Digest([0; 32]),
            };
            let (statement, transition, signature) =
                RevocationTransitionV1::build(statement, &self.identity.keys, &state)
                    .map_err(|_| pairing_conflict())?;
            let intent = DeviceRevocationIntent {
                project_url: self.project.clone(),
                user_id: hosted.user_id,
                session_id: hosted.session_id,
                issuer_certificate: issuer,
                statement,
                transition,
                signature,
            };
            vault
                .store_device_revocation_intent(&intent, &state)
                .map_err(|error| match error {
                    context_relay_core::vault::VaultError::BudgetExceeded => ClientError {
                        code: ErrorCode::QuotaExceeded,
                        message: "The retained revocation history is full".into(),
                        field_path: None,
                        retryable: false,
                    },
                    _ => pairing_conflict(),
                })?;
            stored = vault
                .device_revocation_coordination(id)
                .map_err(|_| pairing_conflict())?;
        } else {
            return Err(pairing_not_found());
        }
        let mut stored = stored.ok_or_else(pairing_not_found)?;
        if let DeviceRevocationDisposition::Accepted(receipt) = stored.disposition.clone() {
            self.apply_revocation_receipt(vault, &stored.intent, &receipt)?;
            stored = vault
                .device_revocation_coordination(id)
                .map_err(|_| pairing_conflict())?
                .ok_or_else(pairing_not_found)?;
        }
        if action == "cancel" {
            stored = vault
                .cancel_device_revocation_submission(id)
                .map_err(|_| pairing_conflict())?;
        } else if action == "status"
            && matches!(
                stored.disposition,
                DeviceRevocationDisposition::Submitting | DeviceRevocationDisposition::Unconfirmed
            )
            && self.original_revocation_access(vault, &stored.intent, now_ms)
                == DeviceRevocationAccess::Ready
        {
            // Status is allowed to refresh the exact hosted outcome, but the local durable
            // facts remain readable when that authorized lookup is temporarily unavailable.
            let _ = self.reconcile_revocation_result(vault, &stored.intent, now_ms);
            stored = vault
                .device_revocation_coordination(id)
                .map_err(|_| pairing_conflict())?
                .ok_or_else(pairing_not_found)?;
        } else if action == "send"
            && !stored.send_canceled
            && matches!(
                stored.disposition,
                DeviceRevocationDisposition::Prepared | DeviceRevocationDisposition::Unconfirmed
            )
        {
            self.publish_revocation_intent(vault, &stored.intent, now_ms)?;
            stored = vault
                .device_revocation_coordination(id)
                .map_err(|_| pairing_conflict())?
                .ok_or_else(pairing_not_found)?;
        }
        Ok(LocalResult::DeviceRevocation {
            status: self.revocation_status(vault, stored, now_ms),
        })
    }
}

impl PairingService for HostedPairingService {
    fn resume_prepared_decisions(&self, vault: &mut Vault) -> Result<(), ClientError> {
        // Startup remains local while Auth restores. Explicit status/decision requests reconcile.
        let _ = vault
            .pending_pairing_approvals()
            .map_err(|_| pairing_invalid())?;
        vault
            .recover_device_revocation_submissions()
            .map_err(|_| pairing_invalid())?;
        self.resume_accepted_revocations(vault)?;
        Ok(())
    }

    fn execute(
        &self,
        vault: &mut Vault,
        identity: &PairingIdentity,
        request: LocalRequest,
    ) -> Result<LocalResult, ClientError> {
        use context_relay_core::{
            auth::HostedIdentity, devices::pairing::VaultPairingMaterialSource,
        };
        if identity.device_id != self.identity.device_id
            || identity.keys.signing_public_key() != self.identity.keys.signing_public_key()
            || identity.keys.wrapping_public_key() != self.identity.keys.wrapping_public_key()
        {
            return Err(pairing_conflict());
        }
        if matches!(
            request,
            LocalRequest::DeviceRevoke(_)
                | LocalRequest::DeviceRevocationStatus(_)
                | LocalRequest::DeviceRevocationCancel(_)
                | LocalRequest::DeviceRevocationIntents(_)
        ) {
            return self.execute_revocation(vault, request);
        }
        let pairing_id = match &request {
            LocalRequest::PairingStatus(params) | LocalRequest::PairingCancel(params) => {
                Some(params.pairing_id)
            }
            LocalRequest::PairingDecision(params) => Some(params.pairing_id),
            LocalRequest::PairingConfirm(params) => Some(params.pairing_id),
            LocalRequest::PairingCreate(_) | LocalRequest::PairingJoin(_) => None,
            _ => return Err(pairing_invalid()),
        };
        let saved = pairing_id
            .map(|id| vault.hosted_pairing_intent(id))
            .transpose()
            .map_err(|_| pairing_invalid())?
            .flatten();
        if let Some(saved) = &saved {
            use context_relay_core::vault::HostedPairingRole;
            let joining = matches!(request, LocalRequest::PairingConfirm(_))
                || (matches!(request, LocalRequest::PairingStatus(_))
                    && vault
                        .stored_pairing_join(pairing_id.ok_or_else(pairing_invalid)?)
                        .map_err(|_| pairing_invalid())?
                        .is_some());
            let expected_role = if joining {
                HostedPairingRole::Join
            } else {
                HostedPairingRole::Approve
            };
            if saved.role != expected_role {
                return Err(pairing_conflict());
            }
        }
        let hosted_identity = if let Some(saved) = &saved {
            // Local terminal reads can work after logout; the client still requires this exact
            // identity and current generation for every provider operation.
            HostedIdentity {
                user_id: saved.user_id,
                session_id: saved.session_id,
            }
        } else {
            *self
                .owner
                .current_session(HostedPairingClock.now_ms() / 1000)
                .map_err(|_| pairing_login_required())?
                .ok_or_else(pairing_login_required)?
                .identity()
        };
        let client = self.client(hosted_identity)?;
        if let Some(saved) = &saved
            && client.original_intent(saved.role) != *saved
        {
            return Err(pairing_conflict());
        }
        let authority = self.authority(vault)?;
        let approval =
            authority.map(|(scope, _)| client.approval_client(scope, identity.device_id));
        let coordinator = PairingCoordinator::new(
            HostedPairingClock,
            VaultPairingMaterialSource,
            client,
            approval,
        );
        if let LocalRequest::PairingStatus(params) = &request
            && authority.is_some()
        {
            coordinator
                .resume_prepared_decision(vault, params.pairing_id)
                .map_err(pairing_error)?;
        }
        match authority {
            Some((scope, certificate)) => {
                CoordinatorPairingService::new(coordinator, scope, certificate)
                    .execute(vault, identity, request)
            }
            None => {
                CoordinatorPairingService::new_joiner(coordinator).execute(vault, identity, request)
            }
        }
    }
}

fn pairing_login_required() -> ClientError {
    ClientError {
        code: ErrorCode::ScopeDenied,
        message: "Sign in to continue hosted pairing".into(),
        field_path: None,
        retryable: false,
    }
}

pub(crate) struct CoordinatorPairingService<C, M, J, A> {
    coordinator: PairingCoordinator<C, M, J, A>,
    authority: Option<(SyncScope, DeviceCertificateId)>,
}

impl<C, M, J, A> CoordinatorPairingService<C, M, J, A> {
    pub(crate) fn new(
        coordinator: PairingCoordinator<C, M, J, A>,
        scope: SyncScope,
        issuer_certificate_id: DeviceCertificateId,
    ) -> Self {
        Self {
            coordinator,
            authority: Some((scope, issuer_certificate_id)),
        }
    }

    pub(crate) fn new_joiner(coordinator: PairingCoordinator<C, M, J, A>) -> Self {
        Self {
            coordinator,
            authority: None,
        }
    }

    fn approval_authority(&self) -> Result<(SyncScope, DeviceCertificateId), ClientError> {
        self.authority.ok_or_else(pairing_invalid)
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
        if self.authority.is_none()
            && !vault
                .pending_pairing_approvals()
                .map_err(|_| pairing_invalid())?
                .is_empty()
        {
            return Err(pairing_invalid());
        }
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
                self.approval_authority()?;
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
                let (scope, issuer_certificate_id) = self.approval_authority()?;
                let review = self.decision_review(vault, params.pairing_id)?;
                if review.request_digest != params.request_digest {
                    return Err(pairing_conflict());
                }
                let decision = if params.approve {
                    PairingDecisionInput::Approve(PairingApprovalAuthority {
                        certificate_id: child_certificate_id(params.pairing_id, scope),
                        issuer_certificate_id,
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
                self.approval_authority()?;
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
    fn decision_review(
        &self,
        vault: &Vault,
        pairing_id: PairingId,
    ) -> Result<PairingRequestReview, ClientError> {
        if let Some(review) = self
            .coordinator
            .saved_request_review(vault, pairing_id)
            .map_err(pairing_error)?
        {
            return Ok(review);
        }
        self.coordinator
            .request_status(pairing_id)
            .map_err(pairing_error)?
            .ok_or_else(pairing_not_found)
    }

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
            self.coordinator
                .resume_confirmed_join(vault, pairing_id, &identity.keys)
                .map_err(pairing_error)?;
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

        self.approval_authority()?;
        if let Some(accepted) = self
            .coordinator
            .accepted_decision_status(vault, pairing_id)
            .map_err(pairing_error)?
        {
            let review = self.decision_review(vault, pairing_id)?;
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
        PairingCycleError::Incomplete => (
            ErrorCode::Conflict,
            "Confirmation saved; waiting for verified membership history",
            true,
        ),
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

fn revocation_transport_error(error: PairingTransportError) -> ClientError {
    match error {
        PairingTransportError::Unauthorized => pairing_login_required(),
        PairingTransportError::Transient => ClientError {
            code: ErrorCode::Internal,
            message: "The device service is temporarily unavailable".into(),
            field_path: None,
            retryable: true,
        },
        _ => pairing_conflict(),
    }
}

fn pairing_not_found() -> ClientError {
    ClientError {
        code: ErrorCode::NotFound,
        message: "The pairing request was not found".into(),
        field_path: None,
        retryable: false,
    }
}
