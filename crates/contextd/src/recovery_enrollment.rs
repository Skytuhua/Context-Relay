#![cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "the hosted recovery adapter is not configured in this build"
    )
)]

use std::sync::Mutex;
mod history;

use context_relay_core::{
    crypto::DeviceKeys,
    devices::{
        recovery::{
            RecoveryEnrollmentBeginOutcome, RecoveryEnrollmentClock,
            RecoveryEnrollmentConfirmOutcome, RecoveryEnrollmentCoordinator,
            RecoveryEnrollmentCycleError, RecoveryEnrollmentEntropy,
        },
        recovery_transport::RecoveryEnrollmentTransport,
    },
    vault::Vault,
};
use context_relay_protocol::{
    ClientError, DeviceId, ErrorCode, LocalRequest, LocalResult, NativePlatform,
};

pub(crate) const RECOVERY_UNAVAILABLE_MESSAGE: &str =
    "Recovery setup needs the hosted workspace service and is not available in this build.";

pub(crate) trait RecoveryEnrollmentService: Send + Sync {
    fn resume_prepared(
        &self,
        vault: &mut Vault,
        device_keys: &DeviceKeys,
    ) -> Result<(), ClientError>;

    fn execute(
        &self,
        vault: &mut Vault,
        device_keys: &DeviceKeys,
        request: LocalRequest,
    ) -> Result<LocalResult, ClientError>;
}

pub(crate) struct CoordinatorRecoveryEnrollmentService<C, E, T> {
    coordinator: Mutex<RecoveryEnrollmentCoordinator<C, E, T>>,
    device_id: DeviceId,
    device_name: String,
    platform: NativePlatform,
}

impl<C, E, T> CoordinatorRecoveryEnrollmentService<C, E, T> {
    pub(crate) fn new(
        coordinator: RecoveryEnrollmentCoordinator<C, E, T>,
        device_id: DeviceId,
        device_name: impl Into<String>,
        platform: NativePlatform,
    ) -> Self {
        Self {
            coordinator: Mutex::new(coordinator),
            device_id,
            device_name: device_name.into(),
            platform,
        }
    }

    fn coordinator(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, RecoveryEnrollmentCoordinator<C, E, T>>, ClientError>
    {
        self.coordinator.lock().map_err(|_| transient_error())
    }
}

impl<C, E, T> RecoveryEnrollmentService for CoordinatorRecoveryEnrollmentService<C, E, T>
where
    C: RecoveryEnrollmentClock,
    E: RecoveryEnrollmentEntropy,
    T: RecoveryEnrollmentTransport,
{
    fn resume_prepared(
        &self,
        vault: &mut Vault,
        device_keys: &DeviceKeys,
    ) -> Result<(), ClientError> {
        self.coordinator()?
            .overview(vault, device_keys)
            .map(|_| ())
            .map_err(recovery_error)
    }

    fn execute(
        &self,
        vault: &mut Vault,
        device_keys: &DeviceKeys,
        request: LocalRequest,
    ) -> Result<LocalResult, ClientError> {
        let mut coordinator = self.coordinator()?;
        match request {
            LocalRequest::RecoveryEnrollmentBegin(_) => coordinator
                .begin(
                    vault,
                    self.device_id,
                    &self.device_name,
                    self.platform,
                    device_keys,
                )
                .map(|outcome| match outcome {
                    RecoveryEnrollmentBeginOutcome::Phrase(phrase) => {
                        LocalResult::RecoveryEnrollmentPhrase { phrase }
                    }
                    RecoveryEnrollmentBeginOutcome::Status(status) => {
                        LocalResult::RecoveryEnrollmentStatus { status }
                    }
                })
                .map_err(recovery_error),
            LocalRequest::RecoveryEnrollmentOverview(_) => coordinator
                .overview(vault, device_keys)
                .map(|status| LocalResult::RecoveryEnrollmentStatus { status })
                .map_err(recovery_error),
            LocalRequest::RecoveryEnrollmentConfirm(params) => coordinator
                .confirm(vault, params, device_keys)
                .map(|outcome| match outcome {
                    RecoveryEnrollmentConfirmOutcome::Complete(completion) => {
                        LocalResult::RecoveryEnrollmentComplete { completion }
                    }
                    RecoveryEnrollmentConfirmOutcome::Status(status) => {
                        LocalResult::RecoveryEnrollmentStatus { status }
                    }
                })
                .map_err(recovery_error),
            LocalRequest::RecoveryEnrollmentStatus(params) => coordinator
                .status(vault, params.enrollment_id, device_keys)
                .map(|status| LocalResult::RecoveryEnrollmentStatus { status })
                .map_err(recovery_error),
            LocalRequest::RecoveryEnrollmentCancel(params) => coordinator
                .cancel(vault, params.enrollment_id)
                .map(|status| LocalResult::RecoveryEnrollmentStatus { status })
                .map_err(recovery_error),
            _ => Err(invalid_error()),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct UnavailableRecoveryEnrollmentService;

impl RecoveryEnrollmentService for UnavailableRecoveryEnrollmentService {
    fn resume_prepared(
        &self,
        _vault: &mut Vault,
        _device_keys: &DeviceKeys,
    ) -> Result<(), ClientError> {
        Err(unavailable_error())
    }

    fn execute(
        &self,
        _vault: &mut Vault,
        _device_keys: &DeviceKeys,
        _request: LocalRequest,
    ) -> Result<LocalResult, ClientError> {
        Err(unavailable_error())
    }
}

pub(crate) fn unavailable_error() -> ClientError {
    ClientError {
        code: ErrorCode::HarnessUnsupported,
        message: RECOVERY_UNAVAILABLE_MESSAGE.into(),
        field_path: None,
        retryable: false,
    }
}

fn recovery_error(error: RecoveryEnrollmentCycleError) -> ClientError {
    let (code, message, retryable) = match error {
        RecoveryEnrollmentCycleError::Invalid => (
            ErrorCode::InvalidRequest,
            "The recovery enrollment request is invalid",
            false,
        ),
        RecoveryEnrollmentCycleError::Expired => (
            ErrorCode::Conflict,
            "The recovery enrollment session has expired",
            false,
        ),
        RecoveryEnrollmentCycleError::Conflict => (
            ErrorCode::Conflict,
            "The recovery enrollment state changed",
            false,
        ),
        RecoveryEnrollmentCycleError::Unauthorized => (
            ErrorCode::ScopeDenied,
            "This client is not authorized for recovery enrollment",
            false,
        ),
        RecoveryEnrollmentCycleError::Transient => (
            ErrorCode::Internal,
            "The recovery enrollment service is temporarily unavailable",
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

fn invalid_error() -> ClientError {
    recovery_error(RecoveryEnrollmentCycleError::Invalid)
}

fn transient_error() -> ClientError {
    recovery_error(RecoveryEnrollmentCycleError::Transient)
}

type HostedCoordinator = CoordinatorRecoveryEnrollmentService<
    context_relay_core::devices::recovery::SystemRecoveryEnrollmentClock,
    context_relay_core::devices::recovery::OsRecoveryEnrollmentEntropy,
    context_relay_core::devices::supabase_enrollment::HostedRecoveryEnrollmentTransport<
        context_relay_core::devices::recovery::SystemRecoveryEnrollmentClock,
    >,
>;

pub(crate) struct HostedRecoveryEnrollmentService {
    owner: std::sync::Arc<context_relay_core::auth::HostedSessionOwner>,
    project: String,
    publishable_key: zeroize::Zeroizing<String>,
    identity: crate::pairing::PairingIdentity,
    coordinator: Mutex<Option<HostedCoordinator>>,
    history_pages: Mutex<Option<history::CandidateTraversal>>,
    #[cfg(test)]
    http: Option<std::sync::Arc<dyn context_relay_core::sync::SupabaseHttpClient>>,
}

impl HostedRecoveryEnrollmentService {
    fn execute_restore(
        &self,
        vault: &mut Vault,
        request: LocalRequest,
    ) -> Result<LocalResult, ClientError> {
        use context_relay_core::{
            devices::{
                recovery::SystemRecoveryEnrollmentClock,
                recovery_restore::{
                    RecoveryRestoreCoordinator, RecoveryRestoreIdentity, RecoveryRestoreOutcome,
                },
            },
            vault::{HostedRestoreIntent, RecoveryRestorePersistenceState},
        };
        use context_relay_protocol::RecoveryRestoreStatus as Status;
        let stored = vault.recovery_restore().map_err(|_| transient_error())?;
        let stored_v2 = vault
            .prepared_recovery_v2(&self.identity.keys)
            .map_err(|_| transient_error())?;
        if stored.is_some() && stored_v2.is_some() {
            return Err(restore_error(
                context_relay_core::devices::recovery_restore::RecoveryRestoreCycleError::Conflict,
            ));
        }
        let has_prepared = stored.is_some() || stored_v2.is_some();
        if matches!(request, LocalRequest::RecoveryRestoreCancel(_)) {
            if has_prepared {
                return Err(restore_error(context_relay_core::devices::recovery_restore::RecoveryRestoreCycleError::Conflict));
            }
            if let Some(intent) = vault
                .hosted_restore_intent()
                .map_err(|_| transient_error())?
            {
                vault
                    .discard_unprepared_hosted_restore_intent(&intent)
                    .map_err(|_| transient_error())?;
            }
            return Ok(LocalResult::RecoveryRestoreStatus {
                status: Status::Idle {},
            });
        }
        if let Some(saved) = &stored_v2 {
            if saved.claim.certificate.device_id != self.identity.device_id
                || saved.claim.device_name != self.identity.device_name
                || saved.claim.device_platform != self.identity.platform
            {
                return Err(restore_error(context_relay_core::devices::recovery_restore::RecoveryRestoreCycleError::Conflict));
            }
            if matches!(request, LocalRequest::RecoveryRestoreOverview(_))
                || saved.publication_conflict
            {
                let restore_id = saved.claim.restore_id;
                let status = if saved.publication_conflict {
                    Status::Conflict { restore_id }
                } else if vault
                    .recovery_membership_admission(&self.identity.keys)
                    .map_err(|_| transient_error())?
                    .is_some()
                {
                    vault
                        .recovery_history_status(&self.identity.keys, history::budget())
                        .map_err(history::vault_error)?
                } else {
                    Status::Submitting { restore_id }
                };
                return Ok(LocalResult::RecoveryRestoreStatus { status });
            }
        }
        if let Some(stored) = &stored {
            if stored.claim.certificate.device_id != self.identity.device_id
                || stored.claim.device_name != self.identity.device_name
                || stored.claim.device_platform != self.identity.platform
                || stored.claim.certificate.signing_public_key
                    != self.identity.keys.signing_public_key()
                || stored.claim.certificate.wrapping_public_key
                    != self.identity.keys.wrapping_public_key()
            {
                return Err(restore_error(context_relay_core::devices::recovery_restore::RecoveryRestoreCycleError::Conflict));
            }
            if stored.state == RecoveryRestorePersistenceState::Active {
                vault
                    .recovered_workspace_material(&self.identity.keys)
                    .map_err(|_| transient_error())?;
            }
        }
        if matches!(request, LocalRequest::RecoveryRestoreOverview(_))
            || stored
                .as_ref()
                .is_some_and(|s| s.state != RecoveryRestorePersistenceState::Prepared)
        {
            let status = match stored {
                None => Status::Idle {},
                Some(stored) => match stored.state {
                    RecoveryRestorePersistenceState::Prepared => Status::Submitting {
                        restore_id: stored.claim.restore_id,
                    },
                    RecoveryRestorePersistenceState::Conflict => Status::Conflict {
                        restore_id: stored.claim.restore_id,
                    },
                    RecoveryRestorePersistenceState::Active => Status::Complete {
                        restore_id: stored.claim.restore_id,
                        device: context_relay_protocol::DeviceSummary {
                            device_id: self.identity.device_id,
                            name: self.identity.device_name.clone(),
                            platform: self.identity.platform,
                            state: context_relay_protocol::DeviceState::Active,
                            is_current: true,
                        },
                    },
                },
            };
            return Ok(LocalResult::RecoveryRestoreStatus { status });
        }
        let begin = matches!(request, LocalRequest::RecoveryRestoreBegin(_));
        if !begin && !has_prepared {
            return Err(invalid_error());
        }
        let now = SystemRecoveryEnrollmentClock.now_ms() / 1000;
        let generation = self.owner.cancellation().map_err(|_| transient_error())?;
        let session = self.owner.current_session(now).map_err(|_| transient_error())?
            .ok_or_else(|| restore_error(context_relay_core::devices::recovery_restore::RecoveryRestoreCycleError::Unauthorized))?;
        let identity = *session.identity();
        self.owner.session_for(&generation,identity,now).map_err(|_| restore_error(context_relay_core::devices::recovery_restore::RecoveryRestoreCycleError::Unauthorized))?;
        let current = HostedRestoreIntent {
            project_url: session.project_url().to_string(),
            user_id: identity.user_id,
            session_id: identity.session_id,
        };
        let mut intent = vault
            .hosted_restore_intent()
            .map_err(|_| transient_error())?;
        if begin
            && !has_prepared
            && let Some(saved) = &intent
            && *saved != current
        {
            vault
                .discard_unprepared_hosted_restore_intent(saved)
                .map_err(|_| transient_error())?;
            intent = None;
        }
        if intent.is_none() {
            if stored_v2.is_some() {
                return Err(restore_error(context_relay_core::devices::recovery_restore::RecoveryRestoreCycleError::Conflict));
            }
            vault.store_hosted_restore_intent(&current).map_err(|_| restore_error(context_relay_core::devices::recovery_restore::RecoveryRestoreCycleError::Conflict))?;
            intent = Some(current);
        }
        let intent = intent.ok_or_else(transient_error)?;
        if intent.user_id != identity.user_id
            || intent.session_id != identity.session_id
            || reqwest::Url::parse(&intent.project_url).ok().as_ref() != Some(session.project_url())
        {
            return Err(restore_error(context_relay_core::devices::recovery_restore::RecoveryRestoreCycleError::Unauthorized));
        }
        let client = self.client(identity, generation.clone())?;
        let snapshot = client.snapshot(now).map_err(hosted_transport_error)?
            .ok_or_else(|| restore_error(context_relay_core::devices::recovery_restore::RecoveryRestoreCycleError::Unavailable))?;
        if stored.as_ref().is_some_and(|s| {
            s.canonical_record != snapshot.canonical_record
                || s.canonical_record_sha256 != snapshot.canonical_record_sha256
        }) || stored_v2.as_ref().is_some_and(|s| {
            s.canonical_record != snapshot.canonical_record
                || s.claim.canonical_record_sha256 != snapshot.canonical_record_sha256
        }) {
            return Err(restore_error(
                context_relay_core::devices::recovery_restore::RecoveryRestoreCycleError::Conflict,
            ));
        }
        if stored_v2.is_some()
            && vault
                .recovery_membership_admission(&self.identity.keys)
                .map_err(history::vault_error)?
                .is_some()
        {
            return self.execute_history(vault, request, identity, generation);
        }
        let transport = client
            .into_restore_transport(
                &intent,
                snapshot,
                self.identity.keys.clone(),
                SystemRecoveryEnrollmentClock,
            )
            .map_err(hosted_transport_error)?;
        let coordinator = RecoveryRestoreCoordinator::new(transport);
        let device = RecoveryRestoreIdentity {
            device_id: self.identity.device_id,
            device_name: self.identity.device_name.clone(),
            platform: self.identity.platform,
            keys: &self.identity.keys,
        };
        let result = match request {
            LocalRequest::RecoveryRestoreBegin(params) if !has_prepared => {
                coordinator.recover(vault, params.recovery_phrase_words, &device)
            }
            LocalRequest::RecoveryRestoreBegin(_) | LocalRequest::RecoveryRestoreResume(_) => {
                coordinator.resume_prepared(vault, &device)
            }
            _ => return Err(invalid_error()),
        }
        .map_err(restore_error)?;
        Ok(LocalResult::RecoveryRestoreStatus {
            status: match result {
                RecoveryRestoreOutcome::Submitting { restore_id } => {
                    Status::Submitting { restore_id }
                }
                RecoveryRestoreOutcome::RestoringHistory { restore_id } => {
                    let _ = restore_id;
                    vault
                        .recovery_history_status(&self.identity.keys, history::budget())
                        .map_err(history::vault_error)?
                }
                RecoveryRestoreOutcome::Conflict { restore_id } => Status::Conflict { restore_id },
                RecoveryRestoreOutcome::Complete { restore_id, device } => {
                    Status::Complete { restore_id, device }
                }
            },
        })
    }

    pub(crate) fn new(
        owner: std::sync::Arc<context_relay_core::auth::HostedSessionOwner>,
        project: &str,
        publishable_key: &str,
        identity: crate::pairing::PairingIdentity,
    ) -> Self {
        Self {
            owner,
            project: project.into(),
            publishable_key: zeroize::Zeroizing::new(publishable_key.into()),
            identity,
            coordinator: Mutex::new(None),
            history_pages: Mutex::new(None),
            #[cfg(test)]
            http: None,
        }
    }
    fn client(
        &self,
        identity: context_relay_core::auth::HostedIdentity,
        generation: context_relay_core::auth::LoginCancellation,
    ) -> Result<context_relay_core::devices::supabase_enrollment::HostedEnrollmentClient, ClientError>
    {
        use context_relay_core::devices::supabase_enrollment::HostedEnrollmentClient;
        #[cfg(test)]
        if let Some(http) = &self.http {
            return HostedEnrollmentClient::with_http_client(
                self.owner.clone(),
                identity,
                generation,
                &self.project,
                &self.publishable_key,
                http.clone(),
            )
            .map_err(hosted_transport_error);
        }
        HostedEnrollmentClient::new(
            self.owner.clone(),
            identity,
            generation,
            &self.project,
            &self.publishable_key,
        )
        .map_err(hosted_transport_error)
    }
}

impl RecoveryEnrollmentService for HostedRecoveryEnrollmentService {
    fn resume_prepared(
        &self,
        vault: &mut Vault,
        _device_keys: &DeviceKeys,
    ) -> Result<(), ClientError> {
        // Local startup must work while Auth is restoring or the network is down.
        // Explicit enrollment requests reconcile through the authenticated client.
        vault.recovery_enrollment().map_err(|_| transient_error())?;
        vault
            .hosted_enrollment_intent()
            .map_err(|_| transient_error())?;
        vault.recovery_restore().map_err(|_| transient_error())?;
        vault
            .prepared_recovery_v2(&self.identity.keys)
            .map_err(|_| transient_error())?;
        vault
            .hosted_restore_intent()
            .map_err(|_| transient_error())?;
        if vault
            .recovery_membership_admission(&self.identity.keys)
            .map_err(history::vault_error)?
            .is_some()
        {
            vault
                .recovery_history_status(&self.identity.keys, history::budget())
                .map_err(history::vault_error)?;
        }
        Ok(())
    }

    fn execute(
        &self,
        vault: &mut Vault,
        device_keys: &DeviceKeys,
        request: LocalRequest,
    ) -> Result<LocalResult, ClientError> {
        use context_relay_core::{
            devices::recovery::SystemRecoveryEnrollmentClock, vault::HostedEnrollmentIntent,
        };
        if device_keys.signing_public_key() != self.identity.keys.signing_public_key()
            || device_keys.wrapping_public_key() != self.identity.keys.wrapping_public_key()
        {
            return Err(recovery_error(RecoveryEnrollmentCycleError::Conflict));
        }
        if matches!(
            request,
            LocalRequest::RecoveryRestoreBegin(_)
                | LocalRequest::RecoveryRestoreOverview(_)
                | LocalRequest::RecoveryRestoreResume(_)
                | LocalRequest::RecoveryRestoreCancel(_)
                | LocalRequest::RecoveryHistoryCandidates(_)
                | LocalRequest::RecoveryHistorySelect(_)
                | LocalRequest::RecoveryHistoryUnlock(_)
        ) {
            return self.execute_restore(vault, request);
        }
        let mut coordinator = self.coordinator.lock().map_err(|_| transient_error())?;
        if matches!(request, LocalRequest::RecoveryEnrollmentBegin(_))
            && vault
                .recovery_enrollment()
                .map_err(|_| transient_error())?
                .is_none()
            && let Some(saved) = vault
                .hosted_enrollment_intent()
                .map_err(|_| transient_error())?
        {
            let now_ms = SystemRecoveryEnrollmentClock.now_ms();
            let session = self
                .owner
                .current_session(now_ms / 1000)
                .map_err(|_| transient_error())?;
            if session.is_some_and(|session| {
                saved.user_id != session.identity().user_id
                    || saved.session_id != session.identity().session_id
                    || saved
                        .reservation
                        .as_ref()
                        .is_some_and(|r| r.expires_at.0 <= now_ms)
            }) {
                vault
                    .discard_unprepared_hosted_enrollment_intent(&saved)
                    .map_err(|_| transient_error())?;
                *coordinator = None;
            }
        }
        if coordinator.is_none() {
            let mut intent = vault
                .hosted_enrollment_intent()
                .map_err(|_| transient_error())?;
            if intent.is_none() {
                if vault
                    .recovery_enrollment()
                    .map_err(|_| transient_error())?
                    .is_some()
                {
                    return Err(recovery_error(RecoveryEnrollmentCycleError::Conflict));
                }
                if matches!(request, LocalRequest::RecoveryEnrollmentOverview(_)) {
                    return Ok(LocalResult::RecoveryEnrollmentStatus {
                        status: context_relay_protocol::RecoveryEnrollmentStatus {
                            enrollment_id: None,
                            state: context_relay_protocol::RecoveryEnrollmentState::Idle,
                            created_at_ms: None,
                            transitioned_at_ms: None,
                        },
                    });
                }
                if !matches!(request, LocalRequest::RecoveryEnrollmentBegin(_)) {
                    return Err(invalid_error());
                }
            }
            let now = SystemRecoveryEnrollmentClock.now_ms() / 1000;
            let generation = self.owner.cancellation().map_err(|_| transient_error())?;
            let session = self
                .owner
                .current_session(now)
                .map_err(|_| transient_error())?
                .ok_or_else(|| recovery_error(RecoveryEnrollmentCycleError::Unauthorized))?;
            let hosted_identity = *session.identity();
            self.owner
                .session_for(&generation, hosted_identity, now)
                .map_err(|_| recovery_error(RecoveryEnrollmentCycleError::Unauthorized))?;
            if let Some(saved) = &intent {
                if saved.user_id != hosted_identity.user_id
                    || saved.session_id != hosted_identity.session_id
                    || reqwest::Url::parse(&saved.project_url).ok().as_ref()
                        != Some(session.project_url())
                {
                    return Err(recovery_error(RecoveryEnrollmentCycleError::Unauthorized));
                }
            } else {
                let saved = HostedEnrollmentIntent {
                    project_url: session.project_url().to_string(),
                    user_id: hosted_identity.user_id,
                    session_id: hosted_identity.session_id,
                    operation_id: context_relay_protocol::OperationId::new(uuid::Uuid::now_v7())
                        .map_err(|_| transient_error())?,
                    reservation: None,
                };
                vault
                    .store_hosted_enrollment_intent(&saved)
                    .map_err(|_| transient_error())?;
                intent = Some(saved);
            }
            let mut intent = intent.ok_or_else(transient_error)?;
            let client = self.client(hosted_identity, generation)?;
            if intent.reservation.is_none() {
                intent.reservation = Some(match client.reserve(intent.operation_id, now) {
                    Ok(reservation) => reservation,
                    Err(error) => {
                        if matches!(error, context_relay_core::devices::recovery_transport::RecoveryTransportError::Expired)
                            && matches!(request, LocalRequest::RecoveryEnrollmentBegin(_)) {
                            vault.discard_unprepared_hosted_enrollment_intent(&intent).map_err(|_| transient_error())?;
                        }
                        return Err(hosted_transport_error(error));
                    }
                });
                vault
                    .store_hosted_enrollment_intent(&intent)
                    .map_err(|_| transient_error())?;
            }
            if let Some(previous) = &intent.reservation
                && vault
                    .recovery_enrollment()
                    .map_err(|_| transient_error())?
                    .is_some()
            {
                let renewed = client
                    .renew(previous, now)
                    .map_err(hosted_transport_error)?;
                intent = vault
                    .renew_hosted_enrollment_intent(&intent, renewed)
                    .map_err(|_| transient_error())?;
            }
            let transport = client
                .into_transport(
                    &intent,
                    self.identity.keys.clone(),
                    SystemRecoveryEnrollmentClock,
                )
                .map_err(hosted_transport_error)?;
            *coordinator = Some(CoordinatorRecoveryEnrollmentService::new(
                RecoveryEnrollmentCoordinator::new(SystemRecoveryEnrollmentClock, transport),
                self.identity.device_id,
                self.identity.device_name.clone(),
                self.identity.platform,
            ));
        }
        let cancel = matches!(request, LocalRequest::RecoveryEnrollmentCancel(_));
        let result =
            coordinator
                .as_ref()
                .ok_or_else(transient_error)?
                .execute(vault, device_keys, request);
        if cancel
            && matches!(&result,Ok(LocalResult::RecoveryEnrollmentStatus {status}) if status.state == context_relay_protocol::RecoveryEnrollmentState::Idle)
            && vault
                .recovery_enrollment()
                .map_err(|_| transient_error())?
                .is_none()
        {
            if let Some(intent) = vault
                .hosted_enrollment_intent()
                .map_err(|_| transient_error())?
            {
                vault
                    .discard_unprepared_hosted_enrollment_intent(&intent)
                    .map_err(|_| transient_error())?;
            }
            *coordinator = None;
        }
        if result.is_err()
            && vault
                .recovery_enrollment()
                .map_err(|_| transient_error())?
                .is_some()
        {
            *coordinator = None;
        }
        result
    }
}

fn hosted_transport_error(
    error: context_relay_core::devices::recovery_transport::RecoveryTransportError,
) -> ClientError {
    use context_relay_core::devices::recovery_transport::RecoveryTransportError as T;
    recovery_error(match error {
        T::Invalid => RecoveryEnrollmentCycleError::Invalid,
        T::Conflict | T::PublicationRejected => RecoveryEnrollmentCycleError::Conflict,
        T::Unauthorized => RecoveryEnrollmentCycleError::Unauthorized,
        T::Expired => RecoveryEnrollmentCycleError::Expired,
        T::Transient => RecoveryEnrollmentCycleError::Transient,
    })
}

fn restore_error(
    error: context_relay_core::devices::recovery_restore::RecoveryRestoreCycleError,
) -> ClientError {
    use context_relay_core::devices::recovery_restore::RecoveryRestoreCycleError as E;
    let (code, retryable) = match error {
        E::Invalid => (ErrorCode::InvalidRequest, false),
        E::Conflict => (ErrorCode::Conflict, false),
        E::Unauthorized => (ErrorCode::ScopeDenied, false),
        E::Unavailable => (ErrorCode::NotFound, false),
        E::Transient => (ErrorCode::Internal, true),
    };
    ClientError {
        code,
        message: error.safe_code().into(),
        field_path: None,
        retryable,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    };

    use context_relay_core::{
        devices::{
            recovery::{RecoveryEnrollmentClock, RecoveryEnrollmentCoordinator},
            recovery_crypto::decode_recovery_enrollment_record_v1,
            recovery_transport::{
                RecoveryEnrollmentReceipt, RecoveryEnrollmentTransport, RecoveryRootStatus,
                RecoveryTransportError,
            },
        },
        sync::SyncScope,
        vault::{DatabaseKeyStore, VaultError},
    };
    use context_relay_protocol::{
        AccountId, EmptyParams, RecoveryEnrollmentConfirmParams, RecoveryEnrollmentState,
        RecoveryWordConfirmation, Sha256Digest, WorkspaceId,
    };
    use sha2::{Digest, Sha256};
    use zeroize::Zeroizing;

    use super::*;

    const ACCOUNT_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c075101";
    const WORKSPACE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c075102";
    const DEVICE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c075103";

    type AcceptedRecoveryRecord = Option<(Vec<u8>, RecoveryEnrollmentReceipt)>;

    #[derive(Clone, Default)]
    struct FixedClock(Arc<AtomicU64>);

    impl FixedClock {
        fn set(&self, now_ms: u64) {
            self.0.store(now_ms, Ordering::SeqCst);
        }
    }

    impl RecoveryEnrollmentClock for FixedClock {
        fn now_ms(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    #[derive(Clone)]
    struct TestTransport {
        scope: SyncScope,
        accepted: Arc<Mutex<AcceptedRecoveryRecord>>,
        fail_next_register: Arc<AtomicUsize>,
    }

    impl TestTransport {
        fn new(scope: SyncScope) -> Self {
            Self {
                scope,
                accepted: Arc::new(Mutex::new(None)),
                fail_next_register: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn fail_next_register(&self) {
            self.fail_next_register.store(1, Ordering::SeqCst);
        }
    }

    impl RecoveryEnrollmentTransport for TestTransport {
        fn scope(&self) -> SyncScope {
            self.scope
        }

        fn root_status(&self) -> Result<Option<RecoveryRootStatus>, RecoveryTransportError> {
            Ok(self
                .accepted
                .lock()
                .map_err(|_| RecoveryTransportError::Transient)?
                .as_ref()
                .map(|(_, receipt)| receipt.clone().into_status()))
        }

        fn register(
            &self,
            canonical_record: &[u8],
            now_ms: u64,
        ) -> Result<RecoveryEnrollmentReceipt, RecoveryTransportError> {
            if self.fail_next_register.swap(0, Ordering::SeqCst) != 0 {
                return Err(RecoveryTransportError::Transient);
            }
            let record = decode_recovery_enrollment_record_v1(canonical_record)
                .map_err(|_| RecoveryTransportError::Invalid)?;
            if record.account_id != self.scope.account_id
                || record.workspace_id != self.scope.workspace_id
            {
                return Err(RecoveryTransportError::Unauthorized);
            }
            let receipt = RecoveryEnrollmentReceipt {
                enrollment_id: record.enrollment_id,
                recovery_root_id: record.recovery_root_id,
                account_id: record.account_id,
                workspace_id: record.workspace_id,
                genesis_certificate_id: record.genesis_certificate_id,
                canonical_record_sha256: Sha256Digest(Sha256::digest(canonical_record).into()),
                registered_at_ms: now_ms,
            };
            let mut accepted = self
                .accepted
                .lock()
                .map_err(|_| RecoveryTransportError::Transient)?;
            if let Some((bytes, existing)) = &*accepted {
                return if bytes == canonical_record {
                    Ok(existing.clone())
                } else {
                    Err(RecoveryTransportError::Conflict)
                };
            }
            *accepted = Some((canonical_record.to_vec(), receipt.clone()));
            Ok(receipt)
        }
    }

    #[derive(Default)]
    struct MemoryKeyStore(Mutex<Option<Vec<u8>>>);

    impl DatabaseKeyStore for MemoryKeyStore {
        fn load_key(&self, _: &str) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
            Ok(self.0.lock().unwrap().clone().map(Zeroizing::new))
        }

        fn store_key(&self, _: &str, key: &[u8]) -> Result<(), VaultError> {
            *self.0.lock().unwrap() = Some(key.to_vec());
            Ok(())
        }
    }

    fn scope() -> SyncScope {
        SyncScope {
            account_id: ACCOUNT_ID.parse::<AccountId>().unwrap(),
            workspace_id: WORKSPACE_ID.parse::<WorkspaceId>().unwrap(),
        }
    }

    #[test]
    fn hosted_service_starts_offline_and_requires_login_before_reserving() {
        use context_relay_core::auth::{
            HostedSessionOwner, LoginError, LoginStore, StoredLogin, SupabaseAuthClient,
        };
        struct NoLogin;
        impl LoginStore for NoLogin {
            fn load(&self) -> Result<Option<StoredLogin>, LoginError> {
                Ok(None)
            }
            fn save(&self, _: &StoredLogin) -> Result<(), LoginError> {
                Err(LoginError::CredentialStore)
            }
            fn clear(&self) -> Result<(), LoginError> {
                Ok(())
            }
        }
        let project = "https://example.supabase.co";
        let owner = Arc::new(HostedSessionOwner::new(
            Arc::new(SupabaseAuthClient::new(project, "public-test").unwrap()),
            Arc::new(NoLogin),
        ));
        let keys = Arc::new(DeviceKeys::generate().unwrap());
        let service = HostedRecoveryEnrollmentService::new(
            owner,
            project,
            "public-test",
            crate::pairing::PairingIdentity {
                device_id: DEVICE_ID.parse().unwrap(),
                device_name: "Test desktop".into(),
                platform: NativePlatform::Windows,
                keys: keys.clone(),
            },
        );
        let directory = tempfile::tempdir().unwrap();
        let mut vault = Vault::open(
            &directory.path().join("hosted.db"),
            "hosted-service",
            &MemoryKeyStore::default(),
        )
        .unwrap();
        service.resume_prepared(&mut vault, &keys).unwrap();
        assert!(
            matches!(service.execute(&mut vault,&keys,LocalRequest::RecoveryEnrollmentOverview(EmptyParams {})).unwrap(),
            LocalResult::RecoveryEnrollmentStatus { status } if status.state == RecoveryEnrollmentState::Idle)
        );
        assert_eq!(
            service
                .execute(
                    &mut vault,
                    &keys,
                    LocalRequest::RecoveryEnrollmentBegin(EmptyParams {})
                )
                .unwrap_err()
                .code,
            ErrorCode::ScopeDenied
        );
        assert!(vault.hosted_enrollment_intent().unwrap().is_none());
        assert!(vault.recovery_enrollment().unwrap().is_none());
    }

    #[test]
    fn coordinator_service_maps_the_full_lifecycle_and_resumes_after_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("recovery-service.db");
        let key_store = MemoryKeyStore::default();
        let device_keys = DeviceKeys::generate().unwrap();
        let clock = FixedClock::default();
        clock.set(1_000);
        let transport = TestTransport::new(scope());
        let service = CoordinatorRecoveryEnrollmentService::new(
            RecoveryEnrollmentCoordinator::new(clock.clone(), transport.clone()),
            DEVICE_ID.parse().unwrap(),
            "First Mac",
            NativePlatform::Macos,
        );
        let mut vault = Vault::open(&path, "recovery-service", &key_store).unwrap();
        let LocalResult::RecoveryEnrollmentPhrase { phrase } = service
            .execute(
                &mut vault,
                &device_keys,
                LocalRequest::RecoveryEnrollmentBegin(EmptyParams {}),
            )
            .unwrap()
        else {
            panic!("begin did not return the protected phrase result")
        };
        assert_eq!(
            service
                .execute(
                    &mut vault,
                    &device_keys,
                    LocalRequest::RecoveryEnrollmentOverview(EmptyParams {}),
                )
                .unwrap(),
            LocalResult::RecoveryEnrollmentStatus {
                status: context_relay_protocol::RecoveryEnrollmentStatus {
                    enrollment_id: Some(phrase.enrollment_id),
                    state: RecoveryEnrollmentState::AwaitingConfirmation,
                    created_at_ms: Some(phrase.created_at_ms),
                    transitioned_at_ms: None,
                },
            }
        );
        clock.set(1_100);
        let params = RecoveryEnrollmentConfirmParams {
            enrollment_id: phrase.enrollment_id,
            confirmations: phrase
                .confirmation_positions
                .iter()
                .map(|position| RecoveryWordConfirmation {
                    position: *position,
                    word: phrase.recovery_phrase_words.as_words()[usize::from(*position) - 1]
                        .clone(),
                })
                .collect(),
        };
        transport.fail_next_register();
        assert!(matches!(
            service
                .execute(
                    &mut vault,
                    &device_keys,
                    LocalRequest::RecoveryEnrollmentConfirm(params),
                )
                .unwrap(),
            LocalResult::RecoveryEnrollmentStatus { status }
                if status.state == RecoveryEnrollmentState::Submitting
        ));
        drop(service);
        drop(vault);

        let mut vault = Vault::open(&path, "recovery-service", &key_store).unwrap();
        let resumed = CoordinatorRecoveryEnrollmentService::new(
            RecoveryEnrollmentCoordinator::new(clock, transport),
            DEVICE_ID.parse().unwrap(),
            "First Mac",
            NativePlatform::Macos,
        );
        resumed.resume_prepared(&mut vault, &device_keys).unwrap();
        assert!(matches!(
            resumed
                .execute(
                    &mut vault,
                    &device_keys,
                    LocalRequest::RecoveryEnrollmentOverview(EmptyParams {}),
                )
                .unwrap(),
            LocalResult::RecoveryEnrollmentStatus { status }
                if status.state == RecoveryEnrollmentState::Complete
        ));
    }

    #[test]
    fn unavailable_service_returns_only_the_frozen_safe_error() {
        let directory = tempfile::tempdir().unwrap();
        let key_store = MemoryKeyStore::default();
        let mut vault = Vault::open(
            &directory.path().join("unavailable.db"),
            "unavailable",
            &key_store,
        )
        .unwrap();
        let error = UnavailableRecoveryEnrollmentService
            .execute(
                &mut vault,
                &DeviceKeys::generate().unwrap(),
                LocalRequest::RecoveryEnrollmentOverview(EmptyParams {}),
            )
            .unwrap_err();
        assert_eq!(error, unavailable_error());
        assert_eq!(error.message, RECOVERY_UNAVAILABLE_MESSAGE);
    }
}

#[cfg(test)]
mod hosted_expiry_tests {
    use super::*;
    use context_relay_core::{
        auth::{
            HostedSessionOwner, LoginError, LoginStore, PendingLogin, StoredLogin,
            SupabaseAuthClient,
        },
        sync::{SupabaseHttpClient, SupabaseHttpError, SupabaseHttpRequest, SupabaseHttpResponse},
        vault::{DatabaseKeyStore, RecoveryEnrollmentPersistenceState, VaultError},
    };
    use context_relay_protocol::{
        EmptyParams, RecoveryEnrollmentConfirmParams, RecoveryEnrollmentState,
        RecoveryWordConfirmation,
    };
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use std::sync::{Arc, Mutex};
    #[derive(Default)]
    struct Keys(Mutex<Option<Vec<u8>>>);
    impl DatabaseKeyStore for Keys {
        fn load_key(&self, _: &str) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, VaultError> {
            Ok(self.0.lock().unwrap().clone().map(zeroize::Zeroizing::new))
        }
        fn store_key(&self, _: &str, key: &[u8]) -> Result<(), VaultError> {
            *self.0.lock().unwrap() = Some(key.to_vec());
            Ok(())
        }
    }
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
    #[derive(Default)]
    struct Remote {
        reserve_ids: Vec<Value>,
        reservation: Value,
        receipt: Value,
        records: Vec<Value>,
        lose_reserve: bool,
        expire_commit: bool,
        lose_restore: bool,
        reject_restore: bool,
        history_checkpoints: Vec<Value>,
        history_operations: Vec<Value>,
        history_offline: bool,
        history_repeat_page: bool,
    }
    struct Http {
        state: Mutex<Remote>,
        path: std::path::PathBuf,
        keys: Arc<Keys>,
        now: u64,
    }
    impl SupabaseHttpClient for Http {
        fn execute(
            &self,
            request: SupabaseHttpRequest,
        ) -> Result<SupabaseHttpResponse, SupabaseHttpError> {
            use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
            let reply = |status, body: Value| {
                Ok(SupabaseHttpResponse::new(
                    status,
                    serde_json::to_vec(&body).unwrap(),
                ))
            };
            if request.url().ends_with("/user") {
                return reply(200, json!({"id":"550e8400-e29b-41d4-a716-446655440000"}));
            }
            if request.url().contains("/auth/v1/token") {
                let claims = json!({"iss":"https://example.supabase.co/auth/v1","aud":"authenticated",
                    "sub":"550e8400-e29b-41d4-a716-446655440000","session_id":"550e8400-e29b-41d4-a716-446655440001","exp":self.now+3600});
                return reply(
                    200,
                    json!({"token_type":"bearer","access_token":format!("e30.{}.signature",URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())),"refresh_token":"synthetic-refresh"}),
                );
            }
            if request.url().contains("/rest/v1/sync_") {
                let url = reqwest::Url::parse(request.url()).unwrap();
                let state = self.state.lock().unwrap();
                if state.history_offline {
                    return reply(503, json!({"error":"synthetic offline"}));
                }
                if url.path().ends_with("sync_checkpoints") {
                    if let Some((_, hash)) =
                        url.query_pairs().find(|(k, _)| k == "canonical_sha256")
                    {
                        return reply(
                            200,
                            json!(
                                state
                                    .history_checkpoints
                                    .iter()
                                    .filter(|row| hash
                                        == format!(
                                            "eq.{}",
                                            row["canonical_sha256"].as_str().unwrap()
                                        ))
                                    .cloned()
                                    .collect::<Vec<_>>()
                            ),
                        );
                    }
                    assert!(url.query_pairs().any(|(k, v)| k == "limit" && v == "8"));
                    if url.query_pairs().any(|(k, _)| k == "or") && !state.history_repeat_page {
                        return reply(200, json!([]));
                    }
                    return reply(200, json!(state.history_checkpoints));
                }
                assert!(url.path().ends_with("sync_operations"));
                return reply(200, json!(state.history_operations));
            }
            let body: Value = serde_json::from_slice(request.body()).unwrap();
            let vault = Vault::open(&self.path, "expiry-test", self.keys.as_ref()).unwrap();
            if matches!(
                body["action"].as_str(),
                Some(
                    "snapshot"
                        | "restore"
                        | "restore_status"
                        | "recovery_membership_endpoint"
                        | "recovery_membership_event"
                )
            ) {
                let intent = vault.hosted_restore_intent().unwrap().unwrap();
                assert_eq!(intent.project_url, "https://example.supabase.co/");
                let mut state = self.state.lock().unwrap();
                let encoded =
                    include_str!("../../core/tests/fixtures/recovery-enrollment-record-v1.hex")
                        .trim();
                let canonical: Vec<u8> = encoded
                    .as_bytes()
                    .chunks_exact(2)
                    .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
                    .collect();
                let root = context_relay_core::devices::recovery_crypto::decode_recovery_enrollment_record_v1(&canonical).unwrap();
                let pin = context_relay_protocol::Sha256Digest(Sha256::digest(&canonical).into());
                if body["action"] == "recovery_membership_endpoint" {
                    let endpoint =
                        context_relay_core::devices::membership_transport::enrollment_endpoint(
                            &canonical,
                            pin,
                            context_relay_core::sync::SyncScope {
                                account_id: root.account_id,
                                workspace_id: root.workspace_id,
                            },
                        )
                        .unwrap();
                    return reply(
                        200,
                        json!({"v":1,"endpoint":{"stateSha256":endpoint.state_sha256,"controlEpoch":endpoint.control_epoch,"keyEpoch":endpoint.key_epoch}}),
                    );
                }
                if body["action"] == "recovery_membership_event" {
                    let claim = state.records.last().unwrap().as_str().unwrap();
                    let bytes: Vec<u8> = claim
                        .as_bytes()
                        .chunks_exact(2)
                        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
                        .collect();
                    let object = context_relay_core::devices::membership_transport::MembershipEventObject::from_evidence(&context_relay_core::devices::membership_crypto::MembershipHistoryEvent::RecoveryAdd { canonical_claim: &bytes }).unwrap();
                    assert_eq!(
                        body["successorSha256"],
                        json!(object.endpoints().unwrap().1)
                    );
                    return reply(
                        200,
                        json!({"v":1,"object":object.canonical_bytes().iter().map(|b|format!("{b:02x}")).collect::<String>()}),
                    );
                }
                if body["action"] == "snapshot" {
                    return reply(
                        200,
                        json!({"v":1,"snapshot":{"accountId":root.account_id,"workspaceId":root.workspace_id,
                        "canonicalRecord":encoded,"canonicalRecordSha256":format!("{:x}",Sha256::digest(&canonical)),
                        "registeredAtMs":(self.now*1000).to_string(),"recoveryGeneration":state.receipt["acceptedGeneration"].as_str().unwrap_or("0")}}),
                    );
                }
                if body["action"] == "restore_status" {
                    return reply(
                        200,
                        json!({"v":1,"projection":{"canonicalClaim":state.records.last().unwrap(),"receipt":state.receipt}}),
                    );
                }
                let claim_bytes: Vec<u8> = body["claim"]
                    .as_str()
                    .unwrap()
                    .as_bytes()
                    .chunks_exact(2)
                    .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
                    .collect();
                let claim = context_relay_core::devices::recovery_restore_crypto::v2::decode_recovery_device_claim_v2(&claim_bytes).unwrap();
                assert!(vault.recovery_restore().unwrap().is_none());
                assert_eq!(body["proof"].as_str().unwrap().len(), 128);
                let mut proof_input = b"context-relay/hosted-recovery-device-proof/v2\0".to_vec();
                proof_input.extend_from_slice(intent.user_id.as_bytes());
                proof_input.extend_from_slice(intent.session_id.as_bytes());
                proof_input.extend_from_slice(&Sha256::digest(&claim_bytes));
                let signature: Vec<u8> = body["proof"]
                    .as_str()
                    .unwrap()
                    .as_bytes()
                    .chunks_exact(2)
                    .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
                    .collect();
                context_relay_core::crypto::verify_signature(
                    claim.certificate.signing_public_key,
                    &proof_input,
                    context_relay_protocol::Ed25519SignatureBytes(signature.try_into().unwrap()),
                )
                .unwrap();
                state.records.push(body["claim"].clone());
                if state.reject_restore {
                    return reply(409, json!({"v":1,"error":"recovery_publication_rejected"}));
                }

                state.receipt = json!({"restoreId":claim.restore_id,"enrollmentId":root.enrollment_id,"recoveryRootId":root.recovery_root_id,
                    "accountId":root.account_id,"workspaceId":root.workspace_id,"certificateId":claim.certificate_id,
                    "canonicalRecordSha256":pin,"canonicalClaimSha256":format!("{:x}",Sha256::digest(&claim_bytes)),
                    "acceptedGeneration":(claim.expected_recovery_generation+1).to_string(),"acceptedAtMs":(self.now*1000).to_string()});
                if std::mem::take(&mut state.lose_restore) {
                    return reply(503, json!({"v":1,"error":"transient"}));
                }
                return reply(200, json!({"v":1,"receipt":state.receipt}));
            }
            let intent = vault.hosted_enrollment_intent().unwrap().unwrap();
            assert_eq!(json!(intent.operation_id), body["reservationId"]);
            let mut state = self.state.lock().unwrap();
            match body["action"].as_str().unwrap() {
                "reserve" => {
                    assert!(intent.reservation.is_none());
                    state.reserve_ids.push(body["reservationId"].clone());
                    if state.lose_reserve && state.reserve_ids.len() == 1 {
                        return reply(503, json!({"v":1,"error":"transient"}));
                    }
                    if state.lose_reserve && state.reserve_ids.len() == 2 {
                        return reply(403, json!({"v":1,"error":"enrollment_reservation_expired"}));
                    }
                    state.reservation = json!({"reservationId":body["reservationId"],"accountId":"018f22e2-79b0-7cc8-98c4-dc0c0c075101",
                        "workspaceId":"018f22e2-79b0-7cc8-98c4-dc0c0c075102","nonce":"42".repeat(32),"expiresAt":((self.now+600)*1000).to_string()});
                    reply(200, json!({"v":1,"reservation":state.reservation}))
                }
                "renew" => {
                    assert!(vault.recovery_enrollment().unwrap().is_some());
                    state.reservation["nonce"] = json!("43".repeat(32));
                    state.reservation["expiresAt"] = json!(((self.now + 1200) * 1000).to_string());
                    reply(200, json!({"v":1,"reservation":state.reservation}))
                }
                "status" => {
                    let mut reservation = state.reservation.clone();
                    reservation["receipt"] = state.receipt.clone();
                    reply(200, json!({"v":1,"reservation":reservation}))
                }
                "commit" => {
                    let stored = vault.recovery_enrollment().unwrap().unwrap();
                    assert_eq!(stored.state, RecoveryEnrollmentPersistenceState::Prepared);
                    assert_eq!(
                        body["record"],
                        stored
                            .canonical_record
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<String>()
                    );
                    state.records.push(body["record"].clone());
                    if state.expire_commit {
                        state.expire_commit = false;
                        return reply(403, json!({"v":1,"error":"enrollment_reservation_expired"}));
                    }
                    let r = stored.record;
                    state.receipt = json!({"enrollmentId":r.enrollment_id,"recoveryRootId":r.recovery_root_id,"accountId":r.account_id,
                        "workspaceId":r.workspace_id,"genesisCertificateId":r.genesis_certificate_id,
                        "canonicalRecordSha256":format!("{:x}",Sha256::digest(&stored.canonical_record)),"registeredAtMs":(self.now*1000).to_string()});
                    reply(200, json!({"v":1,"receipt":state.receipt}))
                }
                _ => panic!("unexpected action"),
            }
        }
    }
    #[test]
    fn hosted_restore_resumes_exact_claim_after_restart_without_reentering_phrase() {
        hosted_restore_restart(false, false, false);
    }
    #[test]
    fn hosted_restore_terminal_conflict_reopens_and_resumes_offline() {
        hosted_restore_restart(true, false, false);
    }
    #[test]
    fn original_history_session_cancellation_guards_commit_and_final_status() {
        hosted_restore_restart(false, true, false);
    }
    #[test]
    fn hosted_history_resume_restores_searchable_memory_and_instruction() {
        hosted_restore_restart(false, false, true);
    }
    fn hosted_restore_restart(
        terminal_conflict: bool,
        check_authorization: bool,
        searchable_history: bool,
    ) {
        use context_relay_protocol::{RecoveryRestoreParams, RecoveryRestoreStatus as Status};
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("restore.db");
        let keys = Arc::new(Keys::default());
        let mut vault = Vault::open(&path, "expiry-test", keys.as_ref()).unwrap();
        let now =
            context_relay_core::devices::recovery::SystemRecoveryEnrollmentClock.now_ms() / 1000;
        let http = Arc::new(Http {
            state: Mutex::new(Remote {
                lose_restore: true,
                ..Remote::default()
            }),
            path: path.clone(),
            keys: keys.clone(),
            now,
        });
        let project = "https://example.supabase.co";
        let owner = Arc::new(HostedSessionOwner::new(
            Arc::new(
                SupabaseAuthClient::with_http_client(project, "public-test", http.clone()).unwrap(),
            ),
            Arc::new(Login),
        ));
        let device = Arc::new(DeviceKeys::generate().unwrap());
        let make_service = || {
            let mut service = HostedRecoveryEnrollmentService::new(
                owner.clone(),
                project,
                "public-test",
                crate::pairing::PairingIdentity {
                    device_id: "018f22e2-79b0-7cc8-98c4-dc0c0c075104".parse().unwrap(),
                    device_name: "Recovered desktop".into(),
                    platform: NativePlatform::Windows,
                    keys: device.clone(),
                },
            );
            service.http = Some(http.clone());
            service
        };
        let service = make_service();
        service.resume_prepared(&mut vault, &device).unwrap();
        assert!(matches!(
            service
                .execute(
                    &mut vault,
                    &device,
                    LocalRequest::RecoveryRestoreOverview(EmptyParams {})
                )
                .unwrap(),
            LocalResult::RecoveryRestoreStatus {
                status: Status::Idle {}
            }
        ));
        let phrase = || {
            context_relay_core::crypto::RecoveryPhrase::from_entropy_for_test([0; 32])
                .unwrap()
                .to_words()
        };
        assert!(
            service
                .execute(
                    &mut vault,
                    &device,
                    LocalRequest::RecoveryRestoreBegin(RecoveryRestoreParams {
                        recovery_phrase_words: phrase()
                    })
                )
                .is_err()
        );
        assert!(vault.hosted_restore_intent().unwrap().is_none());
        let instant = std::time::Instant::now();
        let mut pending =
            PendingLogin::new(project, "127.0.0.1:41783".parse().unwrap(), instant).unwrap();
        let auth = pending.authorization_url();
        let redirect = auth
            .query_pairs()
            .find(|(k, _)| k == "redirect_to")
            .unwrap()
            .1
            .into_owned();
        let mut callback = auth.join(&redirect).unwrap();
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
        let LocalResult::RecoveryEnrollmentPhrase { phrase: enrollment } = service
            .execute(
                &mut vault,
                &device,
                LocalRequest::RecoveryEnrollmentBegin(EmptyParams {}),
            )
            .unwrap()
        else {
            panic!("expected enrollment phrase")
        };
        assert!(vault.hosted_enrollment_intent().unwrap().is_some());
        service
            .execute(
                &mut vault,
                &device,
                LocalRequest::RecoveryEnrollmentCancel(
                    context_relay_protocol::RecoveryEnrollmentIdParams {
                        enrollment_id: enrollment.enrollment_id,
                    },
                ),
            )
            .unwrap();
        assert!(vault.hosted_enrollment_intent().unwrap().is_none());
        assert!(
            service
                .execute(
                    &mut vault,
                    &device,
                    LocalRequest::RecoveryRestoreBegin(RecoveryRestoreParams {
                        recovery_phrase_words:
                            context_relay_core::crypto::RecoveryPhrase::from_entropy_for_test(
                                [1; 32]
                            )
                            .unwrap()
                            .to_words(),
                    })
                )
                .is_err()
        );
        assert!(vault.recovery_restore().unwrap().is_none());
        assert!(vault.hosted_restore_intent().unwrap().is_some());
        assert!(matches!(
            service
                .execute(
                    &mut vault,
                    &device,
                    LocalRequest::RecoveryRestoreCancel(EmptyParams {})
                )
                .unwrap(),
            LocalResult::RecoveryRestoreStatus {
                status: Status::Idle {}
            }
        ));
        assert!(vault.hosted_restore_intent().unwrap().is_none());
        assert!(matches!(
            service
                .execute(
                    &mut vault,
                    &device,
                    LocalRequest::RecoveryRestoreBegin(RecoveryRestoreParams {
                        recovery_phrase_words: phrase()
                    })
                )
                .unwrap(),
            LocalResult::RecoveryRestoreStatus {
                status: Status::Submitting { .. }
            }
        ));
        let claim = vault
            .prepared_recovery_v2(&device)
            .unwrap()
            .unwrap()
            .canonical_claim;
        assert!(matches!(
            service
                .execute(
                    &mut vault,
                    &device,
                    LocalRequest::RecoveryRestoreOverview(EmptyParams {})
                )
                .unwrap(),
            LocalResult::RecoveryRestoreStatus {
                status: Status::Submitting { .. }
            }
        ));
        assert_eq!(
            service
                .execute(
                    &mut vault,
                    &device,
                    LocalRequest::RecoveryRestoreCancel(EmptyParams {})
                )
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
        drop(service);
        drop(vault);
        let mut vault = Vault::open(&path, "expiry-test", keys.as_ref()).unwrap();
        let service = make_service();
        assert_eq!(
            vault
                .prepared_recovery_v2(&device)
                .unwrap()
                .unwrap()
                .canonical_claim,
            claim
        );
        assert!(matches!(
            service
                .execute(
                    &mut vault,
                    &device,
                    LocalRequest::RecoveryRestoreOverview(EmptyParams {})
                )
                .unwrap(),
            LocalResult::RecoveryRestoreStatus {
                status: Status::Submitting { .. }
            }
        ));
        service.resume_prepared(&mut vault, &device).unwrap();
        if terminal_conflict {
            http.state.lock().unwrap().reject_restore = true;
            assert!(matches!(
                service
                    .execute(
                        &mut vault,
                        &device,
                        LocalRequest::RecoveryRestoreResume(EmptyParams {})
                    )
                    .unwrap(),
                LocalResult::RecoveryRestoreStatus {
                    status: Status::Conflict { .. }
                }
            ));
            drop(vault);
            let mut vault = Vault::open(&path, "expiry-test", keys.as_ref()).unwrap();
            let service = make_service();
            owner.begin_login().unwrap();
            let requests = http.state.lock().unwrap().records.len();
            for request in [
                LocalRequest::RecoveryRestoreOverview(EmptyParams {}),
                LocalRequest::RecoveryRestoreResume(EmptyParams {}),
            ] {
                assert!(matches!(
                    service.execute(&mut vault, &device, request).unwrap(),
                    LocalResult::RecoveryRestoreStatus {
                        status: Status::Conflict { .. }
                    }
                ));
            }
            assert_eq!(http.state.lock().unwrap().records.len(), requests);
            assert_eq!(
                vault
                    .prepared_recovery_v2(&device)
                    .unwrap()
                    .unwrap()
                    .canonical_claim,
                claim
            );
            assert!(
                service
                    .execute(
                        &mut vault,
                        &device,
                        LocalRequest::RecoveryRestoreCancel(EmptyParams {})
                    )
                    .is_err()
            );
            assert!(vault.trusted_sync_material(&device).is_err());
            return;
        }
        assert!(matches!(
            service
                .execute(
                    &mut vault,
                    &device,
                    LocalRequest::RecoveryRestoreResume(EmptyParams {})
                )
                .unwrap(),
            LocalResult::RecoveryRestoreStatus {
                status: Status::RestoringHistory { .. }
            }
        ));
        assert_eq!(
            vault
                .prepared_recovery_v2(&device)
                .unwrap()
                .unwrap()
                .canonical_claim,
            claim
        );
        assert_eq!(http.state.lock().unwrap().records.len(), 2);
        owner.begin_login().unwrap();
        assert!(
            service
                .execute(
                    &mut vault,
                    &device,
                    LocalRequest::RecoveryRestoreResume(EmptyParams {})
                )
                .is_err()
        );
        assert_eq!(
            vault
                .prepared_recovery_v2(&device)
                .unwrap()
                .unwrap()
                .canonical_claim,
            claim
        );
        assert!(vault.trusted_sync_material(&device).is_err());
        assert!(matches!(
            service
                .execute(
                    &mut vault,
                    &device,
                    LocalRequest::RecoveryRestoreOverview(EmptyParams {})
                )
                .unwrap(),
            LocalResult::RecoveryRestoreStatus {
                status: Status::RestoringHistory { .. }
            }
        ));
        // A fresh authenticated session resumes the same durable restore identity.
        let instant = std::time::Instant::now();
        let mut pending =
            PendingLogin::new(project, "127.0.0.1:41783".parse().unwrap(), instant).unwrap();
        let auth = pending.authorization_url();
        let redirect = auth
            .query_pairs()
            .find(|(k, _)| k == "redirect_to")
            .unwrap()
            .1
            .into_owned();
        let mut callback = auth.join(&redirect).unwrap();
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
        if searchable_history {
            exercise_searchable_history(&service, &mut vault, &device, &http);
            return;
        }
        exercise_history_selection(&service, &mut vault, &device, &http, check_authorization);
        if check_authorization {
            return;
        }
        drop(vault);
        let mut vault = Vault::open(&path, "expiry-test", keys.as_ref()).unwrap();
        let service = make_service();
        service.resume_prepared(&mut vault, &device).unwrap();
        assert!(matches!(
            service
                .execute(
                    &mut vault,
                    &device,
                    LocalRequest::RecoveryRestoreOverview(EmptyParams {})
                )
                .unwrap(),
            LocalResult::RecoveryRestoreStatus {
                status: Status::Complete { .. }
            }
        ));
    }

    fn exercise_searchable_history(
        service: &HostedRecoveryEnrollmentService,
        vault: &mut Vault,
        device: &DeviceKeys,
        http: &Http,
    ) {
        use context_relay_core::{
            search::AllowedSearchScope,
            service::sync_embedding,
            sync::{
                CanonicalCheckpoint, CanonicalOperation, OperationBuildRequest, OperationBuilder,
                OperationChainHead, StateSummaryEntryV1, StateSummaryV1, SyncIdentity,
            },
        };
        use context_relay_protocol::{
            CheckpointV1, DeviceSequence, Ed25519SignatureBytes, HarnessAccessPolicy,
            HybridLogicalClock, InstructionRecord, MemoryKind, MemoryOrigin, MemoryRecord,
            Provenance, RecordMutationV1, RecoveryHistoryCandidatesParams, RecoveryHistoryExtent,
            RecoveryHistoryProgress, RecoveryHistorySelectParams, RecoveryRestoreStatus as Status,
            ScopeRef, Sha256Digest,
        };
        let prepared = vault.prepared_recovery_v2(device).unwrap().unwrap();
        let endpoint = vault
            .recovery_membership_admission(device)
            .unwrap()
            .unwrap();
        let root =
            context_relay_core::devices::recovery_crypto::decode_recovery_enrollment_record_v1(
                &prepared.canonical_record,
            )
            .unwrap();
        let author = DeviceKeys::from_seeds_for_test([0x11; 32], [0x22; 32]);
        let author_id = root.genesis_certificate.device_id;
        let project_id = "018f22e2-79b0-7cc8-98c4-dc0c0c073950".parse().unwrap();
        let memory_operation = "018f22e2-79b0-7cc8-98c4-dc0c0c073952".parse().unwrap();
        let instruction_operation = "018f22e2-79b0-7cc8-98c4-dc0c0c073955".parse().unwrap();
        let clock = HybridLogicalClock::new(1001, 0, author_id);
        let provenance = Provenance {
            origin_device: author_id,
            harness: None,
            source: None,
            created_hlc: clock,
        };
        let memory = MemoryRecord {
            id: "018f22e2-79b0-7cc8-98c4-dc0c0c073951".parse().unwrap(),
            scope: ScopeRef::Project { project_id },
            kind: MemoryKind::Fact,
            title: "Restored memory".into(),
            body_markdown: "Authenticated historical memory content".into(),
            tags: vec!["recovery".into()],
            origin: MemoryOrigin::Explicit,
            provenance: provenance.clone(),
            revision: memory_operation,
            created_hlc: clock,
            updated_hlc: clock,
            archived: false,
        };
        let instruction = InstructionRecord {
            id: "018f22e2-79b0-7cc8-98c4-dc0c0c073954".parse().unwrap(),
            scope: ScopeRef::Project { project_id },
            title: "Restored instruction".into(),
            body_markdown: "Authenticated historical instruction content".into(),
            provenance,
            archived: false,
        };
        let content = context_relay_core::crypto::ContentKey::from_bytes([0x55; 32]);
        let builder = OperationBuilder::new(SyncIdentity {
            membership_endpoint: Some(prepared.parent.endpoint()),
            account_id: root.account_id,
            workspace_id: root.workspace_id,
            device_id: author_id,
            control_epoch: 1,
            key_epoch: 1,
            device_keys: &author,
            content_key: &content,
        });
        let mutations = [
            (
                memory_operation,
                RecordMutationV1::UpsertMemory(memory.clone()),
            ),
            (
                instruction_operation,
                RecordMutationV1::UpsertInstruction(instruction.clone()),
            ),
        ];
        let mut operations = Vec::new();
        let mut summaries = Vec::new();
        let mut previous = None;
        for (index, (operation_id, mutation)) in mutations.iter().enumerate() {
            let sequence = index as u64 + 1;
            let built = builder
                .build(OperationBuildRequest {
                    operation_id: *operation_id,
                    project_id: Some(project_id),
                    mutation,
                    causal_frontier: if index == 0 {
                        vec![]
                    } else {
                        vec![DeviceSequence {
                            device_id: author_id,
                            sequence: sequence - 1,
                        }]
                    },
                    previous,
                    blob_refs: vec![],
                    created_hlc: HybridLogicalClock::new(1001 + index as u64, 0, author_id),
                })
                .unwrap();
            previous = Some(OperationChainHead {
                sequence,
                canonical_hash: built.canonical_hash,
            });
            summaries.push(StateSummaryEntryV1 {
                record_id: mutation.record_id(),
                record_kind: mutation.record_kind(),
                head_hashes: vec![built.canonical_hash],
                tombstoned: false,
                conflicted: false,
            });
            operations.push(CanonicalOperation {
                operation_id: *operation_id,
                device_id: author_id,
                device_sequence: sequence,
                bytes: built.canonical_bytes,
            });
        }
        let mut checkpoint = CheckpointV1 {
            schema_version: 2,
            account_id: root.account_id,
            workspace_id: root.workspace_id,
            previous_checkpoint_hash: Sha256Digest([0; 32]),
            causal_frontier: vec![DeviceSequence {
                device_id: author_id,
                sequence: 2,
            }],
            state_hash: StateSummaryV1 { entries: summaries }.state_hash().unwrap(),
            key_epoch: 1,
            creator_device: author_id,
            created_hlc: HybridLogicalClock::new(1003, 0, author_id),
            signature: Ed25519SignatureBytes([0; 64]),
        };
        author.sign_checkpoint(&mut checkpoint).unwrap();
        let checkpoint = CanonicalCheckpoint::from_checkpoint(checkpoint).unwrap();
        {
            let mut remote = http.state.lock().unwrap();
            remote.history_checkpoints = vec![history_checkpoint_row(&checkpoint)];
            remote.history_operations = operations.iter().map(history_operation_row).collect();
        }
        let LocalResult::RecoveryHistoryCandidates { page } = service
            .execute(
                vault,
                device,
                LocalRequest::RecoveryHistoryCandidates(RecoveryHistoryCandidatesParams {
                    restore_id: prepared.claim.restore_id,
                    accepted_endpoint_sha256: endpoint.state_sha256,
                    cursor: None,
                }),
            )
            .unwrap()
        else {
            panic!("authenticated candidate page")
        };
        assert_eq!(page.candidates.len(), 1);
        assert_eq!(
            page.candidates[0].checkpoint_sha256,
            checkpoint.canonical_hash
        );
        assert_eq!(
            page.candidates[0].extent,
            RecoveryHistoryExtent::Supported { operation_count: 2 }
        );
        assert!(
            vault
                .recovery_history_selection(device, history::budget())
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            service
                .execute(
                    vault,
                    device,
                    LocalRequest::RecoveryHistorySelect(RecoveryHistorySelectParams {
                        restore_id: prepared.claim.restore_id,
                        accepted_endpoint_sha256: endpoint.state_sha256,
                        checkpoint_sha256: checkpoint.canonical_hash,
                    })
                )
                .unwrap(),
            LocalResult::RecoveryRestoreStatus {
                status: Status::RestoringHistory {
                    history: RecoveryHistoryProgress::Incomplete { .. },
                    ..
                }
            }
        ));
        assert!(
            matches!(
                service
                    .execute(
                        vault,
                        device,
                        LocalRequest::RecoveryRestoreResume(EmptyParams {})
                    )
                    .unwrap(),
                LocalResult::RecoveryRestoreStatus {
                    status: Status::Complete { .. }
                }
            ),
            "actual Resume must restore searchable signed records without an injected resolver"
        );
        for reopened in [false, true] {
            if reopened {
                *vault = Vault::open(&http.path, "expiry-test", http.keys.as_ref()).unwrap();
            }
            assert_eq!(vault.memory(&memory.id).unwrap(), Some(memory.clone()));
            assert_eq!(
                vault.instruction(&instruction.id).unwrap(),
                Some(instruction.clone())
            );
            let scope =
                AllowedSearchScope::resolve(None, &HarnessAccessPolicy::Default, Some(project_id))
                    .unwrap();
            let vector = sync_embedding(memory_operation, &mutations[0].1)
                .unwrap()
                .unwrap();
            let hits = vault.search("Restored", &scope, &vector, 10).unwrap();
            for (_, mutation) in &mutations {
                assert_eq!(
                    vault
                        .record_heads(root.workspace_id, mutation.record_id())
                        .unwrap()
                        .len(),
                    1
                );
                assert!(
                    vault
                        .embedding_storage_bytes(&mutation.record_id().to_string())
                        .unwrap()
                        > 0
                );
                assert!(
                    hits.iter()
                        .any(|hit| hit.record_id() == mutation.record_id().to_string()),
                    "restored lexical representation is searchable after reopen"
                );
            }
            assert!(matches!(
                service
                    .execute(
                        vault,
                        device,
                        LocalRequest::RecoveryRestoreOverview(EmptyParams {})
                    )
                    .unwrap(),
                LocalResult::RecoveryRestoreStatus {
                    status: Status::Complete { .. }
                }
            ));
            assert_eq!(
                vault
                    .prepared_recovery_v2(device)
                    .unwrap()
                    .unwrap()
                    .canonical_claim,
                prepared.canonical_claim
            );
        }
    }

    fn exercise_history_selection(
        service: &HostedRecoveryEnrollmentService,
        vault: &mut Vault,
        device: &DeviceKeys,
        http: &Http,
        check_authorization: bool,
    ) {
        use context_relay_core::sync::{
            CanonicalCheckpoint, CanonicalOperation, OperationBuildRequest, OperationBuilder,
            StateSummaryEntryV1, StateSummaryV1, SyncIdentity,
        };
        use context_relay_protocol::{
            CheckpointV1, DeviceSequence, Ed25519SignatureBytes, HybridLogicalClock,
            ProjectIdentity, RecordMutationV1, RecoveryHistoryCandidatesParams,
            RecoveryHistoryExtent, RecoveryHistoryProgress, RecoveryHistorySelectParams,
            RecoveryRestoreStatus as Status, Sha256Digest,
        };
        let prepared = vault.prepared_recovery_v2(device).unwrap().unwrap();
        let endpoint = vault
            .recovery_membership_admission(device)
            .unwrap()
            .unwrap();
        let root =
            context_relay_core::devices::recovery_crypto::decode_recovery_enrollment_record_v1(
                &prepared.canonical_record,
            )
            .unwrap();
        let author = DeviceKeys::from_seeds_for_test([0x11; 32], [0x22; 32]);
        let author_id = root.genesis_certificate.device_id;
        let project_id = "018f22e2-79b0-7cc8-98c4-dc0c0c073951".parse().unwrap();
        let mutation = RecordMutationV1::UpsertProject(ProjectIdentity {
            project_id,
            name: "Explicitly recovered project".into(),
            github_repository_id: None,
            git_remote_fingerprint: None,
            monorepo_subdirectory: None,
        });
        let mutation = if check_authorization {
            RecordMutationV1::UpsertMemory(context_relay_protocol::MemoryRecord {
                id: project_id.to_string().parse().unwrap(),
                scope: context_relay_protocol::ScopeRef::Project { project_id },
                kind: context_relay_protocol::MemoryKind::Fact,
                title: "Canceled history".into(),
                body_markdown: "History resolver cancellation".into(),
                tags: vec![],
                origin: context_relay_protocol::MemoryOrigin::Explicit,
                provenance: context_relay_protocol::Provenance {
                    origin_device: author_id,
                    harness: None,
                    source: None,
                    created_hlc: HybridLogicalClock::new(1001, 0, author_id),
                },
                revision: "018f22e2-79b0-7cc8-98c4-dc0c0c073952".parse().unwrap(),
                created_hlc: HybridLogicalClock::new(1001, 0, author_id),
                updated_hlc: HybridLogicalClock::new(1001, 0, author_id),
                archived: false,
            })
        } else {
            mutation
        };
        let content = context_relay_core::crypto::ContentKey::from_bytes([0x55; 32]);
        let operation = OperationBuilder::new(SyncIdentity {
            membership_endpoint: Some(prepared.parent.endpoint()),
            account_id: root.account_id,
            workspace_id: root.workspace_id,
            device_id: author_id,
            control_epoch: 1,
            key_epoch: 1,
            device_keys: &author,
            content_key: &content,
        })
        .build(OperationBuildRequest {
            operation_id: "018f22e2-79b0-7cc8-98c4-dc0c0c073952".parse().unwrap(),
            project_id: Some(project_id),
            mutation: &mutation,
            causal_frontier: vec![],
            previous: None,
            blob_refs: vec![],
            created_hlc: HybridLogicalClock::new(1001, 0, author_id),
        })
        .unwrap();
        let mut checkpoint = CheckpointV1 {
            schema_version: 2,
            account_id: root.account_id,
            workspace_id: root.workspace_id,
            previous_checkpoint_hash: Sha256Digest([0; 32]),
            causal_frontier: vec![DeviceSequence {
                device_id: author_id,
                sequence: 1,
            }],
            state_hash: StateSummaryV1 {
                entries: vec![StateSummaryEntryV1 {
                    record_id: mutation.record_id(),
                    record_kind: mutation.record_kind(),
                    head_hashes: vec![operation.canonical_hash],
                    tombstoned: false,
                    conflicted: false,
                }],
            }
            .state_hash()
            .unwrap(),
            key_epoch: 1,
            creator_device: author_id,
            created_hlc: HybridLogicalClock::new(1002, 0, author_id),
            signature: Ed25519SignatureBytes([0; 64]),
        };
        author.sign_checkpoint(&mut checkpoint).unwrap();
        let checkpoint = CanonicalCheckpoint::from_checkpoint(checkpoint).unwrap();
        let operation = CanonicalOperation {
            operation_id: operation.operation.operation_id,
            device_id: author_id,
            device_sequence: 1,
            bytes: operation.canonical_bytes,
        };
        if check_authorization {
            let login = || {
                let instant = std::time::Instant::now();
                let mut pending = PendingLogin::new(
                    &service.project,
                    "127.0.0.1:41783".parse().unwrap(),
                    instant,
                )
                .unwrap();
                let auth = pending.authorization_url();
                let redirect = auth
                    .query_pairs()
                    .find(|(k, _)| k == "redirect_to")
                    .unwrap()
                    .1
                    .into_owned();
                let mut callback = auth.join(&redirect).unwrap();
                callback
                    .query_pairs_mut()
                    .append_pair("code", "synthetic-code");
                service
                    .owner
                    .complete_login(
                        service.owner.begin_login().unwrap(),
                        pending.take_callback(&callback, instant).unwrap(),
                        http.now,
                    )
                    .unwrap();
            };
            let original_identity = *service
                .owner
                .current_session(http.now)
                .unwrap()
                .unwrap()
                .identity();
            let generation = service.owner.cancellation().unwrap();
            let selected = service
                .authorized_history_action(original_identity, &generation, |authorize| {
                    vault
                        .select_recovery_history_authorized(
                            endpoint,
                            &checkpoint.bytes,
                            device,
                            history::budget(),
                            authorize,
                        )
                        .map_err(history::vault_error)
                })
                .unwrap();
            let embeddings =
                |_: context_relay_protocol::OperationId,
                 _: &context_relay_protocol::RecordMutationV1| {
                    Ok(Some(
                        context_relay_core::search::Embedding384::try_from(vec![1.0; 384]).unwrap(),
                    ))
                };
            let proof = vault
                .reconstruct_recovery_history(
                    selected,
                    std::slice::from_ref(&operation.bytes),
                    device,
                    history::budget(),
                    &embeddings,
                )
                .unwrap()
                .unwrap();
            let before = vault.test_plaintext_cells().unwrap();
            let resolved = std::cell::Cell::new(0);
            let cancel_embeddings =
                |_: context_relay_protocol::OperationId,
                 _: &context_relay_protocol::RecordMutationV1| {
                    resolved.set(resolved.get() + 1);
                    generation.cancel();
                    Ok(Some(
                        context_relay_core::search::Embedding384::try_from(vec![1.0; 384]).unwrap(),
                    ))
                };
            let result =
                service.authorized_history_action(original_identity, &generation, |authorize| {
                    vault
                        .install_recovery_history_authorized(
                            &proof,
                            device,
                            history::budget(),
                            &cancel_embeddings,
                            authorize,
                        )
                        .map_err(history::vault_error)
                });
            assert!(resolved.get() > 0);
            assert_eq!(result.unwrap_err().code, ErrorCode::ScopeDenied);
            assert_eq!(vault.test_plaintext_cells().unwrap(), before);
            assert!(vault.trusted_sync_material(device).is_err());
            *vault = Vault::open(&http.path, "expiry-test", http.keys.as_ref()).unwrap();
            assert_eq!(
                vault.test_plaintext_cells().unwrap(),
                before,
                "canceled original generation cannot commit records, heads, installed receipt or activation"
            );
            login();
            let generation = service.owner.cancellation().unwrap();
            let result =
                service.authorized_history_action(original_identity, &generation, |authorize| {
                    assert!(
                        vault
                            .install_recovery_history_authorized(
                                &proof,
                                device,
                                history::budget(),
                                &embeddings,
                                authorize
                            )
                            .map_err(history::vault_error)?
                    );
                    let status = vault
                        .recovery_history_status(device, history::budget())
                        .map_err(history::vault_error)?;
                    assert!(matches!(status, Status::Complete { .. }));
                    generation.cancel();
                    Ok(LocalResult::RecoveryRestoreStatus { status })
                });
            assert_eq!(
                result.unwrap_err().code,
                ErrorCode::ScopeDenied,
                "cancellation during expensive final status construction must suppress active-action success"
            );
            let committed = vault.test_plaintext_cells().unwrap();
            *vault = Vault::open(&http.path, "expiry-test", http.keys.as_ref()).unwrap();
            assert_eq!(vault.test_plaintext_cells().unwrap(), committed);
            assert!(
                matches!(
                    service
                        .execute(
                            vault,
                            device,
                            LocalRequest::RecoveryRestoreOverview(EmptyParams {})
                        )
                        .unwrap(),
                    LocalResult::RecoveryRestoreStatus {
                        status: Status::Complete { .. }
                    }
                ),
                "durable read-only overview survives cancellation after commit"
            );
            login();
            let generation = service.owner.cancellation().unwrap();
            let result: Result<(), ClientError> =
                service.authorized_history_action(original_identity, &generation, |_| {
                    Err(history::vault_error(
                        context_relay_core::vault::VaultError::OperationConflict,
                    ))
                });
            assert_eq!(
                result.unwrap_err().code,
                ErrorCode::Conflict,
                "unrelated integrity/selection conflict stays distinct from Auth denial"
            );
            return;
        }
        http.state.lock().unwrap().history_checkpoints = vec![history_checkpoint_row(&checkpoint)];
        let candidates = || {
            LocalRequest::RecoveryHistoryCandidates(RecoveryHistoryCandidatesParams {
                restore_id: prepared.claim.restore_id,
                accepted_endpoint_sha256: endpoint.state_sha256,
                cursor: None,
            })
        };
        assert!(matches!(
            service
                .execute(
                    vault,
                    device,
                    LocalRequest::RecoveryRestoreResume(EmptyParams {})
                )
                .unwrap(),
            LocalResult::RecoveryRestoreStatus {
                status: Status::RestoringHistory {
                    history: RecoveryHistoryProgress::Unselected {},
                    ..
                }
            }
        ));
        let LocalResult::RecoveryHistoryCandidates { page } =
            service.execute(vault, device, candidates()).unwrap()
        else {
            panic!("candidate page")
        };
        assert_eq!(page.candidates.len(), 1);
        assert_eq!(
            page.candidates[0].extent,
            RecoveryHistoryExtent::Supported { operation_count: 1 }
        );
        assert!(
            vault
                .recovery_history_selection(device, history::budget())
                .unwrap()
                .is_none()
        );
        let next = || {
            LocalRequest::RecoveryHistoryCandidates(RecoveryHistoryCandidatesParams {
                restore_id: prepared.claim.restore_id,
                accepted_endpoint_sha256: endpoint.state_sha256,
                cursor: page.next_cursor.clone(),
            })
        };
        http.state.lock().unwrap().history_repeat_page = true;
        assert!(
            service.execute(vault, device, next()).is_err(),
            "non-advancing authenticated page denied"
        );
        http.state.lock().unwrap().history_repeat_page = false;
        assert!(
            matches!(service.execute(vault,device,next()).unwrap(),LocalResult::RecoveryHistoryCandidates {page} if page.candidates.is_empty() && page.next_cursor.is_none())
        );
        let selected = RecoveryHistorySelectParams {
            restore_id: prepared.claim.restore_id,
            accepted_endpoint_sha256: endpoint.state_sha256,
            checkpoint_sha256: checkpoint.canonical_hash,
        };
        let mut substituted = selected.clone();
        substituted.checkpoint_sha256 = Sha256Digest([9; 32]);
        assert!(
            service
                .execute(
                    vault,
                    device,
                    LocalRequest::RecoveryHistorySelect(substituted)
                )
                .is_err()
        );
        assert!(
            vault
                .recovery_history_selection(device, history::budget())
                .unwrap()
                .is_none()
        );
        let mut stale = selected.clone();
        stale.accepted_endpoint_sha256 = Sha256Digest([8; 32]);
        assert!(
            service
                .execute(vault, device, LocalRequest::RecoveryHistorySelect(stale))
                .is_err()
        );
        assert!(matches!(
            service
                .execute(
                    vault,
                    device,
                    LocalRequest::RecoveryHistorySelect(selected.clone())
                )
                .unwrap(),
            LocalResult::RecoveryRestoreStatus {
                status: Status::RestoringHistory {
                    history: RecoveryHistoryProgress::Incomplete { .. },
                    ..
                }
            }
        ));
        http.state.lock().unwrap().history_offline = true;
        assert!(
            service
                .execute(
                    vault,
                    device,
                    LocalRequest::RecoveryRestoreResume(EmptyParams {})
                )
                .is_err()
        );
        http.state.lock().unwrap().history_offline = false;
        assert!(
            matches!(
                service
                    .execute(
                        vault,
                        device,
                        LocalRequest::RecoveryRestoreResume(EmptyParams {})
                    )
                    .unwrap(),
                LocalResult::RecoveryRestoreStatus {
                    status: Status::RestoringHistory {
                        history: RecoveryHistoryProgress::Incomplete { .. },
                        ..
                    }
                }
            ),
            "missing operations do not become completion or phrase entry"
        );
        assert_eq!(
            vault
                .recovery_history_selection(device, history::budget())
                .unwrap()
                .unwrap()
                .checkpoint_sha256(),
            selected.checkpoint_sha256
        );
        http.state.lock().unwrap().history_operations = vec![history_operation_row(&operation)];
        assert!(matches!(
            service
                .execute(
                    vault,
                    device,
                    LocalRequest::RecoveryRestoreResume(EmptyParams {})
                )
                .unwrap(),
            LocalResult::RecoveryRestoreStatus {
                status: Status::Complete { .. }
            }
        ));
        assert_eq!(
            vault
                .record_heads(root.workspace_id, mutation.record_id())
                .unwrap()
                .len(),
            1
        );
        // A later authenticated cutoff may mention operations beyond the installed history.
        let later = OperationBuilder::new(SyncIdentity {
            membership_endpoint: Some(endpoint),
            account_id: root.account_id,
            workspace_id: root.workspace_id,
            device_id: author_id,
            control_epoch: 1,
            key_epoch: 1,
            device_keys: &author,
            content_key: &content,
        })
        .build(OperationBuildRequest {
            operation_id: "018f22e2-79b0-7cc8-98c4-dc0c0c073953".parse().unwrap(),
            project_id: Some(project_id),
            mutation: &mutation,
            causal_frontier: vec![DeviceSequence {
                device_id: author_id,
                sequence: 1,
            }],
            previous: Some(context_relay_core::sync::OperationChainHead {
                sequence: 1,
                canonical_hash: Sha256Digest(Sha256::digest(&operation.bytes).into()),
            }),
            blob_refs: vec![],
            created_hlc: HybridLogicalClock::new(1003, 0, author_id),
        })
        .unwrap();
        let history = vault
            .accepted_membership_history(history::budget().transfer.history)
            .unwrap()
            .unwrap();
        let (statement, transition, signature) =
            context_relay_core::devices::revocation_crypto::RevocationTransitionV1::build(
                context_relay_core::devices::revocation_crypto::DeviceRevocationStatementV1 {
                    schema_version: 1,
                    revocation_id: "018f22e2-79b0-7cc8-98c4-dc0c0c073954".parse().unwrap(),
                    account_id: root.account_id,
                    workspace_id: root.workspace_id,
                    issuer_device_id: prepared.claim.certificate.device_id,
                    target_device_id: author_id,
                    control_epoch: endpoint.control_epoch,
                    key_epoch: endpoint.key_epoch,
                    cutoff_sequence: 2,
                    cutoff_hash: later.canonical_hash,
                    transition_sha256: Sha256Digest([1; 32]),
                },
                device,
                &history.state(),
            )
            .unwrap();
        let descendant = context_relay_core::devices::membership_crypto::MembershipEndpoint {
            state_sha256: statement.control_state_sha256(signature).unwrap(),
            control_epoch: 2,
            key_epoch: 2,
        };
        vault.accept_membership_extension(endpoint,descendant,&[context_relay_core::devices::membership_crypto::MembershipHistoryEvent::Revocation {statement:&statement.signing_preimage().unwrap(),signature,transition:&transition.canonical_bytes().unwrap()}],history::budget().transfer.history).unwrap();
        assert!(
            matches!(
                vault.recovery_history_status(device, history::budget()),
                Ok(Status::Complete { .. })
            ),
            "an installed historical prefix remains complete while a later accepted cutoff operation has not downloaded"
        );
        assert!(
            vault.trusted_sync_material(device).is_err(),
            "historical completion never activates descendant write authority"
        );
    }
    fn history_bytea(bytes: &[u8]) -> String {
        format!(
            "\\x{}",
            bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
        )
    }
    fn history_operation_row(
        operation: &context_relay_core::sync::CanonicalOperation,
    ) -> serde_json::Value {
        let decoded = context_relay_protocol::decode_sync_operation_v1(&operation.bytes).unwrap();
        serde_json::json!({
            "id": decoded.operation_id,
            "account_id": decoded.account_id,
            "workspace_id": decoded.workspace_id,
            "project_id": decoded.project_id,
            "record_id": decoded.record_id,
            "record_kind": decoded.record_kind,
            "mutation_kind": decoded.mutation_kind,
            "device_id": decoded.device_id,
            "schema_version": decoded.schema_version,
            "device_sequence": decoded.device_sequence,
            "causal_frontier": decoded.causal_frontier,
            "control_epoch": decoded.control_epoch,
            "key_epoch": decoded.key_epoch,
            "previous_device_hash": history_bytea(&decoded.previous_device_hash.0),
            "nonce": history_bytea(&decoded.nonce.0),
            "ciphertext": history_bytea(decoded.ciphertext.as_slice()),
            "ciphertext_hash": history_bytea(&decoded.ciphertext_hash.0),
            "blob_refs": decoded.blob_refs,
            "created_hlc": decoded.created_hlc,
            "signature": history_bytea(&decoded.signature.0),
            "canonical_sha256": history_bytea(&Sha256::digest(&operation.bytes)),
            "received_at": "2026-09-14T00:00:00Z",
        })
    }

    fn history_checkpoint_row(
        checkpoint: &context_relay_core::sync::CanonicalCheckpoint,
    ) -> serde_json::Value {
        let decoded = &checkpoint.checkpoint;
        serde_json::json!({
            "account_id": decoded.account_id,
            "workspace_id": decoded.workspace_id,
            "schema_version": decoded.schema_version,
            "previous_checkpoint_hash": history_bytea(&decoded.previous_checkpoint_hash.0),
            "causal_frontier": decoded.causal_frontier,
            "state_hash": history_bytea(&decoded.state_hash.0),
            "key_epoch": decoded.key_epoch,
            "creator_device_id": decoded.creator_device,
            "created_hlc": decoded.created_hlc,
            "signature": history_bytea(&decoded.signature.0),
            "canonical_sha256": history_bytea(&checkpoint.canonical_hash.0),
            "received_at": "2026-09-14T00:00:00Z",
        })
    }

    #[test]
    fn lost_reserve_and_expired_commit_recover_without_replacing_prepared_record() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.db");
        let keys = Arc::new(Keys::default());
        let mut vault = Vault::open(&path, "expiry-test", keys.as_ref()).unwrap();
        let now =
            context_relay_core::devices::recovery::SystemRecoveryEnrollmentClock.now_ms() / 1000;
        let http = Arc::new(Http {
            state: Mutex::new(Remote {
                lose_reserve: true,
                expire_commit: true,
                ..Remote::default()
            }),
            path,
            keys,
            now,
        });
        let project = "https://example.supabase.co";
        let auth =
            SupabaseAuthClient::with_http_client(project, "public-test", http.clone()).unwrap();
        let owner = Arc::new(HostedSessionOwner::new(Arc::new(auth), Arc::new(Login)));
        let instant = std::time::Instant::now();
        let mut pending =
            PendingLogin::new(project, "127.0.0.1:41783".parse().unwrap(), instant).unwrap();
        let auth = pending.authorization_url();
        let redirect = auth
            .query_pairs()
            .find(|(key, _)| key == "redirect_to")
            .unwrap()
            .1
            .into_owned();
        let mut callback = auth.join(&redirect).unwrap();
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
        let device = Arc::new(DeviceKeys::generate().unwrap());
        let mut service = HostedRecoveryEnrollmentService::new(
            owner,
            project,
            "public-test",
            crate::pairing::PairingIdentity {
                device_id: "018f22e2-79b0-7cc8-98c4-dc0c0c075103".parse().unwrap(),
                device_name: "Test desktop".into(),
                platform: NativePlatform::Windows,
                keys: device.clone(),
            },
        );
        service.http = Some(http.clone());
        assert!(
            service
                .execute(
                    &mut vault,
                    &device,
                    LocalRequest::RecoveryEnrollmentBegin(EmptyParams {})
                )
                .is_err()
        );
        let first = vault
            .hosted_enrollment_intent()
            .unwrap()
            .unwrap()
            .operation_id;
        assert!(
            service
                .execute(
                    &mut vault,
                    &device,
                    LocalRequest::RecoveryEnrollmentBegin(EmptyParams {})
                )
                .is_err()
        );
        assert!(vault.hosted_enrollment_intent().unwrap().is_none());
        let LocalResult::RecoveryEnrollmentPhrase { phrase } = service
            .execute(
                &mut vault,
                &device,
                LocalRequest::RecoveryEnrollmentBegin(EmptyParams {}),
            )
            .unwrap()
        else {
            panic!("expected phrase")
        };
        assert_ne!(
            vault
                .hosted_enrollment_intent()
                .unwrap()
                .unwrap()
                .operation_id,
            first
        );
        let params = RecoveryEnrollmentConfirmParams {
            enrollment_id: phrase.enrollment_id,
            confirmations: phrase
                .confirmation_positions
                .iter()
                .map(|p| RecoveryWordConfirmation {
                    position: *p,
                    word: phrase.recovery_phrase_words.as_words()[usize::from(*p) - 1].clone(),
                })
                .collect(),
        };
        assert!(
            service
                .execute(
                    &mut vault,
                    &device,
                    LocalRequest::RecoveryEnrollmentConfirm(params)
                )
                .is_err()
        );
        assert_eq!(
            vault.recovery_enrollment().unwrap().unwrap().state,
            RecoveryEnrollmentPersistenceState::Prepared
        );
        assert!(
            matches!(service.execute(&mut vault,&device,LocalRequest::RecoveryEnrollmentOverview(EmptyParams{})).unwrap(),LocalResult::RecoveryEnrollmentStatus{status} if status.state==RecoveryEnrollmentState::Complete)
        );
        let remote = http.state.lock().unwrap();
        assert_eq!(remote.reserve_ids[0], remote.reserve_ids[1]);
        assert_ne!(remote.reserve_ids[1], remote.reserve_ids[2]);
        assert_eq!(remote.records.len(), 2);
        assert_eq!(remote.records[0], remote.records[1]);
    }
}
