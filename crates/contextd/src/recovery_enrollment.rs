#![cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "the hosted recovery adapter is not configured in this build"
    )
)]

use std::sync::Mutex;

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
        if matches!(request, LocalRequest::RecoveryRestoreCancel(_)) {
            if stored.is_some() {
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
        if !begin && stored.is_none() {
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
            && stored.is_none()
            && let Some(saved) = &intent
            && *saved != current
        {
            vault
                .discard_unprepared_hosted_restore_intent(saved)
                .map_err(|_| transient_error())?;
            intent = None;
        }
        if intent.is_none() {
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
        let client = self.client(identity, generation)?;
        let snapshot = client.snapshot(now).map_err(hosted_transport_error)?
            .ok_or_else(|| restore_error(context_relay_core::devices::recovery_restore::RecoveryRestoreCycleError::Unavailable))?;
        if stored.as_ref().is_some_and(|s| {
            s.canonical_record != snapshot.canonical_record
                || s.canonical_record_sha256 != snapshot.canonical_record_sha256
        }) {
            return Err(restore_error(
                context_relay_core::devices::recovery_restore::RecoveryRestoreCycleError::Conflict,
            ));
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
            LocalRequest::RecoveryRestoreBegin(params) if stored.is_none() => {
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
            .hosted_restore_intent()
            .map_err(|_| transient_error())?;
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
        T::Conflict => RecoveryEnrollmentCycleError::Conflict,
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
            let body: Value = serde_json::from_slice(request.body()).unwrap();
            let vault = Vault::open(&self.path, "expiry-test", self.keys.as_ref()).unwrap();
            if matches!(
                body["action"].as_str(),
                Some("snapshot" | "restore" | "restore_status")
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
                let stored = vault.recovery_restore().unwrap().unwrap();
                assert_eq!(
                    stored.state,
                    context_relay_core::vault::RecoveryRestorePersistenceState::Prepared
                );
                let exact: String = stored
                    .canonical_claim
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                assert_eq!(body["claim"], exact);
                assert_eq!(body["proof"].as_str().unwrap().len(), 128);
                state.records.push(body["claim"].clone());
                state.receipt = json!({"restoreId":stored.claim.restore_id,"enrollmentId":root.enrollment_id,"recoveryRootId":root.recovery_root_id,
                    "accountId":root.account_id,"workspaceId":root.workspace_id,"certificateId":stored.claim.certificate_id,
                    "canonicalRecordSha256":stored.canonical_record_sha256,"canonicalClaimSha256":stored.canonical_claim_sha256,
                    "acceptedGeneration":(stored.claim.expected_recovery_generation+1).to_string(),"acceptedAtMs":(self.now*1000).to_string()});
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
        let claim = vault.recovery_restore().unwrap().unwrap().canonical_claim;
        assert!(
            service
                .execute(
                    &mut vault,
                    &device,
                    LocalRequest::RecoveryRestoreCancel(EmptyParams {})
                )
                .is_err()
        );
        drop(service);
        drop(vault);
        let mut vault = Vault::open(&path, "expiry-test", keys.as_ref()).unwrap();
        let service = make_service();
        service.resume_prepared(&mut vault, &device).unwrap();
        assert!(matches!(
            service
                .execute(
                    &mut vault,
                    &device,
                    LocalRequest::RecoveryRestoreResume(EmptyParams {})
                )
                .unwrap(),
            LocalResult::RecoveryRestoreStatus {
                status: Status::Complete { .. }
            }
        ));
        assert_eq!(
            vault.recovery_restore().unwrap().unwrap().canonical_claim,
            claim
        );
        assert_eq!(http.state.lock().unwrap().records.len(), 2);
        owner.begin_login().unwrap();
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
