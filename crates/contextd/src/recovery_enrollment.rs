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
