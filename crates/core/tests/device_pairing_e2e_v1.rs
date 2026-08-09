mod support;

use std::{
    fs,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use context_relay_core::{
    crypto::{CertificateFieldsV1, DeviceCertificateV1, DeviceKeys, RecoveryKeys, RecoveryPhrase},
    devices::{
        crypto::{
            PairingGrantApproval, PairingKeyBundle, build_pairing_approved_payload_v1,
            build_pairing_grant, encode_pairing_approved_payload_v1, inspect_pairing_approval,
            verify_pairing_request,
        },
        memory_transport::InMemoryPairingProvider,
        pairing::{
            PairingApprovalAuthority, PairingClock, PairingCoordinator, PairingCycleError,
            PairingDecisionInput, PairingDecisionStatus, PairingJoinStatus, PairingMaterialSource,
            PairingRequestReview, WorkspacePairingMaterial,
        },
        transport::{
            PairingApprovalTransport, PairingDecisionEnvelope, PairingDecisionReceipt,
            PairingInvite, PairingInviteStatus, PairingJoinTransport, PairingRequestReceipt,
            PairingResult, PairingTransportError, StoredPairingRequest,
        },
    },
    sync::SyncScope,
    vault::{DeviceCertificateState, DeviceDisplayMetadata, Vault},
};
use context_relay_protocol::{
    AccountId, DeviceCertificateId, DeviceId, NativePlatform, PairingRequestNonce,
    RecoveryPhraseWords, Sha256Digest, WorkspaceId, decode_pairing_request_v1,
};
use rusqlite::Connection;

use support::{MemoryKeyStore, TempVault};

const APPROVER_CREDENTIAL: &str = "pairing-e2e-approver";
const JOINER_CREDENTIAL: &str = "pairing-e2e-joiner";
const ACCOUNT_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074001";
const WORKSPACE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074002";
const APPROVER_DEVICE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074003";
const JOINER_DEVICE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074004";
const APPROVER_CERTIFICATE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074005";
const JOINER_CERTIFICATE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074006";
const KEY_CANARY: &[u8] = b"TASK_17_PAIRING_KEY_CANARY_DO_NOT_LEAK";

#[derive(Clone, Default)]
struct TestClock(Arc<AtomicU64>);

impl TestClock {
    fn set(&self, now_ms: u64) {
        self.0.store(now_ms, Ordering::SeqCst);
    }
}

impl PairingClock for TestClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Clone)]
struct TestMaterialSource {
    scope: SyncScope,
    control_epoch: u32,
    key_epoch: u32,
    workspace_root_key: [u8; 32],
    active_epoch_key: [u8; 32],
}

impl TestMaterialSource {
    fn from_material(material: &WorkspacePairingMaterial) -> Self {
        Self {
            scope: material.scope(),
            control_epoch: material.control_epoch(),
            key_epoch: material.key_epoch(),
            workspace_root_key: *material.workspace_root_key(),
            active_epoch_key: *material.active_epoch_key(),
        }
    }
}

impl PairingMaterialSource for TestMaterialSource {
    fn current_material(
        &self,
        _vault: &mut Vault,
        _device_keys: &DeviceKeys,
        scope: SyncScope,
    ) -> Result<WorkspacePairingMaterial, PairingCycleError> {
        if scope != self.scope {
            return Err(PairingCycleError::Conflict);
        }
        WorkspacePairingMaterial::new(
            self.scope,
            self.control_epoch,
            self.key_epoch,
            self.workspace_root_key,
            self.active_epoch_key,
        )
    }
}

#[derive(Clone)]
struct FailSubmitOnce {
    inner: context_relay_core::devices::memory_transport::InMemoryPairingJoinClient,
    fail: Arc<AtomicBool>,
}

impl PairingJoinTransport for FailSubmitOnce {
    fn resolve_code(
        &self,
        code: &context_relay_protocol::PairingCode,
        now_ms: u64,
    ) -> Result<context_relay_protocol::PairingId, PairingTransportError> {
        self.inner.resolve_code(code, now_ms)
    }

    fn submit_request(
        &self,
        pairing_id: context_relay_protocol::PairingId,
        canonical: &[u8],
        now_ms: u64,
    ) -> Result<PairingRequestReceipt, PairingTransportError> {
        if self.fail.swap(false, Ordering::SeqCst) {
            return Err(PairingTransportError::Transient);
        }
        self.inner.submit_request(pairing_id, canonical, now_ms)
    }

    fn result(
        &self,
        pairing_id: context_relay_protocol::PairingId,
        digest: Sha256Digest,
        now_ms: u64,
    ) -> Result<PairingResult, PairingTransportError> {
        self.inner.result(pairing_id, digest, now_ms)
    }
}

#[derive(Clone)]
struct FailDecisionOnce {
    inner: context_relay_core::devices::memory_transport::InMemoryPairingApprovalClient,
    fail: Arc<AtomicBool>,
}

impl PairingApprovalTransport for FailDecisionOnce {
    fn create_invite(&self, now_ms: u64) -> Result<PairingInvite, PairingTransportError> {
        self.inner.create_invite(now_ms)
    }

    fn invite_status(
        &self,
        pairing_id: context_relay_protocol::PairingId,
        now_ms: u64,
    ) -> Result<PairingInviteStatus, PairingTransportError> {
        self.inner.invite_status(pairing_id, now_ms)
    }

    fn request(
        &self,
        pairing_id: context_relay_protocol::PairingId,
        now_ms: u64,
    ) -> Result<Option<StoredPairingRequest>, PairingTransportError> {
        self.inner.request(pairing_id, now_ms)
    }

    fn decide(
        &self,
        envelope: PairingDecisionEnvelope,
        now_ms: u64,
    ) -> Result<PairingDecisionReceipt, PairingTransportError> {
        if self.fail.swap(false, Ordering::SeqCst) {
            return Err(PairingTransportError::Transient);
        }
        self.inner.decide(envelope, now_ms)
    }

    fn cancel(
        &self,
        pairing_id: context_relay_protocol::PairingId,
        now_ms: u64,
    ) -> Result<(), PairingTransportError> {
        self.inner.cancel(pairing_id, now_ms)
    }
}

#[test]
fn two_replicas_pair_through_the_resumable_coordinator() {
    let approver_path = TempVault::new("pairing-e2e-approver");
    let joiner_path = TempVault::new("pairing-e2e-joiner");
    let approver_store = MemoryKeyStore::default();
    let joiner_store = MemoryKeyStore::default();
    let provider = InMemoryPairingProvider::with_test_entropy(
        [0xa5; 32],
        (1_u8..=16).map(|value| [value; 32]).collect(),
    );
    let clock = TestClock::default();
    clock.set(1_000);
    let material = workspace_material();
    let scope = scope();
    let approver_device_id = id(APPROVER_DEVICE_ID);
    let approver_client = provider.existing_device_client(scope, approver_device_id);
    let joiner_client = provider
        .join_session_client("joining-device-session")
        .unwrap();
    let coordinator = PairingCoordinator::new(
        clock.clone(),
        TestMaterialSource::from_material(&material),
        joiner_client.clone(),
        approver_client.clone(),
    );
    let approver_keys = DeviceKeys::generate().unwrap();
    let joiner_keys = DeviceKeys::generate().unwrap();
    let approver_certificate = genesis_certificate(&approver_keys);
    let approver_certificate_id = id(APPROVER_CERTIFICATE_ID);
    let approver_display = DeviceDisplayMetadata {
        device_name: "Existing desktop".to_owned(),
        platform: NativePlatform::Macos,
    };
    let mut approver_vault =
        Vault::open(approver_path.path(), APPROVER_CREDENTIAL, &approver_store).unwrap();
    approver_vault
        .store_device_certificate(
            approver_certificate_id,
            &approver_certificate,
            DeviceCertificateState::Active,
            &approver_display,
            900,
        )
        .unwrap();
    let mut joiner_vault =
        Vault::open(joiner_path.path(), JOINER_CREDENTIAL, &joiner_store).unwrap();

    let invite = coordinator.create_invite().unwrap();
    clock.set(1_001);
    let submission = coordinator
        .join(
            &mut joiner_vault,
            &invite.code,
            id(JOINER_DEVICE_ID),
            "Joining laptop",
            NativePlatform::Macos,
            &joiner_keys,
        )
        .unwrap();
    assert_eq!(submission.pairing_id, invite.pairing_id);

    clock.set(1_002);
    let review = coordinator
        .request_status(invite.pairing_id)
        .unwrap()
        .unwrap();
    assert_eq!(review.device_name, "Joining laptop");
    assert_eq!(review.request_digest, submission.request_digest);
    let authority = PairingApprovalAuthority {
        certificate_id: id(JOINER_CERTIFICATE_ID),
        issuer_certificate_id: approver_certificate_id,
        issuer_keys: &approver_keys,
    };
    let decision = coordinator
        .decide(
            &mut approver_vault,
            invite.pairing_id,
            review.request_digest,
            PairingDecisionInput::Approve(authority),
        )
        .unwrap();
    let PairingDecisionStatus::Approved { safety_number } = decision else {
        panic!("approval must produce a safety number");
    };

    clock.set(1_003);
    let status = coordinator
        .join_status(&mut joiner_vault, submission.pairing_id)
        .unwrap();
    assert_eq!(
        status,
        PairingJoinStatus::AwaitingConfirmation {
            pairing_id: submission.pairing_id,
        }
    );
    let awaiting = joiner_vault
        .awaiting_pairing_confirmation(submission.pairing_id)
        .unwrap()
        .unwrap();
    let transcript_hex = awaiting
        .approval
        .transcript_digest()
        .0
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<String>();
    let status_debug = format!("{status:?}");
    let stored_debug = format!("{awaiting:?}");
    assert!(!status_debug.contains(safety_number.as_str()));
    assert!(!status_debug.contains(&transcript_hex));
    assert!(!stored_debug.contains(safety_number.as_str()));
    assert!(!stored_debug.contains(&transcript_hex));
    assert!(joiner_vault.devices(scope).unwrap().is_empty());
    drop(joiner_vault);

    let mut joiner_vault =
        Vault::open(joiner_path.path(), JOINER_CREDENTIAL, &joiner_store).unwrap();
    clock.set(1_004);
    let completed = coordinator
        .confirm_join(
            &mut joiner_vault,
            submission.pairing_id,
            safety_number.as_str(),
            &joiner_keys,
        )
        .unwrap();
    assert_eq!(completed.scope(), scope);
    assert_eq!(completed.control_epoch(), 7);
    assert_eq!(completed.key_epoch(), 11);
    assert_eq!(joiner_vault.devices(scope).unwrap().len(), 2);
    drop(joiner_vault);
    drop(approver_vault);

    let approver_vault =
        Vault::open(approver_path.path(), APPROVER_CREDENTIAL, &approver_store).unwrap();
    let joiner_vault = Vault::open(joiner_path.path(), JOINER_CREDENTIAL, &joiner_store).unwrap();
    assert_eq!(approver_vault.devices(scope).unwrap().len(), 2);
    assert_eq!(joiner_vault.devices(scope).unwrap().len(), 2);
    let reopened = coordinator
        .completed_material(&joiner_vault, submission.pairing_id, &joiner_keys)
        .unwrap()
        .unwrap();
    assert_eq!(reopened.workspace_root_key(), material.workspace_root_key());
    assert_eq!(reopened.active_epoch_key(), material.active_epoch_key());

    let mut recovered_canary = Vec::from(reopened.workspace_root_key());
    recovered_canary.extend_from_slice(&reopened.active_epoch_key()[..KEY_CANARY.len() - 32]);
    assert_eq!(recovered_canary, KEY_CANARY);
    assert_canary_absent(approver_path.path());
    assert_canary_absent(joiner_path.path());
    assert!(!contains(&provider.test_capture_bytes(), KEY_CANARY));
    for vault in [&approver_vault, &joiner_vault] {
        assert!(vault.test_plaintext_cells().unwrap().iter().all(|cell| {
            !cell
                .bytes
                .windows(KEY_CANARY.len())
                .any(|window| window == KEY_CANARY)
        }));
    }
}

#[test]
fn locally_persisted_join_request_resumes_after_transient_submission_failure() {
    let joiner_path = TempVault::new("pairing-e2e-submit-resume");
    let joiner_store = MemoryKeyStore::default();
    let provider = InMemoryPairingProvider::with_test_entropy([0xb1; 32], vec![[0x21; 32]]);
    let owner = provider.existing_device_client(scope(), id(APPROVER_DEVICE_ID));
    let inner = provider.join_session_client("submit-resume").unwrap();
    let fail = Arc::new(AtomicBool::new(true));
    let join = FailSubmitOnce {
        inner,
        fail: Arc::clone(&fail),
    };
    let clock = TestClock::default();
    clock.set(2_000);
    let coordinator = PairingCoordinator::new(
        clock.clone(),
        TestMaterialSource::from_material(&workspace_material()),
        join.clone(),
        owner.clone(),
    );
    let invite = coordinator.create_invite().unwrap();
    let joiner_keys = DeviceKeys::generate().unwrap();
    clock.set(2_001);
    let mut vault = Vault::open(joiner_path.path(), JOINER_CREDENTIAL, &joiner_store).unwrap();
    assert_eq!(
        coordinator
            .join(
                &mut vault,
                &invite.code,
                id(JOINER_DEVICE_ID),
                "Joining laptop",
                NativePlatform::Macos,
                &joiner_keys,
            )
            .unwrap_err(),
        context_relay_core::devices::pairing::PairingCycleError::Transient
    );
    let stored = vault
        .stored_pairing_join(invite.pairing_id)
        .unwrap()
        .unwrap();
    let stored_digest = stored.request_sha256;
    assert!(!stored.completed);
    drop(vault);

    clock.set(2_002);
    let mut reopened = Vault::open(joiner_path.path(), JOINER_CREDENTIAL, &joiner_store).unwrap();
    let resumed = coordinator
        .join(
            &mut reopened,
            &invite.code,
            id(JOINER_DEVICE_ID),
            "Joining laptop",
            NativePlatform::Macos,
            &joiner_keys,
        )
        .unwrap();
    assert_eq!(resumed.request_digest, stored_digest);
    assert_eq!(
        owner
            .request(invite.pairing_id, clock.now_ms())
            .unwrap()
            .unwrap()
            .request_digest,
        stored_digest
    );
    assert!(reopened.test_plaintext_cells().unwrap().iter().all(|cell| {
        !cell
            .bytes
            .windows(invite.code.as_str().len())
            .any(|window| window == invite.code.as_str().as_bytes())
    }));
}

#[test]
fn prepared_approval_resumes_after_transient_provider_failure() {
    let scenario = coordinator_scenario(3_000, 0x31);
    let owner = scenario
        .provider
        .existing_device_client(scope(), id(APPROVER_DEVICE_ID));
    let failing = FailDecisionOnce {
        inner: owner.clone(),
        fail: Arc::new(AtomicBool::new(true)),
    };
    let failing_coordinator = PairingCoordinator::new(
        scenario.clock.clone(),
        TestMaterialSource::from_material(&scenario.material),
        scenario
            .provider
            .join_session_client("unused-prepared-resume")
            .unwrap(),
        failing,
    );
    let mut vault = Vault::open(
        scenario.approver_path.path(),
        APPROVER_CREDENTIAL,
        &scenario.approver_store,
    )
    .unwrap();
    let authority = scenario.authority();
    assert_eq!(
        failing_coordinator
            .decide(
                &mut vault,
                scenario.invite.pairing_id,
                scenario.review.request_digest,
                PairingDecisionInput::Approve(authority),
            )
            .unwrap_err(),
        context_relay_core::devices::pairing::PairingCycleError::Transient
    );
    assert_eq!(vault.pending_pairing_approvals().unwrap().len(), 1);
    assert_eq!(
        scenario
            .coordinator
            .resume_prepared_decisions(&mut vault)
            .unwrap(),
        1
    );
    assert!(
        vault
            .accepted_pairing_approval(scenario.invite.pairing_id)
            .unwrap()
            .is_some()
    );
}

#[test]
fn provider_acceptance_followed_by_local_failure_resumes_exactly_after_reopen() {
    let scenario = coordinator_scenario(4_000, 0x41);
    let key = scenario.approver_store.key(APPROVER_CREDENTIAL);
    let raw = open_keyed(scenario.approver_path.path(), &key);
    raw.execute_batch(
        "CREATE TRIGGER fail_local_approval_finish
         BEFORE UPDATE OF state ON pairing_approval_transcripts
         WHEN NEW.state = 'accepted'
         BEGIN
           SELECT RAISE(ABORT, 'injected local approval failure');
         END;",
    )
    .unwrap();
    drop(raw);

    let mut vault = Vault::open(
        scenario.approver_path.path(),
        APPROVER_CREDENTIAL,
        &scenario.approver_store,
    )
    .unwrap();
    assert_eq!(
        scenario
            .coordinator
            .decide(
                &mut vault,
                scenario.invite.pairing_id,
                scenario.review.request_digest,
                PairingDecisionInput::Approve(scenario.authority()),
            )
            .unwrap_err(),
        context_relay_core::devices::pairing::PairingCycleError::Transient
    );
    assert_eq!(vault.pending_pairing_approvals().unwrap().len(), 1);
    drop(vault);

    let raw = open_keyed(scenario.approver_path.path(), &key);
    raw.execute_batch("DROP TRIGGER fail_local_approval_finish;")
        .unwrap();
    drop(raw);
    let mut reopened = Vault::open(
        scenario.approver_path.path(),
        APPROVER_CREDENTIAL,
        &scenario.approver_store,
    )
    .unwrap();
    assert_eq!(
        scenario
            .coordinator
            .resume_prepared_decisions(&mut reopened)
            .unwrap(),
        1
    );
    let accepted = reopened
        .accepted_pairing_approval(scenario.invite.pairing_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        accepted.approval.approved_payload().grant.request_digest,
        scenario.review.request_digest
    );
}

#[test]
fn wrong_safety_number_and_confirmation_before_display_leave_trust_unchanged() {
    let scenario = coordinator_scenario(5_000, 0x51);
    let mut joiner_vault = Vault::open(
        scenario.joiner_path.path(),
        JOINER_CREDENTIAL,
        &scenario.joiner_store,
    )
    .unwrap();

    assert_eq!(
        scenario
            .coordinator
            .confirm_join(
                &mut joiner_vault,
                scenario.invite.pairing_id,
                "0000-0000-0000-0000-0000",
                &scenario.joiner_keys,
            )
            .unwrap_err(),
        PairingCycleError::Invalid
    );
    assert!(joiner_vault.devices(scope()).unwrap().is_empty());

    let mut approver_vault = Vault::open(
        scenario.approver_path.path(),
        APPROVER_CREDENTIAL,
        &scenario.approver_store,
    )
    .unwrap();
    let decision = scenario
        .coordinator
        .decide(
            &mut approver_vault,
            scenario.invite.pairing_id,
            scenario.review.request_digest,
            PairingDecisionInput::Approve(scenario.authority()),
        )
        .unwrap();
    let PairingDecisionStatus::Approved { safety_number, .. } = decision else {
        panic!("approval must produce a safety number");
    };
    scenario.clock.set(5_003);
    assert!(matches!(
        scenario
            .coordinator
            .join_status(&mut joiner_vault, scenario.invite.pairing_id)
            .unwrap(),
        PairingJoinStatus::AwaitingConfirmation { .. }
    ));
    scenario.clock.set(5_004);
    assert!(matches!(
        scenario
            .coordinator
            .join_status(&mut joiner_vault, scenario.invite.pairing_id)
            .unwrap(),
        PairingJoinStatus::AwaitingConfirmation { .. }
    ));
    assert_eq!(
        scenario
            .coordinator
            .confirm_join(
                &mut joiner_vault,
                scenario.invite.pairing_id,
                "FFFF-FFFF-FFFF-FFFF-FFFF",
                &scenario.joiner_keys,
            )
            .unwrap_err(),
        PairingCycleError::Invalid
    );
    assert!(joiner_vault.devices(scope()).unwrap().is_empty());
    assert!(
        joiner_vault
            .awaiting_pairing_confirmation(scenario.invite.pairing_id)
            .unwrap()
            .is_some()
    );
    scenario
        .coordinator
        .confirm_join(
            &mut joiner_vault,
            scenario.invite.pairing_id,
            safety_number.as_str(),
            &scenario.joiner_keys,
        )
        .unwrap();
    assert_eq!(joiner_vault.devices(scope()).unwrap().len(), 2);
    scenario.clock.set(5_005);
    assert_eq!(
        scenario
            .coordinator
            .confirm_join(
                &mut joiner_vault,
                scenario.invite.pairing_id,
                "FFFF-FFFF-FFFF-FFFF-FFFF",
                &scenario.joiner_keys,
            )
            .unwrap_err(),
        PairingCycleError::Invalid
    );
    assert_eq!(
        scenario
            .coordinator
            .confirm_join(
                &mut joiner_vault,
                scenario.invite.pairing_id,
                safety_number.as_str(),
                &scenario.joiner_keys,
            )
            .unwrap()
            .scope(),
        scope()
    );
}

#[test]
fn prepared_approval_cannot_be_rejected_after_the_local_decision_is_bound() {
    let scenario = coordinator_scenario(5_500, 0x56);
    let owner = scenario
        .provider
        .existing_device_client(scope(), id(APPROVER_DEVICE_ID));
    let failing = FailDecisionOnce {
        inner: owner.clone(),
        fail: Arc::new(AtomicBool::new(true)),
    };
    let failing_coordinator = PairingCoordinator::new(
        scenario.clock.clone(),
        TestMaterialSource::from_material(&scenario.material),
        scenario
            .provider
            .join_session_client("unused-prepared-conflict")
            .unwrap(),
        failing,
    );
    let mut vault = Vault::open(
        scenario.approver_path.path(),
        APPROVER_CREDENTIAL,
        &scenario.approver_store,
    )
    .unwrap();
    assert_eq!(
        failing_coordinator
            .decide(
                &mut vault,
                scenario.invite.pairing_id,
                scenario.review.request_digest,
                PairingDecisionInput::Approve(scenario.authority()),
            )
            .unwrap_err(),
        PairingCycleError::Transient
    );
    assert_eq!(
        scenario
            .coordinator
            .decide(
                &mut vault,
                scenario.invite.pairing_id,
                scenario.review.request_digest,
                PairingDecisionInput::Reject,
            )
            .unwrap_err(),
        PairingCycleError::Conflict
    );
    let joiner = scenario
        .provider
        .join_session_client("scenario-86")
        .unwrap();
    assert_eq!(
        joiner
            .result(
                scenario.invite.pairing_id,
                scenario.review.request_digest,
                scenario.clock.now_ms(),
            )
            .unwrap(),
        PairingResult::Pending
    );
    assert_eq!(
        scenario
            .coordinator
            .resume_prepared_decisions(&mut vault)
            .unwrap(),
        1
    );
}

#[test]
fn accepted_decision_retry_reuses_the_exact_durable_approval() {
    let scenario = coordinator_scenario(6_000, 0x61);
    let mut vault = Vault::open(
        scenario.approver_path.path(),
        APPROVER_CREDENTIAL,
        &scenario.approver_store,
    )
    .unwrap();
    let first = scenario
        .coordinator
        .decide(
            &mut vault,
            scenario.invite.pairing_id,
            scenario.review.request_digest,
            PairingDecisionInput::Approve(scenario.authority()),
        )
        .unwrap();
    scenario.clock.set(6_003);
    let retry = scenario
        .coordinator
        .decide(
            &mut vault,
            scenario.invite.pairing_id,
            scenario.review.request_digest,
            PairingDecisionInput::Approve(scenario.authority()),
        )
        .unwrap();
    assert_eq!(retry, first);
    let recovered = scenario
        .coordinator
        .accepted_decision_status(&vault, scenario.invite.pairing_id)
        .unwrap()
        .unwrap();
    assert_eq!(recovered.request_digest, scenario.review.request_digest);
    assert!(vault.pending_pairing_approvals().unwrap().is_empty());
}

#[test]
fn cancel_and_reject_are_terminal_without_installing_joiner_trust() {
    let provider =
        InMemoryPairingProvider::with_test_entropy([0x71; 32], vec![[0x71; 32], [0x72; 32]]);
    let clock = TestClock::default();
    clock.set(7_000);
    let owner = provider.existing_device_client(scope(), id(APPROVER_DEVICE_ID));
    let coordinator = PairingCoordinator::new(
        clock.clone(),
        TestMaterialSource::from_material(&workspace_material()),
        provider.join_session_client("cancel-coordinator").unwrap(),
        owner.clone(),
    );
    let canceled = coordinator.create_invite().unwrap();
    coordinator.cancel(canceled.pairing_id).unwrap();
    assert_eq!(
        provider
            .join_session_client("canceled")
            .unwrap()
            .resolve_code(&canceled.code, 7_001)
            .unwrap_err(),
        PairingTransportError::Canceled
    );

    let scenario = coordinator_scenario(7_100, 0x73);
    let mut approver_vault = Vault::open(
        scenario.approver_path.path(),
        APPROVER_CREDENTIAL,
        &scenario.approver_store,
    )
    .unwrap();
    assert_eq!(
        scenario
            .coordinator
            .decide(
                &mut approver_vault,
                scenario.invite.pairing_id,
                scenario.review.request_digest,
                PairingDecisionInput::Reject,
            )
            .unwrap(),
        PairingDecisionStatus::Rejected
    );
    let mut joiner_vault = Vault::open(
        scenario.joiner_path.path(),
        JOINER_CREDENTIAL,
        &scenario.joiner_store,
    )
    .unwrap();
    assert_eq!(
        scenario
            .coordinator
            .join_status(&mut joiner_vault, scenario.invite.pairing_id)
            .unwrap(),
        PairingJoinStatus::Rejected {
            pairing_id: scenario.invite.pairing_id,
        }
    );
    assert!(joiner_vault.devices(scope()).unwrap().is_empty());
}

#[test]
fn self_consistent_provider_issuer_substitution_cannot_cross_safety_confirmation() {
    let scenario = coordinator_scenario(8_000, 0x81);
    let owner = scenario
        .provider
        .existing_device_client(scope(), id(APPROVER_DEVICE_ID));
    let stored = owner
        .request(scenario.invite.pairing_id, 8_002)
        .unwrap()
        .unwrap();
    let request = decode_pairing_request_v1(&stored.canonical_bytes).unwrap();
    let signed_request = verify_pairing_request(&request).unwrap();

    let attacker_keys = DeviceKeys::generate().unwrap();
    let attacker_certificate = DeviceCertificateV1::issue_genesis(
        CertificateFieldsV1 {
            account_id: id(ACCOUNT_ID),
            workspace_id: id(WORKSPACE_ID),
            control_epoch: 7,
            request_nonce: PairingRequestNonce([0x91; 32]),
            device_id: id(APPROVER_DEVICE_ID),
            signing_public_key: attacker_keys.signing_public_key(),
            wrapping_public_key: attacker_keys.wrapping_public_key(),
        },
        &RecoveryKeys::derive(&alternate_recovery_phrase()).unwrap(),
    )
    .unwrap();
    let attacker_bundle = PairingKeyBundle::new(scope(), 7, 11, [0x92; 32], [0x93; 32]).unwrap();
    let attacker_grant = build_pairing_grant(
        &signed_request,
        &PairingGrantApproval {
            request_digest: signed_request.digest(),
            certificate_id: id(JOINER_CERTIFICATE_ID),
            scope: scope(),
            control_epoch: 7,
            issuer_certificate: attacker_certificate.clone(),
        },
        &attacker_keys,
        &attacker_bundle,
    )
    .unwrap();
    let attacker_payload = build_pairing_approved_payload_v1(
        &signed_request,
        attacker_grant,
        id(APPROVER_CERTIFICATE_ID),
        attacker_certificate,
        "Existing desktop",
        NativePlatform::Macos,
    )
    .unwrap();
    let attacker_canonical = encode_pairing_approved_payload_v1(&attacker_payload).unwrap();
    owner
        .decide(
            PairingDecisionEnvelope::approve(
                scenario.invite.pairing_id,
                signed_request.digest(),
                attacker_canonical,
            ),
            8_003,
        )
        .unwrap();

    let legitimate_grant = build_pairing_grant(
        &signed_request,
        &PairingGrantApproval {
            request_digest: signed_request.digest(),
            certificate_id: id(JOINER_CERTIFICATE_ID),
            scope: scope(),
            control_epoch: 7,
            issuer_certificate: scenario.approver_certificate.clone(),
        },
        &scenario.approver_keys,
        &PairingKeyBundle::new(
            scope(),
            7,
            11,
            *scenario.material.workspace_root_key(),
            *scenario.material.active_epoch_key(),
        )
        .unwrap(),
    )
    .unwrap();
    let legitimate_payload = build_pairing_approved_payload_v1(
        &signed_request,
        legitimate_grant,
        scenario.approver_certificate_id,
        scenario.approver_certificate.clone(),
        scenario.approver_display.device_name.clone(),
        scenario.approver_display.platform,
    )
    .unwrap();
    let legitimate_canonical = encode_pairing_approved_payload_v1(&legitimate_payload).unwrap();
    let legitimate = inspect_pairing_approval(&legitimate_canonical, &signed_request).unwrap();

    let mut joiner_vault = Vault::open(
        scenario.joiner_path.path(),
        JOINER_CREDENTIAL,
        &scenario.joiner_store,
    )
    .unwrap();
    assert!(matches!(
        scenario
            .coordinator
            .join_status(&mut joiner_vault, scenario.invite.pairing_id)
            .unwrap(),
        PairingJoinStatus::AwaitingConfirmation { .. }
    ));
    assert_eq!(
        scenario
            .coordinator
            .confirm_join(
                &mut joiner_vault,
                scenario.invite.pairing_id,
                legitimate.safety_number().as_str(),
                &scenario.joiner_keys,
            )
            .unwrap_err(),
        PairingCycleError::Invalid
    );
    assert!(joiner_vault.devices(scope()).unwrap().is_empty());
}

struct CoordinatorScenario {
    approver_path: TempVault,
    joiner_path: TempVault,
    approver_store: MemoryKeyStore,
    joiner_store: MemoryKeyStore,
    provider: InMemoryPairingProvider,
    clock: TestClock,
    coordinator: PairingCoordinator<
        TestClock,
        TestMaterialSource,
        context_relay_core::devices::memory_transport::InMemoryPairingJoinClient,
        context_relay_core::devices::memory_transport::InMemoryPairingApprovalClient,
    >,
    approver_keys: DeviceKeys,
    joiner_keys: DeviceKeys,
    approver_certificate: DeviceCertificateV1,
    approver_certificate_id: DeviceCertificateId,
    approver_display: DeviceDisplayMetadata,
    material: WorkspacePairingMaterial,
    invite: PairingInvite,
    review: PairingRequestReview,
}

impl CoordinatorScenario {
    fn authority(&self) -> PairingApprovalAuthority<'_> {
        PairingApprovalAuthority {
            certificate_id: id(JOINER_CERTIFICATE_ID),
            issuer_certificate_id: self.approver_certificate_id,
            issuer_keys: &self.approver_keys,
        }
    }
}

fn coordinator_scenario(now_ms: u64, entropy: u8) -> CoordinatorScenario {
    let approver_path = TempVault::new(&format!("pairing-e2e-scenario-approver-{entropy}"));
    let joiner_path = TempVault::new(&format!("pairing-e2e-scenario-joiner-{entropy}"));
    let approver_store = MemoryKeyStore::default();
    let joiner_store = MemoryKeyStore::default();
    let provider = InMemoryPairingProvider::with_test_entropy([entropy; 32], vec![[entropy; 32]]);
    let clock = TestClock::default();
    clock.set(now_ms);
    let material = workspace_material();
    let approver_keys = DeviceKeys::generate().unwrap();
    let joiner_keys = DeviceKeys::generate().unwrap();
    let approver_certificate = genesis_certificate(&approver_keys);
    let approver_certificate_id = id(APPROVER_CERTIFICATE_ID);
    let approver_display = DeviceDisplayMetadata {
        device_name: "Existing desktop".to_owned(),
        platform: NativePlatform::Macos,
    };
    let owner = provider.existing_device_client(scope(), id(APPROVER_DEVICE_ID));
    let joiner = provider
        .join_session_client(&format!("scenario-{entropy}"))
        .unwrap();
    let coordinator = PairingCoordinator::new(
        clock.clone(),
        TestMaterialSource::from_material(&material),
        joiner.clone(),
        owner.clone(),
    );
    let mut approver_vault =
        Vault::open(approver_path.path(), APPROVER_CREDENTIAL, &approver_store).unwrap();
    approver_vault
        .store_device_certificate(
            approver_certificate_id,
            &approver_certificate,
            DeviceCertificateState::Active,
            &approver_display,
            now_ms.saturating_sub(1),
        )
        .unwrap();
    let invite = coordinator.create_invite().unwrap();
    clock.set(now_ms + 1);
    let mut joiner_vault =
        Vault::open(joiner_path.path(), JOINER_CREDENTIAL, &joiner_store).unwrap();
    coordinator
        .join(
            &mut joiner_vault,
            &invite.code,
            id(JOINER_DEVICE_ID),
            "Joining laptop",
            NativePlatform::Macos,
            &joiner_keys,
        )
        .unwrap();
    clock.set(now_ms + 2);
    let review = coordinator
        .request_status(invite.pairing_id)
        .unwrap()
        .unwrap();
    drop(joiner_vault);
    drop(approver_vault);
    CoordinatorScenario {
        approver_path,
        joiner_path,
        approver_store,
        joiner_store,
        provider,
        clock,
        coordinator,
        approver_keys,
        joiner_keys,
        approver_certificate,
        approver_certificate_id,
        approver_display,
        material,
        invite,
        review,
    }
}

fn scope() -> SyncScope {
    SyncScope {
        account_id: id(ACCOUNT_ID),
        workspace_id: id(WORKSPACE_ID),
    }
}

fn genesis_certificate(keys: &DeviceKeys) -> DeviceCertificateV1 {
    DeviceCertificateV1::issue_genesis(
        CertificateFieldsV1 {
            account_id: id(ACCOUNT_ID),
            workspace_id: id(WORKSPACE_ID),
            control_epoch: 7,
            request_nonce: PairingRequestNonce([0x41; 32]),
            device_id: id(APPROVER_DEVICE_ID),
            signing_public_key: keys.signing_public_key(),
            wrapping_public_key: keys.wrapping_public_key(),
        },
        &RecoveryKeys::derive(&fixed_recovery_phrase()).unwrap(),
    )
    .unwrap()
}

fn fixed_recovery_phrase() -> RecoveryPhrase {
    let mut words = vec!["abandon".to_owned(); 23];
    words.push("art".to_owned());
    RecoveryPhrase::from_words(RecoveryPhraseWords::new(words).unwrap()).unwrap()
}

fn alternate_recovery_phrase() -> RecoveryPhrase {
    let mut words = vec!["zoo".to_owned(); 23];
    words.push("vote".to_owned());
    RecoveryPhrase::from_words(RecoveryPhraseWords::new(words).unwrap()).unwrap()
}

fn workspace_material() -> WorkspacePairingMaterial {
    let mut workspace_root_key = [0x71; 32];
    workspace_root_key.copy_from_slice(&KEY_CANARY[..32]);
    let mut active_epoch_key = [0x83; 32];
    active_epoch_key[..KEY_CANARY.len() - 32].copy_from_slice(&KEY_CANARY[32..]);
    WorkspacePairingMaterial::new(scope(), 7, 11, workspace_root_key, active_epoch_key).unwrap()
}

fn assert_canary_absent(path: &std::path::Path) {
    for suffix in ["", "-wal", "-shm"] {
        let candidate = format!("{}{suffix}", path.display());
        let Ok(bytes) = fs::read(candidate) else {
            continue;
        };
        assert!(!contains(&bytes, KEY_CANARY));
    }
}

fn open_keyed(path: &std::path::Path, key: &[u8; 32]) -> Connection {
    let connection = Connection::open(path).unwrap();
    // SAFETY: this is the first SQLite operation and the key remains live for the call.
    let result = unsafe {
        rusqlite::ffi::sqlite3_key(
            connection.handle(),
            key.as_ptr().cast(),
            key.len().try_into().unwrap(),
        )
    };
    assert_eq!(result, rusqlite::ffi::SQLITE_OK);
    connection
        .query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
        .unwrap();
    connection
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn id<T: FromStr>(value: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    value.parse().unwrap()
}

#[allow(dead_code)]
fn _type_check_ids(_: AccountId, _: WorkspaceId, _: DeviceId, _: DeviceCertificateId) {}
