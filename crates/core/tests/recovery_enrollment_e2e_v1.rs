mod support;

use std::{
    fs,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use bip39::{Language, Mnemonic};
use context_relay_core::{
    crypto::DeviceKeys,
    devices::{
        memory_recovery_transport::{
            InMemoryRecoveryEnrollmentProvider, InMemoryRecoveryEnrollmentTransport,
        },
        memory_transport::InMemoryPairingProvider,
        pairing::{
            PairingApprovalAuthority, PairingClock, PairingCoordinator, PairingDecisionInput,
            PairingDecisionStatus, PairingJoinStatus, VaultPairingMaterialSource,
        },
        recovery::{
            RecoveryEnrollmentBeginOutcome, RecoveryEnrollmentClock,
            RecoveryEnrollmentConfirmOutcome, RecoveryEnrollmentCoordinator,
            RecoveryEnrollmentCycleError, RecoveryEnrollmentEntropy,
        },
        recovery_transport::{RecoveryEnrollmentReceipt, RecoveryEnrollmentTransport},
    },
    sync::SyncScope,
    vault::{RecoveryEnrollmentPersistenceState, Vault},
};
use context_relay_protocol::{
    AccountId, DeviceCertificateId, DeviceId, NativePlatform, RecoveryEnrollmentConfirmParams,
    RecoveryEnrollmentPhrase, RecoveryEnrollmentState, RecoveryRootId, RecoveryWordConfirmation,
    Sha256Digest, WorkspaceId,
};
use hkdf::Hkdf;
use rusqlite::Connection;
use sha2::Sha256;

use support::{MemoryKeyStore, TempVault};

const CREDENTIAL: &str = "recovery-enrollment-e2e-v1";
const ACCOUNT_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074101";
const WORKSPACE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074102";
const DEVICE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074103";
const JOINER_DEVICE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074104";
const JOINER_CERTIFICATE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c074105";

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

impl PairingClock for FixedClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

struct XorShiftEntropy(Mutex<u64>);

impl XorShiftEntropy {
    const fn new(seed: u64) -> Self {
        Self(Mutex::new(seed))
    }
}

impl RecoveryEnrollmentEntropy for XorShiftEntropy {
    fn fill_bytes(&self, output: &mut [u8]) -> Result<(), RecoveryEnrollmentCycleError> {
        let mut state = self.0.lock().unwrap();
        for byte in output {
            let mut value = *state;
            value ^= value << 13;
            value ^= value >> 7;
            value ^= value << 17;
            *state = value;
            *byte = value as u8;
        }
        Ok(())
    }
}

fn scope() -> SyncScope {
    SyncScope {
        account_id: ACCOUNT_ID.parse::<AccountId>().unwrap(),
        workspace_id: WORKSPACE_ID.parse::<WorkspaceId>().unwrap(),
    }
}

fn confirmations(
    phrase: &context_relay_protocol::RecoveryEnrollmentPhrase,
) -> RecoveryEnrollmentConfirmParams {
    RecoveryEnrollmentConfirmParams {
        enrollment_id: phrase.enrollment_id,
        confirmations: phrase
            .confirmation_positions
            .iter()
            .map(|position| RecoveryWordConfirmation {
                position: *position,
                word: phrase.recovery_phrase_words.as_words()[usize::from(*position) - 1].clone(),
            })
            .collect(),
    }
}

type TestRecoveryCoordinator =
    RecoveryEnrollmentCoordinator<FixedClock, XorShiftEntropy, InMemoryRecoveryEnrollmentTransport>;

struct PendingHarness {
    _path: TempVault,
    _key_store: MemoryKeyStore,
    vault: Vault,
    provider: InMemoryRecoveryEnrollmentProvider,
    clock: FixedClock,
    device_keys: DeviceKeys,
    coordinator: TestRecoveryCoordinator,
    phrase: RecoveryEnrollmentPhrase,
}

fn pending_harness(name: &str, seed: u64) -> PendingHarness {
    let path = TempVault::new(name);
    let key_store = MemoryKeyStore::default();
    let vault = Vault::open(path.path(), CREDENTIAL, &key_store).unwrap();
    let provider = InMemoryRecoveryEnrollmentProvider::new();
    let clock = FixedClock::default();
    clock.set(40_000);
    let device_keys = DeviceKeys::from_seeds_for_test([seed as u8; 32], [seed as u8 + 1; 32]);
    let mut coordinator = RecoveryEnrollmentCoordinator::new_for_test(
        clock.clone(),
        XorShiftEntropy::new(seed),
        provider.transport(scope()),
    );
    let mut vault = vault;
    let RecoveryEnrollmentBeginOutcome::Phrase(phrase) = coordinator
        .begin(
            &mut vault,
            DEVICE_ID.parse().unwrap(),
            "First Mac",
            NativePlatform::Macos,
            &device_keys,
        )
        .unwrap()
    else {
        unreachable!()
    };
    PendingHarness {
        _path: path,
        _key_store: key_store,
        vault,
        provider,
        clock,
        device_keys,
        coordinator,
        phrase,
    }
}

fn file_set_contains(path: &std::path::Path, needle: &[u8]) -> bool {
    ["", "-wal", "-shm", "-journal"].iter().any(|suffix| {
        fs::read(format!("{}{suffix}", path.display()))
            .ok()
            .is_some_and(|bytes| bytes.windows(needle.len()).any(|window| window == needle))
    })
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

fn assert_no_recovery_trust(vault: &Vault, device_keys: &DeviceKeys) {
    assert!(vault.devices(scope()).unwrap().is_empty());
    assert!(vault.enrolled_workspace_material(device_keys).is_err());
}

fn recovery_secret_canaries(phrase: &RecoveryEnrollmentPhrase) -> [[u8; 32]; 2] {
    let sentence = phrase.recovery_phrase_words.as_words().join(" ");
    let mnemonic = Mnemonic::parse_in(Language::English, sentence).unwrap();
    let seed = mnemonic.to_seed_normalized("");
    let mut signing = [0_u8; 32];
    Hkdf::<Sha256>::new(Some(b"context-relay/recovery/v1"), &seed)
        .expand(b"context-relay/recovery/signing/v1", &mut signing)
        .unwrap();
    let mut wrapping = [0_u8; 32];
    Hkdf::<Sha256>::new(Some(b"context-relay/recovery/v1"), &seed)
        .expand(b"context-relay/recovery/wrapping/v1", &mut wrapping)
        .unwrap();
    [signing, wrapping]
}

#[test]
fn coordinator_generates_once_then_confirms_and_activates_without_early_writes() {
    let path = TempVault::new("recovery-coordinator-confirm");
    let key_store = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &key_store).unwrap();
    let provider = InMemoryRecoveryEnrollmentProvider::new();
    let transport = provider.transport(scope());
    let clock = FixedClock::default();
    clock.set(10_000);
    let device_keys = DeviceKeys::from_seeds_for_test([0x11; 32], [0x22; 32]);
    let mut coordinator = RecoveryEnrollmentCoordinator::new_for_test(
        clock.clone(),
        XorShiftEntropy::new(0x1234_5678_9abc_def0),
        transport.clone(),
    );

    let RecoveryEnrollmentBeginOutcome::Phrase(phrase) = coordinator
        .begin(
            &mut vault,
            DEVICE_ID.parse::<DeviceId>().unwrap(),
            "First Mac",
            NativePlatform::Macos,
            &device_keys,
        )
        .unwrap()
    else {
        panic!("first begin must return the one-time phrase")
    };
    assert_eq!(phrase.recovery_phrase_words.as_words().len(), 24);
    assert_eq!(phrase.confirmation_positions.len(), 4);
    assert!(
        phrase
            .confirmation_positions
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
    assert!(vault.recovery_enrollment().unwrap().is_none());
    assert!(transport.root_status().unwrap().is_none());

    let status = coordinator.overview(&mut vault, &device_keys).unwrap();
    assert_eq!(status.state, RecoveryEnrollmentState::AwaitingConfirmation);
    assert_eq!(status.enrollment_id, Some(phrase.enrollment_id));
    assert!(matches!(
        coordinator
            .begin(
                &mut vault,
                DEVICE_ID.parse::<DeviceId>().unwrap(),
                "First Mac",
                NativePlatform::Macos,
                &device_keys,
            )
            .unwrap(),
        RecoveryEnrollmentBeginOutcome::Status(status)
            if status.state == RecoveryEnrollmentState::AwaitingConfirmation
    ));

    let recovery_secret_canaries = recovery_secret_canaries(&phrase);
    clock.set(10_500);
    let RecoveryEnrollmentConfirmOutcome::Complete(completion) = coordinator
        .confirm(&mut vault, confirmations(&phrase), &device_keys)
        .unwrap()
    else {
        panic!("matching confirmation must complete")
    };
    assert_eq!(completion.enrollment_id, phrase.enrollment_id);
    assert_eq!(completion.device.device_id, DEVICE_ID.parse().unwrap());
    assert_eq!(completion.device.name, "First Mac");
    assert!(transport.root_status().unwrap().is_some());
    assert_eq!(
        vault.recovery_enrollment().unwrap().unwrap().state,
        RecoveryEnrollmentPersistenceState::Active
    );
    assert!(vault.enrolled_workspace_material(&device_keys).is_ok());
    let opened_material = vault.enrolled_workspace_material(&device_keys).unwrap();
    let phrase_canary = phrase.recovery_phrase_words.as_words().join(" ");
    assert!(!file_set_contains(path.path(), phrase_canary.as_bytes()));
    assert!(!format!("{coordinator:?}").contains(&phrase_canary));
    assert!(!format!("{:?}", provider.test_safe_captures()).contains(&phrase_canary));
    assert!(vault.test_plaintext_cells().unwrap().iter().all(|cell| {
        !cell
            .bytes
            .windows(phrase_canary.len())
            .any(|window| window == phrase_canary.as_bytes())
    }));
    for secret in [
        recovery_secret_canaries[0].as_slice(),
        recovery_secret_canaries[1].as_slice(),
        opened_material.workspace_root_key().as_slice(),
        opened_material.active_epoch_key().as_slice(),
    ] {
        assert!(!file_set_contains(path.path(), secret));
        assert!(vault.test_plaintext_cells().unwrap().iter().all(|cell| {
            !cell
                .bytes
                .windows(secret.len())
                .any(|window| window == secret)
        }));
        assert!(
            !format!("{coordinator:?}")
                .as_bytes()
                .windows(secret.len())
                .any(|window| window == secret)
        );
        assert!(
            !format!("{:?}", provider.test_safe_captures())
                .as_bytes()
                .windows(secret.len())
                .any(|window| window == secret)
        );
    }
}

#[test]
fn every_confirmation_mismatch_consumes_the_session_without_writing_trust() {
    for case in 0..6 {
        let mut harness = pending_harness(&format!("recovery-confirm-invalid-{case}"), case + 1);
        let mut params = confirmations(&harness.phrase);
        match case {
            0 => params.confirmations[0].word = "wrong".to_owned(),
            1 => params.confirmations[0].position = params.confirmations[1].position,
            2 => {
                params.confirmations.pop();
            }
            3 => {
                params.confirmations.push(RecoveryWordConfirmation {
                    position: 24,
                    word: "wrong".to_owned(),
                });
            }
            4 => params.confirmations.swap(0, 1),
            5 => {
                params.enrollment_id = "018f22e2-79b0-7cc8-98c4-dc0c0c074199".parse().unwrap();
            }
            _ => unreachable!(),
        }
        assert!(matches!(
            harness
                .coordinator
                .confirm(&mut harness.vault, params, &harness.device_keys),
            Err(RecoveryEnrollmentCycleError::Invalid)
        ));
        assert_eq!(
            harness
                .coordinator
                .overview(&mut harness.vault, &harness.device_keys)
                .unwrap()
                .state,
            RecoveryEnrollmentState::Idle
        );
        assert!(harness.vault.recovery_enrollment().unwrap().is_none());
        assert!(
            harness
                .provider
                .transport(scope())
                .root_status()
                .unwrap()
                .is_none()
        );
    }
}

#[test]
fn completed_confirmation_cannot_be_replayed_or_changed() {
    let mut harness = pending_harness("recovery-confirm-replay", 91);
    harness.clock.set(40_100);
    let original = confirmations(&harness.phrase);
    assert!(matches!(
        harness
            .coordinator
            .confirm(&mut harness.vault, original, &harness.device_keys),
        Ok(RecoveryEnrollmentConfirmOutcome::Complete(_))
    ));
    assert!(matches!(
        harness.coordinator.confirm(
            &mut harness.vault,
            confirmations(&harness.phrase),
            &harness.device_keys
        ),
        Err(RecoveryEnrollmentCycleError::Invalid)
    ));
    assert_eq!(
        harness.vault.recovery_enrollment().unwrap().unwrap().state,
        RecoveryEnrollmentPersistenceState::Active
    );
}

#[test]
fn dropping_an_unconfirmed_coordinator_leaves_no_recoverable_session_or_trust() {
    let PendingHarness {
        _path: path,
        _key_store: key_store,
        vault,
        provider,
        clock,
        device_keys,
        coordinator,
        phrase,
    } = pending_harness("recovery-unconfirmed-drop", 92);
    let phrase_canary = phrase.recovery_phrase_words.as_words().join(" ");
    drop(phrase);
    drop(coordinator);
    assert!(vault.recovery_enrollment().unwrap().is_none());
    assert_no_recovery_trust(&vault, &device_keys);
    assert!(provider.transport(scope()).root_status().unwrap().is_none());
    assert!(!file_set_contains(path.path(), phrase_canary.as_bytes()));
    drop(vault);

    let mut reopened = Vault::open(path.path(), CREDENTIAL, &key_store).unwrap();
    let mut fresh = RecoveryEnrollmentCoordinator::new_for_test(
        clock,
        XorShiftEntropy::new(93),
        provider.transport(scope()),
    );
    assert_eq!(
        fresh.overview(&mut reopened, &device_keys).unwrap().state,
        RecoveryEnrollmentState::Idle
    );
}

#[test]
fn active_status_fails_closed_when_the_stable_device_identity_changes() {
    let mut harness = pending_harness("recovery-active-wrong-device-keys", 101);
    harness.clock.set(40_100);
    assert!(matches!(
        harness.coordinator.confirm(
            &mut harness.vault,
            confirmations(&harness.phrase),
            &harness.device_keys,
        ),
        Ok(RecoveryEnrollmentConfirmOutcome::Complete(_))
    ));
    let wrong_keys = DeviceKeys::from_seeds_for_test([0x3a; 32], [0x4a; 32]);
    drop(harness.coordinator);
    let mut resumed = RecoveryEnrollmentCoordinator::new_for_test(
        harness.clock,
        XorShiftEntropy::new(102),
        harness.provider.transport(scope()),
    );
    assert_eq!(
        resumed
            .overview(&mut harness.vault, &wrong_keys)
            .unwrap()
            .state,
        RecoveryEnrollmentState::Conflict
    );
    assert!(
        harness
            .vault
            .enrolled_workspace_material(&wrong_keys)
            .is_err()
    );
}

#[test]
fn coordinator_expiry_and_cancel_consume_only_the_exact_memory_session() {
    let path = TempVault::new("recovery-coordinator-expiry-cancel");
    let key_store = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &key_store).unwrap();
    let provider = InMemoryRecoveryEnrollmentProvider::new();
    let clock = FixedClock::default();
    let device_keys = DeviceKeys::from_seeds_for_test([0x31; 32], [0x41; 32]);
    let mut coordinator = RecoveryEnrollmentCoordinator::new_for_test(
        clock.clone(),
        XorShiftEntropy::new(7),
        provider.transport(scope()),
    );
    let RecoveryEnrollmentBeginOutcome::Phrase(first) = coordinator
        .begin(
            &mut vault,
            DEVICE_ID.parse().unwrap(),
            "First Mac",
            NativePlatform::Macos,
            &device_keys,
        )
        .unwrap()
    else {
        unreachable!()
    };
    assert!(matches!(
        coordinator.cancel(
            &mut vault,
            "018f22e2-79b0-7cc8-98c4-dc0c0c074199".parse().unwrap()
        ),
        Err(RecoveryEnrollmentCycleError::Invalid)
    ));
    assert_eq!(
        coordinator
            .status(&mut vault, first.enrollment_id, &device_keys)
            .unwrap()
            .state,
        RecoveryEnrollmentState::AwaitingConfirmation
    );
    assert_eq!(
        coordinator
            .cancel(&mut vault, first.enrollment_id)
            .unwrap()
            .state,
        RecoveryEnrollmentState::Idle
    );

    let RecoveryEnrollmentBeginOutcome::Phrase(second) = coordinator
        .begin(
            &mut vault,
            DEVICE_ID.parse().unwrap(),
            "First Mac",
            NativePlatform::Macos,
            &device_keys,
        )
        .unwrap()
    else {
        unreachable!()
    };
    clock.set(second.expires_at_ms.0 - 1);
    assert_eq!(
        coordinator
            .status(&mut vault, second.enrollment_id, &device_keys)
            .unwrap()
            .state,
        RecoveryEnrollmentState::AwaitingConfirmation
    );
    clock.set(second.expires_at_ms.0);
    assert!(matches!(
        coordinator.status(&mut vault, second.enrollment_id, &device_keys),
        Err(RecoveryEnrollmentCycleError::Expired)
    ));
    assert_eq!(
        coordinator
            .overview(&mut vault, &device_keys)
            .unwrap()
            .state,
        RecoveryEnrollmentState::Idle
    );
}

#[test]
fn coordinator_restarts_and_resumes_a_transient_prepared_enrollment() {
    let path = TempVault::new("recovery-coordinator-restart");
    let key_store = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &key_store).unwrap();
    let provider = InMemoryRecoveryEnrollmentProvider::new();
    let transport = provider.transport(scope());
    let clock = FixedClock::default();
    clock.set(20_000);
    let device_keys = DeviceKeys::from_seeds_for_test([0x51; 32], [0x61; 32]);
    let mut coordinator = RecoveryEnrollmentCoordinator::new_for_test(
        clock.clone(),
        XorShiftEntropy::new(11),
        transport.clone(),
    );
    let RecoveryEnrollmentBeginOutcome::Phrase(phrase) = coordinator
        .begin(
            &mut vault,
            DEVICE_ID.parse().unwrap(),
            "First Mac",
            NativePlatform::Macos,
            &device_keys,
        )
        .unwrap()
    else {
        unreachable!()
    };
    provider.test_fail_next(1);
    clock.set(20_100);
    assert!(matches!(
        coordinator
            .confirm(&mut vault, confirmations(&phrase), &device_keys)
            .unwrap(),
        RecoveryEnrollmentConfirmOutcome::Status(status)
            if status.state == RecoveryEnrollmentState::Submitting
    ));
    assert_eq!(
        vault.recovery_enrollment().unwrap().unwrap().state,
        RecoveryEnrollmentPersistenceState::Prepared
    );
    drop(coordinator);
    drop(vault);

    clock.set(20_500);
    let mut vault = Vault::open(path.path(), CREDENTIAL, &key_store).unwrap();
    let mut resumed =
        RecoveryEnrollmentCoordinator::new_for_test(clock, XorShiftEntropy::new(99), transport);
    let status = resumed.overview(&mut vault, &device_keys).unwrap();
    assert_eq!(status.state, RecoveryEnrollmentState::Complete);
    assert_eq!(status.enrollment_id, Some(phrase.enrollment_id));
    assert!(vault.enrolled_workspace_material(&device_keys).is_ok());
}

#[test]
fn provider_accept_before_local_activation_resumes_after_reopen() {
    let mut harness = pending_harness("recovery-provider-before-activation", 121);
    let database_key = harness._key_store.key(CREDENTIAL);
    let raw = open_keyed(harness._path.path(), &database_key);
    raw.execute_batch(
        "CREATE TRIGGER abort_recovery_activation_e2e
         BEFORE UPDATE OF state ON recovery_enrollments
         WHEN NEW.state = 'active'
         BEGIN
           SELECT RAISE(ABORT, 'injected activation failure');
         END;",
    )
    .unwrap();
    drop(raw);

    harness.clock.set(40_100);
    assert!(matches!(
        harness.coordinator.confirm(
            &mut harness.vault,
            confirmations(&harness.phrase),
            &harness.device_keys,
        ),
        Err(RecoveryEnrollmentCycleError::Transient)
    ));
    assert!(
        harness
            .provider
            .transport(scope())
            .root_status()
            .unwrap()
            .is_some()
    );
    assert_eq!(
        harness.vault.recovery_enrollment().unwrap().unwrap().state,
        RecoveryEnrollmentPersistenceState::Prepared
    );
    assert_no_recovery_trust(&harness.vault, &harness.device_keys);
    drop(harness.coordinator);
    drop(harness.vault);

    let raw = open_keyed(harness._path.path(), &database_key);
    raw.execute_batch("DROP TRIGGER abort_recovery_activation_e2e")
        .unwrap();
    drop(raw);
    let mut vault = Vault::open(harness._path.path(), CREDENTIAL, &harness._key_store).unwrap();
    harness.clock.set(40_200);
    let mut resumed = RecoveryEnrollmentCoordinator::new_for_test(
        harness.clock,
        XorShiftEntropy::new(122),
        harness.provider.transport(scope()),
    );
    assert_eq!(
        resumed
            .overview(&mut vault, &harness.device_keys)
            .unwrap()
            .state,
        RecoveryEnrollmentState::Complete
    );
    assert_eq!(vault.devices(scope()).unwrap().len(), 1);
    assert!(
        vault
            .enrolled_workspace_material(&harness.device_keys)
            .is_ok()
    );
}

#[test]
fn provider_only_and_deleted_provider_state_fail_closed_without_new_trust() {
    let source_path = TempVault::new("recovery-provider-only-source");
    let source_store = MemoryKeyStore::default();
    let provider = InMemoryRecoveryEnrollmentProvider::new();
    let clock = FixedClock::default();
    clock.set(50_000);
    let source_keys = DeviceKeys::from_seeds_for_test([0xc1; 32], [0xd1; 32]);
    let mut source_vault = Vault::open(source_path.path(), CREDENTIAL, &source_store).unwrap();
    let mut source = RecoveryEnrollmentCoordinator::new_for_test(
        clock.clone(),
        XorShiftEntropy::new(123),
        provider.transport(scope()),
    );
    let RecoveryEnrollmentBeginOutcome::Phrase(phrase) = source
        .begin(
            &mut source_vault,
            DEVICE_ID.parse().unwrap(),
            "First Mac",
            NativePlatform::Macos,
            &source_keys,
        )
        .unwrap()
    else {
        unreachable!()
    };
    clock.set(50_100);
    assert!(matches!(
        source
            .confirm(&mut source_vault, confirmations(&phrase), &source_keys)
            .unwrap(),
        RecoveryEnrollmentConfirmOutcome::Complete(_)
    ));

    let target_path = TempVault::new("recovery-provider-only-target");
    let target_store = MemoryKeyStore::default();
    let mut target_vault = Vault::open(target_path.path(), CREDENTIAL, &target_store).unwrap();
    let target_keys = DeviceKeys::from_seeds_for_test([0xe1; 32], [0xf1; 32]);
    let mut target = RecoveryEnrollmentCoordinator::new_for_test(
        clock.clone(),
        XorShiftEntropy::new(124),
        provider.transport(scope()),
    );
    assert_eq!(
        target
            .overview(&mut target_vault, &target_keys)
            .unwrap()
            .state,
        RecoveryEnrollmentState::Conflict
    );
    assert!(matches!(
        target
            .begin(
                &mut target_vault,
                JOINER_DEVICE_ID.parse().unwrap(),
                "Other Mac",
                NativePlatform::Macos,
                &target_keys,
            )
            .unwrap(),
        RecoveryEnrollmentBeginOutcome::Status(status)
            if status.state == RecoveryEnrollmentState::Conflict
    ));
    assert!(target_vault.recovery_enrollment().unwrap().is_none());
    assert_no_recovery_trust(&target_vault, &target_keys);

    provider.test_delete_account(scope().account_id);
    assert_eq!(
        source
            .overview(&mut source_vault, &source_keys)
            .unwrap()
            .state,
        RecoveryEnrollmentState::Conflict
    );
    assert!(matches!(
        source
            .begin(
                &mut source_vault,
                DEVICE_ID.parse().unwrap(),
                "First Mac",
                NativePlatform::Macos,
                &source_keys,
            )
            .unwrap(),
        RecoveryEnrollmentBeginOutcome::Status(status)
            if status.state == RecoveryEnrollmentState::Conflict
    ));
    assert_eq!(source_vault.devices(scope()).unwrap().len(), 1);
    assert!(
        source_vault
            .enrolled_workspace_material(&source_keys)
            .is_ok()
    );
}

#[test]
fn forged_receipt_or_status_is_terminal_and_never_installs_trust() {
    let mut forged_receipt = pending_harness("recovery-forged-receipt", 131);
    forged_receipt
        .provider
        .test_forge_next_receipt(RecoveryEnrollmentReceipt {
            enrollment_id: forged_receipt.phrase.enrollment_id,
            recovery_root_id: "018f22e2-79b0-7cc8-98c4-dc0c0c074191"
                .parse::<RecoveryRootId>()
                .unwrap(),
            account_id: scope().account_id,
            workspace_id: scope().workspace_id,
            genesis_certificate_id: "018f22e2-79b0-7cc8-98c4-dc0c0c074192".parse().unwrap(),
            canonical_record_sha256: Sha256Digest([0xff; 32]),
            registered_at_ms: 40_100,
        });
    forged_receipt.clock.set(40_100);
    assert!(matches!(
        forged_receipt
            .coordinator
            .confirm(
                &mut forged_receipt.vault,
                confirmations(&forged_receipt.phrase),
                &forged_receipt.device_keys,
            )
            .unwrap(),
        RecoveryEnrollmentConfirmOutcome::Status(status)
            if status.state == RecoveryEnrollmentState::Conflict
    ));
    assert_eq!(
        forged_receipt
            .vault
            .recovery_enrollment()
            .unwrap()
            .unwrap()
            .state,
        RecoveryEnrollmentPersistenceState::Conflict
    );
    assert_no_recovery_trust(&forged_receipt.vault, &forged_receipt.device_keys);

    let mut forged_status = pending_harness("recovery-forged-status", 141);
    forged_status.provider.test_fail_next(1);
    forged_status.clock.set(40_100);
    assert!(matches!(
        forged_status
            .coordinator
            .confirm(
                &mut forged_status.vault,
                confirmations(&forged_status.phrase),
                &forged_status.device_keys,
            )
            .unwrap(),
        RecoveryEnrollmentConfirmOutcome::Status(status)
            if status.state == RecoveryEnrollmentState::Submitting
    ));
    let transport = forged_status.provider.transport(scope());
    let stored = forged_status.vault.recovery_enrollment().unwrap().unwrap();
    transport
        .register(&stored.canonical_record, 40_100)
        .unwrap();
    let mut status = transport.root_status().unwrap().unwrap();
    status.canonical_record_sha256 = Sha256Digest([0xee; 32]);
    forged_status.provider.test_forge_next_status(status);
    drop(forged_status.coordinator);
    let mut resumed = RecoveryEnrollmentCoordinator::new_for_test(
        forged_status.clock,
        XorShiftEntropy::new(142),
        transport,
    );
    assert_eq!(
        resumed
            .overview(&mut forged_status.vault, &forged_status.device_keys)
            .unwrap()
            .state,
        RecoveryEnrollmentState::Conflict
    );
    assert_eq!(
        forged_status
            .vault
            .recovery_enrollment()
            .unwrap()
            .unwrap()
            .state,
        RecoveryEnrollmentPersistenceState::Conflict
    );
    assert_no_recovery_trust(&forged_status.vault, &forged_status.device_keys);
}

#[test]
fn tampered_prepared_record_certificate_or_envelope_never_converges_or_installs_trust() {
    for (index, (case, mutation)) in [
        (
            "record",
            "UPDATE recovery_enrollments
             SET canonical_record = zeroblob(length(canonical_record))",
        ),
        (
            "certificate",
            "UPDATE recovery_enrollments
             SET device_signing_public_key = zeroblob(32)",
        ),
        (
            "envelope",
            "UPDATE recovery_enrollments
             SET device_material_envelope = zeroblob(length(device_material_envelope))",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let seed = 161 + u64::try_from(index).unwrap() * 10;
        let mut harness = pending_harness(&format!("recovery-tampered-{case}"), seed);
        harness.provider.test_fail_next(1);
        harness.clock.set(40_100);
        assert!(matches!(
            harness
                .coordinator
                .confirm(
                    &mut harness.vault,
                    confirmations(&harness.phrase),
                    &harness.device_keys,
                )
                .unwrap(),
            RecoveryEnrollmentConfirmOutcome::Status(status)
                if status.state == RecoveryEnrollmentState::Submitting
        ));
        let database_key = harness._key_store.key(CREDENTIAL);
        drop(harness.coordinator);
        drop(harness.vault);
        let raw = open_keyed(harness._path.path(), &database_key);
        raw.execute_batch(mutation).unwrap();
        drop(raw);

        let mut vault = Vault::open(harness._path.path(), CREDENTIAL, &harness._key_store).unwrap();
        let mut resumed = RecoveryEnrollmentCoordinator::new_for_test(
            harness.clock,
            XorShiftEntropy::new(152),
            harness.provider.transport(scope()),
        );
        assert!(matches!(
            resumed.overview(&mut vault, &harness.device_keys),
            Err(RecoveryEnrollmentCycleError::Conflict)
        ));
        assert!(vault.devices(scope()).unwrap().is_empty());
        assert!(
            vault
                .enrolled_workspace_material(&harness.device_keys)
                .is_err()
        );
    }
}

#[test]
fn recovered_vault_material_bootstraps_real_pairing_and_both_replicas_reopen() {
    let approver_path = TempVault::new("recovery-pairing-approver");
    let joiner_path = TempVault::new("recovery-pairing-joiner");
    let approver_store = MemoryKeyStore::default();
    let joiner_store = MemoryKeyStore::default();
    let recovery_provider = InMemoryRecoveryEnrollmentProvider::new();
    let recovery_clock = FixedClock::default();
    recovery_clock.set(30_000);
    let approver_keys = DeviceKeys::from_seeds_for_test([0x71; 32], [0x81; 32]);
    let mut recovery = RecoveryEnrollmentCoordinator::new_for_test(
        recovery_clock.clone(),
        XorShiftEntropy::new(0xfeed_face_cafe_babe),
        recovery_provider.transport(scope()),
    );
    let mut approver_vault =
        Vault::open(approver_path.path(), "recovery-pairing-a", &approver_store).unwrap();
    let RecoveryEnrollmentBeginOutcome::Phrase(phrase) = recovery
        .begin(
            &mut approver_vault,
            DEVICE_ID.parse().unwrap(),
            "First Mac",
            NativePlatform::Macos,
            &approver_keys,
        )
        .unwrap()
    else {
        unreachable!()
    };
    recovery_clock.set(30_100);
    let RecoveryEnrollmentConfirmOutcome::Complete(_) = recovery
        .confirm(&mut approver_vault, confirmations(&phrase), &approver_keys)
        .unwrap()
    else {
        unreachable!()
    };
    let enrollment = approver_vault.recovery_enrollment().unwrap().unwrap();
    let issuer_certificate_id = enrollment.record.genesis_certificate_id;
    drop(approver_vault);

    let pairing_provider = InMemoryPairingProvider::with_test_entropy(
        [0x91; 32],
        (1_u8..=8).map(|value| [value; 32]).collect(),
    );
    let pairing_clock = FixedClock::default();
    pairing_clock.set(31_000);
    let pairing = PairingCoordinator::new(
        pairing_clock.clone(),
        VaultPairingMaterialSource,
        pairing_provider
            .join_session_client("recovery-pairing-joiner-session")
            .unwrap(),
        pairing_provider.existing_device_client(scope(), DEVICE_ID.parse().unwrap()),
    );
    let mut approver_vault =
        Vault::open(approver_path.path(), "recovery-pairing-a", &approver_store).unwrap();
    let mut joiner_vault =
        Vault::open(joiner_path.path(), "recovery-pairing-b", &joiner_store).unwrap();
    let joiner_keys = DeviceKeys::from_seeds_for_test([0xa1; 32], [0xb1; 32]);
    let invite = pairing.create_invite().unwrap();
    pairing_clock.set(31_001);
    let submission = pairing
        .join(
            &mut joiner_vault,
            &invite.code,
            JOINER_DEVICE_ID.parse().unwrap(),
            "Joining Mac",
            NativePlatform::Macos,
            &joiner_keys,
        )
        .unwrap();
    pairing_clock.set(31_002);
    let review = pairing.request_status(invite.pairing_id).unwrap().unwrap();
    let decision = pairing
        .decide(
            &mut approver_vault,
            invite.pairing_id,
            review.request_digest,
            PairingDecisionInput::Approve(PairingApprovalAuthority {
                certificate_id: JOINER_CERTIFICATE_ID
                    .parse::<DeviceCertificateId>()
                    .unwrap(),
                issuer_certificate_id,
                issuer_keys: &approver_keys,
            }),
        )
        .unwrap();
    let PairingDecisionStatus::Approved { safety_number } = decision else {
        unreachable!()
    };
    pairing_clock.set(31_003);
    assert!(matches!(
        pairing
            .join_status(&mut joiner_vault, submission.pairing_id)
            .unwrap(),
        PairingJoinStatus::AwaitingConfirmation { .. }
    ));
    pairing_clock.set(31_004);
    let joined = pairing
        .confirm_join(
            &mut joiner_vault,
            submission.pairing_id,
            safety_number.as_str(),
            &joiner_keys,
        )
        .unwrap();
    let enrolled = approver_vault
        .enrolled_workspace_material(&approver_keys)
        .unwrap();
    assert_eq!(enrolled.scope(), joined.scope());
    assert_eq!(enrolled.control_epoch(), joined.control_epoch());
    assert_eq!(enrolled.key_epoch(), joined.key_epoch());
    assert_eq!(enrolled.workspace_root_key(), joined.workspace_root_key());
    assert_eq!(enrolled.active_epoch_key(), joined.active_epoch_key());
    assert_eq!(approver_vault.devices(scope()).unwrap().len(), 2);
    assert_eq!(joiner_vault.devices(scope()).unwrap().len(), 2);
    drop(approver_vault);
    drop(joiner_vault);

    let approver_vault =
        Vault::open(approver_path.path(), "recovery-pairing-a", &approver_store).unwrap();
    let joiner_vault =
        Vault::open(joiner_path.path(), "recovery-pairing-b", &joiner_store).unwrap();
    let reopened_enrolled = approver_vault
        .enrolled_workspace_material(&approver_keys)
        .unwrap();
    let reopened_joined = pairing
        .completed_material(&joiner_vault, submission.pairing_id, &joiner_keys)
        .unwrap()
        .unwrap();
    assert_eq!(
        reopened_enrolled.workspace_root_key(),
        reopened_joined.workspace_root_key()
    );
    assert_eq!(
        reopened_enrolled.active_epoch_key(),
        reopened_joined.active_epoch_key()
    );
    assert_eq!(approver_vault.devices(scope()).unwrap().len(), 2);
    assert_eq!(joiner_vault.devices(scope()).unwrap().len(), 2);
}
