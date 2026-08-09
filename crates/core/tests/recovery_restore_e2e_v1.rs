mod support;

use std::{
    fs,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use bip39::{Language, Mnemonic};
use context_relay_core::{
    crypto::{DeviceKeys, RecoveryPhrase},
    devices::{
        memory_recovery_transport::{
            InMemoryRecoveryEnrollmentProvider, InMemoryRecoveryRestoreTransport,
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
        recovery_restore::{
            RecoveryRestoreCoordinator, RecoveryRestoreCycleError, RecoveryRestoreIdentity,
            RecoveryRestoreOutcome,
        },
        recovery_restore_transport::{
            RecoveryRestoreProjection, RecoveryRestoreReceipt, RecoveryRestoreTransport,
            RecoveryRootSnapshot,
        },
        recovery_transport::RecoveryTransportError,
    },
    sync::SyncScope,
    vault::{RecoveryRestorePersistenceState, Vault},
};
use context_relay_protocol::{
    AccountId, DeviceCertificateId, DeviceId, NativePlatform, RecoveryEnrollmentConfirmParams,
    RecoveryPhraseWords, RecoveryWordConfirmation, Sha256Digest, WorkspaceId,
};
use hkdf::Hkdf;
use rusqlite::Connection;
use sha2::{Digest, Sha256};

use support::{MemoryKeyStore, TempVault};

const CREDENTIAL: &str = "recovery-restore-e2e-v1";
const ACCOUNT_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c075101";
const WORKSPACE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c075102";
const GENESIS_DEVICE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c075103";
const RECOVERED_DEVICE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c075104";
const RACING_DEVICE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c075105";
const THIRD_DEVICE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c075106";
const THIRD_CERTIFICATE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c075107";

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

struct FailOnFourthEntropy(Mutex<usize>);

impl FailOnFourthEntropy {
    const fn new() -> Self {
        Self(Mutex::new(0))
    }
}

impl RecoveryEnrollmentEntropy for FailOnFourthEntropy {
    fn fill_bytes(&self, output: &mut [u8]) -> Result<(), RecoveryEnrollmentCycleError> {
        let mut calls = self.0.lock().unwrap();
        *calls += 1;
        if *calls == 4 {
            return Err(RecoveryEnrollmentCycleError::Transient);
        }
        output.fill(u8::try_from(*calls).unwrap());
        Ok(())
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

struct EnrolledSource {
    provider: InMemoryRecoveryEnrollmentProvider,
    phrase_words: RecoveryPhraseWords,
    workspace_root_key: [u8; 32],
    active_epoch_key: [u8; 32],
}

fn enrolled_source(name: &str) -> EnrolledSource {
    let path = TempVault::new(name);
    let key_store = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &key_store).unwrap();
    let provider = InMemoryRecoveryEnrollmentProvider::new();
    let clock = FixedClock::default();
    clock.set(10_000);
    let keys = DeviceKeys::from_seeds_for_test([0x11; 32], [0x22; 32]);
    let entropy_seed = name.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |state, byte| {
        state.wrapping_mul(0x0000_0100_0000_01b3) ^ u64::from(byte)
    });
    let mut coordinator = RecoveryEnrollmentCoordinator::new_for_test(
        clock.clone(),
        XorShiftEntropy::new(entropy_seed),
        provider.transport(scope()),
    );
    let RecoveryEnrollmentBeginOutcome::Phrase(phrase) = coordinator
        .begin(
            &mut vault,
            GENESIS_DEVICE_ID.parse::<DeviceId>().unwrap(),
            "Original Mac",
            NativePlatform::Macos,
            &keys,
        )
        .unwrap()
    else {
        unreachable!()
    };
    clock.set(10_100);
    let result = coordinator.confirm(&mut vault, confirmations(&phrase), &keys);
    let RecoveryEnrollmentConfirmOutcome::Complete(_) = result.unwrap_or_else(|error| {
        panic!(
            "source enrollment failed: {error:?}; local={:?}; provider={:?}",
            vault.recovery_enrollment(),
            provider.test_safe_captures()
        )
    }) else {
        unreachable!()
    };
    let material = vault.enrolled_workspace_material(&keys).unwrap();
    EnrolledSource {
        provider,
        phrase_words: phrase.recovery_phrase_words,
        workspace_root_key: *material.workspace_root_key(),
        active_epoch_key: *material.active_epoch_key(),
    }
}

type TestRestoreCoordinator =
    RecoveryRestoreCoordinator<FixedClock, XorShiftEntropy, InMemoryRecoveryRestoreTransport>;

#[derive(Clone)]
struct FaultedRestoreTransport {
    inner: InMemoryRecoveryRestoreTransport,
    fail_submit: Arc<AtomicBool>,
    fail_lookup: Arc<AtomicBool>,
}

impl FaultedRestoreTransport {
    fn fail_submit_once(inner: InMemoryRecoveryRestoreTransport) -> Self {
        Self {
            inner,
            fail_submit: Arc::new(AtomicBool::new(true)),
            fail_lookup: Arc::new(AtomicBool::new(false)),
        }
    }

    fn fail_lookup_once(inner: InMemoryRecoveryRestoreTransport) -> Self {
        Self {
            inner,
            fail_submit: Arc::new(AtomicBool::new(false)),
            fail_lookup: Arc::new(AtomicBool::new(true)),
        }
    }
}

impl RecoveryRestoreTransport for FaultedRestoreTransport {
    fn scope(&self) -> SyncScope {
        self.inner.scope()
    }

    fn root_snapshot(&self) -> Result<Option<RecoveryRootSnapshot>, RecoveryTransportError> {
        self.inner.root_snapshot()
    }

    fn submit_restore(
        &self,
        canonical_claim: &[u8],
        now_ms: u64,
    ) -> Result<RecoveryRestoreReceipt, RecoveryTransportError> {
        if self.fail_submit.swap(false, Ordering::SeqCst) {
            return Err(RecoveryTransportError::Transient);
        }
        self.inner.submit_restore(canonical_claim, now_ms)
    }

    fn restore_claim(
        &self,
        restore_id: context_relay_protocol::RecoveryRestoreId,
    ) -> Result<Option<RecoveryRestoreProjection>, RecoveryTransportError> {
        if self.fail_lookup.swap(false, Ordering::SeqCst) {
            return Err(RecoveryTransportError::Transient);
        }
        self.inner.restore_claim(restore_id)
    }
}

fn open_keyed(path: &Path, key: &[u8; 32]) -> Connection {
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

fn file_set_contains(path: &Path, needle: &[u8]) -> bool {
    ["", "-wal", "-shm", "-journal"].iter().any(|suffix| {
        fs::read(format!("{}{suffix}", path.display()))
            .ok()
            .is_some_and(|bytes| bytes.windows(needle.len()).any(|window| window == needle))
    })
}

fn recovery_secret_canaries(words: &RecoveryPhraseWords) -> [[u8; 32]; 2] {
    let sentence = words.as_words().join(" ");
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

fn restore_coordinator(
    provider: &InMemoryRecoveryEnrollmentProvider,
    now_ms: u64,
    seed: u64,
) -> (FixedClock, TestRestoreCoordinator) {
    let clock = FixedClock::default();
    clock.set(now_ms);
    let coordinator = RecoveryRestoreCoordinator::new_for_test(
        clock.clone(),
        XorShiftEntropy::new(seed),
        provider.restore_transport(scope()),
    );
    (clock, coordinator)
}

#[test]
fn wrong_phrase_is_one_invalid_error_without_local_or_provider_mutation() {
    let source = enrolled_source("restore-wrong-phrase-source");
    let path = TempVault::new("restore-wrong-phrase-target");
    let key_store = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &key_store).unwrap();
    let recovered_keys = DeviceKeys::from_seeds_for_test([0x33; 32], [0x44; 32]);
    let mut words = source.phrase_words.as_words().to_vec();
    words[0] = "notaword".to_owned();
    let wrong_words = RecoveryPhraseWords::new(words).unwrap();
    let (_, coordinator) = restore_coordinator(&source.provider, 20_000, 0x2000);

    assert_eq!(
        coordinator
            .recover(
                &mut vault,
                wrong_words,
                &RecoveryRestoreIdentity {
                    device_id: RECOVERED_DEVICE_ID.parse().unwrap(),
                    device_name: "Recovered Mac".to_owned(),
                    platform: NativePlatform::Macos,
                    keys: &recovered_keys,
                },
            )
            .unwrap_err(),
        RecoveryRestoreCycleError::Invalid
    );
    assert!(vault.recovery_restore().unwrap().is_none());
    assert!(vault.devices(scope()).unwrap().is_empty());
    assert!(source.provider.test_safe_restore_captures().is_empty());
    assert!(vault.trusted_workspace_material(&recovered_keys).is_err());

    let other_valid_phrase = RecoveryPhrase::from_entropy_for_test([0x91; 32])
        .unwrap()
        .to_words();
    assert_eq!(
        coordinator
            .recover(
                &mut vault,
                other_valid_phrase,
                &RecoveryRestoreIdentity {
                    device_id: RECOVERED_DEVICE_ID.parse().unwrap(),
                    device_name: "Recovered Mac".to_owned(),
                    platform: NativePlatform::Macos,
                    keys: &recovered_keys,
                },
            )
            .unwrap_err(),
        RecoveryRestoreCycleError::Invalid
    );
    assert!(vault.recovery_restore().unwrap().is_none());
    assert!(source.provider.test_safe_restore_captures().is_empty());
}

#[test]
fn entropy_failure_while_wrapping_is_transient_without_durable_mutation() {
    let source = enrolled_source("restore-entropy-source");
    let path = TempVault::new("restore-entropy-target");
    let key_store = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &key_store).unwrap();
    let recovered_keys = DeviceKeys::from_seeds_for_test([0x45; 32], [0x46; 32]);
    let clock = FixedClock::default();
    clock.set(20_500);
    let coordinator = RecoveryRestoreCoordinator::new_for_test(
        clock,
        FailOnFourthEntropy::new(),
        source.provider.restore_transport(scope()),
    );
    assert_eq!(
        coordinator
            .recover(
                &mut vault,
                source.phrase_words,
                &RecoveryRestoreIdentity {
                    device_id: RECOVERED_DEVICE_ID.parse().unwrap(),
                    device_name: "Recovered Entropy".to_owned(),
                    platform: NativePlatform::Macos,
                    keys: &recovered_keys,
                },
            )
            .unwrap_err(),
        RecoveryRestoreCycleError::Transient
    );
    assert!(vault.recovery_restore().unwrap().is_none());
    assert!(vault.devices(scope()).unwrap().is_empty());
    assert!(source.provider.test_safe_restore_captures().is_empty());
}

#[test]
fn correct_phrase_restores_a_fresh_vault_and_reopens_the_exact_material() {
    let source = enrolled_source("restore-happy-source");
    let path = TempVault::new("restore-happy-target");
    let key_store = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &key_store).unwrap();
    let recovered_keys = DeviceKeys::from_seeds_for_test([0x55; 32], [0x66; 32]);
    let (_, coordinator) = restore_coordinator(&source.provider, 20_000, 0x3000);
    let identity = RecoveryRestoreIdentity {
        device_id: RECOVERED_DEVICE_ID.parse().unwrap(),
        device_name: "Recovered Mac".to_owned(),
        platform: NativePlatform::Macos,
        keys: &recovered_keys,
    };

    assert!(matches!(
        coordinator
            .recover(&mut vault, source.phrase_words, &identity)
            .unwrap(),
        RecoveryRestoreOutcome::Complete { .. }
    ));
    let material = vault.trusted_workspace_material(&recovered_keys).unwrap();
    assert_eq!(material.scope(), scope());
    assert_eq!(material.control_epoch(), 1);
    assert_eq!(material.key_epoch(), 1);
    assert_eq!(material.workspace_root_key(), &source.workspace_root_key);
    assert_eq!(material.active_epoch_key(), &source.active_epoch_key);
    drop(vault);

    let reopened = Vault::open(path.path(), CREDENTIAL, &key_store).unwrap();
    let reopened_material = reopened
        .trusted_workspace_material(&recovered_keys)
        .unwrap();
    assert_eq!(
        reopened_material.workspace_root_key(),
        &source.workspace_root_key
    );
    assert_eq!(
        reopened_material.active_epoch_key(),
        &source.active_epoch_key
    );
}

#[test]
fn prepared_and_provider_accepted_restores_resume_after_reopen_without_the_phrase() {
    for (case, fail_lookup, seed) in [
        ("prepared", false, 0x4000),
        ("provider-accepted", true, 0x5000),
    ] {
        let source = enrolled_source(&format!("restore-{case}-source"));
        let path = TempVault::new(&format!("restore-{case}-target"));
        let key_store = MemoryKeyStore::default();
        let mut vault = Vault::open(path.path(), CREDENTIAL, &key_store).unwrap();
        let recovered_keys = DeviceKeys::from_seeds_for_test([seed as u8; 32], [0x72; 32]);
        let identity = RecoveryRestoreIdentity {
            device_id: RECOVERED_DEVICE_ID.parse().unwrap(),
            device_name: "Recovered Mac".to_owned(),
            platform: NativePlatform::Macos,
            keys: &recovered_keys,
        };
        let clock = FixedClock::default();
        clock.set(30_000);
        let inner = source.provider.restore_transport(scope());
        let faulted = if fail_lookup {
            FaultedRestoreTransport::fail_lookup_once(inner)
        } else {
            FaultedRestoreTransport::fail_submit_once(inner)
        };
        let coordinator = RecoveryRestoreCoordinator::new_for_test(
            clock.clone(),
            XorShiftEntropy::new(seed),
            faulted,
        );
        let RecoveryRestoreOutcome::Submitting { restore_id } = coordinator
            .recover(&mut vault, source.phrase_words, &identity)
            .unwrap()
        else {
            panic!("fault must leave a resumable restore")
        };
        assert!(vault.devices(scope()).unwrap().is_empty());
        assert_eq!(
            source.provider.test_safe_restore_captures().len(),
            usize::from(fail_lookup)
        );
        drop(vault);

        clock.set(30_100);
        let resumed = RecoveryRestoreCoordinator::new_for_test(
            clock,
            XorShiftEntropy::new(seed + 1),
            source.provider.restore_transport(scope()),
        );
        let mut reopened = Vault::open(path.path(), CREDENTIAL, &key_store).unwrap();
        assert!(matches!(
            resumed.resume_prepared(&mut reopened, &identity).unwrap(),
            RecoveryRestoreOutcome::Complete {
                restore_id: completed,
                ..
            } if completed == restore_id
        ));
        assert_eq!(
            reopened
                .trusted_workspace_material(&recovered_keys)
                .unwrap()
                .workspace_root_key(),
            &source.workspace_root_key
        );
    }
}

#[test]
fn activation_abort_rolls_back_trust_then_exact_resume_completes() {
    let source = enrolled_source("restore-activation-abort-source");
    let path = TempVault::new("restore-activation-abort-target");
    let key_store = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &key_store).unwrap();
    let recovered_keys = DeviceKeys::from_seeds_for_test([0x73; 32], [0x74; 32]);
    let identity = RecoveryRestoreIdentity {
        device_id: RECOVERED_DEVICE_ID.parse().unwrap(),
        device_name: "Recovered Mac".to_owned(),
        platform: NativePlatform::Macos,
        keys: &recovered_keys,
    };
    let clock = FixedClock::default();
    clock.set(40_000);
    let prepared = RecoveryRestoreCoordinator::new_for_test(
        clock.clone(),
        XorShiftEntropy::new(0x6000),
        FaultedRestoreTransport::fail_submit_once(source.provider.restore_transport(scope())),
    );
    assert!(matches!(
        prepared
            .recover(&mut vault, source.phrase_words, &identity)
            .unwrap(),
        RecoveryRestoreOutcome::Submitting { .. }
    ));
    drop(vault);

    let raw = open_keyed(path.path(), &key_store.key(CREDENTIAL));
    raw.execute_batch(
        "CREATE TRIGGER abort_restore_activation_e2e
         BEFORE UPDATE OF state ON recovery_restores
         WHEN NEW.state = 'active'
         BEGIN
           SELECT RAISE(ABORT, 'injected restore activation failure');
         END;",
    )
    .unwrap();
    drop(raw);
    let coordinator = RecoveryRestoreCoordinator::new_for_test(
        clock.clone(),
        XorShiftEntropy::new(0x6001),
        source.provider.restore_transport(scope()),
    );
    let mut reopened = Vault::open(path.path(), CREDENTIAL, &key_store).unwrap();
    assert_eq!(
        coordinator
            .resume_prepared(&mut reopened, &identity)
            .unwrap_err(),
        RecoveryRestoreCycleError::Transient
    );
    assert!(reopened.devices(scope()).unwrap().is_empty());
    drop(reopened);

    let raw = open_keyed(path.path(), &key_store.key(CREDENTIAL));
    raw.execute_batch("DROP TRIGGER abort_restore_activation_e2e")
        .unwrap();
    drop(raw);
    clock.set(40_100);
    let mut reopened = Vault::open(path.path(), CREDENTIAL, &key_store).unwrap();
    assert!(matches!(
        coordinator
            .resume_prepared(&mut reopened, &identity)
            .unwrap(),
        RecoveryRestoreOutcome::Complete { .. }
    ));
    assert_eq!(reopened.devices(scope()).unwrap().len(), 2);
}

#[test]
fn two_fresh_targets_race_one_generation_and_only_the_winner_installs_trust() {
    let source = enrolled_source("restore-race-source");
    let first_path = TempVault::new("restore-race-first");
    let second_path = TempVault::new("restore-race-second");
    let first_store = MemoryKeyStore::default();
    let second_store = MemoryKeyStore::default();
    let mut first = Vault::open(first_path.path(), "restore-race-first", &first_store).unwrap();
    let mut second = Vault::open(second_path.path(), "restore-race-second", &second_store).unwrap();
    let first_keys = DeviceKeys::from_seeds_for_test([0x81; 32], [0x82; 32]);
    let second_keys = DeviceKeys::from_seeds_for_test([0x83; 32], [0x84; 32]);
    let first_identity = RecoveryRestoreIdentity {
        device_id: RECOVERED_DEVICE_ID.parse().unwrap(),
        device_name: "Recovered First".to_owned(),
        platform: NativePlatform::Macos,
        keys: &first_keys,
    };
    let second_identity = RecoveryRestoreIdentity {
        device_id: RACING_DEVICE_ID.parse().unwrap(),
        device_name: "Recovered Second".to_owned(),
        platform: NativePlatform::Macos,
        keys: &second_keys,
    };
    let clock = FixedClock::default();
    clock.set(50_000);
    let first_prepare = RecoveryRestoreCoordinator::new_for_test(
        clock.clone(),
        XorShiftEntropy::new(0x7000),
        FaultedRestoreTransport::fail_submit_once(source.provider.restore_transport(scope())),
    );
    let second_prepare = RecoveryRestoreCoordinator::new_for_test(
        clock.clone(),
        XorShiftEntropy::new(0x8000),
        FaultedRestoreTransport::fail_submit_once(source.provider.restore_transport(scope())),
    );
    assert!(matches!(
        first_prepare
            .recover(&mut first, source.phrase_words.clone(), &first_identity,)
            .unwrap(),
        RecoveryRestoreOutcome::Submitting { .. }
    ));
    assert!(matches!(
        second_prepare
            .recover(&mut second, source.phrase_words, &second_identity)
            .unwrap(),
        RecoveryRestoreOutcome::Submitting { .. }
    ));

    let winner = RecoveryRestoreCoordinator::new_for_test(
        clock.clone(),
        XorShiftEntropy::new(0x9000),
        source.provider.restore_transport(scope()),
    );
    assert!(matches!(
        winner.resume_prepared(&mut first, &first_identity).unwrap(),
        RecoveryRestoreOutcome::Complete { .. }
    ));
    let loser = RecoveryRestoreCoordinator::new_for_test(
        clock,
        XorShiftEntropy::new(0xa000),
        source.provider.restore_transport(scope()),
    );
    assert!(matches!(
        loser
            .resume_prepared(&mut second, &second_identity)
            .unwrap(),
        RecoveryRestoreOutcome::Conflict { .. }
    ));
    assert_eq!(source.provider.test_safe_restore_captures().len(), 1);
    assert_eq!(first.devices(scope()).unwrap().len(), 2);
    assert!(second.devices(scope()).unwrap().is_empty());
    assert!(second.trusted_workspace_material(&second_keys).is_err());
}

#[test]
fn conflict_is_durable_even_if_the_local_clock_moves_behind_prepare_time() {
    let source = enrolled_source("restore-clock-rollback-source");
    let path = TempVault::new("restore-clock-rollback-target");
    let key_store = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &key_store).unwrap();
    let recovered_keys = DeviceKeys::from_seeds_for_test([0x95; 32], [0x96; 32]);
    let identity = RecoveryRestoreIdentity {
        device_id: RECOVERED_DEVICE_ID.parse().unwrap(),
        device_name: "Recovered Clock".to_owned(),
        platform: NativePlatform::Macos,
        keys: &recovered_keys,
    };
    let clock = FixedClock::default();
    clock.set(55_000);
    let coordinator = RecoveryRestoreCoordinator::new_for_test(
        clock.clone(),
        XorShiftEntropy::new(0xa500),
        FaultedRestoreTransport::fail_submit_once(source.provider.restore_transport(scope())),
    );
    assert!(matches!(
        coordinator
            .recover(&mut vault, source.phrase_words, &identity)
            .unwrap(),
        RecoveryRestoreOutcome::Submitting { .. }
    ));
    source
        .provider
        .test_set_recovery_generation(scope().account_id, 1);
    clock.set(54_000);

    assert!(matches!(
        coordinator.resume_prepared(&mut vault, &identity).unwrap(),
        RecoveryRestoreOutcome::Conflict { .. }
    ));
    let stored = vault.recovery_restore().unwrap().unwrap();
    assert_eq!(stored.state, RecoveryRestorePersistenceState::Conflict);
    assert_eq!(stored.conflict_at_ms, Some(stored.prepared_at_ms));
    assert!(vault.devices(scope()).unwrap().is_empty());
}

#[test]
fn missing_forged_or_substituted_provider_proof_is_terminal_without_trust() {
    for (index, case) in ["missing", "forged-receipt", "substituted-claim"]
        .into_iter()
        .enumerate()
    {
        let source = enrolled_source(&format!("restore-proof-{case}-source"));
        let path = TempVault::new(&format!("restore-proof-{case}-target"));
        let key_store = MemoryKeyStore::default();
        let mut vault = Vault::open(path.path(), CREDENTIAL, &key_store).unwrap();
        let key_seed = 0xa1 + u8::try_from(index).unwrap() * 2;
        let recovered_keys = DeviceKeys::from_seeds_for_test([key_seed; 32], [key_seed + 1; 32]);
        let identity = RecoveryRestoreIdentity {
            device_id: RECOVERED_DEVICE_ID.parse().unwrap(),
            device_name: format!("Recovered {case}"),
            platform: NativePlatform::Macos,
            keys: &recovered_keys,
        };
        let clock = FixedClock::default();
        clock.set(60_000);
        let outcome = if case == "missing" {
            source.provider.test_omit_next_restore_claim();
            let coordinator = RecoveryRestoreCoordinator::new_for_test(
                clock.clone(),
                XorShiftEntropy::new(0xb000 + u64::try_from(index).unwrap()),
                source.provider.restore_transport(scope()),
            );
            coordinator
                .recover(&mut vault, source.phrase_words, &identity)
                .unwrap()
        } else {
            let coordinator = RecoveryRestoreCoordinator::new_for_test(
                clock.clone(),
                XorShiftEntropy::new(0xb000 + u64::try_from(index).unwrap()),
                FaultedRestoreTransport::fail_lookup_once(
                    source.provider.restore_transport(scope()),
                ),
            );
            let RecoveryRestoreOutcome::Submitting { restore_id } = coordinator
                .recover(&mut vault, source.phrase_words, &identity)
                .unwrap()
            else {
                unreachable!()
            };
            let mut projection = source
                .provider
                .restore_transport(scope())
                .restore_claim(restore_id)
                .unwrap()
                .unwrap();
            if case == "forged-receipt" {
                projection.receipt.accepted_generation += 1;
                source
                    .provider
                    .test_forge_next_restore_receipt(projection.receipt);
            } else {
                projection.canonical_claim[0] ^= 1;
                source
                    .provider
                    .test_forge_next_restore_projection(projection);
            }
            let resumed = RecoveryRestoreCoordinator::new_for_test(
                clock.clone(),
                XorShiftEntropy::new(0xc000 + u64::try_from(index).unwrap()),
                source.provider.restore_transport(scope()),
            );
            resumed.resume_prepared(&mut vault, &identity).unwrap()
        };
        assert!(matches!(outcome, RecoveryRestoreOutcome::Conflict { .. }));
        assert_eq!(
            vault.recovery_restore().unwrap().unwrap().state,
            RecoveryRestorePersistenceState::Conflict
        );
        assert!(vault.devices(scope()).unwrap().is_empty());
        assert!(vault.trusted_workspace_material(&recovered_keys).is_err());
    }
}

#[test]
fn substituted_self_consistent_root_wrong_scope_and_mutated_root_never_prepare() {
    let genuine = enrolled_source("restore-root-genuine-source");
    let genuine_phrase = genuine.phrase_words.clone();
    let attacker = enrolled_source("restore-root-attacker-source");
    let path = TempVault::new("restore-root-substitution-target");
    let key_store = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &key_store).unwrap();
    let recovered_keys = DeviceKeys::from_seeds_for_test([0xad; 32], [0xae; 32]);
    let identity = RecoveryRestoreIdentity {
        device_id: RECOVERED_DEVICE_ID.parse().unwrap(),
        device_name: "Recovered Root Check".to_owned(),
        platform: NativePlatform::Macos,
        keys: &recovered_keys,
    };
    let (_, attacker_coordinator) = restore_coordinator(&attacker.provider, 65_000, 0xb500);
    assert_eq!(
        attacker_coordinator
            .recover(&mut vault, genuine.phrase_words, &identity)
            .unwrap_err(),
        RecoveryRestoreCycleError::Invalid
    );
    assert!(vault.recovery_restore().unwrap().is_none());

    let transport = genuine.provider.restore_transport(scope());
    let mut wrong_scope = transport.root_snapshot().unwrap().unwrap();
    wrong_scope.scope.workspace_id = "018f22e2-79b0-7cc8-98c4-dc0c0c075199".parse().unwrap();
    genuine
        .provider
        .test_forge_next_restore_snapshot(wrong_scope);
    let (_, coordinator) = restore_coordinator(&genuine.provider, 65_100, 0xb501);
    assert_eq!(
        coordinator
            .recover(&mut vault, genuine_phrase.clone(), &identity)
            .unwrap_err(),
        RecoveryRestoreCycleError::Conflict
    );
    assert!(vault.recovery_restore().unwrap().is_none());

    let mut mutated = transport.root_snapshot().unwrap().unwrap();
    let last = mutated.canonical_record.len() - 1;
    mutated.canonical_record[last] ^= 1;
    mutated.canonical_record_sha256 =
        Sha256Digest(Sha256::digest(&mutated.canonical_record).into());
    genuine.provider.test_forge_next_restore_snapshot(mutated);
    assert_eq!(
        coordinator
            .recover(&mut vault, genuine_phrase, &identity)
            .unwrap_err(),
        RecoveryRestoreCycleError::Conflict
    );
    assert!(vault.recovery_restore().unwrap().is_none());
    assert!(vault.devices(scope()).unwrap().is_empty());
    assert!(genuine.provider.test_safe_restore_captures().is_empty());
}

#[test]
fn prepared_restore_requires_the_exact_stable_identity_and_rejects_row_tamper() {
    let source = enrolled_source("restore-identity-source");
    let path = TempVault::new("restore-identity-target");
    let key_store = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &key_store).unwrap();
    let recovered_keys = DeviceKeys::from_seeds_for_test([0xb1; 32], [0xb2; 32]);
    let identity = RecoveryRestoreIdentity {
        device_id: RECOVERED_DEVICE_ID.parse().unwrap(),
        device_name: "Recovered Stable".to_owned(),
        platform: NativePlatform::Macos,
        keys: &recovered_keys,
    };
    let clock = FixedClock::default();
    clock.set(70_000);
    let coordinator = RecoveryRestoreCoordinator::new_for_test(
        clock.clone(),
        XorShiftEntropy::new(0xd000),
        FaultedRestoreTransport::fail_submit_once(source.provider.restore_transport(scope())),
    );
    assert!(matches!(
        coordinator
            .recover(&mut vault, source.phrase_words, &identity)
            .unwrap(),
        RecoveryRestoreOutcome::Submitting { .. }
    ));
    let wrong_keys = DeviceKeys::from_seeds_for_test([0xb3; 32], [0xb4; 32]);
    assert_eq!(
        coordinator
            .resume_prepared(
                &mut vault,
                &RecoveryRestoreIdentity {
                    device_id: identity.device_id,
                    device_name: identity.device_name.clone(),
                    platform: identity.platform,
                    keys: &wrong_keys,
                },
            )
            .unwrap_err(),
        RecoveryRestoreCycleError::Conflict
    );
    assert!(source.provider.test_safe_restore_captures().is_empty());
    drop(vault);

    let raw = open_keyed(path.path(), &key_store.key(CREDENTIAL));
    raw.execute(
        "UPDATE recovery_restores SET recovered_device_name = 'Tampered Name'",
        [],
    )
    .unwrap();
    drop(raw);
    let mut reopened = Vault::open(path.path(), CREDENTIAL, &key_store).unwrap();
    assert_eq!(
        coordinator
            .resume_prepared(&mut reopened, &identity)
            .unwrap_err(),
        RecoveryRestoreCycleError::Conflict
    );
    assert!(reopened.devices(scope()).unwrap().is_empty());
}

#[test]
fn active_restore_replays_offline_and_a_new_restore_reports_unavailable() {
    let source = enrolled_source("restore-offline-source");
    let saved_phrase = source.phrase_words.clone();
    let path = TempVault::new("restore-offline-target");
    let key_store = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &key_store).unwrap();
    let recovered_keys = DeviceKeys::from_seeds_for_test([0xc1; 32], [0xc2; 32]);
    let identity = RecoveryRestoreIdentity {
        device_id: RECOVERED_DEVICE_ID.parse().unwrap(),
        device_name: "Recovered Offline".to_owned(),
        platform: NativePlatform::Macos,
        keys: &recovered_keys,
    };
    let (_, coordinator) = restore_coordinator(&source.provider, 80_000, 0xe000);
    let complete = coordinator
        .recover(&mut vault, source.phrase_words, &identity)
        .unwrap();
    assert!(matches!(complete, RecoveryRestoreOutcome::Complete { .. }));
    source.provider.test_delete_account(scope().account_id);
    drop(vault);

    let mut reopened = Vault::open(path.path(), CREDENTIAL, &key_store).unwrap();
    assert_eq!(
        coordinator
            .resume_prepared(&mut reopened, &identity)
            .unwrap(),
        complete
    );
    assert_eq!(
        reopened
            .trusted_workspace_material(&recovered_keys)
            .unwrap()
            .workspace_root_key(),
        &source.workspace_root_key
    );

    let fresh_path = TempVault::new("restore-offline-fresh-target");
    let fresh_store = MemoryKeyStore::default();
    let mut fresh = Vault::open(fresh_path.path(), "restore-offline-fresh", &fresh_store).unwrap();
    let fresh_keys = DeviceKeys::from_seeds_for_test([0xc3; 32], [0xc4; 32]);
    assert_eq!(
        coordinator
            .recover(
                &mut fresh,
                saved_phrase,
                &RecoveryRestoreIdentity {
                    device_id: RACING_DEVICE_ID.parse().unwrap(),
                    device_name: "Too Late".to_owned(),
                    platform: NativePlatform::Macos,
                    keys: &fresh_keys,
                },
            )
            .unwrap_err(),
        RecoveryRestoreCycleError::Unavailable
    );
    assert!(fresh.recovery_restore().unwrap().is_none());
}

#[test]
fn terminal_restore_surfaces_and_storage_do_not_expose_phrase_or_key_canaries() {
    let source = enrolled_source("restore-canary-source");
    let phrase_words = source.phrase_words.clone();
    let phrase_sentence = phrase_words.as_words().join(" ");
    let recovery_canaries = recovery_secret_canaries(&phrase_words);
    let path = TempVault::new("restore-canary-target");
    let key_store = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &key_store).unwrap();
    let recovered_keys = DeviceKeys::from_seeds_for_test([0xd1; 32], [0xd2; 32]);
    let identity = RecoveryRestoreIdentity {
        device_id: RECOVERED_DEVICE_ID.parse().unwrap(),
        device_name: "Recovered Canary".to_owned(),
        platform: NativePlatform::Macos,
        keys: &recovered_keys,
    };
    let (_, coordinator) = restore_coordinator(&source.provider, 90_000, 0xf000);
    let outcome = coordinator
        .recover(&mut vault, source.phrase_words, &identity)
        .unwrap();
    let safe_text = format!(
        "{identity:?} {coordinator:?} {outcome:?} {:?} {:?}",
        RecoveryRestoreCycleError::Invalid,
        source.provider.test_safe_restore_captures()
    );
    assert!(!safe_text.contains(&phrase_sentence));
    for canary in [
        recovery_canaries[0],
        recovery_canaries[1],
        source.workspace_root_key,
        source.active_epoch_key,
        [0xd1; 32],
        [0xd2; 32],
    ] {
        let hex = canary
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert!(!safe_text.to_ascii_lowercase().contains(&hex));
        assert!(vault.test_plaintext_cells().unwrap().iter().all(|cell| {
            !cell
                .bytes
                .windows(canary.len())
                .any(|window| window == canary)
        }));
    }
    drop(vault);
    assert!(!file_set_contains(path.path(), phrase_sentence.as_bytes()));
    for canary in [
        recovery_canaries[0],
        recovery_canaries[1],
        source.workspace_root_key,
        source.active_epoch_key,
        [0xd1; 32],
        [0xd2; 32],
    ] {
        assert!(!file_set_contains(path.path(), &canary));
    }
}

#[test]
fn recovered_device_approves_a_third_vault_and_all_material_reopens() {
    let source = enrolled_source("restore-third-pairing-source");
    let recovered_path = TempVault::new("restore-third-pairing-recovered");
    let third_path = TempVault::new("restore-third-pairing-third");
    let recovered_store = MemoryKeyStore::default();
    let third_store = MemoryKeyStore::default();
    let mut recovered_vault = Vault::open(
        recovered_path.path(),
        "restore-third-recovered",
        &recovered_store,
    )
    .unwrap();
    let recovered_keys = DeviceKeys::from_seeds_for_test([0xe1; 32], [0xe2; 32]);
    let recovered_identity = RecoveryRestoreIdentity {
        device_id: RECOVERED_DEVICE_ID.parse().unwrap(),
        device_name: "Recovered Authority".to_owned(),
        platform: NativePlatform::Macos,
        keys: &recovered_keys,
    };
    let (_, restore) = restore_coordinator(&source.provider, 100_000, 0x1_0000);
    assert!(matches!(
        restore
            .recover(
                &mut recovered_vault,
                source.phrase_words,
                &recovered_identity,
            )
            .unwrap(),
        RecoveryRestoreOutcome::Complete { .. }
    ));
    let stored_restore = recovered_vault.recovery_restore().unwrap().unwrap();
    let genesis_certificate_id = stored_restore.record.genesis_certificate_id;
    let recovered_certificate_id = stored_restore.claim.certificate_id;

    let pairing_provider = InMemoryPairingProvider::with_test_entropy(
        [0xf1; 32],
        (1_u8..=16)
            .map(|value| [value.wrapping_add(0x40); 32])
            .collect(),
    );
    let pairing_clock = FixedClock::default();
    pairing_clock.set(101_000);
    let pairing = PairingCoordinator::new(
        pairing_clock.clone(),
        VaultPairingMaterialSource,
        pairing_provider
            .join_session_client("recovery-third-device-session")
            .unwrap(),
        pairing_provider.existing_device_client(scope(), recovered_identity.device_id),
    );
    let mut third_vault =
        Vault::open(third_path.path(), "restore-third-device", &third_store).unwrap();
    let third_keys = DeviceKeys::from_seeds_for_test([0xe3; 32], [0xe4; 32]);
    let invite = pairing.create_invite().unwrap();
    pairing_clock.set(101_001);
    let submission = pairing
        .join(
            &mut third_vault,
            &invite.code,
            THIRD_DEVICE_ID.parse().unwrap(),
            "Third Mac",
            NativePlatform::Macos,
            &third_keys,
        )
        .unwrap();
    pairing_clock.set(101_002);
    let review = pairing.request_status(invite.pairing_id).unwrap().unwrap();
    let decision = pairing
        .decide(
            &mut recovered_vault,
            invite.pairing_id,
            review.request_digest,
            PairingDecisionInput::Approve(PairingApprovalAuthority {
                certificate_id: THIRD_CERTIFICATE_ID.parse::<DeviceCertificateId>().unwrap(),
                issuer_certificate_id: recovered_certificate_id,
                issuer_keys: &recovered_keys,
            }),
        )
        .unwrap();
    let PairingDecisionStatus::Approved { safety_number } = decision else {
        unreachable!()
    };
    pairing_clock.set(101_003);
    assert!(matches!(
        pairing
            .join_status(&mut third_vault, submission.pairing_id)
            .unwrap(),
        PairingJoinStatus::AwaitingConfirmation { .. }
    ));
    pairing_clock.set(101_004);
    let third_material = pairing
        .confirm_join(
            &mut third_vault,
            submission.pairing_id,
            safety_number.as_str(),
            &third_keys,
        )
        .unwrap();
    let recovered_material = recovered_vault
        .trusted_workspace_material(&recovered_keys)
        .unwrap();
    assert_eq!(third_material.scope(), scope());
    assert_eq!(third_material.control_epoch(), 1);
    assert_eq!(third_material.key_epoch(), 1);
    assert_eq!(
        third_material.workspace_root_key(),
        &source.workspace_root_key
    );
    assert_eq!(third_material.active_epoch_key(), &source.active_epoch_key);
    assert_eq!(
        recovered_material.workspace_root_key(),
        third_material.workspace_root_key()
    );
    assert_eq!(
        recovered_material.active_epoch_key(),
        third_material.active_epoch_key()
    );
    assert_eq!(recovered_vault.devices(scope()).unwrap().len(), 3);
    assert_eq!(third_vault.devices(scope()).unwrap().len(), 2);
    for certificate_id in [
        genesis_certificate_id,
        recovered_certificate_id,
        THIRD_CERTIFICATE_ID.parse().unwrap(),
    ] {
        assert!(
            recovered_vault
                .device_certificate(certificate_id)
                .unwrap()
                .is_some()
        );
    }
    assert!(
        third_vault
            .device_certificate(genesis_certificate_id)
            .unwrap()
            .is_none()
    );
    assert!(
        third_vault
            .device_certificate(recovered_certificate_id)
            .unwrap()
            .is_some()
    );
    drop(recovered_vault);
    drop(third_vault);

    let reopened_recovered = Vault::open(
        recovered_path.path(),
        "restore-third-recovered",
        &recovered_store,
    )
    .unwrap();
    let reopened_third =
        Vault::open(third_path.path(), "restore-third-device", &third_store).unwrap();
    let reopened_recovered_material = reopened_recovered
        .trusted_workspace_material(&recovered_keys)
        .unwrap();
    let reopened_third_material = pairing
        .completed_material(&reopened_third, submission.pairing_id, &third_keys)
        .unwrap()
        .unwrap();
    assert_eq!(
        reopened_recovered_material.workspace_root_key(),
        reopened_third_material.workspace_root_key()
    );
    assert_eq!(
        reopened_recovered_material.active_epoch_key(),
        reopened_third_material.active_epoch_key()
    );
    assert_eq!(reopened_recovered.devices(scope()).unwrap().len(), 3);
    assert_eq!(reopened_third.devices(scope()).unwrap().len(), 2);
}
