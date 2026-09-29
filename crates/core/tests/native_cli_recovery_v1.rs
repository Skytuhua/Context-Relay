mod support;

use std::{cell::RefCell, rc::Rc};

use context_relay_core::{
    native_transaction::{
        NativeObjectToken, RestorableStateFingerprint,
        engine::BoundaryError,
        recovery::{
            CliRecoveryRestore, NativeCliRecoveryIo, NativeRecoveryIo, RecoveryCleanup,
            RecoveryOutcome, RecoveryProbe, RecoveryRestore, RecoverySandboxIdentity,
            recover_native_transactions, recover_native_transactions_with_cli,
        },
    },
    vault::{
        NativeCliWalRecord, NativeCliWalState, NativeCliWalWrite, NativePlanWrite,
        NativeSandboxIdentity, NativeTransactionStatus, NativeWalState, Vault,
    },
};
use context_relay_protocol::{HarnessId, PlanId, Sha256Digest, WireNativeValue};
use sha2::{Digest as _, Sha256};

use support::{ID_1, ID_2, MemoryKeyStore, TempVault};

const CREDENTIAL: &str = "native-cli-recovery-v1";
const TRANSACTION_ID: &str = "native-cli-recovery-transaction";
const PLAN_PAYLOAD: &[u8] = b"sealed-native-cli-plan";
const EXPECTED: &[u8] = br#"{"command":"/old","args":[]}"#;
const INTENDED: &[u8] = br#"{"command":"/bridge","args":["--harness","codex"]}"#;

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest([byte; 32])
}

fn fingerprint(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest(Sha256::digest(bytes).into())
}

fn identity() -> NativeSandboxIdentity {
    NativeSandboxIdentity::Windows {
        moniker: "context-relay.native.0123456789abcdef0123456789abcdef".to_owned(),
        sid:
            b"S-1-15-2-3872518810-2985098273-1912316193-2655983105-1250049442-371239648-1157085541"
                .to_vec(),
    }
}

fn open_transaction(name: &str) -> (TempVault, MemoryKeyStore, Vault) {
    let path = TempVault::new(name);
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let plan_id = ID_1.parse::<PlanId>().unwrap();
    vault
        .begin_native_transaction(
            TRANSACTION_ID,
            NativePlanWrite {
                plan_id: &plan_id,
                approval_hash: &digest(9),
                payload: PLAN_PAYLOAD,
                created_ms: 10,
                expires_ms: 20,
            },
            identity(),
        )
        .unwrap();
    (path, keys, vault)
}

fn prepare_cli(vault: &mut Vault) {
    vault
        .prepare_native_cli_wal(
            TRANSACTION_ID,
            &NativeCliWalWrite {
                sequence: 0,
                stable_id: ID_2,
                harness: HarnessId::Codex,
                server_name: "context-relay",
                expected_declaration: Some(EXPECTED),
                expected_fingerprint: Some(&fingerprint(EXPECTED)),
                intended_declaration: Some(INTENDED),
                intended_fingerprint: Some(&fingerprint(INTENDED)),
                forward_operations: br#"[{"op":"add"}]"#,
                rollback_operations: br#"[{"op":"restore"}]"#,
            },
        )
        .unwrap();
}

#[derive(Default)]
struct NativeIo {
    events: Rc<RefCell<Vec<String>>>,
}

impl NativeRecoveryIo for NativeIo {
    #[allow(clippy::too_many_arguments)]
    fn probe(
        &mut self,
        _transaction_nonce: &[u8; 16],
        _target: &WireNativeValue,
        _object_token: &NativeObjectToken,
        _applied_object_token: Option<&NativeObjectToken>,
        _restored_object_token: Option<&NativeObjectToken>,
        _state: NativeWalState,
        expected_before: &RestorableStateFingerprint,
        _expected_applied: &RestorableStateFingerprint,
        _intended_restored: &RestorableStateFingerprint,
    ) -> Result<RecoveryProbe, BoundaryError> {
        self.events.borrow_mut().push("native:probe".to_owned());
        Ok(RecoveryProbe::Fingerprint(expected_before.clone()))
    }

    #[allow(clippy::too_many_arguments)]
    fn restore_if_matches(
        &mut self,
        _transaction_nonce: &[u8; 16],
        _target: &WireNativeValue,
        _object_token: &NativeObjectToken,
        _applied_object_token: Option<&NativeObjectToken>,
        _expected_applied: &RestorableStateFingerprint,
        _intended_restored: &RestorableStateFingerprint,
        _before_image: &[u8],
        _persist_restored_candidate: &mut dyn FnMut(
            &NativeObjectToken,
        ) -> Result<(), BoundaryError>,
    ) -> Result<RecoveryRestore, BoundaryError> {
        self.events.borrow_mut().push("native:restore".to_owned());
        Ok(RecoveryRestore::Restored)
    }

    fn cleanup_sandbox(
        &mut self,
        _identity: &RecoverySandboxIdentity,
        _outcome: RecoveryOutcome,
    ) -> Result<RecoveryCleanup, BoundaryError> {
        self.events.borrow_mut().push("native:sandbox".to_owned());
        Ok(RecoveryCleanup::Cleaned)
    }

    fn cleanup_committed_mutation(
        &mut self,
        _transaction_nonce: &[u8; 16],
        _target: &WireNativeValue,
        _object_token: &NativeObjectToken,
        _expected_before: &RestorableStateFingerprint,
        _removed_parent_entries: u64,
    ) -> Result<(), BoundaryError> {
        self.events.borrow_mut().push("native:committed".to_owned());
        Ok(())
    }

    fn rebind_applied_absence(
        &mut self,
        _target: &WireNativeValue,
        _object_token: &NativeObjectToken,
        _expected_old_token: &NativeObjectToken,
        _expected_applied: &RestorableStateFingerprint,
    ) -> Result<Option<NativeObjectToken>, BoundaryError> {
        Ok(None)
    }
}

struct CliIo {
    live: Option<Sha256Digest>,
    events: Rc<RefCell<Vec<String>>>,
    restores: usize,
}

impl NativeCliRecoveryIo for CliIo {
    fn probe_cli_declaration(
        &mut self,
        sealed_plan_payload: &[u8],
        wal: &NativeCliWalRecord,
    ) -> Result<Option<Sha256Digest>, BoundaryError> {
        assert_eq!(sealed_plan_payload, PLAN_PAYLOAD);
        self.events
            .borrow_mut()
            .push(format!("cli:probe:{}", wal.sequence));
        Ok(self.live)
    }

    fn restore_cli_mutation_if_matches(
        &mut self,
        sealed_plan_payload: &[u8],
        wal: &NativeCliWalRecord,
    ) -> Result<CliRecoveryRestore, BoundaryError> {
        assert_eq!(sealed_plan_payload, PLAN_PAYLOAD);
        self.events
            .borrow_mut()
            .push(format!("cli:restore:{}", wal.sequence));
        if self.live != wal.intended_fingerprint {
            return Ok(CliRecoveryRestore::Conflict);
        }
        self.restores += 1;
        self.live = wal.expected_fingerprint;
        Ok(CliRecoveryRestore::Restored)
    }

    fn finish_committed_cli_mutations(
        &mut self,
        sealed_plan_payload: &[u8],
        wal: &[NativeCliWalRecord],
    ) -> Result<(), BoundaryError> {
        assert_eq!(sealed_plan_payload, PLAN_PAYLOAD);
        self.events
            .borrow_mut()
            .push(format!("cli:committed:{}", wal.len()));
        Ok(())
    }
}

#[test]
fn prepared_expected_state_is_a_durable_no_write_restart() {
    let (_path, _keys, mut vault) = open_transaction("native-cli-no-write-recovery");
    prepare_cli(&mut vault);
    let events = Rc::new(RefCell::new(Vec::new()));
    let mut native = NativeIo {
        events: events.clone(),
    };
    let mut cli = CliIo {
        live: Some(fingerprint(EXPECTED)),
        events,
        restores: 0,
    };

    let summary = recover_native_transactions_with_cli(&mut vault, &mut native, &mut cli).unwrap();

    assert_eq!(summary.restored, 1);
    assert_eq!(cli.restores, 0);
    assert_eq!(
        vault
            .native_transaction(TRANSACTION_ID)
            .unwrap()
            .unwrap()
            .status,
        NativeTransactionStatus::Restored
    );
    assert_eq!(
        vault.native_cli_wal(TRANSACTION_ID).unwrap()[0].state,
        NativeCliWalState::Prepared
    );
}

#[test]
fn prepared_intended_state_is_checkpointed_then_restored() {
    let (_path, _keys, mut vault) = open_transaction("native-cli-intended-recovery");
    prepare_cli(&mut vault);
    let events = Rc::new(RefCell::new(Vec::new()));
    let mut native = NativeIo {
        events: events.clone(),
    };
    let mut cli = CliIo {
        live: Some(fingerprint(INTENDED)),
        events,
        restores: 0,
    };

    let summary = recover_native_transactions_with_cli(&mut vault, &mut native, &mut cli).unwrap();

    assert_eq!(summary.restored, 1);
    assert_eq!(cli.restores, 1);
    assert_eq!(cli.live, Some(fingerprint(EXPECTED)));
    assert!(vault.native_cli_wal(TRANSACTION_ID).unwrap().is_empty());
}

#[test]
fn cli_recovery_runs_before_native_recovery() {
    let (_path, _keys, mut vault) = open_transaction("native-cli-before-native-recovery");
    prepare_cli(&mut vault);
    let target = WireNativeValue {
        platform: context_relay_protocol::NativePlatform::Macos,
        bytes: b"/fixture/native".to_vec(),
        display: None,
    };
    let before = RestorableStateFingerprint(digest(3));
    vault
        .put_before_images_batch(
            &[context_relay_core::vault::BeforeImageWrite {
                id: "before-native",
                plan_id: Some(&ID_1.parse().unwrap()),
                payload: b"before",
                created_ms: 10,
            }],
            context_relay_core::vault::BeforeImagePolicy::new(1024, 20),
        )
        .unwrap();
    vault
        .prepare_native_wal(
            TRANSACTION_ID,
            &context_relay_core::vault::NativeWalWrite {
                target_sequence: 0,
                target: &target,
                object_token: &NativeObjectToken {
                    volume: vec![1],
                    object: vec![2],
                    topology: vec![3],
                },
                before_image_id: "before-native",
                operation_kind: context_relay_core::native_transaction::MutationKind::Payload,
                expected: &before,
                intended_applied: &RestorableStateFingerprint(digest(4)),
                intended_restored: &before,
            },
        )
        .unwrap();
    let events = Rc::new(RefCell::new(Vec::new()));
    let mut native = NativeIo {
        events: events.clone(),
    };
    let mut cli = CliIo {
        live: Some(fingerprint(EXPECTED)),
        events: events.clone(),
        restores: 0,
    };

    recover_native_transactions_with_cli(&mut vault, &mut native, &mut cli).unwrap();

    let events = events.borrow();
    let cli_probe = events
        .iter()
        .position(|event| event == "cli:probe:0")
        .unwrap();
    let native_probe = events
        .iter()
        .position(|event| event == "native:probe")
        .unwrap();
    assert!(cli_probe < native_probe);
}

#[test]
fn live_divergence_is_terminalized_without_restore_or_overwrite() {
    let (_path, _keys, mut vault) = open_transaction("native-cli-divergence-recovery");
    prepare_cli(&mut vault);
    vault
        .transition_native_cli_wal(TRANSACTION_ID, 0, NativeCliWalState::Applied)
        .unwrap();
    let events = Rc::new(RefCell::new(Vec::new()));
    let mut native = NativeIo {
        events: events.clone(),
    };
    let mut cli = CliIo {
        live: Some(digest(99)),
        events,
        restores: 0,
    };

    let summary = recover_native_transactions_with_cli(&mut vault, &mut native, &mut cli).unwrap();

    assert_eq!(summary.conflicts, 1);
    assert_eq!(cli.restores, 0);
    assert_eq!(cli.live, Some(digest(99)));
    assert_eq!(
        vault.native_cli_wal(TRANSACTION_ID).unwrap()[0].state,
        NativeCliWalState::Conflict
    );
    let transaction = vault.native_transaction(TRANSACTION_ID).unwrap().unwrap();
    assert_eq!(transaction.status, NativeTransactionStatus::Conflict);
    assert_eq!(transaction.current_step, 20);
}

#[test]
fn legacy_noop_recovery_fails_closed_when_cli_wal_is_nonempty() {
    let (_path, _keys, mut vault) = open_transaction("native-cli-noop-recovery");
    prepare_cli(&mut vault);
    let mut native = NativeIo::default();

    let error = recover_native_transactions(&mut vault, &mut native).unwrap_err();

    assert!(error.to_string().contains("CLI recovery I/O"));
    assert_eq!(
        vault.native_cli_wal(TRANSACTION_ID).unwrap()[0].state,
        NativeCliWalState::Prepared
    );
}
