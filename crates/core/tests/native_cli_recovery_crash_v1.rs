mod support;

use std::{cell::RefCell, rc::Rc};

use context_relay_core::{
    native_transaction::{
        NativeApplyReceipt, NativeReceiptEntry, OwnershipChange, TransactionStep,
        engine::BoundaryError,
        recovery::{
            CliRecoveryRestore, NativeCliRecoveryIo, NativeRecoveryIo, RecoveryAction,
            RecoveryCleanup, RecoveryFaultHook, RecoveryFaultPoint, RecoveryMoment,
            RecoveryOutcome, RecoveryProbe, RecoveryRestore, RecoverySandboxIdentity,
            recover_native_transactions_with_cli, recover_native_transactions_with_cli_and_faults,
        },
    },
    vault::{
        NativeCliWalRecord, NativeCliWalState, NativeCliWalWrite, NativePlanWrite,
        NativeSandboxIdentity, NativeTransactionStatus, Vault,
    },
};
use context_relay_protocol::{ApplyReceipt, HarnessId, PlanId, Sha256Digest};
use sha2::{Digest as _, Sha256};

use support::{ID_1, ID_2, MemoryKeyStore, TempVault, clock};

const CREDENTIAL: &str = "native-cli-recovery-crash-v1";
const TRANSACTION_ID: &str = "native-cli-recovery-crash-transaction";
const PLAN_PAYLOAD: &[u8] = b"sealed-native-cli-crash-plan";
const EXPECTED: &[u8] = b"expected";
const INTENDED: &[u8] = b"intended";

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest([byte; 32])
}

fn fingerprint(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest(Sha256::digest(bytes).into())
}

fn fixture(name: &str, state: NativeCliWalState) -> (TempVault, MemoryKeyStore, Vault) {
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
            NativeSandboxIdentity::Windows {
                moniker: "context-relay.native.1123456789abcdef0123456789abcdef".to_owned(),
                sid: b"S-1-15-2-3872518810-2985098273-1912316193-2655983105-1250049442-371239648-1157085541".to_vec(),
            },
        )
        .unwrap();
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
                forward_operations: b"[1]",
                rollback_operations: b"[2]",
            },
        )
        .unwrap();
    match state {
        NativeCliWalState::Prepared => {}
        NativeCliWalState::Applied => vault
            .transition_native_cli_wal(TRANSACTION_ID, 0, NativeCliWalState::Applied)
            .unwrap(),
        NativeCliWalState::RestorePrepared => {
            vault
                .transition_native_cli_wal(TRANSACTION_ID, 0, NativeCliWalState::Applied)
                .unwrap();
            vault
                .transition_native_cli_wal(TRANSACTION_ID, 0, NativeCliWalState::RestorePrepared)
                .unwrap();
        }
        NativeCliWalState::Restored | NativeCliWalState::Conflict => unreachable!(),
    }
    (path, keys, vault)
}

#[derive(Default)]
struct NativeIo;

impl NativeRecoveryIo for NativeIo {
    #[allow(clippy::too_many_arguments)]
    fn probe(
        &mut self,
        _transaction_nonce: &[u8; 16],
        _target: &context_relay_protocol::WireNativeValue,
        _object_token: &context_relay_core::native_transaction::NativeObjectToken,
        _applied_object_token: Option<&context_relay_core::native_transaction::NativeObjectToken>,
        _restored_object_token: Option<&context_relay_core::native_transaction::NativeObjectToken>,
        _state: context_relay_core::vault::NativeWalState,
        expected_before: &context_relay_core::native_transaction::RestorableStateFingerprint,
        _expected_applied: &context_relay_core::native_transaction::RestorableStateFingerprint,
        _intended_restored: &context_relay_core::native_transaction::RestorableStateFingerprint,
    ) -> Result<RecoveryProbe, BoundaryError> {
        Ok(RecoveryProbe::Fingerprint(expected_before.clone()))
    }

    #[allow(clippy::too_many_arguments)]
    fn restore_if_matches(
        &mut self,
        _transaction_nonce: &[u8; 16],
        _target: &context_relay_protocol::WireNativeValue,
        _object_token: &context_relay_core::native_transaction::NativeObjectToken,
        _applied_object_token: Option<&context_relay_core::native_transaction::NativeObjectToken>,
        _expected_applied: &context_relay_core::native_transaction::RestorableStateFingerprint,
        _intended_restored: &context_relay_core::native_transaction::RestorableStateFingerprint,
        _before_image: &[u8],
        _persist_restored_candidate: &mut dyn FnMut(
            &context_relay_core::native_transaction::NativeObjectToken,
        ) -> Result<(), BoundaryError>,
    ) -> Result<RecoveryRestore, BoundaryError> {
        Ok(RecoveryRestore::Restored)
    }

    fn cleanup_sandbox(
        &mut self,
        _identity: &RecoverySandboxIdentity,
        _outcome: RecoveryOutcome,
    ) -> Result<RecoveryCleanup, BoundaryError> {
        Ok(RecoveryCleanup::Cleaned)
    }

    fn cleanup_committed_mutation(
        &mut self,
        _transaction_nonce: &[u8; 16],
        _target: &context_relay_protocol::WireNativeValue,
        _object_token: &context_relay_core::native_transaction::NativeObjectToken,
        _expected_before: &context_relay_core::native_transaction::RestorableStateFingerprint,
        _removed_parent_entries: u64,
    ) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn rebind_applied_absence(
        &mut self,
        _target: &context_relay_protocol::WireNativeValue,
        _object_token: &context_relay_core::native_transaction::NativeObjectToken,
        _expected_old_token: &context_relay_core::native_transaction::NativeObjectToken,
        _expected_applied: &context_relay_core::native_transaction::RestorableStateFingerprint,
    ) -> Result<Option<context_relay_core::native_transaction::NativeObjectToken>, BoundaryError>
    {
        Ok(None)
    }
}

struct CliIo {
    live: Option<Sha256Digest>,
    restores: usize,
    committed_finishes: usize,
}

impl NativeCliRecoveryIo for CliIo {
    fn probe_cli_declaration(
        &mut self,
        payload: &[u8],
        _wal: &NativeCliWalRecord,
    ) -> Result<Option<Sha256Digest>, BoundaryError> {
        assert_eq!(payload, PLAN_PAYLOAD);
        Ok(self.live)
    }

    fn restore_cli_mutation_if_matches(
        &mut self,
        payload: &[u8],
        wal: &NativeCliWalRecord,
    ) -> Result<CliRecoveryRestore, BoundaryError> {
        assert_eq!(payload, PLAN_PAYLOAD);
        if self.live != wal.intended_fingerprint {
            return Ok(CliRecoveryRestore::Conflict);
        }
        self.restores += 1;
        self.live = wal.expected_fingerprint;
        Ok(CliRecoveryRestore::Restored)
    }

    fn finish_committed_cli_mutations(
        &mut self,
        payload: &[u8],
        _wal: &[NativeCliWalRecord],
    ) -> Result<(), BoundaryError> {
        assert_eq!(payload, PLAN_PAYLOAD);
        self.committed_finishes += 1;
        Ok(())
    }
}

struct FailOnce {
    point: RecoveryFaultPoint,
    failed: Rc<RefCell<bool>>,
}

impl RecoveryFaultHook for FailOnce {
    fn at(&mut self, point: &RecoveryFaultPoint) -> Result<(), BoundaryError> {
        if point == &self.point && !*self.failed.borrow() {
            *self.failed.borrow_mut() = true;
            return Err(BoundaryError::new("injected CLI recovery crash"));
        }
        Ok(())
    }
}

#[test]
fn forward_command_crash_boundaries_recover_deterministically() {
    for (name, wal_state, live, expected_restores) in [
        (
            "cli-before-command",
            NativeCliWalState::Prepared,
            fingerprint(EXPECTED),
            0,
        ),
        (
            "cli-after-command",
            NativeCliWalState::Prepared,
            fingerprint(INTENDED),
            1,
        ),
        (
            "cli-after-applied-checkpoint",
            NativeCliWalState::Applied,
            fingerprint(INTENDED),
            1,
        ),
    ] {
        let (_path, _keys, mut vault) = fixture(name, wal_state);
        let mut native = NativeIo;
        let mut cli = CliIo {
            live: Some(live),
            restores: 0,
            committed_finishes: 0,
        };

        let summary =
            recover_native_transactions_with_cli(&mut vault, &mut native, &mut cli).unwrap();

        assert_eq!(summary.restored, 1, "{name}");
        assert_eq!(cli.restores, expected_restores, "{name}");
        assert_eq!(cli.live, Some(fingerprint(EXPECTED)), "{name}");
    }
}

#[test]
fn crash_before_restore_retries_from_restore_prepared() {
    let (_path, _keys, mut vault) = fixture("cli-crash-before-restore", NativeCliWalState::Applied);
    let mut native = NativeIo;
    let mut cli = CliIo {
        live: Some(fingerprint(INTENDED)),
        restores: 0,
        committed_finishes: 0,
    };
    let failed = Rc::new(RefCell::new(false));
    let mut fault = FailOnce {
        point: RecoveryFaultPoint {
            action: RecoveryAction::RestoreCliMutation,
            moment: RecoveryMoment::Before,
            target_sequence: Some(0),
        },
        failed,
    };

    assert!(
        recover_native_transactions_with_cli_and_faults(
            &mut vault,
            &mut native,
            &mut cli,
            &mut fault,
        )
        .is_err()
    );
    assert_eq!(
        vault.native_cli_wal(TRANSACTION_ID).unwrap()[0].state,
        NativeCliWalState::RestorePrepared
    );

    recover_native_transactions_with_cli(&mut vault, &mut native, &mut cli).unwrap();
    assert_eq!(cli.restores, 1);
    assert_eq!(cli.live, Some(fingerprint(EXPECTED)));
}

#[test]
fn crash_after_restore_before_checkpoint_does_not_restore_twice() {
    let (_path, _keys, mut vault) = fixture(
        "cli-crash-after-restore",
        NativeCliWalState::RestorePrepared,
    );
    let mut native = NativeIo;
    let mut cli = CliIo {
        live: Some(fingerprint(INTENDED)),
        restores: 0,
        committed_finishes: 0,
    };
    let mut fault = FailOnce {
        point: RecoveryFaultPoint {
            action: RecoveryAction::RestoreCliMutation,
            moment: RecoveryMoment::After,
            target_sequence: Some(0),
        },
        failed: Rc::new(RefCell::new(false)),
    };

    assert!(
        recover_native_transactions_with_cli_and_faults(
            &mut vault,
            &mut native,
            &mut cli,
            &mut fault,
        )
        .is_err()
    );
    assert_eq!(cli.restores, 1);
    assert_eq!(cli.live, Some(fingerprint(EXPECTED)));
    assert_eq!(
        vault.native_cli_wal(TRANSACTION_ID).unwrap()[0].state,
        NativeCliWalState::RestorePrepared
    );

    recover_native_transactions_with_cli(&mut vault, &mut native, &mut cli).unwrap();
    assert_eq!(cli.restores, 1);
}

fn commit(vault: &mut Vault) {
    for step in &TransactionStep::ORDER[..18] {
        vault.enter_native_step(TRANSACTION_ID, *step).unwrap();
        vault.complete_native_step(TRANSACTION_ID, *step).unwrap();
    }
    vault
        .enter_native_step(TRANSACTION_ID, TransactionStep::CommitOwnershipAndReceipt)
        .unwrap();
    vault
        .commit_native_success(
            TRANSACTION_ID,
            &NativeApplyReceipt {
                legacy: ApplyReceipt {
                    plan_id: ID_1.parse().unwrap(),
                    applied_hlc: clock(20),
                    resulting_digests: vec![],
                },
                targets: Vec::<NativeReceiptEntry>::new(),
            },
            &[OwnershipChange {
                stable_id: "cli:context-relay".to_owned(),
                structural_location: "cli/context-relay".to_owned(),
                semantic_digest: digest(7),
                native_digest: digest(8),
            }],
        )
        .unwrap();
}

#[test]
fn committed_cli_cleanup_is_retried_before_native_cleanup() {
    let (_path, _keys, mut vault) = fixture("cli-committed-cleanup", NativeCliWalState::Applied);
    commit(&mut vault);
    let mut native = NativeIo;
    let mut cli = CliIo {
        live: Some(fingerprint(INTENDED)),
        restores: 0,
        committed_finishes: 0,
    };
    let mut fault = FailOnce {
        point: RecoveryFaultPoint {
            action: RecoveryAction::CleanupCommittedCliMutations,
            moment: RecoveryMoment::After,
            target_sequence: None,
        },
        failed: Rc::new(RefCell::new(false)),
    };

    assert!(
        recover_native_transactions_with_cli_and_faults(
            &mut vault,
            &mut native,
            &mut cli,
            &mut fault,
        )
        .is_err()
    );
    assert_eq!(cli.committed_finishes, 1);
    assert_eq!(
        vault
            .native_transaction(TRANSACTION_ID)
            .unwrap()
            .unwrap()
            .current_step,
        19
    );

    let summary = recover_native_transactions_with_cli(&mut vault, &mut native, &mut cli).unwrap();
    assert_eq!(summary.committed, 1);
    assert_eq!(cli.committed_finishes, 2);
    assert!(vault.native_cli_wal(TRANSACTION_ID).unwrap().is_empty());
    let transaction = vault.native_transaction(TRANSACTION_ID).unwrap().unwrap();
    assert_eq!(transaction.status, NativeTransactionStatus::Committed);
    assert_eq!(transaction.current_step, 20);
}
