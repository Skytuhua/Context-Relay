use context_relay_core::native_transaction::{MutationKind, NativeObjectToken};
use context_relay_core::native_transaction::{
    engine::BoundaryError,
    model::{MutationWalState, RestorableStateFingerprint},
    recovery::{
        NativeRecoveryIo, OsNativeRecoveryIo, RecoveryCleanup, RecoveryDecision, RecoveryMutation,
        RecoveryOutcome, RecoveryProbe, RecoveryRestore, RecoverySandboxIdentity,
        TransactionCommitState, classify_recovery, recover_native_transactions,
    },
};
use context_relay_core::vault::{
    BeforeImagePolicy, BeforeImageWrite, MacGenerationState, MacGenerationSubstate,
    NativePlanWrite, NativeSandboxIdentity, NativeWalState, NativeWalWrite, Vault,
};
use context_relay_native_runner::{MacRootIdentity, NativeState, OsNativeFileSystem};
use context_relay_protocol::{PlanId, Sha256Digest};

mod support;

use support::{ID_1, ID_2, MemoryKeyStore, TempVault, native_path};

const CREDENTIAL: &str = "task-9-native-recovery";

fn fp(byte: u8) -> RestorableStateFingerprint {
    RestorableStateFingerprint(Sha256Digest([byte; 32]))
}

fn mac_root(byte: u8) -> Vec<u8> {
    MacRootIdentity::new(
        u64::from(byte) + 1,
        u64::from(byte) + 2,
        u32::from(byte) + 3,
        i64::from(byte) + 4,
        u32::from(byte) + 5,
        0o040700,
    )
    .unwrap()
    .encode()
}

fn activate_macos(vault: &mut Vault, transaction_id: &str) {
    vault.bind_macos_guardian(transaction_id, 4242).unwrap();
    vault
        .bind_macos_bundle_root(transaction_id, &mac_root(1))
        .unwrap();
    vault
        .finalize_macos_generation(transaction_id, &Sha256Digest([2; 32]))
        .unwrap();
    vault
        .bind_macos_container_root(transaction_id, &mac_root(3))
        .unwrap();
    vault
        .transition_macos_generation(transaction_id, MacGenerationState::Active)
        .unwrap();
}

fn journal_token(token: &context_relay_native_runner::NativeObjectToken) -> NativeObjectToken {
    let mut topology = Vec::with_capacity(29);
    topology.push(1);
    topology.extend_from_slice(&token.reparse_tag().to_le_bytes());
    topology.extend_from_slice(&token.parent_volume().to_le_bytes());
    topology.extend_from_slice(token.parent_object());
    NativeObjectToken {
        volume: token.volume().to_le_bytes().to_vec(),
        object: token.object().to_vec(),
        topology,
    }
}

fn record(state: MutationWalState) -> RecoveryMutation {
    RecoveryMutation {
        state,
        before: fp(1),
        applied: fp(2),
        restored: fp(3),
    }
}

#[test]
fn committed_transactions_finalize_and_never_restore() {
    for current in [fp(1), fp(2), fp(3), fp(99)] {
        assert_eq!(
            classify_recovery(
                &record(MutationWalState::Applied),
                &current,
                TransactionCommitState::Committed,
            ),
            RecoveryDecision::FinalizeCommitted
        );
    }
}

#[test]
fn precommit_recovery_restores_only_the_exact_applied_state() {
    assert_eq!(
        classify_recovery(
            &record(MutationWalState::Applied),
            &fp(2),
            TransactionCommitState::PreCommit,
        ),
        RecoveryDecision::PrepareRestore
    );
    assert_eq!(
        classify_recovery(
            &record(MutationWalState::Applied),
            &fp(99),
            TransactionCommitState::PreCommit,
        ),
        RecoveryDecision::MarkConflict
    );
}

#[test]
fn never_applied_and_already_restored_states_are_idempotent() {
    assert_eq!(
        classify_recovery(
            &record(MutationWalState::Prepared),
            &fp(1),
            TransactionCommitState::PreCommit,
        ),
        RecoveryDecision::MarkRestored
    );
    assert_eq!(
        classify_recovery(
            &record(MutationWalState::Prepared),
            &fp(2),
            TransactionCommitState::PreCommit,
        ),
        RecoveryDecision::MarkConflict
    );
    assert_eq!(
        classify_recovery(
            &record(MutationWalState::RestorePrepared),
            &fp(3),
            TransactionCommitState::PreCommit,
        ),
        RecoveryDecision::MarkRestored
    );
    assert_eq!(
        classify_recovery(
            &record(MutationWalState::Restored),
            &fp(3),
            TransactionCommitState::PreCommit,
        ),
        RecoveryDecision::AlreadyRestored
    );
    assert_eq!(
        classify_recovery(
            &record(MutationWalState::Conflict),
            &fp(2),
            TransactionCommitState::PreCommit,
        ),
        RecoveryDecision::PreserveConflict
    );
}

#[test]
fn a_crash_after_restore_before_restored_durability_does_not_restore_twice() {
    let interrupted = record(MutationWalState::RestorePrepared);
    assert_eq!(
        classify_recovery(
            &interrupted,
            &interrupted.restored,
            TransactionCommitState::PreCommit,
        ),
        RecoveryDecision::MarkRestored
    );
}

#[derive(Default)]
struct RecoveryIo {
    current: Option<RestorableStateFingerprint>,
    probes: Vec<(RestorableStateFingerprint, RestorableStateFingerprint)>,
    nonces: Vec<[u8; 16]>,
    restores: usize,
    cleanups: Vec<RecoveryOutcome>,
    identities: Vec<RecoverySandboxIdentity>,
}

impl NativeRecoveryIo for RecoveryIo {
    #[allow(clippy::too_many_arguments)]
    fn probe(
        &mut self,
        transaction_nonce: &[u8; 16],
        _target: &context_relay_protocol::WireNativeValue,
        _object_token: &NativeObjectToken,
        _applied_object_token: Option<&NativeObjectToken>,
        _restored_object_token: Option<&NativeObjectToken>,
        _state: MutationWalState,
        expected_before: &RestorableStateFingerprint,
        expected_applied: &RestorableStateFingerprint,
        _intended_restored: &RestorableStateFingerprint,
    ) -> Result<RecoveryProbe, BoundaryError> {
        self.nonces.push(*transaction_nonce);
        self.probes
            .push((expected_before.clone(), expected_applied.clone()));
        self.current
            .clone()
            .map(RecoveryProbe::Fingerprint)
            .ok_or_else(|| BoundaryError::new("missing fixture state"))
    }

    #[allow(clippy::too_many_arguments)]
    fn restore_if_matches(
        &mut self,
        transaction_nonce: &[u8; 16],
        _target: &context_relay_protocol::WireNativeValue,
        _object_token: &NativeObjectToken,
        _applied_object_token: Option<&NativeObjectToken>,
        expected_applied: &RestorableStateFingerprint,
        intended_restored: &RestorableStateFingerprint,
        before_image: &[u8],
        persist_restored_candidate: &mut dyn FnMut(&NativeObjectToken) -> Result<(), BoundaryError>,
    ) -> Result<RecoveryRestore, BoundaryError> {
        self.nonces.push(*transaction_nonce);
        assert_eq!(before_image, b"before-state");
        if self.current.as_ref() != Some(expected_applied) {
            return Ok(RecoveryRestore::Conflict);
        }
        persist_restored_candidate(&NativeObjectToken {
            volume: vec![7],
            object: vec![8],
            topology: vec![9],
        })?;
        self.restores += 1;
        self.current = Some(intended_restored.clone());
        Ok(RecoveryRestore::Restored)
    }

    fn cleanup_sandbox(
        &mut self,
        identity: &RecoverySandboxIdentity,
        outcome: RecoveryOutcome,
    ) -> Result<RecoveryCleanup, BoundaryError> {
        self.identities.push(identity.clone());
        self.cleanups.push(outcome);
        Ok(RecoveryCleanup::Cleaned)
    }

    fn cleanup_committed_mutation(
        &mut self,
        _transaction_nonce: &[u8; 16],
        _target: &context_relay_protocol::WireNativeValue,
        _object_token: &NativeObjectToken,
        _expected_before: &RestorableStateFingerprint,
        _removed_parent_entries: u64,
    ) -> Result<(), BoundaryError> {
        Ok(())
    }

    fn rebind_applied_absence(
        &mut self,
        _target: &context_relay_protocol::WireNativeValue,
        _object_token: &NativeObjectToken,
        _expected_old_token: &NativeObjectToken,
        _expected_applied: &RestorableStateFingerprint,
    ) -> Result<Option<NativeObjectToken>, BoundaryError> {
        Ok(None)
    }
}

#[test]
fn never_applied_uses_the_stable_fingerprint_and_never_reuses_the_ephemeral_token() {
    let path = TempVault::new("native-never-applied");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let plan_id = ID_2.parse().unwrap();
    let approval = Sha256Digest([11; 32]);
    vault
        .begin_native_transaction(
            ID_1,
            NativePlanWrite {
                plan_id: &plan_id,
                approval_hash: &approval,
                payload: b"plan",
                created_ms: 1,
                expires_ms: 2,
            },
            NativeSandboxIdentity::Windows {
                moniker: "context-relay.native.00000000000000000000000000000003".to_owned(),
                sid: b"S-1-15-2-1-2-3-4-5-6-7".to_vec(),
            },
        )
        .unwrap();
    vault
        .put_before_images_batch(
            &[BeforeImageWrite {
                id: "before-0",
                plan_id: Some(&plan_id),
                payload: b"before-state",
                created_ms: 1,
            }],
            BeforeImagePolicy::new(1024, 100),
        )
        .unwrap();
    let target = native_path();
    let before = fp(1);
    let applied = fp(2);
    vault
        .prepare_native_wal(
            ID_1,
            &NativeWalWrite {
                target_sequence: 0,
                target: &target,
                object_token: &NativeObjectToken {
                    volume: b"ephemeral-volume".to_vec(),
                    object: b"ephemeral-object".to_vec(),
                    topology: b"ephemeral-topology".to_vec(),
                },
                before_image_id: "before-0",
                operation_kind: MutationKind::Payload,
                expected: &before,
                intended_applied: &applied,
                intended_restored: &before,
            },
        )
        .unwrap();
    let mut io = RecoveryIo {
        current: Some(before),
        ..RecoveryIo::default()
    };
    recover_native_transactions(&mut vault, &mut io).unwrap();
    assert_eq!(io.restores, 0);
    assert!(vault.native_wal(ID_1).unwrap().is_empty());
}

#[test]
fn leftover_active_macos_generation_is_durably_poisoned_before_cleanup() {
    let path = TempVault::new("native-active-macos");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let plan_id = ID_2.parse().unwrap();
    let approval = Sha256Digest([12; 32]);
    let generation = "0123456789abcdef0123456789abcdef";
    let bundle = format!("com.contextrelay.native-runner.{generation}");
    let mut container = b"context-relay/macos-container/v1\0".to_vec();
    container.extend_from_slice(bundle.as_bytes());
    vault
        .begin_native_transaction(
            ID_1,
            NativePlanWrite {
                plan_id: &plan_id,
                approval_hash: &approval,
                payload: b"plan",
                created_ms: 1,
                expires_ms: 2,
            },
            NativeSandboxIdentity::reserved_macos(
                generation.to_owned(),
                bundle.clone(),
                container.clone(),
            ),
        )
        .unwrap();
    activate_macos(&mut vault, ID_1);
    let mut io = RecoveryIo::default();
    recover_native_transactions(&mut vault, &mut io).unwrap();
    assert_eq!(
        io.identities,
        vec![RecoverySandboxIdentity::Macos {
            generation_id: generation.to_owned(),
            bundle_id: bundle,
            container,
            guardian_pgid: Some(4242),
            bundle_root: Some(mac_root(1)),
            signed_digest: Some(Sha256Digest([2; 32])),
            container_root: Some(mac_root(3)),
            substate: MacGenerationSubstate::ContainerBound,
            state: context_relay_core::vault::MacGenerationState::Poisoned,
        }],
    );
    assert_eq!(
        vault.native_transaction(ID_1).unwrap().unwrap().identity,
        NativeSandboxIdentity::Macos {
            generation_id: generation.to_owned(),
            bundle_id: "com.contextrelay.native-runner.0123456789abcdef0123456789abcdef".to_owned(),
            container: {
                let mut value = b"context-relay/macos-container/v1\0".to_vec();
                value.extend_from_slice(
                    b"com.contextrelay.native-runner.0123456789abcdef0123456789abcdef",
                );
                value
            },
            guardian_pgid: Some(4242),
            bundle_root: Some(mac_root(1)),
            signed_digest: Some(Sha256Digest([2; 32])),
            container_root: Some(mac_root(3)),
            substate: MacGenerationSubstate::ContainerBound,
            state: MacGenerationState::Poisoned,
        },
    );
}

#[test]
fn vault_recovery_durably_restores_only_the_exact_applied_state_and_is_idempotent() {
    let path = TempVault::new("native-recovery-loop");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let plan_id = ID_2.parse().unwrap();
    let approval = Sha256Digest([9; 32]);
    vault
        .begin_native_transaction(
            ID_1,
            NativePlanWrite {
                plan_id: &plan_id,
                approval_hash: &approval,
                payload: b"plan",
                created_ms: 1,
                expires_ms: 2,
            },
            NativeSandboxIdentity::Windows {
                moniker: "context-relay.native.00000000000000000000000000000001".to_owned(),
                sid: b"S-1-15-2-1-2-3-4-5-6-7".to_vec(),
            },
        )
        .unwrap();
    vault
        .put_before_images_batch(
            &[BeforeImageWrite {
                id: "before-0",
                plan_id: Some(&plan_id),
                payload: b"before-state",
                created_ms: 1,
            }],
            BeforeImagePolicy::new(1024, 100),
        )
        .unwrap();
    let target = native_path();
    let token = NativeObjectToken {
        volume: vec![1],
        object: vec![2],
        topology: vec![3],
    };
    let before = fp(1);
    let applied = fp(2);
    vault
        .prepare_native_wal(
            ID_1,
            &NativeWalWrite {
                target_sequence: 0,
                target: &target,
                object_token: &token,
                before_image_id: "before-0",
                operation_kind: MutationKind::Payload,
                expected: &before,
                intended_applied: &applied,
                intended_restored: &before,
            },
        )
        .unwrap();
    vault
        .transition_native_wal_with_applied_object_token(
            ID_1,
            0,
            NativeWalState::Applied,
            &NativeObjectToken {
                volume: vec![4],
                object: vec![5],
                topology: vec![6],
            },
        )
        .unwrap();

    let mut io = RecoveryIo {
        current: Some(applied),
        ..RecoveryIo::default()
    };
    let summary = recover_native_transactions(&mut vault, &mut io).unwrap();
    assert_eq!(summary.restored, 1);
    assert_eq!(summary.conflicts, 0);
    assert_eq!(io.restores, 1);
    assert_eq!(io.cleanups, vec![RecoveryOutcome::Restored]);
    assert_eq!(io.probes, vec![(fp(1), fp(2))]);
    assert_eq!(io.nonces, vec![*plan_id.as_bytes(); 2]);

    let again = recover_native_transactions(&mut vault, &mut io).unwrap();
    assert_eq!(again.recovered(), 0);
    assert_eq!(io.restores, 1);
    assert_eq!(io.cleanups.len(), 1);
}

#[cfg(windows)]
#[test]
fn os_recovery_restores_the_opaque_native_before_state_with_a_second_exact_cas() {
    use std::{fs, os::windows::ffi::OsStrExt};

    let root = TempVault::new("native-os-recovery-root");
    fs::create_dir(root.path()).unwrap();
    let target_path = root.path().join("target.txt");
    fs::write(&target_path, b"before").unwrap();

    let filesystem = OsNativeFileSystem::new();
    let before = filesystem.snapshot(&target_path).unwrap();
    let applied_state =
        NativeState::regular_file(b"applied".to_vec(), before.metadata().unwrap().clone());
    let plan_id = ID_2.parse::<PlanId>().unwrap();
    let applied = filesystem
        .compare_and_swap_with_nonce(
            &target_path,
            before.fingerprint(),
            &applied_state,
            plan_id.as_bytes(),
        )
        .unwrap();
    assert!(applied.wrote());

    let target = context_relay_protocol::WireNativeValue {
        platform: context_relay_protocol::NativePlatform::Windows,
        bytes: target_path
            .as_os_str()
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect(),
        display: Some(target_path.display().to_string()),
    };
    let vault_path = TempVault::new("native-os-recovery-vault");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(vault_path.path(), CREDENTIAL, &keys).unwrap();
    let approval = Sha256Digest([10; 32]);
    vault
        .begin_native_transaction(
            ID_1,
            NativePlanWrite {
                plan_id: &plan_id,
                approval_hash: &approval,
                payload: b"plan",
                created_ms: 1,
                expires_ms: 2,
            },
            NativeSandboxIdentity::Windows {
                moniker: "context-relay.native.00000000000000000000000000000002".to_owned(),
                sid: b"S-1-15-2-1-2-3-4-5-6-7".to_vec(),
            },
        )
        .unwrap();
    vault
        .put_before_images_batch(
            &[BeforeImageWrite {
                id: "before-0",
                plan_id: Some(&plan_id),
                payload: &before.state().encode_v1().unwrap(),
                created_ms: 1,
            }],
            BeforeImagePolicy::new(1024 * 1024, 100),
        )
        .unwrap();
    let expected = RestorableStateFingerprint(Sha256Digest(*before.fingerprint()));
    let intended = RestorableStateFingerprint(Sha256Digest(*applied.snapshot().fingerprint()));
    let token = journal_token(before.object_token().unwrap());
    let applied_token = journal_token(applied.installed_token().unwrap());
    vault
        .prepare_native_wal(
            ID_1,
            &NativeWalWrite {
                target_sequence: 0,
                target: &target,
                object_token: &token,
                before_image_id: "before-0",
                operation_kind: MutationKind::Payload,
                expected: &expected,
                intended_applied: &intended,
                intended_restored: &expected,
            },
        )
        .unwrap();
    vault
        .transition_native_wal_with_applied_object_token(
            ID_1,
            0,
            NativeWalState::Applied,
            &applied_token,
        )
        .unwrap();

    let mut io = OsNativeRecoveryIo::new(|_, _| Ok(()));
    recover_native_transactions(&mut vault, &mut io).unwrap();
    assert_eq!(fs::read(&target_path).unwrap(), b"before");
    assert_eq!(
        filesystem.snapshot(&target_path).unwrap().fingerprint(),
        before.fingerprint(),
        "restorable state excludes volatile access time and ephemeral object identity",
    );
}

#[cfg(windows)]
#[test]
fn os_recovery_restores_an_absent_before_state_under_the_original_parent() {
    use std::{fs, os::windows::ffi::OsStrExt};

    let root = TempVault::new("native-os-recovery-absent-before");
    fs::create_dir(root.path()).unwrap();
    let seed_path = root.path().join("metadata-seed.txt");
    fs::write(&seed_path, b"seed").unwrap();
    let filesystem = OsNativeFileSystem::new();
    let seed = filesystem.snapshot(&seed_path).unwrap();
    let intended_state =
        NativeState::regular_file(b"applied".to_vec(), seed.metadata().unwrap().clone());
    fs::remove_file(seed_path).unwrap();

    let target_path = root.path().join("target.txt");
    let before = filesystem.snapshot(&target_path).unwrap();
    let applied = filesystem
        .compare_and_swap_with_nonce(
            &target_path,
            before.fingerprint(),
            &intended_state,
            &[0x61; 16],
        )
        .unwrap();
    assert!(applied.wrote());
    let expected_before = RestorableStateFingerprint(Sha256Digest(*before.fingerprint()));
    let expected_applied =
        RestorableStateFingerprint(Sha256Digest(*applied.snapshot().fingerprint()));
    let token = journal_token(before.object_token().unwrap());
    let applied_token = journal_token(applied.installed_token().unwrap());
    let target = context_relay_protocol::WireNativeValue {
        platform: context_relay_protocol::NativePlatform::Windows,
        bytes: target_path
            .as_os_str()
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect(),
        display: Some(target_path.display().to_string()),
    };
    let mut io = OsNativeRecoveryIo::new(|_, _| Ok(()));

    assert_eq!(
        io.probe(
            &[0x61; 16],
            &target,
            &token,
            Some(&applied_token),
            None,
            MutationWalState::Applied,
            &expected_before,
            &expected_applied,
            &expected_before,
        )
        .unwrap(),
        RecoveryProbe::Fingerprint(expected_applied.clone()),
    );
    assert_eq!(
        io.restore_if_matches(
            &[0x61; 16],
            &target,
            &token,
            Some(&applied_token),
            &expected_applied,
            &expected_before,
            &before.state().encode_v1().unwrap(),
            &mut |_| Ok(()),
        )
        .unwrap(),
        RecoveryRestore::Restored,
    );
    assert!(!target_path.exists());
    assert_eq!(
        filesystem.snapshot(&target_path).unwrap().fingerprint(),
        before.fingerprint(),
    );
}

#[cfg(target_os = "macos")]
#[test]
fn os_recovery_restores_an_absent_before_state_under_the_original_parent_on_macos() {
    use std::{fs, os::unix::ffi::OsStrExt};

    let root = TempVault::new("native-os-recovery-absent-before-macos");
    fs::create_dir(root.path()).unwrap();
    let seed_path = root.path().join("metadata-seed.txt");
    fs::write(&seed_path, b"seed").unwrap();
    let filesystem = OsNativeFileSystem::new();
    let seed = filesystem.snapshot(&seed_path).unwrap();
    let intended_state =
        NativeState::regular_file(b"applied".to_vec(), seed.metadata().unwrap().clone());
    fs::remove_file(seed_path).unwrap();

    let target_path = root.path().join("target.txt");
    let before = filesystem.snapshot(&target_path).unwrap();
    let applied = filesystem
        .compare_and_swap_with_nonce(
            &target_path,
            before.fingerprint(),
            &intended_state,
            &[0x62; 16],
        )
        .unwrap();
    assert!(applied.wrote());
    let expected_before = RestorableStateFingerprint(Sha256Digest(*before.fingerprint()));
    let expected_applied =
        RestorableStateFingerprint(Sha256Digest(*applied.snapshot().fingerprint()));
    let token = journal_token(before.object_token().unwrap());
    let applied_token = journal_token(applied.installed_token().unwrap());
    let target = context_relay_protocol::WireNativeValue {
        platform: context_relay_protocol::NativePlatform::Macos,
        bytes: target_path.as_os_str().as_bytes().to_vec(),
        display: Some(target_path.display().to_string()),
    };
    let mut io = OsNativeRecoveryIo::new(|_, _| Ok(()));

    assert_eq!(
        io.probe(
            &[0x62; 16],
            &target,
            &token,
            Some(&applied_token),
            None,
            MutationWalState::Applied,
            &expected_before,
            &expected_applied,
            &expected_before,
        )
        .unwrap(),
        RecoveryProbe::Fingerprint(expected_applied.clone()),
    );
    assert_eq!(
        io.restore_if_matches(
            &[0x62; 16],
            &target,
            &token,
            Some(&applied_token),
            &expected_applied,
            &expected_before,
            &before.state().encode_v1().unwrap(),
            &mut |_| Ok(()),
        )
        .unwrap(),
        RecoveryRestore::Restored,
    );
    assert!(!target_path.exists());
    assert_eq!(
        filesystem.snapshot(&target_path).unwrap().fingerprint(),
        before.fingerprint(),
    );
}

#[cfg(windows)]
#[test]
fn os_recovery_rejects_a_mismatched_absent_before_image_before_native_cas() {
    use std::{fs, os::windows::ffi::OsStrExt};

    let root = TempVault::new("native-os-recovery-absent-mismatch");
    fs::create_dir(root.path()).unwrap();
    let target_path = root.path().join("target.txt");
    fs::write(&target_path, b"applied").unwrap();

    let filesystem = OsNativeFileSystem::new();
    let applied = filesystem.snapshot(&target_path).unwrap();
    let target = context_relay_protocol::WireNativeValue {
        platform: context_relay_protocol::NativePlatform::Windows,
        bytes: target_path
            .as_os_str()
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect(),
        display: Some(target_path.display().to_string()),
    };
    let expected_applied = RestorableStateFingerprint(Sha256Digest(*applied.fingerprint()));
    let corrupt_restored = fp(99);
    let absent = NativeState::absent(0, 0).encode_v1().unwrap();
    let mut io = OsNativeRecoveryIo::new(|_, _| Ok(()));
    let token = journal_token(applied.object_token().unwrap());

    assert!(
        io.restore_if_matches(
            &[7; 16],
            &target,
            &token,
            Some(&token),
            &expected_applied,
            &corrupt_restored,
            &absent,
            &mut |_| Ok(()),
        )
        .is_err()
    );
    assert_eq!(fs::read(&target_path).unwrap(), b"applied");
    assert_eq!(
        filesystem.snapshot(&target_path).unwrap().fingerprint(),
        applied.fingerprint(),
        "journal validation must fail before any native mutation",
    );
}

#[cfg(windows)]
#[test]
fn os_recovery_rejects_an_identical_applied_state_under_a_replaced_parent() {
    use std::{fs, os::windows::ffi::OsStrExt};

    let root = TempVault::new("native-os-recovery-parent-replacement-root");
    fs::create_dir(root.path()).unwrap();
    let approved = root.path().join("approved");
    let moved = root.path().join("moved");
    fs::create_dir(&approved).unwrap();
    let target_path = approved.join("target.txt");
    fs::write(&target_path, b"before").unwrap();
    let filesystem = OsNativeFileSystem::new();
    let before = filesystem.snapshot(&target_path).unwrap();
    let applied_state =
        NativeState::regular_file(b"applied".to_vec(), before.metadata().unwrap().clone());
    let plan_id = ID_2.parse::<PlanId>().unwrap();
    let applied = filesystem
        .compare_and_swap_with_nonce(
            &target_path,
            before.fingerprint(),
            &applied_state,
            plan_id.as_bytes(),
        )
        .unwrap();
    assert!(applied.wrote());
    let expected = RestorableStateFingerprint(Sha256Digest(*before.fingerprint()));
    let intended = RestorableStateFingerprint(Sha256Digest(*applied.snapshot().fingerprint()));
    let token = journal_token(before.object_token().unwrap());
    let applied_token = journal_token(applied.installed_token().unwrap());

    fs::rename(&approved, &moved).unwrap();
    fs::create_dir(&approved).unwrap();
    let replacement_absent = filesystem.snapshot(&target_path).unwrap();
    let concurrent = filesystem
        .compare_and_swap_with_nonce(
            &target_path,
            replacement_absent.fingerprint(),
            &applied_state,
            &[0x44; 16],
        )
        .unwrap();
    assert_eq!(concurrent.snapshot().fingerprint(), &intended.0.0);
    let concurrent_token = concurrent.snapshot().object_token().unwrap().clone();

    let target = context_relay_protocol::WireNativeValue {
        platform: context_relay_protocol::NativePlatform::Windows,
        bytes: target_path
            .as_os_str()
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect(),
        display: Some(target_path.display().to_string()),
    };
    let vault_path = TempVault::new("native-os-recovery-parent-replacement-vault");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(vault_path.path(), CREDENTIAL, &keys).unwrap();
    let approval = Sha256Digest([13; 32]);
    vault
        .begin_native_transaction(
            ID_1,
            NativePlanWrite {
                plan_id: &plan_id,
                approval_hash: &approval,
                payload: b"plan",
                created_ms: 1,
                expires_ms: 2,
            },
            NativeSandboxIdentity::Windows {
                moniker: "context-relay.native.00000000000000000000000000000004".to_owned(),
                sid: b"S-1-15-2-1-2-3-4-5-6-7".to_vec(),
            },
        )
        .unwrap();
    vault
        .put_before_images_batch(
            &[BeforeImageWrite {
                id: "before-parent-replacement",
                plan_id: Some(&plan_id),
                payload: &before.state().encode_v1().unwrap(),
                created_ms: 1,
            }],
            BeforeImagePolicy::new(1024 * 1024, 100),
        )
        .unwrap();
    vault
        .prepare_native_wal(
            ID_1,
            &NativeWalWrite {
                target_sequence: 0,
                target: &target,
                object_token: &token,
                before_image_id: "before-parent-replacement",
                operation_kind: MutationKind::Payload,
                expected: &expected,
                intended_applied: &intended,
                intended_restored: &expected,
            },
        )
        .unwrap();
    vault
        .transition_native_wal_with_applied_object_token(
            ID_1,
            0,
            NativeWalState::Applied,
            &applied_token,
        )
        .unwrap();

    let mut io = OsNativeRecoveryIo::new(|_, _| Ok(()));
    let summary = recover_native_transactions(&mut vault, &mut io).unwrap();
    assert_eq!(summary.conflicts, 1);
    assert_eq!(summary.restored, 0);
    let after = filesystem.snapshot(&target_path).unwrap();
    assert_eq!(after.object_token(), Some(&concurrent_token));
    assert_eq!(after.fingerprint(), &intended.0.0);
    assert_eq!(fs::read(&target_path).unwrap(), b"applied");
    assert_eq!(fs::read(moved.join("target.txt")).unwrap(), b"applied");
}

#[cfg(target_os = "macos")]
#[test]
fn os_recovery_rejects_an_identical_applied_state_under_a_replaced_parent_on_macos() {
    use std::{fs, os::unix::ffi::OsStrExt};

    let root = TempVault::new("native-os-recovery-parent-replacement-root-macos");
    fs::create_dir(root.path()).unwrap();
    let approved = root.path().join("approved");
    let moved = root.path().join("moved");
    fs::create_dir(&approved).unwrap();
    let target_path = approved.join("target.txt");
    fs::write(&target_path, b"before").unwrap();
    let filesystem = OsNativeFileSystem::new();
    let before = filesystem.snapshot(&target_path).unwrap();
    let applied_state =
        NativeState::regular_file(b"applied".to_vec(), before.metadata().unwrap().clone());
    let plan_id = ID_2.parse::<PlanId>().unwrap();
    let applied = filesystem
        .compare_and_swap_with_nonce(
            &target_path,
            before.fingerprint(),
            &applied_state,
            plan_id.as_bytes(),
        )
        .unwrap();
    assert!(applied.wrote());
    let expected = RestorableStateFingerprint(Sha256Digest(*before.fingerprint()));
    let intended = RestorableStateFingerprint(Sha256Digest(*applied.snapshot().fingerprint()));
    let token = journal_token(before.object_token().unwrap());
    let applied_token = journal_token(applied.installed_token().unwrap());

    fs::rename(&approved, &moved).unwrap();
    fs::create_dir(&approved).unwrap();
    let replacement_absent = filesystem.snapshot(&target_path).unwrap();
    let concurrent = filesystem
        .compare_and_swap_with_nonce(
            &target_path,
            replacement_absent.fingerprint(),
            &applied_state,
            &[0x55; 16],
        )
        .unwrap();
    assert_eq!(concurrent.snapshot().fingerprint(), &intended.0.0);
    let concurrent_token = concurrent.snapshot().object_token().unwrap().clone();

    let target = context_relay_protocol::WireNativeValue {
        platform: context_relay_protocol::NativePlatform::Macos,
        bytes: target_path.as_os_str().as_bytes().to_vec(),
        display: Some(target_path.display().to_string()),
    };
    let vault_path = TempVault::new("native-os-recovery-parent-replacement-vault-macos");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(vault_path.path(), CREDENTIAL, &keys).unwrap();
    let approval = Sha256Digest([14; 32]);
    let generation = "0123456789abcdef0123456789abcdef";
    let bundle = format!("com.contextrelay.native-runner.{generation}");
    let mut container = b"context-relay/macos-container/v1\0".to_vec();
    container.extend_from_slice(bundle.as_bytes());
    vault
        .begin_native_transaction(
            ID_1,
            NativePlanWrite {
                plan_id: &plan_id,
                approval_hash: &approval,
                payload: b"plan",
                created_ms: 1,
                expires_ms: 2,
            },
            NativeSandboxIdentity::reserved_macos(generation.to_owned(), bundle, container),
        )
        .unwrap();
    activate_macos(&mut vault, ID_1);
    vault
        .put_before_images_batch(
            &[BeforeImageWrite {
                id: "before-parent-replacement-macos",
                plan_id: Some(&plan_id),
                payload: &before.state().encode_v1().unwrap(),
                created_ms: 1,
            }],
            BeforeImagePolicy::new(1024 * 1024, 100),
        )
        .unwrap();
    vault
        .prepare_native_wal(
            ID_1,
            &NativeWalWrite {
                target_sequence: 0,
                target: &target,
                object_token: &token,
                before_image_id: "before-parent-replacement-macos",
                operation_kind: MutationKind::Payload,
                expected: &expected,
                intended_applied: &intended,
                intended_restored: &expected,
            },
        )
        .unwrap();
    vault
        .transition_native_wal_with_applied_object_token(
            ID_1,
            0,
            NativeWalState::Applied,
            &applied_token,
        )
        .unwrap();

    let mut io = OsNativeRecoveryIo::new(|_, _| Ok(()));
    let summary = recover_native_transactions(&mut vault, &mut io).unwrap();
    assert_eq!(summary.conflicts, 1);
    assert_eq!(summary.restored, 0);
    let after = filesystem.snapshot(&target_path).unwrap();
    assert_eq!(after.object_token(), Some(&concurrent_token));
    assert_eq!(after.fingerprint(), &intended.0.0);
    assert_eq!(fs::read(&target_path).unwrap(), b"applied");
    assert_eq!(fs::read(moved.join("target.txt")).unwrap(), b"applied");
}
