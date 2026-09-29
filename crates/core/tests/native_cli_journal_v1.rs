mod support;

use context_relay_core::vault::{
    NativeCliWalState, NativeCliWalWrite, NativePlanWrite, NativeSandboxIdentity, SetupPlanAction,
    SetupPlanWrite, Vault, VaultError,
};
use context_relay_protocol::{HarnessId, PlanId, Sha256Digest};
use sha2::{Digest as _, Sha256};

use support::{ID_1, ID_2, ID_3, ID_4, ID_5, MemoryKeyStore, TempVault};

const CREDENTIAL: &str = "native-cli-journal-v1";
const TRANSACTION_ID: &str = "native-cli-transaction";
const REAL_APPCONTAINER_SID: &[u8] =
    b"S-1-15-2-3872518810-2985098273-1912316193-2655983105-1250049442-371239648-1157085541";

fn identity() -> NativeSandboxIdentity {
    NativeSandboxIdentity::Windows {
        moniker: "context-relay.native.0123456789abcdef0123456789abcdef".to_owned(),
        sid: REAL_APPCONTAINER_SID.to_vec(),
    }
}

fn open_transaction() -> (TempVault, MemoryKeyStore, Vault) {
    let path = TempVault::new("native-cli-wal");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let plan_id = ID_1.parse::<PlanId>().unwrap();
    let approval_hash = Sha256Digest([3; 32]);
    let payload = b"canonical-plan";
    vault
        .put_setup_plan(SetupPlanWrite {
            plan_id: &plan_id,
            schema_version: 1,
            approval_version: 2,
            approval_hash: &approval_hash,
            payload,
            created_ms: 10,
            expires_ms: 20,
        })
        .unwrap();
    vault
        .claim_setup_plan(&plan_id, SetupPlanAction::Apply, 11)
        .unwrap();
    vault
        .begin_native_transaction(
            TRANSACTION_ID,
            NativePlanWrite {
                plan_id: &plan_id,
                approval_hash: &approval_hash,
                payload,
                created_ms: 10,
                expires_ms: 20,
            },
            identity(),
        )
        .unwrap();
    (path, keys, vault)
}

fn cli_write<'a>(
    expected: &'a [u8],
    expected_fingerprint: &'a Sha256Digest,
    intended: &'a [u8],
    intended_fingerprint: &'a Sha256Digest,
) -> NativeCliWalWrite<'a> {
    NativeCliWalWrite {
        sequence: 0,
        stable_id: ID_2,
        harness: HarnessId::Codex,
        server_name: "context-relay",
        expected_declaration: Some(expected),
        expected_fingerprint: Some(expected_fingerprint),
        intended_declaration: Some(intended),
        intended_fingerprint: Some(intended_fingerprint),
        forward_operations: br#"[{"op":"add","exact":true}]"#,
        rollback_operations: br#"[{"op":"restore","exact":true}]"#,
    }
}

fn fingerprint(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest(Sha256::digest(bytes).into())
}

#[test]
fn temp_vault_paths_are_unique_under_concurrent_construction() {
    const BUILDERS: usize = 64;

    let gate = std::sync::Arc::new(std::sync::Barrier::new(BUILDERS));
    let builders = (0..BUILDERS)
        .map(|_| {
            let gate = std::sync::Arc::clone(&gate);
            std::thread::spawn(move || {
                gate.wait();
                let vault = TempVault::new("parallel-uniqueness");
                (vault.path().to_owned(), vault)
            })
        })
        .collect::<Vec<_>>();
    let vaults = builders
        .into_iter()
        .map(|builder| builder.join().unwrap())
        .collect::<Vec<_>>();
    let unique_paths = vaults
        .iter()
        .map(|(path, _)| path)
        .collect::<std::collections::HashSet<_>>();

    assert_eq!(unique_paths.len(), BUILDERS);
}

/// The CLI compensation path marks every not-yet-restored record `Conflict`,
/// one record at a time, each transition committing on its own. A crash partway
/// through therefore leaves some records already `Conflict` and others not, so
/// the walk has to tolerate re-entering a record it already finished. This is
/// the CLI counterpart to the write-ahead log resumption covered for
/// `native_journal_v1`, and the same argument applies.
#[test]
fn a_partially_applied_cli_compensation_resumes_from_its_own_midpoint() {
    let (_path, _keys, mut vault) = open_transaction();
    let expected = br#"{"command":"/old","args":[]}"#;
    let intended = br#"{"command":"/new","args":["--harness","codex"]}"#;
    let expected_fingerprint = fingerprint(expected);
    let intended_fingerprint = fingerprint(intended);
    // Two distinct sequences, so a crash between them leaves one finished and
    // one untouched.
    for sequence in 0..2_u32 {
        vault
            .prepare_native_cli_wal(
                TRANSACTION_ID,
                &NativeCliWalWrite {
                    sequence,
                    // A transaction may not name the same target twice: the
                    // vault rejects a repeated stable id, or a repeated
                    // harness/server-name pair, and the server name is pinned to
                    // the context-relay server. The two records therefore differ
                    // in stable id and in harness.
                    stable_id: if sequence == 0 { ID_2 } else { ID_3 },
                    harness: if sequence == 0 {
                        HarnessId::Codex
                    } else {
                        HarnessId::ClaudeCode
                    },
                    server_name: "context-relay",
                    expected_declaration: Some(expected),
                    expected_fingerprint: Some(&expected_fingerprint),
                    intended_declaration: Some(intended),
                    intended_fingerprint: Some(&intended_fingerprint),
                    forward_operations: br#"[{"op":"add","exact":true}]"#,
                    rollback_operations: br#"[{"op":"restore","exact":true}]"#,
                },
            )
            .unwrap();
        vault
            .transition_native_cli_wal(TRANSACTION_ID, sequence, NativeCliWalState::Applied)
            .unwrap();
    }

    // First pass: mark sequence 0, then stop the way a crash would.
    vault
        .transition_native_cli_wal(TRANSACTION_ID, 0, NativeCliWalState::Conflict)
        .unwrap();
    let interrupted = vault.native_cli_wal(TRANSACTION_ID).unwrap();
    assert_eq!(interrupted[0].state, NativeCliWalState::Conflict);
    assert_eq!(interrupted[1].state, NativeCliWalState::Applied);

    // Second pass: the same state-driven walk `finish_compensated` performs.
    // A record already `Conflict` takes the no-op arm rather than being
    // rejected, and one still `Applied` is carried the rest of the way.
    for record in vault.native_cli_wal(TRANSACTION_ID).unwrap() {
        let sequence = record.sequence;
        match record.state {
            NativeCliWalState::Prepared
            | NativeCliWalState::Applied
            | NativeCliWalState::RestorePrepared => {
                vault
                    .transition_native_cli_wal(
                        TRANSACTION_ID,
                        sequence,
                        NativeCliWalState::Conflict,
                    )
                    .unwrap_or_else(|error| {
                        panic!("sequence {sequence} must accept a resume into Conflict: {error:?}")
                    });
            }
            NativeCliWalState::Restored | NativeCliWalState::Conflict => {}
        }
    }

    for record in vault.native_cli_wal(TRANSACTION_ID).unwrap() {
        assert_eq!(
            record.state,
            NativeCliWalState::Conflict,
            "sequence {} must finish Conflict after a resumed compensation",
            record.sequence
        );
    }
}

#[test]
fn cli_wal_round_trips_canonical_bytes_and_allows_only_monotonic_transitions() {
    let (_path, _keys, mut vault) = open_transaction();
    let expected = br#"{"command":"/old","args":[]}"#;
    let intended = br#"{"command":"/new","args":["--harness","codex"]}"#;
    let expected_fingerprint = fingerprint(expected);
    let intended_fingerprint = fingerprint(intended);
    let write = cli_write(
        expected,
        &expected_fingerprint,
        intended,
        &intended_fingerprint,
    );

    vault
        .prepare_native_cli_wal(TRANSACTION_ID, &write)
        .unwrap();
    vault
        .prepare_native_cli_wal(TRANSACTION_ID, &write)
        .unwrap();
    let rows = vault.native_cli_wal(TRANSACTION_ID).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].expected_declaration.as_deref(),
        Some(expected.as_slice())
    );
    assert_eq!(
        rows[0].intended_declaration.as_deref(),
        Some(intended.as_slice())
    );
    assert_eq!(rows[0].forward_operations, write.forward_operations);
    assert_eq!(rows[0].rollback_operations, write.rollback_operations);
    assert_eq!(rows[0].state, NativeCliWalState::Prepared);

    vault
        .transition_native_cli_wal(TRANSACTION_ID, 0, NativeCliWalState::Applied)
        .unwrap();
    vault
        .transition_native_cli_wal(TRANSACTION_ID, 0, NativeCliWalState::RestorePrepared)
        .unwrap();
    vault
        .transition_native_cli_wal(TRANSACTION_ID, 0, NativeCliWalState::Restored)
        .unwrap();
    vault
        .transition_native_cli_wal(TRANSACTION_ID, 0, NativeCliWalState::Restored)
        .unwrap();
    assert!(matches!(
        vault.transition_native_cli_wal(TRANSACTION_ID, 0, NativeCliWalState::Applied),
        Err(VaultError::Validation(_))
    ));
}

#[test]
fn cli_wal_rejects_altered_replay_gaps_duplicates_and_invalid_targets() {
    let (_path, _keys, mut vault) = open_transaction();
    let expected = br#"{"command":"/old"}"#;
    let intended = br#"{"command":"/new"}"#;
    let expected_fingerprint = fingerprint(expected);
    let intended_fingerprint = fingerprint(intended);
    let write = cli_write(
        expected,
        &expected_fingerprint,
        intended,
        &intended_fingerprint,
    );
    vault
        .prepare_native_cli_wal(TRANSACTION_ID, &write)
        .unwrap();

    let altered = NativeCliWalWrite {
        forward_operations: br#"[{"op":"remove"}]"#,
        ..write
    };
    assert!(matches!(
        vault.prepare_native_cli_wal(TRANSACTION_ID, &altered),
        Err(VaultError::Validation(_))
    ));
    let gap = NativeCliWalWrite {
        sequence: 2,
        stable_id: ID_3,
        harness: HarnessId::ClaudeCode,
        ..write
    };
    assert!(matches!(
        vault.prepare_native_cli_wal(TRANSACTION_ID, &gap),
        Err(VaultError::Validation(_))
    ));
    let duplicate_stable_id = NativeCliWalWrite {
        sequence: 1,
        harness: HarnessId::ClaudeCode,
        ..write
    };
    assert!(matches!(
        vault.prepare_native_cli_wal(TRANSACTION_ID, &duplicate_stable_id),
        Err(VaultError::Validation(_))
    ));
    let duplicate_target = NativeCliWalWrite {
        sequence: 1,
        stable_id: ID_4,
        ..write
    };
    assert!(matches!(
        vault.prepare_native_cli_wal(TRANSACTION_ID, &duplicate_target),
        Err(VaultError::Validation(_))
    ));
    let unsupported = NativeCliWalWrite {
        sequence: 1,
        stable_id: ID_5,
        harness: HarnessId::Hermes,
        ..write
    };
    assert!(matches!(
        vault.prepare_native_cli_wal(TRANSACTION_ID, &unsupported),
        Err(VaultError::Validation(_))
    ));
}

#[test]
fn recovery_requires_an_exact_prepared_cli_no_write_disposition() {
    let (_path, _keys, mut vault) = open_transaction();
    let expected = br#"{"command":"/old"}"#;
    let intended = br#"{"command":"/new"}"#;
    let expected_fingerprint = fingerprint(expected);
    let intended_fingerprint = fingerprint(intended);
    vault
        .prepare_native_cli_wal(
            TRANSACTION_ID,
            &cli_write(
                expected,
                &expected_fingerprint,
                intended,
                &intended_fingerprint,
            ),
        )
        .unwrap();
    vault.begin_native_recovery(TRANSACTION_ID).unwrap();

    assert!(matches!(
        vault.finish_native_recovery(TRANSACTION_ID, false),
        Err(VaultError::Validation(_))
    ));
    assert!(matches!(
        vault.finish_native_recovery_with_cli_no_write(TRANSACTION_ID, false, &[1]),
        Err(VaultError::Validation(_))
    ));
    vault
        .finish_native_recovery_with_cli_no_write(TRANSACTION_ID, false, &[0])
        .unwrap();
}

#[test]
fn recovery_validates_cli_conflict_claims_and_rejects_unfinished_rows() {
    let prepare = |vault: &mut Vault| {
        let expected = br#"{"command":"/old"}"#;
        let intended = br#"{"command":"/new"}"#;
        let expected_fingerprint = fingerprint(expected);
        let intended_fingerprint = fingerprint(intended);
        vault
            .prepare_native_cli_wal(
                TRANSACTION_ID,
                &cli_write(
                    expected,
                    &expected_fingerprint,
                    intended,
                    &intended_fingerprint,
                ),
            )
            .unwrap();
    };

    let (_path, _keys, mut unfinished) = open_transaction();
    prepare(&mut unfinished);
    unfinished
        .transition_native_cli_wal(TRANSACTION_ID, 0, NativeCliWalState::Applied)
        .unwrap();
    unfinished.begin_native_recovery(TRANSACTION_ID).unwrap();
    for conflict in [false, true] {
        assert!(matches!(
            unfinished.finish_native_recovery(TRANSACTION_ID, conflict),
            Err(VaultError::Validation(_))
        ));
    }

    let (_path, _keys, mut conflicted) = open_transaction();
    prepare(&mut conflicted);
    conflicted
        .transition_native_cli_wal(TRANSACTION_ID, 0, NativeCliWalState::Conflict)
        .unwrap();
    conflicted.begin_native_recovery(TRANSACTION_ID).unwrap();
    assert!(matches!(
        conflicted.finish_native_recovery(TRANSACTION_ID, false),
        Err(VaultError::Validation(_))
    ));
    conflicted
        .finish_native_recovery(TRANSACTION_ID, true)
        .unwrap();

    let (_path, _keys, mut restored) = open_transaction();
    prepare(&mut restored);
    for state in [
        NativeCliWalState::Applied,
        NativeCliWalState::RestorePrepared,
        NativeCliWalState::Restored,
    ] {
        restored
            .transition_native_cli_wal(TRANSACTION_ID, 0, state)
            .unwrap();
    }
    restored.begin_native_recovery(TRANSACTION_ID).unwrap();
    assert!(matches!(
        restored.finish_native_recovery(TRANSACTION_ID, true),
        Err(VaultError::Validation(_))
    ));
    restored
        .finish_native_recovery(TRANSACTION_ID, false)
        .unwrap();
}
