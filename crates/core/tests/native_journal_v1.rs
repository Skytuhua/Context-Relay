mod support;

use std::path::Path;

use context_relay_core::{
    native_transaction::{
        MutationKind, NativeApplyReceipt, NativeObjectToken, NativeReceiptEntry, OwnershipChange,
        RestorableStateFingerprint, TransactionStep,
    },
    vault::{
        BeforeImagePolicy, BeforeImageWrite, LATEST_SCHEMA_VERSION, MacGenerationState,
        NativePlanWrite, NativeSandboxCleanupState, NativeSandboxIdentity, NativeTransactionStatus,
        NativeWalState, NativeWalWrite, Vault, VaultError,
    },
};
use context_relay_native_runner::MacRootIdentity;
use context_relay_protocol::{PlanId, Sha256Digest};
use rusqlite::{Connection, OptionalExtension};

use support::{
    ID_1, ID_2, ID_3, ID_4, ID_5, ID_6, MemoryKeyStore, TempVault, native_path, receipt,
};

const CREDENTIAL: &str = "task-9-native-journal";
const REAL_APPCONTAINER_SID: &[u8] =
    b"S-1-15-2-3872518810-2985098273-1912316193-2655983105-1250049442-371239648-1157085541";

fn open_keyed(path: &Path, key: &[u8; 32]) -> Connection {
    let connection = Connection::open(path).unwrap();
    // SAFETY: this is the first operation on the owned handle and the key lives
    // for the entire call.
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

fn create_v2(path: &Path, key: &[u8; 32]) -> Connection {
    let connection = open_keyed(path, key);
    connection
        .execute_batch(include_str!("../migrations/0001_vault.sql"))
        .unwrap();
    connection.pragma_update(None, "user_version", 1).unwrap();
    connection
        .execute_batch(include_str!("../migrations/0002_before_image_plans.sql"))
        .unwrap();
    connection.pragma_update(None, "user_version", 2).unwrap();
    connection
}

fn plan_id(value: &str) -> PlanId {
    value.parse().unwrap()
}

fn fingerprint(byte: u8) -> RestorableStateFingerprint {
    RestorableStateFingerprint(Sha256Digest([byte; 32]))
}

fn canonical_token(object: u8, tag: u32, parent: u8) -> NativeObjectToken {
    let volume = 7_u64.to_le_bytes();
    let mut topology = Vec::with_capacity(29);
    topology.push(1);
    topology.extend_from_slice(&tag.to_le_bytes());
    topology.extend_from_slice(&volume);
    topology.extend_from_slice(&[parent; 16]);
    NativeObjectToken {
        volume: volume.to_vec(),
        object: vec![object; 16],
        topology,
    }
}

fn windows_identity() -> NativeSandboxIdentity {
    NativeSandboxIdentity::Windows {
        moniker: "context-relay.native.0123456789abcdef0123456789abcdef".to_owned(),
        sid: REAL_APPCONTAINER_SID.to_vec(),
    }
}

fn canonical_macos_container(bundle_id: &str) -> Vec<u8> {
    let mut value = b"context-relay/macos-container/v1\0".to_vec();
    value.extend_from_slice(bundle_id.as_bytes());
    value
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

fn plan<'a>(
    plan_id: &'a PlanId,
    approval_hash: &'a Sha256Digest,
    payload: &'a [u8],
) -> NativePlanWrite<'a> {
    NativePlanWrite {
        plan_id,
        approval_hash,
        payload,
        created_ms: 10,
        expires_ms: 20,
    }
}

fn wal<'a>(
    sequence: u32,
    before_image_id: &'a str,
    target: &'a context_relay_protocol::WireNativeValue,
    object_token: &'a NativeObjectToken,
    expected: &'a RestorableStateFingerprint,
    applied: &'a RestorableStateFingerprint,
    restored: &'a RestorableStateFingerprint,
) -> NativeWalWrite<'a> {
    NativeWalWrite {
        target_sequence: sequence,
        target,
        object_token,
        before_image_id,
        operation_kind: MutationKind::Payload,
        expected,
        intended_applied: applied,
        intended_restored: restored,
    }
}

#[test]
fn v2_to_v3_is_atomic_rejects_future_versions_and_keeps_foreign_keys_enabled() {
    const TABLES: &[&str] = &[
        "native_plans",
        "native_transactions",
        "native_mutation_wal",
        "native_ownership",
        "native_receipts",
    ];
    for blocker in TABLES {
        let path = TempVault::new(&format!("native-migration-{blocker}"));
        let keys = MemoryKeyStore::default();
        let key = [21; 32];
        keys.insert(CREDENTIAL, key);
        let raw = create_v2(path.path(), &key);
        raw.execute(&format!("CREATE TABLE {blocker}(blocker INTEGER)"), [])
            .unwrap();
        drop(raw);

        assert!(matches!(
            Vault::open(path.path(), CREDENTIAL, &keys),
            Err(VaultError::Migration(_))
        ));
        let raw = open_keyed(path.path(), &key);
        assert_eq!(
            raw.query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))
                .unwrap(),
            2
        );
        for table in TABLES {
            let sql: Option<String> = raw
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    [table],
                    |row| row.get(0),
                )
                .optional()
                .unwrap();
            assert_eq!(sql.is_some(), table == blocker, "{blocker}: {table}");
        }
    }

    let path = TempVault::new("native-migration-index");
    let keys = MemoryKeyStore::default();
    let key = [22; 32];
    keys.insert(CREDENTIAL, key);
    let raw = create_v2(path.path(), &key);
    raw.execute(
        "CREATE INDEX native_transactions_status_idx ON records(id)",
        [],
    )
    .unwrap();
    drop(raw);
    assert!(matches!(
        Vault::open(path.path(), CREDENTIAL, &keys),
        Err(VaultError::Migration(_))
    ));
    let raw = open_keyed(path.path(), &key);
    assert_eq!(
        raw.query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        raw.query_row(
            "SELECT count(*) FROM sqlite_master
             WHERE type = 'table' AND name LIKE 'native_%'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap(),
        0
    );
    drop(raw);

    let raw = open_keyed(path.path(), &key);
    raw.execute("DROP INDEX native_transactions_status_idx", [])
        .unwrap();
    raw.pragma_update(None, "user_version", LATEST_SCHEMA_VERSION + 1)
        .unwrap();
    drop(raw);
    assert!(matches!(
        Vault::open(path.path(), CREDENTIAL, &keys),
        Err(VaultError::FutureSchema { .. })
    ));

    let path = TempVault::new("native-migration-green");
    let keys = MemoryKeyStore::default();
    let vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(vault.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
    let runtime = vault.runtime_info().unwrap();
    assert!(runtime.foreign_keys);
    assert_eq!(runtime.synchronous, 2);
    let names = vault.table_names().unwrap();
    for table in TABLES {
        assert!(names.iter().any(|name| name == table), "{table}");
    }
    drop(vault);

    let raw = open_keyed(path.path(), &keys.key(CREDENTIAL));
    for table in [
        "native_transactions",
        "native_mutation_wal",
        "native_ownership",
        "native_receipts",
    ] {
        let count = raw
            .prepare(&format!("PRAGMA foreign_key_list({table})"))
            .unwrap()
            .query_map([], |_| Ok(()))
            .unwrap()
            .count();
        assert!(count > 0, "{table}");
    }
}

#[test]
fn before_image_batch_reserves_budget_before_inserting_any_member() {
    let path = TempVault::new("native-before-image-batch");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let policy = BeforeImagePolicy::new(10, 100);
    vault
        .put_before_image("anchor", None, &[9; 2], 1, policy)
        .unwrap();
    let plan = plan_id(ID_1);
    let batch = [
        BeforeImageWrite {
            id: "first",
            plan_id: Some(&plan),
            payload: &[1; 6],
            created_ms: 2,
        },
        BeforeImageWrite {
            id: "second",
            plan_id: Some(&plan),
            payload: &[2; 6],
            created_ms: 2,
        },
    ];
    assert!(matches!(
        vault.put_before_images_batch(&batch, policy),
        Err(VaultError::BudgetExceeded)
    ));
    assert_eq!(vault.before_image_bytes().unwrap(), 2);
    assert!(vault.has_before_image("anchor").unwrap());
    assert!(!vault.has_before_image("first").unwrap());
    assert!(!vault.has_before_image("second").unwrap());

    let exact = [
        BeforeImageWrite {
            id: "first",
            plan_id: Some(&plan),
            payload: &[1; 4],
            created_ms: 2,
        },
        BeforeImageWrite {
            id: "second",
            plan_id: Some(&plan),
            payload: &[2; 4],
            created_ms: 2,
        },
    ];
    vault.put_before_images_batch(&exact, policy).unwrap();
    assert_eq!(vault.before_image_bytes().unwrap(), 10);
    assert!(vault.has_before_image("first").unwrap());
    assert!(vault.has_before_image("second").unwrap());
}

#[test]
fn wal_is_sequenced_immutable_and_only_allows_monotonic_idempotent_transitions() {
    let path = TempVault::new("native-wal");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let plan_id = plan_id(ID_2);
    let approval = Sha256Digest([8; 32]);
    vault
        .begin_native_transaction(
            ID_1,
            plan(&plan_id, &approval, b"encrypted native plan"),
            windows_identity(),
        )
        .unwrap();
    let snapshot = vault.native_transaction(ID_1).unwrap().unwrap();
    assert_eq!(snapshot.plan_id, plan_id);
    assert_eq!(snapshot.status, NativeTransactionStatus::Pending);
    assert_eq!(snapshot.identity, windows_identity());
    assert_eq!(vault.pending_native_transactions().unwrap(), vec![snapshot]);

    vault
        .put_before_images_batch(
            &[
                BeforeImageWrite {
                    id: "before-0",
                    plan_id: Some(&plan_id),
                    payload: b"before zero",
                    created_ms: 10,
                },
                BeforeImageWrite {
                    id: "before-1",
                    plan_id: Some(&plan_id),
                    payload: b"before one",
                    created_ms: 10,
                },
            ],
            BeforeImagePolicy::new(1024, 100),
        )
        .unwrap();

    let target = native_path();
    let token = NativeObjectToken {
        volume: vec![1],
        object: vec![2],
        topology: vec![3],
    };
    let expected = fingerprint(1);
    let applied = fingerprint(2);
    let restored = fingerprint(3);
    let first = wal(
        0, "before-0", &target, &token, &expected, &applied, &restored,
    );
    vault.prepare_native_wal(ID_1, &first).unwrap();
    vault.prepare_native_wal(ID_1, &first).unwrap();

    let changed_expected = fingerprint(9);
    assert!(matches!(
        vault.prepare_native_wal(
            ID_1,
            &wal(
                0,
                "before-0",
                &target,
                &token,
                &changed_expected,
                &applied,
                &restored,
            )
        ),
        Err(VaultError::Validation(_))
    ));
    let mut display_alias = target.clone();
    display_alias.display = Some("same native bytes, different display".to_owned());
    assert!(matches!(
        vault.prepare_native_wal(
            ID_1,
            &wal(
                1,
                "before-1",
                &display_alias,
                &token,
                &expected,
                &applied,
                &restored,
            )
        ),
        Err(VaultError::Validation(_))
    ));
    assert!(matches!(
        vault.prepare_native_wal(
            ID_1,
            &wal(
                2, "before-1", &target, &token, &expected, &applied, &restored,
            )
        ),
        Err(VaultError::Validation(_))
    ));
    let applied_token = NativeObjectToken {
        volume: vec![4],
        object: vec![5],
        topology: vec![6],
    };
    assert!(matches!(
        vault.transition_native_wal(ID_1, 0, NativeWalState::RestorePrepared),
        Err(VaultError::Validation(_))
    ));
    vault
        .record_native_wal_candidate(ID_1, 0, &applied_token)
        .unwrap();
    vault
        .record_native_wal_candidate(ID_1, 0, &applied_token)
        .unwrap();
    let prepared = vault.native_wal(ID_1).unwrap();
    assert_eq!(prepared[0].state, NativeWalState::Prepared);
    assert_eq!(
        prepared[0].applied_object_token.as_ref(),
        Some(&applied_token)
    );
    assert!(matches!(
        vault.record_native_wal_candidate(
            ID_1,
            0,
            &NativeObjectToken {
                volume: vec![7],
                object: vec![8],
                topology: vec![9],
            }
        ),
        Err(VaultError::Validation(_))
    ));
    vault
        .transition_native_wal_with_applied_object_token(
            ID_1,
            0,
            NativeWalState::Applied,
            &applied_token,
        )
        .unwrap();
    for state in [
        NativeWalState::RestorePrepared,
        NativeWalState::RestorePrepared,
    ] {
        vault.transition_native_wal(ID_1, 0, state).unwrap();
    }
    assert!(matches!(
        vault.transition_native_wal(ID_1, 0, NativeWalState::Restored),
        Err(VaultError::Validation(_))
    ));
    let restored_token = NativeObjectToken {
        volume: vec![10],
        object: vec![11],
        topology: vec![12],
    };
    vault
        .record_native_wal_restored_candidate(ID_1, 0, &restored_token)
        .unwrap();
    vault
        .record_native_wal_restored_candidate(ID_1, 0, &restored_token)
        .unwrap();
    assert_eq!(
        vault.native_wal(ID_1).unwrap()[0]
            .restored_object_token
            .as_ref(),
        Some(&restored_token)
    );
    assert!(matches!(
        vault.record_native_wal_restored_candidate(
            ID_1,
            0,
            &NativeObjectToken {
                volume: vec![13],
                object: vec![14],
                topology: vec![15],
            }
        ),
        Err(VaultError::Validation(_))
    ));
    vault
        .transition_native_wal(ID_1, 0, NativeWalState::Restored)
        .unwrap();
    vault
        .transition_native_wal(ID_1, 0, NativeWalState::Restored)
        .unwrap();
    assert!(matches!(
        vault.transition_native_wal(ID_1, 0, NativeWalState::Applied),
        Err(VaultError::Validation(_))
    ));
    assert!(matches!(
        vault.transition_native_wal(ID_1, 0, NativeWalState::Conflict),
        Err(VaultError::Validation(_))
    ));

    let mut second_target = native_path();
    second_target.display = Some(r"C:\vault\second".to_owned());
    second_target.bytes = r"C:\vault\second"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    vault
        .prepare_native_wal(
            ID_1,
            &wal(
                1,
                "before-1",
                &second_target,
                &token,
                &expected,
                &applied,
                &restored,
            ),
        )
        .unwrap();
    vault
        .transition_native_wal(ID_1, 1, NativeWalState::Conflict)
        .unwrap();
    let rows = vault.native_wal(ID_1).unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].state, NativeWalState::Restored);
    assert_eq!(rows[0].expected, expected);
    assert_eq!(rows[0].intended_applied, applied);
    assert_eq!(rows[0].intended_restored, restored);
    assert_eq!(rows[1].target_sequence, 1);
    assert_eq!(rows[1].state, NativeWalState::Conflict);
}

#[test]
fn absence_rebind_is_an_exact_authorized_descending_wal_cas() {
    let path = TempVault::new("native-wal-absence-rebind");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let plan_id = plan_id(ID_2);
    vault
        .begin_native_transaction(
            ID_1,
            plan(&plan_id, &Sha256Digest([8; 32]), b"absence rebind plan"),
            windows_identity(),
        )
        .unwrap();
    vault
        .put_before_images_batch(
            &[
                BeforeImageWrite {
                    id: "rebind-before-0",
                    plan_id: Some(&plan_id),
                    payload: b"before zero",
                    created_ms: 10,
                },
                BeforeImageWrite {
                    id: "rebind-before-1",
                    plan_id: Some(&plan_id),
                    payload: b"before one",
                    created_ms: 10,
                },
            ],
            BeforeImagePolicy::new(1024, 100),
        )
        .unwrap();
    let first_target = native_path();
    let mut second_target = native_path();
    second_target.display = Some(r"C:\vault\second".to_owned());
    second_target.bytes = r"C:\vault\second"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let first_original = canonical_token(1, 0, 9);
    let second_original = canonical_token(2, 0, 9);
    let first_old = canonical_token(3, u32::MAX, 9);
    let second_applied = canonical_token(4, u32::MAX, 9);
    let first_new = canonical_token(5, u32::MAX, 9);
    let expected = fingerprint(1);
    let applied = fingerprint(2);
    for (sequence, before_id, target, original, candidate) in [
        (
            0,
            "rebind-before-0",
            &first_target,
            &first_original,
            &first_old,
        ),
        (
            1,
            "rebind-before-1",
            &second_target,
            &second_original,
            &second_applied,
        ),
    ] {
        vault
            .prepare_native_wal(
                ID_1,
                &wal(
                    sequence, before_id, target, original, &expected, &applied, &expected,
                ),
            )
            .unwrap();
        vault
            .record_native_wal_candidate(ID_1, sequence, candidate)
            .unwrap();
        vault
            .transition_native_wal_with_applied_object_token(
                ID_1,
                sequence,
                NativeWalState::Applied,
                candidate,
            )
            .unwrap();
    }
    vault.begin_native_recovery(ID_1).unwrap();
    vault
        .transition_native_wal(ID_1, 0, NativeWalState::RestorePrepared)
        .unwrap();
    vault
        .transition_native_wal(ID_1, 1, NativeWalState::RestorePrepared)
        .unwrap();
    vault
        .record_native_wal_restored_candidate(ID_1, 1, &second_original)
        .unwrap();

    assert!(matches!(
        vault.rebind_native_wal_applied_absence(ID_1, 0, 1, &first_old, &first_new),
        Err(VaultError::Validation(_))
    ));
    vault
        .checkpoint_native_wal_absence_rebind(ID_1, 0, 1, &first_old, &first_new)
        .unwrap();
    vault
        .checkpoint_native_wal_absence_rebind(ID_1, 0, 1, &first_old, &first_new)
        .unwrap();
    let checkpoint = vault.native_wal(ID_1).unwrap()[1]
        .absence_rebind
        .clone()
        .unwrap();
    assert_eq!(checkpoint.target_sequence, 0);
    assert_eq!(checkpoint.old_token, first_old);
    assert_eq!(checkpoint.new_token, first_new);
    assert!(matches!(
        vault.checkpoint_native_wal_absence_rebind(
            ID_1,
            0,
            1,
            &checkpoint.old_token,
            &canonical_token(6, u32::MAX, 9),
        ),
        Err(VaultError::Validation(_))
    ));

    vault
        .rebind_native_wal_applied_absence(ID_1, 0, 1, &first_old, &first_new)
        .unwrap();
    vault
        .rebind_native_wal_applied_absence(ID_1, 0, 1, &first_old, &first_new)
        .unwrap();
    assert_eq!(
        vault.native_wal(ID_1).unwrap()[0]
            .applied_object_token
            .as_ref(),
        Some(&first_new)
    );
    assert!(matches!(
        vault.rebind_native_wal_applied_absence(ID_1, 1, 0, &second_applied, &first_new),
        Err(VaultError::Validation(_))
    ));
    assert!(matches!(
        vault.rebind_native_wal_applied_absence(
            ID_1,
            0,
            1,
            &first_new,
            &canonical_token(6, u32::MAX, 10),
        ),
        Err(VaultError::Validation(_))
    ));
}

#[test]
fn platform_identity_and_macos_generation_state_survive_reopen() {
    let path = TempVault::new("native-platform-identity");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let windows_plan = plan_id(ID_2);
    let macos_plan = plan_id(ID_4);
    let approval = Sha256Digest([5; 32]);
    vault
        .begin_native_transaction(
            ID_1,
            plan(&windows_plan, &approval, b"windows"),
            windows_identity(),
        )
        .unwrap();
    let macos = NativeSandboxIdentity::reserved_macos(
        "0123456789abcdef0123456789abcdef".to_owned(),
        "com.contextrelay.native-runner.0123456789abcdef0123456789abcdef".to_owned(),
        canonical_macos_container(
            "com.contextrelay.native-runner.0123456789abcdef0123456789abcdef",
        ),
    );
    vault
        .begin_native_transaction(ID_3, plan(&macos_plan, &approval, b"macos"), macos.clone())
        .unwrap();
    vault.bind_macos_guardian(ID_3, 4242).unwrap();
    vault.bind_macos_bundle_root(ID_3, &mac_root(1)).unwrap();
    vault
        .finalize_macos_generation(ID_3, &Sha256Digest([2; 32]))
        .unwrap();
    vault.bind_macos_container_root(ID_3, &mac_root(3)).unwrap();
    vault
        .transition_macos_generation(ID_3, MacGenerationState::Active)
        .unwrap();
    vault
        .transition_macos_generation(ID_3, MacGenerationState::Active)
        .unwrap();
    vault
        .transition_macos_generation(ID_3, MacGenerationState::Retired)
        .unwrap();
    assert!(matches!(
        vault.transition_macos_generation(ID_3, MacGenerationState::Active),
        Err(VaultError::Validation(_))
    ));
    drop(vault);

    let vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(
        vault.native_transaction(ID_1).unwrap().unwrap().identity,
        windows_identity()
    );
    assert_eq!(
        vault.native_transaction(ID_3).unwrap().unwrap().identity,
        NativeSandboxIdentity::Macos {
            generation_id: "0123456789abcdef0123456789abcdef".to_owned(),
            bundle_id: "com.contextrelay.native-runner.0123456789abcdef0123456789abcdef".to_owned(),
            container: canonical_macos_container(
                "com.contextrelay.native-runner.0123456789abcdef0123456789abcdef",
            ),
            guardian_pgid: Some(4242),
            bundle_root: Some(mac_root(1)),
            signed_digest: Some(Sha256Digest([2; 32])),
            container_root: Some(mac_root(3)),
            substate: context_relay_core::vault::MacGenerationSubstate::ContainerBound,
            state: MacGenerationState::Retired,
        }
    );
}

#[test]
fn durable_sandbox_identities_reject_noncanonical_or_path_like_cleanup_authority() {
    let valid_moniker = "context-relay.native.0123456789abcdef0123456789abcdef";
    let valid_sid = REAL_APPCONTAINER_SID;
    let generation = "0123456789abcdef0123456789abcdef";
    let bundle = format!("com.contextrelay.native-runner.{generation}");
    let invalid = [
        NativeSandboxIdentity::Windows {
            moniker: "context-relay.native.0123456789ABCDEF0123456789ABCDEF".to_owned(),
            sid: valid_sid.to_vec(),
        },
        NativeSandboxIdentity::Windows {
            moniker: valid_moniker.to_owned(),
            sid: vec![1, 2, 3, 4],
        },
        NativeSandboxIdentity::Windows {
            moniker: valid_moniker.to_owned(),
            sid: b"S-1-15-2-1-2-3-4-5-6".to_vec(),
        },
        NativeSandboxIdentity::Windows {
            moniker: valid_moniker.to_owned(),
            sid: b"S-1-15-2-1-2-3-4-5-6-7-8".to_vec(),
        },
        NativeSandboxIdentity::Windows {
            moniker: valid_moniker.to_owned(),
            sid: b"S-1-15-2-01-2-3-4-5-6-7".to_vec(),
        },
        NativeSandboxIdentity::reserved_macos(
            generation.to_owned(),
            "com.contextrelay.native-runner.ffffffffffffffffffffffffffffffff".to_owned(),
            canonical_macos_container(&bundle),
        ),
        NativeSandboxIdentity::reserved_macos(
            generation.to_owned(),
            bundle.clone(),
            b"/private/arbitrary/path".to_vec(),
        ),
    ];

    for (index, identity) in invalid.into_iter().enumerate() {
        let path = TempVault::new(&format!("native-invalid-identity-{index}"));
        let keys = MemoryKeyStore::default();
        let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
        let plan_id = plan_id(ID_6);
        let approval = Sha256Digest([31; 32]);
        assert!(matches!(
            vault.begin_native_transaction(
                ID_5,
                plan(&plan_id, &approval, b"invalid identity"),
                identity,
            ),
            Err(VaultError::Validation(_))
        ));
    }
}

fn prepare_commit_fixture(
    vault: &mut Vault,
    transaction_id: &str,
    plan_id: &PlanId,
) -> (
    NativeApplyReceipt,
    Vec<OwnershipChange>,
    context_relay_protocol::WireNativeValue,
) {
    prepare_commit_fixture_with_policy(
        vault,
        transaction_id,
        plan_id,
        BeforeImagePolicy::new(1024, 100),
    )
}

#[test]
fn native_steps_durably_distinguish_entered_from_completed_and_reserve_step_nineteen() {
    let path = TempVault::new("native-step-journal");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let plan_id = plan_id(ID_2);
    let approval = Sha256Digest([6; 32]);
    vault
        .begin_native_transaction(
            ID_1,
            plan(&plan_id, &approval, b"step journal"),
            windows_identity(),
        )
        .unwrap();

    for step in &TransactionStep::ORDER[..18] {
        vault.enter_native_step(ID_1, *step).unwrap();
        let entered = vault.native_transaction(ID_1).unwrap().unwrap();
        assert_eq!(entered.entered_step, *step as u8);
        assert_eq!(entered.current_step, *step as u8 - 1);

        vault.complete_native_step(ID_1, *step).unwrap();
        let completed = vault.native_transaction(ID_1).unwrap().unwrap();
        assert_eq!(completed.entered_step, *step as u8);
        assert_eq!(completed.current_step, *step as u8);
    }

    vault
        .enter_native_step(ID_1, TransactionStep::CommitOwnershipAndReceipt)
        .unwrap();
    let entered = vault.native_transaction(ID_1).unwrap().unwrap();
    assert_eq!(entered.entered_step, 19);
    assert_eq!(entered.current_step, 18);
    assert!(matches!(
        vault.complete_native_step(ID_1, TransactionStep::CommitOwnershipAndReceipt),
        Err(VaultError::Validation(_))
    ));
}

fn prepare_commit_fixture_with_policy(
    vault: &mut Vault,
    transaction_id: &str,
    plan_id: &PlanId,
    policy: BeforeImagePolicy,
) -> (
    NativeApplyReceipt,
    Vec<OwnershipChange>,
    context_relay_protocol::WireNativeValue,
) {
    let approval = Sha256Digest([6; 32]);
    vault
        .begin_native_transaction(
            transaction_id,
            plan(plan_id, &approval, b"commit plan"),
            windows_identity(),
        )
        .unwrap();
    vault
        .put_before_images_batch(
            &[BeforeImageWrite {
                id: "commit-before",
                plan_id: Some(plan_id),
                payload: b"commit before image",
                created_ms: 10,
            }],
            policy,
        )
        .unwrap();
    let target = native_path();
    let token = NativeObjectToken {
        volume: vec![1],
        object: vec![2],
        topology: vec![3],
    };
    let expected = fingerprint(1);
    let applied = fingerprint(2);
    let restored = fingerprint(3);
    vault
        .prepare_native_wal(
            transaction_id,
            &wal(
                0,
                "commit-before",
                &target,
                &token,
                &expected,
                &applied,
                &restored,
            ),
        )
        .unwrap();
    vault
        .transition_native_wal_with_applied_object_token(
            transaction_id,
            0,
            NativeWalState::Applied,
            &NativeObjectToken {
                volume: vec![4],
                object: vec![5],
                topology: vec![6],
            },
        )
        .unwrap();
    let mut legacy = receipt(&plan_id.to_string(), 100);
    legacy.resulting_digests = vec![applied.0];
    let native_receipt = NativeApplyReceipt {
        legacy,
        targets: vec![NativeReceiptEntry {
            target: target.clone(),
            fingerprint: applied,
        }],
    };
    let ownership = vec![OwnershipChange {
        stable_id: "managed:item".to_owned(),
        structural_location: "instructions/0".to_owned(),
        semantic_digest: Sha256Digest([4; 32]),
        native_digest: Sha256Digest([5; 32]),
    }];
    for step in &TransactionStep::ORDER[..18] {
        vault.enter_native_step(transaction_id, *step).unwrap();
        vault.complete_native_step(transaction_id, *step).unwrap();
    }
    vault
        .enter_native_step(transaction_id, TransactionStep::CommitOwnershipAndReceipt)
        .unwrap();
    (native_receipt, ownership, target)
}

#[test]
fn terminal_cleanup_reclaims_wal_and_before_images_under_a_tiny_cap() {
    const BEFORE: &[u8] = b"commit before image";
    let path = TempVault::new("native-terminal-cleanup");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();

    for (transaction_id, plan_value) in [(ID_1, ID_2), (ID_3, ID_4)] {
        let plan_id = plan_id(plan_value);
        let (receipt, ownership, _) = prepare_commit_fixture_with_policy(
            &mut vault,
            transaction_id,
            &plan_id,
            BeforeImagePolicy::new(BEFORE.len() as u64, 1),
        );
        vault
            .commit_native_success(transaction_id, &receipt, &ownership)
            .unwrap();
        vault.finish_native_cleanup(transaction_id).unwrap();
        vault.finish_native_cleanup(transaction_id).unwrap();

        assert!(vault.native_wal(transaction_id).unwrap().is_empty());
        assert!(matches!(
            vault.native_before_image("commit-before"),
            Err(VaultError::Validation(_))
        ));
        assert_eq!(
            vault
                .native_transaction(transaction_id)
                .unwrap()
                .unwrap()
                .current_step,
            20
        );
    }
}

#[test]
fn conflict_cleanup_preserves_wal_and_before_image_evidence() {
    let path = TempVault::new("native-conflict-cleanup");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let plan_id = plan_id(ID_2);
    let _ = prepare_commit_fixture(&mut vault, ID_1, &plan_id);

    vault.begin_native_recovery(ID_1).unwrap();
    vault
        .transition_native_wal(ID_1, 0, NativeWalState::Conflict)
        .unwrap();
    vault.finish_native_recovery(ID_1, true).unwrap();
    vault.finish_native_cleanup(ID_1).unwrap();

    assert_eq!(
        vault.native_wal(ID_1).unwrap()[0].state,
        NativeWalState::Conflict
    );
    assert_eq!(
        vault.native_before_image("commit-before").unwrap(),
        b"commit before image"
    );
    let snapshot = vault.native_transaction(ID_1).unwrap().unwrap();
    assert_eq!(snapshot.status, NativeTransactionStatus::Conflict);
    assert_eq!(snapshot.current_step, 20);
}

#[test]
fn cleanup_conflict_accepts_a_durably_entered_terminal_cleanup_step() {
    let path = TempVault::new("native-entered-cleanup-conflict");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let plan_id = plan_id(ID_2);
    let (receipt, ownership, _) = prepare_commit_fixture(&mut vault, ID_1, &plan_id);
    vault
        .commit_native_success(ID_1, &receipt, &ownership)
        .unwrap();
    vault
        .enter_native_step(ID_1, TransactionStep::RestoreMatchingAppliedTargets)
        .unwrap();

    let entered = vault.native_transaction(ID_1).unwrap().unwrap();
    assert_eq!((entered.current_step, entered.entered_step), (19, 20));

    vault.mark_native_cleanup_conflict(ID_1).unwrap();
    let conflicted = vault.native_transaction(ID_1).unwrap().unwrap();
    assert_eq!(
        (
            conflicted.current_step,
            conflicted.entered_step,
            conflicted.sandbox_cleanup_state,
        ),
        (19, 20, NativeSandboxCleanupState::Conflict)
    );
    vault.mark_native_cleanup_conflict(ID_1).unwrap();
    vault.finish_native_cleanup(ID_1).unwrap();

    let finished = vault.native_transaction(ID_1).unwrap().unwrap();
    assert_eq!((finished.current_step, finished.entered_step), (20, 20));
    assert_eq!(
        finished.sandbox_cleanup_state,
        NativeSandboxCleanupState::Conflict
    );
}

#[test]
fn terminal_cleanup_is_atomic_when_before_image_deletion_fails() {
    let path = TempVault::new("native-cleanup-atomic");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let plan_id = plan_id(ID_2);
    let (receipt, ownership, _) = prepare_commit_fixture(&mut vault, ID_1, &plan_id);
    vault
        .commit_native_success(ID_1, &receipt, &ownership)
        .unwrap();
    drop(vault);

    let raw = open_keyed(path.path(), &keys.key(CREDENTIAL));
    raw.execute_batch(
        "CREATE TRIGGER fail_before_image_cleanup
         BEFORE DELETE ON before_images
         BEGIN
           SELECT RAISE(ABORT, 'injected cleanup failure');
         END;",
    )
    .unwrap();
    drop(raw);

    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert!(matches!(
        vault.finish_native_cleanup(ID_1),
        Err(VaultError::Database(_))
    ));
    assert_eq!(vault.native_wal(ID_1).unwrap().len(), 1);
    assert_eq!(
        vault.native_before_image("commit-before").unwrap(),
        b"commit before image"
    );
    assert_eq!(
        vault
            .native_transaction(ID_1)
            .unwrap()
            .unwrap()
            .current_step,
        19
    );
}

#[test]
fn step_19_commits_ownership_legacy_and_native_receipts_and_status_atomically() {
    let path = TempVault::new("native-step-19");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let success_plan = plan_id(ID_2);
    let (native_receipt, ownership, _) = prepare_commit_fixture(&mut vault, ID_1, &success_plan);
    vault
        .commit_native_success(ID_1, &native_receipt, &ownership)
        .unwrap();
    vault
        .commit_native_success(ID_1, &native_receipt, &ownership)
        .unwrap();
    assert_eq!(
        vault.native_transaction(ID_1).unwrap().unwrap().status,
        NativeTransactionStatus::Committed
    );
    assert!(vault.pending_native_transactions().unwrap().is_empty());
    assert_eq!(
        vault.receipt(&success_plan).unwrap(),
        Some(native_receipt.legacy.clone())
    );
    assert_eq!(
        vault.native_receipt(&success_plan).unwrap(),
        Some(native_receipt.clone())
    );
    assert_eq!(
        vault.native_ownership("managed:item").unwrap(),
        Some(ownership[0].clone())
    );

    let fail_path = TempVault::new("native-step-19-fault");
    let fail_keys = MemoryKeyStore::default();
    let mut fail_vault = Vault::open(fail_path.path(), CREDENTIAL, &fail_keys).unwrap();
    let fail_plan = plan_id(ID_4);
    let (fail_receipt, fail_ownership, _) =
        prepare_commit_fixture(&mut fail_vault, ID_3, &fail_plan);
    drop(fail_vault);

    let raw = open_keyed(fail_path.path(), &fail_keys.key(CREDENTIAL));
    raw.execute_batch(
        "CREATE TRIGGER fail_native_commit
         BEFORE UPDATE OF status ON native_transactions
         WHEN NEW.status = 'committed'
         BEGIN
           SELECT RAISE(ABORT, 'injected final commit failure');
         END;",
    )
    .unwrap();
    drop(raw);
    let mut fail_vault = Vault::open(fail_path.path(), CREDENTIAL, &fail_keys).unwrap();
    assert!(matches!(
        fail_vault.commit_native_success(ID_3, &fail_receipt, &fail_ownership),
        Err(VaultError::Database(_))
    ));
    drop(fail_vault);

    let raw = open_keyed(fail_path.path(), &fail_keys.key(CREDENTIAL));
    assert_eq!(
        raw.query_row(
            "SELECT status FROM native_transactions WHERE transaction_id = ?1",
            [ID_3],
            |row| row.get::<_, String>(0),
        )
        .unwrap(),
        "pending"
    );
    for (table, column, value) in [
        ("receipts", "plan_id", fail_plan.to_string()),
        ("native_receipts", "plan_id", fail_plan.to_string()),
        ("native_ownership", "stable_id", "managed:item".to_owned()),
    ] {
        assert_eq!(
            raw.query_row(
                &format!("SELECT count(*) FROM {table} WHERE {column} = ?1"),
                [value],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            0,
            "{table}"
        );
    }
}

#[test]
fn native_journal_payloads_never_appear_plaintext_in_database_files() {
    const SENTINEL: &[u8] = b"NATIVE_JOURNAL_PLAINTEXT_SENTINEL";
    let path = TempVault::new("native-journal-encryption");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let plan_id = plan_id(ID_6);
    let approval = Sha256Digest([7; 32]);
    vault
        .begin_native_transaction(
            ID_5,
            plan(&plan_id, &approval, SENTINEL),
            windows_identity(),
        )
        .unwrap();
    vault
        .put_before_images_batch(
            &[BeforeImageWrite {
                id: "secret-before",
                plan_id: Some(&plan_id),
                payload: SENTINEL,
                created_ms: 10,
            }],
            BeforeImagePolicy::new(1024, 100),
        )
        .unwrap();
    drop(vault);

    let prefix = path.path().file_name().unwrap().to_string_lossy();
    for entry in std::fs::read_dir(path.path().parent().unwrap()).unwrap() {
        let entry = entry.unwrap();
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with(prefix.as_ref())
        {
            let bytes = std::fs::read(entry.path()).unwrap();
            assert!(
                !bytes
                    .windows(SENTINEL.len())
                    .any(|window| window == SENTINEL),
                "plaintext leaked to {}",
                entry.path().display()
            );
        }
    }
}
