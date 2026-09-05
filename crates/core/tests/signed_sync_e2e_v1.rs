mod support;

use std::{collections::BTreeMap, fs, ops::RangeInclusive, str::FromStr};

use context_relay_core::{
    crypto::{CertificateIssuerV1, ContentKey, DeviceCertificateV1, DeviceKeys},
    search::Embedding384,
    sync::{
        AdmissionDecision, CanonicalCheckpoint, CanonicalOperation, CheckpointCursor,
        CheckpointPage, CheckpointReceipt, FaultSchedule, InMemoryTransport, OperationBuildRequest,
        OperationBuilder, OperationChainHead, PullPage, PushReceipt, ReceivedOperation,
        RepresentativeEmbeddingResolver, SyncEngine, SyncError, SyncIdentity, SyncProvider,
        SyncScope, SyncTransport, TransportError, TrustedDevice, TrustedSyncMaterial,
        admit_operation,
    },
    vault::{LATEST_SCHEMA_VERSION, SyncCursor, Vault},
};
use context_relay_protocol::{
    AccountId, ComponentKind, ComponentRecord, DeviceId, DeviceSequence, Ed25519SignatureBytes,
    HybridLogicalClock, OperationId, PairingRequestNonce, ProjectId, ProjectIdentity, RecordId,
    RecordKind, RecordMutationV1, ScopeRef, SecretRef, SecretRefId, Sha256Digest, WorkspaceId,
};
use rusqlite::Connection;

use support::{ID_1, ID_2, MemoryKeyStore, TempVault, basis, candidate, instruction, memory, task};

const CREDENTIAL: &str = "signed-sync-e2e-v1";
const CONTROL_EPOCH: u32 = 7;
const KEY_EPOCH: u32 = 13;
const CONTENT_KEY: [u8; 32] = [0x5a; 32];
const CANARY: &str = "TASK_16_PLAINTEXT_CANARY_DO_NOT_LEAK";
const SEED_COUNT: u64 = 256;
const MAX_ACTIONS_PER_SEED: usize = 10_000;
const RANDOM_ACTIONS_PER_SEED: usize = 3;
const ID_BASE: u64 = 0x100_000;
const RECORD_COUNT: usize = 4;

#[test]
fn randomized_replicas_converge_after_bounded_offline_faults() {
    for seed in 0..SEED_COUNT {
        let mut scenario = RandomizedScenario::new(seed, MAX_ACTIONS_PER_SEED);
        scenario.run_faulted_actions();
        let evidence = scenario.sync_until_idle();

        assert!(
            (2..=5).contains(&evidence.replicas.len()),
            "seed {seed}: invalid replica count"
        );
        assert!(
            evidence.action_count <= MAX_ACTIONS_PER_SEED,
            "seed {seed}: {} actions exceeded {MAX_ACTIONS_PER_SEED}",
            evidence.action_count
        );
        assert!(evidence.converged, "seed {seed}: drain did not become idle");
        assert_equal_frontiers(seed, &evidence);
        assert_equal_state_hashes(seed, &evidence);
        assert_equal_ordered_conflicts(seed, &evidence);
        assert_all_outboxes_empty(seed, &evidence);
        assert_no_plaintext_canary(seed, &evidence);
    }
}

#[test]
fn broken_chains_are_stably_quarantined_and_never_claim_convergence() {
    let evidence = BrokenChainScenario::new().run();

    assert!(!evidence.converged);
    assert_identical_stable_safe_reasons(&evidence);
    assert_all_outboxes_empty(0, &evidence);
    assert_no_plaintext_canary(0, &evidence);
}

#[test]
fn local_causal_successor_replaces_the_previous_record_head() {
    let mut scenario = RandomizedScenario::new(999, MAX_ACTIONS_PER_SEED);
    scenario.commit_local(0, 0, false);
    scenario.commit_local(0, 0, false);

    let heads = scenario.replicas[0]
        .vault()
        .record_heads(scope().workspace_id, scenario.record_ids[0])
        .unwrap();
    assert_eq!(heads.len(), 1);
    assert_eq!(heads[0].operation_id, generated_id(999 * ID_BASE + 2));
    assert!(
        scenario.replicas[0]
            .vault()
            .conflict(&scenario.record_ids[0])
            .unwrap()
            .is_none()
    );
}

#[test]
fn causal_tombstone_is_admitted_after_a_concurrent_delete_removed_materialization() {
    let device_a = device_fixture(20);
    let device_b = device_fixture(21);
    let observer_device = device_fixture(22);
    let trust = Trust {
        devices: [
            (device_a.certificate.device_id, device_a.certificate.clone()),
            (device_b.certificate.device_id, device_b.certificate.clone()),
            (
                observer_device.certificate.device_id,
                observer_device.certificate.clone(),
            ),
        ]
        .into_iter()
        .collect(),
        key: ContentKey::from_bytes(CONTENT_KEY),
    };
    let record_id = record_id(0);
    let upsert = RecordMutationV1::UpsertSecretRef(SecretRef {
        id: record_id.to_string().parse().unwrap(),
        name: format!("{CANARY}:tombstone-base"),
        provider: "local-keychain".to_owned(),
        required_on_device: true,
    });
    let tombstone = RecordMutationV1::Tombstone {
        record_id,
        record_kind: RecordKind::SecretRef,
    };
    let base = build_operation(&device_a, generated_id(0x20_001), &upsert, Vec::new(), None);
    let delete_b = build_operation(
        &device_b,
        generated_id(0x20_002),
        &tombstone,
        vec![DeviceSequence {
            device_id: device_a.certificate.device_id,
            sequence: 1,
        }],
        None,
    );
    let delete_a = build_operation(
        &device_a,
        generated_id(0x20_003),
        &tombstone,
        Vec::new(),
        Some(OperationChainHead {
            sequence: 1,
            canonical_hash: base.canonical_hash,
        }),
    );
    let mut transport = CapturingTransport::default();
    for operation in [&base, &delete_b, &delete_a] {
        transport
            .push_operations(scope(), &[canonical(operation)])
            .unwrap();
    }
    let mut observer = Replica::new(SEED_COUNT + 2, 0, observer_device);

    let report = SyncEngine::new(scope(), SyncProvider::Memory)
        .sync_once(
            observer.vault_mut(),
            &mut transport,
            &trust,
            &NoEmbeddings,
            4_200_000_000_000,
        )
        .unwrap();

    assert_eq!(report.quarantined, 0);
    assert_eq!(
        observer.vault().sync_checkpoint_frontier(scope()).unwrap(),
        vec![
            DeviceSequence {
                device_id: device_a.certificate.device_id,
                sequence: 2,
            },
            DeviceSequence {
                device_id: device_b.certificate.device_id,
                sequence: 1,
            },
        ]
    );
}

#[test]
fn signed_operations_cannot_reuse_a_materialized_record_id_across_sync_scopes() {
    let scope_a = scope();
    let scope_b = SyncScope {
        account_id: generated_id(0x30_001),
        workspace_id: generated_id(0x30_002),
    };
    let owner = device_fixture_in_scope(30, scope_a);
    let foreign_upserter = device_fixture_in_scope(31, scope_b);
    let foreign_deleter = device_fixture_in_scope(32, scope_b);
    let trust = Trust {
        devices: [&owner, &foreign_upserter, &foreign_deleter]
            .into_iter()
            .map(|device| (device.certificate.device_id, device.certificate.clone()))
            .collect(),
        key: ContentKey::from_bytes(CONTENT_KEY),
    };
    let record_id = record_id(0);
    let owner_mutation = RecordMutationV1::UpsertSecretRef(SecretRef {
        id: record_id.to_string().parse().unwrap(),
        name: format!("{CANARY}:scope-owner"),
        provider: "local-keychain".to_owned(),
        required_on_device: true,
    });
    let owner_operation = build_operation_in_scope(
        scope_a,
        &owner,
        generated_id(0x30_010),
        &owner_mutation,
        Vec::new(),
        None,
    );
    let path = TempVault::new("signed-sync-cross-scope-record");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault
        .commit_outgoing_operation(&owner_mutation, &owner_operation, None)
        .unwrap();

    let foreign_upsert = RecordMutationV1::UpsertSecretRef(SecretRef {
        id: record_id.to_string().parse().unwrap(),
        name: format!("{CANARY}:foreign-overwrite"),
        provider: "foreign-provider".to_owned(),
        required_on_device: false,
    });
    let foreign_upsert = build_operation_in_scope(
        scope_b,
        &foreign_upserter,
        generated_id(0x30_011),
        &foreign_upsert,
        Vec::new(),
        None,
    );
    let foreign_tombstone = RecordMutationV1::Tombstone {
        record_id,
        record_kind: RecordKind::SecretRef,
    };
    let foreign_tombstone = build_operation_in_scope(
        scope_b,
        &foreign_deleter,
        generated_id(0x30_012),
        &foreign_tombstone,
        Vec::new(),
        None,
    );

    for operation in [&foreign_upsert, &foreign_tombstone] {
        assert_eq!(
            admit_operation(&vault, &operation.canonical_bytes, &trust).unwrap_err(),
            SyncError::InvalidScope
        );
    }
    assert_eq!(
        vault
            .secret_ref(&record_id.to_string().parse::<SecretRefId>().unwrap())
            .unwrap()
            .unwrap()
            .name,
        format!("{CANARY}:scope-owner")
    );
    assert_eq!(
        vault
            .record_heads(scope_a.workspace_id, record_id)
            .unwrap()
            .len(),
        1
    );
    assert!(
        vault
            .record_heads(scope_b.workspace_id, record_id)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn signed_operations_cannot_claim_an_ownerless_offline_record_id() {
    let foreign_scope = SyncScope {
        account_id: generated_id(0x31_001),
        workspace_id: generated_id(0x31_002),
    };
    let foreign_upserter = device_fixture_in_scope(33, foreign_scope);
    let foreign_deleter = device_fixture_in_scope(34, foreign_scope);
    let trust = Trust {
        devices: [&foreign_upserter, &foreign_deleter]
            .into_iter()
            .map(|device| (device.certificate.device_id, device.certificate.clone()))
            .collect(),
        key: ContentKey::from_bytes(CONTENT_KEY),
    };
    let record_id = record_id(1);
    let offline = memory(
        &record_id.to_string(),
        ScopeRef::Global,
        "offline owner",
        &format!("{CANARY}:offline-owner"),
    );
    let path = TempVault::new("signed-sync-ownerless-offline-record");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault.put_local_memory(&offline, &basis(0)).unwrap();

    let mut overwrite = offline.clone();
    overwrite.title = "foreign overwrite".to_owned();
    overwrite.body_markdown = format!("{CANARY}:foreign-overwrite");
    let foreign_upsert = build_operation_in_scope(
        foreign_scope,
        &foreign_upserter,
        generated_id(0x31_010),
        &RecordMutationV1::UpsertMemory(overwrite),
        Vec::new(),
        None,
    );
    let foreign_tombstone = build_operation_in_scope(
        foreign_scope,
        &foreign_deleter,
        generated_id(0x31_011),
        &RecordMutationV1::Tombstone {
            record_id,
            record_kind: RecordKind::Memory,
        },
        Vec::new(),
        None,
    );

    for operation in [&foreign_upsert, &foreign_tombstone] {
        assert_eq!(
            admit_operation(&vault, &operation.canonical_bytes, &trust).unwrap_err(),
            SyncError::InvalidScope
        );
    }
    assert_eq!(vault.memory(&offline.id).unwrap(), Some(offline));
    assert!(
        vault
            .record_heads(foreign_scope.workspace_id, record_id)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn explicit_offline_record_binding_allows_only_the_matching_sync_scope() {
    let owner_scope = scope();
    let owner_device = device_fixture_in_scope(35, owner_scope);
    let record_id = record_id(2);
    let offline = memory(
        &record_id.to_string(),
        ScopeRef::Global,
        "offline owner",
        &format!("{CANARY}:explicit-bind"),
    );
    let path = TempVault::new("signed-sync-explicit-offline-binding");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault.put_local_memory(&offline, &basis(0)).unwrap();

    vault
        .bind_sync_record_owner(owner_scope, record_id, RecordKind::Memory)
        .unwrap();
    vault
        .bind_sync_record_owner(owner_scope, record_id, RecordKind::Memory)
        .unwrap();
    assert!(
        vault
            .bind_sync_record_owner(
                SyncScope {
                    account_id: generated_id(0x32_001),
                    workspace_id: generated_id(0x32_002),
                },
                record_id,
                RecordKind::Memory,
            )
            .is_err()
    );
    assert!(
        vault
            .bind_sync_record_owner(owner_scope, record_id, RecordKind::Instruction)
            .is_err()
    );

    let mut updated = offline.clone();
    updated.title = "matching scope update".to_owned();
    let mutation = RecordMutationV1::UpsertMemory(updated.clone());
    let operation = build_operation_in_scope(
        owner_scope,
        &owner_device,
        generated_id(0x32_010),
        &mutation,
        Vec::new(),
        None,
    );
    vault
        .commit_outgoing_operation(&mutation, &operation, Some(&basis(1)))
        .unwrap();
    assert_eq!(vault.memory(&offline.id).unwrap(), Some(updated));
}

#[test]
fn sync_record_owner_survives_tombstone_and_blocks_foreign_reuse() {
    let owner_scope = scope();
    let foreign_scope = SyncScope {
        account_id: generated_id(0x33_001),
        workspace_id: generated_id(0x33_002),
    };
    let owner = device_fixture_in_scope(36, owner_scope);
    let foreign = device_fixture_in_scope(37, foreign_scope);
    let trust = Trust {
        devices: [&owner, &foreign]
            .into_iter()
            .map(|device| (device.certificate.device_id, device.certificate.clone()))
            .collect(),
        key: ContentKey::from_bytes(CONTENT_KEY),
    };
    let record_id = record_id(3);
    let upsert = RecordMutationV1::UpsertSecretRef(SecretRef {
        id: record_id.to_string().parse().unwrap(),
        name: format!("{CANARY}:durable-owner"),
        provider: "local-keychain".to_owned(),
        required_on_device: true,
    });
    let first = build_operation_in_scope(
        owner_scope,
        &owner,
        generated_id(0x33_010),
        &upsert,
        Vec::new(),
        None,
    );
    let tombstone = RecordMutationV1::Tombstone {
        record_id,
        record_kind: RecordKind::SecretRef,
    };
    let second = build_operation_in_scope(
        owner_scope,
        &owner,
        generated_id(0x33_011),
        &tombstone,
        Vec::new(),
        Some(OperationChainHead {
            sequence: 1,
            canonical_hash: first.canonical_hash,
        }),
    );
    let path = TempVault::new("signed-sync-owner-survives-tombstone");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault
        .commit_outgoing_operation(&upsert, &first, None)
        .unwrap();
    vault
        .commit_outgoing_operation(&tombstone, &second, None)
        .unwrap();
    assert!(
        vault
            .secret_ref(&record_id.to_string().parse().unwrap())
            .unwrap()
            .is_none()
    );

    let foreign_upsert = build_operation_in_scope(
        foreign_scope,
        &foreign,
        generated_id(0x33_012),
        &upsert,
        Vec::new(),
        None,
    );
    assert_eq!(
        admit_operation(&vault, &foreign_upsert.canonical_bytes, &trust).unwrap_err(),
        SyncError::InvalidScope
    );
}

#[test]
fn sync_record_owner_migration_backfills_and_rejects_collisions() {
    let migrated = Connection::open_in_memory().unwrap();
    create_owner_migration_inputs(&migrated);
    insert_owner_migration_head(&migrated, "op-a", scope(), record_id(0), "memory");
    migrated
        .execute_batch(include_str!("../migrations/0019_sync_record_owners.sql"))
        .unwrap();
    let owner = migrated
        .query_row(
            "SELECT account_id, workspace_id, record_kind, binding_state
             FROM sync_record_owners WHERE record_id = ?1",
            [record_id(0).to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(
        owner,
        (
            scope().account_id.to_string(),
            scope().workspace_id.to_string(),
            "memory".to_owned(),
            "legacy_pending".to_owned()
        )
    );

    let mut collision = Connection::open_in_memory().unwrap();
    create_owner_migration_inputs(&collision);
    insert_owner_migration_head(&collision, "op-a", scope(), record_id(0), "memory");
    insert_owner_migration_head(
        &collision,
        "op-b",
        SyncScope {
            account_id: generated_id(0x34_001),
            workspace_id: generated_id(0x34_002),
        },
        record_id(0),
        "memory",
    );
    let migration = collision.transaction().unwrap();
    assert!(
        migration
            .execute_batch(include_str!("../migrations/0019_sync_record_owners.sql"))
            .is_err()
    );
    drop(migration);
    assert_eq!(
        collision
            .query_row(
                "SELECT count(*) FROM sqlite_master
                 WHERE type = 'table' AND name = 'sync_record_owners'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0
    );
}

#[test]
fn legacy_pending_owner_can_be_explicitly_rebound_to_the_restored_local_scope() {
    let stale_scope = SyncScope {
        account_id: generated_id(0x36_001),
        workspace_id: generated_id(0x36_002),
    };
    let restored_scope = SyncScope {
        account_id: generated_id(0x36_003),
        workspace_id: generated_id(0x36_004),
    };
    let stale_device = device_fixture_in_scope(40, stale_scope);
    let trust = Trust {
        devices: [(
            stale_device.certificate.device_id,
            stale_device.certificate.clone(),
        )]
        .into_iter()
        .collect(),
        key: ContentKey::from_bytes(CONTENT_KEY),
    };
    let record_id = record_id(6);
    let stale = memory(
        &record_id.to_string(),
        ScopeRef::Global,
        "stale signed owner",
        &format!("{CANARY}:stale-owner-before-restore"),
    );
    let first = build_operation_in_scope(
        stale_scope,
        &stale_device,
        generated_id(0x36_010),
        &RecordMutationV1::UpsertMemory(stale.clone()),
        Vec::new(),
        None,
    );
    let path = TempVault::new("signed-sync-schema-18-explicit-rebind");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault
        .commit_outgoing_operation(
            &RecordMutationV1::UpsertMemory(stale),
            &first,
            Some(&basis(0)),
        )
        .unwrap();
    let restored = memory(
        &record_id.to_string(),
        ScopeRef::Global,
        "restored under selected scope",
        &format!("{CANARY}:restored-explicit-owner"),
    );
    vault.put_local_memory(&restored, &basis(1)).unwrap();
    drop(vault);
    downgrade_to_schema_18(path.path(), &keys);

    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault
        .bind_sync_record_owner(restored_scope, record_id, RecordKind::Memory)
        .unwrap();
    assert!(
        vault
            .bind_sync_record_owner(stale_scope, record_id, RecordKind::Memory)
            .is_err(),
        "verified ownership must remain immutable after explicit reconciliation"
    );
    let stale_overwrite = RecordMutationV1::UpsertMemory(memory(
        &record_id.to_string(),
        ScopeRef::Global,
        "stale scope overwrite",
        &format!("{CANARY}:stale-scope-after-rebind"),
    ));
    let stale_overwrite = build_operation_in_scope(
        stale_scope,
        &stale_device,
        generated_id(0x36_011),
        &stale_overwrite,
        Vec::new(),
        Some(OperationChainHead {
            sequence: 1,
            canonical_hash: first.canonical_hash,
        }),
    );
    assert_eq!(
        admit_operation(&vault, &stale_overwrite.canonical_bytes, &trust).unwrap_err(),
        SyncError::InvalidScope
    );
    assert_eq!(vault.memory(&restored.id).unwrap(), Some(restored));
    drop(vault);
    let raw = open_keyed_vault(path.path(), &keys.key(CREDENTIAL));
    assert_eq!(
        sync_owner(&raw, record_id),
        (
            restored_scope.account_id.to_string(),
            restored_scope.workspace_id.to_string(),
            "memory".to_owned(),
            "verified".to_owned(),
        )
    );
}

#[test]
fn legacy_pending_owner_auto_promotes_when_the_stored_upsert_is_still_materialized() {
    let sync_scope = SyncScope {
        account_id: generated_id(0x38_001),
        workspace_id: generated_id(0x38_002),
    };
    let device = device_fixture_in_scope(44, sync_scope);
    let trust = Trust {
        devices: [(device.certificate.device_id, device.certificate.clone())]
            .into_iter()
            .collect(),
        key: ContentKey::from_bytes(CONTENT_KEY),
    };
    let record_id = record_id(8);
    let original = memory(
        &record_id.to_string(),
        ScopeRef::Global,
        "signed original",
        &format!("{CANARY}:signed-original"),
    );
    let first = build_operation_in_scope(
        sync_scope,
        &device,
        generated_id(0x38_010),
        &RecordMutationV1::UpsertMemory(original.clone()),
        Vec::new(),
        None,
    );
    let path = TempVault::new("signed-sync-schema-18-matching-upsert");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault
        .commit_outgoing_operation(
            &RecordMutationV1::UpsertMemory(original.clone()),
            &first,
            Some(&basis(0)),
        )
        .unwrap();
    drop(vault);
    downgrade_to_schema_18(path.path(), &keys);

    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let updated = memory(
        &record_id.to_string(),
        ScopeRef::Global,
        "signed successor",
        &format!("{CANARY}:signed-successor"),
    );
    let second = build_operation_in_scope(
        sync_scope,
        &device,
        generated_id(0x38_011),
        &RecordMutationV1::UpsertMemory(updated.clone()),
        Vec::new(),
        Some(OperationChainHead {
            sequence: 1,
            canonical_hash: first.canonical_hash,
        }),
    );
    assert!(
        vault
            .commit_outgoing_operation(
                &RecordMutationV1::UpsertMemory(updated.clone()),
                &second,
                Some(&basis(1)),
            )
            .is_err(),
        "outgoing commit must not promote a pending owner without trusted material"
    );
    assert_eq!(vault.memory(&original.id).unwrap(), Some(original.clone()));
    let admitted = match admit_operation(&vault, &second.canonical_bytes, &trust).unwrap() {
        AdmissionDecision::Admitted(admitted) => admitted,
        other => panic!("unexpected matching-upsert admission: {other:?}"),
    };
    assert!(
        vault
            .apply_admitted_operation(
                &admitted,
                &trust,
                "memory",
                "2026-08-09T00:01:59Z",
                &NoEmbeddings,
            )
            .is_err(),
        "a post-promotion apply failure must roll the promotion back"
    );
    assert_eq!(vault.memory(&original.id).unwrap(), Some(original));
    drop(vault);
    let raw = open_keyed_vault(path.path(), &keys.key(CREDENTIAL));
    assert_eq!(sync_owner(&raw, record_id).3, "legacy_pending");
    drop(raw);
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault
        .apply_admitted_operation(
            &admitted,
            &trust,
            "memory",
            "2026-08-09T00:02:00Z",
            &FixedEmbedding,
        )
        .unwrap();
    assert_eq!(vault.memory(&updated.id).unwrap(), Some(updated));
    drop(vault);
    let raw = open_keyed_vault(path.path(), &keys.key(CREDENTIAL));
    assert_eq!(sync_owner(&raw, record_id).3, "verified");
}

#[test]
fn legacy_pending_tombstone_auto_promotes_only_while_materialization_is_absent() {
    let sync_scope = SyncScope {
        account_id: generated_id(0x39_001),
        workspace_id: generated_id(0x39_002),
    };
    let device = device_fixture_in_scope(45, sync_scope);
    let trust = Trust {
        devices: [(device.certificate.device_id, device.certificate.clone())]
            .into_iter()
            .collect(),
        key: ContentKey::from_bytes(CONTENT_KEY),
    };
    let record_id = record_id(9);
    let original = memory(
        &record_id.to_string(),
        ScopeRef::Global,
        "signed before tombstone",
        &format!("{CANARY}:signed-before-tombstone"),
    );
    let first = build_operation_in_scope(
        sync_scope,
        &device,
        generated_id(0x39_010),
        &RecordMutationV1::UpsertMemory(original.clone()),
        Vec::new(),
        None,
    );
    let tombstone = RecordMutationV1::Tombstone {
        record_id,
        record_kind: RecordKind::Memory,
    };
    let second = build_operation_in_scope(
        sync_scope,
        &device,
        generated_id(0x39_011),
        &tombstone,
        Vec::new(),
        Some(OperationChainHead {
            sequence: 1,
            canonical_hash: first.canonical_hash,
        }),
    );
    let path = TempVault::new("signed-sync-schema-18-matching-tombstone");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault
        .commit_outgoing_operation(
            &RecordMutationV1::UpsertMemory(original),
            &first,
            Some(&basis(0)),
        )
        .unwrap();
    vault
        .commit_outgoing_operation(&tombstone, &second, None)
        .unwrap();
    drop(vault);
    downgrade_to_schema_18(path.path(), &keys);

    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert!(
        vault
            .bind_sync_record_owner(sync_scope, record_id, RecordKind::Memory)
            .is_err(),
        "an absent pending tombstone cannot be explicitly rebound"
    );
    let restored = memory(
        &record_id.to_string(),
        ScopeRef::Global,
        "signed after tombstone",
        &format!("{CANARY}:signed-after-tombstone"),
    );
    let third = build_operation_in_scope(
        sync_scope,
        &device,
        generated_id(0x39_012),
        &RecordMutationV1::UpsertMemory(restored.clone()),
        Vec::new(),
        Some(OperationChainHead {
            sequence: 2,
            canonical_hash: second.canonical_hash,
        }),
    );
    let admitted = match admit_operation(&vault, &third.canonical_bytes, &trust).unwrap() {
        AdmissionDecision::Admitted(admitted) => admitted,
        other => panic!("unexpected matching-tombstone admission: {other:?}"),
    };
    vault
        .apply_admitted_operation(
            &admitted,
            &trust,
            "memory",
            "2026-08-09T00:03:00Z",
            &FixedEmbedding,
        )
        .unwrap();
    assert_eq!(vault.memory(&restored.id).unwrap(), Some(restored));
    drop(vault);
    let raw = open_keyed_vault(path.path(), &keys.key(CREDENTIAL));
    assert_eq!(sync_owner(&raw, record_id).3, "verified");
}

#[test]
fn legacy_pending_tombstone_rejects_a_recreated_local_materialization() {
    let sync_scope = SyncScope {
        account_id: generated_id(0x3a_001),
        workspace_id: generated_id(0x3a_002),
    };
    let device = device_fixture_in_scope(46, sync_scope);
    let trust = Trust {
        devices: [(device.certificate.device_id, device.certificate.clone())]
            .into_iter()
            .collect(),
        key: ContentKey::from_bytes(CONTENT_KEY),
    };
    let record_id = record_id(10);
    let original = memory(
        &record_id.to_string(),
        ScopeRef::Global,
        "signed before stale tombstone",
        &format!("{CANARY}:signed-before-stale-tombstone"),
    );
    let first = build_operation_in_scope(
        sync_scope,
        &device,
        generated_id(0x3a_010),
        &RecordMutationV1::UpsertMemory(original.clone()),
        Vec::new(),
        None,
    );
    let tombstone = RecordMutationV1::Tombstone {
        record_id,
        record_kind: RecordKind::Memory,
    };
    let second = build_operation_in_scope(
        sync_scope,
        &device,
        generated_id(0x3a_011),
        &tombstone,
        Vec::new(),
        Some(OperationChainHead {
            sequence: 1,
            canonical_hash: first.canonical_hash,
        }),
    );
    let path = TempVault::new("signed-sync-schema-18-stale-tombstone");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault
        .commit_outgoing_operation(
            &RecordMutationV1::UpsertMemory(original),
            &first,
            Some(&basis(0)),
        )
        .unwrap();
    vault
        .commit_outgoing_operation(&tombstone, &second, None)
        .unwrap();
    let restored = memory(
        &record_id.to_string(),
        ScopeRef::Global,
        "restored after signed tombstone",
        &format!("{CANARY}:restored-after-signed-tombstone"),
    );
    vault.put_local_memory(&restored, &basis(1)).unwrap();
    drop(vault);
    downgrade_to_schema_18(path.path(), &keys);

    let vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let third = build_operation_in_scope(
        sync_scope,
        &device,
        generated_id(0x3a_012),
        &RecordMutationV1::UpsertMemory(memory(
            &record_id.to_string(),
            ScopeRef::Global,
            "incoming after stale tombstone",
            &format!("{CANARY}:incoming-after-stale-tombstone"),
        )),
        Vec::new(),
        Some(OperationChainHead {
            sequence: 2,
            canonical_hash: second.canonical_hash,
        }),
    );
    assert_eq!(
        admit_operation(&vault, &third.canonical_bytes, &trust).unwrap_err(),
        SyncError::InvalidScope
    );
    assert_eq!(vault.memory(&restored.id).unwrap(), Some(restored));
    drop(vault);
    let raw = open_keyed_vault(path.path(), &keys.key(CREDENTIAL));
    assert_eq!(sync_owner(&raw, record_id).3, "legacy_pending");
}

#[test]
fn legacy_pending_typed_rehydration_covers_every_non_memory_upsert_kind() {
    for (index, mutation) in typed_owner_mutations().into_iter().enumerate() {
        let sync_scope = SyncScope {
            account_id: generated_id(0x3b_001 + index as u64),
            workspace_id: generated_id(0x3b_101 + index as u64),
        };
        let device = device_fixture_in_scope(47 + index, sync_scope);
        let trust = Trust {
            devices: [(device.certificate.device_id, device.certificate.clone())]
                .into_iter()
                .collect(),
            key: ContentKey::from_bytes(CONTENT_KEY),
        };
        let first = build_operation_in_scope(
            sync_scope,
            &device,
            generated_id(0x3b_200 + index as u64 * 4),
            &mutation,
            Vec::new(),
            None,
        );
        let embedding = basis(20 + index);
        let maybe_embedding =
            matches!(mutation, RecordMutationV1::UpsertInstruction(_)).then_some(&embedding);

        let matching_path = TempVault::new(&format!("signed-sync-typed-match-{index}"));
        let matching_keys = MemoryKeyStore::default();
        let mut matching = Vault::open(matching_path.path(), CREDENTIAL, &matching_keys).unwrap();
        matching
            .commit_outgoing_operation(&mutation, &first, maybe_embedding)
            .unwrap();
        drop(matching);
        downgrade_to_schema_18(matching_path.path(), &matching_keys);
        let mut matching = Vault::open(matching_path.path(), CREDENTIAL, &matching_keys).unwrap();
        let successor = build_operation_in_scope(
            sync_scope,
            &device,
            generated_id(0x3b_201 + index as u64 * 4),
            &mutation,
            Vec::new(),
            Some(OperationChainHead {
                sequence: 1,
                canonical_hash: first.canonical_hash,
            }),
        );
        let admitted = match admit_operation(&matching, &successor.canonical_bytes, &trust).unwrap()
        {
            AdmissionDecision::Admitted(admitted) => admitted,
            other => panic!(
                "unexpected typed admission for {:?}: {other:?}",
                mutation.record_kind()
            ),
        };
        matching
            .apply_admitted_operation(
                &admitted,
                &trust,
                "memory",
                &format!("2026-08-09T00:05:{index:02}Z"),
                &FixedEmbedding,
            )
            .unwrap();
        drop(matching);
        let raw = open_keyed_vault(matching_path.path(), &matching_keys.key(CREDENTIAL));
        assert_eq!(
            sync_owner(&raw, mutation.record_id()).3,
            "verified",
            "matching {:?} did not promote",
            mutation.record_kind()
        );

        let mismatch_path = TempVault::new(&format!("signed-sync-typed-mismatch-{index}"));
        let mismatch_keys = MemoryKeyStore::default();
        let mut mismatch = Vault::open(mismatch_path.path(), CREDENTIAL, &mismatch_keys).unwrap();
        mismatch
            .commit_outgoing_operation(&mutation, &first, maybe_embedding)
            .unwrap();
        drop(mismatch);
        let raw = open_keyed_vault(mismatch_path.path(), &mismatch_keys.key(CREDENTIAL));
        support::remove_native_memory_migrations_after_schema_23(&raw);
        replace_materialized_payload(&raw, &changed_typed_mutation(mutation.clone()));
        raw.execute_batch(
            "DROP TABLE recovery_restores;
             DROP TABLE recovery_enrollments;
             DROP TABLE pairing_approval_transcripts;
             DROP TABLE pairing_joins;
             DROP TABLE pairing_decisions;
             DROP TABLE device_certificates;
             DROP TABLE sync_record_owners;
             PRAGMA user_version = 18;",
        )
        .unwrap();
        drop(raw);
        let mismatch = Vault::open(mismatch_path.path(), CREDENTIAL, &mismatch_keys).unwrap();
        let successor = build_operation_in_scope(
            sync_scope,
            &device,
            generated_id(0x3b_202 + index as u64 * 4),
            &mutation,
            Vec::new(),
            Some(OperationChainHead {
                sequence: 1,
                canonical_hash: first.canonical_hash,
            }),
        );
        assert_eq!(
            admit_operation(&mismatch, &successor.canonical_bytes, &trust).unwrap_err(),
            SyncError::InvalidScope,
            "changed {:?} materialization was accepted",
            mutation.record_kind()
        );
        drop(mismatch);
        let raw = open_keyed_vault(mismatch_path.path(), &mismatch_keys.key(CREDENTIAL));
        assert_eq!(sync_owner(&raw, mutation.record_id()).3, "legacy_pending");
    }
}

#[test]
fn legacy_pending_multi_head_owner_uses_the_deterministic_representative() {
    let stale_scope = SyncScope {
        account_id: generated_id(0x37_001),
        workspace_id: generated_id(0x37_002),
    };
    let device_a = device_fixture_in_scope(41, stale_scope);
    let device_b = device_fixture_in_scope(42, stale_scope);
    let device_c = device_fixture_in_scope(43, stale_scope);
    let trust = Trust {
        devices: [&device_a, &device_b, &device_c]
            .into_iter()
            .map(|device| (device.certificate.device_id, device.certificate.clone()))
            .collect(),
        key: ContentKey::from_bytes(CONTENT_KEY),
    };
    let record_id = record_id(7);
    let first_record = memory(
        &record_id.to_string(),
        ScopeRef::Global,
        "first conflict head",
        &format!("{CANARY}:first-conflict-head"),
    );
    let second_record = memory(
        &record_id.to_string(),
        ScopeRef::Global,
        "second conflict head",
        &format!("{CANARY}:second-conflict-head"),
    );
    let first = build_operation_in_scope(
        stale_scope,
        &device_a,
        generated_id(0x37_010),
        &RecordMutationV1::UpsertMemory(first_record.clone()),
        Vec::new(),
        None,
    );
    let second = build_operation_in_scope(
        stale_scope,
        &device_b,
        generated_id(0x37_011),
        &RecordMutationV1::UpsertMemory(second_record),
        Vec::new(),
        None,
    );
    let path = TempVault::new("signed-sync-schema-18-multi-head-pending");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault
        .commit_outgoing_operation(
            &RecordMutationV1::UpsertMemory(first_record),
            &first,
            Some(&basis(0)),
        )
        .unwrap();
    let second = match admit_operation(&vault, &second.canonical_bytes, &trust).unwrap() {
        AdmissionDecision::Admitted(admitted) => admitted,
        other => panic!("unexpected conflict admission: {other:?}"),
    };
    vault
        .apply_admitted_operation(
            &second,
            &trust,
            "memory",
            "2026-08-09T00:01:00Z",
            &FixedEmbedding,
        )
        .unwrap();
    assert_eq!(
        vault
            .record_heads(stale_scope.workspace_id, record_id)
            .unwrap()
            .len(),
        2
    );
    drop(vault);
    downgrade_to_schema_18(path.path(), &keys);
    let vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();

    let third = build_operation_in_scope(
        stale_scope,
        &device_c,
        generated_id(0x37_012),
        &RecordMutationV1::UpsertMemory(memory(
            &record_id.to_string(),
            ScopeRef::Global,
            "third conflict head",
            &format!("{CANARY}:third-conflict-head"),
        )),
        Vec::new(),
        None,
    );
    let admitted = match admit_operation(&vault, &third.canonical_bytes, &trust).unwrap() {
        AdmissionDecision::Admitted(admitted) => admitted,
        other => panic!("unexpected multi-head admission: {other:?}"),
    };
    let mut vault = vault;
    vault
        .apply_admitted_operation(
            &admitted,
            &trust,
            "memory",
            "2026-08-09T00:04:00Z",
            &FixedEmbedding,
        )
        .unwrap();
    assert_eq!(
        vault
            .record_heads(stale_scope.workspace_id, record_id)
            .unwrap()
            .len(),
        3
    );
    drop(vault);
    let raw = open_keyed_vault(path.path(), &keys.key(CREDENTIAL));
    assert_eq!(sync_owner(&raw, record_id).3, "verified");
}

#[test]
fn schema_18_upgrade_does_not_let_stale_sync_heads_claim_later_local_records() {
    let stale_scope = SyncScope {
        account_id: generated_id(0x35_001),
        workspace_id: generated_id(0x35_002),
    };
    let upserter = device_fixture_in_scope(38, stale_scope);
    let deleter = device_fixture_in_scope(39, stale_scope);
    let trust = Trust {
        devices: [&upserter, &deleter]
            .into_iter()
            .map(|device| (device.certificate.device_id, device.certificate.clone()))
            .collect(),
        key: ContentKey::from_bytes(CONTENT_KEY),
    };
    let upsert_id = record_id(4);
    let tombstone_id = record_id(5);
    let signed_upsert = memory(
        &upsert_id.to_string(),
        ScopeRef::Global,
        "stale signed upsert",
        &format!("{CANARY}:stale-signed-upsert"),
    );
    let signed_tombstone = memory(
        &tombstone_id.to_string(),
        ScopeRef::Global,
        "stale signed tombstone",
        &format!("{CANARY}:stale-signed-tombstone"),
    );
    let first_upsert = build_operation_in_scope(
        stale_scope,
        &upserter,
        generated_id(0x35_010),
        &RecordMutationV1::UpsertMemory(signed_upsert),
        Vec::new(),
        None,
    );
    let first_tombstone = build_operation_in_scope(
        stale_scope,
        &deleter,
        generated_id(0x35_011),
        &RecordMutationV1::UpsertMemory(signed_tombstone),
        Vec::new(),
        None,
    );
    let path = TempVault::new("signed-sync-schema-18-local-override");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault
        .commit_outgoing_operation(
            &RecordMutationV1::UpsertMemory(memory(
                &upsert_id.to_string(),
                ScopeRef::Global,
                "stale signed upsert",
                &format!("{CANARY}:stale-signed-upsert"),
            )),
            &first_upsert,
            Some(&basis(0)),
        )
        .unwrap();
    vault
        .commit_outgoing_operation(
            &RecordMutationV1::UpsertMemory(memory(
                &tombstone_id.to_string(),
                ScopeRef::Global,
                "stale signed tombstone",
                &format!("{CANARY}:stale-signed-tombstone"),
            )),
            &first_tombstone,
            Some(&basis(1)),
        )
        .unwrap();

    let restored_upsert = memory(
        &upsert_id.to_string(),
        ScopeRef::Global,
        "restored local upsert",
        &format!("{CANARY}:restored-local-upsert"),
    );
    let restored_tombstone = memory(
        &tombstone_id.to_string(),
        ScopeRef::Global,
        "restored local tombstone",
        &format!("{CANARY}:restored-local-tombstone"),
    );
    vault.put_local_memory(&restored_upsert, &basis(2)).unwrap();
    vault
        .put_local_memory(&restored_tombstone, &basis(3))
        .unwrap();
    drop(vault);

    let raw = open_keyed_vault(path.path(), &keys.key(CREDENTIAL));
    support::remove_native_memory_migrations_after_schema_23(&raw);
    raw.execute_batch(
        "DROP TABLE recovery_restores;
         DROP TABLE recovery_enrollments;
         DROP TABLE pairing_approval_transcripts;
         DROP TABLE pairing_joins;
         DROP TABLE pairing_decisions;
         DROP TABLE device_certificates;
         DROP TABLE sync_record_owners;
         PRAGMA user_version = 18;",
    )
    .unwrap();
    drop(raw);
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(vault.schema_version().unwrap(), LATEST_SCHEMA_VERSION);

    let overwrite = RecordMutationV1::UpsertMemory(memory(
        &upsert_id.to_string(),
        ScopeRef::Global,
        "foreign post-upgrade overwrite",
        &format!("{CANARY}:foreign-post-upgrade-overwrite"),
    ));
    let overwrite = build_operation_in_scope(
        stale_scope,
        &upserter,
        generated_id(0x35_012),
        &overwrite,
        Vec::new(),
        Some(OperationChainHead {
            sequence: 1,
            canonical_hash: first_upsert.canonical_hash,
        }),
    );
    let tombstone = build_operation_in_scope(
        stale_scope,
        &deleter,
        generated_id(0x35_013),
        &RecordMutationV1::Tombstone {
            record_id: tombstone_id,
            record_kind: RecordKind::Memory,
        },
        Vec::new(),
        Some(OperationChainHead {
            sequence: 1,
            canonical_hash: first_tombstone.canonical_hash,
        }),
    );
    let mut outcomes = Vec::new();
    for (index, operation) in [&overwrite, &tombstone].into_iter().enumerate() {
        match admit_operation(&vault, &operation.canonical_bytes, &trust) {
            Ok(AdmissionDecision::Admitted(admitted)) => {
                outcomes.push(None);
                vault
                    .apply_admitted_operation(
                        &admitted,
                        &trust,
                        "memory",
                        &format!("2026-08-09T00:00:0{}Z", index + 1),
                        &FixedEmbedding,
                    )
                    .unwrap();
            }
            Ok(other) => panic!("unexpected post-upgrade admission decision: {other:?}"),
            Err(error) => outcomes.push(Some(error)),
        }
    }

    assert_eq!(
        (
            vault.memory(&restored_upsert.id).unwrap(),
            vault.memory(&restored_tombstone.id).unwrap(),
        ),
        (
            Some(restored_upsert.clone()),
            Some(restored_tombstone.clone()),
        ),
        "schema-18 migration let stale scope outcomes {outcomes:?} mutate restored rows"
    );
    assert_eq!(
        outcomes,
        vec![Some(SyncError::InvalidScope), Some(SyncError::InvalidScope)]
    );
}

struct DeviceFixture {
    keys: DeviceKeys,
    certificate: DeviceCertificateV1,
}

struct Trust {
    devices: BTreeMap<DeviceId, DeviceCertificateV1>,
    key: ContentKey,
}

impl TrustedSyncMaterial for Trust {
    fn trusted_device(
        &self,
        _account: AccountId,
        _workspace: WorkspaceId,
        device: DeviceId,
    ) -> Result<TrustedDevice, SyncError> {
        Ok(TrustedDevice {
            certificate: self
                .devices
                .get(&device)
                .cloned()
                .ok_or(SyncError::InvalidIdentity)?,
            active_control_epoch: CONTROL_EPOCH,
            active_key_epoch: KEY_EPOCH,
        })
    }

    fn content_key(
        &self,
        _workspace: WorkspaceId,
        _key_epoch: u32,
    ) -> Result<&ContentKey, SyncError> {
        Ok(&self.key)
    }
}

struct NoEmbeddings;

impl RepresentativeEmbeddingResolver for NoEmbeddings {
    fn resolve_representative_embedding(
        &self,
        _operation_id: OperationId,
        _mutation: &RecordMutationV1,
    ) -> Result<Option<Embedding384>, SyncError> {
        Ok(None)
    }
}

struct FixedEmbedding;

impl RepresentativeEmbeddingResolver for FixedEmbedding {
    fn resolve_representative_embedding(
        &self,
        _operation_id: OperationId,
        _mutation: &RecordMutationV1,
    ) -> Result<Option<Embedding384>, SyncError> {
        Ok(Some(basis(9)))
    }
}

struct Replica {
    path: TempVault,
    keys: MemoryKeyStore,
    vault: Option<Vault>,
    device: DeviceFixture,
    connected: bool,
}

impl Replica {
    fn new(seed: u64, index: usize, device: DeviceFixture) -> Self {
        let path = TempVault::new(&format!("signed-sync-e2e-{seed}-{index}"));
        let keys = MemoryKeyStore::default();
        let vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
        Self {
            path,
            keys,
            vault: Some(vault),
            device,
            connected: true,
        }
    }

    fn vault(&self) -> &Vault {
        self.vault.as_ref().unwrap()
    }

    fn vault_mut(&mut self) -> &mut Vault {
        self.vault.as_mut().unwrap()
    }

    fn crash_and_reopen(&mut self) {
        drop(self.vault.take());
        self.vault = Some(Vault::open(self.path.path(), CREDENTIAL, &self.keys).unwrap());
    }
}

#[derive(Default)]
struct CapturingTransport {
    inner: InMemoryTransport,
    captured_bytes: Vec<Vec<u8>>,
}

impl CapturingTransport {
    fn schedule_faults(&mut self, faults: FaultSchedule) {
        self.inner.schedule_faults(faults);
    }

    fn take_change_hint(&mut self, scope: SyncScope) -> bool {
        self.inner.take_change_hint(scope)
    }

    fn capture_operations<'a>(
        &mut self,
        operations: impl IntoIterator<Item = &'a CanonicalOperation>,
    ) {
        self.captured_bytes.extend(
            operations
                .into_iter()
                .map(|operation| operation.bytes.clone()),
        );
    }
}

impl SyncTransport for CapturingTransport {
    fn push_operations(
        &mut self,
        scope: SyncScope,
        batch: &[CanonicalOperation],
    ) -> Result<PushReceipt, TransportError> {
        self.capture_operations(batch);
        self.inner.push_operations(scope, batch)
    }

    fn pull_operations(
        &mut self,
        scope: SyncScope,
        after: Option<&SyncCursor>,
        limit: usize,
    ) -> Result<PullPage, TransportError> {
        let page = self.inner.pull_operations(scope, after, limit)?;
        self.capture_operations(page.rows.iter().map(|row| &row.operation));
        Ok(page)
    }

    fn pull_device_range(
        &mut self,
        scope: SyncScope,
        device: DeviceId,
        range: RangeInclusive<u64>,
    ) -> Result<Vec<ReceivedOperation>, TransportError> {
        let rows = self.inner.pull_device_range(scope, device, range)?;
        self.capture_operations(rows.iter().map(|row| &row.operation));
        Ok(rows)
    }

    fn push_checkpoint(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        checkpoint: &CanonicalCheckpoint,
    ) -> Result<CheckpointReceipt, TransportError> {
        self.captured_bytes.push(checkpoint.bytes.clone());
        self.inner
            .push_checkpoint(scope, checkpoint_version, checkpoint)
    }

    fn pull_checkpoints(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        after: Option<&CheckpointCursor>,
        limit: usize,
    ) -> Result<CheckpointPage, TransportError> {
        let page = self
            .inner
            .pull_checkpoints(scope, checkpoint_version, after, limit)?;
        self.captured_bytes
            .extend(page.rows.iter().map(|row| row.checkpoint.bytes.clone()));
        Ok(page)
    }

    fn checkpoint_by_hash(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        canonical_hash: Sha256Digest,
    ) -> Result<Option<CanonicalCheckpoint>, TransportError> {
        let checkpoint =
            self.inner
                .checkpoint_by_hash(scope, checkpoint_version, canonical_hash)?;
        if let Some(checkpoint) = &checkpoint {
            self.captured_bytes.push(checkpoint.bytes.clone());
        }
        Ok(checkpoint)
    }
}

#[derive(Default)]
struct ActionCoverage {
    upsert: bool,
    tombstone: bool,
    concurrent_update: bool,
    disconnect: bool,
    reconnect: bool,
    duplicate: bool,
    delay: bool,
    drop: bool,
    reverse: bool,
    crash_reopen: bool,
    lost_hint: bool,
}

impl ActionCoverage {
    fn complete(&self) -> bool {
        self.upsert
            && self.tombstone
            && self.concurrent_update
            && self.disconnect
            && self.reconnect
            && self.duplicate
            && self.delay
            && self.drop
            && self.reverse
            && self.crash_reopen
            && self.lost_hint
    }
}

struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self {
            state: seed ^ 0x9e37_79b9_7f4a_7c15,
        }
    }

    fn next(&mut self) -> u64 {
        let mut value = self.state;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.state = value;
        value
    }

    fn index(&mut self, length: usize) -> usize {
        (self.next() as usize) % length
    }
}

struct RandomizedScenario {
    seed: u64,
    max_actions: usize,
    action_count: usize,
    operation_count: u64,
    rng: XorShift64,
    coverage: ActionCoverage,
    replicas: Vec<Replica>,
    trust: Trust,
    transport: CapturingTransport,
    captured_logs: Vec<String>,
    record_ids: Vec<RecordId>,
}

impl RandomizedScenario {
    fn new(seed: u64, max_actions: usize) -> Self {
        let mut rng = XorShift64::new(seed);
        let replica_count = 2 + rng.index(4);
        let devices = (0..replica_count).map(device_fixture).collect::<Vec<_>>();
        let trust = Trust {
            devices: devices
                .iter()
                .map(|device| (device.certificate.device_id, device.certificate.clone()))
                .collect(),
            key: ContentKey::from_bytes(CONTENT_KEY),
        };
        let replicas = devices
            .into_iter()
            .enumerate()
            .map(|(index, device)| Replica::new(seed, index, device))
            .collect();
        Self {
            seed,
            max_actions,
            action_count: 0,
            operation_count: 0,
            rng,
            coverage: ActionCoverage::default(),
            replicas,
            trust,
            transport: CapturingTransport::default(),
            captured_logs: Vec::new(),
            record_ids: (0..RECORD_COUNT).map(record_id).collect(),
        }
    }

    fn run_faulted_actions(&mut self) {
        self.upsert_action(0, 0);
        self.sync_replica(0, 0);
        self.disconnect_action(1);
        self.upsert_action(0, 1);
        self.drop_action(0);
        self.reconnect_action(1);
        self.delay_action(1);
        self.duplicate_action(1);
        self.reverse_action(0);
        self.lost_hint_action(0);
        self.crash_reopen_action(0);
        self.concurrent_update_action(0, 1, 2);
        self.tombstone_action(1, 1);

        for _ in 0..RANDOM_ACTIONS_PER_SEED {
            let replica = self.rng.index(self.replicas.len());
            let record = self.rng.index(self.record_ids.len());
            match self.rng.index(11) {
                0 => self.upsert_action(replica, record),
                1 => self.tombstone_action(replica, record),
                2 => {
                    let other = (replica + 1) % self.replicas.len();
                    self.concurrent_update_action(replica, other, record);
                }
                3 => self.disconnect_action(replica),
                4 => self.reconnect_action(replica),
                5 => self.duplicate_action(replica),
                6 => self.delay_action(replica),
                7 => self.drop_action(replica),
                8 => self.reverse_action(replica),
                9 => self.crash_reopen_action(replica),
                _ => self.lost_hint_action(replica),
            }
        }
        assert!(
            self.coverage.complete(),
            "seed {} did not exercise every required action",
            self.seed
        );
        assert!(self.action_count <= self.max_actions);
    }

    fn begin_action(&mut self) {
        self.action_count += 1;
        assert!(
            self.action_count <= self.max_actions,
            "seed {} exceeded action bound {}",
            self.seed,
            self.max_actions
        );
    }

    fn upsert_action(&mut self, replica: usize, record: usize) {
        self.begin_action();
        self.coverage.upsert = true;
        self.commit_local(replica, record, false);
    }

    fn tombstone_action(&mut self, replica: usize, record: usize) {
        self.begin_action();
        self.coverage.tombstone = true;
        let secret_ref_id = self.record_ids[record]
            .to_string()
            .parse::<SecretRefId>()
            .unwrap();
        if self.replicas[replica]
            .vault()
            .secret_ref(&secret_ref_id)
            .unwrap()
            .is_none()
        {
            self.commit_local(replica, record, false);
        }
        self.commit_local(replica, record, true);
    }

    fn concurrent_update_action(&mut self, left: usize, right: usize, record: usize) {
        self.begin_action();
        self.coverage.concurrent_update = true;
        self.commit_local(left, record, false);
        self.commit_local(right, record, false);
    }

    fn disconnect_action(&mut self, replica: usize) {
        self.begin_action();
        self.coverage.disconnect = true;
        self.replicas[replica].connected = false;
    }

    fn reconnect_action(&mut self, replica: usize) {
        self.begin_action();
        self.coverage.reconnect = true;
        self.replicas[replica].connected = true;
        self.sync_replica(replica, self.action_count as u64);
    }

    fn duplicate_action(&mut self, replica: usize) {
        self.begin_action();
        self.coverage.duplicate = true;
        let record = self.random_record();
        self.commit_local(replica, record, false);
        self.transport
            .schedule_faults(FaultSchedule::default().with_duplicated_pulls(1));
        self.sync_replica(replica, self.action_count as u64);
    }

    fn delay_action(&mut self, replica: usize) {
        self.begin_action();
        self.coverage.delay = true;
        let record = self.random_record();
        self.commit_local(replica, record, false);
        self.transport
            .schedule_faults(FaultSchedule::default().with_delayed_pulls(1));
        self.sync_replica(replica, self.action_count as u64);
    }

    fn drop_action(&mut self, replica: usize) {
        self.begin_action();
        self.coverage.drop = true;
        let record = self.random_record();
        self.commit_local(replica, record, false);
        self.transport
            .schedule_faults(FaultSchedule::default().with_dropped_pulls(1));
        self.sync_replica(replica, self.action_count as u64);
    }

    fn reverse_action(&mut self, replica: usize) {
        self.begin_action();
        self.coverage.reverse = true;
        let first_record = self.random_record();
        let second_record = self.random_record();
        self.commit_local(replica, first_record, false);
        self.commit_local(replica, second_record, false);
        self.transport
            .schedule_faults(FaultSchedule::default().with_reversed_pulls(1));
        self.sync_replica(replica, self.action_count as u64);
    }

    fn lost_hint_action(&mut self, replica: usize) {
        self.begin_action();
        self.coverage.lost_hint = true;
        let record = self.random_record();
        self.commit_local(replica, record, false);
        self.transport
            .schedule_faults(FaultSchedule::default().with_lost_hints(1));
        self.sync_replica(replica, self.action_count as u64);
        assert!(
            !self.transport.take_change_hint(scope()),
            "seed {}: scheduled hint loss was not observed",
            self.seed
        );
    }

    fn crash_reopen_action(&mut self, replica: usize) {
        self.begin_action();
        self.coverage.crash_reopen = true;
        self.replicas[replica].crash_and_reopen();
    }

    fn random_record(&mut self) -> usize {
        self.rng.index(self.record_ids.len())
    }

    fn commit_local(&mut self, replica_index: usize, record_index: usize, tombstone: bool) {
        self.operation_count += 1;
        let operation_number = self.seed * ID_BASE + self.operation_count;
        let operation_id = generated_id(operation_number);
        let record_id = self.record_ids[record_index];
        let replica = &mut self.replicas[replica_index];
        let previous = replica
            .vault()
            .device_head(scope().workspace_id, replica.device.certificate.device_id)
            .unwrap()
            .map(|head| OperationChainHead {
                sequence: head.sequence,
                canonical_hash: head.canonical_hash,
            });
        let frontier = replica.vault().sync_checkpoint_frontier(scope()).unwrap();
        let mutation = if tombstone {
            RecordMutationV1::Tombstone {
                record_id,
                record_kind: RecordKind::SecretRef,
            }
        } else {
            RecordMutationV1::UpsertSecretRef(SecretRef {
                id: record_id.to_string().parse::<SecretRefId>().unwrap(),
                name: format!(
                    "{CANARY}:seed={}:operation={}:replica={replica_index}",
                    self.seed, self.operation_count
                ),
                provider: "local-keychain".to_owned(),
                required_on_device: self.operation_count.is_multiple_of(2),
            })
        };
        let content_key = ContentKey::from_bytes(CONTENT_KEY);
        let built = OperationBuilder::new(SyncIdentity {
            account_id: scope().account_id,
            workspace_id: scope().workspace_id,
            device_id: replica.device.certificate.device_id,
            control_epoch: CONTROL_EPOCH,
            key_epoch: KEY_EPOCH,
            device_keys: &replica.device.keys,
            content_key: &content_key,
        })
        .build(OperationBuildRequest {
            operation_id,
            project_id: None,
            mutation: &mutation,
            causal_frontier: frontier,
            previous,
            blob_refs: Vec::new(),
            created_hlc: HybridLogicalClock::new(
                1_800_000_000_000 + operation_number,
                0,
                replica.device.certificate.device_id,
            ),
        })
        .unwrap();
        replica
            .vault_mut()
            .commit_outgoing_operation_at(&mutation, &built, None, operation_number)
            .unwrap();
        self.captured_logs.push(format!(
            "commit seed={} operation={} replica={replica_index} device_sequence={} record={record_index} mutation={}",
            self.seed,
            operation_id,
            built.operation.device_sequence,
            if tombstone { "tombstone" } else { "upsert" }
        ));
    }

    fn sync_replica(&mut self, replica_index: usize, tick: u64) {
        if !self.replicas[replica_index].connected {
            return;
        }
        let report = SyncEngine::new(scope(), SyncProvider::Memory)
            .sync_once(
                self.replicas[replica_index].vault_mut(),
                &mut self.transport,
                &self.trust,
                &NoEmbeddings,
                2_000_000_000_000 + tick * 60_000,
            )
            .unwrap_or_else(|error| {
                panic!(
                    "seed {} replica {replica_index} sync failed safely as {}",
                    self.seed,
                    error.safe_code()
                )
            });
        self.captured_logs.push(format!(
            "sync seed={} replica={replica_index} pushed={} pulled={} applied={} conflicts={} quarantined={} more_work={}",
            self.seed,
            report.pushed,
            report.pulled,
            report.applied,
            report.conflicts,
            report.quarantined,
            report.more_work
        ));
    }

    fn sync_until_idle(mut self) -> ScenarioEvidence {
        self.transport.schedule_faults(FaultSchedule::default());
        for replica in &mut self.replicas {
            replica.connected = true;
        }
        let mut quiet_rounds = 0usize;
        let mut converged = false;
        for round in 0..128_u64 {
            let before_log_count = self.captured_logs.len();
            let mut activity = 0usize;
            for replica_index in 0..self.replicas.len() {
                let report = SyncEngine::new(scope(), SyncProvider::Memory)
                    .sync_once(
                        self.replicas[replica_index].vault_mut(),
                        &mut self.transport,
                        &self.trust,
                        &NoEmbeddings,
                        3_000_000_000_000 + round * 60_000,
                    )
                    .unwrap_or_else(|error| {
                        panic!(
                            "seed {} replica {replica_index} drain failed as {}",
                            self.seed,
                            error.safe_code()
                        )
                    });
                activity += report.pushed
                    + report.duplicates
                    + report.pulled
                    + report.applied
                    + report.conflicts
                    + report.quarantined
                    + report.gaps_repaired
                    + usize::from(report.checkpointed)
                    + usize::from(report.more_work);
                self.captured_logs.push(format!(
                    "drain seed={} replica={replica_index} round={round} activity={activity}",
                    self.seed
                ));
            }
            let outboxes_empty = self
                .replicas
                .iter()
                .all(|replica| replica.vault().outbox_operations().unwrap().is_empty());
            if activity == 0 && outboxes_empty {
                quiet_rounds += 1;
                if quiet_rounds == 2 {
                    converged = true;
                    break;
                }
            } else {
                quiet_rounds = 0;
            }
            assert!(self.captured_logs.len() > before_log_count);
        }
        scenario_evidence(
            self.replicas,
            self.transport.captured_bytes,
            self.captured_logs,
            self.record_ids,
            self.action_count,
            converged,
            Vec::new(),
        )
    }
}

struct BrokenChainScenario {
    trust: Trust,
    broken: DeviceFixture,
    observers: Vec<Replica>,
    transport: CapturingTransport,
    record_ids: Vec<RecordId>,
}

impl BrokenChainScenario {
    fn new() -> Self {
        let broken = device_fixture(7);
        let observer_devices = vec![device_fixture(8), device_fixture(9)];
        let mut devices =
            BTreeMap::from([(broken.certificate.device_id, broken.certificate.clone())]);
        devices.extend(
            observer_devices
                .iter()
                .map(|device| (device.certificate.device_id, device.certificate.clone())),
        );
        let observers = observer_devices
            .into_iter()
            .enumerate()
            .map(|(index, device)| Replica::new(SEED_COUNT + 1, index, device))
            .collect();
        Self {
            trust: Trust {
                devices,
                key: ContentKey::from_bytes(CONTENT_KEY),
            },
            broken,
            observers,
            transport: CapturingTransport::default(),
            record_ids: vec![record_id(0)],
        }
    }

    fn run(mut self) -> ScenarioEvidence {
        let first = build_broken_chain_operation(&self.broken, 1, None);
        let second = build_broken_chain_operation(
            &self.broken,
            2,
            Some(OperationChainHead {
                sequence: first.operation.device_sequence,
                canonical_hash: Sha256Digest([0x42; 32]),
            }),
        );
        assert_eq!(second.operation.device_sequence, 2);
        assert_ne!(second.operation.previous_device_hash, first.canonical_hash);
        self.transport
            .push_operations(scope(), &[canonical(&first), canonical(&second)])
            .unwrap();
        let receipts = self
            .transport
            .inner
            .pull_operations(scope(), None, 2)
            .unwrap()
            .rows;
        let mut captured_logs = Vec::new();
        for (index, observer) in self.observers.iter_mut().enumerate() {
            let report = SyncEngine::new(scope(), SyncProvider::Memory)
                .sync_once(
                    observer.vault_mut(),
                    &mut self.transport,
                    &self.trust,
                    &NoEmbeddings,
                    4_000_000_000_000,
                )
                .unwrap();
            assert_eq!(report.quarantined, 1, "observer {index}");
            observer.crash_and_reopen();
            let replay = SyncEngine::new(scope(), SyncProvider::Memory)
                .sync_once(
                    observer.vault_mut(),
                    &mut self.transport,
                    &self.trust,
                    &NoEmbeddings,
                    4_000_000_060_000,
                )
                .unwrap();
            assert_eq!(replay.pulled, 0, "observer {index}");
            captured_logs.push(format!(
                "broken observer={index} safe_reason=integrity_quarantined quarantined={}",
                report.quarantined
            ));
        }
        let observer_safe_reasons = self
            .observers
            .iter()
            .map(|observer| {
                receipts
                    .iter()
                    .filter_map(|receipt| {
                        observer
                            .vault()
                            .quarantined_sync_receipt(
                                scope().account_id,
                                scope().workspace_id,
                                SyncProvider::Memory.as_str(),
                                &receipt.cursor.received_at,
                                receipt.cursor.operation_id,
                            )
                            .unwrap()
                            .map(|quarantine| quarantine.safe_error_code)
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let core_state_equal = self.observers.windows(2).all(|pair| {
            pair[0].vault().sync_state_summary(scope()).unwrap()
                == pair[1].vault().sync_state_summary(scope()).unwrap()
                && pair[0].vault().sync_checkpoint_frontier(scope()).unwrap()
                    == pair[1].vault().sync_checkpoint_frontier(scope()).unwrap()
        });
        let has_quarantine = observer_safe_reasons
            .iter()
            .any(|reasons| !reasons.is_empty());
        scenario_evidence(
            self.observers,
            self.transport.captured_bytes,
            captured_logs,
            self.record_ids,
            0,
            core_state_equal && !has_quarantine,
            observer_safe_reasons,
        )
    }
}

struct ReplicaEvidence {
    state_summary: context_relay_core::sync::StateSummaryV1,
    state_hash: Sha256Digest,
    frontier: Vec<DeviceSequence>,
    ordered_conflicts: Vec<Option<(OperationId, OperationId)>>,
    outbox: Vec<OperationId>,
    raw_vault_bytes: Vec<Vec<u8>>,
}

struct ScenarioEvidence {
    replicas: Vec<ReplicaEvidence>,
    provider_bytes: Vec<Vec<u8>>,
    captured_logs: Vec<String>,
    action_count: usize,
    converged: bool,
    observer_safe_reasons: Vec<Vec<String>>,
}

fn scenario_evidence(
    mut replicas: Vec<Replica>,
    provider_bytes: Vec<Vec<u8>>,
    captured_logs: Vec<String>,
    record_ids: Vec<RecordId>,
    action_count: usize,
    converged: bool,
    observer_safe_reasons: Vec<Vec<String>>,
) -> ScenarioEvidence {
    let replicas = replicas
        .iter_mut()
        .map(|replica| {
            replica.vault().checkpoint_wal().unwrap();
            let state_summary = replica.vault().sync_state_summary(scope()).unwrap();
            let state_hash = state_summary.state_hash().unwrap();
            let frontier = replica.vault().sync_checkpoint_frontier(scope()).unwrap();
            let ordered_conflicts = record_ids
                .iter()
                .map(|record_id| {
                    replica
                        .vault()
                        .conflict(record_id)
                        .unwrap()
                        .map(|(left, right)| (left.operation_id, right.operation_id))
                })
                .collect();
            let outbox = replica
                .vault()
                .outbox_operations()
                .unwrap()
                .into_iter()
                .map(|operation| operation.operation_id)
                .collect();
            let raw_vault_bytes = ["", "-wal", "-shm"]
                .iter()
                .filter_map(|suffix| {
                    fs::read(format!("{}{suffix}", replica.path.path().display())).ok()
                })
                .collect();
            ReplicaEvidence {
                state_summary,
                state_hash,
                frontier,
                ordered_conflicts,
                outbox,
                raw_vault_bytes,
            }
        })
        .collect();
    ScenarioEvidence {
        replicas,
        provider_bytes,
        captured_logs,
        action_count,
        converged,
        observer_safe_reasons,
    }
}

fn assert_equal_state_hashes(seed: u64, evidence: &ScenarioEvidence) {
    let expected = evidence.replicas[0].state_hash;
    for (index, replica) in evidence.replicas.iter().enumerate() {
        assert_eq!(
            replica.state_hash, expected,
            "seed {seed} replica {index}: expected {:?}, observed {:?}",
            evidence.replicas[0].state_summary, replica.state_summary
        );
    }
}

fn assert_equal_frontiers(seed: u64, evidence: &ScenarioEvidence) {
    let expected = &evidence.replicas[0].frontier;
    for (index, replica) in evidence.replicas.iter().enumerate() {
        assert_eq!(
            &replica.frontier, expected,
            "seed {seed} replica {index}; logs: {:?}",
            evidence.captured_logs,
        );
    }
}

fn assert_equal_ordered_conflicts(seed: u64, evidence: &ScenarioEvidence) {
    let expected = &evidence.replicas[0].ordered_conflicts;
    for (index, replica) in evidence.replicas.iter().enumerate() {
        assert_eq!(
            &replica.ordered_conflicts, expected,
            "seed {seed} replica {index}"
        );
        assert!(
            replica
                .ordered_conflicts
                .iter()
                .flatten()
                .all(|(left, right)| left < right),
            "seed {seed} replica {index}: conflict pair was not canonically ordered"
        );
    }
}

fn assert_all_outboxes_empty(seed: u64, evidence: &ScenarioEvidence) {
    for (index, replica) in evidence.replicas.iter().enumerate() {
        assert!(
            replica.outbox.is_empty(),
            "seed {seed} replica {index}: outbox retained {:?}",
            replica.outbox
        );
    }
}

fn assert_no_plaintext_canary(seed: u64, evidence: &ScenarioEvidence) {
    let canary = CANARY.as_bytes();
    for (index, replica) in evidence.replicas.iter().enumerate() {
        for raw in &replica.raw_vault_bytes {
            assert!(
                !contains_bytes(raw, canary),
                "seed {seed} replica {index}: raw Vault bytes contained plaintext canary"
            );
        }
    }
    for bytes in &evidence.provider_bytes {
        assert!(
            !contains_bytes(bytes, canary),
            "seed {seed}: provider evidence contained plaintext canary"
        );
    }
    for log in &evidence.captured_logs {
        assert!(
            !log.as_bytes()
                .windows(canary.len())
                .any(|window| window == canary),
            "seed {seed}: captured log contained plaintext canary"
        );
    }
}

fn assert_identical_stable_safe_reasons(evidence: &ScenarioEvidence) {
    assert!(!evidence.observer_safe_reasons.is_empty());
    let expected = &evidence.observer_safe_reasons[0];
    assert_eq!(expected, &["integrity_quarantined".to_owned()]);
    for reasons in &evidence.observer_safe_reasons {
        assert_eq!(reasons, expected);
        assert!(
            reasons
                .iter()
                .all(|reason| matches!(reason.as_str(), "integrity_quarantined" | "gap_pending"))
        );
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn create_owner_migration_inputs(connection: &Connection) {
    connection
        .execute_batch(
            "CREATE TABLE sync_operation_meta(
                 operation_id TEXT PRIMARY KEY,
                 account_id TEXT NOT NULL,
                 workspace_id TEXT NOT NULL
             );
             CREATE TABLE sync_record_heads(
                 workspace_id TEXT NOT NULL,
                 record_id TEXT NOT NULL,
                 operation_id TEXT NOT NULL,
                 record_kind TEXT NOT NULL
             );",
        )
        .unwrap();
}

fn insert_owner_migration_head(
    connection: &Connection,
    operation_id: &str,
    sync_scope: SyncScope,
    record_id: RecordId,
    record_kind: &str,
) {
    connection
        .execute(
            "INSERT INTO sync_operation_meta(operation_id, account_id, workspace_id)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![
                operation_id,
                sync_scope.account_id.to_string(),
                sync_scope.workspace_id.to_string()
            ],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO sync_record_heads(workspace_id, record_id, operation_id, record_kind)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                sync_scope.workspace_id.to_string(),
                record_id.to_string(),
                operation_id,
                record_kind
            ],
        )
        .unwrap();
}

fn scope() -> SyncScope {
    SyncScope {
        account_id: id(ID_1),
        workspace_id: id(ID_2),
    }
}

fn device_fixture(index: usize) -> DeviceFixture {
    device_fixture_in_scope(index, scope())
}

fn device_fixture_in_scope(index: usize, sync_scope: SyncScope) -> DeviceFixture {
    let keys = DeviceKeys::generate().unwrap();
    let device_id = generated_id(0x800 + index as u64);
    DeviceFixture {
        certificate: DeviceCertificateV1 {
            issuer: CertificateIssuerV1::Device {
                device_id: id(ID_1),
                signing_public_key: keys.signing_public_key(),
            },
            account_id: sync_scope.account_id,
            workspace_id: sync_scope.workspace_id,
            control_epoch: CONTROL_EPOCH,
            request_nonce: PairingRequestNonce([index as u8 + 1; 32]),
            device_id,
            signing_public_key: keys.signing_public_key(),
            wrapping_public_key: keys.wrapping_public_key(),
            signature: Ed25519SignatureBytes([0; 64]),
        },
        keys,
    }
}

fn record_id(index: usize) -> RecordId {
    generated_id(0xc00 + index as u64)
}

fn build_broken_chain_operation(
    device: &DeviceFixture,
    sequence: u64,
    previous: Option<OperationChainHead>,
) -> context_relay_core::sync::BuiltOperation {
    let record_id = record_id(0);
    let mutation = RecordMutationV1::UpsertSecretRef(SecretRef {
        id: record_id.to_string().parse().unwrap(),
        name: format!("{CANARY}:broken-sequence={sequence}"),
        provider: "local-keychain".to_owned(),
        required_on_device: true,
    });
    let content_key = ContentKey::from_bytes(CONTENT_KEY);
    OperationBuilder::new(SyncIdentity {
        account_id: scope().account_id,
        workspace_id: scope().workspace_id,
        device_id: device.certificate.device_id,
        control_epoch: CONTROL_EPOCH,
        key_epoch: KEY_EPOCH,
        device_keys: &device.keys,
        content_key: &content_key,
    })
    .build(OperationBuildRequest {
        operation_id: generated_id(0xf00 + sequence),
        project_id: None,
        mutation: &mutation,
        causal_frontier: Vec::new(),
        previous,
        blob_refs: Vec::new(),
        created_hlc: HybridLogicalClock::new(
            4_100_000_000_000 + sequence,
            0,
            device.certificate.device_id,
        ),
    })
    .unwrap()
}

fn build_operation(
    device: &DeviceFixture,
    operation_id: OperationId,
    mutation: &RecordMutationV1,
    frontier: Vec<DeviceSequence>,
    previous: Option<OperationChainHead>,
) -> context_relay_core::sync::BuiltOperation {
    build_operation_in_scope(scope(), device, operation_id, mutation, frontier, previous)
}

fn build_operation_in_scope(
    sync_scope: SyncScope,
    device: &DeviceFixture,
    operation_id: OperationId,
    mutation: &RecordMutationV1,
    frontier: Vec<DeviceSequence>,
    previous: Option<OperationChainHead>,
) -> context_relay_core::sync::BuiltOperation {
    let content_key = ContentKey::from_bytes(CONTENT_KEY);
    OperationBuilder::new(SyncIdentity {
        account_id: sync_scope.account_id,
        workspace_id: sync_scope.workspace_id,
        device_id: device.certificate.device_id,
        control_epoch: CONTROL_EPOCH,
        key_epoch: KEY_EPOCH,
        device_keys: &device.keys,
        content_key: &content_key,
    })
    .build(OperationBuildRequest {
        operation_id,
        project_id: mutation_project_id(mutation),
        mutation,
        causal_frontier: frontier,
        previous,
        blob_refs: Vec::new(),
        created_hlc: HybridLogicalClock::new(4_200_000_000_000, 0, device.certificate.device_id),
    })
    .unwrap()
}

fn canonical(built: &context_relay_core::sync::BuiltOperation) -> CanonicalOperation {
    CanonicalOperation {
        operation_id: built.operation.operation_id,
        device_id: built.operation.device_id,
        device_sequence: built.operation.device_sequence,
        bytes: built.canonical_bytes.clone(),
    }
}

fn generated_id<T: FromStr>(number: u64) -> T
where
    T::Err: std::fmt::Debug,
{
    format!("018f22e2-79b0-7cc8-98c4-{number:012x}")
        .parse()
        .unwrap()
}

fn id<T: FromStr>(value: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    value.parse().unwrap()
}

fn open_keyed_vault(path: &std::path::Path, key: &[u8; 32]) -> Connection {
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

fn downgrade_to_schema_18(path: &std::path::Path, keys: &MemoryKeyStore) {
    let raw = open_keyed_vault(path, &keys.key(CREDENTIAL));
    support::remove_native_memory_migrations_after_schema_23(&raw);
    raw.execute_batch(
        "DROP TABLE recovery_restores;
         DROP TABLE recovery_enrollments;
         DROP TABLE pairing_approval_transcripts;
         DROP TABLE pairing_joins;
         DROP TABLE pairing_decisions;
         DROP TABLE device_certificates;
         DROP TABLE sync_record_owners;
         PRAGMA user_version = 18;",
    )
    .unwrap();
}

fn sync_owner(connection: &Connection, record_id: RecordId) -> (String, String, String, String) {
    connection
        .query_row(
            "SELECT account_id, workspace_id, record_kind, binding_state
             FROM sync_record_owners WHERE record_id = ?1",
            [record_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap()
}

fn mutation_project_id(mutation: &RecordMutationV1) -> Option<ProjectId> {
    fn from_scope(scope: &ScopeRef) -> Option<ProjectId> {
        match scope {
            ScopeRef::Global => None,
            ScopeRef::Project { project_id } => Some(*project_id),
        }
    }

    match mutation {
        RecordMutationV1::UpsertMemory(record) => from_scope(&record.scope),
        RecordMutationV1::UpsertMemoryCandidate(record) => {
            from_scope(&record.proposed_memory.scope)
        }
        RecordMutationV1::UpsertTask(record) => Some(record.project_id),
        RecordMutationV1::UpsertSecretRef(_) => None,
        RecordMutationV1::UpsertInstruction(record) => from_scope(&record.scope),
        RecordMutationV1::UpsertComponent(record) => from_scope(&record.scope),
        RecordMutationV1::UpsertProject(record) => Some(record.project_id),
        RecordMutationV1::Tombstone {
            record_id,
            record_kind,
        } => match record_kind {
            RecordKind::Task | RecordKind::Project => Some(record_id.to_string().parse().unwrap()),
            _ => None,
        },
    }
}

fn typed_owner_mutations() -> Vec<RecordMutationV1> {
    let mut candidate = candidate();
    candidate.id = record_id(11).to_string().parse().unwrap();
    candidate.proposed_memory.id = record_id(111).to_string().parse().unwrap();
    let mut task = task();
    task.id = record_id(12).to_string().parse().unwrap();
    let instruction = instruction(
        &record_id(14).to_string(),
        ScopeRef::Global,
        "Typed instruction",
        &format!("{CANARY}:typed-instruction"),
    );
    let component_seed = memory(
        &record_id(113).to_string(),
        ScopeRef::Global,
        "Component provenance",
        &format!("{CANARY}:component-provenance"),
    );
    vec![
        RecordMutationV1::UpsertMemoryCandidate(candidate),
        RecordMutationV1::UpsertTask(task),
        RecordMutationV1::UpsertSecretRef(SecretRef {
            id: record_id(13).to_string().parse().unwrap(),
            name: "Typed secret".to_owned(),
            provider: "local-keychain".to_owned(),
            required_on_device: true,
        }),
        RecordMutationV1::UpsertInstruction(instruction),
        RecordMutationV1::UpsertComponent(ComponentRecord {
            id: record_id(15),
            scope: ScopeRef::Global,
            kind: ComponentKind::Rule,
            name: "Typed component".to_owned(),
            body_markdown: format!("{CANARY}:typed-component"),
            metadata: vec![("key".to_owned(), "value".to_owned())],
            provenance: component_seed.provenance,
            archived: false,
        }),
        RecordMutationV1::UpsertProject(ProjectIdentity {
            project_id: record_id(16).to_string().parse().unwrap(),
            github_repository_id: Some(42),
            git_remote_fingerprint: Some(Sha256Digest([0x31; 32])),
            monorepo_subdirectory: Some("crates/core".to_owned()),
            name: "Typed project".to_owned(),
        }),
    ]
}

fn changed_typed_mutation(mut mutation: RecordMutationV1) -> RecordMutationV1 {
    match &mut mutation {
        RecordMutationV1::UpsertMemoryCandidate(record) => {
            record.evidence_summary.push_str(" changed")
        }
        RecordMutationV1::UpsertTask(record) => record.title.push_str(" changed"),
        RecordMutationV1::UpsertSecretRef(record) => record.name.push_str(" changed"),
        RecordMutationV1::UpsertInstruction(record) => record.title.push_str(" changed"),
        RecordMutationV1::UpsertComponent(record) => record.name.push_str(" changed"),
        RecordMutationV1::UpsertProject(record) => record.name.push_str(" changed"),
        RecordMutationV1::UpsertMemory(_) | RecordMutationV1::Tombstone { .. } => unreachable!(),
    }
    mutation
}

fn replace_materialized_payload(connection: &Connection, mutation: &RecordMutationV1) {
    let payload = match mutation {
        RecordMutationV1::UpsertMemoryCandidate(record) => serde_json::to_vec(record).unwrap(),
        RecordMutationV1::UpsertTask(record) => serde_json::to_vec(record).unwrap(),
        RecordMutationV1::UpsertSecretRef(record) => serde_json::to_vec(record).unwrap(),
        RecordMutationV1::UpsertInstruction(record) => serde_json::to_vec(record).unwrap(),
        RecordMutationV1::UpsertComponent(record) => serde_json::to_vec(record).unwrap(),
        RecordMutationV1::UpsertProject(record) => serde_json::to_vec(record).unwrap(),
        RecordMutationV1::UpsertMemory(_) | RecordMutationV1::Tombstone { .. } => unreachable!(),
    };
    let id = mutation.record_id().to_string();
    let changed = match mutation {
        RecordMutationV1::UpsertMemoryCandidate(_) => connection
            .execute(
                "UPDATE candidates SET payload_json = ?2 WHERE id = ?1",
                rusqlite::params![id, payload],
            )
            .unwrap(),
        RecordMutationV1::UpsertTask(_) => connection
            .execute(
                "UPDATE tasks SET payload_json = ?2 WHERE id = ?1",
                rusqlite::params![id, payload],
            )
            .unwrap(),
        RecordMutationV1::UpsertSecretRef(_) => connection
            .execute(
                "UPDATE secret_refs SET payload_json = ?2 WHERE id = ?1",
                rusqlite::params![id, payload],
            )
            .unwrap(),
        RecordMutationV1::UpsertInstruction(_) => {
            let records = connection
                .execute(
                    "UPDATE records SET payload_json = ?2 WHERE id = ?1 AND kind = 'instruction'",
                    rusqlite::params![id, payload],
                )
                .unwrap();
            let instructions = connection
                .execute(
                    "UPDATE instructions SET payload_json = ?2 WHERE id = ?1",
                    rusqlite::params![id, payload],
                )
                .unwrap();
            assert_eq!(instructions, 1);
            records
        }
        RecordMutationV1::UpsertComponent(_) => connection
            .execute(
                "UPDATE components SET payload_json = ?2 WHERE id = ?1",
                rusqlite::params![id, payload],
            )
            .unwrap(),
        RecordMutationV1::UpsertProject(_) => connection
            .execute(
                "UPDATE projects SET payload_json = ?2 WHERE id = ?1",
                rusqlite::params![id, payload],
            )
            .unwrap(),
        RecordMutationV1::UpsertMemory(_) | RecordMutationV1::Tombstone { .. } => unreachable!(),
    };
    assert_eq!(changed, 1);
}
