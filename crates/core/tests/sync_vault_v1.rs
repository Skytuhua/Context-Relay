mod support;

use std::{path::Path, str::FromStr};

use context_relay_core::{
    crypto::{ContentKey, DeviceKeys},
    sync::{
        BuiltOperation, OperationBuildRequest, OperationBuilder, OperationChainHead, SyncIdentity,
    },
    vault::{
        CommitDisposition, LATEST_SCHEMA_VERSION, SyncQuarantineDisposition, SyncQuarantineWrite,
        SyncRejectionDisposition, SyncRejectionWrite, Vault, VaultError,
    },
};
use context_relay_protocol::{
    AccountId, ComponentKind, ComponentRecord, DeviceId, HybridLogicalClock,
    MAX_CBOR_OPERATION_BYTES, MutationKind, OperationId, ProjectIdentity, RecordKind,
    RecordMutationV1, ScopeRef, SecretRef, SecretRefId, Sha256Digest, WorkspaceId, XChaChaNonce,
    encode_sync_operation_v1,
};
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};

use support::{
    ID_1, ID_2, ID_3, ID_4, ID_5, ID_6, ID_7, ID_8, ID_9, MemoryKeyStore, TempVault, basis,
    candidate, instruction, memory, operation, task,
};

const CREDENTIAL: &str = "sync-vault-v1";
const ACCOUNT_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073981";
const WORKSPACE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073982";
const DEVICE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073983";
const CANARY: &str = "SYNC_PLAINTEXT_CANARY_16_3";

fn id<T: FromStr>(value: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    value.parse().unwrap()
}

fn generated_id(index: u16) -> String {
    format!("018f22e2-79b0-7cc8-98c4-dc0c0c08{index:04x}")
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

fn project_for(mutation: &RecordMutationV1) -> Option<context_relay_protocol::ProjectId> {
    fn scope_project(scope: &ScopeRef) -> Option<context_relay_protocol::ProjectId> {
        match scope {
            ScopeRef::Global => None,
            ScopeRef::Project { project_id } => Some(*project_id),
        }
    }
    match mutation {
        RecordMutationV1::UpsertMemory(value) => scope_project(&value.scope),
        RecordMutationV1::UpsertMemoryCandidate(value) => {
            scope_project(&value.proposed_memory.scope)
        }
        RecordMutationV1::UpsertTask(value) => Some(value.project_id),
        RecordMutationV1::UpsertSecretRef(_) => None,
        RecordMutationV1::UpsertInstruction(value) => scope_project(&value.scope),
        RecordMutationV1::UpsertComponent(value) => scope_project(&value.scope),
        RecordMutationV1::UpsertProject(value) => Some(value.project_id),
        RecordMutationV1::Tombstone {
            record_kind,
            record_id,
        } => match record_kind {
            RecordKind::Task | RecordKind::Project => Some(id(&record_id.to_string())),
            _ => None,
        },
    }
}

fn build(
    mutation: &RecordMutationV1,
    operation_id: &str,
    previous: Option<OperationChainHead>,
) -> BuiltOperation {
    build_with_project(mutation, operation_id, previous, project_for(mutation))
}

fn build_with_project(
    mutation: &RecordMutationV1,
    operation_id: &str,
    previous: Option<OperationChainHead>,
    project_id: Option<context_relay_protocol::ProjectId>,
) -> BuiltOperation {
    let keys = DeviceKeys::generate().unwrap();
    let content_key = ContentKey::from_bytes([11; 32]);
    OperationBuilder::new(SyncIdentity {
        account_id: id(ACCOUNT_ID),
        workspace_id: id(WORKSPACE_ID),
        device_id: id(DEVICE_ID),
        control_epoch: 3,
        key_epoch: 5,
        device_keys: &keys,
        content_key: &content_key,
    })
    .build(OperationBuildRequest {
        operation_id: id(operation_id),
        project_id,
        mutation,
        causal_frontier: vec![],
        previous,
        blob_refs: vec![],
        created_hlc: HybridLogicalClock::new(1_700_000_000_000, 0, id(DEVICE_ID)),
    })
    .unwrap()
}

fn build_with_nonce(
    mutation: &RecordMutationV1,
    operation_id: &str,
    previous: Option<OperationChainHead>,
    nonce: XChaChaNonce,
    content_key_byte: u8,
) -> BuiltOperation {
    let keys = DeviceKeys::generate().unwrap();
    let content_key = ContentKey::from_bytes([content_key_byte; 32]);
    OperationBuilder::with_nonce_for_test(
        SyncIdentity {
            account_id: id(ACCOUNT_ID),
            workspace_id: id(WORKSPACE_ID),
            device_id: id(DEVICE_ID),
            control_epoch: 3,
            key_epoch: 5,
            device_keys: &keys,
            content_key: &content_key,
        },
        nonce,
    )
    .build(OperationBuildRequest {
        operation_id: id(operation_id),
        project_id: project_for(mutation),
        mutation,
        causal_frontier: vec![],
        previous,
        blob_refs: vec![],
        created_hlc: HybridLogicalClock::new(1_700_000_000_000, 0, id(DEVICE_ID)),
    })
    .unwrap()
}

fn recanonicalize(mut built: BuiltOperation) -> BuiltOperation {
    built.canonical_bytes = encode_sync_operation_v1(&built.operation).unwrap();
    built.canonical_hash = Sha256Digest(Sha256::digest(&built.canonical_bytes).into());
    built
}

fn all_mutations() -> Vec<RecordMutationV1> {
    let mut memory_value = memory(ID_1, ScopeRef::Global, "Canary memory", CANARY);
    memory_value.revision = id(ID_8);
    let mut candidate_value = candidate();
    candidate_value.id = id(ID_2);
    candidate_value.proposed_memory.id = id(ID_9);
    let mut task_value = task();
    task_value.id = id(ID_3);
    let instruction_value = instruction(ID_4, ScopeRef::Global, "Instruction", CANARY);
    let component_value = ComponentRecord {
        id: id(ID_5),
        scope: ScopeRef::Global,
        kind: ComponentKind::Rule,
        name: "Component".to_owned(),
        body_markdown: CANARY.to_owned(),
        metadata: vec![("key".to_owned(), "value".to_owned())],
        provenance: memory_value.provenance.clone(),
        archived: false,
    };
    vec![
        RecordMutationV1::UpsertMemory(memory_value),
        RecordMutationV1::UpsertMemoryCandidate(candidate_value),
        RecordMutationV1::UpsertTask(task_value),
        RecordMutationV1::UpsertSecretRef(SecretRef {
            id: id::<SecretRefId>(ID_6),
            name: "Database token".to_owned(),
            provider: "local-keychain".to_owned(),
            required_on_device: true,
        }),
        RecordMutationV1::UpsertInstruction(instruction_value),
        RecordMutationV1::UpsertComponent(component_value),
        RecordMutationV1::UpsertProject(ProjectIdentity {
            project_id: id(ID_7),
            github_repository_id: Some(42),
            git_remote_fingerprint: Some(Sha256Digest([31; 32])),
            monorepo_subdirectory: Some("crates/core".to_owned()),
            name: "Sync project".to_owned(),
        }),
    ]
}

#[test]
fn signed_operation_cannot_materialize_a_different_same_identity_mutation() {
    let path = TempVault::new("sync-mutation-binding");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let signed_mutation = all_mutations().remove(0);
    let mut substituted_mutation = signed_mutation.clone();
    let RecordMutationV1::UpsertMemory(record) = &mut substituted_mutation else {
        unreachable!()
    };
    record.title = "Substituted plaintext".to_owned();
    record.body_markdown = "not the signed mutation".to_owned();
    let record_id = record.id;
    let built = build(&signed_mutation, &generated_id(251), None);

    assert!(matches!(
        vault.commit_outgoing_operation(&substituted_mutation, &built, Some(&basis(0))),
        Err(VaultError::Validation(_))
    ));
    assert!(vault.memory(&record_id).unwrap().is_none());
    assert!(vault.due_outbox(0, 10).unwrap().is_empty());
}

#[test]
fn built_operation_public_fields_cannot_be_resealed_by_the_caller() {
    let path = TempVault::new("sync-built-operation-seal");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let mutation = RecordMutationV1::UpsertSecretRef(SecretRef {
        id: id(ID_6),
        name: "Token".to_owned(),
        provider: "provider".to_owned(),
        required_on_device: true,
    });
    let mut tampered = build(&mutation, &generated_id(252), None);
    tampered.operation.nonce.0 = [77; 24];
    tampered = recanonicalize(tampered);

    assert!(matches!(
        vault.commit_outgoing_operation(&mutation, &tampered, None),
        Err(VaultError::Validation(_))
    ));

    let mut tampered_bytes = build(&mutation, &generated_id(257), None);
    tampered_bytes.canonical_bytes.push(0);
    assert!(matches!(
        vault.commit_outgoing_operation(&mutation, &tampered_bytes, None),
        Err(VaultError::Validation(_))
    ));

    let mut tampered_hash = build(&mutation, &generated_id(258), None);
    tampered_hash.canonical_hash.0[0] ^= 1;
    assert!(matches!(
        vault.commit_outgoing_operation(&mutation, &tampered_hash, None),
        Err(VaultError::Validation(_))
    ));
    assert!(vault.due_outbox(0, 10).unwrap().is_empty());
}

#[test]
fn persisted_device_head_requires_exact_next_sequence_and_previous_hash() {
    let path = TempVault::new("sync-device-chain");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let first_mutation = RecordMutationV1::UpsertSecretRef(SecretRef {
        id: id(ID_6),
        name: "First".to_owned(),
        provider: "provider".to_owned(),
        required_on_device: true,
    });
    let first = build(&first_mutation, &generated_id(253), None);
    vault
        .commit_outgoing_operation(&first_mutation, &first, None)
        .unwrap();

    let second_mutation = RecordMutationV1::UpsertSecretRef(SecretRef {
        id: id(ID_7),
        name: "Second".to_owned(),
        provider: "provider".to_owned(),
        required_on_device: false,
    });
    let second_genesis = build(&second_mutation, &generated_id(254), None);
    assert!(matches!(
        vault.commit_outgoing_operation(&second_mutation, &second_genesis, None),
        Err(VaultError::Validation(_))
    ));

    let wrong_previous = build(
        &second_mutation,
        &generated_id(255),
        Some(OperationChainHead {
            sequence: 1,
            canonical_hash: Sha256Digest([99; 32]),
        }),
    );
    assert!(matches!(
        vault.commit_outgoing_operation(&second_mutation, &wrong_previous, None),
        Err(VaultError::Validation(_))
    ));

    let second = build(
        &second_mutation,
        &generated_id(256),
        Some(OperationChainHead {
            sequence: 1,
            canonical_hash: first.canonical_hash,
        }),
    );
    vault
        .commit_outgoing_operation(&second_mutation, &second, None)
        .unwrap();
    assert_eq!(
        vault
            .commit_outgoing_operation(&first_mutation, &first, None)
            .unwrap(),
        CommitDisposition::ExactReplay
    );
}

#[test]
fn sync_error_codes_and_provider_ids_use_exact_version_one_allowlists() {
    let path = TempVault::new("sync-safe-strings");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    for code in [
        "offline",
        "transient",
        "auth_required",
        "revoked",
        "quota_blocked",
        "gap_pending",
        "integrity_quarantined",
        "conflict",
        "configuration_error",
    ] {
        vault.defer_outbox(&[], 0, code).unwrap();
    }
    for invalid in [
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature",
        "unknown_error",
        "Auth_Required",
        "auth required",
    ] {
        assert!(matches!(
            vault.defer_outbox(&[], 0, invalid),
            Err(VaultError::Validation(_))
        ));
    }
    let oversized = "x".repeat(4_096);
    assert!(matches!(
        vault.defer_outbox(&[], 0, &oversized),
        Err(VaultError::Validation(_))
    ));

    for provider in ["memory", "supabase"] {
        assert_eq!(vault.sync_cursor(id(WORKSPACE_ID), provider).unwrap(), None);
    }
    for invalid in [
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature",
        "relay",
        "Memory",
        "supabase/project",
    ] {
        assert!(matches!(
            vault.sync_cursor(id(WORKSPACE_ID), invalid),
            Err(VaultError::Validation(_))
        ));
    }
    assert!(matches!(
        vault.sync_cursor(id(WORKSPACE_ID), &oversized),
        Err(VaultError::Validation(_))
    ));
}

#[test]
fn schema_13_upgrades_reopens_and_preserves_legacy_json_operations() {
    let path = TempVault::new("sync-migration-15");
    let keys = MemoryKeyStore::default();
    let key = [41; 32];
    keys.insert(CREDENTIAL, key);
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let legacy_memory = memory(ID_1, ScopeRef::Global, "Legacy", "kept");
    let legacy_operation = operation(ID_8, ID_1, RecordKind::Memory);
    vault
        .put_memory(&legacy_memory, &legacy_operation, &basis(0))
        .unwrap();
    drop(vault);

    let raw = open_keyed(path.path(), &key);
    support::remove_native_memory_migrations_after_schema_23(&raw);
    raw.execute_batch(
        "DROP TABLE recovery_restores;
         DROP TABLE recovery_enrollments;
         DROP TABLE pairing_approval_transcripts;
         DROP TABLE pairing_joins;
         DROP TABLE pairing_decisions;
         DROP TABLE device_certificates;
         DROP TABLE sync_checkpoint_scans;
         DROP TABLE sync_record_owners;
         DROP TABLE sync_checkpoint_schedule;
         DROP TABLE sync_checkpoint_pins;
         DROP TABLE signed_sync_checkpoints;
         DROP TABLE sync_rejections;
         DROP TABLE sync_quarantine;
         DROP TABLE sync_checkpoint_meta;
         DROP TABLE sync_cursors;
         DROP TABLE sync_record_heads;
         DROP TABLE sync_device_heads;
         DROP TABLE sync_operation_meta;
         DROP TABLE sync_nonces;
         DROP TABLE secret_refs;
         DROP TABLE components;
         DROP INDEX sync_outbox_due_idx;
         ALTER TABLE outbox DROP COLUMN safe_error_code;
         ALTER TABLE outbox DROP COLUMN next_attempt_ms;
         ALTER TABLE outbox DROP COLUMN attempt_count;
         PRAGMA user_version = 13;",
    )
    .unwrap();
    drop(raw);

    let vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(vault.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
    assert_eq!(
        vault.memory(&legacy_memory.id).unwrap(),
        Some(legacy_memory)
    );
    let due = vault.due_outbox(0, 10).unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].operation_id, legacy_operation.operation_id);
    assert_eq!(
        due[0].canonical_bytes,
        encode_sync_operation_v1(&legacy_operation).unwrap()
    );
    drop(vault);
    assert_eq!(
        Vault::open(path.path(), CREDENTIAL, &keys)
            .unwrap()
            .schema_version()
            .unwrap(),
        LATEST_SCHEMA_VERSION
    );
}

#[test]
fn quarantine_insert_replay_conflict_and_cursor_advance_are_atomic_and_durable() {
    let path = TempVault::new("sync-quarantine-durable");
    let keys = MemoryKeyStore::default();
    let account_id = id::<AccountId>(ID_1);
    let workspace_id = id::<WorkspaceId>(ID_2);
    let device_id = id::<DeviceId>(ID_3);
    let operation_id = id::<OperationId>(ID_7);
    let envelope = b"\x01signed-ciphertext";
    let write = SyncQuarantineWrite {
        account_id,
        workspace_id,
        provider: "memory",
        received_at: "2026-08-06T04:05:06Z",
        receipt_operation_id: operation_id,
        routed_operation_id: operation_id,
        device_id,
        device_sequence: 1,
        safe_error_code: "integrity_quarantined",
        envelope,
        quarantined_at_ms: 123,
        advance_cursor: true,
    };

    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(
        vault.quarantine_sync_receipt(&write).unwrap(),
        SyncQuarantineDisposition::Inserted
    );
    assert_eq!(
        vault.quarantine_sync_receipt(&write).unwrap(),
        SyncQuarantineDisposition::ExactReplay
    );
    let later_replay = SyncQuarantineWrite {
        quarantined_at_ms: 999,
        ..write
    };
    assert_eq!(
        vault.quarantine_sync_receipt(&later_replay).unwrap(),
        SyncQuarantineDisposition::ExactReplay
    );
    let stored = vault
        .quarantined_sync_receipt(
            account_id,
            workspace_id,
            "memory",
            write.received_at,
            operation_id,
        )
        .unwrap()
        .unwrap();
    assert_eq!(stored.account_id, account_id);
    assert_eq!(stored.workspace_id, workspace_id);
    assert_eq!(stored.provider, "memory");
    assert_eq!(stored.received_at, write.received_at);
    assert_eq!(stored.receipt_operation_id, operation_id);
    assert_eq!(stored.routed_operation_id, operation_id);
    assert_eq!(stored.device_id, device_id);
    assert_eq!(stored.device_sequence, 1);
    assert_eq!(stored.safe_error_code, "integrity_quarantined");
    assert_eq!(stored.envelope, envelope);
    assert_eq!(stored.quarantined_at_ms, 123);
    assert_eq!(
        vault
            .sync_cursor(workspace_id, "memory")
            .unwrap()
            .unwrap()
            .operation_id,
        operation_id
    );
    assert!(
        vault
            .device_head(workspace_id, device_id)
            .unwrap()
            .is_none()
    );
    assert!(
        vault
            .record_heads(workspace_id, id(ID_6))
            .unwrap()
            .is_empty()
    );
    assert!(vault.secret_ref(&id(ID_6)).unwrap().is_none());

    let altered = b"\x01altered-ciphertext";
    let altered_write = SyncQuarantineWrite {
        envelope: altered,
        ..write
    };
    assert!(matches!(
        vault.quarantine_sync_receipt(&altered_write),
        Err(VaultError::OperationConflict)
    ));
    assert_eq!(
        vault
            .quarantined_sync_receipt(
                account_id,
                workspace_id,
                "memory",
                write.received_at,
                operation_id,
            )
            .unwrap()
            .unwrap()
            .envelope,
        envelope
    );
    drop(vault);

    let reopened = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let stored = reopened
        .quarantined_sync_receipt(
            account_id,
            workspace_id,
            "memory",
            write.received_at,
            operation_id,
        )
        .unwrap()
        .unwrap();
    assert_eq!(stored.envelope, envelope);
    assert_eq!(stored.account_id, account_id);
    assert_eq!(stored.workspace_id, workspace_id);
    assert_eq!(stored.provider, "memory");
    assert_eq!(stored.quarantined_at_ms, 123);
    assert!(
        reopened
            .device_head(workspace_id, device_id)
            .unwrap()
            .is_none()
    );
    drop(reopened);

    let raw = open_keyed(path.path(), &keys.key(CREDENTIAL));
    for table in [
        "operations",
        "sync_operation_meta",
        "sync_device_heads",
        "sync_record_heads",
        "sync_nonces",
        "records",
        "secret_refs",
        "conflicts",
    ] {
        assert_eq!(
            raw.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            0,
            "quarantine mutated {table}"
        );
    }
}

#[test]
fn quarantine_rejects_oversized_envelopes_without_advancing_the_cursor() {
    let path = TempVault::new("sync-quarantine-oversized");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let oversized = vec![0; MAX_CBOR_OPERATION_BYTES + 1];
    let operation_id = id::<OperationId>(ID_7);
    let write = SyncQuarantineWrite {
        account_id: id(ID_1),
        workspace_id: id(ID_2),
        provider: "memory",
        received_at: "2026-08-06T07:08:09Z",
        receipt_operation_id: operation_id,
        routed_operation_id: operation_id,
        device_id: id(ID_3),
        device_sequence: 1,
        safe_error_code: "integrity_quarantined",
        envelope: &oversized,
        quarantined_at_ms: 123,
        advance_cursor: true,
    };

    assert!(matches!(
        vault.quarantine_sync_receipt(&write),
        Err(VaultError::Validation(_))
    ));
    assert!(vault.sync_cursor(id(ID_2), "memory").unwrap().is_none());
    assert!(
        vault
            .quarantined_sync_receipt(
                id(ID_1),
                id(ID_2),
                "memory",
                write.received_at,
                operation_id,
            )
            .unwrap()
            .is_none()
    );
}

#[test]
fn oversized_rejection_insert_replay_conflict_and_cursor_advance_are_atomic_and_durable() {
    let path = TempVault::new("sync-rejection-durable");
    let keys = MemoryKeyStore::default();
    let account_id = id::<AccountId>(ID_1);
    let workspace_id = id::<WorkspaceId>(ID_2);
    let device_id = id::<DeviceId>(ID_3);
    let operation_id = id::<OperationId>(ID_7);
    let received_bytes = vec![7; MAX_CBOR_OPERATION_BYTES + 1];
    let write = SyncRejectionWrite {
        account_id,
        workspace_id,
        provider: "memory",
        received_at: "2026-08-06T08:09:10Z",
        receipt_operation_id: operation_id,
        routed_operation_id: operation_id,
        device_id,
        device_sequence: 1,
        safe_error_code: "integrity_quarantined",
        received_bytes: &received_bytes,
        rejected_at_ms: 321,
        advance_cursor: false,
    };
    let expected_digest = Sha256Digest(Sha256::digest(&received_bytes).into());

    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(
        vault.reject_oversized_sync_receipt(&write).unwrap(),
        SyncRejectionDisposition::Inserted
    );
    assert!(vault.sync_cursor(workspace_id, "memory").unwrap().is_none());

    let mut altered_bytes = received_bytes.clone();
    altered_bytes[0] ^= 1;
    let altered = SyncRejectionWrite {
        received_bytes: &altered_bytes,
        advance_cursor: true,
        ..write
    };
    assert!(matches!(
        vault.reject_oversized_sync_receipt(&altered),
        Err(VaultError::OperationConflict)
    ));
    assert!(vault.sync_cursor(workspace_id, "memory").unwrap().is_none());
    let undersized = SyncRejectionWrite {
        received_bytes: b"not oversized",
        advance_cursor: true,
        ..write
    };
    assert!(matches!(
        vault.reject_oversized_sync_receipt(&undersized),
        Err(VaultError::Validation(_))
    ));
    assert!(vault.sync_cursor(workspace_id, "memory").unwrap().is_none());

    let later = SyncRejectionWrite {
        rejected_at_ms: 999,
        advance_cursor: true,
        ..write
    };
    assert_eq!(
        vault.reject_oversized_sync_receipt(&later).unwrap(),
        SyncRejectionDisposition::ExactReplay
    );
    let stored = vault
        .rejected_sync_receipt(
            account_id,
            workspace_id,
            "memory",
            write.received_at,
            operation_id,
        )
        .unwrap()
        .unwrap();
    assert_eq!(stored.account_id, account_id);
    assert_eq!(stored.workspace_id, workspace_id);
    assert_eq!(stored.provider, "memory");
    assert_eq!(stored.received_at, write.received_at);
    assert_eq!(stored.receipt_operation_id, operation_id);
    assert_eq!(stored.routed_operation_id, operation_id);
    assert_eq!(stored.device_id, device_id);
    assert_eq!(stored.device_sequence, 1);
    assert_eq!(stored.safe_error_code, "integrity_quarantined");
    assert_eq!(stored.claimed_byte_length, received_bytes.len() as u64);
    assert_eq!(stored.received_sha256, expected_digest);
    assert_eq!(stored.rejected_at_ms, 321);
    assert_eq!(
        vault
            .sync_cursor(workspace_id, "memory")
            .unwrap()
            .unwrap()
            .operation_id,
        operation_id
    );
    assert!(
        vault
            .device_head(workspace_id, device_id)
            .unwrap()
            .is_none()
    );
    assert!(
        vault
            .record_heads(workspace_id, id(ID_6))
            .unwrap()
            .is_empty()
    );
    assert!(vault.secret_ref(&id(ID_6)).unwrap().is_none());

    assert_eq!(
        vault
            .rejected_sync_receipt(
                account_id,
                workspace_id,
                "memory",
                write.received_at,
                operation_id,
            )
            .unwrap()
            .unwrap()
            .received_sha256,
        expected_digest
    );
    drop(vault);

    let reopened = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(
        reopened
            .rejected_sync_receipt(
                account_id,
                workspace_id,
                "memory",
                write.received_at,
                operation_id,
            )
            .unwrap()
            .unwrap(),
        stored
    );
    drop(reopened);
    let raw = open_keyed(path.path(), &keys.key(CREDENTIAL));
    for table in [
        "operations",
        "sync_operation_meta",
        "sync_device_heads",
        "sync_record_heads",
        "sync_nonces",
        "records",
        "secret_refs",
        "conflicts",
    ] {
        assert_eq!(
            raw.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            0,
            "oversized rejection mutated {table}"
        );
    }
}

#[test]
fn schema_15_upgrades_to_latest_without_losing_existing_quarantine() {
    let path = TempVault::new("sync-migration-16");
    let keys = MemoryKeyStore::default();
    let key = [43; 32];
    keys.insert(CREDENTIAL, key);
    let operation_id = id::<OperationId>(ID_7);
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault
        .quarantine_sync_receipt(&SyncQuarantineWrite {
            account_id: id(ID_1),
            workspace_id: id(ID_2),
            provider: "memory",
            received_at: "2026-08-06T11:12:13Z",
            receipt_operation_id: operation_id,
            routed_operation_id: operation_id,
            device_id: id(ID_3),
            device_sequence: 1,
            safe_error_code: "integrity_quarantined",
            envelope: b"bounded-envelope",
            quarantined_at_ms: 44,
            advance_cursor: false,
        })
        .unwrap();
    drop(vault);

    let raw = open_keyed(path.path(), &key);
    support::remove_native_memory_migrations_after_schema_23(&raw);
    raw.execute_batch(
        "DROP TABLE recovery_restores;
         DROP TABLE recovery_enrollments;
         DROP TABLE pairing_approval_transcripts;
         DROP TABLE pairing_joins;
         DROP TABLE pairing_decisions;
         DROP TABLE device_certificates;
         DROP TABLE sync_checkpoint_scans;
         DROP TABLE sync_record_owners;
         DROP TABLE sync_checkpoint_schedule;
         DROP TABLE sync_checkpoint_pins;
         DROP TABLE signed_sync_checkpoints;
         DROP TABLE sync_rejections;
         PRAGMA user_version = 15;",
    )
    .unwrap();
    drop(raw);

    let vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(vault.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
    assert_eq!(
        vault
            .quarantined_sync_receipt(
                id(ID_1),
                id(ID_2),
                "memory",
                "2026-08-06T11:12:13Z",
                operation_id,
            )
            .unwrap()
            .unwrap()
            .envelope,
        b"bounded-envelope"
    );
}

#[test]
fn commit_materializes_all_variants_and_tombstones_remove_them() {
    let path = TempVault::new("sync-materialization");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let mutations = all_mutations();
    let mut previous = None;
    for (index, mutation) in mutations.iter().enumerate() {
        let operation_id = generated_id(index as u16 + 1);
        let embedding = matches!(
            mutation,
            RecordMutationV1::UpsertMemory(_) | RecordMutationV1::UpsertInstruction(_)
        )
        .then(|| basis(index));
        let built = build(mutation, &operation_id, previous);
        assert_eq!(
            vault
                .commit_outgoing_operation(mutation, &built, embedding.as_ref())
                .unwrap(),
            CommitDisposition::Inserted
        );
        previous = Some(OperationChainHead {
            sequence: built.operation.device_sequence,
            canonical_hash: built.canonical_hash,
        });
    }
    assert!(vault.memory(&id(ID_1)).unwrap().is_some());
    assert!(vault.candidate(&id(ID_2)).unwrap().is_some());
    assert!(vault.task(&id(ID_3)).unwrap().is_some());
    assert!(vault.instruction(&id(ID_4)).unwrap().is_some());
    assert!(
        vault
            .projects()
            .unwrap()
            .iter()
            .any(|value| value.project_id == id(ID_7))
    );

    for (index, mutation) in mutations.iter().enumerate() {
        let tombstone = RecordMutationV1::Tombstone {
            record_id: mutation.record_id(),
            record_kind: mutation.record_kind(),
        };
        let built = build_with_project(
            &tombstone,
            &generated_id(index as u16 + 101),
            previous,
            project_for(mutation),
        );
        vault
            .commit_outgoing_operation(&tombstone, &built, None)
            .unwrap();
        previous = Some(OperationChainHead {
            sequence: built.operation.device_sequence,
            canonical_hash: built.canonical_hash,
        });
    }
    assert!(vault.memory(&id(ID_1)).unwrap().is_none());
    assert!(vault.candidate(&id(ID_2)).unwrap().is_none());
    assert!(vault.task(&id(ID_3)).unwrap().is_none());
    assert!(vault.instruction(&id(ID_4)).unwrap().is_none());
    assert!(
        !vault
            .projects()
            .unwrap()
            .iter()
            .any(|value| value.project_id == id(ID_7))
    );
    drop(vault);
    let raw = open_keyed(path.path(), &keys.key(CREDENTIAL));
    for table in [
        "records",
        "candidates",
        "tasks",
        "instructions",
        "secret_refs",
        "components",
        "projects",
        "search_documents",
        "embeddings",
        "search_fts",
    ] {
        let count: i64 = raw
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0, "{table} retained a tombstoned row");
    }
}

#[test]
fn missing_embedding_and_nonce_collision_roll_back_every_atomic_write() {
    let path = TempVault::new("sync-atomic-rollback");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let mutation = all_mutations().remove(0);
    let collision_nonce = XChaChaNonce([44; 24]);
    let built = build_with_nonce(&mutation, &generated_id(220), None, collision_nonce, 11);
    assert!(
        vault
            .commit_outgoing_operation(&mutation, &built, None)
            .is_err()
    );
    assert!(vault.memory(&id(ID_1)).unwrap().is_none());
    assert!(vault.due_outbox(0, 10).unwrap().is_empty());
    assert!(
        vault
            .device_head(id(WORKSPACE_ID), id(DEVICE_ID))
            .unwrap()
            .is_none()
    );
    assert!(
        vault
            .record_heads(id(WORKSPACE_ID), mutation.record_id())
            .unwrap()
            .is_empty()
    );

    vault
        .commit_outgoing_operation(&mutation, &built, Some(&basis(0)))
        .unwrap();
    let second_mutation = RecordMutationV1::UpsertSecretRef(SecretRef {
        id: id(ID_6),
        name: "Other".to_owned(),
        provider: "provider".to_owned(),
        required_on_device: false,
    });
    let collision = build_with_nonce(
        &second_mutation,
        &generated_id(221),
        Some(OperationChainHead {
            sequence: built.operation.device_sequence,
            canonical_hash: built.canonical_hash,
        }),
        collision_nonce,
        12,
    );
    assert!(
        vault
            .commit_outgoing_operation(&second_mutation, &collision, None)
            .is_err()
    );
    assert_eq!(vault.due_outbox(0, 10).unwrap().len(), 1);
    assert!(
        vault
            .record_heads(id(WORKSPACE_ID), second_mutation.record_id())
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        vault
            .device_head(id(WORKSPACE_ID), id(DEVICE_ID))
            .unwrap()
            .unwrap()
            .canonical_hash,
        built.canonical_hash
    );
    drop(vault);
    let raw = open_keyed(path.path(), &keys.key(CREDENTIAL));
    assert_eq!(
        raw.query_row("SELECT count(*) FROM secret_refs", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        raw.query_row("SELECT count(*) FROM sync_nonces", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    for table in [
        "operations",
        "outbox",
        "sync_operation_meta",
        "sync_device_heads",
        "sync_record_heads",
    ] {
        assert_eq!(
            raw.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            1,
            "{table} retained a partial collision write"
        );
    }
}

#[test]
fn exact_replay_is_a_noop_but_altered_replay_rolls_back() {
    let path = TempVault::new("sync-replay");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let mutation = all_mutations().remove(0);
    let operation_id = generated_id(230);
    let built = build(&mutation, &operation_id, None);
    assert_eq!(
        vault
            .commit_outgoing_operation(&mutation, &built, Some(&basis(0)))
            .unwrap(),
        CommitDisposition::Inserted
    );
    assert_eq!(
        vault
            .commit_outgoing_operation(&mutation, &built, None)
            .unwrap(),
        CommitDisposition::ExactReplay
    );
    assert_eq!(vault.due_outbox(0, 10).unwrap().len(), 1);
    assert_eq!(
        vault
            .record_heads(id(WORKSPACE_ID), mutation.record_id())
            .unwrap()
            .len(),
        1
    );

    let mut altered = mutation.clone();
    let RecordMutationV1::UpsertMemory(value) = &mut altered else {
        unreachable!()
    };
    value.title = "Altered replay".to_owned();
    let error = vault.commit_outgoing_operation(
        &altered,
        &build(&altered, &operation_id, None),
        Some(&basis(1)),
    );
    assert!(matches!(error, Err(VaultError::OperationConflict)));
    let RecordMutationV1::UpsertMemory(original) = mutation else {
        unreachable!()
    };
    assert_eq!(vault.memory(&original.id).unwrap(), Some(original));
    assert_eq!(vault.due_outbox(0, 10).unwrap().len(), 1);
}

#[test]
fn outbox_retry_ack_heads_cursor_and_u64_sequences_survive_reopen() {
    let path = TempVault::new("sync-durable-state");
    let keys = MemoryKeyStore::default();
    let key = [42; 32];
    keys.insert(CREDENTIAL, key);
    let vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let mutation = RecordMutationV1::UpsertSecretRef(SecretRef {
        id: id(ID_6),
        name: "Token".to_owned(),
        provider: "provider".to_owned(),
        required_on_device: true,
    });
    let previous = OperationChainHead {
        sequence: i64::MAX as u64,
        canonical_hash: Sha256Digest([19; 32]),
    };
    let built = build(&mutation, &generated_id(240), Some(previous));
    let operation_id = built.operation.operation_id;
    drop(vault);
    let raw = open_keyed(path.path(), &key);
    raw.execute(
        "INSERT INTO sync_device_heads(
             workspace_id, device_id, device_sequence, canonical_sha256
         ) VALUES (?1, ?2, ?3, ?4)",
        params![
            WORKSPACE_ID,
            DEVICE_ID,
            previous.sequence.to_string(),
            previous.canonical_hash.0.as_slice()
        ],
    )
    .unwrap();
    drop(raw);
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault
        .commit_outgoing_operation(&mutation, &built, None)
        .unwrap();
    assert_eq!(vault.due_outbox(0, 1).unwrap()[0].attempt_count, 0);
    vault
        .defer_outbox(&[operation_id], 500, "transient")
        .unwrap();
    assert!(vault.due_outbox(499, 10).unwrap().is_empty());
    drop(vault);

    let raw = open_keyed(path.path(), &key);
    raw.execute(
        "INSERT INTO sync_cursors(workspace_id, provider, received_at, operation_id) VALUES (?1, 'memory', '2026-08-06T01:02:03Z', ?2)",
        params![WORKSPACE_ID, operation_id.to_string()],
    ).unwrap();
    drop(raw);

    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let due = vault.due_outbox(500, 10).unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].attempt_count, 1);
    assert_eq!(due[0].canonical_bytes, built.canonical_bytes);
    let device_head = vault
        .device_head(id(WORKSPACE_ID), id(DEVICE_ID))
        .unwrap()
        .unwrap();
    assert_eq!(device_head.sequence, i64::MAX as u64 + 1);
    assert_eq!(device_head.canonical_hash, built.canonical_hash);
    let record_head = vault
        .record_heads(id(WORKSPACE_ID), mutation.record_id())
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(record_head.operation_id, operation_id);
    assert_eq!(record_head.record_kind, RecordKind::SecretRef);
    assert_eq!(record_head.mutation_kind, MutationKind::Upsert);
    assert_eq!(record_head.canonical_hash, built.canonical_hash);
    let cursor = vault
        .sync_cursor(id(WORKSPACE_ID), "memory")
        .unwrap()
        .unwrap();
    assert_eq!(cursor.received_at, "2026-08-06T01:02:03Z");
    assert_eq!(cursor.operation_id, operation_id);
    vault.acknowledge_outbox(&[operation_id]).unwrap();
    drop(vault);
    assert!(
        Vault::open(path.path(), CREDENTIAL, &keys)
            .unwrap()
            .due_outbox(u64::MAX, 10)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn plaintext_canary_never_enters_sync_metadata_cells() {
    let path = TempVault::new("sync-canary");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let mutation = all_mutations().remove(0);
    let built = build(&mutation, &generated_id(250), None);
    vault
        .commit_outgoing_operation(&mutation, &built, Some(&basis(0)))
        .unwrap();
    let mut oversized = vec![0; MAX_CBOR_OPERATION_BYTES + 1];
    oversized[..CANARY.len()].copy_from_slice(CANARY.as_bytes());
    let rejected_operation_id = id(&generated_id(259));
    vault
        .reject_oversized_sync_receipt(&SyncRejectionWrite {
            account_id: id(ACCOUNT_ID),
            workspace_id: id(WORKSPACE_ID),
            provider: "memory",
            received_at: "2026-08-06T14:15:16Z",
            receipt_operation_id: rejected_operation_id,
            routed_operation_id: rejected_operation_id,
            device_id: id(DEVICE_ID),
            device_sequence: 2,
            safe_error_code: "integrity_quarantined",
            received_bytes: &oversized,
            rejected_at_ms: 999,
            advance_cursor: false,
        })
        .unwrap();
    let sync_tables = [
        "operations",
        "outbox",
        "sync_operation_meta",
        "sync_device_heads",
        "sync_record_heads",
        "sync_cursors",
        "sync_checkpoint_meta",
        "signed_sync_checkpoints",
        "sync_checkpoint_pins",
        "sync_checkpoint_schedule",
        "sync_checkpoint_scans",
        "sync_nonces",
        "sync_quarantine",
        "sync_rejections",
    ];
    for cell in vault
        .test_plaintext_cells()
        .unwrap()
        .into_iter()
        .filter(|cell| sync_tables.contains(&cell.table.as_str()))
    {
        assert!(
            !cell
                .bytes
                .windows(CANARY.len())
                .any(|window| window == CANARY.as_bytes()),
            "plaintext in {}.{}",
            cell.table,
            cell.column
        );
    }
}
