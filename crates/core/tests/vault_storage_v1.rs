mod support;

use std::{fs, process::Command};

use context_relay_core::{
    search::AllowedSearchScope,
    service::OfflineWorkspace,
    vault::{BeforeImagePolicy, LATEST_SCHEMA_VERSION, Vault, VaultError},
};
use context_relay_protocol::{
    HarnessAccessPolicy, MAX_EVIDENCE_ITEMS, MemoryCreateParams, MemoryKind, MutationKind,
    RecordKind, ScopeRef, Sha256Digest, TaskStatus, TaskTransitionParams, TaskUpsertParams,
};
use rusqlite::{Connection, params};

use support::{
    ID_1, ID_2, ID_3, ID_4, ID_5, ID_6, ID_7, ID_9, MemoryKeyStore, TempVault, basis, candidate,
    checkpoint, clock, instruction, memory, native_path, operation, receipt, task,
};

const CREDENTIAL: &str = "task-6-tests";

fn open_keyed(path: &std::path::Path, key: &[u8; 32]) -> Connection {
    let connection = Connection::open(path).unwrap();
    // SAFETY: the connection owns the handle, the 32-byte key remains valid for the call,
    // and this is the first SQLite operation after open.
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

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_key(value: &str) -> [u8; 32] {
    let mut key = [0; 32];
    for (index, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
    }
    key
}

fn generated_id(index: u16) -> String {
    format!("018f22e2-79b0-7cc8-98c4-dc0c0c07{index:04x}")
}

fn version_at_least(actual: &str, minimum: [u32; 3]) -> bool {
    let numeric = actual.split_whitespace().next().unwrap();
    let mut parts = numeric.split('.').map(|part| part.parse::<u32>().unwrap());
    [
        parts.next().unwrap(),
        parts.next().unwrap(),
        parts.next().unwrap(),
    ] >= minimum
}

#[test]
fn wrong_or_missing_key_fails_closed_and_secure_defaults_are_active() {
    let path = TempVault::new("keys");
    let keys = MemoryKeyStore::default();
    let vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let runtime = vault.runtime_info().unwrap();
    assert!(version_at_least(&runtime.sqlite_version, [3, 53, 2]));
    assert!(version_at_least(&runtime.cipher_version, [4, 17, 0]));
    assert!(runtime.fts5_enabled);
    assert!(runtime.defensive);
    assert!(!runtime.trusted_schema);
    assert!(runtime.foreign_keys);
    assert_eq!(runtime.journal_mode, "delete");
    assert_eq!(runtime.temp_store, 2);
    assert!(runtime.secure_delete);
    drop(vault);

    let correct_key = keys.key(CREDENTIAL);
    keys.remove(CREDENTIAL);
    assert!(matches!(
        Vault::open(path.path(), CREDENTIAL, &keys),
        Err(VaultError::MissingKey)
    ));

    keys.insert(CREDENTIAL, [9; 32]);
    assert!(matches!(
        Vault::open(path.path(), CREDENTIAL, &keys),
        Err(VaultError::WrongKey)
    ));

    keys.insert(CREDENTIAL, correct_key);
    assert!(Vault::open(path.path(), CREDENTIAL, &keys).is_ok());
}

#[test]
fn migrations_run_once_reject_future_versions_and_roll_back_failure() {
    let path = TempVault::new("migrations");
    let keys = MemoryKeyStore::default();
    let key = [11; 32];
    keys.insert(CREDENTIAL, key);

    let raw = open_keyed(path.path(), &key);
    raw.execute("CREATE TABLE search_fts(blocker INTEGER)", [])
        .unwrap();
    drop(raw);

    assert!(matches!(
        Vault::open(path.path(), CREDENTIAL, &keys),
        Err(VaultError::Migration(_))
    ));
    let raw = open_keyed(path.path(), &key);
    assert!(
        raw.query_row("SELECT count(*) FROM records", [], |_| Ok(()))
            .is_err()
    );
    assert_eq!(
        raw.query_row("SELECT count(*) FROM search_fts", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    raw.execute("DROP TABLE search_fts", []).unwrap();
    drop(raw);

    let vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(vault.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
    drop(vault);
    let vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(vault.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
    drop(vault);

    let raw = open_keyed(path.path(), &key);
    raw.pragma_update(None, "user_version", LATEST_SCHEMA_VERSION + 1)
        .unwrap();
    drop(raw);
    assert!(matches!(
        Vault::open(path.path(), CREDENTIAL, &keys),
        Err(VaultError::FutureSchema { .. })
    ));
}

#[test]
fn version_one_vault_upgrades_before_images_without_data_loss() {
    let path = TempVault::new("migration-v1-to-v2");
    let keys = MemoryKeyStore::default();
    let key = [12; 32];
    keys.insert(CREDENTIAL, key);

    let raw = open_keyed(path.path(), &key);
    raw.execute_batch(include_str!("../migrations/0001_vault.sql"))
        .unwrap();
    raw.pragma_update(None, "user_version", 1).unwrap();
    let legacy_receipt = receipt(ID_1, 10);
    raw.execute(
        "INSERT INTO receipts(plan_id, successful, resolved, applied_ms, payload_json)
         VALUES (?1, 1, 1, 10, ?2)",
        params![
            legacy_receipt.plan_id.to_string(),
            serde_json::to_vec(&legacy_receipt).unwrap()
        ],
    )
    .unwrap();
    raw.execute(
        "INSERT INTO before_images(id, receipt_id, created_ms, payload)
         VALUES ('legacy', ?1, 10, X'01')",
        [legacy_receipt.plan_id.to_string()],
    )
    .unwrap();
    raw.execute("CREATE TABLE before_images_v2(blocker INTEGER)", [])
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
        1
    );
    assert_eq!(
        raw.query_row("SELECT count(*) FROM before_images", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        1
    );
    raw.execute("DROP TABLE before_images_v2", []).unwrap();
    drop(raw);

    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(vault.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
    assert!(vault.has_before_image("legacy").unwrap());
    assert_eq!(
        vault.receipt(&legacy_receipt.plan_id).unwrap(),
        Some(legacy_receipt)
    );

    let pending_receipt = receipt(ID_2, 20);
    vault
        .put_before_image(
            "pending",
            Some(&pending_receipt.plan_id),
            &[2],
            20,
            BeforeImagePolicy::new(10, 100),
        )
        .unwrap();
    vault.put_receipt(&pending_receipt, true, true).unwrap();
    assert!(vault.has_before_image("pending").unwrap());
}

#[test]
fn version_five_vault_adds_local_operation_results_without_losing_bindings() {
    let path = TempVault::new("migration-v5-to-v6");
    let keys = MemoryKeyStore::default();
    let key = [13; 32];
    keys.insert(CREDENTIAL, key);

    let raw = open_keyed(path.path(), &key);
    raw.execute_batch(include_str!("../migrations/0001_vault.sql"))
        .unwrap();
    raw.execute_batch(include_str!("../migrations/0002_before_image_plans.sql"))
        .unwrap();
    raw.execute_batch(include_str!("../migrations/0003_native_transactions.sql"))
        .unwrap();
    raw.execute_batch(include_str!("../migrations/0004_offline_workspace.sql"))
        .unwrap();
    raw.execute_batch(include_str!(
        "../migrations/0005_local_operation_bindings.sql"
    ))
    .unwrap();
    raw.execute(
        "INSERT INTO local_operation_bindings(
             operation_id, operation_kind, target_id, expected_revision, canonical_payload
         ) VALUES (?1, 'memory_create', ?2, NULL, X'7B7D')",
        [ID_1, ID_1],
    )
    .unwrap();
    raw.pragma_update(None, "user_version", 5).unwrap();
    drop(raw);

    let vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(vault.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
    assert!(
        vault
            .table_names()
            .unwrap()
            .iter()
            .any(|name| name == "local_operation_results")
    );
    drop(vault);

    let raw = open_keyed(path.path(), &key);
    assert_eq!(
        raw.query_row(
            "SELECT count(*) FROM local_operation_bindings WHERE operation_id = ?1",
            [ID_1],
            |row| row.get::<_, i64>(0),
        )
        .unwrap(),
        1
    );
    assert_eq!(
        raw.query_row("SELECT count(*) FROM local_operation_results", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        0
    );
}

#[test]
fn version_six_vault_preserves_operation_snapshots_and_accepts_task_bindings() {
    let path = TempVault::new("migration-v6-to-v7");
    let keys = MemoryKeyStore::default();
    let key = [14; 32];
    keys.insert(CREDENTIAL, key);
    let legacy_params = MemoryCreateParams {
        operation_id: ID_1.parse().unwrap(),
        scope: ScopeRef::Global,
        kind: MemoryKind::Fact,
        title: "Preserved memory".to_owned(),
        body_markdown: "Preserved snapshot".to_owned(),
        tags: vec!["migration".to_owned()],
    };
    let mut legacy_snapshot = memory(
        ID_1,
        ScopeRef::Global,
        "Preserved memory",
        "Preserved snapshot",
    );
    legacy_snapshot.tags = vec!["migration".to_owned()];
    legacy_snapshot.revision = ID_1.parse().unwrap();
    let canonical_payload = serde_json::to_vec(&legacy_params).unwrap();
    let canonical_response = serde_json::to_vec(&legacy_snapshot).unwrap();

    let raw = open_keyed(path.path(), &key);
    raw.execute_batch(include_str!("../migrations/0001_vault.sql"))
        .unwrap();
    raw.execute_batch(include_str!("../migrations/0002_before_image_plans.sql"))
        .unwrap();
    raw.execute_batch(include_str!("../migrations/0003_native_transactions.sql"))
        .unwrap();
    raw.execute_batch(include_str!("../migrations/0004_offline_workspace.sql"))
        .unwrap();
    raw.execute_batch(include_str!(
        "../migrations/0005_local_operation_bindings.sql"
    ))
    .unwrap();
    raw.execute_batch(include_str!(
        "../migrations/0006_local_operation_results.sql"
    ))
    .unwrap();
    raw.execute(
        "INSERT INTO local_operation_bindings(
             operation_id, operation_kind, target_id, expected_revision, canonical_payload
         ) VALUES (?1, 'memory_create', ?2, NULL, ?3)",
        params![ID_1, ID_1, &canonical_payload],
    )
    .unwrap();
    raw.execute(
        "INSERT INTO local_operation_results(operation_id, canonical_response)
         VALUES (?1, ?2)",
        params![ID_1, &canonical_response],
    )
    .unwrap();
    raw.pragma_update(None, "user_version", 6).unwrap();
    drop(raw);

    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(vault.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
    let mut workspace = OfflineWorkspace::new(&mut vault, ID_9.parse().unwrap());
    assert_eq!(
        workspace.create_memory(legacy_params).unwrap(),
        legacy_snapshot
    );
    let task = workspace
        .upsert_task(TaskUpsertParams {
            operation_id: ID_2.parse().unwrap(),
            task_id: None,
            project_id: ID_7.parse().unwrap(),
            title: "Migrated task".to_owned(),
            body_markdown: "Task binding is supported after migration".to_owned(),
            status: TaskStatus::Open,
            expected_revision: None,
        })
        .unwrap();
    assert_eq!(task.id.to_string(), ID_2);
    drop(vault);

    let raw = open_keyed(path.path(), &key);
    let preserved = raw
        .query_row(
            "SELECT binding.operation_kind,
                    binding.target_id,
                    binding.expected_revision,
                    binding.canonical_payload,
                    result.canonical_response
             FROM local_operation_bindings AS binding
             JOIN local_operation_results AS result
               ON result.operation_id = binding.operation_id
             WHERE binding.operation_id = ?1",
            [ID_1],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(preserved.0, "memory_create");
    assert_eq!(preserved.1, ID_1);
    assert_eq!(preserved.2, None);
    assert_eq!(preserved.3, canonical_payload);
    assert_eq!(preserved.4, canonical_response);
    assert_eq!(
        raw.query_row(
            "SELECT operation_kind FROM local_operation_bindings WHERE operation_id = ?1",
            [ID_2],
            |row| row.get::<_, String>(0),
        )
        .unwrap(),
        "task_upsert"
    );
    assert_eq!(
        raw.query_row(
            "SELECT count(*) FROM local_operation_results WHERE operation_id = ?1",
            [ID_2],
            |row| row.get::<_, i64>(0),
        )
        .unwrap(),
        1
    );
}

#[test]
fn version_seven_vault_preserves_task_snapshots_and_accepts_transition_bindings() {
    let path = TempVault::new("migration-v7-to-v8");
    let keys = MemoryKeyStore::default();
    let key = [15; 32];
    keys.insert(CREDENTIAL, key);
    let legacy_params = TaskUpsertParams {
        operation_id: ID_1.parse().unwrap(),
        task_id: None,
        project_id: ID_7.parse().unwrap(),
        title: "Preserved task".to_owned(),
        body_markdown: "Preserved task snapshot".to_owned(),
        status: TaskStatus::Open,
        expected_revision: None,
    };
    let mut legacy_snapshot = task();
    legacy_snapshot.id = ID_1.parse().unwrap();
    legacy_snapshot.title.clone_from(&legacy_params.title);
    legacy_snapshot
        .body_markdown
        .clone_from(&legacy_params.body_markdown);
    legacy_snapshot.revision = ID_1.parse().unwrap();
    let canonical_payload = serde_json::to_vec(&legacy_params).unwrap();
    let canonical_response = serde_json::to_vec(&legacy_snapshot).unwrap();
    let mut legacy_decision = memory(
        ID_3,
        ScopeRef::Project {
            project_id: legacy_params.project_id,
        },
        "Preserved decision",
        "Backfill the handoff query projection",
    );
    legacy_decision.kind = MemoryKind::Decision;
    legacy_decision.updated_hlc = clock(77);
    let decision_response = serde_json::to_vec(&legacy_decision).unwrap();

    let raw = open_keyed(path.path(), &key);
    raw.execute_batch(include_str!("../migrations/0001_vault.sql"))
        .unwrap();
    raw.execute_batch(include_str!("../migrations/0002_before_image_plans.sql"))
        .unwrap();
    raw.execute_batch(include_str!("../migrations/0003_native_transactions.sql"))
        .unwrap();
    raw.execute_batch(include_str!("../migrations/0004_offline_workspace.sql"))
        .unwrap();
    raw.execute_batch(include_str!(
        "../migrations/0005_local_operation_bindings.sql"
    ))
    .unwrap();
    raw.execute_batch(include_str!(
        "../migrations/0006_local_operation_results.sql"
    ))
    .unwrap();
    raw.execute_batch(include_str!(
        "../migrations/0007_task_operation_bindings.sql"
    ))
    .unwrap();
    raw.execute(
        "INSERT INTO tasks(id, project_id, status, payload_json)
         VALUES (?1, ?2, 'open', ?3)",
        params![ID_1, ID_7, &canonical_response],
    )
    .unwrap();
    raw.execute(
        "INSERT INTO records(
             id, kind, scope_kind, project_id, archived, payload_json
         ) VALUES (?1, 'memory', 'project', ?2, 0, ?3)",
        params![ID_3, ID_7, &decision_response],
    )
    .unwrap();
    raw.execute(
        "INSERT INTO local_operation_bindings(
             operation_id, operation_kind, target_id, expected_revision, canonical_payload
         ) VALUES (?1, 'task_upsert', ?2, NULL, ?3)",
        params![ID_1, ID_1, &canonical_payload],
    )
    .unwrap();
    raw.execute(
        "INSERT INTO local_operation_results(operation_id, canonical_response)
         VALUES (?1, ?2)",
        params![ID_1, &canonical_response],
    )
    .unwrap();
    raw.pragma_update(None, "user_version", 7).unwrap();
    drop(raw);

    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(vault.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
    assert_eq!(
        vault
            .recent_project_decisions(legacy_params.project_id, MAX_EVIDENCE_ITEMS)
            .unwrap(),
        vec![legacy_decision]
    );
    let transitioned = OfflineWorkspace::new(&mut vault, ID_9.parse().unwrap())
        .transition_task(TaskTransitionParams {
            operation_id: ID_2.parse().unwrap(),
            task_id: legacy_snapshot.id,
            expected_revision: legacy_snapshot.revision,
            status: TaskStatus::Blocked,
        })
        .unwrap();
    assert_eq!(transitioned.status, TaskStatus::Blocked);
    drop(vault);

    let raw = open_keyed(path.path(), &key);
    let preserved = raw
        .query_row(
            "SELECT binding.operation_kind,
                    binding.canonical_payload,
                    result.canonical_response
             FROM local_operation_bindings AS binding
             JOIN local_operation_results AS result
               ON result.operation_id = binding.operation_id
             WHERE binding.operation_id = ?1",
            [ID_1],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(preserved.0, "task_upsert");
    assert_eq!(preserved.1, canonical_payload);
    assert_eq!(preserved.2, canonical_response);
    assert_eq!(
        raw.query_row(
            "SELECT operation_kind FROM local_operation_bindings WHERE operation_id = ?1",
            [ID_2],
            |row| row.get::<_, String>(0),
        )
        .unwrap(),
        "task_transition"
    );
    assert_eq!(
        raw.query_row(
            "SELECT count(*) FROM local_operation_results WHERE operation_id = ?1",
            [ID_2],
            |row| row.get::<_, i64>(0),
        )
        .unwrap(),
        1
    );
}

#[test]
fn v8_to_v9_preserves_operation_results_and_native_plan_rows() {
    let path = TempVault::new("v8-to-v9-preservation");
    let keys = MemoryKeyStore::default();
    let key = [19; 32];
    keys.insert(CREDENTIAL, key);
    let canonical_payload = br#"{"preserve":"binding"}"#;
    let canonical_response = br#"{"preserve":"result"}"#;
    let native_payload = br#"{"preserve":"native-plan"}"#;
    let approval_hash = [23_u8; 32];

    let raw = open_keyed(path.path(), &key);
    raw.execute_batch(include_str!("../migrations/0001_vault.sql"))
        .unwrap();
    raw.execute_batch(include_str!("../migrations/0002_before_image_plans.sql"))
        .unwrap();
    raw.execute_batch(include_str!("../migrations/0003_native_transactions.sql"))
        .unwrap();
    raw.execute_batch(include_str!("../migrations/0004_offline_workspace.sql"))
        .unwrap();
    raw.execute_batch(include_str!(
        "../migrations/0005_local_operation_bindings.sql"
    ))
    .unwrap();
    raw.execute_batch(include_str!(
        "../migrations/0006_local_operation_results.sql"
    ))
    .unwrap();
    raw.execute_batch(include_str!(
        "../migrations/0007_task_operation_bindings.sql"
    ))
    .unwrap();
    raw.execute_batch(include_str!(
        "../migrations/0008_task_transitions_and_handoff_queries.sql"
    ))
    .unwrap();
    raw.execute(
        "INSERT INTO local_operation_bindings(
             operation_id, operation_kind, target_id, expected_revision, canonical_payload
         ) VALUES (?1, 'memory_create', ?2, NULL, ?3)",
        params![ID_1, ID_2, canonical_payload],
    )
    .unwrap();
    raw.execute(
        "INSERT INTO local_operation_results(operation_id, canonical_response)
         VALUES (?1, ?2)",
        params![ID_1, canonical_response],
    )
    .unwrap();
    raw.execute(
        "INSERT INTO native_plans(
             plan_id, approval_hash, payload, created_ms, expires_ms
         ) VALUES (?1, ?2, ?3, 10, 20)",
        params![ID_3, approval_hash, native_payload],
    )
    .unwrap();
    raw.execute(
        "INSERT INTO native_transactions(
             transaction_id, plan_id, status, current_step, entered_step,
             created_ms, updated_ms, platform, windows_moniker, windows_sid
         ) VALUES (?1, ?2, 'pending', 0, 0, 10, 10, 'windows', ?3, ?4)",
        params![
            "preserved-native-transaction",
            ID_3,
            "context-relay.native.0123456789abcdef0123456789abcdef",
            b"S-1-15-2-preserved".as_slice(),
        ],
    )
    .unwrap();
    raw.pragma_update(None, "user_version", 8).unwrap();
    drop(raw);

    let vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(vault.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
    assert!(
        vault
            .table_names()
            .unwrap()
            .iter()
            .any(|name| name == "setup_plan_lifecycle")
    );
    drop(vault);

    let raw = open_keyed(path.path(), &key);
    let operation = raw
        .query_row(
            "SELECT binding.canonical_payload, result.canonical_response
             FROM local_operation_bindings AS binding
             JOIN local_operation_results AS result USING(operation_id)
             WHERE binding.operation_id = ?1",
            [ID_1],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .unwrap();
    assert_eq!(operation.0, canonical_payload);
    assert_eq!(operation.1, canonical_response);
    let native = raw
        .query_row(
            "SELECT approval_hash, payload FROM native_plans WHERE plan_id = ?1",
            [ID_3],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .unwrap();
    assert_eq!(native.0, approval_hash);
    assert_eq!(native.1, native_payload);
    assert_eq!(
        raw.query_row(
            "SELECT plan_id FROM native_transactions WHERE transaction_id = ?1",
            ["preserved-native-transaction"],
            |row| row.get::<_, String>(0),
        )
        .unwrap(),
        ID_3
    );
}

#[test]
fn bounded_handoff_queries_filter_and_limit_records_in_storage() {
    let path = TempVault::new("bounded-handoff-queries");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let project_id = ID_7.parse().unwrap();
    let project_scope = ScopeRef::Project { project_id };
    for index in 0..70_u16 {
        let record_id = generated_id(100 + index);
        let mut record = memory(
            &record_id,
            project_scope.clone(),
            &format!("Decision {index}"),
            "bounded handoff decision",
        );
        record.kind = MemoryKind::Decision;
        record.updated_hlc = clock(u64::from(index));
        vault
            .put_local_memory(&record, &basis(usize::from(index) % 384))
            .unwrap();
    }
    let mut fact = memory(
        &generated_id(99),
        project_scope,
        "Not a decision",
        "must be filtered before the limit",
    );
    fact.updated_hlc = clock(u64::MAX);
    vault.put_local_memory(&fact, &basis(100)).unwrap();

    let mut canceled = task();
    canceled.id = generated_id(299).parse().unwrap();
    canceled.status = TaskStatus::Canceled;
    vault.put_task(&canceled).unwrap();
    for index in 0..70_u16 {
        let mut record = task();
        record.id = generated_id(300 + index).parse().unwrap();
        record.status = if index % 2 == 0 {
            TaskStatus::Open
        } else {
            TaskStatus::Blocked
        };
        vault.put_task(&record).unwrap();
    }

    let decisions = vault
        .recent_project_decisions(project_id, MAX_EVIDENCE_ITEMS)
        .unwrap();
    let tasks = vault
        .open_or_blocked_tasks(project_id, MAX_EVIDENCE_ITEMS)
        .unwrap();

    assert_eq!(decisions.len(), MAX_EVIDENCE_ITEMS);
    assert_eq!(decisions.first().unwrap().id.to_string(), generated_id(169));
    assert_eq!(decisions.last().unwrap().id.to_string(), generated_id(106));
    assert!(
        decisions
            .iter()
            .all(|record| record.kind == MemoryKind::Decision)
    );
    assert_eq!(tasks.len(), MAX_EVIDENCE_ITEMS);
    assert_eq!(tasks.first().unwrap().id.to_string(), generated_id(300));
    assert_eq!(tasks.last().unwrap().id.to_string(), generated_id(363));
    assert!(
        tasks
            .iter()
            .all(|record| matches!(record.status, TaskStatus::Open | TaskStatus::Blocked))
    );
}

#[test]
fn instruction_fold_streams_the_full_allowed_corpus_with_bounded_caller_state() {
    #[derive(Default)]
    struct Probe {
        visited: usize,
        relevant: usize,
        retained_ids: Vec<context_relay_protocol::RecordId>,
        peak_retained_candidates: usize,
    }

    let path = TempVault::new("streaming-instruction-fold");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    for index in 0..180_u16 {
        let record_id = generated_id(1_000 + index);
        let value = instruction(
            &record_id,
            ScopeRef::Global,
            &format!("Instruction {index}"),
            if index < 100 {
                "unrelated guidance"
            } else {
                "later relevant streamneedle"
            },
        );
        vault
            .put_instruction(
                &value,
                &operation(
                    &generated_id(3_000 + index),
                    &record_id,
                    RecordKind::Instruction,
                ),
                &basis(usize::from(index) % 384),
            )
            .unwrap();
    }
    let scope = AllowedSearchScope::resolve(None, &HarnessAccessPolicy::Default, None).unwrap();

    let probe = vault
        .fold_instructions(&scope, Probe::default(), |probe, value| {
            probe.visited += 1;
            if value.body_markdown.contains("streamneedle") {
                probe.relevant += 1;
                if probe.retained_ids.len() < MAX_EVIDENCE_ITEMS {
                    probe.retained_ids.push(value.id);
                }
            }
            probe.peak_retained_candidates =
                probe.peak_retained_candidates.max(probe.retained_ids.len());
            Ok(())
        })
        .unwrap();

    assert_eq!(probe.visited, 180);
    assert_eq!(probe.relevant, 80);
    assert_eq!(probe.retained_ids.len(), MAX_EVIDENCE_ITEMS);
    assert!(probe.peak_retained_candidates <= MAX_EVIDENCE_ITEMS);
    assert_eq!(
        probe.retained_ids.first().unwrap().to_string(),
        generated_id(1_100)
    );
    assert_eq!(
        probe.retained_ids.last().unwrap().to_string(),
        generated_id(1_163)
    );
}

#[test]
fn every_required_table_round_trips_validated_protocol_payloads() {
    let path = TempVault::new("round-trip");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();

    let stored_memory = memory(ID_1, ScopeRef::Global, "Memory", "round trip needle");
    let memory_operation = operation(ID_4, ID_1, RecordKind::Memory);
    vault
        .put_memory(&stored_memory, &memory_operation, &basis(0))
        .unwrap();
    assert_eq!(
        vault.memory(&stored_memory.id).unwrap(),
        Some(stored_memory.clone())
    );
    assert_eq!(
        vault.outbox_operations().unwrap(),
        vec![memory_operation.clone()]
    );
    assert_eq!(
        vault.provenance(ID_1).unwrap(),
        Some(stored_memory.provenance.clone())
    );

    let candidate = candidate();
    vault.put_candidate(&candidate).unwrap();
    assert_eq!(
        vault.candidate(&candidate.id).unwrap(),
        Some(candidate.clone())
    );

    let task = task();
    vault.put_task(&task).unwrap();
    assert_eq!(vault.task(&task.id).unwrap(), Some(task.clone()));

    let instruction = instruction(ID_2, ScopeRef::Global, "Instruction", "round trip");
    let instruction_operation = operation(ID_5, ID_2, RecordKind::Instruction);
    vault
        .put_instruction(&instruction, &instruction_operation, &basis(1))
        .unwrap();
    assert_eq!(
        vault.instruction(&instruction.id).unwrap(),
        Some(instruction.clone())
    );

    let checkpoint = checkpoint();
    vault.put_checkpoint(&checkpoint).unwrap();
    assert_eq!(
        vault.checkpoint(&checkpoint.state_hash).unwrap(),
        Some(checkpoint.clone())
    );

    let mut contender = memory_operation.clone();
    contender.operation_id = ID_6.parse().unwrap();
    contender.device_sequence = 2;
    vault
        .put_conflict(&memory_operation.record_id, &memory_operation, &contender)
        .unwrap();
    assert_eq!(
        vault.conflict(&memory_operation.record_id).unwrap(),
        Some((memory_operation.clone(), contender))
    );

    let receipt = receipt(ID_7, 100);
    vault.put_receipt(&receipt, true, true).unwrap();
    assert_eq!(
        vault.receipt(&receipt.plan_id).unwrap(),
        Some(receipt.clone())
    );

    let path_value = native_path();
    vault.put_path(ID_3, &path_value).unwrap();
    assert_eq!(vault.path(ID_3).unwrap(), Some(path_value));

    let mut invalid = memory(ID_3, ScopeRef::Global, " ", "invalid");
    invalid.tags.clear();
    let invalid_operation = operation(ID_6, ID_3, RecordKind::Memory);
    assert!(
        vault
            .put_memory(&invalid, &invalid_operation, &basis(2))
            .is_err()
    );
    assert_eq!(vault.memory(&invalid.id).unwrap(), None);
    assert!(
        !vault
            .outbox_operations()
            .unwrap()
            .iter()
            .any(|operation| operation.operation_id == invalid_operation.operation_id)
    );
}

#[test]
fn operation_ids_are_immutable_and_live_writes_require_upserts() {
    let path = TempVault::new("operation-idempotency");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let first = memory(ID_1, ScopeRef::Global, "First", "first operation");
    let first_operation = operation(ID_4, ID_1, RecordKind::Memory);

    vault
        .put_memory(&first, &first_operation, &basis(0))
        .unwrap();
    let anchor = memory(ID_2, ScopeRef::Global, "Anchor", "semantic anchor");
    let anchor_operation = operation(ID_7, ID_2, RecordKind::Memory);
    vault
        .put_memory(&anchor, &anchor_operation, &basis(3))
        .unwrap();
    let mut altered_retry = first.clone();
    altered_retry.title = "Altered retry".to_owned();
    vault
        .put_memory(&altered_retry, &first_operation, &basis(3))
        .unwrap();
    assert_eq!(vault.memory(&first.id).unwrap(), Some(first.clone()));
    let scope = AllowedSearchScope::resolve(None, &HarnessAccessPolicy::Default, None).unwrap();
    assert_eq!(
        vault.search("", &scope, &basis(3), 2).unwrap()[0].record_id(),
        ID_2
    );
    assert_eq!(
        vault.outbox_operations().unwrap(),
        vec![first_operation.clone(), anchor_operation]
    );

    let second = memory(ID_3, ScopeRef::Global, "Second", "reused operation");
    let reused_operation = operation(ID_4, ID_3, RecordKind::Memory);
    assert!(
        vault
            .put_memory(&second, &reused_operation, &basis(1))
            .is_err()
    );
    assert_eq!(vault.memory(&first.id).unwrap(), Some(first));
    assert_eq!(vault.memory(&second.id).unwrap(), None);
    assert_eq!(vault.outbox_operations().unwrap()[0], first_operation);

    let tombstoned = memory(ID_5, ScopeRef::Global, "Tombstone", "must roll back");
    let mut tombstone_operation = operation(ID_6, ID_5, RecordKind::Memory);
    tombstone_operation.mutation_kind = MutationKind::Tombstone;
    assert!(
        vault
            .put_memory(&tombstoned, &tombstone_operation, &basis(2))
            .is_err()
    );
    assert_eq!(vault.memory(&tombstoned.id).unwrap(), None);
    assert!(
        vault
            .outbox_operations()
            .unwrap()
            .iter()
            .all(|operation| { operation.operation_id != tombstone_operation.operation_id })
    );

    let batch_path = TempVault::new("batch-operation-idempotency");
    let batch_keys = MemoryKeyStore::default();
    let mut batch_vault = Vault::open(batch_path.path(), CREDENTIAL, &batch_keys).unwrap();
    let batch = vec![
        (
            memory(ID_1, ScopeRef::Global, "Batch one", "first"),
            operation(ID_6, ID_1, RecordKind::Memory),
            basis(0),
        ),
        (
            memory(ID_2, ScopeRef::Global, "Batch two", "second"),
            operation(ID_6, ID_2, RecordKind::Memory),
            basis(1),
        ),
    ];
    assert!(batch_vault.put_memories_batch(&batch).is_err());
    assert_eq!(batch_vault.memory(&batch[0].0.id).unwrap(), None);
    assert_eq!(batch_vault.memory(&batch[1].0.id).unwrap(), None);
    assert!(batch_vault.outbox_operations().unwrap().is_empty());
    assert!(
        batch_vault
            .search("Batch", &scope, &basis(0), 10)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn record_ids_cannot_change_kind() {
    let path = TempVault::new("record-kind-immutable");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let stored = memory(ID_1, ScopeRef::Global, "Memory", "stable kind");
    vault
        .put_memory(
            &stored,
            &operation(ID_4, ID_1, RecordKind::Memory),
            &basis(0),
        )
        .unwrap();

    let replacement = instruction(ID_1, ScopeRef::Global, "Instruction", "wrong kind");
    assert!(
        vault
            .put_instruction(
                &replacement,
                &operation(ID_5, ID_1, RecordKind::Instruction),
                &basis(1),
            )
            .is_err()
    );
    assert_eq!(vault.memory(&stored.id).unwrap(), Some(stored));
    assert_eq!(vault.instruction(&replacement.id).unwrap(), None);
}

#[test]
fn before_image_budget_is_exact_and_prunes_only_old_successful_resolved_receipts() {
    const DAY: u64 = 24 * 60 * 60 * 1000;
    let path = TempVault::new("before-images");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let policy = BeforeImagePolicy::new(10, 30 * DAY);
    let now = 100 * DAY;

    vault
        .put_before_image("exact", None, &[1; 10], now, policy)
        .unwrap();
    assert!(matches!(
        vault.put_before_image("overflow", None, &[2], now, policy),
        Err(VaultError::BudgetExceeded)
    ));
    assert_eq!(vault.before_image_bytes().unwrap(), 10);

    vault.delete_before_image("exact").unwrap();
    let old_success = receipt(ID_1, now - 31 * DAY);
    let cutoff_success = receipt(ID_2, now - 30 * DAY);
    let old_failed = receipt(ID_3, now - 40 * DAY);
    vault
        .put_before_image(
            "old-success",
            Some(&old_success.plan_id),
            &[3; 6],
            now,
            policy,
        )
        .unwrap();
    vault
        .put_before_image(
            "cutoff-success",
            Some(&cutoff_success.plan_id),
            &[4; 2],
            now,
            policy,
        )
        .unwrap();
    vault
        .put_before_image(
            "old-failed",
            Some(&old_failed.plan_id),
            &[5; 2],
            now,
            policy,
        )
        .unwrap();
    vault.put_receipt(&old_success, true, true).unwrap();
    vault.put_receipt(&cutoff_success, true, true).unwrap();
    vault.put_receipt(&old_failed, false, true).unwrap();

    vault
        .put_before_image("replacement", None, &[6; 6], now, policy)
        .unwrap();
    assert!(!vault.has_before_image("old-success").unwrap());
    assert!(vault.has_before_image("cutoff-success").unwrap());
    assert!(vault.has_before_image("old-failed").unwrap());
    assert!(vault.has_before_image("replacement").unwrap());
    assert_eq!(vault.before_image_bytes().unwrap(), 10);
    assert_eq!(vault.receipt(&old_success.plan_id).unwrap(), None);
    assert_eq!(
        vault.receipt(&cutoff_success.plan_id).unwrap(),
        Some(cutoff_success)
    );
    assert_eq!(
        vault.receipt(&old_failed.plan_id).unwrap(),
        Some(old_failed)
    );
}

#[test]
fn crash_rolls_back_partial_record_and_never_writes_plaintext_to_database_sidecars() {
    let path = TempVault::new("crash");
    let keys = MemoryKeyStore::default();
    drop(Vault::open(path.path(), CREDENTIAL, &keys).unwrap());
    let key = keys.key(CREDENTIAL);

    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "crash_writer_child", "--nocapture"])
        .env("CONTEXT_RELAY_CRASH_VAULT", path.path())
        .env("CONTEXT_RELAY_CRASH_KEY", encode_hex(&key))
        .status()
        .unwrap();
    assert!(!status.success());

    let sentinel = b"CONTEXT_RELAY_PLAINTEXT_CRASH_SENTINEL";
    let prefix = path.path().file_name().unwrap().to_string_lossy();
    for entry in fs::read_dir(path.path().parent().unwrap()).unwrap() {
        let entry = entry.unwrap();
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with(prefix.as_ref())
        {
            let bytes = fs::read(entry.path()).unwrap();
            assert!(
                !bytes
                    .windows(sentinel.len())
                    .any(|window| window == sentinel),
                "plaintext leaked to {}",
                entry.path().display()
            );
        }
    }

    let raw = open_keyed(path.path(), &key);
    let partial: i64 = raw
        .query_row(
            "SELECT count(*) FROM records WHERE id LIKE 'crash-%'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(partial, 0);
}

#[test]
fn crash_writer_child() {
    let Some(path) = std::env::var_os("CONTEXT_RELAY_CRASH_VAULT") else {
        return;
    };
    let key = decode_key(&std::env::var("CONTEXT_RELAY_CRASH_KEY").unwrap());
    let mut connection = open_keyed(std::path::Path::new(&path), &key);
    connection.pragma_update(None, "cache_size", 1).unwrap();
    let transaction = connection.transaction().unwrap();
    let sentinel = b"CONTEXT_RELAY_PLAINTEXT_CRASH_SENTINEL";
    for index in 0..256 {
        let mut payload = vec![0; 4096];
        payload[..sentinel.len()].copy_from_slice(sentinel);
        transaction
            .execute(
                "INSERT INTO records(id, kind, scope_kind, project_id, archived, payload_json)
                 VALUES (?1, 'memory', 'global', NULL, 0, ?2)",
                params![format!("crash-{index}"), payload],
            )
            .unwrap();
    }
    std::process::abort();
}

#[test]
fn bundled_schema_contains_all_required_tables() {
    let path = TempVault::new("tables");
    let keys = MemoryKeyStore::default();
    let vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let names = vault.table_names().unwrap();
    for required in [
        "records",
        "candidates",
        "tasks",
        "instructions",
        "operations",
        "local_operation_bindings",
        "local_operation_results",
        "outbox",
        "checkpoints",
        "conflicts",
        "receipts",
        "paths",
        "provenance",
        "before_images",
        "setup_plan_lifecycle",
        "native_cli_wal",
        "native_memory_sources",
        "search_documents",
        "embeddings",
        "search_fts",
    ] {
        assert!(names.iter().any(|name| name == required), "{required}");
    }
    assert_eq!(vault.checkpoint(&Sha256Digest([0; 32])).unwrap(), None);
}

#[test]
fn reopen_rehydrates_semantic_search_and_rejects_invalid_cached_scope() {
    let path = TempVault::new("semantic-cache-reopen");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let stored = memory(ID_1, ScopeRef::Global, "Stored", "semantic only");
    vault
        .put_memory(
            &stored,
            &operation(ID_4, ID_1, RecordKind::Memory),
            &basis(0),
        )
        .unwrap();
    drop(vault);

    let vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let scope = AllowedSearchScope::resolve(None, &HarnessAccessPolicy::Default, None).unwrap();
    assert_eq!(
        vault
            .search("lexically absent", &scope, &basis(0), 10)
            .unwrap()[0]
            .record_id(),
        ID_1
    );
    drop(vault);

    let raw = open_keyed(path.path(), &keys.key(CREDENTIAL));
    raw.execute(
        "UPDATE search_documents
         SET scope_kind = 'project', project_id = 'not-a-project-id'
         WHERE record_id = ?1",
        [ID_1],
    )
    .unwrap();
    drop(raw);

    assert!(matches!(
        Vault::open(path.path(), CREDENTIAL, &keys),
        Err(VaultError::Validation(_))
    ));

    let raw = open_keyed(path.path(), &keys.key(CREDENTIAL));
    raw.execute(
        "UPDATE search_documents
         SET scope_kind = 'global', project_id = NULL
         WHERE record_id = ?1",
        [ID_1],
    )
    .unwrap();
    raw.execute(
        "UPDATE embeddings SET vector = zeroblob(1536) WHERE record_id = ?1",
        [ID_1],
    )
    .unwrap();
    drop(raw);

    assert!(matches!(
        Vault::open(path.path(), CREDENTIAL, &keys),
        Err(VaultError::Validation(_))
    ));
}

#[test]
fn failed_embedding_insert_does_not_mutate_database_or_semantic_cache() {
    let path = TempVault::new("semantic-cache-rollback");
    let keys = MemoryKeyStore::default();
    drop(Vault::open(path.path(), CREDENTIAL, &keys).unwrap());

    let raw = open_keyed(path.path(), &keys.key(CREDENTIAL));
    raw.execute_batch(
        "CREATE TRIGGER abort_embedding_insert
         BEFORE INSERT ON embeddings
         BEGIN
           SELECT RAISE(ABORT, 'injected embedding failure');
         END;",
    )
    .unwrap();
    drop(raw);

    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let stored = memory(ID_1, ScopeRef::Global, "Stored", "semantic only");
    let stored_operation = operation(ID_4, ID_1, RecordKind::Memory);
    assert!(
        vault
            .put_memory(&stored, &stored_operation, &basis(0))
            .is_err()
    );
    assert_eq!(vault.memory(&stored.id).unwrap(), None);
    assert!(
        !vault
            .outbox_operations()
            .unwrap()
            .iter()
            .any(|operation| operation.operation_id == stored_operation.operation_id)
    );
    let scope = AllowedSearchScope::resolve(None, &HarnessAccessPolicy::Default, None).unwrap();
    assert!(vault.search("", &scope, &basis(0), 10).unwrap().is_empty());
}
