mod support;

use std::{fs, process::Command};

use context_relay_core::{
    search::AllowedSearchScope,
    vault::{BeforeImagePolicy, LATEST_SCHEMA_VERSION, Vault, VaultError},
};
use context_relay_protocol::{HarnessAccessPolicy, RecordKind, ScopeRef, Sha256Digest};
use rusqlite::{Connection, params};

use support::{
    ID_1, ID_2, ID_3, ID_4, ID_5, ID_6, ID_7, MemoryKeyStore, TempVault, basis, candidate,
    checkpoint, instruction, memory, native_path, operation, receipt, task,
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
    vault.put_receipt(&old_success, true, true).unwrap();
    vault.put_receipt(&cutoff_success, true, true).unwrap();
    vault.put_receipt(&old_failed, false, true).unwrap();
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
        "outbox",
        "checkpoints",
        "conflicts",
        "receipts",
        "paths",
        "provenance",
        "before_images",
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
