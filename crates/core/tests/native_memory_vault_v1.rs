mod support;

use context_relay_core::{
    native_memory::{
        NativeMemoryDocumentKind, NativeMemoryLedger, NativeMemoryLimits, NativeMemorySnapshot,
        NativeMemorySource, NativeMemorySourceId, ReadyNativeMemory, extract_managed_markdown,
    },
    service::OfflineWorkspace,
    vault::{Vault, VaultError},
};
use context_relay_protocol::{
    CandidateState, ErrorCode, HarnessId, MemoryOrigin, NativePlatform, ScopeRef, Sha256Digest,
    WireNativeValue,
};
use rusqlite::{Connection, params};

use support::{ID_7, MemoryKeyStore, TempVault};

const CREDENTIAL: &str = "native-memory-vault-tests";

fn open_keyed(path: &std::path::Path, key: &[u8; 32]) -> Connection {
    let connection = Connection::open(path).unwrap();
    // SAFETY: the connection owns the handle, the key remains valid for the call,
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

fn source(scope: ScopeRef, harness: HarnessId, suffix: &str) -> NativeMemorySource {
    NativeMemorySource::new(
        harness,
        "test-1.0.0",
        scope,
        NativeMemoryDocumentKind::Agent,
        WireNativeValue {
            platform: NativePlatform::Macos,
            bytes: format!("/tmp/context-relay/{suffix}.md").into_bytes(),
            display: Some(format!("/tmp/context-relay/{suffix}.md")),
        },
        NativeMemoryLimits {
            max_bytes: 4_096,
            max_characters: 4_096,
        },
        true,
    )
    .unwrap()
}

fn ledger(source: NativeMemorySource, byte: u8) -> NativeMemoryLedger {
    let mut ledger = NativeMemoryLedger::for_source(source);
    ledger.last_observed_digest = Some(Sha256Digest([byte; 32]));
    ledger.last_unmanaged_digest = Some(Sha256Digest([byte + 1; 32]));
    ledger.last_imported_digest = Some(Sha256Digest([byte + 2; 32]));
    ledger.last_applied_digest = Some(Sha256Digest([byte + 3; 32]));
    ledger.initial_preview_complete = true;
    ledger
}

fn hex(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

fn source_hex(id: NativeMemorySourceId) -> String {
    id.0.0.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn migration_v9_to_v10_preserves_prior_rows_and_enforces_scope_shape() {
    let path = TempVault::new("native-memory-migration-v9");
    let keys = MemoryKeyStore::default();
    let key = [31; 32];
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
    raw.execute_batch(include_str!(
        "../migrations/0009_setup_cli_transactions.sql"
    ))
    .unwrap();
    raw.execute(
        "INSERT INTO projects(id, payload_json) VALUES (?1, ?2)",
        params![ID_7, br#"{"preserved":true}"#.as_slice()],
    )
    .unwrap();
    raw.pragma_update(None, "user_version", 9).unwrap();
    drop(raw);

    let vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(vault.schema_version().unwrap(), 10);
    drop(vault);

    let raw = open_keyed(path.path(), &key);
    assert_eq!(
        raw.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'native_memory_sources'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap(),
        1
    );
    assert_eq!(
        raw.query_row(
            "SELECT count(*) FROM projects WHERE id = ?1",
            [ID_7],
            |row| { row.get::<_, i64>(0) }
        )
        .unwrap(),
        1
    );
    let payload = br#"{}"#;
    assert!(
        raw.execute(
            "INSERT INTO native_memory_sources(
                 source_id, harness, scope_kind, project_id, document_kind,
                 initial_preview_complete, payload_json
             ) VALUES (?1, 'codex', 'global', ?2, 'agent', 0, ?3)",
            params![hex(1), ID_7, payload.as_slice()],
        )
        .is_err()
    );
    assert!(
        raw.execute(
            "INSERT INTO native_memory_sources(
                 source_id, harness, scope_kind, project_id, document_kind,
                 initial_preview_complete, payload_json
             ) VALUES (?1, 'codex', 'project', NULL, 'agent', 0, ?2)",
            params![hex(2), payload.as_slice()],
        )
        .is_err()
    );
}

#[test]
fn ledger_round_trips_global_and_project_metadata() {
    let path = TempVault::new("native-memory-ledger-round-trip");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let global = ledger(source(ScopeRef::Global, HarnessId::Codex, "global"), 10);
    let project = ledger(
        source(
            ScopeRef::Project {
                project_id: ID_7.parse().unwrap(),
            },
            HarnessId::ClaudeCode,
            "project",
        ),
        20,
    );

    vault.put_native_memory_candidate(&global, None).unwrap();
    vault.put_native_memory_candidate(&project, None).unwrap();

    assert_eq!(
        vault.native_memory_ledger(&global.source_id).unwrap(),
        Some(global)
    );
    assert_eq!(
        vault.native_memory_ledger(&project.source_id).unwrap(),
        Some(project)
    );
    assert_eq!(
        vault
            .native_memory_ledger(&NativeMemorySourceId(Sha256Digest([99; 32])))
            .unwrap(),
        None
    );
}

#[test]
fn malformed_ledger_payload_is_rejected() {
    let path = TempVault::new("native-memory-ledger-malformed");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let stored = ledger(source(ScopeRef::Global, HarnessId::Hermes, "malformed"), 30);
    vault.put_native_memory_candidate(&stored, None).unwrap();
    drop(vault);

    let key = keys.key(CREDENTIAL);
    let raw = open_keyed(path.path(), &key);
    raw.execute(
        "UPDATE native_memory_sources SET payload_json = ?2 WHERE source_id = ?1",
        params![
            source_hex(stored.source_id),
            br#"{"unknown":true}"#.as_slice()
        ],
    )
    .unwrap();
    drop(raw);

    let vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert!(matches!(
        vault.native_memory_ledger(&stored.source_id),
        Err(VaultError::Serialization(_)) | Err(VaultError::Validation(_))
    ));
}

fn ready(source: NativeMemorySource, body: &str) -> ReadyNativeMemory {
    ReadyNativeMemory {
        source,
        snapshot: NativeMemorySnapshot::Regular(body.as_bytes().to_vec()),
    }
}

#[test]
fn native_candidates_are_deterministic_bound_and_atomically_replayed() {
    let project_id = ID_7.parse().unwrap();
    let source = source(
        ScopeRef::Project { project_id },
        HarnessId::ClaudeCode,
        "atomic",
    );
    let fixture_a = TempVault::new("native-memory-atomic-a");
    let keys_a = MemoryKeyStore::default();
    let mut vault_a = Vault::open(fixture_a.path(), CREDENTIAL, &keys_a).unwrap();
    let initial = {
        let mut service = OfflineWorkspace::new(&mut vault_a, ID_7.parse().unwrap());
        service
            .reconcile_native_memory(ready(source.clone(), "Native fact\n"))
            .unwrap()
            .unwrap()
    };

    assert_eq!(initial.state, CandidateState::Pending);
    assert_eq!(initial.source_harness, HarnessId::ClaudeCode);
    assert_eq!(
        initial.proposed_memory.scope,
        ScopeRef::Project { project_id }
    );
    assert_eq!(initial.proposed_memory.origin, MemoryOrigin::NativeImport);
    assert_eq!(initial.proposed_memory.body_markdown, "Native fact\n");
    assert_eq!(
        initial.proposed_memory.tags,
        vec!["native-import", "claude-code"]
    );
    assert_eq!(initial.evidence_summary, "initial native-memory preview");
    assert_eq!(
        initial.id.to_string(),
        initial.proposed_memory.id.to_string()
    );
    assert_eq!(
        initial.id.to_string(),
        initial.proposed_memory.revision.to_string()
    );
    let imported_digest = extract_managed_markdown(b"Native fact\n")
        .unwrap()
        .unmanaged_digest;
    let stored = vault_a.native_memory_ledger(&source.id).unwrap().unwrap();
    assert_eq!(stored.last_imported_digest, Some(imported_digest));
    assert!(stored.initial_preview_complete);

    {
        let mut service = OfflineWorkspace::new(&mut vault_a, ID_7.parse().unwrap());
        assert_eq!(
            service
                .reconcile_native_memory(ready(source.clone(), "Native fact\n"))
                .unwrap(),
            None
        );
        assert_eq!(service.candidates(Some(project_id)).unwrap().len(), 1);
    }

    let fixture_b = TempVault::new("native-memory-atomic-b");
    let keys_b = MemoryKeyStore::default();
    let mut vault_b = Vault::open(fixture_b.path(), CREDENTIAL, &keys_b).unwrap();
    let deterministic = OfflineWorkspace::new(&mut vault_b, ID_7.parse().unwrap())
        .reconcile_native_memory(ready(source.clone(), "Native fact\n"))
        .unwrap()
        .unwrap();
    assert_eq!(deterministic.id, initial.id);

    let mut service = OfflineWorkspace::new(&mut vault_a, ID_7.parse().unwrap());
    let live = service
        .reconcile_native_memory(ready(source.clone(), "Native fact changed\n"))
        .unwrap()
        .unwrap();
    assert_ne!(live.id, initial.id);
    assert_eq!(live.evidence_summary, "native-memory edit");
    assert_eq!(service.candidates(Some(project_id)).unwrap().len(), 2);
}

#[test]
fn candidate_conflict_rolls_back_the_ledger_advance() {
    let source = source(ScopeRef::Global, HarnessId::Codex, "rollback");
    let path = TempVault::new("native-memory-candidate-conflict");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let first = OfflineWorkspace::new(&mut vault, ID_7.parse().unwrap())
        .reconcile_native_memory(ready(source.clone(), "Original native body"))
        .unwrap()
        .unwrap();
    let before = vault.native_memory_ledger(&source.id).unwrap().unwrap();
    let mut altered = first;
    altered.proposed_memory.body_markdown = "Altered bytes under the same identity".to_owned();
    let mut attempted = before.clone();
    attempted.last_observed_digest = Some(Sha256Digest([77; 32]));

    assert!(matches!(
        vault.put_native_memory_candidate(&attempted, Some(&altered)),
        Err(VaultError::OperationConflict)
    ));
    assert_eq!(
        vault.native_memory_ledger(&source.id).unwrap(),
        Some(before)
    );
}

#[test]
fn invalid_ready_source_is_rejected_without_persisting_state() {
    let mut source = source(ScopeRef::Global, HarnessId::Hermes, "invalid-ready");
    let original_id = source.id;
    source.id = NativeMemorySourceId(Sha256Digest([88; 32]));
    let path = TempVault::new("native-memory-invalid-ready");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let error = OfflineWorkspace::new(&mut vault, ID_7.parse().unwrap())
        .reconcile_native_memory(ready(source, "body"))
        .unwrap_err();

    assert_eq!(error.code, ErrorCode::InvalidRequest);
    assert_eq!(vault.native_memory_ledger(&original_id).unwrap(), None);
}
