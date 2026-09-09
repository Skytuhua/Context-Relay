mod support;

use std::{fs, time::Instant};

use context_relay_core::{
    search::{
        AllowedSearchScope, Embedding384, EmbeddingPurpose, ModelError, PinnedModelEmbedder,
        SearchError, verify_model_manifest, verify_pinned_model,
    },
    vault::Vault,
};
use context_relay_protocol::{
    HarnessAccessPolicy, McpScopeSelector, MemoryRecord, ProjectId, RecordKind, ScopeRef,
    SyncOperationV1,
};

use support::{
    ID_1, ID_2, ID_3, ID_4, ID_5, ID_6, ID_7, ID_8, MemoryKeyStore, TempVault, basis, candidate,
    instruction, memory, operation,
};

const CREDENTIAL: &str = "task-6-search";

fn finish_semantic_index(vault: &mut Vault) -> usize {
    let mut indexed = 0;
    loop {
        let batch = vault
            .index_semantic_batch(32, std::time::Duration::from_millis(100))
            .unwrap();
        indexed += batch.indexed;
        if batch.remaining == 0 {
            return indexed;
        }
        assert!(batch.processed > 0, "index batch must make progress");
    }
}

fn open_keyed(path: &std::path::Path, key: &[u8; 32]) -> rusqlite::Connection {
    let connection = rusqlite::Connection::open(path).unwrap();
    // SAFETY: this is the first SQLite operation, and the connection and key
    // remain alive for the call. This key belongs only to the disposable fixture.
    let result =
        unsafe { rusqlite::ffi::sqlite3_key(connection.handle(), key.as_ptr().cast(), 32) };
    assert_eq!(result, rusqlite::ffi::SQLITE_OK);
    connection
}

fn downgrade_fixture_to_schema_26(path: &TempVault, keys: &MemoryKeyStore) {
    let raw = open_keyed(path.path(), &keys.key(CREDENTIAL));
    raw.execute_batch(
        "DROP TABLE IF EXISTS candidate_aliases; DROP TABLE account_lifecycle_intents; DROP TABLE pairing_request_reviews; DROP TABLE hosted_pairing_intents;
         DROP TABLE hosted_restore_intent;
         DROP TABLE hosted_enrollment_intent;
         DROP TRIGGER semantic_document_insert;
         DROP TRIGGER semantic_document_update;
         DROP TABLE semantic_embeddings;
         DROP TABLE semantic_index_queue;
         DROP TABLE semantic_index_model;
         ALTER TABLE search_documents DROP COLUMN input_digest;
         ALTER TABLE search_documents DROP COLUMN tags;
         DELETE FROM search_fts;
         INSERT INTO search_fts(record_id,title,body) SELECT record_id,title,body FROM search_documents;
         PRAGMA user_version=26;",
    ).unwrap();
}

#[test]
fn schema_26_upgrade_backfills_tags_without_changing_records_or_sync() {
    let path = TempVault::new("semantic-metadata-upgrade");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let mut record = memory(ID_1, ScopeRef::Global, "Vehicle", "Keep it serviced.");
    record.tags = vec!["automotive".into(), "maintenance".into()];
    vault
        .put_memory(
            &record,
            &operation(ID_3, ID_1, RecordKind::Memory),
            &basis(0),
        )
        .unwrap();
    let original_outbox = vault.outbox_operations().unwrap();
    drop(vault);
    downgrade_fixture_to_schema_26(&path, &keys);
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(vault.memory(&record.id).unwrap(), Some(record.clone()));
    assert_eq!(vault.outbox_operations().unwrap(), original_outbox);
    let hits =
        context_relay_core::service::OfflineWorkspace::new(&mut vault, ID_8.parse().unwrap())
            .search_memories(context_relay_protocol::SearchParams {
                query: "automotive".into(),
                project_id: None,
            })
            .unwrap();
    assert_eq!(hits.first().map(|hit| hit.id), Some(record.id));
    drop(vault);
    let raw = open_keyed(path.path(), &keys.key(CREDENTIAL));
    let metadata: (String, i64, i64) = raw.query_row(
        "SELECT tags,length(input_digest),(SELECT count(*) FROM semantic_embeddings) FROM search_documents WHERE record_id=?1",
        [ID_1], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
    ).unwrap();
    assert_eq!(metadata, ("automotive maintenance".into(), 32, 0));
}

fn hit_ids(
    vault: &Vault,
    query: &str,
    scope: &AllowedSearchScope,
    embedding: &Embedding384,
) -> Vec<String> {
    vault
        .search(query, scope, embedding, 100)
        .unwrap()
        .into_iter()
        .map(|hit| hit.record_id().to_owned())
        .collect()
}

#[test]
fn embeddings_require_finite_nonzero_384d_vectors_and_round_trip_as_1536_bytes() {
    assert!(matches!(
        Embedding384::try_from(vec![1.0; 383]),
        Err(SearchError::InvalidEmbedding)
    ));
    let mut nonfinite = vec![1.0; 384];
    nonfinite[1] = f32::NAN;
    assert!(matches!(
        Embedding384::try_from(nonfinite),
        Err(SearchError::InvalidEmbedding)
    ));
    assert!(matches!(
        Embedding384::try_from(vec![0.0; 384]),
        Err(SearchError::InvalidEmbedding)
    ));

    let embedding = Embedding384::try_from(vec![2.0; 384]).unwrap();
    let bytes = embedding.to_le_bytes();
    assert_eq!(bytes.len(), 384 * size_of::<f32>());
    assert_eq!(Embedding384::from_le_bytes(&bytes).unwrap(), embedding);
    let norm: f32 = embedding.as_slice().iter().map(|value| value * value).sum();
    assert!((norm - 1.0).abs() < 1e-5);
}

#[test]
fn lexical_and_semantic_search_apply_caller_relative_scope_before_ranking() {
    let path = TempVault::new("scope-search");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let project_a = ID_7.parse::<ProjectId>().unwrap();
    let project_b = ID_8.parse::<ProjectId>().unwrap();

    let global = memory(ID_1, ScopeRef::Global, "Global needle", "global");
    let project_a_memory = memory(
        ID_2,
        ScopeRef::Project {
            project_id: project_a,
        },
        "Project A needle",
        "alpha",
    );
    let project_b_memory = memory(
        ID_3,
        ScopeRef::Project {
            project_id: project_b,
        },
        "Project B needle",
        "beta",
    );
    let mut archived = memory(
        ID_4,
        ScopeRef::Project {
            project_id: project_a,
        },
        "Archived needle",
        "archived",
    );
    archived.archived = true;
    let global_instruction = instruction(
        ID_5,
        ScopeRef::Global,
        "Global instruction needle",
        "instruction",
    );

    vault
        .put_memory(
            &global,
            &operation(ID_4, ID_1, RecordKind::Memory),
            &basis(0),
        )
        .unwrap();
    vault
        .put_memory(
            &project_a_memory,
            &operation(ID_5, ID_2, RecordKind::Memory),
            &basis(1),
        )
        .unwrap();
    vault
        .put_memory(
            &project_b_memory,
            &operation(ID_6, ID_3, RecordKind::Memory),
            &basis(2),
        )
        .unwrap();
    vault
        .put_memory(
            &archived,
            &operation(ID_7, ID_4, RecordKind::Memory),
            &basis(2),
        )
        .unwrap();
    vault
        .put_instruction(
            &global_instruction,
            &operation(ID_8, ID_5, RecordKind::Instruction),
            &basis(0),
        )
        .unwrap();
    vault.put_candidate(&candidate()).unwrap();

    let all_allowed =
        AllowedSearchScope::resolve(None, &HarnessAccessPolicy::Default, Some(project_a)).unwrap();
    let ids = hit_ids(&vault, "needle", &all_allowed, &basis(2));
    assert!(ids.contains(&ID_1.to_owned()));
    assert!(ids.contains(&ID_2.to_owned()));
    assert!(ids.contains(&ID_5.to_owned()));
    assert!(!ids.contains(&ID_3.to_owned()));
    assert!(!ids.contains(&ID_4.to_owned()));

    let global_only = AllowedSearchScope::resolve(
        None,
        &HarnessAccessPolicy::GlobalOnly { read_only: true },
        Some(project_a),
    )
    .unwrap();
    assert_eq!(
        hit_ids(&vault, "needle", &global_only, &basis(2)),
        vec![ID_1.to_owned(), ID_5.to_owned()]
    );

    let active_only = AllowedSearchScope::resolve(
        None,
        &HarnessAccessPolicy::ActiveProjectOnly { read_only: true },
        Some(project_a),
    )
    .unwrap();
    assert_eq!(
        hit_ids(&vault, "needle", &active_only, &basis(2)),
        vec![ID_2.to_owned()]
    );

    let selected = AllowedSearchScope::resolve(
        None,
        &HarnessAccessPolicy::SelectedProject {
            project_id: project_b,
            read_only: true,
        },
        Some(project_a),
    )
    .unwrap();
    assert_eq!(
        hit_ids(&vault, "needle", &selected, &basis(2)),
        vec![ID_3.to_owned()]
    );

    assert!(matches!(
        AllowedSearchScope::resolve(
            Some(McpScopeSelector::ActiveProject),
            &HarnessAccessPolicy::GlobalOnly { read_only: true },
            Some(project_a)
        ),
        Err(SearchError::ScopeDenied)
    ));
    assert!(matches!(
        AllowedSearchScope::resolve(
            Some(McpScopeSelector::ActiveProject),
            &HarnessAccessPolicy::Default,
            None
        ),
        Err(SearchError::ActiveProjectRequired)
    ));
    assert!(matches!(
        AllowedSearchScope::resolve(None, &HarnessAccessPolicy::Disabled, Some(project_a)),
        Err(SearchError::ScopeDenied)
    ));
}

#[test]
fn committed_updates_replace_cached_scope_and_embedding_and_archive_removes_entry() {
    let path = TempVault::new("cache-update");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let project = ID_7.parse::<ProjectId>().unwrap();
    let original = memory(ID_1, ScopeRef::Global, "Original", "semantic only");
    vault
        .put_memory(
            &original,
            &operation(ID_4, ID_1, RecordKind::Memory),
            &basis(0),
        )
        .unwrap();

    let mut updated = original.clone();
    updated.scope = ScopeRef::Project {
        project_id: project,
    };
    vault
        .put_memory(
            &updated,
            &operation(ID_5, ID_1, RecordKind::Memory),
            &basis(1),
        )
        .unwrap();
    let competitor = memory(
        ID_2,
        ScopeRef::Project {
            project_id: project,
        },
        "Competitor",
        "semantic only",
    );
    vault
        .put_memory(
            &competitor,
            &operation(ID_6, ID_2, RecordKind::Memory),
            &basis(0),
        )
        .unwrap();

    let global = AllowedSearchScope::resolve(None, &HarnessAccessPolicy::Default, None).unwrap();
    assert!(vault.search("", &global, &basis(1), 10).unwrap().is_empty());
    let selected = AllowedSearchScope::resolve(
        None,
        &HarnessAccessPolicy::SelectedProject {
            project_id: project,
            read_only: true,
        },
        None,
    )
    .unwrap();
    assert_eq!(
        vault.search("", &selected, &basis(1), 1).unwrap()[0].record_id(),
        ID_1
    );

    let mut archived = updated;
    archived.archived = true;
    vault
        .put_memory(
            &archived,
            &operation(ID_8, ID_1, RecordKind::Memory),
            &basis(1),
        )
        .unwrap();
    assert_eq!(
        vault
            .search("", &selected, &basis(1), 10)
            .unwrap()
            .iter()
            .map(|hit| hit.record_id())
            .collect::<Vec<_>>(),
        vec![ID_2]
    );
}

#[test]
fn hybrid_search_uses_deterministic_rrf_ties_and_quotes_fts_special_characters() {
    let path = TempVault::new("rrf");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let lexical_first = memory(
        ID_1,
        ScopeRef::Global,
        "needle needle needle",
        "needle needle needle needle",
    );
    let semantic_first = memory(ID_2, ScopeRef::Global, "needle", "other");
    vault
        .put_memory(
            &lexical_first,
            &operation(ID_3, ID_1, RecordKind::Memory),
            &basis(0),
        )
        .unwrap();
    vault
        .put_memory(
            &semantic_first,
            &operation(ID_4, ID_2, RecordKind::Memory),
            &basis(1),
        )
        .unwrap();

    let scope = AllowedSearchScope::resolve(
        Some(McpScopeSelector::Global),
        &HarnessAccessPolicy::Default,
        None,
    )
    .unwrap();
    let hits = vault.search("needle", &scope, &basis(1), 2).unwrap();
    assert_eq!(hits[0].record_id(), ID_1);
    assert_eq!(hits[1].record_id(), ID_2);
    assert!((hits[0].score - hits[1].score).abs() < f64::EPSILON);
    assert_eq!(vault.embedding_storage_bytes(ID_1).unwrap(), 1536);

    let special = vault
        .search("needle\") OR *: (", &scope, &basis(1), 2)
        .unwrap();
    assert_eq!(
        special
            .iter()
            .map(|hit| hit.record_id())
            .collect::<Vec<_>>(),
        vault
            .search("needle\") OR *: (", &scope, &basis(1), 2)
            .unwrap()
            .iter()
            .map(|hit| hit.record_id())
            .collect::<Vec<_>>()
    );
}

#[test]
fn model_manifest_verifier_rejects_missing_and_hash_mismatched_artifacts() {
    let directory = TempVault::new("model-fixture");
    fs::create_dir(directory.path()).unwrap();
    let manifest = br#"{
      "schemaVersion": 1,
      "model": "test/model",
      "revision": "0123456789abcdef0123456789abcdef01234567",
      "dimensions": 384,
      "license": "MIT",
      "artifacts": [{
        "file": "tiny.bin",
        "bytes": 3,
        "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
      }]
    }"#;
    assert!(matches!(
        verify_model_manifest(directory.path(), manifest),
        Err(ModelError::MissingArtifact(_))
    ));
    fs::write(directory.path().join("tiny.bin"), b"abd").unwrap();
    assert!(matches!(
        verify_model_manifest(directory.path(), manifest),
        Err(ModelError::HashMismatch(_))
    ));
    fs::write(directory.path().join("tiny.bin"), b"abcd").unwrap();
    assert!(matches!(
        verify_model_manifest(directory.path(), manifest),
        Err(ModelError::SizeMismatch(_))
    ));
    fs::write(directory.path().join("tiny.bin"), b"abc").unwrap();
    verify_model_manifest(directory.path(), manifest).unwrap();

    let pinned_directory = TempVault::new("missing-pinned-model");
    fs::create_dir(pinned_directory.path()).unwrap();
    assert!(matches!(
        verify_pinned_model(pinned_directory.path()),
        Err(ModelError::MissingArtifact(_))
    ));
}

#[test]
#[ignore = "requires verified BGE assets and ONNX Runtime"]
fn real_pinned_model_smoke_test_is_opt_in() {
    let directory = std::env::var_os("CONTEXT_RELAY_MODEL_DIR")
        .expect("set CONTEXT_RELAY_MODEL_DIR to the verified pinned model directory");
    let mut model = PinnedModelEmbedder::load(std::path::Path::new(&directory)).unwrap();
    let embedding = model
        .embed(EmbeddingPurpose::Query, "context relay memory")
        .unwrap();
    assert_eq!(embedding.as_slice().len(), 384);
}

#[test]
#[ignore = "requires verified BGE assets and ONNX Runtime"]
fn real_semantic_workspace_search_finds_a_paraphrase() {
    use context_relay_core::service::OfflineWorkspace;
    use context_relay_protocol::SearchParams;

    let path = TempVault::new("semantic-workspace");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let car = memory(
        ID_1,
        ScopeRef::Global,
        "Vehicle",
        "Keep the car engine serviced and replace its oil regularly.",
    );
    let bread = memory(
        ID_2,
        ScopeRef::Global,
        "Kitchen",
        "Knead the dough and bake a fresh loaf of bread.",
    );
    for (record, operation_id) in [(&car, ID_3), (&bread, ID_4)] {
        vault
            .put_memory(
                record,
                &operation(operation_id, &record.id.to_string(), RecordKind::Memory),
                &basis(0),
            )
            .unwrap();
    }
    let directory = std::env::var_os("CONTEXT_RELAY_MODEL_DIR")
        .expect("set CONTEXT_RELAY_MODEL_DIR to the verified pinned model directory");
    vault.enable_semantic_search(
        PinnedModelEmbedder::load(std::path::Path::new(&directory)).unwrap(),
    );
    let search = |vault: &mut Vault, query: &str| {
        OfflineWorkspace::new(vault, ID_8.parse().unwrap())
            .search_memories(SearchParams {
                query: query.to_owned(),
                project_id: None,
            })
            .unwrap()
    };
    let outbox_before_index = vault.outbox_operations().unwrap();
    assert_eq!(finish_semantic_index(&mut vault), 2);
    assert_eq!(vault.outbox_operations().unwrap(), outbox_before_index);
    let hits = search(&mut vault, "automobile maintenance");
    assert_eq!(hits.first().map(|record| record.id), Some(car.id));

    // Model mismatches invalidate both persisted readiness and warm snapshots.
    let raw = open_keyed(path.path(), &keys.key(CREDENTIAL));
    raw.execute(
        "UPDATE semantic_embeddings SET model_fingerprint=zeroblob(32) WHERE record_id=?1",
        [ID_1],
    )
    .unwrap();
    drop(raw);
    let global_scope =
        AllowedSearchScope::resolve(None, &HarnessAccessPolicy::Default, None).unwrap();
    assert_eq!(
        vault
            .semantic_index_progress(&global_scope)
            .unwrap()
            .unwrap()
            .indexed_records,
        1
    );
    assert!(
        !search(&mut vault, "automobile maintenance")
            .iter()
            .any(|hit| hit.id == car.id)
    );
    assert_eq!(finish_semantic_index(&mut vault), 1);

    // Warm vectors must change when the same record ID receives different text.
    let mut changed = car.clone();
    changed.title = "Garden".to_owned();
    changed.body_markdown = "Plant tulips and water the flowers in spring.".to_owned();
    vault
        .put_memory(
            &changed,
            &operation(ID_5, ID_1, RecordKind::Memory),
            &basis(0),
        )
        .unwrap();
    assert!(
        !search(&mut vault, "flower cultivation")
            .iter()
            .any(|hit| hit.id == car.id),
        "changed text must not use a stale vector"
    );
    assert_eq!(finish_semantic_index(&mut vault), 1);
    assert_eq!(search(&mut vault, "flower cultivation")[0].id, car.id);
    assert_eq!(search(&mut vault, "making sourdough")[0].id, bread.id);

    // Tag-only edits are part of both keyword and semantic input.
    changed.tags = vec!["horticulture".into()];
    vault
        .put_memory(
            &changed,
            &operation(
                "018f22e3-79b0-7cc8-98c4-dc0c0c073992",
                ID_1,
                RecordKind::Memory,
            ),
            &basis(0),
        )
        .unwrap();
    assert_eq!(
        vault
            .semantic_index_progress(&global_scope)
            .unwrap()
            .unwrap()
            .indexed_records,
        1
    );
    assert_eq!(search(&mut vault, "horticulture")[0].id, car.id);
    assert_eq!(finish_semantic_index(&mut vault), 1);

    // Even an exact semantic match in another project is excluded.
    let hidden = memory(
        ID_6,
        ScopeRef::Project {
            project_id: ID_7.parse().unwrap(),
        },
        "automobile maintenance",
        "automobile maintenance",
    );
    vault
        .put_memory(
            &hidden,
            &operation(ID_7, ID_6, RecordKind::Memory),
            &basis(0),
        )
        .unwrap();
    assert!(
        !search(&mut vault, "automobile maintenance")
            .iter()
            .any(|record| record.id == hidden.id)
    );
    assert_eq!(finish_semantic_index(&mut vault), 1);
    let progress = vault
        .semantic_index_progress(&global_scope)
        .unwrap()
        .unwrap();
    assert_eq!(
        (progress.indexed_records, progress.total_records),
        (2, 2),
        "other project counts are excluded"
    );

    changed.archived = true;
    vault
        .put_memory(
            &changed,
            &operation(ID_8, ID_1, RecordKind::Memory),
            &basis(0),
        )
        .unwrap();
    assert!(
        !search(&mut vault, "flower cultivation")
            .iter()
            .any(|record| record.id == car.id)
    );

    drop(vault);
    let mut reopened = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    reopened.enable_semantic_search(
        PinnedModelEmbedder::load(std::path::Path::new(&directory)).unwrap(),
    );
    assert_eq!(
        finish_semantic_index(&mut reopened),
        0,
        "restart reuses stored vectors"
    );
    assert_eq!(search(&mut reopened, "making sourdough")[0].id, bread.id);
    assert!(
        !search(&mut reopened, "flower cultivation")
            .iter()
            .any(|record| record.id == car.id)
    );

    let mut pending = candidate();
    pending.proposed_memory = memory(
        ID_5,
        ScopeRef::Global,
        "making sourdough",
        "making sourdough",
    );
    reopened.put_candidate(&pending).unwrap();
    assert!(
        !search(&mut reopened, "making sourdough")
            .iter()
            .any(|record| record.id == pending.proposed_memory.id)
    );

    let rule_id = "018f22e2-79b0-7cc8-98c4-dc0c0c073990";
    let rule = instruction(
        rule_id,
        ScopeRef::Global,
        "Credentials",
        "Never disclose passwords or secret authentication tokens.",
    );
    reopened
        .put_instruction(
            &rule,
            &operation(
                "018f22e3-79b0-7cc8-98c4-dc0c0c073990",
                rule_id,
                RecordKind::Instruction,
            ),
            &basis(0),
        )
        .unwrap();
    let scope = AllowedSearchScope::resolve(None, &HarnessAccessPolicy::Default, None).unwrap();
    assert_eq!(finish_semantic_index(&mut reopened), 1);
    let records = OfflineWorkspace::new(&mut reopened, ID_8.parse().unwrap())
        .search_records("protect login information", &scope, 20)
        .unwrap();
    assert!(
        matches!(records.first(), Some(context_relay_protocol::ReadableRecord::Instruction(value)) if value.id == rule.id)
    );

    // A commit through a second connection must invalidate warmed scope membership.
    let mut other_connection = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let mut moved = bread.clone();
    moved.scope = ScopeRef::Project {
        project_id: ID_7.parse().unwrap(),
    };
    other_connection
        .put_memory(
            &moved,
            &operation(
                "018f22e3-79b0-7cc8-98c4-dc0c0c073991",
                ID_2,
                RecordKind::Memory,
            ),
            &basis(0),
        )
        .unwrap();
    drop(other_connection);
    assert!(
        !search(&mut reopened, "making sourdough")
            .iter()
            .any(|record| record.id == bread.id)
    );
}

#[test]
#[ignore = "release-mode 10k-memory performance gate"]
fn search_10k_p95_is_below_150ms_with_warm_injected_query_embedding() {
    benchmark_search(false);
}

#[test]
fn keyword_results_remain_available_before_the_packaged_model_loads() {
    use context_relay_core::service::OfflineWorkspace;
    use context_relay_protocol::SearchParams;
    let path = TempVault::new("keyword-model-fallback");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let mut record = memory(
        ID_1,
        ScopeRef::Global,
        "Vehicle",
        "Keep the car engine serviced.",
    );
    record.tags = vec!["uniquephonemicidentifier".into()];
    vault
        .put_memory(
            &record,
            &operation(ID_2, ID_1, RecordKind::Memory),
            &basis(0),
        )
        .unwrap();
    vault.prepare_semantic_search();
    let scope = AllowedSearchScope::resolve(None, &HarnessAccessPolicy::Default, None).unwrap();
    assert!(
        vault
            .search("unseenword", &scope, &basis(0), 20)
            .unwrap()
            .is_empty(),
        "preparing search must not return unrelated legacy-vector matches"
    );
    let matches = OfflineWorkspace::new(&mut vault, ID_8.parse().unwrap())
        .search_memories(SearchParams {
            query: "uniquephonemicidentifier".into(),
            project_id: None,
        })
        .unwrap();
    assert_eq!(
        matches.iter().map(|m| m.id).collect::<Vec<_>>(),
        [record.id]
    );
}

#[test]
#[cfg(feature = "test-support")]
#[ignore = "requires verified BGE assets and ONNX Runtime"]
fn real_query_failure_keeps_keywords_and_a_reloaded_session_recovers() {
    let path = TempVault::new("query-model-fallback");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let record = memory(
        ID_1,
        ScopeRef::Global,
        "Vehicle",
        "Keep the car engine serviced.",
    );
    vault
        .put_memory(
            &record,
            &operation(ID_2, ID_1, RecordKind::Memory),
            &basis(0),
        )
        .unwrap();
    let directory = std::path::PathBuf::from(std::env::var_os("CONTEXT_RELAY_MODEL_DIR").unwrap());
    let mut model = PinnedModelEmbedder::load(&directory).unwrap();
    model.fail_next_inference_for_test();
    vault.enable_semantic_search(model);
    let scope = AllowedSearchScope::resolve(None, &HarnessAccessPolicy::Default, None).unwrap();
    let hits = vault
        .search("engine", &scope, &basis(0), 20)
        .expect("keyword fallback after inference failure");
    assert_eq!(hits.len(), 1);
    assert!(
        vault
            .search("unseenword", &scope, &basis(0), 20)
            .unwrap()
            .is_empty()
    );
    assert!(vault.take_semantic_search_failure());
    assert!(!vault.semantic_search_enabled());
    assert!(!vault.take_semantic_search_failure());
    vault.enable_semantic_search(PinnedModelEmbedder::load(&directory).unwrap());
    finish_semantic_index(&mut vault);
    assert_eq!(
        vault
            .search("automobile maintenance", &scope, &basis(0), 20)
            .unwrap()
            .len(),
        1
    );
}

#[test]
#[ignore = "requires verified BGE assets and ONNX Runtime"]
fn real_cold_search_does_not_index_passages_on_the_request_path() {
    let path = TempVault::new("responsive-cold-search");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let mut batch = Vec::new();
    for index in 0..40_u64 {
        let id = format!("018f22e2-79b0-7cc8-98c4-{index:012x}");
        let op = format!("018f22e3-79b0-7cc8-98c4-{index:012x}");
        batch.push((
            memory(
                &id,
                ScopeRef::Global,
                "Vehicle",
                "Keep the car engine serviced and replace its oil regularly.",
            ),
            operation(&op, &id, RecordKind::Memory),
            basis(0),
        ));
    }
    vault.put_memories_batch(&batch).unwrap();
    let directory = std::env::var_os("CONTEXT_RELAY_MODEL_DIR").expect("verified BGE directory");
    vault.enable_semantic_search(
        PinnedModelEmbedder::load(std::path::Path::new(&directory)).unwrap(),
    );
    let scope = AllowedSearchScope::resolve(None, &HarnessAccessPolicy::Default, None).unwrap();
    let started = Instant::now();
    let hits = vault.search("Vehicle", &scope, &basis(0), 20).unwrap();
    assert!(
        !hits.is_empty(),
        "keyword results remain available while indexing"
    );
    assert!(
        started.elapsed() < std::time::Duration::from_millis(500),
        "cold search blocked for {:?}",
        started.elapsed()
    );
    let progress = vault.semantic_index_progress(&scope).unwrap().unwrap();
    assert_eq!((progress.indexed_records, progress.total_records), (0, 40));
    let batch = vault
        .index_semantic_batch(1, std::time::Duration::from_nanos(1))
        .unwrap();
    assert_eq!((batch.indexed, batch.remaining), (1, 39));
    let progress = vault.semantic_index_progress(&scope).unwrap().unwrap();
    assert_eq!((progress.indexed_records, progress.total_records), (1, 40));
}

#[test]
#[ignore = "release-mode 10k gate with verified BGE assets and ONNX Runtime"]
fn semantic_search_10k_p95_includes_query_inference() {
    benchmark_search(true);
}

#[test]
#[ignore = "requires verified BGE assets and ONNX Runtime"]
fn real_maximum_document_indexing_yields_after_one_inference() {
    let path = TempVault::new("semantic-maximum-document");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let body =
        "car engine oil maintenance ".repeat(context_relay_protocol::MAX_MARKDOWN_BYTES / 27);
    for (id, op) in [(ID_1, ID_3), (ID_2, ID_4)] {
        let record = memory(id, ScopeRef::Global, "Vehicle", &body);
        vault
            .put_memory(&record, &operation(op, id, RecordKind::Memory), &basis(0))
            .unwrap();
    }
    let directory = std::env::var_os("CONTEXT_RELAY_MODEL_DIR").expect("verified BGE directory");
    vault.enable_semantic_search(
        PinnedModelEmbedder::load(std::path::Path::new(&directory)).unwrap(),
    );
    let started = Instant::now();
    let batch = vault
        .index_semantic_batch(32, std::time::Duration::from_nanos(1))
        .unwrap();
    eprintln!(
        "maximum-document batch: {:?} for {} body bytes",
        started.elapsed(),
        body.len()
    );
    assert_eq!((batch.indexed, batch.processed, batch.remaining), (1, 1, 1));
    assert!(
        started.elapsed() < std::time::Duration::from_secs(2),
        "one inference must fit the interactive worker allowance"
    );
}

#[test]
#[ignore = "release-mode cache-capacity check with verified BGE assets and ONNX Runtime"]
fn semantic_cache_overflow_uses_persisted_vectors() {
    let path = TempVault::new("semantic-cache-overflow");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let mut records = Vec::new();
    let globals = 16_400_u64;
    for index in 0..=globals {
        let id = format!("018f22e2-79b0-7cc8-98c4-{index:012x}");
        let op = format!("018f22e3-79b0-7cc8-98c4-{index:012x}");
        let scope = if index == globals {
            ScopeRef::Project {
                project_id: ID_7.parse().unwrap(),
            }
        } else {
            ScopeRef::Global
        };
        records.push((
            memory(
                &id,
                scope,
                "Vehicle",
                "Keep the car engine serviced and replace its oil regularly.",
            ),
            operation(&op, &id, RecordKind::Memory),
            basis(0),
        ));
    }
    vault.put_memories_batch(&records).unwrap();
    let directory = std::env::var_os("CONTEXT_RELAY_MODEL_DIR").expect("verified BGE directory");
    vault.enable_semantic_search(
        PinnedModelEmbedder::load(std::path::Path::new(&directory)).unwrap(),
    );
    assert_eq!(
        vault
            .index_semantic_batch(1, std::time::Duration::from_secs(1))
            .unwrap()
            .indexed,
        1
    );
    // Every fixture has identical model input. Reuse the first actual BGE vector
    // to exercise cache capacity without spending minutes repeating inference.
    let raw = open_keyed(path.path(), &keys.key(CREDENTIAL));
    assert_eq!(
        raw.execute(
            "INSERT INTO semantic_embeddings(record_id,model_fingerprint,input_digest,vector)
         SELECT d.record_id,e.model_fingerprint,d.input_digest,e.vector
         FROM search_documents AS d JOIN semantic_embeddings AS e
           ON e.record_id=?1 AND e.input_digest=d.input_digest
         WHERE d.record_id != e.record_id",
            [records[0].0.id.to_string()],
        )
        .unwrap(),
        globals as usize
    );
    drop(raw);
    assert_eq!(
        finish_semantic_index(&mut vault),
        0,
        "matching persisted vectors need no inference"
    );
    let global = AllowedSearchScope::resolve(None, &HarnessAccessPolicy::Default, None).unwrap();
    let project = AllowedSearchScope::resolve(
        Some(McpScopeSelector::ActiveProject),
        &HarnessAccessPolicy::Default,
        Some(ID_7.parse().unwrap()),
    )
    .unwrap();
    let project_record = records.last().unwrap().0.id.to_string();
    for _ in 0..2 {
        let started = Instant::now();
        let hits = vault
            .search("automobile maintenance", &global, &basis(0), 20)
            .unwrap();
        assert_eq!(hits.len(), 20);
        assert!(hits.iter().all(|hit| hit.record_id() != project_record));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "cache overflow must not re-embed the corpus"
        );
        let hits = vault
            .search("automobile maintenance", &project, &basis(0), 20)
            .unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].record_id(), project_record);
    }
    let progress = vault.semantic_index_progress(&global).unwrap().unwrap();
    assert_eq!(
        (progress.indexed_records, progress.total_records),
        (globals, globals)
    );
    drop(vault);
    let mut reopened = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    reopened.enable_semantic_search(
        PinnedModelEmbedder::load(std::path::Path::new(&directory)).unwrap(),
    );
    assert_eq!(finish_semantic_index(&mut reopened), 0);
    assert_eq!(
        reopened
            .search("automobile maintenance", &project, &basis(0), 20)
            .unwrap()[0]
            .record_id(),
        project_record
    );
}

fn benchmark_search(real_model: bool) {
    let path = TempVault::new("benchmark");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let mut batch: Vec<(MemoryRecord, SyncOperationV1, Embedding384)> = Vec::with_capacity(10_000);
    for index in 0..10_000_u64 {
        let record_id = format!("018f22e2-79b0-7cc8-98c4-{index:012x}");
        let operation_id = format!("018f22e3-79b0-7cc8-98c4-{index:012x}");
        batch.push((
            memory(
                &record_id,
                ScopeRef::Global,
                &format!("Memory {index} needle"),
                "benchmark corpus",
            ),
            operation(&operation_id, &record_id, RecordKind::Memory),
            basis(index as usize % 384),
        ));
    }
    vault.put_memories_batch(&batch).unwrap();
    if real_model {
        drop(vault);
        downgrade_fixture_to_schema_26(&path, &keys);
        let upgrade_started = Instant::now();
        vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
        eprintln!(
            "10k vault metadata upgrade and open: {:?}",
            upgrade_started.elapsed()
        );
        assert!(upgrade_started.elapsed() < std::time::Duration::from_secs(5));
        let directory = std::env::var_os("CONTEXT_RELAY_MODEL_DIR")
            .expect("set CONTEXT_RELAY_MODEL_DIR to the verified pinned model directory");
        vault.enable_semantic_search(
            PinnedModelEmbedder::load(std::path::Path::new(&directory)).unwrap(),
        );
        let scope = AllowedSearchScope::resolve(None, &HarnessAccessPolicy::Default, None).unwrap();
        let first_query = Instant::now();
        assert!(
            !vault
                .search("needle", &scope, &basis(0), 20)
                .unwrap()
                .is_empty()
        );
        eprintln!("10k query before indexing: {:?}", first_query.elapsed());
        assert!(first_query.elapsed() < std::time::Duration::from_millis(500));
        let index_started = Instant::now();
        assert_eq!(finish_semantic_index(&mut vault), 10_000);
        eprintln!(
            "10k resumable indexing: {:.3} seconds",
            index_started.elapsed().as_secs_f64()
        );
    }
    let scope = AllowedSearchScope::resolve(None, &HarnessAccessPolicy::Default, None).unwrap();
    let query_embedding = basis(17);
    let cold_started = Instant::now();
    vault
        .search("needle", &scope, &query_embedding, 20)
        .unwrap();
    eprintln!(
        "10k cold search: {:.3} seconds (real model: {real_model})",
        cold_started.elapsed().as_secs_f64()
    );
    for _ in 0..5 {
        vault
            .search("needle", &scope, &query_embedding, 20)
            .unwrap();
    }
    let mut samples = Vec::with_capacity(100);
    for _ in 0..100 {
        let started = Instant::now();
        vault
            .search("needle", &scope, &query_embedding, 20)
            .unwrap();
        samples.push(started.elapsed());
    }
    samples.sort_unstable();
    let p95 = samples[94];
    eprintln!(
        "10k search P95: {:.3} ms (warm DB, real model: {real_model})",
        p95.as_secs_f64() * 1000.0
    );
    assert!(p95.as_millis() < 150, "P95 was {p95:?}");
}
