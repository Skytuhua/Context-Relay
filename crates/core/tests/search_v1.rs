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
fn real_pinned_model_smoke_test_is_opt_in() {
    let Some(directory) = std::env::var_os("CONTEXT_RELAY_MODEL_DIR") else {
        return;
    };
    let mut model = PinnedModelEmbedder::load(std::path::Path::new(&directory)).unwrap();
    let embedding = model
        .embed(EmbeddingPurpose::Query, "context relay memory")
        .unwrap();
    assert_eq!(embedding.as_slice().len(), 384);
}

#[test]
#[ignore = "release-mode 10k-memory performance gate"]
fn search_10k_p95_is_below_150ms_with_warm_injected_query_embedding() {
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
    let scope = AllowedSearchScope::resolve(None, &HarnessAccessPolicy::Default, None).unwrap();
    let query_embedding = basis(17);
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
        "10k search P95: {:.3} ms (warm DB, injected normalized query embedding)",
        p95.as_secs_f64() * 1000.0
    );
    assert!(p95.as_millis() < 150, "P95 was {p95:?}");
}
