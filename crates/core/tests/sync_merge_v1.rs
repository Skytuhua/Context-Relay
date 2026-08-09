mod support;

use std::{collections::BTreeMap, str::FromStr};

use context_relay_core::{
    crypto::{CertificateIssuerV1, ContentKey, DeviceCertificateV1, DeviceKeys},
    search::{AllowedSearchScope, Embedding384},
    sync::{
        AdmissionDecision, AdmittedOperation, CausalOrder, MergeDecision, OperationBuilder,
        OperationChainHead, RepresentativeEmbeddingResolver, SyncError, SyncIdentity,
        TrustedDevice, TrustedSyncMaterial, admit_operation, compare_operations, decide_merge,
        missing_range,
    },
    vault::{StoredDeviceHead, StoredRecordHead, Vault},
};
use context_relay_protocol::{
    AccountId, DeviceId, DeviceSequence, Ed25519SignatureBytes, HarnessAccessPolicy,
    HybridLogicalClock, OperationId, PairingRequestNonce, RecordKind, RecordMutationV1, ScopeRef,
    SecretRef, SecretRefId, Sha256Digest, SyncOperationV1, WorkspaceId,
};

use support::{ID_1, ID_2, ID_3, ID_4, ID_5, ID_6, ID_7, ID_8, ID_9, MemoryKeyStore, TempVault};

const CREDENTIAL: &str = "sync-merge-v1";
const CONTROL_EPOCH: u32 = 5;
const KEY_EPOCH: u32 = 11;
const CONTENT_KEY: [u8; 32] = [55; 32];

struct DeviceFixture {
    keys: DeviceKeys,
    certificate: DeviceCertificateV1,
}

struct Trust {
    devices: BTreeMap<DeviceId, DeviceCertificateV1>,
    key: ContentKey,
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

struct RejectEmbeddings;

impl RepresentativeEmbeddingResolver for RejectEmbeddings {
    fn resolve_representative_embedding(
        &self,
        _operation_id: OperationId,
        _mutation: &RecordMutationV1,
    ) -> Result<Option<Embedding384>, SyncError> {
        Err(SyncError::InvalidMutation)
    }
}

struct FixtureEmbeddings;

impl RepresentativeEmbeddingResolver for FixtureEmbeddings {
    fn resolve_representative_embedding(
        &self,
        operation_id: OperationId,
        mutation: &RecordMutationV1,
    ) -> Result<Option<Embedding384>, SyncError> {
        let title = match mutation {
            RecordMutationV1::UpsertMemory(record) => record.title.as_str(),
            RecordMutationV1::UpsertInstruction(record) => record.title.as_str(),
            _ => return Ok(None),
        };
        let (expected_operation_id, basis) = match title {
            "incoming" | "canonical searchable" | "A1" => (ID_7, 0),
            "canonical instruction" => (ID_7, 0),
            "B1 retained representative" => (ID_8, 1),
            "concurrent searchable" => (ID_9, 1),
            "concurrent instruction" => (ID_9, 1),
            "A2 incoming" => (ID_9, 2),
            _ => return Ok(None),
        };
        if operation_id != id::<OperationId>(expected_operation_id) {
            return Err(SyncError::InvalidMutation);
        }
        Ok(Some(support::basis(basis)))
    }
}

impl Trust {
    fn new(devices: &[&DeviceFixture]) -> Self {
        Self {
            devices: devices
                .iter()
                .map(|device| (device.certificate.device_id, device.certificate.clone()))
                .collect(),
            key: ContentKey::from_bytes(CONTENT_KEY),
        }
    }

    fn apply() -> Self {
        Self::new(&[])
    }
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

#[test]
fn causal_truth_table_uses_only_device_sequences_and_frontiers() {
    let a = operation(ID_3, ID_7, 1, vec![], "a");
    let a_second = operation(ID_3, ID_8, 2, vec![], "a2");
    let b = operation(ID_4, ID_9, 1, vec![], "b");
    let a_after_b = operation(
        ID_3,
        ID_8,
        2,
        vec![DeviceSequence {
            device_id: id(ID_4),
            sequence: 1,
        }],
        "after-b",
    );

    assert_eq!(compare_operations(&a, &a), CausalOrder::Equal);
    assert_eq!(compare_operations(&a_second, &a), CausalOrder::After);
    assert_eq!(compare_operations(&a, &a_second), CausalOrder::Before);
    assert_eq!(compare_operations(&a_after_b, &b), CausalOrder::After);
    assert_eq!(compare_operations(&b, &a_after_b), CausalOrder::Before);
    assert_eq!(compare_operations(&a, &b), CausalOrder::Concurrent);

    let mut different_clock = a_after_b.clone();
    different_clock.created_hlc.physical_ms = 1;
    assert_eq!(compare_operations(&different_clock, &b), CausalOrder::After);

    let mut unsorted = a_after_b.clone();
    unsorted.causal_frontier.insert(
        0,
        DeviceSequence {
            device_id: id(ID_5),
            sequence: 1,
        },
    );
    assert_eq!(compare_operations(&unsorted, &b), CausalOrder::After);
    let mut duplicate = a_after_b.clone();
    duplicate.causal_frontier.push(DeviceSequence {
        device_id: id(ID_4),
        sequence: 2,
    });
    assert_eq!(compare_operations(&duplicate, &b), CausalOrder::After);
}

#[test]
fn gap_ranges_are_exact_and_overflow_fails_closed() {
    let incoming = operation(ID_3, ID_7, 4, vec![], "four");
    let known = StoredDeviceHead {
        sequence: 1,
        canonical_hash: Sha256Digest([1; 32]),
    };
    assert_eq!(missing_range(Some(known), &incoming), Ok(Some(2..=3)));
    let genesis = operation(ID_3, ID_7, 1, vec![], "one");
    assert_eq!(missing_range(None, &genesis), Ok(None));
    assert_eq!(
        missing_range(
            Some(StoredDeviceHead {
                sequence: u64::MAX,
                canonical_hash: Sha256Digest([1; 32]),
            }),
            &incoming,
        ),
        Err(SyncError::SequenceExhausted)
    );
}

#[test]
fn merge_decision_matrix_covers_older_newer_concurrent_delete_and_resolution() {
    let device_a = device(ID_3, 31);
    let device_b = device(ID_4, 32);
    let device_c = device(ID_5, 33);
    let trust = Trust::new(&[&device_a, &device_b, &device_c]);
    let path = TempVault::new("merge-decision-admission");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();

    let first_built = build(&device_a, ID_7, &secret("first"), vec![], None);
    let first = admit(&vault, &first_built, &trust);
    vault
        .apply_admitted_operation(
            &first,
            &trust,
            "memory",
            "2026-08-06T00:00:01Z",
            &NoEmbeddings,
        )
        .unwrap();
    let newer_built = build(
        &device_a,
        ID_8,
        &RecordMutationV1::Tombstone {
            record_id: id(ID_6),
            record_kind: RecordKind::SecretRef,
        },
        vec![],
        Some(OperationChainHead {
            sequence: 1,
            canonical_hash: first_built.canonical_hash,
        }),
    );
    let newer = admit(&vault, &newer_built, &trust);
    vault
        .apply_admitted_operation(
            &newer,
            &trust,
            "memory",
            "2026-08-06T00:00:02Z",
            &NoEmbeddings,
        )
        .unwrap();
    let concurrent_built = build(&device_b, ID_9, &secret("concurrent"), vec![], None);
    let concurrent = admit(&vault, &concurrent_built, &trust);
    vault
        .apply_admitted_operation(
            &concurrent,
            &trust,
            "memory",
            "2026-08-06T00:00:03Z",
            &NoEmbeddings,
        )
        .unwrap();
    let resolving_built = build(
        &device_c,
        ID_6,
        &secret("resolved"),
        vec![
            DeviceSequence {
                device_id: id(ID_3),
                sequence: 2,
            },
            DeviceSequence {
                device_id: id(ID_4),
                sequence: 1,
            },
        ],
        None,
    );
    let resolving = admit(&vault, &resolving_built, &trust);

    assert!(matches!(
        decide_merge(&first, &[]).unwrap(),
        MergeDecision::ReplaceHeads { remove } if remove.is_empty()
    ));
    assert_eq!(
        decide_merge(&first, &[head(&newer)]).unwrap(),
        MergeDecision::NoLiveChange
    );
    assert!(matches!(
        decide_merge(&newer, &[head(&first)]).unwrap(),
        MergeDecision::ReplaceHeads { remove }
            if remove == vec![first.operation().operation_id]
    ));
    assert!(matches!(
        decide_merge(&concurrent, &[head(&newer)]).unwrap(),
        MergeDecision::AddConflictHead { remove } if remove.is_empty()
    ));
    assert!(matches!(
        decide_merge(&resolving, &[head(&newer), head(&concurrent)]).unwrap(),
        MergeDecision::ResolveConflict { remove }
            if remove == vec![newer.operation().operation_id, concurrent.operation().operation_id]
    ));
}

#[test]
fn concurrent_arrival_orders_converge_on_heads_conflict_and_canonical_representative() {
    let device_a = device(ID_3, 34);
    let device_b = device(ID_4, 35);
    let trust = Trust::new(&[&device_a, &device_b]);
    let admission_path = TempVault::new("merge-order-admission");
    let admission_keys = MemoryKeyStore::default();
    let admission_vault = Vault::open(admission_path.path(), CREDENTIAL, &admission_keys).unwrap();
    let low_built = build(&device_a, ID_7, &secret("canonical-low"), vec![], None);
    let high_built = build(&device_b, ID_9, &secret("canonical-high"), vec![], None);
    let low = admit(&admission_vault, &low_built, &trust);
    let high = admit(&admission_vault, &high_built, &trust);

    let left = apply_order("merge-order-left", [&high, &low]);
    let right = apply_order("merge-order-right", [&low, &high]);

    assert_eq!(left.0, right.0);
    assert_eq!(left.0, "canonical-low");
    assert_eq!(left.1, right.1);
    assert_eq!(
        left.1,
        vec![id::<OperationId>(ID_7), id::<OperationId>(ID_9)]
    );
    assert_eq!(left.2, right.2);
    assert_eq!(left.3, right.3);
}

#[test]
fn concurrent_searchable_arrival_orders_install_the_representative_embedding() {
    let device_a = device(ID_3, 43);
    let device_b = device(ID_4, 44);
    let trust = Trust::new(&[&device_a, &device_b]);
    let admission_path = TempVault::new("merge-search-order-admission");
    let admission_keys = MemoryKeyStore::default();
    let admission_vault = Vault::open(admission_path.path(), CREDENTIAL, &admission_keys).unwrap();
    let low_built = build(
        &device_a,
        ID_7,
        &memory_mutation("canonical searchable", ID_8),
        vec![],
        None,
    );
    let high_built = build(
        &device_b,
        ID_9,
        &memory_mutation("concurrent searchable", ID_9),
        vec![],
        None,
    );
    let low = admit(&admission_vault, &low_built, &trust);
    let high = admit(&admission_vault, &high_built, &trust);

    let left = apply_memory_order("merge-search-order-left", [&high, &low]);
    let right = apply_memory_order("merge-search-order-right", [&low, &high]);

    assert_eq!(left, right);
    assert_eq!(left.0, "canonical searchable");
    assert_eq!(
        left.1,
        vec![id::<OperationId>(ID_7), id::<OperationId>(ID_9)]
    );
    assert_eq!(
        left.2,
        Some((id::<OperationId>(ID_7), id::<OperationId>(ID_9)))
    );
    assert_eq!(left.3.first().map(String::as_str), Some(ID_6));
}

#[test]
fn concurrent_instruction_arrival_orders_install_the_representative_embedding() {
    let device_a = device(ID_3, 45);
    let device_b = device(ID_4, 46);
    let trust = Trust::new(&[&device_a, &device_b]);
    let admission_path = TempVault::new("merge-instruction-order-admission");
    let admission_keys = MemoryKeyStore::default();
    let admission_vault = Vault::open(admission_path.path(), CREDENTIAL, &admission_keys).unwrap();
    let low_built = build(
        &device_a,
        ID_7,
        &instruction_mutation("canonical instruction"),
        vec![],
        None,
    );
    let high_built = build(
        &device_b,
        ID_9,
        &instruction_mutation("concurrent instruction"),
        vec![],
        None,
    );
    let low = admit(&admission_vault, &low_built, &trust);
    let high = admit(&admission_vault, &high_built, &trust);

    let left = apply_instruction_order("merge-instruction-order-left", [&high, &low]);
    let right = apply_instruction_order("merge-instruction-order-right", [&low, &high]);

    assert_eq!(left, right);
    assert_eq!(left.0, "canonical instruction");
    assert_eq!(
        left.1,
        vec![id::<OperationId>(ID_7), id::<OperationId>(ID_9)]
    );
    assert_eq!(
        left.2,
        Some((id::<OperationId>(ID_7), id::<OperationId>(ID_9)))
    );
    assert_eq!(left.3.first().map(String::as_str), Some(ID_6));
}

#[test]
fn concurrent_update_delete_uses_the_same_operation_id_representative_rule() {
    let device_a = device(ID_3, 36);
    let device_b = device(ID_4, 37);
    let trust = Trust::new(&[&device_a, &device_b]);
    let admission_path = TempVault::new("merge-update-delete-admission");
    let admission_keys = MemoryKeyStore::default();
    let mut admission_vault =
        Vault::open(admission_path.path(), CREDENTIAL, &admission_keys).unwrap();
    let update_built = build(&device_a, ID_9, &secret("update"), vec![], None);
    let update = admit(&admission_vault, &update_built, &trust);
    admission_vault
        .apply_admitted_operation(
            &update,
            &trust,
            "memory",
            "2026-08-06T00:00:01Z",
            &NoEmbeddings,
        )
        .unwrap();
    let delete_built = build(
        &device_b,
        ID_7,
        &RecordMutationV1::Tombstone {
            record_id: id(ID_6),
            record_kind: RecordKind::SecretRef,
        },
        vec![],
        None,
    );
    let delete = admit(&admission_vault, &delete_built, &trust);

    let path = TempVault::new("merge-update-delete");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault
        .apply_admitted_operation(
            &update,
            &trust,
            "memory",
            "2026-08-06T00:00:01Z",
            &NoEmbeddings,
        )
        .unwrap();
    vault
        .apply_admitted_operation(
            &delete,
            &trust,
            "memory",
            "2026-08-06T00:00:02Z",
            &NoEmbeddings,
        )
        .unwrap();
    assert!(vault.secret_ref(&id(ID_6)).unwrap().is_none());
    assert!(
        vault
            .conflict(&update.operation().record_id)
            .unwrap()
            .is_some()
    );
}

#[test]
fn transaction_failure_rolls_back_materialization_operations_heads_conflict_and_cursor() {
    let device = device(ID_3, 38);
    let trust = Trust::new(&[&device]);
    let admission_path = TempVault::new("merge-rollback-admission");
    let admission_keys = MemoryKeyStore::default();
    let admission_vault = Vault::open(admission_path.path(), CREDENTIAL, &admission_keys).unwrap();
    let mut memory = support::memory(
        ID_6,
        context_relay_protocol::ScopeRef::Global,
        "incoming",
        "body",
    );
    memory.revision = id(ID_8);
    let built = build(
        &device,
        ID_7,
        &RecordMutationV1::UpsertMemory(memory),
        vec![],
        None,
    );
    let admitted = admit(&admission_vault, &built, &trust);

    let path = TempVault::new("merge-rollback");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    install_search_sentinel(&mut vault);
    assert!(
        vault
            .apply_admitted_operation(
                &admitted,
                &trust,
                "memory",
                "2026-08-06T01:00:00Z",
                &NoEmbeddings,
            )
            .is_err()
    );
    assert_eq!(semantic_ids(&vault, &support::basis(0)), vec![ID_5]);
    assert!(
        vault
            .apply_admitted_operation(
                &admitted,
                &trust,
                "memory",
                "2026-08-06T01:00:00Z",
                &RejectEmbeddings,
            )
            .is_err()
    );
    assert_eq!(semantic_ids(&vault, &support::basis(0)), vec![ID_5]);
    assert!(vault.memory(&id(ID_6)).unwrap().is_none());
    assert!(
        vault
            .record_heads(id(ID_2), admitted.operation().record_id)
            .unwrap()
            .is_empty()
    );
    assert!(vault.device_head(id(ID_2), id(ID_3)).unwrap().is_none());
    assert!(vault.sync_cursor(id(ID_2), "memory").unwrap().is_none());

    vault
        .apply_admitted_operation(
            &admitted,
            &trust,
            "memory",
            "2026-08-06T01:00:00Z",
            &FixtureEmbeddings,
        )
        .unwrap();
    assert!(vault.memory(&id(ID_6)).unwrap().is_some());
    assert_eq!(
        vault
            .record_heads(id(ID_2), admitted.operation().record_id)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        vault
            .device_head(id(ID_2), id(ID_3))
            .unwrap()
            .unwrap()
            .sequence,
        1
    );
    assert_eq!(
        vault
            .sync_cursor(id(ID_2), "memory")
            .unwrap()
            .unwrap()
            .operation_id,
        id(ID_7)
    );
}

#[test]
fn exact_replay_advances_only_the_monotonic_cursor() {
    let device = device(ID_3, 39);
    let trust = Trust::new(&[&device]);
    let admission_path = TempVault::new("merge-replay-admission");
    let admission_keys = MemoryKeyStore::default();
    let admission_vault = Vault::open(admission_path.path(), CREDENTIAL, &admission_keys).unwrap();
    let built = build(&device, ID_7, &secret("stable"), vec![], None);
    let admitted = admit(&admission_vault, &built, &trust);
    let path = TempVault::new("merge-replay-cursor");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault
        .apply_admitted_operation(
            &admitted,
            &trust,
            "memory",
            "2026-08-06T01:00:00Z",
            &NoEmbeddings,
        )
        .unwrap();

    vault
        .advance_replay_cursor(
            admitted.operation().workspace_id,
            "memory",
            "2026-08-06T02:00:00Z",
            admitted.operation().operation_id,
        )
        .unwrap();

    assert_eq!(vault.secret_ref(&id(ID_6)).unwrap().unwrap().name, "stable");
    assert_eq!(
        vault
            .record_heads(id(ID_2), admitted.operation().record_id)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        vault
            .sync_cursor(id(ID_2), "memory")
            .unwrap()
            .unwrap()
            .received_at,
        "2026-08-06T02:00:00Z"
    );
}

#[test]
fn opaque_admitted_capability_materializes_only_authenticated_plaintext() {
    let device = device(ID_3, 40);
    let trust = Trust::new(&[&device]);
    let admission_path = TempVault::new("merge-capability-admission");
    let admission_keys = MemoryKeyStore::default();
    let admission_vault = Vault::open(admission_path.path(), CREDENTIAL, &admission_keys).unwrap();
    let built = build(&device, ID_7, &secret("signed"), vec![], None);
    let admitted = admit(&admission_vault, &built, &trust);
    assert_eq!(secret_name(admitted.mutation()), "signed");

    let path = TempVault::new("merge-capability");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault
        .apply_admitted_operation(
            &admitted,
            &trust,
            "memory",
            "2026-08-06T03:00:00Z",
            &NoEmbeddings,
        )
        .unwrap();
    assert_eq!(vault.secret_ref(&id(ID_6)).unwrap().unwrap().name, "signed");
}

#[test]
fn partial_dominance_keeps_only_maximal_heads_and_rehydrates_existing_representative() {
    let device_a = device(ID_3, 41);
    let device_b = device(ID_4, 42);
    let trust = Trust::new(&[&device_a, &device_b]);
    let admission_path = TempVault::new("partial-dominance-admission");
    let admission_keys = MemoryKeyStore::default();
    let mut admission_vault =
        Vault::open(admission_path.path(), CREDENTIAL, &admission_keys).unwrap();

    let a1_built = build(&device_a, ID_7, &memory_mutation("A1", ID_7), vec![], None);
    let a1 = admit(&admission_vault, &a1_built, &trust);
    admission_vault
        .apply_admitted_operation(
            &a1,
            &trust,
            "memory",
            "2026-08-06T04:00:00Z",
            &FixtureEmbeddings,
        )
        .unwrap();
    let b1_built = build(
        &device_b,
        ID_8,
        &memory_mutation("B1 retained representative", ID_8),
        vec![],
        None,
    );
    let b1 = admit(&admission_vault, &b1_built, &trust);
    admission_vault
        .apply_admitted_operation(
            &b1,
            &trust,
            "memory",
            "2026-08-06T04:00:01Z",
            &FixtureEmbeddings,
        )
        .unwrap();
    let a2_built = build(
        &device_a,
        ID_9,
        &memory_mutation("A2 incoming", ID_9),
        vec![],
        Some(OperationChainHead {
            sequence: 1,
            canonical_hash: a1_built.canonical_hash,
        }),
    );
    let a2 = admit(&admission_vault, &a2_built, &trust);

    for (name, prefix) in [
        ("partial-dominance-a-first", [&a1, &b1]),
        ("partial-dominance-b-first", [&b1, &a1]),
    ] {
        let path = TempVault::new(name);
        let keys = MemoryKeyStore::default();
        let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
        install_search_sentinel(&mut vault);
        for operation in prefix.into_iter().chain(std::iter::once(&a2)) {
            vault
                .apply_admitted_operation(
                    operation,
                    &trust,
                    "memory",
                    "2026-08-06T04:00:02Z",
                    &FixtureEmbeddings,
                )
                .unwrap();
        }
        assert_eq!(
            vault.memory(&id(ID_6)).unwrap().unwrap().title,
            "B1 retained representative"
        );
        assert_eq!(
            vault
                .record_heads(id(ID_2), id(ID_6))
                .unwrap()
                .into_iter()
                .map(|head| head.operation_id)
                .collect::<Vec<_>>(),
            vec![id::<OperationId>(ID_8), id::<OperationId>(ID_9)]
        );
        let conflict = vault.conflict(&id(ID_6)).unwrap().unwrap();
        assert_eq!(conflict.0.operation_id, id::<OperationId>(ID_8));
        assert_eq!(conflict.1.operation_id, id::<OperationId>(ID_9));
        assert_eq!(semantic_ids(&vault, &support::basis(1))[0], ID_6);
    }
}

fn apply_memory_order(
    name: &str,
    operations: [&AdmittedOperation; 2],
) -> (
    String,
    Vec<OperationId>,
    Option<(OperationId, OperationId)>,
    Vec<String>,
) {
    let path = TempVault::new(name);
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let trust = Trust::apply();
    install_search_sentinel(&mut vault);
    for admitted in operations {
        vault
            .apply_admitted_operation(
                admitted,
                &trust,
                "memory",
                "2026-08-06T05:00:00Z",
                &FixtureEmbeddings,
            )
            .unwrap();
    }
    let title = vault.memory(&id(ID_6)).unwrap().unwrap().title;
    let heads = vault
        .record_heads(id(ID_2), id(ID_6))
        .unwrap()
        .into_iter()
        .map(|head| head.operation_id)
        .collect();
    let conflict = vault
        .conflict(&id(ID_6))
        .unwrap()
        .map(|(left, right)| (left.operation_id, right.operation_id));
    let semantic = semantic_ids(&vault, &support::basis(0));
    (title, heads, conflict, semantic)
}

fn apply_instruction_order(
    name: &str,
    operations: [&AdmittedOperation; 2],
) -> (
    String,
    Vec<OperationId>,
    Option<(OperationId, OperationId)>,
    Vec<String>,
) {
    let path = TempVault::new(name);
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let trust = Trust::apply();
    install_search_sentinel(&mut vault);
    for admitted in operations {
        vault
            .apply_admitted_operation(
                admitted,
                &trust,
                "memory",
                "2026-08-06T05:30:00Z",
                &FixtureEmbeddings,
            )
            .unwrap();
    }
    let title = vault.instruction(&id(ID_6)).unwrap().unwrap().title;
    let heads = vault
        .record_heads(id(ID_2), id(ID_6))
        .unwrap()
        .into_iter()
        .map(|head| head.operation_id)
        .collect();
    let conflict = vault
        .conflict(&id(ID_6))
        .unwrap()
        .map(|(left, right)| (left.operation_id, right.operation_id));
    let semantic = semantic_ids(&vault, &support::basis(0));
    (title, heads, conflict, semantic)
}

fn install_search_sentinel(vault: &mut Vault) {
    vault
        .put_local_memory(
            &support::memory(ID_5, ScopeRef::Global, "semantic sentinel", "sentinel"),
            &mixed_embedding(0, 3),
        )
        .unwrap();
}

fn semantic_ids(vault: &Vault, query: &Embedding384) -> Vec<String> {
    let scope = AllowedSearchScope::resolve(None, &HarnessAccessPolicy::Default, None).unwrap();
    vault
        .search("", &scope, query, 2)
        .unwrap()
        .into_iter()
        .map(|hit| hit.record_id().to_owned())
        .collect()
}

fn mixed_embedding(left: usize, right: usize) -> Embedding384 {
    let mut values = vec![0.0; 384];
    values[left] = 1.0;
    values[right] = 1.0;
    Embedding384::try_from(values).unwrap()
}

fn apply_order(
    name: &str,
    operations: [&AdmittedOperation; 2],
) -> (
    String,
    Vec<OperationId>,
    Option<(OperationId, OperationId)>,
    OperationId,
) {
    let path = TempVault::new(name);
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let trust = Trust::apply();
    for admitted in operations {
        vault
            .apply_admitted_operation(
                admitted,
                &trust,
                "memory",
                "2026-08-06T00:00:01Z",
                &NoEmbeddings,
            )
            .unwrap();
    }
    let live = vault.secret_ref(&id(ID_6)).unwrap().unwrap().name;
    let heads = vault
        .record_heads(id(ID_2), id(ID_6))
        .unwrap()
        .into_iter()
        .map(|head| head.operation_id)
        .collect();
    let conflict = vault
        .conflict(&id(ID_6))
        .unwrap()
        .map(|(left, right)| (left.operation_id, right.operation_id));
    let cursor = vault
        .sync_cursor(id(ID_2), "memory")
        .unwrap()
        .unwrap()
        .operation_id;
    (live, heads, conflict, cursor)
}

fn admit(
    vault: &Vault,
    built: &context_relay_core::sync::BuiltOperation,
    trust: &Trust,
) -> AdmittedOperation {
    match admit_operation(vault, &built.canonical_bytes, trust).unwrap() {
        AdmissionDecision::Admitted(admitted) => admitted,
        other => panic!("expected admitted operation, got {other:?}"),
    }
}

fn head(admitted: &AdmittedOperation) -> StoredRecordHead {
    StoredRecordHead {
        operation_id: admitted.operation().operation_id,
        record_kind: admitted.operation().record_kind,
        mutation_kind: admitted.operation().mutation_kind,
        canonical_hash: admitted.canonical_hash(),
        operation: admitted.operation().clone(),
    }
}

fn operation(
    device_id: &str,
    operation_id: &str,
    sequence: u64,
    frontier: Vec<DeviceSequence>,
    name: &str,
) -> SyncOperationV1 {
    let device = device(device_id, device_id.as_bytes()[device_id.len() - 1]);
    let previous = (sequence > 1).then_some(OperationChainHead {
        sequence: sequence - 1,
        canonical_hash: Sha256Digest([7; 32]),
    });
    build(&device, operation_id, &secret(name), frontier, previous).operation
}

fn build(
    device: &DeviceFixture,
    operation_id: &str,
    mutation: &RecordMutationV1,
    frontier: Vec<DeviceSequence>,
    previous: Option<OperationChainHead>,
) -> context_relay_core::sync::BuiltOperation {
    let key = ContentKey::from_bytes(CONTENT_KEY);
    OperationBuilder::new(SyncIdentity {
        account_id: id(ID_1),
        workspace_id: id(ID_2),
        device_id: device.certificate.device_id,
        control_epoch: CONTROL_EPOCH,
        key_epoch: KEY_EPOCH,
        device_keys: &device.keys,
        content_key: &key,
    })
    .build(
        id(operation_id),
        None,
        mutation,
        frontier,
        previous,
        vec![],
        HybridLogicalClock::new(9_000_000_000_000, 0, device.certificate.device_id),
    )
    .unwrap()
}

fn device(device_id: &str, seed: u8) -> DeviceFixture {
    let keys = DeviceKeys::generate().unwrap();
    DeviceFixture {
        certificate: DeviceCertificateV1 {
            issuer: CertificateIssuerV1::Device {
                device_id: id(ID_1),
                signing_public_key: keys.signing_public_key(),
            },
            account_id: id(ID_1),
            workspace_id: id(ID_2),
            control_epoch: CONTROL_EPOCH,
            request_nonce: PairingRequestNonce([seed; 32]),
            device_id: id(device_id),
            signing_public_key: keys.signing_public_key(),
            wrapping_public_key: keys.wrapping_public_key(),
            signature: Ed25519SignatureBytes([0; 64]),
        },
        keys,
    }
}

fn secret(name: &str) -> RecordMutationV1 {
    RecordMutationV1::UpsertSecretRef(SecretRef {
        id: id::<SecretRefId>(ID_6),
        name: name.to_owned(),
        provider: "local-keychain".to_owned(),
        required_on_device: true,
    })
}

fn memory_mutation(title: &str, revision: &str) -> RecordMutationV1 {
    let mut memory = support::memory(ID_6, ScopeRef::Global, title, title);
    memory.revision = id(revision);
    RecordMutationV1::UpsertMemory(memory)
}

fn instruction_mutation(title: &str) -> RecordMutationV1 {
    RecordMutationV1::UpsertInstruction(support::instruction(ID_6, ScopeRef::Global, title, title))
}

fn secret_name(mutation: &RecordMutationV1) -> &str {
    let RecordMutationV1::UpsertSecretRef(secret) = mutation else {
        panic!("expected secret mutation")
    };
    &secret.name
}

fn id<T: FromStr>(value: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    value.parse().unwrap()
}
