mod support;

use std::str::FromStr;

use context_relay_protocol::{
    BoundedCiphertext, CandidateState, ComponentKind, ComponentRecord, Ed25519SignatureBytes,
    HarnessId, InstructionRecord, MemoryCandidate, MutationKind, ProjectIdentity, RecordKind,
    RecordMutationV1, ScopeRef, SecretRef, Sha256Digest, TaskRecord, decode_record_mutation_v1,
    encode_record_mutation_v1, encode_sync_operation_aad_v1,
};
use minicbor::Encoder;

#[test]
fn all_upsert_variants_and_tombstones_round_trip() {
    let memory = fixed_memory();
    let candidate = MemoryCandidate {
        id: id("018f22e2-79b0-7cc8-98c4-dc0c0c073990"),
        proposed_memory: memory.clone(),
        evidence_summary: "Observed in a focused test.".into(),
        source_harness: HarnessId::Codex,
        state: CandidateState::Pending,
    };
    let task = TaskRecord {
        id: id("018f22e2-79b0-7cc8-98c4-dc0c0c073991"),
        project_id: id("018f22e2-79b0-7cc8-98c4-dc0c0c073992"),
        title: "Finish payload codec".into(),
        body_markdown: "Write the strict CBOR decoder.".into(),
        status: context_relay_protocol::TaskStatus::Open,
        evidence: vec![],
        revision: id("018f22e2-79b0-7cc8-98c4-dc0c0c073993"),
    };
    let secret = SecretRef {
        id: id("018f22e2-79b0-7cc8-98c4-dc0c0c073994"),
        name: "sync-token".into(),
        provider: "keychain".into(),
        required_on_device: true,
    };
    let instruction = InstructionRecord {
        id: id("018f22e2-79b0-7cc8-98c4-dc0c0c073995"),
        scope: ScopeRef::Global,
        title: "Use canonical CBOR".into(),
        body_markdown: "Always preserve user Markdown bytes.".into(),
        provenance: memory.provenance.clone(),
        archived: false,
    };
    let component = ComponentRecord {
        id: id("018f22e2-79b0-7cc8-98c4-dc0c0c073996"),
        scope: ScopeRef::Global,
        kind: ComponentKind::Rule,
        name: "sync-rule".into(),
        body_markdown: "Keep payloads deterministic.".into(),
        metadata: vec![("language".into(), "rust".into())],
        provenance: memory.provenance.clone(),
        archived: false,
    };
    let project = ProjectIdentity {
        project_id: id("018f22e2-79b0-7cc8-98c4-dc0c0c073997"),
        github_repository_id: Some(42),
        git_remote_fingerprint: Some(Sha256Digest([9; 32])),
        monorepo_subdirectory: Some("crates/protocol".into()),
        name: "Context Relay".into(),
    };

    let mutations = vec![
        RecordMutationV1::UpsertMemory(memory),
        RecordMutationV1::UpsertMemoryCandidate(candidate),
        RecordMutationV1::UpsertTask(task),
        RecordMutationV1::UpsertSecretRef(secret),
        RecordMutationV1::UpsertInstruction(instruction),
        RecordMutationV1::UpsertComponent(component),
        RecordMutationV1::UpsertProject(project),
        RecordMutationV1::Tombstone {
            record_id: id("018f22e2-79b0-7cc8-98c4-dc0c0c073998"),
            record_kind: RecordKind::Task,
        },
    ];

    for mutation in mutations {
        let encoded = encode_record_mutation_v1(&mutation).unwrap();
        assert_eq!(decode_record_mutation_v1(&encoded).unwrap(), mutation);
    }
}

#[test]
fn fixed_memory_mutation_matches_the_version_one_fixture() {
    let mutation = RecordMutationV1::UpsertMemory(fixed_memory());
    let encoded = encode_record_mutation_v1(&mutation).unwrap();
    assert_eq!(
        hex(&encoded),
        include_str!("fixtures/sync-mutation-v1.hex").trim()
    );
    assert_eq!(decode_record_mutation_v1(&encoded).unwrap(), mutation);
}

#[test]
fn mutation_decoder_rejects_noncanonical_and_mismatched_payloads() {
    assert_rejected(duplicate_key_fixture());
    assert_rejected(out_of_order_key_fixture());
    assert_rejected(trailing_bytes_fixture());
    assert_rejected(memory_kind_with_task_json_fixture());
    assert_rejected(noncanonical_json_fixture());
}

#[test]
fn aad_binds_every_included_operation_field_only() {
    let operation = support::sync_operation();
    let canonical = encode_sync_operation_aad_v1(&operation).unwrap();

    let mut changed = operation.clone();
    changed.schema_version = 2;
    assert_ne!(encode_sync_operation_aad_v1(&changed).unwrap(), canonical);
    let mut changed = operation.clone();
    changed.operation_id = id("018f22e2-79b0-7cc8-98c4-dc0c0c073999");
    assert_ne!(encode_sync_operation_aad_v1(&changed).unwrap(), canonical);
    let mut changed = operation.clone();
    changed.account_id = id("018f22e2-79b0-7cc8-98c4-dc0c0c07399a");
    assert_ne!(encode_sync_operation_aad_v1(&changed).unwrap(), canonical);
    let mut changed = operation.clone();
    changed.workspace_id = id("018f22e2-79b0-7cc8-98c4-dc0c0c07399b");
    assert_ne!(encode_sync_operation_aad_v1(&changed).unwrap(), canonical);
    let mut changed = operation.clone();
    changed.project_id = None;
    assert_ne!(encode_sync_operation_aad_v1(&changed).unwrap(), canonical);
    let mut changed = operation.clone();
    changed.record_id = id("018f22e2-79b0-7cc8-98c4-dc0c0c07399c");
    assert_ne!(encode_sync_operation_aad_v1(&changed).unwrap(), canonical);
    let mut changed = operation.clone();
    changed.record_kind = RecordKind::Task;
    assert_ne!(encode_sync_operation_aad_v1(&changed).unwrap(), canonical);
    let mut changed = operation.clone();
    changed.mutation_kind = MutationKind::Tombstone;
    assert_ne!(encode_sync_operation_aad_v1(&changed).unwrap(), canonical);
    let mut changed = operation.clone();
    changed.device_id = id("018f22e2-79b0-7cc8-98c4-dc0c0c07399d");
    assert_ne!(encode_sync_operation_aad_v1(&changed).unwrap(), canonical);
    let mut changed = operation.clone();
    changed.device_sequence += 1;
    assert_ne!(encode_sync_operation_aad_v1(&changed).unwrap(), canonical);
    let mut changed = operation.clone();
    changed.causal_frontier[0].sequence += 1;
    assert_ne!(encode_sync_operation_aad_v1(&changed).unwrap(), canonical);
    let mut changed = operation.clone();
    changed.control_epoch += 1;
    assert_ne!(encode_sync_operation_aad_v1(&changed).unwrap(), canonical);
    let mut changed = operation.clone();
    changed.key_epoch += 1;
    assert_ne!(encode_sync_operation_aad_v1(&changed).unwrap(), canonical);
    let mut changed = operation.clone();
    changed.previous_device_hash = Sha256Digest([13; 32]);
    assert_ne!(encode_sync_operation_aad_v1(&changed).unwrap(), canonical);
    let mut changed = operation.clone();
    changed.blob_refs[0].storage_id = "blob-2".into();
    assert_ne!(encode_sync_operation_aad_v1(&changed).unwrap(), canonical);
    let mut changed = operation.clone();
    changed.created_hlc.logical += 1;
    assert_ne!(encode_sync_operation_aad_v1(&changed).unwrap(), canonical);

    let mut changed = operation.clone();
    changed.nonce.0[0] = 99;
    assert_eq!(encode_sync_operation_aad_v1(&changed).unwrap(), canonical);
    let mut changed = operation.clone();
    changed.ciphertext = BoundedCiphertext::new(vec![99, 4, 5]).unwrap();
    assert_eq!(encode_sync_operation_aad_v1(&changed).unwrap(), canonical);
    let mut changed = operation.clone();
    changed.ciphertext_hash = Sha256Digest([99; 32]);
    assert_eq!(encode_sync_operation_aad_v1(&changed).unwrap(), canonical);
    let mut changed = operation;
    changed.signature = Ed25519SignatureBytes([99; 64]);
    assert_eq!(encode_sync_operation_aad_v1(&changed).unwrap(), canonical);
}

fn fixed_memory() -> context_relay_protocol::MemoryRecord {
    let mut memory = support::memory_record();
    memory.title = "Café memory".into();
    memory.body_markdown = "# 東京\n\nMémoir — 🦀".into();
    memory.tags = vec!["étude".into(), "東京".into()];
    memory
}

fn duplicate_key_fixture() -> Vec<u8> {
    let mut encoded =
        encode_record_mutation_v1(&RecordMutationV1::UpsertMemory(fixed_memory())).unwrap();
    encoded[5] = 1;
    encoded
}

fn out_of_order_key_fixture() -> Vec<u8> {
    let mut encoded =
        encode_record_mutation_v1(&RecordMutationV1::UpsertMemory(fixed_memory())).unwrap();
    encoded[5] = 3;
    encoded[7] = 2;
    encoded
}

fn trailing_bytes_fixture() -> Vec<u8> {
    let mut encoded =
        encode_record_mutation_v1(&RecordMutationV1::UpsertMemory(fixed_memory())).unwrap();
    encoded.push(0);
    encoded
}

fn memory_kind_with_task_json_fixture() -> Vec<u8> {
    let task = TaskRecord {
        id: id("018f22e2-79b0-7cc8-98c4-dc0c0c073991"),
        project_id: id("018f22e2-79b0-7cc8-98c4-dc0c0c073992"),
        title: "Task JSON".into(),
        body_markdown: "Not a memory.".into(),
        status: context_relay_protocol::TaskStatus::Open,
        evidence: vec![],
        revision: id("018f22e2-79b0-7cc8-98c4-dc0c0c073993"),
    };
    mutation_fixture(
        RecordKind::Memory,
        MutationKind::Upsert,
        task.id.as_bytes(),
        &serde_json::to_vec(&task).unwrap(),
    )
}

fn noncanonical_json_fixture() -> Vec<u8> {
    let memory = fixed_memory();
    let json = format!(
        " {}",
        String::from_utf8(serde_json::to_vec(&memory).unwrap()).unwrap()
    );
    mutation_fixture(
        RecordKind::Memory,
        MutationKind::Upsert,
        memory.id.as_bytes(),
        json.as_bytes(),
    )
}

fn mutation_fixture(
    record_kind: RecordKind,
    mutation_kind: MutationKind,
    record_id: &[u8; 16],
    payload: &[u8],
) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(5).unwrap();
    encoder.u8(0).unwrap();
    encoder.u16(1).unwrap();
    encoder.u8(1).unwrap();
    encoder.u8(record_kind_value(record_kind)).unwrap();
    encoder.u8(2).unwrap();
    encoder.u8(mutation_kind_value(mutation_kind)).unwrap();
    encoder.u8(3).unwrap();
    encoder.bytes(record_id).unwrap();
    encoder.u8(4).unwrap();
    encoder.bytes(payload).unwrap();
    encoder.into_writer()
}

fn record_kind_value(value: RecordKind) -> u8 {
    match value {
        RecordKind::Memory => 0,
        RecordKind::MemoryCandidate => 1,
        RecordKind::Task => 2,
        RecordKind::SecretRef => 3,
        RecordKind::Instruction => 4,
        RecordKind::Component => 5,
        RecordKind::Project => 6,
    }
}

fn mutation_kind_value(value: MutationKind) -> u8 {
    match value {
        MutationKind::Upsert => 0,
        MutationKind::Tombstone => 1,
    }
}

fn assert_rejected(encoded: Vec<u8>) {
    assert!(decode_record_mutation_v1(&encoded).is_err());
}

fn id<T: FromStr>(value: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    value.parse().unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
