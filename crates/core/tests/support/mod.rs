#![allow(dead_code)]

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
};

use context_relay_core::{
    search::Embedding384,
    vault::{DatabaseKeyStore, VaultError},
};
use context_relay_protocol::{
    AccountId, ApplyReceipt, BoundedCiphertext, CandidateId, CandidateState, CheckpointV1,
    DeviceId, Ed25519SignatureBytes, HarnessId, HybridLogicalClock, InstructionRecord,
    MemoryCandidate, MemoryId, MemoryKind, MemoryOrigin, MemoryRecord, MutationKind,
    NativePlatform, OperationId, PlanId, ProjectId, Provenance, RecordId, RecordKind, ScopeRef,
    Sha256Digest, SyncOperationV1, TaskId, TaskRecord, TaskStatus, WireNativeValue, WorkspaceId,
    XChaChaNonce,
};
use zeroize::Zeroizing;

pub const ID_1: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073981";
pub const ID_2: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073982";
pub const ID_3: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073983";
pub const ID_4: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073984";
pub const ID_5: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073985";
pub const ID_6: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073986";
pub const ID_7: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073987";
pub const ID_8: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073988";
pub const ID_9: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073989";

#[derive(Default)]
pub struct MemoryKeyStore(Mutex<HashMap<String, Vec<u8>>>);

impl MemoryKeyStore {
    pub fn insert(&self, credential_id: &str, key: [u8; 32]) {
        self.0
            .lock()
            .unwrap()
            .insert(credential_id.to_owned(), key.to_vec());
    }

    pub fn remove(&self, credential_id: &str) {
        self.0.lock().unwrap().remove(credential_id);
    }

    pub fn key(&self, credential_id: &str) -> [u8; 32] {
        self.0.lock().unwrap()[credential_id]
            .as_slice()
            .try_into()
            .unwrap()
    }
}

impl DatabaseKeyStore for MemoryKeyStore {
    fn load_key(&self, credential_id: &str) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .get(credential_id)
            .cloned()
            .map(Zeroizing::new))
    }

    fn store_key(&self, credential_id: &str, key: &[u8]) -> Result<(), VaultError> {
        self.0
            .lock()
            .unwrap()
            .insert(credential_id.to_owned(), key.to_vec());
        Ok(())
    }
}

pub struct TempVault(PathBuf);

impl TempVault {
    pub fn new(name: &str) -> Self {
        let unique = format!(
            "context-relay-{name}-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        Self(std::env::temp_dir().join(unique))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempVault {
    fn drop(&mut self) {
        if self.0.is_dir() {
            let _ = fs::remove_dir_all(&self.0);
            return;
        }
        for suffix in ["", "-journal", "-wal", "-shm"] {
            let _ = fs::remove_file(format!("{}{}", self.0.display(), suffix));
        }
    }
}

pub fn clock(physical_ms: u64) -> HybridLogicalClock {
    HybridLogicalClock::new(physical_ms, 0, ID_9.parse::<DeviceId>().unwrap())
}

pub fn provenance() -> Provenance {
    Provenance {
        origin_device: ID_9.parse().unwrap(),
        harness: Some(HarnessId::Codex),
        source: None,
        created_hlc: clock(1),
    }
}

pub fn memory(id: &str, scope: ScopeRef, title: &str, body: &str) -> MemoryRecord {
    MemoryRecord {
        id: id.parse::<MemoryId>().unwrap(),
        scope,
        kind: MemoryKind::Fact,
        title: title.to_owned(),
        body_markdown: body.to_owned(),
        tags: vec!["test".to_owned()],
        origin: MemoryOrigin::Explicit,
        provenance: provenance(),
        revision: ID_8.parse().unwrap(),
        created_hlc: clock(1),
        updated_hlc: clock(2),
        archived: false,
    }
}

pub fn instruction(id: &str, scope: ScopeRef, title: &str, body: &str) -> InstructionRecord {
    InstructionRecord {
        id: id.parse().unwrap(),
        scope,
        title: title.to_owned(),
        body_markdown: body.to_owned(),
        provenance: provenance(),
        archived: false,
    }
}

pub fn operation(id: &str, record_id: &str, kind: RecordKind) -> SyncOperationV1 {
    SyncOperationV1 {
        schema_version: 1,
        operation_id: id.parse::<OperationId>().unwrap(),
        account_id: ID_7.parse::<AccountId>().unwrap(),
        workspace_id: ID_6.parse::<WorkspaceId>().unwrap(),
        project_id: None,
        record_id: record_id.parse::<RecordId>().unwrap(),
        record_kind: kind,
        mutation_kind: MutationKind::Upsert,
        device_id: ID_9.parse().unwrap(),
        device_sequence: 1,
        causal_frontier: Vec::new(),
        control_epoch: 1,
        key_epoch: 1,
        previous_device_hash: Sha256Digest([0; 32]),
        nonce: XChaChaNonce([1; 24]),
        ciphertext: BoundedCiphertext::new(vec![1, 2, 3]).unwrap(),
        ciphertext_hash: Sha256Digest([2; 32]),
        blob_refs: Vec::new(),
        created_hlc: clock(2),
        signature: Ed25519SignatureBytes([3; 64]),
    }
}

pub fn candidate() -> MemoryCandidate {
    MemoryCandidate {
        id: ID_2.parse::<CandidateId>().unwrap(),
        proposed_memory: memory(ID_2, ScopeRef::Global, "Candidate", "pending needle"),
        evidence_summary: "Observed in a test".to_owned(),
        source_harness: HarnessId::Codex,
        state: CandidateState::Pending,
    }
}

pub fn task() -> TaskRecord {
    TaskRecord {
        id: ID_3.parse::<TaskId>().unwrap(),
        project_id: ID_7.parse::<ProjectId>().unwrap(),
        title: "Task".to_owned(),
        body_markdown: "Task body".to_owned(),
        status: TaskStatus::Open,
        evidence: Vec::new(),
        revision: ID_8.parse().unwrap(),
    }
}

pub fn checkpoint() -> CheckpointV1 {
    CheckpointV1 {
        schema_version: 1,
        previous_checkpoint_hash: Sha256Digest([4; 32]),
        causal_frontier: Vec::new(),
        state_hash: Sha256Digest([5; 32]),
        key_epoch: 1,
        creator_device: ID_9.parse().unwrap(),
        created_hlc: clock(3),
        signature: Ed25519SignatureBytes([6; 64]),
    }
}

pub fn receipt(plan_id: &str, applied_ms: u64) -> ApplyReceipt {
    ApplyReceipt {
        plan_id: plan_id.parse::<PlanId>().unwrap(),
        applied_hlc: clock(applied_ms),
        resulting_digests: vec![Sha256Digest([7; 32])],
    }
}

pub fn native_path() -> WireNativeValue {
    WireNativeValue {
        platform: NativePlatform::Windows,
        bytes: r"C:\vault"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect(),
        display: Some(r"C:\vault".to_owned()),
    }
}

pub fn basis(index: usize) -> Embedding384 {
    let mut values = vec![0.0; 384];
    values[index] = 1.0;
    Embedding384::try_from(values).unwrap()
}
