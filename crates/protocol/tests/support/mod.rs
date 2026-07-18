#![allow(dead_code)]

use context_relay_protocol::*;
use std::str::FromStr;

pub const ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07398f";

fn id<T: FromStr>(value: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    value.parse().unwrap()
}
pub fn device() -> DeviceId {
    id(ID)
}
pub fn hlc() -> HybridLogicalClock {
    HybridLogicalClock::new(1_700_000_000_000, 0, device())
}

pub fn memory_record() -> MemoryRecord {
    MemoryRecord {
        id: id(ID),
        scope: ScopeRef::Global,
        kind: MemoryKind::Fact,
        title: "Title".into(),
        body_markdown: "Body".into(),
        tags: vec!["tag".into()],
        origin: MemoryOrigin::Explicit,
        provenance: Provenance {
            origin_device: device(),
            harness: Some(HarnessId::Codex),
            source: None,
            created_hlc: hlc(),
        },
        revision: id(ID),
        created_hlc: hlc(),
        updated_hlc: hlc(),
        archived: false,
    }
}

pub fn task_evidence(summary: &str) -> TaskEvidence {
    TaskEvidence {
        summary: summary.into(),
        evidence_kind: "result".into(),
        reference: None,
        recorded_hlc: hlc(),
    }
}

pub fn sync_operation() -> SyncOperationV1 {
    SyncOperationV1 {
        schema_version: 1,
        operation_id: id(ID),
        account_id: id(ID),
        workspace_id: id(ID),
        project_id: Some(id(ID)),
        record_id: id(ID),
        record_kind: RecordKind::Memory,
        mutation_kind: MutationKind::Upsert,
        device_id: device(),
        device_sequence: 7,
        causal_frontier: vec![DeviceSequence {
            device_id: device(),
            sequence: 6,
        }],
        control_epoch: 2,
        key_epoch: 3,
        previous_device_hash: Sha256Digest([1; 32]),
        nonce: XChaChaNonce([2; 24]),
        ciphertext: BoundedCiphertext::new(vec![3, 4, 5]).unwrap(),
        ciphertext_hash: Sha256Digest([6; 32]),
        blob_refs: vec![BlobRef {
            digest: Sha256Digest([7; 32]),
            ciphertext_bytes: 9,
            storage_id: "blob-1".into(),
        }],
        created_hlc: hlc(),
        signature: Ed25519SignatureBytes([8; 64]),
    }
}

pub fn checkpoint() -> CheckpointV1 {
    CheckpointV1 {
        schema_version: 1,
        previous_checkpoint_hash: Sha256Digest([9; 32]),
        causal_frontier: vec![DeviceSequence {
            device_id: device(),
            sequence: 7,
        }],
        state_hash: Sha256Digest([10; 32]),
        key_epoch: 3,
        creator_device: device(),
        created_hlc: hlc(),
        signature: Ed25519SignatureBytes([11; 64]),
    }
}

pub fn rpc_request() -> JsonRpcRequestV1 {
    JsonRpcRequestV1 {
        jsonrpc: JsonRpcVersion::V2,
        id: id(ID),
        protocol: PROTOCOL_VERSION,
        daemon_instance_nonce: DaemonInstanceNonce::new([1; 32]),
        request: LocalRequest::Health(EmptyParams {}),
    }
}

pub fn setup_plan() -> SetupPlan {
    SetupPlan {
        plan_id: id(ID),
        harness: HarnessId::Codex,
        adapter_version: 1,
        executable_path: WireNativeValue {
            platform: NativePlatform::Windows,
            bytes: vec![b'c', 0],
            display: Some("c".into()),
        },
        executable_hash: Sha256Digest([1; 32]),
        harness_version: "1.0.0".into(),
        target_scopes: vec![NativeScope::Global],
        expected_native_digests: vec![],
        semantic_changes: vec![],
        cli_operations: vec![],
        package_artifacts: vec![],
        permission_delta: PermissionDelta {
            added: vec![],
            removed: vec![],
        },
        network_delta: NetworkDelta {
            added: vec![],
            removed: vec![],
        },
        scanner_report_hash: Sha256Digest([2; 32]),
        rulesync_version: "1".into(),
        rulesync_hash: Sha256Digest([3; 32]),
        approval_class: ApprovalClass::Passive,
        expires_at: 1_700_000_060_000,
        batch_hash: Sha256Digest([4; 32]),
    }
}
