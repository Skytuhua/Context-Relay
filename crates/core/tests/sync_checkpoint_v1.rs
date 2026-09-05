mod support;

use std::{collections::BTreeMap, path::Path, str::FromStr};

use context_relay_core::{
    crypto::{CertificateIssuerV1, ContentKey, DeviceCertificateV1, DeviceKeys},
    sync::{
        CheckpointBuildContext, CheckpointDisposition, StateSummaryEntryV1, StateSummaryV1,
        SyncError, SyncScope, TrustedDevice, TrustedSyncMaterial, build_checkpoint,
        decode_state_summary_v1, verify_checkpoint,
    },
    vault::{LATEST_SCHEMA_VERSION, Vault},
};
use context_relay_protocol::{
    AccountId, DeviceId, DeviceSequence, Ed25519SignatureBytes, HybridLogicalClock,
    PairingRequestNonce, RecordId, RecordKind, Sha256Digest, WorkspaceId,
};
use rusqlite::Connection;

use support::{ID_1, ID_2, ID_3, ID_4, ID_5, MemoryKeyStore, TempVault};

const CREDENTIAL: &str = "sync-checkpoint-v1";
const CONTROL_EPOCH: u32 = 5;
const KEY_EPOCH: u32 = 11;

struct Trust {
    certificates: BTreeMap<DeviceId, DeviceCertificateV1>,
    key: ContentKey,
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
                .certificates
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
fn state_summary_is_canonical_under_record_and_head_permutations() {
    let first = StateSummaryEntryV1 {
        record_id: id(ID_4),
        record_kind: RecordKind::Task,
        head_hashes: vec![Sha256Digest([9; 32]), Sha256Digest([3; 32])],
        tombstoned: false,
        conflicted: true,
    };
    let second = StateSummaryEntryV1 {
        record_id: id(ID_3),
        record_kind: RecordKind::Memory,
        head_hashes: vec![Sha256Digest([7; 32])],
        tombstoned: true,
        conflicted: false,
    };
    let a = StateSummaryV1 {
        entries: vec![first.clone(), second.clone()],
    };
    let b = StateSummaryV1 {
        entries: vec![second, first],
    };
    let a_bytes = a.canonical_bytes().unwrap();
    let b_bytes = b.canonical_bytes().unwrap();
    assert_eq!(a_bytes, b_bytes);
    assert_eq!(a.state_hash().unwrap(), b.state_hash().unwrap());
    assert_eq!(
        decode_state_summary_v1(&a_bytes)
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        a_bytes
    );
}

#[test]
fn state_summary_has_a_fixed_definite_array_vector() {
    let summary = StateSummaryV1 {
        entries: vec![StateSummaryEntryV1 {
            record_id: id(ID_3),
            record_kind: RecordKind::Memory,
            head_hashes: vec![Sha256Digest([7; 32])],
            tombstoned: true,
            conflicted: false,
        }],
    };
    let mut expected = vec![0x81, 0x85, 0x50];
    expected.extend_from_slice(id::<RecordId>(ID_3).as_bytes());
    expected.extend_from_slice(&[0x00, 0x81, 0x58, 0x20]);
    expected.extend_from_slice(&[7; 32]);
    expected.extend_from_slice(&[0xf5, 0xf4]);
    assert_eq!(summary.canonical_bytes().unwrap(), expected);
    assert_eq!(
        summary.state_hash().unwrap(),
        Sha256Digest([
            0xba, 0xfd, 0x9d, 0x30, 0x8c, 0x9e, 0x58, 0xd9, 0x21, 0xeb, 0xa5, 0x9c, 0x00, 0x53,
            0x05, 0xaf, 0xe2, 0x2c, 0xa3, 0x4e, 0xf2, 0x20, 0xbc, 0x03, 0x97, 0xd0, 0x28, 0xdd,
            0x2a, 0x44, 0x24, 0x13,
        ])
    );
}

#[test]
fn state_summary_rejects_duplicate_records_heads_and_inconsistent_flags() {
    let entry = StateSummaryEntryV1 {
        record_id: id(ID_3),
        record_kind: RecordKind::Memory,
        head_hashes: vec![Sha256Digest([7; 32]), Sha256Digest([7; 32])],
        tombstoned: false,
        conflicted: true,
    };
    assert!(
        StateSummaryV1 {
            entries: vec![entry]
        }
        .canonical_bytes()
        .is_err()
    );

    let entry = StateSummaryEntryV1 {
        record_id: id(ID_3),
        record_kind: RecordKind::Memory,
        head_hashes: vec![Sha256Digest([7; 32])],
        tombstoned: false,
        conflicted: true,
    };
    assert!(
        StateSummaryV1 {
            entries: vec![entry.clone()]
        }
        .canonical_bytes()
        .is_err()
    );
    assert!(
        StateSummaryV1 {
            entries: vec![entry.clone(), entry]
        }
        .canonical_bytes()
        .is_err()
    );
}

#[test]
fn equal_state_checkpoint_chain_nodes_are_distinct_and_forks_fail_behind_pin() {
    let path = TempVault::new("checkpoint-chain");
    let keys_store = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys_store).unwrap();
    let device_keys = DeviceKeys::generate().unwrap();
    let device_id = id(ID_3);
    let trust = trust(device_id, &device_keys);
    let first = build_checkpoint(
        &vault,
        &CheckpointBuildContext {
            scope: scope(),
            creator_device: device_id,
            active_key_epoch: KEY_EPOCH,
            device_keys: &device_keys,
            created_hlc: HybridLogicalClock::new(100, 0, device_id),
        },
        &trust,
    )
    .unwrap();
    let verified = verify_checkpoint(&vault, scope(), &first, &trust).unwrap();
    assert_eq!(
        vault.accept_sync_checkpoint(&verified, 100).unwrap(),
        CheckpointDisposition::Inserted
    );

    let second = build_checkpoint(
        &vault,
        &CheckpointBuildContext {
            scope: scope(),
            creator_device: device_id,
            active_key_epoch: KEY_EPOCH,
            device_keys: &device_keys,
            created_hlc: HybridLogicalClock::new(101, 0, device_id),
        },
        &trust,
    )
    .unwrap();
    assert_eq!(first.state_hash, second.state_hash);
    assert_ne!(first.canonical_hash, second.canonical_hash);
    assert_eq!(
        second.checkpoint.previous_checkpoint_hash,
        first.canonical_hash
    );
    let verified = verify_checkpoint(&vault, scope(), &second, &trust).unwrap();
    vault.accept_sync_checkpoint(&verified, 101).unwrap();

    let pinned = vault.sync_checkpoint_pin(scope()).unwrap().unwrap();
    assert_eq!(pinned.canonical_hash, second.canonical_hash);
    assert_eq!(pinned.state_hash, second.state_hash);

    let fork = build_checkpoint_from_previous(
        &vault,
        scope(),
        device_id,
        &device_keys,
        &trust,
        Sha256Digest([0; 32]),
        102,
    );
    assert_eq!(
        verify_checkpoint(&vault, scope(), &fork, &trust),
        Err(SyncError::InvalidChain)
    );

    drop(vault);
    let reopened = Vault::open(path.path(), CREDENTIAL, &keys_store).unwrap();
    assert_eq!(
        reopened
            .sync_checkpoint_pin(scope())
            .unwrap()
            .unwrap()
            .canonical_hash,
        second.canonical_hash
    );
    drop(reopened);
    let raw = open_keyed(path.path(), &keys_store.key(CREDENTIAL));
    assert_eq!(
        raw.query_row("SELECT count(*) FROM signed_sync_checkpoints", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        2
    );
}

#[test]
fn checkpoint_pin_reads_reject_corrupt_metadata_and_never_cross_scope() {
    let path = TempVault::new("checkpoint-pin-validation");
    let keys_store = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys_store).unwrap();
    let keys = DeviceKeys::generate().unwrap();
    let device_id = id(ID_3);
    let trusted = trust(device_id, &keys);
    let checkpoint = build_checkpoint(
        &vault,
        &CheckpointBuildContext {
            scope: scope(),
            creator_device: device_id,
            active_key_epoch: KEY_EPOCH,
            device_keys: &keys,
            created_hlc: HybridLogicalClock::new(300, 0, device_id),
        },
        &trusted,
    )
    .unwrap();
    let verified = verify_checkpoint(&vault, scope(), &checkpoint, &trusted).unwrap();
    vault.accept_sync_checkpoint(&verified, 300).unwrap();
    assert!(
        vault
            .sync_checkpoint_pin(SyncScope {
                account_id: id(ID_4),
                workspace_id: scope().workspace_id,
            })
            .unwrap()
            .is_none()
    );
    drop(vault);

    let raw = open_keyed(path.path(), &keys_store.key(CREDENTIAL));
    raw.execute(
        "UPDATE signed_sync_checkpoints SET state_hash = zeroblob(32)",
        [],
    )
    .unwrap();
    drop(raw);
    let vault = Vault::open(path.path(), CREDENTIAL, &keys_store).unwrap();
    assert!(vault.sync_checkpoint_pin(scope()).is_err());
}

#[test]
fn checkpoint_verification_rejects_identity_signature_frontier_chain_epoch_and_state_changes() {
    let path = TempVault::new("checkpoint-verification-order");
    let keys_store = MemoryKeyStore::default();
    let vault = Vault::open(path.path(), CREDENTIAL, &keys_store).unwrap();
    let keys = DeviceKeys::generate().unwrap();
    let device_id = id(ID_3);
    let trusted = trust(device_id, &keys);
    let good = build_checkpoint(
        &vault,
        &CheckpointBuildContext {
            scope: scope(),
            creator_device: device_id,
            active_key_epoch: KEY_EPOCH,
            device_keys: &keys,
            created_hlc: HybridLogicalClock::new(200, 0, device_id),
        },
        &trusted,
    )
    .unwrap();

    let mut changed = good.clone();
    changed.checkpoint.signature.0[0] ^= 1;
    changed.recanonicalize().unwrap();
    assert_eq!(
        verify_checkpoint(&vault, scope(), &changed, &trusted),
        Err(SyncError::AuthenticationFailed)
    );

    let mut changed = good.clone();
    changed.checkpoint.key_epoch += 1;
    resign(&keys, &mut changed);
    assert_eq!(
        verify_checkpoint(&vault, scope(), &changed, &trusted),
        Err(SyncError::InvalidIdentity)
    );

    let mut changed = good.clone();
    changed.checkpoint.causal_frontier = vec![DeviceSequence {
        device_id,
        sequence: 1,
    }];
    resign(&keys, &mut changed);
    assert_eq!(
        verify_checkpoint(&vault, scope(), &changed, &trusted),
        Err(SyncError::InvalidFrontier)
    );

    let mut changed = good.clone();
    changed.checkpoint.previous_checkpoint_hash = Sha256Digest([4; 32]);
    resign(&keys, &mut changed);
    assert_eq!(
        verify_checkpoint(&vault, scope(), &changed, &trusted),
        Err(SyncError::InvalidChain)
    );

    let mut changed = good.clone();
    changed.checkpoint.state_hash = Sha256Digest([5; 32]);
    resign(&keys, &mut changed);
    assert_eq!(
        verify_checkpoint(&vault, scope(), &changed, &trusted),
        Err(SyncError::InvalidEnvelope)
    );

    let mut changed = good.clone();
    changed.checkpoint.created_hlc.node = id(ID_4);
    resign(&keys, &mut changed);
    assert_eq!(
        verify_checkpoint(&vault, scope(), &changed, &trusted),
        Err(SyncError::InvalidEnvelope)
    );

    let mut wrong_scope_trust = trust(device_id, &keys);
    wrong_scope_trust
        .certificates
        .get_mut(&device_id)
        .unwrap()
        .account_id = id(ID_4);
    assert_eq!(
        verify_checkpoint(&vault, scope(), &good, &wrong_scope_trust),
        Err(SyncError::InvalidIdentity)
    );
}

#[test]
fn checkpoint_signature_cannot_be_relabelled_into_another_workspace() {
    let source_path = TempVault::new("checkpoint-signed-source-scope");
    let receiver_path = TempVault::new("checkpoint-signed-receiver-scope");
    let keys_store = MemoryKeyStore::default();
    let source = Vault::open(source_path.path(), CREDENTIAL, &keys_store).unwrap();
    let receiver = Vault::open(receiver_path.path(), CREDENTIAL, &keys_store).unwrap();
    let keys = DeviceKeys::generate().unwrap();
    let device_id = id(ID_3);
    let mut trusted = trust(device_id, &keys);
    let checkpoint = build_checkpoint(
        &source,
        &CheckpointBuildContext {
            scope: scope(),
            creator_device: device_id,
            active_key_epoch: KEY_EPOCH,
            device_keys: &keys,
            created_hlc: HybridLogicalClock::new(400, 0, device_id),
        },
        &trusted,
    )
    .unwrap();

    let relabelled_scope = SyncScope {
        account_id: scope().account_id,
        workspace_id: id(ID_4),
    };
    let certificate = trusted.certificates.get_mut(&device_id).unwrap();
    certificate.workspace_id = relabelled_scope.workspace_id;

    assert_eq!(
        verify_checkpoint(&receiver, relabelled_scope, &checkpoint, &trusted),
        Err(SyncError::InvalidIdentity)
    );
}

#[test]
fn schema_16_upgrades_through_workspace_checkpoints_and_durable_scans() {
    let path = TempVault::new("checkpoint-migration-17");
    let keys = MemoryKeyStore::default();
    let key = [44; 32];
    keys.insert(CREDENTIAL, key);

    let raw = open_keyed(path.path(), &key);
    for (version, migration) in (1_i64..).zip([
        include_str!("../migrations/0001_vault.sql"),
        include_str!("../migrations/0002_before_image_plans.sql"),
        include_str!("../migrations/0003_native_transactions.sql"),
        include_str!("../migrations/0004_offline_workspace.sql"),
        include_str!("../migrations/0005_local_operation_bindings.sql"),
        include_str!("../migrations/0006_local_operation_results.sql"),
        include_str!("../migrations/0007_task_operation_bindings.sql"),
        include_str!("../migrations/0008_task_transitions_and_handoff_queries.sql"),
        include_str!("../migrations/0009_setup_cli_transactions.sql"),
        include_str!("../migrations/0010_native_memory_reconciliation.sql"),
        include_str!("../migrations/0011_native_hook_sessions.sql"),
        include_str!("../migrations/0012_setup_native_memory_bindings.sql"),
        include_str!("../migrations/0013_setup_native_memory_ownership.sql"),
        include_str!("../migrations/0014_signed_sync.sql"),
        include_str!("../migrations/0015_sync_quarantine.sql"),
        include_str!("../migrations/0016_sync_rejections.sql"),
    ]) {
        raw.execute_batch(migration).unwrap();
        raw.pragma_update(None, "user_version", version).unwrap();
    }
    drop(raw);

    let vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(vault.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
    let names = vault.table_names().unwrap();
    for required in [
        "signed_sync_checkpoints",
        "sync_checkpoint_pins",
        "sync_checkpoint_schedule",
        "sync_checkpoint_scans",
    ] {
        assert!(names.iter().any(|name| name == required));
    }
}

fn build_checkpoint_from_previous(
    vault: &Vault,
    scope: SyncScope,
    device_id: DeviceId,
    keys: &DeviceKeys,
    trust: &Trust,
    previous: Sha256Digest,
    physical_ms: u64,
) -> context_relay_core::sync::CanonicalCheckpoint {
    let mut value = build_checkpoint(
        vault,
        &CheckpointBuildContext {
            scope,
            creator_device: device_id,
            active_key_epoch: KEY_EPOCH,
            device_keys: keys,
            created_hlc: HybridLogicalClock::new(physical_ms, 0, device_id),
        },
        trust,
    )
    .unwrap();
    value.checkpoint.previous_checkpoint_hash = previous;
    keys.sign_checkpoint(&mut value.checkpoint).unwrap();
    value.recanonicalize().unwrap();
    value
}

fn resign(keys: &DeviceKeys, value: &mut context_relay_core::sync::CanonicalCheckpoint) {
    keys.sign_checkpoint(&mut value.checkpoint).unwrap();
    value.recanonicalize().unwrap();
}

fn trust(device_id: DeviceId, keys: &DeviceKeys) -> Trust {
    Trust {
        certificates: [(
            device_id,
            DeviceCertificateV1 {
                issuer: CertificateIssuerV1::Device {
                    device_id: id(ID_5),
                    signing_public_key: keys.signing_public_key(),
                },
                account_id: id(ID_1),
                workspace_id: id(ID_2),
                control_epoch: CONTROL_EPOCH,
                request_nonce: PairingRequestNonce([8; 32]),
                device_id,
                signing_public_key: keys.signing_public_key(),
                wrapping_public_key: keys.wrapping_public_key(),
                signature: Ed25519SignatureBytes([0; 64]),
            },
        )]
        .into_iter()
        .collect(),
        key: ContentKey::from_bytes([3; 32]),
    }
}

fn scope() -> SyncScope {
    SyncScope {
        account_id: id(ID_1),
        workspace_id: id(ID_2),
    }
}

fn id<T: FromStr>(value: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    value.parse().unwrap()
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
