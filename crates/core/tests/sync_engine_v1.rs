mod support;

use std::{collections::BTreeMap, ops::RangeInclusive, path::Path, str::FromStr};

use context_relay_core::{
    crypto::{CertificateIssuerV1, ContentKey, DeviceCertificateV1, DeviceKeys},
    search::Embedding384,
    sync::{
        CanonicalCheckpoint, CanonicalOperation, CheckpointBuildContext, CheckpointCursor,
        CheckpointPage, CheckpointReceipt, FaultSchedule, InMemoryTransport, OperationBuilder,
        OperationChainHead, PullPage, PushReceipt, ReceivedOperation,
        RepresentativeEmbeddingResolver, RetryRandomSource, SyncEngine, SyncError, SyncIdentity,
        SyncProvider, SyncScope, SyncTransport, TransportError, TrustedDevice, TrustedSyncMaterial,
    },
    vault::{
        CommitDisposition, LATEST_SCHEMA_VERSION, OutboxUnblockReason, SyncCheckpointSchedule,
        Vault,
    },
};
use context_relay_protocol::{
    AccountId, BlobRef, CHECKPOINT_SCHEMA_VERSION, CheckpointV1, DeviceId, Ed25519SignatureBytes,
    HybridLogicalClock, MAX_CBOR_OPERATION_BYTES, OperationId, PairingRequestNonce,
    RecordMutationV1, SecretRef, SecretRefId, Sha256Digest, WorkspaceId,
};
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};

use support::{ID_1, ID_2, ID_3, MemoryKeyStore, TempVault};

const CREDENTIAL: &str = "sync-engine-v1";
const CONTROL_EPOCH: u32 = 5;
const KEY_EPOCH: u32 = 11;
const CONTENT_KEY: [u8; 32] = [61; 32];

struct DeviceFixture {
    keys: DeviceKeys,
    certificate: DeviceCertificateV1,
}

struct Trust {
    devices: BTreeMap<DeviceId, DeviceCertificateV1>,
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

#[test]
fn provider_scopes_exact_duplicates_and_device_sequences() {
    let device = device(ID_3, 31);
    let operations = chain(&device, 2, 100);
    let first = canonical(&operations[0].1);
    let scope = scope();
    let other_scope = SyncScope {
        account_id: id(ID_1),
        workspace_id: generated_id(901),
    };
    let mut provider = InMemoryTransport::new();

    let receipt = provider
        .push_operations(scope, std::slice::from_ref(&first))
        .unwrap();
    assert_eq!(receipt.accepted, vec![first.operation_id]);
    assert!(receipt.duplicates.is_empty());

    let receipt = provider
        .push_operations(scope, std::slice::from_ref(&first))
        .unwrap();
    assert!(receipt.accepted.is_empty());
    assert_eq!(receipt.duplicates, vec![first.operation_id]);

    let altered = canonical(&chain(&device, 1, 100).remove(0).1);
    assert_eq!(altered.operation_id, first.operation_id);
    assert_ne!(altered.bytes, first.bytes);
    assert_eq!(
        provider.push_operations(scope, &[altered]),
        Err(TransportError::Integrity)
    );

    let reused_sequence = canonical(&chain(&device, 1, 200).remove(0).1);
    assert_ne!(reused_sequence.operation_id, first.operation_id);
    assert_eq!(reused_sequence.device_sequence, first.device_sequence);
    assert_eq!(
        provider.push_operations(scope, &[reused_sequence]),
        Err(TransportError::Integrity)
    );
    assert!(
        provider
            .pull_operations(other_scope, None, 256)
            .unwrap()
            .rows
            .is_empty()
    );
}

#[test]
fn pull_is_strictly_cursor_ordered_and_capped_at_256() {
    let device = device(ID_3, 32);
    let operations = chain(&device, 257, 1_000);
    let canonical = operations
        .iter()
        .map(|(_, built)| canonical(built))
        .collect::<Vec<_>>();
    let mut provider = InMemoryTransport::new();

    assert_eq!(
        provider.push_operations(scope(), &canonical),
        Err(TransportError::Configuration)
    );
    provider
        .push_operations(scope(), &canonical[..256])
        .unwrap();
    provider
        .push_operations(scope(), &canonical[256..])
        .unwrap();
    let first = provider.pull_operations(scope(), None, usize::MAX).unwrap();
    assert_eq!(first.rows.len(), 256);
    assert!(first.rows.windows(2).all(|pair| {
        pair[0].cursor.received_at < pair[1].cursor.received_at
            || (pair[0].cursor.received_at == pair[1].cursor.received_at
                && pair[0].cursor.operation_id < pair[1].cursor.operation_id)
    }));
    assert!(
        first
            .rows
            .iter()
            .all(|row| row.cursor.received_at == first.rows[0].cursor.received_at)
    );

    let cursor = first.next_cursor.as_ref().unwrap();
    let second = provider
        .pull_operations(scope(), Some(cursor), usize::MAX)
        .unwrap();
    assert_eq!(second.rows.len(), 1);
    assert_eq!(
        second.rows[0].operation.operation_id,
        canonical[256].operation_id
    );
    assert!(
        provider
            .pull_operations(scope(), second.next_cursor.as_ref(), 256)
            .unwrap()
            .rows
            .is_empty()
    );
}

#[test]
fn deterministic_faults_are_nondestructive_and_lost_hints_do_not_block_pull() {
    let device = device(ID_3, 33);
    let operations = chain(&device, 2, 2_000)
        .iter()
        .map(|(_, built)| canonical(built))
        .collect::<Vec<_>>();
    let faults = FaultSchedule::default()
        .with_transient_pulls(1)
        .with_dropped_pulls(1)
        .with_delayed_pulls(1)
        .with_duplicated_pulls(1)
        .with_reversed_pulls(1)
        .with_lost_hints(1);
    let mut provider = InMemoryTransport::with_faults(faults);
    provider.push_operations(scope(), &operations).unwrap();

    assert!(!provider.take_change_hint(scope()));
    assert!(!provider.take_change_hint(scope()));
    assert_eq!(
        provider.pull_operations(scope(), None, 256),
        Err(TransportError::Transient)
    );
    assert!(
        provider
            .pull_operations(scope(), None, 256)
            .unwrap()
            .rows
            .is_empty()
    );
    assert!(
        provider
            .pull_operations(scope(), None, 256)
            .unwrap()
            .rows
            .is_empty()
    );
    let duplicated = provider.pull_operations(scope(), None, 256).unwrap();
    assert_eq!(duplicated.rows.len(), 3);
    assert_eq!(duplicated.rows[0], duplicated.rows[2]);
    provider.schedule_faults(FaultSchedule::default().with_reversed_pulls(1));
    let reversed = provider.pull_operations(scope(), None, 256).unwrap();
    assert_eq!(reversed.rows.len(), 2);
    assert!(reversed.rows[0].operation.operation_id > reversed.rows[1].operation.operation_id);
    assert_eq!(
        provider.pull_operations(scope(), None, 256).unwrap().rows[0]
            .operation
            .operation_id,
        operations[0].operation_id
    );
}

#[test]
fn checkpoint_transport_is_scoped_exact_and_bounded() {
    let mut provider = InMemoryTransport::new();
    let checkpoint = canonical_checkpoint(7, 1);
    assert_eq!(
        provider
            .push_checkpoint(scope(), CHECKPOINT_SCHEMA_VERSION, &checkpoint)
            .unwrap(),
        CheckpointReceipt {
            canonical_hash: checkpoint.canonical_hash,
            duplicate: false,
        }
    );
    assert_eq!(
        provider.push_checkpoint(
            SyncScope {
                account_id: scope().account_id,
                workspace_id: id(ID_3),
            },
            CHECKPOINT_SCHEMA_VERSION,
            &checkpoint,
        ),
        Err(TransportError::Integrity)
    );
    let mut same_state_new_node = canonical_checkpoint(7, 2);
    same_state_new_node.checkpoint.previous_checkpoint_hash = checkpoint.canonical_hash;
    same_state_new_node.recanonicalize().unwrap();
    assert_ne!(
        same_state_new_node.canonical_hash,
        checkpoint.canonical_hash
    );
    assert_eq!(
        provider
            .push_checkpoint(scope(), CHECKPOINT_SCHEMA_VERSION, &same_state_new_node)
            .unwrap(),
        CheckpointReceipt {
            canonical_hash: same_state_new_node.canonical_hash,
            duplicate: false,
        }
    );
    assert_eq!(
        provider
            .push_checkpoint(scope(), CHECKPOINT_SCHEMA_VERSION, &checkpoint)
            .unwrap(),
        CheckpointReceipt {
            canonical_hash: checkpoint.canonical_hash,
            duplicate: true,
        }
    );
    let mut altered = checkpoint.clone();
    altered.bytes[0] ^= 1;
    assert_eq!(
        provider.push_checkpoint(scope(), CHECKPOINT_SCHEMA_VERSION, &altered),
        Err(TransportError::Integrity)
    );
    let pulled = provider
        .pull_checkpoints(scope(), CHECKPOINT_SCHEMA_VERSION, None, 999)
        .unwrap();
    assert_eq!(pulled.rows.len(), 2);
    assert_eq!(pulled.rows[0].checkpoint, checkpoint);
    assert_eq!(pulled.rows[1].checkpoint, same_state_new_node);
    assert!(
        pulled
            .rows
            .iter()
            .all(|row| row.cursor.canonical_hash == row.checkpoint.canonical_hash)
    );
    let mut oversized = canonical_checkpoint(8, 2);
    oversized.bytes = vec![0; MAX_CBOR_OPERATION_BYTES + 1];
    assert_eq!(
        provider.push_checkpoint(scope(), CHECKPOINT_SCHEMA_VERSION, &oversized),
        Err(TransportError::Configuration)
    );
}

struct AttemptBoundRandom;

impl RetryRandomSource for AttemptBoundRandom {
    fn random_u64(&self, _operation_id: OperationId, attempt: u32) -> u64 {
        match attempt {
            0 => 1_000,
            3 => 8_000,
            _ => 0,
        }
    }
}

#[test]
fn transient_batch_uses_each_rows_durable_attempt_count() {
    let device = device(ID_3, 91);
    let trust = trust(&device);
    let operations = chain(&device, 2, 21_000);
    let path = TempVault::new("sync-engine-per-row-backoff");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    for (mutation, operation) in &operations {
        vault
            .commit_outgoing_operation(mutation, operation, None)
            .unwrap();
    }
    for _ in 0..3 {
        vault
            .defer_outbox(&[operations[0].1.operation.operation_id], 0, "transient")
            .unwrap();
    }
    let mut provider = InMemoryTransport::with_faults(FaultSchedule::transient_push(1));
    let engine =
        SyncEngine::new(scope(), SyncProvider::Memory).with_retry_random_source(AttemptBoundRandom);

    assert_eq!(
        engine
            .sync_once(&mut vault, &mut provider, &trust, &NoEmbeddings, 0)
            .unwrap_err()
            .safe_code(),
        "transient"
    );
    assert_eq!(
        vault
            .due_outbox(1_000, 256)
            .unwrap()
            .iter()
            .map(|row| row.operation_id)
            .collect::<Vec<_>>(),
        vec![operations[1].1.operation.operation_id]
    );
    assert_eq!(vault.due_outbox(7_999, 256).unwrap().len(), 1);
    assert_eq!(vault.due_outbox(8_000, 256).unwrap().len(), 2);
}

#[test]
fn blocked_outbox_classes_never_become_time_due() {
    let device = device(ID_3, 95);
    let operations = chain(&device, 1, 21_500);
    let path = TempVault::new("sync-engine-blocked-outbox");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault
        .commit_outgoing_operation(&operations[0].0, &operations[0].1, None)
        .unwrap();
    for code in [
        "auth_required",
        "revoked",
        "quota_blocked",
        "integrity_quarantined",
        "configuration_error",
    ] {
        vault
            .defer_outbox(
                &[operations[0].1.operation.operation_id],
                i64::MAX as u64,
                code,
            )
            .unwrap();
        assert!(vault.due_outbox(u64::MAX, 256).unwrap().is_empty());
    }
}

#[test]
fn explicit_checkpoint_is_pushed_verified_pinned_and_durable() {
    let device = device(ID_3, 92);
    let trust = trust(&device);
    let operations = chain(&device, 1, 22_000);
    let path = TempVault::new("sync-engine-explicit-checkpoint");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault
        .commit_outgoing_operation(&operations[0].0, &operations[0].1, None)
        .unwrap();
    vault.request_sync_checkpoint(scope()).unwrap();
    let mut provider = InMemoryTransport::new();
    let engine =
        SyncEngine::new(scope(), SyncProvider::Memory).with_retry_random_source(AttemptBoundRandom);
    let context = CheckpointBuildContext {
        scope: scope(),
        creator_device: device.certificate.device_id,
        active_key_epoch: KEY_EPOCH,
        device_keys: &device.keys,
        created_hlc: HybridLogicalClock::new(22_100, 0, device.certificate.device_id),
    };

    let report = engine
        .sync_once_with_checkpoint(
            &mut vault,
            &mut provider,
            &trust,
            &NoEmbeddings,
            22_100,
            &context,
        )
        .unwrap();
    assert!(report.checkpointed);
    let pin = vault.sync_checkpoint_pin(scope()).unwrap().unwrap();
    let remote = provider
        .pull_checkpoints(scope(), CHECKPOINT_SCHEMA_VERSION, None, 256)
        .unwrap();
    assert_eq!(remote.rows.len(), 1);
    assert_eq!(remote.rows[0].checkpoint.canonical_hash, pin.canonical_hash);
    assert!(!vault.sync_checkpoint_schedule(scope()).unwrap().requested);
    drop(vault);

    let reopened = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(
        reopened
            .sync_checkpoint_pin(scope())
            .unwrap()
            .unwrap()
            .canonical_hash,
        pin.canonical_hash
    );
}

#[test]
fn retained_legacy_log_is_partitioned_while_proxy_forwards_v2_lookup_after_a_pin_exists() {
    let device = device(ID_3, 103);
    let path = TempVault::new("sync-checkpoint-delegating-transport");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault.request_sync_checkpoint(scope()).unwrap();
    let context = CheckpointBuildContext {
        scope: scope(),
        creator_device: device.certificate.device_id,
        active_key_epoch: KEY_EPOCH,
        device_keys: &device.keys,
        created_hlc: HybridLogicalClock::new(21_100, 0, device.certificate.device_id),
    };
    let mut provider = DelegatingTransport {
        inner: InMemoryTransport::new(),
        legacy_checkpoint_v1: decode_hex(include_str!("fixtures/checkpoint-schema17-v1.hex")),
        requested_checkpoint_versions: Vec::new(),
    };
    let engine = SyncEngine::new(scope(), SyncProvider::Memory);

    assert!(
        engine
            .sync_once_with_checkpoint(
                &mut vault,
                &mut provider,
                &trust(&device),
                &NoEmbeddings,
                21_100,
                &context,
            )
            .unwrap()
            .checkpointed
    );
    let pinned = vault
        .sync_checkpoint_pin(scope())
        .unwrap()
        .unwrap()
        .canonical_hash;

    let second = engine
        .sync_once_with_checkpoint(
            &mut vault,
            &mut provider,
            &trust(&device),
            &NoEmbeddings,
            21_101,
            &context,
        )
        .unwrap();
    assert_eq!(
        vault
            .sync_checkpoint_pin(scope())
            .unwrap()
            .unwrap()
            .canonical_hash,
        pinned
    );
    assert_eq!(second.pulled, 0);
    assert!(!provider.legacy_checkpoint_v1.is_empty());
    assert!(
        !provider.requested_checkpoint_versions.is_empty()
            && provider
                .requested_checkpoint_versions
                .iter()
                .all(|version| *version == CHECKPOINT_SCHEMA_VERSION)
    );
}

#[test]
fn checkpoint_threshold_and_24_hour_clock_are_durable_predicates() {
    let device = device(ID_3, 93);
    let operations = chain(&device, 1, 23_000);
    let path = TempVault::new("sync-engine-checkpoint-schedule");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let started = operations[0].1.operation.created_hlc.physical_ms;
    vault
        .commit_outgoing_operation_at(&operations[0].0, &operations[0].1, None, started)
        .unwrap();
    let schedule = vault.sync_checkpoint_schedule(scope()).unwrap();
    assert_eq!(schedule.applied_operations, 1);
    assert!(!schedule.is_due(started + SyncCheckpointSchedule::INTERVAL_MS - 1));
    assert!(schedule.is_due(started + SyncCheckpointSchedule::INTERVAL_MS));
    drop(vault);

    let reopened = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(
        reopened.sync_checkpoint_schedule(scope()).unwrap(),
        schedule
    );
    assert!(
        SyncCheckpointSchedule {
            applied_operations: SyncCheckpointSchedule::OPERATION_THRESHOLD,
            first_uncheckpointed_ms: Some(started),
            last_checkpoint_ms: None,
            requested: false,
        }
        .is_due(started)
    );
}

#[test]
fn checkpoint_schedule_uses_local_commit_time_not_signed_hlc() {
    let device = device(ID_3, 96);
    let operations = chain(&device, 1, 23_500);
    let signed_hlc_ms = operations[0].1.operation.created_hlc.physical_ms;

    let future_path = TempVault::new("sync-checkpoint-future-signed-clock");
    let future_keys = MemoryKeyStore::default();
    let mut future_vault = Vault::open(future_path.path(), CREDENTIAL, &future_keys).unwrap();
    let local_commit_ms = 10_000;
    future_vault
        .commit_outgoing_operation_at(&operations[0].0, &operations[0].1, None, local_commit_ms)
        .unwrap();
    let schedule = future_vault.sync_checkpoint_schedule(scope()).unwrap();
    assert!(signed_hlc_ms > local_commit_ms + SyncCheckpointSchedule::INTERVAL_MS);
    assert_eq!(schedule.first_uncheckpointed_ms, Some(local_commit_ms));
    assert!(!schedule.is_due(local_commit_ms + SyncCheckpointSchedule::INTERVAL_MS - 1));
    assert!(schedule.is_due(local_commit_ms + SyncCheckpointSchedule::INTERVAL_MS));
    assert_eq!(
        future_vault
            .commit_outgoing_operation_at(
                &operations[0].0,
                &operations[0].1,
                None,
                local_commit_ms + 1,
            )
            .unwrap(),
        CommitDisposition::ExactReplay
    );
    assert_eq!(
        future_vault
            .sync_checkpoint_schedule(scope())
            .unwrap()
            .applied_operations,
        1
    );

    let stale_path = TempVault::new("sync-checkpoint-stale-signed-clock");
    let stale_keys = MemoryKeyStore::default();
    let mut stale_vault = Vault::open(stale_path.path(), CREDENTIAL, &stale_keys).unwrap();
    let later_local_commit_ms = signed_hlc_ms + 10 * SyncCheckpointSchedule::INTERVAL_MS;
    stale_vault
        .commit_outgoing_operation_at(
            &operations[0].0,
            &operations[0].1,
            None,
            later_local_commit_ms,
        )
        .unwrap();
    let schedule = stale_vault.sync_checkpoint_schedule(scope()).unwrap();
    assert_eq!(
        schedule.first_uncheckpointed_ms,
        Some(later_local_commit_ms)
    );
    assert!(!schedule.is_due(later_local_commit_ms + SyncCheckpointSchedule::INTERVAL_MS - 1));
    assert!(schedule.is_due(later_local_commit_ms + SyncCheckpointSchedule::INTERVAL_MS));

    let incoming_path = TempVault::new("sync-checkpoint-incoming-local-clock");
    let incoming_keys = MemoryKeyStore::default();
    let mut incoming_vault = Vault::open(incoming_path.path(), CREDENTIAL, &incoming_keys).unwrap();
    let mut provider = InMemoryTransport::new();
    provider
        .push_operations(scope(), &[canonical(&operations[0].1)])
        .unwrap();
    let incoming_applied_ms = 20_000;
    SyncEngine::new(scope(), SyncProvider::Memory)
        .sync_once(
            &mut incoming_vault,
            &mut provider,
            &trust(&device),
            &NoEmbeddings,
            incoming_applied_ms,
        )
        .unwrap();
    assert_eq!(
        incoming_vault
            .sync_checkpoint_schedule(scope())
            .unwrap()
            .first_uncheckpointed_ms,
        Some(incoming_applied_ms)
    );
}

#[test]
fn remote_checkpoint_chain_is_verified_and_provider_omission_of_pin_is_integrity_failure() {
    let device = device(ID_3, 94);
    let trust = trust(&device);
    let sender_path = TempVault::new("sync-engine-checkpoint-source");
    let receiver_path = TempVault::new("sync-engine-checkpoint-receiver");
    let sender_keys = MemoryKeyStore::default();
    let receiver_keys = MemoryKeyStore::default();
    let sender = Vault::open(sender_path.path(), CREDENTIAL, &sender_keys).unwrap();
    let mut receiver = Vault::open(receiver_path.path(), CREDENTIAL, &receiver_keys).unwrap();
    let context = CheckpointBuildContext {
        scope: scope(),
        creator_device: device.certificate.device_id,
        active_key_epoch: KEY_EPOCH,
        device_keys: &device.keys,
        created_hlc: HybridLogicalClock::new(24_000, 0, device.certificate.device_id),
    };
    let checkpoint = context_relay_core::sync::build_checkpoint(&sender, &context, &trust).unwrap();
    let mut provider = InMemoryTransport::new();
    provider
        .push_checkpoint(scope(), CHECKPOINT_SCHEMA_VERSION, &checkpoint)
        .unwrap();
    let engine = SyncEngine::new(scope(), SyncProvider::Memory);

    let report = engine
        .sync_once_with_checkpoint(
            &mut receiver,
            &mut provider,
            &trust,
            &NoEmbeddings,
            24_000,
            &context,
        )
        .unwrap();
    assert!(report.checkpointed);
    assert_eq!(
        receiver
            .sync_checkpoint_pin(scope())
            .unwrap()
            .unwrap()
            .canonical_hash,
        checkpoint.canonical_hash
    );

    let mut omitting_provider = InMemoryTransport::new();
    assert_eq!(
        engine
            .sync_once_with_checkpoint(
                &mut receiver,
                &mut omitting_provider,
                &trust,
                &NoEmbeddings,
                24_001,
                &context,
            )
            .unwrap_err()
            .safe_code(),
        "integrity_quarantined"
    );
}

#[test]
fn checkpoint_history_validates_distinct_states_and_resumes_beyond_cycle_limit() {
    let device = device(ID_3, 97);
    let trust = trust(&device);
    let sender_path = TempVault::new("sync-engine-checkpoint-history-source");
    let receiver_path = TempVault::new("sync-engine-checkpoint-history-receiver");
    let sender_keys = MemoryKeyStore::default();
    let receiver_keys = MemoryKeyStore::default();
    let sender = Vault::open(sender_path.path(), CREDENTIAL, &sender_keys).unwrap();
    let mut receiver = Vault::open(receiver_path.path(), CREDENTIAL, &receiver_keys).unwrap();
    let context = CheckpointBuildContext {
        scope: scope(),
        creator_device: device.certificate.device_id,
        active_key_epoch: KEY_EPOCH,
        device_keys: &device.keys,
        created_hlc: HybridLogicalClock::new(24_100, 0, device.certificate.device_id),
    };
    let local_state =
        context_relay_core::sync::build_checkpoint(&sender, &context, &trust).unwrap();
    let first = signed_checkpoint(
        &device,
        Sha256Digest([0; 32]),
        Sha256Digest([1; 32]),
        24_101,
    );
    let second = signed_checkpoint(&device, first.canonical_hash, Sha256Digest([2; 32]), 24_102);
    let third = signed_checkpoint(
        &device,
        second.canonical_hash,
        local_state.state_hash,
        24_103,
    );
    let mut provider = InMemoryTransport::new();
    for checkpoint in [&first, &second, &third] {
        provider
            .push_checkpoint(scope(), CHECKPOINT_SCHEMA_VERSION, checkpoint)
            .unwrap();
    }
    let engine = SyncEngine::new(scope(), SyncProvider::Memory).with_max_operations(2);

    let first_report = engine
        .sync_once_with_checkpoint(
            &mut receiver,
            &mut provider,
            &trust,
            &NoEmbeddings,
            24_200,
            &context,
        )
        .unwrap();
    assert!(first_report.more_work);
    assert!(!first_report.checkpointed);
    assert!(receiver.sync_checkpoint_pin(scope()).unwrap().is_none());
    drop(receiver);

    let mut reopened = Vault::open(receiver_path.path(), CREDENTIAL, &receiver_keys).unwrap();
    let second_report = engine
        .sync_once_with_checkpoint(
            &mut reopened,
            &mut provider,
            &trust,
            &NoEmbeddings,
            24_201,
            &context,
        )
        .unwrap();
    assert!(second_report.checkpointed);
    assert_eq!(
        reopened
            .sync_checkpoint_pin(scope())
            .unwrap()
            .unwrap()
            .canonical_hash,
        third.canonical_hash
    );
}

#[test]
fn valid_remote_checkpoint_that_lags_local_state_is_not_pinned_or_rejected() {
    let device = device(ID_3, 100);
    let trust = trust(&device);
    let sender_path = TempVault::new("sync-engine-stale-checkpoint-source");
    let receiver_path = TempVault::new("sync-engine-stale-checkpoint-receiver");
    let sender_keys = MemoryKeyStore::default();
    let receiver_keys = MemoryKeyStore::default();
    let sender = Vault::open(sender_path.path(), CREDENTIAL, &sender_keys).unwrap();
    let mut receiver = Vault::open(receiver_path.path(), CREDENTIAL, &receiver_keys).unwrap();
    let context = CheckpointBuildContext {
        scope: scope(),
        creator_device: device.certificate.device_id,
        active_key_epoch: KEY_EPOCH,
        device_keys: &device.keys,
        created_hlc: HybridLogicalClock::new(24_250, 0, device.certificate.device_id),
    };
    let stale_checkpoint =
        context_relay_core::sync::build_checkpoint(&sender, &context, &trust).unwrap();
    let local = chain(&device, 1, 24_251);
    receiver
        .commit_outgoing_operation_at(&local[0].0, &local[0].1, None, 24_251)
        .unwrap();
    let mut provider = InMemoryTransport::new();
    provider
        .push_checkpoint(scope(), CHECKPOINT_SCHEMA_VERSION, &stale_checkpoint)
        .unwrap();

    let report = SyncEngine::new(scope(), SyncProvider::Memory)
        .sync_once_with_checkpoint(
            &mut receiver,
            &mut provider,
            &trust,
            &NoEmbeddings,
            24_252,
            &context,
        )
        .unwrap();
    assert!(!report.checkpointed);
    assert!(receiver.sync_checkpoint_pin(scope()).unwrap().is_none());

    let mut current_endpoint = context_relay_core::sync::build_checkpoint(
        &receiver,
        &CheckpointBuildContext {
            created_hlc: HybridLogicalClock::new(24_253, 0, device.certificate.device_id),
            ..context
        },
        &trust,
    )
    .unwrap();
    current_endpoint.checkpoint.previous_checkpoint_hash = stale_checkpoint.canonical_hash;
    device
        .keys
        .sign_checkpoint(&mut current_endpoint.checkpoint)
        .unwrap();
    current_endpoint.recanonicalize().unwrap();
    provider
        .push_checkpoint(scope(), CHECKPOINT_SCHEMA_VERSION, &current_endpoint)
        .unwrap();

    let resumed = SyncEngine::new(scope(), SyncProvider::Memory)
        .sync_once_with_checkpoint(
            &mut receiver,
            &mut provider,
            &trust,
            &NoEmbeddings,
            24_254,
            &context,
        )
        .unwrap();
    assert!(resumed.checkpointed);
    assert_eq!(
        receiver
            .sync_checkpoint_pin(scope())
            .unwrap()
            .unwrap()
            .canonical_hash,
        current_endpoint.canonical_hash
    );
}

#[test]
fn due_checkpoint_extends_authenticated_lagging_endpoint_without_a_local_pin() {
    let device = device(ID_3, 104);
    let trusted = trust(&device);
    let source_path = TempVault::new("sync-checkpoint-due-extension-source");
    let receiver_path = TempVault::new("sync-checkpoint-due-extension-receiver");
    let source_keys = MemoryKeyStore::default();
    let receiver_keys = MemoryKeyStore::default();
    let source = Vault::open(source_path.path(), CREDENTIAL, &source_keys).unwrap();
    let mut receiver = Vault::open(receiver_path.path(), CREDENTIAL, &receiver_keys).unwrap();
    let remote_context = CheckpointBuildContext {
        scope: scope(),
        creator_device: device.certificate.device_id,
        active_key_epoch: KEY_EPOCH,
        device_keys: &device.keys,
        created_hlc: HybridLogicalClock::new(24_280, 0, device.certificate.device_id),
    };
    let lagging =
        context_relay_core::sync::build_checkpoint(&source, &remote_context, &trusted).unwrap();
    let local = chain(&device, 1, 24_281).remove(0);
    receiver
        .commit_outgoing_operation_at(&local.0, &local.1, None, 24_281)
        .unwrap();
    receiver.request_sync_checkpoint(scope()).unwrap();
    let local_context = CheckpointBuildContext {
        created_hlc: HybridLogicalClock::new(24_282, 0, device.certificate.device_id),
        ..remote_context
    };
    let mut provider = InMemoryTransport::new();
    provider
        .push_checkpoint(scope(), CHECKPOINT_SCHEMA_VERSION, &lagging)
        .unwrap();
    let engine = SyncEngine::new(scope(), SyncProvider::Memory);

    let report = engine
        .sync_once_with_checkpoint(
            &mut receiver,
            &mut provider,
            &trusted,
            &NoEmbeddings,
            24_282,
            &local_context,
        )
        .unwrap();
    assert!(report.checkpointed);
    let remote = provider
        .pull_checkpoints(scope(), CHECKPOINT_SCHEMA_VERSION, None, 256)
        .unwrap();
    assert_eq!(remote.rows.len(), 2);
    let published = remote.rows[1].checkpoint.clone();
    assert_eq!(
        published.checkpoint.previous_checkpoint_hash,
        lagging.canonical_hash
    );
    assert_eq!(
        receiver
            .sync_checkpoint_pin(scope())
            .unwrap()
            .unwrap()
            .canonical_hash,
        published.canonical_hash
    );

    drop(receiver);
    let mut reopened = Vault::open(receiver_path.path(), CREDENTIAL, &receiver_keys).unwrap();
    engine
        .sync_once_with_checkpoint(
            &mut reopened,
            &mut provider,
            &trusted,
            &NoEmbeddings,
            24_283,
            &local_context,
        )
        .unwrap();
    assert_eq!(
        reopened
            .sync_checkpoint_pin(scope())
            .unwrap()
            .unwrap()
            .canonical_hash,
        published.canonical_hash
    );
}

#[test]
fn due_checkpoint_extends_authenticated_lagging_endpoint_after_existing_pin() {
    let device = device(ID_3, 105);
    let trusted = trust(&device);
    let source_path = TempVault::new("sync-checkpoint-due-existing-pin-source");
    let receiver_path = TempVault::new("sync-checkpoint-due-existing-pin-receiver");
    let source_keys = MemoryKeyStore::default();
    let receiver_keys = MemoryKeyStore::default();
    let source = Vault::open(source_path.path(), CREDENTIAL, &source_keys).unwrap();
    let mut receiver = Vault::open(receiver_path.path(), CREDENTIAL, &receiver_keys).unwrap();
    let context = CheckpointBuildContext {
        scope: scope(),
        creator_device: device.certificate.device_id,
        active_key_epoch: KEY_EPOCH,
        device_keys: &device.keys,
        created_hlc: HybridLogicalClock::new(24_290, 0, device.certificate.device_id),
    };
    let initial = context_relay_core::sync::build_checkpoint(&source, &context, &trusted).unwrap();
    let lagging = signed_checkpoint(&device, initial.canonical_hash, initial.state_hash, 24_291);
    let mut provider = InMemoryTransport::new();
    provider
        .push_checkpoint(scope(), CHECKPOINT_SCHEMA_VERSION, &initial)
        .unwrap();
    let engine = SyncEngine::new(scope(), SyncProvider::Memory);
    engine
        .sync_once_with_checkpoint(
            &mut receiver,
            &mut provider,
            &trusted,
            &NoEmbeddings,
            24_290,
            &context,
        )
        .unwrap();
    assert_eq!(
        receiver
            .sync_checkpoint_pin(scope())
            .unwrap()
            .unwrap()
            .canonical_hash,
        initial.canonical_hash
    );

    let local = chain(&device, 1, 24_292).remove(0);
    receiver
        .commit_outgoing_operation_at(&local.0, &local.1, None, 24_292)
        .unwrap();
    receiver.request_sync_checkpoint(scope()).unwrap();
    provider
        .push_checkpoint(scope(), CHECKPOINT_SCHEMA_VERSION, &lagging)
        .unwrap();
    let current_context = CheckpointBuildContext {
        created_hlc: HybridLogicalClock::new(24_293, 0, device.certificate.device_id),
        ..context
    };
    let report = engine
        .sync_once_with_checkpoint(
            &mut receiver,
            &mut provider,
            &trusted,
            &NoEmbeddings,
            24_293,
            &current_context,
        )
        .unwrap();
    assert!(report.checkpointed);
    let remote = provider
        .pull_checkpoints(scope(), CHECKPOINT_SCHEMA_VERSION, None, 256)
        .unwrap();
    assert_eq!(remote.rows.len(), 3);
    let published = remote.rows[2].checkpoint.clone();
    assert_eq!(
        published.checkpoint.previous_checkpoint_hash,
        lagging.canonical_hash
    );
    assert_eq!(
        receiver
            .sync_checkpoint_pin(scope())
            .unwrap()
            .unwrap()
            .canonical_hash,
        published.canonical_hash
    );
}

#[test]
fn in_memory_checkpoint_log_rejects_a_sibling_extension() {
    let device = device(ID_3, 106);
    let first = signed_checkpoint(
        &device,
        Sha256Digest([0; 32]),
        Sha256Digest([1; 32]),
        24_300,
    );
    let second = signed_checkpoint(&device, first.canonical_hash, Sha256Digest([2; 32]), 24_301);
    let sibling = signed_checkpoint(&device, first.canonical_hash, Sha256Digest([3; 32]), 24_302);
    let mut provider = InMemoryTransport::new();
    provider
        .push_checkpoint(scope(), CHECKPOINT_SCHEMA_VERSION, &first)
        .unwrap();
    provider
        .push_checkpoint(scope(), CHECKPOINT_SCHEMA_VERSION, &second)
        .unwrap();

    assert_eq!(
        provider.push_checkpoint(scope(), CHECKPOINT_SCHEMA_VERSION, &sibling),
        Err(TransportError::Integrity)
    );
}

#[test]
fn concurrent_provider_extension_rejects_due_sibling_and_leaves_pin_unaccepted() {
    let device = device(ID_3, 107);
    let trusted = trust(&device);
    let source_path = TempVault::new("sync-checkpoint-concurrent-source");
    let receiver_path = TempVault::new("sync-checkpoint-concurrent-receiver");
    let source_keys = MemoryKeyStore::default();
    let receiver_keys = MemoryKeyStore::default();
    let source = Vault::open(source_path.path(), CREDENTIAL, &source_keys).unwrap();
    let mut receiver = Vault::open(receiver_path.path(), CREDENTIAL, &receiver_keys).unwrap();
    let context = CheckpointBuildContext {
        scope: scope(),
        creator_device: device.certificate.device_id,
        active_key_epoch: KEY_EPOCH,
        device_keys: &device.keys,
        created_hlc: HybridLogicalClock::new(24_310, 0, device.certificate.device_id),
    };
    let anchor = context_relay_core::sync::build_checkpoint(&source, &context, &trusted).unwrap();
    let concurrent = signed_checkpoint(
        &device,
        anchor.canonical_hash,
        Sha256Digest([8; 32]),
        24_311,
    );
    let local = chain(&device, 1, 24_312).remove(0);
    receiver
        .commit_outgoing_operation_at(&local.0, &local.1, None, 24_312)
        .unwrap();
    receiver.request_sync_checkpoint(scope()).unwrap();
    let mut inner = InMemoryTransport::new();
    inner
        .push_checkpoint(scope(), CHECKPOINT_SCHEMA_VERSION, &anchor)
        .unwrap();
    let mut provider = ConcurrentCheckpointExtensionTransport {
        inner,
        concurrent,
        injected: false,
        accepted_sibling: None,
    };

    assert_eq!(
        SyncEngine::new(scope(), SyncProvider::Memory)
            .sync_once_with_checkpoint(
                &mut receiver,
                &mut provider,
                &trusted,
                &NoEmbeddings,
                24_313,
                &CheckpointBuildContext {
                    created_hlc: HybridLogicalClock::new(24_313, 0, device.certificate.device_id,),
                    ..context
                },
            )
            .unwrap_err()
            .safe_code(),
        "integrity_quarantined"
    );
    assert!(receiver.sync_checkpoint_pin(scope()).unwrap().is_none());
    assert!(
        receiver
            .sync_checkpoint_schedule(scope())
            .unwrap()
            .requested
    );
    let remote = provider
        .inner
        .pull_checkpoints(scope(), CHECKPOINT_SCHEMA_VERSION, None, 256)
        .unwrap();
    assert_eq!(remote.rows.len(), 2);
    assert_eq!(
        remote.rows[1].checkpoint.canonical_hash,
        provider.concurrent.canonical_hash
    );
}

#[test]
fn fresh_checkpoint_rejects_forged_receipt_when_provider_stores_competing_genesis() {
    assert_fresh_checkpoint_forgery_fails_closed_and_recovers(FreshCheckpointForgery::Competing);
}

#[test]
fn fresh_checkpoint_rejects_forged_receipt_when_provider_omits_checkpoint() {
    assert_fresh_checkpoint_forgery_fails_closed_and_recovers(FreshCheckpointForgery::Omitted);
}

fn assert_fresh_checkpoint_forgery_fails_closed_and_recovers(forgery: FreshCheckpointForgery) {
    let device = device(ID_3, 108 + forgery as u8);
    let trusted = trust(&device);
    let (source_name, receiver_name) = match forgery {
        FreshCheckpointForgery::Competing => (
            "sync-checkpoint-forged-competing-source",
            "sync-checkpoint-forged-competing-receiver",
        ),
        FreshCheckpointForgery::Omitted => (
            "sync-checkpoint-forged-omitted-source",
            "sync-checkpoint-forged-omitted-receiver",
        ),
    };
    let source_path = TempVault::new(source_name);
    let receiver_path = TempVault::new(receiver_name);
    let source_keys = MemoryKeyStore::default();
    let receiver_keys = MemoryKeyStore::default();
    let source = Vault::open(source_path.path(), CREDENTIAL, &source_keys).unwrap();
    let mut receiver = Vault::open(receiver_path.path(), CREDENTIAL, &receiver_keys).unwrap();
    let context = CheckpointBuildContext {
        scope: scope(),
        creator_device: device.certificate.device_id,
        active_key_epoch: KEY_EPOCH,
        device_keys: &device.keys,
        created_hlc: HybridLogicalClock::new(24_330, 0, device.certificate.device_id),
    };
    let competing = context_relay_core::sync::build_checkpoint(
        &source,
        &CheckpointBuildContext {
            created_hlc: HybridLogicalClock::new(24_329, 0, device.certificate.device_id),
            ..context
        },
        &trusted,
    )
    .unwrap();
    let local = chain(&device, 1, 24_331).remove(0);
    receiver
        .commit_outgoing_operation_at(&local.0, &local.1, None, 24_331)
        .unwrap();
    receiver.request_sync_checkpoint(scope()).unwrap();
    let mut provider = FreshCheckpointForgeryTransport {
        inner: InMemoryTransport::new(),
        forgery,
        competing,
        forged: false,
    };
    let engine = SyncEngine::new(scope(), SyncProvider::Memory);

    assert_eq!(
        engine
            .sync_once_with_checkpoint(
                &mut receiver,
                &mut provider,
                &trusted,
                &NoEmbeddings,
                24_332,
                &context,
            )
            .unwrap_err()
            .safe_code(),
        "integrity_quarantined"
    );
    assert!(receiver.sync_checkpoint_pin(scope()).unwrap().is_none());
    assert!(
        receiver
            .sync_checkpoint_schedule(scope())
            .unwrap()
            .requested
    );
    let database_key = receiver_keys.key(CREDENTIAL);
    drop(receiver);
    let raw = open_keyed(receiver_path.path(), &database_key);
    assert_eq!(
        raw.query_row("SELECT count(*) FROM signed_sync_checkpoints", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        0
    );
    drop(raw);

    let mut reopened = Vault::open(receiver_path.path(), CREDENTIAL, &receiver_keys).unwrap();
    let report = engine
        .sync_once_with_checkpoint(
            &mut reopened,
            &mut provider,
            &trusted,
            &NoEmbeddings,
            24_333,
            &CheckpointBuildContext {
                created_hlc: HybridLogicalClock::new(24_333, 0, device.certificate.device_id),
                ..context
            },
        )
        .unwrap();
    assert!(report.checkpointed);
    assert!(reopened.sync_checkpoint_pin(scope()).unwrap().is_some());
    assert!(
        !reopened
            .sync_checkpoint_schedule(scope())
            .unwrap()
            .requested
    );
}

#[test]
fn checkpoint_transport_version_selection_is_explicit() {
    let mut provider = InMemoryTransport::new();
    let checkpoint = canonical_checkpoint(9, 24_320);
    assert_eq!(CHECKPOINT_SCHEMA_VERSION, 2);
    assert_eq!(
        provider.push_checkpoint(scope(), 1, &checkpoint),
        Err(TransportError::CheckpointVersionUnsupported)
    );
    assert_eq!(
        provider.pull_checkpoints(scope(), 1, None, 256),
        Err(TransportError::CheckpointVersionUnsupported)
    );
    assert_eq!(
        provider.checkpoint_by_hash(scope(), 1, checkpoint.canonical_hash),
        Err(TransportError::CheckpointVersionUnsupported)
    );
}

#[test]
fn schema_17_retires_unbound_checkpoints_and_requests_a_fresh_scoped_pin() {
    let device = device(ID_3, 101);
    let trusted = trust(&device);
    let path = TempVault::new("sync-checkpoint-migration-schema-17");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let operation = chain(&device, 1, 24_260).remove(0);
    vault
        .commit_outgoing_operation_at(&operation.0, &operation.1, None, 24_260)
        .unwrap();
    let frontier_before = vault.sync_checkpoint_frontier(scope()).unwrap();
    let state_before = vault.sync_state_summary(scope()).unwrap();
    let database_key = keys.key(CREDENTIAL);
    drop(vault);

    let legacy_payload = decode_hex(include_str!("fixtures/checkpoint-schema17-v1.hex"));
    let legacy_hash = Sha256Digest(Sha256::digest(&legacy_payload).into());
    let raw = open_keyed(path.path(), &database_key);
    raw.execute_batch("DROP TABLE sync_checkpoint_scans;")
        .unwrap();
    raw.execute(
        "INSERT INTO signed_sync_checkpoints(
             account_id, workspace_id, canonical_sha256, state_hash,
             canonical_payload, accepted_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, 500)",
        params![
            scope().account_id.to_string(),
            scope().workspace_id.to_string(),
            legacy_hash.0.as_slice(),
            [10_u8; 32].as_slice(),
            legacy_payload,
        ],
    )
    .unwrap();
    raw.execute(
        "INSERT INTO sync_checkpoint_pins(account_id, workspace_id, canonical_sha256)
         VALUES (?1, ?2, ?3)",
        params![
            scope().account_id.to_string(),
            scope().workspace_id.to_string(),
            legacy_hash.0.as_slice(),
        ],
    )
    .unwrap();
    raw.execute(
        "UPDATE sync_checkpoint_schedule
         SET applied_operations = 0, first_uncheckpointed_ms = NULL,
             last_checkpoint_ms = 500, requested = 0
         WHERE account_id = ?1 AND workspace_id = ?2",
        params![
            scope().account_id.to_string(),
            scope().workspace_id.to_string(),
        ],
    )
    .unwrap();
    raw.execute_batch(
        "DROP TABLE recovery_restores;
         DROP TABLE recovery_enrollments;
         DROP TABLE pairing_approval_transcripts;
         DROP TABLE pairing_joins;
         DROP TABLE pairing_decisions;
         DROP TABLE device_certificates;
         DROP TABLE sync_record_owners;",
    )
    .unwrap();
    raw.pragma_update(None, "user_version", 17).unwrap();
    drop(raw);

    let mut migrated = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(migrated.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
    assert!(migrated.sync_checkpoint_pin(scope()).unwrap().is_none());
    assert_eq!(
        migrated.sync_checkpoint_frontier(scope()).unwrap(),
        frontier_before
    );
    assert_eq!(migrated.sync_state_summary(scope()).unwrap(), state_before);
    assert!(
        migrated
            .sync_checkpoint_schedule(scope())
            .unwrap()
            .requested
    );

    let fresh = context_relay_core::sync::build_checkpoint(
        &migrated,
        &CheckpointBuildContext {
            scope: scope(),
            creator_device: device.certificate.device_id,
            active_key_epoch: KEY_EPOCH,
            device_keys: &device.keys,
            created_hlc: HybridLogicalClock::new(24_261, 0, device.certificate.device_id),
        },
        &trusted,
    )
    .unwrap();
    assert_eq!(fresh.checkpoint.account_id, scope().account_id);
    assert_eq!(fresh.checkpoint.workspace_id, scope().workspace_id);
    let verified =
        context_relay_core::sync::verify_checkpoint(&migrated, scope(), &fresh, &trusted).unwrap();
    migrated.accept_sync_checkpoint(&verified, 24_261).unwrap();
    assert_eq!(
        migrated
            .sync_checkpoint_pin(scope())
            .unwrap()
            .unwrap()
            .canonical_hash,
        fresh.canonical_hash
    );

    drop(migrated);
    let raw = open_keyed(path.path(), &database_key);
    assert_eq!(
        raw.query_row("SELECT count(*) FROM signed_sync_checkpoints", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        1
    );
}

#[test]
fn endpoint_pin_rolls_back_with_scan_rebase_and_resumes_after_reopen() {
    let device = device(ID_3, 102);
    let trusted = trust(&device);
    let source_path = TempVault::new("sync-checkpoint-atomic-source");
    let receiver_path = TempVault::new("sync-checkpoint-atomic-receiver");
    let source_keys = MemoryKeyStore::default();
    let receiver_keys = MemoryKeyStore::default();
    let source = Vault::open(source_path.path(), CREDENTIAL, &source_keys).unwrap();
    let checkpoint_context = CheckpointBuildContext {
        scope: scope(),
        creator_device: device.certificate.device_id,
        active_key_epoch: KEY_EPOCH,
        device_keys: &device.keys,
        created_hlc: HybridLogicalClock::new(24_270, 0, device.certificate.device_id),
    };
    let endpoint =
        context_relay_core::sync::build_checkpoint(&source, &checkpoint_context, &trusted).unwrap();
    let mut provider = InMemoryTransport::new();
    provider
        .push_checkpoint(scope(), CHECKPOINT_SCHEMA_VERSION, &endpoint)
        .unwrap();

    drop(Vault::open(receiver_path.path(), CREDENTIAL, &receiver_keys).unwrap());
    let database_key = receiver_keys.key(CREDENTIAL);
    let raw = open_keyed(receiver_path.path(), &database_key);
    raw.execute_batch(
        "CREATE TRIGGER fail_checkpoint_scan_rebase
         BEFORE UPDATE OF base_pin_sha256 ON sync_checkpoint_scans
         BEGIN
             SELECT RAISE(ABORT, 'checkpoint scan rebase failpoint');
         END;",
    )
    .unwrap();
    drop(raw);

    let mut receiver = Vault::open(receiver_path.path(), CREDENTIAL, &receiver_keys).unwrap();
    assert_eq!(
        SyncEngine::new(scope(), SyncProvider::Memory)
            .sync_once_with_checkpoint(
                &mut receiver,
                &mut provider,
                &trusted,
                &NoEmbeddings,
                24_271,
                &checkpoint_context,
            )
            .unwrap_err()
            .safe_code(),
        "transient"
    );
    drop(receiver);

    let raw = open_keyed(receiver_path.path(), &database_key);
    assert_eq!(
        raw.query_row("SELECT count(*) FROM sync_checkpoint_pins", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        0
    );
    assert_eq!(
        raw.query_row("SELECT count(*) FROM signed_sync_checkpoints", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        0
    );
    assert_eq!(
        raw.query_row("SELECT count(*) FROM sync_checkpoint_scans", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        1
    );
    raw.execute_batch("DROP TRIGGER fail_checkpoint_scan_rebase;")
        .unwrap();
    drop(raw);

    let mut reopened = Vault::open(receiver_path.path(), CREDENTIAL, &receiver_keys).unwrap();
    let resumed = SyncEngine::new(scope(), SyncProvider::Memory)
        .sync_once_with_checkpoint(
            &mut reopened,
            &mut provider,
            &trusted,
            &NoEmbeddings,
            24_272,
            &checkpoint_context,
        )
        .unwrap();
    assert!(resumed.checkpointed);
    assert_eq!(
        reopened
            .sync_checkpoint_pin(scope())
            .unwrap()
            .unwrap()
            .canonical_hash,
        endpoint.canonical_hash
    );
}

#[test]
fn checkpoint_provider_rejects_forks_and_engine_rejects_tampered_resume_anchors() {
    let device = device(ID_3, 99);
    let trust = trust(&device);
    let sender_path = TempVault::new("sync-engine-checkpoint-fork-source");
    let sender_keys = MemoryKeyStore::default();
    let sender = Vault::open(sender_path.path(), CREDENTIAL, &sender_keys).unwrap();
    let context = CheckpointBuildContext {
        scope: scope(),
        creator_device: device.certificate.device_id,
        active_key_epoch: KEY_EPOCH,
        device_keys: &device.keys,
        created_hlc: HybridLogicalClock::new(24_300, 0, device.certificate.device_id),
    };
    let local_state =
        context_relay_core::sync::build_checkpoint(&sender, &context, &trust).unwrap();

    let first = signed_checkpoint(
        &device,
        Sha256Digest([0; 32]),
        Sha256Digest([3; 32]),
        24_301,
    );
    let forked = signed_checkpoint(
        &device,
        Sha256Digest([9; 32]),
        local_state.state_hash,
        24_302,
    );
    let mut fork_provider = InMemoryTransport::new();
    fork_provider
        .push_checkpoint(scope(), CHECKPOINT_SCHEMA_VERSION, &first)
        .unwrap();
    assert_eq!(
        fork_provider.push_checkpoint(scope(), CHECKPOINT_SCHEMA_VERSION, &forked),
        Err(TransportError::Integrity)
    );

    let second = signed_checkpoint(
        &device,
        first.canonical_hash,
        local_state.state_hash,
        24_303,
    );
    let anchor_path = TempVault::new("sync-engine-checkpoint-anchor-receiver");
    let anchor_keys = MemoryKeyStore::default();
    let mut anchor_receiver = Vault::open(anchor_path.path(), CREDENTIAL, &anchor_keys).unwrap();
    let mut anchor_provider = CheckpointCursorTamperTransport(InMemoryTransport::new());
    anchor_provider
        .0
        .push_checkpoint(scope(), CHECKPOINT_SCHEMA_VERSION, &first)
        .unwrap();
    anchor_provider
        .0
        .push_checkpoint(scope(), CHECKPOINT_SCHEMA_VERSION, &second)
        .unwrap();
    let engine = SyncEngine::new(scope(), SyncProvider::Memory).with_max_operations(1);
    assert!(
        engine
            .sync_once_with_checkpoint(
                &mut anchor_receiver,
                &mut anchor_provider,
                &trust,
                &NoEmbeddings,
                24_401,
                &context,
            )
            .unwrap()
            .more_work
    );
    assert_eq!(
        engine
            .sync_once_with_checkpoint(
                &mut anchor_receiver,
                &mut anchor_provider,
                &trust,
                &NoEmbeddings,
                24_402,
                &context,
            )
            .unwrap_err()
            .safe_code(),
        "integrity_quarantined"
    );
}

#[test]
fn transient_push_retains_durable_outbox_and_exact_retry_acknowledges_it() {
    let device = device(ID_3, 34);
    let trust = trust(&device);
    let operations = chain(&device, 1, 3_000);
    let path = TempVault::new("sync-engine-retry");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault
        .commit_outgoing_operation(&operations[0].0, &operations[0].1, None)
        .unwrap();
    let mut provider = InMemoryTransport::with_faults(FaultSchedule::transient_push(1));
    let engine =
        SyncEngine::new(scope(), SyncProvider::Memory).with_retry_random_source(AttemptBoundRandom);

    let failure = engine
        .sync_once(&mut vault, &mut provider, &trust, &NoEmbeddings, 0)
        .unwrap_err();
    assert_eq!(failure.safe_code(), "transient");
    assert!(vault.due_outbox(999, 256).unwrap().is_empty());
    drop(vault);

    let mut reopened = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let report = engine
        .sync_once(&mut reopened, &mut provider, &trust, &NoEmbeddings, 1_000)
        .unwrap();
    assert_eq!(report.pushed, 1);
    assert!(reopened.due_outbox(1_000, 256).unwrap().is_empty());
    let duplicate = provider
        .push_operations(scope(), &[canonical(&operations[0].1)])
        .unwrap();
    assert_eq!(
        duplicate.duplicates,
        vec![operations[0].1.operation.operation_id]
    );
}

#[test]
fn permanent_outbox_blocks_resume_only_after_matching_explicit_state_change() {
    let device = device(ID_3, 98);
    let operations = chain(&device, 3, 24_500);
    let path = TempVault::new("sync-outbox-explicit-unblock");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    for (mutation, operation) in &operations {
        vault
            .commit_outgoing_operation_at(mutation, operation, None, 100)
            .unwrap();
    }
    let auth_id = operations[0].1.operation.operation_id;
    let quota_id = operations[1].1.operation.operation_id;
    let integrity_id = operations[2].1.operation.operation_id;
    vault
        .defer_outbox(&[auth_id], i64::MAX as u64, "auth_required")
        .unwrap();
    vault
        .defer_outbox(&[quota_id], i64::MAX as u64, "quota_blocked")
        .unwrap();
    vault
        .defer_outbox(&[integrity_id], i64::MAX as u64, "integrity_quarantined")
        .unwrap();
    assert!(vault.due_outbox(i64::MAX as u64, 256).unwrap().is_empty());

    assert_eq!(
        vault
            .unblock_outbox_after_state_change(
                &[auth_id, quota_id],
                OutboxUnblockReason::AuthenticationChanged,
                1_000,
            )
            .unwrap(),
        1
    );
    let due = vault.due_outbox(1_000, 256).unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].operation_id, auth_id);
    assert_eq!(due[0].attempt_count, 1);

    assert!(
        vault
            .unblock_outbox_after_state_change(
                &[integrity_id],
                OutboxUnblockReason::ConfigurationChanged,
                1_001,
            )
            .is_err()
    );
    assert_eq!(
        vault
            .unblock_outbox_after_state_change(
                &[quota_id],
                OutboxUnblockReason::QuotaChanged,
                1_002,
            )
            .unwrap(),
        1
    );
    let due = vault.due_outbox(1_002, 256).unwrap();
    assert_eq!(
        due.iter()
            .map(|row| (row.operation_id, row.attempt_count))
            .collect::<Vec<_>>(),
        vec![(auth_id, 1), (quota_id, 1)]
    );
    assert!(!due.iter().any(|row| row.operation_id == integrity_id));
}

#[test]
fn crash_after_provider_acceptance_replays_as_exact_duplicate_and_clears_outbox() {
    let device = device(ID_3, 42);
    let trust = trust(&device);
    let operations = chain(&device, 1, 11_000);
    let path = TempVault::new("sync-engine-accepted-before-ack-crash");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault
        .commit_outgoing_operation(&operations[0].0, &operations[0].1, None)
        .unwrap();
    let mut provider = InMemoryTransport::new();
    provider
        .push_operations(scope(), &[canonical(&operations[0].1)])
        .unwrap();
    drop(vault);

    let mut reopened = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let report = SyncEngine::new(scope(), SyncProvider::Memory)
        .sync_once(&mut reopened, &mut provider, &trust, &NoEmbeddings, 0)
        .unwrap();
    assert_eq!(report.pushed, 0);
    assert_eq!(report.duplicates, 1);
    assert!(reopened.due_outbox(0, 256).unwrap().is_empty());
}

#[test]
fn push_uses_oldest_prefix_fitting_eight_mib_and_leaves_remainder_due() {
    const REQUEST_BYTES: usize = 8 * 1024 * 1024;
    let device = device(ID_3, 43);
    let trust = trust(&device);
    let operations = large_chain(&device, 2, 12_000);
    let canonical = operations
        .iter()
        .map(|(_, built)| canonical(built))
        .collect::<Vec<_>>();
    assert!(
        canonical
            .iter()
            .all(|operation| operation.bytes.len() < REQUEST_BYTES)
    );
    assert!(
        canonical
            .iter()
            .map(|operation| operation.bytes.len())
            .sum::<usize>()
            > REQUEST_BYTES
    );
    let mut direct = InMemoryTransport::new();
    assert_eq!(
        direct.push_operations(scope(), &canonical),
        Err(TransportError::Configuration)
    );

    let path = TempVault::new("sync-engine-eight-mib-prefix");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    for (mutation, built) in &operations {
        vault
            .commit_outgoing_operation(mutation, built, None)
            .unwrap();
    }
    let mut provider = InMemoryTransport::with_faults(FaultSchedule::drop_pull(1));
    let engine = SyncEngine::new(scope(), SyncProvider::Memory);

    let first = engine
        .sync_once(&mut vault, &mut provider, &trust, &NoEmbeddings, 0)
        .unwrap();
    assert_eq!(first.pushed, 1);
    assert!(first.more_work);
    assert_eq!(vault.due_outbox(0, 256).unwrap().len(), 1);
    assert_eq!(
        provider.pull_operations(scope(), None, 1).unwrap().rows[0]
            .operation
            .operation_id,
        operations[0].1.operation.operation_id
    );

    provider.schedule_faults(FaultSchedule::drop_pull(1));
    let second = engine
        .sync_once(&mut vault, &mut provider, &trust, &NoEmbeddings, 0)
        .unwrap();
    assert_eq!(second.pushed, 1);
    assert!(vault.due_outbox(0, 256).unwrap().is_empty());
}

#[test]
fn large_gap_prefix_commits_before_blocker_budget_and_resumes_after_reopen() {
    let device = device(ID_3, 46);
    let trust = trust(&device);
    let operations = large_chain(&device, 2, 15_000);
    let mut provider = InMemoryTransport::new();
    provider
        .push_operations(scope(), &[canonical(&operations[1].1)])
        .unwrap();
    provider
        .push_operations(scope(), &[canonical(&operations[0].1)])
        .unwrap();
    let path = TempVault::new("sync-engine-large-gap-budget");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();

    let first = SyncEngine::new(scope(), SyncProvider::Memory)
        .sync_once(&mut vault, &mut provider, &trust, &NoEmbeddings, 0)
        .unwrap();
    assert!(first.more_work);
    assert_eq!(first.gaps_repaired, 1);
    assert_eq!(
        vault
            .device_head(id(ID_2), id(ID_3))
            .unwrap()
            .unwrap()
            .sequence,
        1
    );
    assert!(vault.sync_cursor(id(ID_2), "memory").unwrap().is_none());
    drop(vault);

    let mut reopened = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let resumed = SyncEngine::new(scope(), SyncProvider::Memory)
        .sync_once(&mut reopened, &mut provider, &trust, &NoEmbeddings, 0)
        .unwrap();
    assert_eq!(resumed.applied, 1);
    assert_eq!(
        reopened
            .device_head(id(ID_2), id(ID_3))
            .unwrap()
            .unwrap()
            .sequence,
        2
    );
}

#[test]
fn durable_pull_survives_lost_hint_drop_reverse_and_exact_replay() {
    let device = device(ID_3, 35);
    let trust = trust(&device);
    let operations = chain(&device, 2, 4_000);
    let sender_path = TempVault::new("sync-engine-sender");
    let receiver_path = TempVault::new("sync-engine-receiver");
    let sender_keys = MemoryKeyStore::default();
    let receiver_keys = MemoryKeyStore::default();
    let mut sender = Vault::open(sender_path.path(), CREDENTIAL, &sender_keys).unwrap();
    let mut receiver = Vault::open(receiver_path.path(), CREDENTIAL, &receiver_keys).unwrap();
    for (mutation, built) in &operations {
        sender
            .commit_outgoing_operation(mutation, built, None)
            .unwrap();
    }
    let mut provider = InMemoryTransport::new();
    let engine = SyncEngine::new(scope(), SyncProvider::Memory);
    engine
        .sync_once(&mut sender, &mut provider, &trust, &NoEmbeddings, 0)
        .unwrap();
    provider.schedule_faults(
        FaultSchedule::drop_pull(1)
            .with_reversed_pulls(1)
            .with_lost_hints(1),
    );
    assert!(!provider.take_change_hint(scope()));

    let dropped = engine
        .sync_once(&mut receiver, &mut provider, &trust, &NoEmbeddings, 0)
        .unwrap();
    assert_eq!(dropped.pulled, 0);
    assert!(receiver.sync_cursor(id(ID_2), "memory").unwrap().is_none());
    let applied = engine
        .sync_once(&mut receiver, &mut provider, &trust, &NoEmbeddings, 0)
        .unwrap();
    assert_eq!(applied.applied, 2);
    assert_eq!(
        receiver
            .device_head(id(ID_2), id(ID_3))
            .unwrap()
            .unwrap()
            .sequence,
        2
    );

    let replay = engine
        .sync_once(&mut sender, &mut provider, &trust, &NoEmbeddings, 0)
        .unwrap();
    assert_eq!(replay.applied, 0);
    assert!(sender.sync_cursor(id(ID_2), "memory").unwrap().is_some());
}

#[test]
fn duplicate_delay_and_reverse_faults_converge_to_the_clean_head_set() {
    let device = device(ID_3, 40);
    let trust = trust(&device);
    let operations = chain(&device, 2, 9_000);
    let canonical = operations
        .iter()
        .map(|(_, built)| canonical(built))
        .collect::<Vec<_>>();
    let mut clean_transport = InMemoryTransport::new();
    let mut faulty_transport = InMemoryTransport::with_faults(
        FaultSchedule::default()
            .with_delayed_pulls(1)
            .with_duplicated_pulls(1)
            .with_reversed_pulls(1),
    );
    clean_transport
        .push_operations(scope(), &canonical)
        .unwrap();
    faulty_transport
        .push_operations(scope(), &canonical)
        .unwrap();
    let clean_path = TempVault::new("sync-engine-clean-convergence");
    let faulty_path = TempVault::new("sync-engine-fault-convergence");
    let clean_keys = MemoryKeyStore::default();
    let faulty_keys = MemoryKeyStore::default();
    let mut clean = Vault::open(clean_path.path(), CREDENTIAL, &clean_keys).unwrap();
    let mut faulty = Vault::open(faulty_path.path(), CREDENTIAL, &faulty_keys).unwrap();
    let engine = SyncEngine::new(scope(), SyncProvider::Memory);

    engine
        .sync_once(&mut clean, &mut clean_transport, &trust, &NoEmbeddings, 0)
        .unwrap();
    for _ in 0..3 {
        engine
            .sync_once(&mut faulty, &mut faulty_transport, &trust, &NoEmbeddings, 0)
            .unwrap();
    }

    assert_eq!(
        clean
            .record_heads(id(ID_2), operations[0].0.record_id())
            .unwrap(),
        faulty
            .record_heads(id(ID_2), operations[0].0.record_id())
            .unwrap()
    );
    assert_eq!(
        clean
            .secret_ref(&id::<SecretRefId>("018f22e2-79b0-7cc8-98c4-dc0c0c073986"))
            .unwrap(),
        faulty
            .secret_ref(&id::<SecretRefId>("018f22e2-79b0-7cc8-98c4-dc0c0c073986"))
            .unwrap()
    );
}

#[test]
fn provider_namespaces_keep_independent_durable_cursor_histories() {
    let device = device(ID_3, 47);
    let trust = trust(&device);
    let operations = chain(&device, 2, 16_000);
    let mut provider = InMemoryTransport::new();
    provider
        .push_operations(scope(), &[canonical(&operations[0].1)])
        .unwrap();
    let path = TempVault::new("sync-engine-provider-cursors");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let memory = SyncEngine::new(scope(), SyncProvider::Memory);
    let supabase = SyncEngine::new(scope(), SyncProvider::Supabase);

    memory
        .sync_once(&mut vault, &mut provider, &trust, &NoEmbeddings, 0)
        .unwrap();
    let memory_first = vault.sync_cursor(id(ID_2), "memory").unwrap().unwrap();
    assert_eq!(
        memory_first.operation_id,
        operations[0].1.operation.operation_id
    );
    provider
        .push_operations(scope(), &[canonical(&operations[1].1)])
        .unwrap();

    supabase
        .sync_once(&mut vault, &mut provider, &trust, &NoEmbeddings, 0)
        .unwrap();
    let supabase_cursor = vault.sync_cursor(id(ID_2), "supabase").unwrap().unwrap();
    assert_eq!(
        supabase_cursor.operation_id,
        operations[1].1.operation.operation_id
    );
    assert_eq!(
        vault.sync_cursor(id(ID_2), "memory").unwrap().unwrap(),
        memory_first
    );

    memory
        .sync_once(&mut vault, &mut provider, &trust, &NoEmbeddings, 0)
        .unwrap();
    assert_eq!(
        vault
            .sync_cursor(id(ID_2), "memory")
            .unwrap()
            .unwrap()
            .operation_id,
        operations[1].1.operation.operation_id
    );
}

#[test]
fn a_gap_is_repaired_in_device_sequence_before_the_blocking_row() {
    let device = device(ID_3, 36);
    let trust = trust(&device);
    let operations = chain(&device, 2, 5_000);
    let mut provider = InMemoryTransport::new();
    provider
        .push_operations(scope(), &[canonical(&operations[1].1)])
        .unwrap();
    provider
        .push_operations(scope(), &[canonical(&operations[0].1)])
        .unwrap();
    let path = TempVault::new("sync-engine-gap");
    let keys = MemoryKeyStore::default();
    let mut receiver = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();

    let report = SyncEngine::new(scope(), SyncProvider::Memory)
        .sync_once(&mut receiver, &mut provider, &trust, &NoEmbeddings, 0)
        .unwrap();
    assert_eq!(report.gaps_repaired, 1);
    assert_eq!(report.applied, 2);
    assert_eq!(
        receiver
            .device_head(id(ID_2), id(ID_3))
            .unwrap()
            .unwrap()
            .sequence,
        2
    );
}

#[test]
fn gap_repair_chunks_more_than_256_rows_without_skipping_sequence() {
    let device = device(ID_3, 48);
    let trust = trust(&device);
    let operations = chain(&device, 258, 17_000);
    let canonical = operations
        .iter()
        .map(|(_, built)| canonical(built))
        .collect::<Vec<_>>();
    let mut provider = InMemoryTransport::new();
    provider
        .push_operations(scope(), &canonical[257..])
        .unwrap();
    provider
        .push_operations(scope(), &canonical[..256])
        .unwrap();
    provider
        .push_operations(scope(), &canonical[256..257])
        .unwrap();
    let path = TempVault::new("sync-engine-gap-257");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();

    let report = SyncEngine::new(scope(), SyncProvider::Memory)
        .sync_once(&mut vault, &mut provider, &trust, &NoEmbeddings, 0)
        .unwrap();
    assert_eq!(report.gaps_repaired, 257);
    assert_eq!(
        vault
            .device_head(id(ID_2), id(ID_3))
            .unwrap()
            .unwrap()
            .sequence,
        258
    );
}

#[test]
fn missing_or_duplicate_range_rows_commit_nothing() {
    let device = device(ID_3, 49);
    let trust = trust(&device);
    let operations = chain(&device, 3, 18_000);
    for shape in [RangeShape::Missing, RangeShape::Duplicate] {
        let mut inner = InMemoryTransport::new();
        inner
            .push_operations(scope(), &[canonical(&operations[2].1)])
            .unwrap();
        inner
            .push_operations(
                scope(),
                &[canonical(&operations[0].1), canonical(&operations[1].1)],
            )
            .unwrap();
        let mut provider = RangeShapeTransport { inner, shape };
        let path = TempVault::new(&format!("sync-engine-range-{shape:?}"));
        let keys = MemoryKeyStore::default();
        let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();

        let report = SyncEngine::new(scope(), SyncProvider::Memory)
            .sync_once(&mut vault, &mut provider, &trust, &NoEmbeddings, 0)
            .unwrap();
        assert!(report.more_work, "{shape:?}");
        assert!(vault.device_head(id(ID_2), id(ID_3)).unwrap().is_none());
        assert!(vault.sync_cursor(id(ID_2), "memory").unwrap().is_none());
    }
}

#[test]
fn crash_after_gap_repair_cannot_advance_past_the_blocking_row() {
    let device = device(ID_3, 37);
    let trust = trust(&device);
    let operations = chain(&device, 2, 6_000);
    let mut provider = InMemoryTransport::new();
    provider
        .push_operations(scope(), &[canonical(&operations[1].1)])
        .unwrap();
    provider
        .push_operations(scope(), &[canonical(&operations[0].1)])
        .unwrap();
    let path = TempVault::new("sync-engine-gap-crash");
    let keys = MemoryKeyStore::default();
    let mut receiver = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();

    let interrupted = SyncEngine::new(scope(), SyncProvider::Memory)
        .with_max_operations(1)
        .sync_once(&mut receiver, &mut provider, &trust, &NoEmbeddings, 0)
        .unwrap();
    assert!(interrupted.more_work);
    assert_eq!(
        receiver
            .device_head(id(ID_2), id(ID_3))
            .unwrap()
            .unwrap()
            .sequence,
        1
    );
    assert!(receiver.sync_cursor(id(ID_2), "memory").unwrap().is_none());
    drop(receiver);

    let mut reopened = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let resumed = SyncEngine::new(scope(), SyncProvider::Memory)
        .sync_once(&mut reopened, &mut provider, &trust, &NoEmbeddings, 0)
        .unwrap();
    assert_eq!(resumed.applied, 1);
    assert_eq!(
        reopened
            .device_head(id(ID_2), id(ID_3))
            .unwrap()
            .unwrap()
            .sequence,
        2
    );
}

#[test]
fn every_malformed_push_receipt_shape_retains_every_outbox_row() {
    let device = device(ID_3, 38);
    let trust = trust(&device);
    let operations = chain(&device, 1, 7_000);
    for kind in [
        BadReceiptKind::Omission,
        BadReceiptKind::Extra,
        BadReceiptKind::DuplicateAccepted,
        BadReceiptKind::DuplicateDuplicate,
        BadReceiptKind::Overlap,
    ] {
        let path = TempVault::new(&format!("sync-engine-bad-receipt-{kind:?}"));
        let keys = MemoryKeyStore::default();
        let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
        vault
            .commit_outgoing_operation(&operations[0].0, &operations[0].1, None)
            .unwrap();
        let mut transport = BadReceiptTransport {
            inner: InMemoryTransport::new(),
            kind,
        };

        let error = SyncEngine::new(scope(), SyncProvider::Memory)
            .sync_once(&mut vault, &mut transport, &trust, &NoEmbeddings, 0)
            .unwrap_err();
        assert_eq!(error.safe_code(), "configuration_error", "{kind:?}");
        assert_eq!(vault.outbox_operations().unwrap().len(), 1, "{kind:?}");
    }
}

#[test]
fn invalid_pulled_ciphertext_is_durably_quarantined_and_advances_only_the_cursor() {
    let device = device(ID_3, 39);
    let trust = trust(&device);
    let operations = chain(&device, 1, 8_000);
    let mut inner = InMemoryTransport::new();
    inner
        .push_operations(scope(), &[canonical(&operations[0].1)])
        .unwrap();
    let receipt = inner
        .pull_operations(scope(), None, 1)
        .unwrap()
        .rows
        .remove(0);
    let mut expected_envelope = receipt.operation.bytes.clone();
    expected_envelope[0] ^= 1;
    let mut transport = CorruptPullTransport(inner);
    let path = TempVault::new("sync-engine-quarantine");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();

    let report = SyncEngine::new(scope(), SyncProvider::Memory)
        .sync_once(&mut vault, &mut transport, &trust, &NoEmbeddings, 0)
        .unwrap();
    assert_eq!(report.quarantined, 1);
    assert_eq!(
        vault.sync_cursor(id(ID_2), "memory").unwrap().unwrap(),
        receipt.cursor
    );
    assert!(vault.device_head(id(ID_2), id(ID_3)).unwrap().is_none());
    let stored = vault
        .quarantined_sync_receipt(
            id(ID_1),
            id(ID_2),
            "memory",
            &receipt.cursor.received_at,
            receipt.cursor.operation_id,
        )
        .unwrap()
        .unwrap();
    assert_eq!(stored.envelope, expected_envelope);
    assert_eq!(stored.safe_error_code, "integrity_quarantined");
    drop(vault);

    let reopened = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(
        reopened
            .quarantined_sync_receipt(
                id(ID_1),
                id(ID_2),
                "memory",
                &receipt.cursor.received_at,
                receipt.cursor.operation_id,
            )
            .unwrap()
            .unwrap()
            .envelope,
        expected_envelope
    );
}

#[test]
fn oversized_pulled_row_is_rejected_once_and_cannot_livelock_the_cursor() {
    let device = device(ID_3, 48);
    let trust = trust(&device);
    let operations = chain(&device, 1, 15_200);
    let mut inner = InMemoryTransport::new();
    inner
        .push_operations(scope(), &[canonical(&operations[0].1)])
        .unwrap();
    let receipt = inner
        .pull_operations(scope(), None, 1)
        .unwrap()
        .rows
        .remove(0);
    let mut transport = OversizedPullTransport(inner);
    let path = TempVault::new("sync-engine-oversized-pull");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let engine = SyncEngine::new(scope(), SyncProvider::Memory);

    let report = engine
        .sync_once(&mut vault, &mut transport, &trust, &NoEmbeddings, 0)
        .unwrap();
    assert_eq!(report.quarantined, 1);
    assert_eq!(
        vault.sync_cursor(id(ID_2), "memory").unwrap().unwrap(),
        receipt.cursor
    );
    assert!(vault.device_head(id(ID_2), id(ID_3)).unwrap().is_none());
    let rejection = vault
        .rejected_sync_receipt(
            id(ID_1),
            id(ID_2),
            "memory",
            &receipt.cursor.received_at,
            receipt.cursor.operation_id,
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        rejection.claimed_byte_length,
        (MAX_CBOR_OPERATION_BYTES + 1) as u64
    );
    assert_eq!(
        rejection.received_sha256,
        Sha256Digest(Sha256::digest(vec![0; MAX_CBOR_OPERATION_BYTES + 1]).into())
    );
    assert_eq!(rejection.safe_error_code, "integrity_quarantined");
    assert!(
        vault
            .quarantined_sync_receipt(
                id(ID_1),
                id(ID_2),
                "memory",
                &receipt.cursor.received_at,
                receipt.cursor.operation_id,
            )
            .unwrap()
            .is_none()
    );
    drop(vault);

    let mut reopened = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(
        reopened
            .rejected_sync_receipt(
                id(ID_1),
                id(ID_2),
                "memory",
                &receipt.cursor.received_at,
                receipt.cursor.operation_id,
            )
            .unwrap()
            .unwrap(),
        rejection
    );
    let idle = engine
        .sync_once(&mut reopened, &mut transport, &trust, &NoEmbeddings, 1)
        .unwrap();
    assert_eq!(idle.pulled, 0);
}

#[test]
fn oversized_range_row_is_durably_rejected_before_the_blocker_cursor_advances() {
    let device = device(ID_3, 49);
    let trust = trust(&device);
    let operations = chain(&device, 2, 15_300);
    let mut inner = InMemoryTransport::new();
    inner
        .push_operations(scope(), &[canonical(&operations[1].1)])
        .unwrap();
    inner
        .push_operations(scope(), &[canonical(&operations[0].1)])
        .unwrap();
    let rows = inner.pull_operations(scope(), None, 2).unwrap().rows;
    let blocker = rows
        .iter()
        .find(|row| row.operation.operation_id == operations[1].1.operation.operation_id)
        .unwrap()
        .clone();
    let missing = rows
        .iter()
        .find(|row| row.operation.operation_id == operations[0].1.operation.operation_id)
        .unwrap()
        .clone();
    let mut transport = OversizedRangeTransport {
        inner,
        operation_id: missing.operation.operation_id,
    };
    let path = TempVault::new("sync-engine-oversized-range");
    let keys = MemoryKeyStore::default();
    let engine = SyncEngine::new(scope(), SyncProvider::Memory);
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();

    let report = engine
        .sync_once(&mut vault, &mut transport, &trust, &NoEmbeddings, 55)
        .unwrap();
    assert!(report.quarantined >= 2);
    assert!(vault.device_head(id(ID_2), id(ID_3)).unwrap().is_none());
    assert_eq!(
        vault.sync_cursor(id(ID_2), "memory").unwrap().unwrap(),
        blocker.cursor
    );
    let rejection = vault
        .rejected_sync_receipt(
            id(ID_1),
            id(ID_2),
            "memory",
            &missing.cursor.received_at,
            missing.cursor.operation_id,
        )
        .unwrap()
        .unwrap();
    assert_eq!(
        rejection.claimed_byte_length,
        (MAX_CBOR_OPERATION_BYTES + 1) as u64
    );
    assert_eq!(rejection.safe_error_code, "integrity_quarantined");
    assert_eq!(rejection.rejected_at_ms, 55);
    assert_eq!(
        vault
            .quarantined_sync_receipt(
                id(ID_1),
                id(ID_2),
                "memory",
                &blocker.cursor.received_at,
                blocker.cursor.operation_id,
            )
            .unwrap()
            .unwrap()
            .safe_error_code,
        "gap_pending"
    );
    drop(vault);

    let mut reopened = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(
        reopened
            .rejected_sync_receipt(
                id(ID_1),
                id(ID_2),
                "memory",
                &missing.cursor.received_at,
                missing.cursor.operation_id,
            )
            .unwrap()
            .unwrap(),
        rejection
    );
    let idle = engine
        .sync_once(&mut reopened, &mut transport, &trust, &NoEmbeddings, 56)
        .unwrap();
    assert_eq!(idle.pulled, 0);
    assert!(reopened.device_head(id(ID_2), id(ID_3)).unwrap().is_none());
}

#[test]
fn quarantined_device_stays_blocked_while_an_unrelated_device_converges_across_reopen() {
    let broken = device(ID_3, 46);
    let healthy = device("018f22e2-79b0-7cc8-98c4-dc0c0c073984", 47);
    let broken_operations = chain(&broken, 3, 15_000);
    let healthy_operations = chain(&healthy, 1, 15_100);
    let trust = Trust {
        devices: [
            (broken.certificate.device_id, broken.certificate.clone()),
            (healthy.certificate.device_id, healthy.certificate.clone()),
        ]
        .into_iter()
        .collect(),
        key: ContentKey::from_bytes(CONTENT_KEY),
    };
    let mut inner = InMemoryTransport::new();
    inner
        .push_operations(scope(), &[canonical(&broken_operations[0].1)])
        .unwrap();
    inner
        .push_operations(scope(), &[canonical(&broken_operations[1].1)])
        .unwrap();
    inner
        .push_operations(scope(), &[canonical(&healthy_operations[0].1)])
        .unwrap();
    let initial_rows = inner.pull_operations(scope(), None, 3).unwrap().rows;
    let broken_first = initial_rows
        .iter()
        .find(|row| row.operation.operation_id == broken_operations[0].1.operation.operation_id)
        .unwrap()
        .clone();
    let broken_second = initial_rows
        .iter()
        .find(|row| row.operation.operation_id == broken_operations[1].1.operation.operation_id)
        .unwrap()
        .clone();
    let healthy_row = initial_rows
        .iter()
        .find(|row| row.operation.operation_id == healthy_operations[0].1.operation.operation_id)
        .unwrap()
        .clone();
    let mut transport = PoisonOperationTransport {
        inner,
        operation_id: broken_first.operation.operation_id,
    };
    let path = TempVault::new("sync-engine-durable-device-quarantine");
    let keys = MemoryKeyStore::default();
    let engine = SyncEngine::new(scope(), SyncProvider::Memory);
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();

    let report = engine
        .sync_once(&mut vault, &mut transport, &trust, &NoEmbeddings, 10)
        .unwrap();
    assert!(report.quarantined >= 2);
    assert_eq!(report.applied, 1);
    assert!(
        vault
            .device_head(id(ID_2), broken.certificate.device_id)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        vault
            .device_head(id(ID_2), healthy.certificate.device_id)
            .unwrap()
            .unwrap()
            .sequence,
        1
    );
    assert_eq!(
        vault.sync_cursor(id(ID_2), "memory").unwrap().unwrap(),
        healthy_row.cursor
    );
    assert_eq!(
        vault
            .quarantined_sync_receipt(
                id(ID_1),
                id(ID_2),
                "memory",
                &broken_first.cursor.received_at,
                broken_first.cursor.operation_id,
            )
            .unwrap()
            .unwrap()
            .safe_error_code,
        "integrity_quarantined"
    );
    assert_eq!(
        vault
            .quarantined_sync_receipt(
                id(ID_1),
                id(ID_2),
                "memory",
                &broken_second.cursor.received_at,
                broken_second.cursor.operation_id,
            )
            .unwrap()
            .unwrap()
            .safe_error_code,
        "gap_pending"
    );
    drop(vault);

    let mut reopened = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let idle = engine
        .sync_once(&mut reopened, &mut transport, &trust, &NoEmbeddings, 20)
        .unwrap();
    assert_eq!(idle.pulled, 0);
    transport
        .push_operations(scope(), &[canonical(&broken_operations[2].1)])
        .unwrap();
    let third_row = transport
        .inner
        .pull_operations(
            scope(),
            reopened.sync_cursor(id(ID_2), "memory").unwrap().as_ref(),
            1,
        )
        .unwrap()
        .rows
        .remove(0);
    let report = engine
        .sync_once(&mut reopened, &mut transport, &trust, &NoEmbeddings, 30)
        .unwrap();
    assert!(report.quarantined >= 2);
    assert!(
        reopened
            .device_head(id(ID_2), broken.certificate.device_id)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        reopened.sync_cursor(id(ID_2), "memory").unwrap().unwrap(),
        third_row.cursor
    );
    assert_eq!(
        reopened
            .quarantined_sync_receipt(
                id(ID_1),
                id(ID_2),
                "memory",
                &third_row.cursor.received_at,
                third_row.cursor.operation_id,
            )
            .unwrap()
            .unwrap()
            .safe_error_code,
        "gap_pending"
    );
}

#[test]
fn mismatched_or_malformed_main_receipt_never_mutates_normal_or_replay_state() {
    let device = device(ID_3, 44);
    let trust = trust(&device);
    let operations = chain(&device, 1, 13_000);
    for (name, fault) in [
        ("cursor-id", CursorFault::OperationId),
        ("cursor-time", CursorFault::ReceivedAt),
    ] {
        let mut inner = InMemoryTransport::new();
        inner
            .push_operations(scope(), &[canonical(&operations[0].1)])
            .unwrap();
        let mut transport = CursorFaultTransport { inner, fault };
        let path = TempVault::new(name);
        let keys = MemoryKeyStore::default();
        let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
        let error = SyncEngine::new(scope(), SyncProvider::Memory)
            .sync_once(&mut vault, &mut transport, &trust, &NoEmbeddings, 0)
            .unwrap_err();
        assert_eq!(error.safe_code(), "integrity_quarantined");
        assert!(vault.device_head(id(ID_2), id(ID_3)).unwrap().is_none());
        assert!(vault.sync_cursor(id(ID_2), "memory").unwrap().is_none());
    }

    let mut inner = InMemoryTransport::new();
    inner
        .push_operations(scope(), &[canonical(&operations[0].1)])
        .unwrap();
    let mut transport = CursorFaultTransport {
        inner,
        fault: CursorFault::OperationId,
    };
    let path = TempVault::new("cursor-id-exact-replay");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault
        .commit_outgoing_operation(&operations[0].0, &operations[0].1, None)
        .unwrap();
    let error = SyncEngine::new(scope(), SyncProvider::Memory)
        .sync_once(&mut vault, &mut transport, &trust, &NoEmbeddings, 0)
        .unwrap_err();
    assert_eq!(error.safe_code(), "integrity_quarantined");
    assert!(vault.sync_cursor(id(ID_2), "memory").unwrap().is_none());
}

#[test]
fn mismatched_gap_range_receipt_cannot_commit_a_repair_prefix() {
    let device = device(ID_3, 45);
    let trust = trust(&device);
    let operations = chain(&device, 2, 14_000);
    let mut inner = InMemoryTransport::new();
    inner
        .push_operations(scope(), &[canonical(&operations[1].1)])
        .unwrap();
    inner
        .push_operations(scope(), &[canonical(&operations[0].1)])
        .unwrap();
    let mut transport = CursorFaultTransport {
        inner,
        fault: CursorFault::RangeOperationId,
    };
    let path = TempVault::new("cursor-id-gap-range");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();

    let error = SyncEngine::new(scope(), SyncProvider::Memory)
        .sync_once(&mut vault, &mut transport, &trust, &NoEmbeddings, 0)
        .unwrap_err();
    assert_eq!(error.safe_code(), "integrity_quarantined");
    assert!(vault.device_head(id(ID_2), id(ID_3)).unwrap().is_none());
    assert!(vault.sync_cursor(id(ID_2), "memory").unwrap().is_none());
}

#[test]
fn revoked_or_unknown_device_is_stable_and_never_mislabeled_as_quarantine() {
    let device = device(ID_3, 41);
    let operations = chain(&device, 1, 10_000);
    let mut provider = InMemoryTransport::new();
    provider
        .push_operations(scope(), &[canonical(&operations[0].1)])
        .unwrap();
    let trust = Trust {
        devices: BTreeMap::new(),
        key: ContentKey::from_bytes(CONTENT_KEY),
    };
    let path = TempVault::new("sync-engine-revoked");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();

    let error = SyncEngine::new(scope(), SyncProvider::Memory)
        .sync_once(&mut vault, &mut provider, &trust, &NoEmbeddings, 0)
        .unwrap_err();
    assert_eq!(error.safe_code(), "revoked");
    assert!(vault.sync_cursor(id(ID_2), "memory").unwrap().is_none());
}

#[derive(Clone, Copy, Debug)]
enum BadReceiptKind {
    Omission,
    Extra,
    DuplicateAccepted,
    DuplicateDuplicate,
    Overlap,
}

struct BadReceiptTransport {
    inner: InMemoryTransport,
    kind: BadReceiptKind,
}

struct CorruptPullTransport(InMemoryTransport);

struct DelegatingTransport {
    inner: InMemoryTransport,
    legacy_checkpoint_v1: Vec<u8>,
    requested_checkpoint_versions: Vec<u16>,
}

struct ConcurrentCheckpointExtensionTransport {
    inner: InMemoryTransport,
    concurrent: CanonicalCheckpoint,
    injected: bool,
    accepted_sibling: Option<CanonicalCheckpoint>,
}

#[derive(Clone, Copy)]
#[repr(u8)]
enum FreshCheckpointForgery {
    Competing = 0,
    Omitted = 1,
}

struct FreshCheckpointForgeryTransport {
    inner: InMemoryTransport,
    forgery: FreshCheckpointForgery,
    competing: CanonicalCheckpoint,
    forged: bool,
}

struct CheckpointCursorTamperTransport(InMemoryTransport);

struct OversizedPullTransport(InMemoryTransport);

struct OversizedRangeTransport {
    inner: InMemoryTransport,
    operation_id: OperationId,
}

struct PoisonOperationTransport {
    inner: InMemoryTransport,
    operation_id: OperationId,
}

#[derive(Clone, Copy)]
enum CursorFault {
    OperationId,
    ReceivedAt,
    RangeOperationId,
}

struct CursorFaultTransport {
    inner: InMemoryTransport,
    fault: CursorFault,
}

#[derive(Clone, Copy, Debug)]
enum RangeShape {
    Missing,
    Duplicate,
}

struct RangeShapeTransport {
    inner: InMemoryTransport,
    shape: RangeShape,
}

impl SyncTransport for BadReceiptTransport {
    fn push_operations(
        &mut self,
        scope: SyncScope,
        batch: &[CanonicalOperation],
    ) -> Result<PushReceipt, TransportError> {
        let mut receipt = self.inner.push_operations(scope, batch)?;
        let operation_id = batch[0].operation_id;
        match self.kind {
            BadReceiptKind::Omission => receipt.accepted.clear(),
            BadReceiptKind::Extra => receipt.accepted.push(generated_id(900_003)),
            BadReceiptKind::DuplicateAccepted => receipt.accepted.push(operation_id),
            BadReceiptKind::DuplicateDuplicate => {
                receipt.accepted.clear();
                receipt.duplicates = vec![operation_id, operation_id];
            }
            BadReceiptKind::Overlap => receipt.duplicates.push(operation_id),
        }
        Ok(receipt)
    }

    fn pull_operations(
        &mut self,
        scope: SyncScope,
        after: Option<&context_relay_core::vault::SyncCursor>,
        limit: usize,
    ) -> Result<PullPage, TransportError> {
        self.inner.pull_operations(scope, after, limit)
    }

    fn pull_device_range(
        &mut self,
        scope: SyncScope,
        device: DeviceId,
        range: RangeInclusive<u64>,
    ) -> Result<Vec<ReceivedOperation>, TransportError> {
        self.inner.pull_device_range(scope, device, range)
    }

    fn push_checkpoint(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        checkpoint: &CanonicalCheckpoint,
    ) -> Result<CheckpointReceipt, TransportError> {
        self.inner
            .push_checkpoint(scope, checkpoint_version, checkpoint)
    }

    fn pull_checkpoints(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        after: Option<&CheckpointCursor>,
        limit: usize,
    ) -> Result<CheckpointPage, TransportError> {
        self.inner
            .pull_checkpoints(scope, checkpoint_version, after, limit)
    }

    fn checkpoint_by_hash(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        canonical_hash: Sha256Digest,
    ) -> Result<Option<CanonicalCheckpoint>, TransportError> {
        self.inner
            .checkpoint_by_hash(scope, checkpoint_version, canonical_hash)
    }
}

impl SyncTransport for CorruptPullTransport {
    fn push_operations(
        &mut self,
        scope: SyncScope,
        batch: &[CanonicalOperation],
    ) -> Result<PushReceipt, TransportError> {
        self.0.push_operations(scope, batch)
    }

    fn pull_operations(
        &mut self,
        scope: SyncScope,
        after: Option<&context_relay_core::vault::SyncCursor>,
        limit: usize,
    ) -> Result<PullPage, TransportError> {
        let mut page = self.0.pull_operations(scope, after, limit)?;
        if let Some(row) = page.rows.first_mut() {
            row.operation.bytes[0] ^= 1;
        }
        Ok(page)
    }

    fn pull_device_range(
        &mut self,
        scope: SyncScope,
        device: DeviceId,
        range: RangeInclusive<u64>,
    ) -> Result<Vec<ReceivedOperation>, TransportError> {
        self.0.pull_device_range(scope, device, range)
    }

    fn push_checkpoint(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        checkpoint: &CanonicalCheckpoint,
    ) -> Result<CheckpointReceipt, TransportError> {
        self.0
            .push_checkpoint(scope, checkpoint_version, checkpoint)
    }

    fn pull_checkpoints(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        after: Option<&CheckpointCursor>,
        limit: usize,
    ) -> Result<CheckpointPage, TransportError> {
        self.0
            .pull_checkpoints(scope, checkpoint_version, after, limit)
    }

    fn checkpoint_by_hash(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        canonical_hash: Sha256Digest,
    ) -> Result<Option<CanonicalCheckpoint>, TransportError> {
        self.0
            .checkpoint_by_hash(scope, checkpoint_version, canonical_hash)
    }
}

impl SyncTransport for DelegatingTransport {
    fn push_operations(
        &mut self,
        scope: SyncScope,
        batch: &[CanonicalOperation],
    ) -> Result<PushReceipt, TransportError> {
        self.inner.push_operations(scope, batch)
    }

    fn pull_operations(
        &mut self,
        scope: SyncScope,
        after: Option<&context_relay_core::vault::SyncCursor>,
        limit: usize,
    ) -> Result<PullPage, TransportError> {
        self.inner.pull_operations(scope, after, limit)
    }

    fn pull_device_range(
        &mut self,
        scope: SyncScope,
        device: DeviceId,
        range: RangeInclusive<u64>,
    ) -> Result<Vec<ReceivedOperation>, TransportError> {
        self.inner.pull_device_range(scope, device, range)
    }

    fn push_checkpoint(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        checkpoint: &CanonicalCheckpoint,
    ) -> Result<CheckpointReceipt, TransportError> {
        self.requested_checkpoint_versions.push(checkpoint_version);
        self.inner
            .push_checkpoint(scope, checkpoint_version, checkpoint)
    }

    fn pull_checkpoints(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        after: Option<&CheckpointCursor>,
        limit: usize,
    ) -> Result<CheckpointPage, TransportError> {
        self.requested_checkpoint_versions.push(checkpoint_version);
        self.inner
            .pull_checkpoints(scope, checkpoint_version, after, limit)
    }

    fn checkpoint_by_hash(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        canonical_hash: Sha256Digest,
    ) -> Result<Option<CanonicalCheckpoint>, TransportError> {
        self.requested_checkpoint_versions.push(checkpoint_version);
        self.inner
            .checkpoint_by_hash(scope, checkpoint_version, canonical_hash)
    }
}

impl SyncTransport for ConcurrentCheckpointExtensionTransport {
    fn push_operations(
        &mut self,
        scope: SyncScope,
        batch: &[CanonicalOperation],
    ) -> Result<PushReceipt, TransportError> {
        self.inner.push_operations(scope, batch)
    }

    fn pull_operations(
        &mut self,
        scope: SyncScope,
        after: Option<&context_relay_core::vault::SyncCursor>,
        limit: usize,
    ) -> Result<PullPage, TransportError> {
        self.inner.pull_operations(scope, after, limit)
    }

    fn pull_device_range(
        &mut self,
        scope: SyncScope,
        device: DeviceId,
        range: RangeInclusive<u64>,
    ) -> Result<Vec<ReceivedOperation>, TransportError> {
        self.inner.pull_device_range(scope, device, range)
    }

    fn push_checkpoint(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        checkpoint: &CanonicalCheckpoint,
    ) -> Result<CheckpointReceipt, TransportError> {
        if !self.injected {
            self.inner
                .push_checkpoint(scope, checkpoint_version, &self.concurrent)?;
            self.injected = true;
            self.accepted_sibling = Some(checkpoint.clone());
            return Ok(CheckpointReceipt {
                canonical_hash: checkpoint.canonical_hash,
                duplicate: false,
            });
        }
        self.inner
            .push_checkpoint(scope, checkpoint_version, checkpoint)
    }

    fn pull_checkpoints(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        after: Option<&CheckpointCursor>,
        limit: usize,
    ) -> Result<CheckpointPage, TransportError> {
        if self.accepted_sibling.as_ref().is_some_and(|sibling| {
            after.is_some_and(|cursor| cursor.canonical_hash == sibling.canonical_hash)
        }) {
            return Ok(CheckpointPage {
                rows: Vec::new(),
                next_cursor: None,
            });
        }
        let mut page = self
            .inner
            .pull_checkpoints(scope, checkpoint_version, after, limit)?;
        if page.rows.len() < limit
            && let Some(sibling) = self.accepted_sibling.as_ref()
        {
            let cursor = CheckpointCursor {
                received_at: "memory-99999999999999999999".to_owned(),
                canonical_hash: sibling.canonical_hash,
            };
            page.rows
                .push(context_relay_core::sync::ReceivedCheckpoint {
                    cursor: cursor.clone(),
                    checkpoint: sibling.clone(),
                });
            page.next_cursor = Some(cursor);
        }
        Ok(page)
    }

    fn checkpoint_by_hash(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        canonical_hash: Sha256Digest,
    ) -> Result<Option<CanonicalCheckpoint>, TransportError> {
        if let Some(sibling) = self.accepted_sibling.as_ref()
            && sibling.canonical_hash == canonical_hash
        {
            return Ok(Some(sibling.clone()));
        }
        self.inner
            .checkpoint_by_hash(scope, checkpoint_version, canonical_hash)
    }
}

impl SyncTransport for FreshCheckpointForgeryTransport {
    fn push_operations(
        &mut self,
        scope: SyncScope,
        batch: &[CanonicalOperation],
    ) -> Result<PushReceipt, TransportError> {
        self.inner.push_operations(scope, batch)
    }

    fn pull_operations(
        &mut self,
        scope: SyncScope,
        after: Option<&context_relay_core::vault::SyncCursor>,
        limit: usize,
    ) -> Result<PullPage, TransportError> {
        self.inner.pull_operations(scope, after, limit)
    }

    fn pull_device_range(
        &mut self,
        scope: SyncScope,
        device: DeviceId,
        range: RangeInclusive<u64>,
    ) -> Result<Vec<ReceivedOperation>, TransportError> {
        self.inner.pull_device_range(scope, device, range)
    }

    fn push_checkpoint(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        checkpoint: &CanonicalCheckpoint,
    ) -> Result<CheckpointReceipt, TransportError> {
        if !self.forged {
            self.forged = true;
            if matches!(self.forgery, FreshCheckpointForgery::Competing) {
                self.inner
                    .push_checkpoint(scope, checkpoint_version, &self.competing)?;
            }
            return Ok(CheckpointReceipt {
                canonical_hash: checkpoint.canonical_hash,
                duplicate: false,
            });
        }
        self.inner
            .push_checkpoint(scope, checkpoint_version, checkpoint)
    }

    fn pull_checkpoints(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        after: Option<&CheckpointCursor>,
        limit: usize,
    ) -> Result<CheckpointPage, TransportError> {
        self.inner
            .pull_checkpoints(scope, checkpoint_version, after, limit)
    }

    fn checkpoint_by_hash(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        canonical_hash: Sha256Digest,
    ) -> Result<Option<CanonicalCheckpoint>, TransportError> {
        self.inner
            .checkpoint_by_hash(scope, checkpoint_version, canonical_hash)
    }
}

impl SyncTransport for CheckpointCursorTamperTransport {
    fn push_operations(
        &mut self,
        scope: SyncScope,
        batch: &[CanonicalOperation],
    ) -> Result<PushReceipt, TransportError> {
        self.0.push_operations(scope, batch)
    }

    fn pull_operations(
        &mut self,
        scope: SyncScope,
        after: Option<&context_relay_core::vault::SyncCursor>,
        limit: usize,
    ) -> Result<PullPage, TransportError> {
        self.0.pull_operations(scope, after, limit)
    }

    fn pull_device_range(
        &mut self,
        scope: SyncScope,
        device: DeviceId,
        range: RangeInclusive<u64>,
    ) -> Result<Vec<ReceivedOperation>, TransportError> {
        self.0.pull_device_range(scope, device, range)
    }

    fn push_checkpoint(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        checkpoint: &CanonicalCheckpoint,
    ) -> Result<CheckpointReceipt, TransportError> {
        self.0
            .push_checkpoint(scope, checkpoint_version, checkpoint)
    }

    fn pull_checkpoints(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        after: Option<&CheckpointCursor>,
        limit: usize,
    ) -> Result<CheckpointPage, TransportError> {
        let tampered = after.cloned().map(|mut cursor| {
            cursor.canonical_hash.0[0] ^= 1;
            cursor
        });
        self.0
            .pull_checkpoints(scope, checkpoint_version, tampered.as_ref(), limit)
    }

    fn checkpoint_by_hash(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        canonical_hash: Sha256Digest,
    ) -> Result<Option<CanonicalCheckpoint>, TransportError> {
        self.0
            .checkpoint_by_hash(scope, checkpoint_version, canonical_hash)
    }
}

impl SyncTransport for OversizedPullTransport {
    fn push_operations(
        &mut self,
        scope: SyncScope,
        batch: &[CanonicalOperation],
    ) -> Result<PushReceipt, TransportError> {
        self.0.push_operations(scope, batch)
    }

    fn pull_operations(
        &mut self,
        scope: SyncScope,
        after: Option<&context_relay_core::vault::SyncCursor>,
        limit: usize,
    ) -> Result<PullPage, TransportError> {
        let mut page = self.0.pull_operations(scope, after, limit)?;
        if let Some(row) = page.rows.first_mut() {
            row.operation.bytes = vec![0; MAX_CBOR_OPERATION_BYTES + 1];
        }
        Ok(page)
    }

    fn pull_device_range(
        &mut self,
        scope: SyncScope,
        device: DeviceId,
        range: RangeInclusive<u64>,
    ) -> Result<Vec<ReceivedOperation>, TransportError> {
        self.0.pull_device_range(scope, device, range)
    }

    fn push_checkpoint(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        checkpoint: &CanonicalCheckpoint,
    ) -> Result<CheckpointReceipt, TransportError> {
        self.0
            .push_checkpoint(scope, checkpoint_version, checkpoint)
    }

    fn pull_checkpoints(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        after: Option<&CheckpointCursor>,
        limit: usize,
    ) -> Result<CheckpointPage, TransportError> {
        self.0
            .pull_checkpoints(scope, checkpoint_version, after, limit)
    }

    fn checkpoint_by_hash(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        canonical_hash: Sha256Digest,
    ) -> Result<Option<CanonicalCheckpoint>, TransportError> {
        self.0
            .checkpoint_by_hash(scope, checkpoint_version, canonical_hash)
    }
}

impl SyncTransport for OversizedRangeTransport {
    fn push_operations(
        &mut self,
        scope: SyncScope,
        batch: &[CanonicalOperation],
    ) -> Result<PushReceipt, TransportError> {
        self.inner.push_operations(scope, batch)
    }

    fn pull_operations(
        &mut self,
        scope: SyncScope,
        after: Option<&context_relay_core::vault::SyncCursor>,
        limit: usize,
    ) -> Result<PullPage, TransportError> {
        let mut page = self.inner.pull_operations(scope, after, limit)?;
        page.rows
            .retain(|row| row.operation.operation_id != self.operation_id);
        page.next_cursor = page.rows.last().map(|row| row.cursor.clone());
        Ok(page)
    }

    fn pull_device_range(
        &mut self,
        scope: SyncScope,
        device: DeviceId,
        range: RangeInclusive<u64>,
    ) -> Result<Vec<ReceivedOperation>, TransportError> {
        let mut rows = self.inner.pull_device_range(scope, device, range)?;
        for row in &mut rows {
            if row.operation.operation_id == self.operation_id {
                row.operation.bytes = vec![0; MAX_CBOR_OPERATION_BYTES + 1];
            }
        }
        Ok(rows)
    }

    fn push_checkpoint(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        checkpoint: &CanonicalCheckpoint,
    ) -> Result<CheckpointReceipt, TransportError> {
        self.inner
            .push_checkpoint(scope, checkpoint_version, checkpoint)
    }

    fn pull_checkpoints(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        after: Option<&CheckpointCursor>,
        limit: usize,
    ) -> Result<CheckpointPage, TransportError> {
        self.inner
            .pull_checkpoints(scope, checkpoint_version, after, limit)
    }

    fn checkpoint_by_hash(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        canonical_hash: Sha256Digest,
    ) -> Result<Option<CanonicalCheckpoint>, TransportError> {
        self.inner
            .checkpoint_by_hash(scope, checkpoint_version, canonical_hash)
    }
}

impl SyncTransport for PoisonOperationTransport {
    fn push_operations(
        &mut self,
        scope: SyncScope,
        batch: &[CanonicalOperation],
    ) -> Result<PushReceipt, TransportError> {
        self.inner.push_operations(scope, batch)
    }

    fn pull_operations(
        &mut self,
        scope: SyncScope,
        after: Option<&context_relay_core::vault::SyncCursor>,
        limit: usize,
    ) -> Result<PullPage, TransportError> {
        let mut page = self.inner.pull_operations(scope, after, limit)?;
        for row in &mut page.rows {
            poison_operation(row, self.operation_id);
        }
        Ok(page)
    }

    fn pull_device_range(
        &mut self,
        scope: SyncScope,
        device: DeviceId,
        range: RangeInclusive<u64>,
    ) -> Result<Vec<ReceivedOperation>, TransportError> {
        let mut rows = self.inner.pull_device_range(scope, device, range)?;
        for row in &mut rows {
            poison_operation(row, self.operation_id);
        }
        Ok(rows)
    }

    fn push_checkpoint(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        checkpoint: &CanonicalCheckpoint,
    ) -> Result<CheckpointReceipt, TransportError> {
        self.inner
            .push_checkpoint(scope, checkpoint_version, checkpoint)
    }

    fn pull_checkpoints(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        after: Option<&CheckpointCursor>,
        limit: usize,
    ) -> Result<CheckpointPage, TransportError> {
        self.inner
            .pull_checkpoints(scope, checkpoint_version, after, limit)
    }

    fn checkpoint_by_hash(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        canonical_hash: Sha256Digest,
    ) -> Result<Option<CanonicalCheckpoint>, TransportError> {
        self.inner
            .checkpoint_by_hash(scope, checkpoint_version, canonical_hash)
    }
}

fn poison_operation(row: &mut ReceivedOperation, operation_id: OperationId) {
    if row.operation.operation_id == operation_id {
        row.operation.bytes[0] ^= 1;
    }
}

impl SyncTransport for CursorFaultTransport {
    fn push_operations(
        &mut self,
        scope: SyncScope,
        batch: &[CanonicalOperation],
    ) -> Result<PushReceipt, TransportError> {
        self.inner.push_operations(scope, batch)
    }

    fn pull_operations(
        &mut self,
        scope: SyncScope,
        after: Option<&context_relay_core::vault::SyncCursor>,
        limit: usize,
    ) -> Result<PullPage, TransportError> {
        let mut page = self.inner.pull_operations(scope, after, limit)?;
        if !matches!(self.fault, CursorFault::RangeOperationId) {
            if let Some(row) = page.rows.first_mut() {
                match self.fault {
                    CursorFault::OperationId => row.cursor.operation_id = generated_id(900_001),
                    CursorFault::ReceivedAt => row.cursor.received_at = "bad'cursor".to_owned(),
                    CursorFault::RangeOperationId => unreachable!(),
                }
                page.next_cursor = Some(row.cursor.clone());
            }
        }
        Ok(page)
    }

    fn pull_device_range(
        &mut self,
        scope: SyncScope,
        device: DeviceId,
        range: RangeInclusive<u64>,
    ) -> Result<Vec<ReceivedOperation>, TransportError> {
        let mut rows = self.inner.pull_device_range(scope, device, range)?;
        if matches!(self.fault, CursorFault::RangeOperationId)
            && let Some(row) = rows.first_mut()
        {
            row.cursor.operation_id = generated_id(900_002);
        }
        Ok(rows)
    }

    fn push_checkpoint(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        checkpoint: &CanonicalCheckpoint,
    ) -> Result<CheckpointReceipt, TransportError> {
        self.inner
            .push_checkpoint(scope, checkpoint_version, checkpoint)
    }

    fn pull_checkpoints(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        after: Option<&CheckpointCursor>,
        limit: usize,
    ) -> Result<CheckpointPage, TransportError> {
        self.inner
            .pull_checkpoints(scope, checkpoint_version, after, limit)
    }

    fn checkpoint_by_hash(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        canonical_hash: Sha256Digest,
    ) -> Result<Option<CanonicalCheckpoint>, TransportError> {
        self.inner
            .checkpoint_by_hash(scope, checkpoint_version, canonical_hash)
    }
}

impl SyncTransport for RangeShapeTransport {
    fn push_operations(
        &mut self,
        scope: SyncScope,
        batch: &[CanonicalOperation],
    ) -> Result<PushReceipt, TransportError> {
        self.inner.push_operations(scope, batch)
    }

    fn pull_operations(
        &mut self,
        scope: SyncScope,
        after: Option<&context_relay_core::vault::SyncCursor>,
        limit: usize,
    ) -> Result<PullPage, TransportError> {
        self.inner.pull_operations(scope, after, limit)
    }

    fn pull_device_range(
        &mut self,
        scope: SyncScope,
        device: DeviceId,
        range: RangeInclusive<u64>,
    ) -> Result<Vec<ReceivedOperation>, TransportError> {
        let mut rows = self.inner.pull_device_range(scope, device, range)?;
        match self.shape {
            RangeShape::Missing => {
                rows.pop();
            }
            RangeShape::Duplicate => {
                if let Some(first) = rows.first().cloned() {
                    rows.push(first);
                }
            }
        }
        Ok(rows)
    }

    fn push_checkpoint(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        checkpoint: &CanonicalCheckpoint,
    ) -> Result<CheckpointReceipt, TransportError> {
        self.inner
            .push_checkpoint(scope, checkpoint_version, checkpoint)
    }

    fn pull_checkpoints(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        after: Option<&CheckpointCursor>,
        limit: usize,
    ) -> Result<CheckpointPage, TransportError> {
        self.inner
            .pull_checkpoints(scope, checkpoint_version, after, limit)
    }

    fn checkpoint_by_hash(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        canonical_hash: Sha256Digest,
    ) -> Result<Option<CanonicalCheckpoint>, TransportError> {
        self.inner
            .checkpoint_by_hash(scope, checkpoint_version, canonical_hash)
    }
}

fn scope() -> SyncScope {
    SyncScope {
        account_id: id(ID_1),
        workspace_id: id(ID_2),
    }
}

fn trust(device: &DeviceFixture) -> Trust {
    Trust {
        devices: [(device.certificate.device_id, device.certificate.clone())]
            .into_iter()
            .collect(),
        key: ContentKey::from_bytes(CONTENT_KEY),
    }
}

fn chain(
    device: &DeviceFixture,
    count: usize,
    id_start: usize,
) -> Vec<(RecordMutationV1, context_relay_core::sync::BuiltOperation)> {
    let content_key = ContentKey::from_bytes(CONTENT_KEY);
    let mut previous = None;
    let mut output = Vec::with_capacity(count);
    for index in 0..count {
        let mutation = RecordMutationV1::UpsertSecretRef(SecretRef {
            id: id::<SecretRefId>("018f22e2-79b0-7cc8-98c4-dc0c0c073986"),
            name: format!("secret-{index}"),
            provider: "local-keychain".to_owned(),
            required_on_device: true,
        });
        let built = OperationBuilder::new(SyncIdentity {
            account_id: id(ID_1),
            workspace_id: id(ID_2),
            device_id: device.certificate.device_id,
            control_epoch: CONTROL_EPOCH,
            key_epoch: KEY_EPOCH,
            device_keys: &device.keys,
            content_key: &content_key,
        })
        .build(
            generated_id(id_start + index),
            None,
            &mutation,
            Vec::new(),
            previous,
            Vec::new(),
            HybridLogicalClock::new(
                1_700_000_000_000 + index as u64,
                0,
                device.certificate.device_id,
            ),
        )
        .unwrap();
        previous = Some(OperationChainHead {
            sequence: built.operation.device_sequence,
            canonical_hash: built.canonical_hash,
        });
        output.push((mutation, built));
    }
    output
}

fn large_chain(
    device: &DeviceFixture,
    count: usize,
    id_start: usize,
) -> Vec<(RecordMutationV1, context_relay_core::sync::BuiltOperation)> {
    let content_key = ContentKey::from_bytes(CONTENT_KEY);
    let blob_refs = (0..9_000)
        .map(|index| BlobRef {
            digest: Sha256Digest([(index % 251) as u8; 32]),
            ciphertext_bytes: 1,
            storage_id: format!("{index:04}-{}", "x".repeat(425)),
        })
        .collect::<Vec<_>>();
    let mut previous = None;
    let mut output = Vec::with_capacity(count);
    for index in 0..count {
        let mutation = RecordMutationV1::UpsertSecretRef(SecretRef {
            id: id::<SecretRefId>("018f22e2-79b0-7cc8-98c4-dc0c0c073986"),
            name: format!("large-secret-{index}"),
            provider: "local-keychain".to_owned(),
            required_on_device: true,
        });
        let built = OperationBuilder::new(SyncIdentity {
            account_id: id(ID_1),
            workspace_id: id(ID_2),
            device_id: device.certificate.device_id,
            control_epoch: CONTROL_EPOCH,
            key_epoch: KEY_EPOCH,
            device_keys: &device.keys,
            content_key: &content_key,
        })
        .build(
            generated_id(id_start + index),
            None,
            &mutation,
            Vec::new(),
            previous,
            blob_refs.clone(),
            HybridLogicalClock::new(
                1_700_100_000_000 + index as u64,
                0,
                device.certificate.device_id,
            ),
        )
        .unwrap();
        previous = Some(OperationChainHead {
            sequence: built.operation.device_sequence,
            canonical_hash: built.canonical_hash,
        });
        output.push((mutation, built));
    }
    output
}

fn canonical(built: &context_relay_core::sync::BuiltOperation) -> CanonicalOperation {
    CanonicalOperation {
        operation_id: built.operation.operation_id,
        device_id: built.operation.device_id,
        device_sequence: built.operation.device_sequence,
        bytes: built.canonical_bytes.clone(),
    }
}

fn canonical_checkpoint(state: u8, physical_ms: u64) -> CanonicalCheckpoint {
    CanonicalCheckpoint::from_checkpoint(CheckpointV1 {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        account_id: scope().account_id,
        workspace_id: scope().workspace_id,
        previous_checkpoint_hash: Sha256Digest([0; 32]),
        causal_frontier: Vec::new(),
        state_hash: Sha256Digest([state; 32]),
        key_epoch: KEY_EPOCH,
        creator_device: id(ID_3),
        created_hlc: HybridLogicalClock::new(physical_ms, 0, id(ID_3)),
        signature: Ed25519SignatureBytes([state; 64]),
    })
    .unwrap()
}

fn signed_checkpoint(
    device: &DeviceFixture,
    previous_checkpoint_hash: Sha256Digest,
    state_hash: Sha256Digest,
    physical_ms: u64,
) -> CanonicalCheckpoint {
    let mut checkpoint = CheckpointV1 {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        account_id: scope().account_id,
        workspace_id: scope().workspace_id,
        previous_checkpoint_hash,
        causal_frontier: Vec::new(),
        state_hash,
        key_epoch: KEY_EPOCH,
        creator_device: device.certificate.device_id,
        created_hlc: HybridLogicalClock::new(physical_ms, 0, device.certificate.device_id),
        signature: Ed25519SignatureBytes([0; 64]),
    };
    device.keys.sign_checkpoint(&mut checkpoint).unwrap();
    CanonicalCheckpoint::from_checkpoint(checkpoint).unwrap()
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

fn generated_id<T: FromStr>(number: usize) -> T
where
    T::Err: std::fmt::Debug,
{
    format!("018f22e2-79b0-7cc8-98c4-{number:012x}")
        .parse()
        .unwrap()
}

fn id<T: FromStr>(value: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    value.parse().unwrap()
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .trim()
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
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
}
