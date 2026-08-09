use std::{collections::BTreeMap, ops::RangeInclusive};

use context_relay_protocol::{
    AccountId, CHECKPOINT_SCHEMA_VERSION, DeviceId, MAX_BATCH_OPERATIONS, OperationId,
    Sha256Digest, WorkspaceId, decode_checkpoint_v1, decode_sync_operation_v1,
    encode_checkpoint_v1, encode_sync_operation_v1,
};
use sha2::{Digest, Sha256};

use crate::vault::SyncCursor;

use super::{
    CanonicalCheckpoint, CanonicalOperation, CheckpointCursor, CheckpointPage, CheckpointReceipt,
    PullPage, PushReceipt, ReceivedCheckpoint, ReceivedOperation, SyncScope, SyncTransport,
    TransportError,
};

const MAX_PAGE: usize = 256;
const MAX_BATCH_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FaultSchedule {
    transient_pushes: usize,
    transient_pulls: usize,
    transient_ranges: usize,
    dropped_pulls: usize,
    delayed_pulls: usize,
    duplicated_pulls: usize,
    reversed_pulls: usize,
    lost_hints: usize,
}

impl FaultSchedule {
    pub fn transient_push(times: usize) -> Self {
        Self::default().with_transient_pushes(times)
    }

    pub fn drop_pull(times: usize) -> Self {
        Self::default().with_dropped_pulls(times)
    }

    #[must_use]
    pub fn with_transient_pushes(mut self, times: usize) -> Self {
        self.transient_pushes = times;
        self
    }

    #[must_use]
    pub fn with_transient_pulls(mut self, times: usize) -> Self {
        self.transient_pulls = times;
        self
    }

    #[must_use]
    pub fn with_transient_ranges(mut self, times: usize) -> Self {
        self.transient_ranges = times;
        self
    }

    #[must_use]
    pub fn with_dropped_pulls(mut self, times: usize) -> Self {
        self.dropped_pulls = times;
        self
    }

    #[must_use]
    pub fn with_delayed_pulls(mut self, times: usize) -> Self {
        self.delayed_pulls = times;
        self
    }

    #[must_use]
    pub fn with_duplicated_pulls(mut self, times: usize) -> Self {
        self.duplicated_pulls = times;
        self
    }

    #[must_use]
    pub fn with_reversed_pulls(mut self, times: usize) -> Self {
        self.reversed_pulls = times;
        self
    }

    #[must_use]
    pub fn with_lost_hints(mut self, times: usize) -> Self {
        self.lost_hints = times;
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct CursorKey {
    received_at: String,
    operation_id: OperationId,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct CheckpointCursorKey {
    received_at: String,
    canonical_hash: Sha256Digest,
}

impl CheckpointCursorKey {
    fn from_cursor(cursor: &CheckpointCursor) -> Self {
        Self {
            received_at: cursor.received_at.clone(),
            canonical_hash: cursor.canonical_hash,
        }
    }

    fn cursor(&self) -> CheckpointCursor {
        CheckpointCursor {
            received_at: self.received_at.clone(),
            canonical_hash: self.canonical_hash,
        }
    }
}

impl CursorKey {
    fn from_cursor(cursor: &SyncCursor) -> Self {
        Self {
            received_at: cursor.received_at.clone(),
            operation_id: cursor.operation_id,
        }
    }

    fn cursor(&self) -> SyncCursor {
        SyncCursor {
            received_at: self.received_at.clone(),
            operation_id: self.operation_id,
        }
    }
}

#[derive(Default)]
struct ScopeStore {
    operations: BTreeMap<CursorKey, CanonicalOperation>,
    by_id: BTreeMap<OperationId, CanonicalOperation>,
    by_sequence: BTreeMap<(DeviceId, u64), OperationId>,
    checkpoint_logs: BTreeMap<u16, CheckpointLog>,
    pending_hints: usize,
}

#[derive(Default)]
struct CheckpointLog {
    checkpoints: BTreeMap<CheckpointCursorKey, CanonicalCheckpoint>,
    by_hash: BTreeMap<Sha256Digest, Vec<u8>>,
}

#[derive(Default)]
pub struct InMemoryTransport {
    scopes: BTreeMap<(AccountId, WorkspaceId), ScopeStore>,
    next_receipt: u64,
    faults: FaultSchedule,
}

impl InMemoryTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_faults(faults: FaultSchedule) -> Self {
        Self {
            faults,
            ..Self::default()
        }
    }

    pub fn schedule_faults(&mut self, faults: FaultSchedule) {
        self.faults = faults;
    }

    pub fn take_change_hint(&mut self, scope: SyncScope) -> bool {
        let Some(store) = self.scopes.get_mut(&scope_key(scope)) else {
            return false;
        };
        if store.pending_hints == 0 {
            return false;
        }
        if consume(&mut self.faults.lost_hints) {
            store.pending_hints -= 1;
            return false;
        }
        store.pending_hints -= 1;
        true
    }

    fn next_received_at(&mut self) -> String {
        self.next_receipt = self.next_receipt.saturating_add(1);
        format!("memory-{receipt:020}", receipt = self.next_receipt)
    }
}

impl SyncTransport for InMemoryTransport {
    fn push_operations(
        &mut self,
        scope: SyncScope,
        batch: &[CanonicalOperation],
    ) -> Result<PushReceipt, TransportError> {
        if batch.len() > MAX_BATCH_OPERATIONS || batch.len() > MAX_PAGE {
            return Err(TransportError::Configuration);
        }
        let mut batch_bytes = 0usize;
        for operation in batch {
            batch_bytes = batch_bytes
                .checked_add(operation.bytes.len())
                .ok_or(TransportError::Configuration)?;
            if batch_bytes > MAX_BATCH_BYTES {
                return Err(TransportError::Configuration);
            }
        }
        if consume(&mut self.faults.transient_pushes) {
            return Err(TransportError::Transient);
        }

        let key = scope_key(scope);
        let store = self.scopes.entry(key).or_default();
        let mut accepted = Vec::new();
        let mut duplicates = Vec::new();
        let mut seen = BTreeMap::<OperationId, CanonicalOperation>::new();
        let mut new_sequences = BTreeMap::<(DeviceId, u64), OperationId>::new();

        for item in batch {
            validate_canonical_operation(scope, item)?;
            if let Some(prior) = seen.get(&item.operation_id) {
                if prior != item {
                    return Err(TransportError::Integrity);
                }
                continue;
            }
            seen.insert(item.operation_id, item.clone());

            if let Some(existing) = store.by_id.get(&item.operation_id) {
                if existing != item {
                    return Err(TransportError::Integrity);
                }
                duplicates.push(item.operation_id);
                continue;
            }
            let sequence = (item.device_id, item.device_sequence);
            if store.by_sequence.contains_key(&sequence)
                || new_sequences.insert(sequence, item.operation_id).is_some()
            {
                return Err(TransportError::Integrity);
            }
            accepted.push(item.operation_id);
        }

        if !accepted.is_empty() {
            let received_at = self.next_received_at();
            let store = self.scopes.entry(key).or_default();
            for operation_id in &accepted {
                let operation = seen
                    .get(operation_id)
                    .expect("accepted operation was validated")
                    .clone();
                let cursor = CursorKey {
                    received_at: received_at.clone(),
                    operation_id: *operation_id,
                };
                store.by_sequence.insert(
                    (operation.device_id, operation.device_sequence),
                    operation.operation_id,
                );
                store
                    .by_id
                    .insert(operation.operation_id, operation.clone());
                store.operations.insert(cursor, operation);
            }
            store.pending_hints = store.pending_hints.saturating_add(1);
        }

        Ok(PushReceipt {
            accepted,
            duplicates,
        })
    }

    fn pull_operations(
        &mut self,
        scope: SyncScope,
        after: Option<&SyncCursor>,
        limit: usize,
    ) -> Result<PullPage, TransportError> {
        if consume(&mut self.faults.transient_pulls) {
            return Err(TransportError::Transient);
        }
        if consume(&mut self.faults.dropped_pulls) || consume(&mut self.faults.delayed_pulls) {
            return Ok(PullPage {
                rows: Vec::new(),
                next_cursor: None,
            });
        }
        let limit = limit.min(MAX_PAGE);
        if limit == 0 {
            return Ok(PullPage {
                rows: Vec::new(),
                next_cursor: None,
            });
        }
        let after = after.map(CursorKey::from_cursor);
        let mut rows = self
            .scopes
            .get(&scope_key(scope))
            .into_iter()
            .flat_map(|store| store.operations.iter())
            .filter(|(cursor, _)| after.as_ref().is_none_or(|after| *cursor > after))
            .take(limit)
            .map(|(cursor, operation)| ReceivedOperation {
                cursor: cursor.cursor(),
                operation: operation.clone(),
            })
            .collect::<Vec<_>>();
        let next_cursor = rows.last().map(|row| row.cursor.clone());
        if consume(&mut self.faults.duplicated_pulls)
            && rows.len() < limit
            && let Some(first) = rows.first().cloned()
        {
            rows.push(first);
        }
        if consume(&mut self.faults.reversed_pulls) {
            rows.reverse();
        }
        Ok(PullPage { rows, next_cursor })
    }

    fn pull_device_range(
        &mut self,
        scope: SyncScope,
        device: DeviceId,
        range: RangeInclusive<u64>,
    ) -> Result<Vec<ReceivedOperation>, TransportError> {
        if consume(&mut self.faults.transient_ranges) {
            return Err(TransportError::Transient);
        }
        let count = range
            .end()
            .checked_sub(*range.start())
            .and_then(|difference| difference.checked_add(1))
            .ok_or(TransportError::Configuration)?;
        if count > MAX_PAGE as u64 {
            return Err(TransportError::Configuration);
        }
        let Some(store) = self.scopes.get(&scope_key(scope)) else {
            return Ok(Vec::new());
        };
        let mut rows = store
            .operations
            .iter()
            .filter(|(_, operation)| {
                operation.device_id == device && range.contains(&operation.device_sequence)
            })
            .map(|(cursor, operation)| ReceivedOperation {
                cursor: cursor.cursor(),
                operation: operation.clone(),
            })
            .collect::<Vec<_>>();
        rows.sort_by_key(|row| row.operation.device_sequence);
        Ok(rows)
    }

    fn push_checkpoint(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        checkpoint: &CanonicalCheckpoint,
    ) -> Result<CheckpointReceipt, TransportError> {
        if checkpoint_version != CHECKPOINT_SCHEMA_VERSION
            || checkpoint.checkpoint.schema_version != checkpoint_version
        {
            return Err(TransportError::CheckpointVersionUnsupported);
        }
        if checkpoint.bytes.len() > context_relay_protocol::MAX_CBOR_OPERATION_BYTES {
            return Err(TransportError::Configuration);
        }
        validate_canonical_checkpoint(scope, checkpoint)?;
        let key = scope_key(scope);
        if let Some(existing) = self
            .scopes
            .get(&key)
            .and_then(|store| store.checkpoint_logs.get(&checkpoint_version))
            .and_then(|log| log.by_hash.get(&checkpoint.canonical_hash))
        {
            return if existing == &checkpoint.bytes {
                Ok(CheckpointReceipt {
                    canonical_hash: checkpoint.canonical_hash,
                    duplicate: true,
                })
            } else {
                Err(TransportError::Integrity)
            };
        }
        let expected_previous = self
            .scopes
            .get(&key)
            .and_then(|store| store.checkpoint_logs.get(&checkpoint_version))
            .and_then(|log| log.checkpoints.last_key_value())
            .map_or(Sha256Digest([0; 32]), |(_, checkpoint)| {
                checkpoint.canonical_hash
            });
        if checkpoint.checkpoint.previous_checkpoint_hash != expected_previous {
            return Err(TransportError::Integrity);
        }
        let received_at = self.next_received_at();
        let cursor = CheckpointCursorKey {
            received_at,
            canonical_hash: checkpoint.canonical_hash,
        };
        let store = self.scopes.entry(key).or_default();
        let log = store.checkpoint_logs.entry(checkpoint_version).or_default();
        log.by_hash
            .insert(checkpoint.canonical_hash, checkpoint.bytes.clone());
        log.checkpoints.insert(cursor, checkpoint.clone());
        Ok(CheckpointReceipt {
            canonical_hash: checkpoint.canonical_hash,
            duplicate: false,
        })
    }

    fn pull_checkpoints(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        after: Option<&CheckpointCursor>,
        limit: usize,
    ) -> Result<CheckpointPage, TransportError> {
        if checkpoint_version != CHECKPOINT_SCHEMA_VERSION {
            return Err(TransportError::CheckpointVersionUnsupported);
        }
        let limit = limit.min(MAX_PAGE);
        let after = after.map(CheckpointCursorKey::from_cursor);
        let log = self
            .scopes
            .get(&scope_key(scope))
            .and_then(|store| store.checkpoint_logs.get(&checkpoint_version));
        if let Some(anchor) = after.as_ref()
            && log.is_none_or(|log| !log.checkpoints.contains_key(anchor))
        {
            return Err(TransportError::Integrity);
        }
        let mut total_bytes = 0usize;
        let rows = log
            .into_iter()
            .flat_map(|log| log.checkpoints.iter())
            .filter(|(cursor, _)| after.as_ref().is_none_or(|after| *cursor > after))
            .take(limit)
            .take_while(|(_, checkpoint)| {
                let Some(next) = total_bytes.checked_add(checkpoint.bytes.len()) else {
                    return false;
                };
                if next > MAX_BATCH_BYTES {
                    return false;
                }
                total_bytes = next;
                true
            })
            .map(|(cursor, checkpoint)| ReceivedCheckpoint {
                cursor: cursor.cursor(),
                checkpoint: checkpoint.clone(),
            })
            .collect::<Vec<_>>();
        let next_cursor = rows.last().map(|row| row.cursor.clone());
        Ok(CheckpointPage { rows, next_cursor })
    }

    fn checkpoint_by_hash(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        canonical_hash: Sha256Digest,
    ) -> Result<Option<CanonicalCheckpoint>, TransportError> {
        if checkpoint_version != CHECKPOINT_SCHEMA_VERSION {
            return Err(TransportError::CheckpointVersionUnsupported);
        }
        let Some(bytes) = self
            .scopes
            .get(&scope_key(scope))
            .and_then(|store| store.checkpoint_logs.get(&checkpoint_version))
            .and_then(|log| log.by_hash.get(&canonical_hash))
        else {
            return Ok(None);
        };
        let decoded = decode_checkpoint_v1(bytes).map_err(|_| TransportError::Integrity)?;
        let checkpoint =
            CanonicalCheckpoint::from_checkpoint(decoded).map_err(|_| TransportError::Integrity)?;
        validate_canonical_checkpoint(scope, &checkpoint)?;
        if checkpoint.canonical_hash != canonical_hash {
            return Err(TransportError::Integrity);
        }
        Ok(Some(checkpoint))
    }
}

fn validate_canonical_operation(
    scope: SyncScope,
    value: &CanonicalOperation,
) -> Result<(), TransportError> {
    let decoded = decode_sync_operation_v1(&value.bytes).map_err(|_| TransportError::Integrity)?;
    decoded.validate().map_err(|_| TransportError::Integrity)?;
    let canonical = encode_sync_operation_v1(&decoded).map_err(|_| TransportError::Integrity)?;
    if canonical != value.bytes
        || decoded.operation_id != value.operation_id
        || decoded.device_id != value.device_id
        || decoded.device_sequence != value.device_sequence
        || decoded.account_id != scope.account_id
        || decoded.workspace_id != scope.workspace_id
    {
        return Err(TransportError::Integrity);
    }
    Ok(())
}

fn validate_canonical_checkpoint(
    scope: SyncScope,
    value: &CanonicalCheckpoint,
) -> Result<(), TransportError> {
    let decoded = decode_checkpoint_v1(&value.bytes).map_err(|_| TransportError::Integrity)?;
    let canonical = encode_checkpoint_v1(&decoded).map_err(|_| TransportError::Integrity)?;
    let canonical_hash = Sha256Digest(Sha256::digest(&canonical).into());
    if canonical != value.bytes
        || decoded != value.checkpoint
        || decoded.state_hash != value.state_hash
        || canonical_hash != value.canonical_hash
        || decoded.account_id != scope.account_id
        || decoded.workspace_id != scope.workspace_id
    {
        return Err(TransportError::Integrity);
    }
    Ok(())
}

fn scope_key(scope: SyncScope) -> (AccountId, WorkspaceId) {
    (scope.account_id, scope.workspace_id)
}

fn consume(counter: &mut usize) -> bool {
    if *counter == 0 {
        return false;
    }
    *counter -= 1;
    true
}
