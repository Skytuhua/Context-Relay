mod checkpoints;
pub use checkpoints::{
    CheckpointProgress, CheckpointRequest, CheckpointResponse, PreparedCheckpoint,
};
mod pull;
pub use pull::{PreparedPull, PullProgress, PullRequest, PullResponse};

use std::{collections::BTreeSet, error::Error, fmt};

use context_relay_protocol::{
    CHECKPOINT_SCHEMA_VERSION, MAX_CBOR_OPERATION_BYTES, OperationId, Sha256Digest,
    decode_checkpoint_v1, decode_sync_operation_v1, encode_checkpoint_v1, encode_sync_operation_v1,
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::vault::{
    DueOutboxOperation, StoredSyncQuarantine, StoredSyncRejection, SyncCursor, SyncQuarantineWrite,
    SyncRejectionWrite, Vault, VaultError,
};

use super::{
    AdmissionDecision, BackoffPolicy, CanonicalOperation, CheckpointBuildContext, CheckpointCursor,
    MergeDecision, ReceivedCheckpoint, ReceivedOperation, RepresentativeEmbeddingResolver,
    SyncError, SyncScope, SyncTransport, TransportError, TrustedSyncMaterial,
    VerifiedCheckpointChainAnchor, admit_operation, build_checkpoint, build_checkpoint_after_chain,
    verify_checkpoint, verify_checkpoint_after_chain, verify_checkpoint_chain_extension,
    verify_checkpoint_link,
};

const MAX_BATCH: usize = 256;
const DEFAULT_MAX_OPERATIONS: usize = 1_024;
const MAX_REQUEST_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_MAX_BYTES: usize = MAX_REQUEST_BYTES;
const PERMANENT_RETRY_MS: u64 = i64::MAX as u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GapRepairOutcome {
    Complete,
    Pending,
    BlockedByQuarantine,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncCycleReport {
    pub pushed: usize,
    pub duplicates: usize,
    pub pulled: usize,
    pub applied: usize,
    pub conflicts: usize,
    pub quarantined: usize,
    pub gaps_repaired: usize,
    pub checkpointed: bool,
    pub more_work: bool,
}

impl SyncCycleReport {
    const fn empty() -> Self {
        Self {
            pushed: 0,
            duplicates: 0,
            pulled: 0,
            applied: 0,
            conflicts: 0,
            quarantined: 0,
            gaps_repaired: 0,
            checkpointed: false,
            more_work: false,
        }
    }
}

/// Immutable push work prepared on the vault owner, movable across network waits.
/// Hosts must revalidate the original session before finishing on that same owner.
pub struct PreparedPush {
    scope: SyncScope,
    provider: SyncProvider,
    due: Vec<DueOutboxOperation>,
    operations: Vec<CanonicalOperation>,
    more_work: bool,
}

impl PreparedPush {
    pub const fn scope(&self) -> SyncScope {
        self.scope
    }
    pub fn operations(&self) -> &[CanonicalOperation] {
        &self.operations
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncCycleError {
    safe_code: &'static str,
}

impl SyncCycleError {
    pub const fn safe_code(self) -> &'static str {
        self.safe_code
    }

    const fn new(safe_code: &'static str) -> Self {
        Self { safe_code }
    }
}

impl fmt::Display for SyncCycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.safe_code)
    }
}

impl Error for SyncCycleError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncProvider {
    Memory,
    Supabase,
}

impl SyncProvider {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Supabase => "supabase",
        }
    }
}

pub trait RetryRandomSource {
    fn random_u64(&self, operation_id: OperationId, attempt: u32) -> u64;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SystemRetryRandom;

impl RetryRandomSource for SystemRetryRandom {
    fn random_u64(&self, _operation_id: OperationId, _attempt: u32) -> u64 {
        let mut random = OsRng;
        let mut bytes = [0_u8; 8];
        if random.try_fill_bytes(&mut bytes).is_err() {
            return 0;
        }
        u64::from_le_bytes(bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncEngine<G = SystemRetryRandom> {
    scope: SyncScope,
    provider: SyncProvider,
    max_operations: usize,
    max_bytes: usize,
    backoff_policy: BackoffPolicy,
    retry_random: G,
}

impl SyncEngine<SystemRetryRandom> {
    pub const fn new(scope: SyncScope, provider: SyncProvider) -> Self {
        Self {
            scope,
            provider,
            max_operations: DEFAULT_MAX_OPERATIONS,
            max_bytes: DEFAULT_MAX_BYTES,
            backoff_policy: BackoffPolicy::DEFAULT,
            retry_random: SystemRetryRandom,
        }
    }
}

impl<G> SyncEngine<G> {
    #[must_use]
    pub fn with_retry_random_source<S>(self, retry_random: S) -> SyncEngine<S> {
        SyncEngine {
            scope: self.scope,
            provider: self.provider,
            max_operations: self.max_operations,
            max_bytes: self.max_bytes,
            backoff_policy: self.backoff_policy,
            retry_random,
        }
    }

    #[must_use]
    pub fn with_backoff_policy(mut self, backoff_policy: BackoffPolicy) -> Self {
        self.backoff_policy = backoff_policy;
        self
    }

    #[must_use]
    pub fn with_max_operations(mut self, max_operations: usize) -> Self {
        self.max_operations = max_operations.max(1);
        self
    }

    #[must_use]
    /// Sets the per-cycle byte budget within the fixed v1 8 MiB request ceiling.
    ///
    /// The lower bound is one maximum-size canonical operation so every legal
    /// operation can make progress.
    pub fn with_max_bytes(mut self, max_bytes: usize) -> Self {
        self.max_bytes = max_bytes.clamp(MAX_CBOR_OPERATION_BYTES, MAX_REQUEST_BYTES);
        self
    }

    pub fn sync_once<T, M, E>(
        &self,
        vault: &mut Vault,
        transport: &mut T,
        trusted_material: &M,
        embedding_resolver: &E,
        now_ms: u64,
    ) -> Result<SyncCycleReport, SyncCycleError>
    where
        T: SyncTransport,
        M: TrustedSyncMaterial,
        E: RepresentativeEmbeddingResolver,
        G: RetryRandomSource,
    {
        let mut pushed = SyncCycleReport::empty();
        self.push_due(vault, transport, now_ms, &mut pushed)?;
        let mut progress = self.prepare_pull(vault)?;
        loop {
            progress = match progress {
                PullProgress::Complete(mut report) => {
                    report.pushed += pushed.pushed;
                    report.duplicates += pushed.duplicates;
                    report.more_work |= pushed.more_work;
                    return Ok(report);
                }
                PullProgress::Request(prepared) => {
                    let response = match prepared.request() {
                        PullRequest::Operations { cursor, limit } => PullResponse::Operations(
                            transport
                                .pull_operations(prepared.scope(), cursor.as_ref(), *limit)
                                .map_err(transport_error)?,
                        ),
                        PullRequest::DeviceRange { device, range } => PullResponse::DeviceRange(
                            transport
                                .pull_device_range(prepared.scope(), *device, range.clone())
                                .map_err(transport_error)?,
                        ),
                    };
                    self.finish_pull(
                        vault,
                        *prepared,
                        response,
                        trusted_material,
                        embedding_resolver,
                        now_ms,
                    )?
                }
            };
        }
    }

    pub fn sync_once_with_checkpoint<T, M, E>(
        &self,
        vault: &mut Vault,
        transport: &mut T,
        trusted_material: &M,
        embedding_resolver: &E,
        now_ms: u64,
        checkpoint_context: &CheckpointBuildContext<'_>,
    ) -> Result<SyncCycleReport, SyncCycleError>
    where
        T: SyncTransport,
        M: TrustedSyncMaterial,
        E: RepresentativeEmbeddingResolver,
        G: RetryRandomSource,
    {
        if checkpoint_context.scope != self.scope {
            return Err(SyncCycleError::new("configuration_error"));
        }
        let mut report = self.sync_once(
            vault,
            transport,
            trusted_material,
            embedding_resolver,
            now_ms,
        )?;
        let mut progress = self.prepare_checkpoint(vault)?;
        loop {
            progress = match progress {
                CheckpointProgress::Complete(checkpoints) => {
                    report.checkpointed |= checkpoints.checkpointed;
                    report.more_work |= checkpoints.more_work;
                    return Ok(report);
                }
                CheckpointProgress::Request(prepared) => {
                    let response = match prepared.request() {
                        CheckpointRequest::ByHash(hash) => CheckpointResponse::ByHash(
                            transport
                                .checkpoint_by_hash(self.scope, CHECKPOINT_SCHEMA_VERSION, *hash)
                                .map_err(transport_error)?
                                .map(Box::new),
                        ),
                        CheckpointRequest::Page { after, limit } => CheckpointResponse::Page(
                            transport
                                .pull_checkpoints(
                                    self.scope,
                                    CHECKPOINT_SCHEMA_VERSION,
                                    after.as_ref(),
                                    *limit,
                                )
                                .map_err(transport_error)?,
                        ),
                        CheckpointRequest::Push(checkpoint) => CheckpointResponse::Push(
                            transport
                                .push_checkpoint(self.scope, CHECKPOINT_SCHEMA_VERSION, checkpoint)
                                .map_err(transport_error)?,
                        ),
                    };
                    self.finish_checkpoint(
                        vault,
                        *prepared,
                        response,
                        trusted_material,
                        now_ms,
                        checkpoint_context,
                    )?
                }
            };
        }
    }

    fn existing_quarantine(
        &self,
        vault: &Vault,
        row: &ReceivedOperation,
    ) -> Result<Option<StoredSyncQuarantine>, SyncCycleError> {
        vault
            .quarantined_sync_receipt(
                self.scope.account_id,
                self.scope.workspace_id,
                self.provider.as_str(),
                &row.cursor.received_at,
                row.cursor.operation_id,
            )
            .map_err(quarantine_vault_error)
    }

    fn persist_quarantine(
        &self,
        vault: &mut Vault,
        row: &ReceivedOperation,
        safe_error_code: &str,
        now_ms: u64,
        advance_cursor: bool,
    ) -> Result<(), SyncCycleError> {
        vault
            .quarantine_sync_receipt(&SyncQuarantineWrite {
                account_id: self.scope.account_id,
                workspace_id: self.scope.workspace_id,
                provider: self.provider.as_str(),
                received_at: &row.cursor.received_at,
                receipt_operation_id: row.cursor.operation_id,
                routed_operation_id: row.operation.operation_id,
                device_id: row.operation.device_id,
                device_sequence: row.operation.device_sequence,
                safe_error_code,
                envelope: &row.operation.bytes,
                quarantined_at_ms: now_ms,
                advance_cursor,
            })
            .map(|_| ())
            .map_err(quarantine_vault_error)
    }

    fn existing_rejection(
        &self,
        vault: &Vault,
        row: &ReceivedOperation,
    ) -> Result<Option<StoredSyncRejection>, SyncCycleError> {
        vault
            .rejected_sync_receipt(
                self.scope.account_id,
                self.scope.workspace_id,
                self.provider.as_str(),
                &row.cursor.received_at,
                row.cursor.operation_id,
            )
            .map_err(quarantine_vault_error)
    }

    fn persist_rejection(
        &self,
        vault: &mut Vault,
        row: &ReceivedOperation,
        now_ms: u64,
        advance_cursor: bool,
    ) -> Result<(), SyncCycleError> {
        vault
            .reject_oversized_sync_receipt(&SyncRejectionWrite {
                account_id: self.scope.account_id,
                workspace_id: self.scope.workspace_id,
                provider: self.provider.as_str(),
                received_at: &row.cursor.received_at,
                receipt_operation_id: row.cursor.operation_id,
                routed_operation_id: row.operation.operation_id,
                device_id: row.operation.device_id,
                device_sequence: row.operation.device_sequence,
                safe_error_code: "integrity_quarantined",
                received_bytes: &row.operation.bytes,
                rejected_at_ms: now_ms,
                advance_cursor,
            })
            .map(|_| ())
            .map_err(quarantine_vault_error)
    }

    fn push_due<T: SyncTransport>(
        &self,
        vault: &mut Vault,
        transport: &mut T,
        now_ms: u64,
        report: &mut SyncCycleReport,
    ) -> Result<(), SyncCycleError>
    where
        G: RetryRandomSource,
    {
        let Some(prepared) = self.prepare_push(vault, now_ms)? else {
            return Ok(());
        };
        let response = transport.push_operations(prepared.scope(), prepared.operations());
        let finished = self.finish_push(vault, prepared, response, now_ms)?;
        report.more_work |= finished.more_work;
        report.pushed += finished.pushed;
        report.duplicates += finished.duplicates;
        Ok(())
    }

    /// Select and validate a bounded push without performing network I/O.
    pub fn prepare_push(
        &self,
        vault: &mut Vault,
        now_ms: u64,
    ) -> Result<Option<PreparedPush>, SyncCycleError> {
        let mut due = vault.due_outbox(now_ms, MAX_BATCH).map_err(local_error)?;
        if due.is_empty() {
            return Ok(None);
        }
        let mut more_work = due.len() == MAX_BATCH;
        let mut batch = Vec::with_capacity(due.len());
        let mut total_bytes = 0usize;
        for row in &due {
            let Some(next_total) = total_bytes.checked_add(row.canonical_bytes.len()) else {
                if batch.is_empty() {
                    defer(
                        vault,
                        &[row.operation_id],
                        PERMANENT_RETRY_MS,
                        "configuration_error",
                    )?;
                    return Err(SyncCycleError::new("configuration_error"));
                }
                more_work = true;
                break;
            };
            if next_total > self.max_bytes || next_total > MAX_REQUEST_BYTES {
                if batch.is_empty() {
                    defer(
                        vault,
                        &[row.operation_id],
                        PERMANENT_RETRY_MS,
                        "configuration_error",
                    )?;
                    return Err(SyncCycleError::new("configuration_error"));
                }
                more_work = true;
                break;
            }
            let operation = match decode_sync_operation_v1(&row.canonical_bytes) {
                Ok(operation) => operation,
                Err(_) => {
                    if batch.is_empty() {
                        defer(
                            vault,
                            &[row.operation_id],
                            PERMANENT_RETRY_MS,
                            "integrity_quarantined",
                        )?;
                        return Err(SyncCycleError::new("integrity_quarantined"));
                    }
                    more_work = true;
                    break;
                }
            };
            let canonical = match encode_sync_operation_v1(&operation) {
                Ok(canonical) => canonical,
                Err(_) => {
                    if batch.is_empty() {
                        defer(
                            vault,
                            &[row.operation_id],
                            PERMANENT_RETRY_MS,
                            "integrity_quarantined",
                        )?;
                        return Err(SyncCycleError::new("integrity_quarantined"));
                    }
                    more_work = true;
                    break;
                }
            };
            if canonical != row.canonical_bytes
                || operation.operation_id != row.operation_id
                || operation.account_id != self.scope.account_id
                || operation.workspace_id != self.scope.workspace_id
            {
                if batch.is_empty() {
                    defer(
                        vault,
                        &[row.operation_id],
                        PERMANENT_RETRY_MS,
                        "integrity_quarantined",
                    )?;
                    return Err(SyncCycleError::new("integrity_quarantined"));
                }
                more_work = true;
                break;
            }
            total_bytes = next_total;
            batch.push(CanonicalOperation {
                operation_id: operation.operation_id,
                device_id: operation.device_id,
                device_sequence: operation.device_sequence,
                bytes: canonical,
            });
        }

        due.truncate(batch.len());
        Ok(Some(PreparedPush {
            scope: self.scope,
            provider: self.provider,
            due,
            operations: batch,
            more_work,
        }))
    }

    /// Apply a response only to the immutable operations selected before HTTP.
    pub fn finish_push(
        &self,
        vault: &mut Vault,
        prepared: PreparedPush,
        response: Result<super::PushReceipt, TransportError>,
        now_ms: u64,
    ) -> Result<SyncCycleReport, SyncCycleError>
    where
        G: RetryRandomSource,
    {
        if prepared.scope != self.scope || prepared.provider != self.provider {
            return Err(SyncCycleError::new("integrity_quarantined"));
        }
        for operation in &prepared.operations {
            if vault
                .stored_sync_operation(operation.operation_id)
                .map_err(local_error)?
                .as_ref()
                != Some(&operation.bytes)
            {
                return Err(SyncCycleError::new("integrity_quarantined"));
            }
        }
        let ids = prepared
            .operations
            .iter()
            .map(|operation| operation.operation_id)
            .collect::<Vec<_>>();
        let mut report = SyncCycleReport::empty();
        report.more_work = prepared.more_work;
        let receipt = match response {
            Ok(receipt) => receipt,
            Err(error) => {
                self.defer_transport_failure(vault, &prepared.due, now_ms, error)?;
                return Err(transport_error(error));
            }
        };
        let acknowledged = match validate_receipt(&ids, &receipt.accepted, &receipt.duplicates) {
            Ok(acknowledged) => acknowledged,
            Err(error) => {
                defer(vault, &ids, PERMANENT_RETRY_MS, error.safe_code())?;
                return Err(error);
            }
        };
        vault
            .acknowledge_outbox(&acknowledged)
            .map_err(local_error)?;
        report.pushed += receipt.accepted.len();
        report.duplicates += receipt.duplicates.len();
        report.more_work |= !vault.due_outbox(now_ms, 1).map_err(local_error)?.is_empty();
        Ok(report)
    }

    fn defer_transport_failure(
        &self,
        vault: &mut Vault,
        due: &[DueOutboxOperation],
        now_ms: u64,
        error: TransportError,
    ) -> Result<(), SyncCycleError>
    where
        G: RetryRandomSource,
    {
        if !error.is_retryable() {
            let ids = due.iter().map(|row| row.operation_id).collect::<Vec<_>>();
            return defer(vault, &ids, PERMANENT_RETRY_MS, error.safe_code());
        }
        if self.backoff_policy.validate().is_err() {
            let ids = due.iter().map(|row| row.operation_id).collect::<Vec<_>>();
            defer(vault, &ids, PERMANENT_RETRY_MS, "configuration_error")?;
            return Err(SyncCycleError::new("configuration_error"));
        }
        let retries = due
            .iter()
            .map(|row| {
                let random = self
                    .retry_random
                    .random_u64(row.operation_id, row.attempt_count);
                let delay = self.backoff_policy.next_delay(row.attempt_count, random);
                (
                    row.operation_id,
                    now_ms.saturating_add(delay).min(PERMANENT_RETRY_MS),
                )
            })
            .collect::<Vec<_>>();
        vault
            .defer_outbox_individual(&retries, error.safe_code())
            .map_err(local_error)
    }
}

fn validate_receipt(
    expected: &[OperationId],
    accepted: &[OperationId],
    duplicates: &[OperationId],
) -> Result<Vec<OperationId>, SyncCycleError> {
    let expected_len = expected.len();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if expected.len() != expected_len {
        return Err(SyncCycleError::new("configuration_error"));
    }
    let mut acknowledged = BTreeSet::new();
    for operation_id in accepted.iter().chain(duplicates) {
        if !expected.contains(operation_id) || !acknowledged.insert(*operation_id) {
            return Err(SyncCycleError::new("configuration_error"));
        }
    }
    if acknowledged != expected {
        return Err(SyncCycleError::new("configuration_error"));
    }
    Ok(acknowledged.into_iter().collect())
}

fn validate_page(
    after: Option<&SyncCursor>,
    rows: &[ReceivedOperation],
    next_cursor: Option<&SyncCursor>,
    limit: usize,
) -> Result<(), SyncCycleError> {
    if rows.len() > limit || rows.len() > MAX_BATCH {
        return Err(SyncCycleError::new("configuration_error"));
    }
    if rows.is_empty() {
        return if next_cursor.is_none() {
            Ok(())
        } else {
            Err(SyncCycleError::new("configuration_error"))
        };
    }
    let maximum = rows
        .iter()
        .map(|row| &row.cursor)
        .max_by(|left, right| compare_cursor(left, right))
        .expect("non-empty page has a maximum");
    if next_cursor != Some(maximum)
        || rows
            .iter()
            .any(|row| after.is_some_and(|after| compare_cursor(&row.cursor, after).is_le()))
    {
        return Err(SyncCycleError::new("configuration_error"));
    }
    Ok(())
}

fn validate_checkpoint_page(
    after: Option<&CheckpointCursor>,
    rows: &[ReceivedCheckpoint],
    next_cursor: Option<&CheckpointCursor>,
    limit: usize,
) -> Result<(), SyncCycleError> {
    if rows.len() > limit || rows.len() > MAX_BATCH {
        return Err(SyncCycleError::new("configuration_error"));
    }
    if rows.is_empty() {
        return if next_cursor.is_none() {
            Ok(())
        } else {
            Err(SyncCycleError::new("configuration_error"))
        };
    }
    let mut total_bytes = 0usize;
    for row in rows {
        total_bytes = total_bytes
            .checked_add(row.checkpoint.bytes.len())
            .ok_or_else(|| SyncCycleError::new("configuration_error"))?;
    }
    if total_bytes > MAX_REQUEST_BYTES
        || rows.windows(2).any(|pair| pair[0].cursor >= pair[1].cursor)
        || rows
            .iter()
            .any(|row| after.is_some_and(|after| row.cursor <= *after))
        || next_cursor != rows.last().map(|row| &row.cursor)
    {
        return Err(SyncCycleError::new("configuration_error"));
    }
    Ok(())
}

fn validate_received_checkpoint(row: &ReceivedCheckpoint) -> Result<(), SyncCycleError> {
    let received_at = row.cursor.received_at.as_str();
    if received_at.is_empty()
        || received_at.len() > 128
        || !received_at
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'\'' && byte != b'"')
        || row.cursor.canonical_hash != row.checkpoint.canonical_hash
        || row.checkpoint.bytes.len() > MAX_CBOR_OPERATION_BYTES
    {
        return Err(SyncCycleError::new("integrity_quarantined"));
    }
    let decoded = decode_checkpoint_v1(&row.checkpoint.bytes)
        .map_err(|_| SyncCycleError::new("integrity_quarantined"))?;
    let canonical =
        encode_checkpoint_v1(&decoded).map_err(|_| SyncCycleError::new("integrity_quarantined"))?;
    let canonical_hash = Sha256Digest(Sha256::digest(&canonical).into());
    if canonical != row.checkpoint.bytes
        || decoded != row.checkpoint.checkpoint
        || decoded.state_hash != row.checkpoint.state_hash
        || canonical_hash != row.checkpoint.canonical_hash
    {
        return Err(SyncCycleError::new("integrity_quarantined"));
    }
    Ok(())
}

fn validate_received(scope: SyncScope, row: &ReceivedOperation) -> Result<(), SyncCycleError> {
    let operation = decode_sync_operation_v1(&row.operation.bytes)
        .map_err(|_| SyncCycleError::new("integrity_quarantined"))?;
    let canonical = encode_sync_operation_v1(&operation)
        .map_err(|_| SyncCycleError::new("integrity_quarantined"))?;
    if canonical != row.operation.bytes
        || operation.operation_id != row.operation.operation_id
        || operation.device_id != row.operation.device_id
        || operation.device_sequence != row.operation.device_sequence
        || operation.account_id != scope.account_id
        || operation.workspace_id != scope.workspace_id
    {
        return Err(SyncCycleError::new("integrity_quarantined"));
    }
    Ok(())
}

fn validate_receipt_binding(row: &ReceivedOperation) -> Result<(), SyncCycleError> {
    let received_at = row.cursor.received_at.as_str();
    if row.cursor.operation_id != row.operation.operation_id
        || received_at.is_empty()
        || received_at.len() > 128
        || !received_at
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'\'' && byte != b'"')
    {
        return Err(SyncCycleError::new("integrity_quarantined"));
    }
    Ok(())
}

fn record_apply(report: &mut SyncCycleReport, decision: MergeDecision) {
    report.applied += 1;
    if matches!(decision, MergeDecision::AddConflictHead { .. }) {
        report.conflicts += 1;
    }
}

fn require_quarantinable(error: SyncError) -> Result<(), SyncCycleError> {
    match error {
        SyncError::InvalidIdentity => Err(SyncCycleError::new("revoked")),
        SyncError::PersistenceFailed => Err(SyncCycleError::new("transient")),
        _ => Ok(()),
    }
}

fn validate_existing_quarantine(
    stored: &StoredSyncQuarantine,
    row: &ReceivedOperation,
) -> Result<(), SyncCycleError> {
    if stored.receipt_operation_id != row.cursor.operation_id
        || stored.routed_operation_id != row.operation.operation_id
        || stored.device_id != row.operation.device_id
        || stored.device_sequence != row.operation.device_sequence
        || stored.envelope != row.operation.bytes
    {
        return Err(SyncCycleError::new("integrity_quarantined"));
    }
    Ok(())
}

fn validate_existing_rejection(
    stored: &StoredSyncRejection,
    row: &ReceivedOperation,
) -> Result<(), SyncCycleError> {
    let claimed_byte_length = u64::try_from(row.operation.bytes.len())
        .map_err(|_| SyncCycleError::new("integrity_quarantined"))?;
    let received_sha256 =
        context_relay_protocol::Sha256Digest(Sha256::digest(&row.operation.bytes).into());
    if stored.receipt_operation_id != row.cursor.operation_id
        || stored.routed_operation_id != row.operation.operation_id
        || stored.device_id != row.operation.device_id
        || stored.device_sequence != row.operation.device_sequence
        || stored.safe_error_code != "integrity_quarantined"
        || stored.claimed_byte_length != claimed_byte_length
        || stored.received_sha256 != received_sha256
    {
        return Err(SyncCycleError::new("integrity_quarantined"));
    }
    Ok(())
}

fn quarantine_vault_error(error: VaultError) -> SyncCycleError {
    match error {
        VaultError::OperationConflict | VaultError::Validation(_) => {
            SyncCycleError::new("integrity_quarantined")
        }
        _ => SyncCycleError::new("transient"),
    }
}

fn checkpoint_vault_error(error: VaultError) -> SyncCycleError {
    match error {
        VaultError::OperationConflict | VaultError::Validation(_) => {
            SyncCycleError::new("integrity_quarantined")
        }
        _ => SyncCycleError::new("transient"),
    }
}

fn reserve_bytes(total: &mut usize, addition: usize, maximum: usize) -> bool {
    let Some(next) = total.checked_add(addition) else {
        return false;
    };
    if next > maximum {
        return false;
    }
    *total = next;
    true
}

fn compare_received(left: &ReceivedOperation, right: &ReceivedOperation) -> std::cmp::Ordering {
    compare_cursor(&left.cursor, &right.cursor)
}

fn compare_cursor(left: &SyncCursor, right: &SyncCursor) -> std::cmp::Ordering {
    left.received_at
        .cmp(&right.received_at)
        .then_with(|| left.operation_id.cmp(&right.operation_id))
}

fn defer(
    vault: &mut Vault,
    ids: &[OperationId],
    next_ms: u64,
    safe_code: &str,
) -> Result<(), SyncCycleError> {
    vault
        .defer_outbox(ids, next_ms, safe_code)
        .map_err(local_error)
}

fn transport_error(error: TransportError) -> SyncCycleError {
    SyncCycleError::new(error.safe_code())
}

fn sync_error(error: SyncError) -> SyncCycleError {
    SyncCycleError::new(error.safe_code())
}

fn local_error(_error: VaultError) -> SyncCycleError {
    SyncCycleError::new("transient")
}
