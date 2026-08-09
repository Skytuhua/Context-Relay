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

struct CheckpointPullResult {
    accepted: usize,
    more_work: bool,
    chain_anchor: Option<CheckpointChainAnchor>,
    append_anchor: Option<CheckpointAppendAnchor>,
}

struct CheckpointChainAnchor {
    verified: VerifiedCheckpointChainAnchor,
}

enum CheckpointAppendAnchor {
    Empty,
    Endpoint {
        cursor: CheckpointCursor,
        canonical_hash: Sha256Digest,
    },
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
        let mut report = SyncCycleReport::empty();
        self.push_due(vault, transport, now_ms, &mut report)?;

        let mut processed = 0usize;
        let mut processed_bytes = 0usize;
        while processed < self.max_operations {
            let cursor = vault
                .sync_cursor(self.scope.workspace_id, self.provider.as_str())
                .map_err(local_error)?;
            let page_limit = (self.max_operations - processed).min(MAX_BATCH);
            let mut page = transport
                .pull_operations(self.scope, cursor.as_ref(), page_limit)
                .map_err(transport_error)?;
            validate_page(
                cursor.as_ref(),
                &page.rows,
                page.next_cursor.as_ref(),
                page_limit,
            )?;
            if page.rows.is_empty() {
                break;
            }
            page.rows.sort_by(compare_received);
            report.pulled = report.pulled.saturating_add(page.rows.len());

            for row in page.rows {
                validate_receipt_binding(&row)?;
                if processed == self.max_operations {
                    report.more_work = true;
                    return Ok(report);
                }
                if let Some(stored) = self.existing_quarantine(vault, &row)? {
                    validate_existing_quarantine(&stored, &row)?;
                    self.persist_quarantine(vault, &row, &stored.safe_error_code, now_ms, true)?;
                    report.quarantined += 1;
                    processed += 1;
                    continue;
                }
                if let Some(stored) = self.existing_rejection(vault, &row)? {
                    validate_existing_rejection(&stored, &row)?;
                    self.persist_rejection(vault, &row, now_ms, true)?;
                    report.quarantined += 1;
                    processed += 1;
                    continue;
                }
                if row.operation.bytes.len() > MAX_CBOR_OPERATION_BYTES {
                    self.persist_rejection(vault, &row, now_ms, true)?;
                    report.quarantined += 1;
                    processed += 1;
                    continue;
                }
                if !reserve_bytes(
                    &mut processed_bytes,
                    row.operation.bytes.len(),
                    self.max_bytes,
                ) {
                    report.more_work = true;
                    return Ok(report);
                }
                if validate_received(self.scope, &row).is_err() {
                    self.persist_quarantine(vault, &row, "integrity_quarantined", now_ms, true)?;
                    report.quarantined += 1;
                    processed += 1;
                    continue;
                }
                match admit_operation(vault, &row.operation.bytes, trusted_material) {
                    Ok(AdmissionDecision::ExactReplay(operation_id)) => {
                        if operation_id != row.operation.operation_id {
                            return Err(SyncCycleError::new("integrity_quarantined"));
                        }
                        vault
                            .advance_replay_cursor(
                                self.scope.workspace_id,
                                self.provider.as_str(),
                                &row.cursor.received_at,
                                operation_id,
                            )
                            .map_err(local_error)?;
                        processed += 1;
                    }
                    Ok(AdmissionDecision::Admitted(admitted)) => {
                        let decision = vault
                            .apply_admitted_operation_at(
                                &admitted,
                                trusted_material,
                                self.provider.as_str(),
                                &row.cursor.received_at,
                                embedding_resolver,
                                now_ms,
                            )
                            .map_err(local_error)?;
                        record_apply(&mut report, decision);
                        processed += 1;
                    }
                    Ok(AdmissionDecision::Gap(range)) => {
                        processed_bytes -= row.operation.bytes.len();
                        match self.repair_gap(
                            vault,
                            transport,
                            trusted_material,
                            embedding_resolver,
                            row.operation.device_id,
                            range,
                            &mut processed,
                            &mut processed_bytes,
                            &mut report,
                            now_ms,
                        )? {
                            GapRepairOutcome::Complete => {}
                            GapRepairOutcome::Pending => {
                                report.more_work = true;
                                return Ok(report);
                            }
                            GapRepairOutcome::BlockedByQuarantine => {
                                if processed == self.max_operations
                                    || !reserve_bytes(
                                        &mut processed_bytes,
                                        row.operation.bytes.len(),
                                        self.max_bytes,
                                    )
                                {
                                    report.more_work = true;
                                    return Ok(report);
                                }
                                self.persist_quarantine(vault, &row, "gap_pending", now_ms, true)?;
                                report.quarantined += 1;
                                processed += 1;
                                continue;
                            }
                        }
                        if processed == self.max_operations {
                            report.more_work = true;
                            return Ok(report);
                        }
                        if !reserve_bytes(
                            &mut processed_bytes,
                            row.operation.bytes.len(),
                            self.max_bytes,
                        ) {
                            report.more_work = true;
                            return Ok(report);
                        }
                        match admit_operation(vault, &row.operation.bytes, trusted_material) {
                            Ok(AdmissionDecision::Admitted(admitted)) => {
                                let decision = vault
                                    .apply_admitted_operation_at(
                                        &admitted,
                                        trusted_material,
                                        self.provider.as_str(),
                                        &row.cursor.received_at,
                                        embedding_resolver,
                                        now_ms,
                                    )
                                    .map_err(local_error)?;
                                record_apply(&mut report, decision);
                                processed += 1;
                            }
                            Ok(AdmissionDecision::ExactReplay(operation_id)) => {
                                if operation_id != row.operation.operation_id {
                                    return Err(SyncCycleError::new("integrity_quarantined"));
                                }
                                vault
                                    .advance_replay_cursor(
                                        self.scope.workspace_id,
                                        self.provider.as_str(),
                                        &row.cursor.received_at,
                                        operation_id,
                                    )
                                    .map_err(local_error)?;
                                processed += 1;
                            }
                            Ok(AdmissionDecision::Gap(_)) => {
                                report.more_work = true;
                                return Ok(report);
                            }
                            Err(error) => {
                                require_quarantinable(error)?;
                                self.persist_quarantine(
                                    vault,
                                    &row,
                                    "integrity_quarantined",
                                    now_ms,
                                    true,
                                )?;
                                report.quarantined += 1;
                                processed += 1;
                            }
                        }
                    }
                    Err(error) => {
                        require_quarantinable(error)?;
                        self.persist_quarantine(
                            vault,
                            &row,
                            "integrity_quarantined",
                            now_ms,
                            true,
                        )?;
                        report.quarantined += 1;
                        processed += 1;
                    }
                }
            }
        }
        if processed == self.max_operations {
            report.more_work = true;
        }
        Ok(report)
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
        let checkpoint_pull =
            self.pull_checkpoint_chain(vault, transport, trusted_material, now_ms)?;
        if checkpoint_pull.accepted > 0 {
            report.checkpointed = true;
        }
        report.more_work |= checkpoint_pull.more_work;
        if checkpoint_pull.more_work {
            return Ok(report);
        }
        let schedule = vault
            .sync_checkpoint_schedule(self.scope)
            .map_err(checkpoint_vault_error)?;
        if !schedule.is_due(now_ms) {
            return Ok(report);
        }
        let checkpoint = if let Some(anchor) = checkpoint_pull.chain_anchor.as_ref() {
            build_checkpoint_after_chain(
                vault,
                checkpoint_context,
                trusted_material,
                &anchor.verified,
            )
            .map_err(sync_error)?
        } else {
            build_checkpoint(vault, checkpoint_context, trusted_material).map_err(sync_error)?
        };
        let receipt = transport
            .push_checkpoint(self.scope, CHECKPOINT_SCHEMA_VERSION, &checkpoint)
            .map_err(transport_error)?;
        if receipt.canonical_hash != checkpoint.canonical_hash {
            return Err(SyncCycleError::new("integrity_quarantined"));
        }
        let append_anchor = checkpoint_pull
            .append_anchor
            .as_ref()
            .ok_or_else(|| SyncCycleError::new("integrity_quarantined"))?;
        self.confirm_checkpoint_append(transport, append_anchor, &checkpoint, trusted_material)?;
        if let Some(anchor) = checkpoint_pull.chain_anchor.as_ref() {
            let verified = verify_checkpoint_chain_extension(
                vault,
                self.scope,
                &checkpoint,
                &anchor.verified,
                trusted_material,
            )
            .map_err(sync_error)?;
            vault
                .accept_sync_checkpoint_chain_extension(
                    &verified,
                    now_ms,
                    self.provider.as_str(),
                    anchor.verified.checkpoint.canonical_hash,
                )
                .map_err(checkpoint_vault_error)?;
        } else {
            let verified = verify_checkpoint(vault, self.scope, &checkpoint, trusted_material)
                .map_err(sync_error)?;
            vault
                .accept_sync_checkpoint(&verified, now_ms)
                .map_err(checkpoint_vault_error)?;
        }
        report.checkpointed = true;
        Ok(report)
    }

    fn pull_checkpoint_chain<T, M>(
        &self,
        vault: &mut Vault,
        transport: &mut T,
        trusted_material: &M,
        now_ms: u64,
    ) -> Result<CheckpointPullResult, SyncCycleError>
    where
        T: SyncTransport,
        M: TrustedSyncMaterial,
    {
        let initial_pin = vault
            .sync_checkpoint_pin(self.scope)
            .map_err(checkpoint_vault_error)?;
        if let Some(pin) = initial_pin.as_ref() {
            let remote_pin = transport
                .checkpoint_by_hash(self.scope, CHECKPOINT_SCHEMA_VERSION, pin.canonical_hash)
                .map_err(transport_error)?
                .ok_or_else(|| SyncCycleError::new("integrity_quarantined"))?;
            if remote_pin.bytes != pin.canonical_bytes || remote_pin.state_hash != pin.state_hash {
                return Err(SyncCycleError::new("integrity_quarantined"));
            }
        }
        let scan = vault
            .sync_checkpoint_scan(self.scope, self.provider.as_str())
            .map_err(checkpoint_vault_error)?;
        let base_pin_hash = initial_pin.as_ref().map(|pin| pin.canonical_hash);
        if scan
            .as_ref()
            .is_some_and(|scan| scan.base_pin_hash != base_pin_hash)
        {
            return Err(SyncCycleError::new("integrity_quarantined"));
        }
        let mut found_pin = scan
            .as_ref()
            .map_or(initial_pin.is_none(), |scan| scan.pin_seen);
        let mut after = scan.as_ref().map(|scan| scan.cursor.clone());
        let mut expected_previous = scan
            .as_ref()
            .map_or(Sha256Digest([0; 32]), |scan| scan.checkpoint.canonical_hash);
        let mut scanned = 0usize;
        loop {
            let remaining = self.max_operations.saturating_sub(scanned);
            if remaining == 0 {
                return Ok(CheckpointPullResult {
                    accepted: 0,
                    more_work: true,
                    chain_anchor: None,
                    append_anchor: None,
                });
            }
            let limit = remaining.min(MAX_BATCH);
            let page = transport
                .pull_checkpoints(self.scope, CHECKPOINT_SCHEMA_VERSION, after.as_ref(), limit)
                .map_err(transport_error)?;
            validate_checkpoint_page(after.as_ref(), &page.rows, page.next_cursor.as_ref(), limit)?;
            if page.rows.is_empty() {
                if !found_pin {
                    return Err(SyncCycleError::new("integrity_quarantined"));
                }
                let Some(scan) = vault
                    .sync_checkpoint_scan(self.scope, self.provider.as_str())
                    .map_err(checkpoint_vault_error)?
                else {
                    return Ok(CheckpointPullResult {
                        accepted: 0,
                        more_work: false,
                        chain_anchor: None,
                        append_anchor: Some(CheckpointAppendAnchor::Empty),
                    });
                };
                let (chain_anchor, verified) = verify_checkpoint_after_chain(
                    vault,
                    self.scope,
                    &scan.checkpoint,
                    scan.base_pin_hash,
                    trusted_material,
                )
                .map_err(sync_error)?;
                if let Some(verified) = verified {
                    vault
                        .accept_sync_checkpoint_endpoint(&verified, now_ms, self.provider.as_str())
                        .map_err(checkpoint_vault_error)?;
                    return Ok(CheckpointPullResult {
                        accepted: 1,
                        more_work: false,
                        chain_anchor: None,
                        append_anchor: Some(CheckpointAppendAnchor::Endpoint {
                            cursor: scan.cursor,
                            canonical_hash: chain_anchor.checkpoint.canonical_hash,
                        }),
                    });
                }
                let append_cursor = scan.cursor.clone();
                let append_hash = chain_anchor.checkpoint.canonical_hash;
                return Ok(CheckpointPullResult {
                    accepted: 0,
                    more_work: false,
                    chain_anchor: Some(CheckpointChainAnchor {
                        verified: chain_anchor,
                    }),
                    append_anchor: Some(CheckpointAppendAnchor::Endpoint {
                        cursor: append_cursor,
                        canonical_hash: append_hash,
                    }),
                });
            }
            for row in page.rows {
                scanned = scanned.saturating_add(1);
                validate_received_checkpoint(&row)?;
                let authenticated = verify_checkpoint_link(
                    self.scope,
                    &row.checkpoint,
                    expected_previous,
                    trusted_material,
                )
                .map_err(sync_error)?;
                if let Some(pin) = initial_pin.as_ref()
                    && row.checkpoint.canonical_hash == pin.canonical_hash
                {
                    if row.checkpoint.bytes != pin.canonical_bytes
                        || row.checkpoint.state_hash != pin.state_hash
                    {
                        return Err(SyncCycleError::new("integrity_quarantined"));
                    }
                    found_pin = true;
                }
                vault
                    .save_sync_checkpoint_scan(
                        self.scope,
                        self.provider.as_str(),
                        &row.cursor,
                        &authenticated,
                        base_pin_hash,
                        found_pin,
                    )
                    .map_err(checkpoint_vault_error)?;
                expected_previous = row.checkpoint.canonical_hash;
                after = Some(row.cursor);
            }
            if scanned == self.max_operations {
                return Ok(CheckpointPullResult {
                    accepted: 0,
                    more_work: true,
                    chain_anchor: None,
                    append_anchor: None,
                });
            }
        }
    }

    fn confirm_checkpoint_append<T, M>(
        &self,
        transport: &mut T,
        anchor: &CheckpointAppendAnchor,
        checkpoint: &super::CanonicalCheckpoint,
        trusted_material: &M,
    ) -> Result<(), SyncCycleError>
    where
        T: SyncTransport,
        M: TrustedSyncMaterial,
    {
        let (after, expected_previous) = match anchor {
            CheckpointAppendAnchor::Empty => (None, Sha256Digest([0; 32])),
            CheckpointAppendAnchor::Endpoint {
                cursor,
                canonical_hash,
            } => (Some(cursor), *canonical_hash),
        };
        let page = transport
            .pull_checkpoints(self.scope, CHECKPOINT_SCHEMA_VERSION, after, 2)
            .map_err(transport_error)?;
        validate_checkpoint_page(after, &page.rows, page.next_cursor.as_ref(), 2)?;
        let [row] = page.rows.as_slice() else {
            return Err(SyncCycleError::new("integrity_quarantined"));
        };
        validate_received_checkpoint(row)?;
        let authenticated = verify_checkpoint_link(
            self.scope,
            &row.checkpoint,
            expected_previous,
            trusted_material,
        )
        .map_err(sync_error)?;
        if authenticated.checkpoint != *checkpoint {
            return Err(SyncCycleError::new("integrity_quarantined"));
        }
        let tail = transport
            .pull_checkpoints(self.scope, CHECKPOINT_SCHEMA_VERSION, Some(&row.cursor), 1)
            .map_err(transport_error)?;
        validate_checkpoint_page(Some(&row.cursor), &tail.rows, tail.next_cursor.as_ref(), 1)?;
        if !tail.rows.is_empty() {
            return Err(SyncCycleError::new("integrity_quarantined"));
        }
        Ok(())
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
        let due = vault.due_outbox(now_ms, MAX_BATCH).map_err(local_error)?;
        if due.is_empty() {
            return Ok(());
        }
        report.more_work |= due.len() == MAX_BATCH;
        let mut batch = Vec::with_capacity(due.len());
        let mut ids = Vec::with_capacity(due.len());
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
                report.more_work = true;
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
                report.more_work = true;
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
                    report.more_work = true;
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
                    report.more_work = true;
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
                report.more_work = true;
                break;
            }
            total_bytes = next_total;
            ids.push(row.operation_id);
            batch.push(CanonicalOperation {
                operation_id: operation.operation_id,
                device_id: operation.device_id,
                device_sequence: operation.device_sequence,
                bytes: canonical,
            });
        }

        let receipt = match transport.push_operations(self.scope, &batch) {
            Ok(receipt) => receipt,
            Err(error) => {
                self.defer_transport_failure(vault, &due[..ids.len()], now_ms, error)?;
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
        Ok(())
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

    #[allow(clippy::too_many_arguments)]
    fn repair_gap<T, M, R>(
        &self,
        vault: &mut Vault,
        transport: &mut T,
        trusted_material: &M,
        embedding_resolver: &R,
        device: context_relay_protocol::DeviceId,
        range: std::ops::RangeInclusive<u64>,
        processed: &mut usize,
        processed_bytes: &mut usize,
        report: &mut SyncCycleReport,
        now_ms: u64,
    ) -> Result<GapRepairOutcome, SyncCycleError>
    where
        T: SyncTransport,
        M: TrustedSyncMaterial,
        R: RepresentativeEmbeddingResolver,
    {
        let mut next = *range.start();
        let end = *range.end();
        while next <= end {
            if *processed == self.max_operations {
                return Ok(GapRepairOutcome::Pending);
            }
            let capacity = (self.max_operations - *processed).min(MAX_BATCH) as u64;
            let chunk_end = next.saturating_add(capacity.saturating_sub(1)).min(end);
            let mut rows = transport
                .pull_device_range(self.scope, device, next..=chunk_end)
                .map_err(transport_error)?;
            rows.sort_by_key(|row| row.operation.device_sequence);
            let expected_count = usize::try_from(chunk_end - next + 1)
                .map_err(|_| SyncCycleError::new("configuration_error"))?;
            if rows.len() != expected_count {
                return Ok(GapRepairOutcome::Pending);
            }
            for (offset, row) in rows.iter().enumerate() {
                let expected = next + offset as u64;
                if row.operation.device_id != device || row.operation.device_sequence != expected {
                    return Err(SyncCycleError::new("integrity_quarantined"));
                }
                validate_receipt_binding(row)?;
            }
            for row in rows {
                if let Some(stored) = self.existing_quarantine(vault, &row)? {
                    validate_existing_quarantine(&stored, &row)?;
                    report.quarantined += 1;
                    return Ok(GapRepairOutcome::BlockedByQuarantine);
                }
                if let Some(stored) = self.existing_rejection(vault, &row)? {
                    validate_existing_rejection(&stored, &row)?;
                    report.quarantined += 1;
                    return Ok(GapRepairOutcome::BlockedByQuarantine);
                }
                if row.operation.bytes.len() > MAX_CBOR_OPERATION_BYTES {
                    self.persist_rejection(vault, &row, now_ms, false)?;
                    report.quarantined += 1;
                    return Ok(GapRepairOutcome::BlockedByQuarantine);
                }
                if !reserve_bytes(processed_bytes, row.operation.bytes.len(), self.max_bytes) {
                    return Ok(GapRepairOutcome::Pending);
                }
                if validate_received(self.scope, &row).is_err() {
                    self.persist_quarantine(vault, &row, "integrity_quarantined", now_ms, false)?;
                    report.quarantined += 1;
                    return Ok(GapRepairOutcome::BlockedByQuarantine);
                }
                match admit_operation(vault, &row.operation.bytes, trusted_material) {
                    Ok(AdmissionDecision::Admitted(admitted)) => {
                        let decision = vault
                            .apply_repaired_operation_at(
                                &admitted,
                                trusted_material,
                                &row.cursor.received_at,
                                embedding_resolver,
                                now_ms,
                            )
                            .map_err(local_error)?;
                        record_apply(report, decision);
                    }
                    Ok(AdmissionDecision::ExactReplay(operation_id))
                        if operation_id == row.operation.operation_id => {}
                    Ok(AdmissionDecision::ExactReplay(_)) | Ok(AdmissionDecision::Gap(_)) => {
                        return Err(SyncCycleError::new("integrity_quarantined"));
                    }
                    Err(error) => {
                        require_quarantinable(error)?;
                        self.persist_quarantine(
                            vault,
                            &row,
                            "integrity_quarantined",
                            now_ms,
                            false,
                        )?;
                        report.quarantined += 1;
                        return Ok(GapRepairOutcome::BlockedByQuarantine);
                    }
                }
                *processed += 1;
                report.gaps_repaired += 1;
            }
            next = match chunk_end.checked_add(1) {
                Some(value) => value,
                None => break,
            };
        }
        Ok(GapRepairOutcome::Complete)
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
