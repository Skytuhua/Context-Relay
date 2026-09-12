use super::*;
use crate::sync::PullPage;
use std::{collections::VecDeque, ops::RangeInclusive};

pub enum PullRequest {
    Operations {
        cursor: Option<SyncCursor>,
        limit: usize,
    },
    DeviceRange {
        device: context_relay_protocol::DeviceId,
        range: RangeInclusive<u64>,
    },
}

pub enum PullResponse {
    Operations(PullPage),
    DeviceRange(Vec<ReceivedOperation>),
}

pub enum PullProgress {
    Request(Box<PreparedPull>),
    Complete(SyncCycleReport),
}

/// Owned continuation. Hosts must recheck the original session and current trust
/// before admitting a network response on the sole vault owner.
pub struct PreparedPull {
    state: PullState,
    request: PullRequest,
    expected_cursor: Option<SyncCursor>,
}

impl PreparedPull {
    pub const fn scope(&self) -> SyncScope {
        self.state.scope
    }
    pub const fn request(&self) -> &PullRequest {
        &self.request
    }
}

struct PullState {
    scope: SyncScope,
    provider: SyncProvider,
    max_operations: usize,
    max_bytes: usize,
    processed: usize,
    processed_bytes: usize,
    report: SyncCycleReport,
    rows: VecDeque<ReceivedOperation>,
    repair: Option<RepairState>,
    repaired_blocker: bool,
}

struct RepairState {
    device: context_relay_protocol::DeviceId,
    next: u64,
    end: u64,
    blocker: ReceivedOperation,
}

fn complete(mut state: PullState, more_work: bool) -> PullProgress {
    state.report.more_work |= more_work;
    PullProgress::Complete(state.report)
}

impl<G> SyncEngine<G> {
    pub fn prepare_pull(&self, vault: &Vault) -> Result<PullProgress, SyncCycleError> {
        let state = PullState {
            scope: self.scope,
            provider: self.provider,
            max_operations: self.max_operations,
            max_bytes: self.max_bytes,
            processed: 0,
            processed_bytes: 0,
            report: SyncCycleReport::empty(),
            rows: VecDeque::new(),
            repair: None,
            repaired_blocker: false,
        };
        self.next_page(vault, state)
    }

    fn request_pull(
        &self,
        vault: &Vault,
        state: PullState,
        request: PullRequest,
    ) -> Result<PullProgress, SyncCycleError> {
        let expected_cursor = vault
            .sync_cursor(self.scope.workspace_id, self.provider.as_str())
            .map_err(local_error)?;
        Ok(PullProgress::Request(Box::new(PreparedPull {
            state,
            request,
            expected_cursor,
        })))
    }

    fn next_page(&self, vault: &Vault, state: PullState) -> Result<PullProgress, SyncCycleError> {
        if state.processed == self.max_operations {
            return Ok(complete(state, true));
        }
        let cursor = vault
            .sync_cursor(self.scope.workspace_id, self.provider.as_str())
            .map_err(local_error)?;
        let limit = (self.max_operations - state.processed).min(MAX_BATCH);
        self.request_pull(vault, state, PullRequest::Operations { cursor, limit })
    }

    fn next_repair(&self, vault: &Vault, state: PullState) -> Result<PullProgress, SyncCycleError> {
        if state.processed == self.max_operations {
            return Ok(complete(state, true));
        }
        let repair = state
            .repair
            .as_ref()
            .ok_or(SyncCycleError::new("configuration_error"))?;
        let capacity = (self.max_operations - state.processed).min(MAX_BATCH) as u64;
        let end = repair
            .next
            .saturating_add(capacity.saturating_sub(1))
            .min(repair.end);
        let request = PullRequest::DeviceRange {
            device: repair.device,
            range: repair.next..=end,
        };
        self.request_pull(vault, state, request)
    }

    pub fn finish_pull<M: TrustedSyncMaterial, E: RepresentativeEmbeddingResolver>(
        &self,
        vault: &mut Vault,
        prepared: PreparedPull,
        response: PullResponse,
        trusted_material: &M,
        embedding_resolver: &E,
        now_ms: u64,
    ) -> Result<PullProgress, SyncCycleError> {
        let PreparedPull {
            mut state,
            request,
            expected_cursor,
        } = prepared;
        if state.scope != self.scope
            || state.provider != self.provider
            || state.max_operations != self.max_operations
            || state.max_bytes != self.max_bytes
            || vault
                .sync_cursor(self.scope.workspace_id, self.provider.as_str())
                .map_err(local_error)?
                != expected_cursor
        {
            return Err(SyncCycleError::new("integrity_quarantined"));
        }
        match (request, response) {
            (PullRequest::Operations { cursor, limit }, PullResponse::Operations(mut page)) => {
                validate_page(
                    cursor.as_ref(),
                    &page.rows,
                    page.next_cursor.as_ref(),
                    limit,
                )?;
                if page.rows.is_empty() {
                    return Ok(complete(state, false));
                }
                page.rows.sort_by(compare_received);
                state.report.pulled = state.report.pulled.saturating_add(page.rows.len());
                state.rows = page.rows.into();
            }
            (PullRequest::DeviceRange { device, range }, PullResponse::DeviceRange(rows)) => {
                match self.apply_repair_rows(
                    vault,
                    &mut state,
                    device,
                    range.clone(),
                    rows,
                    trusted_material,
                    embedding_resolver,
                    now_ms,
                )? {
                    GapRepairOutcome::Pending => return Ok(complete(state, true)),
                    GapRepairOutcome::BlockedByQuarantine => {
                        let blocker = state
                            .repair
                            .take()
                            .ok_or(SyncCycleError::new("configuration_error"))?
                            .blocker;
                        if state.processed == self.max_operations
                            || !reserve_bytes(
                                &mut state.processed_bytes,
                                blocker.operation.bytes.len(),
                                self.max_bytes,
                            )
                        {
                            return Ok(complete(state, true));
                        }
                        self.persist_quarantine(vault, &blocker, "gap_pending", now_ms, true)?;
                        state.report.quarantined += 1;
                        state.processed += 1;
                    }
                    GapRepairOutcome::Complete => {
                        let repair = state
                            .repair
                            .as_mut()
                            .ok_or(SyncCycleError::new("configuration_error"))?;
                        if let Some(next) = range.end().checked_add(1)
                            && next <= repair.end
                        {
                            repair.next = next;
                            return self.next_repair(vault, state);
                        }
                        let repair = state.repair.take().expect("repair was checked above");
                        state.rows.push_front(repair.blocker);
                        state.repaired_blocker = true;
                    }
                }
            }
            _ => return Err(SyncCycleError::new("integrity_quarantined")),
        }
        self.advance_pull(vault, state, trusted_material, embedding_resolver, now_ms)
    }

    fn advance_pull<M: TrustedSyncMaterial, E: RepresentativeEmbeddingResolver>(
        &self,
        vault: &mut Vault,
        mut state: PullState,
        trusted_material: &M,
        embedding_resolver: &E,
        now_ms: u64,
    ) -> Result<PullProgress, SyncCycleError> {
        while let Some(row) = state.rows.pop_front() {
            let was_repaired = std::mem::take(&mut state.repaired_blocker);

            validate_receipt_binding(&row)?;
            if state.processed == self.max_operations {
                state.report.more_work = true;
                return Ok(complete(state, true));
            }
            if let Some(stored) = self.existing_quarantine(vault, &row)? {
                validate_existing_quarantine(&stored, &row)?;
                self.persist_quarantine(vault, &row, &stored.safe_error_code, now_ms, true)?;
                state.report.quarantined += 1;
                state.processed += 1;
                continue;
            }
            if let Some(stored) = self.existing_rejection(vault, &row)? {
                validate_existing_rejection(&stored, &row)?;
                self.persist_rejection(vault, &row, now_ms, true)?;
                state.report.quarantined += 1;
                state.processed += 1;
                continue;
            }
            if row.operation.bytes.len() > MAX_CBOR_OPERATION_BYTES {
                self.persist_rejection(vault, &row, now_ms, true)?;
                state.report.quarantined += 1;
                state.processed += 1;
                continue;
            }
            if !reserve_bytes(
                &mut state.processed_bytes,
                row.operation.bytes.len(),
                self.max_bytes,
            ) {
                state.report.more_work = true;
                return Ok(complete(state, true));
            }
            if validate_received(self.scope, &row).is_err() {
                self.persist_quarantine(vault, &row, "integrity_quarantined", now_ms, true)?;
                state.report.quarantined += 1;
                state.processed += 1;
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
                    state.processed += 1;
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
                    record_apply(&mut state.report, decision);
                    state.processed += 1;
                }
                Ok(AdmissionDecision::Gap(range)) => {
                    state.processed_bytes -= row.operation.bytes.len();
                    if was_repaired {
                        return Ok(complete(state, true));
                    }
                    state.repair = Some(RepairState {
                        device: row.operation.device_id,
                        next: *range.start(),
                        end: *range.end(),
                        blocker: row,
                    });
                    return self.next_repair(vault, state);
                }
                Err(error) => {
                    require_quarantinable(error)?;
                    self.persist_quarantine(vault, &row, "integrity_quarantined", now_ms, true)?;
                    state.report.quarantined += 1;
                    state.processed += 1;
                }
            }
        }
        self.next_page(vault, state)
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_repair_rows<M: TrustedSyncMaterial, E: RepresentativeEmbeddingResolver>(
        &self,
        vault: &mut Vault,
        state: &mut PullState,
        device: context_relay_protocol::DeviceId,
        range: RangeInclusive<u64>,
        mut rows: Vec<ReceivedOperation>,
        trusted_material: &M,
        embedding_resolver: &E,
        now_ms: u64,
    ) -> Result<GapRepairOutcome, SyncCycleError> {
        let next = *range.start();
        let chunk_end = *range.end();
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
                state.report.quarantined += 1;
                return Ok(GapRepairOutcome::BlockedByQuarantine);
            }
            if let Some(stored) = self.existing_rejection(vault, &row)? {
                validate_existing_rejection(&stored, &row)?;
                state.report.quarantined += 1;
                return Ok(GapRepairOutcome::BlockedByQuarantine);
            }
            if row.operation.bytes.len() > MAX_CBOR_OPERATION_BYTES {
                self.persist_rejection(vault, &row, now_ms, false)?;
                state.report.quarantined += 1;
                return Ok(GapRepairOutcome::BlockedByQuarantine);
            }
            if !reserve_bytes(
                &mut state.processed_bytes,
                row.operation.bytes.len(),
                self.max_bytes,
            ) {
                return Ok(GapRepairOutcome::Pending);
            }
            if validate_received(self.scope, &row).is_err() {
                self.persist_quarantine(vault, &row, "integrity_quarantined", now_ms, false)?;
                state.report.quarantined += 1;
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
                    record_apply(&mut state.report, decision);
                }
                Ok(AdmissionDecision::ExactReplay(operation_id))
                    if operation_id == row.operation.operation_id => {}
                Ok(AdmissionDecision::ExactReplay(_)) | Ok(AdmissionDecision::Gap(_)) => {
                    return Err(SyncCycleError::new("integrity_quarantined"));
                }
                Err(error) => {
                    require_quarantinable(error)?;
                    self.persist_quarantine(vault, &row, "integrity_quarantined", now_ms, false)?;
                    state.report.quarantined += 1;
                    return Ok(GapRepairOutcome::BlockedByQuarantine);
                }
            }
            state.processed += 1;
            state.report.gaps_repaired += 1;
        }

        Ok(GapRepairOutcome::Complete)
    }
}
