use super::*;
use crate::{
    sync::{CanonicalCheckpoint, CheckpointPage, CheckpointReceipt, StoredCheckpointPin},
    vault::StoredCheckpointScan,
};

pub enum CheckpointRequest {
    ByHash(Sha256Digest),
    Page {
        after: Option<CheckpointCursor>,
        limit: usize,
    },
    Push(Box<CanonicalCheckpoint>),
}

pub enum CheckpointResponse {
    ByHash(Option<Box<CanonicalCheckpoint>>),
    Page(CheckpointPage),
    Push(CheckpointReceipt),
}

pub enum CheckpointProgress {
    Request(Box<PreparedCheckpoint>),
    Complete(SyncCycleReport),
}

/// Owned checkpoint work; hosts must recheck the original session and current
/// trust before completing each response on the sole vault owner.
pub struct PreparedCheckpoint {
    state: CheckpointState,
    request: CheckpointRequest,
    expected_pin: Option<StoredCheckpointPin>,
    expected_scan: Option<StoredCheckpointScan>,
}

impl PreparedCheckpoint {
    pub const fn scope(&self) -> SyncScope {
        self.state.scope
    }
    pub const fn request(&self) -> &CheckpointRequest {
        &self.request
    }
}

struct CheckpointState {
    scope: SyncScope,
    provider: SyncProvider,
    max_operations: usize,
    initial_pin: Option<StoredCheckpointPin>,
    scanned: usize,
    report: SyncCycleReport,
    phase: Phase,
    chain_anchor: Option<VerifiedCheckpointChainAnchor>,
    append_hash: Sha256Digest,
    append_cursor: Option<CheckpointCursor>,
    published: Option<Box<CanonicalCheckpoint>>,
}

#[derive(Clone, Copy)]
enum Phase {
    Lookup,
    Scan,
    Push,
    Append,
    Tail,
}

impl<G> SyncEngine<G> {
    pub fn prepare_checkpoint(&self, vault: &Vault) -> Result<CheckpointProgress, SyncCycleError> {
        let initial_pin = vault
            .sync_checkpoint_pin(self.scope)
            .map_err(checkpoint_vault_error)?;
        let hash = initial_pin.as_ref().map(|pin| pin.canonical_hash);
        let state = CheckpointState {
            scope: self.scope,
            provider: self.provider,
            max_operations: self.max_operations,
            initial_pin,
            scanned: 0,
            report: SyncCycleReport::empty(),
            phase: Phase::Lookup,
            chain_anchor: None,
            append_hash: Sha256Digest([0; 32]),
            append_cursor: None,
            published: None,
        };
        if let Some(hash) = hash {
            self.request_checkpoint(vault, state, CheckpointRequest::ByHash(hash))
        } else {
            self.next_checkpoint_page(vault, state)
        }
    }

    fn request_checkpoint(
        &self,
        vault: &Vault,
        state: CheckpointState,
        request: CheckpointRequest,
    ) -> Result<CheckpointProgress, SyncCycleError> {
        Ok(CheckpointProgress::Request(Box::new(PreparedCheckpoint {
            state,
            request,
            expected_pin: vault
                .sync_checkpoint_pin(self.scope)
                .map_err(checkpoint_vault_error)?,
            expected_scan: vault
                .sync_checkpoint_scan(self.scope, self.provider.as_str())
                .map_err(checkpoint_vault_error)?,
        })))
    }

    fn next_checkpoint_page(
        &self,
        vault: &Vault,
        mut state: CheckpointState,
    ) -> Result<CheckpointProgress, SyncCycleError> {
        let scan = vault
            .sync_checkpoint_scan(self.scope, self.provider.as_str())
            .map_err(checkpoint_vault_error)?;
        let base_pin_hash = state.initial_pin.as_ref().map(|pin| pin.canonical_hash);
        if scan
            .as_ref()
            .is_some_and(|scan| scan.base_pin_hash != base_pin_hash)
        {
            return Err(SyncCycleError::new("integrity_quarantined"));
        }
        let remaining = self.max_operations.saturating_sub(state.scanned);
        if remaining == 0 {
            state.report.more_work = true;
            return Ok(CheckpointProgress::Complete(state.report));
        }
        state.phase = Phase::Scan;
        self.request_checkpoint(
            vault,
            state,
            CheckpointRequest::Page {
                after: scan.map(|scan| scan.cursor),
                limit: remaining.min(MAX_BATCH),
            },
        )
    }

    pub fn finish_checkpoint<M: TrustedSyncMaterial>(
        &self,
        vault: &mut Vault,
        prepared: PreparedCheckpoint,
        response: CheckpointResponse,
        trusted_material: &M,
        now_ms: u64,
        context: &CheckpointBuildContext<'_>,
    ) -> Result<CheckpointProgress, SyncCycleError> {
        let PreparedCheckpoint {
            mut state,
            request,
            expected_pin,
            expected_scan,
        } = prepared;
        if context.scope != self.scope
            || state.scope != self.scope
            || state.provider != self.provider
            || state.max_operations != self.max_operations
        {
            return Err(SyncCycleError::new("configuration_error"));
        }
        if vault
            .sync_checkpoint_pin(self.scope)
            .map_err(checkpoint_vault_error)?
            != expected_pin
            || vault
                .sync_checkpoint_scan(self.scope, self.provider.as_str())
                .map_err(checkpoint_vault_error)?
                != expected_scan
        {
            return Err(SyncCycleError::new("integrity_quarantined"));
        }
        match (state.phase, request, response) {
            (Phase::Lookup, CheckpointRequest::ByHash(_), CheckpointResponse::ByHash(remote)) => {
                let pin = state
                    .initial_pin
                    .as_ref()
                    .ok_or(SyncCycleError::new("configuration_error"))?;
                let remote = remote.ok_or(SyncCycleError::new("integrity_quarantined"))?;
                if remote.bytes != pin.canonical_bytes || remote.state_hash != pin.state_hash {
                    return Err(SyncCycleError::new("integrity_quarantined"));
                }
                self.next_checkpoint_page(vault, state)
            }
            (
                Phase::Scan,
                CheckpointRequest::Page { after, limit },
                CheckpointResponse::Page(page),
            ) => {
                validate_checkpoint_page(
                    after.as_ref(),
                    &page.rows,
                    page.next_cursor.as_ref(),
                    limit,
                )?;
                let base_pin_hash = state.initial_pin.as_ref().map(|pin| pin.canonical_hash);
                let mut found_pin = expected_scan
                    .as_ref()
                    .map_or(state.initial_pin.is_none(), |scan| scan.pin_seen);
                if page.rows.is_empty() {
                    if !found_pin {
                        return Err(SyncCycleError::new("integrity_quarantined"));
                    }
                    if let Some(scan) = expected_scan {
                        let (anchor, verified) = verify_checkpoint_after_chain(
                            vault,
                            self.scope,
                            &scan.checkpoint,
                            scan.base_pin_hash,
                            trusted_material,
                        )
                        .map_err(sync_error)?;
                        state.append_cursor = Some(scan.cursor);
                        state.append_hash = anchor.checkpoint.canonical_hash;
                        if let Some(verified) = verified {
                            vault
                                .accept_sync_checkpoint_endpoint(
                                    &verified,
                                    now_ms,
                                    self.provider.as_str(),
                                )
                                .map_err(checkpoint_vault_error)?;
                            state.report.checkpointed = true;
                        } else {
                            state.chain_anchor = Some(anchor);
                        }
                    }
                    if !vault
                        .sync_checkpoint_schedule(self.scope)
                        .map_err(checkpoint_vault_error)?
                        .is_due(now_ms)
                    {
                        return Ok(CheckpointProgress::Complete(state.report));
                    }
                    let checkpoint = if let Some(anchor) = state.chain_anchor.as_ref() {
                        build_checkpoint_after_chain(vault, context, trusted_material, anchor)
                    } else {
                        build_checkpoint(vault, context, trusted_material)
                    }
                    .map_err(sync_error)?;
                    state.phase = Phase::Push;
                    return self.request_checkpoint(
                        vault,
                        state,
                        CheckpointRequest::Push(Box::new(checkpoint)),
                    );
                }
                let mut previous = expected_scan
                    .as_ref()
                    .map_or(Sha256Digest([0; 32]), |scan| scan.checkpoint.canonical_hash);
                for row in page.rows {
                    validate_received_checkpoint(&row)?;
                    let authenticated = verify_checkpoint_link(
                        self.scope,
                        &row.checkpoint,
                        previous,
                        trusted_material,
                    )
                    .map_err(sync_error)?;
                    if let Some(pin) = state.initial_pin.as_ref()
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
                    state.scanned = state.scanned.saturating_add(1);
                    previous = row.checkpoint.canonical_hash;
                }
                self.next_checkpoint_page(vault, state)
            }
            (
                Phase::Push,
                CheckpointRequest::Push(checkpoint),
                CheckpointResponse::Push(receipt),
            ) => {
                if receipt.canonical_hash != checkpoint.canonical_hash {
                    return Err(SyncCycleError::new("integrity_quarantined"));
                }
                state.published = Some(checkpoint);
                state.phase = Phase::Append;
                let after = state.append_cursor.clone();
                self.request_checkpoint(vault, state, CheckpointRequest::Page { after, limit: 2 })
            }
            (
                Phase::Append,
                CheckpointRequest::Page { after, limit },
                CheckpointResponse::Page(page),
            ) => {
                validate_checkpoint_page(
                    after.as_ref(),
                    &page.rows,
                    page.next_cursor.as_ref(),
                    limit,
                )?;
                let [row] = page.rows.as_slice() else {
                    return Err(SyncCycleError::new("integrity_quarantined"));
                };
                validate_received_checkpoint(row)?;
                let authenticated = verify_checkpoint_link(
                    self.scope,
                    &row.checkpoint,
                    state.append_hash,
                    trusted_material,
                )
                .map_err(sync_error)?;
                if state.published.as_deref() != Some(&authenticated.checkpoint) {
                    return Err(SyncCycleError::new("integrity_quarantined"));
                }
                state.phase = Phase::Tail;
                self.request_checkpoint(
                    vault,
                    state,
                    CheckpointRequest::Page {
                        after: Some(row.cursor.clone()),
                        limit: 1,
                    },
                )
            }
            (
                Phase::Tail,
                CheckpointRequest::Page { after, limit },
                CheckpointResponse::Page(page),
            ) => {
                validate_checkpoint_page(
                    after.as_ref(),
                    &page.rows,
                    page.next_cursor.as_ref(),
                    limit,
                )?;
                if !page.rows.is_empty() {
                    return Err(SyncCycleError::new("integrity_quarantined"));
                }
                let checkpoint = state
                    .published
                    .as_deref()
                    .ok_or(SyncCycleError::new("configuration_error"))?;
                // Local writes and trust may have changed during HTTP. Never commit
                // the state verification performed before the request.
                if let Some(anchor) = state.chain_anchor.as_ref() {
                    let verified = verify_checkpoint_chain_extension(
                        vault,
                        self.scope,
                        checkpoint,
                        anchor,
                        trusted_material,
                    )
                    .map_err(sync_error)?;
                    vault
                        .accept_sync_checkpoint_chain_extension(
                            &verified,
                            now_ms,
                            self.provider.as_str(),
                            anchor.checkpoint.canonical_hash,
                        )
                        .map_err(checkpoint_vault_error)?;
                } else {
                    let verified =
                        verify_checkpoint(vault, self.scope, checkpoint, trusted_material)
                            .map_err(sync_error)?;
                    vault
                        .accept_sync_checkpoint(&verified, now_ms)
                        .map_err(checkpoint_vault_error)?;
                }
                state.report.checkpointed = true;
                Ok(CheckpointProgress::Complete(state.report))
            }
            _ => Err(SyncCycleError::new("configuration_error")),
        }
    }
}
