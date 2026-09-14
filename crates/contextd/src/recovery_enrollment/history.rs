use super::*;
use context_relay_core::{
    auth::{HostedIdentity, LoginCancellation},
    devices::{
        membership_crypto::MembershipHistoryBudget, recovery::SystemRecoveryEnrollmentClock,
    },
    service::sync_embedding,
    sync::{
        CheckpointCursor, SupabaseTransport, SupabaseTransportConfig, SyncScope, SyncTransport,
        TransportError,
    },
    vault::{HistoricalReconstructionBudget, HistoricalTransferBudget, VaultError},
};
use context_relay_protocol::{
    CHECKPOINT_SCHEMA_VERSION, RecoveryHistoryCandidatesPage, RecoveryHistoryCursor,
    RecoveryHistoryExtent, RecoveryRestoreStatus,
};

pub(super) fn budget() -> HistoricalReconstructionBudget {
    HistoricalReconstructionBudget {
        transfer: HistoricalTransferBudget {
            history: MembershipHistoryBudget {
                max_events: 4096,
                max_bytes: 64 * 1024 * 1024,
            },
            max_pages: 4096,
            max_bytes: 64 * 1024 * 1024,
        },
        max_operations: 100000,
        max_operation_bytes: 64 * 1024 * 1024,
        max_dependencies: 1000000,
    }
}
pub(super) struct CandidateTraversal {
    cursor: RecoveryHistoryCursor,
    pages: usize,
    bytes: usize,
}
pub(super) fn vault_error(error: VaultError) -> ClientError {
    let code = match error {
        VaultError::OperationConflict => ErrorCode::Conflict,
        VaultError::BudgetExceeded => ErrorCode::QuotaExceeded,
        _ => ErrorCode::InvalidRequest,
    };
    ClientError {
        code,
        message: "Recovery history could not be authenticated.".into(),
        field_path: None,
        retryable: false,
    }
}
fn transport_error(error: TransportError) -> ClientError {
    ClientError {
        code: match error {
            TransportError::AuthRequired | TransportError::Revoked => ErrorCode::ScopeDenied,
            TransportError::Integrity => ErrorCode::InvalidRequest,
            _ => ErrorCode::Internal,
        },
        message: error.safe_code().into(),
        field_path: None,
        retryable: error.is_retryable(),
    }
}
impl HostedRecoveryEnrollmentService {
    fn check_history_session(
        &self,
        identity: HostedIdentity,
        generation: &LoginCancellation,
    ) -> Result<(), ClientError> {
        self.owner
            .session_for(
                generation,
                identity,
                SystemRecoveryEnrollmentClock.now_ms() / 1000,
            )
            .map_err(|_| transport_error(TransportError::AuthRequired))?;
        Ok(())
    }
    pub(super) fn authorized_history_action<T>(
        &self,
        identity: HostedIdentity,
        generation: &LoginCancellation,
        action: impl FnOnce(&dyn Fn() -> Result<(), VaultError>) -> Result<T, ClientError>,
    ) -> Result<T, ClientError> {
        let denied = std::cell::Cell::new(false);
        let authorize = || {
            self.check_history_session(identity, generation)
                .map_err(|_| {
                    denied.set(true);
                    VaultError::OperationConflict
                })
        };
        let result = action(&authorize);
        if denied.get() {
            return Err(transport_error(TransportError::AuthRequired));
        }
        // Every active-action result, including inner early returns, belongs to this session.
        self.check_history_session(identity, generation)?;
        result
    }

    pub(super) fn execute_history(
        &self,
        vault: &mut Vault,
        request: LocalRequest,
        identity: HostedIdentity,
        generation: LoginCancellation,
    ) -> Result<LocalResult, ClientError> {
        self.authorized_history_action(identity, &generation, |authorize| {
            self.execute_history_authorized(vault, request, identity, generation.clone(), authorize)
        })
    }
    fn execute_history_authorized(
        &self,
        vault: &mut Vault,
        request: LocalRequest,
        identity: HostedIdentity,
        generation: LoginCancellation,
        authorize: &dyn Fn() -> Result<(), VaultError>,
    ) -> Result<LocalResult, ClientError> {
        let saved = vault
            .prepared_recovery_v2(&self.identity.keys)
            .map_err(vault_error)?
            .ok_or_else(invalid_error)?;
        let scope = SyncScope {
            account_id: saved.claim.account_id,
            workspace_id: saved.claim.workspace_id,
        };
        let status = vault
            .recovery_history_status(&self.identity.keys, budget())
            .map_err(vault_error)?;
        let accepted = vault
            .accepted_membership_history(budget().transfer.history)
            .map_err(vault_error)?
            .ok_or_else(invalid_error)?
            .endpoint();
        let session = self
            .owner
            .session_for(
                &generation,
                identity,
                SystemRecoveryEnrollmentClock.now_ms() / 1000,
            )
            .map_err(|_| transport_error(TransportError::AuthRequired))?;
        let config = SupabaseTransportConfig::new(
            &self.project,
            self.publishable_key.to_string(),
            session.access_token(),
        )
        .map_err(transport_error)?;
        #[cfg(test)]
        let transport = if let Some(http) = &self.http {
            SupabaseTransport::with_http_client(config, http.clone())
        } else {
            SupabaseTransport::new(config)
        };
        #[cfg(not(test))]
        let transport = SupabaseTransport::new(config);
        let mut transport = transport.map_err(transport_error)?.with_session_owner(
            self.owner.clone(),
            identity,
            generation.clone(),
        );
        match request {
            LocalRequest::RecoveryHistoryUnlock(params) => {
                if params.restore_id != saved.claim.restore_id
                    || params.accepted_endpoint_sha256 != accepted.state_sha256
                {
                    return Err(vault_error(VaultError::OperationConflict));
                }
                let target = vault
                    .recovery_history_selection(&self.identity.keys, budget())
                    .map_err(vault_error)?
                    .ok_or_else(invalid_error)?;
                if target.restore_id() != params.restore_id
                    || target.checkpoint_sha256() != params.checkpoint_sha256
                    || target.authorizing_endpoint() != accepted
                {
                    return Err(vault_error(VaultError::OperationConflict));
                }
                vault
                    .unlock_recovery_history(
                        target,
                        params.recovery_phrase_words,
                        &self.identity.keys,
                        budget(),
                        authorize,
                    )
                    .map_err(vault_error)?;
                Ok(LocalResult::RecoveryRestoreStatus {
                    status: vault
                        .recovery_history_status(&self.identity.keys, budget())
                        .map_err(vault_error)?,
                })
            }
            LocalRequest::RecoveryHistoryCandidates(params) => {
                if params.restore_id != saved.claim.restore_id
                    || params.accepted_endpoint_sha256 != accepted.state_sha256
                {
                    return Err(vault_error(VaultError::OperationConflict));
                }
                let mut traversal = self.history_pages.lock().map_err(|_| transient_error())?;
                let (pages, mut bytes) = match &params.cursor {
                    None => (0, 0),
                    Some(cursor) => match traversal.as_ref() {
                        Some(previous) if previous.cursor == *cursor => {
                            (previous.pages, previous.bytes)
                        }
                        _ => return Err(invalid_error()),
                    },
                };
                if pages >= 4096 {
                    return Err(vault_error(VaultError::BudgetExceeded));
                }
                let after = params.cursor.as_ref().map(|c| CheckpointCursor {
                    received_at: c.received_at.clone(),
                    canonical_hash: c.canonical_hash,
                });
                let page = transport
                    .pull_checkpoints(scope, CHECKPOINT_SCHEMA_VERSION, after.as_ref(), 8)
                    .map_err(transport_error)?;
                if page.rows.len() > 8
                    || page.next_cursor != page.rows.last().map(|r| r.cursor.clone())
                {
                    return Err(transport_error(TransportError::Integrity));
                }
                let mut previous = after;
                let mut candidates = Vec::new();
                for row in page.rows {
                    if previous.as_ref().is_some_and(|p| row.cursor <= *p)
                        || row.cursor.canonical_hash != row.checkpoint.canonical_hash
                    {
                        return Err(transport_error(TransportError::Integrity));
                    }
                    bytes = bytes
                        .checked_add(row.checkpoint.bytes.len())
                        .filter(|n| *n <= 64 * 1024 * 1024)
                        .ok_or_else(|| vault_error(VaultError::BudgetExceeded))?;
                    candidates.push(
                        vault
                            .recovery_history_candidate(
                                params.restore_id,
                                params.accepted_endpoint_sha256,
                                &row.checkpoint.bytes,
                                row.checkpoint.canonical_hash,
                                &self.identity.keys,
                                budget(),
                            )
                            .map_err(vault_error)?,
                    );
                    previous = Some(row.cursor);
                }
                self.check_history_session(identity, &generation)?;
                let next_cursor = page.next_cursor.map(|c| RecoveryHistoryCursor {
                    restore_id: params.restore_id,
                    accepted_endpoint_sha256: params.accepted_endpoint_sha256,
                    received_at: c.received_at,
                    canonical_hash: c.canonical_hash,
                });
                *traversal = next_cursor.clone().map(|cursor| CandidateTraversal {
                    cursor,
                    pages: pages + 1,
                    bytes,
                });
                Ok(LocalResult::RecoveryHistoryCandidates {
                    page: RecoveryHistoryCandidatesPage {
                        restore_id: params.restore_id,
                        accepted_endpoint: context_relay_protocol::RecoveryHistoryEndpoint {
                            state_sha256: accepted.state_sha256,
                            control_epoch: accepted.control_epoch,
                            key_epoch: accepted.key_epoch,
                        },
                        candidates,
                        next_cursor,
                    },
                })
            }
            LocalRequest::RecoveryHistorySelect(params) => {
                if params.restore_id != saved.claim.restore_id
                    || params.accepted_endpoint_sha256 != accepted.state_sha256
                {
                    return Err(vault_error(VaultError::OperationConflict));
                }
                let checkpoint = transport
                    .checkpoint_by_hash(scope, CHECKPOINT_SCHEMA_VERSION, params.checkpoint_sha256)
                    .map_err(transport_error)?
                    .ok_or_else(invalid_error)?;
                let candidate = vault
                    .recovery_history_candidate(
                        params.restore_id,
                        params.accepted_endpoint_sha256,
                        &checkpoint.bytes,
                        params.checkpoint_sha256,
                        &self.identity.keys,
                        budget(),
                    )
                    .map_err(vault_error)?;
                if !matches!(candidate.extent, RecoveryHistoryExtent::Supported { .. }) {
                    return Err(vault_error(VaultError::BudgetExceeded));
                }
                self.check_history_session(identity, &generation)?;
                vault
                    .select_recovery_history_authorized(
                        accepted,
                        &checkpoint.bytes,
                        &self.identity.keys,
                        budget(),
                        authorize,
                    )
                    .map_err(vault_error)?;
                Ok(LocalResult::RecoveryRestoreStatus {
                    status: vault
                        .recovery_history_status(&self.identity.keys, budget())
                        .map_err(vault_error)?,
                })
            }
            LocalRequest::RecoveryRestoreBegin(_) | LocalRequest::RecoveryRestoreResume(_) => {
                if matches!(status, RecoveryRestoreStatus::Complete { .. }) {
                    return Ok(LocalResult::RecoveryRestoreStatus { status });
                }
                if !matches!(
                    status,
                    RecoveryRestoreStatus::RestoringHistory {
                        history: context_relay_protocol::RecoveryHistoryProgress::Incomplete { .. },
                        ..
                    }
                ) {
                    return Ok(LocalResult::RecoveryRestoreStatus { status });
                }
                let target = vault
                    .recovery_history_selection(&self.identity.keys, budget())
                    .map_err(vault_error)?
                    .ok_or_else(invalid_error)?;
                let mut bytes = 0usize;
                for page in 0..=4096 {
                    self.check_history_session(identity, &generation)?;
                    let Some((device, range)) = vault
                        .recovery_history_missing_operations(target, &self.identity.keys, budget())
                        .map_err(vault_error)?
                    else {
                        break;
                    };
                    if page == 4096 {
                        return Err(vault_error(VaultError::BudgetExceeded));
                    }
                    let rows = transport
                        .pull_device_range(scope, device, range.clone())
                        .map_err(transport_error)?;
                    if rows.is_empty() {
                        return Ok(LocalResult::RecoveryRestoreStatus {
                            status: vault
                                .recovery_history_status(&self.identity.keys, budget())
                                .map_err(vault_error)?,
                        });
                    }
                    let mut operations = Vec::new();
                    for row in rows {
                        if row.operation.device_id != device
                            || !range.contains(&row.operation.device_sequence)
                        {
                            return Err(transport_error(TransportError::Integrity));
                        }
                        bytes = bytes
                            .checked_add(row.operation.bytes.len())
                            .filter(|n| *n <= 64 * 1024 * 1024)
                            .ok_or_else(|| vault_error(VaultError::BudgetExceeded))?;
                        operations.push(row.operation.bytes);
                    }
                    self.check_history_session(identity, &generation)?;
                    vault
                        .stage_historical_operations(
                            accepted,
                            self.identity.device_id,
                            &operations,
                            &self.identity.keys,
                            budget(),
                        )
                        .map_err(vault_error)?;
                    if vault
                        .recovery_history_missing_operations(target, &self.identity.keys, budget())
                        .map_err(vault_error)?
                        .as_ref()
                        .is_some_and(|next| next.0 == device && next.1.start() == range.start())
                    {
                        return Err(transport_error(TransportError::Integrity));
                    }
                }
                self.check_history_session(identity, &generation)?;
                if let Some(proof) = vault
                    .reconstruct_recovery_history_authorized(
                        target,
                        &[],
                        &self.identity.keys,
                        budget(),
                        &sync_embedding,
                        authorize,
                    )
                    .map_err(vault_error)?
                {
                    self.check_history_session(identity, &generation)?;
                    vault
                        .install_recovery_history_authorized(
                            &proof,
                            &self.identity.keys,
                            budget(),
                            &sync_embedding,
                            authorize,
                        )
                        .map_err(vault_error)?;
                }
                Ok(LocalResult::RecoveryRestoreStatus {
                    status: vault
                        .recovery_history_status(&self.identity.keys, budget())
                        .map_err(vault_error)?,
                })
            }
            _ => Err(invalid_error()),
        }
    }
}
