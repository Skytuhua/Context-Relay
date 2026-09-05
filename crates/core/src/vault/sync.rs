use std::{
    collections::BTreeSet,
    time::{SystemTime, UNIX_EPOCH},
};

use context_relay_protocol::{
    AccountId, ComponentRecord, DeviceId, DeviceSequence, InstructionRecord,
    MAX_CBOR_OPERATION_BYTES, MemoryCandidate, MemoryRecord, MutationKind, OperationId, ProjectId,
    ProjectIdentity, RecordId, RecordKind, RecordMutationV1, ScopeRef, SecretRef, Sha256Digest,
    SyncOperationV1, TaskRecord, WorkspaceId, decode_checkpoint_v1, decode_record_mutation_v1,
    encode_checkpoint_v1, encode_sync_operation_aad_v1, encode_sync_operation_v1,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};

use crate::sync::scope_matches;
use crate::{
    crypto::EncryptedPayload,
    search::Embedding384,
    sync::{
        AdmittedOperation, AuthenticatedCheckpoint, BuiltOperation, CanonicalCheckpoint,
        CausalOrder, CheckpointCursor, CheckpointDisposition, MergeDecision,
        RepresentativeEmbeddingResolver, StateSummaryEntryV1, StateSummaryV1, StoredCheckpointPin,
        SyncScope, TrustedSyncMaterial, VerifiedCheckpoint, compare_operations, decide_merge,
    },
};

use super::{
    Vault, VaultError, cached_embedding, candidate_state, from_json, task_status, to_json,
    upsert_searchable_record,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitDisposition {
    Inserted,
    ExactReplay,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncCursor {
    pub received_at: String,
    pub operation_id: OperationId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoredDeviceHead {
    pub sequence: u64,
    pub canonical_hash: Sha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredRecordHead {
    pub operation_id: OperationId,
    pub record_kind: RecordKind,
    pub mutation_kind: MutationKind,
    pub canonical_hash: Sha256Digest,
    pub operation: SyncOperationV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DueOutboxOperation {
    pub operation_id: OperationId,
    pub canonical_bytes: Vec<u8>,
    pub attempt_count: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboxUnblockReason {
    AuthenticationChanged,
    RevocationChanged,
    QuotaChanged,
    ConfigurationChanged,
}

impl OutboxUnblockReason {
    const fn blocked_code(self) -> &'static str {
        match self {
            Self::AuthenticationChanged => "auth_required",
            Self::RevocationChanged => "revoked",
            Self::QuotaChanged => "quota_blocked",
            Self::ConfigurationChanged => "configuration_error",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncQuarantineDisposition {
    Inserted,
    ExactReplay,
}

#[derive(Clone, Copy, Debug)]
pub struct SyncQuarantineWrite<'a> {
    pub account_id: AccountId,
    pub workspace_id: WorkspaceId,
    pub provider: &'a str,
    pub received_at: &'a str,
    pub receipt_operation_id: OperationId,
    pub routed_operation_id: OperationId,
    pub device_id: DeviceId,
    pub device_sequence: u64,
    pub safe_error_code: &'a str,
    pub envelope: &'a [u8],
    pub quarantined_at_ms: u64,
    pub advance_cursor: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredSyncQuarantine {
    pub account_id: AccountId,
    pub workspace_id: WorkspaceId,
    pub provider: String,
    pub received_at: String,
    pub receipt_operation_id: OperationId,
    pub routed_operation_id: OperationId,
    pub device_id: DeviceId,
    pub device_sequence: u64,
    pub safe_error_code: String,
    pub envelope: Vec<u8>,
    pub quarantined_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncRejectionDisposition {
    Inserted,
    ExactReplay,
}

#[derive(Clone, Copy, Debug)]
pub struct SyncRejectionWrite<'a> {
    pub account_id: AccountId,
    pub workspace_id: WorkspaceId,
    pub provider: &'a str,
    pub received_at: &'a str,
    pub receipt_operation_id: OperationId,
    pub routed_operation_id: OperationId,
    pub device_id: DeviceId,
    pub device_sequence: u64,
    pub safe_error_code: &'a str,
    pub received_bytes: &'a [u8],
    pub rejected_at_ms: u64,
    pub advance_cursor: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredSyncRejection {
    pub account_id: AccountId,
    pub workspace_id: WorkspaceId,
    pub provider: String,
    pub received_at: String,
    pub receipt_operation_id: OperationId,
    pub routed_operation_id: OperationId,
    pub device_id: DeviceId,
    pub device_sequence: u64,
    pub safe_error_code: String,
    pub claimed_byte_length: u64,
    pub received_sha256: Sha256Digest,
    pub rejected_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncCheckpointSchedule {
    pub applied_operations: u64,
    pub first_uncheckpointed_ms: Option<u64>,
    pub last_checkpoint_ms: Option<u64>,
    pub requested: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct StoredCheckpointScan {
    pub(crate) scope: SyncScope,
    pub(crate) provider: String,
    pub(crate) cursor: CheckpointCursor,
    pub(crate) checkpoint: CanonicalCheckpoint,
    pub(crate) base_pin_hash: Option<Sha256Digest>,
    pub(crate) pin_seen: bool,
}

impl SyncCheckpointSchedule {
    pub const OPERATION_THRESHOLD: u64 = 1_024;
    pub const INTERVAL_MS: u64 = 24 * 60 * 60 * 1_000;

    pub fn is_due(self, now_ms: u64) -> bool {
        self.requested
            || self.applied_operations >= Self::OPERATION_THRESHOLD
            || (self.applied_operations > 0
                && self
                    .first_uncheckpointed_ms
                    .is_some_and(|started| now_ms.saturating_sub(started) >= Self::INTERVAL_MS))
    }
}

enum CacheChange<'a> {
    PutMemory(&'a context_relay_protocol::MemoryRecord, &'a Embedding384),
    PutInstruction(
        &'a context_relay_protocol::InstructionRecord,
        &'a Embedding384,
    ),
    Remove(String),
    None,
}

impl Vault {
    pub fn quarantine_sync_receipt(
        &mut self,
        write: &SyncQuarantineWrite<'_>,
    ) -> Result<SyncQuarantineDisposition, VaultError> {
        validate_quarantine_write(write)?;
        let quarantined_at_ms = i64::try_from(write.quarantined_at_ms).map_err(|_| {
            VaultError::Validation("quarantine time exceeds SQLite integer range".to_owned())
        })?;
        let transaction = self.connection.transaction()?;
        if let Some(stored) = load_quarantined_sync_receipt(
            &transaction,
            write.account_id,
            write.workspace_id,
            write.provider,
            write.received_at,
            write.receipt_operation_id,
        )? {
            if stored.routed_operation_id != write.routed_operation_id
                || stored.device_id != write.device_id
                || stored.device_sequence != write.device_sequence
                || stored.safe_error_code != write.safe_error_code
                || stored.envelope != write.envelope
            {
                return Err(VaultError::OperationConflict);
            }
            if write.advance_cursor {
                upsert_cursor(
                    &transaction,
                    write.workspace_id,
                    write.provider,
                    write.received_at,
                    write.receipt_operation_id,
                )?;
            }
            transaction.commit()?;
            return Ok(SyncQuarantineDisposition::ExactReplay);
        }

        transaction.execute(
            "INSERT INTO sync_quarantine(
                 account_id, workspace_id, provider, received_at,
                 receipt_operation_id, routed_operation_id, device_id,
                 device_sequence, safe_error_code, envelope, quarantined_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                write.account_id.to_string(),
                write.workspace_id.to_string(),
                write.provider,
                write.received_at,
                write.receipt_operation_id.to_string(),
                write.routed_operation_id.to_string(),
                write.device_id.to_string(),
                write.device_sequence.to_string(),
                write.safe_error_code,
                write.envelope,
                quarantined_at_ms,
            ],
        )?;
        if write.advance_cursor {
            upsert_cursor(
                &transaction,
                write.workspace_id,
                write.provider,
                write.received_at,
                write.receipt_operation_id,
            )?;
        }
        transaction.commit()?;
        Ok(SyncQuarantineDisposition::Inserted)
    }

    pub fn quarantined_sync_receipt(
        &self,
        account_id: AccountId,
        workspace_id: WorkspaceId,
        provider: &str,
        received_at: &str,
        receipt_operation_id: OperationId,
    ) -> Result<Option<StoredSyncQuarantine>, VaultError> {
        validate_sync_provider_v1(provider)?;
        validate_received_at(received_at)?;
        load_quarantined_sync_receipt(
            &self.connection,
            account_id,
            workspace_id,
            provider,
            received_at,
            receipt_operation_id,
        )
    }

    pub fn reject_oversized_sync_receipt(
        &mut self,
        write: &SyncRejectionWrite<'_>,
    ) -> Result<SyncRejectionDisposition, VaultError> {
        let (claimed_byte_length, claimed_byte_length_sql, received_sha256) =
            validate_rejection_write(write)?;
        let rejected_at_ms = i64::try_from(write.rejected_at_ms).map_err(|_| {
            VaultError::Validation("rejection time exceeds SQLite integer range".to_owned())
        })?;
        let transaction = self.connection.transaction()?;
        if let Some(stored) = load_rejected_sync_receipt(
            &transaction,
            write.account_id,
            write.workspace_id,
            write.provider,
            write.received_at,
            write.receipt_operation_id,
        )? {
            if stored.routed_operation_id != write.routed_operation_id
                || stored.device_id != write.device_id
                || stored.device_sequence != write.device_sequence
                || stored.safe_error_code != write.safe_error_code
                || stored.claimed_byte_length != claimed_byte_length
                || stored.received_sha256 != received_sha256
            {
                return Err(VaultError::OperationConflict);
            }
            if write.advance_cursor {
                upsert_cursor(
                    &transaction,
                    write.workspace_id,
                    write.provider,
                    write.received_at,
                    write.receipt_operation_id,
                )?;
            }
            transaction.commit()?;
            return Ok(SyncRejectionDisposition::ExactReplay);
        }

        transaction.execute(
            "INSERT INTO sync_rejections(
                 account_id, workspace_id, provider, received_at,
                 receipt_operation_id, routed_operation_id, device_id,
                 device_sequence, safe_error_code, claimed_byte_length,
                 received_sha256, rejected_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                write.account_id.to_string(),
                write.workspace_id.to_string(),
                write.provider,
                write.received_at,
                write.receipt_operation_id.to_string(),
                write.routed_operation_id.to_string(),
                write.device_id.to_string(),
                write.device_sequence.to_string(),
                write.safe_error_code,
                claimed_byte_length_sql,
                received_sha256.0.as_slice(),
                rejected_at_ms,
            ],
        )?;
        if write.advance_cursor {
            upsert_cursor(
                &transaction,
                write.workspace_id,
                write.provider,
                write.received_at,
                write.receipt_operation_id,
            )?;
        }
        transaction.commit()?;
        Ok(SyncRejectionDisposition::Inserted)
    }

    pub fn rejected_sync_receipt(
        &self,
        account_id: AccountId,
        workspace_id: WorkspaceId,
        provider: &str,
        received_at: &str,
        receipt_operation_id: OperationId,
    ) -> Result<Option<StoredSyncRejection>, VaultError> {
        validate_sync_provider_v1(provider)?;
        validate_received_at(received_at)?;
        load_rejected_sync_receipt(
            &self.connection,
            account_id,
            workspace_id,
            provider,
            received_at,
            receipt_operation_id,
        )
    }

    pub fn advance_replay_cursor(
        &mut self,
        workspace: WorkspaceId,
        provider: &str,
        received_at: &str,
        operation_id: OperationId,
    ) -> Result<(), VaultError> {
        validate_sync_provider_v1(provider)?;
        validate_received_at(received_at)?;
        let transaction = self.connection.transaction()?;
        let exists = transaction
            .query_row(
                "SELECT 1 FROM sync_operation_meta
                 WHERE operation_id = ?1 AND workspace_id = ?2",
                params![operation_id.to_string(), workspace.to_string()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !exists {
            return Err(VaultError::Validation(
                "replay cursor requires an existing operation".to_owned(),
            ));
        }
        upsert_cursor(&transaction, workspace, provider, received_at, operation_id)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn apply_admitted_operation(
        &mut self,
        admitted: &AdmittedOperation,
        trusted_material: &impl TrustedSyncMaterial,
        provider: &str,
        received_at: &str,
        embedding_resolver: &impl RepresentativeEmbeddingResolver,
    ) -> Result<MergeDecision, VaultError> {
        let applied_at_ms = local_unix_ms()?;
        self.apply_admitted_operation_at(
            admitted,
            trusted_material,
            provider,
            received_at,
            embedding_resolver,
            applied_at_ms,
        )
    }

    pub fn apply_admitted_operation_at(
        &mut self,
        admitted: &AdmittedOperation,
        trusted_material: &impl TrustedSyncMaterial,
        provider: &str,
        received_at: &str,
        embedding_resolver: &impl RepresentativeEmbeddingResolver,
        applied_at_ms: u64,
    ) -> Result<MergeDecision, VaultError> {
        validate_sync_provider_v1(provider)?;
        validate_received_at(received_at)?;
        self.apply_admitted_operation_inner(
            admitted,
            trusted_material,
            received_at,
            Some(provider),
            embedding_resolver,
            applied_at_ms,
        )
    }

    /// Applies a fetched device-chain repair without advancing the global pull cursor.
    ///
    /// The blocking receipt is retried and advances the cursor only after the repaired
    /// prefix and the blocking operation have both committed.
    pub(crate) fn apply_repaired_operation_at(
        &mut self,
        admitted: &AdmittedOperation,
        trusted_material: &impl TrustedSyncMaterial,
        received_at: &str,
        embedding_resolver: &impl RepresentativeEmbeddingResolver,
        applied_at_ms: u64,
    ) -> Result<MergeDecision, VaultError> {
        validate_received_at(received_at)?;
        self.apply_admitted_operation_inner(
            admitted,
            trusted_material,
            received_at,
            None,
            embedding_resolver,
            applied_at_ms,
        )
    }

    fn apply_admitted_operation_inner(
        &mut self,
        admitted: &AdmittedOperation,
        trusted_material: &impl TrustedSyncMaterial,
        received_at: &str,
        cursor_provider: Option<&str>,
        embedding_resolver: &impl RepresentativeEmbeddingResolver,
        applied_at_ms: u64,
    ) -> Result<MergeDecision, VaultError> {
        validate_admitted(admitted)?;
        let transaction = self.connection.transaction()?;
        if exact_incoming_replay(&transaction, admitted)? {
            if let Some(provider) = cursor_provider {
                upsert_cursor(
                    &transaction,
                    admitted.operation().workspace_id,
                    provider,
                    received_at,
                    admitted.operation().operation_id,
                )?;
            }
            transaction.commit()?;
            return Ok(MergeDecision::NoLiveChange);
        }
        ensure_sync_record_owner(
            &transaction,
            Some(trusted_material),
            admitted.operation().account_id,
            admitted.operation().workspace_id,
            admitted.operation().record_id,
            admitted.operation().record_kind,
        )?;
        let current = load_record_heads(
            &transaction,
            admitted.operation().workspace_id,
            admitted.operation().record_id,
        )?;
        let decision = decide_merge(admitted, &current)
            .map_err(|error| VaultError::Validation(error.to_string()))?;
        validate_device_chain(&transaction, admitted.operation())?;

        let conflict_heads = match &decision {
            MergeDecision::AddConflictHead { remove } => {
                let mut heads = current
                    .iter()
                    .filter(|head| !remove.contains(&head.operation_id))
                    .map(|head| head.operation.clone())
                    .chain(std::iter::once(admitted.operation().clone()))
                    .collect::<Vec<_>>();
                heads.sort_by_key(|operation| operation.operation_id);
                Some(heads)
            }
            _ => None,
        };
        let rehydrated_mutation = match conflict_heads.as_ref() {
            Some(heads) if heads[0].operation_id != admitted.operation().operation_id => {
                Some(rehydrate_stored_mutation(trusted_material, &heads[0])?)
            }
            _ => None,
        };
        let representative = match &decision {
            MergeDecision::NoLiveChange => None,
            MergeDecision::ReplaceHeads { .. } | MergeDecision::ResolveConflict { .. } => {
                Some((admitted.operation().operation_id, admitted.mutation()))
            }
            MergeDecision::AddConflictHead { .. } => {
                let representative = conflict_heads
                    .as_ref()
                    .and_then(|heads| heads.first())
                    .ok_or_else(|| {
                        VaultError::Validation("conflict head set is empty".to_owned())
                    })?;
                let mutation = if representative.operation_id == admitted.operation().operation_id {
                    admitted.mutation()
                } else {
                    rehydrated_mutation.as_ref().ok_or_else(|| {
                        VaultError::Validation(
                            "conflict representative was not rehydrated".to_owned(),
                        )
                    })?
                };
                Some((representative.operation_id, mutation))
            }
        };
        let resolved_embedding = match representative {
            Some((operation_id, mutation))
                if matches!(
                    mutation,
                    RecordMutationV1::UpsertMemory(_) | RecordMutationV1::UpsertInstruction(_)
                ) =>
            {
                embedding_resolver
                    .resolve_representative_embedding(operation_id, mutation)
                    .map_err(|error| VaultError::Validation(error.to_string()))?
            }
            _ => None,
        };
        let cache_change = match representative {
            Some((_, mutation)) => {
                materialize_mutation(&transaction, mutation, resolved_embedding.as_ref())?
            }
            None => CacheChange::None,
        };

        insert_incoming_operation(&transaction, admitted, received_at)?;
        note_checkpoint_operation(
            &transaction,
            admitted.operation().account_id,
            admitted.operation().workspace_id,
            applied_at_ms,
        )?;
        transaction.execute(
            "INSERT INTO sync_nonces(key_epoch, nonce, operation_id) VALUES (?1, ?2, ?3)",
            params![
                i64::from(admitted.operation().key_epoch),
                admitted.operation().nonce.0.as_slice(),
                admitted.operation().operation_id.to_string(),
            ],
        )?;
        transaction.execute(
            "INSERT INTO sync_device_heads(
                 workspace_id, device_id, device_sequence, canonical_sha256
             ) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(workspace_id, device_id) DO UPDATE SET
                 device_sequence = excluded.device_sequence,
                 canonical_sha256 = excluded.canonical_sha256",
            params![
                admitted.operation().workspace_id.to_string(),
                admitted.operation().device_id.to_string(),
                admitted.operation().device_sequence.to_string(),
                admitted.canonical_hash().0.as_slice(),
            ],
        )?;

        match &decision {
            MergeDecision::NoLiveChange => {}
            MergeDecision::ReplaceHeads { remove } | MergeDecision::ResolveConflict { remove } => {
                for operation_id in remove {
                    transaction.execute(
                        "DELETE FROM sync_record_heads
                         WHERE workspace_id = ?1 AND record_id = ?2 AND operation_id = ?3",
                        params![
                            admitted.operation().workspace_id.to_string(),
                            admitted.operation().record_id.to_string(),
                            operation_id.to_string(),
                        ],
                    )?;
                }
                insert_record_head(&transaction, admitted)?;
                transaction.execute(
                    "DELETE FROM conflicts WHERE record_id = ?1",
                    [admitted.operation().record_id.to_string()],
                )?;
            }
            MergeDecision::AddConflictHead { remove } => {
                for operation_id in remove {
                    transaction.execute(
                        "DELETE FROM sync_record_heads
                         WHERE workspace_id = ?1 AND record_id = ?2 AND operation_id = ?3",
                        params![
                            admitted.operation().workspace_id.to_string(),
                            admitted.operation().record_id.to_string(),
                            operation_id.to_string(),
                        ],
                    )?;
                }
                insert_record_head(&transaction, admitted)?;
                let heads = conflict_heads.as_ref().ok_or_else(|| {
                    VaultError::Validation("conflict head set is unavailable".to_owned())
                })?;
                if heads.len() < 2 {
                    return Err(VaultError::Validation(
                        "conflict head set is incomplete".to_owned(),
                    ));
                }
                transaction.execute(
                    "INSERT INTO conflicts(record_id, left_operation_json, right_operation_json)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT(record_id) DO UPDATE SET
                         left_operation_json = excluded.left_operation_json,
                         right_operation_json = excluded.right_operation_json",
                    params![
                        admitted.operation().record_id.to_string(),
                        to_json(&heads[0])?,
                        to_json(&heads[1])?,
                    ],
                )?;
            }
        }
        if let Some(provider) = cursor_provider {
            upsert_cursor(
                &transaction,
                admitted.operation().workspace_id,
                provider,
                received_at,
                admitted.operation().operation_id,
            )?;
        }
        transaction.commit()?;
        apply_cache_change(&mut self.embedding_cache, cache_change);
        Ok(decision)
    }

    pub fn commit_outgoing_operation(
        &mut self,
        mutation: &RecordMutationV1,
        built: &BuiltOperation,
        embedding: Option<&Embedding384>,
    ) -> Result<CommitDisposition, VaultError> {
        let committed_at_ms = local_unix_ms()?;
        self.commit_outgoing_operation_at(mutation, built, embedding, committed_at_ms)
    }

    pub fn commit_outgoing_operation_at(
        &mut self,
        mutation: &RecordMutationV1,
        built: &BuiltOperation,
        embedding: Option<&Embedding384>,
        committed_at_ms: u64,
    ) -> Result<CommitDisposition, VaultError> {
        validate_commit(mutation, built)?;

        let transaction = self.connection.transaction()?;
        if exact_replay(&transaction, built)? {
            return Ok(CommitDisposition::ExactReplay);
        }

        ensure_sync_record_owner(
            &transaction,
            None,
            built.operation.account_id,
            built.operation.workspace_id,
            built.operation.record_id,
            built.operation.record_kind,
        )?;

        validate_device_chain(&transaction, &built.operation)?;
        let current_heads = load_record_heads(
            &transaction,
            built.operation.workspace_id,
            built.operation.record_id,
        )?;
        if current_heads
            .iter()
            .any(|head| compare_operations(&built.operation, &head.operation) != CausalOrder::After)
        {
            return Err(VaultError::Validation(
                "outgoing operation must causally follow every current record head".to_owned(),
            ));
        }
        let cache_change = materialize_mutation(&transaction, mutation, embedding)?;
        let operation = &built.operation;
        let operation_id = operation.operation_id.to_string();
        transaction.execute(
            "INSERT INTO operations(id, record_id, payload_json) VALUES (?1, ?2, ?3)",
            params![
                operation_id,
                operation.record_id.to_string(),
                to_json(operation)?
            ],
        )?;
        transaction.execute(
            "INSERT INTO sync_operation_meta(
                 operation_id, account_id, workspace_id, device_id, device_sequence,
                 canonical_sha256, direction, state
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'outgoing', 'queued')",
            params![
                operation_id,
                operation.account_id.to_string(),
                operation.workspace_id.to_string(),
                operation.device_id.to_string(),
                operation.device_sequence.to_string(),
                built.canonical_hash.0.as_slice(),
            ],
        )?;
        note_checkpoint_operation(
            &transaction,
            operation.account_id,
            operation.workspace_id,
            committed_at_ms,
        )?;
        transaction.execute(
            "INSERT INTO outbox(operation_id) VALUES (?1)",
            [&operation_id],
        )?;
        transaction.execute(
            "INSERT INTO sync_device_heads(
                 workspace_id, device_id, device_sequence, canonical_sha256
             ) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(workspace_id, device_id) DO UPDATE SET
                 device_sequence = excluded.device_sequence,
                 canonical_sha256 = excluded.canonical_sha256",
            params![
                operation.workspace_id.to_string(),
                operation.device_id.to_string(),
                operation.device_sequence.to_string(),
                built.canonical_hash.0.as_slice(),
            ],
        )?;
        transaction.execute(
            "DELETE FROM sync_record_heads
             WHERE workspace_id = ?1 AND record_id = ?2",
            params![
                operation.workspace_id.to_string(),
                operation.record_id.to_string()
            ],
        )?;
        transaction.execute(
            "INSERT INTO sync_record_heads(
                 workspace_id, record_id, operation_id, record_kind, mutation_kind,
                 canonical_sha256
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                operation.workspace_id.to_string(),
                operation.record_id.to_string(),
                operation_id,
                record_kind_name(operation.record_kind),
                mutation_kind_name(operation.mutation_kind),
                built.canonical_hash.0.as_slice(),
            ],
        )?;
        transaction.execute(
            "DELETE FROM conflicts WHERE record_id = ?1",
            [operation.record_id.to_string()],
        )?;
        transaction.execute(
            "INSERT INTO sync_nonces(key_epoch, nonce, operation_id) VALUES (?1, ?2, ?3)",
            params![
                i64::from(operation.key_epoch),
                operation.nonce.0.as_slice(),
                operation_id,
            ],
        )?;
        transaction.commit()?;

        match cache_change {
            CacheChange::PutMemory(record, embedding) => {
                self.embedding_cache.insert(
                    record.id.to_string(),
                    cached_embedding(&record.scope, record.archived, embedding),
                );
            }
            CacheChange::PutInstruction(record, embedding) => {
                self.embedding_cache.insert(
                    record.id.to_string(),
                    cached_embedding(&record.scope, record.archived, embedding),
                );
            }
            CacheChange::Remove(record_id) => {
                self.embedding_cache.remove(&record_id);
            }
            CacheChange::None => {}
        }
        Ok(CommitDisposition::Inserted)
    }

    pub fn due_outbox(
        &self,
        now_ms: u64,
        limit: usize,
    ) -> Result<Vec<DueOutboxOperation>, VaultError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit = i64::try_from(limit)
            .map_err(|_| VaultError::Validation("outbox limit exceeds i64".to_owned()))?;
        let now_ms = i64::try_from(now_ms).unwrap_or(i64::MAX);
        let mut statement = self.connection.prepare(
            "SELECT outbox.operation_id, operations.payload_json, outbox.attempt_count
             FROM outbox
             JOIN operations ON operations.id = outbox.operation_id
             WHERE outbox.next_attempt_ms <= ?1
               AND (
                   outbox.safe_error_code IS NULL
                   OR outbox.safe_error_code IN ('offline', 'transient')
               )
             ORDER BY outbox.next_attempt_ms, outbox.queued_at, outbox.operation_id
             LIMIT ?2",
        )?;
        let rows = statement.query_map(params![now_ms, limit], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        rows.map(|row| {
            let (operation_id, payload, attempt_count) = row?;
            let operation: SyncOperationV1 = from_json(&payload)?;
            let parsed_id = parse_operation_id(&operation_id)?;
            if operation.operation_id != parsed_id {
                return Err(VaultError::Validation(
                    "outbox operation identity does not match payload".to_owned(),
                ));
            }
            Ok(DueOutboxOperation {
                operation_id: parsed_id,
                canonical_bytes: encode_sync_operation_v1(&operation)
                    .map_err(|error| VaultError::Validation(error.to_string()))?,
                attempt_count: u32::try_from(attempt_count).map_err(|_| {
                    VaultError::Validation("invalid outbox attempt count".to_owned())
                })?,
            })
        })
        .collect()
    }

    pub fn acknowledge_outbox(&mut self, accepted: &[OperationId]) -> Result<(), VaultError> {
        let transaction = self.connection.transaction()?;
        for operation_id in accepted {
            transaction.execute(
                "DELETE FROM outbox WHERE operation_id = ?1",
                [operation_id.to_string()],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn defer_outbox(
        &mut self,
        ids: &[OperationId],
        next_ms: u64,
        code: &str,
    ) -> Result<(), VaultError> {
        validate_safe_error_code_v1(code)?;
        let next_ms = i64::try_from(next_ms).map_err(|_| {
            VaultError::Validation("outbox retry time exceeds SQLite integer range".to_owned())
        })?;
        let transaction = self.connection.transaction()?;
        for operation_id in ids {
            transaction.execute(
                "UPDATE outbox
                 SET attempt_count = attempt_count + 1,
                     next_attempt_ms = ?2,
                     safe_error_code = ?3
                 WHERE operation_id = ?1",
                params![operation_id.to_string(), next_ms, code],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn defer_outbox_individual(
        &mut self,
        retries: &[(OperationId, u64)],
        code: &str,
    ) -> Result<(), VaultError> {
        validate_safe_error_code_v1(code)?;
        let transaction = self.connection.transaction()?;
        for (operation_id, next_ms) in retries {
            let next_ms = i64::try_from(*next_ms).map_err(|_| {
                VaultError::Validation("outbox retry time exceeds SQLite integer range".to_owned())
            })?;
            transaction.execute(
                "UPDATE outbox
                 SET attempt_count = attempt_count + 1,
                     next_attempt_ms = ?2,
                     safe_error_code = ?3
                 WHERE operation_id = ?1",
                params![operation_id.to_string(), next_ms, code],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn unblock_outbox_after_state_change(
        &mut self,
        ids: &[OperationId],
        reason: OutboxUnblockReason,
        now_ms: u64,
    ) -> Result<usize, VaultError> {
        let now_ms = i64::try_from(now_ms).map_err(|_| {
            VaultError::Validation("outbox unblock time exceeds SQLite integer range".to_owned())
        })?;
        let mut unique = BTreeSet::new();
        if ids.iter().any(|operation_id| !unique.insert(*operation_id)) {
            return Err(VaultError::Validation(
                "outbox unblock operation IDs must be unique".to_owned(),
            ));
        }
        let eligible_code = reason.blocked_code();
        let transaction = self.connection.transaction()?;
        let mut changed = 0usize;
        for operation_id in ids {
            let code = transaction
                .query_row(
                    "SELECT safe_error_code FROM outbox WHERE operation_id = ?1",
                    [operation_id.to_string()],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()?
                .flatten();
            if code.as_deref() == Some("integrity_quarantined") {
                return Err(VaultError::Validation(
                    "integrity-quarantined outbox rows require forensic recovery".to_owned(),
                ));
            }
            if code.as_deref() != Some(eligible_code) {
                continue;
            }
            changed += transaction.execute(
                "UPDATE outbox
                 SET next_attempt_ms = ?2, safe_error_code = NULL
                 WHERE operation_id = ?1 AND safe_error_code = ?3",
                params![operation_id.to_string(), now_ms, eligible_code],
            )?;
        }
        transaction.commit()?;
        Ok(changed)
    }

    pub fn device_head(
        &self,
        workspace: WorkspaceId,
        device: DeviceId,
    ) -> Result<Option<StoredDeviceHead>, VaultError> {
        let row = self
            .connection
            .query_row(
                "SELECT device_sequence, canonical_sha256
                 FROM sync_device_heads
                 WHERE workspace_id = ?1 AND device_id = ?2",
                params![workspace.to_string(), device.to_string()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?;
        row.map(|(sequence, hash)| {
            Ok(StoredDeviceHead {
                sequence: parse_decimal_u64(&sequence)?,
                canonical_hash: parse_digest(&hash)?,
            })
        })
        .transpose()
    }

    pub fn record_heads(
        &self,
        workspace: WorkspaceId,
        record: RecordId,
    ) -> Result<Vec<StoredRecordHead>, VaultError> {
        load_record_heads(&self.connection, workspace, record)
    }

    pub fn sync_checkpoint_frontier(
        &self,
        scope: SyncScope,
    ) -> Result<Vec<DeviceSequence>, VaultError> {
        load_checkpoint_frontier(&self.connection, scope)
    }

    pub fn sync_state_summary(&self, scope: SyncScope) -> Result<StateSummaryV1, VaultError> {
        load_state_summary(&self.connection, scope)
    }

    pub fn sync_checkpoint_pin(
        &self,
        scope: SyncScope,
    ) -> Result<Option<StoredCheckpointPin>, VaultError> {
        load_checkpoint_pin(&self.connection, scope)
    }

    pub(crate) fn sync_checkpoint_scan(
        &self,
        scope: SyncScope,
        provider: &str,
    ) -> Result<Option<StoredCheckpointScan>, VaultError> {
        validate_sync_provider_v1(provider)?;
        load_checkpoint_scan(&self.connection, scope, provider)
    }

    pub(crate) fn save_sync_checkpoint_scan(
        &mut self,
        scope: SyncScope,
        provider: &str,
        cursor: &CheckpointCursor,
        authenticated: &AuthenticatedCheckpoint,
        base_pin_hash: Option<Sha256Digest>,
        pin_seen: bool,
    ) -> Result<(), VaultError> {
        validate_sync_provider_v1(provider)?;
        validate_received_at(&cursor.received_at)?;
        if authenticated.scope != scope
            || cursor.canonical_hash != authenticated.checkpoint.canonical_hash
            || authenticated.checkpoint.checkpoint.account_id != scope.account_id
            || authenticated.checkpoint.checkpoint.workspace_id != scope.workspace_id
        {
            return Err(VaultError::Validation(
                "checkpoint scan scope or cursor mismatch".to_owned(),
            ));
        }
        let transaction = self.connection.transaction()?;
        let existing = load_checkpoint_scan(&transaction, scope, provider)?;
        if let Some(existing) = existing {
            if existing.base_pin_hash != base_pin_hash
                || (existing.pin_seen && !pin_seen)
                || authenticated.checkpoint.checkpoint.previous_checkpoint_hash
                    != existing.checkpoint.canonical_hash
            {
                return Err(VaultError::Validation(
                    "checkpoint scan chain mismatch".to_owned(),
                ));
            }
        } else {
            let current_pin_hash =
                load_checkpoint_pin(&transaction, scope)?.map(|pin| pin.canonical_hash);
            if current_pin_hash != base_pin_hash
                || authenticated.checkpoint.checkpoint.previous_checkpoint_hash
                    != Sha256Digest([0; 32])
            {
                return Err(VaultError::Validation(
                    "checkpoint scan must begin at the trusted genesis".to_owned(),
                ));
            }
        }
        transaction.execute(
            "INSERT INTO sync_checkpoint_scans(
                 account_id, workspace_id, provider, received_at, canonical_sha256,
                 canonical_payload, base_pin_sha256, pin_seen
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(account_id, workspace_id, provider) DO UPDATE SET
                 received_at = excluded.received_at,
                 canonical_sha256 = excluded.canonical_sha256,
                 canonical_payload = excluded.canonical_payload,
                 base_pin_sha256 = excluded.base_pin_sha256,
                 pin_seen = excluded.pin_seen",
            params![
                scope.account_id.to_string(),
                scope.workspace_id.to_string(),
                provider,
                cursor.received_at,
                cursor.canonical_hash.0.as_slice(),
                authenticated.checkpoint.bytes,
                base_pin_hash.map(|hash| hash.0.to_vec()),
                i64::from(pin_seen),
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn accept_sync_checkpoint(
        &mut self,
        verified: &VerifiedCheckpoint,
        accepted_at_ms: u64,
    ) -> Result<CheckpointDisposition, VaultError> {
        let transaction = self.connection.transaction()?;
        let disposition =
            Self::accept_sync_checkpoint_in_transaction(&transaction, verified, accepted_at_ms)?;
        transaction.commit()?;
        Ok(disposition)
    }

    pub(crate) fn accept_sync_checkpoint_endpoint(
        &mut self,
        verified: &VerifiedCheckpoint,
        accepted_at_ms: u64,
        provider: &str,
    ) -> Result<CheckpointDisposition, VaultError> {
        validate_sync_provider_v1(provider)?;
        let transaction = self.connection.transaction()?;
        let scan =
            load_checkpoint_scan(&transaction, verified.scope, provider)?.ok_or_else(|| {
                VaultError::Validation("checkpoint endpoint scan is missing".to_owned())
            })?;
        if !scan.pin_seen
            || scan.base_pin_hash != verified.expected_pin_hash
            || scan.checkpoint != verified.checkpoint
        {
            return Err(VaultError::Validation(
                "checkpoint endpoint does not match its verified scan".to_owned(),
            ));
        }
        let disposition =
            Self::accept_sync_checkpoint_in_transaction(&transaction, verified, accepted_at_ms)?;
        let changed = transaction.execute(
            "UPDATE sync_checkpoint_scans
             SET base_pin_sha256 = ?4, pin_seen = 1
             WHERE account_id = ?1 AND workspace_id = ?2 AND provider = ?3
               AND canonical_sha256 = ?4",
            params![
                verified.scope.account_id.to_string(),
                verified.scope.workspace_id.to_string(),
                provider,
                verified.checkpoint.canonical_hash.0.as_slice(),
            ],
        )?;
        if changed != 1 {
            return Err(VaultError::Validation(
                "checkpoint scan cannot rebase to a different endpoint".to_owned(),
            ));
        }
        transaction.commit()?;
        Ok(disposition)
    }

    pub(crate) fn accept_sync_checkpoint_chain_extension(
        &mut self,
        verified: &VerifiedCheckpoint,
        accepted_at_ms: u64,
        provider: &str,
        anchor_hash: Sha256Digest,
    ) -> Result<CheckpointDisposition, VaultError> {
        validate_sync_provider_v1(provider)?;
        let transaction = self.connection.transaction()?;
        let scan =
            load_checkpoint_scan(&transaction, verified.scope, provider)?.ok_or_else(|| {
                VaultError::Validation("checkpoint chain anchor scan is missing".to_owned())
            })?;
        if !scan.pin_seen
            || scan.base_pin_hash != verified.expected_pin_hash
            || scan.checkpoint.canonical_hash != anchor_hash
            || verified.checkpoint.checkpoint.previous_checkpoint_hash != anchor_hash
        {
            return Err(VaultError::Validation(
                "checkpoint extension does not match its verified chain anchor".to_owned(),
            ));
        }
        let disposition =
            Self::accept_sync_checkpoint_in_transaction(&transaction, verified, accepted_at_ms)?;
        if load_checkpoint_scan(&transaction, verified.scope, provider)?.is_some() {
            return Err(VaultError::Validation(
                "checkpoint extension scan was not retired atomically".to_owned(),
            ));
        }
        transaction.commit()?;
        Ok(disposition)
    }

    fn accept_sync_checkpoint_in_transaction(
        transaction: &Transaction<'_>,
        verified: &VerifiedCheckpoint,
        accepted_at_ms: u64,
    ) -> Result<CheckpointDisposition, VaultError> {
        let accepted_at_sql = i64::try_from(accepted_at_ms).map_err(|_| {
            VaultError::Validation("checkpoint acceptance time exceeds SQLite range".to_owned())
        })?;
        let checkpoint = &verified.checkpoint;
        let decoded = decode_checkpoint_v1(&checkpoint.bytes)
            .map_err(|_| VaultError::Validation("invalid signed checkpoint".to_owned()))?;
        let canonical = encode_checkpoint_v1(&decoded)
            .map_err(|_| VaultError::Validation("invalid signed checkpoint".to_owned()))?;
        let canonical_hash = Sha256Digest(Sha256::digest(&canonical).into());
        if canonical != checkpoint.bytes
            || decoded != checkpoint.checkpoint
            || decoded.state_hash != checkpoint.state_hash
            || canonical_hash != checkpoint.canonical_hash
            || decoded.account_id != verified.scope.account_id
            || decoded.workspace_id != verified.scope.workspace_id
        {
            return Err(VaultError::Validation(
                "signed checkpoint metadata mismatch".to_owned(),
            ));
        }
        let current_frontier = load_checkpoint_frontier(transaction, verified.scope)?;
        let current_state_hash = load_state_summary(transaction, verified.scope)?
            .state_hash()
            .map_err(|_| VaultError::Validation("invalid checkpoint state".to_owned()))?;
        if decoded.causal_frontier != current_frontier || decoded.state_hash != current_state_hash {
            return Err(VaultError::Validation(
                "signed checkpoint no longer matches local state".to_owned(),
            ));
        }
        let current_pin = load_checkpoint_pin(transaction, verified.scope)?;
        let replay = current_pin
            .as_ref()
            .is_some_and(|pin| pin.canonical_hash == canonical_hash);
        if replay {
            let pin = current_pin.as_ref().expect("replay has a pin");
            if pin.canonical_bytes != canonical || pin.state_hash != decoded.state_hash {
                return Err(VaultError::OperationConflict);
            }
        } else if current_pin.as_ref().map(|pin| pin.canonical_hash) != verified.expected_pin_hash {
            return Err(VaultError::Validation(
                "signed checkpoint chain proof does not extend the local pin".to_owned(),
            ));
        }

        if let Some((account, workspace, state_hash, payload)) = transaction
            .query_row(
                "SELECT account_id, workspace_id, state_hash, canonical_payload
                 FROM signed_sync_checkpoints
                 WHERE account_id = ?1 AND workspace_id = ?2 AND canonical_sha256 = ?3",
                params![
                    verified.scope.account_id.to_string(),
                    verified.scope.workspace_id.to_string(),
                    canonical_hash.0.as_slice(),
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .optional()?
        {
            if account != verified.scope.account_id.to_string()
                || workspace != verified.scope.workspace_id.to_string()
                || parse_digest(&state_hash)? != decoded.state_hash
                || payload != canonical
            {
                return Err(VaultError::OperationConflict);
            }
        } else {
            transaction.execute(
                "INSERT INTO signed_sync_checkpoints(
                     canonical_sha256, account_id, workspace_id, state_hash,
                     canonical_payload, accepted_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    canonical_hash.0.as_slice(),
                    verified.scope.account_id.to_string(),
                    verified.scope.workspace_id.to_string(),
                    decoded.state_hash.0.as_slice(),
                    canonical,
                    accepted_at_sql,
                ],
            )?;
        }
        transaction.execute(
            "INSERT INTO sync_checkpoint_pins(account_id, workspace_id, canonical_sha256)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(account_id, workspace_id) DO UPDATE SET
                 canonical_sha256 = excluded.canonical_sha256",
            params![
                verified.scope.account_id.to_string(),
                verified.scope.workspace_id.to_string(),
                canonical_hash.0.as_slice(),
            ],
        )?;
        transaction.execute(
            "DELETE FROM sync_checkpoint_scans
             WHERE account_id = ?1 AND workspace_id = ?2
               AND canonical_sha256 != ?3",
            params![
                verified.scope.account_id.to_string(),
                verified.scope.workspace_id.to_string(),
                canonical_hash.0.as_slice(),
            ],
        )?;
        transaction.execute(
            "INSERT INTO sync_checkpoint_schedule(
                 account_id, workspace_id, applied_operations, first_uncheckpointed_ms,
                 last_checkpoint_ms, requested
             ) VALUES (?1, ?2, 0, NULL, ?3, 0)
             ON CONFLICT(account_id, workspace_id) DO UPDATE SET
                 applied_operations = 0,
                 first_uncheckpointed_ms = NULL,
                 last_checkpoint_ms = excluded.last_checkpoint_ms,
                 requested = 0",
            params![
                verified.scope.account_id.to_string(),
                verified.scope.workspace_id.to_string(),
                accepted_at_sql,
            ],
        )?;
        Ok(if replay {
            CheckpointDisposition::ExactReplay
        } else {
            CheckpointDisposition::Inserted
        })
    }

    pub fn sync_checkpoint_schedule(
        &self,
        scope: SyncScope,
    ) -> Result<SyncCheckpointSchedule, VaultError> {
        load_checkpoint_schedule(&self.connection, scope)
    }

    pub fn request_sync_checkpoint(&mut self, scope: SyncScope) -> Result<(), VaultError> {
        self.connection.execute(
            "INSERT INTO sync_checkpoint_schedule(
                 account_id, workspace_id, applied_operations, first_uncheckpointed_ms,
                 last_checkpoint_ms, requested
             ) VALUES (?1, ?2, 0, NULL, NULL, 1)
             ON CONFLICT(account_id, workspace_id) DO UPDATE SET requested = 1",
            params![scope.account_id.to_string(), scope.workspace_id.to_string()],
        )?;
        Ok(())
    }

    pub fn secret_ref(
        &self,
        id: &context_relay_protocol::SecretRefId,
    ) -> Result<Option<context_relay_protocol::SecretRef>, VaultError> {
        self.connection
            .query_row(
                "SELECT payload_json FROM secret_refs WHERE id = ?1",
                [id.to_string()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|payload| from_json(&payload))
            .transpose()
    }

    pub(crate) fn stored_sync_operation(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<Vec<u8>>, VaultError> {
        self.connection
            .query_row(
                "SELECT payload_json FROM operations WHERE id = ?1",
                [operation_id.to_string()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|payload| {
                let operation: SyncOperationV1 = from_json(&payload)?;
                encode_sync_operation_v1(&operation)
                    .map_err(|_| VaultError::Validation("invalid stored operation".to_owned()))
            })
            .transpose()
    }

    pub(crate) fn operation_at_device_sequence(
        &self,
        workspace: WorkspaceId,
        device: DeviceId,
        sequence: u64,
    ) -> Result<Option<OperationId>, VaultError> {
        self.connection
            .query_row(
                "SELECT operation_id FROM sync_operation_meta
                 WHERE workspace_id = ?1 AND device_id = ?2 AND device_sequence = ?3",
                params![
                    workspace.to_string(),
                    device.to_string(),
                    sequence.to_string()
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(|value| parse_operation_id(&value))
            .transpose()
    }

    pub(crate) fn materialized_record_scope(
        &self,
        workspace_id: WorkspaceId,
        record_id: RecordId,
        record_kind: RecordKind,
    ) -> Result<Option<ScopeRef>, VaultError> {
        if let Some(scope) = materialized_scope(&self.connection, record_id, record_kind)? {
            return Ok(Some(scope));
        }
        durable_record_scope(&self.connection, workspace_id, record_id, record_kind)
    }

    pub(crate) fn record_belongs_to_sync_scope(
        &self,
        trusted_material: &impl TrustedSyncMaterial,
        account_id: AccountId,
        workspace_id: WorkspaceId,
        record_id: RecordId,
        record_kind: RecordKind,
    ) -> Result<bool, VaultError> {
        record_belongs_to_sync_scope(
            &self.connection,
            trusted_material,
            account_id,
            workspace_id,
            record_id,
            record_kind,
        )
    }

    pub fn bind_sync_record_owner(
        &mut self,
        scope: SyncScope,
        record_id: RecordId,
        record_kind: RecordKind,
    ) -> Result<(), VaultError> {
        let transaction = self.connection.transaction()?;
        let materialized = materialized_record_kinds(&transaction, record_id)?;
        if let Some(owner) = stored_sync_record_owner(&transaction, record_id)?
            && owner.state == SyncRecordOwnerState::LegacyPending
        {
            if owner.record_kind != record_kind || materialized.as_slice() != [record_kind] {
                return Err(VaultError::Validation(
                    "legacy sync record binding does not match materialized kind".to_owned(),
                ));
            }
            transaction.execute(
                "UPDATE sync_record_owners
                 SET account_id = ?2, workspace_id = ?3, binding_state = 'verified'
                 WHERE record_id = ?1 AND binding_state = 'legacy_pending'",
                params![
                    record_id.to_string(),
                    scope.account_id.to_string(),
                    scope.workspace_id.to_string(),
                ],
            )?;
            transaction.commit()?;
            return Ok(());
        }
        if materialized.as_slice() != [record_kind] {
            return Err(VaultError::Validation(
                "sync record binding requires exactly one matching materialized kind".to_owned(),
            ));
        }
        insert_or_verify_sync_record_owner(
            &transaction,
            scope.account_id,
            scope.workspace_id,
            record_id,
            record_kind,
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn sync_cursor(
        &self,
        workspace: WorkspaceId,
        provider: &str,
    ) -> Result<Option<SyncCursor>, VaultError> {
        validate_sync_provider_v1(provider)?;
        let row = self
            .connection
            .query_row(
                "SELECT received_at, operation_id
                 FROM sync_cursors
                 WHERE workspace_id = ?1 AND provider = ?2",
                params![workspace.to_string(), provider],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        row.map(|(received_at, operation_id)| {
            Ok(SyncCursor {
                received_at,
                operation_id: parse_operation_id(&operation_id)?,
            })
        })
        .transpose()
    }
}

fn validate_quarantine_write(write: &SyncQuarantineWrite<'_>) -> Result<(), VaultError> {
    validate_sync_provider_v1(write.provider)?;
    validate_received_at(write.received_at)?;
    if write.receipt_operation_id != write.routed_operation_id {
        return Err(VaultError::Validation(
            "quarantine cursor does not match routed operation".to_owned(),
        ));
    }
    if !matches!(
        write.safe_error_code,
        "integrity_quarantined" | "gap_pending"
    ) {
        return Err(VaultError::Validation(
            "invalid quarantine error code".to_owned(),
        ));
    }
    if write.envelope.len() > MAX_CBOR_OPERATION_BYTES {
        return Err(VaultError::Validation(
            "quarantine envelope exceeds the signed operation limit".to_owned(),
        ));
    }
    Ok(())
}

fn load_quarantined_sync_receipt(
    connection: &Connection,
    account_id: AccountId,
    workspace_id: WorkspaceId,
    provider: &str,
    received_at: &str,
    receipt_operation_id: OperationId,
) -> Result<Option<StoredSyncQuarantine>, VaultError> {
    let stored = connection
        .query_row(
            "SELECT routed_operation_id, device_id, device_sequence,
                    safe_error_code, envelope, quarantined_at_ms
             FROM sync_quarantine
             WHERE account_id = ?1 AND workspace_id = ?2 AND provider = ?3
               AND received_at = ?4 AND receipt_operation_id = ?5",
            params![
                account_id.to_string(),
                workspace_id.to_string(),
                provider,
                received_at,
                receipt_operation_id.to_string(),
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()?;
    stored
        .map(
            |(routed_operation_id, device_id, device_sequence, code, envelope, at_ms)| {
                let routed_operation_id = routed_operation_id.parse().map_err(|_| {
                    VaultError::Validation("invalid quarantined routed operation ID".to_owned())
                })?;
                let device_id = device_id.parse().map_err(|_| {
                    VaultError::Validation("invalid quarantined device ID".to_owned())
                })?;
                let quarantined_at_ms = u64::try_from(at_ms).map_err(|_| {
                    VaultError::Validation("invalid quarantined timestamp".to_owned())
                })?;
                Ok(StoredSyncQuarantine {
                    account_id,
                    workspace_id,
                    provider: provider.to_owned(),
                    received_at: received_at.to_owned(),
                    receipt_operation_id,
                    routed_operation_id,
                    device_id,
                    device_sequence: parse_decimal_u64(&device_sequence)?,
                    safe_error_code: code,
                    envelope,
                    quarantined_at_ms,
                })
            },
        )
        .transpose()
}

fn validate_rejection_write(
    write: &SyncRejectionWrite<'_>,
) -> Result<(u64, i64, Sha256Digest), VaultError> {
    validate_sync_provider_v1(write.provider)?;
    validate_received_at(write.received_at)?;
    if write.receipt_operation_id != write.routed_operation_id {
        return Err(VaultError::Validation(
            "rejection cursor does not match routed operation".to_owned(),
        ));
    }
    if write.safe_error_code != "integrity_quarantined" {
        return Err(VaultError::Validation(
            "invalid oversized rejection error code".to_owned(),
        ));
    }
    if write.received_bytes.len() <= MAX_CBOR_OPERATION_BYTES {
        return Err(VaultError::Validation(
            "oversized rejection requires bytes above the signed operation limit".to_owned(),
        ));
    }
    let claimed_byte_length = u64::try_from(write.received_bytes.len())
        .map_err(|_| VaultError::Validation("rejected byte length exceeds u64 range".to_owned()))?;
    let claimed_byte_length_sql = i64::try_from(write.received_bytes.len()).map_err(|_| {
        VaultError::Validation("rejected byte length exceeds SQLite integer range".to_owned())
    })?;
    let received_sha256 = Sha256Digest(Sha256::digest(write.received_bytes).into());
    Ok((
        claimed_byte_length,
        claimed_byte_length_sql,
        received_sha256,
    ))
}

fn load_rejected_sync_receipt(
    connection: &Connection,
    account_id: AccountId,
    workspace_id: WorkspaceId,
    provider: &str,
    received_at: &str,
    receipt_operation_id: OperationId,
) -> Result<Option<StoredSyncRejection>, VaultError> {
    let stored = connection
        .query_row(
            "SELECT routed_operation_id, device_id, device_sequence,
                    safe_error_code, claimed_byte_length, received_sha256,
                    rejected_at_ms
             FROM sync_rejections
             WHERE account_id = ?1 AND workspace_id = ?2 AND provider = ?3
               AND received_at = ?4 AND receipt_operation_id = ?5",
            params![
                account_id.to_string(),
                workspace_id.to_string(),
                provider,
                received_at,
                receipt_operation_id.to_string(),
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )
        .optional()?;
    stored
        .map(
            |(
                routed_operation_id,
                device_id,
                device_sequence,
                code,
                byte_length,
                digest,
                at_ms,
            )| {
                let routed_operation_id = routed_operation_id.parse().map_err(|_| {
                    VaultError::Validation("invalid rejected routed operation ID".to_owned())
                })?;
                let device_id = device_id
                    .parse()
                    .map_err(|_| VaultError::Validation("invalid rejected device ID".to_owned()))?;
                let claimed_byte_length = u64::try_from(byte_length).map_err(|_| {
                    VaultError::Validation("invalid rejected byte length".to_owned())
                })?;
                if claimed_byte_length <= MAX_CBOR_OPERATION_BYTES as u64 {
                    return Err(VaultError::Validation(
                        "invalid rejected byte length".to_owned(),
                    ));
                }
                let rejected_at_ms = u64::try_from(at_ms)
                    .map_err(|_| VaultError::Validation("invalid rejected timestamp".to_owned()))?;
                Ok(StoredSyncRejection {
                    account_id,
                    workspace_id,
                    provider: provider.to_owned(),
                    received_at: received_at.to_owned(),
                    receipt_operation_id,
                    routed_operation_id,
                    device_id,
                    device_sequence: parse_decimal_u64(&device_sequence)?,
                    safe_error_code: code,
                    claimed_byte_length,
                    received_sha256: parse_digest(&digest)?,
                    rejected_at_ms,
                })
            },
        )
        .transpose()
}

fn validate_admitted(admitted: &AdmittedOperation) -> Result<(), VaultError> {
    admitted
        .operation()
        .validate()
        .map_err(|_| VaultError::Validation("invalid admitted operation".to_owned()))?;
    admitted
        .mutation()
        .validate()
        .map_err(|_| VaultError::Validation("invalid admitted mutation".to_owned()))?;
    if admitted.operation().record_id != admitted.mutation().record_id()
        || admitted.operation().record_kind != admitted.mutation().record_kind()
        || admitted.operation().mutation_kind != admitted.mutation().mutation_kind()
    {
        return Err(VaultError::Validation(
            "admitted operation does not match mutation".to_owned(),
        ));
    }
    let canonical = encode_sync_operation_v1(admitted.operation())
        .map_err(|_| VaultError::Validation("invalid admitted operation".to_owned()))?;
    let hash = Sha256Digest(Sha256::digest(&canonical).into());
    if canonical != admitted.canonical_bytes() || hash != admitted.canonical_hash() {
        return Err(VaultError::Validation(
            "admitted canonical operation mismatch".to_owned(),
        ));
    }
    Ok(())
}

fn rehydrate_stored_mutation(
    trusted_material: &(impl TrustedSyncMaterial + ?Sized),
    operation: &SyncOperationV1,
) -> Result<RecordMutationV1, VaultError> {
    let key = trusted_material
        .content_key(operation.workspace_id, operation.key_epoch)
        .map_err(|_| {
            VaultError::Validation("stored representative key is unavailable".to_owned())
        })?;
    let aad = encode_sync_operation_aad_v1(operation).map_err(|_| {
        VaultError::Validation("stored representative envelope is invalid".to_owned())
    })?;
    let plaintext = key
        .decrypt(
            &EncryptedPayload {
                nonce: operation.nonce,
                ciphertext: operation.ciphertext.as_slice().to_vec(),
            },
            &aad,
        )
        .map_err(|_| {
            VaultError::Validation("stored representative decryption failed".to_owned())
        })?;
    let mutation = decode_record_mutation_v1(plaintext.expose()).map_err(|_| {
        VaultError::Validation("stored representative mutation is invalid".to_owned())
    })?;
    if operation.record_id != mutation.record_id()
        || operation.record_kind != mutation.record_kind()
        || operation.mutation_kind != mutation.mutation_kind()
        || !scope_matches(operation.project_id, &mutation)
    {
        return Err(VaultError::Validation(
            "stored representative mutation does not match envelope".to_owned(),
        ));
    }
    Ok(mutation)
}

fn load_record_heads(
    connection: &Connection,
    workspace: WorkspaceId,
    record: RecordId,
) -> Result<Vec<StoredRecordHead>, VaultError> {
    let mut statement = connection.prepare(
        "SELECT sync_record_heads.operation_id, sync_record_heads.record_kind,
                sync_record_heads.mutation_kind, sync_record_heads.canonical_sha256,
                operations.payload_json
         FROM sync_record_heads
         JOIN operations ON operations.id = sync_record_heads.operation_id
         WHERE sync_record_heads.workspace_id = ?1 AND sync_record_heads.record_id = ?2
         ORDER BY sync_record_heads.operation_id",
    )?;
    let rows = statement.query_map(params![workspace.to_string(), record.to_string()], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Vec<u8>>(3)?,
            row.get::<_, Vec<u8>>(4)?,
        ))
    })?;
    rows.map(|row| {
        let (operation_id, record_kind, mutation_kind, hash, payload) = row?;
        let operation_id = parse_operation_id(&operation_id)?;
        let record_kind = parse_record_kind(&record_kind)?;
        let mutation_kind = parse_mutation_kind(&mutation_kind)?;
        let canonical_hash = parse_digest(&hash)?;
        let operation: SyncOperationV1 = from_json(&payload)?;
        operation
            .validate()
            .map_err(|_| VaultError::Validation("invalid stored head operation".to_owned()))?;
        let operation_bytes = encode_sync_operation_v1(&operation)
            .map_err(|_| VaultError::Validation("invalid stored head operation".to_owned()))?;
        if operation.operation_id != operation_id
            || operation.record_kind != record_kind
            || operation.mutation_kind != mutation_kind
            || Sha256Digest(Sha256::digest(&operation_bytes).into()) != canonical_hash
        {
            return Err(VaultError::Validation(
                "stored head metadata does not match operation".to_owned(),
            ));
        }
        Ok(StoredRecordHead {
            operation_id,
            record_kind,
            mutation_kind,
            canonical_hash,
            operation,
        })
    })
    .collect()
}

fn load_checkpoint_frontier(
    connection: &Connection,
    scope: SyncScope,
) -> Result<Vec<DeviceSequence>, VaultError> {
    let mut statement = connection.prepare(
        "SELECT heads.device_id, heads.device_sequence, heads.canonical_sha256,
                meta.account_id, meta.canonical_sha256
         FROM sync_device_heads AS heads
         JOIN sync_operation_meta AS meta
           ON meta.workspace_id = heads.workspace_id
          AND meta.device_id = heads.device_id
          AND meta.device_sequence = heads.device_sequence
         WHERE heads.workspace_id = ?1
         ORDER BY heads.device_id",
    )?;
    let rows = statement.query_map([scope.workspace_id.to_string()], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, Vec<u8>>(4)?,
        ))
    })?;
    let mut frontier = Vec::new();
    for row in rows {
        let (device, sequence, head_hash, account, operation_hash) = row?;
        if account != scope.account_id.to_string()
            || parse_digest(&head_hash)? != parse_digest(&operation_hash)?
        {
            return Err(VaultError::Validation(
                "invalid stored checkpoint frontier".to_owned(),
            ));
        }
        frontier.push(DeviceSequence {
            device_id: parse_device_id(&device)?,
            sequence: parse_decimal_u64(&sequence)?,
        });
    }
    if frontier
        .windows(2)
        .any(|pair| pair[0].device_id >= pair[1].device_id)
    {
        return Err(VaultError::Validation(
            "invalid stored checkpoint frontier order".to_owned(),
        ));
    }
    let stored_head_count: i64 = connection.query_row(
        "SELECT count(*) FROM sync_device_heads WHERE workspace_id = ?1",
        [scope.workspace_id.to_string()],
        |row| row.get(0),
    )?;
    if usize::try_from(stored_head_count).ok() != Some(frontier.len()) {
        return Err(VaultError::Validation(
            "checkpoint frontier contains an unbound device head".to_owned(),
        ));
    }
    Ok(frontier)
}

fn load_state_summary(
    connection: &Connection,
    scope: SyncScope,
) -> Result<StateSummaryV1, VaultError> {
    let mut statement = connection.prepare(
        "SELECT DISTINCT heads.record_id
         FROM sync_record_heads AS heads
         JOIN sync_operation_meta AS meta ON meta.operation_id = heads.operation_id
         WHERE heads.workspace_id = ?1 AND meta.account_id = ?2 AND meta.workspace_id = ?1
         ORDER BY heads.record_id",
    )?;
    let record_rows = statement.query_map(
        params![scope.workspace_id.to_string(), scope.account_id.to_string()],
        |row| row.get::<_, String>(0),
    )?;
    let mut record_ids = Vec::new();
    for row in record_rows {
        record_ids.push(parse_record_id(&row?)?);
    }
    drop(statement);

    let mut entries = Vec::with_capacity(record_ids.len());
    for record_id in record_ids {
        let heads = load_record_heads(connection, scope.workspace_id, record_id)?;
        let representative = heads.first().ok_or_else(|| {
            VaultError::Validation("checkpoint record has no durable heads".to_owned())
        })?;
        if heads.iter().any(|head| {
            head.record_kind != representative.record_kind
                || head.operation.account_id != scope.account_id
                || head.operation.workspace_id != scope.workspace_id
                || head.operation.record_id != record_id
        }) {
            return Err(VaultError::Validation(
                "checkpoint record heads disagree on scope or kind".to_owned(),
            ));
        }
        let mut head_hashes = heads
            .iter()
            .map(|head| head.canonical_hash)
            .collect::<Vec<_>>();
        head_hashes.sort();
        if head_hashes.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(VaultError::Validation(
                "checkpoint record has duplicate head hashes".to_owned(),
            ));
        }
        entries.push(StateSummaryEntryV1 {
            record_id,
            record_kind: representative.record_kind,
            head_hashes,
            tombstoned: representative.mutation_kind == MutationKind::Tombstone,
            conflicted: heads.len() > 1,
        });
    }

    let total_heads: i64 = connection.query_row(
        "SELECT count(*) FROM sync_record_heads WHERE workspace_id = ?1",
        [scope.workspace_id.to_string()],
        |row| row.get(0),
    )?;
    let summarized_heads = entries
        .iter()
        .try_fold(0_i64, |total, entry| {
            i64::try_from(entry.head_hashes.len())
                .ok()
                .and_then(|count| total.checked_add(count))
        })
        .ok_or_else(|| VaultError::Validation("checkpoint head count overflow".to_owned()))?;
    if total_heads != summarized_heads {
        return Err(VaultError::Validation(
            "checkpoint workspace contains unscoped heads".to_owned(),
        ));
    }
    Ok(StateSummaryV1 { entries })
}

fn load_checkpoint_pin(
    connection: &Connection,
    scope: SyncScope,
) -> Result<Option<StoredCheckpointPin>, VaultError> {
    let pin_hash = connection
        .query_row(
            "SELECT canonical_sha256 FROM sync_checkpoint_pins
             WHERE account_id = ?1 AND workspace_id = ?2",
            params![scope.account_id.to_string(), scope.workspace_id.to_string()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    let Some(pin_hash) = pin_hash else {
        return Ok(None);
    };
    let pin_hash = parse_digest(&pin_hash)?;
    let row = connection
        .query_row(
            "SELECT state_hash, canonical_payload, accepted_at_ms, account_id, workspace_id
             FROM signed_sync_checkpoints
             WHERE account_id = ?1 AND workspace_id = ?2 AND canonical_sha256 = ?3",
            params![
                scope.account_id.to_string(),
                scope.workspace_id.to_string(),
                pin_hash.0.as_slice(),
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| VaultError::Validation("checkpoint pin target is missing".to_owned()))?;
    let (state_hash, payload, accepted_at_ms, account, workspace) = row;
    if account != scope.account_id.to_string()
        || workspace != scope.workspace_id.to_string()
        || accepted_at_ms < 0
    {
        return Err(VaultError::Validation(
            "invalid stored checkpoint pin scope".to_owned(),
        ));
    }
    let state_hash = parse_digest(&state_hash)?;
    let checkpoint = decode_checkpoint_v1(&payload)
        .map_err(|_| VaultError::Validation("invalid stored checkpoint payload".to_owned()))?;
    let canonical = encode_checkpoint_v1(&checkpoint)
        .map_err(|_| VaultError::Validation("invalid stored checkpoint payload".to_owned()))?;
    if canonical != payload
        || digest_bytes(&canonical) != pin_hash
        || checkpoint.state_hash != state_hash
    {
        return Err(VaultError::Validation(
            "stored checkpoint pin metadata mismatch".to_owned(),
        ));
    }
    Ok(Some(StoredCheckpointPin {
        scope,
        canonical_hash: pin_hash,
        state_hash,
        canonical_bytes: canonical,
        accepted_at_ms: u64::try_from(accepted_at_ms)
            .map_err(|_| VaultError::Validation("invalid checkpoint acceptance time".to_owned()))?,
    }))
}

fn load_checkpoint_schedule(
    connection: &Connection,
    scope: SyncScope,
) -> Result<SyncCheckpointSchedule, VaultError> {
    let row = connection
        .query_row(
            "SELECT applied_operations, first_uncheckpointed_ms,
                    last_checkpoint_ms, requested
             FROM sync_checkpoint_schedule
             WHERE account_id = ?1 AND workspace_id = ?2",
            params![scope.account_id.to_string(), scope.workspace_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?;
    let Some((applied, first, last, requested)) = row else {
        return Ok(SyncCheckpointSchedule {
            applied_operations: 0,
            first_uncheckpointed_ms: None,
            last_checkpoint_ms: None,
            requested: false,
        });
    };
    if applied < 0
        || first.is_some_and(|value| value < 0)
        || last.is_some_and(|value| value < 0)
        || !matches!(requested, 0 | 1)
        || (applied == 0) != first.is_none()
    {
        return Err(VaultError::Validation(
            "invalid stored checkpoint schedule".to_owned(),
        ));
    }
    Ok(SyncCheckpointSchedule {
        applied_operations: u64::try_from(applied)
            .map_err(|_| VaultError::Validation("invalid checkpoint count".to_owned()))?,
        first_uncheckpointed_ms: first
            .map(u64::try_from)
            .transpose()
            .map_err(|_| VaultError::Validation("invalid checkpoint schedule time".to_owned()))?,
        last_checkpoint_ms: last
            .map(u64::try_from)
            .transpose()
            .map_err(|_| VaultError::Validation("invalid checkpoint schedule time".to_owned()))?,
        requested: requested == 1,
    })
}

fn load_checkpoint_scan(
    connection: &Connection,
    scope: SyncScope,
    provider: &str,
) -> Result<Option<StoredCheckpointScan>, VaultError> {
    let row = connection
        .query_row(
            "SELECT received_at, canonical_sha256, canonical_payload,
                    base_pin_sha256, pin_seen
             FROM sync_checkpoint_scans
             WHERE account_id = ?1 AND workspace_id = ?2 AND provider = ?3",
            params![
                scope.account_id.to_string(),
                scope.workspace_id.to_string(),
                provider,
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((received_at, stored_hash, payload, base_pin, pin_seen)) = row else {
        return Ok(None);
    };
    validate_received_at(&received_at)?;
    if !matches!(pin_seen, 0 | 1) {
        return Err(VaultError::Validation(
            "invalid checkpoint scan pin marker".to_owned(),
        ));
    }
    let canonical_hash = parse_digest(&stored_hash)?;
    let decoded = decode_checkpoint_v1(&payload)
        .map_err(|_| VaultError::Validation("invalid scanned checkpoint".to_owned()))?;
    let checkpoint = CanonicalCheckpoint::from_checkpoint(decoded)
        .map_err(|_| VaultError::Validation("invalid scanned checkpoint".to_owned()))?;
    if checkpoint.bytes != payload
        || checkpoint.canonical_hash != canonical_hash
        || checkpoint.checkpoint.account_id != scope.account_id
        || checkpoint.checkpoint.workspace_id != scope.workspace_id
    {
        return Err(VaultError::Validation(
            "checkpoint scan metadata mismatch".to_owned(),
        ));
    }
    let base_pin_hash = base_pin.as_deref().map(parse_digest).transpose()?;
    Ok(Some(StoredCheckpointScan {
        scope,
        provider: provider.to_owned(),
        cursor: CheckpointCursor {
            received_at,
            canonical_hash,
        },
        checkpoint,
        base_pin_hash,
        pin_seen: pin_seen == 1,
    }))
}

fn note_checkpoint_operation(
    transaction: &Transaction<'_>,
    account: AccountId,
    workspace: WorkspaceId,
    applied_at_ms: u64,
) -> Result<(), VaultError> {
    let applied_at_ms = i64::try_from(applied_at_ms).unwrap_or(i64::MAX);
    transaction.execute(
        "INSERT INTO sync_checkpoint_schedule(
             account_id, workspace_id, applied_operations, first_uncheckpointed_ms,
             last_checkpoint_ms, requested
         ) VALUES (?1, ?2, 1, ?3, NULL, 0)
         ON CONFLICT(account_id, workspace_id) DO UPDATE SET
             applied_operations = CASE
                 WHEN applied_operations < 9223372036854775807
                 THEN applied_operations + 1
                 ELSE applied_operations
             END,
             first_uncheckpointed_ms = COALESCE(first_uncheckpointed_ms, excluded.first_uncheckpointed_ms)",
        params![account.to_string(), workspace.to_string(), applied_at_ms],
    )?;
    Ok(())
}

fn local_unix_ms() -> Result<u64, VaultError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| VaultError::Validation("local clock predates Unix epoch".to_owned()))?
        .as_millis();
    u64::try_from(millis)
        .map_err(|_| VaultError::Validation("local clock exceeds supported range".to_owned()))
}

fn digest_bytes(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest(Sha256::digest(bytes).into())
}

fn validate_received_at(received_at: &str) -> Result<(), VaultError> {
    if received_at.is_empty()
        || received_at.len() > 128
        || !received_at
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'\'' && byte != b'"')
    {
        return Err(VaultError::Validation(
            "invalid sync receipt cursor".to_owned(),
        ));
    }
    Ok(())
}

fn exact_incoming_replay(
    transaction: &Transaction<'_>,
    admitted: &AdmittedOperation,
) -> Result<bool, VaultError> {
    let payload = transaction
        .query_row(
            "SELECT payload_json FROM operations WHERE id = ?1",
            [admitted.operation().operation_id.to_string()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    let Some(payload) = payload else {
        return Ok(false);
    };
    let operation: SyncOperationV1 = from_json(&payload)?;
    let canonical = encode_sync_operation_v1(&operation)
        .map_err(|_| VaultError::Validation("invalid stored operation".to_owned()))?;
    if canonical == admitted.canonical_bytes() {
        Ok(true)
    } else {
        Err(VaultError::OperationConflict)
    }
}

fn insert_incoming_operation(
    transaction: &Transaction<'_>,
    admitted: &AdmittedOperation,
    received_at: &str,
) -> Result<(), VaultError> {
    let operation = admitted.operation();
    transaction.execute(
        "INSERT INTO operations(id, record_id, payload_json) VALUES (?1, ?2, ?3)",
        params![
            operation.operation_id.to_string(),
            operation.record_id.to_string(),
            to_json(operation)?,
        ],
    )?;
    transaction.execute(
        "INSERT INTO sync_operation_meta(
             operation_id, account_id, workspace_id, device_id, device_sequence,
             canonical_sha256, direction, state, received_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'incoming', 'applied', ?7)",
        params![
            operation.operation_id.to_string(),
            operation.account_id.to_string(),
            operation.workspace_id.to_string(),
            operation.device_id.to_string(),
            operation.device_sequence.to_string(),
            admitted.canonical_hash().0.as_slice(),
            received_at,
        ],
    )?;
    Ok(())
}

fn insert_record_head(
    transaction: &Transaction<'_>,
    admitted: &AdmittedOperation,
) -> Result<(), VaultError> {
    let operation = admitted.operation();
    transaction.execute(
        "INSERT INTO sync_record_heads(
             workspace_id, record_id, operation_id, record_kind, mutation_kind,
             canonical_sha256
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            operation.workspace_id.to_string(),
            operation.record_id.to_string(),
            operation.operation_id.to_string(),
            record_kind_name(operation.record_kind),
            mutation_kind_name(operation.mutation_kind),
            admitted.canonical_hash().0.as_slice(),
        ],
    )?;
    Ok(())
}

fn upsert_cursor(
    transaction: &Transaction<'_>,
    workspace: WorkspaceId,
    provider: &str,
    received_at: &str,
    operation_id: OperationId,
) -> Result<(), VaultError> {
    transaction.execute(
        "INSERT INTO sync_cursors(workspace_id, provider, received_at, operation_id)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(workspace_id, provider) DO UPDATE SET
             received_at = excluded.received_at,
             operation_id = excluded.operation_id
         WHERE excluded.received_at > sync_cursors.received_at
            OR (excluded.received_at = sync_cursors.received_at
                AND excluded.operation_id > sync_cursors.operation_id)",
        params![
            workspace.to_string(),
            provider,
            received_at,
            operation_id.to_string(),
        ],
    )?;
    Ok(())
}

fn apply_cache_change(
    cache: &mut std::collections::BTreeMap<String, super::CachedEmbedding>,
    change: CacheChange<'_>,
) {
    match change {
        CacheChange::PutMemory(record, embedding) => {
            cache.insert(
                record.id.to_string(),
                cached_embedding(&record.scope, record.archived, embedding),
            );
        }
        CacheChange::PutInstruction(record, embedding) => {
            cache.insert(
                record.id.to_string(),
                cached_embedding(&record.scope, record.archived, embedding),
            );
        }
        CacheChange::Remove(record_id) => {
            cache.remove(&record_id);
        }
        CacheChange::None => {}
    }
}

fn materialized_scope(
    connection: &Connection,
    record_id: RecordId,
    record_kind: RecordKind,
) -> Result<Option<ScopeRef>, VaultError> {
    let id = record_id.to_string();
    match record_kind {
        RecordKind::Memory | RecordKind::Instruction => connection
            .query_row(
                "SELECT scope_kind, project_id FROM records WHERE id = ?1 AND kind = ?2",
                params![id, record_kind_name(record_kind)],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .optional()?
            .map(|(kind, project)| parse_scope(&kind, project.as_deref()))
            .transpose(),
        RecordKind::MemoryCandidate => connection
            .query_row(
                "SELECT payload_json FROM candidates WHERE id = ?1",
                [&id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|payload| {
                let value: MemoryCandidate = from_json(&payload)?;
                Ok(value.proposed_memory.scope)
            })
            .transpose(),
        RecordKind::Task => connection
            .query_row("SELECT project_id FROM tasks WHERE id = ?1", [&id], |row| {
                row.get::<_, String>(0)
            })
            .optional()?
            .map(|project| {
                Ok(ScopeRef::Project {
                    project_id: project.parse::<ProjectId>().map_err(|_| {
                        VaultError::Validation("invalid stored project scope".to_owned())
                    })?,
                })
            })
            .transpose(),
        RecordKind::SecretRef => connection
            .query_row("SELECT 1 FROM secret_refs WHERE id = ?1", [&id], |_| Ok(()))
            .optional()
            .map(|value| value.map(|()| ScopeRef::Global))
            .map_err(VaultError::from),
        RecordKind::Component => connection
            .query_row(
                "SELECT payload_json FROM components WHERE id = ?1",
                [&id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|payload| {
                let value: context_relay_protocol::ComponentRecord = from_json(&payload)?;
                Ok(value.scope)
            })
            .transpose(),
        RecordKind::Project => connection
            .query_row("SELECT 1 FROM projects WHERE id = ?1", [&id], |_| Ok(()))
            .optional()?
            .map(|()| {
                Ok(ScopeRef::Project {
                    project_id: id.parse::<ProjectId>().map_err(|_| {
                        VaultError::Validation("invalid stored project scope".to_owned())
                    })?,
                })
            })
            .transpose(),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SyncRecordOwnerState {
    Verified,
    LegacyPending,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StoredSyncRecordOwner {
    account_id: AccountId,
    workspace_id: WorkspaceId,
    record_kind: RecordKind,
    state: SyncRecordOwnerState,
}

fn record_belongs_to_sync_scope(
    connection: &Connection,
    trusted_material: &dyn TrustedSyncMaterial,
    account_id: AccountId,
    workspace_id: WorkspaceId,
    record_id: RecordId,
    record_kind: RecordKind,
) -> Result<bool, VaultError> {
    match stored_sync_record_owner(connection, record_id)? {
        Some(owner)
            if (owner.account_id, owner.workspace_id, owner.record_kind)
                != (account_id, workspace_id, record_kind) =>
        {
            Ok(false)
        }
        Some(owner) if owner.state == SyncRecordOwnerState::Verified => Ok(true),
        Some(_) => legacy_owner_matches_materialization(
            connection,
            trusted_material,
            account_id,
            workspace_id,
            record_id,
            record_kind,
        ),
        None => Ok(materialized_record_kinds(connection, record_id)?.is_empty()),
    }
}

fn ensure_sync_record_owner(
    connection: &Connection,
    trusted_material: Option<&dyn TrustedSyncMaterial>,
    account_id: AccountId,
    workspace_id: WorkspaceId,
    record_id: RecordId,
    record_kind: RecordKind,
) -> Result<(), VaultError> {
    match stored_sync_record_owner(connection, record_id)? {
        Some(owner)
            if (owner.account_id, owner.workspace_id, owner.record_kind)
                != (account_id, workspace_id, record_kind) =>
        {
            return Err(VaultError::Validation(
                "record identifier belongs to another sync scope".to_owned(),
            ));
        }
        Some(owner) if owner.state == SyncRecordOwnerState::Verified => return Ok(()),
        Some(_) => {
            let trusted_material = trusted_material.ok_or_else(|| {
                VaultError::Validation(
                    "legacy sync record owner requires verified reconciliation".to_owned(),
                )
            })?;
            let matches = legacy_owner_matches_materialization(
                connection,
                trusted_material,
                account_id,
                workspace_id,
                record_id,
                record_kind,
            )?;
            if !matches {
                return Err(VaultError::Validation(
                    "legacy sync record owner requires verified reconciliation".to_owned(),
                ));
            }
            connection.execute(
                "UPDATE sync_record_owners SET binding_state = 'verified'
                 WHERE record_id = ?1 AND binding_state = 'legacy_pending'",
                [record_id.to_string()],
            )?;
            return Ok(());
        }
        None if !materialized_record_kinds(connection, record_id)?.is_empty() => {
            return Err(VaultError::Validation(
                "ownerless materialized record requires explicit sync binding".to_owned(),
            ));
        }
        None => {}
    }
    insert_or_verify_sync_record_owner(connection, account_id, workspace_id, record_id, record_kind)
}

fn insert_or_verify_sync_record_owner(
    connection: &Connection,
    account_id: AccountId,
    workspace_id: WorkspaceId,
    record_id: RecordId,
    record_kind: RecordKind,
) -> Result<(), VaultError> {
    if let Some(owner) = stored_sync_record_owner(connection, record_id)? {
        if (
            owner.account_id,
            owner.workspace_id,
            owner.record_kind,
            owner.state,
        ) != (
            account_id,
            workspace_id,
            record_kind,
            SyncRecordOwnerState::Verified,
        ) {
            return Err(VaultError::Validation(
                "record identifier belongs to another sync scope".to_owned(),
            ));
        }
        return Ok(());
    }
    connection.execute(
        "INSERT INTO sync_record_owners(
             record_id, account_id, workspace_id, binding_state, record_kind
         ) VALUES (?1, ?2, ?3, 'verified', ?4)",
        params![
            record_id.to_string(),
            account_id.to_string(),
            workspace_id.to_string(),
            record_kind_name(record_kind)
        ],
    )?;
    Ok(())
}

fn stored_sync_record_owner(
    connection: &Connection,
    record_id: RecordId,
) -> Result<Option<StoredSyncRecordOwner>, VaultError> {
    connection
        .query_row(
            "SELECT account_id, workspace_id, record_kind, binding_state
             FROM sync_record_owners WHERE record_id = ?1",
            [record_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()?
        .map(|(account, workspace, kind, state)| {
            Ok(StoredSyncRecordOwner {
                account_id: account
                    .parse()
                    .map_err(|_| VaultError::Validation("invalid owner account ID".to_owned()))?,
                workspace_id: workspace
                    .parse()
                    .map_err(|_| VaultError::Validation("invalid owner workspace ID".to_owned()))?,
                record_kind: parse_record_kind(&kind)?,
                state: match state.as_str() {
                    "verified" => SyncRecordOwnerState::Verified,
                    "legacy_pending" => SyncRecordOwnerState::LegacyPending,
                    _ => {
                        return Err(VaultError::Validation(
                            "invalid sync record owner binding state".to_owned(),
                        ));
                    }
                },
            })
        })
        .transpose()
}

fn legacy_owner_matches_materialization(
    connection: &Connection,
    trusted_material: &dyn TrustedSyncMaterial,
    account_id: AccountId,
    workspace_id: WorkspaceId,
    record_id: RecordId,
    record_kind: RecordKind,
) -> Result<bool, VaultError> {
    let heads = load_record_heads(connection, workspace_id, record_id)?;
    let representative = heads.first().ok_or_else(|| {
        VaultError::Validation("legacy sync record owner has no durable head".to_owned())
    })?;
    if heads.iter().any(|head| {
        head.record_kind != record_kind
            || head.operation.account_id != account_id
            || head.operation.workspace_id != workspace_id
            || head.operation.record_id != record_id
    }) {
        return Err(VaultError::Validation(
            "legacy sync record heads disagree on owner or kind".to_owned(),
        ));
    }

    let representative_mutation =
        rehydrate_stored_mutation(trusted_material, &representative.operation)?;
    let materialized_kinds = materialized_record_kinds(connection, record_id)?;
    if matches!(representative_mutation, RecordMutationV1::Tombstone { .. }) {
        return Ok(materialized_kinds.is_empty());
    }
    if materialized_kinds.as_slice() != [record_kind] {
        return Ok(false);
    }
    Ok(
        load_materialized_mutation(connection, record_id, record_kind)?.as_ref()
            == Some(&representative_mutation),
    )
}

fn load_materialized_mutation(
    connection: &Connection,
    record_id: RecordId,
    record_kind: RecordKind,
) -> Result<Option<RecordMutationV1>, VaultError> {
    let id = record_id.to_string();
    let payload = match record_kind {
        RecordKind::Memory => connection
            .query_row(
                "SELECT payload_json FROM records WHERE id = ?1 AND kind = 'memory'",
                [&id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|payload| from_json::<MemoryRecord>(&payload).map(RecordMutationV1::UpsertMemory))
            .transpose()?,
        RecordKind::MemoryCandidate => connection
            .query_row(
                "SELECT payload_json FROM candidates WHERE id = ?1",
                [&id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|payload| {
                from_json::<MemoryCandidate>(&payload).map(RecordMutationV1::UpsertMemoryCandidate)
            })
            .transpose()?,
        RecordKind::Task => connection
            .query_row(
                "SELECT payload_json FROM tasks WHERE id = ?1",
                [&id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|payload| from_json::<TaskRecord>(&payload).map(RecordMutationV1::UpsertTask))
            .transpose()?,
        RecordKind::SecretRef => connection
            .query_row(
                "SELECT payload_json FROM secret_refs WHERE id = ?1",
                [&id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|payload| from_json::<SecretRef>(&payload).map(RecordMutationV1::UpsertSecretRef))
            .transpose()?,
        RecordKind::Instruction => connection
            .query_row(
                "SELECT payload_json FROM records WHERE id = ?1 AND kind = 'instruction'",
                [&id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|payload| {
                from_json::<InstructionRecord>(&payload).map(RecordMutationV1::UpsertInstruction)
            })
            .transpose()?,
        RecordKind::Component => connection
            .query_row(
                "SELECT payload_json FROM components WHERE id = ?1",
                [&id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|payload| {
                from_json::<ComponentRecord>(&payload).map(RecordMutationV1::UpsertComponent)
            })
            .transpose()?,
        RecordKind::Project => connection
            .query_row(
                "SELECT payload_json FROM projects WHERE id = ?1",
                [&id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|payload| {
                from_json::<ProjectIdentity>(&payload).map(RecordMutationV1::UpsertProject)
            })
            .transpose()?,
    };
    Ok(payload)
}

fn materialized_record_kinds(
    connection: &Connection,
    record_id: RecordId,
) -> Result<Vec<RecordKind>, VaultError> {
    let id = record_id.to_string();
    let mut statement = connection.prepare(
        "SELECT kind FROM records WHERE id = ?1
         UNION ALL SELECT 'memory_candidate' FROM candidates WHERE id = ?1
         UNION ALL SELECT 'task' FROM tasks WHERE id = ?1
         UNION ALL SELECT 'secret_ref' FROM secret_refs WHERE id = ?1
         UNION ALL SELECT 'component' FROM components WHERE id = ?1
         UNION ALL SELECT 'project' FROM projects WHERE id = ?1",
    )?;
    statement
        .query_map([id], |row| row.get::<_, String>(0))?
        .map(|kind| parse_record_kind(&kind?))
        .collect()
}

fn durable_record_scope(
    connection: &Connection,
    workspace_id: WorkspaceId,
    record_id: RecordId,
    record_kind: RecordKind,
) -> Result<Option<ScopeRef>, VaultError> {
    let heads = load_record_heads(connection, workspace_id, record_id)?;
    let mut scope = None;
    for head in heads {
        if head.record_kind != record_kind || head.operation.record_id != record_id {
            return Err(VaultError::Validation(
                "durable record head kind or identity mismatch".to_owned(),
            ));
        }
        let head_scope = operation_scope(&head.operation)?;
        if scope.as_ref().is_some_and(|scope| scope != &head_scope) {
            return Err(VaultError::Validation(
                "durable record heads disagree on scope".to_owned(),
            ));
        }
        scope = Some(head_scope);
    }
    Ok(scope)
}

fn operation_scope(operation: &SyncOperationV1) -> Result<ScopeRef, VaultError> {
    match operation.record_kind {
        RecordKind::SecretRef if operation.project_id.is_none() => Ok(ScopeRef::Global),
        RecordKind::Task => operation
            .project_id
            .map(|project_id| ScopeRef::Project { project_id })
            .ok_or_else(|| VaultError::Validation("task head is missing its project".to_owned())),
        RecordKind::Project => operation
            .project_id
            .filter(|project_id| project_id.as_bytes() == operation.record_id.as_bytes())
            .map(|project_id| ScopeRef::Project { project_id })
            .ok_or_else(|| VaultError::Validation("project head scope is invalid".to_owned())),
        RecordKind::SecretRef => Err(VaultError::Validation(
            "secret reference head cannot have a project".to_owned(),
        )),
        _ => Ok(operation
            .project_id
            .map_or(ScopeRef::Global, |project_id| ScopeRef::Project {
                project_id,
            })),
    }
}

fn parse_scope(kind: &str, project: Option<&str>) -> Result<ScopeRef, VaultError> {
    match (kind, project) {
        ("global", None) => Ok(ScopeRef::Global),
        ("project", Some(project)) => Ok(ScopeRef::Project {
            project_id: project
                .parse()
                .map_err(|_| VaultError::Validation("invalid stored project scope".to_owned()))?,
        }),
        _ => Err(VaultError::Validation(
            "invalid stored record scope".to_owned(),
        )),
    }
}

fn validate_commit(mutation: &RecordMutationV1, built: &BuiltOperation) -> Result<(), VaultError> {
    built
        .validate_for_persistence(mutation)
        .map_err(|error| VaultError::Validation(error.to_string()))?;
    if built.operation.record_id != mutation.record_id()
        || built.operation.record_kind != mutation.record_kind()
        || built.operation.mutation_kind != mutation.mutation_kind()
    {
        return Err(VaultError::Validation(
            "operation identity does not match mutation".to_owned(),
        ));
    }
    Ok(())
}

fn validate_device_chain(
    transaction: &Transaction<'_>,
    operation: &SyncOperationV1,
) -> Result<(), VaultError> {
    let persisted = transaction
        .query_row(
            "SELECT device_sequence, canonical_sha256
             FROM sync_device_heads
             WHERE workspace_id = ?1 AND device_id = ?2",
            params![
                operation.workspace_id.to_string(),
                operation.device_id.to_string()
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    match persisted {
        Some((sequence, hash)) => {
            let expected_sequence = parse_decimal_u64(&sequence)?
                .checked_add(1)
                .ok_or_else(|| VaultError::Validation("device sequence exhausted".to_owned()))?;
            let expected_hash = parse_digest(&hash)?;
            if operation.device_sequence != expected_sequence
                || operation.previous_device_hash != expected_hash
            {
                return Err(VaultError::Validation(
                    "operation does not extend the persisted device head".to_owned(),
                ));
            }
        }
        None => {
            if operation.device_sequence != 1
                || operation.previous_device_hash != Sha256Digest([0; 32])
            {
                return Err(VaultError::Validation(
                    "first persisted device operation must be genesis".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_safe_error_code_v1(code: &str) -> Result<(), VaultError> {
    match code {
        "offline"
        | "transient"
        | "auth_required"
        | "revoked"
        | "quota_blocked"
        | "gap_pending"
        | "integrity_quarantined"
        | "conflict"
        | "configuration_error" => Ok(()),
        _ => Err(VaultError::Validation(
            "unknown safe sync error code".to_owned(),
        )),
    }
}

pub(crate) fn validate_sync_provider_v1(provider: &str) -> Result<(), VaultError> {
    match provider {
        "memory" | "supabase" => Ok(()),
        _ => Err(VaultError::Validation(
            "unknown version-1 sync provider".to_owned(),
        )),
    }
}

fn exact_replay(transaction: &Transaction<'_>, built: &BuiltOperation) -> Result<bool, VaultError> {
    let existing = transaction
        .query_row(
            "SELECT record_id, payload_json FROM operations WHERE id = ?1",
            [built.operation.operation_id.to_string()],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    let Some((record_id, payload)) = existing else {
        return Ok(false);
    };
    let operation: SyncOperationV1 = from_json(&payload)?;
    let canonical = encode_sync_operation_v1(&operation)
        .map_err(|error| VaultError::Validation(error.to_string()))?;
    if record_id == built.operation.record_id.to_string() && canonical == built.canonical_bytes {
        return Ok(true);
    }
    Err(VaultError::OperationConflict)
}

fn materialize_mutation<'a>(
    transaction: &Transaction<'_>,
    mutation: &'a RecordMutationV1,
    embedding: Option<&'a Embedding384>,
) -> Result<CacheChange<'a>, VaultError> {
    match mutation {
        RecordMutationV1::UpsertMemory(record) => {
            let embedding = embedding.ok_or_else(|| {
                VaultError::Validation("searchable sync mutation requires an embedding".to_owned())
            })?;
            upsert_searchable_record(
                transaction,
                &record.id.to_string(),
                "memory",
                &record.scope,
                record.archived,
                &record.title,
                &record.body_markdown,
                &to_json(record)?,
                &record.provenance,
                embedding,
            )?;
            Ok(CacheChange::PutMemory(record, embedding))
        }
        RecordMutationV1::UpsertMemoryCandidate(record) => {
            transaction.execute(
                "INSERT INTO candidates(id, state, payload_json) VALUES (?1, ?2, ?3)
                 ON CONFLICT(id) DO UPDATE SET state = excluded.state,
                     payload_json = excluded.payload_json",
                params![
                    record.id.to_string(),
                    candidate_state(record.state),
                    to_json(record)?
                ],
            )?;
            Ok(CacheChange::None)
        }
        RecordMutationV1::UpsertTask(record) => {
            transaction.execute(
                "INSERT INTO tasks(id, project_id, status, payload_json)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(id) DO UPDATE SET project_id = excluded.project_id,
                     status = excluded.status, payload_json = excluded.payload_json",
                params![
                    record.id.to_string(),
                    record.project_id.to_string(),
                    task_status(record.status),
                    to_json(record)?
                ],
            )?;
            Ok(CacheChange::None)
        }
        RecordMutationV1::UpsertSecretRef(record) => {
            transaction.execute(
                "INSERT INTO secret_refs(id, payload_json) VALUES (?1, ?2)
                 ON CONFLICT(id) DO UPDATE SET payload_json = excluded.payload_json",
                params![record.id.to_string(), to_json(record)?],
            )?;
            Ok(CacheChange::None)
        }
        RecordMutationV1::UpsertInstruction(record) => {
            let embedding = embedding.ok_or_else(|| {
                VaultError::Validation("searchable sync mutation requires an embedding".to_owned())
            })?;
            upsert_searchable_record(
                transaction,
                &record.id.to_string(),
                "instruction",
                &record.scope,
                record.archived,
                &record.title,
                &record.body_markdown,
                &to_json(record)?,
                &record.provenance,
                embedding,
            )?;
            transaction.execute(
                "INSERT INTO instructions(id, payload_json) VALUES (?1, ?2)
                 ON CONFLICT(id) DO UPDATE SET payload_json = excluded.payload_json",
                params![record.id.to_string(), to_json(record)?],
            )?;
            Ok(CacheChange::PutInstruction(record, embedding))
        }
        RecordMutationV1::UpsertComponent(record) => {
            transaction.execute(
                "INSERT INTO components(id, payload_json) VALUES (?1, ?2)
                 ON CONFLICT(id) DO UPDATE SET payload_json = excluded.payload_json",
                params![record.id.to_string(), to_json(record)?],
            )?;
            Ok(CacheChange::None)
        }
        RecordMutationV1::UpsertProject(record) => {
            transaction.execute(
                "INSERT INTO projects(id, payload_json) VALUES (?1, ?2)
                 ON CONFLICT(id) DO UPDATE SET payload_json = excluded.payload_json",
                params![record.project_id.to_string(), to_json(record)?],
            )?;
            Ok(CacheChange::None)
        }
        RecordMutationV1::Tombstone {
            record_id,
            record_kind,
        } => {
            let id = record_id.to_string();
            match record_kind {
                RecordKind::Memory | RecordKind::Instruction => {
                    transaction.execute("DELETE FROM search_fts WHERE record_id = ?1", [&id])?;
                    transaction.execute("DELETE FROM records WHERE id = ?1", [&id])?;
                }
                RecordKind::MemoryCandidate => {
                    transaction.execute("DELETE FROM candidates WHERE id = ?1", [&id])?;
                }
                RecordKind::Task => {
                    transaction.execute("DELETE FROM tasks WHERE id = ?1", [&id])?;
                }
                RecordKind::SecretRef => {
                    transaction.execute("DELETE FROM secret_refs WHERE id = ?1", [&id])?;
                }
                RecordKind::Component => {
                    transaction.execute("DELETE FROM components WHERE id = ?1", [&id])?;
                }
                RecordKind::Project => {
                    transaction.execute("DELETE FROM projects WHERE id = ?1", [&id])?;
                }
            }
            Ok(
                if matches!(record_kind, RecordKind::Memory | RecordKind::Instruction) {
                    CacheChange::Remove(id)
                } else {
                    CacheChange::None
                },
            )
        }
    }
}

fn parse_decimal_u64(value: &str) -> Result<u64, VaultError> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| VaultError::Validation("invalid decimal u64".to_owned()))?;
    if parsed.to_string() != value {
        return Err(VaultError::Validation(
            "noncanonical decimal u64".to_owned(),
        ));
    }
    Ok(parsed)
}

fn parse_digest(value: &[u8]) -> Result<Sha256Digest, VaultError> {
    value
        .try_into()
        .map(Sha256Digest)
        .map_err(|_| VaultError::Validation("invalid SHA-256 digest".to_owned()))
}

fn parse_operation_id(value: &str) -> Result<OperationId, VaultError> {
    value
        .parse()
        .map_err(|_| VaultError::Validation("invalid operation ID".to_owned()))
}

fn parse_device_id(value: &str) -> Result<DeviceId, VaultError> {
    value
        .parse()
        .map_err(|_| VaultError::Validation("invalid stored device ID".to_owned()))
}

fn parse_record_id(value: &str) -> Result<RecordId, VaultError> {
    value
        .parse()
        .map_err(|_| VaultError::Validation("invalid stored record ID".to_owned()))
}

const fn record_kind_name(value: RecordKind) -> &'static str {
    match value {
        RecordKind::Memory => "memory",
        RecordKind::MemoryCandidate => "memory_candidate",
        RecordKind::Task => "task",
        RecordKind::SecretRef => "secret_ref",
        RecordKind::Instruction => "instruction",
        RecordKind::Component => "component",
        RecordKind::Project => "project",
    }
}

fn parse_record_kind(value: &str) -> Result<RecordKind, VaultError> {
    match value {
        "memory" => Ok(RecordKind::Memory),
        "memory_candidate" => Ok(RecordKind::MemoryCandidate),
        "task" => Ok(RecordKind::Task),
        "secret_ref" => Ok(RecordKind::SecretRef),
        "instruction" => Ok(RecordKind::Instruction),
        "component" => Ok(RecordKind::Component),
        "project" => Ok(RecordKind::Project),
        _ => Err(VaultError::Validation("invalid record kind".to_owned())),
    }
}

const fn mutation_kind_name(value: MutationKind) -> &'static str {
    match value {
        MutationKind::Upsert => "upsert",
        MutationKind::Tombstone => "tombstone",
    }
}

fn parse_mutation_kind(value: &str) -> Result<MutationKind, VaultError> {
    match value {
        "upsert" => Ok(MutationKind::Upsert),
        "tombstone" => Ok(MutationKind::Tombstone),
        _ => Err(VaultError::Validation("invalid mutation kind".to_owned())),
    }
}
