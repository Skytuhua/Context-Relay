use std::{collections::BTreeMap, path::Path, time::Duration};

use context_relay_protocol::{
    ApplyReceipt, CandidateId, CandidateState, CheckpointV1, HarnessAccessPolicy, HarnessId,
    InstructionRecord, MAX_EVIDENCE_ITEMS, MemoryCandidate, MemoryId, MemoryKind, MemoryOrigin,
    MemoryRecord, MutationKind, OperationId, PlanId, ProjectId, ProjectIdentity, Provenance,
    RecordId, RecordKind, ScopeRef, Sha256Digest, SyncOperationV1, TaskId, TaskRecord, TaskStatus,
    WireNativeValue, encode_sync_operation_v1,
};
use keyring::Entry;
use rand_core::{OsRng, RngCore};
use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, config::DbConfig, params};
use serde::{Serialize, de::DeserializeOwned};
use zeroize::Zeroizing;

use crate::native_memory::{
    NativeMemoryChangeKind, NativeMemoryLedger, NativeMemorySource, NativeMemorySourceId,
    extract_managed_markdown, native_memory_evidence, native_memory_identity, native_memory_tags,
    native_memory_title,
};
use crate::search::{
    AllowedSearchScope, Embedding384, SearchHit, quote_fts_query, reciprocal_rank_fusion,
};

mod native_transactions;
pub use native_transactions::*;

pub const LATEST_SCHEMA_VERSION: u32 = 10;
const DATABASE_KEY_BYTES: usize = 32;
const DEFAULT_BEFORE_IMAGE_BYTES: u64 = 200 * 1024 * 1024;
const DEFAULT_RETENTION_MS: u64 = 30 * 24 * 60 * 60 * 1_000;
const MINIMUM_SQLITE_VERSION: [u32; 3] = [3, 53, 2];
const MINIMUM_CIPHER_VERSION: [u32; 3] = [4, 17, 0];

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("the vault key is missing")]
    MissingKey,
    #[error("the vault key is invalid")]
    WrongKey,
    #[error("vault schema {found} is newer than supported schema {LATEST_SCHEMA_VERSION}")]
    FutureSchema { found: u32 },
    #[error("vault migration failed: {0}")]
    Migration(String),
    #[error("the before-image budget is exhausted")]
    BudgetExceeded,
    #[error("credential store failure: {0}")]
    Credential(String),
    #[error("vault security requirement failed: {0}")]
    Security(String),
    #[error("invalid vault value: {0}")]
    Validation(String),
    #[error("the operation ID is already bound to a different mutation")]
    OperationConflict,
    #[error("vault serialization failed: {0}")]
    Serialization(String),
    #[error("vault database failure: {0}")]
    Database(#[from] rusqlite::Error),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LocalOperationKind {
    Create,
    Proposal,
    Update,
    Archive,
    TaskUpsert,
    TaskComplete,
    TaskTransition,
}

impl LocalOperationKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "memory_create",
            Self::Proposal => "memory_proposal",
            Self::Update => "memory_update",
            Self::Archive => "memory_archive",
            Self::TaskUpsert => "task_upsert",
            Self::TaskComplete => "task_complete",
            Self::TaskTransition => "task_transition",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LocalOperationBinding {
    pub operation_id: OperationId,
    pub operation_kind: LocalOperationKind,
    pub target_id: String,
    pub expected_revision: Option<OperationId>,
    pub canonical_payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum LocalOperationReplay {
    Fresh,
    Snapshot(Vec<u8>),
    Legacy,
}

pub trait DatabaseKeyStore: Send + Sync {
    fn load_key(&self, credential_id: &str) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError>;
    fn store_key(&self, credential_id: &str, key: &[u8]) -> Result<(), VaultError>;
}

#[derive(Clone, Debug)]
pub struct PlatformKeyStore {
    service: String,
}

impl PlatformKeyStore {
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    fn entry(&self, credential_id: &str) -> Result<Entry, VaultError> {
        Entry::new(&self.service, credential_id)
            .map_err(|error| VaultError::Credential(error.to_string()))
    }
}

impl Default for PlatformKeyStore {
    fn default() -> Self {
        Self::new("Context Relay")
    }
}

impl DatabaseKeyStore for PlatformKeyStore {
    fn load_key(&self, credential_id: &str) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
        match self.entry(credential_id)?.get_secret() {
            Ok(key) => Ok(Some(Zeroizing::new(key))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(VaultError::Credential(error.to_string())),
        }
    }

    fn store_key(&self, credential_id: &str, key: &[u8]) -> Result<(), VaultError> {
        self.entry(credential_id)?
            .set_secret(key)
            .map_err(|error| VaultError::Credential(error.to_string()))
    }
}

pub type OsCredentialStore = PlatformKeyStore;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BeforeImagePolicy {
    max_bytes: u64,
    retention_ms: u64,
}

impl BeforeImagePolicy {
    pub const fn new(max_bytes: u64, retention_ms: u64) -> Self {
        Self {
            max_bytes,
            retention_ms,
        }
    }
}

impl Default for BeforeImagePolicy {
    fn default() -> Self {
        Self::new(DEFAULT_BEFORE_IMAGE_BYTES, DEFAULT_RETENTION_MS)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultRuntimeInfo {
    pub sqlite_version: String,
    pub cipher_version: String,
    pub fts5_enabled: bool,
    pub defensive: bool,
    pub trusted_schema: bool,
    pub foreign_keys: bool,
    pub journal_mode: String,
    pub synchronous: i64,
    pub temp_store: i64,
    pub secure_delete: bool,
}

pub struct Vault {
    connection: Connection,
    embedding_cache: BTreeMap<String, CachedEmbedding>,
}

#[derive(Clone)]
struct CachedEmbedding {
    approved: bool,
    archived: bool,
    scope: CachedScope,
    embedding: Embedding384,
}

#[derive(Clone, Copy)]
enum CachedScope {
    Global,
    Project(ProjectId),
}

impl CachedScope {
    fn from_scope(scope: &ScopeRef) -> Self {
        match scope {
            ScopeRef::Global => Self::Global,
            ScopeRef::Project { project_id } => Self::Project(*project_id),
        }
    }

    fn allowed_by(self, allowed: &AllowedSearchScope) -> bool {
        match self {
            Self::Global => allowed.allows_global(),
            Self::Project(project_id) => allowed.project_id() == Some(project_id),
        }
    }
}

impl Vault {
    pub fn checkpoint_wal(&self) -> Result<(), VaultError> {
        self.connection
            .execute_batch("PRAGMA wal_checkpoint(FULL)")?;
        Ok(())
    }

    pub fn open(
        path: &Path,
        credential_id: &str,
        key_store: &dyn DatabaseKeyStore,
    ) -> Result<Self, VaultError> {
        let existed = path.is_file();
        let key = match key_store.load_key(credential_id)? {
            Some(key) => key,
            None if existed => return Err(VaultError::MissingKey),
            None => {
                let mut key = Zeroizing::new(vec![0_u8; DATABASE_KEY_BYTES]);
                OsRng.fill_bytes(&mut key);
                key_store.store_key(credential_id, &key)?;
                key
            }
        };
        if key.len() != DATABASE_KEY_BYTES {
            return Err(if existed {
                VaultError::WrongKey
            } else {
                VaultError::Credential("vault key must contain exactly 32 bytes".to_owned())
            });
        }

        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let mut connection = Connection::open_with_flags(path, flags)?;
        // SAFETY: `connection` owns a live SQLite handle, `key` remains valid for the
        // duration of the call, and no SQLite operation has been issued since open.
        let keyed = unsafe {
            rusqlite::ffi::sqlite3_key(
                connection.handle(),
                key.as_ptr().cast(),
                DATABASE_KEY_BYTES as std::ffi::c_int,
            )
        };
        if keyed != rusqlite::ffi::SQLITE_OK {
            return Err(if existed {
                VaultError::WrongKey
            } else {
                VaultError::Database(rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(keyed),
                    None,
                ))
            });
        }

        if connection
            .query_row("SELECT count(*) FROM sqlite_master", [], |row| {
                row.get::<_, i64>(0)
            })
            .is_err()
        {
            return Err(if existed {
                VaultError::WrongKey
            } else {
                VaultError::Security("new encrypted database could not be read".to_owned())
            });
        }

        configure_connection(&connection)?;
        verify_runtime(&connection)?;
        migrate(&mut connection)?;
        let embedding_cache = load_embedding_cache(&connection)?;
        Ok(Self {
            connection,
            embedding_cache,
        })
    }

    pub fn runtime_info(&self) -> Result<VaultRuntimeInfo, VaultError> {
        let sqlite_version = self
            .connection
            .query_row("SELECT sqlite_version()", [], |row| row.get(0))?;
        let cipher_version = self
            .connection
            .query_row("PRAGMA cipher_version", [], |row| row.get(0))?;
        let fts5_enabled = self.connection.query_row(
            "SELECT sqlite_compileoption_used('ENABLE_FTS5')",
            [],
            |row| row.get::<_, i64>(0),
        )? != 0;
        let defensive = self
            .connection
            .db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE)?;
        let trusted_schema = pragma_bool(&self.connection, "trusted_schema")?;
        let foreign_keys = pragma_bool(&self.connection, "foreign_keys")?;
        let journal_mode = self
            .connection
            .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))?
            .to_ascii_lowercase();
        let synchronous = self
            .connection
            .query_row("PRAGMA synchronous", [], |row| row.get(0))?;
        let temp_store = self
            .connection
            .query_row("PRAGMA temp_store", [], |row| row.get(0))?;
        let secure_delete = pragma_bool(&self.connection, "secure_delete")?;
        Ok(VaultRuntimeInfo {
            sqlite_version,
            cipher_version,
            fts5_enabled,
            defensive,
            trusted_schema,
            foreign_keys,
            journal_mode,
            synchronous,
            temp_store,
            secure_delete,
        })
    }

    pub fn schema_version(&self) -> Result<u32, VaultError> {
        Ok(self
            .connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))?)
    }

    pub fn table_names(&self) -> Result<Vec<String>, VaultError> {
        let mut statement = self.connection.prepare(
            "SELECT name FROM sqlite_master
             WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%'
             ORDER BY name",
        )?;
        Ok(statement
            .query_map([], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?)
    }

    pub fn put_memory(
        &mut self,
        memory: &MemoryRecord,
        operation: &SyncOperationV1,
        embedding: &Embedding384,
    ) -> Result<(), VaultError> {
        memory
            .validate()
            .map_err(|error| VaultError::Validation(error.to_string()))?;
        validate_operation_for(operation, &memory.id.to_string(), RecordKind::Memory)?;
        let transaction = self.connection.transaction()?;
        let inserted = put_memory_tx(&transaction, memory, operation, embedding)?;
        transaction.commit()?;
        if inserted {
            self.embedding_cache.insert(
                memory.id.to_string(),
                cached_embedding(&memory.scope, memory.archived, embedding),
            );
        }
        Ok(())
    }

    pub fn put_memories_batch(
        &mut self,
        values: &[(MemoryRecord, SyncOperationV1, Embedding384)],
    ) -> Result<(), VaultError> {
        for (memory, operation, _) in values {
            memory
                .validate()
                .map_err(|error| VaultError::Validation(error.to_string()))?;
            validate_operation_for(operation, &memory.id.to_string(), RecordKind::Memory)?;
        }
        let transaction = self.connection.transaction()?;
        let mut inserted = Vec::with_capacity(values.len());
        for (memory, operation, embedding) in values {
            inserted.push(put_memory_tx(&transaction, memory, operation, embedding)?);
        }
        transaction.commit()?;
        for ((memory, _, embedding), inserted) in values.iter().zip(inserted) {
            if inserted {
                self.embedding_cache.insert(
                    memory.id.to_string(),
                    cached_embedding(&memory.scope, memory.archived, embedding),
                );
            }
        }
        Ok(())
    }

    pub fn memory(&self, id: &MemoryId) -> Result<Option<MemoryRecord>, VaultError> {
        load_json(
            &self.connection,
            "SELECT payload_json FROM records WHERE id = ?1 AND kind = 'memory'",
            &id.to_string(),
        )
    }

    pub fn put_local_memory(
        &mut self,
        memory: &MemoryRecord,
        embedding: &Embedding384,
    ) -> Result<(), VaultError> {
        memory
            .validate()
            .map_err(|error| VaultError::Validation(error.to_string()))?;
        let transaction = self.connection.transaction()?;
        upsert_searchable_record(
            &transaction,
            &memory.id.to_string(),
            "memory",
            &memory.scope,
            memory.archived,
            &memory.title,
            &memory.body_markdown,
            &to_json(memory)?,
            &memory.provenance,
            embedding,
        )?;
        transaction.commit()?;
        self.embedding_cache.insert(
            memory.id.to_string(),
            cached_embedding(&memory.scope, memory.archived, embedding),
        );
        Ok(())
    }

    pub(crate) fn local_operation_replay(
        &self,
        binding: &LocalOperationBinding,
    ) -> Result<LocalOperationReplay, VaultError> {
        check_local_operation_binding(&self.connection, binding)
    }

    pub(crate) fn put_local_memory_with_binding(
        &mut self,
        memory: &MemoryRecord,
        embedding: &Embedding384,
        binding: &LocalOperationBinding,
    ) -> Result<(), VaultError> {
        memory
            .validate()
            .map_err(|error| VaultError::Validation(error.to_string()))?;
        let canonical_response = to_json(memory)?;
        let transaction = self.connection.transaction()?;
        if !insert_local_operation_binding(&transaction, binding, &canonical_response)? {
            return Err(VaultError::OperationConflict);
        }
        upsert_searchable_record(
            &transaction,
            &memory.id.to_string(),
            "memory",
            &memory.scope,
            memory.archived,
            &memory.title,
            &memory.body_markdown,
            &canonical_response,
            &memory.provenance,
            embedding,
        )?;
        transaction.commit()?;
        self.embedding_cache.insert(
            memory.id.to_string(),
            cached_embedding(&memory.scope, memory.archived, embedding),
        );
        Ok(())
    }

    pub fn memories(
        &self,
        project_id: Option<ProjectId>,
        include_archived: bool,
    ) -> Result<Vec<MemoryRecord>, VaultError> {
        let (scope_kind, project_id) = project_id
            .map(|project_id| ("project", Some(project_id.to_string())))
            .unwrap_or(("global", None));
        load_json_list(
            &self.connection,
            "SELECT payload_json FROM records
             WHERE kind = 'memory' AND scope_kind = ?1
               AND project_id IS ?2 AND (?3 = 1 OR archived = 0)
             ORDER BY id",
            params![scope_kind, project_id, i64::from(include_archived)],
        )
    }

    pub fn put_instruction(
        &mut self,
        instruction: &InstructionRecord,
        operation: &SyncOperationV1,
        embedding: &Embedding384,
    ) -> Result<(), VaultError> {
        instruction
            .validate()
            .map_err(|error| VaultError::Validation(error.to_string()))?;
        validate_operation_for(
            operation,
            &instruction.id.to_string(),
            RecordKind::Instruction,
        )?;
        let transaction = self.connection.transaction()?;
        let inserted = put_searchable_record(
            &transaction,
            &instruction.id.to_string(),
            "instruction",
            &instruction.scope,
            instruction.archived,
            &instruction.title,
            &instruction.body_markdown,
            &to_json(instruction)?,
            &instruction.provenance,
            operation,
            embedding,
        )?;
        if inserted {
            transaction.execute(
                "INSERT INTO instructions(id, payload_json) VALUES (?1, ?2)
                 ON CONFLICT(id) DO UPDATE SET payload_json = excluded.payload_json",
                params![instruction.id.to_string(), to_json(instruction)?],
            )?;
        }
        transaction.commit()?;
        if inserted {
            self.embedding_cache.insert(
                instruction.id.to_string(),
                cached_embedding(&instruction.scope, instruction.archived, embedding),
            );
        }
        Ok(())
    }

    pub fn instruction(&self, id: &RecordId) -> Result<Option<InstructionRecord>, VaultError> {
        load_json(
            &self.connection,
            "SELECT payload_json FROM instructions WHERE id = ?1",
            &id.to_string(),
        )
    }

    pub fn instructions(
        &self,
        scope: &AllowedSearchScope,
        limit: usize,
    ) -> Result<Vec<InstructionRecord>, VaultError> {
        if !(1..=100).contains(&limit) {
            return Err(VaultError::Validation(
                "instruction limit must be between 1 and 100".to_owned(),
            ));
        }
        let limit_i64 = i64::try_from(limit)
            .map_err(|_| VaultError::Validation("instruction limit exceeds i64".to_owned()))?;
        load_json_list(
            &self.connection,
            "SELECT instructions.payload_json
             FROM instructions
             JOIN search_documents ON search_documents.record_id = instructions.id
             WHERE search_documents.archived = 0
               AND (
                 (search_documents.scope_kind = 'global' AND ?1 = 1)
                 OR (
                   search_documents.scope_kind = 'project'
                   AND search_documents.project_id = ?2
                 )
               )
             ORDER BY instructions.id
             LIMIT ?3",
            params![
                i64::from(scope.allows_global()),
                scope.project_id().map(|id| id.to_string()),
                limit_i64
            ],
        )
    }

    pub fn fold_instructions<State, Fold>(
        &self,
        scope: &AllowedSearchScope,
        mut state: State,
        mut fold: Fold,
    ) -> Result<State, VaultError>
    where
        Fold: FnMut(&mut State, InstructionRecord) -> Result<(), VaultError>,
    {
        let mut statement = self.connection.prepare(
            "SELECT instructions.payload_json
             FROM instructions
             JOIN search_documents ON search_documents.record_id = instructions.id
             WHERE search_documents.archived = 0
               AND (
                 (search_documents.scope_kind = 'global' AND ?1 = 1)
                 OR (
                   search_documents.scope_kind = 'project'
                   AND search_documents.project_id = ?2
                 )
               )
             ORDER BY instructions.id",
        )?;
        let rows = statement.query_map(
            params![
                i64::from(scope.allows_global()),
                scope.project_id().map(|id| id.to_string())
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )?;
        for payload in rows {
            fold(&mut state, from_json(&payload?)?)?;
        }
        Ok(state)
    }

    pub fn put_candidate(&mut self, candidate: &MemoryCandidate) -> Result<(), VaultError> {
        candidate
            .validate()
            .map_err(|error| VaultError::Validation(error.to_string()))?;
        let state = match candidate.state {
            CandidateState::Pending => "pending",
            CandidateState::Accepted => "accepted",
            CandidateState::Rejected => "rejected",
        };
        self.connection.execute(
            "INSERT INTO candidates(id, state, payload_json) VALUES (?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET state = excluded.state, payload_json = excluded.payload_json",
            params![candidate.id.to_string(), state, to_json(candidate)?],
        )?;
        Ok(())
    }

    pub(crate) fn put_candidate_with_binding(
        &mut self,
        candidate: &MemoryCandidate,
        binding: &LocalOperationBinding,
    ) -> Result<(), VaultError> {
        candidate
            .validate()
            .map_err(|error| VaultError::Validation(error.to_string()))?;
        let state = match candidate.state {
            CandidateState::Pending => "pending",
            CandidateState::Accepted => "accepted",
            CandidateState::Rejected => "rejected",
        };
        let canonical_response = to_json(candidate)?;
        let transaction = self.connection.transaction()?;
        if !insert_local_operation_binding(&transaction, binding, &canonical_response)? {
            return Err(VaultError::OperationConflict);
        }
        transaction.execute(
            "INSERT INTO candidates(id, state, payload_json) VALUES (?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET state = excluded.state, payload_json = excluded.payload_json",
            params![candidate.id.to_string(), state, canonical_response],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn candidate(&self, id: &CandidateId) -> Result<Option<MemoryCandidate>, VaultError> {
        load_json(
            &self.connection,
            "SELECT payload_json FROM candidates WHERE id = ?1",
            &id.to_string(),
        )
    }

    pub fn candidates(
        &self,
        project_id: Option<ProjectId>,
    ) -> Result<Vec<MemoryCandidate>, VaultError> {
        let mut candidates: Vec<MemoryCandidate> = load_json_list(
            &self.connection,
            "SELECT payload_json FROM candidates ORDER BY id",
            [],
        )?;
        candidates.retain(
            |candidate| match (&candidate.proposed_memory.scope, project_id) {
                (ScopeRef::Global, None) => true,
                (ScopeRef::Project { project_id: actual }, Some(expected)) => actual == &expected,
                _ => false,
            },
        );
        Ok(candidates)
    }

    pub fn native_memory_ledger(
        &self,
        id: &NativeMemorySourceId,
    ) -> Result<Option<NativeMemoryLedger>, VaultError> {
        let row = self
            .connection
            .query_row(
                "SELECT harness, scope_kind, project_id, document_kind,
                        last_observed_digest, last_unmanaged_digest,
                        last_imported_digest, last_applied_digest,
                        initial_preview_complete, payload_json
                 FROM native_memory_sources WHERE source_id = ?1",
                [sha256_key(&id.0)],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<String>>(6)?,
                        row.get::<_, Option<String>>(7)?,
                        row.get::<_, i64>(8)?,
                        row.get::<_, Vec<u8>>(9)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            stored_harness,
            stored_scope,
            stored_project_id,
            stored_document_kind,
            stored_observed,
            stored_unmanaged,
            stored_imported,
            stored_applied,
            stored_initial_preview_complete,
            payload,
        )) = row
        else {
            return Ok(None);
        };
        let ledger: NativeMemoryLedger = from_json(&payload)?;
        let source = ledger
            .validate_persisted()
            .map_err(|error| VaultError::Validation(error.to_string()))?;
        if ledger.source_id != *id
            || harness_name(source.harness) != stored_harness
            || scope_columns(&source.scope) != (stored_scope.as_str(), stored_project_id)
            || native_memory_document_kind(source.document_kind) != stored_document_kind
            || optional_sha256_key(ledger.last_observed_digest.as_ref()) != stored_observed
            || optional_sha256_key(ledger.last_unmanaged_digest.as_ref()) != stored_unmanaged
            || optional_sha256_key(ledger.last_imported_digest.as_ref()) != stored_imported
            || optional_sha256_key(ledger.last_applied_digest.as_ref()) != stored_applied
            || ledger.initial_preview_complete
                != sqlite_bool(
                    stored_initial_preview_complete,
                    "native memory initial-preview flag",
                )?
        {
            return Err(VaultError::Validation(
                "native memory ledger metadata does not match its row".to_owned(),
            ));
        }
        Ok(Some(ledger))
    }

    pub fn put_native_memory_candidate(
        &mut self,
        ledger: &NativeMemoryLedger,
        candidate: Option<&MemoryCandidate>,
    ) -> Result<(), VaultError> {
        let source = ledger
            .validate_persisted()
            .map_err(|error| VaultError::Validation(error.to_string()))?;
        let (scope_kind, project_id) = scope_columns(&source.scope);
        let canonical_ledger = to_json(ledger)?;
        let transaction = self.connection.transaction()?;
        if let Some(candidate) = candidate {
            candidate
                .validate()
                .map_err(|error| VaultError::Validation(error.to_string()))?;
            let prior_ledger = transaction
                .query_row(
                    "SELECT initial_preview_complete, payload_json
                     FROM native_memory_sources WHERE source_id = ?1",
                    [sha256_key(&ledger.source_id.0)],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
                )
                .optional()?;
            let expected_change_kind = if prior_ledger
                .as_ref()
                .map(|(initial_preview_complete, _)| {
                    sqlite_bool(
                        *initial_preview_complete,
                        "native memory initial-preview flag",
                    )
                })
                .transpose()?
                .unwrap_or(false)
            {
                NativeMemoryChangeKind::LiveEdit
            } else {
                NativeMemoryChangeKind::InitialPreview
            };
            let canonical_candidate = to_json(candidate)?;
            let existing = transaction
                .query_row(
                    "SELECT payload_json FROM candidates WHERE id = ?1",
                    [candidate.id.to_string()],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()?;
            if let Some(existing) = existing {
                if existing == canonical_candidate {
                    let replay_change_kind = if prior_ledger
                        .as_ref()
                        .is_some_and(|(_, payload)| payload == &canonical_ledger)
                    {
                        native_memory_change_kind(candidate)?
                    } else {
                        expected_change_kind
                    };
                    validate_native_memory_candidate(
                        source,
                        ledger,
                        candidate,
                        replay_change_kind,
                    )?;
                } else {
                    let existing_candidate: MemoryCandidate = from_json(&existing)?;
                    existing_candidate
                        .validate()
                        .map_err(|error| VaultError::Validation(error.to_string()))?;
                    native_memory_change_kind(&existing_candidate)?;
                    if !same_native_candidate_identity(&existing_candidate, candidate) {
                        return Err(VaultError::OperationConflict);
                    }
                    validate_native_memory_candidate(
                        source,
                        ledger,
                        candidate,
                        expected_change_kind,
                    )?;
                }
            } else {
                validate_native_memory_candidate(source, ledger, candidate, expected_change_kind)?;
                transaction.execute(
                    "INSERT INTO candidates(id, state, payload_json) VALUES (?1, 'pending', ?2)",
                    params![candidate.id.to_string(), canonical_candidate],
                )?;
            }
        }
        transaction.execute(
            "INSERT INTO native_memory_sources(
                 source_id, harness, scope_kind, project_id, document_kind,
                 last_observed_digest, last_unmanaged_digest, last_imported_digest,
                 last_applied_digest, initial_preview_complete, payload_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(source_id) DO UPDATE SET
                 harness = excluded.harness,
                 scope_kind = excluded.scope_kind,
                 project_id = excluded.project_id,
                 document_kind = excluded.document_kind,
                 last_observed_digest = excluded.last_observed_digest,
                 last_unmanaged_digest = excluded.last_unmanaged_digest,
                 last_imported_digest = excluded.last_imported_digest,
                 last_applied_digest = excluded.last_applied_digest,
                 initial_preview_complete = excluded.initial_preview_complete,
                 payload_json = excluded.payload_json",
            params![
                sha256_key(&ledger.source_id.0),
                harness_name(source.harness),
                scope_kind,
                project_id,
                native_memory_document_kind(source.document_kind),
                optional_sha256_key(ledger.last_observed_digest.as_ref()),
                optional_sha256_key(ledger.last_unmanaged_digest.as_ref()),
                optional_sha256_key(ledger.last_imported_digest.as_ref()),
                optional_sha256_key(ledger.last_applied_digest.as_ref()),
                i64::from(ledger.initial_preview_complete),
                canonical_ledger,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn review_candidate(
        &mut self,
        id: CandidateId,
        state: CandidateState,
        memory: Option<&MemoryRecord>,
        embedding: Option<&Embedding384>,
    ) -> Result<(), VaultError> {
        if state == CandidateState::Pending {
            return Err(VaultError::Validation(
                "candidate review must accept or reject".to_owned(),
            ));
        }
        let transaction = self.connection.transaction()?;
        let payload = transaction
            .query_row(
                "SELECT payload_json FROM candidates WHERE id = ?1",
                [id.to_string()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .ok_or_else(|| VaultError::Validation("candidate does not exist".to_owned()))?;
        let mut candidate: MemoryCandidate = from_json(&payload)?;
        match (state, memory, embedding) {
            (CandidateState::Accepted, Some(memory), Some(embedding))
                if memory == &candidate.proposed_memory =>
            {
                memory
                    .validate()
                    .map_err(|error| VaultError::Validation(error.to_string()))?;
                upsert_searchable_record(
                    &transaction,
                    &memory.id.to_string(),
                    "memory",
                    &memory.scope,
                    memory.archived,
                    &memory.title,
                    &memory.body_markdown,
                    &to_json(memory)?,
                    &memory.provenance,
                    embedding,
                )?;
            }
            (CandidateState::Rejected, None, None) => {}
            _ => {
                return Err(VaultError::Validation(
                    "candidate review payload does not match its decision".to_owned(),
                ));
            }
        }
        candidate.state = state;
        transaction.execute(
            "UPDATE candidates SET state = ?2, payload_json = ?3 WHERE id = ?1",
            params![id.to_string(), candidate_state(state), to_json(&candidate)?],
        )?;
        transaction.commit()?;
        if let (Some(memory), Some(embedding)) = (memory, embedding) {
            self.embedding_cache.insert(
                memory.id.to_string(),
                cached_embedding(&memory.scope, memory.archived, embedding),
            );
        }
        Ok(())
    }

    pub fn put_task(&mut self, task: &TaskRecord) -> Result<(), VaultError> {
        task.validate()
            .map_err(|error| VaultError::Validation(error.to_string()))?;
        self.connection.execute(
            "INSERT INTO tasks(id, project_id, status, payload_json) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET project_id = excluded.project_id,
                status = excluded.status, payload_json = excluded.payload_json",
            params![
                task.id.to_string(),
                task.project_id.to_string(),
                task_status(task.status),
                to_json(task)?
            ],
        )?;
        Ok(())
    }

    pub(crate) fn put_task_with_binding(
        &mut self,
        task: &TaskRecord,
        binding: &LocalOperationBinding,
    ) -> Result<(), VaultError> {
        task.validate()
            .map_err(|error| VaultError::Validation(error.to_string()))?;
        let canonical_response = to_json(task)?;
        let transaction = self.connection.transaction()?;
        if !insert_local_operation_binding(&transaction, binding, &canonical_response)? {
            return Err(VaultError::OperationConflict);
        }
        transaction.execute(
            "INSERT INTO tasks(id, project_id, status, payload_json) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET project_id = excluded.project_id,
                status = excluded.status, payload_json = excluded.payload_json",
            params![
                task.id.to_string(),
                task.project_id.to_string(),
                task_status(task.status),
                canonical_response
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn task(&self, id: &TaskId) -> Result<Option<TaskRecord>, VaultError> {
        load_json(
            &self.connection,
            "SELECT payload_json FROM tasks WHERE id = ?1",
            &id.to_string(),
        )
    }

    pub fn tasks(&self, project_id: ProjectId) -> Result<Vec<TaskRecord>, VaultError> {
        load_json_list(
            &self.connection,
            "SELECT payload_json FROM tasks WHERE project_id = ?1 ORDER BY id",
            [project_id.to_string()],
        )
    }

    pub fn recent_project_decisions(
        &self,
        project_id: ProjectId,
        limit: usize,
    ) -> Result<Vec<MemoryRecord>, VaultError> {
        let limit = handoff_limit(limit)?;
        load_json_list(
            &self.connection,
            "SELECT payload_json
             FROM records
             WHERE kind = 'memory'
               AND scope_kind = 'project'
               AND project_id = ?1
               AND archived = 0
               AND memory_kind = 'decision'
             ORDER BY updated_physical_sort DESC,
                      updated_logical DESC,
                      updated_node DESC,
                      id ASC
             LIMIT ?2",
            params![project_id.to_string(), limit],
        )
    }

    pub fn open_or_blocked_tasks(
        &self,
        project_id: ProjectId,
        limit: usize,
    ) -> Result<Vec<TaskRecord>, VaultError> {
        let limit = handoff_limit(limit)?;
        load_json_list(
            &self.connection,
            "SELECT payload_json
             FROM tasks
             WHERE project_id = ?1
               AND status IN ('open', 'blocked')
             ORDER BY id
             LIMIT ?2",
            params![project_id.to_string(), limit],
        )
    }

    pub fn put_project(&mut self, project: &ProjectIdentity) -> Result<(), VaultError> {
        project
            .validate()
            .map_err(|error| VaultError::Validation(error.to_string()))?;
        self.connection.execute(
            "INSERT INTO projects(id, payload_json) VALUES (?1, ?2)
             ON CONFLICT(id) DO UPDATE SET payload_json = excluded.payload_json",
            params![project.project_id.to_string(), to_json(project)?],
        )?;
        Ok(())
    }

    pub fn projects(&self) -> Result<Vec<ProjectIdentity>, VaultError> {
        let mut projects: Vec<ProjectIdentity> = load_json_list(
            &self.connection,
            "SELECT payload_json FROM projects ORDER BY id",
            [],
        )?;
        projects.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then(left.project_id.cmp(&right.project_id))
        });
        Ok(projects)
    }

    pub fn set_access_policy(
        &mut self,
        harness: HarnessId,
        policy: &HarnessAccessPolicy,
    ) -> Result<(), VaultError> {
        self.connection.execute(
            "INSERT INTO harness_access(harness, payload_json) VALUES (?1, ?2)
             ON CONFLICT(harness) DO UPDATE SET payload_json = excluded.payload_json",
            params![harness_name(harness), to_json(policy)?],
        )?;
        Ok(())
    }

    pub fn access_policy(&self, harness: HarnessId) -> Result<HarnessAccessPolicy, VaultError> {
        Ok(load_json(
            &self.connection,
            "SELECT payload_json FROM harness_access WHERE harness = ?1",
            harness_name(harness),
        )?
        .unwrap_or(HarnessAccessPolicy::Default))
    }

    pub fn put_checkpoint(&mut self, checkpoint: &CheckpointV1) -> Result<(), VaultError> {
        checkpoint
            .validate()
            .map_err(|error| VaultError::Validation(error.to_string()))?;
        self.connection.execute(
            "INSERT INTO checkpoints(state_hash, payload_json) VALUES (?1, ?2)
             ON CONFLICT(state_hash) DO UPDATE SET payload_json = excluded.payload_json",
            params![sha256_key(&checkpoint.state_hash), to_json(checkpoint)?],
        )?;
        Ok(())
    }

    pub fn checkpoint(
        &self,
        state_hash: &Sha256Digest,
    ) -> Result<Option<CheckpointV1>, VaultError> {
        load_json(
            &self.connection,
            "SELECT payload_json FROM checkpoints WHERE state_hash = ?1",
            &sha256_key(state_hash),
        )
    }

    pub fn put_conflict(
        &mut self,
        record_id: &RecordId,
        left: &SyncOperationV1,
        right: &SyncOperationV1,
    ) -> Result<(), VaultError> {
        left.validate()
            .map_err(|error| VaultError::Validation(error.to_string()))?;
        right
            .validate()
            .map_err(|error| VaultError::Validation(error.to_string()))?;
        if left.record_id != *record_id || right.record_id != *record_id {
            return Err(VaultError::Validation(
                "conflict operations must target the conflict record".to_owned(),
            ));
        }
        self.connection.execute(
            "INSERT INTO conflicts(record_id, left_operation_json, right_operation_json)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(record_id) DO UPDATE SET
                left_operation_json = excluded.left_operation_json,
                right_operation_json = excluded.right_operation_json",
            params![record_id.to_string(), to_json(left)?, to_json(right)?],
        )?;
        Ok(())
    }

    pub fn conflict(
        &self,
        record_id: &RecordId,
    ) -> Result<Option<(SyncOperationV1, SyncOperationV1)>, VaultError> {
        let row = self
            .connection
            .query_row(
                "SELECT left_operation_json, right_operation_json FROM conflicts WHERE record_id = ?1",
                [record_id.to_string()],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?;
        row.map(|(left, right)| Ok((from_json(&left)?, from_json(&right)?)))
            .transpose()
    }

    pub fn put_receipt(
        &mut self,
        receipt: &ApplyReceipt,
        successful: bool,
        resolved: bool,
    ) -> Result<(), VaultError> {
        receipt
            .validate()
            .map_err(|error| VaultError::Validation(error.to_string()))?;
        let applied_ms = receipt.applied_hlc.physical_ms;
        self.connection.execute(
            "INSERT INTO receipts(plan_id, successful, resolved, applied_ms, payload_json)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(plan_id) DO UPDATE SET successful = excluded.successful,
                resolved = excluded.resolved, applied_ms = excluded.applied_ms,
                payload_json = excluded.payload_json",
            params![
                receipt.plan_id.to_string(),
                i64::from(successful),
                i64::from(resolved),
                to_i64(applied_ms)?,
                to_json(receipt)?,
            ],
        )?;
        Ok(())
    }

    pub fn receipt(&self, plan_id: &PlanId) -> Result<Option<ApplyReceipt>, VaultError> {
        load_json(
            &self.connection,
            "SELECT payload_json FROM receipts WHERE plan_id = ?1",
            &plan_id.to_string(),
        )
    }

    pub fn put_path(&mut self, id: &str, path: &WireNativeValue) -> Result<(), VaultError> {
        if id.trim().is_empty() {
            return Err(VaultError::Validation("path id cannot be empty".to_owned()));
        }
        path.validate()
            .map_err(|error| VaultError::Validation(error.to_string()))?;
        self.connection.execute(
            "INSERT INTO paths(id, payload_json) VALUES (?1, ?2)
             ON CONFLICT(id) DO UPDATE SET payload_json = excluded.payload_json",
            params![id, to_json(path)?],
        )?;
        Ok(())
    }

    pub fn path(&self, id: &str) -> Result<Option<WireNativeValue>, VaultError> {
        load_json(
            &self.connection,
            "SELECT payload_json FROM paths WHERE id = ?1",
            id,
        )
    }

    pub fn provenance(&self, record_id: &str) -> Result<Option<Provenance>, VaultError> {
        load_json(
            &self.connection,
            "SELECT payload_json FROM provenance WHERE record_id = ?1",
            record_id,
        )
    }

    pub fn outbox_operations(&self) -> Result<Vec<SyncOperationV1>, VaultError> {
        let mut statement = self.connection.prepare(
            "SELECT operations.payload_json
             FROM outbox JOIN operations ON operations.id = outbox.operation_id
             ORDER BY outbox.queued_at, outbox.operation_id",
        )?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        rows.map(|row| from_json(&row?)).collect()
    }

    pub fn put_before_image(
        &mut self,
        id: &str,
        plan_id: Option<&PlanId>,
        payload: &[u8],
        created_ms: u64,
        policy: BeforeImagePolicy,
    ) -> Result<(), VaultError> {
        self.put_before_images_batch(
            &[BeforeImageWrite {
                id,
                plan_id,
                payload,
                created_ms,
            }],
            policy,
        )
    }

    pub fn delete_before_image(&mut self, id: &str) -> Result<(), VaultError> {
        self.connection
            .execute("DELETE FROM before_images WHERE id = ?1", [id])?;
        Ok(())
    }

    pub fn has_before_image(&self, id: &str) -> Result<bool, VaultError> {
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM before_images WHERE id = ?1)",
            [id],
            |row| row.get::<_, i64>(0),
        )? != 0)
    }

    pub fn before_image_bytes(&self) -> Result<u64, VaultError> {
        sqlite_u64(
            self.connection.query_row(
                "SELECT coalesce(sum(length(payload)), 0) FROM before_images",
                [],
                |row| row.get::<_, i64>(0),
            )?,
            "before-image byte total",
        )
    }

    pub fn embedding_storage_bytes(&self, record_id: &str) -> Result<u64, VaultError> {
        sqlite_u64(
            self.connection.query_row(
                "SELECT length(vector) FROM embeddings WHERE record_id = ?1",
                [record_id],
                |row| row.get::<_, i64>(0),
            )?,
            "embedding length",
        )
    }

    pub fn search(
        &self,
        query: &str,
        scope: &AllowedSearchScope,
        query_embedding: &Embedding384,
        limit: usize,
    ) -> Result<Vec<SearchHit>, VaultError> {
        if !(1..=100).contains(&limit) {
            return Err(VaultError::Validation(
                "search limit must be between 1 and 100".to_owned(),
            ));
        }
        let allows_global = i64::from(scope.allows_global());
        let project_id = scope.project_id().map(|id| id.to_string());
        let limit_i64 = i64::try_from(limit)
            .map_err(|_| VaultError::Validation("search limit exceeds i64".to_owned()))?;

        let lexical = if let Some(fts_query) = quote_fts_query(query) {
            let mut statement = self.connection.prepare(
                "SELECT search_documents.record_id
                 FROM search_fts
                 JOIN search_documents
                   ON search_documents.record_id = search_fts.record_id
                 WHERE search_fts MATCH ?1
                   AND search_documents.approved = 1
                   AND search_documents.archived = 0
                   AND (
                     (search_documents.scope_kind = 'global' AND ?2 = 1)
                     OR (
                       search_documents.scope_kind = 'project'
                       AND search_documents.project_id = ?3
                     )
                   )
                 ORDER BY bm25(search_fts), search_documents.record_id
                 LIMIT ?4",
            )?;
            statement
                .query_map(
                    params![fts_query, allows_global, project_id.as_deref(), limit_i64],
                    |row| row.get::<_, String>(0),
                )?
                .collect::<Result<Vec<_>, _>>()?
        } else {
            Vec::new()
        };

        let mut semantic = Vec::with_capacity(self.embedding_cache.len());
        for (record_id, cached) in &self.embedding_cache {
            if !cached.approved || cached.archived || !cached.scope.allowed_by(scope) {
                continue;
            }
            semantic.push((
                record_id.clone(),
                cached.embedding.cosine_similarity(query_embedding),
            ));
        }
        semantic.sort_by(|left, right| {
            right
                .1
                .total_cmp(&left.1)
                .then_with(|| left.0.cmp(&right.0))
        });
        semantic.truncate(limit);
        let semantic = semantic
            .into_iter()
            .map(|(record_id, _)| record_id)
            .collect::<Vec<_>>();

        Ok(reciprocal_rank_fusion(&lexical, &semantic, limit))
    }
}

fn cached_embedding(scope: &ScopeRef, archived: bool, embedding: &Embedding384) -> CachedEmbedding {
    CachedEmbedding {
        approved: true,
        archived,
        scope: CachedScope::from_scope(scope),
        embedding: embedding.clone(),
    }
}

fn validate_native_memory_candidate(
    source: &NativeMemorySource,
    ledger: &NativeMemoryLedger,
    candidate: &MemoryCandidate,
    expected_change_kind: NativeMemoryChangeKind,
) -> Result<(), VaultError> {
    let unmanaged_digest = ledger.last_imported_digest.ok_or_else(|| {
        VaultError::Validation("native memory candidate requires an imported digest".to_owned())
    })?;
    let extracted = extract_managed_markdown(candidate.proposed_memory.body_markdown.as_bytes())
        .map_err(|error| VaultError::Validation(error.to_string()))?;
    let (expected_candidate_id, expected_memory_id, expected_operation_id) =
        native_memory_identity(source.id, unmanaged_digest)
            .map_err(|error| VaultError::Validation(error.to_string()))?;
    let memory = &candidate.proposed_memory;
    if extracted.managed_body.is_some()
        || extracted.unmanaged_digest != unmanaged_digest
        || candidate.id != expected_candidate_id
        || memory.id != expected_memory_id
        || memory.revision != expected_operation_id
        || candidate.state != CandidateState::Pending
        || candidate.source_harness != source.harness
        || memory.scope != source.scope
        || memory.kind != MemoryKind::Note
        || memory.origin != MemoryOrigin::NativeImport
        || memory.title != native_memory_title(source)
        || memory.tags != native_memory_tags(source.harness)
        || memory.provenance.harness != Some(source.harness)
        || memory.provenance.source.is_some()
        || memory.archived
        || candidate.evidence_summary != native_memory_evidence(expected_change_kind)
    {
        return Err(VaultError::Validation(
            "native memory candidate does not match its source ledger".to_owned(),
        ));
    }
    Ok(())
}

fn native_memory_change_kind(
    candidate: &MemoryCandidate,
) -> Result<NativeMemoryChangeKind, VaultError> {
    match candidate.evidence_summary.as_str() {
        evidence if evidence == native_memory_evidence(NativeMemoryChangeKind::InitialPreview) => {
            Ok(NativeMemoryChangeKind::InitialPreview)
        }
        evidence if evidence == native_memory_evidence(NativeMemoryChangeKind::LiveEdit) => {
            Ok(NativeMemoryChangeKind::LiveEdit)
        }
        _ => Err(VaultError::Validation(
            "native memory candidate has invalid reconciliation evidence".to_owned(),
        )),
    }
}

fn same_native_candidate_identity(existing: &MemoryCandidate, incoming: &MemoryCandidate) -> bool {
    let mut normalized = existing.clone();
    normalized
        .evidence_summary
        .clone_from(&incoming.evidence_summary);
    normalized.state = incoming.state;
    normalized == *incoming
}

fn load_embedding_cache(
    connection: &Connection,
) -> Result<BTreeMap<String, CachedEmbedding>, VaultError> {
    let rows = {
        let mut statement = connection.prepare(
            "SELECT search_documents.record_id,
                    search_documents.record_kind,
                    search_documents.scope_kind,
                    search_documents.project_id,
                    search_documents.archived,
                    search_documents.approved,
                    embeddings.vector
             FROM search_documents
             LEFT JOIN embeddings
               ON embeddings.record_id = search_documents.record_id
             ORDER BY search_documents.record_id",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<Vec<u8>>>(6)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };

    let mut cache = BTreeMap::new();
    for (record_id, record_kind, scope_kind, project_id, archived, approved, vector) in rows {
        record_id
            .parse::<RecordId>()
            .map_err(|_| VaultError::Validation("invalid cached record id".to_owned()))?;
        if !matches!(record_kind.as_str(), "memory" | "instruction") {
            return Err(VaultError::Validation(
                "invalid cached record kind".to_owned(),
            ));
        }
        let scope = match (scope_kind.as_str(), project_id) {
            ("global", None) => CachedScope::Global,
            ("project", Some(project_id)) => CachedScope::Project(
                project_id
                    .parse::<ProjectId>()
                    .map_err(|_| VaultError::Validation("invalid cached project id".to_owned()))?,
            ),
            _ => {
                return Err(VaultError::Validation(
                    "invalid cached scope metadata".to_owned(),
                ));
            }
        };
        let vector = vector
            .ok_or_else(|| VaultError::Validation("cached embedding is missing".to_owned()))?;
        let embedding = Embedding384::from_le_bytes(&vector)
            .map_err(|error| VaultError::Validation(error.to_string()))?;
        let cached = CachedEmbedding {
            approved: sqlite_bool(approved, "cached approved flag")?,
            archived: sqlite_bool(archived, "cached archived flag")?,
            scope,
            embedding,
        };
        if cache.insert(record_id, cached).is_some() {
            return Err(VaultError::Validation(
                "duplicate cached record id".to_owned(),
            ));
        }
    }
    Ok(cache)
}

fn configure_connection(connection: &Connection) -> Result<(), VaultError> {
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.pragma_update(None, "trusted_schema", false)?;
    connection.pragma_update(None, "temp_store", 2)?;
    connection.pragma_update(None, "secure_delete", true)?;
    connection.execute_batch("PRAGMA cipher_memory_security = ON;")?;
    connection.query_row("PRAGMA journal_mode = DELETE", [], |_| Ok(()))?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?;
    Ok(())
}

fn verify_runtime(connection: &Connection) -> Result<(), VaultError> {
    let sqlite_version: String =
        connection.query_row("SELECT sqlite_version()", [], |row| row.get(0))?;
    let cipher_version: String =
        connection.query_row("PRAGMA cipher_version", [], |row| row.get(0))?;
    if !version_at_least(&sqlite_version, MINIMUM_SQLITE_VERSION) {
        return Err(VaultError::Security(format!(
            "SQLite {sqlite_version} is below 3.53.2"
        )));
    }
    if !version_at_least(&cipher_version, MINIMUM_CIPHER_VERSION) {
        return Err(VaultError::Security(format!(
            "SQLCipher {cipher_version} is below 4.17.0"
        )));
    }
    let fts5: i64 = connection.query_row(
        "SELECT sqlite_compileoption_used('ENABLE_FTS5')",
        [],
        |row| row.get(0),
    )?;
    if fts5 == 0 {
        return Err(VaultError::Security(
            "SQLite FTS5 is unavailable".to_owned(),
        ));
    }
    let synchronous: i64 = connection.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
    if synchronous != 2 {
        return Err(VaultError::Security(
            "SQLite synchronous mode is not FULL".to_owned(),
        ));
    }
    Ok(())
}

fn migrate(connection: &mut Connection) -> Result<(), VaultError> {
    let found: u32 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if found > LATEST_SCHEMA_VERSION {
        return Err(VaultError::FutureSchema { found });
    }
    if found < 1 {
        let transaction = connection
            .transaction()
            .map_err(|error| VaultError::Migration(error.to_string()))?;
        transaction
            .execute_batch(include_str!("../migrations/0001_vault.sql"))
            .and_then(|_| transaction.pragma_update(None, "user_version", 1))
            .and_then(|_| transaction.commit())
            .map_err(|error| VaultError::Migration(error.to_string()))?;
    }
    if found < 2 {
        let transaction = connection
            .transaction()
            .map_err(|error| VaultError::Migration(error.to_string()))?;
        transaction
            .execute_batch(include_str!("../migrations/0002_before_image_plans.sql"))
            .and_then(|_| transaction.pragma_update(None, "user_version", 2))
            .and_then(|_| transaction.commit())
            .map_err(|error| VaultError::Migration(error.to_string()))?;
    }
    if found < 3 {
        let transaction = connection
            .transaction()
            .map_err(|error| VaultError::Migration(error.to_string()))?;
        transaction
            .execute_batch(include_str!("../migrations/0003_native_transactions.sql"))
            .and_then(|_| transaction.pragma_update(None, "user_version", 3))
            .and_then(|_| transaction.commit())
            .map_err(|error| VaultError::Migration(error.to_string()))?;
    }
    if found < 4 {
        let transaction = connection
            .transaction()
            .map_err(|error| VaultError::Migration(error.to_string()))?;
        transaction
            .execute_batch(include_str!("../migrations/0004_offline_workspace.sql"))
            .and_then(|_| transaction.pragma_update(None, "user_version", 4))
            .and_then(|_| transaction.commit())
            .map_err(|error| VaultError::Migration(error.to_string()))?;
    }
    if found < 5 {
        let transaction = connection
            .transaction()
            .map_err(|error| VaultError::Migration(error.to_string()))?;
        transaction
            .execute_batch(include_str!(
                "../migrations/0005_local_operation_bindings.sql"
            ))
            .and_then(|_| transaction.pragma_update(None, "user_version", 5))
            .and_then(|_| transaction.commit())
            .map_err(|error| VaultError::Migration(error.to_string()))?;
    }
    if found < 6 {
        let transaction = connection
            .transaction()
            .map_err(|error| VaultError::Migration(error.to_string()))?;
        transaction
            .execute_batch(include_str!(
                "../migrations/0006_local_operation_results.sql"
            ))
            .and_then(|_| transaction.pragma_update(None, "user_version", 6))
            .and_then(|_| transaction.commit())
            .map_err(|error| VaultError::Migration(error.to_string()))?;
    }
    if found < 7 {
        let transaction = connection
            .transaction()
            .map_err(|error| VaultError::Migration(error.to_string()))?;
        transaction
            .execute_batch(include_str!(
                "../migrations/0007_task_operation_bindings.sql"
            ))
            .and_then(|_| transaction.pragma_update(None, "user_version", 7))
            .and_then(|_| transaction.commit())
            .map_err(|error| VaultError::Migration(error.to_string()))?;
    }
    if found < 8 {
        let transaction = connection
            .transaction()
            .map_err(|error| VaultError::Migration(error.to_string()))?;
        transaction
            .execute_batch(include_str!(
                "../migrations/0008_task_transitions_and_handoff_queries.sql"
            ))
            .and_then(|_| transaction.pragma_update(None, "user_version", 8))
            .and_then(|_| transaction.commit())
            .map_err(|error| VaultError::Migration(error.to_string()))?;
    }
    if found < 9 {
        let transaction = connection
            .transaction()
            .map_err(|error| VaultError::Migration(error.to_string()))?;
        transaction
            .execute_batch(include_str!(
                "../migrations/0009_setup_cli_transactions.sql"
            ))
            .and_then(|_| transaction.pragma_update(None, "user_version", 9))
            .and_then(|_| transaction.commit())
            .map_err(|error| VaultError::Migration(error.to_string()))?;
    }
    if found < 10 {
        let transaction = connection
            .transaction()
            .map_err(|error| VaultError::Migration(error.to_string()))?;
        transaction
            .execute_batch(include_str!(
                "../migrations/0010_native_memory_reconciliation.sql"
            ))
            .and_then(|_| transaction.pragma_update(None, "user_version", 10))
            .and_then(|_| transaction.commit())
            .map_err(|error| VaultError::Migration(error.to_string()))?;
    }
    Ok(())
}

const fn task_status(status: TaskStatus) -> &'static str {
    match status {
        TaskStatus::Open => "open",
        TaskStatus::InProgress => "in_progress",
        TaskStatus::Blocked => "blocked",
        TaskStatus::Done => "done",
        TaskStatus::Canceled => "canceled",
    }
}

fn handoff_limit(limit: usize) -> Result<i64, VaultError> {
    if !(1..=MAX_EVIDENCE_ITEMS).contains(&limit) {
        return Err(VaultError::Validation(
            "handoff query limit must be between 1 and 64".to_owned(),
        ));
    }
    i64::try_from(limit)
        .map_err(|_| VaultError::Validation("handoff query limit exceeds i64".to_owned()))
}

fn put_memory_tx(
    transaction: &Transaction<'_>,
    memory: &MemoryRecord,
    operation: &SyncOperationV1,
    embedding: &Embedding384,
) -> Result<bool, VaultError> {
    put_searchable_record(
        transaction,
        &memory.id.to_string(),
        "memory",
        &memory.scope,
        memory.archived,
        &memory.title,
        &memory.body_markdown,
        &to_json(memory)?,
        &memory.provenance,
        operation,
        embedding,
    )
}

#[allow(clippy::too_many_arguments)]
fn put_searchable_record(
    transaction: &Transaction<'_>,
    id: &str,
    kind: &str,
    scope: &ScopeRef,
    archived: bool,
    title: &str,
    body: &str,
    payload: &[u8],
    provenance: &Provenance,
    operation: &SyncOperationV1,
    embedding: &Embedding384,
) -> Result<bool, VaultError> {
    let existing_kind = transaction
        .query_row("SELECT kind FROM records WHERE id = ?1", [id], |row| {
            row.get::<_, String>(0)
        })
        .optional()?;
    if let Some(existing_kind) = existing_kind
        && existing_kind != kind
    {
        return Err(VaultError::Validation(
            "record kind cannot change".to_owned(),
        ));
    }

    let operation_id = operation.operation_id.to_string();
    if transaction
        .query_row(
            "SELECT 1 FROM local_operation_bindings WHERE operation_id = ?1",
            [&operation_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .is_some()
    {
        return Err(VaultError::OperationConflict);
    }
    let operation_payload = to_json(operation)?;
    let operation_canonical = encode_sync_operation_v1(operation)
        .map_err(|error| VaultError::Validation(error.to_string()))?;
    let existing_operation = transaction
        .query_row(
            "SELECT record_id, payload_json FROM operations WHERE id = ?1",
            [&operation_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;
    if let Some((existing_record_id, existing_payload)) = existing_operation {
        let existing_operation: SyncOperationV1 = from_json(&existing_payload)?;
        let existing_canonical = encode_sync_operation_v1(&existing_operation)
            .map_err(|error| VaultError::Validation(error.to_string()))?;
        if existing_record_id == id && existing_canonical == operation_canonical {
            return Ok(false);
        }
        return Err(VaultError::Validation(
            "operation id cannot be reused with different bytes".to_owned(),
        ));
    }

    upsert_searchable_record(
        transaction,
        id,
        kind,
        scope,
        archived,
        title,
        body,
        payload,
        provenance,
        embedding,
    )?;
    transaction.execute(
        "INSERT INTO operations(id, record_id, payload_json) VALUES (?1, ?2, ?3)",
        params![&operation_id, id, &operation_payload],
    )?;
    transaction.execute(
        "INSERT INTO outbox(operation_id) VALUES (?1)",
        [operation_id],
    )?;
    Ok(true)
}

fn check_local_operation_binding(
    connection: &Connection,
    binding: &LocalOperationBinding,
) -> Result<LocalOperationReplay, VaultError> {
    let operation_id = binding.operation_id.to_string();
    let existing = connection
        .query_row(
            "SELECT binding.operation_kind,
                    binding.target_id,
                    binding.expected_revision,
                    binding.canonical_payload,
                    result.canonical_response
             FROM local_operation_bindings AS binding
             LEFT JOIN local_operation_results AS result
               ON result.operation_id = binding.operation_id
             WHERE binding.operation_id = ?1",
            [&operation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                ))
            },
        )
        .optional()?;
    if let Some((
        operation_kind,
        target_id,
        expected_revision,
        canonical_payload,
        canonical_response,
    )) = existing
    {
        if operation_kind == binding.operation_kind.as_str()
            && target_id == binding.target_id
            && expected_revision
                == binding
                    .expected_revision
                    .map(|revision| revision.to_string())
            && canonical_payload == binding.canonical_payload
        {
            return Ok(match canonical_response {
                Some(response) => LocalOperationReplay::Snapshot(response),
                None => LocalOperationReplay::Legacy,
            });
        }
        return Err(VaultError::OperationConflict);
    }
    if connection
        .query_row(
            "SELECT 1 FROM operations WHERE id = ?1",
            [&operation_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .is_some()
    {
        return Err(VaultError::OperationConflict);
    }
    Ok(LocalOperationReplay::Fresh)
}

fn insert_local_operation_binding(
    transaction: &Transaction<'_>,
    binding: &LocalOperationBinding,
    canonical_response: &[u8],
) -> Result<bool, VaultError> {
    if check_local_operation_binding(transaction, binding)? != LocalOperationReplay::Fresh {
        return Ok(false);
    }
    transaction.execute(
        "INSERT INTO local_operation_bindings(
             operation_id, operation_kind, target_id, expected_revision, canonical_payload
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            binding.operation_id.to_string(),
            binding.operation_kind.as_str(),
            &binding.target_id,
            binding
                .expected_revision
                .map(|revision| revision.to_string()),
            &binding.canonical_payload,
        ],
    )?;
    transaction.execute(
        "INSERT INTO local_operation_results(operation_id, canonical_response) VALUES (?1, ?2)",
        params![binding.operation_id.to_string(), canonical_response],
    )?;
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
fn upsert_searchable_record(
    transaction: &Transaction<'_>,
    id: &str,
    kind: &str,
    scope: &ScopeRef,
    archived: bool,
    title: &str,
    body: &str,
    payload: &[u8],
    provenance: &Provenance,
    embedding: &Embedding384,
) -> Result<(), VaultError> {
    let existing_kind = transaction
        .query_row("SELECT kind FROM records WHERE id = ?1", [id], |row| {
            row.get::<_, String>(0)
        })
        .optional()?;
    if let Some(existing_kind) = existing_kind
        && existing_kind != kind
    {
        return Err(VaultError::Validation(
            "record kind cannot change".to_owned(),
        ));
    }
    let (scope_kind, project_id) = scope_columns(scope);
    let handoff_projection = handoff_projection(kind, payload)?;
    transaction.execute(
        "INSERT INTO records(
             id, kind, scope_kind, project_id, archived, payload_json,
             memory_kind, updated_physical_sort, updated_logical, updated_node
         )
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
         ON CONFLICT(id) DO UPDATE SET kind = excluded.kind,
            scope_kind = excluded.scope_kind, project_id = excluded.project_id,
            archived = excluded.archived, payload_json = excluded.payload_json,
            memory_kind = excluded.memory_kind,
            updated_physical_sort = excluded.updated_physical_sort,
            updated_logical = excluded.updated_logical,
            updated_node = excluded.updated_node",
        params![
            id,
            kind,
            scope_kind,
            project_id,
            i64::from(archived),
            payload,
            handoff_projection.memory_kind,
            handoff_projection.updated_physical_sort,
            handoff_projection.updated_logical,
            handoff_projection.updated_node
        ],
    )?;
    transaction.execute(
        "INSERT INTO provenance(record_id, payload_json) VALUES (?1, ?2)
         ON CONFLICT(record_id) DO UPDATE SET payload_json = excluded.payload_json",
        params![id, to_json(provenance)?],
    )?;
    transaction.execute(
        "INSERT INTO search_documents(
            record_id, record_kind, scope_kind, project_id, archived, approved, title, body
         ) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?7)
         ON CONFLICT(record_id) DO UPDATE SET record_kind = excluded.record_kind,
            scope_kind = excluded.scope_kind, project_id = excluded.project_id,
            archived = excluded.archived, approved = 1,
            title = excluded.title, body = excluded.body",
        params![
            id,
            kind,
            scope_kind,
            project_id,
            i64::from(archived),
            title,
            body,
        ],
    )?;
    transaction.execute(
        "INSERT INTO embeddings(record_id, vector) VALUES (?1, ?2)
         ON CONFLICT(record_id) DO UPDATE SET vector = excluded.vector",
        params![id, embedding.to_le_bytes()],
    )?;
    transaction.execute("DELETE FROM search_fts WHERE record_id = ?1", [id])?;
    transaction.execute(
        "INSERT INTO search_fts(record_id, title, body) VALUES (?1, ?2, ?3)",
        params![id, title, body],
    )?;
    Ok(())
}

struct HandoffProjection {
    memory_kind: Option<&'static str>,
    updated_physical_sort: Option<String>,
    updated_logical: Option<i64>,
    updated_node: Option<String>,
}

fn handoff_projection(record_kind: &str, payload: &[u8]) -> Result<HandoffProjection, VaultError> {
    if record_kind != "memory" {
        return Ok(HandoffProjection {
            memory_kind: None,
            updated_physical_sort: None,
            updated_logical: None,
            updated_node: None,
        });
    }
    let memory: MemoryRecord = from_json(payload)?;
    Ok(HandoffProjection {
        memory_kind: Some(memory_kind(memory.kind)),
        updated_physical_sort: Some(format!("{:020}", memory.updated_hlc.physical_ms)),
        updated_logical: Some(i64::from(memory.updated_hlc.logical)),
        updated_node: Some(memory.updated_hlc.node.to_string()),
    })
}

const fn memory_kind(kind: context_relay_protocol::MemoryKind) -> &'static str {
    match kind {
        context_relay_protocol::MemoryKind::Fact => "fact",
        context_relay_protocol::MemoryKind::Decision => "decision",
        context_relay_protocol::MemoryKind::Preference => "preference",
        context_relay_protocol::MemoryKind::Pattern => "pattern",
        context_relay_protocol::MemoryKind::Procedure => "procedure",
        context_relay_protocol::MemoryKind::Note => "note",
    }
}

fn validate_operation_for(
    operation: &SyncOperationV1,
    record_id: &str,
    kind: RecordKind,
) -> Result<(), VaultError> {
    operation
        .validate()
        .map_err(|error| VaultError::Validation(error.to_string()))?;
    if operation.record_id.to_string() != record_id || operation.record_kind != kind {
        return Err(VaultError::Validation(
            "operation record identity does not match payload".to_owned(),
        ));
    }
    if operation.mutation_kind != MutationKind::Upsert {
        return Err(VaultError::Validation(
            "live record writes require an upsert operation".to_owned(),
        ));
    }
    Ok(())
}

fn scope_columns(scope: &ScopeRef) -> (&'static str, Option<String>) {
    match scope {
        ScopeRef::Global => ("global", None),
        ScopeRef::Project { project_id } => ("project", Some(project_id.to_string())),
    }
}

fn to_json<T: Serialize>(value: &T) -> Result<Vec<u8>, VaultError> {
    serde_json::to_vec(value).map_err(|error| VaultError::Serialization(error.to_string()))
}

fn from_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, VaultError> {
    serde_json::from_slice(bytes).map_err(|error| VaultError::Serialization(error.to_string()))
}

fn load_json<T: DeserializeOwned>(
    connection: &Connection,
    sql: &str,
    id: &str,
) -> Result<Option<T>, VaultError> {
    let payload = connection
        .query_row(sql, [id], |row| row.get::<_, Vec<u8>>(0))
        .optional()?;
    payload.map(|bytes| from_json(&bytes)).transpose()
}

fn load_json_list<T: DeserializeOwned, P: rusqlite::Params>(
    connection: &Connection,
    sql: &str,
    params: P,
) -> Result<Vec<T>, VaultError> {
    let mut statement = connection.prepare(sql)?;
    statement
        .query_map(params, |row| row.get::<_, Vec<u8>>(0))?
        .map(|payload| from_json(&payload?))
        .collect()
}

const fn candidate_state(state: CandidateState) -> &'static str {
    match state {
        CandidateState::Pending => "pending",
        CandidateState::Accepted => "accepted",
        CandidateState::Rejected => "rejected",
    }
}

const fn harness_name(harness: HarnessId) -> &'static str {
    match harness {
        HarnessId::ClaudeCode => "claude_code",
        HarnessId::Codex => "codex",
        HarnessId::Hermes => "hermes",
    }
}

const fn native_memory_document_kind(
    kind: crate::native_memory::NativeMemoryDocumentKind,
) -> &'static str {
    match kind {
        crate::native_memory::NativeMemoryDocumentKind::Agent => "agent",
        crate::native_memory::NativeMemoryDocumentKind::UserProfile => "user_profile",
        crate::native_memory::NativeMemoryDocumentKind::Summary => "summary",
        crate::native_memory::NativeMemoryDocumentKind::Topic => "topic",
    }
}

fn pragma_bool(connection: &Connection, name: &str) -> Result<bool, VaultError> {
    if !matches!(name, "trusted_schema" | "foreign_keys" | "secure_delete") {
        return Err(VaultError::Validation("unsupported pragma".to_owned()));
    }
    let sql = format!("PRAGMA {name}");
    Ok(connection.query_row(&sql, [], |row| row.get::<_, i64>(0))? != 0)
}

fn version_at_least(version: &str, minimum: [u32; 3]) -> bool {
    let Some(numeric) = version.split_whitespace().next() else {
        return false;
    };
    let mut parts = numeric.split('.').map(str::parse::<u32>);
    let actual = [
        parts.next().and_then(Result::ok),
        parts.next().and_then(Result::ok),
        parts.next().and_then(Result::ok),
    ];
    matches!(actual, [Some(major), Some(minor), Some(patch)] if [major, minor, patch] >= minimum)
}

fn to_i64(value: u64) -> Result<i64, VaultError> {
    i64::try_from(value).map_err(|_| VaultError::Validation("timestamp exceeds i64".to_owned()))
}

fn sqlite_u64(value: i64, field: &'static str) -> Result<u64, VaultError> {
    u64::try_from(value).map_err(|_| VaultError::Validation(format!("{field} cannot be negative")))
}

fn sqlite_bool(value: i64, field: &'static str) -> Result<bool, VaultError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(VaultError::Validation(format!("{field} is not boolean"))),
    }
}

fn sha256_key(digest: &Sha256Digest) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut key = String::with_capacity(64);
    for byte in digest.0 {
        key.push(char::from(HEX[usize::from(byte >> 4)]));
        key.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    key
}

fn optional_sha256_key(digest: Option<&Sha256Digest>) -> Option<String> {
    digest.map(sha256_key)
}
