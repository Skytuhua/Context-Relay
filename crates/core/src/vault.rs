use std::{collections::BTreeMap, path::Path, time::Duration};

use context_relay_protocol::{
    ApplyReceipt, CandidateId, CandidateState, CheckpointV1, InstructionRecord, MemoryCandidate,
    MemoryId, MemoryRecord, MutationKind, PlanId, ProjectId, Provenance, RecordId, RecordKind,
    ScopeRef, Sha256Digest, SyncOperationV1, TaskId, TaskRecord, TaskStatus, WireNativeValue,
    encode_sync_operation_v1,
};
use keyring::Entry;
use rand_core::{OsRng, RngCore};
use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, config::DbConfig, params};
use serde::{Serialize, de::DeserializeOwned};
use zeroize::Zeroizing;

use crate::search::{
    AllowedSearchScope, Embedding384, SearchHit, quote_fts_query, reciprocal_rank_fusion,
};

mod native_transactions;
pub use native_transactions::*;

pub const LATEST_SCHEMA_VERSION: u32 = 3;
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
    #[error("vault serialization failed: {0}")]
    Serialization(String),
    #[error("vault database failure: {0}")]
    Database(#[from] rusqlite::Error),
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

    pub fn candidate(&self, id: &CandidateId) -> Result<Option<MemoryCandidate>, VaultError> {
        load_json(
            &self.connection,
            "SELECT payload_json FROM candidates WHERE id = ?1",
            &id.to_string(),
        )
    }

    pub fn put_task(&mut self, task: &TaskRecord) -> Result<(), VaultError> {
        task.validate()
            .map_err(|error| VaultError::Validation(error.to_string()))?;
        let status = match task.status {
            TaskStatus::Open => "open",
            TaskStatus::InProgress => "in_progress",
            TaskStatus::Blocked => "blocked",
            TaskStatus::Done => "done",
            TaskStatus::Canceled => "canceled",
        };
        self.connection.execute(
            "INSERT INTO tasks(id, project_id, status, payload_json) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET project_id = excluded.project_id,
                status = excluded.status, payload_json = excluded.payload_json",
            params![
                task.id.to_string(),
                task.project_id.to_string(),
                status,
                to_json(task)?
            ],
        )?;
        Ok(())
    }

    pub fn task(&self, id: &TaskId) -> Result<Option<TaskRecord>, VaultError> {
        load_json(
            &self.connection,
            "SELECT payload_json FROM tasks WHERE id = ?1",
            &id.to_string(),
        )
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
    Ok(())
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

    let (scope_kind, project_id) = scope_columns(scope);
    transaction.execute(
        "INSERT INTO records(id, kind, scope_kind, project_id, archived, payload_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(id) DO UPDATE SET kind = excluded.kind,
            scope_kind = excluded.scope_kind, project_id = excluded.project_id,
            archived = excluded.archived, payload_json = excluded.payload_json",
        params![
            id,
            kind,
            scope_kind,
            project_id,
            i64::from(archived),
            payload
        ],
    )?;
    transaction.execute(
        "INSERT INTO provenance(record_id, payload_json) VALUES (?1, ?2)
         ON CONFLICT(record_id) DO UPDATE SET payload_json = excluded.payload_json",
        params![id, to_json(provenance)?],
    )?;
    transaction.execute(
        "INSERT INTO operations(id, record_id, payload_json) VALUES (?1, ?2, ?3)",
        params![&operation_id, id, &operation_payload],
    )?;
    transaction.execute(
        "INSERT INTO outbox(operation_id) VALUES (?1)",
        [operation_id],
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
    Ok(true)
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
