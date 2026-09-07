use std::time::{Duration, Instant};

use rusqlite::{OptionalExtension, Transaction, params};

use super::{Vault, VaultError, handoff_projection};
use crate::search::{
    AllowedSearchScope, Embedding384, semantic_input_digest, semantic_model_fingerprint,
    semantic_passage_input,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SemanticIndexProgress {
    pub indexed_records: u64,
    pub total_records: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SemanticIndexBatch {
    /// New vectors published by this slice.
    pub indexed: usize,
    /// Queue entries completed, including already-matching persisted vectors.
    pub processed: usize,
    /// Pending queue entries; use scoped progress for user-visible ready counts.
    pub remaining: u64,
}

impl Vault {
    /// Counts only records visible in the caller's resolved scope.
    pub fn semantic_index_progress(
        &self,
        scope: &AllowedSearchScope,
    ) -> Result<Option<SemanticIndexProgress>, VaultError> {
        if self.semantic_search.is_none() {
            return Ok(None);
        }
        let fingerprint = semantic_model_fingerprint();
        let (indexed, total) = self.connection.query_row(
            "SELECT count(e.record_id), count(d.record_id)
             FROM search_documents AS d LEFT JOIN semantic_embeddings AS e
               ON e.record_id = d.record_id AND e.input_digest = d.input_digest
               AND e.model_fingerprint = ?1
             WHERE d.approved = 1 AND d.archived = 0 AND (
               (d.scope_kind = 'global' AND ?2 = 1)
               OR (d.scope_kind = 'project' AND d.project_id = ?3))",
            params![
                fingerprint.as_slice(),
                i64::from(scope.allows_global()),
                scope.project_id().map(|id| id.to_string()),
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )?;
        Ok(Some(SemanticIndexProgress {
            indexed_records: super::sqlite_u64(indexed, "indexed records")?,
            total_records: super::sqlite_u64(total, "searchable records")?,
        }))
    }

    /// Performs resumable local derived work. The time budget is checked between
    /// individual inferences; a single inference cannot be preempted.
    pub fn index_semantic_batch(
        &mut self,
        max_records: usize,
        max_duration: Duration,
    ) -> Result<SemanticIndexBatch, VaultError> {
        if !(1..=32).contains(&max_records) || max_duration.is_zero() {
            return Err(VaultError::Validation(
                "index batches require 1 to 32 records and a positive time budget".into(),
            ));
        }
        if self.semantic_search.is_none() {
            return Ok(SemanticIndexBatch {
                indexed: 0,
                processed: 0,
                remaining: 0,
            });
        }
        let fingerprint = semantic_model_fingerprint();
        self.prepare_semantic_queue(&fingerprint)?;
        let started = Instant::now();
        let documents = {
            let mut statement = self.connection.prepare(
                "SELECT d.record_id, d.title, d.tags, d.body, d.input_digest, e.record_id IS NOT NULL
                 FROM semantic_index_queue AS q CROSS JOIN search_documents AS d
                 LEFT JOIN semantic_embeddings AS e
                   ON e.record_id = d.record_id AND e.input_digest = d.input_digest
                   AND e.model_fingerprint = ?1
                 WHERE d.record_id=q.record_id AND d.approved = 1 AND d.archived = 0
                 ORDER BY q.record_id LIMIT ?2",
            )?;
            statement
                .query_map(params![fingerprint.as_slice(), max_records as u32], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, bool>(5)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        // No database transaction or live statement is held during inference.
        let mut generated = Vec::with_capacity(documents.len());
        {
            let mut engine = self
                .semantic_search
                .as_ref()
                .expect("enabled model")
                .borrow_mut();
            for (id, title, tags, body, stored_digest, ready) in documents {
                if !generated.is_empty() && started.elapsed() >= max_duration {
                    break;
                }
                let digest = semantic_input_digest(&title, &tags, &body);
                if stored_digest.as_slice() != digest {
                    return Err(VaultError::Validation(
                        "invalid semantic input digest".into(),
                    ));
                }
                let vector = if ready {
                    None
                } else {
                    Some(engine.embed_passage(&semantic_passage_input(&title, &tags, &body))?)
                };
                generated.push((id, digest, vector));
            }
        }
        let mut indexed = 0;
        let mut processed = 0;
        if !generated.is_empty() {
            let transaction = self.connection.transaction()?;
            for (id, digest, vector) in generated {
                if let Some(vector) = vector {
                    indexed +=
                        persist_embedding(&transaction, &id, &fingerprint, &digest, &vector)?;
                }
                processed += transaction.execute(
                    "DELETE FROM semantic_index_queue WHERE record_id=?1 AND EXISTS (
                       SELECT 1 FROM search_documents AS d JOIN semantic_embeddings AS e
                         ON e.record_id=d.record_id AND e.input_digest=d.input_digest
                       WHERE d.record_id=?1 AND d.input_digest=?2 AND e.model_fingerprint=?3)",
                    params![id, digest.as_slice(), fingerprint.as_slice()],
                )?;
            }
            transaction.commit()?;
        }
        let remaining =
            self.connection
                .query_row("SELECT count(*) FROM semantic_index_queue", [], |row| {
                    row.get::<_, i64>(0)
                })?;
        Ok(SemanticIndexBatch {
            indexed,
            processed,
            remaining: super::sqlite_u64(remaining, "remaining records")?,
        })
    }

    fn prepare_semantic_queue(&mut self, fingerprint: &[u8; 32]) -> Result<(), VaultError> {
        let existing = self
            .connection
            .query_row(
                "SELECT fingerprint FROM semantic_index_model WHERE singleton=1",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        if existing.as_deref() == Some(fingerprint.as_slice()) {
            return Ok(());
        }
        // One reconciliation scan when the model/preprocessing identity changes.
        // Subsequent slices visit only the durable pending queue.
        let tx = self.connection.transaction()?;
        tx.execute("INSERT OR IGNORE INTO semantic_index_queue SELECT record_id FROM search_documents WHERE approved=1 AND archived=0", [])?;
        tx.execute("INSERT INTO semantic_index_model VALUES(1,?1) ON CONFLICT(singleton) DO UPDATE SET fingerprint=excluded.fingerprint", [fingerprint.as_slice()])?;
        tx.commit()?;
        Ok(())
    }
}

fn persist_embedding(
    transaction: &Transaction<'_>,
    record_id: &str,
    fingerprint: &[u8; 32],
    digest: &[u8; 32],
    vector: &Embedding384,
) -> Result<usize, VaultError> {
    // Another connection may have edited or archived the document during
    // inference. Only publish if the current projection still matches.
    Ok(transaction.execute(
        "INSERT INTO semantic_embeddings(record_id, model_fingerprint, input_digest, vector)
         SELECT record_id, ?2, ?3, ?4 FROM search_documents
         WHERE record_id = ?1 AND input_digest = ?3 AND approved = 1 AND archived = 0
         ON CONFLICT(record_id) DO UPDATE SET
           model_fingerprint = excluded.model_fingerprint,
           input_digest = excluded.input_digest, vector = excluded.vector",
        params![
            record_id,
            fingerprint.as_slice(),
            digest.as_slice(),
            vector.to_le_bytes()
        ],
    )?)
}

pub(super) fn backfill_search_metadata(transaction: &Transaction<'_>) -> Result<(), VaultError> {
    // record_id is UNINDEXED in FTS. Clear once instead of an O(N²) sequence
    // of per-record deletes, and page source text to bound migration memory.
    transaction.execute("DELETE FROM search_fts", [])?;
    let mut cursor = String::new();
    let mut select = transaction.prepare(
        "SELECT d.record_id, d.title, d.body, r.kind, r.payload_json
         FROM search_documents AS d JOIN records AS r ON r.id = d.record_id
         WHERE d.record_id > ?1 ORDER BY d.record_id LIMIT 32",
    )?;
    let mut update = transaction
        .prepare("UPDATE search_documents SET tags = ?2, input_digest = ?3 WHERE record_id = ?1")?;
    loop {
        let documents = {
            select
                .query_map([&cursor], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        if documents.is_empty() {
            break;
        }
        for (id, title, body, kind, payload) in documents {
            cursor.clone_from(&id);
            let tags = handoff_projection(&kind, &payload)?.tags;
            let digest = semantic_input_digest(&title, &tags, &body);
            update.execute(params![id, tags, digest.as_slice()])?;
        }
    }
    transaction.execute(
        "INSERT INTO search_fts(record_id, title, body)
         SELECT record_id, title, tags || char(10) || body FROM search_documents",
        [],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publishing_a_vector_rechecks_changed_deleted_and_ineligible_documents() {
        // Exercise the actual publication SQL at the race boundary without
        // depending on native inference timing or concurrent test scheduling.
        let mut connection = rusqlite::Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE search_documents(record_id TEXT PRIMARY KEY, input_digest BLOB,
               approved INTEGER, archived INTEGER);
             CREATE TABLE semantic_embeddings(record_id TEXT PRIMARY KEY, model_fingerprint BLOB,
               input_digest BLOB, vector BLOB);",
            )
            .unwrap();
        let old_digest = [1_u8; 32];
        let current_digest = [2_u8; 32];
        connection
            .execute(
                "INSERT INTO search_documents VALUES ('record',?1,1,0)",
                [current_digest.as_slice()],
            )
            .unwrap();
        let vector = Embedding384::try_from(vec![1.0; 384]).unwrap();
        let fingerprint = semantic_model_fingerprint();
        let tx = connection.transaction().unwrap();
        assert_eq!(
            persist_embedding(&tx, "record", &fingerprint, &old_digest, &vector).unwrap(),
            0
        );
        assert_eq!(
            persist_embedding(&tx, "record", &fingerprint, &current_digest, &vector).unwrap(),
            1
        );
        tx.execute("DELETE FROM semantic_embeddings", []).unwrap();
        tx.execute("UPDATE search_documents SET archived=1", [])
            .unwrap();
        assert_eq!(
            persist_embedding(&tx, "record", &fingerprint, &current_digest, &vector).unwrap(),
            0
        );
        tx.execute("UPDATE search_documents SET archived=0,approved=0", [])
            .unwrap();
        assert_eq!(
            persist_embedding(&tx, "record", &fingerprint, &current_digest, &vector).unwrap(),
            0
        );
        tx.execute("DELETE FROM search_documents", []).unwrap();
        assert_eq!(
            persist_embedding(&tx, "record", &fingerprint, &current_digest, &vector).unwrap(),
            0
        );
        let count: i64 = tx
            .query_row("SELECT count(*) FROM semantic_embeddings", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0);
    }
}
