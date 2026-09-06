use super::{Vault, VaultError, from_json, to_json};
use context_relay_protocol::{DesktopWrite, DesktopWritesPage, OperationId};
use rusqlite::{OptionalExtension, TransactionBehavior, params};

const MAX_WRITES: i64 = 256;
const MAX_BYTES: i64 = 64 * 1024 * 1024;

impl Vault {
    /// Preparing does not apply the mutation. Only the ordinary service can do that.
    pub fn prepare_desktop_write(&mut self, write: &DesktopWrite) -> Result<(), VaultError> {
        write
            .validate()
            .map_err(|error| VaultError::Validation(error.to_string()))?;
        let payload = to_json(write)?;
        let id = write.operation_id().to_string();
        let mut summary = write.summary();
        let target = match write {
            DesktopWrite::MemoryUpdate(p) => self
                .memory(&p.memory_id)?
                .map(|record| (record.title, record.scope)),
            DesktopWrite::MemoryArchive(p) => self
                .memory(&p.memory_id)?
                .map(|record| (record.title, record.scope)),
            DesktopWrite::CandidateReview(p) => self
                .candidate(&p.candidate_id)?
                .map(|record| (record.proposed_memory.title, record.proposed_memory.scope)),
            DesktopWrite::TaskComplete(p) => self.task(&p.task_id)?.map(|record| {
                (
                    record.title,
                    context_relay_protocol::ScopeRef::Project {
                        project_id: record.project_id,
                    },
                )
            }),
            DesktopWrite::TaskTransition(p) => self.task(&p.task_id)?.map(|record| {
                (
                    record.title,
                    context_relay_protocol::ScopeRef::Project {
                        project_id: record.project_id,
                    },
                )
            }),
            _ => None,
        };
        if let Some((title, scope)) = target {
            if !matches!(write, DesktopWrite::MemoryUpdate(p) if p.title.is_some()) {
                summary.title = title;
            }
            summary.scope = Some(scope);
        }
        let summary = to_json(&summary)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT payload_json FROM desktop_writes WHERE operation_id = ?1",
                [&id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            if from_json::<DesktopWrite>(&existing)? == *write {
                return Ok(());
            }
            return Err(VaultError::OperationConflict);
        }
        let (count, bytes): (i64, i64) = transaction.query_row(
            "SELECT COUNT(*), COALESCE(SUM(LENGTH(payload_json) + LENGTH(summary_json)), 0) FROM desktop_writes",
            [], |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if count >= MAX_WRITES || bytes + payload.len() as i64 + summary.len() as i64 > MAX_BYTES {
            return Err(VaultError::BudgetExceeded);
        }
        transaction.execute(
            "INSERT INTO desktop_writes(operation_id, payload_json, summary_json) VALUES (?1, ?2, ?3)",
            params![id, payload, summary],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn desktop_write(&self, id: OperationId) -> Result<Option<DesktopWrite>, VaultError> {
        let payload: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT payload_json FROM desktop_writes WHERE operation_id = ?1",
                [id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        payload
            .map(|bytes| {
                let write: DesktopWrite = from_json(&bytes)?;
                write
                    .validate()
                    .map_err(|error| VaultError::Validation(error.to_string()))?;
                if write.operation_id() != id {
                    return Err(VaultError::OperationConflict);
                }
                Ok(write)
            })
            .transpose()
    }

    pub fn desktop_writes(
        &self,
        after: Option<OperationId>,
    ) -> Result<DesktopWritesPage, VaultError> {
        let mut statement = self.connection.prepare(
            "SELECT summary_json FROM desktop_writes WHERE operation_id > ?1 ORDER BY operation_id LIMIT 51",
        )?;
        let rows = statement.query_map(
            [after.map(|id| id.to_string()).unwrap_or_default()],
            |row| row.get::<_, Vec<u8>>(0),
        )?;
        let mut writes = rows
            .map(|row| from_json(&row?))
            .collect::<Result<Vec<context_relay_protocol::DesktopWriteSummary>, VaultError>>()?;
        let next_cursor = if writes.len() > 50 {
            writes.truncate(50);
            writes.last().map(|write| write.operation_id)
        } else {
            None
        };
        let page = DesktopWritesPage {
            writes,
            next_cursor,
        };
        page.validate()
            .map_err(|error| VaultError::Validation(error.to_string()))?;
        Ok(page)
    }

    /// Forgetting a recovery copy does not undo an already committed mutation.
    pub fn forget_desktop_write(&mut self, id: OperationId) -> Result<(), VaultError> {
        self.connection.execute(
            "DELETE FROM desktop_writes WHERE operation_id = ?1",
            [id.to_string()],
        )?;
        Ok(())
    }
}
