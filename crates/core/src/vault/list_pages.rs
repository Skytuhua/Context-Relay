use super::{Vault, from_json};
use context_relay_protocol::{
    CandidatesPage, ClientError, ErrorCode, MAX_LIST_PAGE_BYTES, MAX_LIST_PAGE_ITEMS, MemoriesPage,
    MemoryCandidate, MemoryRecord, ProjectId, ProjectIdentity, ProjectsPage, RecordId, ScopeRef,
    TaskRecord, TaskStatus, TasksPage, validate_list_cursor,
};
use rusqlite::{Params, params};
use serde::{Serialize, de::DeserializeOwned};

impl Vault {
    pub fn memories_page(
        &self,
        project_id: Option<ProjectId>,
        include_archived: bool,
        cursor: Option<&str>,
    ) -> Result<MemoriesPage, ClientError> {
        let key = format!(
            "v1:memories:{}:{}:",
            scope_key(project_id),
            u8::from(include_archived)
        );
        let after = cursor_after(&key, cursor)?;
        let (memories, next_cursor) = self.list_page::<MemoryRecord, _>(
            "SELECT id, payload_json FROM records WHERE kind = 'memory' AND scope_kind = ?1 AND project_id IS ?2 AND (?3 = 1 OR archived = 0) AND id > ?4 ORDER BY id",
            params![if project_id.is_some() { "project" } else { "global" }, project_id.map(|id| id.to_string()), i64::from(include_archived), after],
            &key, MAX_LIST_PAGE_BYTES, |_| true,
        )?;
        Ok(MemoriesPage {
            memories,
            next_cursor,
        })
    }

    pub fn candidates_page(
        &self,
        project_id: Option<ProjectId>,
        cursor: Option<&str>,
    ) -> Result<CandidatesPage, ClientError> {
        let key = format!("v1:candidates:{}:", scope_key(project_id));
        let after = cursor_after(&key, cursor)?;
        let (candidates, next_cursor) = self.list_page::<MemoryCandidate, _>(
            "SELECT id, payload_json FROM candidates WHERE id > ?1 ORDER BY id",
            [after],
            &key,
            MAX_LIST_PAGE_BYTES,
            |candidate| match candidate.proposed_memory.scope {
                ScopeRef::Global => project_id.is_none(),
                ScopeRef::Project { project_id: actual } => Some(actual) == project_id,
            },
        )?;
        Ok(CandidatesPage {
            candidates,
            next_cursor,
        })
    }

    pub fn projects_page(&self, cursor: Option<&str>) -> Result<ProjectsPage, ClientError> {
        let key = "v1:projects:";
        let after = cursor_after(key, cursor)?;
        let (projects, next_cursor) = self.list_page::<ProjectIdentity, _>(
            "SELECT id, payload_json FROM projects WHERE id > ?1 ORDER BY id",
            [after],
            key,
            MAX_LIST_PAGE_BYTES,
            |_| true,
        )?;
        Ok(ProjectsPage {
            projects,
            next_cursor,
        })
    }

    pub fn tasks_page(
        &self,
        project_id: ProjectId,
        status: Option<TaskStatus>,
        cursor: Option<&str>,
        max_bytes: usize,
    ) -> Result<TasksPage, ClientError> {
        let status_key = status
            .map(|status| serde_json::to_string(&status).expect("task status serializes"))
            .unwrap_or_else(|| "all".into());
        let key = format!("v1:tasks:{project_id}:{status_key}:");
        let after = cursor_after(&key, cursor)?;
        let (tasks, next_cursor) = self.list_page::<TaskRecord, _>(
            "SELECT id, payload_json FROM tasks WHERE project_id = ?1 AND id > ?2 ORDER BY id",
            params![project_id.to_string(), after],
            &key,
            max_bytes.min(MAX_LIST_PAGE_BYTES),
            |task| status.is_none_or(|status| status == task.status),
        )?;
        Ok(TasksPage { tasks, next_cursor })
    }

    fn list_page<T: DeserializeOwned + Serialize, P: Params>(
        &self,
        sql: &str,
        params: P,
        key: &str,
        max_bytes: usize,
        include: impl Fn(&T) -> bool,
    ) -> Result<(Vec<T>, Option<String>), ClientError> {
        let mut statement = self.connection.prepare(sql).map_err(|_| list_error())?;
        let mut rows = statement.query(params).map_err(|_| list_error())?;
        let mut items = Vec::new();
        // Includes array separators, page/result envelopes and the maximum continuation token.
        let mut bytes = 1024usize;
        let mut last_id = None;
        while let Some(row) = rows.next().map_err(|_| list_error())? {
            let id: String = row.get(0).map_err(|_| list_error())?;
            let payload: Vec<u8> = row.get(1).map_err(|_| list_error())?;
            let item: T = from_json(&payload).map_err(|_| list_error())?;
            if !include(&item) {
                continue;
            }
            let size = serde_json::to_vec(&item).map_err(|_| list_error())?.len() + 1;
            if items.len() == MAX_LIST_PAGE_ITEMS || bytes.saturating_add(size) > max_bytes {
                return match last_id {
                    Some(id) => Ok((items, Some(format!("{key}{id}")))),
                    None => Err(ClientError { code: ErrorCode::FrameTooLarge, message: "A record exceeds the list response budget; read it individually in the desktop app".into(), field_path: None, retryable: false }),
                };
            }
            bytes += size;
            last_id = Some(id);
            items.push(item);
        }
        Ok((items, None))
    }
}

fn scope_key(project_id: Option<ProjectId>) -> String {
    project_id
        .map(|id| id.to_string())
        .unwrap_or_else(|| "global".into())
}

fn cursor_after<'a>(key: &str, cursor: Option<&'a str>) -> Result<&'a str, ClientError> {
    let invalid = || ClientError {
        code: ErrorCode::InvalidRequest,
        message: "The list cursor is invalid for this query; restart from the first page".into(),
        field_path: Some("cursor".into()),
        retryable: false,
    };
    validate_list_cursor(cursor).map_err(|_| invalid())?;
    match cursor {
        None => Ok(""),
        Some(cursor) => {
            let after = cursor.strip_prefix(key).ok_or_else(invalid)?;
            after.parse::<RecordId>().map_err(|_| invalid())?;
            Ok(after)
        }
    }
}

fn list_error() -> ClientError {
    ClientError {
        code: ErrorCode::Internal,
        message: "The local vault could not read this list".into(),
        field_path: None,
        retryable: false,
    }
}
