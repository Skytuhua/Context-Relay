use context_relay_protocol::{
    CandidateReviewParams, CandidateState, ClientError, DeviceId, ErrorCode, HarnessAccessPolicy,
    HarnessId, HybridLogicalClock, McpScopeSelector, MemoryArchiveParams, MemoryCreateParams,
    MemoryId, MemoryOrigin, MemoryRecord, MemoryUpdateParams, OperationId, ProjectId,
    ProjectIdentity, Provenance, SearchParams, TaskCompleteParams, TaskEvidence, TaskId,
    TaskRecord, TaskStatus, TaskTransitionParams, TaskUpsertParams, WireNativeValue,
};
use sha2::{Digest, Sha256};

use crate::{
    search::{AllowedSearchScope, EMBEDDING_DIMENSIONS, Embedding384},
    vault::{Vault, VaultError},
};

pub struct OfflineWorkspace<'a> {
    vault: &'a mut Vault,
    device_id: DeviceId,
}

impl<'a> OfflineWorkspace<'a> {
    pub const fn new(vault: &'a mut Vault, device_id: DeviceId) -> Self {
        Self { vault, device_id }
    }

    pub fn create_memory(
        &mut self,
        params: MemoryCreateParams,
    ) -> Result<MemoryRecord, ClientError> {
        let id = MemoryId::new(params.operation_id.into_uuid()).map_err(|_| invalid_request())?;
        if let Some(memory) = vault(self.vault.memory(&id))? {
            return Ok(memory);
        }
        let clock = operation_clock(params.operation_id, self.device_id);
        let memory = MemoryRecord {
            id,
            scope: params.scope,
            kind: params.kind,
            title: params.title,
            body_markdown: params.body_markdown,
            tags: params.tags,
            origin: MemoryOrigin::Explicit,
            provenance: Provenance {
                origin_device: self.device_id,
                harness: None,
                source: None,
                created_hlc: clock,
            },
            revision: params.operation_id,
            created_hlc: clock,
            updated_hlc: clock,
            archived: false,
        };
        memory.validate().map_err(|_| invalid_request())?;
        vault(
            self.vault
                .put_local_memory(&memory, &memory_embedding(&memory)?),
        )?;
        Ok(memory)
    }

    pub fn memory(&self, id: MemoryId) -> Result<Option<MemoryRecord>, ClientError> {
        vault(self.vault.memory(&id))
    }

    pub fn update_memory(
        &mut self,
        params: MemoryUpdateParams,
    ) -> Result<MemoryRecord, ClientError> {
        let mut memory = self.memory(params.memory_id)?.ok_or_else(not_found)?;
        if memory.revision == params.operation_id {
            return Ok(memory);
        }
        require_revision(memory.revision, params.expected_revision)?;
        if let Some(title) = params.title {
            memory.title = title;
        }
        if let Some(body) = params.body_markdown {
            memory.body_markdown = body;
        }
        if let Some(tags) = params.tags {
            memory.tags = tags;
        }
        memory.revision = params.operation_id;
        memory.updated_hlc = operation_clock(params.operation_id, self.device_id);
        memory.validate().map_err(|_| invalid_request())?;
        vault(
            self.vault
                .put_local_memory(&memory, &memory_embedding(&memory)?),
        )?;
        Ok(memory)
    }

    pub fn archive_memory(
        &mut self,
        params: MemoryArchiveParams,
    ) -> Result<MemoryRecord, ClientError> {
        let mut memory = self.memory(params.memory_id)?.ok_or_else(not_found)?;
        if memory.revision == params.operation_id {
            return Ok(memory);
        }
        require_revision(memory.revision, params.expected_revision)?;
        memory.archived = true;
        memory.revision = params.operation_id;
        memory.updated_hlc = operation_clock(params.operation_id, self.device_id);
        vault(
            self.vault
                .put_local_memory(&memory, &memory_embedding(&memory)?),
        )?;
        Ok(memory)
    }

    pub fn search_memories(&self, params: SearchParams) -> Result<Vec<MemoryRecord>, ClientError> {
        if params.query.trim().is_empty() {
            return Err(invalid_request());
        }
        let selector = if params.project_id.is_some() {
            McpScopeSelector::ActiveProject
        } else {
            McpScopeSelector::Global
        };
        let scope = AllowedSearchScope::resolve(
            Some(selector),
            &HarnessAccessPolicy::Default,
            params.project_id,
        )
        .map_err(|_| scope_denied())?;
        let query_embedding = text_embedding(&params.query)?;
        let hits = vault(
            self.vault
                .search(&params.query, &scope, &query_embedding, 100),
        )?;
        let mut memories = Vec::with_capacity(hits.len());
        for hit in hits {
            let Ok(id) = hit.record_id().parse::<MemoryId>() else {
                continue;
            };
            let Some(memory) = vault(self.vault.memory(&id))? else {
                continue;
            };
            if memory_embedding(&memory)?.cosine_similarity(&query_embedding) > 0.0 {
                memories.push(memory);
            }
        }
        Ok(memories)
    }

    pub fn review_candidate(
        &mut self,
        params: CandidateReviewParams,
    ) -> Result<context_relay_protocol::MemoryCandidate, ClientError> {
        let mut candidate =
            vault(self.vault.candidate(&params.candidate_id))?.ok_or_else(not_found)?;
        let state = if params.accepted {
            CandidateState::Accepted
        } else {
            CandidateState::Rejected
        };
        if candidate.state == state {
            return Ok(candidate);
        }
        if candidate.state != CandidateState::Pending {
            return Err(conflict("The candidate was already reviewed"));
        }
        if params.accepted {
            let embedding = memory_embedding(&candidate.proposed_memory)?;
            vault(self.vault.review_candidate(
                candidate.id,
                state,
                Some(&candidate.proposed_memory),
                Some(&embedding),
            ))?;
        } else {
            vault(self.vault.review_candidate(candidate.id, state, None, None))?;
        }
        candidate.state = state;
        Ok(candidate)
    }

    pub fn candidates(
        &self,
        project_id: Option<ProjectId>,
    ) -> Result<Vec<context_relay_protocol::MemoryCandidate>, ClientError> {
        vault(self.vault.candidates(project_id))
    }

    pub fn upsert_task(&mut self, params: TaskUpsertParams) -> Result<TaskRecord, ClientError> {
        let id = match params.task_id {
            Some(id) => id,
            None => TaskId::new(params.operation_id.into_uuid()).map_err(|_| invalid_request())?,
        };
        if let Some(mut task) = vault(self.vault.task(&id))? {
            if task.revision == params.operation_id {
                return Ok(task);
            }
            let expected = params.expected_revision.ok_or_else(invalid_request)?;
            require_revision(task.revision, expected)?;
            task.project_id = params.project_id;
            task.title = params.title;
            task.body_markdown = params.body_markdown;
            task.status = params.status;
            task.revision = params.operation_id;
            task.validate().map_err(|_| invalid_request())?;
            vault(self.vault.put_task(&task))?;
            return Ok(task);
        }
        if params.task_id.is_some() || params.expected_revision.is_some() {
            return Err(not_found());
        }
        let task = TaskRecord {
            id,
            project_id: params.project_id,
            title: params.title,
            body_markdown: params.body_markdown,
            status: params.status,
            evidence: Vec::new(),
            revision: params.operation_id,
        };
        task.validate().map_err(|_| invalid_request())?;
        vault(self.vault.put_task(&task))?;
        Ok(task)
    }

    pub fn transition_task(
        &mut self,
        params: TaskTransitionParams,
    ) -> Result<TaskRecord, ClientError> {
        let mut task = vault(self.vault.task(&params.task_id))?.ok_or_else(not_found)?;
        if task.revision == params.operation_id {
            return Ok(task);
        }
        require_revision(task.revision, params.expected_revision)?;
        if params.status == TaskStatus::Done {
            return Err(invalid_request());
        }
        task.status = params.status;
        task.revision = params.operation_id;
        task.validate().map_err(|_| invalid_request())?;
        vault(self.vault.put_task(&task))?;
        Ok(task)
    }

    pub fn complete_task(&mut self, params: TaskCompleteParams) -> Result<TaskRecord, ClientError> {
        let mut task = vault(self.vault.task(&params.task_id))?.ok_or_else(not_found)?;
        if task.revision == params.operation_id {
            return Ok(task);
        }
        require_revision(task.revision, params.expected_revision)?;
        let recorded_hlc = operation_clock(params.operation_id, self.device_id);
        task.status = TaskStatus::Done;
        task.revision = params.operation_id;
        task.evidence = params
            .evidence
            .into_iter()
            .map(|evidence| TaskEvidence {
                summary: evidence.summary,
                evidence_kind: evidence.kind,
                reference: evidence.reference,
                recorded_hlc,
            })
            .collect();
        task.validate().map_err(|_| invalid_request())?;
        vault(self.vault.put_task(&task))?;
        Ok(task)
    }

    pub fn tasks(&self, project_id: ProjectId) -> Result<Vec<TaskRecord>, ClientError> {
        vault(self.vault.tasks(project_id))
    }

    pub fn upsert_project(&mut self, project: ProjectIdentity) -> Result<(), ClientError> {
        vault(self.vault.put_project(&project))
    }

    pub fn projects(&self) -> Result<Vec<ProjectIdentity>, ClientError> {
        vault(self.vault.projects())
    }

    pub fn set_project_path(
        &mut self,
        project_id: ProjectId,
        path: WireNativeValue,
    ) -> Result<(), ClientError> {
        vault(self.vault.put_path(&project_id.to_string(), &path))
    }

    pub fn project_path(
        &self,
        project_id: ProjectId,
    ) -> Result<Option<WireNativeValue>, ClientError> {
        vault(self.vault.path(&project_id.to_string()))
    }

    pub fn access_policy(&self, harness: HarnessId) -> Result<HarnessAccessPolicy, ClientError> {
        vault(self.vault.access_policy(harness))
    }

    pub fn set_access_policy(
        &mut self,
        harness: HarnessId,
        policy: &HarnessAccessPolicy,
    ) -> Result<(), ClientError> {
        vault(self.vault.set_access_policy(harness, policy))
    }
}

fn operation_clock(operation_id: OperationId, device_id: DeviceId) -> HybridLogicalClock {
    let bytes = operation_id.as_bytes();
    let physical_ms = u64::from_be_bytes([
        0, 0, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
    ]);
    HybridLogicalClock::new(physical_ms, 0, device_id)
}

fn memory_embedding(memory: &MemoryRecord) -> Result<Embedding384, ClientError> {
    text_embedding(&format!(
        "{} {} {}",
        memory.title,
        memory.body_markdown,
        memory.tags.join(" ")
    ))
}

fn text_embedding(text: &str) -> Result<Embedding384, ClientError> {
    let mut values = vec![0.0_f32; EMBEDDING_DIMENSIONS];
    for token in text
        .split(|character: char| !character.is_alphanumeric())
        .filter(|token| !token.is_empty())
    {
        let digest = Sha256::digest(token.to_lowercase().as_bytes());
        let index = usize::from(u16::from_be_bytes([digest[0], digest[1]])) % EMBEDDING_DIMENSIONS;
        values[index] += 1.0;
    }
    if values.iter().all(|value| *value == 0.0) {
        values[0] = 1.0;
    }
    Embedding384::try_from(values).map_err(|_| internal())
}

fn require_revision(actual: OperationId, expected: OperationId) -> Result<(), ClientError> {
    if actual == expected {
        Ok(())
    } else {
        Err(ClientError {
            code: ErrorCode::RevisionConflict,
            message: "The record changed since it was loaded".to_owned(),
            field_path: Some("expectedRevision".to_owned()),
            retryable: false,
        })
    }
}

fn vault<T>(result: Result<T, VaultError>) -> Result<T, ClientError> {
    result.map_err(|_| internal())
}

fn invalid_request() -> ClientError {
    ClientError {
        code: ErrorCode::InvalidRequest,
        message: "The request is invalid".to_owned(),
        field_path: None,
        retryable: false,
    }
}

fn not_found() -> ClientError {
    ClientError {
        code: ErrorCode::NotFound,
        message: "The requested record was not found".to_owned(),
        field_path: None,
        retryable: false,
    }
}

fn scope_denied() -> ClientError {
    ClientError {
        code: ErrorCode::ScopeDenied,
        message: "The requested scope is not available".to_owned(),
        field_path: None,
        retryable: false,
    }
}

fn conflict(message: &str) -> ClientError {
    ClientError {
        code: ErrorCode::Conflict,
        message: message.to_owned(),
        field_path: None,
        retryable: false,
    }
}

fn internal() -> ClientError {
    ClientError {
        code: ErrorCode::Internal,
        message: "The local vault operation failed".to_owned(),
        field_path: None,
        retryable: false,
    }
}
