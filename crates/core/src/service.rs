use std::str::FromStr as _;

use context_relay_protocol::{
    CandidateId, CandidateReviewParams, CandidateState, ClientError, DeviceId, ErrorCode,
    HarnessAccessPolicy, HarnessId, HybridLogicalClock, InstructionRecord, LocalRequest,
    McpScopeSelector, MemoryArchiveParams, MemoryCandidate, MemoryCreateParams, MemoryId,
    MemoryOrigin, MemoryRecord, MemoryUpdateParams, NativeHookEvent, NativeHookEventParams,
    OperationId, ProjectId, ProjectIdentity, ProposeMemoryInput, Provenance, ReadableRecord,
    RecordId, ScopeRef, SearchParams, Sha256Digest, TaskCompleteParams, TaskEvidence, TaskId,
    TaskRecord, TaskStatus, TaskTransitionParams, TaskUpsertParams, WireNativeValue,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    native_memory::{
        NativeMemoryDiagnostic, NativeMemoryDiagnosticClass, NativeMemoryError, NativeMemoryLedger,
        NativeMemorySnapshot, ReadyNativeMemory, ReconcileDecision, build_native_memory_candidate,
        reconcile_classified,
    },
    search::{AllowedSearchScope, EMBEDDING_DIMENSIONS, Embedding384},
    vault::{
        LocalOperationBinding, LocalOperationKind, LocalOperationReplay, NativeHookSession, Vault,
        VaultError,
    },
};

pub struct OfflineWorkspace<'a> {
    vault: &'a mut Vault,
    device_id: DeviceId,
}

struct PreparedLocalMutation<T> {
    value: T,
    binding: LocalOperationBinding,
    should_write: bool,
}

impl<'a> OfflineWorkspace<'a> {
    pub const fn new(vault: &'a mut Vault, device_id: DeviceId) -> Self {
        Self { vault, device_id }
    }

    pub fn handle_native_hook_event(
        &mut self,
        project_id: ProjectId,
        params: NativeHookEventParams,
    ) -> Result<(), ClientError> {
        LocalRequest::NativeHookEvent(params.clone())
            .validate()
            .map_err(|_| invalid_request())?;
        if !vault(self.vault.projects())?
            .into_iter()
            .any(|project| project.project_id == project_id)
        {
            return Err(conflict("The native hook project is no longer registered"));
        }
        match &params.event {
            NativeHookEvent::SessionStart { .. } | NativeHookEvent::SessionStop { .. } => {
                let session_id = match &params.event {
                    NativeHookEvent::SessionStart { session_id }
                    | NativeHookEvent::SessionStop { session_id } => session_id,
                    NativeHookEvent::TaskEvidence { .. } => unreachable!(),
                };
                if let Some(current) = vault(
                    self.vault
                        .native_hook_session(params.binding.harness, session_id),
                )? && current.project_id != project_id
                {
                    let latest = current.stopped_at_ms.unwrap_or(current.started_at_ms);
                    let may_rebind = matches!(&params.event, NativeHookEvent::SessionStart { .. })
                        && params.occurred_at_ms > latest;
                    if !may_rebind {
                        return Err(conflict(
                            "The native hook session is bound to another project",
                        ));
                    }
                }
                vault(self.vault.put_native_hook_session(project_id, &params))
            }
            NativeHookEvent::TaskEvidence {
                session_id,
                task_id,
                evidence,
            } => {
                let session = vault(
                    self.vault
                        .native_hook_session(params.binding.harness, session_id),
                )?
                .ok_or_else(|| conflict("The native hook task evidence session does not exist"))?;
                if session.project_id != project_id {
                    return Err(conflict(
                        "The native hook task evidence session belongs to another project",
                    ));
                }
                if params.occurred_at_ms < session.started_at_ms
                    || session
                        .stopped_at_ms
                        .is_some_and(|stopped_at_ms| params.occurred_at_ms > stopped_at_ms)
                {
                    return Err(conflict(
                        "The native hook task evidence is outside its session lifecycle",
                    ));
                }
                let task = vault(self.vault.task(task_id))?.ok_or_else(|| {
                    conflict("The native hook task evidence target does not exist")
                })?;
                if task.project_id != project_id {
                    return Err(conflict(
                        "The native hook task is outside the resolved project",
                    ));
                }
                let operation_id = native_hook_operation_id(project_id, &params)?;
                if task.status == TaskStatus::Done {
                    if task.revision == operation_id {
                        return Ok(());
                    }
                    return Err(conflict("The native hook task evidence is stale"));
                }
                self.complete_task_with_recorded_hlc(
                    TaskCompleteParams {
                        operation_id,
                        task_id: *task_id,
                        expected_revision: task.revision,
                        evidence: evidence.clone(),
                    },
                    HybridLogicalClock::new(params.occurred_at_ms, 0, self.device_id),
                )
                .map(|_| ())
            }
        }
    }

    pub fn native_hook_session(
        &self,
        harness: HarnessId,
        session_id: &str,
    ) -> Result<Option<NativeHookSession>, ClientError> {
        vault(self.vault.native_hook_session(harness, session_id))
    }

    pub fn native_hook_session_count(&self) -> Result<usize, ClientError> {
        vault(self.vault.native_hook_session_count())
    }

    pub fn reconcile_native_memory(
        &mut self,
        ready: ReadyNativeMemory,
    ) -> Result<Option<MemoryCandidate>, ClientError> {
        ready
            .source
            .validate_compatible()
            .map_err(|_| invalid_request())?;
        let mut ledger = match vault(self.vault.native_memory_ledger(&ready.source.id))? {
            Some(ledger) => {
                if ledger.source.as_ref() != Some(&ready.source) {
                    return Err(conflict("The native memory source metadata changed"));
                }
                ledger
            }
            None => NativeMemoryLedger::for_source(ready.source.clone()),
        };

        let candidate = match ready.snapshot {
            NativeMemorySnapshot::Absent => {
                ledger.last_observed_digest = None;
                ledger.last_diagnostic = None;
                ledger.initial_preview_complete = true;
                None
            }
            NativeMemorySnapshot::Regular(bytes) => {
                let decision =
                    match reconcile_classified(&ready.source, &ledger, &bytes, ready.kind) {
                        Ok(decision) => {
                            ledger.last_diagnostic = None;
                            decision
                        }
                        Err(NativeMemoryError::InvalidSource(_)) => return Err(invalid_request()),
                        Err(error) => {
                            let error_class = match error {
                                NativeMemoryError::InvalidUtf8 => {
                                    NativeMemoryDiagnosticClass::InvalidUtf8
                                }
                                NativeMemoryError::SensitiveText => {
                                    NativeMemoryDiagnosticClass::SensitiveText
                                }
                                NativeMemoryError::TooLarge => {
                                    NativeMemoryDiagnosticClass::TooLarge
                                }
                                NativeMemoryError::MalformedManagedFence => {
                                    NativeMemoryDiagnosticClass::MalformedManagedFence
                                }
                                NativeMemoryError::ManagedContentModified => {
                                    NativeMemoryDiagnosticClass::ManagedContentModified
                                }
                                NativeMemoryError::InvalidSource(_) => unreachable!(),
                            };
                            let digest = Sha256Digest(Sha256::digest(&bytes).into());
                            ledger.last_observed_digest = Some(digest);
                            ledger.last_diagnostic = Some(NativeMemoryDiagnostic {
                                source_id: ready.source.id,
                                error_class,
                                digest,
                            });
                            ledger.initial_preview_complete = true;
                            vault(self.vault.put_native_memory_candidate(&ledger, None))?;
                            return Ok(None);
                        }
                    };
                match decision {
                    ReconcileDecision::Pending {
                        full_digest,
                        unmanaged_digest,
                        candidate_markdown,
                        change_kind,
                        ..
                    } => {
                        let candidate = build_native_memory_candidate(
                            &ready.source,
                            unmanaged_digest,
                            candidate_markdown,
                            change_kind,
                            self.device_id,
                        )
                        .map_err(|_| invalid_request())?;
                        ledger.last_observed_digest = Some(full_digest);
                        ledger.last_unmanaged_digest = Some(unmanaged_digest);
                        ledger.last_imported_digest = Some(unmanaged_digest);
                        ledger.initial_preview_complete = true;
                        Some(candidate)
                    }
                    ReconcileDecision::NoContent {
                        full_digest,
                        unmanaged_digest,
                    }
                    | ReconcileDecision::AlreadyImported {
                        full_digest,
                        unmanaged_digest,
                    } => {
                        ledger.last_observed_digest = Some(full_digest);
                        ledger.last_unmanaged_digest = Some(unmanaged_digest);
                        ledger.initial_preview_complete = true;
                        None
                    }
                    ReconcileDecision::SelfExport {
                        full_digest,
                        managed_digest,
                    } => {
                        ledger.last_observed_digest = Some(full_digest);
                        ledger.last_applied_managed_digest = managed_digest;
                        ledger.initial_preview_complete = true;
                        None
                    }
                }
            }
        };
        let candidate_is_new = candidate
            .as_ref()
            .map(|candidate| {
                vault(self.vault.candidate(&candidate.id)).map(|stored| stored.is_none())
            })
            .transpose()?
            .unwrap_or(false);
        vault(
            self.vault
                .put_native_memory_candidate(&ledger, candidate.as_ref()),
        )?;
        Ok(candidate.filter(|_| candidate_is_new))
    }

    pub fn create_memory(
        &mut self,
        params: MemoryCreateParams,
    ) -> Result<MemoryRecord, ClientError> {
        let prepared = self.prepare_memory_create(&params)?;
        if prepared.should_write {
            vault(self.vault.put_local_memory_with_binding(
                &prepared.value,
                &memory_embedding(&prepared.value)?,
                &prepared.binding,
            ))?;
        }
        Ok(prepared.value)
    }

    pub(crate) fn preview_memory_create(
        &self,
        params: &MemoryCreateParams,
    ) -> Result<MemoryRecord, ClientError> {
        self.prepare_memory_create(params)
            .map(|prepared| prepared.value)
    }

    fn prepare_memory_create(
        &self,
        params: &MemoryCreateParams,
    ) -> Result<PreparedLocalMutation<MemoryRecord>, ClientError> {
        let id = MemoryId::new(params.operation_id.into_uuid()).map_err(|_| invalid_request())?;
        let binding = local_operation_binding(
            params.operation_id,
            LocalOperationKind::Create,
            id.to_string(),
            None,
            params,
        )?;
        match vault(self.vault.local_operation_replay(&binding))? {
            LocalOperationReplay::Snapshot(snapshot) => {
                let memory = memory_snapshot(&snapshot, id, params.operation_id)?;
                if memory.archived {
                    return Err(internal());
                }
                return Ok(PreparedLocalMutation {
                    value: memory,
                    binding,
                    should_write: false,
                });
            }
            LocalOperationReplay::Legacy => {
                let memory = vault(self.vault.memory(&id))?.ok_or_else(internal)?;
                return Ok(PreparedLocalMutation {
                    value: memory,
                    binding,
                    should_write: false,
                });
            }
            LocalOperationReplay::Fresh => {}
        }
        if vault(self.vault.memory(&id))?.is_some() {
            return Err(operation_conflict());
        }
        let clock = operation_clock(params.operation_id, self.device_id);
        let memory = MemoryRecord {
            id,
            scope: params.scope.clone(),
            kind: params.kind,
            title: params.title.clone(),
            body_markdown: params.body_markdown.clone(),
            tags: params.tags.clone(),
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
        Ok(PreparedLocalMutation {
            value: memory,
            binding,
            should_write: true,
        })
    }

    pub fn memory(&self, id: MemoryId) -> Result<Option<MemoryRecord>, ClientError> {
        vault(self.vault.memory(&id))
    }

    pub fn instruction(&self, id: RecordId) -> Result<Option<InstructionRecord>, ClientError> {
        vault(self.vault.instruction(&id))
    }

    pub(crate) fn candidate(
        &self,
        id: CandidateId,
    ) -> Result<Option<MemoryCandidate>, ClientError> {
        vault(self.vault.candidate(&id))
    }

    pub fn propose_memory(
        &mut self,
        input: ProposeMemoryInput,
        scope: ScopeRef,
        harness: HarnessId,
    ) -> Result<MemoryCandidate, ClientError> {
        let prepared = self.prepare_memory_proposal(&input, &scope, harness)?;
        if prepared.should_write {
            vault(
                self.vault
                    .put_candidate_with_binding(&prepared.value, &prepared.binding),
            )?;
        }
        Ok(prepared.value)
    }

    pub(crate) fn preview_memory_proposal(
        &self,
        input: &ProposeMemoryInput,
        scope: &ScopeRef,
        harness: HarnessId,
    ) -> Result<MemoryCandidate, ClientError> {
        self.prepare_memory_proposal(input, scope, harness)
            .map(|prepared| prepared.value)
    }

    fn prepare_memory_proposal(
        &self,
        input: &ProposeMemoryInput,
        scope: &ScopeRef,
        harness: HarnessId,
    ) -> Result<PreparedLocalMutation<MemoryCandidate>, ClientError> {
        let id = CandidateId::new(input.operation_id.into_uuid()).map_err(|_| invalid_request())?;
        let binding = local_operation_binding(
            input.operation_id,
            LocalOperationKind::Proposal,
            id.to_string(),
            None,
            &(input, scope, harness),
        )?;
        match vault(self.vault.local_operation_replay(&binding))? {
            LocalOperationReplay::Snapshot(snapshot) => {
                let candidate = candidate_snapshot(&snapshot, id, input.operation_id)?;
                return Ok(PreparedLocalMutation {
                    value: candidate,
                    binding,
                    should_write: false,
                });
            }
            LocalOperationReplay::Legacy => {
                let candidate = vault(self.vault.candidate(&id))?.ok_or_else(internal)?;
                return Ok(PreparedLocalMutation {
                    value: candidate,
                    binding,
                    should_write: false,
                });
            }
            LocalOperationReplay::Fresh => {}
        }
        if vault(self.vault.candidate(&id))?.is_some() {
            return Err(operation_conflict());
        }
        let memory_id =
            MemoryId::new(input.operation_id.into_uuid()).map_err(|_| invalid_request())?;
        let clock = operation_clock(input.operation_id, self.device_id);
        let proposed_memory = MemoryRecord {
            id: memory_id,
            scope: scope.clone(),
            kind: input.kind,
            title: input.title.clone(),
            body_markdown: input.markdown.clone(),
            tags: input.tags.clone(),
            origin: MemoryOrigin::Inferred,
            provenance: Provenance {
                origin_device: self.device_id,
                harness: Some(harness),
                source: None,
                created_hlc: clock,
            },
            revision: input.operation_id,
            created_hlc: clock,
            updated_hlc: clock,
            archived: false,
        };
        let candidate = MemoryCandidate {
            id,
            proposed_memory,
            evidence_summary: input.evidence_summary.clone(),
            source_harness: harness,
            state: CandidateState::Pending,
        };
        candidate.validate().map_err(|_| invalid_request())?;
        Ok(PreparedLocalMutation {
            value: candidate,
            binding,
            should_write: true,
        })
    }

    pub fn update_memory(
        &mut self,
        params: MemoryUpdateParams,
    ) -> Result<MemoryRecord, ClientError> {
        let prepared = self.prepare_memory_update(&params)?;
        if prepared.should_write {
            vault(self.vault.put_local_memory_with_binding(
                &prepared.value,
                &memory_embedding(&prepared.value)?,
                &prepared.binding,
            ))?;
        }
        Ok(prepared.value)
    }

    pub(crate) fn preview_memory_update(
        &self,
        params: &MemoryUpdateParams,
    ) -> Result<MemoryRecord, ClientError> {
        self.prepare_memory_update(params)
            .map(|prepared| prepared.value)
    }

    fn prepare_memory_update(
        &self,
        params: &MemoryUpdateParams,
    ) -> Result<PreparedLocalMutation<MemoryRecord>, ClientError> {
        let binding = local_operation_binding(
            params.operation_id,
            LocalOperationKind::Update,
            params.memory_id.to_string(),
            Some(params.expected_revision),
            params,
        )?;
        match vault(self.vault.local_operation_replay(&binding))? {
            LocalOperationReplay::Snapshot(snapshot) => {
                let memory = memory_snapshot(&snapshot, params.memory_id, params.operation_id)?;
                return Ok(PreparedLocalMutation {
                    value: memory,
                    binding,
                    should_write: false,
                });
            }
            LocalOperationReplay::Legacy => {
                let memory = self.memory(params.memory_id)?.ok_or_else(internal)?;
                return Ok(PreparedLocalMutation {
                    value: memory,
                    binding,
                    should_write: false,
                });
            }
            LocalOperationReplay::Fresh => {}
        }
        let mut memory = self.memory(params.memory_id)?.ok_or_else(not_found)?;
        require_revision(memory.revision, params.expected_revision)?;
        if let Some(title) = &params.title {
            memory.title.clone_from(title);
        }
        if let Some(body) = &params.body_markdown {
            memory.body_markdown.clone_from(body);
        }
        if let Some(tags) = &params.tags {
            memory.tags.clone_from(tags);
        }
        memory.revision = params.operation_id;
        memory.updated_hlc = operation_clock(params.operation_id, self.device_id);
        memory.validate().map_err(|_| invalid_request())?;
        Ok(PreparedLocalMutation {
            value: memory,
            binding,
            should_write: true,
        })
    }

    pub fn archive_memory(
        &mut self,
        params: MemoryArchiveParams,
    ) -> Result<MemoryRecord, ClientError> {
        let prepared = self.prepare_memory_archive(&params)?;
        if prepared.should_write {
            vault(self.vault.put_local_memory_with_binding(
                &prepared.value,
                &memory_embedding(&prepared.value)?,
                &prepared.binding,
            ))?;
        }
        Ok(prepared.value)
    }

    pub(crate) fn preview_memory_archive(
        &self,
        params: &MemoryArchiveParams,
    ) -> Result<MemoryRecord, ClientError> {
        self.prepare_memory_archive(params)
            .map(|prepared| prepared.value)
    }

    fn prepare_memory_archive(
        &self,
        params: &MemoryArchiveParams,
    ) -> Result<PreparedLocalMutation<MemoryRecord>, ClientError> {
        let binding = local_operation_binding(
            params.operation_id,
            LocalOperationKind::Archive,
            params.memory_id.to_string(),
            Some(params.expected_revision),
            params,
        )?;
        match vault(self.vault.local_operation_replay(&binding))? {
            LocalOperationReplay::Snapshot(snapshot) => {
                let memory = memory_snapshot(&snapshot, params.memory_id, params.operation_id)?;
                if !memory.archived {
                    return Err(internal());
                }
                return Ok(PreparedLocalMutation {
                    value: memory,
                    binding,
                    should_write: false,
                });
            }
            LocalOperationReplay::Legacy => {
                let memory = self.memory(params.memory_id)?.ok_or_else(internal)?;
                return Ok(PreparedLocalMutation {
                    value: memory,
                    binding,
                    should_write: false,
                });
            }
            LocalOperationReplay::Fresh => {}
        }
        let mut memory = self.memory(params.memory_id)?.ok_or_else(not_found)?;
        require_revision(memory.revision, params.expected_revision)?;
        memory.archived = true;
        memory.revision = params.operation_id;
        memory.updated_hlc = operation_clock(params.operation_id, self.device_id);
        Ok(PreparedLocalMutation {
            value: memory,
            binding,
            should_write: true,
        })
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

    pub fn search_records(
        &self,
        query: &str,
        scope: &AllowedSearchScope,
        limit: usize,
    ) -> Result<Vec<ReadableRecord>, ClientError> {
        if query.trim().is_empty() {
            return Err(invalid_request());
        }
        let query_embedding = text_embedding(query)?;
        let hits = vault(self.vault.search(query, scope, &query_embedding, limit))?;
        let mut records = Vec::new();
        for hit in hits {
            let Ok(record_id) = hit.record_id().parse::<RecordId>() else {
                continue;
            };
            let Ok(memory_id) = MemoryId::new(record_id.into_uuid()) else {
                continue;
            };
            if let Some(memory) = vault(self.vault.memory(&memory_id))? {
                records.push(ReadableRecord::Memory(memory));
            } else if let Some(instruction) = vault(self.vault.instruction(&record_id))? {
                records.push(ReadableRecord::Instruction(instruction));
            }
        }
        Ok(records)
    }

    pub fn instructions(
        &self,
        scope: &AllowedSearchScope,
        limit: usize,
    ) -> Result<Vec<InstructionRecord>, ClientError> {
        vault(self.vault.instructions(scope, limit))
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
        let prepared = self.prepare_task_upsert(&params)?;
        if prepared.should_write {
            vault(
                self.vault
                    .put_task_with_binding(&prepared.value, &prepared.binding),
            )?;
        }
        Ok(prepared.value)
    }

    pub(crate) fn preview_task_upsert(
        &self,
        params: &TaskUpsertParams,
    ) -> Result<TaskRecord, ClientError> {
        self.prepare_task_upsert(params)
            .map(|prepared| prepared.value)
    }

    fn prepare_task_upsert(
        &self,
        params: &TaskUpsertParams,
    ) -> Result<PreparedLocalMutation<TaskRecord>, ClientError> {
        if params.task_id.is_some() != params.expected_revision.is_some() {
            return Err(invalid_request());
        }
        let id = match params.task_id {
            Some(id) => id,
            None => TaskId::new(params.operation_id.into_uuid()).map_err(|_| invalid_request())?,
        };
        let binding = local_operation_binding(
            params.operation_id,
            LocalOperationKind::TaskUpsert,
            id.to_string(),
            params.expected_revision,
            params,
        )?;
        match vault(self.vault.local_operation_replay(&binding))? {
            LocalOperationReplay::Snapshot(snapshot) => {
                let task = task_snapshot(&snapshot, id, params.operation_id)?;
                return Ok(PreparedLocalMutation {
                    value: task,
                    binding,
                    should_write: false,
                });
            }
            LocalOperationReplay::Legacy => {
                let task = vault(self.vault.task(&id))?.ok_or_else(internal)?;
                return Ok(PreparedLocalMutation {
                    value: task,
                    binding,
                    should_write: false,
                });
            }
            LocalOperationReplay::Fresh => {}
        }
        if let Some(mut task) = vault(self.vault.task(&id))? {
            let expected = params.expected_revision.ok_or_else(operation_conflict)?;
            require_revision(task.revision, expected)?;
            task.project_id = params.project_id;
            task.title.clone_from(&params.title);
            task.body_markdown.clone_from(&params.body_markdown);
            task.status = params.status;
            task.revision = params.operation_id;
            task.validate().map_err(|_| invalid_request())?;
            return Ok(PreparedLocalMutation {
                value: task,
                binding,
                should_write: true,
            });
        }
        if params.task_id.is_some() || params.expected_revision.is_some() {
            return Err(not_found());
        }
        let task = TaskRecord {
            id,
            project_id: params.project_id,
            title: params.title.clone(),
            body_markdown: params.body_markdown.clone(),
            status: params.status,
            evidence: Vec::new(),
            revision: params.operation_id,
        };
        task.validate().map_err(|_| invalid_request())?;
        Ok(PreparedLocalMutation {
            value: task,
            binding,
            should_write: true,
        })
    }

    pub fn transition_task(
        &mut self,
        params: TaskTransitionParams,
    ) -> Result<TaskRecord, ClientError> {
        let prepared = self.prepare_task_transition(&params)?;
        if prepared.should_write {
            vault(
                self.vault
                    .put_task_with_binding(&prepared.value, &prepared.binding),
            )?;
        }
        Ok(prepared.value)
    }

    fn prepare_task_transition(
        &self,
        params: &TaskTransitionParams,
    ) -> Result<PreparedLocalMutation<TaskRecord>, ClientError> {
        if params.status == TaskStatus::Done {
            return Err(invalid_request());
        }
        let binding = local_operation_binding(
            params.operation_id,
            LocalOperationKind::TaskTransition,
            params.task_id.to_string(),
            Some(params.expected_revision),
            params,
        )?;
        match vault(self.vault.local_operation_replay(&binding))? {
            LocalOperationReplay::Snapshot(snapshot) => {
                let task = task_snapshot(&snapshot, params.task_id, params.operation_id)?;
                if task.status != params.status {
                    return Err(internal());
                }
                return Ok(PreparedLocalMutation {
                    value: task,
                    binding,
                    should_write: false,
                });
            }
            LocalOperationReplay::Legacy => {
                let task = vault(self.vault.task(&params.task_id))?.ok_or_else(internal)?;
                return Ok(PreparedLocalMutation {
                    value: task,
                    binding,
                    should_write: false,
                });
            }
            LocalOperationReplay::Fresh => {}
        }
        let mut task = vault(self.vault.task(&params.task_id))?.ok_or_else(not_found)?;
        if task.revision == params.operation_id && task.status == params.status {
            return Ok(PreparedLocalMutation {
                value: task,
                binding,
                should_write: true,
            });
        }
        require_revision(task.revision, params.expected_revision)?;
        task.status = params.status;
        task.revision = params.operation_id;
        task.validate().map_err(|_| invalid_request())?;
        Ok(PreparedLocalMutation {
            value: task,
            binding,
            should_write: true,
        })
    }

    pub fn complete_task(&mut self, params: TaskCompleteParams) -> Result<TaskRecord, ClientError> {
        let recorded_hlc = operation_clock(params.operation_id, self.device_id);
        self.complete_task_with_recorded_hlc(params, recorded_hlc)
    }

    fn complete_task_with_recorded_hlc(
        &mut self,
        params: TaskCompleteParams,
        recorded_hlc: HybridLogicalClock,
    ) -> Result<TaskRecord, ClientError> {
        let prepared = self.prepare_task_completion(&params, recorded_hlc)?;
        if prepared.should_write {
            vault(
                self.vault
                    .put_task_with_binding(&prepared.value, &prepared.binding),
            )?;
        }
        Ok(prepared.value)
    }

    pub(crate) fn preview_task_completion(
        &self,
        params: &TaskCompleteParams,
    ) -> Result<TaskRecord, ClientError> {
        self.prepare_task_completion(params, operation_clock(params.operation_id, self.device_id))
            .map(|prepared| prepared.value)
    }

    fn prepare_task_completion(
        &self,
        params: &TaskCompleteParams,
        recorded_hlc: HybridLogicalClock,
    ) -> Result<PreparedLocalMutation<TaskRecord>, ClientError> {
        let binding = local_operation_binding(
            params.operation_id,
            LocalOperationKind::TaskComplete,
            params.task_id.to_string(),
            Some(params.expected_revision),
            params,
        )?;
        match vault(self.vault.local_operation_replay(&binding))? {
            LocalOperationReplay::Snapshot(snapshot) => {
                let task = task_snapshot(&snapshot, params.task_id, params.operation_id)?;
                if task.status != TaskStatus::Done {
                    return Err(internal());
                }
                return Ok(PreparedLocalMutation {
                    value: task,
                    binding,
                    should_write: false,
                });
            }
            LocalOperationReplay::Legacy => {
                let task = vault(self.vault.task(&params.task_id))?.ok_or_else(internal)?;
                return Ok(PreparedLocalMutation {
                    value: task,
                    binding,
                    should_write: false,
                });
            }
            LocalOperationReplay::Fresh => {}
        }
        let mut task = vault(self.vault.task(&params.task_id))?.ok_or_else(not_found)?;
        require_revision(task.revision, params.expected_revision)?;
        task.status = TaskStatus::Done;
        task.revision = params.operation_id;
        task.evidence = params
            .evidence
            .iter()
            .map(|evidence| TaskEvidence {
                summary: evidence.summary.clone(),
                evidence_kind: evidence.kind.clone(),
                reference: evidence.reference.clone(),
                recorded_hlc,
            })
            .collect();
        task.validate().map_err(|_| invalid_request())?;
        Ok(PreparedLocalMutation {
            value: task,
            binding,
            should_write: true,
        })
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

fn native_hook_operation_id(
    project_id: ProjectId,
    params: &NativeHookEventParams,
) -> Result<OperationId, ClientError> {
    let NativeHookEvent::TaskEvidence {
        session_id,
        task_id,
        evidence,
    } = &params.event
    else {
        return Err(invalid_request());
    };
    let canonical_evidence = serde_json::to_vec(evidence).map_err(|_| internal())?;
    let mut hasher = Sha256::new();
    hasher.update(b"context-relay.native-hook-task-evidence.v1");
    hasher.update(project_id.as_bytes());
    hash_identity_field(
        &mut hasher,
        match params.binding.harness {
            HarnessId::ClaudeCode => b"claude_code",
            HarnessId::Codex => b"codex",
            HarnessId::Hermes => b"hermes",
        },
    );
    hash_identity_field(&mut hasher, session_id.as_bytes());
    hasher.update(task_id.as_bytes());
    hash_identity_field(&mut hasher, &canonical_evidence);
    let digest: [u8; 32] = hasher.finalize().into();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    OperationId::from_str(&format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    ))
    .map_err(|_| internal())
}

fn hash_identity_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}

fn local_operation_binding<T: Serialize>(
    operation_id: OperationId,
    operation_kind: LocalOperationKind,
    target_id: String,
    expected_revision: Option<OperationId>,
    payload: &T,
) -> Result<LocalOperationBinding, ClientError> {
    let canonical_payload = serde_json::to_vec(payload).map_err(|_| internal())?;
    Ok(LocalOperationBinding {
        operation_id,
        operation_kind,
        target_id,
        expected_revision,
        canonical_payload,
    })
}

fn memory_snapshot(
    canonical_response: &[u8],
    expected_id: MemoryId,
    expected_revision: OperationId,
) -> Result<MemoryRecord, ClientError> {
    let memory: MemoryRecord =
        serde_json::from_slice(canonical_response).map_err(|_| internal())?;
    memory.validate().map_err(|_| internal())?;
    if memory.id != expected_id || memory.revision != expected_revision {
        return Err(internal());
    }
    Ok(memory)
}

fn candidate_snapshot(
    canonical_response: &[u8],
    expected_id: CandidateId,
    expected_revision: OperationId,
) -> Result<MemoryCandidate, ClientError> {
    let candidate: MemoryCandidate =
        serde_json::from_slice(canonical_response).map_err(|_| internal())?;
    candidate.validate().map_err(|_| internal())?;
    if candidate.id != expected_id
        || candidate.proposed_memory.id.to_string() != expected_id.to_string()
        || candidate.proposed_memory.revision != expected_revision
        || candidate.state != CandidateState::Pending
    {
        return Err(internal());
    }
    Ok(candidate)
}

fn task_snapshot(
    canonical_response: &[u8],
    expected_id: TaskId,
    expected_revision: OperationId,
) -> Result<TaskRecord, ClientError> {
    let task: TaskRecord = serde_json::from_slice(canonical_response).map_err(|_| internal())?;
    task.validate().map_err(|_| internal())?;
    if task.id != expected_id || task.revision != expected_revision {
        return Err(internal());
    }
    Ok(task)
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
    result.map_err(|error| match error {
        VaultError::OperationConflict => operation_conflict(),
        _ => internal(),
    })
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

fn operation_conflict() -> ClientError {
    conflict("The operation ID is already bound to a different mutation")
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
