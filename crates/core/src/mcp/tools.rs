use context_relay_protocol::{
    ArchiveMemoryInput, ArchiveMemoryOutput, CandidateId, ClientError, CompleteTaskInput,
    CompleteTaskOutput, CreateHandoffInput, CreateHandoffOutput, DeviceId, ErrorCode, GetInput,
    GetOutput, ListTasksInput, ListTasksOutput, MAX_IPC_FRAME_BYTES, McpCallParams,
    MemoryArchiveParams, MemoryCreateParams, MemoryId, MemoryUpdateParams, PROTOCOL_VERSION,
    ProposeMemoryInput, ProposeMemoryOutput, ProtocolVersionRange, ReadableRecord, RememberInput,
    RememberOutput, SearchInput, SearchOutput, StatusInput, StatusOutput, SyncState,
    TaskCompleteParams, TaskId, TaskUpsertParams, UpdateMemoryInput, UpdateMemoryOutput,
    UpsertTaskInput, UpsertTaskOutput, VaultState, validate_mcp_fixture,
};
use serde::Serialize;
use serde_json::Value;

use crate::{
    mcp::{
        binding::{ResolvedMcpBinding, resolve_binding},
        handoff::build_handoff,
    },
    search::AllowedSearchScope,
    service::OfflineWorkspace,
    vault::Vault,
};

// MCP success responses carry structured output and a JSON text copy. A quarter-frame budget
// leaves room for both encodings plus the JSON-RPC and local transport envelopes.
const MCP_TOOL_OUTPUT_MAX_BYTES: usize = MAX_IPC_FRAME_BYTES / 4;

pub struct McpWorkspace<'a> {
    vault: &'a mut Vault,
    device_id: DeviceId,
}

impl<'a> McpWorkspace<'a> {
    pub const fn new(vault: &'a mut Vault, device_id: DeviceId) -> Self {
        Self { vault, device_id }
    }

    pub fn call(&mut self, params: McpCallParams) -> Result<Value, ClientError> {
        let McpCallParams {
            binding,
            name,
            arguments,
        } = params;
        let resolved = resolve_binding(self.vault, &binding)?;
        let output = match name.as_str() {
            "context_relay_archive_memory" => {
                let input = parse(arguments)?;
                output(self.archive_memory(&resolved, input)?)?
            }
            "context_relay_update_memory" => {
                let input = parse(arguments)?;
                output(self.update_memory(&resolved, input)?)?
            }
            "context_relay_search" => {
                let input = parse(arguments)?;
                output(self.search(&resolved, input)?)?
            }
            "context_relay_get" => {
                let input = parse(arguments)?;
                output(self.get(&resolved, input)?)?
            }
            "context_relay_propose_memory" => {
                let input = parse(arguments)?;
                output(self.propose_memory(&resolved, input)?)?
            }
            "context_relay_remember" => {
                let input = parse(arguments)?;
                output(self.remember(&resolved, input)?)?
            }
            "context_relay_status" => {
                let input = parse(arguments)?;
                output(self.status(&resolved, input)?)?
            }
            _ => self.call_task_or_handoff(&resolved, &name, arguments)?,
        };
        validate_mcp_fixture(&name, false, &output)
            .map_err(|_| internal_error("The MCP output was invalid"))?;
        ensure_output_fits(&output)?;
        Ok(output)
    }

    fn call_task_or_handoff(
        &mut self,
        resolved: &ResolvedMcpBinding,
        name: &str,
        arguments: Value,
    ) -> Result<Value, ClientError> {
        match name {
            "context_relay_list_tasks" => {
                let input = parse(arguments)?;
                output(self.list_tasks(resolved, input)?)
            }
            "context_relay_upsert_task" => {
                let input = parse(arguments)?;
                output(self.upsert_task(resolved, input)?)
            }
            "context_relay_complete_task" => {
                let input = parse(arguments)?;
                output(self.complete_task(resolved, input)?)
            }
            "context_relay_create_handoff" => {
                let input = parse(arguments)?;
                output(self.create_handoff(resolved, input)?)
            }
            _ => Err(invalid_tool_name()),
        }
    }

    fn list_tasks(
        &mut self,
        resolved: &ResolvedMcpBinding,
        input: ListTasksInput,
    ) -> Result<ListTasksOutput, ClientError> {
        let project_id = resolved.access.require_tasks(false)?;
        let tasks = OfflineWorkspace::new(self.vault, self.device_id).tasks(project_id)?;
        let output = ListTasksOutput {
            tasks: tasks
                .into_iter()
                .filter(|task| input.status.is_none_or(|status| task.status == status))
                .collect(),
        };
        ensure_output_fits(&output)?;
        Ok(output)
    }

    fn upsert_task(
        &mut self,
        resolved: &ResolvedMcpBinding,
        input: UpsertTaskInput,
    ) -> Result<UpsertTaskOutput, ClientError> {
        let project_id = resolved.access.require_tasks(true)?;
        if input.task_id.is_some() != input.expected_revision.is_some()
            || input.status == context_relay_protocol::TaskStatus::Done
        {
            return Err(invalid_arguments());
        }
        let task_id = input.task_id.unwrap_or(
            TaskId::new(input.operation_id.into_uuid()).map_err(|_| invalid_arguments())?,
        );
        if let Some(existing) = self
            .vault
            .task(&task_id)
            .map_err(|_| internal_error("The local vault operation failed"))?
            && existing.project_id != project_id
        {
            return Err(scope_denied());
        }
        let params = TaskUpsertParams {
            operation_id: input.operation_id,
            task_id: input.task_id,
            project_id,
            title: input.title,
            body_markdown: input.body_markdown,
            status: input.status,
            expected_revision: input.expected_revision,
        };
        let mut workspace = OfflineWorkspace::new(self.vault, self.device_id);
        let prospective = workspace.preview_task_upsert(&params)?;
        if prospective.project_id != project_id {
            return Err(scope_denied());
        }
        ensure_output_fits(&UpsertTaskOutput { task: prospective })?;
        let task = workspace.upsert_task(params)?;
        if task.project_id != project_id {
            return Err(scope_denied());
        }
        Ok(UpsertTaskOutput { task })
    }

    fn complete_task(
        &mut self,
        resolved: &ResolvedMcpBinding,
        input: CompleteTaskInput,
    ) -> Result<CompleteTaskOutput, ClientError> {
        input.validate().map_err(|_| invalid_arguments())?;
        let project_id = resolved.access.require_tasks(true)?;
        let existing = self
            .vault
            .task(&input.task_id)
            .map_err(|_| internal_error("The local vault operation failed"))?
            .ok_or_else(record_not_found)?;
        if existing.project_id != project_id {
            return Err(scope_denied());
        }
        let params = TaskCompleteParams {
            operation_id: input.operation_id,
            task_id: input.task_id,
            expected_revision: input.expected_revision,
            evidence: input.evidence,
        };
        let mut workspace = OfflineWorkspace::new(self.vault, self.device_id);
        let prospective = workspace.preview_task_completion(&params)?;
        if prospective.project_id != project_id {
            return Err(scope_denied());
        }
        ensure_output_fits(&CompleteTaskOutput { task: prospective })?;
        let task = workspace.complete_task(params)?;
        if task.project_id != project_id {
            return Err(scope_denied());
        }
        Ok(CompleteTaskOutput { task })
    }

    fn create_handoff(
        &mut self,
        resolved: &ResolvedMcpBinding,
        input: CreateHandoffInput,
    ) -> Result<CreateHandoffOutput, ClientError> {
        let handoff_id = input.operation_id;
        let payload = build_handoff(self.vault, resolved, &input)?;
        let output = CreateHandoffOutput {
            handoff_id,
            payload,
        };
        ensure_output_fits(&output)?;
        Ok(output)
    }

    fn archive_memory(
        &mut self,
        resolved: &ResolvedMcpBinding,
        input: ArchiveMemoryInput,
    ) -> Result<ArchiveMemoryOutput, ClientError> {
        let mut workspace = OfflineWorkspace::new(self.vault, self.device_id);
        let existing = workspace
            .memory(input.memory_id)?
            .ok_or_else(record_not_found)?;
        require_record_access(resolved, &existing.scope, true)?;
        let params = MemoryArchiveParams {
            operation_id: input.operation_id,
            memory_id: input.memory_id,
            expected_revision: input.expected_revision,
        };
        let prospective = workspace.preview_memory_archive(&params)?;
        ensure_output_fits(&ArchiveMemoryOutput {
            memory: prospective,
        })?;
        let memory = workspace.archive_memory(params)?;
        Ok(ArchiveMemoryOutput { memory })
    }

    fn update_memory(
        &mut self,
        resolved: &ResolvedMcpBinding,
        input: UpdateMemoryInput,
    ) -> Result<UpdateMemoryOutput, ClientError> {
        let mut workspace = OfflineWorkspace::new(self.vault, self.device_id);
        let existing = workspace
            .memory(input.memory_id)?
            .ok_or_else(record_not_found)?;
        require_record_access(resolved, &existing.scope, true)?;
        let params = MemoryUpdateParams {
            operation_id: input.operation_id,
            memory_id: input.memory_id,
            expected_revision: input.expected_revision,
            title: None,
            body_markdown: Some(input.markdown),
            tags: None,
        };
        let prospective = workspace.preview_memory_update(&params)?;
        ensure_output_fits(&UpdateMemoryOutput {
            memory: prospective,
        })?;
        let memory = workspace.update_memory(params)?;
        Ok(UpdateMemoryOutput { memory })
    }

    fn search(
        &mut self,
        resolved: &ResolvedMcpBinding,
        input: SearchInput,
    ) -> Result<SearchOutput, ClientError> {
        let active_project = resolved
            .active_project
            .as_ref()
            .map(|project| project.project_id);
        let scope = AllowedSearchScope::resolve(input.scope, &resolved.policy, active_project)
            .map_err(|_| scope_denied())?;
        let records = OfflineWorkspace::new(self.vault, self.device_id).search_records(
            &input.query,
            &scope,
            usize::from(input.limit.unwrap_or(20)),
        )?;
        let mut output = SearchOutput {
            memories: Vec::new(),
            instructions: Vec::new(),
        };
        let mut serialized_bytes = encoded_len(&output)?;
        for record in records {
            let (scope, record_bytes, needs_comma) = match &record {
                ReadableRecord::Memory(memory) => (
                    &memory.scope,
                    encoded_len(memory)?,
                    !output.memories.is_empty(),
                ),
                ReadableRecord::Instruction(instruction) => (
                    &instruction.scope,
                    encoded_len(instruction)?,
                    !output.instructions.is_empty(),
                ),
            };
            require_record_access(resolved, scope, false)?;
            let Some(next_bytes) = serialized_bytes
                .checked_add(record_bytes)
                .and_then(|bytes| bytes.checked_add(usize::from(needs_comma)))
            else {
                break;
            };
            if next_bytes > MCP_TOOL_OUTPUT_MAX_BYTES {
                break;
            }
            match record {
                ReadableRecord::Memory(memory) => output.memories.push(memory),
                ReadableRecord::Instruction(instruction) => output.instructions.push(instruction),
            }
            serialized_bytes = next_bytes;
        }
        Ok(output)
    }

    fn get(
        &mut self,
        resolved: &ResolvedMcpBinding,
        input: GetInput,
    ) -> Result<GetOutput, ClientError> {
        let memory_id =
            MemoryId::new(input.record_id.into_uuid()).map_err(|_| invalid_arguments())?;
        let workspace = OfflineWorkspace::new(self.vault, self.device_id);
        if let Some(memory) = workspace.memory(memory_id)? {
            require_record_access(resolved, &memory.scope, false)?;
            return Ok(GetOutput {
                record: Some(ReadableRecord::Memory(memory)),
            });
        }
        if let Some(instruction) = workspace.instruction(input.record_id)? {
            require_record_access(resolved, &instruction.scope, false)?;
            return Ok(GetOutput {
                record: Some(ReadableRecord::Instruction(instruction)),
            });
        }
        Ok(GetOutput { record: None })
    }

    fn propose_memory(
        &mut self,
        resolved: &ResolvedMcpBinding,
        input: ProposeMemoryInput,
    ) -> Result<ProposeMemoryOutput, ClientError> {
        let scope = resolved.access.write_scope(input.scope)?;
        let mut workspace = OfflineWorkspace::new(self.vault, self.device_id);
        let candidate_id =
            CandidateId::new(input.operation_id.into_uuid()).map_err(|_| invalid_arguments())?;
        if let Some(existing) = workspace.candidate(candidate_id)? {
            require_record_access(resolved, &existing.proposed_memory.scope, true)?;
        }
        let prospective = workspace.preview_memory_proposal(&input, &scope, resolved.harness)?;
        require_record_access(resolved, &prospective.proposed_memory.scope, true)?;
        ensure_output_fits(&ProposeMemoryOutput {
            candidate: prospective,
        })?;
        let candidate = workspace.propose_memory(input, scope, resolved.harness)?;
        require_record_access(resolved, &candidate.proposed_memory.scope, true)?;
        Ok(ProposeMemoryOutput { candidate })
    }

    fn remember(
        &mut self,
        resolved: &ResolvedMcpBinding,
        input: RememberInput,
    ) -> Result<RememberOutput, ClientError> {
        let scope = resolved.access.write_scope(input.scope)?;
        let params = MemoryCreateParams {
            operation_id: input.operation_id,
            scope,
            kind: input.kind,
            title: input.title,
            body_markdown: input.markdown,
            tags: input.tags,
        };
        let mut workspace = OfflineWorkspace::new(self.vault, self.device_id);
        let memory_id =
            MemoryId::new(params.operation_id.into_uuid()).map_err(|_| invalid_arguments())?;
        if let Some(existing) = workspace.memory(memory_id)? {
            require_record_access(resolved, &existing.scope, true)?;
        }
        let prospective = workspace.preview_memory_create(&params)?;
        require_record_access(resolved, &prospective.scope, true)?;
        ensure_output_fits(&RememberOutput {
            memory: prospective,
        })?;
        let memory = workspace.create_memory(params)?;
        require_record_access(resolved, &memory.scope, true)?;
        Ok(RememberOutput { memory })
    }

    fn status(
        &self,
        resolved: &ResolvedMcpBinding,
        _input: StatusInput,
    ) -> Result<StatusOutput, ClientError> {
        Ok(StatusOutput {
            protocol: ProtocolVersionRange {
                min: PROTOCOL_VERSION,
                max: PROTOCOL_VERSION,
            },
            vault: VaultState::Unlocked,
            resolved_project: resolved
                .active_project
                .as_ref()
                .map(|project| project.project_id),
            sync: SyncState::Offline,
            access: resolved.policy.clone(),
        })
    }
}

fn parse<T: serde::de::DeserializeOwned>(arguments: Value) -> Result<T, ClientError> {
    serde_json::from_value(arguments).map_err(|_| invalid_arguments())
}

fn output<T: Serialize>(value: T) -> Result<Value, ClientError> {
    serde_json::to_value(value).map_err(|_| internal_error("The MCP output could not be encoded"))
}

fn encoded_len<T: Serialize>(value: &T) -> Result<usize, ClientError> {
    serde_json::to_vec(value)
        .map(|encoded| encoded.len())
        .map_err(|_| internal_error("The MCP output could not be encoded"))
}

fn ensure_output_fits<T: Serialize>(value: &T) -> Result<(), ClientError> {
    if encoded_len(value)? > MCP_TOOL_OUTPUT_MAX_BYTES {
        Err(output_too_large())
    } else {
        Ok(())
    }
}

fn invalid_tool_name() -> ClientError {
    ClientError {
        code: ErrorCode::InvalidRequest,
        message: "The MCP tool name is invalid".to_owned(),
        field_path: None,
        retryable: false,
    }
}

fn invalid_arguments() -> ClientError {
    ClientError {
        code: ErrorCode::InvalidRequest,
        message: "The MCP tool arguments are invalid".to_owned(),
        field_path: None,
        retryable: false,
    }
}

fn require_record_access(
    resolved: &ResolvedMcpBinding,
    scope: &context_relay_protocol::ScopeRef,
    write: bool,
) -> Result<(), ClientError> {
    if resolved.access.allows_record_scope(scope, write) {
        Ok(())
    } else {
        Err(scope_denied())
    }
}

fn scope_denied() -> ClientError {
    ClientError {
        code: ErrorCode::ScopeDenied,
        message: "The calling harness is not allowed to access this scope".to_owned(),
        field_path: None,
        retryable: false,
    }
}

fn record_not_found() -> ClientError {
    ClientError {
        code: ErrorCode::NotFound,
        message: "The requested record was not found".to_owned(),
        field_path: None,
        retryable: false,
    }
}

fn output_too_large() -> ClientError {
    ClientError {
        code: ErrorCode::FrameTooLarge,
        message: "The MCP tool output exceeds the safe frame budget".to_owned(),
        field_path: None,
        retryable: false,
    }
}

fn internal_error(message: &str) -> ClientError {
    ClientError {
        code: ErrorCode::Internal,
        message: message.to_owned(),
        field_path: None,
        retryable: false,
    }
}
