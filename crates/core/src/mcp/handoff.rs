use std::{
    cmp::Ordering,
    collections::{BTreeSet, HashSet},
};

use context_relay_protocol::{
    ClientError, CreateHandoffInput, ErrorCode, HandoffPayload, MAX_EVIDENCE_ITEMS,
    MAX_MARKDOWN_BYTES, MemoryKind, MemoryRecord, ProjectIdentity, TaskRecord, TaskStatus,
};

use crate::{
    mcp::{binding::ResolvedMcpBinding, secret_text::reject_secret_like},
    search::AllowedSearchScope,
    vault::{Vault, VaultError},
};

pub fn build_handoff(
    vault_ref: &mut Vault,
    resolved: &ResolvedMcpBinding,
    input: &CreateHandoffInput,
) -> Result<HandoffPayload, ClientError> {
    input.validate().map_err(|_| invalid_request())?;
    let project_id = resolved.access.require_tasks(false)?;
    let project = resolved
        .active_project
        .clone()
        .filter(|project| project.project_id == project_id)
        .ok_or_else(scope_denied)?;

    let mut memories = Vec::with_capacity(input.memory_ids.len());
    for id in &input.memory_ids {
        let memory = vault(vault_ref.memory(id))?.ok_or_else(not_found)?;
        validate_memory_selection(resolved, &memory, false)?;
        memories.push(memory);
    }

    let mut decisions = Vec::with_capacity(input.decision_ids.len());
    let mut decision_ids = HashSet::with_capacity(MAX_EVIDENCE_ITEMS);
    for id in &input.decision_ids {
        let decision = vault(vault_ref.memory(id))?.ok_or_else(not_found)?;
        validate_memory_selection(resolved, &decision, true)?;
        decision_ids.insert(decision.id);
        decisions.push(decision);
    }
    for decision in vault(vault_ref.recent_project_decisions(project_id, MAX_EVIDENCE_ITEMS))? {
        if decisions.len() == MAX_EVIDENCE_ITEMS {
            break;
        }
        if decision_ids.insert(decision.id) {
            decisions.push(decision);
        }
    }

    let mut tasks = Vec::with_capacity(input.task_ids.len());
    let mut task_ids = HashSet::with_capacity(MAX_EVIDENCE_ITEMS);
    for id in &input.task_ids {
        let task = vault(vault_ref.task(id))?.ok_or_else(not_found)?;
        validate_task_selection(&task, project_id)?;
        task_ids.insert(task.id);
        tasks.push(task);
    }
    for task in vault(vault_ref.open_or_blocked_tasks(project_id, MAX_EVIDENCE_ITEMS))? {
        if tasks.len() == MAX_EVIDENCE_ITEMS {
            break;
        }
        if task_ids.insert(task.id) {
            tasks.push(task);
        }
    }

    let instruction_refs = relevant_instruction_refs(
        vault_ref,
        resolved,
        &input.summary,
        &memories,
        &decisions,
        &tasks,
    )?;
    reject_handoff_text(&project, &input.summary, &memories, &decisions, &tasks)?;
    let markdown = render_markdown(
        &project,
        &input.summary,
        &memories,
        &decisions,
        &tasks,
        &instruction_refs,
    )?;
    reject_secret_like(&markdown)?;
    let payload = HandoffPayload {
        project: Some(project),
        markdown,
        memories,
        decisions,
        tasks,
        instruction_refs,
    };
    payload.validate().map_err(|_| invalid_request())?;
    Ok(payload)
}

fn validate_memory_selection(
    resolved: &ResolvedMcpBinding,
    memory: &MemoryRecord,
    must_be_decision: bool,
) -> Result<(), ClientError> {
    if !resolved.access.allows_record_scope(&memory.scope, false) {
        return Err(scope_denied());
    }
    if memory.archived || (memory.kind == MemoryKind::Decision) != must_be_decision {
        return Err(invalid_request());
    }
    Ok(())
}

fn validate_task_selection(
    task: &TaskRecord,
    project_id: context_relay_protocol::ProjectId,
) -> Result<(), ClientError> {
    if task.project_id == project_id {
        Ok(())
    } else {
        Err(scope_denied())
    }
}

fn relevant_instruction_refs(
    vault_ref: &Vault,
    resolved: &ResolvedMcpBinding,
    summary: &str,
    memories: &[MemoryRecord],
    decisions: &[MemoryRecord],
    tasks: &[TaskRecord],
) -> Result<Vec<context_relay_protocol::RecordId>, ClientError> {
    let active_project = resolved
        .active_project
        .as_ref()
        .map(|project| project.project_id);
    let scope = AllowedSearchScope::resolve(None, &resolved.policy, active_project)
        .map_err(|_| scope_denied())?;
    let query_terms = handoff_terms(summary, memories, decisions, tasks);
    let ranked = vault(vault_ref.fold_instructions(
        &scope,
        Vec::with_capacity(MAX_EVIDENCE_ITEMS),
        |ranked, instruction| {
            let mut instruction_terms = text_terms(&instruction.title);
            instruction_terms.extend(text_terms(&instruction.body_markdown));
            let score = instruction_terms.intersection(&query_terms).count();
            if score > 0 {
                retain_ranked_instruction(ranked, (score, instruction.id));
            }
            Ok(())
        },
    ))?;
    Ok(ranked.into_iter().map(|(_, id)| id).collect())
}

fn retain_ranked_instruction(
    ranked: &mut Vec<(usize, context_relay_protocol::RecordId)>,
    candidate: (usize, context_relay_protocol::RecordId),
) {
    let position = ranked
        .binary_search_by(|existing| instruction_rank_order(existing, &candidate))
        .unwrap_or_else(|position| position);
    if position >= MAX_EVIDENCE_ITEMS {
        return;
    }
    if ranked.len() == MAX_EVIDENCE_ITEMS {
        ranked.pop();
    }
    ranked.insert(position, candidate);
}

fn instruction_rank_order(
    (left_score, left_id): &(usize, context_relay_protocol::RecordId),
    (right_score, right_id): &(usize, context_relay_protocol::RecordId),
) -> Ordering {
    right_score
        .cmp(left_score)
        .then_with(|| left_id.cmp(right_id))
}

fn handoff_terms(
    summary: &str,
    memories: &[MemoryRecord],
    decisions: &[MemoryRecord],
    tasks: &[TaskRecord],
) -> BTreeSet<String> {
    let mut terms = text_terms(summary);
    for memory in memories.iter().chain(decisions) {
        terms.extend(text_terms(&memory.title));
        terms.extend(text_terms(&memory.body_markdown));
    }
    for task in tasks {
        terms.extend(text_terms(&task.title));
        terms.extend(text_terms(&task.body_markdown));
        for evidence in &task.evidence {
            terms.extend(text_terms(&evidence.summary));
            terms.extend(text_terms(&evidence.evidence_kind));
            if let Some(reference) = &evidence.reference {
                terms.extend(text_terms(reference));
            }
        }
    }
    terms
}

fn text_terms(text: &str) -> BTreeSet<String> {
    text.split(|character: char| !character.is_alphanumeric())
        .filter(|term| term.len() >= 3)
        .map(str::to_lowercase)
        .filter(|term| {
            !matches!(
                term.as_str(),
                "and" | "for" | "the" | "this" | "that" | "with"
            )
        })
        .collect()
}

fn reject_handoff_text(
    project: &ProjectIdentity,
    summary: &str,
    memories: &[MemoryRecord],
    decisions: &[MemoryRecord],
    tasks: &[TaskRecord],
) -> Result<(), ClientError> {
    reject_secret_like(&project.name)?;
    if let Some(subdirectory) = &project.monorepo_subdirectory {
        reject_secret_like(subdirectory)?;
    }
    reject_secret_like(summary)?;
    for memory in memories.iter().chain(decisions) {
        reject_secret_like(&memory.title)?;
        reject_secret_like(&memory.body_markdown)?;
        for tag in &memory.tags {
            reject_secret_like(tag)?;
        }
    }
    for task in tasks {
        reject_secret_like(&task.title)?;
        reject_secret_like(&task.body_markdown)?;
        for evidence in &task.evidence {
            reject_secret_like(&evidence.summary)?;
            reject_secret_like(&evidence.evidence_kind)?;
            if let Some(reference) = &evidence.reference {
                reject_secret_like(reference)?;
            }
        }
    }
    Ok(())
}

fn render_markdown(
    project: &ProjectIdentity,
    summary: &str,
    memories: &[MemoryRecord],
    decisions: &[MemoryRecord],
    tasks: &[TaskRecord],
    instruction_refs: &[context_relay_protocol::RecordId],
) -> Result<String, ClientError> {
    let mut markdown = Markdown::default();
    markdown.push("# Handoff\n\n## Project\n\n")?;
    markdown.push(&format!("- Name: {}\n", project.name))?;
    markdown.push(&format!("- Project ID: {}\n", project.project_id))?;
    if let Some(repository_id) = project.github_repository_id {
        markdown.push(&format!("- GitHub repository ID: {repository_id}\n"))?;
    }
    if let Some(subdirectory) = &project.monorepo_subdirectory {
        markdown.push(&format!("- Monorepo subdirectory: {subdirectory}\n"))?;
    }
    markdown.push("\n## Summary\n\n")?;
    markdown.push(summary)?;
    markdown.push("\n\n## Selected memories\n\n")?;
    render_memories(&mut markdown, memories)?;
    markdown.push("\n## Recent decisions\n\n")?;
    render_memories(&mut markdown, decisions)?;
    markdown.push("\n## Open and blocked tasks\n\n")?;
    if tasks.is_empty() {
        markdown.push("_None._\n")?;
    } else {
        for task in tasks {
            markdown.push(&format!(
                "- {} (`{}`; {}): {}\n",
                task.title,
                task.id,
                task_status(task.status),
                task.body_markdown
            ))?;
        }
    }
    markdown.push("\n## Completion evidence\n\n")?;
    let mut evidence_count = 0;
    for task in tasks {
        for evidence in &task.evidence {
            evidence_count += 1;
            markdown.push(&format!(
                "- {}: {} ({})",
                task.title, evidence.summary, evidence.evidence_kind
            ))?;
            if let Some(reference) = &evidence.reference {
                markdown.push(&format!(" — {reference}"))?;
            }
            markdown.push("\n")?;
        }
    }
    if evidence_count == 0 {
        markdown.push("_None._\n")?;
    }
    markdown.push("\n## Relevant instructions\n\n")?;
    if instruction_refs.is_empty() {
        markdown.push("_None._\n")?;
    } else {
        for instruction_id in instruction_refs {
            markdown.push(&format!("- `{instruction_id}`\n"))?;
        }
    }
    Ok(markdown.value)
}

fn render_memories(markdown: &mut Markdown, memories: &[MemoryRecord]) -> Result<(), ClientError> {
    if memories.is_empty() {
        return markdown.push("_None._\n");
    }
    for memory in memories {
        markdown.push(&format!(
            "- {} (`{}`; {}): {}\n",
            memory.title,
            memory.id,
            memory_kind(memory.kind),
            memory.body_markdown
        ))?;
    }
    Ok(())
}

#[derive(Default)]
struct Markdown {
    value: String,
}

impl Markdown {
    fn push(&mut self, text: &str) -> Result<(), ClientError> {
        if self.value.len().saturating_add(text.len()) > MAX_MARKDOWN_BYTES {
            return Err(output_too_large());
        }
        self.value.push_str(text);
        Ok(())
    }
}

const fn memory_kind(kind: MemoryKind) -> &'static str {
    match kind {
        MemoryKind::Fact => "fact",
        MemoryKind::Decision => "decision",
        MemoryKind::Preference => "preference",
        MemoryKind::Pattern => "pattern",
        MemoryKind::Procedure => "procedure",
        MemoryKind::Note => "note",
    }
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

fn vault<T>(result: Result<T, VaultError>) -> Result<T, ClientError> {
    result.map_err(|_| ClientError {
        code: ErrorCode::Internal,
        message: "The local vault operation failed".to_owned(),
        field_path: None,
        retryable: false,
    })
}

fn invalid_request() -> ClientError {
    ClientError {
        code: ErrorCode::InvalidRequest,
        message: "The handoff request is invalid".to_owned(),
        field_path: None,
        retryable: false,
    }
}

fn not_found() -> ClientError {
    ClientError {
        code: ErrorCode::NotFound,
        message: "The requested handoff record was not found".to_owned(),
        field_path: None,
        retryable: false,
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

fn output_too_large() -> ClientError {
    ClientError {
        code: ErrorCode::FrameTooLarge,
        message: "The MCP tool output exceeds the safe frame budget".to_owned(),
        field_path: None,
        retryable: false,
    }
}
