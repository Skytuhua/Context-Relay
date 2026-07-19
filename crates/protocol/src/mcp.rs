use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use ts_rs::TS;

use crate::{
    HarnessAccessPolicy, InstructionRecord, MAX_EVIDENCE_BYTES, MAX_MARKDOWN_BYTES,
    MAX_TITLE_BYTES, MemoryCandidate, MemoryId, MemoryKind, MemoryRecord, OperationId, ProjectId,
    ProjectIdentity, ProtocolVersionRange, RecordId, TaskId, TaskRecord, TaskStatus,
    ValidationError, required_text,
};

pub const MCP_TOOL_NAMES: [&str; 11] = [
    "context_relay_search",
    "context_relay_get",
    "context_relay_remember",
    "context_relay_propose_memory",
    "context_relay_update_memory",
    "context_relay_archive_memory",
    "context_relay_list_tasks",
    "context_relay_upsert_task",
    "context_relay_complete_task",
    "context_relay_create_handoff",
    "context_relay_status",
];

macro_rules! dto {
    ($name:ident { $($field:ident : $ty:ty),* $(,)? }) => {
        #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        #[ts(rename_all = "camelCase")]
        pub struct $name { $(pub $field: $ty),* }
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(tag = "scope", rename_all = "snake_case", deny_unknown_fields)]
#[ts(tag = "scope", rename_all = "snake_case")]
pub enum McpScopeSelector {
    Global,
    ActiveProject,
}

dto!(SearchInput { query: String, scope: Option<McpScopeSelector>, limit: Option<u16> });
dto!(SearchOutput { memories: Vec<MemoryRecord>, instructions: Vec<InstructionRecord> });
dto!(GetInput {
    record_id: RecordId
});

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(
    tag = "kind",
    content = "record",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[ts(tag = "kind", content = "record", rename_all = "snake_case")]
pub enum ReadableRecord {
    Memory(MemoryRecord),
    Instruction(InstructionRecord),
}

dto!(GetOutput { record: Option<ReadableRecord> });
dto!(RememberInput { operation_id: OperationId, kind: MemoryKind, title: String, markdown: String, tags: Vec<String>, scope: McpScopeSelector });
dto!(RememberOutput {
    memory: MemoryRecord
});
dto!(ProposeMemoryInput { operation_id: OperationId, kind: MemoryKind, title: String, markdown: String, tags: Vec<String>, evidence_summary: String, scope: McpScopeSelector });
dto!(ProposeMemoryOutput {
    candidate: MemoryCandidate
});
dto!(UpdateMemoryInput {
    operation_id: OperationId,
    memory_id: MemoryId,
    expected_revision: OperationId,
    markdown: String
});
dto!(UpdateMemoryOutput {
    memory: MemoryRecord
});
dto!(ArchiveMemoryInput {
    operation_id: OperationId,
    memory_id: MemoryId,
    expected_revision: OperationId
});
dto!(ArchiveMemoryOutput {
    memory: MemoryRecord
});
dto!(ListTasksInput { status: Option<TaskStatus> });
dto!(ListTasksOutput { tasks: Vec<TaskRecord> });
dto!(UpsertTaskInput { operation_id: OperationId, task_id: Option<TaskId>, title: String, body_markdown: String, status: TaskStatus, expected_revision: Option<OperationId> });
dto!(UpsertTaskOutput { task: TaskRecord });
dto!(CompletionEvidenceInput { summary: String, kind: String, reference: Option<String> });
dto!(CompleteTaskInput { operation_id: OperationId, task_id: TaskId, expected_revision: OperationId, evidence: Vec<CompletionEvidenceInput> });
dto!(CompleteTaskOutput { task: TaskRecord });
dto!(CreateHandoffInput { operation_id: OperationId, memory_ids: Vec<MemoryId>, decision_ids: Vec<MemoryId>, task_ids: Vec<TaskId>, summary: String });
dto!(HandoffPayload { project: Option<ProjectIdentity>, markdown: String, memories: Vec<MemoryRecord>, decisions: Vec<MemoryRecord>, tasks: Vec<TaskRecord>, instruction_refs: Vec<RecordId> });
dto!(CreateHandoffOutput {
    handoff_id: OperationId,
    payload: HandoffPayload
});
dto!(StatusInput {});

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum VaultState {
    Locked,
    Unlocked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum SyncState {
    Idle,
    Syncing,
    Error,
}

dto!(StatusOutput { protocol: ProtocolVersionRange, vault: VaultState, resolved_project: Option<ProjectId>, sync: SyncState, access: HarnessAccessPolicy });

impl HandoffPayload {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.memories.len() > crate::MAX_EVIDENCE_ITEMS
            || self.decisions.len() > crate::MAX_EVIDENCE_ITEMS
            || self.tasks.len() > crate::MAX_EVIDENCE_ITEMS
        {
            return Err(ValidationError::TooLarge {
                field: "payload records",
                limit: crate::MAX_EVIDENCE_ITEMS,
            });
        }
        required_text(&self.markdown, "payload.markdown", MAX_MARKDOWN_BYTES)?;
        if let Some(project) = &self.project {
            project.validate()?;
        }
        if self
            .decisions
            .iter()
            .any(|item| item.kind != MemoryKind::Decision)
        {
            return Err(ValidationError::Invalid("payload.decisions"));
        }
        if self.instruction_refs.len() > crate::MAX_EVIDENCE_ITEMS
            || self
                .instruction_refs
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.instruction_refs.len()
        {
            return Err(ValidationError::Invalid("payload.instructionRefs"));
        }
        for memory in self.memories.iter().chain(&self.decisions) {
            memory.validate()?;
        }
        for task in &self.tasks {
            task.validate()?;
        }
        Ok(())
    }
}

impl StatusOutput {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.protocol.min.major != crate::PROTOCOL_MAJOR
            || self.protocol.max.major != crate::PROTOCOL_MAJOR
            || self.protocol.min.minor > self.protocol.max.minor
        {
            return Err(ValidationError::Invalid("status.protocol"));
        }
        Ok(())
    }
}

impl CompleteTaskInput {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.evidence.is_empty() {
            return Err(ValidationError::EmptyRequired("evidence"));
        }
        if self.evidence.len() > crate::MAX_EVIDENCE_ITEMS {
            return Err(ValidationError::TooLarge {
                field: "evidence",
                limit: crate::MAX_EVIDENCE_ITEMS,
            });
        }
        for item in &self.evidence {
            required_text(&item.summary, "evidence.summary", MAX_EVIDENCE_BYTES)?;
            required_text(&item.kind, "evidence.kind", 128)?;
            if item
                .reference
                .as_ref()
                .is_some_and(|value| value.len() > MAX_EVIDENCE_BYTES)
            {
                return Err(ValidationError::TooLarge {
                    field: "evidence.reference",
                    limit: MAX_EVIDENCE_BYTES,
                });
            }
        }
        Ok(())
    }
}

impl CreateHandoffInput {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.memory_ids.len() + self.decision_ids.len() + self.task_ids.len()
            > crate::MAX_EVIDENCE_ITEMS
        {
            return Err(ValidationError::TooLarge {
                field: "handoff selection",
                limit: crate::MAX_EVIDENCE_ITEMS,
            });
        }
        if self
            .memory_ids
            .iter()
            .chain(&self.decision_ids)
            .map(ToString::to_string)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != self.memory_ids.len() + self.decision_ids.len()
            || self
                .task_ids
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.task_ids.len()
        {
            return Err(ValidationError::Invalid("handoff duplicates"));
        }
        if self.memory_ids.is_empty() && self.decision_ids.is_empty() && self.task_ids.is_empty() {
            return Err(ValidationError::EmptyRequired("handoff selection"));
        }
        required_text(&self.summary, "summary", MAX_MARKDOWN_BYTES)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct McpToolSchema {
    pub input: Value,
    pub output: Value,
}

pub fn mcp_schema(name: &str) -> Option<McpToolSchema> {
    let operation = || ("operationId", uuid());
    let (required, properties, output_required, output_properties) = match name {
        "context_relay_search" => (
            vec!["query"],
            json!({"query":text(1,MAX_MARKDOWN_BYTES),"scope":{"oneOf":[{"type":"null"},mcp_scope_selector()]},"limit":{"oneOf":[{"type":"null"},{"type":"integer","minimum":1,"maximum":100}]}}),
            vec!["memories", "instructions"],
            json!({"memories":{"type":"array","maxItems":crate::MAX_BATCH_OPERATIONS,"items":memory()},"instructions":{"type":"array","maxItems":crate::MAX_BATCH_OPERATIONS,"items":instruction()}}),
        ),
        "context_relay_get" => (
            vec!["recordId"],
            json!({"recordId":uuid()}),
            vec!["record"],
            json!({"record":{"oneOf":[{"type":"null"},readable_record()]}}),
        ),
        "context_relay_remember" => {
            let op = operation();
            (
                vec![op.0, "kind", "title", "markdown", "tags", "scope"],
                json!({op.0:op.1,"kind":{"enum":["fact","decision","preference","pattern","procedure","note"]},"title":text(1,MAX_TITLE_BYTES),"markdown":text(1,MAX_MARKDOWN_BYTES),"tags":{"type":"array","maxItems":crate::MAX_TAGS,"uniqueItems":true,"items":text(1,crate::MAX_TAG_BYTES)},"scope":mcp_scope_selector()}),
                vec!["memory"],
                json!({"memory":memory()}),
            )
        }
        "context_relay_propose_memory" => {
            let op = operation();
            (
                vec![
                    op.0,
                    "kind",
                    "title",
                    "markdown",
                    "tags",
                    "evidenceSummary",
                    "scope",
                ],
                json!({op.0:op.1,"kind":{"enum":["fact","decision","preference","pattern","procedure","note"]},"title":text(1,MAX_TITLE_BYTES),"markdown":text(1,MAX_MARKDOWN_BYTES),"tags":{"type":"array","maxItems":crate::MAX_TAGS,"uniqueItems":true,"items":text(1,crate::MAX_TAG_BYTES)},"evidenceSummary":text(1,MAX_EVIDENCE_BYTES),"scope":mcp_scope_selector()}),
                vec!["candidate"],
                json!({"candidate":candidate()}),
            )
        }
        "context_relay_update_memory" => {
            let op = operation();
            (
                vec![op.0, "memoryId", "expectedRevision", "markdown"],
                json!({op.0:op.1,"memoryId":uuid(),"expectedRevision":uuid(),"markdown":text(1,MAX_MARKDOWN_BYTES)}),
                vec!["memory"],
                json!({"memory":memory()}),
            )
        }
        "context_relay_archive_memory" => {
            let op = operation();
            (
                vec![op.0, "memoryId", "expectedRevision"],
                json!({op.0:op.1,"memoryId":uuid(),"expectedRevision":uuid()}),
                vec!["memory"],
                json!({"memory":memory()}),
            )
        }
        "context_relay_list_tasks" => (
            vec![],
            json!({"status":{"oneOf":[{"type":"null"},task_status()]}}),
            vec!["tasks"],
            json!({"tasks":{"type":"array","maxItems":crate::MAX_BATCH_OPERATIONS,"items":task()}}),
        ),
        "context_relay_upsert_task" => {
            let op = operation();
            (
                vec![op.0, "title", "bodyMarkdown", "status"],
                json!({op.0:op.1,"taskId":{"oneOf":[{"type":"null"},uuid()]},"title":text(1,MAX_TITLE_BYTES),"bodyMarkdown":text(1,MAX_MARKDOWN_BYTES),"status":{"enum":["open","in_progress","blocked","canceled"]},"expectedRevision":{"oneOf":[{"type":"null"},uuid()]}}),
                vec!["task"],
                json!({"task":task()}),
            )
        }
        "context_relay_complete_task" => {
            let op = operation();
            (
                vec![op.0, "taskId", "expectedRevision", "evidence"],
                json!({op.0:op.1,"taskId":uuid(),"expectedRevision":uuid(),"evidence":{"type":"array","minItems":1,"maxItems":crate::MAX_EVIDENCE_ITEMS,"items":evidence()}}),
                vec!["task"],
                json!({"task":task()}),
            )
        }
        "context_relay_create_handoff" => {
            let op = operation();
            (
                vec![op.0, "memoryIds", "decisionIds", "taskIds", "summary"],
                json!({op.0:op.1,"memoryIds":{"type":"array","maxItems":crate::MAX_EVIDENCE_ITEMS,"uniqueItems":true,"items":uuid()},"decisionIds":{"type":"array","maxItems":crate::MAX_EVIDENCE_ITEMS,"uniqueItems":true,"items":uuid()},"taskIds":{"type":"array","maxItems":crate::MAX_EVIDENCE_ITEMS,"uniqueItems":true,"items":uuid()},"summary":text(1,MAX_MARKDOWN_BYTES)}),
                vec!["handoffId", "payload"],
                json!({"handoffId":uuid(),"payload":handoff_payload()}),
            )
        }
        "context_relay_status" => (
            vec![],
            json!({}),
            vec!["protocol", "vault", "resolvedProject", "sync", "access"],
            json!({"protocol":protocol_range(),"vault":{"enum":["locked","unlocked"]},"resolvedProject":{"oneOf":[{"type":"null"},uuid()]},"sync":{"enum":["idle","syncing","error"]},"access":access_policy()}),
        ),
        _ => return None,
    };
    let mut input = strict(required, properties);
    if name == "context_relay_upsert_task" {
        input.as_object_mut().expect("schema object").insert("anyOf".into(),json!([{"not":{"anyOf":[{"properties":{"taskId":{}},"required":["taskId"]},{"properties":{"expectedRevision":{}},"required":["expectedRevision"]}]}},{"properties":{"taskId":{"type":"null"},"expectedRevision":{"type":"null"}},"required":["taskId","expectedRevision"]},{"properties":{"taskId":uuid(),"expectedRevision":uuid()},"required":["taskId","expectedRevision"]}]));
    }
    if name == "context_relay_create_handoff" {
        input.as_object_mut().expect("schema object").insert(
            "anyOf".into(),
            json!([
                {"properties":{"memoryIds":{"type":"array","minItems":1}},"required":["memoryIds"]},
                {"properties":{"decisionIds":{"type":"array","minItems":1}},"required":["decisionIds"]},
                {"properties":{"taskIds":{"type":"array","minItems":1}},"required":["taskIds"]}
            ]),
        );
    }
    Some(McpToolSchema {
        input,
        output: strict(output_required, output_properties),
    })
}

pub fn validate_mcp_fixture(name: &str, input: bool, value: &Value) -> Result<(), ValidationError> {
    if input {
        validate_input(name, value)
    } else {
        validate_output(name, value)
    }
}

fn validate_tags(tags: &[String]) -> Result<(), ValidationError> {
    if tags.len() > crate::MAX_TAGS {
        return Err(ValidationError::TooLarge {
            field: "tags",
            limit: crate::MAX_TAGS,
        });
    }
    let mut unique = std::collections::BTreeSet::new();
    for tag in tags {
        required_text(tag, "tags", crate::MAX_TAG_BYTES)?;
        if !unique.insert(tag) {
            return Err(ValidationError::Invalid("duplicate tag"));
        }
    }
    Ok(())
}

fn validate_input(name: &str, value: &Value) -> Result<(), ValidationError> {
    let invalid = || ValidationError::Invalid("MCP input");
    match name {
        "context_relay_search" => {
            let dto: SearchInput = serde_json::from_value(value.clone()).map_err(|_| invalid())?;
            required_text(&dto.query, "query", MAX_MARKDOWN_BYTES)?;
            if dto.limit.is_some_and(|limit| !(1..=100).contains(&limit)) {
                return Err(invalid());
            }
            Ok(())
        }
        "context_relay_get" => parse::<GetInput>(value, invalid),
        "context_relay_remember" => {
            let dto: RememberInput = parse_value(value, invalid)?;
            required_text(&dto.title, "title", MAX_TITLE_BYTES)?;
            required_text(&dto.markdown, "markdown", MAX_MARKDOWN_BYTES)?;
            validate_tags(&dto.tags)
        }
        "context_relay_propose_memory" => {
            let dto: ProposeMemoryInput = parse_value(value, invalid)?;
            required_text(&dto.title, "title", MAX_TITLE_BYTES)?;
            required_text(&dto.markdown, "markdown", MAX_MARKDOWN_BYTES)?;
            required_text(&dto.evidence_summary, "evidenceSummary", MAX_EVIDENCE_BYTES)?;
            validate_tags(&dto.tags)
        }
        "context_relay_update_memory" => {
            let dto: UpdateMemoryInput = parse_value(value, invalid)?;
            required_text(&dto.markdown, "markdown", MAX_MARKDOWN_BYTES)
        }
        "context_relay_archive_memory" => parse::<ArchiveMemoryInput>(value, invalid),
        "context_relay_list_tasks" => parse::<ListTasksInput>(value, invalid),
        "context_relay_upsert_task" => {
            let dto: UpsertTaskInput = parse_value(value, invalid)?;
            required_text(&dto.title, "title", MAX_TITLE_BYTES)?;
            required_text(&dto.body_markdown, "bodyMarkdown", MAX_MARKDOWN_BYTES)?;
            if dto.status == TaskStatus::Done
                || dto.task_id.is_some() != dto.expected_revision.is_some()
            {
                return Err(invalid());
            }
            Ok(())
        }
        "context_relay_complete_task" => {
            parse_value::<CompleteTaskInput>(value, invalid)?.validate()
        }
        "context_relay_create_handoff" => {
            parse_value::<CreateHandoffInput>(value, invalid)?.validate()
        }
        "context_relay_status" => parse::<StatusInput>(value, invalid),
        _ => Err(invalid()),
    }
}

fn validate_output(name: &str, value: &Value) -> Result<(), ValidationError> {
    let invalid = || ValidationError::Invalid("MCP output");
    match name {
        "context_relay_search" => {
            let dto: SearchOutput = parse_value(value, invalid)?;
            if dto.memories.len() > crate::MAX_BATCH_OPERATIONS
                || dto.instructions.len() > crate::MAX_BATCH_OPERATIONS
            {
                return Err(ValidationError::TooLarge {
                    field: "search output",
                    limit: crate::MAX_BATCH_OPERATIONS,
                });
            }
            for item in &dto.memories {
                item.validate()?;
            }
            for item in &dto.instructions {
                item.validate()?;
            }
            Ok(())
        }
        "context_relay_get" => {
            let dto: GetOutput = parse_value(value, invalid)?;
            if let Some(record) = &dto.record {
                match record {
                    ReadableRecord::Memory(item) => item.validate()?,
                    ReadableRecord::Instruction(item) => item.validate()?,
                }
            }
            Ok(())
        }
        "context_relay_remember" => parse_value::<RememberOutput>(value, invalid)?
            .memory
            .validate(),
        "context_relay_propose_memory" => parse_value::<ProposeMemoryOutput>(value, invalid)?
            .candidate
            .validate(),
        "context_relay_update_memory" => parse_value::<UpdateMemoryOutput>(value, invalid)?
            .memory
            .validate(),
        "context_relay_archive_memory" => parse_value::<ArchiveMemoryOutput>(value, invalid)?
            .memory
            .validate(),
        "context_relay_list_tasks" => {
            let dto: ListTasksOutput = parse_value(value, invalid)?;
            if dto.tasks.len() > crate::MAX_BATCH_OPERATIONS {
                return Err(ValidationError::TooLarge {
                    field: "tasks",
                    limit: crate::MAX_BATCH_OPERATIONS,
                });
            }
            for item in &dto.tasks {
                item.validate()?;
            }
            Ok(())
        }
        "context_relay_upsert_task" => parse_value::<UpsertTaskOutput>(value, invalid)?
            .task
            .validate(),
        "context_relay_complete_task" => parse_value::<CompleteTaskOutput>(value, invalid)?
            .task
            .validate(),
        "context_relay_create_handoff" => parse_value::<CreateHandoffOutput>(value, invalid)?
            .payload
            .validate(),
        "context_relay_status" => parse::<StatusOutput>(value, invalid),
        _ => Err(invalid()),
    }
}
fn parse<T: for<'de> Deserialize<'de>>(
    value: &Value,
    error: impl FnOnce() -> ValidationError,
) -> Result<(), ValidationError> {
    serde_json::from_value::<T>(value.clone())
        .map(|_| ())
        .map_err(|_| error())
}
fn parse_value<T: for<'de> Deserialize<'de>>(
    value: &Value,
    error: impl FnOnce() -> ValidationError,
) -> Result<T, ValidationError> {
    serde_json::from_value(value.clone()).map_err(|_| error())
}
fn strict(required: Vec<&str>, properties: Value) -> Value {
    json!({"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":properties,"required":required,"additionalProperties":false})
}
fn uuid() -> Value {
    json!({"type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"})
}
fn text(min: usize, max: usize) -> Value {
    json!({"type":"string","minLength":min,"maxLength":max,"x-utf8-maxBytes":max,"pattern":r".*\S.*"})
}
fn mcp_scope_selector() -> Value {
    json!({"oneOf":[{"type":"object","properties":{"scope":{"const":"global"}},"required":["scope"],"additionalProperties":false},{"type":"object","properties":{"scope":{"const":"active_project"}},"required":["scope"],"additionalProperties":false}]})
}
fn scope() -> Value {
    json!({"oneOf":[{"type":"object","properties":{"scope":{"const":"global"}},"required":["scope"],"additionalProperties":false},{"type":"object","properties":{"scope":{"const":"project"},"projectId":uuid()},"required":["scope","projectId"],"additionalProperties":false}]})
}
fn task_status() -> Value {
    json!({"enum":["open","in_progress","blocked","done","canceled"]})
}
fn evidence() -> Value {
    json!({"type":"object","properties":{"summary":text(1,MAX_EVIDENCE_BYTES),"kind":text(1,128),"reference":{"oneOf":[{"type":"null"},{"type":"string","maxLength":MAX_EVIDENCE_BYTES,"x-utf8-maxBytes":MAX_EVIDENCE_BYTES}]}},"required":["summary","kind"],"additionalProperties":false})
}
fn memory() -> Value {
    json!({"type":"object","properties":{"id":uuid(),"scope":scope(),"kind":{"enum":["fact","decision","preference","pattern","procedure","note"]},"title":text(1,MAX_TITLE_BYTES),"bodyMarkdown":text(1,MAX_MARKDOWN_BYTES),"tags":{"type":"array","maxItems":crate::MAX_TAGS,"uniqueItems":true,"items":text(1,crate::MAX_TAG_BYTES)},"origin":{"enum":["explicit","inferred","native_import","package_import"]},"provenance":provenance(),"revision":uuid(),"createdHlc":hlc(),"updatedHlc":hlc(),"archived":{"type":"boolean"}},"required":["id","scope","kind","title","bodyMarkdown","tags","origin","provenance","revision","createdHlc","updatedHlc","archived"],"additionalProperties":false})
}
fn instruction() -> Value {
    json!({"type":"object","properties":{"id":uuid(),"scope":scope(),"title":text(1,MAX_TITLE_BYTES),"bodyMarkdown":text(1,MAX_MARKDOWN_BYTES),"provenance":provenance(),"archived":{"type":"boolean"}},"required":["id","scope","title","bodyMarkdown","provenance","archived"],"additionalProperties":false})
}
fn candidate() -> Value {
    json!({"type":"object","properties":{"id":uuid(),"proposedMemory":memory(),"evidenceSummary":text(1,MAX_EVIDENCE_BYTES),"sourceHarness":{"enum":["claude_code","codex","hermes"]},"state":{"enum":["pending","accepted","rejected"]}},"required":["id","proposedMemory","evidenceSummary","sourceHarness","state"],"additionalProperties":false})
}
fn task() -> Value {
    json!({"type":"object","properties":{"id":uuid(),"projectId":uuid(),"title":text(1,MAX_TITLE_BYTES),"bodyMarkdown":text(1,MAX_MARKDOWN_BYTES),"status":task_status(),"evidence":{"type":"array","maxItems":crate::MAX_EVIDENCE_ITEMS,"items":task_evidence()},"revision":uuid()},"required":["id","projectId","title","bodyMarkdown","status","evidence","revision"],"allOf":[{"if":{"properties":{"status":{"const":"done"}},"required":["status"]},"then":{"properties":{"evidence":{"type":"array","minItems":1}}}}],"additionalProperties":false})
}
fn readable_record() -> Value {
    json!({"oneOf":[{"type":"object","properties":{"kind":{"const":"memory"},"record":memory()},"required":["kind","record"],"additionalProperties":false},{"type":"object","properties":{"kind":{"const":"instruction"},"record":instruction()},"required":["kind","record"],"additionalProperties":false}]})
}
fn version() -> Value {
    json!({"type":"object","properties":{"major":{"type":"integer","minimum":0,"maximum":65535},"minor":{"type":"integer","minimum":0,"maximum":65535}},"required":["major","minor"],"additionalProperties":false})
}
fn protocol_range() -> Value {
    json!({"type":"object","properties":{"min":version(),"max":version()},"required":["min","max"],"additionalProperties":false})
}

fn hlc() -> Value {
    json!({"type":"object","properties":{"physicalMs":{"type":"string","pattern":"^(0|[1-9][0-9]*)$"},"logical":{"type":"integer","minimum":0,"maximum":4294967295u64},"node":uuid()},"required":["physicalMs","logical","node"],"additionalProperties":false})
}
fn provenance() -> Value {
    json!({"type":"object","properties":{"originDevice":uuid(),"harness":{"oneOf":[{"type":"null"},{"enum":["claude_code","codex","hermes"]}]},"source":{"oneOf":[{"type":"null"},{"type":"object","properties":{"source":{"const":"record"},"recordId":uuid()},"required":["source","recordId"],"additionalProperties":false},{"type":"object","properties":{"source":{"const":"package"},"packageId":uuid()},"required":["source","packageId"],"additionalProperties":false}]},"createdHlc":hlc()},"required":["originDevice","harness","source","createdHlc"],"additionalProperties":false})
}
fn task_evidence() -> Value {
    json!({"type":"object","properties":{"summary":text(1,MAX_EVIDENCE_BYTES),"evidenceKind":text(1,crate::MAX_TAG_BYTES),"reference":{"oneOf":[{"type":"null"},{"type":"string","maxLength":MAX_EVIDENCE_BYTES,"x-utf8-maxBytes":MAX_EVIDENCE_BYTES}]},"recordedHlc":hlc()},"required":["summary","evidenceKind","reference","recordedHlc"],"additionalProperties":false})
}
fn access_policy() -> Value {
    json!({"oneOf":[
        {"type":"object","properties":{"mode":{"const":"default"}},"required":["mode"],"additionalProperties":false},
        {"type":"object","properties":{"mode":{"const":"read_only"}},"required":["mode"],"additionalProperties":false},
        {"type":"object","properties":{"mode":{"const":"active_project_only"},"readOnly":{"type":"boolean"}},"required":["mode","readOnly"],"additionalProperties":false},
        {"type":"object","properties":{"mode":{"const":"global_only"},"readOnly":{"type":"boolean"}},"required":["mode","readOnly"],"additionalProperties":false},
        {"type":"object","properties":{"mode":{"const":"selected_project"},"projectId":uuid(),"readOnly":{"type":"boolean"}},"required":["mode","projectId","readOnly"],"additionalProperties":false},
        {"type":"object","properties":{"mode":{"const":"disabled"}},"required":["mode"],"additionalProperties":false}
    ]})
}
fn decision_memory() -> Value {
    let mut schema = memory();
    schema["properties"]["kind"] = json!({"const":"decision"});
    schema
}
fn handoff_payload() -> Value {
    json!({"type":"object","properties":{"project":{"oneOf":[{"type":"null"},project_identity()]},"markdown":text(1,MAX_MARKDOWN_BYTES),"memories":{"type":"array","maxItems":crate::MAX_EVIDENCE_ITEMS,"items":memory()},"decisions":{"type":"array","maxItems":crate::MAX_EVIDENCE_ITEMS,"items":decision_memory()},"tasks":{"type":"array","maxItems":crate::MAX_EVIDENCE_ITEMS,"items":task()},"instructionRefs":{"type":"array","maxItems":crate::MAX_EVIDENCE_ITEMS,"uniqueItems":true,"items":uuid()}},"required":["project","markdown","memories","decisions","tasks","instructionRefs"],"additionalProperties":false})
}
fn project_identity() -> Value {
    json!({"type":"object","properties":{"projectId":uuid(),"githubRepositoryId":{"oneOf":[{"type":"null"},{"type":"string","pattern":"^[1-9][0-9]*$"}]},"gitRemoteFingerprint":{"oneOf":[{"type":"null"},{"type":"string","pattern":"^[0-9a-f]{64}$"}]},"monorepoSubdirectory":{"oneOf":[{"type":"null"},{"type":"string","pattern":r"^(?!/)(?!.*(?:^|/)\.\.?(?:/|$))(?!.*[\\:\x00-\x1F]).+$","maxLength":MAX_TITLE_BYTES,"x-utf8-maxBytes":MAX_TITLE_BYTES}]},"name":text(1,MAX_TITLE_BYTES)},"required":["projectId","githubRepositoryId","gitRemoteFingerprint","monorepoSubdirectory","name"],"additionalProperties":false})
}
