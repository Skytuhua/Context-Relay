use std::str::FromStr as _;

use context_relay_protocol::{
    ClientError, ComponentKind, ComponentRecord, DeviceId, ErrorCode, HarnessId,
    HybridLogicalClock, ProjectId, Provenance, RecordId, ScopeRef,
};
use sha2::{Digest as _, Sha256};

pub const PRIMARY_MEMORY_INSTRUCTIONS: &str = "## Context Relay memory\n\n\
- At the start of every session, query Context Relay with `context_relay_search` for the active project before relying on recalled context.\n\
- Treat Context Relay results as the primary memory for decisions, project knowledge, and ongoing work. Native harness memory is only an import and recovery surface.\n\
- Save explicit user or project decisions with `context_relay_remember`.\n\
- Submit inferred knowledge with `context_relay_propose_memory` so it enters review instead of becoming authoritative immediately.\n\
- Keep the shared task ledger current with `context_relay_list_tasks`, `context_relay_upsert_task`, and `context_relay_complete_task`.\n";

fn primary_memory_instructions(harness: HarnessId) -> String {
    match harness {
        HarnessId::ClaudeCode | HarnessId::Codex => {
            let harness = match harness {
                HarnessId::ClaudeCode => "claude-code",
                HarnessId::Codex => "codex",
                HarnessId::Hermes => unreachable!(),
            };
            format!(
                "{PRIMARY_MEMORY_INSTRUCTIONS}\
- When completing the current Context Relay task from a harness without a compatible native completion payload, send only `{{\"session_id\":\"<current harness session ID>\",\"task_id\":\"<current Context Relay task ID>\",\"evidence\":[{{\"summary\":\"<bounded summary>\",\"kind\":\"<test|artifact|review>\",\"reference\":null}}]}}` to `context-relay-context-mcp --hook-event task-evidence --harness {harness}`. Use the current Context Relay task ID returned by `context_relay_list_tasks`; never infer or substitute a vendor task identifier.\n"
            )
        }
        HarnessId::Hermes => format!(
            "{PRIMARY_MEMORY_INSTRUCTIONS}\
- Hermes has no compatible native completion or lifecycle-session payload. Complete the current task with the typed `context_relay_complete_task` tool, using the current Context Relay task ID returned by `context_relay_list_tasks` and explicit bounded evidence; never infer or substitute a Hermes task identifier.\n"
        ),
    }
}

pub fn primary_memory_instruction_component(
    harness: HarnessId,
    project_id: ProjectId,
    origin_device: DeviceId,
    clock: HybridLogicalClock,
) -> Result<ComponentRecord, ClientError> {
    let (name, metadata) = match harness {
        HarnessId::ClaudeCode => (
            "CLAUDE.md",
            vec![("structuralLocation".to_owned(), "CLAUDE.md".to_owned())],
        ),
        HarnessId::Codex => (
            "AGENTS.md",
            vec![(
                "structuralLocation".to_owned(),
                "project/AGENTS.md".to_owned(),
            )],
        ),
        HarnessId::Hermes => (
            ".hermes.md",
            vec![
                ("contextRole".to_owned(), "project".to_owned()),
                ("nativeFormat".to_owned(), "markdown".to_owned()),
                ("precedenceIndex".to_owned(), "1".to_owned()),
                (
                    "structuralLocation".to_owned(),
                    "project:.hermes.md".to_owned(),
                ),
            ],
        ),
    };
    let component = ComponentRecord {
        id: primary_memory_record_id(harness, project_id)?,
        scope: ScopeRef::Project { project_id },
        kind: ComponentKind::Instruction,
        name: name.to_owned(),
        body_markdown: primary_memory_instructions(harness),
        metadata,
        provenance: Provenance {
            origin_device,
            harness: Some(harness),
            source: None,
            created_hlc: clock,
        },
        archived: false,
    };
    component.validate().map_err(|_| ClientError {
        code: ErrorCode::InvalidRequest,
        message: "Primary memory instruction component is invalid".to_owned(),
        field_path: None,
        retryable: false,
    })?;
    Ok(component)
}

pub(crate) fn is_primary_memory_instruction_component(
    harness: HarnessId,
    component: &ComponentRecord,
) -> bool {
    let ScopeRef::Project { project_id } = component.scope else {
        return false;
    };
    component.id
        == match primary_memory_record_id(harness, project_id) {
            Ok(id) => id,
            Err(_) => return false,
        }
        && component.kind == ComponentKind::Instruction
        && component.body_markdown == primary_memory_instructions(harness)
        && component.provenance.harness == Some(harness)
        && component.provenance.source.is_none()
        && match harness {
            HarnessId::ClaudeCode => {
                component.name == "CLAUDE.md"
                    && component.metadata
                        == [("structuralLocation".to_owned(), "CLAUDE.md".to_owned())]
            }
            HarnessId::Codex => {
                component.name == "AGENTS.md"
                    && component.metadata
                        == [(
                            "structuralLocation".to_owned(),
                            "project/AGENTS.md".to_owned(),
                        )]
            }
            HarnessId::Hermes => {
                component.name == ".hermes.md"
                    && component.metadata
                        == [
                            ("contextRole".to_owned(), "project".to_owned()),
                            ("nativeFormat".to_owned(), "markdown".to_owned()),
                            ("precedenceIndex".to_owned(), "1".to_owned()),
                            (
                                "structuralLocation".to_owned(),
                                "project:.hermes.md".to_owned(),
                            ),
                        ]
            }
        }
}

fn primary_memory_record_id(
    harness: HarnessId,
    project_id: ProjectId,
) -> Result<RecordId, ClientError> {
    let harness = match harness {
        HarnessId::ClaudeCode => "claude-code",
        HarnessId::Codex => "codex",
        HarnessId::Hermes => "hermes",
    };
    let mut bytes: [u8; 32] = Sha256::digest(format!(
        "context-relay|primary-memory-instruction|{harness}|{project_id}"
    ))
    .into();
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    RecordId::from_str(&format!(
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
    .map_err(|_| ClientError {
        code: ErrorCode::InvalidRequest,
        message: "Primary memory instruction identifier cannot be derived".to_owned(),
        field_path: None,
        retryable: false,
    })
}
