#![cfg(any(windows, target_os = "macos"))]

mod support;

use std::path::Path;

use context_relay_core::{mcp::McpWorkspace, search::Embedding384, vault::Vault};
use context_relay_protocol::{
    ClientError, DeviceId, ErrorCode, HarnessAccessPolicy, HarnessId, MAX_EVIDENCE_ITEMS,
    MAX_IPC_FRAME_BYTES, MAX_MARKDOWN_BYTES, McpBinding, McpCallParams, MemoryKind, MemoryRecord,
    NativePlatform, ProjectId, ProjectIdentity, RecordKind, ScopeRef, TaskEvidence, TaskId,
    TaskRecord, TaskStatus, WireNativeValue,
};
use serde_json::{Value, json};
use tempfile::{TempDir, tempdir};

use support::{MemoryKeyStore, TempVault, basis, clock, instruction, memory, operation};

const CREDENTIAL: &str = "mcp-tasks-handoffs-v1";

fn id(index: u16) -> String {
    format!("018f22e2-79b0-7cc8-98c4-dc0c0c07{index:04x}")
}

struct Fixture {
    database: TempVault,
    keys: MemoryKeyStore,
    root: TempDir,
    vault: Vault,
    device_id: DeviceId,
    project: ProjectIdentity,
    other_project: ProjectIdentity,
}

impl Fixture {
    fn new(name: &str, policy: HarnessAccessPolicy) -> Self {
        let database = TempVault::new(name);
        let keys = MemoryKeyStore::default();
        let mut vault = Vault::open(database.path(), CREDENTIAL, &keys).unwrap();
        let root = tempdir().unwrap();
        let project = ProjectIdentity {
            project_id: id(900).parse().unwrap(),
            github_repository_id: Some(42),
            git_remote_fingerprint: None,
            monorepo_subdirectory: Some("crates/core".to_owned()),
            name: "Active project".to_owned(),
        };
        let other_project = ProjectIdentity {
            project_id: id(901).parse().unwrap(),
            github_repository_id: None,
            git_remote_fingerprint: None,
            monorepo_subdirectory: None,
            name: "Other project".to_owned(),
        };
        vault.put_project(&project).unwrap();
        vault.put_project(&other_project).unwrap();
        vault
            .put_path(&project.project_id.to_string(), &wire_path(root.path()))
            .unwrap();
        vault.set_access_policy(HarnessId::Codex, &policy).unwrap();
        Self {
            database,
            keys,
            root,
            vault,
            device_id: id(902).parse().unwrap(),
            project,
            other_project,
        }
    }

    fn call(&mut self, name: &str, arguments: Value) -> Result<Value, ClientError> {
        McpWorkspace::new(&mut self.vault, self.device_id).call(McpCallParams {
            binding: McpBinding {
                harness: HarnessId::Codex,
                working_directory: wire_path(self.root.path()),
            },
            name: name.to_owned(),
            arguments,
        })
    }

    fn reopen(&mut self) {
        self.vault = Vault::open(self.database.path(), CREDENTIAL, &self.keys).unwrap();
    }

    fn upsert_input(
        &self,
        operation: u16,
        task_id: Option<&str>,
        expected_revision: Option<&str>,
        title: &str,
        status: &str,
    ) -> Value {
        json!({
            "operationId": id(operation),
            "taskId": task_id,
            "title": title,
            "bodyMarkdown": format!("{title} body"),
            "status": status,
            "expectedRevision": expected_revision
        })
    }

    fn insert_memory(
        &mut self,
        record: u16,
        scope: ScopeRef,
        kind: MemoryKind,
        title: &str,
        body: &str,
        updated_ms: u64,
    ) -> MemoryRecord {
        let record_id = id(record);
        let mut value = memory(&record_id, scope, title, body);
        value.kind = kind;
        value.updated_hlc = clock(updated_ms);
        self.vault
            .put_local_memory(&value, &embedding_for(record))
            .unwrap();
        value
    }

    fn archive_memory(&mut self, mut memory: MemoryRecord, record: u16) -> MemoryRecord {
        memory.archived = true;
        self.vault
            .put_local_memory(&memory, &embedding_for(record))
            .unwrap();
        memory
    }

    fn insert_task(
        &mut self,
        record: u16,
        project_id: ProjectId,
        title: &str,
        status: TaskStatus,
        evidence: Vec<TaskEvidence>,
    ) -> TaskRecord {
        let task = TaskRecord {
            id: id(record).parse().unwrap(),
            project_id,
            title: title.to_owned(),
            body_markdown: format!("{title} body"),
            status,
            evidence,
            revision: id(record + 1_000).parse().unwrap(),
        };
        self.vault.put_task(&task).unwrap();
        task
    }

    fn insert_instruction(
        &mut self,
        record: u16,
        scope: ScopeRef,
        title: &str,
        body: &str,
        archived: bool,
    ) {
        let record_id = id(record);
        let mut value = instruction(&record_id, scope, title, body);
        value.archived = archived;
        self.vault
            .put_instruction(
                &value,
                &operation(&id(record + 2_000), &record_id, RecordKind::Instruction),
                &embedding_for(record),
            )
            .unwrap();
    }
}

fn embedding_for(index: u16) -> Embedding384 {
    basis(usize::from(index) % 384)
}

fn evidence(summary: &str) -> Value {
    json!([{
        "summary": summary,
        "kind": "test",
        "reference": "cargo test"
    }])
}

fn stored_evidence(summary: &str) -> Vec<TaskEvidence> {
    vec![TaskEvidence {
        summary: summary.to_owned(),
        evidence_kind: "test".to_owned(),
        reference: Some("cargo test".to_owned()),
        recorded_hlc: clock(50),
    }]
}

fn handoff_input(
    operation: u16,
    memory_ids: &[&str],
    decision_ids: &[&str],
    task_ids: &[&str],
    summary: &str,
) -> Value {
    json!({
        "operationId": id(operation),
        "memoryIds": memory_ids,
        "decisionIds": decision_ids,
        "taskIds": task_ids,
        "summary": summary
    })
}

fn assert_error(error: &ClientError, code: ErrorCode) {
    assert_eq!(error.code, code);
    assert!(!error.retryable);
}

fn wire_path(path: &Path) -> WireNativeValue {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::ffi::OsStrExt;

        WireNativeValue {
            platform: NativePlatform::Macos,
            bytes: path.as_os_str().as_bytes().to_vec(),
            display: Some(path.display().to_string()),
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;

        WireNativeValue {
            platform: NativePlatform::Windows,
            bytes: path
                .as_os_str()
                .encode_wide()
                .flat_map(u16::to_le_bytes)
                .collect(),
            display: Some(path.display().to_string()),
        }
    }
}

#[test]
fn list_and_upsert_are_project_scoped_and_status_filtered() {
    let mut fixture = Fixture::new("task-list-upsert", HarnessAccessPolicy::Default);
    fixture.insert_task(
        10,
        fixture.other_project.project_id,
        "Other",
        TaskStatus::Open,
        Vec::new(),
    );

    let created = fixture
        .call(
            "context_relay_upsert_task",
            fixture.upsert_input(1, None, None, "Created", "open"),
        )
        .unwrap();
    let updated = fixture
        .call(
            "context_relay_upsert_task",
            fixture.upsert_input(
                2,
                created["task"]["id"].as_str(),
                created["task"]["revision"].as_str(),
                "Updated",
                "blocked",
            ),
        )
        .unwrap();
    let all = fixture.call("context_relay_list_tasks", json!({})).unwrap();
    let blocked = fixture
        .call("context_relay_list_tasks", json!({"status": "blocked"}))
        .unwrap();

    assert_eq!(created["task"]["id"], id(1));
    assert_eq!(updated["task"]["title"], "Updated");
    assert_eq!(updated["task"]["status"], "blocked");
    assert_eq!(all["tasks"].as_array().unwrap().len(), 1);
    assert_eq!(blocked["tasks"], all["tasks"]);
}

#[test]
fn oversized_filtered_task_list_errors_instead_of_returning_a_partial_prefix() {
    let mut fixture = Fixture::new("task-list-output-budget", HarnessAccessPolicy::Default);
    for record in [60, 61, 62] {
        let mut task = fixture.insert_task(
            record,
            fixture.project.project_id,
            &format!("Large task {record}"),
            TaskStatus::Open,
            Vec::new(),
        );
        task.body_markdown = "x".repeat(MAX_MARKDOWN_BYTES);
        fixture.vault.put_task(&task).unwrap();
    }

    let error = fixture
        .call("context_relay_list_tasks", json!({"status": "open"}))
        .unwrap_err();

    assert_error(&error, ErrorCode::FrameTooLarge);
    assert!(error.field_path.is_none());
    assert_eq!(
        fixture
            .vault
            .tasks(fixture.project.project_id)
            .unwrap()
            .len(),
        3
    );
}

#[test]
fn task_create_update_pair_and_completion_evidence_are_required() {
    let mut fixture = Fixture::new("task-pairs-evidence", HarnessAccessPolicy::Default);
    let invalid_create_pair = fixture
        .call(
            "context_relay_upsert_task",
            fixture.upsert_input(1, Some(&id(20)), None, "Invalid", "open"),
        )
        .unwrap_err();
    let invalid_update_pair = fixture
        .call(
            "context_relay_upsert_task",
            fixture.upsert_input(2, None, Some(&id(1)), "Invalid", "open"),
        )
        .unwrap_err();
    assert_error(&invalid_create_pair, ErrorCode::InvalidRequest);
    assert_error(&invalid_update_pair, ErrorCode::InvalidRequest);

    let created = fixture
        .call(
            "context_relay_upsert_task",
            fixture.upsert_input(3, None, None, "Complete me", "open"),
        )
        .unwrap();
    let task_id = created["task"]["id"].as_str().unwrap();
    let revision = created["task"]["revision"].as_str().unwrap();
    let empty_evidence = fixture
        .call(
            "context_relay_complete_task",
            json!({
                "operationId": id(4),
                "taskId": task_id,
                "expectedRevision": revision,
                "evidence": []
            }),
        )
        .unwrap_err();
    assert_error(&empty_evidence, ErrorCode::InvalidRequest);

    let completed = fixture
        .call(
            "context_relay_complete_task",
            json!({
                "operationId": id(5),
                "taskId": task_id,
                "expectedRevision": revision,
                "evidence": evidence("focused suite passed")
            }),
        )
        .unwrap();
    assert_eq!(completed["task"]["status"], "done");
    assert_eq!(
        completed["task"]["evidence"][0]["summary"],
        "focused suite passed"
    );

    let stale = fixture
        .call(
            "context_relay_complete_task",
            json!({
                "operationId": id(6),
                "taskId": task_id,
                "expectedRevision": revision,
                "evidence": evidence("stale")
            }),
        )
        .unwrap_err();
    assert_error(&stale, ErrorCode::RevisionConflict);
}

#[test]
fn task_replays_return_immutable_snapshots_after_later_mutations_and_reopen() {
    let mut fixture = Fixture::new("task-immutable-replay", HarnessAccessPolicy::Default);
    let create_input = fixture.upsert_input(1, None, None, "Initial", "open");
    let created = fixture
        .call("context_relay_upsert_task", create_input.clone())
        .unwrap();
    let task_id = created["task"]["id"].as_str().unwrap().to_owned();
    let update_input = fixture.upsert_input(
        2,
        Some(&task_id),
        created["task"]["revision"].as_str(),
        "Updated",
        "blocked",
    );
    let updated = fixture
        .call("context_relay_upsert_task", update_input.clone())
        .unwrap();
    let completion_input = json!({
        "operationId": id(3),
        "taskId": task_id,
        "expectedRevision": updated["task"]["revision"],
        "evidence": evidence("done")
    });
    let completed = fixture
        .call("context_relay_complete_task", completion_input.clone())
        .unwrap();
    fixture
        .call(
            "context_relay_upsert_task",
            fixture.upsert_input(
                4,
                Some(&task_id),
                completed["task"]["revision"].as_str(),
                "Reopened",
                "open",
            ),
        )
        .unwrap();
    fixture.reopen();

    assert_eq!(
        fixture
            .call("context_relay_upsert_task", create_input)
            .unwrap(),
        created
    );
    assert_eq!(
        fixture
            .call("context_relay_upsert_task", update_input)
            .unwrap(),
        updated
    );
    assert_eq!(
        fixture
            .call("context_relay_complete_task", completion_input)
            .unwrap(),
        completed
    );
    let altered_completion = fixture
        .call(
            "context_relay_complete_task",
            json!({
                "operationId": id(3),
                "taskId": task_id,
                "expectedRevision": updated["task"]["revision"],
                "evidence": evidence("altered replay")
            }),
        )
        .unwrap_err();
    assert_error(&altered_completion, ErrorCode::Conflict);
}

#[test]
fn altered_and_global_operation_id_reuse_conflicts_without_mutating_tasks() {
    let mut fixture = Fixture::new("task-operation-conflicts", HarnessAccessPolicy::Default);
    let create_input = fixture.upsert_input(1, None, None, "Original", "open");
    let created = fixture
        .call("context_relay_upsert_task", create_input)
        .unwrap();
    fixture.reopen();

    let altered = fixture
        .call(
            "context_relay_upsert_task",
            fixture.upsert_input(1, None, None, "Altered", "blocked"),
        )
        .unwrap_err();
    assert_error(&altered, ErrorCode::Conflict);

    let cross_action = fixture
        .call(
            "context_relay_complete_task",
            json!({
                "operationId": id(1),
                "taskId": created["task"]["id"],
                "expectedRevision": created["task"]["revision"],
                "evidence": evidence("must conflict")
            }),
        )
        .unwrap_err();
    assert_error(&cross_action, ErrorCode::Conflict);

    let cross_domain = fixture
        .call(
            "context_relay_remember",
            json!({
                "operationId": id(1),
                "kind": "note",
                "title": "Collision",
                "markdown": "must conflict",
                "tags": [],
                "scope": {"scope": "active_project"}
            }),
        )
        .unwrap_err();
    assert_error(&cross_domain, ErrorCode::Conflict);

    let persisted = fixture
        .vault
        .task(&id(1).parse::<TaskId>().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(persisted.title, "Original");
    assert_eq!(persisted.status, TaskStatus::Open);
}

#[test]
fn task_ids_never_bypass_project_scope() {
    let mut fixture = Fixture::new("task-cross-project", HarnessAccessPolicy::Default);
    let other = fixture.insert_task(
        10,
        fixture.other_project.project_id,
        "Other",
        TaskStatus::Open,
        Vec::new(),
    );

    for error in [
        fixture
            .call(
                "context_relay_upsert_task",
                fixture.upsert_input(
                    1,
                    Some(&other.id.to_string()),
                    Some(&other.revision.to_string()),
                    "Denied",
                    "blocked",
                ),
            )
            .unwrap_err(),
        fixture
            .call(
                "context_relay_complete_task",
                json!({
                    "operationId": id(2),
                    "taskId": other.id,
                    "expectedRevision": other.revision,
                    "evidence": evidence("denied")
                }),
            )
            .unwrap_err(),
    ] {
        assert_error(&error, ErrorCode::ScopeDenied);
    }
    assert_eq!(fixture.vault.task(&other.id).unwrap().unwrap(), other);
}

#[test]
fn read_only_can_list_tasks_but_all_task_writes_are_denied() {
    let mut fixture = Fixture::new("task-read-only", HarnessAccessPolicy::ReadOnly);
    let task = fixture.insert_task(
        10,
        fixture.project.project_id,
        "Visible",
        TaskStatus::Open,
        Vec::new(),
    );

    assert_eq!(
        fixture.call("context_relay_list_tasks", json!({})).unwrap()["tasks"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    for error in [
        fixture
            .call(
                "context_relay_upsert_task",
                fixture.upsert_input(1, None, None, "Denied", "open"),
            )
            .unwrap_err(),
        fixture
            .call(
                "context_relay_complete_task",
                json!({
                    "operationId": id(2),
                    "taskId": task.id,
                    "expectedRevision": task.revision,
                    "evidence": evidence("denied")
                }),
            )
            .unwrap_err(),
    ] {
        assert_error(&error, ErrorCode::ScopeDenied);
    }
}

#[test]
fn oversized_task_outputs_are_rejected_before_persistence() {
    let mut fixture = Fixture::new("task-output-preflight", HarnessAccessPolicy::Default);
    let error = fixture
        .call(
            "context_relay_upsert_task",
            json!({
                "operationId": id(1),
                "title": "Escaped output",
                "bodyMarkdown": "\0".repeat(MAX_MARKDOWN_BYTES),
                "status": "open"
            }),
        )
        .unwrap_err();

    assert_error(&error, ErrorCode::FrameTooLarge);
    assert!(
        fixture
            .vault
            .task(&id(1).parse::<TaskId>().unwrap())
            .unwrap()
            .is_none()
    );
}

#[test]
fn handoff_enriches_ordered_selections_recent_decisions_tasks_evidence_and_instructions() {
    let mut fixture = Fixture::new("handoff-complete", HarnessAccessPolicy::Default);
    let project_scope = ScopeRef::Project {
        project_id: fixture.project.project_id,
    };
    let first = fixture.insert_memory(
        10,
        project_scope.clone(),
        MemoryKind::Fact,
        "First memory",
        "daemon bridge context",
        10,
    );
    let second = fixture.insert_memory(
        11,
        ScopeRef::Global,
        MemoryKind::Procedure,
        "Second memory",
        "daemon procedure",
        11,
    );
    let selected_decision = fixture.insert_memory(
        12,
        project_scope.clone(),
        MemoryKind::Decision,
        "Selected decision",
        "selected daemon decision",
        20,
    );
    let older_recent = fixture.insert_memory(
        13,
        project_scope.clone(),
        MemoryKind::Decision,
        "Older recent",
        "older daemon decision",
        30,
    );
    let newer_recent = fixture.insert_memory(
        14,
        project_scope.clone(),
        MemoryKind::Decision,
        "Newer recent",
        "newer daemon decision",
        40,
    );
    let done = fixture.insert_task(
        20,
        fixture.project.project_id,
        "Done selected",
        TaskStatus::Done,
        stored_evidence("workspace tests passed"),
    );
    let blocked = fixture.insert_task(
        21,
        fixture.project.project_id,
        "Blocked auto",
        TaskStatus::Blocked,
        Vec::new(),
    );
    let open = fixture.insert_task(
        22,
        fixture.project.project_id,
        "Open auto",
        TaskStatus::Open,
        Vec::new(),
    );
    let canceled = fixture.insert_task(
        23,
        fixture.project.project_id,
        "Canceled omitted",
        TaskStatus::Canceled,
        Vec::new(),
    );
    fixture.insert_instruction(
        30,
        ScopeRef::Global,
        "Daemon rule",
        "Use the daemon bridge.",
        false,
    );
    fixture.insert_instruction(
        31,
        project_scope,
        "Project rule",
        "Keep daemon handoffs scoped.",
        false,
    );
    fixture.insert_instruction(
        32,
        ScopeRef::Global,
        "Archived daemon rule",
        "This daemon rule must be omitted.",
        true,
    );

    let input = handoff_input(
        1,
        &[&second.id.to_string(), &first.id.to_string()],
        &[&selected_decision.id.to_string()],
        &[&done.id.to_string(), &canceled.id.to_string()],
        "Continue the daemon bridge.",
    );
    let first_output = fixture
        .call("context_relay_create_handoff", input.clone())
        .unwrap();
    let replay = fixture.call("context_relay_create_handoff", input).unwrap();
    let payload = &first_output["payload"];

    assert_eq!(first_output, replay);
    assert_eq!(first_output["handoffId"], id(1));
    assert_eq!(
        payload["project"]["projectId"],
        fixture.project.project_id.to_string()
    );
    assert_eq!(
        payload["memories"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec![second.id.to_string(), first.id.to_string()]
    );
    assert_eq!(
        payload["decisions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec![
            selected_decision.id.to_string(),
            newer_recent.id.to_string(),
            older_recent.id.to_string()
        ]
    );
    let task_ids = payload["tasks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value["id"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(task_ids[0], done.id.to_string());
    assert_eq!(task_ids[1], canceled.id.to_string());
    assert!(task_ids.contains(&blocked.id.to_string().as_str()));
    assert!(task_ids.contains(&open.id.to_string().as_str()));
    assert!(task_ids.contains(&id(23).as_str()));
    assert_eq!(
        payload["tasks"][0]["evidence"][0]["summary"],
        "workspace tests passed"
    );
    assert!(!payload["instructionRefs"].as_array().unwrap().is_empty());
    assert!(
        payload["instructionRefs"]
            .as_array()
            .unwrap()
            .iter()
            .all(|value| value == &id(30) || value == &id(31))
    );
    let markdown = payload["markdown"].as_str().unwrap();
    for heading in [
        "# Handoff",
        "## Project",
        "## Summary",
        "## Selected memories",
        "## Recent decisions",
        "## Open and blocked tasks",
        "## Selected terminal tasks",
        "## Completion evidence",
        "## Relevant instructions",
    ] {
        assert!(markdown.contains(heading), "{heading}");
    }
    let open_section = markdown
        .split_once("## Open and blocked tasks\n\n")
        .unwrap()
        .1
        .split_once("\n## Selected terminal tasks")
        .unwrap()
        .0;
    let terminal_section = markdown
        .split_once("## Selected terminal tasks\n\n")
        .unwrap()
        .1
        .split_once("\n## Completion evidence")
        .unwrap()
        .0;
    assert!(open_section.contains("Open auto"));
    assert!(open_section.contains("Blocked auto"));
    assert!(!open_section.contains("Done selected"));
    assert!(!open_section.contains("Canceled omitted"));
    assert!(terminal_section.contains("Done selected"));
    assert!(terminal_section.contains("Canceled omitted"));
    assert!(markdown.contains("workspace tests passed"));
    assert!(!first_output.to_string().contains("transcript"));
    assert!(serde_json::to_vec(&first_output).unwrap().len() <= MAX_IPC_FRAME_BYTES / 4);
}

#[test]
fn handoff_rejects_wrong_kind_archived_missing_and_cross_project_selections() {
    let mut fixture = Fixture::new("handoff-invalid-selections", HarnessAccessPolicy::Default);
    let project_scope = ScopeRef::Project {
        project_id: fixture.project.project_id,
    };
    let fact = fixture.insert_memory(
        10,
        project_scope.clone(),
        MemoryKind::Fact,
        "Fact",
        "fact body",
        1,
    );
    let decision = fixture.insert_memory(
        11,
        project_scope.clone(),
        MemoryKind::Decision,
        "Decision",
        "decision body",
        2,
    );
    let archived_record = fixture.insert_memory(
        12,
        project_scope,
        MemoryKind::Fact,
        "Archived",
        "archived body",
        3,
    );
    let archived = fixture.archive_memory(archived_record, 12);
    let other_task = fixture.insert_task(
        20,
        fixture.other_project.project_id,
        "Other",
        TaskStatus::Open,
        Vec::new(),
    );
    let other_memory = fixture.insert_memory(
        21,
        ScopeRef::Project {
            project_id: fixture.other_project.project_id,
        },
        MemoryKind::Fact,
        "Other memory",
        "other body",
        4,
    );

    let cases = [
        handoff_input(1, &[], &[&fact.id.to_string()], &[], "wrong decision kind"),
        handoff_input(
            2,
            &[&decision.id.to_string()],
            &[],
            &[],
            "wrong memory kind",
        ),
        handoff_input(3, &[&archived.id.to_string()], &[], &[], "archived"),
        handoff_input(4, &[&id(99)], &[], &[], "missing"),
        handoff_input(5, &[], &[], &[&other_task.id.to_string()], "cross project"),
        handoff_input(
            6,
            &[&other_memory.id.to_string()],
            &[],
            &[],
            "cross project memory",
        ),
    ];
    let expected = [
        ErrorCode::InvalidRequest,
        ErrorCode::InvalidRequest,
        ErrorCode::InvalidRequest,
        ErrorCode::NotFound,
        ErrorCode::ScopeDenied,
        ErrorCode::ScopeDenied,
    ];
    for (input, code) in cases.into_iter().zip(expected) {
        let error = fixture
            .call("context_relay_create_handoff", input)
            .unwrap_err();
        assert_error(&error, code);
    }
}

#[test]
fn handoff_rejects_secret_like_text_without_echoing_it() {
    let mut fixture = Fixture::new("handoff-secret", HarnessAccessPolicy::Default);
    let secret = "Authorization: Bearer must-not-echo";
    let memory = fixture.insert_memory(
        10,
        ScopeRef::Project {
            project_id: fixture.project.project_id,
        },
        MemoryKind::Fact,
        "Sensitive",
        secret,
        1,
    );

    let error = fixture
        .call(
            "context_relay_create_handoff",
            handoff_input(1, &[&memory.id.to_string()], &[], &[], "summary"),
        )
        .unwrap_err();

    assert_error(&error, ErrorCode::InvalidRequest);
    assert!(!error.message.contains("must-not-echo"));
    assert!(!error.message.contains(secret));
}

#[test]
fn handoff_rejects_an_ascii_armored_pgp_private_key_without_echoing_it() {
    let mut fixture = Fixture::new("handoff-pgp-private-key", HarnessAccessPolicy::Default);
    let marker = "-----BEGIN PGP PRIVATE KEY BLOCK-----";
    let memory = fixture.insert_memory(
        10,
        ScopeRef::Project {
            project_id: fixture.project.project_id,
        },
        MemoryKind::Fact,
        "Sensitive",
        marker,
        1,
    );

    let error = fixture
        .call(
            "context_relay_create_handoff",
            handoff_input(1, &[&memory.id.to_string()], &[], &[], "summary"),
        )
        .unwrap_err();

    assert_error(&error, ErrorCode::InvalidRequest);
    assert_eq!(error.message, "The handoff contains secret-like text");
    assert!(!error.message.contains(marker));
}

#[test]
fn handoff_rejects_a_bare_slack_session_token_without_echoing_it() {
    let mut fixture = Fixture::new("handoff-slack-session-token", HarnessAccessPolicy::Default);
    let token = "xoxs-abcdefghijklmnopqrstuvwxyz0123456789";
    let memory = fixture.insert_memory(
        10,
        ScopeRef::Project {
            project_id: fixture.project.project_id,
        },
        MemoryKind::Fact,
        "Sensitive",
        token,
        1,
    );

    let error = fixture
        .call(
            "context_relay_create_handoff",
            handoff_input(1, &[&memory.id.to_string()], &[], &[], "summary"),
        )
        .unwrap_err();

    assert_error(&error, ErrorCode::InvalidRequest);
    assert_eq!(error.message, "The handoff contains secret-like text");
    assert!(!error.message.contains(token));
}

#[test]
fn handoff_accepts_a_bearer_environment_placeholder() {
    let mut fixture = Fixture::new(
        "handoff-bearer-environment-placeholder",
        HarnessAccessPolicy::Default,
    );
    let placeholder = "Bearer ${CONTEXT_RELAY_ACCESS_TOKEN}";
    let memory = fixture.insert_memory(
        10,
        ScopeRef::Project {
            project_id: fixture.project.project_id,
        },
        MemoryKind::Fact,
        "Environment-backed authorization",
        placeholder,
        1,
    );

    let output = fixture
        .call(
            "context_relay_create_handoff",
            handoff_input(1, &[&memory.id.to_string()], &[], &[], "summary"),
        )
        .unwrap();

    assert!(
        output["payload"]["markdown"]
            .as_str()
            .unwrap()
            .contains(placeholder)
    );
}

#[test]
fn handoff_rejects_markdown_delimited_token_shapes_without_echoing_them() {
    let mut fixture = Fixture::new(
        "handoff-markdown-delimited-secret",
        HarnessAccessPolicy::Default,
    );
    for (index, token) in [
        "`sk-abcdefghijkl`",
        "**(ghp_abcdefghijkl),**",
        "<xoxb-abcdefghijkl>",
        "[AKIA1234567890ABCDEF]",
        "{abcdefgh.ijklmnop.qrstuvwx};",
    ]
    .into_iter()
    .enumerate()
    {
        let record = 40 + u16::try_from(index).unwrap();
        let memory = fixture.insert_memory(
            record,
            ScopeRef::Project {
                project_id: fixture.project.project_id,
            },
            MemoryKind::Fact,
            "Sensitive",
            token,
            u64::from(record),
        );

        let error = fixture
            .call(
                "context_relay_create_handoff",
                handoff_input(
                    10 + u16::try_from(index).unwrap(),
                    &[&memory.id.to_string()],
                    &[],
                    &[],
                    "summary",
                ),
            )
            .unwrap_err();

        assert_error(&error, ErrorCode::InvalidRequest);
        assert_eq!(error.message, "The handoff contains secret-like text");
        assert!(error.field_path.is_none());
        assert!(!error.message.contains(token));
    }
}

#[test]
fn handoff_ranks_relevant_instructions_beyond_the_first_hundred_ids() {
    let mut fixture = Fixture::new(
        "handoff-full-instruction-ranking",
        HarnessAccessPolicy::Default,
    );
    let scope = ScopeRef::Project {
        project_id: fixture.project.project_id,
    };
    let selected = fixture.insert_memory(
        10,
        scope.clone(),
        MemoryKind::Fact,
        "Anchor context",
        "baseline material",
        1,
    );
    for record in 100..200 {
        fixture.insert_instruction(
            record,
            scope.clone(),
            &format!("Unrelated instruction {record}"),
            "generic formatting guidance",
            false,
        );
    }
    for record in 500..580 {
        fixture.insert_instruction(
            record,
            scope.clone(),
            &format!("Relevant instruction {record}"),
            if record == 579 {
                "Use onlyrelevantsignal and prioritysignal for this handoff."
            } else {
                "Use onlyrelevantsignal for this handoff."
            },
            false,
        );
    }

    let output = fixture
        .call(
            "context_relay_create_handoff",
            handoff_input(
                1,
                &[&selected.id.to_string()],
                &[],
                &[],
                "Continue onlyrelevantsignal with prioritysignal.",
            ),
        )
        .unwrap();

    let expected = std::iter::once(id(579))
        .chain((500..563).map(id))
        .collect::<Vec<_>>();
    assert_eq!(output["payload"]["instructionRefs"], json!(expected));
    assert!(
        output["payload"]["markdown"]
            .as_str()
            .unwrap()
            .contains(&id(579))
    );
    assert!(
        !output["payload"]["markdown"]
            .as_str()
            .unwrap()
            .contains(&id(563))
    );
}

#[test]
fn handoff_validates_selection_bounds_duplicates_and_aggregate_output_budget() {
    let mut fixture = Fixture::new("handoff-bounds", HarnessAccessPolicy::Default);
    let large = fixture.insert_task(
        10,
        fixture.project.project_id,
        "Large",
        TaskStatus::Open,
        Vec::new(),
    );
    let mut large_record = large.clone();
    large_record.body_markdown = "\0".repeat(MAX_MARKDOWN_BYTES);
    fixture.vault.put_task(&large_record).unwrap();

    let oversized_output = fixture
        .call(
            "context_relay_create_handoff",
            handoff_input(1, &[], &[], &[&large.id.to_string()], "summary"),
        )
        .unwrap_err();
    assert_error(&oversized_output, ErrorCode::FrameTooLarge);

    let duplicate = fixture
        .call(
            "context_relay_create_handoff",
            handoff_input(
                2,
                &[],
                &[],
                &[&large.id.to_string(), &large.id.to_string()],
                "summary",
            ),
        )
        .unwrap_err();
    assert_error(&duplicate, ErrorCode::InvalidRequest);

    let too_many = (0..=MAX_EVIDENCE_ITEMS)
        .map(|index| id(100 + u16::try_from(index).unwrap()))
        .collect::<Vec<_>>();
    let too_many_refs = too_many.iter().map(String::as_str).collect::<Vec<_>>();
    let bound = fixture
        .call(
            "context_relay_create_handoff",
            handoff_input(3, &too_many_refs, &[], &[], "summary"),
        )
        .unwrap_err();
    assert_error(&bound, ErrorCode::InvalidRequest);
}
