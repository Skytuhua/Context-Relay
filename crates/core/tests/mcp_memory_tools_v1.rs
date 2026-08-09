#![cfg(any(windows, target_os = "macos"))]

mod support;

use std::path::Path;

use context_relay_core::{
    mcp::McpWorkspace, search::AllowedSearchScope, service::OfflineWorkspace, vault::Vault,
};
use context_relay_protocol::{
    ClientError, DeviceId, HarnessAccessPolicy, HarnessId, MAX_IPC_FRAME_BYTES, MAX_MARKDOWN_BYTES,
    McpBinding, McpCallParams, McpScopeSelector, MemoryCreateParams, MemoryKind, MemoryRecord,
    NativePlatform, ProjectId, ProjectIdentity, RecordKind, ScopeRef, WireNativeValue,
};
use serde_json::{Value, json};
use tempfile::{TempDir, tempdir};

use support::{
    ID_1, ID_2, ID_3, ID_4, ID_5, ID_6, ID_7, ID_8, ID_9, MemoryKeyStore, TempVault, basis,
    candidate, instruction, operation,
};

const CREDENTIAL: &str = "mcp-memory-tools-v1";

struct Fixture {
    _database: TempVault,
    _keys: MemoryKeyStore,
    root: TempDir,
    vault: Vault,
    device_id: DeviceId,
    project_id: ProjectId,
}

impl Fixture {
    fn new(name: &str, policy: HarnessAccessPolicy) -> Self {
        let database = TempVault::new(name);
        let keys = MemoryKeyStore::default();
        let mut vault = Vault::open(database.path(), CREDENTIAL, &keys).unwrap();
        let root = tempdir().unwrap();
        let project_id = ID_7.parse().unwrap();
        let project = ProjectIdentity {
            project_id,
            github_repository_id: None,
            git_remote_fingerprint: None,
            monorepo_subdirectory: None,
            name: "Active project".to_owned(),
        };
        vault.put_project(&project).unwrap();
        vault
            .put_path(&project_id.to_string(), &wire_path(root.path()))
            .unwrap();
        vault.set_access_policy(HarnessId::Codex, &policy).unwrap();
        Self {
            _database: database,
            _keys: keys,
            root,
            vault,
            device_id: ID_9.parse().unwrap(),
            project_id,
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
        self.vault = Vault::open(self._database.path(), CREDENTIAL, &self._keys).unwrap();
    }

    fn project_memory_count(&self) -> usize {
        self.vault
            .memories(Some(self.project_id), false)
            .unwrap()
            .len()
    }

    fn project_candidate_count(&self) -> usize {
        self.vault.candidates(Some(self.project_id)).unwrap().len()
    }

    fn create_memory(
        &mut self,
        operation_id: &str,
        scope: ScopeRef,
        title: &str,
        body: &str,
    ) -> MemoryRecord {
        OfflineWorkspace::new(&mut self.vault, self.device_id)
            .create_memory(MemoryCreateParams {
                operation_id: operation_id.parse().unwrap(),
                scope,
                kind: MemoryKind::Fact,
                title: title.to_owned(),
                body_markdown: body.to_owned(),
                tags: vec!["mcp".to_owned()],
            })
            .unwrap()
    }

    fn insert_instruction(&mut self, id: &str, operation_id: &str, scope: ScopeRef) {
        let instruction = instruction(id, scope, "MCP instruction", "follow scoped needle");
        self.vault
            .put_instruction(
                &instruction,
                &operation(operation_id, id, RecordKind::Instruction),
                &basis(1),
            )
            .unwrap();
    }
}

fn assert_operation_conflict(error: &ClientError) {
    assert_eq!(error.code, context_relay_protocol::ErrorCode::Conflict);
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
fn status_reports_the_resolved_project_and_actual_policy() {
    let mut fixture = Fixture::new(
        "mcp-status",
        HarnessAccessPolicy::ActiveProjectOnly { read_only: true },
    );

    let output = fixture.call("context_relay_status", json!({})).unwrap();

    assert_eq!(output["protocol"]["min"], json!({"major": 1, "minor": 3}));
    assert_eq!(output["protocol"]["max"], json!({"major": 1, "minor": 3}));
    assert_eq!(output["vault"], "unlocked");
    assert_eq!(output["resolvedProject"], fixture.project_id.to_string());
    assert_eq!(output["sync"], "offline");
    assert_eq!(
        output["access"],
        json!({"mode": "active_project_only", "readOnly": true})
    );
}

#[test]
fn explicit_memory_replay_returns_one_record() {
    let mut fixture = Fixture::new("mcp-remember-replay", HarnessAccessPolicy::Default);
    let input = json!({
        "operationId": ID_1,
        "kind": "note",
        "title": "Decision context",
        "markdown": "Use the daemon-owned binding.",
        "tags": ["mcp"],
        "scope": {"scope": "active_project"}
    });

    let first = fixture
        .call("context_relay_remember", input.clone())
        .unwrap();
    let second = fixture.call("context_relay_remember", input).unwrap();

    assert_eq!(first, second);
    assert_eq!(first["memory"]["origin"], "explicit");
    assert_eq!(fixture.project_memory_count(), 1);
}

#[test]
fn altered_remember_replay_conflicts_after_reopen_without_changing_the_memory() {
    let mut fixture = Fixture::new("mcp-remember-altered-replay", HarnessAccessPolicy::Default);
    let first = fixture
        .call(
            "context_relay_remember",
            json!({
                "operationId": ID_1,
                "kind": "note",
                "title": "Original",
                "markdown": "original body",
                "tags": ["first"],
                "scope": {"scope": "active_project"}
            }),
        )
        .unwrap();
    fixture.reopen();

    for altered in [
        json!({
            "operationId": ID_1,
            "kind": "note",
            "title": "Original",
            "markdown": "altered body",
            "tags": ["first"],
            "scope": {"scope": "active_project"}
        }),
        json!({
            "operationId": ID_1,
            "kind": "note",
            "title": "Original",
            "markdown": "original body",
            "tags": ["altered"],
            "scope": {"scope": "active_project"}
        }),
    ] {
        let error = fixture.call("context_relay_remember", altered).unwrap_err();
        assert_operation_conflict(&error);
    }

    let memory_id = ID_1.parse().unwrap();
    let persisted = fixture.vault.memory(&memory_id).unwrap().unwrap();
    assert_eq!(serde_json::to_value(persisted).unwrap(), first["memory"]);
    assert_eq!(fixture.project_memory_count(), 1);
}

#[test]
fn inferred_proposal_replay_is_pending_and_attributed_to_the_harness() {
    let mut fixture = Fixture::new("mcp-proposal-replay", HarnessAccessPolicy::Default);
    let input = json!({
        "operationId": ID_1,
        "kind": "pattern",
        "title": "Scoped call",
        "markdown": "Resolve the project inside the daemon.",
        "tags": ["mcp"],
        "evidenceSummary": "Repeatedly observed in tool calls.",
        "scope": {"scope": "active_project"}
    });

    let first = fixture
        .call("context_relay_propose_memory", input.clone())
        .unwrap();
    let second = fixture.call("context_relay_propose_memory", input).unwrap();

    assert_eq!(first, second);
    assert_eq!(first["candidate"]["state"], "pending");
    assert_eq!(first["candidate"]["sourceHarness"], "codex");
    assert_eq!(first["candidate"]["proposedMemory"]["origin"], "inferred");
    assert_eq!(fixture.project_candidate_count(), 1);
    assert_eq!(fixture.project_memory_count(), 0);
}

#[test]
fn altered_proposal_replay_conflicts_without_changing_the_candidate() {
    let mut fixture = Fixture::new("mcp-proposal-altered-replay", HarnessAccessPolicy::Default);
    let first = fixture
        .call(
            "context_relay_propose_memory",
            json!({
                "operationId": ID_1,
                "kind": "pattern",
                "title": "Original",
                "markdown": "original body",
                "tags": ["first"],
                "evidenceSummary": "Original evidence.",
                "scope": {"scope": "active_project"}
            }),
        )
        .unwrap();

    for altered in [
        json!({
            "operationId": ID_1,
            "kind": "pattern",
            "title": "Original",
            "markdown": "altered body",
            "tags": ["first"],
            "evidenceSummary": "Original evidence.",
            "scope": {"scope": "active_project"}
        }),
        json!({
            "operationId": ID_1,
            "kind": "pattern",
            "title": "Original",
            "markdown": "original body",
            "tags": ["altered"],
            "evidenceSummary": "Original evidence.",
            "scope": {"scope": "active_project"}
        }),
        json!({
            "operationId": ID_1,
            "kind": "pattern",
            "title": "Original",
            "markdown": "original body",
            "tags": ["first"],
            "evidenceSummary": "Altered evidence.",
            "scope": {"scope": "active_project"}
        }),
    ] {
        let error = fixture
            .call("context_relay_propose_memory", altered)
            .unwrap_err();
        assert_operation_conflict(&error);
    }

    let candidates = fixture.vault.candidates(Some(fixture.project_id)).unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(
        serde_json::to_value(&candidates[0]).unwrap(),
        first["candidate"]
    );
}

#[test]
fn get_returns_memory_instruction_and_null_for_missing_records() {
    let mut fixture = Fixture::new("mcp-get-records", HarnessAccessPolicy::Default);
    let scope = ScopeRef::Project {
        project_id: fixture.project_id,
    };
    let memory = fixture.create_memory(ID_1, scope.clone(), "MCP memory", "remember needle");
    fixture.insert_instruction(ID_2, ID_3, scope);

    let memory_output = fixture
        .call(
            "context_relay_get",
            json!({"recordId": memory.id.to_string()}),
        )
        .unwrap();
    let instruction_output = fixture
        .call("context_relay_get", json!({"recordId": ID_2}))
        .unwrap();
    let missing_output = fixture
        .call("context_relay_get", json!({"recordId": ID_4}))
        .unwrap();

    assert_eq!(memory_output["record"]["kind"], "memory");
    assert_eq!(
        memory_output["record"]["record"]["id"],
        memory.id.to_string()
    );
    assert_eq!(instruction_output["record"]["kind"], "instruction");
    assert_eq!(instruction_output["record"]["record"]["id"], ID_2);
    assert_eq!(missing_output["record"], Value::Null);
}

#[test]
fn record_id_does_not_bypass_project_scope() {
    let mut fixture = Fixture::new("mcp-get-cross-project", HarnessAccessPolicy::Default);
    let other_project = ProjectIdentity {
        project_id: ID_8.parse().unwrap(),
        github_repository_id: None,
        git_remote_fingerprint: None,
        monorepo_subdirectory: None,
        name: "Other project".to_owned(),
    };
    fixture.vault.put_project(&other_project).unwrap();
    let other = fixture.create_memory(
        ID_1,
        ScopeRef::Project {
            project_id: other_project.project_id,
        },
        "Other memory",
        "must remain scoped",
    );

    let error = fixture
        .call(
            "context_relay_get",
            json!({"recordId": other.id.to_string()}),
        )
        .unwrap_err();

    assert_eq!(error.code, context_relay_protocol::ErrorCode::ScopeDenied);
}

#[test]
fn search_returns_only_the_requested_allowed_scope_and_includes_instructions() {
    let mut fixture = Fixture::new("mcp-search-scopes", HarnessAccessPolicy::Default);
    let project_scope = ScopeRef::Project {
        project_id: fixture.project_id,
    };
    fixture.create_memory(ID_1, ScopeRef::Global, "Global needle", "global search");
    fixture.create_memory(
        ID_2,
        project_scope.clone(),
        "Project needle",
        "project search",
    );
    fixture.insert_instruction(ID_3, ID_5, ScopeRef::Global);
    fixture.insert_instruction(ID_4, ID_6, project_scope);

    let global = fixture
        .call(
            "context_relay_search",
            json!({"query": "needle", "scope": {"scope": "global"}, "limit": 10}),
        )
        .unwrap();
    let project = fixture
        .call(
            "context_relay_search",
            json!({
                "query": "needle",
                "scope": {"scope": "active_project"},
                "limit": 10
            }),
        )
        .unwrap();
    let combined = fixture
        .call(
            "context_relay_search",
            json!({"query": "needle", "limit": 10}),
        )
        .unwrap();

    assert_eq!(record_ids(&global, "memories"), vec![ID_1]);
    assert_eq!(record_ids(&global, "instructions"), vec![ID_3]);
    assert_eq!(record_ids(&project, "memories"), vec![ID_2]);
    assert_eq!(record_ids(&project, "instructions"), vec![ID_4]);
    assert_eq!(record_ids(&combined, "memories").len(), 2);
    assert_eq!(record_ids(&combined, "instructions").len(), 2);
}

fn record_ids<'a>(output: &'a Value, field: &str) -> Vec<&'a str> {
    output[field]
        .as_array()
        .unwrap()
        .iter()
        .map(|record| record["id"].as_str().unwrap())
        .collect()
}

#[test]
fn update_changes_only_markdown_and_enforces_expected_revision() {
    let mut fixture = Fixture::new("mcp-update-revision", HarnessAccessPolicy::Default);
    let memory = fixture.create_memory(
        ID_1,
        ScopeRef::Project {
            project_id: fixture.project_id,
        },
        "Preserved title",
        "original body",
    );

    let updated = fixture
        .call(
            "context_relay_update_memory",
            json!({
                "operationId": ID_2,
                "memoryId": memory.id.to_string(),
                "expectedRevision": memory.revision.to_string(),
                "markdown": "updated body"
            }),
        )
        .unwrap();
    let stale = fixture
        .call(
            "context_relay_update_memory",
            json!({
                "operationId": ID_3,
                "memoryId": memory.id.to_string(),
                "expectedRevision": memory.revision.to_string(),
                "markdown": "stale body"
            }),
        )
        .unwrap_err();

    assert_eq!(updated["memory"]["title"], "Preserved title");
    assert_eq!(updated["memory"]["tags"], json!(["mcp"]));
    assert_eq!(
        updated["memory"]["scope"]["projectId"],
        fixture.project_id.to_string()
    );
    assert_eq!(updated["memory"]["bodyMarkdown"], "updated body");
    assert_eq!(
        stale.code,
        context_relay_protocol::ErrorCode::RevisionConflict
    );
}

#[test]
fn altered_update_replay_conflicts_without_changing_the_first_update() {
    let mut fixture = Fixture::new("mcp-update-altered-replay", HarnessAccessPolicy::Default);
    let memory = fixture.create_memory(
        ID_1,
        ScopeRef::Project {
            project_id: fixture.project_id,
        },
        "Update once",
        "original",
    );
    fixture
        .call(
            "context_relay_update_memory",
            json!({
                "operationId": ID_2,
                "memoryId": memory.id.to_string(),
                "expectedRevision": memory.revision.to_string(),
                "markdown": "first update"
            }),
        )
        .unwrap();

    let error = fixture
        .call(
            "context_relay_update_memory",
            json!({
                "operationId": ID_2,
                "memoryId": memory.id.to_string(),
                "expectedRevision": memory.revision.to_string(),
                "markdown": "altered replay"
            }),
        )
        .unwrap_err();

    assert_operation_conflict(&error);
    let persisted = fixture.vault.memory(&memory.id).unwrap().unwrap();
    assert_eq!(persisted.revision.to_string(), ID_2);
    assert_eq!(persisted.body_markdown, "first update");
}

#[test]
fn update_operation_cannot_be_reused_for_another_memory() {
    let mut fixture = Fixture::new("mcp-update-cross-record", HarnessAccessPolicy::Default);
    let scope = ScopeRef::Project {
        project_id: fixture.project_id,
    };
    let first = fixture.create_memory(ID_1, scope.clone(), "First", "first");
    let second = fixture.create_memory(ID_2, scope, "Second", "second");
    fixture
        .call(
            "context_relay_update_memory",
            json!({
                "operationId": ID_3,
                "memoryId": first.id.to_string(),
                "expectedRevision": first.revision.to_string(),
                "markdown": "updated first"
            }),
        )
        .unwrap();

    let error = fixture
        .call(
            "context_relay_update_memory",
            json!({
                "operationId": ID_3,
                "memoryId": second.id.to_string(),
                "expectedRevision": second.revision.to_string(),
                "markdown": "must not update second"
            }),
        )
        .unwrap_err();

    assert_operation_conflict(&error);
    assert_eq!(
        fixture
            .vault
            .memory(&second.id)
            .unwrap()
            .unwrap()
            .body_markdown,
        "second"
    );
}

#[test]
fn archive_replays_and_enforces_expected_revision() {
    let mut fixture = Fixture::new("mcp-archive-revision", HarnessAccessPolicy::Default);
    let memory = fixture.create_memory(
        ID_1,
        ScopeRef::Project {
            project_id: fixture.project_id,
        },
        "Archive me",
        "archive body",
    );
    let input = json!({
        "operationId": ID_2,
        "memoryId": memory.id.to_string(),
        "expectedRevision": memory.revision.to_string()
    });

    let first = fixture
        .call("context_relay_archive_memory", input.clone())
        .unwrap();
    let replay = fixture.call("context_relay_archive_memory", input).unwrap();
    let stale = fixture
        .call(
            "context_relay_archive_memory",
            json!({
                "operationId": ID_3,
                "memoryId": memory.id.to_string(),
                "expectedRevision": memory.revision.to_string()
            }),
        )
        .unwrap_err();

    assert_eq!(first, replay);
    assert_eq!(first["memory"]["archived"], true);
    assert_eq!(
        stale.code,
        context_relay_protocol::ErrorCode::RevisionConflict
    );
}

#[test]
fn altered_archive_expected_revision_conflicts_without_a_second_mutation() {
    let mut fixture = Fixture::new("mcp-archive-altered-replay", HarnessAccessPolicy::Default);
    let memory = fixture.create_memory(
        ID_1,
        ScopeRef::Project {
            project_id: fixture.project_id,
        },
        "Archive once",
        "body",
    );
    fixture
        .call(
            "context_relay_archive_memory",
            json!({
                "operationId": ID_2,
                "memoryId": memory.id.to_string(),
                "expectedRevision": memory.revision.to_string()
            }),
        )
        .unwrap();

    let error = fixture
        .call(
            "context_relay_archive_memory",
            json!({
                "operationId": ID_2,
                "memoryId": memory.id.to_string(),
                "expectedRevision": ID_9
            }),
        )
        .unwrap_err();

    assert_operation_conflict(&error);
    let persisted = fixture.vault.memory(&memory.id).unwrap().unwrap();
    assert!(persisted.archived);
    assert_eq!(persisted.revision.to_string(), ID_2);
}

#[test]
fn archive_operation_cannot_be_reused_for_another_memory() {
    let mut fixture = Fixture::new("mcp-archive-cross-record", HarnessAccessPolicy::Default);
    let scope = ScopeRef::Project {
        project_id: fixture.project_id,
    };
    let first = fixture.create_memory(ID_1, scope.clone(), "First", "first");
    let second = fixture.create_memory(ID_2, scope, "Second", "second");
    fixture
        .call(
            "context_relay_archive_memory",
            json!({
                "operationId": ID_3,
                "memoryId": first.id.to_string(),
                "expectedRevision": first.revision.to_string()
            }),
        )
        .unwrap();

    let error = fixture
        .call(
            "context_relay_archive_memory",
            json!({
                "operationId": ID_3,
                "memoryId": second.id.to_string(),
                "expectedRevision": second.revision.to_string()
            }),
        )
        .unwrap_err();

    assert_operation_conflict(&error);
    let persisted = fixture.vault.memory(&second.id).unwrap().unwrap();
    assert!(!persisted.archived);
    assert_eq!(persisted.revision, second.revision);
}

#[test]
fn operation_id_cannot_cross_from_update_to_archive() {
    let mut fixture = Fixture::new("mcp-operation-cross-action", HarnessAccessPolicy::Default);
    let memory = fixture.create_memory(
        ID_1,
        ScopeRef::Project {
            project_id: fixture.project_id,
        },
        "One action",
        "original",
    );
    fixture
        .call(
            "context_relay_update_memory",
            json!({
                "operationId": ID_2,
                "memoryId": memory.id.to_string(),
                "expectedRevision": memory.revision.to_string(),
                "markdown": "updated"
            }),
        )
        .unwrap();

    let error = fixture
        .call(
            "context_relay_archive_memory",
            json!({
                "operationId": ID_2,
                "memoryId": memory.id.to_string(),
                "expectedRevision": ID_2
            }),
        )
        .unwrap_err();

    assert_operation_conflict(&error);
    let persisted = fixture.vault.memory(&memory.id).unwrap().unwrap();
    assert!(!persisted.archived);
    assert_eq!(persisted.body_markdown, "updated");
    assert_eq!(persisted.revision.to_string(), ID_2);
}

#[test]
fn remember_replay_cannot_return_another_projects_record() {
    let mut fixture = Fixture::new("mcp-remember-cross-project", HarnessAccessPolicy::Default);
    let other_project_id = ID_8.parse().unwrap();
    fixture
        .vault
        .put_project(&ProjectIdentity {
            project_id: other_project_id,
            github_repository_id: None,
            git_remote_fingerprint: None,
            monorepo_subdirectory: None,
            name: "Other project".to_owned(),
        })
        .unwrap();
    fixture.create_memory(
        ID_1,
        ScopeRef::Project {
            project_id: other_project_id,
        },
        "Other operation",
        "not an authorized replay",
    );

    let error = fixture
        .call(
            "context_relay_remember",
            json!({
                "operationId": ID_1,
                "kind": "note",
                "title": "Collision",
                "markdown": "must fail closed",
                "tags": ["mcp"],
                "scope": {"scope": "active_project"}
            }),
        )
        .unwrap_err();

    assert_eq!(error.code, context_relay_protocol::ErrorCode::ScopeDenied);
}

#[test]
fn proposal_replay_cannot_return_another_projects_candidate() {
    let mut fixture = Fixture::new("mcp-proposal-cross-project", HarnessAccessPolicy::Default);
    let mut existing = candidate();
    existing.proposed_memory.scope = ScopeRef::Project {
        project_id: ID_8.parse().unwrap(),
    };
    fixture.vault.put_candidate(&existing).unwrap();

    let error = fixture
        .call(
            "context_relay_propose_memory",
            json!({
                "operationId": ID_2,
                "kind": "note",
                "title": "Collision",
                "markdown": "must fail closed",
                "tags": ["mcp"],
                "evidenceSummary": "A replay collision.",
                "scope": {"scope": "active_project"}
            }),
        )
        .unwrap_err();

    assert_eq!(error.code, context_relay_protocol::ErrorCode::ScopeDenied);
}

#[test]
fn read_only_and_disabled_policies_block_every_memory_write() {
    for (name, policy) in [
        ("read-only", HarnessAccessPolicy::ReadOnly),
        ("disabled", HarnessAccessPolicy::Disabled),
    ] {
        let mut fixture = Fixture::new(name, policy);
        let memory = fixture.create_memory(
            ID_1,
            ScopeRef::Project {
                project_id: fixture.project_id,
            },
            "Existing",
            "existing body",
        );
        let remember = fixture
            .call(
                "context_relay_remember",
                json!({
                    "operationId": ID_2,
                    "kind": "note",
                    "title": "Denied",
                    "markdown": "denied",
                    "tags": ["mcp"],
                    "scope": {"scope": "active_project"}
                }),
            )
            .unwrap_err();
        let proposal = fixture
            .call(
                "context_relay_propose_memory",
                json!({
                    "operationId": ID_3,
                    "kind": "note",
                    "title": "Denied",
                    "markdown": "denied",
                    "tags": ["mcp"],
                    "evidenceSummary": "Must remain pending only when allowed.",
                    "scope": {"scope": "active_project"}
                }),
            )
            .unwrap_err();
        let update = fixture
            .call(
                "context_relay_update_memory",
                json!({
                    "operationId": ID_4,
                    "memoryId": memory.id.to_string(),
                    "expectedRevision": memory.revision.to_string(),
                    "markdown": "denied"
                }),
            )
            .unwrap_err();
        let archive = fixture
            .call(
                "context_relay_archive_memory",
                json!({
                    "operationId": ID_5,
                    "memoryId": memory.id.to_string(),
                    "expectedRevision": memory.revision.to_string()
                }),
            )
            .unwrap_err();

        for error in [remember, proposal, update, archive] {
            assert_eq!(
                error.code,
                context_relay_protocol::ErrorCode::ScopeDenied,
                "{name}"
            );
        }
    }
}

#[test]
fn invalid_task_and_handoff_arguments_fail_closed() {
    let mut fixture = Fixture::new("mcp-task-four-invalid", HarnessAccessPolicy::Default);

    for (name, arguments) in [
        (
            "context_relay_list_tasks",
            json!({"status": "not_a_status"}),
        ),
        ("context_relay_upsert_task", json!({})),
        ("context_relay_complete_task", json!({})),
        ("context_relay_create_handoff", json!({})),
    ] {
        let error = fixture.call(name, arguments).unwrap_err();
        assert_eq!(
            error.code,
            context_relay_protocol::ErrorCode::InvalidRequest,
            "{name}"
        );
        assert!(!error.retryable);
    }
}

#[test]
fn instruction_listing_is_bounded_to_non_archived_allowed_scopes() {
    let mut fixture = Fixture::new("mcp-instruction-list", HarnessAccessPolicy::Default);
    let project_scope = ScopeRef::Project {
        project_id: fixture.project_id,
    };
    fixture.insert_instruction(ID_2, ID_3, ScopeRef::Global);
    fixture.insert_instruction(ID_4, ID_5, project_scope.clone());
    let mut archived = instruction(ID_6, project_scope, "Archived", "archived needle");
    archived.archived = true;
    fixture
        .vault
        .put_instruction(
            &archived,
            &operation(ID_1, ID_6, RecordKind::Instruction),
            &basis(2),
        )
        .unwrap();
    let scope = AllowedSearchScope::resolve(
        Some(McpScopeSelector::ActiveProject),
        &HarnessAccessPolicy::Default,
        Some(fixture.project_id),
    )
    .unwrap();

    let instructions =
        OfflineWorkspace::new(&mut fixture.vault, fixture.device_id).instructions(&scope, 10);

    assert_eq!(
        instructions
            .unwrap()
            .into_iter()
            .map(|instruction| instruction.id.to_string())
            .collect::<Vec<_>>(),
        vec![ID_4]
    );
}

#[test]
fn search_returns_the_largest_whole_record_prefix_that_fits_the_output_budget() {
    let mut fixture = Fixture::new("mcp-search-output-budget", HarnessAccessPolicy::Default);
    let body = format!(
        "needle {}",
        "x".repeat(MAX_MARKDOWN_BYTES - "needle ".len())
    );
    let scope = ScopeRef::Project {
        project_id: fixture.project_id,
    };
    for operation_id in [ID_1, ID_2, ID_3, ID_4, ID_5, ID_6, ID_7, ID_8, ID_9] {
        fixture.create_memory(operation_id, scope.clone(), "Large record", &body);
    }

    let output = fixture
        .call(
            "context_relay_search",
            json!({
                "query": "needle",
                "scope": {"scope": "active_project"},
                "limit": 10
            }),
        )
        .unwrap();

    assert_eq!(output["memories"].as_array().unwrap().len(), 1);
    assert!(output["instructions"].as_array().unwrap().is_empty());
    assert_eq!(output["memories"][0]["id"], ID_1);
    assert_eq!(
        output["memories"][0]["bodyMarkdown"]
            .as_str()
            .unwrap()
            .len(),
        MAX_MARKDOWN_BYTES
    );
    assert!(serde_json::to_vec(&output).unwrap().len() <= MAX_IPC_FRAME_BYTES / 4);
}

#[test]
fn oversized_remember_output_does_not_persist_the_memory() {
    let mut fixture = Fixture::new("mcp-remember-output-budget", HarnessAccessPolicy::Default);

    let error = fixture
        .call(
            "context_relay_remember",
            json!({
                "operationId": ID_1,
                "kind": "note",
                "title": "Escaped output",
                "markdown": "\0".repeat(MAX_MARKDOWN_BYTES),
                "tags": ["mcp"],
                "scope": {"scope": "active_project"}
            }),
        )
        .unwrap_err();

    assert_eq!(error.code, context_relay_protocol::ErrorCode::FrameTooLarge);
    assert_eq!(error.field_path, None);
    assert!(!error.retryable);
    assert_eq!(fixture.project_memory_count(), 0);
}

#[test]
fn oversized_proposal_output_does_not_persist_the_candidate() {
    let mut fixture = Fixture::new("mcp-proposal-output-budget", HarnessAccessPolicy::Default);

    let error = fixture
        .call(
            "context_relay_propose_memory",
            json!({
                "operationId": ID_1,
                "kind": "note",
                "title": "Escaped output",
                "markdown": "\0".repeat(MAX_MARKDOWN_BYTES),
                "tags": ["mcp"],
                "evidenceSummary": "Must remain uncommitted.",
                "scope": {"scope": "active_project"}
            }),
        )
        .unwrap_err();

    assert_eq!(error.code, context_relay_protocol::ErrorCode::FrameTooLarge);
    assert_eq!(fixture.project_candidate_count(), 0);
    assert_eq!(fixture.project_memory_count(), 0);
}

#[test]
fn oversized_update_output_does_not_change_the_memory_or_revision() {
    let mut fixture = Fixture::new("mcp-update-output-budget", HarnessAccessPolicy::Default);
    let memory = fixture.create_memory(
        ID_1,
        ScopeRef::Project {
            project_id: fixture.project_id,
        },
        "Preserved",
        "original body",
    );

    let error = fixture
        .call(
            "context_relay_update_memory",
            json!({
                "operationId": ID_2,
                "memoryId": memory.id.to_string(),
                "expectedRevision": memory.revision.to_string(),
                "markdown": "\0".repeat(MAX_MARKDOWN_BYTES)
            }),
        )
        .unwrap_err();

    assert_eq!(error.code, context_relay_protocol::ErrorCode::FrameTooLarge);
    let persisted = fixture.vault.memory(&memory.id).unwrap().unwrap();
    assert_eq!(persisted.revision, memory.revision);
    assert!(
        persisted.body_markdown == memory.body_markdown,
        "the rejected update changed the stored body"
    );
}

#[test]
fn oversized_archive_output_does_not_archive_or_rev_the_memory() {
    let mut fixture = Fixture::new("mcp-archive-output-budget", HarnessAccessPolicy::Default);
    let memory = fixture.create_memory(
        ID_1,
        ScopeRef::Project {
            project_id: fixture.project_id,
        },
        "Escaped output",
        &"\0".repeat(MAX_MARKDOWN_BYTES),
    );

    let error = fixture
        .call(
            "context_relay_archive_memory",
            json!({
                "operationId": ID_2,
                "memoryId": memory.id.to_string(),
                "expectedRevision": memory.revision.to_string()
            }),
        )
        .unwrap_err();

    assert_eq!(error.code, context_relay_protocol::ErrorCode::FrameTooLarge);
    let persisted = fixture.vault.memory(&memory.id).unwrap().unwrap();
    assert_eq!(persisted.revision, memory.revision);
    assert!(!persisted.archived);
}
