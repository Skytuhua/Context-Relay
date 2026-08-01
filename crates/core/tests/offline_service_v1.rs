mod support;

use context_relay_core::{
    native_memory::{
        NativeMemoryDocumentKind, NativeMemoryLimits, NativeMemorySnapshot, NativeMemorySource,
        ReadyNativeMemory,
    },
    service::OfflineWorkspace,
    vault::{LATEST_SCHEMA_VERSION, MAX_NATIVE_HOOK_SESSIONS, Vault},
};
use context_relay_protocol::{
    CandidateReviewParams, CandidateState, CompletionEvidenceInput, ErrorCode, HarnessId,
    McpBinding, McpScopeSelector, MemoryArchiveParams, MemoryCreateParams, MemoryKind,
    MemoryUpdateParams, NativeHookEvent, NativeHookEventParams, NativePlatform, ProjectIdentity,
    ProposeMemoryInput, ScopeRef, SearchParams, TaskCompleteParams, TaskId, TaskStatus,
    TaskTransitionParams, TaskUpsertParams, WireNativeValue,
};
use rusqlite::Connection;

use support::{
    ID_1, ID_2, ID_3, ID_4, ID_5, ID_6, ID_7, ID_8, ID_9, MemoryKeyStore, TempVault, candidate,
    native_path,
};

const CREDENTIAL: &str = "offline-service-tests";

struct Fixture {
    path: TempVault,
    keys: MemoryKeyStore,
}

impl Fixture {
    fn new(name: &str) -> Self {
        Self {
            path: TempVault::new(name),
            keys: MemoryKeyStore::default(),
        }
    }

    fn vault(&self) -> Vault {
        Vault::open(self.path.path(), CREDENTIAL, &self.keys).unwrap()
    }
}

fn open_keyed(path: &std::path::Path, key: &[u8; 32]) -> Connection {
    let connection = Connection::open(path).unwrap();
    // SAFETY: the connection owns the handle, the key remains valid for the call,
    // and this is the first SQLite operation after open.
    let result = unsafe {
        rusqlite::ffi::sqlite3_key(
            connection.handle(),
            key.as_ptr().cast(),
            key.len().try_into().unwrap(),
        )
    };
    assert_eq!(result, rusqlite::ffi::SQLITE_OK);
    connection
        .query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
        .unwrap();
    connection
}

#[test]
fn migration_v10_to_v11_preserves_existing_workspace_rows() {
    let fixture = Fixture::new("native-hook-migration-v10");
    let project = ProjectIdentity {
        project_id: ID_7.parse().unwrap(),
        github_repository_id: Some(41),
        git_remote_fingerprint: None,
        monorepo_subdirectory: None,
        name: "Preserved project".into(),
    };
    let task = {
        let mut vault = fixture.vault();
        let mut service = OfflineWorkspace::new(&mut vault, ID_9.parse().unwrap());
        service.upsert_project(project.clone()).unwrap();
        service
            .upsert_task(TaskUpsertParams {
                operation_id: ID_1.parse().unwrap(),
                task_id: None,
                project_id: project.project_id,
                title: "Preserved task".into(),
                body_markdown: "Must survive the v11 migration".into(),
                status: TaskStatus::Open,
                expected_revision: None,
            })
            .unwrap()
    };

    let raw = open_keyed(fixture.path.path(), &fixture.keys.key(CREDENTIAL));
    raw.execute_batch("DROP TABLE IF EXISTS native_hook_sessions")
        .unwrap();
    raw.pragma_update(None, "user_version", 10).unwrap();
    drop(raw);

    let vault = fixture.vault();
    assert_eq!(LATEST_SCHEMA_VERSION, 11);
    assert_eq!(vault.schema_version().unwrap(), 11);
    assert_eq!(vault.projects().unwrap(), vec![project]);
    assert_eq!(vault.task(&task.id).unwrap(), Some(task));
    assert!(
        vault
            .table_names()
            .unwrap()
            .contains(&"native_hook_sessions".to_owned())
    );
}

fn hook_params(
    harness: HarnessId,
    session_id: impl Into<String>,
    event: impl FnOnce(String) -> NativeHookEvent,
    occurred_at_ms: u64,
) -> NativeHookEventParams {
    let session_id = session_id.into();
    NativeHookEventParams {
        binding: McpBinding {
            harness,
            working_directory: native_path(),
        },
        event: event(session_id),
        occurred_at_ms,
    }
}

#[test]
fn native_hook_lifecycle_replaces_one_bounded_sanitized_session_row() {
    let fixture = Fixture::new("native-hook-lifecycle");
    let raw_session = fixture.path.path().with_extension("raw-session.jsonl");
    let raw_bytes = br#"{"prompt":"PROMPT_SENTINEL","response":"RESPONSE_SENTINEL","transcript_path":"TRANSCRIPT_SENTINEL","tool_output":"TOOL_SENTINEL"}"#;
    std::fs::write(&raw_session, raw_bytes).unwrap();
    let project = ProjectIdentity {
        project_id: ID_7.parse().unwrap(),
        github_repository_id: None,
        git_remote_fingerprint: None,
        monorepo_subdirectory: None,
        name: "Hook project".into(),
    };
    {
        let mut vault = fixture.vault();
        let mut service = OfflineWorkspace::new(&mut vault, ID_9.parse().unwrap());
        service.upsert_project(project.clone()).unwrap();

        let start = hook_params(
            HarnessId::Codex,
            "session-replaced",
            |session_id| NativeHookEvent::SessionStart { session_id },
            101,
        );
        let serialized = serde_json::to_string(&start).unwrap();
        for forbidden in [
            "PROMPT_SENTINEL",
            "RESPONSE_SENTINEL",
            "TRANSCRIPT_SENTINEL",
            "TOOL_SENTINEL",
            "prompt",
            "response",
            "transcript_path",
            "tool_output",
        ] {
            assert!(!serialized.contains(forbidden));
        }
        service
            .handle_native_hook_event(project.project_id, start.clone())
            .unwrap();
        let stored = service
            .native_hook_session(HarnessId::Codex, "session-replaced")
            .unwrap()
            .unwrap();
        assert_eq!(stored.project_id, project.project_id);
        assert_eq!((stored.started_at_ms, stored.stopped_at_ms), (101, None));
        assert_eq!(stored.payload, start);

        let stop = hook_params(
            HarnessId::Codex,
            "session-replaced",
            |session_id| NativeHookEvent::SessionStop { session_id },
            202,
        );
        service
            .handle_native_hook_event(project.project_id, stop.clone())
            .unwrap();
        let stored = service
            .native_hook_session(HarnessId::Codex, "session-replaced")
            .unwrap()
            .unwrap();
        assert_eq!(
            (stored.started_at_ms, stored.stopped_at_ms),
            (101, Some(202))
        );
        assert_eq!(stored.payload, stop);
        assert_eq!(service.native_hook_session_count().unwrap(), 1);

        let replacement = hook_params(
            HarnessId::Codex,
            "session-replaced",
            |session_id| NativeHookEvent::SessionStart { session_id },
            303,
        );
        service
            .handle_native_hook_event(project.project_id, replacement.clone())
            .unwrap();
        let stored = service
            .native_hook_session(HarnessId::Codex, "session-replaced")
            .unwrap()
            .unwrap();
        assert_eq!((stored.started_at_ms, stored.stopped_at_ms), (303, None));
        assert_eq!(stored.payload, replacement);

        for index in 0..=MAX_NATIVE_HOOK_SESSIONS {
            let session_id = format!("bounded-{index:04}");
            service
                .handle_native_hook_event(
                    project.project_id,
                    hook_params(
                        HarnessId::ClaudeCode,
                        session_id,
                        |session_id| NativeHookEvent::SessionStart { session_id },
                        1_000 + index as u64,
                    ),
                )
                .unwrap();
        }
        assert_eq!(
            service.native_hook_session_count().unwrap(),
            MAX_NATIVE_HOOK_SESSIONS
        );
        assert!(
            service
                .native_hook_session(HarnessId::Codex, "session-replaced")
                .unwrap()
                .is_none(),
            "the deterministic oldest row is evicted"
        );
    }

    let raw = open_keyed(fixture.path.path(), &fixture.keys.key(CREDENTIAL));
    let payloads: Vec<Vec<u8>> = raw
        .prepare("SELECT payload_json FROM native_hook_sessions ORDER BY harness, session_id")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    for payload in payloads {
        let payload = String::from_utf8(payload).unwrap();
        for forbidden in [
            "prompt",
            "response",
            "transcript_path",
            "tool_output",
            "SENTINEL",
        ] {
            assert!(!payload.contains(forbidden));
        }
    }
    assert_eq!(std::fs::read(&raw_session).unwrap(), raw_bytes);
}

#[test]
fn native_hook_lifecycle_ordering_is_monotonic_idempotent_and_project_bound() {
    let fixture = Fixture::new("native-hook-ordering");
    let project_id = ID_7.parse().unwrap();
    let other_project_id = ID_6.parse().unwrap();
    let mut vault = fixture.vault();
    let mut service = OfflineWorkspace::new(&mut vault, ID_9.parse().unwrap());
    for (id, name) in [(project_id, "Primary"), (other_project_id, "Other")] {
        service
            .upsert_project(ProjectIdentity {
                project_id: id,
                github_repository_id: None,
                git_remote_fingerprint: None,
                monorepo_subdirectory: None,
                name: name.into(),
            })
            .unwrap();
    }

    let stop_first = hook_params(
        HarnessId::Codex,
        "ordered-stop-first",
        |session_id| NativeHookEvent::SessionStop { session_id },
        200,
    );
    service
        .handle_native_hook_event(project_id, stop_first.clone())
        .unwrap();
    let terminal = service
        .native_hook_session(HarnessId::Codex, "ordered-stop-first")
        .unwrap()
        .unwrap();
    assert_eq!(
        (terminal.started_at_ms, terminal.stopped_at_ms),
        (200, Some(200))
    );

    for occurred_at_ms in [100, 200] {
        service
            .handle_native_hook_event(
                project_id,
                hook_params(
                    HarnessId::Codex,
                    "ordered-stop-first",
                    |session_id| NativeHookEvent::SessionStart { session_id },
                    occurred_at_ms,
                ),
            )
            .unwrap();
        assert_eq!(
            service
                .native_hook_session(HarnessId::Codex, "ordered-stop-first")
                .unwrap(),
            Some(terminal.clone())
        );
    }
    assert_eq!(
        service
            .handle_native_hook_event(
                other_project_id,
                hook_params(
                    HarnessId::Codex,
                    "ordered-stop-first",
                    |session_id| NativeHookEvent::SessionStart { session_id },
                    150,
                ),
            )
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert_eq!(
        service
            .native_hook_session(HarnessId::Codex, "ordered-stop-first")
            .unwrap(),
        Some(terminal)
    );

    let reopen = hook_params(
        HarnessId::Codex,
        "ordered-stop-first",
        |session_id| NativeHookEvent::SessionStart { session_id },
        201,
    );
    service
        .handle_native_hook_event(project_id, reopen.clone())
        .unwrap();
    let reopened = service
        .native_hook_session(HarnessId::Codex, "ordered-stop-first")
        .unwrap()
        .unwrap();
    assert_eq!(
        (reopened.started_at_ms, reopened.stopped_at_ms),
        (201, None)
    );
    assert_eq!(reopened.payload, reopen);

    let start_first = hook_params(
        HarnessId::Codex,
        "ordered-start-first",
        |session_id| NativeHookEvent::SessionStart { session_id },
        100,
    );
    service
        .handle_native_hook_event(project_id, start_first.clone())
        .unwrap();
    service
        .handle_native_hook_event(
            project_id,
            hook_params(
                HarnessId::Codex,
                "ordered-start-first",
                |session_id| NativeHookEvent::SessionStop { session_id },
                50,
            ),
        )
        .unwrap();
    let open = service
        .native_hook_session(HarnessId::Codex, "ordered-start-first")
        .unwrap()
        .unwrap();
    assert_eq!((open.started_at_ms, open.stopped_at_ms), (100, None));
    assert_eq!(open.payload, start_first);

    let stop_250 = hook_params(
        HarnessId::Codex,
        "ordered-start-first",
        |session_id| NativeHookEvent::SessionStop { session_id },
        250,
    );
    service
        .handle_native_hook_event(project_id, stop_250.clone())
        .unwrap();
    let stopped_250 = service
        .native_hook_session(HarnessId::Codex, "ordered-start-first")
        .unwrap()
        .unwrap();
    assert_eq!(stopped_250.stopped_at_ms, Some(250));
    assert_eq!(stopped_250.payload, stop_250);

    let mut conflicting_equal_stop = hook_params(
        HarnessId::Codex,
        "ordered-start-first",
        |session_id| NativeHookEvent::SessionStop { session_id },
        250,
    );
    conflicting_equal_stop.binding.working_directory.display = Some("equal-but-different".into());
    for ignored in [
        hook_params(
            HarnessId::Codex,
            "ordered-start-first",
            |session_id| NativeHookEvent::SessionStop { session_id },
            240,
        ),
        conflicting_equal_stop,
    ] {
        service
            .handle_native_hook_event(project_id, ignored)
            .unwrap();
        assert_eq!(
            service
                .native_hook_session(HarnessId::Codex, "ordered-start-first")
                .unwrap(),
            Some(stopped_250.clone())
        );
    }

    let stop_300 = hook_params(
        HarnessId::Codex,
        "ordered-start-first",
        |session_id| NativeHookEvent::SessionStop { session_id },
        300,
    );
    service
        .handle_native_hook_event(project_id, stop_300.clone())
        .unwrap();
    let stopped_300 = service
        .native_hook_session(HarnessId::Codex, "ordered-start-first")
        .unwrap()
        .unwrap();
    assert_eq!(stopped_300.stopped_at_ms, Some(300));
    assert_eq!(stopped_300.payload, stop_300);

    assert_eq!(
        service
            .handle_native_hook_event(
                other_project_id,
                hook_params(
                    HarnessId::Codex,
                    "ordered-start-first",
                    |session_id| NativeHookEvent::SessionStop { session_id },
                    350,
                ),
            )
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert_eq!(
        service
            .native_hook_session(HarnessId::Codex, "ordered-start-first")
            .unwrap(),
        Some(stopped_300.clone())
    );

    service
        .handle_native_hook_event(
            project_id,
            hook_params(
                HarnessId::Codex,
                "ordered-start-first",
                |session_id| NativeHookEvent::SessionStart { session_id },
                300,
            ),
        )
        .unwrap();
    assert_eq!(
        service
            .native_hook_session(HarnessId::Codex, "ordered-start-first")
            .unwrap(),
        Some(stopped_300)
    );
    let start_301 = hook_params(
        HarnessId::Codex,
        "ordered-start-first",
        |session_id| NativeHookEvent::SessionStart { session_id },
        301,
    );
    service
        .handle_native_hook_event(project_id, start_301.clone())
        .unwrap();
    service
        .handle_native_hook_event(project_id, start_301.clone())
        .unwrap();
    let reopened = service
        .native_hook_session(HarnessId::Codex, "ordered-start-first")
        .unwrap()
        .unwrap();
    assert_eq!(
        (reopened.started_at_ms, reopened.stopped_at_ms),
        (301, None)
    );
    assert_eq!(reopened.payload, start_301);
}

#[test]
fn native_hook_task_evidence_completes_only_the_explicit_current_project_task() {
    let fixture = Fixture::new("native-hook-task-evidence");
    let raw_session = fixture.path.path().with_extension("history.jsonl");
    let raw_bytes = b"private prompt and response fixture";
    std::fs::write(&raw_session, raw_bytes).unwrap();
    let project_id = ID_7.parse().unwrap();
    let other_project_id = ID_6.parse().unwrap();
    let created = {
        let mut vault = fixture.vault();
        let mut service = OfflineWorkspace::new(&mut vault, ID_9.parse().unwrap());
        for (id, name) in [
            (project_id, "Hook project"),
            (other_project_id, "Other project"),
        ] {
            service
                .upsert_project(ProjectIdentity {
                    project_id: id,
                    github_repository_id: None,
                    git_remote_fingerprint: None,
                    monorepo_subdirectory: None,
                    name: name.into(),
                })
                .unwrap();
        }
        let created = service
            .upsert_task(TaskUpsertParams {
                operation_id: ID_1.parse().unwrap(),
                task_id: None,
                project_id,
                title: "Explicit task".into(),
                body_markdown: "Complete only from explicit evidence".into(),
                status: TaskStatus::InProgress,
                expected_revision: None,
            })
            .unwrap();
        let params = hook_params(
            HarnessId::ClaudeCode,
            "task-session",
            |session_id| NativeHookEvent::TaskEvidence {
                session_id,
                task_id: created.id,
                evidence: vec![CompletionEvidenceInput {
                    summary: "Focused checks passed".into(),
                    kind: "test".into(),
                    reference: Some("offline_service_v1".into()),
                }],
            },
            404,
        );
        service
            .handle_native_hook_event(project_id, params.clone())
            .unwrap();
        let completed = service
            .tasks(project_id)
            .unwrap()
            .into_iter()
            .find(|task| task.id == created.id)
            .unwrap();
        assert_eq!(completed.status, TaskStatus::Done);
        assert_eq!(completed.evidence.len(), 1);
        assert_eq!(completed.evidence[0].summary, "Focused checks passed");
        assert_eq!(completed.evidence[0].recorded_hlc.physical_ms, 404);
        assert_ne!(completed.revision, created.revision);
        assert_eq!(service.native_hook_session_count().unwrap(), 0);

        let mut later_delivery = params.clone();
        later_delivery.occurred_at_ms = 9_999;
        later_delivery.binding.working_directory.bytes = r"C:\different\delivery\cwd"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        later_delivery.binding.working_directory.display =
            Some(r"C:\different\delivery\cwd".into());
        service
            .handle_native_hook_event(project_id, later_delivery)
            .unwrap();
        assert_eq!(service.tasks(project_id).unwrap(), vec![completed]);

        let stale = hook_params(
            HarnessId::ClaudeCode,
            "task-session",
            |session_id| NativeHookEvent::TaskEvidence {
                session_id,
                task_id: created.id,
                evidence: vec![CompletionEvidenceInput {
                    summary: "Different later evidence".into(),
                    kind: "test".into(),
                    reference: None,
                }],
            },
            405,
        );
        assert_eq!(
            service
                .handle_native_hook_event(project_id, stale)
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
        assert_eq!(
            service
                .handle_native_hook_event(other_project_id, params.clone())
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
        let missing = hook_params(
            HarnessId::ClaudeCode,
            "task-session",
            |session_id| NativeHookEvent::TaskEvidence {
                session_id,
                task_id: ID_5.parse::<TaskId>().unwrap(),
                evidence: vec![CompletionEvidenceInput {
                    summary: "Must not infer a task".into(),
                    kind: "test".into(),
                    reference: None,
                }],
            },
            406,
        );
        assert_eq!(
            service
                .handle_native_hook_event(project_id, missing)
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
        created
    };

    let raw = open_keyed(fixture.path.path(), &fixture.keys.key(CREDENTIAL));
    let (kind, target_id, expected_revision): (String, String, Option<String>) = raw
        .query_row(
            "SELECT operation_kind, target_id, expected_revision
             FROM local_operation_bindings
             WHERE operation_kind = 'task_complete'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(kind, "task_complete");
    assert_eq!(target_id, created.id.to_string());
    assert_eq!(expected_revision, Some(created.revision.to_string()));
    let binding_count: i64 = raw
        .query_row(
            "SELECT count(*) FROM local_operation_bindings WHERE operation_kind = 'task_complete'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(binding_count, 1, "replay must reuse the completion binding");
    assert_eq!(std::fs::read(&raw_session).unwrap(), raw_bytes);
}

fn create(operation_id: &str, title: &str, body: &str) -> MemoryCreateParams {
    MemoryCreateParams {
        operation_id: operation_id.parse().unwrap(),
        scope: ScopeRef::Global,
        kind: MemoryKind::Fact,
        title: title.to_owned(),
        body_markdown: body.to_owned(),
        tags: vec!["offline".to_owned()],
    }
}

#[test]
fn memory_lifecycle_is_searchable_and_revision_safe() {
    let fixture = Fixture::new("memory-lifecycle");
    let mut vault = fixture.vault();
    let device = ID_9.parse().unwrap();
    let mut service = OfflineWorkspace::new(&mut vault, device);
    let created = service
        .create_memory(create(ID_1, "Alpha", "the first searchable note"))
        .unwrap();
    service
        .create_memory(create(ID_2, "Beta", "a separate note"))
        .unwrap();

    assert_eq!(service.memory(created.id).unwrap(), Some(created.clone()));
    assert_eq!(
        service
            .search_memories(SearchParams {
                query: "first".to_owned(),
                project_id: None,
            })
            .unwrap()[0]
            .id,
        created.id
    );

    let updated = service
        .update_memory(MemoryUpdateParams {
            operation_id: ID_3.parse().unwrap(),
            memory_id: created.id,
            expected_revision: created.revision,
            title: Some("Alpha updated".to_owned()),
            body_markdown: None,
            tags: None,
        })
        .unwrap();
    assert_eq!(updated.title, "Alpha updated");

    let error = service
        .update_memory(MemoryUpdateParams {
            operation_id: ID_4.parse().unwrap(),
            memory_id: created.id,
            expected_revision: created.revision,
            title: Some("stale".to_owned()),
            body_markdown: None,
            tags: None,
        })
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::RevisionConflict);
    assert_eq!(
        service.memory(created.id).unwrap().unwrap().title,
        "Alpha updated"
    );

    let archived = service
        .archive_memory(MemoryArchiveParams {
            operation_id: ID_5.parse().unwrap(),
            memory_id: created.id,
            expected_revision: updated.revision,
        })
        .unwrap();
    assert!(archived.archived);
    assert!(
        service
            .search_memories(SearchParams {
                query: "first".to_owned(),
                project_id: None,
            })
            .unwrap()
            .is_empty()
    );
}

#[test]
fn altered_operation_retry_is_rejected_without_changing_the_first_result() {
    let fixture = Fixture::new("operation-retry");
    let mut vault = fixture.vault();
    let mut service = OfflineWorkspace::new(&mut vault, ID_9.parse().unwrap());
    let first = service
        .create_memory(create(ID_1, "First", "original"))
        .unwrap();
    let error = service
        .create_memory(create(ID_1, "Changed retry", "different"))
        .unwrap_err();

    assert_eq!(error.code, ErrorCode::Conflict);
    assert_eq!(service.memory(first.id).unwrap(), Some(first));
}

#[test]
fn create_replay_returns_the_original_snapshot_after_an_update() {
    let fixture = Fixture::new("create-replay-snapshot");
    let mut vault = fixture.vault();
    let mut service = OfflineWorkspace::new(&mut vault, ID_9.parse().unwrap());
    let params = create(ID_1, "Created", "original");
    let created = service.create_memory(params.clone()).unwrap();
    let updated = service
        .update_memory(MemoryUpdateParams {
            operation_id: ID_2.parse().unwrap(),
            memory_id: created.id,
            expected_revision: created.revision,
            title: None,
            body_markdown: Some("updated".to_owned()),
            tags: None,
        })
        .unwrap();

    let replay = service.create_memory(params).unwrap();

    assert_eq!(replay, created);
    assert_eq!(service.memory(created.id).unwrap(), Some(updated));
}

#[test]
fn update_replay_returns_its_snapshot_after_a_later_update() {
    let fixture = Fixture::new("update-replay-snapshot");
    let (created, first_params, first, second) = {
        let mut vault = fixture.vault();
        let mut service = OfflineWorkspace::new(&mut vault, ID_9.parse().unwrap());
        let created = service
            .create_memory(create(ID_1, "Created", "original"))
            .unwrap();
        let first_params = MemoryUpdateParams {
            operation_id: ID_2.parse().unwrap(),
            memory_id: created.id,
            expected_revision: created.revision,
            title: None,
            body_markdown: Some("update A".to_owned()),
            tags: None,
        };
        let first = service.update_memory(first_params.clone()).unwrap();
        let second = service
            .update_memory(MemoryUpdateParams {
                operation_id: ID_3.parse().unwrap(),
                memory_id: created.id,
                expected_revision: first.revision,
                title: None,
                body_markdown: Some("update B".to_owned()),
                tags: None,
            })
            .unwrap();
        (created, first_params, first, second)
    };
    let mut vault = fixture.vault();
    let mut service = OfflineWorkspace::new(&mut vault, ID_9.parse().unwrap());

    let replay = service.update_memory(first_params).unwrap();

    assert_eq!(replay, first);
    assert_eq!(replay.body_markdown, "update A");
    assert_eq!(replay.revision.to_string(), ID_2);
    assert_eq!(service.memory(created.id).unwrap(), Some(second));
}

#[test]
fn archive_replay_returns_its_snapshot_after_a_later_update() {
    let fixture = Fixture::new("archive-replay-snapshot");
    let mut vault = fixture.vault();
    let mut service = OfflineWorkspace::new(&mut vault, ID_9.parse().unwrap());
    let created = service
        .create_memory(create(ID_1, "Created", "original"))
        .unwrap();
    let archive_params = MemoryArchiveParams {
        operation_id: ID_2.parse().unwrap(),
        memory_id: created.id,
        expected_revision: created.revision,
    };
    let archived = service.archive_memory(archive_params.clone()).unwrap();
    let updated = service
        .update_memory(MemoryUpdateParams {
            operation_id: ID_3.parse().unwrap(),
            memory_id: created.id,
            expected_revision: archived.revision,
            title: None,
            body_markdown: Some("updated after archive".to_owned()),
            tags: None,
        })
        .unwrap();

    let replay = service.archive_memory(archive_params).unwrap();

    assert_eq!(replay, archived);
    assert!(replay.archived);
    assert_eq!(replay.revision.to_string(), ID_2);
    assert_eq!(service.memory(created.id).unwrap(), Some(updated));
}

#[test]
fn proposal_replay_returns_the_pending_snapshot_after_review() {
    for accepted in [true, false] {
        let fixture = Fixture::new(if accepted {
            "proposal-replay-after-accept"
        } else {
            "proposal-replay-after-reject"
        });
        let mut vault = fixture.vault();
        let mut service = OfflineWorkspace::new(&mut vault, ID_9.parse().unwrap());
        let input = ProposeMemoryInput {
            operation_id: ID_1.parse().unwrap(),
            kind: MemoryKind::Pattern,
            title: "Proposed".to_owned(),
            markdown: "pending body".to_owned(),
            tags: vec!["offline".to_owned()],
            evidence_summary: "Observed repeatedly.".to_owned(),
            scope: McpScopeSelector::Global,
        };
        let pending = service
            .propose_memory(input.clone(), ScopeRef::Global, HarnessId::Codex)
            .unwrap();
        let reviewed = service
            .review_candidate(CandidateReviewParams {
                candidate_id: pending.id,
                accepted,
                operation_id: ID_2.parse().unwrap(),
            })
            .unwrap();

        let replay = service
            .propose_memory(input, ScopeRef::Global, HarnessId::Codex)
            .unwrap();

        assert_eq!(replay, pending);
        assert_eq!(replay.state, CandidateState::Pending);
        assert_eq!(service.candidates(None).unwrap()[0].state, reviewed.state);
    }
}

#[test]
fn candidate_review_and_task_completion_persist_real_state() {
    let fixture = Fixture::new("candidate-task");
    let mut vault = fixture.vault();
    let pending = candidate();
    vault.put_candidate(&pending).unwrap();
    let mut service = OfflineWorkspace::new(&mut vault, ID_9.parse().unwrap());

    let accepted = service
        .review_candidate(CandidateReviewParams {
            candidate_id: pending.id,
            accepted: true,
            operation_id: ID_4.parse().unwrap(),
        })
        .unwrap();
    assert_eq!(
        accepted.state,
        context_relay_protocol::CandidateState::Accepted
    );
    assert_eq!(
        service.memory(pending.proposed_memory.id).unwrap(),
        Some(pending.proposed_memory)
    );

    let created = service
        .upsert_task(TaskUpsertParams {
            operation_id: ID_5.parse().unwrap(),
            task_id: None,
            project_id: ID_7.parse().unwrap(),
            title: "Ship".to_owned(),
            body_markdown: "Finish locally".to_owned(),
            status: TaskStatus::Open,
            expected_revision: None,
        })
        .unwrap();
    let in_progress = service
        .transition_task(TaskTransitionParams {
            operation_id: ID_6.parse().unwrap(),
            task_id: created.id,
            expected_revision: created.revision,
            status: TaskStatus::InProgress,
        })
        .unwrap();
    let completed = service
        .complete_task(TaskCompleteParams {
            operation_id: ID_8.parse().unwrap(),
            task_id: created.id,
            expected_revision: in_progress.revision,
            evidence: vec![CompletionEvidenceInput {
                summary: "All focused checks passed".to_owned(),
                kind: "test".to_owned(),
                reference: Some("offline_service_v1".to_owned()),
            }],
        })
        .unwrap();

    assert_eq!(completed.status, TaskStatus::Done);
    assert_eq!(completed.evidence.len(), 1);
    assert_eq!(
        service.tasks(ID_7.parse().unwrap()).unwrap(),
        vec![completed]
    );
}

#[test]
fn native_candidate_review_preserves_import_ledger_for_accept_and_reject() {
    for accepted in [true, false] {
        let fixture = Fixture::new(if accepted {
            "native-review-accepted"
        } else {
            "native-review-rejected"
        });
        let mut vault = fixture.vault();
        let source = NativeMemorySource::new(
            HarnessId::Codex,
            "test-1.0.0",
            ScopeRef::Global,
            NativeMemoryDocumentKind::Agent,
            WireNativeValue {
                platform: NativePlatform::Macos,
                bytes: b"/tmp/context-relay/review.md".to_vec(),
                display: Some("/tmp/context-relay/review.md".to_owned()),
            },
            NativeMemoryLimits {
                max_bytes: 4_096,
                max_characters: 4_096,
            },
            true,
        )
        .unwrap();
        let pending = OfflineWorkspace::new(&mut vault, ID_9.parse().unwrap())
            .reconcile_native_memory(ReadyNativeMemory {
                source: source.clone(),
                snapshot: NativeMemorySnapshot::Regular(b"review this native memory".to_vec()),
            })
            .unwrap()
            .unwrap();
        let ledger_before = vault.native_memory_ledger(&source.id).unwrap().unwrap();

        let reviewed = OfflineWorkspace::new(&mut vault, ID_9.parse().unwrap())
            .review_candidate(CandidateReviewParams {
                candidate_id: pending.id,
                accepted,
                operation_id: ID_4.parse().unwrap(),
            })
            .unwrap();

        assert_eq!(
            reviewed.state,
            if accepted {
                CandidateState::Accepted
            } else {
                CandidateState::Rejected
            }
        );
        assert_eq!(
            vault.memory(&pending.proposed_memory.id).unwrap().is_some(),
            accepted
        );
        assert_eq!(
            vault.native_memory_ledger(&source.id).unwrap(),
            Some(ledger_before)
        );
    }
}

#[test]
fn task_transition_replay_returns_its_snapshot_after_later_mutation_and_reopen() {
    let fixture = Fixture::new("task-transition-replay");
    let (params, transitioned, later) = {
        let mut vault = fixture.vault();
        let mut service = OfflineWorkspace::new(&mut vault, ID_9.parse().unwrap());
        let created = service
            .upsert_task(TaskUpsertParams {
                operation_id: ID_1.parse().unwrap(),
                task_id: None,
                project_id: ID_7.parse().unwrap(),
                title: "Transition replay".to_owned(),
                body_markdown: "Preserve the first transition snapshot".to_owned(),
                status: TaskStatus::Open,
                expected_revision: None,
            })
            .unwrap();
        let params = TaskTransitionParams {
            operation_id: ID_2.parse().unwrap(),
            task_id: created.id,
            expected_revision: created.revision,
            status: TaskStatus::InProgress,
        };
        let transitioned = service.transition_task(params.clone()).unwrap();
        let later = service
            .transition_task(TaskTransitionParams {
                operation_id: ID_3.parse().unwrap(),
                task_id: created.id,
                expected_revision: transitioned.revision,
                status: TaskStatus::Blocked,
            })
            .unwrap();
        (params, transitioned, later)
    };

    let mut vault = fixture.vault();
    let mut service = OfflineWorkspace::new(&mut vault, ID_9.parse().unwrap());
    let replay = service.transition_task(params.clone()).unwrap();
    let altered = service
        .transition_task(TaskTransitionParams {
            status: TaskStatus::Canceled,
            ..params
        })
        .unwrap_err();

    assert_eq!(replay, transitioned);
    assert_eq!(altered.code, ErrorCode::Conflict);
    assert_eq!(
        service
            .tasks(ID_7.parse().unwrap())
            .unwrap()
            .into_iter()
            .find(|task| task.id == later.id),
        Some(later)
    );
}

#[test]
fn task_transition_cannot_reuse_an_operation_bound_by_task_upsert() {
    let fixture = Fixture::new("task-transition-cross-path-collision");
    let mut vault = fixture.vault();
    let mut service = OfflineWorkspace::new(&mut vault, ID_9.parse().unwrap());
    service
        .upsert_task(TaskUpsertParams {
            operation_id: ID_1.parse().unwrap(),
            task_id: None,
            project_id: ID_7.parse().unwrap(),
            title: "First task".to_owned(),
            body_markdown: "Owns operation one".to_owned(),
            status: TaskStatus::Open,
            expected_revision: None,
        })
        .unwrap();
    let second = service
        .upsert_task(TaskUpsertParams {
            operation_id: ID_2.parse().unwrap(),
            task_id: None,
            project_id: ID_7.parse().unwrap(),
            title: "Second task".to_owned(),
            body_markdown: "Must not accept operation one".to_owned(),
            status: TaskStatus::Open,
            expected_revision: None,
        })
        .unwrap();

    let error = service
        .transition_task(TaskTransitionParams {
            operation_id: ID_1.parse().unwrap(),
            task_id: second.id,
            expected_revision: second.revision,
            status: TaskStatus::Blocked,
        })
        .unwrap_err();

    assert_eq!(error.code, ErrorCode::Conflict);
    assert_eq!(
        service
            .tasks(ID_7.parse().unwrap())
            .unwrap()
            .into_iter()
            .find(|task| task.id == second.id),
        Some(second)
    );
}

#[test]
fn project_and_native_path_mapping_round_trip_through_the_service() {
    let fixture = Fixture::new("project-path");
    let mut vault = fixture.vault();
    let mut service = OfflineWorkspace::new(&mut vault, ID_9.parse().unwrap());
    let project = ProjectIdentity {
        project_id: ID_7.parse().unwrap(),
        github_repository_id: Some(42),
        git_remote_fingerprint: None,
        monorepo_subdirectory: Some("crates/core".to_owned()),
        name: "Context Relay".to_owned(),
    };

    service.upsert_project(project.clone()).unwrap();
    service
        .set_project_path(project.project_id, native_path())
        .unwrap();

    assert_eq!(service.projects().unwrap(), vec![project.clone()]);
    assert_eq!(
        service.project_path(project.project_id).unwrap(),
        Some(native_path())
    );
    assert_eq!(
        service.access_policy(HarnessId::ClaudeCode).unwrap(),
        context_relay_protocol::HarnessAccessPolicy::Default
    );
}
