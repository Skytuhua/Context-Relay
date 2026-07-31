mod support;

use context_relay_core::{service::OfflineWorkspace, vault::Vault};
use context_relay_protocol::{
    CandidateReviewParams, CandidateState, CompletionEvidenceInput, ErrorCode, HarnessId,
    McpScopeSelector, MemoryArchiveParams, MemoryCreateParams, MemoryKind, MemoryUpdateParams,
    ProjectIdentity, ProposeMemoryInput, ScopeRef, SearchParams, TaskCompleteParams, TaskStatus,
    TaskTransitionParams, TaskUpsertParams,
};

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
