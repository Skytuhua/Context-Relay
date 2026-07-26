mod support;

use context_relay_core::{service::OfflineWorkspace, vault::Vault};
use context_relay_protocol::{
    CandidateReviewParams, CompletionEvidenceInput, ErrorCode, HarnessId, MemoryArchiveParams,
    MemoryCreateParams, MemoryKind, MemoryUpdateParams, ProjectIdentity, ScopeRef, SearchParams,
    TaskCompleteParams, TaskStatus, TaskTransitionParams, TaskUpsertParams,
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
fn repeating_an_operation_returns_the_first_committed_result() {
    let fixture = Fixture::new("operation-retry");
    let mut vault = fixture.vault();
    let mut service = OfflineWorkspace::new(&mut vault, ID_9.parse().unwrap());
    let first = service
        .create_memory(create(ID_1, "First", "original"))
        .unwrap();
    let retry = service
        .create_memory(create(ID_1, "Changed retry", "different"))
        .unwrap();

    assert_eq!(retry, first);
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
