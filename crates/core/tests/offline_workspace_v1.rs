mod support;

use context_relay_core::vault::{LATEST_SCHEMA_VERSION, Vault};
use context_relay_protocol::{
    CandidateId, CandidateState, HarnessAccessPolicy, HarnessId, ProjectId, ProjectIdentity,
    ScopeRef, TaskId,
};

use support::{
    ID_1, ID_2, ID_3, ID_4, ID_5, ID_6, ID_7, MemoryKeyStore, TempVault, basis, candidate, memory,
    task,
};

const CREDENTIAL: &str = "offline-workspace-tests";

fn project(id: &str, name: &str) -> ProjectIdentity {
    ProjectIdentity {
        project_id: id.parse::<ProjectId>().unwrap(),
        github_repository_id: None,
        git_remote_fingerprint: None,
        monorepo_subdirectory: None,
        name: name.to_owned(),
    }
}

#[test]
fn offline_records_survive_restart_and_remain_scope_filtered() {
    let path = TempVault::new("offline-restart");
    let keys = MemoryKeyStore::default();
    let alpha = project(ID_7, "Alpha");
    let beta = project(ID_6, "Beta");
    let alpha_memory = memory(
        ID_1,
        ScopeRef::Project {
            project_id: alpha.project_id,
        },
        "Alpha memory",
        "alpha",
    );
    let global_memory = memory(ID_2, ScopeRef::Global, "Global memory", "global");
    let mut archived_memory = memory(
        ID_3,
        ScopeRef::Project {
            project_id: alpha.project_id,
        },
        "Archived memory",
        "archived",
    );
    archived_memory.archived = true;
    let mut alpha_candidate = candidate();
    alpha_candidate.id = ID_4.parse::<CandidateId>().unwrap();
    alpha_candidate.proposed_memory = memory(
        ID_4,
        ScopeRef::Project {
            project_id: alpha.project_id,
        },
        "Candidate",
        "candidate",
    );
    let mut alpha_task = task();
    alpha_task.id = ID_5.parse::<TaskId>().unwrap();
    alpha_task.project_id = alpha.project_id;

    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault.put_project(&beta).unwrap();
    vault.put_project(&alpha).unwrap();
    vault.put_local_memory(&alpha_memory, &basis(0)).unwrap();
    vault.put_local_memory(&global_memory, &basis(1)).unwrap();
    vault.put_local_memory(&archived_memory, &basis(2)).unwrap();
    vault.put_candidate(&alpha_candidate).unwrap();
    vault.put_task(&alpha_task).unwrap();
    vault
        .set_access_policy(
            HarnessId::ClaudeCode,
            &HarnessAccessPolicy::SelectedProject {
                project_id: alpha.project_id,
                read_only: true,
            },
        )
        .unwrap();
    drop(vault);

    let vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(vault.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
    assert_eq!(vault.projects().unwrap(), vec![alpha.clone(), beta]);
    assert_eq!(
        vault.memories(Some(alpha.project_id), false).unwrap(),
        vec![alpha_memory.clone()]
    );
    assert_eq!(
        vault.memories(Some(alpha.project_id), true).unwrap(),
        vec![alpha_memory, archived_memory]
    );
    assert_eq!(vault.memories(None, false).unwrap(), vec![global_memory]);
    assert_eq!(
        vault.candidates(Some(alpha.project_id)).unwrap(),
        vec![alpha_candidate]
    );
    assert_eq!(vault.tasks(alpha.project_id).unwrap(), vec![alpha_task]);
    assert_eq!(
        vault.access_policy(HarnessId::ClaudeCode).unwrap(),
        HarnessAccessPolicy::SelectedProject {
            project_id: alpha.project_id,
            read_only: true,
        }
    );
    assert_eq!(
        vault.access_policy(HarnessId::Codex).unwrap(),
        HarnessAccessPolicy::Default
    );
}

#[test]
fn repeated_local_writes_replace_the_same_records_without_outbox_entries() {
    let path = TempVault::new("offline-idempotency");
    let keys = MemoryKeyStore::default();
    let project = project(ID_7, "Project");
    let mut stored = memory(ID_1, ScopeRef::Global, "Original", "body");
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();

    vault.put_project(&project).unwrap();
    vault.put_project(&project).unwrap();
    vault.put_local_memory(&stored, &basis(0)).unwrap();
    stored.title = "Updated".to_owned();
    vault.put_local_memory(&stored, &basis(1)).unwrap();

    assert_eq!(vault.projects().unwrap(), vec![project]);
    assert_eq!(vault.memories(None, false).unwrap(), vec![stored]);
    assert!(vault.outbox_operations().unwrap().is_empty());
}

#[test]
fn accepting_a_candidate_commits_the_memory_and_review_state_together() {
    let path = TempVault::new("offline-candidate-review");
    let keys = MemoryKeyStore::default();
    let candidate = candidate();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault.put_candidate(&candidate).unwrap();

    vault
        .review_candidate(
            candidate.id,
            CandidateState::Accepted,
            Some(&candidate.proposed_memory),
            Some(&basis(0)),
        )
        .unwrap();

    let mut accepted = candidate.clone();
    accepted.state = CandidateState::Accepted;
    assert_eq!(vault.candidate(&candidate.id).unwrap(), Some(accepted));
    assert_eq!(
        vault.memory(&candidate.proposed_memory.id).unwrap(),
        Some(candidate.proposed_memory)
    );
    assert!(vault.outbox_operations().unwrap().is_empty());
}
