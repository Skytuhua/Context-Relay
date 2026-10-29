mod support;

use context_relay_core::vault::Vault;
use context_relay_protocol::{ErrorCode, LocalResult, MAX_IPC_FRAME_BYTES, ScopeRef};
use support::{MemoryKeyStore, TempVault, basis, memory};

fn id(index: u16) -> String {
    format!("018f22e2-79b0-7cc8-98c4-dc0c0c07{index:04x}")
}

#[test]
fn memory_pages_bound_encoded_bytes_and_visit_every_record_once() {
    let path = TempVault::new("memory-list-pages");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), "pages", &keys).unwrap();
    let body = "x".repeat(64 * 1024);
    let mut expected = Vec::new();
    for index in (0..128).rev() {
        let value = memory(&id(index), ScopeRef::Global, "Large note", &body);
        expected.push(value.id);
        vault.put_local_memory(&value, &basis(0)).unwrap();
    }
    expected.sort();
    let mut cursor = None;
    let mut actual = Vec::new();
    let mut pages = 0;
    loop {
        let page = vault.memories_page(None, false, cursor.as_deref()).unwrap();
        let encoded =
            serde_json::to_vec(&LocalResult::MemoriesPage { page: page.clone() }).unwrap();
        assert!(encoded.len() < MAX_IPC_FRAME_BYTES);
        assert!(!page.memories.is_empty());
        actual.extend(page.memories.into_iter().map(|item| item.id));
        pages += 1;
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
        assert!(pages < 10);
    }
    assert!(pages > 1);
    assert_eq!(actual, expected);
}

#[test]
fn page_cursors_reject_invalid_and_different_scope_or_filters() {
    let path = TempVault::new("memory-list-cursor");
    let keys = MemoryKeyStore::default();
    let vault = Vault::open(path.path(), "pages", &keys).unwrap();
    let oversized_cursor = "x".repeat(1025);
    for cursor in [
        "bad",
        "v1:memories:global:0:garbage",
        oversized_cursor.as_str(),
    ] {
        assert_eq!(
            vault
                .memories_page(None, false, Some(cursor))
                .unwrap_err()
                .code,
            ErrorCode::InvalidRequest
        );
    }
    let cursor = format!("v1:memories:global:0:{}", id(1));
    assert_eq!(
        vault
            .memories_page(None, true, Some(&cursor))
            .unwrap_err()
            .code,
        ErrorCode::InvalidRequest
    );
    assert_eq!(
        vault
            .memories_page(Some(id(2).parse().unwrap()), false, Some(&cursor))
            .unwrap_err()
            .code,
        ErrorCode::InvalidRequest
    );
    assert_eq!(
        vault.candidates_page(None, Some(&cursor)).unwrap_err().code,
        ErrorCode::InvalidRequest
    );
}

#[test]
fn escaped_markdown_is_measured_after_json_encoding() {
    let path = TempVault::new("memory-list-escaped-pages");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), "pages", &keys).unwrap();
    let body = format!("a{}", "\0".repeat(1024 * 1024 - 1));
    for index in 0..2 {
        vault
            .put_local_memory(
                &memory(&id(index), ScopeRef::Global, "Escaped", &body),
                &basis(0),
            )
            .unwrap();
    }
    let first = vault.memories_page(None, false, None).unwrap();
    assert_eq!(first.memories.len(), 1);
    let second = vault
        .memories_page(None, false, first.next_cursor.as_deref())
        .unwrap();
    assert_eq!(second.memories.len(), 1);
    assert!(second.next_cursor.is_none());
    for page in [first, second] {
        assert!(
            serde_json::to_vec(&LocalResult::MemoriesPage { page })
                .unwrap()
                .len()
                < MAX_IPC_FRAME_BYTES
        );
    }
}

#[test]
fn task_pages_preserve_status_scope_and_report_a_single_oversized_record() {
    let path = TempVault::new("task-list-pages");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), "pages", &keys).unwrap();
    let mut task = support::task();
    let project = task.project_id;
    task.body_markdown = "x".repeat(64 * 1024);
    for index in 1..5 {
        task.id = id(index).parse().unwrap();
        task.status = if index == 2 {
            context_relay_protocol::TaskStatus::Done
        } else {
            context_relay_protocol::TaskStatus::Open
        };
        if index == 2 {
            task.evidence = vec![context_relay_protocol::TaskEvidence {
                summary: "Test complete".into(),
                evidence_kind: "test".into(),
                reference: None,
                recorded_hlc: support::clock(1),
            }];
        } else {
            task.evidence.clear();
        }
        vault.put_task(&task).unwrap();
    }
    let first = vault
        .tasks_page(
            project,
            Some(context_relay_protocol::TaskStatus::Open),
            None,
            70_000,
        )
        .unwrap();
    assert_eq!(first.tasks.len(), 1);
    let cursor = first.next_cursor.as_deref().unwrap();
    assert_eq!(
        vault
            .tasks_page(project, None, Some(cursor), 70_000)
            .unwrap_err()
            .code,
        ErrorCode::InvalidRequest
    );
    assert_eq!(
        vault
            .tasks_page(
                id(99).parse().unwrap(),
                Some(context_relay_protocol::TaskStatus::Open),
                Some(cursor),
                70_000
            )
            .unwrap_err()
            .code,
        ErrorCode::InvalidRequest
    );
    let second = vault
        .tasks_page(
            project,
            Some(context_relay_protocol::TaskStatus::Open),
            Some(cursor),
            70_000,
        )
        .unwrap();
    assert_eq!(second.tasks[0].id.to_string(), id(3));
    assert_eq!(
        vault
            .tasks_page(project, None, None, 1024)
            .unwrap_err()
            .code,
        ErrorCode::FrameTooLarge
    );
}

#[test]
fn candidate_and_project_pages_preserve_scope_and_count_continuation() {
    use context_relay_protocol::{MAX_LIST_PAGE_ITEMS, ProjectIdentity};
    let path = TempVault::new("other-list-pages");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), "pages", &keys).unwrap();
    let body = "x".repeat(64 * 1024);
    for index in 0..129 {
        let mut candidate = support::candidate();
        candidate.id = id(index).parse().unwrap();
        candidate.proposed_memory = memory(&id(index), ScopeRef::Global, "Candidate", &body);
        vault.put_candidate(&candidate).unwrap();
        vault
            .put_project(&ProjectIdentity {
                project_id: id(index).parse().unwrap(),
                github_repository_id: None,
                git_remote_fingerprint: None,
                monorepo_subdirectory: None,
                name: "Project".into(),
            })
            .unwrap();
    }
    let project_first = vault.projects_page(None).unwrap();
    assert_eq!(project_first.projects.len(), MAX_LIST_PAGE_ITEMS);
    let project_last = vault
        .projects_page(project_first.next_cursor.as_deref())
        .unwrap();
    assert_eq!(project_last.projects.len(), 1);
    assert!(project_last.next_cursor.is_none());
    let candidate_first = vault.candidates_page(None, None).unwrap();
    assert!(candidate_first.candidates.len() < MAX_LIST_PAGE_ITEMS);
    let candidate_last = vault
        .candidates_page(None, candidate_first.next_cursor.as_deref())
        .unwrap();
    assert!(candidate_last.next_cursor.is_none());
    assert_eq!(
        candidate_first.candidates.len() + candidate_last.candidates.len(),
        129
    );
    assert!(
        vault
            .candidates_page(Some(id(1).parse().unwrap()), None)
            .unwrap()
            .candidates
            .is_empty()
    );
}
