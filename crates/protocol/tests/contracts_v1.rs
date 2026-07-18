mod support;

use context_relay_protocol::{
    ApprovalClass, CandidateState, HarnessAccessPolicy, HarnessId, MemoryKind, MemoryOrigin,
    ProjectId, ScopeRef, TaskStatus, ValidationError,
};
use std::str::FromStr;

#[test]
fn enum_wire_names_and_unknown_fields_are_strict() {
    assert_eq!(
        serde_json::to_string(&HarnessId::ClaudeCode).unwrap(),
        r#""claude_code""#
    );
    assert_eq!(
        serde_json::to_string(&TaskStatus::InProgress).unwrap(),
        r#""in_progress""#
    );
    assert_eq!(
        serde_json::to_string(&MemoryKind::Procedure).unwrap(),
        r#""procedure""#
    );
    assert_eq!(
        serde_json::to_string(&MemoryOrigin::NativeImport).unwrap(),
        r#""native_import""#
    );
    assert_eq!(
        serde_json::to_string(&CandidateState::Pending).unwrap(),
        r#""pending""#
    );
    assert_eq!(
        serde_json::to_string(&ApprovalClass::Active).unwrap(),
        r#""active""#
    );
}

#[test]
fn record_validation_rejects_blank_text_but_preserves_markdown() {
    let mut record = support::memory_record();
    record.title = "   ".into();
    assert_eq!(
        record.validate(),
        Err(ValidationError::EmptyRequired("title"))
    );
    record.title = " title ".into();
    record.body_markdown = "\n# Keep bytes  \n".into();
    record.validate().unwrap();
    assert_eq!(record.body_markdown, "\n# Keep bytes  \n");
}

#[test]
fn task_evidence_requires_nonempty_summary() {
    assert!(support::task_evidence(" ").validate().is_err());
}

#[test]
fn access_policy_denies_other_projects_by_construction() {
    let policy = HarnessAccessPolicy::SelectedProject {
        project_id: ProjectId::from_str(support::ID).unwrap(),
        read_only: false,
    };
    assert!(!policy.allows_other_projects());
    assert_eq!(
        serde_json::to_string(&ScopeRef::Global).unwrap(),
        r#"{"scope":"global"}"#
    );
}
