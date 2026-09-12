use crate::{
    CandidateReviewParams, LocalRequest, MemoryArchiveParams, MemoryCreateParams,
    MemoryUpdateParams, OperationId, TaskCompleteParams, TaskTransitionParams, TaskUpsertParams,
    ValidationError,
};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// A recovery copy of an explicit desktop record change, never a setup command.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(
    tag = "method",
    content = "params",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[ts(tag = "method", content = "params", rename_all = "snake_case")]
pub enum DesktopWrite {
    MemoryCreate(MemoryCreateParams),
    MemoryUpdate(MemoryUpdateParams),
    MemoryArchive(MemoryArchiveParams),
    CandidateReview(CandidateReviewParams),
    TaskUpsert(TaskUpsertParams),
    TaskComplete(TaskCompleteParams),
    TaskTransition(TaskTransitionParams),
}

impl DesktopWrite {
    pub fn operation_id(&self) -> OperationId {
        match self {
            Self::MemoryCreate(p) => p.operation_id,
            Self::MemoryUpdate(p) => p.operation_id,
            Self::MemoryArchive(p) => p.operation_id,
            Self::CandidateReview(p) => p.operation_id,
            Self::TaskUpsert(p) => p.operation_id,
            Self::TaskComplete(p) => p.operation_id,
            Self::TaskTransition(p) => p.operation_id,
        }
    }
    pub fn into_request(self) -> LocalRequest {
        match self {
            Self::MemoryCreate(p) => LocalRequest::MemoryCreate(p),
            Self::MemoryUpdate(p) => LocalRequest::MemoryUpdate(p),
            Self::MemoryArchive(p) => LocalRequest::MemoryArchive(p),
            Self::CandidateReview(p) => LocalRequest::CandidateReview(p),
            Self::TaskUpsert(p) => LocalRequest::TaskUpsert(p),
            Self::TaskComplete(p) => LocalRequest::TaskComplete(p),
            Self::TaskTransition(p) => LocalRequest::TaskTransition(p),
        }
    }
    pub fn validate(&self) -> Result<(), ValidationError> {
        self.clone().into_request().validate()
    }
    pub fn summary(&self) -> DesktopWriteSummary {
        let (action, title) = match self {
            Self::MemoryCreate(p) => ("Save context", p.title.as_str()),
            Self::MemoryUpdate(p) => (
                "Update context",
                p.title.as_deref().unwrap_or("Saved context"),
            ),
            Self::MemoryArchive(_) => ("Archive context", "Saved context"),
            Self::CandidateReview(_) => ("Review suggestion", "Context suggestion"),
            Self::TaskUpsert(p) => (
                if p.task_id.is_some() {
                    "Update task"
                } else {
                    "Save task"
                },
                p.title.as_str(),
            ),
            Self::TaskComplete(_) => ("Complete task", "Saved task"),
            Self::TaskTransition(_) => ("Change task status", "Saved task"),
        };
        let scope = match self {
            Self::MemoryCreate(p) => Some(p.scope.clone()),
            Self::TaskUpsert(p) => Some(crate::ScopeRef::Project {
                project_id: p.project_id,
            }),
            _ => None,
        };
        DesktopWriteSummary {
            operation_id: self.operation_id(),
            action: action.into(),
            title: title.into(),
            scope,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct DesktopWriteSummary {
    pub operation_id: OperationId,
    pub action: String,
    pub title: String,
    #[serde(deserialize_with = "crate::required_nullable")]
    pub scope: Option<crate::ScopeRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct DesktopWritesPage {
    pub writes: Vec<DesktopWriteSummary>,
    #[serde(deserialize_with = "crate::required_nullable")]
    pub next_cursor: Option<OperationId>,
}

impl DesktopWritesPage {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.writes.len() > 50 {
            return Err(ValidationError::Invalid("desktopWrites.page"));
        }
        for write in &self.writes {
            crate::required_text(&write.title, "desktopWrite.title", crate::MAX_TITLE_BYTES)?;
            crate::required_text(&write.action, "desktopWrite.action", 64)?;
        }
        Ok(())
    }
}
