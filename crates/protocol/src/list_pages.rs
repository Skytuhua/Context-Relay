use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    MemoryCandidate, MemoryRecord, ProjectId, ProjectIdentity, TaskRecord, ValidationError,
};

pub const MAX_LIST_PAGE_BYTES: usize = 7 * 1024 * 1024;
pub const MAX_LIST_PAGE_ITEMS: usize = 128;
pub const MAX_LIST_CURSOR_BYTES: usize = 256;

pub fn validate_list_cursor(cursor: Option<&str>) -> Result<(), ValidationError> {
    if cursor.is_some_and(|cursor| {
        cursor.is_empty() || cursor.len() > MAX_LIST_CURSOR_BYTES || !cursor.is_ascii()
    }) {
        return Err(ValidationError::Invalid("cursor"));
    }
    Ok(())
}

macro_rules! params {
    ($name:ident { $($(#[$field_attr:meta])* $field:ident: $ty:ty),* $(,)? }) => {
        #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        #[ts(rename_all = "camelCase")]
        pub struct $name {
            $($(#[$field_attr])* pub $field: $ty,)*
            #[serde(default)]
            pub cursor: Option<String>,
        }
    };
}
params!(ProjectsListPageParams {});
params!(MemoryListPageParams {
    #[serde(deserialize_with = "crate::required_nullable")]
    project_id: Option<ProjectId>, include_archived: bool
});
params!(CandidateListPageParams {
    #[serde(deserialize_with = "crate::required_nullable")]
    project_id: Option<ProjectId>
});
params!(TasksListPageParams {
    project_id: ProjectId
});

macro_rules! page {
    ($name:ident, $field:ident, $ty:ty) => {
        #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        #[ts(rename_all = "camelCase")]
        pub struct $name {
            pub $field: Vec<$ty>,
            #[serde(deserialize_with = "crate::required_nullable")]
            pub next_cursor: Option<String>,
        }
        impl $name {
            pub fn validate(&self) -> Result<(), ValidationError> {
                validate_list_cursor(self.next_cursor.as_deref())?;
                if self.$field.len() > MAX_LIST_PAGE_ITEMS
                    || (self.next_cursor.is_some() && self.$field.is_empty())
                {
                    return Err(ValidationError::Invalid("list page"));
                }
                for record in &self.$field {
                    record.validate()?;
                }
                if serde_json::to_vec(self)
                    .map_err(|_| ValidationError::Invalid("list page"))?
                    .len()
                    > MAX_LIST_PAGE_BYTES
                {
                    return Err(ValidationError::TooLarge {
                        field: "list page",
                        limit: MAX_LIST_PAGE_BYTES,
                    });
                }
                Ok(())
            }
        }
    };
}
page!(ProjectsPage, projects, ProjectIdentity);
page!(MemoriesPage, memories, MemoryRecord);
page!(CandidatesPage, candidates, MemoryCandidate);
page!(TasksPage, tasks, TaskRecord);
