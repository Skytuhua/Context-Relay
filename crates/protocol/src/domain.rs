use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    CandidateId, DeviceId, HybridLogicalClock, MAX_COMPONENT_METADATA_BYTES, MAX_EVIDENCE_BYTES,
    MAX_EVIDENCE_ITEMS, MAX_MARKDOWN_BYTES, MAX_TAG_BYTES, MAX_TAGS, MAX_TITLE_BYTES, MemoryId,
    OperationId, PackageId, ProjectId, RecordId, SecretRefId, Sha256Digest, TaskId,
    ValidationError, required_text,
};

macro_rules! closed_enum {
    ($name:ident { $($variant:ident),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
        #[serde(rename_all = "snake_case")]
        pub enum $name { $($variant),+ }
    };
}

closed_enum!(HarnessId {
    ClaudeCode,
    Codex,
    Hermes
});
closed_enum!(MemoryKind {
    Fact,
    Decision,
    Preference,
    Pattern,
    Procedure,
    Note
});
closed_enum!(MemoryOrigin {
    Explicit,
    Inferred,
    NativeImport,
    PackageImport
});
closed_enum!(CandidateState {
    Pending,
    Accepted,
    Rejected
});
closed_enum!(TaskStatus {
    Open,
    InProgress,
    Blocked,
    Done,
    Canceled
});
closed_enum!(ComponentKind {
    Instruction,
    Rule,
    Skill,
    Plugin,
    McpServer,
    Hook,
    PermissionDeclaration
});
closed_enum!(ApprovalClass { Passive, Active });

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(
    tag = "scope",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[ts(tag = "scope", rename_all = "snake_case")]
pub enum ScopeRef {
    Global,
    Project { project_id: ProjectId },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(
    tag = "source",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[ts(tag = "source", rename_all = "snake_case")]
pub enum ProvenanceSource {
    Record { record_id: RecordId },
    Package { package_id: PackageId },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct Provenance {
    pub origin_device: DeviceId,
    pub harness: Option<HarnessId>,
    pub source: Option<ProvenanceSource>,
    pub created_hlc: HybridLogicalClock,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct MemoryRecord {
    pub id: MemoryId,
    pub scope: ScopeRef,
    pub kind: MemoryKind,
    pub title: String,
    pub body_markdown: String,
    pub tags: Vec<String>,
    pub origin: MemoryOrigin,
    pub provenance: Provenance,
    pub revision: OperationId,
    pub created_hlc: HybridLogicalClock,
    pub updated_hlc: HybridLogicalClock,
    pub archived: bool,
}

impl MemoryRecord {
    pub fn validate(&self) -> Result<(), ValidationError> {
        required_text(&self.title, "title", MAX_TITLE_BYTES)?;
        required_text(&self.body_markdown, "bodyMarkdown", MAX_MARKDOWN_BYTES)?;
        if self.tags.len() > MAX_TAGS {
            return Err(ValidationError::TooLarge {
                field: "tags",
                limit: MAX_TAGS,
            });
        }
        let mut unique_tags = std::collections::BTreeSet::new();
        for tag in &self.tags {
            required_text(tag, "tags", MAX_TAG_BYTES)?;
            if !unique_tags.insert(tag) {
                return Err(ValidationError::Invalid("duplicate tag"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct MemoryCandidate {
    pub id: CandidateId,
    pub proposed_memory: MemoryRecord,
    pub evidence_summary: String,
    pub source_harness: HarnessId,
    pub state: CandidateState,
}

impl MemoryCandidate {
    pub fn validate(&self) -> Result<(), ValidationError> {
        self.proposed_memory.validate()?;
        required_text(
            &self.evidence_summary,
            "evidenceSummary",
            MAX_EVIDENCE_BYTES,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct TaskEvidence {
    pub summary: String,
    pub evidence_kind: String,
    pub reference: Option<String>,
    pub recorded_hlc: HybridLogicalClock,
}

impl TaskEvidence {
    pub fn validate(&self) -> Result<(), ValidationError> {
        required_text(&self.summary, "summary", MAX_EVIDENCE_BYTES)?;
        required_text(&self.evidence_kind, "evidenceKind", MAX_TAG_BYTES)?;
        if self
            .reference
            .as_ref()
            .is_some_and(|reference| reference.len() > MAX_EVIDENCE_BYTES)
        {
            return Err(ValidationError::TooLarge {
                field: "evidence.reference",
                limit: MAX_EVIDENCE_BYTES,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct TaskRecord {
    pub id: TaskId,
    pub project_id: ProjectId,
    pub title: String,
    pub body_markdown: String,
    pub status: TaskStatus,
    pub evidence: Vec<TaskEvidence>,
    pub revision: OperationId,
}

impl TaskRecord {
    pub fn validate(&self) -> Result<(), ValidationError> {
        required_text(&self.title, "title", MAX_TITLE_BYTES)?;
        required_text(&self.body_markdown, "bodyMarkdown", MAX_MARKDOWN_BYTES)?;
        if self.status == TaskStatus::Done && self.evidence.is_empty() {
            return Err(ValidationError::EmptyRequired("evidence"));
        }
        if self.evidence.len() > MAX_EVIDENCE_ITEMS {
            return Err(ValidationError::TooLarge {
                field: "evidence",
                limit: MAX_EVIDENCE_ITEMS,
            });
        }
        for evidence in &self.evidence {
            evidence.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct SecretRef {
    pub id: SecretRefId,
    pub name: String,
    pub provider: String,
    pub required_on_device: bool,
}

impl SecretRef {
    pub fn validate(&self) -> Result<(), ValidationError> {
        required_text(&self.name, "name", MAX_TITLE_BYTES)?;
        required_text(&self.provider, "provider", MAX_TITLE_BYTES)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct InstructionRecord {
    pub id: RecordId,
    pub scope: ScopeRef,
    pub title: String,
    pub body_markdown: String,
    pub provenance: Provenance,
    pub archived: bool,
}

impl InstructionRecord {
    pub fn validate(&self) -> Result<(), ValidationError> {
        required_text(&self.title, "title", MAX_TITLE_BYTES)?;
        required_text(&self.body_markdown, "bodyMarkdown", MAX_MARKDOWN_BYTES)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ComponentRecord {
    pub id: RecordId,
    pub scope: ScopeRef,
    pub kind: ComponentKind,
    pub name: String,
    pub body_markdown: String,
    pub metadata: Vec<(String, String)>,
    pub provenance: Provenance,
    pub archived: bool,
}

impl ComponentRecord {
    pub fn validate(&self) -> Result<(), ValidationError> {
        required_text(&self.name, "name", MAX_TITLE_BYTES)?;
        required_text(&self.body_markdown, "bodyMarkdown", MAX_MARKDOWN_BYTES)?;
        if self
            .metadata
            .iter()
            .map(|(key, value)| key.len() + value.len())
            .sum::<usize>()
            > MAX_COMPONENT_METADATA_BYTES
        {
            return Err(ValidationError::TooLarge {
                field: "metadata",
                limit: MAX_COMPONENT_METADATA_BYTES,
            });
        }
        for (key, _) in &self.metadata {
            required_text(key, "metadata.key", MAX_TITLE_BYTES)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(
    tag = "mode",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[ts(tag = "mode", rename_all = "snake_case")]
pub enum HarnessAccessPolicy {
    Default,
    ReadOnly,
    ActiveProjectOnly {
        read_only: bool,
    },
    GlobalOnly {
        read_only: bool,
    },
    SelectedProject {
        project_id: ProjectId,
        read_only: bool,
    },
    Disabled,
}

impl HarnessAccessPolicy {
    pub const fn allows_other_projects(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ProjectIdentity {
    pub project_id: ProjectId,
    #[serde(default, with = "optional_decimal_u64")]
    #[ts(type = "DecimalU64 | null")]
    pub github_repository_id: Option<u64>,
    pub git_remote_fingerprint: Option<Sha256Digest>,
    pub monorepo_subdirectory: Option<String>,
    pub name: String,
}

impl ProjectIdentity {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.github_repository_id == Some(0) {
            return Err(ValidationError::Invalid("repositoryIdentity"));
        }
        if let Some(path) = &self.monorepo_subdirectory
            && (path.len() > MAX_TITLE_BYTES
                || path.is_empty()
                || path.starts_with('/')
                || path.contains('\\')
                || path.contains(':')
                || path.chars().any(char::is_control)
                || path
                    .split('/')
                    .any(|part| part.is_empty() || part == "." || part == ".."))
        {
            return Err(ValidationError::Invalid("monorepoSubdirectory"));
        }
        required_text(&self.name, "name", MAX_TITLE_BYTES)
    }
}

mod optional_decimal_u64 {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};
    pub fn serialize<S: Serializer>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error> {
        match value {
            Some(value) => serializer.serialize_some(&value.to_string()),
            None => serializer.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<u64>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|text| {
                let value: u64 = text.parse().map_err(D::Error::custom)?;
                if value.to_string() != text {
                    return Err(D::Error::custom("noncanonical decimal u64"));
                }
                Ok(value)
            })
            .transpose()
    }
}
