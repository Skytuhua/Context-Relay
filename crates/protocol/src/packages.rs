use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    ApprovalClass, BoundedBytes, BoundedCiphertext, ExportId, HarnessId, HybridLogicalClock,
    MAX_BATCH_OPERATIONS, MAX_MARKDOWN_BYTES, MAX_TITLE_BYTES, OperationId, PackageId, Provenance,
    RecordId, RecordKind, ScopeRef, SecretRef, Sha256Digest, ValidationError, WorkspaceId,
    required_text,
};

pub const PACKAGE_FORMAT_V1: &str = "context-relay.package.v1";
pub const EXPORT_FORMAT_V1: &str = "context-relay.export.v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ImmutableDependency {
    pub name: String,
    pub version: String,
    pub digest: Sha256Digest,
    pub immutable_source_ref: String,
}

impl ImmutableDependency {
    pub fn validate(&self) -> Result<(), ValidationError> {
        required_text(&self.name, "dependency.name", MAX_TITLE_BYTES)?;
        required_text(&self.version, "dependency.version", MAX_TITLE_BYTES)?;
        required_text(
            &self.immutable_source_ref,
            "dependency.immutableSourceRef",
            MAX_MARKDOWN_BYTES,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[ts(tag = "kind", rename_all = "snake_case")]
pub enum PackageComponent {
    Instruction {
        id: RecordId,
        scope: ScopeRef,
        title: String,
        body_markdown: String,
    },
    Rule {
        id: RecordId,
        scope: ScopeRef,
        title: String,
        body_markdown: String,
    },
    Skill {
        id: RecordId,
        scope: ScopeRef,
        name: String,
        body_markdown: String,
        dependencies: Vec<ImmutableDependency>,
    },
    Plugin {
        id: RecordId,
        scope: ScopeRef,
        name: String,
        dependencies: Vec<ImmutableDependency>,
    },
    McpServer {
        id: RecordId,
        scope: ScopeRef,
        server_name: String,
        package: ImmutableDependency,
    },
    Hook {
        id: RecordId,
        scope: ScopeRef,
        event: String,
        component_id: RecordId,
    },
    PermissionDeclaration {
        id: RecordId,
        scope: ScopeRef,
        permissions: Vec<String>,
        approval_class: ApprovalClass,
    },
}

impl PackageComponent {
    pub const fn id(&self) -> RecordId {
        match self {
            Self::Instruction { id, .. }
            | Self::Rule { id, .. }
            | Self::Skill { id, .. }
            | Self::Plugin { id, .. }
            | Self::McpServer { id, .. }
            | Self::Hook { id, .. }
            | Self::PermissionDeclaration { id, .. } => *id,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct NamespacedExtension {
    pub namespace: String,
    pub value: BoundedBytes,
}

impl NamespacedExtension {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.namespace.len() > 255
            || !self.namespace.contains('.')
            || self.namespace.split('.').any(|part| {
                part.is_empty()
                    || !part.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
        {
            return Err(ValidationError::Invalid("extensions.namespace"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct PackageManifestV1 {
    pub format: String,
    pub package_id: PackageId,
    pub components: Vec<PackageComponent>,
    pub secret_refs: Vec<SecretRef>,
    pub harness_targets: Vec<HarnessId>,
    pub extensions: Vec<NamespacedExtension>,
}

impl PackageManifestV1 {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.format != PACKAGE_FORMAT_V1 {
            return Err(ValidationError::Invalid("format"));
        }
        if self.components.len() > MAX_BATCH_OPERATIONS
            || self.secret_refs.len() > MAX_BATCH_OPERATIONS
            || self.extensions.len() > MAX_BATCH_OPERATIONS
        {
            return Err(ValidationError::TooLarge {
                field: "manifest collections",
                limit: MAX_BATCH_OPERATIONS,
            });
        }
        if self.components.is_empty() {
            return Err(ValidationError::EmptyRequired("components"));
        }
        if self.harness_targets.is_empty() {
            return Err(ValidationError::EmptyRequired("harnessTargets"));
        }
        for secret in &self.secret_refs {
            secret.validate()?;
        }
        for extension in &self.extensions {
            extension.validate()?;
        }
        let mut component_ids = std::collections::BTreeSet::new();
        let mut namespaces = std::collections::BTreeSet::new();
        let mut secret_ids = std::collections::BTreeSet::new();
        let mut harnesses = std::collections::BTreeSet::new();
        if self
            .components
            .iter()
            .any(|component| !component_ids.insert(component.id()))
        {
            return Err(ValidationError::Invalid("duplicate component id"));
        }
        if self
            .secret_refs
            .iter()
            .any(|secret| !secret_ids.insert(secret.id))
        {
            return Err(ValidationError::Invalid("duplicate secret ref id"));
        }
        if self
            .extensions
            .iter()
            .any(|extension| !namespaces.insert(&extension.namespace))
        {
            return Err(ValidationError::Invalid("duplicate extension namespace"));
        }
        if self
            .harness_targets
            .iter()
            .any(|harness| !harnesses.insert(format!("{harness:?}")))
        {
            return Err(ValidationError::Invalid("duplicate harness target"));
        }
        for component in &self.components {
            if let PackageComponent::Hook {
                id, component_id, ..
            } = component
                && (id == component_id || !component_ids.contains(component_id))
            {
                return Err(ValidationError::Invalid("hook.componentId"));
            }
            match component {
                PackageComponent::Instruction {
                    title,
                    body_markdown,
                    ..
                }
                | PackageComponent::Rule {
                    title,
                    body_markdown,
                    ..
                } => {
                    required_text(title, "component.title", MAX_TITLE_BYTES)?;
                    required_text(body_markdown, "component.bodyMarkdown", MAX_MARKDOWN_BYTES)?;
                }
                PackageComponent::Skill {
                    name,
                    body_markdown,
                    dependencies,
                    ..
                } => {
                    if dependencies.len() > MAX_BATCH_OPERATIONS {
                        return Err(ValidationError::TooLarge {
                            field: "component.dependencies",
                            limit: MAX_BATCH_OPERATIONS,
                        });
                    }
                    for dependency in dependencies {
                        dependency.validate()?;
                    }
                    required_text(name, "component.name", MAX_TITLE_BYTES)?;
                    required_text(body_markdown, "component.bodyMarkdown", MAX_MARKDOWN_BYTES)?;
                }
                PackageComponent::Plugin {
                    name, dependencies, ..
                } => {
                    required_text(name, "component.name", MAX_TITLE_BYTES)?;
                    if dependencies.len() > MAX_BATCH_OPERATIONS {
                        return Err(ValidationError::TooLarge {
                            field: "component.dependencies",
                            limit: MAX_BATCH_OPERATIONS,
                        });
                    }
                    for dependency in dependencies {
                        dependency.validate()?;
                    }
                }
                PackageComponent::McpServer {
                    server_name,
                    package,
                    ..
                } => {
                    required_text(server_name, "component.serverName", MAX_TITLE_BYTES)?;
                    package.validate()?;
                }
                PackageComponent::Hook { event, .. } => {
                    required_text(event, "component.event", MAX_TITLE_BYTES)?
                }
                PackageComponent::PermissionDeclaration { permissions, .. }
                    if permissions.is_empty() =>
                {
                    return Err(ValidationError::EmptyRequired("component.permissions"));
                }
                PackageComponent::PermissionDeclaration { permissions, .. } => {
                    if permissions.len() > MAX_BATCH_OPERATIONS {
                        return Err(ValidationError::TooLarge {
                            field: "component.permissions",
                            limit: MAX_BATCH_OPERATIONS,
                        });
                    }
                    let mut unique = std::collections::BTreeSet::new();
                    for permission in permissions {
                        required_text(permission, "component.permissions", MAX_TITLE_BYTES)?;
                        if !unique.insert(permission) {
                            return Err(ValidationError::Invalid("duplicate permission"));
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ExportedRecordV1 {
    pub record_id: RecordId,
    pub record_kind: RecordKind,
    pub revision: OperationId,
    pub tombstone: bool,
    pub provenance: Provenance,
    pub encrypted_payload: BoundedCiphertext,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ExportEnvelopeV1 {
    pub format: String,
    pub export_id: ExportId,
    pub workspace_id: WorkspaceId,
    pub created_hlc: HybridLogicalClock,
    pub records: Vec<ExportedRecordV1>,
    pub operation_order: Vec<OperationId>,
}

impl ExportEnvelopeV1 {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.format != EXPORT_FORMAT_V1 {
            return Err(ValidationError::Invalid("format"));
        }
        if self.records.len() > MAX_BATCH_OPERATIONS {
            return Err(ValidationError::TooLarge {
                field: "records",
                limit: MAX_BATCH_OPERATIONS,
            });
        }
        if self.operation_order.len() > MAX_BATCH_OPERATIONS {
            return Err(ValidationError::TooLarge {
                field: "operationOrder",
                limit: MAX_BATCH_OPERATIONS,
            });
        }
        let mut records = std::collections::BTreeSet::new();
        if self
            .records
            .iter()
            .any(|record| !records.insert(record.record_id))
        {
            return Err(ValidationError::Invalid("duplicate record id"));
        }
        let mut order = std::collections::BTreeSet::new();
        if self
            .operation_order
            .iter()
            .any(|operation| !order.insert(*operation))
        {
            return Err(ValidationError::Invalid("duplicate operation order id"));
        }
        if self
            .records
            .iter()
            .any(|record| !order.contains(&record.revision))
        {
            return Err(ValidationError::Invalid(
                "record revision missing from operation order",
            ));
        }
        Ok(())
    }
}
