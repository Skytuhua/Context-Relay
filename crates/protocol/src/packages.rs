use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use ts_rs::TS;

use crate::{
    ApprovalClass, BoundedCiphertext, ExportId, HarnessId, HybridLogicalClock,
    MAX_BATCH_OPERATIONS, MAX_MARKDOWN_BYTES, MAX_TITLE_BYTES, OperationId, PackageId, Provenance,
    RecordId, RecordKind, ScopeRef, SecretRef, Sha256Digest, ValidationError, WorkspaceId,
    required_text,
};

pub const PACKAGE_FORMAT_V1: &str = "context-relay.package.v1";
pub const EXPORT_FORMAT_V1: &str = "context-relay.export.v1";
pub const MAX_EXTENSION_ITEMS: usize = 64;
pub const MAX_EXTENSION_KEY_BYTES: usize = 128;
pub const MAX_EXTENSION_TEXT_BYTES: usize = 16 * 1024;

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

#[derive(Clone, Debug, Eq, PartialEq, TS)]
#[ts(rename_all = "camelCase")]
pub struct NamespacedExtension {
    pub data: std::collections::BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NamespacedExtensionWire {
    data: std::collections::BTreeMap<String, String>,
}

fn validate_extension_namespace(namespace: &str) -> Result<(), ValidationError> {
    if namespace.len() > 255
        || !namespace.contains('.')
        || namespace.split('.').any(|part| {
            part.is_empty()
                || !part
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                || !part
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
    {
        return Err(ValidationError::Invalid("extensions.namespace"));
    }
    Ok(())
}

impl NamespacedExtension {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.data.len() > MAX_EXTENSION_ITEMS {
            return Err(ValidationError::TooLarge {
                field: "extensions.data",
                limit: MAX_EXTENSION_ITEMS,
            });
        }
        const FORBIDDEN_ROLES: [&str; 13] = [
            "password",
            "secret",
            "token",
            "cookie",
            "privatekey",
            "credential",
            "executable",
            "binary",
            "script",
            "shell",
            "command",
            "hook",
            "code",
        ];
        for (key, value) in &self.data {
            if key.is_empty()
                || key.len() > MAX_EXTENSION_KEY_BYTES
                || !key
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            {
                return Err(ValidationError::Invalid("extensions.data.key"));
            }
            let normalized: String = key
                .bytes()
                .filter(u8::is_ascii_alphanumeric)
                .map(|byte| byte.to_ascii_lowercase() as char)
                .collect();
            if FORBIDDEN_ROLES.iter().any(|role| normalized.contains(role)) {
                return Err(ValidationError::Invalid("extensions.data.keyRole"));
            }
            if value.len() > MAX_EXTENSION_TEXT_BYTES {
                return Err(ValidationError::TooLarge {
                    field: "extensions.data.text",
                    limit: MAX_EXTENSION_TEXT_BYTES,
                });
            }
            let uppercase = value.to_ascii_uppercase();
            if value.chars().any(char::is_control)
                || (uppercase.contains("-----BEGIN") && uppercase.contains("PRIVATE KEY-----"))
            {
                return Err(ValidationError::Invalid("extensions.data.text"));
            }
        }
        Ok(())
    }
}

impl Serialize for NamespacedExtension {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.validate().map_err(serde::ser::Error::custom)?;
        NamespacedExtensionWire {
            data: self.data.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for NamespacedExtension {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = NamespacedExtensionWire::deserialize(deserializer)?;
        let value = Self { data: wire.data };
        value.validate().map_err(D::Error::custom)?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, TS)]
#[ts(rename_all = "camelCase")]
pub struct PackageManifestV1 {
    pub format: String,
    pub package_id: PackageId,
    pub components: Vec<PackageComponent>,
    pub secret_refs: Vec<SecretRef>,
    pub harness_targets: Vec<HarnessId>,
    #[ts(optional)]
    pub extensions: Option<std::collections::BTreeMap<String, NamespacedExtension>>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PackageManifestV1Wire {
    format: String,
    package_id: PackageId,
    components: Vec<PackageComponent>,
    secret_refs: Vec<SecretRef>,
    harness_targets: Vec<HarnessId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_extensions"
    )]
    extensions: Option<std::collections::BTreeMap<String, NamespacedExtension>>,
}

fn deserialize_optional_extensions<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<std::collections::BTreeMap<String, NamespacedExtension>>, D::Error> {
    std::collections::BTreeMap::deserialize(deserializer).map(Some)
}

impl Serialize for PackageManifestV1 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.validate().map_err(serde::ser::Error::custom)?;
        PackageManifestV1Wire {
            format: self.format.clone(),
            package_id: self.package_id,
            components: self.components.clone(),
            secret_refs: self.secret_refs.clone(),
            harness_targets: self.harness_targets.clone(),
            extensions: self.extensions.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PackageManifestV1 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = PackageManifestV1Wire::deserialize(deserializer)?;
        let value = Self {
            format: wire.format,
            package_id: wire.package_id,
            components: wire.components,
            secret_refs: wire.secret_refs,
            harness_targets: wire.harness_targets,
            extensions: wire.extensions,
        };
        value.validate().map_err(D::Error::custom)?;
        Ok(value)
    }
}

impl PackageManifestV1 {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.format != PACKAGE_FORMAT_V1 {
            return Err(ValidationError::Invalid("format"));
        }
        if self.components.len() > MAX_BATCH_OPERATIONS
            || self.secret_refs.len() > MAX_BATCH_OPERATIONS
            || self
                .extensions
                .as_ref()
                .is_some_and(|extensions| extensions.len() > MAX_BATCH_OPERATIONS)
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
        if let Some(extensions) = &self.extensions {
            for (namespace, extension) in extensions {
                validate_extension_namespace(namespace)?;
                extension.validate()?;
            }
        }
        let mut component_ids = std::collections::BTreeSet::new();
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

#[derive(Clone, Debug, Eq, PartialEq, TS)]
#[ts(rename_all = "camelCase")]
pub struct ExportEnvelopeV1 {
    pub format: String,
    pub export_id: ExportId,
    pub workspace_id: WorkspaceId,
    pub created_hlc: HybridLogicalClock,
    pub records: Vec<ExportedRecordV1>,
    pub operation_order: Vec<OperationId>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExportEnvelopeV1Wire {
    format: String,
    export_id: ExportId,
    workspace_id: WorkspaceId,
    created_hlc: HybridLogicalClock,
    records: Vec<ExportedRecordV1>,
    operation_order: Vec<OperationId>,
}

impl Serialize for ExportEnvelopeV1 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.validate().map_err(serde::ser::Error::custom)?;
        ExportEnvelopeV1Wire {
            format: self.format.clone(),
            export_id: self.export_id,
            workspace_id: self.workspace_id,
            created_hlc: self.created_hlc,
            records: self.records.clone(),
            operation_order: self.operation_order.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ExportEnvelopeV1 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = ExportEnvelopeV1Wire::deserialize(deserializer)?;
        let value = Self {
            format: wire.format,
            export_id: wire.export_id,
            workspace_id: wire.workspace_id,
            created_hlc: wire.created_hlc,
            records: wire.records,
            operation_order: wire.operation_order,
        };
        value.validate().map_err(D::Error::custom)?;
        Ok(value)
    }
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
