use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use ts_rs::TS;

use crate::{
    ApprovalClass, ComponentRecord, HarnessId, HybridLogicalClock, ImmutableDependency,
    MAX_ARBITRARY_BYTES, MAX_BATCH_OPERATIONS, MAX_MARKDOWN_BYTES, MAX_TITLE_BYTES, PackageId,
    PlanId, ProjectId, Sha256Digest, ValidationError, decimal_u64, required_text,
};

pub const MAX_ADAPTER_COLLECTION_ITEMS: usize = 1024;
pub const MAX_ADAPTER_TEXT_BYTES: usize = 16 * 1024;

fn validate_adapter_collection(field: &'static str, length: usize) -> Result<(), ValidationError> {
    if length > MAX_ADAPTER_COLLECTION_ITEMS {
        return Err(ValidationError::TooLarge {
            field,
            limit: MAX_ADAPTER_COLLECTION_ITEMS,
        });
    }
    Ok(())
}

fn validate_adapter_text(value: &str, field: &'static str) -> Result<(), ValidationError> {
    if value.len() > MAX_ADAPTER_TEXT_BYTES {
        return Err(ValidationError::TooLarge {
            field,
            limit: MAX_ADAPTER_TEXT_BYTES,
        });
    }
    Ok(())
}

macro_rules! validated_adapter_dto {
    ($name:ident, $wire:ident, $wire_ref:ident { $($field:ident: $type:ty),+ $(,)? }) => {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct $wire {
            $($field: $type),+
        }

        #[derive(Serialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct $wire_ref<'a> {
            $($field: &'a $type),+
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                self.validate().map_err(serde::ser::Error::custom)?;
                $wire_ref {
                    $($field: &self.$field),+
                }
                .serialize(serializer)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let wire = $wire::deserialize(deserializer)?;
                let value = Self {
                    $($field: wire.$field),+
                };
                value.validate().map_err(D::Error::custom)?;
                Ok(value)
            }
        }
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum NativePlatform {
    Windows,
    Macos,
}

#[derive(Clone, Debug, Eq, PartialEq, TS)]
#[ts(rename_all = "camelCase")]
pub struct WireNativeValue {
    pub platform: NativePlatform,
    #[ts(type = "Base64Url")]
    pub bytes: Vec<u8>,
    pub display: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireNativeValueDto {
    platform: NativePlatform,
    #[serde(with = "base64url_bytes")]
    bytes: Vec<u8>,
    display: Option<String>,
}

impl WireNativeValue {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.bytes.len() > MAX_ARBITRARY_BYTES {
            return Err(ValidationError::TooLarge {
                field: "nativeValue.bytes",
                limit: MAX_ARBITRARY_BYTES,
            });
        }
        if self
            .display
            .as_ref()
            .is_some_and(|display| display.len() > 1024)
        {
            return Err(ValidationError::TooLarge {
                field: "nativeValue.display",
                limit: 1024,
            });
        }
        if self.platform == NativePlatform::Windows && !self.bytes.len().is_multiple_of(2) {
            return Err(ValidationError::Invalid("windowsUtf16Le"));
        }
        Ok(())
    }
}

impl Serialize for WireNativeValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.validate().map_err(serde::ser::Error::custom)?;
        WireNativeValueDto {
            platform: self.platform,
            bytes: self.bytes.clone(),
            display: self.display.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for WireNativeValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let dto = WireNativeValueDto::deserialize(deserializer)?;
        let value = Self {
            platform: dto.platform,
            bytes: dto.bytes,
            display: dto.display,
        };
        value.validate().map_err(D::Error::custom)?;
        Ok(value)
    }
}

mod base64url_bytes {
    use super::*;

    pub fn serialize<S: Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        URL_SAFE_NO_PAD
            .decode(String::deserialize(deserializer)?)
            .map_err(D::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityLevel {
    Full,
    ImportOnly,
    Blocked,
    Missing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum InstallationMethod {
    Bundled,
    PackageManager,
    Manual,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, TS)]
#[ts(rename_all = "camelCase")]
pub struct ProbeContext {
    pub harness: HarnessId,
    pub requested_profile: Option<String>,
}

impl ProbeContext {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if let Some(profile) = &self.requested_profile {
            validate_adapter_text(profile, "probeContext.requestedProfile")?;
        }
        Ok(())
    }
}

validated_adapter_dto!(
    ProbeContext,
    ProbeContextWire,
    ProbeContextWireRef {
        harness: HarnessId,
        requested_profile: Option<String>,
    }
);

#[derive(Clone, Debug, Eq, PartialEq, TS)]
#[ts(rename_all = "camelCase")]
pub struct ProbeReport {
    pub executable: Option<WireNativeValue>,
    pub executable_sha256: Option<Sha256Digest>,
    pub harness_version: Option<String>,
    pub installation_method: InstallationMethod,
    pub config_roots: Vec<WireNativeValue>,
    pub active_profile: Option<String>,
    pub policy_conflicts: Vec<String>,
    pub capability: CapabilityLevel,
}

impl ProbeReport {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_adapter_collection("probeReport.configRoots", self.config_roots.len())?;
        validate_adapter_collection("probeReport.policyConflicts", self.policy_conflicts.len())?;
        if let Some(executable) = &self.executable {
            executable.validate()?;
        }
        for root in &self.config_roots {
            root.validate()?;
        }
        if let Some(version) = &self.harness_version {
            validate_adapter_text(version, "probeReport.harnessVersion")?;
        }
        if let Some(profile) = &self.active_profile {
            validate_adapter_text(profile, "probeReport.activeProfile")?;
        }
        for conflict in &self.policy_conflicts {
            validate_adapter_text(conflict, "probeReport.policyConflicts.text")?;
        }
        Ok(())
    }
}

validated_adapter_dto!(
    ProbeReport,
    ProbeReportWire,
    ProbeReportWireRef {
        executable: Option<WireNativeValue>,
        executable_sha256: Option<Sha256Digest>,
        harness_version: Option<String>,
        installation_method: InstallationMethod,
        config_roots: Vec<WireNativeValue>,
        active_profile: Option<String>,
        policy_conflicts: Vec<String>,
        capability: CapabilityLevel,
    }
);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(
    tag = "scope",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[ts(tag = "scope", rename_all = "snake_case")]
pub enum NativeScope {
    Global,
    Project {
        project_id: ProjectId,
        root: WireNativeValue,
    },
}

impl NativeScope {
    pub fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Self::Global => Ok(()),
            Self::Project { root, .. } => root.validate(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, TS)]
#[ts(rename_all = "camelCase")]
pub struct ImportRequest {
    pub scopes: Vec<NativeScope>,
    pub include_disabled: bool,
}

impl ImportRequest {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_adapter_collection("importRequest.scopes", self.scopes.len())?;
        for scope in &self.scopes {
            scope.validate()?;
        }
        Ok(())
    }
}

validated_adapter_dto!(
    ImportRequest,
    ImportRequestWire,
    ImportRequestWireRef {
        scopes: Vec<NativeScope>,
        include_disabled: bool,
    }
);

#[derive(Clone, Debug, Eq, PartialEq, TS)]
#[ts(rename_all = "camelCase")]
pub struct ImportedState {
    pub components: Vec<ComponentRecord>,
    pub source_digests: Vec<Sha256Digest>,
}

impl ImportedState {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_adapter_collection("importedState.components", self.components.len())?;
        validate_adapter_collection("importedState.sourceDigests", self.source_digests.len())?;
        for component in &self.components {
            component.validate()?;
        }
        Ok(())
    }
}

validated_adapter_dto!(
    ImportedState,
    ImportedStateWire,
    ImportedStateWireRef {
        components: Vec<ComponentRecord>,
        source_digests: Vec<Sha256Digest>,
    }
);

#[derive(Clone, Debug, Eq, PartialEq, TS)]
#[ts(rename_all = "camelCase")]
pub struct DesiredState {
    pub components: Vec<ComponentRecord>,
    pub scopes: Vec<NativeScope>,
}

impl DesiredState {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_adapter_collection("desiredState.components", self.components.len())?;
        validate_adapter_collection("desiredState.scopes", self.scopes.len())?;
        for component in &self.components {
            component.validate()?;
        }
        for scope in &self.scopes {
            scope.validate()?;
        }
        Ok(())
    }
}

validated_adapter_dto!(
    DesiredState,
    DesiredStateWire,
    DesiredStateWireRef {
        components: Vec<ComponentRecord>,
        scopes: Vec<NativeScope>,
    }
);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct RenderedState {
    pub files: Vec<RenderedFile>,
    pub cli_operations: Vec<CliOperation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct RenderedFile {
    pub path: WireNativeValue,
    pub bytes_sha256: Sha256Digest,
    #[serde(with = "decimal_u64")]
    #[ts(type = "DecimalU64")]
    pub byte_length: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum ChangeClass {
    Create,
    Update,
    Remove,
    Enable,
    Disable,
    Preserve,
    Conflict,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ClassifiedChange {
    pub class: ChangeClass,
    pub target: String,
    pub summary: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct SemanticDiff {
    pub changes: Vec<ClassifiedChange>,
    pub conflicts: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct CliOperation {
    pub executable: WireNativeValue,
    pub arguments: Vec<WireNativeValue>,
    pub timeout_ms: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ApplyReceipt {
    pub plan_id: PlanId,
    pub applied_hlc: HybridLogicalClock,
    pub resulting_digests: Vec<Sha256Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ValidationReport {
    pub valid: bool,
    pub findings: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ExpectedNativeDigest {
    pub target: WireNativeValue,
    pub expected_digest: Option<Sha256Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct PackageArtifact {
    pub package_id: PackageId,
    pub immutable_source_ref: String,
    pub resolved_commit: String,
    pub archive_digest: Sha256Digest,
    pub artifact_path: WireNativeValue,
    pub artifact_digest: Sha256Digest,
    pub dependencies: Vec<ImmutableDependency>,
}

impl PackageArtifact {
    pub fn validate(&self) -> Result<(), ValidationError> {
        required_text(
            &self.immutable_source_ref,
            "packageArtifact.immutableSourceRef",
            MAX_MARKDOWN_BYTES,
        )?;
        if !matches!(self.resolved_commit.len(), 40 | 64)
            || !self
                .resolved_commit
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ValidationError::Invalid("packageArtifact.resolvedCommit"));
        }
        self.artifact_path.validate()?;
        if self.dependencies.len() > MAX_BATCH_OPERATIONS {
            return Err(ValidationError::TooLarge {
                field: "packageArtifact.dependencies",
                limit: MAX_BATCH_OPERATIONS,
            });
        }
        for dependency in &self.dependencies {
            dependency.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct PermissionDelta {
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum NetworkScheme {
    Https,
    Wss,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct NetworkEndpoint {
    pub scheme: NetworkScheme,
    pub host: String,
    pub port: u16,
}

impl NetworkEndpoint {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.host.is_empty()
            || self.host.len() > 253
            || self.host.starts_with('.')
            || self.host.ends_with('.')
            || self.host.split('.').any(|part| {
                part.is_empty()
                    || part.len() > 63
                    || part.starts_with('-')
                    || part.ends_with('-')
                    || !part
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
            || self.port == 0
        {
            return Err(ValidationError::Invalid("networkEndpoint"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct NetworkDelta {
    pub added: Vec<NetworkEndpoint>,
    pub removed: Vec<NetworkEndpoint>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub struct SetupPlan {
    pub plan_id: PlanId,
    pub harness: HarnessId,
    pub adapter_version: u32,
    pub executable_path: WireNativeValue,
    pub executable_hash: Sha256Digest,
    pub harness_version: String,
    pub target_scopes: Vec<NativeScope>,
    pub expected_native_digests: Vec<ExpectedNativeDigest>,
    pub semantic_changes: Vec<ClassifiedChange>,
    pub cli_operations: Vec<CliOperation>,
    pub package_artifacts: Vec<PackageArtifact>,
    pub permission_delta: PermissionDelta,
    pub network_delta: NetworkDelta,
    pub scanner_report_hash: Sha256Digest,
    pub rulesync_version: String,
    pub rulesync_hash: Sha256Digest,
    pub approval_class: ApprovalClass,
    #[serde(with = "decimal_u64")]
    #[ts(type = "DecimalU64")]
    pub expires_at: u64,
    pub batch_hash: Sha256Digest,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SetupPlanWire {
    plan_id: PlanId,
    harness: HarnessId,
    adapter_version: u32,
    executable_path: WireNativeValue,
    executable_hash: Sha256Digest,
    harness_version: String,
    target_scopes: Vec<NativeScope>,
    expected_native_digests: Vec<ExpectedNativeDigest>,
    semantic_changes: Vec<ClassifiedChange>,
    cli_operations: Vec<CliOperation>,
    package_artifacts: Vec<PackageArtifact>,
    permission_delta: PermissionDelta,
    network_delta: NetworkDelta,
    scanner_report_hash: Sha256Digest,
    rulesync_version: String,
    rulesync_hash: Sha256Digest,
    approval_class: ApprovalClass,
    #[serde(with = "decimal_u64")]
    expires_at: u64,
    batch_hash: Sha256Digest,
}

impl TryFrom<SetupPlanWire> for SetupPlan {
    type Error = ValidationError;
    fn try_from(value: SetupPlanWire) -> Result<Self, Self::Error> {
        let plan = Self {
            plan_id: value.plan_id,
            harness: value.harness,
            adapter_version: value.adapter_version,
            executable_path: value.executable_path,
            executable_hash: value.executable_hash,
            harness_version: value.harness_version,
            target_scopes: value.target_scopes,
            expected_native_digests: value.expected_native_digests,
            semantic_changes: value.semantic_changes,
            cli_operations: value.cli_operations,
            package_artifacts: value.package_artifacts,
            permission_delta: value.permission_delta,
            network_delta: value.network_delta,
            scanner_report_hash: value.scanner_report_hash,
            rulesync_version: value.rulesync_version,
            rulesync_hash: value.rulesync_hash,
            approval_class: value.approval_class,
            expires_at: value.expires_at,
            batch_hash: value.batch_hash,
        };
        plan.validate()?;
        Ok(plan)
    }
}

impl<'de> Deserialize<'de> for SetupPlan {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        SetupPlanWire::deserialize(deserializer)?
            .try_into()
            .map_err(D::Error::custom)
    }
}

impl SetupPlan {
    pub fn validate(&self) -> Result<(), ValidationError> {
        self.executable_path.validate()?;
        required_text(&self.harness_version, "harnessVersion", MAX_TITLE_BYTES)?;
        required_text(&self.rulesync_version, "rulesyncVersion", MAX_TITLE_BYTES)?;
        for (field, length) in [
            ("targetScopes", self.target_scopes.len()),
            ("expectedNativeDigests", self.expected_native_digests.len()),
            ("semanticChanges", self.semantic_changes.len()),
            ("cliOperations", self.cli_operations.len()),
            ("packageArtifacts", self.package_artifacts.len()),
            ("permissions.added", self.permission_delta.added.len()),
            ("permissions.removed", self.permission_delta.removed.len()),
            ("network.added", self.network_delta.added.len()),
            ("network.removed", self.network_delta.removed.len()),
        ] {
            if length > MAX_BATCH_OPERATIONS {
                return Err(ValidationError::TooLarge {
                    field,
                    limit: MAX_BATCH_OPERATIONS,
                });
            }
        }
        for change in &self.semantic_changes {
            required_text(&change.target, "semanticChange.target", MAX_MARKDOWN_BYTES)?;
            required_text(
                &change.summary,
                "semanticChange.summary",
                MAX_MARKDOWN_BYTES,
            )?;
        }
        for permission in self
            .permission_delta
            .added
            .iter()
            .chain(&self.permission_delta.removed)
        {
            required_text(permission, "permission", MAX_TITLE_BYTES)?;
        }
        for expected in &self.expected_native_digests {
            expected.target.validate()?;
        }
        for operation in &self.cli_operations {
            operation.executable.validate()?;
            for argument in &operation.arguments {
                argument.validate()?;
            }
        }
        for artifact in &self.package_artifacts {
            artifact.validate()?;
        }
        for endpoint in self
            .network_delta
            .added
            .iter()
            .chain(&self.network_delta.removed)
        {
            endpoint.validate()?;
        }
        Ok(())
    }
}

pub trait HarnessAdapter {
    fn probe(&self, context: &ProbeContext) -> Result<ProbeReport, crate::ClientError>;
    fn discover_scopes(&self, report: &ProbeReport)
    -> Result<Vec<NativeScope>, crate::ClientError>;
    fn import(&self, request: &ImportRequest) -> Result<ImportedState, crate::ClientError>;
    fn render(&self, desired: &DesiredState) -> Result<RenderedState, crate::ClientError>;
    fn classify(&self, diff: &SemanticDiff) -> Result<Vec<ClassifiedChange>, crate::ClientError>;
    fn plan_cli_ops(
        &self,
        changes: &[ClassifiedChange],
    ) -> Result<Vec<CliOperation>, crate::ClientError>;
    fn validate_effective(
        &self,
        receipt: &ApplyReceipt,
    ) -> Result<ValidationReport, crate::ClientError>;
}
