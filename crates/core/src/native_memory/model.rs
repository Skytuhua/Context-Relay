use context_relay_protocol::{
    HarnessId, MAX_MARKDOWN_BYTES, MAX_TITLE_BYTES, NativePlatform, ScopeRef, Sha256Digest,
    WireNativeValue,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{error::Error, fmt};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NativeMemorySourceId(pub Sha256Digest);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeMemoryDocumentKind {
    Agent,
    UserProfile,
    Summary,
    Topic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeMemoryLimits {
    pub max_bytes: usize,
    pub max_characters: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeMemorySource {
    pub id: NativeMemorySourceId,
    pub harness: HarnessId,
    pub adapter_version: String,
    pub scope: ScopeRef,
    pub document_kind: NativeMemoryDocumentKind,
    pub path: WireNativeValue,
    pub limits: NativeMemoryLimits,
    pub managed_fence: bool,
}

impl NativeMemorySource {
    pub fn new(
        harness: HarnessId,
        adapter_version: &str,
        scope: ScopeRef,
        document_kind: NativeMemoryDocumentKind,
        path: WireNativeValue,
        limits: NativeMemoryLimits,
        managed_fence: bool,
    ) -> Result<Self, NativeMemoryError> {
        let id = derive_source_id(
            harness,
            adapter_version,
            &scope,
            document_kind,
            &path,
            limits,
            managed_fence,
        )?;
        Ok(Self {
            id,
            harness,
            adapter_version: adapter_version.to_owned(),
            scope,
            document_kind,
            path,
            limits,
            managed_fence,
        })
    }

    pub fn validate(&self) -> Result<(), NativeMemoryError> {
        let expected = derive_source_id(
            self.harness,
            &self.adapter_version,
            &self.scope,
            self.document_kind,
            &self.path,
            self.limits,
            self.managed_fence,
        )?;
        if expected != self.id {
            return Err(NativeMemoryError::InvalidSource("id"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeMemorySnapshot {
    Absent,
    Regular(Vec<u8>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeMemoryObservationKind {
    InitialPreview,
    LiveEdit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadyNativeMemory {
    pub source: NativeMemorySource,
    pub snapshot: NativeMemorySnapshot,
    pub kind: NativeMemoryObservationKind,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeMemoryRegistration {
    pub source: NativeMemorySource,
    pub last_applied_digest: Option<Sha256Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeMemoryLedger {
    pub source_id: NativeMemorySourceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<NativeMemorySource>,
    pub last_observed_digest: Option<Sha256Digest>,
    pub last_unmanaged_digest: Option<Sha256Digest>,
    pub last_imported_digest: Option<Sha256Digest>,
    pub last_applied_digest: Option<Sha256Digest>,
    pub initial_preview_complete: bool,
}

impl NativeMemoryLedger {
    pub const fn new(source_id: NativeMemorySourceId) -> Self {
        Self {
            source_id,
            source: None,
            last_observed_digest: None,
            last_unmanaged_digest: None,
            last_imported_digest: None,
            last_applied_digest: None,
            initial_preview_complete: false,
        }
    }

    pub fn for_source(source: NativeMemorySource) -> Self {
        let mut ledger = Self::new(source.id);
        ledger.source = Some(source);
        ledger
    }

    pub(crate) fn validate_persisted(&self) -> Result<&NativeMemorySource, NativeMemoryError> {
        let source = self
            .source
            .as_ref()
            .ok_or(NativeMemoryError::InvalidSource("ledger.source"))?;
        source.validate_compatible()?;
        if source.id != self.source_id {
            return Err(NativeMemoryError::InvalidSource("ledger.source_id"));
        }
        Ok(source)
    }
}

impl NativeMemorySource {
    pub(crate) fn validate_compatible(&self) -> Result<(), NativeMemoryError> {
        if self.validate().is_ok() {
            return Ok(());
        }
        let legacy = derive_legacy_source_id(
            self.harness,
            &self.adapter_version,
            &self.scope,
            self.document_kind,
            &self.path,
            self.limits,
        )?;
        if legacy != self.id {
            return Err(NativeMemoryError::InvalidSource("id"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeMemoryError {
    InvalidSource(&'static str),
    InvalidUtf8,
    TooLarge,
    MalformedManagedFence,
}

impl fmt::Display for NativeMemoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSource(field) => {
                write!(formatter, "invalid native memory source: {field}")
            }
            Self::InvalidUtf8 => formatter.write_str("native memory is not valid UTF-8"),
            Self::TooLarge => formatter.write_str("native memory exceeds its declared limit"),
            Self::MalformedManagedFence => {
                formatter.write_str("native memory managed markers are malformed")
            }
        }
    }
}

impl Error for NativeMemoryError {}

fn derive_source_id(
    harness: HarnessId,
    adapter_version: &str,
    scope: &ScopeRef,
    document_kind: NativeMemoryDocumentKind,
    path: &WireNativeValue,
    limits: NativeMemoryLimits,
    managed_fence: bool,
) -> Result<NativeMemorySourceId, NativeMemoryError> {
    validate_source_fields(adapter_version, path, limits)?;

    let mut hasher = Sha256::new();
    add_field(&mut hasher, b"context-relay.native-memory-source.v2");
    add_source_location_fields(
        &mut hasher,
        harness,
        adapter_version,
        scope,
        document_kind,
        path,
    );
    add_field(&mut hasher, &(limits.max_bytes as u64).to_be_bytes());
    add_field(&mut hasher, &(limits.max_characters as u64).to_be_bytes());
    add_field(&mut hasher, &[u8::from(managed_fence)]);
    Ok(NativeMemorySourceId(Sha256Digest(hasher.finalize().into())))
}

fn derive_legacy_source_id(
    harness: HarnessId,
    adapter_version: &str,
    scope: &ScopeRef,
    document_kind: NativeMemoryDocumentKind,
    path: &WireNativeValue,
    limits: NativeMemoryLimits,
) -> Result<NativeMemorySourceId, NativeMemoryError> {
    validate_source_fields(adapter_version, path, limits)?;

    let mut hasher = Sha256::new();
    add_field(&mut hasher, b"context-relay.native-memory-source.v1");
    add_source_location_fields(
        &mut hasher,
        harness,
        adapter_version,
        scope,
        document_kind,
        path,
    );
    Ok(NativeMemorySourceId(Sha256Digest(hasher.finalize().into())))
}

fn validate_source_fields(
    adapter_version: &str,
    path: &WireNativeValue,
    limits: NativeMemoryLimits,
) -> Result<(), NativeMemoryError> {
    if adapter_version.trim().is_empty()
        || adapter_version.len() > MAX_TITLE_BYTES
        || adapter_version.chars().any(char::is_control)
    {
        return Err(NativeMemoryError::InvalidSource("adapter_version"));
    }
    if path.validate().is_err() || path.bytes.is_empty() || path_contains_nul(path) {
        return Err(NativeMemoryError::InvalidSource("path"));
    }
    if limits.max_bytes == 0
        || limits.max_characters == 0
        || limits.max_bytes > MAX_MARKDOWN_BYTES
        || limits.max_characters > MAX_MARKDOWN_BYTES
    {
        return Err(NativeMemoryError::InvalidSource("limits"));
    }
    Ok(())
}

fn add_source_location_fields(
    hasher: &mut Sha256,
    harness: HarnessId,
    adapter_version: &str,
    scope: &ScopeRef,
    document_kind: NativeMemoryDocumentKind,
    path: &WireNativeValue,
) {
    add_field(hasher, harness_name(harness).as_bytes());
    add_field(hasher, adapter_version.as_bytes());
    match scope {
        ScopeRef::Global => {
            add_field(hasher, b"global");
            add_field(hasher, b"");
        }
        ScopeRef::Project { project_id } => {
            add_field(hasher, b"project");
            add_field(hasher, project_id.as_bytes());
        }
    }
    add_field(hasher, document_kind_name(document_kind).as_bytes());
    add_field(hasher, platform_name(path.platform).as_bytes());
    add_field(hasher, &path.bytes);
}

fn add_field(hasher: &mut Sha256, field: &[u8]) {
    hasher.update((field.len() as u64).to_be_bytes());
    hasher.update(field);
}

fn path_contains_nul(path: &WireNativeValue) -> bool {
    match path.platform {
        NativePlatform::Macos => path.bytes.contains(&0),
        NativePlatform::Windows => path.bytes.chunks_exact(2).any(|pair| pair == [0, 0]),
    }
}

const fn harness_name(harness: HarnessId) -> &'static str {
    match harness {
        HarnessId::ClaudeCode => "claude_code",
        HarnessId::Codex => "codex",
        HarnessId::Hermes => "hermes",
    }
}

const fn document_kind_name(kind: NativeMemoryDocumentKind) -> &'static str {
    match kind {
        NativeMemoryDocumentKind::Agent => "agent",
        NativeMemoryDocumentKind::UserProfile => "user_profile",
        NativeMemoryDocumentKind::Summary => "summary",
        NativeMemoryDocumentKind::Topic => "topic",
    }
}

const fn platform_name(platform: NativePlatform) -> &'static str {
    match platform {
        NativePlatform::Windows => "windows",
        NativePlatform::Macos => "macos",
    }
}
