use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;
#[cfg(windows)]
use std::os::windows::{fs::MetadataExt as _, io::AsRawHandle as _};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
};

use serde::{Deserialize, Deserializer};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::{RunnerError, StagePath, validate_path_set};

const MAX_MANIFEST_BYTES: usize = 1_048_576;
const MAX_ARTIFACT_BYTES: u64 = 268_435_456;
const MAX_TOOLS: usize = 16;
const MAX_TARGETS: usize = 3;
const MAX_ENTRIES: usize = 64;
const MAX_TOOL_MATERIALS: usize = 32;
const MAX_SOURCE_LOCK_BYTES: usize = 16 * 1024 * 1024;
const MAX_BUNDLE_EVIDENCE_BYTES: usize = 64 * 1024;
const MAX_NATIVE_BUILD_EVIDENCE_BYTES: usize = 1024 * 1024;
const MAX_SOURCE_BUNDLE_BYTES: u64 = 2_147_483_648;
const MAX_SEMGREP_SOURCE_PACKAGES: usize = 1_024;
#[cfg(feature = "ci-candidate-sidecar-smoke")]
const CI_CANDIDATE_DOMAIN: &[u8] = b"context-relay/ci-candidate-sidecar-smoke/v1\0";
#[cfg(feature = "ci-candidate-sidecar-smoke")]
const CI_CANDIDATE_PURPOSE: &str = "ci-native-sidecar-smoke-only";
#[cfg(feature = "ci-candidate-sidecar-smoke")]
const CI_CANDIDATE_PENDING_STATUS: &str = "source_bundle_reproducible_native_builds_pending";
#[cfg(feature = "ci-candidate-sidecar-smoke")]
const CI_CANDIDATE_MISSING_MATERIAL: [&str; 4] = [
    "two byte-identical executable and runtime-closure inventories per target",
    "schema-valid Windows builder evidence with the exact Cygwin package-version snapshot",
    "Windows no-Python AppContainer smoke evidence",
    "macOS post-sign entitlement and inherited-sandbox smoke evidence",
];
const SEMGREP_LICENSE_SOURCES: [&str; 11] = [
    "memtrace",
    "obackward",
    "ocaml-compiler",
    "ocaml-opentelemetry",
    "ocaml-tree-sitter-core",
    "pcre2-ocaml",
    "pyro-caml",
    "semgrep",
    "semgrep-interfaces",
    "testo",
    "tree-sitter-runtime",
];
const SEMGREP_SOURCE_ASSET_URL: &str = "https://github.com/Skytuhua/Context-Relay/releases/download/sidecars-semgrep-1.170.0-source.1/semgrep-1.170.0-corresponding-source.tar";
const SEMGREP_NATIVE_EVIDENCE_PATH: &str =
    "third_party/sidecars/semgrep/native-build-evidence.v1.json";
const SEMGREP_NATIVE_SUPPORT: [(&str, &str); 3] = [
    (
        "native-ci-provenance",
        "third_party/sidecars/semgrep/native-ci-provenance.v1.json",
    ),
    (
        "native-release-finalizer",
        "scripts/finalize-semgrep-native-release.mjs",
    ),
    (
        "source-bundle-reseal",
        "scripts/reseal-semgrep-source-bundle.mjs",
    ),
];
const LEGACY_BIGSTRINGAF_URL: &str =
    "https://github.com/inhabitedtype/bigstringaf/archive/0.10.0.tar.gz";
const LEGACY_BIGSTRINGAF_MD5: &str = "be0a44416840852777651150757a0a3b";
const LEGACY_BIGSTRINGAF_SHA256: &str =
    "ed92f5b05fbc11b9defcec734d59b1068f3717a9ae4f9705c16c7f7ac3729f28";

const RULESYNC_TEMPLATE: (&str, &[&str]) = (
    "rulesync-generate-v1",
    &[
        "rulesync",
        "generate",
        "--targets",
        "<closed-target>",
        "--features",
        "<closed-features>",
        "--output-roots",
        "output",
        "--config",
        "rulesync.jsonc",
        "--input-root",
        "input",
        "--silent",
    ],
);
const GITLEAKS_TEMPLATE: (&str, &[&str]) = (
    "gitleaks-dir-v1",
    &[
        "gitleaks",
        "--no-banner",
        "--no-color",
        "--log-level=info",
        "--redact=100",
        "--exit-code=10",
        "--report-format=json",
        "--report-path=-",
        "--config",
        "<trusted-stage-config>",
        "--gitleaks-ignore-path",
        "<trusted-empty-ignore>",
        "--ignore-gitleaks-allow",
        "--max-target-megabytes=0",
        "--max-archive-depth=0",
        "--max-decode-depth=1",
        "--timeout=30",
        "--diagnostics=",
        "dir",
        "--follow-symlinks=false",
        "<stage-scan-root>",
    ],
);
const OSEMGREP_TEMPLATE: (&str, &[&str]) = (
    "osemgrep-scan-v1",
    &[
        "osemgrep",
        "scan",
        "--experimental",
        "--oss-only",
        "--metrics=off",
        "--disable-version-check",
        "--strict",
        "--error",
        "--json",
        "--quiet",
        "--no-git-ignore",
        "--x-ignore-semgrepignore-files",
        "--time",
        "--jobs=1",
        "--timeout=30",
        "--timeout-threshold=1",
        "--max-target-bytes=8388608",
        "--config",
        "<staged-rule>",
        "<staged-target>",
    ],
);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RuntimeTarget {
    WindowsX86_64,
    MacosArm64,
}

impl RuntimeTarget {
    pub const fn current() -> Result<Self, RunnerError> {
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        {
            return Ok(Self::WindowsX86_64);
        }
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            return Ok(Self::MacosArm64);
        }
        #[allow(unreachable_code)]
        Err(RunnerError::UnsupportedTarget)
    }

    pub const fn stable_name(self) -> &'static str {
        match self {
            Self::WindowsX86_64 => "windows-x86_64",
            Self::MacosArm64 => "macos-aarch64",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SidecarId {
    RuleSync,
    Gitleaks,
    Osemgrep,
}

impl SidecarId {
    pub const fn stable_name(self) -> &'static str {
        match self {
            Self::RuleSync => "rulesync",
            Self::Gitleaks => "gitleaks",
            Self::Osemgrep => "semgrep",
        }
    }
}

#[derive(Clone, Debug)]
pub struct SidecarManifest {
    parsed: ManifestV1,
    sha256: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedMaterial {
    path: StagePath,
    size: u64,
    sha256: [u8; 32],
    executable: bool,
}

impl VerifiedMaterial {
    pub fn path(&self) -> &StagePath {
        &self.path
    }

    pub const fn size(&self) -> u64 {
        self.size
    }

    pub const fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    pub const fn executable(&self) -> bool {
        self.executable
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedClosure {
    target: RuntimeTarget,
    sidecar: SidecarId,
    version: String,
    manifest_sha256: [u8; 32],
    closure_sha256: [u8; 32],
    command_template_id: String,
    command_template_sha256: [u8; 32],
    root: PathBuf,
    executable: VerifiedMaterial,
    materials: Vec<VerifiedMaterial>,
}

impl VerifiedClosure {
    pub const fn target(&self) -> RuntimeTarget {
        self.target
    }

    pub const fn sidecar(&self) -> SidecarId {
        self.sidecar
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub const fn manifest_sha256(&self) -> &[u8; 32] {
        &self.manifest_sha256
    }

    pub const fn closure_sha256(&self) -> &[u8; 32] {
        &self.closure_sha256
    }

    pub fn command_template_id(&self) -> &str {
        &self.command_template_id
    }

    pub const fn command_template_sha256(&self) -> &[u8; 32] {
        &self.command_template_sha256
    }

    pub fn executable(&self) -> &VerifiedMaterial {
        &self.executable
    }

    pub fn materials(&self) -> &[VerifiedMaterial] {
        &self.materials
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ManifestV1 {
    schema_version: u16,
    digest_format: String,
    allowed_release_hosts: Vec<String>,
    tools: Vec<Tool>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Tool {
    id: String,
    version: String,
    source: Source,
    license: License,
    #[serde(deserialize_with = "required_nullable")]
    relinking: Option<MaterialRef>,
    materials: Vec<ToolMaterial>,
    command_template: CommandTemplate,
    targets: Vec<Target>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Source {
    repository: String,
    revision: String,
    tree: String,
    material_path: String,
    material_sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct License {
    spdx: String,
    path: String,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MaterialRef {
    path: String,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolMaterial {
    role: String,
    path: String,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandTemplate {
    id: String,
    argv: Vec<String>,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Target {
    target: String,
    enabled: bool,
    #[serde(deserialize_with = "required_nullable")]
    disabled_reason: Option<String>,
    reproducible_builds: u64,
    corresponding_source_complete: bool,
    #[serde(deserialize_with = "required_nullable")]
    download: Option<Download>,
    #[serde(deserialize_with = "required_nullable")]
    executable: Option<Executable>,
    closure: Vec<ClosureEntry>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Download {
    url: String,
    format: String,
    size: u64,
    sha256: String,
    entries: Vec<ArchiveEntry>,
    extract_path: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveEntry {
    path: String,
    #[serde(rename = "type")]
    kind: String,
    size: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Executable {
    path: String,
    size: u64,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClosureEntry {
    path: String,
    size: u64,
    sha256: String,
    executable: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SemgrepSourceGate {
    source_revision: String,
    source_tree: String,
    complete_corresponding_source: bool,
    recursive_inventory_complete: bool,
    opam: SemgrepOpamGate,
    license_materials: Vec<SemgrepLicenseMaterial>,
    target_status: Vec<SemgrepTargetStatus>,
    toolchains: Vec<SemgrepNativeToolchainGate>,
    missing_material: Vec<serde_json::Value>,
    native_build_evidence: Option<SemgrepNativeEvidenceReference>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SemgrepNativeEvidenceReference {
    path: String,
    sha256: String,
    support: Vec<SemgrepNativeSupport>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SemgrepNativeSupport {
    path: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SemgrepNativeToolchainGate {
    distribution_target: String,
    status: Option<String>,
    builder_evidence: Option<SemgrepWindowsBuilderGate>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SemgrepWindowsBuilderGate {
    schema_sha256: String,
    sha256: Option<String>,
    status: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SemgrepLicenseMaterial {
    source: String,
    kind: String,
    spdx: String,
    path: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SemgrepOpamGate {
    resolved_source_archives: Vec<SemgrepResolvedSource>,
    resolved_source_archives_complete: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SemgrepResolvedSource {
    package: String,
    version: String,
    targets: Vec<String>,
    opam_path: String,
    opam_sha256: String,
    licenses: Vec<String>,
    #[serde(deserialize_with = "required_nullable")]
    source: Option<SemgrepSourceArchive>,
    extra_sources: Vec<SemgrepExtraSource>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SemgrepSourceArchive {
    checksums: Vec<SemgrepSourceChecksum>,
    mirrors: Vec<String>,
    supplemental_checksums: Vec<SemgrepSourceChecksum>,
    url: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SemgrepExtraSource {
    checksums: Vec<SemgrepSourceChecksum>,
    mirrors: Vec<String>,
    name: String,
    supplemental_checksums: Vec<SemgrepSourceChecksum>,
    url: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SemgrepSourceChecksum {
    algorithm: String,
    digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SemgrepTargetStatus {
    distribution_target: String,
    enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SemgrepBundleEvidence {
    schema_version: u16,
    format: String,
    source_lock_sha256: String,
    bundle_generator_sha256: String,
    independent_builds: u8,
    byte_identical: bool,
    status: String,
    source_asset_url: String,
    bundle: SemgrepBundle,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SemgrepBundle {
    sha256: String,
    size: u64,
    payload_entries: u64,
    recorded_links: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SemgrepNativeBuildEvidence {
    schema_version: u16,
    status: String,
    bootstrap_source: SemgrepNativeBootstrapSource,
    ci: SemgrepNativeCi,
    provenance_sha256: String,
    builders: Vec<SemgrepNativeBuilder>,
    smokes: Vec<SemgrepNativeSmoke>,
    targets: Vec<SemgrepNativeTargetEvidence>,
    windows_builder: Option<SemgrepWindowsBuilderEvidence>,
    support: Vec<SemgrepNativeSupport>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SemgrepNativeBootstrapSource {
    source_lock_sha256: String,
    source_revision: String,
    source_tree: String,
    bundle_evidence_sha256: String,
    bundle: SemgrepBundle,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SemgrepNativeCi {
    commit: String,
    run_id: String,
    run_attempt: u64,
    workflow_ref: String,
    workflow_sha: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SemgrepNativeBuilder {
    target: String,
    build: String,
    artifact_name: String,
    identity_sha256: String,
    identity_size: u64,
    check_run_id: u64,
    job_definition: String,
    job_index: u8,
    job_total: u8,
    runner_name: String,
    runner_os: String,
    runner_arch: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SemgrepNativeSmoke {
    target: String,
    check_run_id: u64,
    job_definition: String,
    sandbox_mechanism: String,
    sha256: String,
    size: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SemgrepNativeTargetEvidence {
    target: String,
    runtime_archive: SemgrepNamedIdentity,
    evidence_archive: SemgrepNamedIdentity,
    runtime_closure: SemgrepIdentity,
    manifests: SemgrepNativeManifests,
    offline_evidence: Vec<SemgrepOfflineEvidence>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SemgrepNamedIdentity {
    name: String,
    size: u64,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SemgrepIdentity {
    size: u64,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SemgrepNativeManifests {
    #[serde(rename = "build-a.MANIFEST.sha256")]
    build_a: SemgrepIdentity,
    #[serde(rename = "build-b.MANIFEST.sha256")]
    build_b: SemgrepIdentity,
    #[serde(rename = "build-a-evidence.MANIFEST.sha256")]
    build_a_evidence: SemgrepIdentity,
    #[serde(rename = "build-b-evidence.MANIFEST.sha256")]
    build_b_evidence: SemgrepIdentity,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SemgrepOfflineEvidence {
    build: String,
    size: u64,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SemgrepWindowsBuilderEvidence {
    evidence: SemgrepIdentity,
    schema: SemgrepIdentity,
    toolchain: SemgrepIdentity,
}

#[cfg(feature = "ci-candidate-sidecar-smoke")]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CiCandidateDocument {
    schema_version: u16,
    purpose: String,
    publishable: bool,
    enabled: bool,
    target: String,
    sidecar: String,
    version: String,
    production_manifest_sha256: String,
    source_lock_sha256: String,
    bundle_evidence_sha256: String,
    bundle_evidence_status: String,
    archive: CiCandidateArchive,
    executable: Executable,
    closure: Vec<ClosureEntry>,
}

#[cfg(feature = "ci-candidate-sidecar-smoke")]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CiCandidateArchive {
    format: String,
    size: u64,
    sha256: String,
    entries: Vec<ArchiveEntry>,
    extract_path: String,
}

fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

pub fn parse_sidecar_manifest(bytes: &[u8]) -> Result<SidecarManifest, RunnerError> {
    if bytes.is_empty() || bytes.len() > MAX_MANIFEST_BYTES {
        return Err(RunnerError::InvalidManifest);
    }
    let parsed: ManifestV1 =
        serde_json::from_slice(bytes).map_err(|_| RunnerError::InvalidManifest)?;
    validate_manifest(&parsed)?;
    Ok(SidecarManifest {
        parsed,
        sha256: Sha256::digest(bytes).into(),
    })
}

pub fn verify_closure(
    manifest: &SidecarManifest,
    workspace_root: &Path,
    hydrated_root: &Path,
    target: RuntimeTarget,
    sidecar: SidecarId,
) -> Result<VerifiedClosure, RunnerError> {
    if !workspace_root.is_absolute() || !hydrated_root.is_absolute() {
        return Err(RunnerError::InvalidStage);
    }
    let tool = manifest
        .parsed
        .tools
        .iter()
        .find(|tool| tool.id == sidecar.stable_name())
        .ok_or(RunnerError::SidecarUnavailable)?;
    let selected = tool
        .targets
        .iter()
        .find(|candidate| candidate.target == target.stable_name())
        .filter(|candidate| candidate.enabled)
        .ok_or(RunnerError::SidecarUnavailable)?;

    verify_file(
        workspace_root,
        &tool.source.material_path,
        None,
        parse_hash(&tool.source.material_sha256)?,
        None,
    )?;
    if sidecar == SidecarId::Osemgrep {
        verify_semgrep_source_gate(workspace_root, tool, target)?;
    }
    verify_file(
        workspace_root,
        &tool.license.path,
        None,
        parse_hash(&tool.license.sha256)?,
        None,
    )?;
    if let Some(relinking) = &tool.relinking {
        verify_file(
            workspace_root,
            &relinking.path,
            None,
            parse_hash(&relinking.sha256)?,
            None,
        )?;
    }
    for material in &tool.materials {
        verify_file(
            workspace_root,
            &material.path,
            None,
            parse_hash(&material.sha256)?,
            None,
        )?;
    }

    let mut expected_paths = selected
        .closure
        .iter()
        .map(|entry| StagePath::try_from(entry.path.as_str()))
        .collect::<Result<Vec<_>, _>>()?;
    expected_paths.sort_unstable();
    let actual_paths = enumerate_files(hydrated_root)?;
    if actual_paths != expected_paths {
        return Err(RunnerError::ClosureMismatch);
    }

    let mut materials = Vec::with_capacity(selected.closure.len());
    for entry in &selected.closure {
        let path = StagePath::try_from(entry.path.as_str())?;
        let digest = parse_hash(&entry.sha256)?;
        verify_file(
            hydrated_root,
            path.as_str(),
            Some(entry.size),
            digest,
            Some(entry.executable),
        )?;
        materials.push(VerifiedMaterial {
            path,
            size: entry.size,
            sha256: digest,
            executable: entry.executable,
        });
    }
    if enumerate_files(hydrated_root)? != expected_paths {
        return Err(RunnerError::ClosureMismatch);
    }
    materials.sort_unstable_by(|left, right| left.path.cmp(&right.path));
    let executable_path = selected
        .executable
        .as_ref()
        .ok_or(RunnerError::InvalidManifest)?
        .path
        .as_str();
    let executable = materials
        .iter()
        .find(|material| material.path.as_str() == executable_path && material.executable)
        .cloned()
        .ok_or(RunnerError::InvalidManifest)?;
    let closure_sha256 = closure_digest(&materials);
    Ok(VerifiedClosure {
        target,
        sidecar,
        version: tool.version.clone(),
        manifest_sha256: manifest.sha256,
        closure_sha256,
        command_template_id: tool.command_template.id.clone(),
        command_template_sha256: parse_hash(&tool.command_template.sha256)?,
        root: hydrated_root.to_path_buf(),
        executable,
        materials,
    })
}

/// Verifies an unpublished native Semgrep candidate for the ignored CI smoke tests.
///
/// This API exists only when the explicit CI feature is enabled. It deliberately accepts only a
/// disabled production target whose corresponding-source and bundle evidence remain pending; it
/// cannot turn a candidate document into a production manifest or release target.
#[cfg(feature = "ci-candidate-sidecar-smoke")]
pub fn verify_ci_candidate_closure(
    candidate_document_bytes: &[u8],
    manifest: &SidecarManifest,
    workspace_root: &Path,
    hydrated_root: &Path,
    target: RuntimeTarget,
    sidecar: SidecarId,
) -> Result<VerifiedClosure, RunnerError> {
    if candidate_document_bytes.is_empty()
        || candidate_document_bytes.len() > MAX_MANIFEST_BYTES
        || !workspace_root.is_absolute()
        || !hydrated_root.is_absolute()
        || sidecar != SidecarId::Osemgrep
    {
        return Err(RunnerError::InvalidManifest);
    }
    let candidate: CiCandidateDocument = serde_json::from_slice(candidate_document_bytes)
        .map_err(|_| RunnerError::InvalidManifest)?;
    let candidate_digest: [u8; 32] = Sha256::new()
        .chain_update(CI_CANDIDATE_DOMAIN)
        .chain_update(candidate_document_bytes)
        .finalize()
        .into();
    let generation = hydrated_root
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .ok_or(RunnerError::InvalidStage)?;
    if hydrated_root.file_name().and_then(|name| name.to_str()) != Some(sidecar.stable_name())
        || !lower_hex(generation, 64)
        || parse_hash(generation)? != candidate_digest
    {
        return Err(RunnerError::InvalidStage);
    }

    let tool = manifest
        .parsed
        .tools
        .iter()
        .find(|tool| tool.id == sidecar.stable_name())
        .ok_or(RunnerError::SidecarUnavailable)?;
    let production_target = tool
        .targets
        .iter()
        .find(|candidate| candidate.target == target.stable_name())
        .ok_or(RunnerError::SidecarUnavailable)?;
    if candidate.schema_version != 1
        || candidate.purpose != CI_CANDIDATE_PURPOSE
        || candidate.publishable
        || candidate.enabled
        || candidate.target != target.stable_name()
        || candidate.sidecar != sidecar.stable_name()
        || candidate.version != tool.version
        || parse_hash(&candidate.production_manifest_sha256)? != manifest.sha256
        || candidate.source_lock_sha256 != tool.source.material_sha256
        || candidate.bundle_evidence_status != CI_CANDIDATE_PENDING_STATUS
        || production_target.enabled
        || production_target
            .disabled_reason
            .as_deref()
            .is_none_or(str::is_empty)
        || production_target.reproducible_builds != 0
        || production_target.corresponding_source_complete
        || production_target.download.is_some()
        || production_target.executable.is_some()
        || !production_target.closure.is_empty()
    {
        return Err(RunnerError::InvalidManifest);
    }

    verify_ci_candidate_workspace(
        workspace_root,
        tool,
        target,
        &candidate.source_lock_sha256,
        &candidate.bundle_evidence_sha256,
    )?;
    validate_ci_candidate_runtime(&candidate)?;
    let materials = verify_candidate_hydrated_closure(hydrated_root, &candidate.closure)?;
    let executable = materials
        .iter()
        .find(|material| material.path.as_str() == candidate.executable.path && material.executable)
        .cloned()
        .ok_or(RunnerError::InvalidManifest)?;
    let closure_sha256 = closure_digest(&materials);
    Ok(VerifiedClosure {
        target,
        sidecar,
        version: tool.version.clone(),
        manifest_sha256: candidate_digest,
        closure_sha256,
        command_template_id: tool.command_template.id.clone(),
        command_template_sha256: parse_hash(&tool.command_template.sha256)?,
        root: hydrated_root.to_path_buf(),
        executable,
        materials,
    })
}

#[cfg(feature = "ci-candidate-sidecar-smoke")]
fn validate_ci_candidate_runtime(candidate: &CiCandidateDocument) -> Result<(), RunnerError> {
    let archive_digest = parse_hash(&candidate.archive.sha256)?;
    let closure_paths = validate_closure_entries(&candidate.closure)?;
    if candidate.archive.format != "tar.gz"
        || candidate.archive.size == 0
        || candidate.archive.size > MAX_ARTIFACT_BYTES
        || archive_digest == [0; 32]
        || candidate.archive.entries.is_empty()
        || candidate.archive.entries.len() != candidate.closure.len()
        || candidate.archive.entries.len() > MAX_ENTRIES
        || candidate.executable.size == 0
        || candidate.executable.size > MAX_ARTIFACT_BYTES
        || parse_hash(&candidate.executable.sha256).is_err()
        || manifest_path(&candidate.executable.path).is_err()
        || candidate.archive.extract_path != candidate.executable.path
        || !closure_paths.contains(&manifest_path(&candidate.executable.path)?)
        || candidate
            .closure
            .iter()
            .filter(|entry| entry.executable)
            .count()
            != 1
    {
        return Err(RunnerError::InvalidManifest);
    }
    for (archive, closure) in candidate.archive.entries.iter().zip(&candidate.closure) {
        if archive.kind != "file" || archive.path != closure.path || archive.size != closure.size {
            return Err(RunnerError::InvalidManifest);
        }
    }
    let executable = candidate
        .closure
        .iter()
        .find(|entry| entry.path == candidate.executable.path)
        .ok_or(RunnerError::InvalidManifest)?;
    if !executable.executable
        || executable.size != candidate.executable.size
        || executable.sha256 != candidate.executable.sha256
    {
        return Err(RunnerError::InvalidManifest);
    }
    Ok(())
}

#[cfg(feature = "ci-candidate-sidecar-smoke")]
fn verify_candidate_hydrated_closure(
    hydrated_root: &Path,
    closure: &[ClosureEntry],
) -> Result<Vec<VerifiedMaterial>, RunnerError> {
    let mut expected_paths = closure
        .iter()
        .map(|entry| StagePath::try_from(entry.path.as_str()))
        .collect::<Result<Vec<_>, _>>()?;
    expected_paths.sort_unstable();
    if enumerate_files(hydrated_root)? != expected_paths {
        return Err(RunnerError::ClosureMismatch);
    }
    let mut materials = Vec::with_capacity(closure.len());
    for entry in closure {
        let path = StagePath::try_from(entry.path.as_str())?;
        let digest = parse_hash(&entry.sha256)?;
        verify_file(
            hydrated_root,
            path.as_str(),
            Some(entry.size),
            digest,
            Some(entry.executable),
        )?;
        materials.push(VerifiedMaterial {
            path,
            size: entry.size,
            sha256: digest,
            executable: entry.executable,
        });
    }
    if enumerate_files(hydrated_root)? != expected_paths {
        return Err(RunnerError::ClosureMismatch);
    }
    materials.sort_unstable_by(|left, right| left.path.cmp(&right.path));
    Ok(materials)
}

#[cfg(feature = "ci-candidate-sidecar-smoke")]
fn verify_ci_candidate_workspace(
    root: &Path,
    tool: &Tool,
    target: RuntimeTarget,
    source_lock_sha256: &str,
    bundle_evidence_sha256: &str,
) -> Result<(), RunnerError> {
    let source_bytes = read_verified_file(
        root,
        &tool.source.material_path,
        parse_hash(source_lock_sha256)?,
        MAX_SOURCE_LOCK_BYTES,
    )?;
    verify_file(
        root,
        &tool.license.path,
        None,
        parse_hash(&tool.license.sha256)?,
        None,
    )?;
    if let Some(relinking) = &tool.relinking {
        verify_file(
            root,
            &relinking.path,
            None,
            parse_hash(&relinking.sha256)?,
            None,
        )?;
    }
    for material in &tool.materials {
        verify_file(
            root,
            &material.path,
            None,
            parse_hash(&material.sha256)?,
            None,
        )?;
    }

    let gate: SemgrepSourceGate =
        serde_json::from_slice(&source_bytes).map_err(|_| RunnerError::InvalidManifest)?;
    validate_semgrep_resolved_sources(&gate.opam.resolved_source_archives)?;
    validate_semgrep_license_materials(&gate.license_materials)?;
    let missing = gate
        .missing_material
        .iter()
        .map(|value| value.as_str().ok_or(RunnerError::InvalidManifest))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected_missing = CI_CANDIDATE_MISSING_MATERIAL
        .into_iter()
        .collect::<BTreeSet<_>>();
    let distribution_target = match target {
        RuntimeTarget::WindowsX86_64 => "windows-x86_64",
        RuntimeTarget::MacosArm64 => "aarch64-apple-darwin",
    };
    let matching_targets = gate
        .target_status
        .iter()
        .filter(|status| status.distribution_target == distribution_target)
        .collect::<Vec<_>>();
    if gate.source_revision != tool.source.revision
        || gate.source_tree != tool.source.tree
        || gate.complete_corresponding_source
        || !gate.recursive_inventory_complete
        || !gate.opam.resolved_source_archives_complete
        || gate.opam.resolved_source_archives.is_empty()
        || missing != expected_missing
        || matching_targets.len() != 1
        || matching_targets[0].enabled
        || gate.target_status.iter().any(|status| status.enabled)
    {
        return Err(RunnerError::InvalidManifest);
    }
    verify_pending_semgrep_bundle_evidence(root, tool, bundle_evidence_sha256)
}

#[cfg(feature = "ci-candidate-sidecar-smoke")]
fn verify_pending_semgrep_bundle_evidence(
    root: &Path,
    tool: &Tool,
    candidate_evidence_sha256: &str,
) -> Result<(), RunnerError> {
    let evidence = tool
        .materials
        .iter()
        .filter(|material| material.role == "source-bundle-evidence")
        .collect::<Vec<_>>();
    let generator = tool
        .materials
        .iter()
        .filter(|material| material.role == "source-bundle-generator")
        .collect::<Vec<_>>();
    if evidence.len() != 1
        || generator.len() != 1
        || evidence[0].sha256 != candidate_evidence_sha256
    {
        return Err(RunnerError::InvalidManifest);
    }
    let evidence_bytes = read_verified_file(
        root,
        &evidence[0].path,
        parse_hash(candidate_evidence_sha256)?,
        MAX_BUNDLE_EVIDENCE_BYTES,
    )?;
    let evidence: SemgrepBundleEvidence =
        serde_json::from_slice(&evidence_bytes).map_err(|_| RunnerError::InvalidManifest)?;
    let bundle_hash = parse_hash(&evidence.bundle.sha256)?;
    if evidence.schema_version != 1
        || evidence.format != "context-relay-semgrep-source-v1"
        || evidence.source_lock_sha256 != tool.source.material_sha256
        || evidence.bundle_generator_sha256 != generator[0].sha256
        || evidence.independent_builds != 2
        || !evidence.byte_identical
        || evidence.status != CI_CANDIDATE_PENDING_STATUS
        || evidence.source_asset_url != SEMGREP_SOURCE_ASSET_URL
        || bundle_hash == [0; 32]
        || evidence.bundle.size == 0
        || evidence.bundle.size > MAX_SOURCE_BUNDLE_BYTES
        || evidence.bundle.payload_entries == 0
        || evidence.bundle.payload_entries > 1_000_000
        || evidence.bundle.recorded_links > 1_000_000
    {
        return Err(RunnerError::InvalidManifest);
    }
    Ok(())
}

fn validate_manifest(manifest: &ManifestV1) -> Result<(), RunnerError> {
    if manifest.schema_version != 1
        || manifest.digest_format != "sha256-nul-argv-v1"
        || manifest.allowed_release_hosts.is_empty()
        || manifest.allowed_release_hosts.len() > 8
        || manifest.tools.is_empty()
        || manifest.tools.len() > MAX_TOOLS
    {
        return Err(RunnerError::InvalidManifest);
    }
    let hosts = validate_hosts(&manifest.allowed_release_hosts)?;
    let mut tool_ids = BTreeSet::new();
    for tool in &manifest.tools {
        if !valid_id(&tool.id)
            || tool.version.is_empty()
            || !tool_ids.insert(tool.id.as_str())
            || tool.targets.is_empty()
            || tool.targets.len() > MAX_TARGETS
        {
            return Err(RunnerError::InvalidManifest);
        }
        validate_source_and_license(tool)?;
        validate_tool_materials(&tool.materials)?;
        validate_command_template(&tool.id, &tool.command_template)?;
        let mut targets = BTreeSet::new();
        for target in &tool.targets {
            if !targets.insert(target.target.as_str()) {
                return Err(RunnerError::InvalidManifest);
            }
            validate_target(tool, target, &hosts)?;
        }
    }
    Ok(())
}

fn validate_hosts(hosts: &[String]) -> Result<BTreeSet<&str>, RunnerError> {
    let mut output = BTreeSet::new();
    for host in hosts {
        if host.is_empty()
            || host != &host.to_ascii_lowercase()
            || !host.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b".-".contains(&byte)
            })
            || !output.insert(host.as_str())
        {
            return Err(RunnerError::InvalidManifest);
        }
    }
    Ok(output)
}

fn validate_source_and_license(tool: &Tool) -> Result<(), RunnerError> {
    validate_https_url(&tool.source.repository, &BTreeSet::from(["github.com"]))?;
    if !lower_hex(&tool.source.revision, 40)
        || !lower_hex(&tool.source.tree, 40)
        || manifest_path(&tool.source.material_path).is_err()
        || parse_hash(&tool.source.material_sha256).is_err()
        || !matches!(tool.license.spdx.as_str(), "MIT" | "LGPL-2.1-or-later")
        || manifest_path(&tool.license.path).is_err()
        || parse_hash(&tool.license.sha256).is_err()
    {
        return Err(RunnerError::InvalidManifest);
    }
    if let Some(relinking) = &tool.relinking
        && (manifest_path(&relinking.path).is_err() || parse_hash(&relinking.sha256).is_err())
    {
        return Err(RunnerError::InvalidManifest);
    }
    if tool.id == "semgrep" && tool.relinking.is_none() {
        return Err(RunnerError::InvalidManifest);
    }
    Ok(())
}

fn validate_tool_materials(materials: &[ToolMaterial]) -> Result<(), RunnerError> {
    if materials.len() > MAX_TOOL_MATERIALS {
        return Err(RunnerError::InvalidManifest);
    }
    let mut paths = Vec::with_capacity(materials.len());
    for material in materials {
        if !valid_id(&material.role) || parse_hash(&material.sha256).is_err() {
            return Err(RunnerError::InvalidManifest);
        }
        paths.push(manifest_path(&material.path)?);
    }
    validate_path_set(RuntimeTarget::WindowsX86_64, &paths)?;
    validate_path_set(RuntimeTarget::MacosArm64, &paths)?;
    Ok(())
}

fn validate_command_template(tool_id: &str, template: &CommandTemplate) -> Result<(), RunnerError> {
    let (expected_id, expected_argv) = match tool_id {
        "rulesync" => RULESYNC_TEMPLATE,
        "gitleaks" => GITLEAKS_TEMPLATE,
        "semgrep" => OSEMGREP_TEMPLATE,
        _ => return Err(RunnerError::InvalidManifest),
    };
    if !valid_id(&template.id)
        || template.argv.is_empty()
        || template.argv.len() > 64
        || template
            .argv
            .iter()
            .any(|argument| argument.is_empty() || argument.len() > 256 || argument.contains('\0'))
        || template.id != expected_id
        || template.argv.len() != expected_argv.len()
        || template
            .argv
            .iter()
            .map(String::as_str)
            .ne(expected_argv.iter().copied())
    {
        return Err(RunnerError::InvalidManifest);
    }
    let expected = parse_hash(&template.sha256)?;
    let actual: [u8; 32] = Sha256::digest(template.argv.join("\0").as_bytes()).into();
    (actual == expected)
        .then_some(())
        .ok_or(RunnerError::InvalidManifest)
}

fn validate_target(
    tool: &Tool,
    target: &Target,
    hosts: &BTreeSet<&str>,
) -> Result<(), RunnerError> {
    if !matches!(
        target.target.as_str(),
        "windows-x86_64" | "macos-aarch64" | "macos-x86_64"
    ) || target.closure.len() > MAX_ENTRIES
    {
        return Err(RunnerError::InvalidManifest);
    }
    let closure_paths = validate_closure_entries(&target.closure)?;
    if !target.enabled {
        return target
            .disabled_reason
            .as_deref()
            .filter(|reason| !reason.is_empty())
            .filter(|_| {
                target.download.is_none()
                    && target.executable.is_none()
                    && target.closure.is_empty()
            })
            .map(|_| ())
            .ok_or(RunnerError::InvalidManifest);
    }
    if target.disabled_reason.is_some()
        || (tool.id == "semgrep"
            && (target.reproducible_builds < 2 || !target.corresponding_source_complete))
    {
        return Err(RunnerError::InvalidManifest);
    }
    let download = target
        .download
        .as_ref()
        .ok_or(RunnerError::InvalidManifest)?;
    let executable = target
        .executable
        .as_ref()
        .ok_or(RunnerError::InvalidManifest)?;
    validate_download(download, hosts)?;
    let executable_path = manifest_path(&executable.path)?;
    let executable_digest = parse_hash(&executable.sha256)?;
    if executable.size == 0 || executable.size > MAX_ARTIFACT_BYTES {
        return Err(RunnerError::InvalidManifest);
    }
    let matching = target.closure.iter().any(|entry| {
        entry.path == executable.path
            && entry.executable
            && entry.size == executable.size
            && parse_hash(&entry.sha256) == Ok(executable_digest)
    });
    if !matching || !closure_paths.contains(&executable_path) {
        return Err(RunnerError::InvalidManifest);
    }
    Ok(())
}

fn validate_download(download: &Download, hosts: &BTreeSet<&str>) -> Result<(), RunnerError> {
    if !matches!(download.format.as_str(), "raw" | "zip" | "tar.gz")
        || download.size == 0
        || download.size > MAX_ARTIFACT_BYTES
        || parse_hash(&download.sha256).is_err()
        || download.entries.is_empty()
        || download.entries.len() > MAX_ENTRIES
    {
        return Err(RunnerError::InvalidManifest);
    }
    validate_https_url(&download.url, hosts)?;
    let mut paths = Vec::with_capacity(download.entries.len());
    for entry in &download.entries {
        let path = manifest_path(&entry.path)?;
        if !matches!(entry.kind.as_str(), "file" | "directory")
            || entry.size > MAX_ARTIFACT_BYTES
            || (entry.kind == "directory" && entry.size != 0)
        {
            return Err(RunnerError::InvalidManifest);
        }
        paths.push(path);
    }
    validate_path_set(RuntimeTarget::WindowsX86_64, &paths)?;
    validate_path_set(RuntimeTarget::MacosArm64, &paths)?;
    let extract_path = manifest_path(&download.extract_path)?;
    download
        .entries
        .iter()
        .any(|entry| entry.path == extract_path.as_str() && entry.kind == "file")
        .then_some(())
        .ok_or(RunnerError::InvalidManifest)
}

fn validate_closure_entries(entries: &[ClosureEntry]) -> Result<BTreeSet<StagePath>, RunnerError> {
    let mut paths = Vec::with_capacity(entries.len());
    for entry in entries {
        if entry.size > MAX_ARTIFACT_BYTES || parse_hash(&entry.sha256).is_err() {
            return Err(RunnerError::InvalidManifest);
        }
        paths.push(manifest_path(&entry.path)?);
    }
    validate_path_set(RuntimeTarget::WindowsX86_64, &paths)?;
    validate_path_set(RuntimeTarget::MacosArm64, &paths)?;
    Ok(paths.into_iter().collect())
}

fn manifest_path(value: &str) -> Result<StagePath, RunnerError> {
    if value.nfc().collect::<String>() != value {
        return Err(RunnerError::InvalidManifest);
    }
    StagePath::try_from(value).map_err(|_| RunnerError::InvalidManifest)
}

fn validate_https_url(value: &str, hosts: &BTreeSet<&str>) -> Result<(), RunnerError> {
    let rest = value
        .strip_prefix("https://")
        .ok_or(RunnerError::InvalidManifest)?;
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .ok_or(RunnerError::InvalidManifest)?;
    if authority.is_empty()
        || authority.contains(['@', ':'])
        || !hosts.contains(authority)
        || rest.len() == authority.len()
    {
        return Err(RunnerError::InvalidManifest);
    }
    Ok(())
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parse_hash(value: &str) -> Result<[u8; 32], RunnerError> {
    if !lower_hex(value, 64) {
        return Err(RunnerError::InvalidManifest);
    }
    let mut output = [0_u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| RunnerError::InvalidManifest)?;
    }
    Ok(output)
}

fn verify_file(
    root: &Path,
    relative: &str,
    expected_size: Option<u64>,
    expected_digest: [u8; 32],
    expected_executable: Option<bool>,
) -> Result<(), RunnerError> {
    verify_file_inner(
        root,
        relative,
        expected_size,
        expected_digest,
        expected_executable,
        None,
    )
    .map(drop)
}

fn read_verified_file(
    root: &Path,
    relative: &str,
    expected_digest: [u8; 32],
    maximum_size: usize,
) -> Result<Vec<u8>, RunnerError> {
    verify_file_inner(
        root,
        relative,
        None,
        expected_digest,
        None,
        Some(maximum_size),
    )?
    .ok_or(RunnerError::MissingMaterial)
}

fn verify_file_inner(
    root: &Path,
    relative: &str,
    expected_size: Option<u64>,
    expected_digest: [u8; 32],
    expected_executable: Option<bool>,
    capture_maximum: Option<usize>,
) -> Result<Option<Vec<u8>>, RunnerError> {
    verify_directory_node(root)?;
    let path = manifest_path(relative)?;
    let components = path.as_str().split('/').collect::<Vec<_>>();
    let mut current = root.to_path_buf();
    let mut final_metadata = None;
    for (index, component) in components.iter().enumerate() {
        current.push(component);
        let metadata = fs::symlink_metadata(&current).map_err(|_| RunnerError::MissingMaterial)?;
        if unsafe_topology(&metadata)
            || (index + 1 == components.len() && !metadata.is_file())
            || (index + 1 < components.len() && !metadata.is_dir())
        {
            return Err(RunnerError::MissingMaterial);
        }
        if index + 1 == components.len() {
            final_metadata = Some(metadata);
        }
    }
    let before = final_metadata.ok_or(RunnerError::MissingMaterial)?;
    let mut file = File::open(&current).map_err(|_| RunnerError::MissingMaterial)?;
    let opened = file.metadata().map_err(|_| RunnerError::MissingMaterial)?;
    let opened_identity = file_identity(&file)?;
    let reopened_file = File::open(&current).map_err(|_| RunnerError::MissingMaterial)?;
    let reopened_identity = file_identity(&reopened_file)?;
    let reopened = fs::symlink_metadata(&current).map_err(|_| RunnerError::MissingMaterial)?;
    if unsafe_topology(&reopened)
        || !reopened.is_file()
        || opened_identity.links != 1
        || reopened_identity.links != 1
        || opened_identity != reopened_identity
        || before.len() != opened.len()
        || opened.len() != reopened.len()
    {
        return Err(RunnerError::ClosureMismatch);
    }
    let canonical_root = fs::canonicalize(root).map_err(|_| RunnerError::MissingMaterial)?;
    let canonical_file = fs::canonicalize(&current).map_err(|_| RunnerError::MissingMaterial)?;
    if canonical_file.strip_prefix(canonical_root).is_err()
        || expected_size.is_some_and(|size| size != opened.len())
        || expected_executable.is_some_and(|expected| !executable_mode_matches(&opened, expected))
        || capture_maximum.is_some_and(|maximum| opened.len() > maximum as u64)
    {
        return Err(RunnerError::ClosureMismatch);
    }
    let mut hasher = Sha256::new();
    let mut captured = capture_maximum.map(|_| Vec::with_capacity(opened.len() as usize));
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| RunnerError::MissingMaterial)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        if let Some(bytes) = &mut captured {
            bytes.extend_from_slice(&buffer[..count]);
        }
    }
    let actual: [u8; 32] = hasher.finalize().into();
    let after_handle = file.metadata().map_err(|_| RunnerError::MissingMaterial)?;
    let after_file = File::open(&current).map_err(|_| RunnerError::MissingMaterial)?;
    let after_identity = file_identity(&after_file)?;
    let after_path = fs::symlink_metadata(&current).map_err(|_| RunnerError::MissingMaterial)?;
    (actual == expected_digest
        && opened_identity == after_identity
        && opened.len() == after_handle.len()
        && opened.len() == after_path.len()
        && after_identity.links == 1
        && !unsafe_topology(&after_path))
    .then_some(captured)
    .ok_or(RunnerError::ClosureMismatch)
}

fn enumerate_files(root: &Path) -> Result<Vec<StagePath>, RunnerError> {
    verify_directory_node(root)?;
    let mut paths = Vec::new();
    enumerate_directory(root, root, &mut paths)?;
    paths.sort_unstable();
    Ok(paths)
}

fn enumerate_directory(
    root: &Path,
    directory: &Path,
    output: &mut Vec<StagePath>,
) -> Result<(), RunnerError> {
    for entry in fs::read_dir(directory).map_err(|_| RunnerError::MissingMaterial)? {
        let entry = entry.map_err(|_| RunnerError::MissingMaterial)?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|_| RunnerError::MissingMaterial)?;
        if unsafe_topology(&metadata) {
            return Err(RunnerError::ClosureMismatch);
        }
        if metadata.is_dir() {
            enumerate_directory(root, &path, output)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| RunnerError::ClosureMismatch)?;
            let value = relative
                .components()
                .map(|component| {
                    component
                        .as_os_str()
                        .to_str()
                        .ok_or(RunnerError::ClosureMismatch)
                })
                .collect::<Result<Vec<_>, _>>()?
                .join("/");
            output.push(manifest_path(&value)?);
        } else {
            return Err(RunnerError::ClosureMismatch);
        }
    }
    Ok(())
}

fn verify_directory_node(path: &Path) -> Result<(), RunnerError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| RunnerError::MissingMaterial)?;
    if !metadata.is_dir() || unsafe_topology(&metadata) {
        return Err(RunnerError::MissingMaterial);
    }
    Ok(())
}

fn unsafe_topology(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn semgrep_atom(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.nfc().collect::<String>() == value
        && value.bytes().enumerate().all(|(index, byte)| {
            (index != 0 || byte.is_ascii_alphanumeric())
                && (byte.is_ascii_alphanumeric()
                    || matches!(byte, b'+' | b'_' | b'.' | b'~' | b'-'))
        })
}

fn semgrep_source_url(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 2_048
        || value.contains('#')
        || value.bytes().any(|byte| byte <= b' ' || byte == 0x7f)
    {
        return false;
    }
    let Some(rest) = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
    else {
        return false;
    };
    let authority = rest.split(['/', '?']).next().unwrap_or_default();
    !authority.is_empty()
        && !authority.contains(['@', ':'])
        && authority
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        && rest.len() > authority.len()
}

fn semgrep_checksum_rank(algorithm: &str) -> Option<usize> {
    match algorithm {
        "md5" => Some(0),
        "sha256" => Some(1),
        "sha512" => Some(2),
        _ => None,
    }
}

fn validate_semgrep_checksums(
    checksums: &[SemgrepSourceChecksum],
    require_strong: bool,
) -> Result<bool, RunnerError> {
    if checksums.is_empty() || checksums.len() > 3 {
        return Err(RunnerError::InvalidManifest);
    }
    let mut previous = None;
    let mut strong = false;
    for checksum in checksums {
        let rank =
            semgrep_checksum_rank(&checksum.algorithm).ok_or(RunnerError::InvalidManifest)?;
        if previous.is_some_and(|prior| rank <= prior) {
            return Err(RunnerError::InvalidManifest);
        }
        let length = match checksum.algorithm.as_str() {
            "md5" => 32,
            "sha256" => 64,
            "sha512" => 128,
            _ => return Err(RunnerError::InvalidManifest),
        };
        if !lower_hex(&checksum.digest, length) || !checksum.digest.bytes().any(|byte| byte != b'0')
        {
            return Err(RunnerError::InvalidManifest);
        }
        strong |= matches!(checksum.algorithm.as_str(), "sha256" | "sha512");
        previous = Some(rank);
    }
    if require_strong && !strong {
        return Err(RunnerError::InvalidManifest);
    }
    Ok(strong)
}

fn validate_semgrep_source_archive(
    checksums: &[SemgrepSourceChecksum],
    mirrors: &[String],
    supplemental: &[SemgrepSourceChecksum],
    url: &str,
) -> Result<(), RunnerError> {
    if !semgrep_source_url(url) || mirrors.len() > 16 {
        return Err(RunnerError::InvalidManifest);
    }
    let mut seen_mirrors = BTreeSet::new();
    for mirror in mirrors {
        if !semgrep_source_url(mirror) || !seen_mirrors.insert(mirror.as_str()) {
            return Err(RunnerError::InvalidManifest);
        }
    }
    let declared_strong = validate_semgrep_checksums(checksums, false)?;
    if supplemental.is_empty() {
        return declared_strong
            .then_some(())
            .ok_or(RunnerError::InvalidManifest);
    }
    if declared_strong
        || url != LEGACY_BIGSTRINGAF_URL
        || supplemental.len() != 1
        || checksums
            .iter()
            .find(|item| item.algorithm == "md5")
            .map(|item| item.digest.as_str())
            != Some(LEGACY_BIGSTRINGAF_MD5)
        || supplemental[0].algorithm != "sha256"
        || supplemental[0].digest != LEGACY_BIGSTRINGAF_SHA256
    {
        return Err(RunnerError::InvalidManifest);
    }
    validate_semgrep_checksums(supplemental, true).map(|_| ())
}

fn validate_semgrep_resolved_sources(sources: &[SemgrepResolvedSource]) -> Result<(), RunnerError> {
    if sources.is_empty() || sources.len() > MAX_SEMGREP_SOURCE_PACKAGES {
        return Err(RunnerError::InvalidManifest);
    }
    let mut previous: Option<(&str, &str)> = None;
    let mut seen = BTreeSet::new();
    for source in sources {
        if !semgrep_atom(&source.package)
            || !semgrep_atom(&source.version)
            || !seen.insert((source.package.as_str(), source.version.as_str()))
            || previous.is_some_and(|prior| {
                prior.0 > source.package.as_str()
                    || (prior.0 == source.package && prior.1 >= source.version.as_str())
            })
        {
            return Err(RunnerError::InvalidManifest);
        }
        previous = Some((&source.package, &source.version));

        if source.targets.is_empty() || source.targets.len() > 2 {
            return Err(RunnerError::InvalidManifest);
        }
        let mut previous_target = None;
        for target in &source.targets {
            let rank = match target.as_str() {
                "aarch64-apple-darwin" => 0,
                "windows-x86_64" => 1,
                _ => return Err(RunnerError::InvalidManifest),
            };
            if previous_target.is_some_and(|prior| rank <= prior) {
                return Err(RunnerError::InvalidManifest);
            }
            previous_target = Some(rank);
        }

        let expected_path = format!("packages/{0}/{0}.{1}/opam", source.package, source.version);
        if source.opam_path != expected_path
            || !lower_hex(&source.opam_sha256, 64)
            || !source.opam_sha256.bytes().any(|byte| byte != b'0')
            || source.licenses.is_empty()
            || source.licenses.len() > 16
            || source.licenses.iter().any(|license| {
                license.is_empty()
                    || license.len() > 256
                    || license.nfc().collect::<String>() != *license
                    || license.bytes().any(|byte| byte < b' ' || byte == 0x7f)
            })
        {
            return Err(RunnerError::InvalidManifest);
        }
        if let Some(archive) = &source.source {
            validate_semgrep_source_archive(
                &archive.checksums,
                &archive.mirrors,
                &archive.supplemental_checksums,
                &archive.url,
            )?;
        }
        if source.extra_sources.len() > 16 {
            return Err(RunnerError::InvalidManifest);
        }
        let mut previous_extra: Option<&str> = None;
        let mut folded_extra = BTreeSet::new();
        for extra in &source.extra_sources {
            if !semgrep_atom(&extra.name)
                || extra.name.contains(['/', '\\'])
                || matches!(extra.name.as_str(), "." | "..")
                || previous_extra.is_some_and(|prior| prior >= extra.name.as_str())
                || !folded_extra.insert(extra.name.to_ascii_lowercase())
            {
                return Err(RunnerError::InvalidManifest);
            }
            previous_extra = Some(&extra.name);
            validate_semgrep_source_archive(
                &extra.checksums,
                &extra.mirrors,
                &extra.supplemental_checksums,
                &extra.url,
            )?;
        }
    }
    Ok(())
}

fn validate_semgrep_license_materials(
    materials: &[SemgrepLicenseMaterial],
) -> Result<(), RunnerError> {
    if materials.is_empty() || materials.len() > 64 {
        return Err(RunnerError::InvalidManifest);
    }
    let mut previous: Option<String> = None;
    let mut paths = BTreeSet::new();
    let mut licensed_sources = BTreeSet::new();
    let mut noticed_sources = BTreeSet::new();
    for material in materials {
        let key = format!("{}\0{}\0{}", material.source, material.kind, material.path);
        if !valid_id(&material.source)
            || !matches!(material.kind.as_str(), "license" | "notice")
            || material.spdx.is_empty()
            || material.spdx.len() > 256
            || material.spdx.nfc().collect::<String>() != material.spdx
            || material
                .spdx
                .bytes()
                .any(|byte| byte < b' ' || byte == 0x7f)
            || manifest_path(&material.path).is_err()
            || !lower_hex(&material.sha256, 64)
            || !material.sha256.bytes().any(|byte| byte != b'0')
            || previous.as_ref().is_some_and(|value| value >= &key)
            || !paths.insert(material.path.as_str())
        {
            return Err(RunnerError::InvalidManifest);
        }
        previous = Some(key);
        if material.kind == "license" {
            if !licensed_sources.insert(material.source.as_str()) {
                return Err(RunnerError::InvalidManifest);
            }
        } else {
            noticed_sources.insert(material.source.as_str());
        }
        let expected_prefix = match material.source.as_str() {
            "semgrep" => "sources/semgrep/",
            "tree-sitter-runtime" => "support/",
            _ => "pins/",
        };
        if !material.path.starts_with(expected_prefix) {
            return Err(RunnerError::InvalidManifest);
        }
    }
    let expected = SEMGREP_LICENSE_SOURCES.into_iter().collect::<BTreeSet<_>>();
    if licensed_sources != expected || !noticed_sources.is_subset(&licensed_sources) {
        return Err(RunnerError::InvalidManifest);
    }
    Ok(())
}

fn verify_semgrep_source_gate(
    root: &Path,
    tool: &Tool,
    target: RuntimeTarget,
) -> Result<(), RunnerError> {
    let source = &tool.source;
    let bytes = read_verified_file(
        root,
        &source.material_path,
        parse_hash(&source.material_sha256)?,
        MAX_SOURCE_LOCK_BYTES,
    )?;
    let gate: SemgrepSourceGate =
        serde_json::from_slice(&bytes).map_err(|_| RunnerError::InvalidManifest)?;
    let distribution_target = match target {
        RuntimeTarget::WindowsX86_64 => "windows-x86_64",
        RuntimeTarget::MacosArm64 => "aarch64-apple-darwin",
    };
    let matching_targets = gate
        .target_status
        .iter()
        .filter(|status| status.distribution_target == distribution_target)
        .collect::<Vec<_>>();
    validate_semgrep_resolved_sources(&gate.opam.resolved_source_archives)?;
    validate_semgrep_license_materials(&gate.license_materials)?;
    if gate.source_revision != source.revision
        || gate.source_tree != source.tree
        || !gate.complete_corresponding_source
        || !gate.recursive_inventory_complete
        || !gate.opam.resolved_source_archives_complete
        || gate.opam.resolved_source_archives.is_empty()
        || !gate.missing_material.is_empty()
        || matching_targets.len() != 1
        || !matching_targets[0].enabled
    {
        return Err(RunnerError::InvalidManifest);
    }
    verify_semgrep_bundle_evidence(root, tool)?;
    verify_semgrep_native_build_evidence(root, tool, &gate)?;
    Ok(())
}

fn verify_semgrep_bundle_evidence(root: &Path, tool: &Tool) -> Result<(), RunnerError> {
    let evidence = tool
        .materials
        .iter()
        .filter(|material| material.role == "source-bundle-evidence")
        .collect::<Vec<_>>();
    let generator = tool
        .materials
        .iter()
        .filter(|material| material.role == "source-bundle-generator")
        .collect::<Vec<_>>();
    if evidence.len() != 1 || generator.len() != 1 {
        return Err(RunnerError::InvalidManifest);
    }
    let evidence = evidence[0];
    let generator = generator[0];
    verify_file(
        root,
        &generator.path,
        None,
        parse_hash(&generator.sha256)?,
        None,
    )?;
    let bytes = read_verified_file(
        root,
        &evidence.path,
        parse_hash(&evidence.sha256)?,
        MAX_BUNDLE_EVIDENCE_BYTES,
    )?;
    let evidence: SemgrepBundleEvidence =
        serde_json::from_slice(&bytes).map_err(|_| RunnerError::InvalidManifest)?;
    let bundle_hash = parse_hash(&evidence.bundle.sha256)?;
    parse_hash(&evidence.source_lock_sha256)?;
    parse_hash(&evidence.bundle_generator_sha256)?;
    if evidence.schema_version != 1
        || evidence.format != "context-relay-semgrep-source-v1"
        || evidence.source_lock_sha256 != tool.source.material_sha256
        || evidence.bundle_generator_sha256 != generator.sha256
        || evidence.independent_builds != 2
        || !evidence.byte_identical
        || evidence.status != "complete_corresponding_source"
        || evidence.source_asset_url != SEMGREP_SOURCE_ASSET_URL
        || bundle_hash == [0; 32]
        || evidence.bundle.size == 0
        || evidence.bundle.size > MAX_SOURCE_BUNDLE_BYTES
        || evidence.bundle.payload_entries == 0
        || evidence.bundle.payload_entries > 1_000_000
        || evidence.bundle.recorded_links > 1_000_000
    {
        return Err(RunnerError::InvalidManifest);
    }
    Ok(())
}

fn verify_semgrep_native_identity(
    identity: &SemgrepIdentity,
    maximum: u64,
) -> Result<(), RunnerError> {
    if parse_hash(&identity.sha256)? == [0; 32] || identity.size == 0 || identity.size > maximum {
        return Err(RunnerError::InvalidManifest);
    }
    Ok(())
}

fn semgrep_native_policy(
    target: &str,
) -> Option<(&'static str, &'static str, &'static str, &'static str)> {
    match target {
        "windows-x86_64" => Some((
            "task9-semgrep-windows-build",
            "native-semgrep-windows-x64-builders",
            "native-isolation-windows-x64",
            "windows-appcontainer",
        )),
        "macos-aarch64" => Some((
            "task9-semgrep-macos-build",
            "native-semgrep-macos-arm64-builders",
            "native-isolation-macos-arm64",
            "macos-sandbox-exec-inherited",
        )),
        _ => None,
    }
}

fn verify_semgrep_native_build_evidence(
    root: &Path,
    tool: &Tool,
    source_gate: &SemgrepSourceGate,
) -> Result<(), RunnerError> {
    let native_materials = tool
        .materials
        .iter()
        .filter(|material| material.role == "native-build-evidence")
        .collect::<Vec<_>>();
    let source_reference = source_gate
        .native_build_evidence
        .as_ref()
        .ok_or(RunnerError::InvalidManifest)?;
    if native_materials.len() != 1
        || native_materials[0].path != SEMGREP_NATIVE_EVIDENCE_PATH
        || source_reference.path != native_materials[0].path
        || source_reference.sha256 != native_materials[0].sha256
        || source_reference.support.len() != SEMGREP_NATIVE_SUPPORT.len()
    {
        return Err(RunnerError::InvalidManifest);
    }
    let native_hash = parse_hash(&native_materials[0].sha256)?;
    if native_hash == [0; 32] {
        return Err(RunnerError::InvalidManifest);
    }
    let bytes = read_verified_file(
        root,
        &native_materials[0].path,
        native_hash,
        MAX_NATIVE_BUILD_EVIDENCE_BYTES,
    )?;
    let evidence: SemgrepNativeBuildEvidence =
        serde_json::from_slice(&bytes).map_err(|_| RunnerError::InvalidManifest)?;
    if evidence.schema_version != 1
        || evidence.status != "native_builds_and_sandbox_smokes_verified"
        || evidence.support.len() != SEMGREP_NATIVE_SUPPORT.len()
    {
        return Err(RunnerError::InvalidManifest);
    }
    for (index, (role, path)) in SEMGREP_NATIVE_SUPPORT.iter().enumerate() {
        let matches = tool
            .materials
            .iter()
            .filter(|material| material.role == *role && material.path == *path)
            .collect::<Vec<_>>();
        if matches.len() != 1
            || source_reference.support[index].path != *path
            || evidence.support[index].path != *path
            || source_reference.support[index].sha256 != matches[0].sha256
            || evidence.support[index].sha256 != matches[0].sha256
            || parse_hash(&matches[0].sha256)? == [0; 32]
        {
            return Err(RunnerError::InvalidManifest);
        }
    }
    if evidence.provenance_sha256 != evidence.support[0].sha256
        || parse_hash(&evidence.provenance_sha256)? == [0; 32]
    {
        return Err(RunnerError::InvalidManifest);
    }

    let bootstrap = &evidence.bootstrap_source;
    if bootstrap.source_revision != source_gate.source_revision
        || bootstrap.source_tree != source_gate.source_tree
        || !lower_hex(&bootstrap.source_revision, 40)
        || !lower_hex(&bootstrap.source_tree, 40)
        || parse_hash(&bootstrap.source_lock_sha256)? == [0; 32]
        || parse_hash(&bootstrap.bundle_evidence_sha256)? == [0; 32]
        || parse_hash(&bootstrap.bundle.sha256)? == [0; 32]
        || bootstrap.bundle.size == 0
        || bootstrap.bundle.size > MAX_SOURCE_BUNDLE_BYTES
        || bootstrap.bundle.payload_entries == 0
        || bootstrap.bundle.payload_entries > 1_000_000
        || bootstrap.bundle.recorded_links > 1_000_000
    {
        return Err(RunnerError::InvalidManifest);
    }
    let ci = &evidence.ci;
    if !lower_hex(&ci.commit, 40)
        || ci.workflow_sha != ci.commit
        || ci.run_attempt == 0
        || ci.run_id.is_empty()
        || ci.run_id.len() > 32
        || ci.run_id.starts_with('0')
        || !ci.run_id.bytes().all(|byte| byte.is_ascii_digit())
        || !ci
            .workflow_ref
            .ends_with("/.github/workflows/ci.yml@refs/heads/main")
    {
        return Err(RunnerError::InvalidManifest);
    }

    let enabled = tool
        .targets
        .iter()
        .filter(|target| target.enabled)
        .map(|target| target.target.as_str())
        .collect::<BTreeSet<_>>();
    let smoke_targets = evidence
        .smokes
        .iter()
        .map(|smoke| smoke.target.as_str())
        .collect::<BTreeSet<_>>();
    let runtime_targets = evidence
        .targets
        .iter()
        .map(|target| target.target.as_str())
        .collect::<BTreeSet<_>>();
    if enabled.is_empty()
        || smoke_targets != enabled
        || runtime_targets != enabled
        || evidence.smokes.len() != enabled.len()
        || evidence.targets.len() != enabled.len()
        || evidence.builders.len() != enabled.len() * 2
    {
        return Err(RunnerError::InvalidManifest);
    }
    let mut check_run_ids = BTreeSet::new();
    for target_name in &enabled {
        let (artifact_prefix, builder_job, smoke_job, sandbox) =
            semgrep_native_policy(target_name).ok_or(RunnerError::InvalidManifest)?;
        let builders = evidence
            .builders
            .iter()
            .filter(|builder| builder.target == *target_name)
            .collect::<Vec<_>>();
        if builders.len() != 2 {
            return Err(RunnerError::InvalidManifest);
        }
        for (slot, expected_index) in [("a", 0_u8), ("b", 1_u8)] {
            let builder = builders
                .iter()
                .find(|builder| builder.build == format!("build-{slot}"))
                .ok_or(RunnerError::InvalidManifest)?;
            let artifact_name = format!(
                "{artifact_prefix}-{slot}-{}-{}-{}",
                ci.commit, ci.run_id, ci.run_attempt
            );
            if builder.artifact_name != artifact_name
                || builder.job_definition != builder_job
                || builder.job_index != expected_index
                || builder.job_total != 2
                || builder.identity_size == 0
                || builder.identity_size > 1_048_576
                || builder.check_run_id == 0
                || builder.runner_name.is_empty()
                || builder.runner_os.is_empty()
                || builder.runner_arch.is_empty()
                || parse_hash(&builder.identity_sha256)? == [0; 32]
                || !check_run_ids.insert(builder.check_run_id)
            {
                return Err(RunnerError::InvalidManifest);
            }
        }
        let smoke = evidence
            .smokes
            .iter()
            .find(|smoke| smoke.target == *target_name)
            .ok_or(RunnerError::InvalidManifest)?;
        if smoke.job_definition != smoke_job
            || smoke.sandbox_mechanism != sandbox
            || smoke.check_run_id == 0
            || smoke.size == 0
            || smoke.size > 1_048_576
            || parse_hash(&smoke.sha256)? == [0; 32]
            || !check_run_ids.insert(smoke.check_run_id)
        {
            return Err(RunnerError::InvalidManifest);
        }

        let target_evidence = evidence
            .targets
            .iter()
            .find(|target| target.target == *target_name)
            .ok_or(RunnerError::InvalidManifest)?;
        let manifest_target = tool
            .targets
            .iter()
            .find(|target| target.target == *target_name)
            .ok_or(RunnerError::InvalidManifest)?;
        let download = manifest_target
            .download
            .as_ref()
            .ok_or(RunnerError::InvalidManifest)?;
        let archive_name = download
            .url
            .rsplit('/')
            .next()
            .ok_or(RunnerError::InvalidManifest)?;
        if target_evidence.runtime_archive.name != archive_name
            || target_evidence.runtime_archive.size != download.size
            || target_evidence.runtime_archive.sha256 != download.sha256
            || target_evidence.evidence_archive.name.is_empty()
        {
            return Err(RunnerError::InvalidManifest);
        }
        verify_semgrep_native_identity(
            &SemgrepIdentity {
                size: target_evidence.evidence_archive.size,
                sha256: target_evidence.evidence_archive.sha256.clone(),
            },
            MAX_ARTIFACT_BYTES,
        )?;
        verify_semgrep_native_identity(&target_evidence.runtime_closure, 1_048_576)?;
        let manifests = &target_evidence.manifests;
        for identity in [
            &manifests.build_a,
            &manifests.build_b,
            &manifests.build_a_evidence,
            &manifests.build_b_evidence,
        ] {
            verify_semgrep_native_identity(identity, 1_048_576)?;
        }
        if manifests.build_a.sha256 != manifests.build_b.sha256
            || manifests.build_a_evidence.sha256 != manifests.build_b_evidence.sha256
            || target_evidence.offline_evidence.len() != 2
        {
            return Err(RunnerError::InvalidManifest);
        }
        for (index, offline) in target_evidence.offline_evidence.iter().enumerate() {
            if offline.build != format!("build-{}", if index == 0 { "a" } else { "b" }) {
                return Err(RunnerError::InvalidManifest);
            }
            verify_semgrep_native_identity(
                &SemgrepIdentity {
                    size: offline.size,
                    sha256: offline.sha256.clone(),
                },
                1_048_576,
            )?;
        }
    }

    if enabled.contains("windows-x86_64") {
        let windows = evidence
            .windows_builder
            .as_ref()
            .ok_or(RunnerError::InvalidManifest)?;
        for identity in [&windows.evidence, &windows.schema, &windows.toolchain] {
            verify_semgrep_native_identity(identity, 16_777_216)?;
        }
        let source_windows = source_gate
            .toolchains
            .iter()
            .filter(|toolchain| toolchain.distribution_target == "windows-x86_64")
            .collect::<Vec<_>>();
        let builder = source_windows
            .first()
            .and_then(|toolchain| toolchain.builder_evidence.as_ref())
            .ok_or(RunnerError::InvalidManifest)?;
        if source_windows.len() != 1
            || source_windows[0].status.as_deref() != Some("native_builds_verified")
            || builder.status != "verified_native_capture"
            || builder.sha256.as_deref() != Some(windows.evidence.sha256.as_str())
            || builder.schema_sha256 != windows.schema.sha256
        {
            return Err(RunnerError::InvalidManifest);
        }
    } else if evidence.windows_builder.is_some() {
        return Err(RunnerError::InvalidManifest);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    volume: u64,
    index: u64,
    links: u64,
}

#[cfg(unix)]
fn file_identity(file: &File) -> Result<FileIdentity, RunnerError> {
    let metadata = file.metadata().map_err(|_| RunnerError::MissingMaterial)?;
    Ok(FileIdentity {
        volume: metadata.dev(),
        index: metadata.ino(),
        links: metadata.nlink(),
    })
}

#[cfg(windows)]
fn file_identity(file: &File) -> Result<FileIdentity, RunnerError> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the owned file handle stays valid for this call and the output pointer refers to
    // initialized writable storage of the exact Win32 structure type.
    let succeeded = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) };
    if succeeded == 0 {
        return Err(RunnerError::MissingMaterial);
    }
    Ok(FileIdentity {
        volume: u64::from(information.dwVolumeSerialNumber),
        index: (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow),
        links: u64::from(information.nNumberOfLinks),
    })
}

#[cfg(unix)]
fn executable_mode_matches(metadata: &fs::Metadata, expected: bool) -> bool {
    (metadata.mode() & 0o111 != 0) == expected
}

#[cfg(windows)]
fn executable_mode_matches(_metadata: &fs::Metadata, _expected: bool) -> bool {
    true
}

fn closure_digest(materials: &[VerifiedMaterial]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"context-relay/sidecar-closure/v1\0");
    for material in materials {
        hasher.update(material.path.as_str().as_bytes());
        hasher.update([0]);
        hasher.update(material.size.to_be_bytes());
        hasher.update(material.sha256);
        hasher.update([u8::from(material.executable)]);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_semgrep_archive_inventory_passes_the_rust_gate() {
        let bytes = include_bytes!("../../../third_party/sidecars/semgrep/source-lock.v1.json");
        let gate: SemgrepSourceGate = serde_json::from_slice(bytes).unwrap();
        let sources = &gate.opam.resolved_source_archives;

        assert_eq!(sources.len(), 244);
        assert_eq!(
            sources
                .iter()
                .filter(|source| source.source.is_some())
                .count(),
            208
        );
        assert_eq!(
            sources
                .iter()
                .filter(|source| source.source.is_none())
                .count(),
            36
        );
        assert_eq!(
            sources
                .iter()
                .map(|source| source.extra_sources.len())
                .sum::<usize>(),
            10
        );
        assert_eq!(
            sources
                .iter()
                .filter(|source| {
                    source
                        .source
                        .as_ref()
                        .is_some_and(|archive| !archive.supplemental_checksums.is_empty())
                        || source
                            .extra_sources
                            .iter()
                            .any(|archive| !archive.supplemental_checksums.is_empty())
                })
                .count(),
            1
        );
        validate_semgrep_resolved_sources(sources).unwrap();
        validate_semgrep_license_materials(&gate.license_materials).unwrap();
    }

    #[test]
    fn semgrep_archive_inventory_rejects_missing_license_metadata() {
        let source: SemgrepResolvedSource = serde_json::from_value(serde_json::json!({
            "package": "virtual",
            "version": "base",
            "targets": ["windows-x86_64"],
            "opamPath": "packages/virtual/virtual.base/opam",
            "opamSha256": "a".repeat(64),
            "licenses": [],
            "source": null,
            "extraSources": []
        }))
        .unwrap();
        assert!(validate_semgrep_resolved_sources(&[source]).is_err());
    }
}
