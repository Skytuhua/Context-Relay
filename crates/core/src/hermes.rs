//! Hermes adapter identity and profile binding.
//!
//! The adapter attests one explicit profile before importing only reviewed
//! configuration and file surfaces. Native rendering remains closed.

mod import;
mod profile;
mod yaml;

use std::{
    collections::BTreeSet,
    env, fs,
    fs::OpenOptions,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use context_relay_protocol::{
    ApplyReceipt, CapabilityLevel, ClassifiedChanges, CliOperations, ClientError, DesiredState,
    DeviceId, DiscoveredScopes, ErrorCode, HarnessAdapter, HarnessId, HybridLogicalClock,
    ImportRequest, ImportedState, InstallationMethod, NativePlatform, NativeScope, ProbeContext,
    ProbeReport, ProjectId, RenderedState, SemanticDiff, Sha256Digest, ValidationReport,
    WireNativeValue,
};
use sha2::{Digest as _, Sha256};

const SUPPORTED_VERSIONS: [&str; 2] = ["0.18.2", "0.18.1"];
const CLI_TIMEOUT_MS: u32 = 30_000;
const CLI_OUTPUT_LIMIT: u64 = 64 * 1024;
#[allow(dead_code)]
const MANAGED_START: &str = "<!-- context-relay:start -->";
#[allow(dead_code)]
const MANAGED_END: &str = "<!-- context-relay:end -->";
const DEFAULT_PROFILE: &str = "default";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HermesExecutableKind {
    Native,
    Wrapper,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExecutableSnapshot {
    kind: HermesExecutableKind,
    digest: Sha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AttestedExecutable {
    snapshot: ExecutableSnapshot,
    bytes: Vec<u8>,
}

#[derive(Debug)]
struct StagedExecutable {
    _directory: tempfile::TempDir,
    path: PathBuf,
    snapshot: ExecutableSnapshot,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HermesProfile {
    pub name: String,
    pub hermes_home: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HermesMemoryKind {
    Agent,
    User,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HermesMemoryDocument {
    pub kind: HermesMemoryKind,
    pub body_markdown: String,
    pub source_digest: Sha256Digest,
}

#[derive(Clone, Debug)]
pub struct HermesLayout {
    pub executable: PathBuf,
    pub executable_kind: HermesExecutableKind,
    pub version: String,
    pub installation_method: InstallationMethod,
    pub default_hermes_home: PathBuf,
    pub profile: HermesProfile,
    pub project_root: PathBuf,
    pub working_directory: PathBuf,
}

#[derive(Clone, Debug)]
pub struct HermesAdapter {
    layout: HermesLayout,
    project_id: ProjectId,
    #[allow(dead_code)]
    origin_device: DeviceId,
    #[allow(dead_code)]
    observed_hlc: HybridLogicalClock,
    executable_hash: Sha256Digest,
}

impl HermesAdapter {
    pub fn discover(
        project_root: impl Into<PathBuf>,
        working_directory: impl Into<PathBuf>,
        requested_profile: &str,
        project_id: ProjectId,
        origin_device: DeviceId,
        observed_hlc: HybridLogicalClock,
    ) -> Result<Self, ClientError> {
        let default_hermes_home = default_hermes_home()?;
        let profile = profile::select_profile(&default_hermes_home, requested_profile)?;
        let executable =
            find_executable().ok_or_else(|| not_found("Hermes executable was not found"))?;
        let (snapshot, version) = discover_executable_version(&executable)?;
        let installation_method = installation_method(&executable);
        Self::from_attested_layout(
            HermesLayout {
                executable,
                executable_kind: snapshot.kind,
                version,
                installation_method,
                default_hermes_home,
                profile,
                project_root: project_root.into(),
                working_directory: working_directory.into(),
            },
            project_id,
            origin_device,
            observed_hlc,
            snapshot,
        )
    }

    pub fn from_layout(
        layout: HermesLayout,
        project_id: ProjectId,
        origin_device: DeviceId,
        observed_hlc: HybridLogicalClock,
    ) -> Result<Self, ClientError> {
        Self::from_layout_with_expected_snapshot(
            layout,
            project_id,
            origin_device,
            observed_hlc,
            None,
        )
    }

    fn from_attested_layout(
        layout: HermesLayout,
        project_id: ProjectId,
        origin_device: DeviceId,
        observed_hlc: HybridLogicalClock,
        expected_snapshot: ExecutableSnapshot,
    ) -> Result<Self, ClientError> {
        Self::from_layout_with_expected_snapshot(
            layout,
            project_id,
            origin_device,
            observed_hlc,
            Some(expected_snapshot),
        )
    }

    fn from_layout_with_expected_snapshot(
        mut layout: HermesLayout,
        project_id: ProjectId,
        origin_device: DeviceId,
        observed_hlc: HybridLogicalClock,
        expected_snapshot: Option<ExecutableSnapshot>,
    ) -> Result<Self, ClientError> {
        if !valid_version(&layout.version) && layout.version != "unknown" {
            return Err(invalid("Hermes version is invalid"));
        }
        require_file(&layout.executable, "Hermes executable was not found")?;
        layout.executable = fs::canonicalize(&layout.executable)
            .map_err(|_| invalid("Hermes executable cannot be safely resolved"))?;
        let executable = snapshot_executable(&layout.executable)?;
        if expected_snapshot.is_some_and(|expected| executable != expected) {
            return Err(conflict("Hermes executable changed"));
        }
        require_directory(&layout.project_root, "Hermes project root was not found")?;
        require_directory(
            &layout.working_directory,
            "Hermes working directory was not found",
        )?;
        layout.default_hermes_home = profile::canonical_real_directory(
            &layout.default_hermes_home,
            "Hermes default profile was not found",
        )?;
        layout.project_root = fs::canonicalize(&layout.project_root)
            .map_err(|_| invalid("Hermes project root cannot be safely resolved"))?;
        layout.working_directory = fs::canonicalize(&layout.working_directory)
            .map_err(|_| invalid("Hermes working directory cannot be safely resolved"))?;
        if !layout.working_directory.starts_with(&layout.project_root) {
            return Err(invalid(
                "Hermes working directory is outside the project root",
            ));
        }
        profile::validate_profile_binding(&layout.default_hermes_home, &layout.profile)?;
        layout.profile =
            profile::select_profile(&layout.default_hermes_home, &layout.profile.name)?;
        layout.executable_kind = executable.kind;
        Ok(Self {
            layout,
            project_id,
            origin_device,
            observed_hlc,
            executable_hash: executable.digest,
        })
    }

    pub fn discover_profiles(
        default_hermes_home: impl AsRef<Path>,
    ) -> Result<Vec<HermesProfile>, ClientError> {
        profile::enumerate_profiles(default_hermes_home.as_ref())
    }

    pub fn profile_home_wire(&self) -> WireNativeValue {
        wire_path(&self.layout.profile.hermes_home)
    }

    pub fn project_root_wire(&self) -> WireNativeValue {
        wire_path(&self.layout.project_root)
    }

    pub fn import_native_memory(&self) -> Result<Vec<HermesMemoryDocument>, ClientError> {
        self.import_memory_documents()
    }

    fn capability(&self) -> CapabilityLevel {
        if SUPPORTED_VERSIONS.contains(&self.layout.version.as_str())
            && self.layout.executable_kind == HermesExecutableKind::Native
            && self.yaml_topology_supported()
        {
            CapabilityLevel::Full
        } else {
            CapabilityLevel::ImportOnly
        }
    }

    fn yaml_topology_supported(&self) -> bool {
        let path = self.layout.profile.hermes_home.join("config.yaml");
        fs::read(path)
            .ok()
            .and_then(|bytes| yaml::parse_config(&bytes).ok())
            .is_some_and(|parsed| yaml::topology_supported(&parsed))
    }
}

impl HarnessAdapter for HermesAdapter {
    fn probe(&self, context: &ProbeContext) -> Result<ProbeReport, ClientError> {
        context
            .validate()
            .map_err(|_| invalid("Hermes probe context is invalid"))?;
        if context.harness != HarnessId::Hermes {
            return Err(invalid("Hermes adapter received another harness"));
        }
        let requested = context
            .requested_profile
            .as_deref()
            .ok_or_else(|| invalid("Hermes probe requires an explicit profile"))?;
        if ascii_lowercase(requested) != self.layout.profile.name {
            return Err(invalid("Hermes probe profile does not match the adapter"));
        }
        Ok(ProbeReport {
            executable: Some(wire_path(&self.layout.executable)),
            executable_sha256: Some(self.executable_hash),
            harness_version: Some(self.layout.version.clone()),
            installation_method: self.layout.installation_method,
            config_roots: vec![self.profile_home_wire(), self.project_root_wire()],
            active_profile: Some(self.layout.profile.name.clone()),
            policy_conflicts: self.import_policy_conflicts(),
            capability: self.capability(),
        })
    }

    fn discover_scopes(&self, report: &ProbeReport) -> Result<DiscoveredScopes, ClientError> {
        report
            .validate()
            .map_err(|_| invalid("Hermes probe report is invalid"))?;
        Ok(DiscoveredScopes(vec![
            NativeScope::Global,
            NativeScope::Project {
                project_id: self.project_id,
                root: self.project_root_wire(),
            },
        ]))
    }

    fn import(&self, request: &ImportRequest) -> Result<ImportedState, ClientError> {
        request
            .validate()
            .map_err(|_| invalid("Hermes import request is invalid"))?;
        let mut components = Vec::new();
        let mut digests = BTreeSet::new();
        let mut seen = BTreeSet::new();
        for native_scope in &request.scopes {
            let scope = import::validate_bound_scope(self, native_scope)?;
            let key = match scope {
                context_relay_protocol::ScopeRef::Global => "global".to_owned(),
                context_relay_protocol::ScopeRef::Project { project_id } => {
                    format!("project:{project_id}")
                }
            };
            if !seen.insert(key) {
                return Err(invalid("Hermes import repeated a scope"));
            }
            self.import_scope(
                scope,
                request.include_disabled,
                &mut components,
                &mut digests,
            )?;
        }
        components.sort_by_key(|component| component.id);
        let imported = ImportedState {
            components,
            source_digests: digests.into_iter().collect(),
        };
        imported
            .validate()
            .map_err(|_| invalid("Hermes imported state exceeds protocol limits"))?;
        Ok(imported)
    }

    fn render(&self, _desired: &DesiredState) -> Result<RenderedState, ClientError> {
        Err(phase_unsupported())
    }

    fn classify(&self, _diff: &SemanticDiff) -> Result<ClassifiedChanges, ClientError> {
        Err(phase_unsupported())
    }

    fn plan_cli_ops(&self, _changes: &ClassifiedChanges) -> Result<CliOperations, ClientError> {
        Err(phase_unsupported())
    }

    fn validate_effective(&self, _receipt: &ApplyReceipt) -> Result<ValidationReport, ClientError> {
        Err(phase_unsupported())
    }
}

fn default_hermes_home() -> Result<PathBuf, ClientError> {
    if let Some(home) = env::var_os("HERMES_HOME") {
        return Ok(PathBuf::from(home));
    }
    let home = home_dir().ok_or_else(|| not_found("Hermes home directory was not found"))?;
    #[cfg(target_os = "windows")]
    {
        return Ok(env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .map(|local| local.join("hermes"))
            .unwrap_or_else(|| home.join(".hermes")));
    }
    #[cfg(not(target_os = "windows"))]
    Ok(home.join(".hermes"))
}

fn find_executable() -> Option<PathBuf> {
    let executable = if cfg!(windows) {
        "hermes.exe"
    } else {
        "hermes"
    };
    env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| env::split_paths(&paths).collect::<Vec<_>>())
        .map(|directory| directory.join(executable))
        .find(|candidate| candidate.is_file())
        .or_else(|| {
            cfg!(target_os = "macos")
                .then(home_dir)
                .flatten()
                .map(|home| home.join(".local/bin/hermes"))
                .filter(|candidate| candidate.is_file())
        })
}

fn snapshot_executable(path: &Path) -> Result<ExecutableSnapshot, ClientError> {
    Ok(attest_executable(path)?.snapshot)
}

fn attest_executable(path: &Path) -> Result<AttestedExecutable, ClientError> {
    let bytes = fs::read(path).map_err(|_| not_found("Hermes executable was not found"))?;
    Ok(AttestedExecutable {
        snapshot: ExecutableSnapshot {
            kind: classify_executable_bytes(path, &bytes),
            digest: Sha256Digest(Sha256::digest(&bytes).into()),
        },
        bytes,
    })
}

fn stage_executable(attested: &AttestedExecutable) -> Result<StagedExecutable, ClientError> {
    let mut builder = tempfile::Builder::new();
    builder.prefix("context-relay-hermes-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        builder.permissions(fs::Permissions::from_mode(0o700));
    }
    let directory = builder
        .tempdir()
        .map_err(|_| invalid("Hermes executable could not be staged"))?;
    let path = directory.path().join(if cfg!(windows) {
        "hermes.exe"
    } else {
        "hermes"
    });
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o700);
    }
    let mut file = options
        .open(&path)
        .map_err(|_| invalid("Hermes executable could not be staged"))?;
    file.write_all(&attested.bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| invalid("Hermes executable could not be staged"))?;
    drop(file);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .map_err(|_| invalid("Hermes executable could not be staged"))?;
    }
    let staged_snapshot = snapshot_executable(&path)?;
    if staged_snapshot != attested.snapshot {
        return Err(conflict("Hermes staged executable changed"));
    }
    Ok(StagedExecutable {
        _directory: directory,
        path,
        snapshot: staged_snapshot,
    })
}

fn classify_executable_bytes(path: &Path, bytes: &[u8]) -> HermesExecutableKind {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase);
    if matches!(extension.as_deref(), Some("cmd" | "bat" | "ps1")) {
        return HermesExecutableKind::Wrapper;
    }
    if bytes.starts_with(b"\x7fELF")
        || bytes.starts_with(b"MZ")
        || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xce])
        || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
        || bytes.starts_with(&[0xce, 0xfa, 0xed, 0xfe])
        || bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
        || bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
        || bytes.starts_with(&[0xbe, 0xba, 0xfe, 0xca])
        || bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbf])
        || bytes.starts_with(&[0xbf, 0xba, 0xfe, 0xca])
    {
        return HermesExecutableKind::Native;
    }
    if bytes.starts_with(b"#!") {
        return HermesExecutableKind::Wrapper;
    }
    HermesExecutableKind::Unknown
}

fn discover_executable_version(
    executable: &Path,
) -> Result<(ExecutableSnapshot, String), ClientError> {
    discover_executable_version_after_snapshot(executable, || {}, run_version)
}

fn discover_executable_version_after_snapshot(
    executable: &Path,
    after_snapshot: impl FnOnce(),
    execute: impl FnMut(&Path, ExecutableSnapshot) -> Result<Vec<u8>, ClientError>,
) -> Result<(ExecutableSnapshot, String), ClientError> {
    discover_executable_version_with_boundaries(executable, after_snapshot, |_, _| {}, execute)
}

fn discover_executable_version_with_boundaries(
    executable: &Path,
    after_snapshot: impl FnOnce(),
    after_staging: impl FnOnce(&Path, &Path),
    mut execute: impl FnMut(&Path, ExecutableSnapshot) -> Result<Vec<u8>, ClientError>,
) -> Result<(ExecutableSnapshot, String), ClientError> {
    let attested = attest_executable(executable)?;
    let version = if attested.snapshot.kind == HermesExecutableKind::Native {
        after_snapshot();
        if snapshot_executable(executable)? != attested.snapshot {
            return Err(conflict("Hermes executable changed"));
        }
        let staged = stage_executable(&attested)?;
        after_staging(executable, &staged.path);
        let output = execute(&staged.path, staged.snapshot)?;
        if snapshot_executable(&staged.path)? != staged.snapshot {
            return Err(conflict("Hermes staged executable changed"));
        }
        parse_version(&output).ok_or_else(|| invalid("Hermes returned an invalid version"))?
    } else {
        "unknown".to_owned()
    };
    Ok((attested.snapshot, version))
}

fn run_version(
    executable: &Path,
    expected_snapshot: ExecutableSnapshot,
) -> Result<Vec<u8>, ClientError> {
    if snapshot_executable(executable)? != expected_snapshot {
        return Err(conflict("Hermes executable changed"));
    }
    let mut child = Command::new(executable)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| not_found("Hermes executable could not be started"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| invalid("Hermes version output is unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| invalid("Hermes version output is unavailable"))?;
    let stdout_thread = thread::spawn(move || read_capped(stdout));
    let stderr_thread = thread::spawn(move || read_capped(stderr));
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|_| invalid("Hermes version probe failed"))?
        {
            break status;
        }
        if started.elapsed() > Duration::from_millis(CLI_TIMEOUT_MS.into()) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ClientError {
                code: ErrorCode::Timeout,
                message: "Hermes version probe timed out".into(),
                field_path: None,
                retryable: false,
            });
        }
        thread::sleep(Duration::from_millis(10));
    };
    let stdout = stdout_thread
        .join()
        .map_err(|_| invalid("Hermes version output is invalid"))?
        .map_err(|_| invalid("Hermes version output is invalid"))?;
    let stderr = stderr_thread
        .join()
        .map_err(|_| invalid("Hermes version output is invalid"))?
        .map_err(|_| invalid("Hermes version output is invalid"))?;
    if !status.success() || !stderr.is_empty() {
        return Err(invalid("Hermes version probe failed"));
    }
    Ok(stdout)
}

fn read_capped(reader: impl Read) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(CLI_OUTPUT_LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > CLI_OUTPUT_LIMIT {
        return Err(std::io::Error::other("output limit exceeded"));
    }
    Ok(bytes)
}

fn parse_version(bytes: &[u8]) -> Option<String> {
    let output = std::str::from_utf8(bytes).ok()?;
    let output = strip_ansi(output).replace("\r\n", "\n");
    if output
        .chars()
        .any(|character| character.is_control() && character != '\n')
    {
        return None;
    }
    let versions = output
        .split(|character: char| !(character.is_ascii_alphanumeric() || character == '.'))
        .filter(|token| valid_version(token))
        .collect::<Vec<_>>();
    (versions.len() == 1).then(|| versions[0].to_owned())
}

fn strip_ansi(value: &str) -> String {
    let mut result = String::new();
    let mut characters = value.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '\u{1b}' && characters.peek() == Some(&'[') {
            characters.next();
            for next in characters.by_ref() {
                if ('@'..='~').contains(&next) {
                    break;
                }
            }
        } else {
            result.push(character);
        }
    }
    result
}

fn valid_version(version: &str) -> bool {
    let mut parts = version.split('.');
    let valid = |part: Option<&str>| {
        part.is_some_and(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    };
    valid(parts.next()) && valid(parts.next()) && valid(parts.next()) && parts.next().is_none()
}

fn installation_method(path: &Path) -> InstallationMethod {
    let rendered = path.to_string_lossy();
    if rendered.contains("/bin/") || rendered.contains("\\bin\\") {
        InstallationMethod::PackageManager
    } else {
        InstallationMethod::Unknown
    }
}

fn require_file(path: &Path, message: &'static str) -> Result<(), ClientError> {
    path.is_file()
        .then_some(())
        .ok_or_else(|| not_found(message))
}

fn require_directory(path: &Path, message: &'static str) -> Result<(), ClientError> {
    path.is_dir()
        .then_some(())
        .ok_or_else(|| not_found(message))
}

fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME").map(PathBuf::from)
}

fn ascii_lowercase(value: &str) -> String {
    value
        .bytes()
        .map(|byte| byte.to_ascii_lowercase() as char)
        .collect()
}

fn wire_path(path: &Path) -> WireNativeValue {
    #[cfg(windows)]
    let bytes = {
        use std::os::windows::ffi::OsStrExt as _;
        path.as_os_str()
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect()
    };
    #[cfg(not(windows))]
    let bytes = {
        use std::os::unix::ffi::OsStrExt as _;
        path.as_os_str().as_bytes().to_vec()
    };
    WireNativeValue {
        platform: if cfg!(windows) {
            NativePlatform::Windows
        } else {
            NativePlatform::Macos
        },
        bytes,
        display: path.to_str().map(str::to_owned),
    }
}

pub(super) fn invalid(message: &'static str) -> ClientError {
    ClientError {
        code: ErrorCode::InvalidRequest,
        message: message.into(),
        field_path: None,
        retryable: false,
    }
}

pub(super) fn not_found(message: &'static str) -> ClientError {
    ClientError {
        code: ErrorCode::NotFound,
        message: message.into(),
        field_path: None,
        retryable: false,
    }
}

fn conflict(message: &'static str) -> ClientError {
    ClientError {
        code: ErrorCode::Conflict,
        message: message.into(),
        field_path: None,
        retryable: false,
    }
}

fn phase_unsupported() -> ClientError {
    ClientError {
        code: ErrorCode::HarnessUnsupported,
        message: "Hermes adapter phase is not available".into(),
        field_path: None,
        retryable: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn parse_version_accepts_a_single_version_with_a_trailing_newline() {
        assert_eq!(parse_version(b"hermes 0.18.2\n"), Some("0.18.2".to_owned()));
    }

    #[test]
    fn parse_version_accepts_a_single_ansi_decorated_version() {
        assert_eq!(
            parse_version(b"\x1b[32mhermes 0.18.2\x1b[0m\r\n"),
            Some("0.18.2".to_owned())
        );
    }

    #[test]
    fn parse_version_rejects_malformed_or_multiple_versions() {
        assert_eq!(parse_version(b"hermes 9.9\n"), None);
        assert_eq!(parse_version(b"hermes 9.9.9.9\n"), None);
        assert_eq!(parse_version(b"hermes 9.9.9 runtime 0.18.2\n"), None);
    }

    #[test]
    fn classify_executable_recognizes_universal_mach_o_headers() {
        let root = fs::canonicalize(env::temp_dir()).unwrap().join(format!(
            "context-relay-hermes-classifier-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let executable = root.join("hermes");
        for header in [
            [0xca, 0xfe, 0xba, 0xbe],
            [0xbe, 0xba, 0xfe, 0xca],
            [0xca, 0xfe, 0xba, 0xbf],
            [0xbf, 0xba, 0xfe, 0xca],
        ] {
            fs::write(&executable, header).unwrap();
            assert_eq!(
                snapshot_executable(&executable).unwrap().kind,
                HermesExecutableKind::Native
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn wrapper_extension_overrides_native_magic() {
        let root = fs::canonicalize(env::temp_dir()).unwrap().join(format!(
            "context-relay-hermes-wrapper-precedence-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let executable = root.join("hermes.cmd");
        fs::write(&executable, b"MZnative-looking wrapper").unwrap();

        assert_eq!(
            snapshot_executable(&executable).unwrap().kind,
            HermesExecutableKind::Wrapper
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn native_discovery_rejects_replacement_after_snapshot_without_executing_wrapper() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = fs::canonicalize(env::temp_dir()).unwrap().join(format!(
            "context-relay-hermes-discovery-race-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let executable = root.join("hermes");
        let sentinel = root.join("wrapper-ran");
        fs::write(&executable, b"\x7fELFnative executable").unwrap();

        let result = discover_executable_version_after_snapshot(
            &executable,
            || {
                fs::write(
                    &executable,
                    format!(
                        "#!/bin/sh\n/usr/bin/touch '{}'\nprintf 'hermes 0.18.2\\n'\n",
                        sentinel.display()
                    ),
                )
                .unwrap();
                fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
            },
            run_version,
        );
        let sentinel_exists = sentinel.exists();
        let _ = fs::remove_dir_all(root);

        assert!(matches!(
            result,
            Err(ClientError {
                code: ErrorCode::Conflict,
                ..
            })
        ));
        assert!(!sentinel_exists);
    }

    #[cfg(unix)]
    #[test]
    fn native_discovery_executes_staged_attested_bytes_when_source_changes_after_staging() {
        use std::{cell::RefCell, os::unix::fs::PermissionsExt as _};

        let root = fs::canonicalize(env::temp_dir()).unwrap().join(format!(
            "context-relay-hermes-staged-race-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let executable = root.join("hermes");
        let sentinel = root.join("wrapper-ran");
        fs::write(&executable, b"\x7fELFattested native executable").unwrap();
        let executed_path = RefCell::new(None);

        let (snapshot, version) = discover_executable_version_with_boundaries(
            &executable,
            || {},
            |source, staged| {
                assert_ne!(staged, source);
                fs::write(
                    source,
                    format!(
                        "#!/bin/sh\n/usr/bin/touch '{}'\nprintf 'hermes 0.18.2\\n'\n",
                        sentinel.display()
                    ),
                )
                .unwrap();
                fs::set_permissions(source, fs::Permissions::from_mode(0o700)).unwrap();
            },
            |staged, expected_snapshot| {
                assert_eq!(snapshot_executable(staged).unwrap(), expected_snapshot);
                assert_eq!(
                    fs::metadata(staged).unwrap().permissions().mode() & 0o777,
                    0o700
                );
                assert_eq!(
                    fs::metadata(staged.parent().unwrap())
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o700
                );
                executed_path.replace(Some(staged.to_owned()));
                Ok(b"hermes 0.18.2\n".to_vec())
            },
        )
        .unwrap();

        assert_eq!(snapshot.kind, HermesExecutableKind::Native);
        assert_eq!(version, "0.18.2");
        assert_ne!(
            executed_path.borrow().as_deref(),
            Some(executable.as_path())
        );
        assert!(!executed_path.borrow().as_ref().unwrap().exists());
        assert!(!sentinel.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn attested_constructor_rejects_different_native_binary_replaced_after_version_probe() {
        use std::str::FromStr as _;

        let root = fs::canonicalize(env::temp_dir()).unwrap().join(format!(
            "context-relay-hermes-constructor-race-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        let default_home = root.join("home");
        let profile_home = default_home.join("profiles/coder");
        let project_root = root.join("project");
        let working_directory = project_root.join("service");
        fs::create_dir_all(&profile_home).unwrap();
        fs::create_dir_all(&working_directory).unwrap();
        fs::write(profile_home.join("config.yaml"), "approvals: {}\n").unwrap();
        let executable = root.join("hermes");
        fs::write(&executable, b"\x7fELForiginal native executable").unwrap();

        let (snapshot, version) = discover_executable_version_after_snapshot(
            &executable,
            || {},
            |_, _| Ok(b"hermes 0.18.2\n".to_vec()),
        )
        .unwrap();
        fs::write(&executable, b"\x7fELFdifferent native executable").unwrap();

        let project_id = ProjectId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073981").unwrap();
        let device_id = DeviceId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073982").unwrap();
        let result = HermesAdapter::from_attested_layout(
            HermesLayout {
                executable,
                executable_kind: snapshot.kind,
                version,
                installation_method: InstallationMethod::PackageManager,
                default_hermes_home: default_home,
                profile: HermesProfile {
                    name: "coder".to_owned(),
                    hermes_home: profile_home,
                },
                project_root,
                working_directory,
            },
            project_id,
            device_id,
            HybridLogicalClock::new(1_900_000_000_000, 0, device_id),
            snapshot,
        );

        assert!(matches!(
            result,
            Err(ClientError {
                code: ErrorCode::Conflict,
                ..
            })
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn native_discovery_accepts_newline_and_ansi_version_output() {
        let root = fs::canonicalize(env::temp_dir()).unwrap().join(format!(
            "context-relay-hermes-version-output-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let executable = root.join("hermes");
        fs::write(&executable, b"\x7fELFnative executable").unwrap();
        for output in [
            b"hermes 0.18.2\n".as_slice(),
            b"\x1b[32mhermes 0.18.2\x1b[0m\r\n",
        ] {
            let (_, version) = discover_executable_version_after_snapshot(
                &executable,
                || {},
                |_, _| Ok(output.to_vec()),
            )
            .unwrap();
            assert_eq!(version, "0.18.2");
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn native_discovery_accepts_one_unknown_semantic_version() {
        use std::str::FromStr as _;

        let root = fs::canonicalize(env::temp_dir()).unwrap().join(format!(
            "context-relay-hermes-unknown-version-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        let default_home = root.join("home");
        let profile_home = default_home.join("profiles/coder");
        let project_root = root.join("project");
        let working_directory = project_root.join("service");
        fs::create_dir_all(&profile_home).unwrap();
        fs::create_dir_all(&working_directory).unwrap();
        fs::write(profile_home.join("config.yaml"), "approvals: {}\n").unwrap();
        let executable = root.join("hermes");
        fs::write(&executable, b"\x7fELFnative executable").unwrap();

        let (snapshot, version) = discover_executable_version_after_snapshot(
            &executable,
            || {},
            |_, _| Ok(b"hermes 9.9.9\n".to_vec()),
        )
        .unwrap();

        assert_eq!(snapshot.kind, HermesExecutableKind::Native);
        assert_eq!(version, "9.9.9");
        let project_id = ProjectId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073981").unwrap();
        let device_id = DeviceId::from_str("018f22e2-79b0-7cc8-98c4-dc0c0c073982").unwrap();
        let adapter = HermesAdapter::from_attested_layout(
            HermesLayout {
                executable,
                executable_kind: snapshot.kind,
                version,
                installation_method: InstallationMethod::PackageManager,
                default_hermes_home: default_home,
                profile: HermesProfile {
                    name: "coder".to_owned(),
                    hermes_home: profile_home,
                },
                project_root,
                working_directory,
            },
            project_id,
            device_id,
            HybridLogicalClock::new(1_900_000_000_000, 0, device_id),
            snapshot,
        )
        .unwrap();
        assert_eq!(
            adapter
                .probe(&ProbeContext {
                    harness: HarnessId::Hermes,
                    requested_profile: Some("coder".to_owned()),
                })
                .unwrap()
                .capability,
            CapabilityLevel::ImportOnly
        );
        fs::remove_dir_all(root).unwrap();
    }
}
