//! Hermes adapter identity and profile binding.
//!
//! This first adapter phase attests one explicit profile before it reads any
//! Hermes configuration. Content import and native rendering remain closed.

mod profile;

use std::{
    env, fs,
    io::Read,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HermesProfile {
    pub name: String,
    pub hermes_home: PathBuf,
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
        let executable_kind = classify_executable(&executable)?;
        let installation_method = installation_method(&executable);
        let version = if executable_kind == HermesExecutableKind::Native {
            let output = run_version(&executable)?;
            parse_version(&output).ok_or_else(|| invalid("Hermes returned an invalid version"))?
        } else {
            "unknown".to_owned()
        };
        Self::from_layout(
            HermesLayout {
                executable,
                executable_kind,
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
        )
    }

    pub fn from_layout(
        mut layout: HermesLayout,
        project_id: ProjectId,
        origin_device: DeviceId,
        observed_hlc: HybridLogicalClock,
    ) -> Result<Self, ClientError> {
        if !valid_version(&layout.version) && layout.version != "unknown" {
            return Err(invalid("Hermes version is invalid"));
        }
        require_file(&layout.executable, "Hermes executable was not found")?;
        require_directory(&layout.project_root, "Hermes project root was not found")?;
        require_directory(
            &layout.working_directory,
            "Hermes working directory was not found",
        )?;
        layout.executable = fs::canonicalize(&layout.executable)
            .map_err(|_| invalid("Hermes executable cannot be safely resolved"))?;
        layout.default_hermes_home = fs::canonicalize(&layout.default_hermes_home)
            .map_err(|_| not_found("Hermes default profile was not found"))?;
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
        let executable_hash = digest_file(&layout.executable)?;
        Ok(Self {
            layout,
            project_id,
            origin_device,
            observed_hlc,
            executable_hash,
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
            .and_then(|bytes| serde_yaml_ng::from_slice::<serde_yaml_ng::Value>(&bytes).ok())
            .is_some_and(|value| matches!(value, serde_yaml_ng::Value::Mapping(_)))
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
            policy_conflicts: vec![],
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

    fn import(&self, _request: &ImportRequest) -> Result<ImportedState, ClientError> {
        Err(phase_unsupported())
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

fn classify_executable(path: &Path) -> Result<HermesExecutableKind, ClientError> {
    let bytes = fs::read(path).map_err(|_| not_found("Hermes executable was not found"))?;
    if bytes.starts_with(b"\x7fELF")
        || bytes.starts_with(b"MZ")
        || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xce])
        || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
        || bytes.starts_with(&[0xce, 0xfa, 0xed, 0xfe])
        || bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
    {
        return Ok(HermesExecutableKind::Native);
    }
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase);
    if bytes.starts_with(b"#!") || matches!(extension.as_deref(), Some("cmd" | "bat" | "ps1")) {
        return Ok(HermesExecutableKind::Wrapper);
    }
    Ok(HermesExecutableKind::Unknown)
}

fn run_version(executable: &Path) -> Result<Vec<u8>, ClientError> {
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
    if output.chars().any(char::is_control)
        && output
            .chars()
            .any(|character| character != '\n' && character != '\r' && character != '\t')
    {
        return None;
    }
    let output = strip_ansi(output);
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

fn digest_file(path: &Path) -> Result<Sha256Digest, ClientError> {
    fs::read(path)
        .map(|bytes| Sha256Digest(Sha256::digest(bytes).into()))
        .map_err(|_| not_found("Hermes executable was not found"))
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

fn phase_unsupported() -> ClientError {
    ClientError {
        code: ErrorCode::HarnessUnsupported,
        message: "Hermes adapter phase is not available".into(),
        field_path: None,
        retryable: false,
    }
}
