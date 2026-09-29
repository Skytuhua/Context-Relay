//! Passive Windows Python installation description, never execution authority.

use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Read,
    path::{Component, Path, PathBuf},
};

use context_relay_protocol::{ClientError, Sha256Digest};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

const MAX_METADATA_BYTES: u64 = 256 * 1024;
const MAX_PACKAGE_ENTRIES: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataObservation {
    pub path: PathBuf,
    pub sha256: Sha256Digest,
}

/// These roots and metadata are inputs to future complete runtime capture.
/// They neither describe a complete import closure nor authorize execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PythonInstallation {
    pub version: String,
    pub venv: PathBuf,
    pub interpreter: PathBuf,
    pub python_home: PathBuf,
    pub site_packages: PathBuf,
    pub editable_source: Option<PathBuf>,
    pub metadata: Vec<MetadataObservation>,
}

/// Inspect metadata only. No Python code or launcher command is executed.
/// A successful result must never be used as permission to launch this runtime.
pub fn inspect(executable: &Path) -> Result<Option<PythonInstallation>, ClientError> {
    if !named(executable, "hermes.exe")
        || !executable
            .parent()
            .is_some_and(|path| named(path, "Scripts"))
    {
        return Ok(None);
    }
    let executable = real_path(executable, false)?;
    let scripts = executable.parent().ok_or_else(invalid)?;
    let venv = scripts.parent().ok_or_else(invalid)?.to_path_buf();
    let interpreter = real_path(&scripts.join("python.exe"), false)?;
    let site_packages = real_path(&venv.join("Lib/site-packages"), true)?;
    let mut observations = Vec::new();
    let config = observe(&venv.join("pyvenv.cfg"), &mut observations)?;
    let config = assignments(&config)?;
    if config
        .get("include-system-site-packages")
        .map(String::as_str)
        != Some("false")
        || config
            .get("implementation")
            .is_some_and(|value| value != "CPython")
    {
        return Err(invalid());
    }
    let declared_python = config
        .get("version_info")
        .or_else(|| config.get("version"))
        .ok_or_else(invalid)?;
    let python_minor = python_minor(declared_python)?;
    if config
        .get("version")
        .is_some_and(|version| self::python_minor(version).ok() != Some(python_minor))
    {
        return Err(invalid());
    }
    let python_home = resolve_python_home(
        Path::new(config.get("home").ok_or_else(invalid)?),
        python_minor,
    )?;
    real_path(&python_home.join("python.exe"), false)?;
    real_path(
        &python_home.join(format!("python3{python_minor}.dll")),
        false,
    )?;
    real_path(&python_home.join("Lib"), true)?;

    let mut distributions = Vec::new();
    for (count, entry) in fs::read_dir(&site_packages)
        .map_err(|_| invalid())?
        .enumerate()
    {
        if count >= MAX_PACKAGE_ENTRIES {
            return Err(invalid());
        }
        let entry = entry.map_err(|_| invalid())?;
        let name = entry.file_name().into_string().map_err(|_| invalid())?;
        let normalized = name.to_ascii_lowercase();
        if normalized.starts_with("hermes_agent-") && normalized.ends_with(".dist-info") {
            distributions.push((name, entry.path()));
        }
    }
    let [(distribution_name, distribution)] = distributions.as_slice() else {
        return Err(invalid());
    };
    let distribution = real_path(distribution, true)?;
    let metadata = observe(&distribution.join("METADATA"), &mut observations)?;
    let version = distribution_version(&metadata)?;
    if distribution_name != &format!("hermes_agent-{version}.dist-info") {
        return Err(invalid());
    }
    let entry_points = observe(&distribution.join("entry_points.txt"), &mut observations)?;
    validate_entry_points(&entry_points)?;

    let direct_url_path = distribution.join("direct_url.json");
    let editable_source = match fs::symlink_metadata(&direct_url_path) {
        Ok(_) => {
            let direct_url = observe(&direct_url_path, &mut observations)?;
            let direct: DirectUrl = serde_json::from_str(&direct_url).map_err(|_| invalid())?;
            if !direct.dir_info.editable {
                return Err(invalid());
            }
            let url = reqwest::Url::parse(&direct.url).map_err(|_| invalid())?;
            if url.scheme() != "file"
                || url.host_str().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err(invalid());
            }
            let source = real_path(&url.to_file_path().map_err(|_| invalid())?, true)?;
            // uv normally places the venv inside the source checkout. Complete
            // capture must treat those as separate roots, not recursively copy
            // the venv a second time as editable package source.
            if source.starts_with(&venv) {
                return Err(invalid());
            }
            let project = observe(&source.join("pyproject.toml"), &mut observations)?;
            let project: toml_edit::DocumentMut = project.parse().map_err(|_| invalid())?;
            let project = project.get("project").ok_or_else(invalid)?;
            if project.get("name").and_then(|item| item.as_str()) != Some("hermes-agent")
                || project.get("version").and_then(|item| item.as_str()) != Some(version.as_str())
                || project
                    .get("scripts")
                    .and_then(|item| item.get("hermes"))
                    .and_then(|item| item.as_str())
                    != Some("hermes_cli.main:main")
            {
                return Err(invalid());
            }
            Some(source)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(invalid()),
    };
    let source = editable_source.as_ref().unwrap_or(&site_packages);
    real_path(&source.join("hermes_cli/main.py"), false)?;
    Ok(Some(PythonInstallation {
        version,
        venv,
        interpreter,
        python_home,
        site_packages,
        editable_source,
        metadata: observations,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectUrl {
    url: String,
    dir_info: DirectoryInfo,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectoryInfo {
    editable: bool,
}

fn invalid() -> ClientError {
    super::invalid("Hermes Python installation metadata is incomplete or inconsistent")
}

fn named(path: &Path, name: &str) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case(name))
}

fn resolve_python_home(path: &Path, minor: u8) -> Result<PathBuf, ClientError> {
    validate_local_path(path)?;
    if let Ok(path) = real_path(path, true) {
        return Ok(path);
    }
    // uv's managed minor-version alias is a junction on Windows. Resolve only
    // this exact same-parent layout and inspect the real directory thereafter.
    // The pyvenv.cfg observation binds the reference; this is still metadata,
    // not an attestation that the interpreter or its packages can be executed.
    if !named(path, &format!("cpython-3.{minor}-windows-x86_64-none")) {
        return Err(invalid());
    }
    let parent = real_path(path.parent().ok_or_else(invalid)?, true)?;
    // Read the alias target without traversing it. A remote target must be
    // rejected before canonicalization can cause network filesystem access.
    let target = fs::read_link(path).map_err(|_| invalid())?;
    validate_local_path(&target)?;
    let resolved = real_path(&target, true)?;
    if resolved.parent() != Some(parent.as_path()) {
        return Err(invalid());
    }
    let name = resolved
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(invalid)?;
    let patch = name
        .strip_prefix(&format!("cpython-3.{minor}."))
        .and_then(|name| name.strip_suffix("-windows-x86_64-none"))
        .ok_or_else(invalid)?;
    if patch.is_empty() || !patch.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid());
    }
    real_path(&resolved, true)
}

pub(super) fn real_path(path: &Path, directory: bool) -> Result<PathBuf, ClientError> {
    validate_local_path(path)?;
    // Walk from the root so a linked ancestor is rejected before any lookup
    // through it (including a lookup that might reach a remote share).
    let ancestors: Vec<_> = path.ancestors().collect();
    for ancestor in ancestors
        .into_iter()
        .rev()
        .filter(|path| path.file_name().is_some())
    {
        let metadata = fs::symlink_metadata(ancestor).map_err(|_| invalid())?;
        if is_link(&metadata) {
            return Err(invalid());
        }
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| invalid())?;
    if (directory && !metadata.is_dir()) || (!directory && !metadata.is_file()) {
        return Err(invalid());
    }
    fs::canonicalize(path).map_err(|_| invalid())
}

fn validate_local_path(path: &Path) -> Result<(), ClientError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(invalid());
    }
    #[cfg(windows)]
    {
        use std::path::Prefix;
        if !matches!(path.components().next(), Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)))
        {
            return Err(invalid());
        }
    }
    Ok(())
}

pub(super) fn is_link(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn observe(
    path: &Path,
    observations: &mut Vec<MetadataObservation>,
) -> Result<String, ClientError> {
    observe_after_resolve(path, observations, || {})
}

fn observe_after_resolve(
    path: &Path,
    observations: &mut Vec<MetadataObservation>,
    after_resolve: impl FnOnce(),
) -> Result<String, ClientError> {
    let path = real_path(path, false)?;
    after_resolve();
    let file = open_without_substitution(&path).map_err(|_| invalid())?;
    let metadata = file.metadata().map_err(|_| invalid())?;
    real_path(&path, false)?;
    if !metadata.is_file() || is_link(&metadata) || metadata.len() > MAX_METADATA_BYTES {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    (&file)
        .take(MAX_METADATA_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    if bytes.len() as u64 > MAX_METADATA_BYTES {
        return Err(invalid());
    }
    let current = open_without_substitution(&path).map_err(|_| invalid())?;
    real_path(&path, false)?;
    if file_identity(&file).map_err(|_| invalid())?
        != file_identity(&current).map_err(|_| invalid())?
        || file.metadata().map_err(|_| invalid())?.len() != metadata.len()
        || file
            .metadata()
            .map_err(|_| invalid())?
            .modified()
            .map_err(|_| invalid())?
            != metadata.modified().map_err(|_| invalid())?
    {
        return Err(invalid());
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| invalid())?;
    if text.contains('\0') {
        return Err(invalid());
    }
    observations.push(MetadataObservation {
        path,
        sha256: Sha256Digest(Sha256::digest(&bytes).into()),
    });
    Ok(text.to_owned())
}

pub(super) fn open_without_substitution(path: &Path) -> std::io::Result<File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        };
        options
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path)
}

#[cfg(unix)]
pub(super) fn file_identity(file: &File) -> std::io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = file.metadata()?;
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(windows)]
pub(super) fn file_identity(file: &File) -> std::io::Result<(u64, u64)> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle},
    };
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: file owns a valid handle, and info has the required writable layout.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((
        u64::from(info.dwVolumeSerialNumber),
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    ))
}

fn assignments(text: &str) -> Result<BTreeMap<String, String>, ClientError> {
    let mut values = BTreeMap::new();
    for line in text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let (key, value) = line.split_once('=').ok_or_else(invalid)?;
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        if key.is_empty() || value.is_empty() || values.insert(key, value.to_owned()).is_some() {
            return Err(invalid());
        }
    }
    Ok(values)
}

fn python_minor(version: &str) -> Result<u8, ClientError> {
    let parts: Vec<_> = version.split('.').collect();
    if !(2..=3).contains(&parts.len())
        || parts[0] != "3"
        || parts
            .iter()
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(invalid());
    }
    match parts[1] {
        "11" => Ok(11),
        "12" => Ok(12),
        "13" => Ok(13),
        _ => Err(invalid()),
    }
}

fn distribution_version(text: &str) -> Result<String, ClientError> {
    let mut name = None;
    let mut version = None;
    for line in text.lines().take_while(|line| !line.is_empty()) {
        if line.starts_with([' ', '\t']) {
            return Err(invalid());
        }
        let (key, value) = line.split_once(':').ok_or_else(invalid)?;
        let target = match key.to_ascii_lowercase().as_str() {
            "name" => &mut name,
            "version" => &mut version,
            _ => continue,
        };
        if target.replace(value.trim().to_owned()).is_some() {
            return Err(invalid());
        }
    }
    let version = version.ok_or_else(invalid)?;
    if name.as_deref() != Some("hermes-agent")
        || version.len() > 32
        || !super::valid_version(&version)
    {
        return Err(invalid());
    }
    Ok(version)
}

fn validate_entry_points(text: &str) -> Result<(), ClientError> {
    let mut section = "";
    let mut sections = std::collections::BTreeSet::new();
    let mut entry = None;
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if let Some(name) = line
            .strip_prefix('[')
            .and_then(|line| line.strip_suffix(']'))
        {
            if !sections.insert(name) {
                return Err(invalid());
            }
            section = name;
        } else {
            let (name, value) = line.split_once('=').ok_or_else(invalid)?;
            if section == "console_scripts"
                && name.trim() == "hermes"
                && entry.replace(value.trim()).is_some()
            {
                return Err(invalid());
            }
        }
    }
    if entry != Some("hermes_cli.main:main") {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, fs};

    struct Fixture {
        _root: tempfile::TempDir,
        root: PathBuf,
        executable: PathBuf,
        distribution: PathBuf,
    }

    impl Fixture {
        fn new(editable: bool) -> Self {
            let temp = tempfile::tempdir().unwrap();
            let root = fs::canonicalize(temp.path()).unwrap();
            let venv = root.join(if editable { "source/venv" } else { "venv" });
            let base = root.join("python");
            let distribution = venv.join("Lib/site-packages/hermes_agent-0.17.0.dist-info");
            fs::create_dir_all(venv.join("Scripts")).unwrap();
            fs::create_dir_all(base.join("Lib")).unwrap();
            fs::create_dir_all(&distribution).unwrap();
            let executable = venv.join("Scripts/hermes.exe");
            fs::write(&executable, b"MZ synthetic Python console launcher").unwrap();
            fs::write(
                venv.join("Scripts/python.exe"),
                b"MZ synthetic venv redirector",
            )
            .unwrap();
            fs::write(base.join("python.exe"), b"MZ synthetic interpreter").unwrap();
            fs::write(base.join("python311.dll"), b"MZ synthetic runtime").unwrap();
            fs::write(venv.join("pyvenv.cfg"), format!(
                "home = {}\nimplementation = CPython\nversion_info = 3.11\ninclude-system-site-packages = false\n",
                base.display()
            )).unwrap();
            fs::write(distribution.join("METADATA"), "Metadata-Version: 2.4\nName: hermes-agent\nVersion: 0.17.0\nRequires-Dist: openai\nRequires-Dist: rich\n\nDescription\nVersion: ignored body\n").unwrap();
            fs::write(distribution.join("entry_points.txt"), "[console_scripts]\nhermes = hermes_cli.main:main\nhermes-acp = acp_adapter.entry:main\n").unwrap();
            let source = if editable {
                root.join("source")
            } else {
                venv.join("Lib/site-packages")
            };
            fs::create_dir_all(source.join("hermes_cli")).unwrap();
            fs::write(
                source.join("hermes_cli/main.py"),
                "raise RuntimeError('inspection must never import me')\n",
            )
            .unwrap();
            if editable {
                fs::write(source.join("pyproject.toml"), "[project]\nname = 'hermes-agent'\nversion = '0.17.0'\n[project.scripts]\nhermes = 'hermes_cli.main:main'\n").unwrap();
                let url = reqwest::Url::from_directory_path(&source).unwrap();
                fs::write(
                    distribution.join("direct_url.json"),
                    serde_json::json!({"url":url.as_str(),"dir_info":{"editable":true}})
                        .to_string(),
                )
                .unwrap();
            }
            fs::write(
                venv.join("Lib/site-packages/poison.pth"),
                format!(
                    "import pathlib; pathlib.Path({:?}).write_text('executed')\n",
                    root.join("executed")
                ),
            )
            .unwrap();
            Self {
                _root: temp,
                root,
                executable,
                distribution,
            }
        }
    }

    #[test]
    fn describes_editable_installation_without_importing_startup_code() {
        let fixture = Fixture::new(true);
        let found = inspect(&fixture.executable)
            .unwrap()
            .expect("Python installation");
        assert_eq!(found.version, "0.17.0");
        assert_eq!(found.venv, fixture.root.join("source/venv"));
        assert_eq!(found.python_home, fixture.root.join("python"));
        assert_eq!(found.editable_source, Some(fixture.root.join("source")));
        assert!(!fixture.root.join("executed").exists());
        assert_eq!(found.metadata.len(), 5);
    }

    #[test]
    fn discovery_reports_metadata_version_without_version_execution() {
        let fixture = Fixture::new(true);
        let calls = Cell::new(0);
        let (snapshot, version) = super::super::discover_executable_version_after_snapshot(
            &fixture.executable,
            || {},
            |_, _| {
                calls.set(calls.get() + 1);
                panic!("Python launcher executed")
            },
        )
        .unwrap();
        assert_eq!(version, "0.17.0");
        assert_eq!(snapshot.kind, super::super::HermesExecutableKind::Wrapper);
        assert!(!snapshot.runnable());
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn describes_wheel_installation_and_observes_changed_metadata() {
        let fixture = Fixture::new(false);
        let before = inspect(&fixture.executable).unwrap().unwrap();
        assert_eq!(before.editable_source, None);
        assert_eq!(before.metadata.len(), 3);
        fs::write(
            fixture.distribution.join("METADATA"),
            "Name: hermes-agent\nVersion: 0.17.0\nSummary: changed\n",
        )
        .unwrap();
        let after = inspect(&fixture.executable).unwrap().unwrap();
        assert_ne!(before.metadata, after.metadata);
    }

    #[test]
    fn rejects_ambiguous_or_mismatched_distribution_identity() {
        let fixture = Fixture::new(false);
        let metadata = fixture.distribution.join("METADATA");
        for text in [
            "Name: other-harness\nVersion: 0.17.0\n",
            "Name: hermes-agent\nVersion: 0.18.2\n",
            "Name: hermes-agent\nVersion: 0.17.0\nVersion: 0.18.2\n",
            "Name: hermes-agent\nName: hermes-agent\nVersion: 0.17.0\n",
            "Name: hermes-agent\nVersion: 0.17.0+local\n",
            "Name: hermes-agent\nVersion: 0.17.0\n folded-header\n",
        ] {
            fs::write(&metadata, text).unwrap();
            assert!(inspect(&fixture.executable).is_err(), "accepted {text:?}");
        }
        fs::write(metadata, "Name: hermes-agent\nVersion: 0.17.0\n").unwrap();
        fs::create_dir(
            fixture
                .distribution
                .parent()
                .unwrap()
                .join("hermes_agent-0.18.2.dist-info"),
        )
        .unwrap();
        assert!(inspect(&fixture.executable).is_err());
    }

    #[test]
    fn rejects_wrong_or_duplicate_console_entry_points() {
        let fixture = Fixture::new(false);
        for text in [
            "[console_scripts]\nhermes = other.module:main\n",
            "[console_scripts]\nhermes = hermes_cli.main:main\nhermes = hermes_cli.main:main\n",
            "[console_scripts]\nhermes = hermes_cli.main:main\n[console_scripts]\n",
            "[another_group]\nhermes = hermes_cli.main:main\n",
        ] {
            fs::write(fixture.distribution.join("entry_points.txt"), text).unwrap();
            assert!(inspect(&fixture.executable).is_err());
        }
    }

    #[test]
    fn bounds_metadata_reads_and_package_enumeration() {
        let fixture = Fixture::new(false);
        let metadata = fixture.distribution.join("METADATA");
        fs::write(&metadata, vec![b'x'; MAX_METADATA_BYTES as usize + 1]).unwrap();
        assert!(inspect(&fixture.executable).is_err());
        fs::write(metadata, "Name: hermes-agent\nVersion: 0.17.0\n").unwrap();
        let packages = fixture.distribution.parent().unwrap();
        for index in 0..MAX_PACKAGE_ENTRIES {
            fs::write(packages.join(format!("package-{index}")), b"").unwrap();
        }
        assert!(inspect(&fixture.executable).is_err());
    }

    #[test]
    fn rejects_unqualified_python_layout_and_ambient_site_packages() {
        let fixture = Fixture::new(false);
        let venv_config = fixture
            .executable
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("pyvenv.cfg");
        let original = fs::read_to_string(&venv_config).unwrap();
        for text in [
            original.replace("CPython", "PyPy"),
            original.replace("3.11", "3.14"),
            original.replace("false", "true"),
            original.clone() + "version_info = 3.12\n",
            original.clone() + "version = 3.12.1\n",
            original.replace(
                &fixture.root.join("python").display().to_string(),
                "relative/python",
            ),
        ] {
            fs::write(&venv_config, text).unwrap();
            assert!(inspect(&fixture.executable).is_err());
        }
        // Standard CPython venvs use version rather than uv's version_info.
        fs::write(
            &venv_config,
            original
                .replace("version_info = 3.11", "version = 3.11.15")
                .replace("implementation = CPython\n", ""),
        )
        .unwrap();
        assert!(inspect(&fixture.executable).unwrap().is_some());
        fs::remove_file(fixture.executable.parent().unwrap().join("python.exe")).unwrap();
        assert!(inspect(&fixture.executable).is_err());
    }

    #[test]
    fn rejects_external_ambiguous_or_inconsistent_editable_sources() {
        let fixture = Fixture::new(true);
        let direct = fixture.distribution.join("direct_url.json");
        let original = fs::read_to_string(&direct).unwrap();
        for text in [
            "{\"url\":\"https://example.invalid/source\",\"dir_info\":{\"editable\":true}}",
            "{\"url\":\"file://remote/share/source\",\"dir_info\":{\"editable\":true}}",
            "{\"url\":\"file:///source\",\"url\":\"file:///other\",\"dir_info\":{\"editable\":true}}",
            "{\"url\":\"file:///source\",\"dir_info\":{\"editable\":false}}",
        ] {
            fs::write(&direct, text).unwrap();
            assert!(inspect(&fixture.executable).is_err());
        }
        fs::write(&direct, original).unwrap();
        let project = fixture.root.join("source/pyproject.toml");
        let original = fs::read_to_string(&project).unwrap();
        fs::write(project, original.replace("0.17.0", "0.18.2")).unwrap();
        assert!(inspect(&fixture.executable).is_err());
    }

    #[test]
    fn metadata_observation_is_not_authority_to_run_a_supported_version() {
        let fixture = Fixture::new(false);
        let distribution = fixture
            .distribution
            .with_file_name("hermes_agent-0.18.2.dist-info");
        fs::rename(&fixture.distribution, &distribution).unwrap();
        fs::write(
            distribution.join("METADATA"),
            "Name: hermes-agent\nVersion: 0.18.2\n",
        )
        .unwrap();
        let (snapshot, version) = super::super::discover_executable_version_after_snapshot(
            &fixture.executable,
            || {},
            |_, _| panic!("metadata authorized execution"),
        )
        .unwrap();
        assert_eq!(version, "0.18.2");
        assert!(!snapshot.runnable());
    }

    #[cfg(windows)]
    #[test]
    fn rejects_remote_and_device_paths_without_filesystem_access() {
        for path in [
            r"\\server.invalid\share\python",
            r"\\?\UNC\server.invalid\share\python",
            r"\\.\C:\python",
            r"\\?\GLOBALROOT\Device\HarddiskVolume1\python",
            r"C:relative",
            r"\rooted",
        ] {
            assert!(
                validate_local_path(Path::new(path)).is_err(),
                "accepted {path}"
            );
        }
        for path in [r"C:\python", r"\\?\C:\python"] {
            assert!(validate_local_path(Path::new(path)).is_ok());
        }
    }

    #[cfg(windows)]
    #[test]
    fn metadata_parent_substitution_never_returns_outside_bytes() {
        use std::os::windows::process::CommandExt as _;
        let fixture = Fixture::new(false);
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("METADATA"), b"PRIVATE-OUTSIDE-CANARY").unwrap();
        let moved = fixture.root.join("moved-distribution");
        let mut observations = Vec::new();
        let result = observe_after_resolve(
            &fixture.distribution.join("METADATA"),
            &mut observations,
            || {
                fs::rename(&fixture.distribution, &moved).unwrap();
                assert!(
                    std::process::Command::new("cmd.exe")
                        .args(["/d", "/c", "mklink", "/J"])
                        .arg(&fixture.distribution)
                        .arg(outside.path())
                        .creation_flags(0x0800_0000)
                        .output()
                        .unwrap()
                        .status
                        .success()
                );
            },
        );
        fs::remove_dir(&fixture.distribution).unwrap();
        assert!(result.is_err());
        assert!(observations.is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn resolves_uv_minor_alias_but_rejects_arbitrary_junction_roots() {
        use std::os::windows::process::CommandExt as _;
        fn junction(path: &Path, target: &Path) {
            assert!(
                std::process::Command::new("cmd.exe")
                    .args(["/d", "/c", "mklink", "/J"])
                    .arg(path)
                    .arg(target)
                    .creation_flags(0x0800_0000)
                    .output()
                    .unwrap()
                    .status
                    .success()
            );
        }
        let fixture = Fixture::new(false);
        let actual = fixture.root.join("cpython-3.11.15-windows-x86_64-none");
        fs::rename(fixture.root.join("python"), &actual).unwrap();
        let alias = fixture.root.join("cpython-3.11-windows-x86_64-none");
        junction(&alias, &actual);
        let config = fixture.root.join("venv/pyvenv.cfg");
        let original = fs::read_to_string(&config).unwrap();
        fs::write(
            &config,
            original.replace(
                &fixture.root.join("python").display().to_string(),
                &alias.display().to_string(),
            ),
        )
        .unwrap();
        assert_eq!(
            inspect(&fixture.executable).unwrap().unwrap().python_home,
            actual
        );
        // A same-named alias into another directory is not the managed uv layout.
        fs::remove_dir(&alias).unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside_python = outside.path().join("cpython-3.11.15-windows-x86_64-none");
        fs::create_dir(&outside_python).unwrap();
        junction(&alias, &outside_python);
        assert!(inspect(&fixture.executable).is_err());
        fs::remove_dir(&alias).unwrap();
        // Other installation roots cannot be aliases.
        let actual_distribution = fixture.root.join("distribution");
        fs::rename(&fixture.distribution, &actual_distribution).unwrap();
        junction(&fixture.distribution, &actual_distribution);
        fs::write(
            &config,
            original.replace(
                &fixture.root.join("python").display().to_string(),
                &actual.display().to_string(),
            ),
        )
        .unwrap();
        assert!(inspect(&fixture.executable).is_err());
        fs::remove_dir(&fixture.distribution).unwrap();
    }

    #[test]
    #[ignore = "opt-in read-only metadata inspection; requires an explicit installation path"]
    fn installed_windows_python_metadata_is_inspected_without_launching() {
        let path = std::env::var_os("CONTEXT_RELAY_HERMES_METADATA_EXE")
            .expect("set CONTEXT_RELAY_HERMES_METADATA_EXE to the selected hermes.exe");
        let found = inspect(Path::new(&path))
            .unwrap()
            .expect("Python installation");
        println!(
            "Metadata version: {}; observations: {}; editable: {}",
            found.version,
            found.metadata.len(),
            found.editable_source.is_some()
        );
        assert!(!found.metadata.is_empty());
        let (snapshot, version) = super::super::discover_executable_version_after_snapshot(
            Path::new(&path),
            || {},
            |_, _| panic!("passive discovery executed the installed harness"),
        )
        .unwrap();
        assert_eq!(version, found.version);
        assert!(!snapshot.runnable());
    }
}
