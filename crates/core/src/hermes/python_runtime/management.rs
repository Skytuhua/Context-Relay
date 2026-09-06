//! Runtime-bound checks with an owned private validation home.

use super::retained::LockedRuntime;
use context_relay_native_runner::{
    OsNativeFileSystem, PinnedNativeDirectory,
    windows_management::{
        HermesManagementCommand, ManagementError, ManagementOutput, run_hermes_python,
    },
};
use context_relay_protocol::{ClientError, ErrorCode};
use std::{fs, io::Write as _, path::PathBuf, sync::atomic::AtomicBool};

struct ManagementHome {
    // Keep the private home pinned through execution, then release its handles
    // before the owning temporary directory recursively cleans up.
    _pin: PinnedNativeDirectory,
    _directory: tempfile::TempDir,
    path: PathBuf,
}

impl ManagementHome {
    fn new(config: &[u8]) -> Result<Self, ClientError> {
        crate::hermes::yaml::parse_config(config)?;
        let directory = tempfile::Builder::new()
            .prefix("context-relay-hermes-check-")
            .tempdir()
            .map_err(|_| invalid())?;
        let root = fs::canonicalize(directory.path()).map_err(|_| invalid())?;
        let path = root.join("home");
        let pin = OsNativeFileSystem::new()
            .create_private_directory(&path)
            .map_err(|_| invalid())?;
        let home = Self {
            _pin: pin,
            _directory: directory,
            path,
        };
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(home.path.join("config.yaml"))
            .map_err(|_| invalid())?;
        file.write_all(config).map_err(|_| invalid())?;
        file.sync_all().map_err(|_| invalid())?;
        Ok(home)
    }
}

impl LockedRuntime {
    /// Runs only the version command against this runtime's own verified root.
    /// The native layer keeps both runtime and private profile owners on any
    /// uncertain cleanup path. Success returns the still-locked runtime.
    pub fn check_version(self, cancelled: &AtomicBool) -> Result<(String, Self), ClientError> {
        let (output, runtime) = self.check(HermesManagementCommand::Version, b"{}\n", cancelled)?;
        let version = retained_version(&output.stdout)
            .ok_or_else(|| crate::hermes::invalid("Hermes returned an invalid version banner"))?;
        Ok((version, runtime))
    }

    /// Checks a bounded YAML projection in a new private home. Callers interpret
    /// the output using the configuration parser and the bound harness version.
    pub fn check_config(
        self,
        config: &[u8],
        cancelled: &AtomicBool,
    ) -> Result<(ManagementOutput, Self), ClientError> {
        self.check(HermesManagementCommand::ConfigCheck, config, cancelled)
    }

    fn check(
        self,
        command: HermesManagementCommand,
        config: &[u8],
        cancelled: &AtomicBool,
    ) -> Result<(ManagementOutput, Self), ClientError> {
        if cancelled.load(std::sync::atomic::Ordering::Acquire) {
            return Err(command_error(ManagementError::Cancelled));
        }
        let home = ManagementHome::new(config)?;
        self.verify()?;
        let root = self.root().to_owned();
        let home_path = home.path.clone();
        let (output, (runtime, _home)) =
            run_hermes_python(&root, &home_path, command, (self, home), cancelled)
                .map_err(command_error)?;
        runtime.verify()?;
        if output.exit_code != 0 {
            return Err(crate::hermes::invalid("Hermes management check failed"));
        }
        if !output.stderr.is_empty() {
            return Err(crate::hermes::invalid(
                "Hermes management check wrote to stderr",
            ));
        }
        Ok((output, runtime))
    }
}

fn command_error(error: ManagementError) -> ClientError {
    let code = match error {
        ManagementError::Cancelled => ErrorCode::Canceled,
        ManagementError::Timeout => ErrorCode::Timeout,
        ManagementError::Busy | ManagementError::CleanupPending => ErrorCode::Busy,
        ManagementError::Launch | ManagementError::OutputLimit => ErrorCode::HarnessUnsupported,
        ManagementError::Io => ErrorCode::Internal,
    };
    ClientError {
        code,
        message: error.to_string(),
        field_path: None,
        retryable: matches!(
            code,
            ErrorCode::Busy | ErrorCode::Timeout | ErrorCode::Internal
        ),
    }
}

fn retained_version(bytes: &[u8]) -> Option<String> {
    if bytes.len() as u64 > crate::hermes::CLI_OUTPUT_LIMIT {
        return None;
    }
    let output = crate::hermes::strip_ansi(std::str::from_utf8(bytes).ok()?).replace("\r\n", "\n");
    if output
        .chars()
        .any(|character| character.is_control() && character != '\n')
    {
        return None;
    }
    let prefix = "Hermes Agent v";
    let first = output.lines().next()?.strip_prefix(prefix)?;
    let (version, date) = first.split_once(" (")?;
    let date = date.strip_suffix(')')?;
    if !crate::hermes::valid_version(version)
        || !crate::hermes::valid_version(date)
        || output
            .lines()
            .filter(|line| line.starts_with(prefix))
            .count()
            != 1
    {
        return None;
    }
    Some(version.into())
}

fn invalid() -> ClientError {
    crate::hermes::invalid("Hermes isolated check could not be prepared or verified")
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use std::fs;

    pub(in crate::hermes) fn management_test_guard() -> std::sync::MutexGuard<'static, ()> {
        static CHECKS: std::sync::Mutex<()> = std::sync::Mutex::new(());
        CHECKS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[test]
    fn management_home_is_private_and_drops_its_pin_before_cleanup() {
        let home = ManagementHome::new(b"model: fixture\n").unwrap();
        let path = home.path.clone();
        let holder = home._directory.path().to_owned();
        home._pin.verify_private().unwrap();
        assert_eq!(
            fs::read(path.join("config.yaml")).unwrap(),
            b"model: fixture\n"
        );
        assert!(fs::rename(&path, holder.join("moved")).is_err());
        drop(home);
        assert!(!holder.exists());
    }

    #[test]
    fn management_home_rejects_invalid_and_oversized_config() {
        for config in [b"[]".as_slice(), b"model: [", &[0xff]] {
            assert!(ManagementHome::new(config).is_err());
        }
        assert!(ManagementHome::new(&vec![b'x'; 1024 * 1024 + 1]).is_err());
    }

    #[test]
    fn management_banner_uses_harness_version_not_python_or_sdk_version() {
        let banner = b"Hermes Agent v0.17.0 (2026.6.19)\nProject: fixture\nPython: 3.11.15\nOpenAI SDK: 2.24.0\n";
        assert_eq!(retained_version(banner).as_deref(), Some("0.17.0"));
        for invalid in [
            b"Python: 3.11.15\n".as_slice(),
            b"Hermes Agent v0.17 (2026.6.19)\n",
            b"Hermes Agent v0.17.0 (2026.6.19)\0",
            b"Hermes Agent v0.17.0 (2026.6.19)\nHermes Agent v0.18.2 (2026.6.19)\n",
        ] {
            assert!(retained_version(invalid).is_none());
        }
    }

    #[test]
    fn management_parses_the_actual_isolated_config_check_output() {
        let bytes = include_bytes!("../../../tests/fixtures/hermes-0.17.0-config-check.txt");
        let report = crate::hermes::parse_config_check_output(bytes, "0.17.0").unwrap();
        assert!(report.valid);
        assert_eq!(report.findings, ["isolated_credential_missing"]);
    }

    #[test]
    fn management_facade_runs_only_the_owned_runtime_and_cleans_each_private_home() {
        let _guard = management_test_guard();
        let (_temp, runtime) = runtime_fixture(b"fixture launcher");
        let identity = runtime.identity();
        let (version, runtime) = runtime.check_version(&AtomicBool::new(false)).unwrap();
        assert_eq!(version, "0.17.0");
        assert_eq!(runtime.identity(), identity);
        let (output, runtime) = runtime
            .check_config(b"model: fixture\n", &AtomicBool::new(false))
            .unwrap();
        assert_eq!(runtime.identity(), identity);
        let stdout = String::from_utf8(output.stdout).unwrap();
        let home = PathBuf::from(stdout.trim().strip_prefix("PROFILE=").unwrap());
        assert!(!home.parent().unwrap().exists());
        runtime.verify().unwrap();
    }

    pub(in crate::hermes) fn runtime_fixture(
        launcher: &[u8],
    ) -> (tempfile::TempDir, LockedRuntime) {
        use crate::hermes::python_runtime::{RuntimeSource, capture_inputs};
        use std::{os::windows::process::CommandExt as _, process::Command};
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let source = root.join("fixture.rs");
        let python = root.join("python");
        fs::create_dir(&python).unwrap();
        fs::write(&source, r#"
use std::{env, fs, path::PathBuf};
fn main() {
    let args = env::args().collect::<Vec<_>>();
    assert_eq!(&args[1..4], ["-I", "-S", "-B"]);
    let root = env::current_exe().unwrap().parent().unwrap().parent().unwrap().to_owned();
    assert_eq!(fs::canonicalize(&args[4]).unwrap(), fs::canonicalize(root.join("bootstrap.py")).unwrap());
    let home = PathBuf::from(env::var_os("HERMES_HOME").unwrap());
    for key in ["HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP"] {
        assert_eq!(PathBuf::from(env::var_os(key).unwrap()), home);
    }
    let config = fs::read_to_string(home.join("config.yaml")).unwrap();
    match args[5..].iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["--version"] => {
            assert_eq!(config, "{}\n");
            println!("Hermes Agent v0.17.0 (2026.6.19)\nPython: 3.11.15\nOpenAI SDK: 2.24.0");
        }
        ["config", "check"] => {
            if config == "model: adapter\n" {
                println!("📋 Configuration Status\n\n  Config version: 32 ✓\n\n  Required:\n\n  Optional:");
            } else if config == "model: stderr\n" {
                eprintln!("fixture failure that must not be exposed");
            } else {
                assert_eq!(config, "model: fixture\n");
                println!("PROFILE={}", home.display());
            }
        }
        _ => panic!("unexpected command"),
    }
}
"#).unwrap();
        let compilation = Command::new("rustc")
            .args([
                "--edition=2024",
                "--crate-name",
                "hermes_management_fixture",
            ])
            .arg(&source)
            .arg("-o")
            .arg(python.join("python.exe"))
            .creation_flags(0x0800_0000)
            .output()
            .unwrap();
        assert!(
            compilation.status.success(),
            "{}",
            String::from_utf8_lossy(&compilation.stderr)
        );
        let bootstrap = root.join("bootstrap.py");
        fs::write(&bootstrap, b"# inert fixture, never interpreted\n").unwrap();
        let launcher_source = root.join("launcher");
        fs::write(&launcher_source, launcher).unwrap();
        let runtime = capture_inputs(
            &root,
            vec![
                RuntimeSource {
                    source: python,
                    destination: "python".into(),
                },
                RuntimeSource {
                    source: bootstrap,
                    destination: "bootstrap.py".into(),
                },
                RuntimeSource {
                    source: launcher_source,
                    destination: "metadata/hermes-launcher.exe".into(),
                },
            ],
        )
        .unwrap()
        .retain()
        .unwrap()
        .lock()
        .unwrap();
        (temp, runtime)
    }
}
