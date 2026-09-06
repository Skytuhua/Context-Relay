//! Fixed, test-only native-loader readback using the production ownership guard.
use super::*;

/// Runs only the fixed settings readback below in an approved disposable profile.
/// Uses the same suspended launch, bounds, job-empty check and quarantine as
/// management commands. This entry is absent from ordinary production builds.
pub fn read_hermes_settings_for_qualification<G: Send + 'static>(
    root: &Path,
    home: &Path,
    owner: G,
    cancelled: &AtomicBool,
) -> Result<(ManagementOutput, G), ManagementError> {
    if !root.is_absolute() || !home.is_absolute() {
        return Err(ManagementError::Launch);
    }
    let system_root = crate::environment::windows_directory().ok_or(ManagementError::Launch)?;
    let mut environment = [
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "HERMES_HOME",
        "TEMP",
        "TMP",
    ]
    .into_iter()
    .map(|key| (key.into(), home.as_os_str().to_owned()))
    .collect::<Vec<_>>();
    environment.extend([
        (
            "PATH".into(),
            Path::new(&system_root).join("System32").into_os_string(),
        ),
        ("SystemRoot".into(), system_root),
        ("NO_COLOR".into(), "1".into()),
        ("TERM".into(), "dumb".into()),
    ]);
    run_process(
        ProcessSpec {
            executable: root.join("python/python.exe"),
            args: vec![
                "-I".into(),
                "-S".into(),
                "-B".into(),
                "-c".into(),
                READBACK.into(),
                root.as_os_str().to_owned(),
            ],
            directory: home.to_owned(),
            environment,
        },
        owner,
        cancelled,
        Limits {
            runtime: Duration::from_secs(30),
            cleanup: Duration::from_secs(3),
            output: 64 * 1024,
        },
        Faults::default(),
    )
}

const READBACK: &str = r#"
import sys, os, json
from pathlib import Path
root = Path(sys.argv[1]).resolve()
assert sys.flags.isolated and sys.flags.no_site
assert all(Path(p).resolve().is_relative_to(root) for p in sys.path)
sys.prefix = str(root / 'environment')
sys.exec_prefix = sys.prefix
dll = root / 'packages' / 'pywin32_system32'
handles = [os.add_dll_directory(str(dll))] if dll.is_dir() else []
from hermes_cli.config import load_config_readonly
config = load_config_readonly()
server = config.get('mcp_servers', {}).get('context-relay')
print(json.dumps({'server': None if server is None else {
    'command': server.get('command'), 'args': server.get('args')},
    'agentMemory': config['memory']['memory_enabled'],
    'userMemory': config['memory']['user_profile_enabled']}))
"#;
