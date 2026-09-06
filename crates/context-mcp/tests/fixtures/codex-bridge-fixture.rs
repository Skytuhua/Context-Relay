//! Test-only process entry point: production dispatch with an isolated IPC target.
//! Never connects to the installed daemon or reads the user's credential store.
use std::{
    io::Write as _,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use context_relay_context_mcp::{
    Invocation, LocalDaemon, Server, execute_hook, parse_invocation, read_hook_input,
};
use context_relay_local_ipc::{InstallationToken, RuntimeConfig};
use context_relay_protocol::{HarnessId, McpBinding, NativePlatform, WireNativeValue};
use tokio::io::BufReader;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    if arguments.len() == 2 && arguments[1] == "--fixture-info" {
        println!("context-relay-isolated-codex-bridge-fixture-v1");
        return Ok(());
    }
    let invocation = parse_invocation(arguments).ok_or("invalid fixture invocation")?;
    let executable = std::env::current_exe()?;
    let root = executable.parent().ok_or("missing fixture parent")?;
    let suffix = std::fs::read_to_string(root.join("bridge-runtime.txt"))?;
    // The production suffix is 'main'; this fixture cannot select it.
    if !suffix.starts_with("codex-native-") || suffix.len() != 45 {
        return Err("invalid fixture runtime".into());
    }
    let runtime = RuntimeConfig::for_test(suffix, Some(root.join("runtime")))?;
    let daemon = LocalDaemon::for_test(runtime, InstallationToken::from_bytes([0x71; 32]));
    let cwd = std::env::current_dir()?;
    match invocation {
        Invocation::Mcp {
            harness: HarnessId::Codex,
        } => {
            Server::new(
                daemon,
                McpBinding {
                    harness: HarnessId::Codex,
                    working_directory: wire_path(&cwd),
                },
            )
            .run(BufReader::new(tokio::io::stdin()), tokio::io::stdout())
            .await?;
        }
        Invocation::Hook {
            harness: HarnessId::Codex,
            event,
        } => {
            let bytes = read_hook_input(tokio::io::stdin()).await?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_millis()
                .try_into()?;
            let output = execute_hook(daemon, HarnessId::Codex, event, &bytes, &cwd, now).await?;
            std::io::stdout().write_all(output.as_bytes())?;
        }
        _ => return Err("fixture requires Codex".into()),
    }
    Ok(())
}

fn wire_path(path: &Path) -> WireNativeValue {
    #[cfg(windows)]
    let (platform, bytes) = {
        use std::os::windows::ffi::OsStrExt as _;
        (
            NativePlatform::Windows,
            path.as_os_str()
                .encode_wide()
                .flat_map(u16::to_le_bytes)
                .collect(),
        )
    };
    #[cfg(not(windows))]
    let (platform, bytes) = {
        use std::os::unix::ffi::OsStrExt as _;
        (NativePlatform::Macos, path.as_os_str().as_bytes().to_vec())
    };
    WireNativeValue {
        platform,
        bytes,
        display: None,
    }
}
