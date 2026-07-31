mod daemon;
pub mod protocol;
mod server;

use std::{ffi::OsString, path::Path};

use context_relay_protocol::{HarnessId, McpBinding, NativePlatform, WireNativeValue};
use tokio::io::BufReader;

pub use daemon::{BridgeError, Daemon, LocalDaemon};
pub use protocol::{MCP_COMPAT_REVISION, MCP_REVISION, RpcId, encode_message};
pub use server::{MAX_IN_FLIGHT_TOOL_CALLS, Server};

pub fn parse_harness(arguments: impl IntoIterator<Item = OsString>) -> Option<HarnessId> {
    let mut arguments = arguments.into_iter();
    arguments.next()?;
    if arguments.next()?.to_str()? != "--harness" {
        return None;
    }
    let harness = match arguments.next()?.to_str()? {
        "claude-code" => HarnessId::ClaudeCode,
        "codex" => HarnessId::Codex,
        "hermes" => HarnessId::Hermes,
        _ => return None,
    };
    arguments.next().is_none().then_some(harness)
}

pub async fn run_stdio(harness: HarnessId) -> Result<(), BridgeError> {
    let working_directory = std::env::current_dir().map_err(|_| BridgeError::Unavailable)?;
    let binding = McpBinding {
        harness,
        working_directory: encode_native_path(&working_directory),
    };
    Server::new(LocalDaemon::default(), binding)
        .run(BufReader::new(tokio::io::stdin()), tokio::io::stdout())
        .await
}

#[cfg(windows)]
fn encode_native_path(path: &Path) -> WireNativeValue {
    use std::os::windows::ffi::OsStrExt;

    WireNativeValue {
        platform: NativePlatform::Windows,
        bytes: path
            .as_os_str()
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect(),
        display: None,
    }
}

#[cfg(not(windows))]
fn encode_native_path(path: &Path) -> WireNativeValue {
    use std::os::unix::ffi::OsStrExt;

    WireNativeValue {
        platform: NativePlatform::Macos,
        bytes: path.as_os_str().as_bytes().to_vec(),
        display: None,
    }
}
