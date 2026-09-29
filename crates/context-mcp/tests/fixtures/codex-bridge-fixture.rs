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
    let harness = match &invocation {
        Invocation::Mcp { harness } | Invocation::Hook { harness, .. } => *harness,
    };
    let token = fixture_token(&suffix, harness).ok_or("invalid fixture runtime")?;
    let runtime = RuntimeConfig::for_test(suffix, Some(root.join("runtime")))?;
    let daemon = LocalDaemon::for_test(runtime, InstallationToken::from_bytes(token));
    let cwd = std::env::current_dir()?;
    match invocation {
        Invocation::Mcp { harness } => {
            Server::new(
                daemon,
                McpBinding {
                    harness,
                    working_directory: wire_path(&cwd),
                },
            )
            .run(BufReader::new(tokio::io::stdin()), tokio::io::stdout())
            .await?;
        }
        Invocation::Hook {
            harness: harness @ (HarnessId::Codex | HarnessId::ClaudeCode),
            event,
        } => {
            let bytes = read_hook_input(tokio::io::stdin()).await?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_millis()
                .try_into()?;
            let output = execute_hook(daemon, harness, event, &bytes, &cwd, now).await?;
            std::io::stdout().write_all(output.as_bytes())?;
        }
        _ => return Err("fixture requires a supported native hook harness".into()),
    }
    Ok(())
}

// Closed test namespaces and fixed synthetic tokens cannot select production 'main'.
fn fixture_token(suffix: &str, harness: HarnessId) -> Option<[u8; 32]> {
    match harness {
        HarnessId::Codex if suffix.starts_with("codex-native-") && suffix.len() == 45 => {
            Some([0x71; 32])
        }
        HarnessId::Hermes if suffix.starts_with("hermes-native-") && suffix.len() == 46 => {
            Some([0x5a; 32])
        }
        HarnessId::ClaudeCode if suffix.starts_with("claude-native-") && suffix.len() == 46 => {
            Some([0x62; 32])
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_binding_cannot_select_production_or_another_harness() {
        let codex = format!("codex-native-{}", "a".repeat(32));
        let hermes = format!("hermes-native-{}", "b".repeat(32));
        let claude = format!("claude-native-{}", "c".repeat(32));
        assert_eq!(fixture_token(&codex, HarnessId::Codex), Some([0x71; 32]));
        assert_eq!(fixture_token(&hermes, HarnessId::Hermes), Some([0x5a; 32]));
        assert_eq!(
            fixture_token(&claude, HarnessId::ClaudeCode),
            Some([0x62; 32])
        );
        for (suffix, harness) in [
            ("main", HarnessId::Hermes),
            ("main", HarnessId::Codex),
            ("main", HarnessId::ClaudeCode),
            (&codex, HarnessId::Hermes),
            (&hermes, HarnessId::Codex),
            (&hermes, HarnessId::ClaudeCode),
            (&codex, HarnessId::ClaudeCode),
            (&claude, HarnessId::Codex),
            (&claude, HarnessId::Hermes),
            ("claude-native-short", HarnessId::ClaudeCode),
            ("hermes-native-short", HarnessId::Hermes),
        ] {
            assert_eq!(fixture_token(suffix, harness), None);
        }
    }
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
