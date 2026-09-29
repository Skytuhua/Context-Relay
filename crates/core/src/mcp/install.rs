use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
};

use context_relay_protocol::{
    ClientError, ComponentKind, ComponentRecord, DeviceId, ErrorCode, HarnessId,
    HybridLogicalClock, Provenance, RecordId, ScopeRef,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

pub const BRIDGE_SERVER_NAME: &str = "context-relay";
const HERMES_STRUCTURAL_LOCATION: &str = "config:mcp_servers.context-relay";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeExecutable {
    pub path: PathBuf,
    pub digest: context_relay_protocol::Sha256Digest,
}

pub const fn harness_cli_name(harness: HarnessId) -> &'static str {
    match harness {
        HarnessId::ClaudeCode => "claude-code",
        HarnessId::Codex => "codex",
        HarnessId::Hermes => "hermes",
    }
}

pub fn bridge_component(
    harness: HarnessId,
    executable: &Path,
    origin_device: DeviceId,
    created_hlc: HybridLogicalClock,
) -> Result<ComponentRecord, ClientError> {
    let executable = attest_bridge_executable(executable)?;
    bridge_component_for_attested(harness, &executable, origin_device, created_hlc)
}

pub fn bridge_component_for_attested(
    harness: HarnessId,
    executable: &BridgeExecutable,
    origin_device: DeviceId,
    created_hlc: HybridLogicalClock,
) -> Result<ComponentRecord, ClientError> {
    let command = executable
        .path
        .to_str()
        .ok_or_else(|| invalid("MCP bridge executable path is invalid"))?;
    let component = ComponentRecord {
        id: stable_bridge_record_id(harness)?,
        scope: ScopeRef::Global,
        kind: ComponentKind::McpServer,
        name: BRIDGE_SERVER_NAME.to_owned(),
        body_markdown: canonical_bridge_body(harness, command)?,
        metadata: bridge_metadata(harness),
        provenance: Provenance {
            origin_device,
            harness: None,
            source: None,
            created_hlc,
        },
        archived: false,
    };
    component
        .validate()
        .map_err(|_| invalid("MCP bridge component is invalid"))?;
    Ok(component)
}

pub fn attest_bridge_executable(path: &Path) -> Result<BridgeExecutable, ClientError> {
    let command = absolute_non_link_executable(path)?;
    let bytes =
        fs::read(&command).map_err(|_| invalid("MCP bridge executable cannot be safely read"))?;
    Ok(BridgeExecutable {
        path: PathBuf::from(command),
        digest: context_relay_protocol::Sha256Digest(Sha256::digest(bytes).into()),
    })
}

pub fn is_managed_bridge_component(harness: HarnessId, component: &ComponentRecord) -> bool {
    if component.id
        != match stable_bridge_record_id(harness) {
            Ok(id) => id,
            Err(_) => return false,
        }
        || component.scope != ScopeRef::Global
        || component.kind != ComponentKind::McpServer
        || component.name != BRIDGE_SERVER_NAME
        || component.metadata != bridge_metadata(harness)
        || component.provenance.harness.is_some()
        || component.provenance.source.is_some()
    {
        return false;
    }
    is_canonical_bridge_body(harness, &component.body_markdown, false)
}

pub(crate) fn is_canonical_bridge_body(
    harness: HarnessId,
    body: &str,
    allow_disabled_projection: bool,
) -> bool {
    let Ok(mut value) = serde_json::from_str::<Value>(body) else {
        return false;
    };
    if !serde_json::to_string(&value).is_ok_and(|canonical| canonical == body) {
        return false;
    }
    if allow_disabled_projection
        && value
            .get("enabled")
            .is_some_and(|enabled| enabled == &Value::Bool(false))
    {
        let Some(object) = value.as_object_mut() else {
            return false;
        };
        object.remove("enabled");
    }
    let Some(command) = value.get("command").and_then(Value::as_str) else {
        return false;
    };
    let Ok(command) = absolute_non_link_executable(Path::new(command)) else {
        return false;
    };
    canonical_bridge_body(harness, &command).is_ok_and(|expected| {
        serde_json::to_string(&value).is_ok_and(|canonical| canonical == expected)
    })
}

fn bridge_metadata(harness: HarnessId) -> Vec<(String, String)> {
    match harness {
        HarnessId::Hermes => vec![(
            "structuralLocation".to_owned(),
            HERMES_STRUCTURAL_LOCATION.to_owned(),
        )],
        HarnessId::ClaudeCode | HarnessId::Codex => Vec::new(),
    }
}

fn canonical_bridge_body(harness: HarnessId, command: &str) -> Result<String, ClientError> {
    let value = match harness {
        HarnessId::Hermes => json!({
            "args": ["--harness", harness_cli_name(harness)],
            "command": command,
        }),
        HarnessId::ClaudeCode | HarnessId::Codex => json!({
            "args": ["--harness", harness_cli_name(harness)],
            "command": command,
            "type": "stdio",
        }),
    };
    serde_json::to_string(&value).map_err(|_| invalid("MCP bridge declaration is invalid"))
}

fn stable_bridge_record_id(harness: HarnessId) -> Result<RecordId, ClientError> {
    let mut bytes: [u8; 32] = Sha256::digest(format!(
        "context-relay|mcp-bridge|{}",
        harness_cli_name(harness)
    ))
    .into();
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    RecordId::from_str(&format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    ))
    .map_err(|_| invalid("MCP bridge identifier cannot be derived"))
}

fn absolute_non_link_executable(path: &Path) -> Result<String, ClientError> {
    if !path.is_absolute() {
        return Err(invalid("MCP bridge executable path is invalid"));
    }
    let source = path
        .to_str()
        .filter(|value| !value.chars().any(char::is_control))
        .ok_or_else(|| invalid("MCP bridge executable path is invalid"))?;
    if source.is_empty() {
        return Err(invalid("MCP bridge executable path is invalid"));
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|_| invalid("MCP bridge executable is unavailable"))?;
    if is_link_or_reparse_point(&metadata) || !metadata.is_file() {
        return Err(invalid("MCP bridge executable is invalid"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(invalid("MCP bridge executable is not executable"));
        }
    }
    let canonical = fs::canonicalize(path)
        .map_err(|_| invalid("MCP bridge executable cannot be safely resolved"))?;
    let canonical = canonical
        .to_str()
        .filter(|value| !value.chars().any(char::is_control))
        .ok_or_else(|| invalid("MCP bridge executable path is invalid"))?;
    Ok(canonical.to_owned())
}

fn is_link_or_reparse_point(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;

        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn invalid(message: &'static str) -> ClientError {
    ClientError {
        code: ErrorCode::InvalidRequest,
        message: message.to_owned(),
        field_path: None,
        retryable: false,
    }
}
