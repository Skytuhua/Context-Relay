//! Explicit, read-only OpenCode project setup. This module never owns or writes
//! native configuration and cannot produce a managed setup plan or receipt.

use std::{fmt, fs, io::Read as _, path::Path};

use context_relay_protocol::{
    ClientError, ErrorCode, NativePlatform, OpenCodeMcpExport, ProjectId, WireNativeValue,
};
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Value, json};

use super::install::{BRIDGE_SERVER_NAME, BridgeExecutable, attest_bridge_executable};

pub const INSTRUCTION_FILE: &str = ".context-relay-opencode.md";
pub const MCP_TIMEOUT_MS: u32 = 60_000;
const MAX_CONFIG_BYTES: usize = 262_144;
pub const INSTRUCTIONS: &str = "## Context Relay\n\n\
- At the start of a task, use `context_relay_search` for the active project to find relevant saved context.\n\
- Save explicit user or project decisions with `context_relay_remember`. Submit inferred knowledge with `context_relay_propose_memory` for review.\n\
- Use `context_relay_list_tasks`, `context_relay_upsert_task`, and `context_relay_complete_task` for the shared task ledger. Only complete a Context Relay task using its returned ID and explicit evidence.\n\
- Respect the user's Context Relay access policy. If the tools are unavailable or access is denied, explain that and continue without claiming to have read or saved context.\n";

/// Inspect only the selected project and the installed bridge. The returned
/// fragment is for a user to merge; no existing JSONC or instruction bytes are
/// included in the response or changed. Other OpenCode configuration layers
/// and runtime approvals remain the user's responsibility.
pub fn project_export(
    project_id: ProjectId,
    project_root: &Path,
    bridge: &BridgeExecutable,
) -> Result<OpenCodeMcpExport, ClientError> {
    if !project_root.is_absolute() || !project_root.is_dir() {
        return Err(invalid(
            "OpenCode setup requires an existing registered project folder",
        ));
    }
    let root = fs::canonicalize(project_root)
        .map_err(|_| invalid("The registered project folder is unavailable"))?;
    // Do not turn a previously attested path into authority after its contents
    // have changed. Nothing in this export executes the bridge or a harness.
    let current = attest_bridge_executable(&bridge.path)?;
    if current != *bridge {
        return Err(invalid(
            "The installed MCP bridge changed; prepare a new export",
        ));
    }
    let command = literal_path(&current.path)?;
    let cwd = literal_path(&root)?;
    let server = json!({
        "type": "local",
        "command": [command, "--harness", "opencode"],
        "enabled": true,
        "cwd": cwd,
        "timeout": MCP_TIMEOUT_MS
    });
    let json_path = root.join("opencode.json");
    let jsonc_path = root.join("opencode.jsonc");
    let json = read_optional(&json_path, MAX_CONFIG_BYTES)?;
    let jsonc = read_optional(&jsonc_path, MAX_CONFIG_BYTES)?;
    let config_path = match (json, jsonc) {
        (Some(_), Some(_)) => {
            return Err(invalid(
                "Both opencode.json and opencode.jsonc exist; resolve the ambiguous project configuration first",
            ));
        }
        (Some(bytes), None) => {
            validate_config(&bytes, &server)?;
            json_path
        }
        (None, Some(bytes)) => {
            validate_config(&bytes, &server)?;
            jsonc_path
        }
        (None, None) => json_path,
    };
    let instruction_path = root.join(INSTRUCTION_FILE);
    if let Some(existing) = read_optional(&instruction_path, 8_192)?
        && !std::str::from_utf8(&existing).is_ok_and(|value| {
            value
                .strip_prefix('\u{feff}')
                .unwrap_or(value)
                .replace("\r\n", "\n")
                == INSTRUCTIONS
        })
    {
        return Err(invalid(
            "The OpenCode instruction file already has different content; review it before exporting",
        ));
    }
    let config_fragment = serde_json::to_string_pretty(&json!({
        "mcp": { BRIDGE_SERVER_NAME: server },
        "instructions": [INSTRUCTION_FILE]
    }))
    .map_err(|_| invalid("The OpenCode configuration fragment could not be prepared"))?;
    let export = OpenCodeMcpExport {
        project_id,
        project_root: wire_path(&root),
        config_path: wire_path(&config_path),
        instruction_path: wire_path(&instruction_path),
        config_fragment,
        instruction_markdown: INSTRUCTIONS.to_owned(),
    };
    export
        .validate()
        .map_err(|_| invalid("The OpenCode export is outside supported path or size limits"))?;
    Ok(export)
}

fn literal_path(path: &Path) -> Result<&str, ClientError> {
    let value = path
        .to_str()
        .ok_or_else(|| invalid("OpenCode requires a Unicode path"))?;
    // OpenCode expands these tokens inside config strings, including commands.
    // JSON escaping cannot make such a path literal.
    if value.chars().any(char::is_control) || value.contains("{env:") || value.contains("{file:") {
        return Err(invalid(
            "The path cannot be represented literally in OpenCode configuration",
        ));
    }
    Ok(value)
}

fn read_optional(path: &Path, limit: usize) -> Result<Option<Vec<u8>>, ClientError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => {
            return Err(invalid(
                "The existing OpenCode project files cannot be inspected",
            ));
        }
    };
    #[cfg(windows)]
    let reparse = {
        use std::os::windows::fs::MetadataExt as _;
        metadata.file_attributes() & 0x400 != 0
    };
    #[cfg(not(windows))]
    let reparse = false;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || reparse
        || metadata.len() > limit as u64
    {
        return Err(invalid(
            "OpenCode project files must be bounded regular files without links",
        ));
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .and_then(|file| file.take(limit as u64 + 1).read_to_end(&mut bytes))
        .map_err(|_| invalid("The existing OpenCode project files cannot be read"))?;
    if bytes.len() > limit {
        return Err(invalid(
            "The existing OpenCode project file exceeds the supported size",
        ));
    }
    Ok(Some(bytes))
}

fn validate_config(bytes: &[u8], expected: &Value) -> Result<(), ClientError> {
    std::str::from_utf8(bytes)
        .map_err(|_| invalid("OpenCode project configuration must be UTF-8"))?;
    // OpenCode uses its JSONC parser for both .json and .jsonc project files.
    let normalized = normalize_jsonc(bytes)?;
    let StrictValue(value) = serde_json::from_slice(&normalized).map_err(|_| {
        invalid("OpenCode project configuration is malformed or contains duplicate keys")
    })?;
    let object = value
        .as_object()
        .ok_or_else(|| invalid("OpenCode project configuration must be an object"))?;
    if let Some(mcp) = object.get("mcp") {
        let mcp = mcp
            .as_object()
            .ok_or_else(|| invalid("OpenCode mcp must be an object"))?;
        if mcp
            .get("servers")
            .and_then(Value::as_object)
            .is_some_and(|servers| servers.contains_key(BRIDGE_SERVER_NAME))
        {
            return Err(invalid(
                "An existing mcp.servers.context-relay entry uses another OpenCode configuration layout; review it before exporting",
            ));
        }
        if let Some(existing) = mcp.get(BRIDGE_SERVER_NAME)
            && existing != expected
        {
            return Err(invalid(
                "An existing context-relay MCP entry differs; review it before exporting",
            ));
        }
    }
    if let Some(instructions) = object.get("instructions") {
        let values = instructions
            .as_array()
            .ok_or_else(|| invalid("OpenCode instructions must be an array of paths"))?;
        if values.iter().any(|value| !value.is_string())
            || values
                .iter()
                .filter(|value| value.as_str() == Some(INSTRUCTION_FILE))
                .count()
                > 1
        {
            return Err(invalid(
                "OpenCode instructions are malformed or duplicate the Context Relay file",
            ));
        }
    }
    Ok(())
}

// Strip comments and trailing commas for validation only. Keep string bytes
// intact; serde then checks the entire grammar and recursion limit. Never use
// this normalized copy to rewrite the user's file.
fn normalize_jsonc(bytes: &[u8]) -> Result<Vec<u8>, ClientError> {
    let mut output = bytes.to_vec();
    let mut index = 0;
    let mut string = false;
    while index < bytes.len() {
        if string {
            match bytes[index] {
                b'\\' => {
                    index += 2;
                    continue;
                }
                b'"' => string = false,
                _ => {}
            }
        } else if bytes[index] == b'"' {
            string = true;
        } else if bytes.get(index..index + 2) == Some(b"//") {
            while index < bytes.len() && !matches!(bytes[index], b'\n' | b'\r') {
                output[index] = b' ';
                index += 1;
            }
            continue;
        } else if bytes.get(index..index + 2) == Some(b"/*") {
            output[index] = b' ';
            output[index + 1] = b' ';
            index += 2;
            while index + 1 < bytes.len() && bytes.get(index..index + 2) != Some(b"*/") {
                output[index] = b' ';
                index += 1;
            }
            if index + 1 >= bytes.len() {
                return Err(invalid("OpenCode JSONC has an unterminated comment"));
            }
            output[index] = b' ';
            output[index + 1] = b' ';
            index += 2;
            continue;
        }
        index += 1;
    }
    index = 0;
    string = false;
    let mut previous = None;
    while index < output.len() {
        let byte = output[index];
        if string {
            match byte {
                b'\\' => {
                    index += 2;
                    continue;
                }
                b'"' => string = false,
                _ => {}
            }
        } else if byte == b'"' {
            string = true;
        } else if byte == b','
            && previous.is_some_and(|value| !matches!(value, b'[' | b'{' | b',' | b':'))
        {
            let next = output[index + 1..]
                .iter()
                .find(|byte| !byte.is_ascii_whitespace());
            if next.is_some_and(|value| matches!(value, b']' | b'}')) {
                output[index] = b' ';
            }
        }
        if !byte.is_ascii_whitespace() {
            previous = Some(byte);
        }
        index += 1;
    }
    Ok(output)
}

struct StrictValue(Value);
impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictValue;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("JSON with unique object keys")
            }
            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(StrictValue(value.into()))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(StrictValue(value.into()))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(StrictValue(value.into()))
            }
            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(|value| StrictValue(Value::Number(value)))
                    .ok_or_else(|| E::custom("invalid JSON number"))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(StrictValue(value.into()))
            }
            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(StrictValue(value.into()))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(StrictValue(value)) = sequence.next_element()? {
                    values.push(value);
                }
                Ok(StrictValue(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut object: A) -> Result<Self::Value, A::Error> {
                let mut values = Map::new();
                while let Some((key, StrictValue(value))) =
                    object.next_entry::<String, StrictValue>()?
                {
                    if values.insert(key, value).is_some() {
                        return Err(de::Error::custom("duplicate JSON key"));
                    }
                }
                Ok(StrictValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(StrictVisitor)
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
        display: path.to_str().map(str::to_owned),
    }
}

fn invalid(message: &str) -> ClientError {
    ClientError {
        code: ErrorCode::InvalidRequest,
        message: message.to_owned(),
        field_path: None,
        retryable: false,
    }
}
