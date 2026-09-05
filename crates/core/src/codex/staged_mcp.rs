//! Host-side validation and merge boundary for isolated Codex MCP generation.
//!
//! Parsing output does not attest how it was generated. The restricted runner
//! and approval-bound generation evidence must be verified by the caller before
//! any resulting native state can be applied. This module performs no writes.

use context_relay_native_runner::NativeState;
use context_relay_protocol::ClientError;
use serde::Deserialize;
use serde_json::Value;
use toml_edit::{DocumentMut, Item, Table, Value as TomlValue};

use super::{bytes_to_document, invalid, validate_cli_declaration};
use crate::native_transaction::model::CanonicalCliDeclaration;

const MAX_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_COMMAND_BYTES: usize = 4096;
const SERVER: &str = "context-relay";

/// Closed input: one already-canonical local bridge, with no configurable flags,
/// environment, server name, or working directory. It contains no live config.
pub struct CodexMcpGenerationInput {
    command: String,
}

impl CodexMcpGenerationInput {
    pub fn new(declaration: &CanonicalCliDeclaration) -> Result<Self, ClientError> {
        if declaration.canonical_body.len() > MAX_OUTPUT_BYTES {
            return Err(invalid("Codex staged input is too large"));
        }
        validate_cli_declaration(declaration)
            .map_err(|_| invalid("Codex staged input is not the managed bridge"))?;
        let body: Value = serde_json::from_str(&declaration.canonical_body)
            .map_err(|_| invalid("Codex staged input is invalid"))?;
        let command = body["command"]
            .as_str()
            .filter(|command| command.len() <= MAX_COMMAND_BYTES)
            .ok_or_else(|| invalid("Codex staged command is invalid"))?;
        Ok(Self {
            command: command.to_owned(),
        })
    }

    /// Arguments for the pinned Codex executable, never for a shell.
    pub fn add_arguments(&self) -> Vec<String> {
        [
            "mcp",
            "add",
            SERVER,
            "--",
            &self.command,
            "--harness",
            "codex",
        ]
        .map(str::to_owned)
        .into()
    }

    pub fn validate_output(
        &self,
        config: &[u8],
        readback: &[u8],
    ) -> Result<ValidatedCodexMcpItem, ClientError> {
        if config.len() > MAX_OUTPUT_BYTES || readback.len() > MAX_OUTPUT_BYTES {
            return Err(invalid("Codex staged output is too large"));
        }
        let document = bytes_to_document(config)?;
        let servers = document
            .get("mcp_servers")
            .and_then(Item::as_table)
            .ok_or_else(|| invalid("Codex staged output is invalid"))?;
        let item = servers
            .get(SERVER)
            .and_then(Item::as_table)
            .ok_or_else(|| invalid("Codex staged output is invalid"))?;
        if document.len() != 1 || servers.len() != 1 || !matches_managed_item(item, &self.command) {
            return Err(invalid("Codex staged output contains unexpected settings"));
        }
        // Typed objects reject duplicate as well as unknown keys. A generic
        // JSON Value would silently keep the last duplicate declaration.
        let output: McpReadback = serde_json::from_slice(readback)
            .map_err(|_| invalid("Codex staged readback is invalid"))?;
        if !output.matches(&self.command) {
            return Err(invalid(
                "Codex staged readback differs from the managed bridge",
            ));
        }
        let mut item = item.clone();
        item.set_position(None);
        Ok(ValidatedCodexMcpItem {
            item,
            command: self.command.clone(),
        })
    }
}

/// A structurally checked CLI output item, not a sandbox or approval attestation.
pub struct ValidatedCodexMcpItem {
    item: Table,
    command: String,
}

impl ValidatedCodexMcpItem {
    /// Produces one intended global file state from a captured live snapshot.
    /// The caller must seal/apply it through the native transaction machinery.
    /// Absent files need an approved creation-metadata policy and are rejected.
    pub fn merge_into(&self, original: &NativeState) -> Result<NativeState, ClientError> {
        let NativeState::RegularFile { bytes, metadata } = original else {
            return Err(invalid(
                "Codex staged merge requires a captured regular file",
            ));
        };
        let mut document = bytes_to_document(bytes)?;
        if let Some(servers) = document.get("mcp_servers") {
            let servers = servers
                .as_table()
                .ok_or_else(|| invalid("Codex MCP configuration cannot be safely merged"))?;
            if let Some(existing) = servers.get(SERVER)
                && !existing
                    .as_table()
                    .is_some_and(|item| matches_managed_item(item, &self.command))
            {
                return Err(invalid(
                    "Codex managed bridge conflicts with existing settings",
                ));
            }
        }
        disable_memory_settings(&mut document, false)?;
        if document
            .get("mcp_servers")
            .and_then(|servers| servers.get(SERVER))
            .is_none()
        {
            // Chained indexing on an absent item creates an inline table.
            // The Codex adapter imports ordinary MCP tables, including on the
            // first connection when no other server has created the parent.
            if !document.contains_key("mcp_servers") {
                let mut servers = Table::new();
                servers.set_implicit(true);
                document["mcp_servers"] = Item::Table(servers);
            }
            document["mcp_servers"][SERVER] = Item::Table(self.item.clone());
        }
        Ok(NativeState::regular_file(
            document.to_string().into_bytes(),
            metadata.clone(),
        ))
    }
}

fn matches_managed_item(item: &Table, command: &str) -> bool {
    item.len() == 2
        && item.get("command").and_then(Item::as_str) == Some(command)
        && item
            .get("args")
            .and_then(Item::as_array)
            .is_some_and(|args| {
                args.len() == 2
                    && args.get(0).and_then(TomlValue::as_str) == Some("--harness")
                    && args.get(1).and_then(TomlValue::as_str) == Some("codex")
            })
}

/// Shared with native memory preview so the staged global merge and project
/// layer edits use the same shape validation and comment-preserving booleans.
pub(super) fn disable_memory_settings(
    document: &mut DocumentMut,
    project_layer: bool,
) -> Result<bool, ClientError> {
    let keys = ["generate_memories", "use_memories"];
    if !document.get("memories").is_none_or(|item| {
        item.as_table_like().is_some_and(|table| {
            keys.iter()
                .all(|key| table.get(key).is_none_or(|value| value.as_bool().is_some()))
        })
    }) {
        return Err(invalid(
            "Codex memory configuration cannot be safely merged",
        ));
    }
    let mut changed = false;
    for key in keys {
        let current = document
            .get("memories")
            .and_then(Item::as_table_like)
            .and_then(|table| table.get(key))
            .and_then(Item::as_bool);
        if current == Some(false) || (project_layer && current.is_none()) {
            continue;
        }
        let item = &mut document["memories"][key];
        if let Some(TomlValue::Boolean(current)) = item.as_value_mut() {
            let decor = current.decor().clone();
            let mut intended = toml_edit::Formatted::new(false);
            *intended.decor_mut() = decor;
            *item = Item::Value(TomlValue::Boolean(intended));
        } else {
            *item = toml_edit::value(false);
        }
        changed = true;
    }
    Ok(changed)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct McpReadback {
    name: String,
    enabled: bool,
    disabled_reason: Value,
    transport: StdioReadback,
    enabled_tools: Value,
    disabled_tools: Value,
    startup_timeout_sec: Value,
    tool_timeout_sec: Value,
}

impl McpReadback {
    fn matches(&self, command: &str) -> bool {
        self.name == SERVER
            && self.enabled
            && self.disabled_reason.is_null()
            && self.enabled_tools.is_null()
            && self.disabled_tools.is_null()
            && self.startup_timeout_sec.is_null()
            && self.tool_timeout_sec.is_null()
            && self.transport.kind == "stdio"
            && self.transport.command == command
            && self.transport.args == ["--harness", "codex"]
            && (self.transport.env.is_null()
                || self
                    .transport
                    .env
                    .as_object()
                    .is_some_and(|env| env.is_empty()))
            && self.transport.env_vars.is_empty()
            && self.transport.cwd.is_null()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StdioReadback {
    #[serde(rename = "type")]
    kind: String,
    command: String,
    args: Vec<String>,
    env: Value,
    env_vars: Vec<String>,
    cwd: Value,
}
