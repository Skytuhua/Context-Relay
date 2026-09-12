//! Canonical managed Codex MCP serialization, compatibility checks and native merge.
//! Native setup serializes the documented fields directly. The output validator
//! also supports checking captured CLI fixtures; it does not attest execution.
//! This module performs no writes. Apply requires an approved native transaction.

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
pub struct CodexManagedMcpInput {
    command: String,
}

impl CodexManagedMcpInput {
    /// Serializes the documented native configuration directly. This does not
    /// claim CLI authorship and does not execute the configured command.
    pub(super) fn native_item(&self) -> CodexManagedMcpItem {
        let mut item = Table::new();
        item["command"] = toml_edit::value(&self.command);
        let mut args = toml_edit::Array::new();
        args.push("--harness");
        args.push("codex");
        item["args"] = toml_edit::value(args);
        CodexManagedMcpItem {
            item,
            command: self.command.clone(),
        }
    }

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
    ) -> Result<CodexManagedMcpItem, ClientError> {
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
        Ok(CodexManagedMcpItem {
            item,
            command: self.command.clone(),
        })
    }
}

/// A structurally checked managed item, not a sandbox or approval attestation.
pub struct CodexManagedMcpItem {
    item: Table,
    command: String,
}

impl CodexManagedMcpItem {
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

#[cfg(all(test, windows))]
mod native_tests {
    use super::*;
    use context_relay_native_runner::OsNativeFileSystem;
    use context_relay_protocol::{HarnessId, Sha256Digest};
    use serde_json::json;
    use sha2::{Digest as _, Sha256};
    use std::{
        env, fs,
        path::{Path, PathBuf},
        process::{Command, Stdio},
        time::Duration,
    };

    #[test]
    #[ignore = "requires explicitly selected Codex 0.144.6 and Node; synthetic profiles only"]
    fn pinned_codex_reads_native_bridge_exactly_like_its_official_cli() {
        const SHA256: &str = "4b76ded066d0239115ca97473d010c92072bc5c5550a45dd7cbebe1e9eb956a7";
        let executable = PathBuf::from(
            env::var_os("CONTEXT_RELAY_TEST_CODEX_EXE").expect("explicit Codex executable"),
        );
        let node = PathBuf::from(
            env::var_os("CONTEXT_RELAY_TEST_NODE_EXE").expect("explicit Node executable"),
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(fs::read(&executable).unwrap())),
            SHA256
        );
        let temp = tempfile::tempdir().unwrap();
        let physical = fs::canonicalize(temp.path()).unwrap();
        assert!(
            matches!(physical.components().next(), Some(std::path::Component::Prefix(prefix)) if matches!(prefix.kind(), std::path::Prefix::VerbatimDisk(_)))
        );
        let root = PathBuf::from(physical.to_str().unwrap().strip_prefix(r"\\?\").unwrap());
        assert!(root.is_absolute());
        assert_eq!(fs::canonicalize(&root).unwrap(), physical);
        let mut cases = vec![];
        for name in ["plain", "space 測試 O'Brien $HOME"] {
            let home = root.join(name);
            fs::create_dir(&home).unwrap();
            let command = home.join("inert bridge.exe");
            fs::write(&command, b"synthetic bridge; must never execute").unwrap();
            let command = fs::canonicalize(command).unwrap();
            let body =
                json!({"args":["--harness","codex"],"command":command,"type":"stdio"}).to_string();
            let declaration = CanonicalCliDeclaration {
                harness: HarnessId::Codex,
                server_name: SERVER.into(),
                fingerprint: Sha256Digest(Sha256::digest(body.as_bytes()).into()),
                canonical_body: body,
            };
            let input = CodexManagedMcpInput::new(&declaration).unwrap();
            let config = home.join("config.toml");
            fs::write(&config, "# retain synthetic mixed configuration\nmodel = 'synthetic-unused'\n[memories]\ngenerate_memories = true # retain comment\nuse_memories = true\n[mcp_servers.unrelated]\nurl = 'https://example.invalid/synthetic'\n").unwrap();
            let before = OsNativeFileSystem::new().snapshot(&config).unwrap();
            let intended = input.native_item().merge_into(before.state()).unwrap();
            let NativeState::RegularFile { bytes, .. } = intended else {
                panic!("native file")
            };
            assert!(
                String::from_utf8_lossy(&bytes)
                    .contains("generate_memories = false # retain comment")
            );
            fs::write(&config, bytes).unwrap();
            cases.push(json!({"name":name,"home":home,"command":command}));
        }
        let manifest = root.join("manifest.json");
        fs::write(
            &manifest,
            serde_json::to_vec(&json!({"executable":executable,"sha256":SHA256,"cases":cases}))
                .unwrap(),
        )
        .unwrap();
        let stdout = root.join("stdout");
        let stderr = root.join("stderr");
        let mut command = Command::new(node);
        command.env_clear();
        for name in ["SystemRoot", "WINDIR"] {
            if let Some(value) = env::var_os(name) {
                command.env(name, value);
            }
        }
        command
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/codex-native-mcp-readback.mjs"),
            )
            .arg(manifest)
            .current_dir(&root)
            .stdin(Stdio::piped())
            .stdout(fs::File::create(&stdout).unwrap())
            .stderr(fs::File::create(&stderr).unwrap());
        let result =
            crate::test_windows_process::run_in_owned_job(&mut command, Duration::from_secs(90))
                .unwrap();
        assert!(result.success(), "{}", fs::read_to_string(stderr).unwrap());
        println!("{}", fs::read_to_string(stdout).unwrap());
    }
}
