use std::{fs, path::PathBuf};

use context_relay_core::mcp::{
    install::{BridgeExecutable, attest_bridge_executable},
    opencode::{INSTRUCTION_FILE, INSTRUCTIONS, MCP_TIMEOUT_MS, project_export},
};
use context_relay_protocol::{OpenCodeMcpExport, ProjectId};
use serde_json::{Value, json};

const PROJECT: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073987";

struct Fixture {
    _directory: tempfile::TempDir,
    root: PathBuf,
    bridge: BridgeExecutable,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("Project & notes 專案 🚀");
        fs::create_dir(&root).unwrap();
        let executable = directory.path().join(if cfg!(windows) {
            "context-relay-context-mcp.exe"
        } else {
            "context-relay-context-mcp"
        });
        fs::write(&executable, b"not executed: attestation fixture").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let bridge = attest_bridge_executable(&executable).unwrap();
        Self {
            _directory: directory,
            root,
            bridge,
        }
    }

    fn export(&self) -> Result<OpenCodeMcpExport, context_relay_protocol::ClientError> {
        project_export(
            PROJECT.parse::<ProjectId>().unwrap(),
            &self.root,
            &self.bridge,
        )
    }
}

#[test]
fn export_uses_attested_literal_command_project_cwd_and_documented_timeout_without_writes() {
    let fixture = Fixture::new();
    fs::write(
        fixture.root.join("AGENTS.md"),
        b"Keep my project instructions.\n",
    )
    .unwrap();
    let exported = fixture.export().unwrap();
    let fragment: Value = serde_json::from_str(&exported.config_fragment).unwrap();
    let root = fs::canonicalize(&fixture.root).unwrap();
    assert_eq!(
        fragment,
        json!({
            "mcp": {"context-relay": {
                "type": "local",
                "command": [fixture.bridge.path.to_str().unwrap(), "--harness", "opencode"],
                "cwd": root.to_str().unwrap(),
                "enabled": true,
                "timeout": MCP_TIMEOUT_MS,
            }},
            "instructions": [INSTRUCTION_FILE]
        })
    );
    assert_eq!(MCP_TIMEOUT_MS, 60_000);
    assert_eq!(exported.project_id.to_string(), PROJECT);
    assert_eq!(exported.instruction_markdown, INSTRUCTIONS);
    assert!(!fixture.root.join("opencode.json").exists());
    assert!(!fixture.root.join(INSTRUCTION_FILE).exists());
    assert_eq!(
        fs::read(fixture.root.join("AGENTS.md")).unwrap(),
        b"Keep my project instructions.\n"
    );
}

#[test]
fn existing_jsonc_comments_servers_instructions_and_private_values_are_preserved() {
    let fixture = Fixture::new();
    let original = br#"{
      // My existing settings must remain byte-for-byte unchanged.
      "model": "provider/model",
      "mcp": {"another-server": {"type":"remote", "url":"https://example.invalid/with//slashes"},},
      "instructions": ["AGENTS.md", "docs/*.md",],
      "environment-note": "private configuration value",
    }"#;
    fs::write(fixture.root.join("opencode.jsonc"), original).unwrap();
    fs::write(
        fixture.root.join("CLAUDE.md"),
        b"Existing fallback instructions.\n",
    )
    .unwrap();
    let exported = fixture.export().unwrap();
    assert!(
        exported
            .config_path
            .display
            .unwrap()
            .ends_with("opencode.jsonc")
    );
    assert_eq!(
        fs::read(fixture.root.join("opencode.jsonc")).unwrap(),
        original
    );
    assert_eq!(
        fs::read(fixture.root.join("CLAUDE.md")).unwrap(),
        b"Existing fallback instructions.\n"
    );
    assert!(
        !exported
            .config_fragment
            .contains("private configuration value")
    );
    assert!(!fixture.root.join(INSTRUCTION_FILE).exists());
}

#[test]
fn malformed_duplicate_and_conflicting_configurations_are_refused_without_writes() {
    let fixture = Fixture::new();
    for original in [
        br#"{"mcp":{},"mcp":{}}"#.as_slice(),
        br#"{"mcp":{},"\u006dcp":{}}"#,
        br#"{"other":{"value":1,"value":2}}"#,
        br#"{"mcp":{"context-relay":{"command":["some-other-server"]}}}"#,
        br#"{"mcp":{"servers":{"context-relay":{"type":"local","command":["some-other-server"]}}}}"#,
        br#"{"mcp":[]}"#,
        br#"{"instructions":"AGENTS.md"}"#,
        br#"{"instructions":[1]}"#,
        br#"{"instructions":[".context-relay-opencode.md",".context-relay-opencode.md"]}"#,
        br#"{"instructions":[,]}"#,
        br#"{"mcp":{,}}"#,
        br#"{"mcp":{},,}"#,
        br#"{"mcp":{}, /* unterminated"#,
        b"{\"comment\":\"\xff\"}",
        b"{} trailing text",
        b"[]",
    ] {
        fs::write(fixture.root.join("opencode.jsonc"), original).unwrap();
        assert!(fixture.export().is_err(), "accepted {original:?}");
        assert_eq!(fs::read(fixture.root.join("opencode.jsonc")).unwrap(), original);
        assert!(!fixture.root.join(INSTRUCTION_FILE).exists());
    }
}

#[test]
fn json_extension_accepts_opencode_comments_and_trailing_commas_without_rewriting() {
    let fixture = Fixture::new();
    let original =
        b"{ // OpenCode parses both extensions as JSONC.\n \"instructions\": [\"AGENTS.md\",], }";
    fs::write(fixture.root.join("opencode.json"), original).unwrap();
    let exported = fixture.export().unwrap();
    assert!(
        exported
            .config_path
            .display
            .unwrap()
            .ends_with("opencode.json")
    );
    assert_eq!(
        fs::read(fixture.root.join("opencode.json")).unwrap(),
        original
    );
    assert!(!fixture.root.join(INSTRUCTION_FILE).exists());
}

#[test]
fn ambiguous_config_files_and_unowned_instruction_text_are_refused() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("opencode.json"), b"{}").unwrap();
    fs::write(fixture.root.join("opencode.jsonc"), b"{}").unwrap();
    assert!(fixture.export().is_err());
    fs::remove_file(fixture.root.join("opencode.jsonc")).unwrap();
    fs::write(
        fixture.root.join(INSTRUCTION_FILE),
        b"User-authored instructions",
    )
    .unwrap();
    assert!(fixture.export().is_err());
    assert_eq!(
        fs::read(fixture.root.join(INSTRUCTION_FILE)).unwrap(),
        b"User-authored instructions"
    );
}

#[test]
fn matching_existing_entry_can_be_exported_again_without_claiming_ownership() {
    let fixture = Fixture::new();
    let original = fixture.export().unwrap();
    fs::write(
        fixture.root.join("opencode.json"),
        &original.config_fragment,
    )
    .unwrap();
    fs::write(
        fixture.root.join(INSTRUCTION_FILE),
        &original.instruction_markdown,
    )
    .unwrap();
    assert_eq!(fixture.export().unwrap(), original);
    assert_eq!(
        fs::read_to_string(fixture.root.join("opencode.json")).unwrap(),
        original.config_fragment
    );
    let windows_text = format!("\u{feff}{}", INSTRUCTIONS.replace('\n', "\r\n"));
    fs::write(fixture.root.join(INSTRUCTION_FILE), &windows_text).unwrap();
    assert_eq!(fixture.export().unwrap(), original);
    assert_eq!(
        fs::read_to_string(fixture.root.join(INSTRUCTION_FILE)).unwrap(),
        windows_text
    );
}

#[test]
fn oversized_files_and_changed_bridge_attestation_are_refused() {
    let fixture = Fixture::new();
    fs::write(fixture.root.join("opencode.json"), vec![b' '; 262_145]).unwrap();
    assert!(fixture.export().is_err());
    fs::remove_file(fixture.root.join("opencode.json")).unwrap();
    fs::write(&fixture.bridge.path, b"changed executable fixture").unwrap();
    assert!(fixture.export().is_err());
}

#[cfg(unix)]
#[test]
fn project_config_links_and_expansion_tokens_are_refused() {
    let fixture = Fixture::new();
    let outside = fixture._directory.path().join("outside.json");
    fs::write(&outside, b"{}").unwrap();
    std::os::unix::fs::symlink(&outside, fixture.root.join("opencode.json")).unwrap();
    assert!(fixture.export().is_err());
    let expanded = fixture.root.join("{env:PROJECT}");
    fs::create_dir(&expanded).unwrap();
    assert!(project_export(PROJECT.parse().unwrap(), &expanded, &fixture.bridge).is_err());
    assert_eq!(fs::read(outside).unwrap(), b"{}");
}

#[test]
fn access_migration_preserves_existing_policies_and_adds_only_the_opencode_identity() {
    let connection = rusqlite::Connection::open_in_memory().unwrap();
    connection
        .execute_batch(include_str!("../migrations/0004_offline_workspace.sql"))
        .unwrap();
    for harness in ["claude_code", "codex", "hermes"] {
        connection
            .execute(
                "INSERT INTO harness_access VALUES (?1, ?2)",
                rusqlite::params![harness, b"{\"mode\":\"disabled\"}".as_slice()],
            )
            .unwrap();
    }
    connection
        .execute_batch(include_str!("../migrations/0049_opencode_access.sql"))
        .unwrap();
    for harness in ["claude_code", "codex", "hermes"] {
        let policy: Vec<u8> = connection
            .query_row(
                "SELECT payload_json FROM harness_access WHERE harness = ?1",
                [harness],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(policy, b"{\"mode\":\"disabled\"}");
    }
    connection
        .execute(
            "INSERT INTO harness_access VALUES ('opencode', ?1)",
            [b"{\"mode\":\"read_only\"}".as_slice()],
        )
        .unwrap();
    assert!(
        connection
            .execute(
                "INSERT INTO harness_access VALUES ('unknown', ?1)",
                [b"{}".as_slice()]
            )
            .is_err()
    );
}
