use std::fs;

use context_relay_core::{
    codex::managed_mcp::CodexManagedMcpInput, native_transaction::model::CanonicalCliDeclaration,
};
#[cfg(any(windows, target_os = "macos"))]
use context_relay_native_runner::{NativeState, OsNativeFileSystem};
use context_relay_protocol::{HarnessId, Sha256Digest};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

struct Fixture {
    _root: tempfile::TempDir,
    command: String,
    declaration: CanonicalCliDeclaration,
    toml: String,
    readback: Value,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::Builder::new()
            .prefix("relay staged 測試 '")
            .tempdir()
            .unwrap();
        let bridge = root.path().join("bridge inert.exe");
        fs::write(&bridge, b"synthetic bridge data; never execute").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&bridge, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let command = fs::canonicalize(bridge)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let body = json!({"args": ["--harness", "codex"], "command": command, "type": "stdio"})
            .to_string();
        let declaration = CanonicalCliDeclaration {
            harness: HarnessId::Codex,
            server_name: "context-relay".into(),
            fingerprint: Sha256Digest(Sha256::digest(body.as_bytes()).into()),
            canonical_body: body,
        };
        // Shape observed from the official 0.144.6 empty-home add/get fixture.
        let toml = format!(
            "[mcp_servers.context-relay]\ncommand = {}\nargs = [\"--harness\", \"codex\"]\n",
            serde_json::to_string(&command).unwrap()
        );
        let readback = json!({
            "name": "context-relay", "enabled": true, "disabled_reason": null,
            "transport": {"type": "stdio", "command": command, "args": ["--harness", "codex"], "env": null, "env_vars": [], "cwd": null},
            "enabled_tools": null, "disabled_tools": null,
            "startup_timeout_sec": null, "tool_timeout_sec": null
        });
        Self {
            _root: root,
            command,
            declaration,
            toml,
            readback,
        }
    }

    fn input(&self) -> CodexManagedMcpInput {
        CodexManagedMcpInput::new(&self.declaration).unwrap()
    }

    #[cfg(any(windows, target_os = "macos"))]
    fn snapshot(&self, text: &str) -> NativeState {
        let path = self._root.path().join("live.toml");
        fs::write(&path, text).unwrap();
        OsNativeFileSystem::new()
            .snapshot(&path)
            .unwrap()
            .state()
            .clone()
    }
}

#[test]
fn generation_has_only_the_fixed_managed_add_arguments() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture.input().add_arguments(),
        vec![
            "mcp",
            "add",
            "context-relay",
            "--",
            &fixture.command,
            "--harness",
            "codex"
        ]
    );
}

#[test]
fn generation_rejects_noncanonical_or_tampered_inputs() {
    let fixture = Fixture::new();
    let mut cases = Vec::new();
    let mut wrong = fixture.declaration.clone();
    wrong.fingerprint = Sha256Digest([0; 32]);
    cases.push(wrong);
    let mut wrong = fixture.declaration.clone();
    wrong.server_name = "other".into();
    cases.push(wrong);
    let mut wrong = fixture.declaration.clone();
    wrong.harness = HarnessId::ClaudeCode;
    cases.push(wrong);
    for replacement in [
        json!("relative.exe"),
        json!("C:\\missing\\bridge.exe"),
        json!("x".repeat(70_000)),
    ] {
        let mut wrong = fixture.declaration.clone();
        let mut body: Value = serde_json::from_str(&wrong.canonical_body).unwrap();
        body["command"] = replacement;
        wrong.canonical_body = body.to_string();
        wrong.fingerprint = Sha256Digest(Sha256::digest(wrong.canonical_body.as_bytes()).into());
        cases.push(wrong);
    }
    for (key, value) in [
        ("env", json!({"SECRET": "canary"})),
        ("args", json!(["--harness", "codex", "--extra"])),
        ("url", json!("https://example.invalid")),
    ] {
        let mut wrong = fixture.declaration.clone();
        let mut body: Value = serde_json::from_str(&wrong.canonical_body).unwrap();
        body[key] = value;
        wrong.canonical_body = body.to_string();
        wrong.fingerprint = Sha256Digest(Sha256::digest(wrong.canonical_body.as_bytes()).into());
        cases.push(wrong);
    }
    for wrong in cases {
        assert!(CodexManagedMcpInput::new(&wrong).is_err());
    }
}

#[test]
fn output_must_contain_only_the_expected_managed_item_and_matching_readback() {
    let fixture = Fixture::new();
    let input = fixture.input();
    let readback = fixture.readback.to_string();
    assert!(
        input
            .validate_output(fixture.toml.as_bytes(), readback.as_bytes())
            .is_ok()
    );
    for config in [
        format!("model = 'foreign'\n{}", fixture.toml),
        format!("{}env = {{ SECRET = 'canary' }}\n", fixture.toml),
        format!("{}[mcp_servers.other]\ncommand = 'foreign'\n", fixture.toml),
        fixture.toml.replace("\"codex\"", "\"other\""),
        fixture.toml.replace("command =", "unknown ="),
        "#".repeat(65_537),
    ] {
        assert!(
            input
                .validate_output(config.as_bytes(), readback.as_bytes())
                .is_err()
        );
    }
    for (key, value) in [
        ("enabled", json!(false)),
        ("name", json!("other")),
        ("enabled_tools", json!([])),
        ("extra", json!(null)),
    ] {
        let mut output = fixture.readback.clone();
        output[key] = value;
        assert!(
            input
                .validate_output(fixture.toml.as_bytes(), output.to_string().as_bytes())
                .is_err()
        );
    }
    for (key, value) in [
        ("command", json!("foreign")),
        ("args", json!(["--harness", "other"])),
        ("env", json!({"SECRET": "canary"})),
        ("cwd", json!("foreign")),
    ] {
        let mut output = fixture.readback.clone();
        output["transport"][key] = value;
        assert!(
            input
                .validate_output(fixture.toml.as_bytes(), output.to_string().as_bytes())
                .is_err()
        );
    }
    let duplicate = readback.replacen('{', "{\"enabled\":false,", 1);
    assert!(
        input
            .validate_output(fixture.toml.as_bytes(), duplicate.as_bytes())
            .is_err()
    );
    let duplicate_transport =
        readback.replace("\"transport\":{", "\"transport\":{\"command\":\"foreign\",");
    assert!(
        input
            .validate_output(fixture.toml.as_bytes(), duplicate_transport.as_bytes())
            .is_err()
    );
    for invalid in [vec![0xff], vec![b' '; 65_537], b"{}".to_vec()] {
        assert!(
            input
                .validate_output(fixture.toml.as_bytes(), &invalid)
                .is_err()
        );
        assert!(
            input
                .validate_output(&invalid, readback.as_bytes())
                .is_err()
        );
    }
    let mut missing = fixture.readback.clone();
    missing.as_object_mut().unwrap().remove("disabled_reason");
    assert!(
        input
            .validate_output(fixture.toml.as_bytes(), missing.to_string().as_bytes())
            .is_err()
    );
}

#[cfg(any(windows, target_os = "macos"))]
#[test]
fn first_connection_creates_an_ordinary_mcp_table_and_is_idempotent() {
    let fixture = Fixture::new();
    let item = fixture
        .input()
        .validate_output(
            fixture.toml.as_bytes(),
            fixture.readback.to_string().as_bytes(),
        )
        .unwrap();
    for text in [
        "",
        "# no MCP servers yet\nmodel = 'keep'\n\n[projects.'my project']\ntrust_level = 'trusted'\n",
    ] {
        let merged = item.merge_into(&fixture.snapshot(text)).unwrap();
        let NativeState::RegularFile { bytes, .. } = &merged else {
            panic!("expected regular file")
        };
        let parsed: toml_edit::DocumentMut = std::str::from_utf8(bytes).unwrap().parse().unwrap();
        assert!(
            parsed["mcp_servers"].as_table().is_some(),
            "the adapter requires an ordinary MCP table"
        );
        assert_eq!(
            parsed["mcp_servers"]["context-relay"]["command"].as_str(),
            Some(fixture.command.as_str())
        );
        assert_eq!(item.merge_into(&merged).unwrap(), merged);
    }
}

#[cfg(any(windows, target_os = "macos"))]
#[test]
fn merge_supports_empty_and_inline_memory_and_retains_existing_bridge_comments() {
    let fixture = Fixture::new();
    let item = fixture
        .input()
        .validate_output(
            fixture.toml.as_bytes(),
            fixture.readback.to_string().as_bytes(),
        )
        .unwrap();
    for memory in [
        "",
        "memories = { use_memories = true, unrelated = 'retain' } # inline\n",
        "[memories]\nuse_memories = false # already disabled\n",
    ] {
        let text = format!(
            "{memory}\n{}",
            fixture
                .toml
                .replace("command =", "# my bridge comment\ncommand =")
        );
        let original = fixture.snapshot(&text);
        let merged = item.merge_into(&original).unwrap();
        let NativeState::RegularFile { bytes, .. } = &merged else {
            panic!("expected file")
        };
        let rendered = std::str::from_utf8(bytes).unwrap();
        assert!(rendered.contains("# my bridge comment\ncommand ="));
        if memory.contains("unrelated") {
            assert!(rendered.contains("unrelated = 'retain'"));
            assert!(rendered.contains("# inline"));
        }
        let document: toml_edit::DocumentMut = rendered.parse().unwrap();
        assert_eq!(document["memories"]["use_memories"].as_bool(), Some(false));
        assert_eq!(
            document["memories"]["generate_memories"].as_bool(),
            Some(false)
        );
        assert_eq!(item.merge_into(&merged).unwrap(), merged);
    }
}

#[cfg(any(windows, target_os = "macos"))]
#[test]
fn one_merge_preserves_live_metadata_comments_and_unrelated_secrets() {
    let fixture = Fixture::new();
    let original_text = "# user comment\nmodel = 'keep-me'\n\n[memories]\ngenerate_memories = true # remember this comment\nuse_memories = true\n\n[mcp_servers.other]\ncommand = 'foreign'\nenv = { SECRET = 'host-only-canary' }\n\n[projects.'project with spaces']\ntrust_level = 'trusted'\n";
    let original = fixture.snapshot(original_text);
    let item = fixture
        .input()
        .validate_output(
            fixture.toml.as_bytes(),
            fixture.readback.to_string().as_bytes(),
        )
        .unwrap();
    let merged = item.merge_into(&original).unwrap();
    let NativeState::RegularFile { bytes, metadata } = &merged else {
        panic!("expected regular file")
    };
    let NativeState::RegularFile {
        metadata: prior_metadata,
        ..
    } = &original
    else {
        panic!("expected original regular file")
    };
    assert_eq!(metadata, prior_metadata);
    let text = std::str::from_utf8(bytes).unwrap();
    for retained in [
        "# user comment\nmodel = 'keep-me'",
        "generate_memories = false # remember this comment",
        "command = 'foreign'\nenv = { SECRET = 'host-only-canary' }",
        "[projects.'project with spaces']\ntrust_level = 'trusted'",
    ] {
        assert!(
            text.contains(retained),
            "missing preserved text: {retained}"
        );
    }
    let parsed: toml_edit::DocumentMut = text.parse().unwrap();
    assert_eq!(
        parsed["mcp_servers"]["context-relay"]["command"].as_str(),
        Some(fixture.command.as_str())
    );
    assert_eq!(parsed["memories"]["use_memories"].as_bool(), Some(false));
    assert_eq!(item.merge_into(&merged).unwrap(), merged);
    assert_eq!(
        fs::read_to_string(fixture._root.path().join("live.toml")).unwrap(),
        original_text
    );
    assert!(!format!("{:?}", fixture.input().add_arguments()).contains("host-only-canary"));
}

#[cfg(any(windows, target_os = "macos"))]
#[test]
fn merge_rejects_foreign_bridge_and_malformed_memory_without_changing_source() {
    let fixture = Fixture::new();
    let item = fixture
        .input()
        .validate_output(
            fixture.toml.as_bytes(),
            fixture.readback.to_string().as_bytes(),
        )
        .unwrap();
    for text in [
        "[mcp_servers.context-relay]\ncommand='foreign'\n",
        "memories = false\n",
        "[memories]\nuse_memories='true'\n",
        "mcp_servers = false\n",
        "[mcp_servers.context-relay]\nenabled = false\n",
        "[[memories]]\nuse_memories=true\n",
    ] {
        let original = fixture.snapshot(text);
        assert!(item.merge_into(&original).is_err());
        assert_eq!(
            fs::read_to_string(fixture._root.path().join("live.toml")).unwrap(),
            text
        );
    }
    assert!(item.merge_into(&NativeState::absent(0, 1)).is_err());
}
