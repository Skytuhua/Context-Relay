use std::{
    io::Write,
    process::{Command, Output, Stdio},
};

#[test]
fn shell_exits_without_writing_mcp_stdout() {
    for harness in ["claude-code", "codex", "hermes"] {
        let output = command(&["--harness", harness]);
        assert!(output.status.success());
        assert_eq!(output.stdout, b"");
        assert_eq!(output.stderr, b"");
    }
}

#[test]
fn missing_repeated_and_unknown_bindings_exit_two_without_stdout() {
    for arguments in [
        vec![],
        vec!["--harness"],
        vec!["--harness", "codex", "--harness", "hermes"],
        vec!["--harness", "unknown"],
        vec!["--unknown", "codex"],
    ] {
        let output = command(&arguments);
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(output.stdout, b"");
    }
}

#[test]
fn every_stdout_line_is_one_compact_json_rpc_object() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_context-relay-context-mcp"))
        .args(["--harness", "claude-code"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":"list","method":"tools/list","params":{}}
"#,
        )
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(output.status.success());
    assert_eq!(output.stderr, b"");
    assert!(!output.stdout.is_empty());
    assert!(output.stdout.ends_with(b"\n"));
    for line in output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        assert!(!line.contains(&b'\r'));
        let value: serde_json::Value = serde_json::from_slice(line).unwrap();
        assert_eq!(value["jsonrpc"], "2.0");
        assert!(value.is_object());
    }
}

fn command(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_context-relay-context-mcp"))
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap()
}
