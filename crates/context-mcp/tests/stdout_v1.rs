use std::process::{Command, Stdio};

#[test]
fn shell_exits_without_writing_mcp_stdout() {
    let output = Command::new(env!("CARGO_BIN_EXE_context-relay-context-mcp"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(output.stdout, b"");
}
