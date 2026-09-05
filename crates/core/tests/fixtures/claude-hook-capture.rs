// Inert executable for the opt-in, pinned Claude CLI startup test. It does not
// connect to Context Relay or read any configuration, credentials, or transcript.
use std::io::Read as _;

fn main() {
    assert_eq!(
        std::env::args().skip(1).collect::<Vec<_>>(),
        ["--hook-event", "session-start", "--harness", "claude-code"]
    );
    let mut input = Vec::new();
    std::io::stdin().take(65_537).read_to_end(&mut input).unwrap();
    assert!(input.len() <= 65_536);
    let executable = std::env::current_exe().unwrap();
    std::fs::write(executable.with_file_name("hook-input.json"), input).unwrap();
}
