// Inert executable for the opt-in, pinned harness lifecycle tests. It does not
// connect to Context Relay or read any configuration, credentials, or transcript.
use std::io::Read as _;

fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    assert_eq!(arguments.len(), 4);
    assert_eq!(arguments[0], "--hook-event");
    assert_eq!(arguments[2], "--harness");
    assert!(matches!(arguments[3].as_str(), "claude-code" | "codex"));
    let output = match arguments[1].as_str() {
        "session-start" => "hook-input.json",
        "session-stop" => "hook-stop-input.json",
        _ => panic!("unexpected hook event"),
    };
    let mut input = Vec::new();
    std::io::stdin().take(65_537).read_to_end(&mut input).unwrap();
    assert!(input.len() <= 65_536);
    let executable = std::env::current_exe().unwrap();
    std::fs::write(executable.with_file_name(output), input).unwrap();
}
