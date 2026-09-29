// Standalone executable for proving that registration verification never starts
// a harness, including an unchanged approved executable or a PATH replacement.
fn main() {
    let marker = std::env::var_os("CONTEXT_RELAY_TEST_WATCH_MARKER")
        .unwrap_or_else(|| env!("CONTEXT_RELAY_TEST_WATCH_FALLBACK").into());
    std::fs::write(marker, b"harness was launched\n").unwrap();
    let executable = std::env::current_exe().unwrap();
    match executable.file_stem().unwrap().to_str().unwrap() {
        "claude" => println!("9.9.9 (Claude Code)"),
        "codex" => println!("codex-cli 9.9.9"),
        _ => println!("Hermes 9.9.9"),
    }
}
