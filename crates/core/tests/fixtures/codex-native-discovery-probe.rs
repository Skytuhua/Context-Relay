#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() {
    let executable = std::env::current_exe().unwrap();
    let directory = executable.parent().unwrap();
    assert_eq!(std::env::args().skip(1).collect::<Vec<_>>(), ["--version"]);
    std::fs::write(directory.join("invoked"), b"native probe ran").unwrap();
    let version = std::fs::read_to_string(directory.join("version.txt")).unwrap();
    println!("codex-cli {version}");
}
