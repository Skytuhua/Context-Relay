#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() {
    let executable = std::env::current_exe().unwrap();
    let directory = executable.parent().unwrap();
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments == ["--context"] {
        for name in ["CODEX_HOME", "HOME", "USERPROFILE"] {
            println!("{name}={}", std::env::var(name).unwrap_or_default());
        }
        println!("cwd={}", std::env::current_dir().unwrap().display());
        return;
    }
    assert_eq!(arguments, ["--version"]);
    std::fs::write(directory.join("invoked"), b"native probe ran").unwrap();
    let version = std::fs::read_to_string(directory.join("version.txt")).unwrap();
    println!("codex-cli {version}");
}
