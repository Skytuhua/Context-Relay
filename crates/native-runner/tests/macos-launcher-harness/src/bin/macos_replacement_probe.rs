#[cfg(target_os = "macos")]
use std::{fs, io::Read};

#[cfg(target_os = "macos")]
fn main() {
    let executable = std::env::current_exe().unwrap();
    let bundle = executable.ancestors().nth(3).unwrap();
    fs::write(bundle.join("replacement-ran"), b"replacement executed\n").unwrap();

    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).unwrap();
}

#[cfg(not(target_os = "macos"))]
fn main() {}
