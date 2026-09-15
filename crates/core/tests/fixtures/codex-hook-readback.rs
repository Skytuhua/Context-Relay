//! Inert stdio server for process containment and protocol regression tests.
use std::{
    fs,
    io::{self, BufRead, Write},
    process::{Command, Stdio},
    thread,
    time::Duration,
};

fn main() {
    if std::env::args().any(|arg| arg == "--hook-event") {
        fs::write(
            std::env::current_exe()
                .unwrap()
                .with_file_name("hook-executed"),
            b"hook was invoked",
        )
        .unwrap();
        return;
    }
    if std::env::args().any(|arg| arg == "--descendant") {
        fs::write("descendant-started", b"ready").unwrap();
        thread::sleep(Duration::from_millis(1500));
        fs::write("escaped", b"still running").unwrap();
        return;
    }
    let mode = fs::read_to_string("mode").unwrap();
    let mut descendant = if mode == "metadata" {
        None
    } else {
        let mut descendant = Command::new(std::env::current_exe().unwrap());
        descendant.arg("--descendant").stdin(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt as _;
            descendant.creation_flags(0x0800_0000);
        }
        let descendant = descendant.spawn().unwrap();
        while !std::path::Path::new("descendant-started").exists() {
            thread::sleep(Duration::from_millis(5));
        }
        Some(descendant)
    };
    if mode == "hang" {
        thread::sleep(Duration::from_secs(30));
    }
    if mode == "stdout" {
        io::stdout().write_all(&vec![b'x'; 300 * 1024]).unwrap();
    }
    if mode == "stderr" {
        io::stderr().write_all(&vec![b'x'; 300 * 1024]).unwrap();
    }
    let mut input = io::stdin().lock();
    let mut line = String::new();
    input.read_line(&mut line).unwrap();
    assert!(line.contains("initialize"));
    fs::write("requests", &line).unwrap();
    if mode == "malformed" {
        println!("invalid response");
    } else {
        println!("{{\"id\":1,\"result\":{{\"userAgent\":\"fixture\"}}}}");
        io::stdout().flush().unwrap();
        for method in ["initialized", "hooks/list"] {
            line.clear();
            input.read_line(&mut line).unwrap();
            assert!(line.contains(method));
            let mut log = fs::OpenOptions::new()
                .append(true)
                .open("requests")
                .unwrap();
            log.write_all(line.as_bytes()).unwrap();
        }
        println!("{}", fs::read_to_string("response").unwrap());
    }
    io::stdout().flush().unwrap();
    // Leave the descendant (and its inherited output pipes) alive when exiting.
    if let Some(descendant) = descendant.as_mut() {
        let _ = descendant.try_wait();
    }
}
