#![cfg(windows)]

#[path = "../../core/src/test_windows_process.rs"]
mod test_windows_process;

use std::{
    fs,
    io::Read as _,
    os::windows::{
        io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle},
        process::CommandExt as _,
    },
    process::{Command, Stdio},
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::{ERROR_INVALID_PARAMETER, GetLastError, WAIT_OBJECT_0},
    System::Threading::{OpenProcess, WaitForSingleObject},
};

#[test]
fn owned_fixture_cleans_descendants_after_exit_and_timeout() {
    let fixture = tempfile::tempdir().unwrap();
    for mode in ["exit", "timeout"] {
        let pid_path = fixture.path().join(mode);
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["contained_child", "--exact", "--ignored"])
            .env("CONTEXT_RELAY_CONTAINMENT_MODE", mode)
            .env("CONTEXT_RELAY_CONTAINMENT_PID", &pid_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let result = test_windows_process::run_in_owned_job(&mut command, Duration::from_secs(5));
        if mode == "exit" {
            assert!(result.unwrap().success());
        } else {
            assert!(result.is_err());
        }
        let pid = fs::read_to_string(pid_path).unwrap().parse().unwrap();
        // SAFETY: request synchronization access only to this fixture's recorded child.
        let raw = unsafe { OpenProcess(0x0010_0000, 0, pid) };
        if raw.is_null() {
            // SAFETY: inspect the immediately preceding Win32 call's error.
            assert_eq!(unsafe { GetLastError() }, ERROR_INVALID_PARAMETER);
        } else {
            // SAFETY: OpenProcess returned a new owned handle.
            let child = unsafe { OwnedHandle::from_raw_handle(raw) };
            // SAFETY: synchronization handle is live for the duration of the wait.
            assert_eq!(
                unsafe { WaitForSingleObject(child.as_raw_handle(), 5000) },
                WAIT_OBJECT_0
            );
        }
    }
}

#[test]
#[ignore = "synthetic child of owned_fixture_cleans_descendants_after_exit_and_timeout"]
fn contained_child() {
    let mut gate = Vec::new();
    std::io::stdin().read_to_end(&mut gate).unwrap();
    assert_eq!(gate, b"run");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["sleeping_descendant", "--exact", "--ignored"])
        .creation_flags(0x0800_0000)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    fs::write(
        std::env::var_os("CONTEXT_RELAY_CONTAINMENT_PID").unwrap(),
        child.id().to_string(),
    )
    .unwrap();
    if std::env::var("CONTEXT_RELAY_CONTAINMENT_MODE").unwrap() == "exit" {
        std::process::exit(0);
    }
    child.wait().unwrap();
    panic!("the owning job should terminate this fixture before its sleeping child exits");
}

#[test]
#[ignore = "synthetic descendant confined by its grandparent's job"]
fn sleeping_descendant() {
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}
