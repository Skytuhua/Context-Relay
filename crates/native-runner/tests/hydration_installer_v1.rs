#![cfg(any(windows, target_os = "macos"))]

use std::{
    fs,
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
    time::SystemTime,
};

#[test]
fn installer_rejects_truncated_and_digest_mismatched_frames_before_mutation() {
    let binary = env!("CARGO_BIN_EXE_context-relay-sidecar-installer");
    let mut truncated = Command::new(binary)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    truncated.stdin.take().unwrap().write_all(b"CRHY").unwrap();
    let truncated = truncated.wait_with_output().unwrap();
    assert!(!truncated.status.success());
    assert!(truncated.stdout.is_empty());

    let workspace = scratch();
    let workspace_bytes = workspace.to_str().unwrap().as_bytes();
    let target = if cfg!(windows) {
        b"windows-x86_64".as_slice()
    } else {
        b"macos-aarch64".as_slice()
    };
    let path = b"fixture/fixture.exe";
    let payload = b"fixture";
    let mut frame = Vec::new();
    frame.extend_from_slice(b"CRHYDR1\0");
    frame.extend_from_slice(&(workspace_bytes.len() as u32).to_le_bytes());
    frame.extend_from_slice(workspace_bytes);
    frame.extend_from_slice(&(target.len() as u16).to_le_bytes());
    frame.extend_from_slice(target);
    frame.extend_from_slice(&[0x11; 32]);
    frame.extend_from_slice(&[0x22; 16]);
    frame.extend_from_slice(&1_u16.to_le_bytes());
    frame.extend_from_slice(&(path.len() as u16).to_le_bytes());
    frame.extend_from_slice(path);
    frame.push(1);
    frame.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    frame.extend_from_slice(&[0; 32]);
    frame.extend_from_slice(payload);

    let mut mismatch = Command::new(binary)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    mismatch.stdin.take().unwrap().write_all(&frame).unwrap();
    let mismatch = mismatch.wait_with_output().unwrap();
    assert!(!mismatch.status.success());
    assert!(mismatch.stdout.is_empty());
    assert_eq!(fs::read_dir(&workspace).unwrap().count(), 0);
    fs::remove_dir(workspace).unwrap();
}

fn scratch() -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "context-relay-installer-frame-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    fs::create_dir(&root).unwrap();
    root
}
