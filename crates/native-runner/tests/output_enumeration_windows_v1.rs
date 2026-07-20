#![cfg(windows)]

use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use context_relay_native_runner::{
    PrivateStage, RunLimits, RunnerError, RuntimeTarget, SidecarCommand, StageDirectory,
};

static NEXT_SCRATCH: AtomicU64 = AtomicU64::new(0);

#[test]
fn output_enumeration_rejects_more_than_1024_empty_files() {
    let (stage, _scratch) = stage([0x31; 16]);
    let output = stage.layout().path(StageDirectory::Output);
    for index in 0..1_025 {
        fs::write(output.join(format!("file-{index:04}.txt")), []).unwrap();
    }

    assert_eq!(
        stage.read_outputs(RunLimits::for_command(&SidecarCommand::OsemgrepScanPackage)),
        Err(RunnerError::LimitExceeded)
    );
}

#[test]
fn output_enumeration_rejects_directory_only_fanout_at_the_same_hard_cap() {
    let (stage, _scratch) = stage([0x32; 16]);
    let output = stage.layout().path(StageDirectory::Output);
    for index in 0..1_025 {
        fs::create_dir(output.join(format!("directory-{index:04}"))).unwrap();
    }

    assert_eq!(
        stage.read_outputs(RunLimits::for_command(&SidecarCommand::OsemgrepScanPackage)),
        Err(RunnerError::LimitExceeded)
    );
}

#[test]
fn output_enumeration_enforces_per_file_and_aggregate_byte_caps() {
    let (per_file, _scratch) = stage([0x33; 16]);
    let output = per_file.layout().path(StageDirectory::Output);
    fs::write(output.join("oversized.txt"), b"12345").unwrap();
    let limits = RunLimits::for_command(&SidecarCommand::OsemgrepScanPackage)
        .tightened(1, 4, 4)
        .unwrap();
    assert_eq!(
        per_file.read_outputs(limits),
        Err(RunnerError::LimitExceeded)
    );

    let (aggregate, _scratch) = stage([0x34; 16]);
    let output = aggregate.layout().path(StageDirectory::Output);
    fs::write(output.join("first.txt"), b"1234").unwrap();
    fs::write(output.join("second.txt"), b"5678").unwrap();
    let limits = RunLimits::for_command(&SidecarCommand::OsemgrepScanPackage)
        .tightened(2, 4, 7)
        .unwrap();
    assert_eq!(
        aggregate.read_outputs(limits),
        Err(RunnerError::LimitExceeded)
    );
}

fn stage(nonce: [u8; 16]) -> (PrivateStage, Scratch) {
    let scratch = Scratch::new();
    let stage = PrivateStage::create(&scratch.0, nonce, RuntimeTarget::WindowsX86_64).unwrap();
    (stage, scratch)
}

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let id = NEXT_SCRATCH.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "context-relay-output-limits-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
