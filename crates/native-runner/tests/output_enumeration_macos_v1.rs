#![cfg(target_os = "macos")]

use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use context_relay_native_runner::{
    PrivateStage, RunLimits, RunnerError, RuntimeTarget, SidecarCommand, StageDirectory,
};

static NEXT_SCRATCH: AtomicU64 = AtomicU64::new(0);

#[test]
fn output_inventory_caps_file_and_directory_fanout_on_both_apfs_modes() {
    for parent in [std::env::temp_dir(), case_sensitive_apfs_root()] {
        let (files, _files_scratch) = stage(&parent, [0x41; 16], "files");
        let output = files.layout().path(StageDirectory::Output);
        for index in 0..1_025 {
            fs::write(output.join(format!("file-{index:04}.txt")), []).unwrap();
        }
        assert_eq!(
            files.read_outputs(RunLimits::for_command(&SidecarCommand::OsemgrepScanPackage)),
            Err(RunnerError::LimitExceeded)
        );

        let (directories, _directories_scratch) = stage(&parent, [0x42; 16], "directories");
        let output = directories.layout().path(StageDirectory::Output);
        for index in 0..1_025 {
            fs::create_dir(output.join(format!("directory-{index:04}"))).unwrap();
        }
        assert_eq!(
            directories.read_outputs(RunLimits::for_command(&SidecarCommand::OsemgrepScanPackage)),
            Err(RunnerError::LimitExceeded)
        );

        let (bytes, _bytes_scratch) = stage(&parent, [0x43; 16], "bytes");
        let output = bytes.layout().path(StageDirectory::Output);
        fs::write(output.join("first.txt"), b"1234").unwrap();
        fs::write(output.join("second.txt"), b"5678").unwrap();
        let limits = RunLimits::for_command(&SidecarCommand::OsemgrepScanPackage)
            .tightened(2, 4, 7)
            .unwrap();
        assert_eq!(bytes.read_outputs(limits), Err(RunnerError::LimitExceeded));
    }
}

fn stage(parent: &Path, nonce: [u8; 16], label: &str) -> (PrivateStage, Scratch) {
    let scratch = Scratch::new(parent, label);
    let stage = PrivateStage::create(&scratch.0, nonce, RuntimeTarget::MacosArm64).unwrap();
    (stage, scratch)
}

fn case_sensitive_apfs_root() -> PathBuf {
    let root = std::env::var_os("CONTEXT_RELAY_CASE_SENSITIVE_APFS_ROOT")
        .map(PathBuf::from)
        .expect("native CI must provide a case-sensitive APFS root");
    assert!(root.is_absolute());
    assert_eq!(root.canonicalize().unwrap(), root);
    root
}

struct Scratch(PathBuf);

impl Scratch {
    fn new(parent: &Path, label: &str) -> Self {
        let id = NEXT_SCRATCH.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!(
            "context-relay-output-limits-{}-{id}-{label}",
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
