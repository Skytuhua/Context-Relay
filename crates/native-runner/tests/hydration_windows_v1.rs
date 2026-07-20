#![cfg(windows)]

use std::{fs, path::PathBuf, time::SystemTime};

use context_relay_native_runner::{
    HydrationFile, HydrationOutcome, StagePath, install_hydrated_closure,
};
use sha2::{Digest, Sha256};

#[test]
fn guarded_hydration_is_atomic_and_idempotent() {
    let workspace = scratch();
    let bytes = b"fixture".to_vec();
    let file = HydrationFile::new(
        StagePath::try_from("fixture/fixture.exe").unwrap(),
        bytes.clone(),
        Sha256::digest(&bytes).into(),
        true,
    )
    .unwrap();
    assert_eq!(
        install_hydrated_closure(
            &workspace,
            "windows-x86_64",
            [0x11; 32],
            [0x22; 16],
            vec![file],
        )
        .unwrap(),
        HydrationOutcome::Installed,
    );
    assert_eq!(
        fs::read(
            workspace
                .join("target/sidecars/windows-x86_64")
                .join("11".repeat(32))
                .join("fixture/fixture.exe"),
        )
        .unwrap(),
        bytes,
    );
    let replacement = b"replacement".to_vec();
    assert_eq!(
        install_hydrated_closure(
            &workspace,
            "windows-x86_64",
            [0x11; 32],
            [0x33; 16],
            vec![
                HydrationFile::new(
                    StagePath::try_from("fixture/fixture.exe").unwrap(),
                    replacement.clone(),
                    Sha256::digest(&replacement).into(),
                    true,
                )
                .unwrap()
            ],
        )
        .unwrap(),
        HydrationOutcome::AlreadyExists,
    );
    fs::remove_dir_all(workspace).unwrap();
}

fn scratch() -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "context-relay-hydration-integration-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    fs::create_dir(&root).unwrap();
    root
}
