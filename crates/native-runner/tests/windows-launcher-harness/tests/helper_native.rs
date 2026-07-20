#![cfg(windows)]

use std::{
    fs, process,
    time::{SystemTime, UNIX_EPOCH},
};

use context_relay_windows_launcher_harness::windows::{
    CreateProfileOutcome, LaunchError, ProfileApi, ProfileIdentity, ProfileMoniker,
    Win32LaunchBackend, Win32ProfileApi, Win32ProfileLayout,
};
use sha2::{Digest, Sha256};

#[test]
fn digest_mismatch_rejects_the_locked_helper_before_launch() {
    let (identity, layout, _guard) = fresh_layout(b"digest-mismatch");
    fs::copy(
        env!("CARGO_BIN_EXE_windows_sandbox_probe"),
        layout.helper_path(),
    )
    .unwrap();

    let result = Win32LaunchBackend::prepare(&identity, layout, [0x5a; 32]);
    assert!(matches!(result, Err(LaunchError::HelperDigestMismatch)));
}

#[test]
fn hardlinked_helper_is_rejected_even_when_its_digest_matches() {
    let (identity, layout, _guard) = fresh_layout(b"hardlink");
    let source = layout.root().join("hardlink-source.exe");
    fs::copy(env!("CARGO_BIN_EXE_windows_sandbox_probe"), &source).unwrap();
    fs::hard_link(&source, layout.helper_path()).unwrap();
    let digest: [u8; 32] = Sha256::digest(fs::read(&source).unwrap()).into();

    let result = Win32LaunchBackend::prepare(&identity, layout, digest);
    assert!(matches!(result, Err(LaunchError::LockedHelperRejected)));
}

fn fresh_layout(label: &[u8]) -> (ProfileIdentity, Win32ProfileLayout, ProfileCleanup) {
    let mut profiles = Win32ProfileApi::new();
    let identity = profiles.derive_identity(&unique_moniker(label)).unwrap();
    assert_eq!(
        profiles.create_profile(&identity).unwrap(),
        CreateProfileOutcome::Created
    );
    let layout =
        Win32ProfileLayout::initialize(profiles.profile_folder(&identity).unwrap()).unwrap();
    (identity.clone(), layout, ProfileCleanup(identity))
}

struct ProfileCleanup(ProfileIdentity);

impl Drop for ProfileCleanup {
    fn drop(&mut self) {
        let _ = Win32ProfileApi::new().delete_profile(&self.0);
    }
}

fn unique_moniker(label: &[u8]) -> ProfileMoniker {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let mut hasher = Sha256::new();
    hasher.update(process::id().to_le_bytes());
    hasher.update(now.to_le_bytes());
    hasher.update(label);
    let digest: [u8; 32] = hasher.finalize().into();
    ProfileMoniker::from_nonce(digest[..16].try_into().unwrap())
}
