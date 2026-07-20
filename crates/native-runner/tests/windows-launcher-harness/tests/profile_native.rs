#![cfg(windows)]

use std::{
    process,
    time::{SystemTime, UNIX_EPOCH},
};

use context_relay_windows_launcher_harness::windows::{
    CreateProfileOutcome, LaunchError, ProfileApi, ProfileIdentity, ProfileMoniker,
    Win32ProfileApi, cleanup_recovered_profile,
};
use sha2::{Digest, Sha256};

#[test]
fn recovered_profile_cleanup_accepts_only_exact_identity_and_deletes_idempotently() {
    let mut api = Win32ProfileApi::new();
    let moniker = unique_moniker();
    let derived = api.derive_identity(&moniker).unwrap();

    assert_eq!(
        api.create_profile(&derived).unwrap(),
        CreateProfileOutcome::Created
    );
    let guard = CleanupGuard(derived.clone());

    let folder = api.profile_folder(&derived).unwrap();
    assert!(folder.is_absolute());
    assert!(folder.exists());

    assert_eq!(
        api.create_profile(&derived).unwrap(),
        CreateProfileOutcome::AlreadyExists
    );
    let mismatched = ProfileIdentity::from_derived(moniker, "S-1-15-2-1").unwrap();
    assert_eq!(
        api.delete_profile(&mismatched),
        Err(LaunchError::ProfileIdentityMismatch)
    );
    for invalid_moniker in [
        "context-relay.native.00112233445566778899aabbccddeef",
        "context-relay.native.00112233445566778899AABBCCDDEEFF",
        "context-relay.native.00112233445566778899aabbccddeeff00",
        "C:\\context-relay.native.00112233445566778899aabbccddeeff",
    ] {
        assert_eq!(
            cleanup_recovered_profile(invalid_moniker, derived.sid()),
            Err(LaunchError::InvalidProfileIdentity)
        );
    }
    for invalid_sid in [
        "S-1-15-2-1",
        "S-1-15-2-01-2-3-4-5-6-7",
        "S-1-15-2-1-2-3-4-5-6-seven",
        "S-1-15-2-1-2-3-4-5-6-7-8",
    ] {
        assert_eq!(
            cleanup_recovered_profile(derived.moniker().as_str(), invalid_sid),
            Err(LaunchError::InvalidProfileIdentity)
        );
    }
    let different_sid = different_sid(derived.sid());
    assert_eq!(
        cleanup_recovered_profile(derived.moniker().as_str(), &different_sid),
        Err(LaunchError::ProfileIdentityMismatch),
        "{} -> {different_sid}",
        derived.sid()
    );
    assert!(folder.exists());
    cleanup_recovered_profile(derived.moniker().as_str(), derived.sid()).unwrap();
    cleanup_recovered_profile(derived.moniker().as_str(), derived.sid()).unwrap();
    std::mem::forget(guard);
}

fn different_sid(sid: &str) -> String {
    let (prefix, last) = sid.rsplit_once('-').unwrap();
    let last = last.parse::<u32>().unwrap();
    format!("{prefix}-{}", if last == u32::MAX { 0 } else { last + 1 })
}

struct CleanupGuard(ProfileIdentity);

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        let _ = Win32ProfileApi::new().delete_profile(&self.0);
    }
}

fn unique_moniker() -> ProfileMoniker {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let mut hasher = Sha256::new();
    hasher.update(process::id().to_le_bytes());
    hasher.update(now.to_le_bytes());
    hasher.update(
        std::thread::current()
            .name()
            .unwrap_or("unnamed")
            .as_bytes(),
    );
    let digest: [u8; 32] = hasher.finalize().into();
    ProfileMoniker::from_nonce(digest[..16].try_into().unwrap())
}
