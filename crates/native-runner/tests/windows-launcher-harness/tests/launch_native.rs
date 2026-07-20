#![cfg(windows)]

use std::{
    fs,
    os::windows::io::{FromRawHandle, OwnedHandle},
    process,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use context_relay_windows_launcher_harness::windows::{
    CreateProfileOutcome, LaunchSequence, ProfileApi, ProfileIdentity, ProfileMoniker,
    Win32LaunchBackend, Win32ProfileApi, Win32ProfileLayout,
};
use sha2::{Digest, Sha256};
use windows_sys::Win32::{
    Foundation::HANDLE, Security::SECURITY_ATTRIBUTES, System::Threading::CreateEventW,
};

#[test]
fn native_launch_is_suspended_attested_pipe_only_and_bounded() {
    let mut profiles = Win32ProfileApi::new();
    let identity = profiles.derive_identity(&unique_moniker()).unwrap();
    assert_eq!(
        profiles.create_profile(&identity).unwrap(),
        CreateProfileOutcome::Created
    );
    let profile_guard = ProfileCleanup(identity.clone());

    let layout =
        Win32ProfileLayout::initialize(profiles.profile_folder(&identity).unwrap()).unwrap();
    fs::copy(
        env!("CARGO_BIN_EXE_windows_sandbox_probe"),
        layout.helper_path(),
    )
    .unwrap();
    let digest: [u8; 32] = Sha256::digest(fs::read(layout.helper_path()).unwrap()).into();
    let canary = inheritable_event();
    let home_canary =
        std::path::PathBuf::from(std::env::var_os("USERPROFILE").unwrap()).join(format!(
            ".context-relay-sandbox-canary-{}.txt",
            identity.moniker().as_str()
        ));
    fs::write(&home_canary, b"REAL-HOME-CANARY").unwrap();
    let home_canary_guard = FileCleanup(home_canary.clone());
    let network_canary = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    network_canary.set_nonblocking(true).unwrap();
    let network_canary_address = network_canary.local_addr().unwrap();

    let backend = Win32LaunchBackend::prepare(&identity, layout, digest).unwrap();
    assert!(
        fs::OpenOptions::new()
            .write(true)
            .open(backend.helper_path())
            .is_err()
    );

    let suspended = LaunchSequence::for_identity(backend, &identity)
        .create_suspended()
        .unwrap();
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(suspended.peek_stdout().unwrap(), 0);
    assert!(
        !suspended
            .inherited_exact_handle(canary.as_raw_handle() as usize)
            .unwrap()
    );

    let bound = suspended.bind_kill_on_close_job().unwrap();
    let attested = bound.attest_zero_capability_token().unwrap();
    let mut running = attested.resume_once().unwrap();
    let output = running
        .exchange(
            format!(
                "DENY={}\nCONNECT={}\nPING\n",
                home_canary.display(),
                network_canary_address
            )
            .as_bytes(),
        )
        .unwrap();

    assert_eq!(output.exit_code(), 0);
    assert_eq!(output.stdout(), b"READY\nINPUT-OK\n");
    assert_eq!(output.stderr(), b"PROBE-ERR\n");
    assert!(matches!(
        network_canary.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
    let audit = running.audit();
    assert!(audit.created_suspended());
    assert!(audit.job_kill_on_close_verified());
    assert!(audit.job_membership_verified());
    assert!(audit.token_is_appcontainer());
    assert!(audit.token_sid_verified());
    assert_eq!(audit.token_capability_count(), 0);
    assert_eq!(audit.inherited_handle_count(), 3);
    assert!(audit.resumed_exactly_once());

    drop(running);
    drop(canary);
    drop(home_canary_guard);
    drop(profile_guard);
}

#[test]
fn closure_runtime_acl_denies_appcontainer_writes_and_allows_host_cleanup() {
    let mut profiles = Win32ProfileApi::new();
    let identity = profiles.derive_identity(&unique_moniker()).unwrap();
    assert_eq!(
        profiles.create_profile(&identity).unwrap(),
        CreateProfileOutcome::Created
    );
    let profile_guard = ProfileCleanup(identity.clone());

    let profile_folder = profiles.profile_folder(&identity).unwrap();
    let layout = Win32ProfileLayout::initialize(profile_folder.clone()).unwrap();
    fs::copy(
        env!("CARGO_BIN_EXE_windows_sandbox_probe"),
        layout.helper_path(),
    )
    .unwrap();
    let runtime = layout.root().join("closure/runtime");
    let nested = runtime.join("nested");
    fs::create_dir(&nested).unwrap();
    let pinned = nested.join("pinned.dll");
    fs::write(&pinned, b"pinned\n").unwrap();
    let digest: [u8; 32] = Sha256::digest(fs::read(layout.helper_path()).unwrap()).into();

    let backend = Win32LaunchBackend::prepare(&identity, layout, digest).unwrap();
    let inherited = nested.join("inherited.dll");
    fs::write(&inherited, b"inherited\n").unwrap();
    let mut running = LaunchSequence::for_identity(backend, &identity)
        .create_suspended()
        .unwrap()
        .bind_kill_on_close_job()
        .unwrap()
        .attest_zero_capability_token()
        .unwrap()
        .resume_once()
        .unwrap();
    let output = running.exchange(b"RUNTIME-SEAL\n").unwrap();

    assert_eq!(
        output.exit_code(),
        0,
        "{}",
        String::from_utf8_lossy(output.stderr())
    );
    assert_eq!(output.stdout(), b"READY\nRUNTIME-SEALED\n");
    assert_eq!(output.stderr(), b"");
    assert!(!runtime.join("root-attacker.dll").exists());
    assert!(!nested.join("attacker.dll").exists());

    drop(running);
    fs::write(&pinned, b"host-updated\n").unwrap();
    fs::write(&inherited, b"host-updated-inherited\n").unwrap();
    assert_eq!(fs::read(&pinned).unwrap(), b"host-updated\n");
    assert_eq!(fs::read(&inherited).unwrap(), b"host-updated-inherited\n");
    profiles.delete_profile(&identity).unwrap();
    assert!(!profile_folder.exists());
    drop(profile_guard);
}

struct FileCleanup(std::path::PathBuf);

impl Drop for FileCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

struct ProfileCleanup(ProfileIdentity);

impl Drop for ProfileCleanup {
    fn drop(&mut self) {
        let _ = Win32ProfileApi::new().delete_profile(&self.0);
    }
}

fn inheritable_event() -> OwnedHandle {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    let raw = unsafe { CreateEventW(&attributes, 1, 0, std::ptr::null()) };
    assert!(!raw.is_null());
    unsafe { OwnedHandle::from_raw_handle(raw as *mut _) }
}

trait RawHandleValue {
    fn as_raw_handle(&self) -> HANDLE;
}

impl RawHandleValue for OwnedHandle {
    fn as_raw_handle(&self) -> HANDLE {
        use std::os::windows::io::AsRawHandle;
        AsRawHandle::as_raw_handle(self) as HANDLE
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
    hasher.update(b"native-launch");
    let digest: [u8; 32] = hasher.finalize().into();
    ProfileMoniker::from_nonce(digest[..16].try_into().unwrap())
}
