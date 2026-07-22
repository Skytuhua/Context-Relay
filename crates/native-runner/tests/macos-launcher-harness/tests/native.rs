#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CStr,
    fs::{self, File},
    os::{
        fd::AsRawFd,
        unix::{ffi::OsStrExt, fs::PermissionsExt},
    },
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use context_relay_macos_launcher_harness::{
    model::{GenerationId, GenerationState, MacPolicyError, MacRootIdentity},
    native::{
        MacGenerationSpec, MacRecoveryCleanup, MacRecoveryIdentity, MacRecoveryOutcome,
        MacSourceMaterial, cleanup_recovered_generation, prepare_generation,
    },
    policy::{
        EntitlementSubject, EntitlementValue, GenerationJournal, SignedGeneration,
        execute_generation,
    },
};
use sha2::{Digest, Sha256};

#[test]
fn signed_generation_inspects_the_actual_inside_out_macho_closure() {
    let fixture = Fixture::new();
    let journal = MemoryJournal::default();
    let prepared =
        prepare_generation(fixture.spec(b"PING\n", Duration::from_secs(2)), &journal).unwrap();

    assert_ne!(prepared.signed_generation().sha256(), &[0; 32]);
    assert_eq!(
        prepared.signed_generation().bundle_identity(),
        &root_identity(prepared.bundle_path())
    );
    assert_eq!(prepared.inspections().len(), 2);
    assert_eq!(prepared.runtime_materials().len(), 1);
    let runtime_material = &prepared.runtime_materials()[0];
    let runtime_child = prepared
        .bundle_path()
        .join("Contents/Helpers/runtime/probe-child");
    assert_eq!(runtime_material.relative_path(), "probe-child");
    assert_eq!(runtime_material.size(), fs::metadata(&runtime_child).unwrap().len());
    assert_eq!(runtime_material.sha256(), &digest(&runtime_child));
    assert_ne!(runtime_material.sha256(), &digest(&fixture.child));
    assert!(runtime_material.executable());
    assert!(prepared.inspections().iter().any(|item| {
        item.subject == EntitlementSubject::Helper
            && item.entitlements
                == [(
                    "com.apple.security.app-sandbox".into(),
                    EntitlementValue::Boolean(true),
                )]
    }));
    assert!(prepared.inspections().iter().any(|item| {
        item.subject == EntitlementSubject::Sidecar
            && item.entitlements
                == [
                    (
                        "com.apple.security.app-sandbox".into(),
                        EntitlementValue::Boolean(true),
                    ),
                    (
                        "com.apple.security.inherit".into(),
                        EntitlementValue::Boolean(true),
                    ),
                ]
    }));
}

#[test]
fn launch_rejects_a_same_name_bundle_replacement_before_code_or_input() {
    let fixture = Fixture::new();
    let journal = MemoryJournal::default();
    let prepared =
        prepare_generation(fixture.spec(b"PING\n", Duration::from_secs(2)), &journal).unwrap();
    let signed = prepared.signed_generation().clone();
    let bundle = prepared.bundle_path().to_path_buf();
    let moved = fixture.root.join("approved-moved.app");
    fs::rename(&bundle, &moved).unwrap();
    let marker = bundle.join("replacement-ran");

    let replacement_helper = bundle.join("Contents/MacOS/context-relay-native-helper");
    fs::create_dir_all(replacement_helper.parent().unwrap()).unwrap();
    fs::copy(
        env!("CARGO_BIN_EXE_macos_replacement_probe"),
        &replacement_helper,
    )
    .unwrap();
    sign_empty(&replacement_helper);

    let mut process = prepared.into_process();
    assert!(execute_generation(&journal, &signed, &mut process).is_err());
    assert!(
        !marker.exists(),
        "the replacement helper reached its first user-space instruction"
    );

    fs::remove_dir_all(&bundle).unwrap();
    fs::rename(&moved, &bundle).unwrap();
    make_tree_mutable(&bundle);
    fs::remove_dir_all(bundle).unwrap();
}

#[test]
fn runtime_denies_real_home_loopback_inherited_fd_and_env_but_allows_fake_home() {
    let fixture = Fixture::new();
    let canary = PathBuf::from(std::env::var_os("HOME").unwrap()).join(format!(
        ".context-relay-real-home-canary-{}",
        fixture.suffix
    ));
    fs::write(&canary, b"REAL HOME").unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let inherited = File::open(&canary).unwrap();
    assert_eq!(
        unsafe { libc::fcntl(inherited.as_raw_fd(), libc::F_SETFD, 0) },
        0
    );
    let input = format!(
        "CANARY={}\nADDRESS={}\nFD={}\n",
        canary.display(),
        listener.local_addr().unwrap(),
        inherited.as_raw_fd(),
    );
    let journal = MemoryJournal::default();
    let prepared = prepare_generation(
        fixture.spec(input.as_bytes(), Duration::from_secs(5)),
        &journal,
    )
    .unwrap();
    let bundle = prepared.bundle_path().to_path_buf();
    let signed = prepared.signed_generation().clone();
    let container = account_home()
        .join("Library/Containers")
        .join(signed.id().as_str());
    let mut process = prepared.into_process();
    let output = execute_generation(&journal, &signed, &mut process).unwrap();

    assert_eq!(output.exit_code(), 0);
    assert_eq!(
        String::from_utf8(output.stdout().to_vec()).unwrap(),
        "REAL_HOME_DENIED=1\nLOOPBACK_DENIED=1\nFD_DENIED=1\nENV_DENIED=1\nFAKE_HOME_WRITE=1\nCHILD_DENIED=1\n"
    );
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
    assert_eq!(
        journal.events.lock().unwrap().as_slice(),
        [
            "reserved",
            "guardian_bound",
            "bundle_bound",
            "finalized",
            "container_bound",
            "active",
            "retired",
        ]
    );
    assert!(!bundle.exists());
    assert!(!container.exists());
    let _ = fs::remove_file(canary);
}

#[test]
fn recovery_cleanup_is_stateless_exact_idempotent_and_never_accepts_active() {
    let fixture = Fixture::new();
    let journal = MemoryJournal::default();
    let prepared =
        prepare_generation(fixture.spec(b"PING\n", Duration::from_secs(2)), &journal).unwrap();
    let bundle = prepared.bundle_path().to_path_buf();
    let bundle_id = prepared.signed_generation().id().as_str().to_owned();
    let suffix = bundle_id.rsplit_once('.').unwrap().1;
    let container = account_home().join("Library/Containers").join(&bundle_id);
    let sibling_container = container.with_file_name(format!("{bundle_id}-sibling"));
    let sibling_marker = sibling_container.join("sentinel");
    fs::create_dir_all(container.join("Data/nested")).unwrap();
    fs::create_dir_all(&sibling_container).unwrap();
    fs::write(&sibling_marker, b"keep").unwrap();
    fs::write(container.join("Data/nested/secret"), b"remove").unwrap();
    std::os::unix::fs::symlink(&sibling_marker, container.join("Data/sibling-link")).unwrap();
    let bundle_identity = root_identity(&bundle);
    let container_identity = root_identity(&container);
    let alias = fixture
        .root
        .with_file_name(format!("alias-{}", fixture.suffix));
    std::os::unix::fs::symlink(&fixture.root, &alias).unwrap();
    assert_eq!(
        cleanup_recovered_generation(
            &alias,
            &recovery_identity(
                suffix,
                &bundle_id,
                Some(i32::MAX),
                Some(&bundle_identity),
                Some(&container_identity),
            ),
            GenerationState::Poisoned,
            MacRecoveryOutcome::Restored,
        ),
        Ok(MacRecoveryCleanup::Conflict)
    );
    assert!(bundle.exists());
    fs::remove_file(alias).unwrap();

    assert_eq!(
        cleanup_recovered_generation(
            &fixture.root,
            &recovery_identity(suffix, &bundle_id, None, None, None),
            GenerationState::Poisoned,
            MacRecoveryOutcome::Restored,
        ),
        Ok(MacRecoveryCleanup::Conflict)
    );
    assert!(bundle.exists());
    assert!(container.exists());

    let moved_container = container.with_file_name(format!("{bundle_id}-moved"));
    fs::rename(&container, &moved_container).unwrap();
    fs::create_dir(&container).unwrap();
    fs::write(container.join("replacement"), b"keep").unwrap();
    fs::set_permissions(&container, fs::Permissions::from_mode(0o000)).unwrap();
    assert_eq!(
        cleanup_recovered_generation(
            &fixture.root,
            &recovery_identity(
                suffix,
                &bundle_id,
                Some(i32::MAX),
                Some(&bundle_identity),
                Some(&container_identity),
            ),
            GenerationState::Poisoned,
            MacRecoveryOutcome::Restored,
        ),
        Ok(MacRecoveryCleanup::Conflict)
    );
    fs::set_permissions(&container, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(bundle.exists());
    assert_eq!(fs::read(container.join("replacement")).unwrap(), b"keep");
    fs::remove_dir_all(&container).unwrap();
    fs::rename(&moved_container, &container).unwrap();

    let moved_bundle = fixture.root.join("recorded-moved.app");
    fs::rename(&bundle, &moved_bundle).unwrap();
    fs::create_dir(&bundle).unwrap();
    fs::write(bundle.join("replacement"), b"keep").unwrap();
    assert_eq!(
        cleanup_recovered_generation(
            &fixture.root,
            &recovery_identity(
                suffix,
                &bundle_id,
                Some(i32::MAX),
                Some(&bundle_identity),
                Some(&container_identity),
            ),
            GenerationState::Poisoned,
            MacRecoveryOutcome::Restored,
        ),
        Ok(MacRecoveryCleanup::Conflict)
    );
    assert_eq!(fs::read(bundle.join("replacement")).unwrap(), b"keep");
    assert!(container.exists());
    fs::remove_dir_all(&bundle).unwrap();
    fs::rename(&moved_bundle, &bundle).unwrap();

    let sibling = fixture
        .root
        .with_file_name(format!("macos-launcher-sibling-{}", fixture.suffix));
    fs::create_dir(&sibling).unwrap();
    fs::set_permissions(&sibling, fs::Permissions::from_mode(0o700)).unwrap();
    let sibling_marker = sibling.join(format!("{bundle_id}.app"));
    fs::create_dir(&sibling_marker).unwrap();

    for state in [GenerationState::Prepared, GenerationState::Active] {
        assert_eq!(
            cleanup_recovered_generation(
                &fixture.root,
                &recovery_identity(
                    suffix,
                    &bundle_id,
                    Some(i32::MAX),
                    Some(&bundle_identity),
                    Some(&container_identity),
                ),
                state,
                MacRecoveryOutcome::Restored,
            )
            .unwrap_err(),
            MacPolicyError::InvalidTransition
        );
        assert!(bundle.exists());
        assert!(container.exists());
    }
    assert_eq!(
        cleanup_recovered_generation(
            &fixture.root,
            &recovery_identity(
                suffix,
                &bundle_id,
                Some(i32::MAX),
                Some(&bundle_identity),
                Some(&container_identity),
            ),
            GenerationState::Poisoned,
            MacRecoveryOutcome::Restored,
        ),
        Ok(MacRecoveryCleanup::Cleaned)
    );
    assert_eq!(
        cleanup_recovered_generation(
            &fixture.root,
            &recovery_identity(
                suffix,
                &bundle_id,
                Some(i32::MAX),
                Some(&bundle_identity),
                Some(&container_identity),
            ),
            GenerationState::Poisoned,
            MacRecoveryOutcome::Restored,
        ),
        Ok(MacRecoveryCleanup::Conflict)
    );
    assert!(!bundle.exists());
    assert!(!container.exists());
    assert!(sibling_marker.exists());
    assert!(
        cleanup_recovered_generation(
            &fixture.root,
            &recovery_identity(
                &"0".repeat(32),
                &bundle_id,
                Some(i32::MAX),
                Some(&bundle_identity),
                Some(&container_identity),
            ),
            GenerationState::Poisoned,
            MacRecoveryOutcome::Restored,
        )
        .is_err()
    );
    fs::remove_dir_all(sibling).unwrap();
    fs::remove_dir_all(sibling_container).unwrap();
}

#[test]
fn recovery_observes_a_live_or_reused_group_without_signaling_it() {
    let fixture = Fixture::new();
    let journal = MemoryJournal::default();
    let prepared =
        prepare_generation(fixture.spec(b"PING\n", Duration::from_secs(2)), &journal).unwrap();
    let bundle = prepared.bundle_path().to_path_buf();
    let bundle_id = prepared.signed_generation().id().as_str().to_owned();
    let suffix = bundle_id.rsplit_once('.').unwrap().1;
    let container = account_home().join("Library/Containers").join(&bundle_id);
    fs::create_dir_all(&container).unwrap();
    fs::set_permissions(&container, fs::Permissions::from_mode(0o700)).unwrap();
    let bundle_identity = root_identity(&bundle);
    let container_identity = root_identity(&container);

    let group = unsafe { libc::fork() };
    if group == 0 {
        unsafe {
            if libc::setpgid(0, 0) != 0 {
                libc::_exit(126);
            }
            loop {
                libc::pause();
            }
        }
    }
    assert!(group > 0);
    let ready_deadline = Instant::now() + Duration::from_secs(2);
    while unsafe { libc::getpgid(group) } != group {
        assert!(Instant::now() < ready_deadline);
        std::thread::sleep(Duration::from_millis(1));
    }

    assert_eq!(
        cleanup_recovered_generation(
            &fixture.root,
            &recovery_identity(
                suffix,
                &bundle_id,
                Some(group),
                Some(&bundle_identity),
                Some(&container_identity),
            ),
            GenerationState::Poisoned,
            MacRecoveryOutcome::Restored,
        ),
        Ok(MacRecoveryCleanup::Conflict)
    );
    assert_eq!(unsafe { libc::kill(group, 0) }, 0);
    assert!(bundle.exists());
    assert!(container.exists());

    assert_eq!(unsafe { libc::kill(group, libc::SIGKILL) }, 0);
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(group, &mut status, 0) }, group);
    assert_eq!(
        cleanup_recovered_generation(
            &fixture.root,
            &recovery_identity(
                suffix,
                &bundle_id,
                Some(group),
                Some(&bundle_identity),
                Some(&container_identity),
            ),
            GenerationState::Poisoned,
            MacRecoveryOutcome::Restored,
        ),
        Ok(MacRecoveryCleanup::Cleaned)
    );
}

#[test]
fn recovery_cleanup_resumes_after_owned_root_chmod_and_partial_unlink() {
    let fixture = Fixture::new();
    let journal = MemoryJournal::default();
    let prepared =
        prepare_generation(fixture.spec(b"PING\n", Duration::from_secs(2)), &journal).unwrap();
    let bundle = prepared.bundle_path().to_path_buf();
    let bundle_id = prepared.signed_generation().id().as_str().to_owned();
    let suffix = bundle_id.rsplit_once('.').unwrap().1;
    let container = account_home().join("Library/Containers").join(&bundle_id);
    fs::create_dir_all(container.join("Data/nested")).unwrap();
    fs::set_permissions(&container, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(container.join("Data/nested/first"), b"remove").unwrap();
    fs::write(container.join("Data/nested/second"), b"remove").unwrap();
    let bundle_identity = root_identity(&bundle);
    let container_identity = root_identity(&container);

    make_tree_mutable(&bundle);
    fs::remove_file(bundle.join("Contents/Resources/helper.entitlements.plist")).unwrap();
    fs::remove_file(container.join("Data/nested/first")).unwrap();

    for path in [
        container.join("Data/nested/second"),
        container.join("Data/nested"),
        container.clone(),
        bundle.clone(),
    ] {
        let file = File::open(&path).unwrap();
        assert_eq!(unsafe { libc::fchmod(file.as_raw_fd(), 0) }, 0);
        assert_eq!(
            unsafe { libc::fchflags(file.as_raw_fd(), libc::UF_IMMUTABLE) },
            0
        );
    }

    assert_eq!(
        cleanup_recovered_generation(
            &fixture.root,
            &recovery_identity(
                suffix,
                &bundle_id,
                Some(i32::MAX),
                Some(&bundle_identity),
                Some(&container_identity),
            ),
            GenerationState::Poisoned,
            MacRecoveryOutcome::Restored,
        ),
        Ok(MacRecoveryCleanup::Cleaned)
    );
    assert!(!bundle.exists());
    assert!(!container.exists());
}

#[test]
fn recovery_cleanup_normalizes_exact_root_modes_excluded_from_identity() {
    let fixture = Fixture::new();
    let journal = MemoryJournal::default();
    let prepared =
        prepare_generation(fixture.spec(b"PING\n", Duration::from_secs(2)), &journal).unwrap();
    let bundle = prepared.bundle_path().to_path_buf();
    let bundle_id = prepared.signed_generation().id().as_str().to_owned();
    let suffix = bundle_id.rsplit_once('.').unwrap().1;
    let container = account_home().join("Library/Containers").join(&bundle_id);
    fs::create_dir_all(&container).unwrap();
    fs::set_permissions(&container, fs::Permissions::from_mode(0o700)).unwrap();
    let bundle_identity = root_identity(&bundle);
    let container_identity = root_identity(&container);

    let bundle_file = File::open(&bundle).unwrap();
    let container_file = File::open(&container).unwrap();
    assert_eq!(unsafe { libc::fchflags(bundle_file.as_raw_fd(), 0) }, 0);
    assert_eq!(unsafe { libc::fchflags(container_file.as_raw_fd(), 0) }, 0);
    assert_eq!(unsafe { libc::fchmod(bundle_file.as_raw_fd(), 0o100) }, 0);
    assert_eq!(unsafe { libc::fchmod(container_file.as_raw_fd(), 0o300) }, 0);
    assert_eq!(
        unsafe { libc::fchflags(bundle_file.as_raw_fd(), libc::UF_IMMUTABLE) },
        0
    );
    assert_eq!(
        unsafe { libc::fchflags(container_file.as_raw_fd(), libc::UF_IMMUTABLE) },
        0
    );
    drop(bundle_file);
    drop(container_file);
    assert_eq!(
        cleanup_recovered_generation(
            &fixture.root,
            &recovery_identity(
                suffix,
                &bundle_id,
                Some(i32::MAX),
                Some(&bundle_identity),
                Some(&container_identity),
            ),
            GenerationState::Poisoned,
            MacRecoveryOutcome::Restored,
        ),
        Ok(MacRecoveryCleanup::Cleaned)
    );
    assert!(!bundle.exists());
    assert!(!container.exists());
}

#[test]
fn recovery_preflight_preserves_every_name_when_any_descendant_is_unsafe() {
    let fixture = Fixture::new();
    let journal = MemoryJournal::default();
    let prepared =
        prepare_generation(fixture.spec(b"PING\n", Duration::from_secs(2)), &journal).unwrap();
    let bundle = prepared.bundle_path().to_path_buf();
    let bundle_id = prepared.signed_generation().id().as_str().to_owned();
    let suffix = bundle_id.rsplit_once('.').unwrap().1;
    let containers = account_home().join("Library/Containers");
    let container = containers.join(&bundle_id);
    fs::create_dir_all(&container).unwrap();
    fs::set_permissions(&container, fs::Permissions::from_mode(0o700)).unwrap();
    let safe = container.join("safe-sibling");
    fs::write(&safe, b"preserve\n").unwrap();
    let outside = containers.join(format!(".context-relay-outside-{}", fixture.suffix));
    fs::write(&outside, b"outside\n").unwrap();
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o640)).unwrap();
    let outside_mode = fs::metadata(&outside).unwrap().permissions().mode() & 0o7777;
    let hardlink = container.join("unsafe-hardlink");
    fs::hard_link(&outside, &hardlink).unwrap();
    let fifo = container.join("unsafe-fifo");
    let fifo_name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);

    let bundle_identity = root_identity(&bundle);
    let container_identity = root_identity(&container);
    assert_eq!(
        cleanup_recovered_generation(
            &fixture.root,
            &recovery_identity(
                suffix,
                &bundle_id,
                Some(i32::MAX),
                Some(&bundle_identity),
                Some(&container_identity),
            ),
            GenerationState::Poisoned,
            MacRecoveryOutcome::Restored,
        ),
        Ok(MacRecoveryCleanup::Conflict)
    );
    assert_eq!(fs::read(&safe).unwrap(), b"preserve\n");
    assert!(hardlink.exists());
    assert!(fifo.exists());
    assert_eq!(fs::read(&outside).unwrap(), b"outside\n");
    assert_eq!(
        fs::metadata(&outside).unwrap().permissions().mode() & 0o7777,
        outside_mode
    );
    assert!(bundle.exists());

    fs::remove_file(hardlink).unwrap();
    fs::remove_file(fifo).unwrap();
    make_tree_mutable(&bundle);
    let outside_bundle = fixture.root.join("outside-bundle-hardlink");
    fs::write(&outside_bundle, b"outside bundle\n").unwrap();
    fs::set_permissions(&outside_bundle, fs::Permissions::from_mode(0o640)).unwrap();
    let outside_bundle_mode = fs::metadata(&outside_bundle).unwrap().permissions().mode() & 0o7777;
    let bundle_hardlink = bundle.join("unsafe-bundle-hardlink");
    fs::hard_link(&outside_bundle, &bundle_hardlink).unwrap();
    assert_eq!(
        cleanup_recovered_generation(
            &fixture.root,
            &recovery_identity(
                suffix,
                &bundle_id,
                Some(i32::MAX),
                Some(&bundle_identity),
                Some(&container_identity),
            ),
            GenerationState::Poisoned,
            MacRecoveryOutcome::Restored,
        ),
        Ok(MacRecoveryCleanup::Conflict)
    );
    assert_eq!(fs::read(&safe).unwrap(), b"preserve\n");
    assert!(container.exists());
    assert!(bundle.exists());
    assert_eq!(fs::read(&outside_bundle).unwrap(), b"outside bundle\n");
    assert_eq!(
        fs::metadata(&outside_bundle).unwrap().permissions().mode() & 0o7777,
        outside_bundle_mode
    );

    fs::remove_file(bundle_hardlink).unwrap();
    assert_eq!(
        cleanup_recovered_generation(
            &fixture.root,
            &recovery_identity(
                suffix,
                &bundle_id,
                Some(i32::MAX),
                Some(&bundle_identity),
                Some(&container_identity),
            ),
            GenerationState::Poisoned,
            MacRecoveryOutcome::Restored,
        ),
        Ok(MacRecoveryCleanup::Cleaned)
    );
    assert_eq!(fs::read(&outside).unwrap(), b"outside\n");
    fs::remove_file(outside).unwrap();
    fs::remove_file(outside_bundle).unwrap();
}

#[test]
fn preparation_rejects_and_preserves_a_preexisting_container_name() {
    let fixture = Fixture::new();
    let id = fixture.id();
    let container = account_home().join("Library/Containers").join(id.as_str());
    let marker = container.join("preexisting-sentinel");
    fs::create_dir_all(&container).unwrap();
    fs::write(&marker, b"keep").unwrap();

    assert!(matches!(
        prepare_generation(
            fixture.spec(b"PING\n", Duration::from_secs(2)),
            &MemoryJournal::default()
        ),
        Err(MacPolicyError::InvalidTransition)
    ));
    assert_eq!(fs::read(&marker).unwrap(), b"keep");
    assert!(!fixture.root.join(format!("{}.app", id.as_str())).exists());

    fs::remove_dir_all(container).unwrap();
}

#[test]
fn timeout_is_poisoned_before_the_original_process_group_is_killed() {
    let fixture = Fixture::new();
    let journal = MemoryJournal::default();
    let prepared = prepare_generation(
        fixture.spec(b"MODE=HANG\n", Duration::from_millis(100)),
        &journal,
    )
    .unwrap();
    let bundle = prepared.bundle_path().to_path_buf();
    let signed = prepared.signed_generation().clone();
    let container = account_home()
        .join("Library/Containers")
        .join(signed.id().as_str());
    let mut process = prepared.into_process();
    assert_eq!(
        execute_generation(&journal, &signed, &mut process).unwrap_err(),
        MacPolicyError::ProcessTimedOut
    );
    assert_eq!(
        journal.events.lock().unwrap().as_slice(),
        [
            "reserved",
            "guardian_bound",
            "bundle_bound",
            "finalized",
            "container_bound",
            "active",
            "poisoned",
        ]
    );
    assert!(!bundle.exists());
    assert!(!container.exists());
}

#[test]
fn cleanly_detached_process_cannot_recreate_a_cleaned_container() {
    let first = Fixture::new();
    let second = Fixture::new();
    let real_home = PathBuf::from(std::env::var_os("HOME").unwrap());
    let first_container = real_home
        .join("Library/Containers")
        .join(first.id().as_str())
        .join("Data");
    let second_container = real_home
        .join("Library/Containers")
        .join(second.id().as_str())
        .join("Data");
    let marker = first_container.join("detached-result");
    let target = second_container.join("later-secret");
    let detach = format!(
        "MODE=DETACH\nTARGET={}\nMARKER={}\n",
        target.display(),
        marker.display()
    );

    run_probe(&first, detach.as_bytes(), Duration::from_secs(2)).unwrap();
    run_probe(
        &second,
        b"MODE=WRITE\nRELATIVE=later-secret\n",
        Duration::from_secs(2),
    )
    .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(!marker.exists());
    assert!(!first_container.parent().unwrap().exists());
    assert!(!second_container.parent().unwrap().exists());
}

#[test]
fn detached_inherited_stdio_does_not_delay_terminal_cleanup() {
    let fixture = Fixture::new();
    let journal = MemoryJournal::default();
    let prepared = prepare_generation(
        fixture.spec(b"MODE=DETACH_STDIO\n", Duration::from_secs(2)),
        &journal,
    )
    .unwrap();
    let bundle = prepared.bundle_path().to_path_buf();
    let signed = prepared.signed_generation().clone();
    let mut process = prepared.into_process();
    let started = Instant::now();

    execute_generation(&journal, &signed, &mut process).unwrap();

    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(!bundle.exists());
    std::thread::sleep(Duration::from_secs(3));
}

struct Fixture {
    root: PathBuf,
    helper: PathBuf,
    child: PathBuf,
    suffix: u128,
}

impl Fixture {
    fn new() -> Self {
        assert_eq!(architecture(), "arm64");
        let parent = PathBuf::from(
            std::env::var_os("CONTEXT_RELAY_CASE_SENSITIVE_APFS_ROOT")
                .expect("native CI must mount and declare a case-sensitive APFS root"),
        );
        prove_case_sensitive(&parent);
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = parent.join(format!("macos-launcher-{}-{suffix}", std::process::id()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let helper = root.join("template-helper");
        let child = root.join("template-child");
        fs::copy(env!("CARGO_BIN_EXE_macos_sandbox_probe"), &helper).unwrap();
        fs::copy(env!("CARGO_BIN_EXE_macos_sandbox_probe"), &child).unwrap();
        sign_helper_template(&helper);
        sign_empty(&child);
        Self {
            root,
            helper,
            child,
            suffix,
        }
    }

    fn spec(&self, input: &[u8], timeout: Duration) -> MacGenerationSpec {
        let child_metadata = fs::metadata(&self.child).unwrap();
        let child = MacSourceMaterial::new(
            "probe-child",
            self.child.clone(),
            child_metadata.len(),
            digest(&self.child),
            true,
        )
        .unwrap();
        MacGenerationSpec::new(
            self.id(),
            self.root.clone(),
            self.helper.clone(),
            digest(&self.helper),
            vec![child],
            input.to_vec(),
            timeout,
        )
        .unwrap()
    }

    fn id(&self) -> GenerationId {
        GenerationId::from_nonce(self.suffix.to_le_bytes())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[derive(Default)]
struct MemoryJournal {
    seen: Mutex<BTreeSet<GenerationId>>,
    states: Mutex<BTreeMap<GenerationId, GenerationState>>,
    events: Mutex<Vec<&'static str>>,
}

impl GenerationJournal for MemoryJournal {
    fn reserve(&self, id: &GenerationId) -> Result<(), MacPolicyError> {
        if !self.seen.lock().unwrap().insert(id.clone()) {
            return Err(MacPolicyError::InvalidTransition);
        }
        self.states
            .lock()
            .unwrap()
            .insert(id.clone(), GenerationState::Prepared);
        self.events.lock().unwrap().push("reserved");
        Ok(())
    }

    fn bind_guardian(&self, id: &GenerationId, pgid: i32) -> Result<(), MacPolicyError> {
        if pgid <= 0 || self.states.lock().unwrap().get(id) != Some(&GenerationState::Prepared) {
            return Err(MacPolicyError::InvalidTransition);
        }
        self.events.lock().unwrap().push("guardian_bound");
        Ok(())
    }

    fn bind_bundle_root(
        &self,
        id: &GenerationId,
        _bundle: &MacRootIdentity,
    ) -> Result<(), MacPolicyError> {
        if self.states.lock().unwrap().get(id) != Some(&GenerationState::Prepared) {
            return Err(MacPolicyError::InvalidTransition);
        }
        self.events.lock().unwrap().push("bundle_bound");
        Ok(())
    }

    fn finalize(&self, generation: &SignedGeneration) -> Result<(), MacPolicyError> {
        if self.states.lock().unwrap().get(generation.id()) != Some(&GenerationState::Prepared) {
            return Err(MacPolicyError::InvalidTransition);
        }
        self.events.lock().unwrap().push("finalized");
        Ok(())
    }

    fn bind_container_root(
        &self,
        id: &GenerationId,
        _container: &MacRootIdentity,
    ) -> Result<(), MacPolicyError> {
        if self.states.lock().unwrap().get(id) != Some(&GenerationState::Prepared) {
            return Err(MacPolicyError::InvalidTransition);
        }
        self.events.lock().unwrap().push("container_bound");
        Ok(())
    }

    fn transition(
        &self,
        id: &GenerationId,
        from: GenerationState,
        to: GenerationState,
    ) -> Result<(), MacPolicyError> {
        let mut states = self.states.lock().unwrap();
        if states.get(id) != Some(&from) {
            return Err(MacPolicyError::InvalidTransition);
        }
        states.insert(id.clone(), to);
        self.events.lock().unwrap().push(match to {
            GenerationState::Active => "active",
            GenerationState::Retired => "retired",
            GenerationState::Poisoned => "poisoned",
            GenerationState::Prepared => return Err(MacPolicyError::InvalidTransition),
        });
        Ok(())
    }

    fn poison_interrupted_after_restart(&self) -> Result<(), MacPolicyError> {
        let mut states = self.states.lock().unwrap();
        for state in states.values_mut() {
            if matches!(*state, GenerationState::Prepared | GenerationState::Active) {
                *state = GenerationState::Poisoned;
            }
        }
        Ok(())
    }
}

fn prove_case_sensitive(root: &Path) {
    static NONCE: AtomicU64 = AtomicU64::new(0);

    let nonce = NONCE.fetch_add(1, Ordering::Relaxed);
    let lower = root.join(format!("case-check-{}-{nonce}", std::process::id()));
    let upper = root.join(format!("CASE-CHECK-{}-{nonce}", std::process::id()));
    fs::write(&lower, b"lower").unwrap();
    fs::write(&upper, b"upper").unwrap();
    assert_eq!(fs::read(&lower).unwrap(), b"lower");
    assert_eq!(fs::read(&upper).unwrap(), b"upper");
    fs::remove_file(lower).unwrap();
    fs::remove_file(upper).unwrap();
}

fn architecture() -> String {
    String::from_utf8(
        Command::new("/usr/bin/uname")
            .arg("-m")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_owned()
}

fn sign_helper_template(path: &Path) {
    let entitlements = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../resources/macos/helper.entitlements.plist");
    let status = Command::new("/usr/bin/codesign")
        .args([
            "--force",
            "--sign",
            "-",
            "--options",
            "runtime",
            "--timestamp=none",
        ])
        .arg("--entitlements")
        .arg(entitlements)
        .arg(path)
        .status()
        .unwrap();
    assert!(status.success());
}

fn sign_empty(path: &Path) {
    let status = Command::new("/usr/bin/codesign")
        .args([
            "--force",
            "--sign",
            "-",
            "--options",
            "runtime",
            "--timestamp=none",
        ])
        .arg(path)
        .status()
        .unwrap();
    assert!(status.success());
}

fn digest(path: &Path) -> [u8; 32] {
    Sha256::digest(fs::read(path).unwrap()).into()
}

fn account_home() -> PathBuf {
    let passwd = unsafe { libc::getpwuid(libc::geteuid()) };
    assert!(!passwd.is_null());
    PathBuf::from(
        unsafe { CStr::from_ptr((*passwd).pw_dir) }
            .to_str()
            .unwrap(),
    )
}

fn root_identity(path: &Path) -> MacRootIdentity {
    let file = File::open(path).unwrap();
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    assert_eq!(
        unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) },
        0
    );
    let stat = unsafe { stat.assume_init() };
    MacRootIdentity::new(
        stat.st_dev as u64,
        stat.st_ino,
        stat.st_gen,
        stat.st_birthtime,
        u32::try_from(stat.st_birthtime_nsec).unwrap(),
        u32::from(stat.st_mode),
    )
    .unwrap()
}

fn recovery_identity<'a>(
    generation_id: &'a str,
    bundle_id: &'a str,
    guardian_pgid: Option<i32>,
    bundle_root: Option<&'a MacRootIdentity>,
    container_root: Option<&'a MacRootIdentity>,
) -> MacRecoveryIdentity<'a> {
    MacRecoveryIdentity::new(
        generation_id,
        bundle_id,
        guardian_pgid,
        bundle_root,
        container_root,
    )
}

fn make_tree_mutable(path: &Path) {
    assert!(
        Command::new("/usr/bin/chflags")
            .args(["-R", "nouchg"])
            .arg(path)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("/bin/chmod")
            .args(["-R", "u+rwx"])
            .arg(path)
            .status()
            .unwrap()
            .success()
    );
}

fn run_probe(fixture: &Fixture, input: &[u8], timeout: Duration) -> Result<(), MacPolicyError> {
    let journal = MemoryJournal::default();
    let prepared = prepare_generation(fixture.spec(input, timeout), &journal)?;
    let signed = prepared.signed_generation().clone();
    let mut process = prepared.into_process();
    execute_generation(&journal, &signed, &mut process).map(|_| ())
}
