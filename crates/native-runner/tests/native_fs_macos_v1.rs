#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use std::{
    ffi::{CStr, CString},
    fs,
    mem::zeroed,
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::fs::{MetadataExt, PermissionsExt, symlink},
    },
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use context_relay_native_runner::{
    ContentFrame, NativeState, OsNativeFileSystem, PrivateStage, RunnerError, RuntimeTarget,
    StagePath, inspect_native_tree, validate_path_set,
};

const TEST_NONCE: [u8; 16] = [0x6d; 16];

const XATTR_NAME: &str = "com.context-relay.native-test";
const QUARANTINE_XATTR_NAME: &str = "com.apple.quarantine";

fn scratch(parent: &Path, label: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = parent.join(format!("crnf-{label}-{}-{suffix}", std::process::id()));
    fs::create_dir(&path).unwrap();
    path
}

fn cleanup(path: &Path) {
    let _ = fs::remove_dir_all(path);
}

fn set_immutable(path: &Path, symlink: bool) {
    let flags = libc::O_RDONLY
        | libc::O_CLOEXEC
        | if symlink {
            libc::O_SYMLINK
        } else {
            libc::O_NOFOLLOW
        };
    let descriptor = unsafe { libc::open(c_path(path).as_ptr(), flags) };
    assert!(descriptor >= 0, "failed to open {}", path.display());
    let file = unsafe { fs::File::from_raw_fd(descriptor) };
    assert_eq!(
        unsafe { libc::fchflags(file.as_raw_fd(), libc::UF_IMMUTABLE) },
        0
    );
}

fn clear_immutable_tree(path: &Path) {
    let _ = Command::new("/usr/bin/chflags")
        .args(["-R", "nouchg"])
        .arg(path)
        .status();
    let _ = Command::new("/bin/chmod")
        .args(["-R", "u+rwx"])
        .arg(path)
        .status();
}

fn case_sensitive_apfs_root() -> PathBuf {
    let root = PathBuf::from(
        std::env::var_os("CONTEXT_RELAY_CASE_SENSITIVE_APFS_ROOT")
            .expect("native CI must mount and declare a case-sensitive APFS root"),
    );
    assert!(root.is_absolute() && root.is_dir());
    let mut volume = unsafe { zeroed::<libc::statfs>() };
    assert_eq!(
        unsafe { libc::statfs(c_path(&root).as_ptr(), &mut volume) },
        0
    );
    assert_eq!(
        unsafe { CStr::from_ptr(volume.f_fstypename.as_ptr()) }
            .to_str()
            .unwrap(),
        "apfs",
        "declared case-sensitive fixture must be APFS"
    );
    let probe = scratch(&root, "case-precondition");
    fs::write(probe.join("CaseProbe"), b"upper").unwrap();
    fs::write(probe.join("caseprobe"), b"lower").unwrap();
    assert_ne!(
        fs::metadata(probe.join("CaseProbe")).unwrap().ino(),
        fs::metadata(probe.join("caseprobe")).unwrap().ino(),
        "declared APFS fixture is not case-sensitive"
    );
    cleanup(&probe);
    root
}

fn default_case_insensitive_root() -> PathBuf {
    let root = default_root();
    let probe = scratch(&root, "default-case-precondition");
    fs::write(probe.join("CaseProbe"), b"upper").unwrap();
    fs::write(probe.join("caseprobe"), b"lower").unwrap();
    assert_eq!(
        fs::metadata(probe.join("CaseProbe")).unwrap().ino(),
        fs::metadata(probe.join("caseprobe")).unwrap().ino(),
        "native CI default temporary volume must be case-insensitive"
    );
    cleanup(&probe);
    root
}

fn default_root() -> PathBuf {
    fs::canonicalize(std::env::temp_dir()).unwrap()
}

fn c_path(path: &Path) -> CString {
    use std::os::unix::ffi::OsStrExt as _;
    CString::new(path.as_os_str().as_bytes()).unwrap()
}

fn set_xattr(path: &Path, bytes: &[u8]) {
    set_named_xattr(path, XATTR_NAME, bytes);
}

fn set_named_xattr(path: &Path, name: &str, bytes: &[u8]) {
    let path = c_path(path);
    let name = CString::new(name).unwrap();
    assert_eq!(
        unsafe {
            libc::setxattr(
                path.as_ptr(),
                name.as_ptr(),
                bytes.as_ptr().cast(),
                bytes.len(),
                0,
                0,
            )
        },
        0
    );
}

#[test]
fn native_tree_accepts_only_fingerprinted_macos_quarantine_metadata() {
    let root = scratch(&default_case_insensitive_root(), "quarantine-xattr");
    let nested = root.join("nested");
    fs::create_dir(&nested).unwrap();
    let file = nested.join("rules.md");
    fs::write(&file, b"rules\n").unwrap();
    set_named_xattr(
        &nested,
        QUARANTINE_XATTR_NAME,
        b"0081;fixture;ContextRelay;",
    );
    set_named_xattr(&file, QUARANTINE_XATTR_NAME, b"0081;fixture;ContextRelay;");

    let inventory = inspect_native_tree(&root, RuntimeTarget::MacosArm64).unwrap();
    set_named_xattr(&file, QUARANTINE_XATTR_NAME, b"0081;changed;ContextRelay;");
    assert_eq!(
        inventory.verify_unchanged(),
        Err(RunnerError::ConcurrentChange)
    );
    set_xattr(&file, b"unexpected-metadata");
    assert_eq!(
        inspect_native_tree(&root, RuntimeTarget::MacosArm64),
        Err(RunnerError::UnsafeTopology)
    );
    cleanup(&root);
}

fn get_xattr(path: &Path) -> Vec<u8> {
    let path = c_path(path);
    let name = CString::new(XATTR_NAME).unwrap();
    let size =
        unsafe { libc::getxattr(path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0, 0, 0) };
    assert!(size >= 0);
    let mut bytes = vec![0; size as usize];
    assert_eq!(
        unsafe {
            libc::getxattr(
                path.as_ptr(),
                name.as_ptr(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                0,
                0,
            )
        },
        size
    );
    bytes
}

fn locked_file(path: &Path) -> std::fs::File {
    let path = c_path(path);
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDWR | libc::O_EXLOCK | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    assert!(fd >= 0);
    unsafe { std::fs::File::from_raw_fd(fd as RawFd) }
}

#[test]
fn native_tree_rejects_links_special_files_and_mac_alias_collisions() {
    let case_sensitive = case_sensitive_apfs_root();
    let collision = scratch(&case_sensitive, "case-collision");
    fs::write(collision.join("Case.md"), b"upper").unwrap();
    fs::write(collision.join("case.md"), b"lower").unwrap();
    assert_eq!(
        inspect_native_tree(&collision, RuntimeTarget::MacosArm64),
        Err(RunnerError::PathCollision)
    );
    cleanup(&collision);

    for parent in [default_case_insensitive_root(), case_sensitive] {
        let root = scratch(&parent, "topology");
        let file = root.join("rules.md");
        fs::write(&file, b"rules\n").unwrap();
        fs::hard_link(&file, root.join("alias.md")).unwrap();
        assert_eq!(
            inspect_native_tree(&root, RuntimeTarget::MacosArm64),
            Err(RunnerError::UnsafeTopology)
        );
        cleanup(&root);

        let root = scratch(&parent, "xattr-alias");
        let file = root.join("alias");
        fs::write(&file, b"alias\n").unwrap();
        set_xattr(&file, b"finder-alias-like-metadata");
        assert_eq!(
            inspect_native_tree(&root, RuntimeTarget::MacosArm64),
            Err(RunnerError::UnsafeTopology)
        );
        cleanup(&root);

        let root = scratch(&parent, "symlink");
        fs::write(root.join("target.md"), b"rules\n").unwrap();
        std::os::unix::fs::symlink("target.md", root.join("link.md")).unwrap();
        assert_eq!(
            inspect_native_tree(&root, RuntimeTarget::MacosArm64),
            Err(RunnerError::UnsafeTopology)
        );
        cleanup(&root);

        let root = scratch(&parent, "fifo");
        let fifo = c_path(&root.join("pipe"));
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert_eq!(
            inspect_native_tree(&root, RuntimeTarget::MacosArm64),
            Err(RunnerError::UnsafeTopology)
        );
        cleanup(&root);

        let root = scratch(&parent, "socket");
        let _socket = std::os::unix::net::UnixListener::bind(root.join("socket")).unwrap();
        assert_eq!(
            inspect_native_tree(&root, RuntimeTarget::MacosArm64),
            Err(RunnerError::UnsafeTopology)
        );
        cleanup(&root);
    }

    assert_eq!(
        OsNativeFileSystem::new().snapshot(Path::new("/dev/null")),
        Err(RunnerError::UnsafeTopology)
    );
    assert_eq!(
        validate_path_set(
            RuntimeTarget::MacosArm64,
            &[
                StagePath::try_from("input/Case.md").unwrap(),
                StagePath::try_from("input/case.md").unwrap(),
            ],
        ),
        Err(RunnerError::PathCollision)
    );
    assert_eq!(
        validate_path_set(
            RuntimeTarget::MacosArm64,
            &[
                StagePath::try_from("input/\u{e9}.md").unwrap(),
                StagePath::try_from("input/e\u{301}.md").unwrap(),
            ],
        ),
        Err(RunnerError::PathCollision)
    );
}

#[test]
fn snapshot_and_compare_and_swap_restore_posix_metadata_and_xattrs() {
    let root = scratch(&default_root(), "snapshot");
    let path = root.join("settings.json");
    fs::write(&path, b"before\n").unwrap();
    set_xattr(&path, b"preserve-me");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o440)).unwrap();
    let user = std::env::var("USER").expect("macOS native CI must expose USER");
    assert!(
        Command::new("/bin/chmod")
            .args(["+a", &format!("{user} allow read")])
            .arg(&path)
            .status()
            .unwrap()
            .success(),
        "macOS native CI must support a real file ACL"
    );
    let native = OsNativeFileSystem::new();
    let before = native.snapshot(&path).unwrap();
    let before_meta = fs::metadata(&path).unwrap();

    let encoded = before.state().encode_v1().unwrap();
    let decoded = NativeState::decode_v1(&encoded).unwrap();
    assert_eq!(&decoded, before.state());
    assert_eq!(decoded.fingerprint(), *before.fingerprint());

    assert_eq!(before.bytes(), Some(b"before\n".as_slice()));
    assert!(!before.metadata().unwrap().security_descriptor().is_empty());
    assert_eq!(
        native.snapshot(&path).unwrap().fingerprint(),
        before.fingerprint()
    );
    let unchanged = native
        .compare_and_swap(&path, before.fingerprint(), before.state(), &TEST_NONCE)
        .unwrap();
    assert!(!unchanged.wrote());
    assert_eq!(unchanged.snapshot().object_token(), before.object_token());

    let desired =
        NativeState::regular_file(b"after\n".to_vec(), before.metadata().unwrap().clone());
    let changed = native
        .compare_and_swap(&path, before.fingerprint(), &desired, &TEST_NONCE)
        .unwrap();
    assert!(changed.wrote());
    assert_eq!(fs::read(&path).unwrap(), b"after\n");
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o440);
    assert_eq!(get_xattr(&path), b"preserve-me");
    assert_eq!(
        changed.snapshot().metadata().unwrap().security_descriptor(),
        before.metadata().unwrap().security_descriptor()
    );
    assert_eq!(
        fs::metadata(&path).unwrap().modified().unwrap(),
        before_meta.modified().unwrap()
    );

    let restored = native
        .compare_and_swap(
            &path,
            changed.snapshot().fingerprint(),
            before.state(),
            &TEST_NONCE,
        )
        .unwrap();
    assert!(restored.wrote());
    assert_eq!(restored.snapshot().fingerprint(), before.fingerprint());
    assert_eq!(fs::read(&path).unwrap(), b"before\n");
    assert_eq!(get_xattr(&path), b"preserve-me");
    cleanup(&root);
}

#[test]
fn snapshot_fails_closed_for_advisory_lock_and_ancestor_symlink() {
    let root = scratch(&default_root(), "locked");
    let path = root.join("settings.json");
    fs::write(&path, b"{}\n").unwrap();
    let _lock = locked_file(&path);
    assert_eq!(
        OsNativeFileSystem::new().snapshot(&path),
        Err(RunnerError::Io)
    );
    cleanup(&root);

    let root = scratch(&default_root(), "ancestor-symlink");
    fs::create_dir(root.join("real")).unwrap();
    fs::write(root.join("real/settings.json"), b"{}\n").unwrap();
    std::os::unix::fs::symlink("real", root.join("linked")).unwrap();
    assert_eq!(
        OsNativeFileSystem::new().snapshot(&root.join("linked/settings.json")),
        Err(RunnerError::UnsafeTopology)
    );
    assert_eq!(
        OsNativeFileSystem::new().snapshot(&root.join("real/../real/settings.json")),
        Err(RunnerError::InvalidPath)
    );
    cleanup(&root);
}

#[test]
fn compare_and_swap_create_delete_and_post_enumeration_swap_are_exact() {
    let root = scratch(&default_root(), "cas");
    let path = root.join("settings.json");
    fs::write(&path, b"before\n").unwrap();
    let native = OsNativeFileSystem::new();
    let before = native.snapshot(&path).unwrap();
    let before_token = before.object_token().unwrap().clone();
    let absent = before.absent_state();

    let deleted = native
        .compare_and_swap(&path, before.fingerprint(), &absent, &TEST_NONCE)
        .unwrap();
    assert!(deleted.wrote());
    assert!(!path.exists());
    native
        .cleanup_committed_delete_observed(&path, before.fingerprint(), &TEST_NONCE, &before_token)
        .unwrap();
    let cleaned_absent = native.snapshot(&path).unwrap();
    let restored = native
        .compare_and_swap(
            &path,
            cleaned_absent.fingerprint(),
            before.state(),
            &TEST_NONCE,
        )
        .unwrap();
    assert!(restored.wrote());
    assert_eq!(restored.snapshot().fingerprint(), before.fingerprint());

    let inventory = inspect_native_tree(&root, RuntimeTarget::MacosArm64).unwrap();
    fs::rename(&path, root.join("old.json")).unwrap();
    fs::write(&path, b"swapped\n").unwrap();
    assert_eq!(
        inventory.verify_unchanged(),
        Err(RunnerError::ConcurrentChange)
    );
    cleanup(&root);
}

#[test]
fn private_stage_uses_create_new_read_only_inputs_on_both_apfs_modes() {
    for parent in [default_case_insensitive_root(), case_sensitive_apfs_root()] {
        let root = scratch(&parent, "stage-parent");
        let mut stage =
            PrivateStage::create(&root, [0x5au8; 16], RuntimeTarget::MacosArm64).unwrap();
        let frame = ContentFrame::new(
            StagePath::try_from("input/gitleaks-scan/payload/rules.md").unwrap(),
            b"approved\n".to_vec(),
        )
        .unwrap();
        let inventory = stage.write_and_seal_inputs(&[frame]).unwrap();
        let input = stage
            .layout()
            .root()
            .join("input/gitleaks-scan/payload/rules.md");
        assert_eq!(fs::read(&input).unwrap(), b"approved\n");
        assert_eq!(fs::metadata(&input).unwrap().mode() & 0o222, 0);
        assert_eq!(
            PrivateStage::create(&root, [0x5au8; 16], RuntimeTarget::MacosArm64),
            Err(RunnerError::InvalidStage)
        );

        fs::rename(&input, input.with_extension("old")).unwrap();
        fs::write(&input, b"swapped\n").unwrap();
        assert_eq!(
            inventory.verify_unchanged(),
            Err(RunnerError::ConcurrentChange)
        );
        cleanup(&root);
    }
}

#[test]
fn private_stage_cleanup_is_recursive_idempotent_and_never_follows_siblings() {
    let parent = scratch(&default_root(), "stage-cleanup");
    let sibling = parent.join("sibling");
    fs::create_dir(&sibling).unwrap();
    fs::write(sibling.join("canary"), b"outside\n").unwrap();

    let mut stage = PrivateStage::create(&parent, [0x71; 16], RuntimeTarget::MacosArm64).unwrap();
    let stage_root = stage.layout().root().to_path_buf();
    let nested = stage_root.join("output/nested");
    fs::create_dir(&nested).unwrap();
    fs::write(nested.join("report.json"), b"{}\n").unwrap();
    symlink(&sibling, stage_root.join("output/sibling-link")).unwrap();

    stage.cleanup().unwrap();
    assert!(!stage_root.exists());
    assert_eq!(fs::read(sibling.join("canary")).unwrap(), b"outside\n");
    stage.cleanup().unwrap();

    cleanup(&parent);
}

#[test]
fn private_stage_cleanup_clears_immutable_flags_without_following_symlinks() {
    let parent = scratch(&default_root(), "stage-cleanup-immutable");
    let sibling = parent.join("sibling");
    fs::create_dir(&sibling).unwrap();
    fs::write(sibling.join("canary"), b"outside\n").unwrap();

    let mut stage = PrivateStage::create(&parent, [0x74; 16], RuntimeTarget::MacosArm64).unwrap();
    let stage_root = stage.layout().root().to_path_buf();
    let nested = stage_root.join("output/immutable");
    let file = nested.join("report.json");
    let link = nested.join("sibling-link");
    fs::create_dir(&nested).unwrap();
    fs::write(&file, b"{}\n").unwrap();
    symlink(&sibling, &link).unwrap();

    set_immutable(&file, false);
    set_immutable(&link, true);
    set_immutable(&nested, false);
    set_immutable(&stage_root, false);

    let result = stage.cleanup();
    if result.is_err() {
        clear_immutable_tree(&stage_root);
        let _ = stage.cleanup();
    }
    assert_eq!(result, Ok(()));
    assert!(!stage_root.exists());
    assert_eq!(fs::read(sibling.join("canary")).unwrap(), b"outside\n");
    stage.cleanup().unwrap();

    cleanup(&parent);
}

#[test]
fn private_stage_cleanup_retry_restarts_directory_enumeration() {
    let parent = scratch(&default_root(), "stage-cleanup-retry");
    let sibling = parent.join("sibling");
    fs::create_dir(&sibling).unwrap();

    let mut stage = PrivateStage::create(&parent, [0x75; 16], RuntimeTarget::MacosArm64).unwrap();
    let stage_root = stage.layout().root().to_path_buf();
    let blocked = stage_root.join("output/blocked");
    let outside_link = sibling.join("outside-hardlink");
    fs::write(&blocked, b"blocked\n").unwrap();
    fs::hard_link(&blocked, &outside_link).unwrap();

    assert_eq!(stage.cleanup(), Err(RunnerError::UnsafeTopology));
    fs::remove_file(&outside_link).unwrap();
    stage.cleanup().unwrap();
    assert!(!stage_root.exists());
    stage.cleanup().unwrap();

    cleanup(&parent);
}

#[test]
fn private_stage_drop_cleans_the_owned_tree_on_an_error_path() {
    let parent = scratch(&default_root(), "stage-cleanup-error");
    let sibling = parent.join("sibling");
    fs::create_dir(&sibling).unwrap();
    fs::write(sibling.join("canary"), b"outside\n").unwrap();
    let stage_root = parent.join("73".repeat(16));

    let result: Result<(), RunnerError> = {
        let stage = PrivateStage::create(&parent, [0x73; 16], RuntimeTarget::MacosArm64).unwrap();
        assert_eq!(stage.layout().root(), stage_root);
        fs::write(stage.layout().root().join("output/partial"), b"partial\n").unwrap();
        Err(RunnerError::InvalidToolOutput)
    };

    assert_eq!(result, Err(RunnerError::InvalidToolOutput));
    assert!(!stage_root.exists());
    assert_eq!(fs::read(sibling.join("canary")).unwrap(), b"outside\n");
    cleanup(&parent);
}

#[test]
fn private_stage_cleanup_rejects_a_replaced_root_without_touching_either_tree() {
    let parent = scratch(&default_root(), "stage-cleanup-swap");
    let sibling = parent.join("sibling");
    fs::create_dir(&sibling).unwrap();
    fs::write(sibling.join("canary"), b"outside\n").unwrap();

    let mut stage = PrivateStage::create(&parent, [0x72; 16], RuntimeTarget::MacosArm64).unwrap();
    let stage_root = stage.layout().root().to_path_buf();
    let moved_stage = parent.join("moved-stage");
    fs::rename(&stage_root, &moved_stage).unwrap();
    fs::create_dir(&stage_root).unwrap();
    fs::write(stage_root.join("replacement"), b"keep\n").unwrap();

    assert_eq!(stage.cleanup(), Err(RunnerError::ConcurrentChange));
    assert_eq!(fs::read(stage_root.join("replacement")).unwrap(), b"keep\n");
    assert!(moved_stage.join("input").is_dir());
    assert_eq!(fs::read(sibling.join("canary")).unwrap(), b"outside\n");

    drop(stage);
    cleanup(&parent);
}
