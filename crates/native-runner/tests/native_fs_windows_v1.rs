#![cfg(windows)]

use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::windows::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    process::Command,
    sync::mpsc,
    thread,
    time::Duration,
    time::{SystemTime, UNIX_EPOCH},
};

use context_relay_native_runner::{
    ContentFrame, NativeObjectToken, NativeState, OsNativeFileSystem, PrivateStage, RunnerError,
    RuntimeTarget, StagePath, inspect_native_tree,
};

const TEST_NONCE: [u8; 16] = [0x6d; 16];

#[test]
fn parent_binding_allows_the_product_object_and_type_to_be_replaced() {
    let observed = NativeObjectToken::from_parts(7, [1; 16], 0x4000, 9, [3; 16]);
    let installed = NativeObjectToken::from_parts(7, [2; 16], 0, 9, [3; 16]);

    assert!(installed.has_same_parent_binding(&observed));
}

fn scratch(label: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "context-relay-native-fs-{label}-{}-{suffix}",
        std::process::id()
    ));
    fs::create_dir(&path).unwrap();
    path
}

fn cleanup(path: &Path) {
    let _ = fs::remove_dir_all(path);
}

fn junction(link: &Path, target: &Path) {
    let status = Command::new("cmd")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .status()
        .unwrap();
    assert!(status.success(), "failed to create mandatory NTFS junction");
}

fn move_approved_directory_behind_junction(label: &str) -> (PathBuf, PathBuf, PathBuf) {
    let root = scratch(label);
    let outside = scratch(&format!("{label}-outside"));
    let approved = root.join("approved");
    fs::create_dir(&approved).unwrap();
    fs::create_dir(approved.join("nested")).unwrap();
    let moved = outside.join("moved");
    fs::rename(&approved, &moved).unwrap();
    junction(&approved, &moved);
    (root, outside, approved)
}

#[test]
fn private_stage_is_fresh_copies_create_new_and_detects_input_swap() {
    let parent = scratch("stage");
    let mut stage =
        PrivateStage::create(&parent, [0xabu8; 16], RuntimeTarget::WindowsX86_64).unwrap();
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
    assert!(fs::metadata(&input).unwrap().permissions().readonly());
    assert!(
        stage
            .layout()
            .path(context_relay_native_runner::StageDirectory::Output)
            .is_dir()
    );
    assert_eq!(
        PrivateStage::create(&parent, [0xabu8; 16], RuntimeTarget::WindowsX86_64),
        Err(RunnerError::InvalidStage)
    );

    fs::rename(&input, input.with_extension("old")).unwrap();
    fs::write(&input, b"swapped\n").unwrap();
    assert_eq!(
        inventory.verify_unchanged(),
        Err(RunnerError::ConcurrentChange)
    );
    cleanup(&parent);
}

#[test]
fn native_tree_rejects_hardlinks_ads_and_normalization_collisions() {
    let root = scratch("topology");
    let file = root.join("rules.md");
    fs::write(&file, b"rules\n").unwrap();
    fs::hard_link(&file, root.join("alias.md")).unwrap();
    assert_eq!(
        inspect_native_tree(&root, RuntimeTarget::WindowsX86_64),
        Err(RunnerError::UnsafeTopology)
    );
    cleanup(&root);

    let root = scratch("ads");
    let file = root.join("rules.md");
    fs::write(&file, b"rules\n").unwrap();
    let ads = PathBuf::from(format!("{}:hidden", file.display()));
    match File::create(&ads).and_then(|mut stream| stream.write_all(b"secret")) {
        Ok(()) => assert_eq!(
            inspect_native_tree(&root, RuntimeTarget::WindowsX86_64),
            Err(RunnerError::UnsafeTopology)
        ),
        Err(error) if matches!(error.kind(), std::io::ErrorKind::Unsupported) => {}
        Err(error) => panic!("failed to create an NTFS alternate stream: {error}"),
    }
    cleanup(&root);

    let root = scratch("normalization");
    fs::write(root.join("\u{e9}.md"), b"nfc").unwrap();
    fs::write(root.join("e\u{301}.md"), b"nfd").unwrap();
    assert_eq!(
        inspect_native_tree(&root, RuntimeTarget::WindowsX86_64),
        Err(RunnerError::PathCollision)
    );
    cleanup(&root);
}

#[test]
fn native_tree_rejects_real_symlinks_when_windows_allows_creating_them() {
    let root = scratch("symlink");
    let target = root.join("target.md");
    fs::write(&target, b"rules\n").unwrap();
    let link = root.join("link.md");
    match std::os::windows::fs::symlink_file(&target, &link) {
        Ok(()) => assert_eq!(
            inspect_native_tree(&root, RuntimeTarget::WindowsX86_64),
            Err(RunnerError::UnsafeTopology)
        ),
        Err(error) if error.raw_os_error() == Some(1314) => {}
        Err(error) => panic!("failed to create a Windows symlink: {error}"),
    }
    cleanup(&root);
}

#[test]
fn snapshot_and_cas_reject_every_junction_ancestor_without_touching_moved_targets() {
    let native = OsNativeFileSystem::new();

    let (root, outside, approved) = move_approved_directory_behind_junction("junction-snapshot");
    let moved_file = outside.join("moved").join("nested").join("settings.json");
    fs::write(&moved_file, b"outside\n").unwrap();
    assert_eq!(
        native.snapshot(&approved.join("nested").join("settings.json")),
        Err(RunnerError::UnsafeTopology)
    );
    fs::remove_dir(&approved).unwrap();
    cleanup(&root);
    cleanup(&outside);

    let root = scratch("junction-create");
    let approved = root.join("approved");
    fs::create_dir(&approved).unwrap();
    fs::create_dir(approved.join("nested")).unwrap();
    let absent_path = approved.join("nested").join("settings.json");
    let absent = native.snapshot(&absent_path).unwrap();
    let template = root.join("template.json");
    fs::write(&template, b"template\n").unwrap();
    let template = native.snapshot(&template).unwrap();
    let desired =
        NativeState::regular_file(b"created\n".to_vec(), template.metadata().unwrap().clone());
    let outside = scratch("junction-create-outside");
    let moved = outside.join("moved");
    fs::rename(&approved, &moved).unwrap();
    junction(&approved, &moved);
    assert_eq!(
        native.compare_and_swap(&absent_path, absent.fingerprint(), &desired, &TEST_NONCE),
        Err(RunnerError::UnsafeTopology)
    );
    assert!(!moved.join("nested").join("settings.json").exists());
    fs::remove_dir(&approved).unwrap();
    cleanup(&root);
    cleanup(&outside);

    for (label, desired_absent) in [("junction-replace", false), ("junction-delete", true)] {
        let root = scratch(label);
        let approved = root.join("approved");
        fs::create_dir(&approved).unwrap();
        fs::create_dir(approved.join("nested")).unwrap();
        let path = approved.join("nested").join("settings.json");
        fs::write(&path, b"before\n").unwrap();
        let before = native.snapshot(&path).unwrap();
        let desired = if desired_absent {
            before.absent_state()
        } else {
            NativeState::regular_file(b"after\n".to_vec(), before.metadata().unwrap().clone())
        };
        let outside = scratch(&format!("{label}-outside"));
        let moved = outside.join("moved");
        fs::rename(&approved, &moved).unwrap();
        junction(&approved, &moved);
        assert_eq!(
            native.compare_and_swap(&path, before.fingerprint(), &desired, &TEST_NONCE),
            Err(RunnerError::UnsafeTopology)
        );
        assert_eq!(
            fs::read(moved.join("nested").join("settings.json")).unwrap(),
            b"before\n"
        );
        fs::remove_dir(&approved).unwrap();
        cleanup(&root);
        cleanup(&outside);
    }
}

#[test]
fn snapshot_rejects_dotdot_verbatim_and_long_path_forms() {
    let root = scratch("path-forms");
    let directory = root.join("directory");
    fs::create_dir(&directory).unwrap();
    let path = directory.join("settings.json");
    fs::write(&path, b"{}\n").unwrap();
    let native = OsNativeFileSystem::new();

    assert!(
        native
            .snapshot(&directory.join("..\\directory\\settings.json"))
            .is_err()
    );
    let verbatim = PathBuf::from(format!(r"\\?\{}", path.display()));
    assert!(native.snapshot(&verbatim).is_err());

    let mut long_directory = root.clone();
    while long_directory.as_os_str().encode_wide().count() < 270 {
        long_directory.push("0123456789abcdef");
    }
    let long_directory_verbatim = PathBuf::from(format!(r"\\?\{}", long_directory.display()));
    fs::create_dir_all(&long_directory_verbatim).unwrap();
    let long_file = long_directory.join("settings.json");
    let long_file_verbatim = PathBuf::from(format!(r"\\?\{}", long_file.display()));
    fs::write(&long_file_verbatim, b"{}\n").unwrap();
    assert!(native.snapshot(&long_file).is_err());

    cleanup(&PathBuf::from(format!(r"\\?\{}", root.display())));
}

#[test]
fn snapshot_rejects_noncanonical_and_reserved_windows_absolute_paths() {
    let root = scratch("path-aliases");
    let path = root.join("settings.json");
    fs::write(&path, b"{}\n").unwrap();
    let native = OsNativeFileSystem::new();
    let root_text = root.display().to_string();
    let lowercase_drive = format!(
        "{}{}\\settings.json",
        root_text[0..1].to_ascii_lowercase(),
        &root_text[1..]
    );

    for candidate in [
        PathBuf::from(lowercase_drive),
        PathBuf::from(format!(r"{}\.\settings.json", root.display())),
        PathBuf::from(format!(r"{}\\settings.json", root.display())),
        PathBuf::from(format!("{}/settings.json", root.display())),
        root.join("CON"),
        root.join("NUL.txt"),
        root.join("control\u{1f}.json"),
    ] {
        assert_eq!(
            native.snapshot(&candidate),
            Err(RunnerError::InvalidPath),
            "accepted alias or reserved path: {}",
            candidate.display()
        );
    }
    cleanup(&root);
}

#[test]
fn snapshot_is_complete_stable_and_unchanged_compare_and_swap_writes_nothing() {
    let root = scratch("snapshot");
    let path = root.join("settings.json");
    fs::write(&path, b"{\"enabled\":true}\n").unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&path, permissions).unwrap();
    let native = OsNativeFileSystem::new();
    let before = native.snapshot(&path).unwrap();
    let before_metadata = fs::metadata(&path).unwrap();

    assert_eq!(before.bytes(), Some(b"{\"enabled\":true}\n".as_slice()));
    assert!(before.metadata().unwrap().file_attributes() & 1 != 0);
    assert_eq!(
        native.snapshot(&path).unwrap().fingerprint(),
        before.fingerprint()
    );
    assert!(before.object_token().is_some());

    let outcome = native
        .compare_and_swap(&path, before.fingerprint(), before.state(), &TEST_NONCE)
        .unwrap();
    let after_metadata = fs::metadata(&path).unwrap();
    assert!(!outcome.wrote());
    assert_eq!(
        before_metadata.creation_time(),
        after_metadata.creation_time()
    );
    assert_eq!(
        before_metadata.last_write_time(),
        after_metadata.last_write_time()
    );
    assert_eq!(outcome.snapshot().object_token(), before.object_token());

    let mut wrong = *before.fingerprint();
    wrong[0] ^= 0xff;
    assert_eq!(
        native.compare_and_swap(&path, &wrong, before.state(), &TEST_NONCE),
        Err(RunnerError::ConcurrentChange)
    );
    cleanup(&root);
}

#[test]
fn snapshot_fails_closed_when_another_handle_exclusively_locks_the_file() {
    let root = scratch("locked");
    let path = root.join("settings.json");
    fs::write(&path, b"{}\n").unwrap();
    let _lock = OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(0)
        .open(&path)
        .unwrap();

    assert_eq!(
        OsNativeFileSystem::new().snapshot(&path),
        Err(RunnerError::Io)
    );
    cleanup(&root);
}

#[test]
fn guarded_install_writes_complete_state_and_preserves_ads() {
    let root = scratch("cas-write");
    let first_path = root.join("first.json");
    let second_path = root.join("second.json");
    fs::write(&first_path, b"old\n").unwrap();
    fs::write(&second_path, b"other\n").unwrap();
    for path in [&first_path, &second_path] {
        let ads = PathBuf::from(format!("{}:context-relay", path.display()));
        File::create(ads)
            .and_then(|mut stream| stream.write_all(b"preserve-me"))
            .unwrap();
    }
    let native = OsNativeFileSystem::new();
    let first_before = native.snapshot(&first_path).unwrap();
    let second_before = native.snapshot(&second_path).unwrap();
    assert_eq!(
        first_before.metadata().unwrap().alternate_streams()[0].bytes(),
        b"preserve-me"
    );
    let desired =
        NativeState::regular_file(b"new\n".to_vec(), first_before.metadata().unwrap().clone());

    let first = native
        .compare_and_swap(
            &first_path,
            first_before.fingerprint(),
            &desired,
            &TEST_NONCE,
        )
        .unwrap();
    assert!(first.wrote());
    assert_eq!(first.snapshot().bytes(), Some(b"new\n".as_slice()));
    assert_ne!(first.snapshot().object_token(), first_before.object_token());
    assert_eq!(
        first.snapshot().metadata().unwrap().alternate_streams()[0].bytes(),
        b"preserve-me"
    );

    let second = native
        .compare_and_swap(
            &second_path,
            second_before.fingerprint(),
            &desired,
            &TEST_NONCE,
        )
        .unwrap();
    assert!(second.wrote());
    assert_eq!(
        first.snapshot().fingerprint(),
        second.snapshot().fingerprint()
    );
    assert_ne!(
        first.snapshot().object_token(),
        second.snapshot().object_token()
    );

    let unchanged = native
        .compare_and_swap(
            &first_path,
            first.snapshot().fingerprint(),
            &desired,
            &TEST_NONCE,
        )
        .unwrap();
    assert!(!unchanged.wrote());
    cleanup(&root);
}

#[test]
fn compare_and_swap_rejects_a_writer_opened_while_the_replacement_is_staged() {
    let root = scratch("cas-current-writer");
    let path = root.join("settings.json");
    fs::write(&path, b"before\n").unwrap();
    let native = OsNativeFileSystem::new();
    let before = native.snapshot(&path).unwrap();
    let desired = NativeState::regular_file(
        vec![b'x'; 64 * 1024 * 1024],
        before.metadata().unwrap().clone(),
    );
    let expected = *before.fingerprint();
    let (opened_tx, opened_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let watched_root = root.clone();
    let watched_path = path.clone();
    let attacker = thread::spawn(move || {
        wait_for_adjacent_temp(&watched_root);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0x0000_0001 | 0x0000_0002 | 0x0000_0004)
            .open(&watched_path)
            .unwrap();
        file.write_all(b"attacker\n").unwrap();
        file.flush().unwrap();
        opened_tx.send(()).unwrap();
        release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    });
    let (result_tx, result_rx) = mpsc::channel();
    let cas_path = path.clone();
    let cas = thread::spawn(move || {
        result_tx
            .send(OsNativeFileSystem::new().compare_and_swap(
                &cas_path,
                &expected,
                &desired,
                &TEST_NONCE,
            ))
            .unwrap();
    });

    opened_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let result = result_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    release_tx.send(()).unwrap();
    cas.join().unwrap();
    attacker.join().unwrap();
    assert!(matches!(result, Err(RunnerError::ConcurrentChange)));
    assert_eq!(fs::read(&path).unwrap(), b"attacker\n");
    cleanup(&root);
}

#[test]
fn compare_and_swap_denies_a_write_capable_handle_to_the_staged_temp() {
    let root = scratch("cas-temp-writer");
    let path = root.join("settings.json");
    fs::write(&path, b"before\n").unwrap();
    let native = OsNativeFileSystem::new();
    let before = native.snapshot(&path).unwrap();
    let desired = NativeState::regular_file(
        vec![b'y'; 64 * 1024 * 1024],
        before.metadata().unwrap().clone(),
    );
    let expected = *before.fingerprint();
    let (attempt_tx, attempt_rx) = mpsc::channel();
    let watched_root = root.clone();
    let attacker = thread::spawn(move || {
        let temporary = wait_for_adjacent_temp(&watched_root);
        let blocked = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0x0000_0001 | 0x0000_0002 | 0x0000_0004)
            .open(temporary)
            .is_err();
        attempt_tx.send(blocked).unwrap();
    });
    let (result_tx, result_rx) = mpsc::channel();
    let cas_path = path.clone();
    let cas = thread::spawn(move || {
        result_tx
            .send(OsNativeFileSystem::new().compare_and_swap(
                &cas_path,
                &expected,
                &desired,
                &TEST_NONCE,
            ))
            .unwrap();
    });

    assert!(attempt_rx.recv_timeout(Duration::from_secs(10)).unwrap());
    let result = result_rx.recv_timeout(Duration::from_secs(60)).unwrap();
    cas.join().unwrap();
    attacker.join().unwrap();
    assert!(result.is_ok());
    assert_eq!(fs::metadata(&path).unwrap().len(), 64 * 1024 * 1024);
    cleanup(&root);
}

fn wait_for_adjacent_temp(root: &Path) -> PathBuf {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(path) = fs::read_dir(root).unwrap().find_map(|entry| {
            let path = entry.unwrap().path();
            let name = path.file_name()?.to_str()?;
            (name.starts_with(".context-relay-") && name.ends_with(".tmp")).then_some(path)
        }) {
            return path;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "staged temp did not appear"
        );
        thread::yield_now();
    }
}

#[test]
fn restorable_state_encoding_is_versioned_bounded_and_excludes_object_identity() {
    let root = scratch("state-codec");
    let path = root.join("settings.json");
    fs::write(&path, b"{}\n").unwrap();
    let native = OsNativeFileSystem::new();
    let snapshot = native.snapshot(&path).unwrap();

    let encoded = snapshot.state().encode_v1().unwrap();
    let decoded = NativeState::decode_v1(&encoded).unwrap();
    assert_eq!(&decoded, snapshot.state());
    assert_eq!(decoded.fingerprint(), *snapshot.fingerprint());

    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(NativeState::decode_v1(&trailing).is_err());
    let mut wrong_version = encoded;
    wrong_version[1] = 2;
    assert!(NativeState::decode_v1(&wrong_version).is_err());
    cleanup(&root);
}

#[test]
fn compare_and_swap_deletes_and_restores_an_exact_file_state() {
    let root = scratch("cas-delete");
    let path = root.join("settings.json");
    fs::write(&path, b"before\n").unwrap();
    let native = OsNativeFileSystem::new();
    let before = native.snapshot(&path).unwrap();
    let absent = before.absent_state();

    let deleted = native
        .compare_and_swap(&path, before.fingerprint(), &absent, &TEST_NONCE)
        .unwrap();
    assert!(deleted.wrote());
    assert_eq!(deleted.snapshot().state(), &absent);
    assert!(!path.exists());

    let unchanged = native
        .compare_and_swap(
            &path,
            deleted.snapshot().fingerprint(),
            &absent,
            &TEST_NONCE,
        )
        .unwrap();
    assert!(!unchanged.wrote());

    let restored = native
        .compare_and_swap(
            &path,
            unchanged.snapshot().fingerprint(),
            before.state(),
            &TEST_NONCE,
        )
        .unwrap();
    assert!(restored.wrote());
    assert_eq!(restored.snapshot().fingerprint(), before.fingerprint());
    assert_eq!(fs::read(&path).unwrap(), b"before\n");
    cleanup(&root);
}
