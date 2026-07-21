#![cfg(target_os = "macos")]

use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use context_relay_core::native_transaction::{
    engine::NativeFileSystem,
    filesystem::OsNativeTransactionFileSystem,
    model::{ApprovedMutation, MutationKind, RestorableStateFingerprint},
};
use context_relay_native_runner::{NativeState, OsNativeFileSystem};
use context_relay_protocol::{NativePlatform, Sha256Digest, WireNativeValue};

const NONCE: [u8; 16] = [0x6b; 16];

fn scratch(label: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "context-relay-core-native-fs-{label}-{}-{suffix}",
        std::process::id()
    ));
    fs::create_dir(&path).unwrap();
    path
}

fn cleanup(path: &Path) {
    let _ = fs::remove_dir_all(path);
}

fn mutation(path: &Path, expected: [u8; 32], intended: &NativeState) -> ApprovedMutation {
    use std::os::unix::ffi::OsStrExt as _;

    ApprovedMutation {
        target: WireNativeValue {
            platform: NativePlatform::Macos,
            bytes: path.as_os_str().as_bytes().to_vec(),
            display: None,
        },
        kind: MutationKind::Payload,
        content: intended.encode_v1().unwrap(),
        expected: RestorableStateFingerprint(Sha256Digest(expected)),
        intended: RestorableStateFingerprint(Sha256Digest(intended.fingerprint())),
    }
}

#[test]
fn production_adapter_applies_and_restores_an_absent_target() {
    let root = scratch("macos-apply-restore");
    let path = root.join("settings.json");
    let template_path = root.join("template.json");
    fs::write(&template_path, b"template\n").unwrap();
    let native = OsNativeFileSystem::new();
    let template = native.snapshot(&template_path).unwrap();
    fs::remove_file(&template_path).unwrap();
    let absent = native.snapshot(&path).unwrap();
    let intended =
        NativeState::regular_file(b"created\n".to_vec(), template.metadata().unwrap().clone());
    let mutation = mutation(&path, *absent.fingerprint(), &intended);
    let mut filesystem = OsNativeTransactionFileSystem::new(NONCE);
    let image = filesystem
        .create_before_images(std::slice::from_ref(&mutation))
        .unwrap()
        .remove(0);
    let encoded_absent = NativeState::decode_v1(&image.encrypted_state).unwrap();
    assert_eq!(&encoded_absent, absent.state());
    assert_eq!(encoded_absent.fingerprint(), *absent.fingerprint());
    assert!(!image.object_token.volume.is_empty());
    assert!(!image.object_token.object.is_empty());
    assert_eq!(image.object_token.topology.len(), 29);
    assert_eq!(image.object_token.topology[0], 1);
    assert_ne!(
        u64::from_le_bytes(image.object_token.topology[5..13].try_into().unwrap()),
        0
    );
    assert!(
        image.object_token.topology[13..]
            .iter()
            .any(|byte| *byte != 0)
    );
    filesystem
        .compare_and_swap_targets(std::slice::from_ref(&mutation))
        .unwrap();
    assert!(filesystem.apply_mutation(&NONCE, &mutation).unwrap().wrote);
    assert_eq!(fs::read(&path).unwrap(), b"created\n");
    filesystem.restore_matching_applied_targets(&NONCE).unwrap();
    assert!(!path.exists());
    cleanup(&root);
}

#[test]
fn production_adapter_leaves_an_unchanged_target_byte_for_byte_untouched() {
    use std::os::unix::fs::MetadataExt as _;

    let root = scratch("macos-unchanged");
    let path = root.join("settings.json");
    fs::write(&path, b"unchanged\n").unwrap();
    let native = OsNativeFileSystem::new();
    let before = native.snapshot(&path).unwrap();
    let mutation = mutation(&path, *before.fingerprint(), before.state());
    let metadata = fs::metadata(&path).unwrap();
    let mut filesystem = OsNativeTransactionFileSystem::new(NONCE);
    filesystem
        .create_before_images(std::slice::from_ref(&mutation))
        .unwrap();
    filesystem
        .compare_and_swap_targets(std::slice::from_ref(&mutation))
        .unwrap();

    assert!(!filesystem.apply_mutation(&NONCE, &mutation).unwrap().wrote);
    let after = fs::metadata(&path).unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"unchanged\n");
    assert_eq!(metadata.ino(), after.ino());
    assert_eq!(metadata.mtime(), after.mtime());
    assert_eq!(metadata.mtime_nsec(), after.mtime_nsec());
    cleanup(&root);
}

#[test]
fn unchanged_apply_rejects_content_and_metadata_drift_after_preflight() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = scratch("macos-unchanged-final-revalidation");
    let native = OsNativeFileSystem::new();

    for metadata_only in [false, true] {
        let path = root.join(format!("target-{metadata_only}.json"));
        fs::write(&path, b"approved\n").unwrap();
        let before = native.snapshot(&path).unwrap();
        let unchanged = mutation(&path, *before.fingerprint(), before.state());
        let nonce = if metadata_only {
            [0x61; 16]
        } else {
            [0x62; 16]
        };
        let mut filesystem = OsNativeTransactionFileSystem::new(nonce);
        filesystem
            .create_before_images(std::slice::from_ref(&unchanged))
            .unwrap();
        filesystem
            .compare_and_swap_targets(std::slice::from_ref(&unchanged))
            .unwrap();

        if metadata_only {
            let mut permissions = fs::metadata(&path).unwrap().permissions();
            permissions.set_mode(0o600);
            fs::set_permissions(&path, permissions).unwrap();
        } else {
            fs::write(&path, b"concurrent\n").unwrap();
        }

        assert!(filesystem.apply_mutation(&nonce, &unchanged).is_err());
        assert_eq!(
            fs::read(&path).unwrap(),
            if metadata_only {
                b"approved\n".as_slice()
            } else {
                b"concurrent\n".as_slice()
            }
        );
    }
    cleanup(&root);
}

#[test]
fn absent_parent_symlink_swap_after_preflight_leaves_outside_canary_untouched() {
    let root = scratch("macos-symlink-swap");
    let outside = scratch("macos-symlink-swap-outside");
    let approved = root.join("approved");
    fs::create_dir(&approved).unwrap();
    let path = approved.join("settings.json");
    let template_path = approved.join("template.json");
    fs::write(&template_path, b"template\n").unwrap();
    let native = OsNativeFileSystem::new();
    let template = native.snapshot(&template_path).unwrap();
    fs::remove_file(&template_path).unwrap();
    let absent = native.snapshot(&path).unwrap();
    let intended =
        NativeState::regular_file(b"approved\n".to_vec(), template.metadata().unwrap().clone());
    let mutation = mutation(&path, *absent.fingerprint(), &intended);
    let mut filesystem = OsNativeTransactionFileSystem::new(NONCE);
    filesystem
        .create_before_images(std::slice::from_ref(&mutation))
        .unwrap();
    filesystem
        .compare_and_swap_targets(std::slice::from_ref(&mutation))
        .unwrap();

    let moved = outside.join("moved");
    fs::rename(&approved, &moved).unwrap();
    fs::write(moved.join("canary"), b"outside\n").unwrap();
    std::os::unix::fs::symlink(&moved, &approved).unwrap();

    assert!(filesystem.apply_mutation(&NONCE, &mutation).is_err());
    assert!(!moved.join("settings.json").exists());
    assert_eq!(fs::read(moved.join("canary")).unwrap(), b"outside\n");
    fs::remove_file(&approved).unwrap();
    cleanup(&root);
    cleanup(&outside);
}

#[test]
fn concurrent_identical_install_is_not_attributed_to_the_failed_transaction() {
    let root = scratch("macos-identical-concurrent-install");
    let path = root.join("settings.json");
    let template_path = root.join("template.json");
    fs::write(&template_path, b"template\n").unwrap();
    let native = OsNativeFileSystem::new();
    let template = native.snapshot(&template_path).unwrap();
    fs::remove_file(&template_path).unwrap();
    let absent = native.snapshot(&path).unwrap();
    let intended =
        NativeState::regular_file(b"intended\n".to_vec(), template.metadata().unwrap().clone());
    let mutation = mutation(&path, *absent.fingerprint(), &intended);
    let mut filesystem = OsNativeTransactionFileSystem::new(NONCE);
    filesystem
        .create_before_images(std::slice::from_ref(&mutation))
        .unwrap();
    filesystem
        .compare_and_swap_targets(std::slice::from_ref(&mutation))
        .unwrap();

    let concurrent = native
        .compare_and_swap_with_nonce(&path, absent.fingerprint(), &intended, &[0x55; 16])
        .unwrap();
    assert!(concurrent.wrote());
    let concurrent_token = concurrent.snapshot().object_token().unwrap().clone();

    assert!(filesystem.apply_mutation(&NONCE, &mutation).is_err());
    filesystem.restore_matching_applied_targets(&NONCE).unwrap();
    let after = native.snapshot(&path).unwrap();
    assert_eq!(after.object_token(), Some(&concurrent_token));
    assert_eq!(after.fingerprint(), &mutation.intended.0.0);
    assert_eq!(fs::read(&path).unwrap(), b"intended\n");
    cleanup(&root);
}

#[test]
fn compensation_restores_two_deletes_in_one_directory_in_reverse_generation_order() {
    let root = scratch("macos-same-parent-delete-chain");
    let first_path = root.join("first.json");
    let second_path = root.join("second.json");
    fs::write(&first_path, b"first-before\n").unwrap();
    fs::write(&second_path, b"second-before\n").unwrap();
    let native = OsNativeFileSystem::new();
    let first_before = native.snapshot(&first_path).unwrap();
    let second_before = native.snapshot(&second_path).unwrap();
    let mutations = vec![
        mutation(
            &first_path,
            *first_before.fingerprint(),
            &first_before.absent_state(),
        ),
        mutation(
            &second_path,
            *second_before.fingerprint(),
            &second_before.absent_state(),
        ),
    ];
    let mut filesystem = OsNativeTransactionFileSystem::new(NONCE);
    filesystem.create_before_images(&mutations).unwrap();
    filesystem.compare_and_swap_targets(&mutations).unwrap();
    filesystem.apply_mutation(&NONCE, &mutations[0]).unwrap();
    filesystem.apply_mutation(&NONCE, &mutations[1]).unwrap();

    filesystem.restore_matching_applied_targets(&NONCE).unwrap();

    assert_eq!(fs::read(&first_path).unwrap(), b"first-before\n");
    assert_eq!(fs::read(&second_path).unwrap(), b"second-before\n");
    cleanup(&root);
}

#[test]
fn same_parent_non_delete_is_a_barrier_between_delete_rebinds() {
    let root = scratch("macos-same-parent-delete-write-chain");
    let first_path = root.join("first.json");
    let middle_path = root.join("middle.json");
    let last_path = root.join("last.json");
    fs::write(&first_path, b"first-before\n").unwrap();
    fs::write(&middle_path, b"middle-before\n").unwrap();
    fs::write(&last_path, b"last-before\n").unwrap();

    let native = OsNativeFileSystem::new();
    let first_before = native.snapshot(&first_path).unwrap();
    let middle_before = native.snapshot(&middle_path).unwrap();
    let last_before = native.snapshot(&last_path).unwrap();
    let middle_after = NativeState::regular_file(
        b"middle-after\n".to_vec(),
        middle_before.metadata().unwrap().clone(),
    );
    let mutations = vec![
        mutation(
            &first_path,
            *first_before.fingerprint(),
            &first_before.absent_state(),
        ),
        mutation(&middle_path, *middle_before.fingerprint(), &middle_after),
        mutation(
            &last_path,
            *last_before.fingerprint(),
            &last_before.absent_state(),
        ),
    ];
    let mut filesystem = OsNativeTransactionFileSystem::new(NONCE);
    filesystem.create_before_images(&mutations).unwrap();
    filesystem.compare_and_swap_targets(&mutations).unwrap();
    for mutation in &mutations {
        filesystem.apply_mutation(&NONCE, mutation).unwrap();
    }

    let mut checkpoints = Vec::new();
    let mut rebinds = Vec::new();
    <OsNativeTransactionFileSystem as NativeFileSystem>::restore_matching_applied_targets(
        &mut filesystem,
        &NONCE,
        &mut |_, _| Ok(()),
        &mut |earlier, later, _, _| {
            checkpoints.push((earlier, later));
            Ok(())
        },
        &mut |earlier, later, _, _| {
            rebinds.push((earlier, later));
            Ok(())
        },
    )
    .unwrap();

    assert_eq!(checkpoints, [(0, 1)]);
    assert_eq!(rebinds, [(0, 1)]);
    assert_eq!(fs::read(&first_path).unwrap(), b"first-before\n");
    assert_eq!(fs::read(&middle_path).unwrap(), b"middle-before\n");
    assert_eq!(fs::read(&last_path).unwrap(), b"last-before\n");
    cleanup(&root);
}

#[test]
fn recreate_then_delete_aba_breaks_the_same_parent_delete_chain() {
    let root = scratch("macos-same-parent-delete-aba");
    let first_path = root.join("first.json");
    let second_path = root.join("second.json");
    fs::write(&first_path, b"first-before\n").unwrap();
    fs::write(&second_path, b"second-before\n").unwrap();
    let native = OsNativeFileSystem::new();
    let first_before = native.snapshot(&first_path).unwrap();
    let second_before = native.snapshot(&second_path).unwrap();
    let mutations = vec![
        mutation(
            &first_path,
            *first_before.fingerprint(),
            &first_before.absent_state(),
        ),
        mutation(
            &second_path,
            *second_before.fingerprint(),
            &second_before.absent_state(),
        ),
    ];
    let mut filesystem = OsNativeTransactionFileSystem::new(NONCE);
    filesystem.create_before_images(&mutations).unwrap();
    filesystem.compare_and_swap_targets(&mutations).unwrap();
    filesystem.apply_mutation(&NONCE, &mutations[0]).unwrap();
    filesystem.apply_mutation(&NONCE, &mutations[1]).unwrap();
    fs::write(&second_path, b"attacker-recreated\n").unwrap();
    fs::remove_file(&second_path).unwrap();

    let outcome = filesystem.restore_matching_applied_targets(&NONCE).unwrap();

    assert_eq!(outcome.conflict_target_sequences(), &[1, 0]);
    assert!(!first_path.exists());
    assert!(!second_path.exists());
    cleanup(&root);
}

#[test]
fn committed_delete_removes_only_its_exact_retained_backup_idempotently() {
    let root = scratch("macos-committed-delete-cleanup");
    let path = root.join("settings.json");
    fs::write(&path, b"before\n").unwrap();
    let native = OsNativeFileSystem::new();
    let before = native.snapshot(&path).unwrap();
    let delete = mutation(&path, *before.fingerprint(), &before.absent_state());
    let mut filesystem = OsNativeTransactionFileSystem::new(NONCE);
    filesystem
        .create_before_images(std::slice::from_ref(&delete))
        .unwrap();
    filesystem
        .compare_and_swap_targets(std::slice::from_ref(&delete))
        .unwrap();
    filesystem.apply_mutation(&NONCE, &delete).unwrap();
    let backups = || {
        fs::read_dir(&root)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".backup"))
            .count()
    };
    assert_eq!(backups(), 1);

    filesystem.finish_committed_targets(&NONCE).unwrap();
    filesystem.finish_committed_targets(&NONCE).unwrap();

    assert!(!path.exists());
    assert_eq!(backups(), 0);
    cleanup(&root);
}
