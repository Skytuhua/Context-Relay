#![cfg(windows)]

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use context_relay_core::native_transaction::{
    engine::NativeFileSystem,
    filesystem::OsNativeTransactionFileSystem,
    model::{ApprovedMutation, MutationKind, RestorableStateFingerprint},
};
use context_relay_native_runner::{NativeState, OsNativeFileSystem};
use context_relay_protocol::{NativePlatform, Sha256Digest, WireNativeValue};

const NONCE: [u8; 16] = [0x7a; 16];

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

fn target(path: &Path) -> WireNativeValue {
    use std::os::windows::ffi::OsStrExt as _;

    WireNativeValue {
        platform: NativePlatform::Windows,
        bytes: path
            .as_os_str()
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect(),
        display: None,
    }
}

fn mutation(path: &Path, expected: [u8; 32], intended: &NativeState) -> ApprovedMutation {
    ApprovedMutation {
        target: target(path),
        kind: MutationKind::Payload,
        content: intended.encode_v1().unwrap(),
        expected: RestorableStateFingerprint(Sha256Digest(expected)),
        intended: RestorableStateFingerprint(Sha256Digest(intended.fingerprint())),
    }
}

fn junction(link: &Path, destination: &Path) {
    let status = Command::new("cmd")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(link)
        .arg(destination)
        .status()
        .unwrap();
    assert!(status.success(), "failed to create mandatory NTFS junction");
}

#[test]
fn production_adapter_captures_stable_exact_before_images_and_restores_writes() {
    let root = scratch("apply-restore");
    let path = root.join("settings.json");
    fs::write(&path, b"before\n").unwrap();
    let native = OsNativeFileSystem::new();
    let before = native.snapshot(&path).unwrap();
    let intended =
        NativeState::regular_file(b"after\n".to_vec(), before.metadata().unwrap().clone());
    let mutation = mutation(&path, *before.fingerprint(), &intended);
    let mut filesystem = OsNativeTransactionFileSystem::new(NONCE);

    let images = filesystem
        .create_before_images(std::slice::from_ref(&mutation))
        .unwrap();
    assert_eq!(images.len(), 1);
    let encoded_before = NativeState::decode_v1(&images[0].encrypted_state).unwrap();
    assert_eq!(encoded_before.fingerprint(), before.state().fingerprint());
    assert_eq!(
        encoded_before.encode_v1().unwrap(),
        images[0].encrypted_state
    );
    let NativeState::RegularFile { bytes, .. } = encoded_before else {
        panic!("existing target before-image became absent");
    };
    assert_eq!(bytes, b"before\n");
    assert_eq!(images[0].fingerprint, mutation.expected);
    assert_eq!(images[0].id.len(), 64);
    assert!(!images[0].object_token.volume.is_empty());
    assert!(!images[0].object_token.object.is_empty());
    assert_eq!(images[0].object_token.topology.len(), 29);
    assert_eq!(images[0].object_token.topology[0], 1);
    assert_ne!(
        u64::from_le_bytes(images[0].object_token.topology[5..13].try_into().unwrap()),
        0
    );
    assert!(
        images[0].object_token.topology[13..]
            .iter()
            .any(|byte| *byte != 0)
    );

    let mut repeat = OsNativeTransactionFileSystem::new(NONCE);
    assert_eq!(
        repeat
            .create_before_images(std::slice::from_ref(&mutation))
            .unwrap()[0]
            .id,
        images[0].id
    );
    let mut other_transaction = OsNativeTransactionFileSystem::new([0x7b; 16]);
    assert_ne!(
        other_transaction
            .create_before_images(std::slice::from_ref(&mutation))
            .unwrap()[0]
            .id,
        images[0].id
    );

    filesystem.record_native_metadata(&images).unwrap();
    filesystem
        .compare_and_swap_targets(std::slice::from_ref(&mutation))
        .unwrap();
    let outcome = filesystem.apply_mutation(&NONCE, &mutation).unwrap();
    assert!(outcome.wrote);
    assert_eq!(outcome.resulting_fingerprint, mutation.intended);
    assert_eq!(fs::read(&path).unwrap(), b"after\n");

    filesystem.restore_matching_applied_targets(&NONCE).unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"before\n");
    cleanup(&root);
}

#[test]
fn production_adapter_creates_absent_targets_and_unchanged_apply_writes_nothing() {
    let root = scratch("absent-and-unchanged");
    let template_path = root.join("template.json");
    let path = root.join("created.json");
    fs::write(&template_path, b"template\n").unwrap();
    let native = OsNativeFileSystem::new();
    let template = native.snapshot(&template_path).unwrap();
    let absent = native.snapshot(&path).unwrap();
    let intended =
        NativeState::regular_file(b"created\n".to_vec(), template.metadata().unwrap().clone());
    let create = mutation(&path, *absent.fingerprint(), &intended);
    let mut filesystem = OsNativeTransactionFileSystem::new(NONCE);
    let images = filesystem
        .create_before_images(std::slice::from_ref(&create))
        .unwrap();
    let encoded_absent = NativeState::decode_v1(&images[0].encrypted_state).unwrap();
    assert_eq!(&encoded_absent, absent.state());
    assert_eq!(encoded_absent.fingerprint(), *absent.fingerprint());
    assert!(!images[0].object_token.object.is_empty());
    filesystem
        .compare_and_swap_targets(std::slice::from_ref(&create))
        .unwrap();
    assert!(filesystem.apply_mutation(&NONCE, &create).unwrap().wrote);
    assert_eq!(fs::read(&path).unwrap(), b"created\n");

    let current = native.snapshot(&path).unwrap();
    let unchanged = mutation(&path, *current.fingerprint(), current.state());
    let metadata = fs::metadata(&path).unwrap();
    let mut unchanged_filesystem = OsNativeTransactionFileSystem::new([0x7c; 16]);
    unchanged_filesystem
        .create_before_images(std::slice::from_ref(&unchanged))
        .unwrap();
    unchanged_filesystem
        .compare_and_swap_targets(std::slice::from_ref(&unchanged))
        .unwrap();
    assert!(
        !unchanged_filesystem
            .apply_mutation(&[0x7c; 16], &unchanged)
            .unwrap()
            .wrote
    );
    let after = fs::metadata(&path).unwrap();
    use std::os::windows::fs::MetadataExt as _;
    assert_eq!(metadata.creation_time(), after.creation_time());
    assert_eq!(metadata.last_write_time(), after.last_write_time());
    cleanup(&root);
}

#[test]
#[allow(clippy::permissions_set_readonly_false)]
fn unchanged_apply_rejects_content_and_metadata_drift_after_preflight() {
    let root = scratch("unchanged-final-revalidation");
    let native = OsNativeFileSystem::new();

    for metadata_only in [false, true] {
        let path = root.join(format!("target-{metadata_only}.json"));
        fs::write(&path, b"approved\n").unwrap();
        let before = native.snapshot(&path).unwrap();
        let unchanged = mutation(&path, *before.fingerprint(), before.state());
        let mut filesystem = OsNativeTransactionFileSystem::new(if metadata_only {
            [0x71; 16]
        } else {
            [0x72; 16]
        });
        filesystem
            .create_before_images(std::slice::from_ref(&unchanged))
            .unwrap();
        filesystem
            .compare_and_swap_targets(std::slice::from_ref(&unchanged))
            .unwrap();

        if metadata_only {
            let mut permissions = fs::metadata(&path).unwrap().permissions();
            permissions.set_readonly(true);
            fs::set_permissions(&path, permissions).unwrap();
        } else {
            fs::write(&path, b"concurrent\n").unwrap();
        }

        assert!(
            filesystem
                .apply_mutation(
                    if metadata_only {
                        &[0x71; 16]
                    } else {
                        &[0x72; 16]
                    },
                    &unchanged,
                )
                .is_err()
        );
        assert_eq!(
            fs::read(&path).unwrap(),
            if metadata_only {
                b"approved\n".as_slice()
            } else {
                b"concurrent\n".as_slice()
            }
        );
        if metadata_only {
            let mut permissions = fs::metadata(&path).unwrap().permissions();
            permissions.set_readonly(false);
            fs::set_permissions(&path, permissions).unwrap();
        }
    }
    cleanup(&root);
}

#[test]
fn absent_parent_identity_change_after_preflight_cannot_redirect_install() {
    let root = scratch("parent-swap");
    let outside = scratch("parent-swap-outside");
    let approved = root.join("approved");
    fs::create_dir(&approved).unwrap();
    let path = approved.join("settings.json");
    let template_path = root.join("template.json");
    fs::write(&template_path, b"template\n").unwrap();
    let native = OsNativeFileSystem::new();
    let absent = native.snapshot(&path).unwrap();
    let template = native.snapshot(&template_path).unwrap();
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
    fs::create_dir(&approved).unwrap();

    assert!(filesystem.apply_mutation(&NONCE, &mutation).is_err());
    assert!(!path.exists());
    assert!(!moved.join("settings.json").exists());
    assert_eq!(fs::read(moved.join("canary")).unwrap(), b"outside\n");
    cleanup(&root);
    cleanup(&outside);
}

#[test]
fn absent_parent_junction_swap_after_preflight_leaves_outside_canary_untouched() {
    let root = scratch("junction-swap");
    let outside = scratch("junction-swap-outside");
    let approved = root.join("approved");
    fs::create_dir(&approved).unwrap();
    let path = approved.join("settings.json");
    let template_path = root.join("template.json");
    fs::write(&template_path, b"template\n").unwrap();
    let native = OsNativeFileSystem::new();
    let absent = native.snapshot(&path).unwrap();
    let template = native.snapshot(&template_path).unwrap();
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
    junction(&approved, &moved);

    assert!(filesystem.apply_mutation(&NONCE, &mutation).is_err());
    assert!(!moved.join("settings.json").exists());
    assert_eq!(fs::read(moved.join("canary")).unwrap(), b"outside\n");
    fs::remove_dir(&approved).unwrap();
    cleanup(&root);
    cleanup(&outside);
}

#[test]
fn failed_batch_preflight_authorizes_no_target_in_the_batch() {
    let root = scratch("failed-batch-preflight");
    let first_path = root.join("first.json");
    let second_path = root.join("second.json");
    fs::write(&first_path, b"first-before\n").unwrap();
    fs::write(&second_path, b"second-before\n").unwrap();
    let native = OsNativeFileSystem::new();
    let first_before = native.snapshot(&first_path).unwrap();
    let second_before = native.snapshot(&second_path).unwrap();
    let first_after = NativeState::regular_file(
        b"first-after\n".to_vec(),
        first_before.metadata().unwrap().clone(),
    );
    let second_after = NativeState::regular_file(
        b"second-after\n".to_vec(),
        second_before.metadata().unwrap().clone(),
    );
    let mutations = vec![
        mutation(&first_path, *first_before.fingerprint(), &first_after),
        mutation(&second_path, *second_before.fingerprint(), &second_after),
    ];
    let mut filesystem = OsNativeTransactionFileSystem::new(NONCE);
    filesystem.create_before_images(&mutations).unwrap();
    fs::write(&second_path, b"concurrent\n").unwrap();

    assert!(filesystem.compare_and_swap_targets(&mutations).is_err());
    assert!(filesystem.apply_mutation(&NONCE, &mutations[0]).is_err());
    assert_eq!(fs::read(&first_path).unwrap(), b"first-before\n");
    assert_eq!(fs::read(&second_path).unwrap(), b"concurrent\n");
    cleanup(&root);
}

#[test]
fn concurrent_identical_install_is_not_attributed_to_the_failed_transaction() {
    let root = scratch("identical-concurrent-install");
    let path = root.join("settings.json");
    let template_path = root.join("template.json");
    fs::write(&template_path, b"template\n").unwrap();
    let native = OsNativeFileSystem::new();
    let absent = native.snapshot(&path).unwrap();
    let template = native.snapshot(&template_path).unwrap();
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
fn compensation_restores_every_matching_target_even_when_another_target_conflicts() {
    let root = scratch("multi-restore-conflict");
    let first_path = root.join("first.json");
    let second_path = root.join("second.json");
    fs::write(&first_path, b"first-before\n").unwrap();
    fs::write(&second_path, b"second-before\n").unwrap();
    let native = OsNativeFileSystem::new();
    let first_before = native.snapshot(&first_path).unwrap();
    let second_before = native.snapshot(&second_path).unwrap();
    let first_after = NativeState::regular_file(
        b"first-after\n".to_vec(),
        first_before.metadata().unwrap().clone(),
    );
    let second_after = NativeState::regular_file(
        b"second-after\n".to_vec(),
        second_before.metadata().unwrap().clone(),
    );
    let mutations = vec![
        mutation(&first_path, *first_before.fingerprint(), &first_after),
        mutation(&second_path, *second_before.fingerprint(), &second_after),
    ];
    let mut filesystem = OsNativeTransactionFileSystem::new(NONCE);
    filesystem.create_before_images(&mutations).unwrap();
    filesystem.compare_and_swap_targets(&mutations).unwrap();
    filesystem.apply_mutation(&NONCE, &mutations[0]).unwrap();
    filesystem.apply_mutation(&NONCE, &mutations[1]).unwrap();
    fs::write(&second_path, b"concurrent\n").unwrap();

    assert!(filesystem.restore_matching_applied_targets(&NONCE).is_err());
    assert_eq!(fs::read(&first_path).unwrap(), b"first-before\n");
    assert_eq!(fs::read(&second_path).unwrap(), b"concurrent\n");
    cleanup(&root);
}

#[test]
fn compensation_restores_two_deletes_in_one_directory_in_reverse_generation_order() {
    let root = scratch("same-parent-delete-chain");
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
    assert!(!first_path.exists());
    assert!(!second_path.exists());

    filesystem.restore_matching_applied_targets(&NONCE).unwrap();

    assert_eq!(fs::read(&first_path).unwrap(), b"first-before\n");
    assert_eq!(fs::read(&second_path).unwrap(), b"second-before\n");
    cleanup(&root);
}

#[test]
fn same_parent_non_delete_is_a_barrier_between_delete_rebinds() {
    let root = scratch("same-parent-delete-write-chain");
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
    let root = scratch("same-parent-delete-aba");
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
    let root = scratch("committed-delete-cleanup");
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
