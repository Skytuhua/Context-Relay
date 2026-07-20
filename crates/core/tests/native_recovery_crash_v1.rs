#![cfg(any(windows, target_os = "macos"))]

mod support;

use std::{fs, process::Command};

use context_relay_core::{
    native_transaction::{
        MutationKind, NativeApplyReceipt, NativeObjectToken, NativeReceiptEntry, OwnershipChange,
        RestorableStateFingerprint, TransactionStep,
        engine::BoundaryError,
        recovery::{
            OsNativeRecoveryIo, RecoveryAction, RecoveryCleanup, RecoveryFaultHook,
            RecoveryFaultPoint, RecoveryMoment, recover_native_transactions,
            recover_native_transactions_with_faults,
        },
    },
    vault::{
        BeforeImagePolicy, BeforeImageWrite, NativePlanWrite, NativeSandboxCleanupState,
        NativeSandboxIdentity, NativeTransactionStatus, NativeWalState, NativeWalWrite, Vault,
    },
};
use context_relay_native_runner::{NativeState, OsNativeFileSystem};
use context_relay_protocol::{ApplyReceipt, NativePlatform, Sha256Digest, WireNativeValue};

#[cfg(windows)]
use context_relay_core::native_transaction::recovery::RecoverySandboxIdentity;

use support::{ID_1, ID_2, MemoryKeyStore, TempVault, clock};

const CREDENTIAL: &str = "task-9-native-recovery-crash";
const KEY: [u8; 32] = [77; 32];
const CHILD_ROOT: &str = "CONTEXT_RELAY_NATIVE_RECOVERY_ROOT";
const CHILD_FAULT: &str = "CONTEXT_RELAY_NATIVE_RECOVERY_FAULT";
const CHILD_COMMIT: &str = "CONTEXT_RELAY_NATIVE_RECOVERY_COMMIT";
const CHILD_FORWARD: &str = "CONTEXT_RELAY_NATIVE_RECOVERY_FORWARD";
const CHILD_CLEANUP_CONFLICT: &str = "CONTEXT_RELAY_NATIVE_RECOVERY_CLEANUP_CONFLICT";
#[cfg(windows)]
const CHILD_GUARDED_GAP: &str = "CONTEXT_RELAY_NATIVE_RECOVERY_GUARDED_GAP";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ForwardAction {
    PutBeforeImages,
    PrepareWal,
    ApplyNative,
    MarkApplied,
    Commit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ForwardFaultPoint {
    action: ForwardAction,
    moment: RecoveryMoment,
    target_sequence: Option<u32>,
}

impl ForwardFaultPoint {
    fn encode(self) -> String {
        let action = match self.action {
            ForwardAction::PutBeforeImages => "put_before_images",
            ForwardAction::PrepareWal => "prepare_wal",
            ForwardAction::ApplyNative => "apply_native",
            ForwardAction::MarkApplied => "mark_applied",
            ForwardAction::Commit => "commit",
        };
        let moment = match self.moment {
            RecoveryMoment::Before => "before",
            RecoveryMoment::After => "after",
        };
        format!(
            "{action}:{moment}:{}",
            self.target_sequence
                .map_or_else(|| "-".to_owned(), |value| value.to_string())
        )
    }

    fn decode(value: &str) -> Option<Self> {
        let mut fields = value.split(':');
        let action = match fields.next()? {
            "put_before_images" => ForwardAction::PutBeforeImages,
            "prepare_wal" => ForwardAction::PrepareWal,
            "apply_native" => ForwardAction::ApplyNative,
            "mark_applied" => ForwardAction::MarkApplied,
            "commit" => ForwardAction::Commit,
            _ => return None,
        };
        let moment = match fields.next()? {
            "before" => RecoveryMoment::Before,
            "after" => RecoveryMoment::After,
            _ => return None,
        };
        let target_sequence = match fields.next()? {
            "-" => None,
            value => Some(value.parse().ok()?),
        };
        fields.next().is_none().then_some(Self {
            action,
            moment,
            target_sequence,
        })
    }
}

fn open_vault(root: &std::path::Path) -> Vault {
    let keys = MemoryKeyStore::default();
    keys.insert(CREDENTIAL, KEY);
    Vault::open(&root.join("vault.db"), CREDENTIAL, &keys).unwrap()
}

#[cfg(windows)]
fn wire_path(path: &std::path::Path) -> WireNativeValue {
    use std::os::windows::ffi::OsStrExt;

    WireNativeValue {
        platform: NativePlatform::Windows,
        bytes: path
            .as_os_str()
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect(),
        display: Some(path.display().to_string()),
    }
}

#[cfg(target_os = "macos")]
fn wire_path(path: &std::path::Path) -> WireNativeValue {
    use std::os::unix::ffi::OsStrExt;

    WireNativeValue {
        platform: NativePlatform::Macos,
        bytes: path.as_os_str().as_bytes().to_vec(),
        display: Some(path.display().to_string()),
    }
}

fn journal_token(token: &context_relay_native_runner::NativeObjectToken) -> NativeObjectToken {
    let mut topology = Vec::with_capacity(29);
    topology.push(1);
    topology.extend_from_slice(&token.reparse_tag().to_le_bytes());
    topology.extend_from_slice(&token.parent_volume().to_le_bytes());
    topology.extend_from_slice(token.parent_object());
    NativeObjectToken {
        volume: token.volume().to_le_bytes().to_vec(),
        object: token.object().to_vec(),
        topology,
    }
}

#[cfg(windows)]
fn sandbox_identity() -> NativeSandboxIdentity {
    NativeSandboxIdentity::Windows {
        moniker: "context-relay.native.00000000000000000000000000000001".to_owned(),
        sid: b"S-1-15-2-1-2-3-4-5-6-7".to_vec(),
    }
}

#[cfg(target_os = "macos")]
fn sandbox_identity() -> NativeSandboxIdentity {
    let generation_id = "00000000000000000000000000000001";
    let bundle_id = format!("com.contextrelay.native-runner.{generation_id}");
    let mut container = b"context-relay/macos-container/v1\0".to_vec();
    container.extend_from_slice(bundle_id.as_bytes());
    NativeSandboxIdentity::Macos {
        generation_id: generation_id.to_owned(),
        bundle_id,
        container,
        guardian_pgid: Some(4242),
        bundle_root: Some(
            context_relay_native_runner::MacRootIdentity::new(1, 2, 3, 4, 5, 0o040500)
                .unwrap()
                .encode(),
        ),
        signed_digest: Some(context_relay_protocol::Sha256Digest([6; 32])),
        container_root: Some(
            context_relay_native_runner::MacRootIdentity::new(7, 8, 9, 10, 11, 0o040700)
                .unwrap()
                .encode(),
        ),
        substate: context_relay_core::vault::MacGenerationSubstate::ContainerBound,
        state: context_relay_core::vault::MacGenerationState::Active,
    }
}

fn commit_success(vault: &mut Vault) {
    let transaction = vault.native_transaction(ID_1).unwrap().unwrap();
    let wal = vault.native_wal(ID_1).unwrap();
    let receipt = NativeApplyReceipt {
        legacy: ApplyReceipt {
            plan_id: transaction.plan_id,
            applied_hlc: clock(10),
            resulting_digests: wal.iter().map(|record| record.intended_applied.0).collect(),
        },
        targets: wal
            .iter()
            .map(|record| NativeReceiptEntry {
                target: record.target.clone(),
                fingerprint: record.intended_applied.clone(),
            })
            .collect(),
    };
    for step in &TransactionStep::ORDER[..18] {
        vault.enter_native_step(ID_1, *step).unwrap();
        vault.complete_native_step(ID_1, *step).unwrap();
    }
    vault
        .enter_native_step(ID_1, TransactionStep::CommitOwnershipAndReceipt)
        .unwrap();
    vault
        .commit_native_success(
            ID_1,
            &receipt,
            &[OwnershipChange {
                stable_id: "managed:item".to_owned(),
                structural_location: "fixture/0".to_owned(),
                semantic_digest: Sha256Digest([21; 32]),
                native_digest: Sha256Digest([22; 32]),
            }],
        )
        .unwrap();
}

fn applied_fixture(root: &std::path::Path) {
    fs::create_dir(root).unwrap();
    let target_path = root.join("target.txt");
    fs::write(&target_path, b"before").unwrap();
    let filesystem = OsNativeFileSystem::new();
    let before = filesystem.snapshot(&target_path).unwrap();
    let before_fingerprint = RestorableStateFingerprint(Sha256Digest(*before.fingerprint()));
    let applied_state =
        NativeState::regular_file(b"applied".to_vec(), before.metadata().unwrap().clone());
    let target = wire_path(&target_path);

    let mut vault = open_vault(root);
    let plan_id = ID_2.parse().unwrap();
    let approval = Sha256Digest([9; 32]);
    vault
        .begin_native_transaction(
            ID_1,
            NativePlanWrite {
                plan_id: &plan_id,
                approval_hash: &approval,
                payload: b"crash plan",
                created_ms: 1,
                expires_ms: 2,
            },
            sandbox_identity(),
        )
        .unwrap();
    let encoded = before.state().encode_v1().unwrap();
    vault
        .put_before_images_batch(
            &[BeforeImageWrite {
                id: "before-0",
                plan_id: Some(&plan_id),
                payload: &encoded,
                created_ms: 1,
            }],
            BeforeImagePolicy::new(1024 * 1024, 100),
        )
        .unwrap();
    let token = journal_token(before.object_token().unwrap());
    let applied = filesystem
        .compare_and_swap_with_nonce(
            &target_path,
            before.fingerprint(),
            &applied_state,
            plan_id.as_bytes(),
        )
        .unwrap();
    let applied_fingerprint =
        RestorableStateFingerprint(Sha256Digest(*applied.snapshot().fingerprint()));
    let applied_token = journal_token(applied.installed_token().unwrap());
    vault
        .prepare_native_wal(
            ID_1,
            &NativeWalWrite {
                target_sequence: 0,
                target: &target,
                object_token: &token,
                before_image_id: "before-0",
                operation_kind: MutationKind::Payload,
                expected: &before_fingerprint,
                intended_applied: &applied_fingerprint,
                intended_restored: &before_fingerprint,
            },
        )
        .unwrap();
    vault
        .transition_native_wal_with_applied_object_token(
            ID_1,
            0,
            NativeWalState::Applied,
            &applied_token,
        )
        .unwrap();
}

fn same_parent_delete_fixture(root: &std::path::Path) {
    fs::create_dir(root).unwrap();
    let target_root = root.join("targets");
    fs::create_dir(&target_root).unwrap();
    let paths = [
        target_root.join("first.txt"),
        target_root.join("second.txt"),
    ];
    fs::write(&paths[0], b"first-before").unwrap();
    fs::write(&paths[1], b"second-before").unwrap();
    let filesystem = OsNativeFileSystem::new();
    let snapshots = paths
        .iter()
        .map(|path| filesystem.snapshot(path).unwrap())
        .collect::<Vec<_>>();

    let mut vault = open_vault(root);
    let plan_id = ID_2.parse().unwrap();
    vault
        .begin_native_transaction(
            ID_1,
            NativePlanWrite {
                plan_id: &plan_id,
                approval_hash: &Sha256Digest([9; 32]),
                payload: b"same-parent delete crash plan",
                created_ms: 1,
                expires_ms: 2,
            },
            sandbox_identity(),
        )
        .unwrap();
    let encoded = snapshots
        .iter()
        .map(|snapshot| snapshot.state().encode_v1().unwrap())
        .collect::<Vec<_>>();
    vault
        .put_before_images_batch(
            &[
                BeforeImageWrite {
                    id: "delete-before-0",
                    plan_id: Some(&plan_id),
                    payload: &encoded[0],
                    created_ms: 1,
                },
                BeforeImageWrite {
                    id: "delete-before-1",
                    plan_id: Some(&plan_id),
                    payload: &encoded[1],
                    created_ms: 1,
                },
            ],
            BeforeImagePolicy::new(1024 * 1024, 100),
        )
        .unwrap();

    for (index, (path, before)) in paths.iter().zip(&snapshots).enumerate() {
        let target_sequence = u32::try_from(index).unwrap();
        let expected = RestorableStateFingerprint(Sha256Digest(*before.fingerprint()));
        let intended_state = before.absent_state();
        let intended = RestorableStateFingerprint(Sha256Digest(intended_state.fingerprint()));
        vault
            .prepare_native_wal(
                ID_1,
                &NativeWalWrite {
                    target_sequence,
                    target: &wire_path(path),
                    object_token: &journal_token(before.object_token().unwrap()),
                    before_image_id: if index == 0 {
                        "delete-before-0"
                    } else {
                        "delete-before-1"
                    },
                    operation_kind: MutationKind::Payload,
                    expected: &expected,
                    intended_applied: &intended,
                    intended_restored: &expected,
                },
            )
            .unwrap();
        let applied = filesystem
            .compare_and_swap_observed_with_candidate_provenance(
                path,
                before.fingerprint(),
                before.object_token(),
                &intended_state,
                plan_id.as_bytes(),
                &mut |candidate| {
                    vault
                        .record_native_wal_candidate(
                            ID_1,
                            target_sequence,
                            &journal_token(candidate),
                        )
                        .map_err(|_| context_relay_native_runner::RunnerError::ConcurrentChange)
                },
            )
            .unwrap();
        vault
            .transition_native_wal_with_applied_object_token(
                ID_1,
                target_sequence,
                NativeWalState::Applied,
                &journal_token(applied.installed_token().unwrap()),
            )
            .unwrap();
    }
    assert!(!paths[0].exists());
    assert!(!paths[1].exists());
}

#[cfg(windows)]
fn guarded_gap_fixture(root: &std::path::Path) {
    use std::{
        fs::OpenOptions,
        os::windows::{ffi::OsStrExt, io::AsRawHandle},
    };

    use sha2::{Digest, Sha256};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_BASIC_INFO, FileBasicInfo, SetFileInformationByHandle,
    };

    fs::create_dir(root).unwrap();
    let target_path = root.join("target.txt");
    fs::write(&target_path, b"before").unwrap();
    let filesystem = OsNativeFileSystem::new();
    let before = filesystem.snapshot(&target_path).unwrap();
    let before_fingerprint = RestorableStateFingerprint(Sha256Digest(*before.fingerprint()));
    let intended_state =
        NativeState::regular_file(b"applied".to_vec(), before.metadata().unwrap().clone());
    let intended_fingerprint =
        RestorableStateFingerprint(Sha256Digest(intended_state.fingerprint()));
    let target = wire_path(&target_path);

    let mut vault = open_vault(root);
    let plan_id = ID_2.parse().unwrap();
    vault
        .begin_native_transaction(
            ID_1,
            NativePlanWrite {
                plan_id: &plan_id,
                approval_hash: &Sha256Digest([9; 32]),
                payload: b"guarded gap plan",
                created_ms: 1,
                expires_ms: 2,
            },
            sandbox_identity(),
        )
        .unwrap();
    let encoded = before.state().encode_v1().unwrap();
    vault
        .put_before_images_batch(
            &[BeforeImageWrite {
                id: "before-0",
                plan_id: Some(&plan_id),
                payload: &encoded,
                created_ms: 1,
            }],
            BeforeImagePolicy::new(1024 * 1024, 100),
        )
        .unwrap();
    vault
        .prepare_native_wal(
            ID_1,
            &NativeWalWrite {
                target_sequence: 0,
                target: &target,
                object_token: &journal_token(before.object_token().unwrap()),
                before_image_id: "before-0",
                operation_kind: MutationKind::Payload,
                expected: &before_fingerprint,
                intended_applied: &intended_fingerprint,
                intended_restored: &before_fingerprint,
            },
        )
        .unwrap();

    let mut hasher = Sha256::new();
    for unit in target_path.file_name().unwrap().encode_wide() {
        hasher.update(unit.to_le_bytes());
    }
    let suffix = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let backup = root.join(format!(".context-relay-{suffix}.backup"));
    fs::rename(&target_path, &backup).unwrap();

    let metadata = before.metadata().unwrap();
    let basic = FILE_BASIC_INFO {
        CreationTime: metadata.creation_time(),
        LastAccessTime: metadata.last_access_time(),
        LastWriteTime: metadata.last_write_time(),
        ChangeTime: metadata.change_time(),
        FileAttributes: metadata.file_attributes(),
    };
    let backup_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&backup)
        .unwrap();
    assert_ne!(
        unsafe {
            SetFileInformationByHandle(
                backup_file.as_raw_handle(),
                FileBasicInfo,
                (&raw const basic).cast(),
                std::mem::size_of::<FILE_BASIC_INFO>() as u32,
            )
        },
        0,
    );
    backup_file.sync_all().unwrap();
    fs::write(root.join("fault-hit"), b"guarded-gap").unwrap();
    std::process::abort();
}

fn forward_fixture(root: &std::path::Path) {
    fs::create_dir(root).unwrap();
    for index in 0..3 {
        fs::write(
            root.join(format!("target-{index}.txt")),
            format!("before-{index}"),
        )
        .unwrap();
    }
    let mut vault = open_vault(root);
    let plan_id = ID_2.parse().unwrap();
    vault
        .begin_native_transaction(
            ID_1,
            NativePlanWrite {
                plan_id: &plan_id,
                approval_hash: &Sha256Digest([9; 32]),
                payload: b"forward crash plan",
                created_ms: 1,
                expires_ms: 2,
            },
            sandbox_identity(),
        )
        .unwrap();
}

fn forward_hit(root: &std::path::Path, expected: ForwardFaultPoint, actual: ForwardFaultPoint) {
    if actual == expected {
        fs::write(root.join("fault-hit"), actual.encode()).unwrap();
        std::process::abort();
    }
}

fn run_forward_child(root: &std::path::Path, vault: &mut Vault, fault: ForwardFaultPoint) -> ! {
    let filesystem = OsNativeFileSystem::new();
    let plan_id = ID_2.parse().unwrap();
    let paths = (0..3)
        .map(|index| root.join(format!("target-{index}.txt")))
        .collect::<Vec<_>>();
    let snapshots = paths
        .iter()
        .map(|path| filesystem.snapshot(path).unwrap())
        .collect::<Vec<_>>();
    let encoded_states = snapshots
        .iter()
        .map(|snapshot| snapshot.state().encode_v1().unwrap())
        .collect::<Vec<_>>();
    let before_ids = (0..3)
        .map(|index| format!("forward-before-{index}"))
        .collect::<Vec<_>>();
    let before_images = before_ids
        .iter()
        .zip(&encoded_states)
        .map(|(id, payload)| BeforeImageWrite {
            id,
            plan_id: Some(&plan_id),
            payload,
            created_ms: 1,
        })
        .collect::<Vec<_>>();
    forward_hit(
        root,
        fault,
        ForwardFaultPoint {
            action: ForwardAction::PutBeforeImages,
            moment: RecoveryMoment::Before,
            target_sequence: None,
        },
    );
    vault
        .put_before_images_batch(&before_images, BeforeImagePolicy::new(1024 * 1024, 100))
        .unwrap();
    forward_hit(
        root,
        fault,
        ForwardFaultPoint {
            action: ForwardAction::PutBeforeImages,
            moment: RecoveryMoment::After,
            target_sequence: None,
        },
    );

    for target_sequence in 0..3_u32 {
        let index = target_sequence as usize;
        let target = wire_path(&paths[index]);
        let before = &snapshots[index];
        let expected = RestorableStateFingerprint(Sha256Digest(*before.fingerprint()));
        let intended_state = NativeState::regular_file(
            format!("applied-{target_sequence}").into_bytes(),
            before.metadata().unwrap().clone(),
        );
        let intended = RestorableStateFingerprint(Sha256Digest(intended_state.fingerprint()));
        let kind = match target_sequence {
            0 => MutationKind::Payload,
            1 => MutationKind::ExecutableDisabled,
            2 => MutationKind::ActivationReference,
            _ => unreachable!(),
        };
        let token = journal_token(before.object_token().unwrap());
        let target_point = |action, moment| ForwardFaultPoint {
            action,
            moment,
            target_sequence: Some(target_sequence),
        };

        forward_hit(
            root,
            fault,
            target_point(ForwardAction::PrepareWal, RecoveryMoment::Before),
        );
        vault
            .prepare_native_wal(
                ID_1,
                &NativeWalWrite {
                    target_sequence,
                    target: &target,
                    object_token: &token,
                    before_image_id: &before_ids[index],
                    operation_kind: kind,
                    expected: &expected,
                    intended_applied: &intended,
                    intended_restored: &expected,
                },
            )
            .unwrap();
        forward_hit(
            root,
            fault,
            target_point(ForwardAction::PrepareWal, RecoveryMoment::After),
        );

        forward_hit(
            root,
            fault,
            target_point(ForwardAction::ApplyNative, RecoveryMoment::Before),
        );
        let applied = filesystem
            .compare_and_swap_with_nonce(
                &paths[index],
                before.fingerprint(),
                &intended_state,
                plan_id.as_bytes(),
            )
            .unwrap();
        assert!(applied.wrote());
        assert_eq!(applied.snapshot().fingerprint(), &intended.0.0);
        forward_hit(
            root,
            fault,
            target_point(ForwardAction::ApplyNative, RecoveryMoment::After),
        );

        forward_hit(
            root,
            fault,
            target_point(ForwardAction::MarkApplied, RecoveryMoment::Before),
        );
        vault
            .transition_native_wal_with_applied_object_token(
                ID_1,
                target_sequence,
                NativeWalState::Applied,
                &journal_token(applied.installed_token().unwrap()),
            )
            .unwrap();
        forward_hit(
            root,
            fault,
            target_point(ForwardAction::MarkApplied, RecoveryMoment::After),
        );
    }

    forward_hit(
        root,
        fault,
        ForwardFaultPoint {
            action: ForwardAction::Commit,
            moment: RecoveryMoment::Before,
            target_sequence: None,
        },
    );
    commit_success(vault);
    forward_hit(
        root,
        fault,
        ForwardFaultPoint {
            action: ForwardAction::Commit,
            moment: RecoveryMoment::After,
            target_sequence: None,
        },
    );
    panic!("forward child did not reach requested fault point");
}

struct AbortAt(RecoveryFaultPoint);

impl RecoveryFaultHook for AbortAt {
    fn at(&mut self, point: &RecoveryFaultPoint) -> Result<(), BoundaryError> {
        if point == &self.0 {
            std::process::abort();
        }
        Ok(())
    }
}

#[test]
fn cleanup_conflict_mark_is_restart_safe_for_every_durable_outcome() {
    for (outcome, expected_status) in [
        ("committed", NativeTransactionStatus::Committed),
        ("restored", NativeTransactionStatus::Restored),
        ("conflict", NativeTransactionStatus::Conflict),
    ] {
        for moment in [RecoveryMoment::Before, RecoveryMoment::After] {
            let root = TempVault::new(&format!(
                "native-{outcome}-cleanup-conflict-abort-{moment:?}"
            ));
            applied_fixture(root.path());
            if expected_status == NativeTransactionStatus::Committed {
                let mut vault = open_vault(root.path());
                commit_success(&mut vault);
            } else if expected_status == NativeTransactionStatus::Conflict {
                fs::write(root.path().join("target.txt"), b"third-party").unwrap();
            }

            let point = RecoveryFaultPoint {
                action: RecoveryAction::MarkCleanupConflict,
                moment,
                target_sequence: None,
            };
            let status = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "native_recovery_crash_child", "--nocapture"])
                .env(CHILD_ROOT, root.path())
                .env(CHILD_FAULT, point.encode())
                .env(CHILD_CLEANUP_CONFLICT, "1")
                .status()
                .unwrap();
            assert!(!status.success(), "{outcome}:{}", point.encode());

            let mut vault = open_vault(root.path());
            let snapshot = vault.native_transaction(ID_1).unwrap().unwrap();
            assert_eq!(snapshot.status, expected_status, "{outcome}");
            assert_eq!(snapshot.current_step, 19, "{outcome}");
            assert_eq!(snapshot.entered_step, 19, "{outcome}");
            assert_eq!(
                snapshot.sandbox_cleanup_state,
                if moment == RecoveryMoment::After {
                    NativeSandboxCleanupState::Conflict
                } else {
                    NativeSandboxCleanupState::Pending
                },
                "{outcome}",
            );
            let committed = expected_status == NativeTransactionStatus::Committed;
            assert_eq!(
                vault.receipt(&snapshot.plan_id).unwrap().is_some(),
                committed,
                "{outcome}",
            );
            assert_eq!(
                vault.native_receipt(&snapshot.plan_id).unwrap().is_some(),
                committed,
                "{outcome}",
            );
            assert_eq!(
                vault.native_ownership("managed:item").unwrap().is_some(),
                committed,
                "{outcome}",
            );

            let mut cleanup_calls = 0;
            let summary = {
                let mut io = OsNativeRecoveryIo::new(|_, _| {
                    cleanup_calls += 1;
                    Ok(RecoveryCleanup::Conflict)
                });
                recover_native_transactions(&mut vault, &mut io).unwrap()
            };
            assert_eq!(
                cleanup_calls,
                usize::from(moment == RecoveryMoment::Before),
                "{outcome}",
            );
            assert_eq!(summary.committed, usize::from(committed), "{outcome}");
            assert_eq!(
                summary.restored,
                usize::from(expected_status == NativeTransactionStatus::Restored),
                "{outcome}",
            );
            assert_eq!(
                summary.conflicts,
                usize::from(expected_status == NativeTransactionStatus::Conflict),
                "{outcome}",
            );
            assert_eq!(summary.cleanup_conflicts, 1, "{outcome}");

            let snapshot = vault.native_transaction(ID_1).unwrap().unwrap();
            assert_eq!(snapshot.status, expected_status, "{outcome}");
            assert_eq!(snapshot.current_step, 20, "{outcome}");
            assert_eq!(snapshot.entered_step, 20, "{outcome}");
            assert_eq!(
                snapshot.sandbox_cleanup_state,
                NativeSandboxCleanupState::Conflict,
                "{outcome}",
            );
            assert_eq!(
                vault.receipt(&snapshot.plan_id).unwrap().is_some(),
                committed,
                "{outcome}",
            );
            assert_eq!(
                vault.native_receipt(&snapshot.plan_id).unwrap().is_some(),
                committed,
                "{outcome}",
            );
            assert_eq!(
                vault.native_ownership("managed:item").unwrap().is_some(),
                committed,
                "{outcome}",
            );

            let mut no_retry =
                OsNativeRecoveryIo::new(|_, _| -> Result<RecoveryCleanup, BoundaryError> {
                    panic!("durably conflicted cleanup must not be retried")
                });
            let second = recover_native_transactions(&mut vault, &mut no_retry).unwrap();
            assert_eq!(second.recovered(), 0, "{outcome}");
            assert_eq!(second.cleanup_conflicts, 0, "{outcome}");
        }
    }
}

fn abort_same_parent_recovery_at(root: &std::path::Path, fault: RecoveryFaultPoint) {
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "native_recovery_crash_child", "--nocapture"])
        .env(CHILD_ROOT, root)
        .env(CHILD_FAULT, fault.encode())
        .status()
        .unwrap();
    if status.success() {
        let vault = open_vault(root);
        panic!(
            "fault was not reached: {}; transaction={:?}; wal={:?}",
            fault.encode(),
            vault.native_transaction(ID_1).unwrap(),
            vault.native_wal(ID_1).unwrap(),
        );
    }
}

#[test]
fn crash_after_restore_prepared_is_durable_and_the_second_recovery_is_idempotent() {
    let root = TempVault::new("native-recovery-crash-restore-prepared");
    applied_fixture(root.path());
    let fault = RecoveryFaultPoint {
        action: RecoveryAction::PrepareRestore,
        moment: RecoveryMoment::After,
        target_sequence: Some(0),
    };
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "native_recovery_crash_child", "--nocapture"])
        .env(CHILD_ROOT, root.path())
        .env(CHILD_FAULT, fault.encode())
        .status()
        .unwrap();
    assert!(!status.success());

    let mut vault = open_vault(root.path());
    assert_eq!(
        vault.native_wal(ID_1).unwrap()[0].state,
        NativeWalState::RestorePrepared,
    );
    assert_eq!(
        fs::read(root.path().join("target.txt")).unwrap(),
        b"applied"
    );

    let mut io = OsNativeRecoveryIo::new(|_, _| Ok(()));
    let summary = recover_native_transactions(&mut vault, &mut io).unwrap();
    assert_eq!(summary.restored, 1);
    assert_eq!(fs::read(root.path().join("target.txt")).unwrap(), b"before");
    let snapshot = vault.native_transaction(ID_1).unwrap().unwrap();
    assert_eq!(snapshot.status, NativeTransactionStatus::Restored);
    assert_eq!(snapshot.current_step, 20);
    assert_eq!(
        recover_native_transactions(&mut vault, &mut io)
            .unwrap()
            .recovered(),
        0,
    );
}

#[test]
fn same_parent_delete_rebind_is_restart_safe_before_and_after_its_durable_cas() {
    for moment in [RecoveryMoment::Before, RecoveryMoment::After] {
        let root = TempVault::new(&format!("native-delete-rebind-{moment:?}"));
        same_parent_delete_fixture(root.path());
        let fault = RecoveryFaultPoint {
            action: RecoveryAction::RebindAbsence,
            moment,
            target_sequence: Some(0),
        };
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "native_recovery_crash_child", "--nocapture"])
            .env(CHILD_ROOT, root.path())
            .env(CHILD_FAULT, fault.encode())
            .status()
            .unwrap();
        if status.success() {
            let vault = open_vault(root.path());
            panic!(
                "fault was not reached: {}; transaction={:?}; wal={:?}",
                fault.encode(),
                vault.native_transaction(ID_1).unwrap(),
                vault.native_wal(ID_1).unwrap(),
            );
        }

        let mut vault = open_vault(root.path());
        let wal = vault.native_wal(ID_1).unwrap();
        assert_eq!(wal[0].state, NativeWalState::RestorePrepared);
        assert_eq!(wal[1].state, NativeWalState::RestorePrepared);
        assert!(wal[1].restored_object_token.is_some());
        let mut io = OsNativeRecoveryIo::new(|_, _| Ok(()));
        let summary = recover_native_transactions(&mut vault, &mut io).unwrap();
        assert_eq!(summary.restored, 1, "{}", fault.encode());
        assert_eq!(summary.conflicts, 0, "{}", fault.encode());
        assert_eq!(
            fs::read(root.path().join("targets").join("first.txt")).unwrap(),
            b"first-before"
        );
        assert_eq!(
            fs::read(root.path().join("targets").join("second.txt")).unwrap(),
            b"second-before"
        );
        assert_eq!(
            vault.native_transaction(ID_1).unwrap().unwrap().status,
            NativeTransactionStatus::Restored,
        );
        assert_eq!(
            recover_native_transactions(&mut vault, &mut io)
                .unwrap()
                .recovered(),
            0,
        );
    }
}

#[test]
fn same_parent_delete_checkpoint_fails_closed_before_and_resumes_after() {
    for moment in [RecoveryMoment::Before, RecoveryMoment::After] {
        let root = TempVault::new(&format!("native-delete-checkpoint-{moment:?}"));
        same_parent_delete_fixture(root.path());
        let fault = RecoveryFaultPoint {
            action: RecoveryAction::CheckpointAbsence,
            moment,
            target_sequence: Some(0),
        };
        abort_same_parent_recovery_at(root.path(), fault);

        let mut vault = open_vault(root.path());
        let checkpoint = vault.native_wal(ID_1).unwrap()[1].absence_rebind.clone();
        assert_eq!(checkpoint.is_some(), moment == RecoveryMoment::After);
        let mut io = OsNativeRecoveryIo::new(|_, _| Ok(()));
        let summary = recover_native_transactions(&mut vault, &mut io).unwrap();
        let first = root.path().join("targets").join("first.txt");
        let second = root.path().join("targets").join("second.txt");
        assert_eq!(fs::read(&second).unwrap(), b"second-before");
        if moment == RecoveryMoment::Before {
            assert_eq!(summary.conflicts, 1);
            assert_eq!(summary.restored, 0);
            assert!(!first.exists());
            assert_eq!(
                vault.native_transaction(ID_1).unwrap().unwrap().status,
                NativeTransactionStatus::Conflict,
            );
        } else {
            assert_eq!(summary.conflicts, 0);
            assert_eq!(summary.restored, 1);
            assert_eq!(fs::read(&first).unwrap(), b"first-before");
            assert_eq!(
                vault.native_transaction(ID_1).unwrap().unwrap().status,
                NativeTransactionStatus::Restored,
            );
        }
    }
}

#[test]
fn same_parent_delete_recreate_delete_aba_conflicts_on_either_side_of_checkpoint() {
    for moment in [RecoveryMoment::Before, RecoveryMoment::After] {
        let root = TempVault::new(&format!("native-delete-checkpoint-aba-{moment:?}"));
        same_parent_delete_fixture(root.path());
        let fault = RecoveryFaultPoint {
            action: RecoveryAction::CheckpointAbsence,
            moment,
            target_sequence: Some(0),
        };
        abort_same_parent_recovery_at(root.path(), fault);

        let first = root.path().join("targets").join("first.txt");
        fs::write(&first, b"attacker-recreated").unwrap();
        fs::remove_file(&first).unwrap();
        let mut vault = open_vault(root.path());
        let mut io = OsNativeRecoveryIo::new(|_, _| Ok(()));
        let summary = recover_native_transactions(&mut vault, &mut io).unwrap();

        assert_eq!(summary.conflicts, 1, "{}", fault.encode());
        assert_eq!(summary.restored, 0, "{}", fault.encode());
        assert!(!first.exists());
        assert_eq!(
            fs::read(root.path().join("targets").join("second.txt")).unwrap(),
            b"second-before"
        );
        let wal = vault.native_wal(ID_1).unwrap();
        assert_eq!(wal[0].state, NativeWalState::Conflict);
        assert_eq!(wal[1].state, NativeWalState::Restored);
    }
}

#[test]
fn checkpointed_later_conflict_remains_readable_and_restart_safe() {
    let root = TempVault::new("native-delete-checkpoint-later-conflict");
    same_parent_delete_fixture(root.path());
    abort_same_parent_recovery_at(
        root.path(),
        RecoveryFaultPoint {
            action: RecoveryAction::CheckpointAbsence,
            moment: RecoveryMoment::After,
            target_sequence: Some(0),
        },
    );

    let second = root.path().join("targets").join("second.txt");
    fs::write(&second, b"attacker-changed-later-target").unwrap();
    abort_same_parent_recovery_at(
        root.path(),
        RecoveryFaultPoint {
            action: RecoveryAction::MarkConflict,
            moment: RecoveryMoment::After,
            target_sequence: Some(1),
        },
    );

    let mut vault = open_vault(root.path());
    let wal = vault.native_wal(ID_1).unwrap();
    assert_eq!(wal[1].state, NativeWalState::Conflict);
    assert!(wal[1].absence_rebind.is_some());
    let mut io = OsNativeRecoveryIo::new(|_, _| Ok(()));
    let summary = recover_native_transactions(&mut vault, &mut io).unwrap();
    assert_eq!(summary.conflicts, 1);
    assert_eq!(
        vault.native_transaction(ID_1).unwrap().unwrap().status,
        NativeTransactionStatus::Conflict,
    );
    assert!(
        vault
            .native_wal(ID_1)
            .unwrap()
            .iter()
            .all(|record| record.state == NativeWalState::Conflict)
    );
    assert_eq!(fs::read(&second).unwrap(), b"attacker-changed-later-target");
    assert!(!root.path().join("targets").join("first.txt").exists());
}

#[test]
fn same_parent_recreate_delete_aba_is_a_durable_recovery_conflict() {
    let root = TempVault::new("native-delete-rebind-aba");
    same_parent_delete_fixture(root.path());
    let second = root.path().join("targets").join("second.txt");
    fs::write(&second, b"attacker-recreated").unwrap();
    fs::remove_file(&second).unwrap();

    let mut vault = open_vault(root.path());
    let mut io = OsNativeRecoveryIo::new(|_, _| Ok(()));
    let summary = recover_native_transactions(&mut vault, &mut io).unwrap();

    assert_eq!(summary.conflicts, 1);
    assert_eq!(summary.restored, 0);
    assert_eq!(
        vault.native_transaction(ID_1).unwrap().unwrap().status,
        NativeTransactionStatus::Conflict,
    );
    assert!(
        vault
            .native_wal(ID_1)
            .unwrap()
            .iter()
            .all(|record| record.state == NativeWalState::Conflict)
    );
    assert!(!root.path().join("targets").join("first.txt").exists());
    assert!(!second.exists());
}

#[test]
fn committed_delete_recovery_cleans_exact_retained_backups_idempotently() {
    let root = TempVault::new("native-committed-delete-cleanup");
    same_parent_delete_fixture(root.path());
    let target_root = root.path().join("targets");
    let backup_count = || {
        fs::read_dir(&target_root)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".backup"))
            .count()
    };
    assert_eq!(backup_count(), 2);
    let mut vault = open_vault(root.path());
    commit_success(&mut vault);
    let mut io = OsNativeRecoveryIo::new(|_, _| Ok(()));

    let summary = recover_native_transactions(&mut vault, &mut io).unwrap();

    assert_eq!(summary.committed, 1);
    assert_eq!(backup_count(), 0);
    assert!(!target_root.join("first.txt").exists());
    assert!(!target_root.join("second.txt").exists());
    assert_eq!(
        recover_native_transactions(&mut vault, &mut io)
            .unwrap()
            .recovered(),
        0,
    );
}

#[test]
fn native_recovery_crash_child() {
    let Some(root) = std::env::var_os(CHILD_ROOT) else {
        return;
    };
    #[cfg(windows)]
    {
        if std::env::var_os(CHILD_GUARDED_GAP).is_some() {
            guarded_gap_fixture(std::path::Path::new(&root));
        }
    }
    let mut vault = open_vault(std::path::Path::new(&root));
    if let Ok(point) = std::env::var(CHILD_FORWARD) {
        run_forward_child(
            std::path::Path::new(&root),
            &mut vault,
            ForwardFaultPoint::decode(&point).unwrap(),
        );
    }
    if let Ok(moment) = std::env::var(CHILD_COMMIT) {
        if moment == "before" {
            std::process::abort();
        }
        commit_success(&mut vault);
        std::process::abort();
    }
    let point = RecoveryFaultPoint::decode(&std::env::var(CHILD_FAULT).unwrap()).unwrap();
    let cleanup_conflict = std::env::var_os(CHILD_CLEANUP_CONFLICT).is_some();
    let mut io = OsNativeRecoveryIo::new(move |_, _| {
        Ok(if cleanup_conflict {
            RecoveryCleanup::Conflict
        } else {
            RecoveryCleanup::Cleaned
        })
    });
    recover_native_transactions_with_faults(&mut vault, &mut io, &mut AbortAt(point)).unwrap();
}

#[cfg(windows)]
#[test]
fn a_real_crash_in_the_guarded_replace_gap_is_recovered_before_wal_classification() {
    let root = TempVault::new("native-guarded-gap-crash");
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "native_recovery_crash_child", "--nocapture"])
        .env(CHILD_ROOT, root.path())
        .env(CHILD_GUARDED_GAP, "1")
        .status()
        .unwrap();
    assert!(!status.success());
    assert_eq!(
        fs::read(root.path().join("fault-hit")).unwrap(),
        b"guarded-gap"
    );
    assert!(!root.path().join("target.txt").exists());

    let mut vault = open_vault(root.path());
    let mut io = OsNativeRecoveryIo::new(|_, _| Ok(()));
    let summary = recover_native_transactions(&mut vault, &mut io).unwrap();
    assert_eq!(summary.restored, 1);
    assert_eq!(summary.conflicts, 0);
    assert_eq!(fs::read(root.path().join("target.txt")).unwrap(), b"before");
    assert!(fs::read_dir(root.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".backup")
    }),);
    assert!(vault.native_wal(ID_1).unwrap().is_empty());
    assert_eq!(
        recover_native_transactions(&mut vault, &mut io)
            .unwrap()
            .recovered(),
        0,
    );
}

#[test]
fn step_19_is_the_only_success_linearization_point_across_real_aborts() {
    for moment in ["before", "after"] {
        let root = TempVault::new(&format!("native-step-19-{moment}"));
        applied_fixture(root.path());
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "native_recovery_crash_child", "--nocapture"])
            .env(CHILD_ROOT, root.path())
            .env(CHILD_COMMIT, moment)
            .status()
            .unwrap();
        assert!(!status.success());

        let mut vault = open_vault(root.path());
        let mut io = OsNativeRecoveryIo::new(|_, _| Ok(()));
        let summary = recover_native_transactions(&mut vault, &mut io).unwrap();
        let transaction = vault.native_transaction(ID_1).unwrap().unwrap();
        assert_eq!(transaction.current_step, 20);
        if moment == "before" {
            assert_eq!(summary.restored, 1);
            assert_eq!(transaction.status, NativeTransactionStatus::Restored);
            assert_eq!(fs::read(root.path().join("target.txt")).unwrap(), b"before");
            assert_eq!(vault.native_receipt(&transaction.plan_id).unwrap(), None);
        } else {
            assert_eq!(summary.committed, 1);
            assert_eq!(transaction.status, NativeTransactionStatus::Committed);
            assert_eq!(
                fs::read(root.path().join("target.txt")).unwrap(),
                b"applied"
            );
            assert!(
                vault
                    .native_receipt(&transaction.plan_id)
                    .unwrap()
                    .is_some()
            );
            assert!(vault.native_ownership("managed:item").unwrap().is_some());
        }
    }
}

#[cfg(windows)]
#[test]
fn windows_profile_cleanup_requires_the_exact_journaled_identity_and_a_durable_outcome() {
    let exact = |root: &std::path::Path| {
        let marker = root.join("profile.identity");
        fs::write(
            &marker,
            "context-relay.native.00000000000000000000000000000001|S-1-15-2-1-2-3-4-5-6-7",
        )
        .unwrap();
        let marker_for_cleanup = marker.clone();
        let cleanup = move |identity: RecoverySandboxIdentity, _| {
            let RecoverySandboxIdentity::Windows { moniker, sid } = identity else {
                return Err(BoundaryError::new("unexpected sandbox platform"));
            };
            let observed = fs::read_to_string(&marker_for_cleanup)
                .map_err(|error| BoundaryError::new(error.to_string()))?;
            if observed != format!("{moniker}|{sid}") {
                return Err(BoundaryError::new(
                    "journaled AppContainer identity mismatch",
                ));
            }
            fs::remove_file(&marker_for_cleanup)
                .map_err(|error| BoundaryError::new(error.to_string()))
        };
        (marker, cleanup)
    };

    let root = TempVault::new("native-profile-exact");
    applied_fixture(root.path());
    let (marker, cleanup) = exact(root.path());
    let mut vault = open_vault(root.path());
    recover_native_transactions(&mut vault, &mut OsNativeRecoveryIo::new(cleanup)).unwrap();
    assert!(!marker.exists());
    assert_eq!(
        vault
            .native_transaction(ID_1)
            .unwrap()
            .unwrap()
            .current_step,
        20
    );

    let root = TempVault::new("native-profile-mismatch");
    applied_fixture(root.path());
    let marker = root.path().join("profile.identity");
    fs::write(
        &marker,
        "context-relay.native.00000000000000000000000000000001|S-1-15-2-8-7-6-5-4-3-2",
    )
    .unwrap();
    let marker_for_cleanup = marker.clone();
    let cleanup = move |identity: RecoverySandboxIdentity, _| {
        let RecoverySandboxIdentity::Windows { moniker, sid } = identity else {
            return Err(BoundaryError::new("unexpected sandbox platform"));
        };
        let observed = fs::read_to_string(&marker_for_cleanup)
            .map_err(|error| BoundaryError::new(error.to_string()))?;
        if observed != format!("{moniker}|{sid}") {
            return Err(BoundaryError::new(
                "journaled AppContainer identity mismatch",
            ));
        }
        fs::remove_file(&marker_for_cleanup).map_err(|error| BoundaryError::new(error.to_string()))
    };
    let mut vault = open_vault(root.path());
    assert!(
        recover_native_transactions(&mut vault, &mut OsNativeRecoveryIo::new(cleanup)).is_err()
    );
    let terminal = vault.native_transaction(ID_1).unwrap().unwrap();
    assert_eq!(terminal.status, NativeTransactionStatus::Restored);
    assert_eq!(terminal.current_step, 19);
    assert!(marker.exists(), "mismatched external profile is preserved");

    let (marker, cleanup) = exact(root.path());
    recover_native_transactions(&mut vault, &mut OsNativeRecoveryIo::new(cleanup)).unwrap();
    assert!(!marker.exists());
    assert_eq!(
        vault
            .native_transaction(ID_1)
            .unwrap()
            .unwrap()
            .current_step,
        20
    );
}

#[test]
fn preexisting_nonmatching_bytes_metadata_and_topology_are_explicit_conflicts() {
    for mode in ["bytes", "metadata", "topology"] {
        let root = TempVault::new(&format!("native-recovery-conflict-{mode}"));
        applied_fixture(root.path());
        let target = root.path().join("target.txt");
        match mode {
            "bytes" => fs::write(&target, b"third-party").unwrap(),
            "metadata" => {
                let mut permissions = fs::metadata(&target).unwrap().permissions();
                permissions.set_readonly(true);
                fs::set_permissions(&target, permissions).unwrap();
            }
            "topology" => fs::hard_link(&target, root.path().join("third-party-link.txt")).unwrap(),
            _ => unreachable!(),
        }
        let preserved = fs::read(&target).unwrap();
        let mut vault = open_vault(root.path());
        let mut io = OsNativeRecoveryIo::new(|_, _| Ok(()));
        let summary = recover_native_transactions(&mut vault, &mut io).unwrap();
        assert_eq!(summary.conflicts, 1, "{mode}");
        assert_eq!(fs::read(&target).unwrap(), preserved, "{mode}");
        assert_eq!(
            vault.native_wal(ID_1).unwrap()[0].state,
            NativeWalState::Conflict,
            "{mode}",
        );
        assert_eq!(
            vault.native_transaction(ID_1).unwrap().unwrap().status,
            NativeTransactionStatus::Conflict,
            "{mode}",
        );
        assert_eq!(
            recover_native_transactions(&mut vault, &mut io)
                .unwrap()
                .recovered(),
            0,
            "{mode}",
        );
    }
}

#[test]
fn every_recovery_db_and_native_mutation_boundary_survives_a_real_abort() {
    let mut points = Vec::new();
    for action in [
        RecoveryAction::PoisonGeneration,
        RecoveryAction::BeginRecovery,
        RecoveryAction::FinishRecovery,
        RecoveryAction::CleanupSandbox,
        RecoveryAction::FinishCleanup,
    ] {
        for moment in [RecoveryMoment::Before, RecoveryMoment::After] {
            points.push(RecoveryFaultPoint {
                action,
                moment,
                target_sequence: None,
            });
        }
    }
    for action in [
        RecoveryAction::PrepareRestore,
        RecoveryAction::RestoreTarget,
        RecoveryAction::MarkRestored,
    ] {
        for moment in [RecoveryMoment::Before, RecoveryMoment::After] {
            points.push(RecoveryFaultPoint {
                action,
                moment,
                target_sequence: Some(0),
            });
        }
    }

    for (index, point) in points.into_iter().enumerate() {
        let root = TempVault::new(&format!("native-recovery-boundary-{index}"));
        applied_fixture(root.path());
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "native_recovery_crash_child", "--nocapture"])
            .env(CHILD_ROOT, root.path())
            .env(CHILD_FAULT, point.encode())
            .status()
            .unwrap();
        assert!(!status.success(), "{}", point.encode());

        let mut vault = open_vault(root.path());
        let mut io = OsNativeRecoveryIo::new(|_, _| Ok(()));
        recover_native_transactions(&mut vault, &mut io).unwrap();
        assert_eq!(
            fs::read(root.path().join("target.txt")).unwrap(),
            b"before",
            "{}",
            point.encode(),
        );
        let snapshot = vault.native_transaction(ID_1).unwrap().unwrap();
        assert_eq!(snapshot.status, NativeTransactionStatus::Restored);
        assert_eq!(snapshot.current_step, 20);
    }

    for moment in [RecoveryMoment::Before, RecoveryMoment::After] {
        let root = TempVault::new(&format!("native-recovery-conflict-boundary-{moment:?}"));
        applied_fixture(root.path());
        fs::write(root.path().join("target.txt"), b"third-party").unwrap();
        let point = RecoveryFaultPoint {
            action: RecoveryAction::MarkConflict,
            moment,
            target_sequence: Some(0),
        };
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "native_recovery_crash_child", "--nocapture"])
            .env(CHILD_ROOT, root.path())
            .env(CHILD_FAULT, point.encode())
            .status()
            .unwrap();
        assert!(!status.success());
        let mut vault = open_vault(root.path());
        let mut io = OsNativeRecoveryIo::new(|_, _| Ok(()));
        recover_native_transactions(&mut vault, &mut io).unwrap();
        assert_eq!(
            fs::read(root.path().join("target.txt")).unwrap(),
            b"third-party",
        );
        assert_eq!(
            vault.native_transaction(ID_1).unwrap().unwrap().status,
            NativeTransactionStatus::Conflict,
        );
    }
}

#[test]
fn every_forward_durable_mutation_boundary_aborts_in_a_child_for_all_target_roles() {
    let mut points = vec![
        ForwardFaultPoint {
            action: ForwardAction::PutBeforeImages,
            moment: RecoveryMoment::Before,
            target_sequence: None,
        },
        ForwardFaultPoint {
            action: ForwardAction::PutBeforeImages,
            moment: RecoveryMoment::After,
            target_sequence: None,
        },
    ];
    for target_sequence in 0..3 {
        for action in [
            ForwardAction::PrepareWal,
            ForwardAction::ApplyNative,
            ForwardAction::MarkApplied,
        ] {
            for moment in [RecoveryMoment::Before, RecoveryMoment::After] {
                points.push(ForwardFaultPoint {
                    action,
                    moment,
                    target_sequence: Some(target_sequence),
                });
            }
        }
    }
    for moment in [RecoveryMoment::Before, RecoveryMoment::After] {
        points.push(ForwardFaultPoint {
            action: ForwardAction::Commit,
            moment,
            target_sequence: None,
        });
    }

    for (index, point) in points.into_iter().enumerate() {
        let root = TempVault::new(&format!("native-forward-boundary-{index}"));
        forward_fixture(root.path());
        let encoded = point.encode();
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "native_recovery_crash_child", "--nocapture"])
            .env(CHILD_ROOT, root.path())
            .env(CHILD_FORWARD, &encoded)
            .status()
            .unwrap();
        assert!(!status.success(), "{encoded}");
        assert_eq!(
            fs::read_to_string(root.path().join("fault-hit")).unwrap(),
            encoded,
            "the child must reach the requested injection point",
        );

        let mut vault = open_vault(root.path());
        let mut io = OsNativeRecoveryIo::new(|_, _| Ok(()));
        let summary = recover_native_transactions(&mut vault, &mut io).unwrap();
        let committed =
            point.action == ForwardAction::Commit && point.moment == RecoveryMoment::After;
        let unattributed_apply = matches!(
            (point.action, point.moment),
            (ForwardAction::ApplyNative, RecoveryMoment::After)
                | (ForwardAction::MarkApplied, RecoveryMoment::Before)
        );
        let transaction = vault.native_transaction(ID_1).unwrap().unwrap();
        assert_eq!(transaction.current_step, 20, "{encoded}");
        assert_eq!(
            transaction.status,
            if committed {
                NativeTransactionStatus::Committed
            } else if unattributed_apply {
                NativeTransactionStatus::Conflict
            } else {
                NativeTransactionStatus::Restored
            },
            "{encoded}",
        );
        assert_eq!(summary.committed, usize::from(committed), "{encoded}");
        assert_eq!(
            summary.restored,
            usize::from(!committed && !unattributed_apply),
            "{encoded}",
        );
        assert_eq!(
            summary.conflicts,
            usize::from(unattributed_apply),
            "{encoded}",
        );
        for target_sequence in 0..3 {
            assert_eq!(
                fs::read(root.path().join(format!("target-{target_sequence}.txt"))).unwrap(),
                if committed
                    || (unattributed_apply && point.target_sequence == Some(target_sequence))
                {
                    format!("applied-{target_sequence}")
                } else {
                    format!("before-{target_sequence}")
                }
                .as_bytes(),
                "{encoded}",
            );
        }
        assert_eq!(
            recover_native_transactions(&mut vault, &mut io)
                .unwrap()
                .recovered(),
            0,
            "second restart must be idempotent: {encoded}",
        );
    }
}
