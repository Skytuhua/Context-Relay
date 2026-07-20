use std::{
    fs::{self, File, OpenOptions},
    path::{Component, Path, PathBuf},
};

use context_relay_protocol::PlanId;

use super::{
    engine::{BeforeImage, BoundaryError, MutationOutcome, NativeJournal},
    model::{
        ApprovedMutation, NativeApplyReceipt, NativeObjectToken, NativeTransactionPlan,
        TransactionStep,
    },
};
use crate::vault::{
    BeforeImagePolicy, BeforeImageWrite, NativePlanWrite, NativeSandboxIdentity, NativeWalState,
    NativeWalWrite, Vault, VaultError,
};

pub struct VaultNativeJournal<'a> {
    vault: &'a mut Vault,
    lock_root: PathBuf,
    profile_lock: Option<ProfileTransactionLock>,
    transaction_id: String,
    identity: NativeSandboxIdentity,
    plan_payload: Vec<u8>,
    created_ms: u64,
    before_image_policy: BeforeImagePolicy,
    plan_id: Option<PlanId>,
    before_images: Vec<BeforeImage>,
}

impl<'a> VaultNativeJournal<'a> {
    pub fn new(
        vault: &'a mut Vault,
        lock_root: impl Into<PathBuf>,
        transaction_id: impl Into<String>,
        identity: NativeSandboxIdentity,
        plan_payload: Vec<u8>,
        created_ms: u64,
        before_image_policy: BeforeImagePolicy,
    ) -> Self {
        Self {
            vault,
            lock_root: lock_root.into(),
            profile_lock: None,
            transaction_id: transaction_id.into(),
            identity,
            plan_payload,
            created_ms,
            before_image_policy,
            plan_id: None,
            before_images: Vec::new(),
        }
    }

    fn boundary<T>(result: Result<T, VaultError>) -> Result<T, BoundaryError> {
        result.map_err(|error| BoundaryError::new(error.to_string()))
    }

    fn require_profile_lock(&self) -> Result<(), BoundaryError> {
        self.profile_lock
            .as_ref()
            .map(|_| ())
            .ok_or_else(|| BoundaryError::new("native transaction profile lock is not held"))
    }

    fn release_profile_lock(&mut self) -> Result<(), BoundaryError> {
        self.profile_lock
            .take()
            .ok_or_else(|| BoundaryError::new("native transaction profile lock is not held"))?
            .release()
    }
}

#[cfg(unix)]
struct ProfileTransactionLock {
    directory: File,
}

#[cfg(unix)]
impl ProfileTransactionLock {
    fn acquire(root: &Path) -> Result<Self, BoundaryError> {
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

        validate_canonical_lock_root(root)?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(root)
            .map_err(|_| BoundaryError::new("native transaction profile lock root is unsafe"))?;
        let held = directory
            .metadata()
            .map_err(|_| BoundaryError::new("native transaction profile lock root is unsafe"))?;
        let named = fs::symlink_metadata(root)
            .map_err(|_| BoundaryError::new("native transaction profile lock root is unsafe"))?;
        if !held.is_dir()
            || !named.is_dir()
            || named.file_type().is_symlink()
            || held.dev() != named.dev()
            || held.ino() != named.ino()
        {
            return Err(BoundaryError::new(
                "native transaction profile lock root is unsafe",
            ));
        }
        directory.try_lock().map_err(profile_lock_error)?;
        let named_after = fs::symlink_metadata(root)
            .map_err(|_| BoundaryError::new("native transaction profile lock root changed"))?;
        if named_after.file_type().is_symlink()
            || held.dev() != named_after.dev()
            || held.ino() != named_after.ino()
        {
            let _ = File::unlock(&directory);
            return Err(BoundaryError::new(
                "native transaction profile lock root changed",
            ));
        }
        Ok(Self { directory })
    }

    fn release(self) -> Result<(), BoundaryError> {
        File::unlock(&self.directory)
            .map_err(|_| BoundaryError::new("native transaction profile lock release failed"))
    }
}

#[cfg(windows)]
struct ProfileTransactionLock {
    _root: File,
    lock_file: File,
}

#[cfg(windows)]
impl ProfileTransactionLock {
    fn acquire(root: &Path) -> Result<Self, BoundaryError> {
        use std::os::windows::fs::MetadataExt as _;

        const LOCK_NAME: &str = ".context-relay-native-transaction.lock";

        validate_canonical_lock_root(root)?;
        let root_handle = open_windows_lock_root(root)?;
        let root_metadata = root_handle
            .metadata()
            .map_err(|_| BoundaryError::new("native transaction profile lock root is unsafe"))?;
        if !root_metadata.is_dir()
            || root_metadata.file_attributes() & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT != 0
            || windows_file_identity(&open_windows_lock_root(root)?)?
                != windows_file_identity(&root_handle)?
        {
            return Err(BoundaryError::new(
                "native transaction profile lock root is unsafe",
            ));
        }

        let lock_path = root.join(LOCK_NAME);
        let lock_file = open_windows_lock_file(&lock_path)?;
        let lock_metadata = lock_file
            .metadata()
            .map_err(|_| BoundaryError::new("native transaction profile lock object is unsafe"))?;
        let lock_identity = windows_file_identity(&lock_file)?;
        if !lock_metadata.is_file()
            || lock_metadata.file_attributes() & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT != 0
            || lock_identity.links != 1
            || windows_file_identity(&open_windows_lock_file(&lock_path)?)? != lock_identity
        {
            return Err(BoundaryError::new(
                "native transaction profile lock object is unsafe",
            ));
        }
        lock_file.try_lock().map_err(profile_lock_error)?;
        if windows_file_identity(&open_windows_lock_root(root)?)?
            != windows_file_identity(&root_handle)?
            || windows_file_identity(&open_windows_lock_file(&lock_path)?)? != lock_identity
        {
            let _ = File::unlock(&lock_file);
            return Err(BoundaryError::new(
                "native transaction profile lock topology changed",
            ));
        }
        Ok(Self {
            _root: root_handle,
            lock_file,
        })
    }

    fn release(self) -> Result<(), BoundaryError> {
        File::unlock(&self.lock_file)
            .map_err(|_| BoundaryError::new("native transaction profile lock release failed"))
    }
}

#[cfg(windows)]
const WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
#[cfg(windows)]
const WINDOWS_FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
#[cfg(windows)]
const WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
#[cfg(windows)]
const WINDOWS_FILE_SHARE_READ: u32 = 0x0000_0001;
#[cfg(windows)]
const WINDOWS_FILE_SHARE_WRITE: u32 = 0x0000_0002;

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WindowsFileIdentity {
    volume: u32,
    index: u64,
    links: u32,
}

#[cfg(windows)]
fn open_windows_lock_root(path: &Path) -> Result<File, BoundaryError> {
    use std::os::windows::fs::OpenOptionsExt as _;

    OpenOptions::new()
        .read(true)
        .share_mode(WINDOWS_FILE_SHARE_READ | WINDOWS_FILE_SHARE_WRITE)
        .custom_flags(WINDOWS_FILE_FLAG_BACKUP_SEMANTICS | WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| BoundaryError::new("native transaction profile lock root is unsafe"))
}

#[cfg(windows)]
fn open_windows_lock_file(path: &Path) -> Result<File, BoundaryError> {
    use std::os::windows::fs::OpenOptionsExt as _;

    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .share_mode(WINDOWS_FILE_SHARE_READ | WINDOWS_FILE_SHARE_WRITE)
        .custom_flags(WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| BoundaryError::new("native transaction profile lock object is unsafe"))
}

#[cfg(windows)]
fn windows_file_identity(file: &File) -> Result<WindowsFileIdentity, BoundaryError> {
    use std::{mem::MaybeUninit, os::windows::io::AsRawHandle as _};

    use windows_sys::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle},
    };

    let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    if unsafe {
        GetFileInformationByHandle(file.as_raw_handle() as HANDLE, information.as_mut_ptr())
    } == 0
    {
        return Err(BoundaryError::new(
            "native transaction profile lock identity is unavailable",
        ));
    }
    let information = unsafe { information.assume_init() };
    Ok(WindowsFileIdentity {
        volume: information.dwVolumeSerialNumber,
        index: (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow),
        links: information.nNumberOfLinks,
    })
}

#[cfg(not(any(unix, windows)))]
struct ProfileTransactionLock;

#[cfg(not(any(unix, windows)))]
impl ProfileTransactionLock {
    fn acquire(_root: &Path) -> Result<Self, BoundaryError> {
        Err(BoundaryError::new(
            "native transaction profile locks are unsupported on this platform",
        ))
    }

    fn release(self) -> Result<(), BoundaryError> {
        Ok(())
    }
}

fn validate_canonical_lock_root(root: &Path) -> Result<(), BoundaryError> {
    if !root.is_absolute()
        || root
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(BoundaryError::new(
            "native transaction profile lock root is not canonical",
        ));
    }
    let canonical = fs::canonicalize(root)
        .map_err(|_| BoundaryError::new("native transaction profile lock root is unavailable"))?;
    let metadata = fs::symlink_metadata(root)
        .map_err(|_| BoundaryError::new("native transaction profile lock root is unavailable"))?;
    if canonical != root || !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(BoundaryError::new(
            "native transaction profile lock root is not canonical",
        ));
    }
    Ok(())
}

fn profile_lock_error(error: std::fs::TryLockError) -> BoundaryError {
    match error {
        std::fs::TryLockError::WouldBlock => {
            BoundaryError::new("native transaction profile lock is already held")
        }
        std::fs::TryLockError::Error(_) => {
            BoundaryError::new("native transaction profile lock acquisition failed")
        }
    }
}

impl NativeJournal for VaultNativeJournal<'_> {
    fn acquire_lock_and_begin(
        &mut self,
        plan: &NativeTransactionPlan,
    ) -> Result<(), BoundaryError> {
        if self.profile_lock.is_some() {
            return Err(BoundaryError::new(
                "native transaction profile lock is already held by this journal",
            ));
        }
        self.profile_lock = Some(ProfileTransactionLock::acquire(&self.lock_root)?);
        if let Err(primary) = Self::boundary(self.vault.begin_native_transaction(
            &self.transaction_id,
            NativePlanWrite {
                plan_id: &plan.setup.plan_id,
                approval_hash: &plan.setup.batch_hash,
                payload: &self.plan_payload,
                created_ms: self.created_ms,
                expires_ms: plan.setup.expires_at,
            },
            self.identity.clone(),
        )) {
            return Err(match self.release_profile_lock() {
                Ok(()) => primary,
                Err(release) => BoundaryError::new(format!(
                    "{primary}; native transaction profile lock release failed: {release}"
                )),
            });
        }
        if let Err(primary) = Self::boundary(
            self.vault
                .enter_native_step(&self.transaction_id, TransactionStep::AcquireLock),
        ) {
            return Err(match self.finish_compensated(&[]) {
                Ok(()) => primary,
                Err(compensation) => BoundaryError::new(format!(
                    "{primary}; native transaction start compensation failed: {compensation}"
                )),
            });
        }
        self.plan_id = Some(plan.setup.plan_id);
        Ok(())
    }

    fn enter_step(&mut self, step: TransactionStep) -> Result<(), BoundaryError> {
        if step == TransactionStep::AcquireLock && self.plan_id.is_none() {
            return Ok(());
        }
        self.require_profile_lock()?;
        Self::boundary(self.vault.enter_native_step(&self.transaction_id, step))
    }

    fn complete_step(&mut self, step: TransactionStep) -> Result<(), BoundaryError> {
        self.require_profile_lock()?;
        if step == TransactionStep::RestoreMatchingAppliedTargets {
            let snapshot = Self::boundary(self.vault.native_transaction(&self.transaction_id))?
                .ok_or_else(|| BoundaryError::new("native transaction does not exist"))?;
            return (snapshot.entered_step == step as u8)
                .then_some(())
                .ok_or_else(|| BoundaryError::new("native cleanup step was not entered"));
        }
        Self::boundary(self.vault.complete_native_step(&self.transaction_id, step))
    }

    fn put_before_images(&mut self, images: &[BeforeImage]) -> Result<(), BoundaryError> {
        self.require_profile_lock()?;
        let plan_id = self
            .plan_id
            .ok_or_else(|| BoundaryError::new("native transaction has not begun"))?;
        let writes = images
            .iter()
            .map(|image| BeforeImageWrite {
                id: &image.id,
                plan_id: Some(&plan_id),
                payload: &image.encrypted_state,
                created_ms: self.created_ms,
            })
            .collect::<Vec<_>>();
        Self::boundary(
            self.vault
                .put_before_images_batch(&writes, self.before_image_policy),
        )?;
        self.before_images = images.to_vec();
        Ok(())
    }

    fn prepare_mutation(
        &mut self,
        index: usize,
        mutation: &ApprovedMutation,
    ) -> Result<(), BoundaryError> {
        self.require_profile_lock()?;
        let image = self
            .before_images
            .get(index)
            .ok_or_else(|| BoundaryError::new("native before-image is missing"))?;
        if image.target != mutation.target || image.fingerprint != mutation.expected {
            return Err(BoundaryError::new(
                "native before-image does not match its mutation",
            ));
        }
        let target_sequence = u32::try_from(index)
            .map_err(|_| BoundaryError::new("native mutation index exceeds u32"))?;
        Self::boundary(self.vault.prepare_native_wal(
            &self.transaction_id,
            &NativeWalWrite {
                target_sequence,
                target: &mutation.target,
                object_token: &image.object_token,
                before_image_id: &image.id,
                operation_kind: mutation.kind,
                expected: &mutation.expected,
                intended_applied: &mutation.intended,
                intended_restored: &image.fingerprint,
            },
        ))
    }

    fn mark_mutation_applied(
        &mut self,
        index: usize,
        mutation: &ApprovedMutation,
        outcome: &MutationOutcome,
        applied_token: Option<&NativeObjectToken>,
    ) -> Result<(), BoundaryError> {
        self.require_profile_lock()?;
        if outcome.resulting_fingerprint != mutation.intended
            || outcome.wrote != (mutation.expected != mutation.intended)
        {
            return Err(BoundaryError::new(
                "native mutation outcome does not match its WAL",
            ));
        }
        let target_sequence = u32::try_from(index)
            .map_err(|_| BoundaryError::new("native mutation index exceeds u32"))?;
        if outcome.wrote {
            let applied_token = applied_token.ok_or_else(|| {
                BoundaryError::new("written native mutation provenance is missing")
            })?;
            Self::boundary(self.vault.transition_native_wal_with_applied_object_token(
                &self.transaction_id,
                target_sequence,
                NativeWalState::Applied,
                applied_token,
            ))
        } else {
            if applied_token.is_some() {
                return Err(BoundaryError::new(
                    "unchanged native mutation unexpectedly has installed provenance",
                ));
            }
            Self::boundary(self.vault.transition_native_wal(
                &self.transaction_id,
                target_sequence,
                NativeWalState::Applied,
            ))
        }
    }

    fn record_mutation_candidate(
        &mut self,
        index: usize,
        mutation: &ApprovedMutation,
        candidate_token: &NativeObjectToken,
    ) -> Result<(), BoundaryError> {
        self.require_profile_lock()?;
        if mutation.expected == mutation.intended {
            return Err(BoundaryError::new(
                "unchanged native mutation cannot have an install candidate",
            ));
        }
        let target_sequence = u32::try_from(index)
            .map_err(|_| BoundaryError::new("native mutation index exceeds u32"))?;
        Self::boundary(self.vault.record_native_wal_candidate(
            &self.transaction_id,
            target_sequence,
            candidate_token,
        ))
    }

    fn mark_mutation_conflict(
        &mut self,
        index: usize,
        applied_token: &NativeObjectToken,
    ) -> Result<(), BoundaryError> {
        self.require_profile_lock()?;
        let target_sequence = u32::try_from(index)
            .map_err(|_| BoundaryError::new("native mutation index exceeds u32"))?;
        Self::boundary(self.vault.transition_native_wal_with_applied_object_token(
            &self.transaction_id,
            target_sequence,
            NativeWalState::Conflict,
            applied_token,
        ))
    }

    fn mark_mutation_applied_for_recovery(
        &mut self,
        index: usize,
        mutation: &ApprovedMutation,
        applied_token: &NativeObjectToken,
    ) -> Result<(), BoundaryError> {
        self.require_profile_lock()?;
        if mutation.expected == mutation.intended {
            return Err(BoundaryError::new(
                "unchanged native mutation cannot require applied recovery",
            ));
        }
        let target_sequence = u32::try_from(index)
            .map_err(|_| BoundaryError::new("native mutation index exceeds u32"))?;
        Self::boundary(self.vault.record_native_wal_candidate(
            &self.transaction_id,
            target_sequence,
            applied_token,
        ))
    }

    fn record_mutation_restored_candidate(
        &mut self,
        index: usize,
        candidate_token: &NativeObjectToken,
    ) -> Result<(), BoundaryError> {
        self.require_profile_lock()?;
        let target_sequence = u32::try_from(index)
            .map_err(|_| BoundaryError::new("native mutation index exceeds u32"))?;
        Self::boundary(self.vault.record_native_wal_restored_candidate(
            &self.transaction_id,
            target_sequence,
            candidate_token,
        ))
    }

    fn checkpoint_mutation_applied_absence(
        &mut self,
        index: usize,
        later_index: usize,
        expected_old_token: &NativeObjectToken,
        new_token: &NativeObjectToken,
    ) -> Result<(), BoundaryError> {
        self.require_profile_lock()?;
        let target_sequence = u32::try_from(index)
            .map_err(|_| BoundaryError::new("native mutation index exceeds u32"))?;
        let later_sequence = u32::try_from(later_index)
            .map_err(|_| BoundaryError::new("native mutation index exceeds u32"))?;
        Self::boundary(self.vault.checkpoint_native_wal_absence_rebind(
            &self.transaction_id,
            target_sequence,
            later_sequence,
            expected_old_token,
            new_token,
        ))
    }

    fn rebind_mutation_applied_absence(
        &mut self,
        index: usize,
        later_index: usize,
        expected_old_token: &NativeObjectToken,
        new_token: &NativeObjectToken,
    ) -> Result<(), BoundaryError> {
        self.require_profile_lock()?;
        let target_sequence = u32::try_from(index)
            .map_err(|_| BoundaryError::new("native mutation index exceeds u32"))?;
        let later_sequence = u32::try_from(later_index)
            .map_err(|_| BoundaryError::new("native mutation index exceeds u32"))?;
        Self::boundary(self.vault.rebind_native_wal_applied_absence(
            &self.transaction_id,
            target_sequence,
            later_sequence,
            expected_old_token,
            new_token,
        ))
    }

    fn prepare_compensation(&mut self) -> Result<(), BoundaryError> {
        self.require_profile_lock()?;
        Self::boundary(self.vault.begin_native_recovery(&self.transaction_id))?;
        for record in Self::boundary(self.vault.native_wal(&self.transaction_id))? {
            if record.state == NativeWalState::Applied
                || (record.state == NativeWalState::Prepared
                    && record.applied_object_token.is_some())
            {
                Self::boundary(self.vault.transition_native_wal(
                    &self.transaction_id,
                    record.target_sequence,
                    NativeWalState::RestorePrepared,
                ))?;
            }
        }
        Ok(())
    }

    fn commit_native_transaction(
        &mut self,
        plan: &NativeTransactionPlan,
        receipt: &NativeApplyReceipt,
    ) -> Result<(), BoundaryError> {
        self.require_profile_lock()?;
        Self::boundary(self.vault.commit_native_success(
            &self.transaction_id,
            receipt,
            &plan.ownership_changes,
        ))
    }

    fn finish_committed(&mut self) -> Result<(), BoundaryError> {
        self.require_profile_lock()?;
        Self::boundary(self.vault.finish_native_cleanup(&self.transaction_id))?;
        self.release_profile_lock()
    }

    fn finish_compensated(
        &mut self,
        conflict_target_sequences: &[u32],
    ) -> Result<(), BoundaryError> {
        self.require_profile_lock()?;
        Self::boundary(self.vault.begin_native_recovery(&self.transaction_id))?;
        let mut conflict = false;
        for record in Self::boundary(self.vault.native_wal(&self.transaction_id))? {
            if conflict_target_sequences.contains(&record.target_sequence) {
                if record.state != NativeWalState::Conflict {
                    Self::boundary(self.vault.transition_native_wal(
                        &self.transaction_id,
                        record.target_sequence,
                        NativeWalState::Conflict,
                    ))?;
                }
                conflict = true;
                continue;
            }
            match record.state {
                NativeWalState::Prepared => Self::boundary(self.vault.transition_native_wal(
                    &self.transaction_id,
                    record.target_sequence,
                    NativeWalState::Restored,
                ))?,
                NativeWalState::Applied => {
                    Self::boundary(self.vault.transition_native_wal(
                        &self.transaction_id,
                        record.target_sequence,
                        NativeWalState::RestorePrepared,
                    ))?;
                    Self::boundary(self.vault.transition_native_wal(
                        &self.transaction_id,
                        record.target_sequence,
                        NativeWalState::Restored,
                    ))?;
                }
                NativeWalState::RestorePrepared => {
                    Self::boundary(self.vault.transition_native_wal(
                        &self.transaction_id,
                        record.target_sequence,
                        NativeWalState::Restored,
                    ))?
                }
                NativeWalState::Restored => {}
                NativeWalState::Conflict => conflict = true,
            }
        }
        Self::boundary(
            self.vault
                .finish_native_recovery(&self.transaction_id, conflict),
        )?;
        Self::boundary(self.vault.finish_native_cleanup(&self.transaction_id))?;
        self.release_profile_lock()
    }
}
