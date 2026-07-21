use std::{
    ffi::{CStr, CString, c_void},
    fs::{self, File},
    io::Read,
    mem::{size_of, zeroed},
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd},
        unix::ffi::OsStrExt,
    },
    path::{Component, Path, PathBuf},
    ptr::null_mut,
};

use minicbor::{Decoder, Encoder};
use sha2::{Digest, Sha256};

use super::{
    CaptureError, NativeMetadata, NativeObjectToken, NativeSnapshot, NativeState, fingerprint,
};
use crate::RunnerError;

const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;
const MODE_DIRECTORY: u32 = libc::S_IFDIR as u32;
const MODE_MASK: u32 = libc::S_IFMT as u32;
const MODE_REGULAR: u32 = libc::S_IFREG as u32;
const MODE_SYMLINK: u32 = libc::S_IFLNK as u32;
const MAX_SNAPSHOT_BYTES: u64 = 200 * 1024 * 1024;
const MAX_SECURITY_BYTES: usize = 1024 * 1024;
const MAX_XATTRS: usize = 128;
type ExtendedAttributes = Vec<(Vec<u8>, Vec<u8>)>;

#[cfg(test)]
static PRE_TARGET_MUTATION_TEST_HOOK: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>> =
    std::sync::Mutex::new(None);
#[cfg(test)]
static PRE_INSTALL_TEST_HOOK: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>> =
    std::sync::Mutex::new(None);
#[cfg(test)]
static PRE_BACKUP_REMOVAL_TEST_HOOK: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>> =
    std::sync::Mutex::new(None);
#[cfg(test)]
static POST_MISSING_SNAPSHOT_TEST_HOOK: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>> =
    std::sync::Mutex::new(None);
#[cfg(test)]
static PRE_ROLLBACK_MOVE_TEST_HOOK: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>> =
    std::sync::Mutex::new(None);
#[cfg(test)]
static RECOVERY_AFTER_PARENT_CHECK_TEST_HOOK: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
fn run_pre_target_mutation_test_hook() {
    if let Some(hook) = PRE_TARGET_MUTATION_TEST_HOOK
        .lock()
        .expect("test hook lock")
        .take()
    {
        hook();
    }
}

#[cfg(test)]
fn run_pre_backup_removal_test_hook() {
    if let Some(hook) = PRE_BACKUP_REMOVAL_TEST_HOOK
        .lock()
        .expect("test hook lock")
        .take()
    {
        hook();
    }
}

#[cfg(test)]
fn run_pre_install_test_hook() {
    if let Some(hook) = PRE_INSTALL_TEST_HOOK.lock().expect("test hook lock").take() {
        hook();
    }
}

#[cfg(test)]
fn run_post_missing_snapshot_test_hook() {
    if let Some(hook) = POST_MISSING_SNAPSHOT_TEST_HOOK
        .lock()
        .expect("test hook lock")
        .take()
    {
        hook();
    }
}

#[cfg(test)]
fn run_pre_rollback_move_test_hook() {
    if let Some(hook) = PRE_ROLLBACK_MOVE_TEST_HOOK
        .lock()
        .expect("test hook lock")
        .take()
    {
        hook();
    }
}

#[cfg(test)]
fn run_recovery_after_parent_check_test_hook() {
    if let Some(hook) = RECOVERY_AFTER_PARENT_CHECK_TEST_HOOK
        .lock()
        .expect("test hook lock")
        .take()
    {
        hook();
    }
}

unsafe extern "C" {
    fn acl_free(object: *mut c_void) -> libc::c_int;
    fn acl_init(count: libc::c_int) -> *mut c_void;
    fn acl_get_fd_np(fd: libc::c_int, acl_type: libc::c_int) -> *mut c_void;
    fn acl_set_fd_np(fd: libc::c_int, acl: *mut c_void, acl_type: libc::c_int) -> libc::c_int;
    fn acl_from_text(text: *const libc::c_char) -> *mut c_void;
    fn acl_to_text(acl: *mut c_void, length: *mut libc::ssize_t) -> *mut libc::c_char;
}

pub(super) struct CapturedFile {
    pub bytes: Vec<u8>,
    pub metadata: NativeMetadata,
    pub token: NativeObjectToken,
}

pub(super) struct CapturedNode {
    pub directory: bool,
    pub token: NativeObjectToken,
    pub fingerprint: [u8; 32],
    unsafe_topology: bool,
}

impl CapturedNode {
    pub const fn unsafe_topology(&self) -> bool {
        self.unsafe_topology
    }
}

pub(super) fn snapshot(path: &Path) -> Result<NativeSnapshot, RunnerError> {
    let parent = OpenParent::new(path)?;
    let snapshot = snapshot_named(&parent.directory, &parent.name)?;
    if !identity_matches_path(&parent.directory, &parent.path)? {
        return Err(RunnerError::ConcurrentChange);
    }
    Ok(snapshot)
}

pub(super) fn compare_and_swap_with_provenance(
    path: &Path,
    expected: &[u8; 32],
    expected_token: Option<&NativeObjectToken>,
    desired: &NativeState,
    transaction_nonce: &[u8; 16],
    persist_candidate: &mut dyn FnMut(&NativeObjectToken) -> Result<(), RunnerError>,
) -> Result<super::NativeMutationOutcome, super::NativeMutationFailure> {
    let parent = OpenParent::new(path).map_err(super::NativeMutationFailure::from)?;
    let current = snapshot_named(&parent.directory, &parent.name)
        .map_err(super::NativeMutationFailure::from)?;
    if current.fingerprint() != expected
        || expected_token.is_some_and(|token| current.object_token() != Some(token))
        || !identity_matches_path(&parent.directory, &parent.path)
            .map_err(super::NativeMutationFailure::from)?
    {
        return Err(RunnerError::ConcurrentChange.into());
    }
    if matches!(
        (current.state(), desired),
        (NativeState::Absent { .. }, NativeState::Absent { .. })
    ) || current.fingerprint() == &fingerprint(desired)
    {
        return Ok(super::NativeMutationOutcome {
            wrote: false,
            snapshot: current,
            installed_token: None,
        });
    }
    let mut installed_token = None;
    let write = match desired {
        NativeState::Absent { .. } => delete_regular_file(
            &parent,
            current
                .object_token()
                .ok_or(RunnerError::ConcurrentChange)
                .map_err(super::NativeMutationFailure::from)?,
            expected,
            &mut installed_token,
            persist_candidate,
        ),
        NativeState::RegularFile { bytes, metadata } => replace_regular_file(
            &parent,
            current.object_token(),
            matches!(current.state(), NativeState::RegularFile { .. }),
            expected,
            bytes,
            metadata,
            fingerprint(desired),
            transaction_nonce,
            &mut installed_token,
            persist_candidate,
        ),
    };
    if let Err(error) = write {
        let Some(token) = installed_token else {
            return Err(error.into());
        };
        return Err(super::NativeMutationFailure::installed(error, token));
    }
    let installed_token = installed_token
        .ok_or_else(|| super::NativeMutationFailure::from(RunnerError::ConcurrentChange))?;
    let snapshot = snapshot_named(&parent.directory, &parent.name)
        .map_err(|error| super::NativeMutationFailure::installed(error, installed_token.clone()))?;
    if !identity_matches_path(&parent.directory, &parent.path)
        .map_err(|error| super::NativeMutationFailure::installed(error, installed_token.clone()))?
        || (!matches!(
            (snapshot.state(), desired),
            (NativeState::Absent { .. }, NativeState::Absent { .. })
        ) && snapshot.fingerprint() != &fingerprint(desired))
    {
        return Err(super::NativeMutationFailure::installed(
            RunnerError::ConcurrentChange,
            installed_token,
        ));
    }
    Ok(super::NativeMutationOutcome {
        wrote: true,
        snapshot,
        installed_token: Some(installed_token),
    })
}

pub(super) fn create_new_file(path: &Path) -> Result<File, RunnerError> {
    let parent = OpenParent::new(path)?;
    let file = openat(
        &parent.directory,
        &parent.name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o600,
    )?;
    flush_directory(&parent.directory)?;
    Ok(file)
}

pub(super) fn identity_matches_path(file: &File, path: &Path) -> Result<bool, RunnerError> {
    let reopened = open_path(path, libc::O_RDONLY | libc::O_NONBLOCK)?;
    Ok(raw_node(file)?.same_object(&raw_node(&reopened)?))
}

pub(super) fn capture_file(path: &Path) -> Result<CapturedFile, CaptureError> {
    let parent = OpenParent::new(path)?;
    let captured = capture_named_file(&parent.directory, &parent.name)?;
    if !identity_matches_path(&parent.directory, &parent.path)? {
        return Err(CaptureError::Runner(RunnerError::ConcurrentChange));
    }
    Ok(captured)
}

fn capture_named_file(parent: &File, name: &CStr) -> Result<CapturedFile, CaptureError> {
    let mut file = match openat(
        parent,
        name,
        libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    ) {
        Ok(file) => file,
        Err(RunnerError::Io) if last_errno() == libc::ENOENT => return Err(CaptureError::Missing),
        Err(error) => return Err(CaptureError::Runner(error)),
    };
    let before = raw_node(&file)?;
    if !before.regular() || before.links != 1 {
        return Err(CaptureError::Runner(RunnerError::UnsafeTopology));
    }
    if before.size > MAX_SNAPSHOT_BYTES {
        return Err(CaptureError::Runner(RunnerError::LimitExceeded));
    }
    shared_lock(&file)?;
    let parent_node = raw_node(parent)?;
    if !parent_node.directory() {
        return Err(CaptureError::Runner(RunnerError::UnsafeTopology));
    }
    let mut bytes = Vec::with_capacity(before.size as usize);
    file.read_to_end(&mut bytes)
        .map_err(|_| CaptureError::Runner(RunnerError::Io))?;
    if bytes.len() as u64 != before.size {
        return Err(CaptureError::Runner(RunnerError::ConcurrentChange));
    }
    let security = capture_security(&file, &before, &parent_node)?;
    let after = raw_node(&file)?;
    let named =
        raw_at(parent, name).map_err(|_| CaptureError::Runner(RunnerError::ConcurrentChange))?;
    if !before.same_snapshot(&after)
        || !before.same_object(&named)
        || !raw_node(parent)?.same_snapshot(&parent_node)
    {
        return Err(CaptureError::Runner(RunnerError::ConcurrentChange));
    }
    let (parent_attributes, parent_link_count) = parent_marker(&parent_node);
    Ok(CapturedFile {
        bytes,
        metadata: NativeMetadata {
            file_attributes: 0,
            creation_time: timestamp(before.birth_seconds, before.birth_nanoseconds)?,
            last_access_time: timestamp(before.access_seconds, before.access_nanoseconds)?,
            last_write_time: timestamp(before.write_seconds, before.write_nanoseconds)?,
            change_time: timestamp(before.change_seconds, before.change_nanoseconds)?,
            security_descriptor: security.encoded,
            alternate_streams: Vec::new(),
            link_count: before.links,
            parent_attributes,
            parent_link_count,
        },
        token: token(&before, &parent_node),
    })
}

pub(super) fn capture_node(path: &Path, forbid_xattrs: bool) -> Result<CapturedNode, RunnerError> {
    let mut file = open_path(path, libc::O_RDONLY | libc::O_NONBLOCK)?;
    let before = raw_node(&file)?;
    if !before.regular() && !before.directory() {
        return Err(RunnerError::UnsafeTopology);
    }
    if before.regular() {
        if before.links != 1 {
            return Err(RunnerError::UnsafeTopology);
        }
        if before.size > MAX_SNAPSHOT_BYTES {
            return Err(RunnerError::LimitExceeded);
        }
        shared_lock(&file)?;
    }
    let parent_path = path.parent().unwrap_or(path);
    let parent = open_path(parent_path, libc::O_RDONLY | libc::O_DIRECTORY)?;
    let parent_node = raw_node(&parent)?;
    let security = capture_security(&file, &before, &parent_node)?;
    if forbid_xattrs && security.xattr_count != 0 {
        return Err(RunnerError::UnsafeTopology);
    }
    let mut hash = Sha256::new();
    hash.update(b"context-relay/native-tree-node/v1\0");
    hash.update([u8::from(before.directory())]);
    hash.update(before.mode.to_be_bytes());
    hash.update(before.links.to_be_bytes());
    hash.update(before.size.to_be_bytes());
    hash.update(timestamp(before.birth_seconds, before.birth_nanoseconds)?.to_be_bytes());
    hash.update(timestamp(before.write_seconds, before.write_nanoseconds)?.to_be_bytes());
    hash.update(timestamp(before.change_seconds, before.change_nanoseconds)?.to_be_bytes());
    hash.update((security.encoded.len() as u64).to_be_bytes());
    hash.update(&security.encoded);
    if before.regular() {
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = file.read(&mut buffer).map_err(|_| RunnerError::Io)?;
            if count == 0 {
                break;
            }
            hash.update(&buffer[..count]);
        }
    }
    let after = raw_node(&file)?;
    if !before.same_snapshot(&after)
        || !identity_matches_path(&file, path)?
        || !identity_matches_path(&parent, parent_path)?
    {
        return Err(RunnerError::ConcurrentChange);
    }
    Ok(CapturedNode {
        directory: before.directory(),
        token: token(&before, &parent_node),
        fingerprint: hash.finalize().into(),
        unsafe_topology: before.regular() && before.links != 1,
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "the guarded replace phases require both before and intended identities"
)]
fn replace_regular_file(
    parent: &OpenParent,
    expected: Option<&NativeObjectToken>,
    expected_present: bool,
    expected_fingerprint: &[u8; 32],
    bytes: &[u8],
    metadata: &NativeMetadata,
    intended_fingerprint: [u8; 32],
    transaction_nonce: &[u8; 16],
    installed_token: &mut Option<NativeObjectToken>,
    persist_candidate: &mut dyn FnMut(&NativeObjectToken) -> Result<(), RunnerError>,
) -> Result<(), RunnerError> {
    let security = PosixSecurity::decode(&metadata.security_descriptor)?;
    validate_metadata(metadata, &security)?;
    if !raw_node(&parent.directory)?.directory()
        || !identity_matches_path(&parent.directory, &parent.path)?
    {
        return Err(RunnerError::ConcurrentChange);
    }
    let (mut temporary, mut cleanup) = create_adjacent_temp(parent, transaction_nonce)?;
    use std::io::Write as _;
    temporary.write_all(bytes).map_err(|_| RunnerError::Io)?;
    full_sync(&temporary)?;
    restore_security(&temporary, &security)?;
    set_birthtime(&temporary, metadata.creation_time)?;
    set_times(
        &temporary,
        metadata.last_access_time,
        metadata.last_write_time,
    )?;
    set_flags(&temporary, security.flags)?;
    full_sync(&temporary)?;

    let staged = snapshot_named(&parent.directory, &cleanup.name)?;
    if staged.fingerprint() != &intended_fingerprint {
        return Err(RunnerError::ConcurrentChange);
    }
    let staged_token = staged
        .object_token()
        .ok_or(RunnerError::ConcurrentChange)?
        .clone();
    if !identity_matches_path(&parent.directory, &parent.path)? {
        return Err(RunnerError::ConcurrentChange);
    }
    let _expected_handle = if expected_present {
        verify_expected(parent, expected)?
    } else {
        validate_absent(parent, expected, expected_fingerprint)?;
        None
    };

    #[cfg(test)]
    run_pre_target_mutation_test_hook();

    if !identity_matches_path(&parent.directory, &parent.path)? {
        return Err(RunnerError::ConcurrentChange);
    }

    persist_candidate(&staged_token)?;
    let backup = expected_present.then(|| backup_name(&parent.name));
    if let (Some(expected), Some(backup)) = (expected, backup.as_ref()) {
        rename_exclusive(&parent.directory, &parent.name, backup)?;
        flush_directory(&parent.directory)?;
        if validate_named(
            &parent.directory,
            backup,
            Some(expected),
            expected_fingerprint,
        )
        .is_err()
        {
            let _ = restore_moved_name(parent, backup);
            return Err(RunnerError::ConcurrentChange);
        }
    } else {
        validate_absent(parent, expected, expected_fingerprint)?;
    }

    #[cfg(test)]
    run_pre_install_test_hook();

    if !identity_matches_path(&parent.directory, &parent.path)? {
        return recover_replace_error(
            parent,
            expected_fingerprint,
            &intended_fingerprint,
            transaction_nonce,
            backup.is_some(),
            None,
            RunnerError::ConcurrentChange,
        );
    }

    if let Err(error) = rename_exclusive(&parent.directory, &cleanup.name, &parent.name) {
        return recover_replace_error(
            parent,
            expected_fingerprint,
            &intended_fingerprint,
            transaction_nonce,
            backup.is_some(),
            None,
            error,
        );
    }
    cleanup.armed = false;
    *installed_token = Some(staged_token.clone());
    if let Err(error) = flush_directory(&parent.directory).and_then(|()| {
        validate_named(
            &parent.directory,
            &parent.name,
            Some(&staged_token),
            &intended_fingerprint,
        )
        .map(|_| ())
    }) {
        if backup.is_none()
            && rollback_created_target(parent, &cleanup.name, &staged_token, &intended_fingerprint)
                .is_ok()
        {
            cleanup.armed = true;
            return Err(error);
        }
        return recover_replace_error(
            parent,
            expected_fingerprint,
            &intended_fingerprint,
            transaction_nonce,
            backup.is_some(),
            Some(&staged_token),
            error,
        );
    }

    if let (Some(expected), Some(backup)) = (expected, backup.as_ref()) {
        validate_named(
            &parent.directory,
            &parent.name,
            Some(&staged_token),
            &intended_fingerprint,
        )?;
        validate_named(
            &parent.directory,
            backup,
            Some(expected),
            expected_fingerprint,
        )?;
        remove_exact_named(
            parent,
            backup,
            expected,
            expected_fingerprint,
            NamedGuard {
                name: &parent.name,
                token: &staged_token,
                fingerprint: &intended_fingerprint,
            },
        )?;
    }
    validate_named(
        &parent.directory,
        &parent.name,
        Some(&staged_token),
        &intended_fingerprint,
    )?;
    Ok(())
}

fn delete_regular_file(
    parent: &OpenParent,
    expected: &NativeObjectToken,
    expected_fingerprint: &[u8; 32],
    installed_token: &mut Option<NativeObjectToken>,
    persist_candidate: &mut dyn FnMut(&NativeObjectToken) -> Result<(), RunnerError>,
) -> Result<(), RunnerError> {
    if !identity_matches_path(&parent.directory, &parent.path)? {
        return Err(RunnerError::ConcurrentChange);
    }
    let _expected_handle = verify_expected(parent, Some(expected))?;
    #[cfg(test)]
    run_pre_target_mutation_test_hook();

    if !identity_matches_path(&parent.directory, &parent.path)? {
        return Err(RunnerError::ConcurrentChange);
    }

    let backup = backup_name(&parent.name);
    rename_exclusive(&parent.directory, &parent.name, &backup)?;
    flush_directory(&parent.directory)?;
    if validate_named(
        &parent.directory,
        &backup,
        Some(expected),
        expected_fingerprint,
    )
    .is_err()
    {
        let _ = restore_moved_name(parent, &backup);
        return Err(RunnerError::ConcurrentChange);
    }
    let absent = snapshot_named(&parent.directory, &parent.name)?;
    let absent_token = absent
        .object_token()
        .filter(|_| matches!(absent.state(), NativeState::Absent { .. }))
        .ok_or(RunnerError::ConcurrentChange)?
        .clone();
    if let Err(error) = persist_candidate(&absent_token) {
        let _ = restore_moved_name(parent, &backup);
        let _ = flush_directory(&parent.directory);
        return Err(error);
    }
    *installed_token = Some(absent_token);
    Ok(())
}

pub(super) fn recover_interrupted_replace(
    path: &Path,
    before_fingerprint: &[u8; 32],
    applied_fingerprint: &[u8; 32],
    transaction_nonce: &[u8; 16],
    expected_parent_binding: Option<&NativeObjectToken>,
    expected_backup_token: Option<&NativeObjectToken>,
    provenance: super::RecoveryProvenance<'_>,
) -> Result<super::NativeRecoveryDisposition, RunnerError> {
    let parent = OpenParent::new(path)?;
    if !identity_matches_path(&parent.directory, &parent.path)? {
        return Err(RunnerError::ConcurrentChange);
    }
    if let Some(expected) = expected_parent_binding {
        let snapshot = snapshot_named(&parent.directory, &parent.name)?;
        if snapshot
            .object_token()
            .is_none_or(|actual| !actual.has_same_parent_binding(expected))
        {
            return Err(RunnerError::ConcurrentChange);
        }
    }
    #[cfg(test)]
    run_recovery_after_parent_check_test_hook();
    recover_interrupted_replace_held(
        &parent,
        before_fingerprint,
        applied_fingerprint,
        transaction_nonce,
        expected_backup_token,
        provenance,
    )
}

pub(super) fn cleanup_committed_delete(
    path: &Path,
    before_fingerprint: &[u8; 32],
    _transaction_nonce: &[u8; 16],
    original_token: &NativeObjectToken,
) -> Result<(), RunnerError> {
    let parent = OpenParent::new(path)?;
    if !identity_matches_path(&parent.directory, &parent.path)? {
        return Err(RunnerError::ConcurrentChange);
    }
    let name = backup_name(&parent.name);
    let backup = snapshot_named(&parent.directory, &name)?;
    if matches!(backup.state(), NativeState::Absent { .. }) {
        return Ok(());
    }
    if backup.object_token() != Some(original_token) || backup.fingerprint() != before_fingerprint {
        return Err(RunnerError::ConcurrentChange);
    }
    remove_exact_private_named(&parent, &name, original_token, before_fingerprint)
}

fn recover_interrupted_replace_held(
    parent: &OpenParent,
    before_fingerprint: &[u8; 32],
    applied_fingerprint: &[u8; 32],
    transaction_nonce: &[u8; 16],
    expected_backup_token: Option<&NativeObjectToken>,
    provenance: super::RecoveryProvenance<'_>,
) -> Result<super::NativeRecoveryDisposition, RunnerError> {
    if !identity_matches_path(&parent.directory, &parent.path)? {
        return Err(RunnerError::ConcurrentChange);
    }
    cleanup_recovery_temp(parent, transaction_nonce)?;
    let backup_name = backup_name(&parent.name);
    let backup = match snapshot_named(&parent.directory, &backup_name) {
        Ok(snapshot) if matches!(snapshot.state(), NativeState::Absent { .. }) => {
            let current = snapshot_named(&parent.directory, &parent.name)?;
            return if current.fingerprint() == before_fingerprint {
                Ok(super::NativeRecoveryDisposition::Restored)
            } else if current.fingerprint() == applied_fingerprint {
                if provenance.accepts_applied(current.object_token()) {
                    Ok(super::NativeRecoveryDisposition::Restored)
                } else {
                    Ok(super::NativeRecoveryDisposition::Abandoned)
                }
            } else {
                Err(RunnerError::ConcurrentChange)
            };
        }
        Ok(snapshot) => snapshot,
        Err(_) => return Err(RunnerError::ConcurrentChange),
    };
    if backup.fingerprint() != before_fingerprint {
        return Err(RunnerError::ConcurrentChange);
    }
    let backup_token = backup
        .object_token()
        .ok_or(RunnerError::ConcurrentChange)?
        .clone();
    if expected_backup_token.is_some_and(|expected| expected != &backup_token) {
        return Err(RunnerError::ConcurrentChange);
    }
    let target = snapshot_named(&parent.directory, &parent.name)?;
    if matches!(target.state(), NativeState::Absent { .. }) {
        if (target.fingerprint() == applied_fingerprint
            && !provenance.accepts_applied(target.object_token()))
            || (target.fingerprint() != applied_fingerprint
                && expected_backup_token.is_none()
                && !provenance.permits_unattributed_missing_restore())
        {
            return Ok(super::NativeRecoveryDisposition::Abandoned);
        }
        restore_backup(parent, &backup_name, &backup_token, before_fingerprint)?;
        return Ok(super::NativeRecoveryDisposition::Restored);
    }
    if target.fingerprint() == before_fingerprint {
        let target_token = target
            .object_token()
            .ok_or(RunnerError::ConcurrentChange)?
            .clone();
        remove_exact_named(
            parent,
            &backup_name,
            &backup_token,
            before_fingerprint,
            NamedGuard {
                name: &parent.name,
                token: &target_token,
                fingerprint: before_fingerprint,
            },
        )?;
        return Ok(super::NativeRecoveryDisposition::Restored);
    }
    if target.fingerprint() != applied_fingerprint {
        return Err(RunnerError::ConcurrentChange);
    }
    let target_token = target
        .object_token()
        .ok_or(RunnerError::ConcurrentChange)?
        .clone();
    if !provenance.accepts_applied(Some(&target_token)) {
        return Ok(super::NativeRecoveryDisposition::Abandoned);
    }
    if !identity_matches_path(&parent.directory, &parent.path)? {
        return Err(RunnerError::ConcurrentChange);
    }
    let temp_name = temp_name(&parent.name, transaction_nonce);
    rename_exclusive(&parent.directory, &parent.name, &temp_name)?;
    flush_directory(&parent.directory)?;
    if validate_named(
        &parent.directory,
        &temp_name,
        Some(&target_token),
        applied_fingerprint,
    )
    .is_err()
    {
        let _ = restore_moved_name_to(parent, &temp_name, &parent.name);
        return Err(RunnerError::ConcurrentChange);
    }
    if let Err(error) = restore_backup(parent, &backup_name, &backup_token, before_fingerprint) {
        let _ = restore_moved_name_to(parent, &temp_name, &parent.name);
        return Err(error);
    }
    cleanup_recovery_temp(parent, transaction_nonce)?;
    Ok(super::NativeRecoveryDisposition::Restored)
}

fn recover_replace_error(
    parent: &OpenParent,
    before_fingerprint: &[u8; 32],
    applied_fingerprint: &[u8; 32],
    transaction_nonce: &[u8; 16],
    backup_created: bool,
    installed_token: Option<&NativeObjectToken>,
    error: RunnerError,
) -> Result<(), RunnerError> {
    if !backup_created {
        return Err(error);
    }
    if recover_interrupted_replace_held(
        parent,
        before_fingerprint,
        applied_fingerprint,
        transaction_nonce,
        None,
        super::RecoveryProvenance::Attributed(installed_token),
    )
    .is_ok()
    {
        Err(error)
    } else {
        Err(RunnerError::ConcurrentChange)
    }
}

fn snapshot_named(parent: &File, name: &CStr) -> Result<NativeSnapshot, RunnerError> {
    match capture_named_file(parent, name) {
        Ok(captured) => {
            let state = NativeState::RegularFile {
                bytes: captured.bytes,
                metadata: captured.metadata,
            };
            Ok(NativeSnapshot {
                fingerprint: fingerprint(&state),
                state,
                object_token: Some(captured.token),
            })
        }
        Err(CaptureError::Missing) => {
            let before = raw_node(parent)?;
            #[cfg(test)]
            run_post_missing_snapshot_test_hook();
            match raw_at(parent, name) {
                Err(RunnerError::Io) if last_errno() == libc::ENOENT => {}
                Ok(_) => return Err(RunnerError::ConcurrentChange),
                Err(error) => return Err(error),
            }
            let after = raw_node(parent)?;
            if !before.same_snapshot(&after) {
                return Err(RunnerError::ConcurrentChange);
            }
            let (parent_attributes, parent_link_count) = parent_marker(&before);
            let state = NativeState::absent(parent_attributes, parent_link_count);
            Ok(NativeSnapshot {
                fingerprint: fingerprint(&state),
                state,
                object_token: Some(absent_token(&before)),
            })
        }
        Err(CaptureError::Runner(error)) => Err(error),
    }
}

fn validate_named(
    parent: &File,
    name: &CStr,
    expected_token: Option<&NativeObjectToken>,
    expected_fingerprint: &[u8; 32],
) -> Result<NativeSnapshot, RunnerError> {
    let snapshot = snapshot_named(parent, name)?;
    if snapshot.fingerprint() != expected_fingerprint
        || expected_token.is_some_and(|expected| snapshot.object_token() != Some(expected))
    {
        return Err(RunnerError::ConcurrentChange);
    }
    Ok(snapshot)
}

fn validate_absent(
    parent: &OpenParent,
    expected_token: Option<&NativeObjectToken>,
    expected_fingerprint: &[u8; 32],
) -> Result<(), RunnerError> {
    let snapshot = snapshot_named(&parent.directory, &parent.name)?;
    if !matches!(snapshot.state(), NativeState::Absent { .. })
        || snapshot.fingerprint() != expected_fingerprint
        || expected_token.is_some_and(|expected| snapshot.object_token() != Some(expected))
    {
        return Err(RunnerError::ConcurrentChange);
    }
    Ok(())
}

fn rename_exclusive(parent: &File, from: &CStr, to: &CStr) -> Result<(), RunnerError> {
    if unsafe {
        libc::renameatx_np(
            parent.as_raw_fd(),
            from.as_ptr(),
            parent.as_raw_fd(),
            to.as_ptr(),
            libc::RENAME_EXCL,
        )
    } == 0
    {
        return Ok(());
    }
    if matches!(last_errno(), libc::EEXIST | libc::ENOENT) {
        Err(RunnerError::ConcurrentChange)
    } else {
        Err(RunnerError::Io)
    }
}

fn restore_moved_name(parent: &OpenParent, from: &CStr) -> Result<(), RunnerError> {
    restore_moved_name_to(parent, from, &parent.name)
}

fn restore_moved_name_to(parent: &OpenParent, from: &CStr, to: &CStr) -> Result<(), RunnerError> {
    rename_exclusive(&parent.directory, from, to)?;
    flush_directory(&parent.directory)
}

fn restore_backup(
    parent: &OpenParent,
    backup_name: &CStr,
    backup_token: &NativeObjectToken,
    before_fingerprint: &[u8; 32],
) -> Result<(), RunnerError> {
    if !identity_matches_path(&parent.directory, &parent.path)? {
        return Err(RunnerError::ConcurrentChange);
    }
    validate_named(
        &parent.directory,
        backup_name,
        Some(backup_token),
        before_fingerprint,
    )?;
    if !matches!(
        snapshot_named(&parent.directory, &parent.name)?.state(),
        NativeState::Absent { .. }
    ) {
        return Err(RunnerError::ConcurrentChange);
    }
    rename_exclusive(&parent.directory, backup_name, &parent.name)?;
    flush_directory(&parent.directory)?;
    if validate_named(
        &parent.directory,
        &parent.name,
        Some(backup_token),
        before_fingerprint,
    )
    .is_err()
    {
        let _ = restore_moved_name_to(parent, &parent.name, backup_name);
        return Err(RunnerError::ConcurrentChange);
    }
    Ok(())
}

fn rollback_created_target(
    parent: &OpenParent,
    temp_name: &CStr,
    staged_token: &NativeObjectToken,
    intended_fingerprint: &[u8; 32],
) -> Result<(), RunnerError> {
    validate_named(
        &parent.directory,
        &parent.name,
        Some(staged_token),
        intended_fingerprint,
    )?;
    #[cfg(test)]
    run_pre_rollback_move_test_hook();
    rename_exclusive(&parent.directory, &parent.name, temp_name)?;
    flush_directory(&parent.directory)?;
    if validate_named(
        &parent.directory,
        temp_name,
        Some(staged_token),
        intended_fingerprint,
    )
    .is_err()
    {
        let _ = restore_moved_name_to(parent, temp_name, &parent.name);
        return Err(RunnerError::ConcurrentChange);
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct NamedGuard<'a> {
    name: &'a CStr,
    token: &'a NativeObjectToken,
    fingerprint: &'a [u8; 32],
}

fn remove_exact_named(
    parent: &OpenParent,
    name: &CStr,
    expected_token: &NativeObjectToken,
    expected_fingerprint: &[u8; 32],
    guard: NamedGuard<'_>,
) -> Result<(), RunnerError> {
    // Darwin has no public unlink-by-held-identity primitive. Alternating the
    // sidecar and target guards narrows, but cannot close, unlinkat's final name race.
    #[cfg(test)]
    run_pre_backup_removal_test_hook();
    if !identity_matches_path(&parent.directory, &parent.path)? {
        return Err(RunnerError::ConcurrentChange);
    }
    let first = validate_named(
        &parent.directory,
        name,
        Some(expected_token),
        expected_fingerprint,
    )?;
    validate_named(
        &parent.directory,
        guard.name,
        Some(guard.token),
        guard.fingerprint,
    )?;
    validate_named(
        &parent.directory,
        name,
        first.object_token(),
        expected_fingerprint,
    )?;
    validate_named(
        &parent.directory,
        guard.name,
        Some(guard.token),
        guard.fingerprint,
    )?;
    if !identity_matches_path(&parent.directory, &parent.path)? {
        return Err(RunnerError::ConcurrentChange);
    }
    if unsafe { libc::unlinkat(parent.directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return if last_errno() == libc::ENOENT {
            Err(RunnerError::ConcurrentChange)
        } else {
            Err(RunnerError::Io)
        };
    }
    flush_directory(&parent.directory)
}

fn remove_exact_private_named(
    parent: &OpenParent,
    name: &CStr,
    expected_token: &NativeObjectToken,
    expected_fingerprint: &[u8; 32],
) -> Result<(), RunnerError> {
    if !identity_matches_path(&parent.directory, &parent.path)? {
        return Err(RunnerError::ConcurrentChange);
    }
    let first = validate_named(
        &parent.directory,
        name,
        Some(expected_token),
        expected_fingerprint,
    )?;
    validate_named(
        &parent.directory,
        name,
        first.object_token(),
        expected_fingerprint,
    )?;
    if !identity_matches_path(&parent.directory, &parent.path)? {
        return Err(RunnerError::ConcurrentChange);
    }
    if unsafe { libc::unlinkat(parent.directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return if last_errno() == libc::ENOENT {
            Err(RunnerError::ConcurrentChange)
        } else {
            Err(RunnerError::Io)
        };
    }
    flush_directory(&parent.directory)
}

fn cleanup_recovery_temp(
    parent: &OpenParent,
    transaction_nonce: &[u8; 16],
) -> Result<(), RunnerError> {
    let name = temp_name(&parent.name, transaction_nonce);
    let file = match openat(
        &parent.directory,
        &name,
        libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    ) {
        Ok(file) => file,
        Err(RunnerError::Io) if last_errno() == libc::ENOENT => return Ok(()),
        Err(_) => return Err(RunnerError::ConcurrentChange),
    };
    let node = raw_node(&file)?;
    let named = raw_at(&parent.directory, &name)?;
    if !node.regular()
        || node.links != 1
        || !node.same_object(&named)
        || !raw_node(&file)?.same_snapshot(&node)
    {
        return Err(RunnerError::ConcurrentChange);
    }
    if unsafe { libc::fchflags(file.as_raw_fd(), 0) } != 0 {
        return Err(RunnerError::Io);
    }
    let after = raw_node(&file)?;
    let named_after = raw_at(&parent.directory, &name)?;
    if !after.regular()
        || after.links != 1
        || !node.same_object(&after)
        || !after.same_object(&named_after)
        || !identity_matches_path(&parent.directory, &parent.path)?
    {
        return Err(RunnerError::ConcurrentChange);
    }
    if unsafe { libc::unlinkat(parent.directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(RunnerError::ConcurrentChange);
    }
    flush_directory(&parent.directory)
}

pub(super) fn capture_absent_parent(path: &Path) -> Result<(u32, u64), RunnerError> {
    let parent = OpenParent::new(path)?;
    match raw_at(&parent.directory, &parent.name) {
        Ok(_) => return Err(RunnerError::ConcurrentChange),
        Err(RunnerError::Io) if last_errno() == libc::ENOENT => {}
        Err(error) => return Err(error),
    }
    let node = raw_node(&parent.directory)?;
    Ok(parent_marker(&node))
}

fn parent_marker(node: &RawNode) -> (u32, u64) {
    parent_marker_fields(node.mode, node.flags, node.uid, node.gid, node.links)
}

fn parent_marker_fields(mode: u32, flags: u32, uid: u32, gid: u32, links: u64) -> (u32, u64) {
    let mut hash = Sha256::new();
    hash.update(b"context-relay/macos-parent-state/v1\0");
    hash.update(mode.to_be_bytes());
    hash.update(flags.to_be_bytes());
    hash.update(uid.to_be_bytes());
    hash.update(gid.to_be_bytes());
    hash.update(links.to_be_bytes());
    let digest = hash.finalize();
    (
        u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]),
        u64::from_be_bytes([
            digest[4], digest[5], digest[6], digest[7], digest[8], digest[9], digest[10],
            digest[11],
        ]),
    )
}

fn validate_metadata(
    metadata: &NativeMetadata,
    security: &PosixSecurity,
) -> Result<(), RunnerError> {
    if metadata.file_attributes != 0
        || !metadata.alternate_streams.is_empty()
        || metadata.link_count != 1
        || (metadata.parent_attributes, metadata.parent_link_count)
            != parent_marker_fields(
                security.parent_mode,
                security.parent_flags,
                security.parent_uid,
                security.parent_gid,
                security.parent_links,
            )
        || security.mode & MODE_MASK != MODE_REGULAR
        || security.parent_mode & MODE_MASK != MODE_DIRECTORY
    {
        return Err(RunnerError::InvalidNativeState);
    }
    Ok(())
}

fn verify_expected(
    parent: &OpenParent,
    expected: Option<&NativeObjectToken>,
) -> Result<Option<File>, RunnerError> {
    match expected {
        Some(expected) => {
            let file = openat(
                &parent.directory,
                &parent.name,
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0,
            )?;
            let node = raw_node(&file)?;
            if !node.regular() || node.links != 1 {
                return Err(RunnerError::UnsafeTopology);
            }
            shared_lock(&file)?;
            let parent_node = raw_node(&parent.directory)?;
            if &token(&node, &parent_node) != expected {
                return Err(RunnerError::ConcurrentChange);
            }
            Ok(Some(file))
        }
        None => match raw_at(&parent.directory, &parent.name) {
            Err(RunnerError::Io) if last_errno() == libc::ENOENT => Ok(None),
            Ok(_) => Err(RunnerError::ConcurrentChange),
            Err(error) => Err(error),
        },
    }
}

struct OpenParent {
    directory: File,
    name: CString,
    path: PathBuf,
}

impl OpenParent {
    fn new(path: &Path) -> Result<Self, RunnerError> {
        validate_absolute(path)?;
        let parent = path.parent().ok_or(RunnerError::InvalidPath)?;
        let name = path.file_name().ok_or(RunnerError::InvalidPath)?;
        let name = CString::new(name.as_bytes()).map_err(|_| RunnerError::InvalidPath)?;
        let directory = open_path(parent, libc::O_RDONLY | libc::O_DIRECTORY)?;
        if !raw_node(&directory)?.directory() {
            return Err(RunnerError::UnsafeTopology);
        }
        Ok(Self {
            directory,
            name,
            path: parent.to_path_buf(),
        })
    }
}

#[derive(Debug)]
pub(super) struct PrivateStageCleanup {
    parent: File,
    root: File,
    name: CString,
    identity: RawNode,
    armed: bool,
}

impl PrivateStageCleanup {
    pub(super) fn create(parent: &Path, name: &str) -> Result<Self, RunnerError> {
        validate_absolute(parent)?;
        let name = CString::new(name).map_err(|_| RunnerError::InvalidStage)?;
        let parent_path = parent.to_path_buf();
        let parent = open_path(parent, libc::O_RDONLY | libc::O_DIRECTORY)?;
        if !raw_node(&parent)?.directory()
            || unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0
        {
            return Err(RunnerError::InvalidStage);
        }
        let root = openat(
            &parent,
            &name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )?;
        let identity = raw_node(&root)?;
        let named = raw_at(&parent, &name)?;
        if !identity.directory() || !identity.same_identity(&named) {
            return Err(RunnerError::ConcurrentChange);
        }
        let mut cleanup = Self {
            parent,
            root,
            name,
            identity,
            armed: true,
        };
        if !identity_matches_path(&cleanup.parent, &parent_path)? {
            return Err(RunnerError::ConcurrentChange);
        }
        if let Err(error) = flush_directory(&cleanup.parent) {
            let _ = cleanup.cleanup();
            return Err(error);
        }
        Ok(cleanup)
    }

    pub(super) fn cleanup(&mut self) -> Result<(), RunnerError> {
        if !self.armed {
            return Ok(());
        }
        self.verify_named_root()?;
        cleanup_directory(&self.root, self.identity.device)?;
        self.verify_named_root()?;
        if unsafe {
            libc::unlinkat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                libc::AT_REMOVEDIR,
            )
        } != 0
        {
            return Err(cleanup_unlink_error());
        }
        self.armed = false;
        flush_directory(&self.parent)
    }

    fn verify_named_root(&self) -> Result<(), RunnerError> {
        let held = raw_node(&self.root)?;
        let named = cleanup_raw_at(&self.parent, &self.name)?;
        if held.same_identity(&self.identity) && held.same_identity(&named) {
            Ok(())
        } else {
            Err(RunnerError::ConcurrentChange)
        }
    }
}

impl Drop for PrivateStageCleanup {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

fn cleanup_directory(directory: &File, stage_device: u64) -> Result<(), RunnerError> {
    let held = raw_node(directory)?;
    if !held.directory() || held.device != stage_device {
        return Err(RunnerError::UnsafeTopology);
    }
    if unsafe { libc::fchflags(directory.as_raw_fd(), 0) } != 0
        || unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } != 0
    {
        return Err(RunnerError::Io);
    }
    for name in directory_entry_names(directory)? {
        let before = cleanup_raw_at(directory, &name)?;
        if before.device != stage_device || (!before.directory() && before.links != 1) {
            return Err(RunnerError::UnsafeTopology);
        }
        let child = open_cleanup_node(directory, &name, &before)?;
        let opened = raw_node(&child)?;
        let named = cleanup_raw_at(directory, &name)?;
        if opened.device != stage_device
            || !before.same_identity(&opened)
            || !opened.same_identity(&named)
        {
            return Err(RunnerError::ConcurrentChange);
        }
        if unsafe { libc::fchflags(child.as_raw_fd(), 0) } != 0 {
            return Err(RunnerError::Io);
        }
        if before.directory() {
            if unsafe { libc::fchmod(child.as_raw_fd(), 0o700) } != 0 {
                return Err(RunnerError::Io);
            }
            cleanup_directory(&child, stage_device)?;
            let opened = raw_node(&child)?;
            let named = cleanup_raw_at(directory, &name)?;
            if !opened.same_identity(&named) {
                return Err(RunnerError::ConcurrentChange);
            }
            if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) }
                != 0
            {
                return Err(cleanup_unlink_error());
            }
        } else {
            if !before.symlink() && unsafe { libc::fchmod(child.as_raw_fd(), 0o600) } != 0 {
                return Err(RunnerError::Io);
            }
            let opened = raw_node(&child)?;
            let named = cleanup_raw_at(directory, &name)?;
            if !opened.same_identity(&named) {
                return Err(RunnerError::ConcurrentChange);
            }
            if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                return Err(cleanup_unlink_error());
            }
        }
    }
    flush_directory(directory)
}

fn open_cleanup_node(parent: &File, name: &CStr, expected: &RawNode) -> Result<File, RunnerError> {
    let flags = if expected.directory() {
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC
    } else if expected.symlink() {
        libc::O_RDONLY | libc::O_SYMLINK | libc::O_CLOEXEC
    } else {
        libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC
    };
    openat(parent, name, flags, 0)
}

fn directory_entry_names(directory: &File) -> Result<Vec<CString>, RunnerError> {
    let held = raw_node(directory)?;
    let reopened = openat(
        directory,
        c".",
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )?;
    if !held.same_identity(&raw_node(&reopened)?) {
        return Err(RunnerError::ConcurrentChange);
    }
    let reopened = reopened.into_raw_fd();
    let stream = unsafe { libc::fdopendir(reopened) };
    if stream.is_null() {
        unsafe { libc::close(reopened) };
        return Err(RunnerError::Io);
    }
    let stream = DirectoryStream(stream);
    let mut names = Vec::new();
    loop {
        unsafe { *libc::__error() = 0 };
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            if last_errno() == 0 {
                break;
            }
            return Err(RunnerError::Io);
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if !matches!(name.to_bytes(), b"." | b"..") {
            names.push(name.to_owned());
        }
    }
    Ok(names)
}

struct DirectoryStream(*mut libc::DIR);

impl Drop for DirectoryStream {
    fn drop(&mut self) {
        unsafe { libc::closedir(self.0) };
    }
}

fn cleanup_raw_at(parent: &File, name: &CStr) -> Result<RawNode, RunnerError> {
    match raw_at(parent, name) {
        Err(RunnerError::Io) if last_errno() == libc::ENOENT => Err(RunnerError::ConcurrentChange),
        result => result,
    }
}

fn cleanup_unlink_error() -> RunnerError {
    if matches!(last_errno(), libc::ENOENT | libc::EEXIST | libc::ENOTEMPTY) {
        RunnerError::ConcurrentChange
    } else {
        RunnerError::Io
    }
}

fn open_path(path: &Path, flags: libc::c_int) -> Result<File, RunnerError> {
    validate_absolute(path)?;
    let encoded =
        CString::new(path.as_os_str().as_bytes()).map_err(|_| RunnerError::InvalidPath)?;
    let fd = unsafe {
        libc::open(
            encoded.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW_ANY,
        )
    };
    if fd < 0
        && !matches!(last_errno(), libc::ELOOP | libc::ENOTDIR | libc::ENOENT)
        && fs::symlink_metadata(path)
            .is_ok_and(|metadata| !metadata.is_file() && !metadata.is_dir())
    {
        return Err(RunnerError::UnsafeTopology);
    }
    file_from_fd(fd)
}

fn validate_absolute(path: &Path) -> Result<(), RunnerError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(RunnerError::InvalidPath);
    }
    Ok(())
}

fn openat(
    parent: &File,
    name: &CStr,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> Result<File, RunnerError> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags,
            libc::c_uint::from(mode),
        )
    };
    file_from_fd(fd)
}

fn file_from_fd(fd: libc::c_int) -> Result<File, RunnerError> {
    if fd >= 0 {
        return Ok(unsafe { File::from_raw_fd(fd) });
    }
    if matches!(last_errno(), libc::ELOOP | libc::ENOTDIR) {
        Err(RunnerError::UnsafeTopology)
    } else {
        Err(RunnerError::Io)
    }
}

#[derive(Clone, Copy, Debug)]
struct RawNode {
    device: u64,
    object: u64,
    generation: u32,
    mode: u32,
    links: u64,
    uid: u32,
    gid: u32,
    size: u64,
    flags: u32,
    access_seconds: i64,
    access_nanoseconds: i64,
    write_seconds: i64,
    write_nanoseconds: i64,
    change_seconds: i64,
    change_nanoseconds: i64,
    birth_seconds: i64,
    birth_nanoseconds: i64,
}

impl RawNode {
    const fn regular(self) -> bool {
        self.mode & MODE_MASK == MODE_REGULAR
    }

    const fn directory(self) -> bool {
        self.mode & MODE_MASK == MODE_DIRECTORY
    }

    const fn symlink(self) -> bool {
        self.mode & MODE_MASK == MODE_SYMLINK
    }

    const fn same_object(self, other: &Self) -> bool {
        self.device == other.device
            && self.object == other.object
            && self.generation == other.generation
            && self.mode & MODE_MASK == other.mode & MODE_MASK
            && self.links == other.links
    }

    const fn same_identity(self, other: &Self) -> bool {
        self.device == other.device
            && self.object == other.object
            && self.generation == other.generation
            && self.mode & MODE_MASK == other.mode & MODE_MASK
    }

    const fn same_snapshot(self, other: &Self) -> bool {
        self.same_object(other)
            && self.mode == other.mode
            && self.uid == other.uid
            && self.gid == other.gid
            && self.size == other.size
            && self.flags == other.flags
            && self.write_seconds == other.write_seconds
            && self.write_nanoseconds == other.write_nanoseconds
            && self.change_seconds == other.change_seconds
            && self.change_nanoseconds == other.change_nanoseconds
            && self.birth_seconds == other.birth_seconds
            && self.birth_nanoseconds == other.birth_nanoseconds
    }
}

fn raw_node(file: &File) -> Result<RawNode, RunnerError> {
    let mut stat = unsafe { zeroed::<libc::stat>() };
    if unsafe { libc::fstat(file.as_raw_fd(), &mut stat) } != 0 {
        return Err(RunnerError::Io);
    }
    RawNode::try_from(stat)
}

fn raw_at(parent: &File, name: &CStr) -> Result<RawNode, RunnerError> {
    let mut stat = unsafe { zeroed::<libc::stat>() };
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(RunnerError::Io);
    }
    RawNode::try_from(stat)
}

impl TryFrom<libc::stat> for RawNode {
    type Error = RunnerError;

    fn try_from(stat: libc::stat) -> Result<Self, Self::Error> {
        Ok(Self {
            device: stat.st_dev as u64,
            object: stat.st_ino,
            generation: stat.st_gen,
            mode: u32::from(stat.st_mode),
            links: u64::from(stat.st_nlink),
            uid: stat.st_uid,
            gid: stat.st_gid,
            size: u64::try_from(stat.st_size).map_err(|_| RunnerError::UnsafeTopology)?,
            flags: stat.st_flags,
            access_seconds: stat.st_atime,
            access_nanoseconds: stat.st_atime_nsec,
            write_seconds: stat.st_mtime,
            write_nanoseconds: stat.st_mtime_nsec,
            change_seconds: stat.st_ctime,
            change_nanoseconds: stat.st_ctime_nsec,
            birth_seconds: stat.st_birthtime,
            birth_nanoseconds: stat.st_birthtime_nsec,
        })
    }
}

fn token(node: &RawNode, parent: &RawNode) -> NativeObjectToken {
    let mut object = [0_u8; 16];
    object[..8].copy_from_slice(&node.object.to_be_bytes());
    object[8..12].copy_from_slice(&node.generation.to_be_bytes());
    object[12..].copy_from_slice(&(node.mode & MODE_MASK).to_be_bytes());
    let mut parent_object = [0_u8; 16];
    parent_object[..8].copy_from_slice(&parent.object.to_be_bytes());
    parent_object[8..12].copy_from_slice(&parent.generation.to_be_bytes());
    parent_object[12..].copy_from_slice(&(parent.mode & MODE_MASK).to_be_bytes());
    NativeObjectToken {
        volume: node.device,
        object,
        reparse_tag: node.mode & MODE_MASK,
        parent_volume: parent.device,
        parent_object,
    }
}

fn absent_token(parent: &RawNode) -> NativeObjectToken {
    let mut hasher = Sha256::new();
    hasher.update(b"context-relay/absent-token/macos/v1\0");
    hasher.update(parent.device.to_le_bytes());
    hasher.update(parent.object.to_le_bytes());
    hasher.update(parent.generation.to_le_bytes());
    hasher.update(parent.change_seconds.to_le_bytes());
    hasher.update(parent.change_nanoseconds.to_le_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut object = [0_u8; 16];
    object.copy_from_slice(&digest[..16]);
    let mut parent_object = [0_u8; 16];
    parent_object[..8].copy_from_slice(&parent.object.to_be_bytes());
    parent_object[8..12].copy_from_slice(&parent.generation.to_be_bytes());
    parent_object[12..].copy_from_slice(&(parent.mode & MODE_MASK).to_be_bytes());
    NativeObjectToken {
        volume: parent.device,
        object,
        reparse_tag: super::ABSENT_TOKEN_TAG,
        parent_volume: parent.device,
        parent_object,
    }
}

fn shared_lock(file: &File) -> Result<(), RunnerError> {
    // flock is advisory on Darwin; identity and complete-state rechecks remain required.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } != 0 {
        return Err(RunnerError::Io);
    }
    Ok(())
}

struct CapturedSecurity {
    encoded: Vec<u8>,
    xattr_count: usize,
}

fn capture_security(
    file: &File,
    node: &RawNode,
    parent: &RawNode,
) -> Result<CapturedSecurity, RunnerError> {
    let xattrs = xattrs(file)?;
    let xattr_count = xattrs.len();
    let security = PosixSecurity {
        uid: node.uid,
        gid: node.gid,
        mode: node.mode,
        flags: node.flags,
        acl: acl_text(file)?,
        xattrs,
        parent_uid: parent.uid,
        parent_gid: parent.gid,
        parent_mode: parent.mode,
        parent_flags: parent.flags,
        parent_links: parent.links,
    };
    Ok(CapturedSecurity {
        encoded: security.encode()?,
        xattr_count,
    })
}

#[derive(Clone)]
struct PosixSecurity {
    uid: u32,
    gid: u32,
    mode: u32,
    flags: u32,
    acl: Vec<u8>,
    xattrs: ExtendedAttributes,
    parent_uid: u32,
    parent_gid: u32,
    parent_mode: u32,
    parent_flags: u32,
    parent_links: u64,
}

impl PosixSecurity {
    fn encode(&self) -> Result<Vec<u8>, RunnerError> {
        let mut encoder = Encoder::new(Vec::new());
        encoder.array(12).map_err(codec_error)?;
        encoder.u8(1).map_err(codec_error)?;
        encoder.u32(self.uid).map_err(codec_error)?;
        encoder.u32(self.gid).map_err(codec_error)?;
        encoder.u32(self.mode).map_err(codec_error)?;
        encoder.u32(self.flags).map_err(codec_error)?;
        encoder.bytes(&self.acl).map_err(codec_error)?;
        encoder
            .array(self.xattrs.len() as u64)
            .map_err(codec_error)?;
        for (name, value) in &self.xattrs {
            encoder.array(2).map_err(codec_error)?;
            encoder.bytes(name).map_err(codec_error)?;
            encoder.bytes(value).map_err(codec_error)?;
        }
        encoder.u32(self.parent_uid).map_err(codec_error)?;
        encoder.u32(self.parent_gid).map_err(codec_error)?;
        encoder.u32(self.parent_mode).map_err(codec_error)?;
        encoder.u32(self.parent_flags).map_err(codec_error)?;
        encoder.u64(self.parent_links).map_err(codec_error)?;
        let encoded = encoder.into_writer();
        if encoded.len() > MAX_SECURITY_BYTES {
            return Err(RunnerError::LimitExceeded);
        }
        Ok(encoded)
    }

    fn decode(bytes: &[u8]) -> Result<Self, RunnerError> {
        if bytes.len() > MAX_SECURITY_BYTES {
            return Err(RunnerError::LimitExceeded);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.array().map_err(decode_error)? != Some(12)
            || decoder.u8().map_err(decode_error)? != 1
        {
            return Err(RunnerError::InvalidNativeState);
        }
        let uid = decoder.u32().map_err(decode_error)?;
        let gid = decoder.u32().map_err(decode_error)?;
        let mode = decoder.u32().map_err(decode_error)?;
        let flags = decoder.u32().map_err(decode_error)?;
        let acl = decoder.bytes().map_err(decode_error)?.to_vec();
        let count = decoder
            .array()
            .map_err(decode_error)?
            .ok_or(RunnerError::InvalidNativeState)?;
        if count > MAX_XATTRS as u64 {
            return Err(RunnerError::LimitExceeded);
        }
        let mut xattrs = Vec::with_capacity(count as usize);
        let mut previous: Option<Vec<u8>> = None;
        let mut total = acl.len();
        for _ in 0..count {
            if decoder.array().map_err(decode_error)? != Some(2) {
                return Err(RunnerError::InvalidNativeState);
            }
            let name = decoder.bytes().map_err(decode_error)?.to_vec();
            let value = decoder.bytes().map_err(decode_error)?.to_vec();
            total = total
                .checked_add(name.len())
                .and_then(|size| size.checked_add(value.len()))
                .ok_or(RunnerError::LimitExceeded)?;
            if name.is_empty()
                || name.contains(&0)
                || std::str::from_utf8(&name).is_err()
                || previous.as_ref().is_some_and(|prior| prior >= &name)
                || total > MAX_SECURITY_BYTES
            {
                return Err(RunnerError::InvalidNativeState);
            }
            previous = Some(name.clone());
            xattrs.push((name, value));
        }
        let security = Self {
            uid,
            gid,
            mode,
            flags,
            acl,
            xattrs,
            parent_uid: decoder.u32().map_err(decode_error)?,
            parent_gid: decoder.u32().map_err(decode_error)?,
            parent_mode: decoder.u32().map_err(decode_error)?,
            parent_flags: decoder.u32().map_err(decode_error)?,
            parent_links: decoder.u64().map_err(decode_error)?,
        };
        if decoder.position() != bytes.len()
            || security.acl.contains(&0)
            || security.parent_links == 0
        {
            return Err(RunnerError::InvalidNativeState);
        }
        Ok(security)
    }
}

fn codec_error<E>(_: minicbor::encode::Error<E>) -> RunnerError {
    RunnerError::InvalidNativeState
}

fn decode_error(_: minicbor::decode::Error) -> RunnerError {
    RunnerError::InvalidNativeState
}

fn xattrs(file: &File) -> Result<ExtendedAttributes, RunnerError> {
    let size = unsafe { libc::flistxattr(file.as_raw_fd(), null_mut(), 0, 0) };
    if size < 0 {
        return Err(RunnerError::Io);
    }
    if size as usize > MAX_SECURITY_BYTES {
        return Err(RunnerError::LimitExceeded);
    }
    let mut list = vec![0_u8; size as usize];
    if size != 0 {
        let read =
            unsafe { libc::flistxattr(file.as_raw_fd(), list.as_mut_ptr().cast(), list.len(), 0) };
        if read != size {
            return Err(RunnerError::ConcurrentChange);
        }
    }
    let mut output = Vec::new();
    let mut start = 0;
    for end in 0..list.len() {
        if list[end] != 0 {
            continue;
        }
        if end == start || output.len() == MAX_XATTRS {
            return Err(RunnerError::LimitExceeded);
        }
        let name = list[start..end].to_vec();
        let name_c = CString::new(name.clone()).map_err(|_| RunnerError::Io)?;
        let value_size =
            unsafe { libc::fgetxattr(file.as_raw_fd(), name_c.as_ptr(), null_mut(), 0, 0, 0) };
        if value_size < 0 {
            return Err(RunnerError::Io);
        }
        if value_size as usize > MAX_SECURITY_BYTES {
            return Err(RunnerError::LimitExceeded);
        }
        let mut value = vec![0_u8; value_size as usize];
        let read = unsafe {
            libc::fgetxattr(
                file.as_raw_fd(),
                name_c.as_ptr(),
                value.as_mut_ptr().cast(),
                value.len(),
                0,
                0,
            )
        };
        if read != value_size {
            return Err(RunnerError::ConcurrentChange);
        }
        output.push((name, value));
        start = end + 1;
    }
    if start != list.len() {
        return Err(RunnerError::Io);
    }
    output.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(output)
}

struct Acl(*mut c_void);

impl Drop for Acl {
    fn drop(&mut self) {
        unsafe {
            acl_free(self.0);
        }
    }
}

fn acl_text(file: &File) -> Result<Vec<u8>, RunnerError> {
    unsafe {
        *libc::__error() = 0;
    }
    let pointer = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
    if pointer.is_null() {
        // acl_get_fd_np leaves ENOENT when FILESEC_ACL is absent.
        return if matches!(last_errno(), 0 | libc::ENOENT) {
            Ok(Vec::new())
        } else {
            Err(RunnerError::Io)
        };
    }
    let acl = Acl(pointer);
    let mut length = 0;
    let text = unsafe { acl_to_text(acl.0, &mut length) };
    if text.is_null() || length < 0 {
        return Err(RunnerError::Io);
    }
    if length as usize > MAX_SECURITY_BYTES {
        return Err(RunnerError::LimitExceeded);
    }
    let bytes = unsafe { std::slice::from_raw_parts(text.cast::<u8>(), length as usize) }.to_vec();
    unsafe {
        acl_free(text.cast());
    }
    Ok(bytes)
}

fn restore_security(file: &File, security: &PosixSecurity) -> Result<(), RunnerError> {
    if unsafe { libc::fchown(file.as_raw_fd(), security.uid, security.gid) } != 0
        || unsafe { libc::fchmod(file.as_raw_fd(), (security.mode & 0o7777) as libc::mode_t) } != 0
    {
        return Err(RunnerError::Io);
    }
    for (name, _) in xattrs(file)? {
        let name = CString::new(name).map_err(|_| RunnerError::InvalidNativeState)?;
        if unsafe { libc::fremovexattr(file.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            return Err(RunnerError::Io);
        }
    }
    for (name, value) in &security.xattrs {
        let name = CString::new(name.clone()).map_err(|_| RunnerError::InvalidNativeState)?;
        if unsafe {
            libc::fsetxattr(
                file.as_raw_fd(),
                name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
                0,
            )
        } != 0
        {
            return Err(RunnerError::Io);
        }
    }
    restore_acl(file, &security.acl)
}

fn restore_acl(file: &File, text: &[u8]) -> Result<(), RunnerError> {
    let encoded;
    let acl = if text.is_empty() {
        unsafe { acl_init(0) }
    } else {
        encoded = CString::new(text).map_err(|_| RunnerError::InvalidNativeState)?;
        unsafe { acl_from_text(encoded.as_ptr()) }
    };
    if acl.is_null() {
        return Err(RunnerError::InvalidNativeState);
    }
    let acl = Acl(acl);
    if unsafe { acl_set_fd_np(file.as_raw_fd(), acl.0, ACL_TYPE_EXTENDED) } != 0 {
        return Err(RunnerError::Io);
    }
    Ok(())
}

fn set_birthtime(file: &File, timestamp: i64) -> Result<(), RunnerError> {
    let mut attributes = libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: libc::ATTR_CMN_CRTIME,
        volattr: 0,
        dirattr: 0,
        fileattr: 0,
        forkattr: 0,
    };
    let mut value = timespec(timestamp);
    if unsafe {
        libc::fsetattrlist(
            file.as_raw_fd(),
            (&mut attributes as *mut libc::attrlist).cast(),
            (&mut value as *mut libc::timespec).cast(),
            size_of::<libc::timespec>(),
            0,
        )
    } != 0
    {
        return Err(RunnerError::Io);
    }
    Ok(())
}

fn set_times(file: &File, access: i64, write: i64) -> Result<(), RunnerError> {
    let values = [timespec(access), timespec(write)];
    if unsafe { libc::futimens(file.as_raw_fd(), values.as_ptr()) } != 0 {
        return Err(RunnerError::Io);
    }
    Ok(())
}

fn set_flags(file: &File, flags: u32) -> Result<(), RunnerError> {
    if unsafe { libc::fchflags(file.as_raw_fd(), flags) } != 0 {
        return Err(RunnerError::Io);
    }
    Ok(())
}

fn timestamp(seconds: i64, nanoseconds: i64) -> Result<i64, RunnerError> {
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(RunnerError::LimitExceeded)
}

fn timespec(timestamp: i64) -> libc::timespec {
    libc::timespec {
        tv_sec: timestamp.div_euclid(1_000_000_000),
        tv_nsec: timestamp.rem_euclid(1_000_000_000),
    }
}

fn create_adjacent_temp(
    parent: &OpenParent,
    transaction_nonce: &[u8; 16],
) -> Result<(File, PendingTemp), RunnerError> {
    let name = temp_name(&parent.name, transaction_nonce);
    let file = match openat(
        &parent.directory,
        &name,
        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o600,
    ) {
        Ok(file) => file,
        Err(RunnerError::Io) if last_errno() == libc::EEXIST => {
            return Err(RunnerError::ConcurrentChange);
        }
        Err(error) => return Err(error),
    };
    let raw = raw_node(&file)?;
    let cleanup = PendingTemp {
        parent: parent.directory.try_clone().map_err(|_| RunnerError::Io)?,
        file: file.try_clone().map_err(|_| RunnerError::Io)?,
        name,
        device: raw.device,
        object: raw.object,
        generation: raw.generation,
        armed: true,
    };
    Ok((file, cleanup))
}

fn backup_name(target: &CStr) -> CString {
    let mut name = String::with_capacity(15 + 64 + 7);
    name.push_str(".context-relay-");
    push_hex(&mut name, &target_name_hash(target));
    name.push_str(".backup");
    CString::new(name).expect("internal backup name has no NUL")
}

fn temp_name(target: &CStr, transaction_nonce: &[u8; 16]) -> CString {
    let mut name = String::with_capacity(15 + 64 + 1 + 32 + 4);
    name.push_str(".context-relay-");
    push_hex(&mut name, &target_name_hash(target));
    name.push('-');
    push_hex(&mut name, transaction_nonce);
    name.push_str(".tmp");
    CString::new(name).expect("internal temp name has no NUL")
}

fn target_name_hash(target: &CStr) -> [u8; 32] {
    Sha256::digest(target.to_bytes()).into()
}

fn push_hex(output: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
}

struct PendingTemp {
    parent: File,
    file: File,
    name: CString,
    device: u64,
    object: u64,
    generation: u32,
    armed: bool,
}

impl Drop for PendingTemp {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let Ok(held) = raw_node(&self.file) else {
            return;
        };
        let Ok(named) = raw_at(&self.parent, &self.name) else {
            return;
        };
        if held.device != self.device
            || held.object != self.object
            || held.generation != self.generation
            || !held.regular()
            || held.links != 1
            || !held.same_object(&named)
        {
            return;
        }
        if unsafe { libc::fchflags(self.file.as_raw_fd(), 0) } != 0 {
            return;
        }
        let Ok(held) = raw_node(&self.file) else {
            return;
        };
        let Ok(named) = raw_at(&self.parent, &self.name) else {
            return;
        };
        if held.device == self.device
            && held.object == self.object
            && held.generation == self.generation
            && held.regular()
            && held.links == 1
            && held.same_object(&named)
        {
            unsafe { libc::unlinkat(self.parent.as_raw_fd(), self.name.as_ptr(), 0) };
        }
    }
}

fn full_sync(file: &File) -> Result<(), RunnerError> {
    file.sync_all().map_err(|_| RunnerError::Io)?;
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_FULLFSYNC) } == -1 {
        return Err(RunnerError::Io);
    }
    Ok(())
}

fn flush_directory(directory: &File) -> Result<(), RunnerError> {
    if unsafe { libc::fsync(directory.as_raw_fd()) } == 0 || last_errno() == libc::EINVAL {
        Ok(())
    } else {
        Err(RunnerError::Io)
    }
}

fn last_errno() -> libc::c_int {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

#[cfg(test)]
mod guarded_mutation_tests {
    use std::{ffi::OsStr, fs, os::unix::ffi::OsStrExt, path::PathBuf, time::SystemTime};

    use super::*;
    use crate::{NativeRecoveryDisposition, NativeState, OsNativeFileSystem, RunnerError};

    const TEST_NONCE: [u8; 16] = [0x6d; 16];
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn test_root(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "context-relay-macos-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        root
    }

    #[test]
    fn parent_state_marker_resists_the_prior_mode_flags_xor_collision() {
        let baseline = parent_marker_fields(libc::S_IFDIR as u32 | 0o700, 0, 501, 20, 2);
        let prior_collision = parent_marker_fields(libc::S_IFDIR as u32 | 0o500, 1, 501, 20, 2);

        assert_ne!(baseline, prior_collision);
    }

    #[test]
    fn replacement_preserves_an_unexpected_final_boundary_occupant() {
        let _serial = SERIAL.lock().unwrap();
        let root = test_root("replace-boundary");
        let path = root.join("settings.json");
        let moved = root.join("observed.json");
        fs::write(&path, b"before\n").unwrap();
        let native = OsNativeFileSystem::new();
        let before = native.snapshot(&path).unwrap();
        let desired =
            NativeState::regular_file(b"after\n".to_vec(), before.metadata().unwrap().clone());
        *PRE_TARGET_MUTATION_TEST_HOOK.lock().unwrap() = Some(Box::new({
            let path = path.clone();
            let moved = moved.clone();
            move || {
                fs::rename(&path, moved).unwrap();
                fs::write(path, b"attacker\n").unwrap();
            }
        }));

        assert_eq!(
            native.compare_and_swap(&path, before.fingerprint(), &desired, &TEST_NONCE),
            Err(RunnerError::ConcurrentChange)
        );
        assert_eq!(fs::read(&path).unwrap(), b"attacker\n");
        assert_eq!(fs::read(&moved).unwrap(), b"before\n");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn replacement_does_not_overwrite_a_target_reoccupied_before_install() {
        let _serial = SERIAL.lock().unwrap();
        let root = test_root("replace-install-boundary");
        let path = root.join("settings.json");
        fs::write(&path, b"before\n").unwrap();
        let native = OsNativeFileSystem::new();
        let before = native.snapshot(&path).unwrap();
        let desired =
            NativeState::regular_file(b"after\n".to_vec(), before.metadata().unwrap().clone());
        let opened = OpenParent::new(&path).unwrap();
        let backup = root.join(OsStr::from_bytes(backup_name(&opened.name).to_bytes()));
        *PRE_INSTALL_TEST_HOOK.lock().unwrap() = Some(Box::new({
            let path = path.clone();
            move || fs::write(path, b"attacker\n").unwrap()
        }));

        assert_eq!(
            native.compare_and_swap(&path, before.fingerprint(), &desired, &TEST_NONCE),
            Err(RunnerError::ConcurrentChange)
        );
        assert_eq!(fs::read(&path).unwrap(), b"attacker\n");
        assert_eq!(fs::read(&backup).unwrap(), b"before\n");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn absent_create_rollback_restores_a_late_unexpected_target_occupant() {
        let _serial = SERIAL.lock().unwrap();
        let root = test_root("absent-rollback-boundary");
        let path = root.join("settings.json");
        let preserved = root.join("installed.json");
        fs::write(&path, b"installed\n").unwrap();
        let parent = OpenParent::new(&path).unwrap();
        let installed = snapshot_named(&parent.directory, &parent.name).unwrap();
        let installed_token = installed.object_token().unwrap().clone();
        let installed_fingerprint = *installed.fingerprint();
        let temp = temp_name(&parent.name, &TEST_NONCE);
        *PRE_ROLLBACK_MOVE_TEST_HOOK.lock().unwrap() = Some(Box::new({
            let path = path.clone();
            let preserved = preserved.clone();
            move || {
                fs::rename(&path, preserved).unwrap();
                fs::write(path, b"attacker\n").unwrap();
            }
        }));

        assert_eq!(
            rollback_created_target(&parent, &temp, &installed_token, &installed_fingerprint),
            Err(RunnerError::ConcurrentChange)
        );
        assert_eq!(fs::read(&path).unwrap(), b"attacker\n");
        assert_eq!(fs::read(&preserved).unwrap(), b"installed\n");
        assert!(matches!(
            snapshot_named(&parent.directory, &temp).unwrap().state(),
            NativeState::Absent { .. }
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn deletion_preserves_an_unexpected_final_boundary_occupant() {
        let _serial = SERIAL.lock().unwrap();
        let root = test_root("delete-boundary");
        let path = root.join("settings.json");
        let moved = root.join("observed.json");
        fs::write(&path, b"before\n").unwrap();
        let native = OsNativeFileSystem::new();
        let before = native.snapshot(&path).unwrap();
        let absent = before.absent_state();
        *PRE_TARGET_MUTATION_TEST_HOOK.lock().unwrap() = Some(Box::new({
            let path = path.clone();
            let moved = moved.clone();
            move || {
                fs::rename(&path, moved).unwrap();
                fs::write(path, b"attacker\n").unwrap();
            }
        }));

        assert_eq!(
            native.compare_and_swap(&path, before.fingerprint(), &absent, &TEST_NONCE,),
            Err(RunnerError::ConcurrentChange)
        );
        assert_eq!(fs::read(&path).unwrap(), b"attacker\n");
        assert_eq!(fs::read(&moved).unwrap(), b"before\n");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn backup_removal_revalidates_before_unlinking() {
        let _serial = SERIAL.lock().unwrap();
        let root = test_root("backup-removal-boundary");
        let path = root.join("settings.json");
        fs::write(&path, b"before\n").unwrap();
        let native = OsNativeFileSystem::new();
        let before = native.snapshot(&path).unwrap();
        let desired =
            NativeState::regular_file(b"after\n".to_vec(), before.metadata().unwrap().clone());
        let opened = OpenParent::new(&path).unwrap();
        let backup = root.join(OsStr::from_bytes(backup_name(&opened.name).to_bytes()));
        let preserved = root.join("preserved-before.json");
        *PRE_BACKUP_REMOVAL_TEST_HOOK.lock().unwrap() = Some(Box::new({
            let backup = backup.clone();
            let preserved = preserved.clone();
            move || {
                fs::rename(&backup, preserved).unwrap();
                fs::write(backup, b"attacker\n").unwrap();
            }
        }));

        assert_eq!(
            native.compare_and_swap(&path, before.fingerprint(), &desired, &TEST_NONCE),
            Err(RunnerError::ConcurrentChange)
        );
        assert_eq!(fs::read(&path).unwrap(), b"after\n");
        assert_eq!(fs::read(&backup).unwrap(), b"attacker\n");
        assert_eq!(fs::read(&preserved).unwrap(), b"before\n");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn replacement_keeps_the_backup_if_the_installed_target_changes_during_cleanup() {
        let _serial = SERIAL.lock().unwrap();
        let root = test_root("replace-cleanup-target-boundary");
        let path = root.join("settings.json");
        let installed = root.join("installed.json");
        fs::write(&path, b"before\n").unwrap();
        let native = OsNativeFileSystem::new();
        let before = native.snapshot(&path).unwrap();
        let desired =
            NativeState::regular_file(b"after\n".to_vec(), before.metadata().unwrap().clone());
        let opened = OpenParent::new(&path).unwrap();
        let backup = root.join(OsStr::from_bytes(backup_name(&opened.name).to_bytes()));
        *PRE_BACKUP_REMOVAL_TEST_HOOK.lock().unwrap() = Some(Box::new({
            let path = path.clone();
            let installed = installed.clone();
            move || {
                fs::rename(&path, installed).unwrap();
                fs::write(path, b"attacker\n").unwrap();
            }
        }));

        assert_eq!(
            native.compare_and_swap(&path, before.fingerprint(), &desired, &TEST_NONCE),
            Err(RunnerError::ConcurrentChange)
        );
        assert_eq!(fs::read(&path).unwrap(), b"attacker\n");
        assert_eq!(fs::read(&installed).unwrap(), b"after\n");
        assert_eq!(fs::read(&backup).unwrap(), b"before\n");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn deletion_keeps_the_backup_if_the_empty_target_is_reoccupied_during_cleanup() {
        let _serial = SERIAL.lock().unwrap();
        let root = test_root("delete-cleanup-target-boundary");
        let path = root.join("settings.json");
        fs::write(&path, b"before\n").unwrap();
        let native = OsNativeFileSystem::new();
        let before = native.snapshot(&path).unwrap();
        let absent = before.absent_state();
        let opened = OpenParent::new(&path).unwrap();
        let backup = root.join(OsStr::from_bytes(backup_name(&opened.name).to_bytes()));
        *PRE_BACKUP_REMOVAL_TEST_HOOK.lock().unwrap() = Some(Box::new({
            let path = path.clone();
            move || fs::write(path, b"attacker\n").unwrap()
        }));

        assert_eq!(
            native.compare_and_swap(&path, before.fingerprint(), &absent, &TEST_NONCE,),
            Err(RunnerError::ConcurrentChange)
        );
        assert_eq!(fs::read(&path).unwrap(), b"attacker\n");
        assert_eq!(fs::read(&backup).unwrap(), b"before\n");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn absent_snapshot_rechecks_the_name_before_returning() {
        let _serial = SERIAL.lock().unwrap();
        let root = test_root("absent-snapshot-boundary");
        let path = root.join("settings.json");
        *POST_MISSING_SNAPSHOT_TEST_HOOK.lock().unwrap() = Some(Box::new({
            let path = path.clone();
            move || fs::write(path, b"created concurrently\n").unwrap()
        }));

        assert_eq!(snapshot(&path), Err(RunnerError::ConcurrentChange));
        assert_eq!(fs::read(&path).unwrap(), b"created concurrently\n");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn token_aware_create_rejects_a_parent_replaced_before_the_cas_call() {
        let _serial = SERIAL.lock().unwrap();
        let root = test_root("absent-parent-pre-call-swap");
        let live = root.join("live");
        let moved = root.join("moved");
        let template_path = root.join("template.json");
        fs::create_dir(&live).unwrap();
        fs::write(&template_path, b"template\n").unwrap();
        let path = live.join("settings.json");
        let native = OsNativeFileSystem::new();
        let template = native.snapshot(&template_path).unwrap();
        let before = native.snapshot(&path).unwrap();
        let before_token = before.object_token().unwrap();
        assert_eq!(before_token.volume(), before_token.parent_volume());
        assert_eq!(before_token.object(), before_token.parent_object());
        assert_ne!(before_token.object(), &[0; 16]);
        fs::rename(&live, &moved).unwrap();
        fs::create_dir(&live).unwrap();
        let replacement_parent = native.snapshot(&path).unwrap();
        assert_eq!(replacement_parent.fingerprint(), before.fingerprint());
        assert_ne!(replacement_parent.object_token(), before.object_token());
        let desired = NativeState::regular_file(
            b"approved-secret\n".to_vec(),
            template.metadata().unwrap().clone(),
        );

        assert_eq!(
            native.compare_and_swap_observed(
                &path,
                before.fingerprint(),
                before.object_token(),
                &desired,
                &TEST_NONCE,
            ),
            Err(RunnerError::ConcurrentChange)
        );
        assert!(!path.exists());
        assert!(!moved.join("settings.json").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn token_aware_replace_rejects_the_wrong_present_object_token() {
        let _serial = SERIAL.lock().unwrap();
        let root = test_root("present-token-mismatch");
        let path = root.join("settings.json");
        let other = root.join("other.json");
        fs::write(&path, b"before\n").unwrap();
        fs::write(&other, b"other\n").unwrap();
        let native = OsNativeFileSystem::new();
        let before = native.snapshot(&path).unwrap();
        let other = native.snapshot(&other).unwrap();
        let desired =
            NativeState::regular_file(b"after\n".to_vec(), before.metadata().unwrap().clone());

        assert_eq!(
            native.compare_and_swap_observed(
                &path,
                before.fingerprint(),
                other.object_token(),
                &desired,
                &TEST_NONCE,
            ),
            Err(RunnerError::ConcurrentChange)
        );
        assert_eq!(fs::read(&path).unwrap(), b"before\n");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn absent_create_rejects_a_same_metadata_parent_swap_without_leaking_bytes() {
        let _serial = SERIAL.lock().unwrap();
        let root = test_root("absent-parent-swap");
        let live = root.join("live");
        let moved = root.join("moved");
        fs::create_dir(&live).unwrap();
        let template = live.join("template.json");
        let path = live.join("settings.json");
        fs::write(&template, b"template\n").unwrap();
        let native = OsNativeFileSystem::new();
        let template = native.snapshot(&template).unwrap();
        let before = native.snapshot(&path).unwrap();
        assert!(before.object_token().is_some());
        let desired = NativeState::regular_file(
            b"approved-secret\n".to_vec(),
            template.metadata().unwrap().clone(),
        );
        *PRE_TARGET_MUTATION_TEST_HOOK.lock().unwrap() = Some(Box::new({
            let live = live.clone();
            let moved = moved.clone();
            move || {
                fs::rename(&live, moved).unwrap();
                fs::create_dir(live).unwrap();
            }
        }));

        assert_eq!(
            native.compare_and_swap(&path, before.fingerprint(), &desired, &TEST_NONCE),
            Err(RunnerError::ConcurrentChange)
        );
        assert!(!path.exists());
        assert!(!moved.join("settings.json").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_restores_the_exact_backup_from_the_empty_target_phase() {
        let _serial = SERIAL.lock().unwrap();
        let root = test_root("recover-empty-target");
        let path = root.join("settings.json");
        fs::write(&path, b"before\n").unwrap();
        let native = OsNativeFileSystem::new();
        let before = native.snapshot(&path).unwrap();
        let desired =
            NativeState::regular_file(b"after\n".to_vec(), before.metadata().unwrap().clone());
        let parent = OpenParent::new(&path).unwrap();
        let backup = backup_name(&parent.name);
        rename_exclusive(&parent.directory, &parent.name, &backup).unwrap();
        flush_directory(&parent.directory).unwrap();

        native
            .recover_interrupted_replace(
                &path,
                before.fingerprint(),
                &desired.fingerprint(),
                &TEST_NONCE,
            )
            .unwrap();
        assert_eq!(
            native.snapshot(&path).unwrap().fingerprint(),
            before.fingerprint()
        );
        assert!(!matches!(
            snapshot_named(&parent.directory, &backup).unwrap().state(),
            NativeState::Absent { .. }
        ));
        native
            .recover_interrupted_replace(
                &path,
                before.fingerprint(),
                &desired.fingerprint(),
                &TEST_NONCE,
            )
            .unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_rejects_an_absent_replacement_target_when_no_backup_exists() {
        let _serial = SERIAL.lock().unwrap();
        let root = test_root("recover-unexpected-absent-replace");
        let path = root.join("settings.json");
        fs::write(&path, b"before\n").unwrap();
        let native = OsNativeFileSystem::new();
        let before = native.snapshot(&path).unwrap();
        let desired =
            NativeState::regular_file(b"after\n".to_vec(), before.metadata().unwrap().clone());
        fs::remove_file(&path).unwrap();

        assert_eq!(
            native.recover_interrupted_replace(
                &path,
                before.fingerprint(),
                &desired.fingerprint(),
                &TEST_NONCE,
            ),
            Err(RunnerError::ConcurrentChange)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_accepts_an_absent_delete_target_when_no_backup_exists() {
        let _serial = SERIAL.lock().unwrap();
        let root = test_root("recover-applied-delete");
        let path = root.join("settings.json");
        fs::write(&path, b"before\n").unwrap();
        let native = OsNativeFileSystem::new();
        let before = native.snapshot(&path).unwrap();
        let absent = before.absent_state();
        fs::remove_file(&path).unwrap();

        native
            .recover_interrupted_replace(
                &path,
                before.fingerprint(),
                &absent.fingerprint(),
                &TEST_NONCE,
            )
            .unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_rolls_back_an_installed_target_and_cleans_only_its_nonce() {
        let _serial = SERIAL.lock().unwrap();
        let root = test_root("recover-installed-target");
        let path = root.join("settings.json");
        fs::write(&path, b"before\n").unwrap();
        let native = OsNativeFileSystem::new();
        let before = native.snapshot(&path).unwrap();
        let desired =
            NativeState::regular_file(b"after\n".to_vec(), before.metadata().unwrap().clone());
        let parent = OpenParent::new(&path).unwrap();
        let backup = backup_name(&parent.name);
        rename_exclusive(&parent.directory, &parent.name, &backup).unwrap();
        flush_directory(&parent.directory).unwrap();
        let absent = snapshot_named(&parent.directory, &parent.name).unwrap();
        let NativeState::RegularFile { bytes, metadata } = &desired else {
            unreachable!();
        };
        let mut installed_token = None;
        replace_regular_file(
            &parent,
            absent.object_token(),
            false,
            absent.fingerprint(),
            bytes,
            metadata,
            desired.fingerprint(),
            &TEST_NONCE,
            &mut installed_token,
            &mut |_| Ok(()),
        )
        .unwrap();
        let other_nonce = [0x7eu8; 16];
        let other_temp = temp_name(&parent.name, &other_nonce);
        fs::write(
            root.join(OsStr::from_bytes(other_temp.to_bytes())),
            b"other transaction\n",
        )
        .unwrap();

        native
            .recover_interrupted_replace(
                &path,
                before.fingerprint(),
                &desired.fingerprint(),
                &TEST_NONCE,
            )
            .unwrap();
        assert_eq!(
            native.snapshot(&path).unwrap().fingerprint(),
            before.fingerprint()
        );
        assert!(root.join(OsStr::from_bytes(other_temp.to_bytes())).exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn attributed_recovery_preserves_an_identical_replacement_target() {
        let _serial = SERIAL.lock().unwrap();
        let root = test_root("attributed-recovery-identical-replacement");
        let path = root.join("settings.json");
        fs::write(&path, b"before\n").unwrap();
        let native = OsNativeFileSystem::new();
        let before = native.snapshot(&path).unwrap();
        let desired =
            NativeState::regular_file(b"after\n".to_vec(), before.metadata().unwrap().clone());
        let parent = OpenParent::new(&path).unwrap();
        let backup = backup_name(&parent.name);
        rename_exclusive(&parent.directory, &parent.name, &backup).unwrap();
        flush_directory(&parent.directory).unwrap();

        let absent = native.snapshot(&path).unwrap();
        let first = native
            .compare_and_swap(&path, absent.fingerprint(), &desired, &TEST_NONCE)
            .unwrap();
        let installed_token = first.installed_token().unwrap().clone();
        fs::remove_file(&path).unwrap();
        let absent = native.snapshot(&path).unwrap();
        let concurrent = native
            .compare_and_swap(&path, absent.fingerprint(), &desired, &TEST_NONCE)
            .unwrap();
        let concurrent_token = concurrent.snapshot().object_token().unwrap().clone();
        assert_ne!(concurrent_token, installed_token);

        assert_eq!(
            native.recover_interrupted_replace_observed_with_provenance(
                &path,
                before.fingerprint(),
                &desired.fingerprint(),
                &TEST_NONCE,
                before.object_token(),
                Some(&installed_token),
            ),
            Ok(NativeRecoveryDisposition::Abandoned)
        );
        assert_eq!(
            native.snapshot(&path).unwrap().object_token(),
            Some(&concurrent_token)
        );
        assert!(matches!(
            snapshot_named(&parent.directory, &backup).unwrap().state(),
            NativeState::Absent { .. }
        ));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn attributed_recovery_preserves_a_concurrently_deleted_target() {
        let _serial = SERIAL.lock().unwrap();
        let root = test_root("attributed-recovery-concurrent-delete");
        let path = root.join("settings.json");
        fs::write(&path, b"before\n").unwrap();
        let native = OsNativeFileSystem::new();
        let before = native.snapshot(&path).unwrap();
        let desired =
            NativeState::regular_file(b"after\n".to_vec(), before.metadata().unwrap().clone());
        let parent = OpenParent::new(&path).unwrap();
        let backup = backup_name(&parent.name);
        rename_exclusive(&parent.directory, &parent.name, &backup).unwrap();
        flush_directory(&parent.directory).unwrap();
        let absent = native.snapshot(&path).unwrap();
        let installed = native
            .compare_and_swap(&path, absent.fingerprint(), &desired, &TEST_NONCE)
            .unwrap();
        let installed_token = installed.installed_token().unwrap().clone();
        fs::remove_file(&path).unwrap();

        assert_eq!(
            native.recover_interrupted_replace_observed_with_provenance(
                &path,
                before.fingerprint(),
                &desired.fingerprint(),
                &TEST_NONCE,
                before.object_token(),
                Some(&installed_token),
            ),
            Ok(NativeRecoveryDisposition::Abandoned)
        );
        assert!(!path.exists());
        assert!(matches!(
            snapshot_named(&parent.directory, &backup).unwrap().state(),
            NativeState::Absent { .. }
        ));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_parent_swap_preserves_the_moved_and_replacement_trees() {
        let _serial = SERIAL.lock().unwrap();
        let root = test_root("recovery-parent-swap");
        let live = root.join("live");
        let moved = root.join("moved");
        fs::create_dir(&live).unwrap();
        let path = live.join("settings.json");
        fs::write(&path, b"before\n").unwrap();
        let native = OsNativeFileSystem::new();
        let before = native.snapshot(&path).unwrap();
        let desired =
            NativeState::regular_file(b"after\n".to_vec(), before.metadata().unwrap().clone());
        let parent = OpenParent::new(&path).unwrap();
        let backup = backup_name(&parent.name);
        rename_exclusive(&parent.directory, &parent.name, &backup).unwrap();
        flush_directory(&parent.directory).unwrap();
        let absent = native.snapshot(&path).unwrap();
        let installed = native
            .compare_and_swap(&path, absent.fingerprint(), &desired, &TEST_NONCE)
            .unwrap();
        let installed_token = installed.installed_token().unwrap().clone();

        *RECOVERY_AFTER_PARENT_CHECK_TEST_HOOK.lock().unwrap() = Some(Box::new({
            let live = live.clone();
            let moved = moved.clone();
            move || {
                fs::rename(&live, &moved).unwrap();
                fs::create_dir(&live).unwrap();
                fs::write(live.join("settings.json"), b"replacement\n").unwrap();
            }
        }));

        assert_eq!(
            native.recover_interrupted_replace_observed_with_provenance(
                &path,
                before.fingerprint(),
                &desired.fingerprint(),
                &TEST_NONCE,
                before.object_token(),
                Some(&installed_token),
            ),
            Err(RunnerError::ConcurrentChange)
        );
        assert_eq!(
            fs::read(live.join("settings.json")).unwrap(),
            b"replacement\n"
        );
        assert_eq!(fs::read(moved.join("settings.json")).unwrap(), b"after\n");
        assert_eq!(
            fs::read(moved.join(OsStr::from_bytes(backup.to_bytes()))).unwrap(),
            b"before\n"
        );

        fs::remove_dir_all(root).unwrap();
    }
}
