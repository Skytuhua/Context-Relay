use std::{
    ffi::{OsStr, OsString, c_void},
    fs::File,
    io::{Read, Seek, SeekFrom},
    mem::size_of,
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::{AsRawHandle, FromRawHandle},
    },
    path::{Path, PathBuf},
    ptr::{null, null_mut},
};

use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use windows_sys::Win32::{
    Foundation::{
        ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_HANDLE_EOF,
        ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, ERROR_PATH_NOT_FOUND, GENERIC_READ,
        GENERIC_WRITE, GetLastError, HANDLE, INVALID_HANDLE_VALUE, NTSTATUS, OBJ_CASE_INSENSITIVE,
        OBJ_DONT_REPARSE, RtlNtStatusToDosError, STATUS_REPARSE_POINT_ENCOUNTERED,
        STATUS_STOPPED_ON_SYMLINK, UNICODE_STRING,
    },
    Security::{
        DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, GetKernelObjectSecurity,
        OWNER_SECURITY_INFORMATION, SetKernelObjectSecurity,
    },
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_ATTRIBUTE_TAG_INFO, FILE_BASIC_INFO, FILE_DISPOSITION_FLAG_DELETE,
        FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
        FILE_DISPOSITION_INFO_EX, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_ID_INFO,
        FILE_READ_ATTRIBUTES, FILE_RENAME_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_STANDARD_INFO, FILE_STREAM_INFO, FILE_TRAVERSE,
        FileAttributeTagInfo, FileBasicInfo, FileDispositionInfoEx, FileIdInfo, FileStandardInfo,
        FileStreamInfo, FlushFileBuffers, GetFileInformationByHandle, GetFileInformationByHandleEx,
        SYNCHRONIZE, SetFileInformationByHandle, WRITE_DAC, WRITE_OWNER,
    },
};

use super::{
    AlternateStream, CaptureError, NativeMetadata, NativeMutationOutcome, NativeObjectToken,
    NativeSnapshot, NativeState,
};
use crate::RunnerError;

const MAX_SNAPSHOT_BYTES: u64 = 200 * 1024 * 1024;
const DEFAULT_STREAM: &str = "::$DATA";
const MAX_WIN32_PATH_UNITS: usize = 259;
const STABLE_DIRECTORY_SHARE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE;
const FILE_OPEN: u32 = 1;
const FILE_CREATE: u32 = 2;
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
#[cfg(test)]
static PRE_RENAME_TEST_HOOK: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>> =
    std::sync::Mutex::new(None);
#[cfg(test)]
static POST_INSTALL_TEST_HOOK: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>> =
    std::sync::Mutex::new(None);
#[cfg(test)]
static INSTALLED_VERIFY_TEST_HOOK: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>> =
    std::sync::Mutex::new(None);
#[cfg(test)]
type FileTestHook = Box<dyn FnOnce(&mut File) + Send>;
#[cfg(test)]
static POST_TEMP_CREATE_TEST_HOOK: std::sync::Mutex<Option<FileTestHook>> =
    std::sync::Mutex::new(None);
#[cfg(test)]
static CAPTURE_FINAL_TEST_HOOK: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>> =
    std::sync::Mutex::new(None);
#[cfg(test)]
static RECOVERY_PRE_DESTRUCTIVE_TEST_HOOK: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>> =
    std::sync::Mutex::new(None);
#[cfg(test)]
static PRE_ROLLBACK_TEST_HOOK: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>> =
    std::sync::Mutex::new(None);
#[cfg(test)]
static PRE_RENAME_TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
fn run_pre_rename_test_hook() {
    if let Some(hook) = PRE_RENAME_TEST_HOOK.lock().expect("test hook lock").take() {
        hook();
    }
}

#[cfg(test)]
fn run_post_install_test_hook() {
    if let Some(hook) = POST_INSTALL_TEST_HOOK
        .lock()
        .expect("test hook lock")
        .take()
    {
        hook();
    }
}

#[cfg(test)]
fn run_installed_verify_test_hook() {
    if let Some(hook) = INSTALLED_VERIFY_TEST_HOOK
        .lock()
        .expect("test hook lock")
        .take()
    {
        hook();
    }
}

#[cfg(test)]
fn run_post_temp_create_test_hook(file: &mut File) {
    if let Some(hook) = POST_TEMP_CREATE_TEST_HOOK
        .lock()
        .expect("test hook lock")
        .take()
    {
        hook(file);
    }
}

#[cfg(test)]
fn run_capture_final_test_hook() {
    if let Some(hook) = CAPTURE_FINAL_TEST_HOOK
        .lock()
        .expect("test hook lock")
        .take()
    {
        hook();
    }
}

#[cfg(test)]
fn run_recovery_pre_destructive_test_hook() {
    if let Some(hook) = RECOVERY_PRE_DESTRUCTIVE_TEST_HOOK
        .lock()
        .expect("test hook lock")
        .take()
    {
        hook();
    }
}

#[cfg(test)]
fn run_pre_rollback_test_hook() {
    if let Some(hook) = PRE_ROLLBACK_TEST_HOOK
        .lock()
        .expect("test hook lock")
        .take()
    {
        hook();
    }
}

#[repr(C)]
union IoStatusValue {
    status: NTSTATUS,
    pointer: *mut c_void,
}

#[repr(C)]
struct IoStatusBlock {
    value: IoStatusValue,
    information: usize,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: HANDLE,
    object_name: *mut UNICODE_STRING,
    attributes: u32,
    security_descriptor: *mut c_void,
    security_quality_of_service: *mut c_void,
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtCreateFile(
        file_handle: *mut HANDLE,
        desired_access: u32,
        object_attributes: *const ObjectAttributes,
        io_status_block: *mut IoStatusBlock,
        allocation_size: *const i64,
        file_attributes: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        ea_buffer: *const c_void,
        ea_length: u32,
    ) -> NTSTATUS;

    fn NtSetInformationFile(
        file_handle: HANDLE,
        io_status_block: *mut IoStatusBlock,
        file_information: *const c_void,
        length: u32,
        file_information_class: i32,
    ) -> NTSTATUS;
}

struct HeldPath {
    handles: Vec<File>,
    parent_path: PathBuf,
    name: OsString,
    volume: u64,
}

impl HeldPath {
    fn new(path: &Path) -> Result<Self, RunnerError> {
        Self::new_with_name_policy(path, true)
    }

    fn for_inspection(path: &Path) -> Result<Self, RunnerError> {
        Self::new_with_name_policy(path, false)
    }

    fn new_with_name_policy(path: &Path, require_nfc: bool) -> Result<Self, RunnerError> {
        let (mut parent_path, names) = validated_components(path, require_nfc)?;
        let name = names.last().cloned().ok_or(RunnerError::InvalidPath)?;
        let root = open_absolute_directory(&parent_path)?;
        let root_node = raw_node(&root)?;
        if !root_node.directory || root_node.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(RunnerError::UnsafeTopology);
        }
        let volume = root_node.identity.VolumeSerialNumber;
        let mut handles = vec![root];
        for component in &names[..names.len() - 1] {
            let directory = nt_open_relative(
                handles.last().ok_or(RunnerError::Io)?,
                component,
                FILE_TRAVERSE | FILE_READ_ATTRIBUTES,
                STABLE_DIRECTORY_SHARE,
                FILE_OPEN,
                FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
            )
            .map_err(|error| match error {
                NtOpenError::Reparse => RunnerError::UnsafeTopology,
                _ => open_runner_error(error),
            })?;
            let node = raw_node(&directory)?;
            if !node.directory
                || node.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
                || node.identity.VolumeSerialNumber != volume
            {
                return Err(RunnerError::UnsafeTopology);
            }
            parent_path.push(component);
            handles.push(directory);
        }
        Ok(Self {
            handles,
            parent_path,
            name,
            volume,
        })
    }

    fn parent(&self) -> Result<&File, RunnerError> {
        self.handles.last().ok_or(RunnerError::Io)
    }

    fn parent_node(&self) -> Result<RawNode, RunnerError> {
        let node = raw_node(self.parent()?)?;
        if !node.directory
            || node.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || node.identity.VolumeSerialNumber != self.volume
        {
            return Err(RunnerError::UnsafeTopology);
        }
        Ok(node)
    }

    fn open_flushable_parent(&self) -> Result<File, RunnerError> {
        let parent = open_absolute_directory_with_access(
            &self.parent_path,
            FILE_TRAVERSE | FILE_READ_ATTRIBUTES | GENERIC_WRITE,
        )?;
        if identity(&parent)? != identity(self.parent()?)? {
            return Err(RunnerError::UnsafeTopology);
        }
        Ok(parent)
    }

    fn open_target(&self, desired_access: u32, share: u32) -> Result<File, NtOpenError> {
        nt_open_relative(
            self.parent().map_err(|_| NtOpenError::Io)?,
            &self.name,
            desired_access,
            share,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
        )
    }

    fn create_named(&self, name: &OsStr, desired_access: u32) -> Result<File, RunnerError> {
        validate_name(name, true)?;
        nt_open_relative(
            self.parent()?,
            name,
            desired_access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
        )
        .map_err(open_runner_error)
    }
}

#[derive(Clone, Copy)]
enum NtOpenError {
    Missing,
    Exists,
    Reparse,
    Io,
}

fn validated_components(
    path: &Path,
    require_nfc: bool,
) -> Result<(PathBuf, Vec<OsString>), RunnerError> {
    let raw = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if raw.len() < 4
        || raw.len() > MAX_WIN32_PATH_UNITS
        || !(u16::from(b'A')..=u16::from(b'Z')).contains(&raw[0])
        || raw[1] != u16::from(b':')
        || raw[2] != u16::from(b'\\')
        || raw.contains(&0)
        || raw.contains(&u16::from(b'/'))
    {
        return Err(RunnerError::InvalidPath);
    }
    let drive = u8::try_from(raw[0]).map_err(|_| RunnerError::InvalidPath)?;
    let mut names = Vec::new();
    for component in raw[3..].split(|unit| *unit == u16::from(b'\\')) {
        if component.is_empty() {
            return Err(RunnerError::InvalidPath);
        }
        let name = OsString::from_wide(component);
        validate_name(&name, require_nfc)?;
        names.push(name);
    }
    Ok((
        PathBuf::from(OsString::from_wide(&[
            u16::from(drive),
            u16::from(b':'),
            u16::from(b'\\'),
        ])),
        names,
    ))
}

fn validate_name(name: &OsStr, require_nfc: bool) -> Result<(), RunnerError> {
    let units = name.encode_wide().collect::<Vec<_>>();
    let text = String::from_utf16(&units).map_err(|_| RunnerError::InvalidPath)?;
    if units.is_empty()
        || units.len() > 255
        || units.contains(&0)
        || units.iter().any(|unit| {
            *unit <= 0x1f
                || *unit == 0x7f
                || matches!(
                    *unit,
                    value if value == u16::from(b'<')
                        || value == u16::from(b'>')
                        || value == u16::from(b':')
                        || value == u16::from(b'"')
                        || value == u16::from(b'/')
                        || value == u16::from(b'\\')
                        || value == u16::from(b'|')
                        || value == u16::from(b'?')
                        || value == u16::from(b'*')
                )
        })
        || matches!(units.last(), Some(unit) if *unit == b'.' as u16 || *unit == b' ' as u16)
        || text == "."
        || text == ".."
        || internal_recovery_name(&text)
        || (require_nfc && text.nfc().ne(text.chars()))
        || reserved_windows_name(&text)
    {
        return Err(RunnerError::InvalidPath);
    }
    Ok(())
}

fn internal_backup_name(name: &str) -> bool {
    const PREFIX: &str = ".context-relay-";
    const SUFFIX: &str = ".backup";
    if name.len() != PREFIX.len() + 64 + SUFFIX.len() {
        return false;
    }
    name.get(..PREFIX.len())
        .is_some_and(|value| value.eq_ignore_ascii_case(PREFIX))
        && name
            .get(name.len() - SUFFIX.len()..)
            .is_some_and(|value| value.eq_ignore_ascii_case(SUFFIX))
        && name
            .get(PREFIX.len()..name.len() - SUFFIX.len())
            .is_some_and(|value| value.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn internal_temp_name(name: &str) -> bool {
    const PREFIX: &str = ".context-relay-";
    const SUFFIX: &str = ".tmp";
    if name.len() != PREFIX.len() + 64 + 1 + 32 + SUFFIX.len() {
        return false;
    }
    let digest_start = PREFIX.len();
    let separator = digest_start + 64;
    let nonce_end = separator + 1 + 32;
    name.get(..digest_start)
        .is_some_and(|value| value.eq_ignore_ascii_case(PREFIX))
        && name.as_bytes().get(separator) == Some(&b'-')
        && name
            .get(nonce_end..)
            .is_some_and(|value| value.eq_ignore_ascii_case(SUFFIX))
        && name
            .get(digest_start..separator)
            .is_some_and(|value| value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        && name
            .get(separator + 1..nonce_end)
            .is_some_and(|value| value.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn internal_recovery_name(name: &str) -> bool {
    internal_backup_name(name) || internal_temp_name(name)
}

fn reserved_windows_name(name: &str) -> bool {
    let stem = name
        .split('.')
        .next()
        .unwrap_or_default()
        .trim_end_matches([' ', '.'])
        .to_uppercase();
    matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
    ) || (stem.len() == 4
        && (stem.starts_with("COM") || stem.starts_with("LPT"))
        && matches!(stem.as_bytes()[3], b'1'..=b'9'))
        || matches!(
            stem.as_str(),
            "COM¹" | "COM²" | "COM³" | "LPT¹" | "LPT²" | "LPT³"
        )
}

fn open_absolute_directory(path: &Path) -> Result<File, RunnerError> {
    open_absolute_directory_with_access(path, FILE_TRAVERSE | FILE_READ_ATTRIBUTES)
}

fn open_absolute_directory_with_access(
    path: &Path,
    desired_access: u32,
) -> Result<File, RunnerError> {
    let mut name = OsString::from(r"\??");
    name.push(r"\");
    name.push(path.as_os_str());
    nt_open(
        null_mut(),
        &name,
        desired_access,
        STABLE_DIRECTORY_SHARE,
        FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
    )
    .map_err(open_runner_error)
}

fn nt_open_relative(
    parent: &File,
    name: &OsStr,
    desired_access: u32,
    share_access: u32,
    create_disposition: u32,
    create_options: u32,
) -> Result<File, NtOpenError> {
    nt_open(
        parent.as_raw_handle() as HANDLE,
        name,
        desired_access,
        share_access,
        create_disposition,
        create_options,
    )
}

fn nt_open(
    root_directory: HANDLE,
    name: &OsStr,
    desired_access: u32,
    share_access: u32,
    create_disposition: u32,
    create_options: u32,
) -> Result<File, NtOpenError> {
    let mut name = name.encode_wide().collect::<Vec<_>>();
    let bytes = name
        .len()
        .checked_mul(size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or(NtOpenError::Io)?;
    if name.is_empty() || name.contains(&0) {
        return Err(NtOpenError::Io);
    }
    let mut unicode = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: name.as_mut_ptr(),
    };
    let attributes = ObjectAttributes {
        length: size_of::<ObjectAttributes>() as u32,
        root_directory,
        object_name: &mut unicode,
        attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        security_descriptor: null_mut(),
        security_quality_of_service: null_mut(),
    };
    let mut status_block = IoStatusBlock {
        value: IoStatusValue {
            pointer: null_mut(),
        },
        information: 0,
    };
    let mut handle = INVALID_HANDLE_VALUE;
    let mut mapped_access = desired_access & !(GENERIC_READ | GENERIC_WRITE);
    if desired_access & GENERIC_READ != 0 {
        mapped_access |= FILE_GENERIC_READ;
    }
    if desired_access & GENERIC_WRITE != 0 {
        mapped_access |= FILE_GENERIC_WRITE;
    }
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            mapped_access | SYNCHRONIZE,
            &attributes,
            &mut status_block,
            null(),
            FILE_ATTRIBUTE_NORMAL,
            share_access,
            create_disposition,
            create_options,
            null(),
            0,
        )
    };
    if status >= 0 && handle != INVALID_HANDLE_VALUE {
        return Ok(unsafe { File::from_raw_handle(handle) });
    }
    if matches!(
        status,
        STATUS_REPARSE_POINT_ENCOUNTERED | STATUS_STOPPED_ON_SYMLINK
    ) {
        return Err(NtOpenError::Reparse);
    }
    let error = unsafe { RtlNtStatusToDosError(status) };
    if matches!(error, ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) {
        Err(NtOpenError::Missing)
    } else if matches!(error, ERROR_FILE_EXISTS | ERROR_ALREADY_EXISTS) {
        Err(NtOpenError::Exists)
    } else {
        Err(NtOpenError::Io)
    }
}

const fn open_runner_error(error: NtOpenError) -> RunnerError {
    match error {
        NtOpenError::Reparse => RunnerError::UnsafeTopology,
        NtOpenError::Missing | NtOpenError::Exists | NtOpenError::Io => RunnerError::Io,
    }
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
    attributes: u32,
    links: u64,
    alternate_streams: usize,
}

impl CapturedNode {
    pub const fn unsafe_topology(&self) -> bool {
        self.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || self.links != 1
            || self.alternate_streams != 0
    }
}

pub(super) fn snapshot(path: &Path) -> Result<NativeSnapshot, RunnerError> {
    snapshot_held(&HeldPath::new(path)?)
}

#[cfg(test)]
pub(super) fn compare_and_swap(
    path: &Path,
    expected: &[u8; 32],
    expected_token: Option<&NativeObjectToken>,
    desired: &NativeState,
    transaction_nonce: &[u8; 16],
) -> Result<NativeMutationOutcome, RunnerError> {
    compare_and_swap_with_provenance(
        path,
        expected,
        expected_token,
        desired,
        transaction_nonce,
        &mut |_| Ok(()),
    )
    .map_err(super::NativeMutationFailure::into_error)
}

pub(super) fn compare_and_swap_with_provenance(
    path: &Path,
    expected: &[u8; 32],
    expected_token: Option<&NativeObjectToken>,
    desired: &NativeState,
    transaction_nonce: &[u8; 16],
    persist_candidate: &mut dyn FnMut(&NativeObjectToken) -> Result<(), RunnerError>,
) -> Result<NativeMutationOutcome, super::NativeMutationFailure> {
    let held = HeldPath::new(path).map_err(super::NativeMutationFailure::from)?;
    let current = snapshot_held(&held).map_err(super::NativeMutationFailure::from)?;
    if current.fingerprint() != expected
        || expected_token.is_some_and(|token| current.object_token() != Some(token))
    {
        return Err(RunnerError::ConcurrentChange.into());
    }
    if matches!(
        (current.state(), desired),
        (NativeState::Absent { .. }, NativeState::Absent { .. })
    ) || current.fingerprint() == &super::fingerprint(desired)
    {
        return Ok(NativeMutationOutcome {
            wrote: false,
            snapshot: current,
            installed_token: None,
        });
    }
    let mut installed_token = None;
    let write = match desired {
        NativeState::Absent { .. } => delete_regular_file_held(
            &held,
            current
                .object_token()
                .ok_or(RunnerError::ConcurrentChange)
                .map_err(super::NativeMutationFailure::from)?,
            expected,
            &mut installed_token,
            persist_candidate,
        ),
        NativeState::RegularFile { bytes, metadata } => {
            let current_token = matches!(current.state(), NativeState::RegularFile { .. })
                .then(|| current.object_token())
                .flatten();
            replace_regular_file_held(
                &held,
                current_token,
                expected,
                bytes,
                metadata,
                super::fingerprint(desired),
                transaction_nonce,
                &mut installed_token,
                persist_candidate,
            )
        }
    };
    if let Err(error) = write {
        let Some(token) = installed_token else {
            return Err(error.into());
        };
        return Err(super::NativeMutationFailure::installed(error, token));
    }
    let installed_token = installed_token
        .ok_or_else(|| super::NativeMutationFailure::from(RunnerError::ConcurrentChange))?;
    let snapshot = snapshot_held(&held)
        .map_err(|error| super::NativeMutationFailure::installed(error, installed_token.clone()))?;
    if !matches!(
        (snapshot.state(), desired),
        (NativeState::Absent { .. }, NativeState::Absent { .. })
    ) && snapshot.fingerprint() != &super::fingerprint(desired)
    {
        return Err(super::NativeMutationFailure::installed(
            RunnerError::ConcurrentChange,
            installed_token,
        ));
    }
    Ok(NativeMutationOutcome {
        wrote: true,
        snapshot,
        installed_token: Some(installed_token),
    })
}

fn cleanup_recovery_temp(held: &HeldPath, transaction_nonce: &[u8; 16]) -> Result<(), RunnerError> {
    let name = temp_name(&held.name, transaction_nonce);
    let file = match nt_open_relative(
        held.parent()?,
        &name,
        GENERIC_READ | DELETE,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
    ) {
        Ok(file) => file,
        Err(NtOpenError::Missing) => return Ok(()),
        Err(_) => return Err(RunnerError::ConcurrentChange),
    };
    let node = raw_node(&file).map_err(|_| RunnerError::ConcurrentChange)?;
    if node.identity.VolumeSerialNumber != held.volume
        || node.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || node.directory
        || node.links != 1
    {
        return Err(RunnerError::ConcurrentChange);
    }
    let reopened = nt_open_relative(
        held.parent()?,
        &name,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
    )
    .map_err(|_| RunnerError::ConcurrentChange)?;
    if identity(&file).map_err(|_| RunnerError::ConcurrentChange)?
        != identity(&reopened).map_err(|_| RunnerError::ConcurrentChange)?
    {
        return Err(RunnerError::ConcurrentChange);
    }
    let final_node = raw_node(&file).map_err(|_| RunnerError::ConcurrentChange)?;
    let reopened_node = raw_node(&reopened).map_err(|_| RunnerError::ConcurrentChange)?;
    if final_node.links != 1
        || reopened_node.links != 1
        || final_node.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || reopened_node.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || final_node.directory
        || reopened_node.directory
        || final_node.identity.VolumeSerialNumber != held.volume
        || reopened_node.identity.VolumeSerialNumber != held.volume
        || final_node.identity.FileId.Identifier != reopened_node.identity.FileId.Identifier
    {
        return Err(RunnerError::ConcurrentChange);
    }
    let durable_parent = held.open_flushable_parent()?;
    set_disposition(&file)?;
    drop(reopened);
    drop(file);
    flush_handle(&durable_parent)
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
    let held = HeldPath::new(path)?;
    if let Some(expected) = expected_parent_binding {
        let snapshot = snapshot_held(&held)?;
        if snapshot
            .object_token()
            .is_none_or(|actual| !actual.has_same_parent_binding(expected))
        {
            return Err(RunnerError::ConcurrentChange);
        }
    }
    cleanup_recovery_temp(&held, transaction_nonce)?;
    let name = backup_name(&held.name);
    let mut backup = match open_recovery_backup(&held, &name) {
        Ok(file) => file,
        Err(NtOpenError::Missing) => {
            let current = snapshot_held(&held)?;
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
        Err(_) => return Err(RunnerError::ConcurrentChange),
    };
    let captured =
        capture_open_file(&held, &name, &mut backup).map_err(|_| RunnerError::ConcurrentChange)?;
    let backup_token = captured.token.clone();
    let backup_metadata = captured.metadata.clone();
    let backup_state = NativeState::RegularFile {
        bytes: captured.bytes,
        metadata: captured.metadata,
    };
    if super::fingerprint(&backup_state) != *before_fingerprint {
        return Err(RunnerError::ConcurrentChange);
    }
    if expected_backup_token.is_some_and(|expected| expected != &backup_token) {
        return Err(RunnerError::ConcurrentChange);
    }
    let durable_parent = held.open_flushable_parent()?;

    let mut target = match held.open_target(GENERIC_READ | DELETE, FILE_SHARE_READ) {
        Ok(file) => file,
        Err(NtOpenError::Missing) => {
            let current = snapshot_held(&held)?;
            if (current.fingerprint() == applied_fingerprint
                && !provenance.accepts_applied(current.object_token()))
                || (current.fingerprint() != applied_fingerprint
                    && expected_backup_token.is_none()
                    && !provenance.permits_unattributed_missing_restore())
            {
                return Ok(super::NativeRecoveryDisposition::Abandoned);
            }
            #[cfg(test)]
            run_recovery_pre_destructive_test_hook();
            validate_target_missing(&held)?;
            restore_named_backup(
                &held,
                &durable_parent,
                &name,
                &mut backup,
                &backup_metadata,
                &backup_token,
                before_fingerprint,
            )?;
            return Ok(super::NativeRecoveryDisposition::Restored);
        }
        Err(_) => return Err(RunnerError::ConcurrentChange),
    };
    let captured = capture_open_file(&held, &held.name, &mut target)
        .map_err(|_| RunnerError::ConcurrentChange)?;
    let target_token = captured.token.clone();
    let target_state = NativeState::RegularFile {
        bytes: captured.bytes,
        metadata: captured.metadata,
    };
    let target_fingerprint = super::fingerprint(&target_state);
    if target_fingerprint == *before_fingerprint {
        #[cfg(test)]
        run_recovery_pre_destructive_test_hook();
        validate_backup_state(&held, &name, &mut backup, &backup_token, before_fingerprint)?;
        validate_backup_state(
            &held,
            &held.name,
            &mut target,
            &target_token,
            before_fingerprint,
        )?;
        validate_backup_state(&held, &name, &mut backup, &backup_token, before_fingerprint)?;
        set_disposition(&backup)?;
        drop(backup);
        flush_handle(&durable_parent)?;
        return Ok(super::NativeRecoveryDisposition::Restored);
    }
    if target_fingerprint != *applied_fingerprint {
        return Err(RunnerError::ConcurrentChange);
    }
    if !provenance.accepts_applied(Some(&target_token)) {
        return Ok(super::NativeRecoveryDisposition::Abandoned);
    }

    #[cfg(test)]
    run_recovery_pre_destructive_test_hook();
    validate_backup_state(&held, &name, &mut backup, &backup_token, before_fingerprint)?;
    validate_backup_state(
        &held,
        &held.name,
        &mut target,
        &target_token,
        applied_fingerprint,
    )?;
    set_disposition(&target)?;
    drop(target);
    flush_handle(&durable_parent)?;
    restore_named_backup(
        &held,
        &durable_parent,
        &name,
        &mut backup,
        &backup_metadata,
        &backup_token,
        before_fingerprint,
    )?;
    Ok(super::NativeRecoveryDisposition::Restored)
}

pub(super) fn cleanup_committed_delete(
    path: &Path,
    before_fingerprint: &[u8; 32],
    _transaction_nonce: &[u8; 16],
    original_token: &NativeObjectToken,
) -> Result<(), RunnerError> {
    let held = HeldPath::new(path)?;
    let name = backup_name(&held.name);
    let mut backup = match open_recovery_backup(&held, &name) {
        Ok(file) => file,
        Err(NtOpenError::Missing) => return Ok(()),
        Err(_) => return Err(RunnerError::ConcurrentChange),
    };
    let captured =
        capture_open_file(&held, &name, &mut backup).map_err(|_| RunnerError::ConcurrentChange)?;
    let token = captured.token;
    let state = NativeState::RegularFile {
        bytes: captured.bytes,
        metadata: captured.metadata,
    };
    if token != *original_token || super::fingerprint(&state) != *before_fingerprint {
        return Err(RunnerError::ConcurrentChange);
    }
    let durable_parent = held.open_flushable_parent()?;
    set_disposition(&backup)?;
    drop(backup);
    flush_handle(&durable_parent)
}

fn open_recovery_backup(held: &HeldPath, name: &OsStr) -> Result<File, NtOpenError> {
    nt_open_relative(
        held.parent().map_err(|_| NtOpenError::Io)?,
        name,
        GENERIC_READ | GENERIC_WRITE | DELETE,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
    )
}

fn validate_target_missing(held: &HeldPath) -> Result<(), RunnerError> {
    match held.open_target(FILE_READ_ATTRIBUTES, FILE_SHARE_READ) {
        Err(NtOpenError::Missing) => Ok(()),
        Err(_) | Ok(_) => Err(RunnerError::ConcurrentChange),
    }
}

fn snapshot_held(held: &HeldPath) -> Result<NativeSnapshot, RunnerError> {
    match capture_file_held(held) {
        Ok(captured) => {
            let state = NativeState::RegularFile {
                bytes: captured.bytes,
                metadata: captured.metadata,
            };
            Ok(NativeSnapshot {
                fingerprint: super::fingerprint(&state),
                state,
                object_token: Some(captured.token),
            })
        }
        Err(CaptureError::Missing) => {
            let before = held.parent_node()?;
            validate_target_missing(held)?;
            let after = held.parent_node()?;
            if !raw_node_unchanged(&before, &after) {
                return Err(RunnerError::ConcurrentChange);
            }
            let state = NativeState::absent(after.attributes, after.links);
            Ok(NativeSnapshot {
                fingerprint: super::fingerprint(&state),
                state,
                object_token: Some(absent_token(&after)),
            })
        }
        Err(CaptureError::Runner(error)) => Err(error),
    }
}

fn validate_absent_state(
    held: &HeldPath,
    expected_fingerprint: &[u8; 32],
) -> Result<(), RunnerError> {
    match held.open_target(FILE_READ_ATTRIBUTES, FILE_SHARE_READ) {
        Err(NtOpenError::Missing) => {}
        Err(NtOpenError::Reparse) => return Err(RunnerError::UnsafeTopology),
        Err(NtOpenError::Exists | NtOpenError::Io) | Ok(_) => {
            return Err(RunnerError::ConcurrentChange);
        }
    }
    let parent = held.parent_node()?;
    if super::absent_fingerprint(parent.attributes, parent.links) != *expected_fingerprint {
        return Err(RunnerError::ConcurrentChange);
    }
    Ok(())
}

pub(super) fn create_new_file(path: &Path) -> Result<File, RunnerError> {
    let held = HeldPath::new(path)?;
    held.create_named(&held.name, GENERIC_READ | GENERIC_WRITE | DELETE)
}

pub(super) fn identity_matches_path(file: &File, path: &Path) -> Result<bool, RunnerError> {
    let held = HeldPath::new(path)?;
    let reopened = held
        .open_target(
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        )
        .map_err(open_runner_error)?;
    Ok(identity(file)? == identity(&reopened)?)
}

#[allow(
    clippy::too_many_arguments,
    reason = "the guarded replace phases require both before and intended identities"
)]
fn replace_regular_file_held(
    held: &HeldPath,
    expected: Option<&NativeObjectToken>,
    expected_fingerprint: &[u8; 32],
    bytes: &[u8],
    metadata: &NativeMetadata,
    intended_fingerprint: [u8; 32],
    transaction_nonce: &[u8; 16],
    installed_token: &mut Option<NativeObjectToken>,
    persist_candidate: &mut dyn FnMut(&NativeObjectToken) -> Result<(), RunnerError>,
) -> Result<(), RunnerError> {
    super::validate_state(bytes, metadata)?;
    let durable_parent = held.open_flushable_parent()?;
    let (temporary_name, temporary) = create_adjacent_temp(held, transaction_nonce)?;
    let mut cleanup = PendingTemp(Some(temporary));
    #[cfg(test)]
    run_post_temp_create_test_hook(cleanup.file_mut()?);
    let file = cleanup.file_mut()?;
    use std::io::Write as _;
    file.write_all(bytes).map_err(|_| RunnerError::Io)?;
    file.sync_all().map_err(|_| RunnerError::Io)?;
    let temporary_identity = identity(file)?;
    for stream in &metadata.alternate_streams {
        let stream_name = stream_object_name(&temporary_name, &stream.name)?;
        let mut output = nt_open_relative(
            held.parent()?,
            &stream_name,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
        )
        .map_err(open_runner_error)?;
        if identity(&output)? != temporary_identity {
            return Err(RunnerError::ConcurrentChange);
        }
        output
            .write_all(&stream.bytes)
            .map_err(|_| RunnerError::Io)?;
        output.sync_all().map_err(|_| RunnerError::Io)?;
    }
    let basic = basic_info(metadata);
    set_security_descriptor(cleanup.file()?, &metadata.security_descriptor)?;
    set_basic_info(cleanup.file()?, &basic)?;
    cleanup.file()?.sync_all().map_err(|_| RunnerError::Io)?;
    let staged = capture_open_file(held, &temporary_name, cleanup.file_mut()?).map_err(
        |error| match error {
            CaptureError::Missing => RunnerError::ConcurrentChange,
            CaptureError::Runner(error) => error,
        },
    )?;
    let staged_state = NativeState::RegularFile {
        bytes: staged.bytes,
        metadata: staged.metadata,
    };
    if super::fingerprint(&staged_state) != intended_fingerprint {
        return Err(RunnerError::ConcurrentChange);
    }
    let staged_token = staged.token;

    let mut backup = match expected {
        Some(expected) => {
            let mut current = held
                .open_target(GENERIC_READ | GENERIC_WRITE | DELETE, FILE_SHARE_READ)
                .map_err(|error| match error {
                    NtOpenError::Reparse => RunnerError::UnsafeTopology,
                    _ => RunnerError::ConcurrentChange,
                })?;
            let captured =
                capture_open_file(held, &held.name, &mut current).map_err(|error| match error {
                    CaptureError::Runner(RunnerError::UnsafeTopology) => {
                        RunnerError::UnsafeTopology
                    }
                    _ => RunnerError::ConcurrentChange,
                })?;
            let before_metadata = captured.metadata.clone();
            let state = NativeState::RegularFile {
                bytes: captured.bytes,
                metadata: captured.metadata,
            };
            if captured.token != *expected || super::fingerprint(&state) != *expected_fingerprint {
                return Err(RunnerError::ConcurrentChange);
            }
            Some((current, before_metadata))
        }
        None => {
            validate_absent_state(held, expected_fingerprint)?;
            None
        }
    };

    persist_candidate(&staged_token)?;
    let backup_name = backup_name(&held.name);
    if let Some((backup_file, before_metadata)) = backup.as_mut() {
        rename_to_backup(backup_file, held.parent()?, &backup_name)
            .map_err(|_| RunnerError::ConcurrentChange)?;
        let validation = (|| {
            set_basic_info(backup_file, &basic_info(before_metadata))?;
            flush_handle(backup_file)?;
            validate_backup_state(
                held,
                &backup_name,
                backup_file,
                expected.ok_or(RunnerError::ConcurrentChange)?,
                expected_fingerprint,
            )?;
            flush_handle(&durable_parent)
        })();
        if let Err(error) = validation {
            let _ = restore_backup(
                held,
                &durable_parent,
                backup_file,
                before_metadata,
                expected.ok_or(RunnerError::ConcurrentChange)?,
                expected_fingerprint,
            );
            return Err(error);
        }
    }

    #[cfg(test)]
    run_pre_rename_test_hook();

    if backup.is_none() {
        validate_absent_state(held, expected_fingerprint)?;
    }

    if let Some((backup_file, before_metadata)) = backup.as_mut()
        && let Err(error) = validate_backup_state(
            held,
            &backup_name,
            backup_file,
            expected.ok_or(RunnerError::ConcurrentChange)?,
            expected_fingerprint,
        )
    {
        let _ = restore_backup(
            held,
            &durable_parent,
            backup_file,
            before_metadata,
            expected.ok_or(RunnerError::ConcurrentChange)?,
            expected_fingerprint,
        );
        return Err(error);
    }

    if rename_to_parent(cleanup.file()?, held.parent()?, &held.name).is_err() {
        if let Some((backup_file, before_metadata)) = backup.as_mut() {
            let _ = restore_backup(
                held,
                &durable_parent,
                backup_file,
                before_metadata,
                expected.ok_or(RunnerError::ConcurrentChange)?,
                expected_fingerprint,
            );
        }
        return Err(RunnerError::ConcurrentChange);
    }
    *installed_token = Some(staged_token.clone());

    let mut final_file = cleanup.take()?;
    #[cfg(test)]
    run_installed_verify_test_hook();
    let mut rollback_safe = false;
    let verification = (|| {
        set_basic_info(&final_file, &basic)?;
        final_file.sync_all().map_err(|_| RunnerError::Io)?;
        let installed =
            capture_open_file(held, &held.name, &mut final_file).map_err(|error| match error {
                CaptureError::Runner(RunnerError::UnsafeTopology) => RunnerError::UnsafeTopology,
                _ => RunnerError::ConcurrentChange,
            })?;
        let (installed_token, full_fingerprint, object_fingerprint) =
            captured_fingerprints(installed, metadata);
        rollback_safe =
            installed_token == staged_token && object_fingerprint == intended_fingerprint;
        if installed_token != staged_token || full_fingerprint != intended_fingerprint {
            return Err(RunnerError::ConcurrentChange);
        }
        flush_handle(&durable_parent)
    })();
    if let Err(error) = verification {
        #[cfg(test)]
        run_pre_rollback_test_hook();
        if let Some((backup_file, _)) = backup.as_mut()
            && validate_backup_state(
                held,
                &backup_name,
                backup_file,
                expected.ok_or(RunnerError::ConcurrentChange)?,
                expected_fingerprint,
            )
            .is_err()
        {
            return Err(RunnerError::ConcurrentChange);
        }
        if !rollback_safe {
            return Err(error);
        }
        let rollback = rollback_installed(
            held,
            &durable_parent,
            final_file,
            backup.as_mut().map(|(file, metadata)| (file, &*metadata)),
            expected,
            InstalledExpectation {
                token: &staged_token,
                metadata,
                fingerprint: intended_fingerprint,
            },
            expected_fingerprint,
        );
        return if rollback.is_ok() {
            Err(error)
        } else {
            Err(RunnerError::ConcurrentChange)
        };
    }

    #[cfg(test)]
    run_post_install_test_hook();

    if validate_installed_state(
        held,
        &mut final_file,
        &staged_token,
        metadata,
        intended_fingerprint,
    )
    .is_err()
    {
        return Err(RunnerError::ConcurrentChange);
    }

    if let Some((backup_file, _)) = backup.as_mut() {
        if validate_backup_state(
            held,
            &backup_name,
            backup_file,
            expected.ok_or(RunnerError::ConcurrentChange)?,
            expected_fingerprint,
        )
        .is_err()
        {
            let _ = rollback_changed_backup(
                held,
                &durable_parent,
                final_file,
                backup_file,
                &staged_token,
                metadata,
                intended_fingerprint,
            );
            return Err(RunnerError::ConcurrentChange);
        }
        if validate_installed_state(
            held,
            &mut final_file,
            &staged_token,
            metadata,
            intended_fingerprint,
        )
        .is_err()
        {
            return Err(RunnerError::ConcurrentChange);
        }
    }

    if let Some((backup_file, _)) = backup {
        set_disposition(&backup_file)?;
        drop(backup_file);
        flush_handle(&durable_parent)?;
    }
    Ok(())
}

fn delete_regular_file_held(
    held: &HeldPath,
    expected: &NativeObjectToken,
    expected_fingerprint: &[u8; 32],
    installed_token: &mut Option<NativeObjectToken>,
    persist_candidate: &mut dyn FnMut(&NativeObjectToken) -> Result<(), RunnerError>,
) -> Result<(), RunnerError> {
    let durable_parent = held.open_flushable_parent()?;
    let mut file = held
        .open_target(GENERIC_READ | GENERIC_WRITE | DELETE, FILE_SHARE_READ)
        .map_err(|error| match error {
            NtOpenError::Reparse => RunnerError::UnsafeTopology,
            _ => RunnerError::ConcurrentChange,
        })?;
    let captured = capture_open_file(held, &held.name, &mut file).map_err(|error| match error {
        CaptureError::Runner(RunnerError::UnsafeTopology) => RunnerError::UnsafeTopology,
        _ => RunnerError::ConcurrentChange,
    })?;
    let before_metadata = captured.metadata.clone();
    let state = NativeState::RegularFile {
        bytes: captured.bytes,
        metadata: captured.metadata,
    };
    if captured.token != *expected || super::fingerprint(&state) != *expected_fingerprint {
        return Err(RunnerError::ConcurrentChange);
    }
    let backup_name = backup_name(&held.name);
    rename_to_backup(&file, held.parent()?, &backup_name)
        .map_err(|_| RunnerError::ConcurrentChange)?;
    set_basic_info(&file, &basic_info(&before_metadata))?;
    flush_handle(&file)?;
    flush_handle(&durable_parent)?;
    if validate_backup_state(
        held,
        &backup_name,
        &mut file,
        expected,
        expected_fingerprint,
    )
    .is_err()
    {
        let _ = restore_named_backup(
            held,
            &durable_parent,
            &backup_name,
            &mut file,
            &before_metadata,
            expected,
            expected_fingerprint,
        );
        return Err(RunnerError::ConcurrentChange);
    }
    let snapshot = snapshot_held(held)?;
    let absent_token = snapshot
        .object_token()
        .filter(|_| matches!(snapshot.state(), NativeState::Absent { .. }))
        .ok_or(RunnerError::ConcurrentChange)?
        .clone();
    if let Err(error) = persist_candidate(&absent_token) {
        let _ = restore_named_backup(
            held,
            &durable_parent,
            &backup_name,
            &mut file,
            &before_metadata,
            expected,
            expected_fingerprint,
        );
        return Err(error);
    }
    *installed_token = Some(absent_token);
    flush_handle(&durable_parent)
}

pub(super) fn capture_absent_parent(path: &Path) -> Result<(u32, u64), RunnerError> {
    let held = HeldPath::new(path)?;
    let parent = held.parent_node()?;
    Ok((parent.attributes, parent.links))
}

fn set_basic_info(file: &File, basic: &FILE_BASIC_INFO) -> Result<(), RunnerError> {
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle() as HANDLE,
            FileBasicInfo,
            (basic as *const FILE_BASIC_INFO).cast(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        return Err(RunnerError::Io);
    }
    Ok(())
}

const fn basic_info(metadata: &NativeMetadata) -> FILE_BASIC_INFO {
    FILE_BASIC_INFO {
        CreationTime: metadata.creation_time,
        LastAccessTime: metadata.last_access_time,
        LastWriteTime: metadata.last_write_time,
        ChangeTime: metadata.change_time,
        FileAttributes: metadata.file_attributes,
    }
}

fn backup_name(target: &OsStr) -> OsString {
    let digest = target_name_hash(target);
    let mut name = String::with_capacity(15 + digest.len() * 2 + 7);
    name.push_str(".context-relay-");
    push_hex(&mut name, &digest);
    name.push_str(".backup");
    OsString::from(name)
}

fn temp_name(target: &OsStr, transaction_nonce: &[u8; 16]) -> OsString {
    let digest = target_name_hash(target);
    let mut name = String::with_capacity(15 + digest.len() * 2 + 1 + 32 + 4);
    name.push_str(".context-relay-");
    push_hex(&mut name, &digest);
    name.push('-');
    push_hex(&mut name, transaction_nonce);
    name.push_str(".tmp");
    OsString::from(name)
}

fn target_name_hash(target: &OsStr) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for unit in target.encode_wide() {
        hasher.update(unit.to_le_bytes());
    }
    hasher.finalize().into()
}

fn push_hex(output: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
}

struct PendingTemp(Option<File>);

impl PendingTemp {
    fn file(&self) -> Result<&File, RunnerError> {
        self.0.as_ref().ok_or(RunnerError::Io)
    }

    fn file_mut(&mut self) -> Result<&mut File, RunnerError> {
        self.0.as_mut().ok_or(RunnerError::Io)
    }

    fn take(&mut self) -> Result<File, RunnerError> {
        self.0.take().ok_or(RunnerError::Io)
    }
}

impl Drop for PendingTemp {
    fn drop(&mut self) {
        if let Some(file) = self.0.take() {
            let _ = set_disposition(&file);
        }
    }
}

fn create_adjacent_temp(
    held: &HeldPath,
    transaction_nonce: &[u8; 16],
) -> Result<(OsString, File), RunnerError> {
    let name = temp_name(&held.name, transaction_nonce);
    let file = nt_open_relative(
        held.parent()?,
        &name,
        GENERIC_READ | GENERIC_WRITE | DELETE | WRITE_DAC | WRITE_OWNER,
        FILE_SHARE_READ,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
    )
    .map_err(|error| match error {
        NtOpenError::Exists => RunnerError::ConcurrentChange,
        _ => open_runner_error(error),
    })?;
    Ok((name, file))
}

pub(super) fn capture_file(path: &Path) -> Result<CapturedFile, CaptureError> {
    let held = HeldPath::new(path).map_err(CaptureError::Runner)?;
    capture_file_held(&held)
}

fn capture_file_held(held: &HeldPath) -> Result<CapturedFile, CaptureError> {
    capture_named_file(held, &held.name, FILE_SHARE_READ)
}

fn capture_named_file(
    held: &HeldPath,
    name: &OsStr,
    share: u32,
) -> Result<CapturedFile, CaptureError> {
    let mut file = match nt_open_relative(
        held.parent().map_err(CaptureError::Runner)?,
        name,
        GENERIC_READ,
        share,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
    ) {
        Ok(file) => file,
        Err(NtOpenError::Missing) => return Err(CaptureError::Missing),
        Err(NtOpenError::Reparse) => {
            return Err(CaptureError::Runner(RunnerError::UnsafeTopology));
        }
        Err(NtOpenError::Exists | NtOpenError::Io) => {
            return Err(CaptureError::Runner(RunnerError::Io));
        }
    };
    capture_open_file(held, name, &mut file)
}

fn capture_open_file(
    held: &HeldPath,
    name: &OsStr,
    file: &mut File,
) -> Result<CapturedFile, CaptureError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| CaptureError::Runner(RunnerError::Io))?;
    let node = raw_node(file)?;
    if node.identity.VolumeSerialNumber != held.volume
        || node.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || node.directory
        || node.links != 1
    {
        return Err(CaptureError::Runner(RunnerError::UnsafeTopology));
    }
    if node.size > MAX_SNAPSHOT_BYTES {
        return Err(CaptureError::Runner(RunnerError::LimitExceeded));
    }
    let mut bytes = Vec::with_capacity(node.size as usize);
    file.read_to_end(&mut bytes)
        .map_err(|_| CaptureError::Runner(RunnerError::Io))?;
    #[cfg(test)]
    run_capture_final_test_hook();
    let reopened = nt_open_relative(
        held.parent().map_err(CaptureError::Runner)?,
        name,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
    )
    .map_err(|error| CaptureError::Runner(open_runner_error(error)))?;
    if bytes.len() as u64 != node.size || identity(file)? != identity(&reopened)? {
        return Err(CaptureError::Runner(RunnerError::ConcurrentChange));
    }
    let streams = alternate_streams(held, name, file, true)?;
    let parent_node = held.parent_node()?;
    let token = token(&node, &parent_node);
    let metadata = NativeMetadata {
        file_attributes: node.attributes,
        creation_time: node.basic.CreationTime,
        last_access_time: node.basic.LastAccessTime,
        last_write_time: node.basic.LastWriteTime,
        change_time: node.basic.ChangeTime,
        security_descriptor: security_descriptor(file)?,
        alternate_streams: streams,
        link_count: node.links,
        parent_attributes: parent_node.attributes,
        parent_link_count: parent_node.links,
    };
    let after = raw_node(file)?;
    let reopened_after = raw_node(&reopened)?;
    if after.links != 1
        || reopened_after.links != 1
        || !raw_node_unchanged(&node, &after)
        || !raw_node_unchanged(&after, &reopened_after)
    {
        return Err(CaptureError::Runner(RunnerError::ConcurrentChange));
    }
    Ok(CapturedFile {
        bytes,
        metadata,
        token,
    })
}

pub(super) fn capture_node(path: &Path, forbid_streams: bool) -> Result<CapturedNode, RunnerError> {
    let held = HeldPath::for_inspection(path)?;
    let file = nt_open_relative(
        held.parent()?,
        &held.name,
        GENERIC_READ,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
    )
    .map_err(open_runner_error)?;
    let node = raw_node(&file)?;
    if node.identity.VolumeSerialNumber != held.volume || node.links != 1 {
        return Err(RunnerError::UnsafeTopology);
    }
    let parent_node = held.parent_node()?;
    let streams = alternate_streams(&held, &held.name, &file, false)?;
    let named_streams = streams.len();
    if forbid_streams && named_streams != 0 {
        return Err(RunnerError::UnsafeTopology);
    }
    let mut hash = Sha256::new();
    hash.update(b"context-relay/native-tree-node/v1\0");
    hash.update([u8::from(node.directory)]);
    hash.update(node.attributes.to_be_bytes());
    hash.update(node.links.to_be_bytes());
    hash.update(node.size.to_be_bytes());
    hash.update(node.basic.CreationTime.to_be_bytes());
    hash.update(node.basic.LastWriteTime.to_be_bytes());
    if !node.directory && node.attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
        let mut content = &file;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = content.read(&mut buffer).map_err(|_| RunnerError::Io)?;
            if count == 0 {
                break;
            }
            hash.update(&buffer[..count]);
        }
    }
    #[cfg(test)]
    run_capture_final_test_hook();
    let reopened = nt_open_relative(
        held.parent()?,
        &held.name,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
    )
    .map_err(open_runner_error)?;
    if identity(&file)? != identity(&reopened)? {
        return Err(RunnerError::ConcurrentChange);
    }
    let after = raw_node(&file)?;
    let reopened_after = raw_node(&reopened)?;
    if after.links != 1
        || reopened_after.links != 1
        || !raw_node_unchanged(&node, &after)
        || !raw_node_unchanged(&after, &reopened_after)
    {
        return Err(RunnerError::ConcurrentChange);
    }
    Ok(CapturedNode {
        directory: node.directory,
        token: token(&node, &parent_node),
        fingerprint: hash.finalize().into(),
        attributes: node.attributes,
        links: node.links,
        alternate_streams: named_streams,
    })
}

#[derive(Clone)]
struct RawNode {
    basic: FILE_BASIC_INFO,
    identity: FILE_ID_INFO,
    attributes: u32,
    reparse_tag: u32,
    links: u64,
    size: u64,
    directory: bool,
}

fn raw_node_unchanged(before: &RawNode, after: &RawNode) -> bool {
    before.identity.VolumeSerialNumber == after.identity.VolumeSerialNumber
        && before.identity.FileId.Identifier == after.identity.FileId.Identifier
        && before.reparse_tag == after.reparse_tag
        && before.attributes == after.attributes
        && before.directory == after.directory
        && before.links == after.links
        && before.size == after.size
        && before.basic.CreationTime == after.basic.CreationTime
        && before.basic.LastWriteTime == after.basic.LastWriteTime
        && before.basic.ChangeTime == after.basic.ChangeTime
        && before.basic.FileAttributes == after.basic.FileAttributes
}

fn raw_node(file: &File) -> Result<RawNode, RunnerError> {
    let handle = file.as_raw_handle() as HANDLE;
    let mut basic = FILE_BASIC_INFO::default();
    let mut id = FILE_ID_INFO::default();
    let mut standard = FILE_STANDARD_INFO::default();
    let mut tag = FILE_ATTRIBUTE_TAG_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileBasicInfo,
            (&mut basic as *mut FILE_BASIC_INFO).cast(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
        || unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileIdInfo,
                (&mut id as *mut FILE_ID_INFO).cast(),
                size_of::<FILE_ID_INFO>() as u32,
            )
        } == 0
        || unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileStandardInfo,
                (&mut standard as *mut FILE_STANDARD_INFO).cast(),
                size_of::<FILE_STANDARD_INFO>() as u32,
            )
        } == 0
        || unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileAttributeTagInfo,
                (&mut tag as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
                size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
            )
        } == 0
    {
        return Err(RunnerError::Io);
    }
    Ok(RawNode {
        basic,
        identity: id,
        attributes: tag.FileAttributes,
        reparse_tag: tag.ReparseTag,
        links: u64::from(standard.NumberOfLinks),
        size: u64::try_from(standard.EndOfFile).map_err(|_| RunnerError::UnsafeTopology)?,
        directory: standard.Directory,
    })
}

fn token(node: &RawNode, parent: &RawNode) -> NativeObjectToken {
    NativeObjectToken {
        volume: node.identity.VolumeSerialNumber,
        object: node.identity.FileId.Identifier,
        reparse_tag: node.reparse_tag,
        parent_volume: parent.identity.VolumeSerialNumber,
        parent_object: parent.identity.FileId.Identifier,
    }
}

fn absent_token(parent: &RawNode) -> NativeObjectToken {
    let mut hasher = Sha256::new();
    hasher.update(b"context-relay/absent-token/windows/v1\0");
    hasher.update(parent.identity.VolumeSerialNumber.to_le_bytes());
    hasher.update(parent.identity.FileId.Identifier);
    hasher.update(parent.basic.ChangeTime.to_le_bytes());
    hasher.update(parent.basic.LastWriteTime.to_le_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut object = [0_u8; 16];
    object.copy_from_slice(&digest[..16]);
    NativeObjectToken {
        volume: parent.identity.VolumeSerialNumber,
        object,
        reparse_tag: super::ABSENT_TOKEN_TAG,
        parent_volume: parent.identity.VolumeSerialNumber,
        parent_object: parent.identity.FileId.Identifier,
    }
}

fn identity(file: &File) -> Result<(u64, u64, u64), RunnerError> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info) } == 0 {
        return Err(RunnerError::Io);
    }
    Ok((
        u64::from(info.dwVolumeSerialNumber),
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        u64::from(info.nNumberOfLinks),
    ))
}

fn set_disposition(file: &File) -> Result<(), RunnerError> {
    set_disposition_flags(
        file,
        FILE_DISPOSITION_FLAG_DELETE
            | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
            | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
    )
}

fn set_disposition_flags(file: &File, flags: u32) -> Result<(), RunnerError> {
    let disposition = FILE_DISPOSITION_INFO_EX { Flags: flags };
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle() as HANDLE,
            FileDispositionInfoEx,
            (&disposition as *const FILE_DISPOSITION_INFO_EX).cast(),
            size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    } == 0
    {
        return Err(RunnerError::Io);
    }
    Ok(())
}

fn rename_to_parent(source: &File, parent: &File, destination: &OsStr) -> Result<(), RunnerError> {
    validate_name(destination, true)?;
    rename_to_parent_raw(source, parent, destination)
}

fn rename_to_backup(source: &File, parent: &File, destination: &OsStr) -> Result<(), RunnerError> {
    let name = destination.to_str().ok_or(RunnerError::InvalidPath)?;
    if !internal_backup_name(name) {
        return Err(RunnerError::InvalidPath);
    }
    rename_to_parent_raw(source, parent, destination)
}

fn rename_to_parent_raw(
    source: &File,
    parent: &File,
    destination: &OsStr,
) -> Result<(), RunnerError> {
    let name = destination.encode_wide().collect::<Vec<_>>();
    let name_bytes = name
        .len()
        .checked_mul(size_of::<u16>())
        .and_then(|length| u32::try_from(length).ok())
        .ok_or(RunnerError::InvalidPath)?;
    let header = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
    let length = header
        .checked_add(name_bytes as usize)
        .ok_or(RunnerError::InvalidPath)?;
    let mut storage = vec![0_usize; length.div_ceil(size_of::<usize>())];
    let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    unsafe {
        (*info).Anonymous.Flags = 0;
        (*info).RootDirectory = parent.as_raw_handle() as HANDLE;
        (*info).FileNameLength = name_bytes;
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            std::ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
            name.len(),
        );
        let mut status_block = IoStatusBlock {
            value: IoStatusValue {
                pointer: null_mut(),
            },
            information: 0,
        };
        let status = NtSetInformationFile(
            source.as_raw_handle() as HANDLE,
            &mut status_block,
            info.cast(),
            length as u32,
            65,
        );
        if status < 0 {
            return Err(RunnerError::Io);
        }
    }
    Ok(())
}

fn restore_backup(
    held: &HeldPath,
    durable_parent: &File,
    backup: &mut File,
    metadata: &NativeMetadata,
    expected_token: &NativeObjectToken,
    expected_fingerprint: &[u8; 32],
) -> Result<(), RunnerError> {
    let name = backup_name(&held.name);
    restore_named_backup(
        held,
        durable_parent,
        &name,
        backup,
        metadata,
        expected_token,
        expected_fingerprint,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "restoring a held backup requires its exact name, identity, metadata, and state"
)]
fn restore_named_backup(
    held: &HeldPath,
    durable_parent: &File,
    name: &OsStr,
    backup: &mut File,
    metadata: &NativeMetadata,
    expected_token: &NativeObjectToken,
    expected_fingerprint: &[u8; 32],
) -> Result<(), RunnerError> {
    validate_backup_state(held, name, backup, expected_token, expected_fingerprint)?;
    rename_to_parent(backup, held.parent()?, &held.name)
        .map_err(|_| RunnerError::ConcurrentChange)?;
    set_basic_info(backup, &basic_info(metadata))?;
    flush_handle(backup)?;
    let captured = capture_open_file(held, &held.name, backup).map_err(|error| match error {
        CaptureError::Runner(RunnerError::UnsafeTopology) => RunnerError::UnsafeTopology,
        _ => RunnerError::ConcurrentChange,
    })?;
    let state = NativeState::RegularFile {
        bytes: captured.bytes,
        metadata: captured.metadata,
    };
    if super::fingerprint(&state) != *expected_fingerprint {
        return Err(RunnerError::ConcurrentChange);
    }
    flush_handle(durable_parent)
}

fn rollback_installed(
    held: &HeldPath,
    durable_parent: &File,
    mut installed: File,
    backup: Option<(&mut File, &NativeMetadata)>,
    expected_token: Option<&NativeObjectToken>,
    intended: InstalledExpectation<'_>,
    expected_fingerprint: &[u8; 32],
) -> Result<(), RunnerError> {
    let captured = capture_open_file(held, &held.name, &mut installed)
        .map_err(|_| RunnerError::ConcurrentChange)?;
    let (installed_token, _, object_fingerprint) =
        captured_fingerprints(captured, intended.metadata);
    if installed_token != *intended.token || object_fingerprint != intended.fingerprint {
        return Err(RunnerError::ConcurrentChange);
    }
    set_disposition(&installed)?;
    drop(installed);
    flush_handle(durable_parent)?;
    if let Some((backup, metadata)) = backup {
        restore_backup(
            held,
            durable_parent,
            backup,
            metadata,
            expected_token.ok_or(RunnerError::ConcurrentChange)?,
            expected_fingerprint,
        )?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct InstalledExpectation<'a> {
    token: &'a NativeObjectToken,
    metadata: &'a NativeMetadata,
    fingerprint: [u8; 32],
}

fn rollback_changed_backup(
    held: &HeldPath,
    durable_parent: &File,
    mut installed: File,
    backup: &File,
    staged_token: &NativeObjectToken,
    intended_metadata: &NativeMetadata,
    intended_fingerprint: [u8; 32],
) -> Result<(), RunnerError> {
    let captured = capture_open_file(held, &held.name, &mut installed)
        .map_err(|_| RunnerError::ConcurrentChange)?;
    let (installed_token, _, object_fingerprint) =
        captured_fingerprints(captured, intended_metadata);
    if installed_token != *staged_token || object_fingerprint != intended_fingerprint {
        return Err(RunnerError::ConcurrentChange);
    }
    set_disposition(&installed)?;
    drop(installed);
    flush_handle(durable_parent)?;
    rename_to_parent(backup, held.parent()?, &held.name)
        .map_err(|_| RunnerError::ConcurrentChange)?;
    flush_handle(backup)?;
    flush_handle(durable_parent)
}

fn captured_fingerprints(
    captured: CapturedFile,
    intended_metadata: &NativeMetadata,
) -> (NativeObjectToken, [u8; 32], [u8; 32]) {
    let token = captured.token;
    let mut state = NativeState::RegularFile {
        bytes: captured.bytes,
        metadata: captured.metadata,
    };
    let full = super::fingerprint(&state);
    if let NativeState::RegularFile { metadata, .. } = &mut state {
        metadata.parent_attributes = intended_metadata.parent_attributes;
        metadata.parent_link_count = intended_metadata.parent_link_count;
    }
    let object = super::fingerprint(&state);
    (token, full, object)
}

fn validate_installed_state(
    held: &HeldPath,
    installed: &mut File,
    staged_token: &NativeObjectToken,
    intended_metadata: &NativeMetadata,
    intended_fingerprint: [u8; 32],
) -> Result<(), RunnerError> {
    let captured = capture_open_file(held, &held.name, installed)
        .map_err(|_| RunnerError::ConcurrentChange)?;
    let (token, full, object) = captured_fingerprints(captured, intended_metadata);
    if token != *staged_token || full != intended_fingerprint || object != intended_fingerprint {
        return Err(RunnerError::ConcurrentChange);
    }
    Ok(())
}

fn validate_backup_state(
    held: &HeldPath,
    name: &OsStr,
    backup: &mut File,
    expected_token: &NativeObjectToken,
    expected_fingerprint: &[u8; 32],
) -> Result<(), RunnerError> {
    let captured =
        capture_open_file(held, name, backup).map_err(|_| RunnerError::ConcurrentChange)?;
    let state = NativeState::RegularFile {
        bytes: captured.bytes,
        metadata: captured.metadata,
    };
    if captured.token != *expected_token || super::fingerprint(&state) != *expected_fingerprint {
        return Err(RunnerError::ConcurrentChange);
    }
    Ok(())
}

fn alternate_streams(
    held: &HeldPath,
    name: &OsStr,
    file: &File,
    include_bytes: bool,
) -> Result<Vec<AlternateStream>, RunnerError> {
    let mut capacity = 4096_usize;
    let buffer = loop {
        let mut buffer = vec![0_u64; capacity.div_ceil(size_of::<u64>())];
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle() as HANDLE,
                FileStreamInfo,
                buffer.as_mut_ptr().cast(),
                capacity as u32,
            )
        } != 0
        {
            break buffer;
        }
        let error = unsafe { GetLastError() };
        if error == ERROR_HANDLE_EOF {
            return Ok(Vec::new());
        }
        if !matches!(error, ERROR_MORE_DATA | ERROR_INSUFFICIENT_BUFFER) || capacity >= 1024 * 1024
        {
            return Err(RunnerError::Io);
        }
        capacity *= 2;
    };
    let header = std::mem::offset_of!(FILE_STREAM_INFO, StreamName);
    let base = buffer.as_ptr().cast::<u8>();
    let mut output = Vec::new();
    let mut offset = 0_usize;
    let base_identity = identity(file)?;
    let mut total = 0_u64;
    loop {
        if offset.checked_add(header).is_none_or(|end| end > capacity) {
            return Err(RunnerError::Io);
        }
        let info = unsafe { std::ptr::read_unaligned(base.add(offset).cast::<FILE_STREAM_INFO>()) };
        let name_bytes = usize::try_from(info.StreamNameLength).map_err(|_| RunnerError::Io)?;
        if name_bytes % 2 != 0
            || offset
                .checked_add(header)
                .and_then(|start| start.checked_add(name_bytes))
                .is_none_or(|end| end > capacity)
            || info.StreamSize < 0
        {
            return Err(RunnerError::Io);
        }
        let units = unsafe {
            std::slice::from_raw_parts(
                base.add(offset + header).cast::<u16>(),
                name_bytes / size_of::<u16>(),
            )
        };
        let stream_name = String::from_utf16(units).map_err(|_| RunnerError::Io)?;
        if stream_name != DEFAULT_STREAM {
            let size = info.StreamSize as u64;
            total = total.checked_add(size).ok_or(RunnerError::LimitExceeded)?;
            if size > MAX_SNAPSHOT_BYTES || total > MAX_SNAPSHOT_BYTES {
                return Err(RunnerError::LimitExceeded);
            }
            let bytes = if include_bytes {
                let object_name = stream_object_name(name, &stream_name)?;
                let mut stream = nt_open_relative(
                    held.parent()?,
                    &object_name,
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    FILE_OPEN,
                    FILE_NON_DIRECTORY_FILE
                        | FILE_SYNCHRONOUS_IO_NONALERT
                        | FILE_OPEN_REPARSE_POINT,
                )
                .map_err(open_runner_error)?;
                if identity(&stream)? != base_identity {
                    return Err(RunnerError::ConcurrentChange);
                }
                let mut bytes = Vec::with_capacity(size as usize);
                stream
                    .read_to_end(&mut bytes)
                    .map_err(|_| RunnerError::Io)?;
                if bytes.len() as u64 != size {
                    return Err(RunnerError::ConcurrentChange);
                }
                bytes
            } else {
                Vec::new()
            };
            output.push(AlternateStream {
                name: stream_name,
                bytes,
            });
        }
        if info.NextEntryOffset == 0 {
            break;
        }
        let next = info.NextEntryOffset as usize;
        if next < header + name_bytes || offset.checked_add(next).is_none_or(|end| end >= capacity)
        {
            return Err(RunnerError::Io);
        }
        offset += next;
    }
    output.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(output)
}

fn security_descriptor(file: &File) -> Result<Vec<u8>, RunnerError> {
    let information =
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut needed = 0;
    unsafe {
        GetKernelObjectSecurity(
            file.as_raw_handle() as HANDLE,
            information,
            null_mut(),
            0,
            &mut needed,
        );
    }
    if needed == 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        return Err(RunnerError::Io);
    }
    let mut descriptor = vec![0_u8; needed as usize];
    if unsafe {
        GetKernelObjectSecurity(
            file.as_raw_handle() as HANDLE,
            information,
            descriptor.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(RunnerError::Io);
    }
    descriptor.truncate(needed as usize);
    Ok(descriptor)
}

#[cfg(test)]
mod pre_rename_tests {
    use std::{fs, process::Command, time::SystemTime};

    use super::*;
    use crate::{NativeRecoveryDisposition, NativeState, OsNativeFileSystem, RunnerError};

    const TEST_NONCE: [u8; 16] = [0x3c; 16];
    const TEMP_ABORT_PATH_ENV: &str = "CONTEXT_RELAY_TEMP_ABORT_PATH";
    const TEMP_ABORT_SIGNAL_ENV: &str = "CONTEXT_RELAY_TEMP_ABORT_SIGNAL";

    fn test_root(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "context-relay-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        root
    }

    fn simulate_crash_gap(path: &Path, before: &NativeSnapshot) -> PathBuf {
        let held = HeldPath::new(path).unwrap();
        let name = backup_name(&held.name);
        let mut file =
            match held.open_target(GENERIC_READ | GENERIC_WRITE | DELETE, FILE_SHARE_READ) {
                Ok(file) => file,
                Err(_) => panic!("open target for crash-gap simulation"),
            };
        rename_to_backup(&file, held.parent().unwrap(), &name).unwrap();
        set_basic_info(&file, &basic_info(before.metadata().unwrap())).unwrap();
        flush_handle(&file).unwrap();
        flush_handle(&held.open_flushable_parent().unwrap()).unwrap();
        let captured = capture_open_file(&held, &name, &mut file).unwrap();
        let state = NativeState::RegularFile {
            bytes: captured.bytes,
            metadata: captured.metadata,
        };
        assert_eq!(super::super::fingerprint(&state), *before.fingerprint());
        drop(file);
        path.parent().unwrap().join(name)
    }

    fn recover(
        path: &Path,
        before_fingerprint: &[u8; 32],
        applied_fingerprint: &[u8; 32],
    ) -> Result<(), RunnerError> {
        OsNativeFileSystem::new().recover_interrupted_replace(
            path,
            before_fingerprint,
            applied_fingerprint,
            &TEST_NONCE,
        )
    }

    fn cas(
        path: &Path,
        expected: &[u8; 32],
        desired: &NativeState,
    ) -> Result<NativeMutationOutcome, RunnerError> {
        compare_and_swap(path, expected, None, desired, &TEST_NONCE)
    }

    #[test]
    fn empty_target_window_preserves_attacker_and_recoverable_before_state() {
        let _serial = PRE_RENAME_TEST_SERIAL.lock().unwrap();
        let root = test_root("pre-rename-race");
        let path = root.join("settings.json");
        fs::write(&path, b"before\n").unwrap();
        let before = snapshot(&path).unwrap();
        let desired = NativeState::regular_file(
            b"context-relay\n".to_vec(),
            before.metadata().unwrap().clone(),
        );
        let applied_fingerprint = desired.fingerprint();
        let attacker_path = path.clone();
        *PRE_RENAME_TEST_HOOK.lock().unwrap() = Some(Box::new(move || {
            assert!(
                !attacker_path.exists(),
                "target must be empty during the hook"
            );
            fs::write(attacker_path, b"attacker\n").unwrap();
        }));

        assert_eq!(
            cas(&path, before.fingerprint(), &desired),
            Err(RunnerError::ConcurrentChange)
        );
        assert_eq!(fs::read(&path).unwrap(), b"attacker\n");
        let backup = fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name().is_some_and(|name| {
                    let name = name.to_string_lossy();
                    name.starts_with(".context-relay-") && name.ends_with(".backup")
                })
            })
            .expect("recoverable backup");
        assert_eq!(fs::read(&backup).unwrap(), b"before\n");
        assert_eq!(
            recover(&path, before.fingerprint(), &applied_fingerprint),
            Err(RunnerError::ConcurrentChange)
        );
        assert_eq!(fs::read(&path).unwrap(), b"attacker\n");
        assert_eq!(fs::read(&backup).unwrap(), b"before\n");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn injected_backup_hardlink_is_detected_by_final_recheck() {
        let _serial = PRE_RENAME_TEST_SERIAL.lock().unwrap();
        let root = test_root("backup-hardlink-race");
        let path = root.join("settings.json");
        fs::write(&path, b"before\n").unwrap();
        let before = snapshot(&path).unwrap();
        let desired = NativeState::regular_file(
            b"context-relay\n".to_vec(),
            before.metadata().unwrap().clone(),
        );
        let backup = root.join(backup_name(path.file_name().unwrap()));
        let alias = root.join("attacker-alias.json");
        *PRE_RENAME_TEST_HOOK.lock().unwrap() = Some(Box::new({
            let backup = backup.clone();
            let alias = alias.clone();
            move || fs::hard_link(backup, alias).unwrap()
        }));

        assert_eq!(
            cas(&path, before.fingerprint(), &desired),
            Err(RunnerError::ConcurrentChange)
        );
        assert!(!path.exists());
        assert_eq!(fs::read(&backup).unwrap(), b"before\n");
        assert_eq!(fs::read(&alias).unwrap(), b"before\n");

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn post_install_backup_change_rolls_back_installed_target() {
        let _serial = PRE_RENAME_TEST_SERIAL.lock().unwrap();
        let root = test_root("post-install-backup-race");
        let path = root.join("settings.json");
        fs::write(&path, b"before\n").unwrap();
        let before = snapshot(&path).unwrap();
        let desired = NativeState::regular_file(
            b"context-relay\n".to_vec(),
            before.metadata().unwrap().clone(),
        );
        let backup = root.join(backup_name(path.file_name().unwrap()));
        let alias = root.join("attacker-alias.json");
        *POST_INSTALL_TEST_HOOK.lock().unwrap() = Some(Box::new({
            let backup = backup.clone();
            let alias = alias.clone();
            move || fs::hard_link(backup, alias).unwrap()
        }));

        assert_eq!(
            cas(&path, before.fingerprint(), &desired),
            Err(RunnerError::ConcurrentChange)
        );
        assert_eq!(fs::read(&path).unwrap(), b"before\n");
        assert!(!backup.exists());
        assert_eq!(fs::read(&alias).unwrap(), b"before\n");

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn absent_parent_change_aborts_without_installing_target() {
        let _serial = PRE_RENAME_TEST_SERIAL.lock().unwrap();
        let root = test_root("absent-parent-race");
        let template = root.join("template.json");
        let path = root.join("settings.json");
        fs::write(&template, b"template\n").unwrap();
        let template = snapshot(&template).unwrap();
        let absent = snapshot(&path).unwrap();
        let desired = NativeState::regular_file(
            b"context-relay\n".to_vec(),
            template.metadata().unwrap().clone(),
        );
        let held = HeldPath::new(&path).unwrap();
        let parent = held.open_flushable_parent().unwrap();
        let original = raw_node(&parent).unwrap().basic;
        let changed = FILE_BASIC_INFO {
            FileAttributes: original.FileAttributes | 0x2,
            ..original
        };
        *PRE_RENAME_TEST_HOOK.lock().unwrap() = Some(Box::new(move || {
            set_basic_info(&parent, &changed).unwrap();
            flush_handle(&parent).unwrap();
        }));
        drop(held);

        assert_eq!(
            cas(&path, absent.fingerprint(), &desired),
            Err(RunnerError::ConcurrentChange)
        );
        assert!(!path.exists());

        let held = HeldPath::new(&path).unwrap();
        let parent = held.open_flushable_parent().unwrap();
        set_basic_info(&parent, &original).unwrap();
        flush_handle(&parent).unwrap();
        drop(parent);
        drop(held);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn post_install_parent_change_rolls_back_absent_target() {
        let _serial = PRE_RENAME_TEST_SERIAL.lock().unwrap();
        let root = test_root("post-install-parent-race");
        let template = root.join("template.json");
        let path = root.join("settings.json");
        fs::write(&template, b"template\n").unwrap();
        let template = snapshot(&template).unwrap();
        let absent = snapshot(&path).unwrap();
        let desired = NativeState::regular_file(
            b"context-relay\n".to_vec(),
            template.metadata().unwrap().clone(),
        );
        let held = HeldPath::new(&path).unwrap();
        let parent = held.open_flushable_parent().unwrap();
        let original = raw_node(&parent).unwrap().basic;
        let changed = FILE_BASIC_INFO {
            FileAttributes: original.FileAttributes | 0x2,
            ..original
        };
        *INSTALLED_VERIFY_TEST_HOOK.lock().unwrap() = Some(Box::new(move || {
            set_basic_info(&parent, &changed).unwrap();
            flush_handle(&parent).unwrap();
        }));
        drop(held);

        assert_eq!(
            cas(&path, absent.fingerprint(), &desired),
            Err(RunnerError::ConcurrentChange)
        );
        assert!(!path.exists());

        let held = HeldPath::new(&path).unwrap();
        let parent = held.open_flushable_parent().unwrap();
        set_basic_info(&parent, &original).unwrap();
        flush_handle(&parent).unwrap();
        drop(parent);
        drop(held);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn installed_ads_change_is_preserved_with_recoverable_backup() {
        let _serial = PRE_RENAME_TEST_SERIAL.lock().unwrap();
        let root = test_root("installed-ads-race");
        let path = root.join("settings.json");
        fs::write(&path, b"before\n").unwrap();
        let before = snapshot(&path).unwrap();
        let desired = NativeState::regular_file(
            b"context-relay\n".to_vec(),
            before.metadata().unwrap().clone(),
        );
        let backup = root.join(backup_name(path.file_name().unwrap()));
        let mut stream_name = path.as_os_str().to_os_string();
        stream_name.push(":attacker");
        let stream = PathBuf::from(stream_name);
        *INSTALLED_VERIFY_TEST_HOOK.lock().unwrap() = Some(Box::new({
            let stream = stream.clone();
            move || fs::write(stream, b"attacker\n").unwrap()
        }));

        assert_eq!(
            cas(&path, before.fingerprint(), &desired),
            Err(RunnerError::ConcurrentChange)
        );
        assert_eq!(fs::read(&path).unwrap(), b"context-relay\n");
        assert_eq!(fs::read(&stream).unwrap(), b"attacker\n");
        assert_eq!(fs::read(&backup).unwrap(), b"before\n");
        assert_ne!(
            snapshot(&path).unwrap().fingerprint(),
            &desired.fingerprint()
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn post_install_ads_change_preserves_target_and_recoverable_backup() {
        let _serial = PRE_RENAME_TEST_SERIAL.lock().unwrap();
        let root = test_root("post-install-ads-race");
        let path = root.join("settings.json");
        fs::write(&path, b"before\n").unwrap();
        let before = snapshot(&path).unwrap();
        let desired = NativeState::regular_file(
            b"context-relay\n".to_vec(),
            before.metadata().unwrap().clone(),
        );
        let backup = root.join(backup_name(path.file_name().unwrap()));
        let mut stream_name = path.as_os_str().to_os_string();
        stream_name.push(":attacker");
        let stream = PathBuf::from(stream_name);
        *POST_INSTALL_TEST_HOOK.lock().unwrap() = Some(Box::new({
            let stream = stream.clone();
            move || fs::write(stream, b"attacker\n").unwrap()
        }));

        assert_eq!(
            cas(&path, before.fingerprint(), &desired),
            Err(RunnerError::ConcurrentChange)
        );
        assert_eq!(fs::read(&path).unwrap(), b"context-relay\n");
        assert_eq!(fs::read(&stream).unwrap(), b"attacker\n");
        assert_eq!(fs::read(&backup).unwrap(), b"before\n");

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rollback_final_recheck_preserves_late_ads_and_backup() {
        let _serial = PRE_RENAME_TEST_SERIAL.lock().unwrap();
        let root = test_root("rollback-final-ads-race");
        let path = root.join("settings.json");
        fs::write(&path, b"before\n").unwrap();
        let before = snapshot(&path).unwrap();
        let desired = NativeState::regular_file(
            b"context-relay\n".to_vec(),
            before.metadata().unwrap().clone(),
        );
        let backup = root.join(backup_name(path.file_name().unwrap()));
        let mut stream_name = path.as_os_str().to_os_string();
        stream_name.push(":attacker");
        let stream = PathBuf::from(stream_name);
        let held = HeldPath::new(&path).unwrap();
        let parent = held.open_flushable_parent().unwrap();
        let parent_for_verify = parent.try_clone().unwrap();
        let original = raw_node(&parent).unwrap().basic;
        let changed = FILE_BASIC_INFO {
            FileAttributes: original.FileAttributes | 0x2,
            ..original
        };
        *INSTALLED_VERIFY_TEST_HOOK.lock().unwrap() = Some(Box::new(move || {
            set_basic_info(&parent_for_verify, &changed).unwrap();
            flush_handle(&parent_for_verify).unwrap();
        }));
        *PRE_ROLLBACK_TEST_HOOK.lock().unwrap() = Some(Box::new({
            let stream = stream.clone();
            move || {
                set_basic_info(&parent, &original).unwrap();
                flush_handle(&parent).unwrap();
                fs::write(stream, b"attacker\n").unwrap();
            }
        }));
        drop(held);

        assert_eq!(
            cas(&path, before.fingerprint(), &desired),
            Err(RunnerError::ConcurrentChange)
        );
        assert_eq!(fs::read(&path).unwrap(), b"context-relay\n");
        assert_eq!(fs::read(&stream).unwrap(), b"attacker\n");
        assert_eq!(fs::read(&backup).unwrap(), b"before\n");

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn internal_recovery_namespace_cannot_be_an_approved_target() {
        let root = test_root("recovery-namespace");
        let path = root.join("settings.json");
        let backup = root.join(backup_name(path.file_name().unwrap()));
        let temporary = root.join(temp_name(path.file_name().unwrap(), &TEST_NONCE));
        let generated = temporary.file_name().unwrap().to_string_lossy();
        assert!(internal_temp_name(&generated));
        assert!(internal_temp_name(&generated.to_ascii_uppercase()));
        let uppercase_temporary = root.join(
            temporary
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_ascii_uppercase(),
        );
        fs::write(&backup, b"ordinary target\n").unwrap();
        fs::write(&temporary, b"ordinary target\n").unwrap();
        fs::write(&uppercase_temporary, b"ordinary target\n").unwrap();

        assert_eq!(
            OsNativeFileSystem::new().snapshot(&backup),
            Err(RunnerError::InvalidPath)
        );
        assert_eq!(
            OsNativeFileSystem::new().snapshot(&temporary),
            Err(RunnerError::InvalidPath)
        );
        assert_eq!(
            OsNativeFileSystem::new().snapshot(&uppercase_temporary),
            Err(RunnerError::InvalidPath)
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn nonce_bound_partial_temp_survives_abort_then_recovery_removes_only_it() {
        if let Some(path) = std::env::var_os(TEMP_ABORT_PATH_ENV) {
            let path = PathBuf::from(path);
            let signal =
                PathBuf::from(std::env::var_os(TEMP_ABORT_SIGNAL_ENV).expect("child signal path"));
            let before = snapshot(&path).unwrap();
            let desired = NativeState::regular_file(
                b"context-relay\n".to_vec(),
                before.metadata().unwrap().clone(),
            );
            let applied_fingerprint = desired.fingerprint();
            *POST_TEMP_CREATE_TEST_HOOK.lock().unwrap() = Some(Box::new(move |file| {
                use std::io::Write as _;
                file.write_all(b"partial").unwrap();
                file.sync_all().unwrap();
                let mut marker = fs::File::create(signal).unwrap();
                marker.write_all(&applied_fingerprint).unwrap();
                marker.sync_all().unwrap();
                std::process::abort();
            }));
            let _ = cas(&path, before.fingerprint(), &desired);
            panic!("child CAS returned instead of aborting");
        }

        let _serial = PRE_RENAME_TEST_SERIAL.lock().unwrap();
        let root = test_root("partial-temp-abort");
        let path = root.join("settings.json");
        let signal = root.join("abort.signal");
        fs::write(&path, b"before\n").unwrap();
        let before = snapshot(&path).unwrap();
        let temporary = root.join(temp_name(path.file_name().unwrap(), &TEST_NONCE));
        let output = Command::new(std::env::current_exe().unwrap())
            .arg("nonce_bound_partial_temp_survives_abort_then_recovery_removes_only_it")
            .arg("--nocapture")
            .env(TEMP_ABORT_PATH_ENV, &path)
            .env(TEMP_ABORT_SIGNAL_ENV, &signal)
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "child unexpectedly succeeded: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert_eq!(fs::read(&temporary).unwrap(), b"partial");
        assert_eq!(snapshot(&path).unwrap().fingerprint(), before.fingerprint());
        let applied_fingerprint: [u8; 32] = fs::read(&signal).unwrap().try_into().unwrap();
        let other_nonce = [0x4d; 16];
        let other_temporary = root.join(temp_name(path.file_name().unwrap(), &other_nonce));
        fs::write(&other_temporary, b"other transaction").unwrap();

        recover(&path, before.fingerprint(), &applied_fingerprint).unwrap();
        assert!(!temporary.exists());
        assert_eq!(fs::read(&other_temporary).unwrap(), b"other transaction");
        assert!(signal.exists());
        assert_eq!(snapshot(&path).unwrap().fingerprint(), before.fingerprint());
        recover(&path, before.fingerprint(), &applied_fingerprint).unwrap();

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_refuses_hardlinked_nonce_bound_temp_without_deleting_it() {
        let root = test_root("hardlinked-recovery-temp");
        let path = root.join("settings.json");
        fs::write(&path, b"before\n").unwrap();
        let before = snapshot(&path).unwrap();
        let temporary = root.join(temp_name(path.file_name().unwrap(), &TEST_NONCE));
        let alias = root.join("attacker-alias.tmp");
        fs::write(&temporary, b"partial").unwrap();
        fs::hard_link(&temporary, &alias).unwrap();

        assert_eq!(
            recover(&path, before.fingerprint(), &[0xa5; 32]),
            Err(RunnerError::ConcurrentChange)
        );
        assert_eq!(fs::read(&temporary).unwrap(), b"partial");
        assert_eq!(fs::read(&alias).unwrap(), b"partial");
        assert_eq!(snapshot(&path).unwrap().fingerprint(), before.fingerprint());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_preserves_nonregular_or_reparse_nonce_bound_temp() {
        let root = test_root("unsafe-recovery-temp");
        let path = root.join("settings.json");
        fs::write(&path, b"before\n").unwrap();
        let before = snapshot(&path).unwrap();
        let temporary = root.join(temp_name(path.file_name().unwrap(), &TEST_NONCE));
        fs::create_dir(&temporary).unwrap();

        assert_eq!(
            recover(&path, before.fingerprint(), &[0xa5; 32]),
            Err(RunnerError::ConcurrentChange)
        );
        assert!(temporary.is_dir());
        fs::remove_dir(&temporary).unwrap();

        let reparse_target = root.join("reparse-target.tmp");
        fs::write(&reparse_target, b"attacker").unwrap();
        match std::os::windows::fs::symlink_file(&reparse_target, &temporary) {
            Ok(()) => {
                assert_eq!(
                    recover(&path, before.fingerprint(), &[0xa5; 32]),
                    Err(RunnerError::ConcurrentChange)
                );
                assert!(
                    fs::symlink_metadata(&temporary)
                        .unwrap()
                        .file_type()
                        .is_symlink()
                );
                assert_eq!(fs::read(&reparse_target).unwrap(), b"attacker");
            }
            Err(error) if error.raw_os_error() == Some(1314) => {}
            Err(error) => panic!("create recovery-temp symlink: {error}"),
        }

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn mutation_handles_are_flush_capable() {
        let root = test_root("flush-capable-handles");
        let path = root.join("settings.json");
        fs::write(&path, b"before\n").unwrap();
        let held = HeldPath::new(&path).unwrap();
        let file = match held.open_target(GENERIC_READ | GENERIC_WRITE | DELETE, FILE_SHARE_READ) {
            Ok(file) => file,
            Err(_) => panic!("open mutation target"),
        };

        assert_ne!(
            unsafe { FlushFileBuffers(file.as_raw_handle() as HANDLE) },
            0,
            "retained backup handle must flush"
        );
        let parent = held.open_flushable_parent().unwrap();
        assert_ne!(
            unsafe { FlushFileBuffers(parent.as_raw_handle() as HANDLE) },
            0,
            "parent handle must flush"
        );

        drop(file);
        drop(parent);
        drop(held);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn snapshot_final_topology_recheck_detects_injected_hardlink() {
        let _serial = PRE_RENAME_TEST_SERIAL.lock().unwrap();
        let root = test_root("snapshot-final-hardlink");
        let path = root.join("settings.json");
        let alias = root.join("attacker-alias.json");
        fs::write(&path, b"before\n").unwrap();
        *CAPTURE_FINAL_TEST_HOOK.lock().unwrap() = Some(Box::new({
            let path = path.clone();
            let alias = alias.clone();
            move || fs::hard_link(path, alias).unwrap()
        }));

        assert!(matches!(
            snapshot(&path),
            Err(RunnerError::ConcurrentChange | RunnerError::UnsafeTopology)
        ));
        assert_eq!(fs::read(&alias).unwrap(), b"before\n");

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn tree_capture_final_topology_recheck_detects_injected_hardlink() {
        let _serial = PRE_RENAME_TEST_SERIAL.lock().unwrap();
        let root = test_root("tree-final-hardlink");
        let path = root.join("payload.bin");
        let alias = root.join("attacker-alias.bin");
        fs::write(&path, b"payload\n").unwrap();
        *CAPTURE_FINAL_TEST_HOOK.lock().unwrap() = Some(Box::new({
            let path = path.clone();
            let alias = alias.clone();
            move || fs::hard_link(path, alias).unwrap()
        }));

        assert!(matches!(
            capture_node(&path, true),
            Err(RunnerError::ConcurrentChange)
        ));
        assert_eq!(fs::read(&alias).unwrap(), b"payload\n");

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_restores_crash_gap_and_is_idempotent() {
        let root = test_root("crash-gap-recovery");
        let path = root.join("settings.json");
        fs::write(&path, b"before\n").unwrap();
        let before = snapshot(&path).unwrap();
        let desired = NativeState::regular_file(
            b"context-relay\n".to_vec(),
            before.metadata().unwrap().clone(),
        );
        let backup = simulate_crash_gap(&path, &before);
        assert!(!path.exists());
        assert!(backup.exists());

        recover(&path, before.fingerprint(), &desired.fingerprint()).unwrap();
        assert_eq!(snapshot(&path).unwrap().fingerprint(), before.fingerprint());
        assert!(!backup.exists());
        recover(&path, before.fingerprint(), &desired.fingerprint()).unwrap();

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_reverts_applied_target_and_is_idempotent() {
        let _serial = PRE_RENAME_TEST_SERIAL.lock().unwrap();
        let root = test_root("applied-recovery");
        let path = root.join("settings.json");
        fs::write(&path, b"before\n").unwrap();
        let before = snapshot(&path).unwrap();
        let desired = NativeState::regular_file(
            b"context-relay\n".to_vec(),
            before.metadata().unwrap().clone(),
        );
        let backup = simulate_crash_gap(&path, &before);
        let absent = snapshot(&path).unwrap();
        cas(&path, absent.fingerprint(), &desired).unwrap();
        let applied = snapshot(&path).unwrap();
        assert_eq!(applied.fingerprint(), &desired.fingerprint());

        recover(&path, before.fingerprint(), applied.fingerprint()).unwrap();
        assert_eq!(snapshot(&path).unwrap().fingerprint(), before.fingerprint());
        assert!(!backup.exists());
        recover(&path, before.fingerprint(), applied.fingerprint()).unwrap();

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_removes_stale_backup_when_target_is_already_before() {
        let _serial = PRE_RENAME_TEST_SERIAL.lock().unwrap();
        let root = test_root("stale-backup-recovery");
        let path = root.join("settings.json");
        fs::write(&path, b"before\n").unwrap();
        let before = snapshot(&path).unwrap();
        let backup = simulate_crash_gap(&path, &before);
        let absent = snapshot(&path).unwrap();
        cas(&path, absent.fingerprint(), before.state()).unwrap();
        assert_eq!(snapshot(&path).unwrap().fingerprint(), before.fingerprint());

        recover(&path, before.fingerprint(), &[0x5a; 32]).unwrap();
        assert_eq!(snapshot(&path).unwrap().fingerprint(), before.fingerprint());
        assert!(!backup.exists());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn attributed_recovery_preserves_an_identical_replacement_target() {
        let _serial = PRE_RENAME_TEST_SERIAL.lock().unwrap();
        let root = test_root("attributed-recovery-identical-replacement");
        let path = root.join("settings.json");
        fs::write(&path, b"before\n").unwrap();
        let before = snapshot(&path).unwrap();
        let desired = NativeState::regular_file(
            b"context-relay\n".to_vec(),
            before.metadata().unwrap().clone(),
        );
        let backup = simulate_crash_gap(&path, &before);
        let absent = snapshot(&path).unwrap();
        let first = cas(&path, absent.fingerprint(), &desired).unwrap();
        let installed_token = first.installed_token().unwrap().clone();
        fs::remove_file(&path).unwrap();
        let absent = snapshot(&path).unwrap();
        let concurrent = cas(&path, absent.fingerprint(), &desired).unwrap();
        let concurrent_token = concurrent.snapshot().object_token().unwrap().clone();
        assert_ne!(concurrent_token, installed_token);

        assert_eq!(
            OsNativeFileSystem::new().recover_interrupted_replace_observed_with_provenance(
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
            snapshot(&path).unwrap().object_token(),
            Some(&concurrent_token)
        );
        assert!(backup.exists());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn attributed_recovery_preserves_a_concurrently_deleted_target() {
        let _serial = PRE_RENAME_TEST_SERIAL.lock().unwrap();
        let root = test_root("attributed-recovery-concurrent-delete");
        let path = root.join("settings.json");
        fs::write(&path, b"before\n").unwrap();
        let before = snapshot(&path).unwrap();
        let desired = NativeState::regular_file(
            b"context-relay\n".to_vec(),
            before.metadata().unwrap().clone(),
        );
        let backup = simulate_crash_gap(&path, &before);
        let absent = snapshot(&path).unwrap();
        let installed = cas(&path, absent.fingerprint(), &desired).unwrap();
        let installed_token = installed.installed_token().unwrap().clone();
        fs::remove_file(&path).unwrap();

        assert_eq!(
            OsNativeFileSystem::new().recover_interrupted_replace_observed_with_provenance(
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
        assert!(backup.exists());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_final_recheck_preserves_changed_target_and_backup() {
        let _serial = PRE_RENAME_TEST_SERIAL.lock().unwrap();
        let root = test_root("recovery-target-ads-race");
        let path = root.join("settings.json");
        fs::write(&path, b"before\n").unwrap();
        let before = snapshot(&path).unwrap();
        let backup = simulate_crash_gap(&path, &before);
        let absent = snapshot(&path).unwrap();
        cas(&path, absent.fingerprint(), before.state()).unwrap();
        let mut stream_name = path.as_os_str().to_os_string();
        stream_name.push(":attacker");
        let stream = PathBuf::from(stream_name);
        *RECOVERY_PRE_DESTRUCTIVE_TEST_HOOK.lock().unwrap() = Some(Box::new({
            let stream = stream.clone();
            move || fs::write(stream, b"attacker\n").unwrap()
        }));

        assert_eq!(
            recover(&path, before.fingerprint(), &[0x5a; 32]),
            Err(RunnerError::ConcurrentChange)
        );
        assert_eq!(fs::read(&path).unwrap(), b"before\n");
        assert_eq!(fs::read(&stream).unwrap(), b"attacker\n");
        assert_eq!(fs::read(&backup).unwrap(), b"before\n");

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_final_recheck_preserves_changed_backup_and_applied_target() {
        let _serial = PRE_RENAME_TEST_SERIAL.lock().unwrap();
        let root = test_root("recovery-backup-ads-race");
        let path = root.join("settings.json");
        fs::write(&path, b"before\n").unwrap();
        let before = snapshot(&path).unwrap();
        let desired = NativeState::regular_file(
            b"context-relay\n".to_vec(),
            before.metadata().unwrap().clone(),
        );
        let backup = simulate_crash_gap(&path, &before);
        let absent = snapshot(&path).unwrap();
        cas(&path, absent.fingerprint(), &desired).unwrap();
        let applied = snapshot(&path).unwrap();
        let mut stream_name = backup.as_os_str().to_os_string();
        stream_name.push(":attacker");
        let stream = PathBuf::from(stream_name);
        *RECOVERY_PRE_DESTRUCTIVE_TEST_HOOK.lock().unwrap() = Some(Box::new({
            let stream = stream.clone();
            move || fs::write(stream, b"attacker\n").unwrap()
        }));

        assert_eq!(
            recover(&path, before.fingerprint(), applied.fingerprint()),
            Err(RunnerError::ConcurrentChange)
        );
        assert_eq!(fs::read(&path).unwrap(), b"context-relay\n");
        assert_eq!(fs::read(&backup).unwrap(), b"before\n");
        assert_eq!(fs::read(&stream).unwrap(), b"attacker\n");

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_preserves_wrong_backup_and_target() {
        let root = test_root("wrong-backup-recovery");
        let path = root.join("settings.json");
        fs::write(&path, b"before\n").unwrap();
        let before = snapshot(&path).unwrap();
        let held = HeldPath::new(&path).unwrap();
        let backup = root.join(backup_name(&held.name));
        fs::write(&backup, b"wrong\n").unwrap();

        assert_eq!(
            recover(&path, before.fingerprint(), &[0xa5; 32]),
            Err(RunnerError::ConcurrentChange)
        );
        assert_eq!(fs::read(&path).unwrap(), b"before\n");
        assert_eq!(fs::read(&backup).unwrap(), b"wrong\n");

        drop(held);
        fs::remove_dir_all(root).unwrap();
    }
}

fn set_security_descriptor(file: &File, descriptor: &[u8]) -> Result<(), RunnerError> {
    if descriptor.is_empty() {
        return Err(RunnerError::Io);
    }
    let information =
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    if unsafe {
        SetKernelObjectSecurity(
            file.as_raw_handle() as HANDLE,
            information,
            descriptor.as_ptr().cast_mut().cast(),
        )
    } == 0
    {
        return Err(RunnerError::Io);
    }
    Ok(())
}

fn flush_handle(file: &File) -> Result<(), RunnerError> {
    if unsafe { FlushFileBuffers(file.as_raw_handle() as HANDLE) } == 0 {
        return Err(RunnerError::Io);
    }
    Ok(())
}

fn stream_object_name(file_name: &OsStr, stream_name: &str) -> Result<OsString, RunnerError> {
    let _inner = stream_name
        .strip_prefix(':')
        .and_then(|name| name.strip_suffix(":$DATA"))
        .filter(|name| {
            !name.is_empty()
                && !name
                    .encode_utf16()
                    .any(|unit| matches!(unit, 0 | 47 | 58 | 92))
        })
        .ok_or(RunnerError::InvalidNativeState)?;
    let mut value = file_name.encode_wide().collect::<Vec<_>>();
    value.extend(stream_name.encode_utf16());
    Ok(OsString::from_wide(&value))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;

    #[test]
    fn held_path_blocks_controlled_ancestor_rename_until_released() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "context-relay-native-fs-guard-{}-{suffix}",
            std::process::id()
        ));
        let nested = root.join("approved").join("nested");
        fs::create_dir_all(&nested).unwrap();
        let path = nested.join("settings.json");
        fs::write(&path, b"before\n").unwrap();

        {
            let held = HeldPath::new(&path).unwrap();
            assert!(fs::rename(&root, root.with_extension("attacker")).is_err());
            assert_eq!(
                snapshot_held(&held).unwrap().bytes(),
                Some(b"before\n".as_slice())
            );
        }
        {
            let absent_path = nested.join("absent.json");
            let held = HeldPath::new(&absent_path).unwrap();
            assert!(fs::rename(&root, root.with_extension("attacker")).is_err());
            assert!(matches!(
                snapshot_held(&held).unwrap().state(),
                NativeState::Absent { .. }
            ));
        }
        let moved = root.with_extension("moved");
        fs::rename(&root, &moved).unwrap();
        fs::remove_dir_all(moved).unwrap();
    }
}
