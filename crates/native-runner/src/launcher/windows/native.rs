use std::{
    ffi::{OsStr, OsString, c_void},
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    mem::size_of,
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle},
    },
    path::{Path, PathBuf},
    ptr::{null, null_mut},
    thread,
};

use sha2::{Digest, Sha256};
use windows_sys::Win32::{
    Foundation::{
        CompareObjectHandles, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_HANDLE_EOF,
        ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_HANDLE, ERROR_NO_MORE_FILES, ERROR_SUCCESS,
        GetHandleInformation, GetLastError, HANDLE, HANDLE_FLAG_INHERIT, HLOCAL,
        INVALID_HANDLE_VALUE, LocalFree, NTSTATUS, OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE,
        RtlNtStatusToDosError, STATUS_REPARSE_POINT_ENCOUNTERED, STATUS_STOPPED_ON_SYMLINK,
        SetHandleInformation, UNICODE_STRING, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Security::{
        ACE_HEADER, ACE_INHERITED_OBJECT_TYPE_PRESENT, ACE_OBJECT_TYPE_PRESENT, ACL,
        ACL_REVISION_DS, ACL_SIZE_INFORMATION, AclSizeInformation, AddAce,
        Authorization::{
            BuildTrusteeWithSidW, DENY_ACCESS, EXPLICIT_ACCESS_W, GetSecurityInfo, SE_FILE_OBJECT,
            SET_ACCESS, SetEntriesInAclW, SetSecurityInfo,
        },
        DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation, GetLengthSid,
        GetTokenInformation, InitializeAcl, IsValidSid, NO_INHERITANCE,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
        SECURITY_CAPABILITIES, SUB_CONTAINERS_AND_OBJECTS_INHERIT, TOKEN_APPCONTAINER_INFORMATION,
        TOKEN_QUERY, TokenAppContainerSid, TokenCapabilities, TokenIsAppContainer,
    },
    Storage::FileSystem::{
        CreateFileW, DELETE, FILE_APPEND_DATA, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_ATTRIBUTE_TAG_INFO, FILE_DELETE_CHILD, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ,
        FILE_ID_BOTH_DIR_INFO, FILE_ID_INFO, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO,
        FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA, FileAttributeTagInfo,
        FileIdBothDirectoryInfo, FileIdBothDirectoryRestartInfo, FileIdInfo, FileStandardInfo,
        GetFileInformationByHandleEx, OPEN_EXISTING, SYNCHRONIZE, WRITE_DAC, WRITE_OWNER,
    },
    System::{
        Console::{GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE},
        JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob,
            JOB_OBJECT_LIMIT_BREAKAWAY_OK, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
            TerminateJobObject,
        },
        Memory::{GetProcessHeap, HEAP_ZERO_MEMORY, HeapAlloc, HeapFree},
        Pipes::{CreatePipe, PeekNamedPipe},
        Threading::{
            CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
            DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess,
            GetExitCodeProcess, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
            OpenProcessToken, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION, ResumeThread,
            STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute,
            WaitForSingleObject,
        },
    },
};

use crate::environment::windows_directory;

use super::profile::{OwnedSid, derive_owned_sid, last_error};
use super::{
    LaunchBackend, LaunchError, LaunchSequence, ProfileIdentity, Running, SecurityAttributePlan,
    Suspended, Win32ProfileApi, Win32ProfileLayout, drain_bounded,
};

const CLOSURE_RUNTIME_DENIED_ACCESS: u32 = FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_EA
    | FILE_WRITE_ATTRIBUTES
    | FILE_DELETE_CHILD
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER;
const CLOSURE_RUNTIME_ALLOWED_ACCESS: u32 = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
const MAX_CLOSURE_SEAL_ENTRIES: usize = 512;
const MAX_CLOSURE_SEAL_DEPTH: usize = 64;
const FILE_OPEN: u32 = 1;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;
const ACCESS_ALLOWED_COMPOUND_ACE_TYPE: u8 = 4;
const ACCESS_ALLOWED_OBJECT_ACE_TYPE: u8 = 5;
const ACCESS_DENIED_OBJECT_ACE_TYPE: u8 = 6;
const ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u8 = 9;
const ACCESS_DENIED_CALLBACK_ACE_TYPE: u8 = 10;
const ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE: u8 = 11;
const ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE: u8 = 12;

pub fn seal_protocol_handles_before_sidecar() -> Result<(), LaunchError> {
    let handles = unsafe {
        [
            GetStdHandle(STD_INPUT_HANDLE),
            GetStdHandle(STD_OUTPUT_HANDLE),
            GetStdHandle(STD_ERROR_HANDLE),
        ]
    };
    if handles
        .iter()
        .any(|handle| handle.is_null() || *handle == INVALID_HANDLE_VALUE)
        || handles[0] == handles[1]
        || handles[0] == handles[2]
        || handles[1] == handles[2]
    {
        return Err(LaunchError::InvalidSecurityPlan);
    }
    for handle in handles {
        clear_inheritance(handle)?;
        require_noninherited(handle)?;
    }
    Ok(())
}

const MAX_HELPER_BYTES: i64 = 512 * 1024 * 1024;
const MAX_TOKEN_INFORMATION_BYTES: u32 = 1024 * 1024;
const MAX_STDOUT_BYTES: usize = crate::MAX_WIRE_PAYLOAD_BYTES + 12;
const MAX_STDERR_BYTES: usize = 4 * 1024 * 1024;
const PROCESS_TIMEOUT_MS: u32 = 30_000;
const DROP_WAIT_MS: u32 = 5_000;
const FORCED_EXIT_CODE: u32 = 0x4352_0009;
const RESUME_FAILED: u32 = u32::MAX;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Win32LaunchAudit {
    created_suspended: bool,
    job_kill_on_close_verified: bool,
    job_membership_verified: bool,
    token_is_appcontainer: bool,
    token_sid_verified: bool,
    token_capability_count: u32,
    inherited_handle_count: u32,
    resumed_exactly_once: bool,
}

impl Win32LaunchAudit {
    pub const fn created_suspended(&self) -> bool {
        self.created_suspended
    }

    pub const fn job_kill_on_close_verified(&self) -> bool {
        self.job_kill_on_close_verified
    }

    pub const fn job_membership_verified(&self) -> bool {
        self.job_membership_verified
    }

    pub const fn token_is_appcontainer(&self) -> bool {
        self.token_is_appcontainer
    }

    pub const fn token_sid_verified(&self) -> bool {
        self.token_sid_verified
    }

    pub const fn token_capability_count(&self) -> u32 {
        self.token_capability_count
    }

    pub const fn inherited_handle_count(&self) -> u32 {
        self.inherited_handle_count
    }

    pub const fn resumed_exactly_once(&self) -> bool {
        self.resumed_exactly_once
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Win32SandboxOutput {
    exit_code: u32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl Win32SandboxOutput {
    pub const fn exit_code(&self) -> u32 {
        self.exit_code
    }

    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }
}

pub struct Win32LaunchBackend {
    identity: ProfileIdentity,
    layout: Win32ProfileLayout,
    sid: OwnedSid,
    helper: LockedHelper,
    pipes: ProtocolPipes,
    job: OwnedHandle,
    process: Option<OwnedHandle>,
    thread: Option<OwnedHandle>,
    job_assigned: bool,
    completed: bool,
    audit: Win32LaunchAudit,
}

impl Win32LaunchBackend {
    pub fn prepare(
        identity: &ProfileIdentity,
        layout: Win32ProfileLayout,
        expected_digest: [u8; 32],
    ) -> Result<Self, LaunchError> {
        let profile_root = Win32ProfileApi::new().profile_folder(identity)?;
        let expected_root =
            std::fs::canonicalize(profile_root).map_err(|_| LaunchError::InvalidProfileIdentity)?;
        let actual_root = std::fs::canonicalize(layout.root())
            .map_err(|_| LaunchError::InvalidProfileIdentity)?;
        if expected_root != actual_root {
            return Err(LaunchError::InvalidProfileIdentity);
        }

        let sid = derive_owned_sid(identity)?;
        seal_closure_runtime(&layout, &sid)?;
        prepare_effective_local_app_data(identity, &layout)?;
        let helper = LockedHelper::open(layout.helper_path(), expected_digest)?;
        let pipes = ProtocolPipes::new()?;
        let job = create_verified_kill_job()?;
        Ok(Self {
            identity: identity.clone(),
            layout,
            sid,
            helper,
            pipes,
            job,
            process: None,
            thread: None,
            job_assigned: false,
            completed: false,
            audit: Win32LaunchAudit {
                job_kill_on_close_verified: true,
                ..Win32LaunchAudit::default()
            },
        })
    }

    pub fn helper_path(&self) -> &Path {
        self.helper.path()
    }

    fn process_handle(&self) -> Result<HANDLE, LaunchError> {
        self.process
            .as_ref()
            .map(raw_handle)
            .ok_or(LaunchError::CreateProcessFailed)
    }

    fn inherited_exact_handle(&self, parent_handle: usize) -> Result<bool, LaunchError> {
        let process = self.process_handle()?;
        let mut duplicate = null_mut();
        if unsafe {
            DuplicateHandle(
                process,
                parent_handle as HANDLE,
                GetCurrentProcess(),
                &mut duplicate,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            return if unsafe { windows_sys::Win32::Foundation::GetLastError() }
                == ERROR_INVALID_HANDLE
            {
                Ok(false)
            } else {
                Err(last_error())
            };
        }
        let duplicate = owned_handle(duplicate)?;
        Ok(unsafe { CompareObjectHandles(parent_handle as HANDLE, raw_handle(&duplicate)) } != 0)
    }

    fn exchange(&mut self, input: &[u8]) -> Result<Win32SandboxOutput, LaunchError> {
        let stdout = self.pipes.take_stdout()?;
        let stderr = self.pipes.take_stderr()?;
        let stdout_reader = thread::spawn(move || drain_bounded(stdout, MAX_STDOUT_BYTES));
        let stderr_reader = thread::spawn(move || drain_bounded(stderr, MAX_STDERR_BYTES));

        let write_result = (|| {
            let mut stdin = self.pipes.take_stdin()?;
            stdin.write_all(input).map_err(|_| LaunchError::PipeIo)?;
            stdin.flush().map_err(|_| LaunchError::PipeIo)
        })();
        if write_result.is_err() {
            self.force_terminate();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(LaunchError::PipeIo);
        }

        let process = self.process_handle()?;
        let wait = unsafe { WaitForSingleObject(process, PROCESS_TIMEOUT_MS) };
        if wait == WAIT_TIMEOUT {
            self.force_terminate();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(LaunchError::ProcessTimedOut);
        }
        if wait != WAIT_OBJECT_0 {
            self.force_terminate();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(last_error());
        }

        let mut exit_code = 0;
        if unsafe { GetExitCodeProcess(process, &mut exit_code) } == 0 {
            self.force_terminate();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(last_error());
        }

        if unsafe { TerminateJobObject(raw_handle(&self.job), FORCED_EXIT_CODE) } == 0 {
            self.force_terminate();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(last_error());
        }
        self.completed = true;

        let stdout = stdout_reader.join().map_err(|_| LaunchError::PipeIo)??;
        let stderr = stderr_reader.join().map_err(|_| LaunchError::PipeIo)??;
        Ok(Win32SandboxOutput {
            exit_code,
            stdout,
            stderr,
        })
    }

    fn force_terminate(&self) {
        let Some(process) = self.process.as_ref() else {
            return;
        };
        unsafe {
            if self.job_assigned {
                TerminateJobObject(raw_handle(&self.job), FORCED_EXIT_CODE);
            } else {
                TerminateProcess(raw_handle(process), FORCED_EXIT_CODE);
            }
            WaitForSingleObject(raw_handle(process), DROP_WAIT_MS);
        }
    }
}

fn seal_closure_runtime(layout: &Win32ProfileLayout, sid: &OwnedSid) -> Result<(), LaunchError> {
    let root = open_closure_root_for_seal(layout.closure_runtime())?;
    let retained = closure_node(layout.closure_runtime_lock()?)?;
    let opened = closure_node(&root)?;
    if retained != opened || !safe_closure_node(&opened, true, opened.volume) {
        return Err(LaunchError::InvalidSecurityPlan);
    }
    let mut entry_count = 0;
    seal_closure_object(&root, sid, 0, opened.volume, &mut entry_count)
}

fn seal_closure_object(
    object: &File,
    sid: &OwnedSid,
    depth: usize,
    volume: u64,
    entry_count: &mut usize,
) -> Result<(), LaunchError> {
    if depth > MAX_CLOSURE_SEAL_DEPTH {
        return Err(LaunchError::InvalidSecurityPlan);
    }
    let before = closure_node(object)?;
    if !safe_closure_node(&before, before.directory, volume) {
        return Err(LaunchError::InvalidSecurityPlan);
    }
    seal_closure_acl(object, sid, before.directory)?;

    if before.directory {
        let names = closure_directory_names(
            object,
            MAX_CLOSURE_SEAL_ENTRIES
                .checked_sub(*entry_count)
                .ok_or(LaunchError::InvalidSecurityPlan)?,
        )?;
        for name in &names {
            *entry_count = entry_count
                .checked_add(1)
                .ok_or(LaunchError::InvalidSecurityPlan)?;
            if *entry_count > MAX_CLOSURE_SEAL_ENTRIES {
                return Err(LaunchError::InvalidSecurityPlan);
            }
            let child = nt_open_closure_child(object, name)?;
            seal_closure_object(&child, sid, depth + 1, volume, entry_count)?;
        }
        if closure_directory_names(object, names.len())? != names {
            return Err(LaunchError::InvalidSecurityPlan);
        }
    }

    let after = closure_node(object)?;
    if before != after {
        return Err(LaunchError::InvalidSecurityPlan);
    }
    Ok(())
}

fn seal_closure_acl(object: &File, sid: &OwnedSid, directory: bool) -> Result<(), LaunchError> {
    let mut old_acl: *mut ACL = null_mut();
    let mut security_descriptor: PSECURITY_DESCRIPTOR = null_mut();
    let result = unsafe {
        GetSecurityInfo(
            raw_file_handle(object),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut old_acl,
            null_mut(),
            &mut security_descriptor,
        )
    };
    if result != ERROR_SUCCESS {
        return Err(LaunchError::Win32(result));
    }
    let _security_descriptor = LocalSecurityAllocation::new(security_descriptor)?;
    if old_acl.is_null() {
        return Err(LaunchError::InvalidSecurityPlan);
    }
    let filtered_acl = closure_acl_without_sid(old_acl, sid.as_ptr())?;

    let inheritance = if directory {
        SUB_CONTAINERS_AND_OBJECTS_INHERIT
    } else {
        NO_INHERITANCE
    };
    let mut read_entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: CLOSURE_RUNTIME_ALLOWED_ACCESS,
        grfAccessMode: SET_ACCESS,
        grfInheritance: inheritance,
        ..EXPLICIT_ACCESS_W::default()
    };
    unsafe { BuildTrusteeWithSidW(&mut read_entry.Trustee, sid.as_ptr()) };
    let mut restricted_acl: *mut ACL = null_mut();
    let result =
        unsafe { SetEntriesInAclW(1, &read_entry, filtered_acl.as_ptr(), &mut restricted_acl) };
    if result != ERROR_SUCCESS {
        return Err(LaunchError::Win32(result));
    }
    let _restricted_acl = LocalSecurityAllocation::new(restricted_acl.cast())?;

    let mut deny_entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: CLOSURE_RUNTIME_DENIED_ACCESS,
        grfAccessMode: DENY_ACCESS,
        grfInheritance: inheritance,
        ..EXPLICIT_ACCESS_W::default()
    };
    unsafe { BuildTrusteeWithSidW(&mut deny_entry.Trustee, sid.as_ptr()) };
    let mut sealed_acl: *mut ACL = null_mut();
    let result = unsafe { SetEntriesInAclW(1, &deny_entry, restricted_acl, &mut sealed_acl) };
    if result != ERROR_SUCCESS {
        return Err(LaunchError::Win32(result));
    }
    let _sealed_acl = LocalSecurityAllocation::new(sealed_acl.cast())?;
    let result = unsafe {
        SetSecurityInfo(
            raw_file_handle(object),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            sealed_acl,
            null_mut(),
        )
    };
    if result != ERROR_SUCCESS {
        return Err(LaunchError::Win32(result));
    }
    Ok(())
}

struct FilteredAcl {
    storage: Vec<u64>,
}

impl FilteredAcl {
    fn as_ptr(&self) -> *const ACL {
        self.storage.as_ptr().cast()
    }
}

fn closure_acl_without_sid(old_acl: *const ACL, sid: PSID) -> Result<FilteredAcl, LaunchError> {
    let mut information = ACL_SIZE_INFORMATION::default();
    if unsafe {
        GetAclInformation(
            old_acl,
            (&mut information as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(last_error());
    }
    let capacity = usize::try_from(information.AclBytesInUse)
        .map_err(|_| LaunchError::InvalidSecurityPlan)?
        .max(size_of::<ACL>());
    let mut storage = vec![0_u64; capacity.div_ceil(size_of::<u64>())];
    let filtered: *mut ACL = storage.as_mut_ptr().cast();
    let storage_bytes = storage
        .len()
        .checked_mul(size_of::<u64>())
        .and_then(|size| u32::try_from(size).ok())
        .ok_or(LaunchError::InvalidSecurityPlan)?;
    if unsafe { InitializeAcl(filtered, storage_bytes, ACL_REVISION_DS) } == 0 {
        return Err(last_error());
    }

    for index in 0..information.AceCount {
        let mut ace: *mut c_void = null_mut();
        if unsafe { GetAce(old_acl, index, &mut ace) } == 0 || ace.is_null() {
            return Err(LaunchError::InvalidSecurityPlan);
        }
        let header = unsafe { std::ptr::read_unaligned(ace.cast::<ACE_HEADER>()) };
        let ace_size = usize::from(header.AceSize);
        if ace_size < size_of::<ACE_HEADER>() {
            return Err(LaunchError::InvalidSecurityPlan);
        }
        let remove = match closure_access_ace_sid(ace.cast(), &header)? {
            Some(candidate) => unsafe { EqualSid(candidate, sid) != 0 },
            None => false,
        };
        if !remove
            && unsafe {
                AddAce(
                    filtered,
                    ACL_REVISION_DS,
                    u32::MAX,
                    ace,
                    u32::from(header.AceSize),
                )
            } == 0
        {
            return Err(last_error());
        }
    }
    Ok(FilteredAcl { storage })
}

fn closure_access_ace_sid(
    ace: *const u8,
    header: &ACE_HEADER,
) -> Result<Option<PSID>, LaunchError> {
    let ace_size = usize::from(header.AceSize);
    let sid_offset = match header.AceType {
        ACCESS_ALLOWED_ACE_TYPE
        | ACCESS_DENIED_ACE_TYPE
        | ACCESS_ALLOWED_CALLBACK_ACE_TYPE
        | ACCESS_DENIED_CALLBACK_ACE_TYPE => size_of::<ACE_HEADER>() + size_of::<u32>(),
        ACCESS_ALLOWED_OBJECT_ACE_TYPE
        | ACCESS_DENIED_OBJECT_ACE_TYPE
        | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
        | ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE => {
            let flags_offset = size_of::<ACE_HEADER>() + size_of::<u32>();
            if ace_size < flags_offset + size_of::<u32>() {
                return Err(LaunchError::InvalidSecurityPlan);
            }
            let flags = unsafe { std::ptr::read_unaligned(ace.add(flags_offset).cast::<u32>()) };
            if flags & !(ACE_OBJECT_TYPE_PRESENT | ACE_INHERITED_OBJECT_TYPE_PRESENT) != 0 {
                return Err(LaunchError::InvalidSecurityPlan);
            }
            flags_offset
                + size_of::<u32>()
                + usize::from(flags & ACE_OBJECT_TYPE_PRESENT != 0) * 16
                + usize::from(flags & ACE_INHERITED_OBJECT_TYPE_PRESENT != 0) * 16
        }
        ACCESS_ALLOWED_COMPOUND_ACE_TYPE => {
            return Err(LaunchError::InvalidSecurityPlan);
        }
        2 | 3 | 7 | 8 | 13..=21 => return Ok(None),
        _ => return Err(LaunchError::InvalidSecurityPlan),
    };
    const SID_HEADER_BYTES: usize = 8;
    if sid_offset
        .checked_add(SID_HEADER_BYTES)
        .is_none_or(|end| end > ace_size)
    {
        return Err(LaunchError::InvalidSecurityPlan);
    }
    let candidate: PSID = unsafe { ace.add(sid_offset).cast_mut().cast() };
    if unsafe { IsValidSid(candidate) } == 0 {
        return Err(LaunchError::InvalidSecurityPlan);
    }
    let sid_length = usize::try_from(unsafe { GetLengthSid(candidate) })
        .map_err(|_| LaunchError::InvalidSecurityPlan)?;
    if sid_length == 0
        || sid_offset
            .checked_add(sid_length)
            .is_none_or(|end| end > ace_size)
    {
        return Err(LaunchError::InvalidSecurityPlan);
    }
    Ok(Some(candidate))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ClosureNode {
    directory: bool,
    volume: u64,
    object: [u8; 16],
    attributes: u32,
    links: u64,
    size: u64,
}

fn closure_node(file: &File) -> Result<ClosureNode, LaunchError> {
    let handle = raw_file_handle(file);
    let mut id = FILE_ID_INFO::default();
    let mut standard = FILE_STANDARD_INFO::default();
    let mut tag = FILE_ATTRIBUTE_TAG_INFO::default();
    if unsafe {
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
        || standard.DeletePending
        || standard.EndOfFile < 0
    {
        return Err(last_error());
    }
    Ok(ClosureNode {
        directory: standard.Directory,
        volume: id.VolumeSerialNumber,
        object: id.FileId.Identifier,
        attributes: tag.FileAttributes,
        links: u64::from(standard.NumberOfLinks),
        size: standard.EndOfFile as u64,
    })
}

fn safe_closure_node(node: &ClosureNode, directory: bool, volume: u64) -> bool {
    node.directory == directory
        && node.volume == volume
        && node.attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
        && node.links == 1
}

fn open_closure_root_for_seal(path: &Path) -> Result<File, LaunchError> {
    let path = path_wide(path);
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            FILE_GENERIC_READ | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(last_error());
    }
    Ok(unsafe { File::from_raw_handle(handle.cast()) })
}

fn closure_directory_names(
    directory: &File,
    remaining: usize,
) -> Result<Vec<OsString>, LaunchError> {
    const BUFFER_BYTES: usize = 64 * 1024;
    let header = std::mem::offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);
    let mut names = Vec::new();
    let mut restart = true;
    loop {
        let mut buffer = vec![0_u64; BUFFER_BYTES.div_ceil(size_of::<u64>())];
        let class = if restart {
            FileIdBothDirectoryRestartInfo
        } else {
            FileIdBothDirectoryInfo
        };
        if unsafe {
            GetFileInformationByHandleEx(
                raw_file_handle(directory),
                class,
                buffer.as_mut_ptr().cast(),
                BUFFER_BYTES as u32,
            )
        } == 0
        {
            let error = unsafe { GetLastError() };
            if matches!(error, ERROR_NO_MORE_FILES | ERROR_HANDLE_EOF) {
                break;
            }
            return Err(LaunchError::Win32(error));
        }
        restart = false;
        let base = buffer.as_ptr().cast::<u8>();
        let mut offset = 0_usize;
        loop {
            if offset
                .checked_add(header)
                .is_none_or(|end| end > BUFFER_BYTES)
            {
                return Err(LaunchError::InvalidSecurityPlan);
            }
            let info = unsafe {
                std::ptr::read_unaligned(base.add(offset).cast::<FILE_ID_BOTH_DIR_INFO>())
            };
            let name_bytes = usize::try_from(info.FileNameLength)
                .map_err(|_| LaunchError::InvalidSecurityPlan)?;
            if name_bytes == 0
                || name_bytes % 2 != 0
                || offset
                    .checked_add(header)
                    .and_then(|start| start.checked_add(name_bytes))
                    .is_none_or(|end| end > BUFFER_BYTES)
            {
                return Err(LaunchError::InvalidSecurityPlan);
            }
            let units = unsafe {
                std::slice::from_raw_parts(
                    base.add(offset + header).cast::<u16>(),
                    name_bytes / size_of::<u16>(),
                )
            };
            let name = OsString::from_wide(units);
            if name != "." && name != ".." {
                names.push(name);
                if names.len() > remaining {
                    return Err(LaunchError::InvalidSecurityPlan);
                }
            }
            if info.NextEntryOffset == 0 {
                break;
            }
            let next = info.NextEntryOffset as usize;
            if next < header + name_bytes
                || offset
                    .checked_add(next)
                    .is_none_or(|end| end >= BUFFER_BYTES)
            {
                return Err(LaunchError::InvalidSecurityPlan);
            }
            offset += next;
        }
    }
    names.sort_unstable();
    if names.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(LaunchError::InvalidSecurityPlan);
    }
    Ok(names)
}

#[repr(C)]
union ClosureIoStatusValue {
    status: NTSTATUS,
    pointer: *mut c_void,
}

#[repr(C)]
struct ClosureIoStatusBlock {
    value: ClosureIoStatusValue,
    information: usize,
}

#[repr(C)]
struct ClosureObjectAttributes {
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
        object_attributes: *const ClosureObjectAttributes,
        io_status_block: *mut ClosureIoStatusBlock,
        allocation_size: *const i64,
        file_attributes: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        ea_buffer: *const c_void,
        ea_length: u32,
    ) -> NTSTATUS;
}

fn nt_open_closure_child(parent: &File, name: &OsStr) -> Result<File, LaunchError> {
    let mut name = name.encode_wide().collect::<Vec<_>>();
    let bytes = name
        .len()
        .checked_mul(size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or(LaunchError::InvalidSecurityPlan)?;
    if name.is_empty() || name.contains(&0) {
        return Err(LaunchError::InvalidSecurityPlan);
    }
    let mut unicode = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: name.as_mut_ptr(),
    };
    let attributes = ClosureObjectAttributes {
        length: size_of::<ClosureObjectAttributes>() as u32,
        root_directory: raw_file_handle(parent),
        object_name: &mut unicode,
        attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        security_descriptor: null_mut(),
        security_quality_of_service: null_mut(),
    };
    let mut status_block = ClosureIoStatusBlock {
        value: ClosureIoStatusValue {
            pointer: null_mut(),
        },
        information: 0,
    };
    let mut handle = INVALID_HANDLE_VALUE;
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            FILE_GENERIC_READ | WRITE_DAC | SYNCHRONIZE,
            &attributes,
            &mut status_block,
            null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
            null(),
            0,
        )
    };
    if status >= 0 && handle != INVALID_HANDLE_VALUE {
        return Ok(unsafe { File::from_raw_handle(handle.cast()) });
    }
    if matches!(
        status,
        STATUS_REPARSE_POINT_ENCOUNTERED | STATUS_STOPPED_ON_SYMLINK
    ) {
        return Err(LaunchError::InvalidSecurityPlan);
    }
    Err(LaunchError::Win32(unsafe { RtlNtStatusToDosError(status) }))
}

struct LocalSecurityAllocation(*mut c_void);

impl LocalSecurityAllocation {
    fn new(value: *mut c_void) -> Result<Self, LaunchError> {
        if value.is_null() {
            return Err(LaunchError::InvalidSecurityPlan);
        }
        Ok(Self(value))
    }
}

impl Drop for LocalSecurityAllocation {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0 as HLOCAL);
        }
    }
}

impl LaunchBackend for Win32LaunchBackend {
    fn create_suspended(&mut self) -> Result<(), LaunchError> {
        if self.process.is_some() {
            return Err(LaunchError::CreateProcessFailed);
        }
        let handles = self.pipes.child_handles()?;
        let plan = SecurityAttributePlan::new(
            self.sid.as_ptr() as usize,
            handles.map(|handle| handle as usize),
        )?;
        if plan.attribute_count() != 2
            || plan.capabilities_ptr() != 0
            || plan.capability_count() != 0
            || plan.reserved() != 0
        {
            return Err(LaunchError::InvalidSecurityPlan);
        }

        let capabilities = SECURITY_CAPABILITIES {
            AppContainerSid: self.sid.as_ptr(),
            Capabilities: null_mut(),
            CapabilityCount: 0,
            Reserved: 0,
        };
        let attributes = ProcThreadAttributes::new(plan.attribute_count())?;
        attributes.update(
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
            (&capabilities as *const SECURITY_CAPABILITIES).cast(),
            size_of::<SECURITY_CAPABILITIES>(),
        )?;
        attributes.update(
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            handles.as_ptr().cast(),
            size_of::<[HANDLE; 3]>(),
        )?;

        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = handles[0];
        startup.StartupInfo.hStdOutput = handles[1];
        startup.StartupInfo.hStdError = handles[2];
        startup.lpAttributeList = attributes.list;

        let application = path_wide(self.helper.path());
        let mut command_line = quoted_path_wide(self.helper.path());
        let environment = environment_block(&self.layout)?;
        let current_directory = path_wide(self.layout.stage());
        let mut process_information = PROCESS_INFORMATION::default();
        let flags = CREATE_SUSPENDED
            | EXTENDED_STARTUPINFO_PRESENT
            | CREATE_UNICODE_ENVIRONMENT
            | CREATE_NO_WINDOW;
        let created = unsafe {
            CreateProcessW(
                application.as_ptr(),
                command_line.as_mut_ptr(),
                null(),
                null(),
                1,
                flags,
                environment.as_ptr().cast(),
                current_directory.as_ptr(),
                &startup.StartupInfo,
                &mut process_information,
            )
        };
        self.pipes.close_child_ends();
        if created == 0 {
            return Err(LaunchError::CreateProcessFailed);
        }

        let process = owned_handle(process_information.hProcess)?;
        let thread = owned_handle(process_information.hThread)?;
        require_noninherited(raw_handle(&process))?;
        require_noninherited(raw_handle(&thread))?;
        self.process = Some(process);
        self.thread = Some(thread);
        self.audit.created_suspended = true;
        self.audit.inherited_handle_count = 3;
        Ok(())
    }

    fn bind_kill_on_close_job(&mut self) -> Result<(), LaunchError> {
        let process = self.process_handle()?;
        if unsafe { AssignProcessToJobObject(raw_handle(&self.job), process) } == 0 {
            return Err(LaunchError::JobAssignmentFailed);
        }
        let mut in_job = 0;
        if unsafe { IsProcessInJob(process, raw_handle(&self.job), &mut in_job) } == 0
            || in_job == 0
        {
            return Err(LaunchError::JobAssignmentFailed);
        }
        self.job_assigned = true;
        self.audit.job_membership_verified = true;
        Ok(())
    }

    fn attest_zero_capability_token(&mut self, sid: &str) -> Result<(), LaunchError> {
        if sid != self.identity.sid() {
            return Err(LaunchError::TokenAttestationFailed);
        }
        let process = self.process_handle()?;
        let mut token = null_mut();
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
            return Err(LaunchError::TokenAttestationFailed);
        }
        let token = owned_handle(token).map_err(|_| LaunchError::TokenAttestationFailed)?;

        let mut is_appcontainer = 0u32;
        let mut returned = 0u32;
        if unsafe {
            GetTokenInformation(
                raw_handle(&token),
                TokenIsAppContainer,
                (&mut is_appcontainer as *mut u32).cast(),
                size_of::<u32>() as u32,
                &mut returned,
            )
        } == 0
            || returned < size_of::<u32>() as u32
            || is_appcontainer == 0
        {
            return Err(LaunchError::TokenAttestationFailed);
        }
        self.audit.token_is_appcontainer = true;

        let (sid_buffer, sid_bytes) = query_token_buffer(raw_handle(&token), TokenAppContainerSid)?;
        if sid_bytes < size_of::<TOKEN_APPCONTAINER_INFORMATION>() {
            return Err(LaunchError::TokenAttestationFailed);
        }
        let information =
            unsafe { &*(sid_buffer.as_ptr() as *const TOKEN_APPCONTAINER_INFORMATION) };
        let actual_sid = information.TokenAppContainer;
        let start = sid_buffer.as_ptr() as usize;
        let end = start
            .checked_add(sid_bytes)
            .ok_or(LaunchError::TokenAttestationFailed)?;
        let actual = actual_sid as usize;
        if actual_sid.is_null()
            || actual < start
            || actual >= end
            || unsafe { IsValidSid(actual_sid) } == 0
        {
            return Err(LaunchError::TokenAttestationFailed);
        }
        let sid_length = unsafe { GetLengthSid(actual_sid) } as usize;
        if sid_length == 0
            || actual
                .checked_add(sid_length)
                .is_none_or(|limit| limit > end)
        {
            return Err(LaunchError::TokenAttestationFailed);
        }
        if unsafe { EqualSid(actual_sid, self.sid.as_ptr()) } == 0 {
            return Err(LaunchError::TokenAttestationFailed);
        }
        self.audit.token_sid_verified = true;

        let (capability_buffer, capability_bytes) =
            query_token_buffer(raw_handle(&token), TokenCapabilities)?;
        if capability_bytes < size_of::<u32>() {
            return Err(LaunchError::TokenAttestationFailed);
        }
        let capability_count = unsafe { *(capability_buffer.as_ptr() as *const u32) };
        if capability_count != 0 {
            return Err(LaunchError::TokenAttestationFailed);
        }
        self.audit.token_capability_count = capability_count;
        Ok(())
    }

    fn resume_thread(&mut self) -> Result<u32, LaunchError> {
        let thread = self
            .thread
            .as_ref()
            .map(raw_handle)
            .ok_or(LaunchError::ResumeFailed)?;
        let previous_count = unsafe { ResumeThread(thread) };
        if previous_count == RESUME_FAILED {
            return Err(LaunchError::ResumeFailed);
        }
        self.audit.resumed_exactly_once = previous_count == 1;
        Ok(previous_count)
    }
}

impl Drop for Win32LaunchBackend {
    fn drop(&mut self) {
        if !self.completed {
            self.force_terminate();
        }
    }
}

impl LaunchSequence<Win32LaunchBackend, Suspended> {
    pub fn peek_stdout(&self) -> Result<u32, LaunchError> {
        self.backend.pipes.peek_stdout()
    }

    pub fn inherited_exact_handle(&self, parent_handle: usize) -> Result<bool, LaunchError> {
        self.backend.inherited_exact_handle(parent_handle)
    }
}

impl LaunchSequence<Win32LaunchBackend, Running> {
    pub fn exchange(&mut self, input: &[u8]) -> Result<Win32SandboxOutput, LaunchError> {
        self.backend.exchange(input)
    }

    pub fn audit(&self) -> &Win32LaunchAudit {
        &self.backend.audit
    }
}

struct LockedHelper {
    path: PathBuf,
    _file: File,
}

impl LockedHelper {
    fn open(path: PathBuf, expected_digest: [u8; 32]) -> Result<Self, LaunchError> {
        let file = open_locked_regular(&path, None, expected_digest, FILE_SHARE_READ)?;
        Ok(Self { path, _file: file })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

pub(crate) fn copy_locked_file(
    source: &Path,
    destination: &Path,
    expected_size: Option<u64>,
    expected_digest: [u8; 32],
) -> Result<File, LaunchError> {
    if !destination.is_absolute() {
        return Err(LaunchError::LockedHelperRejected);
    }
    let mut source = open_locked_regular(source, expected_size, expected_digest, FILE_SHARE_READ)?;
    let mut destination_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(FILE_SHARE_READ)
        .open(destination)
        .map_err(|_| LaunchError::LockedHelperRejected)?;
    let copied =
        std::io::copy(&mut source, &mut destination_file).map_err(|_| LaunchError::PipeIo)?;
    if expected_size.is_some_and(|size| copied != size) {
        return Err(LaunchError::HelperDigestMismatch);
    }
    destination_file.flush().map_err(|_| LaunchError::PipeIo)?;
    destination_file
        .sync_all()
        .map_err(|_| LaunchError::PipeIo)?;
    validate_locked_helper(raw_file_handle(&destination_file))?;
    let transition = open_locked_regular(
        destination,
        expected_size,
        expected_digest,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
    )?;
    drop(destination_file);
    let read_only =
        open_locked_regular(destination, expected_size, expected_digest, FILE_SHARE_READ)?;
    drop(transition);
    Ok(read_only)
}

fn open_locked_regular(
    path: &Path,
    expected_size: Option<u64>,
    expected_digest: [u8; 32],
    share_mode: u32,
) -> Result<File, LaunchError> {
    if !path.is_absolute() {
        return Err(LaunchError::LockedHelperRejected);
    }
    let path_wide = path_wide(path);
    let handle = unsafe {
        CreateFileW(
            path_wide.as_ptr(),
            windows_sys::Win32::Foundation::GENERIC_READ,
            share_mode,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(last_error());
    }
    let mut file = unsafe { File::from_raw_handle(handle as RawHandle) };
    require_noninherited(raw_file_handle(&file))?;
    validate_locked_helper(handle)?;
    if expected_size.is_some_and(|size| file.metadata().map_or(true, |item| item.len() != size)) {
        return Err(LaunchError::HelperDigestMismatch);
    }

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|_| LaunchError::PipeIo)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let actual: [u8; 32] = hasher.finalize().into();
    if actual != expected_digest {
        return Err(LaunchError::HelperDigestMismatch);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| LaunchError::PipeIo)?;
    Ok(file)
}

fn validate_locked_helper(handle: HANDLE) -> Result<(), LaunchError> {
    let mut tag = FILE_ATTRIBUTE_TAG_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            (&mut tag as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    } == 0
    {
        return Err(last_error());
    }
    if tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(LaunchError::LockedHelperRejected);
    }

    let mut standard = FILE_STANDARD_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileStandardInfo,
            (&mut standard as *mut FILE_STANDARD_INFO).cast(),
            size_of::<FILE_STANDARD_INFO>() as u32,
        )
    } == 0
    {
        return Err(last_error());
    }
    if standard.Directory
        || standard.DeletePending
        || standard.NumberOfLinks != 1
        || standard.EndOfFile < 0
        || standard.EndOfFile > MAX_HELPER_BYTES
    {
        return Err(LaunchError::LockedHelperRejected);
    }
    Ok(())
}

struct ProtocolPipes {
    stdin: Option<File>,
    stdout: Option<File>,
    stderr: Option<File>,
    child_stdin: Option<OwnedHandle>,
    child_stdout: Option<OwnedHandle>,
    child_stderr: Option<OwnedHandle>,
}

impl ProtocolPipes {
    fn new() -> Result<Self, LaunchError> {
        let (stdin, child_stdin) = pipe_pair(false)?;
        let (stdout, child_stdout) = pipe_pair(true)?;
        let (stderr, child_stderr) = pipe_pair(true)?;
        Ok(Self {
            stdin: Some(stdin),
            stdout: Some(stdout),
            stderr: Some(stderr),
            child_stdin: Some(child_stdin),
            child_stdout: Some(child_stdout),
            child_stderr: Some(child_stderr),
        })
    }

    fn child_handles(&self) -> Result<[HANDLE; 3], LaunchError> {
        Ok([
            self.child_stdin
                .as_ref()
                .map(raw_handle)
                .ok_or(LaunchError::InvalidSecurityPlan)?,
            self.child_stdout
                .as_ref()
                .map(raw_handle)
                .ok_or(LaunchError::InvalidSecurityPlan)?,
            self.child_stderr
                .as_ref()
                .map(raw_handle)
                .ok_or(LaunchError::InvalidSecurityPlan)?,
        ])
    }

    fn close_child_ends(&mut self) {
        self.child_stdin.take();
        self.child_stdout.take();
        self.child_stderr.take();
    }

    fn peek_stdout(&self) -> Result<u32, LaunchError> {
        let stdout = self.stdout.as_ref().ok_or(LaunchError::PipeIo)?;
        let mut available = 0;
        if unsafe {
            PeekNamedPipe(
                raw_file_handle(stdout),
                null_mut(),
                0,
                null_mut(),
                &mut available,
                null_mut(),
            )
        } == 0
        {
            return Err(last_error());
        }
        Ok(available)
    }

    fn take_stdin(&mut self) -> Result<File, LaunchError> {
        self.stdin.take().ok_or(LaunchError::PipeIo)
    }

    fn take_stdout(&mut self) -> Result<File, LaunchError> {
        self.stdout.take().ok_or(LaunchError::PipeIo)
    }

    fn take_stderr(&mut self) -> Result<File, LaunchError> {
        self.stderr.take().ok_or(LaunchError::PipeIo)
    }
}

fn pipe_pair(host_reads: bool) -> Result<(File, OwnedHandle), LaunchError> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    let mut read = null_mut();
    let mut write = null_mut();
    if unsafe { CreatePipe(&mut read, &mut write, &attributes, 0) } == 0 {
        return Err(last_error());
    }
    let read = owned_handle(read)?;
    let write = owned_handle(write)?;
    let (host, child) = if host_reads {
        (read, write)
    } else {
        (write, read)
    };
    clear_inheritance(raw_handle(&host))?;
    require_noninherited(raw_handle(&host))?;
    require_inherited(raw_handle(&child))?;
    Ok((File::from(host), child))
}

struct ProcThreadAttributes {
    heap: HANDLE,
    list: LPPROC_THREAD_ATTRIBUTE_LIST,
}

impl ProcThreadAttributes {
    fn new(count: u32) -> Result<Self, LaunchError> {
        let mut bytes = 0usize;
        if unsafe { InitializeProcThreadAttributeList(null_mut(), count, 0, &mut bytes) } != 0
            || unsafe { windows_sys::Win32::Foundation::GetLastError() }
                != ERROR_INSUFFICIENT_BUFFER
            || bytes == 0
        {
            return Err(LaunchError::InvalidSecurityPlan);
        }
        let heap = unsafe { GetProcessHeap() };
        if heap.is_null() {
            return Err(last_error());
        }
        let list = unsafe { HeapAlloc(heap, HEAP_ZERO_MEMORY, bytes) };
        if list.is_null() {
            return Err(last_error());
        }
        if unsafe { InitializeProcThreadAttributeList(list, count, 0, &mut bytes) } == 0 {
            let error = last_error();
            unsafe {
                HeapFree(heap, 0, list);
            }
            return Err(error);
        }
        Ok(Self { heap, list })
    }

    fn update(
        &self,
        attribute: usize,
        value: *const c_void,
        size: usize,
    ) -> Result<(), LaunchError> {
        if unsafe {
            UpdateProcThreadAttribute(self.list, 0, attribute, value, size, null_mut(), null())
        } == 0
        {
            return Err(last_error());
        }
        Ok(())
    }
}

impl Drop for ProcThreadAttributes {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.list);
            HeapFree(self.heap, 0, self.list);
        }
    }
}

fn create_verified_kill_job() -> Result<OwnedHandle, LaunchError> {
    let raw = unsafe { CreateJobObjectW(null(), null()) };
    let job = owned_handle(raw)?;
    require_noninherited(raw_handle(&job))?;

    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if unsafe {
        SetInformationJobObject(
            raw_handle(&job),
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    } == 0
    {
        return Err(last_error());
    }

    let mut verified = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    if unsafe {
        QueryInformationJobObject(
            raw_handle(&job),
            JobObjectExtendedLimitInformation,
            (&mut verified as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            null_mut(),
        )
    } == 0
    {
        return Err(last_error());
    }
    let flags = verified.BasicLimitInformation.LimitFlags;
    let forbidden = JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;
    if flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE == 0 || flags & forbidden != 0 {
        return Err(LaunchError::JobAssignmentFailed);
    }
    Ok(job)
}

fn query_token_buffer(
    token: HANDLE,
    information_class: i32,
) -> Result<(Vec<usize>, usize), LaunchError> {
    let mut required = 0u32;
    if unsafe { GetTokenInformation(token, information_class, null_mut(), 0, &mut required) } != 0
        || unsafe { windows_sys::Win32::Foundation::GetLastError() } != ERROR_INSUFFICIENT_BUFFER
        || required == 0
        || required > MAX_TOKEN_INFORMATION_BYTES
    {
        return Err(LaunchError::TokenAttestationFailed);
    }
    let word_bytes = size_of::<usize>();
    let word_count = (required as usize)
        .checked_add(word_bytes - 1)
        .ok_or(LaunchError::TokenAttestationFailed)?
        / word_bytes;
    let mut buffer = vec![0usize; word_count];
    let capacity = buffer
        .len()
        .checked_mul(word_bytes)
        .ok_or(LaunchError::TokenAttestationFailed)?;
    let mut returned = capacity as u32;
    if unsafe {
        GetTokenInformation(
            token,
            information_class,
            buffer.as_mut_ptr().cast(),
            capacity as u32,
            &mut returned,
        )
    } == 0
        || returned as usize > capacity
    {
        return Err(LaunchError::TokenAttestationFailed);
    }
    Ok((buffer, returned as usize))
}

fn environment_block(layout: &Win32ProfileLayout) -> Result<Vec<u16>, LaunchError> {
    let system_root = windows_directory().ok_or(LaunchError::CreateProcessFailed)?;
    let mut entries: Vec<(&str, &OsStr)> = vec![
        ("APPDATA", layout.data().as_os_str()),
        ("HOME", layout.home().as_os_str()),
        ("LANG", OsStr::new("C.UTF-8")),
        ("LC_ALL", OsStr::new("C.UTF-8")),
        ("LOCALAPPDATA", layout.data().as_os_str()),
        ("PATH", layout.runtime().as_os_str()),
        ("SYSTEMROOT", system_root.as_os_str()),
        ("TEMP", layout.temp().as_os_str()),
        ("TMP", layout.temp().as_os_str()),
        ("TMPDIR", layout.temp().as_os_str()),
        ("USERPROFILE", layout.home().as_os_str()),
        ("XDG_CACHE_HOME", layout.cache().as_os_str()),
        ("XDG_CONFIG_HOME", layout.config().as_os_str()),
        ("XDG_DATA_HOME", layout.data().as_os_str()),
    ];
    entries.sort_unstable_by(|left, right| left.0.cmp(right.0));
    let mut block = Vec::new();
    for (key, value) in entries {
        block.extend(key.encode_utf16());
        block.push('=' as u16);
        block.extend(value.encode_wide());
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

fn prepare_effective_local_app_data(
    identity: &ProfileIdentity,
    layout: &Win32ProfileLayout,
) -> Result<(), LaunchError> {
    let packages = layout.data().join("Packages");
    let package = packages.join(identity.moniker().as_str());
    let effective = package.join("AC");
    let effective_temp = effective.join("Temp");
    for path in [&packages, &package, &effective, &effective_temp] {
        std::fs::create_dir(path)
            .or_else(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    Ok(())
                } else {
                    Err(error)
                }
            })
            .map_err(|_| LaunchError::PipeIo)?;
        let metadata = std::fs::symlink_metadata(path).map_err(|_| LaunchError::PipeIo)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(LaunchError::InvalidProfileIdentity);
        }
    }
    Ok(())
}

fn path_wide(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn quoted_path_wide(path: &Path) -> Vec<u16> {
    std::iter::once('"' as u16)
        .chain(path.as_os_str().encode_wide())
        .chain(std::iter::once('"' as u16))
        .chain(std::iter::once(0))
        .collect()
}

fn owned_handle(handle: HANDLE) -> Result<OwnedHandle, LaunchError> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(last_error());
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) })
}

fn raw_handle(handle: &OwnedHandle) -> HANDLE {
    handle.as_raw_handle() as HANDLE
}

fn raw_file_handle(file: &File) -> HANDLE {
    file.as_raw_handle() as HANDLE
}

fn clear_inheritance(handle: HANDLE) -> Result<(), LaunchError> {
    if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err(last_error());
    }
    Ok(())
}

fn require_inherited(handle: HANDLE) -> Result<(), LaunchError> {
    let mut flags = 0;
    if unsafe { GetHandleInformation(handle, &mut flags) } == 0 || flags & HANDLE_FLAG_INHERIT == 0
    {
        return Err(LaunchError::InvalidSecurityPlan);
    }
    Ok(())
}

fn require_noninherited(handle: HANDLE) -> Result<(), LaunchError> {
    let mut flags = 0;
    if unsafe { GetHandleInformation(handle, &mut flags) } == 0 || flags & HANDLE_FLAG_INHERIT != 0
    {
        return Err(LaunchError::InvalidSecurityPlan);
    }
    Ok(())
}
