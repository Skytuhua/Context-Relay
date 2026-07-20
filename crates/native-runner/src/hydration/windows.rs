use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString, c_void},
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    mem::size_of,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle},
    },
    path::{Path, PathBuf},
    ptr::{null, null_mut},
};

use sha2::{Digest, Sha256};
use windows_sys::Win32::{
    Foundation::{
        ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND,
        GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, NTSTATUS, OBJ_CASE_INSENSITIVE,
        OBJ_DONT_REPARSE, RtlNtStatusToDosError, STATUS_REPARSE_POINT_ENCOUNTERED,
        STATUS_STOPPED_ON_SYMLINK, UNICODE_STRING,
    },
    Storage::FileSystem::{
        DELETE, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
        FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
        FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO_EX, FILE_GENERIC_READ,
        FILE_GENERIC_WRITE, FILE_ID_INFO, FILE_RENAME_INFO, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_STANDARD_INFO, FileAttributeTagInfo, FileDispositionInfoEx,
        FileIdInfo, FileStandardInfo, GetFileInformationByHandleEx, SYNCHRONIZE,
        SetFileInformationByHandle,
    },
};

use super::{HydrationFile, HydrationOutcome};
use crate::RunnerError;

const FILE_OPEN: u32 = 1;
const FILE_CREATE: u32 = 2;
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const STABLE_SHARE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OpenError {
    Missing,
    Exists,
    Reparse,
    Io,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Identity {
    volume: u64,
    object: [u8; 16],
}

struct BoundDirectory {
    path: PathBuf,
    handle: File,
    identity: Identity,
}

struct CreatedDirectory {
    handle: Option<File>,
    parent: Option<usize>,
    name: OsString,
}

struct CreatedFile {
    handle: Option<File>,
    parent: usize,
    name: OsString,
    digest: [u8; 32],
}

struct PartialTree {
    external_parent: File,
    final_name: OsString,
    directories: Vec<CreatedDirectory>,
    directory_index: BTreeMap<String, usize>,
    files: Vec<CreatedFile>,
    volume: u64,
    published: bool,
}

pub(super) fn install(
    workspace: &Path,
    target: &str,
    manifest: &str,
    partial: &str,
    files: &[HydrationFile],
) -> Result<HydrationOutcome, RunnerError> {
    let mut chain = bind_workspace(workspace)?;
    for component in ["target", "sidecars", target] {
        let parent = &chain.last().ok_or(RunnerError::Io)?.handle;
        let handle = open_or_create_directory(parent, OsStr::new(component))?;
        let identity = safe_identity(&handle, true, chain[0].identity.volume)?;
        let path = chain.last().ok_or(RunnerError::Io)?.path.join(component);
        chain.push(BoundDirectory {
            path,
            handle,
            identity,
        });
    }
    #[cfg(test)]
    super::run_after_parent_bind_test_hook()?;
    verify_chain(&chain)?;
    let parent = &chain.last().ok_or(RunnerError::Io)?.handle;
    match open_relative(
        parent,
        OsStr::new(manifest),
        FILE_GENERIC_READ,
        STABLE_SHARE,
        FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
    ) {
        Ok(existing) => {
            safe_identity(&existing, true, chain[0].identity.volume)?;
            return Ok(HydrationOutcome::AlreadyExists);
        }
        Err(OpenError::Missing) => {}
        Err(OpenError::Reparse) => return Err(RunnerError::UnsafeTopology),
        Err(OpenError::Exists | OpenError::Io) => return Err(RunnerError::Io),
    }

    let partial_handle = open_relative(
        parent,
        OsStr::new(partial),
        FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE,
        FILE_SHARE_READ,
        FILE_CREATE,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
    )
    .map_err(open_error)?;
    safe_identity(&partial_handle, true, chain[0].identity.volume)?;
    let mut tree = PartialTree::new(
        parent.try_clone().map_err(|_| RunnerError::Io)?,
        OsString::from(manifest),
        OsString::from(partial),
        partial_handle,
        chain[0].identity.volume,
    );
    #[cfg(test)]
    super::run_after_partial_create_test_hook()?;
    for file in files {
        tree.create_file(file)?;
    }
    verify_chain(&chain)?;
    let outcome = tree.publish()?;
    verify_chain(&chain)?;
    Ok(outcome)
}

impl PartialTree {
    fn new(
        parent: File,
        final_name: OsString,
        partial_name: OsString,
        partial: File,
        volume: u64,
    ) -> Self {
        let mut directory_index = BTreeMap::new();
        directory_index.insert(String::new(), 0);
        Self {
            external_parent: parent,
            final_name,
            directories: vec![CreatedDirectory {
                handle: Some(partial),
                parent: None,
                name: partial_name,
            }],
            directory_index,
            files: Vec::new(),
            volume,
            published: false,
        }
    }

    fn create_file(&mut self, file: &HydrationFile) -> Result<(), RunnerError> {
        let (parent, name) = file
            .path()
            .as_str()
            .rsplit_once('/')
            .map_or(("", file.path().as_str()), |(parent, name)| (parent, name));
        let parent = self.ensure_directory(parent)?;
        let mut handle = open_relative(
            self.directories[parent]
                .handle
                .as_ref()
                .ok_or(RunnerError::Io)?,
            OsStr::new(name),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE,
            FILE_SHARE_READ,
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
        )
        .map_err(open_error)?;
        handle
            .write_all(file.bytes())
            .map_err(|_| RunnerError::Io)?;
        handle.sync_all().map_err(|_| RunnerError::Io)?;
        let node = safe_node(&handle, false, self.volume)?;
        if node.size != file.bytes().len() as u64 {
            return Err(RunnerError::ConcurrentChange);
        }
        self.files.push(CreatedFile {
            handle: Some(handle),
            parent,
            name: OsString::from(name),
            digest: Sha256::digest(file.bytes()).into(),
        });
        Ok(())
    }

    fn ensure_directory(&mut self, relative: &str) -> Result<usize, RunnerError> {
        let mut key = String::new();
        let mut parent = 0;
        for component in relative
            .split('/')
            .filter(|component| !component.is_empty())
        {
            if !key.is_empty() {
                key.push('/');
            }
            key.push_str(component);
            if let Some(index) = self.directory_index.get(&key) {
                parent = *index;
                continue;
            }
            let handle = open_relative(
                self.directories[parent]
                    .handle
                    .as_ref()
                    .ok_or(RunnerError::Io)?,
                OsStr::new(component),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE,
                FILE_SHARE_READ,
                FILE_CREATE,
                FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
            )
            .map_err(open_error)?;
            safe_identity(&handle, true, self.volume)?;
            let index = self.directories.len();
            self.directories.push(CreatedDirectory {
                handle: Some(handle),
                parent: Some(parent),
                name: OsString::from(component),
            });
            self.directory_index.insert(key.clone(), index);
            parent = index;
        }
        Ok(parent)
    }

    fn publish(mut self) -> Result<HydrationOutcome, RunnerError> {
        self.seal_for_parent_rename()?;
        self.files.clear();
        while self.directories.len() > 1 {
            self.directories.pop();
        }
        let partial = self.directories[0].handle.as_ref().ok_or(RunnerError::Io)?;
        match rename_to_parent(partial, &self.external_parent, &self.final_name) {
            Ok(()) => {
                let installed = open_relative(
                    &self.external_parent,
                    &self.final_name,
                    FILE_GENERIC_READ,
                    STABLE_SHARE,
                    FILE_OPEN,
                    FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
                )
                .map_err(open_error)?;
                if safe_identity(&installed, true, self.volume)?
                    != safe_identity(partial, true, self.volume)?
                {
                    return Err(RunnerError::ConcurrentChange);
                }
                self.published = true;
                Ok(HydrationOutcome::Installed)
            }
            Err(OpenError::Exists) => Ok(HydrationOutcome::AlreadyExists),
            Err(OpenError::Reparse) => Err(RunnerError::UnsafeTopology),
            Err(OpenError::Missing | OpenError::Io) => Err(RunnerError::Io),
        }
    }

    fn seal_for_parent_rename(&mut self) -> Result<(), RunnerError> {
        for index in 0..self.files.len() {
            let parent = self.files[index].parent;
            let name = self.files[index].name.clone();
            let writer = self.files[index].handle.take().ok_or(RunnerError::Io)?;
            let lock = transition_child_lock(
                self.directories[parent]
                    .handle
                    .as_ref()
                    .ok_or(RunnerError::Io)?,
                &name,
                writer,
                false,
                self.volume,
            )?;
            if digest_file(&lock)? != self.files[index].digest {
                return Err(RunnerError::ConcurrentChange);
            }
            self.files[index].handle = Some(lock);
        }
        for index in (0..self.directories.len()).rev() {
            let name = self.directories[index].name.clone();
            let writer = self.directories[index]
                .handle
                .take()
                .ok_or(RunnerError::Io)?;
            let parent = match self.directories[index].parent {
                Some(parent) => self.directories[parent]
                    .handle
                    .as_ref()
                    .ok_or(RunnerError::Io)?,
                None => &self.external_parent,
            };
            self.directories[index].handle = Some(transition_child_lock(
                parent,
                &name,
                writer,
                true,
                self.volume,
            )?);
        }
        Ok(())
    }

    fn cleanup(&mut self) {
        while let Some(file) = self.files.pop() {
            if let Some(handle) = file.handle {
                let _ = delete_handle(&handle);
                drop(handle);
            }
        }
        while let Some(directory) = self.directories.pop() {
            if let Some(handle) = directory.handle {
                let _ = delete_handle(&handle);
                drop(handle);
            }
        }
    }
}

fn transition_child_lock(
    parent: &File,
    name: &OsStr,
    writer: File,
    directory: bool,
    volume: u64,
) -> Result<File, RunnerError> {
    let before = safe_identity(&writer, directory, volume)?;
    let options = FILE_SYNCHRONOUS_IO_NONALERT
        | FILE_OPEN_REPARSE_POINT
        | if directory {
            FILE_DIRECTORY_FILE
        } else {
            FILE_NON_DIRECTORY_FILE
        };
    let transition = open_relative(
        parent,
        name,
        FILE_GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        options,
    )
    .map_err(open_error)?;
    if safe_identity(&transition, directory, volume)? != before {
        return Err(RunnerError::ConcurrentChange);
    }
    drop(writer);
    let lock = open_relative(
        parent,
        name,
        FILE_GENERIC_READ | DELETE,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        FILE_OPEN,
        options,
    )
    .map_err(open_error)?;
    if safe_identity(&lock, directory, volume)? != before
        || safe_identity(&transition, directory, volume)? != before
    {
        return Err(RunnerError::ConcurrentChange);
    }
    Ok(lock)
}

fn digest_file(file: &File) -> Result<[u8; 32], RunnerError> {
    let mut file = file.try_clone().map_err(|_| RunnerError::Io)?;
    file.seek(SeekFrom::Start(0)).map_err(|_| RunnerError::Io)?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|_| RunnerError::Io)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(hash.finalize().into())
}

impl Drop for PartialTree {
    fn drop(&mut self) {
        if !self.published {
            self.cleanup();
        }
    }
}

struct SafeNode {
    identity: Identity,
    size: u64,
    directory: bool,
    attributes: u32,
    links: u64,
}

fn safe_node(file: &File, directory: bool, volume: u64) -> Result<SafeNode, RunnerError> {
    let handle = file.as_raw_handle() as HANDLE;
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
    {
        return Err(RunnerError::Io);
    }
    let node = SafeNode {
        identity: Identity {
            volume: id.VolumeSerialNumber,
            object: id.FileId.Identifier,
        },
        size: u64::try_from(standard.EndOfFile).map_err(|_| RunnerError::UnsafeTopology)?,
        directory: standard.Directory,
        attributes: tag.FileAttributes,
        links: u64::from(standard.NumberOfLinks),
    };
    if node.identity.volume != volume
        || node.directory != directory
        || node.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || node.links != 1
    {
        return Err(RunnerError::UnsafeTopology);
    }
    Ok(node)
}

fn safe_identity(file: &File, directory: bool, volume: u64) -> Result<Identity, RunnerError> {
    Ok(safe_node(file, directory, volume)?.identity)
}

fn bind_workspace(workspace: &Path) -> Result<Vec<BoundDirectory>, RunnerError> {
    validate_absolute(workspace)?;
    let handle = open_absolute_directory(workspace, STABLE_SHARE).map_err(open_error)?;
    let mut id = FILE_ID_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            handle.as_raw_handle() as HANDLE,
            FileIdInfo,
            (&mut id as *mut FILE_ID_INFO).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        return Err(RunnerError::Io);
    }
    let identity = safe_identity(&handle, true, id.VolumeSerialNumber)?;
    Ok(vec![BoundDirectory {
        path: workspace.to_path_buf(),
        handle,
        identity,
    }])
}

fn verify_chain(chain: &[BoundDirectory]) -> Result<(), RunnerError> {
    let volume = chain.first().ok_or(RunnerError::Io)?.identity.volume;
    for bound in chain {
        if safe_identity(&bound.handle, true, volume)? != bound.identity {
            return Err(RunnerError::ConcurrentChange);
        }
        let reopened = open_absolute_directory(&bound.path, STABLE_SHARE).map_err(|error| {
            if error == OpenError::Reparse {
                RunnerError::ConcurrentChange
            } else {
                RunnerError::Io
            }
        })?;
        if safe_identity(&reopened, true, volume)? != bound.identity {
            return Err(RunnerError::ConcurrentChange);
        }
    }
    Ok(())
}

fn open_or_create_directory(parent: &File, name: &OsStr) -> Result<File, RunnerError> {
    let options = FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT;
    match open_relative(
        parent,
        name,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE,
        STABLE_SHARE,
        FILE_CREATE,
        options,
    ) {
        Ok(handle) => Ok(handle),
        Err(OpenError::Exists) => open_relative(
            parent,
            name,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            STABLE_SHARE,
            FILE_OPEN,
            options,
        )
        .map_err(open_error),
        Err(error) => Err(open_error(error)),
    }
}

fn validate_absolute(path: &Path) -> Result<(), RunnerError> {
    let units = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if units.len() < 3
        || units.contains(&0)
        || units.contains(&u16::from(b'/'))
        || !char::from_u32(u32::from(units[0])).is_some_and(|value| value.is_ascii_alphabetic())
        || units[1] != u16::from(b':')
        || units[2] != u16::from(b'\\')
        || units[3..]
            .split(|unit| *unit == u16::from(b'\\'))
            .any(|component| component.is_empty())
    {
        return Err(RunnerError::InvalidPath);
    }
    Ok(())
}

fn open_absolute_directory(path: &Path, share: u32) -> Result<File, OpenError> {
    let mut name = OsString::from(r"\??\");
    name.push(path.as_os_str());
    nt_open(
        null_mut(),
        &name,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE,
        share,
        FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
    )
}

fn open_relative(
    parent: &File,
    name: &OsStr,
    desired_access: u32,
    share: u32,
    disposition: u32,
    options: u32,
) -> Result<File, OpenError> {
    validate_component(name).map_err(|_| OpenError::Io)?;
    nt_open(
        parent.as_raw_handle() as HANDLE,
        name,
        desired_access,
        share,
        disposition,
        options,
    )
}

fn nt_open(
    root: HANDLE,
    name: &OsStr,
    desired_access: u32,
    share: u32,
    disposition: u32,
    options: u32,
) -> Result<File, OpenError> {
    let mut name = name.encode_wide().collect::<Vec<_>>();
    let length = name
        .len()
        .checked_mul(size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or(OpenError::Io)?;
    if name.is_empty() || name.contains(&0) {
        return Err(OpenError::Io);
    }
    let mut unicode = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: name.as_mut_ptr(),
    };
    let attributes = ObjectAttributes {
        length: size_of::<ObjectAttributes>() as u32,
        root_directory: root,
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
    let mut mapped = desired_access & !(GENERIC_READ | GENERIC_WRITE);
    if desired_access & GENERIC_READ != 0 {
        mapped |= FILE_GENERIC_READ;
    }
    if desired_access & GENERIC_WRITE != 0 {
        mapped |= FILE_GENERIC_WRITE;
    }
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            mapped | SYNCHRONIZE,
            &attributes,
            &mut status_block,
            null(),
            FILE_ATTRIBUTE_NORMAL,
            share,
            disposition,
            options,
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
        return Err(OpenError::Reparse);
    }
    match unsafe { RtlNtStatusToDosError(status) } {
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Err(OpenError::Missing),
        ERROR_ALREADY_EXISTS | ERROR_FILE_EXISTS => Err(OpenError::Exists),
        _ => Err(OpenError::Io),
    }
}

fn validate_component(name: &OsStr) -> Result<(), RunnerError> {
    let units = name.encode_wide().collect::<Vec<_>>();
    if units.is_empty()
        || units.len() > 255
        || units.contains(&0)
        || units.iter().any(|unit| {
            *unit == u16::from(b'/') || *unit == u16::from(b'\\') || *unit == u16::from(b':')
        })
    {
        return Err(RunnerError::InvalidPath);
    }
    Ok(())
}

fn rename_to_parent(source: &File, parent: &File, destination: &OsStr) -> Result<(), OpenError> {
    validate_component(destination).map_err(|_| OpenError::Io)?;
    let name = destination.encode_wide().collect::<Vec<_>>();
    let name_bytes = name
        .len()
        .checked_mul(size_of::<u16>())
        .and_then(|length| u32::try_from(length).ok())
        .ok_or(OpenError::Io)?;
    let header = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
    let length = header
        .checked_add(name_bytes as usize)
        .ok_or(OpenError::Io)?;
    let mut storage = vec![0_usize; length.div_ceil(size_of::<usize>())];
    let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    unsafe {
        (*info).Anonymous.Flags = 2;
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
        if status >= 0 {
            return Ok(());
        }
        let error = RtlNtStatusToDosError(status);
        match error {
            ERROR_ALREADY_EXISTS | ERROR_FILE_EXISTS => Err(OpenError::Exists),
            _ => Err(OpenError::Io),
        }
    }
}

fn delete_handle(file: &File) -> Result<(), RunnerError> {
    let disposition = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE
            | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
            | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
    };
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

const fn open_error(error: OpenError) -> RunnerError {
    match error {
        OpenError::Reparse => RunnerError::UnsafeTopology,
        OpenError::Missing | OpenError::Exists | OpenError::Io => RunnerError::Io,
    }
}
