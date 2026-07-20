use std::{
    collections::BTreeMap,
    ffi::{CStr, CString},
    fs::File,
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    },
    path::{Component, Path, PathBuf},
};

use super::{HydrationFile, HydrationOutcome};
use crate::RunnerError;

const RENAME_EXCL: libc::c_uint = 0x0000_0004;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Identity {
    device: libc::dev_t,
    inode: libc::ino_t,
}

struct BoundDirectory {
    path: PathBuf,
    handle: File,
    identity: Identity,
}

struct CreatedDirectory {
    handle: File,
    parent: Option<usize>,
    name: CString,
    identity: Identity,
}

struct CreatedFile {
    handle: File,
    parent: usize,
    name: CString,
    identity: Identity,
}

struct PartialTree {
    external_parent: File,
    final_name: CString,
    directories: Vec<CreatedDirectory>,
    directory_index: BTreeMap<String, usize>,
    files: Vec<CreatedFile>,
    device: libc::dev_t,
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
        let handle = open_or_create_directory(parent, &name(component)?)?;
        let identity = safe_identity(&handle, true, chain[0].identity.device)?;
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
    let final_name = name(manifest)?;
    match open_directory_at(parent, &final_name) {
        Ok(existing) => {
            safe_identity(&existing, true, chain[0].identity.device)?;
            return Ok(HydrationOutcome::AlreadyExists);
        }
        Err(error) if last_errno() == libc::ENOENT => {
            let _ = error;
        }
        Err(_) => return Err(RunnerError::UnsafeTopology),
    }

    let partial_name = name(partial)?;
    if unsafe { libc::mkdirat(parent.as_raw_fd(), partial_name.as_ptr(), 0o700) } != 0 {
        return Err(if last_errno() == libc::EEXIST {
            RunnerError::ConcurrentChange
        } else {
            RunnerError::Io
        });
    }
    let partial_handle = open_directory_at(parent, &partial_name)?;
    let identity = safe_identity(&partial_handle, true, chain[0].identity.device)?;
    let mut tree = PartialTree::new(
        parent.try_clone().map_err(|_| RunnerError::Io)?,
        final_name,
        partial_name,
        partial_handle,
        identity,
        chain[0].identity.device,
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
        final_name: CString,
        partial_name: CString,
        partial: File,
        identity: Identity,
        device: libc::dev_t,
    ) -> Self {
        let mut directory_index = BTreeMap::new();
        directory_index.insert(String::new(), 0);
        Self {
            external_parent: parent,
            final_name,
            directories: vec![CreatedDirectory {
                handle: partial,
                parent: None,
                name: partial_name,
                identity,
            }],
            directory_index,
            files: Vec::new(),
            device,
            published: false,
        }
    }

    fn create_file(&mut self, file: &HydrationFile) -> Result<(), RunnerError> {
        let (parent, basename) = file
            .path()
            .as_str()
            .rsplit_once('/')
            .map_or(("", file.path().as_str()), |(parent, name)| (parent, name));
        let parent = self.ensure_directory(parent)?;
        let basename = name(basename)?;
        let fd = unsafe {
            libc::openat(
                self.directories[parent].handle.as_raw_fd(),
                basename.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(RunnerError::Io);
        }
        let mut handle = unsafe { File::from_raw_fd(fd) };
        handle
            .write_all(file.bytes())
            .map_err(|_| RunnerError::Io)?;
        let mode = if file.executable() { 0o700 } else { 0o600 };
        if unsafe { libc::fchmod(handle.as_raw_fd(), mode) } != 0 {
            return Err(RunnerError::Io);
        }
        handle.sync_all().map_err(|_| RunnerError::Io)?;
        let identity = safe_identity(&handle, false, self.device)?;
        if metadata(&handle)?.st_size < 0
            || metadata(&handle)?.st_size as usize != file.bytes().len()
        {
            return Err(RunnerError::ConcurrentChange);
        }
        self.files.push(CreatedFile {
            handle,
            parent,
            name: basename,
            identity,
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
            let component = name(component)?;
            let parent_handle = &self.directories[parent].handle;
            if unsafe { libc::mkdirat(parent_handle.as_raw_fd(), component.as_ptr(), 0o700) } != 0 {
                return Err(RunnerError::ConcurrentChange);
            }
            let handle = open_directory_at(parent_handle, &component)?;
            let identity = safe_identity(&handle, true, self.device)?;
            let index = self.directories.len();
            self.directories.push(CreatedDirectory {
                handle,
                parent: Some(parent),
                name: component,
                identity,
            });
            self.directory_index.insert(key.clone(), index);
            parent = index;
        }
        Ok(parent)
    }

    fn publish(mut self) -> Result<HydrationOutcome, RunnerError> {
        for directory in &self.directories {
            if safe_identity(&directory.handle, true, self.device)? != directory.identity {
                return Err(RunnerError::ConcurrentChange);
            }
            directory.handle.sync_all().map_err(|_| RunnerError::Io)?;
        }
        for file in &self.files {
            if safe_identity(&file.handle, false, self.device)? != file.identity {
                return Err(RunnerError::ConcurrentChange);
            }
        }
        let result = unsafe {
            libc::renameatx_np(
                self.external_parent.as_raw_fd(),
                self.directories[0].name.as_ptr(),
                self.external_parent.as_raw_fd(),
                self.final_name.as_ptr(),
                RENAME_EXCL,
            )
        };
        if result != 0 {
            return if last_errno() == libc::EEXIST {
                Ok(HydrationOutcome::AlreadyExists)
            } else {
                Err(RunnerError::Io)
            };
        }
        self.external_parent
            .sync_all()
            .map_err(|_| RunnerError::Io)?;
        let installed = open_directory_at(&self.external_parent, &self.final_name)?;
        if safe_identity(&installed, true, self.device)? != self.directories[0].identity {
            return Err(RunnerError::ConcurrentChange);
        }
        self.published = true;
        Ok(HydrationOutcome::Installed)
    }

    fn cleanup(&mut self) {
        while let Some(file) = self.files.pop() {
            if safe_identity(&file.handle, false, self.device).ok() == Some(file.identity) {
                let parent = &self.directories[file.parent].handle;
                if identity_at(parent, &file.name, false).ok() == Some(file.identity) {
                    unsafe {
                        libc::unlinkat(parent.as_raw_fd(), file.name.as_ptr(), 0);
                    }
                }
            }
        }
        while let Some(directory) = self.directories.pop() {
            let parent = match directory.parent {
                Some(parent) => self.directories.get(parent).map(|entry| &entry.handle),
                None => Some(&self.external_parent),
            };
            if safe_identity(&directory.handle, true, self.device).ok() == Some(directory.identity)
                && parent.and_then(|parent| identity_at(parent, &directory.name, true).ok())
                    == Some(directory.identity)
                && let Some(parent) = parent
            {
                unsafe {
                    libc::unlinkat(
                        parent.as_raw_fd(),
                        directory.name.as_ptr(),
                        libc::AT_REMOVEDIR,
                    );
                }
            }
        }
    }
}

impl Drop for PartialTree {
    fn drop(&mut self) {
        if !self.published {
            self.cleanup();
        }
    }
}

fn bind_workspace(workspace: &Path) -> Result<Vec<BoundDirectory>, RunnerError> {
    validate_absolute(workspace)?;
    let handle = open_absolute_directory(workspace)?;
    let stat = metadata(&handle)?;
    let identity = safe_identity(&handle, true, stat.st_dev)?;
    Ok(vec![BoundDirectory {
        path: workspace.to_path_buf(),
        handle,
        identity,
    }])
}

fn verify_chain(chain: &[BoundDirectory]) -> Result<(), RunnerError> {
    let device = chain.first().ok_or(RunnerError::Io)?.identity.device;
    for bound in chain {
        if safe_identity(&bound.handle, true, device)? != bound.identity {
            return Err(RunnerError::ConcurrentChange);
        }
        let reopened =
            open_absolute_directory(&bound.path).map_err(|_| RunnerError::ConcurrentChange)?;
        if safe_identity(&reopened, true, device)? != bound.identity {
            return Err(RunnerError::ConcurrentChange);
        }
    }
    Ok(())
}

fn open_or_create_directory(parent: &File, name: &CStr) -> Result<File, RunnerError> {
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0
        && last_errno() != libc::EEXIST
    {
        return Err(RunnerError::Io);
    }
    open_directory_at(parent, name)
}

fn open_absolute_directory(path: &Path) -> Result<File, RunnerError> {
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| RunnerError::InvalidPath)?;
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW_ANY,
        )
    };
    file_from_fd(fd)
}

fn open_directory_at(parent: &File, name: &CStr) -> Result<File, RunnerError> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0,
        )
    };
    file_from_fd(fd)
}

fn identity_at(parent: &File, name: &CStr, directory: bool) -> Result<Identity, RunnerError> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(RunnerError::Io);
    }
    identity_from_stat(unsafe { stat.assume_init() }, directory)
}

fn safe_identity(
    file: &File,
    directory: bool,
    device: libc::dev_t,
) -> Result<Identity, RunnerError> {
    let stat = metadata(file)?;
    let identity = identity_from_stat(stat, directory)?;
    if identity.device != device || (!directory && stat.st_nlink != 1) {
        return Err(RunnerError::UnsafeTopology);
    }
    Ok(identity)
}

fn identity_from_stat(stat: libc::stat, directory: bool) -> Result<Identity, RunnerError> {
    let mode = stat.st_mode & libc::S_IFMT;
    if (directory && mode != libc::S_IFDIR) || (!directory && mode != libc::S_IFREG) {
        return Err(RunnerError::UnsafeTopology);
    }
    Ok(Identity {
        device: stat.st_dev,
        inode: stat.st_ino,
    })
}

fn metadata(file: &File) -> Result<libc::stat, RunnerError> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(RunnerError::Io);
    }
    Ok(unsafe { stat.assume_init() })
}

fn file_from_fd(fd: libc::c_int) -> Result<File, RunnerError> {
    if fd < 0 {
        Err(RunnerError::Io)
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
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

fn name(value: &str) -> Result<CString, RunnerError> {
    if value.is_empty() || value.contains('/') {
        return Err(RunnerError::InvalidPath);
    }
    CString::new(value).map_err(|_| RunnerError::InvalidPath)
}

fn last_errno() -> libc::c_int {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}
