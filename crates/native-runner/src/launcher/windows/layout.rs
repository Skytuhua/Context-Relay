use std::{
    fs::{self, File},
    mem::size_of,
    os::windows::{ffi::OsStrExt, io::FromRawHandle},
    path::{Path, PathBuf},
    ptr::{null, null_mut},
    sync::Arc,
};

use windows_sys::Win32::{
    Foundation::{GENERIC_READ, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_STANDARD_INFO, FileAttributeTagInfo, FileStandardInfo,
        GetFileInformationByHandleEx, OPEN_EXISTING,
    },
};

use super::LaunchError;

const HELPER_NAME: &str = "context-relay-native-helper.exe";

#[derive(Clone, Debug)]
pub struct Win32ProfileLayout {
    root: PathBuf,
    closure: PathBuf,
    stage: PathBuf,
    home: PathBuf,
    config: PathBuf,
    data: PathBuf,
    cache: PathBuf,
    temp: PathBuf,
    runtime: PathBuf,
    reports: PathBuf,
    closure_runtime: PathBuf,
    closure_runtime_lock: Option<Arc<File>>,
    _directory_locks: Arc<Vec<File>>,
}

impl Win32ProfileLayout {
    pub fn initialize(root: PathBuf) -> Result<Self, LaunchError> {
        if !root.is_absolute() || !root.is_dir() {
            return Err(LaunchError::InvalidProfileIdentity);
        }
        let mut ancestors = root.ancestors().collect::<Vec<_>>();
        ancestors.reverse();
        for ancestor in ancestors {
            if ancestor.parent().is_some() {
                drop(lock_directory(ancestor)?);
            }
        }
        let stage = root.join("stage");
        let closure = root.join("closure");
        let mut layout = Self {
            home: stage.join("home"),
            config: stage.join("config"),
            data: stage.join("data"),
            cache: stage.join("cache"),
            temp: stage.join("temp"),
            runtime: stage.join("runtime"),
            reports: stage.join("reports"),
            closure_runtime: closure.join("runtime"),
            closure_runtime_lock: None,
            closure,
            stage,
            _directory_locks: Arc::new(vec![lock_directory(&root)?]),
            root,
        };
        for path in [
            layout.closure.clone(),
            layout.closure_runtime.clone(),
            layout.stage.clone(),
            layout.home.clone(),
            layout.config.clone(),
            layout.data.clone(),
            layout.cache.clone(),
            layout.temp.clone(),
            layout.runtime.clone(),
            layout.reports.clone(),
        ] {
            fs::create_dir(&path).map_err(|_| LaunchError::PipeIo)?;
            let lock = lock_directory(&path)?;
            if path == layout.closure_runtime {
                layout.closure_runtime_lock =
                    Some(Arc::new(lock.try_clone().map_err(|_| LaunchError::PipeIo)?));
            }
            Arc::get_mut(&mut layout._directory_locks)
                .expect("layout has not been cloned during initialization")
                .push(lock);
        }
        Ok(layout)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn helper_path(&self) -> PathBuf {
        self.closure.join(HELPER_NAME)
    }

    pub(crate) fn closure_runtime(&self) -> &Path {
        &self.closure_runtime
    }

    pub(crate) fn closure_runtime_lock(&self) -> Result<&File, LaunchError> {
        self.closure_runtime_lock
            .as_deref()
            .ok_or(LaunchError::InvalidProfileIdentity)
    }

    pub(crate) fn stage(&self) -> &Path {
        &self.stage
    }

    pub(crate) fn home(&self) -> &Path {
        &self.home
    }

    pub(crate) fn config(&self) -> &Path {
        &self.config
    }

    pub(crate) fn data(&self) -> &Path {
        &self.data
    }

    pub(crate) fn cache(&self) -> &Path {
        &self.cache
    }

    pub(crate) fn temp(&self) -> &Path {
        &self.temp
    }

    pub(crate) fn runtime(&self) -> &Path {
        &self.runtime
    }
}

pub(crate) fn lock_directory(path: &Path) -> Result<File, LaunchError> {
    let path = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(LaunchError::InvalidProfileIdentity);
    }
    let file = unsafe { File::from_raw_handle(handle.cast()) };
    let mut tag = FILE_ATTRIBUTE_TAG_INFO::default();
    let mut standard = FILE_STANDARD_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            (&mut tag as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
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
        || tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || !standard.Directory
        || standard.DeletePending
    {
        return Err(LaunchError::InvalidProfileIdentity);
    }
    Ok(file)
}
