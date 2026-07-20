use std::{
    fmt,
    path::PathBuf,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::IpcError;

const PRODUCTION_SUFFIX: &str = "main";
const MAX_SUFFIX_BYTES: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeConfig {
    suffix: String,
    runtime_root: Option<PathBuf>,
}

impl RuntimeConfig {
    pub fn production() -> Self {
        Self {
            suffix: PRODUCTION_SUFFIX.into(),
            runtime_root: None,
        }
    }

    pub fn for_test(
        suffix: impl Into<String>,
        runtime_root: Option<PathBuf>,
    ) -> Result<Self, IpcError> {
        let suffix = suffix.into();
        validate_suffix(&suffix)?;
        Ok(Self {
            suffix,
            runtime_root,
        })
    }

    pub fn endpoint_name(&self) -> Result<String, IpcError> {
        platform::endpoint_name(self)
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self::production()
    }
}

fn validate_suffix(suffix: &str) -> Result<(), IpcError> {
    if suffix.is_empty()
        || suffix.len() > MAX_SUFFIX_BYTES
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(IpcError::InvalidRuntime);
    }
    Ok(())
}

#[cfg(windows)]
trait PlatformStream:
    AsyncRead + AsyncWrite + Unpin + Send + std::os::windows::io::AsRawHandle
{
}

#[cfg(windows)]
impl<T> PlatformStream for T where
    T: AsyncRead + AsyncWrite + Unpin + Send + std::os::windows::io::AsRawHandle
{
}

#[cfg(not(windows))]
trait PlatformStream: AsyncRead + AsyncWrite + Unpin + Send {}

#[cfg(not(windows))]
impl<T> PlatformStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub struct ConnectedStream {
    inner: Box<dyn PlatformStream>,
}

impl ConnectedStream {
    fn new(stream: impl PlatformStream + 'static) -> Self {
        Self {
            inner: Box::new(stream),
        }
    }
}

impl fmt::Debug for ConnectedStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConnectedStream")
    }
}

impl AsyncRead for ConnectedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for ConnectedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut *self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut *self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut *self.inner).poll_shutdown(context)
    }
}

#[cfg(windows)]
impl std::os::windows::io::AsRawHandle for ConnectedStream {
    fn as_raw_handle(&self) -> std::os::windows::io::RawHandle {
        self.inner.as_raw_handle()
    }
}

pub use platform::{InstanceGuard, Listener, connect};

#[cfg(windows)]
mod platform {
    use std::{
        ffi::c_void,
        mem::{replace, size_of},
        os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
        ptr::null_mut,
    };

    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};
    use windows_sys::Win32::{
        Foundation::{
            ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND,
            ERROR_PIPE_BUSY, GetLastError, HANDLE, HLOCAL, LocalFree,
        },
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                SDDL_REVISION_1,
            },
            GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
            TOKEN_USER, TokenUser,
        },
        System::Threading::{CreateMutexW, GetCurrentProcess, OpenProcessToken},
    };

    use super::{ConnectedStream, RuntimeConfig};
    use crate::IpcError;

    pub struct InstanceGuard {
        _handle: OwnedHandle,
        config: RuntimeConfig,
        listener_claimed: bool,
    }

    impl InstanceGuard {
        pub fn acquire(config: &RuntimeConfig) -> Result<Self, IpcError> {
            let sid = current_user_sid()?;
            let name = format!("Global\\ContextRelay-v1-{sid}-{}", config.suffix);
            let wide_name = wide(&name);
            let descriptor = SecurityDescriptor::for_sid(&sid)?;
            let attributes = descriptor.attributes();
            let handle = unsafe { CreateMutexW(&attributes, 0, wide_name.as_ptr()) };
            let create_error = unsafe { GetLastError() };
            if handle.is_null() {
                return Err(IpcError::Io);
            }
            let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
            if create_error == ERROR_ALREADY_EXISTS {
                drop(handle);
                return Err(IpcError::AlreadyRunning);
            }
            Ok(Self {
                _handle: handle,
                config: config.clone(),
                listener_claimed: false,
            })
        }

        fn claim_listener(&mut self, config: &RuntimeConfig) -> Result<(), IpcError> {
            if &self.config != config {
                return Err(IpcError::InvalidRuntime);
            }
            if self.listener_claimed {
                return Err(IpcError::AlreadyRunning);
            }
            self.listener_claimed = true;
            Ok(())
        }
    }

    pub struct Listener {
        endpoint: String,
        current: NamedPipeServer,
    }

    impl Listener {
        pub fn bind(
            config: &RuntimeConfig,
            instance: &mut InstanceGuard,
        ) -> Result<Self, IpcError> {
            instance.claim_listener(config)?;
            let endpoint = endpoint_name(config)?;
            let current = create_pipe(&endpoint, true)?;
            Ok(Self { endpoint, current })
        }

        pub async fn accept(&mut self) -> Result<ConnectedStream, IpcError> {
            self.current.connect().await.map_err(|_| IpcError::Io)?;
            let replacement = create_pipe(&self.endpoint, false)?;
            let connected = replace(&mut self.current, replacement);
            Ok(ConnectedStream::new(connected))
        }
    }

    pub async fn connect(config: &RuntimeConfig) -> Result<ConnectedStream, IpcError> {
        let endpoint = endpoint_name(config)?;
        ClientOptions::new()
            .open(endpoint)
            .map(ConnectedStream::new)
            .map_err(map_connect_error)
    }

    pub(super) fn endpoint_name(config: &RuntimeConfig) -> Result<String, IpcError> {
        Ok(format!(
            "\\\\.\\pipe\\context-relay-v1-{}-{}",
            current_user_sid()?,
            config.suffix
        ))
    }

    fn create_pipe(endpoint: &str, first: bool) -> Result<NamedPipeServer, IpcError> {
        let sid = current_user_sid()?;
        let descriptor = SecurityDescriptor::for_sid(&sid)?;
        let mut attributes = descriptor.attributes();
        let mut options = ServerOptions::new();
        options
            .first_pipe_instance(first)
            .reject_remote_clients(true);

        unsafe {
            options.create_with_security_attributes_raw(
                endpoint,
                (&mut attributes as *mut SECURITY_ATTRIBUTES).cast(),
            )
        }
        .map_err(|error| {
            if first
                && matches!(
                    error.raw_os_error().map(|code| code as u32),
                    Some(ERROR_ACCESS_DENIED | ERROR_PIPE_BUSY)
                )
            {
                IpcError::AlreadyRunning
            } else {
                IpcError::Io
            }
        })
    }

    fn map_connect_error(error: std::io::Error) -> IpcError {
        match error.raw_os_error().map(|code| code as u32) {
            Some(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) => IpcError::EndpointNotFound,
            _ => IpcError::Io,
        }
    }

    fn current_user_sid() -> Result<String, IpcError> {
        let mut raw_token: HANDLE = null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) } == 0 {
            return Err(IpcError::Io);
        }
        let token = unsafe { OwnedHandle::from_raw_handle(raw_token) };

        let mut required = 0_u32;
        unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                null_mut(),
                0,
                &mut required,
            );
        }
        if (required as usize) < size_of::<TOKEN_USER>() {
            return Err(IpcError::Io);
        }

        let words = (required as usize).div_ceil(size_of::<usize>());
        let mut storage = vec![0_usize; words];
        if unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                storage.as_mut_ptr().cast(),
                required,
                &mut required,
            )
        } == 0
        {
            return Err(IpcError::Io);
        }
        let sid = unsafe { (*(storage.as_ptr().cast::<TOKEN_USER>())).User.Sid };

        let mut string_sid = null_mut();
        if unsafe { ConvertSidToStringSidW(sid, &mut string_sid) } == 0 {
            return Err(IpcError::Io);
        }
        let string_sid = LocalAllocation(string_sid.cast());
        let wide_sid = string_sid.0.cast::<u16>();
        let length = (0..)
            .take_while(|&index| unsafe { *wide_sid.add(index) } != 0)
            .count();
        String::from_utf16(unsafe { std::slice::from_raw_parts(wide_sid, length) })
            .map_err(|_| IpcError::Io)
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain([0]).collect()
    }

    struct LocalAllocation(*mut c_void);

    impl Drop for LocalAllocation {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0 as HLOCAL);
            }
        }
    }

    struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

    impl SecurityDescriptor {
        fn for_sid(sid: &str) -> Result<Self, IpcError> {
            let sddl = wide(&format!("O:{sid}D:P(A;;GA;;;{sid})"));
            let mut descriptor = null_mut();
            if unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    null_mut(),
                )
            } == 0
            {
                return Err(IpcError::Io);
            }
            Ok(Self(descriptor))
        }

        fn attributes(&self) -> SECURITY_ATTRIBUTES {
            SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: self.0,
                bInheritHandle: 0,
            }
        }
    }

    impl Drop for SecurityDescriptor {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0 as HLOCAL);
            }
        }
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use std::{
        fs::{self, File, OpenOptions, TryLockError},
        io::ErrorKind,
        os::unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            net::UnixListener as StdUnixListener,
        },
        path::{Path, PathBuf},
    };

    use tokio::net::{UnixListener, UnixStream};

    use super::{ConnectedStream, RuntimeConfig};
    use crate::IpcError;

    const MAX_SOCKET_PATH_BYTES: usize = 103;

    pub struct InstanceGuard {
        _lock: File,
        config: RuntimeConfig,
        listener_claimed: bool,
    }

    impl InstanceGuard {
        pub fn acquire(config: &RuntimeConfig) -> Result<Self, IpcError> {
            let root = runtime_root(config)?;
            ensure_root(&root)?;
            let lock_path = root.join(format!("context-relay-v1-{}.lock", config.suffix));
            let lock = open_lock(&lock_path)?;
            match lock.try_lock() {
                Ok(()) => Ok(Self {
                    _lock: lock,
                    config: config.clone(),
                    listener_claimed: false,
                }),
                Err(TryLockError::WouldBlock) => Err(IpcError::AlreadyRunning),
                Err(TryLockError::Error(_)) => Err(IpcError::Io),
            }
        }

        fn claim_listener(&mut self, config: &RuntimeConfig) -> Result<(), IpcError> {
            if &self.config != config {
                return Err(IpcError::InvalidRuntime);
            }
            if self.listener_claimed {
                return Err(IpcError::AlreadyRunning);
            }
            self.listener_claimed = true;
            Ok(())
        }
    }

    pub struct Listener {
        inner: UnixListener,
        socket: SocketIdentity,
    }

    impl Listener {
        pub fn bind(
            config: &RuntimeConfig,
            instance: &mut InstanceGuard,
        ) -> Result<Self, IpcError> {
            instance.claim_listener(config)?;
            let root = runtime_root(config)?;
            let path = socket_path(config)?;
            ensure_root(&root)?;
            remove_stale_socket(&path)?;

            let listener = StdUnixListener::bind(&path).map_err(|_| IpcError::Io)?;
            if fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).is_err()
                || listener.set_nonblocking(true).is_err()
            {
                let _ = fs::remove_file(&path);
                return Err(IpcError::Io);
            }
            let metadata = fs::symlink_metadata(&path).map_err(|_| IpcError::Io)?;
            let socket = SocketIdentity {
                path,
                device: metadata.dev(),
                inode: metadata.ino(),
            };
            let inner = match UnixListener::from_std(listener) {
                Ok(inner) => inner,
                Err(_) => {
                    socket.remove_if_same();
                    return Err(IpcError::Io);
                }
            };
            Ok(Self { inner, socket })
        }

        pub async fn accept(&mut self) -> Result<ConnectedStream, IpcError> {
            self.inner
                .accept()
                .await
                .map(|(stream, _)| ConnectedStream::new(stream))
                .map_err(|_| IpcError::Io)
        }
    }

    impl Drop for Listener {
        fn drop(&mut self) {
            self.socket.remove_if_same();
        }
    }

    pub async fn connect(config: &RuntimeConfig) -> Result<ConnectedStream, IpcError> {
        UnixStream::connect(socket_path(config)?)
            .await
            .map(ConnectedStream::new)
            .map_err(|error| {
                if matches!(
                    error.kind(),
                    ErrorKind::NotFound | ErrorKind::ConnectionRefused
                ) {
                    IpcError::EndpointNotFound
                } else {
                    IpcError::Io
                }
            })
    }

    pub(super) fn endpoint_name(config: &RuntimeConfig) -> Result<String, IpcError> {
        socket_path(config)?
            .into_os_string()
            .into_string()
            .map_err(|_| IpcError::InvalidRuntime)
    }

    fn runtime_root(config: &RuntimeConfig) -> Result<PathBuf, IpcError> {
        let root = match &config.runtime_root {
            Some(root) => root.clone(),
            None => dirs::cache_dir()
                .ok_or(IpcError::InvalidRuntime)?
                .join("context-relay"),
        };
        if !root.is_absolute() {
            return Err(IpcError::InvalidRuntime);
        }
        Ok(root)
    }

    fn socket_path(config: &RuntimeConfig) -> Result<PathBuf, IpcError> {
        let path = runtime_root(config)?.join(format!("context-relay-v1-{}.sock", config.suffix));
        if path.as_os_str().as_bytes().len() > MAX_SOCKET_PATH_BYTES {
            return Err(IpcError::InvalidRuntime);
        }
        Ok(path)
    }

    fn ensure_root(root: &Path) -> Result<(), IpcError> {
        match fs::symlink_metadata(root) {
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {
                match fs::DirBuilder::new().mode(0o700).create(root) {
                    Ok(()) => {}
                    Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
                    Err(_) => return Err(IpcError::Io),
                }
            }
            Err(_) => return Err(IpcError::Io),
        }

        let metadata = fs::symlink_metadata(root).map_err(|_| IpcError::Io)?;
        if !metadata.file_type().is_dir() || metadata.permissions().mode() & 0o777 != 0o700 {
            return Err(IpcError::InvalidRuntime);
        }
        Ok(())
    }

    fn open_lock(path: &Path) -> Result<File, IpcError> {
        if let Ok(metadata) = fs::symlink_metadata(path) {
            validate_lock_metadata(&metadata)?;
        }
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .map_err(|_| IpcError::Io)?;
        let path_metadata = fs::symlink_metadata(path).map_err(|_| IpcError::Io)?;
        let file_metadata = lock.metadata().map_err(|_| IpcError::Io)?;
        validate_lock_metadata(&path_metadata)?;
        if (path_metadata.dev(), path_metadata.ino()) != (file_metadata.dev(), file_metadata.ino())
        {
            return Err(IpcError::InvalidRuntime);
        }
        Ok(lock)
    }

    fn validate_lock_metadata(metadata: &fs::Metadata) -> Result<(), IpcError> {
        if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(IpcError::InvalidRuntime);
        }
        Ok(())
    }

    fn remove_stale_socket(path: &Path) -> Result<(), IpcError> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_socket() => {
                fs::remove_file(path).map_err(|_| IpcError::Io)
            }
            Ok(_) => Err(IpcError::InvalidRuntime),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(_) => Err(IpcError::Io),
        }
    }

    struct SocketIdentity {
        path: PathBuf,
        device: u64,
        inode: u64,
    }

    impl SocketIdentity {
        fn remove_if_same(&self) {
            if let Ok(metadata) = fs::symlink_metadata(&self.path)
                && metadata.file_type().is_socket()
                && (metadata.dev(), metadata.ino()) == (self.device, self.inode)
            {
                let _ = fs::remove_file(&self.path);
            }
        }
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
mod platform {
    use super::{ConnectedStream, RuntimeConfig};
    use crate::IpcError;

    pub struct InstanceGuard;

    impl InstanceGuard {
        pub fn acquire(_config: &RuntimeConfig) -> Result<Self, IpcError> {
            Err(IpcError::UnsupportedPlatform)
        }
    }

    pub struct Listener;

    impl Listener {
        pub fn bind(
            _config: &RuntimeConfig,
            _instance: &mut InstanceGuard,
        ) -> Result<Self, IpcError> {
            Err(IpcError::UnsupportedPlatform)
        }

        pub async fn accept(&mut self) -> Result<ConnectedStream, IpcError> {
            Err(IpcError::UnsupportedPlatform)
        }
    }

    pub async fn connect(_config: &RuntimeConfig) -> Result<ConnectedStream, IpcError> {
        Err(IpcError::UnsupportedPlatform)
    }

    pub(super) fn endpoint_name(_config: &RuntimeConfig) -> Result<String, IpcError> {
        Err(IpcError::UnsupportedPlatform)
    }
}
