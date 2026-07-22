use std::{
    ffi::{CStr, CString, OsStr, c_void},
    fs::File,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, process::ExitStatusExt},
    },
    path::{Path, PathBuf},
    process::ExitStatus,
    ptr,
};

use core_foundation::{base::TCFType, url::CFURL};
use core_foundation_sys::{
    base::{CFGetTypeID, CFRelease, CFTypeRef, OSStatus},
    data::{CFDataGetBytePtr, CFDataGetLength, CFDataGetTypeID},
    dictionary::{CFDictionaryGetValue, CFDictionaryRef},
    string::CFStringRef,
};
use security_framework::os::macos::code_signing::{
    Flags, GuestAttributes, SecCode, SecRequirement, SecStaticCode,
};

use crate::macos::{MacCodeIdentity, MacPolicyError};

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecCodeInfoUnique: CFStringRef;
    fn SecCodeCopySigningInformation(
        code: *mut c_void,
        flags: u32,
        information: *mut CFDictionaryRef,
    ) -> OSStatus;
}

unsafe extern "C" {
    fn posix_spawn_file_actions_addchdir_np(
        actions: *mut libc::posix_spawn_file_actions_t,
        path: *const libc::c_char,
    ) -> libc::c_int;
}

pub struct MacChild {
    pid: libc::pid_t,
    stdin: Option<File>,
    stdout: Option<File>,
    stderr: Option<File>,
    suspended: bool,
    reaped: bool,
}

pub struct MacProcessGuardian {
    pid: libc::pid_t,
    lease: Option<File>,
    reaped: bool,
}

impl MacProcessGuardian {
    pub fn start(lease_directory: &File, lease_name: &CStr) -> Result<Self, MacPolicyError> {
        Self::start_with_lease_open_hook(lease_directory, lease_name, || {})
    }

    #[doc(hidden)]
    pub fn start_with_lease_open_hook(
        lease_directory: &File,
        lease_name: &CStr,
        hook: impl FnOnce(),
    ) -> Result<Self, MacPolicyError> {
        let (lease, guardian_wait) = guardian_lease(lease_directory, lease_name, hook)
            .inspect_err(|_error| {
                #[cfg(debug_assertions)]
                eprintln!("macOS guardian startup failed at lease creation: {_error:?}");
            })?;
        let guardian_wait_fd = guardian_wait.as_raw_fd();
        let descriptor_limit =
            guardian_descriptor_limit([lease.as_raw_fd(), guardian_wait.as_raw_fd()]).inspect_err(
                |_error| {
                    #[cfg(debug_assertions)]
                    eprintln!("macOS guardian startup failed at descriptor census: {_error:?}");
                },
            )?;

        let mut blocked_signals = std::mem::MaybeUninit::<libc::sigset_t>::zeroed();
        let mut previous_signals = std::mem::MaybeUninit::<libc::sigset_t>::zeroed();
        if unsafe { libc::sigfillset(blocked_signals.as_mut_ptr()) } != 0
            || unsafe {
                libc::pthread_sigmask(
                    libc::SIG_BLOCK,
                    blocked_signals.as_ptr(),
                    previous_signals.as_mut_ptr(),
                )
            } != 0
        {
            #[cfg(debug_assertions)]
            eprintln!("macOS guardian startup failed while blocking signals");
            return Err(MacPolicyError::ProcessFailed);
        }
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            guardian_child(guardian_wait_fd, descriptor_limit);
        }
        let restored = unsafe {
            libc::pthread_sigmask(
                libc::SIG_SETMASK,
                previous_signals.as_ptr(),
                ptr::null_mut(),
            )
        } == 0;
        if pid == -1 || !restored {
            #[cfg(debug_assertions)]
            if pid == -1 {
                eprintln!(
                    "macOS guardian startup failed while forking: {:?}",
                    std::io::Error::last_os_error()
                );
            } else {
                eprintln!("macOS guardian startup failed while restoring signals");
            }
            if pid > 0 {
                kill_and_reap_exact(pid);
            }
            return Err(MacPolicyError::ProcessFailed);
        }
        drop(guardian_wait);
        let mut guardian = Self {
            pid,
            lease: Some(lease),
            reaped: false,
        };
        if let Err(_error) = wait_guardian_ready(&mut guardian) {
            #[cfg(debug_assertions)]
            eprintln!("macOS guardian startup failed at readiness: {_error:?}");
            let _ = guardian.kill_group_and_reap();
            return Err(MacPolicyError::ProcessFailed);
        }
        Ok(guardian)
    }

    pub const fn pgid(&self) -> libc::pid_t {
        self.pid
    }

    pub fn ensure_alive(&mut self) -> Result<(), MacPolicyError> {
        if self.reaped {
            return Err(MacPolicyError::ProcessFailed);
        }
        let mut status = 0;
        let result = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
        if result == 0 {
            return Ok(());
        }
        if result == self.pid {
            self.reaped = true;
            #[cfg(debug_assertions)]
            eprintln!("macOS guardian exited unexpectedly with wait status {status}");
        }
        Err(MacPolicyError::ProcessFailed)
    }

    pub fn kill_group_and_reap(&mut self) -> Result<(), MacPolicyError> {
        if self.reaped {
            return Ok(());
        }
        let kill_result = unsafe { libc::kill(-self.pid, libc::SIGKILL) };
        self.lease.take();
        let kill_failed =
            kill_result != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH);
        let mut status = 0;
        loop {
            let result = unsafe { libc::waitpid(self.pid, &mut status, 0) };
            if result == self.pid {
                self.reaped = true;
                return if kill_failed {
                    Err(MacPolicyError::ProcessFailed)
                } else {
                    Ok(())
                };
            }
            if result != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                return Err(MacPolicyError::ProcessFailed);
            }
        }
    }
}

fn guardian_lease(
    directory: &File,
    name: &CStr,
    hook: impl FnOnce(),
) -> Result<(File, File), MacPolicyError> {
    let owner_descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if owner_descriptor == -1 {
        return Err(MacPolicyError::ProcessFailed);
    }
    let owner = unsafe { File::from_raw_fd(owner_descriptor) };
    hook();
    let wait_descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if wait_descriptor == -1 {
        unsafe {
            libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0);
        }
        return Err(MacPolicyError::ProcessFailed);
    }
    let guardian_wait = unsafe { File::from_raw_fd(wait_descriptor) };
    if unsafe { libc::flock(owner.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0
        || unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } != 0
    {
        unsafe {
            libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0);
        }
        return Err(MacPolicyError::ProcessFailed);
    }
    Ok((owner, guardian_wait))
}

fn guardian_descriptor_limit<const N: usize>(
    new_descriptors: [libc::c_int; N],
) -> Result<libc::c_int, MacPolicyError> {
    const MAX_GUARDIAN_DESCRIPTORS: u64 = 1_000_000;

    let mut limit = std::mem::MaybeUninit::<libc::rlimit>::zeroed();
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) } != 0 {
        return Err(MacPolicyError::ProcessFailed);
    }
    let limit = unsafe { limit.assume_init() };
    let hard_limit = limit.rlim_max;
    let allocation_limit = if hard_limit == libc::RLIM_INFINITY {
        limit.rlim_cur
    } else {
        hard_limit
    };
    if allocation_limit == libc::RLIM_INFINITY
        || allocation_limit < limit.rlim_cur
        || allocation_limit > MAX_GUARDIAN_DESCRIPTORS
    {
        return Err(MacPolicyError::ProcessFailed);
    }

    // The finite hard limit closes the race with other threads: any descriptor opened between
    // this snapshot and fork must be below it. macOS can report an infinite hard limit alongside
    // a finite soft allocation limit, so use that kernel-enforced ceiling instead. A process can
    // retain descriptors above its current allocation limit, and the /dev/fd snapshot extends the
    // close ceiling over those as well.
    let highest_open = std::fs::read_dir("/dev/fd")
        .map_err(|_| MacPolicyError::ProcessFailed)?
        .try_fold(0_u64, |highest, entry| {
            let entry = entry.map_err(|_| MacPolicyError::ProcessFailed)?;
            let descriptor = entry
                .file_name()
                .to_string_lossy()
                .parse::<u64>()
                .map_err(|_| MacPolicyError::ProcessFailed)?;
            Ok::<_, MacPolicyError>(highest.max(descriptor))
        })?;
    let highest_new = new_descriptors
        .into_iter()
        .map(|descriptor| u64::try_from(descriptor).map_err(|_| MacPolicyError::ProcessFailed))
        .try_fold(0_u64, |highest, descriptor| {
            descriptor.map(|value| highest.max(value))
        })?;
    let descriptor_limit = allocation_limit
        .max(highest_open.saturating_add(1))
        .max(highest_new.saturating_add(1));
    if descriptor_limit > MAX_GUARDIAN_DESCRIPTORS {
        return Err(MacPolicyError::ProcessFailed);
    }
    libc::c_int::try_from(descriptor_limit).map_err(|_| MacPolicyError::ProcessFailed)
}

fn kill_and_reap_exact(pid: libc::pid_t) {
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
    let mut status = 0;
    loop {
        let result = unsafe { libc::waitpid(pid, &mut status, 0) };
        if result == pid
            || result == -1 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
        {
            return;
        }
    }
}

impl Drop for MacProcessGuardian {
    fn drop(&mut self) {
        let _ = self.kill_group_and_reap();
    }
}

impl MacChild {
    pub const fn pid(&self) -> libc::pid_t {
        self.pid
    }

    pub fn take_stdin(&mut self) -> Option<File> {
        self.stdin.take()
    }

    pub fn take_stdout(&mut self) -> Option<File> {
        self.stdout.take()
    }

    pub fn take_stderr(&mut self) -> Option<File> {
        self.stderr.take()
    }

    pub fn resume(&mut self) -> Result<(), MacPolicyError> {
        if !self.suspended || self.reaped {
            return Err(MacPolicyError::InvalidTransition);
        }
        if unsafe { libc::kill(self.pid, libc::SIGCONT) } != 0 {
            return Err(MacPolicyError::ProcessFailed);
        }
        self.suspended = false;
        Ok(())
    }

    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, MacPolicyError> {
        if self.reaped {
            return Err(MacPolicyError::InvalidTransition);
        }
        let mut status = 0;
        let result = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
        if result == 0 {
            return Ok(None);
        }
        if result != self.pid {
            return Err(MacPolicyError::ProcessFailed);
        }
        self.reaped = true;
        Ok(Some(ExitStatus::from_raw(status)))
    }

    pub fn wait(&mut self) -> Result<ExitStatus, MacPolicyError> {
        if self.reaped {
            return Err(MacPolicyError::InvalidTransition);
        }
        let mut status = 0;
        loop {
            let result = unsafe { libc::waitpid(self.pid, &mut status, 0) };
            if result == self.pid {
                self.reaped = true;
                return Ok(ExitStatus::from_raw(status));
            }
            if result != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                return Err(MacPolicyError::ProcessFailed);
            }
        }
    }

    pub fn kill(&self) -> Result<(), MacPolicyError> {
        if unsafe { libc::kill(self.pid, libc::SIGKILL) } == 0 {
            Ok(())
        } else {
            Err(MacPolicyError::ProcessFailed)
        }
    }

    fn kill_and_reap(&mut self) {
        if self.reaped {
            return;
        }
        unsafe {
            libc::kill(self.pid, libc::SIGKILL);
        }
        let _ = self.wait();
    }
}

impl Drop for MacChild {
    fn drop(&mut self) {
        self.kill_and_reap();
    }
}

pub fn capture_code_identity(file: &File) -> Result<MacCodeIdentity, MacPolicyError> {
    let path = PathBuf::from(format!("/dev/fd/{}", file.as_raw_fd()));
    let url = CFURL::from_path(path, false).ok_or(MacPolicyError::IdentityMismatch)?;
    let code = SecStaticCode::from_path(&url, Flags::NONE)
        .map_err(|_| MacPolicyError::IdentityMismatch)?;
    validate_static_code(&code)?;
    signing_identity(code.as_concrete_TypeRef().cast())
}

#[allow(clippy::too_many_arguments)]
pub fn spawn_suspended_verified(
    program: &Path,
    arguments: &[&OsStr],
    environment: &[(&OsStr, &OsStr)],
    current_dir: Option<&Path>,
    process_group: Option<libc::pid_t>,
    expected: &MacCodeIdentity,
) -> Result<MacChild, MacPolicyError> {
    if !program.is_absolute() || current_dir.is_some_and(|path| !path.is_absolute()) {
        return Err(MacPolicyError::InvalidConfiguration);
    }
    let program = c_string(program.as_os_str())?;
    let current_dir = current_dir
        .map(|path| c_string(path.as_os_str()))
        .transpose()?;
    let mut argv = Vec::with_capacity(arguments.len() + 1);
    argv.push(program.clone());
    for argument in arguments {
        argv.push(c_string(argument)?);
    }
    let mut envp = Vec::with_capacity(environment.len());
    for (name, value) in environment {
        if name.is_empty() || name.as_bytes().contains(&b'=') {
            return Err(MacPolicyError::InvalidConfiguration);
        }
        let mut entry = name.as_bytes().to_vec();
        entry.push(b'=');
        entry.extend_from_slice(value.as_bytes());
        envp.push(CString::new(entry).map_err(|_| MacPolicyError::InvalidConfiguration)?);
    }
    let mut argv_pointers = argv
        .iter()
        .map(|value| value.as_ptr().cast_mut())
        .collect::<Vec<_>>();
    argv_pointers.push(ptr::null_mut());
    let mut envp_pointers = envp
        .iter()
        .map(|value| value.as_ptr().cast_mut())
        .collect::<Vec<_>>();
    envp_pointers.push(ptr::null_mut());

    let stdin = pipe()?;
    let stdout = pipe()?;
    let stderr = pipe()?;
    let mut actions = SpawnActions::new()?;
    actions.dup2(stdin.read.as_raw_fd(), libc::STDIN_FILENO)?;
    actions.dup2(stdout.write.as_raw_fd(), libc::STDOUT_FILENO)?;
    actions.dup2(stderr.write.as_raw_fd(), libc::STDERR_FILENO)?;
    for fd in [
        stdin.read.as_raw_fd(),
        stdin.write.as_raw_fd(),
        stdout.read.as_raw_fd(),
        stdout.write.as_raw_fd(),
        stderr.read.as_raw_fd(),
        stderr.write.as_raw_fd(),
    ] {
        if !matches!(
            fd,
            libc::STDIN_FILENO | libc::STDOUT_FILENO | libc::STDERR_FILENO
        ) {
            actions.close(fd)?;
        }
    }
    if let Some(directory) = &current_dir {
        actions.chdir(directory)?;
    }
    let attributes = SpawnAttributes::new(process_group)?;
    let mut pid = 0;
    let status = unsafe {
        libc::posix_spawn(
            &mut pid,
            program.as_ptr(),
            &actions.0,
            &attributes.0,
            argv_pointers.as_ptr(),
            envp_pointers.as_ptr(),
        )
    };
    if status != 0 || pid <= 0 {
        return Err(MacPolicyError::ProcessFailed);
    }
    drop(attributes);
    drop(actions);
    drop(stdin.read);
    drop(stdout.write);
    drop(stderr.write);

    let mut child = MacChild {
        pid,
        stdin: Some(stdin.write),
        stdout: Some(stdout.read),
        stderr: Some(stderr.read),
        suspended: true,
        reaped: false,
    };
    let identity = wait_for_dynamic_code_identity(pid, expected, dynamic_code_identity);
    let expected_pgid = process_group.map(|pgid| if pgid == 0 { pid } else { pgid });
    if let Err(error) = identity {
        child.kill_and_reap();
        return Err(error);
    }
    if expected_pgid.is_some_and(|pgid| unsafe { libc::getpgid(pid) } != pgid) {
        child.kill_and_reap();
        return Err(MacPolicyError::IdentityMismatch);
    }
    Ok(child)
}

fn wait_for_dynamic_code_identity(
    pid: libc::pid_t,
    expected: &MacCodeIdentity,
    mut inspect: impl FnMut(libc::pid_t) -> Result<MacCodeIdentity, MacPolicyError>,
) -> Result<(), MacPolicyError> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        match inspect(pid) {
            Ok(actual) if &actual == expected => return Ok(()),
            Ok(_) => return Err(MacPolicyError::IdentityMismatch),
            Err(MacPolicyError::IdentityMismatch) if std::time::Instant::now() < deadline => {
                if unsafe { libc::kill(pid, 0) } != 0 {
                    return Err(MacPolicyError::IdentityMismatch);
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    }
}

fn dynamic_code_identity(pid: libc::pid_t) -> Result<MacCodeIdentity, MacPolicyError> {
    let mut attributes = GuestAttributes::new();
    attributes.set_pid(pid);
    let code = SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE)
        .map_err(|_| MacPolicyError::IdentityMismatch)?;
    let requirement: SecRequirement = "true"
        .parse()
        .map_err(|_| MacPolicyError::IdentityMismatch)?;
    code.check_validity(
        Flags::STRICT_VALIDATE | Flags::NO_NETWORK_ACCESS,
        &requirement,
    )
    .map_err(|_| MacPolicyError::IdentityMismatch)?;
    signing_identity(code.as_concrete_TypeRef().cast())
}

fn validate_static_code(code: &SecStaticCode) -> Result<(), MacPolicyError> {
    let requirement: SecRequirement = "true"
        .parse()
        .map_err(|_| MacPolicyError::IdentityMismatch)?;
    code.check_validity(
        Flags::STRICT_VALIDATE | Flags::NO_NETWORK_ACCESS,
        &requirement,
    )
    .map_err(|_| MacPolicyError::IdentityMismatch)
}

fn signing_identity(code: *mut c_void) -> Result<MacCodeIdentity, MacPolicyError> {
    let mut information = ptr::null();
    if unsafe { SecCodeCopySigningInformation(code, 0, &mut information) } != 0
        || information.is_null()
    {
        return Err(MacPolicyError::IdentityMismatch);
    }
    let _information = OwnedCf(information.cast());
    let value = unsafe {
        CFDictionaryGetValue(information, kSecCodeInfoUnique.cast::<c_void>()).cast::<c_void>()
    };
    if value.is_null() || unsafe { CFGetTypeID(value) } != unsafe { CFDataGetTypeID() } {
        return Err(MacPolicyError::IdentityMismatch);
    }
    let data = value.cast_mut().cast();
    let length = unsafe { CFDataGetLength(data) };
    let length = usize::try_from(length).map_err(|_| MacPolicyError::IdentityMismatch)?;
    let bytes = unsafe { CFDataGetBytePtr(data) };
    if bytes.is_null() {
        return Err(MacPolicyError::IdentityMismatch);
    }
    MacCodeIdentity::new(unsafe { std::slice::from_raw_parts(bytes, length) }.to_vec())
}

fn c_string(value: &OsStr) -> Result<CString, MacPolicyError> {
    CString::new(value.as_bytes()).map_err(|_| MacPolicyError::InvalidConfiguration)
}

struct OwnedCf(CFTypeRef);

impl Drop for OwnedCf {
    fn drop(&mut self) {
        unsafe { CFRelease(self.0) };
    }
}

struct Pipe {
    read: File,
    write: File,
}

fn pipe() -> Result<Pipe, MacPolicyError> {
    let mut descriptors = [0; 2];
    if unsafe { libc::pipe(descriptors.as_mut_ptr()) } != 0 {
        return Err(MacPolicyError::ProcessFailed);
    }
    let read = unsafe { File::from_raw_fd(descriptors[0]) };
    let write = unsafe { File::from_raw_fd(descriptors[1]) };
    for file in [&read, &write] {
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
            return Err(MacPolicyError::ProcessFailed);
        }
    }
    Ok(Pipe { read, write })
}

fn wait_guardian_ready(guardian: &mut MacProcessGuardian) -> Result<(), MacPolicyError> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        guardian.ensure_alive()?;
        if unsafe { libc::getpgid(guardian.pid) } == guardian.pid {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(MacPolicyError::ProcessFailed);
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

fn guardian_child(wait_source: libc::c_int, descriptor_limit: libc::c_int) -> ! {
    const LEASE_FD: libc::c_int = 3;
    unsafe {
        let lease_copy = libc::fcntl(wait_source, libc::F_DUPFD, 4);
        if lease_copy == -1 || libc::dup2(lease_copy, LEASE_FD) == -1 {
            libc::_exit(126);
        }
        let close_limit = descriptor_limit.max(lease_copy + 1);
        for descriptor in 0..close_limit {
            if descriptor != LEASE_FD {
                libc::close(descriptor);
            }
        }
        if libc::setpgid(0, 0) != 0 {
            libc::_exit(126);
        }
        loop {
            if libc::flock(LEASE_FD, libc::LOCK_EX) == 0 {
                break;
            }
            if *libc::__error() != libc::EINTR {
                libc::kill(0, libc::SIGKILL);
                libc::_exit(126);
            }
        }
        libc::kill(0, libc::SIGKILL);
        libc::_exit(127);
    }
}

struct SpawnActions(libc::posix_spawn_file_actions_t);

impl SpawnActions {
    fn new() -> Result<Self, MacPolicyError> {
        let mut actions = ptr::null_mut();
        (unsafe { libc::posix_spawn_file_actions_init(&mut actions) } == 0)
            .then_some(Self(actions))
            .ok_or(MacPolicyError::ProcessFailed)
    }

    fn dup2(&mut self, from: libc::c_int, to: libc::c_int) -> Result<(), MacPolicyError> {
        (unsafe { libc::posix_spawn_file_actions_adddup2(&mut self.0, from, to) } == 0)
            .then_some(())
            .ok_or(MacPolicyError::ProcessFailed)
    }

    fn close(&mut self, fd: libc::c_int) -> Result<(), MacPolicyError> {
        (unsafe { libc::posix_spawn_file_actions_addclose(&mut self.0, fd) } == 0)
            .then_some(())
            .ok_or(MacPolicyError::ProcessFailed)
    }

    fn chdir(&mut self, path: &CString) -> Result<(), MacPolicyError> {
        (unsafe { posix_spawn_file_actions_addchdir_np(&mut self.0, path.as_ptr()) } == 0)
            .then_some(())
            .ok_or(MacPolicyError::ProcessFailed)
    }
}

impl Drop for SpawnActions {
    fn drop(&mut self) {
        unsafe {
            libc::posix_spawn_file_actions_destroy(&mut self.0);
        }
    }
}

struct SpawnAttributes(libc::posix_spawnattr_t);

impl SpawnAttributes {
    fn new(process_group: Option<libc::pid_t>) -> Result<Self, MacPolicyError> {
        let mut attributes = ptr::null_mut();
        if unsafe { libc::posix_spawnattr_init(&mut attributes) } != 0 {
            return Err(MacPolicyError::ProcessFailed);
        }
        let mut value = Self(attributes);
        if let Some(process_group) = process_group
            && (process_group < 0
                || unsafe { libc::posix_spawnattr_setpgroup(&mut value.0, process_group) } != 0)
        {
            return Err(MacPolicyError::ProcessFailed);
        }
        let flags = libc::POSIX_SPAWN_START_SUSPENDED
            | libc::POSIX_SPAWN_CLOEXEC_DEFAULT
            | if process_group.is_some() {
                libc::POSIX_SPAWN_SETPGROUP
            } else {
                0
            };
        let flags = libc::c_short::try_from(flags).map_err(|_| MacPolicyError::ProcessFailed)?;
        if unsafe { libc::posix_spawnattr_setflags(&mut value.0, flags) } != 0 {
            return Err(MacPolicyError::ProcessFailed);
        }
        Ok(value)
    }
}

impl Drop for SpawnAttributes {
    fn drop(&mut self) {
        unsafe {
            libc::posix_spawnattr_destroy(&mut self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dynamic_code_identity_retries_transient_guest_registration() {
        let expected = MacCodeIdentity::new(vec![0x11]).unwrap();
        let mut attempts = 0;

        wait_for_dynamic_code_identity(unsafe { libc::getpid() }, &expected, |_| {
            attempts += 1;
            if attempts < 3 {
                Err(MacPolicyError::IdentityMismatch)
            } else {
                Ok(expected.clone())
            }
        })
        .unwrap();

        assert_eq!(attempts, 3);
    }

    #[test]
    fn dynamic_code_identity_rejects_an_observed_mismatch_without_retrying() {
        let expected = MacCodeIdentity::new(vec![0x11]).unwrap();
        let mut attempts = 0;

        assert_eq!(
            wait_for_dynamic_code_identity(unsafe { libc::getpid() }, &expected, |_| {
                attempts += 1;
                Ok(MacCodeIdentity::new(vec![0x22]).unwrap())
            }),
            Err(MacPolicyError::IdentityMismatch)
        );
        assert_eq!(attempts, 1);
    }
}
