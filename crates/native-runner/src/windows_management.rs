//! Closed Hermes Python management commands with owned Windows process cleanup.
//! This provides process-tree lifetime control, not an OS sandbox or approval.

use crate::windows::{ProcThreadAttributes, create_verified_kill_job};
use rand_core::{OsRng, RngCore as _};
use std::{
    any::Any,
    ffi::{OsStr, OsString},
    mem::size_of,
    os::windows::{
        ffi::OsStrExt as _,
        io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle},
    },
    path::{Path, PathBuf},
    ptr::{null, null_mut},
    sync::{
        Mutex, TryLockError,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{
        ERROR_BROKEN_PIPE, ERROR_IO_INCOMPLETE, ERROR_IO_PENDING, ERROR_OPERATION_ABORTED,
        GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
    },
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{
        CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING, PIPE_ACCESS_INBOUND, ReadFile,
    },
    System::{
        IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
        JobObjects::{
            AssignProcessToJobObject, IsProcessInJob, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicAccountingInformation,
            JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
            TerminateJobObject,
        },
        Pipes::{CreateNamedPipeW, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT},
        Threading::{
            CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateEventW,
            CreateProcessW, EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION, ResetEvent, ResumeThread,
            STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess, WaitForSingleObject,
        },
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HermesManagementCommand {
    Version,
    ConfigCheck,
}

#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum ManagementError {
    #[error("the management command could not be prepared or launched")]
    Launch,
    #[error("a harness check is already running")]
    Busy,
    #[error("the harness check timed out")]
    Timeout,
    #[error("the harness check was cancelled")]
    Cancelled,
    #[error("the harness check produced too much output")]
    OutputLimit,
    #[error("the harness check output could not be read")]
    Io,
    #[error("process cleanup is still pending; the runtime remains locked")]
    CleanupPending,
}

#[derive(Debug)]
pub struct ManagementOutput {
    pub exit_code: u32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// The caller must approve the runtime and own its verified byte locks in owner.
/// The owner is returned only after the job is empty and pipe I/O has completed.
/// Errors after launch retain it if cleanup cannot be proved. Home must be a
/// caller-prepared isolated profile; no ambient credentials are inherited.
pub fn run_hermes_python<G: Send + 'static>(
    root: &Path,
    home: &Path,
    command: HermesManagementCommand,
    owner: G,
    cancelled: &AtomicBool,
) -> Result<(ManagementOutput, G), ManagementError> {
    if !root.is_absolute() || !home.is_absolute() {
        return Err(ManagementError::Launch);
    }
    let system_root = crate::environment::windows_directory().ok_or(ManagementError::Launch)?;
    let system_path = Path::new(&system_root).join("System32");
    let mut args = vec![
        "-I".into(),
        "-S".into(),
        "-B".into(),
        root.join("bootstrap.py").into_os_string(),
    ];
    match command {
        HermesManagementCommand::Version => args.push("--version".into()),
        HermesManagementCommand::ConfigCheck => args.extend(["config".into(), "check".into()]),
    }
    let mut environment = [
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "HERMES_HOME",
        "TEMP",
        "TMP",
    ]
    .into_iter()
    .map(|key| (key.into(), home.as_os_str().to_owned()))
    .collect::<Vec<_>>();
    environment.extend([
        ("SystemRoot".into(), system_root),
        ("PATH".into(), system_path.into_os_string()),
        ("NO_COLOR".into(), "1".into()),
        ("TERM".into(), "dumb".into()),
    ]);
    run_process(
        ProcessSpec {
            executable: root.join("python/python.exe"),
            args,
            directory: home.to_owned(),
            environment,
        },
        owner,
        cancelled,
        Limits {
            runtime: Duration::from_secs(15),
            cleanup: Duration::from_secs(3),
            output: 256 * 1024,
        },
        Faults::default(),
    )
}

struct ProcessSpec {
    executable: PathBuf,
    args: Vec<OsString>,
    directory: PathBuf,
    environment: Vec<(OsString, OsString)>,
}
#[derive(Clone, Copy)]
struct Limits {
    runtime: Duration,
    cleanup: Duration,
    output: usize,
}
#[derive(Default)]
struct Faults {
    #[cfg(test)]
    assignment: bool,
    #[cfg(test)]
    resume: bool,
    #[cfg(test)]
    cleanup: bool,
    #[cfg(test)]
    defer_output: bool,
    #[cfg(test)]
    unwind: bool,
}

// A single retained slot bounds exceptional cleanup state. It also serializes
// launch. State is installed BEFORE CreateProcess; even unwinding leaves all
// kernel-referenced buffers and runtime ownership here. A subsequent call reaps
// it before launching anything else. Static values are not dropped at shutdown.
static PROCESS: Mutex<Option<ProcessState>> = Mutex::new(None);

fn run_process<G: Send + 'static>(
    spec: ProcessSpec,
    owner: G,
    cancelled: &AtomicBool,
    limits: Limits,
    faults: Faults,
) -> Result<(ManagementOutput, G), ManagementError> {
    let mut slot = match PROCESS.try_lock() {
        Ok(slot) => slot,
        Err(TryLockError::Poisoned(error)) => error.into_inner(),
        Err(TryLockError::WouldBlock) => return Err(ManagementError::Busy),
    };
    if let Some(previous) = slot.as_mut() {
        previous.cleanup(false, limits)?;
        slot.take();
    }
    PROCESS.clear_poison();
    if cancelled.load(Ordering::Acquire) {
        return Err(ManagementError::Cancelled);
    }
    let (state, child_stdout, child_stderr, child_stdin) =
        ProcessState::prepare(Box::new(owner), faults)?;
    *slot = Some(state);
    let state = slot.as_mut().ok_or(ManagementError::Launch)?;
    let launched = state.launch(
        spec,
        [raw(&child_stdin), raw(&child_stdout), raw(&child_stderr)],
    );
    drop((child_stdout, child_stderr, child_stdin));
    let result = launched.and_then(|()| state.collect(cancelled, limits));
    state.cleanup(result.is_ok(), limits)?;
    let mut state = slot.take().ok_or(ManagementError::Launch)?;
    let code = result?;
    if let Some(error) = state.stdout.final_error.take() {
        return Err(error);
    }
    let owner = state
        .owner
        .take()
        .ok_or(ManagementError::Launch)?
        .downcast::<G>()
        .map_err(|_| ManagementError::Launch)?;
    Ok((
        ManagementOutput {
            exit_code: code,
            stdout: std::mem::take(&mut state.stdout.output),
            stderr: std::mem::take(&mut state.stderr.output),
        },
        *owner,
    ))
}

struct ProcessState {
    owner: Option<Box<dyn Any + Send>>,
    job: OwnedHandle,
    process: Option<OwnedHandle>,
    thread: Option<OwnedHandle>,
    assigned: bool,
    stdout: OutputPipe,
    stderr: OutputPipe,
    #[cfg(test)]
    faults: Faults,
}

impl ProcessState {
    fn prepare(
        owner: Box<dyn Any + Send>,
        _faults: Faults,
    ) -> Result<(Self, OwnedHandle, OwnedHandle, OwnedHandle), ManagementError> {
        let job = create_verified_kill_job().map_err(|_| ManagementError::Launch)?;
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        limits.BasicLimitInformation.ActiveProcessLimit = 16;
        if unsafe {
            SetInformationJobObject(
                raw(&job),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            return Err(ManagementError::Launch);
        }
        let (stdout, child_stdout) = OutputPipe::new()?;
        let (stderr, child_stderr) = OutputPipe::new()?;
        let attributes = inheritable();
        let child_stdin = owned(unsafe {
            CreateFileW(
                wide(OsStr::new("NUL"))?.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                &attributes,
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        })?;
        Ok((
            Self {
                owner: Some(owner),
                job,
                process: None,
                thread: None,
                assigned: false,
                stdout,
                stderr,
                #[cfg(test)]
                faults: _faults,
            },
            child_stdout,
            child_stderr,
            child_stdin,
        ))
    }

    fn launch(&mut self, spec: ProcessSpec, handles: [HANDLE; 3]) -> Result<(), ManagementError> {
        let attributes = ProcThreadAttributes::new(1).map_err(|_| ManagementError::Launch)?;
        attributes
            .update(
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr().cast(),
                size_of::<[HANDLE; 3]>(),
            )
            .map_err(|_| ManagementError::Launch)?;
        let application = wide(spec.executable.as_os_str())?;
        let directory = wide(spec.directory.as_os_str())?;
        let mut command = command_line(spec.executable.as_os_str(), &spec.args)?;
        let environment = environment_block(spec.environment)?;
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = handles[0];
        startup.StartupInfo.hStdOutput = handles[1];
        startup.StartupInfo.hStdError = handles[2];
        startup.lpAttributeList = attributes.list;
        let mut information = PROCESS_INFORMATION::default();
        if unsafe {
            CreateProcessW(
                application.as_ptr(),
                command.as_mut_ptr(),
                null(),
                null(),
                1,
                CREATE_SUSPENDED
                    | CREATE_NO_WINDOW
                    | CREATE_UNICODE_ENVIRONMENT
                    | EXTENDED_STARTUPINFO_PRESENT,
                environment.as_ptr().cast(),
                directory.as_ptr(),
                &startup.StartupInfo,
                &mut information,
            )
        } == 0
        {
            return Err(ManagementError::Launch);
        }
        // Successful CreateProcess supplies valid handles. Install ownership
        // immediately, before any fallible operation, allocation or resume.
        self.process = Some(unsafe { OwnedHandle::from_raw_handle(information.hProcess) });
        self.thread = Some(unsafe { OwnedHandle::from_raw_handle(information.hThread) });
        #[cfg(test)]
        if self.faults.assignment {
            return Err(ManagementError::Launch);
        }
        if unsafe { AssignProcessToJobObject(raw(&self.job), information.hProcess) } == 0 {
            return Err(ManagementError::Launch);
        }
        self.assigned = true;
        let mut in_job = 0;
        if unsafe { IsProcessInJob(information.hProcess, raw(&self.job), &mut in_job) } == 0
            || in_job == 0
        {
            return Err(ManagementError::Launch);
        }
        #[cfg(test)]
        if self.faults.resume {
            return Err(ManagementError::Launch);
        }
        if unsafe { ResumeThread(information.hThread) } != 1 {
            return Err(ManagementError::Launch);
        }
        self.thread.take();
        Ok(())
    }

    fn collect(&mut self, cancelled: &AtomicBool, limits: Limits) -> Result<u32, ManagementError> {
        #[cfg(test)]
        if self.faults.unwind {
            panic!("injected management unwind after resume");
        }
        #[cfg(test)]
        let defer_output = self.faults.defer_output;
        #[cfg(not(test))]
        let defer_output = false;
        let started = Instant::now();
        loop {
            if cancelled.load(Ordering::Acquire) {
                return Err(ManagementError::Cancelled);
            }
            if started.elapsed() >= limits.runtime {
                return Err(ManagementError::Timeout);
            }
            if !defer_output {
                self.stdout.poll(limits.output, true)?;
                self.stderr.poll(limits.output, true)?;
            }
            if self.parent_exited()? {
                let mut code = 0;
                if unsafe {
                    GetExitCodeProcess(
                        raw(self.process.as_ref().ok_or(ManagementError::Launch)?),
                        &mut code,
                    )
                } == 0
                {
                    return Err(ManagementError::Io);
                }
                return Ok(code);
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn parent_exited(&self) -> Result<bool, ManagementError> {
        let Some(process) = self.process.as_ref() else {
            return Ok(true);
        };
        match unsafe { WaitForSingleObject(raw(process), 0) } {
            WAIT_OBJECT_0 => Ok(true),
            windows_sys::Win32::Foundation::WAIT_TIMEOUT => Ok(false),
            _ => Err(ManagementError::Io),
        }
    }

    fn empty(&self) -> bool {
        #[cfg(test)]
        if self.faults.cleanup {
            return false;
        }
        let mut information = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        (unsafe {
            QueryInformationJobObject(
                raw(&self.job),
                JobObjectBasicAccountingInformation,
                (&mut information as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                null_mut(),
            )
        }) != 0
            && information.ActiveProcesses == 0
            && self.parent_exited().unwrap_or(false)
    }

    fn cleanup(&mut self, capture: bool, limits: Limits) -> Result<(), ManagementError> {
        if self.assigned {
            unsafe {
                TerminateJobObject(raw(&self.job), 1);
            }
        } else if let Some(process) = &self.process {
            unsafe {
                TerminateProcess(raw(process), 1);
            }
        }
        let started = Instant::now();
        let mut capture = capture;
        let mut output_error = None;
        loop {
            for pipe in [&mut self.stdout, &mut self.stderr] {
                if !capture {
                    pipe.cancel();
                }
                if let Err(error) = pipe.poll(limits.output, capture) {
                    output_error.get_or_insert(error);
                    capture = false;
                    pipe.cancel();
                }
            }
            if self.empty() && self.stdout.finished && self.stderr.finished {
                // An output error is reported by collect or below, but cleanup
                // itself must only return success once releasing state is safe.
                if let Some(error) = output_error {
                    self.stdout.final_error = Some(error);
                }
                return Ok(());
            }
            if started.elapsed() >= limits.cleanup {
                return Err(ManagementError::CleanupPending);
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
}

struct OutputPipe {
    handle: OwnedHandle,
    _event: OwnedHandle,
    overlapped: Box<OVERLAPPED>,
    buffer: Box<[u8; 8192]>,
    pending: bool,
    finished: bool,
    output: Vec<u8>,
    final_error: Option<ManagementError>,
}
// Kernel references point only into the owned boxes. Their allocations never
// move; operations and cancellation are serialized by PROCESS across threads.
unsafe impl Send for OutputPipe {}

impl OutputPipe {
    fn new() -> Result<(Self, OwnedHandle), ManagementError> {
        let mut random = [0u8; 16];
        OsRng
            .try_fill_bytes(&mut random)
            .map_err(|_| ManagementError::Launch)?;
        let suffix = random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let name = wide(OsStr::new(&format!(
            "\\\\.\\pipe\\context-relay-management-{suffix}"
        )))?;
        let handle = owned(unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                8192,
                8192,
                0,
                null(),
            )
        })?;
        let attributes = inheritable();
        let child = owned(unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_WRITE,
                0,
                &attributes,
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        })?;
        // The client is connected synchronously before any server I/O starts.
        let event = owned(unsafe { CreateEventW(null(), 1, 0, null()) })?;
        let overlapped = Box::new(OVERLAPPED {
            hEvent: raw(&event),
            ..OVERLAPPED::default()
        });
        Ok((
            Self {
                handle,
                _event: event,
                overlapped,
                buffer: Box::new([0; 8192]),
                pending: false,
                finished: false,
                output: Vec::new(),
                final_error: None,
            },
            child,
        ))
    }

    fn poll(&mut self, cap: usize, capture: bool) -> Result<(), ManagementError> {
        if self.finished {
            return Ok(());
        }
        if self.pending {
            let mut count = 0;
            let result =
                unsafe { GetOverlappedResult(raw(&self.handle), &*self.overlapped, &mut count, 0) };
            if result == 0 {
                let error = unsafe { GetLastError() };
                if error == ERROR_IO_INCOMPLETE {
                    return Ok(());
                }
                self.pending = false;
                self.finished = true;
                if error == ERROR_BROKEN_PIPE || error == ERROR_OPERATION_ABORTED {
                    return Ok(());
                }
                return Err(ManagementError::Io);
            }
            self.pending = false;
            return self.complete_read(count as usize, cap, capture);
        }
        if !capture {
            self.finished = true;
            return Ok(());
        }
        unsafe {
            ResetEvent(raw(&self._event));
        }
        let result = unsafe {
            ReadFile(
                raw(&self.handle),
                self.buffer.as_mut_ptr(),
                self.buffer.len() as u32,
                null_mut(),
                &mut *self.overlapped,
            )
        };
        if result != 0 || unsafe { GetLastError() } == ERROR_IO_PENDING {
            self.pending = true;
        } else {
            self.finished = true;
            if unsafe { GetLastError() } != ERROR_BROKEN_PIPE {
                return Err(ManagementError::Io);
            }
        }
        Ok(())
    }

    fn complete_read(
        &mut self,
        count: usize,
        cap: usize,
        capture: bool,
    ) -> Result<(), ManagementError> {
        // A successful zero-byte read can reflect a zero-byte pipe write while
        // the writer remains connected. Only broken-pipe completion is EOF.
        if capture {
            if count > self.buffer.len() || self.output.len().saturating_add(count) > cap {
                return Err(ManagementError::OutputLimit);
            }
            self.output.extend_from_slice(&self.buffer[..count]);
        }
        Ok(())
    }

    fn cancel(&mut self) {
        if self.pending {
            unsafe {
                CancelIoEx(raw(&self.handle), &*self.overlapped);
            }
        } else {
            self.finished = true;
        }
    }
}

fn raw(handle: &OwnedHandle) -> HANDLE {
    handle.as_raw_handle()
}
fn owned(handle: HANDLE) -> Result<OwnedHandle, ManagementError> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(ManagementError::Launch);
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}
fn inheritable() -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    }
}
fn wide(value: &OsStr) -> Result<Vec<u16>, ManagementError> {
    let mut units = value.encode_wide().collect::<Vec<_>>();
    if units.contains(&0) || units.len() >= 32767 {
        return Err(ManagementError::Launch);
    }
    units.push(0);
    Ok(units)
}
fn command_line(executable: &OsStr, args: &[OsString]) -> Result<Vec<u16>, ManagementError> {
    let mut result = Vec::new();
    for argument in std::iter::once(executable).chain(args.iter().map(OsString::as_os_str)) {
        if !result.is_empty() {
            result.push(b' ' as u16);
        }
        result.push(b'"' as u16);
        let mut slashes = 0;
        for unit in argument.encode_wide() {
            if unit == 0 {
                return Err(ManagementError::Launch);
            }
            if unit == b'\\' as u16 {
                slashes += 1;
                continue;
            }
            result.extend(std::iter::repeat_n(
                b'\\' as u16,
                slashes * if unit == b'"' as u16 { 2 } else { 1 },
            ));
            slashes = 0;
            if unit == b'"' as u16 {
                result.push(b'\\' as u16);
            }
            result.push(unit);
        }
        result.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2));
        result.push(b'"' as u16);
    }
    if result.len() >= 32767 {
        return Err(ManagementError::Launch);
    }
    result.push(0);
    Ok(result)
}
fn environment_block(mut values: Vec<(OsString, OsString)>) -> Result<Vec<u16>, ManagementError> {
    values.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    let mut block = Vec::new();
    for (key, value) in values {
        if key.is_empty() || key.encode_wide().any(|unit| unit == b'=' as u16) {
            return Err(ManagementError::Launch);
        }
        block.extend(wide(&key)?.into_iter().take_while(|unit| *unit != 0));
        block.push(b'=' as u16);
        block.extend(wide(&value)?);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

#[cfg(test)]
mod tests;
