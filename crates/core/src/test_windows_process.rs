//! Windows containment shared by opt-in native CLI qualification fixtures.
use std::{
    io::Write as _,
    os::windows::{
        io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle},
        process::CommandExt as _,
    },
    process::Command,
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};
// The child must wait for stdin EOF before spawning anything. Assign it to the
// job first so a timeout/panic also terminates every CLI and hook descendant.
pub(crate) fn run_in_owned_job(
    command: &mut Command,
    timeout: Duration,
) -> Result<std::process::ExitStatus, &'static str> {
    // SAFETY: null attributes create a non-inheritable handle owned below.
    let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    assert!(!raw.is_null(), "{}", std::io::Error::last_os_error());
    // SAFETY: CreateJobObjectW returned a new, non-null owned handle.
    let job = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: the handle is live and the information pointer/size match its class.
    assert_ne!(
        unsafe {
            SetInformationJobObject(
                job.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        },
        0
    );
    let mut child = command.creation_flags(0x0800_0000).spawn().unwrap();
    // SAFETY: both handles are live; the child has not received its startup gate.
    if unsafe { AssignProcessToJobObject(job.as_raw_handle(), child.as_raw_handle()) } == 0 {
        let error = std::io::Error::last_os_error();
        child.kill().unwrap();
        child.wait().unwrap();
        panic!("Unable to contain fixture: {error}");
    }
    child.stdin.take().unwrap().write_all(b"run").unwrap();
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return Ok(status);
        }
        if started.elapsed() >= timeout {
            return Err("Contained fixture timed out");
        }
        thread::sleep(Duration::from_millis(20));
    }
}
