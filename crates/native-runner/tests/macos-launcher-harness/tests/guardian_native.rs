#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use std::{
    ffi::CString,
    fs::{self, File},
    net::TcpListener,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    os::unix::fs::PermissionsExt,
    os::unix::process::CommandExt,
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use context_relay_native_runner::macos_spawn::MacProcessGuardian;

const PROBE_ENV: &str = "CONTEXT_RELAY_GUARDIAN_FD_PROBE";
const LEASE_OWNER_ENV: &str = "CONTEXT_RELAY_GUARDIAN_LEASE_OWNER";
const MEMBER_ENV: &str = "CONTEXT_RELAY_GUARDIAN_GROUP_MEMBER";
const UNRELATED_ENV: &str = "CONTEXT_RELAY_GUARDIAN_UNRELATED_CHILD";

#[test]
fn guardian_closes_descriptors_above_a_lowered_soft_limit() {
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "guardian_fd_probe_inner",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(PROBE_ENV, "1")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "guardian FD probe failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn guardian_fd_probe_inner() {
    if std::env::var_os(PROBE_ENV).is_none() {
        return;
    }

    let original_limit = resource_limit();
    let _restore_limit = ResourceLimitGuard(original_limit);
    let lease_directory = LeaseDirectory::new("fd-probe");
    assert_ne!(original_limit.rlim_max, libc::RLIM_INFINITY);

    let baseline_highest = highest_open_descriptor();
    let lowered_soft = baseline_highest + 32;
    let high_floor = lowered_soft + 16;
    let raised_soft = high_floor + 16;
    assert!(raised_soft < original_limit.rlim_max);
    set_soft_limit(original_limit, raised_soft);

    let mut sentinel_pipe = [-1; 2];
    assert_eq!(unsafe { libc::pipe(sentinel_pipe.as_mut_ptr()) }, 0);
    let sentinel_read = unsafe { OwnedFd::from_raw_fd(sentinel_pipe[0]) };
    let high_writer = duplicate_at_or_above(sentinel_pipe[1], high_floor);
    assert_eq!(unsafe { libc::close(sentinel_pipe[1]) }, 0);

    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let listener_address = listener.local_addr().unwrap();
    let high_listener = duplicate_at_or_above(listener.as_raw_fd(), high_floor);
    drop(listener);
    let lowered_soft_fd = libc::c_int::try_from(lowered_soft).unwrap();
    assert!(high_writer.as_raw_fd() >= lowered_soft_fd);
    assert!(high_listener.as_raw_fd() >= lowered_soft_fd);

    set_soft_limit(original_limit, lowered_soft);
    let signals_before = current_signal_mask();
    let mut guardian = lease_directory.start();
    assert_eq!(signals_before, current_signal_mask());
    set_soft_limit(original_limit, original_limit.rlim_cur);

    drop(high_writer);
    drop(high_listener);
    assert_pipe_eof(&sentinel_read);
    TcpListener::bind(listener_address).unwrap();
    guardian.kill_group_and_reap().unwrap();
}

#[test]
fn guardian_lease_is_cloexec_during_spawn_and_daemon_death_kills_only_its_group() {
    let identity_file = scratch_path("lease-identity");
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "guardian_lease_owner_inner",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(LEASE_OWNER_ENV, &identity_file)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "lease owner failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let identity = fs::read_to_string(&identity_file).unwrap();
    let values = identity
        .lines()
        .map(str::parse::<libc::pid_t>)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let [pgid, member_pid, unrelated_pid] = values.as_slice() else {
        panic!("invalid guardian identity");
    };
    wait_until_absent(*member_pid, *pgid);
    assert!(process_exists(*unrelated_pid));
    assert_eq!(unsafe { libc::kill(*unrelated_pid, libc::SIGKILL) }, 0);
    wait_until_process_absent(*unrelated_pid);
    fs::remove_file(identity_file).unwrap();
}

#[test]
fn guardian_lease_owner_inner() {
    let Some(identity_file) = std::env::var_os(LEASE_OWNER_ENV) else {
        return;
    };
    let lease_directory = LeaseDirectory::new("lease-owner");
    let mut unrelated_pid = 0;
    let guardian = lease_directory.start_with_hook(|| {
        let unrelated = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "guardian_unrelated_child_inner",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(UNRELATED_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        unrelated_pid = libc::pid_t::try_from(unrelated.id()).unwrap();
        std::mem::forget(unrelated);
    });
    drop(lease_directory);
    let mut member = Command::new(std::env::current_exe().unwrap());
    member
        .args([
            "--exact",
            "guardian_group_member_inner",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(MEMBER_ENV, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(guardian.pgid());
    let member = member.spawn().unwrap();
    let member_pid = libc::pid_t::try_from(member.id()).unwrap();
    assert_eq!(unsafe { libc::getpgid(member_pid) }, guardian.pgid());
    fs::write(
        identity_file,
        format!("{}\n{member_pid}\n{unrelated_pid}\n", guardian.pgid()),
    )
    .unwrap();
    std::mem::forget(member);
    std::mem::forget(guardian);
    unsafe { libc::_exit(0) };
}

#[test]
fn guardian_group_member_inner() {
    if std::env::var_os(MEMBER_ENV).is_none() {
        return;
    }
    loop {
        std::thread::sleep(Duration::from_secs(60));
    }
}

#[test]
fn guardian_unrelated_child_inner() {
    if std::env::var_os(UNRELATED_ENV).is_none() {
        return;
    }
    loop {
        std::thread::sleep(Duration::from_secs(60));
    }
}

struct ResourceLimitGuard(libc::rlimit);

struct LeaseDirectory {
    path: PathBuf,
    file: File,
}

impl LeaseDirectory {
    fn new(label: &str) -> Self {
        let path = scratch_path(label);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let file = File::open(&path).unwrap();
        Self { path, file }
    }

    fn start(&self) -> MacProcessGuardian {
        MacProcessGuardian::start(&self.file, &CString::new("guardian.lease").unwrap()).unwrap()
    }

    fn start_with_hook(&self, hook: impl FnOnce()) -> MacProcessGuardian {
        MacProcessGuardian::start_with_lease_open_hook(
            &self.file,
            &CString::new("guardian.lease").unwrap(),
            hook,
        )
        .unwrap()
    }
}

impl Drop for LeaseDirectory {
    fn drop(&mut self) {
        fs::remove_dir(&self.path).unwrap();
    }
}

impl Drop for ResourceLimitGuard {
    fn drop(&mut self) {
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &self.0) }, 0);
    }
}

fn resource_limit() -> libc::rlimit {
    let mut limit = std::mem::MaybeUninit::zeroed();
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) },
        0
    );
    unsafe { limit.assume_init() }
}

fn set_soft_limit(original: libc::rlimit, soft: libc::rlim_t) {
    let limit = libc::rlimit {
        rlim_cur: soft,
        rlim_max: original.rlim_max,
    };
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
}

fn highest_open_descriptor() -> libc::rlim_t {
    fs::read_dir("/dev/fd")
        .unwrap()
        .map(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .parse::<libc::rlim_t>()
                .unwrap()
        })
        .max()
        .unwrap()
}

fn duplicate_at_or_above(descriptor: libc::c_int, floor: libc::rlim_t) -> OwnedFd {
    let floor = libc::c_int::try_from(floor).unwrap();
    let duplicated = unsafe { libc::fcntl(descriptor, libc::F_DUPFD, floor) };
    assert!(duplicated >= floor);
    unsafe { OwnedFd::from_raw_fd(duplicated) }
}

fn assert_pipe_eof(pipe: &OwnedFd) {
    let mut descriptor = libc::pollfd {
        fd: pipe.as_raw_fd(),
        events: libc::POLLIN | libc::POLLHUP,
        revents: 0,
    };
    assert!(unsafe { libc::poll(&mut descriptor, 1, 2_000) } > 0);
    let mut byte = 0_u8;
    assert_eq!(
        unsafe { libc::read(pipe.as_raw_fd(), (&mut byte as *mut u8).cast(), 1) },
        0
    );
}

fn current_signal_mask() -> Vec<libc::c_int> {
    const DARWIN_SIGNAL_COUNT: libc::c_int = 32;

    let mut mask = std::mem::MaybeUninit::<libc::sigset_t>::zeroed();
    assert_eq!(
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), mask.as_mut_ptr()) },
        0
    );
    let mask = unsafe { mask.assume_init() };
    (1..DARWIN_SIGNAL_COUNT)
        .map(|signal| unsafe { libc::sigismember(&mask, signal) })
        .collect()
}

fn scratch_path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "context-relay-guardian-{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn wait_until_absent(pid: libc::pid_t, pgid: libc::pid_t) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let pid_absent = unsafe { libc::kill(pid, 0) } == -1
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
        let group_absent = unsafe { libc::kill(-pgid, 0) } == -1
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
        if pid_absent && group_absent {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "guardian group survived lease EOF"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn process_exists(pid: libc::pid_t) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
}

fn wait_until_process_absent(pid: libc::pid_t) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if !process_exists(pid)
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "unrelated child survived SIGKILL"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}
