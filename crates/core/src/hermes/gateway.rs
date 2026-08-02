use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    path::Path,
};
#[cfg(all(unix, not(target_os = "linux")))]
use std::{
    io::Read,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use context_relay_protocol::ClientError;
use serde::Deserialize;

use super::{HermesProfile, conflict};

const MAX_RECORD_BYTES: u64 = 16 * 1024;
#[cfg(all(unix, not(target_os = "linux")))]
const PROCESS_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const PROCESS_OUTPUT_LIMIT: u64 = 16 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum GatewayStatus {
    Idle,
    Stale,
    Live,
    Unverifiable,
}

#[derive(Debug)]
pub(super) struct GatewayLease {
    _lock: File,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct GatewayObservation {
    pub record_present: bool,
    pub record_valid: bool,
    pub lock_held: Option<bool>,
    pub process_exists: Option<bool>,
    pub start_time_matches: Option<bool>,
    pub command_is_gateway: Option<bool>,
    pub profile_matches: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct GatewayIdentityRecord {
    pid: u32,
    kind: String,
    argv: Vec<String>,
    #[serde(deserialize_with = "deserialize_nullable_u64")]
    start_time: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct GatewayRuntimeRecord {
    pid: u32,
    kind: String,
    argv: Vec<String>,
    #[serde(deserialize_with = "deserialize_nullable_u64")]
    start_time: Option<u64>,
    gateway_state: String,
    #[serde(deserialize_with = "deserialize_nullable_string")]
    exit_reason: Option<String>,
    restart_requested: bool,
    active_agents: u64,
    platforms: BTreeMap<String, GatewayPlatformRecord>,
    updated_at: String,
    #[serde(default)]
    served_profiles: Option<Vec<String>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
struct GatewayPlatformRecord {
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    error_code: Option<String>,
    #[serde(default)]
    error_message: Option<String>,
    #[serde(default)]
    updated_at: Option<String>,
}

impl GatewayRuntimeRecord {
    fn identity(&self) -> GatewayIdentityRecord {
        GatewayIdentityRecord {
            pid: self.pid,
            kind: self.kind.clone(),
            argv: self.argv.clone(),
            start_time: self.start_time,
        }
    }
}

fn deserialize_nullable_u64<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<u64>::deserialize(deserializer)
}

fn deserialize_nullable_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer)
}

pub(super) fn evaluate_gateway(observation: &GatewayObservation) -> GatewayStatus {
    if observation.record_present && !observation.record_valid {
        return GatewayStatus::Unverifiable;
    }
    if !observation.record_present {
        return match observation.lock_held {
            Some(false) => GatewayStatus::Idle,
            None if observation.process_exists == Some(false) => GatewayStatus::Idle,
            _ => GatewayStatus::Unverifiable,
        };
    }
    match (observation.process_exists, observation.lock_held) {
        (Some(false), Some(false)) => GatewayStatus::Stale,
        (Some(false), _) => GatewayStatus::Unverifiable,
        (Some(true), _)
            if observation.start_time_matches == Some(true)
                && observation.command_is_gateway == Some(true)
                && observation.profile_matches == Some(true) =>
        {
            GatewayStatus::Live
        }
        (Some(true), _) | (None, _) => GatewayStatus::Unverifiable,
    }
}

pub(super) fn inspect_gateway(profile: &HermesProfile) -> Result<GatewayStatus, ClientError> {
    inspect_gateway_with_lock_state(profile, None)
}

fn inspect_gateway_with_lock_state(
    profile: &HermesProfile,
    known_lock_held: Option<bool>,
) -> Result<GatewayStatus, ClientError> {
    let pid_record = read_identity_record(&profile.hermes_home.join("gateway.pid"));
    let state_record = read_runtime_record(&profile.hermes_home.join("gateway_state.json"));
    let record_present = pid_record.is_some() || state_record.is_some();
    let mut record_valid = true;
    let pid_identity = match pid_record {
        Some(Ok(record)) => Some(record),
        Some(Err(())) => {
            record_valid = false;
            None
        }
        None => None,
    };
    let runtime_identity = match state_record {
        Some(Ok(record)) => Some(record.identity()),
        Some(Err(())) => {
            record_valid = false;
            None
        }
        None => None,
    };
    if pid_identity
        .as_ref()
        .zip(runtime_identity.as_ref())
        .is_some_and(|(pid, runtime)| pid != runtime)
    {
        record_valid = false;
    }
    let selected = pid_identity.or(runtime_identity);
    let lock_held =
        known_lock_held.or_else(|| probe_lock(&profile.hermes_home.join("gateway.lock")));
    let mut observation = GatewayObservation {
        record_present,
        record_valid,
        lock_held,
        process_exists: None,
        start_time_matches: None,
        command_is_gateway: None,
        profile_matches: None,
    };
    if !record_present {
        return Ok(evaluate_gateway(&observation));
    }
    let Some(record) = selected.filter(|_| record_valid) else {
        return Ok(GatewayStatus::Unverifiable);
    };
    let process = inspect_process(&record, profile);
    observation.process_exists = process.exists;
    observation.start_time_matches = process.start_time_matches;
    observation.command_is_gateway = process.command_is_gateway;
    observation.profile_matches = process.profile_matches;
    Ok(evaluate_gateway(&observation))
}

pub(super) fn require_gateway_idle(profile: &HermesProfile) -> Result<(), ClientError> {
    match inspect_gateway(profile)? {
        GatewayStatus::Idle | GatewayStatus::Stale => Ok(()),
        GatewayStatus::Live => Err(conflict("Hermes gateway is live for the selected profile")),
        GatewayStatus::Unverifiable => Err(conflict(
            "Hermes gateway state is unverifiable for the selected profile",
        )),
    }
}

pub(super) fn acquire_gateway_idle(profile: &HermesProfile) -> Result<GatewayLease, ClientError> {
    let lease = acquire_gateway_lock(&profile.hermes_home.join("gateway.lock"))?;
    match inspect_gateway_with_lock_state(profile, Some(false))? {
        GatewayStatus::Idle | GatewayStatus::Stale => Ok(lease),
        GatewayStatus::Live => Err(conflict("Hermes gateway is live for the selected profile")),
        GatewayStatus::Unverifiable => Err(conflict(
            "Hermes gateway state is unverifiable for the selected profile",
        )),
    }
}

#[cfg(unix)]
fn acquire_gateway_lock(path: &Path) -> Result<GatewayLease, ClientError> {
    use std::os::{
        fd::AsRawFd as _,
        unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    };

    if fs::symlink_metadata(path)
        .is_ok_and(|metadata| metadata.file_type().is_symlink() || !metadata.is_file())
    {
        return Err(conflict(
            "Hermes gateway state is unverifiable for the selected profile",
        ));
    }
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| conflict("Hermes gateway state is unverifiable for the selected profile"))?;
    let held = lock
        .metadata()
        .map_err(|_| conflict("Hermes gateway state is unverifiable for the selected profile"))?;
    let named = fs::symlink_metadata(path)
        .map_err(|_| conflict("Hermes gateway state is unverifiable for the selected profile"))?;
    if !held.is_file()
        || !named.is_file()
        || named.file_type().is_symlink()
        || held.uid() != unsafe { libc::geteuid() }
        || held.nlink() != 1
        || held.dev() != named.dev()
        || held.ino() != named.ino()
    {
        return Err(conflict(
            "Hermes gateway state is unverifiable for the selected profile",
        ));
    }
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(conflict("Hermes gateway is live for the selected profile"));
    }
    let named_after = fs::symlink_metadata(path)
        .map_err(|_| conflict("Hermes gateway state is unverifiable for the selected profile"))?;
    if named_after.file_type().is_symlink()
        || !named_after.is_file()
        || held.dev() != named_after.dev()
        || held.ino() != named_after.ino()
    {
        return Err(conflict(
            "Hermes gateway state is unverifiable for the selected profile",
        ));
    }
    Ok(GatewayLease { _lock: lock })
}

#[cfg(windows)]
fn acquire_gateway_lock(path: &Path) -> Result<GatewayLease, ClientError> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::{
        Foundation::{ERROR_LOCK_VIOLATION, GetLastError},
        Storage::FileSystem::{
            FILE_ATTRIBUTE_REPARSE_POINT, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
            LockFileEx,
        },
        System::IO::OVERLAPPED,
    };

    if fs::symlink_metadata(path).is_ok_and(|metadata| {
        use std::os::windows::fs::MetadataExt as _;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !metadata.is_file()
    }) {
        return Err(conflict(
            "Hermes gateway state is unverifiable for the selected profile",
        ));
    }
    let lock = open_windows_gateway_lock(path)?;
    let metadata = lock
        .metadata()
        .map_err(|_| conflict("Hermes gateway state is unverifiable for the selected profile"))?;
    let identity = windows_gateway_identity(&lock)?;
    {
        use std::os::windows::fs::MetadataExt as _;
        if !metadata.is_file()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || identity.links != 1
            || windows_gateway_identity(&open_windows_gateway_lock(path)?)? != identity
        {
            return Err(conflict(
                "Hermes gateway state is unverifiable for the selected profile",
            ));
        }
    }
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    if unsafe {
        LockFileEx(
            lock.as_raw_handle() as _,
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    } == 0
    {
        return if unsafe { GetLastError() } == ERROR_LOCK_VIOLATION {
            Err(conflict("Hermes gateway is live for the selected profile"))
        } else {
            Err(conflict(
                "Hermes gateway state is unverifiable for the selected profile",
            ))
        };
    }
    if windows_gateway_identity(&open_windows_gateway_lock(path)?)? != identity {
        return Err(conflict(
            "Hermes gateway state is unverifiable for the selected profile",
        ));
    }
    Ok(GatewayLease { _lock: lock })
}

#[cfg(windows)]
const WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
#[cfg(windows)]
const WINDOWS_FILE_SHARE_READ: u32 = 0x0000_0001;
#[cfg(windows)]
const WINDOWS_FILE_SHARE_WRITE: u32 = 0x0000_0002;

#[cfg(windows)]
fn open_windows_gateway_lock(path: &Path) -> Result<File, ClientError> {
    use std::os::windows::fs::OpenOptionsExt as _;

    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .share_mode(WINDOWS_FILE_SHARE_READ | WINDOWS_FILE_SHARE_WRITE)
        .custom_flags(WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| conflict("Hermes gateway state is unverifiable for the selected profile"))
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WindowsGatewayIdentity {
    volume: u32,
    index: u64,
    links: u32,
}

#[cfg(windows)]
fn windows_gateway_identity(file: &File) -> Result<WindowsGatewayIdentity, ClientError> {
    use std::{mem::MaybeUninit, os::windows::io::AsRawHandle as _};
    use windows_sys::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle},
    };

    let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    if unsafe {
        GetFileInformationByHandle(file.as_raw_handle() as HANDLE, information.as_mut_ptr())
    } == 0
    {
        return Err(conflict(
            "Hermes gateway state is unverifiable for the selected profile",
        ));
    }
    let information = unsafe { information.assume_init() };
    Ok(WindowsGatewayIdentity {
        volume: information.dwVolumeSerialNumber,
        index: (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow),
        links: information.nNumberOfLinks,
    })
}

fn read_identity_record(path: &Path) -> Option<Result<GatewayIdentityRecord, ()>> {
    read_record_bytes(path).map(|bytes| {
        bytes.and_then(|bytes| {
            serde_json::from_slice::<GatewayIdentityRecord>(&bytes)
                .ok()
                .filter(valid_identity_record)
                .ok_or(())
        })
    })
}

fn read_runtime_record(path: &Path) -> Option<Result<GatewayRuntimeRecord, ()>> {
    read_record_bytes(path).map(|bytes| {
        bytes.and_then(|bytes| {
            serde_json::from_slice::<GatewayRuntimeRecord>(&bytes)
                .ok()
                .filter(valid_runtime_record)
                .ok_or(())
        })
    })
}

fn read_record_bytes(path: &Path) -> Option<Result<Vec<u8>, ()>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(_) => return Some(Err(())),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > MAX_RECORD_BYTES
    {
        return Some(Err(()));
    }
    let bytes = match fs::read(path) {
        Ok(bytes) if bytes.len() as u64 <= MAX_RECORD_BYTES => bytes,
        _ => return Some(Err(())),
    };
    Some(Ok(bytes))
}

fn valid_identity_record(record: &GatewayIdentityRecord) -> bool {
    record.pid > 0
        && record.kind == "hermes-gateway"
        && (1..=64).contains(&record.argv.len())
        && record
            .argv
            .iter()
            .all(|argument| !argument.is_empty() && argument.len() <= 4096)
}

fn valid_runtime_record(record: &GatewayRuntimeRecord) -> bool {
    valid_identity_record(&record.identity())
        && bounded_string(&record.gateway_state, 128)
        && record
            .exit_reason
            .as_deref()
            .is_none_or(|value| bounded_string(value, 4096))
        && record.active_agents <= 1_000_000
        && record.platforms.len() <= 64
        && record.platforms.iter().all(|(name, platform)| {
            bounded_name(name)
                && platform
                    .state
                    .as_deref()
                    .is_none_or(|value| bounded_string(value, 128))
                && platform
                    .error_code
                    .as_deref()
                    .is_none_or(|value| bounded_string(value, 128))
                && platform
                    .error_message
                    .as_deref()
                    .is_none_or(|value| bounded_string(value, 4096))
                && platform
                    .updated_at
                    .as_deref()
                    .is_none_or(|value| bounded_string(value, 128))
        })
        && bounded_string(&record.updated_at, 128)
        && record.served_profiles.as_ref().is_none_or(|profiles| {
            profiles.len() <= 64 && profiles.iter().all(|profile| bounded_name(profile))
        })
}

fn bounded_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn bounded_string(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

struct ProcessObservation {
    exists: Option<bool>,
    start_time_matches: Option<bool>,
    command_is_gateway: Option<bool>,
    profile_matches: Option<bool>,
}

#[cfg(any(windows, test))]
enum LiveCommandLine {
    Readable(Vec<String>),
    Unreadable,
    Ambiguous,
}

#[cfg(any(windows, test))]
fn inspect_live_process_identity(
    record: &GatewayIdentityRecord,
    profile: &HermesProfile,
    actual_start: Option<u64>,
    live_command_line: LiveCommandLine,
) -> ProcessObservation {
    let (command_is_gateway, profile_matches) = match live_command_line {
        LiveCommandLine::Readable(argv) if valid_argv(&argv) => (
            Some(command_is_gateway(&argv)),
            Some(argv_matches_profile(&argv, profile)),
        ),
        LiveCommandLine::Unreadable if valid_argv(&record.argv) => (
            Some(command_is_gateway(&record.argv)),
            Some(argv_matches_profile(&record.argv, profile)),
        ),
        LiveCommandLine::Readable(_) | LiveCommandLine::Unreadable | LiveCommandLine::Ambiguous => {
            (None, None)
        }
    };
    ProcessObservation {
        exists: Some(true),
        start_time_matches: start_time_matches(record.start_time, actual_start),
        command_is_gateway,
        profile_matches,
    }
}

#[cfg(unix)]
fn inspect_process(record: &GatewayIdentityRecord, profile: &HermesProfile) -> ProcessObservation {
    let exists = process_exists_unix(record.pid);
    if exists != Some(true) {
        return ProcessObservation {
            exists,
            start_time_matches: None,
            command_is_gateway: None,
            profile_matches: None,
        };
    }
    let actual_start = process_start_time(record.pid);
    let live_argv = process_command_line(record.pid);
    let argv = live_argv.as_deref().unwrap_or(&record.argv);
    ProcessObservation {
        exists,
        start_time_matches: start_time_matches(record.start_time, actual_start),
        command_is_gateway: Some(command_is_gateway(argv)),
        profile_matches: Some(argv_matches_profile(argv, profile)),
    }
}

#[cfg(unix)]
fn process_exists_unix(pid: u32) -> Option<bool> {
    let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if result == 0 {
        Some(true)
    } else {
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ESRCH) => Some(false),
            Some(libc::EPERM) => Some(true),
            _ => None,
        }
    }
}

#[cfg(target_os = "linux")]
fn process_start_time(pid: u32) -> Option<u64> {
    let bytes = fs::read(format!("/proc/{pid}/stat")).ok()?;
    linux_start_time_from_stat(&bytes)
}

#[cfg(any(target_os = "linux", test))]
fn linux_start_time_from_stat(bytes: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(bytes).ok()?;
    let command_end = text.rfind(')')?;
    text.get(command_end + 1..)?
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

#[cfg(target_os = "macos")]
fn process_start_time(pid: u32) -> Option<u64> {
    use std::mem::MaybeUninit;

    let mut information = MaybeUninit::<libc::proc_bsdinfo>::uninit();
    let expected = std::mem::size_of::<libc::proc_bsdinfo>();
    let read = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDTBSDINFO,
            0,
            information.as_mut_ptr().cast(),
            expected as libc::c_int,
        )
    };
    if read != expected as libc::c_int {
        return None;
    }
    let information = unsafe { information.assume_init() };
    epoch_centiseconds(information.pbi_start_tvsec, information.pbi_start_tvusec)
}

#[cfg(any(target_os = "macos", test))]
fn epoch_centiseconds(seconds: u64, microseconds: u64) -> Option<u64> {
    if microseconds >= 1_000_000 {
        return None;
    }
    let whole = microseconds / 10_000;
    let remainder = microseconds % 10_000;
    let rounded =
        whole + u64::from(remainder > 5_000 || (remainder == 5_000 && !whole.is_multiple_of(2)));
    seconds.checked_mul(100)?.checked_add(rounded)
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn process_start_time(_pid: u32) -> Option<u64> {
    None
}

fn start_time_matches(recorded: Option<u64>, actual: Option<u64>) -> Option<bool> {
    match (recorded, actual) {
        (Some(recorded), Some(actual)) => Some(recorded == actual),
        (None, _) => Some(true),
        (Some(_), None) => None,
    }
}

#[cfg(target_os = "linux")]
fn process_command_line(pid: u32) -> Option<Vec<String>> {
    let bytes = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    if bytes.is_empty() || bytes.len() as u64 > PROCESS_OUTPUT_LIMIT {
        return None;
    }
    let argv = bytes
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| std::str::from_utf8(part).ok().map(str::to_owned))
        .collect::<Option<Vec<_>>>()?;
    valid_argv(&argv).then_some(argv)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn process_command_line(pid: u32) -> Option<Vec<String>> {
    ps_command_line(pid).and_then(|command| {
        let argv = command_tokens(&command);
        valid_argv(&argv).then_some(argv)
    })
}

#[cfg(all(unix, not(target_os = "linux")))]
fn ps_command_line(pid: u32) -> Option<String> {
    let executable = if Path::new("/bin/ps").is_file() {
        "/bin/ps"
    } else if Path::new("/usr/bin/ps").is_file() {
        "/usr/bin/ps"
    } else {
        return None;
    };
    let mut child = Command::new(executable)
        .args(["-p", &pid.to_string(), "-o", "command="])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let stdout = child.stdout.take()?;
    let output_thread = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(PROCESS_OUTPUT_LIMIT + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().ok()? {
            break status;
        }
        if started.elapsed() >= PROCESS_PROBE_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        thread::sleep(Duration::from_millis(5));
    };
    let bytes = output_thread.join().ok()?.ok()?;
    if !status.success() || bytes.len() as u64 > PROCESS_OUTPUT_LIMIT {
        return None;
    }
    let command = std::str::from_utf8(&bytes).ok()?.trim();
    (!command.is_empty()).then(|| command.to_owned())
}

#[cfg(unix)]
fn probe_lock(path: &Path) -> Option<bool> {
    use std::os::fd::AsRawFd as _;

    let file = match OpenOptions::new().read(true).write(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Some(false),
        Err(_) => return None,
    };
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        let unlocked = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) } == 0;
        unlocked.then_some(false)
    } else {
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::EWOULDBLOCK) => Some(true),
            _ => None,
        }
    }
}

#[cfg(windows)]
fn inspect_process(record: &GatewayIdentityRecord, profile: &HermesProfile) -> ProcessObservation {
    use std::mem::MaybeUninit;
    use windows_sys::Win32::{
        Foundation::{CloseHandle, ERROR_INVALID_PARAMETER, FILETIME, GetLastError, STILL_ACTIVE},
        Storage::FileSystem::SYNCHRONIZE,
        System::Threading::{
            GetExitCodeProcess, GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        },
    };

    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
            0,
            record.pid,
        )
    };
    if handle.is_null() {
        let exists = if unsafe { GetLastError() } == ERROR_INVALID_PARAMETER {
            Some(false)
        } else {
            None
        };
        return ProcessObservation {
            exists,
            start_time_matches: None,
            command_is_gateway: None,
            profile_matches: None,
        };
    }
    let mut exit_code = 0u32;
    let mut creation = MaybeUninit::<FILETIME>::uninit();
    let mut exit = MaybeUninit::<FILETIME>::uninit();
    let mut kernel = MaybeUninit::<FILETIME>::uninit();
    let mut user = MaybeUninit::<FILETIME>::uninit();
    let exit_ok = unsafe { GetExitCodeProcess(handle, &mut exit_code) } != 0;
    let live = exit_ok && exit_code == STILL_ACTIVE as u32;
    let times_ok = unsafe {
        GetProcessTimes(
            handle,
            creation.as_mut_ptr(),
            exit.as_mut_ptr(),
            kernel.as_mut_ptr(),
            user.as_mut_ptr(),
        )
    } != 0;
    let live_command_line = live.then(|| windows_process_command_line(handle));
    unsafe { CloseHandle(handle) };
    if !exit_ok {
        return ProcessObservation {
            exists: Some(true),
            start_time_matches: None,
            command_is_gateway: None,
            profile_matches: None,
        };
    }
    if !live {
        return ProcessObservation {
            exists: Some(false),
            start_time_matches: None,
            command_is_gateway: None,
            profile_matches: None,
        };
    }
    let creation = times_ok.then(|| unsafe { creation.assume_init() });
    let creation_ticks =
        creation.map(|time| ((time.dwHighDateTime as u64) << 32) | time.dwLowDateTime as u64);
    let creation_centiseconds = creation_ticks.and_then(windows_filetime_centiseconds);
    inspect_live_process_identity(
        record,
        profile,
        creation_centiseconds,
        live_command_line.unwrap_or(LiveCommandLine::Ambiguous),
    )
}

#[cfg(windows)]
const WINDOWS_PROCESS_COMMAND_LINE_INFORMATION: i32 = 60;
#[cfg(windows)]
const WINDOWS_COMMAND_LINE_BYTES_LIMIT: usize = PROCESS_OUTPUT_LIMIT as usize;

#[cfg(windows)]
#[repr(C)]
struct WindowsUnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

#[cfg(windows)]
#[link(name = "ntdll")]
unsafe extern "system" {
    #[link_name = "NtQueryInformationProcess"]
    fn nt_query_information_process(
        process_handle: *mut std::ffi::c_void,
        process_information_class: i32,
        process_information: *mut std::ffi::c_void,
        process_information_length: u32,
        return_length: *mut u32,
    ) -> windows_sys::Win32::Foundation::NTSTATUS;
}

#[cfg(windows)]
#[link(name = "shell32")]
unsafe extern "system" {
    #[link_name = "CommandLineToArgvW"]
    fn command_line_to_argv_w(command_line: *const u16, argument_count: *mut i32) -> *mut *mut u16;
}

#[cfg(windows)]
fn windows_process_command_line(handle: windows_sys::Win32::Foundation::HANDLE) -> LiveCommandLine {
    use windows_sys::Win32::Foundation::{STATUS_BUFFER_TOO_SMALL, STATUS_INFO_LENGTH_MISMATCH};

    let mut required = 0u32;
    let status = unsafe {
        nt_query_information_process(
            handle,
            WINDOWS_PROCESS_COMMAND_LINE_INFORMATION,
            std::ptr::null_mut(),
            0,
            &mut required,
        )
    };
    if windows_command_line_unreadable(status) {
        return LiveCommandLine::Unreadable;
    }
    if !matches!(
        status,
        STATUS_INFO_LENGTH_MISMATCH | STATUS_BUFFER_TOO_SMALL
    ) {
        return LiveCommandLine::Ambiguous;
    }
    let header_size = std::mem::size_of::<WindowsUnicodeString>();
    let required = required as usize;
    if required < header_size
        || required > header_size.saturating_add(WINDOWS_COMMAND_LINE_BYTES_LIMIT)
    {
        return LiveCommandLine::Ambiguous;
    }

    let mut information = vec![0u8; required];
    let mut returned = 0u32;
    let status = unsafe {
        nt_query_information_process(
            handle,
            WINDOWS_PROCESS_COMMAND_LINE_INFORMATION,
            information.as_mut_ptr().cast(),
            information.len() as u32,
            &mut returned,
        )
    };
    if windows_command_line_unreadable(status) {
        return LiveCommandLine::Unreadable;
    }
    if status != 0 {
        return LiveCommandLine::Ambiguous;
    }
    let returned = returned as usize;
    let written = if returned == 0 {
        information.len()
    } else if (header_size..=information.len()).contains(&returned) {
        returned
    } else {
        return LiveCommandLine::Ambiguous;
    };
    windows_command_line_from_information(&information[..written])
        .map_or(LiveCommandLine::Ambiguous, LiveCommandLine::Readable)
}

#[cfg(windows)]
fn windows_command_line_unreadable(status: windows_sys::Win32::Foundation::NTSTATUS) -> bool {
    use windows_sys::Win32::Foundation::{
        STATUS_ACCESS_DENIED, STATUS_INVALID_INFO_CLASS, STATUS_NOT_IMPLEMENTED,
        STATUS_NOT_SUPPORTED,
    };

    matches!(
        status,
        STATUS_ACCESS_DENIED
            | STATUS_INVALID_INFO_CLASS
            | STATUS_NOT_IMPLEMENTED
            | STATUS_NOT_SUPPORTED
    )
}

#[cfg(windows)]
fn windows_command_line_from_information(information: &[u8]) -> Option<Vec<String>> {
    let header_size = std::mem::size_of::<WindowsUnicodeString>();
    if information.len() < header_size {
        return None;
    }
    let header =
        unsafe { std::ptr::read_unaligned(information.as_ptr().cast::<WindowsUnicodeString>()) };
    let length = usize::from(header.length);
    if length == 0
        || !length.is_multiple_of(2)
        || length > WINDOWS_COMMAND_LINE_BYTES_LIMIT
        || usize::from(header.maximum_length) < length
        || header.buffer.is_null()
    {
        return None;
    }
    let information_start = information.as_ptr() as usize;
    let information_end = information_start.checked_add(information.len())?;
    let command_start = header.buffer as usize;
    let command_end = command_start.checked_add(length)?;
    if command_start < information_start
        || command_end > information_end
        || !command_start.is_multiple_of(std::mem::align_of::<u16>())
    {
        return None;
    }
    let command = unsafe { std::slice::from_raw_parts(header.buffer, length / 2) };
    windows_command_line_to_argv(command)
}

#[cfg(windows)]
fn windows_command_line_to_argv(command: &[u16]) -> Option<Vec<String>> {
    use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};

    if command.is_empty() || command.len().saturating_mul(2) > WINDOWS_COMMAND_LINE_BYTES_LIMIT {
        return None;
    }
    let mut terminated = command.to_vec();
    terminated.push(0);
    let mut argument_count = 0i32;
    let raw_arguments = unsafe { command_line_to_argv_w(terminated.as_ptr(), &mut argument_count) };
    if raw_arguments.is_null() || !(1..=64).contains(&argument_count) {
        if !raw_arguments.is_null() {
            unsafe {
                LocalFree(raw_arguments.cast::<std::ffi::c_void>() as HLOCAL);
            }
        }
        return None;
    }
    struct LocalArguments(HLOCAL);
    impl Drop for LocalArguments {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
    let _allocation = LocalArguments(raw_arguments.cast::<std::ffi::c_void>() as HLOCAL);
    let argument_pointers =
        unsafe { std::slice::from_raw_parts(raw_arguments, argument_count as usize) };
    let mut argv = Vec::with_capacity(argument_pointers.len());
    for &argument in argument_pointers {
        if argument.is_null() {
            return None;
        }
        let length = (0..=4096).find(|&index| unsafe { *argument.add(index) } == 0)?;
        if length == 0 || length > 4096 {
            return None;
        }
        let wide = unsafe { std::slice::from_raw_parts(argument, length) };
        argv.push(String::from_utf16(wide).ok()?);
    }
    valid_argv(&argv).then_some(argv)
}

#[cfg(any(windows, test))]
fn windows_filetime_centiseconds(ticks: u64) -> Option<u64> {
    const UNIX_EPOCH_FILETIME_TICKS: u64 = 116_444_736_000_000_000;
    ticks
        .checked_sub(UNIX_EPOCH_FILETIME_TICKS)
        .map(|unix_ticks| unix_ticks / 100_000)
}

#[cfg(windows)]
fn probe_lock(path: &Path) -> Option<bool> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::{
        Foundation::{ERROR_LOCK_VIOLATION, GetLastError},
        Storage::FileSystem::{
            LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx, UnlockFileEx,
        },
        System::IO::OVERLAPPED,
    };

    let file = match OpenOptions::new().read(true).write(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Some(false),
        Err(_) => return None,
    };
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    let locked = unsafe {
        LockFileEx(
            file.as_raw_handle() as _,
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    } != 0;
    if locked {
        let released = unsafe {
            UnlockFileEx(
                file.as_raw_handle() as _,
                0,
                u32::MAX,
                u32::MAX,
                &mut overlapped,
            )
        } != 0;
        released.then_some(false)
    } else if unsafe { GetLastError() } == ERROR_LOCK_VIOLATION {
        Some(true)
    } else {
        None
    }
}

fn command_is_gateway(argv: &[String]) -> bool {
    matches!(gateway_subcommand(argv).as_deref(), Some("run" | "restart"))
}

fn argv_matches_profile(argv: &[String], profile: &HermesProfile) -> bool {
    let tokens = normalized_tokens(argv);
    let mut selected_profile = None;
    let mut selected_home = None;
    let mut index = 0usize;
    while index < tokens.len() {
        let token = &tokens[index];
        if matches!(token.as_str(), "--profile" | "-p") {
            let Some(value) = tokens.get(index + 1) else {
                return false;
            };
            if selected_profile.replace(value.as_str()).is_some() {
                return false;
            }
            index += 2;
            continue;
        }
        if let Some(value) = token
            .strip_prefix("--profile=")
            .or_else(|| token.strip_prefix("-p="))
        {
            if value.is_empty() || selected_profile.replace(value).is_some() {
                return false;
            }
        } else if matches!(token.as_str(), "--hermes-home") {
            let Some(value) = tokens.get(index + 1) else {
                return false;
            };
            if selected_home.replace(value.as_str()).is_some() {
                return false;
            }
            index += 2;
            continue;
        } else if let Some(value) = token
            .strip_prefix("--hermes-home=")
            .or_else(|| token.strip_prefix("hermes_home="))
            && (value.is_empty() || selected_home.replace(value).is_some())
        {
            return false;
        }
        index += 1;
    }

    let profile_name = profile.name.to_ascii_lowercase();
    let canonical_home = profile
        .hermes_home
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let home_matches = selected_home.is_some_and(|home| home == canonical_home);
    if profile_name != "default" {
        selected_profile.is_some_and(|selected| selected == profile_name) || home_matches
    } else {
        selected_profile.is_none() && selected_home.is_none_or(|home| home == canonical_home)
    }
}

#[cfg(test)]
fn command_text_is_gateway(command: &str) -> bool {
    command_is_gateway(&command_tokens(command))
}

#[cfg(test)]
fn command_text_matches_profile(command: &str, profile: &HermesProfile) -> bool {
    argv_matches_profile(&command_tokens(command), profile)
}

fn command_tokens(command: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut quote = None;
    for character in command.chars() {
        match (quote, character) {
            (Some(open), close) if close == open => quote = None,
            (Some(_), character) => token.push(character),
            (None, '\'' | '"') => quote = Some(character),
            (None, character) if character.is_whitespace() => {
                if !token.is_empty() {
                    tokens.push(std::mem::take(&mut token));
                }
            }
            (None, character) => token.push(character),
        }
    }
    if !token.is_empty() {
        tokens.push(token);
    }
    tokens
}

fn valid_argv(argv: &[String]) -> bool {
    (1..=64).contains(&argv.len())
        && argv
            .iter()
            .all(|argument| !argument.is_empty() && argument.len() <= 4096)
}

fn normalized_tokens(argv: &[String]) -> Vec<String> {
    argv.iter()
        .map(|token| {
            token
                .trim_matches(['\'', '"'])
                .replace('\\', "/")
                .to_ascii_lowercase()
        })
        .collect()
}

fn gateway_subcommand(argv: &[String]) -> Option<String> {
    if !valid_argv(argv) {
        return None;
    }
    let tokens = normalized_tokens(argv);
    for token in &tokens {
        if token == "gateway/run.py" || token.ends_with("/gateway/run.py") {
            return Some("run".into());
        }
        if matches!(
            token.rsplit('/').next(),
            Some("hermes-gateway" | "hermes-gateway.exe")
        ) {
            return Some("run".into());
        }
    }
    let gateway_entry = tokens.iter().any(|token| {
        token == "hermes_cli.main"
            || token.ends_with("/hermes_cli/main.py")
            || matches!(token.rsplit('/').next(), Some("hermes" | "hermes.exe"))
    });
    if !gateway_entry {
        return None;
    }
    let mut filtered = Vec::new();
    let mut index = 0usize;
    while index < tokens.len() {
        let token = &tokens[index];
        if matches!(token.as_str(), "--profile" | "-p") {
            tokens.get(index + 1)?;
            index += 2;
            continue;
        }
        if token.starts_with("--profile=") || token.starts_with("-p=") {
            index += 1;
            continue;
        }
        filtered.push(token.as_str());
        index += 1;
    }
    let gateway = filtered.iter().position(|token| *token == "gateway")?;
    Some(
        filtered
            .get(gateway + 1)
            .copied()
            .unwrap_or("run")
            .to_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[cfg(unix)]
    struct ChildGuard(std::process::Child);

    #[cfg(unix)]
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn observation() -> GatewayObservation {
        GatewayObservation {
            record_present: true,
            record_valid: true,
            lock_held: Some(false),
            process_exists: Some(true),
            start_time_matches: Some(true),
            command_is_gateway: Some(true),
            profile_matches: Some(true),
        }
    }

    #[test]
    fn evaluator_distinguishes_idle_stale_live_and_unverifiable() {
        assert_eq!(
            evaluate_gateway(&GatewayObservation {
                record_present: false,
                record_valid: true,
                lock_held: Some(false),
                process_exists: None,
                start_time_matches: None,
                command_is_gateway: None,
                profile_matches: None,
            }),
            GatewayStatus::Idle
        );
        let mut stale = observation();
        stale.process_exists = Some(false);
        assert_eq!(evaluate_gateway(&stale), GatewayStatus::Stale);
        assert_eq!(evaluate_gateway(&observation()), GatewayStatus::Live);
        for mutate in [
            |value: &mut GatewayObservation| value.record_valid = false,
            |value: &mut GatewayObservation| value.start_time_matches = Some(false),
            |value: &mut GatewayObservation| value.command_is_gateway = Some(false),
            |value: &mut GatewayObservation| value.profile_matches = Some(false),
        ] {
            let mut unverifiable = observation();
            mutate(&mut unverifiable);
            assert_eq!(evaluate_gateway(&unverifiable), GatewayStatus::Unverifiable);
        }
        let held_without_identity = GatewayObservation {
            record_present: false,
            record_valid: true,
            lock_held: Some(true),
            process_exists: None,
            start_time_matches: None,
            command_is_gateway: None,
            profile_matches: None,
        };
        assert_eq!(
            evaluate_gateway(&held_without_identity),
            GatewayStatus::Unverifiable
        );
    }

    #[test]
    fn held_lock_dominates_stale_or_missing_process_identity() {
        let mut dead_unlocked = observation();
        dead_unlocked.process_exists = Some(false);
        assert_eq!(evaluate_gateway(&dead_unlocked), GatewayStatus::Stale);

        let mut dead_locked = dead_unlocked.clone();
        dead_locked.lock_held = Some(true);
        assert_eq!(evaluate_gateway(&dead_locked), GatewayStatus::Unverifiable);

        for (record_present, record_valid) in [(false, true), (true, false)] {
            let held_without_identity = GatewayObservation {
                record_present,
                record_valid,
                lock_held: Some(true),
                process_exists: None,
                start_time_matches: None,
                command_is_gateway: None,
                profile_matches: None,
            };
            assert_eq!(
                evaluate_gateway(&held_without_identity),
                GatewayStatus::Unverifiable
            );
        }

        assert_eq!(evaluate_gateway(&observation()), GatewayStatus::Live);
    }

    #[test]
    fn process_identity_requires_exact_command_and_profile_tokens() {
        let profile = HermesProfile {
            name: "coder".into(),
            hermes_home: PathBuf::from("/tmp/hermes coder"),
        };
        assert!(command_text_is_gateway(
            "/opt/bin/hermes gateway run --profile coder"
        ));
        assert!(!command_text_is_gateway(
            "/opt/bin/not-hermes gateway run --profile coder"
        ));
        assert!(!command_text_is_gateway(
            "/opt/bin/hermes gateway runner --profile coder"
        ));
        assert!(command_text_matches_profile(
            "/opt/bin/hermes gateway run --profile coder",
            &profile
        ));
        assert!(!command_text_matches_profile(
            "/opt/bin/hermes gateway run --profile coder-extra",
            &profile
        ));
        for command in [
            "python /opt/hermes/gateway/run.py -p coder",
            "/opt/bin/hermes-gateway --profile=coder",
            r#""C:\Program Files\Hermes\hermes-gateway.exe" -p=coder"#,
            "python -m hermes_cli.main --profile coder gateway run",
            "python /opt/hermes/hermes_cli/main.py gateway restart -p coder",
            "/opt/bin/hermes --profile coder gateway run",
        ] {
            assert!(command_text_is_gateway(command), "{command}");
            assert!(command_text_matches_profile(command, &profile), "{command}");
        }
        let default = HermesProfile {
            name: "default".into(),
            hermes_home: PathBuf::from("/tmp/hermes"),
        };
        assert!(command_text_matches_profile(
            "/opt/bin/hermes-gateway",
            &default
        ));
        assert!(!command_text_matches_profile(
            "/opt/bin/hermes-gateway --profile writer",
            &default
        ));
    }

    #[test]
    fn readable_live_command_overrides_null_start_record_fallback() {
        let profile = HermesProfile {
            name: "coder".into(),
            hermes_home: PathBuf::from("/tmp/hermes-coder"),
        };
        let record = GatewayIdentityRecord {
            pid: 4242,
            kind: "hermes-gateway".into(),
            argv: vec!["hermes-gateway".into(), "-p".into(), "coder".into()],
            start_time: None,
        };
        let status = |process: ProcessObservation| {
            evaluate_gateway(&GatewayObservation {
                record_present: true,
                record_valid: true,
                lock_held: Some(false),
                process_exists: process.exists,
                start_time_matches: process.start_time_matches,
                command_is_gateway: process.command_is_gateway,
                profile_matches: process.profile_matches,
            })
        };

        let unrelated = inspect_live_process_identity(
            &record,
            &profile,
            Some(123),
            LiveCommandLine::Readable(vec![
                "not-hermes.exe".into(),
                "--profile".into(),
                "coder".into(),
            ]),
        );
        assert_eq!(unrelated.command_is_gateway, Some(false));
        assert_eq!(status(unrelated), GatewayStatus::Unverifiable);

        let wrong_profile = inspect_live_process_identity(
            &record,
            &profile,
            Some(123),
            LiveCommandLine::Readable(vec![
                "hermes-gateway.exe".into(),
                "--profile".into(),
                "writer".into(),
            ]),
        );
        assert_eq!(wrong_profile.command_is_gateway, Some(true));
        assert_eq!(wrong_profile.profile_matches, Some(false));
        assert_eq!(status(wrong_profile), GatewayStatus::Unverifiable);

        let unreadable = inspect_live_process_identity(
            &record,
            &profile,
            Some(123),
            LiveCommandLine::Unreadable,
        );
        assert_eq!(status(unreadable), GatewayStatus::Live);

        let ambiguous =
            inspect_live_process_identity(&record, &profile, Some(123), LiveCommandLine::Ambiguous);
        assert_eq!(ambiguous.command_is_gateway, None);
        assert_eq!(status(ambiguous), GatewayStatus::Unverifiable);

        let malformed = inspect_live_process_identity(
            &record,
            &profile,
            Some(123),
            LiveCommandLine::Readable(Vec::new()),
        );
        assert_eq!(malformed.command_is_gateway, None);
        assert_eq!(status(malformed), GatewayStatus::Unverifiable);
    }

    #[cfg(windows)]
    #[test]
    fn windows_live_command_parser_preserves_quoted_executable_and_profile() {
        let command = r#""C:\Program Files\Hermes\hermes-gateway.exe" --profile "coder""#
            .encode_utf16()
            .collect::<Vec<_>>();
        let argv = windows_command_line_to_argv(&command).unwrap();
        assert_eq!(
            argv,
            [
                r"C:\Program Files\Hermes\hermes-gateway.exe",
                "--profile",
                "coder"
            ]
        );
        assert!(command_is_gateway(&argv));
        assert!(argv_matches_profile(
            &argv,
            &HermesProfile {
                name: "coder".into(),
                hermes_home: PathBuf::from(r"C:\Users\example\.hermes-coder"),
            }
        ));
    }

    #[test]
    fn pinned_pid_and_runtime_records_share_only_the_identity_subset() {
        for release in ["v2026.7.7.2", "v2026.7.7"] {
            let root = tempfile::tempdir().unwrap();
            let profile = HermesProfile {
                name: "coder".into(),
                hermes_home: root.path().to_path_buf(),
            };
            let identity = r#"{"pid":999999,"kind":"hermes-gateway","argv":["/opt/bin/hermes","--profile=coder","gateway","run"],"start_time":123456}"#;
            let runtime = r#"{"pid":999999,"kind":"hermes-gateway","argv":["/opt/bin/hermes","--profile=coder","gateway","run"],"start_time":123456,"gateway_state":"running","exit_reason":null,"restart_requested":false,"active_agents":2,"platforms":{"telegram":{"state":"running","error_code":null,"error_message":null,"updated_at":"2026-07-07T12:00:00+00:00"}},"updated_at":"2026-07-07T12:00:00+00:00","served_profiles":["coder"]}"#;
            fs::write(root.path().join("gateway.pid"), identity).unwrap();
            fs::write(root.path().join("gateway_state.json"), runtime).unwrap();

            assert_eq!(
                inspect_gateway(&profile).unwrap(),
                GatewayStatus::Stale,
                "{release}"
            );

            fs::remove_file(root.path().join("gateway.pid")).unwrap();
            assert_eq!(
                inspect_gateway(&profile).unwrap(),
                GatewayStatus::Stale,
                "{release} runtime-only"
            );
        }
    }

    #[test]
    fn pinned_gateway_record_disagreement_and_pid_reuse_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let profile = HermesProfile {
            name: "coder".into(),
            hermes_home: root.path().to_path_buf(),
        };
        fs::write(
            root.path().join("gateway.pid"),
            r#"{"pid":999998,"kind":"hermes-gateway","argv":["hermes-gateway","-p","coder"],"start_time":123456}"#,
        )
        .unwrap();
        fs::write(
            root.path().join("gateway_state.json"),
            r#"{"pid":999999,"kind":"hermes-gateway","argv":["hermes-gateway","-p","coder"],"start_time":123456,"gateway_state":"running","exit_reason":null,"restart_requested":false,"active_agents":0,"platforms":{},"updated_at":"2026-07-07T12:00:00+00:00"}"#,
        )
        .unwrap();
        assert_eq!(
            inspect_gateway(&profile).unwrap(),
            GatewayStatus::Unverifiable
        );
        assert!(
            !format!("{:?}", require_gateway_idle(&profile).unwrap_err())
                .contains("must-not-enter-errors")
        );

        let mut reused = observation();
        reused.start_time_matches = Some(false);
        assert_eq!(evaluate_gateway(&reused), GatewayStatus::Unverifiable);
    }

    #[test]
    fn pinned_gateway_schemas_reject_unknown_fields_and_accept_null_start_time() {
        let root = tempfile::tempdir().unwrap();
        let profile = HermesProfile {
            name: "default".into(),
            hermes_home: root.path().to_path_buf(),
        };
        fs::write(
            root.path().join("gateway.pid"),
            r#"{"pid":999999,"kind":"hermes-gateway","argv":["hermes-gateway"],"start_time":null}"#,
        )
        .unwrap();
        assert_eq!(inspect_gateway(&profile).unwrap(), GatewayStatus::Stale);

        fs::write(
            root.path().join("gateway_state.json"),
            r#"{"pid":999999,"kind":"hermes-gateway","argv":["hermes-gateway"],"start_time":null,"gateway_state":"running","exit_reason":null,"restart_requested":false,"active_agents":0,"platforms":{},"updated_at":"2026-07-07T12:00:00+00:00","unknown":"must-not-enter-errors"}"#,
        )
        .unwrap();
        assert_eq!(
            inspect_gateway(&profile).unwrap(),
            GatewayStatus::Unverifiable
        );
    }

    #[test]
    fn platform_start_fingerprint_units_match_the_pinned_contract() {
        let mut fields = vec!["S".to_owned()];
        fields.extend((4..=21).map(|field| field.to_string()));
        fields.push("424242".into());
        let stat = format!("123 (command with ) spaces) {}", fields.join(" "));
        assert_eq!(linux_start_time_from_stat(stat.as_bytes()), Some(424242));
        assert_eq!(
            windows_filetime_centiseconds(116_444_736_000_000_000),
            Some(0)
        );
        assert_eq!(
            windows_filetime_centiseconds(116_444_737_234_500_000),
            Some(12_345)
        );
        assert_eq!(windows_filetime_centiseconds(1), None);
        assert_eq!(epoch_centiseconds(10, 5_000), Some(1_000));
        assert_eq!(epoch_centiseconds(10, 15_000), Some(1_002));

        #[cfg(target_os = "macos")]
        {
            let first = process_start_time(std::process::id()).unwrap();
            let second = process_start_time(std::process::id()).unwrap();
            assert_eq!(first, second);
            assert!(first > 100_000_000_000);
        }
    }

    #[cfg(unix)]
    #[test]
    fn live_gateway_record_matches_and_recycled_start_fingerprint_does_not() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let gateway_dir = root.path().join("gateway");
        fs::create_dir(&gateway_dir).unwrap();
        let executable = gateway_dir.join("run.py");
        fs::write(&executable, "#!/bin/sh\nsleep 30 &\nwait\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let child = std::process::Command::new(&executable)
            .args(["-p", "coder"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let child = ChildGuard(child);
        let mut start_time = None;
        for _ in 0..100 {
            start_time = process_start_time(child.0.id());
            if start_time.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let start_time = start_time.unwrap();
        let profile = HermesProfile {
            name: "coder".into(),
            hermes_home: root.path().to_path_buf(),
        };
        let record = |start_time| {
            serde_json::json!({
                "pid": child.0.id(),
                "kind": "hermes-gateway",
                "argv": [executable.to_string_lossy(), "-p", "coder"],
                "start_time": start_time,
            })
            .to_string()
        };
        fs::write(root.path().join("gateway.pid"), record(start_time)).unwrap();
        assert_eq!(inspect_gateway(&profile).unwrap(), GatewayStatus::Live);

        fs::write(
            root.path().join("gateway.pid"),
            record(start_time.saturating_add(1)),
        )
        .unwrap();
        assert_eq!(
            inspect_gateway(&profile).unwrap(),
            GatewayStatus::Unverifiable
        );
    }
}
