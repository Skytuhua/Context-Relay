use std::{
    fs::{self, OpenOptions},
    io::Read,
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use context_relay_protocol::ClientError;
use serde::Deserialize;

use super::{HermesProfile, conflict};

const MAX_RECORD_BYTES: u64 = 16 * 1024;
const PROCESS_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const PROCESS_OUTPUT_LIMIT: u64 = 16 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum GatewayStatus {
    Idle,
    Stale,
    Live,
    Unverifiable,
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
struct GatewayRecord {
    pid: u32,
    kind: String,
    argv: Vec<String>,
    start_time: serde_json::Value,
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
    match observation.process_exists {
        Some(false) => GatewayStatus::Stale,
        Some(true)
            if observation.start_time_matches == Some(true)
                && observation.command_is_gateway == Some(true)
                && observation.profile_matches == Some(true) =>
        {
            GatewayStatus::Live
        }
        Some(true) => GatewayStatus::Unverifiable,
        None => GatewayStatus::Unverifiable,
    }
}

pub(super) fn inspect_gateway(profile: &HermesProfile) -> Result<GatewayStatus, ClientError> {
    let pid_record = read_record(&profile.hermes_home.join("gateway.pid"));
    let state_record = read_record(&profile.hermes_home.join("gateway_state.json"));
    let record_present = pid_record.is_some() || state_record.is_some();
    let records = [pid_record, state_record];
    let mut record_valid = true;
    let mut selected = None;
    for record in records.into_iter().flatten() {
        match record {
            Ok(record)
                if selected
                    .as_ref()
                    .is_none_or(|selected: &GatewayRecord| selected == &record) =>
            {
                selected = Some(record);
            }
            Ok(_) | Err(()) => record_valid = false,
        }
    }
    let lock_held = probe_lock(&profile.hermes_home.join("gateway.lock"));
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

fn read_record(path: &Path) -> Option<Result<GatewayRecord, ()>> {
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
    let record = serde_json::from_slice::<GatewayRecord>(&bytes)
        .ok()
        .filter(valid_record)
        .ok_or(());
    Some(record)
}

fn valid_record(record: &GatewayRecord) -> bool {
    record.pid > 0
        && record.kind == "gateway"
        && (1..=64).contains(&record.argv.len())
        && record
            .argv
            .iter()
            .all(|argument| !argument.is_empty() && argument.len() <= 4096)
        && matches!(
            record.start_time,
            serde_json::Value::String(_) | serde_json::Value::Number(_)
        )
}

struct ProcessObservation {
    exists: Option<bool>,
    start_time_matches: Option<bool>,
    command_is_gateway: Option<bool>,
    profile_matches: Option<bool>,
}

#[cfg(unix)]
fn inspect_process(record: &GatewayRecord, profile: &HermesProfile) -> ProcessObservation {
    let exists = process_exists_unix(record.pid);
    if exists != Some(true) {
        return ProcessObservation {
            exists,
            start_time_matches: None,
            command_is_gateway: None,
            profile_matches: None,
        };
    }
    let Some((start_time, command)) = ps_process(record.pid) else {
        return ProcessObservation {
            exists,
            start_time_matches: None,
            command_is_gateway: None,
            profile_matches: None,
        };
    };
    let record_start = match &record.start_time {
        serde_json::Value::String(value) => Some(value.trim()),
        serde_json::Value::Number(_) => None,
        _ => None,
    };
    let record_command_ok = command_is_gateway(&record.argv);
    let record_profile_ok = argv_matches_profile(&record.argv, profile);
    ProcessObservation {
        exists,
        start_time_matches: record_start.map(|value| value == start_time),
        command_is_gateway: Some(record_command_ok && command_text_is_gateway(&command)),
        profile_matches: Some(record_profile_ok && command_text_matches_profile(&command, profile)),
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

#[cfg(unix)]
fn ps_process(pid: u32) -> Option<(String, String)> {
    let executable = if Path::new("/bin/ps").is_file() {
        "/bin/ps"
    } else if Path::new("/usr/bin/ps").is_file() {
        "/usr/bin/ps"
    } else {
        return None;
    };
    let mut child = Command::new(executable)
        .args(["-p", &pid.to_string(), "-o", "lstart=", "-o", "command="])
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
    let output = std::str::from_utf8(&bytes).ok()?.trim();
    let mut fields = output.split_whitespace();
    let start = (0..5)
        .map(|_| fields.next())
        .collect::<Option<Vec<_>>>()?
        .join(" ");
    let command = fields.collect::<Vec<_>>().join(" ");
    (!command.is_empty()).then_some((start, command))
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
fn inspect_process(record: &GatewayRecord, profile: &HermesProfile) -> ProcessObservation {
    use std::{mem::MaybeUninit, os::windows::ffi::OsStringExt as _};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, ERROR_INVALID_PARAMETER, FILETIME, GetLastError, STILL_ACTIVE},
        System::Threading::{
            GetExitCodeProcess, GetProcessTimes, OpenProcess, PROCESS_NAME_WIN32,
            PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW, SYNCHRONIZE,
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
    let mut path = vec![0u16; 32_768];
    let mut length = path.len() as u32;
    let exit_ok = unsafe { GetExitCodeProcess(handle, &mut exit_code) } != 0;
    let live = exit_ok && exit_code == STILL_ACTIVE;
    let times_ok = unsafe {
        GetProcessTimes(
            handle,
            creation.as_mut_ptr(),
            exit.as_mut_ptr(),
            kernel.as_mut_ptr(),
            user.as_mut_ptr(),
        )
    } != 0;
    let path_ok = unsafe {
        QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, path.as_mut_ptr(), &mut length)
    } != 0;
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
    let record_ticks = record.start_time.as_u64();
    let image = path_ok.then(|| {
        std::ffi::OsString::from_wide(&path[..length as usize])
            .to_string_lossy()
            .to_ascii_lowercase()
    });
    let image_is_hermes = image
        .as_deref()
        .is_some_and(|value| value.ends_with("\\hermes.exe") || value.ends_with("/hermes.exe"));
    ProcessObservation {
        exists: Some(true),
        start_time_matches: match (record_ticks, creation_ticks) {
            (Some(record), Some(actual)) => Some(record == actual),
            _ => None,
        },
        command_is_gateway: Some(image_is_hermes && command_is_gateway(&record.argv)),
        profile_matches: Some(argv_matches_profile(&record.argv, profile)),
    }
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
    argv.first()
        .and_then(|argument| {
            Path::new(argument)
                .file_stem()
                .and_then(|stem| stem.to_str())
        })
        .is_some_and(|stem| stem.eq_ignore_ascii_case("hermes"))
        && argv
            .windows(2)
            .any(|parts| parts[0] == "gateway" && parts[1] == "run")
}

fn argv_matches_profile(argv: &[String], profile: &HermesProfile) -> bool {
    let named = argv
        .windows(2)
        .any(|parts| parts[0] == "--profile" && parts[1] == profile.name);
    let canonical = profile.hermes_home.to_string_lossy();
    let home = argv
        .windows(2)
        .any(|parts| parts[0] == "--hermes-home" && Path::new(&parts[1]) == profile.hermes_home)
        || argv
            .iter()
            .any(|part| part == &format!("HERMES_HOME={canonical}"));
    named || home
}

fn command_text_is_gateway(command: &str) -> bool {
    let tokens = command_tokens(command);
    tokens.iter().any(|token| {
        Path::new(token)
            .file_stem()
            .and_then(|stem| stem.to_str())
            .is_some_and(|stem| stem.eq_ignore_ascii_case("hermes"))
    }) && tokens
        .windows(2)
        .any(|parts| parts[0] == "gateway" && parts[1] == "run")
}

fn command_text_matches_profile(command: &str, profile: &HermesProfile) -> bool {
    let tokens = command_tokens(command);
    tokens
        .windows(2)
        .any(|parts| parts[0] == "--profile" && parts[1] == profile.name)
        || tokens
            .iter()
            .any(|part| part == &format!("--profile={}", profile.name))
        || tokens
            .iter()
            .any(|part| part == &format!("HERMES_HOME={}", profile.hermes_home.to_string_lossy()))
}

fn command_tokens(command: &str) -> Vec<String> {
    command
        .split_whitespace()
        .map(|token| token.trim_matches(['\'', '"']).to_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

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
    }
}
