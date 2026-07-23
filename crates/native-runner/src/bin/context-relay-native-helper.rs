use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
    thread,
    time::{Duration, Instant},
};

#[cfg(windows)]
use std::collections::BTreeMap;

#[cfg(windows)]
use std::{
    ffi::{OsStr, OsString, c_void},
    io::{Seek, SeekFrom},
    mem::size_of,
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::{AsRawHandle, FromRawHandle},
    },
    ptr::{null, null_mut},
};

use context_relay_native_runner::{
    ClosureMaterial, ContentFrame, FailureCode, HelperRunRequest, RestrictedEnvironment,
    RunDisposition, RunLimits, RunRequest, RunResponse, RunStats, RunnerError, RuntimeTarget,
    SidecarCommand, StagePath, read_helper_request, validate_gitleaks_report,
    validate_rulesync_outputs, validate_semgrep_report, write_run_response_for,
};
use sha2::{Digest, Sha256};

#[cfg(windows)]
use context_relay_native_runner::{StageDirectory, StageLayout, validate_path_set};

#[cfg(not(windows))]
use context_relay_native_runner::{
    NativeState, NativeTreeInventory, OsNativeFileSystem, PrivateStage, inspect_native_tree,
};

#[cfg(target_os = "macos")]
use std::os::unix::process::CommandExt;

#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::{
        ERROR_HANDLE_EOF, ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, ERROR_NO_MORE_FILES,
        GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE, INVALID_HANDLE_VALUE, NTSTATUS,
        OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE, RtlNtStatusToDosError,
        STATUS_REPARSE_POINT_ENCOUNTERED, STATUS_STOPPED_ON_SYMLINK, UNICODE_STRING,
    },
    Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
        FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_ID_BOTH_DIR_INFO, FILE_ID_INFO,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO, FILE_STREAM_INFO,
        FileAttributeTagInfo, FileBasicInfo, FileIdBothDirectoryInfo,
        FileIdBothDirectoryRestartInfo, FileIdInfo, FileStandardInfo, FileStreamInfo,
        GetFileInformationByHandleEx, OPEN_EXISTING, SYNCHRONIZE,
    },
};

const GITLEAKS_POLICY: &[u8] =
    include_bytes!("../../../../third_party/sidecars/policies/gitleaks.toml");
const GITLEAKS_EMPTY_IGNORE: &[u8] =
    include_bytes!("../../../../third_party/sidecars/policies/gitleaks.empty-ignore");
const SEMGREP_POLICY: &[u8] =
    include_bytes!("../../../../third_party/sidecars/policies/semgrep-package.yml");
const DRAIN_LIMIT: usize = 8 * 1024 * 1024;

fn main() -> ExitCode {
    if std::env::args_os().len() != 1 {
        return ExitCode::from(2);
    }
    let helper_request = match read_helper_request(&mut std::io::stdin().lock()) {
        Ok(request) => request,
        Err(_) => return ExitCode::from(2),
    };
    #[cfg(windows)]
    if context_relay_native_runner::windows::seal_protocol_handles_before_sidecar().is_err() {
        return ExitCode::from(2);
    }
    let request = helper_request.request();
    let response = match execute(&helper_request) {
        Ok(response) => response,
        Err(error) => RunResponse::failed(failure_code(error)),
    };
    if write_run_response_for(&mut std::io::stdout().lock(), request, &response).is_err() {
        return ExitCode::from(2);
    }
    ExitCode::SUCCESS
}

fn execute(helper_request: &HelperRunRequest) -> Result<RunResponse, RunnerError> {
    let request = helper_request.request();
    let target = RuntimeTarget::current()?;
    let executable = verified_executable(helper_request, target)?;
    let mut stage = prepare_stage(request.nonce(), target)?;
    let config_inventory = install_trusted_config(&mut stage, request.command(), target)?;
    let input_inventory = stage.write_and_seal_inputs(request.inputs())?;
    validate_pre_enumeration(request)?;
    let limits = RunLimits::for_command(request.command());
    let environment = RestrictedEnvironment::for_stage(stage.layout(), target)?;
    let argv = request.command().argv();
    let started = Instant::now();
    let mut command = Command::new(executable.path());
    command
        .args(&argv[1..])
        .current_dir(stage.layout().root())
        .env_clear()
        .envs(environment.iter())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(target_os = "macos")]
    unsafe {
        command.pre_exec(|| {
            let real_uid = libc::getuid();
            let effective_uid = libc::geteuid();
            let real_gid = libc::getgid();
            let effective_gid = libc::getegid();
            if !identity_can_rely_on_nproc(real_uid, effective_uid, real_gid, effective_gid) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "refusing root or set-ID helper execution",
                ));
            }
            let no_children = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::setrlimit(libc::RLIMIT_NPROC, &no_children) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .map_err(|_| RunnerError::SidecarUnavailable)?;
    let stdout = child.stdout.take().ok_or(RunnerError::Io)?;
    let stderr = child.stderr.take().ok_or(RunnerError::Io)?;
    let stdout = thread::spawn(move || drain_bounded(stdout, DRAIN_LIMIT));
    let stderr = thread::spawn(move || drain_bounded(stderr, DRAIN_LIMIT));
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|_| RunnerError::Io)? {
            break status;
        }
        if started.elapsed() >= Duration::from_millis(u64::from(limits.timeout_ms())) {
            kill_child_tree(&mut child);
            let _ = child.wait();
            let _ = stdout.join();
            let _ = stderr.join();
            return Ok(RunResponse::failed(FailureCode::TimedOut));
        }
        thread::sleep(Duration::from_millis(5));
    };
    let stdout = stdout.join().map_err(|_| RunnerError::Io)??;
    let stderr = stderr.join().map_err(|_| RunnerError::Io)??;
    executable
        .verify_unchanged()
        .map_err(|_| RunnerError::ClosureMismatch)?;
    input_inventory.verify_unchanged()?;
    if let Some(inventory) = config_inventory {
        inventory.verify_unchanged()?;
    }
    let duration_ms =
        u32::try_from(started.elapsed().as_millis()).map_err(|_| RunnerError::LimitExceeded)?;
    let scanned_files =
        u32::try_from(request.inputs().len()).map_err(|_| RunnerError::LimitExceeded)?;
    let scanned_bytes = request.inputs().iter().try_fold(0_u64, |total, input| {
        total
            .checked_add(input.bytes().len() as u64)
            .ok_or(RunnerError::LimitExceeded)
    })?;
    let stats = RunStats::new(scanned_files, scanned_bytes, duration_ms);
    let exit = status.code().ok_or(RunnerError::InvalidToolOutput)?;
    match request.command() {
        SidecarCommand::RuleSyncGenerate { .. } => {
            let outputs = stage.read_outputs(limits)?;
            request.command().validate_rulesync_exit(
                exit,
                &stdout,
                &stderr,
                !outputs.is_empty(),
            )?;
            validate_rulesync_outputs(request.command(), request.inputs(), &outputs)?;
            RunResponse::completed(RunDisposition::Generated, outputs, stats, limits)
        }
        SidecarCommand::GitleaksScanPackage => {
            let (disposition, report) =
                validate_gitleaks_report(exit, &stdout, &stderr, request.inputs())?;
            RunResponse::completed(
                disposition,
                vec![ContentFrame::new(
                    StagePath::try_from("reports/gitleaks.json")?,
                    report,
                )?],
                stats,
                limits,
            )
        }
        SidecarCommand::OsemgrepScanPackage => {
            let (disposition, report) =
                validate_semgrep_report(exit, &stdout, &stderr, request.inputs())?;
            RunResponse::completed(
                disposition,
                vec![ContentFrame::new(
                    StagePath::try_from("reports/semgrep.json")?,
                    report,
                )?],
                stats,
                limits,
            )
        }
    }
}

#[cfg(any(target_os = "macos", test))]
const fn identity_can_rely_on_nproc(
    real_uid: u32,
    effective_uid: u32,
    real_gid: u32,
    effective_gid: u32,
) -> bool {
    real_uid != 0 && effective_uid != 0 && real_uid == effective_uid && real_gid == effective_gid
}

fn verified_executable(
    request: &HelperRunRequest,
    target: RuntimeTarget,
) -> Result<VerifiedExecutable, RunnerError> {
    let root = runtime_closure_root()?;
    #[cfg(windows)]
    {
        let inventory = LocalTreeInventory::capture(&root, target, LocalTreeLimits::unbounded())
            .map_err(|_| RunnerError::ClosureMismatch)?;
        let actual_files = inventory
            .file_paths()
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        let actual_directories = inventory.directory_paths();
        let expected_files = request
            .closure()
            .iter()
            .map(|material| material.path().as_str().to_owned())
            .collect::<BTreeSet<_>>();
        if actual_files != expected_files
            || actual_directories != expected_runtime_directories(request.closure())
        {
            return Err(RunnerError::ClosureMismatch);
        }
        let mut executable = None;
        for material in request.closure() {
            let entry = inventory
                .entries
                .iter()
                .find(|entry| entry.snapshot.path == *material.path())
                .ok_or(RunnerError::ClosureMismatch)?;
            if entry.snapshot.directory
                || entry.snapshot.size != material.size()
                || entry.snapshot.digest != *material.sha256()
            {
                return Err(RunnerError::ClosureMismatch);
            }
            if material.executable() {
                executable = Some(
                    material
                        .path()
                        .as_str()
                        .split('/')
                        .fold(root.clone(), |path, component| path.join(component)),
                );
            }
        }
        inventory
            .verify_unchanged()
            .map_err(|_| RunnerError::ClosureMismatch)?;
        Ok(VerifiedExecutable {
            path: executable.ok_or(RunnerError::ClosureMismatch)?,
            _local_inventory: inventory,
        })
    }
    #[cfg(not(windows))]
    {
        let inventory =
            inspect_native_tree(&root, target).map_err(|_| RunnerError::ClosureMismatch)?;
        let (actual_files, actual_directories) =
            enumerate_runtime_closure(&root).map_err(|_| RunnerError::ClosureMismatch)?;
        let expected_files = request
            .closure()
            .iter()
            .map(|material| material.path().as_str().to_owned())
            .collect::<BTreeSet<_>>();
        let expected_directories = expected_runtime_directories(request.closure());
        if actual_files != expected_files || actual_directories != expected_directories {
            return Err(RunnerError::ClosureMismatch);
        }
        let filesystem = OsNativeFileSystem::new();
        let mut executable = None;
        for material in request.closure() {
            let path = material
                .path()
                .as_str()
                .split('/')
                .fold(root.to_path_buf(), |path, component| path.join(component));
            let snapshot = filesystem
                .snapshot(&path)
                .map_err(|_| RunnerError::ClosureMismatch)?;
            let NativeState::RegularFile { bytes, metadata } = snapshot.state() else {
                return Err(RunnerError::ClosureMismatch);
            };
            if !metadata.alternate_streams().is_empty()
                || bytes.len() as u64 != material.size()
                || Sha256::digest(bytes).as_slice() != material.sha256()
            {
                return Err(RunnerError::ClosureMismatch);
            }
            if material.executable() {
                executable = Some(path);
            }
        }
        inventory
            .verify_unchanged()
            .map_err(|_| RunnerError::ClosureMismatch)?;
        Ok(VerifiedExecutable {
            path: executable.ok_or(RunnerError::ClosureMismatch)?,
            #[cfg(target_os = "macos")]
            _native_inventory: inventory,
        })
    }
}

struct VerifiedExecutable {
    path: PathBuf,
    #[cfg(windows)]
    _local_inventory: LocalTreeInventory,
    #[cfg(target_os = "macos")]
    _native_inventory: NativeTreeInventory,
}

impl VerifiedExecutable {
    fn path(&self) -> &Path {
        &self.path
    }

    fn verify_unchanged(&self) -> Result<(), RunnerError> {
        #[cfg(windows)]
        {
            self._local_inventory.verify_unchanged()
        }
        #[cfg(target_os = "macos")]
        {
            self._native_inventory.verify_unchanged()
        }
        #[cfg(not(any(windows, target_os = "macos")))]
        {
            Ok(())
        }
    }
}

fn runtime_closure_root() -> Result<PathBuf, RunnerError> {
    let executable = std::env::current_exe().map_err(|_| RunnerError::Io)?;
    #[cfg(windows)]
    {
        executable
            .parent()
            .map(|parent| parent.join("runtime"))
            .ok_or(RunnerError::ClosureMismatch)
    }
    #[cfg(target_os = "macos")]
    {
        executable
            .parent()
            .and_then(Path::parent)
            .map(|contents| contents.join("Helpers").join("runtime"))
            .ok_or(RunnerError::ClosureMismatch)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = executable;
        Err(RunnerError::UnsupportedTarget)
    }
}

#[cfg(not(windows))]
fn enumerate_runtime_closure(
    root: &Path,
) -> Result<(BTreeSet<String>, BTreeSet<String>), RunnerError> {
    fn visit(
        root: &Path,
        directory: &Path,
        files: &mut BTreeSet<String>,
        directories: &mut BTreeSet<String>,
    ) -> Result<(), RunnerError> {
        for entry in fs::read_dir(directory).map_err(|_| RunnerError::ClosureMismatch)? {
            let entry = entry.map_err(|_| RunnerError::ClosureMismatch)?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|_| RunnerError::ClosureMismatch)?;
            if metadata.file_type().is_symlink() {
                return Err(RunnerError::ClosureMismatch);
            }
            let relative = path
                .strip_prefix(root)
                .map_err(|_| RunnerError::ClosureMismatch)?;
            let relative = relative
                .components()
                .map(|component| {
                    component
                        .as_os_str()
                        .to_str()
                        .ok_or(RunnerError::ClosureMismatch)
                })
                .collect::<Result<Vec<_>, _>>()?
                .join("/");
            let relative = StagePath::try_from(relative)?.as_str().to_owned();
            if metadata.is_dir() {
                if !directories.insert(relative) {
                    return Err(RunnerError::ClosureMismatch);
                }
                visit(root, &path, files, directories)?;
            } else if metadata.is_file() {
                if !files.insert(relative) {
                    return Err(RunnerError::ClosureMismatch);
                }
            } else {
                return Err(RunnerError::ClosureMismatch);
            }
            if files.len() + directories.len() > 512 {
                return Err(RunnerError::LimitExceeded);
            }
        }
        Ok(())
    }
    let mut files = BTreeSet::new();
    let mut directories = BTreeSet::new();
    visit(root, root, &mut files, &mut directories)?;
    Ok((files, directories))
}

fn expected_runtime_directories(materials: &[ClosureMaterial]) -> BTreeSet<String> {
    let mut directories = BTreeSet::new();
    for material in materials {
        let mut components = material.path().as_str().split('/').collect::<Vec<_>>();
        components.pop();
        while !components.is_empty() {
            directories.insert(components.join("/"));
            components.pop();
        }
    }
    directories
}

#[cfg(windows)]
const LOCAL_TREE_MAX_ENTRIES: usize = 512;
#[cfg(windows)]
const LOCAL_TREE_MAX_BYTES: usize = 768 * 1024 * 1024;
#[cfg(windows)]
const LOCAL_TREE_MAX_DEPTH: usize = 64;
#[cfg(windows)]
const DEFAULT_STREAM: &str = "::$DATA";
#[cfg(windows)]
const FILE_OPEN: u32 = 1;
#[cfg(windows)]
const FILE_CREATE: u32 = 2;
#[cfg(windows)]
const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
#[cfg(windows)]
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
#[cfg(windows)]
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
#[cfg(windows)]
const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

#[cfg(windows)]
#[derive(Clone, Copy)]
struct LocalTreeLimits {
    max_entries: usize,
    max_files: usize,
    max_file_bytes: usize,
    max_total_bytes: usize,
}

#[cfg(windows)]
impl LocalTreeLimits {
    const fn unbounded() -> Self {
        Self {
            max_entries: LOCAL_TREE_MAX_ENTRIES,
            max_files: LOCAL_TREE_MAX_ENTRIES,
            max_file_bytes: LOCAL_TREE_MAX_BYTES,
            max_total_bytes: LOCAL_TREE_MAX_BYTES,
        }
    }

    const fn for_outputs(limits: RunLimits) -> Self {
        Self {
            max_entries: LOCAL_TREE_MAX_ENTRIES,
            max_files: limits.max_files(),
            max_file_bytes: limits.max_file_bytes(),
            max_total_bytes: limits.max_total_bytes(),
        }
    }
}

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct LocalNodeSnapshot {
    path: StagePath,
    directory: bool,
    volume: u64,
    object: [u8; 16],
    attributes: u32,
    links: u64,
    size: u64,
    creation_time: i64,
    last_write_time: i64,
    digest: [u8; 32],
}

#[cfg(windows)]
struct LocalEntry {
    snapshot: LocalNodeSnapshot,
    handle: fs::File,
}

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct LocalRootSnapshot {
    volume: u64,
    object: [u8; 16],
    attributes: u32,
    links: u64,
    creation_time: i64,
    last_write_time: i64,
}

#[cfg(windows)]
struct LocalTreeInventory {
    root: PathBuf,
    target: RuntimeTarget,
    limits: LocalTreeLimits,
    root_snapshot: LocalRootSnapshot,
    entries: Vec<LocalEntry>,
    _root_handle: fs::File,
}

#[cfg(windows)]
struct LocalCaptureState {
    entry_count: usize,
    files: usize,
    total_bytes: usize,
    identities: BTreeSet<(u64, [u8; 16])>,
    entries: Vec<LocalEntry>,
}

#[cfg(windows)]
impl LocalTreeInventory {
    fn capture(
        root: &Path,
        target: RuntimeTarget,
        limits: LocalTreeLimits,
    ) -> Result<Self, RunnerError> {
        if !root.is_absolute() || !root.is_dir() {
            return Err(RunnerError::InvalidStage);
        }
        let root_handle = open_local_root(root, FILE_SHARE_READ)?;
        let initial_root = local_raw_node(&root_handle)?;
        if !safe_local_node(&initial_root, true, initial_root.volume)
            || has_named_streams(&root_handle)?
        {
            return Err(RunnerError::UnsafeTopology);
        }
        let reopened =
            open_local_root(root, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)?;
        let reopened_root = local_raw_node(&reopened)?;
        let root_node = local_raw_node(&root_handle)?;
        if !same_local_node(&initial_root, &root_node)
            || !same_local_node(&root_node, &reopened_root)
        {
            return Err(RunnerError::ConcurrentChange);
        }
        if !safe_local_node(&root_node, true, root_node.volume)
            || !safe_local_node(&reopened_root, true, root_node.volume)
            || has_named_streams(&root_handle)?
            || has_named_streams(&reopened)?
        {
            return Err(RunnerError::UnsafeTopology);
        }
        let mut state = LocalCaptureState {
            entry_count: 0,
            files: 0,
            total_bytes: 0,
            identities: BTreeSet::from([local_identity(&root_node)]),
            entries: Vec::new(),
        };
        capture_local_children(&root_handle, "", 0, root_node.volume, limits, &mut state)?;
        let final_root = local_raw_node(&root_handle)?;
        let final_reopened_root = local_raw_node(&reopened)?;
        if !same_local_node(&root_node, &final_root)
            || !same_local_node(&final_root, &final_reopened_root)
        {
            return Err(RunnerError::ConcurrentChange);
        }
        if !safe_local_node(&final_root, true, root_node.volume)
            || !safe_local_node(&final_reopened_root, true, root_node.volume)
            || has_named_streams(&root_handle)?
            || has_named_streams(&reopened)?
        {
            return Err(RunnerError::UnsafeTopology);
        }
        let root_snapshot = LocalRootSnapshot {
            volume: final_root.volume,
            object: final_root.object,
            attributes: final_root.attributes,
            links: final_root.links,
            creation_time: final_root.creation_time,
            last_write_time: final_root.last_write_time,
        };
        let paths = state
            .entries
            .iter()
            .map(|entry| entry.snapshot.path.clone())
            .collect::<Vec<_>>();
        validate_path_set(target, &paths)?;
        state
            .entries
            .sort_by(|left, right| left.snapshot.path.cmp(&right.snapshot.path));
        Ok(Self {
            root: root.to_path_buf(),
            target,
            limits,
            root_snapshot,
            entries: state.entries,
            _root_handle: root_handle,
        })
    }

    fn file_paths(&self) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|entry| !entry.snapshot.directory)
            .map(|entry| entry.snapshot.path.as_str())
            .collect()
    }

    fn directory_paths(&self) -> BTreeSet<String> {
        self.entries
            .iter()
            .filter(|entry| entry.snapshot.directory)
            .map(|entry| entry.snapshot.path.as_str().to_owned())
            .collect()
    }

    fn verify_unchanged(&self) -> Result<(), RunnerError> {
        let current = Self::capture(&self.root, self.target, self.limits)?;
        if current.root_snapshot != self.root_snapshot {
            return Err(RunnerError::ConcurrentChange);
        }
        let expected = self
            .entries
            .iter()
            .map(|entry| &entry.snapshot)
            .collect::<Vec<_>>();
        let actual = current
            .entries
            .iter()
            .map(|entry| &entry.snapshot)
            .collect::<Vec<_>>();
        (actual == expected)
            .then_some(())
            .ok_or(RunnerError::ConcurrentChange)
    }

    fn read_file(&self, path: &StagePath) -> Result<Vec<u8>, RunnerError> {
        let entry = self
            .entries
            .iter()
            .find(|entry| &entry.snapshot.path == path && !entry.snapshot.directory)
            .ok_or(RunnerError::UnsafeTopology)?;
        read_local_bytes(
            &entry.handle,
            usize::try_from(entry.snapshot.size).map_err(|_| RunnerError::LimitExceeded)?,
        )
    }
}

#[cfg(windows)]
fn local_directory_names(
    directory: &fs::File,
    remaining: usize,
) -> Result<Vec<OsString>, RunnerError> {
    const BUFFER_BYTES: usize = 64 * 1024;
    let header = std::mem::offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);
    let mut names = Vec::new();
    let mut restart = true;
    loop {
        let mut buffer = vec![0_u64; BUFFER_BYTES.div_ceil(size_of::<u64>())];
        let class = if restart {
            FileIdBothDirectoryRestartInfo
        } else {
            FileIdBothDirectoryInfo
        };
        if unsafe {
            GetFileInformationByHandleEx(
                directory.as_raw_handle() as HANDLE,
                class,
                buffer.as_mut_ptr().cast(),
                BUFFER_BYTES as u32,
            )
        } == 0
        {
            let error = unsafe { GetLastError() };
            if matches!(error, ERROR_NO_MORE_FILES | ERROR_HANDLE_EOF) {
                break;
            }
            return Err(RunnerError::Io);
        }
        restart = false;
        let base = buffer.as_ptr().cast::<u8>();
        let mut offset = 0_usize;
        loop {
            if offset
                .checked_add(header)
                .is_none_or(|end| end > BUFFER_BYTES)
            {
                return Err(RunnerError::Io);
            }
            let info = unsafe {
                std::ptr::read_unaligned(base.add(offset).cast::<FILE_ID_BOTH_DIR_INFO>())
            };
            let name_bytes = usize::try_from(info.FileNameLength).map_err(|_| RunnerError::Io)?;
            if name_bytes == 0
                || name_bytes % 2 != 0
                || offset
                    .checked_add(header)
                    .and_then(|start| start.checked_add(name_bytes))
                    .is_none_or(|end| end > BUFFER_BYTES)
            {
                return Err(RunnerError::Io);
            }
            let units = unsafe {
                std::slice::from_raw_parts(
                    base.add(offset + header).cast::<u16>(),
                    name_bytes / size_of::<u16>(),
                )
            };
            let name = OsString::from_wide(units);
            if name != "." && name != ".." {
                names.push(name);
                if names.len() > remaining {
                    return Err(RunnerError::LimitExceeded);
                }
            }
            if info.NextEntryOffset == 0 {
                break;
            }
            let next = info.NextEntryOffset as usize;
            if next < header + name_bytes
                || offset
                    .checked_add(next)
                    .is_none_or(|end| end >= BUFFER_BYTES)
            {
                return Err(RunnerError::Io);
            }
            offset += next;
        }
    }
    names.sort_unstable();
    if names.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(RunnerError::UnsafeTopology);
    }
    Ok(names)
}

#[cfg(windows)]
fn capture_local_children(
    directory: &fs::File,
    prefix: &str,
    depth: usize,
    volume: u64,
    limits: LocalTreeLimits,
    state: &mut LocalCaptureState,
) -> Result<(), RunnerError> {
    if depth > LOCAL_TREE_MAX_DEPTH {
        return Err(RunnerError::LimitExceeded);
    }
    for name in local_directory_names(directory, limits.max_entries - state.entry_count)? {
        state.entry_count = state
            .entry_count
            .checked_add(1)
            .ok_or(RunnerError::LimitExceeded)?;
        if state.entry_count > limits.max_entries {
            return Err(RunnerError::LimitExceeded);
        }
        let name_text = name.to_str().ok_or(RunnerError::UnsafeTopology)?;
        let relative = if prefix.is_empty() {
            name_text.to_owned()
        } else {
            format!("{prefix}/{name_text}")
        };
        let stage_path = StagePath::try_from(relative.clone())?;
        let handle = nt_open_local(directory, &name, FILE_SHARE_READ)?;
        let initial_node = local_raw_node(&handle)?;
        if !safe_local_node(&initial_node, initial_node.directory, volume)
            || has_named_streams(&handle)?
        {
            return Err(RunnerError::UnsafeTopology);
        }
        let reopened = nt_open_local(
            directory,
            &name,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        )?;
        let reopened_node = local_raw_node(&reopened)?;
        let node = local_raw_node(&handle)?;
        if !same_local_node(&initial_node, &node) || !same_local_node(&node, &reopened_node) {
            return Err(RunnerError::ConcurrentChange);
        }
        if !safe_local_node(&node, node.directory, volume)
            || !safe_local_node(&reopened_node, node.directory, volume)
            || has_named_streams(&handle)?
            || has_named_streams(&reopened)?
            || !state.identities.insert(local_identity(&node))
        {
            return Err(RunnerError::UnsafeTopology);
        }
        let digest = if node.directory {
            [0; 32]
        } else {
            state.files = state
                .files
                .checked_add(1)
                .ok_or(RunnerError::LimitExceeded)?;
            if state.files > limits.max_files {
                return Err(RunnerError::LimitExceeded);
            }
            let size = usize::try_from(node.size).map_err(|_| RunnerError::LimitExceeded)?;
            if size > limits.max_file_bytes {
                return Err(RunnerError::LimitExceeded);
            }
            state.total_bytes = state
                .total_bytes
                .checked_add(size)
                .ok_or(RunnerError::LimitExceeded)?;
            if state.total_bytes > limits.max_total_bytes {
                return Err(RunnerError::LimitExceeded);
            }
            Sha256::digest(read_local_bytes(&handle, size)?).into()
        };
        if node.directory {
            capture_local_children(&handle, &relative, depth + 1, volume, limits, state)?;
        }
        let final_node = local_raw_node(&handle)?;
        let final_reopened_node = local_raw_node(&reopened)?;
        if !same_local_node(&node, &final_node)
            || !same_local_node(&final_node, &final_reopened_node)
        {
            return Err(RunnerError::ConcurrentChange);
        }
        if !safe_local_node(&final_node, node.directory, volume)
            || !safe_local_node(&final_reopened_node, node.directory, volume)
            || has_named_streams(&handle)?
            || has_named_streams(&reopened)?
        {
            return Err(RunnerError::UnsafeTopology);
        }
        state.entries.push(LocalEntry {
            snapshot: LocalNodeSnapshot {
                path: stage_path,
                directory: final_node.directory,
                volume: final_node.volume,
                object: final_node.object,
                attributes: final_node.attributes,
                links: final_node.links,
                size: final_node.size,
                creation_time: final_node.creation_time,
                last_write_time: final_node.last_write_time,
                digest,
            },
            handle,
        });
    }
    Ok(())
}

#[cfg(windows)]
fn read_local_bytes(file: &fs::File, expected: usize) -> Result<Vec<u8>, RunnerError> {
    let mut reader = file;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|_| RunnerError::Io)?;
    let mut bytes = Vec::with_capacity(expected);
    reader
        .take(expected.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| RunnerError::Io)?;
    if bytes.len() != expected {
        return Err(RunnerError::ConcurrentChange);
    }
    let mut reader = file;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|_| RunnerError::Io)?;
    Ok(bytes)
}

#[cfg(windows)]
struct LocalRawNode {
    directory: bool,
    volume: u64,
    object: [u8; 16],
    attributes: u32,
    links: u64,
    size: u64,
    creation_time: i64,
    last_write_time: i64,
}

#[cfg(windows)]
fn local_raw_node(file: &fs::File) -> Result<LocalRawNode, RunnerError> {
    let handle = file.as_raw_handle() as HANDLE;
    let mut basic = FILE_BASIC_INFO::default();
    let mut id = FILE_ID_INFO::default();
    let mut standard = FILE_STANDARD_INFO::default();
    let mut tag = FILE_ATTRIBUTE_TAG_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileBasicInfo,
            (&mut basic as *mut FILE_BASIC_INFO).cast(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
        || unsafe {
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
        || standard.DeletePending
        || standard.EndOfFile < 0
    {
        return Err(RunnerError::Io);
    }
    Ok(LocalRawNode {
        directory: standard.Directory,
        volume: id.VolumeSerialNumber,
        object: id.FileId.Identifier,
        attributes: tag.FileAttributes,
        links: u64::from(standard.NumberOfLinks),
        size: standard.EndOfFile as u64,
        creation_time: basic.CreationTime,
        last_write_time: basic.LastWriteTime,
    })
}

#[cfg(windows)]
fn local_identity(node: &LocalRawNode) -> (u64, [u8; 16]) {
    (node.volume, node.object)
}

#[cfg(windows)]
fn safe_local_node(node: &LocalRawNode, directory: bool, volume: u64) -> bool {
    node.directory == directory
        && node.volume == volume
        && node.attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
        && node.links == 1
}

#[cfg(windows)]
fn same_local_node(left: &LocalRawNode, right: &LocalRawNode) -> bool {
    left.directory == right.directory
        && left.volume == right.volume
        && left.object == right.object
        && left.attributes == right.attributes
        && left.links == right.links
        && left.size == right.size
        && left.creation_time == right.creation_time
        && left.last_write_time == right.last_write_time
}

#[cfg(windows)]
fn has_named_streams(file: &fs::File) -> Result<bool, RunnerError> {
    let mut capacity = 4096_usize;
    let buffer = loop {
        let mut buffer = vec![0_u64; capacity.div_ceil(size_of::<u64>())];
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle() as HANDLE,
                FileStreamInfo,
                buffer.as_mut_ptr().cast(),
                capacity as u32,
            )
        } != 0
        {
            break buffer;
        }
        let error = unsafe { GetLastError() };
        if error == ERROR_HANDLE_EOF {
            return Ok(false);
        }
        if !matches!(error, ERROR_MORE_DATA | ERROR_INSUFFICIENT_BUFFER) || capacity >= 1024 * 1024
        {
            return Err(RunnerError::Io);
        }
        capacity *= 2;
    };
    let header = std::mem::offset_of!(FILE_STREAM_INFO, StreamName);
    let base = buffer.as_ptr().cast::<u8>();
    let mut offset = 0_usize;
    loop {
        if offset.checked_add(header).is_none_or(|end| end > capacity) {
            return Err(RunnerError::Io);
        }
        let info = unsafe { std::ptr::read_unaligned(base.add(offset).cast::<FILE_STREAM_INFO>()) };
        let name_bytes = usize::try_from(info.StreamNameLength).map_err(|_| RunnerError::Io)?;
        if name_bytes % 2 != 0
            || offset
                .checked_add(header)
                .and_then(|start| start.checked_add(name_bytes))
                .is_none_or(|end| end > capacity)
        {
            return Err(RunnerError::Io);
        }
        let units = unsafe {
            std::slice::from_raw_parts(
                base.add(offset + header).cast::<u16>(),
                name_bytes / size_of::<u16>(),
            )
        };
        if String::from_utf16(units).map_err(|_| RunnerError::Io)? != DEFAULT_STREAM {
            return Ok(true);
        }
        if info.NextEntryOffset == 0 {
            return Ok(false);
        }
        let next = info.NextEntryOffset as usize;
        if next < header + name_bytes || offset.checked_add(next).is_none_or(|end| end >= capacity)
        {
            return Err(RunnerError::Io);
        }
        offset += next;
    }
}

#[cfg(windows)]
fn open_local_root(path: &Path, share: u32) -> Result<fs::File, RunnerError> {
    open_local_root_with(path, GENERIC_READ, share)
}

#[cfg(windows)]
fn open_local_root_with(
    path: &Path,
    desired_access: u32,
    share: u32,
) -> Result<fs::File, RunnerError> {
    let path = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            desired_access,
            share,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(RunnerError::Io);
    }
    Ok(unsafe { fs::File::from_raw_handle(handle.cast()) })
}

#[cfg(windows)]
#[repr(C)]
union LocalIoStatusValue {
    status: NTSTATUS,
    pointer: *mut c_void,
}

#[cfg(windows)]
#[repr(C)]
struct LocalIoStatusBlock {
    value: LocalIoStatusValue,
    information: usize,
}

#[cfg(windows)]
#[repr(C)]
struct LocalObjectAttributes {
    length: u32,
    root_directory: HANDLE,
    object_name: *mut UNICODE_STRING,
    attributes: u32,
    security_descriptor: *mut c_void,
    security_quality_of_service: *mut c_void,
}

#[cfg(windows)]
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtCreateFile(
        file_handle: *mut HANDLE,
        desired_access: u32,
        object_attributes: *const LocalObjectAttributes,
        io_status_block: *mut LocalIoStatusBlock,
        allocation_size: *const i64,
        file_attributes: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        ea_buffer: *const c_void,
        ea_length: u32,
    ) -> NTSTATUS;
}

#[cfg(windows)]
fn nt_open_local(parent: &fs::File, name: &OsStr, share: u32) -> Result<fs::File, RunnerError> {
    nt_open_local_with(
        parent,
        name,
        FILE_GENERIC_READ,
        share,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
    )
}

#[cfg(windows)]
fn nt_open_local_with(
    parent: &fs::File,
    name: &OsStr,
    desired_access: u32,
    share: u32,
    disposition: u32,
    options: u32,
) -> Result<fs::File, RunnerError> {
    let mut name = name.encode_wide().collect::<Vec<_>>();
    let bytes = name
        .len()
        .checked_mul(size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or(RunnerError::Io)?;
    if name.is_empty() || name.contains(&0) {
        return Err(RunnerError::UnsafeTopology);
    }
    let mut unicode = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: name.as_mut_ptr(),
    };
    let attributes = LocalObjectAttributes {
        length: size_of::<LocalObjectAttributes>() as u32,
        root_directory: parent.as_raw_handle() as HANDLE,
        object_name: &mut unicode,
        attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        security_descriptor: null_mut(),
        security_quality_of_service: null_mut(),
    };
    let mut status_block = LocalIoStatusBlock {
        value: LocalIoStatusValue {
            pointer: null_mut(),
        },
        information: 0,
    };
    let mut handle = INVALID_HANDLE_VALUE;
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            desired_access | SYNCHRONIZE,
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
        return Ok(unsafe { fs::File::from_raw_handle(handle.cast()) });
    }
    if matches!(
        status,
        STATUS_REPARSE_POINT_ENCOUNTERED | STATUS_STOPPED_ON_SYMLINK
    ) {
        return Err(RunnerError::UnsafeTopology);
    }
    let _ = unsafe { RtlNtStatusToDosError(status) };
    Err(RunnerError::Io)
}

#[cfg(windows)]
struct LocalStage {
    layout: StageLayout,
    volume: u64,
    root_writer: Option<fs::File>,
    root_lock: Option<fs::File>,
    input: LocalTreeBuilder,
    config: LocalTreeBuilder,
    _output_handle: fs::File,
}

#[cfg(windows)]
impl LocalStage {
    fn initialize_existing(root: PathBuf, target: RuntimeTarget) -> Result<Self, RunnerError> {
        if target != RuntimeTarget::WindowsX86_64 || !root.is_absolute() || !root.is_dir() {
            return Err(RunnerError::InvalidStage);
        }
        let layout = StageLayout::new(root.clone())?;
        let root_handle =
            open_local_root_with(&root, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ)?;
        let root_node = local_raw_node(&root_handle)?;
        if !safe_local_node(&root_node, true, root_node.volume) || has_named_streams(&root_handle)?
        {
            return Err(RunnerError::UnsafeTopology);
        }
        for directory in [
            StageDirectory::Home,
            StageDirectory::Data,
            StageDirectory::Cache,
            StageDirectory::Temp,
            StageDirectory::Runtime,
            StageDirectory::Reports,
        ] {
            let handle = open_local_stage_directory(
                &root_handle,
                layout
                    .path(directory)
                    .file_name()
                    .ok_or(RunnerError::InvalidStage)?,
                root_node.volume,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
            )?;
            drop(handle);
        }
        let config = LocalTreeBuilder::open_existing("config", &root_handle, root_node.volume)?;
        let input = LocalTreeBuilder::create("input", &root_handle, root_node.volume)?;
        let output_writer = create_local_directory(
            &root_handle,
            OsStr::new("output"),
            root_node.volume,
            FILE_SHARE_READ,
        )?;
        let output = transition_local_child_lock(
            &root_handle,
            OsStr::new("output"),
            output_writer,
            true,
            root_node.volume,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
        )?;
        Ok(Self {
            layout,
            volume: root_node.volume,
            root_writer: Some(root_handle),
            root_lock: None,
            input,
            config,
            _output_handle: output,
        })
    }

    fn layout(&self) -> &StageLayout {
        &self.layout
    }

    fn write_and_seal_inputs(
        &mut self,
        frames: &[ContentFrame],
    ) -> Result<LocalTreeInventory, RunnerError> {
        let paths = frames
            .iter()
            .map(|frame| frame.path().clone())
            .collect::<Vec<_>>();
        validate_path_set(RuntimeTarget::WindowsX86_64, &paths)?;
        for frame in frames {
            let relative = frame
                .path()
                .as_str()
                .strip_prefix("input/")
                .filter(|path| !path.is_empty())
                .ok_or(RunnerError::InvalidStage)?;
            self.input.create_file(relative, frame.bytes())?;
        }
        let root_writer = self.root_writer.as_ref().ok_or(RunnerError::InvalidStage)?;
        self.input.seal(root_writer)?;
        if !self.config.sealed {
            self.config.seal(root_writer)?;
        }
        let writer = self.root_writer.take().ok_or(RunnerError::InvalidStage)?;
        self.root_lock = Some(transition_local_root_lock(
            self.layout.root(),
            writer,
            self.volume,
        )?);
        LocalTreeInventory::capture(
            &self.layout.path(StageDirectory::Input),
            RuntimeTarget::WindowsX86_64,
            LocalTreeLimits::unbounded(),
        )
    }

    fn read_outputs(&self, limits: RunLimits) -> Result<Vec<ContentFrame>, RunnerError> {
        let inventory = LocalTreeInventory::capture(
            &self.layout.path(StageDirectory::Output),
            RuntimeTarget::WindowsX86_64,
            LocalTreeLimits::for_outputs(limits),
        )?;
        let mut frames = Vec::new();
        for entry in inventory
            .entries
            .iter()
            .filter(|entry| !entry.snapshot.directory)
        {
            frames.push(ContentFrame::new(
                StagePath::try_from(format!("output/{}", entry.snapshot.path.as_str()))?,
                inventory.read_file(&entry.snapshot.path)?,
            )?);
        }
        inventory.verify_unchanged()?;
        Ok(frames)
    }

    fn install_trusted_config(
        &mut self,
        command: &SidecarCommand,
    ) -> Result<Option<LocalTreeInventory>, RunnerError> {
        match command {
            SidecarCommand::RuleSyncGenerate { .. } => {
                self.input.create_file("rulesync.jsonc", b"{}\n")?;
                Ok(None)
            }
            SidecarCommand::GitleaksScanPackage => {
                self.config.create_file("gitleaks.toml", GITLEAKS_POLICY)?;
                self.config
                    .create_file("gitleaks.empty-ignore", GITLEAKS_EMPTY_IGNORE)?;
                self.seal_and_inventory_config().map(Some)
            }
            SidecarCommand::OsemgrepScanPackage => {
                self.config.ensure_directory("semgrep")?;
                self.config
                    .create_file("semgrep/package.yml", SEMGREP_POLICY)?;
                self.seal_and_inventory_config().map(Some)
            }
        }
    }

    fn seal_and_inventory_config(&mut self) -> Result<LocalTreeInventory, RunnerError> {
        self.config
            .seal(self.root_writer.as_ref().ok_or(RunnerError::InvalidStage)?)?;
        LocalTreeInventory::capture(
            &self.layout.path(StageDirectory::Config),
            RuntimeTarget::WindowsX86_64,
            LocalTreeLimits::unbounded(),
        )
    }
}

#[cfg(windows)]
fn open_local_stage_directory(
    stage_root: &fs::File,
    name: &OsStr,
    volume: u64,
    share: u32,
) -> Result<fs::File, RunnerError> {
    let handle = nt_open_local(stage_root, name, share)?;
    let node = local_raw_node(&handle)?;
    if !safe_local_node(&node, true, volume) || has_named_streams(&handle)? {
        return Err(RunnerError::UnsafeTopology);
    }
    let reopened = nt_open_local(
        stage_root,
        name,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    )?;
    let reopened_node = local_raw_node(&reopened)?;
    let final_node = local_raw_node(&handle)?;
    if !same_local_node(&node, &final_node) || !same_local_node(&final_node, &reopened_node) {
        return Err(RunnerError::ConcurrentChange);
    }
    if !safe_local_node(&final_node, true, volume)
        || !safe_local_node(&reopened_node, true, volume)
        || has_named_streams(&handle)?
        || has_named_streams(&reopened)?
    {
        return Err(RunnerError::UnsafeTopology);
    }
    Ok(handle)
}

#[cfg(windows)]
struct LocalDirectoryWriter {
    parent: Option<String>,
    name: OsString,
    handle: fs::File,
}

#[cfg(windows)]
struct LocalTreeBuilder {
    base: String,
    volume: u64,
    directories: BTreeMap<String, LocalDirectoryWriter>,
    locks: Vec<fs::File>,
    sealed: bool,
}

#[cfg(windows)]
impl LocalTreeBuilder {
    fn open_existing(base: &str, stage_root: &fs::File, volume: u64) -> Result<Self, RunnerError> {
        let handle = nt_open_local_with(
            stage_root,
            OsStr::new(base),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            FILE_SHARE_READ,
            FILE_OPEN,
            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
        )?;
        Self::from_base(base, handle, volume)
    }

    fn create(base: &str, stage_root: &fs::File, volume: u64) -> Result<Self, RunnerError> {
        let handle = create_local_directory(stage_root, OsStr::new(base), volume, FILE_SHARE_READ)?;
        Self::from_base(base, handle, volume)
    }

    fn from_base(base: &str, handle: fs::File, volume: u64) -> Result<Self, RunnerError> {
        validate_local_open_node(&handle, true, volume)?;
        let mut directories = BTreeMap::new();
        directories.insert(
            base.to_owned(),
            LocalDirectoryWriter {
                parent: None,
                name: OsString::from(base),
                handle,
            },
        );
        Ok(Self {
            base: base.to_owned(),
            volume,
            directories,
            locks: Vec::new(),
            sealed: false,
        })
    }

    fn ensure_directory(&mut self, relative: &str) -> Result<String, RunnerError> {
        if self.sealed {
            return Err(RunnerError::InvalidStage);
        }
        StagePath::try_from(format!("{}/{}", self.base, relative))?;
        let mut parent = self.base.clone();
        for component in relative
            .split('/')
            .filter(|component| !component.is_empty())
        {
            let key = format!("{parent}/{component}");
            if !self.directories.contains_key(&key) {
                let handle = create_local_directory(
                    &self
                        .directories
                        .get(&parent)
                        .ok_or(RunnerError::InvalidStage)?
                        .handle,
                    OsStr::new(component),
                    self.volume,
                    FILE_SHARE_READ,
                )?;
                self.directories.insert(
                    key.clone(),
                    LocalDirectoryWriter {
                        parent: Some(parent.clone()),
                        name: OsString::from(component),
                        handle,
                    },
                );
            }
            parent = key;
        }
        Ok(parent)
    }

    fn create_file(&mut self, relative: &str, bytes: &[u8]) -> Result<(), RunnerError> {
        StagePath::try_from(format!("{}/{}", self.base, relative))?;
        let (parent_relative, name) = relative
            .rsplit_once('/')
            .map_or(("", relative), |(parent, name)| (parent, name));
        if name.is_empty() {
            return Err(RunnerError::InvalidStage);
        }
        let parent = if parent_relative.is_empty() {
            self.base.clone()
        } else {
            self.ensure_directory(parent_relative)?
        };
        let parent_handle = &self
            .directories
            .get(&parent)
            .ok_or(RunnerError::InvalidStage)?
            .handle;
        let mut writer = nt_open_local_with(
            parent_handle,
            OsStr::new(name),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            FILE_SHARE_READ,
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
        )?;
        writer.write_all(bytes).map_err(|_| RunnerError::Io)?;
        writer.sync_all().map_err(|_| RunnerError::Io)?;
        let mut permissions = writer
            .metadata()
            .map_err(|_| RunnerError::Io)?
            .permissions();
        permissions.set_readonly(true);
        writer
            .set_permissions(permissions)
            .map_err(|_| RunnerError::Io)?;
        validate_local_open_node(&writer, false, self.volume)?;
        if read_local_bytes(&writer, bytes.len())? != bytes {
            return Err(RunnerError::ConcurrentChange);
        }
        let lock = transition_local_child_lock(
            parent_handle,
            OsStr::new(name),
            writer,
            false,
            self.volume,
            FILE_SHARE_READ,
        )?;
        if read_local_bytes(&lock, bytes.len())? != bytes {
            return Err(RunnerError::ConcurrentChange);
        }
        self.locks.push(lock);
        Ok(())
    }

    fn seal(&mut self, stage_root: &fs::File) -> Result<(), RunnerError> {
        if self.sealed {
            return Ok(());
        }
        let mut keys = self.directories.keys().cloned().collect::<Vec<_>>();
        keys.sort_unstable_by_key(|key| std::cmp::Reverse(key.matches('/').count()));
        for key in keys {
            let writer = self
                .directories
                .remove(&key)
                .ok_or(RunnerError::InvalidStage)?;
            let parent = match writer.parent.as_ref() {
                Some(parent) => {
                    &self
                        .directories
                        .get(parent)
                        .ok_or(RunnerError::InvalidStage)?
                        .handle
                }
                None => stage_root,
            };
            self.locks.push(transition_local_child_lock(
                parent,
                &writer.name,
                writer.handle,
                true,
                self.volume,
                FILE_SHARE_READ,
            )?);
        }
        self.sealed = true;
        Ok(())
    }
}

#[cfg(windows)]
fn create_local_directory(
    parent: &fs::File,
    name: &OsStr,
    volume: u64,
    share: u32,
) -> Result<fs::File, RunnerError> {
    let handle = nt_open_local_with(
        parent,
        name,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE,
        share,
        FILE_CREATE,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
    )?;
    validate_local_open_node(&handle, true, volume)?;
    Ok(handle)
}

#[cfg(windows)]
fn validate_local_open_node(
    handle: &fs::File,
    directory: bool,
    volume: u64,
) -> Result<LocalRawNode, RunnerError> {
    let node = local_raw_node(handle)?;
    if !safe_local_node(&node, directory, volume) || has_named_streams(handle)? {
        return Err(RunnerError::UnsafeTopology);
    }
    Ok(node)
}

#[cfg(windows)]
fn transition_local_child_lock(
    parent: &fs::File,
    name: &OsStr,
    writer: fs::File,
    directory: bool,
    volume: u64,
    final_share: u32,
) -> Result<fs::File, RunnerError> {
    let before = validate_local_open_node(&writer, directory, volume)?;
    let transition = nt_open_local_with(
        parent,
        name,
        FILE_GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT
            | FILE_OPEN_REPARSE_POINT
            | if directory {
                FILE_DIRECTORY_FILE
            } else {
                FILE_NON_DIRECTORY_FILE
            },
    )?;
    let transition_node = validate_local_open_node(&transition, directory, volume)?;
    if !same_local_node(&before, &transition_node) {
        return Err(RunnerError::ConcurrentChange);
    }
    drop(writer);
    let lock = nt_open_local_with(
        parent,
        name,
        FILE_GENERIC_READ,
        final_share,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT
            | FILE_OPEN_REPARSE_POINT
            | if directory {
                FILE_DIRECTORY_FILE
            } else {
                FILE_NON_DIRECTORY_FILE
            },
    )?;
    let lock_node = validate_local_open_node(&lock, directory, volume)?;
    let final_transition = validate_local_open_node(&transition, directory, volume)?;
    if !same_local_node(&transition_node, &final_transition)
        || !same_local_node(&final_transition, &lock_node)
    {
        return Err(RunnerError::ConcurrentChange);
    }
    Ok(lock)
}

#[cfg(windows)]
fn transition_local_root_lock(
    path: &Path,
    writer: fs::File,
    volume: u64,
) -> Result<fs::File, RunnerError> {
    let before = validate_local_open_node(&writer, true, volume)?;
    let transition = open_local_root_with(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE)?;
    let transition_node = validate_local_open_node(&transition, true, volume)?;
    if !same_local_node(&before, &transition_node) {
        return Err(RunnerError::ConcurrentChange);
    }
    drop(writer);
    let lock = open_local_root(path, FILE_SHARE_READ)?;
    let lock_node = validate_local_open_node(&lock, true, volume)?;
    let final_transition = validate_local_open_node(&transition, true, volume)?;
    if !same_local_node(&transition_node, &final_transition)
        || !same_local_node(&final_transition, &lock_node)
    {
        return Err(RunnerError::ConcurrentChange);
    }
    Ok(lock)
}

#[cfg(windows)]
type HelperStage = LocalStage;
#[cfg(not(windows))]
type HelperStage = PrivateStage;
#[cfg(windows)]
type HelperInventory = LocalTreeInventory;
#[cfg(not(windows))]
type HelperInventory = NativeTreeInventory;

fn prepare_stage(_nonce: &[u8; 16], target: RuntimeTarget) -> Result<HelperStage, RunnerError> {
    #[cfg(windows)]
    {
        LocalStage::initialize_existing(
            std::env::current_dir().map_err(|_| RunnerError::InvalidStage)?,
            target,
        )
    }
    #[cfg(target_os = "macos")]
    {
        PrivateStage::create(&sandbox_home()?, *_nonce, target)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = (_nonce, target);
        Err(RunnerError::UnsupportedTarget)
    }
}

fn install_trusted_config(
    stage: &mut HelperStage,
    command: &SidecarCommand,
    target: RuntimeTarget,
) -> Result<Option<HelperInventory>, RunnerError> {
    #[cfg(windows)]
    {
        let _ = target;
        stage.install_trusted_config(command)
    }
    #[cfg(not(windows))]
    {
        let root = stage.layout().root();
        let config = root.join("config");
        match command {
            SidecarCommand::RuleSyncGenerate { .. } => {
                write_new(&root.join("input").join("rulesync.jsonc"), b"{}\n")?;
                Ok(None)
            }
            SidecarCommand::GitleaksScanPackage => {
                write_new(&config.join("gitleaks.toml"), GITLEAKS_POLICY)?;
                write_new(&config.join("gitleaks.empty-ignore"), GITLEAKS_EMPTY_IGNORE)?;
                inspect_helper_tree(&config, target).map(Some)
            }
            SidecarCommand::OsemgrepScanPackage => {
                let semgrep = config.join("semgrep");
                fs::create_dir(&semgrep).map_err(|_| RunnerError::InvalidStage)?;
                write_new(&semgrep.join("package.yml"), SEMGREP_POLICY)?;
                inspect_helper_tree(&config, target).map(Some)
            }
        }
    }
}

#[cfg(not(windows))]
fn inspect_helper_tree(root: &Path, target: RuntimeTarget) -> Result<HelperInventory, RunnerError> {
    inspect_native_tree(root, target)
}

#[cfg(not(windows))]
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), RunnerError> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| RunnerError::Io)?;
    file.write_all(bytes).map_err(|_| RunnerError::Io)?;
    file.sync_all().map_err(|_| RunnerError::Io)?;
    let mut permissions = file.metadata().map_err(|_| RunnerError::Io)?.permissions();
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions).map_err(|_| RunnerError::Io)
}

fn validate_pre_enumeration(request: &RunRequest) -> Result<(), RunnerError> {
    if matches!(request.command(), SidecarCommand::OsemgrepScanPackage)
        && request
            .inputs()
            .iter()
            .any(|input| input.bytes().len() > 8 * 1024 * 1024)
    {
        return Err(RunnerError::LimitExceeded);
    }
    Ok(())
}

fn drain_bounded<R: Read>(mut reader: R, limit: usize) -> Result<Vec<u8>, RunnerError> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 16 * 1024];
    let mut exceeded = false;
    loop {
        let count = reader.read(&mut buffer).map_err(|_| RunnerError::Io)?;
        if count == 0 {
            break;
        }
        if output.len().saturating_add(count) > limit {
            exceeded = true;
        } else if !exceeded {
            output.extend_from_slice(&buffer[..count]);
        }
    }
    (!exceeded)
        .then_some(output)
        .ok_or(RunnerError::LimitExceeded)
}

fn kill_child_tree(child: &mut std::process::Child) {
    let _ = child.kill();
}

fn failure_code(error: RunnerError) -> FailureCode {
    match error {
        RunnerError::ClosureMismatch
        | RunnerError::MissingMaterial
        | RunnerError::SidecarUnavailable => FailureCode::ClosureMismatch,
        RunnerError::LimitExceeded | RunnerError::FrameTooLarge => FailureCode::LimitExceeded,
        _ => FailureCode::InvalidOutput,
    }
}

#[cfg(target_os = "macos")]
fn sandbox_home() -> Result<PathBuf, RunnerError> {
    use std::{
        ffi::CStr,
        os::raw::{c_char, c_void},
    };
    #[link(name = "Foundation", kind = "framework")]
    unsafe extern "C" {
        fn NSHomeDirectory() -> *mut c_void;
    }
    #[link(name = "objc")]
    unsafe extern "C" {
        fn sel_registerName(name: *const c_char) -> *mut c_void;
        fn objc_msgSend(receiver: *mut c_void, selector: *mut c_void) -> *const c_char;
    }
    let string = unsafe { NSHomeDirectory() };
    if string.is_null() {
        return Err(RunnerError::InvalidStage);
    }
    let selector = unsafe { sel_registerName(c"UTF8String".as_ptr()) };
    let bytes = unsafe { objc_msgSend(string, selector) };
    if bytes.is_null() {
        return Err(RunnerError::InvalidStage);
    }
    Ok(PathBuf::from(
        unsafe { CStr::from_ptr(bytes) }
            .to_str()
            .map_err(|_| RunnerError::InvalidStage)?,
    ))
}

#[cfg(all(test, windows))]
mod local_tree_tests {
    use std::{fs::File, time::SystemTime};

    use super::*;

    #[test]
    fn capability_local_inventory_accepts_a_regular_tree_and_detects_change() {
        let root = scratch("regular");
        fs::create_dir(root.join("nested")).unwrap();
        fs::write(root.join("nested").join("rules.md"), b"rules\n").unwrap();

        let inventory = LocalTreeInventory::capture(
            &root,
            RuntimeTarget::WindowsX86_64,
            LocalTreeLimits::unbounded(),
        )
        .unwrap();
        assert_eq!(inventory.file_paths(), ["nested/rules.md"]);
        assert!(inventory.verify_unchanged().is_ok());
        assert!(fs::write(root.join("nested").join("rules.md"), b"changed\n").is_err());
        fs::write(root.join("new.md"), b"new\n").unwrap();
        assert!(matches!(
            inventory.verify_unchanged(),
            Err(RunnerError::ConcurrentChange)
        ));

        drop(inventory);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn capability_local_inventory_rejects_hardlinks_and_alternate_streams() {
        let root = scratch("hardlink");
        let file = root.join("rules.md");
        fs::write(&file, b"rules\n").unwrap();
        fs::hard_link(&file, root.join("alias.md")).unwrap();
        assert!(matches!(capture(&root), Err(RunnerError::UnsafeTopology)));
        fs::remove_dir_all(root).unwrap();

        let root = scratch("ads");
        let file = root.join("rules.md");
        fs::write(&file, b"rules\n").unwrap();
        let ads = PathBuf::from(format!("{}:hidden", file.display()));
        match File::create(&ads).and_then(|mut stream| stream.write_all(b"secret")) {
            Ok(()) => assert!(matches!(capture(&root), Err(RunnerError::UnsafeTopology))),
            Err(error) if matches!(error.kind(), std::io::ErrorKind::Unsupported) => {}
            Err(error) => panic!("failed to create an NTFS alternate stream: {error}"),
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn capability_local_inventory_rejects_reparse_points() {
        let root = scratch("symlink");
        let target = root.join("target.md");
        fs::write(&target, b"rules\n").unwrap();
        let link = root.join("link.md");
        match std::os::windows::fs::symlink_file(&target, &link) {
            Ok(()) => assert!(matches!(capture(&root), Err(RunnerError::UnsafeTopology))),
            Err(error) if error.raw_os_error() == Some(1314) => {}
            Err(error) => panic!("failed to create a Windows symlink: {error}"),
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn capability_local_inventory_counts_entries_before_descending() {
        let root = scratch("entry-limit");
        fs::create_dir(root.join("nested")).unwrap();
        fs::write(root.join("nested").join("rules.md"), b"rules\n").unwrap();
        let mut limits = LocalTreeLimits::unbounded();
        limits.max_entries = 1;

        assert!(matches!(
            LocalTreeInventory::capture(&root, RuntimeTarget::WindowsX86_64, limits),
            Err(RunnerError::LimitExceeded)
        ));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn capability_local_inventory_bounds_directory_enumeration() {
        let root = scratch("wide-directory");
        for index in 0..=LOCAL_TREE_MAX_ENTRIES {
            fs::write(root.join(format!("{index:04}.md")), []).unwrap();
        }

        assert!(matches!(capture(&root), Err(RunnerError::LimitExceeded)));
        fs::remove_dir_all(root).unwrap();
    }

    fn capture(root: &Path) -> Result<LocalTreeInventory, RunnerError> {
        LocalTreeInventory::capture(
            root,
            RuntimeTarget::WindowsX86_64,
            LocalTreeLimits::unbounded(),
        )
    }

    fn scratch(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "context-relay-helper-local-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        root
    }
}

#[cfg(test)]
mod identity_policy_tests {
    use super::identity_can_rely_on_nproc;

    #[test]
    fn nproc_policy_rejects_root_and_set_id_execution() {
        assert!(!identity_can_rely_on_nproc(0, 0, 20, 20));
        assert!(!identity_can_rely_on_nproc(501, 0, 20, 20));
        assert!(!identity_can_rely_on_nproc(501, 502, 20, 20));
        assert!(!identity_can_rely_on_nproc(501, 501, 20, 21));
        assert!(identity_can_rely_on_nproc(501, 501, 20, 20));
    }
}
