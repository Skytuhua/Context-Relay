use crate::{RunRequest, RunResponse, RunnerError, VerifiedClosure};

#[cfg(any(windows, test))]
use crate::{RunLimits, SidecarCommand};

#[cfg(any(windows, test))]
const WINDOWS_HELPER_SHUTDOWN_GRACE_MS: u32 = 5_000;
#[cfg(any(windows, test))]
const WINDOWS_MAX_SEALED_RUNTIME_MS: u32 =
    RunLimits::for_command(&SidecarCommand::OsemgrepScanPackage).timeout_ms();
#[cfg(any(windows, test))]
const WINDOWS_MAX_PROCESS_DEADLINE_MS: u32 =
    WINDOWS_MAX_SEALED_RUNTIME_MS + WINDOWS_HELPER_SHUTDOWN_GRACE_MS;

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WindowsProcessDeadline(u32);

#[cfg(any(windows, test))]
impl WindowsProcessDeadline {
    fn for_request(request: &RunRequest) -> Result<Self, RunnerError> {
        Self::from_runtime_ms(RunLimits::for_command(request.command()).timeout_ms())
    }

    fn from_runtime_ms(runtime_ms: u32) -> Result<Self, RunnerError> {
        if runtime_ms == 0 {
            return Err(RunnerError::LimitExceeded);
        }
        let deadline_ms = runtime_ms
            .checked_add(WINDOWS_HELPER_SHUTDOWN_GRACE_MS)
            .ok_or(RunnerError::LimitExceeded)?;
        if runtime_ms > WINDOWS_MAX_SEALED_RUNTIME_MS
            || deadline_ms > WINDOWS_MAX_PROCESS_DEADLINE_MS
        {
            return Err(RunnerError::LimitExceeded);
        }
        Ok(Self(deadline_ms))
    }

    const fn milliseconds(self) -> u32 {
        self.0
    }
}

#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(windows)]
pub mod windows;

pub trait SandboxLauncher {
    fn run(
        &self,
        closure: &VerifiedClosure,
        request: &RunRequest,
    ) -> Result<RunResponse, RunnerError>;
}

#[cfg(test)]
mod windows_process_deadline_tests {
    use super::WindowsProcessDeadline;
    use crate::{
        ContentFrame, RuleSyncFeature, RuleSyncFeatures, RuleSyncTarget, RunRequest, RunnerError,
        SidecarCommand, StagePath,
    };

    #[test]
    fn default_sidecar_requests_receive_thirty_seconds_plus_shutdown_grace() {
        let rulesync = request(
            SidecarCommand::RuleSyncGenerate {
                target: RuleSyncTarget::ClaudeCode,
                features: RuleSyncFeatures::new(&[RuleSyncFeature::Rules]).unwrap(),
            },
            "input/.rulesync/rules/probe.md",
        );
        let gitleaks = request(
            SidecarCommand::GitleaksScanPackage,
            "input/gitleaks-scan/payload/probe.txt",
        );

        assert_eq!(
            WindowsProcessDeadline::for_request(&rulesync)
                .unwrap()
                .milliseconds(),
            35_000
        );
        assert_eq!(
            WindowsProcessDeadline::for_request(&gitleaks)
                .unwrap()
                .milliseconds(),
            35_000
        );
    }

    #[test]
    fn osemgrep_request_receives_ninety_seconds_plus_shutdown_grace() {
        let request = request(
            SidecarCommand::OsemgrepScanPackage,
            "input/semgrep-target/probe.rs",
        );

        assert_eq!(
            WindowsProcessDeadline::for_request(&request)
                .unwrap()
                .milliseconds(),
            95_000
        );
    }

    #[test]
    fn invalid_runtime_deadlines_fail_closed() {
        for runtime_ms in [0, 90_001, u32::MAX] {
            assert_eq!(
                WindowsProcessDeadline::from_runtime_ms(runtime_ms),
                Err(RunnerError::LimitExceeded)
            );
        }
    }

    fn request(command: SidecarCommand, path: &str) -> RunRequest {
        RunRequest::new(
            [0x11; 16],
            [0x22; 32],
            command,
            vec![ContentFrame::new(StagePath::try_from(path).unwrap(), b"safe".to_vec()).unwrap()],
        )
        .unwrap()
    }
}

#[cfg(windows)]
mod windows_adapter {
    use std::{
        collections::BTreeSet,
        fs,
        io::Cursor,
        path::{Path, PathBuf},
        sync::Mutex,
    };

    use crate::windows::{
        JournaledProfileLease, LaunchError, LaunchSequence, LeaseState, ProfileJournal,
        ProfileMoniker, Win32LaunchBackend, Win32ProfileApi, Win32ProfileLayout,
        cleanup_profile_after_durable_outcome, copy_locked_file, create_fresh_profile,
        lock_directory,
    };
    use crate::{
        ClosureMaterial, FailureCode, HelperRunRequest, RunRequest, RunResponse, RunnerError,
        RuntimeTarget, SidecarCommand, StagePath, VerifiedClosure, read_run_response_for,
    };

    pub struct WindowsSandboxLauncher<J> {
        helper_template: PathBuf,
        helper_sha256: [u8; 32],
        journal: Mutex<J>,
    }

    impl<J: ProfileJournal> WindowsSandboxLauncher<J> {
        pub fn new(
            helper_template: PathBuf,
            helper_sha256: [u8; 32],
            journal: J,
        ) -> Result<Self, RunnerError> {
            if RuntimeTarget::current()? != RuntimeTarget::WindowsX86_64
                || !helper_template.is_absolute()
            {
                return Err(RunnerError::SidecarUnavailable);
            }
            Ok(Self {
                helper_template,
                helper_sha256,
                journal: Mutex::new(journal),
            })
        }

        pub fn prepare_profile(
            &self,
            transaction_nonce: [u8; 16],
        ) -> Result<JournaledProfileLease, RunnerError> {
            let mut journal = self
                .journal
                .lock()
                .map_err(|_| RunnerError::SidecarUnavailable)?;
            create_fresh_profile(
                &mut Win32ProfileApi::new(),
                &mut *journal,
                transaction_nonce,
            )
            .map_err(map_launch_error)
        }

        pub fn validate_request(
            &self,
            closure: &VerifiedClosure,
            request: &RunRequest,
        ) -> Result<(), RunnerError> {
            if closure.target() != RuntimeTarget::WindowsX86_64
                || closure.closure_sha256() != request.expected_closure_sha256()
                || closure.sidecar() != request.command().sidecar()
            {
                return Err(RunnerError::ClosureMismatch);
            }
            Ok(())
        }

        pub fn run_prepared(
            &self,
            lease: &JournaledProfileLease,
            closure: &VerifiedClosure,
            request: &RunRequest,
        ) -> Result<RunResponse, RunnerError> {
            self.validate_request(closure, request)?;
            if lease.state() != LeaseState::Created
                || lease.identity().moniker() != &ProfileMoniker::from_nonce(*request.nonce())
            {
                return Err(RunnerError::ClosureMismatch);
            }
            self.journal
                .lock()
                .map_err(|_| RunnerError::SidecarUnavailable)?
                .attest_created(lease.identity())
                .map_err(map_launch_error)?;
            let helper_request = HelperRunRequest::for_resigned_runtime(
                request.clone(),
                staged_runtime_materials(request.command(), closure)?,
            )?;

            run_in_profile(
                &Win32ProfileApi::new(),
                lease.identity(),
                closure,
                &helper_request,
                &self.helper_template,
                self.helper_sha256,
            )
        }

        pub fn cleanup_after_durable_outcome(
            &self,
            lease: &JournaledProfileLease,
        ) -> Result<(), RunnerError> {
            let mut journal = self
                .journal
                .lock()
                .map_err(|_| RunnerError::SidecarUnavailable)?;
            cleanup_profile_after_durable_outcome(&mut Win32ProfileApi::new(), &mut *journal, lease)
                .map_err(map_launch_error)
        }
    }

    fn run_in_profile(
        profiles: &Win32ProfileApi,
        identity: &crate::windows::ProfileIdentity,
        closure: &VerifiedClosure,
        helper_request: &HelperRunRequest,
        helper_template: &Path,
        helper_sha256: [u8; 32],
    ) -> Result<RunResponse, RunnerError> {
        let request = helper_request.request();
        let layout = Win32ProfileLayout::initialize(
            profiles
                .profile_folder(identity)
                .map_err(map_launch_error)?,
        )
        .map_err(map_launch_error)?;
        let _closure_locks = stage_closure(
            &layout,
            helper_template,
            helper_sha256,
            closure,
            request.command(),
        )?;
        let backend = Win32LaunchBackend::prepare(identity, layout, helper_sha256)
            .map_err(map_launch_error)?;
        let mut running = LaunchSequence::for_identity(backend, identity)
            .create_suspended()
            .and_then(|sequence| sequence.bind_kill_on_close_job())
            .and_then(|sequence| sequence.attest_zero_capability_token())
            .and_then(|sequence| sequence.resume_once())
            .map_err(map_launch_error)?;
        let output = match running.exchange(helper_request) {
            Ok(output) => output,
            Err(LaunchError::ProcessTimedOut) => {
                return Ok(RunResponse::failed(FailureCode::TimedOut));
            }
            Err(LaunchError::PipeLimitExceeded) => {
                return Ok(RunResponse::failed(FailureCode::LimitExceeded));
            }
            Err(LaunchError::PipeIo) => {
                return Ok(RunResponse::failed(FailureCode::ToolFailed));
            }
            Err(error) => return Err(map_launch_error(error)),
        };
        if output.exit_code() != 0 {
            return Ok(RunResponse::failed(FailureCode::ToolFailed));
        }
        if !output.stderr().is_empty() {
            return Ok(RunResponse::failed(FailureCode::ToolFailed));
        }
        let mut cursor = Cursor::new(output.stdout());
        let response = match read_run_response_for(&mut cursor, request) {
            Ok(response) if cursor.position() as usize == output.stdout().len() => response,
            _ => {
                return Ok(RunResponse::failed(FailureCode::ToolFailed));
            }
        };
        Ok(response)
    }

    fn stage_closure(
        layout: &Win32ProfileLayout,
        helper_template: &Path,
        helper_sha256: [u8; 32],
        closure: &VerifiedClosure,
        command: &SidecarCommand,
    ) -> Result<Vec<fs::File>, RunnerError> {
        let mut locks = vec![
            copy_locked_file(helper_template, &layout.helper_path(), None, helper_sha256)
                .map_err(map_launch_error)?,
        ];
        let runtime = layout.closure_runtime();
        let mut directories = BTreeSet::new();
        for material in closure.materials() {
            let runtime_path =
                staged_runtime_path(command, material.path(), material.executable())?;
            let source = material
                .path()
                .as_str()
                .split('/')
                .fold(closure.root().to_path_buf(), |path, component| {
                    path.join(component)
                });
            let destination = runtime_path
                .as_str()
                .split('/')
                .fold(runtime.to_path_buf(), |path, component| {
                    path.join(component)
                });
            let mut parent = PathBuf::new();
            for component in Path::new(runtime_path.as_str())
                .parent()
                .into_iter()
                .flat_map(Path::components)
            {
                parent.push(component);
                if directories.insert(parent.clone()) {
                    let path = runtime.join(&parent);
                    fs::create_dir(&path).map_err(|_| RunnerError::SidecarUnavailable)?;
                    locks.push(lock_directory(&path).map_err(map_launch_error)?);
                }
            }
            locks.push(
                copy_locked_file(
                    &source,
                    &destination,
                    Some(material.size()),
                    *material.sha256(),
                )
                .map_err(map_launch_error)?,
            );
        }
        Ok(locks)
    }

    fn staged_runtime_materials(
        command: &SidecarCommand,
        closure: &VerifiedClosure,
    ) -> Result<Vec<ClosureMaterial>, RunnerError> {
        closure
            .materials()
            .iter()
            .map(|material| {
                ClosureMaterial::new(
                    staged_runtime_path(command, material.path(), material.executable())?,
                    material.size(),
                    *material.sha256(),
                    material.executable(),
                )
            })
            .collect()
    }

    fn staged_runtime_path(
        command: &SidecarCommand,
        path: &StagePath,
        executable: bool,
    ) -> Result<StagePath, RunnerError> {
        if !matches!(command, SidecarCommand::OsemgrepScanPackage) || !executable {
            return Ok(path.clone());
        }
        let (parent, name) = path
            .as_str()
            .rsplit_once('/')
            .unwrap_or(("", path.as_str()));
        let core_name = match name {
            "osemgrep.exe" => "semgrep-core.exe",
            "osemgrep" => "semgrep-core",
            _ => return Err(RunnerError::ClosureMismatch),
        };
        StagePath::try_from(if parent.is_empty() {
            core_name.to_owned()
        } else {
            format!("{parent}/{core_name}")
        })
        .map_err(|_| RunnerError::ClosureMismatch)
    }

    fn map_launch_error(_error: LaunchError) -> RunnerError {
        RunnerError::SidecarUnavailable
    }

    #[cfg(test)]
    mod tests {
        use super::staged_runtime_path;
        use crate::{SidecarCommand, StagePath};

        #[test]
        fn only_the_windows_semgrep_executable_is_staged_under_the_core_name() {
            let executable = StagePath::try_from("osemgrep.exe").unwrap();
            let library = StagePath::try_from("bin/runtime.dll").unwrap();

            assert_eq!(
                staged_runtime_path(&SidecarCommand::OsemgrepScanPackage, &executable, true)
                    .unwrap()
                    .as_str(),
                "semgrep-core.exe"
            );
            assert_eq!(
                staged_runtime_path(&SidecarCommand::OsemgrepScanPackage, &library, false).unwrap(),
                library
            );
            assert_eq!(
                staged_runtime_path(&SidecarCommand::GitleaksScanPackage, &executable, true)
                    .unwrap(),
                executable
            );
        }
    }
}

#[cfg(windows)]
pub use windows_adapter::WindowsSandboxLauncher;
