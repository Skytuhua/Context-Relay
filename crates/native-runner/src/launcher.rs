use crate::{RunRequest, RunResponse, RunnerError, VerifiedClosure};

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
        FailureCode, HelperRunRequest, RunRequest, RunResponse, RunnerError, RuntimeTarget,
        VerifiedClosure, read_run_response_for, write_helper_request,
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
            let helper_request = HelperRunRequest::from_verified(request, closure)?;
            let mut protocol = Vec::new();
            write_helper_request(&mut protocol, &helper_request)?;

            run_in_profile(
                &Win32ProfileApi::new(),
                lease.identity(),
                closure,
                request,
                &protocol,
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
        request: &RunRequest,
        protocol: &[u8],
        helper_template: &Path,
        helper_sha256: [u8; 32],
    ) -> Result<RunResponse, RunnerError> {
        let layout = Win32ProfileLayout::initialize(
            profiles
                .profile_folder(identity)
                .map_err(map_launch_error)?,
        )
        .map_err(map_launch_error)?;
        let _closure_locks = stage_closure(&layout, helper_template, helper_sha256, closure)?;
        let backend = Win32LaunchBackend::prepare(identity, layout, helper_sha256)
            .map_err(map_launch_error)?;
        let mut running = LaunchSequence::for_identity(backend, identity)
            .create_suspended()
            .and_then(|sequence| sequence.bind_kill_on_close_job())
            .and_then(|sequence| sequence.attest_zero_capability_token())
            .and_then(|sequence| sequence.resume_once())
            .map_err(map_launch_error)?;
        let output = match running.exchange(protocol) {
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
        if let Some(diagnostic) = validated_spawn_diagnostic(output.stderr()) {
            eprintln!("{diagnostic}");
        }
        let semgrep_diagnostic = validated_semgrep_diagnostic(output.stderr());
        if let Some(diagnostic) = semgrep_diagnostic {
            eprintln!("{diagnostic}");
        }
        if output.exit_code() != 0 || (!output.stderr().is_empty() && semgrep_diagnostic.is_none())
        {
            return Ok(RunResponse::failed(FailureCode::ToolFailed));
        }
        let mut cursor = Cursor::new(output.stdout());
        let response = match read_run_response_for(&mut cursor, request) {
            Ok(response) if cursor.position() as usize == output.stdout().len() => response,
            _ => return Ok(RunResponse::failed(FailureCode::ToolFailed)),
        };
        Ok(response)
    }

    fn validated_spawn_diagnostic(stderr: &[u8]) -> Option<&str> {
        let diagnostic = std::str::from_utf8(stderr).ok()?.strip_suffix('\n')?;
        let diagnostic = diagnostic.strip_suffix('\r').unwrap_or(diagnostic);
        let code = diagnostic.strip_prefix("context-relay-sidecar-spawn-os-error=")?;
        (!code.is_empty() && code.bytes().all(|byte| byte.is_ascii_digit())).then_some(diagnostic)
    }

    fn validated_semgrep_diagnostic(stderr: &[u8]) -> Option<&str> {
        let diagnostic = std::str::from_utf8(stderr).ok()?.strip_suffix('\n')?;
        let diagnostic = diagnostic.strip_suffix('\r').unwrap_or(diagnostic);
        let kind = diagnostic.strip_prefix("context-relay-semgrep-invalid-output=")?;
        let valid_exit = kind.split_once(':').is_some_and(|(label, rest)| {
            let mut parts = rest.split(':');
            let code = parts.next().unwrap_or("");
            let digits = code.strip_prefix('-').unwrap_or(code);
            let valid_stderr_kind = |part: &str| {
                matches!(
                    part,
                    "stderr-permission-denied-nul"
                        | "stderr-permission-denied"
                        | "stderr-not-found"
                        | "stderr-invalid-argument"
                        | "stderr-timeout"
                        | "stderr-out-of-memory"
                        | "stderr-stack-overflow"
                        | "stderr-unix-ebadf"
                        | "stderr-unix-epipe"
                        | "stderr-unix-eio"
                        | "stderr-unix-eintr"
                        | "stderr-unix-retry"
                        | "stderr-unix-enosys"
                        | "stderr-unix-unknown-5"
                        | "stderr-unix-other"
                        | "stderr-sys-error"
                        | "stderr-end-of-file"
                        | "stderr-not-found-exception"
                        | "stderr-cancelled"
                        | "stderr-timeout-exception"
                        | "stderr-other-exception"
                        | "stderr-empty"
                        | "stderr-other"
                ) || part
                    .strip_prefix("stderr-exception-")
                    .is_some_and(|constructor| {
                        !constructor.is_empty()
                            && constructor.len() <= 64
                            && constructor.bytes().all(|byte| {
                                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.')
                            })
                    })
            };
            label == "exit"
                && !digits.is_empty()
                && digits.bytes().all(|byte| byte.is_ascii_digit())
                && matches!(
                    parts.next(),
                    Some(
                        "report-timeout"
                            | "report-out-of-memory"
                            | "report-stack-overflow"
                            | "report-fatal"
                            | "report-no-errors"
                            | "report-other-error"
                            | "report-no-json"
                    )
                )
                && parts.next().is_some_and(valid_stderr_kind)
                && parts.next().is_none()
        });
        (valid_exit
            || matches!(
                kind,
                "report"
                    | "time-shape"
                    | "time-rules"
                    | "time-fixpoints"
                    | "time-rules-parse"
                    | "time-max-memory"
                    | "time-profiling"
                    | "time-targets"
                    | "time-parsing"
                    | "time-scanning"
                    | "time-matching"
                    | "time-tainting"
                    | "time-prefiltering"
                    | "stderr-crlf"
                    | "stderr-crlf-and-report"
                    | "stderr-crlf-report-json"
                    | "stderr-crlf-report-envelope"
                    | "stderr-crlf-report-time"
                    | "stderr-crlf-report-paths"
                    | "stderr-crlf-report-results"
                    | "stderr-crlf-report-disposition"
                    | "stderr"
                    | "stderr-and-report"
            ))
        .then_some(diagnostic)
    }

    fn stage_closure(
        layout: &Win32ProfileLayout,
        helper_template: &Path,
        helper_sha256: [u8; 32],
        closure: &VerifiedClosure,
    ) -> Result<Vec<fs::File>, RunnerError> {
        let mut locks = vec![
            copy_locked_file(helper_template, &layout.helper_path(), None, helper_sha256)
                .map_err(map_launch_error)?,
        ];
        let runtime = layout.closure_runtime();
        let mut directories = BTreeSet::new();
        for material in closure.materials() {
            let source = material
                .path()
                .as_str()
                .split('/')
                .fold(closure.root().to_path_buf(), |path, component| {
                    path.join(component)
                });
            let destination = material
                .path()
                .as_str()
                .split('/')
                .fold(runtime.to_path_buf(), |path, component| {
                    path.join(component)
                });
            let mut parent = PathBuf::new();
            for component in Path::new(material.path().as_str())
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

    fn map_launch_error(_error: LaunchError) -> RunnerError {
        RunnerError::SidecarUnavailable
    }

    #[cfg(test)]
    mod tests {
        use super::{validated_semgrep_diagnostic, validated_spawn_diagnostic};

        #[test]
        fn only_the_exact_numeric_spawn_diagnostic_is_forwarded() {
            assert_eq!(
                validated_spawn_diagnostic(b"context-relay-sidecar-spawn-os-error=5\n"),
                Some("context-relay-sidecar-spawn-os-error=5")
            );
            assert_eq!(validated_spawn_diagnostic(b"PROBE-ERR\n"), None);
            assert_eq!(
                validated_spawn_diagnostic(b"context-relay-sidecar-spawn-os-error=5 extra\n"),
                None
            );
        }

        #[test]
        fn only_an_exact_static_semgrep_diagnostic_is_forwarded() {
            assert_eq!(
                validated_semgrep_diagnostic(b"context-relay-semgrep-invalid-output=stderr-crlf\n"),
                Some("context-relay-semgrep-invalid-output=stderr-crlf")
            );
            assert_eq!(
                validated_semgrep_diagnostic(
                    b"context-relay-semgrep-invalid-output=stderr-crlf-report-time\n"
                ),
                Some("context-relay-semgrep-invalid-output=stderr-crlf-report-time")
            );
            assert_eq!(
                validated_semgrep_diagnostic(
                    b"context-relay-semgrep-invalid-output=time-targets\n"
                ),
                Some("context-relay-semgrep-invalid-output=time-targets")
            );
            assert_eq!(
                validated_semgrep_diagnostic(
                    b"context-relay-semgrep-invalid-output=exit:2:report-timeout:stderr-permission-denied-nul\n"
                ),
                Some(
                    "context-relay-semgrep-invalid-output=exit:2:report-timeout:stderr-permission-denied-nul"
                )
            );
            assert_eq!(
                validated_semgrep_diagnostic(
                    b"context-relay-semgrep-invalid-output=exit:2:report-timeout:stderr-secret\n"
                ),
                None
            );
        }
    }
}

#[cfg(windows)]
pub use windows_adapter::WindowsSandboxLauncher;
