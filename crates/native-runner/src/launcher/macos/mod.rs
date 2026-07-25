#![cfg(target_os = "macos")]

mod model;
mod native;
mod policy;

use std::{io::Cursor, path::PathBuf, time::Duration};

use rand_core::{OsRng, RngCore};

use super::SandboxLauncher;
use crate::{
    ClosureMaterial, FailureCode, HelperRunRequest, RunLimits, RunRequest, RunResponse,
    RunnerError, RuntimeTarget, SidecarCommand, SidecarId, StagePath, VerifiedClosure,
    read_run_response_for, write_helper_request,
};
use native::{MacGenerationProcess, MacGenerationSpec, MacSourceMaterial, prepare_generation};
use policy::{GenerationProcess, ProcessOutcome, execute_generation};

const HELPER_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

pub use model::{GenerationId, GenerationState, MacCodeIdentity, MacPolicyError, MacRootIdentity};
pub use native::{
    MacRecoveryCleanup, MacRecoveryIdentity, MacRecoveryOutcome, cleanup_recovered_generation,
};
pub use policy::{
    GenerationDecision, GenerationJournal, GenerationLease, SignedGeneration,
    container_identity_bytes, validate_container_identity,
};

pub struct MacOsSandboxLauncher<J> {
    private_root: PathBuf,
    helper_template: PathBuf,
    helper_sha256: [u8; 32],
    journal: J,
}

impl<J: GenerationJournal> MacOsSandboxLauncher<J> {
    /// Construct once during daemon startup, before authenticated IPC is published.
    pub fn new(
        private_root: PathBuf,
        helper_template: PathBuf,
        helper_sha256: [u8; 32],
        journal: J,
    ) -> Result<Self, RunnerError> {
        if RuntimeTarget::current()? != RuntimeTarget::MacosArm64
            || !private_root.is_absolute()
            || !helper_template.is_absolute()
        {
            return Err(RunnerError::SidecarUnavailable);
        }
        journal
            .poison_interrupted_after_restart()
            .map_err(|_| RunnerError::SidecarUnavailable)?;
        Ok(Self {
            private_root,
            helper_template,
            helper_sha256,
            journal,
        })
    }
}

impl<J: GenerationJournal> SandboxLauncher for MacOsSandboxLauncher<J> {
    fn run(
        &self,
        closure: &VerifiedClosure,
        request: &RunRequest,
    ) -> Result<RunResponse, RunnerError> {
        if closure.target() != RuntimeTarget::MacosArm64
            || closure.closure_sha256() != request.expected_closure_sha256()
            || !command_matches_sidecar(request.command(), closure.sidecar())
        {
            return Err(RunnerError::ClosureMismatch);
        }

        let mut protocol = Vec::new();
        let helper_request = HelperRunRequest::from_verified(request, closure)?;
        write_helper_request(&mut protocol, &helper_request)?;
        let materials = closure
            .materials()
            .iter()
            .map(|material| {
                MacSourceMaterial::new(
                    material.path().as_str(),
                    closure.root().join(material.path().as_str()),
                    material.size(),
                    *material.sha256(),
                    material.executable(),
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_policy_error)?;
        let mut nonce = [0_u8; 16];
        OsRng.fill_bytes(&mut nonce);
        let limits = RunLimits::for_command(request.command());
        let helper_timeout = Duration::from_millis(u64::from(limits.timeout_ms()))
            .checked_add(HELPER_SHUTDOWN_GRACE)
            .ok_or(RunnerError::LimitExceeded)?;
        let spec = MacGenerationSpec::new(
            GenerationId::from_nonce(nonce),
            self.private_root.clone(),
            self.helper_template.clone(),
            self.helper_sha256,
            materials,
            protocol,
            helper_timeout,
        )
        .map_err(map_policy_error)?;
        let mut prepared = prepare_generation(spec, &self.journal).map_err(map_policy_error)?;
        if prepared.inspections().is_empty() || !prepared.bundle_path().is_absolute() {
            return Err(RunnerError::SidecarUnavailable);
        }
        let runtime_materials = prepared
            .runtime_materials()
            .iter()
            .map(|material| {
                ClosureMaterial::new(
                    StagePath::try_from(material.relative_path())?,
                    material.size(),
                    *material.sha256(),
                    material.executable(),
                )
            })
            .collect::<Result<Vec<_>, RunnerError>>()?;
        let helper_request =
            HelperRunRequest::for_resigned_runtime(request.clone(), runtime_materials)?;
        let mut protocol = Vec::new();
        write_helper_request(&mut protocol, &helper_request)?;
        prepared.replace_input(protocol).map_err(map_policy_error)?;
        let signed = prepared.signed_generation().clone();
        let mut process = ProtocolProcess {
            process: prepared.into_process(),
            request: request.clone(),
        };
        match execute_generation(&self.journal, &signed, &mut process) {
            Ok(response) => Ok(response),
            Err(MacPolicyError::ProcessTimedOut) => Ok(RunResponse::failed(FailureCode::TimedOut)),
            Err(MacPolicyError::ProtocolLimitExceeded) => {
                Ok(RunResponse::failed(FailureCode::LimitExceeded))
            }
            Err(MacPolicyError::ProcessFailed | MacPolicyError::ProtocolIo) => {
                Ok(RunResponse::failed(FailureCode::ToolFailed))
            }
            Err(error) => Err(map_policy_error(error)),
        }
    }
}

struct ProtocolProcess {
    process: MacGenerationProcess,
    request: RunRequest,
}

impl GenerationProcess for ProtocolProcess {
    type Output = RunResponse;

    fn spawn_suspended(&mut self) -> Result<MacRootIdentity, MacPolicyError> {
        self.process.spawn_suspended()
    }

    fn confirm_container_bound(&mut self) {
        self.process.confirm_container_bound();
    }

    fn resume_and_send_input(&mut self) -> Result<(), MacPolicyError> {
        self.process.resume_and_send_input()
    }

    fn wait(&mut self) -> ProcessOutcome<Self::Output> {
        match self.process.wait() {
            ProcessOutcome::Completed(output) => {
                if output.exit_code() != 0 {
                    return ProcessOutcome::Abnormal(MacPolicyError::ProtocolIo);
                }
                decode_helper_outcome(output.stdout(), output.stderr(), &self.request)
            }
            ProcessOutcome::Abnormal(error) => ProcessOutcome::Abnormal(error),
        }
    }

    fn terminate_original_group(&mut self) -> Result<(), MacPolicyError> {
        self.process.terminate_original_group()
    }

    fn cleanup_terminal(&mut self) -> Result<(), MacPolicyError> {
        self.process.cleanup_terminal()
    }
}

fn decode_helper_outcome(
    stdout: &[u8],
    stderr: &[u8],
    request: &RunRequest,
) -> ProcessOutcome<RunResponse> {
    match decode_helper_output(stdout, stderr, request) {
        Ok(RunResponse::Failed(FailureCode::TimedOut)) => {
            ProcessOutcome::Abnormal(MacPolicyError::ProcessTimedOut)
        }
        Ok(response) => ProcessOutcome::Completed(response),
        Err(error) => ProcessOutcome::Abnormal(error),
    }
}

fn decode_helper_output(
    stdout: &[u8],
    stderr: &[u8],
    request: &RunRequest,
) -> Result<RunResponse, MacPolicyError> {
    if !stderr.is_empty() {
        return Err(MacPolicyError::ProtocolIo);
    }
    let mut cursor = Cursor::new(stdout);
    let response =
        read_run_response_for(&mut cursor, request).map_err(|_| MacPolicyError::ProtocolIo)?;
    if cursor.position() as usize != stdout.len() {
        return Err(MacPolicyError::ProtocolIo);
    }
    Ok(response)
}

fn command_matches_sidecar(command: &SidecarCommand, sidecar: SidecarId) -> bool {
    matches!(
        (command, sidecar),
        (SidecarCommand::RuleSyncGenerate { .. }, SidecarId::RuleSync)
            | (SidecarCommand::GitleaksScanPackage, SidecarId::Gitleaks)
            | (SidecarCommand::OsemgrepScanPackage, SidecarId::Osemgrep)
    )
}

fn map_policy_error(error: MacPolicyError) -> RunnerError {
    match error {
        MacPolicyError::ProtocolLimitExceeded => RunnerError::LimitExceeded,
        MacPolicyError::ProtocolIo => RunnerError::Io,
        _ => RunnerError::SidecarUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ContentFrame, StagePath, write_run_response_for};

    fn request(nonce: u8) -> RunRequest {
        RunRequest::new(
            [nonce; 16],
            [0x22; 32],
            SidecarCommand::OsemgrepScanPackage,
            vec![
                ContentFrame::new(
                    StagePath::try_from("input/semgrep-target/main.rs").unwrap(),
                    b"fn main() {}".to_vec(),
                )
                .unwrap(),
            ],
        )
        .unwrap()
    }

    #[test]
    fn helper_output_is_bound_to_request_one_exact_frame_and_stderr_is_empty() {
        let expected_request = request(0x11);
        let response = RunResponse::failed(FailureCode::ToolFailed);
        let mut stdout = Vec::new();
        write_run_response_for(&mut stdout, &expected_request, &response).unwrap();

        assert_eq!(
            decode_helper_output(&stdout, b"", &expected_request).unwrap(),
            response
        );
        assert!(decode_helper_output(&stdout, b"", &request(0x12)).is_err());
        assert!(decode_helper_output(&stdout, b"unexpected", &expected_request).is_err());
        stdout.push(0);
        assert!(decode_helper_output(&stdout, b"", &expected_request).is_err());
    }

    #[test]
    fn helper_timeout_is_an_abnormal_generation_outcome() {
        let expected_request = request(0x13);
        let response = RunResponse::failed(FailureCode::TimedOut);
        let mut stdout = Vec::new();
        write_run_response_for(&mut stdout, &expected_request, &response).unwrap();

        assert!(matches!(
            decode_helper_outcome(&stdout, b"", &expected_request),
            ProcessOutcome::Abnormal(MacPolicyError::ProcessTimedOut)
        ));
    }

    #[test]
    fn semgrep_helper_envelope_fits_the_native_generation_bound() {
        let limits = RunLimits::for_command(&SidecarCommand::OsemgrepScanPackage);
        let helper_timeout = Duration::from_millis(u64::from(limits.timeout_ms()))
            .checked_add(HELPER_SHUTDOWN_GRACE)
            .unwrap();
        assert_eq!(helper_timeout, Duration::from_secs(95));
        assert!(helper_timeout <= native::MAX_RUNTIME);
    }
}
