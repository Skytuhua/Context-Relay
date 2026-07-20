//! Portable policy for Context Relay's isolated native sidecars.

mod command;
mod environment;
mod helper_protocol;
mod hydration;
mod launcher;
mod macos_identity;
#[cfg(target_os = "macos")]
#[doc(hidden)]
pub mod macos_spawn;
mod manifest;
mod native_fs;
mod path_policy;
mod report_validation;
mod stage;

pub use command::{
    RuleSyncFeature, RuleSyncFeatures, RuleSyncTarget, SidecarCommand, WorkingDirectory,
};
pub use environment::RestrictedEnvironment;
pub use helper_protocol::{
    ClosureMaterial, ContentFrame, FailureCode, HelperRunRequest, MAX_WIRE_PAYLOAD_BYTES,
    RunDisposition, RunLimits, RunRequest, RunResponse, RunStats, closure_material_digest,
    read_helper_request, read_run_request, read_run_response, read_run_response_for,
    write_helper_request, write_run_request, write_run_response, write_run_response_for,
};
pub use hydration::{HydrationFile, HydrationOutcome, install_hydrated_closure};
pub use launcher::SandboxLauncher;
#[cfg(windows)]
pub use launcher::WindowsSandboxLauncher;
#[cfg(target_os = "macos")]
pub use launcher::macos;
#[cfg(windows)]
pub use launcher::windows;
pub use macos_identity::{MacRootIdentity, MacRootIdentityError};
#[cfg(feature = "ci-candidate-sidecar-smoke")]
pub use manifest::verify_ci_candidate_closure;
pub use manifest::{
    RuntimeTarget, SidecarId, SidecarManifest, VerifiedClosure, VerifiedMaterial,
    parse_sidecar_manifest, verify_closure,
};
pub use native_fs::{
    AlternateStream, NativeMetadata, NativeMutationFailure, NativeMutationOutcome,
    NativeObjectToken, NativeRecoveryDisposition, NativeSnapshot, NativeState, NativeTreeInventory,
    OsNativeFileSystem, PrivateStage, inspect_native_tree,
};
pub use path_policy::{StagePath, validate_path_set, windows_ordinal_ignore_case_eq};
pub use report_validation::{
    validate_gitleaks_report, validate_rulesync_outputs, validate_semgrep_report,
};
pub use stage::{StageDirectory, StageLayout};

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum RunnerError {
    #[error("stage path is invalid")]
    InvalidPath,
    #[error("stage paths alias on the target filesystem")]
    PathCollision,
    #[error("the native runtime target is unsupported")]
    UnsupportedTarget,
    #[error("the closed sidecar command is invalid")]
    InvalidCommand,
    #[error("the private stage layout is invalid")]
    InvalidStage,
    #[error("the restricted environment is invalid")]
    InvalidEnvironment,
    #[error("the sidecar output is invalid")]
    InvalidToolOutput,
    #[error("the helper protocol frame is invalid")]
    InvalidFrame,
    #[error("the helper protocol frame exceeds its limit")]
    FrameTooLarge,
    #[error("the helper protocol content exceeds its limit")]
    LimitExceeded,
    #[error("content digest does not match its bytes")]
    DigestMismatch,
    #[error("helper protocol I/O failed")]
    Io,
    #[error("the sidecar manifest is invalid")]
    InvalidManifest,
    #[error("the selected sidecar is unavailable")]
    SidecarUnavailable,
    #[error("the verified sidecar closure does not match")]
    ClosureMismatch,
    #[error("required sidecar material is missing")]
    MissingMaterial,
    #[error("native filesystem topology is unsafe")]
    UnsafeTopology,
    #[error("native filesystem state changed concurrently")]
    ConcurrentChange,
    #[error("the native file type is unsupported")]
    UnsupportedFileType,
    #[error("the restorable native state is invalid")]
    InvalidNativeState,
}
