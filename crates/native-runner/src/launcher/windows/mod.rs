#![cfg(windows)]

mod drain;
mod layout;
mod model;
mod native;
mod profile;
mod sequence;

pub use drain::drain_bounded;
pub use layout::Win32ProfileLayout;
pub(crate) use layout::lock_directory;
pub use model::{
    CreateProfileOutcome, JournaledProfileLease, LaunchError, LeaseState, ProfileApi,
    ProfileIdentity, ProfileJournal, ProfileMoniker, SecurityAttributePlan,
    cleanup_profile_after_durable_outcome, create_fresh_profile, recover_profile,
};
pub(crate) use native::copy_locked_file;
pub use native::{
    Win32LaunchAudit, Win32LaunchBackend, Win32SandboxOutput, seal_protocol_handles_before_sidecar,
};
pub use profile::{Win32ProfileApi, cleanup_recovered_profile};
pub use sequence::{
    Attested, JobBound, LaunchBackend, LaunchSequence, Prepared, Running, Suspended,
    TYPESTATE_REQUIRES_ATTESTATION,
};
