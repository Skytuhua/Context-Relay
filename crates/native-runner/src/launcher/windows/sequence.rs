use std::{fmt, marker::PhantomData};

use super::{LaunchError, ProfileIdentity};

pub trait LaunchBackend {
    fn create_suspended(&mut self) -> Result<(), LaunchError>;
    fn bind_kill_on_close_job(&mut self) -> Result<(), LaunchError>;
    fn attest_zero_capability_token(&mut self, sid: &str) -> Result<(), LaunchError>;
    fn resume_thread(&mut self) -> Result<u32, LaunchError>;
}

pub struct Prepared;
pub struct Suspended;
pub struct JobBound;
pub struct Attested;
pub struct Running;

pub struct LaunchSequence<B, State = Prepared> {
    pub(super) backend: B,
    pub(super) expected_sid: String,
    pub(super) state: PhantomData<State>,
}

impl<B, State> fmt::Debug for LaunchSequence<B, State> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LaunchSequence")
    }
}

impl<B: LaunchBackend> LaunchSequence<B, Prepared> {
    pub fn new(backend: B, expected_sid: &str) -> Self {
        Self {
            backend,
            expected_sid: expected_sid.to_owned(),
            state: PhantomData,
        }
    }

    pub fn for_identity(backend: B, identity: &ProfileIdentity) -> Self {
        Self::new(backend, identity.sid())
    }

    pub fn create_suspended(mut self) -> Result<LaunchSequence<B, Suspended>, LaunchError> {
        self.backend.create_suspended()?;
        Ok(self.transition())
    }
}

impl<B: LaunchBackend> LaunchSequence<B, Suspended> {
    pub fn bind_kill_on_close_job(mut self) -> Result<LaunchSequence<B, JobBound>, LaunchError> {
        self.backend.bind_kill_on_close_job()?;
        Ok(self.transition())
    }
}

impl<B: LaunchBackend> LaunchSequence<B, JobBound> {
    pub fn attest_zero_capability_token(
        mut self,
    ) -> Result<LaunchSequence<B, Attested>, LaunchError> {
        self.backend
            .attest_zero_capability_token(&self.expected_sid)?;
        Ok(self.transition())
    }
}

impl<B: LaunchBackend> LaunchSequence<B, Attested> {
    pub fn resume_once(mut self) -> Result<LaunchSequence<B, Running>, LaunchError> {
        if self.backend.resume_thread()? != 1 {
            return Err(LaunchError::ResumeFailed);
        }
        Ok(self.transition())
    }
}

impl<B, State> LaunchSequence<B, State> {
    fn transition<Next>(self) -> LaunchSequence<B, Next> {
        LaunchSequence {
            backend: self.backend,
            expected_sid: self.expected_sid,
            state: PhantomData,
        }
    }
}

/// The state-specific methods deliberately make this fail to compile:
///
/// ```compile_fail
/// # use context_relay_native_runner::windows::{LaunchSequence, Prepared};
/// # fn misuse<B>(sequence: LaunchSequence<B, Prepared>) {
/// sequence.resume_once();
/// # }
/// ```
pub const TYPESTATE_REQUIRES_ATTESTATION: () = ();
