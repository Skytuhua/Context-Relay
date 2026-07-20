use std::{error::Error, fmt};

const MONIKER_PREFIX: &str = "context-relay.native.";

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ProfileMoniker(String);

impl ProfileMoniker {
    pub fn from_nonce(nonce: [u8; 16]) -> Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut value = String::with_capacity(MONIKER_PREFIX.len() + nonce.len() * 2);
        value.push_str(MONIKER_PREFIX);
        for byte in nonce {
            value.push(HEX[(byte >> 4) as usize] as char);
            value.push(HEX[(byte & 0x0f) as usize] as char);
        }
        debug_assert!(value.len() <= 64);
        Self(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn from_journaled(value: &str) -> Result<Self, LaunchError> {
        let suffix = value
            .strip_prefix(MONIKER_PREFIX)
            .ok_or(LaunchError::InvalidProfileIdentity)?;
        if suffix.len() != 32
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(LaunchError::InvalidProfileIdentity);
        }
        let mut nonce = [0_u8; 16];
        for (slot, pair) in nonce.iter_mut().zip(suffix.as_bytes().chunks_exact(2)) {
            *slot = (lower_hex_nibble(pair[0]) << 4) | lower_hex_nibble(pair[1]);
        }
        Ok(Self::from_nonce(nonce))
    }
}

fn lower_hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("journaled moniker was validated as lowercase hexadecimal"),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileIdentity {
    moniker: ProfileMoniker,
    sid: String,
}

impl ProfileIdentity {
    pub fn from_derived(
        moniker: ProfileMoniker,
        sid: impl Into<String>,
    ) -> Result<Self, LaunchError> {
        let sid = sid.into();
        if !valid_appcontainer_sid_text(&sid) {
            return Err(LaunchError::InvalidProfileIdentity);
        }
        Ok(Self { moniker, sid })
    }

    pub fn moniker(&self) -> &ProfileMoniker {
        &self.moniker
    }

    pub fn sid(&self) -> &str {
        &self.sid
    }
}

fn valid_appcontainer_sid_text(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("S-1-15-2-") else {
        return false;
    };
    !rest.is_empty()
        && value.len() <= 184
        && rest
            .split('-')
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseState {
    Reserved,
    Created,
    CleanupPending,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournaledProfileLease {
    identity: ProfileIdentity,
    state: LeaseState,
}

impl JournaledProfileLease {
    fn new(identity: ProfileIdentity, state: LeaseState) -> Self {
        Self { identity, state }
    }

    pub fn identity(&self) -> &ProfileIdentity {
        &self.identity
    }

    pub const fn state(&self) -> LeaseState {
        self.state
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateProfileOutcome {
    Created,
    AlreadyExists,
}

pub trait ProfileApi {
    fn derive_identity(&mut self, moniker: &ProfileMoniker)
    -> Result<ProfileIdentity, LaunchError>;

    fn create_profile(
        &mut self,
        identity: &ProfileIdentity,
    ) -> Result<CreateProfileOutcome, LaunchError>;

    fn delete_profile(&mut self, identity: &ProfileIdentity) -> Result<(), LaunchError>;
}

pub trait ProfileJournal {
    /// This must not return until the reservation is durable.
    fn reserve(&mut self, identity: &ProfileIdentity) -> Result<(), LaunchError>;

    /// This must not return until the created transition is durable.
    fn mark_created(&mut self, identity: &ProfileIdentity) -> Result<(), LaunchError>;

    /// Prove the exact identity is still durably in the created state before execution.
    fn attest_created(&mut self, identity: &ProfileIdentity) -> Result<(), LaunchError>;

    /// The implementation must reject this transition until the transaction result is durable.
    fn mark_cleanup_pending(&mut self, identity: &ProfileIdentity) -> Result<(), LaunchError>;

    /// This must not return until deletion is durably acknowledged.
    fn mark_deleted(&mut self, identity: &ProfileIdentity) -> Result<(), LaunchError>;
}

pub fn create_fresh_profile<A: ProfileApi, J: ProfileJournal>(
    api: &mut A,
    journal: &mut J,
    nonce: [u8; 16],
) -> Result<JournaledProfileLease, LaunchError> {
    let identity = api.derive_identity(&ProfileMoniker::from_nonce(nonce))?;
    journal.reserve(&identity)?;
    match api.create_profile(&identity)? {
        CreateProfileOutcome::Created => {
            journal.mark_created(&identity)?;
            Ok(JournaledProfileLease::new(identity, LeaseState::Created))
        }
        CreateProfileOutcome::AlreadyExists => Err(LaunchError::ProfileCollision),
    }
}

pub fn recover_profile<A: ProfileApi>(
    api: &mut A,
    journaled: &JournaledProfileLease,
) -> Result<JournaledProfileLease, LaunchError> {
    let derived = api.derive_identity(journaled.identity.moniker())?;
    if &derived != journaled.identity() {
        return Err(LaunchError::ProfileIdentityMismatch);
    }
    Ok(journaled.clone())
}

pub fn cleanup_profile_after_durable_outcome<A: ProfileApi, J: ProfileJournal>(
    api: &mut A,
    journal: &mut J,
    lease: &JournaledProfileLease,
) -> Result<(), LaunchError> {
    journal.attest_created(lease.identity())?;
    journal.mark_cleanup_pending(lease.identity())?;
    api.delete_profile(lease.identity())?;
    journal.mark_deleted(lease.identity())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecurityAttributePlan {
    appcontainer_sid: usize,
    inherited_handles: [usize; 3],
}

impl SecurityAttributePlan {
    pub fn new(
        appcontainer_sid: usize,
        inherited_handles: [usize; 3],
    ) -> Result<Self, LaunchError> {
        if appcontainer_sid == 0
            || inherited_handles.contains(&0)
            || inherited_handles[0] == inherited_handles[1]
            || inherited_handles[0] == inherited_handles[2]
            || inherited_handles[1] == inherited_handles[2]
        {
            return Err(LaunchError::InvalidSecurityPlan);
        }
        Ok(Self {
            appcontainer_sid,
            inherited_handles,
        })
    }

    pub const fn attribute_count(&self) -> u32 {
        2
    }

    pub const fn appcontainer_sid(&self) -> usize {
        self.appcontainer_sid
    }

    pub const fn capabilities_ptr(&self) -> usize {
        0
    }

    pub const fn capability_count(&self) -> u32 {
        0
    }

    pub const fn reserved(&self) -> u32 {
        0
    }

    pub const fn inherited_handles(&self) -> &[usize; 3] {
        &self.inherited_handles
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LaunchError {
    InvalidProfileIdentity,
    ProfileCollision,
    ProfileIdentityMismatch,
    JournalFailure,
    InvalidSecurityPlan,
    PipeLimitExceeded,
    PipeIo,
    LockedHelperRejected,
    HelperDigestMismatch,
    CreateProcessFailed,
    JobAssignmentFailed,
    TokenAttestationFailed,
    ResumeFailed,
    ProcessTimedOut,
    Win32(u32),
    HResult(i32),
}

impl fmt::Display for LaunchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidProfileIdentity => "invalid AppContainer profile identity",
            Self::ProfileCollision => "AppContainer profile collision",
            Self::ProfileIdentityMismatch => "journaled AppContainer identity mismatch",
            Self::JournalFailure => "durable profile journal failed",
            Self::InvalidSecurityPlan => "invalid AppContainer security attribute plan",
            Self::PipeLimitExceeded => "bounded protocol pipe exceeded its limit",
            Self::PipeIo => "protocol pipe I/O failed",
            Self::LockedHelperRejected => "locked helper file failed safety checks",
            Self::HelperDigestMismatch => "locked helper digest mismatch",
            Self::CreateProcessFailed => "suspended process creation failed",
            Self::JobAssignmentFailed => "kill-on-close job assignment failed",
            Self::TokenAttestationFailed => "AppContainer token attestation failed",
            Self::ResumeFailed => "suspended thread did not resume exactly once",
            Self::ProcessTimedOut => "sandboxed helper timed out",
            Self::Win32(_) => "Win32 operation failed",
            Self::HResult(_) => "Windows HRESULT operation failed",
        };
        formatter.write_str(message)
    }
}

impl Error for LaunchError {}
