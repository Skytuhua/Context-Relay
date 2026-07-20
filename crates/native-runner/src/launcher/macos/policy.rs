use std::collections::BTreeSet;

use super::model::{GenerationId, GenerationState, MacPolicyError, MacRootIdentity};

const CONTAINER_IDENTITY_DOMAIN: &[u8] = b"context-relay/macos-container/v1\0";

pub fn container_identity_bytes(id: &GenerationId) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(CONTAINER_IDENTITY_DOMAIN.len() + id.as_str().len());
    bytes.extend_from_slice(CONTAINER_IDENTITY_DOMAIN);
    bytes.extend_from_slice(id.as_str().as_bytes());
    bytes
}

pub fn validate_container_identity(id: &GenerationId, bytes: &[u8]) -> Result<(), MacPolicyError> {
    (bytes == container_identity_bytes(id))
        .then_some(())
        .ok_or(MacPolicyError::InvalidGenerationId)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntitlementValue {
    Boolean(bool),
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationDecision {
    PersistActive,
    PersistRetired,
    PersistPoisoned,
    NoChange,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenerationLease {
    id: GenerationId,
    state: GenerationState,
}

impl GenerationLease {
    pub fn new(id: GenerationId) -> Self {
        Self {
            id,
            state: GenerationState::Prepared,
        }
    }

    pub const fn state(&self) -> GenerationState {
        self.state
    }

    pub fn id(&self) -> &GenerationId {
        &self.id
    }

    pub fn activate(&mut self) -> Result<GenerationDecision, MacPolicyError> {
        if self.state != GenerationState::Prepared {
            return Err(MacPolicyError::InvalidTransition);
        }
        self.state = GenerationState::Active;
        Ok(GenerationDecision::PersistActive)
    }

    pub fn retire(&mut self) -> Result<GenerationDecision, MacPolicyError> {
        if self.state != GenerationState::Active {
            return Err(MacPolicyError::InvalidTransition);
        }
        self.state = GenerationState::Retired;
        Ok(GenerationDecision::PersistRetired)
    }

    pub fn poison(&mut self) -> Result<GenerationDecision, MacPolicyError> {
        if !matches!(
            self.state,
            GenerationState::Prepared | GenerationState::Active
        ) {
            return Err(MacPolicyError::InvalidTransition);
        }
        self.state = GenerationState::Poisoned;
        Ok(GenerationDecision::PersistPoisoned)
    }

    pub fn recover_after_restart(&mut self) -> GenerationDecision {
        match self.state {
            GenerationState::Prepared | GenerationState::Active => {
                self.state = GenerationState::Poisoned;
                GenerationDecision::PersistPoisoned
            }
            GenerationState::Retired | GenerationState::Poisoned => GenerationDecision::NoChange,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntitlementSubject {
    Helper,
    Sidecar,
}

pub fn validate_entitlements(
    subject: EntitlementSubject,
    entitlements: &[(&str, EntitlementValue)],
) -> Result<(), MacPolicyError> {
    let valid = match subject {
        EntitlementSubject::Helper => {
            entitlements
                == [(
                    "com.apple.security.app-sandbox",
                    EntitlementValue::Boolean(true),
                )]
        }
        EntitlementSubject::Sidecar => entitlements.is_empty(),
    };
    valid
        .then_some(())
        .ok_or(MacPolicyError::InvalidEntitlements)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MachOInspection {
    pub relative_path: String,
    pub signed: bool,
    pub entitlements: Vec<(String, EntitlementValue)>,
}

pub fn validate_macho_closure(
    helper_relative_path: &str,
    expected: &[&str],
    inspections: &[MachOInspection],
) -> Result<(), MacPolicyError> {
    if helper_relative_path.is_empty() || expected.len() != inspections.len() {
        return Err(MacPolicyError::InvalidMachOClosure);
    }
    let expected: BTreeSet<_> = expected.iter().copied().collect();
    if expected.len() != inspections.len() || !expected.contains(helper_relative_path) {
        return Err(MacPolicyError::InvalidMachOClosure);
    }
    let mut seen = BTreeSet::new();
    for inspection in inspections {
        if inspection.relative_path.is_empty()
            || !inspection.signed
            || !expected.contains(inspection.relative_path.as_str())
            || !seen.insert(inspection.relative_path.as_str())
        {
            return Err(MacPolicyError::InvalidMachOClosure);
        }
        let subject = if inspection.relative_path == helper_relative_path {
            EntitlementSubject::Helper
        } else {
            EntitlementSubject::Sidecar
        };
        let entitlements = inspection
            .entitlements
            .iter()
            .map(|(key, value)| (key.as_str(), *value))
            .collect::<Vec<_>>();
        validate_entitlements(subject, &entitlements)?;
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedGeneration {
    id: GenerationId,
    sha256: [u8; 32],
    bundle_identity: MacRootIdentity,
}

impl SignedGeneration {
    pub const fn new(id: GenerationId, sha256: [u8; 32], bundle_identity: MacRootIdentity) -> Self {
        Self {
            id,
            sha256,
            bundle_identity,
        }
    }

    pub fn id(&self) -> &GenerationId {
        &self.id
    }

    pub const fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    pub const fn bundle_identity(&self) -> &MacRootIdentity {
        &self.bundle_identity
    }
}

pub trait GenerationJournal {
    /// Durably reserves every derived token before the guardian or bundle is created.
    fn reserve(&self, id: &GenerationId) -> Result<(), MacPolicyError>;

    /// Durably binds the guardian process group before any bundle mutation.
    fn bind_guardian(&self, id: &GenerationId, pgid: i32) -> Result<(), MacPolicyError>;

    /// Durably binds the exact bundle root immediately after its creation and capture.
    fn bind_bundle_root(
        &self,
        id: &GenerationId,
        bundle: &MacRootIdentity,
    ) -> Result<(), MacPolicyError>;

    /// Durably seals the signed digest after the entire bundle is frozen and verified.
    fn finalize(&self, generation: &SignedGeneration) -> Result<(), MacPolicyError>;

    /// Durably binds the verified container root while the helper remains suspended.
    fn bind_container_root(
        &self,
        id: &GenerationId,
        container: &MacRootIdentity,
    ) -> Result<(), MacPolicyError>;

    /// Must durably compare and transition the exact generation state.
    fn transition(
        &self,
        id: &GenerationId,
        from: GenerationState,
        to: GenerationState,
    ) -> Result<(), MacPolicyError>;

    /// Before publishing IPC, daemon startup must durably poison every interrupted
    /// Prepared generation (whether roots are unbound or bound) and every Active one.
    fn poison_interrupted_after_restart(&self) -> Result<(), MacPolicyError>;
}

#[derive(Debug, Eq, PartialEq)]
pub enum ProcessOutcome<T> {
    Completed(T),
    Abnormal(MacPolicyError),
}

pub trait GenerationProcess {
    type Output;

    /// Returns only after the suspended kernel-selected code and container root are verified.
    fn spawn_suspended(&mut self) -> Result<MacRootIdentity, MacPolicyError>;
    /// Records locally that cleanup authority for the captured container is durable.
    fn confirm_container_bound(&mut self);
    fn resume_and_send_input(&mut self) -> Result<(), MacPolicyError>;
    fn wait(&mut self) -> ProcessOutcome<Self::Output>;
    /// Returns only after owned I/O is joined and the original group is verified absent.
    fn terminate_original_group(&mut self) -> Result<(), MacPolicyError>;
    /// Removes the single-use generation only after the process group is absent and the
    /// generation has reached a durable terminal state.
    fn cleanup_terminal(&mut self) -> Result<(), MacPolicyError>;
}

pub fn execute_generation<J: GenerationJournal, P: GenerationProcess>(
    journal: &J,
    generation: &SignedGeneration,
    process: &mut P,
) -> Result<P::Output, MacPolicyError> {
    let mut lease = GenerationLease::new(generation.id.clone());
    let container_identity = match process.spawn_suspended() {
        Ok(identity) => identity,
        Err(error) => return poison_pre_resume(journal, &mut lease, process, error),
    };
    if let Err(error) = journal.bind_container_root(generation.id(), &container_identity) {
        return poison_pre_resume(journal, &mut lease, process, error);
    }
    process.confirm_container_bound();
    if let Err(error) = journal.transition(
        generation.id(),
        GenerationState::Prepared,
        GenerationState::Active,
    ) {
        return poison_pre_resume(journal, &mut lease, process, error);
    }
    lease.activate()?;

    if let Err(error) = process.resume_and_send_input() {
        return poison_and_terminate(journal, &mut lease, process, error);
    }
    match process.wait() {
        ProcessOutcome::Completed(output) => {
            if let Err(error) = process.terminate_original_group() {
                return poison_and_terminate(journal, &mut lease, process, error);
            }
            journal.transition(
                generation.id(),
                GenerationState::Active,
                GenerationState::Retired,
            )?;
            lease.retire()?;
            process.cleanup_terminal()?;
            Ok(output)
        }
        ProcessOutcome::Abnormal(error) => {
            poison_and_terminate(journal, &mut lease, process, error)
        }
    }
}

fn poison_pre_resume<J: GenerationJournal, P: GenerationProcess>(
    journal: &J,
    lease: &mut GenerationLease,
    process: &mut P,
    error: MacPolicyError,
) -> Result<P::Output, MacPolicyError> {
    let journal_result = journal.transition(
        lease.id(),
        GenerationState::Prepared,
        GenerationState::Poisoned,
    );
    if journal_result.is_ok() {
        let _ = lease.poison();
    }
    let termination_result = process.terminate_original_group();
    journal_result?;
    termination_result?;
    process.cleanup_terminal()?;
    Err(error)
}

fn poison_and_terminate<J: GenerationJournal, P: GenerationProcess>(
    journal: &J,
    lease: &mut GenerationLease,
    process: &mut P,
    error: MacPolicyError,
) -> Result<P::Output, MacPolicyError> {
    let journal_result = journal.transition(
        lease.id(),
        GenerationState::Active,
        GenerationState::Poisoned,
    );
    if journal_result.is_ok() {
        let _ = lease.poison();
    }
    let termination_result = process.terminate_original_group();
    journal_result?;
    termination_result?;
    process.cleanup_terminal()?;
    Err(error)
}
