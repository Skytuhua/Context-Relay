use std::path::PathBuf;

use context_relay_native_runner::{
    NativeObjectToken as RunnerObjectToken, NativeRecoveryDisposition, NativeState,
    OsNativeFileSystem, RunnerError,
};
use context_relay_protocol::{NativePlatform, Sha256Digest, WireNativeValue};
use thiserror::Error;

use crate::vault::{
    MacGenerationState, MacGenerationSubstate, NativeSandboxCleanupState, NativeSandboxIdentity,
    NativeTransactionStatus, NativeWalAbsenceRebind, NativeWalRecord, NativeWalState, Vault,
    VaultError,
};

use super::{
    engine::BoundaryError,
    model::{MutationWalState, NativeObjectToken, RestorableStateFingerprint},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionCommitState {
    PreCommit,
    Committed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryMutation {
    pub state: MutationWalState,
    pub before: RestorableStateFingerprint,
    pub applied: RestorableStateFingerprint,
    pub restored: RestorableStateFingerprint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryDecision {
    FinalizeCommitted,
    PrepareRestore,
    MarkRestored,
    AlreadyRestored,
    MarkConflict,
    PreserveConflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryOutcome {
    Committed,
    Restored,
    Conflict,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoverySandboxIdentity {
    Windows {
        moniker: String,
        sid: String,
    },
    Macos {
        generation_id: String,
        bundle_id: String,
        container: Vec<u8>,
        guardian_pgid: Option<i32>,
        bundle_root: Option<Vec<u8>>,
        signed_digest: Option<Sha256Digest>,
        container_root: Option<Vec<u8>>,
        substate: MacGenerationSubstate,
        state: MacGenerationState,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryCleanup {
    Cleaned,
    Conflict,
}

#[doc(hidden)]
pub trait IntoRecoveryCleanup {
    fn into_recovery_cleanup(self) -> RecoveryCleanup;
}

impl IntoRecoveryCleanup for () {
    fn into_recovery_cleanup(self) -> RecoveryCleanup {
        RecoveryCleanup::Cleaned
    }
}

impl IntoRecoveryCleanup for RecoveryCleanup {
    fn into_recovery_cleanup(self) -> RecoveryCleanup {
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryRestore {
    Restored,
    Conflict,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryProbe {
    Fingerprint(RestorableStateFingerprint),
    RestoredNow(RestorableStateFingerprint),
    Conflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryAction {
    PoisonGeneration,
    BeginRecovery,
    PrepareRestore,
    RestoreTarget,
    CheckpointAbsence,
    RebindAbsence,
    MarkRestored,
    MarkConflict,
    FinishRecovery,
    CleanupSandbox,
    MarkCleanupConflict,
    FinishCleanup,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryMoment {
    Before,
    After,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryFaultPoint {
    pub action: RecoveryAction,
    pub moment: RecoveryMoment,
    pub target_sequence: Option<u32>,
}

impl RecoveryFaultPoint {
    pub fn encode(self) -> String {
        format!(
            "{}:{}:{}",
            action_name(self.action),
            if self.moment == RecoveryMoment::Before {
                "before"
            } else {
                "after"
            },
            self.target_sequence
                .map_or_else(|| "-".to_owned(), |value| value.to_string()),
        )
    }

    pub fn decode(value: &str) -> Option<Self> {
        let mut fields = value.split(':');
        let action = match fields.next()? {
            "poison_generation" => RecoveryAction::PoisonGeneration,
            "begin_recovery" => RecoveryAction::BeginRecovery,
            "prepare_restore" => RecoveryAction::PrepareRestore,
            "restore_target" => RecoveryAction::RestoreTarget,
            "checkpoint_absence" => RecoveryAction::CheckpointAbsence,
            "rebind_absence" => RecoveryAction::RebindAbsence,
            "mark_restored" => RecoveryAction::MarkRestored,
            "mark_conflict" => RecoveryAction::MarkConflict,
            "finish_recovery" => RecoveryAction::FinishRecovery,
            "cleanup_sandbox" => RecoveryAction::CleanupSandbox,
            "mark_cleanup_conflict" => RecoveryAction::MarkCleanupConflict,
            "finish_cleanup" => RecoveryAction::FinishCleanup,
            _ => return None,
        };
        let moment = match fields.next()? {
            "before" => RecoveryMoment::Before,
            "after" => RecoveryMoment::After,
            _ => return None,
        };
        let target_sequence = match fields.next()? {
            "-" => None,
            value => Some(value.parse().ok()?),
        };
        fields.next().is_none().then_some(Self {
            action,
            moment,
            target_sequence,
        })
    }
}

const fn action_name(action: RecoveryAction) -> &'static str {
    match action {
        RecoveryAction::PoisonGeneration => "poison_generation",
        RecoveryAction::BeginRecovery => "begin_recovery",
        RecoveryAction::PrepareRestore => "prepare_restore",
        RecoveryAction::RestoreTarget => "restore_target",
        RecoveryAction::CheckpointAbsence => "checkpoint_absence",
        RecoveryAction::RebindAbsence => "rebind_absence",
        RecoveryAction::MarkRestored => "mark_restored",
        RecoveryAction::MarkConflict => "mark_conflict",
        RecoveryAction::FinishRecovery => "finish_recovery",
        RecoveryAction::CleanupSandbox => "cleanup_sandbox",
        RecoveryAction::MarkCleanupConflict => "mark_cleanup_conflict",
        RecoveryAction::FinishCleanup => "finish_cleanup",
    }
}

pub trait RecoveryFaultHook {
    fn at(&mut self, point: &RecoveryFaultPoint) -> Result<(), BoundaryError>;
}

#[derive(Default)]
pub struct NoRecoveryFault;

impl RecoveryFaultHook for NoRecoveryFault {
    fn at(&mut self, _point: &RecoveryFaultPoint) -> Result<(), BoundaryError> {
        Ok(())
    }
}

pub trait NativeRecoveryIo {
    #[allow(clippy::too_many_arguments)]
    fn probe(
        &mut self,
        transaction_nonce: &[u8; 16],
        target: &WireNativeValue,
        object_token: &NativeObjectToken,
        applied_object_token: Option<&NativeObjectToken>,
        restored_object_token: Option<&NativeObjectToken>,
        state: NativeWalState,
        expected_before: &RestorableStateFingerprint,
        expected_applied: &RestorableStateFingerprint,
        intended_restored: &RestorableStateFingerprint,
    ) -> Result<RecoveryProbe, BoundaryError>;

    #[allow(clippy::too_many_arguments)]
    fn restore_if_matches(
        &mut self,
        transaction_nonce: &[u8; 16],
        target: &WireNativeValue,
        object_token: &NativeObjectToken,
        applied_object_token: Option<&NativeObjectToken>,
        expected_applied: &RestorableStateFingerprint,
        intended_restored: &RestorableStateFingerprint,
        before_image: &[u8],
        persist_restored_candidate: &mut dyn FnMut(&NativeObjectToken) -> Result<(), BoundaryError>,
    ) -> Result<RecoveryRestore, BoundaryError>;

    fn cleanup_sandbox(
        &mut self,
        identity: &RecoverySandboxIdentity,
        outcome: RecoveryOutcome,
    ) -> Result<RecoveryCleanup, BoundaryError>;

    fn cleanup_committed_mutation(
        &mut self,
        transaction_nonce: &[u8; 16],
        target: &WireNativeValue,
        object_token: &NativeObjectToken,
        expected_before: &RestorableStateFingerprint,
    ) -> Result<(), BoundaryError>;

    fn rebind_applied_absence(
        &mut self,
        target: &WireNativeValue,
        object_token: &NativeObjectToken,
        expected_old_token: &NativeObjectToken,
        expected_applied: &RestorableStateFingerprint,
    ) -> Result<Option<NativeObjectToken>, BoundaryError>;
}

pub struct OsNativeRecoveryIo<C, R = ()> {
    filesystem: OsNativeFileSystem,
    cleanup: C,
    cleanup_result: std::marker::PhantomData<fn() -> R>,
}

impl<C, R> OsNativeRecoveryIo<C, R>
where
    C: FnMut(RecoverySandboxIdentity, RecoveryOutcome) -> Result<R, BoundaryError>,
{
    pub fn new(cleanup: C) -> Self {
        Self {
            filesystem: OsNativeFileSystem::new(),
            cleanup,
            cleanup_result: std::marker::PhantomData,
        }
    }
}

impl<C, R> NativeRecoveryIo for OsNativeRecoveryIo<C, R>
where
    C: FnMut(RecoverySandboxIdentity, RecoveryOutcome) -> Result<R, BoundaryError>,
    R: IntoRecoveryCleanup,
{
    #[allow(clippy::too_many_arguments)]
    fn probe(
        &mut self,
        transaction_nonce: &[u8; 16],
        target: &WireNativeValue,
        object_token: &NativeObjectToken,
        applied_object_token: Option<&NativeObjectToken>,
        restored_object_token: Option<&NativeObjectToken>,
        state: NativeWalState,
        expected_before: &RestorableStateFingerprint,
        expected_applied: &RestorableStateFingerprint,
        intended_restored: &RestorableStateFingerprint,
    ) -> Result<RecoveryProbe, BoundaryError> {
        let path = decode_native_path(target)?;
        let journaled_token = decode_object_token(object_token)?;
        let decoded_applied_token = applied_object_token.map(decode_object_token).transpose()?;
        let decoded_restored_token = restored_object_token.map(decode_object_token).transpose()?;
        if state == NativeWalState::Conflict {
            return Ok(RecoveryProbe::Conflict);
        }
        let phase_started_applied = if state == NativeWalState::RestorePrepared {
            match self.filesystem.snapshot(&path) {
                Ok(snapshot) => {
                    snapshot.fingerprint() == &expected_applied.0.0
                        && decoded_applied_token.as_ref() == snapshot.object_token()
                }
                Err(
                    RunnerError::ConcurrentChange
                    | RunnerError::UnsafeTopology
                    | RunnerError::UnsupportedFileType,
                ) => false,
                Err(error) => return Err(runner_boundary(error)),
            }
        } else {
            false
        };
        let phase = if state == NativeWalState::Restored
            || (state == NativeWalState::RestorePrepared && expected_before == expected_applied)
        {
            Ok(NativeRecoveryDisposition::Restored)
        } else if state == NativeWalState::RestorePrepared
            && decoded_applied_token
                .as_ref()
                .is_some_and(RunnerObjectToken::is_absence_generation)
        {
            let applied_token = decoded_applied_token.as_ref().ok_or_else(|| {
                BoundaryError::new("restore-prepared deletion is missing absence provenance")
            })?;
            self.filesystem
                .recover_interrupted_replace_observed_with_provenance_and_backup_token(
                    &path,
                    &expected_before.0.0,
                    &expected_applied.0.0,
                    transaction_nonce,
                    Some(&journaled_token),
                    &journaled_token,
                    Some(applied_token),
                )
        } else if state == NativeWalState::RestorePrepared {
            let applied_token = decoded_applied_token.as_ref().ok_or_else(|| {
                BoundaryError::new("restore-prepared native WAL is missing applied provenance")
            })?;
            self.filesystem
                .recover_interrupted_replace_observed_with_provenance_and_backup_token(
                    &path,
                    &expected_applied.0.0,
                    &intended_restored.0.0,
                    transaction_nonce,
                    Some(&journaled_token),
                    applied_token,
                    decoded_restored_token.as_ref(),
                )
        } else {
            let installed_token = match state {
                NativeWalState::Prepared => decoded_applied_token.as_ref(),
                NativeWalState::Applied => match decoded_applied_token.as_ref() {
                    Some(token) => Some(token),
                    None if expected_before == expected_applied => Some(&journaled_token),
                    None => {
                        return Err(BoundaryError::new(
                            "applied native WAL is missing installed provenance",
                        ));
                    }
                },
                NativeWalState::RestorePrepared
                | NativeWalState::Restored
                | NativeWalState::Conflict => unreachable!("handled recovery state"),
            };
            self.filesystem
                .recover_interrupted_replace_observed_with_provenance_and_backup_token(
                    &path,
                    &expected_before.0.0,
                    &expected_applied.0.0,
                    transaction_nonce,
                    Some(&journaled_token),
                    &journaled_token,
                    installed_token,
                )
        };
        match phase {
            Ok(NativeRecoveryDisposition::Restored) => {}
            Ok(NativeRecoveryDisposition::Abandoned) => return Ok(RecoveryProbe::Conflict),
            Err(
                RunnerError::ConcurrentChange
                | RunnerError::UnsafeTopology
                | RunnerError::UnsupportedFileType,
            ) => return Ok(RecoveryProbe::Conflict),
            Err(error) => return Err(runner_boundary(error)),
        }
        match self.filesystem.snapshot(&path) {
            Ok(snapshot)
                if snapshot.object_token().is_some_and(|actual| {
                    if !actual.has_same_parent_binding(&journaled_token) {
                        return false;
                    }
                    if matches!(
                        state,
                        NativeWalState::RestorePrepared | NativeWalState::Restored
                    ) && snapshot.fingerprint() == &intended_restored.0.0
                    {
                        return decoded_restored_token
                            .as_ref()
                            .map_or(actual == &journaled_token, |expected| actual == expected);
                    }
                    if snapshot.fingerprint() == &expected_before.0.0 {
                        return actual == &journaled_token;
                    }
                    snapshot.fingerprint() == &expected_applied.0.0
                        && if expected_before == expected_applied {
                            actual == &journaled_token
                        } else {
                            decoded_applied_token.as_ref() == Some(actual)
                        }
                }) =>
            {
                let fingerprint = RestorableStateFingerprint(Sha256Digest(*snapshot.fingerprint()));
                if phase_started_applied && fingerprint == *intended_restored {
                    Ok(RecoveryProbe::RestoredNow(fingerprint))
                } else {
                    Ok(RecoveryProbe::Fingerprint(fingerprint))
                }
            }
            Ok(_) => Ok(RecoveryProbe::Conflict),
            Err(
                RunnerError::ConcurrentChange
                | RunnerError::UnsafeTopology
                | RunnerError::UnsupportedFileType,
            ) => Ok(RecoveryProbe::Conflict),
            Err(error) => Err(runner_boundary(error)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn restore_if_matches(
        &mut self,
        transaction_nonce: &[u8; 16],
        target: &WireNativeValue,
        object_token: &NativeObjectToken,
        applied_object_token: Option<&NativeObjectToken>,
        expected_applied: &RestorableStateFingerprint,
        intended_restored: &RestorableStateFingerprint,
        before_image: &[u8],
        persist_restored_candidate: &mut dyn FnMut(&NativeObjectToken) -> Result<(), BoundaryError>,
    ) -> Result<RecoveryRestore, BoundaryError> {
        let path = decode_native_path(target)?;
        let before = NativeState::decode_v1(before_image).map_err(runner_boundary)?;
        if before.fingerprint() != intended_restored.0.0 {
            return Err(BoundaryError::new(
                "native before-image does not match its restored fingerprint",
            ));
        }
        let journaled_token = decode_object_token(object_token)?;
        let applied_token = applied_object_token
            .ok_or_else(|| BoundaryError::new("native WAL is missing installed provenance"))
            .and_then(decode_object_token)?;
        let current = match self.filesystem.snapshot(&path) {
            Ok(snapshot) => snapshot,
            Err(
                RunnerError::ConcurrentChange
                | RunnerError::UnsafeTopology
                | RunnerError::UnsupportedFileType,
            ) => return Ok(RecoveryRestore::Conflict),
            Err(error) => return Err(runner_boundary(error)),
        };
        let Some(current_token) = current.object_token() else {
            return Ok(RecoveryRestore::Conflict);
        };
        if current.fingerprint() != &expected_applied.0.0
            || !current_token.has_same_parent_binding(&journaled_token)
            || current_token != &applied_token
        {
            return Ok(RecoveryRestore::Conflict);
        }
        let current_token = current_token.clone();
        let mut candidate_error = None;
        let outcome = match self
            .filesystem
            .compare_and_swap_observed_with_candidate_provenance(
                &path,
                &expected_applied.0.0,
                Some(&current_token),
                &before,
                transaction_nonce,
                &mut |candidate| {
                    if let Err(error) = persist_restored_candidate(&journal_token(candidate)) {
                        candidate_error = Some(error);
                        return Err(RunnerError::ConcurrentChange);
                    }
                    Ok(())
                },
            ) {
            Ok(outcome) => outcome,
            Err(failure) if candidate_error.is_some() => {
                let _ = failure;
                return Err(candidate_error
                    .take()
                    .expect("restored candidate error was checked"));
            }
            Err(failure)
                if matches!(
                    failure.error(),
                    RunnerError::ConcurrentChange
                        | RunnerError::UnsafeTopology
                        | RunnerError::UnsupportedFileType
                ) =>
            {
                return Ok(RecoveryRestore::Conflict);
            }
            Err(failure) => return Err(runner_boundary(failure.into_error())),
        };
        if outcome.snapshot().fingerprint() != &intended_restored.0.0 {
            return Err(BoundaryError::new(
                "restored native state does not match its journaled fingerprint",
            ));
        }
        Ok(RecoveryRestore::Restored)
    }

    fn cleanup_sandbox(
        &mut self,
        identity: &RecoverySandboxIdentity,
        outcome: RecoveryOutcome,
    ) -> Result<RecoveryCleanup, BoundaryError> {
        (self.cleanup)(identity.clone(), outcome).map(IntoRecoveryCleanup::into_recovery_cleanup)
    }

    fn cleanup_committed_mutation(
        &mut self,
        transaction_nonce: &[u8; 16],
        target: &WireNativeValue,
        object_token: &NativeObjectToken,
        expected_before: &RestorableStateFingerprint,
    ) -> Result<(), BoundaryError> {
        self.filesystem
            .cleanup_committed_delete_observed(
                &decode_native_path(target)?,
                &expected_before.0.0,
                transaction_nonce,
                &decode_object_token(object_token)?,
            )
            .map_err(runner_boundary)
    }

    fn rebind_applied_absence(
        &mut self,
        target: &WireNativeValue,
        object_token: &NativeObjectToken,
        expected_old_token: &NativeObjectToken,
        expected_applied: &RestorableStateFingerprint,
    ) -> Result<Option<NativeObjectToken>, BoundaryError> {
        let journaled_token = decode_object_token(object_token)?;
        let old_token = decode_object_token(expected_old_token)?;
        if !old_token.is_absence_generation()
            || !old_token.has_same_parent_binding(&journaled_token)
        {
            return Err(BoundaryError::new(
                "native absence rebind has invalid parent provenance",
            ));
        }
        let snapshot = match self.filesystem.snapshot(&decode_native_path(target)?) {
            Ok(snapshot) => snapshot,
            Err(
                RunnerError::ConcurrentChange
                | RunnerError::UnsafeTopology
                | RunnerError::UnsupportedFileType,
            ) => return Ok(None),
            Err(error) => return Err(runner_boundary(error)),
        };
        let Some(token) = snapshot.object_token() else {
            return Ok(None);
        };
        if snapshot.fingerprint() != &expected_applied.0.0
            || !token.is_absence_generation()
            || !token.has_same_parent_binding(&old_token)
        {
            return Ok(None);
        }
        Ok(Some(journal_token(token)))
    }
}

pub(super) fn runner_boundary(error: RunnerError) -> BoundaryError {
    BoundaryError::new(error.to_string())
}

fn journal_token(token: &RunnerObjectToken) -> NativeObjectToken {
    let mut topology = Vec::with_capacity(29);
    topology.push(1);
    topology.extend_from_slice(&token.reparse_tag().to_le_bytes());
    topology.extend_from_slice(&token.parent_volume().to_le_bytes());
    topology.extend_from_slice(token.parent_object());
    NativeObjectToken {
        volume: token.volume().to_le_bytes().to_vec(),
        object: token.object().to_vec(),
        topology,
    }
}

fn decode_object_token(token: &NativeObjectToken) -> Result<RunnerObjectToken, BoundaryError> {
    if token.volume.len() != 8
        || token.object.len() != 16
        || token.topology.len() != 29
        || token.topology[0] != 1
    {
        return Err(BoundaryError::new(
            "journaled native object token is invalid",
        ));
    }
    let volume =
        u64::from_le_bytes(
            token.volume.as_slice().try_into().map_err(|_| {
                BoundaryError::new("journaled native object token volume is invalid")
            })?,
        );
    let object = token
        .object
        .as_slice()
        .try_into()
        .map_err(|_| BoundaryError::new("journaled native object token identity is invalid"))?;
    let reparse_tag =
        u32::from_le_bytes(token.topology[1..5].try_into().map_err(|_| {
            BoundaryError::new("journaled native object token topology is invalid")
        })?);
    let parent_volume = u64::from_le_bytes(token.topology[5..13].try_into().map_err(|_| {
        BoundaryError::new("journaled native object token parent volume is invalid")
    })?);
    let parent_object = token.topology[13..29].try_into().map_err(|_| {
        BoundaryError::new("journaled native object token parent identity is invalid")
    })?;
    Ok(RunnerObjectToken::from_parts(
        volume,
        object,
        reparse_tag,
        parent_volume,
        parent_object,
    ))
}

pub(super) fn decode_native_path(target: &WireNativeValue) -> Result<PathBuf, BoundaryError> {
    target
        .validate()
        .map_err(|error| BoundaryError::new(error.to_string()))?;
    #[cfg(windows)]
    {
        use std::{ffi::OsString, os::windows::ffi::OsStringExt};

        if target.platform != NativePlatform::Windows {
            return Err(BoundaryError::new(
                "native recovery target does not match this platform",
            ));
        }
        let units = target
            .bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        if units.contains(&0) {
            return Err(BoundaryError::new("native recovery path contains NUL"));
        }
        let path = PathBuf::from(OsString::from_wide(&units));
        path.is_absolute()
            .then_some(path)
            .ok_or_else(|| BoundaryError::new("native recovery path is not absolute"))
    }
    #[cfg(target_os = "macos")]
    {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};

        if target.platform != NativePlatform::Macos || target.bytes.contains(&0) {
            return Err(BoundaryError::new(
                "native recovery target does not match this platform",
            ));
        }
        let path = PathBuf::from(OsString::from_vec(target.bytes.clone()));
        path.is_absolute()
            .then_some(path)
            .ok_or_else(|| BoundaryError::new("native recovery path is not absolute"))
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = target;
        Err(BoundaryError::new(
            "native recovery is unsupported on this platform",
        ))
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RecoverySummary {
    pub committed: usize,
    pub restored: usize,
    pub conflicts: usize,
    pub cleanup_conflicts: usize,
}

impl RecoverySummary {
    pub const fn recovered(self) -> usize {
        self.committed + self.restored + self.conflicts
    }
}

#[derive(Debug, Error)]
pub enum NativeRecoveryError {
    #[error(transparent)]
    Vault(#[from] VaultError),
    #[error(transparent)]
    Boundary(#[from] BoundaryError),
}

fn rebind_next_earlier_absence(
    vault: &mut Vault,
    io: &mut impl NativeRecoveryIo,
    fault: &mut impl RecoveryFaultHook,
    transaction_id: &str,
    wal: &mut [NativeWalRecord],
    later_position: usize,
    checkpoint_fresh_restore: bool,
) -> Result<bool, NativeRecoveryError> {
    let Some(later) = wal.get(later_position) else {
        return Err(
            VaultError::Validation("native WAL restore index is missing".to_owned()).into(),
        );
    };
    if later.applied_object_token.is_none() || later.restored_object_token.is_none() {
        return Ok(false);
    }
    let later_sequence = later.target_sequence;
    let later_parent = later.object_token.clone();
    let durable_checkpoint = later.absence_rebind.clone();
    let earlier_position = (0..later_position).rev().find(|position| {
        wal[*position].applied_object_token.is_some()
            && wal[*position]
                .object_token
                .has_same_parent_binding(&later_parent)
    });
    let Some(earlier_position) = earlier_position else {
        return Ok(false);
    };
    let earlier = &wal[earlier_position];
    let Some(old_token) = earlier.applied_object_token.as_ref() else {
        return Ok(false);
    };
    if !old_token.is_absence_generation() {
        return Ok(false);
    }
    let target_sequence = earlier.target_sequence;
    if matches!(
        earlier.state,
        NativeWalState::Applied | NativeWalState::Prepared
    ) {
        hit(
            fault,
            RecoveryAction::PrepareRestore,
            RecoveryMoment::Before,
            Some(target_sequence),
        )?;
        vault.transition_native_wal(
            transaction_id,
            target_sequence,
            NativeWalState::RestorePrepared,
        )?;
        wal[earlier_position].state = NativeWalState::RestorePrepared;
        hit(
            fault,
            RecoveryAction::PrepareRestore,
            RecoveryMoment::After,
            Some(target_sequence),
        )?;
    }
    if wal[earlier_position].state != NativeWalState::RestorePrepared {
        return Ok(false);
    }
    let old_token = wal[earlier_position]
        .applied_object_token
        .as_ref()
        .expect("checked applied absence token")
        .clone();
    let checkpoint = if let Some(checkpoint) = durable_checkpoint {
        if checkpoint.target_sequence != target_sequence {
            return Err(VaultError::Validation(
                "native WAL absence checkpoint names a non-nearest target".to_owned(),
            )
            .into());
        }
        checkpoint
    } else if checkpoint_fresh_restore {
        let Some(new_token) = io.rebind_applied_absence(
            &wal[earlier_position].target,
            &wal[earlier_position].object_token,
            &old_token,
            &wal[earlier_position].intended_applied,
        )?
        else {
            vault.transition_native_wal(
                transaction_id,
                target_sequence,
                NativeWalState::Conflict,
            )?;
            wal[earlier_position].state = NativeWalState::Conflict;
            return Ok(true);
        };
        hit(
            fault,
            RecoveryAction::CheckpointAbsence,
            RecoveryMoment::Before,
            Some(target_sequence),
        )?;
        vault.checkpoint_native_wal_absence_rebind(
            transaction_id,
            target_sequence,
            later_sequence,
            &old_token,
            &new_token,
        )?;
        let checkpoint = NativeWalAbsenceRebind {
            target_sequence,
            old_token: old_token.clone(),
            new_token,
        };
        wal[later_position].absence_rebind = Some(checkpoint.clone());
        hit(
            fault,
            RecoveryAction::CheckpointAbsence,
            RecoveryMoment::After,
            Some(target_sequence),
        )?;
        checkpoint
    } else {
        vault.transition_native_wal(transaction_id, target_sequence, NativeWalState::Conflict)?;
        wal[earlier_position].state = NativeWalState::Conflict;
        return Ok(true);
    };
    hit(
        fault,
        RecoveryAction::RebindAbsence,
        RecoveryMoment::Before,
        Some(target_sequence),
    )?;
    let live_token = io.rebind_applied_absence(
        &wal[earlier_position].target,
        &wal[earlier_position].object_token,
        &checkpoint.old_token,
        &wal[earlier_position].intended_applied,
    )?;
    if live_token.as_ref() != Some(&checkpoint.new_token) {
        vault.transition_native_wal(transaction_id, target_sequence, NativeWalState::Conflict)?;
        wal[earlier_position].state = NativeWalState::Conflict;
        return Ok(true);
    }
    vault.rebind_native_wal_applied_absence(
        transaction_id,
        target_sequence,
        later_sequence,
        &checkpoint.old_token,
        &checkpoint.new_token,
    )?;
    wal[earlier_position].applied_object_token = Some(checkpoint.new_token);
    hit(
        fault,
        RecoveryAction::RebindAbsence,
        RecoveryMoment::After,
        Some(target_sequence),
    )?;
    Ok(false)
}

pub fn recover_native_transactions(
    vault: &mut Vault,
    io: &mut impl NativeRecoveryIo,
) -> Result<RecoverySummary, NativeRecoveryError> {
    recover_native_transactions_with_faults(vault, io, &mut NoRecoveryFault)
}

pub fn recover_native_transactions_with_faults(
    vault: &mut Vault,
    io: &mut impl NativeRecoveryIo,
    fault: &mut impl RecoveryFaultHook,
) -> Result<RecoverySummary, NativeRecoveryError> {
    let mut summary = RecoverySummary::default();
    for mut transaction in vault.recoverable_native_transactions()? {
        hit(
            fault,
            RecoveryAction::PoisonGeneration,
            RecoveryMoment::Before,
            None,
        )?;
        vault.poison_interrupted_macos_generation(&transaction.transaction_id)?;
        hit(
            fault,
            RecoveryAction::PoisonGeneration,
            RecoveryMoment::After,
            None,
        )?;
        transaction = vault
            .native_transaction(&transaction.transaction_id)?
            .ok_or_else(|| VaultError::Validation("native transaction disappeared".to_owned()))?;

        let cleanup_already_conflicted =
            transaction.sandbox_cleanup_state == NativeSandboxCleanupState::Conflict;
        let cleanup_already_finished = transaction.current_step == 20;
        let outcome = if cleanup_already_conflicted || cleanup_already_finished {
            match transaction.status {
                NativeTransactionStatus::Committed => RecoveryOutcome::Committed,
                NativeTransactionStatus::Restored => RecoveryOutcome::Restored,
                NativeTransactionStatus::Conflict => RecoveryOutcome::Conflict,
                NativeTransactionStatus::Pending | NativeTransactionStatus::Restoring => {
                    return Err(VaultError::Validation(
                        "native cleanup conflict has no durable terminal outcome".to_owned(),
                    )
                    .into());
                }
            }
        } else if transaction.status == NativeTransactionStatus::Committed {
            for mutation in vault.native_wal(&transaction.transaction_id)? {
                io.cleanup_committed_mutation(
                    transaction.plan_id.as_bytes(),
                    &mutation.target,
                    &mutation.object_token,
                    &mutation.expected,
                )?;
            }
            RecoveryOutcome::Committed
        } else if matches!(
            transaction.status,
            NativeTransactionStatus::Restored | NativeTransactionStatus::Conflict
        ) {
            if transaction.status == NativeTransactionStatus::Conflict {
                RecoveryOutcome::Conflict
            } else {
                RecoveryOutcome::Restored
            }
        } else {
            hit(
                fault,
                RecoveryAction::BeginRecovery,
                RecoveryMoment::Before,
                None,
            )?;
            vault.begin_native_recovery(&transaction.transaction_id)?;
            hit(
                fault,
                RecoveryAction::BeginRecovery,
                RecoveryMoment::After,
                None,
            )?;
            let mut conflict = false;
            let mut wal = vault.native_wal(&transaction.transaction_id)?;
            for position in (0..wal.len()).rev() {
                let mut mutation = wal[position].clone();
                if mutation.state == NativeWalState::Conflict {
                    conflict = true;
                    continue;
                }
                if matches!(
                    mutation.state,
                    NativeWalState::Prepared | NativeWalState::Applied
                ) && mutation
                    .applied_object_token
                    .as_ref()
                    .is_some_and(NativeObjectToken::is_absence_generation)
                {
                    hit(
                        fault,
                        RecoveryAction::PrepareRestore,
                        RecoveryMoment::Before,
                        Some(mutation.target_sequence),
                    )?;
                    vault.transition_native_wal(
                        &transaction.transaction_id,
                        mutation.target_sequence,
                        NativeWalState::RestorePrepared,
                    )?;
                    mutation.state = NativeWalState::RestorePrepared;
                    wal[position].state = NativeWalState::RestorePrepared;
                    hit(
                        fault,
                        RecoveryAction::PrepareRestore,
                        RecoveryMoment::After,
                        Some(mutation.target_sequence),
                    )?;
                }
                if mutation.state == NativeWalState::RestorePrepared
                    && mutation
                        .applied_object_token
                        .as_ref()
                        .is_some_and(NativeObjectToken::is_absence_generation)
                    && mutation.restored_object_token.is_none()
                {
                    vault.record_native_wal_restored_candidate(
                        &transaction.transaction_id,
                        mutation.target_sequence,
                        &mutation.object_token,
                    )?;
                    mutation.restored_object_token = Some(mutation.object_token.clone());
                    wal[position].restored_object_token = Some(mutation.object_token.clone());
                }
                let (current, phase_restored_now) = match io.probe(
                    transaction.plan_id.as_bytes(),
                    &mutation.target,
                    &mutation.object_token,
                    mutation.applied_object_token.as_ref(),
                    mutation.restored_object_token.as_ref(),
                    mutation.state,
                    &mutation.expected,
                    &mutation.intended_applied,
                    &mutation.intended_restored,
                )? {
                    RecoveryProbe::Fingerprint(current) => (current, false),
                    RecoveryProbe::RestoredNow(current) => (current, true),
                    RecoveryProbe::Conflict => {
                        conflict = true;
                        if mutation.state != NativeWalState::Conflict {
                            hit(
                                fault,
                                RecoveryAction::MarkConflict,
                                RecoveryMoment::Before,
                                Some(mutation.target_sequence),
                            )?;
                            vault.transition_native_wal(
                                &transaction.transaction_id,
                                mutation.target_sequence,
                                NativeWalState::Conflict,
                            )?;
                            mutation.state = NativeWalState::Conflict;
                            wal[position].state = NativeWalState::Conflict;
                            hit(
                                fault,
                                RecoveryAction::MarkConflict,
                                RecoveryMoment::After,
                                Some(mutation.target_sequence),
                            )?;
                        }
                        continue;
                    }
                };
                let recovery = RecoveryMutation {
                    state: if mutation.state == NativeWalState::Prepared
                        && mutation.applied_object_token.is_some()
                    {
                        NativeWalState::Applied
                    } else {
                        mutation.state
                    },
                    before: mutation.expected.clone(),
                    applied: mutation.intended_applied.clone(),
                    restored: mutation.intended_restored.clone(),
                };
                match classify_recovery(&recovery, &current, TransactionCommitState::PreCommit) {
                    RecoveryDecision::PrepareRestore => {
                        hit(
                            fault,
                            RecoveryAction::PrepareRestore,
                            RecoveryMoment::Before,
                            Some(mutation.target_sequence),
                        )?;
                        vault.transition_native_wal(
                            &transaction.transaction_id,
                            mutation.target_sequence,
                            NativeWalState::RestorePrepared,
                        )?;
                        mutation.state = NativeWalState::RestorePrepared;
                        wal[position].state = NativeWalState::RestorePrepared;
                        hit(
                            fault,
                            RecoveryAction::PrepareRestore,
                            RecoveryMoment::After,
                            Some(mutation.target_sequence),
                        )?;
                        let before_image = vault.native_before_image(&mutation.before_image_id)?;
                        hit(
                            fault,
                            RecoveryAction::RestoreTarget,
                            RecoveryMoment::Before,
                            Some(mutation.target_sequence),
                        )?;
                        let mut restored_candidate = None;
                        match io.restore_if_matches(
                            transaction.plan_id.as_bytes(),
                            &mutation.target,
                            &mutation.object_token,
                            mutation.applied_object_token.as_ref(),
                            &mutation.intended_applied,
                            &mutation.intended_restored,
                            &before_image,
                            &mut |candidate_token| {
                                vault
                                    .record_native_wal_restored_candidate(
                                        &transaction.transaction_id,
                                        mutation.target_sequence,
                                        candidate_token,
                                    )
                                    .map_err(|error| BoundaryError::new(error.to_string()))?;
                                restored_candidate = Some(candidate_token.clone());
                                Ok(())
                            },
                        )? {
                            RecoveryRestore::Restored => {
                                if let Some(candidate) = restored_candidate {
                                    mutation.restored_object_token = Some(candidate.clone());
                                    wal[position].restored_object_token = Some(candidate);
                                }
                                hit(
                                    fault,
                                    RecoveryAction::RestoreTarget,
                                    RecoveryMoment::After,
                                    Some(mutation.target_sequence),
                                )?;
                                conflict |= rebind_next_earlier_absence(
                                    vault,
                                    io,
                                    fault,
                                    &transaction.transaction_id,
                                    &mut wal,
                                    position,
                                    true,
                                )?;
                                hit(
                                    fault,
                                    RecoveryAction::MarkRestored,
                                    RecoveryMoment::Before,
                                    Some(mutation.target_sequence),
                                )?;
                                vault.transition_native_wal(
                                    &transaction.transaction_id,
                                    mutation.target_sequence,
                                    NativeWalState::Restored,
                                )?;
                                mutation.state = NativeWalState::Restored;
                                wal[position].state = NativeWalState::Restored;
                                hit(
                                    fault,
                                    RecoveryAction::MarkRestored,
                                    RecoveryMoment::After,
                                    Some(mutation.target_sequence),
                                )?;
                            }
                            RecoveryRestore::Conflict => {
                                hit(
                                    fault,
                                    RecoveryAction::RestoreTarget,
                                    RecoveryMoment::After,
                                    Some(mutation.target_sequence),
                                )?;
                                conflict = true;
                                hit(
                                    fault,
                                    RecoveryAction::MarkConflict,
                                    RecoveryMoment::Before,
                                    Some(mutation.target_sequence),
                                )?;
                                vault.transition_native_wal(
                                    &transaction.transaction_id,
                                    mutation.target_sequence,
                                    NativeWalState::Conflict,
                                )?;
                                mutation.state = NativeWalState::Conflict;
                                wal[position].state = NativeWalState::Conflict;
                                hit(
                                    fault,
                                    RecoveryAction::MarkConflict,
                                    RecoveryMoment::After,
                                    Some(mutation.target_sequence),
                                )?;
                            }
                        }
                    }
                    RecoveryDecision::MarkRestored => {
                        if mutation.state == NativeWalState::Applied
                            || (mutation.state == NativeWalState::Prepared
                                && mutation.applied_object_token.is_some())
                        {
                            hit(
                                fault,
                                RecoveryAction::PrepareRestore,
                                RecoveryMoment::Before,
                                Some(mutation.target_sequence),
                            )?;
                            vault.transition_native_wal(
                                &transaction.transaction_id,
                                mutation.target_sequence,
                                NativeWalState::RestorePrepared,
                            )?;
                            mutation.state = NativeWalState::RestorePrepared;
                            wal[position].state = NativeWalState::RestorePrepared;
                            hit(
                                fault,
                                RecoveryAction::PrepareRestore,
                                RecoveryMoment::After,
                                Some(mutation.target_sequence),
                            )?;
                        }
                        conflict |= rebind_next_earlier_absence(
                            vault,
                            io,
                            fault,
                            &transaction.transaction_id,
                            &mut wal,
                            position,
                            phase_restored_now,
                        )?;
                        hit(
                            fault,
                            RecoveryAction::MarkRestored,
                            RecoveryMoment::Before,
                            Some(mutation.target_sequence),
                        )?;
                        vault.transition_native_wal(
                            &transaction.transaction_id,
                            mutation.target_sequence,
                            NativeWalState::Restored,
                        )?;
                        mutation.state = NativeWalState::Restored;
                        wal[position].state = NativeWalState::Restored;
                        hit(
                            fault,
                            RecoveryAction::MarkRestored,
                            RecoveryMoment::After,
                            Some(mutation.target_sequence),
                        )?;
                    }
                    RecoveryDecision::AlreadyRestored => {
                        conflict |= rebind_next_earlier_absence(
                            vault,
                            io,
                            fault,
                            &transaction.transaction_id,
                            &mut wal,
                            position,
                            false,
                        )?;
                    }
                    RecoveryDecision::MarkConflict => {
                        conflict = true;
                        hit(
                            fault,
                            RecoveryAction::MarkConflict,
                            RecoveryMoment::Before,
                            Some(mutation.target_sequence),
                        )?;
                        vault.transition_native_wal(
                            &transaction.transaction_id,
                            mutation.target_sequence,
                            NativeWalState::Conflict,
                        )?;
                        mutation.state = NativeWalState::Conflict;
                        wal[position].state = NativeWalState::Conflict;
                        hit(
                            fault,
                            RecoveryAction::MarkConflict,
                            RecoveryMoment::After,
                            Some(mutation.target_sequence),
                        )?;
                    }
                    RecoveryDecision::PreserveConflict => conflict = true,
                    RecoveryDecision::FinalizeCommitted => unreachable!("precommit classification"),
                }
            }
            hit(
                fault,
                RecoveryAction::FinishRecovery,
                RecoveryMoment::Before,
                None,
            )?;
            vault.finish_native_recovery(&transaction.transaction_id, conflict)?;
            hit(
                fault,
                RecoveryAction::FinishRecovery,
                RecoveryMoment::After,
                None,
            )?;
            if conflict {
                RecoveryOutcome::Conflict
            } else {
                RecoveryOutcome::Restored
            }
        };

        let cleanup_identity = recovery_sandbox_identity(&transaction.identity)?;

        let cleanup = if cleanup_already_conflicted {
            RecoveryCleanup::Conflict
        } else if cleanup_already_finished {
            RecoveryCleanup::Cleaned
        } else {
            hit(
                fault,
                RecoveryAction::CleanupSandbox,
                RecoveryMoment::Before,
                None,
            )?;
            let cleanup = io.cleanup_sandbox(&cleanup_identity, outcome)?;
            hit(
                fault,
                RecoveryAction::CleanupSandbox,
                RecoveryMoment::After,
                None,
            )?;
            cleanup
        };
        if cleanup == RecoveryCleanup::Conflict {
            if !cleanup_already_conflicted {
                hit(
                    fault,
                    RecoveryAction::MarkCleanupConflict,
                    RecoveryMoment::Before,
                    None,
                )?;
                vault.mark_native_cleanup_conflict(&transaction.transaction_id)?;
                hit(
                    fault,
                    RecoveryAction::MarkCleanupConflict,
                    RecoveryMoment::After,
                    None,
                )?;
            }
            summary.cleanup_conflicts += 1;
        }
        match outcome {
            RecoveryOutcome::Committed => summary.committed += 1,
            RecoveryOutcome::Restored => summary.restored += 1,
            RecoveryOutcome::Conflict => summary.conflicts += 1,
        }
        hit(
            fault,
            RecoveryAction::FinishCleanup,
            RecoveryMoment::Before,
            None,
        )?;
        vault.finish_native_cleanup(&transaction.transaction_id)?;
        hit(
            fault,
            RecoveryAction::FinishCleanup,
            RecoveryMoment::After,
            None,
        )?;
    }
    Ok(summary)
}

fn recovery_sandbox_identity(
    identity: &NativeSandboxIdentity,
) -> Result<RecoverySandboxIdentity, VaultError> {
    match identity {
        NativeSandboxIdentity::Windows { moniker, sid } => Ok(RecoverySandboxIdentity::Windows {
            moniker: moniker.clone(),
            sid: std::str::from_utf8(sid)
                .map_err(|_| VaultError::Validation("Windows sandbox SID is not UTF-8".to_owned()))?
                .to_owned(),
        }),
        NativeSandboxIdentity::Macos {
            generation_id,
            bundle_id,
            container,
            guardian_pgid,
            bundle_root,
            signed_digest,
            container_root,
            substate,
            state,
        } => Ok(RecoverySandboxIdentity::Macos {
            generation_id: generation_id.clone(),
            bundle_id: bundle_id.clone(),
            container: container.clone(),
            guardian_pgid: *guardian_pgid,
            bundle_root: bundle_root.clone(),
            signed_digest: *signed_digest,
            container_root: container_root.clone(),
            substate: *substate,
            state: *state,
        }),
    }
}

fn hit(
    fault: &mut impl RecoveryFaultHook,
    action: RecoveryAction,
    moment: RecoveryMoment,
    target_sequence: Option<u32>,
) -> Result<(), BoundaryError> {
    fault.at(&RecoveryFaultPoint {
        action,
        moment,
        target_sequence,
    })
}

pub fn classify_recovery(
    mutation: &RecoveryMutation,
    current: &RestorableStateFingerprint,
    commit: TransactionCommitState,
) -> RecoveryDecision {
    if commit == TransactionCommitState::Committed {
        return RecoveryDecision::FinalizeCommitted;
    }
    if mutation.state == MutationWalState::Conflict {
        return RecoveryDecision::PreserveConflict;
    }
    if current == &mutation.restored || current == &mutation.before {
        return if mutation.state == MutationWalState::Restored {
            RecoveryDecision::AlreadyRestored
        } else {
            RecoveryDecision::MarkRestored
        };
    }
    if current == &mutation.applied {
        return if mutation.state == MutationWalState::Prepared {
            RecoveryDecision::MarkConflict
        } else {
            RecoveryDecision::PrepareRestore
        };
    }
    RecoveryDecision::MarkConflict
}
