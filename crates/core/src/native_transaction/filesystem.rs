use std::path::PathBuf;

use context_relay_native_runner::{
    NativeObjectToken as RunnerObjectToken, NativeRecoveryDisposition, NativeState,
    OsNativeFileSystem, RunnerError,
};
use context_relay_protocol::{NativePlatform, Sha256Digest, WireNativeValue};
use sha2::{Digest, Sha256};

use super::{
    engine::{
        BeforeImage, BoundaryError, CheckpointAppliedAbsence, CompensationOutcome, MutationOutcome,
        NativeFileSystem, RebindAppliedAbsence,
    },
    model::{ApprovedMutation, NativeObjectToken, RestorableStateFingerprint},
    recovery::{decode_native_path, runner_boundary},
};

struct Observation {
    mutation: ApprovedMutation,
    path: PathBuf,
    before: NativeState,
    token: RunnerObjectToken,
    intended: NativeState,
    preflighted: bool,
    applied_token: Option<RunnerObjectToken>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompensationSnapshot {
    AlreadyRestored,
    AttributedApplied,
    Unattributed,
}

pub struct OsNativeTransactionFileSystem {
    filesystem: OsNativeFileSystem,
    transaction_nonce: [u8; 16],
    observations: Vec<Observation>,
}

impl OsNativeTransactionFileSystem {
    pub const fn new(transaction_nonce: [u8; 16]) -> Self {
        Self {
            filesystem: OsNativeFileSystem::new(),
            transaction_nonce,
            observations: Vec::new(),
        }
    }

    pub fn apply_mutation(
        &mut self,
        transaction_nonce: &[u8; 16],
        mutation: &ApprovedMutation,
    ) -> Result<MutationOutcome, BoundaryError> {
        <Self as NativeFileSystem>::apply_mutation(self, transaction_nonce, mutation, &mut |_| {
            Ok(())
        })
    }

    pub fn restore_matching_applied_targets(
        &mut self,
        transaction_nonce: &[u8; 16],
    ) -> Result<CompensationOutcome, BoundaryError> {
        <Self as NativeFileSystem>::restore_matching_applied_targets(
            self,
            transaction_nonce,
            &mut |_, _| Ok(()),
            &mut |_, _, _, _| Ok(()),
            &mut |_, _, _, _| Ok(()),
        )
    }

    fn require_nonce(&self, transaction_nonce: &[u8; 16]) -> Result<(), BoundaryError> {
        (&self.transaction_nonce == transaction_nonce)
            .then_some(())
            .ok_or_else(|| BoundaryError::new("native transaction nonce changed"))
    }
}

impl NativeFileSystem for OsNativeTransactionFileSystem {
    fn create_before_images(
        &mut self,
        mutations: &[ApprovedMutation],
    ) -> Result<Vec<BeforeImage>, BoundaryError> {
        if !self.observations.is_empty() {
            return Err(BoundaryError::new(
                "native before-images were already captured",
            ));
        }
        let mut observations = Vec::with_capacity(mutations.len());
        let mut images = Vec::with_capacity(mutations.len());
        for (index, mutation) in mutations.iter().enumerate() {
            if mutations[..index]
                .iter()
                .any(|earlier| earlier.target == mutation.target)
            {
                return Err(BoundaryError::new(
                    "native mutation target appears more than once",
                ));
            }
            let path = decode_native_path(&mutation.target)?;
            let snapshot = self.filesystem.snapshot(&path).map_err(runner_boundary)?;
            let fingerprint = RestorableStateFingerprint(Sha256Digest(*snapshot.fingerprint()));
            if fingerprint != mutation.expected {
                return Err(BoundaryError::new(
                    "native target changed before its before-image was captured",
                ));
            }
            let token = snapshot
                .object_token()
                .cloned()
                .ok_or_else(|| BoundaryError::new("native object token is missing"))?;
            let encoded = snapshot.state().encode_v1().map_err(runner_boundary)?;
            let intended = NativeState::decode_v1(&mutation.content).map_err(runner_boundary)?;
            if intended.encode_v1().map_err(runner_boundary)? != mutation.content
                || intended.fingerprint() != mutation.intended.0.0
            {
                return Err(BoundaryError::new(
                    "approved native state is noncanonical or does not match its intended fingerprint",
                ));
            }
            images.push(BeforeImage {
                id: before_image_id(
                    &self.transaction_nonce,
                    index,
                    &mutation.target,
                    &mutation.expected.0.0,
                ),
                target: mutation.target.clone(),
                object_token: journal_token(&token),
                fingerprint,
                encrypted_state: encoded,
            });
            observations.push(Observation {
                mutation: mutation.clone(),
                path,
                before: snapshot.state().clone(),
                token,
                intended,
                preflighted: false,
                applied_token: None,
            });
        }
        self.observations = observations;
        Ok(images)
    }

    fn record_native_metadata(&mut self, images: &[BeforeImage]) -> Result<(), BoundaryError> {
        if images.len() != self.observations.len()
            || images.iter().zip(&self.observations).enumerate().any(
                |(index, (image, observation))| {
                    image.id
                        != before_image_id(
                            &self.transaction_nonce,
                            index,
                            &observation.mutation.target,
                            &observation.mutation.expected.0.0,
                        )
                        || image.target != observation.mutation.target
                        || image.object_token != journal_token(&observation.token)
                        || image.fingerprint != observation.mutation.expected
                        || observation.before.encode_v1().ok().as_deref()
                            != Some(image.encrypted_state.as_slice())
                },
            )
        {
            return Err(BoundaryError::new(
                "native metadata does not match its before-image",
            ));
        }
        Ok(())
    }

    fn compare_and_swap_targets(
        &mut self,
        mutations: &[ApprovedMutation],
    ) -> Result<(), BoundaryError> {
        for observation in &mut self.observations {
            observation.preflighted = false;
        }
        if mutations.len() != self.observations.len() {
            return Err(BoundaryError::new(
                "native preflight mutation count changed",
            ));
        }
        for (mutation, observation) in mutations.iter().zip(&self.observations) {
            if mutation != &observation.mutation {
                return Err(BoundaryError::new("native preflight mutation changed"));
            }
            let snapshot = self
                .filesystem
                .snapshot(&observation.path)
                .map_err(runner_boundary)?;
            if snapshot.fingerprint() != &mutation.expected.0.0
                || snapshot.object_token() != Some(&observation.token)
            {
                return Err(BoundaryError::new(
                    "native target changed after its before-image was captured",
                ));
            }
        }
        for observation in &mut self.observations {
            observation.preflighted = true;
        }
        Ok(())
    }

    fn apply_mutation(
        &mut self,
        transaction_nonce: &[u8; 16],
        mutation: &ApprovedMutation,
        persist_candidate: &mut dyn FnMut(&NativeObjectToken) -> Result<(), BoundaryError>,
    ) -> Result<MutationOutcome, BoundaryError> {
        self.require_nonce(transaction_nonce)?;
        let observation = self
            .observations
            .iter_mut()
            .find(|observation| observation.mutation.target == mutation.target)
            .ok_or_else(|| BoundaryError::new("native mutation has no before-image"))?;
        if mutation != &observation.mutation || !observation.preflighted {
            return Err(BoundaryError::new(
                "native mutation was not approved by preflight",
            ));
        }
        let mut persisted_candidate = None;
        let mut candidate_error = None;
        let outcome = match self
            .filesystem
            .compare_and_swap_observed_with_candidate_provenance(
                &observation.path,
                &mutation.expected.0.0,
                Some(&observation.token),
                &observation.intended,
                transaction_nonce,
                &mut |candidate| {
                    let token = journal_token(candidate);
                    if let Err(error) = persist_candidate(&token) {
                        candidate_error = Some(error);
                        return Err(context_relay_native_runner::RunnerError::ConcurrentChange);
                    }
                    persisted_candidate = Some(candidate.clone());
                    Ok(())
                },
            ) {
            Ok(outcome) => outcome,
            Err(failure) => {
                observation.applied_token =
                    failure.installed_token().cloned().or(persisted_candidate);
                if let Some(error) = candidate_error {
                    return Err(error);
                }
                return Err(runner_boundary(failure.into_error()));
            }
        };
        observation.applied_token = outcome.installed_token().cloned().or(persisted_candidate);
        if outcome.snapshot().fingerprint() != &mutation.intended.0.0
            || outcome.wrote() != (mutation.expected != mutation.intended)
            || outcome.wrote() != outcome.installed_token().is_some()
        {
            return Err(BoundaryError::new(
                "native mutation result differs from the approved state",
            ));
        }
        if outcome.wrote() && observation.applied_token.is_none() {
            return Err(BoundaryError::new("applied native object token is missing"));
        }
        Ok(MutationOutcome {
            wrote: outcome.wrote(),
            resulting_fingerprint: RestorableStateFingerprint(Sha256Digest(
                *outcome.snapshot().fingerprint(),
            )),
        })
    }

    fn mutation_provenance(&self, mutation: &ApprovedMutation) -> Option<NativeObjectToken> {
        self.observations
            .iter()
            .find(|observation| observation.mutation.target == mutation.target)
            .and_then(|observation| observation.applied_token.as_ref())
            .map(journal_token)
    }

    fn restore_matching_applied_targets(
        &mut self,
        transaction_nonce: &[u8; 16],
        persist_restored_candidate: &mut dyn FnMut(
            usize,
            &NativeObjectToken,
        ) -> Result<(), BoundaryError>,
        checkpoint_applied_absence: &mut CheckpointAppliedAbsence<'_>,
        rebind_applied_absence: &mut RebindAppliedAbsence<'_>,
    ) -> Result<CompensationOutcome, BoundaryError> {
        self.require_nonce(transaction_nonce)?;
        let mut first_error = None;
        let mut conflicts = Vec::new();
        let mut chained_conflicts = vec![false; self.observations.len()];
        for index in (0..self.observations.len()).rev() {
            if chained_conflicts[index] {
                continue;
            }
            let observation = &mut self.observations[index];
            if observation
                .applied_token
                .as_ref()
                .is_some_and(RunnerObjectToken::is_absence_generation)
            {
                persist_restored_candidate(index, &journal_token(&observation.token))?;
            }
            let phase_abandoned = match self
                .filesystem
                .recover_interrupted_replace_observed_with_provenance(
                    &observation.path,
                    &observation.mutation.expected.0.0,
                    &observation.mutation.intended.0.0,
                    transaction_nonce,
                    Some(&observation.token),
                    observation.applied_token.as_ref(),
                ) {
                Ok(NativeRecoveryDisposition::Restored) => false,
                Ok(NativeRecoveryDisposition::Abandoned) => true,
                Err(error) => {
                    first_error.get_or_insert_with(|| runner_boundary(error));
                    continue;
                }
            };
            let current = match self.filesystem.snapshot(&observation.path) {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    first_error.get_or_insert_with(|| runner_boundary(error));
                    continue;
                }
            };
            let classification = match classify_compensation_snapshot(
                current.fingerprint(),
                current.object_token(),
                &observation.token,
                observation.applied_token.as_ref(),
                &observation.mutation.expected.0.0,
                &observation.mutation.intended.0.0,
                phase_abandoned,
            ) {
                Ok(classification) => classification,
                Err(error) => {
                    first_error.get_or_insert(error);
                    continue;
                }
            };
            match classification {
                CompensationSnapshot::AlreadyRestored => {
                    let had_applied = observation.applied_token.is_some();
                    if had_applied {
                        persist_restored_candidate(index, &journal_token(&observation.token))?;
                    }
                    observation.applied_token = None;
                    if had_applied
                        && let Some(conflict_index) = rebind_next_earlier_absence(
                            &self.filesystem,
                            &mut self.observations,
                            index,
                            checkpoint_applied_absence,
                            rebind_applied_absence,
                        )?
                    {
                        self.observations[conflict_index].applied_token = None;
                        chained_conflicts[conflict_index] = true;
                        conflicts.push(u32::try_from(conflict_index).map_err(|_| {
                            BoundaryError::new("native compensation index exceeds u32")
                        })?);
                    }
                    continue;
                }
                CompensationSnapshot::Unattributed => {
                    observation.applied_token = None;
                    conflicts.push(u32::try_from(index).map_err(|_| {
                        BoundaryError::new("native compensation index exceeds u32")
                    })?);
                    continue;
                }
                CompensationSnapshot::AttributedApplied => {}
            }
            let Some(applied_token) = observation.applied_token.as_ref() else {
                first_error.get_or_insert_with(|| {
                    BoundaryError::new("attributed native object token is missing")
                });
                continue;
            };
            let mut restored_candidate = None;
            let mut candidate_error = None;
            let outcome = match self
                .filesystem
                .compare_and_swap_observed_with_candidate_provenance(
                    &observation.path,
                    &observation.mutation.intended.0.0,
                    Some(applied_token),
                    &observation.before,
                    transaction_nonce,
                    &mut |candidate| {
                        if let Err(error) =
                            persist_restored_candidate(index, &journal_token(candidate))
                        {
                            candidate_error = Some(error);
                            return Err(context_relay_native_runner::RunnerError::ConcurrentChange);
                        }
                        restored_candidate = Some(candidate.clone());
                        Ok(())
                    },
                ) {
                Ok(outcome) => outcome,
                Err(failure) => {
                    if let Some(error) = candidate_error {
                        first_error.get_or_insert(error);
                    } else {
                        first_error.get_or_insert_with(|| runner_boundary(failure.into_error()));
                    }
                    continue;
                }
            };
            if outcome.snapshot().fingerprint() != &observation.mutation.expected.0.0 {
                first_error.get_or_insert_with(|| {
                    BoundaryError::new("restored native state differs from its before-image")
                });
                continue;
            }
            if outcome.wrote() && restored_candidate.is_none() {
                first_error.get_or_insert_with(|| {
                    BoundaryError::new("restored native object token is missing")
                });
                continue;
            }
            observation.applied_token = None;
            if let Some(conflict_index) = rebind_next_earlier_absence(
                &self.filesystem,
                &mut self.observations,
                index,
                checkpoint_applied_absence,
                rebind_applied_absence,
            )? {
                self.observations[conflict_index].applied_token = None;
                chained_conflicts[conflict_index] = true;
                conflicts
                    .push(u32::try_from(conflict_index).map_err(|_| {
                        BoundaryError::new("native compensation index exceeds u32")
                    })?);
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(CompensationOutcome::new(conflicts)),
        }
    }

    fn finish_committed_targets(
        &mut self,
        transaction_nonce: &[u8; 16],
    ) -> Result<(), BoundaryError> {
        self.require_nonce(transaction_nonce)?;
        for observation in &self.observations {
            if matches!(observation.intended, NativeState::Absent { .. }) {
                self.filesystem
                    .cleanup_committed_delete_observed(
                        &observation.path,
                        &observation.mutation.expected.0.0,
                        transaction_nonce,
                        &observation.token,
                    )
                    .map_err(runner_boundary)?;
            }
        }
        Ok(())
    }
}

fn rebind_next_earlier_absence(
    filesystem: &OsNativeFileSystem,
    observations: &mut [Observation],
    later_index: usize,
    persist_checkpoint: &mut CheckpointAppliedAbsence<'_>,
    persist_rebind: &mut RebindAppliedAbsence<'_>,
) -> Result<Option<usize>, BoundaryError> {
    let later_parent = observations
        .get(later_index)
        .ok_or_else(|| BoundaryError::new("native restore index is missing"))?
        .token
        .clone();
    for earlier_index in (0..later_index).rev() {
        let observation = &mut observations[earlier_index];
        let Some(old_token) = observation.applied_token.as_ref() else {
            continue;
        };
        if !old_token.has_same_parent_binding(&later_parent) {
            continue;
        }
        if !old_token.is_absence_generation() {
            return Ok(None);
        }
        let old_token = old_token.clone();
        let current = match filesystem.snapshot(&observation.path) {
            Ok(current) => current,
            Err(
                RunnerError::ConcurrentChange
                | RunnerError::UnsafeTopology
                | RunnerError::UnsupportedFileType,
            ) => return Ok(Some(earlier_index)),
            Err(error) => return Err(runner_boundary(error)),
        };
        let current_token = current
            .object_token()
            .filter(|token| token.is_absence_generation())
            .filter(|token| token.has_same_parent_binding(&old_token))
            .cloned();
        if current.fingerprint() != &observation.mutation.intended.0.0 {
            return Ok(Some(earlier_index));
        }
        let Some(current_token) = current_token else {
            return Ok(Some(earlier_index));
        };
        let old_journal_token = journal_token(&old_token);
        let new_journal_token = journal_token(&current_token);
        persist_checkpoint(
            earlier_index,
            later_index,
            &old_journal_token,
            &new_journal_token,
        )?;
        let verified = match filesystem.snapshot(&observation.path) {
            Ok(verified) => verified,
            Err(
                RunnerError::ConcurrentChange
                | RunnerError::UnsafeTopology
                | RunnerError::UnsupportedFileType,
            ) => return Ok(Some(earlier_index)),
            Err(error) => return Err(runner_boundary(error)),
        };
        if verified.fingerprint() != &observation.mutation.intended.0.0
            || verified.object_token() != Some(&current_token)
        {
            return Ok(Some(earlier_index));
        }
        persist_rebind(
            earlier_index,
            later_index,
            &old_journal_token,
            &new_journal_token,
        )?;
        observation.applied_token = Some(current_token);
        return Ok(None);
    }
    Ok(None)
}

fn classify_compensation_snapshot(
    current_fingerprint: &[u8; 32],
    current_token: Option<&RunnerObjectToken>,
    original_token: &RunnerObjectToken,
    applied_token: Option<&RunnerObjectToken>,
    expected_before: &[u8; 32],
    intended: &[u8; 32],
    phase_abandoned: bool,
) -> Result<CompensationSnapshot, BoundaryError> {
    let current_token = current_token
        .ok_or_else(|| BoundaryError::new("native compensation object token is missing"))?;
    if !current_token.has_same_parent_binding(original_token) {
        return Err(BoundaryError::new(
            "native target parent changed during compensation",
        ));
    }
    if current_fingerprint == expected_before {
        return Ok(CompensationSnapshot::AlreadyRestored);
    }
    if phase_abandoned {
        return Ok(CompensationSnapshot::Unattributed);
    }
    if let Some(applied_token) = applied_token {
        if current_fingerprint == intended && current_token == applied_token {
            return Ok(CompensationSnapshot::AttributedApplied);
        }
        return Err(BoundaryError::new(
            "native target changed after it was applied",
        ));
    }
    Ok(CompensationSnapshot::Unattributed)
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

fn before_image_id(
    transaction_nonce: &[u8; 16],
    index: usize,
    target: &WireNativeValue,
    expected: &[u8; 32],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"context-relay/before-image/v1\0");
    hasher.update(transaction_nonce);
    hasher.update((index as u64).to_le_bytes());
    hasher.update([match target.platform {
        NativePlatform::Windows => 1,
        NativePlatform::Macos => 2,
    }]);
    hasher.update((target.bytes.len() as u64).to_le_bytes());
    hasher.update(&target.bytes);
    hasher.update(expected);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{CompensationSnapshot, RunnerObjectToken, classify_compensation_snapshot};

    const BEFORE: [u8; 32] = [1; 32];
    const INTENDED: [u8; 32] = [2; 32];

    fn token(object: u8, parent_object: u8) -> RunnerObjectToken {
        RunnerObjectToken::from_parts(7, [object; 16], 0, 11, [parent_object; 16])
    }

    #[test]
    fn compensation_accepts_a_backup_already_restored_by_phase_recovery() {
        let original = token(1, 3);
        let applied = token(2, 3);
        let restored = token(4, 3);

        assert_eq!(
            classify_compensation_snapshot(
                &BEFORE,
                Some(&restored),
                &original,
                Some(&applied),
                &BEFORE,
                &INTENDED,
                false,
            )
            .expect("already-restored before-state should be accepted"),
            CompensationSnapshot::AlreadyRestored,
        );
    }

    #[test]
    fn compensation_only_attributes_the_exact_installed_object() {
        let original = token(1, 3);
        let applied = token(2, 3);
        let concurrent_identical = token(5, 3);

        assert_eq!(
            classify_compensation_snapshot(
                &INTENDED,
                Some(&applied),
                &original,
                Some(&applied),
                &BEFORE,
                &INTENDED,
                false,
            )
            .expect("the exact installed object should be attributed"),
            CompensationSnapshot::AttributedApplied,
        );
        assert!(
            classify_compensation_snapshot(
                &INTENDED,
                Some(&concurrent_identical),
                &original,
                Some(&applied),
                &BEFORE,
                &INTENDED,
                false,
            )
            .is_err(),
            "an identical concurrent object must not be attributed to this transaction",
        );
    }

    #[test]
    fn compensation_rejects_an_already_restored_state_under_a_replaced_parent() {
        let original = token(1, 3);
        let applied = token(2, 3);
        let replaced_parent = token(4, 9);

        assert!(
            classify_compensation_snapshot(
                &BEFORE,
                Some(&replaced_parent),
                &original,
                Some(&applied),
                &BEFORE,
                &INTENDED,
                false,
            )
            .is_err(),
        );
    }

    #[test]
    fn compensation_preserves_unattributed_state() {
        let original = token(1, 3);
        let current = token(5, 3);

        assert_eq!(
            classify_compensation_snapshot(
                &INTENDED,
                Some(&current),
                &original,
                None,
                &BEFORE,
                &INTENDED,
                false,
            )
            .expect("unattributed state should be preserved"),
            CompensationSnapshot::Unattributed,
        );
    }

    #[test]
    fn compensation_finalizes_a_safely_abandoned_identical_replacement() {
        let original = token(1, 3);
        let applied = token(2, 3);
        let concurrent_identical = token(5, 3);

        assert_eq!(
            classify_compensation_snapshot(
                &INTENDED,
                Some(&concurrent_identical),
                &original,
                Some(&applied),
                &BEFORE,
                &INTENDED,
                true,
            )
            .expect("a safely abandoned phase should preserve the replacement"),
            CompensationSnapshot::Unattributed,
        );
    }
}
