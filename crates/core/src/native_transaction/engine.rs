use std::cell::RefCell;

use context_relay_protocol::{ApplyReceipt, HybridLogicalClock, Sha256Digest, WireNativeValue};
use thiserror::Error;

use super::{
    approval::{ApprovalError, approval_hash_v1},
    model::{
        ApprovedInput, ApprovedMutation, MutationKind, NativeApplyReceipt, NativeObjectToken,
        NativeReceiptEntry, NativeTransactionPlan, RestorableStateFingerprint, SidecarBinding,
        TransactionStep,
    },
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("{message}")]
pub struct BoundaryError {
    message: String,
}

impl BoundaryError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[derive(Debug, Error)]
pub enum TransactionError {
    #[error(transparent)]
    Approval(#[from] ApprovalError),
    #[error("native transaction boundary failed: {0}")]
    Boundary(#[from] BoundaryError),
    #[error("native transaction plan expired")]
    Expired,
    #[error("native transaction approval hash changed")]
    ApprovalMismatch,
    #[error("staged output differs from the approved output")]
    StagedOutputMismatch,
    #[error("native before-images do not match the approved targets")]
    BeforeImageMismatch,
    #[error("native mutation outcome does not match the approved intended state")]
    MutationOutcomeMismatch,
    #[error("compensation failed after {primary}: {compensation}")]
    Compensation {
        primary: Box<TransactionError>,
        compensation: BoundaryError,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestrictedRun {
    pub staged_output_hash: Sha256Digest,
    pub scanner_result_hash: Sha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrozenOutput {
    pub staged_output_hash: Sha256Digest,
    pub scanner_result_hash: Sha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BeforeImage {
    pub id: String,
    pub target: WireNativeValue,
    pub object_token: NativeObjectToken,
    pub fingerprint: RestorableStateFingerprint,
    pub encrypted_state: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationOutcome {
    pub wrote: bool,
    pub resulting_fingerprint: RestorableStateFingerprint,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CompensationOutcome {
    conflict_target_sequences: Vec<u32>,
}

impl CompensationOutcome {
    pub fn new(conflict_target_sequences: Vec<u32>) -> Self {
        Self {
            conflict_target_sequences,
        }
    }

    pub fn conflict_target_sequences(&self) -> &[u32] {
        &self.conflict_target_sequences
    }
}

pub trait NativeAdapter {
    fn reprobe_live_state(&mut self, plan: &NativeTransactionPlan) -> Result<(), BoundaryError>;
    fn compare_approved_digests(
        &mut self,
        plan: &NativeTransactionPlan,
    ) -> Result<(), BoundaryError>;
    fn validate_staged_output(
        &mut self,
        plan: &NativeTransactionPlan,
        run: &RestrictedRun,
    ) -> Result<FrozenOutput, BoundaryError>;
    fn validate_effective(
        &mut self,
        plan: &NativeTransactionPlan,
        receipt: &ApplyReceipt,
    ) -> Result<(), BoundaryError>;
}

pub trait RestrictedExecutor {
    fn copy_allowlisted_inputs(&mut self, inputs: &[ApprovedInput]) -> Result<(), BoundaryError>;
    fn create_fake_roots(&mut self) -> Result<(), BoundaryError>;
    fn build_restricted_environment(&mut self) -> Result<(), BoundaryError>;
    fn run_restricted_tools(
        &mut self,
        sidecars: &[SidecarBinding],
    ) -> Result<RestrictedRun, BoundaryError>;
    fn reject_unsafe_topology(&mut self) -> Result<(), BoundaryError>;
}

pub type RebindAppliedAbsence<'a> = dyn FnMut(usize, usize, &NativeObjectToken, &NativeObjectToken) -> Result<(), BoundaryError>
    + 'a;
pub type CheckpointAppliedAbsence<'a> = dyn FnMut(usize, usize, &NativeObjectToken, &NativeObjectToken) -> Result<(), BoundaryError>
    + 'a;

pub trait NativeFileSystem {
    fn create_before_images(
        &mut self,
        mutations: &[ApprovedMutation],
    ) -> Result<Vec<BeforeImage>, BoundaryError>;
    fn record_native_metadata(&mut self, images: &[BeforeImage]) -> Result<(), BoundaryError>;
    fn compare_and_swap_targets(
        &mut self,
        mutations: &[ApprovedMutation],
    ) -> Result<(), BoundaryError>;
    fn apply_mutation(
        &mut self,
        transaction_nonce: &[u8; 16],
        mutation: &ApprovedMutation,
        persist_candidate: &mut dyn FnMut(&NativeObjectToken) -> Result<(), BoundaryError>,
    ) -> Result<MutationOutcome, BoundaryError>;

    fn mutation_provenance(&self, _mutation: &ApprovedMutation) -> Option<NativeObjectToken> {
        None
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
    ) -> Result<CompensationOutcome, BoundaryError>;
    fn finish_committed_targets(
        &mut self,
        transaction_nonce: &[u8; 16],
    ) -> Result<(), BoundaryError>;
}

pub trait NativeJournal {
    fn acquire_lock_and_begin(&mut self, plan: &NativeTransactionPlan)
    -> Result<(), BoundaryError>;
    fn enter_step(&mut self, step: TransactionStep) -> Result<(), BoundaryError>;
    fn complete_step(&mut self, step: TransactionStep) -> Result<(), BoundaryError>;
    fn put_before_images(&mut self, images: &[BeforeImage]) -> Result<(), BoundaryError>;
    fn prepare_mutation(
        &mut self,
        index: usize,
        mutation: &ApprovedMutation,
    ) -> Result<(), BoundaryError>;
    fn mark_mutation_applied(
        &mut self,
        index: usize,
        mutation: &ApprovedMutation,
        outcome: &MutationOutcome,
        applied_token: Option<&NativeObjectToken>,
    ) -> Result<(), BoundaryError>;
    fn record_mutation_candidate(
        &mut self,
        index: usize,
        mutation: &ApprovedMutation,
        candidate_token: &NativeObjectToken,
    ) -> Result<(), BoundaryError>;
    fn mark_mutation_conflict(
        &mut self,
        index: usize,
        applied_token: &NativeObjectToken,
    ) -> Result<(), BoundaryError>;
    fn mark_mutation_applied_for_recovery(
        &mut self,
        index: usize,
        mutation: &ApprovedMutation,
        applied_token: &NativeObjectToken,
    ) -> Result<(), BoundaryError>;
    fn record_mutation_restored_candidate(
        &mut self,
        index: usize,
        candidate_token: &NativeObjectToken,
    ) -> Result<(), BoundaryError>;
    fn checkpoint_mutation_applied_absence(
        &mut self,
        index: usize,
        later_index: usize,
        expected_old_token: &NativeObjectToken,
        new_token: &NativeObjectToken,
    ) -> Result<(), BoundaryError>;
    fn rebind_mutation_applied_absence(
        &mut self,
        index: usize,
        later_index: usize,
        expected_old_token: &NativeObjectToken,
        new_token: &NativeObjectToken,
    ) -> Result<(), BoundaryError>;
    fn prepare_compensation(&mut self) -> Result<(), BoundaryError>;
    fn commit_native_transaction(
        &mut self,
        plan: &NativeTransactionPlan,
        receipt: &NativeApplyReceipt,
    ) -> Result<(), BoundaryError>;
    fn finish_committed(&mut self) -> Result<(), BoundaryError>;
    fn finish_compensated(
        &mut self,
        conflict_target_sequences: &[u32],
    ) -> Result<(), BoundaryError>;
}

pub trait FaultHook {
    fn after_step(&mut self, step: TransactionStep) -> Result<(), BoundaryError>;
}

#[derive(Default)]
pub struct NoFault;

impl FaultHook for NoFault {
    fn after_step(&mut self, _step: TransactionStep) -> Result<(), BoundaryError> {
        Ok(())
    }
}

pub struct NativeTransactionEngine<'a, A, E, F, J, H> {
    adapter: &'a mut A,
    executor: &'a mut E,
    filesystem: &'a mut F,
    journal: &'a mut J,
    hook: &'a mut H,
}

impl<'a, A, E, F, J, H> NativeTransactionEngine<'a, A, E, F, J, H>
where
    A: NativeAdapter,
    E: RestrictedExecutor,
    F: NativeFileSystem,
    J: NativeJournal,
    H: FaultHook,
{
    pub fn new(
        adapter: &'a mut A,
        executor: &'a mut E,
        filesystem: &'a mut F,
        journal: &'a mut J,
        hook: &'a mut H,
    ) -> Self {
        Self {
            adapter,
            executor,
            filesystem,
            journal,
            hook,
        }
    }

    pub fn apply(
        &mut self,
        plan: &NativeTransactionPlan,
        now_ms: u64,
        applied_hlc: HybridLogicalClock,
    ) -> Result<NativeApplyReceipt, TransactionError> {
        let mut begun = false;
        let transaction_nonce = *plan.setup.plan_id.as_bytes();

        macro_rules! attempt {
            ($expression:expr) => {
                match $expression {
                    Ok(value) => value,
                    Err(error) => {
                        let error = TransactionError::from(error);
                        return Err(self.compensate(error, begun, &transaction_nonce));
                    }
                }
            };
        }

        attempt!(self.journal.acquire_lock_and_begin(plan));
        begun = true;
        attempt!(self.journal.complete_step(TransactionStep::AcquireLock));
        attempt!(self.hook.after_step(TransactionStep::AcquireLock));

        attempt!(self.journal.enter_step(TransactionStep::ReprobeLiveState));
        attempt!(self.adapter.reprobe_live_state(plan));
        attempt!(
            self.journal
                .complete_step(TransactionStep::ReprobeLiveState)
        );
        attempt!(self.hook.after_step(TransactionStep::ReprobeLiveState));

        attempt!(
            self.journal
                .enter_step(TransactionStep::CompareApprovedDigests)
        );
        attempt!(self.adapter.compare_approved_digests(plan));
        attempt!(
            self.journal
                .complete_step(TransactionStep::CompareApprovedDigests)
        );
        attempt!(
            self.hook
                .after_step(TransactionStep::CompareApprovedDigests)
        );

        attempt!(self.journal.enter_step(TransactionStep::CreateBeforeImages));
        let before_images = attempt!(self.filesystem.create_before_images(&plan.mutations));
        if before_images.len() != plan.mutations.len()
            || before_images
                .iter()
                .zip(&plan.mutations)
                .any(|(image, mutation)| {
                    image.target != mutation.target || image.fingerprint != mutation.expected
                })
        {
            return Err(self.compensate(
                TransactionError::BeforeImageMismatch,
                begun,
                &transaction_nonce,
            ));
        }
        attempt!(self.journal.put_before_images(&before_images));
        attempt!(
            self.journal
                .complete_step(TransactionStep::CreateBeforeImages)
        );
        attempt!(self.hook.after_step(TransactionStep::CreateBeforeImages));

        attempt!(
            self.journal
                .enter_step(TransactionStep::RecordNativeMetadata)
        );
        attempt!(self.filesystem.record_native_metadata(&before_images));
        attempt!(
            self.journal
                .complete_step(TransactionStep::RecordNativeMetadata)
        );
        attempt!(self.hook.after_step(TransactionStep::RecordNativeMetadata));

        attempt!(
            self.journal
                .enter_step(TransactionStep::CopyAllowlistedInputs)
        );
        attempt!(self.executor.copy_allowlisted_inputs(&plan.staged_inputs));
        attempt!(
            self.journal
                .complete_step(TransactionStep::CopyAllowlistedInputs)
        );
        attempt!(self.hook.after_step(TransactionStep::CopyAllowlistedInputs));

        attempt!(self.journal.enter_step(TransactionStep::CreateFakeRoots));
        attempt!(self.executor.create_fake_roots());
        attempt!(self.journal.complete_step(TransactionStep::CreateFakeRoots));
        attempt!(self.hook.after_step(TransactionStep::CreateFakeRoots));

        attempt!(
            self.journal
                .enter_step(TransactionStep::BuildRestrictedEnvironment)
        );
        attempt!(self.executor.build_restricted_environment());
        attempt!(
            self.journal
                .complete_step(TransactionStep::BuildRestrictedEnvironment)
        );
        attempt!(
            self.hook
                .after_step(TransactionStep::BuildRestrictedEnvironment)
        );

        attempt!(self.journal.enter_step(TransactionStep::RunRestrictedTools));
        let run = attempt!(self.executor.run_restricted_tools(&plan.sidecars));
        attempt!(
            self.journal
                .complete_step(TransactionStep::RunRestrictedTools)
        );
        attempt!(self.hook.after_step(TransactionStep::RunRestrictedTools));

        attempt!(
            self.journal
                .enter_step(TransactionStep::RejectUnsafeTopology)
        );
        attempt!(self.executor.reject_unsafe_topology());
        attempt!(
            self.journal
                .complete_step(TransactionStep::RejectUnsafeTopology)
        );
        attempt!(self.hook.after_step(TransactionStep::RejectUnsafeTopology));

        attempt!(
            self.journal
                .enter_step(TransactionStep::ValidateStagedOutput)
        );
        let frozen = attempt!(self.adapter.validate_staged_output(plan, &run));
        attempt!(
            self.journal
                .complete_step(TransactionStep::ValidateStagedOutput)
        );
        attempt!(self.hook.after_step(TransactionStep::ValidateStagedOutput));

        attempt!(self.journal.enter_step(TransactionStep::RecomputeApproval));
        let approval = match approval_hash_v1(plan) {
            Ok(value) => value,
            Err(error) => {
                return Err(self.compensate(error.into(), begun, &transaction_nonce));
            }
        };
        if frozen.staged_output_hash != plan.expected_semantic_output_hash
            || frozen.scanner_result_hash != plan.scanner_result_hash
        {
            return Err(self.compensate(
                TransactionError::StagedOutputMismatch,
                begun,
                &transaction_nonce,
            ));
        }
        attempt!(
            self.journal
                .complete_step(TransactionStep::RecomputeApproval)
        );
        attempt!(self.hook.after_step(TransactionStep::RecomputeApproval));

        attempt!(self.journal.enter_step(TransactionStep::CheckPlanFreshness));
        if now_ms > plan.setup.expires_at {
            return Err(self.compensate(TransactionError::Expired, begun, &transaction_nonce));
        }
        if approval != plan.setup.batch_hash {
            return Err(self.compensate(
                TransactionError::ApprovalMismatch,
                begun,
                &transaction_nonce,
            ));
        }
        attempt!(
            self.journal
                .complete_step(TransactionStep::CheckPlanFreshness)
        );
        attempt!(self.hook.after_step(TransactionStep::CheckPlanFreshness));

        attempt!(
            self.journal
                .enter_step(TransactionStep::CompareAndSwapTargets)
        );
        attempt!(self.filesystem.compare_and_swap_targets(&plan.mutations));
        attempt!(
            self.journal
                .complete_step(TransactionStep::CompareAndSwapTargets)
        );
        attempt!(self.hook.after_step(TransactionStep::CompareAndSwapTargets));

        let mut outcomes = Vec::with_capacity(plan.mutations.len());
        for (step, role) in [
            (TransactionStep::WritePayloads, MutationKind::Payload),
            (
                TransactionStep::InstallExecutablesDisabled,
                MutationKind::ExecutableDisabled,
            ),
            (
                TransactionStep::WriteActivationReferences,
                MutationKind::ActivationReference,
            ),
        ] {
            attempt!(self.journal.enter_step(step));
            for (index, mutation) in plan.mutations.iter().enumerate() {
                if mutation.kind != role {
                    continue;
                }
                attempt!(self.journal.prepare_mutation(index, mutation));
                let outcome = match self.filesystem.apply_mutation(
                    &transaction_nonce,
                    mutation,
                    &mut |candidate_token| {
                        self.journal
                            .record_mutation_candidate(index, mutation, candidate_token)
                    },
                ) {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        let primary = TransactionError::from(error);
                        if let Some(token) = self.filesystem.mutation_provenance(mutation)
                            && let Err(compensation) = self
                                .journal
                                .mark_mutation_applied_for_recovery(index, mutation, &token)
                        {
                            return Err(TransactionError::Compensation {
                                primary: Box::new(primary),
                                compensation,
                            });
                        }
                        return Err(self.compensate(primary, begun, &transaction_nonce));
                    }
                };
                let applied_token = self.filesystem.mutation_provenance(mutation);
                if outcome.resulting_fingerprint != mutation.intended
                    || outcome.wrote != (mutation.expected != mutation.intended)
                    || outcome.wrote != applied_token.is_some()
                {
                    let primary = TransactionError::MutationOutcomeMismatch;
                    if let Some(token) = applied_token.as_ref()
                        && let Err(compensation) = self.journal.mark_mutation_conflict(index, token)
                    {
                        return Err(TransactionError::Compensation {
                            primary: Box::new(primary),
                            compensation,
                        });
                    }
                    return Err(self.compensate(primary, begun, &transaction_nonce));
                }
                if outcome.wrote && applied_token.is_none() {
                    return Err(self.compensate(
                        TransactionError::Boundary(BoundaryError::new(
                            "written native mutation provenance is missing",
                        )),
                        begun,
                        &transaction_nonce,
                    ));
                }
                attempt!(self.journal.mark_mutation_applied(
                    index,
                    mutation,
                    &outcome,
                    applied_token.as_ref(),
                ));
                outcomes.push((index, outcome));
            }
            attempt!(self.journal.complete_step(step));
            attempt!(self.hook.after_step(step));
        }
        outcomes.sort_by_key(|(index, _)| *index);

        let receipt = NativeApplyReceipt {
            legacy: ApplyReceipt {
                plan_id: plan.setup.plan_id,
                applied_hlc,
                resulting_digests: outcomes
                    .iter()
                    .map(|(_, outcome)| outcome.resulting_fingerprint.0)
                    .collect(),
            },
            targets: outcomes
                .iter()
                .zip(&plan.mutations)
                .map(|((_, outcome), mutation)| NativeReceiptEntry {
                    target: mutation.target.clone(),
                    fingerprint: outcome.resulting_fingerprint.clone(),
                })
                .collect(),
        };

        attempt!(
            self.journal
                .enter_step(TransactionStep::ValidateEffectiveConfiguration)
        );
        attempt!(self.adapter.validate_effective(plan, &receipt.legacy));
        attempt!(
            self.journal
                .complete_step(TransactionStep::ValidateEffectiveConfiguration)
        );
        attempt!(
            self.hook
                .after_step(TransactionStep::ValidateEffectiveConfiguration)
        );

        attempt!(
            self.journal
                .enter_step(TransactionStep::CommitOwnershipAndReceipt)
        );
        attempt!(self.journal.commit_native_transaction(plan, &receipt));
        let _ = self
            .hook
            .after_step(TransactionStep::CommitOwnershipAndReceipt);

        if self
            .journal
            .enter_step(TransactionStep::RestoreMatchingAppliedTargets)
            .is_ok()
            && self
                .filesystem
                .finish_committed_targets(&transaction_nonce)
                .is_ok()
        {
            let _ = self.journal.finish_committed();
            let _ = self
                .hook
                .after_step(TransactionStep::RestoreMatchingAppliedTargets);
        }

        Ok(receipt)
    }

    fn compensate(
        &mut self,
        primary: TransactionError,
        begun: bool,
        transaction_nonce: &[u8; 16],
    ) -> TransactionError {
        if !begun {
            return primary;
        }
        let compensation = self
            .journal
            .enter_step(TransactionStep::RestoreMatchingAppliedTargets)
            .and_then(|_| self.journal.prepare_compensation())
            .and_then(|_| {
                let journal = RefCell::new(&mut *self.journal);
                self.filesystem.restore_matching_applied_targets(
                    transaction_nonce,
                    &mut |index, candidate_token| {
                        journal
                            .borrow_mut()
                            .record_mutation_restored_candidate(index, candidate_token)
                    },
                    &mut |index, later_index, expected_old_token, new_token| {
                        journal.borrow_mut().checkpoint_mutation_applied_absence(
                            index,
                            later_index,
                            expected_old_token,
                            new_token,
                        )
                    },
                    &mut |index, later_index, expected_old_token, new_token| {
                        journal.borrow_mut().rebind_mutation_applied_absence(
                            index,
                            later_index,
                            expected_old_token,
                            new_token,
                        )
                    },
                )
            })
            .and_then(|outcome| {
                self.journal
                    .complete_step(TransactionStep::RestoreMatchingAppliedTargets)?;
                self.journal
                    .finish_compensated(outcome.conflict_target_sequences())
            });
        let _ = self
            .hook
            .after_step(TransactionStep::RestoreMatchingAppliedTargets);
        match compensation {
            Ok(()) => primary,
            Err(compensation) => TransactionError::Compensation {
                primary: Box::new(primary),
                compensation,
            },
        }
    }
}
