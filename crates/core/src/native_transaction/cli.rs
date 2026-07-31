use context_relay_protocol::Sha256Digest;

use super::{engine::BoundaryError, model::ApprovedCliMutation};

/// The semantic state observed after an approved forward operation sequence.
///
/// `command_error` records an uncertain command result without discarding the
/// mandatory declaration reprobe. The transaction engine resolves that
/// uncertainty against the approval-bound expected and intended fingerprints.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CliMutationOutcome {
    pub resulting_fingerprint: Option<Sha256Digest>,
    pub command_error: Option<BoundaryError>,
}

/// The semantic state observed after an approval-bound compensation attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CliRestoreOutcome {
    /// False means the executor observed live divergence and did not run the
    /// rollback operation sequence.
    pub restored: bool,
    pub resulting_fingerprint: Option<Sha256Digest>,
}

/// Executes only adapter-generated, approval-bound CLI mutations.
///
/// Implementations receive semantic mutations rather than command-line input.
/// They are responsible for executing the mutation's sealed operations and
/// reprobe declarations without launching the configured MCP bridge.
pub trait NativeCliExecutor {
    /// Reprobes one approval-bound declaration without executing a mutation.
    fn probe_cli_mutation(
        &mut self,
        mutation: &ApprovedCliMutation,
    ) -> Result<Option<Sha256Digest>, BoundaryError>;

    fn compare_cli_targets(
        &mut self,
        mutations: &[ApprovedCliMutation],
    ) -> Result<(), BoundaryError>;

    fn apply_cli_mutation(
        &mut self,
        mutation: &ApprovedCliMutation,
    ) -> Result<CliMutationOutcome, BoundaryError>;

    fn restore_cli_mutation_if_matches(
        &mut self,
        mutation: &ApprovedCliMutation,
    ) -> Result<CliRestoreOutcome, BoundaryError>;

    fn finish_committed_cli_mutations(
        &mut self,
        mutations: &[ApprovedCliMutation],
    ) -> Result<(), BoundaryError>;
}

/// Produces the compensation worklist in reverse application order.
///
/// Approval v2 currently admits one managed target per single-harness plan.
/// Keeping ordering in this slice helper makes engine orchestration correct if
/// a later approval version safely admits more independent targets.
pub(crate) fn applied_cli_mutations_in_reverse(
    mutations: &[ApprovedCliMutation],
    applied: &[usize],
) -> Result<Vec<(usize, ApprovedCliMutation)>, BoundaryError> {
    applied
        .iter()
        .rev()
        .map(|index| {
            mutations
                .get(*index)
                .cloned()
                .map(|mutation| (*index, mutation))
                .ok_or_else(|| {
                    BoundaryError::new(
                        "approval-bound CLI mutation is unavailable for compensation",
                    )
                })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mutation(stable_id: &str) -> ApprovedCliMutation {
        ApprovedCliMutation {
            stable_id: stable_id.to_owned(),
            expected: None,
            intended: None,
            forward: vec![],
            rollback: vec![],
        }
    }

    #[test]
    fn compensation_worklist_is_reverse_application_order() {
        let mutations = [mutation("first"), mutation("second")];

        let ordered = applied_cli_mutations_in_reverse(&mutations, &[0, 1]).unwrap();

        assert_eq!(
            ordered
                .iter()
                .map(|(_, mutation)| mutation.stable_id.as_str())
                .collect::<Vec<_>>(),
            ["second", "first"]
        );
    }
}
