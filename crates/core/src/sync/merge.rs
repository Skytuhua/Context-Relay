use context_relay_protocol::{OperationId, RecordMutationV1};

use crate::{search::Embedding384, vault::StoredRecordHead};

use super::{AdmittedOperation, CausalOrder, SyncError, compare_operations};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MergeDecision {
    NoLiveChange,
    ReplaceHeads { remove: Vec<OperationId> },
    AddConflictHead { remove: Vec<OperationId> },
    ResolveConflict { remove: Vec<OperationId> },
}

/// Supplies the vector for the exact mutation selected as the live merge representative.
pub trait RepresentativeEmbeddingResolver {
    fn resolve_representative_embedding(
        &self,
        operation_id: OperationId,
        mutation: &RecordMutationV1,
    ) -> Result<Option<Embedding384>, SyncError>;
}

impl<F> RepresentativeEmbeddingResolver for F
where
    F: Fn(OperationId, &RecordMutationV1) -> Result<Option<Embedding384>, SyncError>,
{
    fn resolve_representative_embedding(
        &self,
        operation_id: OperationId,
        mutation: &RecordMutationV1,
    ) -> Result<Option<Embedding384>, SyncError> {
        self(operation_id, mutation)
    }
}

pub fn decide_merge(
    incoming: &AdmittedOperation,
    current: &[StoredRecordHead],
) -> Result<MergeDecision, SyncError> {
    validate_incoming(incoming)?;
    for head in current {
        validate_head(incoming, head)?;
    }
    if current.is_empty() {
        return Ok(MergeDecision::ReplaceHeads { remove: Vec::new() });
    }

    let mut remove = current
        .iter()
        .map(|head| head.operation_id)
        .collect::<Vec<_>>();
    remove.sort();
    let orders = current
        .iter()
        .map(|head| compare_operations(incoming.operation(), &head.operation))
        .collect::<Vec<_>>();
    if orders.iter().all(|order| *order == CausalOrder::After) {
        return Ok(if current.len() > 1 {
            MergeDecision::ResolveConflict { remove }
        } else {
            MergeDecision::ReplaceHeads { remove }
        });
    }
    if orders
        .iter()
        .any(|order| matches!(order, CausalOrder::Before | CausalOrder::Equal))
    {
        return Ok(MergeDecision::NoLiveChange);
    }
    let mut remove = current
        .iter()
        .zip(orders)
        .filter_map(|(head, order)| (order == CausalOrder::After).then_some(head.operation_id))
        .collect::<Vec<_>>();
    remove.sort();
    Ok(MergeDecision::AddConflictHead { remove })
}

fn validate_incoming(incoming: &AdmittedOperation) -> Result<(), SyncError> {
    if incoming.operation().record_id != incoming.mutation().record_id()
        || incoming.operation().record_kind != incoming.mutation().record_kind()
        || incoming.operation().mutation_kind != incoming.mutation().mutation_kind()
    {
        return Err(SyncError::InvalidMutation);
    }
    Ok(())
}

fn validate_head(incoming: &AdmittedOperation, head: &StoredRecordHead) -> Result<(), SyncError> {
    if head.operation_id != head.operation.operation_id
        || head.record_kind != head.operation.record_kind
        || head.mutation_kind != head.operation.mutation_kind
        || head.operation.workspace_id != incoming.operation().workspace_id
        || head.operation.record_id != incoming.operation().record_id
        || head.record_kind != incoming.operation().record_kind
    {
        return Err(SyncError::InvalidEnvelope);
    }
    Ok(())
}
