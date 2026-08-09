use std::ops::RangeInclusive;

use context_relay_protocol::{
    AccountId, DeviceId, OperationId, RecordMutationV1, Sha256Digest, SyncOperationV1, WorkspaceId,
    decode_sync_operation_v1, encode_sync_operation_v1,
};
use sha2::{Digest, Sha256};

use crate::{
    crypto::{ContentKey, DeviceCertificateV1},
    vault::Vault,
};

use super::operation::verify_operation_public_authenticity;
use super::{
    OperationChainHead, SyncError, TrustedOperationContext, missing_range,
    verify_operation_envelope,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedDevice {
    pub certificate: DeviceCertificateV1,
    pub active_control_epoch: u32,
    pub active_key_epoch: u32,
}

pub trait TrustedSyncMaterial {
    fn trusted_device(
        &self,
        account: AccountId,
        workspace: WorkspaceId,
        device: DeviceId,
    ) -> Result<TrustedDevice, SyncError>;

    fn content_key(&self, workspace: WorkspaceId, key_epoch: u32)
    -> Result<&ContentKey, SyncError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Proof that a canonical signed operation passed complete admission.
///
/// Callers can inspect but cannot construct or mutate this capability.
///
/// ```compile_fail
/// use context_relay_core::sync::AdmittedOperation;
/// let _ = AdmittedOperation {
///     operation: panic!(),
///     mutation: panic!(),
///     canonical_bytes: Vec::new(),
///     canonical_hash: panic!(),
/// };
/// ```
pub struct AdmittedOperation {
    operation: SyncOperationV1,
    mutation: RecordMutationV1,
    canonical_bytes: Vec<u8>,
    canonical_hash: Sha256Digest,
}

impl AdmittedOperation {
    pub const fn operation(&self) -> &SyncOperationV1 {
        &self.operation
    }

    pub const fn mutation(&self) -> &RecordMutationV1 {
        &self.mutation
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn canonical_hash(&self) -> Sha256Digest {
        self.canonical_hash
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmissionDecision {
    ExactReplay(OperationId),
    Gap(RangeInclusive<u64>),
    Admitted(AdmittedOperation),
}

pub fn admit_operation(
    vault: &Vault,
    received_bytes: &[u8],
    trusted_material: &impl TrustedSyncMaterial,
) -> Result<AdmissionDecision, SyncError> {
    let operation =
        decode_sync_operation_v1(received_bytes).map_err(|_| SyncError::InvalidEnvelope)?;
    operation
        .validate()
        .map_err(|_| SyncError::InvalidEnvelope)?;
    let canonical_bytes =
        encode_sync_operation_v1(&operation).map_err(|_| SyncError::InvalidEnvelope)?;
    if canonical_bytes != received_bytes {
        return Err(SyncError::InvalidEnvelope);
    }
    let canonical_hash = digest(&canonical_bytes);

    let trusted = trusted_material.trusted_device(
        operation.account_id,
        operation.workspace_id,
        operation.device_id,
    )?;
    validate_active_identity(&operation, &trusted)?;

    let previous = vault
        .device_head(operation.workspace_id, operation.device_id)
        .map_err(|_| SyncError::PersistenceFailed)?;
    let previous_chain = previous.map(|head| OperationChainHead {
        sequence: head.sequence,
        canonical_hash: head.canonical_hash,
    });
    let public_context = trusted_context(&trusted, previous_chain, None);
    verify_operation_public_authenticity(&operation, &public_context)?;

    if let Some(stored) = vault
        .stored_sync_operation(operation.operation_id)
        .map_err(|_| SyncError::PersistenceFailed)?
    {
        if stored == canonical_bytes {
            return Ok(AdmissionDecision::ExactReplay(operation.operation_id));
        }
        return Err(SyncError::OperationConflict);
    }
    if vault
        .operation_at_device_sequence(
            operation.workspace_id,
            operation.device_id,
            operation.device_sequence,
        )
        .map_err(|_| SyncError::PersistenceFailed)?
        .is_some()
    {
        return Err(SyncError::SequenceConflict);
    }
    if let Some(range) = missing_range(previous, &operation)? {
        return Ok(AdmissionDecision::Gap(range));
    }
    let expected_previous = previous
        .map(|head| head.canonical_hash)
        .unwrap_or(Sha256Digest([0; 32]));
    if operation.previous_device_hash != expected_previous {
        return Err(SyncError::InvalidChain);
    }
    validate_frontier_against_vault(vault, &operation)?;
    if !vault
        .record_belongs_to_sync_scope(
            trusted_material,
            operation.account_id,
            operation.workspace_id,
            operation.record_id,
            operation.record_kind,
        )
        .map_err(|_| SyncError::PersistenceFailed)?
    {
        return Err(SyncError::InvalidScope);
    }

    let existing_scope =
        if operation.mutation_kind == context_relay_protocol::MutationKind::Tombstone {
            Some(
                vault
                    .materialized_record_scope(
                        operation.workspace_id,
                        operation.record_id,
                        operation.record_kind,
                    )
                    .map_err(|_| SyncError::PersistenceFailed)?
                    .ok_or(SyncError::InvalidScope)?,
            )
        } else {
            None
        };

    let key = trusted_material.content_key(operation.workspace_id, operation.key_epoch)?;
    let context = trusted_context(&trusted, previous_chain, existing_scope);
    let mutation = verify_operation_envelope(&operation, &context, key)?;
    Ok(AdmissionDecision::Admitted(AdmittedOperation {
        operation,
        mutation,
        canonical_bytes,
        canonical_hash,
    }))
}

fn validate_active_identity(
    operation: &SyncOperationV1,
    trusted: &TrustedDevice,
) -> Result<(), SyncError> {
    let certificate = &trusted.certificate;
    if certificate.account_id != operation.account_id
        || certificate.workspace_id != operation.workspace_id
        || certificate.device_id != operation.device_id
        || certificate.control_epoch != trusted.active_control_epoch
        || operation.control_epoch != trusted.active_control_epoch
        || operation.key_epoch != trusted.active_key_epoch
    {
        return Err(SyncError::InvalidIdentity);
    }
    Ok(())
}

fn trusted_context<'a>(
    trusted: &'a TrustedDevice,
    previous: Option<OperationChainHead>,
    existing_scope: Option<context_relay_protocol::ScopeRef>,
) -> TrustedOperationContext<'a> {
    let context =
        TrustedOperationContext::new(&trusted.certificate, trusted.active_key_epoch, previous);
    match existing_scope {
        Some(scope) => context.with_existing_record_scope(scope),
        None => context,
    }
}

fn validate_frontier_against_vault(
    vault: &Vault,
    operation: &SyncOperationV1,
) -> Result<(), SyncError> {
    super::operation::validate_frontier(
        &operation.causal_frontier,
        operation.device_id,
        Some(operation.device_sequence),
    )?;
    for entry in &operation.causal_frontier {
        let head = vault
            .device_head(operation.workspace_id, entry.device_id)
            .map_err(|_| SyncError::PersistenceFailed)?
            .ok_or(SyncError::InvalidFrontier)?;
        if head.sequence < entry.sequence {
            return Err(SyncError::InvalidFrontier);
        }
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest(Sha256::digest(bytes).into())
}
