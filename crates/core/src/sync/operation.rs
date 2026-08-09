use std::{error::Error, fmt};

use context_relay_protocol::{
    BlobRef, BoundedCiphertext, DeviceSequence, Ed25519SignatureBytes, HybridLogicalClock,
    OperationId, ProjectId, RecordKind, RecordMutationV1, SYNC_SCHEMA_VERSION, ScopeRef,
    Sha256Digest, SyncOperationV1, XChaChaNonce, decode_record_mutation_v1,
    encode_record_mutation_v1, encode_sync_operation_aad_v1,
    encode_sync_operation_signing_preimage_v1, encode_sync_operation_v1,
};
use sha2::{Digest, Sha256};

use crate::crypto::{
    ContentKey, CryptoError, DeviceCertificateV1, EncryptedPayload, SecretBytes, verify_signature,
};

use super::{OperationChainHead, SyncIdentity};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncError {
    InvalidEnvelope,
    InvalidIdentity,
    InvalidChain,
    InvalidFrontier,
    InvalidScope,
    AuthenticationFailed,
    EncryptionFailed,
    DecryptionFailed,
    InvalidMutation,
    SequenceExhausted,
    OperationConflict,
    SequenceConflict,
    PersistenceFailed,
}

impl fmt::Display for SyncError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidEnvelope => "invalid sync operation envelope",
            Self::InvalidIdentity => "sync operation identity mismatch",
            Self::InvalidChain => "sync operation chain mismatch",
            Self::InvalidFrontier => "invalid sync operation frontier",
            Self::InvalidScope => "sync operation scope mismatch",
            Self::AuthenticationFailed => "sync operation authentication failed",
            Self::EncryptionFailed => "sync operation encryption failed",
            Self::DecryptionFailed => "sync operation decryption failed",
            Self::InvalidMutation => "invalid sync operation mutation",
            Self::SequenceExhausted => "sync operation sequence exhausted",
            Self::OperationConflict => "sync operation identifier conflict",
            Self::SequenceConflict => "sync operation sequence conflict",
            Self::PersistenceFailed => "sync operation persistence failed",
        })
    }
}

impl SyncError {
    /// Returns a stable, non-sensitive diagnostic suitable for durable sync state.
    pub const fn safe_code(self) -> &'static str {
        match self {
            Self::InvalidIdentity => "revoked",
            Self::PersistenceFailed => "transient",
            Self::InvalidEnvelope
            | Self::InvalidChain
            | Self::InvalidFrontier
            | Self::InvalidScope
            | Self::AuthenticationFailed
            | Self::EncryptionFailed
            | Self::DecryptionFailed
            | Self::InvalidMutation
            | Self::SequenceExhausted
            | Self::OperationConflict
            | Self::SequenceConflict => "integrity_quarantined",
        }
    }
}

impl Error for SyncError {}

pub struct BuiltOperation {
    pub operation: SyncOperationV1,
    pub canonical_bytes: Vec<u8>,
    pub canonical_hash: Sha256Digest,
    sealed_mutation_hash: Sha256Digest,
    sealed_operation_hash: Sha256Digest,
}

impl BuiltOperation {
    pub(crate) fn validate_for_persistence(
        &self,
        mutation: &RecordMutationV1,
    ) -> Result<(), SyncError> {
        let mutation_bytes =
            encode_record_mutation_v1(mutation).map_err(|_| SyncError::InvalidMutation)?;
        if digest(&mutation_bytes) != self.sealed_mutation_hash {
            return Err(SyncError::InvalidMutation);
        }

        let operation_bytes =
            encode_sync_operation_v1(&self.operation).map_err(|_| SyncError::InvalidEnvelope)?;
        let operation_hash = digest(&operation_bytes);
        if operation_bytes != self.canonical_bytes
            || operation_hash != self.canonical_hash
            || operation_hash != self.sealed_operation_hash
        {
            return Err(SyncError::InvalidEnvelope);
        }
        Ok(())
    }
}

pub struct OperationBuilder<'a> {
    identity: SyncIdentity<'a>,
    fixed_nonce: Option<XChaChaNonce>,
}

impl<'a> OperationBuilder<'a> {
    pub const fn new(identity: SyncIdentity<'a>) -> Self {
        Self {
            identity,
            fixed_nonce: None,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn with_nonce_for_test(identity: SyncIdentity<'a>, nonce: XChaChaNonce) -> Self {
        Self {
            identity,
            fixed_nonce: Some(nonce),
        }
    }

    pub fn build(
        &self,
        operation_id: OperationId,
        project_id: Option<ProjectId>,
        mutation: &RecordMutationV1,
        mut causal_frontier: Vec<DeviceSequence>,
        previous: Option<OperationChainHead>,
        blob_refs: Vec<BlobRef>,
        created_hlc: HybridLogicalClock,
    ) -> Result<BuiltOperation, SyncError> {
        mutation
            .validate()
            .map_err(|_| SyncError::InvalidMutation)?;
        if !scope_matches(project_id, mutation) {
            return Err(SyncError::InvalidScope);
        }
        if created_hlc.node != self.identity.device_id {
            return Err(SyncError::InvalidIdentity);
        }

        causal_frontier.sort_by_key(|entry| entry.device_id);
        validate_frontier(&causal_frontier, self.identity.device_id, None)?;

        let (device_sequence, previous_device_hash) = match previous {
            Some(head) => (
                head.sequence
                    .checked_add(1)
                    .ok_or(SyncError::SequenceExhausted)?,
                head.canonical_hash,
            ),
            None => (1, Sha256Digest([0; 32])),
        };
        validate_frontier(
            &causal_frontier,
            self.identity.device_id,
            Some(device_sequence),
        )?;

        let mut operation = SyncOperationV1 {
            schema_version: SYNC_SCHEMA_VERSION,
            operation_id,
            account_id: self.identity.account_id,
            workspace_id: self.identity.workspace_id,
            project_id,
            record_id: mutation.record_id(),
            record_kind: mutation.record_kind(),
            mutation_kind: mutation.mutation_kind(),
            device_id: self.identity.device_id,
            device_sequence,
            causal_frontier,
            control_epoch: self.identity.control_epoch,
            key_epoch: self.identity.key_epoch,
            previous_device_hash,
            nonce: XChaChaNonce([0; 24]),
            ciphertext: BoundedCiphertext::new(Vec::new())
                .map_err(|_| SyncError::InvalidEnvelope)?,
            ciphertext_hash: Sha256Digest([0; 32]),
            blob_refs,
            created_hlc,
            signature: Ed25519SignatureBytes([0; 64]),
        };
        operation
            .validate()
            .map_err(|_| SyncError::InvalidEnvelope)?;

        let aad =
            encode_sync_operation_aad_v1(&operation).map_err(|_| SyncError::InvalidEnvelope)?;
        let plaintext =
            encode_record_mutation_v1(mutation).map_err(|_| SyncError::InvalidMutation)?;
        let mutation_hash = digest(&plaintext);
        let encrypted = match self.fixed_nonce {
            Some(nonce) => self
                .identity
                .content_key
                .encrypt_with_nonce(&plaintext, &aad, nonce),
            None => self.identity.content_key.encrypt(&plaintext, &aad),
        }
        .map_err(|_| SyncError::EncryptionFailed)?;
        operation.nonce = encrypted.nonce;
        operation.ciphertext =
            BoundedCiphertext::new(encrypted.ciphertext).map_err(|_| SyncError::InvalidEnvelope)?;
        operation.ciphertext_hash = digest(operation.ciphertext.as_slice());
        self.identity
            .device_keys
            .sign_sync_operation(&mut operation)
            .map_err(|_| SyncError::AuthenticationFailed)?;
        let canonical_bytes =
            encode_sync_operation_v1(&operation).map_err(|_| SyncError::InvalidEnvelope)?;
        let canonical_hash = digest(&canonical_bytes);

        Ok(BuiltOperation {
            operation,
            sealed_mutation_hash: mutation_hash,
            sealed_operation_hash: canonical_hash,
            canonical_bytes,
            canonical_hash,
        })
    }
}

pub struct TrustedOperationContext<'a> {
    certificate: &'a DeviceCertificateV1,
    expected_key_epoch: u32,
    previous: Option<OperationChainHead>,
    existing_record_scope: Option<ScopeRef>,
}

impl<'a> TrustedOperationContext<'a> {
    pub const fn new(
        certificate: &'a DeviceCertificateV1,
        expected_key_epoch: u32,
        previous: Option<OperationChainHead>,
    ) -> Self {
        Self {
            certificate,
            expected_key_epoch,
            previous,
            existing_record_scope: None,
        }
    }

    /// Supplies caller-admitted existing-record scope for tombstone verification.
    #[must_use]
    pub fn with_existing_record_scope(mut self, scope: ScopeRef) -> Self {
        self.existing_record_scope = Some(scope);
        self
    }
}

pub trait OperationDecryptor {
    fn decrypt(&self, encrypted: &EncryptedPayload, aad: &[u8])
    -> Result<SecretBytes, CryptoError>;
}

impl OperationDecryptor for ContentKey {
    fn decrypt(
        &self,
        encrypted: &EncryptedPayload,
        aad: &[u8],
    ) -> Result<SecretBytes, CryptoError> {
        ContentKey::decrypt(self, encrypted, aad)
    }
}

pub fn verify_operation_envelope(
    operation: &SyncOperationV1,
    trusted: &TrustedOperationContext<'_>,
    decryptor: &impl OperationDecryptor,
) -> Result<RecordMutationV1, SyncError> {
    operation
        .validate()
        .map_err(|_| SyncError::InvalidEnvelope)?;
    validate_trusted_fields(operation, trusted)?;
    validate_tombstone_scope(operation, trusted)?;

    let signing_preimage = encode_sync_operation_signing_preimage_v1(operation)
        .map_err(|_| SyncError::InvalidEnvelope)?;
    verify_signature(
        trusted.certificate.signing_public_key,
        &signing_preimage,
        operation.signature,
    )
    .map_err(|_| SyncError::AuthenticationFailed)?;

    if digest(operation.ciphertext.as_slice()) != operation.ciphertext_hash {
        return Err(SyncError::AuthenticationFailed);
    }
    validate_chain(operation, trusted.previous)?;
    validate_frontier(
        &operation.causal_frontier,
        operation.device_id,
        Some(operation.device_sequence),
    )?;

    let aad = encode_sync_operation_aad_v1(operation).map_err(|_| SyncError::InvalidEnvelope)?;
    let encrypted = EncryptedPayload {
        nonce: operation.nonce,
        ciphertext: operation.ciphertext.as_slice().to_vec(),
    };
    let plaintext = decryptor
        .decrypt(&encrypted, &aad)
        .map_err(|_| SyncError::DecryptionFailed)?;
    let mutation =
        decode_record_mutation_v1(plaintext.expose()).map_err(|_| SyncError::InvalidMutation)?;
    if operation.record_id != mutation.record_id()
        || operation.record_kind != mutation.record_kind()
        || operation.mutation_kind != mutation.mutation_kind()
        || !scope_matches(operation.project_id, &mutation)
    {
        return Err(SyncError::InvalidMutation);
    }
    Ok(mutation)
}

pub(crate) fn verify_operation_public_authenticity(
    operation: &SyncOperationV1,
    trusted: &TrustedOperationContext<'_>,
) -> Result<(), SyncError> {
    operation
        .validate()
        .map_err(|_| SyncError::InvalidEnvelope)?;
    validate_trusted_fields(operation, trusted)?;
    let signing_preimage = encode_sync_operation_signing_preimage_v1(operation)
        .map_err(|_| SyncError::InvalidEnvelope)?;
    verify_signature(
        trusted.certificate.signing_public_key,
        &signing_preimage,
        operation.signature,
    )
    .map_err(|_| SyncError::AuthenticationFailed)?;
    if digest(operation.ciphertext.as_slice()) != operation.ciphertext_hash {
        return Err(SyncError::AuthenticationFailed);
    }
    Ok(())
}

fn validate_trusted_fields(
    operation: &SyncOperationV1,
    trusted: &TrustedOperationContext<'_>,
) -> Result<(), SyncError> {
    let certificate = trusted.certificate;
    if operation.account_id != certificate.account_id
        || operation.workspace_id != certificate.workspace_id
        || operation.device_id != certificate.device_id
        || operation.control_epoch != certificate.control_epoch
        || operation.key_epoch != trusted.expected_key_epoch
        || operation.created_hlc.node != operation.device_id
    {
        return Err(SyncError::InvalidIdentity);
    }
    Ok(())
}

fn validate_chain(
    operation: &SyncOperationV1,
    previous: Option<OperationChainHead>,
) -> Result<(), SyncError> {
    let expected = match previous {
        Some(head) => (
            head.sequence
                .checked_add(1)
                .ok_or(SyncError::SequenceExhausted)?,
            head.canonical_hash,
        ),
        None => (1, Sha256Digest([0; 32])),
    };
    if (operation.device_sequence, operation.previous_device_hash) != expected {
        return Err(SyncError::InvalidChain);
    }
    Ok(())
}

fn validate_tombstone_scope(
    operation: &SyncOperationV1,
    trusted: &TrustedOperationContext<'_>,
) -> Result<(), SyncError> {
    if operation.mutation_kind != context_relay_protocol::MutationKind::Tombstone {
        return Ok(());
    }
    let existing_scope = trusted
        .existing_record_scope
        .as_ref()
        .ok_or(SyncError::InvalidScope)?;
    if scope_project(existing_scope) != operation.project_id {
        return Err(SyncError::InvalidScope);
    }
    if operation.record_kind == RecordKind::Project
        && !operation
            .project_id
            .is_some_and(|project_id| project_id.as_bytes() == operation.record_id.as_bytes())
    {
        return Err(SyncError::InvalidScope);
    }
    Ok(())
}

pub(crate) fn validate_frontier(
    frontier: &[DeviceSequence],
    operation_device: context_relay_protocol::DeviceId,
    operation_sequence: Option<u64>,
) -> Result<(), SyncError> {
    if frontier
        .windows(2)
        .any(|pair| pair[0].device_id >= pair[1].device_id)
        || frontier.iter().any(|entry| entry.sequence == 0)
        || operation_sequence.is_some_and(|sequence| {
            frontier
                .iter()
                .any(|entry| entry.device_id == operation_device && entry.sequence >= sequence)
        })
    {
        return Err(SyncError::InvalidFrontier);
    }
    Ok(())
}

pub(crate) fn scope_matches(project_id: Option<ProjectId>, mutation: &RecordMutationV1) -> bool {
    match mutation {
        RecordMutationV1::UpsertMemory(record) => scope_project(&record.scope) == project_id,
        RecordMutationV1::UpsertMemoryCandidate(record) => {
            scope_project(&record.proposed_memory.scope) == project_id
        }
        RecordMutationV1::UpsertTask(record) => project_id == Some(record.project_id),
        RecordMutationV1::UpsertSecretRef(_) => project_id.is_none(),
        RecordMutationV1::UpsertInstruction(record) => scope_project(&record.scope) == project_id,
        RecordMutationV1::UpsertComponent(record) => scope_project(&record.scope) == project_id,
        RecordMutationV1::UpsertProject(record) => project_id == Some(record.project_id),
        RecordMutationV1::Tombstone {
            record_id,
            record_kind,
        } => match record_kind {
            RecordKind::Project => {
                project_id.is_some_and(|project_id| project_id.as_bytes() == record_id.as_bytes())
            }
            RecordKind::Task => project_id.is_some(),
            RecordKind::SecretRef => project_id.is_none(),
            _ => true,
        },
    }
}

fn scope_project(scope: &ScopeRef) -> Option<ProjectId> {
    match scope {
        ScopeRef::Global => None,
        ScopeRef::Project { project_id } => Some(*project_id),
    }
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest(Sha256::digest(bytes).into())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use context_relay_protocol::{
        BlobRef, DeviceSequence, HybridLogicalClock, RecordKind, RecordMutationV1, Sha256Digest,
        XChaChaNonce,
    };

    use crate::{
        crypto::{ContentKey, DeviceKeys},
        sync::{OperationBuilder, OperationChainHead, SyncIdentity},
    };

    #[test]
    fn fixed_signed_operation_matches_canonical_fixture_and_hash() {
        let keys = DeviceKeys::from_seeds([7; 32], [9; 32]);
        let content_key = ContentKey::from_bytes([11; 32]);
        let identity = SyncIdentity {
            account_id: id("018f22e2-79b0-7cc8-98c4-dc0c0c073981"),
            workspace_id: id("018f22e2-79b0-7cc8-98c4-dc0c0c073982"),
            device_id: id("018f22e2-79b0-7cc8-98c4-dc0c0c073983"),
            control_epoch: 17,
            key_epoch: 23,
            device_keys: &keys,
            content_key: &content_key,
        };
        let mutation = RecordMutationV1::Tombstone {
            record_id: id("018f22e2-79b0-7cc8-98c4-dc0c0c073984"),
            record_kind: RecordKind::Memory,
        };
        let built = OperationBuilder::with_nonce_for_test(identity, XChaChaNonce([13; 24]))
            .build(
                id("018f22e2-79b0-7cc8-98c4-dc0c0c073985"),
                Some(id("018f22e2-79b0-7cc8-98c4-dc0c0c073986")),
                &mutation,
                vec![
                    DeviceSequence {
                        device_id: id("018f22e2-79b0-7cc8-98c4-dc0c0c073988"),
                        sequence: 29,
                    },
                    DeviceSequence {
                        device_id: id("018f22e2-79b0-7cc8-98c4-dc0c0c073987"),
                        sequence: 31,
                    },
                ],
                Some(OperationChainHead {
                    sequence: 36,
                    canonical_hash: Sha256Digest([15; 32]),
                }),
                vec![BlobRef {
                    digest: Sha256Digest([19; 32]),
                    ciphertext_bytes: 4_096,
                    storage_id: "blob-fixed-v1".into(),
                }],
                HybridLogicalClock::new(
                    1_700_000_000_123,
                    5,
                    id("018f22e2-79b0-7cc8-98c4-dc0c0c073983"),
                ),
            )
            .unwrap();

        assert_eq!(built.operation.device_sequence, 37);
        assert_eq!(built.operation.previous_device_hash, Sha256Digest([15; 32]));
        assert_eq!(
            hex(&built.canonical_hash.0),
            "d4af94e56f0aab319e4e535b80df6b71865b7303a14c285895fa2808e3af1290"
        );
        let fixture = include_str!("../../tests/fixtures/signed-sync-operation-v1.hex")
            .split_whitespace()
            .collect::<String>();
        assert_eq!(hex(&built.canonical_bytes), fixture);
        let debug = format!(
            "{:#?}",
            OperationBuilder::new(SyncIdentity {
                account_id: id("018f22e2-79b0-7cc8-98c4-dc0c0c073981"),
                workspace_id: id("018f22e2-79b0-7cc8-98c4-dc0c0c073982"),
                device_id: id("018f22e2-79b0-7cc8-98c4-dc0c0c073983"),
                control_epoch: 17,
                key_epoch: 23,
                device_keys: &keys,
                content_key: &content_key,
            })
            .identity
        );
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("[7, 7, 7"));
        assert!(!debug.contains("[11, 11, 11"));
    }

    fn id<T: FromStr>(value: &str) -> T
    where
        T::Err: std::fmt::Debug,
    {
        value.parse().unwrap()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
