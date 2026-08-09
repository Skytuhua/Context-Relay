use std::str::FromStr;

use context_relay_protocol::{
    CHECKPOINT_SCHEMA_VERSION, CheckpointV1, DeviceId, DeviceSequence, Ed25519SignatureBytes,
    HybridLogicalClock, MAX_CBOR_OPERATION_BYTES, RecordId, RecordKind, Sha256Digest,
    decode_checkpoint_v1, encode_checkpoint_signing_preimage_v1, encode_checkpoint_v1,
};
use minicbor::{Decoder, Encoder};
use sha2::{Digest, Sha256};

use crate::{
    crypto::{DeviceKeys, verify_signature},
    vault::{Vault, VaultError},
};

use super::{CanonicalCheckpoint, SyncError, SyncScope, TrustedSyncMaterial};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateSummaryEntryV1 {
    pub record_id: RecordId,
    pub record_kind: RecordKind,
    pub head_hashes: Vec<Sha256Digest>,
    pub tombstoned: bool,
    pub conflicted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateSummaryV1 {
    pub entries: Vec<StateSummaryEntryV1>,
}

impl StateSummaryV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SyncError> {
        let entries = normalized_entries(&self.entries)?;
        let mut encoder = Encoder::new(Vec::new());
        encoder
            .array(entries.len() as u64)
            .map_err(|_| SyncError::InvalidEnvelope)?;
        for entry in entries {
            encoder.array(5).map_err(|_| SyncError::InvalidEnvelope)?;
            encoder
                .bytes(entry.record_id.as_bytes())
                .map_err(|_| SyncError::InvalidEnvelope)?;
            encoder
                .u8(record_kind_code(entry.record_kind))
                .map_err(|_| SyncError::InvalidEnvelope)?;
            encoder
                .array(entry.head_hashes.len() as u64)
                .map_err(|_| SyncError::InvalidEnvelope)?;
            for hash in entry.head_hashes {
                encoder
                    .bytes(&hash.0)
                    .map_err(|_| SyncError::InvalidEnvelope)?;
            }
            encoder
                .bool(entry.tombstoned)
                .map_err(|_| SyncError::InvalidEnvelope)?;
            encoder
                .bool(entry.conflicted)
                .map_err(|_| SyncError::InvalidEnvelope)?;
        }
        Ok(encoder.into_writer())
    }

    pub fn state_hash(&self) -> Result<Sha256Digest, SyncError> {
        Ok(digest(&self.canonical_bytes()?))
    }
}

pub fn decode_state_summary_v1(input: &[u8]) -> Result<StateSummaryV1, SyncError> {
    if input.len() > MAX_CBOR_OPERATION_BYTES {
        return Err(SyncError::InvalidEnvelope);
    }
    let mut decoder = Decoder::new(input);
    let count = definite_len(decoder.array().map_err(|_| SyncError::InvalidEnvelope)?)?;
    if count > input.len() {
        return Err(SyncError::InvalidEnvelope);
    }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        if decoder.array().map_err(|_| SyncError::InvalidEnvelope)? != Some(5) {
            return Err(SyncError::InvalidEnvelope);
        }
        let record_id = parse_record_id(decoder.bytes().map_err(|_| SyncError::InvalidEnvelope)?)?;
        let record_kind = parse_record_kind(decoder.u8().map_err(|_| SyncError::InvalidEnvelope)?)?;
        let head_count = definite_len(decoder.array().map_err(|_| SyncError::InvalidEnvelope)?)?;
        if head_count > input.len() {
            return Err(SyncError::InvalidEnvelope);
        }
        let mut head_hashes = Vec::with_capacity(head_count);
        for _ in 0..head_count {
            let bytes = decoder.bytes().map_err(|_| SyncError::InvalidEnvelope)?;
            let hash: [u8; 32] = bytes.try_into().map_err(|_| SyncError::InvalidEnvelope)?;
            head_hashes.push(Sha256Digest(hash));
        }
        entries.push(StateSummaryEntryV1 {
            record_id,
            record_kind,
            head_hashes,
            tombstoned: decoder.bool().map_err(|_| SyncError::InvalidEnvelope)?,
            conflicted: decoder.bool().map_err(|_| SyncError::InvalidEnvelope)?,
        });
    }
    if decoder.position() != input.len() {
        return Err(SyncError::InvalidEnvelope);
    }
    let summary = StateSummaryV1 { entries };
    if summary.canonical_bytes()? != input {
        return Err(SyncError::InvalidEnvelope);
    }
    Ok(summary)
}

pub struct CheckpointBuildContext<'a> {
    pub scope: SyncScope,
    pub creator_device: DeviceId,
    pub active_key_epoch: u32,
    pub device_keys: &'a DeviceKeys,
    pub created_hlc: HybridLogicalClock,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedCheckpoint {
    pub(crate) scope: SyncScope,
    pub(crate) checkpoint: CanonicalCheckpoint,
    pub(crate) expected_pin_hash: Option<Sha256Digest>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthenticatedCheckpoint {
    pub(crate) scope: SyncScope,
    pub(crate) checkpoint: CanonicalCheckpoint,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedCheckpointChainAnchor {
    pub(crate) scope: SyncScope,
    pub(crate) checkpoint: CanonicalCheckpoint,
    pub(crate) base_pin_hash: Option<Sha256Digest>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointDisposition {
    Inserted,
    ExactReplay,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredCheckpointPin {
    pub scope: SyncScope,
    pub canonical_hash: Sha256Digest,
    pub state_hash: Sha256Digest,
    pub canonical_bytes: Vec<u8>,
    pub accepted_at_ms: u64,
}

pub fn build_checkpoint(
    vault: &Vault,
    context: &CheckpointBuildContext<'_>,
    trusted_material: &impl TrustedSyncMaterial,
) -> Result<CanonicalCheckpoint, SyncError> {
    let previous_checkpoint_hash = vault
        .sync_checkpoint_pin(context.scope)
        .map_err(checkpoint_vault_error)?
        .map_or(Sha256Digest([0; 32]), |pin| pin.canonical_hash);
    build_checkpoint_with_previous(vault, context, trusted_material, previous_checkpoint_hash)
}

pub(crate) fn build_checkpoint_after_chain(
    vault: &Vault,
    context: &CheckpointBuildContext<'_>,
    trusted_material: &impl TrustedSyncMaterial,
    anchor: &VerifiedCheckpointChainAnchor,
) -> Result<CanonicalCheckpoint, SyncError> {
    if anchor.scope != context.scope {
        return Err(SyncError::InvalidScope);
    }
    let current_pin_hash = vault
        .sync_checkpoint_pin(context.scope)
        .map_err(checkpoint_vault_error)?
        .map(|pin| pin.canonical_hash);
    if current_pin_hash != anchor.base_pin_hash {
        return Err(SyncError::InvalidChain);
    }
    build_checkpoint_with_previous(
        vault,
        context,
        trusted_material,
        anchor.checkpoint.canonical_hash,
    )
}

fn build_checkpoint_with_previous(
    vault: &Vault,
    context: &CheckpointBuildContext<'_>,
    trusted_material: &impl TrustedSyncMaterial,
    previous_checkpoint_hash: Sha256Digest,
) -> Result<CanonicalCheckpoint, SyncError> {
    if context.created_hlc.node != context.creator_device {
        return Err(SyncError::InvalidIdentity);
    }
    let trusted = trusted_material.trusted_device(
        context.scope.account_id,
        context.scope.workspace_id,
        context.creator_device,
    )?;
    let certificate = &trusted.certificate;
    if certificate.account_id != context.scope.account_id
        || certificate.workspace_id != context.scope.workspace_id
        || certificate.device_id != context.creator_device
        || certificate.control_epoch != trusted.active_control_epoch
        || trusted.active_key_epoch != context.active_key_epoch
        || certificate.signing_public_key != context.device_keys.signing_public_key()
    {
        return Err(SyncError::InvalidIdentity);
    }
    let frontier = vault
        .sync_checkpoint_frontier(context.scope)
        .map_err(checkpoint_vault_error)?;
    validate_frontier(&frontier)?;
    let summary = vault
        .sync_state_summary(context.scope)
        .map_err(checkpoint_vault_error)?;
    let state_hash = summary.state_hash()?;
    let mut checkpoint = CheckpointV1 {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        account_id: context.scope.account_id,
        workspace_id: context.scope.workspace_id,
        previous_checkpoint_hash,
        causal_frontier: frontier,
        state_hash,
        key_epoch: context.active_key_epoch,
        creator_device: context.creator_device,
        created_hlc: context.created_hlc,
        signature: Ed25519SignatureBytes([0; 64]),
    };
    context
        .device_keys
        .sign_checkpoint(&mut checkpoint)
        .map_err(|_| SyncError::AuthenticationFailed)?;
    CanonicalCheckpoint::from_checkpoint(checkpoint)
}

pub fn verify_checkpoint(
    vault: &Vault,
    scope: SyncScope,
    received: &CanonicalCheckpoint,
    trusted_material: &impl TrustedSyncMaterial,
) -> Result<VerifiedCheckpoint, SyncError> {
    let authenticated = authenticate_checkpoint(scope, received, trusted_material)?;
    verify_local_checkpoint_state(vault, scope, &authenticated.checkpoint)?;

    let pin = vault
        .sync_checkpoint_pin(scope)
        .map_err(checkpoint_vault_error)?;
    let expected_pin_hash = pin.as_ref().map(|pin| pin.canonical_hash);
    match pin {
        Some(ref pin) if pin.canonical_hash == authenticated.checkpoint.canonical_hash => {
            if pin.canonical_bytes != authenticated.checkpoint.bytes
                || pin.state_hash != authenticated.checkpoint.state_hash
            {
                return Err(SyncError::InvalidChain);
            }
        }
        Some(pin)
            if authenticated.checkpoint.checkpoint.previous_checkpoint_hash
                == pin.canonical_hash => {}
        None if authenticated.checkpoint.checkpoint.previous_checkpoint_hash
            == Sha256Digest([0; 32]) => {}
        _ => return Err(SyncError::InvalidChain),
    }

    Ok(VerifiedCheckpoint {
        scope,
        checkpoint: authenticated.checkpoint,
        expected_pin_hash,
    })
}

pub(crate) fn verify_checkpoint_link(
    scope: SyncScope,
    received: &CanonicalCheckpoint,
    expected_previous: Sha256Digest,
    trusted_material: &impl TrustedSyncMaterial,
) -> Result<AuthenticatedCheckpoint, SyncError> {
    let authenticated = authenticate_checkpoint(scope, received, trusted_material)?;
    if authenticated.checkpoint.checkpoint.previous_checkpoint_hash != expected_previous {
        return Err(SyncError::InvalidChain);
    }
    Ok(authenticated)
}

pub(crate) fn verify_checkpoint_after_chain(
    vault: &Vault,
    scope: SyncScope,
    received: &CanonicalCheckpoint,
    base_pin_hash: Option<Sha256Digest>,
    trusted_material: &impl TrustedSyncMaterial,
) -> Result<(VerifiedCheckpointChainAnchor, Option<VerifiedCheckpoint>), SyncError> {
    let authenticated = authenticate_checkpoint(scope, received, trusted_material)?;
    let current_pin_hash = vault
        .sync_checkpoint_pin(scope)
        .map_err(checkpoint_vault_error)?
        .map(|pin| pin.canonical_hash);
    if current_pin_hash != base_pin_hash {
        return Err(SyncError::InvalidChain);
    }
    let anchor = VerifiedCheckpointChainAnchor {
        scope,
        checkpoint: authenticated.checkpoint.clone(),
        base_pin_hash,
    };
    if !checkpoint_matches_local_state(vault, scope, &authenticated.checkpoint)? {
        return Ok((anchor, None));
    }
    Ok((
        anchor,
        Some(VerifiedCheckpoint {
            scope,
            checkpoint: authenticated.checkpoint,
            expected_pin_hash: base_pin_hash,
        }),
    ))
}

pub(crate) fn verify_checkpoint_chain_extension(
    vault: &Vault,
    scope: SyncScope,
    received: &CanonicalCheckpoint,
    anchor: &VerifiedCheckpointChainAnchor,
    trusted_material: &impl TrustedSyncMaterial,
) -> Result<VerifiedCheckpoint, SyncError> {
    if anchor.scope != scope
        || received.checkpoint.previous_checkpoint_hash != anchor.checkpoint.canonical_hash
    {
        return Err(SyncError::InvalidChain);
    }
    let authenticated = authenticate_checkpoint(scope, received, trusted_material)?;
    verify_local_checkpoint_state(vault, scope, &authenticated.checkpoint)?;
    let current_pin_hash = vault
        .sync_checkpoint_pin(scope)
        .map_err(checkpoint_vault_error)?
        .map(|pin| pin.canonical_hash);
    if current_pin_hash != anchor.base_pin_hash {
        return Err(SyncError::InvalidChain);
    }
    Ok(VerifiedCheckpoint {
        scope,
        checkpoint: authenticated.checkpoint,
        expected_pin_hash: anchor.base_pin_hash,
    })
}

fn authenticate_checkpoint(
    scope: SyncScope,
    received: &CanonicalCheckpoint,
    trusted_material: &impl TrustedSyncMaterial,
) -> Result<AuthenticatedCheckpoint, SyncError> {
    let checkpoint =
        decode_checkpoint_v1(&received.bytes).map_err(|_| SyncError::InvalidEnvelope)?;
    let canonical_bytes =
        encode_checkpoint_v1(&checkpoint).map_err(|_| SyncError::InvalidEnvelope)?;
    let canonical_hash = digest(&canonical_bytes);
    if canonical_bytes != received.bytes
        || checkpoint != received.checkpoint
        || checkpoint.state_hash != received.state_hash
        || canonical_hash != received.canonical_hash
        || checkpoint.created_hlc.node != checkpoint.creator_device
    {
        return Err(SyncError::InvalidEnvelope);
    }
    if checkpoint.account_id != scope.account_id || checkpoint.workspace_id != scope.workspace_id {
        return Err(SyncError::InvalidIdentity);
    }

    let trusted = trusted_material.trusted_device(
        scope.account_id,
        scope.workspace_id,
        checkpoint.creator_device,
    )?;
    let certificate = &trusted.certificate;
    if certificate.account_id != scope.account_id
        || certificate.workspace_id != scope.workspace_id
        || certificate.device_id != checkpoint.creator_device
        || certificate.control_epoch != trusted.active_control_epoch
        || checkpoint.key_epoch != trusted.active_key_epoch
    {
        return Err(SyncError::InvalidIdentity);
    }
    let preimage = encode_checkpoint_signing_preimage_v1(&checkpoint)
        .map_err(|_| SyncError::InvalidEnvelope)?;
    verify_signature(
        certificate.signing_public_key,
        &preimage,
        checkpoint.signature,
    )
    .map_err(|_| SyncError::AuthenticationFailed)?;
    validate_frontier(&checkpoint.causal_frontier)?;
    Ok(AuthenticatedCheckpoint {
        scope,
        checkpoint: received.clone(),
    })
}

fn verify_local_checkpoint_state(
    vault: &Vault,
    scope: SyncScope,
    received: &CanonicalCheckpoint,
) -> Result<(), SyncError> {
    if received.checkpoint.causal_frontier
        != vault
            .sync_checkpoint_frontier(scope)
            .map_err(checkpoint_vault_error)?
    {
        return Err(SyncError::InvalidFrontier);
    }
    if received.checkpoint.state_hash
        != vault
            .sync_state_summary(scope)
            .map_err(checkpoint_vault_error)?
            .state_hash()?
    {
        return Err(SyncError::InvalidEnvelope);
    }
    Ok(())
}

fn checkpoint_matches_local_state(
    vault: &Vault,
    scope: SyncScope,
    received: &CanonicalCheckpoint,
) -> Result<bool, SyncError> {
    let local_frontier = vault
        .sync_checkpoint_frontier(scope)
        .map_err(checkpoint_vault_error)?;
    if received.checkpoint.causal_frontier != local_frontier {
        return Ok(false);
    }
    let state_hash = vault
        .sync_state_summary(scope)
        .map_err(checkpoint_vault_error)?
        .state_hash()?;
    Ok(received.checkpoint.state_hash == state_hash)
}

fn normalized_entries(
    entries: &[StateSummaryEntryV1],
) -> Result<Vec<StateSummaryEntryV1>, SyncError> {
    let mut entries = entries.to_vec();
    entries.sort_by_key(|entry| entry.record_id);
    for entry in &mut entries {
        if entry.head_hashes.is_empty() || entry.conflicted != (entry.head_hashes.len() > 1) {
            return Err(SyncError::InvalidEnvelope);
        }
        entry.head_hashes.sort();
        if entry.head_hashes.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(SyncError::InvalidEnvelope);
        }
    }
    if entries
        .windows(2)
        .any(|pair| pair[0].record_id == pair[1].record_id)
    {
        return Err(SyncError::InvalidEnvelope);
    }
    Ok(entries)
}

fn validate_frontier(frontier: &[DeviceSequence]) -> Result<(), SyncError> {
    if frontier
        .windows(2)
        .any(|pair| pair[0].device_id >= pair[1].device_id)
    {
        return Err(SyncError::InvalidFrontier);
    }
    Ok(())
}

fn definite_len(length: Option<u64>) -> Result<usize, SyncError> {
    usize::try_from(length.ok_or(SyncError::InvalidEnvelope)?)
        .map_err(|_| SyncError::InvalidEnvelope)
}

const fn record_kind_code(kind: RecordKind) -> u8 {
    match kind {
        RecordKind::Memory => 0,
        RecordKind::MemoryCandidate => 1,
        RecordKind::Task => 2,
        RecordKind::SecretRef => 3,
        RecordKind::Instruction => 4,
        RecordKind::Component => 5,
        RecordKind::Project => 6,
    }
}

fn parse_record_kind(code: u8) -> Result<RecordKind, SyncError> {
    match code {
        0 => Ok(RecordKind::Memory),
        1 => Ok(RecordKind::MemoryCandidate),
        2 => Ok(RecordKind::Task),
        3 => Ok(RecordKind::SecretRef),
        4 => Ok(RecordKind::Instruction),
        5 => Ok(RecordKind::Component),
        6 => Ok(RecordKind::Project),
        _ => Err(SyncError::InvalidEnvelope),
    }
}

fn parse_record_id(bytes: &[u8]) -> Result<RecordId, SyncError> {
    let bytes: [u8; 16] = bytes.try_into().map_err(|_| SyncError::InvalidEnvelope)?;
    let text = format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    );
    RecordId::from_str(&text).map_err(|_| SyncError::InvalidEnvelope)
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest(Sha256::digest(bytes).into())
}

fn checkpoint_vault_error(error: VaultError) -> SyncError {
    match error {
        VaultError::Validation(_) | VaultError::OperationConflict => SyncError::InvalidEnvelope,
        _ => SyncError::PersistenceFailed,
    }
}
