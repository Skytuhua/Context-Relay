//! Recovery target selection has no exporter and cannot manufacture pairing proof.
use super::*;
use crate::devices::recovery_restore_crypto::v2::{
    decode_recovery_device_claim_v2, recovery_membership_successor,
};
use context_relay_protocol::{AccountId, RecoveryRestoreId, WorkspaceId};

const DOMAIN: &[u8] = b"context-relay/recovery-history-target/v1\0";
const TARGET_BYTES: usize = DOMAIN.len() + 266;
const CHECKPOINT_LIMIT: usize = 1024 * 1024;

/// Opaque reconstruction capability; installation revalidates its exact durable target.
pub struct RecoveryHistoricalReconstruction {
    target: RecoveryTargetV1,
}
impl RecoveryHistoricalReconstruction {
    pub fn target(&self) -> RecoveryTargetV1 {
        self.target
    }
}

fn cap_budget(mut budget: HistoricalReconstructionBudget) -> HistoricalReconstructionBudget {
    budget.transfer.history.max_events = budget.transfer.history.max_events.min(4096);
    budget.transfer.history.max_bytes = budget.transfer.history.max_bytes.min(64 * 1024 * 1024);
    budget.transfer.max_pages = budget.transfer.max_pages.min(4096);
    budget.transfer.max_bytes = budget.transfer.max_bytes.min(64 * 1024 * 1024);
    budget.max_operations = budget.max_operations.min(100000);
    budget.max_operation_bytes = budget.max_operation_bytes.min(64 * 1024 * 1024);
    budget.max_dependencies = budget.max_dependencies.min(1000000);
    budget
}
fn target_storage(
    c: &Connection,
    budget: HistoricalReconstructionBudget,
) -> Result<(), VaultError> {
    let (count,bytes):(i64,i64)=c.query_row("SELECT count(*),COALESCE(sum(length(target_sha256)+length(target)+length(checkpoint)+length(selection_signature)+COALESCE(length(prefixes),0)+COALESCE(length(reconstructed_signature),0)+COALESCE(length(installed_signature),0)),0) FROM recovery_history_targets",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
    if !(0..=4096).contains(&count) || bytes < 0 || bytes as usize > budget.transfer.max_bytes {
        return Err(VaultError::BudgetExceeded);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryTargetV1 {
    restore_id: RecoveryRestoreId,
    scope: SyncScope,
    pin: Sha256Digest,
    claim_sha256: Sha256Digest,
    admission: Sha256Digest,
    endpoint: MembershipEndpoint,
    recipient: DeviceId,
    certificate_sha256: Sha256Digest,
    checkpoint_sha256: Sha256Digest,
}
impl RecoveryTargetV1 {
    pub fn restore_id(&self) -> RecoveryRestoreId {
        self.restore_id
    }
    pub fn authorizing_endpoint(&self) -> MembershipEndpoint {
        self.endpoint
    }
    pub fn checkpoint_sha256(&self) -> Sha256Digest {
        self.checkpoint_sha256
    }
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = DOMAIN.to_vec();
        bytes.extend(1u16.to_be_bytes());
        bytes.extend(self.restore_id.as_bytes());
        bytes.extend(self.scope.account_id.as_bytes());
        bytes.extend(self.scope.workspace_id.as_bytes());
        bytes.extend(self.pin.0);
        bytes.extend(self.claim_sha256.0);
        bytes.extend(self.admission.0);
        bytes.extend(self.endpoint.state_sha256.0);
        bytes.extend(self.endpoint.control_epoch.to_be_bytes());
        bytes.extend(self.endpoint.key_epoch.to_be_bytes());
        bytes.extend(self.recipient.as_bytes());
        bytes.extend(self.certificate_sha256.0);
        bytes.extend(self.checkpoint_sha256.0);
        bytes
    }
    fn decode(bytes: &[u8]) -> Result<Self, VaultError> {
        if bytes.len() != TARGET_BYTES || !bytes.starts_with(DOMAIN) {
            return Err(invalid());
        }
        let mut input = &bytes[DOMAIN.len()..];
        fn take<const N: usize>(input: &mut &[u8]) -> Result<[u8; N], VaultError> {
            let (head, rest) = input.split_at_checked(N).ok_or_else(invalid)?;
            *input = rest;
            head.try_into().map_err(|_| invalid())
        }
        if u16::from_be_bytes(take(&mut input)?) != 1 {
            return Err(invalid());
        }
        let target = Self {
            restore_id: checked(RecoveryRestoreId::new(checked(uuid::Uuid::from_slice(
                &take::<16>(&mut input)?,
            ))?))?,
            scope: SyncScope {
                account_id: checked(AccountId::new(checked(uuid::Uuid::from_slice(
                    &take::<16>(&mut input)?,
                ))?))?,
                workspace_id: checked(WorkspaceId::new(checked(uuid::Uuid::from_slice(
                    &take::<16>(&mut input)?,
                ))?))?,
            },
            pin: Sha256Digest(take(&mut input)?),
            claim_sha256: Sha256Digest(take(&mut input)?),
            admission: Sha256Digest(take(&mut input)?),
            endpoint: MembershipEndpoint {
                state_sha256: Sha256Digest(take(&mut input)?),
                control_epoch: u32::from_be_bytes(take(&mut input)?),
                key_epoch: u32::from_be_bytes(take(&mut input)?),
            },
            recipient: checked(DeviceId::new(checked(uuid::Uuid::from_slice(
                &take::<16>(&mut input)?,
            ))?))?,
            certificate_sha256: Sha256Digest(take(&mut input)?),
            checkpoint_sha256: Sha256Digest(take(&mut input)?),
        };
        if !input.is_empty()
            || target.endpoint.control_epoch == 0
            || target.endpoint.key_epoch == 0
            || [
                target.pin,
                target.claim_sha256,
                target.admission,
                target.endpoint.state_sha256,
                target.certificate_sha256,
                target.checkpoint_sha256,
            ]
            .contains(&Sha256Digest([0; 32]))
        {
            return Err(invalid());
        }
        Ok(target)
    }
}
fn selection_preimage(c: &Connection, target: RecoveryTargetV1) -> Result<Vec<u8>, VaultError> {
    let mut bytes = target.canonical_bytes();
    bytes.extend(digest(&super::super::super::recovery_v2::intent_bytes(c)?).0);
    Ok(bytes)
}

// The signer may have been revoked later. Replay supplies its exact historical
// certificate/epoch authority; complete cutoff/prefix/state verification is separate.
fn checkpoint(
    stored: &Stored,
    bytes: &[u8],
    expected: Sha256Digest,
    budget: HistoricalReconstructionBudget,
) -> Result<context_relay_protocol::CheckpointV1, VaultError> {
    if bytes.is_empty() || bytes.len() > CHECKPOINT_LIMIT || digest(bytes) != expected {
        return Err(invalid());
    }
    let checkpoint = checked(decode_checkpoint_v1(bytes))?;
    if checked(context_relay_protocol::encode_checkpoint_v1(&checkpoint))? != bytes
        || checkpoint.account_id != stored.scope.account_id
        || checkpoint.workspace_id != stored.scope.workspace_id
        || checkpoint.created_hlc.node != checkpoint.creator_device
        || checkpoint.key_epoch > stored.endpoint.key_epoch
    {
        return Err(invalid());
    }
    let mut author = None;
    checked(
        crate::devices::membership_crypto::replay_membership_history(
            &stored.enrollment,
            stored.pin,
            stored.scope,
            &stored
                .events
                .iter()
                .map(Event::evidence)
                .collect::<Vec<_>>(),
            stored.endpoint,
            budget.transfer.history,
            |history, _| {
                if history.endpoint().key_epoch == checkpoint.key_epoch
                    && let Some(cert) = history
                        .state()
                        .active_devices
                        .get(&checkpoint.creator_device)
                {
                    if author.as_ref().is_some_and(|old| old != cert) {
                        return Err(crate::crypto::CryptoError::AuthenticationFailed);
                    }
                    author = Some(cert.clone());
                }
                Ok(())
            },
        ),
    )?;
    checked(crate::crypto::verify_signature(
        author.ok_or_else(invalid)?.signing_public_key,
        &checked(context_relay_protocol::encode_checkpoint_signing_preimage_v1(&checkpoint))?,
        checkpoint.signature,
    ))?;
    Ok(checkpoint)
}

fn validate_target(
    c: &Connection,
    stored: &Stored,
    target: RecoveryTargetV1,
    bytes: &[u8],
    signature: &[u8],
    budget: HistoricalReconstructionBudget,
) -> Result<(), VaultError> {
    let history = stored.verify(budget.transfer.history)?;
    if target.scope != stored.scope || target.pin != stored.pin {
        return Err(invalid());
    }
    material::lineage(stored, target.endpoint, budget.transfer.history)?;
    let event = stored
        .events
        .iter()
        .find(|event| {
            event.successor == target.admission
                && event.statement.is_empty()
                && event.request.is_none()
        })
        .ok_or_else(invalid)?;
    let claim = checked(decode_recovery_device_claim_v2(&event.artifact))?;
    if claim.restore_id != target.restore_id
        || digest(&event.artifact) != target.claim_sha256
        || claim.certificate.device_id != target.recipient
        || checked(crate::devices::crypto::certificate_digest(
            &claim.certificate,
        ))? != target.certificate_sha256
    {
        return Err(invalid());
    }
    let cert = history
        .state()
        .active_devices
        .get(&target.recipient)
        .ok_or_else(invalid)?
        .clone();
    if cert != claim.certificate {
        return Err(invalid());
    }
    let admission = MembershipEndpoint {
        state_sha256: target.admission,
        control_epoch: claim.certificate.control_epoch,
        key_epoch: claim.key_epoch,
    };
    let lineage = material::lineage(stored, admission, budget.transfer.history)?;
    // Both anchors must be ordered on accepted history: R may not follow selected D.
    let r = stored
        .events
        .iter()
        .position(|event| event.successor == admission.state_sha256)
        .ok_or_else(invalid)?;
    let d = stored
        .events
        .iter()
        .position(|event| event.successor == target.endpoint.state_sha256)
        .ok_or_else(invalid)?;
    if r > d || lineage.history().endpoint() != stored.endpoint {
        return Err(invalid());
    }
    checked(crate::crypto::verify_signature(
        cert.signing_public_key,
        &selection_preimage(c, target)?,
        Ed25519SignatureBytes(signature.try_into().map_err(|_| invalid())?),
    ))?;
    // Historical candidate authorization is evaluated through the selected D only.
    let selected = Stored {
        scope: stored.scope,
        pin: stored.pin,
        enrollment: stored.enrollment.clone(),
        endpoint: target.endpoint,
        events: stored.events[..=d].to_vec(),
    };
    checkpoint(&selected, bytes, target.checkpoint_sha256, budget)?;
    Ok(())
}

fn load_target(
    c: &Connection,
    stored: &Stored,
    hash: Sha256Digest,
    budget: HistoricalReconstructionBudget,
) -> Result<(RecoveryTargetV1, Vec<u8>), VaultError> {
    target_storage(c, budget)?;
    let row=c.query_row("SELECT CASE WHEN length(target)=?2 THEN target END,CASE WHEN length(checkpoint) BETWEEN 1 AND ?3 THEN checkpoint END,CASE WHEN length(selection_signature)=64 THEN selection_signature END FROM recovery_history_targets WHERE target_sha256=?1",params![hash.0.as_slice(),TARGET_BYTES as i64,CHECKPOINT_LIMIT as i64],|r|Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,Vec<u8>>(1)?,r.get::<_,Vec<u8>>(2)?)))?;
    if digest(&row.0) != hash {
        return Err(invalid());
    }
    let target = RecoveryTargetV1::decode(&row.0)?;
    validate_target(c, stored, target, &row.1, &row.2, budget)?;
    Ok((target, row.1))
}

fn endpoint_dto(endpoint: MembershipEndpoint) -> context_relay_protocol::RecoveryHistoryEndpoint {
    context_relay_protocol::RecoveryHistoryEndpoint {
        state_sha256: endpoint.state_sha256,
        control_epoch: endpoint.control_epoch,
        key_epoch: endpoint.key_epoch,
    }
}
fn selected_hash(c: &Connection) -> Result<Option<Sha256Digest>, VaultError> {
    let hash = c.query_row("SELECT CASE WHEN length(target_sha256)=32 THEN target_sha256 END FROM recovery_history_selection WHERE singleton=1", [], |r| r.get::<_,Vec<u8>>(0)).optional()?;
    hash.map(|hash| Ok(Sha256Digest(hash.try_into().map_err(|_| invalid())?)))
        .transpose()
}
fn recovery_context(
    c: &Connection,
    keys: &DeviceKeys,
    budget: HistoricalReconstructionBudget,
) -> Result<(crate::vault::PreparedRecoveryV2, Stored), VaultError> {
    let prepared = super::super::super::recovery_v2::load(c, keys)?.ok_or_else(invalid)?;
    super::super::recovery::receipt(c, &prepared, keys)?.ok_or_else(invalid)?;
    if prepared.publication_conflict {
        return Err(invalid());
    }
    let stored = load(c, budget.transfer.history)?.ok_or_else(invalid)?;
    material::endpoint_check(
        &stored,
        stored.endpoint,
        prepared.claim.certificate.device_id,
        keys,
        budget.transfer.history,
    )?;
    material::lineage(
        &stored,
        MembershipEndpoint {
            state_sha256: checked(recovery_membership_successor(&prepared.claim))?,
            control_epoch: prepared.claim.certificate.control_epoch,
            key_epoch: prepared.claim.key_epoch,
        },
        budget.transfer.history,
    )?;
    supplemental_keys(c, &stored, &prepared, keys, budget)?;
    let evidence = authenticate(&stored, load_evidence(c, budget)?, budget)?;
    // Missing operations remain repairable; receipt corruption never means unselected.
    saved_prefixes(
        c,
        &stored,
        &evidence,
        prepared.claim.certificate.device_id,
        budget,
    )?;
    Ok((prepared, stored))
}

enum KeyAvailability {
    Ready,
    HistoricalMissing,
    CurrentMissing,
}
fn key_availability(
    c: &Connection,
    stored: &Stored,
    target: RecoveryTargetV1,
    keys: &DeviceKeys,
    budget: HistoricalReconstructionBudget,
) -> Result<KeyAvailability, VaultError> {
    let prepared = super::super::super::recovery_v2::load(c, keys)?.ok_or_else(invalid)?;
    let root = checked(
        crate::devices::recovery_crypto::decode_recovery_enrollment_record_v1(
            &prepared.canonical_record,
        ),
    )?;
    let lineage = material::lineage(
        stored,
        MembershipEndpoint {
            state_sha256: target.admission,
            control_epoch: prepared.claim.certificate.control_epoch,
            key_epoch: prepared.claim.key_epoch,
        },
        budget.transfer.history,
    )?;
    let mut retained = BTreeSet::new();
    let supplemental = supplemental_keys(c, stored, &prepared, keys, budget)?;
    for key in prepared.history_keys.iter().chain(&supplemental) {
        checked(
            crate::devices::recovery_restore_crypto::v2::open_recovery_history_key(
                &root,
                &prepared.claim,
                &prepared.parent,
                &lineage,
                key,
                keys,
            ),
        )?;
        retained.insert(key.key_epoch);
    }
    // Independent current authority is never supplied by root-only history repair.
    if material::load_secret(
        c,
        stored,
        target.recipient,
        stored.endpoint.key_epoch,
        true,
        keys,
        budget.transfer.history,
    )?
    .is_none()
    {
        return Ok(KeyAvailability::CurrentMissing);
    }
    if stored.endpoint.key_epoch as usize > budget.transfer.history.max_events.saturating_add(1) {
        return Err(VaultError::BudgetExceeded);
    }
    for epoch in 1..stored.endpoint.key_epoch {
        if material::load_secret(
            c,
            stored,
            target.recipient,
            epoch,
            false,
            keys,
            budget.transfer.history,
        )?
        .is_none()
            && !retained.contains(&epoch)
        {
            return Ok(KeyAvailability::HistoricalMissing);
        }
    }
    Ok(KeyAvailability::Ready)
}

fn supplemental_keys(
    c: &Connection,
    stored: &Stored,
    prepared: &crate::vault::PreparedRecoveryV2,
    keys: &DeviceKeys,
    budget: HistoricalReconstructionBudget,
) -> Result<Vec<crate::devices::recovery_restore_crypto::v2::RecoveryHistoryKeyV1>, VaultError> {
    use crate::devices::{
        recovery_crypto::{
            decode_recovery_device_envelope_v1, decode_recovery_enrollment_record_v1,
        },
        recovery_restore_crypto::v2::{RecoveryHistoryKeyV1, open_recovery_history_key},
    };
    let (count,bytes):(i64,i64)=c.query_row("SELECT count(*),COALESCE(sum(length(original_bundle_sha256)+length(canonical_envelope)+length(signature)+4),0) FROM (SELECT * FROM recovery_v2_history_keys UNION ALL SELECT * FROM recovery_v2_supplemental_history_keys)",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
    if !(0..=4096).contains(&count) || bytes < 0 || bytes as usize > budget.transfer.max_bytes {
        return Err(VaultError::BudgetExceeded);
    }
    let root = checked(decode_recovery_enrollment_record_v1(
        &prepared.canonical_record,
    ))?;
    let lineage = material::lineage(
        stored,
        MembershipEndpoint {
            state_sha256: checked(recovery_membership_successor(&prepared.claim))?,
            control_epoch: prepared.claim.certificate.control_epoch,
            key_epoch: prepared.claim.key_epoch,
        },
        budget.transfer.history,
    )?;
    let mut epochs = prepared
        .history_keys
        .iter()
        .map(|k| k.key_epoch)
        .collect::<BTreeSet<_>>();
    let mut query=c.prepare("SELECT key_epoch,CASE WHEN length(original_bundle_sha256)=32 THEN original_bundle_sha256 END,CASE WHEN length(canonical_envelope) BETWEEN 1 AND 1024 THEN canonical_envelope END,CASE WHEN length(signature)=64 THEN signature END FROM recovery_v2_supplemental_history_keys ORDER BY key_epoch")?;
    let mut rows = query.query([])?;
    let mut result = Vec::new();
    while let Some(row) = rows.next()? {
        let key_epoch = row.get(0)?;
        if !epochs.insert(key_epoch) {
            return Err(invalid());
        }
        let retained = RecoveryHistoryKeyV1 {
            key_epoch,
            original_bundle_sha256: Sha256Digest(
                row.get::<_, Vec<u8>>(1)?
                    .try_into()
                    .map_err(|_| invalid())?,
            ),
            envelope: checked(decode_recovery_device_envelope_v1(
                &row.get::<_, Vec<u8>>(2)?,
            ))?,
            signature: Ed25519SignatureBytes(
                row.get::<_, Vec<u8>>(3)?
                    .try_into()
                    .map_err(|_| invalid())?,
            ),
        };
        checked(open_recovery_history_key(
            &root,
            &prepared.claim,
            &prepared.parent,
            &lineage,
            &retained,
            keys,
        ))?;
        result.push(retained);
    }
    Ok(result)
}

impl Vault {
    /// Native phrase reentry repairs only absent historical receipts, never current authority.
    pub fn unlock_recovery_history(
        &mut self,
        target: RecoveryTargetV1,
        words: context_relay_protocol::RecoveryPhraseWords,
        keys: &DeviceKeys,
        budget: HistoricalReconstructionBudget,
        authorize: impl Fn() -> Result<(), VaultError>,
    ) -> Result<(), VaultError> {
        use crate::devices::{
            recovery_crypto::encode_recovery_device_envelope_v1,
            recovery_restore_crypto::{
                authenticate_recovery_root, v2::authenticate_recovery_history,
            },
        };
        let budget = cap_budget(budget);
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (prepared, stored) = recovery_context(&tx, keys, budget)?;
        exact_selected(&tx, &stored, target, keys, budget)?;
        if prepared.claim.restore_id != target.restore_id {
            return Err(invalid());
        }
        let availability = key_availability(&tx, &stored, target, keys, budget)?;
        if matches!(availability, KeyAvailability::CurrentMissing) {
            return Err(invalid());
        }
        if matches!(availability, KeyAvailability::Ready) {
            authorize()?;
            return Ok(());
        }
        let supplemental = supplemental_keys(&tx, &stored, &prepared, keys, budget)?;
        let retained = prepared
            .history_keys
            .iter()
            .chain(&supplemental)
            .map(|key| key.key_epoch)
            .collect::<BTreeSet<_>>();
        let mut missing = BTreeSet::new();
        for epoch in 1..stored.endpoint.key_epoch {
            if !retained.contains(&epoch)
                && material::load_secret(
                    &tx,
                    &stored,
                    target.recipient,
                    epoch,
                    false,
                    keys,
                    budget.transfer.history,
                )?
                .is_none()
            {
                missing.insert(epoch);
            }
        }
        let phrase = checked(crate::crypto::RecoveryPhrase::from_words(words))?;
        let root = checked(authenticate_recovery_root(
            &prepared.canonical_record,
            prepared.claim.canonical_record_sha256,
            phrase,
        ))?;
        let events = stored
            .events
            .iter()
            .map(Event::evidence)
            .collect::<Vec<_>>();
        let authority = checked(authenticate_recovery_history(
            root,
            &events,
            stored.endpoint,
            budget.transfer.history,
        ))?;
        let lineage = material::lineage(
            &stored,
            MembershipEndpoint {
                state_sha256: target.admission,
                control_epoch: prepared.claim.certificate.control_epoch,
                key_epoch: prepared.claim.key_epoch,
            },
            budget.transfer.history,
        )?;
        let repaired = checked(authority.seal_missing_historical_keys(
            &prepared.claim,
            &prepared.parent,
            &lineage,
            &missing,
            keys,
        ))?;
        drop(authority);
        authorize()?;
        for key in repaired {
            tx.execute(
                "INSERT INTO recovery_v2_supplemental_history_keys VALUES(?1,?2,?3,?4)",
                params![
                    key.key_epoch,
                    key.original_bundle_sha256.0.as_slice(),
                    checked(encode_recovery_device_envelope_v1(&key.envelope))?,
                    key.signature.0.as_slice()
                ],
            )?;
        }
        supplemental_keys(&tx, &stored, &prepared, keys, budget)?;
        authorize()?;
        tx.commit()?;
        Ok(())
    }

    /// Download planning only. Final closure, cutoff hashes and state replay stay shared.
    pub fn recovery_history_missing_operations(
        &self,
        target: RecoveryTargetV1,
        keys: &DeviceKeys,
        budget: HistoricalReconstructionBudget,
    ) -> Result<Option<(DeviceId, std::ops::RangeInclusive<u64>)>, VaultError> {
        let budget = cap_budget(budget);
        let tx = self.connection.unchecked_transaction()?;
        let (_, stored) = recovery_context(&tx, keys, budget)?;
        let bytes = exact_selected(&tx, &stored, target, keys, budget)?;
        let checkpoint = checkpoint(&stored, &bytes, target.checkpoint_sha256, budget)?;
        let evidence = authenticate(&stored, load_evidence(&tx, budget)?, budget)?;
        let mut required = checkpoint
            .causal_frontier
            .iter()
            .map(|head| (head.device_id, head.sequence))
            .collect::<BTreeMap<_, _>>();
        loop {
            let before = required.clone();
            for (device, end) in &before {
                if let Some((cutoff, _)) = evidence.cutoffs.get(device) {
                    if end > cutoff {
                        return Err(invalid());
                    }
                    required.insert(*device, *cutoff);
                }
                for (_, entry) in evidence.entries.range((*device, 1)..=(*device, *end)) {
                    for dep in &entry.operation.causal_frontier {
                        required
                            .entry(dep.device_id)
                            .and_modify(|n| *n = (*n).max(dep.sequence))
                            .or_insert(dep.sequence);
                    }
                }
            }
            let total = required
                .values()
                .try_fold(0u64, |n, end| n.checked_add(*end))
                .ok_or(VaultError::BudgetExceeded)?;
            if total > budget.max_operations as u64 {
                return Err(VaultError::BudgetExceeded);
            }
            if before == required {
                break;
            }
        }
        for (device, end) in required {
            for sequence in 1..=end {
                if !evidence.entries.contains_key(&(device, sequence)) {
                    return Ok(Some((
                        device,
                        sequence..=end.min(sequence.saturating_add(255)),
                    )));
                }
            }
        }
        Ok(None)
    }

    /// Authenticate provider bytes without creating or replacing any target receipt.
    pub fn recovery_history_candidate(
        &self,
        restore_id: RecoveryRestoreId,
        expected: Sha256Digest,
        bytes: &[u8],
        hash: Sha256Digest,
        keys: &DeviceKeys,
        budget: HistoricalReconstructionBudget,
    ) -> Result<context_relay_protocol::RecoveryHistoryCandidate, VaultError> {
        let budget = cap_budget(budget);
        let tx = self.connection.unchecked_transaction()?;
        let (prepared, stored) = recovery_context(&tx, keys, budget)?;
        if prepared.claim.restore_id != restore_id || stored.endpoint.state_sha256 != expected {
            return Err(VaultError::OperationConflict);
        }
        let value = checkpoint(&stored, bytes, hash, budget)?;
        let extent = value
            .causal_frontier
            .iter()
            .try_fold(0u64, |n, head| n.checked_add(head.sequence));
        let extent = match extent {
            Some(n) if n <= budget.max_operations as u64 => {
                context_relay_protocol::RecoveryHistoryExtent::Supported {
                    operation_count: n as u32,
                }
            }
            _ => context_relay_protocol::RecoveryHistoryExtent::Unsupported {},
        };
        Ok(context_relay_protocol::RecoveryHistoryCandidate {
            checkpoint_sha256: hash,
            author_device_id: value.creator_device,
            created_hlc: value.created_hlc,
            key_epoch: value.key_epoch,
            frontier_device_count: value
                .causal_frontier
                .len()
                .try_into()
                .map_err(|_| VaultError::BudgetExceeded)?,
            extent,
        })
    }

    /// Exact reauthentication shared by overview and explicit history actions.
    pub fn recovery_history_status(
        &self,
        keys: &DeviceKeys,
        budget: HistoricalReconstructionBudget,
    ) -> Result<context_relay_protocol::RecoveryRestoreStatus, VaultError> {
        use context_relay_protocol::{
            RecoveryHistoryProgress as Progress, RecoveryRestoreStatus as Status,
        };
        let budget = cap_budget(budget);
        let tx = self.connection.unchecked_transaction()?;
        let (prepared, stored) = recovery_context(&tx, keys, budget)?;
        let hash = selected_hash(&tx)?;
        let history = if let Some(hash) = hash {
            let (target, bytes) = load_target(&tx, &stored, hash, budget)?;
            if target.restore_id != prepared.claim.restore_id
                || target.recipient != prepared.claim.certificate.device_id
            {
                return Err(invalid());
            }
            if installed_receipt(&tx, &stored, target, &bytes, keys, budget)? {
                return Ok(Status::Complete {
                    restore_id: prepared.claim.restore_id,
                    device: context_relay_protocol::DeviceSummary {
                        device_id: target.recipient,
                        name: prepared.claim.device_name,
                        platform: prepared.claim.device_platform,
                        state: context_relay_protocol::DeviceState::Active,
                        is_current: true,
                    },
                });
            }
            let selected_endpoint = endpoint_dto(target.endpoint);
            let checkpoint_sha256 = target.checkpoint_sha256;
            if target.endpoint != stored.endpoint {
                Progress::StaleEndpoint {
                    selected_endpoint,
                    checkpoint_sha256,
                }
            } else {
                match key_availability(&tx, &stored, target, keys, budget)? {
                    KeyAvailability::HistoricalMissing => Progress::HistoricalKeysNeeded {
                        selected_endpoint,
                        checkpoint_sha256,
                    },
                    KeyAvailability::CurrentMissing => Progress::CurrentMaterialUnavailable {
                        selected_endpoint,
                        checkpoint_sha256,
                    },
                    KeyAvailability::Ready => Progress::Incomplete {
                        selected_endpoint,
                        checkpoint_sha256,
                    },
                }
            }
        } else {
            Progress::Unselected {}
        };
        tx.commit()?;
        Ok(Status::RestoringHistory {
            restore_id: prepared.claim.restore_id,
            accepted_endpoint: endpoint_dto(stored.endpoint),
            history,
        })
    }

    pub fn recovery_history_selection(
        &self,
        keys: &DeviceKeys,
        budget: HistoricalReconstructionBudget,
    ) -> Result<Option<RecoveryTargetV1>, VaultError> {
        let budget = cap_budget(budget);
        let tx = self.connection.unchecked_transaction()?;
        let hash=tx.query_row("SELECT CASE WHEN length(target_sha256)=32 THEN target_sha256 END FROM recovery_history_selection WHERE singleton=1",[],|r|r.get::<_,Vec<u8>>(0)).optional()?;
        let Some(hash) = hash else { return Ok(None) };
        let stored = load(&tx, budget.transfer.history)?.ok_or_else(invalid)?;
        let (target, _) = load_target(
            &tx,
            &stored,
            Sha256Digest(hash.try_into().map_err(|_| invalid())?),
            budget,
        )?;
        material::endpoint_check(
            &stored,
            target.endpoint,
            target.recipient,
            keys,
            budget.transfer.history,
        )?;
        tx.commit()?;
        Ok(Some(target))
    }

    /// Recheck caller authority immediately before either selection commit.
    /// A later cancellation does not retroactively undo an authorized commit.
    #[allow(clippy::too_many_arguments)]
    pub fn select_recovery_history_authorized(
        &mut self,
        expected: MembershipEndpoint,
        bytes: &[u8],
        keys: &DeviceKeys,
        budget: HistoricalReconstructionBudget,
        authorize: impl Fn() -> Result<(), VaultError>,
    ) -> Result<RecoveryTargetV1, VaultError> {
        let budget = cap_budget(budget);
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prepared = super::super::super::recovery_v2::load(&tx, keys)?.ok_or_else(invalid)?;
        super::super::recovery::receipt(&tx, &prepared, keys)?.ok_or_else(invalid)?;
        let stored = load(&tx, budget.transfer.history)?.ok_or_else(invalid)?;
        material::endpoint_check(
            &stored,
            expected,
            prepared.claim.certificate.device_id,
            keys,
            budget.transfer.history,
        )?;
        let target = RecoveryTargetV1 {
            restore_id: prepared.claim.restore_id,
            scope: stored.scope,
            pin: stored.pin,
            claim_sha256: digest(&prepared.canonical_claim),
            admission: checked(recovery_membership_successor(&prepared.claim))?,
            endpoint: expected,
            recipient: prepared.claim.certificate.device_id,
            certificate_sha256: checked(crate::devices::crypto::certificate_digest(
                &prepared.claim.certificate,
            ))?,
            checkpoint_sha256: digest(bytes),
        };
        let raw = target.canonical_bytes();
        RecoveryTargetV1::decode(&raw)?;
        let signature = keys.sign_hosted_device_proof(&selection_preimage(&tx, target)?);
        validate_target(&tx, &stored, target, bytes, &signature.0, budget)?;
        let hash = digest(&raw);
        let prior = tx
            .query_row(
                "SELECT target_sha256 FROM recovery_history_selection WHERE singleton=1",
                [],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        if let Some(prior) = prior {
            let (old, _) = load_target(
                &tx,
                &stored,
                Sha256Digest(prior.try_into().map_err(|_| invalid())?),
                budget,
            )?;
            if old == target {
                authorize()?;
                tx.commit()?;
                return Ok(target);
            }
        }
        // Selection is only a cursor. Its absence cannot erase authenticated history.
        {
            let evidence = authenticate(&stored, load_evidence(&tx, budget)?, budget)?;
            if !saved_prefixes(&tx, &stored, &evidence, target.recipient, budget)? {
                return Err(VaultError::OperationConflict);
            }
            let next = checked(decode_checkpoint_v1(bytes))?;
            let mut count = 0usize;
            let mut query=tx.prepare("SELECT target_sha256 FROM recovery_history_targets WHERE reconstructed_signature IS NOT NULL ORDER BY target_sha256")?;
            let rows = query.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
            for row in rows {
                count += 1;
                if count > 4096 {
                    return Err(VaultError::BudgetExceeded);
                }
                let (_, baseline) = load_target(
                    &tx,
                    &stored,
                    Sha256Digest(row?.try_into().map_err(|_| invalid())?),
                    budget,
                )?;
                let baseline = checked(decode_checkpoint_v1(&baseline))?;
                if baseline.causal_frontier.iter().any(|head| {
                    next.causal_frontier
                        .iter()
                        .find(|next| next.device_id == head.device_id)
                        .is_none_or(|next| next.sequence < head.sequence)
                }) {
                    return Err(VaultError::OperationConflict);
                }
            }
            drop(query);
            if count != 0 && prefixes(&evidence, &next.causal_frontier, budget)?.is_none() {
                return Err(VaultError::OperationConflict);
            }
        }
        if tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM recovery_history_targets WHERE target_sha256=?1)",
            [hash.0.as_slice()],
            |r| r.get::<_, bool>(0),
        )? {
            let (existing, checkpoint) = load_target(&tx, &stored, hash, budget)?;
            if existing != target || checkpoint != bytes {
                return Err(VaultError::OperationConflict);
            }
        } else {
            tx.execute("INSERT INTO recovery_history_targets(target_sha256,target,checkpoint,selection_signature) VALUES(?1,?2,?3,?4)",params![hash.0.as_slice(),raw,bytes,signature.0.as_slice()])?;
        }
        target_storage(&tx, budget)?;
        tx.execute("INSERT INTO recovery_history_selection VALUES(1,?1) ON CONFLICT(singleton) DO UPDATE SET target_sha256=excluded.target_sha256",[hash.0.as_slice()])?;
        authorize()?;
        tx.commit()?;
        Ok(target)
    }

    pub fn select_recovery_history(
        &mut self,
        expected: MembershipEndpoint,
        bytes: &[u8],
        keys: &DeviceKeys,
        budget: HistoricalReconstructionBudget,
    ) -> Result<RecoveryTargetV1, VaultError> {
        self.select_recovery_history_authorized(expected, bytes, keys, budget, || Ok(()))
    }
}

fn reconstruction_preimage(target: RecoveryTargetV1, prefixes: &[u8], installed: bool) -> Vec<u8> {
    let mut bytes = b"context-relay/recovery-history-reconstruction/v1\0".to_vec();
    bytes.extend(digest(&target.canonical_bytes()).0);
    bytes.extend(digest(prefixes).0);
    bytes.push(u8::from(installed));
    bytes
}

pub(super) fn cover_saved_prefixes(
    c: &Connection,
    stored: &Stored,
    evidence: &AuthenticatedEvidence,
    device: DeviceId,
    budget: HistoricalReconstructionBudget,
    covered: &mut BTreeMap<DeviceId, u64>,
) -> Result<bool, VaultError> {
    let inconsistent:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM recovery_history_targets WHERE (prefixes IS NULL)!=(reconstructed_signature IS NULL) OR (installed_signature IS NOT NULL AND reconstructed_signature IS NULL))",[],|r|r.get(0))?;
    if inconsistent {
        return Err(invalid());
    }
    let (count,bytes):(i64,i64)=c.query_row("SELECT count(*),COALESCE(sum(length(target)+length(checkpoint)+length(prefixes)+64),0) FROM recovery_history_targets WHERE reconstructed_signature IS NOT NULL",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
    if !(0..=4096).contains(&count) || bytes < 0 || bytes as usize > budget.transfer.max_bytes {
        return Err(VaultError::BudgetExceeded);
    }
    let signing = stored
        .verify(budget.transfer.history)?
        .state()
        .active_devices
        .get(&device)
        .ok_or_else(invalid)?
        .signing_public_key;
    let mut q=c.prepare("SELECT CASE WHEN length(target_sha256)=32 THEN target_sha256 END,CASE WHEN length(prefixes)<=?1 THEN prefixes END,CASE WHEN length(reconstructed_signature)=64 THEN reconstructed_signature END FROM recovery_history_targets WHERE reconstructed_signature IS NOT NULL ORDER BY target_sha256")?;
    let mut rows = q.query([budget.max_operation_bytes.min(64 * 1024 * 1024) as i64])?;
    while let Some(row) = rows.next()? {
        let hash: Vec<u8> = row.get(0)?;
        let saved: Vec<u8> = row.get(1)?;
        let signature: Vec<u8> = row.get(2)?;
        let (target, bytes) = load_target(
            c,
            stored,
            Sha256Digest(hash.try_into().map_err(|_| invalid())?),
            budget,
        )?;
        if target.recipient != device || !saved.chunks_exact(56).remainder().is_empty() {
            return Err(invalid());
        }
        checked(crate::crypto::verify_signature(
            signing,
            &reconstruction_preimage(target, &saved, false),
            Ed25519SignatureBytes(signature.try_into().map_err(|_| invalid())?),
        ))?;
        let mut frontier = BTreeMap::new();
        for bytes in saved.chunks_exact(56) {
            let device = checked(DeviceId::new(checked(uuid::Uuid::from_slice(
                &bytes[..16],
            ))?))?;
            let sequence = u64::from_be_bytes(bytes[16..24].try_into().map_err(|_| invalid())?);
            if sequence == 0
                || frontier
                    .last_key_value()
                    .is_some_and(|(last, _)| *last >= device)
            {
                return Err(invalid());
            }
            let Some(entry) = evidence.entries.get(&(device, sequence)) else {
                return Ok(false);
            };
            if entry.hash.0 != bytes[24..56] {
                return Err(invalid());
            }
            frontier.insert(device, sequence);
            covered
                .entry(device)
                .and_modify(|n| *n = (*n).max(sequence))
                .or_insert(sequence);
        }
        let checkpoint = checked(decode_checkpoint_v1(&bytes))?;
        if checkpoint.causal_frontier.iter().any(|head| {
            frontier
                .get(&head.device_id)
                .is_none_or(|n| *n < head.sequence)
        }) {
            return Err(invalid());
        }
    }
    Ok(true)
}

fn exact_selected(
    c: &Connection,
    stored: &Stored,
    target: RecoveryTargetV1,
    keys: &DeviceKeys,
    budget: HistoricalReconstructionBudget,
) -> Result<Vec<u8>, VaultError> {
    material::endpoint_check(
        stored,
        target.endpoint,
        target.recipient,
        keys,
        budget.transfer.history,
    )?;
    let hash:Vec<u8>=c.query_row("SELECT CASE WHEN length(target_sha256)=32 THEN target_sha256 END FROM recovery_history_selection WHERE singleton=1",[],|r|r.get(0))?;
    if hash != digest(&target.canonical_bytes()).0 {
        return Err(VaultError::OperationConflict);
    }
    let (saved, checkpoint) = load_target(
        c,
        stored,
        Sha256Digest(hash.try_into().map_err(|_| invalid())?),
        budget,
    )?;
    if saved != target {
        return Err(VaultError::OperationConflict);
    }
    Ok(checkpoint)
}

fn inventory(
    c: &Connection,
    stored: &Stored,
    target: RecoveryTargetV1,
    keys: &DeviceKeys,
    budget: HistoricalReconstructionBudget,
    retain: bool,
) -> Result<Option<BTreeMap<u32, ContentKey>>, VaultError> {
    use crate::devices::recovery_restore_crypto::v2::open_recovery_history_key;
    let prepared = super::super::super::recovery_v2::load(c, keys)?.ok_or_else(invalid)?;
    super::super::recovery::receipt(c, &prepared, keys)?.ok_or_else(invalid)?;
    if digest(&prepared.canonical_claim) != target.claim_sha256 {
        return Err(invalid());
    }
    let r = MembershipEndpoint {
        state_sha256: target.admission,
        control_epoch: prepared.claim.certificate.control_epoch,
        key_epoch: prepared.claim.key_epoch,
    };
    let lineage = material::lineage(stored, r, budget.transfer.history)?;
    let root = checked(
        crate::devices::recovery_crypto::decode_recovery_enrollment_record_v1(
            &prepared.canonical_record,
        ),
    )?;
    let supplemental = supplemental_keys(c, stored, &prepared, keys, budget)?;
    for retained in prepared.history_keys.iter().chain(&supplemental) {
        let bundle = checked(open_recovery_history_key(
            &root,
            &prepared.claim,
            &prepared.parent,
            &lineage,
            retained,
            keys,
        ))?;
        if retain {
            material::retain(
                c,
                stored,
                target.recipient,
                &bundle,
                false,
                target.claim_sha256,
                keys,
                budget.transfer.history,
            )?;
        }
    }
    let mut content = BTreeMap::new();
    if stored.endpoint.key_epoch as usize > budget.transfer.history.max_events.saturating_add(1) {
        return Err(VaultError::BudgetExceeded);
    }
    for epoch in 1..=stored.endpoint.key_epoch {
        let Some(bundle) = material::load_secret(
            c,
            stored,
            target.recipient,
            epoch,
            epoch == stored.endpoint.key_epoch,
            keys,
            budget.transfer.history,
        )?
        else {
            return Ok(None);
        };
        content.insert(epoch, ContentKey::from_bytes(*bundle.active_epoch_key()));
    }
    Ok(Some(content))
}

fn reconstruct_recovery(
    tx: &Transaction<'_>,
    target: RecoveryTargetV1,
    keys: &DeviceKeys,
    budget: HistoricalReconstructionBudget,
    embeddings: &impl RepresentativeEmbeddingResolver,
) -> Result<Option<Reconstructed>, VaultError> {
    let stored = load(tx, budget.transfer.history)?.ok_or_else(invalid)?;
    let bytes = exact_selected(tx, &stored, target, keys, budget)?;
    let checkpoint = checkpoint(&stored, &bytes, target.checkpoint_sha256, budget)?;
    let Some(proof) = authenticate_target(tx, &stored, &checkpoint, target.recipient, budget)?
    else {
        return Ok(None);
    };
    let Some(content) = inventory(tx, &stored, target, keys, budget, true)? else {
        return Ok(None);
    };
    let Some(reconstructed) =
        reconstruct_verified_target(tx, &stored, &checkpoint, proof, content, embeddings)?
    else {
        return Ok(None);
    };
    let signature = keys.sign_hosted_device_proof(&reconstruction_preimage(
        target,
        &reconstructed.prefixes,
        false,
    ));
    tx.execute("UPDATE recovery_history_targets SET prefixes=?1,reconstructed_signature=?2 WHERE target_sha256=?3",params![&reconstructed.prefixes,signature.0.as_slice(),digest(&target.canonical_bytes()).0.as_slice()])?;
    target_storage(tx, budget)?;
    Ok(Some(reconstructed))
}

impl Vault {
    /// Authenticated staged pages remain repairable if final authorization denies the receipt.
    #[allow(clippy::too_many_arguments)]
    pub fn reconstruct_recovery_history_authorized(
        &mut self,
        target: RecoveryTargetV1,
        operations: &[Vec<u8>],
        keys: &DeviceKeys,
        budget: HistoricalReconstructionBudget,
        embeddings: &impl RepresentativeEmbeddingResolver,
        authorize: impl Fn() -> Result<(), VaultError>,
    ) -> Result<Option<RecoveryHistoricalReconstruction>, VaultError> {
        let budget = cap_budget(budget);
        self.stage_historical_operations(
            target.endpoint,
            target.recipient,
            operations,
            keys,
            budget,
        )?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = reconstruct_recovery(&tx, target, keys, budget, embeddings)?;
        authorize()?;
        tx.commit()?;
        Ok(result.map(|_| RecoveryHistoricalReconstruction { target }))
    }

    pub fn reconstruct_recovery_history(
        &mut self,
        target: RecoveryTargetV1,
        operations: &[Vec<u8>],
        keys: &DeviceKeys,
        budget: HistoricalReconstructionBudget,
        embeddings: &impl RepresentativeEmbeddingResolver,
    ) -> Result<Option<RecoveryHistoricalReconstruction>, VaultError> {
        self.reconstruct_recovery_history_authorized(
            target,
            operations,
            keys,
            budget,
            embeddings,
            || Ok(()),
        )
    }

    /// Authorize after all transactional writes; publish cache updates only after commit.
    #[allow(clippy::too_many_arguments)]
    pub fn install_recovery_history_authorized(
        &mut self,
        proof: &RecoveryHistoricalReconstruction,
        keys: &DeviceKeys,
        budget: HistoricalReconstructionBudget,
        embeddings: &impl RepresentativeEmbeddingResolver,
        authorize: impl Fn() -> Result<(), VaultError>,
    ) -> Result<bool, VaultError> {
        let budget = cap_budget(budget);
        let target = proof.target;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let Some(reconstructed) = reconstruct_recovery(&tx, target, keys, budget, embeddings)?
        else {
            return Ok(false);
        };
        let stored = load(&tx, budget.transfer.history)?.ok_or_else(invalid)?;
        let updates =
            install_reconstructed(&tx, &stored, target.recipient, &reconstructed, embeddings)?;
        let signature = keys.sign_hosted_device_proof(&reconstruction_preimage(
            target,
            &reconstructed.prefixes,
            true,
        ));
        tx.execute(
            "UPDATE recovery_history_targets SET installed_signature=?1 WHERE target_sha256=?2",
            params![
                signature.0.as_slice(),
                digest(&target.canonical_bytes()).0.as_slice()
            ],
        )?;
        target_storage(&tx, budget)?;
        activation::activate(
            &tx,
            target.endpoint,
            target.recipient,
            keys,
            budget.transfer.history,
        )?;
        authorize()?;
        tx.commit()?;
        for update in updates {
            self.apply_sync_cache_update(update);
        }
        Ok(true)
    }

    pub fn install_recovery_history(
        &mut self,
        proof: &RecoveryHistoricalReconstruction,
        keys: &DeviceKeys,
        budget: HistoricalReconstructionBudget,
        embeddings: &impl RepresentativeEmbeddingResolver,
    ) -> Result<bool, VaultError> {
        self.install_recovery_history_authorized(proof, keys, budget, embeddings, || Ok(()))
    }

    pub fn recovery_history_is_installed(
        &self,
        target: RecoveryTargetV1,
        keys: &DeviceKeys,
        budget: HistoricalReconstructionBudget,
    ) -> Result<bool, VaultError> {
        let budget = cap_budget(budget);
        let tx = self.connection.unchecked_transaction()?;
        let stored = load(&tx, budget.transfer.history)?.ok_or_else(invalid)?;
        let bytes = exact_selected(&tx, &stored, target, keys, budget)?;
        let installed = installed_receipt(&tx, &stored, target, &bytes, keys, budget)?;
        if !installed {
            return Ok(false);
        }
        if inventory(&tx, &stored, target, keys, budget, false)?.is_none() {
            return Ok(false);
        }
        activation::current_material(&tx, keys)?.ok_or_else(invalid)?;
        tx.commit()?;
        Ok(installed)
    }
}

// Historical completion is a read-only fact. Installation retains exact_selected/CAS.
fn installed_receipt(
    c: &Connection,
    stored: &Stored,
    target: RecoveryTargetV1,
    bytes: &[u8],
    keys: &DeviceKeys,
    budget: HistoricalReconstructionBudget,
) -> Result<bool, VaultError> {
    let row=c.query_row("SELECT installed_signature IS NOT NULL,CASE WHEN length(prefixes)<=?2 THEN prefixes END,CASE WHEN length(installed_signature)=64 THEN installed_signature END,CASE WHEN length(reconstructed_signature)=64 THEN reconstructed_signature END FROM recovery_history_targets WHERE target_sha256=?1",params![digest(&target.canonical_bytes()).0.as_slice(),budget.max_operation_bytes.min(64*1024*1024) as i64],|r|Ok((r.get::<_,bool>(0)?,r.get::<_,Option<Vec<u8>>>(1)?,r.get::<_,Option<Vec<u8>>>(2)?,r.get::<_,Option<Vec<u8>>>(3)?)))?;
    if !row.0 {
        return Ok(false);
    }
    let saved = row.1.ok_or_else(invalid)?;
    for (signature, installed) in [(row.2, true), (row.3, false)] {
        checked(crate::crypto::verify_signature(
            keys.signing_public_key(),
            &reconstruction_preimage(target, &saved, installed),
            Ed25519SignatureBytes(
                signature
                    .ok_or_else(invalid)?
                    .try_into()
                    .map_err(|_| invalid())?,
            ),
        ))?;
    }
    for epoch in 1..=target.endpoint.key_epoch {
        if material::load_secret(
            c,
            stored,
            target.recipient,
            epoch,
            epoch == target.endpoint.key_epoch,
            keys,
            budget.transfer.history,
        )?
        .is_none()
        {
            return Ok(false);
        }
    }
    let selected_index = stored
        .events
        .iter()
        .position(|e| e.successor == target.endpoint.state_sha256)
        .ok_or_else(invalid)?;
    let selected = Stored {
        scope: stored.scope,
        pin: stored.pin,
        enrollment: stored.enrollment.clone(),
        endpoint: target.endpoint,
        events: stored.events[..=selected_index].to_vec(),
    };
    let checkpoint = checkpoint(&selected, bytes, target.checkpoint_sha256, budget)?;
    let mut evidence = authenticate(stored, load_evidence(c, budget)?, budget)?;
    // Later revocations cannot manufacture a different receipt for an already installed target.
    evidence.cutoffs = authenticate(&selected, BTreeMap::new(), budget)?.cutoffs;
    if prefixes(&evidence, &checkpoint.causal_frontier, budget)?.as_ref() != Some(&saved) {
        return Ok(false);
    }
    let operations = checkpoint
        .causal_frontier
        .iter()
        .flat_map(|head| {
            (1..=head.sequence)
                .map(|sequence| &evidence.entries[&(head.device_id, sequence)].operation)
        })
        .collect::<Vec<_>>();
    representative::authenticate_installed_operations(c, stored, target.recipient, &operations)?;
    Ok(true)
}
