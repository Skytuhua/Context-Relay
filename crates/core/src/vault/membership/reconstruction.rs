use super::*;
mod recovery;
mod representative;
use crate::{
    crypto::{ContentKey, DeviceCertificateV1},
    sync::{AdmittedOperation, OperationChainHead, RepresentativeEmbeddingResolver},
};
use context_relay_protocol::{
    DeviceId, DeviceSequence, RecordMutationV1, SyncOperationV1, decode_checkpoint_v1,
    decode_sync_operation_v1, encode_sync_operation_v1,
};
pub use recovery::{RecoveryHistoricalReconstruction, RecoveryTargetV1};
pub use representative::HistoricalReadMaterial;
pub(in crate::vault) use representative::read_material;
use rusqlite::{OptionalExtension, Transaction};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Copy)]
/// Explicit aggregate limits for durable candidates, verified chains and isolated replay.
/// Installation and completion additionally authenticate live provenance under the private
/// reader's fixed limits: 100,000 rows, 64 MiB and 1,000,000 dependencies. These separate
/// bounded reads may reject larger live vaults and are repeated for affected operations.
pub struct HistoricalReconstructionBudget {
    pub transfer: HistoricalTransferBudget,
    pub max_operations: usize,
    pub max_operation_bytes: usize,
    pub max_dependencies: usize,
}
/// Exact target reconstructed from authenticated operations. Installation rechecks every gate.
///
/// ```compile_fail
/// use context_relay_core::vault::HistoricalReconstruction;
/// let proof = HistoricalReconstruction { selection: panic!() };
/// ```
pub struct HistoricalReconstruction {
    selection: HistoricalTransferSelection,
}
impl HistoricalReconstruction {
    pub fn selection(&self) -> HistoricalTransferSelection {
        self.selection
    }
}
impl Vault {
    /// Reauthenticate the durable completion receipt and installed chain evidence after restart.
    pub fn historical_transfer_is_installed(
        &self,
        selected: HistoricalTransferSelection,
        confirmed: &ConfirmedV2Transcript,
        signature: Ed25519SignatureBytes,
        keys: &DeviceKeys,
        budget: HistoricalReconstructionBudget,
    ) -> Result<bool, VaultError> {
        let tx = self.connection.unchecked_transaction()?;
        let (progress, _) = Self::replay_historical_transfer_tx(
            &tx,
            selected,
            confirmed,
            signature,
            None,
            keys,
            budget.transfer,
        )?;
        if !progress.inventory_verified {
            return Ok(false);
        }
        let stored = load(&tx, budget.transfer.history)?.ok_or_else(invalid)?;
        let t = material::load_transfer(&tx, selected.transfer_id, budget.transfer)?
            .ok_or_else(invalid)?;
        let device = t.header.context.recipient_device_id;
        material::endpoint_check(
            &stored,
            selected.authorizing_endpoint,
            device,
            keys,
            budget.transfer.history,
        )?;
        if material::selection(&tx, device, budget.transfer)? != Some(selected) {
            return Err(VaultError::OperationConflict);
        }
        let row=tx.query_row("SELECT CASE WHEN length(prefixes)<=?2 THEN prefixes END,CASE WHEN length(installed_signature)=64 THEN installed_signature END FROM historical_reconstructions WHERE transfer_id=?1",params![selected.transfer_id.to_string(),budget.max_operation_bytes as i64],|r|Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,Option<Vec<u8>>>(1)?))).optional()?;
        let Some((saved, Some(signature))) = row else {
            return Ok(false);
        };
        let mut preimage = receipt_preimage(&stored, &t, &saved);
        preimage.extend(b"installed");
        checked(crate::crypto::verify_signature(
            keys.signing_public_key(),
            &preimage,
            Ed25519SignatureBytes(signature.try_into().map_err(|_| invalid())?),
        ))?;
        activation::current_material(&tx, keys)?.ok_or_else(invalid)?;
        let checkpoint = checked(decode_checkpoint_v1(&t.checkpoint))?;
        let evidence = authenticate(&stored, load_evidence(&tx, budget)?, budget)?;
        if !saved_prefixes(&tx, &stored, &evidence, device, budget)? {
            return Ok(false);
        }
        if prefixes(&evidence, &checkpoint.causal_frontier, budget)?.as_ref() != Some(&saved) {
            return Ok(false);
        }
        for head in &checkpoint.causal_frontier {
            for seq in 1..=head.sequence {
                let entry = &evidence.entries[&(head.device_id, seq)];
                representative::authenticate_local_operation(
                    &tx,
                    &stored,
                    device,
                    &entry.operation,
                    false,
                )?;
            }
        }
        tx.commit()?;
        Ok(true)
    }
    #[allow(clippy::too_many_arguments)]
    /// Causally merge a reconstructed target into live state and atomically mark installation.
    /// Missing inventory or chain evidence returns `false`; no live or cache changes commit.
    pub fn install_historical_transfer(
        &mut self,
        proof: &HistoricalReconstruction,
        confirmed: &ConfirmedV2Transcript,
        signature: Ed25519SignatureBytes,
        keys: &DeviceKeys,
        budget: HistoricalReconstructionBudget,
        embeddings: &impl RepresentativeEmbeddingResolver,
    ) -> Result<bool, VaultError> {
        let selected = proof.selection;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Replay every trust, inventory and target gate in the same installation transaction.
        let Some(reconstructed) = reconstruct(
            &tx, selected, confirmed, signature, keys, budget, embeddings,
        )?
        else {
            return Ok(false);
        };
        let stored = load(&tx, budget.transfer.history)?.ok_or_else(invalid)?;
        let device = confirmed.payload().grant.certificate.device_id;
        let updates = install_reconstructed(&tx, &stored, device, &reconstructed, embeddings)?;
        let t = material::load_transfer(&tx, selected.transfer_id, budget.transfer)?
            .ok_or_else(invalid)?;
        let mut preimage = receipt_preimage(&stored, &t, &reconstructed.prefixes);
        preimage.extend(b"installed");
        let installed = keys.sign_hosted_device_proof(&preimage);
        tx.execute(
            "UPDATE historical_reconstructions SET installed_signature=?1 WHERE transfer_id=?2",
            params![installed.0.as_slice(), selected.transfer_id.to_string()],
        )?;
        activation::activate(
            &tx,
            selected.authorizing_endpoint,
            confirmed.payload().grant.certificate.device_id,
            keys,
            budget.transfer.history,
        )?;
        tx.commit()?;
        for update in updates {
            self.apply_sync_cache_update(update);
        }
        Ok(true)
    }
    #[allow(clippy::too_many_arguments)]
    /// Select one explicit candidate branch, replay the exact target, and pin verified evidence.
    /// `None` means repairable missing inventory/chain/cutoff evidence. A signed checkpoint
    /// assertion alone is insufficient. Existing V1 bytes prove exact certificate/epoch authority
    /// on accepted lineage; they do not distinguish ordering around a same-epoch ADD.
    pub fn reconstruct_historical_transfer(
        &mut self,
        selected: HistoricalTransferSelection,
        confirmed: &ConfirmedV2Transcript,
        signature: Ed25519SignatureBytes,
        operations: &[Vec<u8>],
        keys: &DeviceKeys,
        budget: HistoricalReconstructionBudget,
        embeddings: &impl RepresentativeEmbeddingResolver,
    ) -> Result<Option<HistoricalReconstruction>, VaultError> {
        let device = confirmed.payload().grant.certificate.device_id;
        self.stage_historical_operations(
            selected.authorizing_endpoint,
            device,
            operations,
            keys,
            budget,
        )?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = reconstruct(
            &tx, selected, confirmed, signature, keys, budget, embeddings,
        )?;
        tx.commit()?;
        Ok(result.map(|_| HistoricalReconstruction {
            selection: selected,
        }))
    }

    /// Collect bounded canonical signed repair evidence without changing the selected read target.
    /// Supplied branches replace conflicting provisional candidates. Cache pressure may evict
    /// provisional bytes; already reconstructed prefixes and installed operations remain intact.
    pub fn stage_historical_operations(
        &mut self,
        expected: MembershipEndpoint,
        device: DeviceId,
        operations: &[Vec<u8>],
        keys: &DeviceKeys,
        budget: HistoricalReconstructionBudget,
    ) -> Result<(), VaultError> {
        let bytes = operations
            .iter()
            .try_fold(0usize, |n, b| n.checked_add(b.len()))
            .ok_or(VaultError::BudgetExceeded)?;
        if operations.len() > budget.max_operations || bytes > budget.max_operation_bytes {
            return Err(VaultError::BudgetExceeded);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored = load(&tx, budget.transfer.history)?.ok_or_else(invalid)?;
        material::endpoint_check(&stored, expected, device, keys, budget.transfer.history)?;
        let (count,size):(i64,i64)=tx.query_row("SELECT count(*),COALESCE(sum(length(canonical)),0) FROM (SELECT canonical FROM historical_operation_evidence UNION ALL SELECT canonical FROM historical_verified_operations)",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
        if count < 0
            || size < 0
            || (count as usize).saturating_add(operations.len()) > budget.max_operations
            || (size as usize).saturating_add(bytes) > budget.max_operation_bytes
        {
            // A full untrusted candidate cache must never block a correct bounded repair.
            tx.execute("DELETE FROM historical_operation_evidence", [])?;
        }
        stage_candidates(&tx, operations, budget)?;
        // Recheck aggregate limits before allocating/replaying newly collected evidence.
        let evidence = match load_evidence(&tx, budget) {
            Ok(evidence) => evidence,
            Err(VaultError::BudgetExceeded) => {
                // Dependency pressure is also cache pressure. Retry only the explicitly
                // supplied branch with immutable verified pins; never evict trusted proof.
                tx.execute("DELETE FROM historical_operation_evidence", [])?;
                stage_candidates(&tx, operations, budget)?;
                load_evidence(&tx, budget)?
            }
            Err(error) => return Err(error),
        };
        authenticate(&stored, evidence, budget)?;
        tx.commit()?;
        Ok(())
    }
}

fn stage_candidates(
    tx: &Transaction<'_>,
    operations: &[Vec<u8>],
    budget: HistoricalReconstructionBudget,
) -> Result<(), VaultError> {
    let mut chosen = BTreeMap::new();
    let mut ids = BTreeMap::new();
    for raw in operations {
        let entry = decode_entry(raw)?;
        let index = (entry.operation.device_id, entry.operation.device_sequence);
        if chosen.insert(index, raw).is_some_and(|old| old != raw) {
            return Err(VaultError::OperationConflict);
        }
        if ids
            .insert(entry.operation.operation_id, raw)
            .is_some_and(|old| old != raw)
        {
            return Err(VaultError::OperationConflict);
        }
        let pinned:Option<Vec<u8>>=tx.query_row("SELECT CASE WHEN length(canonical)<=?4 THEN canonical END FROM historical_verified_operations WHERE operation_id=?1 OR (device_id=?2 AND device_sequence=?3) LIMIT 1",params![entry.operation.operation_id.to_string(),index.0.to_string(),index.1.to_string(),budget.max_operation_bytes.min(i64::MAX as usize) as i64],|r|r.get(0)).optional()?;
        if let Some(pinned) = pinned {
            if pinned != *raw {
                return Err(VaultError::OperationConflict);
            }
            continue;
        }
        tx.execute("DELETE FROM historical_operation_evidence WHERE operation_id=?1 OR (device_id=?2 AND device_sequence=?3)",params![entry.operation.operation_id.to_string(),index.0.to_string(),index.1.to_string()])?;
        tx.execute("INSERT INTO historical_operation_evidence(operation_id,device_id,device_sequence,canonical) VALUES(?1,?2,?3,?4)",params![entry.operation.operation_id.to_string(),index.0.to_string(),index.1.to_string(),raw])?;
    }
    Ok(())
}

struct Entry {
    operation: SyncOperationV1,
    bytes: Vec<u8>,
    hash: Sha256Digest,
    certificate: Option<DeviceCertificateV1>,
}
type Evidence = BTreeMap<(DeviceId, u64), Entry>;
fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest(Sha256::digest(bytes).into())
}
fn checked<T, E>(v: Result<T, E>) -> Result<T, VaultError> {
    v.map_err(|_| invalid())
}
fn decode_entry(raw: &[u8]) -> Result<Entry, VaultError> {
    let operation = checked(decode_sync_operation_v1(raw))?;
    if checked(encode_sync_operation_v1(&operation))? != raw {
        return Err(invalid());
    }
    Ok(Entry {
        operation,
        bytes: raw.to_vec(),
        hash: digest(raw),
        certificate: None,
    })
}
fn load_evidence(
    c: &Connection,
    budget: HistoricalReconstructionBudget,
) -> Result<Evidence, VaultError> {
    let (count,bytes):(i64,i64)=c.query_row("SELECT count(*),COALESCE(sum(length(canonical)),0) FROM (SELECT canonical FROM historical_operation_evidence UNION ALL SELECT canonical FROM historical_verified_operations)",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
    if usize::try_from(count)
        .ok()
        .is_none_or(|n| n > budget.max_operations)
        || usize::try_from(bytes)
            .ok()
            .is_none_or(|n| n > budget.max_operation_bytes)
    {
        return Err(VaultError::BudgetExceeded);
    }
    let mut query=c.prepare("SELECT CASE WHEN length(operation_id)=36 THEN operation_id END,CASE WHEN length(device_id)=36 THEN device_id END,CASE WHEN length(device_sequence) BETWEEN 1 AND 20 THEN device_sequence END,canonical FROM historical_operation_evidence UNION ALL SELECT CASE WHEN length(operation_id)=36 THEN operation_id END,CASE WHEN length(device_id)=36 THEN device_id END,CASE WHEN length(device_sequence) BETWEEN 1 AND 20 THEN device_sequence END,canonical FROM historical_verified_operations")?;
    let mut rows = query.query([])?;
    let mut evidence = BTreeMap::new();
    let mut operation_ids = BTreeSet::new();
    let mut dependencies = 0usize;
    while let Some(row) = rows.next()? {
        let raw: Vec<u8> = row.get(3)?;
        let entry = decode_entry(&raw)?;
        if row.get::<_, String>(0)? != entry.operation.operation_id.to_string()
            || row.get::<_, String>(1)? != entry.operation.device_id.to_string()
            || row.get::<_, String>(2)? != entry.operation.device_sequence.to_string()
        {
            return Err(invalid());
        }
        dependencies = dependencies
            .checked_add(entry.operation.causal_frontier.len())
            .ok_or(VaultError::BudgetExceeded)?;
        if dependencies > budget.max_dependencies {
            return Err(VaultError::BudgetExceeded);
        }
        if !operation_ids.insert(entry.operation.operation_id) {
            return Err(invalid());
        }
        if evidence
            .insert(
                (entry.operation.device_id, entry.operation.device_sequence),
                entry,
            )
            .is_some()
        {
            return Err(invalid());
        }
    }
    Ok(evidence)
}
struct AuthenticatedEvidence {
    entries: Evidence,
    cutoffs: BTreeMap<DeviceId, (u64, Sha256Digest)>,
}
fn authenticate(
    stored: &Stored,
    mut entries: Evidence,
    budget: HistoricalReconstructionBudget,
) -> Result<AuthenticatedEvidence, VaultError> {
    let mut cutoffs = BTreeMap::new();
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
            |history, event| {
                for entry in entries.values_mut() {
                    let op = &entry.operation;
                    if (
                        op.account_id,
                        op.workspace_id,
                        op.control_epoch,
                        op.key_epoch,
                    ) == (
                        stored.scope.account_id,
                        stored.scope.workspace_id,
                        history.endpoint().control_epoch,
                        history.endpoint().key_epoch,
                    ) && let Some(cert) = history.state().active_devices.get(&op.device_id)
                    {
                        if entry.certificate.as_ref().is_some_and(|old| old != cert) {
                            return Err(crate::crypto::CryptoError::AuthenticationFailed);
                        }
                        entry.certificate = Some(cert.clone());
                    }
                }
                if let Some(MembershipHistoryEvent::Revocation { statement, .. }) = event {
                    let s = DeviceRevocationStatementV1::from_signing_preimage(statement)?;
                    cutoffs.insert(s.target_device_id, (s.cutoff_sequence, s.cutoff_hash));
                }
                Ok(())
            },
        ),
    )?;
    for e in entries.values() {
        let cert = e.certificate.as_ref().ok_or_else(invalid)?;
        let op = &e.operation;
        checked(crate::crypto::verify_signature(
            cert.signing_public_key,
            &checked(context_relay_protocol::encode_sync_operation_signing_preimage_v1(op))?,
            op.signature,
        ))?;
        if op.created_hlc.node != op.device_id
            || digest(op.ciphertext.as_slice()) != op.ciphertext_hash
            || op.device_sequence == 0
        {
            return Err(invalid());
        }
    }
    Ok(AuthenticatedEvidence { entries, cutoffs })
}

/// Complete signed chains and causal closure. Missing evidence is repairable.
fn prefixes(
    evidence: &AuthenticatedEvidence,
    frontier: &[DeviceSequence],
    budget: HistoricalReconstructionBudget,
) -> Result<Option<Vec<u8>>, VaultError> {
    Ok(verified_ranges(evidence, frontier, budget)?.map(|ranges| prefix_bytes(evidence, &ranges)))
}

// Historical completion checks existing obligations; ordinary reconstruction still requires
// the full current cutoff. This policy is private to the authenticated local read boundary.
#[derive(Clone, Copy)]
enum CutoffClosure {
    Current,
    RetainedLocal,
}

fn verified_ranges(
    evidence: &AuthenticatedEvidence,
    frontier: &[DeviceSequence],
    budget: HistoricalReconstructionBudget,
) -> Result<Option<BTreeMap<DeviceId, u64>>, VaultError> {
    verified_ranges_with_cutoff(evidence, frontier, budget, CutoffClosure::Current)
}

fn verified_ranges_with_cutoff(
    evidence: &AuthenticatedEvidence,
    frontier: &[DeviceSequence],
    budget: HistoricalReconstructionBudget,
    closure: CutoffClosure,
) -> Result<Option<BTreeMap<DeviceId, u64>>, VaultError> {
    if frontier
        .windows(2)
        .any(|p| p[0].device_id >= p[1].device_id)
        || frontier.iter().any(|e| e.sequence == 0)
    {
        return Err(invalid());
    }
    let mut required = frontier
        .iter()
        .map(|e| (e.device_id, e.sequence))
        .collect::<BTreeMap<_, _>>();
    loop {
        let before = required.clone();
        for (device, sequence) in &before {
            if let Some((cutoff, _)) = evidence.cutoffs.get(device) {
                if sequence > cutoff {
                    return Err(invalid());
                }
                if matches!(closure, CutoffClosure::Current) {
                    required.insert(*device, *cutoff);
                }
            }
        }
        let total = required
            .values()
            .try_fold(0u64, |n, s| n.checked_add(*s))
            .ok_or(VaultError::BudgetExceeded)?;
        if total > budget.max_operations as u64 {
            return Err(VaultError::BudgetExceeded);
        }
        for (device, sequence) in &required.clone() {
            let mut previous = None;
            for seq in 1..=*sequence {
                let Some(e) = evidence.entries.get(&(*device, seq)) else {
                    return Ok(None);
                };
                if e.operation.previous_device_hash
                    != previous.map_or(Sha256Digest([0; 32]), |p: OperationChainHead| {
                        p.canonical_hash
                    })
                {
                    return Err(invalid());
                }
                if seq > 1
                    && let Some(old) = evidence.entries.get(&(*device, seq - 1))
                    && (old.operation.control_epoch > e.operation.control_epoch
                        || old.operation.key_epoch > e.operation.key_epoch)
                {
                    return Err(invalid());
                }
                previous = Some(OperationChainHead {
                    sequence: seq,
                    canonical_hash: e.hash,
                });
                for dep in &e.operation.causal_frontier {
                    if dep.sequence == 0 || (dep.device_id == *device && dep.sequence >= seq) {
                        return Err(invalid());
                    }
                    required
                        .entry(dep.device_id)
                        .and_modify(|n| *n = (*n).max(dep.sequence))
                        .or_insert(dep.sequence);
                }
            }
            if let Some((cutoff, hash)) = evidence.cutoffs.get(device)
                && *sequence == *cutoff
                && previous.map_or(Sha256Digest([0; 32]), |p| p.canonical_hash) != *hash
            {
                return Err(invalid());
            }
        }
        if before == required {
            break;
        }
    }
    let mut applied: BTreeMap<DeviceId, u64> = BTreeMap::new();
    while applied != required {
        let mut progress = false;
        for (device, end) in &required {
            let sequence = applied.get(device).copied().unwrap_or(0) + 1;
            if sequence > *end {
                continue;
            }
            let op = &evidence.entries[&(*device, sequence)].operation;
            if op
                .causal_frontier
                .iter()
                .all(|dep| applied.get(&dep.device_id).copied().unwrap_or(0) >= dep.sequence)
            {
                applied.insert(*device, sequence);
                progress = true;
            }
        }
        if !progress {
            return Err(invalid());
        }
    }
    Ok(Some(required))
}

fn prefix_bytes(evidence: &AuthenticatedEvidence, frontier: &BTreeMap<DeviceId, u64>) -> Vec<u8> {
    let mut result = Vec::with_capacity(frontier.len() * 56);
    for (device, sequence) in frontier {
        result.extend(device.as_bytes());
        result.extend(sequence.to_be_bytes());
        result.extend(evidence.entries[&(*device, *sequence)].hash.0);
    }
    result
}

/// Revalidate every recipient-signed proof obligation, including prerequisites outside targets.
/// Candidates may repair missing bytes, but neither candidates nor raw verified rows create pins.
fn saved_prefixes(
    c: &Connection,
    stored: &Stored,
    evidence: &AuthenticatedEvidence,
    device: DeviceId,
    budget: HistoricalReconstructionBudget,
) -> Result<bool, VaultError> {
    saved_prefixes_with_cutoff(c, stored, evidence, device, budget, CutoffClosure::Current)
}

fn saved_prefixes_with_cutoff(
    c: &Connection,
    stored: &Stored,
    evidence: &AuthenticatedEvidence,
    device: DeviceId,
    budget: HistoricalReconstructionBudget,
    closure: CutoffClosure,
) -> Result<bool, VaultError> {
    let (count, bytes): (i64, i64) = c.query_row(
        "SELECT count(*),COALESCE(sum(length(r.transfer_id)+length(r.prefixes)+length(r.signature)+COALESCE(length(t.header),0)+COALESCE(length(t.checkpoint),0)),0) FROM historical_reconstructions r LEFT JOIN historical_transfers t ON t.transfer_id=r.transfer_id",
        [], |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if count < 0
        || bytes < 0
        || count as usize > budget.transfer.max_bytes
        || bytes as usize > budget.transfer.max_bytes
    {
        return Err(VaultError::BudgetExceeded);
    }
    let history = stored.verify(budget.transfer.history)?;
    let signing_key = history
        .state()
        .active_devices
        .get(&device)
        .ok_or_else(invalid)?
        .signing_public_key;
    let mut covered: BTreeMap<DeviceId, u64> = BTreeMap::new();
    let mut q = c.prepare("SELECT CASE WHEN length(transfer_id)=36 THEN transfer_id END,CASE WHEN length(prefixes)<=?1 THEN prefixes END,CASE WHEN length(signature)=64 THEN signature END FROM historical_reconstructions ORDER BY transfer_id")?;
    let mut rows = q.query([budget.transfer.max_bytes.min(i64::MAX as usize) as i64])?;
    while let Some(row) = rows.next()? {
        let id = row.get::<_, String>(0)?.parse().map_err(|_| invalid())?;
        let saved: Vec<u8> = row.get(1)?;
        let signature: Vec<u8> = row.get(2)?;
        let t = material::load_transfer(c, id, budget.transfer)?.ok_or_else(invalid)?;
        if t.header.context.recipient_device_id != device
            || !saved.chunks_exact(56).remainder().is_empty()
        {
            return Err(invalid());
        }
        let epoch = t
            .header
            .context
            .last_historical_key_epoch
            .checked_add(1)
            .ok_or_else(invalid)?;
        material::lineage(
            stored,
            MembershipEndpoint {
                state_sha256: t.header.context.authorizing_control_state_sha256,
                control_epoch: epoch,
                key_epoch: epoch,
            },
            budget.transfer.history,
        )?;
        checked(crate::crypto::verify_signature(
            signing_key,
            &receipt_preimage(stored, &t, &saved),
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
        let checkpoint = checked(decode_checkpoint_v1(&t.checkpoint))?;
        if checkpoint
            .causal_frontier
            .iter()
            .any(|h| frontier.get(&h.device_id).is_none_or(|n| *n < h.sequence))
        {
            return Err(invalid());
        }
    }
    if !recovery::cover_saved_prefixes(c, stored, evidence, device, budget, &mut covered)? {
        return Ok(false);
    }
    let frontier = covered
        .iter()
        .map(|(device, sequence)| DeviceSequence {
            device_id: *device,
            sequence: *sequence,
        })
        .collect::<Vec<_>>();
    if verified_ranges_with_cutoff(evidence, &frontier, budget, closure)?.is_none() {
        return Ok(false);
    }
    // A row marked verified must be inside an authenticated receipt's prefix. With no
    // transfer, an ordinary retained device's local applied/queued provenance remains valid.
    let mut q = c.prepare("SELECT CASE WHEN length(device_id)=36 THEN device_id END,CASE WHEN length(device_sequence) BETWEEN 1 AND 20 THEN device_sequence END FROM historical_verified_operations")?;
    let mut rows = q.query([])?;
    while let Some(row) = rows.next()? {
        let device: DeviceId = row.get::<_, String>(0)?.parse().map_err(|_| invalid())?;
        let sequence: u64 = row.get::<_, String>(1)?.parse().map_err(|_| invalid())?;
        if sequence == 0 || covered.get(&device).is_none_or(|n| sequence > *n) {
            return Err(invalid());
        }
    }
    Ok(true)
}

fn receipt_preimage(stored: &Stored, t: &material::Transfer, prefixes: &[u8]) -> Vec<u8> {
    let mut bytes = b"context-relay/reconstructed-historical-target/v1\0".to_vec();
    bytes.extend(stored.scope.account_id.as_bytes());
    bytes.extend(stored.scope.workspace_id.as_bytes());
    bytes.extend(stored.pin.0);
    bytes.extend(digest(&t.raw).0);
    bytes.extend(digest(&t.checkpoint).0);
    bytes.extend(prefixes);
    bytes
}
struct Reconstructed {
    operations: Vec<AdmittedOperation>,
    keys: BTreeMap<u32, ContentKey>,
    prefixes: Vec<u8>,
}
#[allow(clippy::too_many_arguments)]
fn reconstruct(
    tx: &Transaction<'_>,
    selected: HistoricalTransferSelection,
    confirmed: &ConfirmedV2Transcript,
    signature: Ed25519SignatureBytes,
    keys: &DeviceKeys,
    budget: HistoricalReconstructionBudget,
    embeddings: &impl RepresentativeEmbeddingResolver,
) -> Result<Option<Reconstructed>, VaultError> {
    let (progress, _) = Vault::replay_historical_transfer_tx(
        tx,
        selected,
        confirmed,
        signature,
        None,
        keys,
        budget.transfer,
    )?;
    if !progress.inventory_verified {
        return Ok(None);
    }
    let stored = load(tx, budget.transfer.history)?.ok_or_else(invalid)?;
    let device = confirmed.payload().grant.certificate.device_id;
    let current = material::load_secret(
        tx,
        &stored,
        device,
        stored.endpoint.key_epoch,
        true,
        keys,
        budget.transfer.history,
    )?;
    if current.is_none() {
        return Ok(None);
    }
    let t =
        material::load_transfer(tx, selected.transfer_id, budget.transfer)?.ok_or_else(invalid)?;
    let checkpoint = checked(decode_checkpoint_v1(&t.checkpoint))?;
    let Some(proof) = authenticate_target(tx, &stored, &checkpoint, device, budget)? else {
        return Ok(None);
    };
    let mut content_keys = BTreeMap::new();
    // Inventory is bounded by authenticated transfer pages, independent current separately.
    for epoch in 1..=stored.endpoint.key_epoch {
        let Some(bundle) = material::load_secret(
            tx,
            &stored,
            device,
            epoch,
            epoch == stored.endpoint.key_epoch,
            keys,
            budget.transfer.history,
        )?
        else {
            return Ok(None);
        };
        content_keys.insert(epoch, ContentKey::from_bytes(*bundle.active_epoch_key()));
    }
    let Some(reconstructed) =
        reconstruct_verified_target(tx, &stored, &checkpoint, proof, content_keys, embeddings)?
    else {
        return Ok(None);
    };
    let signature =
        keys.sign_hosted_device_proof(&receipt_preimage(&stored, &t, &reconstructed.prefixes));
    tx.execute("INSERT INTO historical_reconstructions(transfer_id,prefixes,signature) VALUES(?1,?2,?3) ON CONFLICT(transfer_id) DO UPDATE SET prefixes=excluded.prefixes,signature=excluded.signature",params![selected.transfer_id.to_string(),&reconstructed.prefixes,signature.0.as_slice()])?;
    Ok(Some(reconstructed))
}

// Only pairing/recovery private gates supply canonical authorized targets and opened keys.
// Signature/chain/cutoff/dependency/scratch-state verification remains shared here.
#[allow(clippy::too_many_arguments)]
struct VerifiedTargetEvidence {
    evidence: AuthenticatedEvidence,
    required: BTreeMap<DeviceId, u64>,
    prefixes: Vec<u8>,
}
fn authenticate_target(
    tx: &Transaction<'_>,
    stored: &Stored,
    checkpoint: &context_relay_protocol::CheckpointV1,
    device: DeviceId,
    budget: HistoricalReconstructionBudget,
) -> Result<Option<VerifiedTargetEvidence>, VaultError> {
    let evidence = authenticate(stored, load_evidence(tx, budget)?, budget)?;
    if !saved_prefixes(tx, stored, &evidence, device, budget)? {
        return Ok(None);
    }
    let Some(required) = verified_ranges(&evidence, &checkpoint.causal_frontier, budget)? else {
        return Ok(None);
    };
    let prefixes = prefix_bytes(&evidence, &required);
    Ok(Some(VerifiedTargetEvidence {
        evidence,
        required,
        prefixes,
    }))
}
#[allow(clippy::too_many_arguments)]
fn reconstruct_verified_target(
    tx: &Transaction<'_>,
    stored: &Stored,
    checkpoint: &context_relay_protocol::CheckpointV1,
    proof: VerifiedTargetEvidence,
    content_keys: BTreeMap<u32, ContentKey>,
    embeddings: &impl RepresentativeEmbeddingResolver,
) -> Result<Option<Reconstructed>, VaultError> {
    let VerifiedTargetEvidence {
        evidence,
        required,
        prefixes,
    } = proof;
    let target = checkpoint
        .causal_frontier
        .iter()
        .map(|h| (h.device_id, h.sequence))
        .collect::<BTreeMap<_, _>>();
    let mut pending = evidence
        .entries
        .values()
        .filter(|e| {
            target
                .get(&e.operation.device_id)
                .is_some_and(|s| e.operation.device_sequence <= *s)
        })
        .collect::<Vec<_>>();
    let mut scratch = Vault::reconstruction_workspace()?;
    let mut operations = Vec::new();
    let mut applied: BTreeMap<DeviceId, u64> = BTreeMap::new();
    // ponytail: bounded O(n²) ready scan; use a dependency queue if replay throughput warrants it.
    while !pending.is_empty() {
        let Some(index) = pending.iter().position(|e| {
            e.operation.device_sequence
                == applied.get(&e.operation.device_id).copied().unwrap_or(0) + 1
                && e.operation
                    .causal_frontier
                    .iter()
                    .all(|d| applied.get(&d.device_id).copied().unwrap_or(0) >= d.sequence)
        }) else {
            return Err(invalid());
        };
        let entry = pending.remove(index);
        if entry
            .operation
            .causal_frontier
            .iter()
            .any(|d| target.get(&d.device_id).copied().unwrap_or(0) < d.sequence)
        {
            return Err(invalid());
        }
        let key = content_keys
            .get(&entry.operation.key_epoch)
            .ok_or_else(invalid)?;
        let admitted = checked(AdmittedOperation::from_historical(
            &scratch,
            &entry.bytes,
            entry.certificate.as_ref().ok_or_else(invalid)?,
            key,
            stored.endpoint,
        ))?;
        let work = scratch.connection.transaction()?;
        let (_, update) = Vault::apply_verified_in_transaction(
            &work,
            &admitted,
            None,
            &|op| decrypt(op, &content_keys),
            embeddings,
            0,
            "1970-01-01T00:00:00Z",
        )?;
        work.commit()?;
        scratch.apply_sync_cache_update(update);
        applied.insert(entry.operation.device_id, entry.operation.device_sequence);
        operations.push(admitted);
    }
    if scratch.sync_checkpoint_frontier(stored.scope)? != checkpoint.causal_frontier
        || checked(scratch.sync_state_summary(stored.scope)?.state_hash())? != checkpoint.state_hash
    {
        return Err(invalid());
    }
    for entry in evidence.entries.values().filter(|e| {
        required
            .get(&e.operation.device_id)
            .is_some_and(|n| e.operation.device_sequence <= *n)
    }) {
        tx.execute("INSERT INTO historical_verified_operations(operation_id,device_id,device_sequence,canonical) VALUES(?1,?2,?3,?4) ON CONFLICT(operation_id) DO NOTHING",params![entry.operation.operation_id.to_string(),entry.operation.device_id.to_string(),entry.operation.device_sequence.to_string(),&entry.bytes])?;
        tx.execute(
            "DELETE FROM historical_operation_evidence WHERE operation_id=?1",
            [entry.operation.operation_id.to_string()],
        )?;
    }
    Ok(Some(Reconstructed {
        operations,
        keys: content_keys,
        prefixes,
    }))
}

fn install_reconstructed(
    tx: &Transaction<'_>,
    stored: &Stored,
    device: DeviceId,
    reconstructed: &Reconstructed,
    embeddings: &impl RepresentativeEmbeddingResolver,
) -> Result<Vec<super::super::sync::SyncCacheUpdate>, VaultError> {
    let mut updates = Vec::new();
    if !reconstructed.operations.is_empty() {
        representative::ensure_live_bounds(tx)?;
    }
    for operation in &reconstructed.operations {
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM operations WHERE id=?1)",
            [operation.operation().operation_id.to_string()],
            |r| r.get(0),
        )?;
        if exists {
            representative::authenticate_local_operation(
                tx,
                stored,
                device,
                operation.operation(),
                false,
            )?;
        }
        let (_, update) = Vault::apply_verified_in_transaction(
            tx,
            operation,
            None,
            &|op| {
                representative::authenticate_local_operation(tx, stored, device, op, true)?;
                decrypt(op, &reconstructed.keys)
            },
            embeddings,
            0,
            "1970-01-01T00:00:00Z",
        )?;
        if !exists {
            representative::authenticate_local_operation(
                tx,
                stored,
                device,
                operation.operation(),
                false,
            )?;
        }
        updates.push(update);
    }
    Ok(updates)
}

fn decrypt(
    op: &SyncOperationV1,
    keys: &BTreeMap<u32, ContentKey>,
) -> Result<RecordMutationV1, VaultError> {
    super::super::sync::rehydrate_mutation_with_key(
        op,
        keys.get(&op.key_epoch).ok_or_else(invalid)?,
    )
}

pub(super) fn require_target_extension(
    c: &Connection,
    stored: &Stored,
    previous: HistoricalTransferSelection,
    checkpoint: &[u8],
    keys: &DeviceKeys,
    budget: HistoricalTransferBudget,
) -> Result<(), VaultError> {
    material::lineage(stored, previous.authorizing_endpoint, budget.history)?;
    let old = material::load_transfer(c, previous.transfer_id, budget)?.ok_or_else(invalid)?;
    let prior = checked(decode_checkpoint_v1(&old.checkpoint))?;
    let next = checked(decode_checkpoint_v1(checkpoint))?;
    let exists: bool = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM historical_reconstructions WHERE transfer_id=?1)",
        [previous.transfer_id.to_string()],
        |r| r.get(0),
    )?;
    if !exists {
        return Err(VaultError::OperationConflict);
    }
    // Target domination is distinct from the larger signed cutoff/causal proof closure.
    for head in &prior.causal_frontier {
        if next
            .causal_frontier
            .iter()
            .find(|e| e.device_id == head.device_id)
            .is_none_or(|e| e.sequence < head.sequence)
        {
            return Err(invalid());
        }
    }
    let evidence_budget = HistoricalReconstructionBudget {
        transfer: budget,
        max_operations: budget.max_bytes,
        max_operation_bytes: budget.max_bytes,
        max_dependencies: budget.max_bytes,
    };
    let evidence = authenticate(stored, load_evidence(c, evidence_budget)?, evidence_budget)?;
    let device = old.header.context.recipient_device_id;
    material::endpoint_check(stored, stored.endpoint, device, keys, budget.history)?;
    if !saved_prefixes(c, stored, &evidence, device, evidence_budget)? {
        return Err(VaultError::OperationConflict);
    }
    prefixes(&evidence, &next.causal_frontier, evidence_budget)?
        .ok_or(VaultError::OperationConflict)?;
    Ok(())
}
