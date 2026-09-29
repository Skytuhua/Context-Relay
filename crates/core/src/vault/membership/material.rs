//! Private staging, deliberately separate from current-write activation.
use super::*;
use crate::{
    crypto::wrap_secret,
    devices::{
        crypto::{PairingKeyBundle, decode_pairing_key_bundle, encode_pairing_key_bundle},
        historical_crypto::{
            EpochOneTrust, HistoricalTransferAuthority, HistoricalTransferHeader, MAX_PAGE_BYTES,
        },
        membership_crypto::{
            VerifiedMembershipLineage, replay_membership_history, verify_membership_lineage,
        },
        recovery_crypto::{
            decode_recovery_device_envelope_v1, encode_recovery_device_envelope_v1,
            open_device_workspace_material,
        },
        revocation_crypto::RevocationTransitionV1,
    },
};
use context_relay_protocol::{DeviceId, OperationId};
use rusqlite::OptionalExtension;
use sha2::{Digest, Sha256};

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest(Sha256::digest(bytes).into())
}
fn crypto<T, E>(result: Result<T, E>) -> Result<T, VaultError> {
    result.map_err(|_| invalid())
}
pub(super) fn endpoint_check(
    stored: &Stored,
    expected: MembershipEndpoint,
    device: DeviceId,
    keys: &DeviceKeys,
    budget: MembershipHistoryBudget,
) -> Result<VerifiedMembershipHistory, VaultError> {
    let history = stored.verify(budget)?;
    let state = history.state();
    let cert = state.active_devices.get(&device).ok_or_else(invalid)?;
    if stored.endpoint != expected
        || cert.signing_public_key != keys.signing_public_key()
        || cert.wrapping_public_key != keys.wrapping_public_key()
    {
        return Err(VaultError::OperationConflict);
    }
    Ok(history)
}
pub(super) fn lineage(
    stored: &Stored,
    anchor: MembershipEndpoint,
    budget: MembershipHistoryBudget,
) -> Result<VerifiedMembershipLineage, VaultError> {
    crypto(verify_membership_lineage(
        &stored.enrollment,
        stored.pin,
        stored.scope,
        &stored
            .events
            .iter()
            .map(Event::evidence)
            .collect::<Vec<_>>(),
        anchor,
        stored.endpoint,
        budget,
    ))
}
fn secret_aad(
    stored: &Stored,
    device: DeviceId,
    epoch: u32,
    independent: bool,
    source: MembershipEndpoint,
    provenance: Sha256Digest,
) -> Vec<u8> {
    let mut aad = b"context-relay/staged-membership-secret/v1\0".to_vec();
    aad.extend(stored.scope.account_id.as_bytes());
    aad.extend(stored.scope.workspace_id.as_bytes());
    aad.extend(stored.pin.0);
    aad.extend(device.as_bytes());
    aad.extend(epoch.to_be_bytes());
    aad.push(u8::from(independent));
    aad.extend(source.state_sha256.0);
    aad.extend(source.control_epoch.to_be_bytes());
    aad.extend(source.key_epoch.to_be_bytes());
    aad.extend(provenance.0);
    aad
}
pub(super) fn load_secret(
    c: &Connection,
    stored: &Stored,
    device: DeviceId,
    epoch: u32,
    independent_only: bool,
    keys: &DeviceKeys,
    budget: MembershipHistoryBudget,
) -> Result<Option<PairingKeyBundle>, VaultError> {
    let row = c.query_row("SELECT independent_current,CASE WHEN length(source_hash)=32 THEN source_hash END,source_control_epoch,source_key_epoch,CASE WHEN length(provenance)=32 THEN provenance END,CASE WHEN length(envelope) BETWEEN 1 AND 512 THEN envelope END,CASE WHEN length(signature)=64 THEN signature END FROM membership_epoch_secrets WHERE device_id=?1 AND key_epoch=?2 AND independent_current>=?3 ORDER BY independent_current DESC LIMIT 1", params![device.to_string(),epoch,independent_only], |r| Ok((r.get::<_,bool>(0)?,r.get::<_,Vec<u8>>(1)?,r.get::<_,u32>(2)?,r.get::<_,u32>(3)?,r.get::<_,Vec<u8>>(4)?,r.get::<_,Vec<u8>>(5)?,r.get::<_,Vec<u8>>(6)?))).optional()?;
    let Some((independent, hash, control, key, provenance, envelope, signature)) = row else {
        return Ok(None);
    };
    let source = MembershipEndpoint {
        state_sha256: Sha256Digest(hash.try_into().map_err(|_| invalid())?),
        control_epoch: control,
        key_epoch: key,
    };
    // Every caller has reauthenticated Stored in this transaction. Reuse that
    // verified event stream rather than replaying every signature for each key.
    if source != stored.endpoint {
        if let Some(event) = stored
            .events
            .iter()
            .find(|e| e.successor == source.state_sha256)
        {
            let (control, key) = if event.request.is_some() {
                let s = crypto(DeviceMembershipAddStatementV1::from_signing_preimage(
                    &event.statement,
                ))?;
                (s.control_epoch, s.key_epoch)
            } else if event.statement.is_empty() {
                let claim = crypto(
                    crate::devices::recovery_restore_crypto::v2::decode_recovery_device_claim_v2(
                        &event.artifact,
                    ),
                )?;
                (claim.certificate.control_epoch, claim.key_epoch)
            } else {
                let t = crypto(RevocationTransitionV1::from_canonical_bytes(
                    &event.artifact,
                ))?;
                (t.control_epoch, t.key_epoch)
            };
            if (control, key) != (source.control_epoch, source.key_epoch) {
                return Err(invalid());
            }
        } else {
            crypto(verify_membership_history(
                &stored.enrollment,
                stored.pin,
                stored.scope,
                &[],
                source,
                budget,
            ))?;
        }
    }
    let provenance = Sha256Digest(provenance.try_into().map_err(|_| invalid())?);
    let aad = secret_aad(stored, device, epoch, independent, source, provenance);
    let mut signed = aad.clone();
    signed.extend(&envelope);
    crypto(crate::crypto::verify_signature(
        keys.signing_public_key(),
        &signed,
        Ed25519SignatureBytes(signature.try_into().map_err(|_| invalid())?),
    ))?;
    let envelope = crypto(decode_recovery_device_envelope_v1(&envelope))?;
    let plain = crypto(keys.unwrap_secret(&envelope, &aad))?;
    let bundle = crypto(decode_pairing_key_bundle(plain.expose()))?;
    if bundle.account_id() != stored.scope.account_id
        || bundle.workspace_id() != stored.scope.workspace_id
        || bundle.key_epoch() != epoch
        || bundle.enrollment_record_sha256() != Some(stored.pin)
        || crypto(encode_pairing_key_bundle(&bundle))?.as_slice() != plain.expose()
    {
        return Err(invalid());
    }
    if epoch == 1 {
        if bundle.control_epoch() != 1 {
            return Err(invalid());
        }
    } else {
        let mut commitment = None;
        for e in stored
            .events
            .iter()
            .filter(|e| e.request.is_none() && !e.statement.is_empty())
        {
            let transition = crypto(RevocationTransitionV1::from_canonical_bytes(&e.artifact))?;
            if transition.key_epoch == epoch {
                commitment = Some(transition);
                break;
            }
        }
        let commitment = commitment.ok_or_else(invalid)?;
        let original = crypto(PairingKeyBundle::new(
            stored.scope,
            bundle.control_epoch(),
            epoch,
            *bundle.workspace_root_key(),
            *bundle.active_epoch_key(),
        ))?;
        if commitment.control_epoch != bundle.control_epoch()
            || (digest(&crypto(encode_pairing_key_bundle(&bundle))?)
                != commitment.key_material_sha256
                && digest(&crypto(encode_pairing_key_bundle(&original))?)
                    != commitment.key_material_sha256)
        {
            return Err(invalid());
        }
    }
    Ok(Some(bundle))
}
#[allow(clippy::too_many_arguments)]
pub(super) fn retain(
    c: &Connection,
    stored: &Stored,
    device: DeviceId,
    bundle: &PairingKeyBundle,
    independent: bool,
    provenance: Sha256Digest,
    keys: &DeviceKeys,
    budget: MembershipHistoryBudget,
) -> Result<(), VaultError> {
    let bytes = crypto(encode_pairing_key_bundle(bundle))?;
    if let Some(previous) = load_secret(c, stored, device, bundle.key_epoch(), false, keys, budget)?
    {
        if crypto(encode_pairing_key_bundle(&previous))?.as_slice() != bytes.as_slice() {
            return Err(VaultError::OperationConflict);
        }
        if !independent
            || load_secret(c, stored, device, bundle.key_epoch(), true, keys, budget)?.is_some()
        {
            return Ok(());
        }
    }
    let envelope = crypto(wrap_secret(
        keys.wrapping_public_key(),
        &bytes,
        &secret_aad(
            stored,
            device,
            bundle.key_epoch(),
            independent,
            stored.endpoint,
            provenance,
        ),
    ))?;
    let envelope = crypto(encode_recovery_device_envelope_v1(&envelope))?;
    let mut signed = secret_aad(
        stored,
        device,
        bundle.key_epoch(),
        independent,
        stored.endpoint,
        provenance,
    );
    signed.extend(&envelope);
    let signature = keys.sign_hosted_device_proof(&signed);
    c.execute("INSERT INTO membership_epoch_secrets(device_id,key_epoch,independent_current,source_hash,source_control_epoch,source_key_epoch,provenance,envelope,signature) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",params![device.to_string(),bundle.key_epoch(),independent,stored.endpoint.state_sha256.0.as_slice(),stored.endpoint.control_epoch,stored.endpoint.key_epoch,provenance.0.as_slice(),envelope,signature.0.as_slice()])?;
    Ok(())
}
fn admission_preimage(
    stored: &Stored,
    device: DeviceId,
    successor: Sha256Digest,
    transcript: Sha256Digest,
) -> Vec<u8> {
    let mut signed = b"context-relay/confirmed-membership-admission/v1\0".to_vec();
    signed.extend(stored.scope.account_id.as_bytes());
    signed.extend(stored.scope.workspace_id.as_bytes());
    signed.extend(stored.pin.0);
    signed.extend(device.as_bytes());
    signed.extend(successor.0);
    signed.extend(transcript.0);
    signed
}
pub(super) fn retain_admission(
    c: &Connection,
    stored: &Stored,
    confirmed: &ConfirmedV2Transcript,
    bundle: &PairingKeyBundle,
    keys: &DeviceKeys,
    budget: MembershipHistoryBudget,
) -> Result<(), VaultError> {
    let device = confirmed.payload().grant.certificate.device_id;
    let hash = digest(confirmed.canonical_bytes());
    let existing:Option<(Vec<u8>,Vec<u8>,Vec<u8>)> = c.query_row("SELECT CASE WHEN length(successor)=32 THEN successor END,CASE WHEN length(transcript_hash)=32 THEN transcript_hash END,CASE WHEN length(signature)=64 THEN signature END FROM membership_confirmed_admission WHERE device_id=?1",[device.to_string()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
    if let Some((successor, transcript, signature)) = existing {
        if successor != stored.endpoint.state_sha256.0 || transcript != hash.0 {
            return Err(VaultError::OperationConflict);
        }
        crypto(crate::crypto::verify_signature(
            keys.signing_public_key(),
            &admission_preimage(stored, device, stored.endpoint.state_sha256, hash),
            Ed25519SignatureBytes(signature.try_into().map_err(|_| invalid())?),
        ))?;
    } else {
        let signature = keys.sign_hosted_device_proof(&admission_preimage(
            stored,
            device,
            stored.endpoint.state_sha256,
            hash,
        ));
        c.execute("INSERT INTO membership_confirmed_admission(device_id,successor,transcript_hash,signature) VALUES(?1,?2,?3,?4)",params![device.to_string(),stored.endpoint.state_sha256.0.as_slice(),hash.0.as_slice(),signature.0.as_slice()])?;
    }
    retain(c, stored, device, bundle, true, hash, keys, budget)
}
pub(super) fn retain_enrollment(
    c: &Connection,
    stored: &Stored,
    device: DeviceId,
    bundle: &PairingKeyBundle,
    keys: &DeviceKeys,
    budget: MembershipHistoryBudget,
) -> Result<(), VaultError> {
    let pinned = crypto(PairingKeyBundle::new(
        stored.scope,
        1,
        1,
        *bundle.workspace_root_key(),
        *bundle.active_epoch_key(),
    ))?;
    let pinned = crypto(pinned.with_enrollment_record_sha256(stored.pin))?;
    if bundle.account_id() != stored.scope.account_id
        || bundle.workspace_id() != stored.scope.workspace_id
        || bundle.control_epoch() != 1
        || bundle.key_epoch() != 1
        || bundle
            .enrollment_record_sha256()
            .is_some_and(|pin| pin != stored.pin)
    {
        return Err(invalid());
    }
    retain(c, stored, device, &pinned, true, stored.pin, keys, budget)?;
    c.execute(
        "INSERT OR IGNORE INTO membership_root_material_seed(device_id) VALUES(?1)",
        [device.to_string()],
    )?;
    Ok(())
}

/// Includes all ciphertexts replayed to restore the authenticated cursor.
#[derive(Clone, Copy)]
pub struct HistoricalTransferBudget {
    pub history: MembershipHistoryBudget,
    pub max_pages: usize,
    pub max_bytes: usize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoricalTransferSelection {
    pub transfer_id: OperationId,
    pub header_sha256: Sha256Digest,
    pub checkpoint_sha256: Sha256Digest,
    pub authorizing_endpoint: MembershipEndpoint,
    pub revision: i64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoricalTransferProgress {
    pub selection: HistoricalTransferSelection,
    pub next_page: Option<(u32, Sha256Digest)>,
    pub inventory_verified: bool,
}
pub(super) struct Transfer {
    pub(super) header: HistoricalTransferHeader,
    pub(super) raw: Vec<u8>,
    pub(super) checkpoint: Vec<u8>,
    index: u32,
    hash: Sha256Digest,
}
pub(super) fn load_transfer(
    c: &Connection,
    id: OperationId,
    budget: HistoricalTransferBudget,
) -> Result<Option<Transfer>, VaultError> {
    let checkpoint_limit = budget
        .max_bytes
        .checked_sub(387)
        .ok_or(VaultError::BudgetExceeded)?
        .min(8 * 1024 * 1024);
    let row=c.query_row("SELECT CASE WHEN length(header)=387 THEN header END,CASE WHEN length(checkpoint) BETWEEN 1 AND ?2 THEN checkpoint END,next_index,CASE WHEN length(next_hash)=32 THEN next_hash END FROM historical_transfers WHERE transfer_id=?1",params![id.to_string(),checkpoint_limit as i64],|r|Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,Vec<u8>>(1)?,r.get::<_,u32>(2)?,r.get::<_,Vec<u8>>(3)?))).optional()?;
    let Some((raw, checkpoint, index, hash)) = row else {
        return Ok(None);
    };
    let header = crypto(HistoricalTransferHeader::decode(&raw))?;
    if header.context.transfer_id != id
        || header.context.page_count as usize > budget.max_pages
        || index > header.context.page_count
        || digest(&checkpoint) != header.context.checkpoint_sha256
    {
        return Err(VaultError::BudgetExceeded);
    }
    Ok(Some(Transfer {
        header,
        raw,
        checkpoint,
        index,
        hash: Sha256Digest(hash.try_into().map_err(|_| invalid())?),
    }))
}
pub(super) fn selection(
    c: &Connection,
    device: DeviceId,
    budget: HistoricalTransferBudget,
) -> Result<Option<HistoricalTransferSelection>, VaultError> {
    let row=c.query_row("SELECT CASE WHEN length(transfer_id)=36 THEN transfer_id END,revision FROM historical_transfer_selection WHERE device_id=?1",[device.to_string()],|r|Ok((r.get::<_,String>(0)?,r.get::<_,i64>(1)?))).optional()?;
    let Some((id, revision)) = row else {
        return Ok(None);
    };
    if revision <= 0 {
        return Err(invalid());
    }
    let id = id.parse().map_err(|_| invalid())?;
    let t = load_transfer(c, id, budget)?.ok_or_else(invalid)?;
    if t.header.context.recipient_device_id != device {
        return Err(invalid());
    }
    // Rotation increments both epochs; additions preserve both. Header E_D is key epoch.
    let epoch = t
        .header
        .context
        .last_historical_key_epoch
        .checked_add(1)
        .ok_or_else(invalid)?;
    Ok(Some(HistoricalTransferSelection {
        transfer_id: id,
        header_sha256: digest(&t.raw),
        checkpoint_sha256: digest(&t.checkpoint),
        authorizing_endpoint: MembershipEndpoint {
            state_sha256: t.header.context.authorizing_control_state_sha256,
            control_epoch: epoch,
            key_epoch: epoch,
        },
        revision,
    }))
}
pub(super) fn admission_lineage(
    c: &Connection,
    stored: &Stored,
    confirmed: &ConfirmedV2Transcript,
    signature: Ed25519SignatureBytes,
    budget: MembershipHistoryBudget,
) -> Result<VerifiedMembershipLineage, VaultError> {
    let device = confirmed.payload().grant.certificate.device_id;
    let statement = crypto(DeviceMembershipAddStatementV1::from_approved_payload_v2(
        confirmed.canonical_bytes(),
    ))?;
    let anchor = MembershipEndpoint {
        state_sha256: crypto(statement.control_state_sha256(signature))?,
        control_epoch: statement.control_epoch,
        key_epoch: statement.key_epoch,
    };
    let saved:Vec<u8>=c.query_row("SELECT CASE WHEN length(signature)=64 THEN signature END FROM membership_confirmed_admission WHERE device_id=?1 AND successor=?2 AND transcript_hash=?3",params![device.to_string(),anchor.state_sha256.0.as_slice(),digest(confirmed.canonical_bytes()).0.as_slice()],|r|r.get(0))?;
    crypto(crate::crypto::verify_signature(
        confirmed.payload().grant.certificate.signing_public_key,
        &admission_preimage(
            stored,
            device,
            anchor.state_sha256,
            digest(confirmed.canonical_bytes()),
        ),
        Ed25519SignatureBytes(saved.try_into().map_err(|_| invalid())?),
    ))?;
    lineage(stored, anchor, budget)
}
impl Vault {
    /// Retain independently authenticated current keys without activating writes.
    /// Root/retained devices need no pairing admission C to open their rotation.
    pub fn stage_current_membership_material(
        &mut self,
        expected: MembershipEndpoint,
        device: DeviceId,
        keys: &DeviceKeys,
        budget: MembershipHistoryBudget,
    ) -> Result<(), VaultError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored = load(&tx, budget)?.ok_or_else(invalid)?;
        endpoint_check(&stored, expected, device, keys, budget)?;
        // Prefer signed staging. A known seed can never be repaired from the legacy envelope.
        if load_secret(&tx, &stored, device, 1, true, keys, budget)?.is_none() {
            let seeded: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM membership_root_material_seed WHERE device_id=?1)",
                [device.to_string()],
                |r| r.get(0),
            )?;
            if seeded {
                return Err(invalid());
            }
            // Explicit schema40 root upgrade boundary: the existing active local
            // enrollment opener remains the trust source; genesis has no public key commitment.
            if let Some(enrollment) = super::super::recovery::load_recovery_enrollment(&tx)?
                && enrollment.state == super::super::RecoveryEnrollmentPersistenceState::Active
                && enrollment.record.genesis_certificate.device_id == device
                && enrollment.canonical_record_sha256 == stored.pin
            {
                let original = crypto(open_device_workspace_material(
                    &enrollment.record,
                    &enrollment.device_material_envelope,
                    device,
                    keys,
                ))?;
                retain_enrollment(&tx, &stored, device, &original, keys, budget)?;
            }
        }
        // Full D and local authorization were checked above. Replay once more to
        // recover each rotation's actual predecessor, never the latest state.
        let mut pending = Vec::new();
        crypto(replay_membership_history(
            &stored.enrollment,
            stored.pin,
            stored.scope,
            &stored
                .events
                .iter()
                .map(Event::evidence)
                .collect::<Vec<_>>(),
            expected,
            budget,
            |history, event| {
                let Some(MembershipHistoryEvent::Revocation {
                    statement,
                    signature,
                    transition,
                }) = event
                else {
                    return Ok(());
                };
                // Rotations before this device's admission have no envelope for it.
                if !history.state().active_devices.contains_key(&device)
                    || load_secret(
                        &tx,
                        &stored,
                        device,
                        history.endpoint().key_epoch,
                        true,
                        keys,
                        budget,
                    )
                    .map_err(|_| crate::crypto::CryptoError::AuthenticationFailed)?
                    .is_some()
                {
                    return Ok(());
                }
                let statement = DeviceRevocationStatementV1::from_signing_preimage(statement)?;
                let transition = RevocationTransitionV1::from_canonical_bytes(transition)?;
                let predecessor = history
                    .latest_rotation_predecessor()
                    .ok_or(crate::crypto::CryptoError::AuthenticationFailed)?;
                // Authenticate ORIGINAL plaintext commitment before associating the pin.
                let original = transition.open_device_material(
                    &statement,
                    *signature,
                    &predecessor,
                    device,
                    keys,
                )?;
                if original
                    .enrollment_record_sha256()
                    .is_some_and(|pin| pin != stored.pin)
                {
                    return Err(crate::crypto::CryptoError::AuthenticationFailed);
                }
                pending.push((
                    original.with_enrollment_record_sha256(stored.pin)?,
                    transition.key_material_sha256,
                ));
                Ok(())
            },
        ))?;
        // All opened bundles remain private until the complete replay succeeds.
        // Their count is bounded by the same preflight event/byte budget.
        for (bundle, provenance) in pending {
            retain(
                &tx, &stored, device, &bundle, true, provenance, keys, budget,
            )?;
        }
        if load_secret(&tx, &stored, device, expected.key_epoch, true, keys, budget)?.is_none() {
            return Err(invalid());
        }
        tx.commit()?;
        Ok(())
    }
    /// Inventory inspection only. Requires an active local recipient at exact D.
    pub fn staged_membership_epoch(
        &self,
        expected: MembershipEndpoint,
        device: DeviceId,
        epoch: u32,
        independent_current: bool,
        keys: &DeviceKeys,
        budget: MembershipHistoryBudget,
    ) -> Result<Option<PairingKeyBundle>, VaultError> {
        let tx = self.connection.unchecked_transaction()?;
        let stored = load(&tx, budget)?.ok_or_else(invalid)?;
        endpoint_check(&stored, expected, device, keys, budget)?;
        if epoch == 0 || epoch > expected.key_epoch {
            return Err(invalid());
        }
        let bundle = load_secret(
            &tx,
            &stored,
            device,
            epoch,
            independent_current,
            keys,
            budget,
        )?;
        tx.commit()?;
        Ok(bundle)
    }
    pub fn historical_transfer_selection(
        &self,
        device: DeviceId,
        budget: HistoricalTransferBudget,
    ) -> Result<Option<HistoricalTransferSelection>, VaultError> {
        let tx = self.connection.unchecked_transaction()?;
        let result = selection(&tx, device, budget)?;
        tx.commit()?;
        Ok(result)
    }
    /// Persist immutable identity and select by exact D plus previous target/hash/revision.
    /// Checkpoint signatures are target assertions, not reconstructed frontier proofs.
    #[allow(clippy::too_many_arguments)]
    pub fn select_historical_transfer(
        &mut self,
        expected: MembershipEndpoint,
        previous: Option<HistoricalTransferSelection>,
        confirmed: &ConfirmedV2Transcript,
        signature: Ed25519SignatureBytes,
        header: &[u8],
        checkpoint: &[u8],
        keys: &DeviceKeys,
        budget: HistoricalTransferBudget,
    ) -> Result<HistoricalTransferSelection, VaultError> {
        if checkpoint
            .len()
            .checked_add(header.len())
            .is_none_or(|n| n > budget.max_bytes)
            || checkpoint.len() > 8 * 1024 * 1024
        {
            return Err(VaultError::BudgetExceeded);
        }
        let h = crypto(HistoricalTransferHeader::decode(header))?;
        if h.context.page_count as usize > budget.max_pages {
            return Err(VaultError::BudgetExceeded);
        }
        let device = h.context.recipient_device_id;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored = load(&tx, budget.history)?.ok_or_else(invalid)?;
        endpoint_check(&stored, expected, device, keys, budget.history)?;
        let lineage = admission_lineage(&tx, &stored, confirmed, signature, budget.history)?;
        let authority = crypto(HistoricalTransferAuthority::new(
            &lineage,
            confirmed,
            signature,
            h.context.transfer_id,
            h.context.exporter_device_id,
            checkpoint,
        ))?;
        crypto(authority.verify_header(header))?;
        let selected = selection(&tx, device, budget)?;
        let same = selected.is_some_and(|s| {
            s.transfer_id == h.context.transfer_id
                && s.header_sha256 == digest(header)
                && s.authorizing_endpoint == expected
                && s.checkpoint_sha256 == digest(checkpoint)
        });
        if !same && selected != previous {
            return Err(VaultError::OperationConflict);
        }
        if !same && let Some(prior) = selected {
            super::reconstruction::require_target_extension(
                &tx, &stored, prior, checkpoint, keys, budget,
            )?;
        }
        if let Some(existing) = load_transfer(&tx, h.context.transfer_id, budget)? {
            if existing.raw != header || existing.checkpoint != checkpoint {
                return Err(VaultError::OperationConflict);
            }
            // A superseded ID cannot be selected again, even under the original D.
            if !same {
                return Err(VaultError::OperationConflict);
            }
        } else {
            tx.execute("INSERT INTO historical_transfers(transfer_id,header,checkpoint,next_index,next_hash) VALUES(?1,?2,?3,0,?4)",params![h.context.transfer_id.to_string(),header,checkpoint,h.first_page_sha256.0.as_slice()])?;
        }
        if !same {
            let revision = selected
                .map_or(Some(1), |s| s.revision.checked_add(1))
                .ok_or_else(invalid)?;
            tx.execute("INSERT INTO historical_transfer_selection(device_id,transfer_id,revision) VALUES(?1,?2,?3) ON CONFLICT(device_id) DO UPDATE SET transfer_id=excluded.transfer_id,revision=excluded.revision",params![device.to_string(),h.context.transfer_id.to_string(),revision])?;
        }
        let result = selection(&tx, device, budget)?.ok_or_else(invalid)?;
        tx.commit()?;
        Ok(result)
    }
    /// Replays bounded persisted ciphertexts; no untrusted restored codec cursor.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_historical_transfer_page(
        &mut self,
        selected: HistoricalTransferSelection,
        confirmed: &ConfirmedV2Transcript,
        signature: Ed25519SignatureBytes,
        expected_page: (u32, Sha256Digest),
        ciphertext: &[u8],
        keys: &DeviceKeys,
        budget: HistoricalTransferBudget,
    ) -> Result<CommitDisposition, VaultError> {
        if ciphertext.len() > MAX_PAGE_BYTES {
            return Err(VaultError::BudgetExceeded);
        }
        self.replay_historical_transfer(
            selected,
            confirmed,
            signature,
            Some((expected_page, ciphertext)),
            keys,
            budget,
        )
        .map(|(_, d)| d)
    }
    pub fn historical_transfer_progress(
        &mut self,
        selected: HistoricalTransferSelection,
        confirmed: &ConfirmedV2Transcript,
        signature: Ed25519SignatureBytes,
        keys: &DeviceKeys,
        budget: HistoricalTransferBudget,
    ) -> Result<HistoricalTransferProgress, VaultError> {
        self.replay_historical_transfer(selected, confirmed, signature, None, keys, budget)
            .map(|(p, _)| p)
    }
    #[allow(clippy::too_many_arguments)]
    fn replay_historical_transfer(
        &mut self,
        selected: HistoricalTransferSelection,
        confirmed: &ConfirmedV2Transcript,
        signature: Ed25519SignatureBytes,
        page: Option<((u32, Sha256Digest), &[u8])>,
        keys: &DeviceKeys,
        budget: HistoricalTransferBudget,
    ) -> Result<(HistoricalTransferProgress, CommitDisposition), VaultError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = Self::replay_historical_transfer_tx(
            &tx, selected, confirmed, signature, page, keys, budget,
        )?;
        tx.commit()?;
        Ok(result)
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn replay_historical_transfer_tx(
        tx: &rusqlite::Transaction<'_>,
        selected: HistoricalTransferSelection,
        confirmed: &ConfirmedV2Transcript,
        signature: Ed25519SignatureBytes,
        page: Option<((u32, Sha256Digest), &[u8])>,
        keys: &DeviceKeys,
        budget: HistoricalTransferBudget,
    ) -> Result<(HistoricalTransferProgress, CommitDisposition), VaultError> {
        let device = confirmed.payload().grant.certificate.device_id;
        let stored = load(tx, budget.history)?.ok_or_else(invalid)?;
        endpoint_check(
            &stored,
            selected.authorizing_endpoint,
            device,
            keys,
            budget.history,
        )?;
        if selection(tx, device, budget)? != Some(selected) {
            return Err(VaultError::OperationConflict);
        }
        let t = load_transfer(tx, selected.transfer_id, budget)?.ok_or_else(invalid)?;
        let proof = admission_lineage(tx, &stored, confirmed, signature, budget.history)?;
        let authority = crypto(HistoricalTransferAuthority::new(
            &proof,
            confirmed,
            signature,
            selected.transfer_id,
            t.header.context.exporter_device_id,
            &t.checkpoint,
        ))?;
        let mut verified = crypto(authority.verify_header(&t.raw))?;
        let genesis = load_secret(tx, &stored, device, 1, false, keys, budget.history)?;
        // Confirmed epoch-one admission proves this value was previously trusted.
        // Deletion is not authority to replace it with an exporter assertion.
        if genesis.is_none()
            && confirmed.payload().grant.key_epoch == 1
            && t.header.context.page_count > 0
        {
            return Err(invalid());
        }
        let trust = genesis.as_ref().map_or(
            EpochOneTrust::ActiveExporterAssertion,
            EpochOneTrust::PreviouslyTrusted,
        );
        let (count,bytes):(i64,i64)=tx.query_row("SELECT count(*),COALESCE(sum(length(ciphertext)),0) FROM historical_transfer_pages WHERE transfer_id=?1",[selected.transfer_id.to_string()],|r|Ok((r.get(0)?,r.get(1)?)))?;
        let count = usize::try_from(count).map_err(|_| invalid())?;
        let bytes = usize::try_from(bytes).map_err(|_| invalid())?;
        if count != t.index as usize
            || count > budget.max_pages
            || bytes
                .checked_add(t.raw.len())
                .and_then(|n| n.checked_add(t.checkpoint.len()))
                .and_then(|n| n.checked_add(page.map_or(0, |(_, p)| p.len())))
                .is_none_or(|n| n > budget.max_bytes)
        {
            return Err(VaultError::BudgetExceeded);
        }
        let mut disposition = CommitDisposition::Inserted;
        // ponytail: O(pages) replay per commit; authenticated persisted cursor if profiling warrants it.
        for index in 0..t.index {
            let raw:Vec<u8>=tx.query_row("SELECT CASE WHEN length(ciphertext) BETWEEN 1 AND 16384 THEN ciphertext END FROM historical_transfer_pages WHERE transfer_id=?1 AND page_index=?2",params![selected.transfer_id.to_string(),index],|r|r.get(0))?;
            if let Some((expected, bytes)) = page
                && expected.0 == index
            {
                if verified.next_page() != Some(expected) || bytes != raw {
                    return Err(VaultError::OperationConflict);
                }
                disposition = CommitDisposition::ExactReplay;
            }
            let bundles = crypto(verified.open_next_page(&raw, keys, trust))?;
            for bundle in bundles {
                let retained = load_secret(
                    tx,
                    &stored,
                    device,
                    bundle.key_epoch(),
                    false,
                    keys,
                    budget.history,
                )?
                .ok_or_else(invalid)?;
                if crypto(encode_pairing_key_bundle(&retained))?.as_slice()
                    != crypto(encode_pairing_key_bundle(&bundle))?.as_slice()
                {
                    return Err(invalid());
                }
            }
        }
        let stored_cursor = if t.index == t.header.context.page_count && t.hash.0 == [0; 32] {
            None
        } else {
            Some((t.index, t.hash))
        };
        if verified.next_page() != stored_cursor
            || (verified.inventory_verified() && t.hash.0 != [0; 32])
        {
            return Err(invalid());
        }
        if let Some((expected, raw)) = page
            && disposition != CommitDisposition::ExactReplay
        {
            if verified.next_page() != Some(expected) {
                return Err(VaultError::OperationConflict);
            }
            let bundles = crypto(verified.open_next_page(raw, keys, trust))?;
            for bundle in bundles {
                retain(
                    tx,
                    &stored,
                    device,
                    &bundle,
                    false,
                    digest(&t.raw),
                    keys,
                    budget.history,
                )?;
            }
            tx.execute("INSERT INTO historical_transfer_pages(transfer_id,page_index,ciphertext) VALUES(?1,?2,?3)",params![selected.transfer_id.to_string(),expected.0,raw])?;
            let (index, hash) = verified
                .next_page()
                .unwrap_or((t.header.context.page_count, Sha256Digest([0; 32])));
            let changed=tx.execute("UPDATE historical_transfers SET next_index=?1,next_hash=?2 WHERE transfer_id=?3 AND next_index=?4 AND next_hash=?5",params![index,hash.0.as_slice(),selected.transfer_id.to_string(),expected.0,expected.1.0.as_slice()])?;
            if changed != 1 {
                return Err(VaultError::OperationConflict);
            }
        }
        let progress = HistoricalTransferProgress {
            selection: selected,
            next_page: verified.next_page(),
            inventory_verified: verified.inventory_verified(),
        };
        Ok((progress, disposition))
    }
}
