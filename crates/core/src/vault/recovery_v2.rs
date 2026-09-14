//! Durable root-authorized preparation. No provider receipt or accepted authority.
use super::{CommitDisposition, HostedRestoreIntent, Vault, VaultError};
use crate::{
    crypto::{DeviceKeys, verify_signature},
    devices::{
        membership_crypto::*,
        membership_transport::MembershipEventObject,
        recovery_crypto::{
            decode_recovery_device_envelope_v1, decode_recovery_enrollment_record_v1,
            encode_recovery_device_envelope_v1,
        },
        recovery_restore_crypto::v2::*,
    },
    sync::SyncScope,
};
use context_relay_protocol::{Ed25519SignatureBytes, Sha256Digest};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};

const BUDGET: MembershipHistoryBudget = MembershipHistoryBudget {
    max_events: 4096,
    max_bytes: 64 * 1024 * 1024,
};
fn invalid() -> VaultError {
    VaultError::Validation("recovery_v2_invalid".into())
}
fn checked<T, E>(r: Result<T, E>) -> Result<T, VaultError> {
    r.map_err(|_| invalid())
}

pub struct PreparedRecoveryV2 {
    pub publication_conflict: bool,
    pub canonical_record: Vec<u8>,
    pub canonical_claim: Vec<u8>,
    pub claim: RecoveryDeviceClaimV2,
    pub parent: VerifiedMembershipHistory,
    pub parent_objects: Vec<MembershipEventObject>,
    pub history_keys: Vec<RecoveryHistoryKeyV1>,
}
impl std::fmt::Debug for PreparedRecoveryV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedRecoveryV2([REDACTED])")
    }
}

fn validate(
    record: Vec<u8>,
    canonical: Vec<u8>,
    objects: Vec<MembershipEventObject>,
    retained: Vec<RecoveryHistoryKeyV1>,
    keys: &DeviceKeys,
) -> Result<PreparedRecoveryV2, VaultError> {
    if record.len() > 32768
        || canonical.len() > 32768
        || objects.len() > BUDGET.max_events
        || retained.len() > BUDGET.max_events
    {
        return Err(invalid());
    }
    let claim = checked(decode_recovery_device_claim_v2(&canonical))?;
    let root = checked(decode_recovery_enrollment_record_v1(&record))?;
    let scope = SyncScope {
        account_id: claim.account_id,
        workspace_id: claim.workspace_id,
    };
    let endpoint = MembershipEndpoint {
        state_sha256: claim.previous_state_sha256,
        control_epoch: claim.certificate.control_epoch,
        key_epoch: claim.key_epoch,
    };
    let mut events = objects
        .iter()
        .map(MembershipEventObject::evidence)
        .collect::<Vec<_>>();
    let parent = checked(verify_membership_history(
        &record,
        claim.canonical_record_sha256,
        scope,
        &events,
        endpoint,
        BUDGET,
    ))?;
    checked(open_recovered_device_material_v2(
        &root, &claim, &parent, keys,
    ))?;
    // This prospective replay only validates retained inventory. It is not saved
    // as accepted history and supplies no provider CAS/installation receipt.
    events.push(MembershipHistoryEvent::RecoveryAdd {
        canonical_claim: &canonical,
    });
    let admitted = MembershipEndpoint {
        state_sha256: checked(recovery_membership_successor(&claim))?,
        ..endpoint
    };
    let lineage = checked(verify_membership_lineage(
        &record,
        claim.canonical_record_sha256,
        scope,
        &events,
        admitted,
        admitted,
        BUDGET,
    ))?;
    let mut epochs = std::collections::BTreeSet::new();
    for key in &retained {
        if !epochs.insert(key.key_epoch) {
            return Err(invalid());
        }
        checked(open_recovery_history_key(
            &root, &claim, &parent, &lineage, key, keys,
        ))?;
    }
    Ok(PreparedRecoveryV2 {
        publication_conflict: false,
        canonical_record: record,
        canonical_claim: canonical,
        claim,
        parent,
        parent_objects: objects,
        history_keys: retained,
    })
}

pub(super) fn intent_bytes(c: &Connection) -> Result<Vec<u8>, VaultError> {
    let intent:Option<Vec<u8>>=c.query_row("SELECT CASE WHEN length(payload)<=8192 THEN payload END FROM hosted_restore_intent WHERE singleton=1",[],|r|r.get(0)).optional()?;
    match intent {
        Some(bytes) => {
            let intent: HostedRestoreIntent = checked(serde_json::from_slice(&bytes))?;
            intent.validate()?;
            let canonical = checked(serde_json::to_vec(&intent))?;
            if canonical != bytes {
                return Err(invalid());
            }
            Ok(canonical)
        }
        None => Ok(Vec::new()),
    }
}
fn preimage(record: &[u8], claim: &[u8], intent: &[u8]) -> Vec<u8> {
    let mut bytes = b"context-relay/recovery-preparation/v1\0".to_vec();
    bytes.extend(Sha256::digest(record));
    bytes.extend(Sha256::digest(claim));
    bytes.extend((intent.len() as u32).to_be_bytes());
    bytes.extend(intent);
    bytes
}
pub(super) fn load(
    c: &Connection,
    keys: &DeviceKeys,
) -> Result<Option<PreparedRecoveryV2>, VaultError> {
    let row=c.query_row("SELECT CASE WHEN length(canonical_record) BETWEEN 1 AND 32768 THEN canonical_record END,CASE WHEN length(canonical_claim) BETWEEN 1 AND 32768 THEN canonical_claim END,CASE WHEN length(hosted_intent)<=8192 THEN hosted_intent END,CASE WHEN length(preparation_signature)=64 THEN preparation_signature END FROM recovery_v2_prepared WHERE singleton=1",[],|r|Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,Vec<u8>>(1)?,r.get::<_,Vec<u8>>(2)?,r.get::<_,Vec<u8>>(3)?))).optional()?;
    let marker = c.query_row("SELECT reason, CASE WHEN length(signature)=64 THEN signature END FROM recovery_v2_conflict WHERE singleton=1", [], |r| Ok((r.get::<_,u8>(0)?,r.get::<_,Vec<u8>>(1)?))).optional()?;
    let Some((record, claim, intent, signature)) = row else {
        if marker.is_some() {
            return Err(invalid());
        }
        return Ok(None);
    };
    if c.query_row("SELECT EXISTS(SELECT 1 FROM recovery_restores)", [], |r| {
        r.get::<_, bool>(0)
    })? {
        return Err(invalid());
    }
    if intent_bytes(c)? != intent {
        return Err(VaultError::OperationConflict);
    }
    checked(verify_signature(
        keys.signing_public_key(),
        &preimage(&record, &claim, &intent),
        Ed25519SignatureBytes(checked(signature.try_into())?),
    ))?;
    let (count, total): (i64, i64) = c.query_row(
        "SELECT count(*),coalesce(sum(length(canonical)),0) FROM recovery_v2_parent_objects",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if count < 0 || total < 0 || count > BUDGET.max_events as i64 || total > BUDGET.max_bytes as i64
    {
        return Err(invalid());
    }
    let rows=c.prepare("SELECT ordinal,CASE WHEN length(canonical) BETWEEN 1 AND 16777216 THEN canonical END FROM recovery_v2_parent_objects ORDER BY ordinal")?.query_map([],|r|Ok((r.get::<_,u32>(0)?,r.get::<_,Vec<u8>>(1)?)))?.collect::<Result<Vec<_>,_>>()?;
    let mut objects = Vec::with_capacity(rows.len());
    for (index, (ordinal, bytes)) in rows.into_iter().enumerate() {
        if ordinal as usize != index {
            return Err(invalid());
        }
        objects.push(checked(MembershipEventObject::from_canonical_bytes(
            &bytes,
        ))?);
    }
    let count: i64 = c.query_row("SELECT count(*) FROM recovery_v2_history_keys", [], |r| {
        r.get(0)
    })?;
    if count < 0 || count > BUDGET.max_events as i64 {
        return Err(invalid());
    }
    let rows=c.prepare("SELECT key_epoch,CASE WHEN length(original_bundle_sha256)=32 THEN original_bundle_sha256 END,CASE WHEN length(canonical_envelope) BETWEEN 1 AND 1024 THEN canonical_envelope END,CASE WHEN length(signature)=64 THEN signature END FROM recovery_v2_history_keys ORDER BY key_epoch")?.query_map([],|r|Ok((r.get::<_,u32>(0)?,r.get::<_,Vec<u8>>(1)?,r.get::<_,Vec<u8>>(2)?,r.get::<_,Vec<u8>>(3)?)))?.collect::<Result<Vec<_>,_>>()?;
    let mut retained = Vec::with_capacity(rows.len());
    for (key_epoch, hash, envelope, signature) in rows {
        retained.push(RecoveryHistoryKeyV1 {
            key_epoch,
            original_bundle_sha256: Sha256Digest(checked(hash.try_into())?),
            envelope: checked(decode_recovery_device_envelope_v1(&envelope))?,
            signature: Ed25519SignatureBytes(checked(signature.try_into())?),
        });
    }
    let mut prepared = validate(record, claim, objects, retained, keys)?;
    if let Some((reason, signature)) = marker {
        if reason != 1
            || intent.is_empty()
            || c.query_row(
                "SELECT EXISTS(SELECT 1 FROM recovery_v2_admission)",
                [],
                |r| r.get::<_, bool>(0),
            )?
        {
            return Err(invalid());
        }
        checked(verify_signature(
            prepared.claim.certificate.signing_public_key,
            &conflict_preimage(&prepared.canonical_claim, &intent),
            Ed25519SignatureBytes(checked(signature.try_into())?),
        ))?;
        prepared.publication_conflict = true;
    }
    Ok(Some(prepared))
}

fn conflict_preimage(claim: &[u8], intent: &[u8]) -> Vec<u8> {
    let mut bytes = b"context-relay/recovery-conflict-receipt/v1\0".to_vec();
    bytes.extend(Sha256::digest(claim));
    bytes.extend(Sha256::digest(intent));
    bytes.push(1);
    bytes
}

impl Vault {
    pub(crate) fn mark_recovery_publication_conflict(
        &mut self,
        canonical_claim: &[u8],
        keys: &DeviceKeys,
    ) -> Result<(), VaultError> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let prepared = load(&tx, keys)?.ok_or_else(invalid)?;
        if prepared.canonical_claim != canonical_claim {
            return Err(invalid());
        }
        if prepared.publication_conflict {
            return Ok(());
        }
        let intent = intent_bytes(&tx)?;
        if intent.is_empty()
            || tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM recovery_v2_admission)",
                [],
                |r| r.get::<_, bool>(0),
            )?
        {
            return Err(invalid());
        }
        let signature = keys.sign_hosted_device_proof(&conflict_preimage(canonical_claim, &intent));
        tx.execute(
            "INSERT INTO recovery_v2_conflict VALUES(1,1,?1)",
            [signature.0.as_slice()],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn prepared_recovery_v2(
        &self,
        keys: &DeviceKeys,
    ) -> Result<Option<PreparedRecoveryV2>, VaultError> {
        load(&self.connection, keys)
    }

    pub fn prepare_recovery_v2(
        &mut self,
        record: &[u8],
        claim: &[u8],
        objects: &[MembershipEventObject],
        retained: &[RecoveryHistoryKeyV1],
        keys: &DeviceKeys,
    ) -> Result<CommitDisposition, VaultError> {
        let objects = objects
            .iter()
            .map(|o| {
                checked(MembershipEventObject::from_canonical_bytes(
                    &o.canonical_bytes(),
                ))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let candidate = validate(
            record.to_vec(),
            claim.to_vec(),
            objects,
            retained.to_vec(),
            keys,
        )?;
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if let Some(stored) = load(&tx, keys)? {
            if stored.canonical_record != record || stored.canonical_claim != claim {
                return Err(VaultError::OperationConflict);
            }
            // A retry must preserve the exact originally retained ciphertext.
            let encoded = |list: &[RecoveryHistoryKeyV1]| -> Result<Vec<_>, VaultError> {
                list.iter()
                    .map(|key| {
                        Ok((
                            key.key_epoch,
                            key.original_bundle_sha256,
                            checked(encode_recovery_device_envelope_v1(&key.envelope))?,
                            key.signature,
                        ))
                    })
                    .collect()
            };
            if encoded(&stored.history_keys)? != encoded(&candidate.history_keys)?
                || stored
                    .parent_objects
                    .iter()
                    .map(MembershipEventObject::canonical_bytes)
                    .collect::<Vec<_>>()
                    != candidate
                        .parent_objects
                        .iter()
                        .map(MembershipEventObject::canonical_bytes)
                        .collect::<Vec<_>>()
            {
                return Err(VaultError::OperationConflict);
            }
            return Ok(CommitDisposition::ExactReplay);
        }
        if tx.query_row("SELECT EXISTS(SELECT 1 FROM recovery_restores)", [], |r| {
            r.get::<_, bool>(0)
        })? {
            return Err(VaultError::OperationConflict);
        }
        super::recovery_restore::require_pristine_vault(&tx)?;
        let intent = intent_bytes(&tx)?;
        let signature = keys.sign_hosted_device_proof(&preimage(record, claim, &intent));
        tx.execute(
            "INSERT INTO recovery_v2_prepared VALUES(1,?1,?2,?3,?4)",
            params![record, claim, intent, signature.0.as_slice()],
        )?;
        for (index, object) in candidate.parent_objects.iter().enumerate() {
            tx.execute(
                "INSERT INTO recovery_v2_parent_objects VALUES(?1,?2)",
                params![index as i64, object.canonical_bytes()],
            )?;
        }
        for key in &candidate.history_keys {
            tx.execute(
                "INSERT INTO recovery_v2_history_keys VALUES(?1,?2,?3,?4)",
                params![
                    key.key_epoch,
                    key.original_bundle_sha256.0.as_slice(),
                    checked(encode_recovery_device_envelope_v1(&key.envelope))?,
                    key.signature.0.as_slice()
                ],
            )?;
        }
        tx.commit()?;
        Ok(CommitDisposition::Inserted)
    }
}
