//! Root admission has its own receipt; it never manufactures pairing confirmation.
use super::*;
use crate::devices::{
    membership_transport::MembershipEventObject,
    recovery_restore_crypto::v2::*,
    recovery_restore_transport::{RecoveryRestoreProjection, RecoveryRestoreReceipt},
};
use rusqlite::OptionalExtension;
use sha2::{Digest, Sha256};
fn checked<T, E>(r: Result<T, E>) -> Result<T, VaultError> {
    r.map_err(|_| invalid())
}
fn admission_endpoint(claim: &RecoveryDeviceClaimV2) -> Result<MembershipEndpoint, VaultError> {
    Ok(MembershipEndpoint {
        state_sha256: checked(recovery_membership_successor(claim))?,
        control_epoch: claim.certificate.control_epoch,
        key_epoch: claim.key_epoch,
    })
}
fn receipt_preimage(claim: &[u8], receipt: &[u8]) -> Vec<u8> {
    let mut bytes = b"context-relay/recovery-admission-receipt/v1\0".to_vec();
    bytes.extend(Sha256::digest(claim));
    bytes.extend((receipt.len() as u32).to_be_bytes());
    bytes.extend(receipt);
    bytes
}
pub(super) fn receipt(
    c: &Connection,
    prepared: &super::super::PreparedRecoveryV2,
    keys: &DeviceKeys,
) -> Result<Option<RecoveryRestoreReceipt>, VaultError> {
    let row=c.query_row("SELECT CASE WHEN length(canonical_receipt) BETWEEN 1 AND 8192 THEN canonical_receipt END,CASE WHEN length(signature)=64 THEN signature END FROM recovery_v2_admission WHERE singleton=1",[],|r|Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,Vec<u8>>(1)?))).optional()?;
    let Some((bytes, signature)) = row else {
        return Ok(None);
    };
    checked(crate::crypto::verify_signature(
        keys.signing_public_key(),
        &receipt_preimage(&prepared.canonical_claim, &bytes),
        Ed25519SignatureBytes(checked(signature.try_into())?),
    ))?;
    let receipt: RecoveryRestoreReceipt = checked(serde_json::from_slice(&bytes))?;
    if checked(serde_json::to_vec(&receipt))? != bytes {
        return Err(invalid());
    }
    checked(receipt.validate_v2(&prepared.claim))?;
    Ok(Some(receipt))
}
impl Vault {
    /// Accept the exact published root admission while keeping history installation
    /// and current-write activation separate. The provider receipt alone is insufficient.
    pub fn accept_recovery_membership(
        &mut self,
        ack: &RecoveryRestoreReceipt,
        projection: &RecoveryRestoreProjection,
        published: &MembershipEventObject,
        keys: &DeviceKeys,
    ) -> Result<CommitDisposition, VaultError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prepared = super::super::recovery_v2::load(&tx, keys)?.ok_or_else(invalid)?;
        if prepared.publication_conflict {
            return Err(VaultError::OperationConflict);
        }
        checked(ack.validate_v2(&prepared.claim))?;
        let expected = checked(MembershipEventObject::from_evidence(
            &MembershipHistoryEvent::RecoveryAdd {
                canonical_claim: &prepared.canonical_claim,
            },
        ))?;
        if projection.canonical_claim != prepared.canonical_claim
            || projection.receipt != *ack
            || published.canonical_bytes() != expected.canonical_bytes()
        {
            return Err(VaultError::OperationConflict);
        }
        let endpoint = admission_endpoint(&prepared.claim)?;
        let saved = receipt(&tx, &prepared, keys)?;
        if let Some(stored) = load(&tx, CURRENT_BUDGET)? {
            material::endpoint_check(
                &stored,
                stored.endpoint,
                prepared.claim.certificate.device_id,
                keys,
                CURRENT_BUDGET,
            )?;
            material::lineage(&stored, endpoint, CURRENT_BUDGET)?;
            if saved.as_ref() != Some(ack) {
                return Err(VaultError::OperationConflict);
            }
            return Ok(CommitDisposition::ExactReplay);
        }
        if saved.is_some()
            || tx.query_row("SELECT EXISTS(SELECT 1 FROM recovery_restores)", [], |r| {
                r.get::<_, bool>(0)
            })?
        {
            return Err(VaultError::OperationConflict);
        }
        super::super::recovery_restore::require_pristine_except(
            &tx,
            &[
                "recovery_v2_prepared",
                "recovery_v2_parent_objects",
                "recovery_v2_history_keys",
            ],
        )?;
        let mut events = prepared
            .parent_objects
            .iter()
            .map(|object| Event::from_evidence(&object.evidence()))
            .collect::<Result<Vec<_>, _>>()?;
        events.push(Event::from_evidence(&expected.evidence())?);
        let scope = SyncScope {
            account_id: prepared.claim.account_id,
            workspace_id: prepared.claim.workspace_id,
        };
        let stored = Stored {
            scope,
            pin: prepared.claim.canonical_record_sha256,
            enrollment: prepared.canonical_record.clone(),
            endpoint,
            events,
        };
        stored.verify(CURRENT_BUDGET)?;
        let root = checked(
            crate::devices::recovery_crypto::decode_recovery_enrollment_record_v1(
                &prepared.canonical_record,
            ),
        )?;
        let bundle = checked(open_recovered_device_material_v2(
            &root,
            &prepared.claim,
            &prepared.parent,
            keys,
        ))?;
        bootstrap(&tx, &stored.enrollment, stored.pin, scope, endpoint)?;
        insert_events(&tx, &stored.events, 0)?;
        material::retain(
            &tx,
            &stored,
            prepared.claim.certificate.device_id,
            &bundle,
            true,
            Sha256Digest(Sha256::digest(&prepared.canonical_claim).into()),
            keys,
            CURRENT_BUDGET,
        )?;
        let bytes = checked(serde_json::to_vec(ack))?;
        let signature =
            keys.sign_hosted_device_proof(&receipt_preimage(&prepared.canonical_claim, &bytes));
        tx.execute(
            "INSERT INTO recovery_v2_admission VALUES(1,?1,?2)",
            params![bytes, signature.0.as_slice()],
        )?;
        tx.commit()?;
        Ok(CommitDisposition::Inserted)
    }

    pub fn recovery_membership_admission(
        &self,
        keys: &DeviceKeys,
    ) -> Result<Option<MembershipEndpoint>, VaultError> {
        let tx = self.connection.unchecked_transaction()?;
        let Some(prepared) = super::super::recovery_v2::load(&tx, keys)? else {
            return Ok(None);
        };
        if receipt(&tx, &prepared, keys)?.is_none() {
            return Ok(None);
        }
        let stored = load(&tx, CURRENT_BUDGET)?.ok_or_else(invalid)?;
        material::endpoint_check(
            &stored,
            stored.endpoint,
            prepared.claim.certificate.device_id,
            keys,
            CURRENT_BUDGET,
        )?;
        let endpoint = admission_endpoint(&prepared.claim)?;
        material::lineage(&stored, endpoint, CURRENT_BUDGET)?;
        Ok(Some(endpoint))
    }
}
