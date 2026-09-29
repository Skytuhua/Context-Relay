//! Durable V2 transcripts. Public proof, user confirmation and activation are separate.
use super::{DeviceDisplayMetadata, HostedPairingRole, Vault, VaultError};
use crate::{
    crypto::DeviceKeys,
    devices::{
        crypto::{SignedPairingRequest, control_v2::*, verify_pairing_request},
        membership_crypto::*,
        membership_transport::MembershipEventObject,
    },
};
use context_relay_protocol::{
    Ed25519SignatureBytes, PairingId, Sha256Digest, decode_pairing_request_v1,
};
use rusqlite::{OptionalExtension, params};

pub(crate) const BUDGET: MembershipHistoryBudget = MembershipHistoryBudget {
    max_events: 4096,
    max_bytes: 64 * 1024 * 1024,
};
fn invalid() -> VaultError {
    VaultError::Validation("pairing_v2_invalid".into())
}
fn checked<T, E>(value: Result<T, E>) -> Result<T, VaultError> {
    value.map_err(|_| invalid())
}

fn hosted_binding(intent: Option<super::HostedPairingIntent>) -> Result<Vec<u8>, VaultError> {
    let mut bytes = Vec::new();
    if let Some(intent) = intent {
        if intent.role != HostedPairingRole::Join {
            return Err(VaultError::OperationConflict);
        }
        bytes.extend(intent.user_id.as_bytes());
        bytes.extend(intent.session_id.as_bytes());
        bytes.extend(intent.project_url.as_bytes());
    }
    Ok(bytes)
}

pub(super) fn require_pristine_join(
    tx: &rusqlite::Transaction<'_>,
    request: &SignedPairingRequest,
    canonical: &[u8],
    signature: Ed25519SignatureBytes,
    receipt: Ed25519SignatureBytes,
    keys: &DeviceKeys,
) -> Result<(), VaultError> {
    // Check original intent and recipient receipt within the authority transaction.
    checked(restore_confirmed_pairing_transcript_v2(
        canonical,
        request,
        signature,
        &hosted_binding(super::hosted_pairing::load(
            tx,
            request.request().pairing_id,
        )?)?,
        receipt,
        keys,
    ))?;
    let id = request.request().pairing_id.to_string();
    let exact:bool=tx.query_row("SELECT (SELECT count(*) FROM pairing_v2_transcripts)=1 AND EXISTS(SELECT 1 FROM pairing_v2_transcripts WHERE pairing_id=?1 AND role='joiner' AND state='confirmed' AND canonical_request=?2 AND canonical_payload=?3 AND membership_signature=?4 AND confirmation_signature=?5) AND (SELECT count(*) FROM pairing_joins)=1 AND EXISTS(SELECT 1 FROM pairing_joins WHERE pairing_id=?1 AND canonical_request=?2 AND state='stored' AND certificate_id IS NULL AND wrapped_key_bundle IS NULL AND issuer_certificate_id IS NULL) AND NOT EXISTS(SELECT 1 FROM hosted_pairing_intents WHERE pairing_id<>?1)",params![id,request.canonical_bytes(),canonical,signature.0.as_slice(),receipt.0.as_slice()],|r|r.get(0))?;
    if !exact {
        return Err(VaultError::OperationConflict);
    }
    let unrelated: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM pairing_v2_public_objects WHERE pairing_id<>?1)",
        [&id],
        |r| r.get(0),
    )?;
    if unrelated {
        return Err(VaultError::OperationConflict);
    }
    super::recovery_restore::require_pristine_except(
        tx,
        &[
            "pairing_v2_transcripts",
            "pairing_joins",
            "hosted_pairing_intents",
            "pairing_v2_public_objects",
        ],
    )
}

pub(crate) struct Transcript {
    pub request: SignedPairingRequest,
    pub canonical: Vec<u8>,
    pub signature: Ed25519SignatureBytes,
    pub role: String,
    pub state: String,
    pub receipt: Option<Ed25519SignatureBytes>,
}
impl Transcript {
    pub fn payload(&self) -> Result<PairingApprovedPayloadV2, VaultError> {
        checked(decode_pairing_approved_payload_v2(&self.canonical))
    }
    pub fn object(&self) -> Result<MembershipEventObject, VaultError> {
        let statement = checked(DeviceMembershipAddStatementV1::from_approved_payload_v2(
            &self.canonical,
        ))?;
        let bytes = checked(statement.signing_preimage())?;
        checked(MembershipEventObject::from_evidence(
            &MembershipHistoryEvent::PairingAdd {
                statement: &bytes,
                signature: self.signature,
                request: &self.request,
                approved_payload: &self.canonical,
            },
        ))
    }
    pub fn endpoint(&self) -> Result<MembershipEndpoint, VaultError> {
        let payload = self.payload()?;
        Ok(MembershipEndpoint {
            state_sha256: checked(self.object()?.endpoints())?.1,
            control_epoch: payload.grant.certificate.control_epoch,
            key_epoch: payload.grant.key_epoch,
        })
    }
}

impl Vault {
    /// Version-aware progress only; pending confirmation never implies accepted trust.
    pub fn pairing_confirmation_pending(&self, id: PairingId) -> Result<bool, VaultError> {
        if let Some(stored) = self.pairing_v2(id)? {
            return Ok(stored.role == "joiner"
                && stored.state == "awaiting_confirmation"
                && stored.receipt.is_none());
        }
        Ok(self.awaiting_pairing_confirmation(id)?.is_some())
    }

    pub(crate) fn pairing_public_object(
        &self,
        id: PairingId,
        kind: &str,
        address: Sha256Digest,
    ) -> Result<Option<Vec<u8>>, VaultError> {
        self.connection.query_row("SELECT CASE WHEN length(canonical) BETWEEN 1 AND 16777216 THEN canonical END FROM pairing_v2_public_objects WHERE pairing_id=?1 AND kind=?2 AND address=?3",params![id.to_string(),kind,address.0.as_slice()],|r|r.get(0)).optional().map_err(Into::into)
    }

    pub(crate) fn cache_pairing_public_object(
        &mut self,
        id: PairingId,
        kind: &str,
        address: Sha256Digest,
        canonical: &[u8],
    ) -> Result<(), VaultError> {
        let transcript = self.pairing_v2(id)?.ok_or_else(invalid)?;
        if transcript.role != "joiner"
            || !matches!(kind, "enrollment" | "event")
            || canonical.is_empty()
            || canonical.len() > 16 * 1024 * 1024
        {
            return Err(invalid());
        }
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let existing:Option<Vec<u8>>=tx.query_row("SELECT canonical FROM pairing_v2_public_objects WHERE pairing_id=?1 AND kind=?2 AND address=?3",params![id.to_string(),kind,address.0.as_slice()],|r|r.get(0)).optional()?;
        if let Some(existing) = existing {
            return if existing == canonical {
                Ok(())
            } else {
                Err(VaultError::OperationConflict)
            };
        }
        let (count,bytes):(i64,i64)=tx.query_row("SELECT count(*),coalesce(sum(length(canonical)),0) FROM pairing_v2_public_objects WHERE pairing_id=?1",[id.to_string()],|r|Ok((r.get(0)?,r.get(1)?)))?;
        if count < 0
            || bytes < 0
            || count >= (BUDGET.max_events + 1) as i64
            || bytes
                .checked_add(canonical.len() as i64)
                .is_none_or(|n| n > BUDGET.max_bytes as i64)
        {
            return Err(VaultError::BudgetExceeded);
        }
        tx.execute("INSERT INTO pairing_v2_public_objects(pairing_id,kind,address,canonical) VALUES(?1,?2,?3,?4)",params![id.to_string(),kind,address.0.as_slice(),canonical])?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn pairing_v2(&self, id: PairingId) -> Result<Option<Transcript>, VaultError> {
        let row=self.connection.query_row("SELECT role,state,CASE WHEN length(canonical_request) BETWEEN 1 AND 8192 THEN canonical_request END,CASE WHEN length(canonical_payload) BETWEEN 1 AND 32768 THEN canonical_payload END,CASE WHEN length(membership_signature)=64 THEN membership_signature END,confirmation_signature FROM pairing_v2_transcripts WHERE pairing_id=?1",[id.to_string()],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,Vec<u8>>(2)?,r.get::<_,Vec<u8>>(3)?,r.get::<_,Vec<u8>>(4)?,r.get::<_,Option<Vec<u8>>>(5)?))).optional()?;
        let Some((role, state, request, canonical, signature, receipt)) = row else {
            return Ok(None);
        };
        let request = checked(verify_pairing_request(&checked(
            decode_pairing_request_v1(&request),
        )?))?;
        let transcript = Transcript {
            request,
            canonical,
            signature: Ed25519SignatureBytes(checked(signature.try_into())?),
            role,
            state,
            receipt: receipt
                .map(|s| checked(s.try_into()).map(Ed25519SignatureBytes))
                .transpose()?,
        };
        let payload = transcript.payload()?;
        if transcript.request.request().pairing_id != id
            || payload.grant.pairing_id != id
            || payload.grant.request_digest != transcript.request.digest()
        {
            return Err(invalid());
        }
        checked(approver_safety_number_v2(
            &transcript.canonical,
            &transcript.request,
        ))?;
        transcript.object()?;
        Ok(Some(transcript))
    }

    pub(crate) fn pending_pairing_v2(&self) -> Result<Vec<PairingId>, VaultError> {
        let mut q=self.connection.prepare("SELECT pairing_id FROM pairing_v2_transcripts WHERE role='approver' AND state='prepared' ORDER BY pairing_id LIMIT 65")?;
        let ids = q
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        if ids.len() > 64 {
            return Err(VaultError::BudgetExceeded);
        }
        ids.into_iter().map(|s| checked(s.parse())).collect()
    }

    pub(crate) fn store_pairing_v2(
        &mut self,
        request: &SignedPairingRequest,
        canonical: &[u8],
        signature: Ed25519SignatureBytes,
        role: &str,
        now: u64,
    ) -> Result<(), VaultError> {
        if !matches!(role, "approver" | "joiner") || canonical.len() > 32768 {
            return Err(invalid());
        }
        checked(approver_safety_number_v2(canonical, request))?;
        let id = request.request().pairing_id;
        if self.pairing_approval_transcript(id)?.is_some() {
            return Err(VaultError::OperationConflict);
        }
        if let Some(existing) = self.pairing_v2(id)? {
            return if existing.request == *request
                && existing.canonical == canonical
                && existing.signature == signature
                && existing.role == role
            {
                Ok(())
            } else {
                Err(VaultError::OperationConflict)
            };
        }
        if role == "approver" {
            let history = self
                .accepted_membership_history(BUDGET)?
                .ok_or_else(invalid)?;
            let payload = checked(decode_pairing_approved_payload_v2(canonical))?;
            let statement = checked(DeviceMembershipAddStatementV1::from_approved_payload_v2(
                canonical,
            ))?;
            checked(statement.verify_and_advance(
                signature,
                request,
                canonical,
                &checked(history.pairing_parent(payload.issuer_certificate.device_id))?,
            ))?;
        } else {
            let stored = self.stored_pairing_join(id)?.ok_or_else(invalid)?;
            if stored.canonical_request != request.canonical_bytes()
                || self.accepted_membership_history(BUDGET)?.is_some()
            {
                return Err(VaultError::OperationConflict);
            }
        }
        self.connection.execute("INSERT INTO pairing_v2_transcripts(pairing_id,role,state,canonical_request,canonical_payload,membership_signature,stored_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![id.to_string(),role,if role=="approver" {"prepared"} else {"awaiting_confirmation"},request.canonical_bytes(),canonical,signature.0.as_slice(),super::devices::timestamp_to_db(now)?])?;
        Ok(())
    }

    fn v2_hosted_binding(&self, id: PairingId) -> Result<Vec<u8>, VaultError> {
        hosted_binding(self.hosted_pairing_intent(id)?)
    }

    pub(crate) fn confirm_pairing_v2(
        &mut self,
        id: PairingId,
        number: &str,
        keys: &DeviceKeys,
    ) -> Result<ConfirmedV2Transcript, VaultError> {
        let stored = self.pairing_v2(id)?.ok_or_else(invalid)?;
        if stored.role != "joiner" {
            return Err(invalid());
        }
        let confirmed = checked(confirm_pairing_transcript_v2(
            &stored.canonical,
            number,
            &stored.request,
        ))?;
        if keys.signing_public_key() != stored.request.request().signing_public_key
            || keys.wrapping_public_key() != stored.request.request().wrapping_public_key
        {
            return Err(invalid());
        }
        if stored.receipt.is_some() {
            self.confirmed_pairing_v2(id, keys)?;
            return Ok(confirmed);
        }
        let receipt = keys.sign_hosted_device_proof(&confirmation_preimage_v2(
            &stored.canonical,
            &stored.request,
            stored.signature,
            &self.v2_hosted_binding(id)?,
        ));
        let changed=self.connection.execute("UPDATE pairing_v2_transcripts SET state='confirmed',confirmation_signature=?2 WHERE pairing_id=?1 AND role='joiner' AND state='awaiting_confirmation' AND confirmation_signature IS NULL",params![id.to_string(),receipt.0.as_slice()])?;
        if changed != 1 {
            return Err(VaultError::OperationConflict);
        }
        Ok(confirmed)
    }

    pub(crate) fn confirmed_pairing_v2(
        &self,
        id: PairingId,
        keys: &DeviceKeys,
    ) -> Result<Option<ConfirmedV2Transcript>, VaultError> {
        let Some(stored) = self.pairing_v2(id)? else {
            return Ok(None);
        };
        if stored.role != "joiner" {
            return Err(invalid());
        }
        let Some(receipt) = stored.receipt else {
            return Ok(None);
        };
        checked(restore_confirmed_pairing_transcript_v2(
            &stored.canonical,
            &stored.request,
            stored.signature,
            &self.v2_hosted_binding(id)?,
            receipt,
            keys,
        ))
        .map(Some)
    }

    /// Recognize the original admission only on the fully verified accepted path.
    /// This returns current public D, without admitting a device or activating keys.
    pub(crate) fn accepted_pairing_v2_endpoint(
        &self,
        stored: &Transcript,
    ) -> Result<Option<MembershipEndpoint>, VaultError> {
        let payload = stored.payload()?;
        let Some((enrollment, objects, endpoint)) = self.accepted_membership_objects(BUDGET)?
        else {
            return Ok(None);
        };
        if !objects.contains(&stored.object()?) {
            return Ok(None);
        }
        let lineage = checked(verify_membership_lineage(
            &enrollment,
            payload.enrollment_record_sha256,
            crate::sync::SyncScope {
                account_id: payload.grant.certificate.account_id,
                workspace_id: payload.grant.certificate.workspace_id,
            },
            &objects
                .iter()
                .map(MembershipEventObject::evidence)
                .collect::<Vec<_>>(),
            stored.endpoint()?,
            endpoint,
            BUDGET,
        ))?;
        let history = lineage.history();
        if endpoint.control_epoch != payload.grant.certificate.control_epoch
            || endpoint.key_epoch != payload.grant.key_epoch
        {
            return Err(VaultError::OperationConflict);
        }
        for (certificate, admission) in [
            (&payload.issuer_certificate, payload.issuer_certificate_id),
            (&payload.grant.certificate, payload.grant.certificate_id),
        ] {
            if history.state().active_devices.get(&certificate.device_id) != Some(certificate)
                || history.admissions().get(&certificate.device_id) != Some(&admission)
            {
                return Err(VaultError::OperationConflict);
            }
        }
        Ok(Some(endpoint))
    }

    pub(crate) fn finish_pairing_v2(&mut self, id: PairingId) -> Result<(), VaultError> {
        let stored = self.pairing_v2(id)?.ok_or_else(invalid)?;
        let payload = stored.payload()?;
        let endpoint = self
            .accepted_pairing_v2_endpoint(&stored)?
            .ok_or_else(invalid)?;
        if (stored.role == "approver" && !matches!(stored.state.as_str(), "prepared" | "accepted"))
            || (stored.role == "joiner"
                && (!matches!(stored.state.as_str(), "confirmed" | "completed")
                    || stored.receipt.is_none()))
        {
            return Err(invalid());
        }
        let tx = self.connection.transaction()?;
        if super::membership::history(&tx, BUDGET)?
            .ok_or_else(invalid)?
            .endpoint()
            != endpoint
        {
            return Err(VaultError::OperationConflict);
        }
        for (id, certificate, display) in [
            (
                payload.issuer_certificate_id,
                &payload.issuer_certificate,
                DeviceDisplayMetadata {
                    device_name: payload.issuer_device_name,
                    platform: payload.issuer_platform,
                },
            ),
            (
                payload.grant.certificate_id,
                &payload.grant.certificate,
                DeviceDisplayMetadata {
                    device_name: stored.request.request().device_name.clone(),
                    platform: stored.request.request().platform,
                },
            ),
        ] {
            super::devices::ensure_active_certificate_tx(&tx, id, certificate, &display, 0, true)?;
        }
        tx.execute(
            "UPDATE pairing_v2_transcripts SET state=?2 WHERE pairing_id=?1",
            params![
                id.to_string(),
                if stored.role == "approver" {
                    "accepted"
                } else {
                    "completed"
                }
            ],
        )?;
        tx.commit()?;
        Ok(())
    }
}
