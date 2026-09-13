//! Durable public acceptance. Canonical replay, never certificate rows, supplies authority.
use super::{CommitDisposition, Vault, VaultError};
use crate::{
    crypto::DeviceKeys,
    devices::{
        crypto::{
            SignedPairingRequest,
            control_v2::{ConfirmedV2Transcript, open_confirmed_pairing_approval_v2},
            verify_pairing_request,
        },
        membership_crypto::{
            DeviceMembershipAddStatementV1, MembershipEndpoint, MembershipHistoryBudget,
            MembershipHistoryEvent, VerifiedMembershipHistory, verify_membership_history,
        },
        revocation_crypto::DeviceRevocationStatementV1,
    },
    sync::SyncScope,
};
use context_relay_protocol::{Ed25519SignatureBytes, Sha256Digest, decode_pairing_request_v1};
use rusqlite::{Connection, TransactionBehavior, params};

pub(super) const CURRENT_BUDGET: MembershipHistoryBudget = MembershipHistoryBudget {
    max_events: 4096,
    max_bytes: 64 * 1024 * 1024,
};
fn invalid() -> VaultError {
    VaultError::Validation("accepted membership authority unavailable".into())
}
pub(super) fn require_legacy_pairing(c: &Connection) -> Result<(), VaultError> {
    if c.query_row("SELECT EXISTS(SELECT 1 FROM accepted_membership) OR EXISTS(SELECT 1 FROM membership_events) OR EXISTS(SELECT 1 FROM revocation_genesis_anchor)",[],|r|r.get::<_,bool>(0))? {return Err(invalid());}
    Ok(())
}
fn crypto<T>(result: Result<T, crate::crypto::CryptoError>) -> Result<T, VaultError> {
    result.map_err(|_| invalid())
}

struct Event {
    parent: Sha256Digest,
    successor: Sha256Digest,
    statement: Vec<u8>,
    signature: Ed25519SignatureBytes,
    request: Option<SignedPairingRequest>,
    artifact: Vec<u8>,
}
impl Event {
    fn evidence(&self) -> MembershipHistoryEvent<'_> {
        match &self.request {
            Some(request) => MembershipHistoryEvent::PairingAdd {
                statement: &self.statement,
                signature: self.signature,
                request,
                approved_payload: &self.artifact,
            },
            None => MembershipHistoryEvent::Revocation {
                statement: &self.statement,
                signature: self.signature,
                transition: &self.artifact,
            },
        }
    }
    fn from_evidence(e: &MembershipHistoryEvent<'_>) -> Result<Self, VaultError> {
        let (statement, signature, request, artifact, parent, successor) = match e {
            MembershipHistoryEvent::PairingAdd {
                statement,
                signature,
                request,
                approved_payload,
            } => {
                let s = crypto(DeviceMembershipAddStatementV1::from_signing_preimage(
                    statement,
                ))?;
                (
                    *statement,
                    *signature,
                    Some((*request).clone()),
                    *approved_payload,
                    s.previous_state_sha256,
                    crypto(s.control_state_sha256(*signature))?,
                )
            }
            MembershipHistoryEvent::Revocation {
                statement,
                signature,
                transition,
            } => {
                let s = crypto(DeviceRevocationStatementV1::from_signing_preimage(
                    statement,
                ))?;
                let t = crypto(
                    crate::devices::revocation_crypto::RevocationTransitionV1::from_canonical_bytes(
                        transition,
                    ),
                )?;
                (
                    *statement,
                    *signature,
                    None,
                    *transition,
                    t.previous_state_sha256,
                    crypto(s.control_state_sha256(*signature))?,
                )
            }
        };
        Ok(Self {
            parent,
            successor,
            statement: statement.to_vec(),
            signature,
            request,
            artifact: artifact.to_vec(),
        })
    }
    fn same(&self, other: &Self) -> bool {
        self.parent == other.parent
            && self.successor == other.successor
            && self.statement == other.statement
            && self.signature == other.signature
            && self.request == other.request
            && self.artifact == other.artifact
    }
}
struct Stored {
    scope: SyncScope,
    pin: Sha256Digest,
    enrollment: Vec<u8>,
    endpoint: MembershipEndpoint,
    events: Vec<Event>,
}
impl Stored {
    fn verify(
        &self,
        budget: MembershipHistoryBudget,
    ) -> Result<VerifiedMembershipHistory, VaultError> {
        crypto(verify_membership_history(
            &self.enrollment,
            self.pin,
            self.scope,
            &self.events.iter().map(Event::evidence).collect::<Vec<_>>(),
            self.endpoint,
            budget,
        ))
    }
}
fn load(c: &Connection, budget: MembershipHistoryBudget) -> Result<Option<Stored>, VaultError> {
    // SQL bounds allocations before extracting any BLOB, even if CHECK constraints were bypassed.
    let counts:(i64,i64,i64)=c.query_row("SELECT (SELECT count(*) FROM accepted_membership), (SELECT count(*) FROM membership_events), COALESCE((SELECT sum(length(statement)+length(signature)+length(request)+length(artifact)) FROM membership_events),0)+COALESCE((SELECT sum(length(enrollment)) FROM accepted_membership),0)",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
    if counts.0 == 0 {
        return if counts.1 == 0 {
            Ok(None)
        } else {
            Err(invalid())
        };
    }
    if counts.0 != 1
        || counts.1 < 0
        || counts.2 < 0
        || counts.1 as u64 > budget.max_events as u64
        || counts.2 as u64 > budget.max_bytes as u64
    {
        return Err(VaultError::BudgetExceeded);
    }
    let raw=c.query_row("SELECT singleton,
        CASE WHEN typeof(account_id)='text' AND length(CAST(account_id AS BLOB))=36 THEN account_id END,
        CASE WHEN typeof(workspace_id)='text' AND length(CAST(workspace_id AS BLOB))=36 THEN workspace_id END,
        CASE WHEN typeof(enrollment_pin)='blob' AND length(enrollment_pin)=32 THEN enrollment_pin END,
        CASE WHEN typeof(enrollment)='blob' AND length(enrollment) BETWEEN 1 AND ?1 THEN enrollment END,
        CASE WHEN typeof(state_hash)='blob' AND length(state_hash)=32 THEN state_hash END,
        control_epoch,key_epoch FROM accepted_membership",[budget.max_bytes as i64],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,Vec<u8>>(3)?,r.get::<_,Vec<u8>>(4)?,r.get::<_,Vec<u8>>(5)?,r.get::<_,u32>(6)?,r.get::<_,u32>(7)?)))?;
    if raw.0 != 1 {
        return Err(invalid());
    }
    let mut stored = Stored {
        scope: SyncScope {
            account_id: raw.1.parse().map_err(|_| invalid())?,
            workspace_id: raw.2.parse().map_err(|_| invalid())?,
        },
        pin: Sha256Digest(raw.3.try_into().map_err(|_| invalid())?),
        enrollment: raw.4,
        endpoint: MembershipEndpoint {
            state_sha256: Sha256Digest(raw.5.try_into().map_err(|_| invalid())?),
            control_epoch: raw.6,
            key_epoch: raw.7,
        },
        events: Vec::new(),
    };
    let mut query=c.prepare("SELECT ordinal,kind,
        CASE WHEN typeof(parent)='blob' AND length(parent)=32 THEN parent END,
        CASE WHEN typeof(successor)='blob' AND length(successor)=32 THEN successor END,
        CASE WHEN typeof(statement)='blob' AND length(statement) BETWEEN 1 AND 512 THEN statement END,
        CASE WHEN typeof(signature)='blob' AND length(signature)=64 THEN signature END,
        CASE WHEN typeof(request)='blob' AND length(request)<=?1 THEN request END,
        CASE WHEN typeof(artifact)='blob' AND length(artifact) BETWEEN 1 AND ?1 THEN artifact END
        FROM membership_events ORDER BY ordinal")?;
    let mut rows = query.query([budget.max_bytes as i64])?;
    while let Some(r) = rows.next()? {
        if r.get::<_, i64>(0)? != stored.events.len() as i64 {
            return Err(invalid());
        }
        let kind = r.get::<_, i64>(1)?;
        let request = r.get::<_, Vec<u8>>(6)?;
        let request = match kind {
            1 => {
                let parsed = decode_pairing_request_v1(&request).map_err(|_| invalid())?;
                let parsed = crypto(verify_pairing_request(&parsed))?;
                if parsed.canonical_bytes() != request {
                    return Err(invalid());
                }
                Some(parsed)
            }
            2 if request.is_empty() => None,
            _ => return Err(invalid()),
        };
        let event = Event {
            parent: Sha256Digest(r.get::<_, Vec<u8>>(2)?.try_into().map_err(|_| invalid())?),
            successor: Sha256Digest(r.get::<_, Vec<u8>>(3)?.try_into().map_err(|_| invalid())?),
            statement: r.get(4)?,
            signature: Ed25519SignatureBytes(
                r.get::<_, Vec<u8>>(5)?.try_into().map_err(|_| invalid())?,
            ),
            request,
            artifact: r.get(7)?,
        };
        let derived = Event::from_evidence(&event.evidence())?;
        if !event.same(&derived)
            || stored
                .events
                .last()
                .is_some_and(|last| last.successor != event.parent)
        {
            return Err(invalid());
        }
        stored.events.push(event);
    }
    Ok(Some(stored))
}
pub(super) fn history(
    c: &Connection,
    budget: MembershipHistoryBudget,
) -> Result<Option<VerifiedMembershipHistory>, VaultError> {
    load(c, budget)?.map(|s| s.verify(budget)).transpose()
}
pub(super) fn require_current(
    c: &Connection,
    scope: SyncScope,
    stamp: Option<MembershipEndpoint>,
) -> Result<Option<VerifiedMembershipHistory>, VaultError> {
    let Some(history) = history(c, CURRENT_BUDGET)? else {
        if c.query_row(
            "SELECT EXISTS(SELECT 1 FROM revocation_genesis_anchor)",
            [],
            |r| r.get::<_, bool>(0),
        )? {
            return Err(invalid());
        }
        return Ok(None);
    };
    if history.state().scope != scope || stamp != Some(history.endpoint()) {
        return Err(VaultError::OperationConflict);
    }
    // Until current-rotation activation is installed, only the authenticated enrollment
    // material can be current. Public acceptance must never activate downloaded keys.
    if history.endpoint().control_epoch != 1 || history.endpoint().key_epoch != 1 {
        return Err(invalid());
    }
    let enrollment = super::recovery::load_recovery_enrollment(c)?.ok_or_else(invalid)?;
    if enrollment.state != super::RecoveryEnrollmentPersistenceState::Active
        || crypto(history.pairing_parent(enrollment.record.genesis_certificate.device_id))?
            .enrollment_record_sha256
            != enrollment.canonical_record_sha256
    {
        return Err(invalid());
    }
    Ok(Some(history))
}
pub(super) fn require_operation(
    c: &Connection,
    operation: &context_relay_protocol::SyncOperationV1,
    stamp: Option<MembershipEndpoint>,
) -> Result<(), VaultError> {
    let scope = SyncScope {
        account_id: operation.account_id,
        workspace_id: operation.workspace_id,
    };
    if let Some(history) = require_current(c, scope, stamp)? {
        let state = history.state();
        let cert = state
            .active_devices
            .get(&operation.device_id)
            .ok_or_else(invalid)?;
        if operation.control_epoch != state.control_epoch || operation.key_epoch != state.key_epoch
        {
            return Err(invalid());
        }
        let bytes = context_relay_protocol::encode_sync_operation_signing_preimage_v1(operation)
            .map_err(|_| invalid())?;
        crypto(crate::crypto::verify_signature(
            cert.signing_public_key,
            &bytes,
            operation.signature,
        ))?;
    }
    Ok(())
}
fn insert_events(c: &Connection, events: &[Event], offset: usize) -> Result<(), VaultError> {
    for (i, e) in events.iter().enumerate() {
        c.execute("INSERT INTO membership_events(successor,parent,ordinal,kind,statement,signature,request,artifact) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",params![e.successor.0.as_slice(),e.parent.0.as_slice(),(offset+i) as i64,if e.request.is_some(){1}else{2},&e.statement,e.signature.0.as_slice(),e.request.as_ref().map(|r|r.canonical_bytes()).unwrap_or(&[]),&e.artifact])?;
    }
    Ok(())
}
pub(super) fn bootstrap(
    c: &Connection,
    enrollment: &[u8],
    pin: Sha256Digest,
    scope: SyncScope,
    endpoint: MembershipEndpoint,
) -> Result<(), VaultError> {
    c.execute("INSERT INTO accepted_membership(singleton,account_id,workspace_id,enrollment_pin,enrollment,state_hash,control_epoch,key_epoch) VALUES(1,?1,?2,?3,?4,?5,?6,?7)",params![scope.account_id.to_string(),scope.workspace_id.to_string(),pin.0.as_slice(),enrollment,endpoint.state_sha256.0.as_slice(),endpoint.control_epoch,endpoint.key_epoch])?;
    Ok(())
}
impl Vault {
    pub(crate) fn require_current_device(
        &self,
        scope: SyncScope,
        stamp: Option<MembershipEndpoint>,
        device: &crate::sync::TrustedDevice,
    ) -> Result<(), VaultError> {
        let tx = self.connection.unchecked_transaction()?;
        if let Some(history) = require_current(&tx, scope, stamp)? {
            let state = history.state();
            if state.active_devices.get(&device.certificate.device_id) != Some(&device.certificate)
                || state.control_epoch != device.active_control_epoch
                || state.key_epoch != device.active_key_epoch
            {
                return Err(VaultError::OperationConflict);
            }
        }
        tx.commit()?;
        Ok(())
    }
    pub(crate) fn require_current_operation(
        &self,
        operation: &context_relay_protocol::SyncOperationV1,
        stamp: Option<MembershipEndpoint>,
    ) -> Result<(), VaultError> {
        let tx = self.connection.unchecked_transaction()?;
        require_operation(&tx, operation, stamp)?;
        tx.commit()?;
        Ok(())
    }
    /// Reauthenticate a single database snapshot under explicit caller budgets.
    pub fn accepted_membership_history(
        &self,
        budget: MembershipHistoryBudget,
    ) -> Result<Option<VerifiedMembershipHistory>, VaultError> {
        let tx = self.connection.unchecked_transaction()?;
        let result = history(&tx, budget)?;
        tx.commit()?;
        Ok(result)
    }
    /// The caller deliberately accepts this exact successor. Public evidence alone never bootstraps trust.
    pub fn accept_membership_extension(
        &mut self,
        expected: MembershipEndpoint,
        successor: MembershipEndpoint,
        extension: &[MembershipHistoryEvent<'_>],
        budget: MembershipHistoryBudget,
    ) -> Result<CommitDisposition, VaultError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut stored = load(&tx, budget)?.ok_or_else(invalid)?;
        stored.verify(budget)?;
        // Budget before copying caller-owned evidence.
        let bytes = extension
            .iter()
            .try_fold(0usize, |n, e| {
                let sizes = match e {
                    MembershipHistoryEvent::PairingAdd {
                        statement,
                        request,
                        approved_payload,
                        ..
                    } => [
                        statement.len(),
                        64,
                        request.canonical_bytes().len(),
                        approved_payload.len(),
                    ],
                    MembershipHistoryEvent::Revocation {
                        statement,
                        transition,
                        ..
                    } => [statement.len(), 64, transition.len(), 0],
                };
                sizes.into_iter().try_fold(n, usize::checked_add)
            })
            .ok_or(VaultError::BudgetExceeded)?;
        if extension.is_empty() || extension.len() > budget.max_events || bytes > budget.max_bytes {
            return Err(VaultError::BudgetExceeded);
        }
        let added = extension
            .iter()
            .map(Event::from_evidence)
            .collect::<Result<Vec<_>, _>>()?;
        if added[0].parent != expected.state_sha256
            || added.last().unwrap().successor != successor.state_sha256
        {
            return Err(VaultError::OperationConflict);
        }
        if stored.endpoint == successor {
            let start = stored
                .events
                .len()
                .checked_sub(added.len())
                .ok_or(VaultError::OperationConflict)?;
            if !stored.events[start..]
                .iter()
                .zip(&added)
                .all(|(a, b)| a.same(b))
            {
                return Err(VaultError::OperationConflict);
            }
            let prefix = Stored {
                scope: stored.scope,
                pin: stored.pin,
                enrollment: stored.enrollment.clone(),
                endpoint: expected,
                events: stored.events.drain(..start).collect(),
            };
            prefix.verify(budget)?;
            tx.commit()?;
            return Ok(CommitDisposition::ExactReplay);
        }
        if stored.endpoint != expected {
            return Err(VaultError::OperationConflict);
        }
        let offset = stored.events.len();
        stored.events.extend(added);
        stored.endpoint = successor;
        stored.verify(budget)?;
        insert_events(&tx, &stored.events[offset..], offset)?;
        let changed=tx.execute("UPDATE accepted_membership SET state_hash=?1,control_epoch=?2,key_epoch=?3 WHERE singleton=1 AND state_hash=?4 AND control_epoch=?5 AND key_epoch=?6",params![successor.state_sha256.0.as_slice(),successor.control_epoch,successor.key_epoch,expected.state_sha256.0.as_slice(),expected.control_epoch,expected.key_epoch])?;
        if changed != 1 {
            return Err(VaultError::OperationConflict);
        }
        tx.commit()?;
        Ok(CommitDisposition::Inserted)
    }
    /// Bootstrap only after independent safety confirmation, complete parent replay and private opening.
    #[allow(clippy::too_many_arguments)]
    pub fn accept_confirmed_membership_admission(
        &mut self,
        enrollment: &[u8],
        parent_events: &[MembershipHistoryEvent<'_>],
        confirmed: &ConfirmedV2Transcript,
        request: &SignedPairingRequest,
        signature: Ed25519SignatureBytes,
        keys: &DeviceKeys,
        budget: MembershipHistoryBudget,
    ) -> Result<CommitDisposition, VaultError> {
        let p = confirmed.payload();
        let scope = SyncScope {
            account_id: p.grant.certificate.account_id,
            workspace_id: p.grant.certificate.workspace_id,
        };
        let parent = MembershipEndpoint {
            state_sha256: confirmed.previous_state_sha256(),
            control_epoch: p.grant.certificate.control_epoch,
            key_epoch: p.grant.key_epoch,
        };
        let statement = crypto(DeviceMembershipAddStatementV1::from_approved_payload_v2(
            confirmed.canonical_bytes(),
        ))?;
        let bytes = crypto(statement.signing_preimage())?;
        let admission_bytes = [
            bytes.len(),
            64,
            request.canonical_bytes().len(),
            confirmed.canonical_bytes().len(),
        ]
        .into_iter()
        .try_fold(0usize, usize::checked_add)
        .ok_or(VaultError::BudgetExceeded)?;
        let parent_budget = MembershipHistoryBudget {
            max_events: budget
                .max_events
                .checked_sub(1)
                .ok_or(VaultError::BudgetExceeded)?,
            max_bytes: budget
                .max_bytes
                .checked_sub(admission_bytes)
                .ok_or(VaultError::BudgetExceeded)?,
        };
        let proof = crypto(verify_membership_history(
            enrollment,
            confirmed.enrollment_record_sha256(),
            scope,
            parent_events,
            parent,
            parent_budget,
        ))?;
        let membership = crypto(statement.verify_and_advance(
            signature,
            request,
            confirmed.canonical_bytes(),
            &crypto(proof.pairing_parent(p.issuer_certificate.device_id))?,
        ))?;
        crypto(open_confirmed_pairing_approval_v2(
            confirmed,
            request,
            keys,
            &proof,
            &membership,
        ))?;
        let mut events = parent_events
            .iter()
            .map(Event::from_evidence)
            .collect::<Result<Vec<_>, _>>()?;
        events.push(Event::from_evidence(&MembershipHistoryEvent::PairingAdd {
            statement: &bytes,
            signature,
            request,
            approved_payload: confirmed.canonical_bytes(),
        })?);
        let endpoint = MembershipEndpoint {
            state_sha256: membership.state().state_sha256,
            ..parent
        };
        let stored = Stored {
            scope,
            pin: confirmed.enrollment_record_sha256(),
            enrollment: enrollment.to_vec(),
            endpoint,
            events,
        };
        stored.verify(budget)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = load(&tx, budget)? {
            existing.verify(budget)?;
            if existing.scope == scope
                && existing.pin == stored.pin
                && existing.enrollment == stored.enrollment
                && existing.endpoint == endpoint
                && existing.events.len() == stored.events.len()
                && existing
                    .events
                    .iter()
                    .zip(&stored.events)
                    .all(|(a, b)| a.same(b))
            {
                tx.commit()?;
                return Ok(CommitDisposition::ExactReplay);
            }
            return Err(VaultError::OperationConflict);
        }
        // Restore resumption has its own pristine-vault exceptions. They are not
        // authority to initialize a different pairing identity in this vault.
        if tx.query_row("SELECT EXISTS(SELECT 1 FROM recovery_restores) OR EXISTS(SELECT 1 FROM hosted_restore_intent)",[],|r|r.get::<_,bool>(0))? {return Err(VaultError::OperationConflict);}
        super::recovery_restore::require_pristine_vault(&tx)?;
        bootstrap(&tx, enrollment, stored.pin, scope, endpoint)?;
        insert_events(&tx, &stored.events, 0)?;
        tx.commit()?;
        Ok(CommitDisposition::Inserted)
    }
}
