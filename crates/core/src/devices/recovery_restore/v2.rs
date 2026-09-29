//! Native root recovery: bounded public evidence, durable preparation, admission.
use super::*;
use crate::devices::{
    membership_crypto::MembershipHistoryBudget,
    membership_transport::{MembershipEventObject, enrollment_endpoint},
    recovery_restore_crypto::{authenticate_recovery_root, v2::*},
};
use std::collections::BTreeSet;

const BUDGET: MembershipHistoryBudget = MembershipHistoryBudget {
    max_events: 4096,
    max_bytes: 64 * 1024 * 1024,
};

impl<C, E, T> RecoveryRestoreCoordinator<C, E, T>
where
    C: RecoveryEnrollmentClock,
    E: RecoveryEnrollmentEntropy,
    T: RecoveryRestoreTransport,
{
    pub(super) fn recover_v2(
        &self,
        vault: &mut Vault,
        words: RecoveryPhraseWords,
        identity: &RecoveryRestoreIdentity<'_>,
    ) -> Result<RecoveryRestoreOutcome, RecoveryRestoreCycleError> {
        validate_identity(identity)?;
        if vault.recovery_restore().map_err(map_vault_error)?.is_some()
            || vault
                .prepared_recovery_v2(identity.keys)
                .map_err(map_vault_error)?
                .is_some()
        {
            return Err(RecoveryRestoreCycleError::Conflict);
        }
        let scope = self.transport.scope();
        let snapshot = self
            .transport
            .root_snapshot()
            .map_err(map_initial_transport_error)?
            .ok_or(RecoveryRestoreCycleError::Unavailable)?;
        snapshot
            .validate_for(scope)
            .map_err(map_initial_transport_error)?;
        let candidate = self
            .transport
            .membership_endpoint()
            .map_err(map_initial_transport_error)?;
        let genesis = enrollment_endpoint(
            &snapshot.canonical_record,
            snapshot.canonical_record_sha256,
            scope,
        )
        .map_err(|_| RecoveryRestoreCycleError::Conflict)?;
        let mut address = candidate.state_sha256;
        let mut seen = BTreeSet::new();
        let mut objects = Vec::new();
        let mut bytes = snapshot.canonical_record.len();
        while address != genesis.state_sha256 {
            if objects.len() >= BUDGET.max_events || !seen.insert(address.0) {
                return Err(RecoveryRestoreCycleError::Conflict);
            }
            let object = self
                .transport
                .membership_event(address)
                .map_err(map_initial_transport_error)?
                .ok_or(RecoveryRestoreCycleError::Unavailable)?;
            bytes = bytes
                .checked_add(object.canonical_bytes().len())
                .filter(|n| *n <= BUDGET.max_bytes)
                .ok_or(RecoveryRestoreCycleError::Conflict)?;
            let (parent, successor) = object
                .endpoints()
                .map_err(|_| RecoveryRestoreCycleError::Conflict)?;
            if successor != address {
                return Err(RecoveryRestoreCycleError::Conflict);
            }
            address = parent;
            objects.push(object);
        }
        objects.reverse();
        let phrase =
            RecoveryPhrase::from_words(words).map_err(|_| RecoveryRestoreCycleError::Invalid)?;
        let root = authenticate_recovery_root(
            &snapshot.canonical_record,
            snapshot.canonical_record_sha256,
            phrase,
        )
        .map_err(|_| RecoveryRestoreCycleError::Invalid)?;
        let evidence = objects
            .iter()
            .map(MembershipEventObject::evidence)
            .collect::<Vec<_>>();
        let authority = authenticate_recovery_history(root, &evidence, candidate, BUDGET)
            .map_err(|_| RecoveryRestoreCycleError::Conflict)?;
        let restore_id = self.entropy_uuid_v7::<RecoveryRestoreId>()?;
        let certificate_id = self.entropy_uuid_v7::<DeviceCertificateId>()?;
        let nonce = PairingRequestNonce(self.entropy_array()?);
        let mut rng = RestoreEntropyRng {
            source: &self.entropy,
            failed: false,
        };
        let result = build_recovery_device_claim_v2_inner(
            &authority,
            restore_id,
            snapshot.recovery_generation,
            certificate_id,
            nonce,
            identity.device_id,
            identity.device_name.clone(),
            identity.platform,
            identity.keys,
            &mut rng,
        );
        let claim = result.map_err(|_| {
            if rng.failed {
                RecoveryRestoreCycleError::Transient
            } else {
                RecoveryRestoreCycleError::Invalid
            }
        })?;
        let canonical = encode_recovery_device_claim_v2(&claim)
            .map_err(|_| RecoveryRestoreCycleError::Invalid)?;
        let retained = authority
            .seal_historical_keys(&claim, identity.keys)
            .map_err(|_| RecoveryRestoreCycleError::Invalid)?;
        vault
            .prepare_recovery_v2(
                &snapshot.canonical_record,
                &canonical,
                &objects,
                &retained,
                identity.keys,
            )
            .map_err(map_vault_error)?;
        drop(authority);
        self.resume_v2(vault, identity)
    }

    pub(super) fn resume_v2(
        &self,
        vault: &mut Vault,
        identity: &RecoveryRestoreIdentity<'_>,
    ) -> Result<RecoveryRestoreOutcome, RecoveryRestoreCycleError> {
        let prepared = vault
            .prepared_recovery_v2(identity.keys)
            .map_err(map_vault_error)?
            .ok_or(RecoveryRestoreCycleError::Invalid)?;
        let claim = &prepared.claim;
        let restore_id = claim.restore_id;
        if self.transport.scope()
            != (SyncScope {
                account_id: claim.account_id,
                workspace_id: claim.workspace_id,
            })
            || identity.device_id != claim.certificate.device_id
            || identity.device_name != claim.device_name
            || identity.platform != claim.device_platform
        {
            return Err(RecoveryRestoreCycleError::Conflict);
        }
        if prepared.publication_conflict {
            return Ok(RecoveryRestoreOutcome::Conflict { restore_id });
        }
        if vault
            .recovery_membership_admission(identity.keys)
            .map_err(map_vault_error)?
            .is_some()
        {
            return Ok(RecoveryRestoreOutcome::RestoringHistory { restore_id });
        }
        let pending = || RecoveryRestoreOutcome::Submitting { restore_id };
        let receipt = match self
            .transport
            .submit_restore(&prepared.canonical_claim, self.clock.now_ms())
        {
            Ok(receipt) => receipt,
            Err(RecoveryTransportError::PublicationRejected) => {
                vault
                    .mark_recovery_publication_conflict(&prepared.canonical_claim, identity.keys)
                    .map_err(map_vault_error)?;
                return Ok(RecoveryRestoreOutcome::Conflict { restore_id });
            }
            Err(RecoveryTransportError::Transient | RecoveryTransportError::Expired) => {
                return Ok(pending());
            }
            Err(error) => return Err(map_initial_transport_error(error)),
        };
        receipt
            .validate_v2(claim)
            .map_err(map_initial_transport_error)?;
        let projection = match self.transport.restore_claim(restore_id) {
            Ok(Some(projection)) => projection,
            Ok(None) | Err(RecoveryTransportError::Transient | RecoveryTransportError::Expired) => {
                return Ok(pending());
            }
            Err(error) => return Err(map_initial_transport_error(error)),
        };
        let successor = recovery_membership_successor(claim)
            .map_err(|_| RecoveryRestoreCycleError::Conflict)?;
        let published = match self.transport.membership_event(successor) {
            Ok(Some(object)) => object,
            Ok(None) | Err(RecoveryTransportError::Transient | RecoveryTransportError::Expired) => {
                return Ok(pending());
            }
            Err(error) => return Err(map_initial_transport_error(error)),
        };
        vault
            .accept_recovery_membership(&receipt, &projection, &published, identity.keys)
            .map_err(map_vault_error)?;
        Ok(RecoveryRestoreOutcome::RestoringHistory { restore_id })
    }
}
