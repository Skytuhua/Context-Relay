use super::*;
use crate::devices::{crypto::control_v2::*, membership_crypto::*, membership_transport::*};
use crate::vault::pairing_v2::{BUDGET, Transcript};

type PairingParentProof = (Vec<u8>, Vec<MembershipEventObject>);

impl<
    C: PairingClock,
    M: PairingMaterialSource,
    J: PairingJoinTransport,
    A: PairingApprovalTransport,
> PairingCoordinator<C, M, J, A>
{
    pub(super) fn cache_v2_parent_proof(
        &self,
        vault: &mut Vault,
        stored: &Transcript,
    ) -> Result<Option<PairingParentProof>, PairingCycleError> {
        let id = stored.request.request().pairing_id;
        let payload = stored.payload().map_err(map_vault_error)?;
        let scope = SyncScope {
            account_id: payload.grant.certificate.account_id,
            workspace_id: payload.grant.certificate.workspace_id,
        };
        let pin = payload.enrollment_record_sha256;
        let enrollment = match vault
            .pairing_public_object(id, "enrollment", pin)
            .map_err(map_vault_error)?
        {
            Some(bytes) => bytes,
            None => {
                let Some(bytes) = self
                    .join_transport
                    .enrollment(id, stored.request.digest(), pin, self.clock.now_ms())
                    .map_err(map_transport_error)?
                else {
                    return Ok(None);
                };
                enrollment_endpoint(&bytes, pin, scope).map_err(|_| PairingCycleError::Invalid)?;
                vault
                    .cache_pairing_public_object(id, "enrollment", pin, &bytes)
                    .map_err(map_vault_error)?;
                bytes
            }
        };
        let genesis =
            enrollment_endpoint(&enrollment, pin, scope).map_err(|_| PairingCycleError::Invalid)?;
        let mut address = payload.previous_state_sha256;
        let mut events = Vec::new();
        let mut bytes = enrollment.len();
        let mut visited = std::collections::BTreeSet::new();
        while address != genesis.state_sha256 {
            if events.len() >= BUDGET.max_events || !visited.insert(address.0) {
                return Err(PairingCycleError::Invalid);
            }
            let event = match vault
                .pairing_public_object(id, "event", address)
                .map_err(map_vault_error)?
            {
                Some(bytes) => MembershipEventObject::from_canonical_bytes(&bytes)
                    .map_err(|_| PairingCycleError::Invalid)?,
                None => {
                    let Some(event) = self
                        .join_transport
                        .membership_event(id, stored.request.digest(), address, self.clock.now_ms())
                        .map_err(map_transport_error)?
                    else {
                        return Ok(None);
                    };
                    if event.endpoints().map_err(|_| PairingCycleError::Invalid)?.1 != address {
                        return Err(PairingCycleError::Conflict);
                    }
                    vault
                        .cache_pairing_public_object(id, "event", address, &event.canonical_bytes())
                        .map_err(map_vault_error)?;
                    event
                }
            };
            bytes = bytes
                .checked_add(event.canonical_bytes().len())
                .filter(|n| *n <= BUDGET.max_bytes)
                .ok_or(PairingCycleError::Invalid)?;
            let (parent, successor) = event.endpoints().map_err(|_| PairingCycleError::Invalid)?;
            if successor != address {
                return Err(PairingCycleError::Conflict);
            }
            address = parent;
            events.push(event);
        }
        events.reverse();
        // This inventory is deliberately not accepted. Confirmation and full replay follow.
        Ok(Some((enrollment, events)))
    }

    pub(super) fn decide_v2(
        &self,
        vault: &mut Vault,
        request: &SignedPairingRequest,
        authority: &PairingApprovalAuthority<'_>,
        material: &WorkspacePairingMaterial,
        issuer: &StoredDeviceCertificate,
    ) -> Result<PairingDecisionStatus, PairingCycleError> {
        let id = request.request().pairing_id;
        if let Some(stored) = vault.pairing_v2(id).map_err(map_vault_error)? {
            let payload = stored.payload().map_err(map_vault_error)?;
            if stored.role != "approver"
                || stored.request != *request
                || payload.grant.certificate_id != authority.certificate_id
                || payload.issuer_certificate_id != authority.issuer_certificate_id
                || payload.issuer_certificate != issuer.certificate
            {
                return Err(PairingCycleError::Conflict);
            }
            self.require_v2_issuer(vault, &stored)?;
            let number = approver_safety_number_v2(&stored.canonical, request)
                .map_err(|_| PairingCycleError::Invalid)?;
            if stored.state == "prepared" {
                self.resume_v2_approval(vault, stored)?;
            }
            return Ok(PairingDecisionStatus::Approved {
                safety_number: number,
            });
        }
        let history = vault
            .accepted_membership_history(BUDGET)
            .map_err(map_vault_error)?
            .ok_or(PairingCycleError::Conflict)?;
        if self
            .approval_transport
            .membership_endpoint(self.clock.now_ms())
            .map_err(map_transport_error)?
            != history.endpoint()
        {
            return Err(PairingCycleError::Conflict);
        }
        let parent = history
            .pairing_parent(issuer.certificate.device_id)
            .map_err(|_| PairingCycleError::Conflict)?;
        if parent.issuer_certificate_id != authority.issuer_certificate_id
            || issuer.state != DeviceCertificateState::Active
        {
            return Err(PairingCycleError::Conflict);
        }
        let built = build_pairing_approval_v2(
            request,
            &parent,
            issuer.certificate.device_id,
            authority.issuer_keys,
            authority.certificate_id,
            &issuer.display.device_name,
            issuer.display.platform,
            &material.bundle,
        )
        .map_err(|_| PairingCycleError::Invalid)?;
        let canonical = encode_pairing_approved_payload_v2(&built.payload)
            .map_err(|_| PairingCycleError::Invalid)?;
        let statement = DeviceMembershipAddStatementV1::from_approved_payload_v2(&canonical)
            .map_err(|_| PairingCycleError::Invalid)?;
        let signature = statement
            .sign(&issuer.certificate, authority.issuer_keys)
            .map_err(|_| PairingCycleError::Invalid)?;
        vault
            .store_pairing_v2(
                request,
                &canonical,
                signature,
                "approver",
                self.clock.now_ms(),
            )
            .map_err(map_vault_error)?;
        let stored = vault
            .pairing_v2(id)
            .map_err(map_vault_error)?
            .ok_or(PairingCycleError::Conflict)?;
        self.resume_v2_approval(vault, stored)?;
        Ok(PairingDecisionStatus::Approved {
            safety_number: built.safety_number,
        })
    }

    pub(super) fn require_v2_issuer(
        &self,
        vault: &Vault,
        stored: &Transcript,
    ) -> Result<(), PairingCycleError> {
        let payload = stored.payload().map_err(map_vault_error)?;
        let history = vault
            .accepted_membership_history(BUDGET)
            .map_err(map_vault_error)?
            .ok_or(PairingCycleError::Conflict)?;
        let state = history.state();
        if state
            .active_devices
            .get(&payload.issuer_certificate.device_id)
            != Some(&payload.issuer_certificate)
            || history
                .admissions()
                .get(&payload.issuer_certificate.device_id)
                != Some(&payload.issuer_certificate_id)
            || state.control_epoch != payload.grant.certificate.control_epoch
            || state.key_epoch != payload.grant.key_epoch
        {
            return Err(PairingCycleError::Conflict);
        }
        let (_, objects, endpoint) = vault
            .accepted_membership_objects(BUDGET)
            .map_err(map_vault_error)?
            .ok_or(PairingCycleError::Conflict)?;
        let object = stored.object().map_err(map_vault_error)?;
        if !(stored.state == "prepared" && endpoint.state_sha256 == payload.previous_state_sha256)
            && !objects.contains(&object)
        {
            return Err(PairingCycleError::Conflict);
        }
        Ok(())
    }

    pub(super) fn resume_v2_approval(
        &self,
        vault: &mut Vault,
        stored: Transcript,
    ) -> Result<(), PairingCycleError> {
        let id = stored.request.request().pairing_id;
        bind_pairing_identity(
            vault,
            id,
            self.approval_transport.hosted_intent(),
            HostedPairingRole::Approve,
            false,
        )?;
        self.require_v2_issuer(vault, &stored)?;
        let accepted = vault
            .accepted_pairing_v2_endpoint(&stored)
            .map_err(map_vault_error)?;
        let receipt = self
            .approval_transport
            .decide(
                PairingDecisionEnvelope::approve_request_v2(
                    &stored.request,
                    stored.canonical.clone(),
                    stored.signature,
                ),
                self.clock.now_ms(),
            )
            .map_err(map_transport_error)?;
        if receipt.pairing_id != id
            || receipt.request_digest != stored.request.digest()
            || receipt.decision != PairingDecisionKind::Approved
            || receipt.approved_payload_digest
                != Some(Sha256Digest(Sha256::digest(&stored.canonical).into()))
        {
            return Err(PairingCycleError::Conflict);
        }
        let payload = stored.payload().map_err(map_vault_error)?;
        let endpoint = stored.endpoint().map_err(map_vault_error)?;
        let parent = MembershipEndpoint {
            state_sha256: payload.previous_state_sha256,
            ..endpoint
        };
        let object = stored.object().map_err(map_vault_error)?;
        if accepted.is_none() {
            vault
                .accept_membership_extension(parent, endpoint, &[object.evidence()], BUDGET)
                .map_err(map_vault_error)?;
        }
        vault.finish_pairing_v2(id).map_err(map_vault_error)
    }

    /// A persisted independently signed confirmation can resume without another comparison.
    /// Missing objects leave that receipt and accepted authority unchanged.
    pub fn resume_confirmed_join(
        &self,
        vault: &mut Vault,
        id: PairingId,
        keys: &DeviceKeys,
    ) -> Result<Option<WorkspacePairingMaterial>, PairingCycleError> {
        let Some(confirmed) = vault
            .confirmed_pairing_v2(id, keys)
            .map_err(map_vault_error)?
        else {
            return Ok(None);
        };
        bind_pairing_identity(
            vault,
            id,
            self.join_transport.hosted_intent(),
            HostedPairingRole::Join,
            false,
        )?;
        let stored = vault
            .pairing_v2(id)
            .map_err(map_vault_error)?
            .ok_or(PairingCycleError::Conflict)?;
        if stored.state == "completed" {
            return self.completed_material(vault, id, keys);
        }
        let endpoint = match vault
            .accepted_pairing_v2_endpoint(&stored)
            .map_err(map_vault_error)?
        {
            Some(endpoint) => endpoint,
            None => {
                let Some((enrollment, events)) = self.cache_v2_parent_proof(vault, &stored)? else {
                    return Ok(None);
                };
                vault
                    .accept_confirmed_membership_admission(
                        &enrollment,
                        &events
                            .iter()
                            .map(|event| event.evidence())
                            .collect::<Vec<_>>(),
                        &confirmed,
                        &stored.request,
                        stored.signature,
                        keys,
                        BUDGET,
                    )
                    .map_err(map_vault_error)?;
                stored.endpoint().map_err(map_vault_error)?
            }
        };
        vault
            .activate_current_membership_material(
                endpoint,
                stored.request.request().device_id,
                keys,
                BUDGET,
            )
            .map_err(map_vault_error)?;
        vault.finish_pairing_v2(id).map_err(map_vault_error)?;
        vault
            .trusted_workspace_material(keys)
            .map(Some)
            .map_err(map_vault_error)
    }
}
