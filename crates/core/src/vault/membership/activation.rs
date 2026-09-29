use super::*;
use context_relay_protocol::DeviceId;
use rusqlite::OptionalExtension;

fn preimage(
    c: &Connection,
    stored: &Stored,
    device: DeviceId,
    source: MembershipEndpoint,
) -> Result<Vec<u8>, VaultError> {
    let mut bytes = b"context-relay/current-membership-activation/v1\0".to_vec();
    bytes.extend(stored.scope.account_id.as_bytes());
    bytes.extend(stored.scope.workspace_id.as_bytes());
    bytes.extend(stored.pin.0);
    bytes.extend(device.as_bytes());
    bytes.extend(source.state_sha256.0);
    bytes.extend(source.control_epoch.to_be_bytes());
    bytes.extend(source.key_epoch.to_be_bytes());
    // Bind the exact independent seal, including its recipient-signed provenance.
    let row = c.query_row("SELECT CASE WHEN length(source_hash)=32 THEN source_hash END,source_control_epoch,source_key_epoch,CASE WHEN length(provenance)=32 THEN provenance END,CASE WHEN length(envelope) BETWEEN 1 AND 512 THEN envelope END,CASE WHEN length(signature)=64 THEN signature END FROM membership_epoch_secrets WHERE device_id=?1 AND key_epoch=?2 AND independent_current=1",params![device.to_string(),source.key_epoch],|r|Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,u32>(1)?,r.get::<_,u32>(2)?,r.get::<_,Vec<u8>>(3)?,r.get::<_,Vec<u8>>(4)?,r.get::<_,Vec<u8>>(5)?)))?;
    bytes.extend(row.0);
    bytes.extend(row.1.to_be_bytes());
    bytes.extend(row.2.to_be_bytes());
    bytes.extend(row.3);
    bytes.extend(row.4);
    bytes.extend(row.5);
    Ok(bytes)
}

pub(super) fn active_device(
    c: &Connection,
    stored: &Stored,
    history: &VerifiedMembershipHistory,
) -> Result<Option<DeviceId>, VaultError> {
    let row = c.query_row("SELECT CASE WHEN length(device_id)=36 THEN device_id END,CASE WHEN length(source_hash)=32 THEN source_hash END,control_epoch,key_epoch,CASE WHEN length(signature)=64 THEN signature END FROM membership_current_activation WHERE singleton=1",[],|r|Ok((r.get::<_,String>(0)?,r.get::<_,Vec<u8>>(1)?,r.get::<_,u32>(2)?,r.get::<_,u32>(3)?,r.get::<_,Vec<u8>>(4)?))).optional()?;
    let Some((device, hash, control_epoch, key_epoch, signature)) = row else {
        return Ok(None);
    };
    let device = device.parse().map_err(|_| invalid())?;
    let source = MembershipEndpoint {
        state_sha256: Sha256Digest(hash.try_into().map_err(|_| invalid())?),
        control_epoch,
        key_epoch,
    };
    if (control_epoch, key_epoch) != (stored.endpoint.control_epoch, stored.endpoint.key_epoch) {
        return Err(invalid());
    }
    material::lineage(stored, source, CURRENT_BUDGET)?;
    let cert = history
        .state()
        .active_devices
        .get(&device)
        .ok_or_else(invalid)?;
    crypto(crate::crypto::verify_signature(
        cert.signing_public_key,
        &preimage(c, stored, device, source)?,
        Ed25519SignatureBytes(signature.try_into().map_err(|_| invalid())?),
    ))?;
    Ok(Some(device))
}

impl Vault {
    /// Activate privately opened current keys at exact accepted D. History transfer is independent.
    pub fn activate_current_membership_material(
        &mut self,
        expected: MembershipEndpoint,
        device: DeviceId,
        keys: &DeviceKeys,
        budget: MembershipHistoryBudget,
    ) -> Result<(), VaultError> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        activate(&tx, expected, device, keys, budget)?;
        tx.commit()?;
        Ok(())
    }
}

pub(super) fn activate(
    tx: &rusqlite::Transaction<'_>,
    expected: MembershipEndpoint,
    device: DeviceId,
    keys: &DeviceKeys,
    budget: MembershipHistoryBudget,
) -> Result<(), VaultError> {
    let stored = load(tx, budget)?.ok_or_else(invalid)?;
    material::endpoint_check(&stored, expected, device, keys, budget)?;
    material::load_secret(tx, &stored, device, expected.key_epoch, true, keys, budget)?
        .ok_or_else(invalid)?;
    let signature = keys.sign_hosted_device_proof(&preimage(tx, &stored, device, expected)?);
    tx.execute("INSERT INTO membership_current_activation(singleton,device_id,source_hash,control_epoch,key_epoch,signature) VALUES(1,?1,?2,?3,?4,?5) ON CONFLICT(singleton) DO UPDATE SET device_id=excluded.device_id,source_hash=excluded.source_hash,control_epoch=excluded.control_epoch,key_epoch=excluded.key_epoch,signature=excluded.signature",params![device.to_string(),expected.state_sha256.0.as_slice(),expected.control_epoch,expected.key_epoch,signature.0.as_slice()])?;
    Ok(())
}

pub(in crate::vault) fn current_material(
    c: &Connection,
    keys: &DeviceKeys,
) -> Result<
    Option<(
        crate::devices::pairing::WorkspacePairingMaterial,
        Vec<crate::crypto::DeviceCertificateV1>,
    )>,
    VaultError,
> {
    let Some(stored) = load(c, CURRENT_BUDGET)? else {
        return Ok(None);
    };
    let history = stored.verify(CURRENT_BUDGET)?;
    let Some(device) = active_device(c, &stored, &history)? else {
        return Ok(None);
    };
    material::endpoint_check(&stored, stored.endpoint, device, keys, CURRENT_BUDGET)?;
    let bundle = material::load_secret(
        c,
        &stored,
        device,
        stored.endpoint.key_epoch,
        true,
        keys,
        CURRENT_BUDGET,
    )?
    .ok_or_else(invalid)?;
    let material = crate::devices::pairing::WorkspacePairingMaterial::new(
        stored.scope,
        stored.endpoint.control_epoch,
        stored.endpoint.key_epoch,
        *bundle.workspace_root_key(),
        *bundle.active_epoch_key(),
    )
    .map_err(|_| invalid())?;
    let material = material
        .with_enrollment_record_sha256(stored.pin)
        .map_err(|_| invalid())?;
    Ok(Some((
        material,
        history.state().active_devices.values().cloned().collect(),
    )))
}
