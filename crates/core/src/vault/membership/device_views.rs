//! Display/caller projections of fully accepted public membership, never provider rows.
use super::*;
use crate::vault::{DeviceCertificateState, DeviceDisplayMetadata, StoredDeviceCertificate};

pub(super) fn devices(c: &Connection) -> Result<Option<Vec<StoredDeviceCertificate>>, VaultError> {
    let Some(stored) = load(c, CURRENT_BUDGET)? else {
        return Ok(None);
    };
    let history = stored.verify(CURRENT_BUDGET)?;
    let root =
        crate::devices::recovery_crypto::decode_recovery_enrollment_record_v1(&stored.enrollment)
            .map_err(|_| invalid())?;
    let mut admissions = vec![(
        root.genesis_certificate_id,
        root.genesis_certificate,
        root.device_name,
        root.device_platform,
    )];
    for event in &stored.events {
        match event.evidence() {
            MembershipHistoryEvent::RecoveryAdd { canonical_claim } => {
                let claim =
                    crate::devices::recovery_restore_crypto::v2::decode_recovery_device_claim_v2(
                        canonical_claim,
                    )
                    .map_err(|_| invalid())?;
                admissions.push((
                    claim.certificate_id,
                    claim.certificate,
                    claim.device_name,
                    claim.device_platform,
                ));
            }
            MembershipHistoryEvent::PairingAdd {
                request,
                approved_payload,
                ..
            } => {
                let payload = crypto(
                    crate::devices::crypto::control_v2::decode_pairing_approved_payload_v2(
                        approved_payload,
                    ),
                )?;
                admissions.push((
                    payload.grant.certificate_id,
                    payload.grant.certificate,
                    request.request().device_name.clone(),
                    request.request().platform,
                ));
            }
            MembershipHistoryEvent::Revocation { .. } => {}
        }
    }
    let mut result = Vec::with_capacity(admissions.len());
    for (certificate_id, certificate, device_name, platform) in admissions {
        if history.admissions().get(&certificate.device_id) != Some(&certificate_id) {
            return Err(invalid());
        }
        let state =
            if history.state().active_devices.get(&certificate.device_id) == Some(&certificate) {
                DeviceCertificateState::Active
            } else {
                DeviceCertificateState::Revoked
            };
        let canonical_bytes = crypto(crate::devices::crypto::encode_device_certificate_v1(
            &certificate,
        ))?;
        let canonical_sha256 = Sha256Digest(sha2::Sha256::digest(&canonical_bytes).into());
        // Keep a legacy observation timestamp for enrollment receipt revalidation;
        // certificate, state and display metadata still come solely from accepted history.
        let legacy = c.query_row("SELECT account_id,workspace_id,device_id,canonical_bytes,canonical_sha256,device_name,platform,state,stored_at_ms FROM device_certificates WHERE certificate_id=?1",
            [certificate_id.to_string()], |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,Vec<u8>>(3)?,row.get::<_,Vec<u8>>(4)?,row.get::<_,String>(5)?,row.get::<_,String>(6)?,row.get::<_,String>(7)?,row.get::<_,i64>(8)?))).optional()?;
        let recorded = if let Some(row) = legacy {
            let platform_name = match platform {
                context_relay_protocol::NativePlatform::Windows => "windows",
                context_relay_protocol::NativePlatform::Macos => "macos",
            };
            if row.0 != certificate.account_id.to_string()
                || row.1 != certificate.workspace_id.to_string()
                || row.2 != certificate.device_id.to_string()
                || row.3 != canonical_bytes
                || row.4 != canonical_sha256.0
                || row.5 != device_name
                || row.6 != platform_name
                || !matches!(row.7.as_str(), "active" | "revoked")
                || (row.7 == "revoked" && state == DeviceCertificateState::Active)
            {
                return Err(invalid());
            }
            row.8.try_into().map_err(|_| invalid())?
        } else {
            0
        };
        result.push(StoredDeviceCertificate {
            certificate_id,
            certificate,
            state,
            display: DeviceDisplayMetadata {
                device_name,
                platform,
            },
            stored_at_ms: recorded,
            canonical_bytes,
            canonical_sha256,
        });
    }
    result.sort_by_key(|row| row.certificate.device_id);
    Ok(Some(result))
}
use rusqlite::OptionalExtension;
use sha2::Digest;

impl Vault {
    pub(in crate::vault) fn accepted_device_views(
        &self,
    ) -> Result<Option<Vec<StoredDeviceCertificate>>, VaultError> {
        devices(&self.connection)
    }
}
