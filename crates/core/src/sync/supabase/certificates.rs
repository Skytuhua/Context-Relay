use super::*;
use crate::crypto::{CertificateIssuerV1, DeviceCertificateV1};
use context_relay_protocol::{
    DeviceCertificateId, Ed25519PublicKeyBytes, PairingRequestNonce, X25519PublicKeyBytes,
};

/// Untrusted hosted certificates. The vault must anchor their chains before use.
pub struct DeviceCertificateSnapshot {
    pub(crate) scope: SyncScope,
    pub(crate) certificates: Vec<DeviceCertificateV1>,
}

#[cfg(feature = "test-support")]
impl DeviceCertificateSnapshot {
    pub fn from_certificates_for_test(
        scope: SyncScope,
        certificates: Vec<DeviceCertificateV1>,
    ) -> Self {
        Self {
            scope,
            certificates,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CertificateRow {
    id: DeviceCertificateId,
    account_id: AccountId,
    workspace_id: WorkspaceId,
    control_epoch: u32,
    request_nonce: PostgresBytea,
    device_id: DeviceId,
    issuer_kind: String,
    issuer_device_id: Option<DeviceId>,
    issuer_recovery_public_key: Option<PostgresBytea>,
    issuer_signing_public_key: PostgresBytea,
    device_signing_public_key: PostgresBytea,
    device_wrapping_public_key: PostgresBytea,
    signature: PostgresBytea,
}
impl CertificateRow {
    fn certificate(self, scope: SyncScope) -> Result<DeviceCertificateV1, TransportError> {
        if self.account_id != scope.account_id || self.workspace_id != scope.workspace_id {
            return Err(TransportError::Integrity);
        }
        let issuer_key = Ed25519PublicKeyBytes(self.issuer_signing_public_key.fixed()?);
        let issuer = match (
            self.issuer_kind.as_str(),
            self.issuer_device_id,
            self.issuer_recovery_public_key,
        ) {
            ("device", Some(device_id), None) => CertificateIssuerV1::Device {
                device_id,
                signing_public_key: issuer_key,
            },
            ("recovery_root", None, Some(root)) => {
                let root = Ed25519PublicKeyBytes(root.fixed()?);
                if root != issuer_key {
                    return Err(TransportError::Integrity);
                }
                CertificateIssuerV1::RecoveryRoot(root)
            }
            _ => return Err(TransportError::Integrity),
        };
        let certificate = DeviceCertificateV1 {
            issuer,
            account_id: self.account_id,
            workspace_id: self.workspace_id,
            control_epoch: self.control_epoch,
            request_nonce: PairingRequestNonce(self.request_nonce.fixed()?),
            device_id: self.device_id,
            signing_public_key: Ed25519PublicKeyBytes(self.device_signing_public_key.fixed()?),
            wrapping_public_key: X25519PublicKeyBytes(self.device_wrapping_public_key.fixed()?),
            signature: Ed25519SignatureBytes(self.signature.fixed()?),
        };
        certificate
            .verify_issued_by(&certificate.issuer)
            .map_err(|_| TransportError::Integrity)?;
        Ok(certificate)
    }
}
impl SupabaseTransport {
    pub fn fetch_device_certificates(
        &self,
        scope: SyncScope,
    ) -> Result<DeviceCertificateSnapshot, TransportError> {
        let mut after: Option<DeviceCertificateId> = None;
        let mut certificates = Vec::new();
        let mut devices = BTreeSet::new();
        loop {
            let mut url = self.table_url("device_certificates")?;
            url.query_pairs_mut()
                .append_pair("select", "id,account_id,workspace_id,control_epoch,request_nonce,device_id,issuer_kind,issuer_device_id,issuer_recovery_public_key,issuer_signing_public_key,device_signing_public_key,device_wrapping_public_key,signature")
                .append_pair("account_id", &format!("eq.{}", scope.account_id))
                .append_pair("workspace_id", &format!("eq.{}", scope.workspace_id))
                .append_pair("order", "id.asc").append_pair("limit", &MAX_PAGE.to_string());
            if let Some(id) = after {
                url.query_pairs_mut().append_pair("id", &format!("gt.{id}"));
            }
            let rows: Vec<CertificateRow> = self.get_json(url)?;
            if rows.len() > MAX_PAGE {
                return Err(TransportError::Integrity);
            }
            let count = rows.len();
            for row in rows {
                if after.is_some_and(|previous| previous >= row.id)
                    || !devices.insert(row.device_id)
                {
                    return Err(TransportError::Integrity);
                }
                after = Some(row.id);
                certificates.push(row.certificate(scope)?);
                // ponytail: bound a cycle to 4096 devices; paginate trust admission if larger accounts are supported.
                if certificates.len() > 4096 {
                    return Err(TransportError::Configuration);
                }
            }
            if count < MAX_PAGE {
                return Ok(DeviceCertificateSnapshot {
                    scope,
                    certificates,
                });
            }
        }
    }
}
