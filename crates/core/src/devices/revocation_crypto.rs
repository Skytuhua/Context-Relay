use context_relay_protocol::{
    AccountId, DeviceId, Ed25519SignatureBytes, OperationId, Sha256Digest, WorkspaceId,
};

use crate::crypto::{CryptoError, DeviceCertificateV1, DeviceKeys, verify_signature};

/// Signed cutoff and commitment to the complete canonical key-rotation transition.
/// This is cryptographic evidence, not standalone authorization: callers must
/// recompute the transition digest, authenticate the issuer against the current
/// roster/control chain and atomically compare-and-swap the previous state/epochs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceRevocationStatementV1 {
    pub schema_version: u16,
    pub revocation_id: OperationId,
    pub account_id: AccountId,
    pub workspace_id: WorkspaceId,
    pub issuer_device_id: DeviceId,
    pub target_device_id: DeviceId,
    pub control_epoch: u32,
    pub key_epoch: u32,
    pub cutoff_sequence: u64,
    pub cutoff_hash: Sha256Digest,
    pub transition_sha256: Sha256Digest,
}

impl DeviceRevocationStatementV1 {
    /// Domain, schema, five UUIDs, two epochs, sequence and two digests, in field
    /// order. UUIDs/digests are raw bytes; integers are fixed-width big-endian.
    pub fn signing_preimage(&self) -> Result<Vec<u8>, CryptoError> {
        if self.schema_version != 1
            || !(1..u32::MAX).contains(&self.control_epoch)
            || !(1..u32::MAX).contains(&self.key_epoch)
            || self.cutoff_sequence > i64::MAX as u64
            || (self.cutoff_sequence == 0) != (self.cutoff_hash.0 == [0; 32])
            || self.transition_sha256.0 == [0; 32]
        {
            return Err(CryptoError::InvalidProtocolValue);
        }
        let mut bytes = b"context-relay/device-revocation/v1\0".to_vec();
        bytes.extend_from_slice(&self.schema_version.to_be_bytes());
        bytes.extend_from_slice(self.revocation_id.as_bytes());
        bytes.extend_from_slice(self.account_id.as_bytes());
        bytes.extend_from_slice(self.workspace_id.as_bytes());
        bytes.extend_from_slice(self.issuer_device_id.as_bytes());
        bytes.extend_from_slice(self.target_device_id.as_bytes());
        bytes.extend_from_slice(&self.control_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.key_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.cutoff_sequence.to_be_bytes());
        bytes.extend_from_slice(&self.cutoff_hash.0);
        bytes.extend_from_slice(&self.transition_sha256.0);
        Ok(bytes)
    }

    fn check_issuer(&self, certificate: &DeviceCertificateV1) -> Result<(), CryptoError> {
        if certificate.account_id != self.account_id
            || certificate.workspace_id != self.workspace_id
            || certificate.device_id != self.issuer_device_id
            || certificate.control_epoch == 0
            || certificate.control_epoch > self.control_epoch
        {
            return Err(CryptoError::AuthenticationFailed);
        }
        Ok(())
    }

    pub fn sign(
        &self,
        certificate: &DeviceCertificateV1,
        device: &DeviceKeys,
    ) -> Result<Ed25519SignatureBytes, CryptoError> {
        self.check_issuer(certificate)?;
        if certificate.signing_public_key != device.signing_public_key()
            || certificate.wrapping_public_key != device.wrapping_public_key()
        {
            return Err(CryptoError::InvalidKey);
        }
        Ok(device.sign_hosted_device_proof(&self.signing_preimage()?))
    }

    /// The supplied certificate must already be authenticated and authorized by
    /// the current control chain. This does not verify its issuer or active status.
    pub fn verify(
        &self,
        certificate: &DeviceCertificateV1,
        signature: Ed25519SignatureBytes,
    ) -> Result<(), CryptoError> {
        let preimage = self.signing_preimage()?;
        self.check_issuer(certificate)?;
        verify_signature(certificate.signing_public_key, &preimage, signature)
    }
}
