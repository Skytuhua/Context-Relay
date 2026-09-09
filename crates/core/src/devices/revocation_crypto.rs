use std::collections::BTreeMap;

use context_relay_protocol::{
    AccountId, DeviceId, Ed25519SignatureBytes, OperationId, RecoveryRootId, Sha256Digest,
    WorkspaceId, X25519PublicKeyBytes,
};
use minicbor::Encoder;
use sha2::{Digest, Sha256};

use crate::crypto::{CryptoError, DeviceCertificateV1, DeviceKeys, verify_signature};
use crate::{
    crypto::{WrappedKeyEnvelope, validate_x25519_public_key},
    devices::crypto::encode_certificate_v1,
    sync::SyncScope,
};

const MAX_ROTATION_DEVICES: usize = 4096;
const MAX_ROTATION_CIPHERTEXT_BYTES: usize = 1024;

/// Trusted inputs from the authenticated control chain, never from the submitted
/// transition. The caller must recheck this state atomically when committing.
pub struct RevocationControlState<'a> {
    pub scope: SyncScope,
    pub control_epoch: u32,
    pub key_epoch: u32,
    pub state_sha256: Sha256Digest,
    pub active_devices: &'a BTreeMap<DeviceId, DeviceCertificateV1>,
    pub recovery_root_id: RecoveryRootId,
    pub recovery_wrapping_public_key: X25519PublicKeyBytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceRotationEnvelopeV1 {
    pub certificate: DeviceCertificateV1,
    pub envelope: WrappedKeyEnvelope,
}

/// Exact encrypted rotation committed to by a DeviceRevocationStatementV1.
/// Recipients must also decrypt their envelope, validate its context/epochs and
/// compare the canonical plaintext bundle's digest with key_material_sha256.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationTransitionV1 {
    pub previous_state_sha256: Sha256Digest,
    pub control_epoch: u32,
    pub key_epoch: u32,
    pub key_material_sha256: Sha256Digest,
    /// Strictly increasing device IDs, containing every remaining active device.
    pub devices: Vec<DeviceRotationEnvelopeV1>,
    pub recovery_root_id: RecoveryRootId,
    pub recovery_wrapping_public_key: X25519PublicKeyBytes,
    pub recovery_envelope: WrappedKeyEnvelope,
}

impl RevocationTransitionV1 {
    /// Domain, previous-state hash, next epochs, plaintext commitment, recipient
    /// count, each length-prefixed canonical certificate and envelope, recovery
    /// root ID/public key/envelope. Integers and lengths are u32 big-endian;
    /// envelope fields are raw ephemeral key, nonce, ciphertext length/ciphertext.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        if self.previous_state_sha256.0 == [0; 32]
            || self.key_material_sha256.0 == [0; 32]
            || self.control_epoch < 2
            || self.key_epoch < 2
            || self.devices.len() > MAX_ROTATION_DEVICES
            || self
                .devices
                .windows(2)
                .any(|pair| pair[0].certificate.device_id >= pair[1].certificate.device_id)
        {
            return Err(CryptoError::InvalidProtocolValue);
        }
        validate_x25519_public_key(self.recovery_wrapping_public_key)?;
        let mut bytes = b"context-relay/device-revocation-transition/v1\0".to_vec();
        bytes.extend_from_slice(&self.previous_state_sha256.0);
        bytes.extend_from_slice(&self.control_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.key_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.key_material_sha256.0);
        bytes.extend_from_slice(&(self.devices.len() as u32).to_be_bytes());
        for recipient in &self.devices {
            let mut encoder = Encoder::new(Vec::new());
            encode_certificate_v1(&mut encoder, &recipient.certificate)?;
            let certificate = encoder.into_writer();
            bytes.extend_from_slice(&(certificate.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&certificate);
            append_rotation_envelope(&mut bytes, &recipient.envelope)?;
        }
        bytes.extend_from_slice(self.recovery_root_id.as_bytes());
        bytes.extend_from_slice(&self.recovery_wrapping_public_key.0);
        append_rotation_envelope(&mut bytes, &self.recovery_envelope)?;
        Ok(bytes)
    }

    pub fn digest(&self) -> Result<Sha256Digest, CryptoError> {
        Ok(Sha256Digest(Sha256::digest(self.canonical_bytes()?).into()))
    }

    /// Verifies the signed transition against a caller-authenticated current
    /// state. Does not decrypt envelopes, validate their plaintext, or commit state.
    pub fn verify(
        &self,
        statement: &DeviceRevocationStatementV1,
        signature: Ed25519SignatureBytes,
        current: &RevocationControlState<'_>,
    ) -> Result<(), CryptoError> {
        let invalid = CryptoError::AuthenticationFailed;
        let issuer = current
            .active_devices
            .get(&statement.issuer_device_id)
            .ok_or(invalid)?;
        statement.verify(issuer, signature)?;
        if statement.account_id != current.scope.account_id
            || statement.workspace_id != current.scope.workspace_id
            || statement.control_epoch != current.control_epoch
            || statement.key_epoch != current.key_epoch
            || self.previous_state_sha256 != current.state_sha256
            || current.control_epoch.checked_add(1) != Some(self.control_epoch)
            || current.key_epoch.checked_add(1) != Some(self.key_epoch)
            || self.recovery_root_id != current.recovery_root_id
            || self.recovery_wrapping_public_key != current.recovery_wrapping_public_key
            || current.active_devices.len() > MAX_ROTATION_DEVICES
            || !current
                .active_devices
                .contains_key(&statement.target_device_id)
            || self.devices.len() + 1 != current.active_devices.len()
        {
            return Err(invalid);
        }
        for (id, certificate) in current.active_devices {
            if *id != certificate.device_id
                || certificate.account_id != current.scope.account_id
                || certificate.workspace_id != current.scope.workspace_id
                || certificate.control_epoch == 0
                || certificate.control_epoch > current.control_epoch
            {
                return Err(invalid);
            }
        }
        let remaining = current
            .active_devices
            .values()
            .filter(|certificate| certificate.device_id != statement.target_device_id);
        if self
            .devices
            .iter()
            .zip(remaining)
            .any(|(recipient, certificate)| recipient.certificate != *certificate)
            || self.digest()? != statement.transition_sha256
        {
            return Err(invalid);
        }
        Ok(())
    }
}

fn append_rotation_envelope(
    bytes: &mut Vec<u8>,
    envelope: &WrappedKeyEnvelope,
) -> Result<(), CryptoError> {
    if !(16..=MAX_ROTATION_CIPHERTEXT_BYTES).contains(&envelope.ciphertext.len()) {
        return Err(CryptoError::InvalidProtocolValue);
    }
    validate_x25519_public_key(envelope.ephemeral_public_key)?;
    bytes.extend_from_slice(&envelope.ephemeral_public_key.0);
    bytes.extend_from_slice(&envelope.nonce.0);
    bytes.extend_from_slice(&(envelope.ciphertext.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&envelope.ciphertext);
    Ok(())
}

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
