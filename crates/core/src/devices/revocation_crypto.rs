use std::collections::BTreeMap;

use context_relay_protocol::{
    AccountId, DeviceId, Ed25519SignatureBytes, OperationId, RecoveryRootId, Sha256Digest,
    WorkspaceId, X25519PublicKeyBytes, XChaChaNonce,
};
use minicbor::{Decoder, Encoder};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::{CryptoError, DeviceCertificateV1, DeviceKeys, verify_signature};
use crate::{
    crypto::{RecoveryKeys, WrappedKeyEnvelope, validate_x25519_public_key, wrap_secret},
    devices::crypto::{
        PairingKeyBundle, certificate_digest, decode_certificate_v1, decode_pairing_key_bundle_v1,
        encode_certificate_v1, encode_pairing_key_bundle_v1,
    },
    sync::SyncScope,
};

const MAX_ROTATION_DEVICES: usize = 4096;
const MAX_ROTATION_CIPHERTEXT_BYTES: usize = 1024;
const MAX_ROTATION_CERTIFICATE_BYTES: usize = 512;
const MAX_ROTATION_BYTES: usize = 8 * 1024 * 1024;
const ROTATION_DOMAIN: &[u8] = b"context-relay/device-revocation-transition/v1\0";
const STATEMENT_DOMAIN: &[u8] = b"context-relay/device-revocation/v1\0";
const DEVICE_MATERIAL_DOMAIN: &[u8] = b"context-relay/revocation-device-material/v1\0";
const RECOVERY_MATERIAL_DOMAIN: &[u8] = b"context-relay/revocation-recovery-material/v1\0";

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
    /// Generate fresh workspace/epoch keys and sign their encrypted distribution.
    /// Replaces the input statement's transition digest. Persist these exact
    /// artifacts for retries; do not regenerate them for the same operation ID.
    /// No local or hosted control state is changed by this function.
    pub fn build(
        mut statement: DeviceRevocationStatementV1,
        device: &DeviceKeys,
        current: &RevocationControlState<'_>,
    ) -> Result<(DeviceRevocationStatementV1, Self, Ed25519SignatureBytes), CryptoError> {
        statement.context_preimage()?;
        let invalid = CryptoError::AuthenticationFailed;
        let issuer = current
            .active_devices
            .get(&statement.issuer_device_id)
            .ok_or(invalid)?;
        statement.check_signer(issuer, device)?;
        if current.active_devices.len() > MAX_ROTATION_DEVICES
            || statement.account_id != current.scope.account_id
            || statement.workspace_id != current.scope.workspace_id
            || statement.control_epoch != current.control_epoch
            || statement.key_epoch != current.key_epoch
            || !current
                .active_devices
                .contains_key(&statement.target_device_id)
            || current.state_sha256.0 == [0; 32]
        {
            return Err(invalid);
        }
        let mut root_key = Zeroizing::new([0; 32]);
        let mut epoch_key = Zeroizing::new([0; 32]);
        OsRng
            .try_fill_bytes(&mut *root_key)
            .map_err(|_| CryptoError::RandomnessUnavailable)?;
        OsRng
            .try_fill_bytes(&mut *epoch_key)
            .map_err(|_| CryptoError::RandomnessUnavailable)?;
        let material = PairingKeyBundle::new(
            current.scope,
            current.control_epoch + 1,
            current.key_epoch + 1,
            *root_key,
            *epoch_key,
        )?;
        let plaintext = encode_pairing_key_bundle_v1(&material)?;
        let commitment = Sha256Digest(Sha256::digest(&*plaintext).into());
        let mut devices = Vec::new();
        for certificate in current
            .active_devices
            .values()
            .filter(|certificate| certificate.device_id != statement.target_device_id)
        {
            let aad = rotation_material_aad(
                &statement,
                current.state_sha256,
                commitment,
                DEVICE_MATERIAL_DOMAIN,
                certificate.device_id.as_bytes(),
                &certificate_digest(certificate)?.0,
            )?;
            devices.push(DeviceRotationEnvelopeV1 {
                certificate: certificate.clone(),
                envelope: wrap_secret(certificate.wrapping_public_key, &plaintext, &aad)?,
            });
        }
        let aad = rotation_material_aad(
            &statement,
            current.state_sha256,
            commitment,
            RECOVERY_MATERIAL_DOMAIN,
            current.recovery_root_id.as_bytes(),
            &current.recovery_wrapping_public_key.0,
        )?;
        let transition = Self {
            previous_state_sha256: current.state_sha256,
            control_epoch: material.control_epoch(),
            key_epoch: material.key_epoch(),
            key_material_sha256: commitment,
            devices,
            recovery_root_id: current.recovery_root_id,
            recovery_wrapping_public_key: current.recovery_wrapping_public_key,
            recovery_envelope: wrap_secret(current.recovery_wrapping_public_key, &plaintext, &aad)?,
        };
        statement.transition_sha256 = transition.digest()?;
        let signature = statement.sign(issuer, device)?;
        transition.verify(&statement, signature, current)?;
        Ok((statement, transition, signature))
    }

    pub fn open_device_material(
        &self,
        statement: &DeviceRevocationStatementV1,
        signature: Ed25519SignatureBytes,
        current: &RevocationControlState<'_>,
        device_id: DeviceId,
        keys: &DeviceKeys,
    ) -> Result<PairingKeyBundle, CryptoError> {
        self.verify(statement, signature, current)?;
        let recipient = self
            .devices
            .iter()
            .find(|entry| entry.certificate.device_id == device_id)
            .ok_or(CryptoError::AuthenticationFailed)?;
        if recipient.certificate.signing_public_key != keys.signing_public_key()
            || recipient.certificate.wrapping_public_key != keys.wrapping_public_key()
        {
            return Err(CryptoError::InvalidKey);
        }
        let aad = rotation_material_aad(
            statement,
            self.previous_state_sha256,
            self.key_material_sha256,
            DEVICE_MATERIAL_DOMAIN,
            device_id.as_bytes(),
            &certificate_digest(&recipient.certificate)?.0,
        )?;
        let plaintext = keys.unwrap_secret(&recipient.envelope, &aad)?;
        self.opened_material(statement, plaintext.expose())
    }

    pub fn open_recovery_material(
        &self,
        statement: &DeviceRevocationStatementV1,
        signature: Ed25519SignatureBytes,
        current: &RevocationControlState<'_>,
        keys: &RecoveryKeys,
    ) -> Result<PairingKeyBundle, CryptoError> {
        self.verify(statement, signature, current)?;
        if keys.wrapping_public_key() != self.recovery_wrapping_public_key {
            return Err(CryptoError::InvalidKey);
        }
        let aad = rotation_material_aad(
            statement,
            self.previous_state_sha256,
            self.key_material_sha256,
            RECOVERY_MATERIAL_DOMAIN,
            self.recovery_root_id.as_bytes(),
            &self.recovery_wrapping_public_key.0,
        )?;
        let plaintext = keys.unwrap_secret(&self.recovery_envelope, &aad)?;
        self.opened_material(statement, plaintext.expose())
    }

    fn opened_material(
        &self,
        statement: &DeviceRevocationStatementV1,
        plaintext: &[u8],
    ) -> Result<PairingKeyBundle, CryptoError> {
        if Sha256Digest(Sha256::digest(plaintext).into()) != self.key_material_sha256 {
            return Err(CryptoError::AuthenticationFailed);
        }
        let material = decode_pairing_key_bundle_v1(plaintext)?;
        if material.account_id() != statement.account_id
            || material.workspace_id() != statement.workspace_id
            || material.control_epoch() != self.control_epoch
            || material.key_epoch() != self.key_epoch
        {
            return Err(CryptoError::AuthenticationFailed);
        }
        Ok(material)
    }

    /// Parses bounded canonical wire bytes without authenticating the transition.
    /// Call verify against independently authenticated current state before use.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let invalid = CryptoError::InvalidProtocolValue;
        if bytes.len() > MAX_ROTATION_BYTES {
            return Err(invalid);
        }
        let mut input = bytes.strip_prefix(ROTATION_DOMAIN).ok_or(invalid)?;
        let previous_state_sha256 = Sha256Digest(read_fixed(&mut input)?);
        let control_epoch = u32::from_be_bytes(read_fixed(&mut input)?);
        let key_epoch = u32::from_be_bytes(read_fixed(&mut input)?);
        let key_material_sha256 = Sha256Digest(read_fixed(&mut input)?);
        let count = u32::from_be_bytes(read_fixed(&mut input)?) as usize;
        if count > MAX_ROTATION_DEVICES {
            return Err(invalid);
        }
        let mut devices = Vec::new();
        for _ in 0..count {
            let certificate_bytes = read_sized(&mut input, MAX_ROTATION_CERTIFICATE_BYTES)?;
            let mut decoder = Decoder::new(certificate_bytes);
            let certificate = decode_certificate_v1(&mut decoder)?;
            if decoder.position() != certificate_bytes.len() {
                return Err(invalid);
            }
            devices.push(DeviceRotationEnvelopeV1 {
                certificate,
                envelope: read_rotation_envelope(&mut input)?,
            });
        }
        let recovery_root_id = RecoveryRootId::new(uuid::Uuid::from_bytes(read_fixed(&mut input)?))
            .map_err(|_| invalid)?;
        let recovery_wrapping_public_key = X25519PublicKeyBytes(read_fixed(&mut input)?);
        let recovery_envelope = read_rotation_envelope(&mut input)?;
        let transition = Self {
            previous_state_sha256,
            control_epoch,
            key_epoch,
            key_material_sha256,
            devices,
            recovery_root_id,
            recovery_wrapping_public_key,
            recovery_envelope,
        };
        if !input.is_empty() || transition.canonical_bytes()? != bytes {
            return Err(invalid);
        }
        Ok(transition)
    }

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
        let mut bytes = ROTATION_DOMAIN.to_vec();
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
    /// Decode the exact signing preimage; signature/current-authority verification
    /// is a separate required step. IDs retain the protocol's UUIDv7 validation.
    pub fn from_signing_preimage(bytes: &[u8]) -> Result<Self, CryptoError> {
        let invalid = CryptoError::InvalidProtocolValue;
        if bytes.len() != STATEMENT_DOMAIN.len() + 2 + 5 * 16 + 2 * 4 + 8 + 2 * 32 {
            return Err(invalid);
        }
        let mut input = bytes.strip_prefix(STATEMENT_DOMAIN).ok_or(invalid)?;
        let statement = Self {
            schema_version: u16::from_be_bytes(read_fixed(&mut input)?),
            revocation_id: OperationId::new(uuid::Uuid::from_bytes(read_fixed(&mut input)?))
                .map_err(|_| invalid)?,
            account_id: AccountId::new(uuid::Uuid::from_bytes(read_fixed(&mut input)?))
                .map_err(|_| invalid)?,
            workspace_id: WorkspaceId::new(uuid::Uuid::from_bytes(read_fixed(&mut input)?))
                .map_err(|_| invalid)?,
            issuer_device_id: DeviceId::new(uuid::Uuid::from_bytes(read_fixed(&mut input)?))
                .map_err(|_| invalid)?,
            target_device_id: DeviceId::new(uuid::Uuid::from_bytes(read_fixed(&mut input)?))
                .map_err(|_| invalid)?,
            control_epoch: u32::from_be_bytes(read_fixed(&mut input)?),
            key_epoch: u32::from_be_bytes(read_fixed(&mut input)?),
            cutoff_sequence: u64::from_be_bytes(read_fixed(&mut input)?),
            cutoff_hash: Sha256Digest(read_fixed(&mut input)?),
            transition_sha256: Sha256Digest(read_fixed(&mut input)?),
        };
        if !input.is_empty() || statement.signing_preimage()? != bytes {
            return Err(invalid);
        }
        Ok(statement)
    }

    /// Domain, schema, five UUIDs, two epochs, sequence and two digests, in field
    /// order. UUIDs/digests are raw bytes; integers are fixed-width big-endian.
    pub fn signing_preimage(&self) -> Result<Vec<u8>, CryptoError> {
        if self.transition_sha256.0 == [0; 32] {
            return Err(CryptoError::InvalidProtocolValue);
        }
        let mut bytes = self.context_preimage()?;
        bytes.extend_from_slice(&self.transition_sha256.0);
        Ok(bytes)
    }

    fn context_preimage(&self) -> Result<Vec<u8>, CryptoError> {
        if self.schema_version != 1
            || !(1..u32::MAX).contains(&self.control_epoch)
            || !(1..u32::MAX).contains(&self.key_epoch)
            || self.cutoff_sequence > i64::MAX as u64
            || (self.cutoff_sequence == 0) != (self.cutoff_hash.0 == [0; 32])
        {
            return Err(CryptoError::InvalidProtocolValue);
        }
        let mut bytes = STATEMENT_DOMAIN.to_vec();
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
        self.check_signer(certificate, device)?;
        Ok(device.sign_hosted_device_proof(&self.signing_preimage()?))
    }

    fn check_signer(
        &self,
        certificate: &DeviceCertificateV1,
        device: &DeviceKeys,
    ) -> Result<(), CryptoError> {
        self.check_issuer(certificate)?;
        if certificate.signing_public_key != device.signing_public_key()
            || certificate.wrapping_public_key != device.wrapping_public_key()
        {
            return Err(CryptoError::InvalidKey);
        }
        Ok(())
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

// Bind the immutable statement context (everything except its final transition
// digest), previous state, plaintext commitment and exact recipient. Omitting
// the final digest avoids a circular dependency on the ciphertext being built.
fn rotation_material_aad(
    statement: &DeviceRevocationStatementV1,
    previous: Sha256Digest,
    commitment: Sha256Digest,
    domain: &[u8],
    recipient_id: &[u8; 16],
    recipient_binding: &[u8; 32],
) -> Result<Vec<u8>, CryptoError> {
    let mut bytes = domain.to_vec();
    bytes.extend_from_slice(&statement.context_preimage()?);
    bytes.extend_from_slice(&previous.0);
    bytes.extend_from_slice(&commitment.0);
    bytes.extend_from_slice(recipient_id);
    bytes.extend_from_slice(recipient_binding);
    Ok(bytes)
}

fn read_fixed<const N: usize>(input: &mut &[u8]) -> Result<[u8; N], CryptoError> {
    let (bytes, rest) = input
        .split_at_checked(N)
        .ok_or(CryptoError::InvalidProtocolValue)?;
    *input = rest;
    bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidProtocolValue)
}

fn read_sized<'a>(input: &mut &'a [u8], maximum: usize) -> Result<&'a [u8], CryptoError> {
    let size = u32::from_be_bytes(read_fixed(input)?) as usize;
    if size > maximum {
        return Err(CryptoError::InvalidProtocolValue);
    }
    let (bytes, rest) = input
        .split_at_checked(size)
        .ok_or(CryptoError::InvalidProtocolValue)?;
    *input = rest;
    Ok(bytes)
}

fn read_rotation_envelope(input: &mut &[u8]) -> Result<WrappedKeyEnvelope, CryptoError> {
    let ephemeral_public_key = X25519PublicKeyBytes(read_fixed(input)?);
    let nonce = XChaChaNonce(read_fixed(input)?);
    let ciphertext = read_sized(input, MAX_ROTATION_CIPHERTEXT_BYTES)?;
    if ciphertext.len() < 16 {
        return Err(CryptoError::InvalidProtocolValue);
    }
    Ok(WrappedKeyEnvelope {
        ephemeral_public_key,
        nonce,
        ciphertext: ciphertext.to_vec(),
    })
}
