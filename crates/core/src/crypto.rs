use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt,
    sync::{Mutex, OnceLock},
};

use bip39::{Language, Mnemonic};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use context_relay_protocol::{
    AccountId, CheckpointV1, DeviceId, Ed25519PublicKeyBytes, Ed25519SignatureBytes,
    PairingRequestNonce, RecoveryPhraseWords, SyncOperationV1, WorkspaceId, X25519PublicKeyBytes,
    XChaChaNonce, encode_checkpoint_signing_preimage_v1, encode_sync_operation_signing_preimage_v1,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{CryptoRng, OsRng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

const RECOVERY_HKDF_SALT: &[u8] = b"context-relay/recovery/v1";
const RECOVERY_SIGNING_LABEL: &[u8] = b"context-relay/recovery/signing/v1";
const RECOVERY_WRAPPING_LABEL: &[u8] = b"context-relay/recovery/wrapping/v1";
const X25519_WRAP_LABEL: &[u8] = b"context-relay/x25519-wrap/v1";
const CERTIFICATE_DOMAIN: &[u8] = b"context-relay/device-certificate/v1\0";
const NONCE_KEY_DOMAIN: &[u8] = b"context-relay/nonce-key-id/v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoError {
    InvalidPhrase,
    InvalidKey,
    AuthenticationFailed,
    NonceReuse,
    RandomnessUnavailable,
    InvalidProtocolValue,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPhrase => "invalid recovery phrase",
            Self::InvalidKey => "invalid cryptographic key",
            Self::AuthenticationFailed => "cryptographic authentication failed",
            Self::NonceReuse => "encryption nonce reuse rejected",
            Self::RandomnessUnavailable => "secure randomness unavailable",
            Self::InvalidProtocolValue => "invalid protocol value",
        })
    }
}

impl Error for CryptoError {}

pub struct RecoveryPhrase {
    sentence: Zeroizing<String>,
}

impl RecoveryPhrase {
    pub fn generate() -> Result<Self, CryptoError> {
        let mut entropy = Zeroizing::new([0_u8; 32]);
        OsRng
            .try_fill_bytes(&mut *entropy)
            .map_err(|_| CryptoError::RandomnessUnavailable)?;
        Self::from_entropy(*entropy)
    }

    pub fn from_entropy(mut entropy: [u8; 32]) -> Result<Self, CryptoError> {
        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
            .map_err(|_| CryptoError::InvalidPhrase);
        entropy.zeroize();
        let mnemonic = mnemonic?;
        Ok(Self {
            sentence: Zeroizing::new(mnemonic.to_string()),
        })
    }

    pub fn from_words(words: RecoveryPhraseWords) -> Result<Self, CryptoError> {
        let mut words = words.into_words();
        let sentence = Zeroizing::new(words.join(" "));
        words.zeroize();
        let mnemonic = Mnemonic::parse_in(Language::English, sentence.as_str())
            .map_err(|_| CryptoError::InvalidPhrase)?;
        if mnemonic.word_count() != 24 {
            return Err(CryptoError::InvalidPhrase);
        }
        Ok(Self {
            sentence: Zeroizing::new(mnemonic.to_string()),
        })
    }

    pub fn to_words(&self) -> RecoveryPhraseWords {
        RecoveryPhraseWords::new(
            self.sentence
                .split_whitespace()
                .map(str::to_owned)
                .collect(),
        )
        .expect("validated English BIP39 phrase")
    }
}

impl fmt::Debug for RecoveryPhrase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryPhrase([REDACTED])")
    }
}

pub struct RecoveryKeys {
    signing_secret: Zeroizing<[u8; 32]>,
    wrapping_secret: Zeroizing<[u8; 32]>,
}

impl RecoveryKeys {
    pub fn derive(phrase: &RecoveryPhrase) -> Result<Self, CryptoError> {
        let mnemonic = Mnemonic::parse_in(Language::English, phrase.sentence.as_str())
            .map_err(|_| CryptoError::InvalidPhrase)?;
        let seed = Zeroizing::new(mnemonic.to_seed_normalized(""));
        Ok(Self {
            signing_secret: derive_recovery_secret(&seed[..], RECOVERY_SIGNING_LABEL)?,
            wrapping_secret: derive_recovery_secret(&seed[..], RECOVERY_WRAPPING_LABEL)?,
        })
    }

    pub fn signing_public_key(&self) -> Ed25519PublicKeyBytes {
        signing_public_key(&self.signing_secret)
    }

    pub fn wrapping_public_key(&self) -> X25519PublicKeyBytes {
        wrapping_public_key(&self.wrapping_secret)
    }

    pub fn unwrap_secret(
        &self,
        envelope: &WrappedKeyEnvelope,
        aad: &[u8],
    ) -> Result<SecretBytes, CryptoError> {
        unwrap_x25519(&self.wrapping_secret, envelope, aad)
    }

    fn sign(&self, message: &[u8]) -> Ed25519SignatureBytes {
        sign(&self.signing_secret, message)
    }
}

impl fmt::Debug for RecoveryKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryKeys([REDACTED])")
    }
}

pub struct DeviceKeys {
    signing_secret: Zeroizing<[u8; 32]>,
    wrapping_secret: Zeroizing<[u8; 32]>,
}

impl DeviceKeys {
    pub fn generate() -> Result<Self, CryptoError> {
        let mut signing = Zeroizing::new([0_u8; 32]);
        let mut wrapping = Zeroizing::new([0_u8; 32]);
        OsRng
            .try_fill_bytes(&mut *signing)
            .and_then(|_| OsRng.try_fill_bytes(&mut *wrapping))
            .map_err(|_| CryptoError::RandomnessUnavailable)?;
        Ok(Self::from_seeds(*signing, *wrapping))
    }

    pub fn from_seeds(signing_secret: [u8; 32], wrapping_secret: [u8; 32]) -> Self {
        Self {
            signing_secret: Zeroizing::new(signing_secret),
            wrapping_secret: Zeroizing::new(wrapping_secret),
        }
    }

    pub fn signing_public_key(&self) -> Ed25519PublicKeyBytes {
        signing_public_key(&self.signing_secret)
    }

    pub fn wrapping_public_key(&self) -> X25519PublicKeyBytes {
        wrapping_public_key(&self.wrapping_secret)
    }

    pub fn unwrap_secret(
        &self,
        envelope: &WrappedKeyEnvelope,
        aad: &[u8],
    ) -> Result<SecretBytes, CryptoError> {
        unwrap_x25519(&self.wrapping_secret, envelope, aad)
    }

    pub fn sign_sync_operation(&self, operation: &mut SyncOperationV1) -> Result<(), CryptoError> {
        let preimage = encode_sync_operation_signing_preimage_v1(operation)
            .map_err(|_| CryptoError::InvalidProtocolValue)?;
        operation.signature = self.sign(&preimage);
        Ok(())
    }

    pub fn verify_sync_operation(&self, operation: &SyncOperationV1) -> Result<(), CryptoError> {
        let preimage = encode_sync_operation_signing_preimage_v1(operation)
            .map_err(|_| CryptoError::InvalidProtocolValue)?;
        verify_signature(self.signing_public_key(), &preimage, operation.signature)
    }

    pub fn sign_checkpoint(&self, checkpoint: &mut CheckpointV1) -> Result<(), CryptoError> {
        let preimage = encode_checkpoint_signing_preimage_v1(checkpoint)
            .map_err(|_| CryptoError::InvalidProtocolValue)?;
        checkpoint.signature = self.sign(&preimage);
        Ok(())
    }

    pub fn verify_checkpoint(&self, checkpoint: &CheckpointV1) -> Result<(), CryptoError> {
        let preimage = encode_checkpoint_signing_preimage_v1(checkpoint)
            .map_err(|_| CryptoError::InvalidProtocolValue)?;
        verify_signature(self.signing_public_key(), &preimage, checkpoint.signature)
    }

    fn sign(&self, message: &[u8]) -> Ed25519SignatureBytes {
        sign(&self.signing_secret, message)
    }
}

impl fmt::Debug for DeviceKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeviceKeys([REDACTED])")
    }
}

pub fn verify_signature(
    public_key: Ed25519PublicKeyBytes,
    message: &[u8],
    signature: Ed25519SignatureBytes,
) -> Result<(), CryptoError> {
    let verifying_key =
        VerifyingKey::from_bytes(&public_key.0).map_err(|_| CryptoError::InvalidKey)?;
    verifying_key
        .verify_strict(message, &Signature::from_bytes(&signature.0))
        .map_err(|_| CryptoError::AuthenticationFailed)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedPayload {
    pub nonce: XChaChaNonce,
    pub ciphertext: Vec<u8>,
}

pub struct ContentKey {
    bytes: Zeroizing<[u8; 32]>,
}

impl ContentKey {
    pub fn generate() -> Result<Self, CryptoError> {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        OsRng
            .try_fill_bytes(&mut *bytes)
            .map_err(|_| CryptoError::RandomnessUnavailable)?;
        Ok(Self::from_bytes(*bytes))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }

    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<EncryptedPayload, CryptoError> {
        self.encrypt_with_rng(plaintext, aad, &mut OsRng)
    }

    pub fn decrypt(
        &self,
        encrypted: &EncryptedPayload,
        aad: &[u8],
    ) -> Result<SecretBytes, CryptoError> {
        decrypt_xchacha(&self.bytes, &encrypted.nonce.0, &encrypted.ciphertext, aad)
    }

    fn encrypt_with_rng<R: CryptoRng + RngCore>(
        &self,
        plaintext: &[u8],
        aad: &[u8],
        rng: &mut R,
    ) -> Result<EncryptedPayload, CryptoError> {
        encrypt_xchacha_with_rng(&self.bytes, plaintext, aad, rng)
    }
}

impl fmt::Debug for ContentKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ContentKey([REDACTED])")
    }
}

pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    pub fn expose(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes([REDACTED])")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WrappedKeyEnvelope {
    pub ephemeral_public_key: X25519PublicKeyBytes,
    pub nonce: XChaChaNonce,
    pub ciphertext: Vec<u8>,
}

pub fn wrap_secret(
    recipient_public_key: X25519PublicKeyBytes,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<WrappedKeyEnvelope, CryptoError> {
    let mut ephemeral_bytes = Zeroizing::new([0_u8; 32]);
    OsRng
        .try_fill_bytes(&mut *ephemeral_bytes)
        .map_err(|_| CryptoError::RandomnessUnavailable)?;
    let ephemeral_secret = StaticSecret::from(*ephemeral_bytes);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
    let recipient_public = X25519PublicKey::from(recipient_public_key.0);
    let shared = ephemeral_secret.diffie_hellman(&recipient_public);
    if shared.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(CryptoError::InvalidKey);
    }
    let key = derive_wrap_key(
        shared.as_bytes(),
        ephemeral_public.as_bytes(),
        &recipient_public_key.0,
    )?;
    let encrypted = encrypt_xchacha_with_rng(&key, plaintext, aad, &mut OsRng)?;
    Ok(WrappedKeyEnvelope {
        ephemeral_public_key: X25519PublicKeyBytes(*ephemeral_public.as_bytes()),
        nonce: encrypted.nonce,
        ciphertext: encrypted.ciphertext,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CertificateIssuerV1 {
    RecoveryRoot(Ed25519PublicKeyBytes),
    Device {
        device_id: DeviceId,
        signing_public_key: Ed25519PublicKeyBytes,
    },
}

impl CertificateIssuerV1 {
    fn signing_public_key(&self) -> Ed25519PublicKeyBytes {
        match self {
            Self::RecoveryRoot(key) => *key,
            Self::Device {
                signing_public_key, ..
            } => *signing_public_key,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateFieldsV1 {
    pub account_id: AccountId,
    pub workspace_id: WorkspaceId,
    pub control_epoch: u32,
    pub request_nonce: PairingRequestNonce,
    pub device_id: DeviceId,
    pub signing_public_key: Ed25519PublicKeyBytes,
    pub wrapping_public_key: X25519PublicKeyBytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceCertificateV1 {
    pub issuer: CertificateIssuerV1,
    pub account_id: AccountId,
    pub workspace_id: WorkspaceId,
    pub control_epoch: u32,
    pub request_nonce: PairingRequestNonce,
    pub device_id: DeviceId,
    pub signing_public_key: Ed25519PublicKeyBytes,
    pub wrapping_public_key: X25519PublicKeyBytes,
    pub signature: Ed25519SignatureBytes,
}

impl DeviceCertificateV1 {
    pub fn issue_genesis(
        fields: CertificateFieldsV1,
        recovery: &RecoveryKeys,
    ) -> Result<Self, CryptoError> {
        let mut certificate = Self::unsigned(
            fields,
            CertificateIssuerV1::RecoveryRoot(recovery.signing_public_key()),
        );
        certificate.signature = recovery.sign(&certificate.signing_preimage());
        Ok(certificate)
    }

    pub fn issue_by_device(
        fields: CertificateFieldsV1,
        issuer_device_id: DeviceId,
        issuer: &DeviceKeys,
    ) -> Result<Self, CryptoError> {
        let mut certificate = Self::unsigned(
            fields,
            CertificateIssuerV1::Device {
                device_id: issuer_device_id,
                signing_public_key: issuer.signing_public_key(),
            },
        );
        certificate.signature = issuer.sign(&certificate.signing_preimage());
        Ok(certificate)
    }

    pub fn verify_genesis(
        &self,
        recovery_public_key: Ed25519PublicKeyBytes,
    ) -> Result<(), CryptoError> {
        self.verify_issued_by(&CertificateIssuerV1::RecoveryRoot(recovery_public_key))
    }

    pub fn verify_issued_by(&self, issuer: &CertificateIssuerV1) -> Result<(), CryptoError> {
        if &self.issuer != issuer {
            return Err(CryptoError::AuthenticationFailed);
        }
        verify_signature(
            issuer.signing_public_key(),
            &self.signing_preimage(),
            self.signature,
        )
    }

    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut preimage = Vec::with_capacity(190);
        preimage.extend_from_slice(CERTIFICATE_DOMAIN);
        match self.issuer {
            CertificateIssuerV1::RecoveryRoot(key) => {
                preimage.push(0);
                preimage.extend_from_slice(&key.0);
            }
            CertificateIssuerV1::Device {
                device_id,
                signing_public_key,
            } => {
                preimage.push(1);
                preimage.extend_from_slice(device_id.as_bytes());
                preimage.extend_from_slice(&signing_public_key.0);
            }
        }
        preimage.extend_from_slice(self.account_id.as_bytes());
        preimage.extend_from_slice(self.workspace_id.as_bytes());
        preimage.extend_from_slice(&self.control_epoch.to_be_bytes());
        preimage.extend_from_slice(&self.request_nonce.0);
        preimage.extend_from_slice(self.device_id.as_bytes());
        preimage.extend_from_slice(&self.signing_public_key.0);
        preimage.extend_from_slice(&self.wrapping_public_key.0);
        preimage
    }

    fn unsigned(fields: CertificateFieldsV1, issuer: CertificateIssuerV1) -> Self {
        Self {
            issuer,
            account_id: fields.account_id,
            workspace_id: fields.workspace_id,
            control_epoch: fields.control_epoch,
            request_nonce: fields.request_nonce,
            device_id: fields.device_id,
            signing_public_key: fields.signing_public_key,
            wrapping_public_key: fields.wrapping_public_key,
            signature: Ed25519SignatureBytes([0; 64]),
        }
    }
}

fn derive_recovery_secret(seed: &[u8], label: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(Some(RECOVERY_HKDF_SALT), seed);
    let mut output = Zeroizing::new([0_u8; 32]);
    hkdf.expand(label, &mut *output)
        .map_err(|_| CryptoError::InvalidKey)?;
    Ok(output)
}

fn signing_public_key(secret: &[u8; 32]) -> Ed25519PublicKeyBytes {
    Ed25519PublicKeyBytes(SigningKey::from_bytes(secret).verifying_key().to_bytes())
}

fn wrapping_public_key(secret: &[u8; 32]) -> X25519PublicKeyBytes {
    let secret = StaticSecret::from(*secret);
    X25519PublicKeyBytes(*X25519PublicKey::from(&secret).as_bytes())
}

fn sign(secret: &[u8; 32], message: &[u8]) -> Ed25519SignatureBytes {
    Ed25519SignatureBytes(SigningKey::from_bytes(secret).sign(message).to_bytes())
}

fn unwrap_x25519(
    recipient_secret: &[u8; 32],
    envelope: &WrappedKeyEnvelope,
    aad: &[u8],
) -> Result<SecretBytes, CryptoError> {
    let recipient_secret = StaticSecret::from(*recipient_secret);
    let recipient_public = X25519PublicKey::from(&recipient_secret);
    let ephemeral_public = X25519PublicKey::from(envelope.ephemeral_public_key.0);
    let shared = recipient_secret.diffie_hellman(&ephemeral_public);
    if shared.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(CryptoError::InvalidKey);
    }
    let key = derive_wrap_key(
        shared.as_bytes(),
        &envelope.ephemeral_public_key.0,
        recipient_public.as_bytes(),
    )?;
    decrypt_xchacha(&key, &envelope.nonce.0, &envelope.ciphertext, aad)
}

fn derive_wrap_key(
    shared: &[u8; 32],
    ephemeral_public: &[u8; 32],
    recipient_public: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, shared);
    let mut info = Vec::with_capacity(X25519_WRAP_LABEL.len() + 64);
    info.extend_from_slice(X25519_WRAP_LABEL);
    info.extend_from_slice(ephemeral_public);
    info.extend_from_slice(recipient_public);
    let mut output = Zeroizing::new([0_u8; 32]);
    hkdf.expand(&info, &mut *output)
        .map_err(|_| CryptoError::InvalidKey)?;
    Ok(output)
}

fn encrypt_xchacha_with_rng<R: CryptoRng + RngCore>(
    key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
    rng: &mut R,
) -> Result<EncryptedPayload, CryptoError> {
    let mut nonce = [0_u8; 24];
    rng.try_fill_bytes(&mut nonce)
        .map_err(|_| CryptoError::RandomnessUnavailable)?;
    reserve_nonce(key, nonce)?;
    let cipher = XChaCha20Poly1305::new(key.into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    Ok(EncryptedPayload {
        nonce: XChaChaNonce(nonce),
        ciphertext,
    })
}

fn decrypt_xchacha(
    key: &[u8; 32],
    nonce: &[u8; 24],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<SecretBytes, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(|plaintext| SecretBytes(Zeroizing::new(plaintext)))
        .map_err(|_| CryptoError::AuthenticationFailed)
}

type NonceRegistry = HashMap<[u8; 32], HashSet<[u8; 24]>>;

fn reserve_nonce(key: &[u8; 32], nonce: [u8; 24]) -> Result<(), CryptoError> {
    // ponytail: process-lifetime registry; Task 6/16 persistence owns durable nonce state.
    static NONCES: OnceLock<Mutex<NonceRegistry>> = OnceLock::new();
    let key_id = {
        let mut hash = Sha256::new();
        hash.update(NONCE_KEY_DOMAIN);
        hash.update(key);
        let digest = hash.finalize();
        let mut key_id = [0_u8; 32];
        key_id.copy_from_slice(&digest);
        key_id
    };
    let mut nonces = NONCES
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map_err(|_| CryptoError::RandomnessUnavailable)?;
    if !nonces.entry(key_id).or_default().insert(nonce) {
        return Err(CryptoError::NonceReuse);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use rand_core::{CryptoRng, RngCore};

    use super::{ContentKey, CryptoError};

    struct RepeatingRng;

    impl RngCore for RepeatingRng {
        fn next_u32(&mut self) -> u32 {
            0x0707_0707
        }

        fn next_u64(&mut self) -> u64 {
            0x0707_0707_0707_0707
        }

        fn fill_bytes(&mut self, destination: &mut [u8]) {
            destination.fill(7);
        }

        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(destination);
            Ok(())
        }
    }

    impl CryptoRng for RepeatingRng {}

    #[test]
    fn rejects_forced_nonce_reuse_for_the_same_key() {
        let key = ContentKey::from_bytes([99; 32]);
        let mut rng = RepeatingRng;
        key.encrypt_with_rng(b"first", b"aad", &mut rng).unwrap();
        assert_eq!(
            key.encrypt_with_rng(b"second", b"aad", &mut rng)
                .unwrap_err(),
            CryptoError::NonceReuse
        );
    }
}
