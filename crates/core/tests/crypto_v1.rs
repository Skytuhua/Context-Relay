use std::str::FromStr;

use context_relay_core::crypto::{
    CertificateFieldsV1, CertificateIssuerV1, ContentKey, DeviceCertificateV1, DeviceKeys,
    RecoveryKeys, RecoveryPhrase, verify_signature, wrap_secret,
};
use context_relay_protocol::{
    AccountId, BlobRef, BoundedCiphertext, CheckpointV1, DeviceId, DeviceSequence,
    Ed25519SignatureBytes, HybridLogicalClock, MutationKind, OperationId, PairingRequestNonce,
    ProjectId, RecordId, RecordKind, RecoveryPhraseWords, Sha256Digest, SyncOperationV1,
    WorkspaceId, XChaChaNonce, encode_checkpoint_signing_preimage_v1,
    encode_sync_operation_signing_preimage_v1,
};
use zeroize::Zeroizing;

const ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07398f";
const OTHER_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07398e";
const PLAINTEXT_CANARY: &[u8] = b"plaintext-canary-47c3";

#[test]
fn recovery_is_bip39_domain_separated_and_redacted() {
    assert_eq!(
        RecoveryPhrase::generate()
            .unwrap()
            .to_words()
            .as_words()
            .len(),
        24
    );
    let phrase = fixed_phrase();
    assert_eq!(
        phrase.to_words().as_words().join(" "),
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
    );

    let keys = RecoveryKeys::derive(&phrase).unwrap();
    assert_ne!(
        keys.signing_public_key().0,
        keys.wrapping_public_key().0,
        "stable HKDF labels must produce distinct recovery secrets"
    );

    let consumed_words: Zeroizing<Vec<String>> = phrase.to_words().into_words();
    assert_eq!(consumed_words.len(), 24);
    let wrong = RecoveryPhraseWords::new(vec!["abandon".to_owned(); 24]).unwrap();
    assert!(RecoveryPhrase::from_words(wrong).is_err());

    let diagnostics = format!("{phrase:?} {keys:?}");
    assert!(!diagnostics.contains("abandon"));
    assert!(!diagnostics.contains("art"));
    assert!(!format!("{:?}", phrase.to_words()).contains("abandon"));
}

#[test]
fn xchacha_and_x25519_bind_aad_and_redact_failures() {
    let generated_key = ContentKey::generate().unwrap();
    assert_eq!(
        generated_key
            .decrypt(
                &generated_key
                    .encrypt(b"generated", b"generated-aad")
                    .unwrap(),
                b"generated-aad",
            )
            .unwrap()
            .expose(),
        b"generated"
    );
    let key = ContentKey::from_bytes([41; 32]);
    let aad = b"account/workspace/record/v1";
    let encrypted = key.encrypt(PLAINTEXT_CANARY, aad).unwrap();
    assert_ne!(encrypted.ciphertext, PLAINTEXT_CANARY);
    assert_eq!(
        key.decrypt(&encrypted, aad).unwrap().expose(),
        PLAINTEXT_CANARY
    );

    for index in 0..aad.len() {
        let mut tampered = aad.to_vec();
        tampered[index] ^= 1;
        assert!(key.decrypt(&encrypted, &tampered).is_err());
    }

    let generated_device = DeviceKeys::generate().unwrap();
    assert_ne!(
        generated_device.signing_public_key().0,
        generated_device.wrapping_public_key().0
    );
    let recipient = DeviceKeys::generate().unwrap();
    let wrapped = wrap_secret(recipient.wrapping_public_key(), PLAINTEXT_CANARY, aad).unwrap();
    assert_eq!(
        recipient.unwrap_secret(&wrapped, aad).unwrap().expose(),
        PLAINTEXT_CANARY
    );
    for index in 0..aad.len() {
        let mut tampered = aad.to_vec();
        tampered[index] ^= 1;
        assert!(recipient.unwrap_secret(&wrapped, &tampered).is_err());
    }

    let recovery = RecoveryKeys::derive(&fixed_phrase()).unwrap();
    let recovery_wrapped =
        wrap_secret(recovery.wrapping_public_key(), PLAINTEXT_CANARY, aad).unwrap();
    assert_eq!(
        recovery
            .unwrap_secret(&recovery_wrapped, aad)
            .unwrap()
            .expose(),
        PLAINTEXT_CANARY
    );
    let wrong_recovery = RecoveryKeys::derive(&RecoveryPhrase::generate().unwrap()).unwrap();
    assert!(
        wrong_recovery
            .unwrap_secret(&recovery_wrapped, aad)
            .is_err()
    );

    let mut tampered_ephemeral = wrapped.clone();
    tampered_ephemeral.ephemeral_public_key.0[0] ^= 1;
    assert!(recipient.unwrap_secret(&tampered_ephemeral, aad).is_err());
    let mut tampered_nonce = wrapped.clone();
    tampered_nonce.nonce.0[0] ^= 1;
    assert!(recipient.unwrap_secret(&tampered_nonce, aad).is_err());
    let mut tampered_ciphertext = wrapped;
    tampered_ciphertext.ciphertext[0] ^= 1;
    let error = recipient
        .unwrap_secret(&tampered_ciphertext, aad)
        .unwrap_err();
    let diagnostics = format!("{error:?} {error}");
    assert!(!diagnostics.contains(std::str::from_utf8(PLAINTEXT_CANARY).unwrap()));
}

#[test]
fn certificates_bind_every_field_and_declared_issuer() {
    let recovery = RecoveryKeys::derive(&fixed_phrase()).unwrap();
    let device = DeviceKeys::generate().unwrap();
    let fields = certificate_fields(&device);
    let certificate = DeviceCertificateV1::issue_genesis(fields.clone(), &recovery).unwrap();
    certificate
        .verify_genesis(recovery.signing_public_key())
        .unwrap();

    let mut tampered = Vec::new();
    let mut value = certificate.clone();
    match &mut value.issuer {
        CertificateIssuerV1::RecoveryRoot(key) => key.0[0] ^= 1,
        CertificateIssuerV1::Device { .. } => unreachable!(),
    }
    tampered.push(value);
    let mut value = certificate.clone();
    value.account_id = AccountId::from_str(OTHER_ID).unwrap();
    tampered.push(value);
    let mut value = certificate.clone();
    value.workspace_id = WorkspaceId::from_str(ID).unwrap();
    tampered.push(value);
    let mut value = certificate.clone();
    value.control_epoch ^= 1;
    tampered.push(value);
    let mut value = certificate.clone();
    value.request_nonce.0[0] ^= 1;
    tampered.push(value);
    let mut value = certificate.clone();
    value.device_id = DeviceId::from_str(ID).unwrap();
    tampered.push(value);
    let mut value = certificate.clone();
    value.signing_public_key.0[0] ^= 1;
    tampered.push(value);
    let mut value = certificate.clone();
    value.wrapping_public_key.0[0] ^= 1;
    tampered.push(value);
    let mut value = certificate.clone();
    value.signature.0[0] ^= 1;
    tampered.push(value);
    for value in tampered {
        assert!(value.verify_genesis(recovery.signing_public_key()).is_err());
    }

    let issuer = DeviceKeys::generate().unwrap();
    let issuer_id = DeviceId::from_str(ID).unwrap();
    let device_certificate =
        DeviceCertificateV1::issue_by_device(fields, issuer_id, &issuer).unwrap();
    let declared = CertificateIssuerV1::Device {
        device_id: issuer_id,
        signing_public_key: issuer.signing_public_key(),
    };
    device_certificate.verify_issued_by(&declared).unwrap();
    let mut tampered_issuer_id = device_certificate.clone();
    if let CertificateIssuerV1::Device { device_id, .. } = &mut tampered_issuer_id.issuer {
        *device_id = DeviceId::from_str(OTHER_ID).unwrap();
    }
    let tampered_declared = tampered_issuer_id.issuer.clone();
    assert!(
        tampered_issuer_id
            .verify_issued_by(&tampered_declared)
            .is_err()
    );
    let mut tampered_issuer_key = device_certificate.clone();
    if let CertificateIssuerV1::Device {
        signing_public_key, ..
    } = &mut tampered_issuer_key.issuer
    {
        signing_public_key.0[0] ^= 1;
    }
    let tampered_declared = tampered_issuer_key.issuer.clone();
    assert!(
        tampered_issuer_key
            .verify_issued_by(&tampered_declared)
            .is_err()
    );
    assert!(
        device_certificate
            .verify_issued_by(&CertificateIssuerV1::RecoveryRoot(
                recovery.signing_public_key()
            ))
            .is_err()
    );
}

#[test]
fn operation_and_checkpoint_use_protocol_signing_preimages() {
    let keys = DeviceKeys::generate().unwrap();
    let mut operation = sync_operation();
    keys.sign_sync_operation(&mut operation).unwrap();
    keys.verify_sync_operation(&operation).unwrap();
    assert_each_preimage_bit_is_signed(
        keys.signing_public_key(),
        &encode_sync_operation_signing_preimage_v1(&operation).unwrap(),
        operation.signature,
    );
    operation.signature.0[0] ^= 1;
    assert!(keys.verify_sync_operation(&operation).is_err());

    let mut checkpoint = checkpoint();
    keys.sign_checkpoint(&mut checkpoint).unwrap();
    keys.verify_checkpoint(&checkpoint).unwrap();
    assert_each_preimage_bit_is_signed(
        keys.signing_public_key(),
        &encode_checkpoint_signing_preimage_v1(&checkpoint).unwrap(),
        checkpoint.signature,
    );
    checkpoint.signature.0[0] ^= 1;
    assert!(keys.verify_checkpoint(&checkpoint).is_err());
}

fn assert_each_preimage_bit_is_signed(
    public_key: context_relay_protocol::Ed25519PublicKeyBytes,
    preimage: &[u8],
    signature: Ed25519SignatureBytes,
) {
    for index in 0..preimage.len() {
        let mut tampered = preimage.to_vec();
        tampered[index] ^= 1;
        assert!(verify_signature(public_key, &tampered, signature).is_err());
    }
}

fn certificate_fields(device: &DeviceKeys) -> CertificateFieldsV1 {
    CertificateFieldsV1 {
        account_id: AccountId::from_str(ID).unwrap(),
        workspace_id: WorkspaceId::from_str(OTHER_ID).unwrap(),
        control_epoch: 7,
        request_nonce: PairingRequestNonce([5; 32]),
        device_id: DeviceId::from_str(OTHER_ID).unwrap(),
        signing_public_key: device.signing_public_key(),
        wrapping_public_key: device.wrapping_public_key(),
    }
}

fn fixed_phrase() -> RecoveryPhrase {
    let mut words = vec!["abandon".to_owned(); 23];
    words.push("art".to_owned());
    RecoveryPhrase::from_words(RecoveryPhraseWords::new(words).unwrap()).unwrap()
}

fn sync_operation() -> SyncOperationV1 {
    SyncOperationV1 {
        schema_version: 1,
        operation_id: OperationId::from_str(ID).unwrap(),
        account_id: AccountId::from_str(ID).unwrap(),
        workspace_id: WorkspaceId::from_str(ID).unwrap(),
        project_id: Some(ProjectId::from_str(ID).unwrap()),
        record_id: RecordId::from_str(ID).unwrap(),
        record_kind: RecordKind::Memory,
        mutation_kind: MutationKind::Upsert,
        device_id: DeviceId::from_str(ID).unwrap(),
        device_sequence: 7,
        causal_frontier: vec![DeviceSequence {
            device_id: DeviceId::from_str(ID).unwrap(),
            sequence: 6,
        }],
        control_epoch: 2,
        key_epoch: 3,
        previous_device_hash: Sha256Digest([1; 32]),
        nonce: XChaChaNonce([2; 24]),
        ciphertext: BoundedCiphertext::new(vec![3, 4, 5]).unwrap(),
        ciphertext_hash: Sha256Digest([6; 32]),
        blob_refs: vec![BlobRef {
            digest: Sha256Digest([7; 32]),
            ciphertext_bytes: 9,
            storage_id: "blob-1".into(),
        }],
        created_hlc: HybridLogicalClock::new(1_700_000_000_000, 0, DeviceId::from_str(ID).unwrap()),
        signature: Ed25519SignatureBytes([0; 64]),
    }
}

fn checkpoint() -> CheckpointV1 {
    CheckpointV1 {
        schema_version: 1,
        previous_checkpoint_hash: Sha256Digest([9; 32]),
        causal_frontier: vec![DeviceSequence {
            device_id: DeviceId::from_str(ID).unwrap(),
            sequence: 7,
        }],
        state_hash: Sha256Digest([10; 32]),
        key_epoch: 3,
        creator_device: DeviceId::from_str(ID).unwrap(),
        created_hlc: HybridLogicalClock::new(1_700_000_000_000, 0, DeviceId::from_str(ID).unwrap()),
        signature: Ed25519SignatureBytes([0; 64]),
    }
}
