use std::str::FromStr;

use context_relay_core::{
    crypto::{CertificateIssuerV1, DeviceKeys, RecoveryPhrase},
    devices::{
        crypto::PairingKeyBundle,
        recovery_crypto::decode_recovery_enrollment_record_v1,
        recovery_restore_crypto::{
            MAX_RECOVERY_DEVICE_CLAIM_BYTES, RECOVERY_DEVICE_CLAIM_SCHEMA_VERSION,
            RecoveryDeviceClaimV1, authenticate_recovery_root,
            build_recovery_device_claim_with_rng, decode_recovery_device_claim_v1,
            encode_recovery_device_claim_signing_preimage_v1, encode_recovery_device_claim_v1,
            open_recovered_device_material, verify_recovery_device_claim,
        },
    },
    sync::SyncScope,
};
use context_relay_protocol::{
    AccountId, DeviceCertificateId, DeviceId, Ed25519PublicKeyBytes, NativePlatform,
    PairingRequestNonce, RecoveryEnrollmentId, RecoveryPhraseWords, RecoveryRestoreId,
    RecoveryRootId, Sha256Digest, WorkspaceId,
};
use rand_core::{CryptoRng, Error as RandError, RngCore};
use sha2::{Digest, Sha256};

const ACCOUNT_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07398f";
const WORKSPACE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07398e";
const RESTORE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073981";
const RECOVERED_DEVICE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073982";
const RECOVERED_CERTIFICATE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073983";

struct SequenceRng(u8);

impl RngCore for SequenceRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, output: &mut [u8]) {
        for byte in output {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), RandError> {
        self.fill_bytes(output);
        Ok(())
    }
}

impl CryptoRng for SequenceRng {}

fn id<T: FromStr>(value: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    value.parse().unwrap()
}

fn decode_hex(value: &str) -> Vec<u8> {
    let value = value.trim();
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).unwrap();
            let low = (pair[1] as char).to_digit(16).unwrap();
            u8::try_from((high << 4) | low).unwrap()
        })
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").unwrap();
    }
    output
}

fn enrollment_bytes() -> Vec<u8> {
    decode_hex(include_str!("fixtures/recovery-enrollment-record-v1.hex"))
}

fn claim_bytes() -> Vec<u8> {
    decode_hex(include_str!("fixtures/recovery-device-claim-v1.hex"))
}

fn recovered_device_keys() -> DeviceKeys {
    DeviceKeys::from_seeds_for_test([0x66; 32], [0x77; 32])
}

fn fixture_claim() -> RecoveryDeviceClaimV1 {
    decode_recovery_device_claim_v1(&claim_bytes()).unwrap()
}

fn assert_claim_rejected(
    record: &context_relay_core::devices::recovery_crypto::RecoveryEnrollmentRecordV1,
    device_keys: &DeviceKeys,
    mutate: impl FnOnce(&mut RecoveryDeviceClaimV1),
) {
    let mut claim = fixture_claim();
    mutate(&mut claim);
    assert!(verify_recovery_device_claim(record, &claim).is_err());
    assert!(open_recovered_device_material(record, &claim, device_keys).is_err());
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("fixture contains selected canonical field")
}

fn expected_material() -> PairingKeyBundle {
    PairingKeyBundle::new(
        SyncScope {
            account_id: id::<AccountId>(ACCOUNT_ID),
            workspace_id: id::<WorkspaceId>(WORKSPACE_ID),
        },
        1,
        1,
        [0x44; 32],
        [0x55; 32],
    )
    .unwrap()
}

fn assert_material_eq(actual: &PairingKeyBundle, expected: &PairingKeyBundle) {
    assert_eq!(actual.account_id(), expected.account_id());
    assert_eq!(actual.workspace_id(), expected.workspace_id());
    assert_eq!(actual.control_epoch(), expected.control_epoch());
    assert_eq!(actual.key_epoch(), expected.key_epoch());
    assert_eq!(actual.workspace_root_key(), expected.workspace_root_key());
    assert_eq!(actual.active_epoch_key(), expected.active_epoch_key());
}

#[test]
fn frozen_recovery_device_claim_round_trips_and_opens_for_the_target_device() {
    let canonical_enrollment = enrollment_bytes();
    let enrollment_sha256 = Sha256Digest(Sha256::digest(&canonical_enrollment).into());
    let record = decode_recovery_enrollment_record_v1(&canonical_enrollment).unwrap();
    let phrase = RecoveryPhrase::from_entropy_for_test([0; 32]).unwrap();
    let authority =
        authenticate_recovery_root(&canonical_enrollment, enrollment_sha256, phrase).unwrap();
    let device_keys = DeviceKeys::from_seeds_for_test([0x66; 32], [0x77; 32]);
    let mut rng = SequenceRng(0x80);
    let artifacts = build_recovery_device_claim_with_rng(
        authority,
        id::<RecoveryRestoreId>(RESTORE_ID),
        0,
        id::<DeviceCertificateId>(RECOVERED_CERTIFICATE_ID),
        PairingRequestNonce([0x88; 32]),
        id::<DeviceId>(RECOVERED_DEVICE_ID),
        "Recovered Mac".into(),
        NativePlatform::Macos,
        &device_keys,
        &mut rng,
    )
    .unwrap();

    assert_eq!(RECOVERY_DEVICE_CLAIM_SCHEMA_VERSION, 1);
    assert_eq!(MAX_RECOVERY_DEVICE_CLAIM_BYTES, 32 * 1024);
    assert_eq!(
        encode_hex(&artifacts.canonical_claim),
        include_str!("fixtures/recovery-device-claim-v1.hex").trim(),
    );
    assert_eq!(
        encode_hex(&encode_recovery_device_claim_signing_preimage_v1(&artifacts.claim).unwrap(),),
        include_str!("fixtures/recovery-device-claim-signing-preimage-v1.hex").trim(),
    );
    assert_eq!(
        encode_recovery_device_claim_v1(&artifacts.claim).unwrap(),
        artifacts.canonical_claim,
    );
    assert_eq!(
        decode_recovery_device_claim_v1(&artifacts.canonical_claim).unwrap(),
        artifacts.claim,
    );
    let opened = open_recovered_device_material(&record, &artifacts.claim, &device_keys).unwrap();
    assert_material_eq(&opened, &expected_material());
}

#[test]
fn wrong_recovery_phrase_fails_before_a_claim_can_be_built() {
    let canonical_enrollment = enrollment_bytes();
    let enrollment_sha256 = Sha256Digest(Sha256::digest(&canonical_enrollment).into());
    let wrong_phrase = RecoveryPhrase::from_entropy_for_test([1; 32]).unwrap();

    assert!(
        authenticate_recovery_root(&canonical_enrollment, enrollment_sha256, wrong_phrase).is_err()
    );
}

#[test]
fn root_authentication_rejects_wrong_digest_invalid_words_and_tampered_signed_fields() {
    let canonical_enrollment = enrollment_bytes();
    let correct_digest = Sha256Digest(Sha256::digest(&canonical_enrollment).into());
    let mut wrong_digest = correct_digest;
    wrong_digest.0[0] ^= 1;
    assert!(
        authenticate_recovery_root(
            &canonical_enrollment,
            wrong_digest,
            RecoveryPhrase::from_entropy_for_test([0; 32]).unwrap(),
        )
        .is_err()
    );

    let valid_phrase = RecoveryPhrase::from_entropy_for_test([0; 32]).unwrap();
    let mut invalid_checksum_words = valid_phrase.to_words().as_words().to_vec();
    invalid_checksum_words[23] = "abandon".into();
    assert!(
        RecoveryPhrase::from_words(RecoveryPhraseWords::new(invalid_checksum_words).unwrap())
            .is_err()
    );

    let record = decode_recovery_enrollment_record_v1(&canonical_enrollment).unwrap();
    let mut selected_offsets = vec![canonical_enrollment.len() - 1];
    selected_offsets.push(find_subslice(
        &canonical_enrollment,
        record.recovery_root_id.as_bytes(),
    ));
    selected_offsets.push(find_subslice(
        &canonical_enrollment,
        record.account_id.as_bytes(),
    ));
    selected_offsets.push(find_subslice(
        &canonical_enrollment,
        &record.recovery_signing_public_key.0,
    ));
    selected_offsets.push(find_subslice(
        &canonical_enrollment,
        &record.recovery_wrapping_public_key.0,
    ));
    for offset in selected_offsets {
        let mut tampered = canonical_enrollment.clone();
        tampered[offset] ^= 1;
        let tampered_digest = Sha256Digest(Sha256::digest(&tampered).into());
        assert!(
            authenticate_recovery_root(
                &tampered,
                tampered_digest,
                RecoveryPhrase::from_entropy_for_test([0; 32]).unwrap(),
            )
            .is_err(),
            "tampered enrollment offset {offset} authenticated",
        );
    }
}

#[test]
fn every_public_claim_binding_and_ciphertext_mutation_fails_closed() {
    let record = decode_recovery_enrollment_record_v1(&enrollment_bytes()).unwrap();
    let device_keys = recovered_device_keys();
    let alternate_keys = DeviceKeys::from_seeds_for_test([0x12; 32], [0x34; 32]);

    assert_claim_rejected(&record, &device_keys, |claim| claim.schema_version = 2);
    assert_claim_rejected(&record, &device_keys, |claim| {
        claim.restore_id = id::<RecoveryRestoreId>("018f22e2-79b0-7cc8-98c4-dc0c0c073984")
    });
    assert_claim_rejected(&record, &device_keys, |claim| {
        claim.enrollment_id = id::<RecoveryEnrollmentId>("018f22e2-79b0-7cc8-98c4-dc0c0c073984")
    });
    assert_claim_rejected(&record, &device_keys, |claim| {
        claim.recovery_root_id = id::<RecoveryRootId>("018f22e2-79b0-7cc8-98c4-dc0c0c073984")
    });
    assert_claim_rejected(&record, &device_keys, |claim| {
        claim.account_id = id::<AccountId>("018f22e2-79b0-7cc8-98c4-dc0c0c073984")
    });
    assert_claim_rejected(&record, &device_keys, |claim| {
        claim.workspace_id = id::<WorkspaceId>("018f22e2-79b0-7cc8-98c4-dc0c0c073984")
    });
    assert_claim_rejected(&record, &device_keys, |claim| {
        claim.canonical_record_sha256.0[0] ^= 1
    });
    assert_claim_rejected(&record, &device_keys, |claim| {
        claim.expected_recovery_generation += 1
    });
    assert_claim_rejected(&record, &device_keys, |claim| {
        claim.certificate_id = id::<DeviceCertificateId>("018f22e2-79b0-7cc8-98c4-dc0c0c073984")
    });
    assert_claim_rejected(&record, &device_keys, |claim| claim.device_name.push('!'));
    assert_claim_rejected(&record, &device_keys, |claim| {
        claim.device_platform = NativePlatform::Windows
    });
    assert_claim_rejected(&record, &device_keys, |claim| claim.key_epoch += 1);
    assert_claim_rejected(&record, &device_keys, |claim| {
        claim.certificate.control_epoch += 1
    });
    assert_claim_rejected(&record, &device_keys, |claim| {
        claim.certificate.request_nonce.0[0] ^= 1
    });
    assert_claim_rejected(&record, &device_keys, |claim| {
        claim.certificate.device_id = id::<DeviceId>("018f22e2-79b0-7cc8-98c4-dc0c0c073984")
    });
    assert_claim_rejected(&record, &device_keys, |claim| {
        claim.certificate.signing_public_key = alternate_keys.signing_public_key()
    });
    assert_claim_rejected(&record, &device_keys, |claim| {
        claim.certificate.wrapping_public_key = alternate_keys.wrapping_public_key()
    });
    assert_claim_rejected(&record, &device_keys, |claim| {
        claim.certificate.issuer =
            CertificateIssuerV1::RecoveryRoot(alternate_keys.signing_public_key())
    });
    assert_claim_rejected(&record, &device_keys, |claim| {
        claim.certificate.signature.0[0] ^= 1
    });
    assert_claim_rejected(&record, &device_keys, |claim| {
        claim.device_material_envelope.ephemeral_public_key = alternate_keys.wrapping_public_key()
    });
    assert_claim_rejected(&record, &device_keys, |claim| {
        claim.device_material_envelope.nonce.0[0] ^= 1
    });
    assert_claim_rejected(&record, &device_keys, |claim| {
        claim.device_material_envelope.ciphertext[0] ^= 1
    });
    assert_claim_rejected(&record, &device_keys, |claim| {
        claim.recovery_root_signature.0[0] ^= 1
    });

    let wrong_keys = DeviceKeys::from_seeds_for_test([0x13; 32], [0x35; 32]);
    assert!(open_recovered_device_material(&record, &fixture_claim(), &wrong_keys).is_err());
}

#[test]
fn strict_claim_codec_rejects_noncanonical_malformed_and_oversized_bytes() {
    let canonical = claim_bytes();
    let mut trailing = canonical.clone();
    trailing.push(0);
    assert!(decode_recovery_device_claim_v1(&trailing).is_err());

    let mut wrong_map_size = canonical.clone();
    wrong_map_size[0] = 0xae;
    assert!(decode_recovery_device_claim_v1(&wrong_map_size).is_err());

    let mut wrong_first_key = canonical.clone();
    wrong_first_key[1] = 1;
    assert!(decode_recovery_device_claim_v1(&wrong_first_key).is_err());

    let mut tampered_signature = canonical.clone();
    *tampered_signature.last_mut().unwrap() ^= 1;
    assert!(decode_recovery_device_claim_v1(&tampered_signature).is_err());

    assert!(
        decode_recovery_device_claim_v1(&vec![0; MAX_RECOVERY_DEVICE_CLAIM_BYTES + 1]).is_err()
    );
}

#[test]
fn recovery_claim_debug_output_redacts_secret_and_ciphertext_material() {
    let claim = fixture_claim();
    let canonical = claim_bytes();
    let authority = authenticate_recovery_root(
        &enrollment_bytes(),
        Sha256Digest(Sha256::digest(enrollment_bytes()).into()),
        RecoveryPhrase::from_entropy_for_test([0; 32]).unwrap(),
    )
    .unwrap();
    let debug = format!("{authority:?} {claim:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("abandon abandon"));
    assert!(!debug.contains(&encode_hex(&[0x44; 32])));
    assert!(!debug.contains(&encode_hex(&claim.device_material_envelope.ciphertext)));
    assert!(!debug.contains(&encode_hex(&canonical)));

    let invalid_key = Ed25519PublicKeyBytes([0xff; 32]);
    let mut invalid_claim = claim;
    invalid_claim.certificate.signing_public_key = invalid_key;
    let error = encode_recovery_device_claim_v1(&invalid_claim).unwrap_err();
    assert_eq!(error.to_string(), "recovery authentication failed");
}
