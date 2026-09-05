use std::{str::FromStr, sync::OnceLock};

use context_relay_core::{
    crypto::{
        CertificateFieldsV1, CertificateIssuerV1, DeviceCertificateV1, DeviceKeys, RecoveryKeys,
        RecoveryPhrase, WrappedKeyEnvelope,
    },
    devices::{
        crypto::PairingKeyBundle,
        recovery_crypto::{
            MAX_RECOVERY_ENROLLMENT_RECORD_BYTES, RECOVERY_ENROLLMENT_SCHEMA_VERSION,
            RecoveryEnrollmentArtifacts, RecoveryEnrollmentBuildRequest,
            RecoveryEnrollmentCryptoError, build_recovery_enrollment_artifacts_with_rng,
            decode_recovery_enrollment_record_v1, encode_recovery_enrollment_record_v1,
            encode_recovery_enrollment_signing_preimage_v1, open_device_workspace_material,
            open_recovery_metadata,
        },
    },
    sync::SyncScope,
};
use context_relay_protocol::{
    AccountId, DeviceCertificateId, DeviceId, NativePlatform, PairingRequestNonce,
    RecoveryEnrollmentId, RecoveryRootId, WorkspaceId,
};
use minicbor::Encoder;
use rand_core::{CryptoRng, Error as RandError, RngCore};
use sha2::{Digest, Sha256};

const ACCOUNT_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07398f";
const WORKSPACE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07398e";
const ENROLLMENT_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07398d";
const RECOVERY_ROOT_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07398c";
const DEVICE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07398b";
const CERTIFICATE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07398a";
const OTHER_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073989";

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

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for SequenceRng {}

struct Fixture {
    phrase: RecoveryPhrase,
    recovery_keys: RecoveryKeys,
    device_keys: DeviceKeys,
    material: PairingKeyBundle,
    artifacts: RecoveryEnrollmentArtifacts,
}

fn id<T: FromStr>(value: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    value.parse().unwrap()
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let phrase = RecoveryPhrase::from_entropy_for_test([0; 32]).unwrap();
        let recovery_keys = RecoveryKeys::derive(&phrase).unwrap();
        let device_keys = DeviceKeys::from_seeds_for_test([0x11; 32], [0x22; 32]);
        let scope = SyncScope {
            account_id: id::<AccountId>(ACCOUNT_ID),
            workspace_id: id::<WorkspaceId>(WORKSPACE_ID),
        };
        let material = PairingKeyBundle::new(scope, 1, 1, [0x44; 32], [0x55; 32]).unwrap();
        let certificate = DeviceCertificateV1::issue_genesis(
            CertificateFieldsV1 {
                account_id: scope.account_id,
                workspace_id: scope.workspace_id,
                control_epoch: 1,
                request_nonce: PairingRequestNonce([0x33; 32]),
                device_id: id::<DeviceId>(DEVICE_ID),
                signing_public_key: device_keys.signing_public_key(),
                wrapping_public_key: device_keys.wrapping_public_key(),
            },
            &recovery_keys,
        )
        .unwrap();
        let mut rng = SequenceRng(0x60);
        let request = RecoveryEnrollmentBuildRequest {
            enrollment_id: id::<RecoveryEnrollmentId>(ENROLLMENT_ID),
            recovery_root_id: id::<RecoveryRootId>(RECOVERY_ROOT_ID),
            certificate_id: id::<DeviceCertificateId>(CERTIFICATE_ID),
            certificate,
            device_name: "First Mac".into(),
            device_platform: NativePlatform::Macos,
            recovery_keys: &recovery_keys,
            device_keys: &device_keys,
            material: &material,
        };
        let debug = format!("{request:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("[17, 17, 17"));
        assert!(!debug.contains("[68, 68, 68"));
        let artifacts = build_recovery_enrollment_artifacts_with_rng(request, &mut rng).unwrap();
        Fixture {
            phrase,
            recovery_keys,
            device_keys,
            material,
            artifacts,
        }
    })
}

fn assert_bundle_eq(actual: &PairingKeyBundle, expected: &PairingKeyBundle) {
    assert_eq!(actual.account_id(), expected.account_id());
    assert_eq!(actual.workspace_id(), expected.workspace_id());
    assert_eq!(actual.control_epoch(), expected.control_epoch());
    assert_eq!(actual.key_epoch(), expected.key_epoch());
    assert_eq!(actual.workspace_root_key(), expected.workspace_root_key());
    assert_eq!(actual.active_epoch_key(), expected.active_epoch_key());
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").unwrap();
    }
    output
}

fn encode_envelope(envelope: &WrappedKeyEnvelope) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(3).unwrap();
    encoder.u8(0).unwrap();
    encoder.bytes(&envelope.ephemeral_public_key.0).unwrap();
    encoder.u8(1).unwrap();
    encoder.bytes(&envelope.nonce.0).unwrap();
    encoder.u8(2).unwrap();
    encoder.bytes(&envelope.ciphertext).unwrap();
    encoder.into_writer()
}

fn certificate_fields(
    scope: SyncScope,
    control_epoch: u32,
    device_id: DeviceId,
    device_keys: &DeviceKeys,
    request_nonce: u8,
) -> CertificateFieldsV1 {
    CertificateFieldsV1 {
        account_id: scope.account_id,
        workspace_id: scope.workspace_id,
        control_epoch,
        request_nonce: PairingRequestNonce([request_nonce; 32]),
        device_id,
        signing_public_key: device_keys.signing_public_key(),
        wrapping_public_key: device_keys.wrapping_public_key(),
    }
}

fn build_request<'a>(
    enrollment_id: RecoveryEnrollmentId,
    recovery_root_id: RecoveryRootId,
    certificate_id: DeviceCertificateId,
    certificate: DeviceCertificateV1,
    recovery_keys: &'a RecoveryKeys,
    device_keys: &'a DeviceKeys,
    material: &'a PairingKeyBundle,
) -> RecoveryEnrollmentBuildRequest<'a> {
    RecoveryEnrollmentBuildRequest {
        enrollment_id,
        recovery_root_id,
        certificate_id,
        certificate,
        device_name: "First Mac".into(),
        device_platform: NativePlatform::Macos,
        recovery_keys,
        device_keys,
        material,
    }
}

fn build_variant(
    rng_start: u8,
    request: RecoveryEnrollmentBuildRequest<'_>,
) -> Result<RecoveryEnrollmentArtifacts, RecoveryEnrollmentCryptoError> {
    let mut rng = SequenceRng(rng_start);
    build_recovery_enrollment_artifacts_with_rng(request, &mut rng)
}

fn assert_transplanted_device_envelope_rejected(
    baseline: &RecoveryEnrollmentArtifacts,
    variant: &RecoveryEnrollmentArtifacts,
    device_keys: &DeviceKeys,
) {
    assert!(
        open_device_workspace_material(
            &variant.record,
            &baseline.device_material_envelope,
            variant.record.genesis_certificate.device_id,
            device_keys,
        )
        .is_err()
    );
}

#[test]
fn frozen_record_preimage_and_envelopes_round_trip() {
    let fixture = fixture();
    assert_eq!(RECOVERY_ENROLLMENT_SCHEMA_VERSION, 1);
    assert_eq!(
        fixture.phrase.to_words().as_words().join(" "),
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
    );
    assert_eq!(
        encode_hex(&fixture.artifacts.canonical_record),
        include_str!("fixtures/recovery-enrollment-record-v1.hex").trim()
    );
    assert_eq!(
        encode_hex(
            &encode_recovery_enrollment_signing_preimage_v1(&fixture.artifacts.record).unwrap()
        ),
        include_str!("fixtures/recovery-enrollment-signing-preimage-v1.hex").trim()
    );
    assert_eq!(
        encode_recovery_enrollment_record_v1(&fixture.artifacts.record).unwrap(),
        fixture.artifacts.canonical_record
    );
    assert_eq!(
        decode_recovery_enrollment_record_v1(&fixture.artifacts.canonical_record).unwrap(),
        fixture.artifacts.record
    );
    assert_eq!(
        encode_hex(&fixture.recovery_keys.signing_public_key().0),
        "74288e91d7d4d5a3dc122fd7f97e2041a2bbef05d0cf9096a40233e105687b78"
    );
    assert_eq!(
        encode_hex(&fixture.recovery_keys.wrapping_public_key().0),
        "13018b2219bcc80e3d06a8f28c1b0fa4307dcd5612342a0e9c3556d54247604f"
    );
    assert_eq!(
        (
            encode_hex(&encode_envelope(
                &fixture.artifacts.record.encrypted_recovery_metadata,
            )),
            encode_hex(&encode_envelope(
                &fixture.artifacts.device_material_envelope,
            )),
        ),
        (
            "a3005820675dd574ed7789310b3d2e7681f3790b466c773b1521fecf36577958371ea52f015818808182838485868788898a8b8c8d8e8f90919293949596970258814e4398c6e437c4f6944b436cbfeae84f7debe8eb40455ded75a22157fb97d9e084d7e75595e2fc43fc38f0c77b55e5bd0c4d44b056bd6545420426341ed08d5f7b8ccfc96f12f04b342f992a2411cf44ae0992cceb0b4d88eafff5206dd579ff064f8fc1ae724ffba66f145618ea2565d3ca348116b67e0af36d5838b7c30b8145".to_owned(),
            "a3005820a10eafb0a4fb54b97ec8c0bf34dc8f4c2182453eac5c62e08ece8878f68aa20d015818b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf0258819281dd7ece89b27f512313bb5524a312de548ce43298e3d42af6f9545f854bb3c87dd4c7a0e8e7e5b59b904f067f536b32995caa4046f68aa1a78855b5ea39170ade6aee7ca94575fe96eea6de43adc5187e54b1231f926a49dc9cd6bcd4bc6de60883ab79acf9ed8796a9047486ff4ca2cd8021006bfdf5d5d3caaed8e1daf812".to_owned(),
        ),
    );
    assert_eq!(
        fixture.artifacts.canonical_record_sha256.0,
        <[u8; 32]>::from(Sha256::digest(&fixture.artifacts.canonical_record)),
    );
    assert_eq!(
        fixture.artifacts.device_material_envelope_sha256.0,
        <[u8; 32]>::from(Sha256::digest(encode_envelope(
            &fixture.artifacts.device_material_envelope,
        ))),
    );

    let recovered =
        open_recovery_metadata(&fixture.artifacts.record, &fixture.recovery_keys).unwrap();
    assert_bundle_eq(&recovered, &fixture.material);
    let device = open_device_workspace_material(
        &fixture.artifacts.record,
        &fixture.artifacts.device_material_envelope,
        id(DEVICE_ID),
        &fixture.device_keys,
    )
    .unwrap();
    assert_bundle_eq(&device, &fixture.material);
}

#[test]
fn every_signed_record_field_and_codec_shape_is_fail_closed() {
    let fixture = fixture();
    let record = &fixture.artifacts.record;
    let mut mutations = Vec::new();

    let mut changed = record.clone();
    changed.schema_version += 1;
    mutations.push(changed);
    let mut changed = record.clone();
    changed.enrollment_id = id(OTHER_ID);
    mutations.push(changed);
    let mut changed = record.clone();
    changed.recovery_root_id = id(OTHER_ID);
    mutations.push(changed);
    let mut changed = record.clone();
    changed.account_id = id(OTHER_ID);
    mutations.push(changed);
    let mut changed = record.clone();
    changed.workspace_id = id(OTHER_ID);
    mutations.push(changed);
    let mut changed = record.clone();
    changed.recovery_signing_public_key.0[0] ^= 1;
    mutations.push(changed);
    let mut changed = record.clone();
    changed.recovery_wrapping_public_key.0[0] ^= 1;
    mutations.push(changed);
    let mut changed = record.clone();
    changed.genesis_certificate_id = id(OTHER_ID);
    mutations.push(changed);
    let mut changed = record.clone();
    changed.genesis_certificate.signature.0[0] ^= 1;
    mutations.push(changed);
    let mut changed = record.clone();
    changed.genesis_certificate.account_id = id(OTHER_ID);
    mutations.push(changed);
    let mut changed = record.clone();
    changed.genesis_certificate.workspace_id = id(OTHER_ID);
    mutations.push(changed);
    let mut changed = record.clone();
    changed.genesis_certificate.control_epoch += 1;
    mutations.push(changed);
    let mut changed = record.clone();
    changed.genesis_certificate.request_nonce.0[0] ^= 1;
    mutations.push(changed);
    let mut changed = record.clone();
    changed.genesis_certificate.device_id = id(OTHER_ID);
    mutations.push(changed);
    let mut changed = record.clone();
    changed.genesis_certificate.signing_public_key.0[0] ^= 1;
    mutations.push(changed);
    let mut changed = record.clone();
    changed.genesis_certificate.wrapping_public_key.0[0] ^= 1;
    mutations.push(changed);
    let mut changed = record.clone();
    changed.genesis_certificate.issuer = CertificateIssuerV1::Device {
        device_id: id(OTHER_ID),
        signing_public_key: fixture.device_keys.signing_public_key(),
    };
    mutations.push(changed);
    let mut changed = record.clone();
    changed.device_name.push('!');
    mutations.push(changed);
    let mut changed = record.clone();
    changed.device_platform = NativePlatform::Windows;
    mutations.push(changed);
    let mut changed = record.clone();
    changed.key_epoch += 1;
    mutations.push(changed);
    let mut changed = record.clone();
    changed.encrypted_recovery_metadata.ephemeral_public_key.0[0] ^= 1;
    mutations.push(changed);
    let mut changed = record.clone();
    changed.encrypted_recovery_metadata.nonce.0[0] ^= 1;
    mutations.push(changed);
    let mut changed = record.clone();
    changed.encrypted_recovery_metadata.ciphertext[0] ^= 1;
    mutations.push(changed);
    let mut changed = record.clone();
    changed.recovery_root_signature.0[0] ^= 1;
    mutations.push(changed);

    for changed in mutations {
        assert!(encode_recovery_enrollment_record_v1(&changed).is_err());
    }

    let mut empty_ciphertext = record.clone();
    empty_ciphertext
        .encrypted_recovery_metadata
        .ciphertext
        .clear();
    assert!(encode_recovery_enrollment_record_v1(&empty_ciphertext).is_err());
    let mut oversized_ciphertext = record.clone();
    oversized_ciphertext.encrypted_recovery_metadata.ciphertext =
        vec![0; MAX_RECOVERY_ENROLLMENT_RECORD_BYTES + 1];
    assert!(encode_recovery_enrollment_record_v1(&oversized_ciphertext).is_err());

    let encoded = fixture.artifacts.canonical_record.clone();
    assert_eq!(&encoded[..4], &[0xae, 0, 1, 1]);
    let mut reordered_first_key = encoded.clone();
    reordered_first_key[1] = 1;
    assert!(decode_recovery_enrollment_record_v1(&reordered_first_key).is_err());
    let mut duplicate_key = encoded.clone();
    duplicate_key[3] = 0;
    assert!(decode_recovery_enrollment_record_v1(&duplicate_key).is_err());
    let mut unknown_key = encoded.clone();
    unknown_key[1] = 14;
    assert!(decode_recovery_enrollment_record_v1(&unknown_key).is_err());
    let mut wrong_map_size = encoded.clone();
    wrong_map_size[0] = 0xad;
    assert!(decode_recovery_enrollment_record_v1(&wrong_map_size).is_err());
    let mut noncanonical_schema = encoded.clone();
    noncanonical_schema.splice(2..3, [0x19, 0, 1]);
    assert!(decode_recovery_enrollment_record_v1(&noncanonical_schema).is_err());
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(decode_recovery_enrollment_record_v1(&trailing).is_err());
    assert!(
        decode_recovery_enrollment_record_v1(&vec![0; MAX_RECOVERY_ENROLLMENT_RECORD_BYTES + 1])
            .is_err()
    );
}

#[test]
fn certificate_bundle_and_both_envelope_aads_are_exact() {
    let fixture = fixture();

    let wrong_recovery = RecoveryKeys::derive(&RecoveryPhrase::generate().unwrap()).unwrap();
    assert!(open_recovery_metadata(&fixture.artifacts.record, &wrong_recovery).is_err());
    let wrong_device = DeviceKeys::from_seeds_for_test([0x71; 32], [0x72; 32]);
    assert!(
        open_device_workspace_material(
            &fixture.artifacts.record,
            &fixture.artifacts.device_material_envelope,
            id(DEVICE_ID),
            &wrong_device,
        )
        .is_err()
    );
    assert!(
        open_device_workspace_material(
            &fixture.artifacts.record,
            &fixture.artifacts.device_material_envelope,
            id(OTHER_ID),
            &fixture.device_keys,
        )
        .is_err()
    );

    let transplanted = build_variant(
        0xd0,
        build_request(
            id(OTHER_ID),
            fixture.artifacts.record.recovery_root_id,
            fixture.artifacts.record.genesis_certificate_id,
            fixture.artifacts.record.genesis_certificate.clone(),
            &fixture.recovery_keys,
            &fixture.device_keys,
            &fixture.material,
        ),
    )
    .unwrap();
    assert!(open_recovery_metadata(&transplanted.record, &fixture.recovery_keys,).is_ok());
    assert_transplanted_device_envelope_rejected(
        &fixture.artifacts,
        &transplanted,
        &fixture.device_keys,
    );
}

#[test]
fn builder_rejects_valid_but_mismatched_initial_trust_inputs() {
    let fixture = fixture();
    let scope = SyncScope {
        account_id: fixture.artifacts.record.account_id,
        workspace_id: fixture.artifacts.record.workspace_id,
    };
    let certificate_id = fixture.artifacts.record.genesis_certificate_id;
    let enrollment_id = fixture.artifacts.record.enrollment_id;
    let recovery_root_id = fixture.artifacts.record.recovery_root_id;

    let other_scope = SyncScope {
        account_id: id(OTHER_ID),
        workspace_id: scope.workspace_id,
    };
    let other_scope_certificate = DeviceCertificateV1::issue_genesis(
        certificate_fields(other_scope, 1, id(DEVICE_ID), &fixture.device_keys, 0x34),
        &fixture.recovery_keys,
    )
    .unwrap();
    assert!(
        build_variant(
            1,
            build_request(
                enrollment_id,
                recovery_root_id,
                certificate_id,
                other_scope_certificate,
                &fixture.recovery_keys,
                &fixture.device_keys,
                &fixture.material,
            ),
        )
        .is_err()
    );

    let epoch_two_certificate = DeviceCertificateV1::issue_genesis(
        certificate_fields(scope, 2, id(DEVICE_ID), &fixture.device_keys, 0x34),
        &fixture.recovery_keys,
    )
    .unwrap();
    assert!(
        build_variant(
            1,
            build_request(
                enrollment_id,
                recovery_root_id,
                certificate_id,
                epoch_two_certificate,
                &fixture.recovery_keys,
                &fixture.device_keys,
                &fixture.material,
            ),
        )
        .is_err()
    );

    let other_device_keys = DeviceKeys::from_seeds_for_test([0x73; 32], [0x74; 32]);
    let other_device_certificate = DeviceCertificateV1::issue_genesis(
        certificate_fields(scope, 1, id(DEVICE_ID), &other_device_keys, 0x34),
        &fixture.recovery_keys,
    )
    .unwrap();
    assert!(
        build_variant(
            1,
            build_request(
                enrollment_id,
                recovery_root_id,
                certificate_id,
                other_device_certificate,
                &fixture.recovery_keys,
                &fixture.device_keys,
                &fixture.material,
            ),
        )
        .is_err()
    );

    let device_issued_certificate = DeviceCertificateV1::issue_by_device(
        certificate_fields(scope, 1, id(DEVICE_ID), &fixture.device_keys, 0x34),
        id(OTHER_ID),
        &fixture.device_keys,
    )
    .unwrap();
    assert!(
        build_variant(
            1,
            build_request(
                enrollment_id,
                recovery_root_id,
                certificate_id,
                device_issued_certificate,
                &fixture.recovery_keys,
                &fixture.device_keys,
                &fixture.material,
            ),
        )
        .is_err()
    );

    let other_recovery =
        RecoveryKeys::derive(&RecoveryPhrase::from_entropy_for_test([1; 32]).unwrap()).unwrap();
    let wrong_root_certificate = DeviceCertificateV1::issue_genesis(
        certificate_fields(scope, 1, id(DEVICE_ID), &fixture.device_keys, 0x34),
        &other_recovery,
    )
    .unwrap();
    assert!(
        build_variant(
            1,
            build_request(
                enrollment_id,
                recovery_root_id,
                certificate_id,
                wrong_root_certificate,
                &fixture.recovery_keys,
                &fixture.device_keys,
                &fixture.material,
            ),
        )
        .is_err()
    );

    let wrong_control_material =
        PairingKeyBundle::new(scope, 2, 1, [0x44; 32], [0x55; 32]).unwrap();
    assert!(
        build_variant(
            1,
            build_request(
                enrollment_id,
                recovery_root_id,
                certificate_id,
                fixture.artifacts.record.genesis_certificate.clone(),
                &fixture.recovery_keys,
                &fixture.device_keys,
                &wrong_control_material,
            ),
        )
        .is_err()
    );
    let wrong_key_material = PairingKeyBundle::new(scope, 1, 2, [0x44; 32], [0x55; 32]).unwrap();
    assert!(
        build_variant(
            1,
            build_request(
                enrollment_id,
                recovery_root_id,
                certificate_id,
                fixture.artifacts.record.genesis_certificate.clone(),
                &fixture.recovery_keys,
                &fixture.device_keys,
                &wrong_key_material,
            ),
        )
        .is_err()
    );

    let mut rng = SequenceRng(1);
    assert!(
        build_recovery_enrollment_artifacts_with_rng(
            RecoveryEnrollmentBuildRequest {
                enrollment_id,
                recovery_root_id,
                certificate_id,
                certificate: fixture.artifacts.record.genesis_certificate.clone(),
                device_name: " ".into(),
                device_platform: NativePlatform::Macos,
                recovery_keys: &fixture.recovery_keys,
                device_keys: &fixture.device_keys,
                material: &fixture.material,
            },
            &mut rng,
        )
        .is_err()
    );
    assert!(
        build_recovery_enrollment_artifacts_with_rng(
            RecoveryEnrollmentBuildRequest {
                enrollment_id,
                recovery_root_id,
                certificate_id,
                certificate: fixture.artifacts.record.genesis_certificate.clone(),
                device_name: "x".repeat(257),
                device_platform: NativePlatform::Macos,
                recovery_keys: &fixture.recovery_keys,
                device_keys: &fixture.device_keys,
                material: &fixture.material,
            },
            &mut rng,
        )
        .is_err()
    );
}

#[test]
fn device_envelope_aad_rejects_every_valid_cross_enrollment_binding() {
    let fixture = fixture();
    let scope = SyncScope {
        account_id: fixture.artifacts.record.account_id,
        workspace_id: fixture.artifacts.record.workspace_id,
    };
    let enrollment_id = fixture.artifacts.record.enrollment_id;
    let recovery_root_id = fixture.artifacts.record.recovery_root_id;
    let certificate_id = fixture.artifacts.record.genesis_certificate_id;
    let certificate = &fixture.artifacts.record.genesis_certificate;

    let variants = [
        build_variant(
            0x10,
            build_request(
                id(OTHER_ID),
                recovery_root_id,
                certificate_id,
                certificate.clone(),
                &fixture.recovery_keys,
                &fixture.device_keys,
                &fixture.material,
            ),
        )
        .unwrap(),
        build_variant(
            0x20,
            build_request(
                enrollment_id,
                id(OTHER_ID),
                certificate_id,
                certificate.clone(),
                &fixture.recovery_keys,
                &fixture.device_keys,
                &fixture.material,
            ),
        )
        .unwrap(),
        build_variant(
            0x30,
            build_request(
                enrollment_id,
                recovery_root_id,
                id(OTHER_ID),
                certificate.clone(),
                &fixture.recovery_keys,
                &fixture.device_keys,
                &fixture.material,
            ),
        )
        .unwrap(),
    ];
    for variant in &variants {
        assert_transplanted_device_envelope_rejected(
            &fixture.artifacts,
            variant,
            &fixture.device_keys,
        );
    }

    let changed_certificate = DeviceCertificateV1::issue_genesis(
        certificate_fields(scope, 1, id(DEVICE_ID), &fixture.device_keys, 0x35),
        &fixture.recovery_keys,
    )
    .unwrap();
    let changed_certificate = build_variant(
        0x40,
        build_request(
            enrollment_id,
            recovery_root_id,
            certificate_id,
            changed_certificate,
            &fixture.recovery_keys,
            &fixture.device_keys,
            &fixture.material,
        ),
    )
    .unwrap();
    assert_transplanted_device_envelope_rejected(
        &fixture.artifacts,
        &changed_certificate,
        &fixture.device_keys,
    );

    let other_recovery =
        RecoveryKeys::derive(&RecoveryPhrase::from_entropy_for_test([2; 32]).unwrap()).unwrap();
    let other_root_certificate = DeviceCertificateV1::issue_genesis(
        certificate_fields(scope, 1, id(DEVICE_ID), &fixture.device_keys, 0x36),
        &other_recovery,
    )
    .unwrap();
    let other_root = build_variant(
        0x50,
        build_request(
            enrollment_id,
            recovery_root_id,
            certificate_id,
            other_root_certificate,
            &other_recovery,
            &fixture.device_keys,
            &fixture.material,
        ),
    )
    .unwrap();
    assert_transplanted_device_envelope_rejected(
        &fixture.artifacts,
        &other_root,
        &fixture.device_keys,
    );

    let other_scope = SyncScope {
        account_id: id(OTHER_ID),
        workspace_id: scope.workspace_id,
    };
    let other_scope_material =
        PairingKeyBundle::new(other_scope, 1, 1, [0x44; 32], [0x55; 32]).unwrap();
    let other_scope_certificate = DeviceCertificateV1::issue_genesis(
        certificate_fields(other_scope, 1, id(DEVICE_ID), &fixture.device_keys, 0x37),
        &fixture.recovery_keys,
    )
    .unwrap();
    let other_scope_artifacts = build_variant(
        0x70,
        build_request(
            enrollment_id,
            recovery_root_id,
            certificate_id,
            other_scope_certificate,
            &fixture.recovery_keys,
            &fixture.device_keys,
            &other_scope_material,
        ),
    )
    .unwrap();
    assert_transplanted_device_envelope_rejected(
        &fixture.artifacts,
        &other_scope_artifacts,
        &fixture.device_keys,
    );

    let other_workspace = SyncScope {
        account_id: scope.account_id,
        workspace_id: id(OTHER_ID),
    };
    let other_workspace_material =
        PairingKeyBundle::new(other_workspace, 1, 1, [0x44; 32], [0x55; 32]).unwrap();
    let other_workspace_certificate = DeviceCertificateV1::issue_genesis(
        certificate_fields(
            other_workspace,
            1,
            id(DEVICE_ID),
            &fixture.device_keys,
            0x3a,
        ),
        &fixture.recovery_keys,
    )
    .unwrap();
    let other_workspace_artifacts = build_variant(
        0x71,
        build_request(
            enrollment_id,
            recovery_root_id,
            certificate_id,
            other_workspace_certificate,
            &fixture.recovery_keys,
            &fixture.device_keys,
            &other_workspace_material,
        ),
    )
    .unwrap();
    assert_transplanted_device_envelope_rejected(
        &fixture.artifacts,
        &other_workspace_artifacts,
        &fixture.device_keys,
    );

    let other_device_certificate = DeviceCertificateV1::issue_genesis(
        certificate_fields(scope, 1, id(OTHER_ID), &fixture.device_keys, 0x38),
        &fixture.recovery_keys,
    )
    .unwrap();
    let other_device = build_variant(
        0x80,
        build_request(
            enrollment_id,
            recovery_root_id,
            certificate_id,
            other_device_certificate,
            &fixture.recovery_keys,
            &fixture.device_keys,
            &fixture.material,
        ),
    )
    .unwrap();
    assert_transplanted_device_envelope_rejected(
        &fixture.artifacts,
        &other_device,
        &fixture.device_keys,
    );

    let other_device_keys = DeviceKeys::from_seeds_for_test([0x75; 32], [0x76; 32]);
    let other_device_certificate = DeviceCertificateV1::issue_genesis(
        certificate_fields(scope, 1, id(DEVICE_ID), &other_device_keys, 0x39),
        &fixture.recovery_keys,
    )
    .unwrap();
    let other_device = build_variant(
        0x90,
        build_request(
            enrollment_id,
            recovery_root_id,
            certificate_id,
            other_device_certificate,
            &fixture.recovery_keys,
            &other_device_keys,
            &fixture.material,
        ),
    )
    .unwrap();
    assert_transplanted_device_envelope_rejected(
        &fixture.artifacts,
        &other_device,
        &other_device_keys,
    );
}

#[test]
fn invalid_initial_bindings_and_diagnostics_never_expose_secret_material() {
    let fixture = fixture();
    let mut invalid = fixture.artifacts.record.clone();
    invalid.device_name = " ".into();
    assert!(encode_recovery_enrollment_record_v1(&invalid).is_err());
    let mut invalid = fixture.artifacts.record.clone();
    invalid.device_name = "x".repeat(257);
    assert!(encode_recovery_enrollment_record_v1(&invalid).is_err());

    let diagnostic = format!(
        "{:?} {:?} {:?} {:?} {:?}",
        fixture.phrase,
        fixture.recovery_keys,
        fixture.device_keys,
        fixture.material,
        fixture.artifacts,
    );
    assert!(!diagnostic.contains("abandon"));
    assert!(!diagnostic.contains(&"44".repeat(32)));
    assert!(!diagnostic.contains(&"55".repeat(32)));
    assert!(diagnostic.contains("[REDACTED]"));
}
