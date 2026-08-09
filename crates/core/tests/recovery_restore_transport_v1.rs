use std::{
    str::FromStr,
    sync::{Arc, Barrier},
};

use context_relay_core::{
    crypto::{CertificateFieldsV1, DeviceCertificateV1, DeviceKeys, RecoveryKeys, RecoveryPhrase},
    devices::{
        crypto::PairingKeyBundle,
        memory_recovery_transport::InMemoryRecoveryEnrollmentProvider,
        recovery_crypto::{
            build_recovery_enrollment_artifacts_with_rng, decode_recovery_enrollment_record_v1,
        },
        recovery_restore_crypto::{
            RecoveryDeviceClaimArtifacts, authenticate_recovery_root,
            build_recovery_device_claim_with_rng,
        },
        recovery_restore_transport::{RecoveryRestoreReceipt, RecoveryRestoreTransport},
        recovery_transport::{RecoveryEnrollmentTransport, RecoveryTransportError},
    },
    sync::SyncScope,
};
use context_relay_protocol::{
    AccountId, DeviceCertificateId, DeviceId, NativePlatform, PairingRequestNonce,
    RecoveryEnrollmentId, RecoveryRestoreId, RecoveryRootId, Sha256Digest, WorkspaceId,
};
use rand_core::{CryptoRng, Error as RandError, RngCore};
use sha2::{Digest, Sha256};

const ACCOUNT_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07398f";
const WORKSPACE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07398e";
const RESTORE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073981";
const DEVICE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073982";
const CERTIFICATE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073983";

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

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        for byte in destination {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RandError> {
        self.fill_bytes(destination);
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

fn enrollment_bytes() -> Vec<u8> {
    decode_hex(include_str!("fixtures/recovery-enrollment-record-v1.hex"))
}

fn claim_bytes() -> Vec<u8> {
    decode_hex(include_str!("fixtures/recovery-device-claim-v1.hex"))
}

fn scope() -> SyncScope {
    SyncScope {
        account_id: id::<AccountId>(ACCOUNT_ID),
        workspace_id: id::<WorkspaceId>(WORKSPACE_ID),
    }
}

fn derived_id<T: FromStr>(suffix: u16) -> T
where
    T::Err: std::fmt::Debug,
{
    id(&format!("018f22e2-79b0-7cc8-98c4-dc0c0c07{suffix:04x}"))
}

#[allow(clippy::too_many_arguments)]
fn build_claim(
    restore_id: RecoveryRestoreId,
    certificate_id: DeviceCertificateId,
    device_id: DeviceId,
    expected_generation: u64,
    signing_seed: u8,
    wrapping_seed: u8,
    rng_start: u8,
) -> RecoveryDeviceClaimArtifacts {
    let enrollment = enrollment_bytes();
    let enrollment_sha256 = Sha256Digest(Sha256::digest(&enrollment).into());
    let authority = authenticate_recovery_root(
        &enrollment,
        enrollment_sha256,
        RecoveryPhrase::from_entropy_for_test([0; 32]).unwrap(),
    )
    .unwrap();
    let keys = DeviceKeys::from_seeds_for_test([signing_seed; 32], [wrapping_seed; 32]);
    let mut rng = SequenceRng(rng_start);
    build_recovery_device_claim_with_rng(
        authority,
        restore_id,
        expected_generation,
        certificate_id,
        PairingRequestNonce([rng_start; 32]),
        device_id,
        format!("Recovered {rng_start}"),
        NativePlatform::Macos,
        &keys,
        &mut rng,
    )
    .unwrap()
}

fn register_root(provider: &InMemoryRecoveryEnrollmentProvider) {
    provider
        .transport(scope())
        .register(&enrollment_bytes(), 1_000)
        .unwrap();
}

fn valid_claim_from_another_root_in_the_same_scope() -> RecoveryDeviceClaimArtifacts {
    let phrase = RecoveryPhrase::from_entropy_for_test([9; 32]).unwrap();
    let recovery_keys = RecoveryKeys::derive(&phrase).unwrap();
    let genesis_keys = DeviceKeys::from_seeds_for_test([0x81; 32], [0x82; 32]);
    let material = PairingKeyBundle::new(scope(), 1, 1, [0x44; 32], [0x55; 32]).unwrap();
    let certificate = DeviceCertificateV1::issue_genesis(
        CertificateFieldsV1 {
            account_id: scope().account_id,
            workspace_id: scope().workspace_id,
            control_epoch: 1,
            request_nonce: PairingRequestNonce([0x83; 32]),
            device_id: derived_id(0x600),
            signing_public_key: genesis_keys.signing_public_key(),
            wrapping_public_key: genesis_keys.wrapping_public_key(),
        },
        &recovery_keys,
    )
    .unwrap();
    let mut enrollment_rng = SequenceRng(0x90);
    let enrollment = build_recovery_enrollment_artifacts_with_rng(
        derived_id::<RecoveryEnrollmentId>(0x601),
        derived_id::<RecoveryRootId>(0x602),
        derived_id::<DeviceCertificateId>(0x603),
        certificate,
        "Other Root".into(),
        NativePlatform::Macos,
        &recovery_keys,
        &genesis_keys,
        &material,
        &mut enrollment_rng,
    )
    .unwrap();
    let authority = authenticate_recovery_root(
        &enrollment.canonical_record,
        enrollment.canonical_record_sha256,
        phrase,
    )
    .unwrap();
    let target_keys = DeviceKeys::from_seeds_for_test([0x91; 32], [0x92; 32]);
    let mut claim_rng = SequenceRng(0xa0);
    build_recovery_device_claim_with_rng(
        authority,
        derived_id(0x610),
        0,
        derived_id(0x611),
        PairingRequestNonce([0x93; 32]),
        derived_id(0x612),
        "Wrong Root Device".into(),
        NativePlatform::Macos,
        &target_keys,
        &mut claim_rng,
    )
    .unwrap()
}

fn contains_hex(haystack: &str, needle: &[u8]) -> bool {
    let needle = needle
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    haystack.to_ascii_lowercase().contains(&needle)
}

#[test]
fn enrolled_root_accepts_one_exact_claim_and_retains_replay_proof() {
    let provider = InMemoryRecoveryEnrollmentProvider::new();
    let enrollment = enrollment_bytes();
    provider
        .transport(scope())
        .register(&enrollment, 1_000)
        .unwrap();

    let restore = provider.restore_transport(scope());
    let snapshot = restore.root_snapshot().unwrap().expect("registered root");
    assert_eq!(snapshot.recovery_generation, 0);
    let record = snapshot.validate_for(scope()).unwrap();
    assert_eq!(
        record,
        decode_recovery_enrollment_record_v1(&enrollment).unwrap()
    );

    let canonical_claim = claim_bytes();
    let receipt = restore.submit_restore(&canonical_claim, 2_000).unwrap();
    assert_eq!(receipt.accepted_generation, 1);
    assert_eq!(
        restore.submit_restore(&canonical_claim, 9_999).unwrap(),
        receipt
    );

    let projection = restore
        .restore_claim(id::<RecoveryRestoreId>(RESTORE_ID))
        .unwrap()
        .expect("retained claim");
    assert_eq!(projection.canonical_claim, canonical_claim);
    assert_eq!(projection.receipt, receipt);
    projection.validate_for(scope(), &record).unwrap();
}

#[test]
fn stale_generation_changed_replay_and_reused_device_or_certificate_conflict() {
    let provider = InMemoryRecoveryEnrollmentProvider::new();
    register_root(&provider);
    let restore = provider.restore_transport(scope());
    let canonical = claim_bytes();
    let original = restore.submit_restore(&canonical, 2_000).unwrap();

    provider.test_set_recovery_generation(scope().account_id, i64::MAX as u64);
    assert_eq!(restore.submit_restore(&canonical, 8_000).unwrap(), original);
    provider.test_set_recovery_generation(scope().account_id, 1);

    let changed_same_restore = build_claim(
        id(RESTORE_ID),
        derived_id(0x201),
        derived_id(0x202),
        1,
        0x21,
        0x22,
        0x10,
    );
    assert_eq!(
        restore.submit_restore(&changed_same_restore.canonical_claim, 2_001),
        Err(RecoveryTransportError::Conflict)
    );

    let stale = build_claim(
        derived_id(0x210),
        derived_id(0x211),
        derived_id(0x212),
        0,
        0x31,
        0x32,
        0x20,
    );
    assert_eq!(
        restore.submit_restore(&stale.canonical_claim, 2_002),
        Err(RecoveryTransportError::Conflict)
    );

    let reused_device = build_claim(
        derived_id(0x220),
        derived_id(0x221),
        id(DEVICE_ID),
        1,
        0x66,
        0x77,
        0x30,
    );
    assert_eq!(
        restore.submit_restore(&reused_device.canonical_claim, 2_003),
        Err(RecoveryTransportError::Conflict)
    );

    let reused_certificate = build_claim(
        derived_id(0x230),
        id(CERTIFICATE_ID),
        derived_id(0x232),
        1,
        0x41,
        0x42,
        0x40,
    );
    assert_eq!(
        restore.submit_restore(&reused_certificate.canonical_claim, 2_004),
        Err(RecoveryTransportError::Conflict)
    );

    provider.test_set_recovery_generation(scope().account_id, i64::MAX as u64);
    let capped = build_claim(
        derived_id(0x240),
        derived_id(0x241),
        derived_id(0x242),
        i64::MAX as u64 - 1,
        0x51,
        0x52,
        0x50,
    );
    assert_eq!(
        restore.submit_restore(&capped.canonical_claim, 2_005),
        Err(RecoveryTransportError::Conflict)
    );
    assert_eq!(provider.test_safe_restore_captures().len(), 1);
}

#[test]
fn concurrent_generation_zero_claims_have_exactly_one_winner() {
    let provider = InMemoryRecoveryEnrollmentProvider::new();
    register_root(&provider);
    let first = build_claim(
        derived_id(0x300),
        derived_id(0x301),
        derived_id(0x302),
        0,
        0x61,
        0x62,
        0x60,
    )
    .canonical_claim;
    let second = build_claim(
        derived_id(0x310),
        derived_id(0x311),
        derived_id(0x312),
        0,
        0x71,
        0x72,
        0x70,
    )
    .canonical_claim;
    let barrier = Arc::new(Barrier::new(3));

    let first_handle = provider.restore_transport(scope());
    let first_barrier = Arc::clone(&barrier);
    let first_thread = std::thread::spawn(move || {
        first_barrier.wait();
        first_handle.submit_restore(&first, 3_000)
    });
    let second_handle = provider.restore_transport(scope());
    let second_barrier = Arc::clone(&barrier);
    let second_thread = std::thread::spawn(move || {
        second_barrier.wait();
        second_handle.submit_restore(&second, 3_001)
    });
    barrier.wait();

    let outcomes = [first_thread.join().unwrap(), second_thread.join().unwrap()];
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == Err(RecoveryTransportError::Conflict))
            .count(),
        1
    );
    assert_eq!(provider.test_safe_restore_captures().len(), 1);
    assert_eq!(
        provider
            .restore_transport(scope())
            .root_snapshot()
            .unwrap()
            .unwrap()
            .recovery_generation,
        1
    );
}

#[test]
fn missing_root_wrong_scope_invalid_claim_and_transient_failures_change_nothing() {
    let provider = InMemoryRecoveryEnrollmentProvider::new();
    let restore = provider.restore_transport(scope());
    assert!(restore.root_snapshot().unwrap().is_none());
    assert_eq!(
        restore.submit_restore(&claim_bytes(), 4_000),
        Err(RecoveryTransportError::Invalid)
    );

    register_root(&provider);
    let wrong_scope = provider.restore_transport(SyncScope {
        account_id: derived_id(0x401),
        workspace_id: derived_id(0x402),
    });
    assert_eq!(
        wrong_scope.submit_restore(&claim_bytes(), 4_001),
        Err(RecoveryTransportError::Unauthorized)
    );
    let wrong_root = valid_claim_from_another_root_in_the_same_scope();
    assert_eq!(
        restore.submit_restore(&wrong_root.canonical_claim, 4_002),
        Err(RecoveryTransportError::Invalid)
    );

    let mut bad_signature = claim_bytes();
    *bad_signature.last_mut().unwrap() ^= 1;
    assert_eq!(
        restore.submit_restore(&bad_signature, 4_003),
        Err(RecoveryTransportError::Invalid)
    );
    let mut bad_certificate = claim_bytes();
    let certificate_signature = fixture_certificate_signature();
    let offset = bad_certificate
        .windows(certificate_signature.len())
        .position(|window| window == certificate_signature)
        .unwrap();
    bad_certificate[offset] ^= 1;
    assert_eq!(
        restore.submit_restore(&bad_certificate, 4_004),
        Err(RecoveryTransportError::Invalid)
    );
    assert_eq!(
        restore.submit_restore(
            &vec![0; context_relay_core::devices::recovery_restore_crypto::MAX_RECOVERY_DEVICE_CLAIM_BYTES + 1],
            4_005,
        ),
        Err(RecoveryTransportError::Invalid)
    );

    provider.test_fail_next(3);
    assert_eq!(
        restore.root_snapshot(),
        Err(RecoveryTransportError::Transient)
    );
    assert_eq!(
        restore.submit_restore(&claim_bytes(), 4_006),
        Err(RecoveryTransportError::Transient)
    );
    assert_eq!(
        restore.restore_claim(id(RESTORE_ID)),
        Err(RecoveryTransportError::Transient)
    );
    assert!(provider.test_safe_restore_captures().is_empty());
}

fn fixture_certificate_signature() -> [u8; 64] {
    context_relay_core::devices::recovery_restore_crypto::decode_recovery_device_claim_v1(
        &claim_bytes(),
    )
    .unwrap()
    .certificate
    .signature
    .0
}

#[test]
fn forged_snapshot_receipt_projection_and_omission_are_detectable_without_losing_truth() {
    let provider = InMemoryRecoveryEnrollmentProvider::new();
    register_root(&provider);
    let restore = provider.restore_transport(scope());
    let real_snapshot = restore.root_snapshot().unwrap().unwrap();
    let record = real_snapshot.validate_for(scope()).unwrap();

    let mut forged_snapshot = real_snapshot.clone();
    forged_snapshot.canonical_record_sha256.0[0] ^= 1;
    provider.test_forge_next_restore_snapshot(forged_snapshot.clone());
    let returned = restore.root_snapshot().unwrap().unwrap();
    assert_eq!(returned, forged_snapshot);
    assert_eq!(
        returned.validate_for(scope()),
        Err(RecoveryTransportError::Conflict)
    );
    assert_eq!(restore.root_snapshot().unwrap().unwrap(), real_snapshot);

    let real_receipt = restore.submit_restore(&claim_bytes(), 5_000).unwrap();
    let assert_receipt_conflict = |receipt: RecoveryRestoreReceipt| {
        assert_eq!(
            receipt.validate_for(scope(), &record, &claim_bytes()),
            Err(RecoveryTransportError::Conflict)
        );
    };
    let mut changed = real_receipt.clone();
    changed.restore_id = derived_id(0x501);
    assert_receipt_conflict(changed);
    let mut changed = real_receipt.clone();
    changed.enrollment_id = derived_id(0x502);
    assert_receipt_conflict(changed);
    let mut changed = real_receipt.clone();
    changed.recovery_root_id = derived_id(0x503);
    assert_receipt_conflict(changed);
    let mut changed = real_receipt.clone();
    changed.account_id = derived_id(0x504);
    assert_receipt_conflict(changed);
    let mut changed = real_receipt.clone();
    changed.workspace_id = derived_id(0x505);
    assert_receipt_conflict(changed);
    let mut changed = real_receipt.clone();
    changed.certificate_id = derived_id(0x506);
    assert_receipt_conflict(changed);
    let mut changed = real_receipt.clone();
    changed.canonical_record_sha256.0[0] ^= 1;
    assert_receipt_conflict(changed);
    let mut changed = real_receipt.clone();
    changed.canonical_claim_sha256.0[0] ^= 1;
    assert_receipt_conflict(changed);
    let mut changed = real_receipt.clone();
    changed.accepted_generation += 1;
    assert_receipt_conflict(changed);

    let mut forged_receipt = real_receipt.clone();
    forged_receipt.canonical_claim_sha256.0[0] ^= 1;
    provider.test_forge_next_restore_receipt(forged_receipt.clone());
    assert_eq!(
        restore.submit_restore(&claim_bytes(), 9_999).unwrap(),
        forged_receipt
    );
    assert_eq!(
        forged_receipt.validate_for(scope(), &record, &claim_bytes()),
        Err(RecoveryTransportError::Conflict)
    );

    let real_projection = restore.restore_claim(id(RESTORE_ID)).unwrap().unwrap();
    let mut forged_projection = real_projection.clone();
    forged_projection.receipt.certificate_id = derived_id(0x507);
    provider.test_forge_next_restore_projection(forged_projection.clone());
    let returned = restore.restore_claim(id(RESTORE_ID)).unwrap().unwrap();
    assert_eq!(returned, forged_projection);
    assert_eq!(
        returned.validate_for(scope(), &record),
        Err(RecoveryTransportError::Conflict)
    );
    provider.test_omit_next_restore_claim();
    assert!(restore.restore_claim(id(RESTORE_ID)).unwrap().is_none());
    assert_eq!(
        restore.restore_claim(id(RESTORE_ID)).unwrap().unwrap(),
        real_projection
    );
}

#[test]
fn deletion_and_safe_captures_include_only_bounded_public_metadata() {
    let provider = InMemoryRecoveryEnrollmentProvider::new();
    register_root(&provider);
    let restore = provider.restore_transport(scope());
    let receipt = restore.submit_restore(&claim_bytes(), 6_000).unwrap();
    let projection = restore.restore_claim(id(RESTORE_ID)).unwrap().unwrap();
    let captures = provider.test_safe_restore_captures();
    assert_eq!(captures.len(), 1);
    assert_eq!(captures[0].canonical_claim_len, claim_bytes().len());
    assert_eq!(
        captures[0].canonical_claim_sha256,
        receipt.canonical_claim_sha256
    );

    let diagnostic = format!(
        "{provider:?} {restore:?} {projection:?} {captures:?} {:?}",
        RecoveryTransportError::Invalid,
    );
    assert!(diagnostic.contains("[REDACTED]"));
    assert!(!diagnostic.contains("abandon abandon abandon"));
    assert!(!contains_hex(&diagnostic, &[0x44; 32]));
    assert!(!contains_hex(&diagnostic, &[0x55; 32]));
    assert!(!diagnostic.contains(&format!("{:?}", claim_bytes())));

    provider.test_delete_account(scope().account_id);
    assert!(restore.root_snapshot().unwrap().is_none());
    assert!(restore.restore_claim(id(RESTORE_ID)).unwrap().is_none());
    assert!(provider.test_safe_restore_captures().is_empty());
}
