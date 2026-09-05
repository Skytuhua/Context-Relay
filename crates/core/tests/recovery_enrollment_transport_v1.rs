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
            MAX_RECOVERY_ENROLLMENT_RECORD_BYTES, RecoveryEnrollmentArtifacts,
            RecoveryEnrollmentBuildRequest, build_recovery_enrollment_artifacts_with_rng,
        },
        recovery_transport::{
            RecoveryEnrollmentReceipt, RecoveryEnrollmentTransport, RecoveryTransportError,
        },
    },
    sync::SyncScope,
};
use context_relay_protocol::{
    AccountId, DeviceCertificateId, DeviceId, NativePlatform, PairingRequestNonce,
    RecoveryEnrollmentId, RecoveryRootId, Sha256Digest, WorkspaceId,
};
use rand_core::{CryptoRng, Error as RandError, RngCore};

const ACCOUNT_A: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07398f";
const WORKSPACE_A: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07398e";
const ACCOUNT_B: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073988";
const WORKSPACE_B: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073987";
const WORKSPACE_OTHER: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073986";
const PHRASE_CANARY: &str = "abandon abandon abandon";

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

struct Fixture {
    scope: SyncScope,
    artifacts: RecoveryEnrollmentArtifacts,
}

fn id<T: FromStr>(value: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    value.parse().unwrap()
}

fn derived_id<T: FromStr>(suffix: u16) -> T
where
    T::Err: std::fmt::Debug,
{
    id(&format!("018f22e2-79b0-7cc8-98c4-dc0c0c07{suffix:04x}"))
}

fn fixture(
    scope: SyncScope,
    id_base: u16,
    phrase_entropy: u8,
    device_seed: u8,
    rng_start: u8,
) -> Fixture {
    let recovery =
        RecoveryKeys::derive(&RecoveryPhrase::from_entropy_for_test([phrase_entropy; 32]).unwrap())
            .unwrap();
    let device = DeviceKeys::from_seeds_for_test([device_seed; 32], [device_seed + 1; 32]);
    let material = PairingKeyBundle::new(scope, 1, 1, [0x44; 32], [0x55; 32]).unwrap();
    let certificate = DeviceCertificateV1::issue_genesis(
        CertificateFieldsV1 {
            account_id: scope.account_id,
            workspace_id: scope.workspace_id,
            control_epoch: 1,
            request_nonce: PairingRequestNonce([id_base as u8; 32]),
            device_id: derived_id::<DeviceId>(id_base + 2),
            signing_public_key: device.signing_public_key(),
            wrapping_public_key: device.wrapping_public_key(),
        },
        &recovery,
    )
    .unwrap();
    let mut rng = SequenceRng(rng_start);
    let artifacts = build_recovery_enrollment_artifacts_with_rng(
        RecoveryEnrollmentBuildRequest {
            enrollment_id: derived_id::<RecoveryEnrollmentId>(id_base),
            recovery_root_id: derived_id::<RecoveryRootId>(id_base + 1),
            certificate_id: derived_id::<DeviceCertificateId>(id_base + 3),
            certificate,
            device_name: format!("Device {id_base}"),
            device_platform: NativePlatform::Macos,
            recovery_keys: &recovery,
            device_keys: &device,
            material: &material,
        },
        &mut rng,
    )
    .unwrap();
    Fixture { scope, artifacts }
}

fn scope(account: &str, workspace: &str) -> SyncScope {
    SyncScope {
        account_id: id::<AccountId>(account),
        workspace_id: id::<WorkspaceId>(workspace),
    }
}

fn contains(haystack: &str, needle: &[u8]) -> bool {
    let needle = needle
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    haystack.to_ascii_lowercase().contains(&needle)
}

#[test]
fn first_registration_status_and_exact_retry_are_idempotent_per_account() {
    let provider = InMemoryRecoveryEnrollmentProvider::new();
    let fixture_a = fixture(scope(ACCOUNT_A, WORKSPACE_A), 0x100, 0, 0x11, 0x60);
    let fixture_b = fixture(scope(ACCOUNT_B, WORKSPACE_B), 0x110, 1, 0x21, 0x70);
    let handle_a = provider.transport(fixture_a.scope);
    let handle_b = provider.transport(fixture_b.scope);
    assert_eq!(handle_a.scope(), fixture_a.scope);
    assert_eq!(handle_b.scope(), fixture_b.scope);

    let receipt_a = handle_a
        .register(&fixture_a.artifacts.canonical_record, 1_000)
        .unwrap();
    assert_eq!(
        receipt_a,
        RecoveryEnrollmentReceipt {
            enrollment_id: fixture_a.artifacts.record.enrollment_id,
            recovery_root_id: fixture_a.artifacts.record.recovery_root_id,
            account_id: fixture_a.scope.account_id,
            workspace_id: fixture_a.scope.workspace_id,
            genesis_certificate_id: fixture_a.artifacts.record.genesis_certificate_id,
            canonical_record_sha256: fixture_a.artifacts.canonical_record_sha256,
            registered_at_ms: 1_000,
        }
    );
    receipt_a
        .validate_for(
            fixture_a.scope,
            &fixture_a.artifacts.record,
            fixture_a.artifacts.canonical_record_sha256,
            1_000,
        )
        .unwrap();
    assert_eq!(
        handle_a.root_status().unwrap(),
        Some(receipt_a.clone().into_status())
    );
    assert_eq!(
        handle_a
            .register(&fixture_a.artifacts.canonical_record, 9_999)
            .unwrap(),
        receipt_a
    );

    let receipt_b = handle_b
        .register(&fixture_b.artifacts.canonical_record, 2_000)
        .unwrap();
    assert_ne!(receipt_a.account_id, receipt_b.account_id);
    assert_eq!(
        handle_b.root_status().unwrap(),
        Some(receipt_b.into_status())
    );
}

#[test]
fn same_account_different_record_or_workspace_conflicts() {
    let provider = InMemoryRecoveryEnrollmentProvider::new();
    let original = fixture(scope(ACCOUNT_A, WORKSPACE_A), 0x120, 2, 0x31, 0x80);
    let changed = fixture(scope(ACCOUNT_A, WORKSPACE_A), 0x130, 3, 0x41, 0x90);
    let other_workspace = fixture(scope(ACCOUNT_A, WORKSPACE_OTHER), 0x140, 4, 0x51, 0xa0);
    provider
        .transport(original.scope)
        .register(&original.artifacts.canonical_record, 3_000)
        .unwrap();

    assert_eq!(
        provider
            .transport(changed.scope)
            .register(&changed.artifacts.canonical_record, 3_001),
        Err(RecoveryTransportError::Conflict)
    );
    assert_eq!(
        provider
            .transport(other_workspace.scope)
            .register(&other_workspace.artifacts.canonical_record, 3_002),
        Err(RecoveryTransportError::Conflict)
    );
    assert_eq!(
        provider.transport(other_workspace.scope).root_status(),
        Err(RecoveryTransportError::Conflict)
    );
}

#[test]
fn concurrent_different_records_for_one_account_have_exactly_one_winner() {
    let provider = InMemoryRecoveryEnrollmentProvider::new();
    let first = fixture(scope(ACCOUNT_A, WORKSPACE_A), 0x150, 5, 0x61, 0xb0);
    let second = fixture(scope(ACCOUNT_A, WORKSPACE_A), 0x160, 6, 0x71, 0xc0);
    let barrier = Arc::new(Barrier::new(3));

    let first_handle = provider.transport(first.scope);
    let first_barrier = Arc::clone(&barrier);
    let first_bytes = first.artifacts.canonical_record;
    let first_thread = std::thread::spawn(move || {
        first_barrier.wait();
        first_handle.register(&first_bytes, 4_000)
    });
    let second_handle = provider.transport(second.scope);
    let second_barrier = Arc::clone(&barrier);
    let second_bytes = second.artifacts.canonical_record;
    let second_thread = std::thread::spawn(move || {
        second_barrier.wait();
        second_handle.register(&second_bytes, 4_001)
    });
    barrier.wait();

    let outcomes = [first_thread.join().unwrap(), second_thread.join().unwrap()];
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| **result == Err(RecoveryTransportError::Conflict))
            .count(),
        1
    );
}

#[test]
fn scope_signature_certificate_epoch_canonical_and_size_mutations_fail_closed() {
    let provider = InMemoryRecoveryEnrollmentProvider::new();
    let fixture = fixture(scope(ACCOUNT_A, WORKSPACE_A), 0x170, 7, 0x81, 0xd0);
    let wrong_scope = provider.transport(scope(ACCOUNT_B, WORKSPACE_B));
    assert_eq!(
        wrong_scope.register(&fixture.artifacts.canonical_record, 5_000),
        Err(RecoveryTransportError::Unauthorized)
    );

    let handle = provider.transport(fixture.scope);
    let mut forged_record_signature = fixture.artifacts.canonical_record.clone();
    *forged_record_signature.last_mut().unwrap() ^= 1;
    assert_eq!(
        handle.register(&forged_record_signature, 5_001),
        Err(RecoveryTransportError::Invalid)
    );

    let certificate_signature = fixture.artifacts.record.genesis_certificate.signature.0;
    let offset = fixture
        .artifacts
        .canonical_record
        .windows(certificate_signature.len())
        .position(|window| window == certificate_signature)
        .expect("nested certificate signature");
    let mut forged_certificate = fixture.artifacts.canonical_record.clone();
    forged_certificate[offset] ^= 1;
    assert_eq!(
        handle.register(&forged_certificate, 5_002),
        Err(RecoveryTransportError::Invalid)
    );

    let mut non_initial_key_epoch = fixture.artifacts.canonical_record.clone();
    let epoch = non_initial_key_epoch
        .windows(3)
        .position(|window| window == [0x0b, 0x01, 0x0c])
        .expect("key epoch field");
    non_initial_key_epoch[epoch + 1] = 2;
    assert_eq!(
        handle.register(&non_initial_key_epoch, 5_003),
        Err(RecoveryTransportError::Invalid)
    );

    let mut non_initial_control_epoch = fixture.artifacts.canonical_record.clone();
    let epoch = non_initial_control_epoch
        .windows(5)
        .position(|window| window == [0x03, 0x01, 0x04, 0x58, 0x20])
        .expect("certificate control epoch field");
    non_initial_control_epoch[epoch + 1] = 2;
    assert_eq!(
        handle.register(&non_initial_control_epoch, 5_004),
        Err(RecoveryTransportError::Invalid)
    );

    let mut changed_canonical_byte = fixture.artifacts.canonical_record.clone();
    changed_canonical_byte[1] = 1;
    assert_eq!(
        handle.register(&changed_canonical_byte, 5_005),
        Err(RecoveryTransportError::Invalid)
    );
    assert_eq!(
        handle.register(&vec![0; MAX_RECOVERY_ENROLLMENT_RECORD_BYTES + 1], 5_006,),
        Err(RecoveryTransportError::Invalid)
    );
    assert_eq!(handle.root_status().unwrap(), None);
}

#[test]
fn transient_and_forged_provider_projections_are_explicit_and_verifiable() {
    let provider = InMemoryRecoveryEnrollmentProvider::new();
    let fixture = fixture(scope(ACCOUNT_A, WORKSPACE_A), 0x180, 8, 0x91, 0xe0);
    let handle = provider.transport(fixture.scope);

    provider.test_fail_next(2);
    assert_eq!(handle.root_status(), Err(RecoveryTransportError::Transient));
    assert_eq!(
        handle.register(&fixture.artifacts.canonical_record, 6_000),
        Err(RecoveryTransportError::Transient)
    );
    assert_eq!(handle.root_status().unwrap(), None);

    let expected = RecoveryEnrollmentReceipt {
        enrollment_id: fixture.artifacts.record.enrollment_id,
        recovery_root_id: fixture.artifacts.record.recovery_root_id,
        account_id: fixture.scope.account_id,
        workspace_id: fixture.scope.workspace_id,
        genesis_certificate_id: fixture.artifacts.record.genesis_certificate_id,
        canonical_record_sha256: fixture.artifacts.canonical_record_sha256,
        registered_at_ms: 6_001,
    };
    let assert_receipt_conflict = |receipt: RecoveryEnrollmentReceipt| {
        assert_eq!(
            receipt.validate_for(
                fixture.scope,
                &fixture.artifacts.record,
                fixture.artifacts.canonical_record_sha256,
                6_001,
            ),
            Err(RecoveryTransportError::Conflict)
        );
    };
    let mut changed = expected.clone();
    changed.enrollment_id = derived_id(0x1f0);
    assert_receipt_conflict(changed);
    let mut changed = expected.clone();
    changed.recovery_root_id = derived_id(0x1f1);
    assert_receipt_conflict(changed);
    let mut changed = expected.clone();
    changed.account_id = id(ACCOUNT_B);
    assert_receipt_conflict(changed);
    let mut changed = expected.clone();
    changed.workspace_id = id(WORKSPACE_B);
    assert_receipt_conflict(changed);
    let mut changed = expected.clone();
    changed.genesis_certificate_id = derived_id(0x1f2);
    assert_receipt_conflict(changed);
    let mut changed = expected.clone();
    changed.canonical_record_sha256 = Sha256Digest([0x98; 32]);
    assert_receipt_conflict(changed);
    let mut changed = expected.clone();
    changed.registered_at_ms += 1;
    assert_receipt_conflict(changed);

    let mut forged_receipt = expected.clone();
    forged_receipt.canonical_record_sha256 = Sha256Digest([0x99; 32]);
    provider.test_forge_next_receipt(forged_receipt.clone());
    assert_eq!(
        handle
            .register(&fixture.artifacts.canonical_record, 6_001)
            .unwrap(),
        forged_receipt
    );
    assert_eq!(
        forged_receipt.validate_for(
            fixture.scope,
            &fixture.artifacts.record,
            fixture.artifacts.canonical_record_sha256,
            6_001,
        ),
        Err(RecoveryTransportError::Conflict)
    );
    assert_eq!(
        handle
            .register(&fixture.artifacts.canonical_record, 9_999)
            .unwrap(),
        expected
    );

    let mut forged_status = expected.clone().into_status();
    forged_status.genesis_certificate_id = derived_id(0x1ff);
    provider.test_forge_next_status(forged_status.clone());
    assert_eq!(handle.root_status().unwrap(), Some(forged_status.clone()));
    assert_eq!(
        forged_status.validate_for(
            fixture.scope,
            &fixture.artifacts.record,
            fixture.artifacts.canonical_record_sha256,
            6_001,
        ),
        Err(RecoveryTransportError::Conflict)
    );
    let mut forged_timestamp_status = expected.clone().into_status();
    forged_timestamp_status.registered_at_ms += 1;
    provider.test_forge_next_status(forged_timestamp_status.clone());
    assert_eq!(
        handle.root_status().unwrap(),
        Some(forged_timestamp_status.clone())
    );
    assert_eq!(
        forged_timestamp_status.validate_for(
            fixture.scope,
            &fixture.artifacts.record,
            fixture.artifacts.canonical_record_sha256,
            6_001,
        ),
        Err(RecoveryTransportError::Conflict)
    );
    assert_eq!(handle.root_status().unwrap(), Some(expected.into_status()));
}

#[test]
fn captures_debug_and_errors_expose_only_safe_bounded_metadata() {
    let provider = InMemoryRecoveryEnrollmentProvider::new();
    let fixture = fixture(scope(ACCOUNT_A, WORKSPACE_A), 0x190, 0, 0xa1, 0xf0);
    let handle = provider.transport(fixture.scope);
    handle
        .register(&fixture.artifacts.canonical_record, 7_000)
        .unwrap();

    let captures = provider.test_safe_captures();
    assert_eq!(captures.len(), 1);
    assert_eq!(
        captures[0].canonical_record_len,
        fixture.artifacts.canonical_record.len()
    );
    assert_eq!(
        captures[0].canonical_record_sha256,
        fixture.artifacts.canonical_record_sha256
    );
    let diagnostic = format!(
        "{provider:?} {handle:?} {captures:?} {:?} {:?}",
        RecoveryTransportError::Invalid,
        RecoveryTransportError::Transient,
    );
    assert!(!diagnostic.contains(PHRASE_CANARY));
    assert!(!contains(&diagnostic, &[0x44; 32]));
    assert!(!contains(&diagnostic, &[0x55; 32]));
    assert!(!contains(
        &diagnostic,
        &fixture
            .artifacts
            .record
            .encrypted_recovery_metadata
            .ciphertext,
    ));
    assert!(!diagnostic.contains(&format!(
        "{:?}",
        fixture
            .artifacts
            .record
            .encrypted_recovery_metadata
            .ciphertext
    )));
    assert!(!diagnostic.contains(&format!("{:?}", fixture.artifacts.canonical_record)));
    assert!(!diagnostic.contains("invalid recovery enrollment record"));
    assert!(diagnostic.contains("recovery_invalid"));
    assert_eq!(
        format!("{:?}", RecoveryTransportError::Conflict),
        "recovery_conflict"
    );
    assert_eq!(
        format!("{:?}", RecoveryTransportError::Unauthorized),
        "recovery_unauthorized"
    );
    assert!(diagnostic.contains("transient"));
}
