mod support;

use std::{path::Path, str::FromStr};

use context_relay_core::{
    crypto::{CertificateFieldsV1, DeviceCertificateV1, DeviceKeys, RecoveryKeys, RecoveryPhrase},
    devices::{
        crypto::{PairingKeyBundle, SignedPairingRequest},
        recovery_crypto::{
            RecoveryEnrollmentArtifacts, RecoveryEnrollmentBuildRequest,
            build_recovery_enrollment_artifacts,
        },
        recovery_transport::RecoveryEnrollmentReceipt,
    },
    sync::SyncScope,
    vault::{
        CommitDisposition, DeviceCertificateState, LATEST_SCHEMA_VERSION,
        RecoveryEnrollmentPersistenceState, RecoveryEnrollmentWrite, Vault, VaultError,
    },
};
use context_relay_protocol::{
    AccountId, DeviceCertificateId, DeviceId, NativePlatform, PairingId, PairingRequestNonce,
    RecoveryEnrollmentId, RecoveryRootId, WorkspaceId,
};
use rusqlite::Connection;

use support::{MemoryKeyStore, TempVault};

const CREDENTIAL: &str = "recovery-enrollment-vault-v1";
const ACCOUNT_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073981";
const WORKSPACE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073982";
const ENROLLMENT_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073983";
const RECOVERY_ROOT_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073984";
const DEVICE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073985";
const CERTIFICATE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073986";
const OTHER_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073987";

fn id<T: FromStr>(value: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    value.parse().unwrap()
}

struct Fixture {
    device_keys: DeviceKeys,
    material: PairingKeyBundle,
    artifacts: RecoveryEnrollmentArtifacts,
}

fn fixture() -> Fixture {
    let recovery_phrase = RecoveryPhrase::from_entropy_for_test([0x31; 32]).unwrap();
    let recovery_keys = RecoveryKeys::derive(&recovery_phrase).unwrap();
    let device_keys = DeviceKeys::from_seeds_for_test([0x41; 32], [0x51; 32]);
    let scope = SyncScope {
        account_id: id::<AccountId>(ACCOUNT_ID),
        workspace_id: id::<WorkspaceId>(WORKSPACE_ID),
    };
    let material = PairingKeyBundle::new(scope, 1, 1, [0x61; 32], [0x71; 32]).unwrap();
    let certificate = DeviceCertificateV1::issue_genesis(
        CertificateFieldsV1 {
            account_id: scope.account_id,
            workspace_id: scope.workspace_id,
            control_epoch: 1,
            request_nonce: PairingRequestNonce([0x81; 32]),
            device_id: id::<DeviceId>(DEVICE_ID),
            signing_public_key: device_keys.signing_public_key(),
            wrapping_public_key: device_keys.wrapping_public_key(),
        },
        &recovery_keys,
    )
    .unwrap();
    let artifacts = build_recovery_enrollment_artifacts(RecoveryEnrollmentBuildRequest {
        enrollment_id: id::<RecoveryEnrollmentId>(ENROLLMENT_ID),
        recovery_root_id: id::<RecoveryRootId>(RECOVERY_ROOT_ID),
        certificate_id: id::<DeviceCertificateId>(CERTIFICATE_ID),
        certificate,
        device_name: "First Mac".into(),
        device_platform: NativePlatform::Macos,
        recovery_keys: &recovery_keys,
        device_keys: &device_keys,
        material: &material,
    })
    .unwrap();
    Fixture {
        device_keys,
        material,
        artifacts,
    }
}

fn write(artifacts: &RecoveryEnrollmentArtifacts, prepared_at_ms: u64) -> RecoveryEnrollmentWrite {
    RecoveryEnrollmentWrite {
        canonical_record: artifacts.canonical_record.clone(),
        canonical_record_sha256: artifacts.canonical_record_sha256,
        device_material_envelope: artifacts.device_material_envelope.clone(),
        device_material_envelope_sha256: artifacts.device_material_envelope_sha256,
        prepared_at_ms,
    }
}

fn receipt(
    artifacts: &RecoveryEnrollmentArtifacts,
    registered_at_ms: u64,
) -> RecoveryEnrollmentReceipt {
    RecoveryEnrollmentReceipt {
        enrollment_id: artifacts.record.enrollment_id,
        recovery_root_id: artifacts.record.recovery_root_id,
        account_id: artifacts.record.account_id,
        workspace_id: artifacts.record.workspace_id,
        genesis_certificate_id: artifacts.record.genesis_certificate_id,
        canonical_record_sha256: artifacts.canonical_record_sha256,
        registered_at_ms,
    }
}

fn open_keyed(path: &Path, key: &[u8; 32]) -> Connection {
    let connection = Connection::open(path).unwrap();
    // SAFETY: this is the first SQLite operation and the key remains live for the call.
    let result = unsafe {
        rusqlite::ffi::sqlite3_key(
            connection.handle(),
            key.as_ptr().cast(),
            key.len().try_into().unwrap(),
        )
    };
    assert_eq!(result, rusqlite::ffi::SQLITE_OK);
    connection
        .query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
        .unwrap();
    connection
}

#[test]
fn prepared_enrollment_activates_exactly_and_reopens_sealed_material() {
    let path = TempVault::new("recovery-enrollment-lifecycle");
    let keys = MemoryKeyStore::default();
    let fixture = fixture();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let write = write(&fixture.artifacts, 2_000);

    assert_eq!(
        vault.prepare_recovery_enrollment(&write).unwrap(),
        CommitDisposition::Inserted
    );
    assert_eq!(
        vault.prepare_recovery_enrollment(&write).unwrap(),
        CommitDisposition::ExactReplay
    );
    assert_eq!(
        vault.recovery_enrollment().unwrap().unwrap().state,
        RecoveryEnrollmentPersistenceState::Prepared
    );
    assert_eq!(
        vault
            .activate_recovery_enrollment(
                &receipt(&fixture.artifacts, 2_500),
                &fixture.device_keys,
                3_000
            )
            .unwrap(),
        CommitDisposition::Inserted
    );
    assert_eq!(
        vault
            .activate_recovery_enrollment(
                &receipt(&fixture.artifacts, 2_500),
                &fixture.device_keys,
                3_000
            )
            .unwrap(),
        CommitDisposition::ExactReplay
    );
    drop(vault);

    let reopened = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let stored = reopened.recovery_enrollment().unwrap().unwrap();
    assert_eq!(stored.state, RecoveryEnrollmentPersistenceState::Active);
    assert_eq!(stored.provider_accepted_at_ms, Some(2_500));
    assert_eq!(stored.completed_at_ms, Some(3_000));
    let material = reopened
        .enrolled_workspace_material(&fixture.device_keys)
        .unwrap();
    assert_eq!(
        material.scope(),
        SyncScope {
            account_id: fixture.material.account_id(),
            workspace_id: fixture.material.workspace_id(),
        }
    );
    assert_eq!(material.control_epoch(), fixture.material.control_epoch());
    assert_eq!(material.key_epoch(), fixture.material.key_epoch());
    assert_eq!(
        material.workspace_root_key(),
        fixture.material.workspace_root_key()
    );
    assert_eq!(
        material.active_epoch_key(),
        fixture.material.active_epoch_key()
    );
}

#[test]
fn changed_prepare_and_terminal_conflict_are_exactly_idempotent() {
    let path = TempVault::new("recovery-enrollment-conflict");
    let keys = MemoryKeyStore::default();
    let first = fixture();
    let second = fixture();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault
        .prepare_recovery_enrollment(&write(&first.artifacts, 2_000))
        .unwrap();

    assert!(matches!(
        vault.prepare_recovery_enrollment(&write(&first.artifacts, 2_001)),
        Err(VaultError::OperationConflict)
    ));
    assert!(matches!(
        vault.prepare_recovery_enrollment(&write(&second.artifacts, 2_000)),
        Err(VaultError::OperationConflict)
    ));
    assert_eq!(
        vault.mark_recovery_enrollment_conflict(2_500).unwrap(),
        CommitDisposition::Inserted
    );
    assert_eq!(
        vault.mark_recovery_enrollment_conflict(2_500).unwrap(),
        CommitDisposition::ExactReplay
    );
    assert!(matches!(
        vault.mark_recovery_enrollment_conflict(2_501),
        Err(VaultError::OperationConflict)
    ));
    assert_eq!(
        vault.recovery_enrollment().unwrap().unwrap().state,
        RecoveryEnrollmentPersistenceState::Conflict
    );
    assert!(matches!(
        vault.activate_recovery_enrollment(
            &receipt(&first.artifacts, 2_000),
            &first.device_keys,
            3_000
        ),
        Err(VaultError::OperationConflict)
    ));
}

#[test]
fn activation_rolls_back_certificate_and_state_then_resumes_after_reopen() {
    let path = TempVault::new("recovery-enrollment-atomic");
    let keys = MemoryKeyStore::default();
    let fixture = fixture();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault
        .prepare_recovery_enrollment(&write(&fixture.artifacts, 2_000))
        .unwrap();
    drop(vault);

    let key = keys.key(CREDENTIAL);
    let raw = open_keyed(path.path(), &key);
    raw.execute_batch(
        "CREATE TRIGGER abort_recovery_activation
         BEFORE UPDATE OF state ON recovery_enrollments
         WHEN NEW.state = 'active'
         BEGIN
           SELECT RAISE(ABORT, 'injected activation failure');
         END;",
    )
    .unwrap();
    drop(raw);

    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert!(
        vault
            .activate_recovery_enrollment(
                &receipt(&fixture.artifacts, 2_000),
                &fixture.device_keys,
                3_000,
            )
            .is_err()
    );
    drop(vault);

    let raw = open_keyed(path.path(), &key);
    raw.execute_batch("DROP TRIGGER abort_recovery_activation")
        .unwrap();
    drop(raw);
    let mut reopened = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert!(
        reopened
            .device_certificate(id::<DeviceCertificateId>(CERTIFICATE_ID))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        reopened.recovery_enrollment().unwrap().unwrap().state,
        RecoveryEnrollmentPersistenceState::Prepared
    );
    assert!(
        reopened
            .enrolled_workspace_material(&fixture.device_keys)
            .is_err()
    );
    assert_eq!(
        reopened
            .activate_recovery_enrollment(
                &receipt(&fixture.artifacts, 2_000),
                &fixture.device_keys,
                3_000,
            )
            .unwrap(),
        CommitDisposition::Inserted
    );
}

fn assert_prepared_tamper_rejected(name: &str, mutate: impl FnOnce(&Connection)) {
    let path = TempVault::new(name);
    let keys = MemoryKeyStore::default();
    let fixture = fixture();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault
        .prepare_recovery_enrollment(&write(&fixture.artifacts, 2_000))
        .unwrap();
    drop(vault);
    let raw = open_keyed(path.path(), &keys.key(CREDENTIAL));
    raw.execute_batch("PRAGMA ignore_check_constraints = ON")
        .unwrap();
    mutate(&raw);
    drop(raw);
    let vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert!(matches!(
        vault.recovery_enrollment(),
        Err(VaultError::Validation(_))
    ));
}

#[test]
fn every_prepared_row_binding_and_sealed_byte_fails_closed_when_tampered() {
    let other = OTHER_ID.to_owned();
    for column in [
        "enrollment_id",
        "recovery_root_id",
        "account_id",
        "workspace_id",
        "device_id",
        "genesis_certificate_id",
    ] {
        let other = other.clone();
        assert_prepared_tamper_rejected(column, move |raw| {
            raw.execute(
                &format!("UPDATE recovery_enrollments SET {column} = ?1"),
                [&other],
            )
            .unwrap();
        });
    }
    for column in [
        "recovery_signing_public_key",
        "recovery_wrapping_public_key",
        "device_signing_public_key",
        "device_wrapping_public_key",
        "canonical_record_sha256",
        "device_envelope_sha256",
    ] {
        assert_prepared_tamper_rejected(column, move |raw| {
            raw.execute(
                &format!("UPDATE recovery_enrollments SET {column} = ?1"),
                [vec![0x99_u8; 32]],
            )
            .unwrap();
        });
    }
    for (name, sql) in [
        (
            "device-name",
            "UPDATE recovery_enrollments SET device_name = 'Other Mac'",
        ),
        (
            "platform",
            "UPDATE recovery_enrollments SET platform = 'windows'",
        ),
        (
            "control-epoch",
            "UPDATE recovery_enrollments SET control_epoch = 2",
        ),
        ("key-epoch", "UPDATE recovery_enrollments SET key_epoch = 2"),
        (
            "record-bytes",
            "UPDATE recovery_enrollments SET canonical_record = zeroblob(length(canonical_record))",
        ),
        (
            "envelope-bytes",
            "UPDATE recovery_enrollments SET device_material_envelope = zeroblob(length(device_material_envelope))",
        ),
        ("state", "UPDATE recovery_enrollments SET state = 'active'"),
        (
            "prepared-time",
            "UPDATE recovery_enrollments SET prepared_at_ms = -1",
        ),
        (
            "provider-time",
            "UPDATE recovery_enrollments SET provider_accepted_at_ms = 9",
        ),
        (
            "completed-time",
            "UPDATE recovery_enrollments SET completed_at_ms = 9",
        ),
        (
            "conflict-time",
            "UPDATE recovery_enrollments SET conflict_at_ms = 9",
        ),
    ] {
        assert_prepared_tamper_rejected(name, move |raw| {
            raw.execute_batch(sql).unwrap();
        });
    }
}

#[test]
fn active_certificate_and_replay_metadata_tampering_fail_closed() {
    for (name, table, assignment, material_must_fail) in [
        (
            "activated-id",
            "recovery_enrollments",
            format!("activated_certificate_id = '{OTHER_ID}'"),
            true,
        ),
        (
            "provider-time",
            "recovery_enrollments",
            "provider_accepted_at_ms = 2001".to_owned(),
            false,
        ),
        (
            "completed-time",
            "recovery_enrollments",
            "completed_at_ms = 1999".to_owned(),
            true,
        ),
        (
            "certificate-name",
            "device_certificates",
            "device_name = 'Other Mac'".to_owned(),
            true,
        ),
        (
            "certificate-platform",
            "device_certificates",
            "platform = 'windows'".to_owned(),
            true,
        ),
        (
            "certificate-state",
            "device_certificates",
            "state = 'revoked'".to_owned(),
            true,
        ),
        (
            "certificate-hash",
            "device_certificates",
            "canonical_sha256 = zeroblob(32)".to_owned(),
            true,
        ),
        (
            "certificate-bytes",
            "device_certificates",
            "canonical_bytes = zeroblob(length(canonical_bytes))".to_owned(),
            true,
        ),
        (
            "certificate-time",
            "device_certificates",
            "stored_at_ms = 3001".to_owned(),
            true,
        ),
    ] {
        let path = TempVault::new(name);
        let keys = MemoryKeyStore::default();
        let fixture = fixture();
        let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
        vault
            .prepare_recovery_enrollment(&write(&fixture.artifacts, 2_000))
            .unwrap();
        vault
            .activate_recovery_enrollment(
                &receipt(&fixture.artifacts, 2_000),
                &fixture.device_keys,
                3_000,
            )
            .unwrap();
        drop(vault);
        let raw = open_keyed(path.path(), &keys.key(CREDENTIAL));
        raw.execute_batch("PRAGMA foreign_keys = OFF; PRAGMA ignore_check_constraints = ON")
            .unwrap();
        raw.execute_batch(&format!("UPDATE {table} SET {assignment}"))
            .unwrap();
        drop(raw);
        let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
        assert!(
            vault.recovery_enrollment().is_err()
                || vault
                    .activate_recovery_enrollment(
                        &receipt(&fixture.artifacts, 2_000),
                        &fixture.device_keys,
                        3_000,
                    )
                    .is_err()
        );
        if material_must_fail {
            assert!(
                vault
                    .enrolled_workspace_material(&fixture.device_keys)
                    .is_err()
            );
        }
    }
}

#[test]
fn schema_21_rows_survive_schema_22_upgrade_and_material_plaintext_is_absent() {
    let path = TempVault::new("recovery-schema-21-upgrade");
    let keys = MemoryKeyStore::default();
    let fixture = fixture();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault
        .store_device_certificate(
            fixture.artifacts.record.genesis_certificate_id,
            &fixture.artifacts.record.genesis_certificate,
            DeviceCertificateState::Active,
            &context_relay_core::vault::DeviceDisplayMetadata {
                device_name: fixture.artifacts.record.device_name.clone(),
                platform: fixture.artifacts.record.device_platform,
            },
            1_000,
        )
        .unwrap();
    let joining_keys = DeviceKeys::from_seeds_for_test([0x91; 32], [0xa1; 32]);
    let pairing_id = id::<PairingId>(OTHER_ID);
    let signed_request = SignedPairingRequest::build(
        pairing_id,
        id::<DeviceId>(OTHER_ID),
        "Joining Mac",
        NativePlatform::Macos,
        &joining_keys,
    )
    .unwrap();
    vault
        .store_pairing_join_request(pairing_id, signed_request.canonical_bytes(), 1_100)
        .unwrap();
    vault
        .request_sync_checkpoint(SyncScope {
            account_id: fixture.artifacts.record.account_id,
            workspace_id: fixture.artifacts.record.workspace_id,
        })
        .unwrap();
    drop(vault);
    let key = keys.key(CREDENTIAL);
    let raw = open_keyed(path.path(), &key);
    support::remove_native_memory_migrations_after_schema_23(&raw);
    raw.execute_batch(
        "DROP TABLE recovery_restores;
         DROP TABLE recovery_enrollments;",
    )
    .unwrap();
    raw.pragma_update(None, "user_version", 21).unwrap();
    drop(raw);

    let vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(vault.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
    assert!(
        vault
            .device_certificate(fixture.artifacts.record.genesis_certificate_id)
            .unwrap()
            .is_some()
    );
    assert!(vault.stored_pairing_join(pairing_id).unwrap().is_some());
    assert!(
        vault
            .sync_checkpoint_schedule(SyncScope {
                account_id: fixture.artifacts.record.account_id,
                workspace_id: fixture.artifacts.record.workspace_id,
            })
            .unwrap()
            .requested
    );
    assert!(vault.recovery_enrollment().unwrap().is_none());

    drop(vault);
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault
        .prepare_recovery_enrollment(&write(&fixture.artifacts, 2_000))
        .unwrap();
    let cells = vault.test_plaintext_cells().unwrap();
    for canary in [
        fixture.material.workspace_root_key().as_slice(),
        fixture.material.active_epoch_key().as_slice(),
    ] {
        assert!(cells.iter().all(|cell| {
            !cell
                .bytes
                .windows(canary.len())
                .any(|window| window == canary)
        }));
    }
}
