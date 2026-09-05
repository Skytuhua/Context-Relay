mod support;

use std::{path::Path, str::FromStr};

use context_relay_core::{
    crypto::DeviceKeys,
    devices::{
        memory_recovery_transport::InMemoryRecoveryEnrollmentProvider,
        recovery_restore_crypto::{RecoveryDeviceClaimArtifacts, decode_recovery_device_claim_v1},
        recovery_restore_transport::RecoveryRestoreTransport,
        recovery_transport::RecoveryEnrollmentTransport,
    },
    sync::SyncScope,
    vault::{
        CommitDisposition, DeviceCertificateState, DeviceDisplayMetadata, LATEST_SCHEMA_VERSION,
        RecoveryRestorePersistenceState, RecoveryRestoreWrite, Vault, VaultError,
    },
};
use context_relay_protocol::{AccountId, Sha256Digest, WorkspaceId};
use rusqlite::Connection;
use sha2::{Digest, Sha256};

use support::{MemoryKeyStore, TempVault};

const CREDENTIAL: &str = "recovery-restore-vault-v1";
const ACCOUNT_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07398f";
const WORKSPACE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07398e";

fn id<T: FromStr>(value: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    value.parse().unwrap()
}

fn decode_hex(value: &str) -> Vec<u8> {
    let value = value.trim();
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

fn claim_artifacts() -> RecoveryDeviceClaimArtifacts {
    let canonical_claim = decode_hex(include_str!("fixtures/recovery-device-claim-v1.hex"));
    RecoveryDeviceClaimArtifacts {
        claim: decode_recovery_device_claim_v1(&canonical_claim).unwrap(),
        canonical_claim_sha256: Sha256Digest(Sha256::digest(&canonical_claim).into()),
        canonical_claim,
    }
}

fn scope() -> SyncScope {
    SyncScope {
        account_id: id::<AccountId>(ACCOUNT_ID),
        workspace_id: id::<WorkspaceId>(WORKSPACE_ID),
    }
}

fn recovered_device_keys() -> DeviceKeys {
    DeviceKeys::from_seeds_for_test([0x66; 32], [0x77; 32])
}

fn provider_and_write(
    prepared_at_ms: u64,
) -> (InMemoryRecoveryEnrollmentProvider, RecoveryRestoreWrite) {
    let provider = InMemoryRecoveryEnrollmentProvider::new();
    provider
        .transport(scope())
        .register(&enrollment_bytes(), 1_000)
        .unwrap();
    let snapshot = provider
        .restore_transport(scope())
        .root_snapshot()
        .unwrap()
        .unwrap();
    let write = RecoveryRestoreWrite::new(snapshot, claim_artifacts(), prepared_at_ms).unwrap();
    (provider, write)
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
fn prepared_restore_is_exact_without_installing_either_certificate() {
    let provider = InMemoryRecoveryEnrollmentProvider::new();
    provider
        .transport(scope())
        .register(&enrollment_bytes(), 1_000)
        .unwrap();
    let transport = provider.restore_transport(scope());
    let snapshot = transport.root_snapshot().unwrap().unwrap();
    let artifacts = claim_artifacts();
    let write = RecoveryRestoreWrite::new(snapshot, artifacts, 3_000).unwrap();

    let path = TempVault::new("recovery-restore-prepared");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(
        vault.prepare_recovery_restore(&write).unwrap(),
        CommitDisposition::Inserted
    );
    assert_eq!(
        vault.prepare_recovery_restore(&write).unwrap(),
        CommitDisposition::ExactReplay
    );
    let (_, mut changed_write) = provider_and_write(3_000);
    changed_write.prepared_at_ms += 1;
    assert!(matches!(
        vault.prepare_recovery_restore(&changed_write),
        Err(VaultError::OperationConflict)
    ));
    let stored = vault.recovery_restore().unwrap().unwrap();
    assert_eq!(stored.state, RecoveryRestorePersistenceState::Prepared);
    assert!(
        vault
            .device_certificate(stored.record.genesis_certificate_id)
            .unwrap()
            .is_none()
    );
    assert!(
        vault
            .device_certificate(stored.claim.certificate_id)
            .unwrap()
            .is_none()
    );

    let wrong_keys = DeviceKeys::from_seeds_for_test([0x11; 32], [0x22; 32]);
    assert!(vault.recovered_workspace_material(&wrong_keys).is_err());
}

#[test]
fn prepared_replay_and_conflict_transition_reject_an_installed_certificate() {
    let (_, write) = provider_and_write(3_000);
    let path = TempVault::new("recovery-restore-prepared-certificate-conflict");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault.prepare_recovery_restore(&write).unwrap();
    let stored = vault.recovery_restore().unwrap().unwrap();
    vault
        .store_device_certificate(
            stored.record.genesis_certificate_id,
            &stored.record.genesis_certificate,
            DeviceCertificateState::Active,
            &DeviceDisplayMetadata {
                device_name: stored.record.device_name,
                platform: stored.record.device_platform,
            },
            3_100,
        )
        .unwrap();

    assert!(matches!(
        vault.prepare_recovery_restore(&write),
        Err(VaultError::OperationConflict)
    ));
    assert!(matches!(
        vault.mark_recovery_restore_conflict(3_200),
        Err(VaultError::OperationConflict)
    ));
}

#[test]
fn exact_provider_proof_activates_both_certificates_and_reopens_material() {
    let (provider, write) = provider_and_write(3_000);
    let transport = provider.restore_transport(scope());
    let receipt = transport
        .submit_restore(&write.canonical_claim, 3_500)
        .unwrap();
    let projection = transport
        .restore_claim(receipt.restore_id)
        .unwrap()
        .unwrap();
    let path = TempVault::new("recovery-restore-active");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault.prepare_recovery_restore(&write).unwrap();
    let device_keys = recovered_device_keys();
    assert_eq!(
        vault
            .activate_recovery_restore(&receipt, &projection, &device_keys, 4_000)
            .unwrap(),
        CommitDisposition::Inserted
    );
    assert_eq!(
        vault
            .activate_recovery_restore(&receipt, &projection, &device_keys, 4_000)
            .unwrap(),
        CommitDisposition::ExactReplay
    );
    let stored = vault.recovery_restore().unwrap().unwrap();
    assert_eq!(stored.state, RecoveryRestorePersistenceState::Active);
    assert_eq!(stored.accepted_generation, Some(1));
    assert_eq!(stored.provider_accepted_at_ms, Some(3_500));
    assert_eq!(stored.completed_at_ms, Some(4_000));
    for certificate_id in [
        stored.record.genesis_certificate_id,
        stored.claim.certificate_id,
    ] {
        assert_eq!(
            vault
                .device_certificate(certificate_id)
                .unwrap()
                .unwrap()
                .state,
            DeviceCertificateState::Active
        );
    }
    drop(vault);

    let reopened = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let material = reopened.recovered_workspace_material(&device_keys).unwrap();
    assert_eq!(material.scope(), scope());
    assert_eq!(material.control_epoch(), 1);
    assert_eq!(material.key_epoch(), 1);
    assert_eq!(material.workspace_root_key(), &[0x44; 32]);
    assert_eq!(material.active_epoch_key(), &[0x55; 32]);
    assert_eq!(
        reopened
            .trusted_workspace_material(&device_keys)
            .unwrap()
            .scope(),
        scope()
    );
    let cells = reopened.test_plaintext_cells().unwrap();
    for canary in [[0x44_u8; 32], [0x55_u8; 32], [0x66_u8; 32], [0x77_u8; 32]] {
        assert!(cells.iter().all(|cell| {
            !cell
                .bytes
                .windows(canary.len())
                .any(|window| window == canary)
        }));
    }
}

#[test]
fn active_restore_rejects_a_revoked_certificate_graph_after_reopen() {
    let (provider, write) = provider_and_write(3_000);
    let transport = provider.restore_transport(scope());
    let receipt = transport
        .submit_restore(&write.canonical_claim, 3_500)
        .unwrap();
    let projection = transport
        .restore_claim(receipt.restore_id)
        .unwrap()
        .unwrap();
    let path = TempVault::new("recovery-restore-active-certificate-tamper");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault.prepare_recovery_restore(&write).unwrap();
    vault
        .activate_recovery_restore(&receipt, &projection, &recovered_device_keys(), 4_000)
        .unwrap();
    let recovered_certificate_id = vault
        .recovery_restore()
        .unwrap()
        .unwrap()
        .claim
        .certificate_id;
    drop(vault);

    let raw = open_keyed(path.path(), &keys.key(CREDENTIAL));
    raw.execute(
        "UPDATE device_certificates SET state = 'revoked' WHERE certificate_id = ?1",
        [recovered_certificate_id.to_string()],
    )
    .unwrap();
    drop(raw);

    let reopened = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert!(matches!(
        reopened.recovery_restore(),
        Err(VaultError::Validation(_))
    ));
    assert!(matches!(
        reopened.recovered_workspace_material(&recovered_device_keys()),
        Err(VaultError::Validation(_))
    ));
}

#[test]
fn activation_trigger_abort_rolls_back_both_certificates_and_resumes_after_reopen() {
    let (provider, write) = provider_and_write(3_000);
    let transport = provider.restore_transport(scope());
    let receipt = transport
        .submit_restore(&write.canonical_claim, 3_500)
        .unwrap();
    let projection = transport
        .restore_claim(receipt.restore_id)
        .unwrap()
        .unwrap();
    let path = TempVault::new("recovery-restore-atomic");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault.prepare_recovery_restore(&write).unwrap();
    drop(vault);

    let key = keys.key(CREDENTIAL);
    let raw = open_keyed(path.path(), &key);
    raw.execute_batch(
        "CREATE TRIGGER abort_restore_activation
         BEFORE UPDATE OF state ON recovery_restores
         WHEN NEW.state = 'active'
         BEGIN
           SELECT RAISE(ABORT, 'injected restore activation failure');
         END;",
    )
    .unwrap();
    drop(raw);

    let device_keys = recovered_device_keys();
    let mut reopened = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert!(
        reopened
            .activate_recovery_restore(&receipt, &projection, &device_keys, 4_000)
            .is_err()
    );
    drop(reopened);

    let raw = open_keyed(path.path(), &key);
    raw.execute_batch("DROP TRIGGER abort_restore_activation")
        .unwrap();
    drop(raw);
    let mut reopened = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let stored = reopened.recovery_restore().unwrap().unwrap();
    assert_eq!(stored.state, RecoveryRestorePersistenceState::Prepared);
    assert!(
        reopened
            .device_certificate(stored.record.genesis_certificate_id)
            .unwrap()
            .is_none()
    );
    assert!(
        reopened
            .device_certificate(stored.claim.certificate_id)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        reopened
            .activate_recovery_restore(&receipt, &projection, &device_keys, 4_000)
            .unwrap(),
        CommitDisposition::Inserted
    );
}

#[test]
fn wrong_keys_forged_proof_and_terminal_conflict_install_no_trust() {
    let (provider, write) = provider_and_write(3_000);
    let transport = provider.restore_transport(scope());
    let receipt = transport
        .submit_restore(&write.canonical_claim, 3_500)
        .unwrap();
    let projection = transport
        .restore_claim(receipt.restore_id)
        .unwrap()
        .unwrap();
    let path = TempVault::new("recovery-restore-conflict");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault.prepare_recovery_restore(&write).unwrap();

    let wrong_keys = DeviceKeys::from_seeds_for_test([0x12; 32], [0x34; 32]);
    assert!(
        vault
            .activate_recovery_restore(&receipt, &projection, &wrong_keys, 4_000)
            .is_err()
    );
    let mut forged_receipt = receipt.clone();
    forged_receipt.canonical_claim_sha256.0[0] ^= 1;
    assert!(
        vault
            .activate_recovery_restore(
                &forged_receipt,
                &projection,
                &recovered_device_keys(),
                4_000,
            )
            .is_err()
    );
    let mut forged_projection = projection.clone();
    forged_projection.canonical_claim[0] ^= 1;
    assert!(
        vault
            .activate_recovery_restore(
                &receipt,
                &forged_projection,
                &recovered_device_keys(),
                4_000,
            )
            .is_err()
    );
    assert_eq!(
        vault.mark_recovery_restore_conflict(4_100).unwrap(),
        CommitDisposition::Inserted
    );
    assert_eq!(
        vault.mark_recovery_restore_conflict(4_100).unwrap(),
        CommitDisposition::ExactReplay
    );
    assert!(matches!(
        vault.activate_recovery_restore(&receipt, &projection, &recovered_device_keys(), 4_200,),
        Err(VaultError::OperationConflict)
    ));
    let stored = vault.recovery_restore().unwrap().unwrap();
    assert_eq!(stored.state, RecoveryRestorePersistenceState::Conflict);
    for certificate_id in [
        stored.record.genesis_certificate_id,
        stored.claim.certificate_id,
    ] {
        assert!(vault.device_certificate(certificate_id).unwrap().is_none());
    }
}

#[test]
fn schema_22_real_rows_migrate_forward_without_rewrite() {
    let path = TempVault::new("recovery-restore-schema-22");
    let keys = MemoryKeyStore::default();
    let key = [0x91; 32];
    keys.insert(CREDENTIAL, key);
    drop(Vault::open(path.path(), CREDENTIAL, &keys).unwrap());

    let raw = open_keyed(path.path(), &key);
    support::remove_native_memory_migrations_after_schema_23(&raw);
    raw.execute(
        "INSERT INTO records(id, kind, scope_kind, project_id, archived, payload_json)
         VALUES ('legacy-record', 'memory', 'global', NULL, 0, x'010203')",
        [],
    )
    .unwrap();
    raw.execute_batch("DROP TABLE recovery_restores").unwrap();
    raw.pragma_update(None, "user_version", 22).unwrap();
    drop(raw);

    let vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(vault.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
    let raw = open_keyed(path.path(), &key);
    assert_eq!(
        raw.query_row(
            "SELECT payload_json FROM records WHERE id = 'legacy-record'",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .unwrap(),
        vec![1, 2, 3]
    );
    assert_eq!(
        raw.query_row("SELECT count(*) FROM recovery_restores", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        0
    );
}

fn assert_prepared_tamper_rejected(name: &str, mutate: impl FnOnce(&Connection)) {
    let path = TempVault::new(name);
    let keys = MemoryKeyStore::default();
    let (_, write) = provider_and_write(3_000);
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault.prepare_recovery_restore(&write).unwrap();
    drop(vault);
    let raw = open_keyed(path.path(), &keys.key(CREDENTIAL));
    raw.execute_batch(
        "PRAGMA foreign_keys = OFF;
         PRAGMA ignore_check_constraints = ON;",
    )
    .unwrap();
    mutate(&raw);
    drop(raw);
    let vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert!(matches!(
        vault.recovery_restore(),
        Err(VaultError::Validation(_))
    ));
}

#[test]
fn every_prepared_row_binding_hash_state_and_timestamp_tamper_fails_closed() {
    let other = "018f22e2-79b0-7cc8-98c4-dc0c0c07397f".to_owned();
    for column in [
        "restore_id",
        "enrollment_id",
        "recovery_root_id",
        "account_id",
        "workspace_id",
        "genesis_device_id",
        "genesis_certificate_id",
        "recovered_device_id",
        "recovered_certificate_id",
    ] {
        let other = other.clone();
        assert_prepared_tamper_rejected(column, move |raw| {
            raw.execute(
                &format!("UPDATE recovery_restores SET {column} = ?1"),
                [&other],
            )
            .unwrap();
        });
    }
    for column in [
        "recovery_signing_public_key",
        "recovery_wrapping_public_key",
        "genesis_signing_public_key",
        "genesis_wrapping_public_key",
        "recovered_signing_public_key",
        "recovered_wrapping_public_key",
        "canonical_record_sha256",
        "canonical_claim_sha256",
    ] {
        assert_prepared_tamper_rejected(column, move |raw| {
            raw.execute(
                &format!("UPDATE recovery_restores SET {column} = ?1"),
                [vec![0x99_u8; 32]],
            )
            .unwrap();
        });
    }
    for (name, sql) in [
        (
            "activated-genesis-id",
            "UPDATE recovery_restores SET activated_genesis_certificate_id = '018f22e2-79b0-7cc8-98c4-dc0c0c07397f'",
        ),
        (
            "activated-recovered-id",
            "UPDATE recovery_restores SET activated_recovered_certificate_id = '018f22e2-79b0-7cc8-98c4-dc0c0c07397f'",
        ),
        (
            "genesis-name",
            "UPDATE recovery_restores SET genesis_device_name = 'Other Genesis'",
        ),
        (
            "genesis-platform",
            "UPDATE recovery_restores SET genesis_platform = 'windows'",
        ),
        (
            "recovered-name",
            "UPDATE recovery_restores SET recovered_device_name = 'Other Recovered'",
        ),
        (
            "recovered-platform",
            "UPDATE recovery_restores SET recovered_platform = 'windows'",
        ),
        (
            "control-epoch",
            "UPDATE recovery_restores SET control_epoch = 2",
        ),
        ("key-epoch", "UPDATE recovery_restores SET key_epoch = 2"),
        (
            "expected-generation",
            "UPDATE recovery_restores SET expected_generation = 1",
        ),
        (
            "accepted-generation",
            "UPDATE recovery_restores SET accepted_generation = 1",
        ),
        (
            "record-bytes",
            "UPDATE recovery_restores SET canonical_record = zeroblob(length(canonical_record))",
        ),
        (
            "claim-bytes",
            "UPDATE recovery_restores SET canonical_claim = zeroblob(length(canonical_claim))",
        ),
        ("state", "UPDATE recovery_restores SET state = 'active'"),
        (
            "prepared-time",
            "UPDATE recovery_restores SET prepared_at_ms = -1",
        ),
        (
            "provider-time",
            "UPDATE recovery_restores SET provider_accepted_at_ms = 9",
        ),
        (
            "completed-time",
            "UPDATE recovery_restores SET completed_at_ms = 9",
        ),
        (
            "conflict-time",
            "UPDATE recovery_restores SET conflict_at_ms = 9",
        ),
    ] {
        assert_prepared_tamper_rejected(name, move |raw| {
            raw.execute_batch(sql).unwrap();
        });
    }
}

fn assert_non_pristine_rejected(name: &str, sql: &str) {
    let path = TempVault::new(name);
    let keys = MemoryKeyStore::default();
    let (_, write) = provider_and_write(3_000);
    drop(Vault::open(path.path(), CREDENTIAL, &keys).unwrap());
    let raw = open_keyed(path.path(), &keys.key(CREDENTIAL));
    raw.execute_batch(sql).unwrap();
    drop(raw);
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert!(matches!(
        vault.prepare_recovery_restore(&write),
        Err(VaultError::OperationConflict)
    ));
    assert!(vault.recovery_restore().unwrap().is_none());
}

#[test]
fn user_sync_pairing_and_certificate_state_each_make_the_target_non_pristine() {
    assert_non_pristine_rejected(
        "restore-nonpristine-user",
        "INSERT INTO records(id, kind, scope_kind, project_id, archived, payload_json)
         VALUES ('user-row', 'memory', 'global', NULL, 0, x'01')",
    );
    assert_non_pristine_rejected(
        "restore-nonpristine-sync",
        "INSERT INTO checkpoints(state_hash, payload_json) VALUES ('state', x'01')",
    );
    assert_non_pristine_rejected(
        "restore-nonpristine-pairing",
        "INSERT INTO pairing_approval_transcripts(
             pairing_id, role, state, stored_at_ms
         ) VALUES (
             '018f22e2-79b0-7cc8-98c4-dc0c0c073970',
             'joiner', 'legacy_unconfirmed', 1
         )",
    );
    let record =
        context_relay_core::devices::recovery_crypto::decode_recovery_enrollment_record_v1(
            &enrollment_bytes(),
        )
        .unwrap();
    let path = TempVault::new("restore-nonpristine-certificate");
    let keys = MemoryKeyStore::default();
    let (_, write) = provider_and_write(3_000);
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault
        .store_device_certificate(
            record.genesis_certificate_id,
            &record.genesis_certificate,
            DeviceCertificateState::Active,
            &context_relay_core::vault::DeviceDisplayMetadata {
                device_name: record.device_name,
                platform: record.device_platform,
            },
            1,
        )
        .unwrap();
    assert!(matches!(
        vault.prepare_recovery_restore(&write),
        Err(VaultError::OperationConflict)
    ));
    assert!(vault.recovery_restore().unwrap().is_none());
}
