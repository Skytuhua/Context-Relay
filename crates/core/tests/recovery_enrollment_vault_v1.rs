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

#[test]
fn backfill_queues_unchanged_offline_records_atomically_and_resumes_after_reopen() {
    use context_relay_core::service::OfflineWorkspace;
    use context_relay_protocol::{MemoryCreateParams, MemoryKind, ScopeRef};
    let fixture = fixture();
    let path = TempVault::new("sync-backfill");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let create = MemoryCreateParams {
        operation_id: id(support::ID_1),
        scope: ScopeRef::Global,
        kind: MemoryKind::Fact,
        title: "Offline note".into(),
        body_markdown: "Keep the original".into(),
        tags: vec![],
    };
    let original = OfflineWorkspace::new(&mut vault, id(DEVICE_ID))
        .create_memory(create.clone())
        .unwrap();
    let mut other = create.clone();
    other.operation_id = id(support::ID_2);
    OfflineWorkspace::new(&mut vault, id(DEVICE_ID))
        .create_memory(other)
        .unwrap();
    assert!(
        vault
            .backfill_sync_records(id(DEVICE_ID), &fixture.device_keys, 2)
            .is_err()
    );
    vault
        .prepare_recovery_enrollment(&write(&fixture.artifacts, 1000))
        .unwrap();
    vault
        .activate_recovery_enrollment(
            &receipt(&fixture.artifacts, 2000),
            &fixture.device_keys,
            3000,
        )
        .unwrap();
    let raw = open_keyed(path.path(), &keys.key(CREDENTIAL));
    raw.execute_batch("CREATE TRIGGER fail_backfill BEFORE INSERT ON outbox WHEN (SELECT count(*) FROM outbox) = 1 BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert!(
        vault
            .backfill_sync_records(id(DEVICE_ID), &fixture.device_keys, 2)
            .is_err()
    );
    assert!(vault.due_outbox(u64::MAX, 10).unwrap().is_empty());
    assert_eq!(
        raw.query_row("SELECT count(*) FROM sync_record_owners", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(vault.memory(&original.id).unwrap(), Some(original.clone()));
    raw.execute_batch("DROP TRIGGER fail_backfill;").unwrap();
    drop(raw);
    assert_eq!(
        vault
            .backfill_sync_records(id(DEVICE_ID), &fixture.device_keys, 1)
            .unwrap(),
        1
    );
    let first = vault.due_outbox(u64::MAX, 10).unwrap()[0]
        .canonical_bytes
        .clone();
    drop(vault);
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(
        vault
            .backfill_sync_records(id(DEVICE_ID), &fixture.device_keys, 1)
            .unwrap(),
        1
    );
    assert_eq!(
        vault
            .backfill_sync_records(id(DEVICE_ID), &fixture.device_keys, 1)
            .unwrap(),
        0
    );
    let queued = vault.due_outbox(u64::MAX, 10).unwrap();
    assert_eq!(queued.len(), 2);
    assert!(queued.iter().any(|row| row.canonical_bytes == first));
    assert_eq!(
        OfflineWorkspace::new(&mut vault, id(DEVICE_ID))
            .create_memory(create)
            .unwrap(),
        original
    );
    let project = context_relay_protocol::ProjectIdentity {
        project_id: id(support::ID_7),
        github_repository_id: None,
        git_remote_fingerprint: None,
        monorepo_subdirectory: None,
        name: "Offline project".into(),
    };
    vault.put_project(&project).unwrap();
    vault.put_task(&support::task()).unwrap();
    vault
        .put_instruction(
            &support::instruction(
                support::ID_4,
                ScopeRef::Global,
                "Instruction",
                "Keep instruction",
            ),
            &support::operation(
                support::ID_4,
                support::ID_4,
                context_relay_protocol::RecordKind::Instruction,
            ),
            &support::basis(0),
        )
        .unwrap();
    let mut candidate = support::candidate();
    candidate.id = id(support::ID_9);
    candidate.proposed_memory.id = id(support::ID_5);
    vault.put_candidate(&candidate).unwrap();
    let secret = context_relay_protocol::SecretRef {
        id: id(support::ID_6),
        name: "Reference only".into(),
        provider: "local-keychain".into(),
        required_on_device: true,
    };
    let component = context_relay_protocol::ComponentRecord {
        id: id(support::ID_8),
        scope: ScopeRef::Global,
        kind: context_relay_protocol::ComponentKind::Rule,
        name: "Rule".into(),
        body_markdown: "Keep rule".into(),
        metadata: vec![],
        provenance: original.provenance.clone(),
        archived: false,
    };
    let raw = open_keyed(path.path(), &keys.key(CREDENTIAL));
    raw.execute(
        "INSERT INTO secret_refs(id,payload_json) VALUES (?1,?2)",
        rusqlite::params![support::ID_6, serde_json::to_vec(&secret).unwrap()],
    )
    .unwrap();
    raw.execute(
        "INSERT INTO components(id,payload_json) VALUES (?1,?2)",
        rusqlite::params![support::ID_8, serde_json::to_vec(&component).unwrap()],
    )
    .unwrap();
    drop(raw);
    assert_eq!(
        vault
            .backfill_sync_records(id(DEVICE_ID), &fixture.device_keys, 32)
            .unwrap(),
        6
    );
    let queued = vault.due_outbox(u64::MAX, 32).unwrap();
    assert_eq!(queued.len(), 9); // Includes the instruction's pre-existing legacy operation.
    let kinds = queued
        .iter()
        .filter(|row| row.operation_id != id(support::ID_4))
        .map(|row| {
            format!(
                "{:?}",
                context_relay_protocol::decode_sync_operation_v1(&row.canonical_bytes)
                    .unwrap()
                    .record_kind
            )
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(kinds.len(), 7);
    let mut legacy = support::candidate();
    legacy.id = id(support::ID_5);
    legacy.proposed_memory.id = id(support::ID_5);
    vault.put_candidate(&legacy).unwrap();
    assert!(
        vault
            .backfill_sync_records(id(DEVICE_ID), &fixture.device_keys, 32)
            .is_err()
    );
    assert_eq!(vault.due_outbox(u64::MAX, 32).unwrap().len(), 9);
    let raw = open_keyed(path.path(), &keys.key(CREDENTIAL));
    raw.execute("DELETE FROM candidates WHERE id = ?1", [support::ID_5])
        .unwrap();
    drop(raw);
    legacy.id = id(support::ID_1);
    vault.put_candidate(&legacy).unwrap();
    assert!(
        vault
            .backfill_sync_records(id(DEVICE_ID), &fixture.device_keys, 32)
            .is_err()
    );
    assert_eq!(vault.due_outbox(u64::MAX, 32).unwrap().len(), 9);
}

#[test]
fn sync_material_uses_verified_enrollment_and_rejects_untrusted_devices() {
    use context_relay_core::{
        sync::{SyncError, TrustedSyncMaterial},
        vault::DeviceDisplayMetadata,
    };
    let fixture = fixture();
    let path = TempVault::new("verified-sync-material");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert!(vault.trusted_sync_material(&fixture.device_keys).is_err());
    vault
        .prepare_recovery_enrollment(&write(&fixture.artifacts, 1000))
        .unwrap();
    assert!(vault.trusted_sync_material(&fixture.device_keys).is_err());
    vault
        .activate_recovery_enrollment(
            &receipt(&fixture.artifacts, 2000),
            &fixture.device_keys,
            3000,
        )
        .unwrap();
    let child_keys = DeviceKeys::generate().unwrap();
    let fields = CertificateFieldsV1 {
        account_id: id(ACCOUNT_ID),
        workspace_id: id(WORKSPACE_ID),
        control_epoch: 1,
        request_nonce: PairingRequestNonce([0x91; 32]),
        device_id: id(OTHER_ID),
        signing_public_key: child_keys.signing_public_key(),
        wrapping_public_key: child_keys.wrapping_public_key(),
    };
    let child =
        DeviceCertificateV1::issue_by_device(fields.clone(), id(DEVICE_ID), &fixture.device_keys)
            .unwrap();
    vault
        .store_device_certificate(
            id(OTHER_ID),
            &child,
            DeviceCertificateState::Active,
            &DeviceDisplayMetadata {
                device_name: "Child".into(),
                platform: NativePlatform::Windows,
            },
            4000,
        )
        .unwrap();
    let untrusted_recovery =
        RecoveryKeys::derive(&RecoveryPhrase::from_entropy_for_test([0x92; 32]).unwrap()).unwrap();
    let mut untrusted_fields = fields;
    untrusted_fields.device_id = id(ENROLLMENT_ID);
    let untrusted =
        DeviceCertificateV1::issue_genesis(untrusted_fields, &untrusted_recovery).unwrap();
    vault
        .store_device_certificate(
            id(RECOVERY_ROOT_ID),
            &untrusted,
            DeviceCertificateState::Active,
            &DeviceDisplayMetadata {
                device_name: "Untrusted root".into(),
                platform: NativePlatform::Windows,
            },
            4001,
        )
        .unwrap();
    let trusted = vault.trusted_sync_material(&fixture.device_keys).unwrap();
    assert_eq!(
        trusted.trusted_device(id(ACCOUNT_ID), id(WORKSPACE_ID), id(ENROLLMENT_ID)),
        Err(SyncError::InvalidIdentity)
    );
    assert_eq!(
        trusted
            .trusted_device(id(ACCOUNT_ID), id(WORKSPACE_ID), id(OTHER_ID))
            .unwrap()
            .certificate,
        child
    );
    assert!(trusted.content_key(id(WORKSPACE_ID), 1).is_ok());
    assert!(trusted.content_key(id(WORKSPACE_ID), 2).is_err());
    assert!(trusted.content_key(id(OTHER_ID), 1).is_err());
    assert!(
        trusted
            .trusted_device(id(OTHER_ID), id(WORKSPACE_ID), id(DEVICE_ID))
            .is_err()
    );
    assert!(vault.trusted_sync_material(&child_keys).is_err());
    use context_relay_core::sync::{
        AdmissionDecision, OperationBuildRequest, OperationBuilder, SyncIdentity, admit_operation,
    };
    let mutation = context_relay_protocol::RecordMutationV1::UpsertMemory(support::memory(
        support::ID_1,
        context_relay_protocol::ScopeRef::Global,
        "Remote note",
        "Verified child",
    ));
    let operation = OperationBuilder::new(SyncIdentity {
        account_id: id(ACCOUNT_ID),
        workspace_id: id(WORKSPACE_ID),
        device_id: id(OTHER_ID),
        control_epoch: 1,
        key_epoch: 1,
        device_keys: &child_keys,
        content_key: trusted.content_key(id(WORKSPACE_ID), 1).unwrap(),
    })
    .build(OperationBuildRequest {
        operation_id: id(support::ID_2),
        project_id: None,
        mutation: &mutation,
        causal_frontier: vec![],
        previous: None,
        blob_refs: vec![],
        created_hlc: context_relay_protocol::HybridLogicalClock::new(5000, 0, id(OTHER_ID)),
    })
    .unwrap();
    assert!(matches!(
        admit_operation(&vault, &operation.canonical_bytes, &trusted).unwrap(),
        AdmissionDecision::Admitted(_)
    ));
    drop(trusted);
    drop(vault);
    let raw = open_keyed(path.path(), &keys.key(CREDENTIAL));
    raw.execute(
        "UPDATE device_certificates SET state = 'revoked' WHERE certificate_id = ?1",
        [OTHER_ID],
    )
    .unwrap();
    drop(raw);
    let vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert!(
        admit_operation(
            &vault,
            &operation.canonical_bytes,
            &vault.trusted_sync_material(&fixture.device_keys).unwrap()
        )
        .is_err()
    );
    assert_eq!(
        vault
            .trusted_sync_material(&fixture.device_keys)
            .unwrap()
            .trusted_device(id(ACCOUNT_ID), id(WORKSPACE_ID), id(OTHER_ID)),
        Err(SyncError::InvalidIdentity)
    );
}

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
fn hosted_intent_survives_restart_and_cannot_change_identity_or_challenge() {
    use context_relay_core::{
        devices::supabase_enrollment::HostedEnrollmentReservation, vault::HostedEnrollmentIntent,
    };
    use context_relay_protocol::{DecimalTimestamp, Sha256Digest};
    let path = TempVault::new("hosted-intent");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let mut intent = HostedEnrollmentIntent {
        project_url: "https://example.supabase.co/".into(),
        user_id: id("550e8400-e29b-41d4-a716-446655440000"),
        session_id: id("550e8400-e29b-41d4-a716-446655440001"),
        operation_id: id(ENROLLMENT_ID),
        reservation: None,
    };
    vault.store_hosted_enrollment_intent(&intent).unwrap();
    let mut foreign = intent.clone();
    foreign.session_id = id("550e8400-e29b-41d4-a716-446655440009");
    assert!(
        vault
            .discard_unprepared_hosted_enrollment_intent(&foreign)
            .is_err()
    );
    vault
        .discard_unprepared_hosted_enrollment_intent(&intent)
        .unwrap();
    assert!(vault.hosted_enrollment_intent().unwrap().is_none());
    vault.store_hosted_enrollment_intent(&intent).unwrap();
    let fixture = fixture();
    assert!(
        vault
            .prepare_recovery_enrollment(&write(&fixture.artifacts, 2_000))
            .is_err()
    );
    drop(vault);
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(
        vault.hosted_enrollment_intent().unwrap(),
        Some(intent.clone())
    );
    intent.reservation = Some(HostedEnrollmentReservation {
        reservation_id: intent.operation_id,
        account_id: id(ACCOUNT_ID),
        workspace_id: id(WORKSPACE_ID),
        nonce: Sha256Digest([42; 32]),
        expires_at: DecimalTimestamp(600_000),
    });
    vault.store_hosted_enrollment_intent(&intent).unwrap();
    vault.store_hosted_enrollment_intent(&intent).unwrap();
    for change in [0, 1, 2] {
        let mut changed = intent.clone();
        match change {
            0 => changed.session_id = id("550e8400-e29b-41d4-a716-446655440002"),
            1 => changed.reservation.as_mut().unwrap().nonce = Sha256Digest([43; 32]),
            _ => changed.reservation = None,
        }
        assert!(matches!(
            vault.store_hosted_enrollment_intent(&changed),
            Err(VaultError::OperationConflict)
        ));
    }
    vault
        .prepare_recovery_enrollment(&write(&fixture.artifacts, 2_000))
        .unwrap();
    drop(vault);
    let vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(
        vault.hosted_enrollment_intent().unwrap(),
        Some(intent.clone())
    );
    let mut vault = vault;
    assert!(matches!(
        vault.discard_unprepared_hosted_enrollment_intent(&intent),
        Err(VaultError::OperationConflict)
    ));
    let canonical = vault
        .recovery_enrollment()
        .unwrap()
        .unwrap()
        .canonical_record;
    let mut renewed = intent.reservation.clone().unwrap();
    renewed.nonce = Sha256Digest([44; 32]);
    renewed.expires_at = DecimalTimestamp(1_200_000);
    let mut wrong_scope = renewed.clone();
    wrong_scope.workspace_id = id(OTHER_ID);
    assert!(
        vault
            .renew_hosted_enrollment_intent(&intent, wrong_scope)
            .is_err()
    );
    let replacement = vault
        .renew_hosted_enrollment_intent(&intent, renewed.clone())
        .unwrap();
    assert!(
        vault
            .renew_hosted_enrollment_intent(&intent, renewed.clone())
            .is_err()
    );
    assert_eq!(
        vault
            .renew_hosted_enrollment_intent(&replacement, renewed)
            .unwrap(),
        replacement
    );
    assert_eq!(
        vault
            .recovery_enrollment()
            .unwrap()
            .unwrap()
            .canonical_record,
        canonical
    );

    let legacy_path = TempVault::new("hosted-intent-existing-enrollment");
    let mut legacy = Vault::open(legacy_path.path(), CREDENTIAL, &keys).unwrap();
    legacy
        .prepare_recovery_enrollment(&write(&fixture.artifacts, 2_000))
        .unwrap();
    assert!(matches!(
        legacy.store_hosted_enrollment_intent(&intent),
        Err(VaultError::OperationConflict)
    ));
    assert_eq!(legacy.hosted_enrollment_intent().unwrap(), None);
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

    // Recreate the schema-28 table contract with an active row, then exercise
    // the clock-domain migration without losing its certificate/material links.
    let raw = open_keyed(path.path(), &keys.key(CREDENTIAL));
    raw.execute_batch("ALTER TABLE recovery_enrollments RENAME TO enrollment_fixture;")
        .unwrap();
    raw.execute_batch(include_str!("../migrations/0022_recovery_enrollment.sql"))
        .unwrap();
    raw.execute_batch("INSERT INTO recovery_enrollments SELECT * FROM enrollment_fixture; DROP TABLE enrollment_fixture;").unwrap();
    raw.execute_batch("DROP TABLE account_lifecycle_intents; DROP TABLE pairing_request_reviews; DROP TABLE hosted_pairing_intents; DROP TABLE hosted_restore_intent;")
        .unwrap();
    raw.pragma_update(None, "user_version", 28).unwrap();
    drop(raw);
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
