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
    vault::{CommitDisposition, RecoveryEnrollmentWrite, Vault},
};
use context_relay_protocol::{
    AccountId, DeviceCertificateId, DeviceId, NativePlatform, PairingRequestNonce,
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

fn id<T: FromStr>(text: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    text.parse().unwrap()
}
#[test]
fn accepted_genesis_is_durable_and_budgeted() {
    let f = fixture();
    let path = TempVault::new("membership-genesis");
    let keys = MemoryKeyStore::default();
    let mut v = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    v.prepare_recovery_enrollment(&write(&f.artifacts, 1000))
        .unwrap();
    v.activate_recovery_enrollment(&receipt(&f.artifacts, 2000), &f.device_keys, 3000)
        .unwrap();
    let budget = context_relay_core::devices::membership_crypto::MembershipHistoryBudget {
        max_events: 10,
        max_bytes: 1_000_000,
    };
    let h = v.accepted_membership_history(budget).unwrap().unwrap();
    assert_eq!(h.state().active_devices.len(), 1);
    let endpoint = h.endpoint();
    drop(v);
    let v = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(
        v.accepted_membership_history(budget)
            .unwrap()
            .unwrap()
            .endpoint(),
        endpoint
    );
    assert!(
        v.accepted_membership_history(
            context_relay_core::devices::membership_crypto::MembershipHistoryBudget {
                max_events: 0,
                max_bytes: 1
            }
        )
        .is_err()
    );
}
use context_relay_core::devices::{
    crypto::control_v2::*, membership_crypto::*, revocation_crypto::*,
};
use context_relay_protocol::Sha256Digest;
const BUDGET: MembershipHistoryBudget = MembershipHistoryBudget {
    max_events: 20,
    max_bytes: 1_000_000,
};
fn open_raw(path: &Path, key: &[u8; 32]) -> Connection {
    let c = Connection::open(path).unwrap();
    unsafe {
        assert_eq!(
            rusqlite::ffi::sqlite3_key(c.handle(), key.as_ptr().cast(), 32),
            0
        );
    }
    c
}
#[test]
fn complete_add_revoke_history_cas_restart_corruption_and_staged_admission() {
    let f = fixture();
    let path = TempVault::new("membership-mixed");
    let ks = MemoryKeyStore::default();
    let mut v = Vault::open(path.path(), CREDENTIAL, &ks).unwrap();
    v.prepare_recovery_enrollment(&write(&f.artifacts, 1000))
        .unwrap();
    v.activate_recovery_enrollment(&receipt(&f.artifacts, 2000), &f.device_keys, 3000)
        .unwrap();
    let root = v.accepted_membership_history(BUDGET).unwrap().unwrap();
    let g = root.endpoint();
    let stale = v.trusted_sync_material(&f.device_keys).unwrap();
    let mutation = context_relay_protocol::RecordMutationV1::UpsertMemory(support::memory(
        support::ID_1,
        context_relay_protocol::ScopeRef::Global,
        "membership stale",
        "body",
    ));
    let stale_operation = context_relay_core::sync::OperationBuilder::new(
        stale.local_identity(id(DEVICE_ID), &f.device_keys).unwrap(),
    )
    .build(context_relay_core::sync::OperationBuildRequest {
        operation_id: id("018f22e2-79b0-7cc8-98c4-dc0c0c073991"),
        project_id: None,
        mutation: &mutation,
        causal_frontier: vec![],
        previous: None,
        blob_refs: vec![],
        created_hlc: context_relay_protocol::HybridLogicalClock::new(4000, 0, id(DEVICE_ID)),
    })
    .unwrap();
    let admitted = match context_relay_core::sync::admit_operation(
        &v,
        &stale_operation.canonical_bytes,
        &stale,
    )
    .unwrap()
    {
        context_relay_core::sync::AdmissionDecision::Admitted(a) => a,
        _ => panic!("expected admission"),
    };
    v.commit_outgoing_operation_at(&mutation, &stale_operation, Some(&support::basis(0)), 4000)
        .unwrap();
    let b = DeviceKeys::generate().unwrap();
    let request =
        SignedPairingRequest::build(id(OTHER_ID), id(OTHER_ID), "B", NativePlatform::Windows, &b)
            .unwrap();
    let material = f
        .material
        .with_enrollment_record_sha256(f.artifacts.canonical_record_sha256)
        .unwrap();
    let parent = root.pairing_parent(id(DEVICE_ID)).unwrap();
    {
        use context_relay_core::devices::crypto::*;
        let grant = build_pairing_grant(
            &request,
            &PairingGrantApproval {
                request_digest: request.digest(),
                certificate_id: id(OTHER_ID),
                scope: root.state().scope,
                control_epoch: 1,
                issuer_certificate: f.artifacts.record.genesis_certificate.clone(),
            },
            &f.device_keys,
            &material,
        )
        .unwrap();
        let old = build_pairing_approved_payload_v1(
            &request,
            grant,
            id(CERTIFICATE_ID),
            f.artifacts.record.genesis_certificate.clone(),
            "A",
            NativePlatform::Windows,
        )
        .unwrap();
        let old =
            inspect_pairing_approval(&encode_pairing_approved_payload_v1(&old).unwrap(), &request)
                .unwrap();
        // Standalone V1 approval cannot extend a vault with accepted V2 history.
        assert!(v.prepare_pairing_approval(&request, &old, 4000).is_err());
    }
    let built = build_pairing_approval_v2(
        &request,
        &parent,
        id(DEVICE_ID),
        &f.device_keys,
        id(OTHER_ID),
        "A",
        NativePlatform::Windows,
        &material,
    )
    .unwrap();
    let payload = encode_pairing_approved_payload_v2(&built.payload).unwrap();
    let statement = DeviceMembershipAddStatementV1::from_approved_payload_v2(&payload).unwrap();
    let sig = statement
        .sign(&f.artifacts.record.genesis_certificate, &f.device_keys)
        .unwrap();
    let bytes = statement.signing_preimage().unwrap();
    let successor = statement
        .verify_and_advance(sig, &request, &payload, &parent)
        .unwrap();
    let d = MembershipEndpoint {
        state_sha256: successor.state().state_sha256,
        ..g
    };
    let event = || MembershipHistoryEvent::PairingAdd {
        statement: &bytes,
        signature: sig,
        request: &request,
        approved_payload: &payload,
    };
    let raw = open_raw(path.path(), &ks.key(CREDENTIAL));
    raw.execute_batch("CREATE TRIGGER fail_tip BEFORE UPDATE ON accepted_membership BEGIN SELECT RAISE(ABORT,'injected');END").unwrap();
    assert!(
        v.accept_membership_extension(g, d, &[event()], BUDGET)
            .is_err()
    );
    assert_eq!(
        v.accepted_membership_history(BUDGET)
            .unwrap()
            .unwrap()
            .endpoint(),
        g
    );
    assert_eq!(
        raw.query_row("SELECT count(*) FROM membership_events", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    raw.execute_batch("DROP TRIGGER fail_tip").unwrap();
    assert_eq!(
        v.accept_membership_extension(g, d, &[event()], BUDGET)
            .unwrap(),
        CommitDisposition::Inserted
    );
    assert_eq!(
        v.accept_membership_extension(g, d, &[event()], BUDGET)
            .unwrap(),
        CommitDisposition::ExactReplay
    );
    // Same-epoch advancement invalidates even an exact outgoing retry from an owned snapshot.
    assert!(
        v.advance_replay_cursor(
            id(WORKSPACE_ID),
            "supabase",
            "2026-09-13T00:00:00Z",
            stale_operation.operation.operation_id,
            Some(g)
        )
        .is_err()
    );
    assert!(
        v.sync_cursor(id(WORKSPACE_ID), "supabase")
            .unwrap()
            .is_none()
    );
    assert!(
        context_relay_core::sync::build_checkpoint(
            &v,
            &context_relay_core::sync::CheckpointBuildContext {
                scope: root.state().scope,
                creator_device: id(DEVICE_ID),
                active_key_epoch: 1,
                device_keys: &f.device_keys,
                created_hlc: context_relay_protocol::HybridLogicalClock::new(
                    4100,
                    0,
                    id(DEVICE_ID)
                )
            },
            &stale
        )
        .is_err()
    );
    let fresh = v.trusted_sync_material(&f.device_keys).unwrap();
    assert!(
        v.apply_admitted_operation(
            &admitted,
            &fresh,
            "supabase",
            "2026-09-13T00:00:00Z",
            &NoEmbedding
        )
        .is_err()
    );
    assert!(
        v.commit_outgoing_operation_at(&mutation, &stale_operation, Some(&support::basis(0)), 4000)
            .is_err()
    );
    assert!(
        context_relay_core::sync::admit_operation(&v, &stale_operation.canonical_bytes, &stale)
            .is_err()
    );
    let fork_request = SignedPairingRequest::build(
        id("018f22e2-79b0-7cc8-98c4-dc0c0c073992"),
        id("018f22e2-79b0-7cc8-98c4-dc0c0c073993"),
        "fork",
        NativePlatform::Windows,
        &b,
    )
    .unwrap();
    let fork = build_pairing_approval_v2(
        &fork_request,
        &parent,
        id(DEVICE_ID),
        &f.device_keys,
        id("018f22e2-79b0-7cc8-98c4-dc0c0c073994"),
        "A",
        NativePlatform::Windows,
        &material,
    )
    .unwrap();
    let fork_payload = encode_pairing_approved_payload_v2(&fork.payload).unwrap();
    let fs = DeviceMembershipAddStatementV1::from_approved_payload_v2(&fork_payload).unwrap();
    let fsig = fs
        .sign(&f.artifacts.record.genesis_certificate, &f.device_keys)
        .unwrap();
    let fb = fs.signing_preimage().unwrap();
    assert!(
        v.accept_membership_extension(
            g,
            MembershipEndpoint {
                state_sha256: fs.control_state_sha256(fsig).unwrap(),
                ..g
            },
            &[MembershipHistoryEvent::PairingAdd {
                statement: &fb,
                signature: fsig,
                request: &fork_request,
                approved_payload: &fork_payload
            }],
            BUDGET
        )
        .is_err()
    );
    use context_relay_core::sync::TrustedSyncMaterial;
    assert!(
        v.trusted_sync_material(&f.device_keys)
            .unwrap()
            .trusted_device(id(ACCOUNT_ID), id(WORKSPACE_ID), id(OTHER_ID))
            .is_ok()
    );
    let confirmed =
        confirm_pairing_transcript_v2(&payload, built.safety_number.as_str(), &request).unwrap();
    let pending = TempVault::new("membership-pending-restore");
    let mut pending_vault = Vault::open(pending.path(), CREDENTIAL, &ks).unwrap();
    pending_vault
        .store_hosted_restore_intent(&context_relay_core::vault::HostedRestoreIntent {
            project_url: "https://example.supabase.co".into(),
            user_id: uuid::Uuid::now_v7(),
            session_id: uuid::Uuid::now_v7(),
        })
        .unwrap();
    assert!(
        pending_vault
            .accept_confirmed_membership_admission(
                &f.artifacts.canonical_record,
                &[],
                &confirmed,
                &request,
                sig,
                &b,
                BUDGET
            )
            .is_err()
    );
    let joined = TempVault::new("membership-joined");
    let mut j = Vault::open(joined.path(), CREDENTIAL, &ks).unwrap();
    assert!(
        j.accept_confirmed_membership_admission(
            &f.artifacts.canonical_record,
            &[],
            &confirmed,
            &request,
            sig,
            &f.device_keys,
            BUDGET
        )
        .is_err()
    );
    assert_eq!(
        j.accept_confirmed_membership_admission(
            &f.artifacts.canonical_record,
            &[],
            &confirmed,
            &request,
            sig,
            &b,
            BUDGET
        )
        .unwrap(),
        CommitDisposition::Inserted
    );
    assert_eq!(
        j.accept_confirmed_membership_admission(
            &f.artifacts.canonical_record,
            &[],
            &confirmed,
            &request,
            sig,
            &b,
            BUDGET
        )
        .unwrap(),
        CommitDisposition::ExactReplay
    );
    assert_eq!(
        j.accepted_membership_history(BUDGET)
            .unwrap()
            .unwrap()
            .endpoint(),
        d
    );
    // Public acceptance alone deliberately does not install the privately opened current secrets.
    assert!(j.trusted_sync_material(&b).is_err());
    let joined_raw = open_raw(joined.path(), &ks.key(CREDENTIAL));
    assert_eq!(joined_raw.query_row("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='membership_epoch_secrets'", [], |r| r.get::<_,i64>(0)).unwrap(), 1, "confirmed admission must durably retain its privately opened keys");
    assert_eq!(
        joined_raw
            .query_row("SELECT count(*) FROM membership_epoch_secrets", [], |r| r
                .get::<_, i64>(
                0
            ))
            .unwrap(),
        1
    );
    let current = v.accepted_membership_history(BUDGET).unwrap().unwrap();
    let rotation = DeviceRevocationStatementV1 {
        schema_version: 1,
        revocation_id: id("018f22e2-79b0-7cc8-98c4-dc0c0c073990"),
        account_id: id(ACCOUNT_ID),
        workspace_id: id(WORKSPACE_ID),
        issuer_device_id: id(OTHER_ID),
        target_device_id: id(DEVICE_ID),
        control_epoch: 1,
        key_epoch: 1,
        cutoff_sequence: 0,
        cutoff_hash: Sha256Digest([0; 32]),
        transition_sha256: Sha256Digest([1; 32]),
    };
    let (rotation, transition, rsig) =
        RevocationTransitionV1::build(rotation, &b, &current.state()).unwrap();
    let rbytes = rotation.signing_preimage().unwrap();
    let tbytes = transition.canonical_bytes().unwrap();
    let next = transition
        .verify_and_advance(&rotation, rsig, &current.state())
        .unwrap();
    let r = MembershipEndpoint {
        state_sha256: next.state().state_sha256,
        control_epoch: 2,
        key_epoch: 2,
    };
    assert_eq!(
        v.accept_membership_extension(
            d,
            r,
            &[MembershipHistoryEvent::Revocation {
                statement: &rbytes,
                signature: rsig,
                transition: &tbytes
            }],
            BUDGET
        )
        .unwrap(),
        CommitDisposition::Inserted
    );
    assert!(
        v.accept_membership_extension(g, d, &[event()], BUDGET)
            .is_err()
    );
    assert!(v.trusted_sync_material(&f.device_keys).is_err());
    drop(v);
    let v = Vault::open(path.path(), CREDENTIAL, &ks).unwrap();
    assert_eq!(
        v.accepted_membership_history(BUDGET)
            .unwrap()
            .unwrap()
            .endpoint(),
        r
    );
    assert!(v.trusted_workspace_material(&f.device_keys).is_err());
    // Historical canonical adds provide metadata, but current accepted removals
    // determine issuer/discovery state even when legacy rows still say active.
    let revoked = v.device_certificate(id(CERTIFICATE_ID)).unwrap().unwrap();
    assert_eq!(
        revoked.state,
        context_relay_core::vault::DeviceCertificateState::Revoked
    );
    let all = v.all_devices().unwrap();
    assert_eq!(
        all.iter()
            .find(|row| row.certificate_id == id(CERTIFICATE_ID))
            .unwrap()
            .state,
        context_relay_core::vault::DeviceCertificateState::Revoked
    );
    assert_eq!(
        all.iter()
            .find(|row| row.certificate_id == id(OTHER_ID))
            .unwrap()
            .state,
        context_relay_core::vault::DeviceCertificateState::Active
    );
    assert!(
        v.accepted_membership_history(BUDGET)
            .unwrap()
            .unwrap()
            .pairing_parent(id(DEVICE_ID))
            .is_err()
    );
    let pin: Vec<u8> = raw
        .query_row("SELECT enrollment_pin FROM accepted_membership", [], |r| {
            r.get(0)
        })
        .unwrap();
    raw.execute_batch("UPDATE accepted_membership SET enrollment_pin=zeroblob(32)")
        .unwrap();
    assert!(v.accepted_membership_history(BUDGET).is_err());
    raw.execute("UPDATE accepted_membership SET enrollment_pin=?1", [pin])
        .unwrap();
    raw.execute_batch(
        "UPDATE accepted_membership SET account_id='018f22e2-79b0-7cc8-98c4-dc0c0c073995'",
    )
    .unwrap();
    assert!(v.accepted_membership_history(BUDGET).is_err());
    raw.execute("UPDATE accepted_membership SET account_id=?1", [ACCOUNT_ID])
        .unwrap();
    raw.execute_batch("UPDATE membership_events SET ordinal=99 WHERE ordinal=0")
        .unwrap();
    assert!(v.accepted_membership_history(BUDGET).is_err());
    raw.execute_batch("UPDATE membership_events SET ordinal=0 WHERE ordinal=99")
        .unwrap();
    raw.execute_batch("CREATE TEMP TABLE saved_event AS SELECT * FROM membership_events WHERE ordinal=0; DELETE FROM membership_events WHERE ordinal=0").unwrap();
    assert!(v.accepted_membership_history(BUDGET).is_err());
    assert!(v.trusted_workspace_material(&f.device_keys).is_err());
    raw.execute_batch("INSERT INTO membership_events SELECT * FROM saved_event")
        .unwrap();
    let payload: Vec<u8> = raw
        .query_row(
            "SELECT artifact FROM membership_events WHERE ordinal=0",
            [],
            |r| r.get(0),
        )
        .unwrap();
    raw.execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE membership_events SET artifact=zeroblob(1000001) WHERE ordinal=0").unwrap();
    assert!(v.accepted_membership_history(BUDGET).is_err());
    raw.execute(
        "UPDATE membership_events SET artifact=?1 WHERE ordinal=0",
        [payload],
    )
    .unwrap();
    raw.execute_batch("PRAGMA ignore_check_constraints=OFF")
        .unwrap();
    raw.execute_batch("UPDATE membership_events SET signature=zeroblob(64) WHERE ordinal=0")
        .unwrap();
    assert!(v.accepted_membership_history(BUDGET).is_err());
    assert!(v.trusted_workspace_material(&f.device_keys).is_err());
}
struct NoEmbedding;

#[test]
fn retained_root_stages_rotation_without_pairing_c_and_preserves_epoch_one() {
    let f = fixture();
    let path = TempVault::new("membership-root-staging");
    let ks = MemoryKeyStore::default();
    let mut v = Vault::open(path.path(), CREDENTIAL, &ks).unwrap();
    v.prepare_recovery_enrollment(&write(&f.artifacts, 1000))
        .unwrap();
    let raw = open_raw(path.path(), &ks.key(CREDENTIAL));
    raw.execute_batch("CREATE TRIGGER fail_root_seed BEFORE INSERT ON membership_root_material_seed BEGIN SELECT RAISE(ABORT,'injected');END").unwrap();
    assert!(
        v.activate_recovery_enrollment(&receipt(&f.artifacts, 2000), &f.device_keys, 3000)
            .is_err()
    );
    drop(v);
    let mut v = Vault::open(path.path(), CREDENTIAL, &ks).unwrap();
    assert!(v.accepted_membership_history(BUDGET).unwrap().is_none());
    assert_eq!(
        raw.query_row("SELECT count(*) FROM membership_epoch_secrets", [], |r| r
            .get::<_, i64>(
            0
        ))
        .unwrap(),
        0
    );
    raw.execute_batch("DROP TRIGGER fail_root_seed").unwrap();
    v.activate_recovery_enrollment(&receipt(&f.artifacts, 2000), &f.device_keys, 3000)
        .unwrap();
    assert_eq!(
        raw.query_row("SELECT count(*) FROM membership_epoch_secrets", [], |r| r
            .get::<_, i64>(
            0
        ))
        .unwrap(),
        1
    );
    assert_eq!(
        raw.query_row(
            "SELECT count(*) FROM membership_root_material_seed",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
    let root = v.accepted_membership_history(BUDGET).unwrap().unwrap();
    let g = root.endpoint();
    v.stage_current_membership_material(g, id(DEVICE_ID), &f.device_keys, BUDGET)
        .unwrap();
    v.activate_current_membership_material(g, id(DEVICE_ID), &f.device_keys, BUDGET)
        .unwrap();
    let stale = v.trusted_sync_material(&f.device_keys).unwrap();
    let stale_mutation = context_relay_protocol::RecordMutationV1::UpsertProject(
        context_relay_protocol::ProjectIdentity {
            project_id: id(OTHER_ID),
            github_repository_id: None,
            git_remote_fingerprint: None,
            monorepo_subdirectory: None,
            name: "stale operation".into(),
        },
    );
    let stale_operation = context_relay_core::sync::OperationBuilder::new(
        stale.local_identity(id(DEVICE_ID), &f.device_keys).unwrap(),
    )
    .build(context_relay_core::sync::OperationBuildRequest {
        operation_id: id(ENROLLMENT_ID),
        project_id: Some(id(OTHER_ID)),
        mutation: &stale_mutation,
        causal_frontier: vec![],
        previous: None,
        blob_refs: vec![],
        created_hlc: context_relay_protocol::HybridLogicalClock::new(4000, 0, id(DEVICE_ID)),
    })
    .unwrap();
    v.commit_outgoing_operation_at(&stale_mutation, &stale_operation, None, 4000)
        .unwrap();
    let b = DeviceKeys::generate().unwrap();
    let request =
        SignedPairingRequest::build(id(OTHER_ID), id(OTHER_ID), "B", NativePlatform::Windows, &b)
            .unwrap();
    let material = f
        .material
        .with_enrollment_record_sha256(f.artifacts.canonical_record_sha256)
        .unwrap();
    let built = build_pairing_approval_v2(
        &request,
        &root.pairing_parent(id(DEVICE_ID)).unwrap(),
        id(DEVICE_ID),
        &f.device_keys,
        id(OTHER_ID),
        "A",
        NativePlatform::Windows,
        &material,
    )
    .unwrap();
    let payload = encode_pairing_approved_payload_v2(&built.payload).unwrap();
    let statement = DeviceMembershipAddStatementV1::from_approved_payload_v2(&payload).unwrap();
    let sig = statement
        .sign(&f.artifacts.record.genesis_certificate, &f.device_keys)
        .unwrap();
    let c = MembershipEndpoint {
        state_sha256: statement.control_state_sha256(sig).unwrap(),
        ..g
    };
    v.accept_membership_extension(
        g,
        c,
        &[MembershipHistoryEvent::PairingAdd {
            statement: &statement.signing_preimage().unwrap(),
            signature: sig,
            request: &request,
            approved_payload: &payload,
        }],
        BUDGET,
    )
    .unwrap();
    v.stage_current_membership_material(c, id(DEVICE_ID), &f.device_keys, BUDGET)
        .unwrap();
    assert_eq!(
        v.trusted_sync_material(&f.device_keys)
            .unwrap()
            .local_identity(id(DEVICE_ID), &f.device_keys)
            .unwrap()
            .membership_endpoint,
        Some(c),
        "authenticated activation survives accepted same-epoch ADD with freshly rebuilt authority"
    );
    assert!(
        context_relay_core::sync::admit_operation(&v, &stale_operation.canonical_bytes, &stale)
            .is_err(),
        "old owned endpoint fails even though same-epoch keys remain active"
    );
    assert!(
        v.commit_outgoing_operation_at(&stale_mutation, &stale_operation, None, 4001)
            .is_err()
    );
    assert!(
        v.activate_current_membership_material(
            MembershipEndpoint {
                state_sha256: Sha256Digest([55; 32]),
                ..c
            },
            id(DEVICE_ID),
            &f.device_keys,
            BUDGET
        )
        .is_err(),
        "unrelated same-epoch branch is not activation authority"
    );
    let history = v.accepted_membership_history(BUDGET).unwrap().unwrap();
    let s = DeviceRevocationStatementV1 {
        schema_version: 1,
        revocation_id: id("018f22e2-79b0-7cc8-98c4-dc0c0c073990"),
        account_id: id(ACCOUNT_ID),
        workspace_id: id(WORKSPACE_ID),
        issuer_device_id: id(DEVICE_ID),
        target_device_id: id(OTHER_ID),
        control_epoch: 1,
        key_epoch: 1,
        cutoff_sequence: 0,
        cutoff_hash: Sha256Digest([0; 32]),
        transition_sha256: Sha256Digest([1; 32]),
    };
    let (s, t, sig) = RevocationTransitionV1::build(s, &f.device_keys, &history.state()).unwrap();
    let original = t
        .open_device_material(&s, sig, &history.state(), id(DEVICE_ID), &f.device_keys)
        .unwrap();
    assert!(original.enrollment_record_sha256().is_none());
    let d = MembershipEndpoint {
        state_sha256: s.control_state_sha256(sig).unwrap(),
        control_epoch: 2,
        key_epoch: 2,
    };
    v.accept_membership_extension(
        c,
        d,
        &[MembershipHistoryEvent::Revocation {
            statement: &s.signing_preimage().unwrap(),
            signature: sig,
            transition: &t.canonical_bytes().unwrap(),
        }],
        BUDGET,
    )
    .unwrap();
    let original_seal: Vec<u8> = raw
        .query_row(
            "SELECT envelope FROM membership_epoch_secrets WHERE key_epoch=1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    // Skip staging epoch two, add another device, then rotate again while root survives.
    let next_device = id("018f22e2-79b0-7cc8-98c4-dc0c0c073991");
    let next_keys = DeviceKeys::generate().unwrap();
    let request = SignedPairingRequest::build(
        id("018f22e2-79b0-7cc8-98c4-dc0c0c073992"),
        next_device,
        "C",
        NativePlatform::Windows,
        &next_keys,
    )
    .unwrap();
    let history = v.accepted_membership_history(BUDGET).unwrap().unwrap();
    let pinned = t
        .open_device_material(
            &s,
            sig,
            &history.latest_rotation_predecessor().unwrap(),
            id(DEVICE_ID),
            &f.device_keys,
        )
        .unwrap()
        .with_enrollment_record_sha256(f.artifacts.canonical_record_sha256)
        .unwrap();
    let built = build_pairing_approval_v2(
        &request,
        &history.pairing_parent(id(DEVICE_ID)).unwrap(),
        id(DEVICE_ID),
        &f.device_keys,
        id("018f22e2-79b0-7cc8-98c4-dc0c0c073993"),
        "A",
        NativePlatform::Windows,
        &pinned,
    )
    .unwrap();
    let payload = encode_pairing_approved_payload_v2(&built.payload).unwrap();
    let add = DeviceMembershipAddStatementV1::from_approved_payload_v2(&payload).unwrap();
    let signature = add
        .sign(
            &history.state().active_devices[&id(DEVICE_ID)],
            &f.device_keys,
        )
        .unwrap();
    let added = MembershipEndpoint {
        state_sha256: add.control_state_sha256(signature).unwrap(),
        ..d
    };
    v.accept_membership_extension(
        d,
        added,
        &[MembershipHistoryEvent::PairingAdd {
            statement: &add.signing_preimage().unwrap(),
            signature,
            request: &request,
            approved_payload: &payload,
        }],
        BUDGET,
    )
    .unwrap();
    let history = v.accepted_membership_history(BUDGET).unwrap().unwrap();
    let (s3, t3, sig3) = RevocationTransitionV1::build(
        DeviceRevocationStatementV1 {
            revocation_id: id("018f22e2-79b0-7cc8-98c4-dc0c0c073994"),
            target_device_id: next_device,
            control_epoch: 2,
            key_epoch: 2,
            ..s
        },
        &f.device_keys,
        &history.state(),
    )
    .unwrap();
    let original3 = t3
        .open_device_material(&s3, sig3, &history.state(), id(DEVICE_ID), &f.device_keys)
        .unwrap();
    let d = MembershipEndpoint {
        state_sha256: s3.control_state_sha256(sig3).unwrap(),
        control_epoch: 3,
        key_epoch: 3,
    };
    v.accept_membership_extension(
        added,
        d,
        &[MembershipHistoryEvent::Revocation {
            statement: &s3.signing_preimage().unwrap(),
            signature: sig3,
            transition: &t3.canonical_bytes().unwrap(),
        }],
        BUDGET,
    )
    .unwrap();
    assert!(
        v.stage_current_membership_material(c, id(DEVICE_ID), &f.device_keys, BUDGET)
            .is_err()
    );
    assert!(
        v.stage_current_membership_material(d, id(DEVICE_ID), &b, BUDGET)
            .is_err()
    );
    raw.execute_batch("CREATE TRIGGER fail_third_epoch BEFORE INSERT ON membership_epoch_secrets WHEN NEW.key_epoch=3 BEGIN SELECT RAISE(ABORT,'injected');END").unwrap();
    assert!(
        v.stage_current_membership_material(d, id(DEVICE_ID), &f.device_keys, BUDGET)
            .is_err()
    );
    drop(v);
    let mut v = Vault::open(path.path(), CREDENTIAL, &ks).unwrap();
    assert_eq!(
        raw.query_row(
            "SELECT count(*) FROM membership_epoch_secrets WHERE key_epoch>1",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0,
        "late bundle failure must roll back epoch two too"
    );
    raw.execute_batch("DROP TRIGGER fail_third_epoch").unwrap();
    v.stage_current_membership_material(d, id(DEVICE_ID), &f.device_keys, BUDGET)
        .unwrap();
    let seals: Vec<(u32, Vec<u8>, Vec<u8>)> = raw
        .prepare(
            "SELECT key_epoch,envelope,signature FROM membership_epoch_secrets ORDER BY key_epoch",
        )
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    drop(v);
    let mut v = Vault::open(path.path(), CREDENTIAL, &ks).unwrap();
    assert!(
        v.staged_membership_epoch(d, id(DEVICE_ID), 2, true, &f.device_keys, BUDGET)
            .unwrap()
            .is_some(),
        "skipped intermediate rotation must be durably staged"
    );
    v.stage_current_membership_material(d, id(DEVICE_ID), &f.device_keys, BUDGET)
        .unwrap();
    let retry_seals: Vec<(u32, Vec<u8>, Vec<u8>)> = raw
        .prepare(
            "SELECT key_epoch,envelope,signature FROM membership_epoch_secrets ORDER BY key_epoch",
        )
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        seals, retry_seals,
        "multi-bundle exact retry preserves every seal and signature"
    );
    assert_eq!(
        v.staged_membership_epoch(d, id(DEVICE_ID), 1, true, &f.device_keys, BUDGET)
            .unwrap()
            .unwrap()
            .workspace_root_key(),
        material.workspace_root_key()
    );
    let staged = v
        .staged_membership_epoch(d, id(DEVICE_ID), 2, true, &f.device_keys, BUDGET)
        .unwrap()
        .unwrap();
    assert_eq!(staged.workspace_root_key(), original.workspace_root_key());
    assert_eq!(staged.active_epoch_key(), original.active_epoch_key());
    let epoch1 = v
        .staged_membership_epoch(d, id(DEVICE_ID), 1, true, &f.device_keys, BUDGET)
        .unwrap()
        .unwrap();
    assert_eq!(epoch1.active_epoch_key(), material.active_epoch_key());
    let epoch3 = v
        .staged_membership_epoch(d, id(DEVICE_ID), 3, true, &f.device_keys, BUDGET)
        .unwrap()
        .unwrap();
    assert_eq!(epoch3.workspace_root_key(), original3.workspace_root_key());
    assert_eq!(epoch3.active_epoch_key(), original3.active_epoch_key());
    assert_eq!(
        staged.enrollment_record_sha256(),
        Some(f.artifacts.canonical_record_sha256)
    );
    assert_eq!(
        raw.query_row(
            "SELECT envelope FROM membership_epoch_secrets WHERE key_epoch=1",
            [],
            |r| r.get::<_, Vec<u8>>(0)
        )
        .unwrap(),
        original_seal
    );
    assert_eq!(
        raw.query_row(
            "SELECT count(*) FROM membership_confirmed_admission",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    assert!(v.trusted_sync_material(&f.device_keys).is_err());
    // Once signed, the obsolete enrollment envelope is no longer a recurring source.
    assert!(
        v.activate_current_membership_material(c, id(DEVICE_ID), &f.device_keys, BUDGET)
            .is_err()
    );
    assert!(
        v.activate_current_membership_material(d, id(DEVICE_ID), &b, BUDGET)
            .is_err()
    );
    raw.execute_batch("CREATE TRIGGER fail_activation BEFORE INSERT ON membership_current_activation BEGIN SELECT RAISE(ABORT,'injected');END").unwrap();
    assert!(
        v.activate_current_membership_material(d, id(DEVICE_ID), &f.device_keys, BUDGET)
            .is_err()
    );
    drop(v);
    let mut v = Vault::open(path.path(), CREDENTIAL, &ks).unwrap();
    assert!(v.trusted_sync_material(&f.device_keys).is_err());
    assert!(v.enrolled_workspace_material(&f.device_keys).is_err());
    use context_relay_core::devices::pairing::PairingMaterialSource;
    assert!(
        context_relay_core::devices::pairing::VaultPairingMaterialSource
            .current_material(&mut v, &f.device_keys, root.state().scope)
            .is_err()
    );
    assert!(
        context_relay_core::sync::admit_operation(&v, &stale_operation.canonical_bytes, &stale)
            .is_err()
    );
    assert!(
        v.commit_outgoing_operation_at(&stale_mutation, &stale_operation, None, 5000)
            .is_err()
    );
    raw.execute_batch("DROP TRIGGER fail_activation").unwrap();
    v.activate_current_membership_material(d, id(DEVICE_ID), &f.device_keys, BUDGET)
        .expect("independent retained rotation must activate without a transfer or pairing C");
    let active = v.trusted_sync_material(&f.device_keys).unwrap();
    let identity = active
        .local_identity(id(DEVICE_ID), &f.device_keys)
        .unwrap();
    assert_eq!(identity.key_epoch, 3);
    assert_eq!(identity.membership_endpoint, Some(d));
    drop(v);
    let mut v = Vault::open(path.path(), CREDENTIAL, &ks).unwrap();
    assert_eq!(
        v.trusted_workspace_material(&f.device_keys)
            .unwrap()
            .key_epoch(),
        3
    );
    assert!(
        context_relay_core::sync::admit_operation(&v, &stale_operation.canonical_bytes, &stale)
            .is_err()
    );
    assert!(
        v.commit_outgoing_operation_at(&stale_mutation, &stale_operation, None, 5000)
            .is_err()
    );
    raw.execute_batch("CREATE TEMP TABLE saved_activation AS SELECT * FROM membership_current_activation; UPDATE membership_current_activation SET signature=zeroblob(64)").unwrap();
    assert!(v.trusted_sync_material(&f.device_keys).is_err());
    raw.execute_batch("DELETE FROM membership_current_activation; INSERT INTO membership_current_activation SELECT * FROM saved_activation").unwrap();
    // A retained root's pre-rotation operation needs no historical transfer or pairing C.
    let newcomer = DeviceKeys::generate().unwrap();
    let newcomer_id = id("018f22e2-79b0-7cc8-98c4-dc0c0c073996");
    let newcomer_request = SignedPairingRequest::build(
        id("018f22e2-79b0-7cc8-98c4-dc0c0c073996"),
        newcomer_id,
        "D",
        NativePlatform::Windows,
        &newcomer,
    )
    .unwrap();
    let history = v.accepted_membership_history(BUDGET).unwrap().unwrap();
    let material = v
        .staged_membership_epoch(d, id(DEVICE_ID), 3, true, &f.device_keys, BUDGET)
        .unwrap()
        .unwrap();
    let built = build_pairing_approval_v2(
        &newcomer_request,
        &history.pairing_parent(id(DEVICE_ID)).unwrap(),
        id(DEVICE_ID),
        &f.device_keys,
        id("018f22e2-79b0-7cc8-98c4-dc0c0c073996"),
        "A",
        NativePlatform::Windows,
        &material,
    )
    .unwrap();
    let payload = encode_pairing_approved_payload_v2(&built.payload).unwrap();
    let add = DeviceMembershipAddStatementV1::from_approved_payload_v2(&payload).unwrap();
    let sig = add
        .sign(
            &history.state().active_devices[&id(DEVICE_ID)],
            &f.device_keys,
        )
        .unwrap();
    let added = MembershipEndpoint {
        state_sha256: add.control_state_sha256(sig).unwrap(),
        ..d
    };
    v.accept_membership_extension(
        d,
        added,
        &[MembershipHistoryEvent::PairingAdd {
            statement: &add.signing_preimage().unwrap(),
            signature: sig,
            request: &newcomer_request,
            approved_payload: &payload,
        }],
        BUDGET,
    )
    .unwrap();
    let fresh = v.trusted_sync_material(&f.device_keys).unwrap();
    let incoming = context_relay_core::sync::OperationBuilder::new(
        fresh.local_identity(newcomer_id, &newcomer).unwrap(),
    )
    .build(context_relay_core::sync::OperationBuildRequest {
        operation_id: id("ffffffff-ffff-7fff-8fff-ffffffffffff"),
        project_id: Some(id(OTHER_ID)),
        mutation: &stale_mutation,
        causal_frontier: vec![],
        previous: None,
        blob_refs: vec![],
        created_hlc: context_relay_protocol::HybridLogicalClock::new(6000, 0, newcomer_id),
    })
    .unwrap();
    let context_relay_core::sync::AdmissionDecision::Admitted(admitted) =
        context_relay_core::sync::admit_operation(&v, &incoming.canonical_bytes, &fresh).unwrap()
    else {
        panic!()
    };
    raw.execute_batch("CREATE TEMP TABLE saved_operation_meta AS SELECT * FROM sync_operation_meta; DELETE FROM sync_operation_meta").unwrap();
    assert!(
        v.apply_admitted_operation(
            &admitted,
            &fresh,
            "memory",
            "2026-09-14T00:00:00Z",
            &NoEmbedding
        )
        .is_err(),
        "raw signed operation rows alone do not prove ordinary local admission"
    );
    raw.execute_batch("INSERT INTO sync_operation_meta SELECT * FROM saved_operation_meta")
        .unwrap();
    v.apply_admitted_operation(
        &admitted,
        &fresh,
        "memory",
        "2026-09-14T00:00:00Z",
        &NoEmbedding,
    )
    .expect(
        "ordinary current merge must rehydrate retained root history without C or any transfer",
    );
    assert_eq!(
        v.record_heads(id(WORKSPACE_ID), stale_mutation.record_id())
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        raw.query_row("SELECT count(*) FROM historical_transfers", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    let d = added;
    raw.execute_batch("UPDATE recovery_enrollments SET device_envelope_sha256=zeroblob(32)")
        .unwrap();
    v.stage_current_membership_material(d, id(DEVICE_ID), &f.device_keys, BUDGET)
        .unwrap();
    raw.execute(
        "UPDATE recovery_enrollments SET device_envelope_sha256=?1",
        [f.artifacts.device_material_envelope_sha256.0.as_slice()],
    )
    .unwrap();
    raw.execute_batch("CREATE TEMP TABLE saved_root AS SELECT * FROM membership_epoch_secrets WHERE key_epoch=1; DELETE FROM membership_epoch_secrets WHERE key_epoch=1").unwrap();
    assert!(
        v.stage_current_membership_material(d, id(DEVICE_ID), &f.device_keys, BUDGET)
            .is_err()
    );
    raw.execute_batch("INSERT INTO membership_epoch_secrets SELECT * FROM saved_root; UPDATE membership_epoch_secrets SET signature=zeroblob(64) WHERE key_epoch=1").unwrap();
    assert!(
        v.stage_current_membership_material(d, id(DEVICE_ID), &f.device_keys, BUDGET)
            .is_err()
    );
    let history = v.accepted_membership_history(BUDGET).unwrap().unwrap();
    let (revoked, transition, signature) = RevocationTransitionV1::build(
        DeviceRevocationStatementV1 {
            schema_version: 1,
            revocation_id: id("018f22e2-79b0-7cc8-98c4-dc0c0c073997"),
            account_id: id(ACCOUNT_ID),
            workspace_id: id(WORKSPACE_ID),
            issuer_device_id: newcomer_id,
            target_device_id: id(DEVICE_ID),
            control_epoch: 3,
            key_epoch: 3,
            cutoff_sequence: 1,
            cutoff_hash: stale_operation.canonical_hash,
            transition_sha256: Sha256Digest([1; 32]),
        },
        &newcomer,
        &history.state(),
    )
    .unwrap();
    let revoked_endpoint = MembershipEndpoint {
        state_sha256: revoked.control_state_sha256(signature).unwrap(),
        control_epoch: 4,
        key_epoch: 4,
    };
    v.accept_membership_extension(
        d,
        revoked_endpoint,
        &[MembershipHistoryEvent::Revocation {
            statement: &revoked.signing_preimage().unwrap(),
            signature,
            transition: &transition.canonical_bytes().unwrap(),
        }],
        BUDGET,
    )
    .unwrap();
    drop(v);
    let mut v = Vault::open(path.path(), CREDENTIAL, &ks).unwrap();
    assert!(v.trusted_sync_material(&f.device_keys).is_err());
    assert!(
        v.apply_admitted_operation(
            &admitted,
            &fresh,
            "memory",
            "2026-09-14T00:00:02Z",
            &NoEmbedding
        )
        .is_err(),
        "old owned reader cannot resume after accepted local revocation and restart"
    );
    assert!(
        context_relay_core::devices::pairing::VaultPairingMaterialSource
            .current_material(&mut v, &f.device_keys, root.state().scope)
            .is_err()
    );
}

#[test]
fn schema40_root_seeding_preserves_explicit_legacy_enrollment_trust_boundary() {
    let f = fixture();
    let path = TempVault::new("membership-legacy-root");
    let ks = MemoryKeyStore::default();
    let mut v = Vault::open(path.path(), CREDENTIAL, &ks).unwrap();
    v.prepare_recovery_enrollment(&write(&f.artifacts, 1000))
        .unwrap();
    v.activate_recovery_enrollment(&receipt(&f.artifacts, 2000), &f.device_keys, 3000)
        .unwrap();
    let g = v
        .accepted_membership_history(BUDGET)
        .unwrap()
        .unwrap()
        .endpoint();
    drop(v);
    let raw = open_raw(path.path(), &ks.key(CREDENTIAL));
    support::remove_membership_material_migration(&raw);
    raw.execute_batch("PRAGMA user_version=40").unwrap();
    let mut v = Vault::open(path.path(), CREDENTIAL, &ks).unwrap();
    assert_eq!(
        v.schema_version().unwrap(),
        context_relay_core::vault::LATEST_SCHEMA_VERSION
    );
    assert!(
        v.staged_membership_epoch(g, id(DEVICE_ID), 1, true, &f.device_keys, BUDGET)
            .unwrap()
            .is_none()
    );
    raw.execute_batch("CREATE TRIGGER fail_legacy_seed BEFORE INSERT ON membership_root_material_seed BEGIN SELECT RAISE(ABORT,'injected');END").unwrap();
    assert!(
        v.stage_current_membership_material(g, id(DEVICE_ID), &f.device_keys, BUDGET)
            .is_err()
    );
    drop(v);
    let mut v = Vault::open(path.path(), CREDENTIAL, &ks).unwrap();
    assert!(
        v.staged_membership_epoch(g, id(DEVICE_ID), 1, true, &f.device_keys, BUDGET)
            .unwrap()
            .is_none()
    );
    raw.execute_batch("DROP TRIGGER fail_legacy_seed").unwrap();
    v.stage_current_membership_material(g, id(DEVICE_ID), &f.device_keys, BUDGET)
        .unwrap();
    let bundle = v
        .staged_membership_epoch(g, id(DEVICE_ID), 1, true, &f.device_keys, BUDGET)
        .unwrap()
        .unwrap();
    assert_eq!(bundle.workspace_root_key(), f.material.workspace_root_key());
    assert_eq!(bundle.active_epoch_key(), f.material.active_epoch_key());
    assert_eq!(
        raw.query_row(
            "SELECT count(*) FROM membership_root_material_seed",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
}
impl context_relay_core::sync::RepresentativeEmbeddingResolver for NoEmbedding {
    fn resolve_representative_embedding(
        &self,
        _operation_id: context_relay_protocol::OperationId,
        _mutation: &context_relay_protocol::RecordMutationV1,
    ) -> Result<Option<context_relay_core::search::Embedding384>, context_relay_core::sync::SyncError>
    {
        Ok(None)
    }
}
