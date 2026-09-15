mod support;

use std::str::FromStr;

use context_relay_core::{
    crypto::{CertificateFieldsV1, DeviceCertificateV1, DeviceKeys, RecoveryKeys, RecoveryPhrase},
    devices::{
        crypto::PairingKeyBundle,
        recovery_crypto::{
            RecoveryEnrollmentArtifacts, RecoveryEnrollmentBuildRequest,
            build_recovery_enrollment_artifacts,
        },
        recovery_transport::RecoveryEnrollmentReceipt,
    },
    sync::SyncScope,
    vault::{RecoveryEnrollmentWrite, Vault},
};
use context_relay_protocol::{
    AccountId, DeviceCertificateId, DeviceId, NativePlatform, PairingRequestNonce,
    RecoveryEnrollmentId, RecoveryRootId, Sha256Digest, WorkspaceId,
};

use support::{MemoryKeyStore, TempVault};

const ACCOUNT_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073981";
const WORKSPACE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073982";
const ENROLLMENT_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073983";
const RECOVERY_ROOT_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073984";
const DEVICE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073985";
const CERTIFICATE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073986";

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

use context_relay_core::devices::{
    membership_crypto::MembershipHistoryBudget,
    membership_transport::MembershipEventObject,
    memory_transport::{InMemoryPairingJoinClient, InMemoryPairingProvider},
    pairing::{
        PairingApprovalAuthority, PairingClock, PairingCoordinator, PairingCycleError,
        PairingDecisionInput, PairingDecisionStatus, VaultPairingMaterialSource,
    },
    transport::{
        PairingJoinTransport, PairingRequestReceipt, PairingResult, PairingTransportError,
    },
};
use context_relay_protocol::{PairingCode, PairingId};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
#[derive(Clone, Copy)]
struct Clock;
impl PairingClock for Clock {
    fn now_ms(&self) -> u64 {
        1000
    }
}
#[derive(Clone)]
struct MissingProof {
    inner: InMemoryPairingJoinClient,
    missing: Arc<AtomicBool>,
}
impl PairingJoinTransport for MissingProof {
    fn resolve_code(
        &self,
        code: &PairingCode,
        now: u64,
    ) -> Result<PairingId, PairingTransportError> {
        self.inner.resolve_code(code, now)
    }
    fn submit_request(
        &self,
        id: PairingId,
        bytes: &[u8],
        now: u64,
    ) -> Result<PairingRequestReceipt, PairingTransportError> {
        self.inner.submit_request(id, bytes, now)
    }
    fn result(
        &self,
        id: PairingId,
        digest: Sha256Digest,
        now: u64,
    ) -> Result<PairingResult, PairingTransportError> {
        self.inner.result(id, digest, now)
    }
    fn enrollment(
        &self,
        id: PairingId,
        digest: Sha256Digest,
        pin: Sha256Digest,
        now: u64,
    ) -> Result<Option<Vec<u8>>, PairingTransportError> {
        if self.missing.load(Ordering::SeqCst) {
            Ok(None)
        } else {
            self.inner.enrollment(id, digest, pin, now)
        }
    }
    fn membership_event(
        &self,
        id: PairingId,
        digest: Sha256Digest,
        address: Sha256Digest,
        now: u64,
    ) -> Result<Option<MembershipEventObject>, PairingTransportError> {
        self.inner.membership_event(id, digest, address, now)
    }
}

#[test]
fn confirmed_v2_missing_proof_resumes_after_restart_without_recomparison() {
    let f = fixture();
    let scope = SyncScope {
        account_id: f.artifacts.record.account_id,
        workspace_id: f.artifacts.record.workspace_id,
    };
    let ap = TempVault::new("pair-v2-approver");
    let jp = TempVault::new("pair-v2-joiner");
    let ak = MemoryKeyStore::default();
    let jk = MemoryKeyStore::default();
    let mut a = Vault::open(ap.path(), "a", &ak).unwrap();
    a.prepare_recovery_enrollment(&write(&f.artifacts, 900))
        .unwrap();
    a.activate_recovery_enrollment(&receipt(&f.artifacts, 950), &f.device_keys, 960)
        .unwrap();
    let mut j = Vault::open(jp.path(), "j", &jk).unwrap();
    let provider = InMemoryPairingProvider::with_test_entropy(
        [0xa5; 32],
        (1u8..=16).map(|v| [v; 32]).collect(),
    );
    provider
        .register_committed_enrollment(scope, &f.artifacts.canonical_record)
        .unwrap();
    let missing = Arc::new(AtomicBool::new(true));
    let coordinator = PairingCoordinator::new(
        Clock,
        VaultPairingMaterialSource,
        MissingProof {
            inner: provider.join_session_client("join").unwrap(),
            missing: missing.clone(),
        },
        provider.existing_device_client(scope, f.artifacts.record.genesis_certificate.device_id),
    );
    let join_keys = DeviceKeys::from_seeds_for_test([0x42; 32], [0x52; 32]);
    let invite = coordinator.create_invite().unwrap();
    let joined = coordinator
        .join(
            &mut j,
            &invite.code,
            id("018f22e2-79b0-7cc8-98c4-dc0c0c073991"),
            "Second Windows",
            NativePlatform::Windows,
            &join_keys,
        )
        .unwrap();
    let decision = coordinator
        .decide(
            &mut a,
            invite.pairing_id,
            joined.request_digest,
            PairingDecisionInput::Approve(PairingApprovalAuthority {
                certificate_id: id("018f22e2-79b0-7cc8-98c4-dc0c0c073992"),
                issuer_certificate_id: f.artifacts.record.genesis_certificate_id,
                issuer_keys: &f.device_keys,
            }),
        )
        .unwrap();
    let PairingDecisionStatus::Approved { safety_number } = decision else {
        panic!("approval")
    };
    coordinator.join_status(&mut j, invite.pairing_id).unwrap();
    assert!(j.pairing_confirmation_pending(invite.pairing_id).unwrap());
    assert_eq!(
        coordinator
            .confirm_join(
                &mut j,
                invite.pairing_id,
                safety_number.as_str(),
                &join_keys
            )
            .unwrap_err(),
        PairingCycleError::Incomplete
    );
    assert!(!j.pairing_confirmation_pending(invite.pairing_id).unwrap());
    let budget = MembershipHistoryBudget {
        max_events: 20,
        max_bytes: 1_000_000,
    };
    assert!(j.accepted_membership_history(budget).unwrap().is_none());
    assert!(j.trusted_workspace_material(&join_keys).is_err());
    drop(j);
    let raw = open_keyed(jp.path(), &jk.key("j"));
    let saved: Vec<u8> = raw
        .query_row(
            "SELECT confirmation_signature FROM pairing_v2_transcripts",
            [],
            |r| r.get(0),
        )
        .unwrap();
    raw.execute(
        "UPDATE pairing_v2_transcripts SET confirmation_signature=zeroblob(64)",
        [],
    )
    .unwrap();
    {
        let mut reopened = Vault::open(jp.path(), "j", &jk).unwrap();
        assert!(
            coordinator
                .resume_confirmed_join(&mut reopened, invite.pairing_id, &join_keys)
                .is_err()
        );
        assert!(
            reopened
                .accepted_membership_history(budget)
                .unwrap()
                .is_none()
        );
    }
    raw.execute(
        "UPDATE pairing_v2_transcripts SET confirmation_signature=?1",
        [&saved],
    )
    .unwrap();
    drop(raw);
    let mut j = Vault::open(jp.path(), "j", &jk).unwrap();
    assert!(
        coordinator
            .resume_confirmed_join(&mut j, invite.pairing_id, &join_keys)
            .unwrap()
            .is_none()
    );
    assert!(
        coordinator
            .resume_confirmed_join(&mut j, invite.pairing_id, &f.device_keys)
            .is_err()
    );
    assert!(j.accepted_membership_history(budget).unwrap().is_none());
    missing.store(false, Ordering::SeqCst);
    let material = coordinator
        .resume_confirmed_join(&mut j, invite.pairing_id, &join_keys)
        .unwrap()
        .unwrap();
    assert_eq!(material.active_epoch_key(), f.material.active_epoch_key());
    assert_eq!(
        j.accepted_membership_history(budget)
            .unwrap()
            .unwrap()
            .state()
            .active_devices
            .len(),
        2
    );
    assert!(
        coordinator
            .confirm_join(
                &mut j,
                invite.pairing_id,
                safety_number.as_str(),
                &join_keys
            )
            .is_ok()
    );
}

fn open_keyed(path: &std::path::Path, key: &[u8; 32]) -> rusqlite::Connection {
    let connection = rusqlite::Connection::open(path).unwrap();
    // SAFETY: first SQLite operation; key lives for the complete call.
    let result =
        unsafe { rusqlite::ffi::sqlite3_key(connection.handle(), key.as_ptr().cast(), 32) };
    assert_eq!(result, rusqlite::ffi::SQLITE_OK);
    connection
        .query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
        .unwrap();
    connection
}

#[test]
fn prepared_approver_finishes_at_accepted_descendant_after_restart() {
    interrupted_pairing_finishes_at_descendant(true, false);
}

#[test]
fn confirmed_recipient_finishes_at_accepted_descendant_after_restart() {
    interrupted_pairing_finishes_at_descendant(false, false);
}

#[test]
fn prepared_approver_cannot_finalize_after_recipient_removal() {
    interrupted_pairing_finishes_at_descendant(true, true);
}

#[test]
fn confirmed_recipient_cannot_finalize_after_issuer_removal() {
    interrupted_pairing_finishes_at_descendant(false, true);
}

fn interrupted_pairing_finishes_at_descendant(approver: bool, remove_participant: bool) {
    let f = fixture();
    let scope = SyncScope {
        account_id: f.artifacts.record.account_id,
        workspace_id: f.artifacts.record.workspace_id,
    };
    let ap = TempVault::new("descendant-approver");
    let jp = TempVault::new("descendant-recipient");
    let tp = TempVault::new("descendant-third");
    let ak = MemoryKeyStore::default();
    let jk = MemoryKeyStore::default();
    let tk = MemoryKeyStore::default();
    let mut a = Vault::open(ap.path(), "a", &ak).unwrap();
    a.prepare_recovery_enrollment(&write(&f.artifacts, 900))
        .unwrap();
    a.activate_recovery_enrollment(&receipt(&f.artifacts, 950), &f.device_keys, 960)
        .unwrap();
    let mut j = Vault::open(jp.path(), "j", &jk).unwrap();
    let provider = InMemoryPairingProvider::with_test_entropy(
        [0xa5; 32],
        (1u8..=16).map(|v| [v; 32]).collect(),
    );
    provider
        .register_committed_enrollment(scope, &f.artifacts.canonical_record)
        .unwrap();
    let coordinator = PairingCoordinator::new(
        Clock,
        VaultPairingMaterialSource,
        provider.join_session_client("join").unwrap(),
        provider.existing_device_client(scope, f.artifacts.record.genesis_certificate.device_id),
    );
    let join_keys = DeviceKeys::from_seeds_for_test([0x42; 32], [0x52; 32]);
    let invite = coordinator.create_invite().unwrap();
    let joined = coordinator
        .join(
            &mut j,
            &invite.code,
            id("018f22e2-79b0-7cc8-98c4-dc0c0c073991"),
            "Second Windows",
            NativePlatform::Windows,
            &join_keys,
        )
        .unwrap();
    let (path, store, name) = if approver {
        (ap.path(), &ak, "a")
    } else {
        (jp.path(), &jk, "j")
    };
    let raw = open_keyed(path, &store.key(name));
    raw.execute_batch(&format!("CREATE TRIGGER fail_final_pairing BEFORE UPDATE OF state ON pairing_v2_transcripts WHEN NEW.pairing_id='{}' AND NEW.state IN ('accepted','completed') BEGIN SELECT RAISE(ABORT,'interrupted final transcript'); END;", invite.pairing_id)).unwrap();
    let decision = coordinator.decide(
        &mut a,
        invite.pairing_id,
        joined.request_digest,
        PairingDecisionInput::Approve(PairingApprovalAuthority {
            certificate_id: id("018f22e2-79b0-7cc8-98c4-dc0c0c073992"),
            issuer_certificate_id: f.artifacts.record.genesis_certificate_id,
            issuer_keys: &f.device_keys,
        }),
    );
    if approver {
        assert!(decision.is_err());
    } else {
        let PairingDecisionStatus::Approved { safety_number } = decision.unwrap() else {
            panic!("approval")
        };
        coordinator.join_status(&mut j, invite.pairing_id).unwrap();
        assert!(
            coordinator
                .confirm_join(
                    &mut j,
                    invite.pairing_id,
                    safety_number.as_str(),
                    &join_keys
                )
                .is_err()
        );
    }
    let budget = MembershipHistoryBudget {
        max_events: 20,
        max_bytes: 1_000_000,
    };
    let c = if approver { &a } else { &j }
        .accepted_membership_history(budget)
        .unwrap()
        .unwrap()
        .endpoint();
    assert_eq!(
        if approver { &a } else { &j }
            .accepted_membership_history(budget)
            .unwrap()
            .unwrap()
            .state()
            .active_devices
            .len(),
        2
    );
    let proof = |raw: &rusqlite::Connection| {
        raw.query_row("SELECT canonical_request,canonical_payload,membership_signature,confirmation_signature,stored_at_ms FROM pairing_v2_transcripts WHERE pairing_id=?1", [invite.pairing_id.to_string()], |r| Ok((r.get::<_,Vec<u8>>(0)?, r.get::<_,Vec<u8>>(1)?, r.get::<_,Vec<u8>>(2)?, r.get::<_,Option<Vec<u8>>>(3)?, r.get::<_,i64>(4)?))).unwrap()
    };
    let original = proof(&raw);
    let provider_result = provider
        .join_session_client("join")
        .unwrap()
        .result(invite.pairing_id, joined.request_digest, 1000)
        .unwrap();
    let original_state: String = raw
        .query_row(
            "SELECT state FROM pairing_v2_transcripts WHERE pairing_id=?1",
            [invite.pairing_id.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        original_state,
        if approver { "prepared" } else { "confirmed" }
    );
    raw.execute_batch("DROP TRIGGER fail_final_pairing")
        .unwrap();
    drop(a);
    drop(j);
    let mut a = Vault::open(ap.path(), "a", &ak).unwrap();
    let mut j = Vault::open(jp.path(), "j", &jk).unwrap();
    // A real second pairing advances both the provider and approver from C to D.
    let third = PairingCoordinator::new(
        Clock,
        VaultPairingMaterialSource,
        provider.join_session_client("third").unwrap(),
        provider.existing_device_client(scope, f.artifacts.record.genesis_certificate.device_id),
    );
    let mut t = Vault::open(tp.path(), "t", &tk).unwrap();
    let third_keys = DeviceKeys::from_seeds_for_test([0x43; 32], [0x53; 32]);
    let invite_d = third.create_invite().unwrap();
    let joined_d = third
        .join(
            &mut t,
            &invite_d.code,
            id("018f22e2-79b0-7cc8-98c4-dc0c0c073993"),
            "Third Windows",
            NativePlatform::Windows,
            &third_keys,
        )
        .unwrap();
    third
        .decide(
            &mut a,
            invite_d.pairing_id,
            joined_d.request_digest,
            PairingDecisionInput::Approve(PairingApprovalAuthority {
                certificate_id: id("018f22e2-79b0-7cc8-98c4-dc0c0c073994"),
                issuer_certificate_id: f.artifacts.record.genesis_certificate_id,
                issuer_keys: &f.device_keys,
            }),
        )
        .unwrap();
    let (_, objects, d) = a.accepted_membership_objects(budget).unwrap().unwrap();
    assert_ne!(c, d);
    assert_eq!(
        (c.control_epoch, c.key_epoch),
        (d.control_epoch, d.key_epoch)
    );
    if !approver {
        j.accept_membership_extension(c, d, &[objects.last().unwrap().evidence()], budget)
            .unwrap();
        assert!(
            coordinator
                .resume_confirmed_join(&mut j, invite.pairing_id, &third_keys)
                .is_err()
        );
    }
    if remove_participant {
        use context_relay_core::devices::{
            membership_crypto::{MembershipEndpoint, MembershipHistoryEvent},
            revocation_crypto::{DeviceRevocationStatementV1, RevocationTransitionV1},
        };
        let pending = if approver { &mut a } else { &mut j };
        let history = pending
            .accepted_membership_history(budget)
            .unwrap()
            .unwrap();
        let (statement, transition, signature) = RevocationTransitionV1::build(
            DeviceRevocationStatementV1 {
                schema_version: 1,
                revocation_id: id("018f22e2-79b0-7cc8-98c4-dc0c0c073995"),
                account_id: scope.account_id,
                workspace_id: scope.workspace_id,
                issuer_device_id: id("018f22e2-79b0-7cc8-98c4-dc0c0c073993"),
                target_device_id: if approver {
                    id("018f22e2-79b0-7cc8-98c4-dc0c0c073991")
                } else {
                    f.artifacts.record.genesis_certificate.device_id
                },
                control_epoch: d.control_epoch,
                key_epoch: d.key_epoch,
                cutoff_sequence: 0,
                cutoff_hash: Sha256Digest([0; 32]),
                transition_sha256: Sha256Digest([1; 32]),
            },
            &third_keys,
            &history.state(),
        )
        .unwrap();
        let removed = MembershipEndpoint {
            state_sha256: statement.control_state_sha256(signature).unwrap(),
            control_epoch: d.control_epoch + 1,
            key_epoch: d.key_epoch + 1,
        };
        pending
            .accept_membership_extension(
                d,
                removed,
                &[MembershipHistoryEvent::Revocation {
                    statement: &statement.signing_preimage().unwrap(),
                    signature,
                    transition: &transition.canonical_bytes().unwrap(),
                }],
                budget,
            )
            .unwrap();
        if approver {
            assert!(
                coordinator
                    .resume_prepared_decision(pending, invite.pairing_id)
                    .is_err()
            );
        } else {
            assert!(
                coordinator
                    .resume_confirmed_join(pending, invite.pairing_id, &join_keys)
                    .is_err()
            );
        }
        assert_eq!(
            pending
                .accepted_membership_history(budget)
                .unwrap()
                .unwrap()
                .endpoint(),
            removed
        );
        assert_eq!(proof(&raw), original);
        let state: String = raw
            .query_row(
                "SELECT state FROM pairing_v2_transcripts WHERE pairing_id=?1",
                [invite.pairing_id.to_string()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(state, original_state);
        return;
    }
    // A substituted original event cannot be recognized as the accepted admission.
    raw.execute(
        "UPDATE pairing_v2_transcripts SET membership_signature=zeroblob(64) WHERE pairing_id=?1",
        [invite.pairing_id.to_string()],
    )
    .unwrap();
    if approver {
        assert!(
            coordinator
                .resume_prepared_decision(&mut a, invite.pairing_id)
                .is_err()
        );
    } else {
        assert!(
            coordinator
                .resume_confirmed_join(&mut j, invite.pairing_id, &join_keys)
                .is_err()
        );
    }
    raw.execute(
        "UPDATE pairing_v2_transcripts SET membership_signature=?2 WHERE pairing_id=?1",
        rusqlite::params![invite.pairing_id.to_string(), &original.2],
    )
    .unwrap();
    if !approver {
        // Finalization cannot recreate independent current material from historical C.
        raw.execute_batch("CREATE TEMP TABLE saved_current AS SELECT * FROM membership_epoch_secrets; DELETE FROM membership_epoch_secrets;").unwrap();
        assert!(
            coordinator
                .resume_confirmed_join(&mut j, invite.pairing_id, &join_keys)
                .is_err()
        );
        raw.execute_batch("INSERT INTO membership_epoch_secrets SELECT * FROM saved_current")
            .unwrap();
    }
    if approver {
        assert!(
            coordinator
                .resume_prepared_decision(&mut a, invite.pairing_id)
                .unwrap()
        );
        assert!(
            coordinator
                .accepted_decision_status(&a, invite.pairing_id)
                .unwrap()
                .is_some()
        );
    } else {
        let material = coordinator
            .resume_confirmed_join(&mut j, invite.pairing_id, &join_keys)
            .unwrap()
            .unwrap();
        assert_eq!(material.active_epoch_key(), f.material.active_epoch_key());
    }
    let finished = if approver { &a } else { &j };
    assert_eq!(
        finished
            .accepted_membership_history(budget)
            .unwrap()
            .unwrap()
            .endpoint(),
        d
    );
    assert_eq!(proof(&raw), original);
    assert_eq!(
        provider
            .join_session_client("join")
            .unwrap()
            .result(invite.pairing_id, joined.request_digest, 1000)
            .unwrap(),
        provider_result
    );
    let state: String = raw
        .query_row(
            "SELECT state FROM pairing_v2_transcripts WHERE pairing_id=?1",
            [invite.pairing_id.to_string()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(state, if approver { "accepted" } else { "completed" });
    assert!(
        finished
            .trusted_workspace_material(if approver { &f.device_keys } else { &join_keys })
            .is_ok()
    );
    if !approver {
        let activation: Vec<u8> = raw
            .query_row(
                "SELECT source_hash FROM membership_current_activation",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(activation, d.state_sha256.0);
    }
}

#[test]
fn provider_only_certificate_cannot_admit_a_sync_sender() {
    let f = fixture();
    let scope = SyncScope {
        account_id: f.artifacts.record.account_id,
        workspace_id: f.artifacts.record.workspace_id,
    };
    let path = TempVault::new("provider-only-v2");
    let store = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), "provider-only", &store).unwrap();
    vault
        .prepare_recovery_enrollment(&write(&f.artifacts, 900))
        .unwrap();
    vault
        .activate_recovery_enrollment(&receipt(&f.artifacts, 950), &f.device_keys, 960)
        .unwrap();
    let remote = DeviceKeys::from_seeds_for_test([0x42; 32], [0x52; 32]);
    let certificate = DeviceCertificateV1::issue_by_device(
        CertificateFieldsV1 {
            account_id: scope.account_id,
            workspace_id: scope.workspace_id,
            control_epoch: 1,
            request_nonce: PairingRequestNonce([0x91; 32]),
            device_id: id("018f22e2-79b0-7cc8-98c4-dc0c0c073991"),
            signing_public_key: remote.signing_public_key(),
            wrapping_public_key: remote.wrapping_public_key(),
        },
        f.artifacts.record.genesis_certificate.device_id,
        &f.device_keys,
    )
    .unwrap();
    let budget = MembershipHistoryBudget {
        max_events: 20,
        max_bytes: 1_000_000,
    };
    let before = vault
        .accepted_membership_history(budget)
        .unwrap()
        .unwrap()
        .endpoint();
    let snapshot = context_relay_core::sync::DeviceCertificateSnapshot::from_certificates_for_test(
        scope,
        vec![f.artifacts.record.genesis_certificate, certificate],
    );
    assert!(
        vault
            .trusted_sync_material_with_certificates(&f.device_keys, &snapshot)
            .is_err()
    );
    assert_eq!(
        vault
            .accepted_membership_history(budget)
            .unwrap()
            .unwrap()
            .endpoint(),
        before
    );
    assert_eq!(vault.all_devices().unwrap().len(), 1);
}
