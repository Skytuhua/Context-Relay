mod support;
use context_relay_core::{
    crypto::{CertificateFieldsV1, DeviceCertificateV1, DeviceKeys, RecoveryKeys, RecoveryPhrase},
    devices::{
        crypto::{PairingKeyBundle, SignedPairingRequest, control_v2::*},
        membership_crypto::*,
        recovery_crypto::{RecoveryEnrollmentBuildRequest, build_recovery_enrollment_artifacts},
        recovery_restore_crypto::{authenticate_recovery_root, v2::*},
        revocation_crypto::{DeviceRevocationStatementV1, RevocationTransitionV1},
    },
    sync::SyncScope,
};
use context_relay_protocol::{NativePlatform, PairingRequestNonce, Sha256Digest};
fn id<T: std::str::FromStr>(n: u8) -> T {
    format!("018f22e2-79b0-7cc8-98c4-dc0c0c0739{n:02x}")
        .parse()
        .ok()
        .unwrap()
}
fn raw_vault(path: &std::path::Path, key: &[u8; 32]) -> rusqlite::Connection {
    let db = rusqlite::Connection::open(path).unwrap();
    unsafe {
        assert_eq!(
            rusqlite::ffi::sqlite3_key(db.handle(), key.as_ptr().cast(), 32),
            0
        );
    }
    db
}

fn assert_schema42_rows_preserved(events: &[MembershipHistoryEvent<'_>]) {
    use rusqlite::{Connection, params, types::Value};
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch(include_str!("../migrations/0040_accepted_membership.sql"))
        .unwrap();
    for (ordinal, event) in events.iter().enumerate() {
        let object=context_relay_core::devices::membership_transport::MembershipEventObject::from_evidence(event).unwrap();
        let (parent, successor) = object.endpoints().unwrap();
        let (kind, statement, signature, request, artifact) = match event {
            MembershipHistoryEvent::PairingAdd {
                statement,
                signature,
                request,
                approved_payload,
            } => (
                1,
                *statement,
                *signature,
                request.canonical_bytes(),
                *approved_payload,
            ),
            MembershipHistoryEvent::Revocation {
                statement,
                signature,
                transition,
            } => (2, *statement, *signature, &[][..], *transition),
            _ => panic!("schema42 fixture only contains original accepted kinds"),
        };
        db.execute(
            "INSERT INTO membership_events VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                successor.0.as_slice(),
                parent.0.as_slice(),
                ordinal as i64,
                kind,
                statement,
                signature.0.as_slice(),
                request,
                artifact
            ],
        )
        .unwrap();
    }
    let snapshot = |db: &Connection| -> Vec<Vec<Value>> {
        db.prepare("SELECT * FROM membership_events ORDER BY ordinal")
            .unwrap()
            .query_map([], |row| (0..8).map(|i| row.get(i)).collect())
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    let original = snapshot(&db);
    assert_eq!(original.len(), 2);
    let migration = include_str!("../migrations/0043_recovery_membership.sql");
    db.execute_batch(&format!("BEGIN;{migration}PRAGMA user_version=43;COMMIT;"))
        .unwrap();
    assert_eq!(snapshot(&db), original);
    let malformed = Connection::open_in_memory().unwrap();
    malformed
        .execute_batch(include_str!("../migrations/0040_accepted_membership.sql"))
        .unwrap();
    for row in &original {
        malformed
            .execute(
                "INSERT INTO membership_events VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                rusqlite::params_from_iter(row),
            )
            .unwrap();
    }
    malformed
        .execute_batch(
            "UPDATE membership_events SET request=X'01' WHERE kind=2;PRAGMA user_version=42;",
        )
        .unwrap();
    let before = snapshot(&malformed);
    assert!(
        malformed
            .execute_batch(&format!("BEGIN;{migration}PRAGMA user_version=43;COMMIT;"))
            .is_err()
    );
    malformed.execute_batch("ROLLBACK;").unwrap();
    assert_eq!(snapshot(&malformed), before);
    assert_eq!(
        malformed
            .pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0))
            .unwrap(),
        42
    );
}

#[test]
fn root_recovery_uses_the_exact_verified_rotated_parent_without_a_surviving_exporter() {
    let a = DeviceKeys::from_seeds_for_test([1; 32], [2; 32]);
    let b = DeviceKeys::from_seeds_for_test([3; 32], [4; 32]);
    let recovery =
        RecoveryKeys::derive(&RecoveryPhrase::from_entropy_for_test([7; 32]).unwrap()).unwrap();
    let scope = SyncScope {
        account_id: id(1),
        workspace_id: id(2),
    };
    let cert = DeviceCertificateV1::issue_genesis(
        CertificateFieldsV1 {
            account_id: id(1),
            workspace_id: id(2),
            control_epoch: 1,
            request_nonce: PairingRequestNonce([3; 32]),
            device_id: id(3),
            signing_public_key: a.signing_public_key(),
            wrapping_public_key: a.wrapping_public_key(),
        },
        &recovery,
    )
    .unwrap();
    let material = PairingKeyBundle::new(scope, 1, 1, [21; 32], [22; 32]).unwrap();
    let enrollment = build_recovery_enrollment_artifacts(RecoveryEnrollmentBuildRequest {
        enrollment_id: id(6),
        recovery_root_id: id(7),
        certificate_id: id(8),
        certificate: cert.clone(),
        device_name: "A".into(),
        device_platform: NativePlatform::Windows,
        recovery_keys: &recovery,
        device_keys: &a,
        material: &material,
    })
    .unwrap();
    let pin = enrollment.canonical_record_sha256;
    let material = material.with_enrollment_record_sha256(pin).unwrap();
    let genesis = context_relay_core::devices::membership_transport::enrollment_endpoint(
        &enrollment.canonical_record,
        pin,
        scope,
    )
    .unwrap();
    let budget = MembershipHistoryBudget {
        max_events: 4096,
        max_bytes: 64 * 1024 * 1024,
    };
    let initial = verify_membership_history(
        &enrollment.canonical_record,
        pin,
        scope,
        &[],
        genesis,
        budget,
    )
    .unwrap();
    let request =
        SignedPairingRequest::build(id(10), id(4), "B", NativePlatform::Windows, &b).unwrap();
    let add = build_pairing_approval_v2(
        &request,
        &initial.pairing_parent(id(3)).unwrap(),
        id(3),
        &a,
        id(11),
        "A",
        NativePlatform::Windows,
        &material,
    )
    .unwrap();
    let payload = encode_pairing_approved_payload_v2(&add.payload).unwrap();
    let statement = DeviceMembershipAddStatementV1::from_approved_payload_v2(&payload).unwrap();
    let signature = statement.sign(&cert, &a).unwrap();
    let bytes = statement.signing_preimage().unwrap();
    let event = || MembershipHistoryEvent::PairingAdd {
        statement: &bytes,
        signature,
        request: &request,
        approved_payload: &payload,
    };
    let after = MembershipEndpoint {
        state_sha256: statement.control_state_sha256(signature).unwrap(),
        control_epoch: 1,
        key_epoch: 1,
    };
    let before = verify_membership_history(
        &enrollment.canonical_record,
        pin,
        scope,
        &[event()],
        after,
        budget,
    )
    .unwrap();
    let (revoke, rotation, revoke_signature) = RevocationTransitionV1::build(
        DeviceRevocationStatementV1 {
            schema_version: 1,
            revocation_id: id(12),
            account_id: id(1),
            workspace_id: id(2),
            issuer_device_id: id(4),
            target_device_id: id(3),
            control_epoch: 1,
            key_epoch: 1,
            cutoff_sequence: 0,
            cutoff_hash: Sha256Digest([0; 32]),
            transition_sha256: Sha256Digest([1; 32]),
        },
        &b,
        &before.state(),
    )
    .unwrap();
    let revoke_bytes = revoke.signing_preimage().unwrap();
    let rotation_bytes = rotation.canonical_bytes().unwrap();
    let events = [
        event(),
        MembershipHistoryEvent::Revocation {
            statement: &revoke_bytes,
            signature: revoke_signature,
            transition: &rotation_bytes,
        },
    ];
    assert_schema42_rows_preserved(&events);
    let parent = MembershipEndpoint {
        state_sha256: revoke.control_state_sha256(revoke_signature).unwrap(),
        control_epoch: 2,
        key_epoch: 2,
    };
    let history = verify_membership_history(
        &enrollment.canonical_record,
        pin,
        scope,
        &events,
        parent,
        budget,
    )
    .unwrap();
    assert_eq!(history.state().active_devices.len(), 1);
    let path = support::TempVault::new("recovery-membership-v2");
    let store = support::MemoryKeyStore::default();
    let mut vault =
        context_relay_core::vault::Vault::open(path.path(), "recovery-v2", &store).unwrap();
    vault
        .prepare_recovery_enrollment(&context_relay_core::vault::RecoveryEnrollmentWrite {
            canonical_record: enrollment.canonical_record.clone(),
            canonical_record_sha256: pin,
            device_material_envelope: enrollment.device_material_envelope.clone(),
            device_material_envelope_sha256: enrollment.device_material_envelope_sha256,
            prepared_at_ms: 1,
        })
        .unwrap();
    vault
        .activate_recovery_enrollment(
            &context_relay_core::devices::recovery_transport::RecoveryEnrollmentReceipt {
                enrollment_id: enrollment.record.enrollment_id,
                recovery_root_id: enrollment.record.recovery_root_id,
                account_id: scope.account_id,
                workspace_id: scope.workspace_id,
                genesis_certificate_id: enrollment.record.genesis_certificate_id,
                canonical_record_sha256: pin,
                registered_at_ms: 2,
            },
            &a,
            3,
        )
        .unwrap();
    vault
        .accept_membership_extension(genesis, parent, &events, budget)
        .unwrap();
    let expected = rotation
        .open_recovery_material(&revoke, revoke_signature, &before.state(), &recovery)
        .unwrap();
    drop(a);
    drop(b);
    drop(recovery); // destroyed devices are not recovery prerequisites
    let authority = authenticate_recovery_root(
        &enrollment.canonical_record,
        pin,
        RecoveryPhrase::from_entropy_for_test([7; 32]).unwrap(),
    )
    .unwrap();
    let recipient = DeviceKeys::from_seeds_for_test([31; 32], [32; 32]);
    let authority = authenticate_recovery_history(authority, &events, parent, budget).unwrap();
    let claim = build_recovery_device_claim_v2(
        &authority,
        id(20),
        0,
        id(21),
        PairingRequestNonce([22; 32]),
        id(23),
        "Recovered".into(),
        NativePlatform::Windows,
        &recipient,
    )
    .unwrap();
    assert_eq!(
        (claim.certificate.control_epoch, claim.key_epoch),
        (expected.control_epoch(), expected.key_epoch())
    );
    assert_eq!(claim.previous_state_sha256, parent.state_sha256);
    let opened = open_recovered_device_material_v2(
        &enrollment.record,
        &claim,
        authority.history(),
        &recipient,
    )
    .unwrap();
    assert_eq!(opened.workspace_root_key(), expected.workspace_root_key());
    assert_eq!(opened.active_epoch_key(), expected.active_epoch_key());
    let canonical = encode_recovery_device_claim_v2(&claim).unwrap();
    for end in 0..canonical.len() {
        assert!(decode_recovery_device_claim_v2(&canonical[..end]).is_err());
    }
    let mut trailing = canonical.clone();
    trailing.push(0);
    assert!(decode_recovery_device_claim_v2(&trailing).is_err());
    let mut old_version = canonical.clone();
    old_version[2] = 1;
    assert!(decode_recovery_device_claim_v2(&old_version).is_err());
    let mut wrong_parent = claim.clone();
    wrong_parent.previous_state_sha256.0[0] ^= 1;
    assert!(verify_recovery_device_claim_v2(&enrollment.record, &wrong_parent, &history).is_err());
    let sealed = authority.seal_historical_keys(&claim, &recipient).unwrap();
    assert_eq!(sealed.len(), 1);
    // Prepared recovery persists exact proof and sealed keys, but no accepted
    // membership, current material, certificate or provider acceptance.
    let restore_path = support::TempVault::new("recovery-prepared-v2");
    let mut restore =
        context_relay_core::vault::Vault::open(restore_path.path(), "restore-v2", &store).unwrap();
    let intent = context_relay_core::vault::HostedRestoreIntent {
        project_url: "https://recovery-test.supabase.co".into(),
        user_id: id(33),
        session_id: id(34),
    };
    restore.store_hosted_restore_intent(&intent).unwrap();
    let parent_objects = events
        .iter()
        .map(|event| {
            context_relay_core::devices::membership_transport::MembershipEventObject::from_evidence(
                event,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    restore
        .prepare_recovery_v2(
            &enrollment.canonical_record,
            &canonical,
            &parent_objects,
            &sealed,
            &recipient,
        )
        .unwrap();
    assert!(
        restore
            .accepted_membership_history(budget)
            .unwrap()
            .is_none()
    );
    assert!(
        restore
            .discard_unprepared_hosted_restore_intent(&intent)
            .is_err()
    );
    drop(restore);
    let mut restore =
        context_relay_core::vault::Vault::open(restore_path.path(), "restore-v2", &store).unwrap();
    let prepared = restore.prepared_recovery_v2(&recipient).unwrap().unwrap();
    assert_eq!(prepared.canonical_claim, canonical);
    assert_eq!(prepared.parent.endpoint(), parent);
    assert_eq!(prepared.history_keys.len(), 1);
    assert_eq!(
        restore
            .prepare_recovery_v2(
                &enrollment.canonical_record,
                &canonical,
                &parent_objects,
                &sealed,
                &recipient
            )
            .unwrap(),
        context_relay_core::vault::CommitDisposition::ExactReplay
    );
    assert!(
        restore
            .prepared_recovery_v2(&DeviceKeys::from_seeds_for_test([91; 32], [92; 32]))
            .is_err()
    );
    let raw = raw_vault(restore_path.path(), &store.key("restore-v2"));
    let saved: Vec<u8> = raw
        .query_row(
            "SELECT preparation_signature FROM recovery_v2_prepared",
            [],
            |r| r.get(0),
        )
        .unwrap();
    raw.execute(
        "UPDATE recovery_v2_prepared SET preparation_signature=zeroblob(64)",
        [],
    )
    .unwrap();
    assert!(restore.prepared_recovery_v2(&recipient).is_err());
    raw.execute(
        "UPDATE recovery_v2_prepared SET preparation_signature=?1",
        [&saved],
    )
    .unwrap();
    let intent_bytes = serde_json::to_vec(&intent).unwrap();
    let mut substituted = intent.clone();
    substituted.session_id = id(35);
    raw.execute(
        "UPDATE hosted_restore_intent SET payload=?1",
        [serde_json::to_vec(&substituted).unwrap()],
    )
    .unwrap();
    assert!(restore.prepared_recovery_v2(&recipient).is_err());
    raw.execute(
        "UPDATE hosted_restore_intent SET payload=?1",
        [intent_bytes],
    )
    .unwrap();
    drop(raw);
    let rollback_path = support::TempVault::new("recovery-prepared-rollback-v2");
    let mut rollback =
        context_relay_core::vault::Vault::open(rollback_path.path(), "rollback-v2", &store)
            .unwrap();
    let raw = raw_vault(rollback_path.path(), &store.key("rollback-v2"));
    raw.execute_batch("CREATE TRIGGER reject_retained_key BEFORE INSERT ON recovery_v2_history_keys BEGIN SELECT RAISE(ABORT,'forced preparation failure'); END;").unwrap();
    assert!(
        rollback
            .prepare_recovery_v2(
                &enrollment.canonical_record,
                &canonical,
                &parent_objects,
                &sealed,
                &recipient
            )
            .is_err()
    );
    for table in [
        "recovery_v2_prepared",
        "recovery_v2_parent_objects",
        "recovery_v2_history_keys",
    ] {
        assert_eq!(
            raw.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    drop(raw);
    drop(rollback);
    let rollback =
        context_relay_core::vault::Vault::open(rollback_path.path(), "rollback-v2", &store)
            .unwrap();
    assert!(rollback.prepared_recovery_v2(&recipient).unwrap().is_none());
    assert_eq!(canonical[0], 0xb0);
    assert_eq!(decode_recovery_device_claim_v2(&canonical).unwrap(), claim);
    assert!(
        context_relay_core::devices::recovery_restore_crypto::decode_recovery_device_claim_v1(
            &canonical
        )
        .is_err()
    );
    let mut object = b"context-relay/public-membership-event/v1\0".to_vec();
    object.push(2);
    for field in [
        &[][..],
        &claim.recovery_root_signature.0[..],
        &[][..],
        canonical.as_slice(),
    ] {
        object.extend_from_slice(&(field.len() as u32).to_be_bytes());
        object.extend_from_slice(field);
    }
    let object=context_relay_core::devices::membership_transport::MembershipEventObject::from_canonical_bytes(&object).unwrap();
    let successor = MembershipEndpoint {
        state_sha256: recovery_membership_successor(&claim).unwrap(),
        ..parent
    };
    let full = [
        event(),
        MembershipHistoryEvent::Revocation {
            statement: &revoke_bytes,
            signature: revoke_signature,
            transition: &rotation_bytes,
        },
        object.evidence(),
    ];
    let accepted = verify_membership_history(
        &enrollment.canonical_record,
        pin,
        scope,
        &full,
        successor,
        budget,
    )
    .unwrap();
    assert_eq!(accepted.admissions().len(), 3);
    assert_eq!(accepted.state().active_devices.len(), 2);
    assert!(!accepted.state().active_devices.contains_key(&id(3)));
    let lineage = verify_membership_lineage(
        &enrollment.canonical_record,
        pin,
        scope,
        &full,
        successor,
        successor,
        budget,
    )
    .unwrap();
    drop(authority); // No recovery phrase/root secret is available after this point.
    let restarted = restore.prepared_recovery_v2(&recipient).unwrap().unwrap();
    let historical = open_recovery_history_key(
        &enrollment.record,
        &claim,
        &restarted.parent,
        &lineage,
        &restarted.history_keys[0],
        &recipient,
    )
    .unwrap();
    assert_eq!(
        historical.workspace_root_key(),
        material.workspace_root_key()
    );
    assert_eq!(historical.active_epoch_key(), material.active_epoch_key());
    let mut corrupt = sealed[0].clone();
    corrupt.signature.0[0] ^= 1;
    assert!(
        open_recovery_history_key(
            &enrollment.record,
            &claim,
            &history,
            &lineage,
            &corrupt,
            &recipient
        )
        .is_err()
    );
    let mut corrupt = sealed[0].clone();
    corrupt.key_epoch = 2;
    assert!(
        open_recovery_history_key(
            &enrollment.record,
            &claim,
            &history,
            &lineage,
            &corrupt,
            &recipient
        )
        .is_err()
    );
    let mut corrupt = sealed[0].clone();
    corrupt.original_bundle_sha256.0[0] ^= 1;
    assert!(
        open_recovery_history_key(
            &enrollment.record,
            &claim,
            &history,
            &lineage,
            &corrupt,
            &recipient
        )
        .is_err()
    );
    // Anyone can wrap to a public key; only the initial root-opened private path
    // can authenticate provenance with the original recipient's signature.
    let mut replacement = sealed[0].clone();
    let mut aad = b"context-relay/recovery-history-key/v1\0".to_vec();
    use sha2::{Digest, Sha256};
    aad.extend(Sha256::digest(&canonical));
    aad.extend(1u32.to_be_bytes());
    aad.extend(replacement.original_bundle_sha256.0);
    replacement.envelope = context_relay_core::crypto::wrap_secret(
        recipient.wrapping_public_key(),
        b"forged canonical keys",
        &aad,
    )
    .unwrap();
    assert!(
        open_recovery_history_key(
            &enrollment.record,
            &claim,
            &history,
            &lineage,
            &replacement,
            &recipient
        )
        .is_err()
    );
    vault
        .accept_membership_extension(parent, successor, &[object.evidence()], budget)
        .unwrap();
    drop(vault);
    let vault = context_relay_core::vault::Vault::open(path.path(), "recovery-v2", &store).unwrap();
    assert_eq!(
        vault
            .accepted_membership_history(budget)
            .unwrap()
            .unwrap()
            .endpoint(),
        successor
    );
}
