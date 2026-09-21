use context_relay_core::{
    crypto::{CertificateFieldsV1, DeviceCertificateV1, DeviceKeys, RecoveryKeys, RecoveryPhrase},
    devices::{
        crypto::{PairingKeyBundle, SignedPairingRequest, control_v2::*},
        membership_crypto::*,
        recovery_crypto::{RecoveryEnrollmentBuildRequest, build_recovery_enrollment_artifacts},
        revocation_crypto::{
            DeviceRevocationStatementV1, RevocationControlState, RevocationTransitionV1,
            initial_revocation_control_state,
        },
    },
    sync::SyncScope,
};
use context_relay_protocol::{DeviceId, NativePlatform, PairingRequestNonce, Sha256Digest};

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
fn id<T: std::str::FromStr>(n: u8) -> T {
    format!("018f22e2-79b0-7cc8-98c4-dc0c0c0739{n:02x}")
        .parse()
        .ok()
        .unwrap()
}
fn fields(keys: &DeviceKeys, n: u8) -> CertificateFieldsV1 {
    CertificateFieldsV1 {
        account_id: id(1),
        workspace_id: id(2),
        control_epoch: 1,
        request_nonce: PairingRequestNonce([n; 32]),
        device_id: id(n),
        signing_public_key: keys.signing_public_key(),
        wrapping_public_key: keys.wrapping_public_key(),
    }
}
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn endpoint(s: &RevocationControlState<'_>) -> MembershipEndpoint {
    MembershipEndpoint {
        state_sha256: s.state_sha256,
        control_epoch: s.control_epoch,
        key_epoch: s.key_epoch,
    }
}
fn statement(p: &PairingApprovedPayloadV2) -> DeviceMembershipAddStatementV1 {
    DeviceMembershipAddStatementV1::from_approved_payload_v2(
        &encode_pairing_approved_payload_v2(p).unwrap(),
    )
    .unwrap()
}
#[test]
fn independent_fixed_width_signature_and_successor_vector() {
    let f: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/device-membership-add-v1.json")).unwrap();
    let bytes = hex(f["preimage"].as_str().unwrap());
    assert_eq!(
        bytes.len(),
        b"context-relay/device-membership-add/v1\0".len() + 186
    );
    let s = DeviceMembershipAddStatementV1::from_signing_preimage(&bytes).unwrap();
    assert_eq!(s.signing_preimage().unwrap(), bytes);
    assert_eq!(s.membership_id, id(10));
    assert_eq!(s.issuer_device_id, id(3));
    assert_eq!(s.certificate_id, id(11));
    assert_eq!(s.schema_version, 1);
    assert_eq!(s.account_id, id(1));
    assert_eq!(s.workspace_id, id(2));
    assert_eq!((s.control_epoch, s.key_epoch), (2, 2));
    assert_eq!(s.certificate_sha256, Sha256Digest([0xb1; 32]));
    assert_eq!(s.authorization_artifact_sha256, Sha256Digest([0xc1; 32]));
    assert_eq!(s.previous_state_sha256, Sha256Digest([0xa1; 32]));
    let keys = DeviceKeys::from_seeds_for_test([1; 32], [2; 32]);
    let root =
        RecoveryKeys::derive(&RecoveryPhrase::from_entropy_for_test([7; 32]).unwrap()).unwrap();
    let cert = DeviceCertificateV1::issue_genesis(fields(&keys, 3), &root).unwrap();
    let signature = s.sign(&cert, &keys).unwrap();
    assert_eq!(
        signature.0.as_slice(),
        hex(f["signature"].as_str().unwrap())
    );
    assert_eq!(
        s.control_state_sha256(signature).unwrap().0.as_slice(),
        hex(f["state_sha256"].as_str().unwrap())
    );
    for end in 0..bytes.len() {
        assert!(DeviceMembershipAddStatementV1::from_signing_preimage(&bytes[..end]).is_err());
    }
    let domain = b"context-relay/device-membership-add/v1\0".len();
    let mut cases = vec![];
    let mut v = bytes.clone();
    v.push(0);
    cases.push(v);
    let mut v = bytes.clone();
    v[0] ^= 1;
    cases.push(v);
    let mut v = bytes.clone();
    v[domain + 1] = 2;
    cases.push(v);
    for offset in [2, 18, 34, 90, 106] {
        let mut v = bytes.clone();
        v[domain + offset..domain + offset + 16].fill(0);
        cases.push(v);
    }
    for (offset, len) in [(50, 32), (82, 4), (86, 4), (122, 32), (154, 32)] {
        let mut v = bytes.clone();
        v[domain + offset..domain + offset + len].fill(0);
        cases.push(v);
    }
    for v in cases {
        assert!(DeviceMembershipAddStatementV1::from_signing_preimage(&v).is_err());
    }
    let mut maximum = s;
    maximum.control_epoch = u32::MAX;
    maximum.key_epoch = u32::MAX;
    assert!(maximum.signing_preimage().is_ok()); // adds impose no lifetime epoch limit
}

#[test]
fn complete_root_only_history_retained_issuer_and_adversarial_evidence() {
    let a = DeviceKeys::from_seeds_for_test([1; 32], [2; 32]);
    let b = DeviceKeys::from_seeds_for_test([3; 32], [4; 32]);
    let c = DeviceKeys::from_seeds_for_test([5; 32], [6; 32]);
    let recovery =
        RecoveryKeys::derive(&RecoveryPhrase::from_entropy_for_test([7; 32]).unwrap()).unwrap();
    let scope = SyncScope {
        account_id: id(1),
        workspace_id: id(2),
    };
    let a_cert = DeviceCertificateV1::issue_genesis(fields(&a, 3), &recovery).unwrap();
    let initial = PairingKeyBundle::new(scope, 1, 1, [21; 32], [22; 32]).unwrap();
    let enrollment = build_recovery_enrollment_artifacts(RecoveryEnrollmentBuildRequest {
        enrollment_id: id(6),
        recovery_root_id: id(7),
        certificate_id: id(8),
        certificate: a_cert.clone(),
        device_name: "A".into(),
        device_platform: NativePlatform::Windows,
        recovery_keys: &recovery,
        device_keys: &a,
        material: &initial,
    })
    .unwrap();
    let pin = enrollment.canonical_record_sha256;
    let initial = initial.with_enrollment_record_sha256(pin).unwrap();
    let roster = BTreeMap::from([(id(3), a_cert.clone())]);
    let genesis =
        initial_revocation_control_state(&enrollment.record, pin, scope, &roster).unwrap();
    let generous = MembershipHistoryBudget {
        max_events: 20,
        max_bytes: 1_000_000,
    };
    let replay = |events: &[MembershipHistoryEvent<'_>], tip| {
        verify_membership_history(
            &enrollment.canonical_record,
            pin,
            scope,
            events,
            tip,
            generous,
        )
    };
    let genesis_proof = replay(&[], endpoint(&genesis)).unwrap();
    assert_eq!(genesis_proof.admissions().len(), 1);
    let req_b =
        SignedPairingRequest::build(id(10), id(4), "B", NativePlatform::Windows, &b).unwrap();
    let parent = genesis_proof.pairing_parent(id(3)).unwrap();
    let add_b = build_pairing_approval_v2(
        &req_b,
        &parent,
        id(3),
        &a,
        id(11),
        "A",
        NativePlatform::Windows,
        &initial,
    )
    .unwrap();
    let payload_b = encode_pairing_approved_payload_v2(&add_b.payload).unwrap();
    let s_b = statement(&add_b.payload);
    let sig_b = s_b.sign(&a_cert, &a).unwrap();
    let bytes_b = s_b.signing_preimage().unwrap();
    let after_b = s_b
        .verify_and_advance(sig_b, &req_b, &payload_b, &parent)
        .unwrap();
    let event_b = || MembershipHistoryEvent::PairingAdd {
        statement: &bytes_b,
        signature: sig_b,
        request: &req_b,
        approved_payload: &payload_b,
    };
    let proof_b = replay(&[event_b()], endpoint(&after_b.state())).unwrap();
    assert!(proof_b.latest_rotation_predecessor().is_none());
    let rotation = DeviceRevocationStatementV1 {
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
    };
    let (rotation, transition, sig_r) =
        RevocationTransitionV1::build(rotation, &b, &proof_b.state()).unwrap();
    let r_bytes = rotation.signing_preimage().unwrap();
    let t_bytes = transition.canonical_bytes().unwrap();
    let event_r = || MembershipHistoryEvent::Revocation {
        statement: &r_bytes,
        signature: sig_r,
        transition: &t_bytes,
    };
    let rotated = transition
        .verify_and_advance(&rotation, sig_r, &proof_b.state())
        .unwrap();
    let rotated_tip = endpoint(&rotated.state());
    let proof_r = replay(&[event_b(), event_r()], rotated_tip).unwrap();
    assert!(proof_r.pairing_parent(id(3)).is_err());
    assert_eq!(
        proof_r.state().active_devices.get(&id(4)),
        Some(&add_b.payload.grant.certificate)
    );
    let current = transition
        .open_device_material(&rotation, sig_r, &proof_b.state(), id(4), &b)
        .unwrap()
        .with_enrollment_record_sha256(pin)
        .unwrap();
    let req_c =
        SignedPairingRequest::build(id(13), id(5), "C", NativePlatform::Windows, &c).unwrap();
    let parent_r = proof_r.pairing_parent(id(4)).unwrap();
    let add_c = build_pairing_approval_v2(
        &req_c,
        &parent_r,
        id(4),
        &b,
        id(14),
        "B",
        NativePlatform::Windows,
        &current,
    )
    .unwrap();
    let payload_c = encode_pairing_approved_payload_v2(&add_c.payload).unwrap();
    let s_c = statement(&add_c.payload);
    let sig_c = s_c.sign(&add_b.payload.grant.certificate, &b).unwrap();
    let bytes_c = s_c.signing_preimage().unwrap();
    let after_c = s_c
        .verify_and_advance(sig_c, &req_c, &payload_c, &parent_r)
        .unwrap();
    let tip = endpoint(&after_c.state());
    let event_c = || MembershipHistoryEvent::PairingAdd {
        statement: &bytes_c,
        signature: sig_c,
        request: &req_c,
        approved_payload: &payload_c,
    };
    let proof = replay(&[event_b(), event_r(), event_c()], tip).unwrap();
    assert_eq!(proof.admissions().len(), 3);
    assert_eq!(proof.state().active_devices.len(), 2);
    assert_eq!(
        proof.state().active_devices.get(&id(4)),
        Some(&add_b.payload.grant.certificate)
    );
    assert_eq!(proof.state().control_epoch, 2);
    assert!(
        proof
            .pairing_parent(id(4))
            .unwrap()
            .latest_rotation
            .is_some()
    );
    let opened = confirm_and_open_pairing_approval_v2(
        &payload_c,
        add_c.safety_number.as_str(),
        &req_c,
        &c,
        &parent_r,
    )
    .unwrap();
    assert_eq!(
        opened.key_bundle().active_epoch_key(),
        current.active_epoch_key()
    );
    let confirmed =
        confirm_pairing_transcript_v2(&payload_c, add_c.safety_number.as_str(), &req_c).unwrap();
    let staged =
        open_confirmed_pairing_approval_v2(&confirmed, &req_c, &c, &proof_r, &after_c).unwrap();
    assert_eq!(
        staged.key_bundle().active_epoch_key(),
        current.active_epoch_key()
    );
    // Exact endpoints reject old prefixes, missing edges, reordering and forks.
    assert!(replay(&[event_b()], tip).is_err());
    assert!(replay(&[event_r(), event_c()], tip).is_err());
    assert!(replay(&[event_b(), event_c()], tip).is_err());
    assert!(replay(&[event_b(), event_c(), event_r()], tip).is_err());
    assert!(replay(&[event_b(), event_b()], endpoint(&after_b.state())).is_err());
    let mut fork_payload = add_c.payload.clone();
    fork_payload.issuer_device_name = "Other authorized branch".into();
    let fork_payload = encode_pairing_approved_payload_v2(&fork_payload).unwrap();
    let fork = DeviceMembershipAddStatementV1::from_approved_payload_v2(&fork_payload).unwrap();
    let fork_sig = fork.sign(&add_b.payload.grant.certificate, &b).unwrap();
    let fork_bytes = fork.signing_preimage().unwrap();
    let fork_tip = endpoint(
        &fork
            .verify_and_advance(fork_sig, &req_c, &fork_payload, &parent_r)
            .unwrap()
            .state(),
    );
    let fork_event = MembershipHistoryEvent::PairingAdd {
        statement: &fork_bytes,
        signature: fork_sig,
        request: &req_c,
        approved_payload: &fork_payload,
    };
    assert!(replay(&[event_b(), event_r(), fork_event], fork_tip).is_ok());
    assert!(replay(&[event_b(), event_r(), event_c()], fork_tip).is_err());
    // Lineage authenticates the one independently accepted anchor on this exact branch.
    let lineage = |events: &[MembershipHistoryEvent<'_>], anchor, end, budget| {
        verify_membership_lineage(
            &enrollment.canonical_record,
            pin,
            scope,
            events,
            anchor,
            end,
            budget,
        )
    };
    let empty = lineage(&[], endpoint(&genesis), endpoint(&genesis), generous).unwrap();
    assert!(empty.rotated_key_commitments().is_empty()); // genesis has no public key digest
    let second_rotation = DeviceRevocationStatementV1 {
        revocation_id: id(17),
        target_device_id: id(5),
        control_epoch: 2,
        key_epoch: 2,
        ..rotation.clone()
    };
    let (second_rotation, second_transition, second_sig) =
        RevocationTransitionV1::build(second_rotation, &b, &proof.state()).unwrap();
    let second_bytes = second_rotation.signing_preimage().unwrap();
    let second_transition_bytes = second_transition.canonical_bytes().unwrap();
    let second_tip = endpoint(
        &second_transition
            .verify_and_advance(&second_rotation, second_sig, &proof.state())
            .unwrap()
            .state(),
    );
    let second_event = || MembershipHistoryEvent::Revocation {
        statement: &second_bytes,
        signature: second_sig,
        transition: &second_transition_bytes,
    };
    let events = [event_b(), event_r(), event_c(), second_event()];
    for anchor in [
        endpoint(&genesis),
        endpoint(&after_b.state()),
        rotated_tip,
        tip,
        second_tip,
    ] {
        let verified = lineage(&events, anchor, second_tip, generous).unwrap();
        assert_eq!(verified.anchor(), anchor);
        assert_eq!(verified.history().endpoint(), second_tip);
        assert_eq!(verified.history().admissions(), proof.admissions());
        let commitments = verified.rotated_key_commitments();
        assert_eq!(commitments.len(), 2);
        assert_eq!(
            commitments
                .iter()
                .map(|c| (c.control_epoch(), c.key_epoch()))
                .collect::<Vec<_>>(),
            vec![(2, 2), (3, 3)]
        );
        for (commitment, transition) in commitments.iter().zip([&transition, &second_transition]) {
            assert_eq!(commitment.control_epoch(), transition.control_epoch);
            assert_eq!(commitment.key_epoch(), transition.key_epoch);
            assert_eq!(
                commitment.key_material_sha256(),
                transition.key_material_sha256
            );
        }
        // The latest envelope opens against its authenticated predecessor, not its successor.
        let parent = verified.history().pairing_parent(id(4)).unwrap();
        assert_eq!(parent.latest_rotation.unwrap().1, &second_transition);
        let predecessor = verified.history().latest_rotation_predecessor().unwrap();
        assert_eq!(endpoint(&predecessor), tip);
        let material = second_transition
            .open_device_material(&second_rotation, second_sig, &predecessor, id(4), &b)
            .unwrap();
        assert_eq!(material.key_epoch(), 3);
        assert!(
            second_transition
                .open_device_material(
                    &second_rotation,
                    second_sig,
                    &verified.history().state(),
                    id(4),
                    &b
                )
                .is_err()
        );
        assert!(
            second_transition
                .open_device_material(&second_rotation, second_sig, &predecessor, id(5), &c)
                .is_err()
        );
    }
    let after_add = lineage(&events[..3], tip, tip, generous).unwrap();
    let predecessor = after_add.history().latest_rotation_predecessor().unwrap();
    assert_eq!(endpoint(&predecessor), endpoint(&proof_b.state()));
    let retained = transition
        .open_device_material(&rotation, sig_r, &predecessor, id(4), &b)
        .unwrap();
    assert_eq!(retained.active_epoch_key(), current.active_epoch_key());
    assert_eq!(after_add.rotated_key_commitments().len(), 1);
    assert_eq!(
        after_add.rotated_key_commitments()[0].key_material_sha256(),
        transition.key_material_sha256
    );
    // A valid same-epoch fork endpoint is not an ancestor of this independently accepted tip.
    assert_eq!(
        (fork_tip.control_epoch, fork_tip.key_epoch),
        (tip.control_epoch, tip.key_epoch)
    );
    for anchor in [
        fork_tip,
        MembershipEndpoint {
            control_epoch: tip.control_epoch + 1,
            ..tip
        },
        MembershipEndpoint {
            key_epoch: tip.key_epoch + 1,
            ..tip
        },
        MembershipEndpoint {
            state_sha256: Sha256Digest([99; 32]),
            ..tip
        },
    ] {
        assert!(lineage(&events, anchor, second_tip, generous).is_err());
    }
    // Finding the anchor does not accept a truncated prefix or invalid later evidence.
    assert!(lineage(&events[..3], tip, second_tip, generous).is_err());
    assert!(lineage(&events, tip, tip, generous).is_err());
    let mut bad_rotation_sig = second_sig;
    bad_rotation_sig.0[0] ^= 1;
    assert!(
        lineage(
            &[
                event_b(),
                event_r(),
                event_c(),
                MembershipHistoryEvent::Revocation {
                    statement: &second_bytes,
                    signature: bad_rotation_sig,
                    transition: &second_transition_bytes,
                }
            ],
            tip,
            second_tip,
            generous
        )
        .is_err()
    );
    let mut bad_add_sig = sig_c;
    bad_add_sig.0[0] ^= 1;
    assert!(
        lineage(
            &[
                event_b(),
                event_r(),
                MembershipHistoryEvent::PairingAdd {
                    statement: &bytes_c,
                    signature: bad_add_sig,
                    request: &req_c,
                    approved_payload: &payload_c,
                },
                second_event()
            ],
            tip,
            second_tip,
            generous
        )
        .is_err()
    );
    let exact_bytes = enrollment.canonical_record.len()
        + bytes_b.len()
        + 64
        + req_b.canonical_bytes().len()
        + payload_b.len()
        + r_bytes.len()
        + 64
        + t_bytes.len()
        + bytes_c.len()
        + 64
        + req_c.canonical_bytes().len()
        + payload_c.len()
        + second_bytes.len()
        + 64
        + second_transition_bytes.len();
    let exact_budget = MembershipHistoryBudget {
        max_events: events.len(),
        max_bytes: exact_bytes,
    };
    assert!(lineage(&events, tip, second_tip, exact_budget).is_ok());
    for budget in [
        MembershipHistoryBudget {
            max_events: events.len() - 1,
            ..exact_budget
        },
        MembershipHistoryBudget {
            max_bytes: exact_bytes - 1,
            ..exact_budget
        },
    ] {
        assert!(lineage(&events, tip, second_tip, budget).is_err());
    }
    // This explicitly cannot discover a withheld newer tail beyond an independently old pin.
    assert!(replay(&[event_b()], endpoint(&after_b.state())).is_ok());
    assert!(
        verify_membership_history(
            &enrollment.canonical_record,
            Sha256Digest([99; 32]),
            scope,
            &[event_b()],
            tip,
            generous
        )
        .is_err()
    );
    assert!(
        verify_membership_history(
            &enrollment.canonical_record,
            pin,
            SyncScope {
                account_id: id(99),
                ..scope
            },
            &[],
            endpoint(&genesis),
            generous
        )
        .is_err()
    );
    for budget in [
        MembershipHistoryBudget {
            max_events: 2,
            ..generous
        },
        MembershipHistoryBudget {
            max_bytes: enrollment.canonical_record.len(),
            ..generous
        },
    ] {
        assert!(
            verify_membership_history(
                &enrollment.canonical_record,
                pin,
                scope,
                &[event_b(), event_r(), event_c()],
                tip,
                budget
            )
            .is_err()
        );
    }
    // Every substituted statement field is newly signed, testing binding checks independently of signatures.
    let mut altered = vec![];
    let mut s = s_c.clone();
    s.account_id = id(90);
    altered.push(s);
    let mut s = s_c.clone();
    s.previous_state_sha256 = genesis.state_sha256;
    altered.push(s);
    let mut s = s_c.clone();
    s.membership_id = id(90);
    altered.push(s);
    let mut s = s_c.clone();
    s.certificate_id = id(90);
    altered.push(s);
    let mut s = s_c.clone();
    s.certificate_sha256 = Sha256Digest([90; 32]);
    altered.push(s);
    let mut s = s_c.clone();
    s.authorization_artifact_sha256 = Sha256Digest([90; 32]);
    altered.push(s);
    let mut s = s_c.clone();
    s.key_epoch = 1;
    altered.push(s);
    let mut s = s_c.clone();
    s.control_epoch = 1;
    altered.push(s);
    for s in altered {
        // Signing proposed evidence alone grants no trust to a supplied certificate.
        let mut supplied_issuer = add_b.payload.grant.certificate.clone();
        supplied_issuer.account_id = s.account_id;
        let sig = s.sign(&supplied_issuer, &b).unwrap();
        assert!(
            s.verify_and_advance(sig, &req_c, &payload_c, &parent_r)
                .is_err()
        );
    }
    let mut bad_sig = sig_c;
    bad_sig.0[0] ^= 1;
    assert!(
        s_c.verify_and_advance(bad_sig, &req_c, &payload_c, &parent_r)
            .is_err()
    );
    assert!(
        s_c.verify_and_advance(sig_c, &req_b, &payload_c, &parent_r)
            .is_err()
    );
    let mut changed = add_c.payload.clone();
    changed.issuer_certificate_id = id(90);
    let changed = encode_pairing_approved_payload_v2(&changed).unwrap();
    assert!(
        s_c.verify_and_advance(sig_c, &req_c, &changed, &parent_r)
            .is_err()
    );
    // Cross-kind event-ID collision remains invalid with a valid fresh revocation signature.
    let mut collision = rotation.clone();
    collision.revocation_id = s_b.membership_id;
    let (collision, ct, cs) =
        RevocationTransitionV1::build(collision, &b, &proof_b.state()).unwrap();
    let cb = collision.signing_preimage().unwrap();
    let ctb = ct.canonical_bytes().unwrap();
    let ce = MembershipHistoryEvent::Revocation {
        statement: &cb,
        signature: cs,
        transition: &ctb,
    };
    let ct_tip = endpoint(
        &ct.verify_and_advance(&collision, cs, &proof_b.state())
            .unwrap()
            .state(),
    );
    assert!(replay(&[event_b(), ce], ct_tip).is_err());
    // Even a newly supplied hash cannot make tampered enrollment signatures valid.
    let mut forged_enrollment = enrollment.canonical_record.clone();
    *forged_enrollment.last_mut().unwrap() ^= 1;
    assert!(
        verify_membership_history(
            &forged_enrollment,
            Sha256Digest(Sha256::digest(&forged_enrollment).into()),
            scope,
            &[],
            endpoint(&genesis),
            generous
        )
        .is_err()
    );
    // A revoked author can still create signatures, but cannot authorize a child.
    let mut inactive_payload = add_c.payload.clone();
    inactive_payload.issuer_certificate = a_cert.clone();
    inactive_payload.issuer_certificate_id = id(8);
    let r = req_c.request();
    inactive_payload.grant.certificate = DeviceCertificateV1::issue_by_device(
        CertificateFieldsV1 {
            account_id: scope.account_id,
            workspace_id: scope.workspace_id,
            control_epoch: 2,
            request_nonce: r.request_nonce,
            device_id: r.device_id,
            signing_public_key: r.signing_public_key,
            wrapping_public_key: r.wrapping_public_key,
        },
        id(3),
        &a,
    )
    .unwrap();
    let raw = encode_pairing_approved_payload_v2(&inactive_payload).unwrap();
    let s = DeviceMembershipAddStatementV1::from_approved_payload_v2(&raw).unwrap();
    let sig = s.sign(&a_cert, &a).unwrap();
    let bytes = s.signing_preimage().unwrap();
    let inactive_event = MembershipHistoryEvent::PairingAdd {
        statement: &bytes,
        signature: sig,
        request: &req_c,
        approved_payload: &raw,
    };
    assert!(
        replay(
            &[event_b(), event_r(), inactive_event],
            MembershipEndpoint {
                state_sha256: s.control_state_sha256(sig).unwrap(),
                ..tip
            }
        )
        .is_err()
    );
    // A later same-epoch add uses the retained latest rotation and the exact new parent.
    let req_d =
        SignedPairingRequest::build(id(15), id(9), "D", NativePlatform::Windows, &a).unwrap();
    let parent_c = proof.pairing_parent(id(4)).unwrap();
    let add_d = build_pairing_approval_v2(
        &req_d,
        &parent_c,
        id(4),
        &b,
        id(16),
        "B",
        NativePlatform::Windows,
        &current,
    )
    .unwrap();
    let raw_d = encode_pairing_approved_payload_v2(&add_d.payload).unwrap();
    let s_d = statement(&add_d.payload);
    let sig_d = s_d.sign(&add_b.payload.grant.certificate, &b).unwrap();
    let bytes_d = s_d.signing_preimage().unwrap();
    let next_d = s_d
        .verify_and_advance(sig_d, &req_d, &raw_d, &parent_c)
        .unwrap();
    let event_d = MembershipHistoryEvent::PairingAdd {
        statement: &bytes_d,
        signature: sig_d,
        request: &req_d,
        approved_payload: &raw_d,
    };
    let proof_d = replay(
        &[event_b(), event_r(), event_c(), event_d],
        endpoint(&next_d.state()),
    )
    .unwrap();
    assert_eq!(proof_d.endpoint().control_epoch, tip.control_epoch);
    assert_eq!(proof_d.endpoint().key_epoch, tip.key_epoch);
    assert_ne!(proof_d.endpoint().state_sha256, tip.state_sha256);
    // Reusing retired genesis device/certificate IDs is not a first admission.
    for (pairing_id, device, cert_id) in [
        (id(91), id::<DeviceId>(3), id(90)),
        (id(91), id(90), id(8)),
        (id(91), id(90), id(11)),
        (id(10), id(90), id(92)), // prior membership operation
        (id(12), id(90), id(92)), // prior revocation operation
    ] {
        let request =
            SignedPairingRequest::build(pairing_id, device, "reused", NativePlatform::Windows, &a)
                .unwrap();
        let built = build_pairing_approval_v2(
            &request,
            &parent_r,
            id(4),
            &b,
            cert_id,
            "B",
            NativePlatform::Windows,
            &current,
        );
        if cert_id == id(11) {
            assert!(built.is_err());
            continue;
        }
        let built = built.unwrap();
        let raw = encode_pairing_approved_payload_v2(&built.payload).unwrap();
        let s = statement(&built.payload);
        let sig = s.sign(&add_b.payload.grant.certificate, &b).unwrap();
        let bytes = s.signing_preimage().unwrap();
        let successor = s
            .verify_and_advance(sig, &request, &raw, &parent_r)
            .unwrap();
        let confirmed =
            confirm_pairing_transcript_v2(&raw, built.safety_number.as_str(), &request).unwrap();
        assert!(
            open_confirmed_pairing_approval_v2(&confirmed, &request, &a, &proof_r, &successor)
                .is_err()
        );

        let event = MembershipHistoryEvent::PairingAdd {
            statement: &bytes,
            signature: sig,
            request: &request,
            approved_payload: &raw,
        };
        assert!(replay(&[event_b(), event_r(), event], endpoint(&successor.state())).is_err());
    }
}
