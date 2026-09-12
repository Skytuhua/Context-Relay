use context_relay_core::{
    crypto::{CertificateFieldsV1, DeviceCertificateV1, DeviceKeys, RecoveryKeys, RecoveryPhrase},
    devices::{
        crypto::{PairingConfirmationError, PairingKeyBundle, SignedPairingRequest, control_v2::*},
        revocation_crypto::{
            DeviceRevocationStatementV1, RevocationControlState, RevocationTransitionV1,
        },
    },
    sync::SyncScope,
};
use context_relay_protocol::{NativePlatform, PairingRequestNonce, Sha256Digest};
use std::collections::BTreeMap;
fn id<T: std::str::FromStr>(n: u8) -> T {
    format!("018f22e2-79b0-7cc8-98c4-dc0c0c0739{n:02x}")
        .parse()
        .ok()
        .unwrap()
}
fn fields(keys: &DeviceKeys, n: u8, epoch: u32) -> CertificateFieldsV1 {
    CertificateFieldsV1 {
        account_id: id(1),
        workspace_id: id(2),
        control_epoch: epoch,
        request_nonce: PairingRequestNonce([n; 32]),
        device_id: id(n),
        signing_public_key: keys.signing_public_key(),
        wrapping_public_key: keys.wrapping_public_key(),
    }
}
#[test]
fn retained_child_opens_current_keys_after_actual_revocation_and_rejects_substitutions() {
    let a = DeviceKeys::from_seeds_for_test([1; 32], [2; 32]);
    let b = DeviceKeys::from_seeds_for_test([3; 32], [4; 32]);
    let c = DeviceKeys::from_seeds_for_test([5; 32], [6; 32]);
    let recovery =
        RecoveryKeys::derive(&RecoveryPhrase::from_entropy_for_test([7; 32]).unwrap()).unwrap();
    let a_cert = DeviceCertificateV1::issue_genesis(fields(&a, 3, 1), &recovery).unwrap();
    let b_cert = DeviceCertificateV1::issue_by_device(fields(&b, 4, 1), id(3), &a).unwrap();
    let scope = SyncScope {
        account_id: id(1),
        workspace_id: id(2),
    };
    // The bounded primitive takes an already authenticated A -> B predecessor.
    let roster = BTreeMap::from([(id(3), a_cert), (id(4), b_cert.clone())]);
    let previous = RevocationControlState {
        scope,
        control_epoch: 1,
        key_epoch: 1,
        state_sha256: Sha256Digest([8; 32]),
        active_devices: &roster,
        recovery_root_id: id(9),
        recovery_wrapping_public_key: recovery.wrapping_public_key(),
    };
    let genesis_parent = PairingParentV2 {
        state: RevocationControlState {
            scope,
            control_epoch: 1,
            key_epoch: 1,
            state_sha256: previous.state_sha256,
            active_devices: &roster,
            recovery_root_id: previous.recovery_root_id,
            recovery_wrapping_public_key: previous.recovery_wrapping_public_key,
        },
        issuer_certificate_id: id(11),
        enrollment_record_sha256: Sha256Digest([10; 32]),
        latest_rotation: None,
    };
    let genesis_request =
        SignedPairingRequest::build(id(12), id(5), "C", NativePlatform::Windows, &c).unwrap();
    // Genesis has no public initial-plaintext commitment: authenticated approver
    // assertion is the explicit limit, and an admitted child can make it.
    let initial = PairingKeyBundle::new(scope, 1, 1, [21; 32], [22; 32])
        .unwrap()
        .with_enrollment_record_sha256(Sha256Digest([10; 32]))
        .unwrap();
    let initial_approval = build_pairing_approval_v2(
        &genesis_request,
        &genesis_parent,
        id(4),
        &b,
        id(13),
        "B",
        NativePlatform::Windows,
        &initial,
    )
    .unwrap();
    let initial_opened = confirm_and_open_pairing_approval_v2(
        &encode_pairing_approved_payload_v2(&initial_approval.payload).unwrap(),
        initial_approval.safety_number.as_str(),
        &genesis_request,
        &c,
        &genesis_parent,
    )
    .unwrap();
    assert_eq!(initial_opened.key_bundle().workspace_root_key(), &[21; 32]);
    let statement = DeviceRevocationStatementV1 {
        schema_version: 1,
        revocation_id: id(10),
        account_id: id(1),
        workspace_id: id(2),
        issuer_device_id: id(4),
        target_device_id: id(3),
        control_epoch: 1,
        key_epoch: 1,
        cutoff_sequence: 1,
        cutoff_hash: Sha256Digest([9; 32]),
        transition_sha256: Sha256Digest([1; 32]),
    };
    let (statement, transition, signature) =
        RevocationTransitionV1::build(statement, &b, &previous).unwrap();
    let verified = transition
        .verify_and_advance(&statement, signature, &previous)
        .unwrap();
    let pin = Sha256Digest([10; 32]);
    let bundle = transition
        .open_device_material(&statement, signature, &previous, id(4), &b)
        .unwrap()
        .with_enrollment_record_sha256(pin)
        .unwrap();
    assert_eq!(verified.state().active_devices.get(&id(4)), Some(&b_cert));
    assert!(!verified.state().active_devices.contains_key(&id(3)));
    let parent = PairingParentV2 {
        state: verified.state(),
        issuer_certificate_id: id(11),
        enrollment_record_sha256: pin,
        latest_rotation: Some((&verified, &transition)),
    };
    let request =
        SignedPairingRequest::build(id(12), id(5), "C", NativePlatform::Windows, &c).unwrap();
    let built = build_pairing_approval_v2(
        &request,
        &parent,
        id(4),
        &b,
        id(13),
        "B",
        NativePlatform::Windows,
        &bundle,
    )
    .unwrap();
    assert_eq!(built.payload.issuer_certificate.control_epoch, 1);
    assert_eq!(built.payload.grant.certificate.control_epoch, 2);
    assert!(format!("{:?}", built.payload).contains("certificates_and_envelope: \"[REDACTED]\""));
    let canonical = encode_pairing_approved_payload_v2(&built.payload).unwrap();
    let opened = confirm_and_open_pairing_approval_v2(
        &canonical,
        built.safety_number.as_str(),
        &request,
        &c,
        &parent,
    )
    .unwrap();
    assert_eq!(
        opened.key_bundle().workspace_root_key(),
        bundle.workspace_root_key()
    );
    assert_eq!(
        opened.key_bundle().active_epoch_key(),
        bundle.active_epoch_key()
    );
    assert!(matches!(
        confirm_and_open_pairing_approval_v2(
            &canonical,
            "0000-0000-0000-0000-0000",
            &request,
            &c,
            &parent
        ),
        Err(PairingConfirmationError::SafetyNumberMismatch)
    ));
    assert!(
        build_pairing_approval_v2(
            &request,
            &parent,
            id(3),
            &a,
            id(13),
            "A",
            NativePlatform::Windows,
            &bundle
        )
        .is_err()
    );
    let stale = PairingKeyBundle::new(scope, 2, 2, [1; 32], [2; 32])
        .unwrap()
        .with_enrollment_record_sha256(pin)
        .unwrap();
    assert!(
        build_pairing_approval_v2(
            &request,
            &parent,
            id(4),
            &b,
            id(13),
            "B",
            NativePlatform::Windows,
            &stale
        )
        .is_err()
    );
    let unpinned = PairingKeyBundle::new(
        scope,
        2,
        2,
        *bundle.workspace_root_key(),
        *bundle.active_epoch_key(),
    )
    .unwrap();
    assert!(
        build_pairing_approval_v2(
            &request,
            &parent,
            id(4),
            &b,
            id(13),
            "B",
            NativePlatform::Windows,
            &unpinned
        )
        .is_err()
    );
    for mutate in [
        |p: &mut PairingApprovedPayloadV2| p.previous_state_sha256.0[0] ^= 1,
        |p: &mut PairingApprovedPayloadV2| p.enrollment_record_sha256.0[0] ^= 1,
        |p: &mut PairingApprovedPayloadV2| p.issuer_certificate_id = id(14),
        |p: &mut PairingApprovedPayloadV2| p.issuer_certificate.signature.0[0] ^= 1,
        |p: &mut PairingApprovedPayloadV2| p.grant.request_digest.0[0] ^= 1,
        |p: &mut PairingApprovedPayloadV2| p.grant.certificate.account_id = id(14),
        |p: &mut PairingApprovedPayloadV2| p.grant.certificate.control_epoch = 1,
        |p: &mut PairingApprovedPayloadV2| p.grant.key_epoch = 1,
    ] {
        let mut changed = built.payload.clone();
        mutate(&mut changed);
        let bytes = encode_pairing_approved_payload_v2(&changed).unwrap();
        assert!(inspect_pairing_approval_v2(&bytes, &request, &parent).is_err());
        assert!(
            confirm_and_open_pairing_approval_v2(
                &bytes,
                built.safety_number.as_str(),
                &request,
                &c,
                &parent
            )
            .is_err()
        );
    }
    let mut changed = built.payload.clone();
    changed.grant.wrapped_key_bundle.ciphertext[0] ^= 1;
    assert!(
        confirm_and_open_pairing_approval_v2(
            &encode_pairing_approved_payload_v2(&changed).unwrap(),
            built.safety_number.as_str(),
            &request,
            &c,
            &parent
        )
        .is_err()
    );
    // A malicious authorized approver can encrypt any plaintext and display its
    // matching number. Confirmation must still reject stale relabelled keys and
    // unpinned plaintext after decrypting, not only at the honest builder.
    for (root, epoch, pinned) in [
        ([1; 32], [2; 32], true),
        (
            *bundle.workspace_root_key(),
            *bundle.active_epoch_key(),
            false,
        ),
    ] {
        let mut payload = built.payload.clone();
        let plain = bundle_plaintext(scope, 2, 2, root, epoch, pinned.then_some(pin));
        let aad = independent_aad(&payload);
        payload.grant.wrapped_key_bundle =
            context_relay_core::crypto::wrap_secret(c.wrapping_public_key(), &plain, &aad).unwrap();
        let bytes = encode_pairing_approved_payload_v2(&payload).unwrap();
        assert!(inspect_pairing_approval_v2(&bytes, &request, &parent).is_ok());
        let safety = independent_safety(&payload, &bytes);
        assert!(matches!(
            confirm_and_open_pairing_approval_v2(&bytes, &safety, &request, &c, &parent),
            Err(PairingConfirmationError::Crypto(_))
        ));
    }
    let wrong_wrap = DeviceKeys::from_seeds_for_test([3; 32], [99; 32]);
    assert!(
        build_pairing_approval_v2(
            &request,
            &parent,
            id(4),
            &wrong_wrap,
            id(13),
            "B",
            NativePlatform::Windows,
            &bundle
        )
        .is_err()
    );
    assert!(
        confirm_and_open_pairing_approval_v2(
            &canonical,
            built.safety_number.as_str(),
            &request,
            &b,
            &parent
        )
        .is_err()
    );
    // A raw substituted transition cannot manufacture a verified commitment.
    let mut forged_transition = transition.clone();
    forged_transition.key_material_sha256.0[0] ^= 1;
    let forged_parent = PairingParentV2 {
        state: verified.state(),
        issuer_certificate_id: id(11),
        enrollment_record_sha256: pin,
        latest_rotation: Some((&verified, &forged_transition)),
    };
    assert!(
        confirm_and_open_pairing_approval_v2(
            &canonical,
            built.safety_number.as_str(),
            &request,
            &c,
            &forged_parent
        )
        .is_err()
    );
    let missing_rotation = PairingParentV2 {
        latest_rotation: None,
        ..parent
    };
    assert!(
        confirm_and_open_pairing_approval_v2(
            &canonical,
            built.safety_number.as_str(),
            &request,
            &c,
            &missing_rotation
        )
        .is_err()
    );
}
#[test]
fn v2_rejects_v1_before_interpretation() {
    assert!(decode_pairing_grant_v2(&[0xa7, 0, 1]).is_err());
}

fn bundle_plaintext(
    scope: SyncScope,
    control: u32,
    epoch: u32,
    root: [u8; 32],
    active: [u8; 32],
    pin: Option<Sha256Digest>,
) -> Vec<u8> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.map(if pin.is_some() { 8 } else { 7 })
        .unwrap()
        .u8(0)
        .unwrap()
        .u8(if pin.is_some() { 2 } else { 1 })
        .unwrap();
    e.u8(1).unwrap().bytes(scope.account_id.as_bytes()).unwrap();
    e.u8(2)
        .unwrap()
        .bytes(scope.workspace_id.as_bytes())
        .unwrap();
    e.u8(3)
        .unwrap()
        .u32(control)
        .unwrap()
        .u8(4)
        .unwrap()
        .u32(epoch)
        .unwrap();
    e.u8(5)
        .unwrap()
        .bytes(&root)
        .unwrap()
        .u8(6)
        .unwrap()
        .bytes(&active)
        .unwrap();
    if let Some(pin) = pin {
        e.u8(7).unwrap().bytes(&pin.0).unwrap();
    }
    e.into_writer()
}
fn independent_safety(p: &PairingApprovedPayloadV2, bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"context-relay/pairing-safety/v2\0");
    h.update(p.grant.pairing_id.as_bytes());
    h.update(p.grant.request_digest.0);
    h.update(Sha256::digest(bytes));
    h.finalize()[..10]
        .chunks_exact(2)
        .map(|g| format!("{:02X}{:02X}", g[0], g[1]))
        .collect::<Vec<_>>()
        .join("-")
}
fn independent_aad(p: &PairingApprovedPayloadV2) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    // Extract exact canonical embedded certificate maps without relying on the
    // production AAD helper or duplicating certificate serialization.
    fn cert_bytes(input: &[u8], preceding_values: usize) -> &[u8] {
        let mut d = minicbor::Decoder::new(input);
        d.map().unwrap();
        for _ in 0..preceding_values {
            d.skip().unwrap();
        }
        let start = d.position();
        d.skip().unwrap();
        &input[start..d.position()]
    }
    let grant = encode_pairing_grant_v2(&p.grant).unwrap();
    let payload = encode_pairing_approved_payload_v2(p).unwrap();
    let mut a = b"context-relay/pairing-grant-aad/v2\0".to_vec();
    a.extend_from_slice(p.grant.pairing_id.as_bytes());
    a.extend_from_slice(&p.grant.request_digest.0);
    a.extend_from_slice(p.grant.certificate_id.as_bytes());
    a.extend_from_slice(&Sha256::digest(cert_bytes(&grant, 9)));
    a.extend_from_slice(p.grant.certificate.account_id.as_bytes());
    a.extend_from_slice(p.grant.certificate.workspace_id.as_bytes());
    a.extend_from_slice(&p.grant.certificate.control_epoch.to_be_bytes());
    a.extend_from_slice(&p.grant.key_epoch.to_be_bytes());
    a.extend_from_slice(&p.previous_state_sha256.0);
    a.extend_from_slice(&p.enrollment_record_sha256.0);
    a.extend_from_slice(p.issuer_certificate_id.as_bytes());
    a.extend_from_slice(&Sha256::digest(cert_bytes(&payload, 7)));
    a
}
