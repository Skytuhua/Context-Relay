use std::str::FromStr;

use context_relay_core::{
    crypto::{
        CertificateFieldsV1, CryptoError, DeviceCertificateV1, DeviceKeys, RecoveryKeys,
        RecoveryPhrase, WrappedKeyEnvelope,
    },
    devices::crypto::{
        MAX_PAIRING_APPROVED_PAYLOAD_BYTES, MAX_PAIRING_GRANT_BYTES,
        MAX_PAIRING_ISSUER_DEVICE_NAME_BYTES, PAIRING_APPROVED_PAYLOAD_SCHEMA_VERSION,
        PAIRING_GRANT_SCHEMA_VERSION, PairingApprovedPayloadV1, PairingConfirmationError,
        PairingGrant, PairingGrantApproval, PairingKeyBundle, SignedPairingRequest,
        build_pairing_approved_payload_v1, build_pairing_grant, confirm_and_open_pairing_approval,
        decode_pairing_approved_payload_v1, decode_pairing_grant_v1,
        encode_pairing_approved_payload_v1, encode_pairing_grant_v1, inspect_pairing_approval,
        pairing_request_fingerprint, verify_pairing_request,
    },
    sync::SyncScope,
};
use context_relay_protocol::{
    Ed25519PublicKeyBytes, Ed25519SignatureBytes, NativePlatform, PairingRequestNonce,
    RecoveryPhraseWords, Sha256Digest, X25519PublicKeyBytes, XChaChaNonce,
};
use sha2::{Digest, Sha256};

const ACCOUNT_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07398f";
const WORKSPACE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07398e";
const PAIRING_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07398d";
const JOINER_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07398c";
const ISSUER_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07398b";
const CERTIFICATE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07398a";
const ISSUER_CERTIFICATE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073987";
const _: () = assert!(MAX_PAIRING_APPROVED_PAYLOAD_BYTES > MAX_PAIRING_GRANT_BYTES);

#[test]
fn signed_pairing_requests_verify_exact_fields_and_separate_algorithms() {
    let keys = DeviceKeys::generate().unwrap();
    let signed = signed_request(&keys);

    let verified = verify_pairing_request(signed.request()).unwrap();
    assert_eq!(verified.digest(), signed.digest());
    assert_eq!(verified.canonical_bytes(), signed.canonical_bytes());
    keys.verify_pairing_request(signed.request()).unwrap();

    let mut mutations = Vec::new();
    let mut request = signed.request().clone();
    request.schema_version += 1;
    mutations.push(request);
    let mut request = signed.request().clone();
    request.pairing_id = id(ACCOUNT_ID);
    mutations.push(request);
    let mut request = signed.request().clone();
    request.request_nonce.0[0] ^= 1;
    mutations.push(request);
    let mut request = signed.request().clone();
    request.device_id = id(ISSUER_ID);
    mutations.push(request);
    let mut request = signed.request().clone();
    request.device_name.push('!');
    mutations.push(request);
    let mut request = signed.request().clone();
    request.platform = NativePlatform::Windows;
    mutations.push(request);
    let mut request = signed.request().clone();
    request.signing_public_key.0[0] ^= 1;
    mutations.push(request);
    let mut request = signed.request().clone();
    request.wrapping_public_key.0[0] ^= 1;
    mutations.push(request);
    let mut request = signed.request().clone();
    request.signature.0[0] ^= 1;
    mutations.push(request);
    for request in mutations {
        assert!(verify_pairing_request(&request).is_err());
    }

    let wrong_signer = DeviceKeys::generate().unwrap();
    assert_eq!(
        wrong_signer
            .verify_pairing_request(signed.request())
            .unwrap_err(),
        CryptoError::AuthenticationFailed
    );

    let mut same_bytes_in_both_algorithms = signed.request().clone();
    same_bytes_in_both_algorithms.wrapping_public_key =
        X25519PublicKeyBytes(same_bytes_in_both_algorithms.signing_public_key.0);
    assert_eq!(
        keys.sign_pairing_request(&mut same_bytes_in_both_algorithms)
            .unwrap_err(),
        CryptoError::InvalidKey
    );

    for low_order in [
        X25519PublicKeyBytes([0; 32]),
        X25519PublicKeyBytes({
            let mut one = [0; 32];
            one[0] = 1;
            one
        }),
    ] {
        let mut request = signed.request().clone();
        request.wrapping_public_key = low_order;
        assert_eq!(
            verify_pairing_request(&request).unwrap_err(),
            CryptoError::InvalidKey
        );
    }

    let direct = pairing_request_fingerprint(signed.request());
    let mut swapped = signed.request().clone();
    let signing = swapped.signing_public_key.0;
    swapped.signing_public_key = Ed25519PublicKeyBytes(swapped.wrapping_public_key.0);
    swapped.wrapping_public_key = X25519PublicKeyBytes(signing);
    assert_ne!(direct, pairing_request_fingerprint(&swapped));
}

#[test]
fn pairing_grant_round_trips_and_opens_only_for_the_exact_request_and_approval() {
    let issuer_keys = DeviceKeys::generate().unwrap();
    let issuer_certificate = issuer_certificate(&issuer_keys);
    let joiner = DeviceKeys::generate().unwrap();
    let signed = signed_request(&joiner);
    let bundle = key_bundle();
    let approval = approval(&signed, issuer_certificate.clone());

    let grant = build_pairing_grant(&signed, &approval, &issuer_keys, &bundle).unwrap();
    let encoded = encode_pairing_grant_v1(&grant).unwrap();
    assert_eq!(decode_pairing_grant_v1(&encoded).unwrap(), grant);
    assert_eq!(encode_pairing_grant_v1(&grant).unwrap(), encoded);

    let approved = build_pairing_approved_payload_v1(
        &signed,
        grant.clone(),
        id(ISSUER_CERTIFICATE_ID),
        issuer_certificate.clone(),
        "Desktop",
        NativePlatform::Macos,
    )
    .unwrap();
    let canonical = encode_pairing_approved_payload_v1(&approved).unwrap();
    let inspected = inspect_pairing_approval(&canonical, &signed).unwrap();
    let safety_number = inspected.safety_number().as_str().to_owned();
    let opened =
        confirm_and_open_pairing_approval(&inspected, &safety_number, &signed, &joiner).unwrap();
    assert_eq!(opened.key_bundle().account_id(), bundle.account_id());
    assert_eq!(opened.key_bundle().workspace_id(), bundle.workspace_id());
    assert_eq!(opened.key_bundle().control_epoch(), 7);
    assert_eq!(opened.key_bundle().key_epoch(), 11);
    assert_eq!(opened.key_bundle().workspace_root_key(), &[0xa7; 32]);
    assert_eq!(opened.key_bundle().active_epoch_key(), &[0xb8; 32]);
    assert_eq!(opened.canonical_bytes(), canonical);
    assert_eq!(opened.transcript_digest(), inspected.transcript_digest());

    let wrong_joiner = DeviceKeys::generate().unwrap();
    assert_eq!(
        confirm_and_open_pairing_approval(&inspected, &safety_number, &signed, &wrong_joiner,)
            .unwrap_err(),
        PairingConfirmationError::Crypto(CryptoError::AuthenticationFailed)
    );

    let wrong_wrapping_key = DeviceKeys::generate().unwrap();
    let mut wrong_wrapping_request = signed.request().clone();
    wrong_wrapping_request.wrapping_public_key = wrong_wrapping_key.wrapping_public_key();
    joiner
        .sign_pairing_request(&mut wrong_wrapping_request)
        .unwrap();
    let wrong_wrapping_request = verify_pairing_request(&wrong_wrapping_request).unwrap();
    assert!(inspect_pairing_approval(&canonical, &wrong_wrapping_request).is_err());
}

#[test]
fn grant_build_rejects_changed_digest_scope_epoch_issuer_or_private_key() {
    let issuer_keys = DeviceKeys::generate().unwrap();
    let issuer_certificate = issuer_certificate(&issuer_keys);
    let joiner = DeviceKeys::generate().unwrap();
    let signed = signed_request(&joiner);
    let bundle = key_bundle();
    let grant_approval = approval(&signed, issuer_certificate.clone());

    let mut changed = grant_approval.clone();
    changed.request_digest.0[0] ^= 1;
    assert!(build_pairing_grant(&signed, &changed, &issuer_keys, &bundle).is_err());

    let mut changed = grant_approval.clone();
    changed.scope.account_id = id(WORKSPACE_ID);
    assert!(build_pairing_grant(&signed, &changed, &issuer_keys, &bundle).is_err());

    let mut changed = grant_approval.clone();
    changed.control_epoch += 1;
    assert!(build_pairing_grant(&signed, &changed, &issuer_keys, &bundle).is_err());

    let mut changed = grant_approval.clone();
    changed.issuer_certificate.workspace_id = id(ACCOUNT_ID);
    assert!(build_pairing_grant(&signed, &changed, &issuer_keys, &bundle).is_err());

    let wrong_issuer_keys = DeviceKeys::generate().unwrap();
    assert!(build_pairing_grant(&signed, &grant_approval, &wrong_issuer_keys, &bundle).is_err());

    let parent_keys = DeviceKeys::generate().unwrap();
    let non_genesis_issuer = DeviceCertificateV1::issue_by_device(
        CertificateFieldsV1 {
            account_id: id(ACCOUNT_ID),
            workspace_id: id(WORKSPACE_ID),
            control_epoch: 7,
            request_nonce: PairingRequestNonce([0x34; 32]),
            device_id: id(ISSUER_ID),
            signing_public_key: issuer_keys.signing_public_key(),
            wrapping_public_key: issuer_keys.wrapping_public_key(),
        },
        id(ACCOUNT_ID),
        &parent_keys,
    )
    .unwrap();
    assert!(
        build_pairing_grant(
            &signed,
            &approval(&signed, non_genesis_issuer),
            &issuer_keys,
            &bundle,
        )
        .is_err()
    );
}

#[test]
fn opening_rejects_every_changed_binding_and_envelope_component() {
    let issuer_keys = DeviceKeys::generate().unwrap();
    let issuer_certificate = issuer_certificate(&issuer_keys);
    let joiner = DeviceKeys::generate().unwrap();
    let signed = signed_request(&joiner);
    let grant = build_pairing_grant(
        &signed,
        &approval(&signed, issuer_certificate.clone()),
        &issuer_keys,
        &key_bundle(),
    )
    .unwrap();

    let mut mutations = Vec::new();
    let mut changed = grant.clone();
    changed.pairing_id = id(ACCOUNT_ID);
    mutations.push(changed);
    let mut changed = grant.clone();
    changed.request_digest.0[0] ^= 1;
    mutations.push(changed);
    let mut changed = grant.clone();
    changed.certificate.account_id = id(WORKSPACE_ID);
    mutations.push(changed);
    let mut changed = grant.clone();
    changed.certificate.workspace_id = id(ACCOUNT_ID);
    mutations.push(changed);
    let mut changed = grant.clone();
    changed.certificate.control_epoch += 1;
    mutations.push(changed);
    let mut changed = grant.clone();
    changed.certificate.request_nonce.0[0] ^= 1;
    mutations.push(changed);
    let mut changed = grant.clone();
    changed.certificate.device_id = id(ISSUER_ID);
    mutations.push(changed);
    let mut changed = grant.clone();
    changed.certificate.signing_public_key.0[0] ^= 1;
    mutations.push(changed);
    let mut changed = grant.clone();
    changed.certificate.wrapping_public_key.0[0] ^= 1;
    mutations.push(changed);
    let mut changed = grant.clone();
    changed.certificate.signature.0[0] ^= 1;
    mutations.push(changed);
    let mut changed = grant.clone();
    match &mut changed.certificate.issuer {
        context_relay_core::crypto::CertificateIssuerV1::Device { device_id, .. } => {
            *device_id = id(JOINER_ID);
        }
        context_relay_core::crypto::CertificateIssuerV1::RecoveryRoot(_) => unreachable!(),
    }
    mutations.push(changed);
    for changed in mutations {
        let payload = PairingApprovedPayloadV1 {
            schema_version: PAIRING_APPROVED_PAYLOAD_SCHEMA_VERSION,
            grant: changed,
            issuer_certificate_id: id(ISSUER_CERTIFICATE_ID),
            issuer_certificate: issuer_certificate.clone(),
            issuer_device_name: "Desktop".to_owned(),
            issuer_platform: NativePlatform::Macos,
        };
        let canonical = encode_pairing_approved_payload_v1(&payload).unwrap();
        assert!(inspect_pairing_approval(&canonical, &signed).is_err());
    }

    let direct_payload = PairingApprovedPayloadV1 {
        schema_version: PAIRING_APPROVED_PAYLOAD_SCHEMA_VERSION,
        grant: grant.clone(),
        issuer_certificate_id: id(ISSUER_CERTIFICATE_ID),
        issuer_certificate: issuer_certificate.clone(),
        issuer_device_name: "Desktop".to_owned(),
        issuer_platform: NativePlatform::Macos,
    };
    let direct = inspect_pairing_approval(
        &encode_pairing_approved_payload_v1(&direct_payload).unwrap(),
        &signed,
    )
    .unwrap();
    let mut sealed_mutations = Vec::new();
    let mut changed = grant.clone();
    changed.certificate_id = id(ACCOUNT_ID);
    sealed_mutations.push(changed);
    let mut changed = grant.clone();
    changed.key_epoch += 1;
    sealed_mutations.push(changed);
    let mut changed = grant.clone();
    changed.wrapped_key_bundle.ephemeral_public_key.0[0] ^= 1;
    sealed_mutations.push(changed);
    let mut changed = grant.clone();
    changed.wrapped_key_bundle.nonce.0[0] ^= 1;
    sealed_mutations.push(changed);
    let mut changed = grant.clone();
    changed.wrapped_key_bundle.ciphertext[0] ^= 1;
    sealed_mutations.push(changed);

    for changed in sealed_mutations {
        let payload = PairingApprovedPayloadV1 {
            grant: changed,
            ..direct_payload.clone()
        };
        let inspected = inspect_pairing_approval(
            &encode_pairing_approved_payload_v1(&payload).unwrap(),
            &signed,
        )
        .unwrap();
        assert_ne!(direct.safety_number(), inspected.safety_number());
        let expected = inspected.safety_number().as_str().to_owned();
        assert!(matches!(
            confirm_and_open_pairing_approval(&inspected, &expected, &signed, &joiner),
            Err(PairingConfirmationError::Crypto(_))
        ));
    }

    let mut wrong_issuer = issuer_certificate.clone();
    wrong_issuer.device_id = id(JOINER_ID);
    let payload = PairingApprovedPayloadV1 {
        schema_version: PAIRING_APPROVED_PAYLOAD_SCHEMA_VERSION,
        grant,
        issuer_certificate_id: id(ISSUER_CERTIFICATE_ID),
        issuer_certificate: wrong_issuer,
        issuer_device_name: "Desktop".to_owned(),
        issuer_platform: NativePlatform::Macos,
    };
    assert!(
        inspect_pairing_approval(
            &encode_pairing_approved_payload_v1(&payload).unwrap(),
            &signed,
        )
        .is_err()
    );
}

#[test]
fn approved_payload_codec_is_canonical_bounded_and_frozen() {
    let payload = public_approved_payload_fixture();
    let bytes = encode_pairing_approved_payload_v1(&payload).unwrap();
    assert_eq!(hex(&bytes), approved_payload_fixture_hex());
    assert_eq!(decode_pairing_approved_payload_v1(&bytes).unwrap(), payload);
    assert_eq!(encode_pairing_approved_payload_v1(&payload).unwrap(), bytes);

    let mut wrong_map_size = bytes.clone();
    wrong_map_size[0] = 0xa3;
    assert!(decode_pairing_approved_payload_v1(&wrong_map_size).is_err());
    let mut wrong_first_key = bytes.clone();
    wrong_first_key[1] = 1;
    assert!(decode_pairing_approved_payload_v1(&wrong_first_key).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(decode_pairing_approved_payload_v1(&trailing).is_err());
    let mut noncanonical_schema = bytes;
    noncanonical_schema.splice(2..3, [0x18, 0x01]);
    assert!(decode_pairing_approved_payload_v1(&noncanonical_schema).is_err());
    assert!(
        decode_pairing_approved_payload_v1(&vec![0; MAX_PAIRING_APPROVED_PAYLOAD_BYTES + 1])
            .is_err()
    );

    let mut empty_name = payload.clone();
    empty_name.issuer_device_name.clear();
    assert!(encode_pairing_approved_payload_v1(&empty_name).is_err());
    let mut oversized_name = payload;
    oversized_name.issuer_device_name = "x".repeat(MAX_PAIRING_ISSUER_DEVICE_NAME_BYTES + 1);
    assert!(encode_pairing_approved_payload_v1(&oversized_name).is_err());
}

#[test]
fn inspection_verifies_genesis_and_child_bindings_without_opening_keys() {
    let issuer_keys = DeviceKeys::generate().unwrap();
    let issuer_certificate = issuer_certificate(&issuer_keys);
    let joiner = DeviceKeys::generate().unwrap();
    let signed = signed_request(&joiner);
    let grant = build_pairing_grant(
        &signed,
        &approval(&signed, issuer_certificate.clone()),
        &issuer_keys,
        &key_bundle(),
    )
    .unwrap();
    let approved = build_pairing_approved_payload_v1(
        &signed,
        grant,
        id(ISSUER_CERTIFICATE_ID),
        issuer_certificate,
        "Desktop",
        NativePlatform::Macos,
    )
    .unwrap();
    let canonical = encode_pairing_approved_payload_v1(&approved).unwrap();
    let inspected = inspect_pairing_approval(&canonical, &signed).unwrap();

    assert_eq!(inspected.canonical_bytes(), canonical);
    assert_eq!(inspected.approved_payload(), &approved);
    assert_eq!(
        inspected.transcript_digest(),
        expected_transcript_digest(&signed, &canonical)
    );
    assert_eq!(
        inspected.safety_number().as_str(),
        expected_safety_number(inspected.transcript_digest())
    );
    assert_eq!(inspected.safety_number().as_str().len(), 24);
    assert_eq!(
        inspected
            .safety_number()
            .as_str()
            .bytes()
            .filter(|byte| *byte == b'-')
            .count(),
        4
    );

    let debug = format!("{inspected:?} {:?}", inspected.safety_number());
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains(inspected.safety_number().as_str()));
    assert!(!debug.contains(&hex(&canonical)));
}

#[test]
fn confirmation_compares_the_complete_safety_number_before_unwrap() {
    let issuer_keys = DeviceKeys::generate().unwrap();
    let issuer_certificate = issuer_certificate(&issuer_keys);
    let joiner = DeviceKeys::generate().unwrap();
    let signed = signed_request(&joiner);
    let mut grant = build_pairing_grant(
        &signed,
        &approval(&signed, issuer_certificate.clone()),
        &issuer_keys,
        &key_bundle(),
    )
    .unwrap();
    grant.wrapped_key_bundle.ciphertext[0] ^= 1;
    let payload = PairingApprovedPayloadV1 {
        schema_version: PAIRING_APPROVED_PAYLOAD_SCHEMA_VERSION,
        grant,
        issuer_certificate_id: id(ISSUER_CERTIFICATE_ID),
        issuer_certificate,
        issuer_device_name: "Desktop".to_owned(),
        issuer_platform: NativePlatform::Macos,
    };
    let canonical = encode_pairing_approved_payload_v1(&payload).unwrap();
    let inspected = inspect_pairing_approval(&canonical, &signed).unwrap();
    let expected = inspected.safety_number().as_str().to_owned();
    let truncated = &expected[..expected.len() - 1];
    let lowercase = expected.to_ascii_lowercase();

    for wrong in ["0000-0000-0000-0000-0000", truncated, lowercase.as_str()] {
        assert_eq!(
            confirm_and_open_pairing_approval(&inspected, wrong, &signed, &joiner).unwrap_err(),
            PairingConfirmationError::SafetyNumberMismatch
        );
    }
    assert_eq!(
        confirm_and_open_pairing_approval(&inspected, &expected, &signed, &joiner).unwrap_err(),
        PairingConfirmationError::Crypto(CryptoError::AuthenticationFailed)
    );
}

#[test]
fn cross_pairing_and_self_consistent_malicious_approvals_have_different_safety_numbers() {
    let honest_issuer_keys = DeviceKeys::generate().unwrap();
    let honest_issuer_certificate = issuer_certificate(&honest_issuer_keys);
    let joiner = DeviceKeys::generate().unwrap();
    let signed = signed_request(&joiner);
    let honest = approved_payload(
        &signed,
        &honest_issuer_keys,
        honest_issuer_certificate,
        id(ISSUER_CERTIFICATE_ID),
    );
    let honest_canonical = encode_pairing_approved_payload_v1(&honest).unwrap();
    let honest_inspected = inspect_pairing_approval(&honest_canonical, &signed).unwrap();

    let attacker_keys = DeviceKeys::generate().unwrap();
    let attacker_recovery = RecoveryKeys::derive(&alternate_phrase()).unwrap();
    let attacker_certificate = DeviceCertificateV1::issue_genesis(
        CertificateFieldsV1 {
            account_id: id(ACCOUNT_ID),
            workspace_id: id(WORKSPACE_ID),
            control_epoch: 7,
            request_nonce: PairingRequestNonce([0x44; 32]),
            device_id: id(ISSUER_ID),
            signing_public_key: attacker_keys.signing_public_key(),
            wrapping_public_key: attacker_keys.wrapping_public_key(),
        },
        &attacker_recovery,
    )
    .unwrap();
    let malicious = approved_payload(
        &signed,
        &attacker_keys,
        attacker_certificate,
        id(ISSUER_CERTIFICATE_ID),
    );
    let malicious_canonical = encode_pairing_approved_payload_v1(&malicious).unwrap();
    let malicious_inspected = inspect_pairing_approval(&malicious_canonical, &signed).unwrap();

    assert_ne!(honest_canonical, malicious_canonical);
    assert_ne!(
        honest_inspected.safety_number(),
        malicious_inspected.safety_number()
    );
    assert_eq!(
        confirm_and_open_pairing_approval(
            &malicious_inspected,
            honest_inspected.safety_number().as_str(),
            &signed,
            &joiner,
        )
        .unwrap_err(),
        PairingConfirmationError::SafetyNumberMismatch
    );

    let other_joiner = DeviceKeys::generate().unwrap();
    let other_signed = SignedPairingRequest::build(
        id(ACCOUNT_ID),
        id(JOINER_ID),
        "Other laptop",
        NativePlatform::Windows,
        &other_joiner,
    )
    .unwrap();
    let other = approved_payload(
        &other_signed,
        &honest_issuer_keys,
        issuer_certificate(&honest_issuer_keys),
        id(ISSUER_CERTIFICATE_ID),
    );
    let other_canonical = encode_pairing_approved_payload_v1(&other).unwrap();
    let other_inspected = inspect_pairing_approval(&other_canonical, &other_signed).unwrap();
    assert_ne!(
        honest_inspected.safety_number(),
        other_inspected.safety_number()
    );
    assert_eq!(
        confirm_and_open_pairing_approval(
            &other_inspected,
            honest_inspected.safety_number().as_str(),
            &other_signed,
            &other_joiner,
        )
        .unwrap_err(),
        PairingConfirmationError::SafetyNumberMismatch
    );
}

#[test]
fn issuer_certificate_id_and_certificate_are_both_bound_into_the_transcript() {
    let issuer_keys = DeviceKeys::generate().unwrap();
    let issuer_certificate = issuer_certificate(&issuer_keys);
    let joiner = DeviceKeys::generate().unwrap();
    let signed = signed_request(&joiner);
    let approved = approved_payload(
        &signed,
        &issuer_keys,
        issuer_certificate,
        id(ISSUER_CERTIFICATE_ID),
    );
    let canonical = encode_pairing_approved_payload_v1(&approved).unwrap();
    let direct = inspect_pairing_approval(&canonical, &signed).unwrap();

    let mut changed_id = approved.clone();
    changed_id.issuer_certificate_id = id(ACCOUNT_ID);
    let changed_id = inspect_pairing_approval(
        &encode_pairing_approved_payload_v1(&changed_id).unwrap(),
        &signed,
    )
    .unwrap();
    assert_ne!(direct.safety_number(), changed_id.safety_number());

    let mut changed_name = approved.clone();
    changed_name.issuer_device_name = "Changed desktop".to_owned();
    let changed_name = inspect_pairing_approval(
        &encode_pairing_approved_payload_v1(&changed_name).unwrap(),
        &signed,
    )
    .unwrap();
    assert_ne!(direct.safety_number(), changed_name.safety_number());

    let mut changed_platform = approved.clone();
    changed_platform.issuer_platform = NativePlatform::Windows;
    let changed_platform = inspect_pairing_approval(
        &encode_pairing_approved_payload_v1(&changed_platform).unwrap(),
        &signed,
    )
    .unwrap();
    assert_ne!(direct.safety_number(), changed_platform.safety_number());

    let mut changed_certificate = approved;
    changed_certificate.issuer_certificate.request_nonce.0[0] ^= 1;
    assert!(
        inspect_pairing_approval(
            &encode_pairing_approved_payload_v1(&changed_certificate).unwrap(),
            &signed,
        )
        .is_err()
    );
}

#[test]
fn grant_codec_matches_fixture_and_rejects_structural_changes() {
    let grant = public_grant_fixture();
    let bytes = encode_pairing_grant_v1(&grant).unwrap();
    assert_eq!(
        hex(&bytes),
        include_str!("fixtures/pairing-grant-v1.hex").trim()
    );
    assert_eq!(decode_pairing_grant_v1(&bytes).unwrap(), grant);

    let mut wrong_map_size = bytes.clone();
    wrong_map_size[0] = 0xa6;
    assert!(decode_pairing_grant_v1(&wrong_map_size).is_err());
    let mut wrong_first_key = bytes.clone();
    wrong_first_key[1] = 1;
    assert!(decode_pairing_grant_v1(&wrong_first_key).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(decode_pairing_grant_v1(&trailing).is_err());
    let mut noncanonical_schema = bytes;
    noncanonical_schema.splice(2..3, [0x18, 0x01]);
    assert!(decode_pairing_grant_v1(&noncanonical_schema).is_err());
}

#[test]
fn pairing_debug_output_redacts_signatures_envelopes_and_plaintext_keys() {
    let issuer_keys = DeviceKeys::generate().unwrap();
    let issuer_certificate = issuer_certificate(&issuer_keys);
    let joiner = DeviceKeys::generate().unwrap();
    let signed = signed_request(&joiner);
    let bundle = key_bundle();
    let grant = build_pairing_grant(
        &signed,
        &approval(&signed, issuer_certificate),
        &issuer_keys,
        &bundle,
    )
    .unwrap();

    let signed_debug = format!("{signed:?}");
    assert!(signed_debug.contains("[REDACTED]"));
    assert!(!signed_debug.contains(&format!("{:?}", signed.request().signature.0)));

    let bundle_debug = format!("{bundle:?}");
    assert!(bundle_debug.contains("[REDACTED]"));
    assert!(!bundle_debug.contains("167, 167, 167"));
    assert!(!bundle_debug.contains("184, 184, 184"));

    let grant_debug = format!("{grant:?}");
    assert!(grant_debug.contains("[REDACTED]"));
    assert!(!grant_debug.contains(&format!("{:?}", grant.wrapped_key_bundle.ciphertext)));
}

fn signed_request(keys: &DeviceKeys) -> SignedPairingRequest {
    SignedPairingRequest::build(
        id(PAIRING_ID),
        id(JOINER_ID),
        "Laptop",
        NativePlatform::Macos,
        keys,
    )
    .unwrap()
}

fn scope() -> SyncScope {
    SyncScope {
        account_id: id(ACCOUNT_ID),
        workspace_id: id(WORKSPACE_ID),
    }
}

fn key_bundle() -> PairingKeyBundle {
    PairingKeyBundle::new(scope(), 7, 11, [0xa7; 32], [0xb8; 32]).unwrap()
}

fn approval(
    signed: &SignedPairingRequest,
    issuer_certificate: DeviceCertificateV1,
) -> PairingGrantApproval {
    PairingGrantApproval {
        request_digest: signed.digest(),
        certificate_id: id(CERTIFICATE_ID),
        scope: scope(),
        control_epoch: 7,
        issuer_certificate,
    }
}

fn approved_payload(
    signed: &SignedPairingRequest,
    issuer_keys: &DeviceKeys,
    issuer_certificate: DeviceCertificateV1,
    issuer_certificate_id: context_relay_protocol::DeviceCertificateId,
) -> PairingApprovedPayloadV1 {
    let grant = build_pairing_grant(
        signed,
        &approval(signed, issuer_certificate.clone()),
        issuer_keys,
        &key_bundle(),
    )
    .unwrap();
    build_pairing_approved_payload_v1(
        signed,
        grant,
        issuer_certificate_id,
        issuer_certificate,
        "Desktop",
        NativePlatform::Macos,
    )
    .unwrap()
}

fn issuer_certificate(keys: &DeviceKeys) -> DeviceCertificateV1 {
    DeviceCertificateV1::issue_genesis(
        CertificateFieldsV1 {
            account_id: id(ACCOUNT_ID),
            workspace_id: id(WORKSPACE_ID),
            control_epoch: 7,
            request_nonce: PairingRequestNonce([0x33; 32]),
            device_id: id(ISSUER_ID),
            signing_public_key: keys.signing_public_key(),
            wrapping_public_key: keys.wrapping_public_key(),
        },
        &RecoveryKeys::derive(&fixed_phrase()).unwrap(),
    )
    .unwrap()
}

fn fixed_phrase() -> RecoveryPhrase {
    let mut words = vec!["abandon".to_owned(); 23];
    words.push("art".to_owned());
    RecoveryPhrase::from_words(RecoveryPhraseWords::new(words).unwrap()).unwrap()
}

fn alternate_phrase() -> RecoveryPhrase {
    let mut words = vec!["zoo".to_owned(); 23];
    words.push("vote".to_owned());
    RecoveryPhrase::from_words(RecoveryPhraseWords::new(words).unwrap()).unwrap()
}

fn public_grant_fixture() -> PairingGrant {
    PairingGrant {
        schema_version: PAIRING_GRANT_SCHEMA_VERSION,
        pairing_id: id(PAIRING_ID),
        request_digest: Sha256Digest([0x21; 32]),
        certificate_id: id(CERTIFICATE_ID),
        certificate: DeviceCertificateV1 {
            issuer: context_relay_core::crypto::CertificateIssuerV1::Device {
                device_id: id(ISSUER_ID),
                signing_public_key: Ed25519PublicKeyBytes([0x31; 32]),
            },
            account_id: id(ACCOUNT_ID),
            workspace_id: id(WORKSPACE_ID),
            control_epoch: 7,
            request_nonce: PairingRequestNonce([0x41; 32]),
            device_id: id(JOINER_ID),
            signing_public_key: Ed25519PublicKeyBytes([0x51; 32]),
            wrapping_public_key: X25519PublicKeyBytes([0x61; 32]),
            signature: Ed25519SignatureBytes([0x71; 64]),
        },
        key_epoch: 11,
        wrapped_key_bundle: WrappedKeyEnvelope {
            ephemeral_public_key: X25519PublicKeyBytes([0x81; 32]),
            nonce: XChaChaNonce([0x91; 24]),
            ciphertext: (0_u8..96).collect(),
        },
    }
}

fn public_approved_payload_fixture() -> PairingApprovedPayloadV1 {
    PairingApprovedPayloadV1 {
        schema_version: PAIRING_APPROVED_PAYLOAD_SCHEMA_VERSION,
        grant: public_grant_fixture(),
        issuer_certificate_id: id(ISSUER_CERTIFICATE_ID),
        issuer_certificate: DeviceCertificateV1 {
            issuer: context_relay_core::crypto::CertificateIssuerV1::RecoveryRoot(
                Ed25519PublicKeyBytes([0x21; 32]),
            ),
            account_id: id(ACCOUNT_ID),
            workspace_id: id(WORKSPACE_ID),
            control_epoch: 7,
            request_nonce: PairingRequestNonce([0x31; 32]),
            device_id: id(ISSUER_ID),
            signing_public_key: Ed25519PublicKeyBytes([0x41; 32]),
            wrapping_public_key: X25519PublicKeyBytes([0x51; 32]),
            signature: Ed25519SignatureBytes([0x61; 64]),
        },
        issuer_device_name: "Desktop".to_owned(),
        issuer_platform: NativePlatform::Macos,
    }
}

fn approved_payload_fixture_hex() -> String {
    concat!(
        "a6000101",
        include_str!("fixtures/pairing-grant-v1.hex"),
        "0250018f22e279b07cc898c4dc0c0c073987",
        "03a9",
        "00a20000015820",
        "2121212121212121212121212121212121212121212121212121212121212121",
        "0150018f22e279b07cc898c4dc0c0c07398f",
        "0250018f22e279b07cc898c4dc0c0c07398e",
        "0307",
        "0458203131313131313131313131313131313131313131313131313131313131313131",
        "0550018f22e279b07cc898c4dc0c0c07398b",
        "0658204141414141414141414141414141414141414141414141414141414141414141",
        "0758205151515151515151515151515151515151515151515151515151515151515151",
        "0858406161616161616161616161616161616161616161616161616161616161616161",
        "6161616161616161616161616161616161616161616161616161616161616161",
        "04674465736b746f70",
        "0501",
    )
    .replace(['\n', '\r'], "")
}

fn expected_transcript_digest(
    signed: &SignedPairingRequest,
    canonical_approved_payload: &[u8],
) -> Sha256Digest {
    let payload_digest = Sha256::digest(canonical_approved_payload);
    let mut digest = Sha256::new();
    digest.update(b"context-relay/pairing-safety/v1\0");
    digest.update(signed.request().pairing_id.as_bytes());
    digest.update(signed.digest().0);
    digest.update(payload_digest);
    Sha256Digest(digest.finalize().into())
}

fn expected_safety_number(digest: Sha256Digest) -> String {
    digest.0[..10]
        .chunks_exact(2)
        .map(|group| format!("{:02X}{:02X}", group[0], group[1]))
        .collect::<Vec<_>>()
        .join("-")
}

fn id<T: FromStr>(value: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    value.parse().unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
