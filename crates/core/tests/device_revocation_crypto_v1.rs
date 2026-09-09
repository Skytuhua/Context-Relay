use context_relay_core::{
    crypto::{CertificateFieldsV1, DeviceCertificateV1, DeviceKeys},
    devices::revocation_crypto::DeviceRevocationStatementV1,
};
use context_relay_protocol::{PairingRequestNonce, Sha256Digest};

fn fixture() -> (DeviceRevocationStatementV1, DeviceCertificateV1, DeviceKeys) {
    let keys = DeviceKeys::generate().unwrap();
    let statement = DeviceRevocationStatementV1 {
        schema_version: 1,
        revocation_id: "018f22e2-79b0-7cc8-98c4-dc0c0c073980".parse().unwrap(),
        account_id: "018f22e2-79b0-7cc8-98c4-dc0c0c073981".parse().unwrap(),
        workspace_id: "018f22e2-79b0-7cc8-98c4-dc0c0c073982".parse().unwrap(),
        issuer_device_id: "018f22e2-79b0-7cc8-98c4-dc0c0c073983".parse().unwrap(),
        target_device_id: "018f22e2-79b0-7cc8-98c4-dc0c0c073984".parse().unwrap(),
        control_epoch: 2,
        key_epoch: 2,
        cutoff_sequence: 7,
        cutoff_hash: Sha256Digest([7; 32]),
        transition_sha256: Sha256Digest([8; 32]),
    };
    let certificate = DeviceCertificateV1::issue_by_device(
        CertificateFieldsV1 {
            account_id: statement.account_id,
            workspace_id: statement.workspace_id,
            control_epoch: 1,
            request_nonce: PairingRequestNonce([1; 32]),
            device_id: statement.issuer_device_id,
            signing_public_key: keys.signing_public_key(),
            wrapping_public_key: keys.wrapping_public_key(),
        },
        statement.issuer_device_id,
        &keys,
    )
    .unwrap();
    (statement, certificate, keys)
}

#[test]
fn revocation_binds_scope_cutoff_epochs_and_rotation_to_installed_keys() {
    let (statement, certificate, keys) = fixture();
    let signature = statement.sign(&certificate, &keys).unwrap();
    statement.verify(&certificate, signature).unwrap();
    // Every signed byte, including domain and field boundaries, matters.
    let preimage = statement.signing_preimage().unwrap();
    assert_eq!(
        DeviceRevocationStatementV1::from_signing_preimage(&preimage).unwrap(),
        statement
    );
    for end in 0..preimage.len() {
        assert!(DeviceRevocationStatementV1::from_signing_preimage(&preimage[..end]).is_err());
    }
    let mut trailing = preimage.clone();
    trailing.push(0);
    assert!(DeviceRevocationStatementV1::from_signing_preimage(&trailing).is_err());
    // Independent Node crypto vector: Ed25519 seed [1; 32], explicit Buffer
    // concatenation with BE integer fields and raw UUIDs (no Rust encoder).
    use sha2::{Digest, Sha256};
    assert_eq!(preimage.len(), 197);
    assert_eq!(
        Sha256::digest(&preimage).as_slice(),
        hex_bytes::<32>("6810fb2551d0385609cbcd64f8ca67e8a5d27ed252766b743861f2217711e1ae")
    );
    context_relay_core::crypto::verify_signature(
        context_relay_protocol::Ed25519PublicKeyBytes(hex_bytes(
            "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
        )),
        &preimage,
        context_relay_protocol::Ed25519SignatureBytes(hex_bytes(
            "95e069a5ba7a49aa1fb1fdf06f7af9067dfa180dd9947c36ca24702101a13e45677c08f38fceb20c854fd8156c3509eca4fe1d3b178c5ca4ef22281f9aed8b0b",
        )),
    ).unwrap();
    for index in 0..preimage.len() {
        let mut changed = preimage.clone();
        changed[index] ^= 1;
        assert!(
            context_relay_core::crypto::verify_signature(
                keys.signing_public_key(),
                &changed,
                signature,
            )
            .is_err()
        );
    }
    for mutate in [
        |s: &mut DeviceRevocationStatementV1| s.schema_version = 2,
        |s: &mut DeviceRevocationStatementV1| s.control_epoch = 0,
        |s: &mut DeviceRevocationStatementV1| s.control_epoch = u32::MAX,
        |s: &mut DeviceRevocationStatementV1| s.key_epoch = 0,
        |s: &mut DeviceRevocationStatementV1| s.key_epoch = u32::MAX,
        |s: &mut DeviceRevocationStatementV1| s.cutoff_sequence = u64::MAX,
        |s: &mut DeviceRevocationStatementV1| s.cutoff_sequence = 0,
        |s: &mut DeviceRevocationStatementV1| s.cutoff_hash = Sha256Digest([0; 32]),
        |s: &mut DeviceRevocationStatementV1| s.transition_sha256 = Sha256Digest([0; 32]),
    ] {
        let mut changed = statement.clone();
        mutate(&mut changed);
        assert!(changed.sign(&certificate, &keys).is_err());
        assert!(changed.verify(&certificate, signature).is_err());
    }
    let mut wrong = certificate.clone();
    wrong.wrapping_public_key = DeviceKeys::generate().unwrap().wrapping_public_key();
    assert!(statement.sign(&wrong, &keys).is_err());
    assert!(
        statement
            .sign(&certificate, &DeviceKeys::generate().unwrap())
            .is_err()
    );
    wrong = certificate.clone();
    wrong.control_epoch = 3;
    assert!(statement.verify(&wrong, signature).is_err());
    wrong.control_epoch = 0;
    assert!(statement.verify(&wrong, signature).is_err());
    wrong = certificate.clone();
    wrong.device_id = statement.target_device_id;
    assert!(statement.sign(&wrong, &keys).is_err());
    assert!(statement.verify(&wrong, signature).is_err());
    wrong = certificate.clone();
    wrong.account_id = "018f22e2-79b0-7cc8-98c4-dc0c0c073989".parse().unwrap();
    assert!(statement.verify(&wrong, signature).is_err());
    wrong = certificate.clone();
    wrong.workspace_id = "018f22e2-79b0-7cc8-98c4-dc0c0c073989".parse().unwrap();
    assert!(statement.verify(&wrong, signature).is_err());
    let mut empty = statement.clone();
    empty.target_device_id = empty.issuer_device_id;
    empty.cutoff_sequence = 0;
    empty.cutoff_hash = Sha256Digest([0; 32]);
    empty
        .verify(&certificate, empty.sign(&certificate, &keys).unwrap())
        .unwrap();
}

fn hex_bytes<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    std::array::from_fn(|i| u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).unwrap())
}

#[test]
fn rotation_requires_exact_current_roster_epochs_recovery_and_signed_bytes() {
    use context_relay_core::{
        crypto::wrap_secret,
        devices::revocation_crypto::{
            DeviceRotationEnvelopeV1, RevocationControlState, RevocationTransitionV1,
        },
        sync::SyncScope,
    };
    use std::collections::BTreeMap;
    let (mut statement, issuer, keys) = fixture();
    let target_keys = DeviceKeys::generate().unwrap();
    let mut target = issuer.clone();
    target.device_id = statement.target_device_id;
    target.signing_public_key = target_keys.signing_public_key();
    target.wrapping_public_key = target_keys.wrapping_public_key();
    // Control-state certificates are assumed already authenticated by the caller;
    // this fixture tests exact roster equality, not certificate-chain admission.
    let active = BTreeMap::from([
        (issuer.device_id, issuer.clone()),
        (target.device_id, target.clone()),
    ]);
    let recovery = context_relay_core::crypto::RecoveryKeys::derive(
        &context_relay_core::crypto::RecoveryPhrase::generate().unwrap(),
    )
    .unwrap();
    let state = RevocationControlState {
        scope: SyncScope {
            account_id: statement.account_id,
            workspace_id: statement.workspace_id,
        },
        control_epoch: 2,
        key_epoch: 2,
        state_sha256: Sha256Digest([9; 32]),
        active_devices: &active,
        recovery_root_id: "018f22e2-79b0-7cc8-98c4-dc0c0c073985".parse().unwrap(),
        recovery_wrapping_public_key: recovery.wrapping_public_key(),
    };
    let transition = RevocationTransitionV1 {
        previous_state_sha256: state.state_sha256,
        control_epoch: 3,
        key_epoch: 3,
        key_material_sha256: Sha256Digest([10; 32]),
        devices: vec![DeviceRotationEnvelopeV1 {
            certificate: issuer.clone(),
            envelope: wrap_secret(keys.wrapping_public_key(), &[5; 64], b"rotation-test").unwrap(),
        }],
        recovery_root_id: state.recovery_root_id,
        recovery_wrapping_public_key: state.recovery_wrapping_public_key,
        recovery_envelope: wrap_secret(recovery.wrapping_public_key(), &[5; 64], b"rotation-test")
            .unwrap(),
    };
    statement.transition_sha256 = transition.digest().unwrap();
    let signature = statement.sign(&issuer, &keys).unwrap();
    transition.verify(&statement, signature, &state).unwrap();
    let wire = transition.canonical_bytes().unwrap();
    let decoded = RevocationTransitionV1::from_canonical_bytes(&wire).unwrap();
    assert_eq!(decoded, transition);
    decoded.verify(&statement, signature, &state).unwrap();
    for end in 0..wire.len() {
        assert!(RevocationTransitionV1::from_canonical_bytes(&wire[..end]).is_err());
    }
    let mut trailing = wire.clone();
    trailing.push(0);
    assert!(RevocationTransitionV1::from_canonical_bytes(&trailing).is_err());
    let count_offset = b"context-relay/device-revocation-transition/v1\0".len() + 32 + 8 + 32;
    for offset in [count_offset, count_offset + 4] {
        let mut hostile = wire.clone();
        hostile[offset..offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(RevocationTransitionV1::from_canonical_bytes(&hostile).is_err());
    }
    // The nested CBOR decoder may accept a nonminimal map length; the outer
    // boundary must reject it instead of silently changing the signed digest.
    let certificate_offset = count_offset + 8;
    let certificate_len = u32::from_be_bytes(
        wire[count_offset + 4..certificate_offset]
            .try_into()
            .unwrap(),
    );
    assert_eq!(wire[certificate_offset], 0xa9);
    let mut noncanonical = wire.clone();
    noncanonical[certificate_offset] = 0xb8;
    noncanonical.insert(certificate_offset + 1, 9);
    noncanonical[count_offset + 4..certificate_offset]
        .copy_from_slice(&(certificate_len + 1).to_be_bytes());
    assert!(RevocationTransitionV1::from_canonical_bytes(&noncanonical).is_err());
    let mut hostile = wire.clone();
    let ciphertext_len_offset = certificate_offset + certificate_len as usize + 32 + 24;
    hostile[ciphertext_len_offset..ciphertext_len_offset + 4]
        .copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(RevocationTransitionV1::from_canonical_bytes(&hostile).is_err());
    for index in 0..wire.len() {
        let mut mutated = wire.clone();
        mutated[index] ^= 0xff;
        if let Ok(parsed) = RevocationTransitionV1::from_canonical_bytes(&mutated) {
            assert_eq!(parsed.canonical_bytes().unwrap(), mutated);
            assert!(parsed.verify(&statement, signature, &state).is_err());
        }
    }
    let resign = |changed: &RevocationTransitionV1| {
        let mut s = statement.clone();
        s.transition_sha256 = changed.digest().unwrap();
        let sig = s.sign(&issuer, &keys).unwrap();
        (s, sig)
    };
    // Even an authentic issuer cannot bypass the exact current-state contract.
    for mutate in [
        |t: &mut RevocationTransitionV1| t.devices.clear(),
        |t: &mut RevocationTransitionV1| t.previous_state_sha256 = Sha256Digest([6; 32]),
        |t: &mut RevocationTransitionV1| t.control_epoch = 4,
        |t: &mut RevocationTransitionV1| t.key_epoch = 4,
        |t: &mut RevocationTransitionV1| t.devices[0].certificate.request_nonce.0[0] ^= 1,
    ] {
        let mut changed = transition.clone();
        mutate(&mut changed);
        let (s, sig) = resign(&changed);
        assert!(changed.verify(&s, sig, &state).is_err());
    }
    let mut changed = transition.clone();
    changed.devices[0].certificate = target;
    let (s, sig) = resign(&changed);
    assert!(changed.verify(&s, sig, &state).is_err());
    changed = transition.clone();
    changed.recovery_wrapping_public_key = keys.wrapping_public_key();
    let (s, sig) = resign(&changed);
    assert!(changed.verify(&s, sig, &state).is_err());
    changed = transition.clone();
    changed.devices[0].envelope.ciphertext[0] ^= 1;
    assert!(changed.verify(&statement, signature, &state).is_err());
    changed = transition.clone();
    changed.devices.push(changed.devices[0].clone());
    assert!(changed.digest().is_err());
    changed = transition.clone();
    changed.recovery_envelope.ciphertext.clear();
    assert!(changed.digest().is_err());
    changed = transition.clone();
    changed.devices[0].envelope.ephemeral_public_key.0 = [0; 32];
    assert!(changed.digest().is_err());
    changed = transition.clone();
    changed.devices[0].envelope.ciphertext.resize(1025, 0);
    assert!(changed.digest().is_err());
    changed = transition.clone();
    changed.key_material_sha256 = Sha256Digest([0; 32]);
    assert!(changed.digest().is_err());
    changed = transition.clone();
    changed.recovery_root_id = "018f22e2-79b0-7cc8-98c4-dc0c0c073989".parse().unwrap();
    let (s, sig) = resign(&changed);
    assert!(changed.verify(&s, sig, &state).is_err());
    changed = transition.clone();
    changed.recovery_envelope.ciphertext[0] ^= 1;
    assert!(changed.verify(&statement, signature, &state).is_err());
    let stale = RevocationControlState {
        control_epoch: 3,
        ..state
    };
    assert!(transition.verify(&statement, signature, &stale).is_err());
    let stale = RevocationControlState {
        key_epoch: 3,
        ..state
    };
    assert!(transition.verify(&statement, signature, &stale).is_err());
    let removed_issuer = BTreeMap::from([(
        statement.target_device_id,
        active[&statement.target_device_id].clone(),
    )]);
    let stale = RevocationControlState {
        active_devices: &removed_issuer,
        ..state
    };
    assert!(transition.verify(&statement, signature, &stale).is_err());
    // Last-device self-revocation retains a recovery envelope but no device envelope.
    let only_issuer = BTreeMap::from([(issuer.device_id, issuer.clone())]);
    let solo = RevocationControlState {
        active_devices: &only_issuer,
        ..state
    };
    let mut self_revoke = statement.clone();
    self_revoke.target_device_id = issuer.device_id;
    changed = transition.clone();
    changed.devices.clear();
    self_revoke.transition_sha256 = changed.digest().unwrap();
    let sig = self_revoke.sign(&issuer, &keys).unwrap();
    changed.verify(&self_revoke, sig, &solo).unwrap();

    let (built_statement, built, built_signature) =
        RevocationTransitionV1::build(statement.clone(), &keys, &state).unwrap();
    let from_device = built
        .open_device_material(
            &built_statement,
            built_signature,
            &state,
            issuer.device_id,
            &keys,
        )
        .unwrap();
    let from_recovery = built
        .open_recovery_material(&built_statement, built_signature, &state, &recovery)
        .unwrap();
    assert_eq!(from_device.account_id(), statement.account_id);
    assert_eq!(from_device.workspace_id(), statement.workspace_id);
    assert_eq!(
        (from_device.control_epoch(), from_device.key_epoch()),
        (3, 3)
    );
    assert_eq!(
        from_device.workspace_root_key(),
        from_recovery.workspace_root_key()
    );
    assert_eq!(
        from_device.active_epoch_key(),
        from_recovery.active_epoch_key()
    );
    assert!(
        built
            .open_device_material(
                &built_statement,
                built_signature,
                &state,
                statement.target_device_id,
                &target_keys,
            )
            .is_err()
    );
    assert!(
        built
            .open_device_material(
                &built_statement,
                built_signature,
                &state,
                issuer.device_id,
                &target_keys,
            )
            .is_err()
    );
    let (second_statement, second, second_signature) =
        RevocationTransitionV1::build(statement.clone(), &keys, &state).unwrap();
    let second_keys = second
        .open_device_material(
            &second_statement,
            second_signature,
            &state,
            issuer.device_id,
            &keys,
        )
        .unwrap();
    assert_ne!(
        from_device.workspace_root_key(),
        second_keys.workspace_root_key()
    );
    assert_ne!(
        from_device.active_epoch_key(),
        second_keys.active_epoch_key()
    );
    // Even a newly valid signature cannot transplant an envelope from another
    // rotation's key commitment into this one.
    let mut transplanted = built.clone();
    transplanted.devices[0].envelope = second.devices[0].envelope.clone();
    let mut transplanted_statement = built_statement.clone();
    transplanted_statement.transition_sha256 = transplanted.digest().unwrap();
    let transplanted_sig = transplanted_statement.sign(&issuer, &keys).unwrap();
    transplanted
        .verify(&transplanted_statement, transplanted_sig, &state)
        .unwrap();
    assert!(
        transplanted
            .open_device_material(
                &transplanted_statement,
                transplanted_sig,
                &state,
                issuer.device_id,
                &keys,
            )
            .is_err()
    );
    // A trusted signer can create valid AEAD around a wrong bundle. Opening must
    // still enforce the signed plaintext commitment and next-epoch contract.
    use sha2::{Digest, Sha256};
    for wrong_epoch in [false, true] {
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder
            .map(7)
            .unwrap()
            .u8(0)
            .unwrap()
            .u16(1)
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(from_device.account_id().as_bytes())
            .unwrap()
            .u8(2)
            .unwrap()
            .bytes(from_device.workspace_id().as_bytes())
            .unwrap()
            .u8(3)
            .unwrap()
            .u32(if wrong_epoch { 4 } else { 3 })
            .unwrap()
            .u8(4)
            .unwrap()
            .u32(3)
            .unwrap()
            .u8(5)
            .unwrap()
            .bytes(from_device.workspace_root_key())
            .unwrap()
            .u8(6)
            .unwrap()
            .bytes(from_device.active_epoch_key())
            .unwrap();
        let plaintext = encoder.into_writer();
        let mut forged = built.clone();
        forged.key_material_sha256 = if wrong_epoch {
            Sha256Digest(Sha256::digest(&plaintext).into())
        } else {
            Sha256Digest([19; 32])
        };
        let canonical = built.canonical_bytes().unwrap();
        let cert_len = u32::from_be_bytes(
            canonical[count_offset + 4..certificate_offset]
                .try_into()
                .unwrap(),
        ) as usize;
        let cert_hash =
            Sha256::digest(&canonical[certificate_offset..certificate_offset + cert_len]);
        let mut context = built_statement.signing_preimage().unwrap();
        context.truncate(context.len() - 32);
        let mut aad = b"context-relay/revocation-device-material/v1\0".to_vec();
        aad.extend_from_slice(&context);
        aad.extend_from_slice(&forged.previous_state_sha256.0);
        aad.extend_from_slice(&forged.key_material_sha256.0);
        aad.extend_from_slice(issuer.device_id.as_bytes());
        aad.extend_from_slice(&cert_hash);
        forged.devices[0].envelope =
            wrap_secret(keys.wrapping_public_key(), &plaintext, &aad).unwrap();
        let mut forged_statement = built_statement.clone();
        forged_statement.transition_sha256 = forged.digest().unwrap();
        let sig = forged_statement.sign(&issuer, &keys).unwrap();
        forged.verify(&forged_statement, sig, &state).unwrap();
        assert!(
            forged
                .open_device_material(&forged_statement, sig, &state, issuer.device_id, &keys)
                .is_err()
        );
    }

    let remaining_keys = DeviceKeys::generate().unwrap();
    let mut remaining_cert = issuer.clone();
    remaining_cert.device_id = "018f22e2-79b0-7cc8-98c4-dc0c0c073986".parse().unwrap();
    remaining_cert.signing_public_key = remaining_keys.signing_public_key();
    remaining_cert.wrapping_public_key = remaining_keys.wrapping_public_key();
    let mut expanded_devices = active.clone();
    expanded_devices.insert(remaining_cert.device_id, remaining_cert.clone());
    let expanded = RevocationControlState {
        active_devices: &expanded_devices,
        ..state
    };
    let (expanded_statement, expanded_transition, expanded_signature) =
        RevocationTransitionV1::build(statement.clone(), &keys, &expanded).unwrap();
    let opened_issuer = expanded_transition
        .open_device_material(
            &expanded_statement,
            expanded_signature,
            &expanded,
            issuer.device_id,
            &keys,
        )
        .unwrap();
    let opened_other = expanded_transition
        .open_device_material(
            &expanded_statement,
            expanded_signature,
            &expanded,
            remaining_cert.device_id,
            &remaining_keys,
        )
        .unwrap();
    assert_eq!(
        opened_issuer.workspace_root_key(),
        opened_other.workspace_root_key()
    );
    assert_eq!(
        opened_issuer.active_epoch_key(),
        opened_other.active_epoch_key()
    );
    let (self_statement, self_transition, self_signature) =
        RevocationTransitionV1::build(self_revoke, &keys, &solo).unwrap();
    assert!(self_transition.devices.is_empty());
    self_transition
        .open_recovery_material(&self_statement, self_signature, &solo, &recovery)
        .unwrap();
}
