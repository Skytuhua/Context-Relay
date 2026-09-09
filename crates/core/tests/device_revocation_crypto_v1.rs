use context_relay_core::{
    crypto::{CertificateFieldsV1, DeviceCertificateV1, DeviceKeys},
    devices::revocation_crypto::DeviceRevocationStatementV1,
};
use context_relay_protocol::{PairingRequestNonce, Sha256Digest};

#[test]
fn revocation_binds_scope_cutoff_epochs_and_rotation_to_installed_keys() {
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
    let signature = statement.sign(&certificate, &keys).unwrap();
    statement.verify(&certificate, signature).unwrap();
    // Every signed byte, including domain and field boundaries, matters.
    let preimage = statement.signing_preimage().unwrap();
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
