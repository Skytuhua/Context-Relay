mod support;

use std::str::FromStr;

use context_relay_protocol::{
    DeviceId, Ed25519PublicKeyBytes, LocalRequest, NativePlatform, PairingCode,
    PairingDecisionParams, PairingJoinParams, PairingRequestNonce, RecordId, Sha256Digest,
    X25519PublicKeyBytes,
};

#[test]
fn pairing_join_freezes_identity_nonce_and_algorithm_specific_keys() {
    let params = PairingJoinParams {
        code: PairingCode::new("01234-ABCDE".into()).unwrap(),
        device_id: DeviceId::from_str(support::ID).unwrap(),
        device_name: "new laptop".into(),
        platform: NativePlatform::Macos,
        request_nonce: PairingRequestNonce([3; 32]),
        signing_public_key: Ed25519PublicKeyBytes([5; 32]),
        wrapping_public_key: X25519PublicKeyBytes([7; 32]),
    };
    let request = LocalRequest::PairingJoin(params);
    let value = serde_json::to_value(&request).unwrap();
    assert_eq!(value["params"]["deviceId"], support::ID);
    assert_eq!(value["params"]["deviceName"], "new laptop");
    assert_eq!(value["params"]["platform"], "macos");
    assert_ne!(
        value["params"]["requestNonce"],
        value["params"]["signingPublicKey"]
    );
    assert_ne!(
        value["params"]["signingPublicKey"],
        value["params"]["wrappingPublicKey"]
    );
    assert_eq!(
        serde_json::from_value::<LocalRequest>(value.clone()).unwrap(),
        request
    );

    let mut unknown = value;
    unknown["params"]
        .as_object_mut()
        .unwrap()
        .insert("attackerField".into(), true.into());
    assert!(serde_json::from_value::<LocalRequest>(unknown).is_err());
}

#[test]
fn pairing_keys_cannot_be_substituted_across_algorithm_types() {
    let value = serde_json::json!({
        "method": "pairing_join",
        "params": {
            "code": "01234-ABCDE",
            "deviceId": support::ID,
            "deviceName": "new laptop",
            "platform": "macos",
            "requestNonce": "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM",
            "signingPublicKey": "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU",
            "wrappingPublicKey": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc"
        }
    });
    let request: LocalRequest = serde_json::from_value(value).unwrap();
    let LocalRequest::PairingJoin(params) = request else {
        panic!("wrong request");
    };
    assert_eq!(params.signing_public_key, Ed25519PublicKeyBytes([5; 32]));
    assert_eq!(params.wrapping_public_key, X25519PublicKeyBytes([7; 32]));
}

#[test]
fn pairing_decision_is_bound_to_request_digest() {
    let decision = PairingDecisionParams {
        pairing_id: RecordId::from_str(support::ID).unwrap(),
        request_digest: Sha256Digest([11; 32]),
        approve: true,
    };
    let value = serde_json::to_value(&decision).unwrap();
    assert_eq!(value["requestDigest"], "0b".repeat(32));
    assert_eq!(
        serde_json::from_value::<PairingDecisionParams>(value).unwrap(),
        decision
    );
}
