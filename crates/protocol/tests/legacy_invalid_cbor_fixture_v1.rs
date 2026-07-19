use context_relay_protocol::decode_sync_operation_v1;

#[test]
fn legacy_invalid_cbor_fixture_is_rejected() {
    for line in include_str!("fixtures/invalid-cbor-v1.hex").lines() {
        let (name, encoded) = line.split_once(':').expect("named fixture");
        let bytes = (0..encoded.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&encoded[index..index + 2], 16).unwrap())
            .collect::<Vec<_>>();
        assert!(
            decode_sync_operation_v1(&bytes).is_err(),
            "fixture {name} was accepted"
        );
    }
}
