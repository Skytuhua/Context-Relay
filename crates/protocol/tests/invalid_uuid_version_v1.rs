mod support;

use context_relay_protocol::{ProtocolError, decode_sync_operation_v1, encode_sync_operation_v1};

#[test]
fn invalid_uuid_version_fixture_is_rejected() {
    let mut bytes = encode_sync_operation_v1(&support::sync_operation()).unwrap();
    let valid_uuid = hex_bytes("018f22e279b07cc898c4dc0c0c07398f");
    let invalid_uuid = hex_bytes(include_str!("fixtures/invalid-uuid-version-v1.hex").trim());
    let offset = bytes
        .windows(valid_uuid.len())
        .position(|window| window == valid_uuid)
        .expect("operation ID must be present");
    bytes.splice(offset..offset + valid_uuid.len(), invalid_uuid);

    assert_eq!(
        decode_sync_operation_v1(&bytes),
        Err(ProtocolError::InvalidCbor("operation id"))
    );
}

fn hex_bytes(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}
