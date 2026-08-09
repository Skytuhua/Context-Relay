mod support;

use context_relay_protocol::{
    MAX_PAIRING_REQUEST_BYTES, PAIRING_SCHEMA_VERSION, PairingRequestV1, ProtocolError,
    decode_pairing_request_v1, encode_pairing_request_signing_preimage_v1,
    encode_pairing_request_v1,
};
use minicbor::Encoder;

const SIGNING_DOMAIN: &[u8] = b"context-relay/pairing-request/v1\0";

#[test]
fn pairing_request_v1_matches_the_frozen_vectors() {
    let request = support::pairing_request_fixture();
    let bytes = encode_pairing_request_v1(&request).unwrap();

    assert_eq!(PAIRING_SCHEMA_VERSION, 1);
    assert_eq!(
        hex(&bytes),
        include_str!("fixtures/pairing-request-v1.hex").trim()
    );
    assert_eq!(decode_pairing_request_v1(&bytes).unwrap(), request);
    assert_eq!(
        encode_pairing_request_v1(&decode_pairing_request_v1(&bytes).unwrap()).unwrap(),
        bytes
    );

    let preimage = encode_pairing_request_signing_preimage_v1(&request).unwrap();
    assert!(preimage.starts_with(SIGNING_DOMAIN));
    assert_eq!(
        hex(&preimage),
        include_str!("fixtures/pairing-request-signing-preimage-v1.hex").trim()
    );

    let mut changed_signature = request;
    changed_signature.signature.0[0] ^= 0xff;
    assert_eq!(
        encode_pairing_request_signing_preimage_v1(&changed_signature).unwrap(),
        preimage,
        "the eight-entry signing map must exclude only the signature"
    );
}

#[test]
fn pairing_request_v1_enforces_the_dedicated_size_ceiling() {
    let canonical = encode_pairing_request_v1(&support::pairing_request_fixture()).unwrap();
    assert!(canonical.len() < MAX_PAIRING_REQUEST_BYTES);
    assert_eq!(
        decode_pairing_request_v1(&canonical).unwrap(),
        support::pairing_request_fixture()
    );

    let oversized = vec![0; MAX_PAIRING_REQUEST_BYTES + 1];
    assert_eq!(
        decode_pairing_request_v1(&oversized),
        Err(ProtocolError::InvalidCbor("pairing request too large"))
    );
}

#[test]
fn pairing_request_v1_rejects_structural_mutations() {
    let request = support::pairing_request_fixture();
    let canonical = encode_pairing_request_v1(&request).unwrap();

    let mut wrong_map_size = canonical.clone();
    wrong_map_size[0] = 0xa8;
    rejects(wrong_map_size);

    rejects(encode_unchecked(
        &request,
        &[0, 2, 1, 3, 4, 5, 6, 7, 8],
        request.schema_version,
        &request.device_name,
        1,
    ));

    let signature_key = find(&canonical, &[0x08, 0x58, 0x40, 0x05, 0x05]);

    let mut unknown_key = canonical.clone();
    unknown_key[signature_key] = 9;
    rejects(unknown_key);

    let mut duplicate_key = canonical.clone();
    duplicate_key[signature_key] = 7;
    rejects(duplicate_key);

    let mut trailing = canonical;
    trailing.push(0);
    rejects(trailing);
}

#[test]
fn pairing_request_v1_rejects_noncanonical_value_encodings() {
    let mut noncanonical = encode_pairing_request_v1(&support::pairing_request_fixture()).unwrap();
    noncanonical.splice(2..3, [0x18, 0x01]);
    rejects(noncanonical);
}

#[test]
fn pairing_request_v1_rejects_invalid_domain_values() {
    let request = support::pairing_request_fixture();

    rejects(encode_unchecked(
        &request,
        &[0, 1, 2, 3, 4, 5, 6, 7, 8],
        PAIRING_SCHEMA_VERSION + 1,
        &request.device_name,
        1,
    ));
    rejects(encode_unchecked(
        &request,
        &[0, 1, 2, 3, 4, 5, 6, 7, 8],
        request.schema_version,
        &request.device_name,
        2,
    ));
    rejects(encode_unchecked(
        &request,
        &[0, 1, 2, 3, 4, 5, 6, 7, 8],
        request.schema_version,
        " ",
        1,
    ));
    rejects(encode_unchecked(
        &request,
        &[0, 1, 2, 3, 4, 5, 6, 7, 8],
        request.schema_version,
        &"x".repeat(513),
        1,
    ));

    let mut invalid_pairing_id = encode_pairing_request_v1(&request).unwrap();
    invalid_pairing_id[11] = (invalid_pairing_id[11] & 0x0f) | 0x60;
    rejects(invalid_pairing_id);

    let mut invalid_device_id = encode_pairing_request_v1(&request).unwrap();
    let device_id = find(&invalid_device_id, request.device_id.as_bytes());
    invalid_device_id[device_id + 6] = (invalid_device_id[device_id + 6] & 0x0f) | 0x60;
    rejects(invalid_device_id);
}

#[test]
fn pairing_request_v1_validates_before_encoding() {
    let mut wrong_schema = support::pairing_request_fixture();
    wrong_schema.schema_version += 1;
    assert_eq!(
        encode_pairing_request_v1(&wrong_schema),
        Err(ProtocolError::InvalidCbor("invalid pairing request"))
    );
    assert_eq!(
        encode_pairing_request_signing_preimage_v1(&wrong_schema),
        Err(ProtocolError::InvalidCbor("invalid pairing request"))
    );

    let mut blank_name = support::pairing_request_fixture();
    blank_name.device_name = " ".into();
    assert_eq!(
        encode_pairing_request_v1(&blank_name),
        Err(ProtocolError::InvalidCbor("invalid pairing request"))
    );

    let mut exact_name_limit = support::pairing_request_fixture();
    exact_name_limit.device_name = "x".repeat(512);
    assert!(encode_pairing_request_v1(&exact_name_limit).is_ok());
    exact_name_limit.device_name.push('x');
    assert_eq!(
        encode_pairing_request_v1(&exact_name_limit),
        Err(ProtocolError::InvalidCbor("invalid pairing request"))
    );
}

fn rejects(bytes: Vec<u8>) {
    assert!(
        decode_pairing_request_v1(&bytes).is_err(),
        "mutation unexpectedly decoded: {}",
        hex(&bytes)
    );
}

fn encode_unchecked(
    request: &PairingRequestV1,
    keys: &[u8],
    schema_version: u16,
    device_name: &str,
    platform: u8,
) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(keys.len() as u64).unwrap();
    for key in keys {
        encoder.u8(*key).unwrap();
        match key {
            0 => {
                encoder.u16(schema_version).unwrap();
            }
            1 => {
                encoder.bytes(request.pairing_id.as_bytes()).unwrap();
            }
            2 => {
                encoder.bytes(&request.request_nonce.0).unwrap();
            }
            3 => {
                encoder.bytes(request.device_id.as_bytes()).unwrap();
            }
            4 => {
                encoder.str(device_name).unwrap();
            }
            5 => {
                encoder.u8(platform).unwrap();
            }
            6 => {
                encoder.bytes(&request.signing_public_key.0).unwrap();
            }
            7 => {
                encoder.bytes(&request.wrapping_public_key.0).unwrap();
            }
            8 => {
                encoder.bytes(&request.signature.0).unwrap();
            }
            _ => unreachable!(),
        }
    }
    encoder.into_writer()
}

fn find(source: &[u8], pattern: &[u8]) -> usize {
    source
        .windows(pattern.len())
        .position(|window| window == pattern)
        .expect("fixture pattern must be present")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
