mod support;

use std::str::FromStr;

use context_relay_protocol::{
    BoundedCiphertext, DeviceId, DeviceSequence, MAX_BATCH_OPERATIONS, MAX_BLOB_BYTES,
    MAX_CBOR_OPERATION_BYTES, MAX_CIPHERTEXT_BYTES, ProtocolError, decode_checkpoint_v1,
    decode_sync_operation_v1, encode_checkpoint_signing_preimage_v1, encode_checkpoint_v1,
    encode_sync_operation_signing_preimage_v1, encode_sync_operation_v1,
};

#[test]
fn operation_and_checkpoint_match_golden_bytes() {
    let operation = support::sync_operation();
    let bytes = encode_sync_operation_v1(&operation).unwrap();
    assert_eq!(
        hex(&bytes),
        include_str!("fixtures/sync-operation-v1.hex").trim()
    );
    assert_eq!(decode_sync_operation_v1(&bytes).unwrap(), operation);
    assert_eq!(
        hex(&encode_sync_operation_signing_preimage_v1(&operation).unwrap()),
        include_str!("fixtures/sync-operation-signing-preimage-v1.hex").trim()
    );
    let checkpoint = support::checkpoint();
    let bytes = encode_checkpoint_v1(&checkpoint).unwrap();
    assert_eq!(
        hex(&bytes),
        include_str!("fixtures/checkpoint-v1.hex").trim()
    );
    assert_eq!(decode_checkpoint_v1(&bytes).unwrap(), checkpoint);
    assert_eq!(
        hex(&encode_checkpoint_signing_preimage_v1(&checkpoint).unwrap()),
        include_str!("fixtures/checkpoint-signing-preimage-v1.hex").trim()
    );
}

#[test]
fn invalid_cbor_forms_are_rejected_at_the_named_boundary() {
    let canonical = encode_sync_operation_v1(&support::sync_operation()).unwrap();

    let mut duplicate_key = canonical.clone();
    duplicate_key[3] = 0;
    assert_eq!(
        decode_sync_operation_v1(&duplicate_key),
        Err(ProtocolError::InvalidCbor("map key"))
    );
    let mut indefinite = canonical.clone();
    indefinite[0] = 0xbf;
    assert_eq!(
        decode_sync_operation_v1(&indefinite),
        Err(ProtocolError::InvalidCbor("map size"))
    );
    let mut non_preferred = canonical.clone();
    non_preferred.splice(2..3, [0x18, 0x01]);
    assert_eq!(
        decode_sync_operation_v1(&non_preferred),
        Err(ProtocolError::InvalidCbor("noncanonical encoding"))
    );
    let mut wrong_order = canonical.clone();
    wrong_order[1] = 1;
    assert_eq!(
        decode_sync_operation_v1(&wrong_order),
        Err(ProtocolError::InvalidCbor("map key"))
    );
    let mut tagged = vec![0xc0];
    tagged.extend_from_slice(&canonical);
    assert_eq!(
        decode_sync_operation_v1(&tagged),
        Err(ProtocolError::InvalidCbor("decode"))
    );
    let mut float = canonical.clone();
    float.splice(2..3, [0xf9, 0, 0]);
    assert_eq!(
        decode_sync_operation_v1(&float),
        Err(ProtocolError::InvalidCbor("decode"))
    );
    let mut trailing = canonical.clone();
    trailing.push(0);
    assert_eq!(
        decode_sync_operation_v1(&trailing),
        Err(ProtocolError::InvalidCbor("trailing bytes"))
    );
    assert_eq!(
        decode_sync_operation_v1(&vec![0; MAX_CBOR_OPERATION_BYTES + 1]),
        Err(ProtocolError::InvalidCbor("operation too large"))
    );
    let mut unsupported = canonical.clone();
    unsupported[2] = 2;
    assert_eq!(
        decode_sync_operation_v1(&unsupported),
        Err(ProtocolError::InvalidCbor("unsupported schema"))
    );
    let mut bad_uuid = canonical.clone();
    bad_uuid[11] = 0x4c;
    assert_eq!(
        decode_sync_operation_v1(&bad_uuid),
        Err(ProtocolError::InvalidCbor("operation id"))
    );

    let frontier = [0x0a, 0x81, 0x82, 0x50];
    let frontier_at = canonical
        .windows(frontier.len())
        .position(|window| window == frontier)
        .unwrap();
    let entry_start = frontier_at + 2;
    let entry_end = entry_start + 19;
    let duplicate_entry = canonical[entry_start..entry_end].to_vec();
    let mut duplicate_frontier = canonical.clone();
    duplicate_frontier[frontier_at + 1] = 0x82;
    duplicate_frontier.splice(entry_end..entry_end, duplicate_entry);
    assert_eq!(
        decode_sync_operation_v1(&duplicate_frontier),
        Err(ProtocolError::InvalidCbor("invalid operation"))
    );
    let hlc_at = canonical
        .windows(2)
        .position(|window| window == [0x12, 0xa3])
        .unwrap();
    let mut malformed_hlc = canonical.clone();
    malformed_hlc[hlc_at + 1] = 0xa2;
    assert_eq!(
        decode_sync_operation_v1(&malformed_hlc),
        Err(ProtocolError::InvalidCbor("map size"))
    );
    let mut oversized_blob = support::sync_operation();
    oversized_blob.blob_refs[0].ciphertext_bytes = MAX_BLOB_BYTES as u64 + 1;
    assert_eq!(
        encode_sync_operation_v1(&oversized_blob),
        Err(ProtocolError::InvalidCbor("invalid operation"))
    );
}

fn frontier(count: usize) -> Vec<DeviceSequence> {
    (0..count)
        .map(|index| DeviceSequence {
            device_id: DeviceId::from_str(&format!("018f22e2-79b0-7cc8-98c4-{index:012x}"))
                .unwrap(),
            sequence: index as u64,
        })
        .collect()
}

#[test]
fn exact_collection_and_byte_limits_succeed() {
    let mut operation = support::sync_operation();
    operation.causal_frontier = frontier(MAX_BATCH_OPERATIONS);
    operation.ciphertext = BoundedCiphertext::new(vec![0; MAX_CIPHERTEXT_BYTES]).unwrap();
    assert!(encode_sync_operation_v1(&operation).is_ok());

    let mut checkpoint = support::checkpoint();
    checkpoint.causal_frontier = frontier(MAX_BATCH_OPERATIONS);
    assert!(encode_checkpoint_v1(&checkpoint).is_ok());
}

#[test]
fn max_plus_one_collection_limits_fail() {
    let mut operation = support::sync_operation();
    operation.causal_frontier = frontier(MAX_BATCH_OPERATIONS + 1);
    assert_eq!(
        encode_sync_operation_v1(&operation),
        Err(ProtocolError::InvalidCbor("invalid operation"))
    );
    let mut checkpoint = support::checkpoint();
    checkpoint.causal_frontier = frontier(MAX_BATCH_OPERATIONS + 1);
    assert_eq!(
        encode_checkpoint_v1(&checkpoint),
        Err(ProtocolError::InvalidCbor("invalid checkpoint"))
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
