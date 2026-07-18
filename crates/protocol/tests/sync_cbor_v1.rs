mod support;

use std::str::FromStr;

use context_relay_protocol::{
    BoundedCiphertext, DeviceId, DeviceSequence, MAX_BATCH_OPERATIONS, MAX_CIPHERTEXT_BYTES,
    ProtocolError, decode_checkpoint_v1, decode_sync_operation_v1,
    encode_checkpoint_signing_preimage_v1, encode_checkpoint_v1,
    encode_sync_operation_signing_preimage_v1, encode_sync_operation_v1,
};
use serde::Deserialize;

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

#[derive(Deserialize)]
struct InvalidCborFixture {
    name: String,
    expected: String,
    mutation: InvalidCborMutation,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum InvalidCborMutation {
    Replace {
        offset: usize,
        delete: usize,
        hex: String,
    },
    ReplaceFound {
        find_hex: String,
        offset_from_find: usize,
        delete: usize,
        hex: String,
    },
    Prefix {
        hex: String,
    },
    Append {
        hex: String,
    },
    DuplicateRange {
        find_hex: String,
        patch_offset_from_find: usize,
        patch_hex: String,
        range_offset_from_find: usize,
        range_length: usize,
        insert_offset_from_find: usize,
    },
    Repeat {
        hex: String,
        count: usize,
    },
    ReplaceWithByteString {
        find_hex: String,
        offset_from_find: usize,
        delete: usize,
        length: usize,
        fill: u8,
    },
}

#[test]
fn invalid_cbor_corpus_is_rejected_at_the_named_boundary() {
    let canonical = encode_sync_operation_v1(&support::sync_operation()).unwrap();
    let fixtures: Vec<InvalidCborFixture> =
        serde_json::from_str(include_str!("fixtures/invalid-cbor-corpus-v1.json")).unwrap();

    for fixture in fixtures {
        let invalid = apply_mutation(&canonical, fixture.mutation);
        match decode_sync_operation_v1(&invalid) {
            Err(ProtocolError::InvalidCbor(actual)) => {
                assert_eq!(actual, fixture.expected, "fixture {}", fixture.name);
            }
            result => panic!(
                "fixture {}: expected invalid CBOR, got {result:?}",
                fixture.name
            ),
        }
    }
}

fn apply_mutation(canonical: &[u8], mutation: InvalidCborMutation) -> Vec<u8> {
    match mutation {
        InvalidCborMutation::Replace {
            offset,
            delete,
            hex,
        } => replace(canonical.to_vec(), offset, delete, unhex(&hex)),
        InvalidCborMutation::ReplaceFound {
            find_hex,
            offset_from_find,
            delete,
            hex,
        } => {
            let at = find(canonical, &unhex(&find_hex)) + offset_from_find;
            replace(canonical.to_vec(), at, delete, unhex(&hex))
        }
        InvalidCborMutation::Prefix { hex } => {
            let mut output = unhex(&hex);
            output.extend_from_slice(canonical);
            output
        }
        InvalidCborMutation::Append { hex } => {
            let mut output = canonical.to_vec();
            output.extend(unhex(&hex));
            output
        }
        InvalidCborMutation::DuplicateRange {
            find_hex,
            patch_offset_from_find,
            patch_hex,
            range_offset_from_find,
            range_length,
            insert_offset_from_find,
        } => {
            let base = find(canonical, &unhex(&find_hex));
            let mut output = canonical.to_vec();
            let patch = unhex(&patch_hex);
            output.splice(
                base + patch_offset_from_find..base + patch_offset_from_find + patch.len(),
                patch,
            );
            let duplicate = output
                [base + range_offset_from_find..base + range_offset_from_find + range_length]
                .to_vec();
            output.splice(
                base + insert_offset_from_find..base + insert_offset_from_find,
                duplicate,
            );
            output
        }
        InvalidCborMutation::Repeat { hex, count } => {
            let pattern = unhex(&hex);
            assert_eq!(pattern.len(), 1);
            vec![pattern[0]; count]
        }
        InvalidCborMutation::ReplaceWithByteString {
            find_hex,
            offset_from_find,
            delete,
            length,
            fill,
        } => {
            let at = find(canonical, &unhex(&find_hex)) + offset_from_find;
            let mut value = vec![0x5a];
            value.extend_from_slice(&(length as u32).to_be_bytes());
            value.resize(value.len() + length, fill);
            replace(canonical.to_vec(), at, delete, value)
        }
    }
}

fn replace(mut source: Vec<u8>, offset: usize, delete: usize, value: Vec<u8>) -> Vec<u8> {
    source.splice(offset..offset + delete, value);
    source
}

fn find(source: &[u8], pattern: &[u8]) -> usize {
    source
        .windows(pattern.len())
        .position(|window| window == pattern)
        .expect("fixture pattern must be present")
}

fn unhex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
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
