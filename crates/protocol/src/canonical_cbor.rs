use minicbor::{Decoder, Encoder};

use crate::{
    AccountId, BlobRef, BoundedCiphertext, CheckpointV1, DeviceId, DeviceSequence,
    Ed25519SignatureBytes, HybridLogicalClock, MAX_BATCH_OPERATIONS, MAX_CBOR_OPERATION_BYTES,
    MAX_CIPHERTEXT_BYTES, MAX_TITLE_BYTES, MutationKind, OperationId, ProjectId, ProtocolError,
    RecordId, RecordKind, SYNC_SCHEMA_VERSION, Sha256Digest, SyncOperationV1, WorkspaceId,
    XChaChaNonce, uuid_v7_from_bytes,
};

pub fn encode_sync_operation_signing_preimage_v1(
    operation: &SyncOperationV1,
) -> Result<Vec<u8>, ProtocolError> {
    operation
        .validate()
        .map_err(|_| ProtocolError::InvalidCbor("invalid operation"))?;
    encode_operation(operation, false)
}

pub fn encode_sync_operation_v1(operation: &SyncOperationV1) -> Result<Vec<u8>, ProtocolError> {
    operation
        .validate()
        .map_err(|_| ProtocolError::InvalidCbor("invalid operation"))?;
    encode_operation(operation, true)
}

fn encode_operation(operation: &SyncOperationV1, signed: bool) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .map(if signed { 20 } else { 19 })
        .map_err(|_| ProtocolError::InvalidCbor("encode"))?;
    key(&mut encoder, 0)?;
    encoder.u16(operation.schema_version).map_err(enc)?;
    key(&mut encoder, 1)?;
    bytes(&mut encoder, operation.operation_id.as_bytes())?;
    key(&mut encoder, 2)?;
    bytes(&mut encoder, operation.account_id.as_bytes())?;
    key(&mut encoder, 3)?;
    bytes(&mut encoder, operation.workspace_id.as_bytes())?;
    key(&mut encoder, 4)?;
    match operation.project_id {
        Some(id) => {
            bytes(&mut encoder, id.as_bytes())?;
        }
        None => {
            encoder.null().map_err(enc)?;
        }
    }
    key(&mut encoder, 5)?;
    bytes(&mut encoder, operation.record_id.as_bytes())?;
    key(&mut encoder, 6)?;
    encoder
        .u8(record_kind(operation.record_kind))
        .map_err(enc)?;
    key(&mut encoder, 7)?;
    encoder
        .u8(mutation_kind(operation.mutation_kind))
        .map_err(enc)?;
    key(&mut encoder, 8)?;
    bytes(&mut encoder, operation.device_id.as_bytes())?;
    key(&mut encoder, 9)?;
    encoder.u64(operation.device_sequence).map_err(enc)?;
    key(&mut encoder, 10)?;
    encode_frontier(&mut encoder, &operation.causal_frontier)?;
    key(&mut encoder, 11)?;
    encoder.u32(operation.control_epoch).map_err(enc)?;
    key(&mut encoder, 12)?;
    encoder.u32(operation.key_epoch).map_err(enc)?;
    key(&mut encoder, 13)?;
    bytes(&mut encoder, &operation.previous_device_hash.0)?;
    key(&mut encoder, 14)?;
    bytes(&mut encoder, &operation.nonce.0)?;
    key(&mut encoder, 15)?;
    bytes(&mut encoder, operation.ciphertext.as_slice())?;
    key(&mut encoder, 16)?;
    bytes(&mut encoder, &operation.ciphertext_hash.0)?;
    key(&mut encoder, 17)?;
    encoder
        .array(operation.blob_refs.len() as u64)
        .map_err(enc)?;
    for blob in &operation.blob_refs {
        encode_blob(&mut encoder, blob)?;
    }
    key(&mut encoder, 18)?;
    encode_hlc(&mut encoder, operation.created_hlc)?;
    if signed {
        key(&mut encoder, 19)?;
        bytes(&mut encoder, &operation.signature.0)?;
    }
    let output = encoder.into_writer();
    if output.len() > MAX_CBOR_OPERATION_BYTES {
        return Err(ProtocolError::InvalidCbor("operation too large"));
    }
    Ok(output)
}

pub fn decode_sync_operation_v1(input: &[u8]) -> Result<SyncOperationV1, ProtocolError> {
    if input.len() > MAX_CBOR_OPERATION_BYTES {
        return Err(ProtocolError::InvalidCbor("operation too large"));
    }
    let mut decoder = Decoder::new(input);
    require_map(&mut decoder, 20)?;
    expect_key(&mut decoder, 0)?;
    let schema_version = decoder.u16().map_err(dec)?;
    if schema_version != SYNC_SCHEMA_VERSION {
        return Err(bad("unsupported schema"));
    }
    expect_key(&mut decoder, 1)?;
    let operation_id = uuid_v7_from_bytes(decoder.bytes().map_err(dec)?, OperationId::new)
        .map_err(|_| bad("operation id"))?;
    expect_key(&mut decoder, 2)?;
    let account_id = uuid_v7_from_bytes(decoder.bytes().map_err(dec)?, AccountId::new)
        .map_err(|_| bad("account id"))?;
    expect_key(&mut decoder, 3)?;
    let workspace_id = uuid_v7_from_bytes(decoder.bytes().map_err(dec)?, WorkspaceId::new)
        .map_err(|_| bad("workspace id"))?;
    expect_key(&mut decoder, 4)?;
    let project_id = if decoder.datatype().map_err(dec)? == minicbor::data::Type::Null {
        decoder.null().map_err(dec)?;
        None
    } else {
        Some(
            uuid_v7_from_bytes(decoder.bytes().map_err(dec)?, ProjectId::new)
                .map_err(|_| bad("project id"))?,
        )
    };
    expect_key(&mut decoder, 5)?;
    let record_id = uuid_v7_from_bytes(decoder.bytes().map_err(dec)?, RecordId::new)
        .map_err(|_| bad("record id"))?;
    expect_key(&mut decoder, 6)?;
    let record_kind = decode_record_kind(decoder.u8().map_err(dec)?)?;
    expect_key(&mut decoder, 7)?;
    let mutation_kind = decode_mutation_kind(decoder.u8().map_err(dec)?)?;
    expect_key(&mut decoder, 8)?;
    let device_id = uuid_v7_from_bytes(decoder.bytes().map_err(dec)?, DeviceId::new)
        .map_err(|_| bad("device id"))?;
    expect_key(&mut decoder, 9)?;
    let device_sequence = decoder.u64().map_err(dec)?;
    expect_key(&mut decoder, 10)?;
    let causal_frontier = decode_frontier(&mut decoder)?;
    expect_key(&mut decoder, 11)?;
    let control_epoch = decoder.u32().map_err(dec)?;
    expect_key(&mut decoder, 12)?;
    let key_epoch = decoder.u32().map_err(dec)?;
    expect_key(&mut decoder, 13)?;
    let previous_device_hash = Sha256Digest(read_fixed::<32>(&mut decoder)?);
    expect_key(&mut decoder, 14)?;
    let nonce = XChaChaNonce(read_fixed::<24>(&mut decoder)?);
    expect_key(&mut decoder, 15)?;
    let ciphertext_bytes = decoder.bytes().map_err(dec)?;
    if ciphertext_bytes.len() > MAX_CIPHERTEXT_BYTES {
        return Err(bad("ciphertext"));
    }
    let ciphertext =
        BoundedCiphertext::new(ciphertext_bytes.to_vec()).map_err(|_| bad("ciphertext"))?;
    expect_key(&mut decoder, 16)?;
    let ciphertext_hash = Sha256Digest(read_fixed::<32>(&mut decoder)?);
    expect_key(&mut decoder, 17)?;
    let blob_refs = decode_blobs(&mut decoder)?;
    expect_key(&mut decoder, 18)?;
    let created_hlc = decode_hlc(&mut decoder)?;
    expect_key(&mut decoder, 19)?;
    let signature = Ed25519SignatureBytes(read_fixed::<64>(&mut decoder)?);
    if decoder.position() != input.len() {
        return Err(bad("trailing bytes"));
    }
    let operation = SyncOperationV1 {
        schema_version,
        operation_id,
        account_id,
        workspace_id,
        project_id,
        record_id,
        record_kind,
        mutation_kind,
        device_id,
        device_sequence,
        causal_frontier,
        control_epoch,
        key_epoch,
        previous_device_hash,
        nonce,
        ciphertext,
        ciphertext_hash,
        blob_refs,
        created_hlc,
        signature,
    };
    operation.validate().map_err(|_| bad("invalid operation"))?;
    if encode_sync_operation_v1(&operation)? != input {
        return Err(bad("noncanonical encoding"));
    }
    Ok(operation)
}

pub fn encode_checkpoint_signing_preimage_v1(
    checkpoint: &CheckpointV1,
) -> Result<Vec<u8>, ProtocolError> {
    encode_checkpoint(checkpoint, false)
}
pub fn encode_checkpoint_v1(checkpoint: &CheckpointV1) -> Result<Vec<u8>, ProtocolError> {
    encode_checkpoint(checkpoint, true)
}

fn encode_checkpoint(checkpoint: &CheckpointV1, signed: bool) -> Result<Vec<u8>, ProtocolError> {
    checkpoint
        .validate()
        .map_err(|_| bad("invalid checkpoint"))?;
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(if signed { 8 } else { 7 }).map_err(enc)?;
    key(&mut encoder, 0)?;
    encoder.u16(checkpoint.schema_version).map_err(enc)?;
    key(&mut encoder, 1)?;
    bytes(&mut encoder, &checkpoint.previous_checkpoint_hash.0)?;
    key(&mut encoder, 2)?;
    encode_frontier(&mut encoder, &checkpoint.causal_frontier)?;
    key(&mut encoder, 3)?;
    bytes(&mut encoder, &checkpoint.state_hash.0)?;
    key(&mut encoder, 4)?;
    encoder.u32(checkpoint.key_epoch).map_err(enc)?;
    key(&mut encoder, 5)?;
    bytes(&mut encoder, checkpoint.creator_device.as_bytes())?;
    key(&mut encoder, 6)?;
    encode_hlc(&mut encoder, checkpoint.created_hlc)?;
    if signed {
        key(&mut encoder, 7)?;
        bytes(&mut encoder, &checkpoint.signature.0)?;
    }
    let output = encoder.into_writer();
    if output.len() > MAX_CBOR_OPERATION_BYTES {
        return Err(bad("checkpoint too large"));
    }
    Ok(output)
}

pub fn decode_checkpoint_v1(input: &[u8]) -> Result<CheckpointV1, ProtocolError> {
    if input.len() > MAX_CBOR_OPERATION_BYTES {
        return Err(bad("checkpoint too large"));
    }
    let mut decoder = Decoder::new(input);
    require_map(&mut decoder, 8)?;
    expect_key(&mut decoder, 0)?;
    let schema_version = decoder.u16().map_err(dec)?;
    if schema_version != SYNC_SCHEMA_VERSION {
        return Err(bad("unsupported schema"));
    }
    expect_key(&mut decoder, 1)?;
    let previous_checkpoint_hash = Sha256Digest(read_fixed::<32>(&mut decoder)?);
    expect_key(&mut decoder, 2)?;
    let causal_frontier = decode_frontier(&mut decoder)?;
    expect_key(&mut decoder, 3)?;
    let state_hash = Sha256Digest(read_fixed::<32>(&mut decoder)?);
    expect_key(&mut decoder, 4)?;
    let key_epoch = decoder.u32().map_err(dec)?;
    expect_key(&mut decoder, 5)?;
    let creator_device = uuid_v7_from_bytes(decoder.bytes().map_err(dec)?, DeviceId::new)
        .map_err(|_| bad("creator device"))?;
    expect_key(&mut decoder, 6)?;
    let created_hlc = decode_hlc(&mut decoder)?;
    expect_key(&mut decoder, 7)?;
    let signature = Ed25519SignatureBytes(read_fixed::<64>(&mut decoder)?);
    if decoder.position() != input.len() {
        return Err(bad("trailing bytes"));
    }
    let checkpoint = CheckpointV1 {
        schema_version,
        previous_checkpoint_hash,
        causal_frontier,
        state_hash,
        key_epoch,
        creator_device,
        created_hlc,
        signature,
    };
    checkpoint
        .validate()
        .map_err(|_| bad("invalid checkpoint"))?;
    if encode_checkpoint_v1(&checkpoint)? != input {
        return Err(bad("noncanonical encoding"));
    }
    Ok(checkpoint)
}

fn encode_frontier(
    encoder: &mut Encoder<Vec<u8>>,
    frontier: &[DeviceSequence],
) -> Result<(), ProtocolError> {
    encoder.array(frontier.len() as u64).map_err(enc)?;
    for entry in frontier {
        encoder.array(2).map_err(enc)?;
        bytes(encoder, entry.device_id.as_bytes())?;
        encoder.u64(entry.sequence).map_err(enc)?;
    }
    Ok(())
}

fn decode_frontier(decoder: &mut Decoder<'_>) -> Result<Vec<DeviceSequence>, ProtocolError> {
    let len = decoder
        .array()
        .map_err(dec)?
        .ok_or_else(|| bad("indefinite array"))?;
    if len > MAX_BATCH_OPERATIONS as u64 {
        return Err(bad("frontier too large"));
    }
    let mut output = Vec::with_capacity(len as usize);
    for _ in 0..len {
        if decoder.array().map_err(dec)? != Some(2) {
            return Err(bad("frontier entry"));
        }
        let device_id = uuid_v7_from_bytes(decoder.bytes().map_err(dec)?, DeviceId::new)
            .map_err(|_| bad("frontier device"))?;
        output.push(DeviceSequence {
            device_id,
            sequence: decoder.u64().map_err(dec)?,
        });
    }
    Ok(output)
}

fn encode_blob(encoder: &mut Encoder<Vec<u8>>, blob: &BlobRef) -> Result<(), ProtocolError> {
    encoder.map(3).map_err(enc)?;
    key(encoder, 0)?;
    bytes(encoder, &blob.digest.0)?;
    key(encoder, 1)?;
    encoder.u64(blob.ciphertext_bytes).map_err(enc)?;
    key(encoder, 2)?;
    encoder.str(&blob.storage_id).map_err(enc)?;
    Ok(())
}

fn decode_blobs(decoder: &mut Decoder<'_>) -> Result<Vec<BlobRef>, ProtocolError> {
    let len = decoder
        .array()
        .map_err(dec)?
        .ok_or_else(|| bad("indefinite array"))?;
    if len > MAX_BATCH_OPERATIONS as u64 {
        return Err(bad("blob list too large"));
    }
    let mut output = Vec::with_capacity(len as usize);
    for _ in 0..len {
        require_map(decoder, 3)?;
        expect_key(decoder, 0)?;
        let digest = Sha256Digest(read_fixed::<32>(decoder)?);
        expect_key(decoder, 1)?;
        let ciphertext_bytes = decoder.u64().map_err(dec)?;
        expect_key(decoder, 2)?;
        let storage = decoder.str().map_err(dec)?;
        if storage.len() > MAX_TITLE_BYTES {
            return Err(bad("blob storage id too large"));
        }
        let storage_id = storage.to_owned();
        output.push(BlobRef {
            digest,
            ciphertext_bytes,
            storage_id,
        });
    }
    Ok(output)
}

fn encode_hlc(
    encoder: &mut Encoder<Vec<u8>>,
    hlc: HybridLogicalClock,
) -> Result<(), ProtocolError> {
    encoder.map(3).map_err(enc)?;
    key(encoder, 0)?;
    encoder.u64(hlc.physical_ms).map_err(enc)?;
    key(encoder, 1)?;
    encoder.u32(hlc.logical).map_err(enc)?;
    key(encoder, 2)?;
    bytes(encoder, hlc.node.as_bytes())?;
    Ok(())
}

fn decode_hlc(decoder: &mut Decoder<'_>) -> Result<HybridLogicalClock, ProtocolError> {
    require_map(decoder, 3)?;
    expect_key(decoder, 0)?;
    let physical_ms = decoder.u64().map_err(dec)?;
    expect_key(decoder, 1)?;
    let logical = decoder.u32().map_err(dec)?;
    expect_key(decoder, 2)?;
    let node = uuid_v7_from_bytes(decoder.bytes().map_err(dec)?, DeviceId::new)
        .map_err(|_| bad("HLC node"))?;
    Ok(HybridLogicalClock::new(physical_ms, logical, node))
}

fn key(encoder: &mut Encoder<Vec<u8>>, value: u8) -> Result<(), ProtocolError> {
    encoder.u8(value).map(|_| ()).map_err(enc)
}
fn bytes(encoder: &mut Encoder<Vec<u8>>, value: &[u8]) -> Result<(), ProtocolError> {
    encoder.bytes(value).map(|_| ()).map_err(enc)
}
fn expect_key(decoder: &mut Decoder<'_>, value: u8) -> Result<(), ProtocolError> {
    (decoder.u8().map_err(dec)? == value)
        .then_some(())
        .ok_or_else(|| bad("map key"))
}
fn require_map(decoder: &mut Decoder<'_>, size: u64) -> Result<(), ProtocolError> {
    (decoder.map().map_err(dec)? == Some(size))
        .then_some(())
        .ok_or_else(|| bad("map size"))
}
fn read_fixed<const N: usize>(decoder: &mut Decoder<'_>) -> Result<[u8; N], ProtocolError> {
    decoder
        .bytes()
        .map_err(dec)?
        .try_into()
        .map_err(|_| bad("byte length"))
}
fn record_kind(value: RecordKind) -> u8 {
    match value {
        RecordKind::Memory => 0,
        RecordKind::MemoryCandidate => 1,
        RecordKind::Task => 2,
        RecordKind::SecretRef => 3,
        RecordKind::Instruction => 4,
        RecordKind::Component => 5,
        RecordKind::Project => 6,
    }
}
fn mutation_kind(value: MutationKind) -> u8 {
    match value {
        MutationKind::Upsert => 0,
        MutationKind::Tombstone => 1,
    }
}
fn decode_record_kind(value: u8) -> Result<RecordKind, ProtocolError> {
    match value {
        0 => Ok(RecordKind::Memory),
        1 => Ok(RecordKind::MemoryCandidate),
        2 => Ok(RecordKind::Task),
        3 => Ok(RecordKind::SecretRef),
        4 => Ok(RecordKind::Instruction),
        5 => Ok(RecordKind::Component),
        6 => Ok(RecordKind::Project),
        _ => Err(bad("record kind")),
    }
}
fn decode_mutation_kind(value: u8) -> Result<MutationKind, ProtocolError> {
    match value {
        0 => Ok(MutationKind::Upsert),
        1 => Ok(MutationKind::Tombstone),
        _ => Err(bad("mutation kind")),
    }
}
fn enc<E>(_: minicbor::encode::Error<E>) -> ProtocolError {
    bad("encode")
}
fn dec(_: minicbor::decode::Error) -> ProtocolError {
    bad("decode")
}
const fn bad(message: &'static str) -> ProtocolError {
    ProtocolError::InvalidCbor(message)
}
