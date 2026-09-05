use minicbor::{Decoder, Encoder};

use crate::{
    ComponentRecord, InstructionRecord, MAX_CBOR_OPERATION_BYTES, MemoryCandidate, MemoryRecord,
    MutationKind, ProjectIdentity, ProtocolError, RecordId, RecordKind, SYNC_SCHEMA_VERSION,
    SecretRef, TaskRecord, ValidationError, uuid_v7_from_bytes,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordMutationV1 {
    UpsertMemory(MemoryRecord),
    UpsertMemoryCandidate(MemoryCandidate),
    UpsertTask(TaskRecord),
    UpsertSecretRef(SecretRef),
    UpsertInstruction(InstructionRecord),
    UpsertComponent(ComponentRecord),
    UpsertProject(ProjectIdentity),
    Tombstone {
        record_id: RecordId,
        record_kind: RecordKind,
    },
}

impl RecordMutationV1 {
    pub fn record_id(&self) -> RecordId {
        match self {
            Self::UpsertMemory(record) => record_id(record.id.into_uuid()),
            Self::UpsertMemoryCandidate(record) => record_id(record.id.into_uuid()),
            Self::UpsertTask(record) => record_id(record.id.into_uuid()),
            Self::UpsertSecretRef(record) => record_id(record.id.into_uuid()),
            Self::UpsertInstruction(record) => record.id,
            Self::UpsertComponent(record) => record.id,
            Self::UpsertProject(record) => record_id(record.project_id.into_uuid()),
            Self::Tombstone { record_id, .. } => *record_id,
        }
    }

    pub const fn record_kind(&self) -> RecordKind {
        match self {
            Self::UpsertMemory(_) => RecordKind::Memory,
            Self::UpsertMemoryCandidate(_) => RecordKind::MemoryCandidate,
            Self::UpsertTask(_) => RecordKind::Task,
            Self::UpsertSecretRef(_) => RecordKind::SecretRef,
            Self::UpsertInstruction(_) => RecordKind::Instruction,
            Self::UpsertComponent(_) => RecordKind::Component,
            Self::UpsertProject(_) => RecordKind::Project,
            Self::Tombstone { record_kind, .. } => *record_kind,
        }
    }

    pub const fn mutation_kind(&self) -> MutationKind {
        match self {
            Self::Tombstone { .. } => MutationKind::Tombstone,
            _ => MutationKind::Upsert,
        }
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Self::UpsertMemory(record) => record.validate(),
            Self::UpsertMemoryCandidate(record) => record.validate(),
            Self::UpsertTask(record) => record.validate(),
            Self::UpsertSecretRef(record) => record.validate(),
            Self::UpsertInstruction(record) => record.validate(),
            Self::UpsertComponent(record) => record.validate(),
            Self::UpsertProject(record) => record.validate(),
            Self::Tombstone { .. } => Ok(()),
        }
    }
}

pub fn encode_record_mutation_v1(mutation: &RecordMutationV1) -> Result<Vec<u8>, ProtocolError> {
    mutation.validate().map_err(|_| bad("invalid mutation"))?;
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(5).map_err(enc)?;
    key(&mut encoder, 0)?;
    encoder.u16(SYNC_SCHEMA_VERSION).map_err(enc)?;
    key(&mut encoder, 1)?;
    encoder
        .u8(record_kind_value(mutation.record_kind()))
        .map_err(enc)?;
    key(&mut encoder, 2)?;
    encoder
        .u8(mutation_kind_value(mutation.mutation_kind()))
        .map_err(enc)?;
    key(&mut encoder, 3)?;
    bytes(&mut encoder, mutation.record_id().as_bytes())?;
    key(&mut encoder, 4)?;
    match mutation {
        RecordMutationV1::Tombstone { .. } => {
            encoder.null().map_err(enc)?;
        }
        _ => bytes(&mut encoder, &canonical_json(mutation)?)?,
    }
    let output = encoder.into_writer();
    if output.len() > MAX_CBOR_OPERATION_BYTES {
        return Err(bad("mutation too large"));
    }
    Ok(output)
}

pub fn decode_record_mutation_v1(input: &[u8]) -> Result<RecordMutationV1, ProtocolError> {
    if input.len() > MAX_CBOR_OPERATION_BYTES {
        return Err(bad("mutation too large"));
    }
    let mut decoder = Decoder::new(input);
    require_map(&mut decoder, 5)?;
    expect_key(&mut decoder, 0)?;
    if decoder.u16().map_err(dec)? != SYNC_SCHEMA_VERSION {
        return Err(bad("unsupported schema"));
    }
    expect_key(&mut decoder, 1)?;
    let record_kind = decode_record_kind(decoder.u8().map_err(dec)?)?;
    expect_key(&mut decoder, 2)?;
    let mutation_kind = decode_mutation_kind(decoder.u8().map_err(dec)?)?;
    expect_key(&mut decoder, 3)?;
    let record_id = uuid_v7_from_bytes(decoder.bytes().map_err(dec)?, RecordId::new)
        .map_err(|_| bad("record id"))?;
    expect_key(&mut decoder, 4)?;
    let mutation = match mutation_kind {
        MutationKind::Upsert => {
            let payload = decoder.bytes().map_err(dec)?;
            decode_upsert(record_kind, payload)?
        }
        MutationKind::Tombstone => {
            decoder.null().map_err(dec)?;
            RecordMutationV1::Tombstone {
                record_id,
                record_kind,
            }
        }
    };
    if decoder.position() != input.len() {
        return Err(bad("trailing bytes"));
    }
    if mutation.record_kind() != record_kind
        || mutation.mutation_kind() != mutation_kind
        || mutation.record_id() != record_id
    {
        return Err(bad("mismatched mutation"));
    }
    mutation.validate().map_err(|_| bad("invalid mutation"))?;
    if encode_record_mutation_v1(&mutation)? != input {
        return Err(bad("noncanonical encoding"));
    }
    Ok(mutation)
}

fn decode_upsert(
    record_kind: RecordKind,
    payload: &[u8],
) -> Result<RecordMutationV1, ProtocolError> {
    match record_kind {
        RecordKind::Memory => decode_json(payload).map(RecordMutationV1::UpsertMemory),
        RecordKind::MemoryCandidate => {
            decode_json(payload).map(RecordMutationV1::UpsertMemoryCandidate)
        }
        RecordKind::Task => decode_json(payload).map(RecordMutationV1::UpsertTask),
        RecordKind::SecretRef => decode_json(payload).map(RecordMutationV1::UpsertSecretRef),
        RecordKind::Instruction => decode_json(payload).map(RecordMutationV1::UpsertInstruction),
        RecordKind::Component => decode_json(payload).map(RecordMutationV1::UpsertComponent),
        RecordKind::Project => decode_json(payload).map(RecordMutationV1::UpsertProject),
    }
}

fn canonical_json(mutation: &RecordMutationV1) -> Result<Vec<u8>, ProtocolError> {
    match mutation {
        RecordMutationV1::UpsertMemory(record) => encode_json(record),
        RecordMutationV1::UpsertMemoryCandidate(record) => encode_json(record),
        RecordMutationV1::UpsertTask(record) => encode_json(record),
        RecordMutationV1::UpsertSecretRef(record) => encode_json(record),
        RecordMutationV1::UpsertInstruction(record) => encode_json(record),
        RecordMutationV1::UpsertComponent(record) => encode_json(record),
        RecordMutationV1::UpsertProject(record) => encode_json(record),
        RecordMutationV1::Tombstone { .. } => unreachable!("tombstones have no JSON payload"),
    }
}

fn encode_json<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, ProtocolError> {
    serde_json::to_vec(value).map_err(|_| bad("json"))
}

fn decode_json<T: serde::de::DeserializeOwned>(payload: &[u8]) -> Result<T, ProtocolError> {
    serde_json::from_slice(payload).map_err(|_| bad("json"))
}

fn record_id(value: uuid::Uuid) -> RecordId {
    RecordId::new(value).expect("record source IDs are UUIDv7")
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

fn record_kind_value(value: RecordKind) -> u8 {
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

fn mutation_kind_value(value: MutationKind) -> u8 {
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
