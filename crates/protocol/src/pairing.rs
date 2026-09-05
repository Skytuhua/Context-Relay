use minicbor::{Decoder, Encoder};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{
    DeviceId, Ed25519PublicKeyBytes, Ed25519SignatureBytes, MAX_TITLE_BYTES, NativePlatform,
    PairingId, PairingRequestNonce, ProtocolError, X25519PublicKeyBytes, required_text,
    uuid_v7_from_bytes,
};

pub const PAIRING_SCHEMA_VERSION: u16 = 1;
pub const MAX_PAIRING_REQUEST_BYTES: usize = 8 * 1024;

const PAIRING_REQUEST_SIGNING_DOMAIN_V1: &[u8] = b"context-relay/pairing-request/v1\0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct PairingRequestV1 {
    pub schema_version: u16,
    pub pairing_id: PairingId,
    pub request_nonce: PairingRequestNonce,
    pub device_id: DeviceId,
    pub device_name: String,
    pub platform: NativePlatform,
    pub signing_public_key: Ed25519PublicKeyBytes,
    pub wrapping_public_key: X25519PublicKeyBytes,
    pub signature: Ed25519SignatureBytes,
}

impl PairingRequestV1 {
    pub fn validate(&self) -> Result<(), crate::ValidationError> {
        if self.schema_version != PAIRING_SCHEMA_VERSION {
            return Err(crate::ValidationError::Invalid("schemaVersion"));
        }
        required_text(&self.device_name, "deviceName", MAX_TITLE_BYTES)
    }
}

pub fn encode_pairing_request_v1(request: &PairingRequestV1) -> Result<Vec<u8>, ProtocolError> {
    validate_request(request)?;
    let output = encode_request_map(request, true)?;
    if output.len() > MAX_PAIRING_REQUEST_BYTES {
        return Err(bad("pairing request too large"));
    }
    Ok(output)
}

pub fn encode_pairing_request_signing_preimage_v1(
    request: &PairingRequestV1,
) -> Result<Vec<u8>, ProtocolError> {
    validate_request(request)?;
    let map = encode_request_map(request, false)?;
    let mut output = Vec::with_capacity(PAIRING_REQUEST_SIGNING_DOMAIN_V1.len() + map.len());
    output.extend_from_slice(PAIRING_REQUEST_SIGNING_DOMAIN_V1);
    output.extend_from_slice(&map);
    Ok(output)
}

pub fn decode_pairing_request_v1(input: &[u8]) -> Result<PairingRequestV1, ProtocolError> {
    if input.len() > MAX_PAIRING_REQUEST_BYTES {
        return Err(bad("pairing request too large"));
    }

    let mut decoder = Decoder::new(input);
    require_map(&mut decoder, 9)?;
    expect_key(&mut decoder, 0)?;
    let schema_version = decoder.u16().map_err(dec)?;
    if schema_version != PAIRING_SCHEMA_VERSION {
        return Err(bad("unsupported schema"));
    }
    expect_key(&mut decoder, 1)?;
    let pairing_id = uuid_v7_from_bytes(decoder.bytes().map_err(dec)?, PairingId::new)
        .map_err(|_| bad("pairing id"))?;
    expect_key(&mut decoder, 2)?;
    let request_nonce = PairingRequestNonce(read_fixed::<32>(&mut decoder)?);
    expect_key(&mut decoder, 3)?;
    let device_id = uuid_v7_from_bytes(decoder.bytes().map_err(dec)?, DeviceId::new)
        .map_err(|_| bad("device id"))?;
    expect_key(&mut decoder, 4)?;
    let device_name = decoder.str().map_err(dec)?;
    if device_name.len() > MAX_TITLE_BYTES {
        return Err(bad("device name"));
    }
    let device_name = device_name.to_owned();
    expect_key(&mut decoder, 5)?;
    let platform = decode_platform(decoder.u8().map_err(dec)?)?;
    expect_key(&mut decoder, 6)?;
    let signing_public_key = Ed25519PublicKeyBytes(read_fixed::<32>(&mut decoder)?);
    expect_key(&mut decoder, 7)?;
    let wrapping_public_key = X25519PublicKeyBytes(read_fixed::<32>(&mut decoder)?);
    expect_key(&mut decoder, 8)?;
    let signature = Ed25519SignatureBytes(read_fixed::<64>(&mut decoder)?);
    if decoder.position() != input.len() {
        return Err(bad("trailing bytes"));
    }

    let request = PairingRequestV1 {
        schema_version,
        pairing_id,
        request_nonce,
        device_id,
        device_name,
        platform,
        signing_public_key,
        wrapping_public_key,
        signature,
    };
    validate_request(&request)?;
    if encode_pairing_request_v1(&request)? != input {
        return Err(bad("noncanonical encoding"));
    }
    Ok(request)
}

fn encode_request_map(
    request: &PairingRequestV1,
    include_signature: bool,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .map(if include_signature { 9 } else { 8 })
        .map_err(enc)?;
    key(&mut encoder, 0)?;
    encoder.u16(request.schema_version).map_err(enc)?;
    key(&mut encoder, 1)?;
    bytes(&mut encoder, request.pairing_id.as_bytes())?;
    key(&mut encoder, 2)?;
    bytes(&mut encoder, &request.request_nonce.0)?;
    key(&mut encoder, 3)?;
    bytes(&mut encoder, request.device_id.as_bytes())?;
    key(&mut encoder, 4)?;
    encoder.str(&request.device_name).map_err(enc)?;
    key(&mut encoder, 5)?;
    encoder.u8(encode_platform(request.platform)).map_err(enc)?;
    key(&mut encoder, 6)?;
    bytes(&mut encoder, &request.signing_public_key.0)?;
    key(&mut encoder, 7)?;
    bytes(&mut encoder, &request.wrapping_public_key.0)?;
    if include_signature {
        key(&mut encoder, 8)?;
        bytes(&mut encoder, &request.signature.0)?;
    }
    Ok(encoder.into_writer())
}

fn validate_request(request: &PairingRequestV1) -> Result<(), ProtocolError> {
    request
        .validate()
        .map_err(|_| bad("invalid pairing request"))
}

fn encode_platform(platform: NativePlatform) -> u8 {
    match platform {
        NativePlatform::Windows => 0,
        NativePlatform::Macos => 1,
    }
}

fn decode_platform(value: u8) -> Result<NativePlatform, ProtocolError> {
    match value {
        0 => Ok(NativePlatform::Windows),
        1 => Ok(NativePlatform::Macos),
        _ => Err(bad("platform")),
    }
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

fn bad(message: &'static str) -> ProtocolError {
    ProtocolError::InvalidCbor(message)
}

fn enc(error: minicbor::encode::Error<std::convert::Infallible>) -> ProtocolError {
    let _ = error;
    bad("encode")
}

fn dec(error: minicbor::decode::Error) -> ProtocolError {
    let _ = error;
    bad("decode")
}
