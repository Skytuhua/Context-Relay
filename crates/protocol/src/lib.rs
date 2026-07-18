pub mod adapters;
pub mod canonical_cbor;
pub mod clock;
pub mod digests;
pub mod domain;
pub mod error;
pub mod ids;
pub mod ipc;
pub mod mcp;
pub mod packages;
pub mod sync;
pub mod validation;

pub use adapters::*;
pub use canonical_cbor::*;
pub use clock::*;
pub use digests::*;
pub use domain::*;
pub use error::*;
pub use ids::*;
pub use ipc::*;
pub use mcp::*;
pub use packages::*;
pub use sync::*;
pub use validation::*;

use serde::{Deserialize, Serialize};
use ts_rs::TS;

pub const PROTOCOL_MAJOR: u16 = 1;
pub const PROTOCOL_MINOR: u16 = 0;
pub const SYNC_SCHEMA_VERSION: u16 = 1;
pub const MAX_IPC_FRAME_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ProtocolVersionRange {
    pub min: ProtocolVersion,
    pub max: ProtocolVersion,
}

pub const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion {
    major: PROTOCOL_MAJOR,
    minor: PROTOCOL_MINOR,
};

pub fn negotiate_version(
    local: ProtocolVersionRange,
    peer: ProtocolVersionRange,
) -> Result<ProtocolVersion, ProtocolError> {
    if local.min.major != PROTOCOL_MAJOR
        || local.min.major != local.max.major
        || peer.min.major != peer.max.major
        || local.min.major != peer.min.major
    {
        return Err(ProtocolError::ProtocolVersionUnsupported);
    }
    let min = local.min.minor.max(peer.min.minor);
    let max = local.max.minor.min(peer.max.minor);
    (min <= max)
        .then_some(ProtocolVersion {
            major: local.min.major,
            minor: max,
        })
        .ok_or(ProtocolError::ProtocolVersionUnsupported)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ProtocolInfo {
    pub protocol_version: ProtocolVersion,
}
