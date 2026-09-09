pub mod auth;
pub mod claude_code;
pub mod codex;
pub mod crypto;
pub mod devices;
pub mod hermes;
pub mod mcp;
pub mod native_memory;
pub mod native_transaction;
pub mod search;
pub mod service;
pub mod setup;
pub mod sync;
pub mod vault;

#[cfg(all(test, windows))]
mod test_windows_process;

use context_relay_protocol::{PROTOCOL_VERSION, ProtocolVersion};

#[derive(Debug, PartialEq, Eq)]
pub struct HealthDescriptor {
    pub status: &'static str,
    pub protocol_version: ProtocolVersion,
}

pub fn health_descriptor() -> HealthDescriptor {
    HealthDescriptor {
        status: "pre-alpha",
        protocol_version: PROTOCOL_VERSION,
    }
}

pub(crate) fn derived_record_uuid(source: &[u8; 16], domain: &[u8]) -> Option<uuid::Uuid> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(source);
    let digest = hasher.finalize();
    let mut bytes = *source;
    bytes[6..].copy_from_slice(&digest[..10]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    (&bytes != source).then(|| uuid::Uuid::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::{HealthDescriptor, health_descriptor};
    use context_relay_protocol::PROTOCOL_VERSION;

    #[test]
    fn reports_the_pre_alpha_build_and_protocol_version() {
        assert_eq!(
            health_descriptor(),
            HealthDescriptor {
                status: "pre-alpha",
                protocol_version: PROTOCOL_VERSION
            }
        );
    }
}
