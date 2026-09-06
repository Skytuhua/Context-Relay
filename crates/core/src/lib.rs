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
