use context_relay_protocol::PROTOCOL_VERSION;

#[derive(Debug, PartialEq, Eq)]
pub struct HealthDescriptor {
    pub status: &'static str,
    pub protocol_version: u32,
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

    #[test]
    fn reports_the_pre_alpha_build_and_protocol_version() {
        assert_eq!(
            health_descriptor(),
            HealthDescriptor {
                status: "pre-alpha",
                protocol_version: 1,
            }
        );
    }
}
