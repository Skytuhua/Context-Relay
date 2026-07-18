use serde::Serialize;
use ts_rs::TS;

pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub struct ProtocolInfo {
    pub protocol_version: u32,
}

#[cfg(test)]
mod tests {
    use super::{PROTOCOL_VERSION, ProtocolInfo};

    #[test]
    fn serializes_the_protocol_version_for_ipc() {
        let json = serde_json::to_string(&ProtocolInfo {
            protocol_version: PROTOCOL_VERSION,
        })
        .expect("protocol info should serialize");

        assert_eq!(json, r#"{"protocolVersion":1}"#);
    }
}
