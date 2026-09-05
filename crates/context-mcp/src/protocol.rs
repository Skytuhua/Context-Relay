use std::io::Write;

use context_relay_protocol::MAX_IPC_FRAME_BYTES;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt};

use crate::BridgeError;

pub const MCP_REVISION: &str = "2025-11-25";
pub const MCP_COMPAT_REVISION: &str = "2025-06-18";

pub const PARSE_ERROR: i64 = -32700;
pub const INVALID_REQUEST: i64 = -32600;
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const INVALID_PARAMS: i64 = -32602;

#[derive(Clone, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum RpcId {
    Number(i64),
    String(String),
}

#[derive(Debug)]
pub(crate) struct Request {
    pub id: Option<RpcId>,
    pub method: String,
    pub params: Option<Value>,
}

#[derive(Debug)]
pub(crate) enum ParsedMessage {
    Request(Request),
    InvalidRequest(Option<RpcId>),
    ParseError,
}

pub(crate) async fn read_message<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    buffer: &mut Vec<u8>,
) -> Result<Option<()>, BridgeError> {
    let Some(remaining) = (MAX_IPC_FRAME_BYTES + 2).checked_sub(buffer.len()) else {
        buffer.clear();
        return Err(BridgeError::FrameTooLarge);
    };
    if remaining == 0 {
        buffer.clear();
        return Err(BridgeError::FrameTooLarge);
    }
    let mut limited = (&mut *reader).take(remaining as u64);
    let read = limited.read_until(b'\n', buffer).await?;
    if read == 0 && buffer.is_empty() {
        return Ok(None);
    }
    if buffer.last() == Some(&b'\n') {
        buffer.pop();
        if buffer.last() == Some(&b'\r') {
            buffer.pop();
        }
    }
    if buffer.len() > MAX_IPC_FRAME_BYTES {
        buffer.clear();
        return Err(BridgeError::FrameTooLarge);
    }
    Ok(Some(()))
}

pub(crate) fn parse_message(bytes: &[u8]) -> ParsedMessage {
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        return ParsedMessage::ParseError;
    };
    let Value::Object(mut object) = value else {
        return ParsedMessage::InvalidRequest(None);
    };
    let id = match object.remove("id") {
        Some(value) => match serde_json::from_value(value) {
            Ok(id) => Some(id),
            Err(_) => return ParsedMessage::InvalidRequest(None),
        },
        None => None,
    };
    if object.remove("jsonrpc").as_ref() != Some(&Value::String("2.0".into())) {
        return ParsedMessage::InvalidRequest(id);
    }
    let Some(Value::String(method)) = object.remove("method") else {
        return ParsedMessage::InvalidRequest(id);
    };
    let params = object.remove("params");
    ParsedMessage::Request(Request { id, method, params })
}

pub(crate) fn success(id: RpcId, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

pub(crate) fn error(id: Option<RpcId>, code: i64, message: &'static str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id.map_or(Value::Null, |id| serde_json::to_value(id).expect("RPC ID serializes")),
        "error": {"code": code, "message": message}
    })
}

pub fn encode_message(message: &Value) -> Result<Vec<u8>, BridgeError> {
    let mut writer = BoundedWriter::default();
    serde_json::to_writer(&mut writer, message).map_err(|_| BridgeError::FrameTooLarge)?;
    writer.bytes.push(b'\n');
    Ok(writer.bytes)
}

#[derive(Default)]
struct BoundedWriter {
    bytes: Vec<u8>,
}

impl Write for BoundedWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if self.bytes.len().saturating_add(buffer.len()) > MAX_IPC_FRAME_BYTES {
            return Err(std::io::Error::other("MCP message exceeds limit"));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
