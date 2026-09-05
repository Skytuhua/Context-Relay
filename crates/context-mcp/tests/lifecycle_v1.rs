use std::{
    future::{Future, ready},
    sync::{Arc, Mutex},
};

use context_relay_context_mcp::{
    BridgeError, Daemon, MCP_COMPAT_REVISION, MCP_REVISION, Server, encode_message,
};
use context_relay_protocol::{
    HarnessId, MAX_IPC_FRAME_BYTES, MCP_TOOL_NAMES, McpBinding, McpCallParams, NativePlatform,
    RecordId, WireNativeValue,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};

#[derive(Clone, Default)]
struct FakeDaemon {
    calls: Arc<Mutex<Vec<McpCallParams>>>,
}

impl FakeDaemon {
    fn call_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
}

impl Daemon for FakeDaemon {
    fn call(
        &self,
        _request_id: RecordId,
        call: McpCallParams,
    ) -> impl Future<Output = Result<Value, BridgeError>> + Send {
        self.calls.lock().unwrap().push(call.clone());
        ready(Ok(match call.name.as_str() {
            "context_relay_status" => json!({
                "protocol": {
                    "min": {"major": 1, "minor": 4},
                    "max": {"major": 1, "minor": 4}
                },
                "vault": "unlocked",
                "resolvedProject": null,
                "sync": "offline",
                "access": {"mode": "default"}
            }),
            _ => json!({}),
        }))
    }

    fn cancel(
        &self,
        _request_id: RecordId,
    ) -> impl Future<Output = Result<(), BridgeError>> + Send {
        ready(Ok(()))
    }
}

struct RunResult {
    result: Result<(), BridgeError>,
    output: Vec<u8>,
}

async fn run_server(daemon: FakeDaemon, input: Vec<u8>) -> RunResult {
    let (mut input_writer, input_reader) = tokio::io::duplex(64 * 1024);
    let (output_writer, mut output_reader) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(
        Server::new(daemon, binding()).run(BufReader::new(input_reader), output_writer),
    );
    let input_task = tokio::spawn(async move {
        let result = input_writer.write_all(&input).await;
        let _ = input_writer.shutdown().await;
        result
    });
    let mut output = Vec::new();
    output_reader.read_to_end(&mut output).await.unwrap();
    let result = server.await.unwrap();
    let _ = input_task.await.unwrap();
    RunResult { result, output }
}

fn binding() -> McpBinding {
    McpBinding {
        harness: HarnessId::Codex,
        working_directory: WireNativeValue {
            platform: if cfg!(windows) {
                NativePlatform::Windows
            } else {
                NativePlatform::Macos
            },
            bytes: if cfg!(windows) {
                b"C\0:\0\\\0w\0o\0r\0k\0".to_vec()
            } else {
                b"/work".to_vec()
            },
            display: None,
        },
    }
}

fn line(value: Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&value).unwrap();
    bytes.push(b'\n');
    bytes
}

fn lines(values: impl IntoIterator<Item = Value>) -> Vec<u8> {
    values.into_iter().flat_map(line).collect()
}

fn initialize(id: Value, revision: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "initialize",
        "params": {
            "protocolVersion": revision,
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1"}
        }
    })
}

fn initialized() -> Value {
    json!({"jsonrpc": "2.0", "method": "notifications/initialized"})
}

fn ready_input(requests: impl IntoIterator<Item = Value>) -> Vec<u8> {
    let mut values = vec![initialize(json!(1), MCP_REVISION), initialized()];
    values.extend(requests);
    lines(values)
}

fn parse_stdout_lines(output: &[u8]) -> Vec<Value> {
    assert!(output.is_empty() || output.ends_with(b"\n"));
    output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| {
            assert!(!line.contains(&b'\r'));
            serde_json::from_slice::<Value>(line).unwrap()
        })
        .collect()
}

#[tokio::test]
async fn initializes_then_lists_exact_frozen_tools() {
    let run = run_server(
        FakeDaemon::default(),
        ready_input([
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {}
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/list",
                "params": {"cursor": "context-relay-tools-v1:8"}
            }),
        ]),
    )
    .await;

    assert_eq!(run.result, Ok(()));
    let messages = parse_stdout_lines(&run.output);
    assert_eq!(messages[0]["result"]["protocolVersion"], MCP_REVISION);
    assert_eq!(
        messages[0]["result"]["capabilities"]["tools"]["listChanged"],
        false
    );
    assert_eq!(
        messages[1]["result"]["nextCursor"],
        "context-relay-tools-v1:8"
    );
    let tools = messages[1]["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .chain(messages[2]["result"]["tools"].as_array().unwrap())
        .collect::<Vec<_>>();
    let names = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(names, MCP_TOOL_NAMES);
    assert!(
        tools
            .iter()
            .all(|tool| tool["inputSchema"].is_object() && tool["outputSchema"].is_object())
    );
}

#[tokio::test]
async fn compatibility_revision_is_negotiated_exactly() {
    let run = run_server(
        FakeDaemon::default(),
        lines([initialize(json!("compat"), MCP_COMPAT_REVISION)]),
    )
    .await;

    assert_eq!(run.result, Ok(()));
    let messages = parse_stdout_lines(&run.output);
    assert_eq!(messages[0]["id"], "compat");
    assert_eq!(
        messages[0]["result"]["protocolVersion"],
        MCP_COMPAT_REVISION
    );
}

#[tokio::test]
async fn official_initialize_envelopes_accept_client_title_and_request_metadata() {
    for revision in [MCP_COMPAT_REVISION, MCP_REVISION] {
        let run = run_server(
            FakeDaemon::default(),
            lines([json!({
                "jsonrpc": "2.0",
                "id": revision,
                "method": "initialize",
                "params": {
                    "_meta": {
                        "progressToken": format!("initialize-{revision}"),
                        "com.example/clientTrace": "opaque"
                    },
                    "protocolVersion": revision,
                    "capabilities": {"experimental": {"com.example/feature": {}}},
                    "clientInfo": {
                        "name": "test",
                        "title": "Context Relay conformance client",
                        "version": "1",
                        "description": "Official MCP client metadata",
                        "icons": [{
                            "src": "https://example.test/icon.png",
                            "mimeType": "image/png",
                            "sizes": ["48x48"],
                            "theme": "dark"
                        }],
                        "websiteUrl": "https://example.test"
                    }
                }
            })]),
        )
        .await;

        assert_eq!(run.result, Ok(()));
        let messages = parse_stdout_lines(&run.output);
        assert_eq!(messages[0]["id"], revision);
        assert_eq!(messages[0]["result"]["protocolVersion"], revision);
    }
}

#[tokio::test]
async fn tools_list_uses_an_opaque_cursor_and_call_arguments_default_to_empty_object() {
    let daemon = FakeDaemon::default();
    let run = run_server(
        daemon.clone(),
        ready_input([
            json!({
                "jsonrpc": "2.0",
                "id": "first-page",
                "method": "tools/list",
                "params": {
                    "_meta": {"progressToken": 17, "com.example/trace": true}
                }
            }),
            json!({
                "jsonrpc": "2.0",
                "id": "second-page",
                "method": "tools/list",
                "params": {"cursor": "context-relay-tools-v1:8"}
            }),
            json!({
                "jsonrpc": "2.0",
                "id": "status",
                "method": "tools/call",
                "params": {
                    "_meta": {"progressToken": "status", "com.example/trace": true},
                    "name": "context_relay_status"
                }
            }),
        ]),
    )
    .await;

    assert_eq!(run.result, Ok(()));
    let messages = parse_stdout_lines(&run.output);
    let first = &messages[1]["result"];
    assert_eq!(first["tools"].as_array().unwrap().len(), 8);
    assert_eq!(first["nextCursor"], "context-relay-tools-v1:8");
    let second = &messages[2]["result"];
    assert_eq!(second["tools"].as_array().unwrap().len(), 3);
    assert!(second.get("nextCursor").is_none());
    assert_eq!(daemon.call_count(), 1);
    assert_eq!(messages[3]["result"]["isError"], false);
}

#[tokio::test]
async fn unsupported_revision_returns_invalid_params_and_does_not_initialize() {
    let run = run_server(
        FakeDaemon::default(),
        lines([
            initialize(json!(1), "2024-11-05"),
            json!({"jsonrpc": "2.0", "id": 2, "method": "ping"}),
        ]),
    )
    .await;

    assert_eq!(run.result, Ok(()));
    let messages = parse_stdout_lines(&run.output);
    assert_eq!(messages[0]["error"]["code"], -32602);
    assert_eq!(messages[1]["error"]["code"], -32600);
}

#[tokio::test]
async fn initialized_notification_is_required_before_tools_are_ready() {
    let run = run_server(
        FakeDaemon::default(),
        lines([
            initialize(json!(1), MCP_REVISION),
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
            initialized(),
            json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}}),
        ]),
    )
    .await;

    let messages = parse_stdout_lines(&run.output);
    assert_eq!(messages[1]["error"]["code"], -32600);
    assert_eq!(messages[2]["id"], 3);
    assert!(messages[2]["result"]["tools"].is_array());
}

#[tokio::test]
async fn ping_is_allowed_after_the_initialize_response() {
    let run = run_server(
        FakeDaemon::default(),
        lines([
            initialize(json!(1), MCP_REVISION),
            json!({"jsonrpc": "2.0", "id": "ping", "method": "ping"}),
        ]),
    )
    .await;

    let messages = parse_stdout_lines(&run.output);
    assert_eq!(
        messages[1],
        json!({"jsonrpc": "2.0", "id": "ping", "result": {}})
    );
}

#[tokio::test]
async fn unknown_methods_invalid_params_and_parse_errors_use_json_rpc_codes() {
    let run = run_server(
        FakeDaemon::default(),
        [
            ready_input([
                json!({"jsonrpc": "2.0", "id": 2, "method": "unknown", "params": {}}),
                json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {"extra": true}}),
            ]),
            b"{not json}\n".to_vec(),
        ]
        .concat(),
    )
    .await;

    let messages = parse_stdout_lines(&run.output);
    assert_eq!(messages[1]["error"]["code"], -32601);
    assert_eq!(messages[2]["error"]["code"], -32602);
    assert_eq!(messages[3]["id"], Value::Null);
    assert_eq!(messages[3]["error"]["code"], -32700);
}

#[tokio::test]
async fn notifications_never_receive_responses() {
    let run = run_server(
        FakeDaemon::default(),
        lines([
            initialize(json!(1), MCP_REVISION),
            initialized(),
            json!({"jsonrpc": "2.0", "method": "unknown", "params": {}}),
            json!({"jsonrpc": "2.0", "method": "tools/list", "params": {"extra": true}}),
            json!({"jsonrpc": "2.0", "method": "ping"}),
        ]),
    )
    .await;

    let messages = parse_stdout_lines(&run.output);
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["id"], 1);
}

#[tokio::test]
async fn rpc_ids_are_only_i64_integers_or_strings() {
    let run = run_server(
        FakeDaemon::default(),
        lines([
            initialize(json!(i64::MIN), MCP_REVISION),
            json!({"jsonrpc": "2.0", "id": i64::MAX, "method": "ping"}),
            json!({"jsonrpc": "2.0", "id": 1.5, "method": "ping"}),
            json!({"jsonrpc": "2.0", "id": null, "method": "ping"}),
            json!({"jsonrpc": "2.0", "id": u64::MAX, "method": "ping"}),
        ]),
    )
    .await;

    let messages = parse_stdout_lines(&run.output);
    assert_eq!(messages[0]["id"], i64::MIN);
    assert_eq!(messages[1]["id"], i64::MAX);
    assert_eq!(messages[2]["id"], Value::Null);
    assert_eq!(messages[2]["error"]["code"], -32600);
    assert_eq!(messages[3]["id"], Value::Null);
    assert_eq!(messages[4]["id"], Value::Null);
}

#[tokio::test]
async fn tools_call_validates_and_dispatches_a_scoped_call() {
    let daemon = FakeDaemon::default();
    let run = run_server(
        daemon.clone(),
        ready_input([json!({
            "jsonrpc": "2.0",
            "id": "status",
            "method": "tools/call",
            "params": {"name": "context_relay_status", "arguments": {}}
        })]),
    )
    .await;

    let messages = parse_stdout_lines(&run.output);
    assert_eq!(daemon.call_count(), 1);
    let result = &messages[1]["result"];
    assert_eq!(result["isError"], false);
    assert_eq!(
        result["structuredContent"]["vault"],
        Value::String("unlocked".into())
    );
    let text: Value = serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(text, result["structuredContent"]);
}

#[tokio::test]
async fn unknown_tools_and_invalid_fixtures_are_rejected_before_dispatch() {
    let daemon = FakeDaemon::default();
    let run = run_server(
        daemon.clone(),
        ready_input([
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "not_a_tool", "arguments": {}}
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "context_relay_status", "arguments": {"extra": true}}
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "context_relay_status", "arguments": {}, "extra": true}
            }),
        ]),
    )
    .await;

    let messages = parse_stdout_lines(&run.output);
    assert_eq!(daemon.call_count(), 0);
    assert_eq!(messages[1]["error"]["code"], -32602);
    assert_eq!(messages[2]["error"]["code"], -32602);
    assert_eq!(messages[3]["error"]["code"], -32602);
}

#[tokio::test]
async fn exact_input_bound_and_crlf_are_accepted() {
    let mut exact = b"{}".to_vec();
    exact.resize(MAX_IPC_FRAME_BYTES, b' ');
    exact.extend_from_slice(b"\r\n");
    let run = run_server(FakeDaemon::default(), exact).await;

    assert_eq!(run.result, Ok(()));
    let messages = parse_stdout_lines(&run.output);
    assert_eq!(messages[0]["error"]["code"], -32600);
}

#[tokio::test]
async fn oversized_input_is_rejected_without_unbounded_reading() {
    let mut oversized = b"{}".to_vec();
    oversized.resize(MAX_IPC_FRAME_BYTES + 1, b' ');
    oversized.push(b'\n');
    let run = run_server(FakeDaemon::default(), oversized).await;

    assert_eq!(run.result, Err(BridgeError::FrameTooLarge));
    assert!(run.output.is_empty());
}

#[test]
fn compact_output_is_bounded_and_has_exactly_one_line_feed() {
    let empty_size = serde_json::to_vec(&json!({"value": ""})).unwrap().len();
    let exact = json!({"value": "x".repeat(MAX_IPC_FRAME_BYTES - empty_size)});
    let encoded = encode_message(&exact).unwrap();
    assert_eq!(encoded.len(), MAX_IPC_FRAME_BYTES + 1);
    assert_eq!(encoded.last(), Some(&b'\n'));
    assert!(!encoded[..encoded.len() - 1].contains(&b'\n'));

    let oversized = json!({"value": "x".repeat(MAX_IPC_FRAME_BYTES - empty_size + 1)});
    assert_eq!(encode_message(&oversized), Err(BridgeError::FrameTooLarge));
}

#[test]
fn content_newlines_are_escaped_in_compact_output() {
    let encoded = encode_message(&json!({"text": "first\nsecond"})).unwrap();

    assert_eq!(encoded.iter().filter(|byte| **byte == b'\n').count(), 1);
    assert!(encoded.windows(2).any(|window| window == br"\n"));
    assert_eq!(
        serde_json::from_slice::<Value>(&encoded[..encoded.len() - 1]).unwrap(),
        json!({
            "text": "first\nsecond"
        })
    );
}

#[tokio::test]
async fn empty_eof_exits_without_output() {
    let run = run_server(FakeDaemon::default(), Vec::new()).await;

    assert_eq!(run.result, Ok(()));
    assert!(run.output.is_empty());
}
