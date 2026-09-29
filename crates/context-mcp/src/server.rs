use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use context_relay_local_ipc::{REQUEST_TIMEOUT, SHUTDOWN_TIMEOUT};
use context_relay_protocol::{
    ClientError, ErrorCode, MCP_TOOL_NAMES, McpBinding, McpCallParams, RecordId, mcp_schema,
    validate_mcp_fixture,
};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use tokio::{
    io::{AsyncBufRead, AsyncWrite, AsyncWriteExt},
    sync::{OwnedSemaphorePermit, Semaphore, mpsc},
    task::JoinSet,
    time::{Instant, sleep_until, timeout, timeout_at},
};
use uuid::Uuid;

use crate::{
    BridgeError, Daemon,
    protocol::{
        INVALID_PARAMS, INVALID_REQUEST, MCP_COMPAT_REVISION, MCP_REVISION, METHOD_NOT_FOUND,
        PARSE_ERROR, ParsedMessage, Request, RpcId, encode_message, error, parse_message,
        read_message, success,
    },
};

pub const MAX_IN_FLIGHT_TOOL_CALLS: usize = 64;
pub const TOOL_CALL_RATE_BURST: usize = 64;
pub const TOOL_CALL_RATE_REFILL_PER_SECOND: usize = 16;
const WRITER_QUEUE_CAPACITY: usize = MAX_IN_FLIGHT_TOOL_CALLS + 16;
const LEGACY_TOOLS_SECOND_PAGE_START: usize = 8;
const TOOLS_SECOND_PAGE_CURSOR: &str = "context-relay-tools-v1:8";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Lifecycle {
    AwaitInitialize,
    AwaitInitialized,
    Ready,
}

pub struct Server<D> {
    daemon: D,
    binding: McpBinding,
    lifecycle: Lifecycle,
    active: Arc<Mutex<HashMap<RpcId, ActiveCall>>>,
    call_permits: Arc<Semaphore>,
    cancel_permits: Arc<Semaphore>,
    rate_limit: Mutex<ToolCallRateLimit>,
}

impl<D: Daemon> Server<D> {
    pub fn new(daemon: D, binding: McpBinding) -> Self {
        Self {
            daemon,
            binding,
            lifecycle: Lifecycle::AwaitInitialize,
            active: Arc::default(),
            call_permits: Arc::new(Semaphore::new(MAX_IN_FLIGHT_TOOL_CALLS)),
            cancel_permits: Arc::new(Semaphore::new(MAX_IN_FLIGHT_TOOL_CALLS)),
            rate_limit: Mutex::new(ToolCallRateLimit::new(Instant::now())),
        }
    }

    pub async fn run<R, W>(mut self, mut reader: R, writer: W) -> Result<(), BridgeError>
    where
        R: AsyncBufRead + Unpin,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let (writer_sender, writer_receiver) = mpsc::channel(WRITER_QUEUE_CAPACITY);
        let mut writer_task = tokio::spawn(write_messages(writer, writer_receiver));
        let mut writer_joined = false;
        let mut writer_outcome = None;
        let mut tasks = JoinSet::new();
        let mut cleanup_deadline = None;
        let mut read_buffer = Vec::new();

        let loop_outcome = 'requests: loop {
            let read = tokio::select! {
                biased;
                result = &mut writer_task => {
                    writer_joined = true;
                    writer_outcome = Some(result.map_err(|_| BridgeError::Io).and_then(|result| result));
                    break Ok(());
                }
                result = read_message(&mut reader, &mut read_buffer) => result,
            };
            match read {
                Ok(Some(())) => {}
                Ok(None) => break Ok(()),
                Err(error) => break Err(error),
            }
            while tasks.try_join_next().is_some() {}
            let message = parse_message(&read_buffer);
            read_buffer.clear();
            let response = match message {
                ParsedMessage::ParseError => Some(error(None, PARSE_ERROR, "Parse error")),
                ParsedMessage::InvalidRequest(id) => {
                    Some(error(id, INVALID_REQUEST, "Invalid request"))
                }
                ParsedMessage::Request(request) => {
                    self.handle(request, &writer_sender, &mut tasks).await
                }
            };
            if let Some(response) = response {
                let encoded = match encode_message(&response) {
                    Ok(encoded) => encoded,
                    Err(error) => break Err(error),
                };
                let mut pending = match writer_sender.try_send(encoded) {
                    Ok(()) => continue,
                    Err(mpsc::error::TrySendError::Closed(_)) => break Err(BridgeError::Io),
                    Err(mpsc::error::TrySendError::Full(encoded)) => Some(encoded),
                };
                let backpressure_deadline = Instant::now() + SHUTDOWN_TIMEOUT;
                'backpressure: loop {
                    while tasks.try_join_next().is_some() {}
                    tokio::select! {
                        biased;
                        result = &mut writer_task => {
                            writer_joined = true;
                            writer_outcome =
                                Some(result.map_err(|_| BridgeError::Io).and_then(|result| result));
                            cleanup_deadline = Some(backpressure_deadline);
                            break 'requests Ok(());
                        }
                        permit = writer_sender.reserve() => {
                            match permit {
                                Ok(permit) => {
                                    permit.send(pending.take().expect("response is pending"));
                                    break 'backpressure;
                                }
                                Err(_) => {
                                    cleanup_deadline = Some(backpressure_deadline);
                                    break 'requests Err(BridgeError::Io);
                                }
                            }
                        }
                        _ = sleep_until(backpressure_deadline) => {
                            cleanup_deadline = Some(backpressure_deadline);
                            break 'requests Ok(());
                        }
                        read = read_message(&mut reader, &mut read_buffer) => {
                            match read {
                                Ok(Some(())) => {
                                    let canceled =
                                        self.handle_backpressured_cancel(&read_buffer, &mut tasks);
                                    read_buffer.clear();
                                    if !canceled {
                                        cleanup_deadline = Some(backpressure_deadline);
                                        break 'requests Err(BridgeError::Io);
                                    }
                                }
                                Ok(None) => {
                                    cleanup_deadline = Some(backpressure_deadline);
                                    break 'requests Ok(());
                                }
                                Err(error) => {
                                    cleanup_deadline = Some(backpressure_deadline);
                                    break 'requests Err(error);
                                }
                            }
                        }
                    }
                }
            }
        };

        let shutdown_deadline =
            cleanup_deadline.unwrap_or_else(|| Instant::now() + SHUTDOWN_TIMEOUT);
        if timeout_at(shutdown_deadline, async {
            while tasks.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        }
        drop(writer_sender);
        if !writer_joined {
            writer_outcome = Some(
                match timeout_at(shutdown_deadline, &mut writer_task).await {
                    Ok(result) => result
                        .map_err(|_| BridgeError::Io)
                        .and_then(|result| result),
                    Err(_) => {
                        writer_task.abort();
                        let _ = writer_task.await;
                        Ok(())
                    }
                },
            );
        }
        match loop_outcome {
            Err(error) => Err(error),
            Ok(()) => match writer_outcome {
                Some(outcome) => outcome,
                None => Ok(()),
            },
        }
    }

    async fn handle(
        &mut self,
        request: Request,
        writer: &mpsc::Sender<Vec<u8>>,
        tasks: &mut JoinSet<()>,
    ) -> Option<Value> {
        if let Some(id) = request.id.as_ref()
            && self.active.lock().unwrap().contains_key(id)
        {
            return Some(error(
                Some(id.clone()),
                INVALID_REQUEST,
                "A request with this ID is already active",
            ));
        }
        match request.method.as_str() {
            "initialize" => self.initialize(request),
            "notifications/initialized" => self.initialized(request),
            "notifications/cancelled" => self.cancelled(request, tasks),
            "ping" => self.ping(request),
            "tools/list" => self.list_tools(request),
            "tools/call" => self.call_tool(request, writer, tasks),
            _ => request
                .id
                .map(|id| error(Some(id), METHOD_NOT_FOUND, "Method not found")),
        }
    }

    fn initialize(&mut self, request: Request) -> Option<Value> {
        let id = request.id?;
        if self.lifecycle != Lifecycle::AwaitInitialize {
            return Some(error(
                Some(id),
                INVALID_REQUEST,
                "Initialize is not allowed in the current state",
            ));
        }
        let Some(params) = parse_params::<InitializeParams>(request.params) else {
            return Some(error(Some(id), INVALID_PARAMS, "Invalid initialize params"));
        };
        if !valid_request_meta(params.meta.as_ref())
            || !params.capabilities.is_object()
            || !params.client_info.is_valid()
        {
            return Some(error(Some(id), INVALID_PARAMS, "Invalid initialize params"));
        }
        let revision = match params.protocol_version.as_str() {
            MCP_REVISION => MCP_REVISION,
            MCP_COMPAT_REVISION => MCP_COMPAT_REVISION,
            _ => {
                return Some(error(
                    Some(id),
                    INVALID_PARAMS,
                    "Unsupported protocol version",
                ));
            }
        };
        self.lifecycle = Lifecycle::AwaitInitialized;
        Some(success(
            id,
            json!({
                "protocolVersion": revision,
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": {
                    "name": "context-relay",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }),
        ))
    }

    fn initialized(&mut self, request: Request) -> Option<Value> {
        if let Some(id) = request.id {
            return Some(error(
                Some(id),
                INVALID_REQUEST,
                "Initialized must be a notification",
            ));
        }
        if self.lifecycle == Lifecycle::AwaitInitialized
            && parse_empty_request_params(request.params).is_some()
        {
            self.lifecycle = Lifecycle::Ready;
        }
        None
    }

    fn cancelled(&self, request: Request, tasks: &mut JoinSet<()>) -> Option<Value> {
        if let Some(id) = request.id {
            return Some(error(
                Some(id),
                INVALID_REQUEST,
                "Cancelled must be a notification",
            ));
        }
        if let Some(CancelledParams {
            request_id,
            reason,
            meta,
        }) = parse_params::<CancelledParams>(request.params)
            && valid_request_meta(meta.as_ref())
        {
            let _ = reason;
            let cancellation = {
                let mut active = self.active.lock().unwrap();
                active.get_mut(&request_id).and_then(|call| {
                    call.canceled.store(true, Ordering::SeqCst);
                    if call.cancel_dispatched {
                        None
                    } else {
                        call.cancel_dispatched = true;
                        Some((
                            call.local_id,
                            call.cancel_permit
                                .take()
                                .expect("admitted call reserves cancellation capacity"),
                        ))
                    }
                })
            };
            if let Some((local_id, cancel_permit)) = cancellation {
                let daemon = self.daemon.clone();
                tasks.spawn(async move {
                    let _cancel_permit = cancel_permit;
                    let _ = daemon.cancel(local_id).await;
                });
            }
        }
        None
    }

    fn handle_backpressured_cancel(&self, bytes: &[u8], tasks: &mut JoinSet<()>) -> bool {
        let ParsedMessage::Request(request) = parse_message(bytes) else {
            return false;
        };
        if request.id.is_some() || request.method != "notifications/cancelled" {
            return false;
        }
        let response = self.cancelled(request, tasks);
        debug_assert!(response.is_none());
        true
    }

    fn ping(&self, request: Request) -> Option<Value> {
        let id = request.id?;
        if parse_empty_request_params(request.params).is_none() {
            return Some(error(Some(id), INVALID_PARAMS, "Invalid ping params"));
        }
        match self.lifecycle {
            Lifecycle::AwaitInitialize => Some(error(
                Some(id),
                INVALID_REQUEST,
                "Ping is not allowed before initialize",
            )),
            Lifecycle::AwaitInitialized | Lifecycle::Ready => Some(success(id, json!({}))),
        }
    }

    fn list_tools(&self, request: Request) -> Option<Value> {
        let id = request.id?;
        if self.lifecycle != Lifecycle::Ready {
            return Some(error(Some(id), INVALID_REQUEST, "Tools are not ready"));
        }
        let Some(params) = parse_optional_params::<ListToolsParams>(request.params) else {
            return Some(error(Some(id), INVALID_PARAMS, "Invalid tools/list params"));
        };
        if !valid_request_meta(params.meta.as_ref()) {
            return Some(error(Some(id), INVALID_PARAMS, "Invalid tools/list params"));
        }
        // All eleven tools fit in one bounded response. Native Codex currently
        // exposes only the first page, so paging hid completion, handoff and
        // status. Retain the old opaque cursor for clients already holding it.
        let start = match params.cursor.as_deref() {
            None => 0,
            Some(TOOLS_SECOND_PAGE_CURSOR) => LEGACY_TOOLS_SECOND_PAGE_START,
            Some(_) => {
                return Some(error(Some(id), INVALID_PARAMS, "Invalid tools/list cursor"));
            }
        };
        let tools = MCP_TOOL_NAMES[start..]
            .iter()
            .map(|name| {
                let schema = mcp_schema(name).expect("frozen tool has schema");
                json!({
                    "name": name,
                    "inputSchema": schema.input,
                    "outputSchema": schema.output
                })
            })
            .collect::<Vec<_>>();
        Some(success(id, json!({"tools": tools})))
    }

    fn call_tool(
        &self,
        request: Request,
        writer: &mpsc::Sender<Vec<u8>>,
        tasks: &mut JoinSet<()>,
    ) -> Option<Value> {
        let id = request.id?;
        if self.lifecycle != Lifecycle::Ready {
            return Some(error(Some(id), INVALID_REQUEST, "Tools are not ready"));
        }
        let Some(params) = parse_params::<CallToolParams>(request.params) else {
            return Some(error(Some(id), INVALID_PARAMS, "Invalid tools/call params"));
        };
        if !valid_request_meta(params.meta.as_ref()) {
            return Some(error(Some(id), INVALID_PARAMS, "Invalid tools/call params"));
        }
        let arguments = Value::Object(params.arguments);
        if mcp_schema(&params.name).is_none()
            || validate_mcp_fixture(&params.name, true, &arguments).is_err()
        {
            return Some(error(Some(id), INVALID_PARAMS, "Invalid tools/call params"));
        }
        if !self.rate_limit.lock().unwrap().admit(Instant::now()) {
            return Some(tool_error(id, &busy_error()));
        }
        let request_id = RecordId::new(Uuid::now_v7()).expect("UUIDv7 generator");
        let call = McpCallParams {
            binding: self.binding.clone(),
            name: params.name.clone(),
            arguments,
        };

        let (call_permit, canceled) = {
            let mut active = self.active.lock().unwrap();
            if active.contains_key(&id) {
                return Some(error(
                    Some(id),
                    INVALID_REQUEST,
                    "A request with this ID is already active",
                ));
            }
            let Ok(call_permit) = Arc::clone(&self.call_permits).try_acquire_owned() else {
                return Some(tool_error(id, &busy_error()));
            };
            let Ok(cancel_permit) = Arc::clone(&self.cancel_permits).try_acquire_owned() else {
                return Some(tool_error(id, &busy_error()));
            };
            let canceled = Arc::new(AtomicBool::new(false));
            active.insert(
                id.clone(),
                ActiveCall {
                    local_id: request_id,
                    canceled: Arc::clone(&canceled),
                    cancel_dispatched: false,
                    cancel_permit: Some(cancel_permit),
                },
            );
            (call_permit, canceled)
        };

        let daemon = self.daemon.clone();
        let active = Arc::clone(&self.active);
        let writer = writer.clone();
        tasks.spawn(async move {
            dispatch_call(
                daemon,
                active,
                writer,
                id,
                request_id,
                params.name,
                call,
                canceled,
                call_permit,
            )
            .await;
        });
        None
    }
}

struct ToolCallRateLimit {
    credit_nanos: u128,
    last_refill: Instant,
}

impl ToolCallRateLimit {
    const TOKEN_NANOS: u128 = 1_000_000_000;

    fn new(now: Instant) -> Self {
        Self {
            credit_nanos: TOOL_CALL_RATE_BURST as u128 * Self::TOKEN_NANOS,
            last_refill: now,
        }
    }

    fn admit(&mut self, now: Instant) -> bool {
        let elapsed_nanos = now.duration_since(self.last_refill).as_nanos();
        let refill = elapsed_nanos.saturating_mul(TOOL_CALL_RATE_REFILL_PER_SECOND as u128);
        self.credit_nanos = self
            .credit_nanos
            .saturating_add(refill)
            .min(TOOL_CALL_RATE_BURST as u128 * Self::TOKEN_NANOS);
        self.last_refill = now;
        if self.credit_nanos < Self::TOKEN_NANOS {
            return false;
        }
        self.credit_nanos -= Self::TOKEN_NANOS;
        true
    }
}

struct ActiveCall {
    local_id: RecordId,
    canceled: Arc<AtomicBool>,
    cancel_dispatched: bool,
    cancel_permit: Option<OwnedSemaphorePermit>,
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_call<D: Daemon>(
    daemon: D,
    active: Arc<Mutex<HashMap<RpcId, ActiveCall>>>,
    writer: mpsc::Sender<Vec<u8>>,
    rpc_id: RpcId,
    request_id: RecordId,
    tool_name: String,
    call: McpCallParams,
    canceled: Arc<AtomicBool>,
    _call_permit: OwnedSemaphorePermit,
) {
    let result = match timeout(REQUEST_TIMEOUT, daemon.call(request_id, call)).await {
        Ok(Ok(output)) if validate_mcp_fixture(&tool_name, false, &output).is_ok() => {
            match serde_json::to_string(&output) {
                Ok(text) => json!({
                    "content": [{"type": "text", "text": text}],
                    "structuredContent": output,
                    "isError": false
                }),
                Err(_) => tool_error_result(&invalid_output_error()),
            }
        }
        Ok(Ok(_)) => tool_error_result(&invalid_output_error()),
        Ok(Err(error)) => tool_error_result(&error),
        Err(_) => tool_error_result(&timeout_error()),
    };
    let response = success(rpc_id.clone(), result);
    let mut encoded = encode_message(&response)
        .or_else(|_| {
            encode_message(&success(
                rpc_id.clone(),
                tool_error_result(&BridgeError::FrameTooLarge),
            ))
        })
        .ok();
    let mut writer_permit = writer.reserve().await.ok();
    {
        let mut active = active.lock().unwrap();
        let still_current = active
            .get(&rpc_id)
            .is_some_and(|call| call.local_id == request_id);
        if still_current
            && !canceled.load(Ordering::SeqCst)
            && let (Some(writer_permit), Some(encoded)) = (writer_permit.take(), encoded.take())
        {
            writer_permit.send(encoded);
        }
        if still_current {
            active.remove(&rpc_id);
        }
    }
}

async fn write_messages<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut receiver: mpsc::Receiver<Vec<u8>>,
) -> Result<(), BridgeError> {
    while let Some(message) = receiver.recv().await {
        writer.write_all(&message).await?;
    }
    writer.flush().await?;
    Ok(())
}

fn busy_error() -> BridgeError {
    BridgeError::Client(ClientError {
        code: ErrorCode::Busy,
        message: "The local service is busy".into(),
        field_path: None,
        retryable: true,
    })
}

fn timeout_error() -> BridgeError {
    BridgeError::Client(ClientError {
        code: ErrorCode::Timeout,
        message: "The request timed out with an unknown outcome".into(),
        field_path: None,
        retryable: true,
    })
}

fn invalid_output_error() -> BridgeError {
    BridgeError::Client(ClientError {
        code: ErrorCode::Internal,
        message: "The local service returned invalid output".into(),
        field_path: None,
        retryable: false,
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InitializeParams {
    #[serde(default, rename = "_meta")]
    meta: Option<Map<String, Value>>,
    protocol_version: String,
    capabilities: Value,
    client_info: ClientInfo,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientInfo {
    name: String,
    #[serde(default)]
    title: Option<String>,
    version: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    icons: Option<Vec<ClientIcon>>,
    #[serde(default, rename = "websiteUrl")]
    website_url: Option<String>,
}

impl ClientInfo {
    fn is_valid(&self) -> bool {
        !self.name.is_empty()
            && self.title.as_ref().is_none_or(|title| !title.is_empty())
            && !self.version.is_empty()
            && self
                .description
                .as_ref()
                .is_none_or(|description| !description.contains('\0'))
            && self
                .website_url
                .as_ref()
                .is_none_or(|website_url| !website_url.is_empty())
            && self
                .icons
                .as_ref()
                .is_none_or(|icons| icons.iter().all(ClientIcon::is_valid))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClientIcon {
    src: String,
    #[serde(default)]
    mime_type: Option<String>,
    #[serde(default)]
    sizes: Option<Vec<String>>,
    #[serde(default)]
    theme: Option<String>,
}

impl ClientIcon {
    fn is_valid(&self) -> bool {
        !self.src.is_empty()
            && self.mime_type.as_ref().is_none_or(|mime| !mime.is_empty())
            && self
                .sizes
                .as_ref()
                .is_none_or(|sizes| sizes.iter().all(|size| !size.is_empty()))
            && self
                .theme
                .as_deref()
                .is_none_or(|theme| matches!(theme, "light" | "dark"))
    }
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ListToolsParams {
    #[serde(default, rename = "_meta")]
    meta: Option<Map<String, Value>>,
    #[serde(default)]
    cursor: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CallToolParams {
    name: String,
    #[serde(default)]
    arguments: Map<String, Value>,
    #[serde(default, rename = "_meta")]
    meta: Option<Map<String, Value>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CancelledParams {
    request_id: RpcId,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default, rename = "_meta")]
    meta: Option<Map<String, Value>>,
}

fn parse_params<T: for<'de> Deserialize<'de>>(params: Option<Value>) -> Option<T> {
    serde_json::from_value(params?).ok()
}

fn parse_optional_params<T: for<'de> Deserialize<'de> + Default>(
    params: Option<Value>,
) -> Option<T> {
    params.map_or_else(
        || Some(T::default()),
        |params| serde_json::from_value(params).ok(),
    )
}

fn parse_empty_request_params(params: Option<Value>) -> Option<()> {
    let params = parse_optional_params::<EmptyRequestParams>(params)?;
    valid_request_meta(params.meta.as_ref()).then_some(())
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyRequestParams {
    #[serde(default, rename = "_meta")]
    meta: Option<Map<String, Value>>,
}

fn valid_request_meta(meta: Option<&Map<String, Value>>) -> bool {
    meta.and_then(|meta| meta.get("progressToken"))
        .is_none_or(|token| token.is_string() || token.is_number())
}

fn tool_error(id: RpcId, error: &BridgeError) -> Value {
    success(id, tool_error_result(error))
}

fn tool_error_result(error: &BridgeError) -> Value {
    let client = error.client_error();
    json!({
        "content": [{"type": "text", "text": error.redacted_message()}],
        "isError": true,
        "_meta": {
            "contextRelay": {
                "code": client.code,
                "retryable": client.retryable,
                "fieldPath": client.field_path
            }
        }
    })
}
