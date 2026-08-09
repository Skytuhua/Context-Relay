use std::{
    collections::HashMap,
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
};

use context_relay_context_mcp::{
    BridgeError, Daemon, MAX_IN_FLIGHT_TOOL_CALLS, MCP_REVISION, Server,
};
use context_relay_local_ipc::{REQUEST_TIMEOUT, SHUTDOWN_TIMEOUT};
use context_relay_protocol::{
    ClientError, ErrorCode, HarnessId, MAX_IPC_FRAME_BYTES, McpBinding, McpCallParams,
    NativePlatform, RecordId, WireNativeValue,
};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, DuplexStream, ReadBuf},
    sync::{Notify, oneshot},
    task::JoinHandle,
};

#[derive(Clone, Default)]
struct BlockingDaemon {
    state: Arc<BlockingState>,
}

#[derive(Default)]
struct BlockingState {
    calls: Mutex<Vec<(RecordId, McpCallParams)>>,
    pending: Mutex<HashMap<RecordId, oneshot::Sender<Result<Value, BridgeError>>>>,
    canceled: Mutex<Vec<RecordId>>,
    calls_changed: Notify,
    cancels_changed: Notify,
    hold_cancels: AtomicBool,
    cancels_released: Notify,
}

impl BlockingDaemon {
    async fn wait_for_calls(&self, count: usize) {
        loop {
            let changed = self.state.calls_changed.notified();
            if self.state.calls.lock().unwrap().len() >= count {
                return;
            }
            changed.await;
        }
    }

    fn request_id(&self, index: usize) -> RecordId {
        self.state.calls.lock().unwrap()[index].0
    }

    fn call_count(&self) -> usize {
        self.state.calls.lock().unwrap().len()
    }

    fn finish(&self, request_id: RecordId, result: Result<Value, BridgeError>) {
        self.state
            .pending
            .lock()
            .unwrap()
            .remove(&request_id)
            .unwrap()
            .send(result)
            .ok();
    }

    async fn wait_for_cancel(&self, request_id: RecordId) {
        loop {
            let changed = self.state.cancels_changed.notified();
            if self.state.canceled.lock().unwrap().contains(&request_id) {
                return;
            }
            changed.await;
        }
    }

    fn cancel_count(&self) -> usize {
        self.state.canceled.lock().unwrap().len()
    }

    fn hold_cancels(&self) {
        self.state.hold_cancels.store(true, Ordering::Release);
    }

    fn release_cancels(&self) {
        self.state.hold_cancels.store(false, Ordering::Release);
        self.state.cancels_released.notify_waiters();
    }
}

impl Daemon for BlockingDaemon {
    fn call(
        &self,
        request_id: RecordId,
        call: McpCallParams,
    ) -> impl Future<Output = Result<Value, BridgeError>> + Send {
        let state = Arc::clone(&self.state);
        async move {
            let (sender, receiver) = oneshot::channel();
            state.calls.lock().unwrap().push((request_id, call));
            state.pending.lock().unwrap().insert(request_id, sender);
            state.calls_changed.notify_waiters();
            receiver.await.unwrap_or(Err(BridgeError::Unavailable))
        }
    }

    fn cancel(&self, request_id: RecordId) -> impl Future<Output = Result<(), BridgeError>> + Send {
        let state = Arc::clone(&self.state);
        async move {
            state.canceled.lock().unwrap().push(request_id);
            state.cancels_changed.notify_waiters();
            loop {
                let released = state.cancels_released.notified();
                if !state.hold_cancels.load(Ordering::Acquire) {
                    break;
                }
                released.await;
            }
            Ok(())
        }
    }
}

#[derive(Clone)]
struct ImmediateDaemon {
    result: Result<Value, BridgeError>,
    calls: Arc<Mutex<usize>>,
}

impl ImmediateDaemon {
    fn new(result: Result<Value, BridgeError>) -> Self {
        Self {
            result,
            calls: Arc::default(),
        }
    }

    fn call_count(&self) -> usize {
        *self.calls.lock().unwrap()
    }
}

impl Daemon for ImmediateDaemon {
    fn call(
        &self,
        _request_id: RecordId,
        _call: McpCallParams,
    ) -> impl Future<Output = Result<Value, BridgeError>> + Send {
        *self.calls.lock().unwrap() += 1;
        std::future::ready(self.result.clone())
    }

    fn cancel(
        &self,
        _request_id: RecordId,
    ) -> impl Future<Output = Result<(), BridgeError>> + Send {
        std::future::ready(Ok(()))
    }
}

#[derive(Default)]
struct BlockedWriterState {
    polled: AtomicBool,
    dropped: AtomicBool,
    polled_changed: Notify,
}

struct PermanentlyBlockedWriter {
    state: Arc<BlockedWriterState>,
}

impl PermanentlyBlockedWriter {
    fn observed() -> (Self, BlockedWriterObserver) {
        let state = Arc::new(BlockedWriterState::default());
        (
            Self {
                state: Arc::clone(&state),
            },
            BlockedWriterObserver { state },
        )
    }
}

impl AsyncWrite for PermanentlyBlockedWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        _buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.state.polled.store(true, Ordering::Release);
        self.state.polled_changed.notify_waiters();
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.state.polled.store(true, Ordering::Release);
        self.state.polled_changed.notify_waiters();
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl Drop for PermanentlyBlockedWriter {
    fn drop(&mut self) {
        self.state.dropped.store(true, Ordering::Release);
    }
}

#[derive(Clone)]
struct BlockedWriterObserver {
    state: Arc<BlockedWriterState>,
}

impl BlockedWriterObserver {
    async fn wait_until_polled(&self) {
        loop {
            let changed = self.state.polled_changed.notified();
            if self.state.polled.load(Ordering::Acquire) {
                return;
            }
            changed.await;
        }
    }

    fn is_dropped(&self) -> bool {
        self.state.dropped.load(Ordering::Acquire)
    }
}

#[derive(Default)]
struct SingleStepWriterState {
    polled: AtomicBool,
    released: AtomicBool,
    completed: AtomicUsize,
    dropped: AtomicBool,
    write_waker: Mutex<Option<Waker>>,
    polled_changed: Notify,
    completed_changed: Notify,
}

struct SingleStepWriter {
    state: Arc<SingleStepWriterState>,
}

impl SingleStepWriter {
    fn observed() -> (Self, SingleStepWriterObserver) {
        let state = Arc::new(SingleStepWriterState::default());
        (
            Self {
                state: Arc::clone(&state),
            },
            SingleStepWriterObserver { state },
        )
    }
}

impl AsyncWrite for SingleStepWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.state.polled.store(true, Ordering::Release);
        self.state.polled_changed.notify_waiters();
        if self.state.released.swap(false, Ordering::AcqRel) {
            self.state.completed.fetch_add(1, Ordering::AcqRel);
            self.state.completed_changed.notify_waiters();
            return Poll::Ready(Ok(buffer.len()));
        }
        *self.state.write_waker.lock().unwrap() = Some(context.waker().clone());
        if self.state.released.load(Ordering::Acquire) {
            context.waker().wake_by_ref();
        }
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Drop for SingleStepWriter {
    fn drop(&mut self) {
        self.state.dropped.store(true, Ordering::Release);
    }
}

#[derive(Clone)]
struct SingleStepWriterObserver {
    state: Arc<SingleStepWriterState>,
}

impl SingleStepWriterObserver {
    async fn wait_until_polled(&self) {
        loop {
            let changed = self.state.polled_changed.notified();
            if self.state.polled.load(Ordering::Acquire) {
                return;
            }
            changed.await;
        }
    }

    fn release_one(&self) {
        assert!(!self.state.released.swap(true, Ordering::AcqRel));
        if let Some(waker) = self.state.write_waker.lock().unwrap().take() {
            waker.wake();
        }
    }

    async fn wait_for_completed(&self, count: usize) {
        loop {
            let changed = self.state.completed_changed.notified();
            if self.state.completed.load(Ordering::Acquire) >= count {
                return;
            }
            changed.await;
        }
    }

    fn is_dropped(&self) -> bool {
        self.state.dropped.load(Ordering::Acquire)
    }
}

#[derive(Default)]
struct ReadObserverState {
    bytes: AtomicUsize,
    changed: Notify,
}

struct ObservedReader<R> {
    inner: R,
    state: Arc<ReadObserverState>,
}

impl<R> ObservedReader<R> {
    fn new(inner: R) -> (Self, ReadObserver) {
        let state = Arc::new(ReadObserverState::default());
        (
            Self {
                inner,
                state: Arc::clone(&state),
            },
            ReadObserver { state },
        )
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for ObservedReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let filled_before = buffer.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(context, buffer);
        if matches!(result, Poll::Ready(Ok(()))) {
            let read = buffer.filled().len() - filled_before;
            if read > 0 {
                this.state.bytes.fetch_add(read, Ordering::AcqRel);
                this.state.changed.notify_waiters();
            }
        }
        result
    }
}

#[derive(Clone)]
struct ReadObserver {
    state: Arc<ReadObserverState>,
}

impl ReadObserver {
    async fn wait_for_bytes(&self, count: usize) {
        loop {
            let changed = self.state.changed.notified();
            if self.state.bytes.load(Ordering::Acquire) >= count {
                return;
            }
            changed.await;
        }
    }
}

#[derive(Default)]
struct FailingWriterState {
    attempted: AtomicBool,
    fail: AtomicBool,
    failed: AtomicBool,
    write_waker: Mutex<Option<Waker>>,
    attempted_changed: Notify,
    failed_changed: Notify,
}

struct FailingWriter {
    state: Arc<FailingWriterState>,
}

impl FailingWriter {
    fn immediate() -> Self {
        let state = Arc::new(FailingWriterState::default());
        state.fail.store(true, Ordering::Release);
        Self { state }
    }

    fn observed() -> (Self, FailingWriterObserver) {
        let state = Arc::new(FailingWriterState::default());
        (
            Self {
                state: Arc::clone(&state),
            },
            FailingWriterObserver { state },
        )
    }

    fn poll_failure(&self, context: &Context<'_>) -> Poll<io::Result<usize>> {
        self.state.attempted.store(true, Ordering::Release);
        self.state.attempted_changed.notify_waiters();
        if !self.state.fail.load(Ordering::Acquire) {
            *self.state.write_waker.lock().unwrap() = Some(context.waker().clone());
            if !self.state.fail.load(Ordering::Acquire) {
                return Poll::Pending;
            }
        }
        self.state.failed.store(true, Ordering::Release);
        self.state.failed_changed.notify_waiters();
        Poll::Ready(Err(io::Error::other("writer failed")))
    }
}

impl AsyncWrite for FailingWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        _buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_failure(context)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_failure(context).map(|result| result.map(|_| ()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[derive(Clone)]
struct FailingWriterObserver {
    state: Arc<FailingWriterState>,
}

impl FailingWriterObserver {
    async fn wait_until_attempted(&self) {
        loop {
            let changed = self.state.attempted_changed.notified();
            if self.state.attempted.load(Ordering::Acquire) {
                return;
            }
            changed.await;
        }
    }

    fn fail(&self) {
        self.state.fail.store(true, Ordering::Release);
        if let Some(waker) = self.state.write_waker.lock().unwrap().take() {
            waker.wake();
        }
    }

    async fn wait_until_failed(&self) {
        loop {
            let changed = self.state.failed_changed.notified();
            if self.state.failed.load(Ordering::Acquire) {
                return;
            }
            changed.await;
        }
    }
}

#[derive(Clone, Default)]
struct ReadGate {
    state: Arc<ReadGateState>,
}

#[derive(Default)]
struct ReadGateState {
    open: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

impl ReadGate {
    fn open(&self) {
        self.state.open.store(true, Ordering::Release);
        if let Some(waker) = self.state.waker.lock().unwrap().take() {
            waker.wake();
        }
    }
}

struct GateAfterFirstRead<R> {
    inner: R,
    gate: ReadGate,
    read_once: bool,
}

impl<R> GateAfterFirstRead<R> {
    fn new(inner: R, gate: ReadGate) -> Self {
        Self {
            inner,
            gate,
            read_once: false,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for GateAfterFirstRead<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.read_once && !this.gate.state.open.load(Ordering::Acquire) {
            *this.gate.state.waker.lock().unwrap() = Some(context.waker().clone());
            if !this.gate.state.open.load(Ordering::Acquire) {
                return Poll::Pending;
            }
        }
        let filled_before = buffer.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(context, buffer);
        if matches!(result, Poll::Ready(Ok(()))) && buffer.filled().len() > filled_before {
            this.read_once = true;
        }
        result
    }
}

struct StartedServer {
    input: DuplexStream,
    output: BufReader<DuplexStream>,
    task: JoinHandle<Result<(), BridgeError>>,
}

impl StartedServer {
    async fn start<D: Daemon>(daemon: D) -> Self {
        let (input, input_reader) = tokio::io::duplex(256 * 1024);
        let (output_writer, output) = tokio::io::duplex(256 * 1024);
        let task = tokio::spawn(
            Server::new(daemon, binding()).run(BufReader::new(input_reader), output_writer),
        );
        let mut server = Self {
            input,
            output: BufReader::new(output),
            task,
        };
        server
            .send(json!({
                "jsonrpc": "2.0",
                "id": "initialize",
                "method": "initialize",
                "params": {
                    "protocolVersion": MCP_REVISION,
                    "capabilities": {},
                    "clientInfo": {"name": "dispatcher-test", "version": "1"}
                }
            }))
            .await;
        server
            .send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await;
        assert_eq!(server.receive().await["id"], "initialize");
        server
    }

    async fn send(&mut self, value: Value) {
        let mut bytes = serde_json::to_vec(&value).unwrap();
        bytes.push(b'\n');
        self.input.write_all(&bytes).await.unwrap();
    }

    async fn receive(&mut self) -> Value {
        let mut line = String::new();
        assert_ne!(self.output.read_line(&mut line).await.unwrap(), 0);
        assert!(line.ends_with('\n'));
        serde_json::from_str(&line).unwrap()
    }

    async fn close(mut self) -> Result<(), BridgeError> {
        self.input.shutdown().await.unwrap();
        self.task.await.unwrap()
    }
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

fn status_call(id: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"name": "context_relay_status", "arguments": {}}
    })
}

fn remember_call(id: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": "context_relay_remember",
            "arguments": {
                "operationId": "018f22e2-79b0-7cc8-98c4-dc0c0c0739ba",
                "kind": "note",
                "title": "Held mutation",
                "markdown": "This mutation must remain canceled under output backpressure.",
                "tags": [],
                "scope": {"scope": "global"}
            }
        }
    })
}

fn status_output() -> Value {
    json!({
        "protocol": {
            "min": {"major": 1, "minor": 3},
            "max": {"major": 1, "minor": 3}
        },
        "vault": "unlocked",
        "resolvedProject": null,
        "sync": "offline",
        "access": {"mode": "default"}
    })
}

#[tokio::test]
async fn sixty_fifth_call_is_busy_and_concurrent_responses_remain_whole_lines() {
    let daemon = BlockingDaemon::default();
    let mut server = StartedServer::start(daemon.clone()).await;

    for id in 0..=MAX_IN_FLIGHT_TOOL_CALLS {
        server.send(status_call(json!(id))).await;
    }
    daemon.wait_for_calls(MAX_IN_FLIGHT_TOOL_CALLS).await;

    let busy = server.receive().await;
    assert_eq!(
        busy["result"]["_meta"]["contextRelay"],
        json!({"code": "busy", "retryable": true, "fieldPath": null})
    );
    assert_eq!(busy["result"]["isError"], true);
    assert!(busy["result"].get("structuredContent").is_none());

    let request_ids = (0..MAX_IN_FLIGHT_TOOL_CALLS)
        .map(|index| daemon.request_id(index))
        .collect::<Vec<_>>();
    for request_id in request_ids {
        daemon.finish(request_id, Ok(status_output()));
    }
    let mut response_ids = Vec::new();
    for _ in 0..MAX_IN_FLIGHT_TOOL_CALLS {
        let response = server.receive().await;
        assert_eq!(response["result"]["structuredContent"], status_output());
        response_ids.push(response["id"].as_i64().unwrap());
    }
    response_ids.sort_unstable();
    assert_eq!(
        response_ids,
        (0..MAX_IN_FLIGHT_TOOL_CALLS as i64).collect::<Vec<_>>()
    );
    assert_eq!(server.close().await, Ok(()));
}

#[tokio::test]
async fn duplicate_active_id_is_rejected_but_completed_id_can_be_reused() {
    let daemon = BlockingDaemon::default();
    let mut server = StartedServer::start(daemon.clone()).await;

    server.send(status_call(json!("same"))).await;
    daemon.wait_for_calls(1).await;
    server
        .send(json!({"jsonrpc": "2.0", "id": "same", "method": "ping"}))
        .await;
    let duplicate_ping = server.receive().await;
    assert_eq!(duplicate_ping["id"], "same");
    assert_eq!(duplicate_ping["error"]["code"], -32600);

    server.send(status_call(json!("same"))).await;
    let duplicate = server.receive().await;
    assert_eq!(duplicate["id"], "same");
    assert_eq!(duplicate["error"]["code"], -32600);
    assert_eq!(daemon.call_count(), 1);

    daemon.finish(daemon.request_id(0), Ok(status_output()));
    assert_eq!(server.receive().await["id"], "same");

    server.send(status_call(json!("same"))).await;
    daemon.wait_for_calls(2).await;
    daemon.finish(daemon.request_id(1), Ok(status_output()));
    assert_eq!(server.receive().await["id"], "same");
    assert_eq!(server.close().await, Ok(()));
}

#[tokio::test]
async fn cancellation_marks_the_call_before_canceling_and_suppresses_late_output() {
    let daemon = BlockingDaemon::default();
    let mut server = StartedServer::start(daemon.clone()).await;

    server.send(status_call(json!("cancel-me"))).await;
    daemon.wait_for_calls(1).await;
    let request_id = daemon.request_id(0);
    server
        .send(json!({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": "cancel-me", "reason": "test"}
        }))
        .await;
    daemon.wait_for_cancel(request_id).await;
    daemon.finish(request_id, Ok(status_output()));
    server
        .send(json!({"jsonrpc": "2.0", "id": "after", "method": "ping"}))
        .await;

    let response = server.receive().await;
    assert_eq!(response["id"], "after");
    assert_eq!(response["result"], json!({}));
    assert_eq!(server.close().await, Ok(()));
}

#[tokio::test]
async fn duplicate_cancel_flood_dispatches_once_per_active_call() {
    let daemon = BlockingDaemon::default();
    daemon.hold_cancels();
    let mut server = StartedServer::start(daemon.clone()).await;

    server.send(status_call(json!("cancel-once"))).await;
    daemon.wait_for_calls(1).await;
    let request_id = daemon.request_id(0);
    for _ in 0..256 {
        server
            .send(json!({
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {"requestId": "cancel-once"}
            }))
            .await;
    }
    server
        .send(json!({"jsonrpc": "2.0", "id": "barrier", "method": "ping"}))
        .await;
    assert_eq!(server.receive().await["id"], "barrier");
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }

    assert_eq!(daemon.cancel_count(), 1);
    daemon.release_cancels();
    daemon.wait_for_cancel(request_id).await;
    daemon.finish(request_id, Ok(status_output()));
    assert_eq!(server.close().await, Ok(()));
}

#[tokio::test]
async fn held_cancel_tasks_bound_future_call_admission_at_sixty_four() {
    let daemon = BlockingDaemon::default();
    daemon.hold_cancels();
    let mut server = StartedServer::start(daemon.clone()).await;

    for index in 0..MAX_IN_FLIGHT_TOOL_CALLS {
        server.send(status_call(json!(index))).await;
        daemon.wait_for_calls(index + 1).await;
        let request_id = daemon.request_id(index);
        server
            .send(json!({
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {"requestId": index}
            }))
            .await;
        daemon.wait_for_cancel(request_id).await;
        daemon.finish(request_id, Ok(status_output()));
        server
            .send(json!({"jsonrpc": "2.0", "id": format!("barrier-{index}"), "method": "ping"}))
            .await;
        assert_eq!(
            server.receive().await["id"],
            json!(format!("barrier-{index}"))
        );
    }
    assert_eq!(daemon.cancel_count(), MAX_IN_FLIGHT_TOOL_CALLS);

    server
        .send(status_call(json!("cancel-admission-overflow")))
        .await;
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }

    assert_eq!(daemon.call_count(), MAX_IN_FLIGHT_TOOL_CALLS);
    let busy = server.receive().await;
    assert_eq!(busy["id"], "cancel-admission-overflow");
    assert_eq!(
        busy["result"]["_meta"]["contextRelay"],
        json!({"code": "busy", "retryable": true, "fieldPath": null})
    );

    daemon.release_cancels();
    assert_eq!(server.close().await, Ok(()));
}

#[tokio::test]
async fn sixty_four_active_calls_each_retain_cancellation_capacity() {
    let daemon = BlockingDaemon::default();
    daemon.hold_cancels();
    let mut server = StartedServer::start(daemon.clone()).await;

    for index in 0..MAX_IN_FLIGHT_TOOL_CALLS {
        server.send(status_call(json!(index))).await;
    }
    daemon.wait_for_calls(MAX_IN_FLIGHT_TOOL_CALLS).await;
    let request_ids = (0..MAX_IN_FLIGHT_TOOL_CALLS)
        .map(|index| daemon.request_id(index))
        .collect::<Vec<_>>();
    for index in 0..MAX_IN_FLIGHT_TOOL_CALLS {
        server
            .send(json!({
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {"requestId": index}
            }))
            .await;
    }
    for request_id in &request_ids {
        daemon.wait_for_cancel(*request_id).await;
    }

    assert_eq!(daemon.call_count(), MAX_IN_FLIGHT_TOOL_CALLS);
    assert_eq!(daemon.cancel_count(), MAX_IN_FLIGHT_TOOL_CALLS);
    for request_id in request_ids {
        daemon.finish(request_id, Ok(status_output()));
    }
    daemon.release_cancels();
    assert_eq!(server.close().await, Ok(()));
}

#[tokio::test]
async fn eof_waits_for_the_tracked_cancel_task() {
    let daemon = BlockingDaemon::default();
    daemon.hold_cancels();
    let mut server = StartedServer::start(daemon.clone()).await;

    server.send(status_call(json!("tracked-cancel"))).await;
    daemon.wait_for_calls(1).await;
    let request_id = daemon.request_id(0);
    server
        .send(json!({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": "tracked-cancel"}
        }))
        .await;
    daemon.wait_for_cancel(request_id).await;
    daemon.finish(request_id, Ok(status_output()));
    server.input.shutdown().await.unwrap();
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }

    assert!(
        !server.task.is_finished(),
        "server detached the in-flight cancellation during shutdown"
    );
    daemon.release_cancels();
    assert_eq!(server.task.await.unwrap(), Ok(()));
}

#[tokio::test]
async fn client_error_metadata_is_preserved_without_structured_content() {
    let daemon = ImmediateDaemon::new(Err(BridgeError::Client(ClientError {
        code: ErrorCode::RevisionConflict,
        message: "sensitive daemon detail".into(),
        field_path: Some("expectedRevision".into()),
        retryable: false,
    })));
    let mut server = StartedServer::start(daemon).await;

    server.send(status_call(json!(7))).await;
    let response = server.receive().await;

    assert_eq!(
        response["result"]["_meta"]["contextRelay"],
        json!({
            "code": "revision_conflict",
            "retryable": false,
            "fieldPath": "expectedRevision"
        })
    );
    assert_eq!(
        response["result"]["content"][0]["text"],
        "The record revision changed"
    );
    assert!(response["result"].get("structuredContent").is_none());
    assert_eq!(server.close().await, Ok(()));
}

#[tokio::test]
async fn locked_and_unavailable_errors_are_structured_and_redacted() {
    for (error, code, retryable, message) in [
        (
            BridgeError::Client(ClientError::vault_locked()),
            "vault_locked",
            true,
            "The local vault is locked",
        ),
        (
            BridgeError::Unavailable,
            "internal",
            true,
            "The local service is unavailable",
        ),
    ] {
        let mut server = StartedServer::start(ImmediateDaemon::new(Err(error))).await;
        server.send(status_call(json!(code))).await;
        let response = server.receive().await;

        assert_eq!(response["result"]["_meta"]["contextRelay"]["code"], code);
        assert_eq!(
            response["result"]["_meta"]["contextRelay"]["retryable"],
            retryable
        );
        assert_eq!(response["result"]["content"][0]["text"], message);
        assert!(response["result"].get("structuredContent").is_none());
        assert_eq!(server.close().await, Ok(()));
    }
}

#[tokio::test]
async fn invalid_daemon_output_is_a_structured_internal_error() {
    let daemon = ImmediateDaemon::new(Ok(json!({"not": "a status output"})));
    let mut server = StartedServer::start(daemon).await;

    server.send(status_call(json!(8))).await;
    let response = server.receive().await;

    assert_eq!(
        response["result"]["_meta"]["contextRelay"]["code"],
        "internal"
    );
    assert_eq!(
        response["result"]["_meta"]["contextRelay"]["retryable"],
        false
    );
    assert!(response["result"].get("structuredContent").is_none());
    assert_eq!(server.close().await, Ok(()));
}

#[tokio::test(start_paused = true)]
async fn timed_out_call_is_unknown_outcome_and_is_never_retried() {
    let daemon = BlockingDaemon::default();
    let mut server = StartedServer::start(daemon.clone()).await;

    server.send(status_call(json!("timeout"))).await;
    daemon.wait_for_calls(1).await;
    tokio::time::advance(REQUEST_TIMEOUT + std::time::Duration::from_millis(1)).await;
    let response = server.receive().await;

    assert_eq!(
        response["result"]["_meta"]["contextRelay"],
        json!({"code": "timeout", "retryable": true, "fieldPath": null})
    );
    assert_eq!(
        response["result"]["content"][0]["text"],
        "The request timed out with an unknown outcome"
    );
    assert_eq!(daemon.call_count(), 1);
    assert_eq!(server.close().await, Ok(()));
}

#[tokio::test(start_paused = true)]
async fn eof_waits_only_for_the_bounded_shutdown_period() {
    let daemon = BlockingDaemon::default();
    let mut server = StartedServer::start(daemon.clone()).await;

    server.send(status_call(json!("blocked"))).await;
    daemon.wait_for_calls(1).await;
    server.input.shutdown().await.unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(SHUTDOWN_TIMEOUT + std::time::Duration::from_millis(1)).await;

    assert_eq!(server.task.await.unwrap(), Ok(()));
}

#[tokio::test(start_paused = true)]
async fn eof_shares_one_shutdown_deadline_with_a_blocked_writer() {
    let daemon = BlockingDaemon::default();
    let (writer, writer_observer) = PermanentlyBlockedWriter::observed();
    let (mut input, input_reader) = tokio::io::duplex(64 * 1024);
    let task = tokio::spawn(
        Server::new(daemon.clone(), binding()).run(BufReader::new(input_reader), writer),
    );
    for message in [
        json!({
            "jsonrpc": "2.0",
            "id": "initialize",
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_REVISION,
                "capabilities": {},
                "clientInfo": {"name": "blocked-writer-test", "version": "1"}
            }
        }),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        status_call(json!("blocked-writer")),
    ] {
        let mut bytes = serde_json::to_vec(&message).unwrap();
        bytes.push(b'\n');
        input.write_all(&bytes).await.unwrap();
    }
    input.shutdown().await.unwrap();
    daemon.wait_for_calls(1).await;
    writer_observer.wait_until_polled().await;
    tokio::task::yield_now().await;

    let half_deadline = SHUTDOWN_TIMEOUT / 2;
    tokio::time::advance(half_deadline).await;
    assert!(!task.is_finished());
    daemon.finish(daemon.request_id(0), Ok(status_output()));
    tokio::task::yield_now().await;
    tokio::time::advance(SHUTDOWN_TIMEOUT - half_deadline - std::time::Duration::from_millis(1))
        .await;
    assert!(!task.is_finished());

    tokio::time::advance(std::time::Duration::from_millis(2)).await;
    tokio::task::yield_now().await;
    assert!(
        task.is_finished(),
        "writer drain exceeded the original shutdown deadline"
    );
    assert_eq!(task.await.unwrap(), Ok(()));
    assert!(writer_observer.is_dropped());
}

#[tokio::test(start_paused = true)]
async fn eof_remains_observable_when_the_blocked_writer_queue_is_full() {
    let (writer, writer_observer) = PermanentlyBlockedWriter::observed();
    let (mut input, input_reader) = tokio::io::duplex(64 * 1024);
    let task = tokio::spawn(
        Server::new(ImmediateDaemon::new(Ok(status_output())), binding())
            .run(BufReader::new(input_reader), writer),
    );
    for message in [
        json!({
            "jsonrpc": "2.0",
            "id": "initialize",
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_REVISION,
                "capabilities": {},
                "clientInfo": {"name": "full-writer-queue-test", "version": "1"}
            }
        }),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    ] {
        let mut bytes = serde_json::to_vec(&message).unwrap();
        bytes.push(b'\n');
        input.write_all(&bytes).await.unwrap();
    }
    writer_observer.wait_until_polled().await;
    for id in 0..(MAX_IN_FLIGHT_TOOL_CALLS + 17) {
        let mut bytes =
            serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": id, "method": "ping"})).unwrap();
        bytes.push(b'\n');
        input.write_all(&bytes).await.unwrap();
    }
    input.shutdown().await.unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(SHUTDOWN_TIMEOUT + std::time::Duration::from_millis(1)).await;
    tokio::task::yield_now().await;

    assert!(
        task.is_finished(),
        "full response queue prevented EOF from starting bounded cleanup"
    );
    assert_eq!(task.await.unwrap(), Ok(()));
    assert!(writer_observer.is_dropped());
}

#[tokio::test(start_paused = true)]
async fn full_writer_queue_drains_cancellation_with_open_input_before_deadline() {
    let daemon = BlockingDaemon::default();
    let (writer, writer_observer) = PermanentlyBlockedWriter::observed();
    let (mut input, input_reader) = tokio::io::duplex(64 * 1024);
    let task = tokio::spawn(
        Server::new(daemon.clone(), binding()).run(BufReader::new(input_reader), writer),
    );
    for message in [
        json!({
            "jsonrpc": "2.0",
            "id": "initialize",
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_REVISION,
                "capabilities": {},
                "clientInfo": {"name": "full-queue-cancel-test", "version": "1"}
            }
        }),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        remember_call(json!("held-call")),
    ] {
        let mut bytes = serde_json::to_vec(&message).unwrap();
        bytes.push(b'\n');
        input.write_all(&bytes).await.unwrap();
    }
    writer_observer.wait_until_polled().await;
    daemon.wait_for_calls(1).await;
    let request_id = daemon.request_id(0);
    for id in 0..(MAX_IN_FLIGHT_TOOL_CALLS + 17) {
        let mut bytes =
            serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": id, "method": "ping"})).unwrap();
        bytes.push(b'\n');
        input.write_all(&bytes).await.unwrap();
    }
    let mut cancellation = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "method": "notifications/cancelled",
        "params": {"requestId": "held-call"}
    }))
    .unwrap();
    cancellation.push(b'\n');
    input.write_all(&cancellation).await.unwrap();
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }

    assert_eq!(daemon.cancel_count(), 1);
    daemon.finish(request_id, Ok(status_output()));
    tokio::time::advance(SHUTDOWN_TIMEOUT + std::time::Duration::from_millis(1)).await;
    tokio::task::yield_now().await;

    assert!(
        task.is_finished(),
        "cancellation drain exceeded the original backpressure deadline"
    );
    assert_eq!(task.await.unwrap(), Ok(()));
    assert!(writer_observer.is_dropped());
}

#[tokio::test(start_paused = true)]
async fn fragmented_cancellation_survives_writer_reserve_winning_between_chunks() {
    let daemon = BlockingDaemon::default();
    let (writer, writer_observer) = SingleStepWriter::observed();
    let (mut input, input_reader) = tokio::io::duplex(64 * 1024);
    let (input_reader, read_observer) = ObservedReader::new(input_reader);
    let task = tokio::spawn(
        Server::new(daemon.clone(), binding()).run(BufReader::new(input_reader), writer),
    );
    let mut bytes_sent = 0;
    for message in [
        json!({
            "jsonrpc": "2.0",
            "id": "initialize",
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_REVISION,
                "capabilities": {},
                "clientInfo": {"name": "fragmented-cancel-test", "version": "1"}
            }
        }),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        remember_call(json!("fragmented-cancel")),
    ] {
        let mut bytes = serde_json::to_vec(&message).unwrap();
        bytes.push(b'\n');
        bytes_sent += bytes.len();
        input.write_all(&bytes).await.unwrap();
    }
    writer_observer.wait_until_polled().await;
    daemon.wait_for_calls(1).await;
    let request_id = daemon.request_id(0);
    for id in 0..(MAX_IN_FLIGHT_TOOL_CALLS + 17) {
        let mut bytes =
            serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": id, "method": "ping"})).unwrap();
        bytes.push(b'\n');
        bytes_sent += bytes.len();
        input.write_all(&bytes).await.unwrap();
    }
    let mut cancellation = serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "method": "notifications/cancelled",
        "params": {"requestId": "fragmented-cancel"}
    }))
    .unwrap();
    cancellation.push(b'\n');
    let split = cancellation.len() / 2;
    bytes_sent += split;
    input.write_all(&cancellation[..split]).await.unwrap();
    read_observer.wait_for_bytes(bytes_sent).await;

    writer_observer.release_one();
    writer_observer.wait_for_completed(1).await;
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    input.write_all(&cancellation[split..]).await.unwrap();
    input.shutdown().await.unwrap();
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }

    assert_eq!(daemon.cancel_count(), 1);
    daemon.finish(request_id, Ok(status_output()));
    tokio::time::advance(SHUTDOWN_TIMEOUT + std::time::Duration::from_millis(1)).await;
    tokio::task::yield_now().await;
    assert_eq!(task.await.unwrap(), Ok(()));
    assert!(writer_observer.is_dropped());
}

#[tokio::test(start_paused = true)]
async fn read_error_preserves_its_error_and_joins_a_blocked_writer() {
    let (writer, writer_observer) = PermanentlyBlockedWriter::observed();
    let (mut input, input_reader) = tokio::io::duplex(64 * 1024);
    let task = tokio::spawn(
        Server::new(ImmediateDaemon::new(Ok(status_output())), binding())
            .run(BufReader::new(input_reader), writer),
    );
    let message = json!({
        "jsonrpc": "2.0",
        "id": "initialize",
        "method": "initialize",
        "params": {
            "protocolVersion": MCP_REVISION,
            "capabilities": {},
            "clientInfo": {"name": "read-error-test", "version": "1"}
        }
    });
    let mut bytes = serde_json::to_vec(&message).unwrap();
    bytes.push(b'\n');
    input.write_all(&bytes).await.unwrap();
    writer_observer.wait_until_polled().await;

    input
        .write_all(&vec![b' '; MAX_IPC_FRAME_BYTES + 1])
        .await
        .unwrap();
    input.write_all(b"\n").await.unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(SHUTDOWN_TIMEOUT - std::time::Duration::from_millis(1)).await;
    assert!(!task.is_finished());
    assert!(!writer_observer.is_dropped());

    tokio::time::advance(std::time::Duration::from_millis(2)).await;
    tokio::task::yield_now().await;
    assert!(
        task.is_finished(),
        "read-error cleanup exceeded the single shutdown deadline"
    );
    let error = task.await.unwrap().unwrap_err();
    assert_eq!(error, BridgeError::FrameTooLarge);
    assert_eq!(error.to_string(), "An MCP message exceeded the size limit");
    assert!(writer_observer.is_dropped());
}

#[tokio::test(start_paused = true)]
async fn eof_propagates_a_writer_error_before_the_shutdown_deadline() {
    let (mut input, input_reader) = tokio::io::duplex(64 * 1024);
    let task = tokio::spawn(
        Server::new(ImmediateDaemon::new(Ok(status_output())), binding())
            .run(BufReader::new(input_reader), FailingWriter::immediate()),
    );
    let message = json!({
        "jsonrpc": "2.0",
        "id": "initialize",
        "method": "initialize",
        "params": {
            "protocolVersion": MCP_REVISION,
            "capabilities": {},
            "clientInfo": {"name": "failing-writer-test", "version": "1"}
        }
    });
    let mut bytes = serde_json::to_vec(&message).unwrap();
    bytes.push(b'\n');
    input.write_all(&bytes).await.unwrap();
    input.shutdown().await.unwrap();
    let started_at = tokio::time::Instant::now();

    assert_eq!(task.await.unwrap(), Err(BridgeError::Io));
    assert_eq!(tokio::time::Instant::now(), started_at);
}

#[tokio::test(start_paused = true)]
async fn writer_failure_while_input_is_open_prevents_later_tool_dispatch() {
    let daemon = ImmediateDaemon::new(Ok(status_output()));
    let (writer, writer_observer) = FailingWriter::observed();
    let gate = ReadGate::default();
    let (mut input, input_reader) = tokio::io::duplex(64 * 1024);
    let message = json!({
        "jsonrpc": "2.0",
        "id": "initialize",
        "method": "initialize",
        "params": {
            "protocolVersion": MCP_REVISION,
            "capabilities": {},
            "clientInfo": {"name": "writer-failure-test", "version": "1"}
        }
    });
    let mut bytes = serde_json::to_vec(&message).unwrap();
    bytes.push(b'\n');
    input.write_all(&bytes).await.unwrap();
    let task = tokio::spawn(Server::new(daemon.clone(), binding()).run(
        BufReader::new(GateAfterFirstRead::new(input_reader, gate.clone())),
        writer,
    ));
    writer_observer.wait_until_attempted().await;

    for message in [
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        status_call(json!("must-not-dispatch")),
    ] {
        let mut bytes = serde_json::to_vec(&message).unwrap();
        bytes.push(b'\n');
        input.write_all(&bytes).await.unwrap();
    }
    writer_observer.fail();
    writer_observer.wait_until_failed().await;
    gate.open();
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }

    assert_eq!(daemon.call_count(), 0);
    assert!(
        task.is_finished(),
        "writer failure was not observed while input remained open"
    );
    assert_eq!(task.await.unwrap(), Err(BridgeError::Io));
}
