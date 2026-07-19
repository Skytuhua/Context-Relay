use std::{
    collections::{BTreeSet, HashMap},
    fmt,
    future::Future,
    process::{Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};

use context_relay_protocol::{
    CONTEXT_RELAY_APPLICATION_ERROR, ClientError, ClientRole, DaemonInstanceNonce, ErrorCode,
    HelloParams, JSON_RPC_INVALID_REQUEST, JSON_RPC_PARSE_ERROR, JsonRpcErrorObject,
    JsonRpcErrorV1, JsonRpcRequestV1, JsonRpcSuccessV1, JsonRpcVersion, LocalRequest, LocalResult,
    PROTOCOL_VERSION, ProtocolVersion, RecordId,
};
use serde::{
    Deserialize, Deserializer,
    de::{Error as _, MapAccess, SeqAccess, Visitor},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    time::{Instant, sleep_until, timeout, timeout_at},
};

use crate::{
    AuthAcceptedV1, AuthTranscriptV1, ConnectedStream, HANDSHAKE_TIMEOUT, InstallationToken,
    IpcError, REQUEST_TIMEOUT, RuntimeConfig, ServerHelloV1, connect, create_proof,
    create_server_proof, generate_instance_nonce, load_installation_token, read_frame, read_json,
    role_allows, verify_proof, verify_server_proof, write_frame, write_json,
};

pub(crate) struct ClientConnection<S> {
    stream: Option<S>,
    protocol: ProtocolVersion,
    daemon_instance_nonce: DaemonInstanceNonce,
}

pub(crate) struct ServerConnection<S> {
    _stream: S,
    role: ClientRole,
    _protocol: ProtocolVersion,
    _daemon_instance_nonce: DaemonInstanceNonce,
    pub(crate) registry: RequestRegistry,
}

#[derive(Debug)]
pub struct AuthenticatedRequest {
    pub id: RecordId,
    pub role: ClientRole,
    pub request: LocalRequest,
    pub registration: RequestRegistration,
}

const REQUEST_QUEUED: u8 = 0;
const REQUEST_ACTIVE: u8 = 1;
const REQUEST_CANCELED: u8 = 2;
const REQUEST_COMPLETE: u8 = 3;

#[derive(Clone, Default)]
pub struct RequestRegistry {
    inner: Arc<Mutex<HashMap<RecordId, Arc<RequestState>>>>,
}

struct RequestState {
    phase: AtomicU8,
}

pub struct RequestRegistration {
    id: RecordId,
    state: Arc<RequestState>,
    registry: RequestRegistry,
}

impl RequestRegistry {
    fn register(&self, id: RecordId) -> Option<RequestRegistration> {
        let mut requests = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        if requests.contains_key(&id) {
            return None;
        }
        let state = Arc::new(RequestState {
            phase: AtomicU8::new(REQUEST_QUEUED),
        });
        requests.insert(id, state.clone());
        Some(RequestRegistration {
            id,
            state,
            registry: self.clone(),
        })
    }

    fn cancel(&self, id: RecordId) {
        let state = self
            .inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(&id)
            .cloned();
        if let Some(state) = state {
            let _ = state.phase.compare_exchange(
                REQUEST_QUEUED,
                REQUEST_CANCELED,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
    }
}

impl RequestRegistration {
    pub fn begin(&self) -> bool {
        self.state
            .phase
            .compare_exchange(
                REQUEST_QUEUED,
                REQUEST_ACTIVE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    pub fn is_canceled(&self) -> bool {
        self.state.phase.load(Ordering::Acquire) == REQUEST_CANCELED
    }
}

impl fmt::Debug for RequestRegistration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestRegistration")
            .field("id", &self.id)
            .field("canceled", &self.is_canceled())
            .finish()
    }
}

impl Drop for RequestRegistration {
    fn drop(&mut self) {
        self.state.phase.store(REQUEST_COMPLETE, Ordering::Release);
        let mut requests = self
            .registry
            .inner
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if requests
            .get(&self.id)
            .is_some_and(|state| Arc::ptr_eq(state, &self.state))
        {
            requests.remove(&self.id);
        }
    }
}

pub struct Client {
    inner: ClientConnection<ConnectedStream>,
}

const DAEMON_STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const DAEMON_STARTUP_RETRY_INTERVAL: Duration = Duration::from_millis(50);

impl Client {
    pub async fn connect(role: ClientRole) -> Result<Self, IpcError> {
        let runtime = RuntimeConfig::production();
        let stream = connect_endpoint_with(
            || {
                let runtime = runtime.clone();
                async move { connect(&runtime).await }
            },
            launch_daemon_sibling,
        )
        .await?;
        let token = load_installation_token()?;
        let client_nonce = generate_instance_nonce()?;
        let request_id = RecordId::new(uuid::Uuid::now_v7())
            .expect("UUID v7 constructor returns a valid RecordId");
        Ok(Self {
            inner: client_handshake(stream, role, &token, client_nonce, request_id).await?,
        })
    }

    pub async fn call(
        &mut self,
        id: RecordId,
        request: LocalRequest,
    ) -> Result<LocalResult, ClientError> {
        self.inner.call(id, request).await
    }
}

async fn connect_endpoint_with<T, C, F, L>(mut connector: C, mut launcher: L) -> Result<T, IpcError>
where
    C: FnMut() -> F,
    F: Future<Output = Result<T, IpcError>>,
    L: FnMut() -> Result<(), IpcError>,
{
    match connector().await {
        Ok(stream) => return Ok(stream),
        Err(IpcError::EndpointNotFound) => launcher()?,
        Err(error) => return Err(error),
    }

    let deadline = Instant::now() + DAEMON_STARTUP_TIMEOUT;
    loop {
        match timeout_at(deadline, connector()).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(IpcError::EndpointNotFound)) => {}
            Ok(Err(error)) => return Err(error),
            Err(_) => return Err(IpcError::EndpointNotFound),
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(IpcError::EndpointNotFound);
        }
        sleep_until((now + DAEMON_STARTUP_RETRY_INTERVAL).min(deadline)).await;
        if Instant::now() >= deadline {
            return Err(IpcError::EndpointNotFound);
        }
    }
}

fn launch_daemon_sibling() -> Result<(), IpcError> {
    let executable = std::env::current_exe().map_err(|_| IpcError::Io)?;
    let daemon = executable.with_file_name(format!(
        "context-relay-contextd{}",
        std::env::consts::EXE_SUFFIX
    ));
    let mut command = Command::new(daemon);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

        command.creation_flags(CREATE_NO_WINDOW);
    }
    command.spawn().map(|_| ()).map_err(|_| IpcError::Io)
}

pub struct AuthenticatedConnection {
    inner: ServerConnection<ConnectedStream>,
}

impl AuthenticatedConnection {
    pub async fn accept(
        stream: ConnectedStream,
        token: &InstallationToken,
        daemon_instance_nonce: DaemonInstanceNonce,
        registry: RequestRegistry,
    ) -> Result<Self, IpcError> {
        let server_hello = ServerHelloV1::generate(daemon_instance_nonce)?;
        let mut inner = server_handshake(stream, token, server_hello).await?;
        inner.registry = registry;
        Ok(Self { inner })
    }

    pub fn role(&self) -> ClientRole {
        self.inner.role()
    }

    pub async fn next_request(&mut self) -> Result<AuthenticatedRequest, IpcError> {
        self.inner.next_request().await
    }

    pub async fn respond(
        &mut self,
        id: RecordId,
        result: Result<LocalResult, ClientError>,
    ) -> Result<(), IpcError> {
        self.inner.respond(id, result).await
    }
}

impl<S> ServerConnection<S> {
    pub(crate) fn role(&self) -> ClientRole {
        self.role
    }
}

impl<S> ServerConnection<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub(crate) async fn next_request(&mut self) -> Result<AuthenticatedRequest, IpcError> {
        loop {
            let raw = read_frame(&mut self._stream).await?;
            let probe: RequestProbe = match serde_json::from_slice(&raw) {
                Ok(probe) => probe,
                Err(error) => {
                    write_boundary_error(
                        &mut self._stream,
                        None,
                        request_parse_code(&error),
                        invalid_request("Invalid request", ErrorCode::InvalidRequest, false),
                    )
                    .await?;
                    return Err(IpcError::InvalidRequest);
                }
            };
            let _ = (&probe.jsonrpc, &probe.method, &probe.params);
            if probe.protocol != self._protocol {
                write_boundary_error(
                    &mut self._stream,
                    Some(probe.id),
                    JSON_RPC_INVALID_REQUEST,
                    invalid_request(
                        "Protocol version unsupported",
                        ErrorCode::ProtocolVersionUnsupported,
                        false,
                    ),
                )
                .await?;
                return Err(IpcError::ProtocolVersionUnsupported);
            }
            if probe.daemon_instance_nonce != self._daemon_instance_nonce {
                write_boundary_error(
                    &mut self._stream,
                    Some(probe.id),
                    JSON_RPC_INVALID_REQUEST,
                    invalid_request("Invalid request", ErrorCode::InvalidRequest, true),
                )
                .await?;
                return Err(IpcError::InvalidRequest);
            }
            let request: JsonRpcRequestV1 = match serde_json::from_slice(&raw) {
                Ok(request) => request,
                Err(_) => {
                    write_boundary_error(
                        &mut self._stream,
                        Some(probe.id),
                        JSON_RPC_INVALID_REQUEST,
                        invalid_request("Invalid request", ErrorCode::InvalidRequest, false),
                    )
                    .await?;
                    return Err(IpcError::InvalidRequest);
                }
            };
            if matches!(request.request, LocalRequest::Hello(_)) {
                write_boundary_error(
                    &mut self._stream,
                    Some(request.id),
                    JSON_RPC_INVALID_REQUEST,
                    invalid_request("Invalid request", ErrorCode::InvalidRequest, false),
                )
                .await?;
                return Err(IpcError::InvalidRequest);
            }
            if !role_allows(self.role, &request.request) {
                write_boundary_error(
                    &mut self._stream,
                    Some(request.id),
                    CONTEXT_RELAY_APPLICATION_ERROR,
                    invalid_request(
                        "This client is not authorized for this request",
                        ErrorCode::ScopeDenied,
                        false,
                    ),
                )
                .await?;
                continue;
            }
            if let LocalRequest::Cancel(params) = &request.request {
                self.registry.cancel(params.request_id);
                self.respond(request.id, Ok(LocalResult::Empty)).await?;
                continue;
            }
            let Some(registration) = self.registry.register(request.id) else {
                write_boundary_error(
                    &mut self._stream,
                    Some(request.id),
                    CONTEXT_RELAY_APPLICATION_ERROR,
                    invalid_request(
                        "The request id is already active",
                        ErrorCode::Conflict,
                        false,
                    ),
                )
                .await?;
                continue;
            };
            return Ok(AuthenticatedRequest {
                id: request.id,
                role: self.role,
                request: request.request,
                registration,
            });
        }
    }

    pub(crate) async fn respond(
        &mut self,
        id: RecordId,
        result: Result<LocalResult, ClientError>,
    ) -> Result<(), IpcError> {
        match result {
            Ok(result) => {
                write_json(
                    &mut self._stream,
                    &JsonRpcSuccessV1 {
                        jsonrpc: JsonRpcVersion::V2,
                        id,
                        result,
                    },
                )
                .await
            }
            Err(error) => {
                write_boundary_error(
                    &mut self._stream,
                    Some(id),
                    CONTEXT_RELAY_APPLICATION_ERROR,
                    error,
                )
                .await
            }
        }?;
        self._stream.flush().await.map_err(|_| IpcError::Io)
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RpcResponse {
    Success(JsonRpcSuccessV1),
    Error(JsonRpcErrorV1),
}

impl<S> ClientConnection<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub(crate) async fn call(
        &mut self,
        id: RecordId,
        request: LocalRequest,
    ) -> Result<LocalResult, ClientError> {
        if matches!(&request, LocalRequest::Hello(_)) {
            return Err(invalid_request(
                "Invalid request",
                ErrorCode::InvalidRequest,
                false,
            ));
        }
        let payload = serde_json::to_vec(&JsonRpcRequestV1 {
            jsonrpc: JsonRpcVersion::V2,
            id,
            protocol: self.protocol,
            daemon_instance_nonce: self.daemon_instance_nonce,
            request,
        })
        .map_err(|_| invalid_request("Invalid request", ErrorCode::InvalidRequest, false))?;
        let Some(mut stream) = self.stream.take() else {
            return Err(connection_unavailable());
        };
        let exchange = timeout(REQUEST_TIMEOUT, async {
            write_frame(&mut stream, &payload).await?;
            let raw = read_frame(&mut stream).await?;
            serde_json::from_slice::<RpcResponse>(&raw).map_err(|_| IpcError::InvalidFrame)
        })
        .await;
        match exchange {
            Ok(Ok(RpcResponse::Success(response))) if response.id == id => {
                self.stream = Some(stream);
                Ok(response.result)
            }
            Ok(Ok(RpcResponse::Error(response))) if response.id == Some(id) => {
                self.stream = Some(stream);
                Err(response.error.data)
            }
            _ => Err(indeterminate()),
        }
    }
}

fn connection_unavailable() -> ClientError {
    invalid_request(
        "The local service connection is unavailable",
        ErrorCode::Busy,
        true,
    )
}

fn indeterminate() -> ClientError {
    invalid_request("The request outcome is unknown", ErrorCode::Timeout, true)
}

fn request_parse_code(error: &serde_json::Error) -> i32 {
    if error.is_syntax() || error.is_eof() {
        JSON_RPC_PARSE_ERROR
    } else {
        JSON_RPC_INVALID_REQUEST
    }
}

struct StrictJson;

impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = StrictJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(StrictJson)
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(StrictJson)
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(StrictJson)
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(StrictJson)
    }

    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(StrictJson)
    }

    fn visit_string<E>(self, _: String) -> Result<Self::Value, E> {
        Ok(StrictJson)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJson)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJson)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        StrictJson::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element::<StrictJson>()?.is_some() {}
        Ok(StrictJson)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(A::Error::custom("duplicate JSON object key"));
            }
            map.next_value::<StrictJson>()?;
        }
        Ok(StrictJson)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RequestProbe {
    jsonrpc: JsonRpcVersion,
    id: RecordId,
    protocol: ProtocolVersion,
    daemon_instance_nonce: DaemonInstanceNonce,
    method: String,
    params: StrictJson,
}

fn invalid_request(message: &str, code: ErrorCode, retryable: bool) -> ClientError {
    ClientError {
        code,
        message: message.into(),
        field_path: None,
        retryable,
    }
}

async fn write_boundary_error<S>(
    stream: &mut S,
    id: Option<RecordId>,
    rpc_code: i32,
    error: ClientError,
) -> Result<(), IpcError>
where
    S: AsyncWrite + Unpin,
{
    write_json(
        stream,
        &JsonRpcErrorV1 {
            jsonrpc: JsonRpcVersion::V2,
            id,
            error: JsonRpcErrorObject {
                code: rpc_code,
                message: error.message.clone(),
                data: error,
            },
        },
    )
    .await
}

pub(crate) async fn client_handshake<S>(
    mut stream: S,
    role: ClientRole,
    token: &InstallationToken,
    client_nonce: DaemonInstanceNonce,
    request_id: RecordId,
) -> Result<ClientConnection<S>, IpcError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    timeout(HANDSHAKE_TIMEOUT, async {
        let server_hello: ServerHelloV1 = read_json(&mut stream).await?;
        if server_hello.protocol != PROTOCOL_VERSION {
            return Err(IpcError::ProtocolVersionUnsupported);
        }
        let transcript = AuthTranscriptV1 {
            role,
            client_nonce,
            server_hello,
        };
        let client_proof = create_proof(token, &transcript);
        write_json(
            &mut stream,
            &JsonRpcRequestV1 {
                jsonrpc: JsonRpcVersion::V2,
                id: request_id,
                protocol: server_hello.protocol,
                daemon_instance_nonce: server_hello.daemon_instance_nonce,
                request: LocalRequest::Hello(HelloParams {
                    client_role: role,
                    client_nonce,
                    session_proof: client_proof,
                }),
            },
        )
        .await?;
        let accepted: AuthAcceptedV1 = read_json(&mut stream)
            .await
            .map_err(|_| IpcError::AuthenticationFailed)?;
        if accepted.request_id != request_id {
            return Err(IpcError::AuthenticationFailed);
        }
        verify_server_proof(token, &transcript, &client_proof, &accepted.server_proof)?;
        Ok(ClientConnection {
            stream: Some(stream),
            protocol: server_hello.protocol,
            daemon_instance_nonce: server_hello.daemon_instance_nonce,
        })
    })
    .await
    .map_err(|_| IpcError::HandshakeTimeout)?
}

pub(crate) async fn server_handshake<S>(
    mut stream: S,
    token: &InstallationToken,
    server_hello: ServerHelloV1,
) -> Result<ServerConnection<S>, IpcError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    timeout(HANDSHAKE_TIMEOUT, async {
        write_json(&mut stream, &server_hello).await?;
        let raw = read_frame(&mut stream).await?;
        let probe: RequestProbe = match serde_json::from_slice(&raw) {
            Ok(probe) => probe,
            Err(error) => {
                write_boundary_error(
                    &mut stream,
                    None,
                    request_parse_code(&error),
                    invalid_request("Invalid request", ErrorCode::InvalidRequest, false),
                )
                .await?;
                return Err(IpcError::InvalidRequest);
            }
        };
        if probe.protocol != server_hello.protocol {
            write_boundary_error(
                &mut stream,
                Some(probe.id),
                JSON_RPC_INVALID_REQUEST,
                invalid_request(
                    "Protocol version unsupported",
                    ErrorCode::ProtocolVersionUnsupported,
                    false,
                ),
            )
            .await?;
            return Err(IpcError::ProtocolVersionUnsupported);
        }
        if probe.daemon_instance_nonce != server_hello.daemon_instance_nonce {
            write_boundary_error(
                &mut stream,
                Some(probe.id),
                JSON_RPC_INVALID_REQUEST,
                invalid_request("Invalid request", ErrorCode::InvalidRequest, true),
            )
            .await?;
            return Err(IpcError::InvalidRequest);
        }
        let hello: JsonRpcRequestV1 = match serde_json::from_slice(&raw) {
            Ok(hello) => hello,
            Err(_) => {
                write_boundary_error(
                    &mut stream,
                    Some(probe.id),
                    JSON_RPC_INVALID_REQUEST,
                    invalid_request("Invalid request", ErrorCode::InvalidRequest, false),
                )
                .await?;
                return Err(IpcError::InvalidRequest);
            }
        };
        let LocalRequest::Hello(params) = hello.request else {
            write_boundary_error(
                &mut stream,
                Some(hello.id),
                JSON_RPC_INVALID_REQUEST,
                invalid_request("Invalid request", ErrorCode::InvalidRequest, false),
            )
            .await?;
            return Err(IpcError::InvalidRequest);
        };
        let transcript = AuthTranscriptV1 {
            role: params.client_role,
            client_nonce: params.client_nonce,
            server_hello,
        };
        verify_proof(token, &transcript, &params.session_proof)?;
        write_json(
            &mut stream,
            &AuthAcceptedV1 {
                request_id: hello.id,
                server_proof: create_server_proof(token, &transcript, &params.session_proof),
            },
        )
        .await?;
        Ok(ServerConnection {
            _stream: stream,
            role: params.client_role,
            _protocol: server_hello.protocol,
            _daemon_instance_nonce: server_hello.daemon_instance_nonce,
            registry: RequestRegistry::default(),
        })
    })
    .await
    .map_err(|_| IpcError::HandshakeTimeout)?
}

#[cfg(test)]
mod endpoint_tests {
    use std::{
        collections::VecDeque,
        future::ready,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use super::{DAEMON_STARTUP_TIMEOUT, connect_endpoint_with};
    use crate::IpcError;

    #[tokio::test]
    async fn existing_endpoint_never_launches() {
        let mut connect_calls = 0;
        let mut launch_calls = 0;

        connect_endpoint_with(
            || {
                connect_calls += 1;
                ready(Ok::<_, IpcError>(()))
            },
            || {
                launch_calls += 1;
                Ok(())
            },
        )
        .await
        .unwrap();

        assert_eq!(connect_calls, 1);
        assert_eq!(launch_calls, 0);
    }

    #[tokio::test]
    async fn initial_non_missing_error_is_terminal_without_launching() {
        let mut connect_calls = 0;
        let mut launch_calls = 0;

        let error = connect_endpoint_with(
            || {
                connect_calls += 1;
                ready(Err::<(), _>(IpcError::InvalidRuntime))
            },
            || {
                launch_calls += 1;
                Ok(())
            },
        )
        .await
        .unwrap_err();

        assert!(matches!(error, IpcError::InvalidRuntime));
        assert_eq!(connect_calls, 1);
        assert_eq!(launch_calls, 0);
    }

    #[tokio::test]
    async fn launcher_failure_does_not_probe_again() {
        let mut connect_calls = 0;
        let mut launch_calls = 0;

        let error = connect_endpoint_with(
            || {
                connect_calls += 1;
                ready(Err::<(), _>(IpcError::EndpointNotFound))
            },
            || {
                launch_calls += 1;
                Err(IpcError::Io)
            },
        )
        .await
        .unwrap_err();

        assert!(matches!(error, IpcError::Io));
        assert_eq!(connect_calls, 1);
        assert_eq!(launch_calls, 1);
    }

    #[tokio::test]
    async fn only_initial_endpoint_not_found_launches_and_retries() {
        let mut outcomes = VecDeque::from([
            Err(IpcError::EndpointNotFound),
            Err(IpcError::EndpointNotFound),
            Ok(()),
        ]);
        let mut connect_calls = 0;
        let mut launch_calls = 0;

        connect_endpoint_with(
            || {
                connect_calls += 1;
                ready(outcomes.pop_front().unwrap())
            },
            || {
                launch_calls += 1;
                Ok(())
            },
        )
        .await
        .unwrap();

        assert_eq!(connect_calls, 3);
        assert_eq!(launch_calls, 1);
    }

    #[tokio::test]
    async fn non_missing_retry_error_is_terminal() {
        let mut outcomes: VecDeque<Result<(), IpcError>> = VecDeque::from([
            Err(IpcError::EndpointNotFound),
            Err(IpcError::AuthenticationFailed),
        ]);
        let mut connect_calls = 0;
        let mut launch_calls = 0;

        let error = connect_endpoint_with(
            || {
                connect_calls += 1;
                ready(outcomes.pop_front().unwrap())
            },
            || {
                launch_calls += 1;
                Ok(())
            },
        )
        .await
        .unwrap_err();

        assert!(matches!(error, IpcError::AuthenticationFailed));
        assert_eq!(connect_calls, 2);
        assert_eq!(launch_calls, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn startup_retries_stop_at_deadline_without_relaunching() {
        let connect_calls = Arc::new(AtomicUsize::new(0));
        let launch_calls = Arc::new(AtomicUsize::new(0));
        let observed_connects = connect_calls.clone();
        let observed_launches = launch_calls.clone();
        let started = tokio::time::Instant::now();
        let task = tokio::spawn(connect_endpoint_with(
            move || {
                connect_calls.fetch_add(1, Ordering::SeqCst);
                ready(Err::<(), _>(IpcError::EndpointNotFound))
            },
            move || {
                launch_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        ));

        tokio::task::yield_now().await;
        assert_eq!(observed_launches.load(Ordering::SeqCst), 1);
        assert!(!task.is_finished());

        tokio::time::advance(DAEMON_STARTUP_TIMEOUT - Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert!(!task.is_finished());

        tokio::time::advance(Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert!(matches!(
            task.await.unwrap(),
            Err(IpcError::EndpointNotFound)
        ));
        assert_eq!(
            tokio::time::Instant::now() - started,
            DAEMON_STARTUP_TIMEOUT
        );
        assert_eq!(observed_launches.load(Ordering::SeqCst), 1);
        assert!(observed_connects.load(Ordering::SeqCst) >= 2);
    }
}
