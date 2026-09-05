mod auth;
mod connection;
mod frame;
#[cfg(any(windows, test))]
mod pipe_connect;
#[cfg(windows)]
mod shutdown;
mod transport;

#[cfg(test)]
mod handshake_tests;

pub use auth::{
    AuthAcceptedV1, AuthTranscriptV1, ConnectionChallenge, INSTALLATION_TOKEN_CREDENTIAL_ACCOUNT,
    INSTALLATION_TOKEN_CREDENTIAL_SERVICE, InstallationToken, ServerHelloV1, create_proof,
    create_server_proof, generate_instance_nonce, load_installation_token, role_allows,
    verify_proof, verify_server_proof,
};
pub use connection::{
    AuthenticatedConnection, AuthenticatedRequest, Client, RequestRegistration, RequestRegistry,
};
pub use context_relay_protocol::MAX_IPC_FRAME_BYTES;
pub use frame::{read_frame, read_json, write_frame, write_json};
#[cfg(windows)]
pub use shutdown::shutdown_running_daemon;
pub use transport::{ConnectedStream, InstanceGuard, Listener, RuntimeConfig, connect};

#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    #[error("IPC frame exceeds the maximum size")]
    FrameTooLarge,
    #[error("IPC frame is invalid")]
    InvalidFrame,
    #[error("IPC transport failed")]
    Io,
    #[error("Context Relay is already running")]
    AlreadyRunning,
    #[error("Context Relay endpoint was not found")]
    EndpointNotFound,
    #[error("IPC runtime is invalid")]
    InvalidRuntime,
    #[error("IPC transport is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("IPC authentication failed")]
    AuthenticationFailed,
    #[error("installation credential is unavailable")]
    MissingToken,
    #[error("installation credential is invalid")]
    InvalidToken,
    #[error("credential storage failed")]
    Credential,
    #[error("secure random generation failed")]
    Random,
    #[error("IPC handshake timed out")]
    HandshakeTimeout,
    #[error("IPC protocol version is unsupported")]
    ProtocolVersionUnsupported,
    #[error("IPC request is invalid")]
    InvalidRequest,
    #[error("Context Relay shutdown timed out")]
    ShutdownTimeout,
}

// One connection per maximum MCP call and cancellation, plus a narrow control reserve.
pub const CONNECTION_LIMIT: usize = 130;
pub const REQUEST_QUEUE_CAPACITY: usize = 64;
pub const RESPONSE_QUEUE_CAPACITY: usize = 64;
pub const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
pub const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
pub const SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

const MCP_DISPATCHER_CONNECTION_BUDGET: usize = 64;
const MCP_CANCELLATION_CONNECTION_BUDGET: usize = 64;
const CONTROL_CONNECTION_RESERVE: usize = 2;
const _: () = assert!(
    CONNECTION_LIMIT
        >= MCP_DISPATCHER_CONNECTION_BUDGET
            + MCP_CANCELLATION_CONNECTION_BUDGET
            + CONTROL_CONNECTION_RESERVE
);
