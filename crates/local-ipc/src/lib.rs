mod auth;
mod connection;
mod frame;
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
}

pub const CONNECTION_LIMIT: usize = 32;
pub const REQUEST_QUEUE_CAPACITY: usize = 64;
pub const RESPONSE_QUEUE_CAPACITY: usize = 64;
pub const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
pub const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
pub const SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
