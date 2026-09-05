use std::fmt;
#[cfg(feature = "test-support")]
use std::sync::Arc;

use context_relay_local_ipc::Client;
#[cfg(feature = "test-support")]
use context_relay_local_ipc::{InstallationToken, RuntimeConfig};
use context_relay_protocol::{
    CancelParams, ClientError, ClientRole, ErrorCode, LocalRequest, LocalResult, McpCallParams,
    NativeHookEventParams, RecordId,
};
use serde_json::Value;
#[cfg(feature = "test-support")]
use tokio::sync::Notify;
use uuid::Uuid;

pub trait Daemon: Clone + Send + Sync + 'static {
    fn call(
        &self,
        request_id: RecordId,
        call: McpCallParams,
    ) -> impl Future<Output = Result<Value, BridgeError>> + Send;

    fn cancel(&self, request_id: RecordId) -> impl Future<Output = Result<(), BridgeError>> + Send;
}

pub trait NativeHookDaemon: Clone + Send + Sync + 'static {
    fn native_hook(
        &self,
        params: NativeHookEventParams,
    ) -> impl Future<Output = Result<LocalResult, BridgeError>> + Send;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BridgeError {
    Client(ClientError),
    FrameTooLarge,
    HookInputTooLarge,
    InvalidHookInput,
    Io,
    Unavailable,
}

impl BridgeError {
    pub const fn redacted_message(&self) -> &'static str {
        match self {
            Self::Client(error) => match error.code {
                ErrorCode::VaultLocked => "The local vault is locked",
                ErrorCode::NotFound => "The requested record was not found",
                ErrorCode::RevisionConflict => "The record revision changed",
                ErrorCode::ScopeDenied => "The requested scope is not available",
                ErrorCode::Canceled => "The request was canceled",
                ErrorCode::Timeout => "The request timed out with an unknown outcome",
                ErrorCode::Busy => "The local service is busy",
                _ => "The local service could not complete the request",
            },
            Self::FrameTooLarge => "An MCP message exceeded the size limit",
            Self::HookInputTooLarge => "A hook event exceeded the size limit",
            Self::InvalidHookInput => "A hook event was invalid",
            Self::Io | Self::Unavailable => "The local service is unavailable",
        }
    }

    pub(crate) fn client_error(&self) -> ClientError {
        match self {
            Self::Client(error) => error.clone(),
            Self::FrameTooLarge => ClientError {
                code: ErrorCode::FrameTooLarge,
                message: self.redacted_message().into(),
                field_path: None,
                retryable: false,
            },
            Self::HookInputTooLarge | Self::InvalidHookInput => ClientError {
                code: ErrorCode::InvalidRequest,
                message: self.redacted_message().into(),
                field_path: None,
                retryable: false,
            },
            Self::Io | Self::Unavailable => ClientError {
                code: ErrorCode::Internal,
                message: self.redacted_message().into(),
                field_path: None,
                retryable: true,
            },
        }
    }
}

impl fmt::Display for BridgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.redacted_message())
    }
}

impl std::error::Error for BridgeError {}

impl From<std::io::Error> for BridgeError {
    fn from(_: std::io::Error) -> Self {
        Self::Io
    }
}

impl From<ClientError> for BridgeError {
    fn from(error: ClientError) -> Self {
        Self::Client(error)
    }
}

#[derive(Clone, Default)]
pub struct LocalDaemon {
    target: ConnectionTarget,
    #[cfg(feature = "test-support")]
    test_observer: Arc<TestObserver>,
}

#[derive(Clone, Default)]
enum ConnectionTarget {
    #[default]
    Production,
    #[cfg(feature = "test-support")]
    Test {
        runtime: RuntimeConfig,
        token: Arc<InstallationToken>,
    },
}

impl LocalDaemon {
    #[cfg(feature = "test-support")]
    pub fn for_test(runtime: RuntimeConfig, token: InstallationToken) -> Self {
        Self {
            target: ConnectionTarget::Test {
                runtime,
                token: Arc::new(token),
            },
            test_observer: Arc::default(),
        }
    }

    async fn connect(&self) -> Result<Client, BridgeError> {
        match &self.target {
            ConnectionTarget::Production => Client::connect(ClientRole::McpBridge)
                .await
                .map_err(|_| BridgeError::Unavailable),
            #[cfg(feature = "test-support")]
            ConnectionTarget::Test { runtime, token } => {
                Client::connect_for_test(runtime, ClientRole::McpBridge, token)
                    .await
                    .map_err(|_| BridgeError::Unavailable)
            }
        }
    }

    #[cfg(feature = "test-support")]
    pub async fn wait_for_test_cancels(&self, count: usize) {
        loop {
            let changed = self.test_observer.cancels_changed.notified();
            if self
                .test_observer
                .cancels
                .load(std::sync::atomic::Ordering::Acquire)
                >= count
            {
                return;
            }
            changed.await;
        }
    }

    #[cfg(feature = "test-support")]
    pub fn hold_test_calls(&self) {
        self.test_observer
            .calls_held
            .store(true, std::sync::atomic::Ordering::Release);
    }

    #[cfg(feature = "test-support")]
    pub fn release_test_calls(&self) {
        self.test_observer
            .calls_held
            .store(false, std::sync::atomic::Ordering::Release);
        self.test_observer.calls_released.notify_waiters();
    }

    #[cfg(feature = "test-support")]
    pub async fn wait_for_test_call_completions(&self, count: usize) {
        loop {
            let changed = self.test_observer.call_completions_changed.notified();
            if self
                .test_observer
                .call_completions
                .load(std::sync::atomic::Ordering::Acquire)
                >= count
            {
                return;
            }
            changed.await;
        }
    }
}

impl Daemon for LocalDaemon {
    fn call(
        &self,
        request_id: RecordId,
        call: McpCallParams,
    ) -> impl Future<Output = Result<Value, BridgeError>> + Send {
        let daemon = self.clone();
        async move {
            #[cfg(feature = "test-support")]
            daemon.test_observer.wait_for_calls_released().await;
            let result = async {
                let expected_name = call.name.clone();
                let mut client = daemon.connect().await?;
                decode_mcp_result(
                    &expected_name,
                    client.call(request_id, LocalRequest::McpCall(call)).await?,
                )
            }
            .await;
            #[cfg(feature = "test-support")]
            daemon.test_observer.record_call_completion();
            result
        }
    }

    fn cancel(&self, request_id: RecordId) -> impl Future<Output = Result<(), BridgeError>> + Send {
        let daemon = self.clone();
        async move {
            let mut client = daemon.connect().await?;
            let cancel_id =
                RecordId::new(Uuid::now_v7()).expect("UUID v7 generator returns a valid RecordId");
            match client
                .call(cancel_id, LocalRequest::Cancel(CancelParams { request_id }))
                .await?
            {
                LocalResult::Empty => {
                    #[cfg(feature = "test-support")]
                    {
                        daemon
                            .test_observer
                            .cancels
                            .fetch_add(1, std::sync::atomic::Ordering::Release);
                        daemon.test_observer.cancels_changed.notify_waiters();
                    }
                    Ok(())
                }
                _ => Err(invalid_daemon_result()),
            }
        }
    }
}

impl NativeHookDaemon for LocalDaemon {
    fn native_hook(
        &self,
        params: NativeHookEventParams,
    ) -> impl Future<Output = Result<LocalResult, BridgeError>> + Send {
        let daemon = self.clone();
        async move {
            let mut client = daemon.connect().await?;
            let request_id =
                RecordId::new(Uuid::now_v7()).expect("UUID v7 generator returns a valid RecordId");
            client
                .call(request_id, LocalRequest::NativeHookEvent(params))
                .await
                .map_err(BridgeError::from)
        }
    }
}

fn decode_mcp_result(expected_name: &str, result: LocalResult) -> Result<Value, BridgeError> {
    match result {
        LocalResult::McpOutput { name, output } if name == expected_name => Ok(output),
        _ => Err(invalid_daemon_result()),
    }
}

pub(crate) fn invalid_daemon_result() -> BridgeError {
    BridgeError::Client(ClientError {
        code: ErrorCode::Internal,
        message: "The local service returned an invalid response".into(),
        field_path: None,
        retryable: false,
    })
}

#[cfg(feature = "test-support")]
#[derive(Default)]
struct TestObserver {
    cancels: std::sync::atomic::AtomicUsize,
    cancels_changed: Notify,
    calls_held: std::sync::atomic::AtomicBool,
    calls_released: Notify,
    call_completions: std::sync::atomic::AtomicUsize,
    call_completions_changed: Notify,
}

#[cfg(feature = "test-support")]
impl TestObserver {
    async fn wait_for_calls_released(&self) {
        loop {
            let released = self.calls_released.notified();
            if !self.calls_held.load(std::sync::atomic::Ordering::Acquire) {
                return;
            }
            released.await;
        }
    }

    fn record_call_completion(&self) {
        self.call_completions
            .fetch_add(1, std::sync::atomic::Ordering::Release);
        self.call_completions_changed.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use context_relay_protocol::LocalResult;
    use serde_json::json;

    use super::{BridgeError, decode_mcp_result};

    #[test]
    fn daemon_output_name_must_match_the_requested_tool_exactly() {
        assert_eq!(
            decode_mcp_result(
                "context_relay_status",
                LocalResult::McpOutput {
                    name: "context_relay_status".into(),
                    output: json!({"ok": true}),
                },
            ),
            Ok(json!({"ok": true}))
        );
        assert!(matches!(
            decode_mcp_result(
                "context_relay_status",
                LocalResult::McpOutput {
                    name: "context_relay_search".into(),
                    output: json!({"ok": true}),
                },
            ),
            Err(BridgeError::Client(_))
        ));
    }
}
