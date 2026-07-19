use std::future::Future;

use context_relay_local_ipc::{Client, IpcError};
use context_relay_protocol::{
    ClientError, ClientRole, ErrorCode, LocalRequest, LocalResult, PROTOCOL_VERSION,
    ProtocolVersion, RecordId,
};
use serde::Serialize;
use tauri::State;
use tokio::sync::Mutex;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApplicationInfo {
    application_version: &'static str,
    protocol_version: ProtocolVersion,
}

#[tauri::command]
fn application_info() -> ApplicationInfo {
    ApplicationInfo {
        application_version: env!("CARGO_PKG_VERSION"),
        protocol_version: PROTOCOL_VERSION,
    }
}

#[derive(Default)]
struct LocalClientState {
    client: Mutex<Option<Client>>,
}

#[tauri::command]
async fn local_request(
    request: LocalRequest,
    state: State<'_, LocalClientState>,
) -> Result<LocalResult, ClientError> {
    local_request_with(request, |role, id, request| async move {
        let mut client = state.client.lock().await;
        if client.is_none() {
            *client = Some(Client::connect(role).await.map_err(safe_ipc_error)?);
        }
        let result = client
            .as_mut()
            .expect("client was initialized")
            .call(id, request)
            .await;
        evict_on_call_error(&mut client, &result);
        result
    })
    .await
}

async fn local_request_with<F, Fut>(
    request: LocalRequest,
    delegate: F,
) -> Result<LocalResult, ClientError>
where
    F: FnOnce(ClientRole, RecordId, LocalRequest) -> Fut,
    Fut: Future<Output = Result<LocalResult, ClientError>>,
{
    if matches!(request, LocalRequest::Hello(_)) {
        return Err(ClientError {
            code: ErrorCode::InvalidRequest,
            message: "Invalid request".into(),
            field_path: None,
            retryable: false,
        });
    }
    let id = RecordId::new(uuid::Uuid::now_v7()).expect("UUID v7 is a valid RecordId");
    delegate(ClientRole::Desktop, id, request).await
}

fn safe_ipc_error(_: IpcError) -> ClientError {
    ClientError {
        code: ErrorCode::Internal,
        message: "The local service is unavailable".into(),
        field_path: None,
        retryable: true,
    }
}

fn evict_on_call_error<T>(client: &mut Option<T>, result: &Result<LocalResult, ClientError>) {
    if result.is_err() {
        client.take();
    }
}

fn main() {
    tauri::Builder::default()
        .manage(LocalClientState::default())
        .invoke_handler(tauri::generate_handler![application_info, local_request])
        .run(tauri::generate_context!())
        .expect("Context Relay desktop shell should run");
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        future::ready,
        rc::Rc,
    };

    use context_relay_local_ipc::IpcError;
    use context_relay_protocol::{
        ClientError, ClientRole, DaemonInstanceNonce, EmptyParams, ErrorCode, HelloParams,
        InstallationTokenProof, LocalRequest, LocalResult,
    };

    use super::{evict_on_call_error, local_request_with, safe_ipc_error};

    #[tokio::test]
    async fn hello_is_rejected_before_delegate() {
        let called = Cell::new(false);
        let result = local_request_with(
            LocalRequest::Hello(HelloParams {
                client_role: ClientRole::Desktop,
                client_nonce: DaemonInstanceNonce::new([0; 32]),
                session_proof: InstallationTokenProof([0; 32]),
            }),
            |_, _, _| {
                called.set(true);
                ready(Ok(LocalResult::Empty))
            },
        )
        .await
        .unwrap_err();

        assert_eq!(result.code, ErrorCode::InvalidRequest);
        assert!(!called.get());
    }

    #[tokio::test]
    async fn health_uses_desktop_role_and_rust_uuid_v7() {
        let observed = Rc::new(RefCell::new(None));
        let capture = observed.clone();

        let result = local_request_with(
            LocalRequest::Health(EmptyParams {}),
            move |role, id, request| {
                *capture.borrow_mut() = Some((role, id, request));
                ready(Ok(LocalResult::Empty))
            },
        )
        .await
        .unwrap();

        assert_eq!(result, LocalResult::Empty);
        let (role, id, request) = observed.borrow_mut().take().unwrap();
        assert_eq!(role, ClientRole::Desktop);
        assert_eq!(id.as_uuid().get_version(), Some(uuid::Version::SortRand));
        assert!(matches!(request, LocalRequest::Health(_)));
    }

    #[test]
    fn every_ipc_error_has_the_same_safe_mapping() {
        let expected = ClientError {
            code: ErrorCode::Internal,
            message: "The local service is unavailable".into(),
            field_path: None,
            retryable: true,
        };
        for error in [
            IpcError::FrameTooLarge,
            IpcError::InvalidFrame,
            IpcError::Io,
            IpcError::AlreadyRunning,
            IpcError::EndpointNotFound,
            IpcError::InvalidRuntime,
            IpcError::UnsupportedPlatform,
            IpcError::AuthenticationFailed,
            IpcError::MissingToken,
            IpcError::InvalidToken,
            IpcError::Credential,
            IpcError::Random,
            IpcError::HandshakeTimeout,
            IpcError::ProtocolVersionUnsupported,
            IpcError::InvalidRequest,
        ] {
            assert_eq!(safe_ipc_error(error), expected);
        }
    }

    #[test]
    fn typed_call_errors_are_preserved_and_evict_the_cached_client() {
        let expected = ClientError {
            code: ErrorCode::ScopeDenied,
            message: "denied".into(),
            field_path: Some("scope".into()),
            retryable: false,
        };
        let result: Result<LocalResult, ClientError> = Err(expected.clone());
        let mut client = Some(());

        evict_on_call_error(&mut client, &result);

        assert!(client.is_none());
        assert_eq!(result, Err(expected));
    }
}
