use std::{fmt::Write as _, future::Future};

use context_relay_local_ipc::{Client, IpcError};
use context_relay_protocol::{
    ClientError, ClientRole, ErrorCode, LocalRequest, LocalResult, PROTOCOL_VERSION,
    ProtocolVersion, RecordId, RecoveryEnrollmentChallenge, RecoveryEnrollmentConfirmParams,
    RecoveryEnrollmentHostBeginResult, RecoveryEnrollmentHostConfirmResult,
    RecoveryEnrollmentIdParams, RecoveryEnrollmentPhrase, RecoveryEnrollmentState,
};
use serde::Serialize;
use tauri::{AppHandle, State};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

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

#[derive(Default)]
struct DesktopRecoveryHostState {
    client: Mutex<Option<Client>>,
}

trait RecoveryHostDelegate {
    fn call(
        &mut self,
        role: ClientRole,
        id: RecordId,
        request: LocalRequest,
    ) -> impl Future<Output = Result<LocalResult, ClientError>> + Send + '_;
}

struct CachedRecoveryHostDelegate<'a> {
    client: &'a mut Option<Client>,
}

impl RecoveryHostDelegate for CachedRecoveryHostDelegate<'_> {
    async fn call(
        &mut self,
        role: ClientRole,
        id: RecordId,
        request: LocalRequest,
    ) -> Result<LocalResult, ClientError> {
        if self.client.is_none() {
            *self.client = Some(Client::connect(role).await.map_err(safe_ipc_error)?);
        }
        let result = self
            .client
            .as_mut()
            .expect("client was initialized")
            .call(id, request)
            .await;
        evict_on_call_error(self.client, &result);
        result
    }
}

trait RecoveryPhrasePrompt {
    fn show(&self, phrase: &RecoveryEnrollmentPhrase) -> bool;
}

trait RecoveryApprovalPrompt {
    fn show(&self, params: &RecoveryEnrollmentConfirmParams) -> bool;
}

struct NativeRecoveryPhrasePrompt<'a>(&'a AppHandle);

impl RecoveryPhrasePrompt for NativeRecoveryPhrasePrompt<'_> {
    fn show(&self, phrase: &RecoveryEnrollmentPhrase) -> bool {
        let message = recovery_phrase_message(phrase);
        self.0
            .dialog()
            .message(message.as_str())
            .title("Save your 24-word recovery phrase")
            .buttons(MessageDialogButtons::OkCancelCustom(
                "I saved all 24 words".into(),
                "Go back".into(),
            ))
            .blocking_show()
    }
}

struct NativeRecoveryApprovalPrompt<'a>(&'a AppHandle);

impl RecoveryApprovalPrompt for NativeRecoveryApprovalPrompt<'_> {
    fn show(&self, params: &RecoveryEnrollmentConfirmParams) -> bool {
        let message = recovery_confirmation_message(params);
        self.0
            .dialog()
            .message(message.as_str())
            .title("Activate this recovery phrase?")
            .buttons(MessageDialogButtons::OkCancelCustom(
                "Activate recovery".into(),
                "Go back".into(),
            ))
            .blocking_show()
    }
}

fn recovery_phrase_message(phrase: &RecoveryEnrollmentPhrase) -> Zeroizing<String> {
    let mut message = Zeroizing::new(String::from(
        "Never share these words. Write them down in this exact order. Context Relay cannot restore a lost phrase.\n\n",
    ));
    for (index, word) in phrase.recovery_phrase_words.as_words().iter().enumerate() {
        writeln!(&mut *message, "{}. {}", index + 1, word)
            .expect("writing to a String is infallible");
    }
    message
}

fn recovery_confirmation_message(params: &RecoveryEnrollmentConfirmParams) -> Zeroizing<String> {
    let mut message = Zeroizing::new(String::new());
    for answer in &params.confirmations {
        writeln!(&mut *message, "Word {}: {}", answer.position, answer.word)
            .expect("writing to a String is infallible");
    }
    message.push_str(
        "\nContinue only if these match the phrase you personally saved. Activating permanently establishes recovery for this workspace.",
    );
    message
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
    if matches!(
        request,
        LocalRequest::RecoveryEnrollmentBegin(_) | LocalRequest::RecoveryEnrollmentConfirm(_)
    ) {
        return Err(ClientError {
            code: ErrorCode::ScopeDenied,
            message: "This request requires native user approval".into(),
            field_path: None,
            retryable: false,
        });
    }
    let id = RecordId::new(uuid::Uuid::now_v7()).expect("UUID v7 is a valid RecordId");
    delegate(ClientRole::Desktop, id, request).await
}

async fn recovery_enrollment_begin_with<P, D>(
    prompt: &P,
    delegate: &mut D,
) -> Result<RecoveryEnrollmentHostBeginResult, ClientError>
where
    P: RecoveryPhrasePrompt,
    D: RecoveryHostDelegate,
{
    let result = delegate
        .call(
            ClientRole::DesktopRecoveryHost,
            new_request_id(),
            LocalRequest::RecoveryEnrollmentBegin(context_relay_protocol::EmptyParams {}),
        )
        .await?;
    match result {
        LocalResult::RecoveryEnrollmentPhrase { phrase } => {
            let challenge = RecoveryEnrollmentChallenge {
                enrollment_id: phrase.enrollment_id,
                confirmation_positions: phrase.confirmation_positions.clone(),
                created_at_ms: phrase.created_at_ms,
                expires_at_ms: phrase.expires_at_ms,
            };
            if prompt.show(&phrase) {
                return Ok(RecoveryEnrollmentHostBeginResult::Challenge(challenge));
            }
            match delegate
                .call(
                    ClientRole::DesktopRecoveryHost,
                    new_request_id(),
                    LocalRequest::RecoveryEnrollmentCancel(RecoveryEnrollmentIdParams {
                        enrollment_id: phrase.enrollment_id,
                    }),
                )
                .await?
            {
                LocalResult::RecoveryEnrollmentStatus { status }
                    if status.state == RecoveryEnrollmentState::Idle =>
                {
                    Ok(RecoveryEnrollmentHostBeginResult::Status(status))
                }
                _ => Err(invalid_result_error()),
            }
        }
        LocalResult::RecoveryEnrollmentStatus { status } => {
            Ok(RecoveryEnrollmentHostBeginResult::Status(status))
        }
        _ => Err(invalid_result_error()),
    }
}

async fn recovery_enrollment_confirm_with<P, D>(
    params: RecoveryEnrollmentConfirmParams,
    prompt: &P,
    delegate: &mut D,
) -> Result<RecoveryEnrollmentHostConfirmResult, ClientError>
where
    P: RecoveryApprovalPrompt,
    D: RecoveryHostDelegate,
{
    if !prompt.show(&params) {
        return Ok(RecoveryEnrollmentHostConfirmResult::Canceled);
    }
    match delegate
        .call(
            ClientRole::DesktopRecoveryHost,
            new_request_id(),
            LocalRequest::RecoveryEnrollmentConfirm(params),
        )
        .await?
    {
        LocalResult::RecoveryEnrollmentComplete { completion } => {
            Ok(RecoveryEnrollmentHostConfirmResult::Complete(completion))
        }
        LocalResult::RecoveryEnrollmentStatus { status } => {
            Ok(RecoveryEnrollmentHostConfirmResult::Status(status))
        }
        _ => Err(invalid_result_error()),
    }
}

#[tauri::command]
async fn recovery_enrollment_begin(
    app: AppHandle,
    state: State<'_, DesktopRecoveryHostState>,
) -> Result<RecoveryEnrollmentHostBeginResult, ClientError> {
    let mut client = state.client.lock().await;
    let mut delegate = CachedRecoveryHostDelegate {
        client: &mut client,
    };
    recovery_enrollment_begin_with(&NativeRecoveryPhrasePrompt(&app), &mut delegate).await
}

#[tauri::command]
async fn recovery_enrollment_confirm(
    app: AppHandle,
    params: RecoveryEnrollmentConfirmParams,
    state: State<'_, DesktopRecoveryHostState>,
) -> Result<RecoveryEnrollmentHostConfirmResult, ClientError> {
    let mut client = state.client.lock().await;
    let mut delegate = CachedRecoveryHostDelegate {
        client: &mut client,
    };
    recovery_enrollment_confirm_with(params, &NativeRecoveryApprovalPrompt(&app), &mut delegate)
        .await
}

fn new_request_id() -> RecordId {
    RecordId::new(uuid::Uuid::now_v7()).expect("UUID v7 is a valid RecordId")
}

fn invalid_result_error() -> ClientError {
    ClientError {
        code: ErrorCode::InvalidRequest,
        message: "The local service returned an invalid recovery result".into(),
        field_path: None,
        retryable: false,
    }
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
        .plugin(tauri_plugin_dialog::init())
        .manage(LocalClientState::default())
        .manage(DesktopRecoveryHostState::default())
        .invoke_handler(tauri::generate_handler![
            application_info,
            local_request,
            recovery_enrollment_begin,
            recovery_enrollment_confirm
        ])
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
        ClientError, ClientRole, DaemonInstanceNonce, DecimalTimestamp, EmptyParams, ErrorCode,
        HelloParams, InstallationTokenProof, LocalRequest, LocalResult,
        RecoveryEnrollmentChallenge, RecoveryEnrollmentConfirmParams,
        RecoveryEnrollmentHostBeginResult, RecoveryEnrollmentHostConfirmResult,
        RecoveryEnrollmentId, RecoveryEnrollmentIdParams, RecoveryEnrollmentPhrase,
        RecoveryEnrollmentState, RecoveryEnrollmentStatus, RecoveryPhraseWords,
        RecoveryWordConfirmation,
    };

    use super::{
        RecoveryApprovalPrompt, RecoveryHostDelegate, RecoveryPhrasePrompt, evict_on_call_error,
        local_request_with, recovery_confirmation_message, recovery_enrollment_begin_with,
        recovery_enrollment_confirm_with, recovery_phrase_message, safe_ipc_error,
    };

    fn enrollment_id() -> RecoveryEnrollmentId {
        "018f22e2-79b0-7cc8-98c4-dc0c0c075601".parse().unwrap()
    }

    fn phrase() -> RecoveryEnrollmentPhrase {
        RecoveryEnrollmentPhrase {
            enrollment_id: enrollment_id(),
            recovery_phrase_words: RecoveryPhraseWords::new(vec!["abandon".into(); 24]).unwrap(),
            confirmation_positions: vec![1, 7, 13, 24],
            created_at_ms: DecimalTimestamp(1_000),
            expires_at_ms: DecimalTimestamp(601_000),
        }
    }

    #[derive(Default)]
    struct RecordingDelegate {
        calls: Vec<(ClientRole, LocalRequest)>,
        results: std::collections::VecDeque<Result<LocalResult, ClientError>>,
    }

    impl RecoveryHostDelegate for RecordingDelegate {
        fn call(
            &mut self,
            role: ClientRole,
            _id: context_relay_protocol::RecordId,
            request: LocalRequest,
        ) -> impl std::future::Future<Output = Result<LocalResult, ClientError>> + Send + '_
        {
            self.calls.push((role, request));
            ready(self.results.pop_front().unwrap())
        }
    }

    struct PhrasePrompt(bool);

    impl RecoveryPhrasePrompt for PhrasePrompt {
        fn show(&self, phrase: &RecoveryEnrollmentPhrase) -> bool {
            assert_eq!(phrase.recovery_phrase_words.as_words().len(), 24);
            self.0
        }
    }

    struct ApprovalPrompt(bool);

    impl RecoveryApprovalPrompt for ApprovalPrompt {
        fn show(&self, params: &RecoveryEnrollmentConfirmParams) -> bool {
            assert_eq!(params.confirmations.len(), 4);
            self.0
        }
    }

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

    #[tokio::test]
    async fn generic_request_rejects_sensitive_recovery_methods_before_delegate() {
        for request in [
            LocalRequest::RecoveryEnrollmentBegin(EmptyParams {}),
            LocalRequest::RecoveryEnrollmentConfirm(RecoveryEnrollmentConfirmParams {
                enrollment_id: enrollment_id(),
                confirmations: vec![
                    RecoveryWordConfirmation {
                        position: 1,
                        word: "alpha".into(),
                    },
                    RecoveryWordConfirmation {
                        position: 7,
                        word: "bravo".into(),
                    },
                    RecoveryWordConfirmation {
                        position: 13,
                        word: "charlie".into(),
                    },
                    RecoveryWordConfirmation {
                        position: 24,
                        word: "delta".into(),
                    },
                ],
            }),
        ] {
            let called = Cell::new(false);
            let error = local_request_with(request, |_, _, _| {
                called.set(true);
                ready(Ok(LocalResult::Empty))
            })
            .await
            .unwrap_err();
            assert_eq!(error.code, ErrorCode::ScopeDenied);
            assert!(!called.get());
        }
    }

    #[tokio::test]
    async fn native_begin_never_returns_phrase_and_decline_requires_exact_cancel() {
        let idle = RecoveryEnrollmentStatus {
            enrollment_id: None,
            state: RecoveryEnrollmentState::Idle,
            created_at_ms: None,
            transitioned_at_ms: None,
        };
        let mut accepted = RecordingDelegate {
            calls: Vec::new(),
            results: [Ok(LocalResult::RecoveryEnrollmentPhrase {
                phrase: phrase(),
            })]
            .into_iter()
            .collect(),
        };
        let result = recovery_enrollment_begin_with(&PhrasePrompt(true), &mut accepted)
            .await
            .unwrap();
        assert!(
            matches!(result, RecoveryEnrollmentHostBeginResult::Challenge(
            RecoveryEnrollmentChallenge { confirmation_positions, .. }
        ) if confirmation_positions == vec![1, 7, 13, 24])
        );
        assert_eq!(accepted.calls.len(), 1);
        assert_eq!(accepted.calls[0].0, ClientRole::DesktopRecoveryHost);

        let mut declined = RecordingDelegate {
            calls: Vec::new(),
            results: [
                Ok(LocalResult::RecoveryEnrollmentPhrase { phrase: phrase() }),
                Ok(LocalResult::RecoveryEnrollmentStatus {
                    status: idle.clone(),
                }),
            ]
            .into_iter()
            .collect(),
        };
        assert_eq!(
            recovery_enrollment_begin_with(&PhrasePrompt(false), &mut declined)
                .await
                .unwrap(),
            RecoveryEnrollmentHostBeginResult::Status(idle)
        );
        assert!(matches!(
            &declined.calls[1],
            (
                ClientRole::DesktopRecoveryHost,
                LocalRequest::RecoveryEnrollmentCancel(RecoveryEnrollmentIdParams {
                    enrollment_id: id
                })
            ) if *id == enrollment_id()
        ));

        let retryable = ClientError {
            code: ErrorCode::Internal,
            message: "temporarily unavailable".into(),
            field_path: None,
            retryable: true,
        };
        let mut failed_cancel = RecordingDelegate {
            calls: Vec::new(),
            results: [
                Ok(LocalResult::RecoveryEnrollmentPhrase { phrase: phrase() }),
                Err(retryable.clone()),
            ]
            .into_iter()
            .collect(),
        };
        assert_eq!(
            recovery_enrollment_begin_with(&PhrasePrompt(false), &mut failed_cancel)
                .await
                .unwrap_err(),
            retryable
        );
    }

    #[test]
    fn native_prompt_builders_number_only_the_exact_words_and_answers() {
        let phrase = phrase();
        let message = recovery_phrase_message(&phrase);
        assert!(message.starts_with("Never share these words."));
        assert_eq!(message.matches(". abandon\n").count(), 24);
        assert!(message.contains("1. abandon\n"));
        assert!(message.ends_with("24. abandon\n"));

        let params = RecoveryEnrollmentConfirmParams {
            enrollment_id: enrollment_id(),
            confirmations: vec![
                RecoveryWordConfirmation {
                    position: 1,
                    word: "alpha".into(),
                },
                RecoveryWordConfirmation {
                    position: 7,
                    word: "bravo".into(),
                },
                RecoveryWordConfirmation {
                    position: 13,
                    word: "charlie".into(),
                },
                RecoveryWordConfirmation {
                    position: 24,
                    word: "delta".into(),
                },
            ],
        };
        let confirmation = recovery_confirmation_message(&params);
        assert!(
            confirmation
                .starts_with("Word 1: alpha\nWord 7: bravo\nWord 13: charlie\nWord 24: delta\n")
        );
        assert!(
            confirmation
                .ends_with("Activating permanently establishes recovery for this workspace.")
        );
    }

    #[tokio::test]
    async fn native_confirmation_decline_never_delegates_and_accept_uses_host_role() {
        let params = RecoveryEnrollmentConfirmParams {
            enrollment_id: enrollment_id(),
            confirmations: vec![
                RecoveryWordConfirmation {
                    position: 1,
                    word: "alpha".into(),
                },
                RecoveryWordConfirmation {
                    position: 7,
                    word: "bravo".into(),
                },
                RecoveryWordConfirmation {
                    position: 13,
                    word: "charlie".into(),
                },
                RecoveryWordConfirmation {
                    position: 24,
                    word: "delta".into(),
                },
            ],
        };
        let mut declined = RecordingDelegate::default();
        assert_eq!(
            recovery_enrollment_confirm_with(params.clone(), &ApprovalPrompt(false), &mut declined)
                .await
                .unwrap(),
            RecoveryEnrollmentHostConfirmResult::Canceled
        );
        assert!(declined.calls.is_empty());

        let status = RecoveryEnrollmentStatus {
            enrollment_id: Some(enrollment_id()),
            state: RecoveryEnrollmentState::Submitting,
            created_at_ms: Some(DecimalTimestamp(1_000)),
            transitioned_at_ms: Some(DecimalTimestamp(2_000)),
        };
        let mut accepted = RecordingDelegate {
            calls: Vec::new(),
            results: [Ok(LocalResult::RecoveryEnrollmentStatus {
                status: status.clone(),
            })]
            .into_iter()
            .collect(),
        };
        assert_eq!(
            recovery_enrollment_confirm_with(params.clone(), &ApprovalPrompt(true), &mut accepted)
                .await
                .unwrap(),
            RecoveryEnrollmentHostConfirmResult::Status(status)
        );
        assert_eq!(
            accepted.calls,
            vec![(
                ClientRole::DesktopRecoveryHost,
                LocalRequest::RecoveryEnrollmentConfirm(params),
            )]
        );
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
