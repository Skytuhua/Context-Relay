use context_relay_core::{
    devices::account_lifecycle::{
        AccountDeletionProjection, AccountLifecycleTransport, AccountLifecycleTransportError,
    },
    vault::{AccountLifecycleIntentAction, Vault, VaultError},
};
use context_relay_protocol::{
    ClientError, DecimalTimestamp, ErrorCode, LocalRequest, LocalResult, OperationId,
};

/// Daemon-owned account lifecycle boundary.
///
/// Production implementations must derive account and session authority from an authenticated
/// hosted session. The renderer can request a transition, but it cannot inject a transport,
/// account identifier, session identifier, or provider receipt.
pub(crate) trait AccountLifecycleService: Send + Sync {
    fn execute(&self, vault: &mut Vault, request: LocalRequest)
    -> Result<LocalResult, ClientError>;
}

pub(crate) struct TransportAccountLifecycleService<T> {
    transport: T,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct UnavailableAccountLifecycleTransport;

impl AccountLifecycleTransport for UnavailableAccountLifecycleTransport {
    fn deletion_status(&self) -> Result<AccountDeletionProjection, AccountLifecycleTransportError> {
        Err(AccountLifecycleTransportError::Unavailable)
    }

    fn begin_deletion(
        &self,
        _operation_id: OperationId,
    ) -> Result<AccountDeletionProjection, AccountLifecycleTransportError> {
        Err(AccountLifecycleTransportError::Unavailable)
    }

    fn cancel_deletion(
        &self,
        _operation_id: OperationId,
    ) -> Result<AccountDeletionProjection, AccountLifecycleTransportError> {
        Err(AccountLifecycleTransportError::Unavailable)
    }
}

impl<T> TransportAccountLifecycleService<T> {
    pub(crate) const fn new(transport: T) -> Self {
        Self { transport }
    }
}

impl<T: AccountLifecycleTransport> AccountLifecycleService for TransportAccountLifecycleService<T> {
    fn execute(
        &self,
        vault: &mut Vault,
        request: LocalRequest,
    ) -> Result<LocalResult, ClientError> {
        let mutation = match &request {
            LocalRequest::AccountDeletionBegin(params) => Some((
                params.operation_id,
                AccountLifecycleIntentAction::BeginDeletion,
            )),
            LocalRequest::AccountDeletionCancel(params) => Some((
                params.operation_id,
                AccountLifecycleIntentAction::CancelDeletion,
            )),
            LocalRequest::AccountDeletionStatus(_) => None,
            _ => return Err(invalid_request_error()),
        };
        if let Some((operation_id, action)) = mutation {
            if let Some(intent) = self
                .transport
                .hosted_intent(operation_id, action)
                .map_err(transport_error)?
            {
                if intent.operation_id != operation_id || intent.action != action {
                    return Err(transport_error(AccountLifecycleTransportError::Conflict));
                }
                vault
                    .store_account_lifecycle_intent(&intent)
                    .map_err(intent_error)?;
            } else if vault
                .account_lifecycle_intent(operation_id)
                .map_err(intent_error)?
                .is_some()
            {
                // An unbound transport cannot adopt previously authenticated work.
                return Err(transport_error(AccountLifecycleTransportError::Conflict));
            }
        }
        let projection = match request {
            LocalRequest::AccountDeletionBegin(params) => {
                self.transport.begin_deletion(params.operation_id)
            }
            LocalRequest::AccountDeletionStatus(_) => self.transport.deletion_status(),
            LocalRequest::AccountDeletionCancel(params) => {
                self.transport.cancel_deletion(params.operation_id)
            }
            _ => return Err(invalid_request_error()),
        }
        .map_err(transport_error)?;
        result(projection)
    }
}

fn result(projection: AccountDeletionProjection) -> Result<LocalResult, ClientError> {
    projection.validate().map_err(transport_error)?;
    Ok(LocalResult::AccountDeletion {
        state: projection.state,
        purge_deadline: projection.purge_deadline_ms.map(DecimalTimestamp),
        export_available: projection.export_available(),
    })
}

fn transport_error(error: AccountLifecycleTransportError) -> ClientError {
    let (code, message, retryable) = match error {
        AccountLifecycleTransportError::Invalid => (
            ErrorCode::InvalidRequest,
            "The account lifecycle request is invalid",
            false,
        ),
        AccountLifecycleTransportError::Unavailable => (
            ErrorCode::HarnessUnsupported,
            "Account lifecycle needs the hosted workspace service and is not available in this build.",
            false,
        ),
        AccountLifecycleTransportError::Conflict => (
            ErrorCode::Conflict,
            "The hosted account lifecycle state changed",
            false,
        ),
        AccountLifecycleTransportError::Unauthorized => (
            ErrorCode::ScopeDenied,
            "This device is not authorized for account lifecycle changes",
            false,
        ),
        AccountLifecycleTransportError::Transient => (
            ErrorCode::Internal,
            "The hosted account lifecycle service is temporarily unavailable",
            true,
        ),
    };
    ClientError {
        code,
        message: message.into(),
        field_path: None,
        retryable,
    }
}

fn invalid_request_error() -> ClientError {
    transport_error(AccountLifecycleTransportError::Invalid)
}

fn intent_error(error: VaultError) -> ClientError {
    transport_error(match error {
        VaultError::OperationConflict | VaultError::Validation(_) => {
            AccountLifecycleTransportError::Conflict
        }
        _ => AccountLifecycleTransportError::Transient,
    })
}
