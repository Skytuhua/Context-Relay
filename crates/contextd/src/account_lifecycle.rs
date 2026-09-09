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

pub(crate) struct HostedAccountLifecycleService {
    owner: std::sync::Arc<context_relay_core::auth::HostedSessionOwner>,
    project: String,
    publishable_key: zeroize::Zeroizing<String>,
    identity: crate::pairing::PairingIdentity,
    #[cfg(test)]
    pub(crate) http: Option<std::sync::Arc<dyn context_relay_core::sync::SupabaseHttpClient>>,
}

impl HostedAccountLifecycleService {
    pub(crate) fn new(
        owner: std::sync::Arc<context_relay_core::auth::HostedSessionOwner>,
        project: &str,
        publishable_key: &str,
        identity: crate::pairing::PairingIdentity,
    ) -> Self {
        Self {
            owner,
            project: project.into(),
            publishable_key: zeroize::Zeroizing::new(publishable_key.into()),
            identity,
            #[cfg(test)]
            http: None,
        }
    }
}

impl AccountLifecycleService for HostedAccountLifecycleService {
    fn execute(
        &self,
        vault: &mut Vault,
        request: LocalRequest,
    ) -> Result<LocalResult, ClientError> {
        use context_relay_core::{
            devices::{
                recovery::{RecoveryEnrollmentClock, SystemRecoveryEnrollmentClock},
                supabase_account_lifecycle::SupabaseAccountLifecycleTransport,
            },
            sync::SupabaseTransportConfig,
            vault::DeviceCertificateState,
        };
        if !matches!(
            request,
            LocalRequest::AccountDeletionBegin(_)
                | LocalRequest::AccountDeletionCancel(_)
                | LocalRequest::AccountDeletionStatus(_)
        ) {
            return Err(invalid_request_error());
        }
        let denied = || transport_error(AccountLifecycleTransportError::Unauthorized);
        let now = SystemRecoveryEnrollmentClock.now_ms() / 1000;
        let generation = self.owner.cancellation().map_err(|_| denied())?;
        let session = self
            .owner
            .current_session(now)
            .map_err(|_| denied())?
            .ok_or_else(denied)?;
        let identity = *session.identity();
        self.owner
            .session_for(&generation, identity, now)
            .map_err(|_| denied())?;
        if reqwest::Url::parse(&self.project).ok().as_ref() != Some(session.project_url()) {
            return Err(denied());
        }
        let material = vault
            .trusted_workspace_material(&self.identity.keys)
            .map_err(intent_error)?;
        let scope = material.scope();
        let devices = vault.all_devices().map_err(intent_error)?;
        let mut matching = devices.iter().filter(|stored| {
            let certificate = &stored.certificate;
            stored.state == DeviceCertificateState::Active
                && certificate.device_id == self.identity.device_id
                && certificate.account_id == scope.account_id
                && certificate.workspace_id == scope.workspace_id
                && certificate.control_epoch == material.control_epoch()
                && certificate.signing_public_key == self.identity.keys.signing_public_key()
                && certificate.wrapping_public_key == self.identity.keys.wrapping_public_key()
        });
        if matching.next().is_none() || matching.next().is_some() {
            return Err(denied());
        }
        let config = SupabaseTransportConfig::new(
            &self.project,
            self.publishable_key.to_string(),
            session.access_token(),
        )
        .map_err(|_| invalid_request_error())?;
        #[cfg(test)]
        let transport = match &self.http {
            Some(http) => SupabaseAccountLifecycleTransport::with_http_client(
                config,
                scope.workspace_id,
                http.clone(),
            ),
            None => SupabaseAccountLifecycleTransport::new(config, scope.workspace_id),
        };
        #[cfg(not(test))]
        let transport = SupabaseAccountLifecycleTransport::new(config, scope.workspace_id);
        let transport = transport.map_err(transport_error)?.with_session_owner(
            self.owner.clone(),
            identity,
            generation,
            scope.account_id,
        );
        TransportAccountLifecycleService::new(transport).execute(vault, request)
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
