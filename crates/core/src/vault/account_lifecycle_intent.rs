use super::{HostedRestoreIntent, Vault, VaultError};
use context_relay_protocol::{AccountId, OperationId, WorkspaceId};
use rusqlite::{OptionalExtension, params};

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AccountLifecycleIntentAction {
    BeginDeletion,
    CancelDeletion,
}

/// Original explicit operation authority. Contains no credentials and authorizes no replay.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountLifecycleIntent {
    pub operation_id: OperationId,
    pub action: AccountLifecycleIntentAction,
    pub project_url: String,
    pub user_id: uuid::Uuid,
    pub session_id: uuid::Uuid,
    pub account_id: AccountId,
    pub workspace_id: WorkspaceId,
}
impl AccountLifecycleIntent {
    fn validate(&self) -> Result<(), VaultError> {
        HostedRestoreIntent {
            project_url: self.project_url.clone(),
            user_id: self.user_id,
            session_id: self.session_id,
        }
        .validate()
    }
}

fn load(
    connection: &rusqlite::Connection,
    id: OperationId,
) -> Result<Option<AccountLifecycleIntent>, VaultError> {
    let bytes: Option<Vec<u8>> = connection
        .query_row(
            "SELECT payload FROM account_lifecycle_intents WHERE operation_id=?1",
            [id.to_string()],
            |row| row.get(0),
        )
        .optional()?;
    bytes
        .map(|bytes| {
            if bytes.len() > 8192 {
                return Err(VaultError::OperationConflict);
            }
            let intent: AccountLifecycleIntent =
                serde_json::from_slice(&bytes).map_err(|_| VaultError::OperationConflict)?;
            intent.validate()?;
            if intent.operation_id != id {
                return Err(VaultError::OperationConflict);
            }
            Ok(intent)
        })
        .transpose()
}
impl Vault {
    pub fn account_lifecycle_intent(
        &self,
        id: OperationId,
    ) -> Result<Option<AccountLifecycleIntent>, VaultError> {
        load(&self.connection, id)
    }

    /// Call before the first mutation. An existing operation can never acquire new authority.
    pub fn store_account_lifecycle_intent(
        &mut self,
        intent: &AccountLifecycleIntent,
    ) -> Result<(), VaultError> {
        intent.validate()?;
        let payload = serde_json::to_vec(intent).map_err(|_| VaultError::OperationConflict)?;
        if payload.len() > 8192 {
            return Err(VaultError::OperationConflict);
        }
        let transaction = self.connection.transaction()?;
        if let Some(existing) = load(&transaction, intent.operation_id)? {
            if existing != *intent {
                return Err(VaultError::OperationConflict);
            }
        } else {
            transaction.execute(
                "INSERT INTO account_lifecycle_intents(operation_id,payload) VALUES(?1,?2)",
                params![intent.operation_id.to_string(), payload],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }
}
