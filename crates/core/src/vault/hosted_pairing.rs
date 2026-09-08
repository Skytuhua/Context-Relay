use context_relay_protocol::PairingId;
use rusqlite::{OptionalExtension, params};

use super::{HostedRestoreIntent, Vault, VaultError};

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum HostedPairingRole {
    Join,
    Approve,
}

/// Original login and role; never contains tokens or device secrets.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedPairingIntent {
    pub project_url: String,
    pub user_id: uuid::Uuid,
    pub session_id: uuid::Uuid,
    pub role: HostedPairingRole,
}

impl HostedPairingIntent {
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
    id: PairingId,
) -> Result<Option<HostedPairingIntent>, VaultError> {
    let bytes: Option<Vec<u8>> = connection
        .query_row(
            "SELECT payload FROM hosted_pairing_intents WHERE pairing_id=?1",
            [id.to_string()],
            |row| row.get(0),
        )
        .optional()?;
    bytes
        .map(|bytes| {
            if bytes.len() > 8192 {
                return Err(VaultError::OperationConflict);
            }
            let intent: HostedPairingIntent =
                serde_json::from_slice(&bytes).map_err(|_| VaultError::OperationConflict)?;
            intent.validate()?;
            Ok(intent)
        })
        .transpose()
}

impl Vault {
    pub fn hosted_pairing_intent(
        &self,
        id: PairingId,
    ) -> Result<Option<HostedPairingIntent>, VaultError> {
        load(&self.connection, id)
    }

    /// Persist before preparing any signed work. Historical unbound work cannot
    /// acquire a new login, and an existing binding can only be replayed exactly.
    pub fn store_hosted_pairing_intent(
        &mut self,
        id: PairingId,
        intent: &HostedPairingIntent,
    ) -> Result<(), VaultError> {
        intent.validate()?;
        let transaction = self.connection.transaction()?;
        if let Some(existing) = load(&transaction, id)? {
            if existing != *intent {
                return Err(VaultError::OperationConflict);
            }
        } else {
            let prepared: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM pairing_joins WHERE pairing_id=?1)
                    OR EXISTS(SELECT 1 FROM pairing_decisions WHERE pairing_id=?1)
                    OR EXISTS(SELECT 1 FROM pairing_approval_transcripts WHERE pairing_id=?1)",
                [id.to_string()],
                |row| row.get(0),
            )?;
            if prepared {
                return Err(VaultError::OperationConflict);
            }
            let payload = serde_json::to_vec(intent).map_err(|_| VaultError::OperationConflict)?;
            transaction.execute(
                "INSERT INTO hosted_pairing_intents(pairing_id,payload) VALUES(?1,?2)",
                params![id.to_string(), payload],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }
}
