use context_relay_protocol::{Ed25519SignatureBytes, OperationId};
use minicbor::{Decoder, Encoder};
use rusqlite::{Connection, params};

use super::{HostedRestoreIntent, Vault, VaultError};
use crate::{
    crypto::DeviceCertificateV1,
    devices::{
        crypto::{decode_certificate_v1, encode_certificate_v1},
        revocation_crypto::{
            DeviceRevocationStatementV1, RevocationControlState, RevocationTransitionV1,
        },
    },
};

/// Exact prepared artifacts and original hosted identity, inside SQLCipher.
/// Contains no tokens or plaintext keys. Presence is neither hosted acceptance
/// nor permission to replay after the authenticated account/session changes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceRevocationIntent {
    pub project_url: String,
    pub user_id: uuid::Uuid,
    pub session_id: uuid::Uuid,
    pub issuer_certificate: DeviceCertificateV1,
    pub statement: DeviceRevocationStatementV1,
    pub transition: RevocationTransitionV1,
    pub signature: Ed25519SignatureBytes,
}

impl DeviceRevocationIntent {
    fn validate(&self) -> Result<(), VaultError> {
        HostedRestoreIntent {
            project_url: self.project_url.clone(),
            user_id: self.user_id,
            session_id: self.session_id,
        }
        .validate()?;
        self.statement
            .verify(&self.issuer_certificate, self.signature)
            .map_err(|_| VaultError::OperationConflict)?;
        if self
            .transition
            .digest()
            .map_err(|_| VaultError::OperationConflict)?
            != self.statement.transition_sha256
        {
            return Err(VaultError::OperationConflict);
        }
        Ok(())
    }
}

fn certificate_bytes(certificate: &DeviceCertificateV1) -> Result<Vec<u8>, VaultError> {
    let mut encoder = Encoder::new(Vec::new());
    encode_certificate_v1(&mut encoder, certificate).map_err(|_| VaultError::OperationConflict)?;
    Ok(encoder.into_writer())
}

fn load(
    connection: &Connection,
    id: OperationId,
) -> Result<Option<DeviceRevocationIntent>, VaultError> {
    // CASE bounds protect the allocation even if a damaged database bypassed
    // its CHECK constraints. A NULL result fails the required typed row read.
    let mut query = connection.prepare(
        "SELECT CASE WHEN typeof(project_url)='text' AND length(CAST(project_url AS BLOB)) BETWEEN 1 AND 2048 THEN project_url END,
                CASE WHEN typeof(user_id)='text' AND length(CAST(user_id AS BLOB)) =36 THEN user_id END,
                CASE WHEN typeof(session_id)='text' AND length(CAST(session_id AS BLOB)) =36 THEN session_id END,
                CASE WHEN length(issuer_certificate) BETWEEN 1 AND 512 THEN issuer_certificate END,
                CASE WHEN length(statement)=197 THEN statement END,
                CASE WHEN length(transition) BETWEEN 1 AND 8388608 THEN transition END,
                CASE WHEN length(signature)=64 THEN signature END
         FROM device_revocation_intents WHERE operation_id=?1",
    )?;
    let mut rows = query.query([id.to_string()])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    let user_id: String = row.get(1)?;
    let session_id: String = row.get(2)?;
    let cert: Vec<u8> = row.get(3)?;
    let statement: Vec<u8> = row.get(4)?;
    let transition: Vec<u8> = row.get(5)?;
    let signature: Vec<u8> = row.get(6)?;
    let mut decoder = Decoder::new(&cert);
    let issuer_certificate =
        decode_certificate_v1(&mut decoder).map_err(|_| VaultError::OperationConflict)?;
    if decoder.position() != cert.len() || certificate_bytes(&issuer_certificate)? != cert {
        return Err(VaultError::OperationConflict);
    }
    let intent = DeviceRevocationIntent {
        project_url: row.get(0)?,
        user_id: user_id.parse().map_err(|_| VaultError::OperationConflict)?,
        session_id: session_id
            .parse()
            .map_err(|_| VaultError::OperationConflict)?,
        issuer_certificate,
        statement: DeviceRevocationStatementV1::from_signing_preimage(&statement)
            .map_err(|_| VaultError::OperationConflict)?,
        transition: RevocationTransitionV1::from_canonical_bytes(&transition)
            .map_err(|_| VaultError::OperationConflict)?,
        signature: Ed25519SignatureBytes(
            signature
                .try_into()
                .map_err(|_| VaultError::OperationConflict)?,
        ),
    };
    intent.validate()?;
    if intent.statement.revocation_id != id {
        return Err(VaultError::OperationConflict);
    }
    Ok(Some(intent))
}

impl Vault {
    /// Page only IDs so listing cannot allocate fifty maximum-size manifests.
    /// Hydrate and reauthorize each intent separately before any network action.
    pub fn device_revocation_intent_ids(
        &self,
        after: Option<OperationId>,
    ) -> Result<Vec<OperationId>, VaultError> {
        let mut query = self.connection.prepare(
            "SELECT CASE WHEN typeof(operation_id)='text' AND length(CAST(operation_id AS BLOB))=36
                THEN operation_id END FROM device_revocation_intents WHERE operation_id > ?1
             ORDER BY operation_id LIMIT 50",
        )?;
        let rows = query.query_map(
            [after.map(|id| id.to_string()).unwrap_or_default()],
            |row| row.get::<_, String>(0),
        )?;
        rows.map(|row| {
            let text = row?;
            let id: OperationId = text.parse().map_err(|_| VaultError::OperationConflict)?;
            if id.to_string() != text {
                return Err(VaultError::OperationConflict);
            }
            Ok(id)
        })
        .collect()
    }

    /// Checks canonical bytes/signature integrity, not current certificate-chain
    /// authority or hosted completion. The original issuer may since be revoked.
    pub fn device_revocation_intent(
        &self,
        id: OperationId,
    ) -> Result<Option<DeviceRevocationIntent>, VaultError> {
        load(&self.connection, id)
    }

    /// Persist before the first hosted mutation. Identical retries preserve the
    /// original identity, keys and ciphertexts; changed operation payloads conflict.
    pub fn store_device_revocation_intent(
        &mut self,
        intent: &DeviceRevocationIntent,
        current: &RevocationControlState<'_>,
    ) -> Result<(), VaultError> {
        intent.validate()?;
        let transaction = self.connection.transaction()?;
        if let Some(existing) = load(&transaction, intent.statement.revocation_id)? {
            if existing != *intent {
                return Err(VaultError::OperationConflict);
            }
        } else {
            if current
                .active_devices
                .get(&intent.statement.issuer_device_id)
                != Some(&intent.issuer_certificate)
            {
                return Err(VaultError::OperationConflict);
            }
            intent
                .transition
                .verify(&intent.statement, intent.signature, current)
                .map_err(|_| VaultError::OperationConflict)?;
            transaction.execute(
                "INSERT INTO device_revocation_intents(operation_id,project_url,user_id,session_id,
                    issuer_certificate,statement,transition,signature) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![intent.statement.revocation_id.to_string(), intent.project_url,
                    intent.user_id.to_string(), intent.session_id.to_string(), certificate_bytes(&intent.issuer_certificate)?,
                    intent.statement.signing_preimage().map_err(|_| VaultError::OperationConflict)?,
                    intent.transition.canonical_bytes().map_err(|_| VaultError::OperationConflict)?, &intent.signature.0[..]],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }
}

/// Exact signed public history. Reading proves canonical integrity, not authority:
/// verify each entry against the preceding authenticated state before use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredRevocationControl {
    pub statement: DeviceRevocationStatementV1,
    pub transition: RevocationTransitionV1,
    pub signature: Ed25519SignatureBytes,
}

fn load_control(
    connection: &Connection,
    scope: crate::sync::SyncScope,
    epoch: u32,
) -> Result<Option<StoredRevocationControl>, VaultError> {
    let mut query = connection.prepare(
        "SELECT CASE WHEN typeof(operation_id)='text' AND length(CAST(operation_id AS BLOB))=36 THEN operation_id END,
                key_epoch,
                CASE WHEN length(statement)=197 THEN statement END,
                CASE WHEN length(transition) BETWEEN 1 AND 8388608 THEN transition END,
                CASE WHEN length(signature)=64 THEN signature END,
                CASE WHEN length(state_sha256)=32 THEN state_sha256 END
         FROM revocation_control_history WHERE account_id=?1 AND workspace_id=?2 AND control_epoch=?3",
    )?;
    let mut rows = query.query(params![
        scope.account_id.to_string(),
        scope.workspace_id.to_string(),
        epoch
    ])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    let operation: String = row.get(0)?;
    let key_epoch: u32 = row.get(1)?;
    let statement: Vec<u8> = row.get(2)?;
    let transition: Vec<u8> = row.get(3)?;
    let signature: Vec<u8> = row.get(4)?;
    let hash: Vec<u8> = row.get(5)?;
    let invalid = || VaultError::OperationConflict;
    let stored = StoredRevocationControl {
        statement: DeviceRevocationStatementV1::from_signing_preimage(&statement)
            .map_err(|_| invalid())?,
        transition: RevocationTransitionV1::from_canonical_bytes(&transition)
            .map_err(|_| invalid())?,
        signature: Ed25519SignatureBytes(signature.try_into().map_err(|_| invalid())?),
    };
    if stored.statement.revocation_id.to_string() != operation
        || stored.statement.account_id != scope.account_id
        || stored.statement.workspace_id != scope.workspace_id
        || stored.statement.control_epoch.checked_add(1) != Some(epoch)
        || stored.statement.key_epoch.checked_add(1) != Some(key_epoch)
        || stored.transition.control_epoch != epoch
        || stored.transition.key_epoch != key_epoch
        || stored.transition.digest().map_err(|_| invalid())? != stored.statement.transition_sha256
        || stored
            .statement
            .control_state_sha256(stored.signature)
            .map_err(|_| invalid())?
            .0
            .as_slice()
            != hash
    {
        return Err(invalid());
    }
    Ok(Some(stored))
}

impl Vault {
    /// Load one bounded entry. Reauthenticate the chain from a trusted anchor;
    /// a stored hash or signature alone is not proof of current authority.
    pub fn device_revocation_control(
        &self,
        scope: crate::sync::SyncScope,
        control_epoch: u32,
    ) -> Result<Option<StoredRevocationControl>, VaultError> {
        load_control(&self.connection, scope, control_epoch)
    }

    /// Append exact signed envelopes before activating rotated keys. The caller
    /// must authenticate the supplied prior state and hosted acceptance separately.
    /// An exact retry only confirms storage; it never advances authority again.
    pub fn commit_device_revocation_control(
        &mut self,
        record: &StoredRevocationControl,
        current: &RevocationControlState<'_>,
    ) -> Result<(), VaultError> {
        let scope = current.scope;
        let epoch = record.transition.control_epoch;
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if let Some(stored) = load_control(&transaction, scope, epoch)? {
            if stored != *record {
                return Err(VaultError::OperationConflict);
            }
            transaction.commit()?;
            return Ok(());
        }
        let advanced = record
            .transition
            .verify_and_advance(&record.statement, record.signature, current)
            .map_err(|_| VaultError::OperationConflict)?;
        let latest: Option<u32> = transaction.query_row(
            "SELECT max(control_epoch) FROM revocation_control_history WHERE account_id=?1 AND workspace_id=?2",
            params![scope.account_id.to_string(),scope.workspace_id.to_string()], |row| row.get(0),
        )?;
        if let Some(latest) = latest {
            let previous =
                load_control(&transaction, scope, latest)?.ok_or(VaultError::OperationConflict)?;
            if latest != current.control_epoch
                || previous.transition.key_epoch != current.key_epoch
                || previous
                    .statement
                    .control_state_sha256(previous.signature)
                    .map_err(|_| VaultError::OperationConflict)?
                    != current.state_sha256
            {
                return Err(VaultError::OperationConflict);
            }
        }
        let state = advanced.state();
        transaction.execute(
            "INSERT INTO revocation_control_history(account_id,workspace_id,control_epoch,key_epoch,operation_id,statement,transition,signature,state_sha256)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![scope.account_id.to_string(),scope.workspace_id.to_string(),state.control_epoch,state.key_epoch,
                record.statement.revocation_id.to_string(),record.statement.signing_preimage().map_err(|_| VaultError::OperationConflict)?,
                record.transition.canonical_bytes().map_err(|_| VaultError::OperationConflict)?,record.signature.0.as_slice(),state.state_sha256.0.as_slice()],
        )?;
        transaction.commit()?;
        Ok(())
    }
}
