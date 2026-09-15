use context_relay_protocol::{PairingId, Sha256Digest, decode_pairing_request_v1};
use rusqlite::{OptionalExtension, params};

use super::{Vault, VaultError};
use crate::{
    devices::{crypto::verify_pairing_request, transport::StoredPairingRequest},
    sync::SyncScope,
};

fn validate(review: &StoredPairingRequest) -> Result<(), VaultError> {
    if review.canonical_bytes.len() > 8192 || review.requested_at_ms > i64::MAX as u64 {
        return Err(VaultError::OperationConflict);
    }
    let request = decode_pairing_request_v1(&review.canonical_bytes)
        .map_err(|_| VaultError::OperationConflict)?;
    let signed = verify_pairing_request(&request).map_err(|_| VaultError::OperationConflict)?;
    if request.pairing_id != review.pairing_id
        || signed.digest() != review.request_digest
        || signed.canonical_bytes() != review.canonical_bytes
    {
        return Err(VaultError::OperationConflict);
    }
    Ok(())
}

fn load(
    connection: &rusqlite::Connection,
    id: PairingId,
) -> Result<Option<StoredPairingRequest>, VaultError> {
    let row = connection
        .query_row(
            "SELECT account_id,workspace_id,canonical_request,request_digest,requested_at_ms
         FROM pairing_request_reviews WHERE pairing_id=?1",
            [id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?;
    row.map(|(account, workspace, canonical_bytes, digest, timestamp)| {
        let review = StoredPairingRequest {
            pairing_id: id,
            scope: SyncScope {
                account_id: account.parse().map_err(|_| VaultError::OperationConflict)?,
                workspace_id: workspace
                    .parse()
                    .map_err(|_| VaultError::OperationConflict)?,
            },
            canonical_bytes,
            request_digest: Sha256Digest(
                digest
                    .try_into()
                    .map_err(|_| VaultError::OperationConflict)?,
            ),
            requested_at_ms: timestamp
                .try_into()
                .map_err(|_| VaultError::OperationConflict)?,
        };
        validate(&review)?;
        Ok(review)
    })
    .transpose()
}

impl Vault {
    /// Public signed request metadata; contains no approval payload or safety number.
    pub fn pairing_request_review(
        &self,
        id: PairingId,
    ) -> Result<Option<StoredPairingRequest>, VaultError> {
        load(&self.connection, id)
    }

    /// Preserve the original provider timestamp and scope before preparing a decision.
    pub fn store_pairing_request_review(
        &mut self,
        review: &StoredPairingRequest,
    ) -> Result<(), VaultError> {
        validate(review)?;
        let transaction = self.connection.transaction()?;
        if let Some(existing) = load(&transaction, review.pairing_id)? {
            if existing != *review {
                return Err(VaultError::OperationConflict);
            }
        } else {
            transaction.execute(
                "INSERT INTO pairing_request_reviews VALUES(?1,?2,?3,?4,?5,?6)",
                params![
                    review.pairing_id.to_string(),
                    review.scope.account_id.to_string(),
                    review.scope.workspace_id.to_string(),
                    review.canonical_bytes,
                    review.request_digest.0.as_slice(),
                    review.requested_at_ms as i64
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }
}
