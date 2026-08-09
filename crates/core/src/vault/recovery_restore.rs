use std::fmt;

use context_relay_protocol::{
    AccountId, DeviceCertificateId, DeviceId, Ed25519PublicKeyBytes, RecoveryEnrollmentId,
    RecoveryRestoreId, RecoveryRootId, Sha256Digest, WorkspaceId, X25519PublicKeyBytes,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};

use crate::{
    crypto::DeviceKeys,
    devices::{
        pairing::WorkspacePairingMaterial,
        recovery_restore_crypto::{
            RecoveryDeviceClaimArtifacts, RecoveryDeviceClaimV1, decode_recovery_device_claim_v1,
            open_recovered_device_material, verify_recovery_device_claim,
        },
        recovery_restore_transport::{
            RecoveryRestoreProjection, RecoveryRestoreReceipt, RecoveryRootSnapshot,
        },
    },
    sync::SyncScope,
};

use super::{
    CommitDisposition, DeviceCertificateState, DeviceDisplayMetadata,
    RecoveryEnrollmentPersistenceState, StoredDeviceCertificate, Vault, VaultError,
    devices::{
        digest_from_db, ensure_active_certificate_tx, parse_id, parse_platform, timestamp_from_db,
        timestamp_to_db,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryRestorePersistenceState {
    Prepared,
    Active,
    Conflict,
}

impl RecoveryRestorePersistenceState {
    fn parse(value: &str) -> Result<Self, VaultError> {
        match value {
            "prepared" => Ok(Self::Prepared),
            "active" => Ok(Self::Active),
            "conflict" => Ok(Self::Conflict),
            _ => Err(validation()),
        }
    }
}

pub struct RecoveryRestoreWrite {
    pub canonical_record: Vec<u8>,
    pub canonical_record_sha256: Sha256Digest,
    pub canonical_claim: Vec<u8>,
    pub canonical_claim_sha256: Sha256Digest,
    pub prepared_at_ms: u64,
}

impl RecoveryRestoreWrite {
    pub fn new(
        snapshot: RecoveryRootSnapshot,
        artifacts: RecoveryDeviceClaimArtifacts,
        prepared_at_ms: u64,
    ) -> Result<Self, VaultError> {
        let record = snapshot
            .validate_for(snapshot.scope)
            .map_err(|_| validation())?;
        let decoded = decode_recovery_device_claim_v1(&artifacts.canonical_claim)
            .map_err(|_| validation())?;
        if decoded != artifacts.claim
            || sha256(&artifacts.canonical_claim) != artifacts.canonical_claim_sha256
            || artifacts.claim.canonical_record_sha256 != snapshot.canonical_record_sha256
            || artifacts.claim.expected_recovery_generation != snapshot.recovery_generation
        {
            return Err(validation());
        }
        verify_recovery_device_claim(&record, &artifacts.claim).map_err(|_| validation())?;
        Ok(Self {
            canonical_record: snapshot.canonical_record,
            canonical_record_sha256: snapshot.canonical_record_sha256,
            canonical_claim: artifacts.canonical_claim,
            canonical_claim_sha256: artifacts.canonical_claim_sha256,
            prepared_at_ms,
        })
    }
}

impl fmt::Debug for RecoveryRestoreWrite {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryRestoreWrite")
            .field("canonical_record_sha256", &self.canonical_record_sha256)
            .field("canonical_claim_sha256", &self.canonical_claim_sha256)
            .field("prepared_at_ms", &self.prepared_at_ms)
            .field("canonical_ciphertext", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct StoredRecoveryRestore {
    pub record: crate::devices::recovery_crypto::RecoveryEnrollmentRecordV1,
    pub claim: RecoveryDeviceClaimV1,
    pub canonical_record: Vec<u8>,
    pub canonical_record_sha256: Sha256Digest,
    pub canonical_claim: Vec<u8>,
    pub canonical_claim_sha256: Sha256Digest,
    pub state: RecoveryRestorePersistenceState,
    pub activated_genesis_certificate_id: Option<DeviceCertificateId>,
    pub activated_recovered_certificate_id: Option<DeviceCertificateId>,
    pub expected_generation: u64,
    pub accepted_generation: Option<u64>,
    pub prepared_at_ms: u64,
    pub provider_accepted_at_ms: Option<u64>,
    pub completed_at_ms: Option<u64>,
    pub conflict_at_ms: Option<u64>,
}

impl fmt::Debug for StoredRecoveryRestore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredRecoveryRestore")
            .field("restore_id", &self.claim.restore_id)
            .field("enrollment_id", &self.record.enrollment_id)
            .field("recovery_root_id", &self.record.recovery_root_id)
            .field("state", &self.state)
            .field("canonical_record_sha256", &self.canonical_record_sha256)
            .field("canonical_claim_sha256", &self.canonical_claim_sha256)
            .field("expected_generation", &self.expected_generation)
            .field("accepted_generation", &self.accepted_generation)
            .field("prepared_at_ms", &self.prepared_at_ms)
            .field("provider_accepted_at_ms", &self.provider_accepted_at_ms)
            .field("completed_at_ms", &self.completed_at_ms)
            .field("conflict_at_ms", &self.conflict_at_ms)
            .field("canonical_ciphertext", &"[REDACTED]")
            .finish()
    }
}

struct ValidatedWrite {
    record: crate::devices::recovery_crypto::RecoveryEnrollmentRecordV1,
    claim: RecoveryDeviceClaimV1,
}

struct RawRecoveryRestore {
    restore_id: String,
    enrollment_id: String,
    recovery_root_id: String,
    account_id: String,
    workspace_id: String,
    genesis_device_id: String,
    genesis_certificate_id: String,
    recovered_device_id: String,
    recovered_certificate_id: String,
    activated_genesis_certificate_id: Option<String>,
    activated_recovered_certificate_id: Option<String>,
    recovery_signing_public_key: Vec<u8>,
    recovery_wrapping_public_key: Vec<u8>,
    genesis_signing_public_key: Vec<u8>,
    genesis_wrapping_public_key: Vec<u8>,
    recovered_signing_public_key: Vec<u8>,
    recovered_wrapping_public_key: Vec<u8>,
    genesis_device_name: String,
    genesis_platform: String,
    recovered_device_name: String,
    recovered_platform: String,
    control_epoch: i64,
    key_epoch: i64,
    expected_generation: i64,
    accepted_generation: Option<i64>,
    canonical_record: Vec<u8>,
    canonical_record_sha256: Vec<u8>,
    canonical_claim: Vec<u8>,
    canonical_claim_sha256: Vec<u8>,
    state: String,
    prepared_at_ms: i64,
    provider_accepted_at_ms: Option<i64>,
    completed_at_ms: Option<i64>,
    conflict_at_ms: Option<i64>,
}

impl Vault {
    pub fn prepare_recovery_restore(
        &mut self,
        write: &RecoveryRestoreWrite,
    ) -> Result<CommitDisposition, VaultError> {
        let candidate = validate_write(write)?;
        let transaction = self.connection.transaction()?;
        if let Some(existing) = load_recovery_restore(&transaction)? {
            if exact_prepared_write(&existing, write) {
                ensure_restore_certificates_absent_tx(&transaction, &existing)?;
                transaction.commit()?;
                return Ok(CommitDisposition::ExactReplay);
            }
            transaction.rollback()?;
            return Err(VaultError::OperationConflict);
        }
        require_pristine_vault(&transaction)?;
        let record = &candidate.record;
        let claim = &candidate.claim;
        transaction.execute(
            "INSERT INTO recovery_restores(
                restore_id, enrollment_id, recovery_root_id, account_id, workspace_id,
                genesis_device_id, genesis_certificate_id, recovered_device_id,
                recovered_certificate_id, recovery_signing_public_key,
                recovery_wrapping_public_key, genesis_signing_public_key,
                genesis_wrapping_public_key, recovered_signing_public_key,
                recovered_wrapping_public_key, genesis_device_name, genesis_platform,
                recovered_device_name, recovered_platform, control_epoch, key_epoch,
                expected_generation, canonical_record, canonical_record_sha256,
                canonical_claim, canonical_claim_sha256, state, prepared_at_ms
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26,
                'prepared', ?27
             )",
            params![
                claim.restore_id.to_string(),
                record.enrollment_id.to_string(),
                record.recovery_root_id.to_string(),
                record.account_id.to_string(),
                record.workspace_id.to_string(),
                record.genesis_certificate.device_id.to_string(),
                record.genesis_certificate_id.to_string(),
                claim.certificate.device_id.to_string(),
                claim.certificate_id.to_string(),
                record.recovery_signing_public_key.0.as_slice(),
                record.recovery_wrapping_public_key.0.as_slice(),
                record.genesis_certificate.signing_public_key.0.as_slice(),
                record.genesis_certificate.wrapping_public_key.0.as_slice(),
                claim.certificate.signing_public_key.0.as_slice(),
                claim.certificate.wrapping_public_key.0.as_slice(),
                record.device_name,
                display_record(record).platform_value(),
                claim.device_name,
                display_claim(claim).platform_value(),
                i64::from(claim.certificate.control_epoch),
                i64::from(claim.key_epoch),
                generation_to_db(claim.expected_recovery_generation)?,
                write.canonical_record,
                write.canonical_record_sha256.0.as_slice(),
                write.canonical_claim,
                write.canonical_claim_sha256.0.as_slice(),
                timestamp_to_db(write.prepared_at_ms)?,
            ],
        )?;
        transaction.commit()?;
        Ok(CommitDisposition::Inserted)
    }

    pub fn recovery_restore(&self) -> Result<Option<StoredRecoveryRestore>, VaultError> {
        let stored = load_recovery_restore(&self.connection)?;
        if let Some(value) = &stored {
            validate_certificate_graph(self, value)?;
        }
        Ok(stored)
    }

    pub fn mark_recovery_restore_conflict(
        &mut self,
        conflict_at_ms: u64,
    ) -> Result<CommitDisposition, VaultError> {
        let transaction = self.connection.transaction()?;
        let stored = load_recovery_restore(&transaction)?.ok_or_else(validation)?;
        ensure_restore_certificates_absent_tx(&transaction, &stored)?;
        if conflict_at_ms < stored.prepared_at_ms {
            transaction.rollback()?;
            return Err(validation());
        }
        match stored.state {
            RecoveryRestorePersistenceState::Prepared => {
                let changed = transaction.execute(
                    "UPDATE recovery_restores
                     SET state = 'conflict', conflict_at_ms = ?1
                     WHERE restore_id = ?2 AND state = 'prepared'",
                    params![
                        timestamp_to_db(conflict_at_ms)?,
                        stored.claim.restore_id.to_string()
                    ],
                )?;
                if changed != 1 {
                    transaction.rollback()?;
                    return Err(VaultError::OperationConflict);
                }
                transaction.commit()?;
                Ok(CommitDisposition::Inserted)
            }
            RecoveryRestorePersistenceState::Conflict
                if stored.conflict_at_ms == Some(conflict_at_ms) =>
            {
                transaction.commit()?;
                Ok(CommitDisposition::ExactReplay)
            }
            RecoveryRestorePersistenceState::Conflict | RecoveryRestorePersistenceState::Active => {
                transaction.rollback()?;
                Err(VaultError::OperationConflict)
            }
        }
    }

    pub fn activate_recovery_restore(
        &mut self,
        receipt: &RecoveryRestoreReceipt,
        projection: &RecoveryRestoreProjection,
        device_keys: &DeviceKeys,
        completed_at_ms: u64,
    ) -> Result<CommitDisposition, VaultError> {
        let transaction = self.connection.transaction()?;
        let stored = load_recovery_restore(&transaction)?.ok_or_else(validation)?;
        if projection.canonical_claim != stored.canonical_claim
            || &projection.receipt != receipt
            || receipt.accepted_at_ms < stored.prepared_at_ms
            || completed_at_ms < receipt.accepted_at_ms
        {
            transaction.rollback()?;
            return Err(validation());
        }
        let verified_claim = projection
            .validate_for(scope(&stored.record), &stored.record)
            .map_err(|_| validation())?;
        if verified_claim != stored.claim {
            transaction.rollback()?;
            return Err(validation());
        }
        open_recovered_device_material(&stored.record, &stored.claim, device_keys)
            .map_err(|_| validation())?;

        match stored.state {
            RecoveryRestorePersistenceState::Prepared => {
                ensure_certificate_absent_tx(&transaction, stored.record.genesis_certificate_id)?;
                ensure_certificate_absent_tx(&transaction, stored.claim.certificate_id)?;
                ensure_active_certificate_tx(
                    &transaction,
                    stored.record.genesis_certificate_id,
                    &stored.record.genesis_certificate,
                    &display_record(&stored.record),
                    completed_at_ms,
                    true,
                )?;
                ensure_active_certificate_tx(
                    &transaction,
                    stored.claim.certificate_id,
                    &stored.claim.certificate,
                    &display_claim(&stored.claim),
                    completed_at_ms,
                    true,
                )?;
                let changed = transaction.execute(
                    "UPDATE recovery_restores
                     SET state = 'active', accepted_generation = ?1,
                         activated_genesis_certificate_id = genesis_certificate_id,
                         activated_recovered_certificate_id = recovered_certificate_id,
                         provider_accepted_at_ms = ?2, completed_at_ms = ?3
                     WHERE restore_id = ?4 AND state = 'prepared'",
                    params![
                        generation_to_db(receipt.accepted_generation)?,
                        timestamp_to_db(receipt.accepted_at_ms)?,
                        timestamp_to_db(completed_at_ms)?,
                        stored.claim.restore_id.to_string(),
                    ],
                )?;
                if changed != 1 {
                    transaction.rollback()?;
                    return Err(VaultError::OperationConflict);
                }
                transaction.commit()?;
                Ok(CommitDisposition::Inserted)
            }
            RecoveryRestorePersistenceState::Active
                if stored.accepted_generation == Some(receipt.accepted_generation)
                    && stored.provider_accepted_at_ms == Some(receipt.accepted_at_ms)
                    && stored.completed_at_ms == Some(completed_at_ms)
                    && stored.activated_genesis_certificate_id
                        == Some(stored.record.genesis_certificate_id)
                    && stored.activated_recovered_certificate_id
                        == Some(stored.claim.certificate_id) =>
            {
                ensure_active_certificate_tx(
                    &transaction,
                    stored.record.genesis_certificate_id,
                    &stored.record.genesis_certificate,
                    &display_record(&stored.record),
                    completed_at_ms,
                    false,
                )?;
                ensure_active_certificate_tx(
                    &transaction,
                    stored.claim.certificate_id,
                    &stored.claim.certificate,
                    &display_claim(&stored.claim),
                    completed_at_ms,
                    false,
                )?;
                ensure_certificate_timestamp_tx(
                    &transaction,
                    stored.record.genesis_certificate_id,
                    completed_at_ms,
                )?;
                ensure_certificate_timestamp_tx(
                    &transaction,
                    stored.claim.certificate_id,
                    completed_at_ms,
                )?;
                transaction.commit()?;
                Ok(CommitDisposition::ExactReplay)
            }
            RecoveryRestorePersistenceState::Active | RecoveryRestorePersistenceState::Conflict => {
                transaction.rollback()?;
                Err(VaultError::OperationConflict)
            }
        }
    }

    pub fn recovered_workspace_material(
        &self,
        device_keys: &DeviceKeys,
    ) -> Result<WorkspacePairingMaterial, VaultError> {
        let stored = self.recovery_restore()?.ok_or_else(validation)?;
        if stored.state != RecoveryRestorePersistenceState::Active {
            return Err(validation());
        }
        let material = open_recovered_device_material(&stored.record, &stored.claim, device_keys)
            .map_err(|_| validation())?;
        WorkspacePairingMaterial::new(
            SyncScope {
                account_id: material.account_id(),
                workspace_id: material.workspace_id(),
            },
            material.control_epoch(),
            material.key_epoch(),
            *material.workspace_root_key(),
            *material.active_epoch_key(),
        )
        .map_err(|_| validation())
    }

    pub fn trusted_workspace_material(
        &self,
        device_keys: &DeviceKeys,
    ) -> Result<WorkspacePairingMaterial, VaultError> {
        let enrollment = self.recovery_enrollment()?;
        let restore = self.recovery_restore()?;
        match (enrollment, restore) {
            (Some(enrollment), None)
                if enrollment.state == RecoveryEnrollmentPersistenceState::Active =>
            {
                self.enrolled_workspace_material(device_keys)
            }
            (None, Some(restore)) if restore.state == RecoveryRestorePersistenceState::Active => {
                self.recovered_workspace_material(device_keys)
            }
            _ => Err(validation()),
        }
    }
}

fn validate_write(write: &RecoveryRestoreWrite) -> Result<ValidatedWrite, VaultError> {
    if sha256(&write.canonical_record) != write.canonical_record_sha256
        || sha256(&write.canonical_claim) != write.canonical_claim_sha256
    {
        return Err(validation());
    }
    let record = crate::devices::recovery_crypto::decode_recovery_enrollment_record_v1(
        &write.canonical_record,
    )
    .map_err(|_| validation())?;
    let claim =
        decode_recovery_device_claim_v1(&write.canonical_claim).map_err(|_| validation())?;
    verify_recovery_device_claim(&record, &claim).map_err(|_| validation())?;
    Ok(ValidatedWrite { record, claim })
}

fn exact_prepared_write(stored: &StoredRecoveryRestore, write: &RecoveryRestoreWrite) -> bool {
    stored.state == RecoveryRestorePersistenceState::Prepared
        && stored.canonical_record == write.canonical_record
        && stored.canonical_record_sha256 == write.canonical_record_sha256
        && stored.canonical_claim == write.canonical_claim
        && stored.canonical_claim_sha256 == write.canonical_claim_sha256
        && stored.prepared_at_ms == write.prepared_at_ms
}

fn require_pristine_vault(transaction: &Transaction<'_>) -> Result<(), VaultError> {
    let mut statement = transaction.prepare(
        "SELECT name FROM sqlite_master
         WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
         ORDER BY name",
    )?;
    let tables = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    for table in tables {
        if table == "recovery_restores"
            || table.starts_with("search_documents_")
            || table.starts_with("search_fts_")
        {
            continue;
        }
        if !table
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(validation());
        }
        let count: i64 =
            transaction.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get(0)
            })?;
        if count != 0 {
            return Err(VaultError::OperationConflict);
        }
    }
    Ok(())
}

fn load_recovery_restore(
    connection: &Connection,
) -> Result<Option<StoredRecoveryRestore>, VaultError> {
    let count: i64 = connection.query_row("SELECT count(*) FROM recovery_restores", [], |row| {
        row.get(0)
    })?;
    if count > 1 {
        return Err(validation());
    }
    let raw = connection
        .query_row(
            "SELECT restore_id, enrollment_id, recovery_root_id, account_id, workspace_id,
                    genesis_device_id, genesis_certificate_id, recovered_device_id,
                    recovered_certificate_id, activated_genesis_certificate_id,
                    activated_recovered_certificate_id, recovery_signing_public_key,
                    recovery_wrapping_public_key, genesis_signing_public_key,
                    genesis_wrapping_public_key, recovered_signing_public_key,
                    recovered_wrapping_public_key, genesis_device_name, genesis_platform,
                    recovered_device_name, recovered_platform, control_epoch, key_epoch,
                    expected_generation, accepted_generation, canonical_record,
                    canonical_record_sha256, canonical_claim, canonical_claim_sha256, state,
                    prepared_at_ms, provider_accepted_at_ms, completed_at_ms, conflict_at_ms
             FROM recovery_restores ORDER BY restore_id LIMIT 1",
            [],
            |row| {
                Ok(RawRecoveryRestore {
                    restore_id: row.get(0)?,
                    enrollment_id: row.get(1)?,
                    recovery_root_id: row.get(2)?,
                    account_id: row.get(3)?,
                    workspace_id: row.get(4)?,
                    genesis_device_id: row.get(5)?,
                    genesis_certificate_id: row.get(6)?,
                    recovered_device_id: row.get(7)?,
                    recovered_certificate_id: row.get(8)?,
                    activated_genesis_certificate_id: row.get(9)?,
                    activated_recovered_certificate_id: row.get(10)?,
                    recovery_signing_public_key: row.get(11)?,
                    recovery_wrapping_public_key: row.get(12)?,
                    genesis_signing_public_key: row.get(13)?,
                    genesis_wrapping_public_key: row.get(14)?,
                    recovered_signing_public_key: row.get(15)?,
                    recovered_wrapping_public_key: row.get(16)?,
                    genesis_device_name: row.get(17)?,
                    genesis_platform: row.get(18)?,
                    recovered_device_name: row.get(19)?,
                    recovered_platform: row.get(20)?,
                    control_epoch: row.get(21)?,
                    key_epoch: row.get(22)?,
                    expected_generation: row.get(23)?,
                    accepted_generation: row.get(24)?,
                    canonical_record: row.get(25)?,
                    canonical_record_sha256: row.get(26)?,
                    canonical_claim: row.get(27)?,
                    canonical_claim_sha256: row.get(28)?,
                    state: row.get(29)?,
                    prepared_at_ms: row.get(30)?,
                    provider_accepted_at_ms: row.get(31)?,
                    completed_at_ms: row.get(32)?,
                    conflict_at_ms: row.get(33)?,
                })
            },
        )
        .optional()?;
    raw.map(validate_stored_row).transpose()
}

fn validate_stored_row(raw: RawRecoveryRestore) -> Result<StoredRecoveryRestore, VaultError> {
    let canonical_record_sha256 = digest_from_db(raw.canonical_record_sha256)?;
    let canonical_claim_sha256 = digest_from_db(raw.canonical_claim_sha256)?;
    if sha256(&raw.canonical_record) != canonical_record_sha256
        || sha256(&raw.canonical_claim) != canonical_claim_sha256
    {
        return Err(validation());
    }
    let record = crate::devices::recovery_crypto::decode_recovery_enrollment_record_v1(
        &raw.canonical_record,
    )
    .map_err(|_| validation())?;
    let claim = decode_recovery_device_claim_v1(&raw.canonical_claim).map_err(|_| validation())?;
    verify_recovery_device_claim(&record, &claim).map_err(|_| validation())?;

    let restore_id = parse_id::<RecoveryRestoreId>(&raw.restore_id)?;
    let enrollment_id = parse_id::<RecoveryEnrollmentId>(&raw.enrollment_id)?;
    let recovery_root_id = parse_id::<RecoveryRootId>(&raw.recovery_root_id)?;
    let account_id = parse_id::<AccountId>(&raw.account_id)?;
    let workspace_id = parse_id::<WorkspaceId>(&raw.workspace_id)?;
    let genesis_device_id = parse_id::<DeviceId>(&raw.genesis_device_id)?;
    let genesis_certificate_id = parse_id::<DeviceCertificateId>(&raw.genesis_certificate_id)?;
    let recovered_device_id = parse_id::<DeviceId>(&raw.recovered_device_id)?;
    let recovered_certificate_id = parse_id::<DeviceCertificateId>(&raw.recovered_certificate_id)?;
    let activated_genesis_certificate_id = raw
        .activated_genesis_certificate_id
        .as_deref()
        .map(parse_id::<DeviceCertificateId>)
        .transpose()?;
    let activated_recovered_certificate_id = raw
        .activated_recovered_certificate_id
        .as_deref()
        .map(parse_id::<DeviceCertificateId>)
        .transpose()?;
    let recovery_signing_public_key =
        Ed25519PublicKeyBytes(fixed(raw.recovery_signing_public_key)?);
    let recovery_wrapping_public_key =
        X25519PublicKeyBytes(fixed(raw.recovery_wrapping_public_key)?);
    let genesis_signing_public_key = Ed25519PublicKeyBytes(fixed(raw.genesis_signing_public_key)?);
    let genesis_wrapping_public_key = X25519PublicKeyBytes(fixed(raw.genesis_wrapping_public_key)?);
    let recovered_signing_public_key =
        Ed25519PublicKeyBytes(fixed(raw.recovered_signing_public_key)?);
    let recovered_wrapping_public_key =
        X25519PublicKeyBytes(fixed(raw.recovered_wrapping_public_key)?);
    let genesis_platform = parse_platform(&raw.genesis_platform)?;
    let recovered_platform = parse_platform(&raw.recovered_platform)?;
    let control_epoch = positive_u32(raw.control_epoch)?;
    let key_epoch = positive_u32(raw.key_epoch)?;
    let expected_generation = generation_from_db(raw.expected_generation)?;
    let accepted_generation = raw
        .accepted_generation
        .map(generation_from_db)
        .transpose()?;

    if claim.restore_id != restore_id
        || record.enrollment_id != enrollment_id
        || record.recovery_root_id != recovery_root_id
        || record.account_id != account_id
        || record.workspace_id != workspace_id
        || record.genesis_certificate.device_id != genesis_device_id
        || record.genesis_certificate_id != genesis_certificate_id
        || claim.certificate.device_id != recovered_device_id
        || claim.certificate_id != recovered_certificate_id
        || record.recovery_signing_public_key != recovery_signing_public_key
        || record.recovery_wrapping_public_key != recovery_wrapping_public_key
        || record.genesis_certificate.signing_public_key != genesis_signing_public_key
        || record.genesis_certificate.wrapping_public_key != genesis_wrapping_public_key
        || claim.certificate.signing_public_key != recovered_signing_public_key
        || claim.certificate.wrapping_public_key != recovered_wrapping_public_key
        || record.device_name != raw.genesis_device_name
        || record.device_platform != genesis_platform
        || claim.device_name != raw.recovered_device_name
        || claim.device_platform != recovered_platform
        || claim.certificate.control_epoch != control_epoch
        || claim.key_epoch != key_epoch
        || claim.expected_recovery_generation != expected_generation
    {
        return Err(validation());
    }

    let state = RecoveryRestorePersistenceState::parse(&raw.state)?;
    let prepared_at_ms = timestamp_from_db(raw.prepared_at_ms)?;
    let provider_accepted_at_ms = optional_timestamp(raw.provider_accepted_at_ms)?;
    let completed_at_ms = optional_timestamp(raw.completed_at_ms)?;
    let conflict_at_ms = optional_timestamp(raw.conflict_at_ms)?;
    let state_valid = match state {
        RecoveryRestorePersistenceState::Prepared => {
            activated_genesis_certificate_id.is_none()
                && activated_recovered_certificate_id.is_none()
                && accepted_generation.is_none()
                && provider_accepted_at_ms.is_none()
                && completed_at_ms.is_none()
                && conflict_at_ms.is_none()
        }
        RecoveryRestorePersistenceState::Active => {
            activated_genesis_certificate_id == Some(record.genesis_certificate_id)
                && activated_recovered_certificate_id == Some(claim.certificate_id)
                && accepted_generation == expected_generation.checked_add(1)
                && provider_accepted_at_ms.is_some_and(|value| value >= prepared_at_ms)
                && completed_at_ms
                    .zip(provider_accepted_at_ms)
                    .is_some_and(|(completed, provider)| completed >= provider)
                && conflict_at_ms.is_none()
        }
        RecoveryRestorePersistenceState::Conflict => {
            activated_genesis_certificate_id.is_none()
                && activated_recovered_certificate_id.is_none()
                && accepted_generation.is_none()
                && provider_accepted_at_ms.is_none()
                && completed_at_ms.is_none()
                && conflict_at_ms.is_some_and(|value| value >= prepared_at_ms)
        }
    };
    if !state_valid {
        return Err(validation());
    }
    Ok(StoredRecoveryRestore {
        record,
        claim,
        canonical_record: raw.canonical_record,
        canonical_record_sha256,
        canonical_claim: raw.canonical_claim,
        canonical_claim_sha256,
        state,
        activated_genesis_certificate_id,
        activated_recovered_certificate_id,
        expected_generation,
        accepted_generation,
        prepared_at_ms,
        provider_accepted_at_ms,
        completed_at_ms,
        conflict_at_ms,
    })
}

fn validate_certificate_graph(
    vault: &Vault,
    stored: &StoredRecoveryRestore,
) -> Result<(), VaultError> {
    let genesis = vault.device_certificate(stored.record.genesis_certificate_id)?;
    let recovered = vault.device_certificate(stored.claim.certificate_id)?;
    match stored.state {
        RecoveryRestorePersistenceState::Prepared | RecoveryRestorePersistenceState::Conflict => {
            if genesis.is_some() || recovered.is_some() {
                return Err(validation());
            }
        }
        RecoveryRestorePersistenceState::Active => {
            let completed_at_ms = stored.completed_at_ms.ok_or_else(validation)?;
            validate_exact_certificate(
                genesis.ok_or_else(validation)?,
                stored.record.genesis_certificate_id,
                &stored.record.genesis_certificate,
                &display_record(&stored.record),
                completed_at_ms,
            )?;
            validate_exact_certificate(
                recovered.ok_or_else(validation)?,
                stored.claim.certificate_id,
                &stored.claim.certificate,
                &display_claim(&stored.claim),
                completed_at_ms,
            )?;
        }
    }
    Ok(())
}

fn validate_exact_certificate(
    stored: StoredDeviceCertificate,
    expected_id: DeviceCertificateId,
    expected: &crate::crypto::DeviceCertificateV1,
    display: &DeviceDisplayMetadata,
    stored_at_ms: u64,
) -> Result<(), VaultError> {
    if stored.certificate_id != expected_id
        || &stored.certificate != expected
        || stored.state != DeviceCertificateState::Active
        || &stored.display != display
        || stored.stored_at_ms != stored_at_ms
    {
        return Err(validation());
    }
    Ok(())
}

fn ensure_certificate_absent_tx(
    transaction: &Transaction<'_>,
    certificate_id: DeviceCertificateId,
) -> Result<(), VaultError> {
    let exists: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM device_certificates WHERE certificate_id = ?1)",
        [certificate_id.to_string()],
        |row| row.get(0),
    )?;
    if exists {
        return Err(VaultError::OperationConflict);
    }
    Ok(())
}

fn ensure_restore_certificates_absent_tx(
    transaction: &Transaction<'_>,
    stored: &StoredRecoveryRestore,
) -> Result<(), VaultError> {
    ensure_certificate_absent_tx(transaction, stored.record.genesis_certificate_id)?;
    ensure_certificate_absent_tx(transaction, stored.claim.certificate_id)
}

fn ensure_certificate_timestamp_tx(
    transaction: &Transaction<'_>,
    certificate_id: DeviceCertificateId,
    expected: u64,
) -> Result<(), VaultError> {
    let stored_at: i64 = transaction
        .query_row(
            "SELECT stored_at_ms FROM device_certificates WHERE certificate_id = ?1",
            [certificate_id.to_string()],
            |row| row.get(0),
        )
        .optional()?
        .ok_or_else(validation)?;
    if timestamp_from_db(stored_at)? != expected {
        return Err(VaultError::OperationConflict);
    }
    Ok(())
}

fn display_record(
    record: &crate::devices::recovery_crypto::RecoveryEnrollmentRecordV1,
) -> DeviceDisplayMetadata {
    DeviceDisplayMetadata {
        device_name: record.device_name.clone(),
        platform: record.device_platform,
    }
}

fn display_claim(claim: &RecoveryDeviceClaimV1) -> DeviceDisplayMetadata {
    DeviceDisplayMetadata {
        device_name: claim.device_name.clone(),
        platform: claim.device_platform,
    }
}

const fn scope(record: &crate::devices::recovery_crypto::RecoveryEnrollmentRecordV1) -> SyncScope {
    SyncScope {
        account_id: record.account_id,
        workspace_id: record.workspace_id,
    }
}

fn positive_u32(value: i64) -> Result<u32, VaultError> {
    u32::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(validation)
}

fn generation_to_db(value: u64) -> Result<i64, VaultError> {
    i64::try_from(value).map_err(|_| validation())
}

fn generation_from_db(value: i64) -> Result<u64, VaultError> {
    u64::try_from(value).map_err(|_| validation())
}

fn optional_timestamp(value: Option<i64>) -> Result<Option<u64>, VaultError> {
    value.map(timestamp_from_db).transpose()
}

fn fixed<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], VaultError> {
    bytes.try_into().map_err(|_| validation())
}

fn sha256(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest(Sha256::digest(bytes).into())
}

fn validation() -> VaultError {
    VaultError::Validation("invalid stored recovery restore".to_owned())
}
