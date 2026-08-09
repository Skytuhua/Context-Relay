use std::fmt;

use context_relay_protocol::{
    AccountId, DeviceCertificateId, DeviceId, Ed25519PublicKeyBytes, RecoveryEnrollmentId,
    RecoveryRootId, Sha256Digest, WorkspaceId, X25519PublicKeyBytes,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};

use crate::{
    crypto::{DeviceKeys, WrappedKeyEnvelope},
    devices::{
        pairing::WorkspacePairingMaterial,
        recovery_crypto::{
            RecoveryEnrollmentRecordV1, decode_recovery_device_envelope_v1,
            decode_recovery_enrollment_record_v1, encode_recovery_device_envelope_v1,
            open_device_workspace_material,
        },
        recovery_transport::RecoveryEnrollmentReceipt,
    },
    sync::SyncScope,
};

use super::{
    CommitDisposition, DeviceCertificateState, DeviceDisplayMetadata, StoredDeviceCertificate,
    Vault, VaultError,
    devices::{
        digest_from_db, ensure_active_certificate_tx, parse_id, parse_platform, timestamp_from_db,
        timestamp_to_db,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryEnrollmentPersistenceState {
    Prepared,
    Active,
    Conflict,
}

impl RecoveryEnrollmentPersistenceState {
    fn parse(value: &str) -> Result<Self, VaultError> {
        match value {
            "prepared" => Ok(Self::Prepared),
            "active" => Ok(Self::Active),
            "conflict" => Ok(Self::Conflict),
            _ => Err(validation()),
        }
    }
}

pub struct RecoveryEnrollmentWrite {
    pub canonical_record: Vec<u8>,
    pub canonical_record_sha256: Sha256Digest,
    pub device_material_envelope: WrappedKeyEnvelope,
    pub device_material_envelope_sha256: Sha256Digest,
    pub prepared_at_ms: u64,
}

impl fmt::Debug for RecoveryEnrollmentWrite {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryEnrollmentWrite")
            .field("canonical_record_sha256", &self.canonical_record_sha256)
            .field("prepared_at_ms", &self.prepared_at_ms)
            .field("sealed_material", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct StoredRecoveryEnrollment {
    pub record: RecoveryEnrollmentRecordV1,
    pub canonical_record: Vec<u8>,
    pub canonical_record_sha256: Sha256Digest,
    pub device_material_envelope: WrappedKeyEnvelope,
    pub device_material_envelope_sha256: Sha256Digest,
    pub state: RecoveryEnrollmentPersistenceState,
    pub activated_certificate_id: Option<DeviceCertificateId>,
    pub prepared_at_ms: u64,
    pub provider_accepted_at_ms: Option<u64>,
    pub completed_at_ms: Option<u64>,
    pub conflict_at_ms: Option<u64>,
}

impl fmt::Debug for StoredRecoveryEnrollment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredRecoveryEnrollment")
            .field("enrollment_id", &self.record.enrollment_id)
            .field("recovery_root_id", &self.record.recovery_root_id)
            .field("state", &self.state)
            .field("canonical_record_sha256", &self.canonical_record_sha256)
            .field("prepared_at_ms", &self.prepared_at_ms)
            .field("provider_accepted_at_ms", &self.provider_accepted_at_ms)
            .field("completed_at_ms", &self.completed_at_ms)
            .field("conflict_at_ms", &self.conflict_at_ms)
            .field("sealed_material", &"[REDACTED]")
            .finish()
    }
}

struct RawRecoveryEnrollment {
    enrollment_id: String,
    recovery_root_id: String,
    account_id: String,
    workspace_id: String,
    device_id: String,
    genesis_certificate_id: String,
    activated_certificate_id: Option<String>,
    recovery_signing_public_key: Vec<u8>,
    recovery_wrapping_public_key: Vec<u8>,
    device_signing_public_key: Vec<u8>,
    device_wrapping_public_key: Vec<u8>,
    device_name: String,
    platform: String,
    control_epoch: i64,
    key_epoch: i64,
    canonical_record: Vec<u8>,
    canonical_record_sha256: Vec<u8>,
    device_material_envelope: Vec<u8>,
    device_envelope_sha256: Vec<u8>,
    state: String,
    prepared_at_ms: i64,
    provider_accepted_at_ms: Option<i64>,
    completed_at_ms: Option<i64>,
    conflict_at_ms: Option<i64>,
}

impl Vault {
    pub fn prepare_recovery_enrollment(
        &mut self,
        write: &RecoveryEnrollmentWrite,
    ) -> Result<CommitDisposition, VaultError> {
        let candidate = validate_write(write)?;
        let transaction = self.connection.transaction()?;
        if let Some(existing) = load_recovery_enrollment(&transaction)? {
            let exact = exact_prepared_write(&existing, write)?;
            if exact {
                transaction.commit()?;
                return Ok(CommitDisposition::ExactReplay);
            }
            transaction.rollback()?;
            return Err(VaultError::OperationConflict);
        }

        let record = &candidate.record;
        transaction.execute(
            "INSERT INTO recovery_enrollments(
                enrollment_id, recovery_root_id, account_id, workspace_id, device_id,
                genesis_certificate_id, recovery_signing_public_key,
                recovery_wrapping_public_key, device_signing_public_key,
                device_wrapping_public_key, device_name, platform, control_epoch, key_epoch,
                canonical_record, canonical_record_sha256, device_material_envelope,
                device_envelope_sha256, state, prepared_at_ms
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                ?15, ?16, ?17, ?18, 'prepared', ?19
             )",
            params![
                record.enrollment_id.to_string(),
                record.recovery_root_id.to_string(),
                record.account_id.to_string(),
                record.workspace_id.to_string(),
                record.genesis_certificate.device_id.to_string(),
                record.genesis_certificate_id.to_string(),
                record.recovery_signing_public_key.0.as_slice(),
                record.recovery_wrapping_public_key.0.as_slice(),
                record.genesis_certificate.signing_public_key.0.as_slice(),
                record.genesis_certificate.wrapping_public_key.0.as_slice(),
                record.device_name,
                display(record).platform_value(),
                i64::from(record.genesis_certificate.control_epoch),
                i64::from(record.key_epoch),
                write.canonical_record,
                write.canonical_record_sha256.0.as_slice(),
                candidate.envelope_bytes,
                write.device_material_envelope_sha256.0.as_slice(),
                timestamp_to_db(write.prepared_at_ms)?,
            ],
        )?;
        transaction.commit()?;
        Ok(CommitDisposition::Inserted)
    }

    pub fn recovery_enrollment(&self) -> Result<Option<StoredRecoveryEnrollment>, VaultError> {
        let stored = load_recovery_enrollment(&self.connection)?;
        if let Some(value) = &stored
            && value.state == RecoveryEnrollmentPersistenceState::Active
        {
            validate_active_certificate(self, value)?;
        }
        Ok(stored)
    }

    pub fn mark_recovery_enrollment_conflict(
        &mut self,
        conflict_at_ms: u64,
    ) -> Result<CommitDisposition, VaultError> {
        let transaction = self.connection.transaction()?;
        let stored = load_recovery_enrollment(&transaction)?.ok_or_else(validation)?;
        if conflict_at_ms < stored.prepared_at_ms {
            transaction.rollback()?;
            return Err(validation());
        }
        match stored.state {
            RecoveryEnrollmentPersistenceState::Prepared => {
                transaction.execute(
                    "UPDATE recovery_enrollments
                     SET state = 'conflict', conflict_at_ms = ?1
                     WHERE enrollment_id = ?2 AND state = 'prepared'",
                    params![
                        timestamp_to_db(conflict_at_ms)?,
                        stored.record.enrollment_id.to_string()
                    ],
                )?;
                transaction.commit()?;
                Ok(CommitDisposition::Inserted)
            }
            RecoveryEnrollmentPersistenceState::Conflict
                if stored.conflict_at_ms == Some(conflict_at_ms) =>
            {
                transaction.commit()?;
                Ok(CommitDisposition::ExactReplay)
            }
            RecoveryEnrollmentPersistenceState::Conflict
            | RecoveryEnrollmentPersistenceState::Active => {
                transaction.rollback()?;
                Err(VaultError::OperationConflict)
            }
        }
    }

    pub fn activate_recovery_enrollment(
        &mut self,
        receipt: &RecoveryEnrollmentReceipt,
        device_keys: &DeviceKeys,
        completed_at_ms: u64,
    ) -> Result<CommitDisposition, VaultError> {
        let transaction = self.connection.transaction()?;
        let stored = load_recovery_enrollment(&transaction)?.ok_or_else(validation)?;
        receipt
            .validate_for(
                scope(&stored.record),
                &stored.record,
                stored.canonical_record_sha256,
                receipt.registered_at_ms,
            )
            .map_err(|_| validation())?;
        if receipt.registered_at_ms < stored.prepared_at_ms
            || completed_at_ms < receipt.registered_at_ms
        {
            transaction.rollback()?;
            return Err(validation());
        }
        open_device_workspace_material(
            &stored.record,
            &stored.device_material_envelope,
            stored.record.genesis_certificate.device_id,
            device_keys,
        )
        .map_err(|_| validation())?;

        match stored.state {
            RecoveryEnrollmentPersistenceState::Prepared => {
                ensure_active_certificate_tx(
                    &transaction,
                    stored.record.genesis_certificate_id,
                    &stored.record.genesis_certificate,
                    &display(&stored.record),
                    completed_at_ms,
                    true,
                )?;
                ensure_recovery_certificate_timestamp_tx(
                    &transaction,
                    stored.record.genesis_certificate_id,
                    completed_at_ms,
                )?;
                let changed = transaction.execute(
                    "UPDATE recovery_enrollments
                     SET state = 'active', activated_certificate_id = genesis_certificate_id,
                         provider_accepted_at_ms = ?1, completed_at_ms = ?2
                     WHERE enrollment_id = ?3 AND state = 'prepared'",
                    params![
                        timestamp_to_db(receipt.registered_at_ms)?,
                        timestamp_to_db(completed_at_ms)?,
                        stored.record.enrollment_id.to_string(),
                    ],
                )?;
                if changed != 1 {
                    transaction.rollback()?;
                    return Err(VaultError::OperationConflict);
                }
                transaction.commit()?;
                Ok(CommitDisposition::Inserted)
            }
            RecoveryEnrollmentPersistenceState::Active
                if stored.provider_accepted_at_ms == Some(receipt.registered_at_ms)
                    && stored.completed_at_ms == Some(completed_at_ms)
                    && stored.activated_certificate_id
                        == Some(stored.record.genesis_certificate_id) =>
            {
                ensure_active_certificate_tx(
                    &transaction,
                    stored.record.genesis_certificate_id,
                    &stored.record.genesis_certificate,
                    &display(&stored.record),
                    completed_at_ms,
                    false,
                )?;
                ensure_recovery_certificate_timestamp_tx(
                    &transaction,
                    stored.record.genesis_certificate_id,
                    completed_at_ms,
                )?;
                transaction.commit()?;
                Ok(CommitDisposition::ExactReplay)
            }
            RecoveryEnrollmentPersistenceState::Active
            | RecoveryEnrollmentPersistenceState::Conflict => {
                transaction.rollback()?;
                Err(VaultError::OperationConflict)
            }
        }
    }

    pub fn enrolled_workspace_material(
        &self,
        device_keys: &DeviceKeys,
    ) -> Result<WorkspacePairingMaterial, VaultError> {
        let stored = self.recovery_enrollment()?.ok_or_else(validation)?;
        if stored.state != RecoveryEnrollmentPersistenceState::Active {
            return Err(validation());
        }
        let material = open_device_workspace_material(
            &stored.record,
            &stored.device_material_envelope,
            stored.record.genesis_certificate.device_id,
            device_keys,
        )
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
}

struct ValidatedWrite {
    record: RecoveryEnrollmentRecordV1,
    envelope_bytes: Vec<u8>,
}

fn validate_write(write: &RecoveryEnrollmentWrite) -> Result<ValidatedWrite, VaultError> {
    if sha256(&write.canonical_record) != write.canonical_record_sha256 {
        return Err(validation());
    }
    let record =
        decode_recovery_enrollment_record_v1(&write.canonical_record).map_err(|_| validation())?;
    let envelope_bytes = encode_recovery_device_envelope_v1(&write.device_material_envelope)
        .map_err(|_| validation())?;
    if sha256(&envelope_bytes) != write.device_material_envelope_sha256 {
        return Err(validation());
    }
    Ok(ValidatedWrite {
        record,
        envelope_bytes,
    })
}

fn exact_prepared_write(
    stored: &StoredRecoveryEnrollment,
    write: &RecoveryEnrollmentWrite,
) -> Result<bool, VaultError> {
    let envelope = encode_recovery_device_envelope_v1(&write.device_material_envelope)
        .map_err(|_| validation())?;
    let stored_envelope = encode_recovery_device_envelope_v1(&stored.device_material_envelope)
        .map_err(|_| validation())?;
    Ok(stored.state == RecoveryEnrollmentPersistenceState::Prepared
        && stored.canonical_record == write.canonical_record
        && stored.canonical_record_sha256 == write.canonical_record_sha256
        && stored_envelope == envelope
        && stored.device_material_envelope_sha256 == write.device_material_envelope_sha256
        && stored.prepared_at_ms == write.prepared_at_ms)
}

fn load_recovery_enrollment(
    connection: &Connection,
) -> Result<Option<StoredRecoveryEnrollment>, VaultError> {
    let row_count: i64 =
        connection.query_row("SELECT count(*) FROM recovery_enrollments", [], |row| {
            row.get(0)
        })?;
    if row_count > 1 {
        return Err(validation());
    }
    let raw = connection
        .query_row(
            "SELECT enrollment_id, recovery_root_id, account_id, workspace_id, device_id,
                    genesis_certificate_id, activated_certificate_id,
                    recovery_signing_public_key, recovery_wrapping_public_key,
                    device_signing_public_key, device_wrapping_public_key,
                    device_name, platform, control_epoch, key_epoch,
                    canonical_record, canonical_record_sha256,
                    device_material_envelope, device_envelope_sha256, state,
                    prepared_at_ms, provider_accepted_at_ms, completed_at_ms, conflict_at_ms
             FROM recovery_enrollments ORDER BY enrollment_id LIMIT 1",
            [],
            |row| {
                Ok(RawRecoveryEnrollment {
                    enrollment_id: row.get(0)?,
                    recovery_root_id: row.get(1)?,
                    account_id: row.get(2)?,
                    workspace_id: row.get(3)?,
                    device_id: row.get(4)?,
                    genesis_certificate_id: row.get(5)?,
                    activated_certificate_id: row.get(6)?,
                    recovery_signing_public_key: row.get(7)?,
                    recovery_wrapping_public_key: row.get(8)?,
                    device_signing_public_key: row.get(9)?,
                    device_wrapping_public_key: row.get(10)?,
                    device_name: row.get(11)?,
                    platform: row.get(12)?,
                    control_epoch: row.get(13)?,
                    key_epoch: row.get(14)?,
                    canonical_record: row.get(15)?,
                    canonical_record_sha256: row.get(16)?,
                    device_material_envelope: row.get(17)?,
                    device_envelope_sha256: row.get(18)?,
                    state: row.get(19)?,
                    prepared_at_ms: row.get(20)?,
                    provider_accepted_at_ms: row.get(21)?,
                    completed_at_ms: row.get(22)?,
                    conflict_at_ms: row.get(23)?,
                })
            },
        )
        .optional()?;
    raw.map(validate_stored_row).transpose()
}

fn validate_stored_row(raw: RawRecoveryEnrollment) -> Result<StoredRecoveryEnrollment, VaultError> {
    let canonical_record_sha256 = digest_from_db(raw.canonical_record_sha256)?;
    let device_material_envelope_sha256 = digest_from_db(raw.device_envelope_sha256)?;
    if sha256(&raw.canonical_record) != canonical_record_sha256
        || sha256(&raw.device_material_envelope) != device_material_envelope_sha256
    {
        return Err(validation());
    }
    let record =
        decode_recovery_enrollment_record_v1(&raw.canonical_record).map_err(|_| validation())?;
    let envelope = decode_recovery_device_envelope_v1(&raw.device_material_envelope)
        .map_err(|_| validation())?;
    let enrollment_id = parse_id::<RecoveryEnrollmentId>(&raw.enrollment_id)?;
    let recovery_root_id = parse_id::<RecoveryRootId>(&raw.recovery_root_id)?;
    let account_id = parse_id::<AccountId>(&raw.account_id)?;
    let workspace_id = parse_id::<WorkspaceId>(&raw.workspace_id)?;
    let device_id = parse_id::<DeviceId>(&raw.device_id)?;
    let genesis_certificate_id = parse_id::<DeviceCertificateId>(&raw.genesis_certificate_id)?;
    let activated_certificate_id = raw
        .activated_certificate_id
        .as_deref()
        .map(parse_id::<DeviceCertificateId>)
        .transpose()?;
    let recovery_signing_public_key =
        Ed25519PublicKeyBytes(fixed(raw.recovery_signing_public_key)?);
    let recovery_wrapping_public_key =
        X25519PublicKeyBytes(fixed(raw.recovery_wrapping_public_key)?);
    let device_signing_public_key = Ed25519PublicKeyBytes(fixed(raw.device_signing_public_key)?);
    let device_wrapping_public_key = X25519PublicKeyBytes(fixed(raw.device_wrapping_public_key)?);
    let platform = parse_platform(&raw.platform)?;
    let control_epoch = u32::try_from(raw.control_epoch).map_err(|_| validation())?;
    let key_epoch = u32::try_from(raw.key_epoch).map_err(|_| validation())?;
    if record.enrollment_id != enrollment_id
        || record.recovery_root_id != recovery_root_id
        || record.account_id != account_id
        || record.workspace_id != workspace_id
        || record.genesis_certificate.device_id != device_id
        || record.genesis_certificate_id != genesis_certificate_id
        || record.recovery_signing_public_key != recovery_signing_public_key
        || record.recovery_wrapping_public_key != recovery_wrapping_public_key
        || record.genesis_certificate.signing_public_key != device_signing_public_key
        || record.genesis_certificate.wrapping_public_key != device_wrapping_public_key
        || record.device_name != raw.device_name
        || record.device_platform != platform
        || record.genesis_certificate.control_epoch != control_epoch
        || record.key_epoch != key_epoch
    {
        return Err(validation());
    }
    let state = RecoveryEnrollmentPersistenceState::parse(&raw.state)?;
    let prepared_at_ms = timestamp_from_db(raw.prepared_at_ms)?;
    let provider_accepted_at_ms = optional_timestamp(raw.provider_accepted_at_ms)?;
    let completed_at_ms = optional_timestamp(raw.completed_at_ms)?;
    let conflict_at_ms = optional_timestamp(raw.conflict_at_ms)?;
    let state_valid = match state {
        RecoveryEnrollmentPersistenceState::Prepared => {
            activated_certificate_id.is_none()
                && provider_accepted_at_ms.is_none()
                && completed_at_ms.is_none()
                && conflict_at_ms.is_none()
        }
        RecoveryEnrollmentPersistenceState::Active => {
            activated_certificate_id == Some(record.genesis_certificate_id)
                && provider_accepted_at_ms.is_some_and(|value| value >= prepared_at_ms)
                && completed_at_ms
                    .zip(provider_accepted_at_ms)
                    .is_some_and(|(completed, provider)| completed >= provider)
                && conflict_at_ms.is_none()
        }
        RecoveryEnrollmentPersistenceState::Conflict => {
            activated_certificate_id.is_none()
                && provider_accepted_at_ms.is_none()
                && completed_at_ms.is_none()
                && conflict_at_ms.is_some_and(|value| value >= prepared_at_ms)
        }
    };
    if !state_valid {
        return Err(validation());
    }
    Ok(StoredRecoveryEnrollment {
        record,
        canonical_record: raw.canonical_record,
        canonical_record_sha256,
        device_material_envelope: envelope,
        device_material_envelope_sha256,
        state,
        activated_certificate_id,
        prepared_at_ms,
        provider_accepted_at_ms,
        completed_at_ms,
        conflict_at_ms,
    })
}

fn validate_active_certificate(
    vault: &Vault,
    stored: &StoredRecoveryEnrollment,
) -> Result<StoredDeviceCertificate, VaultError> {
    let certificate_id = stored.activated_certificate_id.ok_or_else(validation)?;
    let certificate = vault
        .device_certificate(certificate_id)?
        .ok_or_else(validation)?;
    if certificate.certificate != stored.record.genesis_certificate
        || certificate.state != DeviceCertificateState::Active
        || certificate.display != display(&stored.record)
        || Some(certificate.stored_at_ms) != stored.completed_at_ms
    {
        return Err(validation());
    }
    Ok(certificate)
}

fn ensure_recovery_certificate_timestamp_tx(
    transaction: &Transaction<'_>,
    certificate_id: DeviceCertificateId,
    expected_stored_at_ms: u64,
) -> Result<(), VaultError> {
    let stored_at_ms = transaction
        .query_row(
            "SELECT stored_at_ms FROM device_certificates WHERE certificate_id = ?1",
            [certificate_id.to_string()],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .ok_or_else(validation)?;
    if timestamp_from_db(stored_at_ms)? != expected_stored_at_ms {
        return Err(VaultError::OperationConflict);
    }
    Ok(())
}

fn display(record: &RecoveryEnrollmentRecordV1) -> DeviceDisplayMetadata {
    DeviceDisplayMetadata {
        device_name: record.device_name.clone(),
        platform: record.device_platform,
    }
}

const fn scope(record: &RecoveryEnrollmentRecordV1) -> SyncScope {
    SyncScope {
        account_id: record.account_id,
        workspace_id: record.workspace_id,
    }
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
    VaultError::Validation("invalid stored recovery enrollment".to_owned())
}
