use std::{
    error::Error,
    fmt,
    num::NonZeroU32,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use context_relay_protocol::{
    DecimalTimestamp, DeviceCertificateId, DeviceId, DeviceState, DeviceSummary, NativePlatform,
    PairingRequestNonce, RECOVERY_ENROLLMENT_SESSION_MS, RecoveryEnrollmentComplete,
    RecoveryEnrollmentConfirmParams, RecoveryEnrollmentId, RecoveryEnrollmentPhrase,
    RecoveryEnrollmentState, RecoveryEnrollmentStatus, RecoveryRootId,
};
use rand_core::{CryptoRng, Error as RandError, OsRng, RngCore};

use crate::{
    crypto::{CertificateFieldsV1, DeviceCertificateV1, DeviceKeys, RecoveryKeys, RecoveryPhrase},
    devices::{
        crypto::PairingKeyBundle,
        recovery_crypto::{
            RecoveryEnrollmentArtifacts, RecoveryEnrollmentBuildRequest,
            build_recovery_enrollment_artifacts_inner,
        },
        recovery_transport::{
            RecoveryEnrollmentReceipt, RecoveryEnrollmentTransport, RecoveryRootStatus,
            RecoveryTransportError,
        },
    },
    sync::SyncScope,
    vault::{
        RecoveryEnrollmentPersistenceState, RecoveryEnrollmentWrite, StoredRecoveryEnrollment,
        Vault, VaultError,
    },
};

pub trait RecoveryEnrollmentClock: Send + Sync {
    fn now_ms(&self) -> u64;
}

pub trait RecoveryEnrollmentEntropy: Send + Sync {
    fn fill_bytes(&self, output: &mut [u8]) -> Result<(), RecoveryEnrollmentCycleError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemRecoveryEnrollmentClock;

impl RecoveryEnrollmentClock for SystemRecoveryEnrollmentClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or_default()
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct OsRecoveryEnrollmentEntropy;

impl RecoveryEnrollmentEntropy for OsRecoveryEnrollmentEntropy {
    fn fill_bytes(&self, output: &mut [u8]) -> Result<(), RecoveryEnrollmentCycleError> {
        OsRng
            .try_fill_bytes(output)
            .map_err(|_| RecoveryEnrollmentCycleError::Transient)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum RecoveryEnrollmentCycleError {
    Invalid,
    Expired,
    Conflict,
    Unauthorized,
    Transient,
}

impl RecoveryEnrollmentCycleError {
    pub const fn safe_code(self) -> &'static str {
        match self {
            Self::Invalid => "recovery_invalid",
            Self::Expired => "recovery_expired",
            Self::Conflict => "recovery_conflict",
            Self::Unauthorized => "recovery_unauthorized",
            Self::Transient => "transient",
        }
    }
}

impl fmt::Debug for RecoveryEnrollmentCycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.safe_code())
    }
}

impl fmt::Display for RecoveryEnrollmentCycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.safe_code())
    }
}

impl Error for RecoveryEnrollmentCycleError {}

#[derive(Debug)]
pub enum RecoveryEnrollmentBeginOutcome {
    Phrase(RecoveryEnrollmentPhrase),
    Status(RecoveryEnrollmentStatus),
}

#[derive(Debug)]
pub enum RecoveryEnrollmentConfirmOutcome {
    Complete(RecoveryEnrollmentComplete),
    Status(RecoveryEnrollmentStatus),
}

struct PendingRecoveryEnrollment {
    phrase: RecoveryPhrase,
    recovery_keys: RecoveryKeys,
    material: PairingKeyBundle,
    artifacts: RecoveryEnrollmentArtifacts,
    confirmation_positions: Vec<u8>,
    created_at_ms: u64,
    expires_at_ms: u64,
}

impl fmt::Debug for PendingRecoveryEnrollment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingRecoveryEnrollment")
            .field("enrollment_id", &self.artifacts.record.enrollment_id)
            .field("created_at_ms", &self.created_at_ms)
            .field("expires_at_ms", &self.expires_at_ms)
            .field("phrase_keys_material_and_record", &"[REDACTED]")
            .finish()
    }
}

pub struct RecoveryEnrollmentCoordinator<C, E, T> {
    clock: C,
    entropy: E,
    transport: T,
    pending: Option<PendingRecoveryEnrollment>,
}

impl<C, T> RecoveryEnrollmentCoordinator<C, OsRecoveryEnrollmentEntropy, T>
where
    C: RecoveryEnrollmentClock,
    T: RecoveryEnrollmentTransport,
{
    pub const fn new(clock: C, transport: T) -> Self {
        Self {
            clock,
            entropy: OsRecoveryEnrollmentEntropy,
            transport,
            pending: None,
        }
    }
}

#[cfg(feature = "test-support")]
impl<C, E, T> RecoveryEnrollmentCoordinator<C, E, T>
where
    C: RecoveryEnrollmentClock,
    E: RecoveryEnrollmentEntropy,
    T: RecoveryEnrollmentTransport,
{
    #[doc(hidden)]
    pub const fn new_for_test(clock: C, entropy: E, transport: T) -> Self {
        Self {
            clock,
            entropy,
            transport,
            pending: None,
        }
    }
}

impl<C, E, T> fmt::Debug for RecoveryEnrollmentCoordinator<C, E, T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryEnrollmentCoordinator([REDACTED])")
    }
}

impl<C, E, T> RecoveryEnrollmentCoordinator<C, E, T>
where
    C: RecoveryEnrollmentClock,
    E: RecoveryEnrollmentEntropy,
    T: RecoveryEnrollmentTransport,
{
    pub fn begin(
        &mut self,
        vault: &mut Vault,
        device_id: DeviceId,
        device_name: impl Into<String>,
        platform: NativePlatform,
        device_keys: &DeviceKeys,
    ) -> Result<RecoveryEnrollmentBeginOutcome, RecoveryEnrollmentCycleError> {
        let now_ms = self.clock.now_ms();
        self.expire_pending(now_ms);
        let status = self.reconcile(vault, device_keys, now_ms)?;
        if status.state != RecoveryEnrollmentState::Idle {
            return Ok(RecoveryEnrollmentBeginOutcome::Status(status));
        }

        let device_name = device_name.into();
        if device_name.trim().is_empty() || device_name.len() > 256 {
            return Err(RecoveryEnrollmentCycleError::Invalid);
        }
        let expires_at_ms = now_ms
            .checked_add(RECOVERY_ENROLLMENT_SESSION_MS)
            .ok_or(RecoveryEnrollmentCycleError::Invalid)?;
        let phrase = RecoveryPhrase::from_entropy(self.entropy_array()?)
            .map_err(|_| RecoveryEnrollmentCycleError::Invalid)?;
        let recovery_keys =
            RecoveryKeys::derive(&phrase).map_err(|_| RecoveryEnrollmentCycleError::Invalid)?;
        let enrollment_id = self.entropy_uuid_v7::<RecoveryEnrollmentId>()?;
        let recovery_root_id = self.entropy_uuid_v7::<RecoveryRootId>()?;
        let certificate_id = self.entropy_uuid_v7::<DeviceCertificateId>()?;
        let request_nonce = PairingRequestNonce(self.entropy_array()?);
        let workspace_root_key = self.entropy_array()?;
        let active_epoch_key = self.entropy_array()?;
        let scope = self.transport.scope();
        let material = PairingKeyBundle::new(scope, 1, 1, workspace_root_key, active_epoch_key)
            .map_err(|_| RecoveryEnrollmentCycleError::Invalid)?;
        let certificate = DeviceCertificateV1::issue_genesis(
            CertificateFieldsV1 {
                account_id: scope.account_id,
                workspace_id: scope.workspace_id,
                control_epoch: 1,
                request_nonce,
                device_id,
                signing_public_key: device_keys.signing_public_key(),
                wrapping_public_key: device_keys.wrapping_public_key(),
            },
            &recovery_keys,
        )
        .map_err(|_| RecoveryEnrollmentCycleError::Invalid)?;
        let mut rng = EntropyRng(&self.entropy);
        let artifacts = build_recovery_enrollment_artifacts_inner(
            RecoveryEnrollmentBuildRequest {
                enrollment_id,
                recovery_root_id,
                certificate_id,
                certificate,
                device_name,
                device_platform: platform,
                recovery_keys: &recovery_keys,
                device_keys,
                material: &material,
            },
            &mut rng,
        )
        .map_err(|_| RecoveryEnrollmentCycleError::Transient)?;
        let confirmation_positions = self.confirmation_positions()?;
        let result = RecoveryEnrollmentPhrase {
            enrollment_id,
            recovery_phrase_words: phrase.to_words(),
            confirmation_positions: confirmation_positions.clone(),
            created_at_ms: DecimalTimestamp(now_ms),
            expires_at_ms: DecimalTimestamp(expires_at_ms),
        };
        self.pending = Some(PendingRecoveryEnrollment {
            phrase,
            recovery_keys,
            material,
            artifacts,
            confirmation_positions,
            created_at_ms: now_ms,
            expires_at_ms,
        });
        Ok(RecoveryEnrollmentBeginOutcome::Phrase(result))
    }

    pub fn overview(
        &mut self,
        vault: &mut Vault,
        device_keys: &DeviceKeys,
    ) -> Result<RecoveryEnrollmentStatus, RecoveryEnrollmentCycleError> {
        let now_ms = self.clock.now_ms();
        self.expire_pending(now_ms);
        self.reconcile(vault, device_keys, now_ms)
    }

    pub fn status(
        &mut self,
        vault: &mut Vault,
        enrollment_id: RecoveryEnrollmentId,
        device_keys: &DeviceKeys,
    ) -> Result<RecoveryEnrollmentStatus, RecoveryEnrollmentCycleError> {
        let now_ms = self.clock.now_ms();
        if self.expire_pending(now_ms) == Some(enrollment_id) {
            return Err(RecoveryEnrollmentCycleError::Expired);
        }
        let local_id = vault
            .recovery_enrollment()
            .map_err(map_vault_error)?
            .map(|stored| stored.record.enrollment_id);
        let pending_id = self
            .pending
            .as_ref()
            .map(|pending| pending.artifacts.record.enrollment_id);
        if pending_id != Some(enrollment_id) && local_id != Some(enrollment_id) {
            return Err(RecoveryEnrollmentCycleError::Invalid);
        }
        let status = self.reconcile(vault, device_keys, now_ms)?;
        if status.enrollment_id != Some(enrollment_id) {
            return Err(RecoveryEnrollmentCycleError::Conflict);
        }
        Ok(status)
    }

    pub fn confirm(
        &mut self,
        vault: &mut Vault,
        params: RecoveryEnrollmentConfirmParams,
        device_keys: &DeviceKeys,
    ) -> Result<RecoveryEnrollmentConfirmOutcome, RecoveryEnrollmentCycleError> {
        let now_ms = self.clock.now_ms();
        if self.expire_pending(now_ms) == Some(params.enrollment_id) {
            return Err(RecoveryEnrollmentCycleError::Expired);
        }
        let pending = self
            .pending
            .take()
            .ok_or(RecoveryEnrollmentCycleError::Invalid)?;
        if params.validate().is_err()
            || params.enrollment_id != pending.artifacts.record.enrollment_id
            || !confirmations_match(&pending, &params)
        {
            return Err(RecoveryEnrollmentCycleError::Invalid);
        }

        let PendingRecoveryEnrollment {
            phrase,
            recovery_keys,
            material,
            artifacts,
            ..
        } = pending;
        let RecoveryEnrollmentArtifacts {
            canonical_record,
            canonical_record_sha256,
            device_material_envelope,
            device_material_envelope_sha256,
            ..
        } = artifacts;
        let write = RecoveryEnrollmentWrite {
            canonical_record,
            canonical_record_sha256,
            device_material_envelope,
            device_material_envelope_sha256,
            prepared_at_ms: now_ms,
        };
        drop(phrase);
        drop(recovery_keys);
        drop(material);
        vault
            .prepare_recovery_enrollment(&write)
            .map_err(map_vault_error)?;
        let stored = vault
            .recovery_enrollment()
            .map_err(map_vault_error)?
            .ok_or(RecoveryEnrollmentCycleError::Conflict)?;
        let receipt = match self.transport.register(&stored.canonical_record, now_ms) {
            Ok(receipt) => receipt,
            Err(RecoveryTransportError::Transient) => {
                return Ok(RecoveryEnrollmentConfirmOutcome::Status(
                    status_from_stored(&stored),
                ));
            }
            Err(RecoveryTransportError::Unauthorized) => {
                return Err(RecoveryEnrollmentCycleError::Unauthorized);
            }
            Err(RecoveryTransportError::Invalid | RecoveryTransportError::Conflict) => {
                vault
                    .mark_recovery_enrollment_conflict(now_ms)
                    .map_err(map_vault_error)?;
                let conflict = vault
                    .recovery_enrollment()
                    .map_err(map_vault_error)?
                    .ok_or(RecoveryEnrollmentCycleError::Conflict)?;
                return Ok(RecoveryEnrollmentConfirmOutcome::Status(
                    status_from_stored(&conflict),
                ));
            }
        };
        match self.activate(vault, &stored, &receipt, device_keys, now_ms) {
            Ok(completion) => Ok(RecoveryEnrollmentConfirmOutcome::Complete(completion)),
            Err(RecoveryEnrollmentCycleError::Conflict) => self
                .mark_conflict(vault, &stored, now_ms)
                .map(RecoveryEnrollmentConfirmOutcome::Status),
            Err(error) => Err(error),
        }
    }

    pub fn cancel(
        &mut self,
        vault: &mut Vault,
        enrollment_id: RecoveryEnrollmentId,
    ) -> Result<RecoveryEnrollmentStatus, RecoveryEnrollmentCycleError> {
        let now_ms = self.clock.now_ms();
        if self.expire_pending(now_ms) == Some(enrollment_id) {
            return Err(RecoveryEnrollmentCycleError::Expired);
        }
        if vault
            .recovery_enrollment()
            .map_err(map_vault_error)?
            .is_some()
        {
            return Err(RecoveryEnrollmentCycleError::Conflict);
        }
        if self
            .pending
            .as_ref()
            .map(|pending| pending.artifacts.record.enrollment_id)
            != Some(enrollment_id)
        {
            return Err(RecoveryEnrollmentCycleError::Invalid);
        }
        self.pending.take();
        Ok(idle_status())
    }

    fn reconcile(
        &mut self,
        vault: &mut Vault,
        device_keys: &DeviceKeys,
        now_ms: u64,
    ) -> Result<RecoveryEnrollmentStatus, RecoveryEnrollmentCycleError> {
        let local = vault.recovery_enrollment().map_err(map_vault_error)?;
        let provider = self.transport.root_status().map_err(map_transport_error)?;
        if let Some(pending) = &self.pending {
            if local.is_none() && provider.is_none() {
                return Ok(awaiting_status(pending));
            }
            let status = conflict_status(
                pending.artifacts.record.enrollment_id,
                pending.created_at_ms,
                now_ms,
            );
            self.pending.take();
            return Ok(status);
        }

        match (local, provider) {
            (None, None) => Ok(idle_status()),
            (None, Some(provider)) => Ok(conflict_status(
                provider.enrollment_id,
                provider.registered_at_ms,
                now_ms,
            )),
            (Some(stored), provider) => match stored.state {
                RecoveryEnrollmentPersistenceState::Conflict => Ok(status_from_stored(&stored)),
                RecoveryEnrollmentPersistenceState::Active => {
                    let Some(provider) = provider else {
                        return Ok(conflict_status(
                            stored.record.enrollment_id,
                            stored.prepared_at_ms,
                            now_ms,
                        ));
                    };
                    if validate_status(&provider, &stored).is_err()
                        || stored.provider_accepted_at_ms != Some(provider.registered_at_ms)
                        || vault.enrolled_workspace_material(device_keys).is_err()
                    {
                        return Ok(conflict_status(
                            stored.record.enrollment_id,
                            stored.prepared_at_ms,
                            now_ms,
                        ));
                    }
                    Ok(status_from_stored(&stored))
                }
                RecoveryEnrollmentPersistenceState::Prepared => {
                    let receipt = match provider {
                        Some(status) => {
                            if validate_status(&status, &stored).is_err() {
                                return self.mark_conflict(vault, &stored, now_ms);
                            }
                            receipt_from_status(status)
                        }
                        None => match self.transport.register(&stored.canonical_record, now_ms) {
                            Ok(receipt) => receipt,
                            Err(RecoveryTransportError::Transient) => {
                                return Ok(status_from_stored(&stored));
                            }
                            Err(RecoveryTransportError::Unauthorized) => {
                                return Err(RecoveryEnrollmentCycleError::Unauthorized);
                            }
                            Err(
                                RecoveryTransportError::Invalid | RecoveryTransportError::Conflict,
                            ) => return self.mark_conflict(vault, &stored, now_ms),
                        },
                    };
                    match self.activate(vault, &stored, &receipt, device_keys, now_ms) {
                        Ok(completion) => Ok(RecoveryEnrollmentStatus {
                            enrollment_id: Some(completion.enrollment_id),
                            state: RecoveryEnrollmentState::Complete,
                            created_at_ms: Some(DecimalTimestamp(stored.prepared_at_ms)),
                            transitioned_at_ms: Some(DecimalTimestamp(now_ms)),
                        }),
                        Err(RecoveryEnrollmentCycleError::Conflict) => {
                            self.mark_conflict(vault, &stored, now_ms)
                        }
                        Err(error) => Err(error),
                    }
                }
            },
        }
    }

    fn activate(
        &self,
        vault: &mut Vault,
        stored: &StoredRecoveryEnrollment,
        receipt: &RecoveryEnrollmentReceipt,
        device_keys: &DeviceKeys,
        completed_at_ms: u64,
    ) -> Result<RecoveryEnrollmentComplete, RecoveryEnrollmentCycleError> {
        match vault.activate_recovery_enrollment(receipt, device_keys, completed_at_ms) {
            Ok(_) => Ok(completion(stored)),
            Err(VaultError::Validation(_) | VaultError::OperationConflict) => {
                Err(RecoveryEnrollmentCycleError::Conflict)
            }
            Err(_) => Err(RecoveryEnrollmentCycleError::Transient),
        }
    }

    fn mark_conflict(
        &self,
        vault: &mut Vault,
        stored: &StoredRecoveryEnrollment,
        now_ms: u64,
    ) -> Result<RecoveryEnrollmentStatus, RecoveryEnrollmentCycleError> {
        vault
            .mark_recovery_enrollment_conflict(now_ms)
            .map_err(map_vault_error)?;
        Ok(conflict_status(
            stored.record.enrollment_id,
            stored.prepared_at_ms,
            now_ms,
        ))
    }

    fn expire_pending(&mut self, now_ms: u64) -> Option<RecoveryEnrollmentId> {
        let expired = self
            .pending
            .as_ref()
            .filter(|pending| now_ms >= pending.expires_at_ms)
            .map(|pending| pending.artifacts.record.enrollment_id);
        if expired.is_some() {
            self.pending.take();
        }
        expired
    }

    fn entropy_array<const N: usize>(&self) -> Result<[u8; N], RecoveryEnrollmentCycleError> {
        let mut output = [0_u8; N];
        self.entropy.fill_bytes(&mut output)?;
        Ok(output)
    }

    fn entropy_uuid_v7<I: FromStr>(&self) -> Result<I, RecoveryEnrollmentCycleError> {
        let mut bytes = self.entropy_array::<16>()?;
        bytes[6] = (bytes[6] & 0x0f) | 0x70;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        let value = format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            bytes[0],
            bytes[1],
            bytes[2],
            bytes[3],
            bytes[4],
            bytes[5],
            bytes[6],
            bytes[7],
            bytes[8],
            bytes[9],
            bytes[10],
            bytes[11],
            bytes[12],
            bytes[13],
            bytes[14],
            bytes[15],
        );
        value
            .parse()
            .map_err(|_| RecoveryEnrollmentCycleError::Invalid)
    }

    fn confirmation_positions(&self) -> Result<Vec<u8>, RecoveryEnrollmentCycleError> {
        let mut positions = Vec::with_capacity(4);
        while positions.len() < 4 {
            let bytes = self.entropy_array::<16>()?;
            for byte in bytes {
                if byte >= 240 {
                    continue;
                }
                let position = byte % 24 + 1;
                if !positions.contains(&position) {
                    positions.push(position);
                    if positions.len() == 4 {
                        break;
                    }
                }
            }
        }
        positions.sort_unstable();
        Ok(positions)
    }
}

struct EntropyRng<'a, E>(&'a E);

impl<E: RecoveryEnrollmentEntropy> RngCore for EntropyRng<'_, E> {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0_u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0_u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, output: &mut [u8]) {
        self.try_fill_bytes(output)
            .expect("infallible RngCore method cannot report entropy failure");
    }

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), RandError> {
        self.0.fill_bytes(output).map_err(|_| {
            RandError::from(
                NonZeroU32::new(RandError::CUSTOM_START)
                    .expect("rand error custom start is nonzero"),
            )
        })
    }
}

impl<E: RecoveryEnrollmentEntropy> CryptoRng for EntropyRng<'_, E> {}

fn confirmations_match(
    pending: &PendingRecoveryEnrollment,
    params: &RecoveryEnrollmentConfirmParams,
) -> bool {
    let words = pending.phrase.to_words();
    params.confirmations.len() == pending.confirmation_positions.len()
        && params
            .confirmations
            .iter()
            .zip(&pending.confirmation_positions)
            .all(|(confirmation, position)| {
                confirmation.position == *position
                    && words.as_words()[usize::from(*position) - 1] == confirmation.word
            })
}

fn validate_status(
    status: &RecoveryRootStatus,
    stored: &StoredRecoveryEnrollment,
) -> Result<(), RecoveryEnrollmentCycleError> {
    status
        .validate_for(
            SyncScope {
                account_id: stored.record.account_id,
                workspace_id: stored.record.workspace_id,
            },
            &stored.record,
            stored.canonical_record_sha256,
            status.registered_at_ms,
        )
        .map_err(|_| RecoveryEnrollmentCycleError::Conflict)
}

fn receipt_from_status(status: RecoveryRootStatus) -> RecoveryEnrollmentReceipt {
    RecoveryEnrollmentReceipt {
        enrollment_id: status.enrollment_id,
        recovery_root_id: status.recovery_root_id,
        account_id: status.account_id,
        workspace_id: status.workspace_id,
        genesis_certificate_id: status.genesis_certificate_id,
        canonical_record_sha256: status.canonical_record_sha256,
        registered_at_ms: status.registered_at_ms,
    }
}

fn completion(stored: &StoredRecoveryEnrollment) -> RecoveryEnrollmentComplete {
    RecoveryEnrollmentComplete {
        enrollment_id: stored.record.enrollment_id,
        device: DeviceSummary {
            device_id: stored.record.genesis_certificate.device_id,
            name: stored.record.device_name.clone(),
            platform: stored.record.device_platform,
            state: DeviceState::Active,
            is_current: true,
        },
    }
}

fn idle_status() -> RecoveryEnrollmentStatus {
    RecoveryEnrollmentStatus {
        enrollment_id: None,
        state: RecoveryEnrollmentState::Idle,
        created_at_ms: None,
        transitioned_at_ms: None,
    }
}

fn awaiting_status(pending: &PendingRecoveryEnrollment) -> RecoveryEnrollmentStatus {
    RecoveryEnrollmentStatus {
        enrollment_id: Some(pending.artifacts.record.enrollment_id),
        state: RecoveryEnrollmentState::AwaitingConfirmation,
        created_at_ms: Some(DecimalTimestamp(pending.created_at_ms)),
        transitioned_at_ms: None,
    }
}

fn status_from_stored(stored: &StoredRecoveryEnrollment) -> RecoveryEnrollmentStatus {
    let (state, transitioned_at_ms) = match stored.state {
        RecoveryEnrollmentPersistenceState::Prepared => (
            RecoveryEnrollmentState::Submitting,
            Some(stored.prepared_at_ms),
        ),
        RecoveryEnrollmentPersistenceState::Active => {
            (RecoveryEnrollmentState::Complete, stored.completed_at_ms)
        }
        RecoveryEnrollmentPersistenceState::Conflict => {
            (RecoveryEnrollmentState::Conflict, stored.conflict_at_ms)
        }
    };
    RecoveryEnrollmentStatus {
        enrollment_id: Some(stored.record.enrollment_id),
        state,
        created_at_ms: Some(DecimalTimestamp(stored.prepared_at_ms)),
        transitioned_at_ms: transitioned_at_ms.map(DecimalTimestamp),
    }
}

fn conflict_status(
    enrollment_id: RecoveryEnrollmentId,
    created_at_ms: u64,
    transitioned_at_ms: u64,
) -> RecoveryEnrollmentStatus {
    RecoveryEnrollmentStatus {
        enrollment_id: Some(enrollment_id),
        state: RecoveryEnrollmentState::Conflict,
        created_at_ms: Some(DecimalTimestamp(created_at_ms)),
        transitioned_at_ms: Some(DecimalTimestamp(transitioned_at_ms)),
    }
}

fn map_transport_error(error: RecoveryTransportError) -> RecoveryEnrollmentCycleError {
    match error {
        RecoveryTransportError::Invalid | RecoveryTransportError::Conflict => {
            RecoveryEnrollmentCycleError::Conflict
        }
        RecoveryTransportError::Unauthorized => RecoveryEnrollmentCycleError::Unauthorized,
        RecoveryTransportError::Transient => RecoveryEnrollmentCycleError::Transient,
    }
}

fn map_vault_error(error: VaultError) -> RecoveryEnrollmentCycleError {
    match error {
        VaultError::Validation(_) | VaultError::OperationConflict => {
            RecoveryEnrollmentCycleError::Conflict
        }
        _ => RecoveryEnrollmentCycleError::Transient,
    }
}
