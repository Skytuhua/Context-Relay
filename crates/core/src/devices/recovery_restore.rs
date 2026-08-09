use std::{error::Error, fmt, num::NonZeroU32, str::FromStr};

use context_relay_protocol::{
    DeviceCertificateId, DeviceId, DeviceState, DeviceSummary, NativePlatform, PairingRequestNonce,
    RecoveryPhraseWords, RecoveryRestoreId,
};
use rand_core::{CryptoRng, Error as RandError, RngCore};

use crate::{
    crypto::{DeviceKeys, RecoveryPhrase},
    devices::{
        recovery::{
            OsRecoveryEnrollmentEntropy, RecoveryEnrollmentClock, RecoveryEnrollmentEntropy,
            SystemRecoveryEnrollmentClock,
        },
        recovery_restore_crypto::{
            build_recovery_device_claim_inner, open_recovered_device_material,
        },
        recovery_restore_transport::RecoveryRestoreTransport,
        recovery_transport::RecoveryTransportError,
    },
    sync::SyncScope,
    vault::{
        RecoveryRestorePersistenceState, RecoveryRestoreWrite, StoredRecoveryRestore, Vault,
        VaultError,
    },
};

pub struct RecoveryRestoreIdentity<'a> {
    pub device_id: DeviceId,
    pub device_name: String,
    pub platform: NativePlatform,
    pub keys: &'a DeviceKeys,
}

impl fmt::Debug for RecoveryRestoreIdentity<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryRestoreIdentity")
            .field("device_id", &self.device_id)
            .field("device_name", &self.device_name)
            .field("platform", &self.platform)
            .field("keys", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum RecoveryRestoreCycleError {
    Invalid,
    Unavailable,
    Conflict,
    Unauthorized,
    Transient,
}

impl RecoveryRestoreCycleError {
    pub const fn safe_code(self) -> &'static str {
        match self {
            Self::Invalid => "recovery_invalid",
            Self::Unavailable => "recovery_unavailable",
            Self::Conflict => "recovery_conflict",
            Self::Unauthorized => "recovery_unauthorized",
            Self::Transient => "transient",
        }
    }
}

impl fmt::Debug for RecoveryRestoreCycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.safe_code())
    }
}

impl fmt::Display for RecoveryRestoreCycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.safe_code())
    }
}

impl Error for RecoveryRestoreCycleError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryRestoreOutcome {
    Submitting {
        restore_id: RecoveryRestoreId,
    },
    Complete {
        restore_id: RecoveryRestoreId,
        device: DeviceSummary,
    },
    Conflict {
        restore_id: RecoveryRestoreId,
    },
}

pub struct RecoveryRestoreCoordinator<C, E, T> {
    clock: C,
    entropy: E,
    transport: T,
}

impl<T> RecoveryRestoreCoordinator<SystemRecoveryEnrollmentClock, OsRecoveryEnrollmentEntropy, T>
where
    T: RecoveryRestoreTransport,
{
    pub const fn new(transport: T) -> Self {
        Self {
            clock: SystemRecoveryEnrollmentClock,
            entropy: OsRecoveryEnrollmentEntropy,
            transport,
        }
    }
}

#[cfg(feature = "test-support")]
impl<C, E, T> RecoveryRestoreCoordinator<C, E, T>
where
    C: RecoveryEnrollmentClock,
    E: RecoveryEnrollmentEntropy,
    T: RecoveryRestoreTransport,
{
    #[doc(hidden)]
    pub const fn new_for_test(clock: C, entropy: E, transport: T) -> Self {
        Self {
            clock,
            entropy,
            transport,
        }
    }
}

impl<C, E, T> fmt::Debug for RecoveryRestoreCoordinator<C, E, T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryRestoreCoordinator([REDACTED])")
    }
}

impl<C, E, T> RecoveryRestoreCoordinator<C, E, T>
where
    C: RecoveryEnrollmentClock,
    E: RecoveryEnrollmentEntropy,
    T: RecoveryRestoreTransport,
{
    pub fn recover(
        &self,
        vault: &mut Vault,
        phrase_words: RecoveryPhraseWords,
        identity: &RecoveryRestoreIdentity<'_>,
    ) -> Result<RecoveryRestoreOutcome, RecoveryRestoreCycleError> {
        validate_identity(identity)?;
        if vault.recovery_restore().map_err(map_vault_error)?.is_some() {
            return Err(RecoveryRestoreCycleError::Conflict);
        }
        let scope = self.transport.scope();
        let snapshot = self
            .transport
            .root_snapshot()
            .map_err(map_initial_transport_error)?
            .ok_or(RecoveryRestoreCycleError::Unavailable)?;
        snapshot
            .validate_for(scope)
            .map_err(|_| RecoveryRestoreCycleError::Conflict)?;
        let phrase = RecoveryPhrase::from_words(phrase_words)
            .map_err(|_| RecoveryRestoreCycleError::Invalid)?;
        let authority = crate::devices::recovery_restore_crypto::authenticate_recovery_root(
            &snapshot.canonical_record,
            snapshot.canonical_record_sha256,
            phrase,
        )
        .map_err(|_| RecoveryRestoreCycleError::Invalid)?;
        let restore_id = self.entropy_uuid_v7::<RecoveryRestoreId>()?;
        let certificate_id = self.entropy_uuid_v7::<DeviceCertificateId>()?;
        let request_nonce = PairingRequestNonce(self.entropy_array()?);
        let mut rng = RestoreEntropyRng {
            source: &self.entropy,
            failed: false,
        };
        let artifacts = build_recovery_device_claim_inner(
            authority,
            restore_id,
            snapshot.recovery_generation,
            certificate_id,
            request_nonce,
            identity.device_id,
            identity.device_name.clone(),
            identity.platform,
            identity.keys,
            &mut rng,
        );
        let artifacts = match artifacts {
            Ok(artifacts) => artifacts,
            Err(_) if rng.failed => return Err(RecoveryRestoreCycleError::Transient),
            Err(_) => return Err(RecoveryRestoreCycleError::Invalid),
        };
        let write = RecoveryRestoreWrite::new(snapshot, artifacts, self.clock.now_ms())
            .map_err(map_vault_error)?;
        vault
            .prepare_recovery_restore(&write)
            .map_err(map_vault_error)?;
        self.resume_prepared(vault, identity)
    }

    pub fn resume_prepared(
        &self,
        vault: &mut Vault,
        identity: &RecoveryRestoreIdentity<'_>,
    ) -> Result<RecoveryRestoreOutcome, RecoveryRestoreCycleError> {
        validate_identity(identity)?;
        let stored = vault
            .recovery_restore()
            .map_err(map_vault_error)?
            .ok_or(RecoveryRestoreCycleError::Invalid)?;
        validate_stored_identity(&stored, identity)?;
        let restore_id = stored.claim.restore_id;
        match stored.state {
            RecoveryRestorePersistenceState::Conflict => {
                return Ok(RecoveryRestoreOutcome::Conflict { restore_id });
            }
            RecoveryRestorePersistenceState::Active => {
                vault
                    .recovered_workspace_material(identity.keys)
                    .map_err(map_vault_error)?;
                return Ok(complete(&stored));
            }
            RecoveryRestorePersistenceState::Prepared => {}
        }

        if self.transport.scope() != stored_scope(&stored) {
            return self.mark_conflict(vault, &stored);
        }
        open_recovered_device_material(&stored.record, &stored.claim, identity.keys)
            .map_err(|_| RecoveryRestoreCycleError::Conflict)?;
        let now_ms = self.clock.now_ms();
        let receipt = match self
            .transport
            .submit_restore(&stored.canonical_claim, now_ms)
        {
            Ok(receipt) => receipt,
            Err(RecoveryTransportError::Transient) => {
                return Ok(RecoveryRestoreOutcome::Submitting { restore_id });
            }
            Err(RecoveryTransportError::Unauthorized) => {
                return Err(RecoveryRestoreCycleError::Unauthorized);
            }
            Err(RecoveryTransportError::Invalid | RecoveryTransportError::Conflict) => {
                return self.mark_conflict(vault, &stored);
            }
        };
        if receipt
            .validate_for(
                stored_scope(&stored),
                &stored.record,
                &stored.canonical_claim,
            )
            .ok()
            .as_ref()
            != Some(&stored.claim)
        {
            return self.mark_conflict(vault, &stored);
        }
        let projection = match self.transport.restore_claim(restore_id) {
            Ok(Some(projection)) => projection,
            Ok(None) | Err(RecoveryTransportError::Invalid | RecoveryTransportError::Conflict) => {
                return self.mark_conflict(vault, &stored);
            }
            Err(RecoveryTransportError::Unauthorized) => {
                return Err(RecoveryRestoreCycleError::Unauthorized);
            }
            Err(RecoveryTransportError::Transient) => {
                return Ok(RecoveryRestoreOutcome::Submitting { restore_id });
            }
        };
        if projection.canonical_claim != stored.canonical_claim
            || projection.receipt != receipt
            || projection
                .validate_for(stored_scope(&stored), &stored.record)
                .ok()
                .as_ref()
                != Some(&stored.claim)
        {
            return self.mark_conflict(vault, &stored);
        }
        match vault.activate_recovery_restore(&receipt, &projection, identity.keys, now_ms) {
            Ok(_) => {
                let active = vault
                    .recovery_restore()
                    .map_err(map_vault_error)?
                    .ok_or(RecoveryRestoreCycleError::Conflict)?;
                Ok(complete(&active))
            }
            Err(VaultError::Validation(_) | VaultError::OperationConflict) => {
                self.mark_conflict(vault, &stored)
            }
            Err(_) => Err(RecoveryRestoreCycleError::Transient),
        }
    }

    fn mark_conflict(
        &self,
        vault: &mut Vault,
        stored: &StoredRecoveryRestore,
    ) -> Result<RecoveryRestoreOutcome, RecoveryRestoreCycleError> {
        let conflict_at_ms = self.clock.now_ms().max(stored.prepared_at_ms);
        vault
            .mark_recovery_restore_conflict(conflict_at_ms)
            .map_err(map_vault_error)?;
        Ok(RecoveryRestoreOutcome::Conflict {
            restore_id: stored.claim.restore_id,
        })
    }

    fn entropy_array<const N: usize>(&self) -> Result<[u8; N], RecoveryRestoreCycleError> {
        let mut output = [0_u8; N];
        self.entropy
            .fill_bytes(&mut output)
            .map_err(|_| RecoveryRestoreCycleError::Transient)?;
        Ok(output)
    }

    fn entropy_uuid_v7<I: FromStr>(&self) -> Result<I, RecoveryRestoreCycleError> {
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
            .map_err(|_| RecoveryRestoreCycleError::Invalid)
    }
}

struct RestoreEntropyRng<'a, E> {
    source: &'a E,
    failed: bool,
}

impl<E: RecoveryEnrollmentEntropy> RngCore for RestoreEntropyRng<'_, E> {
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
        self.source.fill_bytes(output).map_err(|_| {
            self.failed = true;
            RandError::from(
                NonZeroU32::new(RandError::CUSTOM_START)
                    .expect("rand error custom start is nonzero"),
            )
        })
    }
}

impl<E: RecoveryEnrollmentEntropy> CryptoRng for RestoreEntropyRng<'_, E> {}

fn validate_identity(
    identity: &RecoveryRestoreIdentity<'_>,
) -> Result<(), RecoveryRestoreCycleError> {
    if identity.device_name.trim().is_empty() || identity.device_name.len() > 256 {
        return Err(RecoveryRestoreCycleError::Invalid);
    }
    Ok(())
}

fn validate_stored_identity(
    stored: &StoredRecoveryRestore,
    identity: &RecoveryRestoreIdentity<'_>,
) -> Result<(), RecoveryRestoreCycleError> {
    if stored.claim.certificate.device_id != identity.device_id
        || stored.claim.device_name != identity.device_name
        || stored.claim.device_platform != identity.platform
        || stored.claim.certificate.signing_public_key != identity.keys.signing_public_key()
        || stored.claim.certificate.wrapping_public_key != identity.keys.wrapping_public_key()
    {
        return Err(RecoveryRestoreCycleError::Conflict);
    }
    Ok(())
}

fn stored_scope(stored: &StoredRecoveryRestore) -> SyncScope {
    SyncScope {
        account_id: stored.record.account_id,
        workspace_id: stored.record.workspace_id,
    }
}

fn complete(stored: &StoredRecoveryRestore) -> RecoveryRestoreOutcome {
    RecoveryRestoreOutcome::Complete {
        restore_id: stored.claim.restore_id,
        device: DeviceSummary {
            device_id: stored.claim.certificate.device_id,
            name: stored.claim.device_name.clone(),
            platform: stored.claim.device_platform,
            state: DeviceState::Active,
            is_current: true,
        },
    }
}

fn map_initial_transport_error(error: RecoveryTransportError) -> RecoveryRestoreCycleError {
    match error {
        RecoveryTransportError::Invalid | RecoveryTransportError::Conflict => {
            RecoveryRestoreCycleError::Conflict
        }
        RecoveryTransportError::Unauthorized => RecoveryRestoreCycleError::Unauthorized,
        RecoveryTransportError::Transient => RecoveryRestoreCycleError::Transient,
    }
}

fn map_vault_error(error: VaultError) -> RecoveryRestoreCycleError {
    match error {
        VaultError::Validation(_) | VaultError::OperationConflict => {
            RecoveryRestoreCycleError::Conflict
        }
        _ => RecoveryRestoreCycleError::Transient,
    }
}
