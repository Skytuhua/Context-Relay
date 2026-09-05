use std::fmt;

use keyring::Entry;
use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::DeviceKeys;

const DEVICE_IDENTITY_SERVICE: &str = "context-relay-device";
const IDENTITY_RECORD_VERSION: u8 = 1;
const IDENTITY_RECORD_BYTES: usize = 65;
const SEED_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DeviceIdentityError {
    #[error("credential store unavailable")]
    CredentialStore,
    #[error("stored device identity is invalid")]
    InvalidRecord,
    #[error("device identity store changed concurrently")]
    StoreConflict,
    #[error("secure randomness unavailable")]
    RandomnessUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreIfAbsent {
    Stored,
    AlreadyExists,
}

pub trait DeviceIdentityStore: Send + Sync {
    fn load(&self, credential_id: &str) -> Result<Option<Zeroizing<Vec<u8>>>, DeviceIdentityError>;

    fn store_if_absent(
        &self,
        credential_id: &str,
        record: &[u8],
    ) -> Result<StoreIfAbsent, DeviceIdentityError>;
}

#[derive(Clone, Default)]
pub struct PlatformDeviceIdentityStore;

impl PlatformDeviceIdentityStore {
    fn entry(&self, credential_id: &str) -> Result<Entry, DeviceIdentityError> {
        Entry::new(DEVICE_IDENTITY_SERVICE, credential_id)
            .map_err(|_| DeviceIdentityError::CredentialStore)
    }
}

impl DeviceIdentityStore for PlatformDeviceIdentityStore {
    fn load(&self, credential_id: &str) -> Result<Option<Zeroizing<Vec<u8>>>, DeviceIdentityError> {
        match self.entry(credential_id)?.get_secret() {
            Ok(record) => Ok(Some(Zeroizing::new(record))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => Err(DeviceIdentityError::CredentialStore),
        }
    }

    fn store_if_absent(
        &self,
        credential_id: &str,
        record: &[u8],
    ) -> Result<StoreIfAbsent, DeviceIdentityError> {
        let entry = self.entry(credential_id)?;
        match entry.get_secret() {
            Ok(mut existing) => {
                existing.zeroize();
                Ok(StoreIfAbsent::AlreadyExists)
            }
            Err(keyring::Error::NoEntry) => entry
                .set_secret(record)
                .map(|_| StoreIfAbsent::Stored)
                .map_err(|_| DeviceIdentityError::CredentialStore),
            Err(_) => Err(DeviceIdentityError::CredentialStore),
        }
    }
}

impl fmt::Debug for PlatformDeviceIdentityStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PlatformDeviceIdentityStore([REDACTED])")
    }
}

pub fn load_or_create_device_keys(
    store: &(impl DeviceIdentityStore + ?Sized),
    credential_id: &str,
) -> Result<DeviceKeys, DeviceIdentityError> {
    if let Some(record) = store.load(credential_id)? {
        return decode_record(record);
    }

    let mut signing_seed = Zeroizing::new([0_u8; SEED_BYTES]);
    let mut wrapping_seed = Zeroizing::new([0_u8; SEED_BYTES]);
    OsRng
        .try_fill_bytes(&mut *signing_seed)
        .and_then(|_| OsRng.try_fill_bytes(&mut *wrapping_seed))
        .map_err(|_| DeviceIdentityError::RandomnessUnavailable)?;

    let mut record = Zeroizing::new(vec![0_u8; IDENTITY_RECORD_BYTES]);
    record[0] = IDENTITY_RECORD_VERSION;
    record[1..1 + SEED_BYTES].copy_from_slice(&signing_seed[..]);
    record[1 + SEED_BYTES..].copy_from_slice(&wrapping_seed[..]);

    match store.store_if_absent(credential_id, &record)? {
        StoreIfAbsent::Stored => Ok(DeviceKeys::from_zeroizing_seeds(
            signing_seed,
            wrapping_seed,
        )),
        StoreIfAbsent::AlreadyExists => {
            record.zeroize();
            signing_seed.zeroize();
            wrapping_seed.zeroize();
            let record = store
                .load(credential_id)?
                .ok_or(DeviceIdentityError::StoreConflict)?;
            decode_record(record)
        }
    }
}

fn decode_record(mut record: Zeroizing<Vec<u8>>) -> Result<DeviceKeys, DeviceIdentityError> {
    if record.len() != IDENTITY_RECORD_BYTES || record[0] != IDENTITY_RECORD_VERSION {
        return Err(DeviceIdentityError::InvalidRecord);
    }
    let mut signing_seed = Zeroizing::new([0_u8; SEED_BYTES]);
    let mut wrapping_seed = Zeroizing::new([0_u8; SEED_BYTES]);
    signing_seed.copy_from_slice(&record[1..1 + SEED_BYTES]);
    wrapping_seed.copy_from_slice(&record[1 + SEED_BYTES..]);
    record.zeroize();
    Ok(DeviceKeys::from_zeroizing_seeds(
        signing_seed,
        wrapping_seed,
    ))
}
