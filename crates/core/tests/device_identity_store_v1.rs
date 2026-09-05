use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

use context_relay_core::{
    crypto::DeviceKeys,
    devices::identity::{
        DeviceIdentityError, DeviceIdentityStore, StoreIfAbsent, load_or_create_device_keys,
    },
};
use zeroize::Zeroizing;

#[test]
fn first_creation_is_persisted_and_reopen_returns_the_same_public_keys() {
    let store = MemoryStore::default();

    let first = load_or_create_device_keys(&store, "device-a").unwrap();
    let signing = first.signing_public_key();
    let wrapping = first.wrapping_public_key();
    drop(first);

    let reopened = load_or_create_device_keys(&store, "device-a").unwrap();
    assert_eq!(reopened.signing_public_key(), signing);
    assert_eq!(reopened.wrapping_public_key(), wrapping);
    assert_eq!(store.record("device-a").unwrap().len(), 65);
}

#[test]
fn malformed_existing_records_fail_closed() {
    for record in [vec![0; 64], vec![2; 65]] {
        let store = MemoryStore::with_record("device-a", record);
        assert_eq!(
            load_or_create_device_keys(&store, "device-a").unwrap_err(),
            DeviceIdentityError::InvalidRecord
        );
    }
}

#[test]
fn load_and_store_failures_are_propagated_without_fallback() {
    let load_failure = MemoryStore::failing_load();
    assert_eq!(
        load_or_create_device_keys(&load_failure, "device-a").unwrap_err(),
        DeviceIdentityError::CredentialStore
    );

    let store_failure = MemoryStore::failing_store();
    assert_eq!(
        load_or_create_device_keys(&store_failure, "device-a").unwrap_err(),
        DeviceIdentityError::CredentialStore
    );
    assert!(store_failure.record("device-a").is_none());
}

#[test]
fn store_if_absent_is_exact_under_concurrent_attempts() {
    let store = Arc::new(MemoryStore::default());
    let mut workers = Vec::new();
    for _ in 0..8 {
        let store = Arc::clone(&store);
        workers.push(thread::spawn(move || {
            store
                .store_if_absent("device-a", &[1; 65])
                .expect("test store succeeds")
        }));
    }

    let outcomes = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == StoreIfAbsent::Stored)
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == StoreIfAbsent::AlreadyExists)
            .count(),
        7
    );
}

#[test]
fn creation_race_reloads_the_identity_written_by_the_winner() {
    let winning_store = MemoryStore::default();
    let winner = load_or_create_device_keys(&winning_store, "device-a").unwrap();
    let expected_signing = winner.signing_public_key();
    let expected_wrapping = winner.wrapping_public_key();
    let race = RacingStore {
        record: winning_store.record("device-a").unwrap(),
        first_load: AtomicBool::new(true),
    };

    let recovered = load_or_create_device_keys(&race, "device-a").unwrap();
    assert_eq!(recovered.signing_public_key(), expected_signing);
    assert_eq!(recovered.wrapping_public_key(), expected_wrapping);
}

#[test]
fn identity_store_and_device_keys_debug_output_redact_secret_material() {
    let store = MemoryStore::with_record("device-a", vec![0x5a; 65]);
    let debug = format!("{store:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("90, 90, 90"));

    let keys = DeviceKeys::generate().unwrap();
    assert_eq!(format!("{keys:?}"), "DeviceKeys([REDACTED])");
}

struct MemoryStore {
    records: Mutex<BTreeMap<String, Vec<u8>>>,
    fail_load: bool,
    fail_store: bool,
}

impl MemoryStore {
    fn with_record(credential_id: &str, record: Vec<u8>) -> Self {
        Self {
            records: Mutex::new(BTreeMap::from([(credential_id.to_owned(), record)])),
            fail_load: false,
            fail_store: false,
        }
    }

    fn failing_load() -> Self {
        Self {
            records: Mutex::new(BTreeMap::new()),
            fail_load: true,
            fail_store: false,
        }
    }

    fn failing_store() -> Self {
        Self {
            records: Mutex::new(BTreeMap::new()),
            fail_load: false,
            fail_store: true,
        }
    }

    fn record(&self, credential_id: &str) -> Option<Vec<u8>> {
        self.records.lock().unwrap().get(credential_id).cloned()
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self {
            records: Mutex::new(BTreeMap::new()),
            fail_load: false,
            fail_store: false,
        }
    }
}

impl DeviceIdentityStore for MemoryStore {
    fn load(&self, credential_id: &str) -> Result<Option<Zeroizing<Vec<u8>>>, DeviceIdentityError> {
        if self.fail_load {
            return Err(DeviceIdentityError::CredentialStore);
        }
        Ok(self
            .records
            .lock()
            .unwrap()
            .get(credential_id)
            .cloned()
            .map(Zeroizing::new))
    }

    fn store_if_absent(
        &self,
        credential_id: &str,
        record: &[u8],
    ) -> Result<StoreIfAbsent, DeviceIdentityError> {
        if self.fail_store {
            return Err(DeviceIdentityError::CredentialStore);
        }
        let mut records = self.records.lock().unwrap();
        if records.contains_key(credential_id) {
            return Ok(StoreIfAbsent::AlreadyExists);
        }
        records.insert(credential_id.to_owned(), record.to_vec());
        Ok(StoreIfAbsent::Stored)
    }
}

impl std::fmt::Debug for MemoryStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("MemoryStore([REDACTED])")
    }
}

struct RacingStore {
    record: Vec<u8>,
    first_load: AtomicBool,
}

impl DeviceIdentityStore for RacingStore {
    fn load(
        &self,
        _credential_id: &str,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, DeviceIdentityError> {
        if self.first_load.swap(false, Ordering::SeqCst) {
            Ok(None)
        } else {
            Ok(Some(Zeroizing::new(self.record.clone())))
        }
    }

    fn store_if_absent(
        &self,
        _credential_id: &str,
        _record: &[u8],
    ) -> Result<StoreIfAbsent, DeviceIdentityError> {
        Ok(StoreIfAbsent::AlreadyExists)
    }
}
