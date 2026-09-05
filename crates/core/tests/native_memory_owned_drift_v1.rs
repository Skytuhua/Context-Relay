mod support;

use context_relay_core::{
    native_memory::{
        NativeMemoryDiagnosticClass, NativeMemoryDocumentKind, NativeMemoryLedger,
        NativeMemoryLimits, NativeMemoryObservationKind, NativeMemorySnapshot, NativeMemorySource,
        ReadyNativeMemory,
    },
    service::OfflineWorkspace,
    vault::{LATEST_SCHEMA_VERSION, Vault},
};
use context_relay_protocol::{HarnessId, NativePlatform, ScopeRef, Sha256Digest, WireNativeValue};
use rusqlite::Connection;
use sha2::{Digest as _, Sha256};

use support::{ID_7, MemoryKeyStore, TempVault};

const CREDENTIAL: &str = "native-memory-owned-drift-tests";
const START: &str = "<!-- context-relay:start -->";
const END: &str = "<!-- context-relay:end -->";

fn source() -> NativeMemorySource {
    NativeMemorySource::new(
        HarnessId::Hermes,
        "0.18.2",
        ScopeRef::Global,
        NativeMemoryDocumentKind::Agent,
        WireNativeValue {
            platform: NativePlatform::Macos,
            bytes: b"/tmp/context-relay/owned-memory.md".to_vec(),
            display: Some("/tmp/context-relay/owned-memory.md".to_owned()),
        },
        NativeMemoryLimits {
            max_bytes: 4_096,
            max_characters: 4_096,
        },
        true,
    )
    .unwrap()
}

fn ready(
    source: NativeMemorySource,
    bytes: &[u8],
    kind: NativeMemoryObservationKind,
) -> ReadyNativeMemory {
    ReadyNativeMemory {
        source,
        snapshot: NativeMemorySnapshot::Regular(bytes.to_vec()),
        kind,
    }
}

fn open_keyed(path: &std::path::Path, key: &[u8; 32]) -> Connection {
    let connection = Connection::open(path).unwrap();
    // SAFETY: the connection owns the handle, the key remains valid for the call,
    // and this is the first SQLite operation after open.
    let result = unsafe {
        rusqlite::ffi::sqlite3_key(
            connection.handle(),
            key.as_ptr().cast(),
            key.len().try_into().unwrap(),
        )
    };
    assert_eq!(result, rusqlite::ffi::SQLITE_OK);
    connection
        .query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
        .unwrap();
    connection
}

#[test]
fn migration_v24_adds_the_managed_owned_digest_binding() {
    let path = TempVault::new("managed-owned-digest-migration-v24");
    let keys = MemoryKeyStore::default();
    let key = [0x52; 32];
    keys.insert(CREDENTIAL, key);
    let raw = open_keyed(path.path(), &key);
    raw.execute_batch(include_str!("../migrations/0001_vault.sql"))
        .unwrap();
    raw.execute_batch(include_str!(
        "../migrations/0010_native_memory_reconciliation.sql"
    ))
    .unwrap();
    raw.pragma_update(None, "user_version", 24).unwrap();
    drop(raw);

    let vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(LATEST_SCHEMA_VERSION, 25);
    assert_eq!(vault.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
    drop(vault);

    let raw = open_keyed(path.path(), &key);
    let columns = raw
        .prepare("PRAGMA table_info(native_memory_sources)")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(columns.contains(&"last_applied_managed_digest".to_owned()));
}

#[test]
fn managed_owned_block_drift_is_a_durable_conflict_after_restart() {
    let path = TempVault::new("managed-owned-block-drift");
    let keys = MemoryKeyStore::default();
    let descriptor = source();
    let applied = format!("{START}\nAuthoritative memory\n{END}\n");
    let applied_managed_digest = Sha256Digest(Sha256::digest(b"Authoritative memory\n").into());
    let mut ledger = NativeMemoryLedger::for_source(descriptor.clone());
    ledger.last_applied_digest = Some(Sha256Digest(Sha256::digest(applied.as_bytes()).into()));

    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault.put_native_memory_candidate(&ledger, None).unwrap();
    assert_eq!(
        OfflineWorkspace::new(&mut vault, ID_7.parse().unwrap())
            .reconcile_native_memory(ready(
                descriptor.clone(),
                applied.as_bytes(),
                NativeMemoryObservationKind::InitialPreview,
            ))
            .unwrap(),
        None
    );
    drop(vault);

    let drifted = format!("{START}\nUser changed owned memory\n{END}\n");
    let mut reopened = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(
        OfflineWorkspace::new(&mut reopened, ID_7.parse().unwrap())
            .reconcile_native_memory(ready(
                descriptor.clone(),
                drifted.as_bytes(),
                NativeMemoryObservationKind::LiveEdit,
            ))
            .unwrap(),
        None
    );

    let stored = reopened
        .native_memory_ledger(&descriptor.id)
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.last_applied_managed_digest,
        Some(applied_managed_digest)
    );
    assert_eq!(
        stored.last_diagnostic.unwrap().error_class,
        NativeMemoryDiagnosticClass::ManagedContentModified
    );
    assert!(reopened.candidates(None).unwrap().is_empty());
}
