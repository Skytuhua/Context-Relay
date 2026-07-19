use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
};

use context_relay_core::vault::{DatabaseKeyStore, Vault, VaultError};
use zeroize::Zeroizing;

#[derive(Default)]
struct MemoryKeyStore(Mutex<HashMap<String, Vec<u8>>>);

impl DatabaseKeyStore for MemoryKeyStore {
    fn load_key(&self, credential_id: &str) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .get(credential_id)
            .cloned()
            .map(Zeroizing::new))
    }

    fn store_key(&self, credential_id: &str, key: &[u8]) -> Result<(), VaultError> {
        self.0
            .lock()
            .unwrap()
            .insert(credential_id.to_owned(), key.to_vec());
        Ok(())
    }
}

struct TempVault(PathBuf);

impl TempVault {
    fn new(name: &str) -> Self {
        let unique = format!(
            "context-relay-{name}-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        Self(std::env::temp_dir().join(unique))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempVault {
    fn drop(&mut self) {
        for suffix in ["", "-journal", "-wal", "-shm"] {
            let _ = fs::remove_file(format!("{}{}", self.0.display(), suffix));
        }
    }
}

#[test]
fn new_vault_has_an_encrypted_header() {
    let path = TempVault::new("encrypted-header");
    let keys = MemoryKeyStore::default();

    drop(Vault::open(path.path(), "test-vault", &keys).unwrap());

    let bytes = fs::read(path.path()).unwrap();
    assert_ne!(&bytes[..16], b"SQLite format 3\0");
}
