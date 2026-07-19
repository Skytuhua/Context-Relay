use context_relay_contextd::client_error_from_vault;
use context_relay_core::vault::{DatabaseKeyStore, Vault, VaultError};
use context_relay_protocol::{ClientError, ErrorCode};
use std::path::PathBuf;
use zeroize::Zeroizing;

#[test]
fn missing_vault_key_is_a_stable_redacted_locked_error() {
    assert_eq!(
        client_error_from_vault(VaultError::MissingKey),
        ClientError {
            code: ErrorCode::VaultLocked,
            message: "The local vault is locked".into(),
            field_path: None,
            retryable: true,
        }
    );
}

#[test]
fn every_vault_error_maps_to_an_exact_safe_client_error() {
    let canary = "CANARY C:\\secret\\vault.db SELECT keyring /tmp/private";
    let cases = [
        (
            VaultError::MissingKey,
            ErrorCode::VaultLocked,
            "The local vault is locked",
            true,
        ),
        (
            VaultError::WrongKey,
            ErrorCode::VaultLocked,
            "The local vault is locked",
            true,
        ),
        (
            VaultError::FutureSchema { found: u32::MAX },
            ErrorCode::Internal,
            "The local service could not complete the request",
            false,
        ),
        (
            VaultError::Migration(canary.into()),
            ErrorCode::Internal,
            "The local service could not complete the request",
            false,
        ),
        (
            VaultError::BudgetExceeded,
            ErrorCode::QuotaExceeded,
            "The local storage quota is exhausted",
            false,
        ),
        (
            VaultError::Credential(canary.into()),
            ErrorCode::Internal,
            "The local service could not complete the request",
            false,
        ),
        (
            VaultError::Security(canary.into()),
            ErrorCode::Internal,
            "The local service could not complete the request",
            false,
        ),
        (
            VaultError::Validation(canary.into()),
            ErrorCode::InvalidRequest,
            "The request is invalid",
            false,
        ),
        (
            VaultError::Serialization(canary.into()),
            ErrorCode::Internal,
            "The local service could not complete the request",
            false,
        ),
        (
            database_error(),
            ErrorCode::Internal,
            "The local service could not complete the request",
            false,
        ),
    ];

    for (source, code, message, retryable) in cases {
        let error = client_error_from_vault(source);
        assert_eq!(error.code, code);
        assert_eq!(error.message, message);
        assert_eq!(error.field_path, None);
        assert_eq!(error.retryable, retryable);
        let serialized = serde_json::to_string(&error).unwrap();
        for forbidden in [
            "CANARY", "sqlite", "keyring", "SELECT", "secret", "vault.db",
        ] {
            assert!(
                !serialized.contains(forbidden),
                "leaked {forbidden}: {serialized}"
            );
        }
    }
}

struct EmptyKeyStore;

impl DatabaseKeyStore for EmptyKeyStore {
    fn load_key(&self, _: &str) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
        Ok(None)
    }

    fn store_key(&self, _: &str, _: &[u8]) -> Result<(), VaultError> {
        Ok(())
    }
}

fn database_error() -> VaultError {
    let path = unique_temp_path("database-error");
    std::fs::create_dir_all(&path).unwrap();
    let result = Vault::open(&path, "database-error", &EmptyKeyStore);
    std::fs::remove_dir_all(&path).unwrap();
    match result {
        Err(error @ VaultError::Database(_)) => error,
        Err(other) => panic!("expected database error, got {other:?}"),
        Ok(_) => panic!("opening a directory unexpectedly succeeded"),
    }
}

fn unique_temp_path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "context-relay-contextd-{label}-{}",
        uuid::Uuid::now_v7()
    ))
}
