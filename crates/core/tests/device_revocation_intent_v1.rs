mod support;

use context_relay_core::{
    crypto::{CertificateFieldsV1, DeviceCertificateV1, DeviceKeys, RecoveryKeys, RecoveryPhrase},
    devices::revocation_crypto::{
        DeviceRevocationStatementV1, RevocationControlState, RevocationTransitionV1,
    },
    sync::SyncScope,
    vault::{DeviceRevocationIntent, Vault},
};
use context_relay_protocol::{PairingRequestNonce, Sha256Digest};
use std::collections::BTreeMap;
use support::{MemoryKeyStore, TempVault};

#[test]
fn revocation_intent_preserves_exact_keys_and_authority_across_restart() {
    let path = TempVault::new("revocation-intent");
    let store = MemoryKeyStore::default();
    let keys = DeviceKeys::generate().unwrap();
    let request = DeviceRevocationStatementV1 {
        schema_version: 1,
        revocation_id: "018f22e2-79b0-7cc8-98c4-dc0c0c073980".parse().unwrap(),
        account_id: "018f22e2-79b0-7cc8-98c4-dc0c0c073981".parse().unwrap(),
        workspace_id: "018f22e2-79b0-7cc8-98c4-dc0c0c073982".parse().unwrap(),
        issuer_device_id: "018f22e2-79b0-7cc8-98c4-dc0c0c073983".parse().unwrap(),
        target_device_id: "018f22e2-79b0-7cc8-98c4-dc0c0c073983".parse().unwrap(),
        control_epoch: 1,
        key_epoch: 1,
        cutoff_sequence: 0,
        cutoff_hash: Sha256Digest([0; 32]),
        transition_sha256: Sha256Digest([0; 32]),
    };
    let recovery = RecoveryKeys::derive(&RecoveryPhrase::generate().unwrap()).unwrap();
    let certificate = DeviceCertificateV1::issue_genesis(
        CertificateFieldsV1 {
            account_id: request.account_id,
            workspace_id: request.workspace_id,
            control_epoch: 1,
            request_nonce: PairingRequestNonce([1; 32]),
            device_id: request.issuer_device_id,
            signing_public_key: keys.signing_public_key(),
            wrapping_public_key: keys.wrapping_public_key(),
        },
        &recovery,
    )
    .unwrap();
    let active = BTreeMap::from([(certificate.device_id, certificate.clone())]);
    let current = RevocationControlState {
        scope: SyncScope {
            account_id: request.account_id,
            workspace_id: request.workspace_id,
        },
        control_epoch: 1,
        key_epoch: 1,
        state_sha256: Sha256Digest([5; 32]),
        active_devices: &active,
        recovery_root_id: "018f22e2-79b0-7cc8-98c4-dc0c0c073984".parse().unwrap(),
        recovery_wrapping_public_key: recovery.wrapping_public_key(),
    };
    let (statement, transition, signature) =
        RevocationTransitionV1::build(request.clone(), &keys, &current).unwrap();
    let intent = DeviceRevocationIntent {
        project_url: "https://example.supabase.co/".into(),
        user_id: "550e8400-e29b-41d4-a716-446655440000".parse().unwrap(),
        session_id: "550e8400-e29b-41d4-a716-446655440001".parse().unwrap(),
        issuer_certificate: certificate.clone(),
        statement,
        transition,
        signature,
    };
    let original = intent
        .transition
        .open_recovery_material(&intent.statement, intent.signature, &current, &recovery)
        .unwrap();
    let mut vault = Vault::open(path.path(), "revocation", &store).unwrap();
    assert!(
        vault
            .device_revocation_intent(intent.statement.revocation_id)
            .unwrap()
            .is_none()
    );
    vault
        .store_device_revocation_intent(&intent, &current)
        .unwrap();
    drop(vault);
    let mut vault = Vault::open(path.path(), "revocation", &store).unwrap();
    assert_eq!(
        vault.device_revocation_intent_ids(None).unwrap(),
        vec![intent.statement.revocation_id]
    );
    assert!(
        vault
            .device_revocation_intent_ids(Some(intent.statement.revocation_id))
            .unwrap()
            .is_empty()
    );
    let restored = vault
        .device_revocation_intent(intent.statement.revocation_id)
        .unwrap()
        .unwrap();
    assert_eq!(restored, intent);
    let reopened = restored
        .transition
        .open_recovery_material(&restored.statement, restored.signature, &current, &recovery)
        .unwrap();
    assert_eq!(original.workspace_root_key(), reopened.workspace_root_key());
    assert_eq!(original.active_epoch_key(), reopened.active_epoch_key());
    vault
        .store_device_revocation_intent(&restored, &current)
        .unwrap();
    // A second build produces new ciphertext/key material, never a valid retry.
    let (statement, transition, signature) =
        RevocationTransitionV1::build(request, &keys, &current).unwrap();
    let replacement = DeviceRevocationIntent {
        statement,
        transition,
        signature,
        ..intent.clone()
    };
    assert!(
        vault
            .store_device_revocation_intent(&replacement, &current)
            .is_err()
    );
    for field in 0..4 {
        let mut changed = intent.clone();
        match field {
            0 => changed.project_url = "https://other.supabase.co/".into(),
            1 => changed.user_id = intent.session_id,
            2 => changed.session_id = intent.user_id,
            _ => changed.signature.0[0] ^= 1,
        }
        assert!(
            vault
                .store_device_revocation_intent(&changed, &current)
                .is_err()
        );
    }
    assert_eq!(
        vault
            .device_revocation_intent(intent.statement.revocation_id)
            .unwrap(),
        Some(intent.clone())
    );
    drop(vault);
    let raw = rusqlite::Connection::open(path.path()).unwrap();
    let key = store.key("revocation");
    // SAFETY: keying is the first database operation and the key lives through the call.
    assert_eq!(
        unsafe { rusqlite::ffi::sqlite3_key(raw.handle(), key.as_ptr().cast(), 32) },
        rusqlite::ffi::SQLITE_OK
    );
    raw.pragma_update(None, "ignore_check_constraints", true)
        .unwrap();
    let vault = Vault::open(path.path(), "revocation", &store).unwrap();
    for (column, original) in [
        ("project_url", intent.project_url.clone()),
        ("user_id", intent.user_id.to_string()),
        ("session_id", intent.session_id.to_string()),
        ("operation_id", intent.statement.revocation_id.to_string()),
    ] {
        let oversized = format!("{original}\0{}", "x".repeat(8192));
        let sql = format!("UPDATE device_revocation_intents SET {column}=?1");
        raw.execute(&sql, [&oversized]).unwrap();
        let error = if column == "operation_id" {
            vault.device_revocation_intent_ids(None).unwrap_err()
        } else {
            vault
                .device_revocation_intent(intent.statement.revocation_id)
                .unwrap_err()
        };
        // SQL returns NULL before Rust allocates the damaged value.
        assert!(
            matches!(
                error,
                context_relay_core::vault::VaultError::Database(
                    rusqlite::Error::InvalidColumnType(_, _, rusqlite::types::Type::Null)
                )
            ),
            "{column}: {error:?}"
        );
        raw.execute(&sql, [&original]).unwrap();
    }
    raw.execute(
        "UPDATE device_revocation_intents SET operation_id=upper(operation_id)",
        [],
    )
    .unwrap();
    assert!(vault.device_revocation_intent_ids(None).is_err());
    raw.execute(
        "UPDATE device_revocation_intents SET operation_id=?1",
        [intent.statement.revocation_id.to_string()],
    )
    .unwrap();
    drop(vault);
    raw.execute(
        "UPDATE device_revocation_intents SET signature=zeroblob(64)",
        [],
    )
    .unwrap();
    drop(raw);
    let vault = Vault::open(path.path(), "revocation", &store).unwrap();
    assert!(
        vault
            .device_revocation_intent(intent.statement.revocation_id)
            .is_err()
    );
}

#[test]
fn schema_36_upgrade_does_not_invent_revocation_authority() {
    let path = TempVault::new("revocation-migration");
    let store = MemoryKeyStore::default();
    drop(Vault::open(path.path(), "migration", &store).unwrap());
    let raw = rusqlite::Connection::open(path.path()).unwrap();
    let key = store.key("migration");
    // SAFETY: keying is the first database operation and the key lives through the call.
    assert_eq!(
        unsafe { rusqlite::ffi::sqlite3_key(raw.handle(), key.as_ptr().cast(), 32) },
        rusqlite::ffi::SQLITE_OK
    );
    raw.execute_batch("DROP TABLE revocation_genesis_anchor; DROP TABLE revocation_control_history; DROP TABLE device_revocation_intents; PRAGMA user_version=36;")
        .unwrap();
    drop(raw);
    let vault = Vault::open(path.path(), "migration", &store).unwrap();
    assert_eq!(
        vault.schema_version().unwrap(),
        context_relay_core::vault::LATEST_SCHEMA_VERSION
    );
    assert!(vault.device_revocation_intent_ids(None).unwrap().is_empty());
}
