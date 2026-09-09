mod support;
use context_relay_core::vault::{AccountLifecycleIntent, AccountLifecycleIntentAction, Vault};
use support::{MemoryKeyStore, TempVault};

#[test]
fn lifecycle_intent_survives_restart_and_never_rebinds() {
    let path = TempVault::new("lifecycle-intent");
    let keys = MemoryKeyStore::default();
    let original = AccountLifecycleIntent {
        operation_id: "018f22e2-79b0-7cc8-98c4-dc0c0c074001".parse().unwrap(),
        action: AccountLifecycleIntentAction::BeginDeletion,
        project_url: "https://example.supabase.co/".into(),
        user_id: "550e8400-e29b-41d4-a716-446655440000".parse().unwrap(),
        session_id: "550e8400-e29b-41d4-a716-446655440001".parse().unwrap(),
        account_id: "018f22e2-79b0-7cc8-98c4-dc0c0c074002".parse().unwrap(),
        workspace_id: "018f22e2-79b0-7cc8-98c4-dc0c0c074003".parse().unwrap(),
    };
    let mut vault = Vault::open(path.path(), "intent", &keys).unwrap();
    assert!(
        vault
            .account_lifecycle_intent(original.operation_id)
            .unwrap()
            .is_none()
    );
    vault.store_account_lifecycle_intent(&original).unwrap();
    let mut expected = Vec::new();
    for n in (1..=51).rev() {
        let mut intent = original.clone();
        intent.operation_id = format!("018f22e2-79b0-7cc8-98c4-{n:012x}").parse().unwrap();
        vault.store_account_lifecycle_intent(&intent).unwrap();
        expected.push(intent);
    }
    expected.reverse();
    expected.push(original.clone());
    drop(vault);
    let mut vault = Vault::open(path.path(), "intent", &keys).unwrap();
    let first = vault.account_lifecycle_intents(None).unwrap();
    assert_eq!(first, expected[..50]);
    let second = vault
        .account_lifecycle_intents(Some(first.last().unwrap().operation_id))
        .unwrap();
    assert_eq!(second, expected[50..]);
    assert!(
        vault
            .account_lifecycle_intents(Some(second.last().unwrap().operation_id))
            .unwrap()
            .is_empty()
    );
    vault.store_account_lifecycle_intent(&original).unwrap();
    assert_eq!(vault.account_lifecycle_intents(None).unwrap(), first);
    for field in 0..6 {
        let mut changed = original.clone();
        match field {
            0 => changed.action = AccountLifecycleIntentAction::CancelDeletion,
            1 => changed.project_url = "https://other.supabase.co/".into(),
            2 => changed.user_id = original.session_id,
            3 => changed.session_id = original.user_id,
            4 => changed.account_id = "018f22e2-79b0-7cc8-98c4-dc0c0c074099".parse().unwrap(),
            _ => changed.workspace_id = "018f22e2-79b0-7cc8-98c4-dc0c0c074099".parse().unwrap(),
        }
        assert!(vault.store_account_lifecycle_intent(&changed).is_err());
    }
    assert_eq!(
        vault
            .account_lifecycle_intent(original.operation_id)
            .unwrap(),
        Some(original.clone())
    );
    let mut invalid = original.clone();
    invalid.operation_id = "018f22e2-79b0-7cc8-98c4-dc0c0c074098".parse().unwrap();
    invalid.project_url = "https://user:secret@example.supabase.co/".into();
    assert!(vault.store_account_lifecycle_intent(&invalid).is_err());
    invalid.project_url = original.project_url.clone();
    invalid.session_id = uuid::Uuid::nil();
    assert!(vault.store_account_lifecycle_intent(&invalid).is_err());
    assert!(
        vault
            .account_lifecycle_intent(invalid.operation_id)
            .unwrap()
            .is_none()
    );
    drop(vault);
    let raw = rusqlite::Connection::open(path.path()).unwrap();
    let key = keys.key("intent");
    // SAFETY: keying is the first SQLite operation and the key lives through the call.
    assert_eq!(
        unsafe { rusqlite::ffi::sqlite3_key(raw.handle(), key.as_ptr().cast(), 32) },
        rusqlite::ffi::SQLITE_OK
    );
    let mut corrupt = serde_json::to_value(&original).unwrap();
    corrupt["operationId"] = serde_json::json!(invalid.operation_id);
    raw.execute(
        "UPDATE account_lifecycle_intents SET payload=?1",
        [serde_json::to_vec(&corrupt).unwrap()],
    )
    .unwrap();
    drop(raw);
    let vault = Vault::open(path.path(), "intent", &keys).unwrap();
    assert!(vault.account_lifecycle_intents(None).is_err());
    assert!(
        vault
            .account_lifecycle_intent(original.operation_id)
            .is_err()
    );
}

#[test]
fn schema_33_upgrade_never_invents_lifecycle_authority() {
    let path = TempVault::new("lifecycle-intent-migration");
    let keys = MemoryKeyStore::default();
    drop(Vault::open(path.path(), "migration", &keys).unwrap());
    let raw = rusqlite::Connection::open(path.path()).unwrap();
    let key = keys.key("migration");
    // SAFETY: keying is the first SQLite operation and the key lives through the call.
    assert_eq!(
        unsafe { rusqlite::ffi::sqlite3_key(raw.handle(), key.as_ptr().cast(), 32) },
        rusqlite::ffi::SQLITE_OK
    );
    raw.execute_batch("DROP TABLE account_lifecycle_intents; PRAGMA user_version=33;")
        .unwrap();
    drop(raw);
    let vault = Vault::open(path.path(), "migration", &keys).unwrap();
    assert_eq!(
        vault.schema_version().unwrap(),
        context_relay_core::vault::LATEST_SCHEMA_VERSION
    );
    assert!(
        vault
            .account_lifecycle_intent("018f22e2-79b0-7cc8-98c4-dc0c0c074001".parse().unwrap())
            .unwrap()
            .is_none()
    );
}
