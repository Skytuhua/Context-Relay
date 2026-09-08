mod support;

use context_relay_core::vault::{HostedPairingIntent, HostedPairingRole, Vault};
use support::{MemoryKeyStore, TempVault};

#[test]
fn schema_31_upgrade_creates_an_empty_identity_table() {
    let path = TempVault::new("hosted-pairing-schema31");
    let keys = MemoryKeyStore::default();
    drop(Vault::open(path.path(), "pairing-intent", &keys).unwrap());
    let raw = rusqlite::Connection::open(path.path()).unwrap();
    let key = keys.key("pairing-intent");
    // SAFETY: first SQLite operation; the key remains live for the call.
    let result = unsafe { rusqlite::ffi::sqlite3_key(raw.handle(), key.as_ptr().cast(), 32) };
    assert_eq!(result, rusqlite::ffi::SQLITE_OK);
    raw.execute_batch("DROP TABLE hosted_pairing_intents; PRAGMA user_version=31;")
        .unwrap();
    drop(raw);
    let vault = Vault::open(path.path(), "pairing-intent", &keys).unwrap();
    let id = "018f22e2-79b0-7cc8-98c4-dc0c0c073991".parse().unwrap();
    assert!(vault.hosted_pairing_intent(id).unwrap().is_none());
}

#[test]
fn pairing_identity_survives_restart_and_rejects_replacement_or_legacy_adoption() {
    let path = TempVault::new("hosted-pairing-intent");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), "pairing-intent", &keys).unwrap();
    let pairing = "018f22e2-79b0-7cc8-98c4-dc0c0c073991".parse().unwrap();
    let intent = HostedPairingIntent {
        project_url: "https://example.supabase.co/".into(),
        user_id: "550e8400-e29b-41d4-a716-446655440000".parse().unwrap(),
        session_id: "550e8400-e29b-41d4-a716-446655440001".parse().unwrap(),
        role: HostedPairingRole::Join,
    };
    vault.store_hosted_pairing_intent(pairing, &intent).unwrap();
    drop(vault);
    let mut vault = Vault::open(path.path(), "pairing-intent", &keys).unwrap();
    assert_eq!(
        vault.hosted_pairing_intent(pairing).unwrap(),
        Some(intent.clone())
    );
    vault.store_hosted_pairing_intent(pairing, &intent).unwrap();
    for changed in [
        HostedPairingIntent {
            session_id: intent.user_id,
            ..intent.clone()
        },
        HostedPairingIntent {
            user_id: intent.session_id,
            ..intent.clone()
        },
        HostedPairingIntent {
            project_url: "https://other.supabase.co/".into(),
            ..intent.clone()
        },
        HostedPairingIntent {
            role: HostedPairingRole::Approve,
            ..intent.clone()
        },
    ] {
        assert!(
            vault
                .store_hosted_pairing_intent(pairing, &changed)
                .is_err()
        );
    }
    let canonical = include_str!("fixtures/hosted-pairing-request-v1.hex").trim();
    let canonical: Vec<u8> = canonical
        .as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect();
    let request = context_relay_protocol::decode_pairing_request_v1(&canonical).unwrap();
    assert_ne!(request.pairing_id, pairing);
    vault
        .store_pairing_join_request(request.pairing_id, &canonical, 1000)
        .unwrap();
    assert!(
        vault
            .store_hosted_pairing_intent(request.pairing_id, &intent)
            .is_err()
    );
    let invalid = HostedPairingIntent {
        user_id: uuid::Uuid::nil(),
        ..intent
    };
    assert!(
        vault
            .store_hosted_pairing_intent(pairing, &invalid)
            .is_err()
    );
}
