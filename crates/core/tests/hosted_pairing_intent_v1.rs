mod support;

use context_relay_core::vault::{HostedPairingIntent, HostedPairingRole, Vault};
use support::{MemoryKeyStore, TempVault};

#[test]
fn request_review_is_immutable_validated_and_retains_provider_time_after_reopen() {
    use context_relay_core::{devices::transport::StoredPairingRequest, sync::SyncScope};
    use context_relay_protocol::decode_pairing_request_v1;
    let canonical: Vec<u8> = include_str!("fixtures/hosted-pairing-request-v1.hex")
        .trim()
        .as_bytes()
        .chunks_exact(2)
        .map(|bytes| u8::from_str_radix(std::str::from_utf8(bytes).unwrap(), 16).unwrap())
        .collect();
    let request = decode_pairing_request_v1(&canonical).unwrap();
    let signed = context_relay_core::devices::crypto::verify_pairing_request(&request).unwrap();
    let original = StoredPairingRequest {
        pairing_id: request.pairing_id,
        scope: SyncScope {
            account_id: "018f22e2-79b0-7cc8-98c4-dc0c0c074001".parse().unwrap(),
            workspace_id: "018f22e2-79b0-7cc8-98c4-dc0c0c074002".parse().unwrap(),
        },
        canonical_bytes: canonical,
        request_digest: signed.digest(),
        requested_at_ms: 1234,
    };
    let path = TempVault::new("pairing-request-review");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), "review", &keys).unwrap();
    vault.store_pairing_request_review(&original).unwrap();
    drop(vault);
    let mut vault = Vault::open(path.path(), "review", &keys).unwrap();
    assert_eq!(
        vault.pairing_request_review(original.pairing_id).unwrap(),
        Some(original.clone())
    );
    vault.store_pairing_request_review(&original).unwrap();
    let mut changed = original.clone();
    changed.requested_at_ms += 1;
    assert!(vault.store_pairing_request_review(&changed).is_err());
    changed = original.clone();
    changed.scope.workspace_id = "018f22e2-79b0-7cc8-98c4-dc0c0c074099".parse().unwrap();
    assert!(vault.store_pairing_request_review(&changed).is_err());
    changed = original.clone();
    changed.request_digest.0[0] ^= 1;
    assert!(vault.store_pairing_request_review(&changed).is_err());
    changed = original.clone();
    changed.requested_at_ms = u64::MAX;
    assert!(vault.store_pairing_request_review(&changed).is_err());
    assert_eq!(
        vault.pairing_request_review(original.pairing_id).unwrap(),
        Some(original.clone())
    );
    let intent = HostedPairingIntent {
        project_url: "https://example.supabase.co/".into(),
        user_id: "550e8400-e29b-41d4-a716-446655440000".parse().unwrap(),
        session_id: "550e8400-e29b-41d4-a716-446655440001".parse().unwrap(),
        role: HostedPairingRole::Approve,
    };
    assert!(
        vault
            .store_hosted_pairing_intent(original.pairing_id, &intent)
            .is_err()
    );
    drop(vault);
    let raw = rusqlite::Connection::open(path.path()).unwrap();
    let key = keys.key("review");
    // SAFETY: first SQLite operation; the key remains live for the call.
    assert_eq!(
        unsafe { rusqlite::ffi::sqlite3_key(raw.handle(), key.as_ptr().cast(), 32) },
        rusqlite::ffi::SQLITE_OK
    );
    raw.execute(
        "UPDATE pairing_request_reviews SET request_digest=zeroblob(32)",
        [],
    )
    .unwrap();
    drop(raw);
    let vault = Vault::open(path.path(), "review", &keys).unwrap();
    assert!(vault.pairing_request_review(original.pairing_id).is_err());
}

#[test]
fn coordinator_binds_before_submission_and_rejects_changed_or_missing_hosted_identity() {
    use context_relay_core::{
        crypto::DeviceKeys,
        devices::{
            memory_transport::InMemoryPairingProvider,
            pairing::{PairingClock, PairingCoordinator, VaultPairingMaterialSource},
            transport::{
                PairingJoinTransport, PairingRequestReceipt, PairingResult, PairingTransportError,
            },
        },
    };
    use context_relay_protocol::{NativePlatform, PairingCode, PairingId, Sha256Digest};
    use sha2::{Digest, Sha256};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    struct Clock;
    impl PairingClock for Clock {
        fn now_ms(&self) -> u64 {
            1000
        }
    }
    struct Join {
        id: PairingId,
        intent: Option<HostedPairingIntent>,
        calls: Arc<AtomicUsize>,
    }
    impl PairingJoinTransport for Join {
        fn hosted_intent(&self) -> Option<HostedPairingIntent> {
            self.intent.clone()
        }
        fn resolve_code(
            &self,
            _: &PairingCode,
            _: u64,
        ) -> Result<PairingId, PairingTransportError> {
            Ok(self.id)
        }
        fn submit_request(
            &self,
            id: PairingId,
            bytes: &[u8],
            _: u64,
        ) -> Result<PairingRequestReceipt, PairingTransportError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(PairingRequestReceipt {
                pairing_id: id,
                request_digest: Sha256Digest(Sha256::digest(bytes).into()),
                requested_at_ms: 1,
            })
        }
        fn result(
            &self,
            _: PairingId,
            _: Sha256Digest,
            _: u64,
        ) -> Result<PairingResult, PairingTransportError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(PairingResult::Pending)
        }
    }
    let path = TempVault::new("pairing-coordinator-identity");
    let store = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), "pairing-intent", &store).unwrap();
    let id = "018f22e2-79b0-7cc8-98c4-dc0c0c073991".parse().unwrap();
    let device = "018f22e2-79b0-7cc8-98c4-dc0c0c073992".parse().unwrap();
    let intent = HostedPairingIntent {
        project_url: "https://example.supabase.co/".into(),
        user_id: "550e8400-e29b-41d4-a716-446655440000".parse().unwrap(),
        session_id: "550e8400-e29b-41d4-a716-446655440001".parse().unwrap(),
        role: HostedPairingRole::Join,
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let provider = InMemoryPairingProvider::new().unwrap();
    let scope = context_relay_core::sync::SyncScope {
        account_id: "018f22e2-79b0-7cc8-98c4-dc0c0c07398f".parse().unwrap(),
        workspace_id: "018f22e2-79b0-7cc8-98c4-dc0c0c07398e".parse().unwrap(),
    };
    let make = |intent| {
        PairingCoordinator::new(
            Clock,
            VaultPairingMaterialSource,
            Join {
                id,
                intent,
                calls: calls.clone(),
            },
            provider.existing_device_client(scope, device),
        )
    };
    let keys = DeviceKeys::from_seeds_for_test([0x71; 32], [0x72; 32]);
    let code = PairingCode::new("ABCDE-FGHJK".into()).unwrap();
    let original = make(Some(intent.clone()));
    original
        .join(
            &mut vault,
            &code,
            device,
            "Joiner",
            NativePlatform::Windows,
            &keys,
        )
        .unwrap();
    assert_eq!(
        vault.hosted_pairing_intent(id).unwrap(),
        Some(intent.clone())
    );
    let bytes = vault
        .stored_pairing_join(id)
        .unwrap()
        .unwrap()
        .canonical_request;
    drop(vault);
    let mut vault = Vault::open(path.path(), "pairing-intent", &store).unwrap();
    original
        .join(
            &mut vault,
            &code,
            device,
            "Joiner",
            NativePlatform::Windows,
            &keys,
        )
        .unwrap();
    assert_eq!(
        vault
            .stored_pairing_join(id)
            .unwrap()
            .unwrap()
            .canonical_request,
        bytes
    );
    for changed in [
        None,
        Some(HostedPairingIntent {
            session_id: intent.user_id,
            ..intent.clone()
        }),
        Some(HostedPairingIntent {
            user_id: intent.session_id,
            ..intent.clone()
        }),
        Some(HostedPairingIntent {
            project_url: "https://other.supabase.co/".into(),
            ..intent.clone()
        }),
        Some(HostedPairingIntent {
            role: HostedPairingRole::Approve,
            ..intent
        }),
    ] {
        let changed = make(changed);
        assert!(
            changed
                .join(
                    &mut vault,
                    &code,
                    device,
                    "Joiner",
                    NativePlatform::Windows,
                    &keys
                )
                .is_err()
        );
        assert!(changed.join_status(&mut vault, id).is_err());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn schema_31_and_32_upgrades_create_empty_pairing_metadata() {
    for version in [31, 32] {
        let path = TempVault::new("hosted-pairing-schema31");
        let keys = MemoryKeyStore::default();
        drop(Vault::open(path.path(), "pairing-intent", &keys).unwrap());
        let raw = rusqlite::Connection::open(path.path()).unwrap();
        let key = keys.key("pairing-intent");
        // SAFETY: first SQLite operation; the key remains live for the call.
        let result = unsafe { rusqlite::ffi::sqlite3_key(raw.handle(), key.as_ptr().cast(), 32) };
        assert_eq!(result, rusqlite::ffi::SQLITE_OK);
        raw.execute_batch(
            "DROP TABLE IF EXISTS revocation_control_history; DROP TABLE IF EXISTS device_revocation_intents; DROP TABLE IF EXISTS candidate_aliases; DROP TABLE account_lifecycle_intents; DROP TABLE pairing_request_reviews;",
        )
        .unwrap();
        if version == 31 {
            raw.execute_batch("DROP TABLE hosted_pairing_intents;")
                .unwrap();
        }
        raw.pragma_update(None, "user_version", version).unwrap();
        drop(raw);
        let vault = Vault::open(path.path(), "pairing-intent", &keys).unwrap();
        let id = "018f22e2-79b0-7cc8-98c4-dc0c0c073991".parse().unwrap();
        assert!(vault.hosted_pairing_intent(id).unwrap().is_none());
        assert!(vault.pairing_request_review(id).unwrap().is_none());
        assert_eq!(
            vault.schema_version().unwrap(),
            context_relay_core::vault::LATEST_SCHEMA_VERSION
        );
    }
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
