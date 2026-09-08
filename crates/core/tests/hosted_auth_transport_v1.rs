#![cfg(feature = "test-support")]

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use context_relay_core::{
    auth::{
        HostedSessionOwner, LoginError, LoginStore, PendingLogin, StoredLogin, SupabaseAuthClient,
    },
    sync::{SupabaseHttpClient, SupabaseHttpError, SupabaseHttpRequest, SupabaseHttpResponse},
};
use serde_json::json;
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Instant,
};

const PROJECT: &str = "https://example.supabase.co";
const USER: &str = "550e8400-e29b-41d4-a716-446655440000";
const SESSION: &str = "550e8400-e29b-41d4-a716-446655440001";
const NOW: u64 = 1_800_000_000;

#[test]
fn hosted_pairing_join_checks_wire_receipts_proofs_and_logout() {
    use context_relay_core::{
        crypto::DeviceKeys,
        devices::{
            supabase_pairing::HostedPairingClient,
            transport::{PairingJoinTransport, PairingTransportError},
        },
    };
    use sha2::{Digest, Sha256};
    let encoded = include_str!("fixtures/hosted-pairing-request-v1.hex").trim();
    let canonical: Vec<u8> = encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect();
    let request = context_relay_protocol::decode_pairing_request_v1(&canonical).unwrap();
    let digest = context_relay_protocol::Sha256Digest(Sha256::digest(&canonical).into());
    let receipt =
        json!({"pairingId":request.pairing_id,"requestDigest":digest,"requestedAt":"1000"});
    let (auth, http) = client(
        PROJECT,
        vec![
            tokens(&token(NOW + 900)),
            response(200, json!({"id":USER})),
            response(
                200,
                json!({"v":1,"result":{"status":"located","pairingId":request.pairing_id}}),
            ),
            response(200, json!({"v":1,"receipt":receipt})),
            response(
                200,
                json!({"v":1,"result":{"status":"pending","extra":true}}),
            ),
            response(200, json!({"v":1,"result":{"status":"exhausted"}})),
            SupabaseHttpResponse::new(204, vec![]),
        ],
    );
    let owner = Arc::new(HostedSessionOwner::new(
        Arc::new(auth),
        Arc::new(Store::default()),
    ));
    let attempt = owner.begin_login().unwrap();
    let generation = attempt.cancellation();
    let identity = owner.complete_login(attempt, exchange(), NOW).unwrap();
    let transport = HostedPairingClient::with_http_client(
        owner.clone(),
        identity,
        generation,
        PROJECT,
        "public-test",
        Arc::new(DeviceKeys::from_seeds_for_test([0x71; 32], [0x72; 32])),
        http.clone(),
    )
    .unwrap();
    let code = context_relay_protocol::PairingCode::new("ABCDE-FGHJK".into()).unwrap();
    assert_eq!(
        transport.resolve_code(&code, NOW * 1000).unwrap(),
        request.pairing_id
    );
    assert_eq!(
        transport
            .submit_request(request.pairing_id, &canonical, NOW * 1000)
            .unwrap()
            .requested_at_ms,
        1000
    );
    let requests = http.requests.lock().unwrap();
    let sent: serde_json::Value = serde_json::from_slice(requests.last().unwrap().body()).unwrap();
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/hosted-pairing-approval-v1.json")).unwrap();
    assert_eq!(sent["proof"], fixture["proofs"]["request"]);
    assert!(
        requests
            .last()
            .unwrap()
            .url()
            .ends_with("/functions/v1/pairing")
    );
    drop(requests);
    assert_eq!(
        transport
            .result(request.pairing_id, digest, NOW * 1000)
            .unwrap_err(),
        PairingTransportError::Conflict
    );
    assert_eq!(
        transport.resolve_code(&code, NOW * 1000).unwrap_err(),
        PairingTransportError::Exhausted
    );
    let approved = fixture["canonicalApprovedPayload"].as_str().unwrap();
    let approved_bytes: Vec<u8> = approved
        .as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect();
    let decision = json!({"pairingId":request.pairing_id,"requestDigest":digest,"decision":"approved",
        "approvedPayloadDigest":format!("{:x}",Sha256::digest(&approved_bytes)),"decidedAt":"2000"});
    for (field, value) in [
        ("requestDigest", json!("00".repeat(32))),
        ("approvedPayloadDigest", json!(null)),
        ("decidedAt", json!("9223372036854775808")),
        ("decision", json!("rejected")),
        ("extra", json!(true)),
    ] {
        let mut bad = decision.clone();
        bad[field] = value;
        http.responses.lock().unwrap().push_front(response(
            200,
            json!({"v":1,"result":{
            "status":"approved","canonicalApprovedPayload":approved,"receipt":bad}}),
        ));
        assert_eq!(
            transport
                .result(request.pairing_id, digest, NOW * 1000)
                .unwrap_err(),
            PairingTransportError::Conflict
        );
    }
    let mut rejected = decision.clone();
    rejected["decision"] = json!("rejected");
    rejected
        .as_object_mut()
        .unwrap()
        .remove("approvedPayloadDigest");
    http.responses.lock().unwrap().push_front(response(
        200,
        json!({"v":1,"result":{"status":"rejected","receipt":rejected}}),
    ));
    assert_eq!(
        transport
            .result(request.pairing_id, digest, NOW * 1000)
            .unwrap_err(),
        PairingTransportError::Conflict
    );
    http.responses.lock().unwrap().push_front(response(
        200,
        json!({"v":1,"result":{
        "status":"approved","canonicalApprovedPayload":approved,"receipt":decision}}),
    ));
    assert!(matches!(
        transport
            .result(request.pairing_id, digest, NOW * 1000)
            .unwrap(),
        context_relay_core::devices::transport::PairingResult::Approved(_)
    ));
    owner.logout().unwrap();
    assert_eq!(
        transport.resolve_code(&code, NOW * 1000).unwrap_err(),
        PairingTransportError::Unauthorized
    );
}

#[derive(Default)]
struct Store {
    save_gate: Mutex<Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>>,
    saved: Mutex<Option<StoredLogin>>,
    fail_save: std::sync::atomic::AtomicBool,
    fail_load: std::sync::atomic::AtomicBool,
    fail_clear: std::sync::atomic::AtomicBool,
}
impl LoginStore for Store {
    fn load(&self) -> Result<Option<StoredLogin>, LoginError> {
        if self.fail_load.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(LoginError::CredentialStore);
        }
        Ok(self.saved.lock().unwrap().clone())
    }
    fn save(&self, login: &StoredLogin) -> Result<(), LoginError> {
        if let Some((started, release)) = self.save_gate.lock().unwrap().take() {
            started.send(()).unwrap();
            release
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap();
        }
        if self.fail_save.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(LoginError::CredentialStore);
        }
        *self.saved.lock().unwrap() = Some(login.clone());
        Ok(())
    }
    fn clear(&self) -> Result<(), LoginError> {
        if self.fail_clear.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(LoginError::CredentialStore);
        }
        *self.saved.lock().unwrap() = None;
        Ok(())
    }
}

#[test]
fn native_restore_transport_checks_claims_receipts_and_original_session() {
    use context_relay_core::{
        crypto::DeviceKeys,
        devices::{
            recovery::RecoveryEnrollmentClock,
            recovery_crypto::decode_recovery_enrollment_record_v1,
            recovery_restore_crypto::decode_recovery_device_claim_v1,
            recovery_restore_transport::RecoveryRestoreTransport,
            supabase_enrollment::HostedEnrollmentClient,
        },
    };
    use sha2::{Digest, Sha256};
    struct Clock;
    impl RecoveryEnrollmentClock for Clock {
        fn now_ms(&self) -> u64 {
            NOW * 1000
        }
    }
    let decode = |encoded: &str| -> Vec<u8> {
        encoded
            .as_bytes()
            .chunks_exact(2)
            .map(|part| u8::from_str_radix(std::str::from_utf8(part).unwrap(), 16).unwrap())
            .collect()
    };
    let root_hex = include_str!("fixtures/recovery-enrollment-record-v1.hex").trim();
    let claim_hex = include_str!("fixtures/recovery-device-claim-v1.hex").trim();
    let canonical = decode(claim_hex);
    let record = decode_recovery_enrollment_record_v1(&decode(root_hex)).unwrap();
    let claim = decode_recovery_device_claim_v1(&canonical).unwrap();
    let snapshot = json!({"accountId":record.account_id,"workspaceId":record.workspace_id,
        "canonicalRecord":root_hex,"canonicalRecordSha256":format!("{:x}",Sha256::digest(decode(root_hex))),
        "registeredAtMs":(NOW*1000).to_string(),"recoveryGeneration":"0"});
    let receipt = json!({"restoreId":claim.restore_id,"enrollmentId":record.enrollment_id,
        "recoveryRootId":record.recovery_root_id,"accountId":record.account_id,"workspaceId":record.workspace_id,
        "certificateId":claim.certificate_id,"canonicalRecordSha256":snapshot["canonicalRecordSha256"],
        "canonicalClaimSha256":format!("{:x}",Sha256::digest(&canonical)),
        "acceptedGeneration":(claim.expected_recovery_generation+1).to_string(),"acceptedAtMs":(NOW*1000-5000).to_string()});
    let projection = json!({"canonicalClaim":claim_hex,"receipt":receipt});
    let mut responses = vec![
        tokens(&token(NOW + 900)),
        response(200, json!({"id":USER})),
        response(200, json!({"v":1,"snapshot":snapshot})),
        response(200, json!({"v":1,"snapshot":snapshot})),
        response(200, json!({"v":1,"receipt":receipt})),
        response(200, json!({"v":1,"projection":projection})),
        response(200, json!({"v":1,"projection":null})),
    ];
    let mut bad_receipts = Vec::new();
    for (field, value) in [
        ("acceptedGeneration", json!("0")),
        ("acceptedAtMs", json!("9223372036854775808")),
        ("canonicalClaimSha256", json!("00".repeat(32))),
        ("certificateId", json!(record.genesis_certificate_id)),
        ("accountId", json!(record.workspace_id)),
        ("extra", json!(true)),
    ] {
        let mut bad = receipt.clone();
        bad[field] = value;
        bad_receipts.push(bad);
    }
    for bad in &bad_receipts {
        responses.push(response(200, json!({"v":1,"receipt":bad})));
    }
    for bad in &bad_receipts {
        responses.push(response(
            200,
            json!({"v":1,"projection":{"canonicalClaim":claim_hex,"receipt":bad}}),
        ));
    }
    responses.extend([response(200,json!({"v":1})),response(200,json!({"v":2,"projection":null})),
        response(200,json!({"v":1,"projection":{"canonicalClaim":claim_hex.to_uppercase(),"receipt":receipt}})),
        response(200,json!({"v":1,"projection":projection}))]);
    let (auth, http) = client(PROJECT, responses);
    let owner = Arc::new(HostedSessionOwner::new(
        Arc::new(auth),
        Arc::new(Store::default()),
    ));
    let attempt = owner.begin_login().unwrap();
    let generation = attempt.cancellation();
    let identity = owner.complete_login(attempt, exchange(), NOW).unwrap();
    let client = HostedEnrollmentClient::with_http_client(
        owner.clone(),
        identity,
        generation,
        PROJECT,
        "public-test",
        http.clone(),
    )
    .unwrap();
    let initial = client.snapshot(NOW).unwrap().unwrap();
    let original_intent = context_relay_core::vault::HostedRestoreIntent {
        project_url: PROJECT.into(),
        user_id: identity.user_id,
        session_id: identity.session_id,
    };
    for changed in [
        context_relay_core::vault::HostedRestoreIntent {
            project_url: "https://another.supabase.co".into(),
            ..original_intent.clone()
        },
        context_relay_core::vault::HostedRestoreIntent {
            user_id: identity.session_id,
            ..original_intent.clone()
        },
        context_relay_core::vault::HostedRestoreIntent {
            session_id: identity.user_id,
            ..original_intent.clone()
        },
    ] {
        let bound = HostedEnrollmentClient::with_http_client(
            owner.clone(),
            identity,
            owner.cancellation().unwrap(),
            PROJECT,
            "public-test",
            http.clone(),
        )
        .unwrap();
        assert!(
            bound
                .into_restore_transport(
                    &changed,
                    initial.clone(),
                    Arc::new(DeviceKeys::from_seeds_for_test([0x66; 32], [0x77; 32])),
                    Clock
                )
                .is_err()
        );
    }
    let transport = client
        .into_restore_transport(
            &context_relay_core::vault::HostedRestoreIntent {
                project_url: PROJECT.into(),
                user_id: identity.user_id,
                session_id: identity.session_id,
            },
            initial.clone(),
            Arc::new(DeviceKeys::from_seeds_for_test([0x66; 32], [0x77; 32])),
            Clock,
        )
        .unwrap();
    assert_eq!(transport.root_snapshot().unwrap(), Some(initial));
    let accepted = transport.submit_restore(&canonical, NOW * 1000).unwrap();
    let proof: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/hosted-recovery-proof-v1.json")).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(
            http.requests.lock().unwrap().last().unwrap().body()
        )
        .unwrap(),
        json!({"v":1,"action":"restore","claim":claim_hex,"proof":proof["signature"]})
    );
    assert_eq!(
        transport
            .restore_claim(claim.restore_id)
            .unwrap()
            .unwrap()
            .receipt,
        accepted
    );
    assert!(transport.restore_claim(claim.restore_id).unwrap().is_none());
    for _ in &bad_receipts {
        assert!(transport.submit_restore(&canonical, NOW * 1000).is_err());
    }
    for _ in 0..bad_receipts.len() + 3 {
        assert!(transport.restore_claim(claim.restore_id).is_err());
    }
    assert!(
        transport
            .restore_claim("018f22e2-79b0-7cc8-98c4-dc0c0c073999".parse().unwrap())
            .is_err()
    );
    let count = http.requests.lock().unwrap().len();
    let mut corrupt = canonical.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(transport.submit_restore(&corrupt, NOW * 1000).is_err());
    owner.begin_login().unwrap();
    assert!(transport.submit_restore(&canonical, NOW * 1000).is_err());
    assert!(transport.restore_claim(claim.restore_id).is_err());
    assert!(transport.root_snapshot().is_err());
    assert_eq!(http.requests.lock().unwrap().len(), count);

    use context_relay_core::{
        devices::{
            recovery::OsRecoveryEnrollmentEntropy,
            recovery_restore::{
                RecoveryRestoreCoordinator, RecoveryRestoreIdentity, RecoveryRestoreOutcome,
            },
            recovery_restore_crypto::RecoveryDeviceClaimArtifacts,
        },
        vault::{RecoveryRestoreWrite, Vault},
    };
    use std::sync::atomic::{AtomicU64, Ordering};
    #[derive(Clone)]
    struct AdvancingClock(Arc<AtomicU64>);
    impl RecoveryEnrollmentClock for AdvancingClock {
        fn now_ms(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }
    struct DelayedHttp {
        http: Arc<Http>,
        clock: AdvancingClock,
    }
    impl SupabaseHttpClient for DelayedHttp {
        fn execute(
            &self,
            request: SupabaseHttpRequest,
        ) -> Result<SupabaseHttpResponse, SupabaseHttpError> {
            let result = self.http.execute(request);
            self.clock.0.fetch_add(1000, Ordering::SeqCst);
            result
        }
    }
    for server_ms in [NOW * 1000 - 5000, NOW * 1000 + 5000] {
        let mut receipt = receipt.clone();
        receipt["acceptedAtMs"] = json!(server_ms.to_string());
        let (auth, http) = self::client(
            PROJECT,
            vec![
                tokens(&token(NOW + 900)),
                response(200, json!({"id":USER})),
                response(200, json!({"v":1,"snapshot":snapshot})),
                response(200, json!({"v":1,"receipt":receipt})),
                response(
                    200,
                    json!({"v":1,"projection":{"canonicalClaim":claim_hex,"receipt":receipt}}),
                ),
            ],
        );
        let owner = Arc::new(HostedSessionOwner::new(
            Arc::new(auth),
            Arc::new(Store::default()),
        ));
        let attempt = owner.begin_login().unwrap();
        let generation = attempt.cancellation();
        let identity = owner.complete_login(attempt, exchange(), NOW).unwrap();
        let clock = AdvancingClock(Arc::new(AtomicU64::new(NOW * 1000)));
        let client = HostedEnrollmentClient::with_http_client(
            owner,
            identity,
            generation,
            PROJECT,
            "public-test",
            Arc::new(DelayedHttp {
                http,
                clock: clock.clone(),
            }),
        )
        .unwrap();
        let mut initial = client.snapshot(NOW).unwrap().unwrap();
        initial.recovery_generation = claim.expected_recovery_generation;
        let device = Arc::new(DeviceKeys::from_seeds_for_test([0x66; 32], [0x77; 32]));
        let write = RecoveryRestoreWrite::new(
            initial.clone(),
            RecoveryDeviceClaimArtifacts {
                claim: claim.clone(),
                canonical_claim: canonical.clone(),
                canonical_claim_sha256: context_relay_protocol::Sha256Digest(
                    Sha256::digest(&canonical).into(),
                ),
            },
            clock.now_ms(),
        )
        .unwrap();
        let path = support::TempVault::new("native-restore-clock");
        let keys = support::MemoryKeyStore::default();
        let mut vault = Vault::open(path.path(), "native-restore-clock", &keys).unwrap();
        let intent = context_relay_core::vault::HostedRestoreIntent {
            project_url: PROJECT.into(),
            user_id: identity.user_id,
            session_id: identity.session_id,
        };
        vault.store_hosted_restore_intent(&intent).unwrap();
        vault.prepare_recovery_restore(&write).unwrap();
        drop(vault);
        let mut vault = Vault::open(path.path(), "native-restore-clock", &keys).unwrap();
        let transport = client
            .into_restore_transport(
                &vault.hosted_restore_intent().unwrap().unwrap(),
                initial,
                device.clone(),
                clock.clone(),
            )
            .unwrap();
        let coordinator = RecoveryRestoreCoordinator::new_for_test(
            clock.clone(),
            OsRecoveryEnrollmentEntropy,
            transport,
        );
        let identity = RecoveryRestoreIdentity {
            device_id: claim.certificate.device_id,
            device_name: claim.device_name.clone(),
            platform: claim.device_platform,
            keys: &device,
        };
        assert!(matches!(
            coordinator.resume_prepared(&mut vault, &identity).unwrap(),
            RecoveryRestoreOutcome::Complete { .. }
        ));
        drop(vault);
        let vault = Vault::open(path.path(), "native-restore-clock", &keys).unwrap();
        let stored = vault.recovery_restore().unwrap().unwrap();
        assert_eq!(stored.provider_accepted_at_ms, Some(server_ms));
        assert_eq!(stored.completed_at_ms, Some(NOW * 1000 + 3000));
        vault.recovered_workspace_material(&device).unwrap();
    }
}

#[test]
fn native_recovery_snapshot_validates_bytes_and_preserves_session_identity() {
    use context_relay_core::devices::supabase_enrollment::HostedEnrollmentClient;
    use sha2::{Digest, Sha256};
    let encoded = include_str!("fixtures/recovery-enrollment-record-v1.hex").trim();
    let canonical: Vec<u8> = encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|part| u8::from_str_radix(std::str::from_utf8(part).unwrap(), 16).unwrap())
        .collect();
    let record =
        context_relay_core::devices::recovery_crypto::decode_recovery_enrollment_record_v1(
            &canonical,
        )
        .unwrap();
    let snapshot = json!({"accountId":record.account_id,"workspaceId":record.workspace_id,
        "canonicalRecord":encoded,"canonicalRecordSha256":format!("{:x}",Sha256::digest(&canonical)),
        "registeredAtMs":(NOW*1000).to_string(),"recoveryGeneration":"0"});
    let mut invalid = Vec::new();
    for (key, value) in [
        ("canonicalRecordSha256", json!("00".repeat(32))),
        ("accountId", json!(record.workspace_id)),
        ("canonicalRecord", json!(encoded.to_uppercase())),
        ("canonicalRecord", json!("0")),
        ("canonicalRecord", json!("00".repeat(32769))),
        ("recoveryGeneration", json!("9223372036854775808")),
        ("registeredAtMs", json!("9223372036854775808")),
        ("extra", json!(true)),
    ] {
        let mut changed = snapshot.clone();
        changed[key] = value;
        invalid.push(response(200, json!({"v":1,"snapshot":changed})));
    }
    invalid.push(response(200, json!({"v":1})));
    invalid.push(response(200, json!({"v":2,"snapshot":null})));
    invalid.push(response(200, json!({"v":1,"snapshot":null,"extra":true})));
    let mut bad_signature = canonical.clone();
    *bad_signature.last_mut().unwrap() ^= 1;
    let mut forged = snapshot.clone();
    forged["canonicalRecord"] = json!(
        bad_signature
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    forged["canonicalRecordSha256"] = json!(format!("{:x}", Sha256::digest(&bad_signature)));
    invalid.push(response(200, json!({"v":1,"snapshot":forged})));
    let invalid_count = invalid.len();
    let mut responses = vec![
        tokens(&token(NOW + 900)),
        response(200, json!({"id":USER})),
        response(200, json!({"v":1,"snapshot":snapshot})),
        response(200, json!({"v":1,"snapshot":null})),
    ];
    responses.extend(invalid);
    let (auth, http) = client(PROJECT, responses);
    let owner = Arc::new(HostedSessionOwner::new(
        Arc::new(auth),
        Arc::new(Store::default()),
    ));
    let attempt = owner.begin_login().unwrap();
    let generation = attempt.cancellation();
    let identity = owner.complete_login(attempt, exchange(), NOW).unwrap();
    let client = HostedEnrollmentClient::with_http_client(
        owner.clone(),
        identity,
        generation,
        PROJECT,
        "publishable-test",
        http.clone(),
    )
    .unwrap();
    let result = client.snapshot(NOW).unwrap().unwrap();
    assert_eq!(result.canonical_record, canonical);
    assert_eq!(result.scope.account_id, record.account_id);
    assert_eq!(result.recovery_generation, 0);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(
            http.requests.lock().unwrap().last().unwrap().body()
        )
        .unwrap(),
        json!({"v":1,"action":"snapshot"})
    );
    assert!(client.snapshot(NOW).unwrap().is_none());
    for _ in 0..invalid_count {
        assert!(client.snapshot(NOW).is_err());
    }
    let count = http.requests.lock().unwrap().len();
    owner.begin_login().unwrap();
    assert!(client.snapshot(NOW).is_err());
    assert_eq!(http.requests.lock().unwrap().len(), count);
}

#[test]
fn native_enrollment_status_and_commit_validate_the_record_receipt() {
    use context_relay_core::{
        crypto::DeviceKeys,
        devices::{
            recovery_crypto::decode_recovery_enrollment_record_v1,
            supabase_enrollment::{HostedEnrollmentClient, HostedEnrollmentReservation},
        },
    };
    use sha2::{Digest, Sha256};
    let encoded = include_str!("fixtures/recovery-enrollment-record-v1.hex").trim();
    let canonical: Vec<u8> = encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|part| u8::from_str_radix(std::str::from_utf8(part).unwrap(), 16).unwrap())
        .collect();
    let record = decode_recovery_enrollment_record_v1(&canonical).unwrap();
    let reservation = json!({"reservationId":"018f22e2-79b0-7cc8-98c4-dc0c0c073901",
        "accountId":record.account_id,"workspaceId":record.workspace_id,"nonce":"42".repeat(32),
        "expiresAt":((NOW+600)*1000).to_string()});
    let mut status = reservation.clone();
    status["receipt"] = serde_json::Value::Null;
    let receipt = json!({"enrollmentId":record.enrollment_id,"recoveryRootId":record.recovery_root_id,
        "accountId":record.account_id,"workspaceId":record.workspace_id,"genesisCertificateId":record.genesis_certificate_id,
        "canonicalRecordSha256":format!("{:x}",Sha256::digest(&canonical)),"registeredAtMs":(NOW*1000).to_string()});
    let mut forged = receipt.clone();
    forged["canonicalRecordSha256"] = json!("00".repeat(32));
    let (client, http) = client(
        PROJECT,
        vec![
            tokens(&token(NOW + 900)),
            response(200, json!({"id":USER})),
            response(200, json!({"v":1,"reservation":status})),
            response(200, json!({"v":1,"receipt":receipt})),
            response(200, json!({"v":1,"receipt":forged})),
            response(
                200,
                json!({"v":1,"reservation":{
                    "receipt":receipt,
                    "reservationId":reservation["reservationId"],
                    "accountId":reservation["accountId"],
                    "workspaceId":reservation["workspaceId"],
                    "nonce":reservation["nonce"],"expiresAt":reservation["expiresAt"]
                }}),
            ),
            response(200, json!({"v":1,"receipt":receipt})),
        ],
    );
    let owner = Arc::new(HostedSessionOwner::new(
        Arc::new(client),
        Arc::new(Store::default()),
    ));
    let attempt = owner.begin_login().unwrap();
    let generation = attempt.cancellation();
    let identity = owner.complete_login(attempt, exchange(), NOW).unwrap();
    let transport = HostedEnrollmentClient::with_http_client(
        owner.clone(),
        identity,
        generation.clone(),
        PROJECT,
        "public-test",
        http.clone(),
    )
    .unwrap();
    let reservation: HostedEnrollmentReservation = serde_json::from_value(reservation).unwrap();
    assert!(transport.status(&reservation, NOW).unwrap().is_none());
    let device = DeviceKeys::from_seeds_for_test([0x11; 32], [0x22; 32]);
    let accepted = transport
        .commit(&reservation, &canonical, &device, NOW)
        .unwrap();
    assert_eq!(accepted.enrollment_id, record.enrollment_id);
    let requests = http.requests.lock().unwrap();
    let body: serde_json::Value = serde_json::from_slice(requests.last().unwrap().body()).unwrap();
    assert_eq!(body["record"], encoded);
    assert_eq!(body["action"], "commit");
    let proof = body["proof"].as_str().unwrap();
    assert_eq!(proof.len(), 128);
    let signature = context_relay_protocol::Ed25519SignatureBytes(
        proof
            .as_bytes()
            .chunks_exact(2)
            .map(|part| u8::from_str_radix(std::str::from_utf8(part).unwrap(), 16).unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
    );
    let preimage = context_relay_core::devices::recovery_crypto::hosted_enrollment_proof_preimage(
        &context_relay_core::devices::recovery_crypto::HostedEnrollmentChallenge {
            reservation_id: reservation.reservation_id,
            auth_user_id: identity.user_id,
            session_id: identity.session_id,
            nonce: reservation.nonce.0,
        },
        &record,
    )
    .unwrap();
    context_relay_core::crypto::verify_signature(device.signing_public_key(), &preimage, signature)
        .unwrap();
    drop(requests);
    assert!(
        transport
            .commit(&reservation, &canonical, &device, NOW)
            .is_err()
    );
    use context_relay_core::{
        devices::{
            recovery::RecoveryEnrollmentClock, recovery_transport::RecoveryEnrollmentTransport,
        },
        vault::HostedEnrollmentIntent,
    };
    struct Clock;
    impl RecoveryEnrollmentClock for Clock {
        fn now_ms(&self) -> u64 {
            NOW * 1000
        }
    }
    let intent = HostedEnrollmentIntent {
        project_url: PROJECT.into(),
        user_id: identity.user_id,
        session_id: identity.session_id,
        operation_id: reservation.reservation_id,
        reservation: Some(reservation),
    };
    let device = Arc::new(device);
    for wrong_project in [false, true] {
        let mut wrong = intent.clone();
        if wrong_project {
            wrong.project_url = "https://other.supabase.co".into();
        } else {
            wrong.session_id = "550e8400-e29b-41d4-a716-446655440009".parse().unwrap();
        }
        let client = HostedEnrollmentClient::with_http_client(
            owner.clone(),
            identity,
            generation.clone(),
            PROJECT,
            "public-test",
            http.clone(),
        )
        .unwrap();
        assert!(matches!(client.into_transport(&wrong, device.clone(), Clock), Err(context_relay_core::devices::recovery_transport::RecoveryTransportError::Unauthorized)));
    }
    let adapter = transport.into_transport(&intent, device, Clock).unwrap();
    let status = adapter.root_status().unwrap().unwrap();
    status
        .validate_for(
            adapter.scope(),
            &record,
            accepted.canonical_record_sha256,
            accepted.registered_at_ms,
        )
        .unwrap();
    assert_eq!(adapter.register(&canonical, NOW * 1000).unwrap(), accepted);
    let request_count = http.requests.lock().unwrap().len();
    let _replacement = owner.begin_login().unwrap();
    assert!(matches!(
        adapter.root_status(),
        Err(context_relay_core::devices::recovery_transport::RecoveryTransportError::Unauthorized)
    ));
    assert_eq!(http.requests.lock().unwrap().len(), request_count);
}

#[test]
fn enrollment_reservation_uses_original_session_and_rejects_later_login() {
    use context_relay_core::devices::supabase_enrollment::HostedEnrollmentClient;
    let operation = "018f22e2-79b0-7cc8-98c4-dc0c0c073901";
    let (client, http) = client(
        PROJECT,
        vec![
            tokens(&token(NOW + 900)),
            response(200, json!({"id":USER})),
            response(
                200,
                json!({"v":1,"reservation":{
            "reservationId":operation,"accountId":"018f22e2-79b0-7cc8-98c4-dc0c0c073902",
            "workspaceId":"018f22e2-79b0-7cc8-98c4-dc0c0c073903","nonce":"42".repeat(32),
            "expiresAt":((NOW+605)*1000).to_string()}}),
            ),
            response(403, json!({"v":1,"error":"enrollment_reservation_expired"})),
            response(403, json!({"v":1,"error":"enrollment_session_denied"})),
            response(
                403,
                json!({"v":1,"error":"enrollment_reservation_expired","extra":true}),
            ),
        ],
    );
    let owner = Arc::new(HostedSessionOwner::new(
        Arc::new(client),
        Arc::new(Store::default()),
    ));
    let attempt = owner.begin_login().unwrap();
    let generation = attempt.cancellation();
    let identity = owner.complete_login(attempt, exchange(), NOW).unwrap();
    let transport = HostedEnrollmentClient::with_http_client(
        owner.clone(),
        identity,
        generation,
        PROJECT,
        "publishable-test",
        http.clone(),
    )
    .unwrap();
    let id = serde_json::from_value(json!(operation)).unwrap();
    let reserved = transport.reserve(id, NOW).unwrap();
    assert_eq!(reserved.reservation_id, id);
    // A server clock five seconds ahead still issues a valid ten-minute lease.
    assert_eq!(reserved.expires_at.0, (NOW + 605) * 1000);
    {
        let requests = http.requests.lock().unwrap();
        let request = requests.last().unwrap();
        assert_eq!(
            request.url(),
            "https://example.supabase.co/functions/v1/enrollment"
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(request.body()).unwrap(),
            json!({"v":1,"action":"reserve","reservationId":operation})
        );
        assert_eq!(request.header("apikey"), Some("publishable-test"));
    }
    use context_relay_core::devices::recovery_transport::RecoveryTransportError;
    assert!(matches!(
        transport.reserve(id, NOW),
        Err(RecoveryTransportError::Expired)
    ));
    assert!(matches!(
        transport.reserve(id, NOW),
        Err(RecoveryTransportError::Unauthorized)
    ));
    assert!(matches!(
        transport.reserve(id, NOW),
        Err(RecoveryTransportError::Unauthorized)
    ));
    let count = http.requests.lock().unwrap().len();
    owner.begin_login().unwrap();
    assert!(transport.reserve(id, NOW).is_err());
    assert_eq!(http.requests.lock().unwrap().len(), count);
}

#[test]
fn queued_session_access_keeps_identity_across_refresh_and_rejects_replacement() {
    let (client, _) = client(
        PROJECT,
        vec![
            tokens(&token(NOW + 900)),
            response(200, json!({"id":USER})),
            tokens(&token(NOW + 1200)),
            response(200, json!({"id":USER})),
            tokens(&token(NOW + 1400)),
            response(200, json!({"id":USER})),
        ],
    );
    let owner = HostedSessionOwner::new(Arc::new(client), Arc::new(Store::default()));
    let attempt = owner.begin_login().unwrap();
    let generation = attempt.cancellation();
    let identity = owner.complete_login(attempt, exchange(), NOW).unwrap();
    let original = owner.session_for(&generation, identity, NOW).unwrap();
    owner.refresh(NOW + 1).unwrap();
    let refreshed = owner.session_for(&generation, identity, NOW + 1).unwrap();
    assert_ne!(original.access_token(), refreshed.access_token());
    let mut foreign = identity;
    foreign.session_id = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440002").unwrap();
    assert!(matches!(
        owner.session_for(&generation, foreign, NOW + 1),
        Err(LoginError::Denied)
    ));
    let replacement = owner.begin_login().unwrap();
    owner
        .complete_login(replacement, exchange(), NOW + 2)
        .unwrap();
    // Even a later login with the same claims cannot revive the old generation.
    assert!(matches!(
        owner.session_for(&generation, identity, NOW + 2),
        Err(LoginError::Canceled)
    ));
    let current = owner.cancellation().unwrap();
    current.cancel();
    assert!(owner.session_for(&current, identity, NOW + 2).is_err());
}

#[test]
fn session_owner_persists_before_publication_and_invalidates_old_attempts() {
    let (client, http) = client(
        PROJECT,
        vec![tokens(&token(NOW + 900)), response(200, json!({"id":USER}))],
    );
    let store = Arc::new(Store::default());
    let owner = HostedSessionOwner::new(Arc::new(client), store.clone());
    let old = owner.begin_login().unwrap();
    let cancellation = old.cancellation();
    cancellation.cancel();
    assert!(owner.complete_login(old, exchange(), NOW).is_err());
    let old = owner.begin_login().unwrap();
    let current = owner.begin_login().unwrap();
    assert!(matches!(
        owner.cancel_attempt(old.cancellation()),
        Err(LoginError::Canceled)
    ));
    assert!(owner.complete_login(old, exchange(), NOW).is_err());
    assert!(http.requests.lock().unwrap().is_empty());
    store
        .fail_save
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(owner.complete_login(current, exchange(), NOW).is_err());
    assert!(owner.current_session(NOW).unwrap().is_none());
    assert!(store.saved.lock().unwrap().is_none());
    assert!(owner.restore(NOW).is_err());
}

#[test]
fn cancellation_during_credential_write_clears_the_result_before_publication() {
    let (client, _) = client(
        PROJECT,
        vec![tokens(&token(NOW + 900)), response(200, json!({"id":USER}))],
    );
    let store = Arc::new(Store::default());
    let owner = Arc::new(HostedSessionOwner::new(Arc::new(client), store.clone()));
    let attempt = owner.begin_login().unwrap();
    let cancellation = attempt.cancellation();
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    *store.save_gate.lock().unwrap() = Some((started_tx, release_rx));
    let worker = {
        let owner = owner.clone();
        std::thread::spawn(move || owner.complete_login(attempt, exchange(), NOW))
    };
    started_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .unwrap();
    cancellation.cancel();
    release_tx.send(()).unwrap();
    assert!(matches!(worker.join().unwrap(), Err(LoginError::Canceled)));
    assert!(store.saved.lock().unwrap().is_none());
    assert!(owner.current_session(NOW).unwrap().is_none());
}

#[test]
fn canceled_queued_begin_cannot_clear_a_newer_login() {
    let (client, _) = client(
        PROJECT,
        vec![tokens(&token(NOW + 900)), response(200, json!({"id":USER}))],
    );
    let store = Arc::new(Store::default());
    let owner = HostedSessionOwner::new(Arc::new(client), store.clone());
    let delayed = context_relay_core::auth::LoginCancellation::default();
    delayed.cancel();
    owner
        .complete_login(owner.begin_login().unwrap(), exchange(), NOW)
        .unwrap();
    assert!(matches!(
        owner.begin_login_cancellable(delayed),
        Err(LoginError::Canceled)
    ));
    assert!(owner.current_session(NOW).unwrap().is_some());
    assert!(store.saved.lock().unwrap().is_some());
}

#[test]
fn delayed_refresh_cannot_capture_or_clear_a_newer_login() {
    let (client, http) = client(
        PROJECT,
        vec![
            tokens(&token(NOW + 900)),
            response(200, json!({"id":USER})),
            response(401, json!({})),
        ],
    );
    let store = Arc::new(Store::default());
    let owner = HostedSessionOwner::new(Arc::new(client), store.clone());
    let delayed = owner.cancellation().unwrap();
    owner
        .complete_login(owner.begin_login().unwrap(), exchange(), NOW)
        .unwrap();
    for reservation in [
        delayed,
        context_relay_core::auth::LoginCancellation::default(),
    ] {
        assert!(matches!(
            owner.refresh_cancellable(&reservation, NOW),
            Err(LoginError::Canceled)
        ));
        assert!(matches!(
            owner.restore_cancellable(&reservation, NOW),
            Err(LoginError::Canceled)
        ));
    }
    assert_eq!(http.requests.lock().unwrap().len(), 2);
    assert!(owner.current_session(NOW).unwrap().is_some());
    assert!(store.saved.lock().unwrap().is_some());
}

#[test]
fn startup_restore_can_retry_offline_failure_but_denied_refresh_clears_identity() {
    let (client, _) = client(
        PROJECT,
        vec![
            tokens(&token(NOW + 900)),
            response(200, json!({"id":USER})),
            response(500, json!({})),
            tokens(&token(NOW + 1800)),
            response(200, json!({"id":USER})),
            response(401, json!({})),
        ],
    );
    let client = Arc::new(client);
    let store = Arc::new(Store::default());
    let initial = HostedSessionOwner::new(client.clone(), store.clone());
    initial
        .complete_login(initial.begin_login().unwrap(), exchange(), NOW)
        .unwrap();
    let owner = HostedSessionOwner::new(client, store.clone());
    store
        .fail_load
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(matches!(
        owner.restore(NOW),
        Err(LoginError::CredentialStore)
    ));
    store
        .fail_load
        .store(false, std::sync::atomic::Ordering::SeqCst);
    assert!(matches!(owner.restore(NOW), Err(LoginError::Unavailable)));
    assert!(owner.restore(NOW).unwrap().is_some());
    assert!(matches!(owner.refresh(NOW), Err(LoginError::Denied)));
    assert!(owner.current_session(NOW).unwrap().is_none());
    assert!(store.saved.lock().unwrap().is_none());
}

struct Http {
    responses: Mutex<VecDeque<SupabaseHttpResponse>>,
    requests: Mutex<Vec<SupabaseHttpRequest>>,
    refresh_gate: Mutex<Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>>,
}
impl SupabaseHttpClient for Http {
    fn execute(
        &self,
        request: SupabaseHttpRequest,
    ) -> Result<SupabaseHttpResponse, SupabaseHttpError> {
        if request.url().ends_with("grant_type=refresh_token")
            && let Some((started, release)) = self.refresh_gate.lock().unwrap().take()
        {
            started.send(()).unwrap();
            release
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap();
        }
        self.requests.lock().unwrap().push(request);
        Ok(self
            .responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected request"))
    }
}
fn response(status: u16, value: serde_json::Value) -> SupabaseHttpResponse {
    SupabaseHttpResponse::new(status, serde_json::to_vec(&value).unwrap())
}
fn token(exp: u64) -> String {
    token_claims(
        json!({"iss":format!("{PROJECT}/auth/v1"),"aud":"authenticated","sub":USER,"session_id":SESSION,"exp":exp}),
    )
}
fn token_claims(claims: serde_json::Value) -> String {
    format!(
        "{}.{}.synthetic-signature",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256"}"#),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    )
}
fn tokens(access: &str) -> SupabaseHttpResponse {
    response(
        200,
        json!({"token_type":"bearer","access_token":access,"refresh_token":"synthetic-refresh","expires_in":900,"provider_token":"discard-provider-secret"}),
    )
}
fn exchange() -> context_relay_core::auth::LoginExchange {
    let now = Instant::now();
    let mut pending = PendingLogin::new(PROJECT, "127.0.0.1:41783".parse().unwrap(), now).unwrap();
    let auth = pending.authorization_url();
    let redirect = auth
        .query_pairs()
        .find(|(key, _)| key == "redirect_to")
        .unwrap()
        .1
        .into_owned();
    let mut callback = auth.join(&redirect).unwrap();
    callback
        .query_pairs_mut()
        .append_pair("code", "synthetic-code");
    pending.take_callback(&callback, now).unwrap()
}
fn client(project: &str, responses: Vec<SupabaseHttpResponse>) -> (SupabaseAuthClient, Arc<Http>) {
    let http = Arc::new(Http {
        responses: Mutex::new(responses.into()),
        requests: Mutex::new(vec![]),
        refresh_gate: Mutex::new(None),
    });
    (
        SupabaseAuthClient::with_http_client(project, "publishable-key", http.clone()).unwrap(),
        http,
    )
}

#[test]
fn logout_invalidates_inflight_refresh_even_when_credential_deletion_fails() {
    let (client, http) = client(
        PROJECT,
        vec![
            tokens(&token(NOW + 900)),
            response(200, json!({"id":USER})),
            SupabaseHttpResponse::new(204, vec![]),
            tokens(&token(NOW + 1800)),
            response(200, json!({"id":USER})),
        ],
    );
    let store = Arc::new(Store::default());
    let owner = Arc::new(HostedSessionOwner::new(Arc::new(client), store.clone()));
    owner
        .complete_login(owner.begin_login().unwrap(), exchange(), NOW)
        .unwrap();
    assert!(owner.current_session(NOW).unwrap().is_some());
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    *http.refresh_gate.lock().unwrap() = Some((started_tx, release_rx));
    let worker = {
        let owner = owner.clone();
        std::thread::spawn(move || owner.refresh(NOW))
    };
    started_rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .unwrap();
    assert!(matches!(owner.refresh(NOW), Err(LoginError::Busy)));
    store
        .fail_clear
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let outcome = owner.logout().unwrap();
    release_tx.send(()).unwrap();
    assert!(matches!(worker.join().unwrap(), Err(LoginError::Canceled)));
    assert!(outcome.local.is_err());
    assert!(matches!(outcome.remote, Some(Ok(()))));
    assert!(owner.current_session(NOW).unwrap().is_none());
    assert!(owner.restore(NOW).is_err());
    store
        .fail_clear
        .store(false, std::sync::atomic::Ordering::SeqCst);
    assert!(owner.logout().unwrap().local.is_ok());
    assert!(store.saved.lock().unwrap().is_none());
}

#[test]
fn pkce_exchange_checks_hosted_identity_before_returning_a_session() {
    let access = token(NOW + 900);
    let (client, http) = client(
        PROJECT,
        vec![tokens(&access), response(200, json!({"id":USER}))],
    );
    let session = client.exchange(exchange(), NOW).unwrap();
    assert_eq!(session.project_url().as_str(), format!("{PROJECT}/"));
    assert_eq!(session.identity().user_id.to_string(), USER);
    assert_eq!(session.identity().session_id.to_string(), SESSION);
    assert_eq!(session.expires_at(), NOW + 900);
    for secret in [&access, "synthetic-refresh", "discard-provider-secret"] {
        assert!(!format!("{session:?}").contains(secret));
        assert!(!format!("{client:?}").contains(secret));
    }
    let requests = http.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0].url(),
        format!("{PROJECT}/auth/v1/token?grant_type=pkce")
    );
    assert!(requests[0].header("authorization").is_none());
    assert_eq!(requests[0].header("apikey"), Some("publishable-key"));
    let body: serde_json::Value = serde_json::from_slice(requests[0].body()).unwrap();
    assert_eq!(body["auth_code"], "synthetic-code");
    assert_eq!(body["code_verifier"].as_str().unwrap().len(), 43);
    assert_eq!(requests[1].url(), format!("{PROJECT}/auth/v1/user"));
    assert_eq!(
        requests[1].header("authorization"),
        Some(format!("Bearer {access}").as_str())
    );
}

#[test]
fn wrong_project_and_invalid_provider_responses_do_not_establish_a_session() {
    let (wrong, http) = client("https://other.supabase.co", vec![]);
    assert!(wrong.exchange(exchange(), NOW).is_err());
    assert!(http.requests.lock().unwrap().is_empty());
    for responses in [
        vec![response(500, json!({"message":"private-provider-secret"}))],
        vec![tokens("invalid-jwt")],
        vec![tokens(&token(NOW))],
        vec![
            tokens(&token(NOW + 900)),
            response(401, json!({"message":"private-provider-secret"})),
        ],
        vec![
            tokens(&token(NOW + 900)),
            response(200, json!({"id":SESSION})),
        ],
        vec![SupabaseHttpResponse::new(200, vec![b'x'; 65537])],
    ] {
        let (client, _) = client(PROJECT, responses);
        let error = client.exchange(exchange(), NOW).unwrap_err();
        assert!(!format!("{error:?} {error}").contains("private-provider-secret"));
    }
}

#[test]
fn invalid_identity_claims_are_rejected_before_the_user_lookup() {
    for (field, value) in [
        ("iss", json!("https://other.supabase.co/auth/v1")),
        ("aud", json!("anon")),
        ("aud", json!(["anon"])),
        ("session_id", json!("not-a-uuid")),
        ("session_id", json!("00000000-0000-0000-0000-000000000000")),
        ("session_id", serde_json::Value::Null),
        ("sub", json!("not-a-uuid")),
        ("sub", json!("00000000-0000-0000-0000-000000000000")),
        ("sub", serde_json::Value::Null),
        ("exp", json!(NOW + 86401)),
    ] {
        let mut claims = json!({"iss":format!("{PROJECT}/auth/v1"),"aud":"authenticated","sub":USER,"session_id":SESSION,"exp":NOW + 900});
        if value.is_null() {
            claims.as_object_mut().unwrap().remove(field);
        } else {
            claims[field] = value;
        }
        let (client, http) = client(PROJECT, vec![tokens(&token_claims(claims))]);
        assert!(
            client.exchange(exchange(), NOW).is_err(),
            "accepted invalid {field}"
        );
        assert_eq!(http.requests.lock().unwrap().len(), 1);
    }
}

#[test]
fn refresh_preserves_identity_and_logout_revokes_only_that_session() {
    let renewed_access = token(NOW + 1800);
    let (client, http) = client(
        PROJECT,
        vec![
            tokens(&token(NOW + 900)),
            response(200, json!({"id":USER})),
            response(
                200,
                json!({"token_type":"bearer","access_token":renewed_access,"refresh_token":"rotated-refresh"}),
            ),
            response(200, json!({"id":USER})),
            SupabaseHttpResponse::new(204, vec![]),
        ],
    );
    let original = client.exchange(exchange(), NOW).unwrap();
    let renewed = client.refresh(&original, NOW + 900).unwrap();
    assert!(renewed.identity() == original.identity());
    assert_eq!(renewed.refresh_token(), "rotated-refresh");
    assert_eq!(original.refresh_token(), "synthetic-refresh");
    client.logout(&renewed).unwrap();
    let requests = http.requests.lock().unwrap();
    assert_eq!(requests.len(), 5);
    assert_eq!(
        requests[2].url(),
        format!("{PROJECT}/auth/v1/token?grant_type=refresh_token")
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(requests[2].body()).unwrap(),
        json!({"refresh_token":"synthetic-refresh"})
    );
    assert!(requests[2].header("authorization").is_none());
    assert_eq!(
        requests[4].url(),
        format!("{PROJECT}/auth/v1/logout?scope=local")
    );
    assert_eq!(
        requests[4].header("authorization"),
        Some(format!("Bearer {renewed_access}").as_str())
    );
    assert!(requests[4].body().is_empty());
}

#[test]
fn refresh_cannot_change_identity_and_session_operations_cannot_change_project() {
    for field in ["sub", "session_id"] {
        let mut changed = json!({"iss":format!("{PROJECT}/auth/v1"),"aud":"authenticated","sub":USER,"session_id":SESSION,"exp":NOW + 1800});
        changed[field] = json!("550e8400-e29b-41d4-a716-446655440099");
        let (client, http) = client(
            PROJECT,
            vec![
                tokens(&token(NOW + 900)),
                response(200, json!({"id":USER})),
                tokens(&token_claims(changed)),
            ],
        );
        let original = client.exchange(exchange(), NOW).unwrap();
        assert!(client.refresh(&original, NOW + 900).is_err());
        assert_eq!(http.requests.lock().unwrap().len(), 3);
        let (wrong, wrong_http) = self::client("https://other.supabase.co", vec![]);
        assert!(wrong.refresh(&original, NOW).is_err());
        assert!(wrong.logout(&original).is_err());
        assert!(wrong_http.requests.lock().unwrap().is_empty());
    }
}

#[test]
fn failed_refresh_is_not_retried_and_logout_requires_revocation_confirmation() {
    let (client, http) = client(
        PROJECT,
        vec![
            tokens(&token(NOW + 900)),
            response(200, json!({"id":USER})),
            response(500, json!({"message":"private-provider-secret"})),
            response(200, json!({})),
        ],
    );
    let original = client.exchange(exchange(), NOW).unwrap();
    assert!(client.refresh(&original, NOW + 900).is_err());
    assert_eq!(http.requests.lock().unwrap().len(), 3);
    assert_eq!(original.refresh_token(), "synthetic-refresh");
    assert!(client.logout(&original).is_err());
    assert_eq!(http.requests.lock().unwrap().len(), 4);
}

#[test]
fn stored_login_requires_fresh_hosted_verification() {
    let (client, http) = client(
        PROJECT,
        vec![
            tokens(&token(NOW + 900)),
            response(200, json!({"id":USER})),
            tokens(&token(NOW + 1800)),
            response(200, json!({"id":USER})),
        ],
    );
    let session = client.exchange(exchange(), NOW).unwrap();
    let stored = session.stored_login();
    assert!(!format!("{stored:?}").contains("synthetic-refresh"));
    let restored = client.restore(&stored, NOW + 900).unwrap();
    assert!(restored.identity() == session.identity());
    assert_eq!(http.requests.lock().unwrap().len(), 4);
    let (wrong, http) = self::client("https://other.supabase.co", vec![]);
    assert!(wrong.restore(&stored, NOW).is_err());
    assert!(http.requests.lock().unwrap().is_empty());
}

mod support;

#[test]
fn native_enrollment_coordinator_accepts_server_clock_skew_and_reopens() {
    use context_relay_core::{
        crypto::DeviceKeys,
        devices::{
            recovery::{
                RecoveryEnrollmentBeginOutcome, RecoveryEnrollmentClock,
                RecoveryEnrollmentConfirmOutcome, RecoveryEnrollmentCoordinator,
            },
            recovery_crypto::decode_recovery_enrollment_record_v1,
            supabase_enrollment::HostedEnrollmentClient,
        },
        vault::{HostedEnrollmentIntent, Vault},
    };
    use context_relay_protocol::{
        NativePlatform, RecoveryEnrollmentConfirmParams, RecoveryEnrollmentState,
        RecoveryWordConfirmation,
    };
    use sha2::{Digest, Sha256};
    #[derive(Clone, Copy)]
    struct Clock;
    impl RecoveryEnrollmentClock for Clock {
        fn now_ms(&self) -> u64 {
            NOW * 1000
        }
    }
    struct EnrollmentHttp {
        reservation: serde_json::Value,
        receipt: Mutex<serde_json::Value>,
        server_ms: u64,
        lose_response: bool,
    }
    impl SupabaseHttpClient for EnrollmentHttp {
        fn execute(
            &self,
            request: SupabaseHttpRequest,
        ) -> Result<SupabaseHttpResponse, SupabaseHttpError> {
            let body: serde_json::Value = serde_json::from_slice(request.body()).unwrap();
            if body["action"] == "status" {
                let mut reservation = self.reservation.clone();
                reservation["receipt"] = self.receipt.lock().unwrap().clone();
                return Ok(response(200, json!({"v":1,"reservation":reservation})));
            }
            assert_eq!(body["action"], "commit");
            let canonical: Vec<u8> = body["record"]
                .as_str()
                .unwrap()
                .as_bytes()
                .chunks_exact(2)
                .map(|part| u8::from_str_radix(std::str::from_utf8(part).unwrap(), 16).unwrap())
                .collect();
            let record = decode_recovery_enrollment_record_v1(&canonical).unwrap();
            let receipt = json!({"enrollmentId":record.enrollment_id,"recoveryRootId":record.recovery_root_id,
                "accountId":record.account_id,"workspaceId":record.workspace_id,
                "genesisCertificateId":record.genesis_certificate_id,
                "canonicalRecordSha256":format!("{:x}",Sha256::digest(&canonical)),
                "registeredAtMs":self.server_ms.to_string()});
            *self.receipt.lock().unwrap() = receipt.clone();
            if self.lose_response {
                return Ok(response(503, json!({})));
            }
            Ok(response(200, json!({"v":1,"receipt":receipt})))
        }
    }
    for (server_ms, lose_response) in [
        (NOW * 1000 - 5000, false),
        (NOW * 1000 + 5000, false),
        (NOW * 1000 - 5000, true),
        (NOW * 1000 + 5000, true),
    ] {
        let (auth, _) = client(
            PROJECT,
            vec![tokens(&token(NOW + 900)), response(200, json!({"id":USER}))],
        );
        let owner = Arc::new(HostedSessionOwner::new(
            Arc::new(auth),
            Arc::new(Store::default()),
        ));
        let attempt = owner.begin_login().unwrap();
        let generation = attempt.cancellation();
        let identity = owner.complete_login(attempt, exchange(), NOW).unwrap();
        let reservation = json!({"reservationId":"018f22e2-79b0-7cc8-98c4-dc0c0c073901",
            "accountId":"018f22e2-79b0-7cc8-98c4-dc0c0c073902",
            "workspaceId":"018f22e2-79b0-7cc8-98c4-dc0c0c073903",
            "nonce":"42".repeat(32),"expiresAt":((NOW+600)*1000).to_string()});
        let intent = HostedEnrollmentIntent {
            project_url: PROJECT.into(),
            user_id: identity.user_id,
            session_id: identity.session_id,
            operation_id: serde_json::from_value(reservation["reservationId"].clone()).unwrap(),
            reservation: Some(serde_json::from_value(reservation.clone()).unwrap()),
        };
        let http = Arc::new(EnrollmentHttp {
            reservation,
            receipt: Mutex::new(serde_json::Value::Null),
            server_ms,
            lose_response,
        });
        let device = Arc::new(DeviceKeys::from_seeds_for_test([0x11; 32], [0x22; 32]));
        let make_transport = || {
            HostedEnrollmentClient::with_http_client(
                owner.clone(),
                identity,
                generation.clone(),
                PROJECT,
                "public-test",
                http.clone(),
            )
            .unwrap()
            .into_transport(&intent, device.clone(), Clock)
            .unwrap()
        };
        let path = support::TempVault::new("native-enrollment-clock");
        let keys = support::MemoryKeyStore::default();
        let mut vault = Vault::open(path.path(), "native-enrollment-clock", &keys).unwrap();
        vault.store_hosted_enrollment_intent(&intent).unwrap();
        let mut coordinator = RecoveryEnrollmentCoordinator::new(Clock, make_transport());
        let RecoveryEnrollmentBeginOutcome::Phrase(phrase) = coordinator
            .begin(
                &mut vault,
                "018f22e2-79b0-7cc8-98c4-dc0c0c073904".parse().unwrap(),
                "Test desktop",
                NativePlatform::Windows,
                &device,
            )
            .unwrap()
        else {
            panic!("expected phrase")
        };
        let params = RecoveryEnrollmentConfirmParams {
            enrollment_id: phrase.enrollment_id,
            confirmations: phrase
                .confirmation_positions
                .iter()
                .map(|position| RecoveryWordConfirmation {
                    position: *position,
                    word: phrase.recovery_phrase_words.as_words()[usize::from(*position) - 1]
                        .clone(),
                })
                .collect(),
        };
        let outcome = coordinator.confirm(&mut vault, params, &device).unwrap();
        assert_eq!(
            matches!(outcome, RecoveryEnrollmentConfirmOutcome::Complete(_)),
            !lose_response
        );
        drop(coordinator);
        drop(vault);
        let mut vault = Vault::open(path.path(), "native-enrollment-clock", &keys).unwrap();
        let mut coordinator = RecoveryEnrollmentCoordinator::new(Clock, make_transport());
        assert_eq!(
            coordinator.overview(&mut vault, &device).unwrap().state,
            RecoveryEnrollmentState::Complete
        );
        let stored = vault.recovery_enrollment().unwrap().unwrap();
        assert_eq!(stored.provider_accepted_at_ms, Some(server_ms));
        assert_eq!(stored.completed_at_ms, Some(NOW * 1000));
    }
}

#[test]
fn native_renewal_preserves_scope_and_requires_a_fresh_challenge() {
    use context_relay_core::devices::supabase_enrollment::{
        HostedEnrollmentClient, HostedEnrollmentReservation,
    };
    let previous = json!({"reservationId":"018f22e2-79b0-7cc8-98c4-dc0c0c073901",
        "accountId":"018f22e2-79b0-7cc8-98c4-dc0c0c073902","workspaceId":"018f22e2-79b0-7cc8-98c4-dc0c0c073903",
        "nonce":"42".repeat(32),"expiresAt":(NOW*1000).to_string()});
    let mut renewed = previous.clone();
    renewed["nonce"] = json!("43".repeat(32));
    renewed["expiresAt"] = json!(((NOW + 600) * 1000).to_string());
    let mut wrong_scope = renewed.clone();
    wrong_scope["workspaceId"] = previous["accountId"].clone();
    let mut old_nonce = renewed.clone();
    old_nonce["nonce"] = previous["nonce"].clone();
    let (auth, http) = client(
        PROJECT,
        vec![
            tokens(&token(NOW + 900)),
            response(200, json!({"id":USER})),
            response(200, json!({"v":1,"reservation":renewed})),
            response(200, json!({"v":1,"reservation":wrong_scope})),
            response(200, json!({"v":1,"reservation":old_nonce})),
        ],
    );
    let owner = Arc::new(HostedSessionOwner::new(
        Arc::new(auth),
        Arc::new(Store::default()),
    ));
    let attempt = owner.begin_login().unwrap();
    let generation = attempt.cancellation();
    let identity = owner.complete_login(attempt, exchange(), NOW).unwrap();
    let client = HostedEnrollmentClient::with_http_client(
        owner,
        identity,
        generation,
        PROJECT,
        "public-test",
        http.clone(),
    )
    .unwrap();
    let previous: HostedEnrollmentReservation = serde_json::from_value(previous).unwrap();
    let next = client.renew(&previous, NOW).unwrap();
    assert_eq!(serde_json::to_value(next).unwrap(), renewed);
    let requests = http.requests.lock().unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(requests.last().unwrap().body()).unwrap(),
        json!({"v":1,"action":"renew","reservationId":previous.reservation_id})
    );
    drop(requests);
    assert!(client.renew(&previous, NOW).is_err());
    assert!(client.renew(&previous, NOW).is_err());
}
