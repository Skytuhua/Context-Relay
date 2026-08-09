mod support;

use std::{path::Path, str::FromStr};

use context_relay_core::{
    crypto::{
        CertificateFieldsV1, DeviceCertificateV1, DeviceKeys, RecoveryKeys, RecoveryPhrase,
        WrappedKeyEnvelope,
    },
    devices::crypto::{
        ConfirmedPairingApproval, PAIRING_GRANT_SCHEMA_VERSION, PairingGrant, PairingGrantApproval,
        PairingKeyBundle, SignedPairingRequest, UnconfirmedPairingGrant,
        build_pairing_approved_payload_v1, build_pairing_grant, confirm_and_open_pairing_approval,
        encode_pairing_approved_payload_v1, encode_pairing_grant_v1, inspect_pairing_approval,
    },
    sync::SyncScope,
    vault::{
        CommitDisposition, DeviceCertificateState, DeviceDisplayMetadata, LATEST_SCHEMA_VERSION,
        PairingApprovalState, PairingDecisionFinalState, Vault, VaultError,
    },
};
use context_relay_protocol::{
    AccountId, DeviceCertificateId, DeviceId, NativePlatform, PairingRequestNonce,
    RecoveryPhraseWords, WorkspaceId, X25519PublicKeyBytes, XChaChaNonce,
};
use rusqlite::Connection;
use sha2::{Digest, Sha256};

use support::{MemoryKeyStore, TempVault};

const CREDENTIAL: &str = "device-pairing-vault-v1";
const ACCOUNT_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073981";
const WORKSPACE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073982";
const DEVICE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073983";
const CERTIFICATE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073984";
const CONFIRM_PAIRING_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073994";
const CONFIRM_ISSUER_DEVICE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073995";
const CONFIRM_JOINER_DEVICE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073996";
const CONFIRM_ISSUER_CERTIFICATE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073997";
const CONFIRM_CHILD_CERTIFICATE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073998";
const KEY_CANARY: &[u8] = b"TASK_17_PAIRING_KEY_CANARY_DO_NOT_LEAK";

struct ConfirmationFixture {
    issuer_certificate: DeviceCertificateV1,
    issuer_certificate_id: DeviceCertificateId,
    joiner_keys: DeviceKeys,
    signed_request: SignedPairingRequest,
    approval: UnconfirmedPairingGrant,
    confirmed: ConfirmedPairingApproval,
}

fn id<T: FromStr>(value: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    value.parse().unwrap()
}

fn certificate() -> (DeviceCertificateV1, DeviceCertificateId) {
    let device_keys = DeviceKeys::generate().unwrap();
    (
        DeviceCertificateV1::issue_by_device(
            CertificateFieldsV1 {
                account_id: id::<AccountId>(ACCOUNT_ID),
                workspace_id: id::<WorkspaceId>(WORKSPACE_ID),
                control_epoch: 3,
                request_nonce: PairingRequestNonce([4; 32]),
                device_id: id::<DeviceId>(DEVICE_ID),
                signing_public_key: device_keys.signing_public_key(),
                wrapping_public_key: device_keys.wrapping_public_key(),
            },
            id::<DeviceId>(DEVICE_ID),
            &device_keys,
        )
        .unwrap(),
        id::<DeviceCertificateId>(CERTIFICATE_ID),
    )
}

fn display() -> DeviceDisplayMetadata {
    DeviceDisplayMetadata {
        device_name: "joiner".to_owned(),
        platform: NativePlatform::Macos,
    }
}

fn confirmation_scope() -> SyncScope {
    SyncScope {
        account_id: id(ACCOUNT_ID),
        workspace_id: id(WORKSPACE_ID),
    }
}

fn confirmation_fixture() -> ConfirmationFixture {
    let issuer_keys = DeviceKeys::generate().unwrap();
    let issuer_certificate = DeviceCertificateV1::issue_genesis(
        CertificateFieldsV1 {
            account_id: id(ACCOUNT_ID),
            workspace_id: id(WORKSPACE_ID),
            control_epoch: 7,
            request_nonce: PairingRequestNonce([0x51; 32]),
            device_id: id(CONFIRM_ISSUER_DEVICE_ID),
            signing_public_key: issuer_keys.signing_public_key(),
            wrapping_public_key: issuer_keys.wrapping_public_key(),
        },
        &RecoveryKeys::derive(&fixed_recovery_phrase()).unwrap(),
    )
    .unwrap();
    let issuer_certificate_id = id(CONFIRM_ISSUER_CERTIFICATE_ID);
    let joiner_keys = DeviceKeys::generate().unwrap();
    let signed_request = SignedPairingRequest::build(
        id(CONFIRM_PAIRING_ID),
        id(CONFIRM_JOINER_DEVICE_ID),
        "Joining laptop",
        NativePlatform::Macos,
        &joiner_keys,
    )
    .unwrap();
    let mut workspace_root_key = [0x71; 32];
    workspace_root_key.copy_from_slice(&KEY_CANARY[..32]);
    let mut active_epoch_key = [0x83; 32];
    active_epoch_key[..KEY_CANARY.len() - 32].copy_from_slice(&KEY_CANARY[32..]);
    let bundle = PairingKeyBundle::new(
        confirmation_scope(),
        7,
        11,
        workspace_root_key,
        active_epoch_key,
    )
    .unwrap();
    let grant = build_pairing_grant(
        &signed_request,
        &PairingGrantApproval {
            request_digest: signed_request.digest(),
            certificate_id: id(CONFIRM_CHILD_CERTIFICATE_ID),
            scope: confirmation_scope(),
            control_epoch: 7,
            issuer_certificate: issuer_certificate.clone(),
        },
        &issuer_keys,
        &bundle,
    )
    .unwrap();
    let payload = build_pairing_approved_payload_v1(
        &signed_request,
        grant,
        issuer_certificate_id,
        issuer_certificate.clone(),
        "Existing desktop",
        NativePlatform::Macos,
    )
    .unwrap();
    let canonical = encode_pairing_approved_payload_v1(&payload).unwrap();
    let approval = inspect_pairing_approval(&canonical, &signed_request).unwrap();
    let confirmed = confirm_and_open_pairing_approval(
        &approval,
        approval.safety_number().as_str(),
        &signed_request,
        &joiner_keys,
    )
    .unwrap();
    ConfirmationFixture {
        issuer_certificate,
        issuer_certificate_id,
        joiner_keys,
        signed_request,
        approval,
        confirmed,
    }
}

fn fixed_recovery_phrase() -> RecoveryPhrase {
    let mut words = vec!["abandon".to_owned(); 23];
    words.push("art".to_owned());
    RecoveryPhrase::from_words(RecoveryPhraseWords::new(words).unwrap()).unwrap()
}

fn open_keyed(path: &Path, key: &[u8; 32]) -> Connection {
    let connection = Connection::open(path).unwrap();
    // SAFETY: this is the first SQLite operation and the key remains live for the call.
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
fn device_certificate_is_durable_and_exactly_idempotent() {
    let path = TempVault::new("device-certificate");
    let keys = MemoryKeyStore::default();
    let (certificate, certificate_id) = certificate();

    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(
        vault
            .store_device_certificate(
                certificate_id,
                &certificate,
                DeviceCertificateState::Active,
                &display(),
                1
            )
            .unwrap(),
        CommitDisposition::Inserted
    );
    assert_eq!(
        vault
            .store_device_certificate(
                certificate_id,
                &certificate,
                DeviceCertificateState::Active,
                &display(),
                1
            )
            .unwrap(),
        CommitDisposition::ExactReplay
    );
    let stored = vault.device_certificate(certificate_id).unwrap().unwrap();
    assert_eq!(stored.certificate, certificate);
    assert_eq!(stored.state, DeviceCertificateState::Active);
}

#[test]
fn prepared_decision_resumes_and_conflicting_finish_rolls_back() {
    let path = TempVault::new("prepared-decision");
    let keys = MemoryKeyStore::default();
    let key = [37; 32];
    keys.insert(CREDENTIAL, key);
    let (certificate, certificate_id) = certificate();
    let pairing_id = id("018f22e2-79b0-7cc8-98c4-dc0c0c073985");
    let request_digest = context_relay_protocol::Sha256Digest([8; 32]);
    let grant = PairingGrant {
        schema_version: PAIRING_GRANT_SCHEMA_VERSION,
        pairing_id,
        request_digest,
        certificate_id,
        certificate,
        key_epoch: 2,
        wrapped_key_bundle: WrappedKeyEnvelope {
            ephemeral_public_key: X25519PublicKeyBytes([9; 32]),
            nonce: XChaChaNonce([10; 24]),
            ciphertext: vec![11; 16],
        },
    };
    let canonical = encode_pairing_grant_v1(&grant).unwrap();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(
        vault
            .store_device_certificate(
                certificate_id,
                &grant.certificate,
                DeviceCertificateState::Active,
                &display(),
                1
            )
            .unwrap(),
        CommitDisposition::Inserted
    );
    assert_eq!(
        vault
            .prepare_pairing_decision(&grant, &canonical, 2)
            .unwrap(),
        CommitDisposition::Inserted
    );
    assert_eq!(
        vault
            .prepare_pairing_decision(&grant, &canonical, 2)
            .unwrap(),
        CommitDisposition::ExactReplay
    );
    let mut conflicting_grant = grant.clone();
    conflicting_grant.key_epoch = 3;
    let conflicting_canonical = encode_pairing_grant_v1(&conflicting_grant).unwrap();
    assert!(matches!(
        vault.prepare_pairing_decision(&conflicting_grant, &conflicting_canonical, 2),
        Err(VaultError::OperationConflict)
    ));
    drop(vault);
    let mut reopened = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(reopened.pending_pairing_decisions().unwrap().len(), 1);
    assert_eq!(
        reopened
            .finish_pairing_decision(
                pairing_id,
                request_digest,
                PairingDecisionFinalState::Accepted,
                3
            )
            .unwrap(),
        CommitDisposition::Inserted
    );
    assert_eq!(
        reopened
            .finish_pairing_decision(
                pairing_id,
                request_digest,
                PairingDecisionFinalState::Accepted,
                3
            )
            .unwrap(),
        CommitDisposition::ExactReplay
    );
    assert!(matches!(
        reopened.finish_pairing_decision(
            pairing_id,
            context_relay_protocol::Sha256Digest([12; 32]),
            PairingDecisionFinalState::Accepted,
            3
        ),
        Err(VaultError::OperationConflict)
    ));
    assert!(reopened.pending_pairing_decisions().unwrap().is_empty());
    drop(reopened);
    let raw = open_keyed(path.path(), &key);
    raw.execute(
        "UPDATE pairing_decisions SET grant_sha256 = ?2 WHERE pairing_id = ?1",
        rusqlite::params![pairing_id.to_string(), vec![0_u8; 32]],
    )
    .unwrap();
    drop(raw);
    let mut reopened = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert!(matches!(
        reopened.finish_pairing_decision(
            pairing_id,
            request_digest,
            PairingDecisionFinalState::Accepted,
            3,
        ),
        Err(VaultError::OperationConflict)
    ));
}

#[test]
fn rejection_is_terminal_and_idempotent() {
    let path = TempVault::new("pairing-rejection");
    let keys = MemoryKeyStore::default();
    let pairing_id = id("018f22e2-79b0-7cc8-98c4-dc0c0c073988");
    let request_digest = context_relay_protocol::Sha256Digest([21; 32]);
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(
        vault
            .finish_pairing_decision(
                pairing_id,
                request_digest,
                PairingDecisionFinalState::Rejected,
                4
            )
            .unwrap(),
        CommitDisposition::Inserted
    );
    assert_eq!(
        vault
            .finish_pairing_decision(
                pairing_id,
                request_digest,
                PairingDecisionFinalState::Rejected,
                4
            )
            .unwrap(),
        CommitDisposition::ExactReplay
    );
    assert!(matches!(
        vault.finish_pairing_decision(
            pairing_id,
            request_digest,
            PairingDecisionFinalState::Accepted,
            4
        ),
        Err(VaultError::OperationConflict)
    ));
}

#[test]
fn join_completion_is_exact_and_never_persists_pairing_codes_or_private_keys() {
    let path = TempVault::new("pairing-join");
    let keys = MemoryKeyStore::default();
    let key = [41; 32];
    keys.insert(CREDENTIAL, key);
    let (certificate, certificate_id) = certificate();
    let pairing_id = id("018f22e2-79b0-7cc8-98c4-dc0c0c073986");
    let joiner_keys = DeviceKeys::generate().unwrap();
    let request = SignedPairingRequest::build(
        pairing_id,
        id::<DeviceId>("018f22e2-79b0-7cc8-98c4-dc0c0c073987"),
        "joiner",
        NativePlatform::Macos,
        &joiner_keys,
    )
    .unwrap();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(
        vault
            .store_pairing_join_request(pairing_id, request.canonical_bytes(), 2)
            .unwrap(),
        CommitDisposition::Inserted
    );
    assert_eq!(
        vault
            .store_pairing_join_request(pairing_id, request.canonical_bytes(), 2)
            .unwrap(),
        CommitDisposition::ExactReplay
    );
    assert!(matches!(
        vault.store_pairing_join_request(pairing_id, b"not-a-pairing-request", 2),
        Err(VaultError::Validation(_))
    ));
    assert!(matches!(
        vault.store_pairing_join_request(
            id("018f22e2-79b0-7cc8-98c4-dc0c0c073989"),
            request.canonical_bytes(),
            2
        ),
        Err(VaultError::Validation(_))
    ));
    let digest =
        context_relay_protocol::Sha256Digest(Sha256::digest(request.canonical_bytes()).into());
    let mismatch_grant = PairingGrant {
        schema_version: PAIRING_GRANT_SCHEMA_VERSION,
        pairing_id,
        request_digest: digest,
        certificate_id,
        certificate,
        key_epoch: 2,
        wrapped_key_bundle: WrappedKeyEnvelope {
            ephemeral_public_key: X25519PublicKeyBytes([9; 32]),
            nonce: XChaChaNonce([10; 24]),
            ciphertext: vec![11; 16],
        },
    };
    let mismatch_canonical = encode_pairing_grant_v1(&mismatch_grant).unwrap();
    assert!(matches!(
        vault.finish_pairing_join(
            pairing_id,
            request.canonical_bytes(),
            &mismatch_grant,
            &mismatch_canonical,
            &display(),
            3
        ),
        Err(VaultError::Validation(_))
    ));
    assert!(vault.device_certificate(certificate_id).unwrap().is_none());
    let issuer = DeviceKeys::generate().unwrap();
    let matching_certificate = DeviceCertificateV1::issue_by_device(
        CertificateFieldsV1 {
            account_id: id(ACCOUNT_ID),
            workspace_id: id(WORKSPACE_ID),
            control_epoch: 3,
            request_nonce: request.request().request_nonce,
            device_id: request.request().device_id,
            signing_public_key: request.request().signing_public_key,
            wrapping_public_key: request.request().wrapping_public_key,
        },
        id(DEVICE_ID),
        &issuer,
    )
    .unwrap();
    let matching_id = id("018f22e2-79b0-7cc8-98c4-dc0c0c073988");
    let matching_grant = PairingGrant {
        schema_version: PAIRING_GRANT_SCHEMA_VERSION,
        pairing_id,
        request_digest: digest,
        certificate_id: matching_id,
        certificate: matching_certificate,
        key_epoch: 2,
        wrapped_key_bundle: WrappedKeyEnvelope {
            ephemeral_public_key: X25519PublicKeyBytes([9; 32]),
            nonce: XChaChaNonce([10; 24]),
            ciphertext: vec![11; 16],
        },
    };
    let matching_canonical = encode_pairing_grant_v1(&matching_grant).unwrap();
    vault
        .store_device_certificate(
            matching_id,
            &matching_grant.certificate,
            DeviceCertificateState::Active,
            &display(),
            1,
        )
        .unwrap();
    assert_eq!(
        vault
            .finish_pairing_join(
                pairing_id,
                request.canonical_bytes(),
                &matching_grant,
                &matching_canonical,
                &display(),
                3,
            )
            .unwrap(),
        CommitDisposition::Inserted
    );
    assert_eq!(
        vault
            .finish_pairing_join(
                pairing_id,
                request.canonical_bytes(),
                &matching_grant,
                &matching_canonical,
                &display(),
                3
            )
            .unwrap(),
        CommitDisposition::ExactReplay
    );
    let mut conflicting_grant = matching_grant.clone();
    conflicting_grant.key_epoch = 3;
    let conflicting_canonical = encode_pairing_grant_v1(&conflicting_grant).unwrap();
    assert!(matches!(
        vault.finish_pairing_join(
            pairing_id,
            request.canonical_bytes(),
            &conflicting_grant,
            &conflicting_canonical,
            &display(),
            3
        ),
        Err(VaultError::OperationConflict)
    ));
    let cells = vault.test_plaintext_cells().unwrap();
    assert!(cells.iter().all(|cell| {
        !cell.column.contains("code")
            && !cell.column.contains("private")
            && !cell.bytes.windows(12).any(|value| value == b"PAIRING_CODE")
    }));
    drop(vault);
    let raw = open_keyed(path.path(), &key);
    raw.execute(
        "UPDATE pairing_joins SET request_sha256 = ?2 WHERE pairing_id = ?1",
        rusqlite::params![pairing_id.to_string(), vec![0_u8; 32]],
    )
    .unwrap();
    drop(raw);
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert!(matches!(
        vault.finish_pairing_join(
            pairing_id,
            request.canonical_bytes(),
            &matching_grant,
            &matching_canonical,
            &display(),
            3,
        ),
        Err(VaultError::OperationConflict)
    ));
}

#[test]
fn device_scope_is_unique_and_listed() {
    let path = TempVault::new("device-scope-unique");
    let keys = MemoryKeyStore::default();
    let (certificate, certificate_id) = certificate();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault
        .store_device_certificate(
            certificate_id,
            &certificate,
            DeviceCertificateState::Active,
            &display(),
            1,
        )
        .unwrap();
    assert_eq!(
        vault
            .devices(context_relay_core::sync::SyncScope {
                account_id: id(ACCOUNT_ID),
                workspace_id: id(WORKSPACE_ID),
            })
            .unwrap()
            .len(),
        1
    );
    assert!(matches!(
        vault.store_device_certificate(
            id("018f22e2-79b0-7cc8-98c4-dc0c0c073989"),
            &certificate,
            DeviceCertificateState::Active,
            &display(),
            1
        ),
        Err(VaultError::OperationConflict)
    ));
}

#[test]
fn certificate_reads_reject_tampered_hash_and_duplicated_scope_metadata() {
    let path = TempVault::new("certificate-row-tamper");
    let keys = MemoryKeyStore::default();
    let key = [31; 32];
    keys.insert(CREDENTIAL, key);
    let (certificate, certificate_id) = certificate();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault
        .store_device_certificate(
            certificate_id,
            &certificate,
            DeviceCertificateState::Active,
            &display(),
            1,
        )
        .unwrap();
    drop(vault);
    let raw = open_keyed(path.path(), &key);
    raw.execute(
        "UPDATE device_certificates SET account_id = ?2 WHERE certificate_id = ?1",
        rusqlite::params![certificate_id.to_string(), WORKSPACE_ID],
    )
    .unwrap();
    drop(raw);
    let vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert!(matches!(
        vault.device_certificate(certificate_id),
        Err(VaultError::Validation(_))
    ));
    drop(vault);
    let raw = open_keyed(path.path(), &key);
    raw.execute(
        "UPDATE device_certificates SET canonical_sha256 = ?2 WHERE certificate_id = ?1",
        rusqlite::params![certificate_id.to_string(), vec![0_u8; 32]],
    )
    .unwrap();
    drop(raw);
    let vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert!(matches!(
        vault.device_certificate(certificate_id),
        Err(VaultError::Validation(_))
    ));
}

#[test]
fn approval_transcript_prepares_resumes_and_recovers_safety_number() {
    let path = TempVault::new("pairing-approval-transcript");
    let keys = MemoryKeyStore::default();
    let key = [43; 32];
    keys.insert(CREDENTIAL, key);
    let fixture = confirmation_fixture();
    let issuer_display = DeviceDisplayMetadata {
        device_name: "Existing desktop".to_owned(),
        platform: NativePlatform::Macos,
    };
    let pairing_id = id(CONFIRM_PAIRING_ID);

    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault
        .store_device_certificate(
            fixture.issuer_certificate_id,
            &fixture.issuer_certificate,
            DeviceCertificateState::Active,
            &issuer_display,
            1,
        )
        .unwrap();
    assert_eq!(
        vault
            .prepare_pairing_approval(&fixture.signed_request, &fixture.approval, 2)
            .unwrap(),
        CommitDisposition::Inserted
    );
    assert_eq!(
        vault
            .prepare_pairing_approval(&fixture.signed_request, &fixture.approval, 2)
            .unwrap(),
        CommitDisposition::ExactReplay
    );
    let pending = vault.pending_pairing_approvals().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].state, PairingApprovalState::Prepared);
    assert_eq!(
        pending[0].approval.safety_number(),
        fixture.approval.safety_number()
    );
    drop(vault);

    let mut reopened = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let resumed = reopened.pending_pairing_approvals().unwrap();
    assert_eq!(resumed.len(), 1);
    assert_eq!(
        resumed[0].approval.safety_number(),
        fixture.approval.safety_number()
    );
    let payload_hash = context_relay_protocol::Sha256Digest(
        Sha256::digest(fixture.approval.canonical_bytes()).into(),
    );
    assert_eq!(
        reopened
            .finish_pairing_approval(pairing_id, payload_hash, 3)
            .unwrap(),
        CommitDisposition::Inserted
    );
    assert_eq!(
        reopened
            .finish_pairing_approval(pairing_id, payload_hash, 3)
            .unwrap(),
        CommitDisposition::ExactReplay
    );
    let accepted = reopened
        .accepted_pairing_approval(pairing_id)
        .unwrap()
        .unwrap();
    assert_eq!(accepted.state, PairingApprovalState::Accepted);
    assert_eq!(accepted.transitioned_at_ms, Some(3));
    assert_eq!(
        accepted.approval.safety_number(),
        fixture.approval.safety_number()
    );
    drop(reopened);

    let raw = open_keyed(path.path(), &key);
    raw.execute(
        "UPDATE pairing_approval_transcripts
         SET approved_payload_sha256 = ?2 WHERE pairing_id = ?1",
        rusqlite::params![pairing_id.to_string(), vec![0_u8; 32]],
    )
    .unwrap();
    drop(raw);
    let reopened = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert!(matches!(
        reopened.accepted_pairing_approval(pairing_id),
        Err(VaultError::Validation(_))
    ));
}

#[test]
fn join_confirmation_is_durable_atomic_and_reopens_sealed_material() {
    let path = TempVault::new("pairing-join-confirmation");
    let keys = MemoryKeyStore::default();
    let fixture = confirmation_fixture();
    let pairing_id = id(CONFIRM_PAIRING_ID);

    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault
        .store_pairing_join_request(pairing_id, fixture.signed_request.canonical_bytes(), 1)
        .unwrap();
    assert_eq!(
        vault
            .store_awaiting_pairing_confirmation(
                fixture.signed_request.canonical_bytes(),
                &fixture.approval,
                2,
            )
            .unwrap(),
        CommitDisposition::Inserted
    );
    let awaiting = vault
        .awaiting_pairing_confirmation(pairing_id)
        .unwrap()
        .unwrap();
    assert_eq!(awaiting.state, PairingApprovalState::AwaitingConfirmation);
    assert_eq!(
        awaiting.approval.safety_number(),
        fixture.approval.safety_number()
    );
    assert!(vault.devices(confirmation_scope()).unwrap().is_empty());
    drop(vault);

    let mut reopened = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(
        reopened
            .awaiting_pairing_confirmation(pairing_id)
            .unwrap()
            .unwrap()
            .approval
            .safety_number(),
        fixture.approval.safety_number()
    );
    assert_eq!(
        reopened
            .finish_confirmed_pairing_join(&fixture.confirmed, 3)
            .unwrap(),
        CommitDisposition::Inserted
    );
    assert_eq!(
        reopened
            .finish_confirmed_pairing_join(&fixture.confirmed, 3)
            .unwrap(),
        CommitDisposition::ExactReplay
    );
    let reopened_material = reopened
        .completed_pairing_approval(pairing_id, &fixture.joiner_keys)
        .unwrap()
        .unwrap();
    assert_eq!(
        reopened_material.key_bundle().account_id(),
        confirmation_scope().account_id
    );
    assert_eq!(
        reopened_material.key_bundle().workspace_id(),
        confirmation_scope().workspace_id
    );
    assert_eq!(reopened_material.key_bundle().control_epoch(), 7);
    assert_eq!(reopened_material.key_bundle().key_epoch(), 11);
    let mut recovered_canary = Vec::from(reopened_material.key_bundle().workspace_root_key());
    recovered_canary.extend_from_slice(
        &reopened_material.key_bundle().active_epoch_key()[..KEY_CANARY.len() - 32],
    );
    assert_eq!(recovered_canary, KEY_CANARY);
    assert_eq!(reopened.devices(confirmation_scope()).unwrap().len(), 2);
    assert!(reopened.test_plaintext_cells().unwrap().iter().all(|cell| {
        !cell
            .bytes
            .windows(KEY_CANARY.len())
            .any(|window| window == KEY_CANARY)
    }));
    let wrong_keys = DeviceKeys::generate().unwrap();
    assert!(matches!(
        reopened.completed_pairing_approval(pairing_id, &wrong_keys),
        Err(VaultError::Validation(_))
    ));
}

#[test]
fn failed_confirmation_transaction_leaves_awaiting_without_trust() {
    let path = TempVault::new("pairing-confirmation-rollback");
    let keys = MemoryKeyStore::default();
    let key = [47; 32];
    keys.insert(CREDENTIAL, key);
    let fixture = confirmation_fixture();
    let pairing_id = id(CONFIRM_PAIRING_ID);
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault
        .store_pairing_join_request(pairing_id, fixture.signed_request.canonical_bytes(), 1)
        .unwrap();
    vault
        .store_awaiting_pairing_confirmation(
            fixture.signed_request.canonical_bytes(),
            &fixture.approval,
            2,
        )
        .unwrap();
    drop(vault);

    let raw = open_keyed(path.path(), &key);
    raw.execute_batch(
        "CREATE TRIGGER fail_pairing_confirmation
         BEFORE UPDATE OF state ON pairing_approval_transcripts
         WHEN NEW.state = 'completed'
         BEGIN
           SELECT RAISE(ABORT, 'injected pairing confirmation failure');
         END;",
    )
    .unwrap();
    drop(raw);
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert!(matches!(
        vault.finish_confirmed_pairing_join(&fixture.confirmed, 3),
        Err(VaultError::Database(_))
    ));
    drop(vault);

    let raw = open_keyed(path.path(), &key);
    assert_eq!(
        raw.query_row("SELECT count(*) FROM device_certificates", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        0
    );
    assert_eq!(
        raw.query_row(
            "SELECT state FROM pairing_approval_transcripts WHERE pairing_id = ?1",
            [pairing_id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .unwrap(),
        "awaiting_confirmation"
    );
    raw.execute_batch("DROP TRIGGER fail_pairing_confirmation;")
        .unwrap();
    drop(raw);

    let mut reopened = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(
        reopened
            .finish_confirmed_pairing_join(&fixture.confirmed, 3)
            .unwrap(),
        CommitDisposition::Inserted
    );
    assert_eq!(reopened.devices(confirmation_scope()).unwrap().len(), 2);
}

#[test]
fn confirmation_before_awaiting_cannot_install_trust() {
    let path = TempVault::new("pairing-confirm-before-awaiting");
    let keys = MemoryKeyStore::default();
    let fixture = confirmation_fixture();
    let pairing_id = id(CONFIRM_PAIRING_ID);
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    vault
        .store_pairing_join_request(pairing_id, fixture.signed_request.canonical_bytes(), 1)
        .unwrap();
    assert!(matches!(
        vault.finish_confirmed_pairing_join(&fixture.confirmed, 3),
        Err(VaultError::Validation(_)) | Err(VaultError::OperationConflict)
    ));
    assert!(vault.devices(confirmation_scope()).unwrap().is_empty());
    assert!(
        vault
            .pairing_approval_transcript(pairing_id)
            .unwrap()
            .is_none()
    );
}

#[test]
fn schema_19_reopens_to_latest_without_losing_existing_tables() {
    let path = TempVault::new("schema-19-upgrade");
    let keys = MemoryKeyStore::default();
    let key = [13; 32];
    keys.insert(CREDENTIAL, key);
    drop(Vault::open(path.path(), CREDENTIAL, &keys).unwrap());

    let raw = open_keyed(path.path(), &key);
    raw.execute_batch(
        "DROP TABLE recovery_restores;
         DROP TABLE recovery_enrollments;
         DROP TABLE pairing_approval_transcripts;
         DROP TABLE pairing_joins;
         DROP TABLE pairing_decisions;
         DROP TABLE device_certificates;",
    )
    .unwrap();
    raw.pragma_update(None, "user_version", 19).unwrap();
    drop(raw);

    let vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    assert_eq!(vault.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
    for table in [
        "records",
        "sync_record_owners",
        "recovery_enrollments",
        "device_certificates",
        "pairing_decisions",
        "pairing_joins",
        "pairing_approval_transcripts",
    ] {
        assert!(
            vault.table_names().unwrap().contains(&table.to_owned()),
            "{table}"
        );
    }
}

#[test]
fn schema_20_pairing_rows_become_terminal_legacy_unconfirmed_transcripts() {
    let path = TempVault::new("schema-20-pairing-upgrade");
    let keys = MemoryKeyStore::default();
    let key = [17; 32];
    keys.insert(CREDENTIAL, key);
    drop(Vault::open(path.path(), CREDENTIAL, &keys).unwrap());

    let decision_id = "018f22e2-79b0-7cc8-98c4-dc0c0c073991";
    let join_id = "018f22e2-79b0-7cc8-98c4-dc0c0c073992";
    let raw = open_keyed(path.path(), &key);
    raw.execute_batch(
        "PRAGMA foreign_keys = OFF;
         DROP TABLE recovery_restores;
         DROP TABLE recovery_enrollments;
         DROP TABLE pairing_approval_transcripts;
         DROP TABLE pairing_joins;
         DROP TABLE pairing_decisions;
         DROP TABLE device_certificates;",
    )
    .unwrap();
    raw.execute_batch(include_str!("../migrations/0020_device_pairing.sql"))
        .unwrap();
    raw.execute(
        "INSERT INTO pairing_decisions(pairing_id, request_digest, state, finished_at_ms)
         VALUES (?1, ?2, 'rejected', 7)",
        rusqlite::params![decision_id, vec![1_u8; 32]],
    )
    .unwrap();
    raw.execute(
        "INSERT INTO pairing_joins(
            pairing_id, canonical_request, request_sha256, state, stored_at_ms
         ) VALUES (?1, ?2, ?3, 'stored', 8)",
        rusqlite::params![join_id, b"legacy-request".as_slice(), vec![2_u8; 32]],
    )
    .unwrap();
    raw.pragma_update(None, "user_version", 20).unwrap();
    drop(raw);

    drop(Vault::open(path.path(), CREDENTIAL, &keys).unwrap());
    let raw = open_keyed(path.path(), &key);
    let rows = raw
        .prepare(
            "SELECT pairing_id, role, state, canonical_approved_payload
             FROM pairing_approval_transcripts ORDER BY pairing_id",
        )
        .unwrap()
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
            ))
        })
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        rows,
        vec![
            (
                decision_id.to_owned(),
                "approver".to_owned(),
                "legacy_unconfirmed".to_owned(),
                None,
            ),
            (
                join_id.to_owned(),
                "joiner".to_owned(),
                "legacy_unconfirmed".to_owned(),
                None,
            ),
        ]
    );
    let issuer_column: i64 = raw
        .query_row(
            "SELECT count(*) FROM pragma_table_info('pairing_joins')
             WHERE name = 'issuer_certificate_id'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(issuer_column, 1);
}

#[test]
fn schema_20_cross_role_pairing_collision_aborts_migration() {
    let path = TempVault::new("schema-20-pairing-collision");
    let keys = MemoryKeyStore::default();
    let key = [19; 32];
    keys.insert(CREDENTIAL, key);
    drop(Vault::open(path.path(), CREDENTIAL, &keys).unwrap());

    let pairing_id = "018f22e2-79b0-7cc8-98c4-dc0c0c073993";
    let raw = open_keyed(path.path(), &key);
    raw.execute_batch(
        "PRAGMA foreign_keys = OFF;
         DROP TABLE recovery_restores;
         DROP TABLE recovery_enrollments;
         DROP TABLE pairing_approval_transcripts;
         DROP TABLE pairing_joins;
         DROP TABLE pairing_decisions;
         DROP TABLE device_certificates;",
    )
    .unwrap();
    raw.execute_batch(include_str!("../migrations/0020_device_pairing.sql"))
        .unwrap();
    raw.execute(
        "INSERT INTO pairing_decisions(pairing_id, request_digest, state, finished_at_ms)
         VALUES (?1, ?2, 'rejected', 7)",
        rusqlite::params![pairing_id, vec![1_u8; 32]],
    )
    .unwrap();
    raw.execute(
        "INSERT INTO pairing_joins(
            pairing_id, canonical_request, request_sha256, state, stored_at_ms
         ) VALUES (?1, ?2, ?3, 'stored', 8)",
        rusqlite::params![pairing_id, b"legacy-request".as_slice(), vec![2_u8; 32]],
    )
    .unwrap();
    raw.pragma_update(None, "user_version", 20).unwrap();
    drop(raw);

    assert!(matches!(
        Vault::open(path.path(), CREDENTIAL, &keys),
        Err(VaultError::Migration(_))
    ));
    let raw = open_keyed(path.path(), &key);
    let version: u32 = raw
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 20);
}
