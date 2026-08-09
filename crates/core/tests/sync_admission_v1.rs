mod support;

use std::{cell::Cell, collections::BTreeMap, str::FromStr};

use context_relay_core::{
    crypto::{CertificateIssuerV1, ContentKey, DeviceCertificateV1, DeviceKeys},
    sync::{
        AdmissionDecision, OperationBuildRequest, OperationBuilder, OperationChainHead, SyncError,
        SyncIdentity, TrustedDevice, TrustedSyncMaterial, admit_operation,
    },
    vault::Vault,
};
use context_relay_protocol::{
    AccountId, BoundedCiphertext, DeviceId, DeviceSequence, Ed25519SignatureBytes,
    HybridLogicalClock, OperationId, PairingRequestNonce, RecordKind, RecordMutationV1, SecretRef,
    SecretRefId, Sha256Digest, SyncOperationV1, WorkspaceId, encode_record_mutation_v1,
    encode_sync_operation_aad_v1, encode_sync_operation_v1,
};
use sha2::{Digest, Sha256};

use support::{ID_1, ID_2, ID_3, ID_4, ID_5, ID_6, ID_7, ID_8, MemoryKeyStore, TempVault};

const CREDENTIAL: &str = "sync-admission-v1";
const CONTROL_EPOCH: u32 = 5;
const KEY_EPOCH: u32 = 11;

#[test]
fn admission_decision_is_not_dominated_by_the_admitted_payload() {
    assert!(
        std::mem::size_of::<AdmissionDecision>() <= 32,
        "AdmissionDecision grew to {} bytes",
        std::mem::size_of::<AdmissionDecision>()
    );
}

struct DeviceFixture {
    keys: DeviceKeys,
    certificate: DeviceCertificateV1,
}

struct Trust {
    devices: BTreeMap<DeviceId, DeviceCertificateV1>,
    key: ContentKey,
    control_epoch: u32,
    key_epoch: u32,
    key_requests: Cell<usize>,
}

impl Trust {
    fn new(devices: &[&DeviceFixture], key: ContentKey) -> Self {
        Self {
            devices: devices
                .iter()
                .map(|device| (device.certificate.device_id, device.certificate.clone()))
                .collect(),
            key,
            control_epoch: CONTROL_EPOCH,
            key_epoch: KEY_EPOCH,
            key_requests: Cell::new(0),
        }
    }
}

impl TrustedSyncMaterial for Trust {
    fn trusted_device(
        &self,
        _account: AccountId,
        _workspace: WorkspaceId,
        device: DeviceId,
    ) -> Result<TrustedDevice, SyncError> {
        Ok(TrustedDevice {
            certificate: self
                .devices
                .get(&device)
                .cloned()
                .ok_or(SyncError::InvalidIdentity)?,
            active_control_epoch: self.control_epoch,
            active_key_epoch: self.key_epoch,
        })
    }

    fn content_key(
        &self,
        _workspace: WorkspaceId,
        _key_epoch: u32,
    ) -> Result<&ContentKey, SyncError> {
        self.key_requests.set(self.key_requests.get() + 1);
        Ok(&self.key)
    }
}

#[test]
fn admission_matrix_rejects_every_predecrypt_failure_without_requesting_the_key() {
    type Case = (&'static str, Box<dyn Fn(&mut SyncOperationV1, &DeviceKeys)>);
    let device = device(ID_3, 31);
    let content_key = ContentKey::from_bytes([41; 32]);
    let mutation = secret(ID_6, "baseline");
    let baseline = build(&device, &content_key, ID_7, &mutation, vec![], None);
    let cases: Vec<Case> = vec![
        (
            "bad signature",
            Box::new(|operation, _| operation.signature.0[0] ^= 1),
        ),
        (
            "bad ciphertext hash",
            Box::new(|operation, keys| {
                operation.ciphertext_hash.0[0] ^= 1;
                keys.sign_sync_operation(operation).unwrap();
            }),
        ),
        (
            "wrong epoch",
            Box::new(|operation, keys| {
                operation.key_epoch += 1;
                keys.sign_sync_operation(operation).unwrap();
            }),
        ),
        (
            "bad frontier",
            Box::new(|operation, keys| {
                operation.causal_frontier = vec![DeviceSequence {
                    device_id: operation.device_id,
                    sequence: 1,
                }];
                keys.sign_sync_operation(operation).unwrap();
            }),
        ),
    ];

    for (name, mutate) in cases {
        let path = TempVault::new(name);
        let keys = MemoryKeyStore::default();
        let vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
        let mut operation = baseline.operation.clone();
        mutate(&mut operation, &device.keys);
        let bytes = encode_sync_operation_v1(&operation).unwrap();
        let trust = Trust::new(&[&device], ContentKey::from_bytes([41; 32]));
        assert!(admit_operation(&vault, &bytes, &trust).is_err(), "{name}");
        assert_eq!(trust.key_requests.get(), 0, "{name} reached decryption");
    }
}

#[test]
fn stored_replay_sequence_chain_gap_and_frontier_checks_precede_decryption() {
    let path = TempVault::new("admission-stored-matrix");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let device_a = device(ID_3, 31);
    let device_b = device(ID_4, 32);
    let key = ContentKey::from_bytes([42; 32]);
    let first_mutation = secret(ID_6, "first");
    let first = build(&device_a, &key, ID_7, &first_mutation, vec![], None);
    vault
        .commit_outgoing_operation(&first_mutation, &first, None)
        .unwrap();

    let exact_trust = Trust::new(&[&device_a], ContentKey::from_bytes([42; 32]));
    assert!(matches!(
        admit_operation(&vault, &first.canonical_bytes, &exact_trust).unwrap(),
        AdmissionDecision::ExactReplay(id) if id == first.operation.operation_id
    ));
    assert_eq!(exact_trust.key_requests.get(), 0);

    let altered = build(
        &device_a,
        &key,
        ID_7,
        &secret(ID_6, "altered"),
        vec![],
        None,
    );
    let reused = build(&device_a, &key, ID_5, &secret(ID_5, "reused"), vec![], None);
    let broken = build(
        &device_a,
        &key,
        ID_5,
        &secret(ID_5, "broken"),
        vec![],
        Some(OperationChainHead {
            sequence: 1,
            canonical_hash: Sha256Digest([99; 32]),
        }),
    );
    let gap = build(
        &device_a,
        &key,
        ID_5,
        &secret(ID_5, "gap"),
        vec![],
        Some(OperationChainHead {
            sequence: 2,
            canonical_hash: Sha256Digest([88; 32]),
        }),
    );
    let unknown_frontier = build(
        &device_b,
        &key,
        ID_5,
        &secret(ID_5, "frontier"),
        vec![DeviceSequence {
            device_id: id(ID_2),
            sequence: 1,
        }],
        None,
    );

    for (name, bytes, is_gap, trusted_device) in [
        (
            "altered operation id",
            altered.canonical_bytes,
            false,
            &device_a,
        ),
        (
            "reused device sequence",
            reused.canonical_bytes,
            false,
            &device_a,
        ),
        (
            "broken previous hash",
            broken.canonical_bytes,
            false,
            &device_a,
        ),
        ("missing gap", gap.canonical_bytes, true, &device_a),
        (
            "unknown frontier",
            unknown_frontier.canonical_bytes,
            false,
            &device_b,
        ),
    ] {
        let trust = Trust::new(&[trusted_device], ContentKey::from_bytes([42; 32]));
        let result = admit_operation(&vault, &bytes, &trust);
        if is_gap {
            assert!(
                matches!(result, Ok(AdmissionDecision::Gap(range)) if range == (2..=2)),
                "{name}"
            );
        } else {
            assert!(result.is_err(), "{name}");
        }
        assert_eq!(trust.key_requests.get(), 0, "{name} reached decryption");
    }
}

#[test]
fn decryption_and_payload_agreement_fail_closed_after_all_public_checks() {
    let path = TempVault::new("admission-plaintext-matrix");
    let keys = MemoryKeyStore::default();
    let vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let device = device(ID_3, 31);
    let key = ContentKey::from_bytes([43; 32]);
    let mutation = secret(ID_6, "plaintext");
    let built = build(&device, &key, ID_7, &mutation, vec![], None);

    let wrong_key = Trust::new(&[&device], ContentKey::from_bytes([44; 32]));
    assert_eq!(
        admit_operation(&vault, &built.canonical_bytes, &wrong_key).unwrap_err(),
        SyncError::DecryptionFailed
    );
    assert_eq!(wrong_key.key_requests.get(), 1);

    let mut mismatch = built.operation;
    mismatch.record_id = id(ID_5);
    reseal_with_plaintext(&mut mismatch, &device.keys, &key, &mutation);
    let trust = Trust::new(&[&device], ContentKey::from_bytes([43; 32]));
    assert_eq!(
        admit_operation(
            &vault,
            &encode_sync_operation_v1(&mismatch).unwrap(),
            &trust
        )
        .unwrap_err(),
        SyncError::InvalidMutation
    );
    assert_eq!(trust.key_requests.get(), 1);
}

#[test]
fn exact_tombstone_replay_does_not_require_the_already_deleted_materialized_scope() {
    let path = TempVault::new("admission-tombstone-replay");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let device = device(ID_3, 35);
    let key = ContentKey::from_bytes([45; 32]);
    let upsert = secret(ID_6, "before delete");
    let first = build(&device, &key, ID_7, &upsert, vec![], None);
    vault
        .commit_outgoing_operation(&upsert, &first, None)
        .unwrap();
    let tombstone = RecordMutationV1::Tombstone {
        record_id: upsert.record_id(),
        record_kind: RecordKind::SecretRef,
    };
    let deleted = build(
        &device,
        &key,
        ID_8,
        &tombstone,
        vec![],
        Some(OperationChainHead {
            sequence: 1,
            canonical_hash: first.canonical_hash,
        }),
    );
    vault
        .commit_outgoing_operation(&tombstone, &deleted, None)
        .unwrap();
    let trust = Trust::new(&[&device], ContentKey::from_bytes([45; 32]));

    assert!(matches!(
        admit_operation(&vault, &deleted.canonical_bytes, &trust).unwrap(),
        AdmissionDecision::ExactReplay(id) if id == deleted.operation.operation_id
    ));
    assert_eq!(trust.key_requests.get(), 0);
}

#[test]
fn tombstone_gap_is_reported_before_missing_materialized_scope() {
    let path = TempVault::new("admission-tombstone-gap");
    let keys = MemoryKeyStore::default();
    let vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let device = device(ID_3, 36);
    let key = ContentKey::from_bytes([46; 32]);
    let tombstone = RecordMutationV1::Tombstone {
        record_id: id(ID_6),
        record_kind: RecordKind::SecretRef,
    };
    let incoming = build(
        &device,
        &key,
        ID_8,
        &tombstone,
        vec![],
        Some(OperationChainHead {
            sequence: 2,
            canonical_hash: Sha256Digest([91; 32]),
        }),
    );
    let trust = Trust::new(&[&device], ContentKey::from_bytes([46; 32]));

    assert!(matches!(
        admit_operation(&vault, &incoming.canonical_bytes, &trust),
        Ok(AdmissionDecision::Gap(range)) if range == (1..=2)
    ));
    assert_eq!(trust.key_requests.get(), 0);
}

#[test]
fn zero_sequence_frontier_rejects_before_content_key_access() {
    let path = TempVault::new("admission-zero-frontier");
    let keys = MemoryKeyStore::default();
    let mut vault = Vault::open(path.path(), CREDENTIAL, &keys).unwrap();
    let device_a = device(ID_3, 37);
    let device_b = device(ID_4, 38);
    let key = ContentKey::from_bytes([47; 32]);
    let known_mutation = secret(ID_5, "known frontier");
    let known = build(&device_b, &key, ID_7, &known_mutation, vec![], None);
    vault
        .commit_outgoing_operation(&known_mutation, &known, None)
        .unwrap();

    let mutation = secret(ID_6, "zero frontier");
    let mut incoming = build(&device_a, &key, ID_8, &mutation, vec![], None).operation;
    incoming.causal_frontier = vec![DeviceSequence {
        device_id: device_b.certificate.device_id,
        sequence: 0,
    }];
    reseal_with_plaintext(&mut incoming, &device_a.keys, &key, &mutation);
    let trust = Trust::new(&[&device_a], ContentKey::from_bytes([47; 32]));

    assert_eq!(
        admit_operation(
            &vault,
            &encode_sync_operation_v1(&incoming).unwrap(),
            &trust
        )
        .unwrap_err(),
        SyncError::InvalidFrontier
    );
    assert_eq!(trust.key_requests.get(), 0);
}

#[test]
fn sync_errors_expose_only_stable_allowlisted_codes() {
    for error in [
        SyncError::InvalidEnvelope,
        SyncError::InvalidIdentity,
        SyncError::InvalidChain,
        SyncError::InvalidFrontier,
        SyncError::InvalidScope,
        SyncError::AuthenticationFailed,
        SyncError::DecryptionFailed,
        SyncError::InvalidMutation,
    ] {
        assert!(matches!(
            error.safe_code(),
            "integrity_quarantined" | "revoked" | "gap_pending" | "transient"
        ));
        assert!(!error.safe_code().contains(' '));
    }
}

fn device(device_id: &str, seed: u8) -> DeviceFixture {
    let keys = DeviceKeys::generate().unwrap();
    DeviceFixture {
        certificate: DeviceCertificateV1 {
            issuer: CertificateIssuerV1::Device {
                device_id: id(ID_1),
                signing_public_key: keys.signing_public_key(),
            },
            account_id: id(ID_1),
            workspace_id: id(ID_2),
            control_epoch: CONTROL_EPOCH,
            request_nonce: PairingRequestNonce([seed; 32]),
            device_id: id(device_id),
            signing_public_key: keys.signing_public_key(),
            wrapping_public_key: keys.wrapping_public_key(),
            signature: Ed25519SignatureBytes([0; 64]),
        },
        keys,
    }
}

fn secret(id_value: &str, name: &str) -> RecordMutationV1 {
    RecordMutationV1::UpsertSecretRef(SecretRef {
        id: id::<SecretRefId>(id_value),
        name: name.to_owned(),
        provider: "local-keychain".to_owned(),
        required_on_device: true,
    })
}

fn build(
    device: &DeviceFixture,
    key: &ContentKey,
    operation_id: &str,
    mutation: &RecordMutationV1,
    frontier: Vec<DeviceSequence>,
    previous: Option<OperationChainHead>,
) -> context_relay_core::sync::BuiltOperation {
    OperationBuilder::new(SyncIdentity {
        account_id: id(ID_1),
        workspace_id: id(ID_2),
        device_id: device.certificate.device_id,
        control_epoch: CONTROL_EPOCH,
        key_epoch: KEY_EPOCH,
        device_keys: &device.keys,
        content_key: key,
    })
    .build(OperationBuildRequest {
        operation_id: id::<OperationId>(operation_id),
        project_id: None,
        mutation,
        causal_frontier: frontier,
        previous,
        blob_refs: vec![],
        created_hlc: HybridLogicalClock::new(1_700_000_000_000, 0, device.certificate.device_id),
    })
    .unwrap()
}

fn reseal_with_plaintext(
    operation: &mut SyncOperationV1,
    keys: &DeviceKeys,
    key: &ContentKey,
    mutation: &RecordMutationV1,
) {
    operation.nonce = context_relay_protocol::XChaChaNonce([0; 24]);
    operation.ciphertext = BoundedCiphertext::new(Vec::new()).unwrap();
    operation.ciphertext_hash = Sha256Digest([0; 32]);
    operation.signature = Ed25519SignatureBytes([0; 64]);
    let aad = encode_sync_operation_aad_v1(operation).unwrap();
    let plaintext = encode_record_mutation_v1(mutation).unwrap();
    let encrypted = key.encrypt(&plaintext, &aad).unwrap();
    operation.nonce = encrypted.nonce;
    operation.ciphertext = BoundedCiphertext::new(encrypted.ciphertext).unwrap();
    operation.ciphertext_hash =
        Sha256Digest(Sha256::digest(operation.ciphertext.as_slice()).into());
    keys.sign_sync_operation(operation).unwrap();
}

fn id<T: FromStr>(value: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    value.parse().unwrap()
}
