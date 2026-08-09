use std::{cell::Cell, str::FromStr};

use context_relay_core::{
    crypto::{
        CertificateIssuerV1, ContentKey, CryptoError, DeviceCertificateV1, DeviceKeys,
        EncryptedPayload, SecretBytes,
    },
    sync::{
        OperationBuildRequest, OperationBuilder, OperationChainHead, OperationDecryptor,
        SyncIdentity, TrustedOperationContext, verify_operation_envelope,
    },
};
use context_relay_protocol::{
    BlobRef, BoundedCiphertext, DeviceId, DeviceSequence, Ed25519SignatureBytes,
    HybridLogicalClock, MemoryKind, MemoryOrigin, MemoryRecord, MutationKind, PairingRequestNonce,
    Provenance, RecordKind, RecordMutationV1, SYNC_SCHEMA_VERSION, ScopeRef, Sha256Digest,
    SyncOperationV1, XChaChaNonce, encode_record_mutation_v1, encode_sync_operation_aad_v1,
};
use sha2::{Digest, Sha256};

const PRIMARY_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07398f";
const FLIPPED_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07398e";
const OTHER_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073990";

struct Fixture {
    content_key: ContentKey,
    certificate: DeviceCertificateV1,
    operation: SyncOperationV1,
    mutation: RecordMutationV1,
}

struct CountingDecryptor<'a> {
    calls: Cell<usize>,
    key: &'a ContentKey,
}

impl<'a> CountingDecryptor<'a> {
    fn new(key: &'a ContentKey) -> Self {
        Self {
            calls: Cell::new(0),
            key,
        }
    }

    fn calls(&self) -> usize {
        self.calls.get()
    }
}

impl OperationDecryptor for CountingDecryptor<'_> {
    fn decrypt(
        &self,
        encrypted: &EncryptedPayload,
        aad: &[u8],
    ) -> Result<SecretBytes, CryptoError> {
        self.calls.set(self.calls.get() + 1);
        self.key.decrypt(encrypted, aad)
    }
}

#[test]
fn public_builder_and_verifier_round_trip_without_exposing_keys() {
    let fixture = fixture();
    let trusted = TrustedOperationContext::new(&fixture.certificate, 11, None);
    let probe = CountingDecryptor::new(&fixture.content_key);

    let decoded = verify_operation_envelope(&fixture.operation, &trusted, &probe).unwrap();

    assert_eq!(decoded, fixture.mutation);
    assert_eq!(probe.calls(), 1);
    assert_eq!(fixture.operation.device_sequence, 1);
    assert_eq!(
        fixture.operation.previous_device_hash,
        Sha256Digest([0; 32])
    );
}

#[test]
fn every_signed_or_aad_bound_field_rejects_tampering_before_plaintext() {
    type Mutator = fn(&mut SyncOperationV1);
    let mutators: &[(&str, Mutator)] = &[
        ("schema_version", |value| value.schema_version ^= 1),
        ("operation_id", |value| value.operation_id = id(FLIPPED_ID)),
        ("account_id", |value| value.account_id = id(FLIPPED_ID)),
        ("workspace_id", |value| value.workspace_id = id(FLIPPED_ID)),
        ("project_id", |value| {
            value.project_id = Some(id(PRIMARY_ID))
        }),
        ("record_id", |value| value.record_id = id(FLIPPED_ID)),
        ("record_kind", |value| value.record_kind = RecordKind::Task),
        ("mutation_kind", |value| {
            value.mutation_kind = context_relay_protocol::MutationKind::Tombstone
        }),
        ("device_id", |value| value.device_id = id(FLIPPED_ID)),
        ("device_sequence", |value| value.device_sequence ^= 1),
        ("frontier_device", |value| {
            value.causal_frontier[0].device_id = id(FLIPPED_ID)
        }),
        ("frontier_sequence", |value| {
            value.causal_frontier[0].sequence ^= 1
        }),
        ("control_epoch", |value| value.control_epoch ^= 1),
        ("key_epoch", |value| value.key_epoch ^= 1),
        ("previous_device_hash", |value| {
            value.previous_device_hash.0[0] ^= 1
        }),
        ("nonce", |value| value.nonce.0[0] ^= 1),
        ("ciphertext", |value| {
            let mut bytes = value.ciphertext.as_slice().to_vec();
            bytes[0] ^= 1;
            value.ciphertext = BoundedCiphertext::new(bytes).unwrap();
        }),
        ("ciphertext_hash", |value| value.ciphertext_hash.0[0] ^= 1),
        ("blob_digest", |value| value.blob_refs[0].digest.0[0] ^= 1),
        ("blob_size", |value| {
            value.blob_refs[0].ciphertext_bytes ^= 1
        }),
        ("blob_storage", |value| {
            value.blob_refs[0].storage_id = "clob-1".into()
        }),
        ("created_hlc_physical", |value| {
            value.created_hlc.physical_ms ^= 1
        }),
        ("created_hlc_logical", |value| {
            value.created_hlc.logical ^= 1
        }),
        ("created_hlc_node", |value| {
            value.created_hlc.node = id(FLIPPED_ID)
        }),
        ("signature", |value| value.signature.0[0] ^= 1),
    ];

    for (name, mutate) in mutators {
        let fixture = fixture();
        let mut candidate = fixture.operation;
        mutate(&mut candidate);
        let trusted = TrustedOperationContext::new(&fixture.certificate, 11, None);
        let probe = CountingDecryptor::new(&fixture.content_key);

        assert!(
            verify_operation_envelope(&candidate, &trusted, &probe).is_err(),
            "tampering with {name} was accepted"
        );
        assert_eq!(probe.calls(), 0, "{name} reached plaintext decryption");
    }
}

#[test]
fn certificate_epoch_and_chain_mismatches_fail_before_decryption() {
    let fixture = fixture();

    let mut wrong_certificate = fixture.certificate.clone();
    wrong_certificate.account_id = id(FLIPPED_ID);
    let probe = CountingDecryptor::new(&fixture.content_key);
    assert!(
        verify_operation_envelope(
            &fixture.operation,
            &TrustedOperationContext::new(&wrong_certificate, 11, None),
            &probe,
        )
        .is_err()
    );
    assert_eq!(probe.calls(), 0);

    let probe = CountingDecryptor::new(&fixture.content_key);
    assert!(
        verify_operation_envelope(
            &fixture.operation,
            &TrustedOperationContext::new(&fixture.certificate, 10, None),
            &probe,
        )
        .is_err()
    );
    assert_eq!(probe.calls(), 0);

    let probe = CountingDecryptor::new(&fixture.content_key);
    assert!(
        verify_operation_envelope(
            &fixture.operation,
            &TrustedOperationContext::new(
                &fixture.certificate,
                11,
                Some(OperationChainHead {
                    sequence: 9,
                    canonical_hash: Sha256Digest([44; 32]),
                }),
            ),
            &probe,
        )
        .is_err()
    );
    assert_eq!(probe.calls(), 0);
}

#[test]
fn tombstone_without_trusted_existing_scope_rejects_before_decryption() {
    let fixture = tombstone_fixture(id(PRIMARY_ID), RecordKind::Memory, None);
    let trusted = TrustedOperationContext::new(&fixture.certificate, 11, None);
    let probe = CountingDecryptor::new(&fixture.content_key);

    assert!(verify_operation_envelope(&fixture.operation, &trusted, &probe).is_err());
    assert_eq!(probe.calls(), 0);
}

#[test]
fn tombstone_with_matching_trusted_scope_round_trips() {
    let fixture = tombstone_fixture(id(PRIMARY_ID), RecordKind::Memory, None);
    let trusted = TrustedOperationContext::new(&fixture.certificate, 11, None)
        .with_existing_record_scope(ScopeRef::Global);
    let probe = CountingDecryptor::new(&fixture.content_key);

    assert_eq!(
        verify_operation_envelope(&fixture.operation, &trusted, &probe).unwrap(),
        fixture.mutation
    );
    assert_eq!(probe.calls(), 1);
}

#[test]
fn tombstone_with_mismatched_trusted_scope_rejects_before_decryption() {
    let fixture = tombstone_fixture(id(PRIMARY_ID), RecordKind::Memory, None);
    let trusted = TrustedOperationContext::new(&fixture.certificate, 11, None)
        .with_existing_record_scope(ScopeRef::Project {
            project_id: id(OTHER_ID),
        });
    let probe = CountingDecryptor::new(&fixture.content_key);

    assert!(verify_operation_envelope(&fixture.operation, &trusted, &probe).is_err());
    assert_eq!(probe.calls(), 0);
}

#[test]
fn project_tombstone_record_id_must_match_outer_project_before_decryption() {
    let fixture =
        signed_tombstone_fixture_unchecked(id(PRIMARY_ID), RecordKind::Project, Some(id(OTHER_ID)));
    let trusted = TrustedOperationContext::new(&fixture.certificate, 11, None)
        .with_existing_record_scope(ScopeRef::Project {
            project_id: id(OTHER_ID),
        });
    let probe = CountingDecryptor::new(&fixture.content_key);

    assert!(verify_operation_envelope(&fixture.operation, &trusted, &probe).is_err());
    assert_eq!(probe.calls(), 0);
}

#[test]
fn builder_rejects_project_tombstone_routed_under_another_project() {
    let keys = DeviceKeys::generate().unwrap();
    let content_key = ContentKey::from_bytes([32; 32]);
    let builder = OperationBuilder::new(identity(&keys, &content_key));
    let mutation = RecordMutationV1::Tombstone {
        record_id: id(PRIMARY_ID),
        record_kind: RecordKind::Project,
    };

    assert!(
        builder
            .build(OperationBuildRequest {
                operation_id: id(FLIPPED_ID),
                project_id: Some(id(OTHER_ID)),
                mutation: &mutation,
                causal_frontier: vec![],
                previous: None,
                blob_refs: vec![],
                created_hlc: HybridLogicalClock::new(1_700_000_000_100, 0, id(PRIMARY_ID)),
            })
            .is_err()
    );
}

#[test]
fn builder_sorts_frontier_and_rejects_duplicate_devices() {
    let keys = DeviceKeys::generate().unwrap();
    let content_key = ContentKey::from_bytes([31; 32]);
    let identity = identity(&keys, &content_key);
    let builder = OperationBuilder::new(identity);
    let earlier: DeviceId = id(FLIPPED_ID);
    let later: DeviceId = id(OTHER_ID);

    let built = builder
        .build(OperationBuildRequest {
            operation_id: id(OTHER_ID),
            project_id: None,
            mutation: &mutation(),
            causal_frontier: vec![
                DeviceSequence {
                    device_id: later,
                    sequence: 3,
                },
                DeviceSequence {
                    device_id: earlier,
                    sequence: 2,
                },
            ],
            previous: None,
            blob_refs: vec![],
            created_hlc: HybridLogicalClock::new(1_700_000_000_100, 0, id(PRIMARY_ID)),
        })
        .unwrap();
    assert_eq!(built.operation.causal_frontier[0].device_id, earlier);
    assert_eq!(built.operation.causal_frontier[1].device_id, later);

    assert!(
        builder
            .build(OperationBuildRequest {
                operation_id: id(OTHER_ID),
                project_id: None,
                mutation: &mutation(),
                causal_frontier: vec![
                    DeviceSequence {
                        device_id: earlier,
                        sequence: 2,
                    },
                    DeviceSequence {
                        device_id: earlier,
                        sequence: 3,
                    },
                ],
                previous: None,
                blob_refs: vec![],
                created_hlc: HybridLogicalClock::new(1_700_000_000_100, 0, id(PRIMARY_ID)),
            })
            .is_err()
    );
}

fn fixture() -> Fixture {
    let keys = DeviceKeys::generate().unwrap();
    let content_key = ContentKey::from_bytes([31; 32]);
    let certificate = certificate(&keys);
    let mutation = mutation();
    let identity = identity(&keys, &content_key);
    let built = OperationBuilder::new(identity)
        .build(OperationBuildRequest {
            operation_id: id(OTHER_ID),
            project_id: None,
            mutation: &mutation,
            causal_frontier: vec![DeviceSequence {
                device_id: id(OTHER_ID),
                sequence: 7,
            }],
            previous: None,
            blob_refs: vec![BlobRef {
                digest: Sha256Digest([41; 32]),
                ciphertext_bytes: 512,
                storage_id: "blob-1".into(),
            }],
            created_hlc: HybridLogicalClock::new(1_700_000_000_100, 2, id(PRIMARY_ID)),
        })
        .unwrap();
    Fixture {
        content_key,
        certificate,
        operation: built.operation,
        mutation,
    }
}

fn tombstone_fixture(
    record_id: context_relay_protocol::RecordId,
    record_kind: RecordKind,
    project_id: Option<context_relay_protocol::ProjectId>,
) -> Fixture {
    let keys = DeviceKeys::generate().unwrap();
    let content_key = ContentKey::from_bytes([32; 32]);
    let certificate = certificate(&keys);
    let mutation = RecordMutationV1::Tombstone {
        record_id,
        record_kind,
    };
    let built = OperationBuilder::new(identity(&keys, &content_key))
        .build(OperationBuildRequest {
            operation_id: id(FLIPPED_ID),
            project_id,
            mutation: &mutation,
            causal_frontier: vec![],
            previous: None,
            blob_refs: vec![],
            created_hlc: HybridLogicalClock::new(1_700_000_000_100, 0, id(PRIMARY_ID)),
        })
        .unwrap();
    Fixture {
        content_key,
        certificate,
        operation: built.operation,
        mutation,
    }
}

fn signed_tombstone_fixture_unchecked(
    record_id: context_relay_protocol::RecordId,
    record_kind: RecordKind,
    project_id: Option<context_relay_protocol::ProjectId>,
) -> Fixture {
    let keys = DeviceKeys::generate().unwrap();
    let content_key = ContentKey::from_bytes([33; 32]);
    let certificate = certificate(&keys);
    let mutation = RecordMutationV1::Tombstone {
        record_id,
        record_kind,
    };
    let mut operation = SyncOperationV1 {
        schema_version: SYNC_SCHEMA_VERSION,
        operation_id: id(FLIPPED_ID),
        account_id: id(PRIMARY_ID),
        workspace_id: id(OTHER_ID),
        project_id,
        record_id,
        record_kind,
        mutation_kind: MutationKind::Tombstone,
        device_id: id(PRIMARY_ID),
        device_sequence: 1,
        causal_frontier: vec![],
        control_epoch: 5,
        key_epoch: 11,
        previous_device_hash: Sha256Digest([0; 32]),
        nonce: XChaChaNonce([0; 24]),
        ciphertext: BoundedCiphertext::new(vec![]).unwrap(),
        ciphertext_hash: Sha256Digest([0; 32]),
        blob_refs: vec![],
        created_hlc: HybridLogicalClock::new(1_700_000_000_100, 0, id(PRIMARY_ID)),
        signature: Ed25519SignatureBytes([0; 64]),
    };
    let aad = encode_sync_operation_aad_v1(&operation).unwrap();
    let plaintext = encode_record_mutation_v1(&mutation).unwrap();
    let encrypted = content_key.encrypt(&plaintext, &aad).unwrap();
    operation.nonce = encrypted.nonce;
    operation.ciphertext = BoundedCiphertext::new(encrypted.ciphertext).unwrap();
    operation.ciphertext_hash =
        Sha256Digest(Sha256::digest(operation.ciphertext.as_slice()).into());
    keys.sign_sync_operation(&mut operation).unwrap();
    Fixture {
        content_key,
        certificate,
        operation,
        mutation,
    }
}

fn identity<'a>(keys: &'a DeviceKeys, content_key: &'a ContentKey) -> SyncIdentity<'a> {
    SyncIdentity {
        account_id: id(PRIMARY_ID),
        workspace_id: id(OTHER_ID),
        device_id: id(PRIMARY_ID),
        control_epoch: 5,
        key_epoch: 11,
        device_keys: keys,
        content_key,
    }
}

fn certificate(keys: &DeviceKeys) -> DeviceCertificateV1 {
    DeviceCertificateV1 {
        issuer: CertificateIssuerV1::Device {
            device_id: id(OTHER_ID),
            signing_public_key: keys.signing_public_key(),
        },
        account_id: id(PRIMARY_ID),
        workspace_id: id(OTHER_ID),
        control_epoch: 5,
        request_nonce: PairingRequestNonce([19; 32]),
        device_id: id(PRIMARY_ID),
        signing_public_key: keys.signing_public_key(),
        wrapping_public_key: keys.wrapping_public_key(),
        signature: Ed25519SignatureBytes([0; 64]),
    }
}

fn mutation() -> RecordMutationV1 {
    let device_id = id(PRIMARY_ID);
    let clock = HybridLogicalClock::new(1_700_000_000_000, 1, device_id);
    RecordMutationV1::UpsertMemory(MemoryRecord {
        id: id(PRIMARY_ID),
        scope: ScopeRef::Global,
        kind: MemoryKind::Fact,
        title: "Encrypted title".into(),
        body_markdown: "private sync payload marker".into(),
        tags: vec!["sync".into()],
        origin: MemoryOrigin::Explicit,
        provenance: Provenance {
            origin_device: device_id,
            harness: None,
            source: None,
            created_hlc: clock,
        },
        revision: id(PRIMARY_ID),
        created_hlc: clock,
        updated_hlc: clock,
        archived: false,
    })
}

fn id<T: FromStr>(value: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    value.parse().unwrap()
}
