use std::str::FromStr;

use context_relay_core::{
    crypto::{CertificateFieldsV1, DeviceCertificateV1, DeviceKeys, RecoveryKeys, RecoveryPhrase},
    devices::{
        crypto::{
            MAX_PAIRING_APPROVED_PAYLOAD_BYTES, PairingApprovedPayloadV1, PairingGrantApproval,
            PairingKeyBundle, SignedPairingRequest, build_pairing_approved_payload_v1,
            build_pairing_grant, encode_pairing_approved_payload_v1, encode_pairing_grant_v1,
        },
        memory_transport::InMemoryPairingProvider,
        transport::{
            PairingApprovalTransport, PairingDecisionEnvelope, PairingInviteState,
            PairingJoinTransport, PairingResult, PairingTransportError,
        },
    },
    sync::SyncScope,
};
use context_relay_protocol::{
    DeviceId, NativePlatform, PairingCode, PairingRequestNonce, RecoveryPhraseWords, Sha256Digest,
};
use sha2::{Digest, Sha256};

const ACCOUNT_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07398f";
const WORKSPACE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07398e";
const OTHER_ACCOUNT_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073980";
const ISSUER_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07398b";
const OTHER_ISSUER_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073989";
const JOINER_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07398c";
const CERTIFICATE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07398a";
const OTHER_CERTIFICATE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073988";
const ISSUER_CERTIFICATE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073987";
const OTHER_ISSUER_CERTIFICATE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073986";
const CANARY: &str = "TASK17_PAIRING_CANARY";

#[test]
fn codes_have_exact_crockford_shape_and_expire_at_the_exact_boundary() {
    let provider = provider();
    let approval = provider.existing_device_client(scope(), id(ISSUER_ID));
    let join = provider.join_session_client("join-expiry").unwrap();
    let invite = approval.create_invite(1_000).unwrap();

    assert_eq!(invite.code.as_str().len(), 11);
    assert_eq!(invite.code.as_str().as_bytes()[5], b'-');
    assert_eq!(
        invite
            .code
            .as_str()
            .bytes()
            .filter(|byte| *byte != b'-')
            .count(),
        10
    );
    assert!(invite.code.as_str().bytes().all(|byte| matches!(
        byte,
        b'-' | b'0'..=b'9' | b'A'..=b'H' | b'J'..=b'K' | b'M'..=b'N' | b'P'..=b'T' | b'V'..=b'Z'
    )));
    assert_eq!(invite.created_at_ms, 1_000);
    assert_eq!(invite.expires_at_ms, 601_000);
    assert_eq!(
        &invite.pairing_id.as_bytes()[..6],
        &invite.created_at_ms.to_be_bytes()[2..]
    );
    assert_eq!(
        join.resolve_code(&invite.code, 600_999).unwrap(),
        invite.pairing_id
    );

    let second = approval.create_invite(10_000).unwrap();
    assert_eq!(
        provider
            .join_session_client("join-boundary")
            .unwrap()
            .resolve_code(&second.code, 610_000)
            .unwrap_err(),
        PairingTransportError::Expired
    );
    assert_eq!(
        provider
            .join_session_client("join-after-expiry-report")
            .unwrap()
            .resolve_code(&second.code, 610_001)
            .unwrap_err(),
        PairingTransportError::Invalid
    );
}

#[test]
fn invite_status_survives_a_new_approval_handle_without_disclosing_the_code() {
    let provider = provider();
    let owner = provider.existing_device_client(scope(), id(ISSUER_ID));
    let invite = owner.create_invite(2_000).unwrap();
    let raw_code = invite.code.as_str().to_owned();
    drop(owner);

    let restored = provider.existing_device_client(scope(), id(ISSUER_ID));
    let status = restored.invite_status(invite.pairing_id, 2_001).unwrap();
    assert_eq!(status.pairing_id, invite.pairing_id);
    assert_eq!(status.created_at_ms, invite.created_at_ms);
    assert_eq!(status.expires_at_ms, invite.expires_at_ms);
    assert_eq!(status.state, PairingInviteState::Pending);
    assert!(!format!("{status:?}").contains(&raw_code));
}

#[test]
fn attempt_budget_is_five_per_bound_join_session() {
    let provider = provider();
    let approval = provider.existing_device_client(scope(), id(ISSUER_ID));
    let invite = approval.create_invite(5_000).unwrap();
    let wrong = wrong_code(&invite.code);
    let four_then_correct = provider.join_session_client("join-four").unwrap();

    for _ in 0..4 {
        assert_eq!(
            four_then_correct.resolve_code(&wrong, 5_001).unwrap_err(),
            PairingTransportError::Invalid
        );
    }
    assert_eq!(
        four_then_correct.resolve_code(&invite.code, 5_002).unwrap(),
        invite.pairing_id
    );

    let second_invite = approval.create_invite(6_000).unwrap();
    let second_wrong = wrong_code(&second_invite.code);
    let exhausted = provider.join_session_client("join-five").unwrap();
    for attempt in 0..4 {
        assert_eq!(
            exhausted
                .resolve_code(&second_wrong, 6_001 + attempt)
                .unwrap_err(),
            PairingTransportError::Invalid
        );
    }
    assert_eq!(
        exhausted.resolve_code(&second_wrong, 6_005).unwrap_err(),
        PairingTransportError::Exhausted
    );
    assert_eq!(
        exhausted
            .resolve_code(&second_invite.code, 6_006)
            .unwrap_err(),
        PairingTransportError::Exhausted
    );

    let independent = provider.join_session_client("join-independent").unwrap();
    assert_eq!(
        independent
            .resolve_code(&second_invite.code, 6_007)
            .unwrap(),
        second_invite.pairing_id
    );
}

#[test]
fn exact_request_retries_are_stable_and_changed_bytes_or_callers_conflict() {
    let provider = provider();
    let owner = provider.existing_device_client(scope(), id(ISSUER_ID));
    let join = provider.join_session_client("join-request").unwrap();
    let invite = owner.create_invite(20_000).unwrap();
    join.resolve_code(&invite.code, 20_001).unwrap();

    let joiner_keys = DeviceKeys::generate().unwrap();
    let request = signed_request(invite.pairing_id, &joiner_keys, "Laptop");
    let receipt = join
        .submit_request(invite.pairing_id, request.canonical_bytes(), 20_002)
        .unwrap();
    assert_eq!(
        join.submit_request(invite.pairing_id, request.canonical_bytes(), 99_999)
            .unwrap(),
        receipt
    );
    assert_eq!(receipt.request_digest, request.digest());
    assert_eq!(receipt.requested_at_ms, 20_002);

    let changed = signed_request(invite.pairing_id, &joiner_keys, "Changed laptop");
    assert_eq!(
        join.submit_request(invite.pairing_id, changed.canonical_bytes(), 20_003)
            .unwrap_err(),
        PairingTransportError::Conflict
    );
    assert_eq!(
        provider
            .join_session_client("join-other")
            .unwrap()
            .submit_request(invite.pairing_id, request.canonical_bytes(), 20_003)
            .unwrap_err(),
        PairingTransportError::Unauthorized
    );

    let stored = owner.request(invite.pairing_id, 20_003).unwrap().unwrap();
    assert_eq!(stored.canonical_bytes, request.canonical_bytes());
    assert_eq!(stored.request_digest, request.digest());
    assert_eq!(stored.requested_at_ms, 20_002);
    assert_eq!(stored.scope, scope());
    assert_eq!(
        provider
            .existing_device_client(other_scope(), id(ISSUER_ID))
            .request(invite.pairing_id, 20_003)
            .unwrap_err(),
        PairingTransportError::Unauthorized
    );
    assert_eq!(
        provider
            .existing_device_client(scope(), id(OTHER_ISSUER_ID))
            .request(invite.pairing_id, 20_003)
            .unwrap_err(),
        PairingTransportError::Unauthorized
    );
    assert_eq!(
        join.submit_request(
            invite.pairing_id,
            request.canonical_bytes(),
            invite.expires_at_ms,
        )
        .unwrap_err(),
        PairingTransportError::Expired
    );
}

#[test]
fn exact_approval_retry_and_result_are_stable_while_changes_conflict() {
    let fixture = bound_request(30_000, "join-approval");
    let payload = approved_payload(
        &fixture.request,
        &fixture.issuer_keys,
        fixture.issuer_certificate.clone(),
        CERTIFICATE_ID,
        ISSUER_CERTIFICATE_ID,
    );
    let canonical = encode_pairing_approved_payload_v1(&payload).unwrap();
    let envelope = PairingDecisionEnvelope::approve(
        fixture.invite_id,
        fixture.request.digest(),
        canonical.clone(),
    );
    let receipt = fixture.owner.decide(envelope.clone(), 30_010).unwrap();
    assert_eq!(fixture.owner.decide(envelope, 90_000).unwrap(), receipt);
    assert_eq!(receipt.decided_at_ms, 30_010);
    assert_eq!(receipt.request_digest, fixture.request.digest());
    assert_eq!(
        fixture
            .join
            .submit_request(fixture.invite_id, fixture.request.canonical_bytes(), 90_000,)
            .unwrap()
            .requested_at_ms,
        30_002
    );

    let result = fixture
        .join
        .result(fixture.invite_id, fixture.request.digest(), 30_011)
        .unwrap();
    assert_eq!(
        result,
        PairingResult::Approved(
            context_relay_core::devices::transport::PairingApprovedResult::new(
                canonical.clone(),
                receipt.clone(),
            )
        )
    );
    let approved_digest = receipt.approved_payload_digest.unwrap();
    let approved_digest_hex = approved_digest
        .0
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let result_debug = format!("{result:?}");
    assert!(!result_debug.contains(&approved_digest_hex));
    assert!(!result_debug.contains(&format!("{approved_digest:?}")));
    assert_eq!(
        receipt.approved_payload_digest,
        Some(Sha256Digest(Sha256::digest(&canonical).into()))
    );
    let mut wrong_digest = fixture.request.digest();
    wrong_digest.0[0] ^= 1;
    assert_eq!(
        fixture
            .join
            .result(fixture.invite_id, wrong_digest, 30_011)
            .unwrap_err(),
        PairingTransportError::Conflict
    );

    let changed_payload = approved_payload(
        &fixture.request,
        &fixture.issuer_keys,
        fixture.issuer_certificate,
        OTHER_CERTIFICATE_ID,
        OTHER_ISSUER_CERTIFICATE_ID,
    );
    assert_eq!(
        fixture
            .owner
            .decide(
                PairingDecisionEnvelope::approve(
                    fixture.invite_id,
                    fixture.request.digest(),
                    encode_pairing_approved_payload_v1(&changed_payload).unwrap(),
                ),
                30_012,
            )
            .unwrap_err(),
        PairingTransportError::Conflict
    );
    assert_eq!(
        fixture
            .provider
            .existing_device_client(other_scope(), id(ISSUER_ID))
            .decide(
                PairingDecisionEnvelope::reject(fixture.invite_id, fixture.request.digest()),
                30_012,
            )
            .unwrap_err(),
        PairingTransportError::Unauthorized
    );
    assert_eq!(
        fixture
            .provider
            .existing_device_client(scope(), id(OTHER_ISSUER_ID))
            .cancel(fixture.invite_id, 30_012)
            .unwrap_err(),
        PairingTransportError::Unauthorized
    );
}

#[test]
fn approval_payload_must_match_the_authenticated_approving_device() {
    let fixture = bound_request(35_000, "join-wrong-issuer");
    let other_issuer_keys = DeviceKeys::generate().unwrap();
    let other_issuer_certificate = issuer_certificate_for(&other_issuer_keys, id(OTHER_ISSUER_ID));
    let payload = approved_payload(
        &fixture.request,
        &other_issuer_keys,
        other_issuer_certificate,
        CERTIFICATE_ID,
        OTHER_ISSUER_CERTIFICATE_ID,
    );

    assert_eq!(
        fixture
            .owner
            .decide(
                PairingDecisionEnvelope::approve(
                    fixture.invite_id,
                    fixture.request.digest(),
                    encode_pairing_approved_payload_v1(&payload).unwrap(),
                ),
                35_010,
            )
            .unwrap_err(),
        PairingTransportError::Conflict
    );
}

#[test]
fn cancel_reject_and_approve_are_terminal_compare_and_set_transitions() {
    let provider = provider();
    let owner = provider.existing_device_client(scope(), id(ISSUER_ID));

    let canceled = owner.create_invite(40_000).unwrap();
    owner.cancel(canceled.pairing_id, 40_001).unwrap();
    owner.cancel(canceled.pairing_id, 40_002).unwrap();
    assert_eq!(
        owner
            .invite_status(canceled.pairing_id, 40_002)
            .unwrap()
            .state,
        PairingInviteState::Canceled
    );
    assert_eq!(
        provider
            .join_session_client("join-canceled")
            .unwrap()
            .resolve_code(&canceled.code, 40_003)
            .unwrap_err(),
        PairingTransportError::Canceled
    );

    let rejected = bound_request_with(&provider, &owner, 41_000, "join-rejected");
    let rejection = PairingDecisionEnvelope::reject(rejected.invite_id, rejected.request.digest());
    let receipt = owner.decide(rejection.clone(), 41_010).unwrap();
    assert_eq!(owner.decide(rejection, 99_999).unwrap(), receipt);
    assert_eq!(
        owner
            .invite_status(rejected.invite_id, 41_010)
            .unwrap()
            .state,
        PairingInviteState::Rejected
    );
    assert_eq!(
        rejected
            .join
            .result(rejected.invite_id, rejected.request.digest(), 41_011)
            .unwrap(),
        PairingResult::Rejected {
            receipt: receipt.clone()
        }
    );
    assert_eq!(
        owner.cancel(rejected.invite_id, 41_012).unwrap_err(),
        PairingTransportError::Rejected
    );

    let payload = approved_payload(
        &rejected.request,
        &rejected.issuer_keys,
        rejected.issuer_certificate,
        CERTIFICATE_ID,
        ISSUER_CERTIFICATE_ID,
    );
    assert_eq!(
        owner
            .decide(
                PairingDecisionEnvelope::approve(
                    rejected.invite_id,
                    rejected.request.digest(),
                    encode_pairing_approved_payload_v1(&payload).unwrap(),
                ),
                41_012,
            )
            .unwrap_err(),
        PairingTransportError::Rejected
    );
}

#[test]
fn provider_bounds_payloads_redacts_errors_and_retains_no_raw_code_or_plaintext() {
    let fixture = bound_request(50_000, "join-capture");
    assert_eq!(
        fixture
            .join
            .submit_request(fixture.invite_id, &vec![0_u8; 8 * 1024 + 1], 50_003)
            .unwrap_err(),
        PairingTransportError::Conflict
    );

    let payload = approved_payload(
        &fixture.request,
        &fixture.issuer_keys,
        fixture.issuer_certificate,
        CERTIFICATE_ID,
        ISSUER_CERTIFICATE_ID,
    );
    let raw_grant = encode_pairing_grant_v1(&payload.grant).unwrap();
    assert_eq!(
        fixture
            .owner
            .decide(
                PairingDecisionEnvelope::approve(
                    fixture.invite_id,
                    fixture.request.digest(),
                    raw_grant,
                ),
                50_004,
            )
            .unwrap_err(),
        PairingTransportError::Conflict
    );
    assert_eq!(
        fixture
            .owner
            .decide(
                PairingDecisionEnvelope::approve(
                    fixture.invite_id,
                    fixture.request.digest(),
                    vec![0; MAX_PAIRING_APPROVED_PAYLOAD_BYTES + 1],
                ),
                50_005,
            )
            .unwrap_err(),
        PairingTransportError::Conflict
    );
    let canonical = encode_pairing_approved_payload_v1(&payload).unwrap();
    let envelope = PairingDecisionEnvelope::approve(
        fixture.invite_id,
        fixture.request.digest(),
        canonical.clone(),
    );
    let envelope_debug = format!("{envelope:?}");
    assert!(envelope_debug.contains("[REDACTED]"));
    assert!(!envelope_debug.contains(&hex(&canonical)));
    fixture.owner.decide(envelope, 50_010).unwrap();

    let result = fixture
        .join
        .result(fixture.invite_id, fixture.request.digest(), 50_011)
        .unwrap();
    let result_debug = format!("{result:?}");
    assert!(result_debug.contains("[REDACTED]"));
    assert!(!result_debug.contains(&hex(&canonical)));

    let capture = fixture.provider.test_capture_bytes();
    assert!(!contains(&capture, fixture.raw_code.as_str().as_bytes()));
    assert!(!contains(&capture, CANARY.as_bytes()));

    for (error, safe) in [
        (PairingTransportError::Invalid, "pairing_invalid"),
        (PairingTransportError::Exhausted, "pairing_exhausted"),
        (PairingTransportError::Expired, "pairing_expired"),
        (PairingTransportError::Canceled, "pairing_canceled"),
        (PairingTransportError::Rejected, "pairing_rejected"),
        (PairingTransportError::Conflict, "pairing_conflict"),
        (PairingTransportError::Unauthorized, "pairing_unauthorized"),
        (PairingTransportError::Transient, "transient"),
    ] {
        assert_eq!(error.safe_code(), safe);
        assert_eq!(error.to_string(), safe);
        assert_eq!(format!("{error:?}"), safe);
        assert!(!error.to_string().contains(fixture.raw_code.as_str()));
        assert!(!error.to_string().contains(CANARY));
    }
}

struct BoundFixture {
    provider: InMemoryPairingProvider,
    owner: context_relay_core::devices::memory_transport::InMemoryPairingApprovalClient,
    join: context_relay_core::devices::memory_transport::InMemoryPairingJoinClient,
    invite_id: context_relay_protocol::PairingId,
    raw_code: PairingCode,
    request: SignedPairingRequest,
    issuer_keys: DeviceKeys,
    issuer_certificate: DeviceCertificateV1,
}

fn bound_request(now_ms: u64, session: &str) -> BoundFixture {
    let provider = provider();
    let owner = provider.existing_device_client(scope(), id(ISSUER_ID));
    bound_request_with(&provider, &owner, now_ms, session)
}

fn bound_request_with(
    provider: &InMemoryPairingProvider,
    owner: &context_relay_core::devices::memory_transport::InMemoryPairingApprovalClient,
    now_ms: u64,
    session: &str,
) -> BoundFixture {
    let join = provider.join_session_client(session).unwrap();
    let invite = owner.create_invite(now_ms).unwrap();
    join.resolve_code(&invite.code, now_ms + 1).unwrap();
    let joiner_keys = DeviceKeys::generate().unwrap();
    let request = signed_request(invite.pairing_id, &joiner_keys, "Laptop");
    join.submit_request(invite.pairing_id, request.canonical_bytes(), now_ms + 2)
        .unwrap();
    let issuer_keys = DeviceKeys::generate().unwrap();
    let issuer_certificate = issuer_certificate(&issuer_keys);
    BoundFixture {
        provider: provider.clone(),
        owner: owner.clone(),
        join,
        invite_id: invite.pairing_id,
        raw_code: invite.code,
        request,
        issuer_keys,
        issuer_certificate,
    }
}

fn provider() -> InMemoryPairingProvider {
    InMemoryPairingProvider::with_test_entropy(
        [0xa5; 32],
        (0_u8..32).map(|value| [value; 32]).collect(),
    )
}

fn signed_request(
    pairing_id: context_relay_protocol::PairingId,
    keys: &DeviceKeys,
    name: &str,
) -> SignedPairingRequest {
    SignedPairingRequest::build(pairing_id, id(JOINER_ID), name, NativePlatform::Macos, keys)
        .unwrap()
}

fn approved_payload(
    request: &SignedPairingRequest,
    issuer_keys: &DeviceKeys,
    issuer_certificate: DeviceCertificateV1,
    certificate_id: &str,
    issuer_certificate_id: &str,
) -> PairingApprovedPayloadV1 {
    let grant = build_pairing_grant(
        request,
        &PairingGrantApproval {
            request_digest: request.digest(),
            certificate_id: id(certificate_id),
            scope: scope(),
            control_epoch: 7,
            issuer_certificate: issuer_certificate.clone(),
        },
        issuer_keys,
        &PairingKeyBundle::new(scope(), 7, 11, canary_key(0x17), canary_key(0x29)).unwrap(),
    )
    .unwrap();
    build_pairing_approved_payload_v1(
        request,
        grant,
        id(issuer_certificate_id),
        issuer_certificate,
        "Desktop",
        NativePlatform::Macos,
    )
    .unwrap()
}

fn canary_key(fill: u8) -> [u8; 32] {
    let mut key = [fill; 32];
    for (target, source) in key.iter_mut().zip(CANARY.as_bytes()) {
        *target = *source;
    }
    key
}

fn issuer_certificate(keys: &DeviceKeys) -> DeviceCertificateV1 {
    issuer_certificate_for(keys, id(ISSUER_ID))
}

fn issuer_certificate_for(keys: &DeviceKeys, device_id: DeviceId) -> DeviceCertificateV1 {
    DeviceCertificateV1::issue_genesis(
        CertificateFieldsV1 {
            account_id: scope().account_id,
            workspace_id: scope().workspace_id,
            control_epoch: 7,
            request_nonce: PairingRequestNonce([0x33; 32]),
            device_id,
            signing_public_key: keys.signing_public_key(),
            wrapping_public_key: keys.wrapping_public_key(),
        },
        &RecoveryKeys::derive(&fixed_phrase()).unwrap(),
    )
    .unwrap()
}

fn fixed_phrase() -> RecoveryPhrase {
    let mut words = vec!["abandon".to_owned(); 23];
    words.push("art".to_owned());
    RecoveryPhrase::from_words(RecoveryPhraseWords::new(words).unwrap()).unwrap()
}

fn wrong_code(code: &PairingCode) -> PairingCode {
    let mut bytes = code.as_str().as_bytes().to_vec();
    bytes[0] = if bytes[0] == b'0' { b'1' } else { b'0' };
    PairingCode::new(String::from_utf8(bytes).unwrap()).unwrap()
}

fn scope() -> SyncScope {
    SyncScope {
        account_id: id(ACCOUNT_ID),
        workspace_id: id(WORKSPACE_ID),
    }
}

fn other_scope() -> SyncScope {
    SyncScope {
        account_id: id(OTHER_ACCOUNT_ID),
        workspace_id: id(WORKSPACE_ID),
    }
}

fn id<T: FromStr>(value: &str) -> T
where
    T::Err: std::fmt::Debug,
{
    value.parse().unwrap()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[allow(dead_code)]
fn _assert_digest_is_public(_: Sha256Digest, _: DeviceId) {}
