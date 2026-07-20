use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use context_relay_local_ipc::{
    AuthAcceptedV1, AuthTranscriptV1, ConnectionChallenge, InstallationToken, IpcError,
    MAX_IPC_FRAME_BYTES, ServerHelloV1, create_proof as create_proof_v1,
    create_server_proof as create_server_proof_v1, read_frame, read_json, role_allows,
    verify_proof as verify_proof_v1, verify_server_proof as verify_server_proof_v1, write_frame,
    write_json,
};
use context_relay_protocol::{
    ClientRole, DaemonInstanceNonce, InstallationTokenProof, LocalRequest, PROTOCOL_VERSION,
    ProtocolVersion, RecordId,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, ReadBuf};

struct PrefixOnly {
    prefix: [u8; 4],
    offset: usize,
    body_polls: usize,
}

impl PrefixOnly {
    fn new(prefix: [u8; 4]) -> Self {
        Self {
            prefix,
            offset: 0,
            body_polls: 0,
        }
    }

    fn bytes_read(&self) -> usize {
        self.offset
    }

    fn body_polls(&self) -> usize {
        self.body_polls
    }
}

impl AsyncRead for PrefixOnly {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset == self.prefix.len() {
            self.body_polls += 1;
            return Poll::Ready(Err(io::Error::other("body must not be polled")));
        }

        let amount = buffer
            .remaining()
            .min(self.prefix.len().saturating_sub(self.offset));
        buffer.put_slice(&self.prefix[self.offset..self.offset + amount]);
        self.offset += amount;
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn oversized_frame_is_rejected_after_prefix_without_polling_body() {
    let mut input = PrefixOnly::new(((MAX_IPC_FRAME_BYTES + 1) as u32).to_be_bytes());

    assert!(matches!(
        read_frame(&mut input).await,
        Err(IpcError::FrameTooLarge)
    ));
    assert_eq!(input.bytes_read(), 4);
    assert_eq!(input.body_polls(), 0);
}

#[tokio::test]
async fn zero_length_frame_is_invalid() {
    let mut input = &0_u32.to_be_bytes()[..];
    assert!(matches!(
        read_frame(&mut input).await,
        Err(IpcError::InvalidFrame)
    ));
}

#[tokio::test]
async fn truncated_frame_prefix_is_io_error() {
    let mut input = &[0_u8, 0][..];
    assert!(matches!(read_frame(&mut input).await, Err(IpcError::Io)));
}

#[tokio::test]
async fn truncated_frame_body_is_io_error() {
    let mut input = &[0_u8, 0, 0, 2, b'a'][..];
    assert!(matches!(read_frame(&mut input).await, Err(IpcError::Io)));
}

#[tokio::test]
async fn exact_limit_frame_is_accepted() {
    let payload = vec![0x5a; MAX_IPC_FRAME_BYTES];
    let mut input = Vec::with_capacity(4 + payload.len());
    input.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    input.extend_from_slice(&payload);

    assert_eq!(read_frame(&mut &input[..]).await.unwrap(), payload);
}

#[tokio::test]
async fn invalid_utf8_and_json_frames_are_invalid() {
    for payload in [&[0xff_u8][..], &b"{"[..]] {
        let mut input = Vec::with_capacity(4 + payload.len());
        input.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        input.extend_from_slice(payload);
        assert!(matches!(
            read_json::<_, serde_json::Value>(&mut &input[..]).await,
            Err(IpcError::InvalidFrame)
        ));
    }
}

#[tokio::test]
async fn write_frame_rejects_oversized_payload() {
    let mut output = tokio::io::sink();
    let payload = vec![0_u8; MAX_IPC_FRAME_BYTES + 1];
    assert!(matches!(
        write_frame(&mut output, &payload).await,
        Err(IpcError::FrameTooLarge)
    ));
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictMessage {
    value: u8,
}

#[tokio::test]
async fn frame_json_round_trips_strict_message() {
    let (mut writer, mut reader) = tokio::io::duplex(128);
    let expected = StrictMessage { value: 7 };

    write_json(&mut writer, &expected).await.unwrap();
    assert_eq!(
        read_json::<_, StrictMessage>(&mut reader).await.unwrap(),
        expected
    );
}

fn auth_fixture() -> (
    InstallationToken,
    DaemonInstanceNonce,
    DaemonInstanceNonce,
    ConnectionChallenge,
) {
    (
        InstallationToken::from_bytes([0x11; 32]),
        DaemonInstanceNonce::new([0x22; 32]),
        DaemonInstanceNonce::new([0x33; 32]),
        ConnectionChallenge::new([0x44; 32]),
    )
}

fn auth_transcript(
    role: ClientRole,
    client_nonce: &DaemonInstanceNonce,
    daemon_nonce: &DaemonInstanceNonce,
    challenge: &ConnectionChallenge,
    version: ProtocolVersion,
) -> AuthTranscriptV1 {
    AuthTranscriptV1 {
        role,
        client_nonce: *client_nonce,
        server_hello: ServerHelloV1 {
            protocol: version,
            daemon_instance_nonce: *daemon_nonce,
            connection_challenge: *challenge,
        },
    }
}

fn create_proof(
    token: &InstallationToken,
    role: ClientRole,
    client_nonce: &DaemonInstanceNonce,
    daemon_nonce: &DaemonInstanceNonce,
    challenge: &ConnectionChallenge,
    version: ProtocolVersion,
) -> InstallationTokenProof {
    create_proof_v1(
        token,
        &auth_transcript(role, client_nonce, daemon_nonce, challenge, version),
    )
}

fn verify_proof(
    token: &InstallationToken,
    role: ClientRole,
    client_nonce: &DaemonInstanceNonce,
    daemon_nonce: &DaemonInstanceNonce,
    challenge: &ConnectionChallenge,
    version: ProtocolVersion,
    proof: &InstallationTokenProof,
) -> Result<(), IpcError> {
    verify_proof_v1(
        token,
        &auth_transcript(role, client_nonce, daemon_nonce, challenge, version),
        proof,
    )
}

fn create_server_proof(
    token: &InstallationToken,
    role: ClientRole,
    client_nonce: &DaemonInstanceNonce,
    daemon_nonce: &DaemonInstanceNonce,
    challenge: &ConnectionChallenge,
    version: ProtocolVersion,
    client_proof: &InstallationTokenProof,
) -> InstallationTokenProof {
    create_server_proof_v1(
        token,
        &auth_transcript(role, client_nonce, daemon_nonce, challenge, version),
        client_proof,
    )
}

fn verify_server_proof(
    token: &InstallationToken,
    role: ClientRole,
    client_nonce: &DaemonInstanceNonce,
    daemon_nonce: &DaemonInstanceNonce,
    challenge: &ConnectionChallenge,
    version: ProtocolVersion,
    proofs: (&InstallationTokenProof, &InstallationTokenProof),
) -> Result<(), IpcError> {
    verify_server_proof_v1(
        token,
        &auth_transcript(role, client_nonce, daemon_nonce, challenge, version),
        proofs.0,
        proofs.1,
    )
}

#[test]
fn challenged_hmac_matches_frozen_vector() {
    let (token, client_nonce, daemon_nonce, challenge) = auth_fixture();
    let proof = create_proof(
        &token,
        ClientRole::Desktop,
        &client_nonce,
        &daemon_nonce,
        &challenge,
        PROTOCOL_VERSION,
    );

    assert_eq!(
        serde_json::to_string(&proof).unwrap(),
        r#""oisDq7GfjpXM9mivLFsEyrKgQglZHJF0dKLmTyQ1V8c""#
    );
    assert!(
        verify_proof(
            &token,
            ClientRole::Desktop,
            &client_nonce,
            &daemon_nonce,
            &challenge,
            PROTOCOL_VERSION,
            &proof,
        )
        .is_ok()
    );
}

#[test]
fn challenged_hmac_rejects_every_transcript_mutation() {
    let (token, client_nonce, daemon_nonce, challenge) = auth_fixture();
    let proof = create_proof(
        &token,
        ClientRole::Desktop,
        &client_nonce,
        &daemon_nonce,
        &challenge,
        PROTOCOL_VERSION,
    );
    let changed_token = InstallationToken::from_bytes([0x12; 32]);
    let changed_client = DaemonInstanceNonce::new([0x23; 32]);
    let changed_daemon = DaemonInstanceNonce::new([0x34; 32]);
    let changed_challenge = ConnectionChallenge::new([0x45; 32]);

    assert!(
        verify_proof(
            &changed_token,
            ClientRole::Desktop,
            &client_nonce,
            &daemon_nonce,
            &challenge,
            PROTOCOL_VERSION,
            &proof,
        )
        .is_err()
    );
    assert!(
        verify_proof(
            &token,
            ClientRole::McpBridge,
            &client_nonce,
            &daemon_nonce,
            &challenge,
            PROTOCOL_VERSION,
            &proof,
        )
        .is_err()
    );
    assert!(
        verify_proof(
            &token,
            ClientRole::Desktop,
            &changed_client,
            &daemon_nonce,
            &challenge,
            PROTOCOL_VERSION,
            &proof,
        )
        .is_err()
    );
    assert!(
        verify_proof(
            &token,
            ClientRole::Desktop,
            &client_nonce,
            &changed_daemon,
            &challenge,
            PROTOCOL_VERSION,
            &proof,
        )
        .is_err()
    );
    assert!(
        verify_proof(
            &token,
            ClientRole::Desktop,
            &client_nonce,
            &daemon_nonce,
            &changed_challenge,
            PROTOCOL_VERSION,
            &proof,
        )
        .is_err()
    );
    assert!(
        verify_proof(
            &token,
            ClientRole::Desktop,
            &client_nonce,
            &daemon_nonce,
            &challenge,
            ProtocolVersion {
                major: PROTOCOL_VERSION.major + 1,
                minor: PROTOCOL_VERSION.minor,
            },
            &proof,
        )
        .is_err()
    );
    assert!(
        verify_proof(
            &token,
            ClientRole::Desktop,
            &client_nonce,
            &daemon_nonce,
            &challenge,
            ProtocolVersion {
                major: PROTOCOL_VERSION.major,
                minor: PROTOCOL_VERSION.minor + 1,
            },
            &proof,
        )
        .is_err()
    );
}

#[test]
fn auth_captured_proof_fails_for_fresh_challenge() {
    let (token, client_nonce, daemon_nonce, challenge) = auth_fixture();
    let proof = create_proof(
        &token,
        ClientRole::Desktop,
        &client_nonce,
        &daemon_nonce,
        &challenge,
        PROTOCOL_VERSION,
    );

    assert!(
        verify_proof(
            &token,
            ClientRole::Desktop,
            &client_nonce,
            &daemon_nonce,
            &ConnectionChallenge::new([0x45; 32]),
            PROTOCOL_VERSION,
            &proof,
        )
        .is_err()
    );
}

#[test]
fn auth_token_debug_is_redacted() {
    assert_eq!(
        format!("{:?}", InstallationToken::from_bytes([0x11; 32])),
        "InstallationToken([REDACTED])"
    );
}

#[test]
fn auth_server_hello_is_strict_and_requires_a_32_byte_challenge() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    let hello = ServerHelloV1 {
        protocol: PROTOCOL_VERSION,
        daemon_instance_nonce: DaemonInstanceNonce::new([0x33; 32]),
        connection_challenge: ConnectionChallenge::new([0x44; 32]),
    };
    let mut with_unknown = serde_json::to_value(hello).unwrap();
    with_unknown
        .as_object_mut()
        .unwrap()
        .insert("unknown".into(), true.into());
    assert!(serde_json::from_value::<ServerHelloV1>(with_unknown).is_err());

    let invalid = serde_json::json!({
        "protocol": PROTOCOL_VERSION,
        "daemonInstanceNonce": DaemonInstanceNonce::new([0x33; 32]),
        "connectionChallenge": URL_SAFE_NO_PAD.encode([0x44; 31]),
    });
    assert!(serde_json::from_value::<ServerHelloV1>(invalid).is_err());
}

#[test]
fn server_auth_requires_the_installation_token_and_binds_the_client_proof() {
    let (token, client_nonce, daemon_nonce, challenge) = auth_fixture();
    let client_proof = create_proof(
        &token,
        ClientRole::Desktop,
        &client_nonce,
        &daemon_nonce,
        &challenge,
        PROTOCOL_VERSION,
    );
    let server_proof = create_server_proof(
        &token,
        ClientRole::Desktop,
        &client_nonce,
        &daemon_nonce,
        &challenge,
        PROTOCOL_VERSION,
        &client_proof,
    );

    assert_eq!(
        serde_json::to_string(&server_proof).unwrap(),
        r#""d6FWrHsVsBWAQH3RDwcC-cR0X_NOnvyYOzRcGVwo1yo""#
    );
    assert!(
        verify_server_proof(
            &token,
            ClientRole::Desktop,
            &client_nonce,
            &daemon_nonce,
            &challenge,
            PROTOCOL_VERSION,
            (&client_proof, &server_proof),
        )
        .is_ok()
    );

    let fake_server_proof = create_server_proof(
        &InstallationToken::from_bytes([0x12; 32]),
        ClientRole::Desktop,
        &client_nonce,
        &daemon_nonce,
        &challenge,
        PROTOCOL_VERSION,
        &client_proof,
    );
    assert!(
        verify_server_proof(
            &token,
            ClientRole::Desktop,
            &client_nonce,
            &daemon_nonce,
            &challenge,
            PROTOCOL_VERSION,
            (&client_proof, &fake_server_proof),
        )
        .is_err()
    );

    let mut changed_client_proof = client_proof;
    changed_client_proof.0[0] ^= 1;
    assert!(
        verify_server_proof(
            &token,
            ClientRole::Desktop,
            &client_nonce,
            &daemon_nonce,
            &challenge,
            PROTOCOL_VERSION,
            (&changed_client_proof, &server_proof),
        )
        .is_err()
    );
}

#[test]
fn server_auth_rejects_transcript_mutation_and_replay() {
    let (token, client_nonce, daemon_nonce, challenge) = auth_fixture();
    let client_proof = create_proof(
        &token,
        ClientRole::Desktop,
        &client_nonce,
        &daemon_nonce,
        &challenge,
        PROTOCOL_VERSION,
    );
    let proof = create_server_proof(
        &token,
        ClientRole::Desktop,
        &client_nonce,
        &daemon_nonce,
        &challenge,
        PROTOCOL_VERSION,
        &client_proof,
    );

    assert!(
        verify_server_proof(
            &token,
            ClientRole::McpBridge,
            &client_nonce,
            &daemon_nonce,
            &challenge,
            PROTOCOL_VERSION,
            (&client_proof, &proof),
        )
        .is_err()
    );
    assert!(
        verify_server_proof(
            &token,
            ClientRole::Desktop,
            &DaemonInstanceNonce::new([0x23; 32]),
            &daemon_nonce,
            &challenge,
            PROTOCOL_VERSION,
            (&client_proof, &proof),
        )
        .is_err()
    );
    assert!(
        verify_server_proof(
            &token,
            ClientRole::Desktop,
            &client_nonce,
            &DaemonInstanceNonce::new([0x34; 32]),
            &challenge,
            PROTOCOL_VERSION,
            (&client_proof, &proof),
        )
        .is_err()
    );
    assert!(
        verify_server_proof(
            &token,
            ClientRole::Desktop,
            &client_nonce,
            &daemon_nonce,
            &ConnectionChallenge::new([0x45; 32]),
            PROTOCOL_VERSION,
            (&client_proof, &proof),
        )
        .is_err()
    );
    assert!(
        verify_server_proof(
            &token,
            ClientRole::Desktop,
            &client_nonce,
            &daemon_nonce,
            &challenge,
            ProtocolVersion {
                major: PROTOCOL_VERSION.major + 1,
                minor: PROTOCOL_VERSION.minor,
            },
            (&client_proof, &proof),
        )
        .is_err()
    );
    assert!(
        verify_server_proof(
            &token,
            ClientRole::Desktop,
            &client_nonce,
            &daemon_nonce,
            &challenge,
            ProtocolVersion {
                major: PROTOCOL_VERSION.major,
                minor: PROTOCOL_VERSION.minor + 1,
            },
            (&client_proof, &proof),
        )
        .is_err()
    );
}

#[test]
fn server_auth_accepted_message_is_strict() {
    let (token, client_nonce, daemon_nonce, challenge) = auth_fixture();
    let client_proof = create_proof(
        &token,
        ClientRole::Desktop,
        &client_nonce,
        &daemon_nonce,
        &challenge,
        PROTOCOL_VERSION,
    );
    let accepted = AuthAcceptedV1 {
        request_id: "018f22e2-79b0-7cc8-98c4-dc0c0c07398f"
            .parse::<RecordId>()
            .unwrap(),
        server_proof: create_server_proof(
            &token,
            ClientRole::Desktop,
            &client_nonce,
            &daemon_nonce,
            &challenge,
            PROTOCOL_VERSION,
            &client_proof,
        ),
    };
    let mut with_unknown = serde_json::to_value(&accepted).unwrap();
    with_unknown
        .as_object_mut()
        .unwrap()
        .insert("unknown".into(), true.into());

    assert!(serde_json::from_value::<AuthAcceptedV1>(with_unknown).is_err());
    let round_trip: AuthAcceptedV1 =
        serde_json::from_value(serde_json::to_value(&accepted).unwrap()).unwrap();
    assert_eq!(round_trip, accepted);
}

fn request_fixture(method: &str, params: serde_json::Value) -> LocalRequest {
    let request: LocalRequest = serde_json::from_value(serde_json::json!({
        "method": method,
        "params": params,
    }))
    .unwrap();
    request.validate().unwrap();
    request
}

fn all_request_fixtures() -> Vec<(&'static str, LocalRequest)> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    const ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c07398f";
    let bytes32 = URL_SAFE_NO_PAD.encode([0x11; 32]);
    let digest = "11".repeat(32);
    let empty = || serde_json::json!({});
    let harness = || serde_json::json!({"harness": "codex", "projectId": null});

    vec![
        (
            "Hello",
            request_fixture(
                "hello",
                serde_json::json!({
                    "clientRole": "desktop",
                    "clientNonce": bytes32,
                    "sessionProof": bytes32,
                }),
            ),
        ),
        (
            "Cancel",
            request_fixture("cancel", serde_json::json!({"requestId": ID})),
        ),
        ("Shutdown", request_fixture("shutdown", empty())),
        ("Health", request_fixture("health", empty())),
        ("Unlock", request_fixture("unlock", empty())),
        ("ProjectsList", request_fixture("projects_list", empty())),
        (
            "ProjectPathSet",
            request_fixture(
                "project_path_set",
                serde_json::json!({
                    "projectId": ID,
                    "path": {"platform": "windows", "bytes": "", "display": null},
                }),
            ),
        ),
        (
            "MemoryGet",
            request_fixture("memory_get", serde_json::json!({"memoryId": ID})),
        ),
        (
            "MemorySearch",
            request_fixture(
                "memory_search",
                serde_json::json!({"query": "query", "projectId": null}),
            ),
        ),
        (
            "MemoryCreate",
            request_fixture(
                "memory_create",
                serde_json::json!({
                    "operationId": ID,
                    "scope": {"scope": "global"},
                    "kind": "note",
                    "title": "title",
                    "bodyMarkdown": "body",
                    "tags": [],
                }),
            ),
        ),
        (
            "MemoryUpdate",
            request_fixture(
                "memory_update",
                serde_json::json!({
                    "operationId": ID,
                    "memoryId": ID,
                    "expectedRevision": ID,
                    "title": "updated",
                    "bodyMarkdown": null,
                    "tags": null,
                }),
            ),
        ),
        (
            "MemoryArchive",
            request_fixture(
                "memory_archive",
                serde_json::json!({
                    "operationId": ID,
                    "memoryId": ID,
                    "expectedRevision": ID,
                }),
            ),
        ),
        (
            "CandidatesList",
            request_fixture("candidates_list", serde_json::json!({"projectId": null})),
        ),
        (
            "CandidateReview",
            request_fixture(
                "candidate_review",
                serde_json::json!({"candidateId": ID, "accepted": false, "operationId": ID}),
            ),
        ),
        (
            "TasksList",
            request_fixture("tasks_list", serde_json::json!({"projectId": ID})),
        ),
        (
            "TaskUpsert",
            request_fixture(
                "task_upsert",
                serde_json::json!({
                    "operationId": ID,
                    "taskId": null,
                    "projectId": ID,
                    "title": "task",
                    "bodyMarkdown": "body",
                    "status": "open",
                    "expectedRevision": null,
                }),
            ),
        ),
        (
            "TaskComplete",
            request_fixture(
                "task_complete",
                serde_json::json!({
                    "operationId": ID,
                    "taskId": ID,
                    "expectedRevision": ID,
                    "evidence": [{"summary": "done", "kind": "test", "reference": null}],
                }),
            ),
        ),
        (
            "TaskTransition",
            request_fixture(
                "task_transition",
                serde_json::json!({
                    "operationId": ID,
                    "taskId": ID,
                    "expectedRevision": ID,
                    "status": "in_progress",
                }),
            ),
        ),
        (
            "HandoffCreate",
            request_fixture(
                "handoff_create",
                serde_json::json!({
                    "operationId": ID,
                    "memoryIds": [ID],
                    "decisionIds": [],
                    "taskIds": [],
                    "summary": "summary",
                }),
            ),
        ),
        ("AccessGet", request_fixture("access_get", harness())),
        (
            "AccessSet",
            request_fixture(
                "access_set",
                serde_json::json!({
                    "operationId": ID,
                    "harness": "codex",
                    "policy": {"mode": "default"},
                }),
            ),
        ),
        ("HarnessProbe", request_fixture("harness_probe", harness())),
        (
            "HarnessPreview",
            request_fixture("harness_preview", harness()),
        ),
        (
            "HarnessApply",
            request_fixture("harness_apply", serde_json::json!({"planId": ID})),
        ),
        (
            "HarnessRepair",
            request_fixture("harness_repair", harness()),
        ),
        (
            "HarnessRollback",
            request_fixture("harness_rollback", serde_json::json!({"planId": ID})),
        ),
        (
            "PackageImport",
            request_fixture(
                "package_import",
                serde_json::json!({"packageBase64url": "", "dryRun": true}),
            ),
        ),
        (
            "PackageExport",
            request_fixture(
                "package_export",
                serde_json::json!({"projectId": null, "includeArchived": false}),
            ),
        ),
        ("SyncStatus", request_fixture("sync_status", empty())),
        (
            "SyncRetry",
            request_fixture("sync_retry", serde_json::json!({"operationId": ID})),
        ),
        ("DevicesList", request_fixture("devices_list", empty())),
        (
            "DeviceRename",
            request_fixture(
                "device_rename",
                serde_json::json!({"operationId": ID, "deviceId": ID, "name": "device"}),
            ),
        ),
        (
            "DeviceRevoke",
            request_fixture("device_revoke", serde_json::json!({"deviceId": ID})),
        ),
        ("PairingCreate", request_fixture("pairing_create", empty())),
        (
            "PairingJoin",
            request_fixture(
                "pairing_join",
                serde_json::json!({
                    "code": "01234-ABCDE",
                    "deviceId": ID,
                    "deviceName": "device",
                    "platform": "windows",
                    "requestNonce": bytes32,
                    "signingPublicKey": bytes32,
                    "wrappingPublicKey": bytes32,
                }),
            ),
        ),
        (
            "PairingStatus",
            request_fixture("pairing_status", serde_json::json!({"pairingId": ID})),
        ),
        (
            "PairingDecision",
            request_fixture(
                "pairing_decision",
                serde_json::json!({
                    "pairingId": ID,
                    "requestDigest": digest,
                    "approve": false,
                }),
            ),
        ),
        (
            "PairingCancel",
            request_fixture("pairing_cancel", serde_json::json!({"pairingId": ID})),
        ),
        ("RecoveryBegin", request_fixture("recovery_begin", empty())),
        (
            "RecoveryComplete",
            request_fixture(
                "recovery_complete",
                serde_json::json!({"recoveryPhraseWords": vec!["word"; 24]}),
            ),
        ),
        (
            "ExportRecords",
            request_fixture(
                "export_records",
                serde_json::json!({"projectId": null, "includeArchived": false}),
            ),
        ),
        (
            "ExportChunk",
            request_fixture(
                "export_chunk",
                serde_json::json!({"exportId": ID, "chunkIndex": 0}),
            ),
        ),
        (
            "AccountDeletionBegin",
            request_fixture(
                "account_deletion_begin",
                serde_json::json!({"confirmation": "delete"}),
            ),
        ),
        (
            "AccountDeletionStatus",
            request_fixture("account_deletion_status", empty()),
        ),
        (
            "AccountDeletionCancel",
            request_fixture("account_deletion_cancel", empty()),
        ),
    ]
}

#[test]
fn role_allowlist_covers_all_45_requests() {
    let fixtures = all_request_fixtures();
    assert_eq!(fixtures.len(), 45);

    for (name, request) in &fixtures {
        let common = matches!(*name, "Cancel" | "Health");
        let mcp_domain = matches!(
            *name,
            "MemorySearch"
                | "MemoryGet"
                | "MemoryCreate"
                | "MemoryUpdate"
                | "MemoryArchive"
                | "TasksList"
                | "TaskUpsert"
                | "TaskComplete"
                | "HandoffCreate"
                | "SyncStatus"
        );
        let installer_setup = matches!(
            *name,
            "AccessGet"
                | "AccessSet"
                | "HarnessProbe"
                | "HarnessPreview"
                | "HarnessApply"
                | "HarnessRepair"
                | "HarnessRollback"
                | "PackageImport"
                | "PackageExport"
        );

        assert_eq!(
            role_allows(ClientRole::Desktop, request),
            *name != "Hello",
            "Desktop matrix mismatch for {name}"
        );
        assert_eq!(
            role_allows(ClientRole::McpBridge, request),
            common || mcp_domain,
            "MCP matrix mismatch for {name}"
        );
        assert_eq!(
            role_allows(ClientRole::Installer, request),
            common || installer_setup,
            "Installer matrix mismatch for {name}"
        );
    }

    assert_eq!(
        fixtures
            .iter()
            .filter(|(_, request)| role_allows(ClientRole::Desktop, request))
            .count(),
        44
    );
    assert_eq!(
        fixtures
            .iter()
            .filter(|(_, request)| role_allows(ClientRole::McpBridge, request))
            .count(),
        12
    );
    assert_eq!(
        fixtures
            .iter()
            .filter(|(_, request)| role_allows(ClientRole::Installer, request))
            .count(),
        11
    );
}

#[test]
fn transport_runtime_suffix_is_strict() {
    use context_relay_local_ipc::{IpcError, RuntimeConfig};

    for invalid in ["", "../other", "has_underscore"] {
        assert!(matches!(
            RuntimeConfig::for_test(invalid, None),
            Err(IpcError::InvalidRuntime)
        ));
    }
    assert!(matches!(
        RuntimeConfig::for_test("x".repeat(65), None),
        Err(IpcError::InvalidRuntime)
    ));
    RuntimeConfig::for_test("valid-123", None).unwrap();
}

#[cfg(windows)]
mod windows_transport_tests {
    use std::{
        ffi::c_void,
        mem::size_of,
        os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
        ptr::{addr_of, null, null_mut},
    };

    use context_relay_local_ipc::{InstanceGuard, IpcError, Listener, RuntimeConfig, connect};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use uuid::Uuid;
    use windows_sys::Win32::{
        Foundation::{ERROR_ACCESS_DENIED, GetLastError, HANDLE, HLOCAL, LUID, LocalFree},
        Security::{
            ACCESS_ALLOWED_ACE, ACL,
            Authorization::{
                AUTHZ_ACCESS_REPLY, AUTHZ_ACCESS_REQUEST, AUTHZ_CLIENT_CONTEXT_HANDLE,
                AUTHZ_RESOURCE_MANAGER_HANDLE, AUTHZ_RM_FLAG_NO_AUDIT, AUTHZ_SKIP_TOKEN_GROUPS,
                AuthzAccessCheck, AuthzFreeContext, AuthzFreeResourceManager,
                AuthzInitializeContextFromSid, AuthzInitializeResourceManager,
                ConvertSidToStringSidW, ConvertStringSidToSidW, GetSecurityInfo, SE_KERNEL_OBJECT,
            },
            DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetSecurityDescriptorControl,
            GetSecurityDescriptorDacl, GetTokenInformation, OWNER_SECURITY_INFORMATION,
            PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER, TokenUser,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    struct LocalDescriptor(PSECURITY_DESCRIPTOR);

    impl Drop for LocalDescriptor {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0 as HLOCAL);
            }
        }
    }

    struct AuthzHandles {
        context: AUTHZ_CLIENT_CONTEXT_HANDLE,
        manager: AUTHZ_RESOURCE_MANAGER_HANDLE,
    }

    impl Drop for AuthzHandles {
        fn drop(&mut self) {
            unsafe {
                AuthzFreeContext(self.context);
                AuthzFreeResourceManager(self.manager);
            }
        }
    }

    fn runtime() -> RuntimeConfig {
        RuntimeConfig::for_test(format!("test-{}", Uuid::now_v7()), None).unwrap()
    }

    fn token_user_buffer() -> Vec<usize> {
        let mut raw_token: HANDLE = null_mut();
        assert_ne!(
            unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) },
            0
        );
        let token = unsafe { OwnedHandle::from_raw_handle(raw_token) };
        let mut required = 0_u32;
        unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                null_mut(),
                0,
                &mut required,
            );
        }
        assert!(required as usize >= size_of::<TOKEN_USER>());

        let words = (required as usize).div_ceil(size_of::<usize>());
        let mut buffer = vec![0_usize; words];
        assert_ne!(
            unsafe {
                GetTokenInformation(
                    token.as_raw_handle(),
                    TokenUser,
                    buffer.as_mut_ptr().cast(),
                    required,
                    &mut required,
                )
            },
            0
        );
        buffer
    }

    fn token_sid(buffer: &[usize]) -> PSID {
        unsafe { (*(buffer.as_ptr().cast::<TOKEN_USER>())).User.Sid }
    }

    fn current_sid_string() -> String {
        let buffer = token_user_buffer();
        let mut wide = null_mut();
        assert_ne!(
            unsafe { ConvertSidToStringSidW(token_sid(&buffer), &mut wide) },
            0
        );
        let length = (0..)
            .take_while(|&index| unsafe { *wide.add(index) } != 0)
            .count();
        let result =
            String::from_utf16(unsafe { std::slice::from_raw_parts(wide, length) }).unwrap();
        unsafe {
            LocalFree(wide.cast());
        }
        result
    }

    unsafe fn pipe_security_descriptor(handle: HANDLE) -> LocalDescriptor {
        let mut descriptor = null_mut();
        assert_eq!(
            unsafe {
                GetSecurityInfo(
                    handle,
                    SE_KERNEL_OBJECT,
                    OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    &mut descriptor,
                )
            },
            0
        );
        assert!(!descriptor.is_null());
        LocalDescriptor(descriptor)
    }

    unsafe fn assert_current_sid_only_dacl(descriptor: PSECURITY_DESCRIPTOR) {
        let mut control = 0_u16;
        let mut revision = 0_u32;
        assert_ne!(
            unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) },
            0
        );
        assert_ne!(control & SE_DACL_PROTECTED, 0);

        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl: *mut ACL = null_mut();
        assert_ne!(
            unsafe {
                GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted)
            },
            0
        );
        assert_ne!(present, 0);
        assert!(!dacl.is_null());
        assert_eq!(unsafe { (*dacl).AceCount }, 1);

        let mut raw_ace: *mut c_void = null_mut();
        assert_ne!(unsafe { GetAce(dacl, 0, &mut raw_ace) }, 0);
        let ace = raw_ace.cast::<ACCESS_ALLOWED_ACE>();
        assert_eq!(unsafe { (*ace).Header.AceType }, 0);

        let current = token_user_buffer();
        let ace_sid = unsafe { addr_of!((*ace).SidStart).cast_mut().cast() };
        assert_ne!(unsafe { EqualSid(ace_sid, token_sid(&current)) }, 0);
    }

    unsafe fn assert_synthetic_other_sid_denied(descriptor: PSECURITY_DESCRIPTOR) {
        let synthetic = "S-1-5-21-111111111-222222222-333333333-1001";
        let wide: Vec<u16> = synthetic.encode_utf16().chain([0]).collect();
        let mut sid = null_mut();
        assert_ne!(
            unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut sid) },
            0
        );
        let _sid = LocalDescriptor(sid);

        let mut manager = null_mut();
        assert_ne!(
            unsafe {
                AuthzInitializeResourceManager(
                    AUTHZ_RM_FLAG_NO_AUDIT,
                    None,
                    None,
                    None,
                    null(),
                    &mut manager,
                )
            },
            0
        );
        let mut context = null_mut();
        let initialized = unsafe {
            AuthzInitializeContextFromSid(
                AUTHZ_SKIP_TOKEN_GROUPS,
                sid,
                manager,
                null(),
                LUID::default(),
                null(),
                &mut context,
            )
        };
        assert_ne!(
            initialized,
            0,
            "AuthzInitializeContextFromSid failed with {}",
            unsafe { GetLastError() }
        );
        let _handles = AuthzHandles { context, manager };

        const READ_CONTROL: u32 = 0x0002_0000;
        let request = AUTHZ_ACCESS_REQUEST {
            DesiredAccess: READ_CONTROL,
            ..Default::default()
        };
        let mut granted = 0_u32;
        let mut access_error = 0_u32;
        let mut sacl = 0_u32;
        let mut reply = AUTHZ_ACCESS_REPLY {
            ResultListLength: 1,
            GrantedAccessMask: &mut granted,
            SaclEvaluationResults: &mut sacl,
            Error: &mut access_error,
        };
        let checked = unsafe {
            AuthzAccessCheck(
                0,
                context,
                &request,
                null_mut(),
                descriptor,
                null(),
                0,
                &mut reply,
                null_mut(),
            )
        };
        assert_ne!(checked, 0, "AuthzAccessCheck failed with {}", unsafe {
            GetLastError()
        });
        assert_eq!(granted, 0);
        assert_eq!(access_error, ERROR_ACCESS_DENIED);
    }

    #[test]
    fn windows_transport_singleton_is_separate_and_released_on_drop() {
        let runtime = runtime();
        let first = InstanceGuard::acquire(&runtime).unwrap();
        assert!(matches!(
            InstanceGuard::acquire(&runtime),
            Err(IpcError::AlreadyRunning)
        ));
        drop(first);
        InstanceGuard::acquire(&runtime).unwrap();
    }

    #[tokio::test]
    async fn windows_transport_guard_cannot_publish_a_different_endpoint() {
        let guarded_runtime = runtime();
        let other_runtime = runtime();
        let mut instance = InstanceGuard::acquire(&guarded_runtime).unwrap();

        assert!(matches!(
            Listener::bind(&other_runtime, &mut instance),
            Err(IpcError::InvalidRuntime)
        ));
    }

    #[tokio::test]
    async fn windows_transport_missing_endpoint_is_distinct() {
        assert!(matches!(
            connect(&runtime()).await,
            Err(IpcError::EndpointNotFound)
        ));
    }

    #[tokio::test]
    async fn windows_transport_round_trip_has_sid_name_and_protected_dacl() {
        let runtime = runtime();
        let endpoint = runtime.endpoint_name().unwrap();
        assert!(endpoint.contains(&current_sid_string()));

        let mut instance = InstanceGuard::acquire(&runtime).unwrap();
        let mut listener = Listener::bind(&runtime, &mut instance).unwrap();
        assert!(matches!(
            Listener::bind(&runtime, &mut instance),
            Err(IpcError::AlreadyRunning)
        ));
        let server = tokio::spawn(async move {
            for (request, response) in [(b"ping1", b"pong1"), (b"ping2", b"pong2")] {
                let mut stream = listener.accept().await.unwrap();
                let mut actual = [0_u8; 5];
                stream.read_exact(&mut actual).await.unwrap();
                assert_eq!(&actual, request);
                stream.write_all(response).await.unwrap();
            }
        });

        let mut client = connect(&runtime).await.unwrap();
        let descriptor = unsafe { pipe_security_descriptor(client.as_raw_handle()) };
        unsafe {
            assert_current_sid_only_dacl(descriptor.0);
            assert_synthetic_other_sid_denied(descriptor.0);
        }

        client.write_all(b"ping1").await.unwrap();
        let mut response = [0_u8; 5];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong1");
        drop(client);

        let mut second = connect(&runtime).await.unwrap();
        second.write_all(b"ping2").await.unwrap();
        second.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong2");
        server.await.unwrap();
        assert!(matches!(
            Listener::bind(&runtime, &mut instance),
            Err(IpcError::AlreadyRunning)
        ));
    }
}

#[cfg(target_os = "macos")]
mod macos_transport_tests {
    use std::{
        fs,
        os::unix::{
            fs::{DirBuilderExt, MetadataExt, PermissionsExt, symlink},
            net::UnixListener as StdUnixListener,
        },
        path::{Path, PathBuf},
    };

    use context_relay_local_ipc::{InstanceGuard, IpcError, Listener, RuntimeConfig, connect};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use uuid::Uuid;

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!("context-relay-ipc-test-{}", Uuid::now_v7())))
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn create(&self) {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(self.path())
                .unwrap();
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            if self.0.file_name().is_some_and(|name| {
                name.to_string_lossy()
                    .starts_with("context-relay-ipc-test-")
            }) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
    }

    fn runtime(root: &TestRoot) -> (String, RuntimeConfig) {
        let suffix = format!("test-{}", Uuid::now_v7());
        let runtime =
            RuntimeConfig::for_test(suffix.clone(), Some(root.path().to_path_buf())).unwrap();
        (suffix, runtime)
    }

    #[test]
    fn macos_transport_singleton_and_runtime_modes_are_exact() {
        let root = TestRoot::new();
        let (suffix, runtime) = runtime(&root);
        let first = InstanceGuard::acquire(&runtime).unwrap();
        assert!(matches!(
            InstanceGuard::acquire(&runtime),
            Err(IpcError::AlreadyRunning)
        ));

        assert_eq!(
            fs::metadata(root.path()).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let lock = root.path().join(format!("context-relay-v1-{suffix}.lock"));
        assert_eq!(
            fs::metadata(lock).unwrap().permissions().mode() & 0o777,
            0o600
        );

        drop(first);
        InstanceGuard::acquire(&runtime).unwrap();
    }

    #[test]
    fn macos_transport_rejects_unsafe_existing_runtime_permissions() {
        use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt};

        let unsafe_root = TestRoot::new();
        fs::DirBuilder::new()
            .mode(0o755)
            .create(unsafe_root.path())
            .unwrap();
        fs::set_permissions(unsafe_root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let (_, unsafe_runtime) = runtime(&unsafe_root);
        assert!(matches!(
            InstanceGuard::acquire(&unsafe_runtime),
            Err(IpcError::InvalidRuntime)
        ));

        let unsafe_lock = TestRoot::new();
        unsafe_lock.create();
        let (suffix, runtime) = runtime(&unsafe_lock);
        OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o644)
            .open(
                unsafe_lock
                    .path()
                    .join(format!("context-relay-v1-{suffix}.lock")),
            )
            .unwrap();
        fs::set_permissions(
            unsafe_lock
                .path()
                .join(format!("context-relay-v1-{suffix}.lock")),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(matches!(
            InstanceGuard::acquire(&runtime),
            Err(IpcError::InvalidRuntime)
        ));
    }

    #[tokio::test]
    async fn macos_transport_current_user_round_trip_and_socket_mode() {
        let root = TestRoot::new();
        let (_, runtime) = runtime(&root);
        let mut instance = InstanceGuard::acquire(&runtime).unwrap();
        let mut listener = Listener::bind(&runtime, &mut instance).unwrap();
        let socket = PathBuf::from(runtime.endpoint_name().unwrap());
        assert_eq!(
            fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let server = tokio::spawn(async move {
            let mut stream = listener.accept().await.unwrap();
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });

        let mut client = connect(&runtime).await.unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut response = [0_u8; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn macos_transport_replaces_only_a_stale_socket() {
        let root = TestRoot::new();
        root.create();
        let (_, runtime) = runtime(&root);
        let socket = PathBuf::from(runtime.endpoint_name().unwrap());
        drop(StdUnixListener::bind(&socket).unwrap());

        let mut instance = InstanceGuard::acquire(&runtime).unwrap();
        let listener = Listener::bind(&runtime, &mut instance).unwrap();
        assert!(socket.exists());
        drop(listener);
        assert!(!socket.exists());
    }

    #[tokio::test]
    async fn macos_transport_stale_socket_is_endpoint_not_found() {
        let root = TestRoot::new();
        root.create();
        let (_, runtime) = runtime(&root);
        let socket = PathBuf::from(runtime.endpoint_name().unwrap());
        drop(StdUnixListener::bind(socket).unwrap());

        assert!(matches!(
            connect(&runtime).await,
            Err(IpcError::EndpointNotFound)
        ));
    }

    #[test]
    fn macos_transport_refuses_regular_file_or_symlink_socket_paths() {
        for symlink_case in [false, true] {
            let root = TestRoot::new();
            root.create();
            let (_, runtime) = runtime(&root);
            let socket = PathBuf::from(runtime.endpoint_name().unwrap());

            if symlink_case {
                let target = root.path().join("target");
                fs::File::create(&target).unwrap();
                symlink(target, &socket).unwrap();
            } else {
                fs::File::create(&socket).unwrap();
            }

            let mut instance = InstanceGuard::acquire(&runtime).unwrap();
            assert!(matches!(
                Listener::bind(&runtime, &mut instance),
                Err(IpcError::InvalidRuntime)
            ));
        }
    }

    #[tokio::test]
    async fn macos_transport_drop_preserves_a_replacement_socket() {
        let root = TestRoot::new();
        let (_, runtime) = runtime(&root);
        let mut instance = InstanceGuard::acquire(&runtime).unwrap();
        let listener = Listener::bind(&runtime, &mut instance).unwrap();
        let socket = PathBuf::from(runtime.endpoint_name().unwrap());
        let original = fs::symlink_metadata(&socket).unwrap();

        fs::remove_file(&socket).unwrap();
        let replacement = StdUnixListener::bind(&socket).unwrap();
        let replacement_metadata = fs::symlink_metadata(&socket).unwrap();
        assert_ne!(
            (original.dev(), original.ino()),
            (replacement_metadata.dev(), replacement_metadata.ino())
        );

        drop(listener);
        assert!(socket.exists());
        drop(replacement);
    }

    #[test]
    fn macos_transport_rejects_overlong_socket_path() {
        let root = TestRoot::new();
        let long_root = root.path().join("x".repeat(100));
        let runtime = RuntimeConfig::for_test("test-overlong", Some(long_root)).unwrap();

        assert!(matches!(
            runtime.endpoint_name(),
            Err(IpcError::InvalidRuntime)
        ));
    }
}
