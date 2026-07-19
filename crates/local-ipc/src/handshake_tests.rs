use context_relay_protocol::{
    CancelParams, ClientError, ClientRole, DaemonInstanceNonce, EmptyParams, ErrorCode,
    HelloParams, JsonRpcErrorObject, JsonRpcErrorV1, JsonRpcRequestV1, JsonRpcVersion,
    LocalRequest, LocalResult, PROTOCOL_VERSION, RecordId,
};
use tokio::io::duplex;

use crate::{
    AuthAcceptedV1, AuthTranscriptV1, ConnectionChallenge, HANDSHAKE_TIMEOUT, InstallationToken,
    IpcError, REQUEST_TIMEOUT, RequestRegistry, ServerHelloV1,
    connection::{ClientConnection, ServerConnection, client_handshake, server_handshake},
    create_proof, create_server_proof, generate_instance_nonce, read_json, write_frame, write_json,
};

fn record_id(value: &str) -> RecordId {
    value.parse().unwrap()
}

fn expect_ipc_error<T>(result: Result<T, IpcError>) -> IpcError {
    match result {
        Ok(_) => panic!("expected IPC error"),
        Err(error) => error,
    }
}

fn server_hello() -> ServerHelloV1 {
    ServerHelloV1 {
        protocol: context_relay_protocol::PROTOCOL_VERSION,
        daemon_instance_nonce: DaemonInstanceNonce::new([0x33; 32]),
        connection_challenge: ConnectionChallenge::new([0x44; 32]),
    }
}

fn hello_request(
    hello: ServerHelloV1,
    role: ClientRole,
    token: &InstallationToken,
    client_nonce: DaemonInstanceNonce,
    id: RecordId,
) -> JsonRpcRequestV1 {
    let transcript = AuthTranscriptV1 {
        role,
        client_nonce,
        server_hello: hello,
    };
    JsonRpcRequestV1 {
        jsonrpc: JsonRpcVersion::V2,
        id,
        protocol: hello.protocol,
        daemon_instance_nonce: hello.daemon_instance_nonce,
        request: LocalRequest::Hello(HelloParams {
            client_role: role,
            client_nonce,
            session_proof: create_proof(token, &transcript),
        }),
    }
}

async fn manually_authenticated_pair(
    role: ClientRole,
) -> (
    tokio::io::DuplexStream,
    ServerConnection<tokio::io::DuplexStream>,
    ServerHelloV1,
) {
    let (mut client_io, server_io) = duplex(64 * 1024);
    let hello = server_hello();
    let server = tokio::spawn(async move {
        let token = InstallationToken::from_bytes([0x11; 32]);
        server_handshake(server_io, &token, hello).await
    });
    let observed: ServerHelloV1 = read_json(&mut client_io).await.unwrap();
    let token = InstallationToken::from_bytes([0x11; 32]);
    write_json(
        &mut client_io,
        &hello_request(
            observed,
            role,
            &token,
            DaemonInstanceNonce::new([0x22; 32]),
            record_id("018f22e2-79b0-7cc8-98c4-dc0c0c07398f"),
        ),
    )
    .await
    .unwrap();
    let _: AuthAcceptedV1 = read_json(&mut client_io).await.unwrap();
    let server = server.await.unwrap().unwrap();
    (client_io, server, observed)
}

async fn authenticated_pair(
    role: ClientRole,
) -> (
    ClientConnection<tokio::io::DuplexStream>,
    ServerConnection<tokio::io::DuplexStream>,
) {
    let (client_io, server_io) = duplex(64 * 1024);
    let hello = server_hello();
    let server = tokio::spawn(async move {
        let token = InstallationToken::from_bytes([0x11; 32]);
        server_handshake(server_io, &token, hello).await
    });
    let token = InstallationToken::from_bytes([0x11; 32]);
    let client = client_handshake(
        client_io,
        role,
        &token,
        DaemonInstanceNonce::new([0x22; 32]),
        record_id("018f22e2-79b0-7cc8-98c4-dc0c0c07398f"),
    )
    .await
    .unwrap();
    (client, server.await.unwrap().unwrap())
}

async fn authenticated_pair_with_registry(
    role: ClientRole,
    registry: RequestRegistry,
) -> (
    ClientConnection<tokio::io::DuplexStream>,
    ServerConnection<tokio::io::DuplexStream>,
) {
    let (client, mut server) = authenticated_pair(role).await;
    server.registry = registry;
    (client, server)
}

async fn authenticated_client_with_raw_server() -> (
    ClientConnection<tokio::io::DuplexStream>,
    tokio::io::DuplexStream,
) {
    let (client_io, mut server_io) = duplex(64 * 1024);
    let hello = server_hello();
    let server = tokio::spawn(async move {
        write_json(&mut server_io, &hello).await.unwrap();
        let request: JsonRpcRequestV1 = read_json(&mut server_io).await.unwrap();
        let LocalRequest::Hello(params) = request.request else {
            panic!("expected hello");
        };
        let transcript = AuthTranscriptV1 {
            role: params.client_role,
            client_nonce: params.client_nonce,
            server_hello: hello,
        };
        let token = InstallationToken::from_bytes([0x11; 32]);
        write_json(
            &mut server_io,
            &AuthAcceptedV1 {
                request_id: request.id,
                server_proof: create_server_proof(&token, &transcript, &params.session_proof),
            },
        )
        .await
        .unwrap();
        server_io
    });
    let token = InstallationToken::from_bytes([0x11; 32]);
    let client = client_handshake(
        client_io,
        ClientRole::Desktop,
        &token,
        DaemonInstanceNonce::new([0x22; 32]),
        record_id("018f22e2-79b0-7cc8-98c4-dc0c0c07398f"),
    )
    .await
    .unwrap();
    (client, server.await.unwrap())
}

async fn assert_raw_request_rejected(build: impl FnOnce(ServerHelloV1) -> String) {
    let (mut client_io, mut server, hello) = manually_authenticated_pair(ClientRole::Desktop).await;
    let request = build(hello);
    let receive = tokio::spawn(async move { server.next_request().await });
    write_frame(&mut client_io, request.as_bytes())
        .await
        .unwrap();
    let response: JsonRpcErrorV1 = read_json(&mut client_io).await.unwrap();

    assert_eq!(response.error.data.code, ErrorCode::InvalidRequest);
    assert!(matches!(
        expect_ipc_error(receive.await.unwrap()),
        IpcError::InvalidRequest
    ));
}

#[test]
fn instance_nonce_generation_is_fallible_and_returns_32_bytes() {
    assert_eq!(generate_instance_nonce().unwrap().as_bytes().len(), 32);
}

#[tokio::test]
async fn mutual_handshake_authenticates_only_after_server_proof() {
    let (client_io, server_io) = duplex(64 * 1024);
    let hello = server_hello();
    let server = tokio::spawn(async move {
        let token = InstallationToken::from_bytes([0x11; 32]);
        server_handshake(server_io, &token, hello).await
    });
    let token = InstallationToken::from_bytes([0x11; 32]);

    let client = client_handshake(
        client_io,
        ClientRole::Desktop,
        &token,
        DaemonInstanceNonce::new([0x22; 32]),
        record_id("018f22e2-79b0-7cc8-98c4-dc0c0c07398f"),
    )
    .await
    .unwrap();
    let server = server.await.unwrap().unwrap();

    assert_eq!(server.role(), ClientRole::Desktop);
    drop(client);
}

#[tokio::test]
async fn wrong_token_closes_silently_without_authenticating() {
    let (client_io, server_io) = duplex(64 * 1024);
    let hello = server_hello();
    let server = tokio::spawn(async move {
        let token = InstallationToken::from_bytes([0x11; 32]);
        server_handshake(server_io, &token, hello).await
    });
    let wrong_token = InstallationToken::from_bytes([0x12; 32]);

    let client_error = expect_ipc_error(
        client_handshake(
            client_io,
            ClientRole::Desktop,
            &wrong_token,
            DaemonInstanceNonce::new([0x22; 32]),
            record_id("018f22e2-79b0-7cc8-98c4-dc0c0c07398f"),
        )
        .await,
    );
    let server_error = expect_ipc_error(server.await.unwrap());

    assert!(matches!(client_error, IpcError::AuthenticationFailed));
    assert!(matches!(server_error, IpcError::AuthenticationFailed));
}

#[tokio::test]
async fn fake_server_proof_is_rejected_before_client_connects() {
    let (client_io, mut fake_server_io) = duplex(64 * 1024);
    let hello = server_hello();
    let fake_server = tokio::spawn(async move {
        write_json(&mut fake_server_io, &hello).await.unwrap();
        let request: JsonRpcRequestV1 = read_json(&mut fake_server_io).await.unwrap();
        let LocalRequest::Hello(params) = request.request else {
            panic!("expected hello");
        };
        let transcript = AuthTranscriptV1 {
            role: params.client_role,
            client_nonce: params.client_nonce,
            server_hello: hello,
        };
        let wrong_token = InstallationToken::from_bytes([0x12; 32]);
        write_json(
            &mut fake_server_io,
            &AuthAcceptedV1 {
                request_id: request.id,
                server_proof: create_server_proof(&wrong_token, &transcript, &params.session_proof),
            },
        )
        .await
        .unwrap();
    });
    let token = InstallationToken::from_bytes([0x11; 32]);

    let error = expect_ipc_error(
        client_handshake(
            client_io,
            ClientRole::Desktop,
            &token,
            DaemonInstanceNonce::new([0x22; 32]),
            record_id("018f22e2-79b0-7cc8-98c4-dc0c0c07398f"),
        )
        .await,
    );
    fake_server.await.unwrap();

    assert!(matches!(error, IpcError::AuthenticationFailed));
}

#[tokio::test]
async fn hello_response_id_mismatch_fails_mutual_authentication() {
    let (client_io, mut fake_server_io) = duplex(64 * 1024);
    let hello = server_hello();
    let fake_server = tokio::spawn(async move {
        write_json(&mut fake_server_io, &hello).await.unwrap();
        let request: JsonRpcRequestV1 = read_json(&mut fake_server_io).await.unwrap();
        let LocalRequest::Hello(params) = request.request else {
            panic!("expected hello");
        };
        let transcript = AuthTranscriptV1 {
            role: params.client_role,
            client_nonce: params.client_nonce,
            server_hello: hello,
        };
        let token = InstallationToken::from_bytes([0x11; 32]);
        write_json(
            &mut fake_server_io,
            &AuthAcceptedV1 {
                request_id: record_id("018f22e2-79b0-7cc8-98c4-dc0c0c073990"),
                server_proof: create_server_proof(&token, &transcript, &params.session_proof),
            },
        )
        .await
        .unwrap();
    });
    let token = InstallationToken::from_bytes([0x11; 32]);
    let error = expect_ipc_error(
        client_handshake(
            client_io,
            ClientRole::Desktop,
            &token,
            DaemonInstanceNonce::new([0x22; 32]),
            record_id("018f22e2-79b0-7cc8-98c4-dc0c0c07398f"),
        )
        .await,
    );
    fake_server.await.unwrap();
    assert!(matches!(error, IpcError::AuthenticationFailed));
}

#[tokio::test]
async fn captured_hello_fails_against_a_fresh_challenge() {
    let old_hello = server_hello();
    let token = InstallationToken::from_bytes([0x11; 32]);
    let captured = hello_request(
        old_hello,
        ClientRole::Desktop,
        &token,
        DaemonInstanceNonce::new([0x22; 32]),
        record_id("018f22e2-79b0-7cc8-98c4-dc0c0c07398f"),
    );
    let (mut client_io, server_io) = duplex(64 * 1024);
    let fresh_hello = ServerHelloV1 {
        connection_challenge: ConnectionChallenge::new([0x45; 32]),
        ..old_hello
    };
    let server = tokio::spawn(async move {
        let token = InstallationToken::from_bytes([0x11; 32]);
        server_handshake(server_io, &token, fresh_hello).await
    });
    let _: ServerHelloV1 = read_json(&mut client_io).await.unwrap();
    write_json(&mut client_io, &captured).await.unwrap();

    assert!(matches!(
        expect_ipc_error(server.await.unwrap()),
        IpcError::AuthenticationFailed
    ));
}

#[tokio::test]
async fn unsupported_version_is_rejected_before_typed_method_decode() {
    let (mut client_io, server_io) = duplex(64 * 1024);
    let hello = server_hello();
    let server = tokio::spawn(async move {
        let token = InstallationToken::from_bytes([0x11; 32]);
        server_handshake(server_io, &token, hello).await
    });
    let observed: ServerHelloV1 = read_json(&mut client_io).await.unwrap();
    let raw = format!(
        r#"{{"jsonrpc":"2.0","id":"018f22e2-79b0-7cc8-98c4-dc0c0c07398f","protocol":{{"major":2,"minor":0}},"daemonInstanceNonce":{},"method":"not_real","params":{{}}}}"#,
        serde_json::to_string(&observed.daemon_instance_nonce).unwrap()
    );
    crate::write_frame(&mut client_io, raw.as_bytes())
        .await
        .unwrap();

    let response: JsonRpcErrorV1 = read_json(&mut client_io).await.unwrap();
    let error = expect_ipc_error(server.await.unwrap());
    assert_eq!(
        response.error.data.code,
        ErrorCode::ProtocolVersionUnsupported
    );
    assert!(matches!(error, IpcError::ProtocolVersionUnsupported));
}

#[tokio::test]
async fn non_hello_first_request_is_rejected() {
    let (mut client_io, server_io) = duplex(64 * 1024);
    let hello = server_hello();
    let server = tokio::spawn(async move {
        let token = InstallationToken::from_bytes([0x11; 32]);
        server_handshake(server_io, &token, hello).await
    });
    let observed: ServerHelloV1 = read_json(&mut client_io).await.unwrap();
    write_json(
        &mut client_io,
        &JsonRpcRequestV1 {
            jsonrpc: JsonRpcVersion::V2,
            id: record_id("018f22e2-79b0-7cc8-98c4-dc0c0c07398f"),
            protocol: PROTOCOL_VERSION,
            daemon_instance_nonce: observed.daemon_instance_nonce,
            request: LocalRequest::Health(EmptyParams {}),
        },
    )
    .await
    .unwrap();

    let _: JsonRpcErrorV1 = read_json(&mut client_io).await.unwrap();
    assert!(matches!(
        expect_ipc_error(server.await.unwrap()),
        IpcError::InvalidRequest
    ));
}

#[tokio::test]
async fn malformed_first_request_uses_parse_error() {
    let (mut client_io, server_io) = duplex(64 * 1024);
    let hello = server_hello();
    let server = tokio::spawn(async move {
        let token = InstallationToken::from_bytes([0x11; 32]);
        server_handshake(server_io, &token, hello).await
    });
    let _: ServerHelloV1 = read_json(&mut client_io).await.unwrap();
    write_frame(&mut client_io, br#"{"jsonrpc":"2.0""#)
        .await
        .unwrap();
    let response: JsonRpcErrorV1 = read_json(&mut client_io).await.unwrap();
    assert_eq!(
        response.error.code,
        context_relay_protocol::JSON_RPC_PARSE_ERROR
    );
    assert_eq!(response.id, None);
    assert!(matches!(
        expect_ipc_error(server.await.unwrap()),
        IpcError::InvalidRequest
    ));
}

#[tokio::test]
async fn duplicate_hello_param_is_rejected_before_authentication() {
    let (mut client_io, server_io) = duplex(64 * 1024);
    let hello = server_hello();
    let server = tokio::spawn(async move {
        let token = InstallationToken::from_bytes([0x11; 32]);
        server_handshake(server_io, &token, hello).await
    });
    let observed: ServerHelloV1 = read_json(&mut client_io).await.unwrap();
    let token = InstallationToken::from_bytes([0x11; 32]);
    let transcript = AuthTranscriptV1 {
        role: ClientRole::Desktop,
        client_nonce: DaemonInstanceNonce::new([0x22; 32]),
        server_hello: observed,
    };
    let raw = format!(
        r#"{{"jsonrpc":"2.0","id":"018f22e2-79b0-7cc8-98c4-dc0c0c07398f","protocol":{{"major":1,"minor":0}},"daemonInstanceNonce":{},"method":"hello","params":{{"clientRole":"desktop","clientRole":"mcp_bridge","clientNonce":{},"sessionProof":{}}}}}"#,
        serde_json::to_string(&observed.daemon_instance_nonce).unwrap(),
        serde_json::to_string(&transcript.client_nonce).unwrap(),
        serde_json::to_string(&create_proof(&token, &transcript)).unwrap(),
    );
    write_frame(&mut client_io, raw.as_bytes()).await.unwrap();

    assert!(matches!(
        expect_ipc_error(server.await.unwrap()),
        IpcError::InvalidRequest
    ));
}

#[tokio::test]
async fn stale_nonce_and_second_hello_are_terminal_before_dispatch() {
    let (mut client_io, mut server, _hello) =
        manually_authenticated_pair(ClientRole::Desktop).await;
    let receive = tokio::spawn(async move { server.next_request().await });
    write_json(
        &mut client_io,
        &JsonRpcRequestV1 {
            jsonrpc: JsonRpcVersion::V2,
            id: record_id("018f22e2-79b0-7cc8-98c4-dc0c0c073990"),
            protocol: PROTOCOL_VERSION,
            daemon_instance_nonce: DaemonInstanceNonce::new([0x34; 32]),
            request: LocalRequest::Health(EmptyParams {}),
        },
    )
    .await
    .unwrap();
    let _: JsonRpcErrorV1 = read_json(&mut client_io).await.unwrap();
    assert!(matches!(
        expect_ipc_error(receive.await.unwrap()),
        IpcError::InvalidRequest
    ));

    let (mut client_io, mut server, hello) = manually_authenticated_pair(ClientRole::Desktop).await;
    let receive = tokio::spawn(async move { server.next_request().await });
    let token = InstallationToken::from_bytes([0x11; 32]);
    write_json(
        &mut client_io,
        &hello_request(
            hello,
            ClientRole::Desktop,
            &token,
            DaemonInstanceNonce::new([0x22; 32]),
            record_id("018f22e2-79b0-7cc8-98c4-dc0c0c073991"),
        ),
    )
    .await
    .unwrap();
    let _: JsonRpcErrorV1 = read_json(&mut client_io).await.unwrap();
    assert!(matches!(
        expect_ipc_error(receive.await.unwrap()),
        IpcError::InvalidRequest
    ));
}

#[tokio::test]
async fn strict_probe_rejects_duplicate_keys_at_every_object_depth() {
    assert_raw_request_rejected(|hello| {
        let nonce = serde_json::to_string(&hello.daemon_instance_nonce).unwrap();
        format!(
            r#"{{"jsonrpc":"2.0","id":"018f22e2-79b0-7cc8-98c4-dc0c0c073990","protocol":{{"major":1,"minor":0}},"protocol":{{"major":1,"minor":0}},"daemonInstanceNonce":{},"method":"health","params":{{}}}}"#,
            nonce
        )
    })
    .await;
    assert_raw_request_rejected(|hello| {
        let nonce = serde_json::to_string(&hello.daemon_instance_nonce).unwrap();
        format!(
            r#"{{"jsonrpc":"2.0","id":"018f22e2-79b0-7cc8-98c4-dc0c0c073990","protocol":{{"major":1,"minor":0}},"daemonInstanceNonce":{},"method":"health","params":{{}},"params":{{}}}}"#,
            nonce
        )
    })
    .await;
    assert_raw_request_rejected(|hello| {
        let nonce = serde_json::to_string(&hello.daemon_instance_nonce).unwrap();
        format!(
            r#"{{"jsonrpc":"2.0","id":"018f22e2-79b0-7cc8-98c4-dc0c0c073990","protocol":{{"major":1,"minor":0}},"daemonInstanceNonce":{},"method":"cancel","params":{{"requestId":"018f22e2-79b0-7cc8-98c4-dc0c0c07398f","requestId":"018f22e2-79b0-7cc8-98c4-dc0c0c073990"}}}}"#,
            nonce
        )
    })
    .await;
    assert_raw_request_rejected(|hello| {
        let nonce = serde_json::to_string(&hello.daemon_instance_nonce).unwrap();
        format!(
            r#"{{"jsonrpc":"2.0","id":"018f22e2-79b0-7cc8-98c4-dc0c0c073990","protocol":{{"major":1,"minor":0}},"daemonInstanceNonce":{},"method":"project_path_set","params":{{"projectId":"018f22e2-79b0-7cc8-98c4-dc0c0c07398f","path":{{"platform":"windows","platform":"macos","bytes":"YwA"}}}}}}"#,
            nonce
        )
    })
    .await;
}

#[tokio::test]
async fn malformed_json_uses_parse_error_without_exposing_parser_text() {
    let (mut client_io, mut server, _) = manually_authenticated_pair(ClientRole::Desktop).await;
    let receive = tokio::spawn(async move { server.next_request().await });
    write_frame(&mut client_io, br#"{"jsonrpc":"2.0""#)
        .await
        .unwrap();
    let response: JsonRpcErrorV1 = read_json(&mut client_io).await.unwrap();
    assert_eq!(
        response.error.code,
        context_relay_protocol::JSON_RPC_PARSE_ERROR
    );
    assert_eq!(response.id, None);
    assert_eq!(response.error.message, "Invalid request");
    assert_eq!(response.error.data.message, "Invalid request");
    assert!(matches!(
        expect_ipc_error(receive.await.unwrap()),
        IpcError::InvalidRequest
    ));
}

#[tokio::test]
async fn mcp_shutdown_is_scope_denied_without_dispatching_it() {
    let (mut client, mut server) = authenticated_pair(ClientRole::McpBridge).await;
    let server_task = tokio::spawn(async move {
        let request = server.next_request().await.unwrap();
        assert_eq!(request.role, ClientRole::McpBridge);
        assert!(matches!(request.request, LocalRequest::Health(_)));
        server
            .respond(
                request.id,
                Ok(LocalResult::Health {
                    protocol: PROTOCOL_VERSION,
                    vault_locked: false,
                }),
            )
            .await
            .unwrap();
    });

    let denied = client
        .call(
            record_id("018f22e2-79b0-7cc8-98c4-dc0c0c073990"),
            LocalRequest::Shutdown(EmptyParams {}),
        )
        .await
        .unwrap_err();
    assert_eq!(denied.code, ErrorCode::ScopeDenied);
    let health = client
        .call(
            record_id("018f22e2-79b0-7cc8-98c4-dc0c0c073991"),
            LocalRequest::Health(EmptyParams {}),
        )
        .await
        .unwrap();
    assert!(matches!(health, LocalResult::Health { .. }));
    server_task.await.unwrap();
}

#[tokio::test]
async fn correlated_success_and_typed_error_keep_client_reusable() {
    let (mut client, mut server) = authenticated_pair(ClientRole::Desktop).await;
    let server_task = tokio::spawn(async move {
        let first = server.next_request().await.unwrap();
        server
            .respond(
                first.id,
                Ok(LocalResult::Health {
                    protocol: PROTOCOL_VERSION,
                    vault_locked: false,
                }),
            )
            .await
            .unwrap();
        let second = server.next_request().await.unwrap();
        server
            .respond(
                second.id,
                Err(ClientError {
                    code: ErrorCode::Busy,
                    message: "The local service is busy".into(),
                    field_path: None,
                    retryable: true,
                }),
            )
            .await
            .unwrap();
        let third = server.next_request().await.unwrap();
        server
            .respond(third.id, Ok(LocalResult::Empty))
            .await
            .unwrap();
    });

    assert!(matches!(
        client
            .call(
                record_id("018f22e2-79b0-7cc8-98c4-dc0c0c073990"),
                LocalRequest::Health(EmptyParams {})
            )
            .await
            .unwrap(),
        LocalResult::Health { .. }
    ));
    assert_eq!(
        client
            .call(
                record_id("018f22e2-79b0-7cc8-98c4-dc0c0c073991"),
                LocalRequest::Health(EmptyParams {})
            )
            .await
            .unwrap_err()
            .code,
        ErrorCode::Busy
    );
    assert_eq!(
        client
            .call(
                record_id("018f22e2-79b0-7cc8-98c4-dc0c0c073992"),
                LocalRequest::Health(EmptyParams {})
            )
            .await
            .unwrap(),
        LocalResult::Empty
    );
    server_task.await.unwrap();
}

#[tokio::test]
async fn cancel_on_a_second_connection_marks_a_shared_queued_request() {
    let registry = RequestRegistry::default();
    let (mut original_client, mut original_server) =
        authenticated_pair_with_registry(ClientRole::Desktop, registry.clone()).await;
    let (mut cancel_client, mut cancel_server) =
        authenticated_pair_with_registry(ClientRole::Desktop, registry).await;
    let target = record_id("018f22e2-79b0-7cc8-98c4-dc0c0c0739a0");
    let cancel_id = record_id("018f22e2-79b0-7cc8-98c4-dc0c0c0739a1");

    let original_call = tokio::spawn(async move {
        original_client
            .call(target, LocalRequest::Health(EmptyParams {}))
            .await
    });
    let request = original_server.next_request().await.unwrap();
    let cancel_pump = tokio::spawn(async move { cancel_server.next_request().await });
    assert!(matches!(
        cancel_client
            .call(
                cancel_id,
                LocalRequest::Cancel(CancelParams { request_id: target }),
            )
            .await
            .unwrap(),
        LocalResult::Empty
    ));
    assert!(!request.registration.begin());
    assert!(request.registration.is_canceled());
    original_server
        .respond(
            request.id,
            Err(ClientError {
                code: ErrorCode::Canceled,
                message: "The request was canceled".into(),
                field_path: None,
                retryable: false,
            }),
        )
        .await
        .unwrap();
    assert_eq!(
        original_call.await.unwrap().unwrap_err().code,
        ErrorCode::Canceled
    );
    cancel_pump.abort();
}

#[tokio::test]
async fn cancel_acknowledges_but_does_not_interrupt_an_active_request() {
    let registry = RequestRegistry::default();
    let (mut original_client, mut original_server) =
        authenticated_pair_with_registry(ClientRole::Desktop, registry.clone()).await;
    let (mut cancel_client, mut cancel_server) =
        authenticated_pair_with_registry(ClientRole::Desktop, registry).await;
    let target = record_id("018f22e2-79b0-7cc8-98c4-dc0c0c0739a2");

    let original_call = tokio::spawn(async move {
        original_client
            .call(target, LocalRequest::Health(EmptyParams {}))
            .await
    });
    let request = original_server.next_request().await.unwrap();
    assert!(request.registration.begin());
    let cancel_pump = tokio::spawn(async move { cancel_server.next_request().await });
    assert!(matches!(
        cancel_client
            .call(
                record_id("018f22e2-79b0-7cc8-98c4-dc0c0c0739a3"),
                LocalRequest::Cancel(CancelParams { request_id: target }),
            )
            .await
            .unwrap(),
        LocalResult::Empty
    ));
    assert!(!request.registration.is_canceled());
    original_server
        .respond(request.id, Ok(LocalResult::Empty))
        .await
        .unwrap();
    assert!(matches!(
        original_call.await.unwrap().unwrap(),
        LocalResult::Empty
    ));
    cancel_pump.abort();
}

#[tokio::test]
async fn duplicate_active_request_id_is_rejected_without_overwriting_registration() {
    let registry = RequestRegistry::default();
    let (mut first_client, mut first_server) =
        authenticated_pair_with_registry(ClientRole::Desktop, registry.clone()).await;
    let (mut duplicate_client, mut duplicate_server) =
        authenticated_pair_with_registry(ClientRole::Desktop, registry).await;
    let id = record_id("018f22e2-79b0-7cc8-98c4-dc0c0c0739a4");

    let first_call = tokio::spawn(async move {
        first_client
            .call(id, LocalRequest::Health(EmptyParams {}))
            .await
    });
    let first = first_server.next_request().await.unwrap();
    let duplicate_pump = tokio::spawn(async move { duplicate_server.next_request().await });
    assert_eq!(
        duplicate_client
            .call(id, LocalRequest::Health(EmptyParams {}))
            .await
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert!(first.registration.begin());
    first_server
        .respond(first.id, Ok(LocalResult::Empty))
        .await
        .unwrap();
    assert!(matches!(
        first_call.await.unwrap().unwrap(),
        LocalResult::Empty
    ));
    duplicate_pump.abort();
}

#[tokio::test]
async fn wrong_response_id_poisons_the_client() {
    let (mut client, mut server) = authenticated_pair(ClientRole::Desktop).await;
    let server_task = tokio::spawn(async move {
        let _ = server.next_request().await.unwrap();
        server
            .respond(
                record_id("018f22e2-79b0-7cc8-98c4-dc0c0c073992"),
                Ok(LocalResult::Empty),
            )
            .await
            .unwrap();
    });

    let error = client
        .call(
            record_id("018f22e2-79b0-7cc8-98c4-dc0c0c073990"),
            LocalRequest::Health(EmptyParams {}),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Timeout);
    assert_eq!(error.message, "The request outcome is unknown");
    assert!(error.retryable);
    let poisoned = client
        .call(
            record_id("018f22e2-79b0-7cc8-98c4-dc0c0c073991"),
            LocalRequest::Health(EmptyParams {}),
        )
        .await
        .unwrap_err();
    assert_eq!(poisoned.code, ErrorCode::Busy);
    server_task.await.unwrap();
}

#[tokio::test]
async fn null_error_id_poisons_the_client() {
    let (mut client, mut server) = authenticated_client_with_raw_server().await;
    let server_task = tokio::spawn(async move {
        let _: JsonRpcRequestV1 = read_json(&mut server).await.unwrap();
        write_json(
            &mut server,
            &JsonRpcErrorV1 {
                jsonrpc: JsonRpcVersion::V2,
                id: None,
                error: JsonRpcErrorObject {
                    code: context_relay_protocol::JSON_RPC_INVALID_REQUEST,
                    message: "Invalid request".into(),
                    data: ClientError {
                        code: ErrorCode::InvalidRequest,
                        message: "Invalid request".into(),
                        field_path: None,
                        retryable: false,
                    },
                },
            },
        )
        .await
        .unwrap();
    });
    let error = client
        .call(
            record_id("018f22e2-79b0-7cc8-98c4-dc0c0c073990"),
            LocalRequest::Health(EmptyParams {}),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Timeout);
    assert_eq!(error.message, "The request outcome is unknown");
    assert!(error.retryable);
    assert_eq!(
        client
            .call(
                record_id("018f22e2-79b0-7cc8-98c4-dc0c0c073991"),
                LocalRequest::Health(EmptyParams {})
            )
            .await
            .unwrap_err()
            .code,
        ErrorCode::Busy
    );
    server_task.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn request_timeout_writes_once_never_retries_and_poisons() {
    let (mut client, mut server) = authenticated_pair(ClientRole::Desktop).await;
    let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        let request = server.next_request().await.unwrap();
        seen_tx.send(request.id).unwrap();
        let _ = release_rx.await;
    });
    let client_task = tokio::spawn(async move {
        let result = client
            .call(
                record_id("018f22e2-79b0-7cc8-98c4-dc0c0c073990"),
                LocalRequest::Health(EmptyParams {}),
            )
            .await;
        (result, client)
    });
    assert_eq!(
        seen_rx.await.unwrap(),
        record_id("018f22e2-79b0-7cc8-98c4-dc0c0c073990")
    );

    tokio::time::advance(REQUEST_TIMEOUT + std::time::Duration::from_millis(1)).await;
    tokio::task::yield_now().await;
    let (result, mut client) = client_task.await.unwrap();
    let error = result.unwrap_err();
    assert_eq!(error.code, ErrorCode::Timeout);
    assert_eq!(error.message, "The request outcome is unknown");
    assert!(error.retryable);
    assert_eq!(
        client
            .call(
                record_id("018f22e2-79b0-7cc8-98c4-dc0c0c073991"),
                LocalRequest::Health(EmptyParams {})
            )
            .await
            .unwrap_err()
            .code,
        ErrorCode::Busy
    );
    let _ = release_tx.send(());
    server_task.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn incomplete_handshake_times_out_without_sleeping() {
    let (mut client_io, server_io) = duplex(64 * 1024);
    let hello = server_hello();
    let server = tokio::spawn(async move {
        let token = InstallationToken::from_bytes([0x11; 32]);
        server_handshake(server_io, &token, hello).await
    });
    let _: ServerHelloV1 = read_json(&mut client_io).await.unwrap();

    tokio::time::advance(HANDSHAKE_TIMEOUT + std::time::Duration::from_millis(1)).await;
    tokio::task::yield_now().await;

    assert!(matches!(
        expect_ipc_error(server.await.unwrap()),
        IpcError::HandshakeTimeout
    ));
}
