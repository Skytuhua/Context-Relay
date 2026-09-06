use std::{
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    time::Duration,
};

use context_relay_protocol::{
    ClientRole, EmptyParams, HelloParams, JsonRpcRequestV1, JsonRpcSuccessV1, JsonRpcVersion,
    LocalRequest, LocalResult, PROTOCOL_VERSION, ProtocolVersion, RecordId,
};
use tokio::time::{Instant, sleep, timeout, timeout_at};
use windows_sys::Win32::{
    Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::{
        Pipes::GetNamedPipeServerProcessId,
        Threading::{OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject},
    },
};

use crate::{
    AuthAcceptedV1, AuthTranscriptV1, ConnectedStream, HANDSHAKE_TIMEOUT, InstallationToken,
    InstanceGuard, IpcError, REQUEST_TIMEOUT, RuntimeConfig, ServerHelloV1, connect, create_proof,
    generate_instance_nonce, load_installation_token, read_json, verify_server_proof, write_json,
};

const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(45);
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Authenticates to an existing daemon and waits for its process to exit.
/// An absent daemon is a success. This never launches a daemon or creates credentials.
pub async fn shutdown_running_daemon() -> Result<(), IpcError> {
    shutdown_with(
        &RuntimeConfig::production(),
        load_installation_token,
        SHUTDOWN_DEADLINE,
    )
    .await
}

async fn shutdown_with(
    runtime: &RuntimeConfig,
    load_token: impl FnOnce() -> Result<InstallationToken, IpcError>,
    limit: Duration,
) -> Result<(), IpcError> {
    let deadline = Instant::now() + limit;
    timeout_at(deadline, async {
        let stream = loop {
            match connect(runtime).await {
                Ok(stream) => break stream,
                Err(IpcError::EndpointNotFound) => match InstanceGuard::acquire(runtime) {
                    Ok(guard) => {
                        drop(guard);
                        return Ok(());
                    }
                    Err(IpcError::AlreadyRunning) => sleep(POLL_INTERVAL).await,
                    Err(error) => return Err(error),
                },
                Err(error) => return Err(error),
            }
        };

        // Hold the exact connected server's process object before requesting exit:
        // neither an acknowledgment nor a released pipe guarantees the executable is free.
        let process = server_process(&stream)?;
        let token = load_token()?;
        request_shutdown(stream, &token).await?;
        loop {
            // Zero-time polling keeps the wait cancellable without a detached blocking task.
            match unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } {
                WAIT_OBJECT_0 => return Ok(()),
                WAIT_TIMEOUT => sleep(POLL_INTERVAL).await,
                _ => return Err(IpcError::Io),
            }
        }
    })
    .await
    .map_err(|_| IpcError::ShutdownTimeout)?
}

// Upgrade-only compatibility with the Windows previews' frozen shutdown wire.
// This function can send only hello and shutdown, and never returns a client/session.
// Ordinary Client connections continue to require the exact current protocol.
async fn request_shutdown(
    mut stream: ConnectedStream,
    token: &InstallationToken,
) -> Result<(), IpcError> {
    let server_hello = timeout(HANDSHAKE_TIMEOUT, async {
        let server_hello: ServerHelloV1 = read_json(&mut stream).await?;
        if server_hello.protocol != PROTOCOL_VERSION
            && server_hello.protocol != (ProtocolVersion { major: 1, minor: 4 })
            && server_hello.protocol != (ProtocolVersion { major: 1, minor: 5 })
            && server_hello.protocol != (ProtocolVersion { major: 1, minor: 6 })
        {
            return Err(IpcError::ProtocolVersionUnsupported);
        }
        let transcript = AuthTranscriptV1 {
            role: ClientRole::Desktop,
            client_nonce: generate_instance_nonce()?,
            server_hello,
        };
        let client_proof = create_proof(token, &transcript);
        let id = request_id();
        write_json(
            &mut stream,
            &JsonRpcRequestV1 {
                jsonrpc: JsonRpcVersion::V2,
                id,
                protocol: server_hello.protocol,
                daemon_instance_nonce: server_hello.daemon_instance_nonce,
                request: LocalRequest::Hello(HelloParams {
                    client_role: transcript.role,
                    client_nonce: transcript.client_nonce,
                    session_proof: client_proof,
                }),
            },
        )
        .await?;
        let accepted: AuthAcceptedV1 = read_json(&mut stream)
            .await
            .map_err(|_| IpcError::AuthenticationFailed)?;
        if accepted.request_id != id {
            return Err(IpcError::AuthenticationFailed);
        }
        verify_server_proof(token, &transcript, &client_proof, &accepted.server_proof)?;
        Ok(server_hello)
    })
    .await
    .map_err(|_| IpcError::HandshakeTimeout)??;

    timeout(REQUEST_TIMEOUT, async {
        let id = request_id();
        write_json(
            &mut stream,
            &JsonRpcRequestV1 {
                jsonrpc: JsonRpcVersion::V2,
                id,
                protocol: server_hello.protocol,
                daemon_instance_nonce: server_hello.daemon_instance_nonce,
                request: LocalRequest::Shutdown(EmptyParams {}),
            },
        )
        .await?;
        let response: JsonRpcSuccessV1 = read_json(&mut stream).await?;
        if response.id != id || response.result != LocalResult::Empty {
            return Err(IpcError::InvalidRequest);
        }
        Ok(())
    })
    .await
    .map_err(|_| IpcError::ShutdownTimeout)?
}

fn request_id() -> RecordId {
    RecordId::new(uuid::Uuid::now_v7()).expect("UUID v7 constructor returns a valid RecordId")
}

fn server_process(stream: &ConnectedStream) -> Result<OwnedHandle, IpcError> {
    let mut pid = 0;
    if unsafe { GetNamedPipeServerProcessId(stream.as_raw_handle(), &mut pid) } == 0 || pid == 0 {
        return Err(IpcError::Io);
    }
    let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
    if handle.is_null() {
        return Err(IpcError::Io);
    }
    // OpenProcess returns a new owned handle; it stays alive through the entire wait.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        fs,
        os::windows::process::CommandExt,
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
        time::Duration,
    };

    use context_relay_protocol::{
        ClientError, ClientRole, ErrorCode, JsonRpcRequestV1, LocalRequest, LocalResult,
        ProtocolVersion,
    };
    use tokio::time::{Instant, sleep, timeout};
    use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

    use crate::{
        AuthTranscriptV1, AuthenticatedConnection, ConnectedStream, InstallationToken,
        InstanceGuard, IpcError, Listener, RequestRegistry, RuntimeConfig, ServerHelloV1, connect,
        create_server_proof, generate_instance_nonce, read_json, verify_proof, write_json,
    };

    use super::shutdown_with;

    const TEST_LIMIT: Duration = Duration::from_secs(8);

    fn test_runtime() -> RuntimeConfig {
        RuntimeConfig::for_test(format!("test-shutdown-{}", uuid::Uuid::now_v7()), None).unwrap()
    }

    fn token() -> Result<InstallationToken, IpcError> {
        Ok(InstallationToken::from_bytes([71; 32]))
    }

    #[tokio::test]
    async fn absent_daemon_returns_without_reading_credentials_or_starting_an_endpoint() {
        let runtime = test_runtime();
        let reads = Cell::new(0);
        shutdown_with(
            &runtime,
            || {
                reads.set(reads.get() + 1);
                Err(IpcError::MissingToken)
            },
            Duration::from_millis(100),
        )
        .await
        .unwrap();
        assert_eq!(reads.get(), 0);
        assert!(matches!(
            connect(&runtime).await,
            Err(IpcError::EndpointNotFound)
        ));
        assert!(InstanceGuard::acquire(&runtime).is_ok());
    }

    #[tokio::test]
    async fn startup_without_an_endpoint_times_out_and_leaves_the_instance_owned() {
        let runtime = test_runtime();
        let _guard = InstanceGuard::acquire(&runtime).unwrap();
        let result = shutdown_with(&runtime, token, Duration::from_millis(100)).await;
        assert!(matches!(result, Err(IpcError::ShutdownTimeout)));
        assert!(matches!(
            InstanceGuard::acquire(&runtime),
            Err(IpcError::AlreadyRunning)
        ));
    }

    #[tokio::test]
    async fn authenticated_shutdown_waits_for_the_connected_process_to_exit() {
        for mode in ["ack", "legacy-ack"] {
            assert_shutdown_waits_for_exit(mode).await;
        }
    }

    #[tokio::test]
    async fn authenticated_shutdown_accepts_the_previous_1_5_preview() {
        assert_shutdown_waits_for_exit("legacy-ack-1-5").await;
        assert_shutdown_waits_for_exit("legacy-ack-1-6").await;
    }

    async fn assert_shutdown_waits_for_exit(mode: &str) {
        let mut fixture = Fixture::start(mode, false).await;
        let runtime = fixture.runtime.clone();
        let operation = shutdown_with(&runtime, token, TEST_LIMIT);
        tokio::pin!(operation);
        let ack = fixture.root.join("ack");
        tokio::select! {
            result = &mut operation => panic!("shutdown returned before server exit: {result:?}"),
            () = wait_for(&ack) => {}
        }
        assert!(fixture.child.try_wait().unwrap().is_none());
        assert!(
            timeout(Duration::from_millis(100), &mut operation)
                .await
                .is_err()
        );
        fs::write(fixture.root.join("exit"), b"").unwrap();
        operation.await.unwrap();
        assert!(fixture.child.try_wait().unwrap().unwrap().success());
        fixture.finish().await;
    }

    #[tokio::test]
    async fn legacy_shutdown_rejects_unqualified_versions_and_invalid_server_authentication() {
        for mode in ["legacy-unsupported", "legacy-bad-proof", "legacy-auth-id"] {
            let fixture = Fixture::start(mode, false).await;
            let result = shutdown_with(&fixture.runtime, token, TEST_LIMIT).await;
            if mode == "legacy-unsupported" {
                assert!(matches!(result, Err(IpcError::ProtocolVersionUnsupported)));
            } else {
                assert!(matches!(result, Err(IpcError::AuthenticationFailed)));
            }
            assert!(!fixture.root.join("request").exists(), "mode: {mode}");
            fixture.finish().await;
        }
    }

    #[tokio::test]
    async fn legacy_shutdown_rejects_invalid_acknowledgments() {
        for mode in [
            "legacy-response-id",
            "legacy-wrong-ack",
            "legacy-extra-field",
            "legacy-jsonrpc",
        ] {
            let fixture = Fixture::start(mode, false).await;
            assert!(
                shutdown_with(&fixture.runtime, token, TEST_LIMIT)
                    .await
                    .is_err(),
                "mode: {mode}"
            );
            assert!(fixture.root.join("request").exists());
            fixture.finish().await;
        }
    }

    #[tokio::test]
    async fn shutdown_retries_while_an_existing_instance_is_starting() {
        let mut fixture = Fixture::start("ack", true).await;
        fs::write(fixture.root.join("exit"), b"").unwrap();
        shutdown_with(&fixture.runtime, token, TEST_LIMIT)
            .await
            .unwrap();
        assert!(fixture.child.try_wait().unwrap().unwrap().success());
        assert!(fixture.root.join("ack").exists());
        fixture.finish().await;
    }

    #[tokio::test]
    async fn authentication_failure_never_sends_shutdown() {
        let fixture = Fixture::start("bad-auth", false).await;
        let result = shutdown_with(
            &fixture.runtime,
            || Ok(InstallationToken::from_bytes([72; 32])),
            TEST_LIMIT,
        )
        .await;
        assert!(matches!(result, Err(IpcError::AuthenticationFailed)));
        assert!(!fixture.root.join("request").exists());
        fixture.finish().await;
    }

    #[tokio::test]
    async fn shutdown_requires_a_successful_empty_acknowledgment() {
        for mode in ["wrong-ack", "rejected", "disconnect"] {
            let fixture = Fixture::start(mode, false).await;
            assert!(
                shutdown_with(&fixture.runtime, token, TEST_LIMIT)
                    .await
                    .is_err(),
                "mode: {mode}"
            );
            assert!(fixture.root.join("request").exists());
            fixture.finish().await;
        }
    }

    #[tokio::test]
    async fn a_live_process_after_acknowledgment_times_out_without_termination() {
        let mut fixture = Fixture::start("ack", false).await;
        let result = shutdown_with(&fixture.runtime, token, Duration::from_millis(250)).await;
        assert!(matches!(result, Err(IpcError::ShutdownTimeout)));
        assert!(fixture.root.join("ack").exists());
        assert!(fixture.child.try_wait().unwrap().is_none());
        fs::write(fixture.root.join("exit"), b"").unwrap();
        fixture.finish().await;
    }

    #[tokio::test]
    async fn an_unresponsive_authenticated_server_has_a_bounded_shutdown() {
        let fixture = Fixture::start("no-ack", false).await;
        let result = shutdown_with(&fixture.runtime, token, Duration::from_millis(250)).await;
        assert!(matches!(result, Err(IpcError::ShutdownTimeout)));
        assert!(fixture.root.join("request").exists());
        fs::write(fixture.root.join("exit"), b"").unwrap();
        fixture.finish().await;
    }

    struct Fixture {
        child: Child,
        runtime: RuntimeConfig,
        root: PathBuf,
    }

    impl Fixture {
        async fn start(mode: &str, delayed: bool) -> Self {
            let suffix = format!("test-shutdown-{}", uuid::Uuid::now_v7());
            let root = std::env::temp_dir().join(&suffix);
            fs::create_dir(&root).unwrap();
            let child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "shutdown::tests::shutdown_server_fixture",
                    "--ignored",
                    "--nocapture",
                ])
                .env("CONTEXT_RELAY_SHUTDOWN_TEST_SUFFIX", &suffix)
                .env("CONTEXT_RELAY_SHUTDOWN_TEST_MODE", mode)
                .env(
                    "CONTEXT_RELAY_SHUTDOWN_TEST_DELAYED",
                    if delayed { "1" } else { "0" },
                )
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .creation_flags(CREATE_NO_WINDOW)
                .spawn()
                .unwrap();
            let fixture = Self {
                child,
                runtime: RuntimeConfig::for_test(suffix, None).unwrap(),
                root,
            };
            wait_for(&fixture.root.join("ready")).await;
            fixture
        }

        async fn finish(mut self) {
            let deadline = Instant::now() + TEST_LIMIT;
            loop {
                if let Some(status) = self.child.try_wait().unwrap() {
                    assert!(status.success());
                    fs::remove_dir_all(&self.root).unwrap();
                    return;
                }
                assert!(Instant::now() < deadline, "fixture did not exit on its own");
                sleep(Duration::from_millis(10)).await;
            }
        }
    }

    async fn wait_for(path: &Path) {
        timeout(TEST_LIMIT, async {
            while !path.exists() {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("fixture marker timed out");
    }

    // Launched only by the tests above, with a unique pipe namespace and an in-memory token.
    // Its deadline ensures a failed parent assertion cannot leave a daemon running.
    #[tokio::test]
    #[ignore]
    async fn shutdown_server_fixture() {
        let suffix = std::env::var("CONTEXT_RELAY_SHUTDOWN_TEST_SUFFIX").unwrap();
        assert!(suffix.starts_with("test-shutdown-"));
        let runtime = RuntimeConfig::for_test(&suffix, None).unwrap();
        let root = std::env::temp_dir().join(suffix);
        let mode = std::env::var("CONTEXT_RELAY_SHUTDOWN_TEST_MODE").unwrap();
        let _ = timeout(Duration::from_secs(6), async {
            let mut guard = InstanceGuard::acquire(&runtime).unwrap();
            if std::env::var("CONTEXT_RELAY_SHUTDOWN_TEST_DELAYED").unwrap() == "1" {
                fs::write(root.join("ready"), b"").unwrap();
                sleep(Duration::from_millis(150)).await;
            }
            let mut listener = Listener::bind(&runtime, &mut guard).unwrap();
            fs::write(root.join("ready"), b"").unwrap();
            let stream = listener.accept().await.unwrap();
            if mode.starts_with("legacy-") {
                legacy_server(stream, &root, &mode).await;
                return;
            }
            let connection = AuthenticatedConnection::accept(
                stream,
                &token().unwrap(),
                generate_instance_nonce().unwrap(),
                RequestRegistry::default(),
            )
            .await;
            if mode == "bad-auth" {
                assert!(matches!(connection, Err(IpcError::AuthenticationFailed)));
                return;
            }
            let mut connection = connection.unwrap();
            assert_eq!(connection.role(), ClientRole::Desktop);
            let request = connection.next_request().await.unwrap();
            assert!(matches!(request.request, LocalRequest::Shutdown(_)));
            fs::write(root.join("request"), b"").unwrap();
            match mode.as_str() {
                "ack" => {
                    connection
                        .respond(request.id, Ok(LocalResult::Empty))
                        .await
                        .unwrap();
                    fs::write(root.join("ack"), b"").unwrap();
                    wait_for(&root.join("exit")).await;
                }
                "no-ack" => wait_for(&root.join("exit")).await,
                "wrong-ack" => connection
                    .respond(request.id, Ok(LocalResult::Projects { projects: vec![] }))
                    .await
                    .unwrap(),
                "rejected" => connection
                    .respond(
                        request.id,
                        Err(ClientError {
                            code: ErrorCode::Busy,
                            message: "test refusal".into(),
                            field_path: None,
                            retryable: false,
                        }),
                    )
                    .await
                    .unwrap(),
                "disconnect" => {}
                _ => panic!("unexpected fixture mode"),
            }
        })
        .await;
    }

    // The pre---shutdown daemon already accepted these protocol 1.4 messages.
    // Freeze its wire version and replies instead of using the current server handshake.
    async fn legacy_server(mut stream: ConnectedStream, root: &Path, mode: &str) {
        let protocol = ProtocolVersion {
            major: 1,
            minor: match mode {
                "legacy-unsupported" => 3,
                "legacy-ack-1-5" => 5,
                "legacy-ack-1-6" => 6,
                _ => 4,
            },
        };
        let mut hello = ServerHelloV1::generate(generate_instance_nonce().unwrap()).unwrap();
        hello.protocol = protocol;
        write_json(&mut stream, &hello).await.unwrap();
        if mode == "legacy-unsupported" {
            assert!(
                read_json::<_, serde_json::Value>(&mut stream)
                    .await
                    .is_err()
            );
            return;
        }
        let authentication: JsonRpcRequestV1 = read_json(&mut stream).await.unwrap();
        assert_eq!(authentication.protocol, protocol);
        assert_eq!(
            authentication.daemon_instance_nonce,
            hello.daemon_instance_nonce
        );
        let LocalRequest::Hello(params) = authentication.request else {
            panic!("expected hello")
        };
        assert_eq!(params.client_role, ClientRole::Desktop);
        let transcript = AuthTranscriptV1 {
            role: params.client_role,
            client_nonce: params.client_nonce,
            server_hello: hello,
        };
        verify_proof(&token().unwrap(), &transcript, &params.session_proof).unwrap();
        let proof_token = if mode == "legacy-bad-proof" {
            InstallationToken::from_bytes([72; 32])
        } else {
            token().unwrap()
        };
        let proof = create_server_proof(&proof_token, &transcript, &params.session_proof);
        let mut accepted =
            serde_json::json!({ "requestId": authentication.id, "serverProof": proof });
        if mode == "legacy-auth-id" {
            accepted["requestId"] = serde_json::json!(uuid::Uuid::now_v7());
        }
        write_json(&mut stream, &accepted).await.unwrap();
        if matches!(mode, "legacy-bad-proof" | "legacy-auth-id") {
            assert!(
                read_json::<_, serde_json::Value>(&mut stream)
                    .await
                    .is_err()
            );
            return;
        }
        let request: JsonRpcRequestV1 = read_json(&mut stream).await.unwrap();
        assert_eq!(request.protocol, protocol);
        assert_eq!(request.daemon_instance_nonce, hello.daemon_instance_nonce);
        assert_ne!(request.id, authentication.id);
        assert!(matches!(request.request, LocalRequest::Shutdown(_)));
        fs::write(root.join("request"), b"").unwrap();
        let mut response = serde_json::json!({ "jsonrpc": "2.0", "id": request.id, "result": { "kind": "empty" } });
        match mode {
            "legacy-response-id" => response["id"] = serde_json::json!(uuid::Uuid::now_v7()),
            "legacy-wrong-ack" => {
                response["result"] =
                    serde_json::json!({ "kind": "projects", "data": { "projects": [] } })
            }
            "legacy-extra-field" => response["unexpected"] = serde_json::json!(true),
            "legacy-jsonrpc" => response["jsonrpc"] = serde_json::json!("1.0"),
            "legacy-ack" | "legacy-ack-1-5" | "legacy-ack-1-6" => {}
            _ => panic!("unexpected legacy fixture mode"),
        }
        write_json(&mut stream, &response).await.unwrap();
        if matches!(mode, "legacy-ack" | "legacy-ack-1-5" | "legacy-ack-1-6") {
            fs::write(root.join("ack"), b"").unwrap();
            wait_for(&root.join("exit")).await;
        }
    }
}
