use super::*;
use context_relay_local_ipc::{
    AuthenticatedConnection, InstallationToken, InstanceGuard, Listener, RequestRegistry,
    RuntimeConfig,
};
use context_relay_protocol::{
    DaemonInstanceNonce, EmptyParams, HarnessId, HarnessParams, HarnessPreparationIdParams,
    HarnessPreparationPhase, HarnessPreparationStatus,
};
use std::{sync::Arc, time::Duration};
use tokio::{sync::oneshot, task::JoinSet, time::timeout};

#[tokio::test]
async fn status_cancel_and_health_cross_desktop_transport_while_a_vault_call_is_blocked() {
    #[cfg(windows)]
    let temp = tempfile::tempdir().unwrap();
    #[cfg(target_os = "macos")]
    let temp = tempfile::Builder::new()
        .prefix("cr-control-")
        .tempdir_in("/tmp")
        .unwrap();
    let runtime = RuntimeConfig::for_test(
        format!("desktop-control-{}", uuid::Uuid::now_v7()),
        Some(temp.path().to_owned()),
    )
    .unwrap();
    let mut instance = InstanceGuard::acquire(&runtime).unwrap();
    let mut listener = Listener::bind(&runtime, &mut instance).unwrap();
    let token = Arc::new(InstallationToken::from_bytes([0x48; 32]));
    let server_token = token.clone();
    let (entered, started) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let mut tasks = JoinSet::new();
    tasks.spawn(async move {
        let _instance = instance;
        let registry = RequestRegistry::default();
        let nonce = DaemonInstanceNonce::new([0x49; 32]);
        let mut ordinary = AuthenticatedConnection::accept(
            listener.accept().await.unwrap(),
            &server_token,
            nonce,
            registry.clone(),
        )
        .await
        .unwrap();
        assert_eq!(ordinary.role(), ClientRole::Desktop);
        let request = ordinary.next_request().await.unwrap();
        assert!(matches!(request.request, LocalRequest::ProjectsList(_)));
        assert!(request.registration.begin());
        entered.send(()).unwrap();
        let mut blocked = JoinSet::new();
        blocked.spawn(async move {
            released.await.unwrap();
            ordinary
                .respond(request.id, Ok(LocalResult::Projects { projects: vec![] }))
                .await
                .unwrap();
            drop(request.registration);
        });
        let mut control = AuthenticatedConnection::accept(
            listener.accept().await.unwrap(),
            &server_token,
            nonce,
            registry,
        )
        .await
        .unwrap();
        assert_eq!(control.role(), ClientRole::Desktop);
        // All three calls must reuse this control connection while ordinary is blocked.
        for expected in [
            "status",
            "cancel",
            "start",
            "execution",
            "current",
            "health",
        ] {
            let request = control.next_request().await.unwrap();
            assert!(request.registration.begin());
            let result = match (&request.request, expected) {
                (LocalRequest::HarnessExecutionCurrent(_), "current") => {
                    LocalResult::HarnessExecutionCurrent { status: None }
                }
                (LocalRequest::HarnessExecutionStart(params), "start")
                | (LocalRequest::HarnessExecutionStatus(params), "execution") => {
                    LocalResult::HarnessExecution {
                        status: context_relay_protocol::HarnessExecutionStatus {
                            plan_id: params.plan_id,
                            action: params.action,
                            phase: context_relay_protocol::HarnessExecutionPhase::Running,
                            error: None,
                        },
                    }
                }
                (LocalRequest::HarnessPreparationStatus(params), "status")
                | (LocalRequest::HarnessPreparationCancel(params), "cancel") => {
                    LocalResult::HarnessPreparation {
                        status: HarnessPreparationStatus {
                            operation_id: params.operation_id,
                            selection: HarnessParams {
                                harness: HarnessId::Hermes,
                                project_id: None,
                                hermes_profile: Some("default".into()),
                            },
                            phase: if expected == "cancel" {
                                HarnessPreparationPhase::Cancelling
                            } else {
                                HarnessPreparationPhase::Copying
                            },
                            completed_files: 1,
                            completed_bytes: 8,
                            error: None,
                        },
                    }
                }
                (LocalRequest::Health(_), "health") => LocalResult::Health {
                    protocol: PROTOCOL_VERSION,
                    vault_locked: false,
                },
                _ => panic!("unexpected control request"),
            };
            control.respond(request.id, Ok(result)).await.unwrap();
        }
        blocked.join_next().await.unwrap().unwrap();
    });
    let state = Arc::new(LocalClientState::default());
    let ordinary_state = state.clone();
    let ordinary_runtime = runtime.clone();
    let ordinary_token = token.clone();
    let ordinary = tokio::spawn(async move {
        local_request_with(
            LocalRequest::ProjectsList(EmptyParams {}),
            |role, id, request| async move {
                ordinary_state
                    .call_with(role, id, request, |role| async move {
                        Client::connect_for_test(&ordinary_runtime, role, &ordinary_token).await
                    })
                    .await
            },
        )
        .await
    });
    timeout(Duration::from_secs(5), started)
        .await
        .unwrap()
        .unwrap();
    let id = HarnessPreparationIdParams {
        operation_id: "018f22e2-79b0-7cc8-98c4-dc0c0c075701".parse().unwrap(),
    };
    for request in [
        LocalRequest::HarnessPreparationStatus(id.clone()),
        LocalRequest::HarnessPreparationCancel(id),
        LocalRequest::HarnessExecutionStart(context_relay_protocol::HarnessExecutionParams {
            plan_id: "018f22e2-79b0-7cc8-98c4-dc0c0c075701".parse().unwrap(),
            action: context_relay_protocol::HarnessExecutionAction::Apply,
        }),
        LocalRequest::HarnessExecutionStatus(context_relay_protocol::HarnessExecutionParams {
            plan_id: "018f22e2-79b0-7cc8-98c4-dc0c0c075701".parse().unwrap(),
            action: context_relay_protocol::HarnessExecutionAction::Apply,
        }),
        LocalRequest::HarnessExecutionCurrent(EmptyParams {}),
        LocalRequest::Health(EmptyParams {}),
    ] {
        let result = timeout(
            Duration::from_secs(2),
            local_request_with(request, |role, id, request| {
                state.call_with(role, id, request, |role| {
                    Client::connect_for_test(&runtime, role, &token)
                })
            }),
        )
        .await
        .expect("control must not wait for the ordinary client mutex")
        .unwrap();
        assert!(
            !ordinary.is_finished(),
            "the vault request must still be blocked"
        );
        assert!(matches!(
            result,
            LocalResult::HarnessPreparation { .. }
                | LocalResult::HarnessExecution { .. }
                | LocalResult::HarnessExecutionCurrent { .. }
                | LocalResult::Health { .. }
        ));
    }
    release.send(()).unwrap();
    assert_eq!(
        ordinary.await.unwrap().unwrap(),
        LocalResult::Projects { projects: vec![] }
    );
    tasks.join_next().await.unwrap().unwrap();
}
