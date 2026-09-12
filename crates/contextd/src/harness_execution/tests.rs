use super::*;
use crate::{ServiceStatus, WorkItem};
use tokio::sync::mpsc;

fn fixture(
    capacity: usize,
) -> (
    ExecutionClient,
    WorkerClient,
    mpsc::Sender<WorkItem>,
    mpsc::Receiver<WorkItem>,
) {
    let (sender, receiver) = mpsc::channel(capacity);
    let worker = WorkerClient {
        sender: sender.downgrade(),
        admission: Arc::new(Mutex::new(true)),
        worker_hook: None,
        status: Arc::new(ServiceStatus::new()),
    };
    (ExecutionClient::default(), worker, sender, receiver)
}
fn params() -> HarnessExecutionParams {
    HarnessExecutionParams {
        plan_id: "018f22e2-79b0-7cc8-98c4-dc0c0c07398f".parse().unwrap(),
        action: HarnessExecutionAction::Apply,
    }
}

#[test]
fn owned_admission_survives_response_drop_and_deduplicates_active_work() {
    let (client, worker, _sender, mut receiver) = fixture(1);
    let key = params();
    assert_eq!(
        client.start(&worker, key.clone()).unwrap().phase,
        Phase::Queued
    );
    assert_eq!(
        client.start(&worker, key.clone()).unwrap().phase,
        Phase::Queued
    );
    let item = receiver.try_recv().unwrap();
    assert!(receiver.try_recv().is_err());
    assert!(item.response.is_closed());
    assert!(item.admission.begin());
    assert_eq!(client.status(&key).phase, Phase::Running);
    let mut undo = key.clone();
    undo.action = HarnessExecutionAction::Rollback;
    assert_eq!(
        client.start(&worker, undo.clone()).unwrap_err().code,
        context_relay_protocol::ErrorCode::Busy
    );
    assert_eq!(client.status(&undo).phase, Phase::Unknown);
    item.admission.finished(&Ok(LocalResult::Empty));
    drop(item);
    assert_eq!(client.status(&key).phase, Phase::Finished);
    assert!(client.status(&key).error.is_none());
    // Finished is only an attempt hint: an explicit new start is still verified by the vault.
    assert_eq!(
        client.start(&worker, undo.clone()).unwrap().phase,
        Phase::Queued
    );
}

#[test]
fn queue_rejection_clears_reservation_and_dropped_work_reports_uncertainty() {
    let (client, worker, sender, mut receiver) = fixture(1);
    let key = params();
    let other = ExecutionClient::default();
    other.start(&worker, key.clone()).unwrap();
    assert_eq!(
        client.start(&worker, key.clone()).unwrap_err().code,
        context_relay_protocol::ErrorCode::Busy
    );
    assert_eq!(client.status(&key).phase, Phase::Unknown);
    drop(receiver.try_recv().unwrap());
    assert!(other.status(&key).error.is_some());
    client.start(&worker, key.clone()).unwrap();
    let item = receiver.try_recv().unwrap();
    item.admission.begin();
    drop(item); // Includes panic unwinding and receiver shutdown.
    assert_eq!(client.status(&key).phase, Phase::Finished);
    assert!(client.status(&key).error.is_some());
    *worker.admission.lock().unwrap() = false;
    assert!(client.start(&worker, key.clone()).is_err());
    drop(sender);
}

#[test]
fn attempt_errors_are_action_bound_redacted_and_cache_is_bounded() {
    let (client, worker, _sender, mut receiver) = fixture(1);
    let mut key = params();
    key.action = HarnessExecutionAction::Rollback;
    for i in 0..HISTORY_LIMIT + 5 {
        key.plan_id = format!("018f22e2-79b0-7cc8-98c4-{i:012x}").parse().unwrap();
        client.start(&worker, key.clone()).unwrap();
        let item = receiver.try_recv().unwrap();
        item.admission.begin();
        item.admission.finished(&Err(ClientError {
            message: "PRIVATE PROFILE PATH".into(),
            ..service_internal_error()
        }));
        drop(item);
    }
    assert_eq!(client.0.lock().unwrap().len(), HISTORY_LIMIT);
    assert!(
        !client
            .status(&key)
            .error
            .unwrap()
            .message
            .contains("PRIVATE")
    );
    key.action = HarnessExecutionAction::Apply;
    assert_eq!(client.status(&key).phase, Phase::Unknown);
}
