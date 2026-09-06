//! One passive preparation at a time, owned and joined by the daemon.
use context_relay_core::hermes::python_runtime::{PreparationPhase, PreparationProgress};
use context_relay_protocol::{
    ClientError, ErrorCode, HarnessPreparationPhase as Phase, HarnessPreparationStatus,
    HarnessPrepareParams, LocalRequest, OperationId, SetupPlan,
};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::JoinHandle,
};

#[cfg(windows)]
pub type PreparedArtifact = crate::bridge_install::PreparedArtifact;
#[cfg(not(windows))]
pub type PreparedArtifact = ();

/// Work contains immutable discovery inputs, never a borrowed vault or caller command.
pub type PreparationTask<T = PreparedArtifact> = Box<
    dyn FnOnce(
            Arc<AtomicBool>,
            Box<dyn FnMut(PreparationProgress) + Send>,
        ) -> Result<T, ClientError>
        + Send,
>;

struct Operation<T> {
    status: HarnessPreparationStatus,
    cancel: Arc<AtomicBool>,
    active: bool,
    artifact: Option<T>,
    previewing: bool,
    preview: Option<Box<Result<SetupPlan, ClientError>>>,
}

struct State<T> {
    accepting: bool,
    operation: Option<Operation<T>>,
}

enum Work<T> {
    Prepare(PreparationTask<T>, Option<Operation<T>>),
    Stop,
}

pub(crate) struct PreparationClient<T = PreparedArtifact> {
    state: Arc<Mutex<State<T>>>,
    sender: mpsc::SyncSender<Work<T>>,
}

impl<T> Clone for PreparationClient<T> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            sender: self.sender.clone(),
        }
    }
}

pub(crate) struct PreparationSupervisor<T = PreparedArtifact> {
    client: PreparationClient<T>,
    worker: Option<JoinHandle<()>>,
}

impl<T: Send + 'static> PreparationSupervisor<T> {
    pub(crate) fn spawn() -> std::io::Result<Self> {
        let state = Arc::new(Mutex::new(State {
            accepting: true,
            operation: None,
        }));
        // At most one Prepare and one Stop can be pending.
        let (sender, receiver) = mpsc::sync_channel(2);
        let shared = state.clone();
        let worker = std::thread::Builder::new()
            .name("harness-preparation".into())
            .spawn(move || {
                while let Ok(Work::Prepare(task, previous)) = receiver.recv() {
                    drop(previous);
                    let cancel = {
                        let state = shared.lock().unwrap_or_else(|error| error.into_inner());
                        state
                            .operation
                            .as_ref()
                            .expect("admitted operation")
                            .cancel
                            .clone()
                    };
                    let progress_state = shared.clone();
                    let report = Box::new(move |progress| {
                        let mut state = progress_state
                            .lock()
                            .unwrap_or_else(|error| error.into_inner());
                        let operation = state.operation.as_mut().expect("active operation");
                        update_progress(&mut operation.status, progress);
                    });
                    let outcome = catch_unwind(AssertUnwindSafe(|| task(cancel, report)))
                        .unwrap_or_else(|_| Err(failed()));
                    let mut state = shared.lock().unwrap_or_else(|error| error.into_inner());
                    let operation = state.operation.as_mut().expect("active operation");
                    operation.active = false;
                    match outcome {
                        Ok(artifact) => {
                            operation.artifact = Some(artifact);
                            operation.status.phase = Phase::Ready;
                        }
                        Err(error) if error.code == ErrorCode::Canceled => {
                            operation.status.phase = Phase::Canceled
                        }
                        Err(_) => {
                            operation.status.phase = Phase::Failed;
                            // Do not publish filesystem paths, command output, or panic payloads.
                            operation.status.error = Some(failed());
                        }
                    }
                }
            })?;
        Ok(Self {
            client: PreparationClient { state, sender },
            worker: Some(worker),
        })
    }

    pub(crate) fn client(&self) -> PreparationClient<T> {
        self.client.clone()
    }

    pub(crate) fn shutdown_and_join(&mut self) {
        self.client.close();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        self.client.clear();
    }

    pub(crate) async fn shutdown_and_join_async(&mut self) {
        self.client.close();
        // Keep the join handle here across awaits: dropping this future leaves
        // Drop responsible for joining before daemon instance ownership is released.
        while self
            .worker
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
        {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        self.client.clear();
    }
}

impl<T> Drop for PreparationSupervisor<T> {
    fn drop(&mut self) {
        self.client.close();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        self.client.clear();
    }
}

impl<T> PreparationClient<T> {
    /// Inspect the current operation before resolving mutable project inputs.
    /// The vault worker serializes starts; start still rechecks admission below.
    pub(crate) fn replay(
        &self,
        params: &HarnessPrepareParams,
    ) -> Result<Option<HarnessPreparationStatus>, ClientError> {
        let state = self.state.lock().map_err(|_| failed())?;
        if !state.accepting {
            return Err(super::busy_error());
        }
        if let Some(current) = &state.operation {
            if current.status.operation_id == params.operation_id {
                return if current.status.selection == params.selection {
                    Ok(Some(current.status.clone()))
                } else {
                    Err(conflict())
                };
            }
            if current.active || current.previewing {
                return Err(super::busy_error());
            }
        }
        Ok(None)
    }

    pub(crate) fn start(
        &self,
        params: HarnessPrepareParams,
        task: PreparationTask<T>,
    ) -> Result<HarnessPreparationStatus, ClientError> {
        LocalRequest::HarnessPrepare(params.clone())
            .validate()
            .map_err(|_| super::invalid_request_error())?;
        let mut state = self.state.lock().map_err(|_| failed())?;
        if !state.accepting {
            return Err(super::busy_error());
        }
        if let Some(current) = &state.operation {
            if current.status.operation_id == params.operation_id {
                return if current.status.selection == params.selection {
                    Ok(current.status.clone())
                } else {
                    Err(conflict())
                };
            }
            if current.active || current.previewing {
                return Err(super::busy_error());
            }
        }
        let status = HarnessPreparationStatus {
            operation_id: params.operation_id,
            selection: params.selection,
            phase: Phase::Inspecting,
            completed_files: 0,
            completed_bytes: 0,
            error: None,
        };
        let previous = state.operation.replace(Operation {
            status: status.clone(),
            cancel: Arc::new(AtomicBool::new(false)),
            active: true,
            artifact: None,
            previewing: false,
            preview: None,
        });
        if let Err(error) = self.sender.try_send(Work::Prepare(task, previous)) {
            let work = match error {
                mpsc::TrySendError::Full(work) | mpsc::TrySendError::Disconnected(work) => work,
            };
            if let Work::Prepare(_, previous) = work {
                state.operation = previous;
            }
            return Err(failed());
        }
        Ok(status)
    }

    pub(crate) fn status(&self, id: OperationId) -> Result<HarnessPreparationStatus, ClientError> {
        let state = self.state.lock().map_err(|_| failed())?;
        let operation = state
            .operation
            .as_ref()
            .filter(|op| op.status.operation_id == id)
            .ok_or_else(missing)?;
        Ok(operation.status.clone())
    }

    /// Called on the owned vault worker. Only admission/result publication hold
    /// the status lock; preview I/O and unused-artifact cleanup run outside it.
    pub(crate) fn preview(
        &self,
        params: &HarnessPrepareParams,
        build: impl FnOnce(T) -> Result<SetupPlan, ClientError>,
    ) -> Result<SetupPlan, ClientError> {
        LocalRequest::HarnessPreparedPreview(params.clone())
            .validate()
            .map_err(|_| super::invalid_request_error())?;
        let artifact = {
            let mut state = self.state.lock().map_err(|_| failed())?;
            if !state.accepting {
                return Err(super::busy_error());
            }
            let operation = state
                .operation
                .as_mut()
                .filter(|op| op.status.operation_id == params.operation_id)
                .ok_or_else(missing)?;
            if operation.status.selection != params.selection {
                return Err(conflict());
            }
            if let Some(result) = &operation.preview {
                return result.as_ref().clone();
            }
            if operation.active || operation.previewing {
                return Err(super::busy_error());
            }
            let artifact = operation.artifact.take().ok_or_else(missing)?;
            operation.previewing = true;
            artifact
        };
        let result =
            catch_unwind(AssertUnwindSafe(|| build(artifact))).unwrap_or_else(|_| Err(failed()));
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(operation) = state
            .operation
            .as_mut()
            .filter(|op| op.status.operation_id == params.operation_id)
        {
            operation.previewing = false;
            if result.is_err() {
                operation.status.phase = Phase::Failed;
                operation.status.error = Some(failed());
            }
            operation.preview = Some(Box::new(result.clone()));
        }
        result
    }

    pub(crate) fn cancel(&self, id: OperationId) -> Result<HarnessPreparationStatus, ClientError> {
        let mut state = self.state.lock().map_err(|_| failed())?;
        let operation = state
            .operation
            .as_mut()
            .filter(|op| op.status.operation_id == id)
            .ok_or_else(missing)?;
        if operation.active {
            operation.cancel.store(true, Ordering::Release);
            operation.status.phase = Phase::Cancelling;
        }
        Ok(operation.status.clone())
    }

    pub(crate) fn close(&self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if !state.accepting {
            return;
        }
        state.accepting = false;
        if let Some(operation) = &mut state.operation {
            operation.cancel.store(true, Ordering::Release);
        }
        let _ = self.sender.try_send(Work::Stop);
    }

    fn clear(&self) {
        let operation = self
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .operation
            .take();
        drop(operation);
    }
}

fn update_progress(status: &mut HarnessPreparationStatus, progress: PreparationProgress) {
    if status.phase != Phase::Cancelling {
        status.phase = match progress.phase {
            PreparationPhase::Inspecting => Phase::Inspecting,
            PreparationPhase::Copying => Phase::Copying,
            PreparationPhase::CheckingSource => Phase::CheckingSource,
            PreparationPhase::CheckingCopy => Phase::CheckingCopy,
            PreparationPhase::Retaining | PreparationPhase::Ready => Phase::Retaining,
        };
    }
    status.completed_files = progress.completed_files.min(32768) as u32;
    status.completed_bytes = progress.completed_bytes.min(1_073_741_824) as u32;
}

fn failed() -> ClientError {
    ClientError {
        code: ErrorCode::Internal,
        message: "Harness preparation could not finish. Check the installed harness and try again."
            .into(),
        field_path: None,
        retryable: true,
    }
}
fn missing() -> ClientError {
    ClientError {
        code: ErrorCode::NotFound,
        message: "This preparation is no longer available. Start a new check.".into(),
        field_path: None,
        retryable: false,
    }
}
fn conflict() -> ClientError {
    ClientError {
        code: ErrorCode::Conflict,
        message: "This preparation belongs to a different harness selection.".into(),
        field_path: None,
        retryable: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use context_relay_protocol::{HarnessId, HarnessParams};
    use std::{
        sync::atomic::AtomicUsize,
        time::{Duration, Instant},
    };

    fn params() -> HarnessPrepareParams {
        HarnessPrepareParams {
            operation_id: OperationId::new(uuid::Uuid::now_v7()).unwrap(),
            selection: HarnessParams {
                project_id: None,
                harness: HarnessId::Hermes,
                hermes_profile: Some("default".into()),
            },
        }
    }

    #[test]
    fn prepared_preview_consumes_once_and_keeps_status_responsive() {
        let supervisor = PreparationSupervisor::<()>::spawn().unwrap();
        let client = supervisor.client();
        let request = params();
        client
            .start(request.clone(), Box::new(|_, _| Ok(())))
            .unwrap();
        terminal(&client, request.operation_id);
        let (entered, entering) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let preview_client = client.clone();
        let preview_request = request.clone();
        let plan: context_relay_protocol::SetupPlan = serde_json::from_value(
            serde_json::from_str::<serde_json::Value>(include_str!(
                "../../protocol/tests/fixtures/runtime-contracts-v1.json"
            ))
            .unwrap()["setupPlan"]
                .clone(),
        )
        .unwrap();
        let expected = plan.clone();
        let thread = std::thread::spawn(move || {
            preview_client.preview(&preview_request, |_| {
                entered.send(()).unwrap();
                released.recv().unwrap();
                Ok(plan)
            })
        });
        entering.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(
            client.status(request.operation_id).unwrap().phase,
            Phase::Ready
        );
        assert_eq!(
            client.cancel(request.operation_id).unwrap().phase,
            Phase::Ready
        );
        assert_eq!(
            client
                .start(params(), Box::new(|_, _| Ok(())))
                .unwrap_err()
                .code,
            ErrorCode::Busy
        );
        assert_eq!(
            client
                .preview(&request, |_| unreachable!())
                .unwrap_err()
                .code,
            ErrorCode::Busy
        );
        let mut changed = request.clone();
        changed.selection.hermes_profile = Some("another".into());
        assert_eq!(
            client
                .preview(&changed, |_| unreachable!())
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
        release.send(()).unwrap();
        assert_eq!(thread.join().unwrap().unwrap(), expected);
        assert_eq!(
            client
                .preview(&request, |_| panic!("must replay saved review"))
                .unwrap(),
            expected
        );
    }

    #[test]
    fn failed_preview_replays_error_without_reusing_the_copy() {
        let supervisor = PreparationSupervisor::<()>::spawn().unwrap();
        let client = supervisor.client();
        for panic in [false, true] {
            let request = params();
            client
                .start(request.clone(), Box::new(|_, _| Ok(())))
                .unwrap();
            terminal(&client, request.operation_id);
            let result = client.preview(&request, |_| {
                assert!(!panic, "private panic payload");
                Err(conflict())
            });
            assert!(result.is_err());
            assert_eq!(
                client.status(request.operation_id).unwrap().phase,
                Phase::Failed
            );
            let again = client.preview(&request, |_| panic!("must not consume again"));
            assert_eq!(again, result);
            assert!(
                !serde_json::to_string(&client.status(request.operation_id).unwrap())
                    .unwrap()
                    .contains("payload")
            );
        }
    }

    fn terminal<T>(client: &PreparationClient<T>, id: OperationId) -> HarnessPreparationStatus {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let status = client.status(id).unwrap();
            if matches!(status.phase, Phase::Ready | Phase::Canceled | Phase::Failed) {
                return status;
            }
            assert!(Instant::now() < deadline, "preparation did not settle");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn status_and_cancel_do_not_wait_for_copy_and_retry_does_not_spawn_again() {
        let supervisor = PreparationSupervisor::<()>::spawn().unwrap();
        let client = supervisor.client();
        let request = params();
        let (entered, entering) = mpsc::channel();
        let (release, released) = mpsc::channel();
        client
            .start(
                request.clone(),
                Box::new(move |cancel, mut report| {
                    report(PreparationProgress {
                        phase: PreparationPhase::Copying,
                        completed_files: 1,
                        completed_bytes: 65536,
                    });
                    entered.send(()).unwrap();
                    released.recv().unwrap();
                    assert!(cancel.load(Ordering::Acquire));
                    Err(super::super::canceled_error())
                }),
            )
            .unwrap();
        entering.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(
            client.status(request.operation_id).unwrap().completed_bytes,
            65536
        );
        assert_eq!(
            client
                .start(request.clone(), Box::new(|_, _| panic!("duplicate work")))
                .unwrap()
                .phase,
            Phase::Copying
        );
        let mut changed = request.clone();
        changed.selection.hermes_profile = Some("other".into());
        assert_eq!(
            client
                .start(changed, Box::new(|_, _| Ok(())))
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
        assert_eq!(
            client
                .start(params(), Box::new(|_, _| Ok(())))
                .unwrap_err()
                .code,
            ErrorCode::Busy
        );
        assert_eq!(
            client.cancel(request.operation_id).unwrap().phase,
            Phase::Cancelling
        );
        release.send(()).unwrap();
        assert_eq!(
            terminal(&client, request.operation_id).phase,
            Phase::Canceled
        );
    }

    struct Artifact(Arc<AtomicUsize>);
    impl Drop for Artifact {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn ready_waits_for_owned_result_and_unused_results_are_cleaned_on_worker() {
        let supervisor = PreparationSupervisor::<Artifact>::spawn().unwrap();
        let client = supervisor.client();
        let request = params();
        let drops = Arc::new(AtomicUsize::new(0));
        let owned = drops.clone();
        let (entered, entering) = mpsc::channel();
        let (release, released) = mpsc::channel();
        client
            .start(
                request.clone(),
                Box::new(move |_, mut report| {
                    report(PreparationProgress {
                        phase: PreparationPhase::Ready,
                        completed_files: 2,
                        completed_bytes: 4,
                    });
                    entered.send(()).unwrap();
                    released.recv().unwrap();
                    Ok(Artifact(owned))
                }),
            )
            .unwrap();
        entering.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(
            client.status(request.operation_id).unwrap().phase,
            Phase::Retaining
        );
        client.cancel(request.operation_id).unwrap();
        release.send(()).unwrap();
        assert_eq!(terminal(&client, request.operation_id).phase, Phase::Ready);
        assert_eq!(
            client.cancel(request.operation_id).unwrap().phase,
            Phase::Ready
        );
        let next = params();
        let owned = drops.clone();
        client
            .start(next.clone(), Box::new(move |_, _| Ok(Artifact(owned))))
            .unwrap();
        terminal(&client, next.operation_id);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        drop(supervisor);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        assert_eq!(
            client
                .start(params(), Box::new(|_, _| unreachable!()))
                .unwrap_err()
                .code,
            ErrorCode::Busy
        );
    }

    #[test]
    fn shutdown_cancels_and_joins_before_releasing_ownership() {
        let supervisor = PreparationSupervisor::<Artifact>::spawn().unwrap();
        let client = supervisor.client();
        let request = params();
        let drops = Arc::new(AtomicUsize::new(0));
        let owned = drops.clone();
        let (entered, entering) = mpsc::channel();
        let (release, released) = mpsc::channel();
        client
            .start(
                request,
                Box::new(move |cancel, _| {
                    entered.send(()).unwrap();
                    released.recv().unwrap();
                    assert!(cancel.load(Ordering::Acquire));
                    Ok(Artifact(owned))
                }),
            )
            .unwrap();
        entering.recv_timeout(Duration::from_secs(5)).unwrap();
        client.close();
        let (done, finished) = mpsc::channel();
        let join = std::thread::spawn(move || {
            drop(supervisor);
            done.send(()).unwrap();
        });
        assert!(matches!(
            finished.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        release.send(()).unwrap();
        finished.recv_timeout(Duration::from_secs(5)).unwrap();
        join.join().unwrap();
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn panic_is_redacted_and_next_operation_can_start() {
        let supervisor = PreparationSupervisor::<()>::spawn().unwrap();
        let client = supervisor.client();
        let request = params();
        client
            .start(request.clone(), Box::new(|_, _| panic!("private canary")))
            .unwrap();
        let status = terminal(&client, request.operation_id);
        assert_eq!(status.phase, Phase::Failed);
        assert!(!serde_json::to_string(&status).unwrap().contains("canary"));
        let next = params();
        client.start(next.clone(), Box::new(|_, _| Ok(()))).unwrap();
        assert_eq!(terminal(&client, next.operation_id).phase, Phase::Ready);
    }
}
