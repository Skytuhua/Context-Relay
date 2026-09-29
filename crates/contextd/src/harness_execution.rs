//! Short-lived attempt observations. The vault remains the only durable authority.
use crate::{VaultCommand, WorkAdmission, WorkerClient, busy_error, service_internal_error};
use context_relay_protocol::{
    ClientError, HarnessExecutionAction, HarnessExecutionParams, HarnessExecutionPhase as Phase,
    HarnessExecutionStatus, LocalRequest, LocalResult, PlanParams,
};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

const HISTORY_LIMIT: usize = 16;
#[derive(Default, Clone)]
pub(crate) struct ExecutionClient(Arc<Mutex<VecDeque<Arc<Mutex<Attempt>>>>>);
struct Attempt {
    status: HarnessExecutionStatus,
    accepted: bool,
}

impl ExecutionClient {
    /// Find the most recent accepted attempt without waiting for the vault worker.
    pub(crate) fn current(&self) -> Option<HarnessExecutionStatus> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find_map(|entry| {
                let attempt = entry.lock().unwrap_or_else(|e| e.into_inner());
                attempt.accepted.then(|| attempt.status.clone())
            })
    }
    pub(crate) fn status(&self, params: &HarnessExecutionParams) -> HarnessExecutionStatus {
        let entries = self.0.lock().unwrap_or_else(|e| e.into_inner());
        entries
            .iter()
            .find_map(|entry| {
                let attempt = entry.lock().unwrap_or_else(|e| e.into_inner());
                (matches_key(&attempt.status, params) && attempt.accepted)
                    .then(|| attempt.status.clone())
            })
            .unwrap_or(HarnessExecutionStatus {
                plan_id: params.plan_id,
                action: params.action,
                phase: Phase::Unknown,
                error: None,
            })
    }

    pub(crate) fn start(
        &self,
        worker: &WorkerClient,
        params: HarnessExecutionParams,
    ) -> Result<HarnessExecutionStatus, ClientError> {
        let entry = {
            let mut entries = self.0.lock().unwrap_or_else(|e| e.into_inner());
            for entry in entries.iter() {
                let attempt = entry.lock().unwrap_or_else(|e| e.into_inner());
                if matches!(attempt.status.phase, Phase::Queued | Phase::Running) {
                    return if matches_key(&attempt.status, &params) && attempt.accepted {
                        Ok(attempt.status.clone())
                    } else {
                        Err(busy_error())
                    };
                }
            }
            entries.retain(|entry| {
                !matches_key(
                    &entry.lock().unwrap_or_else(|e| e.into_inner()).status,
                    &params,
                )
            });
            while entries.len() >= HISTORY_LIMIT {
                entries.pop_back();
            }
            let entry = Arc::new(Mutex::new(Attempt {
                accepted: false,
                status: HarnessExecutionStatus {
                    plan_id: params.plan_id,
                    action: params.action,
                    phase: Phase::Queued,
                    error: None,
                },
            }));
            entries.push_front(entry.clone());
            entry
        };
        let request = match params.action {
            HarnessExecutionAction::Apply => LocalRequest::HarnessApply(PlanParams {
                plan_id: params.plan_id,
            }),
            HarnessExecutionAction::Rollback => LocalRequest::HarnessRollback(PlanParams {
                plan_id: params.plan_id,
            }),
        };
        // Admission belongs to this ticket after enqueue, not to the IPC connection.
        // No coordinator lock surrounds the worker queue or any execution.
        match worker.try_submit(
            VaultCommand::HarnessSetup(request),
            ExecutionTicket(entry.clone()),
        ) {
            Ok(receiver) => {
                drop(receiver);
                let mut attempt = entry.lock().unwrap_or_else(|e| e.into_inner());
                attempt.accepted = true;
                Ok(attempt.status.clone())
            }
            Err(error) => {
                self.0
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .retain(|other| !Arc::ptr_eq(other, &entry));
                Err(error)
            }
        }
    }
}

fn matches_key(status: &HarnessExecutionStatus, params: &HarnessExecutionParams) -> bool {
    status.plan_id == params.plan_id && status.action == params.action
}

struct ExecutionTicket(Arc<Mutex<Attempt>>);
impl WorkAdmission for ExecutionTicket {
    fn begin(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .status
            .phase = Phase::Running;
        true
    }
    fn finished(&self, result: &Result<LocalResult, ClientError>) {
        let mut attempt = self.0.lock().unwrap_or_else(|e| e.into_inner());
        attempt.status.phase = Phase::Finished;
        attempt.status.error = result.as_ref().err().map(|error| ClientError {
            code: error.code,
            message: "The setup operation did not finish successfully. Review its saved result before trying again.".into(),
            field_path: None, retryable: error.retryable,
        });
    }
}
impl Drop for ExecutionTicket {
    fn drop(&mut self) {
        let mut attempt = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if attempt.status.phase != Phase::Finished {
            attempt.status.phase = Phase::Finished;
            attempt.status.error = Some(ClientError { message: "The setup result was not confirmed. Review its saved result before trying again.".into(), ..service_internal_error() });
        }
    }
}

#[cfg(test)]
mod tests;
