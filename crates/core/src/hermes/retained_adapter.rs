//! Adapter ownership of a checked retained Python runtime.

use super::{HermesAdapter, conflict, invalid, python_runtime};
use crate::native_transaction::{InstalledRuntimeBinding, NativeTransactionPlan};
use context_relay_protocol::{ClientError, ErrorCode, HarnessId, NativeScope};
use python_runtime::{
    RetainedRuntimeReference,
    retained::{LockedRuntime, RetainedRuntime},
};
use std::{
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

#[derive(Clone, Debug)]
pub(super) struct AdapterRuntime {
    binding: InstalledRuntimeBinding,
    // Clones share one owner. A failed or quarantined command must never cause
    // another clone to launch the ordinary installation or reuse lost ownership.
    runtime: Arc<Mutex<Option<LockedRuntime>>>,
    cancelled: Arc<AtomicBool>,
}

impl AdapterRuntime {
    pub(super) fn binding(&self) -> &InstalledRuntimeBinding {
        &self.binding
    }

    pub(super) fn verify(&self) -> Result<(), ClientError> {
        let slot = self.runtime.try_lock().map_err(|_| busy())?;
        slot.as_ref()
            .ok_or_else(|| conflict("Hermes runtime must be reopened before retrying"))?
            .verify()
    }

    pub(super) fn check_config(&self, config: &[u8]) -> Result<Vec<u8>, ClientError> {
        let mut slot = self.runtime.try_lock().map_err(|_| busy())?;
        let runtime = slot
            .take()
            .ok_or_else(|| conflict("Hermes runtime must be reopened before retrying"))?;
        let (output, runtime) = runtime.check_config(config, &self.cancelled)?;
        *slot = Some(runtime);
        Ok(output.stdout)
    }
}

impl HermesAdapter {
    /// Prepares a retained runtime from this adapter's selected installation.
    /// The caller chooses the managed store and schedules this potentially long
    /// operation outside the desktop request path. This does not enable Full.
    pub fn prepare_retained_runtime(
        &self,
        store: &Path,
        cancelled: Arc<AtomicBool>,
    ) -> Result<RetainedRuntimeReference, ClientError> {
        self.prepare_retained_runtime_with_progress(store, cancelled, |_| {})
    }

    /// Progress contains phase-local work counts and no private paths or values.
    pub fn prepare_retained_runtime_with_progress(
        &self,
        store: &Path,
        cancelled: Arc<AtomicBool>,
        mut report: impl FnMut(python_runtime::PreparationProgress),
    ) -> Result<RetainedRuntimeReference, ClientError> {
        let mut ready = None;
        let runtime = self
            .prepare_owned_runtime(store, cancelled, |progress| {
                if progress.phase == python_runtime::PreparationPhase::Ready {
                    ready = Some(progress);
                } else {
                    report(progress);
                }
            })?
            .persist();
        // The durable API reports Ready after cleanup ownership is transferred.
        // The owned API below instead leaves cleanup with its caller.
        if let Some(progress) = ready {
            report(progress);
        }
        Ok(runtime.reference().clone())
    }

    /// The background operation owns this copy until setup commits its reference.
    pub fn prepare_owned_runtime(
        &self,
        store: &Path,
        cancelled: Arc<AtomicBool>,
        mut report: impl FnMut(python_runtime::PreparationProgress),
    ) -> Result<python_runtime::retained::PreparedRuntime, ClientError> {
        check_cancelled(&cancelled)?;
        self.revalidate_bound_installation()?;
        let captured = python_runtime::capture_with_progress(
            &self.layout.executable,
            store,
            &cancelled,
            &mut report,
        )?;
        check_cancelled(&cancelled)?;
        self.revalidate_bound_installation()?;
        captured.prepare_owned_with_progress(&cancelled, report)
    }

    /// Reopens the exact runtime bound by a verified persisted plan. The caller
    /// must authenticate and open the sealed plan before calling this method;
    /// a raw NativeTransactionPlan is not itself proof of user approval.
    pub fn reopen_approved_runtime(
        self,
        store: &Path,
        approved: &NativeTransactionPlan,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Self, ClientError> {
        check_cancelled(&cancelled)?;
        if self.preview_runtime.is_some() {
            return Err(conflict("Hermes preview cannot execute a runtime"));
        }
        let reference = self.approved_runtime_reference(approved)?;
        let runtime = RetainedRuntime::open(store, reference)?.lock()?;
        self.bind_retained_runtime(runtime, cancelled)
    }

    fn approved_runtime_reference<'a>(
        &self,
        approved: &'a NativeTransactionPlan,
    ) -> Result<&'a RetainedRuntimeReference, ClientError> {
        let setup = &approved.setup;
        setup
            .validate()
            .map_err(|_| conflict("Hermes approved runtime plan is invalid"))?;
        let projects = setup
            .target_scopes
            .iter()
            .filter(|scope| matches!(scope, NativeScope::Project { .. }))
            .collect::<Vec<_>>();
        let expected_project = NativeScope::Project {
            project_id: self.project_id,
            root: self.project_root_wire(),
        };
        if approved.approval_version != 2
            || setup.harness != HarnessId::Hermes
            || setup.adapter_version != super::HERMES_ADAPTER_VERSION
            || setup.harness_profile.as_deref() != Some(self.profile_name())
            || setup.executable_path != super::wire_path(&self.layout.executable)
            || setup.executable_hash != self.executable_hash
            || setup.harness_version != self.layout.version
            || projects.as_slice() != [&expected_project]
        {
            return Err(conflict(
                "Hermes approved runtime installation or project changed",
            ));
        }
        let Some(InstalledRuntimeBinding::HermesPythonV1 { runtime }) = &approved.installed_runtime
        else {
            return Err(conflict("Hermes approved runtime reference is missing"));
        };
        runtime.validate()?;
        Ok(runtime)
    }

    pub(super) fn bind_retained_runtime(
        mut self,
        runtime: LockedRuntime,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Self, ClientError> {
        check_cancelled(&cancelled)?;
        self.revalidate_bound_installation()?;
        if self.retained_runtime.is_some()
            || !runtime.manifest().files.iter().any(|file| {
                file.path == "metadata/hermes-launcher.exe" && file.sha256 == self.executable_hash
            })
        {
            return Err(conflict(
                "Hermes retained runtime belongs to another installation",
            ));
        }
        let (version, runtime) = runtime.check_version(&cancelled)?;
        if version != self.layout.version {
            return Err(conflict("Hermes retained runtime version changed"));
        }
        self.revalidate_bound_installation()?;
        self.retained_runtime = Some(AdapterRuntime {
            binding: InstalledRuntimeBinding::HermesPythonV1 {
                runtime: runtime.reference().clone(),
            },
            runtime: Arc::new(Mutex::new(Some(runtime))),
            cancelled,
        });
        Ok(self)
    }
}

fn busy() -> ClientError {
    ClientError {
        code: ErrorCode::Busy,
        message: "Hermes runtime is already being checked".into(),
        field_path: None,
        retryable: true,
    }
}

fn check_cancelled(cancelled: &AtomicBool) -> Result<(), ClientError> {
    if cancelled.load(Ordering::Acquire) {
        let mut error = invalid("Hermes runtime preparation was canceled");
        error.code = ErrorCode::Canceled;
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_adapter_clones_serialize_checks_without_taking_a_busy_owner() {
        let _guard = python_runtime::management_test_guard();
        let (_store, runtime) = python_runtime::runtime_fixture(b"fixture launcher");
        let owner = AdapterRuntime {
            binding: InstalledRuntimeBinding::HermesPythonV1 {
                runtime: runtime.reference().clone(),
            },
            runtime: Arc::new(Mutex::new(Some(runtime))),
            cancelled: Arc::new(AtomicBool::new(false)),
        };
        let clone = owner.clone();
        let guard = owner.runtime.lock().unwrap();
        assert_eq!(
            clone.check_config(b"model: adapter\n").unwrap_err().code,
            ErrorCode::Busy
        );
        assert!(guard.is_some());
        drop(guard);
        assert!(clone.check_config(b"model: adapter\n").is_ok());
        owner.cancelled.store(true, Ordering::Release);
        assert_eq!(
            clone.check_config(b"model: adapter\n").unwrap_err().code,
            ErrorCode::Canceled
        );
        assert!(owner.runtime.lock().unwrap().is_none());
    }
}
