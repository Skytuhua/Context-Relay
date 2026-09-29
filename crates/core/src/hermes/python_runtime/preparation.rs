//! Progress for passive preparation. No paths or configuration values are reported.

use context_relay_protocol::{ClientError, ErrorCode};
use std::{
    cell::{Cell, RefCell},
    sync::atomic::{AtomicBool, Ordering},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparationPhase {
    Inspecting,
    Copying,
    CheckingSource,
    CheckingCopy,
    Retaining,
    Ready,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparationProgress {
    pub phase: PreparationPhase,
    /// Work completed in the active phase, not an estimate. Ready keeps retention totals.
    pub completed_files: u64,
    pub completed_bytes: u64,
}

pub(super) struct Control<'a> {
    cancelled: &'a AtomicBool,
    report: RefCell<&'a mut dyn FnMut(PreparationProgress)>,
    progress: Cell<PreparationProgress>,
}

pub(super) fn canceled() -> ClientError {
    ClientError {
        code: ErrorCode::Canceled,
        message: "Hermes runtime preparation was canceled".into(),
        field_path: None,
        retryable: false,
    }
}

impl<'a> Control<'a> {
    pub(super) fn new(
        cancelled: &'a AtomicBool,
        report: &'a mut dyn FnMut(PreparationProgress),
    ) -> Self {
        Self {
            cancelled,
            report: RefCell::new(report),
            progress: Cell::new(PreparationProgress {
                phase: PreparationPhase::Inspecting,
                completed_files: 0,
                completed_bytes: 0,
            }),
        }
    }
    pub(super) fn check(&self) -> Result<(), ClientError> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(canceled());
        }
        Ok(())
    }
    pub(super) fn phase(&self, phase: PreparationPhase) -> Result<(), ClientError> {
        self.check()?;
        self.progress.set(PreparationProgress {
            phase,
            completed_files: 0,
            completed_bytes: 0,
        });
        self.notify();
        self.check()
    }

    pub(super) fn check_paths(
        &self,
        paths: &[context_relay_native_runner::StagePath],
    ) -> Result<(), ClientError> {
        use context_relay_native_runner::{
            RunnerError, RuntimeTarget, validate_path_set_cancellable,
        };
        validate_path_set_cancellable(RuntimeTarget::WindowsX86_64, paths, || {
            self.check().is_err()
        })
        .map_err(|error| {
            if error == RunnerError::Canceled {
                canceled()
            } else {
                super::invalid()
            }
        })
    }
    pub(super) fn bytes(&self, count: u64) -> Result<(), ClientError> {
        self.check()?;
        let mut progress = self.progress.get();
        progress.completed_bytes = progress.completed_bytes.saturating_add(count);
        self.progress.set(progress);
        self.notify();
        self.check()
    }
    pub(super) fn file(&self) -> Result<(), ClientError> {
        self.check()?;
        let mut progress = self.progress.get();
        progress.completed_files += 1;
        self.progress.set(progress);
        self.notify();
        self.check()
    }
    // Publication has committed. A concurrent cancel cannot turn a retained
    // reference into an unreported failure after its cleanup owner was released.
    #[cfg(windows)]
    pub(super) fn ready(&self) {
        let mut progress = self.progress.get();
        progress.phase = PreparationPhase::Ready;
        self.progress.set(progress);
        self.notify();
    }
    fn notify(&self) {
        (self.report.borrow_mut())(self.progress.get());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hermes::python_runtime::{RuntimeSource, capture_inputs_controlled};
    use std::fs;

    fn cancel_at(phase: PreparationPhase) {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let source = root.join("source");
        fs::create_dir(&source).unwrap();
        let bytes = vec![b'x'; 256 * 1024];
        fs::write(source.join("module.py"), &bytes).unwrap();
        let cancelled = AtomicBool::new(false);
        let mut observed = Vec::new();
        let mut report = |progress: PreparationProgress| {
            observed.push(progress);
            if progress.phase == phase && progress.completed_bytes >= 64 * 1024 {
                cancelled.store(true, Ordering::Release);
            }
        };
        let control = Control::new(&cancelled, &mut report);
        let result = (|| {
            let captured = capture_inputs_controlled(
                &root,
                vec![RuntimeSource {
                    source: source.clone(),
                    destination: "source".into(),
                }],
                &control,
            )?;
            captured.verify_controlled(&control)?;
            #[cfg(windows)]
            let _retained = captured.retain_controlled(&control)?;
            Ok::<_, ClientError>(())
        })();
        assert_eq!(result.unwrap_err().code, ErrorCode::Canceled);
        assert!(
            observed
                .iter()
                .any(|p| p.phase == phase && p.completed_bytes >= 64 * 1024)
        );
        assert!(!observed.iter().any(|p| p.phase == PreparationPhase::Ready));
        if phase != PreparationPhase::Retaining {
            assert!(
                observed
                    .iter()
                    .filter(|p| p.phase == phase)
                    .all(|p| p.completed_bytes <= 64 * 1024)
            );
        }
        assert_eq!(fs::read(source.join("module.py")).unwrap(), bytes);
        assert_eq!(
            fs::read_dir(temp.path()).unwrap().count(),
            1,
            "canceled preparation must clean its owned holder"
        );
    }

    #[test]
    fn preparation_cancels_copy_source_recheck_and_copy_verification_with_cleanup() {
        for phase in [
            PreparationPhase::Copying,
            PreparationPhase::CheckingSource,
            PreparationPhase::CheckingCopy,
        ] {
            cancel_at(phase);
        }
    }

    #[cfg(windows)]
    #[test]
    fn preparation_cancels_retention_before_publishing_a_reference() {
        cancel_at(PreparationPhase::Retaining);
    }

    #[test]
    fn preparation_cancel_before_start_never_reads_the_installation() {
        let error = crate::hermes::python_runtime::capture_with_progress(
            std::path::Path::new("missing.exe"),
            std::path::Path::new("missing-store"),
            &AtomicBool::new(true),
            |_| panic!("already canceled work cannot report a started phase"),
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::Canceled);
    }

    #[cfg(windows)]
    #[test]
    fn preparation_reports_completed_work_and_returns_a_reference_after_publication_wins_cancel() {
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let source = root.join("source");
        fs::create_dir(&source).unwrap();
        fs::create_dir(source.join("empty")).unwrap();
        fs::write(source.join("module.py"), vec![b'x'; 128 * 1024]).unwrap();
        fs::write(source.join("empty.py"), []).unwrap();
        let cancelled = AtomicBool::new(false);
        let mut observed = Vec::new();
        let mut report = |progress: PreparationProgress| {
            observed.push(progress);
            if progress.phase == PreparationPhase::Ready {
                cancelled.store(true, Ordering::Release);
            }
        };
        let control = Control::new(&cancelled, &mut report);
        let captured = capture_inputs_controlled(
            &root,
            vec![RuntimeSource {
                source,
                destination: "source".into(),
            }],
            &control,
        )
        .unwrap();
        captured.verify_controlled(&control).unwrap();
        let retained = captured.retain_controlled(&control).unwrap();
        let reference = retained.reference().clone();
        drop(retained);
        assert!(cancelled.load(Ordering::Acquire));
        let mut phases = observed.iter().map(|p| p.phase).collect::<Vec<_>>();
        phases.dedup();
        assert_eq!(
            phases,
            [
                PreparationPhase::Copying,
                PreparationPhase::CheckingSource,
                PreparationPhase::CheckingCopy,
                PreparationPhase::Retaining,
                PreparationPhase::Ready
            ]
        );
        for phase in phases {
            let last = observed.iter().rfind(|p| p.phase == phase).unwrap();
            assert_eq!(
                (last.completed_files, last.completed_bytes),
                (2, 128 * 1024)
            );
        }
        crate::hermes::python_runtime::retained::RetainedRuntime::open(&root, &reference)
            .unwrap()
            .verify()
            .unwrap();
    }
}
