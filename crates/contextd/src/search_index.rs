use std::{path::PathBuf, time::Duration};

use context_relay_core::vault::{SemanticIndexBatch, Vault, VaultError};
use context_relay_protocol::{SearchIndexPhase, SearchIndexStatus};

#[cfg(windows)]
pub(super) fn resources_beside_executable(
    executable: &std::path::Path,
) -> Result<PathBuf, crate::DaemonError> {
    // MSIX can redirect file opens while leaving directory resolution unchanged.
    // Resolve the executable file before deriving the adjacent resource directory.
    let executable = executable
        .canonicalize()
        .map_err(|_| crate::DaemonError::Startup)?;
    Ok(executable
        .parent()
        .ok_or(crate::DaemonError::Startup)?
        .join("search"))
}

pub(super) struct SearchIndexJob {
    pub(super) status: SearchIndexStatus,
    pending: bool,
    resources: Option<PathBuf>,
}

impl SearchIndexJob {
    pub(super) fn new(enabled: bool) -> Self {
        Self {
            status: SearchIndexStatus {
                phase: if enabled {
                    SearchIndexPhase::Preparing
                } else {
                    SearchIndexPhase::Disabled
                },
                revision: 0,
            },
            pending: enabled,
            resources: None,
        }
    }

    pub(super) fn with_resources(mut self, resources: Option<PathBuf>) -> Self {
        if resources.is_some() {
            self.status.phase = SearchIndexPhase::Preparing;
            self.pending = true;
        }
        self.resources = resources;
        self
    }

    pub(super) fn wake(&mut self) {
        if matches!(
            self.status.phase,
            SearchIndexPhase::Preparing | SearchIndexPhase::Ready
        ) {
            self.pending = true;
        }
    }

    pub(super) fn retry(&mut self) {
        if self.status.phase == SearchIndexPhase::Failed {
            self.change_phase(SearchIndexPhase::Preparing);
            self.pending = true;
        }
    }

    pub(super) fn pending(&self) -> bool {
        self.pending
    }

    pub(super) fn fail(&mut self) {
        self.pending = false;
        self.change_phase(SearchIndexPhase::Failed);
    }

    pub(super) fn tick(&mut self, vault: &mut Vault) {
        if !vault.semantic_search_enabled() {
            let Some(resources) = &self.resources else {
                self.fail();
                return;
            };
            match context_relay_core::search::PinnedModelEmbedder::load_packaged(resources) {
                Ok(model) => vault.enable_semantic_search(model),
                Err(error) => self.finish(Err(error.into())),
            }
            // Return to the request queue between model loading and indexing.
            return;
        }
        // One inference cannot be preempted. The worker checks queued requests
        // and shutdown again before admitting the next record.
        let result = vault.index_semantic_batch(1, Duration::from_millis(50));
        if matches!(&result, Err(VaultError::SearchModel(_))) {
            vault.reset_semantic_search();
        }
        self.finish(result);
    }

    fn finish(&mut self, result: Result<SemanticIndexBatch, VaultError>) {
        match result {
            Ok(batch) => {
                self.pending = batch.remaining > 0;
                if batch.processed > 0 {
                    self.status.revision = self.status.revision.saturating_add(1);
                }
                self.change_phase(if self.pending {
                    SearchIndexPhase::Preparing
                } else {
                    SearchIndexPhase::Ready
                });
            }
            Err(_) => {
                // Keep persisted vectors and pause until an explicit retry.
                self.fail();
            }
        }
    }

    fn change_phase(&mut self, phase: SearchIndexPhase) {
        if self.status.phase != phase {
            self.status.phase = phase;
            self.status.revision = self.status.revision.saturating_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn packaged_search_resources_follow_the_physical_executable_file() {
        // A disposable LocalAppData directory also exercises MSIX file redirection
        // when this test is launched from a packaged desktop application.
        let base = std::env::var_os("LOCALAPPDATA").unwrap();
        let temp = tempfile::Builder::new()
            .prefix("context-relay-search-location-test-")
            .tempdir_in(base)
            .unwrap();
        let executable = temp.path().join("fixture.exe");
        std::fs::write(&executable, b"location fixture; never executed").unwrap();
        let physical_file = std::fs::canonicalize(&executable).unwrap();
        let expected = physical_file.parent().unwrap().join("search");
        assert_eq!(resources_beside_executable(&executable).unwrap(), expected);
        assert!(resources_beside_executable(&temp.path().join("missing.exe")).is_err());
    }

    #[test]
    fn failure_pauses_automatic_work_and_retry_preserves_progress() {
        let mut job = SearchIndexJob::new(true);
        job.finish(Ok(SemanticIndexBatch {
            indexed: 1,
            processed: 1,
            remaining: 2,
        }));
        let published = job.status.revision;
        job.finish(Err(VaultError::Validation("fixture error".into())));
        assert_eq!(job.status.phase, SearchIndexPhase::Failed);
        job.wake();
        assert!(!job.pending());
        job.retry();
        assert!(job.pending());
        assert!(job.status.revision > published);
        let retry = job.status;
        job.retry();
        assert_eq!(job.status, retry);
        job.finish(Ok(SemanticIndexBatch {
            indexed: 1,
            processed: 1,
            remaining: 0,
        }));
        assert_eq!(job.status.phase, SearchIndexPhase::Ready);
        assert!(!job.pending());
    }

    #[test]
    fn empty_rechecks_do_not_flicker_or_advance_the_search_revision() {
        let mut job = SearchIndexJob::new(true);
        job.finish(Ok(SemanticIndexBatch {
            indexed: 0,
            processed: 0,
            remaining: 0,
        }));
        let ready = job.status;
        job.wake();
        assert_eq!(job.status, ready);
        job.finish(Ok(SemanticIndexBatch {
            indexed: 0,
            processed: 0,
            remaining: 0,
        }));
        assert_eq!(job.status, ready);
        let mut disabled = SearchIndexJob::new(false);
        disabled.wake();
        disabled.retry();
        assert!(!disabled.pending());
        assert_eq!(disabled.status.phase, SearchIndexPhase::Disabled);
    }
}
