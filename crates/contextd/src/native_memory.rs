use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    path::{Path, PathBuf},
    sync::Arc,
    thread::JoinHandle,
    time::{Duration, Instant},
};

use context_relay_core::native_memory::{
    DebounceState, NATIVE_MEMORY_POLL_MS, NativeMemoryLedger, NativeMemoryObservationKind,
    NativeMemorySnapshot, NativeMemorySource, NativeMemorySourceId, ReadyNativeMemory,
    StableObservation, acknowledge, observe,
};
#[cfg(any(target_os = "macos", windows))]
use context_relay_native_runner::OsNativeFileSystem;
use context_relay_protocol::{LocalResult, NativePlatform, Sha256Digest};
use sha2::{Digest as _, Sha256};
use tokio::{sync::watch, task::JoinSet};

use crate::{VaultCommand, WorkAdmission, WorkerClient};

pub(crate) trait LifecycleProbe: Send + Sync {
    fn started(&self) {}
    fn stopped(&self) {}
}

#[derive(Default)]
pub(crate) struct NoopLifecycleProbe;

impl LifecycleProbe for NoopLifecycleProbe {}

pub(crate) struct NativeMemorySupervisor {
    shutdown: watch::Sender<bool>,
    thread: Option<JoinHandle<()>>,
}

impl NativeMemorySupervisor {
    pub(crate) fn spawn(
        worker: WorkerClient,
        ledgers: Vec<NativeMemoryLedger>,
        updates: tokio::sync::mpsc::UnboundedReceiver<Vec<NativeMemoryLedger>>,
        probe: Arc<dyn LifecycleProbe>,
    ) -> io::Result<Self> {
        let (shutdown, shutdown_receiver) = watch::channel(false);
        let (ready_sender, ready_receiver) = std::sync::mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("context-relay-native-memory".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_time()
                    .build();
                let Ok(runtime) = runtime else {
                    let _ = ready_sender.send(Err(io::Error::other(
                        "native memory runtime could not start",
                    )));
                    return;
                };
                probe.started();
                let _guard = StopProbe(probe);
                if ready_sender.send(Ok(())).is_err() {
                    return;
                }
                // The schedule is a Tokio task. Its small dedicated runtime
                // thread gives synchronous Daemon::drop a real join boundary,
                // including on a current-thread caller runtime.
                runtime.block_on(async move {
                    let _ =
                        tokio::spawn(run_supervisor(worker, ledgers, updates, shutdown_receiver))
                            .await;
                });
            })?;
        match ready_receiver.recv() {
            Ok(Ok(())) => Ok(Self {
                shutdown,
                thread: Some(thread),
            }),
            Ok(Err(error)) => {
                let _ = thread.join();
                Err(error)
            }
            Err(_) => {
                let _ = thread.join();
                Err(io::Error::other(
                    "native memory runtime exited during startup",
                ))
            }
        }
    }

    pub(crate) fn shutdown_and_join(&mut self) {
        self.shutdown.send_replace(true);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }

    pub(crate) async fn shutdown_and_join_async(&mut self) {
        self.shutdown.send_replace(true);
        if let Some(thread) = self.thread.take() {
            let _ = tokio::task::spawn_blocking(move || thread.join()).await;
        }
    }
}

impl Drop for NativeMemorySupervisor {
    fn drop(&mut self) {
        self.shutdown_and_join();
    }
}

struct StopProbe(Arc<dyn LifecycleProbe>);

impl Drop for StopProbe {
    fn drop(&mut self) {
        self.0.stopped();
    }
}

#[derive(Clone, Copy)]
struct SupervisorAdmission;

impl WorkAdmission for SupervisorAdmission {
    fn begin(&self) -> bool {
        true
    }
}

struct WatchedSource {
    source: NativeMemorySource,
    initial_preview_complete: bool,
    baseline: Option<Option<Sha256Digest>>,
}

struct PendingReady {
    ready: ReadyNativeMemory,
    digest: Option<Sha256Digest>,
    stable: Option<StableObservation>,
}

async fn run_supervisor(
    worker: WorkerClient,
    ledgers: Vec<NativeMemoryLedger>,
    mut updates: tokio::sync::mpsc::UnboundedReceiver<Vec<NativeMemoryLedger>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut sources = ledgers
        .into_iter()
        .filter_map(|ledger| {
            let source = ledger.source?;
            Some((
                source.id,
                WatchedSource {
                    source,
                    initial_preview_complete: ledger.initial_preview_complete,
                    baseline: ledger
                        .initial_preview_complete
                        .then_some(ledger.last_observed_digest),
                },
            ))
        })
        .collect::<BTreeMap<_, _>>();
    let mut debounce = DebounceState::default();
    let mut pending = BTreeMap::<NativeMemorySourceId, PendingReady>::new();
    let mut in_flight = BTreeSet::new();
    let mut completions = JoinSet::new();
    let started = Instant::now();
    let mut interval = tokio::time::interval(Duration::from_millis(NATIVE_MEMORY_POLL_MS));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut updates_open = true;

    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            updated = updates.recv(), if updates_open => {
                match updated {
                    Some(ledgers) => merge_registered_sources(&mut sources, ledgers),
                    None => updates_open = false,
                }
            }
            completed = completions.join_next(), if !completions.is_empty() => {
                if let Some(Ok((source_id, succeeded))) = completed {
                    in_flight.remove(&source_id);
                    if succeeded && let Some(ready) = pending.remove(&source_id) {
                        if let Some(stable) = ready.stable {
                            acknowledge(&mut debounce, stable);
                        }
                        if let Some(source) = sources.get_mut(&source_id) {
                            source.initial_preview_complete = true;
                            source.baseline = Some(ready.digest);
                        }
                    }
                }
            }
            _ = interval.tick() => {
                let now_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                scan_sources(&mut sources, &mut debounce, &mut pending, &in_flight, now_ms);
                submit_pending(&worker, &pending, &mut in_flight, &mut completions);
            }
        }
    }

    completions.abort_all();
    while completions.join_next().await.is_some() {}
}

fn merge_registered_sources(
    sources: &mut BTreeMap<NativeMemorySourceId, WatchedSource>,
    ledgers: Vec<NativeMemoryLedger>,
) {
    for ledger in ledgers {
        let Some(source) = ledger.source else {
            continue;
        };
        sources.entry(source.id).or_insert_with(|| WatchedSource {
            source,
            initial_preview_complete: ledger.initial_preview_complete,
            baseline: ledger
                .initial_preview_complete
                .then_some(ledger.last_observed_digest),
        });
    }
}

fn scan_sources(
    sources: &mut BTreeMap<NativeMemorySourceId, WatchedSource>,
    debounce: &mut DebounceState,
    pending: &mut BTreeMap<NativeMemorySourceId, PendingReady>,
    in_flight: &BTreeSet<NativeMemorySourceId>,
    now_ms: u64,
) {
    for (source_id, watched) in sources {
        if in_flight.contains(source_id) {
            continue;
        }
        let Ok(observed) = safe_snapshot(&watched.source) else {
            continue;
        };
        if pending
            .get(source_id)
            .is_some_and(|ready| ready.digest != observed.digest)
        {
            pending.remove(source_id);
        }
        if !watched.initial_preview_complete {
            pending.insert(
                *source_id,
                PendingReady {
                    ready: ReadyNativeMemory {
                        source: watched.source.clone(),
                        snapshot: observed.snapshot,
                        kind: NativeMemoryObservationKind::InitialPreview,
                    },
                    digest: observed.digest,
                    stable: None,
                },
            );
            continue;
        }
        if watched.baseline == Some(observed.digest) {
            continue;
        }
        if let Some(stable) = observe(debounce, *source_id, observed.digest, now_ms) {
            pending.insert(
                *source_id,
                PendingReady {
                    ready: ReadyNativeMemory {
                        source: watched.source.clone(),
                        snapshot: observed.snapshot,
                        kind: NativeMemoryObservationKind::LiveEdit,
                    },
                    digest: observed.digest,
                    stable: Some(stable),
                },
            );
        }
    }
}

fn submit_pending(
    worker: &WorkerClient,
    pending: &BTreeMap<NativeMemorySourceId, PendingReady>,
    in_flight: &mut BTreeSet<NativeMemorySourceId>,
    completions: &mut JoinSet<(NativeMemorySourceId, bool)>,
) {
    for (source_id, pending) in pending {
        if in_flight.contains(source_id) {
            continue;
        }
        let Ok(response) = worker.try_submit(
            VaultCommand::NativeMemoryObservation(pending.ready.clone()),
            SupervisorAdmission,
        ) else {
            continue;
        };
        in_flight.insert(*source_id);
        let source_id = *source_id;
        completions.spawn(async move {
            let succeeded = matches!(response.await, Ok(Ok(LocalResult::Empty)));
            (source_id, succeeded)
        });
    }
}

struct ObservedSnapshot {
    snapshot: NativeMemorySnapshot,
    digest: Option<Sha256Digest>,
}

#[derive(Debug)]
enum SnapshotError {
    UnsupportedTopology,
    Io,
}

fn safe_snapshot(source: &NativeMemorySource) -> Result<ObservedSnapshot, SnapshotError> {
    source
        .validate()
        .map_err(|_| SnapshotError::UnsupportedTopology)?;
    let path = decode_path(source)?;
    safe_snapshot_path(&path, source.limits.max_bytes)
}

#[cfg(unix)]
fn decode_path(source: &NativeMemorySource) -> Result<PathBuf, SnapshotError> {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt as _};

    if source.path.platform != NativePlatform::Macos {
        return Err(SnapshotError::UnsupportedTopology);
    }
    let path = PathBuf::from(OsString::from_vec(source.path.bytes.clone()));
    if !path.is_absolute() {
        return Err(SnapshotError::UnsupportedTopology);
    }
    Ok(path)
}

#[cfg(windows)]
fn decode_path(source: &NativeMemorySource) -> Result<PathBuf, SnapshotError> {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt as _};

    if source.path.platform != NativePlatform::Windows || source.path.bytes.len() % 2 != 0 {
        return Err(SnapshotError::UnsupportedTopology);
    }
    let units = source
        .path
        .bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    let path = PathBuf::from(OsString::from_wide(&units));
    if !path.is_absolute() {
        return Err(SnapshotError::UnsupportedTopology);
    }
    Ok(path)
}

#[cfg(target_os = "macos")]
fn safe_snapshot_path(path: &Path, max_bytes: usize) -> Result<ObservedSnapshot, SnapshotError> {
    safe_snapshot_path_with_probe(path, max_bytes, |_| {})
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SnapshotStage {
    PreSnapshot,
}

#[cfg(target_os = "macos")]
fn safe_snapshot_path_with_probe(
    path: &Path,
    max_bytes: usize,
    mut probe: impl FnMut(SnapshotStage),
) -> Result<ObservedSnapshot, SnapshotError> {
    use std::os::unix::fs::MetadataExt as _;

    let before = match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Some(metadata),
        Ok(_) => return Err(SnapshotError::UnsupportedTopology),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(_) => return Err(SnapshotError::Io),
    };
    if before.as_ref().is_some_and(|metadata| {
        usize::try_from(metadata.len()).map_or(true, |length| length > max_bytes)
    }) {
        return Err(SnapshotError::UnsupportedTopology);
    }
    probe(SnapshotStage::PreSnapshot);
    let snapshot = OsNativeFileSystem::new()
        .snapshot(path)
        .map_err(|_| SnapshotError::UnsupportedTopology)?;
    match (before, snapshot.bytes(), snapshot.object_token()) {
        (None, None, _) => Ok(ObservedSnapshot {
            snapshot: NativeMemorySnapshot::Absent,
            digest: None,
        }),
        (Some(before), Some(bytes), Some(token)) => {
            let object = u64::from_be_bytes(
                token.object()[..8]
                    .try_into()
                    .expect("native object token has an eight-byte object prefix"),
            );
            if token.volume() != before.dev() || object != before.ino() || bytes.len() > max_bytes {
                return Err(SnapshotError::UnsupportedTopology);
            }
            let after =
                std::fs::symlink_metadata(path).map_err(|_| SnapshotError::UnsupportedTopology)?;
            if !after.file_type().is_file()
                || token.volume() != after.dev()
                || object != after.ino()
            {
                return Err(SnapshotError::UnsupportedTopology);
            }
            Ok(ObservedSnapshot {
                digest: Some(Sha256Digest(Sha256::digest(bytes).into())),
                snapshot: NativeMemorySnapshot::Regular(bytes.to_vec()),
            })
        }
        _ => Err(SnapshotError::UnsupportedTopology),
    }
}

#[cfg(windows)]
fn safe_snapshot_path(path: &Path, max_bytes: usize) -> Result<ObservedSnapshot, SnapshotError> {
    let before = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(ObservedSnapshot {
                snapshot: NativeMemorySnapshot::Absent,
                digest: None,
            });
        }
        Err(_) => return Err(SnapshotError::Io),
    };
    if !before.file_type().is_file()
        || usize::try_from(before.len()).map_or(true, |length| length > max_bytes)
    {
        return Err(SnapshotError::UnsupportedTopology);
    }
    let snapshot = OsNativeFileSystem::new()
        .snapshot(path)
        .map_err(|_| SnapshotError::UnsupportedTopology)?;
    match snapshot.bytes() {
        None => Ok(ObservedSnapshot {
            snapshot: NativeMemorySnapshot::Absent,
            digest: None,
        }),
        Some(bytes) if bytes.len() <= max_bytes => Ok(ObservedSnapshot {
            digest: Some(Sha256Digest(Sha256::digest(bytes).into())),
            snapshot: NativeMemorySnapshot::Regular(bytes.to_vec()),
        }),
        Some(_) => Err(SnapshotError::UnsupportedTopology),
    }
}

#[cfg(not(any(target_os = "macos", windows)))]
fn safe_snapshot_path(_path: &Path, _max_bytes: usize) -> Result<ObservedSnapshot, SnapshotError> {
    Err(SnapshotError::UnsupportedTopology)
}

#[cfg(test)]
mod tests {
    use super::*;
    use context_relay_core::native_memory::{
        NativeMemoryDocumentKind, NativeMemoryLimits, NativeMemorySource,
    };
    use context_relay_protocol::{HarnessId, ScopeRef, WireNativeValue};

    fn source(path: &Path, max_bytes: usize) -> NativeMemorySource {
        #[cfg(unix)]
        use std::os::unix::ffi::OsStrExt as _;
        NativeMemorySource::new(
            HarnessId::Codex,
            "0.144.1",
            ScopeRef::Global,
            NativeMemoryDocumentKind::Agent,
            WireNativeValue {
                platform: NativePlatform::Macos,
                #[cfg(unix)]
                bytes: path.as_os_str().as_bytes().to_vec(),
                #[cfg(windows)]
                bytes: path
                    .to_string_lossy()
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect(),
                display: Some(path.display().to_string()),
            },
            NativeMemoryLimits {
                max_bytes,
                max_characters: max_bytes,
            },
            true,
        )
        .unwrap()
    }

    #[cfg(any(target_os = "macos", windows))]
    #[test]
    fn snapshots_regular_absent_oversize_and_link_replacement() {
        let root = tempfile::tempdir().unwrap();
        let canonical_root = std::fs::canonicalize(root.path()).unwrap();
        let path = canonical_root.join("memory.md");
        std::fs::write(&path, b"remember me").unwrap();
        let descriptor = source(&path, 32);
        assert!(matches!(
            safe_snapshot(&descriptor).unwrap().snapshot,
            NativeMemorySnapshot::Regular(bytes) if bytes == b"remember me"
        ));
        std::fs::remove_file(&path).unwrap();
        assert!(matches!(
            safe_snapshot(&descriptor).unwrap().snapshot,
            NativeMemorySnapshot::Absent
        ));
        std::fs::write(&path, vec![0_u8; 33]).unwrap();
        assert!(matches!(
            safe_snapshot(&descriptor),
            Err(SnapshotError::UnsupportedTopology)
        ));
        #[cfg(unix)]
        {
            std::fs::remove_file(&path).unwrap();
            std::os::unix::fs::symlink(canonical_root.join("target"), &path).unwrap();
            assert!(matches!(
                safe_snapshot(&descriptor),
                Err(SnapshotError::UnsupportedTopology)
            ));
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn identity_change_during_snapshot_is_rejected_without_touching_replacement() {
        let root = tempfile::tempdir().unwrap();
        let canonical_root = std::fs::canonicalize(root.path()).unwrap();
        let path = canonical_root.join("memory.md");
        let replacement = canonical_root.join("replacement.md");
        std::fs::write(&path, b"old bytes").unwrap();
        std::fs::write(&replacement, b"replacement bytes").unwrap();
        let mut replaced = false;

        let result = safe_snapshot_path_with_probe(&path, 64, |stage| {
            if stage == SnapshotStage::PreSnapshot && !replaced {
                std::fs::rename(&replacement, &path).unwrap();
                replaced = true;
            }
        });

        assert!(matches!(result, Err(SnapshotError::UnsupportedTopology)));
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement bytes");
    }
}
