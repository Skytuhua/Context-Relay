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
    StableObservation, ValidatedPersistedNativeMemorySource, acknowledge, invalidate, observe,
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

pub(crate) type NativeMemoryUpdateSender = watch::Sender<Vec<NativeMemoryLedger>>;

pub(crate) fn native_memory_update_channel() -> (
    NativeMemoryUpdateSender,
    watch::Receiver<Vec<NativeMemoryLedger>>,
) {
    watch::channel(Vec::new())
}

impl NativeMemorySupervisor {
    pub(crate) fn spawn(
        worker: WorkerClient,
        ledgers: Vec<NativeMemoryLedger>,
        updates: watch::Receiver<Vec<NativeMemoryLedger>>,
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
    source: ValidatedPersistedNativeMemorySource,
    initial_preview_complete: bool,
    baseline: Option<Option<Sha256Digest>>,
}

struct PendingReady {
    ready: ReadyNativeMemory,
    digest: Option<Sha256Digest>,
    stable: Option<StableObservation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SupervisorSchedule {
    Poll,
    Updated,
    UpdatesClosed,
}

async fn next_poll_or_update(
    interval: &mut tokio::time::Interval,
    updates: &mut watch::Receiver<Vec<NativeMemoryLedger>>,
    updates_open: bool,
) -> SupervisorSchedule {
    tokio::select! {
        biased;
        _ = interval.tick() => SupervisorSchedule::Poll,
        changed = updates.changed(), if updates_open => {
            if changed.is_ok() {
                SupervisorSchedule::Updated
            } else {
                SupervisorSchedule::UpdatesClosed
            }
        }
    }
}

async fn run_supervisor(
    worker: WorkerClient,
    ledgers: Vec<NativeMemoryLedger>,
    mut updates: watch::Receiver<Vec<NativeMemoryLedger>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut sources = ledgers
        .into_iter()
        .filter_map(watched_source_from_persisted_ledger)
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
            scheduled = next_poll_or_update(&mut interval, &mut updates, updates_open) => {
                match scheduled {
                    SupervisorSchedule::Poll => {
                        let now_ms = u64::try_from(started.elapsed().as_millis())
                            .unwrap_or(u64::MAX);
                        scan_sources(
                            &mut sources,
                            &mut debounce,
                            &mut pending,
                            &in_flight,
                            now_ms,
                        );
                        submit_pending(&worker, &pending, &mut in_flight, &mut completions);
                    }
                    SupervisorSchedule::Updated => {
                        let ledgers = updates.borrow_and_update().clone();
                        replace_registered_sources(
                            &mut sources,
                            &mut debounce,
                            &mut pending,
                            ledgers,
                        );
                    }
                    SupervisorSchedule::UpdatesClosed => updates_open = false,
                }
            }
        }
    }

    completions.abort_all();
    while completions.join_next().await.is_some() {}
}

fn replace_registered_sources(
    sources: &mut BTreeMap<NativeMemorySourceId, WatchedSource>,
    debounce: &mut DebounceState,
    pending: &mut BTreeMap<NativeMemorySourceId, PendingReady>,
    ledgers: Vec<NativeMemoryLedger>,
) {
    let replacement = ledgers
        .into_iter()
        .filter_map(watched_source_from_persisted_ledger)
        .collect::<BTreeMap<_, _>>();
    for removed in sources
        .keys()
        .filter(|source_id| !replacement.contains_key(source_id))
        .copied()
        .collect::<Vec<_>>()
    {
        pending.remove(&removed);
        invalidate(debounce, removed);
    }
    *sources = replacement;
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
        let Ok(observed) = safe_snapshot_persisted(&watched.source) else {
            if !pending.contains_key(source_id) {
                invalidate(debounce, *source_id);
            }
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
                        source: watched.source.as_source().clone(),
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
                        source: watched.source.as_source().clone(),
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

#[cfg(test)]
fn safe_snapshot(source: &NativeMemorySource) -> Result<ObservedSnapshot, SnapshotError> {
    source
        .validate()
        .map_err(|_| SnapshotError::UnsupportedTopology)?;
    snapshot_validated_source(source)
}

fn safe_snapshot_persisted(
    source: &ValidatedPersistedNativeMemorySource,
) -> Result<ObservedSnapshot, SnapshotError> {
    snapshot_validated_source(source.as_source())
}

fn snapshot_validated_source(
    source: &NativeMemorySource,
) -> Result<ObservedSnapshot, SnapshotError> {
    let path = decode_path(source)?;
    safe_snapshot_path(&path, source.limits.max_bytes)
}

fn watched_source_from_persisted_ledger(
    ledger: NativeMemoryLedger,
) -> Option<(NativeMemorySourceId, WatchedSource)> {
    let source = ledger.validated_persisted_source().ok()?;
    let source_id = source.as_source().id;
    Some((
        source_id,
        WatchedSource {
            source,
            initial_preview_complete: ledger.initial_preview_complete,
            baseline: ledger
                .initial_preview_complete
                .then_some(ledger.last_observed_digest),
        },
    ))
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

    if source.path.platform != NativePlatform::Windows
        || !source.path.bytes.len().is_multiple_of(2)
    {
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
    use crate::unit_test_support::wire_native_path;
    #[cfg(windows)]
    use context_relay_core::native_memory::{NativeMemoryCapabilities, NativeMemoryDisable};
    use context_relay_core::native_memory::{
        NativeMemoryDocumentKind, NativeMemoryLimits, NativeMemorySource,
    };
    use context_relay_protocol::{HarnessId, ScopeRef};

    fn source(path: &Path, max_bytes: usize) -> NativeMemorySource {
        NativeMemorySource::new(
            HarnessId::Codex,
            "0.144.1",
            ScopeRef::Global,
            NativeMemoryDocumentKind::Agent,
            wire_native_path(path),
            NativeMemoryLimits {
                max_bytes,
                max_characters: max_bytes,
            },
            true,
        )
        .unwrap()
    }

    #[cfg(windows)]
    fn windows_source(
        units: &[u16],
    ) -> Result<NativeMemorySource, context_relay_core::native_memory::NativeMemoryError> {
        use context_relay_protocol::WireNativeValue;

        NativeMemorySource::new(
            HarnessId::Codex,
            "0.144.1",
            ScopeRef::Global,
            NativeMemoryDocumentKind::Agent,
            WireNativeValue {
                platform: NativePlatform::Windows,
                bytes: units.iter().copied().flat_map(u16::to_le_bytes).collect(),
                display: None,
            },
            NativeMemoryLimits {
                max_bytes: 32,
                max_characters: 32,
            },
            true,
        )
    }

    #[cfg(windows)]
    #[test]
    fn windows_native_paths_preserve_supported_absolute_path_forms() {
        use std::os::windows::ffi::OsStrExt as _;

        for path in [
            r"C:\Users\Alice\memory.md",
            r"\\server\share\memory.md",
            r"\\?\C:\very-long\memory.md",
            r"C:\workspace\CON.md",
            r"C:\文档\🦀.md",
        ] {
            let expected = std::ffi::OsStr::new(path).encode_wide().collect::<Vec<_>>();
            let descriptor = windows_source(&expected).unwrap();
            let decoded = decode_path(&descriptor).unwrap();
            assert_eq!(
                decoded.as_os_str().encode_wide().collect::<Vec<_>>(),
                expected
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_native_path_rejects_odd_bytes_and_embedded_nul() {
        use context_relay_protocol::WireNativeValue;

        let odd = WireNativeValue {
            platform: NativePlatform::Windows,
            bytes: vec![b'C', 0, b':'],
            display: None,
        };
        assert!(odd.validate().is_err());
        let mut descriptor =
            windows_source(&r"C:\memory.md".encode_utf16().collect::<Vec<_>>()).unwrap();
        descriptor.path.bytes.pop();
        assert!(matches!(
            decode_path(&descriptor),
            Err(SnapshotError::UnsupportedTopology)
        ));

        let with_nul = r"C:\memory.md"
            .encode_utf16()
            .chain([0])
            .collect::<Vec<_>>();
        assert!(windows_source(&with_nul).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn windows_native_path_preserves_wtf16_isolated_surrogates() {
        use std::os::windows::ffi::OsStrExt as _;

        let mut units = r"C:\workspace\".encode_utf16().collect::<Vec<_>>();
        units.extend([0xd800, b'.' as u16, b'm' as u16, b'd' as u16]);
        let descriptor = windows_source(&units).unwrap();
        let decoded = decode_path(&descriptor).unwrap();

        assert_eq!(decoded.as_os_str().encode_wide().collect::<Vec<_>>(), units);
    }

    #[cfg(windows)]
    #[test]
    fn windows_wtf16_source_reaches_the_native_snapshot_boundary() {
        use std::{
            ffi::OsString,
            os::windows::ffi::{OsStrExt as _, OsStringExt as _},
        };

        let root = tempfile::tempdir().unwrap();
        let canonical_root = std::fs::canonicalize(root.path()).unwrap();
        let mut name = "memory-".encode_utf16().collect::<Vec<_>>();
        name.extend([0xd800, b'.' as u16, b'm' as u16, b'd' as u16]);
        let path = canonical_root.join(OsString::from_wide(&name));
        std::fs::write(&path, b"remember me").unwrap();
        let mut descriptor =
            windows_source(&path.as_os_str().encode_wide().collect::<Vec<_>>()).unwrap();
        descriptor.path.display = Some(r"C:\sessions\history.sqlite".to_owned());
        NativeMemoryCapabilities {
            disable: NativeMemoryDisable::WatchOnly,
            sources: vec![descriptor.clone()],
        }
        .validate()
        .unwrap();

        let decoded = decode_path(&descriptor).unwrap();
        assert_eq!(decoded, path);
        assert!(matches!(
            safe_snapshot(&descriptor).unwrap().snapshot,
            NativeMemorySnapshot::Regular(bytes) if bytes == b"remember me"
        ));
    }

    #[cfg(any(target_os = "macos", windows))]
    fn watched_sources(
        source: NativeMemorySource,
    ) -> BTreeMap<NativeMemorySourceId, WatchedSource> {
        let mut ledger = NativeMemoryLedger::for_source(source);
        ledger.initial_preview_complete = true;
        BTreeMap::from([watched_source_from_persisted_ledger(ledger).unwrap()])
    }

    #[cfg(any(target_os = "macos", windows))]
    #[test]
    fn unsafe_snapshot_restarts_an_unready_debounce_window() {
        let root = tempfile::tempdir().unwrap();
        let canonical_root = std::fs::canonicalize(root.path()).unwrap();
        let path = canonical_root.join("memory.md");
        std::fs::write(&path, b"remember me").unwrap();
        let descriptor = source(&path, 32);
        let source_id = descriptor.id;
        let mut sources = watched_sources(descriptor);
        let mut debounce = DebounceState::default();
        let mut pending = BTreeMap::new();
        let in_flight = BTreeSet::new();

        scan_sources(&mut sources, &mut debounce, &mut pending, &in_flight, 0);
        std::fs::write(&path, vec![0_u8; 33]).unwrap();
        scan_sources(&mut sources, &mut debounce, &mut pending, &in_flight, 1_000);
        std::fs::write(&path, b"remember me").unwrap();
        scan_sources(&mut sources, &mut debounce, &mut pending, &in_flight, 1_100);
        assert!(!pending.contains_key(&source_id));
        scan_sources(&mut sources, &mut debounce, &mut pending, &in_flight, 1_849);
        assert!(!pending.contains_key(&source_id));
        scan_sources(&mut sources, &mut debounce, &mut pending, &in_flight, 1_850);
        assert!(pending.contains_key(&source_id));
    }

    #[cfg(any(target_os = "macos", windows))]
    #[test]
    fn unsafe_snapshot_preserves_an_already_ready_observation() {
        let root = tempfile::tempdir().unwrap();
        let canonical_root = std::fs::canonicalize(root.path()).unwrap();
        let path = canonical_root.join("memory.md");
        std::fs::write(&path, b"remember me").unwrap();
        let descriptor = source(&path, 32);
        let source_id = descriptor.id;
        let mut sources = watched_sources(descriptor);
        let mut debounce = DebounceState::default();
        let mut pending = BTreeMap::new();
        let in_flight = BTreeSet::new();

        scan_sources(&mut sources, &mut debounce, &mut pending, &in_flight, 0);
        scan_sources(&mut sources, &mut debounce, &mut pending, &in_flight, 750);
        assert!(pending.contains_key(&source_id));

        std::fs::write(&path, vec![0_u8; 33]).unwrap();
        scan_sources(&mut sources, &mut debounce, &mut pending, &in_flight, 1_500);
        assert!(pending.contains_key(&source_id));
    }

    #[tokio::test]
    async fn descriptor_refresh_burst_coalesces_to_the_latest_ledger_set() {
        let root = tempfile::tempdir().unwrap();
        let descriptor = source(&root.path().join("memory.md"), 32);
        let (updates, mut receiver) = native_memory_update_channel();
        for byte in 1..=64 {
            let mut ledger = NativeMemoryLedger::for_source(descriptor.clone());
            ledger.last_applied_digest = Some(Sha256Digest([byte; 32]));
            updates.send_replace(vec![ledger]);
        }

        receiver.changed().await.unwrap();
        let latest = receiver.borrow_and_update().clone();
        assert_eq!(latest.len(), 1);
        assert_eq!(latest[0].last_applied_digest, Some(Sha256Digest([64; 32])));
        assert!(!receiver.has_changed().unwrap());
    }

    #[test]
    fn descriptor_refresh_replaces_the_set_and_discards_removed_pending_work() {
        let root = tempfile::tempdir().unwrap();
        let removed = source(&root.path().join("removed.md"), 32);
        let retained = source(&root.path().join("retained.md"), 32);
        let removed_id = removed.id;
        let retained_id = retained.id;
        let mut sources = watched_sources(removed.clone());
        let mut debounce = DebounceState::default();
        let mut pending = BTreeMap::from([(
            removed_id,
            PendingReady {
                ready: ReadyNativeMemory {
                    source: removed,
                    snapshot: NativeMemorySnapshot::Absent,
                    kind: NativeMemoryObservationKind::LiveEdit,
                },
                digest: None,
                stable: None,
            },
        )]);

        replace_registered_sources(
            &mut sources,
            &mut debounce,
            &mut pending,
            vec![NativeMemoryLedger::for_source(retained)],
        );

        assert!(!sources.contains_key(&removed_id));
        assert!(sources.contains_key(&retained_id));
        assert!(!pending.contains_key(&removed_id));
    }

    #[tokio::test(start_paused = true)]
    async fn continuous_ready_refreshes_do_not_starve_scheduler_polls() {
        let root = tempfile::tempdir().unwrap();
        let descriptor = source(&root.path().join("memory.md"), 32);
        let (updates, mut receiver) = native_memory_update_channel();
        let mut interval = tokio::time::interval(Duration::from_millis(NATIVE_MEMORY_POLL_MS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        assert_eq!(
            next_poll_or_update(&mut interval, &mut receiver, true).await,
            SupervisorSchedule::Poll
        );
        for byte in 1..=16 {
            let mut ledger = NativeMemoryLedger::for_source(descriptor.clone());
            ledger.last_applied_digest = Some(Sha256Digest([byte; 32]));
            updates.send_replace(vec![ledger]);
            tokio::time::advance(Duration::from_millis(NATIVE_MEMORY_POLL_MS)).await;

            assert_eq!(
                next_poll_or_update(&mut interval, &mut receiver, true).await,
                SupervisorSchedule::Poll,
                "refresh {byte} suppressed a due poll"
            );
            assert_eq!(
                next_poll_or_update(&mut interval, &mut receiver, true).await,
                SupervisorSchedule::Updated,
                "refresh {byte} was not activated after the poll"
            );
            assert_eq!(
                receiver.borrow_and_update()[0].last_applied_digest,
                Some(Sha256Digest([byte; 32]))
            );
        }
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
