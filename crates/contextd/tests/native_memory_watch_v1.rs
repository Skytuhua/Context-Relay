use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use context_relay_contextd::test_support::{
    TestDaemonConfig, TestRecordingBridgeInstallEngine, TestWorkerGate,
};
use context_relay_core::native_memory::{
    NativeMemoryDocumentKind, NativeMemoryLimits, NativeMemorySource,
};
use context_relay_local_ipc::{InstallationToken, RuntimeConfig};
use context_relay_protocol::{HarnessId, NativePlatform, ScopeRef, WireNativeValue};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

const TOKEN: [u8; 32] = [0x71; 32];

#[tokio::test]
async fn initial_preview_is_persisted_once_and_restart_does_not_duplicate_it() {
    let fixture = Fixture::new("initial");
    let path = fixture.root.join("memory.md");
    std::fs::write(&path, b"native preference\n").unwrap();
    let source = source(&path, 4_096);
    fixture
        .config
        .seed_native_memory_source(&source, None)
        .unwrap();

    let daemon = fixture.config.start().await.unwrap();
    wait_for_candidate_count(&fixture.config, 1).await;
    drop(daemon);
    let ledger = fixture
        .config
        .native_memory_ledger(&source.id)
        .unwrap()
        .unwrap();
    assert!(ledger.initial_preview_complete);
    assert!(ledger.last_observed_digest.is_some());

    let daemon = fixture.config.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    drop(daemon);
    assert_eq!(fixture.config.native_memory_candidates().unwrap().len(), 1);
}

#[tokio::test]
async fn initial_preview_completes_for_absent_empty_and_managed_only_sources() {
    let fixture = Fixture::new("empty");
    let absent = source(&fixture.root.join("absent.md"), 4_096);
    let empty_path = fixture.root.join("empty.md");
    std::fs::write(&empty_path, b"").unwrap();
    let empty = source(&empty_path, 4_096);
    let managed_path = fixture.root.join("managed.md");
    std::fs::write(
        &managed_path,
        b"<!-- context-relay:start -->\nowned\n<!-- context-relay:end -->\n",
    )
    .unwrap();
    let managed = source(&managed_path, 4_096);
    for descriptor in [&absent, &empty, &managed] {
        fixture
            .config
            .seed_native_memory_source(descriptor, None)
            .unwrap();
    }

    let daemon = fixture.config.start().await.unwrap();
    wait_for_preview(&fixture.config, [&absent, &empty, &managed]).await;
    drop(daemon);
    assert!(
        fixture
            .config
            .native_memory_candidates()
            .unwrap()
            .is_empty()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn unsupported_topology_never_advances_initial_preview() {
    let fixture = Fixture::new("topology");
    let target = fixture.root.join("target.md");
    std::fs::write(&target, b"must not follow\n").unwrap();
    let link = fixture.root.join("memory.md");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let source = source(&link, 4_096);
    fixture
        .config
        .seed_native_memory_source(&source, None)
        .unwrap();

    let daemon = fixture.config.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(550)).await;
    drop(daemon);
    let ledger = fixture
        .config
        .native_memory_ledger(&source.id)
        .unwrap()
        .unwrap();
    assert!(!ledger.initial_preview_complete);
    assert!(ledger.last_observed_digest.is_none());
    assert!(
        fixture
            .config
            .native_memory_candidates()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn live_edits_wait_for_one_stable_750ms_window_and_import_only_final_bytes() {
    let fixture = Fixture::new("debounce");
    let path = fixture.root.join("memory.md");
    std::fs::write(
        &path,
        b"<!-- context-relay:start -->\nowned\n<!-- context-relay:end -->\n",
    )
    .unwrap();
    let source = source(&path, 4_096);
    fixture
        .config
        .seed_native_memory_source(&source, None)
        .unwrap();
    let daemon = fixture.config.start().await.unwrap();
    wait_for_preview(&fixture.config, [&source]).await;

    std::fs::write(&path, b"first edit\n").unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    std::fs::write(&path, b"final stable edit\n").unwrap();
    tokio::time::sleep(Duration::from_millis(749)).await;
    assert!(
        fixture
            .config
            .native_memory_candidates()
            .unwrap()
            .is_empty()
    );
    wait_for_candidate_count(&fixture.config, 1).await;
    drop(daemon);

    let candidates = fixture.config.native_memory_candidates().unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(
        candidates[0].proposed_memory.body_markdown,
        "final stable edit\n"
    );
}

#[tokio::test]
async fn delete_recreate_and_atomic_rename_are_reconciled_without_raw_file_changes() {
    let fixture = Fixture::new("replacement");
    let path = fixture.root.join("memory.md");
    std::fs::write(&path, b"initial native bytes\n").unwrap();
    let source = source(&path, 4_096);
    fixture
        .config
        .seed_native_memory_source(&source, None)
        .unwrap();
    let daemon = fixture.config.start().await.unwrap();
    wait_for_candidate_count(&fixture.config, 1).await;

    std::fs::remove_file(&path).unwrap();
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    assert_eq!(fixture.config.native_memory_candidates().unwrap().len(), 1);
    std::fs::write(&path, b"recreated bytes\n").unwrap();
    wait_for_candidate_count(&fixture.config, 2).await;

    let replacement = fixture.root.join("replacement.tmp");
    std::fs::write(&replacement, b"atomic replacement\n").unwrap();
    std::fs::rename(&replacement, &path).unwrap();
    wait_for_candidate_count(&fixture.config, 3).await;
    drop(daemon);

    assert_eq!(std::fs::read(&path).unwrap(), b"atomic replacement\n");
    let bodies = fixture
        .config
        .native_memory_candidates()
        .unwrap()
        .into_iter()
        .map(|candidate| candidate.proposed_memory.body_markdown)
        .collect::<Vec<_>>();
    assert!(bodies.contains(&"recreated bytes\n".to_owned()));
    assert!(bodies.contains(&"atomic replacement\n".to_owned()));
}

#[tokio::test]
async fn bounded_worker_busy_observation_is_retained_until_worker_accepts_it() {
    let root = PathBuf::from("/private/tmp").join(format!(
        "crnm-busy-{}",
        &Uuid::now_v7().simple().to_string()[..12]
    ));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("memory.md");
    std::fs::write(&path, b"queued native bytes\n").unwrap();
    let source = source(&path, 4_096);
    let runtime = RuntimeConfig::for_test(
        format!("nm-{}", &Uuid::now_v7().simple().to_string()[..12]),
        Some(root.join("runtime")),
    )
    .unwrap();
    let gate = Arc::new(TestWorkerGate::new());
    let config = TestDaemonConfig::new(
        runtime,
        root.join("vault.db"),
        InstallationToken::from_bytes(TOKEN),
    )
    .with_bridge_install_engine(Arc::new(TestRecordingBridgeInstallEngine::default()))
    .with_worker_gate(gate.clone());
    config.seed_native_memory_source(&source, None).unwrap();

    let daemon = config.start().await.unwrap();
    gate.wait_until_entered().await;
    assert!(config.native_memory_candidates().unwrap().is_empty());
    gate.release();
    wait_for_candidate_count(&config, 1).await;
    drop(daemon);
}

#[cfg(unix)]
#[tokio::test]
async fn oversize_and_link_replacement_do_not_advance_a_live_ledger() {
    let fixture = Fixture::new("unsafe-live");
    let path = fixture.root.join("memory.md");
    std::fs::write(&path, b"managed seed\n").unwrap();
    let source = source(&path, 32);
    fixture
        .config
        .seed_native_memory_source(&source, None)
        .unwrap();
    let daemon = fixture.config.start().await.unwrap();
    wait_for_candidate_count(&fixture.config, 1).await;
    let baseline = fixture
        .config
        .native_memory_ledger(&source.id)
        .unwrap()
        .unwrap()
        .last_observed_digest;

    std::fs::write(&path, vec![b'x'; 33]).unwrap();
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    assert_eq!(
        fixture
            .config
            .native_memory_ledger(&source.id)
            .unwrap()
            .unwrap()
            .last_observed_digest,
        baseline
    );
    let target = fixture.root.join("target.md");
    std::fs::write(&target, b"link target\n").unwrap();
    std::fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    drop(daemon);
    assert_eq!(fixture.config.native_memory_candidates().unwrap().len(), 1);
    assert_eq!(
        fixture
            .config
            .native_memory_ledger(&source.id)
            .unwrap()
            .unwrap()
            .last_observed_digest,
        baseline
    );
}

#[tokio::test]
async fn applied_export_is_ignored_across_restart_then_only_unmanaged_bytes_are_proposed() {
    let fixture = Fixture::new("export-loop");
    let path = fixture.root.join("memory.md");
    let managed = b"<!-- context-relay:start -->\nowned memory\n<!-- context-relay:end -->\n";
    std::fs::write(&path, managed).unwrap();
    let source = source(&path, 4_096);
    let applied_digest = context_relay_protocol::Sha256Digest(Sha256::digest(managed).into());
    fixture
        .config
        .seed_native_memory_source(&source, Some(applied_digest))
        .unwrap();

    let daemon = fixture.config.start().await.unwrap();
    wait_for_preview(&fixture.config, [&source]).await;
    drop(daemon);
    assert!(
        fixture
            .config
            .native_memory_candidates()
            .unwrap()
            .is_empty()
    );

    let daemon = fixture.config.start().await.unwrap();
    let mut edited = managed.to_vec();
    edited.extend_from_slice(b"native-only paragraph\n");
    std::fs::write(&path, &edited).unwrap();
    wait_for_candidate_count(&fixture.config, 1).await;
    drop(daemon);

    let candidates = fixture.config.native_memory_candidates().unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(
        candidates[0].proposed_memory.body_markdown,
        "native-only paragraph\n"
    );
    assert_eq!(std::fs::read(&path).unwrap(), edited);
}

struct Fixture {
    root: PathBuf,
    config: TestDaemonConfig,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let root = PathBuf::from("/private/tmp").join(format!(
            "crnm-{label}-{}",
            &Uuid::now_v7().simple().to_string()[..12]
        ));
        std::fs::create_dir_all(&root).unwrap();
        let runtime = RuntimeConfig::for_test(
            format!("nm-{}", &Uuid::now_v7().simple().to_string()[..12]),
            Some(root.join("runtime")),
        )
        .unwrap();
        let config = TestDaemonConfig::new(
            runtime,
            root.join("vault.db"),
            InstallationToken::from_bytes(TOKEN),
        )
        .with_bridge_install_engine(Arc::new(TestRecordingBridgeInstallEngine::default()));
        Self { root, config }
    }
}

async fn wait_for_candidate_count(config: &TestDaemonConfig, count: usize) {
    for _ in 0..80 {
        if config.native_memory_candidates().unwrap().len() == count {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("native memory candidate count did not reach {count}");
}

async fn wait_for_preview<const N: usize>(
    config: &TestDaemonConfig,
    sources: [&NativeMemorySource; N],
) {
    for _ in 0..80 {
        if sources.iter().all(|source| {
            config
                .native_memory_ledger(&source.id)
                .unwrap()
                .is_some_and(|ledger| ledger.initial_preview_complete)
        }) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("native memory previews did not complete");
}

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
