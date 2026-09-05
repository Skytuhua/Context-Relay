use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use context_relay_contextd::test_support::{
    TestDaemonConfig, TestRecordingBridgeInstallEngine, TestWorkerGate,
};
use context_relay_core::native_memory::{
    NativeMemoryDiagnosticClass, NativeMemoryDocumentKind, NativeMemoryLimits, NativeMemorySource,
    NativeMemorySourceId,
};
use context_relay_local_ipc::{InstallationToken, RuntimeConfig};
use context_relay_protocol::{HarnessId, NativePlatform, ScopeRef, WireNativeValue};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

const TOKEN: [u8; 32] = [0x71; 32];

#[tokio::test]
async fn persisted_v1_source_previews_and_observes_live_edits_after_upgrade_restart() {
    let fixture = Fixture::new("legacy-v1-upgrade");
    let path = fixture.root.join("memory.md");
    std::fs::write(&path, b"legacy initial preview\n").unwrap();
    let mut legacy = source(&path, 4_096);
    legacy.id = legacy_source_id(&legacy);
    assert!(legacy.validate().is_err());
    fixture
        .config
        .seed_native_memory_source(&legacy, None)
        .unwrap();

    let daemon = fixture.config.start().await.unwrap();
    wait_for_candidate_count(&fixture.config, 1).await;
    drop(daemon);
    let persisted = fixture
        .config
        .native_memory_ledger(&legacy.id)
        .unwrap()
        .unwrap();
    assert!(persisted.initial_preview_complete);
    assert_eq!(persisted.source, Some(legacy.clone()));
    assert_eq!(
        fixture.config.native_memory_candidates().unwrap()[0]
            .proposed_memory
            .body_markdown,
        "legacy initial preview\n"
    );

    let daemon = fixture.config.start().await.unwrap();
    std::fs::write(&path, b"legacy live edit after restart\n").unwrap();
    wait_for_candidate_count(&fixture.config, 2).await;
    drop(daemon);
    assert!(
        fixture
            .config
            .native_memory_candidates()
            .unwrap()
            .iter()
            .any(|candidate| candidate.proposed_memory.body_markdown
                == "legacy live edit after restart\n")
    );
}

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
    // Exact 749/750 ms boundaries are covered with a deterministic clock in the unit tests.
    // This integration test asserts the observable contract — intermediate bytes never become a
    // candidate and only the final stable bytes import — without racing a fixed wall-clock
    // instant, which scheduled FS-notification latency on loaded runners can shift.
    let deadline = std::time::Instant::now() + Duration::from_millis(1_500);
    while std::time::Instant::now() < deadline {
        for candidate in fixture.config.native_memory_candidates().unwrap() {
            assert_ne!(
                candidate.proposed_memory.body_markdown, "first edit\n",
                "intermediate edit was imported before the stability window closed"
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
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
    #[cfg(windows)]
    let base = std::env::temp_dir();
    #[cfg(not(windows))]
    let base = PathBuf::from("/private/tmp");
    let root = base.join(format!("crnm-busy-{}", uuid_v7_tail()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("memory.md");
    std::fs::write(&path, b"queued native bytes\n").unwrap();
    let source = source(&path, 4_096);
    let runtime =
        RuntimeConfig::for_test(format!("nm-{}", uuid_v7_tail()), Some(root.join("runtime")))
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

#[tokio::test]
async fn managed_owned_block_drift_is_reported_after_restart() {
    let fixture = Fixture::new("owned-drift");
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

    let daemon = fixture.config.start().await.unwrap();
    std::fs::write(
        &path,
        b"<!-- context-relay:start -->\nuser changed owned memory\n<!-- context-relay:end -->\n",
    )
    .unwrap();
    wait_for_diagnostic(&fixture.config, &source).await;
    drop(daemon);

    let ledger = fixture
        .config
        .native_memory_ledger(&source.id)
        .unwrap()
        .unwrap();
    assert_eq!(
        ledger.last_diagnostic.unwrap().error_class,
        NativeMemoryDiagnosticClass::ManagedContentModified
    );
    assert!(
        fixture
            .config
            .native_memory_candidates()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn rejected_text_records_only_redacted_digest_diagnostics_and_recovers_after_correction() {
    let fixture = Fixture::new("redacted-diagnostics");
    let invalid_path = fixture.root.join("invalid.md");
    let invalid_bytes = b"invalid-utf8-\xff-private";
    std::fs::write(&invalid_path, invalid_bytes).unwrap();
    let invalid = source(&invalid_path, 4_096);
    let sensitive_path = fixture.root.join("sensitive.md");
    let sensitive_bytes = b"api_key = must-never-enter-the-vault\n";
    std::fs::write(&sensitive_path, sensitive_bytes).unwrap();
    let sensitive = source(&sensitive_path, 4_096);
    for descriptor in [&invalid, &sensitive] {
        fixture
            .config
            .seed_native_memory_source(descriptor, None)
            .unwrap();
    }

    let daemon = fixture.config.start().await.unwrap();
    wait_for_diagnostic(&fixture.config, &invalid).await;
    wait_for_diagnostic(&fixture.config, &sensitive).await;
    assert!(
        fixture
            .config
            .native_memory_candidates()
            .unwrap()
            .is_empty()
    );

    let invalid_ledger = fixture
        .config
        .native_memory_ledger(&invalid.id)
        .unwrap()
        .unwrap();
    let sensitive_ledger = fixture
        .config
        .native_memory_ledger(&sensitive.id)
        .unwrap()
        .unwrap();
    assert_eq!(
        invalid_ledger.last_diagnostic.as_ref().unwrap().error_class,
        NativeMemoryDiagnosticClass::InvalidUtf8
    );
    assert_eq!(
        sensitive_ledger
            .last_diagnostic
            .as_ref()
            .unwrap()
            .error_class,
        NativeMemoryDiagnosticClass::SensitiveText
    );
    assert_eq!(
        invalid_ledger.last_diagnostic.as_ref().unwrap().digest,
        context_relay_protocol::Sha256Digest(Sha256::digest(invalid_bytes).into())
    );
    assert_eq!(
        sensitive_ledger.last_diagnostic.as_ref().unwrap().digest,
        context_relay_protocol::Sha256Digest(Sha256::digest(sensitive_bytes).into())
    );
    for (ledger, forbidden) in [
        (&invalid_ledger, "invalid-utf8"),
        (&sensitive_ledger, "must-never-enter-the-vault"),
    ] {
        let diagnostic = serde_json::to_value(ledger.last_diagnostic.as_ref().unwrap()).unwrap();
        assert_eq!(
            diagnostic
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            ["digest", "errorClass", "sourceId"]
        );
        assert!(!diagnostic.to_string().contains(forbidden));
    }

    std::fs::write(&invalid_path, b"corrected invalid source\n").unwrap();
    std::fs::write(&sensitive_path, b"corrected sensitive source\n").unwrap();
    wait_for_candidate_count(&fixture.config, 2).await;
    drop(daemon);
    for descriptor in [&invalid, &sensitive] {
        assert!(
            fixture
                .config
                .native_memory_ledger(&descriptor.id)
                .unwrap()
                .unwrap()
                .last_diagnostic
                .is_none()
        );
    }
}

struct Fixture {
    root: PathBuf,
    config: TestDaemonConfig,
}

impl Fixture {
    fn new(label: &str) -> Self {
        #[cfg(windows)]
        let base = std::env::temp_dir();
        #[cfg(not(windows))]
        let base = PathBuf::from("/private/tmp");
        let root = base.join(format!("crnm-{label}-{}", uuid_v7_tail()));
        std::fs::create_dir_all(&root).unwrap();
        let runtime =
            RuntimeConfig::for_test(format!("nm-{}", uuid_v7_tail()), Some(root.join("runtime")))
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

async fn wait_for_diagnostic(config: &TestDaemonConfig, source: &NativeMemorySource) {
    for _ in 0..80 {
        if config
            .native_memory_ledger(&source.id)
            .unwrap()
            .is_some_and(|ledger| ledger.last_diagnostic.is_some())
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("native memory diagnostic was not persisted");
}

fn source(path: &Path, max_bytes: usize) -> NativeMemorySource {
    #[cfg(unix)]
    use std::os::unix::ffi::OsStrExt as _;
    #[cfg(windows)]
    use std::os::windows::ffi::OsStrExt as _;
    NativeMemorySource::new(
        HarnessId::Codex,
        "0.144.1",
        ScopeRef::Global,
        NativeMemoryDocumentKind::Agent,
        WireNativeValue {
            #[cfg(unix)]
            platform: NativePlatform::Macos,
            #[cfg(windows)]
            platform: NativePlatform::Windows,
            #[cfg(unix)]
            bytes: path.as_os_str().as_bytes().to_vec(),
            #[cfg(windows)]
            bytes: path
                .as_os_str()
                .encode_wide()
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

fn legacy_source_id(source: &NativeMemorySource) -> NativeMemorySourceId {
    let platform = match source.path.platform {
        NativePlatform::Macos => b"macos".as_slice(),
        NativePlatform::Windows => b"windows".as_slice(),
    };
    let mut hasher = Sha256::new();
    for field in [
        b"context-relay.native-memory-source.v1".as_slice(),
        b"codex",
        source.adapter_version.as_bytes(),
        b"global",
        b"",
        b"agent",
        platform,
        source.path.bytes.as_slice(),
    ] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    NativeMemorySourceId(context_relay_protocol::Sha256Digest(
        hasher.finalize().into(),
    ))
}

// The random tail of a UUIDv7 carries per-call entropy; the leading
// characters encode only the millisecond timestamp, which collides across
// parallel tests. Runtime suffixes name per-user global singletons on
// Windows, so they need the tail.
fn uuid_v7_tail() -> String {
    let uuid = Uuid::now_v7().simple().to_string();
    uuid[uuid.len() - 12..].to_owned()
}
