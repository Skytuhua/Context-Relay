use context_relay_core::native_memory::{
    DebounceState, NativeMemoryChangeKind, NativeMemoryDocumentKind, NativeMemoryError,
    NativeMemoryLedger, NativeMemoryLimits, NativeMemorySource, NativeMemorySourceId,
    ReconcileDecision, StableObservation, acknowledge, extract_managed_markdown, invalidate,
    observe, reconcile,
};
use context_relay_protocol::{
    HarnessId, NativePlatform, ProjectId, ScopeRef, Sha256Digest, WireNativeValue,
};
use sha2::{Digest as _, Sha256};
use std::str::FromStr;

fn source(byte: u8) -> NativeMemorySourceId {
    NativeMemorySourceId(Sha256Digest([byte; 32]))
}

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest([byte; 32])
}

#[test]
fn debounce_waits_for_the_full_750_millisecond_window() {
    let mut state = DebounceState::default();

    assert_eq!(observe(&mut state, source(1), Some(digest(1)), 0), None);
    assert_eq!(observe(&mut state, source(1), Some(digest(1)), 749), None);
    assert_eq!(
        observe(&mut state, source(1), Some(digest(1)), 750),
        Some(StableObservation {
            source_id: source(1),
            digest: Some(digest(1)),
            stable_since_ms: 0,
        })
    );
}

#[test]
fn debounce_digest_change_restarts_the_window() {
    let mut state = DebounceState::default();

    assert_eq!(observe(&mut state, source(1), Some(digest(1)), 0), None);
    assert_eq!(observe(&mut state, source(1), Some(digest(2)), 500), None);
    assert_eq!(observe(&mut state, source(1), Some(digest(2)), 1_249), None);
    assert_eq!(
        observe(&mut state, source(1), Some(digest(2)), 1_250),
        Some(StableObservation {
            source_id: source(1),
            digest: Some(digest(2)),
            stable_since_ms: 500,
        })
    );
}

#[test]
fn debounce_tracks_sources_independently() {
    let mut state = DebounceState::default();

    assert_eq!(observe(&mut state, source(1), Some(digest(1)), 0), None);
    assert_eq!(observe(&mut state, source(2), Some(digest(2)), 400), None);
    assert!(observe(&mut state, source(1), Some(digest(1)), 750).is_some());
    assert_eq!(observe(&mut state, source(2), Some(digest(2)), 750), None);
    assert!(observe(&mut state, source(2), Some(digest(2)), 1_150).is_some());
}

#[test]
fn debounce_treats_absence_as_an_observation() {
    let mut state = DebounceState::default();

    assert_eq!(observe(&mut state, source(1), None, 20), None);
    assert_eq!(
        observe(&mut state, source(1), None, 770),
        Some(StableObservation {
            source_id: source(1),
            digest: None,
            stable_since_ms: 20,
        })
    );
}

#[test]
fn debounce_resets_safely_when_monotonic_time_regresses() {
    let mut state = DebounceState::default();

    assert_eq!(observe(&mut state, source(1), Some(digest(1)), 1_000), None);
    assert_eq!(observe(&mut state, source(1), Some(digest(1)), 900), None);
    assert_eq!(observe(&mut state, source(1), Some(digest(1)), 1_649), None);
    assert_eq!(
        observe(&mut state, source(1), Some(digest(1)), 1_650),
        Some(StableObservation {
            source_id: source(1),
            digest: Some(digest(1)),
            stable_since_ms: 900,
        })
    );
}

#[test]
fn debounce_retries_ready_observations_until_acknowledged_then_evicts_them() {
    let mut state = DebounceState::default();

    assert_eq!(observe(&mut state, source(1), Some(digest(1)), 0), None);
    let ready = observe(&mut state, source(1), Some(digest(1)), 750).unwrap();
    assert_eq!(
        observe(&mut state, source(1), Some(digest(1)), 800),
        Some(ready)
    );

    assert!(acknowledge(&mut state, ready));
    assert!(!acknowledge(&mut state, ready));
    assert!(state.is_empty());
    assert_eq!(observe(&mut state, source(1), Some(digest(1)), 801), None);
}

#[test]
fn debounce_invalid_observation_restarts_the_stability_window() {
    let mut state = DebounceState::default();

    assert_eq!(observe(&mut state, source(1), Some(digest(1)), 0), None);
    assert!(invalidate(&mut state, source(1)));
    assert_eq!(observe(&mut state, source(1), Some(digest(1)), 1_000), None);
    assert_eq!(observe(&mut state, source(1), Some(digest(1)), 1_749), None);
    assert_eq!(
        observe(&mut state, source(1), Some(digest(1)), 1_750),
        Some(StableObservation {
            source_id: source(1),
            digest: Some(digest(1)),
            stable_since_ms: 1_000,
        })
    );
}

const START: &str = "<!-- context-relay:start -->";
const END: &str = "<!-- context-relay:end -->";

#[test]
fn markdown_without_a_fence_is_preserved_byte_for_byte() {
    let bytes = b"# Native memory\nkeep me\n";
    let extracted = extract_managed_markdown(bytes).unwrap();

    assert_eq!(extracted.managed_body, None);
    assert_eq!(extracted.unmanaged_body, bytes);
}

#[test]
fn markdown_extracts_one_well_formed_fence() {
    let bytes = format!("{START}\nmanaged\n{END}\n");
    let extracted = extract_managed_markdown(bytes.as_bytes()).unwrap();

    assert_eq!(
        extracted.managed_body.as_deref(),
        Some(b"managed\n".as_slice())
    );
    assert!(extracted.unmanaged_body.is_empty());
}

#[test]
fn markdown_preserves_crlf_outside_and_inside_the_fence() {
    let bytes = format!("before\r\n{START}\r\nmanaged\r\n{END}\r\nafter\r\n");
    let extracted = extract_managed_markdown(bytes.as_bytes()).unwrap();

    assert_eq!(
        extracted.managed_body.as_deref(),
        Some(b"managed\r\n".as_slice())
    );
    assert_eq!(extracted.unmanaged_body, b"before\r\nafter\r\n");
}

#[test]
fn markdown_preserves_exact_unmanaged_bytes_before_and_after_the_fence() {
    let bytes = format!("before without trimming\n{START}\nowned\n{END}\n\nafter  \n");
    let extracted = extract_managed_markdown(bytes.as_bytes()).unwrap();

    assert_eq!(
        extracted.unmanaged_body,
        b"before without trimming\n\nafter  \n"
    );
}

#[test]
fn markdown_normalizes_only_one_final_line_ending_for_the_unmanaged_digest() {
    let no_newline = extract_managed_markdown(b"notes").unwrap();
    let lf = extract_managed_markdown(b"notes\n").unwrap();
    let crlf = extract_managed_markdown(b"notes\r\n").unwrap();
    let blank_line = extract_managed_markdown(b"notes\n\n").unwrap();

    assert_eq!(no_newline.unmanaged_digest, lf.unmanaged_digest);
    assert_eq!(no_newline.unmanaged_digest, crlf.unmanaged_digest);
    assert_ne!(no_newline.unmanaged_digest, blank_line.unmanaged_digest);
}

#[test]
fn markdown_rejects_a_managed_body_containing_a_reserved_sentinel() {
    let bytes = format!("{START}\nbody mentions {START}\n{END}\n");

    assert_eq!(
        extract_managed_markdown(bytes.as_bytes()),
        Err(NativeMemoryError::MalformedManagedFence)
    );
}

#[test]
fn markdown_rejects_partial_duplicate_nested_and_inline_markers() {
    let partial = format!("{START}\nmissing end\n");
    let truncated_start = "<!-- context-relay:start --\nbody\n".to_owned();
    let truncated_end = "body\n<!-- context-relay:end --\n".to_owned();
    let duplicate = format!("{START}\none\n{END}\n{START}\ntwo\n{END}\n");
    let nested = format!("{START}\n{START}\nbody\n{END}\n{END}\n");
    let inline = format!("prefix {START}\nbody\n{END}\n");

    for bytes in [
        partial,
        truncated_start,
        truncated_end,
        duplicate,
        nested,
        inline,
    ] {
        assert_eq!(
            extract_managed_markdown(bytes.as_bytes()),
            Err(NativeMemoryError::MalformedManagedFence)
        );
    }
}

fn project_id() -> ProjectId {
    ProjectId::from_str("018f0e44-7d5f-7cc2-98c8-5c1c85d633a1").unwrap()
}

fn wire_path(bytes: &[u8], display: Option<&str>) -> WireNativeValue {
    WireNativeValue {
        platform: NativePlatform::Macos,
        bytes: bytes.to_vec(),
        display: display.map(str::to_owned),
    }
}

fn memory_source() -> NativeMemorySource {
    NativeMemorySource::new(
        HarnessId::ClaudeCode,
        "2.1.214",
        ScopeRef::Project {
            project_id: project_id(),
        },
        NativeMemoryDocumentKind::Agent,
        wire_path(
            b"/Users/alice/.claude/projects/demo/memory/MEMORY.md",
            Some("/Users/alice/.claude/projects/demo/memory/MEMORY.md"),
        ),
        NativeMemoryLimits {
            max_bytes: 1_048_576,
            max_characters: 1_048_576,
        },
        true,
    )
    .unwrap()
}

fn canonical_source_digest(source: &NativeMemorySource) -> Sha256Digest {
    let mut hasher = Sha256::new();
    for field in [
        b"context-relay.native-memory-source.v1".as_slice(),
        b"claude_code",
        b"2.1.214",
        b"project",
        project_id().as_bytes(),
        b"agent",
        b"macos",
        source.path.bytes.as_slice(),
    ] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    Sha256Digest(hasher.finalize().into())
}

#[test]
fn reconcile_source_identity_uses_the_versioned_canonical_tuple() {
    let source = memory_source();
    assert_eq!(
        source.id,
        NativeMemorySourceId(canonical_source_digest(&source))
    );

    let same_path_new_display = NativeMemorySource::new(
        HarnessId::ClaudeCode,
        "2.1.214",
        source.scope.clone(),
        NativeMemoryDocumentKind::Agent,
        wire_path(
            source.path.bytes.as_slice(),
            Some("a presentation-only value"),
        ),
        NativeMemoryLimits {
            max_bytes: 4_096,
            max_characters: 4_096,
        },
        false,
    )
    .unwrap();
    assert_eq!(source.id, same_path_new_display.id);

    let different_path = NativeMemorySource::new(
        HarnessId::ClaudeCode,
        "2.1.214",
        source.scope.clone(),
        NativeMemoryDocumentKind::Agent,
        wire_path(b"/different/MEMORY.md", None),
        source.limits,
        true,
    )
    .unwrap();
    assert_ne!(source.id, different_path.id);
}

#[test]
fn reconcile_source_identity_rejects_invalid_version_path_and_limits_before_hashing() {
    let valid = memory_source();
    let build = |version: &str, path: WireNativeValue, limits: NativeMemoryLimits| {
        NativeMemorySource::new(
            HarnessId::ClaudeCode,
            version,
            valid.scope.clone(),
            NativeMemoryDocumentKind::Agent,
            path,
            limits,
            true,
        )
    };

    assert_eq!(
        build("", valid.path.clone(), valid.limits),
        Err(NativeMemoryError::InvalidSource("adapter_version"))
    );
    assert_eq!(
        build("2.1.214", wire_path(b"", None), valid.limits),
        Err(NativeMemoryError::InvalidSource("path"))
    );
    assert_eq!(
        build(
            "2.1.214",
            valid.path.clone(),
            NativeMemoryLimits {
                max_bytes: 0,
                max_characters: 1,
            },
        ),
        Err(NativeMemoryError::InvalidSource("limits"))
    );
}

#[test]
fn reconcile_classifies_the_last_applied_full_digest_as_a_self_export() {
    let source = memory_source();
    let bytes = format!("native\n{START}\nowned\n{END}\n");
    let full_digest = extract_managed_markdown(bytes.as_bytes())
        .unwrap()
        .full_digest;
    let mut ledger = NativeMemoryLedger::new(source.id);
    ledger.last_applied_digest = Some(full_digest);

    assert_eq!(
        reconcile(&source, &ledger, bytes.as_bytes()).unwrap(),
        ReconcileDecision::SelfExport { full_digest }
    );
}

#[test]
fn reconcile_classifies_an_imported_unmanaged_digest_as_already_imported() {
    let source = memory_source();
    let bytes = b"previously imported\n";
    let extracted = extract_managed_markdown(bytes).unwrap();
    let mut ledger = NativeMemoryLedger::new(source.id);
    ledger.last_imported_digest = Some(extracted.unmanaged_digest);

    assert_eq!(
        reconcile(&source, &ledger, bytes).unwrap(),
        ReconcileDecision::AlreadyImported {
            full_digest: extracted.full_digest,
            unmanaged_digest: extracted.unmanaged_digest,
        }
    );
}

#[test]
fn reconcile_classifies_empty_unmanaged_markdown_as_no_content() {
    let source = memory_source();
    let bytes = format!("{START}\nowned only\n{END}\n");
    let extracted = extract_managed_markdown(bytes.as_bytes()).unwrap();

    assert_eq!(
        reconcile(
            &source,
            &NativeMemoryLedger::new(source.id),
            bytes.as_bytes(),
        )
        .unwrap(),
        ReconcileDecision::NoContent {
            full_digest: extracted.full_digest,
            unmanaged_digest: extracted.unmanaged_digest,
        }
    );
}

#[test]
fn reconcile_returns_an_exact_initial_preview_without_managed_content() {
    let source = memory_source();
    let bytes = format!("native exact  \n{START}\nnever import this\n{END}\n");
    let extracted = extract_managed_markdown(bytes.as_bytes()).unwrap();

    assert_eq!(
        reconcile(
            &source,
            &NativeMemoryLedger::new(source.id),
            bytes.as_bytes(),
        )
        .unwrap(),
        ReconcileDecision::Pending {
            source_id: source.id,
            full_digest: extracted.full_digest,
            unmanaged_digest: extracted.unmanaged_digest,
            candidate_markdown: b"native exact  \n".to_vec(),
            change_kind: NativeMemoryChangeKind::InitialPreview,
        }
    );
}

#[test]
fn reconcile_classifies_a_later_edit_as_live_without_trimming_candidate_bytes() {
    let source = memory_source();
    let bytes = b"  live edit  \n";
    let extracted = extract_managed_markdown(bytes).unwrap();
    let mut ledger = NativeMemoryLedger::new(source.id);
    ledger.initial_preview_complete = true;

    assert_eq!(
        reconcile(&source, &ledger, bytes).unwrap(),
        ReconcileDecision::Pending {
            source_id: source.id,
            full_digest: extracted.full_digest,
            unmanaged_digest: extracted.unmanaged_digest,
            candidate_markdown: bytes.to_vec(),
            change_kind: NativeMemoryChangeKind::LiveEdit,
        }
    );
}

#[test]
fn reconcile_rejects_a_ledger_for_a_different_source() {
    let source = memory_source();

    assert_eq!(
        reconcile(
            &source,
            &NativeMemoryLedger::new(NativeMemorySourceId(digest(9))),
            b"content",
        ),
        Err(NativeMemoryError::InvalidSource("ledger.source_id"))
    );
}
