use context_relay_protocol::{
    CandidateId, CandidateState, DeviceId, HarnessId, HybridLogicalClock, MemoryCandidate,
    MemoryId, MemoryKind, MemoryOrigin, MemoryRecord, OperationId, Provenance, Sha256Digest,
};
use sha2::{Digest as _, Sha256};
use std::str::FromStr;

use super::{
    NativeMemoryError, NativeMemoryLedger, NativeMemoryObservationKind, NativeMemorySource,
    NativeMemorySourceId, extract_managed_markdown,
};
use crate::native_memory::markdown::{MANAGED_END, MANAGED_START, digest};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeMemoryChangeKind {
    InitialPreview,
    LiveEdit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReconcileDecision {
    Pending {
        source_id: NativeMemorySourceId,
        full_digest: Sha256Digest,
        unmanaged_digest: Sha256Digest,
        candidate_markdown: Vec<u8>,
        change_kind: NativeMemoryChangeKind,
    },
    NoContent {
        full_digest: Sha256Digest,
        unmanaged_digest: Sha256Digest,
    },
    AlreadyImported {
        full_digest: Sha256Digest,
        unmanaged_digest: Sha256Digest,
    },
    SelfExport {
        full_digest: Sha256Digest,
    },
}

pub fn reconcile(
    source: &NativeMemorySource,
    ledger: &NativeMemoryLedger,
    bytes: &[u8],
) -> Result<ReconcileDecision, NativeMemoryError> {
    reconcile_classified(
        source,
        ledger,
        bytes,
        if ledger.initial_preview_complete {
            NativeMemoryObservationKind::LiveEdit
        } else {
            NativeMemoryObservationKind::InitialPreview
        },
    )
}

pub fn reconcile_classified(
    source: &NativeMemorySource,
    ledger: &NativeMemoryLedger,
    bytes: &[u8],
    observation_kind: NativeMemoryObservationKind,
) -> Result<ReconcileDecision, NativeMemoryError> {
    source.validate_compatible()?;
    if source.id != ledger.source_id {
        return Err(NativeMemoryError::InvalidSource("ledger.source_id"));
    }
    if bytes.len() > source.limits.max_bytes {
        return Err(NativeMemoryError::TooLarge);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| NativeMemoryError::InvalidUtf8)?;
    if text.chars().count() > source.limits.max_characters {
        return Err(NativeMemoryError::TooLarge);
    }

    let full_digest = digest(bytes);
    if ledger.last_applied_digest == Some(full_digest) {
        return Ok(ReconcileDecision::SelfExport { full_digest });
    }

    if !source.managed_fence && (text.contains(MANAGED_START) || text.contains(MANAGED_END)) {
        return Err(NativeMemoryError::MalformedManagedFence);
    }
    let extracted = extract_managed_markdown(bytes)?;
    if extracted.unmanaged_body.is_empty()
        || std::str::from_utf8(&extracted.unmanaged_body)
            .expect("validated source bytes remain UTF-8")
            .trim()
            .is_empty()
    {
        return Ok(ReconcileDecision::NoContent {
            full_digest,
            unmanaged_digest: extracted.unmanaged_digest,
        });
    }
    if ledger.last_imported_digest == Some(extracted.unmanaged_digest) {
        return Ok(ReconcileDecision::AlreadyImported {
            full_digest,
            unmanaged_digest: extracted.unmanaged_digest,
        });
    }

    Ok(ReconcileDecision::Pending {
        source_id: source.id,
        full_digest,
        unmanaged_digest: extracted.unmanaged_digest,
        candidate_markdown: extracted.unmanaged_body,
        change_kind: match observation_kind {
            NativeMemoryObservationKind::InitialPreview => NativeMemoryChangeKind::InitialPreview,
            NativeMemoryObservationKind::LiveEdit => NativeMemoryChangeKind::LiveEdit,
        },
    })
}

pub(crate) fn build_native_memory_candidate(
    source: &NativeMemorySource,
    unmanaged_digest: Sha256Digest,
    candidate_markdown: Vec<u8>,
    change_kind: NativeMemoryChangeKind,
    device_id: DeviceId,
) -> Result<MemoryCandidate, NativeMemoryError> {
    source.validate_compatible()?;
    let body_markdown =
        String::from_utf8(candidate_markdown).map_err(|_| NativeMemoryError::InvalidUtf8)?;
    let (candidate_id, memory_id, operation_id) =
        native_memory_identity(source.id, unmanaged_digest)?;
    let clock = operation_clock(operation_id, device_id);
    let candidate = MemoryCandidate {
        id: candidate_id,
        proposed_memory: MemoryRecord {
            id: memory_id,
            scope: source.scope.clone(),
            kind: MemoryKind::Note,
            title: native_memory_title(source),
            body_markdown,
            tags: native_memory_tags(source.harness),
            origin: MemoryOrigin::NativeImport,
            provenance: Provenance {
                origin_device: device_id,
                harness: Some(source.harness),
                source: None,
                created_hlc: clock,
            },
            revision: operation_id,
            created_hlc: clock,
            updated_hlc: clock,
            archived: false,
        },
        evidence_summary: native_memory_evidence(change_kind).to_owned(),
        source_harness: source.harness,
        state: CandidateState::Pending,
    };
    candidate
        .validate()
        .map_err(|_| NativeMemoryError::InvalidSource("candidate"))?;
    Ok(candidate)
}

pub(crate) fn native_memory_identity(
    source_id: NativeMemorySourceId,
    unmanaged_digest: Sha256Digest,
) -> Result<(CandidateId, MemoryId, OperationId), NativeMemoryError> {
    let mut hasher = Sha256::new();
    hasher.update(b"context-relay.native-memory-candidate.v1");
    hasher.update(source_id.0.0);
    hasher.update(unmanaged_digest.0);
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let value = format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    );
    Ok((
        CandidateId::from_str(&value).map_err(|_| NativeMemoryError::InvalidSource("identity"))?,
        MemoryId::from_str(&value).map_err(|_| NativeMemoryError::InvalidSource("identity"))?,
        OperationId::from_str(&value).map_err(|_| NativeMemoryError::InvalidSource("identity"))?,
    ))
}

pub(crate) fn native_memory_title(source: &NativeMemorySource) -> String {
    format!(
        "{} native {} memory",
        match source.harness {
            HarnessId::ClaudeCode => "Claude Code",
            HarnessId::Codex => "Codex",
            HarnessId::Hermes => "Hermes",
        },
        match source.document_kind {
            super::NativeMemoryDocumentKind::Agent => "agent",
            super::NativeMemoryDocumentKind::UserProfile => "user-profile",
            super::NativeMemoryDocumentKind::Summary => "summary",
            super::NativeMemoryDocumentKind::Topic => "topic",
        }
    )
}

pub(crate) fn native_memory_tags(harness: HarnessId) -> Vec<String> {
    vec![
        "native-import".to_owned(),
        match harness {
            HarnessId::ClaudeCode => "claude-code",
            HarnessId::Codex => "codex",
            HarnessId::Hermes => "hermes",
        }
        .to_owned(),
    ]
}

pub(crate) const fn native_memory_evidence(change_kind: NativeMemoryChangeKind) -> &'static str {
    match change_kind {
        NativeMemoryChangeKind::InitialPreview => "initial native-memory preview",
        NativeMemoryChangeKind::LiveEdit => "native-memory edit",
    }
}

fn operation_clock(operation_id: OperationId, device_id: DeviceId) -> HybridLogicalClock {
    let bytes = operation_id.as_bytes();
    let physical_ms = u64::from_be_bytes([
        0, 0, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
    ]);
    HybridLogicalClock::new(physical_ms, 0, device_id)
}
