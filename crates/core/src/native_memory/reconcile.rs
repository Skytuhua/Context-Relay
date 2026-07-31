use context_relay_protocol::Sha256Digest;

use super::{
    NativeMemoryError, NativeMemoryLedger, NativeMemorySource, NativeMemorySourceId,
    extract_managed_markdown,
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
    source.validate()?;
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
        change_kind: if ledger.initial_preview_complete {
            NativeMemoryChangeKind::LiveEdit
        } else {
            NativeMemoryChangeKind::InitialPreview
        },
    })
}
