use std::collections::BTreeMap;

use context_relay_protocol::Sha256Digest;

use super::{NATIVE_MEMORY_DEBOUNCE_MS, NativeMemorySourceId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StableObservation {
    pub source_id: NativeMemorySourceId,
    pub digest: Option<Sha256Digest>,
    pub stable_since_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingObservation {
    digest: Option<Sha256Digest>,
    stable_since_ms: u64,
}

#[derive(Debug, Default)]
pub struct DebounceState {
    pending: BTreeMap<NativeMemorySourceId, PendingObservation>,
}

impl DebounceState {
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

pub fn observe(
    state: &mut DebounceState,
    source_id: NativeMemorySourceId,
    digest: Option<Sha256Digest>,
    now_ms: u64,
) -> Option<StableObservation> {
    let pending = state
        .pending
        .entry(source_id)
        .or_insert(PendingObservation {
            digest,
            stable_since_ms: now_ms,
        });

    if pending.digest != digest || now_ms.checked_sub(pending.stable_since_ms).is_none() {
        *pending = PendingObservation {
            digest,
            stable_since_ms: now_ms,
        };
        return None;
    }

    (now_ms - pending.stable_since_ms >= NATIVE_MEMORY_DEBOUNCE_MS).then_some(StableObservation {
        source_id,
        digest,
        stable_since_ms: pending.stable_since_ms,
    })
}

pub fn acknowledge(state: &mut DebounceState, observation: StableObservation) -> bool {
    let matches = state
        .pending
        .get(&observation.source_id)
        .is_some_and(|pending| {
            pending.digest == observation.digest
                && pending.stable_since_ms == observation.stable_since_ms
        });
    if matches {
        state.pending.remove(&observation.source_id);
    }
    matches
}

pub fn invalidate(state: &mut DebounceState, source_id: NativeMemorySourceId) -> bool {
    state.pending.remove(&source_id).is_some()
}
