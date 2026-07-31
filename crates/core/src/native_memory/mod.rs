mod debounce;
mod markdown;
mod model;
mod reconcile;

pub use debounce::{DebounceState, StableObservation, acknowledge, observe};
pub use markdown::{ManagedMarkdown, extract_managed_markdown};
pub use model::{
    NativeMemoryDocumentKind, NativeMemoryError, NativeMemoryLedger, NativeMemoryLimits,
    NativeMemorySnapshot, NativeMemorySource, NativeMemorySourceId, ReadyNativeMemory,
};
pub use reconcile::{NativeMemoryChangeKind, ReconcileDecision, reconcile};
pub(crate) use reconcile::{
    build_native_memory_candidate, native_memory_evidence, native_memory_identity,
    native_memory_tags, native_memory_title,
};

pub const NATIVE_MEMORY_POLL_MS: u64 = 250;
pub const NATIVE_MEMORY_DEBOUNCE_MS: u64 = 750;
