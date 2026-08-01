mod capability;
mod debounce;
mod hooks;
mod instruction;
mod markdown;
mod model;
mod reconcile;

pub use debounce::{DebounceState, StableObservation, acknowledge, observe};
pub use hooks::managed_memory_hooks;
pub(crate) use hooks::{has_managed_memory_hook_identity, merge_managed_memory_hooks};
pub(crate) use instruction::is_primary_memory_instruction_component;
pub use instruction::{PRIMARY_MEMORY_INSTRUCTIONS, primary_memory_instruction_component};
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
pub(crate) use capability::source as native_memory_source;
pub use capability::{NativeMemoryAdapter, NativeMemoryCapabilities, NativeMemoryDisable};
