mod admission;
mod backoff;
mod causal;
mod checkpoint;
mod engine;
mod identity;
mod memory;
mod merge;
mod operation;
pub(crate) mod supabase;
mod transport;

pub use admission::{
    AdmissionDecision, AdmittedOperation, TrustedDevice, TrustedSyncMaterial, admit_operation,
};
pub use backoff::{BackoffPolicy, InvalidBackoffPolicy};
pub use causal::{CausalOrder, compare_operations, missing_range};
pub(crate) use checkpoint::{
    AuthenticatedCheckpoint, VerifiedCheckpointChainAnchor, build_checkpoint_after_chain,
    verify_checkpoint_after_chain, verify_checkpoint_chain_extension, verify_checkpoint_link,
};
pub use checkpoint::{
    CheckpointBuildContext, CheckpointDisposition, StateSummaryEntryV1, StateSummaryV1,
    StoredCheckpointPin, VerifiedCheckpoint, build_checkpoint, decode_state_summary_v1,
    verify_checkpoint,
};
pub use engine::{
    RetryRandomSource, SyncCycleError, SyncCycleReport, SyncEngine, SyncProvider, SystemRetryRandom,
};
pub use identity::{OperationChainHead, SyncIdentity};
pub use memory::{FaultSchedule, InMemoryTransport};
pub use merge::{MergeDecision, RepresentativeEmbeddingResolver, decide_merge};
pub(crate) use operation::scope_matches;
pub use operation::{
    BuiltOperation, OperationBuildRequest, OperationBuilder, OperationDecryptor, SyncError,
    TrustedOperationContext, verify_operation_envelope,
};
#[cfg(feature = "test-support")]
pub use supabase::{
    SupabaseHttpClient, SupabaseHttpError, SupabaseHttpMethod, SupabaseHttpRequest,
    SupabaseHttpResponse, SupabaseRetryRuntime,
};
pub use supabase::{SupabaseTransport, SupabaseTransportConfig};
pub use transport::{
    CanonicalCheckpoint, CanonicalOperation, CheckpointCursor, CheckpointPage, CheckpointReceipt,
    PullPage, PushReceipt, ReceivedCheckpoint, ReceivedOperation, SyncScope, SyncTransport,
    TransportError,
};
