use context_relay_native_runner::{RuntimeTarget, SidecarCommand, SidecarId, StagePath};
use context_relay_protocol::{
    ApplyReceipt, CliOperation, HarnessId, SetupPlan, Sha256Digest, WireNativeValue,
};

use crate::native_memory::NativeMemoryRegistration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TransactionStep {
    AcquireLock = 1,
    ReprobeLiveState = 2,
    CompareApprovedDigests = 3,
    CreateBeforeImages = 4,
    RecordNativeMetadata = 5,
    CopyAllowlistedInputs = 6,
    CreateFakeRoots = 7,
    BuildRestrictedEnvironment = 8,
    RunRestrictedTools = 9,
    RejectUnsafeTopology = 10,
    ValidateStagedOutput = 11,
    RecomputeApproval = 12,
    CheckPlanFreshness = 13,
    CompareAndSwapTargets = 14,
    WritePayloads = 15,
    InstallExecutablesDisabled = 16,
    WriteActivationReferences = 17,
    ValidateEffectiveConfiguration = 18,
    CommitOwnershipAndReceipt = 19,
    RestoreMatchingAppliedTargets = 20,
}

impl TransactionStep {
    pub const ORDER: [Self; 20] = [
        Self::AcquireLock,
        Self::ReprobeLiveState,
        Self::CompareApprovedDigests,
        Self::CreateBeforeImages,
        Self::RecordNativeMetadata,
        Self::CopyAllowlistedInputs,
        Self::CreateFakeRoots,
        Self::BuildRestrictedEnvironment,
        Self::RunRestrictedTools,
        Self::RejectUnsafeTopology,
        Self::ValidateStagedOutput,
        Self::RecomputeApproval,
        Self::CheckPlanFreshness,
        Self::CompareAndSwapTargets,
        Self::WritePayloads,
        Self::InstallExecutablesDisabled,
        Self::WriteActivationReferences,
        Self::ValidateEffectiveConfiguration,
        Self::CommitOwnershipAndReceipt,
        Self::RestoreMatchingAppliedTargets,
    ];
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestorableStateFingerprint(pub Sha256Digest);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeObjectToken {
    pub volume: Vec<u8>,
    pub object: Vec<u8>,
    pub topology: Vec<u8>,
}

impl NativeObjectToken {
    pub(crate) fn has_same_parent_binding(&self, expected: &Self) -> bool {
        self.volume == expected.volume
            && self.topology.len() == 29
            && expected.topology.len() == 29
            && self.topology[0] == 1
            && expected.topology[0] == 1
            && self.topology[5..] == expected.topology[5..]
    }

    pub(crate) fn is_absence_generation(&self) -> bool {
        self.topology.len() == 29
            && self.topology[0] == 1
            && self.topology[1..5] == u32::MAX.to_le_bytes()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationWalState {
    Prepared,
    Applied,
    RestorePrepared,
    Restored,
    Conflict,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovedInput {
    pub path: StagePath,
    pub length: u64,
    pub digest: Sha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SidecarBinding {
    pub id: SidecarId,
    pub target: RuntimeTarget,
    pub version: String,
    pub closure_hash: Sha256Digest,
    pub source_bundle_hash: Sha256Digest,
    pub build_toolchain_hash: Sha256Digest,
    pub command_template_digest: Sha256Digest,
    pub command: SidecarCommand,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationKind {
    Payload,
    ExecutableDisabled,
    ActivationReference,
}

impl MutationKind {
    pub(crate) const fn canonical_name(self) -> &'static str {
        match self {
            Self::Payload => "payload",
            Self::ExecutableDisabled => "executable_disabled",
            Self::ActivationReference => "activation_reference",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovedMutation {
    pub target: WireNativeValue,
    pub kind: MutationKind,
    /// Canonical NativeState-v1 encoding of the complete intended restorable state.
    pub content: Vec<u8>,
    pub expected: RestorableStateFingerprint,
    pub intended: RestorableStateFingerprint,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalCliDeclaration {
    pub harness: HarnessId,
    pub server_name: String,
    pub canonical_body: String,
    pub fingerprint: Sha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovedCliMutation {
    pub stable_id: String,
    /// Persisted launch target. None is retained only for legacy plans and
    /// harnesses that do not yet have a qualified explicit context contract.
    pub execution_context: Option<CliExecutionContext>,
    pub expected: Option<CanonicalCliDeclaration>,
    pub intended: Option<CanonicalCliDeclaration>,
    pub forward: Vec<CliOperation>,
    pub rollback: Vec<CliOperation>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum CliExecutionContext {
    CodexV1 {
        codex_home: WireNativeValue,
        user_home: WireNativeValue,
        project_root: WireNativeValue,
        working_directory: WireNativeValue,
    },
    /// Legacy binding retained for reading sealed plans. Its inferred home is
    /// insufficient for custom configurations; new execution requires V2.
    ClaudeCodeV1 {
        config_dir: WireNativeValue,
        state_path: WireNativeValue,
        project_root: WireNativeValue,
    },
    ClaudeCodeV2 {
        config_dir: WireNativeValue,
        state_path: WireNativeValue,
        project_root: WireNativeValue,
        user_home: WireNativeValue,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnershipChange {
    pub stable_id: String,
    pub structural_location: String,
    pub semantic_digest: Sha256Digest,
    pub native_digest: Sha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeTransactionPlan {
    pub setup: SetupPlan,
    /// Approval hash version recorded by the sealed plan envelope.
    pub approval_version: u32,
    pub helper_policy_version: u32,
    pub manifest_schema_version: u32,
    pub manifest_digest: Sha256Digest,
    pub helper_hash: Sha256Digest,
    pub sidecars: Vec<SidecarBinding>,
    pub structural_allowlist_hash: Sha256Digest,
    pub staged_inputs: Vec<ApprovedInput>,
    pub expected_semantic_output_hash: Sha256Digest,
    pub scanner_result_hash: Sha256Digest,
    pub mutations: Vec<ApprovedMutation>,
    pub cli_mutations: Vec<ApprovedCliMutation>,
    /// Exact native fallback source descriptors activated only after this
    /// sealed setup plan commits successfully.
    pub native_memory_registrations: Vec<NativeMemoryRegistration>,
    pub ownership_changes: Vec<OwnershipChange>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeReceiptEntry {
    pub target: WireNativeValue,
    pub fingerprint: RestorableStateFingerprint,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeApplyReceipt {
    pub legacy: ApplyReceipt,
    pub targets: Vec<NativeReceiptEntry>,
}
