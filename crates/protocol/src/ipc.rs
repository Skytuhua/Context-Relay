use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer, de::Error as _, ser::SerializeMap as _,
};
use ts_rs::TS;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    BoundedBytes, CandidateId, ClientError, CompletionEvidenceInput, CreateHandoffInput, DeviceId,
    ExportId, HandoffPayload, HarnessAccessPolicy, HarnessId, InstallationTokenProof,
    MAX_MARKDOWN_BYTES, MAX_TAG_BYTES, MAX_TAGS, MAX_TITLE_BYTES, MemoryCandidate, MemoryId,
    MemoryKind, MemoryRecord, NativePlatform, OperationId, PairingId, PlanId, ProbeReport,
    ProjectId, ProjectIdentity, ProtocolVersion, RecordId, RecoveryEnrollmentId, ScopeRef,
    SetupPlan, Sha256Digest, StatusOutput, TaskId, TaskRecord, TaskStatus, ValidationError,
    WireNativeValue, decimal_u64, required_text,
};

pub const RECOVERY_ENROLLMENT_SESSION_MS: u64 = 600_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
pub enum JsonRpcVersion {
    #[serde(rename = "2.0")]
    V2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, TS)]
#[ts(type = "Base64Url")]
pub struct DaemonInstanceNonce([u8; 32]);
impl DaemonInstanceNonce {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
impl Serialize for DaemonInstanceNonce {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(self.0))
    }
}
impl<'de> Deserialize<'de> for DaemonInstanceNonce {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = URL_SAFE_NO_PAD
            .decode(String::deserialize(deserializer)?)
            .map_err(D::Error::custom)?;
        Ok(Self(bytes.try_into().map_err(|_| {
            D::Error::custom("daemon nonce must be 32 bytes")
        })?))
    }
}

macro_rules! params { ($name:ident { $($(#[$field_attr:meta])* $field:ident : $ty:ty),* $(,)? }) => {
    #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
    #[serde(rename_all="camelCase",deny_unknown_fields)] #[ts(rename_all="camelCase")]
    pub struct $name { $($(#[$field_attr])* pub $field:$ty),* }
}; }
params!(EmptyParams {});
params!(HarnessPrepareParams {
    operation_id: OperationId,
    selection: HarnessParams
});
params!(HarnessPreparationIdParams {
    operation_id: OperationId
});

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum HarnessPreparationPhase {
    Inspecting,
    Copying,
    CheckingSource,
    CheckingCopy,
    Retaining,
    Cancelling,
    Ready,
    Canceled,
    Failed,
}

params!(HarnessPreparationStatus {
    operation_id: OperationId,
    selection: HarnessParams,
    phase: HarnessPreparationPhase,
    completed_files: u32,
    completed_bytes: u32,
    #[serde(deserialize_with = "crate::required_nullable")]
    error: Option<ClientError>
});

impl HarnessPreparationStatus {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_harness_profile(&self.selection)?;
        if self.selection.harness != HarnessId::Hermes
            || self.completed_files > 32768
            || self.completed_bytes > 1_073_741_824
            || (self.phase == HarnessPreparationPhase::Failed) != self.error.is_some()
        {
            return Err(ValidationError::Invalid("harnessPreparation"));
        }
        if let Some(error) = &self.error {
            required_text(&error.message, "harnessPreparation.error", MAX_TITLE_BYTES)?;
        }
        Ok(())
    }
}
params!(ProjectParams {
    project_id: ProjectId
});
params!(ProjectUpsertParams {
    project: ProjectIdentity
});
params!(ProjectRegisterParams {
    project: ProjectIdentity,
    path: WireNativeValue
});
params!(ProjectPathParams {
    project_id: ProjectId,
    path: WireNativeValue
});
params!(MemoryParams {
    memory_id: MemoryId
});
params!(MemoryListParams {
    #[serde(deserialize_with = "crate::required_nullable")]
    project_id: Option<ProjectId>,
    include_archived: bool
});
params!(MemoryCreateParams { operation_id:OperationId,scope:ScopeRef,kind:MemoryKind,title:String,body_markdown:String,tags:Vec<String> });
params!(MemoryUpdateParams {
    operation_id: OperationId,
    memory_id: MemoryId,
    expected_revision: OperationId,
    #[serde(deserialize_with = "crate::required_nullable")]
    title: Option<String>,
    #[serde(deserialize_with = "crate::required_nullable")]
    body_markdown: Option<String>,
    #[serde(deserialize_with = "crate::required_nullable")]
    tags: Option<Vec<String>>
});
params!(MemoryArchiveParams {
    operation_id: OperationId,
    memory_id: MemoryId,
    expected_revision: OperationId
});
params!(CandidateListParams {
    #[serde(deserialize_with = "crate::required_nullable")]
    project_id: Option<ProjectId>
});
params!(SearchParams {
    query: String,
    #[serde(deserialize_with = "crate::required_nullable")]
    project_id: Option<ProjectId>
});
params!(CandidateReviewParams {
    candidate_id: CandidateId,
    accepted: bool,
    operation_id: OperationId
});
params!(TaskParams { task_id: TaskId });
params!(TaskCompleteParams { operation_id:OperationId,task_id:TaskId,expected_revision:OperationId,evidence:Vec<CompletionEvidenceInput> });
params!(TaskTransitionParams {
    operation_id: OperationId,
    task_id: TaskId,
    expected_revision: OperationId,
    status: TaskStatus
});
params!(TaskUpsertParams {
    operation_id: OperationId,
    #[serde(deserialize_with = "crate::required_nullable")]
    task_id: Option<TaskId>,
    project_id: ProjectId,
    title: String,
    body_markdown: String,
    status: TaskStatus,
    #[serde(deserialize_with = "crate::required_nullable")]
    expected_revision: Option<OperationId>
});
params!(HandoffParams { operation_id:OperationId,memory_ids:Vec<MemoryId>,decision_ids:Vec<MemoryId>,task_ids:Vec<TaskId>,summary:String });
params!(HarnessParams {
    harness: HarnessId,
    #[serde(deserialize_with = "crate::required_nullable")]
    project_id: Option<ProjectId>,
    #[serde(deserialize_with = "crate::required_nullable")]
    hermes_profile: Option<String>
});
params!(McpBinding {
    harness: HarnessId,
    working_directory: WireNativeValue
});
params!(McpCallParams {
    binding: McpBinding,
    name: String,
    #[ts(type = "unknown")]
    arguments: serde_json::Value
});

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[ts(tag = "kind", rename_all = "snake_case")]
pub enum NativeHookEvent {
    SessionStart {
        session_id: String,
    },
    SessionStop {
        session_id: String,
    },
    TaskEvidence {
        session_id: String,
        task_id: TaskId,
        evidence: Vec<CompletionEvidenceInput>,
    },
}

params!(NativeHookEventParams {
    binding: McpBinding,
    event: NativeHookEvent,
    #[serde(with = "decimal_u64")]
    #[ts(type = "DecimalU64")]
    occurred_at_ms: u64
});
params!(PlanParams { plan_id: PlanId });
params!(PackageParams {
    package_base64url: BoundedBytes,
    dry_run: bool
});
params!(RetryParams {
    operation_id: OperationId
});
params!(ExportParams {
    #[serde(deserialize_with = "crate::required_nullable")]
    project_id: Option<ProjectId>,
    include_archived: bool
});
params!(ExportChunkParams {
    export_id: ExportId,
    chunk_index: u32
});
params!(RecoveryEnrollmentIdParams {
    enrollment_id: RecoveryEnrollmentId
});
params!(DeviceRevokeParams {
    device_id: DeviceId
});
params!(DeviceRenameParams {
    operation_id: OperationId,
    device_id: DeviceId,
    name: String
});
params!(CancelParams {
    request_id: RecordId
});
params!(HelloParams {
    client_role: ClientRole,
    client_nonce: DaemonInstanceNonce,
    session_proof: InstallationTokenProof
});
params!(PairingJoinParams {
    code: PairingCode,
    device_name: String
});
params!(PairingIdParams {
    pairing_id: PairingId
});
params!(PairingDecisionParams {
    pairing_id: PairingId,
    request_digest: Sha256Digest,
    approve: bool
});
params!(PairingConfirmParams {
    pairing_id: PairingId,
    safety_number: PairingSafetyNumber
});
params!(AccessSetParams {
    operation_id: OperationId,
    harness: HarnessId,
    policy: HarnessAccessPolicy
});
params!(AccountDeletionParams {
    confirmation: String
});

#[derive(Clone, Eq, PartialEq, TS)]
#[ts(type = "Array<string>")]
pub struct RecoveryPhraseWords(Vec<String>);
impl fmt::Debug for RecoveryPhraseWords {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryPhraseWords([REDACTED])")
    }
}
impl RecoveryPhraseWords {
    pub fn new(mut words: Vec<String>) -> Result<Self, &'static str> {
        if words.len() != 24
            || words.iter().any(|word| {
                word.is_empty()
                    || word.len() > 32
                    || !word.bytes().all(|byte| byte.is_ascii_lowercase())
            })
        {
            words.zeroize();
            return Err("recovery phrase must contain 24 lowercase words");
        }
        Ok(Self(words))
    }
    pub fn as_words(&self) -> &[String] {
        &self.0
    }
    pub fn into_words(mut self) -> Zeroizing<Vec<String>> {
        Zeroizing::new(std::mem::take(&mut self.0))
    }
}
impl Drop for RecoveryPhraseWords {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
impl Serialize for RecoveryPhraseWords {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(s)
    }
}
impl<'de> Deserialize<'de> for RecoveryPhraseWords {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::new(Vec::<String>::deserialize(d)?).map_err(D::Error::custom)
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct RecoveryWordConfirmation {
    pub position: u8,
    pub word: String,
}

impl fmt::Debug for RecoveryWordConfirmation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryWordConfirmation")
            .field("position", &self.position)
            .field("word", &"[REDACTED]")
            .finish()
    }
}

impl Drop for RecoveryWordConfirmation {
    fn drop(&mut self) {
        self.word.zeroize();
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct RecoveryEnrollmentConfirmParams {
    pub enrollment_id: RecoveryEnrollmentId,
    pub confirmations: Vec<RecoveryWordConfirmation>,
}

impl fmt::Debug for RecoveryEnrollmentConfirmParams {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryEnrollmentConfirmParams")
            .field("enrollment_id", &self.enrollment_id)
            .field("confirmation_count", &self.confirmations.len())
            .field(
                "positions",
                &self
                    .confirmations
                    .iter()
                    .map(|confirmation| confirmation.position)
                    .collect::<Vec<_>>(),
            )
            .field("words", &"[REDACTED]")
            .finish()
    }
}

impl RecoveryEnrollmentConfirmParams {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.confirmations.len() != 4 {
            return Err(ValidationError::Invalid("recoveryEnrollment.confirmations"));
        }

        let mut previous = 0;
        for confirmation in &self.confirmations {
            if !(1..=24).contains(&confirmation.position)
                || confirmation.position <= previous
                || confirmation.word.is_empty()
                || confirmation.word.len() > 32
                || !confirmation
                    .word
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase())
            {
                return Err(ValidationError::Invalid("recoveryEnrollment.confirmations"));
            }
            previous = confirmation.position;
        }

        Ok(())
    }
}

fn validate_confirmation_positions(positions: &[u8]) -> Result<(), ValidationError> {
    if positions.len() != 4
        || positions.iter().enumerate().any(|(index, position)| {
            !(1..=24).contains(position) || index > 0 && positions[index - 1] >= *position
        })
    {
        return Err(ValidationError::Invalid(
            "recoveryEnrollment.confirmationPositions",
        ));
    }
    Ok(())
}

#[derive(Clone, Eq, PartialEq, TS)]
#[ts(type = "PairingCodeString")]
pub struct PairingCode(String);
impl fmt::Debug for PairingCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingCode([REDACTED])")
    }
}
impl PairingCode {
    pub fn new(value: String) -> Result<Self, &'static str> {
        let valid=value.len()==11&&value.as_bytes()[5]==b'-'&&value.bytes().enumerate().all(|(index,byte)|index==5||matches!(byte,b'0'..=b'9'|b'A'..=b'H'|b'J'..=b'K'|b'M'..=b'N'|b'P'..=b'T'|b'V'..=b'Z'));
        valid
            .then_some(Self(value))
            .ok_or("pairing code must be XXXXX-XXXXX Crockford text")
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl Serialize for PairingCode {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}
impl<'de> Deserialize<'de> for PairingCode {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(d)?).map_err(D::Error::custom)
    }
}

#[derive(Clone, Eq, PartialEq, TS)]
#[ts(type = "PairingSafetyNumberString")]
pub struct PairingSafetyNumber(String);

impl PairingSafetyNumber {
    pub fn new(value: String) -> Result<Self, &'static str> {
        let valid = value.len() == 24
            && value.bytes().enumerate().all(|(index, byte)| {
                if matches!(index, 4 | 9 | 14 | 19) {
                    byte == b'-'
                } else {
                    byte.is_ascii_digit() || matches!(byte, b'A'..=b'F')
                }
            });
        valid
            .then_some(Self(value))
            .ok_or("pairing safety number must contain five uppercase hexadecimal groups")
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PairingSafetyNumber {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingSafetyNumber([REDACTED])")
    }
}

impl Serialize for PairingSafetyNumber {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for PairingSafetyNumber {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

params!(PairingInviteInfo {
    pairing_id: PairingId,
    code: PairingCode,
    created_at: DecimalTimestamp,
    expires_at: DecimalTimestamp
});

params!(PairingInviteStatusInfo {
    pairing_id: PairingId,
    created_at: DecimalTimestamp,
    expires_at: DecimalTimestamp
});

params!(PairingRequestInfo {
    pairing_id: PairingId,
    device_name: String,
    platform: NativePlatform,
    requested_at: DecimalTimestamp,
    key_fingerprint: Sha256Digest,
    request_digest: Sha256Digest
});

impl PairingRequestInfo {
    pub fn validate(&self) -> Result<(), ValidationError> {
        required_text(&self.device_name, "pairing.deviceName", MAX_TITLE_BYTES)
    }
}

params!(PairingApprovalInfo {
    request: PairingRequestInfo,
    safety_number: PairingSafetyNumber
});

params!(PairingCompletionInfo {
    pairing_id: PairingId,
    device: DeviceSummary
});

#[derive(Clone, Copy, Debug, Eq, PartialEq, TS)]
#[ts(type = "DecimalU64")]
pub struct DecimalTimestamp(pub u64);
impl Serialize for DecimalTimestamp {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        decimal_u64::serialize(&self.0, s)
    }
}
impl<'de> Deserialize<'de> for DecimalTimestamp {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        decimal_u64::deserialize(d).map(Self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ExportPayload {
    pub export_id: ExportId,
    pub chunk_index: u32,
    pub chunk_count: u32,
    pub chunk: BoundedBytes,
    pub chunk_digest: Sha256Digest,
    #[serde(with = "decimal_u64")]
    #[ts(type = "DecimalU64")]
    pub total_bytes: u64,
    pub record_count: u32,
}

impl ExportPayload {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.chunk_count == 0 || self.chunk_index >= self.chunk_count {
            return Err(ValidationError::Invalid("export.chunkIndex"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum ClientRole {
    Desktop,
    DesktopRecoveryHost,
    McpBridge,
    Installer,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(
    tag = "method",
    content = "params",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[ts(tag = "method", content = "params", rename_all = "snake_case")]
pub enum LocalRequest {
    DesktopWritePrepare(DesktopWritePrepareParams),
    DesktopWritesList(DesktopWritesListParams),
    DesktopWriteGet(DesktopWriteIdParams),
    DesktopWriteForget(DesktopWriteIdParams),
    Hello(HelloParams),
    Cancel(CancelParams),
    Shutdown(EmptyParams),
    Health(EmptyParams),
    McpCall(McpCallParams),
    NativeHookEvent(NativeHookEventParams),
    Unlock(EmptyParams),
    ProjectsList(EmptyParams),
    ProjectUpsert(ProjectUpsertParams),
    ProjectRegister(ProjectRegisterParams),
    ProjectPathSet(ProjectPathParams),
    MemoryGet(MemoryParams),
    MemoryList(MemoryListParams),
    MemorySearch(SearchParams),
    MemoryCreate(MemoryCreateParams),
    MemoryUpdate(MemoryUpdateParams),
    MemoryArchive(MemoryArchiveParams),
    CandidatesList(CandidateListParams),
    CandidateReview(CandidateReviewParams),
    TasksList(ProjectParams),
    TaskUpsert(TaskUpsertParams),
    TaskComplete(TaskCompleteParams),
    TaskTransition(TaskTransitionParams),
    HandoffCreate(HandoffParams),
    AccessGet(HarnessParams),
    AccessSet(AccessSetParams),
    HarnessProbe(HarnessParams),
    HarnessPrepare(HarnessPrepareParams),
    HarnessPreparedPreview(HarnessPrepareParams),
    HarnessPreparationStatus(HarnessPreparationIdParams),
    HarnessPreparationCancel(HarnessPreparationIdParams),
    HarnessExecutionStart(crate::HarnessExecutionParams),
    HarnessExecutionStatus(crate::HarnessExecutionParams),
    HarnessExecutionCurrent(EmptyParams),
    HarnessSetupsList(crate::HarnessSetupsParams),
    HarnessSetupGet(PlanParams),
    HarnessPreview(HarnessParams),
    HarnessApply(PlanParams),
    HarnessRepair(HarnessParams),
    HarnessRollback(PlanParams),
    PackageImport(PackageParams),
    PackageExport(ExportParams),
    SyncStatus(EmptyParams),
    SyncRetry(RetryParams),
    DevicesList(EmptyParams),
    DeviceRename(DeviceRenameParams),
    DeviceRevoke(DeviceRevokeParams),
    PairingCreate(EmptyParams),
    PairingJoin(PairingJoinParams),
    PairingStatus(PairingIdParams),
    PairingDecision(PairingDecisionParams),
    PairingConfirm(PairingConfirmParams),
    PairingCancel(PairingIdParams),
    RecoveryEnrollmentBegin(EmptyParams),
    RecoveryEnrollmentOverview(EmptyParams),
    RecoveryEnrollmentConfirm(RecoveryEnrollmentConfirmParams),
    RecoveryEnrollmentStatus(RecoveryEnrollmentIdParams),
    RecoveryEnrollmentCancel(RecoveryEnrollmentIdParams),
    ExportRecords(ExportParams),
    ExportChunk(ExportChunkParams),
    AccountDeletionBegin(AccountDeletionParams),
    AccountDeletionStatus(EmptyParams),
    AccountDeletionCancel(EmptyParams),
}

fn validate_tags(tags: &[String]) -> Result<(), ValidationError> {
    if tags.len() > MAX_TAGS {
        return Err(ValidationError::TooLarge {
            field: "tags",
            limit: MAX_TAGS,
        });
    }
    let mut unique = std::collections::BTreeSet::new();
    for tag in tags {
        required_text(tag, "tags", MAX_TAG_BYTES)?;
        if !unique.insert(tag) {
            return Err(ValidationError::Invalid("duplicate tag"));
        }
    }
    Ok(())
}
impl LocalRequest {
    pub fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Self::DesktopWritePrepare(p) => p.write.validate(),
            Self::ProjectUpsert(p) => p.project.validate(),
            Self::ProjectRegister(p) => {
                p.project.validate()?;
                p.path.validate()
            }
            Self::ProjectPathSet(p) => p.path.validate(),
            Self::McpCall(p) => {
                p.binding.working_directory.validate()?;
                crate::validate_mcp_fixture(&p.name, true, &p.arguments)
            }
            Self::NativeHookEvent(p) => {
                p.binding.working_directory.validate()?;
                p.event.validate()
            }
            Self::MemorySearch(p) => required_text(&p.query, "query", MAX_MARKDOWN_BYTES),
            Self::MemoryCreate(p) => {
                required_text(&p.title, "title", MAX_TITLE_BYTES)?;
                required_text(&p.body_markdown, "bodyMarkdown", MAX_MARKDOWN_BYTES)?;
                validate_tags(&p.tags)
            }
            Self::MemoryUpdate(p) => {
                if p.title.is_none() && p.body_markdown.is_none() && p.tags.is_none() {
                    return Err(ValidationError::EmptyRequired("memoryUpdate"));
                }
                if let Some(v) = &p.title {
                    required_text(v, "title", MAX_TITLE_BYTES)?;
                }
                if let Some(v) = &p.body_markdown {
                    required_text(v, "bodyMarkdown", MAX_MARKDOWN_BYTES)?;
                }
                if let Some(v) = &p.tags {
                    validate_tags(v)?;
                }
                Ok(())
            }
            Self::TaskComplete(p) => crate::CompleteTaskInput {
                operation_id: p.operation_id,
                task_id: p.task_id,
                expected_revision: p.expected_revision,
                evidence: p.evidence.clone(),
            }
            .validate(),
            Self::TaskTransition(p) if p.status == TaskStatus::Done => {
                Err(ValidationError::Invalid("taskTransition.done"))
            }
            Self::TaskUpsert(p) => {
                required_text(&p.title, "title", MAX_TITLE_BYTES)?;
                required_text(&p.body_markdown, "bodyMarkdown", MAX_MARKDOWN_BYTES)?;
                if p.status == TaskStatus::Done
                    || p.task_id.is_some() != p.expected_revision.is_some()
                {
                    return Err(ValidationError::Invalid("taskUpsert"));
                }
                Ok(())
            }
            Self::HandoffCreate(p) => CreateHandoffInput {
                operation_id: p.operation_id,
                memory_ids: p.memory_ids.clone(),
                decision_ids: p.decision_ids.clone(),
                task_ids: p.task_ids.clone(),
                summary: p.summary.clone(),
            }
            .validate(),
            Self::HarnessProbe(p) | Self::HarnessPreview(p) | Self::HarnessRepair(p) => {
                validate_harness_profile(p)
            }
            Self::HarnessPrepare(p) | Self::HarnessPreparedPreview(p) => {
                validate_harness_profile(&p.selection)?;
                if p.selection.harness != HarnessId::Hermes {
                    return Err(ValidationError::Invalid("harnessPrepare.selection"));
                }
                Ok(())
            }
            Self::AccessGet(p) if p.hermes_profile.is_some() => {
                Err(ValidationError::Invalid("accessGet.hermesProfile"))
            }
            Self::DeviceRename(p) => required_text(&p.name, "name", MAX_TITLE_BYTES),
            Self::PairingJoin(p) => required_text(&p.device_name, "deviceName", MAX_TITLE_BYTES),
            Self::RecoveryEnrollmentConfirm(p) => p.validate(),
            Self::AccountDeletionBegin(p) => {
                required_text(&p.confirmation, "confirmation", MAX_TITLE_BYTES)
            }
            _ => Ok(()),
        }
    }
}

fn validate_harness_profile(params: &HarnessParams) -> Result<(), ValidationError> {
    match (params.harness, params.hermes_profile.as_deref()) {
        (HarnessId::Hermes, Some(profile)) => {
            required_text(profile, "harness.hermesProfile", MAX_TITLE_BYTES)
        }
        (HarnessId::Hermes, None) => Err(ValidationError::EmptyRequired("harness.hermesProfile")),
        (HarnessId::ClaudeCode | HarnessId::Codex, None) => Ok(()),
        (HarnessId::ClaudeCode | HarnessId::Codex, Some(_)) => {
            Err(ValidationError::Invalid("harness.hermesProfile"))
        }
    }
}

impl NativeHookEvent {
    pub fn validate(&self) -> Result<(), ValidationError> {
        let (session_id, evidence) = match self {
            Self::SessionStart { session_id } | Self::SessionStop { session_id } => {
                (session_id, None)
            }
            Self::TaskEvidence {
                session_id,
                evidence,
                ..
            } => (session_id, Some(evidence)),
        };
        required_text(session_id, "nativeHook.sessionId", MAX_TITLE_BYTES)?;

        let Some(evidence) = evidence else {
            return Ok(());
        };
        if evidence.is_empty() {
            return Err(ValidationError::EmptyRequired("evidence"));
        }
        if evidence.len() > crate::MAX_EVIDENCE_ITEMS {
            return Err(ValidationError::TooLarge {
                field: "evidence",
                limit: crate::MAX_EVIDENCE_ITEMS,
            });
        }
        for item in evidence {
            required_text(&item.summary, "evidence.summary", crate::MAX_EVIDENCE_BYTES)?;
            required_text(&item.kind, "evidence.kind", 128)?;
            if item
                .reference
                .as_ref()
                .is_some_and(|value| value.len() > crate::MAX_EVIDENCE_BYTES)
            {
                return Err(ValidationError::TooLarge {
                    field: "evidence.reference",
                    limit: crate::MAX_EVIDENCE_BYTES,
                });
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, TS)]
#[ts(rename_all = "camelCase")]
pub struct JsonRpcRequestV1 {
    pub jsonrpc: JsonRpcVersion,
    pub id: RecordId,
    pub protocol: ProtocolVersion,
    pub daemon_instance_nonce: DaemonInstanceNonce,
    #[ts(flatten)]
    pub request: LocalRequest,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireRequest {
    jsonrpc: JsonRpcVersion,
    id: RecordId,
    protocol: ProtocolVersion,
    daemon_instance_nonce: DaemonInstanceNonce,
    method: String,
    params: serde_json::Value,
}
impl Serialize for JsonRpcRequestV1 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.request.validate().map_err(serde::ser::Error::custom)?;
        let request = serde_json::to_value(&self.request).map_err(serde::ser::Error::custom)?;
        let mut map = s.serialize_map(Some(6))?;
        map.serialize_entry("jsonrpc", &self.jsonrpc)?;
        map.serialize_entry("id", &self.id)?;
        map.serialize_entry("protocol", &self.protocol)?;
        map.serialize_entry("daemonInstanceNonce", &self.daemon_instance_nonce)?;
        map.serialize_entry("method", &request["method"])?;
        map.serialize_entry("params", &request["params"])?;
        map.end()
    }
}
impl<'de> Deserialize<'de> for JsonRpcRequestV1 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let wire = WireRequest::deserialize(d)?;
        if wire.protocol.major != crate::PROTOCOL_MAJOR {
            return Err(D::Error::custom("unsupported protocol major"));
        }
        let request: LocalRequest =
            serde_json::from_value(serde_json::json!({"method":wire.method,"params":wire.params}))
                .map_err(D::Error::custom)?;
        request.validate().map_err(D::Error::custom)?;
        Ok(Self {
            jsonrpc: wire.jsonrpc,
            id: wire.id,
            protocol: wire.protocol,
            daemon_instance_nonce: wire.daemon_instance_nonce,
            request,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum DeviceState {
    Pending,
    Active,
    Revoked,
}
params!(DeviceSummary {
    device_id: DeviceId,
    name: String,
    platform: NativePlatform,
    state: DeviceState,
    is_current: bool
});

impl DeviceSummary {
    pub fn validate(&self) -> Result<(), ValidationError> {
        required_text(&self.name, "device.name", MAX_TITLE_BYTES)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryEnrollmentState {
    Idle,
    AwaitingConfirmation,
    Submitting,
    Complete,
    Conflict,
}

#[derive(Clone, Debug, Eq, PartialEq, TS)]
#[ts(rename_all = "camelCase")]
pub struct RecoveryEnrollmentPhrase {
    pub enrollment_id: RecoveryEnrollmentId,
    pub recovery_phrase_words: RecoveryPhraseWords,
    pub confirmation_positions: Vec<u8>,
    pub created_at_ms: DecimalTimestamp,
    pub expires_at_ms: DecimalTimestamp,
}

#[derive(Serialize, Deserialize)]
#[serde(
    remote = "RecoveryEnrollmentPhrase",
    rename_all = "camelCase",
    deny_unknown_fields
)]
struct RecoveryEnrollmentPhraseSerde {
    enrollment_id: RecoveryEnrollmentId,
    recovery_phrase_words: RecoveryPhraseWords,
    confirmation_positions: Vec<u8>,
    created_at_ms: DecimalTimestamp,
    expires_at_ms: DecimalTimestamp,
}

impl RecoveryEnrollmentPhrase {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_confirmation_positions(&self.confirmation_positions)?;
        validate_recovery_enrollment_window(self.created_at_ms, self.expires_at_ms)
    }
}

impl Serialize for RecoveryEnrollmentPhrase {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.validate().map_err(serde::ser::Error::custom)?;
        RecoveryEnrollmentPhraseSerde::serialize(self, serializer)
    }
}

impl<'de> Deserialize<'de> for RecoveryEnrollmentPhrase {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = RecoveryEnrollmentPhraseSerde::deserialize(deserializer)?;
        value.validate().map_err(D::Error::custom)?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, TS)]
#[ts(rename_all = "camelCase")]
pub struct RecoveryEnrollmentChallenge {
    pub enrollment_id: RecoveryEnrollmentId,
    pub confirmation_positions: Vec<u8>,
    pub created_at_ms: DecimalTimestamp,
    pub expires_at_ms: DecimalTimestamp,
}

#[derive(Serialize, Deserialize)]
#[serde(
    remote = "RecoveryEnrollmentChallenge",
    rename_all = "camelCase",
    deny_unknown_fields
)]
struct RecoveryEnrollmentChallengeSerde {
    enrollment_id: RecoveryEnrollmentId,
    confirmation_positions: Vec<u8>,
    created_at_ms: DecimalTimestamp,
    expires_at_ms: DecimalTimestamp,
}

impl RecoveryEnrollmentChallenge {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_confirmation_positions(&self.confirmation_positions)?;
        validate_recovery_enrollment_window(self.created_at_ms, self.expires_at_ms)
    }
}

impl Serialize for RecoveryEnrollmentChallenge {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.validate().map_err(serde::ser::Error::custom)?;
        RecoveryEnrollmentChallengeSerde::serialize(self, serializer)
    }
}

impl<'de> Deserialize<'de> for RecoveryEnrollmentChallenge {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = RecoveryEnrollmentChallengeSerde::deserialize(deserializer)?;
        value.validate().map_err(D::Error::custom)?;
        Ok(value)
    }
}

fn validate_recovery_enrollment_window(
    created_at_ms: DecimalTimestamp,
    expires_at_ms: DecimalTimestamp,
) -> Result<(), ValidationError> {
    (created_at_ms.0.checked_add(RECOVERY_ENROLLMENT_SESSION_MS) == Some(expires_at_ms.0))
        .then_some(())
        .ok_or(ValidationError::Invalid("recoveryEnrollment.expiresAtMs"))
}

params!(RecoveryEnrollmentStatus {
    #[serde(deserialize_with = "crate::required_nullable")]
    enrollment_id: Option<RecoveryEnrollmentId>,
    state: RecoveryEnrollmentState,
    #[serde(deserialize_with = "crate::required_nullable")]
    created_at_ms: Option<DecimalTimestamp>,
    #[serde(deserialize_with = "crate::required_nullable")]
    transitioned_at_ms: Option<DecimalTimestamp>
});

impl RecoveryEnrollmentStatus {
    pub fn validate(&self) -> Result<(), ValidationError> {
        let valid = match self.state {
            RecoveryEnrollmentState::Idle => {
                self.enrollment_id.is_none()
                    && self.created_at_ms.is_none()
                    && self.transitioned_at_ms.is_none()
            }
            RecoveryEnrollmentState::AwaitingConfirmation => {
                self.enrollment_id.is_some()
                    && self.created_at_ms.is_some()
                    && self.transitioned_at_ms.is_none()
            }
            RecoveryEnrollmentState::Submitting
            | RecoveryEnrollmentState::Complete
            | RecoveryEnrollmentState::Conflict => {
                self.enrollment_id.is_some()
                    && self.created_at_ms.is_some()
                    && self.transitioned_at_ms.is_some()
            }
        };

        valid
            .then_some(())
            .ok_or(ValidationError::Invalid("recoveryEnrollment.status"))
    }
}

params!(RecoveryEnrollmentComplete {
    enrollment_id: RecoveryEnrollmentId,
    device: DeviceSummary
});

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
#[ts(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum RecoveryEnrollmentHostBeginResult {
    Challenge(RecoveryEnrollmentChallenge),
    Status(RecoveryEnrollmentStatus),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
#[ts(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum RecoveryEnrollmentHostConfirmResult {
    Canceled,
    Complete(RecoveryEnrollmentComplete),
    Status(RecoveryEnrollmentStatus),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum AccountDeletionState {
    Active,
    PendingDelete,
    Purged,
}
#[derive(Clone, Debug, Eq, PartialEq, TS)]
#[ts(
    tag = "kind",
    content = "data",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum LocalResult {
    HarnessExecutionCurrent {
        status: Option<crate::HarnessExecutionStatus>,
    },
    HarnessExecution {
        status: crate::HarnessExecutionStatus,
    },
    HarnessSetup {
        setup: Box<crate::HarnessSetupRecord>,
    },
    HarnessSetups {
        page: crate::HarnessSetupsPage,
    },
    HarnessPreparation {
        status: HarnessPreparationStatus,
    },
    DesktopWrite {
        write: Option<crate::DesktopWrite>,
    },
    DesktopWrites {
        page: crate::DesktopWritesPage,
    },
    Empty,
    Health {
        protocol: ProtocolVersion,
        vault_locked: bool,
    },
    McpOutput {
        name: String,
        #[ts(type = "unknown")]
        output: serde_json::Value,
    },
    Projects {
        projects: Vec<ProjectIdentity>,
    },
    Memory {
        memory: Option<MemoryRecord>,
    },
    Memories {
        memories: Vec<MemoryRecord>,
    },
    Candidates {
        candidates: Vec<MemoryCandidate>,
    },
    Tasks {
        tasks: Vec<TaskRecord>,
    },
    Handoff {
        handoff_id: OperationId,
        payload: HandoffPayload,
    },
    Probe {
        report: ProbeReport,
    },
    Plan {
        plan: Box<SetupPlan>,
    },
    Status {
        status: StatusOutput,
    },
    Devices {
        devices: Vec<DeviceSummary>,
    },
    PairingInvite {
        invite: PairingInviteInfo,
        status: PairingState,
    },
    PairingInviteStatus {
        invite: PairingInviteStatusInfo,
        status: PairingState,
    },
    PairingRequest {
        request: PairingRequestInfo,
        status: PairingState,
    },
    PairingApproval {
        approval: PairingApprovalInfo,
    },
    PairingCompletion {
        completion: PairingCompletionInfo,
    },
    RecoveryEnrollmentPhrase {
        phrase: RecoveryEnrollmentPhrase,
    },
    RecoveryEnrollmentStatus {
        status: RecoveryEnrollmentStatus,
    },
    RecoveryEnrollmentComplete {
        completion: RecoveryEnrollmentComplete,
    },
    Export {
        payload: ExportPayload,
    },
    AccountDeletion {
        state: AccountDeletionState,
        purge_deadline: Option<DecimalTimestamp>,
        export_available: bool,
    },
    Access {
        policy: HarnessAccessPolicy,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(
    remote = "LocalResult",
    tag = "kind",
    content = "data",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum LocalResultSerde {
    HarnessExecutionCurrent {
        #[serde(deserialize_with = "crate::required_nullable")]
        status: Option<crate::HarnessExecutionStatus>,
    },
    HarnessExecution {
        status: crate::HarnessExecutionStatus,
    },
    HarnessSetup {
        setup: Box<crate::HarnessSetupRecord>,
    },
    HarnessSetups {
        page: crate::HarnessSetupsPage,
    },
    HarnessPreparation {
        status: HarnessPreparationStatus,
    },
    DesktopWrite {
        #[serde(deserialize_with = "crate::required_nullable")]
        write: Option<crate::DesktopWrite>,
    },
    DesktopWrites {
        page: crate::DesktopWritesPage,
    },
    Empty,
    Health {
        protocol: ProtocolVersion,
        vault_locked: bool,
    },
    McpOutput {
        name: String,
        output: serde_json::Value,
    },
    Projects {
        projects: Vec<ProjectIdentity>,
    },
    Memory {
        #[serde(deserialize_with = "crate::required_nullable")]
        memory: Option<MemoryRecord>,
    },
    Memories {
        memories: Vec<MemoryRecord>,
    },
    Candidates {
        candidates: Vec<MemoryCandidate>,
    },
    Tasks {
        tasks: Vec<TaskRecord>,
    },
    Handoff {
        handoff_id: OperationId,
        payload: HandoffPayload,
    },
    Probe {
        report: ProbeReport,
    },
    Plan {
        plan: Box<SetupPlan>,
    },
    Status {
        status: StatusOutput,
    },
    Devices {
        devices: Vec<DeviceSummary>,
    },
    PairingInvite {
        invite: PairingInviteInfo,
        status: PairingState,
    },
    PairingInviteStatus {
        invite: PairingInviteStatusInfo,
        status: PairingState,
    },
    PairingRequest {
        request: PairingRequestInfo,
        status: PairingState,
    },
    PairingApproval {
        approval: PairingApprovalInfo,
    },
    PairingCompletion {
        completion: PairingCompletionInfo,
    },
    RecoveryEnrollmentPhrase {
        phrase: RecoveryEnrollmentPhrase,
    },
    RecoveryEnrollmentStatus {
        status: RecoveryEnrollmentStatus,
    },
    RecoveryEnrollmentComplete {
        completion: RecoveryEnrollmentComplete,
    },
    Export {
        payload: ExportPayload,
    },
    AccountDeletion {
        state: AccountDeletionState,
        #[serde(deserialize_with = "crate::required_nullable")]
        purge_deadline: Option<DecimalTimestamp>,
        export_available: bool,
    },
    Access {
        policy: HarnessAccessPolicy,
    },
}

impl LocalResult {
    pub fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Self::HarnessExecutionCurrent { status } => status
                .as_ref()
                .map_or(Ok(()), crate::HarnessExecutionStatus::validate),
            Self::HarnessExecution { status } => status.validate(),
            Self::HarnessSetup { setup } => setup.validate(),
            Self::HarnessSetups { page } => page.validate(),
            Self::HarnessPreparation { status } => status.validate(),
            Self::DesktopWrite { write } => {
                write.as_ref().map_or(Ok(()), crate::DesktopWrite::validate)
            }
            Self::DesktopWrites { page } => page.validate(),
            Self::Empty | Self::AccountDeletion { .. } | Self::Access { .. } => Ok(()),
            Self::Health { protocol, .. } => {
                if protocol.major != crate::PROTOCOL_MAJOR {
                    return Err(ValidationError::Invalid("health.protocol"));
                }
                Ok(())
            }
            Self::McpOutput { name, output } => crate::validate_mcp_fixture(name, false, output),
            Self::Projects { projects } => {
                for project in projects {
                    project.validate()?;
                }
                Ok(())
            }
            Self::Memory { memory } => {
                if let Some(memory) = memory {
                    memory.validate()?;
                }
                Ok(())
            }
            Self::Memories { memories } => {
                for memory in memories {
                    memory.validate()?;
                }
                Ok(())
            }
            Self::Candidates { candidates } => {
                for candidate in candidates {
                    candidate.validate()?;
                }
                Ok(())
            }
            Self::Tasks { tasks } => {
                for task in tasks {
                    task.validate()?;
                }
                Ok(())
            }
            Self::Handoff { payload, .. } => payload.validate(),
            Self::Probe { report } => report.validate(),
            Self::Plan { plan } => plan.validate(),
            Self::Status { status } => status.validate(),
            Self::Devices { devices } => {
                for device in devices {
                    device.validate()?;
                }
                Ok(())
            }
            Self::PairingInvite { .. } | Self::PairingInviteStatus { .. } => Ok(()),
            Self::PairingRequest { request, .. } => request.validate(),
            Self::PairingApproval { approval } => approval.request.validate(),
            Self::PairingCompletion { completion } => completion.device.validate(),
            Self::RecoveryEnrollmentPhrase { phrase } => phrase.validate(),
            Self::RecoveryEnrollmentStatus { status } => status.validate(),
            Self::RecoveryEnrollmentComplete { completion } => completion.device.validate(),
            Self::Export { payload } => payload.validate(),
        }
    }
}

impl Serialize for LocalResult {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.validate().map_err(serde::ser::Error::custom)?;
        LocalResultSerde::serialize(self, serializer)
    }
}

impl<'de> Deserialize<'de> for LocalResult {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = LocalResultSerde::deserialize(deserializer)?;
        value.validate().map_err(D::Error::custom)?;
        Ok(value)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum PairingState {
    Pending,
    Approved,
    Rejected,
    Canceled,
}
params!(JsonRpcSuccessV1 {
    jsonrpc: JsonRpcVersion,
    id: RecordId,
    result: LocalResult
});
params!(JsonRpcErrorObject {
    code: i32,
    message: String,
    data: ClientError
});
params!(JsonRpcErrorV1 {
    jsonrpc: JsonRpcVersion,
    #[serde(deserialize_with = "crate::required_nullable")]
    id: Option<RecordId>,
    error: JsonRpcErrorObject
});
params!(DesktopWritePrepareParams {
    write: crate::DesktopWrite
});
params!(DesktopWriteIdParams {
    operation_id: OperationId
});
params!(DesktopWritesListParams {
    #[serde(deserialize_with = "crate::required_nullable")]
    after: Option<OperationId>
});
pub const JSON_RPC_PARSE_ERROR: i32 = -32700;
pub const JSON_RPC_INVALID_REQUEST: i32 = -32600;
pub const JSON_RPC_METHOD_NOT_FOUND: i32 = -32601;
pub const JSON_RPC_INVALID_PARAMS: i32 = -32602;
pub const JSON_RPC_INTERNAL_ERROR: i32 = -32603;
pub const CONTEXT_RELAY_APPLICATION_ERROR: i32 = -32040;
params!(LocalProjectPath {
    project_id: ProjectId,
    path: WireNativeValue
});
