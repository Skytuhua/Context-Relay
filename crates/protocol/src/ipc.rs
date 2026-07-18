use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer, de::Error as _, ser::SerializeMap as _,
};
use ts_rs::TS;

use crate::{
    BoundedBytes, CandidateId, ClientError, CompletionEvidenceInput, CreateHandoffInput, DeviceId,
    Ed25519PublicKeyBytes, ExportId, HandoffPayload, HarnessAccessPolicy, HarnessId,
    InstallationTokenProof, MAX_MARKDOWN_BYTES, MAX_TAG_BYTES, MAX_TAGS, MAX_TITLE_BYTES,
    MemoryCandidate, MemoryId, MemoryKind, MemoryRecord, NativePlatform, OperationId,
    PairingRequestNonce, PlanId, ProbeReport, ProjectId, ProjectIdentity, ProtocolVersion,
    RecordId, ScopeRef, SetupPlan, Sha256Digest, StatusOutput, TaskId, TaskRecord, TaskStatus,
    ValidationError, WireNativeValue, X25519PublicKeyBytes, decimal_u64, required_text,
};

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

macro_rules! params { ($name:ident { $($field:ident : $ty:ty),* $(,)? }) => {
    #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
    #[serde(rename_all="camelCase",deny_unknown_fields)] #[ts(rename_all="camelCase")]
    pub struct $name { $(pub $field:$ty),* }
}; }
params!(EmptyParams {});
params!(ProjectParams {
    project_id: ProjectId
});
params!(ProjectPathParams {
    project_id: ProjectId,
    path: WireNativeValue
});
params!(MemoryParams {
    memory_id: MemoryId
});
params!(MemoryCreateParams { operation_id:OperationId,scope:ScopeRef,kind:MemoryKind,title:String,body_markdown:String,tags:Vec<String> });
params!(MemoryUpdateParams { operation_id:OperationId,memory_id:MemoryId,expected_revision:OperationId,title:Option<String>,body_markdown:Option<String>,tags:Option<Vec<String>> });
params!(MemoryArchiveParams {
    operation_id: OperationId,
    memory_id: MemoryId,
    expected_revision: OperationId
});
params!(CandidateListParams { project_id:Option<ProjectId> });
params!(SearchParams { query:String,project_id:Option<ProjectId> });
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
params!(TaskUpsertParams { operation_id:OperationId,task_id:Option<TaskId>,project_id:ProjectId,title:String,body_markdown:String,status:TaskStatus,expected_revision:Option<OperationId> });
params!(HandoffParams { operation_id:OperationId,memory_ids:Vec<MemoryId>,decision_ids:Vec<MemoryId>,task_ids:Vec<TaskId>,summary:String });
params!(HarnessParams { harness:HarnessId,project_id:Option<ProjectId> });
params!(PlanParams { plan_id: PlanId });
params!(PackageParams {
    package_base64url: BoundedBytes,
    dry_run: bool
});
params!(RetryParams {
    operation_id: OperationId
});
params!(ExportParams { project_id:Option<ProjectId>,include_archived:bool });
params!(ExportChunkParams {
    export_id: ExportId,
    chunk_index: u32
});
params!(RecoveryParams {
    recovery_phrase_words: RecoveryPhraseWords
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
    device_id: DeviceId,
    device_name: String,
    platform: NativePlatform,
    request_nonce: PairingRequestNonce,
    signing_public_key: Ed25519PublicKeyBytes,
    wrapping_public_key: X25519PublicKeyBytes
});
params!(PairingIdParams {
    pairing_id: RecordId
});
params!(PairingDecisionParams {
    pairing_id: RecordId,
    request_digest: Sha256Digest,
    approve: bool
});
params!(AccessSetParams {
    operation_id: OperationId,
    harness: HarnessId,
    policy: HarnessAccessPolicy
});
params!(AccountDeletionParams {
    confirmation: String
});

#[derive(Clone, Debug, Eq, PartialEq, TS)]
#[ts(type = "Array<string>")]
pub struct RecoveryPhraseWords(Vec<String>);
impl RecoveryPhraseWords {
    pub fn new(words: Vec<String>) -> Result<Self, &'static str> {
        if words.len() != 24
            || words.iter().any(|word| {
                word.is_empty()
                    || word.len() > 32
                    || !word.bytes().all(|byte| byte.is_ascii_lowercase())
            })
        {
            return Err("recovery phrase must contain 24 lowercase words");
        }
        Ok(Self(words))
    }
    pub fn as_words(&self) -> &[String] {
        &self.0
    }
    pub fn into_words(self) -> Vec<String> {
        self.0
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

#[derive(Clone, Debug, Eq, PartialEq, TS)]
#[ts(type = "PairingCodeString")]
pub struct PairingCode(String);
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

params!(PairingRequestInfo {
    pairing_id: RecordId,
    code: PairingCode,
    device_name: String,
    platform: NativePlatform,
    requested_at: DecimalTimestamp,
    key_fingerprint: Sha256Digest,
    request_digest: Sha256Digest
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
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum ClientRole {
    Desktop,
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
    Hello(HelloParams),
    Cancel(CancelParams),
    Shutdown(EmptyParams),
    Health(EmptyParams),
    Unlock(EmptyParams),
    ProjectsList(EmptyParams),
    ProjectPathSet(ProjectPathParams),
    MemoryGet(MemoryParams),
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
    PairingCancel(PairingIdParams),
    RecoveryBegin(EmptyParams),
    RecoveryComplete(RecoveryParams),
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
            Self::ProjectPathSet(p) => p.path.validate(),
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
            Self::DeviceRename(p) => required_text(&p.name, "name", MAX_TITLE_BYTES),
            Self::PairingJoin(p) => required_text(&p.device_name, "deviceName", MAX_TITLE_BYTES),
            Self::AccountDeletionBegin(p) => {
                required_text(&p.confirmation, "confirmation", MAX_TITLE_BYTES)
            }
            _ => Ok(()),
        }
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
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryState {
    Idle,
    AwaitingPhrase,
    Complete,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum AccountDeletionState {
    Active,
    PendingDelete,
    Purged,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(
    tag = "kind",
    content = "data",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
#[ts(
    tag = "kind",
    content = "data",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum LocalResult {
    Empty,
    Health {
        protocol: ProtocolVersion,
        vault_locked: bool,
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
    Pairing {
        request: PairingRequestInfo,
        status: PairingState,
    },
    Recovery {
        state: RecoveryState,
        recovery_phrase_words: Option<RecoveryPhraseWords>,
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
params!(JsonRpcErrorV1 { jsonrpc:JsonRpcVersion,id:Option<RecordId>,error:JsonRpcErrorObject });
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
