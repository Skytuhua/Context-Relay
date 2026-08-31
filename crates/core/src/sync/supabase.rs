use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    sync::Arc,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, FixedOffset};
use context_relay_protocol::{
    AccountId, BlobRef, BoundedCiphertext, CHECKPOINT_SCHEMA_VERSION, CheckpointV1, DeviceId,
    DeviceSequence, Ed25519SignatureBytes, HybridLogicalClock, MAX_BATCH_OPERATIONS, MutationKind,
    OperationId, ProjectId, RecordId, RecordKind, Sha256Digest, SyncOperationV1, WorkspaceId,
    XChaChaNonce, decode_checkpoint_v1, decode_sync_operation_v1, encode_checkpoint_v1,
    encode_sync_operation_v1,
};
use rand_core::{OsRng, RngCore};
use reqwest::{
    Url,
    blocking::Client,
    header::{HeaderName, HeaderValue},
};
use serde::{Deserialize, Deserializer, de::Error as _};
use serde_json::json;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use super::{
    BackoffPolicy, CanonicalCheckpoint, CanonicalOperation, CheckpointCursor, CheckpointPage,
    CheckpointReceipt, PullPage, PushReceipt, ReceivedCheckpoint, ReceivedOperation, SyncScope,
    SyncTransport, TransportError,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_ATTEMPTS: usize = 3;
const MAX_PAGE: usize = 256;
const MAX_REQUEST_BYTES: usize = 8 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 20 * 1024 * 1024;
const OPERATION_COLUMNS: &str = "id,account_id,workspace_id,project_id,record_id,record_kind,mutation_kind,device_id,schema_version,device_sequence,causal_frontier,control_epoch,key_epoch,previous_device_hash,nonce,ciphertext,ciphertext_hash,blob_refs,created_hlc,signature,canonical_sha256,received_at";
const CHECKPOINT_COLUMNS: &str = "account_id,workspace_id,schema_version,previous_checkpoint_hash,causal_frontier,state_hash,key_epoch,creator_device_id,created_hlc,signature,canonical_sha256,received_at";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupabaseHttpMethod {
    Get,
    Post,
}

#[derive(Clone)]
pub struct SupabaseHttpRequest {
    method: SupabaseHttpMethod,
    url: String,
    headers: Vec<(String, String)>,
    timeout: Duration,
    body: Vec<u8>,
}

impl SupabaseHttpRequest {
    pub(crate) fn new(
        method: SupabaseHttpMethod,
        url: String,
        headers: Vec<(String, String)>,
        timeout: Duration,
        body: Vec<u8>,
    ) -> Self {
        Self {
            method,
            url,
            headers,
            timeout,
            body,
        }
    }
}

#[cfg(feature = "test-support")]
impl SupabaseHttpRequest {
    pub const fn method(&self) -> SupabaseHttpMethod {
        self.method
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

impl Drop for SupabaseHttpRequest {
    fn drop(&mut self) {
        for (_, value) in &mut self.headers {
            value.zeroize();
        }
    }
}

pub struct SupabaseHttpResponse {
    status: u16,
    body: Vec<u8>,
}

impl SupabaseHttpResponse {
    pub(crate) const fn status(&self) -> u16 {
        self.status
    }

    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }
}

#[cfg(feature = "test-support")]
impl SupabaseHttpResponse {
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Self { status, body }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupabaseHttpError {
    Offline,
    Transient,
    ResponseTooLarge,
    Configuration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SupabaseRequestError {
    Transport(TransportError),
    ResponseTooLarge,
}

impl SupabaseRequestError {
    const fn into_transport(self) -> TransportError {
        match self {
            Self::Transport(error) => error,
            Self::ResponseTooLarge => TransportError::ProviderServer,
        }
    }
}

pub trait SupabaseHttpClient: Send + Sync {
    fn execute(
        &self,
        request: SupabaseHttpRequest,
    ) -> Result<SupabaseHttpResponse, SupabaseHttpError>;
}

pub trait SupabaseRetryRuntime: Send + Sync {
    fn random_u64(&self, attempt: u32) -> u64;
    fn sleep(&self, delay: Duration);
}

struct SystemRetryRuntime;

impl SupabaseRetryRuntime for SystemRetryRuntime {
    fn random_u64(&self, _attempt: u32) -> u64 {
        let mut bytes = [0_u8; 8];
        let mut random = OsRng;
        if random.try_fill_bytes(&mut bytes).is_err() {
            return 0;
        }
        u64::from_le_bytes(bytes)
    }

    fn sleep(&self, delay: Duration) {
        std::thread::sleep(delay);
    }
}

pub(crate) struct ReqwestHttpClient {
    client: Client,
}

impl ReqwestHttpClient {
    pub(crate) fn new() -> Result<Self, TransportError> {
        let client = Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .tls_backend_rustls()
            .build()
            .map_err(|_| TransportError::Configuration)?;
        Ok(Self { client })
    }
}

impl SupabaseHttpClient for ReqwestHttpClient {
    fn execute(
        &self,
        mut request: SupabaseHttpRequest,
    ) -> Result<SupabaseHttpResponse, SupabaseHttpError> {
        let method = match request.method {
            SupabaseHttpMethod::Get => reqwest::Method::GET,
            SupabaseHttpMethod::Post => reqwest::Method::POST,
        };
        let mut builder = self
            .client
            .request(method, &request.url)
            .timeout(request.timeout);
        for (name, value) in &request.headers {
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| SupabaseHttpError::Configuration)?;
            let mut value =
                HeaderValue::from_str(value).map_err(|_| SupabaseHttpError::Configuration)?;
            if name == reqwest::header::AUTHORIZATION || name.as_str() == "apikey" {
                value.set_sensitive(true);
            }
            builder = builder.header(name, value);
        }
        if !request.body.is_empty() {
            builder = builder.body(std::mem::take(&mut request.body));
        }
        let response = builder.send().map_err(classify_reqwest_error)?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
        {
            return Err(SupabaseHttpError::ResponseTooLarge);
        }
        let status = response.status().as_u16();
        let mut body = Vec::new();
        response
            .take(MAX_RESPONSE_BYTES as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|_| SupabaseHttpError::Transient)?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(SupabaseHttpError::ResponseTooLarge);
        }
        Ok(SupabaseHttpResponse { status, body })
    }
}

fn classify_reqwest_error(error: reqwest::Error) -> SupabaseHttpError {
    if error.is_builder() {
        SupabaseHttpError::Configuration
    } else if error.is_connect() {
        SupabaseHttpError::Offline
    } else {
        SupabaseHttpError::Transient
    }
}

pub struct SupabaseTransportConfig {
    project_url: Url,
    publishable_key: Zeroizing<String>,
    access_token: Zeroizing<String>,
}

impl std::fmt::Debug for SupabaseTransportConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SupabaseTransportConfig")
            .field("project_url", &self.project_url.as_str())
            .field("publishable_key", &"[REDACTED]")
            .field("access_token", &"[REDACTED]")
            .finish()
    }
}

impl SupabaseTransportConfig {
    pub fn new(
        project_url: impl AsRef<str>,
        publishable_key: impl Into<String>,
        access_token: impl Into<String>,
    ) -> Result<Self, TransportError> {
        let project_url =
            Url::parse(project_url.as_ref()).map_err(|_| TransportError::Configuration)?;
        let path_is_root = project_url.path().is_empty() || project_url.path() == "/";
        if project_url.scheme() != "https"
            || project_url.host_str().is_none()
            || !project_url.username().is_empty()
            || project_url.password().is_some()
            || !path_is_root
            || project_url.query().is_some()
            || project_url.fragment().is_some()
        {
            return Err(TransportError::Configuration);
        }
        let publishable_key = publishable_key.into();
        let access_token = access_token.into();
        if !valid_header_secret(&publishable_key) || !valid_header_secret(&access_token) {
            return Err(TransportError::Configuration);
        }
        Ok(Self {
            project_url,
            publishable_key: Zeroizing::new(publishable_key),
            access_token: Zeroizing::new(access_token),
        })
    }

    pub(crate) fn project_url(&self) -> &Url {
        &self.project_url
    }

    pub(crate) fn publishable_key(&self) -> &str {
        &self.publishable_key
    }

    pub(crate) fn access_token(&self) -> &str {
        &self.access_token
    }
}

fn valid_header_secret(value: &str) -> bool {
    !value.is_empty() && value.trim() == value && value.bytes().all(|byte| byte.is_ascii_graphic())
}

pub struct SupabaseTransport {
    config: SupabaseTransportConfig,
    http: Arc<dyn SupabaseHttpClient>,
    retry_runtime: Arc<dyn SupabaseRetryRuntime>,
}

impl SupabaseTransport {
    pub fn new(config: SupabaseTransportConfig) -> Result<Self, TransportError> {
        let http = Arc::new(ReqwestHttpClient::new()?);
        Ok(Self {
            config,
            http,
            retry_runtime: Arc::new(SystemRetryRuntime),
        })
    }

    #[cfg(feature = "test-support")]
    pub fn with_http_client(
        config: SupabaseTransportConfig,
        http: Arc<dyn SupabaseHttpClient>,
    ) -> Result<Self, TransportError> {
        Ok(Self {
            config,
            http,
            retry_runtime: Arc::new(SystemRetryRuntime),
        })
    }

    #[cfg(feature = "test-support")]
    pub fn with_http_client_and_retry_runtime(
        config: SupabaseTransportConfig,
        http: Arc<dyn SupabaseHttpClient>,
        retry_runtime: Arc<dyn SupabaseRetryRuntime>,
    ) -> Result<Self, TransportError> {
        Ok(Self {
            config,
            http,
            retry_runtime,
        })
    }

    pub fn update_access_token(
        &mut self,
        access_token: impl Into<String>,
    ) -> Result<(), TransportError> {
        let access_token = access_token.into();
        if !valid_header_secret(&access_token) {
            return Err(TransportError::Configuration);
        }
        self.config.access_token = Zeroizing::new(access_token);
        Ok(())
    }

    fn sync_url(&self) -> Result<String, TransportError> {
        self.config
            .project_url
            .join("/functions/v1/sync")
            .map(String::from)
            .map_err(|_| TransportError::Configuration)
    }

    fn table_url(&self, table: &str) -> Result<Url, TransportError> {
        self.config
            .project_url
            .join(&format!("/rest/v1/{table}"))
            .map_err(|_| TransportError::Configuration)
    }

    fn request(
        &self,
        method: SupabaseHttpMethod,
        url: String,
        body: Vec<u8>,
        idempotency_key: Option<String>,
    ) -> SupabaseHttpRequest {
        let mut headers = vec![
            (
                "authorization".to_owned(),
                format!("Bearer {}", self.config.access_token.as_str()),
            ),
            (
                "apikey".to_owned(),
                self.config.publishable_key.as_str().to_owned(),
            ),
            ("content-type".to_owned(), "application/json".to_owned()),
            ("accept".to_owned(), "application/json".to_owned()),
        ];
        if let Some(idempotency_key) = idempotency_key {
            headers.push(("idempotency-key".to_owned(), idempotency_key));
        }
        SupabaseHttpRequest {
            method,
            url,
            headers,
            timeout: REQUEST_TIMEOUT,
            body,
        }
    }

    fn execute(
        &self,
        request: SupabaseHttpRequest,
    ) -> Result<SupabaseHttpResponse, SupabaseRequestError> {
        for attempt in 0..MAX_ATTEMPTS {
            let response = match self.http.execute(request.clone()) {
                Ok(response) => response,
                Err(SupabaseHttpError::ResponseTooLarge) => {
                    return Err(SupabaseRequestError::ResponseTooLarge);
                }
                Err(error) => {
                    let error = match error {
                        SupabaseHttpError::Offline => TransportError::Offline,
                        SupabaseHttpError::Transient => TransportError::Transient,
                        SupabaseHttpError::ResponseTooLarge => unreachable!(),
                        SupabaseHttpError::Configuration => TransportError::Configuration,
                    };
                    if error.is_retryable() && attempt + 1 < MAX_ATTEMPTS {
                        self.sleep_before_retry(attempt);
                        continue;
                    }
                    return Err(SupabaseRequestError::Transport(error));
                }
            };
            if response.body.len() > MAX_RESPONSE_BYTES {
                return Err(SupabaseRequestError::ResponseTooLarge);
            }
            if (200..300).contains(&response.status) {
                return Ok(response);
            }
            let error = response_error(response.status, &response.body);
            if error.is_retryable() && attempt + 1 < MAX_ATTEMPTS {
                self.sleep_before_retry(attempt);
                continue;
            }
            return Err(SupabaseRequestError::Transport(error));
        }
        Err(SupabaseRequestError::Transport(TransportError::Transient))
    }

    fn sleep_before_retry(&self, attempt: usize) {
        let attempt = u32::try_from(attempt).unwrap_or(u32::MAX);
        let random = self.retry_runtime.random_u64(attempt);
        let delay_ms = BackoffPolicy::DEFAULT.next_delay(attempt, random);
        self.retry_runtime.sleep(Duration::from_millis(delay_ms));
    }

    fn get_json<T: for<'de> Deserialize<'de>>(&self, url: Url) -> Result<T, TransportError> {
        self.get_json_bounded(url)
            .map_err(SupabaseRequestError::into_transport)
    }

    fn get_json_bounded<T: for<'de> Deserialize<'de>>(
        &self,
        url: Url,
    ) -> Result<T, SupabaseRequestError> {
        let request = self.request(SupabaseHttpMethod::Get, String::from(url), Vec::new(), None);
        let response = self.execute(request)?;
        serde_json::from_slice(&response.body)
            .map_err(|_| SupabaseRequestError::Transport(TransportError::Integrity))
    }

    fn checkpoint_row_by_hash(
        &self,
        scope: SyncScope,
        checkpoint_version: u16,
        canonical_hash: Sha256Digest,
    ) -> Result<Option<ReceivedCheckpoint>, TransportError> {
        validate_checkpoint_version(checkpoint_version)?;
        let mut url = self.table_url("sync_checkpoints")?;
        url.query_pairs_mut()
            .append_pair("select", CHECKPOINT_COLUMNS)
            .append_pair("account_id", &format!("eq.{}", scope.account_id))
            .append_pair("workspace_id", &format!("eq.{}", scope.workspace_id))
            .append_pair("schema_version", &format!("eq.{checkpoint_version}"))
            .append_pair(
                "canonical_sha256",
                &format!("eq.{}", bytea_filter(&canonical_hash.0)),
            )
            .append_pair("limit", "2");
        let rows: Vec<CheckpointRow> = self.get_json(url)?;
        if rows.len() > 1 {
            return Err(TransportError::Integrity);
        }
        rows.into_iter()
            .next()
            .map(|row| row.received(scope))
            .transpose()
            .and_then(|row| {
                if row
                    .as_ref()
                    .is_some_and(|row| row.checkpoint.canonical_hash != canonical_hash)
                {
                    Err(TransportError::Integrity)
                } else {
                    Ok(row)
                }
            })
    }

    fn push_operation_chunk(
        &self,
        operations: &[&CanonicalOperation],
        encoded: &[String],
        body: Vec<u8>,
    ) -> Result<PushReceipt, TransportError> {
        let idempotency_key = request_digest(b"context-relay/sync/push-operations/v1\0", &body);
        let request = self.request(
            SupabaseHttpMethod::Post,
            self.sync_url()?,
            body,
            Some(idempotency_key),
        );
        let response = self
            .execute(request)
            .map_err(SupabaseRequestError::into_transport)?;
        let response: PushOperationsResponse =
            serde_json::from_slice(&response.body).map_err(|_| TransportError::ProviderServer)?;
        if response.v != 1 {
            return Err(TransportError::ProviderServer);
        }
        let expected = operations
            .iter()
            .map(|operation| operation.operation_id)
            .collect::<Vec<_>>();
        validate_receipt(&expected, &response.accepted, &response.duplicates)?;
        if encoded.len() != operations.len() {
            return Err(TransportError::Configuration);
        }
        Ok(PushReceipt {
            accepted: response.accepted,
            duplicates: response.duplicates,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SafeErrorBody {
    v: u8,
    error: String,
}

fn response_error(status: u16, body: &[u8]) -> TransportError {
    let safe_code = serde_json::from_slice::<SafeErrorBody>(body)
        .ok()
        .filter(|body| body.v == 1)
        .map(|body| body.error);
    match (status, safe_code.as_deref()) {
        (401, _) | (_, Some("auth_required")) => TransportError::AuthRequired,
        (403, _) | (_, Some("revoked")) => TransportError::Revoked,
        (_, Some("quota_blocked")) => TransportError::QuotaBlocked,
        (_, Some("invalid_envelope" | "integrity_quarantined")) => TransportError::Integrity,
        (_, Some("configuration_error")) => TransportError::Configuration,
        (429, _) => TransportError::Transient,
        (500..=599, _) => TransportError::ProviderServer,
        (400..=499, _) => TransportError::Integrity,
        _ => TransportError::Transient,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PushOperationsResponse {
    v: u8,
    accepted: Vec<OperationId>,
    duplicates: Vec<OperationId>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PushCheckpointResponse {
    v: u8,
    canonical_hash: Sha256Digest,
    duplicate: bool,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum PostgresU64 {
    Number(u64),
    Text(String),
}

impl PostgresU64 {
    fn get(self) -> Result<u64, TransportError> {
        match self {
            Self::Number(value) => Ok(value),
            Self::Text(value) => {
                let parsed = value
                    .parse::<u64>()
                    .map_err(|_| TransportError::Integrity)?;
                if parsed.to_string() != value {
                    return Err(TransportError::Integrity);
                }
                Ok(parsed)
            }
        }
    }
}

struct PostgresBytea(Vec<u8>);

impl<'de> Deserialize<'de> for PostgresBytea {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        let hex = value
            .strip_prefix("\\x")
            .ok_or_else(|| D::Error::custom("invalid bytea"))?;
        if hex.len() % 2 != 0
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(D::Error::custom("invalid bytea"));
        }
        let bytes = hex
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let high = hex_nibble(pair[0]).ok_or_else(|| D::Error::custom("invalid bytea"))?;
                let low = hex_nibble(pair[1]).ok_or_else(|| D::Error::custom("invalid bytea"))?;
                Ok((high << 4) | low)
            })
            .collect::<Result<Vec<_>, D::Error>>()?;
        Ok(Self(bytes))
    }
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

impl PostgresBytea {
    fn fixed<const N: usize>(self) -> Result<[u8; N], TransportError> {
        self.0.try_into().map_err(|_| TransportError::Integrity)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationRow {
    id: OperationId,
    account_id: AccountId,
    workspace_id: WorkspaceId,
    project_id: Option<ProjectId>,
    record_id: RecordId,
    record_kind: RecordKind,
    mutation_kind: MutationKind,
    device_id: DeviceId,
    schema_version: u16,
    device_sequence: PostgresU64,
    causal_frontier: Vec<DeviceSequence>,
    control_epoch: u32,
    key_epoch: u32,
    previous_device_hash: PostgresBytea,
    nonce: PostgresBytea,
    ciphertext: PostgresBytea,
    ciphertext_hash: PostgresBytea,
    blob_refs: Vec<BlobRef>,
    created_hlc: HybridLogicalClock,
    signature: PostgresBytea,
    canonical_sha256: PostgresBytea,
    received_at: String,
}

impl OperationRow {
    fn received(self, scope: SyncScope) -> Result<ReceivedOperation, TransportError> {
        validate_received_at(&self.received_at)?;
        let canonical_hash = Sha256Digest(self.canonical_sha256.fixed()?);
        let operation = SyncOperationV1 {
            schema_version: self.schema_version,
            operation_id: self.id,
            account_id: self.account_id,
            workspace_id: self.workspace_id,
            project_id: self.project_id,
            record_id: self.record_id,
            record_kind: self.record_kind,
            mutation_kind: self.mutation_kind,
            device_id: self.device_id,
            device_sequence: self.device_sequence.get()?,
            causal_frontier: self.causal_frontier,
            control_epoch: self.control_epoch,
            key_epoch: self.key_epoch,
            previous_device_hash: Sha256Digest(self.previous_device_hash.fixed()?),
            nonce: XChaChaNonce(self.nonce.fixed()?),
            ciphertext: BoundedCiphertext::new(self.ciphertext.0)
                .map_err(|_| TransportError::Integrity)?,
            ciphertext_hash: Sha256Digest(self.ciphertext_hash.fixed()?),
            blob_refs: self.blob_refs,
            created_hlc: self.created_hlc,
            signature: Ed25519SignatureBytes(self.signature.fixed()?),
        };
        operation
            .validate()
            .map_err(|_| TransportError::Integrity)?;
        let bytes = encode_sync_operation_v1(&operation).map_err(|_| TransportError::Integrity)?;
        if Sha256Digest(Sha256::digest(&bytes).into()) != canonical_hash
            || operation.account_id != scope.account_id
            || operation.workspace_id != scope.workspace_id
        {
            return Err(TransportError::Integrity);
        }
        Ok(ReceivedOperation {
            cursor: crate::vault::SyncCursor {
                received_at: self.received_at,
                operation_id: operation.operation_id,
            },
            operation: CanonicalOperation {
                operation_id: operation.operation_id,
                device_id: operation.device_id,
                device_sequence: operation.device_sequence,
                bytes,
            },
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointRow {
    account_id: AccountId,
    workspace_id: WorkspaceId,
    schema_version: u16,
    previous_checkpoint_hash: PostgresBytea,
    causal_frontier: Vec<DeviceSequence>,
    state_hash: PostgresBytea,
    key_epoch: u32,
    creator_device_id: DeviceId,
    created_hlc: HybridLogicalClock,
    signature: PostgresBytea,
    canonical_sha256: PostgresBytea,
    received_at: String,
}

impl CheckpointRow {
    fn received(self, scope: SyncScope) -> Result<ReceivedCheckpoint, TransportError> {
        validate_received_at(&self.received_at)?;
        let reported_hash = Sha256Digest(self.canonical_sha256.fixed()?);
        let checkpoint = CheckpointV1 {
            schema_version: self.schema_version,
            account_id: self.account_id,
            workspace_id: self.workspace_id,
            previous_checkpoint_hash: Sha256Digest(self.previous_checkpoint_hash.fixed()?),
            causal_frontier: self.causal_frontier,
            state_hash: Sha256Digest(self.state_hash.fixed()?),
            key_epoch: self.key_epoch,
            creator_device: self.creator_device_id,
            created_hlc: self.created_hlc,
            signature: Ed25519SignatureBytes(self.signature.fixed()?),
        };
        checkpoint
            .validate()
            .map_err(|_| TransportError::Integrity)?;
        let canonical = CanonicalCheckpoint::from_checkpoint(checkpoint)
            .map_err(|_| TransportError::Integrity)?;
        if canonical.canonical_hash != reported_hash
            || canonical.checkpoint.account_id != scope.account_id
            || canonical.checkpoint.workspace_id != scope.workspace_id
        {
            return Err(TransportError::Integrity);
        }
        Ok(ReceivedCheckpoint {
            cursor: CheckpointCursor {
                received_at: self.received_at,
                canonical_hash: canonical.canonical_hash,
            },
            checkpoint: canonical,
        })
    }
}

impl SyncTransport for SupabaseTransport {
    fn push_operations(
        &mut self,
        scope: SyncScope,
        batch: &[CanonicalOperation],
    ) -> Result<PushReceipt, TransportError> {
        if batch.is_empty() {
            return Ok(PushReceipt {
                accepted: Vec::new(),
                duplicates: Vec::new(),
            });
        }
        if batch.len() > MAX_BATCH_OPERATIONS || batch.len() > MAX_PAGE {
            return Err(TransportError::Configuration);
        }
        let mut by_id = BTreeMap::new();
        let mut operations = Vec::with_capacity(batch.len());
        for operation in batch {
            validate_operation(scope, operation)?;
            if let Some(previous) = by_id.insert(operation.operation_id, operation) {
                if previous != operation {
                    return Err(TransportError::Integrity);
                }
                continue;
            }
            operations.push(operation);
        }
        let encoded = operations
            .iter()
            .map(|operation| URL_SAFE_NO_PAD.encode(&operation.bytes))
            .collect::<Vec<_>>();
        let mut receipt = PushReceipt {
            accepted: Vec::new(),
            duplicates: Vec::new(),
        };
        let mut start = 0usize;
        while start < operations.len() {
            let mut end = start;
            let mut chunk_body = None;
            while end < operations.len() {
                let candidate = operation_push_body(&encoded[start..=end])?;
                if candidate.len() > MAX_REQUEST_BYTES {
                    break;
                }
                chunk_body = Some(candidate);
                end += 1;
            }
            let body = chunk_body.ok_or(TransportError::Configuration)?;
            let chunk =
                self.push_operation_chunk(&operations[start..end], &encoded[start..end], body)?;
            receipt.accepted.extend(chunk.accepted);
            receipt.duplicates.extend(chunk.duplicates);
            start = end;
        }
        let expected = operations
            .iter()
            .map(|operation| operation.operation_id)
            .collect::<Vec<_>>();
        validate_receipt(&expected, &receipt.accepted, &receipt.duplicates)?;
        Ok(receipt)
    }

    fn pull_operations(
        &mut self,
        scope: SyncScope,
        after: Option<&crate::vault::SyncCursor>,
        limit: usize,
    ) -> Result<PullPage, TransportError> {
        let requested_limit = limit.min(MAX_PAGE);
        if requested_limit == 0 {
            return Ok(PullPage {
                rows: Vec::new(),
                next_cursor: None,
            });
        }
        if let Some(after) = after {
            validate_received_at(&after.received_at)?;
        }
        let mut page_limit = requested_limit;
        let rows: Vec<OperationRow> = loop {
            let mut url = self.table_url("sync_operations")?;
            {
                let mut query = url.query_pairs_mut();
                query
                    .append_pair("select", OPERATION_COLUMNS)
                    .append_pair("account_id", &format!("eq.{}", scope.account_id))
                    .append_pair("workspace_id", &format!("eq.{}", scope.workspace_id))
                    .append_pair("order", "received_at.asc,id.asc")
                    .append_pair("limit", &page_limit.to_string());
                if let Some(after) = after {
                    query.append_pair(
                        "or",
                        &format!(
                            "(received_at.gt.{},and(received_at.eq.{},id.gt.{}))",
                            after.received_at, after.received_at, after.operation_id
                        ),
                    );
                }
            }
            match self.get_json_bounded(url) {
                Ok(rows) => break rows,
                Err(SupabaseRequestError::ResponseTooLarge) if page_limit > 1 => {
                    page_limit /= 2;
                }
                Err(error) => return Err(error.into_transport()),
            }
        };
        if rows.len() > page_limit {
            return Err(TransportError::Integrity);
        }
        let rows = rows
            .into_iter()
            .map(|row| row.received(scope))
            .collect::<Result<Vec<_>, _>>()?;
        validate_operation_order(&rows, after)?;
        let next_cursor = rows.last().map(|row| row.cursor.clone());
        Ok(PullPage { rows, next_cursor })
    }

    fn pull_device_range(
        &mut self,
        scope: SyncScope,
        device: DeviceId,
        range: std::ops::RangeInclusive<u64>,
    ) -> Result<Vec<ReceivedOperation>, TransportError> {
        let count = range
            .end()
            .checked_sub(*range.start())
            .and_then(|difference| difference.checked_add(1))
            .ok_or(TransportError::Configuration)?;
        if count > MAX_PAGE as u64 {
            return Err(TransportError::Configuration);
        }
        let final_sequence = *range.end();
        let mut next_sequence = *range.start();
        let mut chunk_limit = count as usize;
        let mut received = Vec::with_capacity(chunk_limit);
        loop {
            let remaining = final_sequence - next_sequence + 1;
            let current_limit = chunk_limit.min(remaining as usize);
            let chunk_end = next_sequence + current_limit as u64 - 1;
            let mut url = self.table_url("sync_operations")?;
            url.query_pairs_mut()
                .append_pair("select", OPERATION_COLUMNS)
                .append_pair("account_id", &format!("eq.{}", scope.account_id))
                .append_pair("workspace_id", &format!("eq.{}", scope.workspace_id))
                .append_pair("device_id", &format!("eq.{device}"))
                .append_pair("device_sequence", &format!("gte.{next_sequence}"))
                .append_pair("device_sequence", &format!("lte.{chunk_end}"))
                .append_pair("order", "device_sequence.asc,id.asc")
                .append_pair("limit", &current_limit.to_string());
            let rows: Vec<OperationRow> = match self.get_json_bounded(url) {
                Ok(rows) => rows,
                Err(SupabaseRequestError::ResponseTooLarge) if current_limit > 1 => {
                    chunk_limit = current_limit / 2;
                    continue;
                }
                Err(error) => return Err(error.into_transport()),
            };
            if rows.len() > current_limit {
                return Err(TransportError::Integrity);
            }
            let rows = rows
                .into_iter()
                .map(|row| row.received(scope))
                .collect::<Result<Vec<_>, _>>()?;
            let mut previous = received
                .last()
                .map(|row: &ReceivedOperation| row.operation.device_sequence);
            for row in &rows {
                if row.operation.device_id != device
                    || !(next_sequence..=chunk_end).contains(&row.operation.device_sequence)
                    || previous.is_some_and(|previous| previous >= row.operation.device_sequence)
                {
                    return Err(TransportError::Integrity);
                }
                previous = Some(row.operation.device_sequence);
            }
            received.extend(rows);
            if chunk_end == final_sequence {
                break;
            }
            next_sequence = chunk_end + 1;
        }
        Ok(received)
    }

    fn push_checkpoint(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        checkpoint: &CanonicalCheckpoint,
    ) -> Result<CheckpointReceipt, TransportError> {
        validate_checkpoint_version(checkpoint_version)?;
        validate_checkpoint(scope, checkpoint_version, checkpoint)?;
        let body = serde_json::to_vec(&json!({
            "v": 1,
            "action": "push_checkpoint",
            "checkpoint": URL_SAFE_NO_PAD.encode(&checkpoint.bytes),
        }))
        .map_err(|_| TransportError::Configuration)?;
        if body.len() > MAX_REQUEST_BYTES {
            return Err(TransportError::Configuration);
        }
        let idempotency_key = request_digest(b"context-relay/sync/push-checkpoint/v1\0", &body);
        let request = self.request(
            SupabaseHttpMethod::Post,
            self.sync_url()?,
            body,
            Some(idempotency_key),
        );
        let response = self
            .execute(request)
            .map_err(SupabaseRequestError::into_transport)?;
        let response: PushCheckpointResponse =
            serde_json::from_slice(&response.body).map_err(|_| TransportError::ProviderServer)?;
        if response.v != 1 || response.canonical_hash != checkpoint.canonical_hash {
            return Err(TransportError::Integrity);
        }
        Ok(CheckpointReceipt {
            canonical_hash: response.canonical_hash,
            duplicate: response.duplicate,
        })
    }

    fn pull_checkpoints(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        after: Option<&CheckpointCursor>,
        limit: usize,
    ) -> Result<CheckpointPage, TransportError> {
        validate_checkpoint_version(checkpoint_version)?;
        let limit = limit.min(MAX_PAGE);
        if limit == 0 {
            return Ok(CheckpointPage {
                rows: Vec::new(),
                next_cursor: None,
            });
        }
        if let Some(after) = after {
            validate_received_at(&after.received_at)?;
            let anchor = self
                .checkpoint_row_by_hash(scope, checkpoint_version, after.canonical_hash)?
                .ok_or(TransportError::Integrity)?;
            if anchor.cursor != *after {
                return Err(TransportError::Integrity);
            }
        }
        let mut url = self.table_url("sync_checkpoints")?;
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("select", CHECKPOINT_COLUMNS)
                .append_pair("account_id", &format!("eq.{}", scope.account_id))
                .append_pair("workspace_id", &format!("eq.{}", scope.workspace_id))
                .append_pair("schema_version", &format!("eq.{checkpoint_version}"))
                .append_pair("order", "received_at.asc,canonical_sha256.asc")
                .append_pair("limit", &limit.to_string());
            if let Some(after) = after {
                query.append_pair(
                    "or",
                    &format!(
                        "(received_at.gt.{},and(received_at.eq.{},canonical_sha256.gt.{}))",
                        after.received_at,
                        after.received_at,
                        bytea_filter(&after.canonical_hash.0)
                    ),
                );
            }
        }
        let rows: Vec<CheckpointRow> = self.get_json(url)?;
        if rows.len() > limit {
            return Err(TransportError::Integrity);
        }
        let rows = rows
            .into_iter()
            .map(|row| row.received(scope))
            .collect::<Result<Vec<_>, _>>()?;
        validate_checkpoint_order(&rows, after)?;
        let next_cursor = rows.last().map(|row| row.cursor.clone());
        Ok(CheckpointPage { rows, next_cursor })
    }

    fn checkpoint_by_hash(
        &mut self,
        scope: SyncScope,
        checkpoint_version: u16,
        canonical_hash: Sha256Digest,
    ) -> Result<Option<CanonicalCheckpoint>, TransportError> {
        Ok(self
            .checkpoint_row_by_hash(scope, checkpoint_version, canonical_hash)?
            .map(|row| row.checkpoint))
    }
}

fn validate_operation(
    scope: SyncScope,
    operation: &CanonicalOperation,
) -> Result<(), TransportError> {
    let decoded =
        decode_sync_operation_v1(&operation.bytes).map_err(|_| TransportError::Integrity)?;
    let canonical = encode_sync_operation_v1(&decoded).map_err(|_| TransportError::Integrity)?;
    if canonical != operation.bytes
        || decoded.operation_id != operation.operation_id
        || decoded.device_id != operation.device_id
        || decoded.device_sequence != operation.device_sequence
        || decoded.account_id != scope.account_id
        || decoded.workspace_id != scope.workspace_id
    {
        return Err(TransportError::Integrity);
    }
    Ok(())
}

fn validate_receipt(
    expected: &[OperationId],
    accepted: &[OperationId],
    duplicates: &[OperationId],
) -> Result<(), TransportError> {
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    for operation_id in accepted.iter().chain(duplicates) {
        if !actual.insert(*operation_id) {
            return Err(TransportError::Integrity);
        }
    }
    if expected != actual {
        return Err(TransportError::Integrity);
    }
    Ok(())
}

fn operation_push_body(encoded: &[String]) -> Result<Vec<u8>, TransportError> {
    serde_json::to_vec(&json!({
        "v": 1,
        "action": "push_operations",
        "operations": encoded,
    }))
    .map_err(|_| TransportError::Configuration)
}

fn request_digest(domain: &[u8], body: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(body);
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn validate_checkpoint_version(checkpoint_version: u16) -> Result<(), TransportError> {
    if checkpoint_version != CHECKPOINT_SCHEMA_VERSION {
        Err(TransportError::CheckpointVersionUnsupported)
    } else {
        Ok(())
    }
}

fn validate_checkpoint(
    scope: SyncScope,
    checkpoint_version: u16,
    checkpoint: &CanonicalCheckpoint,
) -> Result<(), TransportError> {
    let decoded = decode_checkpoint_v1(&checkpoint.bytes).map_err(|_| TransportError::Integrity)?;
    let bytes = encode_checkpoint_v1(&decoded).map_err(|_| TransportError::Integrity)?;
    if decoded.schema_version != checkpoint_version
        || decoded.account_id != scope.account_id
        || decoded.workspace_id != scope.workspace_id
        || decoded != checkpoint.checkpoint
        || bytes != checkpoint.bytes
        || decoded.state_hash != checkpoint.state_hash
        || Sha256Digest(Sha256::digest(&bytes).into()) != checkpoint.canonical_hash
    {
        return Err(TransportError::Integrity);
    }
    Ok(())
}

fn parse_received_at(value: &str) -> Result<DateTime<FixedOffset>, TransportError> {
    let timestamp = value
        .strip_suffix('Z')
        .or_else(|| value.strip_suffix("+00:00"))
        .ok_or(TransportError::Integrity)?;
    let (seconds, fraction) = match timestamp.split_once('.') {
        Some((seconds, fraction)) => (seconds, Some(fraction)),
        None => (timestamp, None),
    };
    let bytes = seconds.as_bytes();
    if bytes.len() != 19
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| !matches!(index, 4 | 7 | 10 | 13 | 16) && !byte.is_ascii_digit())
        || fraction.is_some_and(|fraction| {
            fraction.is_empty()
                || fraction.len() > 6
                || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return Err(TransportError::Integrity);
    }
    DateTime::parse_from_rfc3339(value).map_err(|_| TransportError::Integrity)
}

fn validate_received_at(value: &str) -> Result<(), TransportError> {
    parse_received_at(value).map(|_| ())
}

fn validate_operation_order(
    rows: &[ReceivedOperation],
    after: Option<&crate::vault::SyncCursor>,
) -> Result<(), TransportError> {
    let mut prior = after
        .map(|cursor| {
            parse_received_at(&cursor.received_at)
                .map(|received_at| (received_at, cursor.operation_id))
        })
        .transpose()?;
    for row in rows {
        let current = (
            parse_received_at(&row.cursor.received_at)?,
            row.cursor.operation_id,
        );
        if prior.is_some_and(|prior| prior >= current) {
            return Err(TransportError::Integrity);
        }
        prior = Some(current);
    }
    Ok(())
}

fn validate_checkpoint_order(
    rows: &[ReceivedCheckpoint],
    after: Option<&CheckpointCursor>,
) -> Result<(), TransportError> {
    let mut prior = after
        .map(|cursor| {
            parse_received_at(&cursor.received_at)
                .map(|received_at| (received_at, cursor.canonical_hash))
        })
        .transpose()?;
    for row in rows {
        let current = (
            parse_received_at(&row.cursor.received_at)?,
            row.cursor.canonical_hash,
        );
        if prior.is_some_and(|prior| prior >= current) {
            return Err(TransportError::Integrity);
        }
        prior = Some(current);
    }
    Ok(())
}

fn bytea_filter(value: &[u8]) -> String {
    format!(
        "\\x{}",
        value
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}
