use std::{
    collections::VecDeque,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use context_relay_core::sync::{
    CanonicalCheckpoint, CanonicalOperation, SupabaseHttpClient, SupabaseHttpMethod,
    SupabaseHttpRequest, SupabaseHttpResponse, SupabaseRetryRuntime, SupabaseTransport,
    SupabaseTransportConfig, SyncScope, SyncTransport,
};
use context_relay_protocol::{
    AccountId, BoundedCiphertext, CHECKPOINT_SCHEMA_VERSION, OperationId, Sha256Digest,
    WorkspaceId, decode_sync_operation_v1, encode_sync_operation_v1,
};
use sha2::{Digest, Sha256};

mod support;

const ACCOUNT_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073981";
const WORKSPACE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073982";
const DEVICE_ID: &str = "018f22e2-79b0-7cc8-98c4-dc0c0c073983";

#[derive(Clone)]
struct ScriptedHttpClient {
    state: Arc<Mutex<ScriptedState>>,
}

struct ScriptedState {
    requests: Vec<SupabaseHttpRequest>,
    responses: VecDeque<SupabaseHttpResponse>,
}

impl ScriptedHttpClient {
    fn new(responses: impl IntoIterator<Item = SupabaseHttpResponse>) -> Self {
        Self {
            state: Arc::new(Mutex::new(ScriptedState {
                requests: Vec::new(),
                responses: responses.into_iter().collect(),
            })),
        }
    }

    fn requests(&self) -> Vec<RequestSnapshot> {
        self.state
            .lock()
            .unwrap()
            .requests
            .iter()
            .map(RequestSnapshot::from)
            .collect()
    }
}

impl SupabaseHttpClient for ScriptedHttpClient {
    fn execute(
        &self,
        request: SupabaseHttpRequest,
    ) -> Result<SupabaseHttpResponse, context_relay_core::sync::SupabaseHttpError> {
        let mut state = self.state.lock().unwrap();
        state.requests.push(request);
        Ok(state.responses.pop_front().expect("scripted response"))
    }
}

#[derive(Default)]
struct RecordingRetryRuntime {
    delays: Mutex<Vec<Duration>>,
}

impl RecordingRetryRuntime {
    fn delays(&self) -> Vec<Duration> {
        self.delays.lock().unwrap().clone()
    }
}

impl SupabaseRetryRuntime for RecordingRetryRuntime {
    fn random_u64(&self, _attempt: u32) -> u64 {
        1_000
    }

    fn sleep(&self, delay: Duration) {
        self.delays.lock().unwrap().push(delay);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RequestSnapshot {
    method: SupabaseHttpMethod,
    url: String,
    authorization: Option<String>,
    api_key: Option<String>,
    content_type: Option<String>,
    idempotency_key: Option<String>,
    timeout: Duration,
    body: Vec<u8>,
}

impl From<&SupabaseHttpRequest> for RequestSnapshot {
    fn from(request: &SupabaseHttpRequest) -> Self {
        Self {
            method: request.method(),
            url: request.url().to_owned(),
            authorization: request.header("authorization").map(str::to_owned),
            api_key: request.header("apikey").map(str::to_owned),
            content_type: request.header("content-type").map(str::to_owned),
            idempotency_key: request.header("idempotency-key").map(str::to_owned),
            timeout: request.timeout(),
            body: request.body().to_vec(),
        }
    }
}

fn scope() -> SyncScope {
    SyncScope {
        account_id: AccountId::from_str(ACCOUNT_ID).unwrap(),
        workspace_id: WorkspaceId::from_str(WORKSPACE_ID).unwrap(),
    }
}

fn fixture_operation() -> CanonicalOperation {
    let bytes = decode_hex(include_str!("fixtures/signed-sync-operation-v1.hex"));
    let operation = decode_sync_operation_v1(&bytes).unwrap();
    assert_eq!(operation.account_id, scope().account_id);
    assert_eq!(operation.workspace_id, scope().workspace_id);
    assert_eq!(operation.device_id.to_string(), DEVICE_ID);
    CanonicalOperation {
        operation_id: operation.operation_id,
        device_id: operation.device_id,
        device_sequence: operation.device_sequence,
        bytes,
    }
}

fn operation_with_identity(operation_id: &str, sequence: u64) -> CanonicalOperation {
    let mut operation = decode_sync_operation_v1(&fixture_operation().bytes).unwrap();
    operation.operation_id = OperationId::from_str(operation_id).unwrap();
    operation.device_sequence = sequence;
    let bytes = encode_sync_operation_v1(&operation).unwrap();
    CanonicalOperation {
        operation_id: operation.operation_id,
        device_id: operation.device_id,
        device_sequence: operation.device_sequence,
        bytes,
    }
}

fn large_operation(operation_id: &str, sequence: u64, fill: u8) -> CanonicalOperation {
    let mut operation = decode_sync_operation_v1(&fixture_operation().bytes).unwrap();
    operation.operation_id = OperationId::from_str(operation_id).unwrap();
    operation.device_sequence = sequence;
    operation.ciphertext = BoundedCiphertext::new(vec![fill; 3_200_000]).unwrap();
    operation.ciphertext_hash =
        Sha256Digest(Sha256::digest(operation.ciphertext.as_slice()).into());
    let bytes = encode_sync_operation_v1(&operation).unwrap();
    CanonicalOperation {
        operation_id: operation.operation_id,
        device_id: operation.device_id,
        device_sequence: operation.device_sequence,
        bytes,
    }
}

fn decode_hex(value: &str) -> Vec<u8> {
    let value = value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).unwrap();
            let low = (pair[1] as char).to_digit(16).unwrap();
            u8::try_from((high << 4) | low).unwrap()
        })
        .collect()
}

fn base64url(value: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut encoded = String::with_capacity(value.len().div_ceil(3) * 4);
    for chunk in value.chunks(3) {
        let bits = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        encoded.push(char::from(ALPHABET[((bits >> 18) & 0x3f) as usize]));
        encoded.push(char::from(ALPHABET[((bits >> 12) & 0x3f) as usize]));
        if chunk.len() > 1 {
            encoded.push(char::from(ALPHABET[((bits >> 6) & 0x3f) as usize]));
        }
        if chunk.len() > 2 {
            encoded.push(char::from(ALPHABET[(bits & 0x3f) as usize]));
        }
    }
    encoded
}

fn json_response(status: u16, value: serde_json::Value) -> SupabaseHttpResponse {
    SupabaseHttpResponse::new(status, serde_json::to_vec(&value).unwrap())
}

fn bytea(value: &[u8]) -> String {
    format!(
        "\\x{}",
        value
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

fn operation_row(operation: &CanonicalOperation, received_at: &str) -> serde_json::Value {
    let decoded = decode_sync_operation_v1(&operation.bytes).unwrap();
    serde_json::json!({
        "id": decoded.operation_id,
        "account_id": decoded.account_id,
        "workspace_id": decoded.workspace_id,
        "project_id": decoded.project_id,
        "record_id": decoded.record_id,
        "record_kind": decoded.record_kind,
        "mutation_kind": decoded.mutation_kind,
        "device_id": decoded.device_id,
        "schema_version": decoded.schema_version,
        "device_sequence": decoded.device_sequence,
        "causal_frontier": decoded.causal_frontier,
        "control_epoch": decoded.control_epoch,
        "key_epoch": decoded.key_epoch,
        "previous_device_hash": bytea(&decoded.previous_device_hash.0),
        "nonce": bytea(&decoded.nonce.0),
        "ciphertext": bytea(decoded.ciphertext.as_slice()),
        "ciphertext_hash": bytea(&decoded.ciphertext_hash.0),
        "blob_refs": decoded.blob_refs,
        "created_hlc": decoded.created_hlc,
        "signature": bytea(&decoded.signature.0),
        "canonical_sha256": bytea(&Sha256::digest(&operation.bytes)),
        "received_at": received_at,
    })
}

fn checkpoint_row(checkpoint: &CanonicalCheckpoint, received_at: &str) -> serde_json::Value {
    let decoded = &checkpoint.checkpoint;
    serde_json::json!({
        "account_id": decoded.account_id,
        "workspace_id": decoded.workspace_id,
        "schema_version": decoded.schema_version,
        "previous_checkpoint_hash": bytea(&decoded.previous_checkpoint_hash.0),
        "causal_frontier": decoded.causal_frontier,
        "state_hash": bytea(&decoded.state_hash.0),
        "key_epoch": decoded.key_epoch,
        "creator_device_id": decoded.creator_device,
        "created_hlc": decoded.created_hlc,
        "signature": bytea(&decoded.signature.0),
        "canonical_sha256": bytea(&checkpoint.canonical_hash.0),
        "received_at": received_at,
    })
}

fn transport(client: &ScriptedHttpClient) -> SupabaseTransport {
    let config =
        SupabaseTransportConfig::new("https://unit.supabase.co", "publishable-key", "jwt-secret")
            .unwrap();
    SupabaseTransport::with_http_client(config, Arc::new(client.clone())).unwrap()
}

fn query(request: &RequestSnapshot) -> Vec<(String, String)> {
    reqwest::Url::parse(&request.url)
        .unwrap()
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect()
}

#[test]
fn operation_push_is_opaque_authenticated_idempotent_and_retried_within_a_timeout() {
    let operation = fixture_operation();
    let client = ScriptedHttpClient::new([
        json_response(503, serde_json::json!({"v": 1, "error": "transient"})),
        json_response(
            200,
            serde_json::json!({
                "v": 1,
                "accepted": [operation.operation_id],
                "duplicates": []
            }),
        ),
    ]);
    let retry_runtime = Arc::new(RecordingRetryRuntime::default());
    let config =
        SupabaseTransportConfig::new("https://unit.supabase.co", "publishable-key", "jwt-secret")
            .unwrap();
    let mut transport = SupabaseTransport::with_http_client_and_retry_runtime(
        config,
        Arc::new(client.clone()),
        retry_runtime.clone(),
    )
    .unwrap();

    let receipt = transport
        .push_operations(scope(), std::slice::from_ref(&operation))
        .unwrap();

    assert_eq!(receipt.accepted, vec![operation.operation_id]);
    assert!(receipt.duplicates.is_empty());
    let requests = client.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(retry_runtime.delays(), vec![Duration::from_millis(1_000)]);
    assert_eq!(requests[0], requests[1]);
    assert_eq!(requests[0].method, SupabaseHttpMethod::Post);
    assert_eq!(
        requests[0].url,
        "https://unit.supabase.co/functions/v1/sync"
    );
    assert_eq!(
        requests[0].authorization.as_deref(),
        Some("Bearer jwt-secret")
    );
    assert_eq!(requests[0].api_key.as_deref(), Some("publishable-key"));
    assert_eq!(
        requests[0].content_type.as_deref(),
        Some("application/json")
    );
    assert!(requests[0].idempotency_key.is_some());
    assert!(requests[0].timeout <= Duration::from_secs(15));
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(
        body,
        serde_json::json!({
            "v": 1,
            "action": "push_operations",
            "operations": [base64url(&operation.bytes)]
        })
    );
    let body = String::from_utf8(requests[0].body.clone()).unwrap();
    assert!(!body.contains(ACCOUNT_ID));
    assert!(!body.contains(WORKSPACE_ID));
    assert!(!body.contains(DEVICE_ID));
}

#[test]
fn operation_push_splits_base64_expansion_into_independently_idempotent_edge_requests() {
    let first = large_operation("018f22e2-79b0-7cc8-98c4-dc0c0c073984", 41, 0x31);
    let second = large_operation("018f22e2-79b0-7cc8-98c4-dc0c0c073985", 42, 0x32);
    let client = ScriptedHttpClient::new([
        json_response(
            200,
            serde_json::json!({"v": 1, "accepted": [first.operation_id], "duplicates": []}),
        ),
        json_response(
            200,
            serde_json::json!({"v": 1, "accepted": [second.operation_id], "duplicates": []}),
        ),
    ]);
    let mut transport = transport(&client);

    let receipt = transport
        .push_operations(scope(), &[first.clone(), second.clone()])
        .unwrap();

    assert_eq!(
        receipt.accepted,
        vec![first.operation_id, second.operation_id]
    );
    assert!(receipt.duplicates.is_empty());
    let requests = client.requests();
    assert_eq!(requests.len(), 2);
    assert!(
        requests
            .iter()
            .all(|request| request.body.len() <= 8 * 1024 * 1024)
    );
    assert!(
        requests
            .iter()
            .all(|request| request.idempotency_key.is_some())
    );
    assert_ne!(requests[0].idempotency_key, requests[1].idempotency_key);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&requests[0].body).unwrap(),
        serde_json::json!({
            "v": 1,
            "action": "push_operations",
            "operations": [base64url(&first.bytes)]
        })
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&requests[1].body).unwrap(),
        serde_json::json!({
            "v": 1,
            "action": "push_operations",
            "operations": [base64url(&second.bytes)]
        })
    );
}

#[test]
fn operation_pull_uses_a_stable_cursor_and_range_repair_is_workspace_scoped() {
    let operation = fixture_operation();
    let received_at = "2026-08-10T07:08:09.123456Z";
    let client = ScriptedHttpClient::new([
        json_response(
            200,
            serde_json::json!([operation_row(&operation, received_at)]),
        ),
        json_response(200, serde_json::json!([])),
        json_response(
            200,
            serde_json::json!([operation_row(&operation, received_at)]),
        ),
    ]);
    let mut transport = transport(&client);

    let page = transport.pull_operations(scope(), None, 999).unwrap();
    assert_eq!(page.rows.len(), 1);
    assert_eq!(page.rows[0].operation, operation);
    assert_eq!(page.rows[0].cursor.received_at, received_at);
    assert_eq!(page.next_cursor.as_ref().unwrap(), &page.rows[0].cursor);
    let resumed = transport
        .pull_operations(scope(), page.next_cursor.as_ref(), 10)
        .unwrap();
    assert!(resumed.rows.is_empty());
    assert!(resumed.next_cursor.is_none());

    let repair = transport
        .pull_device_range(
            scope(),
            page.rows[0].operation.device_id,
            page.rows[0].operation.device_sequence..=page.rows[0].operation.device_sequence,
        )
        .unwrap();
    assert_eq!(repair.len(), 1);
    assert_eq!(repair[0].operation, operation);

    let requests = client.requests();
    assert_eq!(requests.len(), 3);
    for request in &requests {
        assert_eq!(request.method, SupabaseHttpMethod::Get);
        assert!(
            request
                .url
                .starts_with("https://unit.supabase.co/rest/v1/sync_operations?")
        );
        assert_eq!(request.authorization.as_deref(), Some("Bearer jwt-secret"));
        assert_eq!(request.api_key.as_deref(), Some("publishable-key"));
        assert!(
            query(request)
                .iter()
                .any(|(name, value)| name == "workspace_id"
                    && value == &format!("eq.{WORKSPACE_ID}"))
        );
        assert!(
            query(request).iter().any(|(name, value)| {
                name == "account_id" && value == &format!("eq.{ACCOUNT_ID}")
            })
        );
    }
    let pull_query = query(&requests[0]);
    assert!(
        pull_query
            .iter()
            .any(|(name, value)| { name == "order" && value == "received_at.asc,id.asc" })
    );
    assert!(
        pull_query
            .iter()
            .any(|(name, value)| name == "limit" && value == "256")
    );
    let resumed_query = query(&requests[1]);
    assert!(resumed_query.iter().any(|(name, value)| {
        name == "or"
            && value.contains(&format!("received_at.gt.{received_at}"))
            && value.contains(&format!("id.gt.{}", operation.operation_id))
    }));
    let range_query = query(&requests[2]);
    assert!(
        range_query
            .iter()
            .any(|(name, value)| { name == "device_id" && value == &format!("eq.{DEVICE_ID}") })
    );
    assert!(range_query.iter().any(|(name, value)| {
        name == "device_sequence" && value == &format!("gte.{}", operation.device_sequence)
    }));
    assert!(range_query.iter().any(|(name, value)| {
        name == "device_sequence" && value == &format!("lte.{}", operation.device_sequence)
    }));
}

#[test]
fn oversized_operation_page_retries_with_a_smaller_row_limit() {
    let operation = fixture_operation();
    let received_at = "2026-08-10T07:08:09.123456Z";
    let client = ScriptedHttpClient::new([
        SupabaseHttpResponse::new(200, vec![b'x'; 20 * 1024 * 1024 + 1]),
        json_response(
            200,
            serde_json::json!([operation_row(&operation, received_at)]),
        ),
    ]);
    let mut transport = transport(&client);

    let page = transport.pull_operations(scope(), None, 3).unwrap();

    assert_eq!(page.rows.len(), 1);
    let requests = client.requests();
    assert_eq!(requests.len(), 2);
    assert!(
        query(&requests[0])
            .iter()
            .any(|(name, value)| name == "limit" && value == "3")
    );
    assert!(
        query(&requests[1])
            .iter()
            .any(|(name, value)| name == "limit" && value == "1")
    );
}

#[test]
fn oversized_range_repair_pages_are_retried_and_aggregated_without_a_gap() {
    let first = operation_with_identity("018f22e2-79b0-7cc8-98c4-dc0c0c073984", 41);
    let second = operation_with_identity("018f22e2-79b0-7cc8-98c4-dc0c0c073985", 42);
    let third = operation_with_identity("018f22e2-79b0-7cc8-98c4-dc0c0c073986", 43);
    let received_at = "2026-08-10T07:08:09.123456Z";
    let client = ScriptedHttpClient::new([
        SupabaseHttpResponse::new(200, vec![b'x'; 20 * 1024 * 1024 + 1]),
        json_response(200, serde_json::json!([operation_row(&first, received_at)])),
        json_response(
            200,
            serde_json::json!([operation_row(&second, received_at)]),
        ),
        json_response(200, serde_json::json!([operation_row(&third, received_at)])),
    ]);
    let mut transport = transport(&client);

    let rows = transport
        .pull_device_range(scope(), first.device_id, 41..=43)
        .unwrap();

    assert_eq!(
        rows.iter()
            .map(|row| row.operation.device_sequence)
            .collect::<Vec<_>>(),
        vec![41, 42, 43]
    );
    let requests = client.requests();
    assert_eq!(requests.len(), 4);
    assert!(
        query(&requests[0])
            .iter()
            .any(|(name, value)| name == "limit" && value == "3")
    );
    for (request, sequence) in requests[1..].iter().zip(41_u64..=43) {
        let query = query(request);
        assert!(
            query
                .iter()
                .any(|(name, value)| name == "limit" && value == "1")
        );
        assert!(query.iter().any(|(name, value)| {
            name == "device_sequence" && value == &format!("gte.{sequence}")
        }));
        assert!(query.iter().any(|(name, value)| {
            name == "device_sequence" && value == &format!("lte.{sequence}")
        }));
    }
}

#[test]
fn checkpoint_v2_push_pull_and_hash_lookup_preserve_canonical_bytes() {
    let checkpoint = CanonicalCheckpoint::from_checkpoint(support::checkpoint()).unwrap();
    assert_eq!(
        checkpoint.checkpoint.schema_version,
        CHECKPOINT_SCHEMA_VERSION
    );
    assert_eq!(checkpoint.checkpoint.account_id, scope().account_id);
    assert_eq!(checkpoint.checkpoint.workspace_id, scope().workspace_id);
    let received_at = "2026-08-10T08:09:10.654321Z";
    let client = ScriptedHttpClient::new([
        json_response(
            200,
            serde_json::json!({
                "v": 1,
                "canonicalHash": checkpoint.canonical_hash,
                "duplicate": false
            }),
        ),
        json_response(
            200,
            serde_json::json!([checkpoint_row(&checkpoint, received_at)]),
        ),
        json_response(
            200,
            serde_json::json!([checkpoint_row(&checkpoint, received_at)]),
        ),
        json_response(200, serde_json::json!([])),
        json_response(
            200,
            serde_json::json!([checkpoint_row(&checkpoint, received_at)]),
        ),
    ]);
    let mut transport = transport(&client);

    let receipt = transport
        .push_checkpoint(scope(), CHECKPOINT_SCHEMA_VERSION, &checkpoint)
        .unwrap();
    assert_eq!(receipt.canonical_hash, checkpoint.canonical_hash);
    assert!(!receipt.duplicate);

    let page = transport
        .pull_checkpoints(scope(), CHECKPOINT_SCHEMA_VERSION, None, 999)
        .unwrap();
    assert_eq!(page.rows.len(), 1);
    assert_eq!(page.rows[0].checkpoint, checkpoint);
    assert_eq!(page.rows[0].cursor.received_at, received_at);
    assert_eq!(
        page.rows[0].cursor.canonical_hash,
        checkpoint.canonical_hash
    );
    assert_eq!(page.next_cursor.as_ref().unwrap(), &page.rows[0].cursor);
    let resumed = transport
        .pull_checkpoints(
            scope(),
            CHECKPOINT_SCHEMA_VERSION,
            page.next_cursor.as_ref(),
            10,
        )
        .unwrap();
    assert!(resumed.rows.is_empty());
    assert!(resumed.next_cursor.is_none());

    assert_eq!(
        transport
            .checkpoint_by_hash(
                scope(),
                CHECKPOINT_SCHEMA_VERSION,
                checkpoint.canonical_hash
            )
            .unwrap(),
        Some(checkpoint.clone())
    );

    let requests = client.requests();
    assert_eq!(requests.len(), 5);
    assert_eq!(requests[0].method, SupabaseHttpMethod::Post);
    let push_body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(
        push_body,
        serde_json::json!({
            "v": 1,
            "action": "push_checkpoint",
            "checkpoint": base64url(&checkpoint.bytes)
        })
    );
    let push_body = String::from_utf8(requests[0].body.clone()).unwrap();
    assert!(!push_body.contains(ACCOUNT_ID));
    assert!(!push_body.contains(WORKSPACE_ID));
    assert!(!push_body.contains(&checkpoint.checkpoint.creator_device.to_string()));
    for request in &requests[1..] {
        assert_eq!(request.method, SupabaseHttpMethod::Get);
        assert!(
            request
                .url
                .starts_with("https://unit.supabase.co/rest/v1/sync_checkpoints?")
        );
        assert!(
            query(request).iter().any(|(name, value)| {
                name == "account_id" && value == &format!("eq.{ACCOUNT_ID}")
            })
        );
        assert!(query(request).iter().any(|(name, value)| {
            name == "workspace_id" && value == &format!("eq.{WORKSPACE_ID}")
        }));
        assert!(
            query(request)
                .iter()
                .any(|(name, value)| { name == "schema_version" && value == "eq.2" })
        );
    }
    assert!(query(&requests[1]).iter().any(|(name, value)| {
        name == "order" && value == "received_at.asc,canonical_sha256.asc"
    }));
    assert!(query(&requests[2]).iter().any(|(name, value)| {
        name == "canonical_sha256"
            && value == &format!("eq.{}", bytea(&checkpoint.canonical_hash.0))
    }));
    assert!(query(&requests[3]).iter().any(|(name, value)| {
        name == "or"
            && value.contains(&format!("received_at.gt.{received_at}"))
            && value.contains(&format!(
                "canonical_sha256.gt.{}",
                bytea(&checkpoint.canonical_hash.0)
            ))
    }));
    assert!(query(&requests[4]).iter().any(|(name, value)| {
        name == "canonical_sha256"
            && value == &format!("eq.{}", bytea(&checkpoint.canonical_hash.0))
    }));
}

#[test]
fn checkpoint_resume_rejects_a_missing_exact_anchor() {
    let checkpoint = CanonicalCheckpoint::from_checkpoint(support::checkpoint()).unwrap();
    let client = ScriptedHttpClient::new([json_response(200, serde_json::json!([]))]);
    let mut transport = transport(&client);
    let cursor = context_relay_core::sync::CheckpointCursor {
        received_at: "2026-08-10T08:09:10.654321Z".to_owned(),
        canonical_hash: checkpoint.canonical_hash,
    };

    assert_eq!(
        transport.pull_checkpoints(scope(), CHECKPOINT_SCHEMA_VERSION, Some(&cursor), 10,),
        Err(context_relay_core::sync::TransportError::Integrity)
    );
    assert_eq!(client.requests().len(), 1);
}

#[test]
fn configuration_and_provider_errors_are_sanitized() {
    assert!(SupabaseTransportConfig::new("http://unit.supabase.co", "key", "token").is_err());
    assert!(
        SupabaseTransportConfig::new("https://unit.supabase.co", "key\nleak", "token").is_err()
    );

    let client = ScriptedHttpClient::new([json_response(
        401,
        serde_json::json!({"message": "Bearer jwt-secret database detail"}),
    )]);
    let mut transport = transport(&client);
    assert_eq!(
        transport.pull_operations(scope(), None, 1),
        Err(context_relay_core::sync::TransportError::AuthRequired)
    );
    assert_eq!(
        context_relay_core::sync::TransportError::AuthRequired.to_string(),
        "auth_required"
    );

    let debug = format!(
        "{:?}",
        SupabaseTransportConfig::new("https://unit.supabase.co", "publishable-key", "jwt-secret")
            .unwrap()
    );
    assert!(!debug.contains("publishable-key"));
    assert!(!debug.contains("jwt-secret"));
}

#[test]
fn pull_rejects_noncanonical_or_invalid_received_at_cursors() {
    let operation = fixture_operation();
    for received_at in [
        "2026-08-10T08:09:10+01:00",
        "2026-99-99T08:09:10.123456Z",
        "2026-08-10T08:09:10.1234567Z",
    ] {
        let client = ScriptedHttpClient::new([json_response(
            200,
            serde_json::json!([operation_row(&operation, received_at)]),
        )]);
        let mut transport = transport(&client);

        assert_eq!(
            transport.pull_operations(scope(), None, 1),
            Err(context_relay_core::sync::TransportError::Integrity),
            "accepted noncanonical cursor {received_at}"
        );
    }
}
