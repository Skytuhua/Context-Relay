ALTER TABLE outbox ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0);
ALTER TABLE outbox ADD COLUMN next_attempt_ms INTEGER NOT NULL DEFAULT 0 CHECK (next_attempt_ms >= 0);
ALTER TABLE outbox ADD COLUMN safe_error_code TEXT;

CREATE TABLE sync_operation_meta (
    operation_id TEXT PRIMARY KEY REFERENCES operations(id) ON DELETE CASCADE,
    account_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    device_sequence TEXT NOT NULL,
    canonical_sha256 BLOB NOT NULL CHECK (length(canonical_sha256) = 32),
    direction TEXT NOT NULL CHECK (direction IN ('outgoing', 'incoming')),
    state TEXT NOT NULL CHECK (state IN ('queued', 'admitted', 'applied', 'quarantined')),
    safe_error_code TEXT,
    received_at TEXT,
    applied_at_ms INTEGER,
    UNIQUE(workspace_id, device_id, device_sequence)
);

CREATE TABLE sync_device_heads (
    workspace_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    device_sequence TEXT NOT NULL,
    canonical_sha256 BLOB NOT NULL CHECK (length(canonical_sha256) = 32),
    PRIMARY KEY(workspace_id, device_id)
);

CREATE TABLE sync_record_heads (
    workspace_id TEXT NOT NULL,
    record_id TEXT NOT NULL,
    operation_id TEXT NOT NULL REFERENCES operations(id) ON DELETE CASCADE,
    record_kind TEXT NOT NULL,
    mutation_kind TEXT NOT NULL,
    canonical_sha256 BLOB NOT NULL CHECK (length(canonical_sha256) = 32),
    PRIMARY KEY(workspace_id, record_id, operation_id)
);

CREATE TABLE sync_cursors (
    workspace_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    received_at TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    PRIMARY KEY(workspace_id, provider)
);

CREATE TABLE sync_checkpoint_meta (
    state_hash TEXT PRIMARY KEY REFERENCES checkpoints(state_hash) ON DELETE CASCADE,
    canonical_sha256 BLOB NOT NULL CHECK (length(canonical_sha256) = 32),
    accepted_at_ms INTEGER NOT NULL,
    pinned INTEGER NOT NULL CHECK (pinned IN (0, 1))
);

CREATE TABLE sync_nonces (
    key_epoch INTEGER NOT NULL CHECK (key_epoch >= 0),
    nonce BLOB NOT NULL CHECK (length(nonce) = 24),
    operation_id TEXT NOT NULL UNIQUE,
    PRIMARY KEY(key_epoch, nonce)
);

CREATE TABLE secret_refs (
    id TEXT PRIMARY KEY,
    payload_json BLOB NOT NULL
);

CREATE TABLE components (
    id TEXT PRIMARY KEY,
    payload_json BLOB NOT NULL
);

CREATE INDEX sync_outbox_due_idx
    ON outbox(next_attempt_ms, queued_at, operation_id);
CREATE INDEX sync_operation_device_sequence_idx
    ON sync_operation_meta(workspace_id, device_id, device_sequence);
CREATE INDEX sync_record_heads_record_idx
    ON sync_record_heads(workspace_id, record_id);
CREATE INDEX sync_incoming_receipt_idx
    ON sync_operation_meta(workspace_id, received_at, operation_id)
    WHERE direction = 'incoming';
