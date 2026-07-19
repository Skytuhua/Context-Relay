CREATE TABLE records (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('memory', 'instruction')),
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('global', 'project')),
    project_id TEXT,
    archived INTEGER NOT NULL CHECK (archived IN (0, 1)),
    payload_json BLOB NOT NULL,
    CHECK (
        (scope_kind = 'global' AND project_id IS NULL)
        OR (scope_kind = 'project' AND project_id IS NOT NULL)
    )
);

CREATE TABLE candidates (
    id TEXT PRIMARY KEY,
    state TEXT NOT NULL CHECK (state IN ('pending', 'accepted', 'rejected')),
    payload_json BLOB NOT NULL
);

CREATE TABLE tasks (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    status TEXT NOT NULL,
    payload_json BLOB NOT NULL
);

CREATE TABLE instructions (
    id TEXT PRIMARY KEY REFERENCES records(id) ON DELETE CASCADE,
    payload_json BLOB NOT NULL
);

CREATE TABLE operations (
    id TEXT PRIMARY KEY,
    record_id TEXT NOT NULL,
    payload_json BLOB NOT NULL,
    canonical_cbor BLOB NOT NULL
);

CREATE TABLE outbox (
    operation_id TEXT PRIMARY KEY REFERENCES operations(id) ON DELETE CASCADE,
    queued_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE checkpoints (
    state_hash TEXT PRIMARY KEY,
    payload_json BLOB NOT NULL
);

CREATE TABLE conflicts (
    record_id TEXT PRIMARY KEY,
    left_operation_json BLOB NOT NULL,
    right_operation_json BLOB NOT NULL
);

CREATE TABLE receipts (
    plan_id TEXT PRIMARY KEY,
    successful INTEGER NOT NULL CHECK (successful IN (0, 1)),
    resolved INTEGER NOT NULL CHECK (resolved IN (0, 1)),
    applied_ms INTEGER NOT NULL,
    payload_json BLOB NOT NULL
);

CREATE TABLE paths (
    id TEXT PRIMARY KEY,
    payload_json BLOB NOT NULL
);

CREATE TABLE provenance (
    record_id TEXT PRIMARY KEY REFERENCES records(id) ON DELETE CASCADE,
    payload_json BLOB NOT NULL
);

CREATE TABLE before_images (
    id TEXT PRIMARY KEY,
    plan_id TEXT,
    created_ms INTEGER NOT NULL,
    payload BLOB NOT NULL
);

CREATE TABLE search_documents (
    record_id TEXT PRIMARY KEY REFERENCES records(id) ON DELETE CASCADE,
    record_kind TEXT NOT NULL CHECK (record_kind IN ('memory', 'instruction')),
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('global', 'project')),
    project_id TEXT,
    archived INTEGER NOT NULL CHECK (archived IN (0, 1)),
    approved INTEGER NOT NULL CHECK (approved IN (0, 1)),
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    CHECK (
        (scope_kind = 'global' AND project_id IS NULL)
        OR (scope_kind = 'project' AND project_id IS NOT NULL)
    )
);

CREATE TABLE embeddings (
    record_id TEXT PRIMARY KEY REFERENCES search_documents(record_id) ON DELETE CASCADE,
    vector BLOB NOT NULL CHECK (length(vector) = 1536)
);

CREATE INDEX records_scope_idx
    ON records(scope_kind, project_id, archived);
CREATE INDEX search_documents_scope_idx
    ON search_documents(scope_kind, project_id, archived, approved);
CREATE INDEX before_images_plan_idx
    ON before_images(plan_id, created_ms);

CREATE VIRTUAL TABLE search_fts USING fts5(
    record_id UNINDEXED,
    title,
    body,
    tokenize = 'unicode61 remove_diacritics 2'
);
