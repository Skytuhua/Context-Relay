CREATE TABLE native_memory_sources (
    source_id TEXT PRIMARY KEY CHECK (length(source_id) = 64),
    harness TEXT NOT NULL CHECK (harness IN ('claude_code', 'codex', 'hermes')),
    scope_kind TEXT NOT NULL CHECK (scope_kind IN ('global', 'project')),
    project_id TEXT,
    document_kind TEXT NOT NULL CHECK (
        document_kind IN ('agent', 'user_profile', 'summary', 'topic')
    ),
    last_observed_digest TEXT CHECK (
        last_observed_digest IS NULL OR length(last_observed_digest) = 64
    ),
    last_unmanaged_digest TEXT CHECK (
        last_unmanaged_digest IS NULL OR length(last_unmanaged_digest) = 64
    ),
    last_imported_digest TEXT CHECK (
        last_imported_digest IS NULL OR length(last_imported_digest) = 64
    ),
    last_applied_digest TEXT CHECK (
        last_applied_digest IS NULL OR length(last_applied_digest) = 64
    ),
    initial_preview_complete INTEGER NOT NULL DEFAULT 0 CHECK (
        initial_preview_complete IN (0, 1)
    ),
    payload_json BLOB NOT NULL CHECK (length(payload_json) > 0),
    CHECK (
        (scope_kind = 'global' AND project_id IS NULL)
        OR (scope_kind = 'project' AND project_id IS NOT NULL)
    )
);

CREATE INDEX native_memory_sources_scope_idx
    ON native_memory_sources(scope_kind, project_id, harness, document_kind);
