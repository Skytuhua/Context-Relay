CREATE TABLE native_hook_sessions (
    harness TEXT NOT NULL CHECK (harness IN ('claude_code', 'codex', 'hermes')),
    session_id TEXT NOT NULL CHECK (
        length(CAST(session_id AS BLOB)) BETWEEN 1 AND 512
    ),
    project_id TEXT NOT NULL,
    started_at_ms TEXT NOT NULL CHECK (
        length(started_at_ms) = 20
        AND started_at_ms NOT GLOB '*[^0-9]*'
    ),
    stopped_at_ms TEXT CHECK (
        stopped_at_ms IS NULL
        OR (
            length(stopped_at_ms) = 20
            AND stopped_at_ms NOT GLOB '*[^0-9]*'
        )
    ),
    payload_json BLOB NOT NULL CHECK (
        length(payload_json) BETWEEN 1 AND 1048576
    ),
    PRIMARY KEY (harness, session_id)
);

CREATE INDEX native_hook_sessions_retention_idx
    ON native_hook_sessions(started_at_ms DESC, harness, session_id);
