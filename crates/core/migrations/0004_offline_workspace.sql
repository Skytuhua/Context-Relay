CREATE TABLE projects (
    id TEXT PRIMARY KEY,
    payload_json BLOB NOT NULL
);

CREATE TABLE harness_access (
    harness TEXT PRIMARY KEY CHECK (harness IN ('claude_code', 'codex', 'hermes')),
    payload_json BLOB NOT NULL
);
