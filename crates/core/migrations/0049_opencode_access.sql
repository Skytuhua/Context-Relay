-- Only MCP access gains a harness identity. Native memory, hook sessions, CLI
-- ownership, setup plans, and receipts retain their qualified harness sets.
ALTER TABLE harness_access RENAME TO harness_access_before_opencode;

CREATE TABLE harness_access (
    harness TEXT PRIMARY KEY CHECK (harness IN ('claude_code', 'codex', 'hermes', 'opencode')),
    payload_json BLOB NOT NULL
);

INSERT INTO harness_access(harness, payload_json)
SELECT harness, payload_json FROM harness_access_before_opencode;

DROP TABLE harness_access_before_opencode;
