CREATE TABLE setup_plan_lifecycle (
    plan_id TEXT PRIMARY KEY REFERENCES native_plans(plan_id) ON DELETE RESTRICT,
    schema_version INTEGER NOT NULL CHECK (schema_version BETWEEN 1 AND 4294967295),
    approval_version INTEGER NOT NULL CHECK (approval_version BETWEEN 1 AND 4294967295),
    state TEXT NOT NULL CHECK (
        state IN (
            'previewed', 'applying', 'applied', 'apply_restored',
            'rolling_back', 'rolled_back', 'rollback_restored',
            'conflict', 'expired'
        )
    ),
    updated_ms INTEGER NOT NULL CHECK (updated_ms >= 0)
);

CREATE TABLE native_cli_wal (
    transaction_id TEXT NOT NULL
        REFERENCES native_transactions(transaction_id) ON DELETE RESTRICT,
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    stable_id TEXT NOT NULL CHECK (length(stable_id) BETWEEN 1 AND 512),
    harness TEXT NOT NULL CHECK (harness IN ('claude_code', 'codex')),
    server_name TEXT NOT NULL CHECK (length(server_name) BETWEEN 1 AND 256),
    expected_declaration BLOB,
    expected_fingerprint BLOB,
    intended_declaration BLOB,
    intended_fingerprint BLOB,
    forward_operations BLOB NOT NULL CHECK (length(forward_operations) > 0),
    rollback_operations BLOB NOT NULL CHECK (length(rollback_operations) > 0),
    state TEXT NOT NULL CHECK (
        state IN ('prepared', 'applied', 'restore_prepared', 'restored', 'conflict')
    ),
    CHECK (
        (
            expected_declaration IS NULL
            AND expected_fingerprint IS NULL
        )
        OR (
            expected_declaration IS NOT NULL
            AND length(expected_declaration) > 0
            AND expected_fingerprint IS NOT NULL
            AND length(expected_fingerprint) = 32
        )
    ),
    CHECK (
        (
            intended_declaration IS NULL
            AND intended_fingerprint IS NULL
        )
        OR (
            intended_declaration IS NOT NULL
            AND length(intended_declaration) > 0
            AND intended_fingerprint IS NOT NULL
            AND length(intended_fingerprint) = 32
        )
    ),
    CHECK (expected_declaration IS NOT NULL OR intended_declaration IS NOT NULL),
    PRIMARY KEY (transaction_id, sequence),
    UNIQUE (transaction_id, stable_id),
    UNIQUE (transaction_id, harness, server_name)
);

CREATE INDEX setup_plan_lifecycle_state_idx
    ON setup_plan_lifecycle(state, updated_ms, plan_id);
CREATE INDEX native_cli_wal_state_idx
    ON native_cli_wal(transaction_id, state, sequence);
