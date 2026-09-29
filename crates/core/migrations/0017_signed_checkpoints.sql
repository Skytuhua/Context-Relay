CREATE TABLE signed_sync_checkpoints (
    account_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    canonical_sha256 BLOB NOT NULL CHECK (length(canonical_sha256) = 32),
    state_hash BLOB NOT NULL CHECK (length(state_hash) = 32),
    canonical_payload BLOB NOT NULL CHECK (length(canonical_payload) <= 5242880),
    accepted_at_ms INTEGER NOT NULL CHECK (accepted_at_ms >= 0),
    PRIMARY KEY(account_id, workspace_id, canonical_sha256)
);

CREATE INDEX signed_sync_checkpoints_scope_idx
    ON signed_sync_checkpoints(account_id, workspace_id, accepted_at_ms, canonical_sha256);

CREATE TABLE sync_checkpoint_pins (
    account_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    canonical_sha256 BLOB NOT NULL,
    PRIMARY KEY(account_id, workspace_id),
    FOREIGN KEY(account_id, workspace_id, canonical_sha256)
        REFERENCES signed_sync_checkpoints(account_id, workspace_id, canonical_sha256)
);

CREATE TABLE sync_checkpoint_schedule (
    account_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    applied_operations INTEGER NOT NULL DEFAULT 0 CHECK (applied_operations >= 0),
    first_uncheckpointed_ms INTEGER CHECK (first_uncheckpointed_ms >= 0),
    last_checkpoint_ms INTEGER CHECK (last_checkpoint_ms >= 0),
    requested INTEGER NOT NULL DEFAULT 0 CHECK (requested IN (0, 1)),
    PRIMARY KEY(account_id, workspace_id),
    CHECK (
        (applied_operations = 0 AND first_uncheckpointed_ms IS NULL)
        OR (applied_operations > 0 AND first_uncheckpointed_ms IS NOT NULL)
    )
);
