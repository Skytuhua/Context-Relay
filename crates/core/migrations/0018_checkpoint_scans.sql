INSERT INTO sync_checkpoint_schedule(
    account_id, workspace_id, applied_operations, first_uncheckpointed_ms,
    last_checkpoint_ms, requested
)
SELECT DISTINCT account_id, workspace_id, 0, NULL, NULL, 1
FROM signed_sync_checkpoints
WHERE true
ON CONFLICT(account_id, workspace_id) DO UPDATE SET requested = 1;

DELETE FROM sync_checkpoint_pins;
DELETE FROM signed_sync_checkpoints;

CREATE TABLE sync_checkpoint_scans (
    account_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    received_at TEXT NOT NULL,
    canonical_sha256 BLOB NOT NULL CHECK (length(canonical_sha256) = 32),
    canonical_payload BLOB NOT NULL CHECK (length(canonical_payload) <= 5242880),
    base_pin_sha256 BLOB CHECK (base_pin_sha256 IS NULL OR length(base_pin_sha256) = 32),
    pin_seen INTEGER NOT NULL CHECK (pin_seen IN (0, 1)),
    PRIMARY KEY(account_id, workspace_id, provider)
);
