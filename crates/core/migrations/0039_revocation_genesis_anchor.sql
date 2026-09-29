-- Historical enrollment evidence only. No migration backfill or later tip writes.
CREATE TABLE revocation_genesis_anchor (
    singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
    account_id TEXT NOT NULL CHECK (typeof(account_id) = 'text' AND length(CAST(account_id AS BLOB)) = 36),
    workspace_id TEXT NOT NULL CHECK (typeof(workspace_id) = 'text' AND length(CAST(workspace_id AS BLOB)) = 36),
    enrollment_sha256 BLOB NOT NULL CHECK (typeof(enrollment_sha256) = 'blob' AND length(enrollment_sha256) = 32),
    anchor_sha256 BLOB NOT NULL CHECK (typeof(anchor_sha256) = 'blob' AND length(anchor_sha256) = 32),
    control_epoch INTEGER NOT NULL CHECK (typeof(control_epoch) = 'integer' AND control_epoch = 1),
    key_epoch INTEGER NOT NULL CHECK (typeof(key_epoch) = 'integer' AND key_epoch = 1),
    accepted_state_sha256 BLOB NOT NULL CHECK (typeof(accepted_state_sha256) = 'blob' AND length(accepted_state_sha256) = 32)
);
