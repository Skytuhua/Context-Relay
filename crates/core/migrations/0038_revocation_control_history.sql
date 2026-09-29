CREATE TABLE revocation_control_history (
    account_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    control_epoch INTEGER NOT NULL CHECK (control_epoch BETWEEN 2 AND 4294967295),
    key_epoch INTEGER NOT NULL CHECK (key_epoch BETWEEN 2 AND 4294967295),
    operation_id TEXT NOT NULL UNIQUE CHECK (typeof(operation_id) = 'text' AND length(CAST(operation_id AS BLOB)) = 36),
    statement BLOB NOT NULL CHECK (length(statement) = 197),
    transition BLOB NOT NULL CHECK (length(transition) BETWEEN 1 AND 8388608),
    signature BLOB NOT NULL CHECK (length(signature) = 64),
    state_sha256 BLOB NOT NULL CHECK (length(state_sha256) = 32),
    PRIMARY KEY (account_id, workspace_id, control_epoch)
);
