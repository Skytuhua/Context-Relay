CREATE TABLE account_lifecycle_intents (
    operation_id TEXT PRIMARY KEY NOT NULL,
    payload BLOB NOT NULL CHECK (length(payload) BETWEEN 1 AND 8192)
);
