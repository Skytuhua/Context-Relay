-- Recovery copies stay local to the encrypted vault, outside records and sync.
CREATE TABLE desktop_writes (
    operation_id TEXT PRIMARY KEY NOT NULL,
    payload_json BLOB NOT NULL,
    summary_json BLOB NOT NULL
);
