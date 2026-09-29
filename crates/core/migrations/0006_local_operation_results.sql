CREATE TABLE local_operation_results (
    operation_id TEXT PRIMARY KEY
        REFERENCES local_operation_bindings(operation_id) ON DELETE CASCADE,
    canonical_response BLOB NOT NULL CHECK (length(canonical_response) > 0)
);
