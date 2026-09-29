CREATE TABLE local_operation_bindings (
    operation_id TEXT PRIMARY KEY,
    operation_kind TEXT NOT NULL CHECK (
        operation_kind IN (
            'memory_create',
            'memory_proposal',
            'memory_update',
            'memory_archive'
        )
    ),
    target_id TEXT NOT NULL,
    expected_revision TEXT,
    canonical_payload BLOB NOT NULL
);
