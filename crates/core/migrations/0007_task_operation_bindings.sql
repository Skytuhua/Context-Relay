ALTER TABLE local_operation_results RENAME TO local_operation_results_v6;
ALTER TABLE local_operation_bindings RENAME TO local_operation_bindings_v6;

CREATE TABLE local_operation_bindings (
    operation_id TEXT PRIMARY KEY,
    operation_kind TEXT NOT NULL CHECK (
        operation_kind IN (
            'memory_create',
            'memory_proposal',
            'memory_update',
            'memory_archive',
            'task_upsert',
            'task_complete'
        )
    ),
    target_id TEXT NOT NULL,
    expected_revision TEXT,
    canonical_payload BLOB NOT NULL
);

CREATE TABLE local_operation_results (
    operation_id TEXT PRIMARY KEY
        REFERENCES local_operation_bindings(operation_id) ON DELETE CASCADE,
    canonical_response BLOB NOT NULL CHECK (length(canonical_response) > 0)
);

INSERT INTO local_operation_bindings(
    operation_id, operation_kind, target_id, expected_revision, canonical_payload
)
SELECT operation_id, operation_kind, target_id, expected_revision, canonical_payload
FROM local_operation_bindings_v6;

INSERT INTO local_operation_results(operation_id, canonical_response)
SELECT operation_id, canonical_response
FROM local_operation_results_v6;

DROP TABLE local_operation_results_v6;
DROP TABLE local_operation_bindings_v6;
