ALTER TABLE local_operation_results RENAME TO local_operation_results_v7;
ALTER TABLE local_operation_bindings RENAME TO local_operation_bindings_v7;

CREATE TABLE local_operation_bindings (
    operation_id TEXT PRIMARY KEY,
    operation_kind TEXT NOT NULL CHECK (
        operation_kind IN (
            'memory_create',
            'memory_proposal',
            'memory_update',
            'memory_archive',
            'task_upsert',
            'task_complete',
            'task_transition'
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
FROM local_operation_bindings_v7;

INSERT INTO local_operation_results(operation_id, canonical_response)
SELECT operation_id, canonical_response
FROM local_operation_results_v7;

DROP TABLE local_operation_results_v7;
DROP TABLE local_operation_bindings_v7;

ALTER TABLE records ADD COLUMN memory_kind TEXT;
ALTER TABLE records ADD COLUMN updated_physical_sort TEXT;
ALTER TABLE records ADD COLUMN updated_logical INTEGER;
ALTER TABLE records ADD COLUMN updated_node TEXT;

UPDATE records
SET memory_kind = json_extract(CAST(payload_json AS TEXT), '$.kind'),
    updated_physical_sort = substr(
        '00000000000000000000'
            || json_extract(CAST(payload_json AS TEXT), '$.updatedHlc.physicalMs'),
        -20,
        20
    ),
    updated_logical = json_extract(
        CAST(payload_json AS TEXT),
        '$.updatedHlc.logical'
    ),
    updated_node = json_extract(CAST(payload_json AS TEXT), '$.updatedHlc.node')
WHERE kind = 'memory';

CREATE INDEX records_handoff_decisions
ON records(
    project_id,
    memory_kind,
    archived,
    updated_physical_sort DESC,
    updated_logical DESC,
    updated_node DESC,
    id ASC
)
WHERE kind = 'memory';

CREATE INDEX tasks_handoff_active
ON tasks(project_id, id)
WHERE status IN ('open', 'blocked');
