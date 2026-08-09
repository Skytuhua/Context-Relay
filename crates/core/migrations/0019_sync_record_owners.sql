CREATE TABLE sync_record_owners (
    record_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    binding_state TEXT NOT NULL CHECK (binding_state IN ('verified', 'legacy_pending')),
    record_kind TEXT NOT NULL CHECK (
        record_kind IN (
            'memory', 'memory_candidate', 'task', 'secret_ref',
            'instruction', 'component', 'project'
        )
    )
);

INSERT INTO sync_record_owners(
    record_id, account_id, workspace_id, binding_state, record_kind
)
SELECT DISTINCT
    heads.record_id, meta.account_id, meta.workspace_id, 'legacy_pending', heads.record_kind
FROM sync_record_heads AS heads
JOIN sync_operation_meta AS meta ON meta.operation_id = heads.operation_id;
