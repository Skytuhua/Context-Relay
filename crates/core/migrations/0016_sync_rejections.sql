CREATE TABLE sync_rejections (
    account_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    provider TEXT NOT NULL CHECK (provider IN ('memory', 'supabase')),
    received_at TEXT NOT NULL,
    receipt_operation_id TEXT NOT NULL,
    routed_operation_id TEXT NOT NULL CHECK (routed_operation_id = receipt_operation_id),
    device_id TEXT NOT NULL,
    device_sequence TEXT NOT NULL,
    safe_error_code TEXT NOT NULL CHECK (safe_error_code = 'integrity_quarantined'),
    claimed_byte_length INTEGER NOT NULL CHECK (claimed_byte_length > 5242880),
    received_sha256 BLOB NOT NULL CHECK (length(received_sha256) = 32),
    rejected_at_ms INTEGER NOT NULL CHECK (rejected_at_ms >= 0),
    PRIMARY KEY (
        account_id,
        workspace_id,
        provider,
        received_at,
        receipt_operation_id
    )
);

CREATE INDEX sync_rejections_device_sequence_idx
    ON sync_rejections(
        account_id,
        workspace_id,
        provider,
        device_id,
        device_sequence
    );
