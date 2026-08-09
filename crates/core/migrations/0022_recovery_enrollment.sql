CREATE TABLE recovery_enrollments (
    enrollment_id TEXT PRIMARY KEY NOT NULL CHECK (
        length(enrollment_id) = 36
        AND substr(enrollment_id, 9, 1) = '-'
        AND substr(enrollment_id, 14, 1) = '-'
        AND substr(enrollment_id, 15, 1) = '7'
        AND substr(enrollment_id, 19, 1) = '-'
        AND substr(enrollment_id, 24, 1) = '-'
    ),
    recovery_root_id TEXT NOT NULL UNIQUE CHECK (
        length(recovery_root_id) = 36
        AND substr(recovery_root_id, 9, 1) = '-'
        AND substr(recovery_root_id, 14, 1) = '-'
        AND substr(recovery_root_id, 15, 1) = '7'
        AND substr(recovery_root_id, 19, 1) = '-'
        AND substr(recovery_root_id, 24, 1) = '-'
    ),
    account_id TEXT NOT NULL UNIQUE CHECK (
        length(account_id) = 36
        AND substr(account_id, 9, 1) = '-'
        AND substr(account_id, 14, 1) = '-'
        AND substr(account_id, 15, 1) = '7'
        AND substr(account_id, 19, 1) = '-'
        AND substr(account_id, 24, 1) = '-'
    ),
    workspace_id TEXT NOT NULL UNIQUE CHECK (
        length(workspace_id) = 36
        AND substr(workspace_id, 9, 1) = '-'
        AND substr(workspace_id, 14, 1) = '-'
        AND substr(workspace_id, 15, 1) = '7'
        AND substr(workspace_id, 19, 1) = '-'
        AND substr(workspace_id, 24, 1) = '-'
    ),
    device_id TEXT NOT NULL UNIQUE CHECK (
        length(device_id) = 36
        AND substr(device_id, 9, 1) = '-'
        AND substr(device_id, 14, 1) = '-'
        AND substr(device_id, 15, 1) = '7'
        AND substr(device_id, 19, 1) = '-'
        AND substr(device_id, 24, 1) = '-'
    ),
    genesis_certificate_id TEXT NOT NULL CHECK (
        length(genesis_certificate_id) = 36
        AND substr(genesis_certificate_id, 9, 1) = '-'
        AND substr(genesis_certificate_id, 14, 1) = '-'
        AND substr(genesis_certificate_id, 15, 1) = '7'
        AND substr(genesis_certificate_id, 19, 1) = '-'
        AND substr(genesis_certificate_id, 24, 1) = '-'
    ),
    activated_certificate_id TEXT REFERENCES device_certificates(certificate_id) CHECK (
        activated_certificate_id IS NULL OR (
            length(activated_certificate_id) = 36
            AND substr(activated_certificate_id, 9, 1) = '-'
            AND substr(activated_certificate_id, 14, 1) = '-'
            AND substr(activated_certificate_id, 15, 1) = '7'
            AND substr(activated_certificate_id, 19, 1) = '-'
            AND substr(activated_certificate_id, 24, 1) = '-'
        )
    ),
    recovery_signing_public_key BLOB NOT NULL CHECK (length(recovery_signing_public_key) = 32),
    recovery_wrapping_public_key BLOB NOT NULL CHECK (length(recovery_wrapping_public_key) = 32),
    device_signing_public_key BLOB NOT NULL CHECK (length(device_signing_public_key) = 32),
    device_wrapping_public_key BLOB NOT NULL CHECK (length(device_wrapping_public_key) = 32),
    device_name TEXT NOT NULL CHECK (length(device_name) BETWEEN 1 AND 256),
    platform TEXT NOT NULL CHECK (platform IN ('windows', 'macos')),
    control_epoch INTEGER NOT NULL CHECK (control_epoch = 1),
    key_epoch INTEGER NOT NULL CHECK (key_epoch = 1),
    canonical_record BLOB NOT NULL CHECK (length(canonical_record) > 0),
    canonical_record_sha256 BLOB NOT NULL CHECK (length(canonical_record_sha256) = 32),
    device_material_envelope BLOB NOT NULL CHECK (length(device_material_envelope) > 0),
    device_envelope_sha256 BLOB NOT NULL CHECK (length(device_envelope_sha256) = 32),
    state TEXT NOT NULL CHECK (state IN ('prepared', 'active', 'conflict')),
    prepared_at_ms INTEGER NOT NULL CHECK (prepared_at_ms >= 0),
    provider_accepted_at_ms INTEGER CHECK (
        provider_accepted_at_ms IS NULL OR provider_accepted_at_ms >= 0
    ),
    completed_at_ms INTEGER CHECK (completed_at_ms IS NULL OR completed_at_ms >= 0),
    conflict_at_ms INTEGER CHECK (conflict_at_ms IS NULL OR conflict_at_ms >= 0),
    CHECK (
        (state = 'prepared'
            AND activated_certificate_id IS NULL
            AND provider_accepted_at_ms IS NULL
            AND completed_at_ms IS NULL
            AND conflict_at_ms IS NULL)
        OR
        (state = 'active'
            AND activated_certificate_id = genesis_certificate_id
            AND provider_accepted_at_ms >= prepared_at_ms
            AND completed_at_ms >= provider_accepted_at_ms
            AND conflict_at_ms IS NULL)
        OR
        (state = 'conflict'
            AND activated_certificate_id IS NULL
            AND provider_accepted_at_ms IS NULL
            AND completed_at_ms IS NULL
            AND conflict_at_ms >= prepared_at_ms)
    )
);
