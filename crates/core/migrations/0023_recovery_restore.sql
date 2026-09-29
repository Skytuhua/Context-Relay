CREATE TABLE recovery_restores (
    restore_id TEXT PRIMARY KEY NOT NULL CHECK (
        length(restore_id) = 36 AND substr(restore_id, 9, 1) = '-'
        AND substr(restore_id, 14, 1) = '-' AND substr(restore_id, 15, 1) = '7'
        AND substr(restore_id, 19, 1) = '-' AND substr(restore_id, 24, 1) = '-'
    ),
    enrollment_id TEXT NOT NULL UNIQUE CHECK (
        length(enrollment_id) = 36 AND substr(enrollment_id, 9, 1) = '-'
        AND substr(enrollment_id, 14, 1) = '-' AND substr(enrollment_id, 15, 1) = '7'
        AND substr(enrollment_id, 19, 1) = '-' AND substr(enrollment_id, 24, 1) = '-'
    ),
    recovery_root_id TEXT NOT NULL UNIQUE CHECK (
        length(recovery_root_id) = 36 AND substr(recovery_root_id, 9, 1) = '-'
        AND substr(recovery_root_id, 14, 1) = '-' AND substr(recovery_root_id, 15, 1) = '7'
        AND substr(recovery_root_id, 19, 1) = '-' AND substr(recovery_root_id, 24, 1) = '-'
    ),
    account_id TEXT NOT NULL UNIQUE CHECK (
        length(account_id) = 36 AND substr(account_id, 9, 1) = '-'
        AND substr(account_id, 14, 1) = '-' AND substr(account_id, 15, 1) = '7'
        AND substr(account_id, 19, 1) = '-' AND substr(account_id, 24, 1) = '-'
    ),
    workspace_id TEXT NOT NULL UNIQUE CHECK (
        length(workspace_id) = 36 AND substr(workspace_id, 9, 1) = '-'
        AND substr(workspace_id, 14, 1) = '-' AND substr(workspace_id, 15, 1) = '7'
        AND substr(workspace_id, 19, 1) = '-' AND substr(workspace_id, 24, 1) = '-'
    ),
    genesis_device_id TEXT NOT NULL UNIQUE CHECK (
        length(genesis_device_id) = 36 AND substr(genesis_device_id, 9, 1) = '-'
        AND substr(genesis_device_id, 14, 1) = '-' AND substr(genesis_device_id, 15, 1) = '7'
        AND substr(genesis_device_id, 19, 1) = '-' AND substr(genesis_device_id, 24, 1) = '-'
    ),
    genesis_certificate_id TEXT NOT NULL UNIQUE CHECK (
        length(genesis_certificate_id) = 36 AND substr(genesis_certificate_id, 9, 1) = '-'
        AND substr(genesis_certificate_id, 14, 1) = '-'
        AND substr(genesis_certificate_id, 15, 1) = '7'
        AND substr(genesis_certificate_id, 19, 1) = '-'
        AND substr(genesis_certificate_id, 24, 1) = '-'
    ),
    recovered_device_id TEXT NOT NULL UNIQUE CHECK (
        length(recovered_device_id) = 36 AND substr(recovered_device_id, 9, 1) = '-'
        AND substr(recovered_device_id, 14, 1) = '-'
        AND substr(recovered_device_id, 15, 1) = '7'
        AND substr(recovered_device_id, 19, 1) = '-'
        AND substr(recovered_device_id, 24, 1) = '-'
    ),
    recovered_certificate_id TEXT NOT NULL UNIQUE CHECK (
        length(recovered_certificate_id) = 36
        AND substr(recovered_certificate_id, 9, 1) = '-'
        AND substr(recovered_certificate_id, 14, 1) = '-'
        AND substr(recovered_certificate_id, 15, 1) = '7'
        AND substr(recovered_certificate_id, 19, 1) = '-'
        AND substr(recovered_certificate_id, 24, 1) = '-'
    ),
    activated_genesis_certificate_id TEXT REFERENCES device_certificates(certificate_id),
    activated_recovered_certificate_id TEXT REFERENCES device_certificates(certificate_id),
    recovery_signing_public_key BLOB NOT NULL CHECK (length(recovery_signing_public_key) = 32),
    recovery_wrapping_public_key BLOB NOT NULL CHECK (length(recovery_wrapping_public_key) = 32),
    genesis_signing_public_key BLOB NOT NULL CHECK (length(genesis_signing_public_key) = 32),
    genesis_wrapping_public_key BLOB NOT NULL CHECK (length(genesis_wrapping_public_key) = 32),
    recovered_signing_public_key BLOB NOT NULL CHECK (length(recovered_signing_public_key) = 32),
    recovered_wrapping_public_key BLOB NOT NULL CHECK (length(recovered_wrapping_public_key) = 32),
    genesis_device_name TEXT NOT NULL CHECK (length(genesis_device_name) BETWEEN 1 AND 256),
    genesis_platform TEXT NOT NULL CHECK (genesis_platform IN ('windows', 'macos')),
    recovered_device_name TEXT NOT NULL CHECK (length(recovered_device_name) BETWEEN 1 AND 256),
    recovered_platform TEXT NOT NULL CHECK (recovered_platform IN ('windows', 'macos')),
    control_epoch INTEGER NOT NULL CHECK (control_epoch > 0),
    key_epoch INTEGER NOT NULL CHECK (key_epoch > 0),
    expected_generation INTEGER NOT NULL CHECK (
        expected_generation >= 0 AND expected_generation < 9223372036854775807
    ),
    accepted_generation INTEGER CHECK (
        accepted_generation IS NULL OR accepted_generation > 0
    ),
    canonical_record BLOB NOT NULL CHECK (length(canonical_record) BETWEEN 1 AND 32768),
    canonical_record_sha256 BLOB NOT NULL CHECK (length(canonical_record_sha256) = 32),
    canonical_claim BLOB NOT NULL CHECK (length(canonical_claim) BETWEEN 1 AND 32768),
    canonical_claim_sha256 BLOB NOT NULL CHECK (length(canonical_claim_sha256) = 32),
    state TEXT NOT NULL CHECK (state IN ('prepared', 'active', 'conflict')),
    prepared_at_ms INTEGER NOT NULL CHECK (prepared_at_ms >= 0),
    provider_accepted_at_ms INTEGER CHECK (
        provider_accepted_at_ms IS NULL OR provider_accepted_at_ms >= 0
    ),
    completed_at_ms INTEGER CHECK (completed_at_ms IS NULL OR completed_at_ms >= 0),
    conflict_at_ms INTEGER CHECK (conflict_at_ms IS NULL OR conflict_at_ms >= 0),
    CHECK (
        (state = 'prepared'
            AND accepted_generation IS NULL
            AND activated_genesis_certificate_id IS NULL
            AND activated_recovered_certificate_id IS NULL
            AND provider_accepted_at_ms IS NULL
            AND completed_at_ms IS NULL
            AND conflict_at_ms IS NULL)
        OR
        (state = 'active'
            AND accepted_generation = expected_generation + 1
            AND activated_genesis_certificate_id = genesis_certificate_id
            AND activated_recovered_certificate_id = recovered_certificate_id
            AND provider_accepted_at_ms >= prepared_at_ms
            AND completed_at_ms >= provider_accepted_at_ms
            AND conflict_at_ms IS NULL)
        OR
        (state = 'conflict'
            AND accepted_generation IS NULL
            AND activated_genesis_certificate_id IS NULL
            AND activated_recovered_certificate_id IS NULL
            AND provider_accepted_at_ms IS NULL
            AND completed_at_ms IS NULL
            AND conflict_at_ms >= prepared_at_ms)
    )
);
