CREATE TABLE device_certificates (
    certificate_id TEXT PRIMARY KEY NOT NULL CHECK (
        length(certificate_id) = 36
        AND substr(certificate_id, 9, 1) = '-'
        AND substr(certificate_id, 14, 1) = '-'
        AND substr(certificate_id, 15, 1) = '7'
        AND substr(certificate_id, 19, 1) = '-'
        AND substr(certificate_id, 24, 1) = '-'
    ),
    account_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    device_name TEXT NOT NULL CHECK (length(device_name) BETWEEN 1 AND 256),
    platform TEXT NOT NULL CHECK (platform IN ('windows', 'macos')),
    canonical_bytes BLOB NOT NULL CHECK (length(canonical_bytes) > 0),
    canonical_sha256 BLOB NOT NULL CHECK (length(canonical_sha256) = 32),
    state TEXT NOT NULL CHECK (state IN ('active', 'revoked')),
    stored_at_ms INTEGER NOT NULL CHECK (stored_at_ms >= 0),
    UNIQUE (account_id, workspace_id, device_id)
);

CREATE TABLE pairing_decisions (
    pairing_id TEXT PRIMARY KEY NOT NULL CHECK (
        length(pairing_id) = 36
        AND substr(pairing_id, 9, 1) = '-'
        AND substr(pairing_id, 14, 1) = '-'
        AND substr(pairing_id, 15, 1) = '7'
        AND substr(pairing_id, 19, 1) = '-'
        AND substr(pairing_id, 24, 1) = '-'
    ),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    certificate_id TEXT REFERENCES device_certificates(certificate_id),
    canonical_grant BLOB CHECK (canonical_grant IS NULL OR length(canonical_grant) > 0),
    grant_sha256 BLOB CHECK (grant_sha256 IS NULL OR length(grant_sha256) = 32),
    prepared_at_ms INTEGER,
    finished_at_ms INTEGER,
    state TEXT NOT NULL CHECK (state IN ('prepared', 'accepted', 'rejected')),
    CHECK (
        (state IN ('prepared', 'accepted')
            AND certificate_id IS NOT NULL
            AND canonical_grant IS NOT NULL
            AND grant_sha256 IS NOT NULL
            AND prepared_at_ms IS NOT NULL
            AND ((state = 'prepared' AND finished_at_ms IS NULL)
                OR (state = 'accepted' AND finished_at_ms IS NOT NULL)))
        OR (state = 'rejected'
            AND certificate_id IS NULL
            AND canonical_grant IS NULL
            AND grant_sha256 IS NULL
            AND prepared_at_ms IS NULL
            AND finished_at_ms IS NOT NULL)
    )
);

CREATE TABLE pairing_joins (
    pairing_id TEXT PRIMARY KEY NOT NULL CHECK (
        length(pairing_id) = 36
        AND substr(pairing_id, 9, 1) = '-'
        AND substr(pairing_id, 14, 1) = '-'
        AND substr(pairing_id, 15, 1) = '7'
        AND substr(pairing_id, 19, 1) = '-'
        AND substr(pairing_id, 24, 1) = '-'
    ),
    canonical_request BLOB NOT NULL CHECK (length(canonical_request) > 0),
    request_sha256 BLOB NOT NULL CHECK (length(request_sha256) = 32),
    certificate_id TEXT REFERENCES device_certificates(certificate_id),
    wrapped_key_bundle BLOB CHECK (wrapped_key_bundle IS NULL OR length(wrapped_key_bundle) > 0),
    state TEXT NOT NULL CHECK (state IN ('stored', 'completed')),
    stored_at_ms INTEGER NOT NULL CHECK (stored_at_ms >= 0),
    completed_at_ms INTEGER,
    CHECK (
        (state = 'stored' AND certificate_id IS NULL AND wrapped_key_bundle IS NULL AND completed_at_ms IS NULL)
        OR (state = 'completed' AND certificate_id IS NOT NULL AND wrapped_key_bundle IS NOT NULL AND completed_at_ms IS NOT NULL)
    )
);
