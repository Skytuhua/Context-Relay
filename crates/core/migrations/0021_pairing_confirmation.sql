ALTER TABLE pairing_joins ADD COLUMN issuer_certificate_id TEXT
    REFERENCES device_certificates(certificate_id);

CREATE TABLE pairing_approval_transcripts (
    pairing_id TEXT PRIMARY KEY NOT NULL CHECK (
        length(pairing_id) = 36
        AND substr(pairing_id, 9, 1) = '-'
        AND substr(pairing_id, 14, 1) = '-'
        AND substr(pairing_id, 15, 1) = '7'
        AND substr(pairing_id, 19, 1) = '-'
        AND substr(pairing_id, 24, 1) = '-'
    ),
    role TEXT NOT NULL CHECK (role IN ('approver', 'joiner')),
    state TEXT NOT NULL CHECK (
        state IN ('prepared', 'accepted', 'awaiting_confirmation', 'completed', 'legacy_unconfirmed')
    ),
    canonical_request BLOB,
    request_sha256 BLOB CHECK (
        request_sha256 IS NULL OR length(request_sha256) = 32
    ),
    canonical_approved_payload BLOB,
    approved_payload_sha256 BLOB CHECK (
        approved_payload_sha256 IS NULL OR length(approved_payload_sha256) = 32
    ),
    transcript_sha256 BLOB CHECK (
        transcript_sha256 IS NULL OR length(transcript_sha256) = 32
    ),
    issuer_certificate_id TEXT CHECK (
        issuer_certificate_id IS NULL OR (
            length(issuer_certificate_id) = 36
            AND substr(issuer_certificate_id, 9, 1) = '-'
            AND substr(issuer_certificate_id, 14, 1) = '-'
            AND substr(issuer_certificate_id, 15, 1) = '7'
            AND substr(issuer_certificate_id, 19, 1) = '-'
            AND substr(issuer_certificate_id, 24, 1) = '-'
        )
    ),
    account_id TEXT,
    workspace_id TEXT,
    control_epoch INTEGER CHECK (control_epoch IS NULL OR control_epoch > 0),
    key_epoch INTEGER CHECK (key_epoch IS NULL OR key_epoch > 0),
    stored_at_ms INTEGER NOT NULL CHECK (stored_at_ms >= 0),
    transitioned_at_ms INTEGER CHECK (transitioned_at_ms IS NULL OR transitioned_at_ms >= 0),
    CHECK (
        (state = 'legacy_unconfirmed'
            AND canonical_request IS NULL
            AND request_sha256 IS NULL
            AND canonical_approved_payload IS NULL
            AND approved_payload_sha256 IS NULL
            AND transcript_sha256 IS NULL
            AND issuer_certificate_id IS NULL
            AND account_id IS NULL
            AND workspace_id IS NULL
            AND control_epoch IS NULL
            AND key_epoch IS NULL
            AND transitioned_at_ms IS NULL)
        OR
        (role = 'approver'
            AND state IN ('prepared', 'accepted')
            AND canonical_request IS NOT NULL
            AND length(canonical_request) > 0
            AND request_sha256 IS NOT NULL
            AND canonical_approved_payload IS NOT NULL
            AND length(canonical_approved_payload) > 0
            AND approved_payload_sha256 IS NOT NULL
            AND transcript_sha256 IS NOT NULL
            AND issuer_certificate_id IS NOT NULL
            AND account_id IS NOT NULL
            AND workspace_id IS NOT NULL
            AND control_epoch IS NOT NULL
            AND key_epoch IS NOT NULL
            AND ((state = 'prepared' AND transitioned_at_ms IS NULL)
                OR (state = 'accepted' AND transitioned_at_ms IS NOT NULL)))
        OR
        (role = 'joiner'
            AND state IN ('awaiting_confirmation', 'completed')
            AND canonical_request IS NOT NULL
            AND length(canonical_request) > 0
            AND request_sha256 IS NOT NULL
            AND canonical_approved_payload IS NOT NULL
            AND length(canonical_approved_payload) > 0
            AND approved_payload_sha256 IS NOT NULL
            AND transcript_sha256 IS NOT NULL
            AND issuer_certificate_id IS NOT NULL
            AND account_id IS NOT NULL
            AND workspace_id IS NOT NULL
            AND control_epoch IS NOT NULL
            AND key_epoch IS NOT NULL
            AND ((state = 'awaiting_confirmation' AND transitioned_at_ms IS NULL)
                OR (state = 'completed' AND transitioned_at_ms IS NOT NULL)))
    )
);

CREATE INDEX pairing_approval_transcripts_state_idx
    ON pairing_approval_transcripts(role, state, pairing_id);

INSERT INTO pairing_approval_transcripts(
    pairing_id, role, state, stored_at_ms
)
SELECT
    pairing_id,
    'approver',
    'legacy_unconfirmed',
    COALESCE(prepared_at_ms, finished_at_ms, 0)
FROM pairing_decisions;

INSERT INTO pairing_approval_transcripts(
    pairing_id, role, state, stored_at_ms
)
SELECT
    pairing_id,
    'joiner',
    'legacy_unconfirmed',
    stored_at_ms
FROM pairing_joins;
