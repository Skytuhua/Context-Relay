CREATE TABLE pairing_v2_transcripts (
    pairing_id TEXT PRIMARY KEY NOT NULL CHECK(length(pairing_id)=36),
    role TEXT NOT NULL CHECK(role IN ('approver','joiner')),
    state TEXT NOT NULL CHECK(state IN ('prepared','accepted','awaiting_confirmation','confirmed','completed')),
    canonical_request BLOB NOT NULL CHECK(length(canonical_request) BETWEEN 1 AND 8192),
    canonical_payload BLOB NOT NULL CHECK(length(canonical_payload) BETWEEN 1 AND 32768),
    membership_signature BLOB NOT NULL CHECK(length(membership_signature)=64),
    confirmation_signature BLOB CHECK(confirmation_signature IS NULL OR length(confirmation_signature)=64),
    stored_at_ms INTEGER NOT NULL CHECK(stored_at_ms>=0),
    CHECK((role='approver' AND state IN ('prepared','accepted') AND confirmation_signature IS NULL)
      OR (role='joiner' AND ((state='awaiting_confirmation' AND confirmation_signature IS NULL)
        OR (state IN ('confirmed','completed') AND confirmation_signature IS NOT NULL))))
);

-- Downloaded public proof is only inventory. It never establishes accepted authority.
CREATE TABLE pairing_v2_public_objects (
    pairing_id TEXT NOT NULL REFERENCES pairing_v2_transcripts(pairing_id),
    kind TEXT NOT NULL CHECK(kind IN ('enrollment','event')),
    address BLOB NOT NULL CHECK(length(address)=32),
    canonical BLOB NOT NULL CHECK(length(canonical) BETWEEN 1 AND 16777216),
    PRIMARY KEY(pairing_id,kind,address)
);
