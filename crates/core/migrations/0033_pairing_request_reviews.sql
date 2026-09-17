CREATE TABLE pairing_request_reviews (
    pairing_id TEXT PRIMARY KEY NOT NULL,
    account_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    canonical_request BLOB NOT NULL CHECK(length(canonical_request) BETWEEN 1 AND 8192),
    request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
    requested_at_ms INTEGER NOT NULL CHECK(requested_at_ms >= 0)
);
