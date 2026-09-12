CREATE TABLE candidate_aliases (
    legacy_id TEXT PRIMARY KEY,
    canonical_id TEXT NOT NULL UNIQUE,
    CHECK (legacy_id <> canonical_id)
);
