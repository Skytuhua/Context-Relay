-- A source first introduced by transactional setup is eligible for removal
-- after its final applied setup plan rolls back. Preexisting ledgers are never
-- inserted here and therefore remain outside setup ownership.
CREATE TABLE setup_native_memory_managed_sources (
    source_id TEXT PRIMARY KEY
        REFERENCES native_memory_sources(source_id) ON DELETE CASCADE
        CHECK (length(source_id) = 64)
);

-- Every successfully applied setup plan owns an exact reference to each
-- descriptor in its sealed binding. Shared descriptors survive until the last
-- applied owner rolls back.
CREATE TABLE setup_native_memory_source_refs (
    plan_id TEXT NOT NULL
        REFERENCES setup_plan_lifecycle(plan_id) ON DELETE RESTRICT,
    source_id TEXT NOT NULL
        REFERENCES native_memory_sources(source_id) ON DELETE CASCADE
        CHECK (length(source_id) = 64),
    PRIMARY KEY (plan_id, source_id)
);

CREATE INDEX setup_native_memory_source_refs_source_idx
    ON setup_native_memory_source_refs(source_id);
