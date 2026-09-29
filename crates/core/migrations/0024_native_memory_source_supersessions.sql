-- Adapter upgrades produce a new authenticated source id because the adapter
-- version participates in its digest. Keep the predecessor for exact rollback,
-- but expose only the newest descriptor to the watcher.
CREATE TABLE native_memory_source_supersessions (
    prior_source_id TEXT PRIMARY KEY
        REFERENCES native_memory_sources(source_id) ON DELETE RESTRICT
        CHECK (length(prior_source_id) = 64),
    replacement_source_id TEXT NOT NULL UNIQUE
        REFERENCES native_memory_sources(source_id) ON DELETE CASCADE
        CHECK (length(replacement_source_id) = 64),
    setup_plan_id TEXT NOT NULL
        REFERENCES setup_plan_lifecycle(plan_id) ON DELETE RESTRICT,
    CHECK (prior_source_id <> replacement_source_id)
);

CREATE INDEX native_memory_source_supersessions_plan_idx
    ON native_memory_source_supersessions(setup_plan_id);
