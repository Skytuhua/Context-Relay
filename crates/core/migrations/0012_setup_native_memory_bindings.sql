CREATE TABLE setup_native_memory_bindings (
    plan_id TEXT PRIMARY KEY
        REFERENCES setup_plan_lifecycle(plan_id) ON DELETE RESTRICT,
    payload_json BLOB NOT NULL CHECK (length(payload_json) > 0)
);

-- Plans finalized before this binding existed had no native-memory
-- registrations. Binding them to the exact empty set prevents a later replay
-- from attaching new descriptors to an already-approved plan.
INSERT INTO setup_native_memory_bindings(plan_id, payload_json)
SELECT plan_id, CAST('[]' AS BLOB)
FROM setup_plan_lifecycle;
