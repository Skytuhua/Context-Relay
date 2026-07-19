CREATE TABLE before_images_v2 (
    id TEXT PRIMARY KEY,
    plan_id TEXT,
    created_ms INTEGER NOT NULL,
    payload BLOB NOT NULL
);

INSERT INTO before_images_v2(id, plan_id, created_ms, payload)
SELECT id, receipt_id, created_ms, payload
FROM before_images;

DROP TABLE before_images;
ALTER TABLE before_images_v2 RENAME TO before_images;

CREATE INDEX before_images_plan_idx
    ON before_images(plan_id, created_ms);
