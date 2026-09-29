ALTER TABLE device_revocation_intents
    ADD COLUMN outcome INTEGER NOT NULL DEFAULT 0
        CHECK(typeof(outcome) = 'integer' AND outcome BETWEEN 0 AND 5);
ALTER TABLE device_revocation_intents
    ADD COLUMN send_canceled INTEGER NOT NULL DEFAULT 0
        CHECK(typeof(send_canceled) = 'integer' AND send_canceled IN (0, 1));
ALTER TABLE device_revocation_intents
    ADD COLUMN receipt BLOB
        CHECK(receipt IS NULL OR (typeof(receipt) = 'blob' AND length(receipt) = 149));
