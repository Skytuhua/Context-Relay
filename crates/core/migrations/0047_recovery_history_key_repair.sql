CREATE TABLE recovery_v2_supplemental_history_keys (
    key_epoch INTEGER PRIMARY KEY CHECK(key_epoch BETWEEN 1 AND 4294967295),
    original_bundle_sha256 BLOB NOT NULL CHECK(length(original_bundle_sha256)=32),
    canonical_envelope BLOB NOT NULL CHECK(length(canonical_envelope) BETWEEN 1 AND 1024),
    signature BLOB NOT NULL CHECK(length(signature)=64)
);
