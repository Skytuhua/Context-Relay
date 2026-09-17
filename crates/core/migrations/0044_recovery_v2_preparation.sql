-- Prepared recovery is inventory, never accepted membership or installed history.
CREATE TABLE recovery_v2_prepared (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    canonical_record BLOB NOT NULL CHECK(length(canonical_record) BETWEEN 1 AND 32768),
    canonical_claim BLOB NOT NULL CHECK(length(canonical_claim) BETWEEN 1 AND 32768),
    hosted_intent BLOB NOT NULL CHECK(length(hosted_intent)<=8192),
    preparation_signature BLOB NOT NULL CHECK(length(preparation_signature)=64)
);
CREATE TABLE recovery_v2_parent_objects (
    ordinal INTEGER PRIMARY KEY CHECK(ordinal BETWEEN 0 AND 4095),
    canonical BLOB NOT NULL CHECK(length(canonical) BETWEEN 1 AND 16777216)
);
CREATE TABLE recovery_v2_history_keys (
    key_epoch INTEGER PRIMARY KEY CHECK(key_epoch BETWEEN 1 AND 4294967295),
    original_bundle_sha256 BLOB NOT NULL CHECK(length(original_bundle_sha256)=32),
    canonical_envelope BLOB NOT NULL CHECK(length(canonical_envelope) BETWEEN 1 AND 1024),
    signature BLOB NOT NULL CHECK(length(signature)=64)
);
CREATE TABLE recovery_v2_admission (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    canonical_receipt BLOB NOT NULL CHECK(length(canonical_receipt) BETWEEN 1 AND 8192),
    signature BLOB NOT NULL CHECK(length(signature)=64)
);
