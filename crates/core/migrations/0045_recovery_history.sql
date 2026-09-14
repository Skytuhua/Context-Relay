CREATE TABLE recovery_history_targets (
    target_sha256 BLOB PRIMARY KEY CHECK(length(target_sha256)=32),
    target BLOB NOT NULL CHECK(length(target) BETWEEN 266 AND 512),
    checkpoint BLOB NOT NULL CHECK(length(checkpoint) BETWEEN 1 AND 1048576),
    selection_signature BLOB NOT NULL CHECK(length(selection_signature)=64),
    prefixes BLOB CHECK(length(prefixes)<=67108864 AND length(prefixes)%56=0),
    reconstructed_signature BLOB CHECK(length(reconstructed_signature)=64),
    installed_signature BLOB CHECK(length(installed_signature)=64),
    CHECK((prefixes IS NULL)=(reconstructed_signature IS NULL)),
    CHECK(installed_signature IS NULL OR reconstructed_signature IS NOT NULL)
) STRICT;
CREATE TABLE recovery_history_selection (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    target_sha256 BLOB NOT NULL REFERENCES recovery_history_targets(target_sha256) CHECK(length(target_sha256)=32)
) STRICT;
