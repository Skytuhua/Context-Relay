-- A recipient-signed local terminal marker; no accepted authority.
CREATE TABLE recovery_v2_conflict (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    reason INTEGER NOT NULL CHECK(reason=1),
    signature BLOB NOT NULL CHECK(length(signature)=64)
) STRICT;
