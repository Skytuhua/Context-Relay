-- No backfill: acceptance is established only at authenticated enrollment/admission.
CREATE TABLE accepted_membership (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 account_id TEXT NOT NULL CHECK(length(CAST(account_id AS BLOB))=36),
 workspace_id TEXT NOT NULL CHECK(length(CAST(workspace_id AS BLOB))=36),
 enrollment_pin BLOB NOT NULL CHECK(length(enrollment_pin)=32),
 enrollment BLOB NOT NULL CHECK(length(enrollment) BETWEEN 1 AND 8388608),
 state_hash BLOB NOT NULL CHECK(length(state_hash)=32),
 control_epoch INTEGER NOT NULL CHECK(control_epoch BETWEEN 1 AND 4294967295),
 key_epoch INTEGER NOT NULL CHECK(key_epoch BETWEEN 1 AND 4294967295)
);
CREATE TABLE membership_events (
 successor BLOB PRIMARY KEY NOT NULL CHECK(length(successor)=32),
 parent BLOB NOT NULL UNIQUE CHECK(length(parent)=32),
 ordinal INTEGER NOT NULL UNIQUE CHECK(ordinal>=0),
 kind INTEGER NOT NULL CHECK(kind IN (1,2)),
 statement BLOB NOT NULL CHECK(length(statement) BETWEEN 1 AND 512),
 signature BLOB NOT NULL CHECK(length(signature)=64),
 request BLOB NOT NULL CHECK(length(request)<=8388608),
 artifact BLOB NOT NULL CHECK(length(artifact) BETWEEN 1 AND 8388608)
);
