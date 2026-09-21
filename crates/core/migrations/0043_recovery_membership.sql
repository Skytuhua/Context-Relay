-- Preserve every accepted row and ordinal while adding explicit recovery events.
ALTER TABLE membership_events RENAME TO membership_events_v42;
CREATE TABLE membership_events (
 successor BLOB PRIMARY KEY NOT NULL CHECK(length(successor)=32),
 parent BLOB NOT NULL UNIQUE CHECK(length(parent)=32),
 ordinal INTEGER NOT NULL UNIQUE CHECK(ordinal>=0),
 kind INTEGER NOT NULL CHECK(kind IN (1,2,3)),
 statement BLOB NOT NULL CHECK((kind IN (1,2) AND length(statement) BETWEEN 1 AND 512) OR (kind=3 AND length(statement)=0)),
 signature BLOB NOT NULL CHECK(length(signature)=64),
 request BLOB NOT NULL CHECK(length(request)<=8388608 AND (kind=1 OR length(request)=0)),
 artifact BLOB NOT NULL CHECK(length(artifact) BETWEEN 1 AND 8388608 AND (kind<>3 OR length(artifact)<=32768))
);
INSERT INTO membership_events SELECT * FROM membership_events_v42;
DROP TABLE membership_events_v42;
