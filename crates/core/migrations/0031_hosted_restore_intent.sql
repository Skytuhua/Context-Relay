CREATE TABLE hosted_restore_intent (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    payload BLOB NOT NULL CHECK (length(payload) BETWEEN 1 AND 8192)
);
