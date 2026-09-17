CREATE TABLE hosted_enrollment_intent (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    payload BLOB NOT NULL CHECK (length(payload) BETWEEN 1 AND 8192)
);
