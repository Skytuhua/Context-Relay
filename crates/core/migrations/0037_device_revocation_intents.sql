CREATE TABLE device_revocation_intents (
    operation_id TEXT PRIMARY KEY NOT NULL CHECK (typeof(operation_id) = 'text' AND length(CAST(operation_id AS BLOB)) = 36),
    project_url TEXT NOT NULL CHECK (typeof(project_url) = 'text' AND length(CAST(project_url AS BLOB)) BETWEEN 1 AND 2048),
    user_id TEXT NOT NULL CHECK (typeof(user_id) = 'text' AND length(CAST(user_id AS BLOB)) = 36),
    session_id TEXT NOT NULL CHECK (typeof(session_id) = 'text' AND length(CAST(session_id AS BLOB)) = 36),
    issuer_certificate BLOB NOT NULL CHECK (length(issuer_certificate) BETWEEN 1 AND 512),
    statement BLOB NOT NULL CHECK (length(statement) = 197),
    transition BLOB NOT NULL CHECK (length(transition) BETWEEN 1 AND 8388608),
    signature BLOB NOT NULL CHECK (length(signature) = 64)
);
