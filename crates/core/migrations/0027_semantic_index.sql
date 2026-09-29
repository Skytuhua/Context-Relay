-- Derived local search data stays inside SQLCipher and outside sync operations.
ALTER TABLE search_documents ADD COLUMN tags TEXT NOT NULL DEFAULT '';
ALTER TABLE search_documents ADD COLUMN input_digest BLOB
    CHECK (input_digest IS NULL OR length(input_digest) = 32);

CREATE TABLE semantic_embeddings (
    record_id TEXT PRIMARY KEY NOT NULL REFERENCES search_documents(record_id) ON DELETE CASCADE,
    model_fingerprint BLOB NOT NULL CHECK (length(model_fingerprint) = 32),
    input_digest BLOB NOT NULL CHECK (length(input_digest) = 32),
    vector BLOB NOT NULL CHECK (length(vector) = 1536)
);

CREATE TABLE semantic_index_queue (
    record_id TEXT PRIMARY KEY NOT NULL REFERENCES search_documents(record_id) ON DELETE CASCADE
);
CREATE TABLE semantic_index_model (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    fingerprint BLOB NOT NULL CHECK(length(fingerprint) = 32)
);

CREATE TRIGGER semantic_document_insert AFTER INSERT ON search_documents
WHEN new.approved=1 AND new.archived=0 BEGIN
    INSERT INTO semantic_index_queue VALUES(new.record_id) ON CONFLICT(record_id) DO NOTHING;
END;
CREATE TRIGGER semantic_document_update AFTER UPDATE OF input_digest, approved, archived ON search_documents
WHEN old.input_digest IS NOT new.input_digest OR old.approved != new.approved OR old.archived != new.archived BEGIN
    DELETE FROM semantic_index_queue WHERE record_id=new.record_id AND (new.approved != 1 OR new.archived != 0);
    INSERT INTO semantic_index_queue
        SELECT new.record_id WHERE new.approved=1 AND new.archived=0
        ON CONFLICT(record_id) DO NOTHING;
END;
CREATE TRIGGER semantic_vector_insert AFTER INSERT ON semantic_embeddings BEGIN
    INSERT INTO semantic_index_queue
        SELECT record_id FROM search_documents WHERE record_id=new.record_id AND approved=1 AND archived=0
        ON CONFLICT(record_id) DO NOTHING;
END;
CREATE TRIGGER semantic_vector_update AFTER UPDATE ON semantic_embeddings BEGIN
    INSERT INTO semantic_index_queue
        SELECT record_id FROM search_documents WHERE record_id=new.record_id AND approved=1 AND archived=0
        ON CONFLICT(record_id) DO NOTHING;
END;
CREATE TRIGGER semantic_vector_delete AFTER DELETE ON semantic_embeddings BEGIN
    INSERT INTO semantic_index_queue
        SELECT record_id FROM search_documents WHERE record_id=old.record_id AND approved=1 AND archived=0
        ON CONFLICT(record_id) DO NOTHING;
END;
