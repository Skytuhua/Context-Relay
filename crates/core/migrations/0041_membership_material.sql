-- No backfill or activation. Private authentication establishes these rows.
CREATE TABLE membership_epoch_secrets (
 device_id TEXT NOT NULL CHECK(length(device_id)=36),
 key_epoch INTEGER NOT NULL CHECK(key_epoch BETWEEN 1 AND 4294967295),
 independent_current INTEGER NOT NULL CHECK(independent_current IN (0,1)),
 source_hash BLOB NOT NULL CHECK(length(source_hash)=32),
 source_control_epoch INTEGER NOT NULL CHECK(source_control_epoch BETWEEN 1 AND 4294967295),
 source_key_epoch INTEGER NOT NULL CHECK(source_key_epoch BETWEEN 1 AND 4294967295),
 provenance BLOB NOT NULL CHECK(length(provenance)=32),
 envelope BLOB NOT NULL CHECK(length(envelope) BETWEEN 1 AND 512),
 signature BLOB NOT NULL CHECK(length(signature)=64),
 PRIMARY KEY(device_id,key_epoch,independent_current)
);
CREATE TABLE membership_confirmed_admission (
 device_id TEXT PRIMARY KEY NOT NULL CHECK(length(device_id)=36),
 successor BLOB NOT NULL CHECK(length(successor)=32),
 transcript_hash BLOB NOT NULL CHECK(length(transcript_hash)=32),
 signature BLOB NOT NULL CHECK(length(signature)=64)
);
-- Presence forbids repairing a missing/corrupt signed root from legacy storage.
CREATE TABLE membership_root_material_seed (
 device_id TEXT PRIMARY KEY NOT NULL CHECK(length(device_id)=36)
);
CREATE TABLE historical_transfers (
 transfer_id TEXT PRIMARY KEY NOT NULL CHECK(length(transfer_id)=36),
 header BLOB NOT NULL CHECK(length(header)=387),
 checkpoint BLOB NOT NULL CHECK(length(checkpoint) BETWEEN 1 AND 8388608),
 next_index INTEGER NOT NULL CHECK(next_index BETWEEN 0 AND 4294967295),
 next_hash BLOB NOT NULL CHECK(length(next_hash)=32)
);
CREATE TABLE historical_transfer_pages (
 transfer_id TEXT NOT NULL REFERENCES historical_transfers(transfer_id),
 page_index INTEGER NOT NULL CHECK(page_index BETWEEN 0 AND 4294967295),
 ciphertext BLOB NOT NULL CHECK(length(ciphertext) BETWEEN 1 AND 16384),
 PRIMARY KEY(transfer_id,page_index)
);
CREATE TABLE historical_transfer_selection (
 device_id TEXT PRIMARY KEY NOT NULL CHECK(length(device_id)=36),
 transfer_id TEXT NOT NULL REFERENCES historical_transfers(transfer_id),
 revision INTEGER NOT NULL CHECK(revision>0)
);
CREATE TABLE membership_current_activation (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 device_id TEXT NOT NULL CHECK(length(device_id)=36),
 source_hash BLOB NOT NULL CHECK(length(source_hash)=32),
 control_epoch INTEGER NOT NULL CHECK(control_epoch BETWEEN 1 AND 4294967295),
 key_epoch INTEGER NOT NULL CHECK(key_epoch BETWEEN 1 AND 4294967295),
 signature BLOB NOT NULL CHECK(length(signature)=64)
);
-- Repair evidence has no selected-target or completion authority.
CREATE TABLE historical_operation_evidence (
 operation_id TEXT PRIMARY KEY CHECK(length(operation_id)=36),
 device_id TEXT NOT NULL CHECK(length(device_id)=36),
 device_sequence TEXT NOT NULL,
 canonical BLOB NOT NULL CHECK(length(canonical) BETWEEN 1 AND 8388608),
 UNIQUE(device_id,device_sequence)
);
-- Only exact reconstruction/cutoff verification pins a branch here.
CREATE TABLE historical_verified_operations (
 operation_id TEXT PRIMARY KEY CHECK(length(operation_id)=36),
 device_id TEXT NOT NULL CHECK(length(device_id)=36),
 device_sequence TEXT NOT NULL,
 canonical BLOB NOT NULL CHECK(length(canonical) BETWEEN 1 AND 8388608),
 UNIQUE(device_id,device_sequence)
);
CREATE TABLE historical_reconstructions (
 transfer_id TEXT PRIMARY KEY REFERENCES historical_transfers(transfer_id),
 prefixes BLOB NOT NULL,
 signature BLOB NOT NULL CHECK(length(signature)=64),
 installed_signature BLOB CHECK(installed_signature IS NULL OR length(installed_signature)=64)
);
