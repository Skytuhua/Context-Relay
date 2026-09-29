ALTER TABLE native_memory_sources
ADD COLUMN last_applied_managed_digest TEXT CHECK (
    last_applied_managed_digest IS NULL OR length(last_applied_managed_digest) = 64
);
