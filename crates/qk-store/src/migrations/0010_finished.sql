-- When a stopped container stopped (unix time), used to age rollback copies.
ALTER TABLE containers ADD COLUMN finished_at INTEGER;
