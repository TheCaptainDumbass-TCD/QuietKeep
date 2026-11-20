-- Release tracking from registry checks.
ALTER TABLE containers ADD COLUMN update_kind TEXT;
ALTER TABLE containers ADD COLUMN latest_tag TEXT;
ALTER TABLE containers ADD COLUMN major_tag TEXT;
