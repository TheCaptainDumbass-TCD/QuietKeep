ALTER TABLE host_packages ADD COLUMN source_name TEXT;
ALTER TABLE host_packages ADD COLUMN source_version TEXT;
ALTER TABLE hosts ADD COLUMN os_id TEXT;
ALTER TABLE hosts ADD COLUMN os_version TEXT;
