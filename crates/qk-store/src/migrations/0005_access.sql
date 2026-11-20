-- Whether QuietKeep's own key last logged in to the host successfully.
ALTER TABLE hosts ADD COLUMN access_ok INTEGER NOT NULL DEFAULT 0;
