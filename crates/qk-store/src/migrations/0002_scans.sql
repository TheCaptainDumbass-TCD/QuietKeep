ALTER TABLE hosts ADD COLUMN last_scan_at INTEGER;
ALTER TABLE hosts ADD COLUMN reboot_required INTEGER NOT NULL DEFAULT 0;
ALTER TABLE hosts ADD COLUMN scan_error TEXT;

CREATE TABLE pending_updates (
    host_id           INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name              TEXT NOT NULL,
    current_version   TEXT,
    available_version TEXT NOT NULL,
    source            TEXT,
    security          INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (host_id, name)
);
