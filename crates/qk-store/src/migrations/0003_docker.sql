CREATE TABLE containers (
    host_id          INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name             TEXT NOT NULL,
    image            TEXT NOT NULL,
    state            TEXT NOT NULL,
    status           TEXT NOT NULL,
    project          TEXT,
    service          TEXT,
    config_file      TEXT,
    update_available INTEGER,
    PRIMARY KEY (host_id, name)
);

ALTER TABLE hosts ADD COLUMN docker_scan_at INTEGER;
ALTER TABLE hosts ADD COLUMN docker_error TEXT;
