CREATE TABLE metrics (
    host_id       INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    at            INTEGER NOT NULL,
    load1         REAL NOT NULL,
    cpus          INTEGER NOT NULL,
    mem_used_pct  REAL NOT NULL,
    disk_used_pct REAL NOT NULL,
    uptime_s      INTEGER NOT NULL,
    PRIMARY KEY (host_id, at)
);

ALTER TABLE hosts ADD COLUMN kernel TEXT;
ALTER TABLE hosts ADD COLUMN os_name TEXT;
