CREATE TABLE hosts (
    id              INTEGER PRIMARY KEY,
    name            TEXT NOT NULL COLLATE NOCASE UNIQUE,
    address         TEXT NOT NULL,
    username        TEXT NOT NULL,
    os_type         TEXT NOT NULL CHECK (os_type IN ('apt', 'kali', 'pacman', 'proxmox')),
    is_patch_target INTEGER NOT NULL DEFAULT 1,
    has_docker      INTEGER NOT NULL DEFAULT 0,
    host_key        TEXT,
    created_at      INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at      INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE activity_log (
    id         INTEGER PRIMARY KEY,
    at         INTEGER NOT NULL DEFAULT (unixepoch()),
    kind       TEXT NOT NULL,
    host_id    INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
    message    TEXT NOT NULL
);
CREATE INDEX activity_log_at ON activity_log(at DESC);

CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
