CREATE TABLE host_packages (
    host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name    TEXT NOT NULL,
    version TEXT NOT NULL,
    PRIMARY KEY (host_id, name)
);
