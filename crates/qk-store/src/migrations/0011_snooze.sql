CREATE TABLE docker_snoozes (
    host_id   INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    container TEXT NOT NULL,
    major_tag TEXT NOT NULL,
    PRIMARY KEY (host_id, container)
);
