-- Why apt upgrade skips this update: 'phasing' or 'kept back'. NULL when it installs normally.
ALTER TABLE pending_updates ADD COLUMN held TEXT;
