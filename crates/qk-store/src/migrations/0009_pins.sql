-- Values needed to move a digest pin: the exact configured image and the tag's newest digest.
ALTER TABLE containers ADD COLUMN configured_image TEXT;
ALTER TABLE containers ADD COLUMN latest_digest TEXT;
