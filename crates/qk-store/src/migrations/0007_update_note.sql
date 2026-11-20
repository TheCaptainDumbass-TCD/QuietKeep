-- Why an image update could not be determined, or that the image is pinned.
ALTER TABLE containers ADD COLUMN update_note TEXT;
