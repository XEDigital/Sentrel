-- +goose Up
-- A status page can fix its own theme instead of following the viewer's.
ALTER TABLE status_pages ADD COLUMN theme TEXT NOT NULL DEFAULT 'auto'; -- auto | light | dark

-- +goose Down
ALTER TABLE status_pages DROP COLUMN theme;
