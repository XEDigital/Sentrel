-- +goose Up
-- Optional extras for status pages. The defaults keep an existing page exactly
-- as it was: the standard icon, the list layout and no graphs.
ALTER TABLE status_pages ADD COLUMN icon TEXT NOT NULL DEFAULT '';           -- '', 'preset:<name>' or a data:image URL
ALTER TABLE status_pages ADD COLUMN layout TEXT NOT NULL DEFAULT 'list';     -- list | wall
ALTER TABLE status_pages ADD COLUMN show_overview INTEGER NOT NULL DEFAULT 0; -- combined graphs for the hosts on the page

-- +goose Down
ALTER TABLE status_pages DROP COLUMN show_overview;
ALTER TABLE status_pages DROP COLUMN layout;
ALTER TABLE status_pages DROP COLUMN icon;
