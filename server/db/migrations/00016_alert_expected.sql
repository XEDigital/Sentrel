-- +goose Up
-- An alert marked as expected is hidden from the active list and sends no
-- notifications, however often it fires and resolves, until the mark is removed.
ALTER TABLE alerts ADD COLUMN expected INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE alerts DROP COLUMN expected;
