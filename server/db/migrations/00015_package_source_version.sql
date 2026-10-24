-- +goose Up
-- Version of a deb's source package when it differs from the binary version
-- (libldb2 2:2.6.2+samba4.17.12-… is built from samba 2:4.17.12-…). Grype
-- compares source-keyed vulnerability data against it.
ALTER TABLE packages ADD COLUMN source_version TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE packages DROP COLUMN source_version;
