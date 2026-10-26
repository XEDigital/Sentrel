package app

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func auditArchive(t *testing.T, names ...string) *bytes.Reader {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	for _, name := range names {
		content := []byte("backup-data")
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(b.Bytes())
}

func TestRestoreConfinesArchivePaths(t *testing.T) {
	for _, name := range []string{"../outside", "a/../../outside", "/tmp/outside"} {
		t.Run(name, func(t *testing.T) {
			if err := RestoreBackup(auditArchive(t, name), t.TempDir(), false); err == nil {
				t.Fatal("accepted escaping archive path")
			}
		})
	}
	t.Run("existing directory symlink", func(t *testing.T) {
		dst, outside := t.TempDir(), t.TempDir()
		if err := os.Symlink(outside, filepath.Join(dst, "pki")); err != nil {
			t.Fatal(err)
		}
		if err := RestoreBackup(auditArchive(t, "pki/ca.key", "sentrel.db"), dst, false); err == nil {
			t.Fatal("followed directory symlink outside restore root")
		}
		if _, err := os.Stat(filepath.Join(outside, "ca.key")); !os.IsNotExist(err) {
			t.Fatalf("wrote outside restore root: %v", err)
		}
	})
	t.Run("planted staging symlink", func(t *testing.T) {
		dst, outside := t.TempDir(), t.TempDir()
		victim := filepath.Join(outside, "victim")
		if err := os.WriteFile(victim, []byte("precious"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(victim, filepath.Join(dst, "sentrel.db.restore")); err != nil {
			t.Fatal(err)
		}
		if err := RestoreBackup(auditArchive(t, "sentrel.db", "pki/ca.key"), dst, false); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(victim)
		if err != nil || string(got) != "precious" {
			t.Fatalf("staging symlink target changed: %s %v", got, err)
		}
		st, err := os.Stat(filepath.Join(dst, "pki/ca.key"))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("private key permissions: %v %v", st, err)
		}
		if err := RestoreBackup(auditArchive(t, "sentrel.db"), dst, false); err == nil {
			t.Fatal("overwrote database without force")
		}
	})
}
