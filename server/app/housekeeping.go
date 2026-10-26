package app

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sentrel/server/db"
)

// housekeepingLoop runs periodic maintenance: retention, storage accounting,
// history pruning and storage warnings.
// maxRestoreEntry caps a single file restored from a backup, so a crafted
// archive cannot fill the disk.
const maxRestoreEntry = 512 << 30

func (a *App) housekeepingLoop(ctx context.Context) {
	// First pass shortly after start, then hourly; heavy work nightly.
	t := time.NewTimer(2 * time.Minute)
	defer t.Stop()
	lastNightly := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		a.cleanup(ctx)
		a.checkServerDisk(ctx)
		now := time.Now()
		if now.Sub(lastNightly) > 23*time.Hour && (now.Hour() == 3 || lastNightly.IsZero()) {
			a.nightly(ctx)
			lastNightly = now
		}
		t.Reset(time.Hour)
	}
}

func (a *App) cleanup(ctx context.Context) {
	r := a.settings.Retention()
	now := time.Now()
	day := int64(24 * 3600)
	stmts := []struct {
		q    string
		args []any
	}{
		{`DELETE FROM agent_hello WHERE updated_at < ?`, []any{now.Unix() - day}},
		{`DELETE FROM sessions WHERE expires_at < ?`, []any{now.Unix()}},
		{`DELETE FROM enrollment_tokens WHERE (used_at=0 AND expires_at < ?) OR (used_at>0 AND used_at < ?)`, []any{now.Unix() - day, now.Unix() - 30*day}},
		{`DELETE FROM alert_events WHERE created_at < ?`, []any{now.Unix() - int64(r.AlertHistoryDays)*day}},
		{`DELETE FROM alerts WHERE status='resolved' AND resolved_at>0 AND resolved_at < ?`, []any{now.Unix() - int64(r.AlertHistoryDays)*day}},
		{`DELETE FROM audit_log WHERE created_at < ?`, []any{now.Unix() - int64(r.AuditDays)*day}},
		{`DELETE FROM jobs WHERE finished_at>0 AND finished_at < ?`, []any{now.Unix() - int64(r.JobHistoryDays)*day}},
		{`DELETE FROM security_events WHERE window_end < ?`, []any{now.Unix() - int64(r.SecurityEventDays)*day}},
		{`DELETE FROM notification_log WHERE created_at < ?`, []any{now.Unix() - 30*day}},
		{`DELETE FROM vuln_scans WHERE started_at < ?`, []any{now.Unix() - 180*day}},
		{`DELETE FROM vuln_findings WHERE status='fixed' AND fixed_at < ?`, []any{now.Unix() - 180*day}},
		{`DELETE FROM ip_blocks WHERE status IN ('removed','failed') AND created_at < ?`, []any{now.Unix() - 90*day}},
		{`DELETE FROM uptime_daily WHERE day < ?`, []any{now.UTC().AddDate(-1, 0, 0).Format("2006-01-02")}},
	}
	for _, s := range stmts {
		if _, err := a.db.ExecContext(ctx, s.q, s.args...); err != nil {
			a.log.Warn("cleanup", "err", err)
		}
	}
	a.pruneDiskReports(ctx)
}

// nightly enforces per-host retention and computes per-host storage.
func (a *App) nightly(ctx context.Context) {
	type hr struct {
		ID   int64 `db:"id"`
		Days *int  `db:"retention_days"`
	}
	var rows []hr
	_ = a.db.SelectContext(ctx, &rows, `SELECT id, retention_days FROM hosts`)
	ret := map[int64]time.Duration{}
	for _, r := range rows {
		if r.Days != nil {
			ret[r.ID] = time.Duration(*r.Days) * 24 * time.Hour
		}
	}
	_ = a.ts.SetRetention(a.maxRetention(a.settings.Retention().Days))
	if err := a.ts.EnforceRetention(ctx, ret); err != nil {
		a.log.Warn("retention", "err", err)
	}
	a.computeStorage(ctx)
	_, _ = a.db.ExecContext(ctx, `PRAGMA optimize`)
	_, _ = a.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
}

// computeStorage estimates stored bytes per host and alerts above the
// threshold (rule metric host_storage_mb).
func (a *App) computeStorage(ctx context.Context) {
	counts, err := a.ts.HostSampleCounts(ctx)
	if err != nil {
		a.log.Warn("storage accounting", "err", err)
		return
	}
	bps := a.ts.Stats().BytesPerSample
	now := db.Now()
	for id, n := range counts {
		bytes := int64(float64(n) * bps)
		_, _ = a.db.ExecContext(ctx, `UPDATE hosts SET storage_bytes=?, storage_computed_at=? WHERE id=?`, bytes, now, id)
		h, ok := a.alerts.host(id)
		if !ok {
			continue
		}
		mb := float64(bytes) / (1 << 20)
		hid := id
		c := condition{Key: "storage:host:" + itoa(id), TenantID: h.TenantID, HostID: &hid, Source: "storage", Metric: "host_storage_mb", Severity: "ok", ForCount: 1}
		if r := a.alerts.rules.resolve(h, "host_storage_mb", ""); r != nil && r.Rule.Enabled {
			def, _ := metricByKey("host_storage_mb")
			if sev, thr := severityFor(def, r.Rule, mb); sev != "ok" {
				c.Severity, c.Threshold, c.Value = sev, thr, &mb
				c.Title = "Metric storage for " + h.Name + " is large"
				c.Message = fmt.Sprintf("%s stores %.0f MB of time-series data (threshold %.0f MB); reduce its interval or retention", h.Name, mb, *thr)
			}
		}
		a.alerts.apply(ctx, c)
	}
}

func (a *App) checkServerDisk(ctx context.Context) {
	d := diskUsage(a.cfg.DataDir)
	if d.TotalBytes == 0 {
		return
	}
	limit := float64(a.settings.Retention().DiskWarnPercent)
	if limit <= 0 {
		limit = 85
	}
	pct := float64(d.UsedBytes) * 100 / float64(d.TotalBytes)
	sev := "ok"
	switch {
	case pct >= 95:
		sev = "critical"
	case pct >= limit:
		sev = "warning"
	}
	a.alerts.systemCondition(ctx, "disk", sev, "Server data disk is filling up",
		fmt.Sprintf("The disk holding %s is %.1f%% full (%.1f GB free)", a.cfg.DataDir, pct, float64(d.FreeBytes)/1e9))
}

// DiskInfo describes a filesystem.
type DiskInfo struct {
	TotalBytes uint64 `json:"total_bytes"`
	FreeBytes  uint64 `json:"free_bytes"`
	UsedBytes  uint64 `json:"used_bytes"`
}

// uptimeLoop accumulates per-host up/down seconds for status pages and SLA.
func (a *App) uptimeLoop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		a.runUpdateSchedules(ctx)
		type hs struct {
			ID       int64  `db:"id"`
			TenantID int64  `db:"tenant_id"`
			Status   string `db:"status"`
		}
		var rows []hs
		_ = a.db.SelectContext(ctx, &rows, `SELECT id, tenant_id, status FROM hosts WHERE status IN ('up','down') AND revoked=0`)
		for _, r := range rows {
			if a.maint.hostInWindow(r.ID) && r.Status == "down" {
				continue // planned downtime does not count against uptime
			}
			a.addUptime(ctx, r.TenantID, "host", r.ID, r.Status == "up", 60)
		}
	}
}

// --- backup / restore ---

// backupDirs are copied besides the database. The TSDB and vulnerability DB
// are excluded: metrics are bulky and the vuln DB is re-downloaded.
var backupDirs = []string{"pki", "snmp-profiles"}

// WriteBackup streams a tar.gz containing a consistent SQLite snapshot plus
// PKI material. withTSDB includes the metrics directory.
func (a *App) WriteBackup(ctx context.Context, w io.Writer, withTSDB bool) error {
	return WriteBackup(ctx, a.db, a.cfg.DataDir, w, withTSDB)
}

// WriteBackup is usable without a running App (CLI backups while the
// server runs: SQLite snapshots are safe under WAL).
func WriteBackup(ctx context.Context, d *db.DB, dataDir string, w io.Writer, withTSDB bool) error {
	tmp, err := os.MkdirTemp(dataDir, ".backup-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	snap := filepath.Join(tmp, "sentrel.db")
	if _, err := d.ExecContext(ctx, `VACUUM INTO ?`, snap); err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	add := func(src, name string) error {
		fi, err := os.Stat(src)
		if err != nil {
			return err
		}
		hdr, _ := tar.FileInfoHeader(fi, "")
		hdr.Name = filepath.ToSlash(name)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		f, err := os.Open(src)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	}
	if err := add(snap, "sentrel.db"); err != nil {
		return err
	}
	dirs := append([]string{}, backupDirs...)
	if withTSDB {
		dirs = append(dirs, "tsdb")
	}
	for _, dir := range dirs {
		root := filepath.Join(dataDir, dir)
		_ = filepath.WalkDir(root, func(p string, de fs.DirEntry, err error) error {
			if err != nil || de.IsDir() || strings.HasSuffix(p, ".tmp") || strings.HasSuffix(p, "lock") {
				return nil
			}
			rel, _ := filepath.Rel(dataDir, p)
			return add(p, rel)
		})
	}
	manifest := fmt.Sprintf("sentrel-backup v1\ncreated %s\ntsdb %v\n", time.Now().UTC().Format(time.RFC3339), withTSDB)
	_ = tw.WriteHeader(&tar.Header{Name: "MANIFEST", Mode: 0o644, Size: int64(len(manifest)), ModTime: time.Now()})
	_, _ = tw.Write([]byte(manifest))
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

// RestoreBackup unpacks a backup into an (empty or replaceable) data dir.
// The server must not be running.
func RestoreBackup(r io.Reader, dataDir string, force bool) error {
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return err
	}
	root, err := os.OpenRoot(dataDir)
	if err != nil {
		return err
	}
	defer root.Close()
	if _, err := root.Stat("sentrel.db"); err == nil && !force {
		return errors.New("data directory already contains a database; pass --force to overwrite")
	}
	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	seenDB := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		name := filepath.Clean(filepath.FromSlash(hdr.Name))
		if !filepath.IsLocal(name) || name == "." {
			return fmt.Errorf("unsafe path in backup: %s", hdr.Name)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if hdr.Size > maxRestoreEntry {
			return fmt.Errorf("backup entry %s is larger than %d bytes", name, int64(maxRestoreEntry))
		}
		if err := root.MkdirAll(filepath.Dir(name), 0o750); err != nil {
			return err
		}
		mode := os.FileMode(0o640)
		if name == "pki" || strings.HasPrefix(name, "pki"+string(filepath.Separator)) {
			mode = 0o600
		}
		// All operations stay inside the opened root, including when an existing
		// directory is a symlink. Exclusive, random staging files prevent planted
		// .restore links from being followed or inheriting permissive file modes.
		tmp := name + ".restore-" + randomToken(12)
		f, err := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if err != nil {
			return err
		}
		_, copyErr := io.CopyN(f, tr, hdr.Size)
		closeErr := f.Close()
		if copyErr != nil || closeErr != nil {
			_ = root.Remove(tmp)
			return errors.Join(copyErr, closeErr)
		}
		if err := root.Rename(tmp, name); err != nil {
			_ = root.Remove(tmp)
			return err
		}
		if name == "sentrel.db" {
			seenDB = true
			_ = root.Remove(name + "-wal")
			_ = root.Remove(name + "-shm")
		}
	}
	if !seenDB {
		return errors.New("backup does not contain sentrel.db")
	}
	return nil
}
