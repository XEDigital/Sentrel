package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"sentrel/server/db"
	"sentrel/server/metrics"
	"sentrel/server/vuln"
)

// VulnService runs scans and keeps the vulnerability DB fresh.
type VulnService struct {
	app     *App
	scanner *vuln.Scanner

	mu      sync.Mutex
	queue   []vulnJob
	queued  map[int64]bool
	wake    chan struct{}
	syncing bool

	// Progress of "update database and scan all" (see Refresh).
	refresh refreshState

	// Hooks for tests; default to the real scanner.
	updateFn func(url string) error
	loadFn   func() error
}

// errVulnDisabled is returned by every scan and DB-update entry point while
// vulnerability scanning is switched off.
const msgVulnDisabled = "Vulnerability scanning is disabled; enable it in Settings"

type vulnJob struct {
	hostID  int64
	trigger string
}

func newVulnService(a *App) *VulnService {
	v := &VulnService{app: a, scanner: vuln.New(filepath.Join(a.cfg.DataDir, "vulndb"), a.log), queued: map[int64]bool{}, wake: make(chan struct{}, 1)}
	v.updateFn = func(url string) error { return v.scanner.Update(url) }
	v.loadFn = func() error { return v.scanner.Load() }
	v.migrateDefault()
	return v
}

func (v *VulnService) dbDir() string { return filepath.Join(v.app.cfg.DataDir, "vulndb") }

// migrateDefault keeps scanning on for installs that predate the opt-in
// setting: when no explicit vuln setting is stored but a DB directory or scan
// history exists, the setting is saved as enabled. New installs stay off.
func (v *VulnService) migrateDefault() {
	a := v.app
	if raw, err := a.settings.raw(0, keyVuln); err != nil || raw != nil {
		return
	}
	legacy := false
	if ents, err := os.ReadDir(v.dbDir()); err == nil && len(ents) > 0 {
		legacy = true
	}
	if !legacy {
		var n int
		if err := a.db.Get(&n, `SELECT COUNT(*) FROM vuln_scans`); err == nil && n > 0 {
			legacy = true
		}
	}
	if !legacy {
		return
	}
	s := a.settings.Vuln()
	s.Enabled = true
	if err := a.settings.Save(context.Background(), 0, keyVuln, s); err != nil {
		a.log.Warn("could not keep vulnerability scanning enabled for an existing install", "err", err)
		return
	}
	a.log.Info("existing vulnerability data found; vulnerability scanning stays enabled")
}

// Enabled reports whether scanning is switched on.
func (v *VulnService) Enabled() bool { return v.app.settings.Vuln().Enabled }

// Disable stops queued work and releases the DB. With deleteDB the files are
// removed from disk as well.
func (v *VulnService) Disable(deleteDB bool) error {
	v.mu.Lock()
	v.queue = nil
	v.queued = map[int64]bool{}
	v.mu.Unlock()
	if deleteDB {
		return v.scanner.Delete()
	}
	v.scanner.Close()
	return nil
}

func (v *VulnService) close() { v.scanner.Close() }

// Status returns DB status.
func (v *VulnService) Status() vuln.Status { return v.scanner.Status() }

func (v *VulnService) enqueue(hostID int64, trigger string) bool {
	if !v.app.settings.Vuln().Enabled {
		return false
	}
	v.mu.Lock()
	if v.queued[hostID] {
		v.mu.Unlock()
		return false
	}
	v.queued[hostID] = true
	v.queue = append(v.queue, vulnJob{hostID, trigger})
	v.mu.Unlock()
	select {
	case v.wake <- struct{}{}:
	default:
	}
	return true
}

// QueueLength returns the number of pending scans.
func (v *VulnService) QueueLength() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.queue)
}

// LookupCVE returns local DB metadata for one CVE id.
func (v *VulnService) LookupCVE(id string) (vuln.Finding, bool) { return v.scanner.LookupCVE(id) }

// refreshState is the progress of a server-side "update database and scan all".
type refreshState struct {
	Pending    bool   `json:"refresh_pending"`
	Phase      string `json:"refresh_phase"` // updating, scanning, done, failed
	Error      string `json:"refresh_error,omitempty"`
	ScanTotal  int    `json:"refresh_scan_total"`
	StartedAt  int64  `json:"refresh_started_at,omitempty"`
	FinishedAt int64  `json:"refresh_finished_at,omitempty"`
}

// RefreshStatus reports the progress of the last or running refresh. While
// scanning, ScanRemaining counts the hosts still queued or being scanned.
func (v *VulnService) RefreshStatus() map[string]any {
	v.mu.Lock()
	defer v.mu.Unlock()
	r := v.refresh
	remaining := 0
	if r.Phase == "scanning" {
		remaining = len(v.queued)
		if remaining == 0 {
			v.refresh.Pending, v.refresh.Phase, v.refresh.FinishedAt = false, "done", db.Now()
			r = v.refresh
		}
	}
	return map[string]any{"refresh_pending": r.Pending, "refresh_phase": r.Phase, "refresh_error": r.Error,
		"refresh_scan_total": r.ScanTotal, "refresh_scan_remaining": remaining, "refresh_started_at": r.StartedAt, "refresh_finished_at": r.FinishedAt}
}

// SyncNow starts a DB update in the background.
func (v *VulnService) SyncNow() error {
	if !v.Enabled() {
		return errors.New(msgVulnDisabled)
	}
	v.mu.Lock()
	if v.syncing {
		v.mu.Unlock()
		return errors.New("a database update is already running")
	}
	v.syncing = true
	v.mu.Unlock()
	go func() {
		defer func() {
			v.mu.Lock()
			v.syncing = false
			v.mu.Unlock()
		}()
		_ = v.updateDB()
	}()
	return nil
}

// updateDB runs one DB update (a no-op when already current).
func (v *VulnService) updateDB() error {
	v.app.log.Info("vulnerability DB update starting")
	start := time.Now()
	err := v.updateFn(v.app.settings.Vuln().DBURL)
	ctx := context.Background()
	if err != nil {
		v.app.log.Error("vulnerability DB update failed", "err", err)
		v.app.alerts.systemCondition(ctx, "vulndb", "warning", "Vulnerability database update failed", err.Error())
		return err
	}
	v.app.alerts.systemCondition(ctx, "vulndb", "ok", "", "")
	st := v.scanner.Status()
	v.app.log.Info("vulnerability DB ready", "built", st.Built, "took", time.Since(start).Round(time.Second))
	v.app.audit(ctx, auditEntry{Actor: "system", Action: "vulndb.updated", Details: map[string]any{"built": st.Built, "schema": st.SchemaVersion}})
	return nil
}

// Refresh updates the DB and then queues a scan of every host that hostIDs
// returns. It runs on the server, so it carries on when the browser closes.
// Progress is exposed through RefreshStatus.
func (v *VulnService) Refresh(hostIDs func() []int64) error {
	if !v.Enabled() {
		return errors.New(msgVulnDisabled)
	}
	v.mu.Lock()
	if v.syncing || v.refresh.Pending {
		v.mu.Unlock()
		return errors.New("a database update is already running")
	}
	v.syncing = true
	v.refresh = refreshState{Pending: true, Phase: "updating", StartedAt: db.Now()}
	v.mu.Unlock()
	go func() {
		err := v.updateDB()
		v.mu.Lock()
		v.syncing = false
		v.mu.Unlock()
		if err != nil {
			v.mu.Lock()
			v.refresh.Pending, v.refresh.Phase, v.refresh.Error, v.refresh.FinishedAt = false, "failed", err.Error(), db.Now()
			v.mu.Unlock()
			return
		}
		ids := hostIDs()
		for _, id := range ids {
			v.enqueue(id, "refresh")
		}
		n := len(ids)
		v.mu.Lock()
		v.refresh.Phase, v.refresh.ScanTotal = "scanning", n
		if n == 0 {
			v.refresh.Pending, v.refresh.Phase, v.refresh.FinishedAt = false, "done", db.Now()
		}
		v.mu.Unlock()
	}()
	return nil
}

func (v *VulnService) loop(ctx context.Context) {
	// Scans interrupted by a restart are marked failed and re-queued.
	var interrupted []int64
	_ = v.app.db.SelectContext(ctx, &interrupted, `SELECT DISTINCT host_id FROM vuln_scans WHERE status='running'`)
	_, _ = v.app.db.ExecContext(ctx, `UPDATE vuln_scans SET status='failed', error='interrupted by a server restart', finished_at=? WHERE status='running'`, db.Now())
	// Open an existing DB at startup (no network); download on first run.
	go func() {
		defer func() {
			for _, id := range interrupted {
				v.enqueue(id, "restart")
			}
		}()
		// Nothing is opened or downloaded while scanning is disabled.
		if !v.Enabled() {
			return
		}
		if err := v.loadFn(); err != nil {
			v.app.log.Info("no local vulnerability DB; downloading", "reason", err)
			_ = v.SyncNow()
		}
	}()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			v.maybeSync()
			v.runSchedules(ctx)
		case <-v.wake:
		}
		v.drain(ctx)
	}
}

func (v *VulnService) maybeSync() {
	s := v.app.settings.Vuln()
	if !s.Enabled {
		return
	}
	st := v.scanner.Status()
	now := time.Now()
	// Daily at the configured hour, or immediately if the DB is >36h old.
	if now.Sub(st.LastCheck) > 20*time.Hour && (now.Hour() == s.SyncHour || now.Sub(st.Built) > 36*time.Hour) {
		_ = v.SyncNow()
	}
}

func (v *VulnService) drain(ctx context.Context) {
	for v.Enabled() {
		v.mu.Lock()
		if len(v.queue) == 0 {
			v.mu.Unlock()
			return
		}
		j := v.queue[0]
		v.queue = v.queue[1:]
		v.mu.Unlock()
		if _, err := v.ScanHost(ctx, j.hostID, j.trigger); err != nil {
			v.app.log.Debug("vuln scan", "host_id", j.hostID, "err", err)
		}
		v.mu.Lock()
		delete(v.queued, j.hostID)
		v.mu.Unlock()
		if ctx.Err() != nil {
			return
		}
	}
}

// ScanHost scans one host synchronously and stores findings.
func (v *VulnService) ScanHost(ctx context.Context, hostID int64, trigger string) (*VulnScan, error) {
	a := v.app
	h, err := a.getHost(ctx, hostID)
	if err != nil {
		return nil, err
	}
	hi := hostInfo(h)
	now := db.Now()
	res, err := a.db.ExecContext(ctx, `INSERT INTO vuln_scans (tenant_id, host_id, status, triggered_by, started_at) VALUES (?,?,?,?,?)`, h.TenantID, h.ID, "running", trigger, now)
	if err != nil {
		return nil, err
	}
	scanID, _ := res.LastInsertId()
	finish := func(status, errMsg string, s *VulnScan) (*VulnScan, error) {
		if s == nil {
			s = &VulnScan{}
		}
		s.ID, s.HostID, s.TenantID, s.Status, s.Error, s.TriggeredBy, s.StartedAt, s.FinishedAt = scanID, h.ID, h.TenantID, status, errMsg, trigger, now, db.Now()
		_, _ = a.db.ExecContext(ctx, `UPDATE vuln_scans SET status=?, error=?, packages=?, findings=?, critical=?, high=?, medium=?, low=?, db_built=?, finished_at=? WHERE id=?`,
			status, errMsg, s.Packages, s.Findings, s.Critical, s.High, s.Medium, s.Low, s.DBBuilt, s.FinishedAt, scanID)
		a.events.publish(Event{Type: "vuln.scanned", TenantID: h.TenantID, HostID: h.ID})
		if status == "failed" {
			return s, errors.New(errMsg)
		}
		return s, nil
	}
	if h.Kind != "agent" {
		return finish("skipped", "only agent hosts have a package inventory", nil)
	}
	if hi.Os == "windows" {
		// Windows findings come from the CVEs of pending Windows Updates (see
		// winvuln.go); a scan only refreshes their DB metadata.
		a.enrichWindowsFindings(ctx, h.ID)
		c := a.hostVulnCounts(ctx, h)
		return finish("completed", "", &VulnScan{Findings: c.Total, Critical: c.Critical, High: c.High, Medium: c.Medium, Low: c.Low, DBBuilt: v.scanner.Status().Built.UTC().Format(time.RFC3339)})
	}
	if !vuln.SupportedOS(hi.OsId) {
		return finish("skipped", fmt.Sprintf("distribution %q is not covered by the vulnerability database", hi.OsId), nil)
	}
	var rows []Package
	if err := a.db.SelectContext(ctx, &rows, `SELECT * FROM packages WHERE host_id=? AND version<>'-'`, h.ID); err != nil {
		return finish("failed", err.Error(), nil)
	}
	if len(rows) == 0 {
		return finish("skipped", "no package inventory received yet", nil)
	}
	pkgs := make([]vuln.Package, 0, len(rows))
	for _, r := range rows {
		pkgs = append(pkgs, vuln.Package{Name: r.Name, Version: r.Version, Arch: r.Arch, Type: r.Type, Source: r.Source, SourceVersion: r.SourceVersion})
	}
	sctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	findings, err := v.scanner.Scan(sctx, hi.OsId, hi.OsVersionId, pkgs)
	if err != nil {
		return finish("failed", err.Error(), &VulnScan{Packages: len(pkgs)})
	}
	st := v.scanner.Status()
	summary := &VulnScan{Packages: len(pkgs), DBBuilt: st.Built.UTC().Format(time.RFC3339)}
	seen := map[string]bool{} // distinct CVEs: one source package ships many binaries
	err = a.db.Tx(ctx, func(tx *sqlxTx) error {
		for _, f := range findings {
			if !seen[f.VulnID] {
				seen[f.VulnID] = true
				summary.Findings++
				switch f.Severity {
				case "Critical":
					summary.Critical++
				case "High":
					summary.High++
				case "Medium":
					summary.Medium++
				case "Low":
					summary.Low++
				}
			}
			_, err := tx.ExecContext(ctx, `INSERT INTO vuln_findings (tenant_id, host_id, vuln_id, package, version, fixed_version, fix_state, severity, cvss, cvss_vector,
				epss, kev, description, urls, namespace, status, first_seen_at, last_seen_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'open',?,?)
				ON CONFLICT(host_id, vuln_id, package) DO UPDATE SET version=excluded.version, fixed_version=excluded.fixed_version, fix_state=excluded.fix_state,
				severity=excluded.severity, cvss=excluded.cvss, cvss_vector=excluded.cvss_vector, epss=excluded.epss, kev=excluded.kev, description=excluded.description,
				urls=excluded.urls, namespace=excluded.namespace, last_seen_at=excluded.last_seen_at,
				status=CASE WHEN vuln_findings.status='ignored' THEN 'ignored' ELSE 'open' END, fixed_at=CASE WHEN vuln_findings.status='ignored' THEN vuln_findings.fixed_at ELSE 0 END`,
				h.TenantID, h.ID, f.VulnID, f.Package, f.Version, f.FixedVersion, f.FixState, f.Severity, f.CVSS, f.Vector, f.EPSS, f.KEV,
				truncateStr(f.Description, 4000), StrList(f.URLs), f.Namespace, now, now)
			if err != nil {
				return err
			}
		}
		// Anything open that was not seen this time has been fixed.
		_, err := tx.ExecContext(ctx, `UPDATE vuln_findings SET status='fixed', fixed_at=? WHERE host_id=? AND status='open' AND last_seen_at < ?`, now, h.ID, now)
		return err
	})
	if err != nil {
		return finish("failed", err.Error(), summary)
	}
	v.evaluate(ctx, h)
	return finish("completed", "", summary)
}

// evaluate raises a per-host vulnerability alert and records counts.
func (v *VulnService) evaluate(ctx context.Context, h *Host) {
	a := v.app
	s := a.settings.Vuln()
	type cnt struct {
		Severity string `db:"severity"`
		N        int    `db:"n"`
	}
	var counts []cnt
	_ = a.db.SelectContext(ctx, &counts, `SELECT severity, COUNT(*) AS n FROM (SELECT `+sevAggSQL+` AS severity FROM vuln_findings f WHERE f.host_id=? AND f.status='open' GROUP BY f.vuln_id) GROUP BY severity`, h.ID)
	var samples []metrics.Sample
	bySev := map[string]int{}
	for _, c := range counts {
		bySev[c.Severity] = c.N
		samples = append(samples, metrics.Sample{Name: "vulnerabilities_open", Labels: map[string]string{"severity": strings.ToLower(c.Severity)}, Value: float64(c.N)})
	}
	for _, sv := range []string{"Critical", "High", "Medium", "Low"} {
		if _, ok := bySev[sv]; !ok {
			samples = append(samples, metrics.Sample{Name: "vulnerabilities_open", Labels: map[string]string{"severity": strings.ToLower(sv)}, Value: 0})
		}
	}
	_ = a.ts.Append(h.ID, h.TenantID, samples)
	hid := h.ID
	cond := condition{Key: "vuln:" + itoa(h.ID), TenantID: h.TenantID, HostID: &hid, Source: "vuln", Metric: "vulnerabilities", Severity: "ok", ForCount: 1}
	if s.AlertSeverity != "" && s.AlertSeverity != "none" {
		min := vuln.SeverityRank(s.AlertSeverity)
		total, crit := 0, 0
		// Decorated findings, so "fixable" means actionable now, as in the
		// counts and the "Fixable now" filter: a fix that is not yet in the
		// host's repositories (wait) does not count.
		list := a.openFindings(ctx, h.ID)
		for i := range list {
			cv := &list[i]
			if cv.Inactive && !s.AlertOnInactiveKernels {
				continue // a kernel that is installed but not running is not exploitable
			}
			if s.OnlyFixable && !actionable(cv) {
				continue
			}
			if vuln.SeverityRank(cv.Severity) < min {
				continue
			}
			total++
			if cv.Severity == "Critical" {
				crit++
			}
		}
		if total > 0 {
			cond.Severity = "warning"
			if crit > 0 {
				cond.Severity = "critical"
			}
			fixable, fixNote := "", ""
			if s.OnlyFixable {
				fixable, fixNote = " fixable", ", fixable now"
			}
			cond.Title = fmt.Sprintf("%d%s vulnerabilities on %s", total, fixable, h.Name)
			cond.Message = fmt.Sprintf("%d critical, %d at or above %s severity%s", crit, total, s.AlertSeverity, fixNote)
			val := float64(total)
			cond.Value = &val
		}
	}
	a.alerts.apply(ctx, cond)
}

// runSchedules enqueues hosts for due schedules.
func (v *VulnService) runSchedules(ctx context.Context) {
	a := v.app
	if !a.settings.Vuln().Enabled {
		return
	}
	var ss []VulnSchedule
	if err := a.db.SelectContext(ctx, &ss, `SELECT * FROM vuln_schedules WHERE enabled=1`); err != nil {
		return
	}
	loc, err := time.LoadLocation(a.settings.General().Timezone)
	if err != nil {
		loc = time.UTC
	}
	now := time.Now().In(loc)
	for _, s := range ss {
		hh, mm, ok := parseHHMM(s.TimeOfDay)
		if !ok {
			continue
		}
		at := time.Date(now.Year(), now.Month(), now.Day(), hh, mm, 0, 0, loc)
		if now.Before(at) || s.LastRunAt >= at.Unix() {
			continue
		}
		if s.Frequency == "weekly" && int(now.Weekday()) != s.Weekday {
			continue
		}
		q := `SELECT id FROM hosts WHERE kind='agent' AND revoked=0`
		var args []any
		switch s.Scope {
		case "tenant":
			q += ` AND tenant_id=?`
			args = append(args, s.ScopeID)
		case "group":
			q += ` AND group_id=?`
			args = append(args, s.ScopeID)
		case "host":
			q += ` AND id=?`
			args = append(args, s.ScopeID)
		}
		if s.TenantID != 0 {
			q += ` AND tenant_id=?`
			args = append(args, s.TenantID)
		}
		var ids []int64
		_ = a.db.SelectContext(ctx, &ids, q, args...)
		for _, id := range ids {
			v.enqueue(id, "schedule")
		}
		_, _ = a.db.ExecContext(ctx, `UPDATE vuln_schedules SET last_run_at=? WHERE id=?`, time.Now().Unix(), s.ID)
	}
}
