package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"sentrel/server/db"
	"sentrel/server/metrics"
)

// --- beat bars ---

type hostBeat struct {
	Day    string   `json:"day"`
	Uptime *float64 `json:"uptime"`
}

// apiHostBeats returns one uptime percentage per day for every visible host,
// oldest first, for the compact status bars in the host list.
func (a *App) apiHostBeats(c *Ctx) (any, error) {
	days := c.queryLimit("days", 30, 90)
	if days <= 0 {
		days = 30
	}
	if days > 90 {
		days = 90
	}
	tw, args := c.tenantWhere("h.tenant_id")
	var ids []int64
	if err := a.db.SelectContext(c.ctx(), &ids, `SELECT h.id FROM hosts h WHERE `+tw, args...); err != nil {
		return nil, err
	}
	today := time.Now().UTC()
	labels := make([]string, days)
	for i := 0; i < days; i++ {
		labels[i] = today.AddDate(0, 0, -(days - 1 - i)).Format("2006-01-02")
	}
	type row struct {
		ID   int64  `db:"item_id"`
		Day  string `db:"day"`
		Up   int64  `db:"up_seconds"`
		Down int64  `db:"down_seconds"`
	}
	var rows []row
	if err := a.db.SelectContext(c.ctx(), &rows, `SELECT u.item_id, u.day, u.up_seconds, u.down_seconds FROM uptime_daily u
		JOIN hosts h ON h.id=u.item_id WHERE u.item_type='host' AND u.day>=? AND `+tw, append([]any{labels[0]}, args...)...); err != nil {
		return nil, err
	}
	byHost := map[int64]map[string]row{}
	for _, r := range rows {
		m := byHost[r.ID]
		if m == nil {
			m = map[string]row{}
			byHost[r.ID] = m
		}
		m[r.Day] = r
	}
	out := make(map[string][]hostBeat, len(ids))
	for _, id := range ids {
		beats := make([]hostBeat, days)
		for i, d := range labels {
			beats[i] = hostBeat{Day: d}
			if r, ok := byHost[id][d]; ok && r.Up+r.Down > 0 {
				v := float64(r.Up) * 100 / float64(r.Up+r.Down)
				beats[i].Uptime = &v
			}
		}
		out[itoa(id)] = beats
	}
	return out, nil
}

type checkBeat struct {
	T         int64    `json:"t"`
	OK        bool     `json:"ok"`
	LatencyMs *float64 `json:"latency_ms"`
}

// apiCheckBeats returns the most recent results of every visible check,
// oldest first, read from the time-series store.
func (a *App) apiCheckBeats(c *Ctx) (any, error) {
	limit := c.queryLimit("limit", 40, 100)
	if limit <= 0 {
		limit = 40
	}
	if limit > 100 {
		limit = 100
	}
	tw, args := c.tenantWhere("k.tenant_id")
	type chk struct {
		ID       int64 `db:"id"`
		TenantID int64 `db:"tenant_id"`
		Interval int   `db:"interval_seconds"`
	}
	var checks []chk
	if err := a.db.SelectContext(c.ctx(), &checks, `SELECT k.id, k.tenant_id, k.interval_seconds FROM checks k WHERE `+tw, args...); err != nil {
		return nil, err
	}
	out := make(map[string][]checkBeat, len(checks))
	now := time.Now()
	for _, k := range checks {
		beats := []checkBeat{}
		out[itoa(k.ID)] = beats
		step := time.Duration(k.Interval) * time.Second
		if step < 10*time.Second {
			step = 10 * time.Second
		}
		start := now.Add(-step * time.Duration(limit))
		upS, err := a.ts.QueryRange(c.ctx(), fmt.Sprintf(`%scheck_up{check_id="%d",tenant_id="%d"}`, metrics.Prefix, k.ID, k.TenantID), start, now, step)
		if err != nil || len(upS) == 0 {
			continue
		}
		lat := map[int64]float64{}
		if latS, err := a.ts.QueryRange(c.ctx(), fmt.Sprintf(`%scheck_latency_ms{check_id="%d",tenant_id="%d"}`, metrics.Prefix, k.ID, k.TenantID), start, now, step); err == nil && len(latS) > 0 {
			for _, p := range latS[0].Points {
				lat[int64(p[0])] = p[1]
			}
		}
		for _, p := range upS[0].Points {
			b := checkBeat{T: int64(p[0]), OK: p[1] >= 1}
			if v, ok := lat[b.T]; ok && b.OK {
				lv := v
				b.LatencyMs = &lv
			}
			beats = append(beats, b)
		}
		if len(beats) > limit {
			beats = beats[len(beats)-limit:]
		}
		out[itoa(k.ID)] = beats
	}
	return out, nil
}

// --- per-host notification mute ---

type hostNotifyReq struct {
	Metric string `json:"metric"`
	Notify bool   `json:"notify"`
}

func (a *App) hostRefFor(h *Host) hostRef {
	if ref, ok := a.alerts.host(h.ID); ok {
		return ref
	}
	ref := hostRef{ID: h.ID, TenantID: h.TenantID, Name: h.Name, Kind: h.Kind}
	if h.GroupID != nil {
		ref.GroupID = *h.GroupID
	}
	return ref
}

// apiHostNotify sets whether alerts for one metric notify channels for this
// host. It writes a host-scoped rule that copies the effective thresholds and
// changes only the notify flag.
func (a *App) apiHostNotify(c *Ctx) (any, error) {
	h, err := c.visibleHost(c.ID())
	if err != nil {
		return nil, err
	}
	var req hostNotifyReq
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	if _, ok := metricByKey(req.Metric); !ok {
		return nil, badRequest("unknown metric %q", req.Metric)
	}
	var warn, crit *float64
	forCount, enabled := 1, true
	if eff := a.alerts.rules.resolve(a.hostRefFor(h), req.Metric, ""); eff != nil {
		warn, crit, forCount, enabled = eff.Rule.Warn, eff.Rule.Crit, eff.Rule.ForCount, eff.Rule.Enabled
	}
	now := db.Now()
	_, err = a.db.ExecContext(c.ctx(), `INSERT INTO threshold_rules (tenant_id, scope, scope_id, metric, label_match, warn, crit, for_count, enabled, notify, created_at, updated_at)
		VALUES (?,'host',?,?,'',?,?,?,?,?,?,?) ON CONFLICT(tenant_id, scope, scope_id, metric, label_match) DO UPDATE SET notify=excluded.notify, updated_at=excluded.updated_at`,
		h.TenantID, h.ID, req.Metric, warn, crit, forCount, enabled, req.Notify, now, now)
	if err != nil {
		return nil, err
	}
	_ = a.alerts.ReloadRules(c.ctx())
	c.auditT(h.TenantID, "host.notify", "host", itoa(h.ID), req)
	return map[string]any{"metric": req.Metric, "notify": req.Notify}, nil
}

// hostNotifies reports the effective notify flag of a metric for a host.
func (a *App) hostNotifies(h *Host, metric string) bool {
	if eff := a.alerts.rules.resolve(a.hostRefFor(h), metric, ""); eff != nil {
		return eff.Rule.Notify
	}
	return true
}

// --- vulnerability upgrade info ---

// decorateFindings fills available_version, upgradable and os on findings.
// A finding is upgradable when an agent host running Linux has a pending
// package update at or beyond the version that fixes the vulnerability.
func (a *App) decorateFindings(c *Ctx, list []VulnFinding) { a.decorateFindingsCtx(c.ctx(), list) }

func (a *App) decorateFindingsCtx(ctx context.Context, list []VulnFinding) {
	type pkgUpdate struct{ newVer, typ, srcVer string }
	type hostData struct {
		os      string
		linux   bool
		updates map[string]pkgUpdate
		fixed   map[string]string // vuln_id|package -> fixed version
		ks      *hostKernels
		cves    map[string]*cveSummary
	}
	hosts := map[int64]*hostData{}
	load := func(id int64) *hostData {
		if d, ok := hosts[id]; ok {
			return d
		}
		d := &hostData{os: "linux", updates: map[string]pkgUpdate{}, fixed: map[string]string{}}
		hosts[id] = d
		h, err := a.getHost(ctx, id)
		if err != nil {
			return d
		}
		if hostInfo(h).Os == "windows" {
			d.os = "windows"
		}
		d.linux = h.Kind == "agent" && d.os == "linux"
		if !d.linux {
			return d
		}
		d.ks = a.loadKernels(ctx, h)
		if len(d.ks.Groups) > 0 {
			d.cves = map[string]*cveSummary{}
			for _, s := range a.hostCVEs(ctx, h, d.ks) {
				d.cves[s.VulnID] = s
			}
		}
		var pk []struct {
			Name       string `db:"name"`
			Type       string `db:"type"`
			NewVersion string `db:"new_version"`
			SrcVersion string `db:"source_version"`
		}
		_ = a.db.SelectContext(ctx, &pk, `SELECT name, type, new_version, source_version FROM packages WHERE host_id=? AND new_version<>''`, id)
		for _, p := range pk {
			if _, dup := d.updates[p.Name]; !dup {
				d.updates[p.Name] = pkgUpdate{p.NewVersion, p.Type, p.SrcVersion}
			}
		}
		var fx []struct {
			VulnID  string `db:"vuln_id"`
			Package string `db:"package"`
			Fixed   string `db:"fixed_version"`
		}
		_ = a.db.SelectContext(ctx, &fx, `SELECT vuln_id, package, fixed_version FROM vuln_findings WHERE host_id=? AND fixed_version<>'' AND status<>'fixed'`, id)
		for _, f := range fx {
			d.fixed[f.VulnID+"|"+f.Package] = f.Fixed
		}
		return d
	}
	for i := range list {
		f := &list[i]
		d := load(f.HostID)
		f.OS = d.os
		if !d.linux {
			if d.os == "windows" && f.Namespace == nsWindowsUpdate {
				// The pending update is the fix; it installs through the upgrade job.
				f.Upgradable, f.AvailableVersion, f.Remediation = true, f.FixedVersion, remUpgrade
			}
			continue
		}
		for _, name := range strings.Split(f.Package, ", ") {
			up, ok := d.updates[name]
			if !ok {
				continue
			}
			if f.AvailableVersion == "" {
				f.AvailableVersion = up.newVer
			}
			fixed := d.fixed[f.VulnID+"|"+name]
			if fixed == "" {
				continue
			}
			// A binary with its own version (libldb2 from samba) cannot be compared
			// with a fix given as a source version; the pending update is taken as the fix.
			if ge, known := versionAtLeast(up.typ, up.newVer, fixed); !known || ge || up.srcVer != "" {
				f.Upgradable = true
				f.AvailableVersion = up.newVer
			}
		}
		finishRemediation(f, d.ks, d.cves[f.VulnID])
	}
}

// versionAtLeast reports whether version a is at least version b for the
// given package type. known is false when the type is not understood.
func versionAtLeast(pkgType, a, b string) (ge, known bool) {
	switch strings.ToLower(pkgType) {
	case "deb":
		return debVersionCompare(a, b) >= 0, true
	case "rpm", "apk":
		return rpmVersionCompare(a, b) >= 0, true
	}
	return false, false
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

func splitEpoch(v string) (int, string) {
	if i := strings.IndexByte(v, ':'); i > 0 {
		n := 0
		for _, ch := range []byte(v[:i]) {
			if !isDigit(ch) {
				return 0, v
			}
			n = n*10 + int(ch-'0')
		}
		return n, v[i+1:]
	}
	return 0, v
}

// debVersionCompare follows dpkg's version ordering.
func debVersionCompare(a, b string) int {
	ea, a := splitEpoch(a)
	eb, b := splitEpoch(b)
	if c := cmpInt(ea, eb); c != 0 {
		return c
	}
	split := func(v string) (string, string) {
		if i := strings.LastIndexByte(v, '-'); i >= 0 {
			return v[:i], v[i+1:]
		}
		return v, ""
	}
	ua, ra := split(a)
	ub, rb := split(b)
	if c := debPartCompare(ua, ub); c != 0 {
		return c
	}
	return debPartCompare(ra, rb)
}

func debOrder(s string) int {
	if s == "" {
		return 0
	}
	c := s[0]
	switch {
	case isDigit(c):
		return 0
	case isAlpha(c):
		return int(c)
	case c == '~':
		return -1
	}
	return int(c) + 256
}

func debPartCompare(a, b string) int {
	for a != "" || b != "" {
		for (a != "" && !isDigit(a[0])) || (b != "" && !isDigit(b[0])) {
			if c := cmpInt(debOrder(a), debOrder(b)); c != 0 {
				return c
			}
			if a != "" {
				a = a[1:]
			}
			if b != "" {
				b = b[1:]
			}
		}
		a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
		diff := 0
		for a != "" && isDigit(a[0]) && b != "" && isDigit(b[0]) {
			if diff == 0 {
				diff = cmpInt(int(a[0]), int(b[0]))
			}
			a, b = a[1:], b[1:]
		}
		if a != "" && isDigit(a[0]) {
			return 1
		}
		if b != "" && isDigit(b[0]) {
			return -1
		}
		if diff != 0 {
			return diff
		}
	}
	return 0
}

// rpmVersionCompare compares "[epoch:]version-release" strings using the
// rpmvercmp segment rules. It is also used for Alpine versions, which share
// the numeric/alphabetic segment model.
func rpmVersionCompare(a, b string) int {
	ea, a := splitEpoch(a)
	eb, b := splitEpoch(b)
	if c := cmpInt(ea, eb); c != 0 {
		return c
	}
	return rpmvercmp(a, b)
}

func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	isAlnum := func(c byte) bool { return isDigit(c) || isAlpha(c) }
	for a != "" || b != "" {
		for a != "" && !isAlnum(a[0]) && a[0] != '~' && a[0] != '^' {
			a = a[1:]
		}
		for b != "" && !isAlnum(b[0]) && b[0] != '~' && b[0] != '^' {
			b = b[1:]
		}
		if (a != "" && a[0] == '~') || (b != "" && b[0] == '~') {
			if a == "" || a[0] != '~' {
				return 1
			}
			if b == "" || b[0] != '~' {
				return -1
			}
			a, b = a[1:], b[1:]
			continue
		}
		if (a != "" && a[0] == '^') || (b != "" && b[0] == '^') {
			if a == "" {
				return -1
			}
			if b == "" {
				return 1
			}
			if a[0] != '^' {
				return 1
			}
			if b[0] != '^' {
				return -1
			}
			a, b = a[1:], b[1:]
			continue
		}
		if a == "" || b == "" {
			break
		}
		numeric := isDigit(a[0])
		take := func(s string) (string, string) {
			i := 0
			for i < len(s) && ((numeric && isDigit(s[i])) || (!numeric && isAlpha(s[i]))) {
				i++
			}
			return s[:i], s[i:]
		}
		var sa, sb string
		sa, a = take(a)
		sb, b = take(b)
		if sb == "" {
			if numeric {
				return 1
			}
			return -1
		}
		if numeric {
			sa, sb = strings.TrimLeft(sa, "0"), strings.TrimLeft(sb, "0")
			if c := cmpInt(len(sa), len(sb)); c != 0 {
				return c
			}
		}
		if sa != sb {
			if sa < sb {
				return -1
			}
			return 1
		}
	}
	switch {
	case a == "" && b == "":
		return 0
	case a == "":
		return -1
	}
	return 1
}
