package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"

	"sentrel/server/db"
	"sentrel/server/metrics"
	"sentrel/server/notify"
)

// --- checks ---

type checkReq struct {
	TenantID         int64           `json:"tenant_id"`
	HostID           *int64          `json:"host_id"`
	Name             string          `json:"name"`
	Type             string          `json:"type"`
	Target           string          `json:"target"`
	Config           json.RawMessage `json:"config"`
	IntervalSeconds  int             `json:"interval_seconds"`
	TimeoutSeconds   int             `json:"timeout_seconds"`
	FailureThreshold int             `json:"failure_threshold"`
	Severity         string          `json:"severity"`
	Enabled          *bool           `json:"enabled"`
	// Parent: leave both out to keep the current dependency; an empty
	// parent_type clears it.
	ParentType *string `json:"parent_type"`
	ParentID   *int64  `json:"parent_id"`
}

func (a *App) validateCheck(c *Ctx, req *checkReq) (int64, error) {
	req.Name = strings.TrimSpace(req.Name)
	req.Target = strings.TrimSpace(req.Target)
	if req.Name == "" || len(req.Name) > 128 {
		return 0, badRequest("name must be 1-128 characters")
	}
	if !serverCheckTypes[req.Type] && !agentCheckTypes[req.Type] {
		return 0, badRequest("unknown check type %q", req.Type)
	}
	if req.Type == "push" {
		req.Target = "heartbeat" // the target is the generated URL
	}
	if req.Target == "" {
		return 0, badRequest("target is required")
	}
	if req.IntervalSeconds == 0 {
		req.IntervalSeconds = 60
		if req.Type == "cert" {
			req.IntervalSeconds = 3600 * 6
		}
		if req.Type == "push" {
			req.IntervalSeconds = pushDefaultInterval
		}
	}
	if req.IntervalSeconds < 10 || req.IntervalSeconds > 86400 {
		return 0, badRequest("interval must be 10-86400 seconds")
	}
	if req.TimeoutSeconds == 0 {
		req.TimeoutSeconds = 10
	}
	if req.TimeoutSeconds < 1 || req.TimeoutSeconds > 120 {
		return 0, badRequest("timeout must be 1-120 seconds")
	}
	if req.FailureThreshold == 0 {
		req.FailureThreshold = 3
		if agentCheckTypes[req.Type] {
			req.FailureThreshold = 2
		}
		if req.Type == "push" {
			req.FailureThreshold = 1
		}
	}
	if req.FailureThreshold < 1 || req.FailureThreshold > 100 {
		return 0, badRequest("failure threshold must be 1-100")
	}
	if req.Severity == "" {
		req.Severity = "critical"
	}
	if req.Severity != "warning" && req.Severity != "critical" {
		return 0, badRequest("severity must be warning or critical")
	}
	if len(req.Config) == 0 {
		req.Config = json.RawMessage("{}")
	}
	var cfg CheckConfig
	if err := json.Unmarshal(req.Config, &cfg); err != nil {
		return 0, badRequest("config: %v", err)
	}
	switch req.Type {
	case "push":
		if cfg.GraceSeconds < 0 || cfg.GraceSeconds > 86400 {
			return 0, badRequest("grace must be 0-86400 seconds")
		}
	case "tcp":
		if _, p, err := net.SplitHostPort(req.Target); err != nil || p == "" {
			return 0, badRequest("TCP target must be host:port")
		}
	case "http":
		u, err := url.Parse(req.Target)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return 0, badRequest("HTTP target must be a full http(s) URL")
		}
		if cfg.KeywordRegex {
			if _, err := regexp.Compile(cfg.Keyword); err != nil {
				return 0, badRequest("keyword regex: %v", err)
			}
		}
	case "port":
		if p, err := strconv.Atoi(req.Target); err != nil || p < 1 || p > 65535 {
			return 0, badRequest("port must be 1-65535")
		}
	case "process":
		if cfg.Regex {
			if _, err := regexp.Compile(req.Target); err != nil {
				return 0, badRequest("process regex: %v", err)
			}
		}
	}
	var tenant int64
	if req.HostID != nil && *req.HostID != 0 {
		h, err := c.visibleHost(*req.HostID)
		if err != nil {
			return 0, badRequest("unknown host")
		}
		if agentCheckTypes[req.Type] && h.Kind != "agent" {
			return 0, badRequest("%s checks need a host with an agent", req.Type)
		}
		tenant = h.TenantID
	} else {
		if agentCheckTypes[req.Type] {
			return 0, badRequest("%s checks must be attached to a host", req.Type)
		}
		req.HostID = nil
		var err error
		if tenant, err = c.tenantFor(req.TenantID); err != nil {
			return 0, err
		}
	}
	return tenant, nil
}

func (a *App) apiListChecks(c *Ctx) (any, error) {
	tw, args := c.tenantWhere("k.tenant_id")
	q := `SELECT k.* FROM checks k WHERE ` + tw
	if h := c.QInt("host_id", 0); h > 0 {
		q += ` AND k.host_id=?`
		args = append(args, h)
	}
	if t := c.Q("type"); t != "" {
		q += ` AND k.type=?`
		args = append(args, t)
	}
	if s := c.Q("status"); s != "" {
		q += ` AND k.status=?`
		args = append(args, s)
	}
	q += ` ORDER BY k.name COLLATE NOCASE`
	out := []Check{}
	if err := a.db.SelectContext(c.ctx(), &out, q, args...); err != nil {
		return nil, err
	}
	names := a.hostNames(c.ctx())
	since := time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02")
	type up struct {
		ID   int64 `db:"item_id"`
		Up   int64 `db:"u"`
		Down int64 `db:"d"`
	}
	var ups []up
	_ = a.db.SelectContext(c.ctx(), &ups, `SELECT item_id, SUM(up_seconds) AS u, SUM(down_seconds) AS d FROM uptime_daily WHERE item_type='check' AND day>=? GROUP BY item_id`, since)
	upm := map[int64]float64{}
	for _, u := range ups {
		if u.Up+u.Down > 0 {
			upm[u.ID] = float64(u.Up) * 100 / float64(u.Up+u.Down)
		}
	}
	for i := range out {
		if out[i].HostID != nil {
			out[i].HostName = names[*out[i].HostID]
		}
		if v, ok := upm[out[i].ID]; ok {
			vv := v
			out[i].Uptime24h = &vv
		}
		a.decorateCheck(c, &out[i])
	}
	return out, nil
}

// decorateCheck is the single response serialiser for checks (list, get,
// create, update and token regeneration). It masks stored credentials in the
// config, hides the push token from read-only users and adds the parent.
func (a *App) decorateCheck(c *Ctx, k *Check) {
	k.Config = JSON(mustJSON(notify.RedactCheckConfig(k.Config)))
	if !c.P.Has(PermMonitoring) {
		k.PushToken = ""
	}
	k.Parent = a.parentInfo(c.ctx(), "check", k.ID)
}

// checkDependency validates the parent named in a request. set is false when
// the request leaves the dependency alone.
func (a *App) checkDependency(c *Ctx, tenant, id int64, req *checkReq) (pt string, pid int64, set bool, err error) {
	d := depRequest{ParentType: req.ParentType, ParentID: req.ParentID}
	if !d.present() {
		return "", 0, false, nil
	}
	pt, pid = d.values()
	if err := a.validateDependency(c.ctx(), tenant, "check", id, pt, pid); err != nil {
		return "", 0, false, err
	}
	return pt, pid, true, nil
}

func (a *App) visibleCheck(c *Ctx, id int64) (*Check, error) {
	var k Check
	if err := a.db.GetContext(c.ctx(), &k, `SELECT * FROM checks WHERE id=?`, id); err != nil || !c.P.CanTenant(k.TenantID) {
		return nil, errNotFound
	}
	return &k, nil
}

func (a *App) apiCreateCheck(c *Ctx) (any, error) {
	var req checkReq
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	tenant, err := a.validateCheck(c, &req)
	if err != nil {
		return nil, err
	}
	enabled := req.Enabled == nil || *req.Enabled
	pt, pid, setDep, err := a.checkDependency(c, tenant, 0, &req)
	if err != nil {
		return nil, err
	}
	var pushTok, pushHash string
	if req.Type == "push" {
		pushTok, pushHash = newPushToken()
	}
	res, err := a.db.ExecContext(c.ctx(), `INSERT INTO checks (tenant_id, host_id, name, type, target, config, interval_seconds, timeout_seconds, failure_threshold, severity, enabled, created_at, push_token, push_token_hash)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, tenant, req.HostID, req.Name, req.Type, req.Target, string(req.Config), req.IntervalSeconds, req.TimeoutSeconds,
		req.FailureThreshold, req.Severity, enabled, db.Now(), pushTok, pushHash)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	if setDep {
		if err := a.setDependency(c.ctx(), tenant, "check", id, pt, pid); err != nil {
			return nil, err
		}
		c.auditDep(tenant, "check", id, pt, pid)
	}
	a.checks.Invalidate(id)
	if req.Type == "service" && req.HostID != nil {
		a.hub.PushConfig(c.ctx(), *req.HostID)
	}
	c.auditT(tenant, "check.created", "check", itoa(id), map[string]any{"name": req.Name, "type": req.Type, "target": req.Target})
	k, err := a.visibleCheck(c, id)
	if err != nil {
		return nil, err
	}
	a.decorateCheck(c, k)
	return created{k}, nil
}

func (a *App) apiGetCheck(c *Ctx) (any, error) {
	k, err := a.visibleCheck(c, c.ID())
	if err != nil {
		return nil, err
	}
	if k.HostID != nil {
		k.HostName = a.hostNames(c.ctx())[*k.HostID]
	}
	a.decorateCheck(c, k)
	return k, nil
}

func (a *App) apiUpdateCheck(c *Ctx) (any, error) {
	k, err := a.visibleCheck(c, c.ID())
	if err != nil {
		return nil, err
	}
	var req checkReq
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	if req.TenantID == 0 {
		req.TenantID = k.TenantID
	}
	tenant, err := a.validateCheck(c, &req)
	if err != nil {
		return nil, err
	}
	cfg := notify.MergeCheckConfig(req.Config, k.Config)
	enabled := req.Enabled == nil || *req.Enabled
	if tenant != k.TenantID {
		// Dependencies never cross tenants.
		a.forgetDependencies(c.ctx(), "check", k.ID)
	}
	pt, pid, setDep, err := a.checkDependency(c, tenant, k.ID, &req)
	if err != nil {
		return nil, err
	}
	pushTok, pushHash := k.PushToken, k.PushTokenHash
	switch {
	case req.Type != "push":
		pushTok, pushHash = "", ""
	case pushTok == "":
		pushTok, pushHash = newPushToken()
	}
	_, err = a.db.ExecContext(c.ctx(), `UPDATE checks SET tenant_id=?, host_id=?, name=?, type=?, target=?, config=?, interval_seconds=?, timeout_seconds=?,
		failure_threshold=?, severity=?, enabled=?, push_token=?, push_token_hash=? WHERE id=?`, tenant, req.HostID, req.Name, req.Type, req.Target, string(cfg), req.IntervalSeconds,
		req.TimeoutSeconds, req.FailureThreshold, req.Severity, enabled, pushTok, pushHash, k.ID)
	if err != nil {
		return nil, err
	}
	if req.Type == "push" && enabled && !k.Enabled {
		// Re-enabled: give the job a fresh window to call in.
		_, _ = a.db.ExecContext(c.ctx(), `UPDATE checks SET last_beat_at=?, last_beat_up=1, last_beat_msg='Check enabled' WHERE id=?`, db.Now(), k.ID)
	}
	if setDep {
		if err := a.setDependency(c.ctx(), tenant, "check", k.ID, pt, pid); err != nil {
			return nil, err
		}
		c.auditDep(tenant, "check", k.ID, pt, pid)
	}
	if !enabled {
		a.alerts.forceResolve(c.ctx(), "check:"+itoa(k.ID), "check disabled", c.P.Name)
		a.alerts.forceResolve(c.ctx(), "check:"+itoa(k.ID)+":cert", "check disabled", c.P.Name)
		_, _ = a.db.ExecContext(c.ctx(), `UPDATE checks SET status='pending', consecutive_failures=0 WHERE id=?`, k.ID)
	}
	a.checks.Invalidate(k.ID)
	if req.HostID != nil {
		a.hub.PushConfig(c.ctx(), *req.HostID)
	}
	c.auditT(tenant, "check.updated", "check", itoa(k.ID), map[string]any{"name": req.Name})
	nk, err := a.visibleCheck(c, k.ID)
	if err != nil {
		return nil, err
	}
	a.decorateCheck(c, nk)
	return nk, nil
}

func (a *App) apiDeleteCheck(c *Ctx) (any, error) {
	k, err := a.visibleCheck(c, c.ID())
	if err != nil {
		return nil, err
	}
	a.alerts.forgetCheck(k.ID)
	if _, err := a.db.ExecContext(c.ctx(), `DELETE FROM checks WHERE id=?`, k.ID); err != nil {
		return nil, err
	}
	a.forgetDependencies(c.ctx(), "check", k.ID)
	_, _ = a.db.ExecContext(c.ctx(), `DELETE FROM uptime_daily WHERE item_type='check' AND item_id=?`, k.ID)
	a.checks.Invalidate(k.ID)
	c.auditT(k.TenantID, "check.deleted", "check", itoa(k.ID), map[string]any{"name": k.Name})
	return nil, nil
}

func (a *App) apiRunCheck(c *Ctx) (any, error) {
	k, err := a.visibleCheck(c, c.ID())
	if err != nil {
		return nil, err
	}
	res, err := a.checks.RunNow(c.ctx(), k)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (a *App) apiCheckHistory(c *Ctx) (any, error) {
	k, err := a.visibleCheck(c, c.ID())
	if err != nil {
		return nil, err
	}
	start, end, step := parseRange(c, 24*time.Hour)
	q := fmt.Sprintf(`%scheck_latency_ms{check_id="%d",tenant_id="%d"}`, metrics.Prefix, k.ID, k.TenantID)
	if step > time.Minute {
		q = fmt.Sprintf("avg_over_time(%s[%ds])", q, int(step.Seconds()))
	}
	lat, err := a.ts.QueryRange(c.ctx(), q, start, end, step)
	if err != nil {
		return nil, err
	}
	upq := fmt.Sprintf(`min_over_time(%scheck_up{check_id="%d",tenant_id="%d"}[%ds])`, metrics.Prefix, k.ID, k.TenantID, int(step.Seconds()))
	up, _ := a.ts.QueryRange(c.ctx(), upq, start, end, step)
	days, pct := a.uptimeDays(c.ctx(), "check", k.ID, 90)
	var latency, upPoints []metrics.Point
	if len(lat) > 0 {
		latency = lat[0].Points
	}
	if len(up) > 0 {
		upPoints = up[0].Points
	}
	if k.Type == "cert" || checkConfig(k).CheckCert {
		q := fmt.Sprintf(`%scheck_cert_days{check_id="%d",tenant_id="%d"}`, metrics.Prefix, k.ID, k.TenantID)
		if s, err := a.ts.QueryInstant(c.ctx(), "last_over_time("+q+"[1d])", time.Now()); err == nil && len(s) > 0 {
			return map[string]any{"latency": latency, "up": upPoints, "uptime_days": days, "uptime_percent": pct, "cert_days": s[0].Points[0][1]}, nil
		}
	}
	return map[string]any{"latency": latency, "up": upPoints, "uptime_days": days, "uptime_percent": pct}, nil
}

// --- thresholds ---

func (a *App) apiThresholdCatalog(c *Ctx) (any, error) { return metricCatalog, nil }

func (a *App) apiListThresholds(c *Ctx) (any, error) {
	// A host rule only counts while its tenant owns the host.
	q := `SELECT * FROM threshold_rules WHERE (scope<>'host' OR EXISTS (SELECT 1 FROM hosts h WHERE h.id=scope_id AND h.tenant_id=threshold_rules.tenant_id))`
	var args []any
	if c.P.TenantID != 0 {
		q += ` AND (tenant_id=? OR (tenant_id=0 AND scope='global'))`
		args = append(args, c.P.TenantID)
	}
	if s := c.Q("scope"); s != "" {
		q += ` AND scope=?`
		args = append(args, s)
	}
	if id := c.QInt("scope_id", -1); id >= 0 {
		q += ` AND scope_id=?`
		args = append(args, id)
	}
	if t := c.Q("tenant_id"); t != "" && c.P.TenantID == 0 {
		q += ` AND tenant_id=?`
		args = append(args, c.QInt("tenant_id", 0))
	}
	q += ` ORDER BY scope, scope_id, metric, label_match`
	out := []ThresholdRule{}
	err := a.db.SelectContext(c.ctx(), &out, q, args...)
	return out, err
}

type thresholdReq struct {
	TenantID   int64    `json:"tenant_id"`
	Scope      string   `json:"scope"`
	ScopeID    int64    `json:"scope_id"`
	Metric     string   `json:"metric"`
	LabelMatch string   `json:"label_match"`
	Warn       *float64 `json:"warn"`
	Crit       *float64 `json:"crit"`
	ForCount   int      `json:"for_count"`
	Enabled    *bool    `json:"enabled"`
	Notify     *bool    `json:"notify"`
}

func (a *App) apiUpsertThreshold(c *Ctx) (any, error) {
	var req thresholdReq
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	def, ok := metricByKey(req.Metric)
	if !ok {
		return nil, badRequest("unknown metric %q", req.Metric)
	}
	if req.LabelMatch != "" && def.LabelKey == "" {
		return nil, badRequest("%s has no per-instance label", def.Name)
	}
	if req.ForCount <= 0 {
		req.ForCount = 1
	}
	if req.ForCount > 100 {
		return nil, badRequest("for_count must be at most 100")
	}
	if req.Warn != nil && req.Crit != nil {
		if def.LowerIsWorse && *req.Warn < *req.Crit || !def.LowerIsWorse && *req.Warn > *req.Crit {
			return nil, badRequest("warning threshold must be less severe than critical")
		}
	}
	var tenant int64
	switch req.Scope {
	case "global":
		t, err := c.tenantFor(req.TenantID)
		if err != nil {
			return nil, err
		}
		tenant = t
		req.ScopeID = 0
	case "group":
		g, err := a.visibleGroup(c, req.ScopeID)
		if err != nil {
			return nil, badRequest("unknown group")
		}
		tenant = g.TenantID
	case "host":
		h, err := c.visibleHost(req.ScopeID)
		if err != nil {
			return nil, badRequest("unknown host")
		}
		tenant = h.TenantID
	default:
		return nil, badRequest("scope must be global, group or host")
	}
	enabled := req.Enabled == nil || *req.Enabled
	notify := req.Notify == nil || *req.Notify
	now := db.Now()
	_, err := a.db.ExecContext(c.ctx(), `INSERT INTO threshold_rules (tenant_id, scope, scope_id, metric, label_match, warn, crit, for_count, enabled, notify, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(tenant_id, scope, scope_id, metric, label_match) DO UPDATE SET warn=excluded.warn, crit=excluded.crit,
		for_count=excluded.for_count, enabled=excluded.enabled, notify=excluded.notify, updated_at=excluded.updated_at`,
		tenant, req.Scope, req.ScopeID, req.Metric, strings.TrimSpace(req.LabelMatch), req.Warn, req.Crit, req.ForCount, enabled, notify, now, now)
	if err != nil {
		return nil, err
	}
	_ = a.alerts.ReloadRules(c.ctx())
	var r ThresholdRule
	_ = a.db.GetContext(c.ctx(), &r, `SELECT * FROM threshold_rules WHERE tenant_id=? AND scope=? AND scope_id=? AND metric=? AND label_match=?`,
		tenant, req.Scope, req.ScopeID, req.Metric, strings.TrimSpace(req.LabelMatch))
	c.auditT(tenant, "threshold.saved", "threshold", itoa(r.ID), req)
	return r, nil
}

func (a *App) apiDeleteThreshold(c *Ctx) (any, error) {
	var r ThresholdRule
	if err := a.db.GetContext(c.ctx(), &r, `SELECT * FROM threshold_rules WHERE id=?`, c.ID()); err != nil || !c.P.CanTenant(r.TenantID) {
		return nil, errNotFound
	}
	if r.Scope == "global" && r.TenantID == 0 && r.LabelMatch == "" {
		return nil, badRequest("provider defaults cannot be deleted; disable or edit them instead")
	}
	if r.Scope == "host" && !c.P.IsProvider() {
		// A rule left behind by a host transfer is not the old tenant's to touch.
		var ht int64
		if err := a.db.GetContext(c.ctx(), &ht, `SELECT tenant_id FROM hosts WHERE id=?`, r.ScopeID); err != nil || ht != r.TenantID {
			return nil, errNotFound
		}
	}
	if _, err := a.db.ExecContext(c.ctx(), `DELETE FROM threshold_rules WHERE id=?`, r.ID); err != nil {
		return nil, err
	}
	_ = a.alerts.ReloadRules(c.ctx())
	c.auditT(r.TenantID, "threshold.deleted", "threshold", itoa(r.ID), r)
	return nil, nil
}

// --- alerts ---

func (a *App) apiListAlerts(c *Ctx) (any, error) {
	status := c.Q("status")
	if status == "" {
		status = "active"
	}
	hostID := c.QInt("host_id", 0)
	sev := c.Q("severity")
	names := a.hostNames(c.ctx())
	var tenantFilter *int64
	if t := c.Q("tenant_id"); t != "" && c.P.IsProvider() {
		v := c.QInt("tenant_id", 0)
		tenantFilter = &v
	}
	keep := func(al *Alert) bool {
		if !c.P.CanTenant(al.TenantID) || (tenantFilter != nil && al.TenantID != *tenantFilter) {
			return false
		}
		if hostID > 0 && (al.HostID == nil || *al.HostID != hostID) {
			return false
		}
		if sev != "" && al.Severity != sev {
			return false
		}
		return true
	}
	out := []Alert{}
	if status == "active" || status == "firing" || status == "pending" {
		for _, al := range a.alerts.Active() {
			if !keep(&al) || (status != "active" && al.Status != status) {
				continue
			}
			if al.HostID != nil {
				al.HostName = names[*al.HostID]
			}
			al.InMaintenance = a.alerts.inMaintenance(&al)
			al.SuppressedBy = a.dependencyReason(&al)
			out = append(out, al)
		}
		sort.SliceStable(out, func(i, j int) bool {
			if out[i].Status != out[j].Status {
				return out[i].Status == "firing"
			}
			if severityRank(out[i].Severity) != severityRank(out[j].Severity) {
				return severityRank(out[i].Severity) > severityRank(out[j].Severity)
			}
			return out[i].StartedAt > out[j].StartedAt
		})
		return out, nil
	}
	tw, args := c.tenantWhere("tenant_id")
	q := `SELECT * FROM alerts WHERE fired_at>0 AND ` + tw
	if status == "resolved" {
		q += ` AND status='resolved'`
	}
	if hostID > 0 {
		q += ` AND host_id=?`
		args = append(args, hostID)
	}
	if sev != "" {
		q += ` AND severity=?`
		args = append(args, sev)
	}
	limit := c.queryLimit("limit", 200, 2000)
	q += ` ORDER BY COALESCE(NULLIF(resolved_at,0), fired_at) DESC LIMIT ?`
	args = append(args, limit)
	if err := a.db.SelectContext(c.ctx(), &out, q, args...); err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].HostID != nil {
			out[i].HostName = names[*out[i].HostID]
		}
	}
	return out, nil
}

func (a *App) apiGetAlert(c *Ctx) (any, error) {
	var al Alert
	if err := a.db.GetContext(c.ctx(), &al, `SELECT * FROM alerts WHERE id=?`, c.ID()); err != nil || !c.P.CanTenant(al.TenantID) {
		return nil, errNotFound
	}
	for _, act := range a.alerts.Active() {
		if act.ID == al.ID {
			al = act
		}
	}
	if al.HostID != nil {
		al.HostName = a.hostNames(c.ctx())[*al.HostID]
	}
	if al.Status == "pending" || al.Status == "firing" {
		al.InMaintenance = a.alerts.inMaintenance(&al)
		al.SuppressedBy = a.dependencyReason(&al)
	}
	events := []AlertEvent{}
	_ = a.db.SelectContext(c.ctx(), &events, `SELECT e.*, '' AS title, '' AS host_name FROM alert_events e WHERE alert_id=? ORDER BY id DESC LIMIT 300`, al.ID)
	return map[string]any{"alert": al, "events": events}, nil
}

type ackReq struct {
	Comment string `json:"comment"`
}

func (a *App) alertTenant(c *Ctx, id int64) (int64, error) {
	var t int64
	if err := a.db.GetContext(c.ctx(), &t, `SELECT tenant_id FROM alerts WHERE id=?`, id); err != nil || !c.P.CanTenant(t) {
		return 0, errNotFound
	}
	return t, nil
}

func (a *App) apiAckAlert(c *Ctx) (any, error) {
	t, err := a.alertTenant(c, c.ID())
	if err != nil {
		return nil, err
	}
	var req ackReq
	_ = c.Decode(&req)
	al, err := a.alerts.Ack(c.ctx(), c.ID(), c.P.Name, truncateStr(req.Comment, 1000))
	if err != nil {
		return nil, badRequest("alert is not active")
	}
	c.auditT(t, "alert.acked", "alert", itoa(c.ID()), map[string]any{"comment": req.Comment, "title": al.Title})
	return al, nil
}

func (a *App) apiUnackAlert(c *Ctx) (any, error) {
	t, err := a.alertTenant(c, c.ID())
	if err != nil {
		return nil, err
	}
	if err := a.alerts.Unack(c.ctx(), c.ID(), c.P.Name); err != nil {
		return nil, badRequest("alert is not active")
	}
	c.auditT(t, "alert.unacked", "alert", itoa(c.ID()), nil)
	return nil, nil
}

func (a *App) apiResolveAlert(c *Ctx) (any, error) {
	t, err := a.alertTenant(c, c.ID())
	if err != nil {
		return nil, err
	}
	if err := a.alerts.ResolveManual(c.ctx(), c.ID(), c.P.Name); err != nil {
		return nil, badRequest("alert is not active")
	}
	c.auditT(t, "alert.resolved", "alert", itoa(c.ID()), nil)
	return nil, nil
}

type bulkAckReq struct {
	IDs     []int64 `json:"ids"`
	Comment string  `json:"comment"`
}

func (a *App) apiBulkAck(c *Ctx) (any, error) {
	var req bulkAckReq
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	n := 0
	for _, id := range req.IDs {
		t, err := a.alertTenant(c, id)
		if err != nil {
			continue
		}
		if _, err := a.alerts.Ack(c.ctx(), id, c.P.Name, req.Comment); err == nil {
			n++
			c.auditT(t, "alert.acked", "alert", itoa(id), map[string]any{"comment": req.Comment})
		}
	}
	return map[string]int{"acked": n}, nil
}

func (a *App) apiAlertEvents(c *Ctx) (any, error) {
	tw, args := c.tenantWhere("e.tenant_id")
	q := `SELECT e.*, al.title, COALESCE(h.name,'') AS host_name FROM alert_events e JOIN alerts al ON al.id=e.alert_id LEFT JOIN hosts h ON h.id=e.host_id WHERE ` + tw
	if h := c.QInt("host_id", 0); h > 0 {
		q += ` AND e.host_id=?`
		args = append(args, h)
	}
	if b := c.QInt("before", 0); b > 0 {
		q += ` AND e.id<?`
		args = append(args, b)
	}
	limit := c.queryLimit("limit", 100, 1000)
	q += ` ORDER BY e.id DESC LIMIT ?`
	args = append(args, limit)
	out := []AlertEvent{}
	err := a.db.SelectContext(c.ctx(), &out, q, args...)
	return out, err
}

// --- maintenance ---

type maintReq struct {
	TenantID        int64   `json:"tenant_id"`
	Name            string  `json:"name"`
	Scope           string  `json:"scope"`
	ScopeIDs        []int64 `json:"scope_ids"`
	StartsAt        int64   `json:"starts_at"`
	EndsAt          int64   `json:"ends_at"`
	Recurrence      string  `json:"recurrence"`
	Weekdays        []int64 `json:"weekdays"`
	StartTime       string  `json:"start_time"`
	DurationMinutes int     `json:"duration_minutes"`
	Timezone        string  `json:"timezone"`
	SuppressAlerts  *bool   `json:"suppress_alerts"`
	AllowJobs       *bool   `json:"allow_jobs"`
	Enabled         *bool   `json:"enabled"`
}

func (a *App) validateMaint(c *Ctx, req *maintReq) (int64, error) {
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		return 0, badRequest("name is required")
	}
	tenant, err := c.tenantFor(req.TenantID)
	if err != nil {
		return 0, err
	}
	switch req.Scope {
	case "all":
		if !c.P.IsProvider() {
			req.Scope = "tenant"
			req.ScopeIDs = []int64{tenant}
		}
	case "tenant":
		if !c.P.IsProvider() {
			req.ScopeIDs = []int64{tenant}
		}
	case "group":
		for _, id := range req.ScopeIDs {
			if _, err := a.visibleGroup(c, id); err != nil {
				return 0, badRequest("unknown group %d", id)
			}
		}
	case "host":
		for _, id := range req.ScopeIDs {
			if _, err := c.visibleHost(id); err != nil {
				return 0, badRequest("unknown host %d", id)
			}
		}
	default:
		return 0, badRequest("scope must be all, tenant, group or host")
	}
	if (req.Scope == "group" || req.Scope == "host") && len(req.ScopeIDs) == 0 {
		return 0, badRequest("choose at least one %s", req.Scope)
	}
	if req.Timezone == "" {
		req.Timezone = a.settings.General().Timezone
	}
	if _, err := time.LoadLocation(req.Timezone); err != nil {
		return 0, badRequest("unknown timezone")
	}
	switch req.Recurrence {
	case "", "none":
		req.Recurrence = "none"
		if req.EndsAt <= req.StartsAt {
			return 0, badRequest("end must be after start")
		}
	case "daily", "weekly", "monthly":
		if _, _, ok := parseHHMM(req.StartTime); !ok {
			return 0, badRequest("start time must be HH:MM")
		}
		if req.DurationMinutes < 1 || req.DurationMinutes > 7*24*60 {
			return 0, badRequest("duration must be 1 minute to 7 days")
		}
		if req.Recurrence == "weekly" && len(req.Weekdays) == 0 {
			return 0, badRequest("choose at least one weekday")
		}
		if req.StartsAt == 0 {
			req.StartsAt = time.Now().Unix()
		}
	default:
		return 0, badRequest("recurrence must be none, daily, weekly or monthly")
	}
	return tenant, nil
}

func (a *App) apiListMaintenance(c *Ctx) (any, error) {
	tw, args := c.tenantWhere("tenant_id")
	out := []MaintenanceWindow{}
	if err := a.db.SelectContext(c.ctx(), &out, `SELECT * FROM maintenance_windows WHERE `+tw+` ORDER BY starts_at DESC`, args...); err != nil {
		return nil, err
	}
	now := time.Now()
	for i := range out {
		out[i].Decorate(now)
	}
	return out, nil
}

func boolOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

func (a *App) apiCreateMaintenance(c *Ctx) (any, error) {
	var req maintReq
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	tenant, err := a.validateMaint(c, &req)
	if err != nil {
		return nil, err
	}
	res, err := a.db.ExecContext(c.ctx(), `INSERT INTO maintenance_windows (tenant_id, name, scope, scope_ids, starts_at, ends_at, recurrence, weekdays, start_time,
		duration_minutes, timezone, suppress_alerts, allow_jobs, enabled, created_by, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		tenant, req.Name, req.Scope, IntList(req.ScopeIDs), req.StartsAt, req.EndsAt, req.Recurrence, IntList(req.Weekdays), req.StartTime, req.DurationMinutes,
		req.Timezone, boolOr(req.SuppressAlerts, true), boolOr(req.AllowJobs, true), boolOr(req.Enabled, true), c.P.Name, db.Now())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	a.maint.refresh(c.ctx())
	c.auditT(tenant, "maintenance.created", "maintenance", itoa(id), req)
	var w MaintenanceWindow
	_ = a.db.GetContext(c.ctx(), &w, `SELECT * FROM maintenance_windows WHERE id=?`, id)
	w.Decorate(time.Now())
	return created{w}, nil
}

func (a *App) visibleMaint(c *Ctx, id int64) (*MaintenanceWindow, error) {
	var w MaintenanceWindow
	if err := a.db.GetContext(c.ctx(), &w, `SELECT * FROM maintenance_windows WHERE id=?`, id); err != nil || !c.P.CanTenant(w.TenantID) {
		return nil, errNotFound
	}
	return &w, nil
}

func (a *App) apiUpdateMaintenance(c *Ctx) (any, error) {
	w, err := a.visibleMaint(c, c.ID())
	if err != nil {
		return nil, err
	}
	var req maintReq
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	req.TenantID = w.TenantID
	if _, err := a.validateMaint(c, &req); err != nil {
		return nil, err
	}
	_, err = a.db.ExecContext(c.ctx(), `UPDATE maintenance_windows SET name=?, scope=?, scope_ids=?, starts_at=?, ends_at=?, recurrence=?, weekdays=?, start_time=?,
		duration_minutes=?, timezone=?, suppress_alerts=?, allow_jobs=?, enabled=? WHERE id=?`,
		req.Name, req.Scope, IntList(req.ScopeIDs), req.StartsAt, req.EndsAt, req.Recurrence, IntList(req.Weekdays), req.StartTime, req.DurationMinutes,
		req.Timezone, boolOr(req.SuppressAlerts, true), boolOr(req.AllowJobs, true), boolOr(req.Enabled, true), w.ID)
	a.maint.refresh(c.ctx())
	c.auditT(w.TenantID, "maintenance.updated", "maintenance", itoa(w.ID), req)
	return nil, err
}

func (a *App) apiDeleteMaintenance(c *Ctx) (any, error) {
	w, err := a.visibleMaint(c, c.ID())
	if err != nil {
		return nil, err
	}
	_, err = a.db.ExecContext(c.ctx(), `DELETE FROM maintenance_windows WHERE id=?`, w.ID)
	a.maint.refresh(c.ctx())
	c.auditT(w.TenantID, "maintenance.deleted", "maintenance", itoa(w.ID), map[string]any{"name": w.Name})
	return nil, err
}

// --- notification channels ---

type channelReq struct {
	TenantID      int64           `json:"tenant_id"`
	Name          string          `json:"name"`
	Type          string          `json:"type"`
	Config        json.RawMessage `json:"config"`
	MinSeverity   string          `json:"min_severity"`
	SendResolved  *bool           `json:"send_resolved"`
	RepeatMinutes *int            `json:"repeat_minutes"`
	FilterGroups  []int64         `json:"filter_groups"`
	FilterTags    []string        `json:"filter_tags"`
	FilterHosts   []int64         `json:"filter_hosts"`
	Enabled       *bool           `json:"enabled"`
	ChannelID     int64           `json:"channel_id"` // for testing an edit with stored secrets
}

func (a *App) apiListChannels(c *Ctx) (any, error) {
	tw, args := c.tenantWhere("tenant_id")
	out := []NotificationChannel{}
	if err := a.db.SelectContext(c.ctx(), &out, `SELECT * FROM notification_channels WHERE `+tw+` ORDER BY name COLLATE NOCASE`, args...); err != nil {
		return nil, err
	}
	for i := range out {
		channelView(&out[i])
	}
	return out, nil
}

// channelView is the single response serialiser for notification channels
// (list, create and update): stored credentials never leave the server.
func channelView(ch *NotificationChannel) *NotificationChannel {
	ch.Config = JSON(mustJSON(notify.RedactConfig(ch.Type, ch.Config)))
	return ch
}

func (a *App) validateChannel(c *Ctx, req *channelReq, existing []byte) (int64, []byte, error) {
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		return 0, nil, badRequest("name is required")
	}
	if len(req.Config) == 0 {
		req.Config = json.RawMessage("{}")
	}
	cfg := []byte(req.Config)
	if existing != nil {
		cfg = notify.MergeConfig(req.Type, cfg, existing)
	}
	if err := notify.Validate(req.Type, cfg); err != nil {
		return 0, nil, badRequest("%v", err)
	}
	if req.MinSeverity == "" {
		req.MinSeverity = "warning"
	}
	if req.MinSeverity != "warning" && req.MinSeverity != "critical" {
		return 0, nil, badRequest("min_severity must be warning or critical")
	}
	tenant, err := c.tenantFor(req.TenantID)
	return tenant, cfg, err
}

func (a *App) apiCreateChannel(c *Ctx) (any, error) {
	var req channelReq
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	tenant, cfg, err := a.validateChannel(c, &req, nil)
	if err != nil {
		return nil, err
	}
	repeat := a.alerting().DefaultRepeatMinutes
	if req.RepeatMinutes != nil {
		repeat = *req.RepeatMinutes
	}
	res, err := a.db.ExecContext(c.ctx(), `INSERT INTO notification_channels (tenant_id, name, type, config, min_severity, send_resolved, repeat_minutes, filter_groups,
		filter_tags, filter_hosts, enabled, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		tenant, req.Name, req.Type, string(cfg), req.MinSeverity, boolOr(req.SendResolved, true), repeat, IntList(req.FilterGroups),
		StrList(req.FilterTags), IntList(req.FilterHosts), boolOr(req.Enabled, true), db.Now())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	a.notifier.Invalidate()
	c.auditT(tenant, "channel.created", "channel", itoa(id), map[string]any{"name": req.Name, "type": req.Type})
	nc, err := a.visibleChannel(c, id)
	if err != nil {
		return nil, err
	}
	return created{channelView(nc)}, nil
}

func (a *App) visibleChannel(c *Ctx, id int64) (*NotificationChannel, error) {
	var ch NotificationChannel
	if err := a.db.GetContext(c.ctx(), &ch, `SELECT * FROM notification_channels WHERE id=?`, id); err != nil || !c.P.CanTenant(ch.TenantID) {
		return nil, errNotFound
	}
	return &ch, nil
}

func (a *App) apiUpdateChannel(c *Ctx) (any, error) {
	ch, err := a.visibleChannel(c, c.ID())
	if err != nil {
		return nil, err
	}
	var req channelReq
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	req.TenantID = ch.TenantID
	if req.Type == "" {
		req.Type = ch.Type
	}
	_, cfg, err := a.validateChannel(c, &req, ch.Config)
	if err != nil {
		return nil, err
	}
	repeat := ch.RepeatMinutes
	if req.RepeatMinutes != nil {
		repeat = *req.RepeatMinutes
	}
	_, err = a.db.ExecContext(c.ctx(), `UPDATE notification_channels SET name=?, type=?, config=?, min_severity=?, send_resolved=?, repeat_minutes=?, filter_groups=?,
		filter_tags=?, filter_hosts=?, enabled=? WHERE id=?`, req.Name, req.Type, string(cfg), req.MinSeverity, boolOr(req.SendResolved, true), repeat,
		IntList(req.FilterGroups), StrList(req.FilterTags), IntList(req.FilterHosts), boolOr(req.Enabled, true), ch.ID)
	if err != nil {
		return nil, err
	}
	a.notifier.Invalidate()
	c.auditT(ch.TenantID, "channel.updated", "channel", itoa(ch.ID), map[string]any{"name": req.Name})
	nc, err := a.visibleChannel(c, ch.ID)
	if err != nil {
		return nil, err
	}
	return channelView(nc), nil
}

func (a *App) apiDeleteChannel(c *Ctx) (any, error) {
	ch, err := a.visibleChannel(c, c.ID())
	if err != nil {
		return nil, err
	}
	_, err = a.db.ExecContext(c.ctx(), `DELETE FROM notification_channels WHERE id=?`, ch.ID)
	a.notifier.Invalidate()
	c.auditT(ch.TenantID, "channel.deleted", "channel", itoa(ch.ID), map[string]any{"name": ch.Name})
	return nil, err
}

func (a *App) apiTestChannel(c *Ctx) (any, error) {
	ch, err := a.visibleChannel(c, c.ID())
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(c.ctx(), 30*time.Second)
	defer cancel()
	if err := a.notifier.SendTest(ctx, *ch); err != nil {
		_, _ = a.db.ExecContext(c.ctx(), `UPDATE notification_channels SET last_error=? WHERE id=?`, err.Error(), ch.ID)
		return map[string]any{"ok": false, "error": err.Error()}, nil
	}
	_, _ = a.db.ExecContext(c.ctx(), `UPDATE notification_channels SET last_error='', last_sent_at=? WHERE id=?`, db.Now(), ch.ID)
	return map[string]any{"ok": true}, nil
}

func (a *App) apiTestChannelConfig(c *Ctx) (any, error) {
	var req channelReq
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	var existing []byte
	var existingTenant int64 = -1
	if req.ChannelID != 0 {
		ch, err := a.visibleChannel(c, req.ChannelID)
		if err != nil {
			return nil, err
		}
		existing = ch.Config
		existingTenant = ch.TenantID
	}
	if req.Name == "" {
		req.Name = "Unsaved channel"
	}
	tenant, cfg, err := a.validateChannel(c, &req, existing)
	if err != nil {
		return nil, err
	}
	if existingTenant >= 0 {
		tenant = existingTenant
	}
	ctx, cancel := context.WithTimeout(c.ctx(), 30*time.Second)
	defer cancel()
	if err := a.notifier.SendTest(ctx, NotificationChannel{TenantID: tenant, Name: req.Name, Type: req.Type, Config: cfg}); err != nil {
		return map[string]any{"ok": false, "error": err.Error()}, nil
	}
	return map[string]any{"ok": true}, nil
}

func (a *App) apiNotificationLog(c *Ctx) (any, error) {
	tw, args := c.tenantWhere("l.tenant_id")
	type row struct {
		ID        int64   `db:"id" json:"id"`
		ChannelID *int64  `db:"channel_id" json:"channel_id"`
		Channel   string  `db:"channel" json:"channel"`
		AlertIDs  IntList `db:"alert_ids" json:"alert_ids"`
		Status    string  `db:"status" json:"status"`
		Error     string  `db:"error" json:"error"`
		CreatedAt int64   `db:"created_at" json:"created_at"`
	}
	out := []row{}
	err := a.db.SelectContext(c.ctx(), &out, `SELECT l.id, l.channel_id, COALESCE(ch.name,'') AS channel, l.alert_ids, l.status, l.error, l.created_at
		FROM notification_log l LEFT JOIN notification_channels ch ON ch.id=l.channel_id WHERE `+tw+` ORDER BY l.id DESC LIMIT 200`, args...)
	return out, err
}

// --- metrics query ---

// injectTenant adds tenant_id="<t>" to every selector in a PromQL expression.
func injectTenant(q string, tenant int64) (string, error) {
	expr, err := metrics.ParseExpr(q)
	if err != nil {
		return "", err
	}
	m := labels.MustNewMatcher(labels.MatchEqual, "tenant_id", itoa(tenant))
	parser.Inspect(expr, func(n parser.Node, _ []parser.Node) error {
		if vs, ok := n.(*parser.VectorSelector); ok {
			kept := vs.LabelMatchers[:0]
			for _, lm := range vs.LabelMatchers {
				if lm.Name != "tenant_id" {
					kept = append(kept, lm)
				}
			}
			vs.LabelMatchers = append(kept, m)
		}
		return nil
	})
	return expr.String(), nil
}

func (a *App) apiMetricQuery(c *Ctx) (any, error) {
	q := strings.TrimSpace(c.Q("query"))
	if q == "" {
		return nil, badRequest("query is required")
	}
	if c.P.TenantID != 0 {
		var err error
		if q, err = injectTenant(q, c.P.TenantID); err != nil {
			return nil, badRequest("query: %v", err)
		}
	} else if t := c.Q("tenant_id"); t != "" {
		var err error
		if q, err = injectTenant(q, c.QInt("tenant_id", 0)); err != nil {
			return nil, badRequest("query: %v", err)
		}
	}
	start, end, step := parseRange(c, time.Hour)
	res, err := a.ts.QueryRange(c.ctx(), q, start, end, step)
	if err != nil {
		return nil, badRequest("query: %v", err)
	}
	return map[string]any{"query": q, "series": res, "step": int(step.Seconds())}, nil
}

func (a *App) apiMetricNames(c *Ctx) (any, error) {
	q := `count by (__name__) ({__name__=~"sentrel_.+"})`
	if c.P.TenantID != 0 {
		q = fmt.Sprintf(`count by (__name__) ({__name__=~"sentrel_.+",tenant_id="%d"})`, c.P.TenantID)
	}
	res, err := a.ts.QueryInstant(c.ctx(), q, time.Now())
	if err != nil {
		return nil, err
	}
	names := []string{}
	for _, s := range res {
		names = append(names, s.Labels["__name__"])
	}
	sort.Strings(names)
	return names, nil
}
