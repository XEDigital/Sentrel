package app

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"time"

	"sentrel/server/db"
)

// --- jobs ---

func (a *App) apiListJobs(c *Ctx) (any, error) {
	tw, args := c.tenantWhere("j.tenant_id")
	q := `SELECT ` + jobCols + `, COALESCE(h.name,'') AS host_name FROM jobs j LEFT JOIN hosts h ON h.id=j.host_id WHERE ` + tw
	if h := c.QInt("host_id", 0); h > 0 {
		q += ` AND j.host_id=?`
		args = append(args, h)
	}
	if s := c.Q("status"); s != "" {
		q += ` AND j.status=?`
		args = append(args, s)
	}
	if t := c.Q("type"); t != "" {
		q += ` AND j.type=?`
		args = append(args, t)
	}
	limit := c.queryLimit("limit", 200, 1000)
	q += ` ORDER BY j.created_at DESC LIMIT ?`
	args = append(args, limit)
	out := []Job{}
	err := a.db.SelectContext(c.ctx(), &out, q, args...)
	return out, err
}

func (a *App) apiCreateJob(c *Ctx) (any, error) {
	var req JobRequest
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	j, err := a.jobs.Create(c.ctx(), c.P, req)
	if err != nil {
		return nil, err
	}
	return created{j}, nil
}

type bulkJobReq struct {
	JobRequest
	HostIDs []int64 `json:"host_ids"`
}

func (a *App) apiBulkJobs(c *Ctx) (any, error) {
	var req bulkJobReq
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	if len(req.HostIDs) == 0 || len(req.HostIDs) > 1000 {
		return nil, badRequest("choose 1-1000 hosts")
	}
	type res struct {
		HostID int64  `json:"host_id"`
		JobID  string `json:"job_id,omitempty"`
		Status string `json:"status,omitempty"`
		Error  string `json:"error,omitempty"`
	}
	out := []res{}
	for _, id := range req.HostIDs {
		r := req.JobRequest
		r.HostID = id
		j, err := a.jobs.Create(c.ctx(), c.P, r)
		if err != nil {
			out = append(out, res{HostID: id, Error: err.Error()})
			continue
		}
		out = append(out, res{HostID: id, JobID: j.ID, Status: j.Status})
	}
	return out, nil
}

func (a *App) apiGetJob(c *Ctx) (any, error) {
	j, err := a.getJob(c.ctx(), c.Param("id"))
	if err != nil || !c.P.CanTenant(j.TenantID) {
		return nil, errNotFound
	}
	if j.Type == "script" { // historical jobs from before the feature was removed
		var p map[string]string
		_ = json.Unmarshal(j.Params, &p)
		if p != nil {
			p["script"] = "(removed)"
			j.Params = JSON(mustJSON(p))
		}
	}
	if j.Type == "self_update" {
		var p map[string]string
		_ = json.Unmarshal(j.Params, &p)
		delete(p, "signature")
		j.Params = JSON(mustJSON(p))
	}
	return j, nil
}

func (a *App) apiJobSpec(c *Ctx) (any, error) {
	return a.jobs.JobSpecFor(c.ctx(), c.P, c.Param("id"))
}

func (a *App) apiOperatorSignature(c *Ctx) (any, error) {
	var req OperatorSignRequest
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	return a.jobs.OperatorSign(c.ctx(), c.P, c.Param("id"), req)
}

func (a *App) apiCancelJob(c *Ctx) (any, error) {
	j, err := a.getJob(c.ctx(), c.Param("id"))
	if err != nil || !c.P.CanTenant(j.TenantID) {
		return nil, errNotFound
	}
	return nil, a.jobs.Cancel(c.ctx(), c.P, j.ID)
}

// --- vulnerabilities ---

func (a *App) apiListFindings(c *Ctx) (any, error) {
	if !a.vuln.Enabled() {
		return []VulnFinding{}, nil
	}
	// One row per CVE per host: a source package usually ships several binary
	// packages (linux-headers, linux-modules, ...) that share a CVE.
	tw, args := c.tenantWhere("f.tenant_id")
	q := `SELECT MIN(f.id) AS id, f.tenant_id, f.host_id, f.vuln_id, GROUP_CONCAT(f.package, ', ') AS package, MIN(f.version) AS version,
		MAX(f.fixed_version) AS fixed_version, MAX(f.fix_state) AS fix_state, ` + sevAggSQL + ` AS severity, MAX(f.cvss) AS cvss,
		MAX(f.cvss_vector) AS cvss_vector, MAX(f.epss) AS epss, MAX(f.kev) AS kev, MAX(f.description) AS description, MIN(f.urls) AS urls,
		MIN(f.namespace) AS namespace, MIN(f.status) AS status, MIN(f.first_seen_at) AS first_seen_at, MAX(f.last_seen_at) AS last_seen_at,
		MAX(f.fixed_at) AS fixed_at, COALESCE(h.name,'') AS host_name FROM vuln_findings f LEFT JOIN hosts h ON h.id=f.host_id WHERE COALESCE(h.revoked,0)=0 AND ` + tw
	if h := c.QInt("host_id", 0); h > 0 {
		q += ` AND f.host_id=?`
		args = append(args, h)
	}
	var hargs []any
	status := c.Q("status")
	if status == "" {
		status = "open"
	}
	if status != "all" {
		q += ` AND f.status=?`
		args = append(args, status)
	}
	var having string
	if s := c.Q("severity"); s != "" {
		// The filter applies to the CVE's highest severity, as in the counts.
		sev := strings.Split(s, ",")
		having = ` HAVING ` + sevAggSQL + ` IN (` + strings.TrimRight(strings.Repeat("?,", len(sev)), ",") + `)`
		for _, x := range sev {
			hargs = append(hargs, x)
		}
	}
	fixableOnly := c.Q("fixable") == "1"
	if c.Q("kev") == "1" {
		q += ` AND f.kev=1`
	}
	if s := strings.TrimSpace(c.Q("q")); s != "" {
		q += ` AND (f.vuln_id LIKE ? OR f.package LIKE ?)`
		args = append(args, "%"+s+"%", "%"+s+"%")
	}
	limit := c.queryLimit("limit", 500, 5000)
	q += ` GROUP BY f.host_id, f.vuln_id` + having + ` ORDER BY MAX(` + sevRank("f.severity") + `) DESC,
		MAX(f.kev) DESC, MAX(f.cvss) DESC, f.vuln_id LIMIT ?`
	skipInactive := c.Q("inactive") == "0"
	sqlLimit := limit
	if skipInactive || fixableOnly {
		sqlLimit = 5000 // inactive and fixable are only known after decoration
	}
	args = append(args, hargs...)
	args = append(args, sqlLimit)
	out := []VulnFinding{}
	err := a.db.SelectContext(c.ctx(), &out, q, args...)
	if err != nil {
		return nil, err
	}
	a.decorateFindings(c, out)
	if skipInactive || fixableOnly {
		kept := out[:0]
		for _, f := range out {
			if skipInactive && f.Inactive {
				continue
			}
			if fixableOnly && !actionable(&f) {
				continue
			}
			kept = append(kept, f)
		}
		out = kept
		if int64(len(out)) > int64(limit) {
			out = out[:limit]
		}
	}
	return out, nil
}

func (a *App) apiVulnSummary(c *Ctx) (any, error) {
	type row struct {
		HostID   int64  `json:"host_id"`
		HostName string `json:"host_name"`
		vulnCounts
		LastScan   int64  `json:"last_scan"`
		LastStatus string `json:"last_status"`
		LastError  string `json:"last_error"`
	}
	out := []row{}
	var total vulnCounts
	enabled := a.settings.Vuln().Enabled
	for _, h := range a.visibleAgentHosts(c) {
		r := row{HostID: h.ID, HostName: h.Name}
		if enabled {
			r.vulnCounts = a.hostVulnCounts(c.ctx(), h)
		}
		total.add(r.vulnCounts)
		_ = a.db.GetContext(c.ctx(), &r.LastScan, `SELECT COALESCE(MAX(started_at),0) FROM vuln_scans WHERE host_id=?`, h.ID)
		var last struct {
			Status string `db:"status"`
			Error  string `db:"error"`
		}
		if err := a.db.GetContext(c.ctx(), &last, `SELECT status, error FROM vuln_scans WHERE host_id=? ORDER BY id DESC LIMIT 1`, h.ID); err == nil {
			r.LastStatus, r.LastError = last.Status, last.Error
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Critical != out[j].Critical {
			return out[i].Critical > out[j].Critical
		}
		if out[i].High != out[j].High {
			return out[i].High > out[j].High
		}
		return out[i].HostName < out[j].HostName
	})
	return map[string]any{"hosts": out, "totals": total, "db": a.vuln.Status(), "queue": a.vuln.QueueLength(), "enabled": enabled}, nil
}

type findingUpdate struct {
	Status string `json:"status"` // open, ignored
	Reason string `json:"reason"`
}

func (a *App) apiUpdateFinding(c *Ctx) (any, error) {
	var f VulnFinding
	if err := a.db.GetContext(c.ctx(), &f, `SELECT *, '' AS host_name FROM vuln_findings WHERE id=?`, c.ID()); err != nil || !c.P.CanTenant(f.TenantID) {
		return nil, errNotFound
	}
	var req findingUpdate
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	if req.Status != "open" && req.Status != "ignored" {
		return nil, badRequest("status must be open or ignored")
	}
	if _, err := a.db.ExecContext(c.ctx(), `UPDATE vuln_findings SET status=? WHERE host_id=? AND vuln_id=? AND status<>'fixed'`, req.Status, f.HostID, f.VulnID); err != nil {
		return nil, err
	}
	if h, err := a.getHost(c.ctx(), f.HostID); err == nil {
		a.vuln.evaluate(c.ctx(), h)
	}
	c.auditT(f.TenantID, "vuln.finding_"+req.Status, "finding", itoa(f.ID), map[string]any{"vuln": f.VulnID, "package": f.Package, "reason": req.Reason})
	return nil, nil
}

// scanTargets returns the ids of the hosts a scan-all covers: the visible,
// non-revoked agent hosts.
func (a *App) scanTargets(ctx context.Context, tw string, args []any) []int64 {
	var ids []int64
	_ = a.db.SelectContext(ctx, &ids, `SELECT id FROM hosts WHERE kind='agent' AND revoked=0 AND `+tw, args...)
	return ids
}

func (a *App) apiScanAll(c *Ctx) (any, error) {
	if !a.vuln.Enabled() {
		return nil, conflict(msgVulnDisabled)
	}
	tw, args := c.tenantWhere("tenant_id")
	n := 0
	for _, id := range a.scanTargets(c.ctx(), tw, args) {
		if a.vuln.enqueue(id, "manual") {
			n++
		}
	}
	c.audit("vuln.scan_all", "", "", map[string]int{"queued": n})
	return map[string]int{"queued": n}, nil
}

func (a *App) apiVulnDBStatus(c *Ctx) (any, error) {
	out := a.vuln.RefreshStatus()
	out["enabled"], out["db"], out["queue"], out["settings"] = a.vuln.Enabled(), a.vuln.Status(), a.vuln.QueueLength(), a.settings.Vuln()
	return out, nil
}

func (a *App) apiVulnDBSync(c *Ctx) (any, error) {
	if !a.vuln.Enabled() {
		return nil, conflict(msgVulnDisabled)
	}
	if err := a.vuln.SyncNow(); err != nil {
		return nil, conflict(err.Error())
	}
	c.audit("vulndb.sync_requested", "", "", nil)
	return map[string]bool{"started": true}, nil
}

// apiVulnRefresh updates the DB and then scans every visible host, on the server.
func (a *App) apiVulnRefresh(c *Ctx) (any, error) {
	if !a.vuln.Enabled() {
		return nil, conflict(msgVulnDisabled)
	}
	tw, args := c.tenantWhere("tenant_id")
	if err := a.vuln.Refresh(func() []int64 { return a.scanTargets(context.Background(), tw, args) }); err != nil {
		return nil, conflict(err.Error())
	}
	c.audit("vulndb.refresh_requested", "", "", nil)
	return map[string]bool{"started": true}, nil
}

func (a *App) apiListScans(c *Ctx) (any, error) {
	tw, args := c.tenantWhere("s.tenant_id")
	q := `SELECT s.*, COALESCE(h.name,'') AS host_name FROM vuln_scans s LEFT JOIN hosts h ON h.id=s.host_id WHERE ` + tw
	if h := c.QInt("host_id", 0); h > 0 {
		q += ` AND s.host_id=?`
		args = append(args, h)
	}
	q += ` ORDER BY s.id DESC LIMIT 200`
	out := []VulnScan{}
	err := a.db.SelectContext(c.ctx(), &out, q, args...)
	return out, err
}

type vulnScheduleReq struct {
	TenantID  int64  `json:"tenant_id"`
	Scope     string `json:"scope"`
	ScopeID   int64  `json:"scope_id"`
	Frequency string `json:"frequency"`
	Weekday   int    `json:"weekday"`
	TimeOfDay string `json:"time_of_day"`
	Enabled   *bool  `json:"enabled"`
}

// validateScheduleScope resolves the tenant and checks the scope of a schedule.
// Non-provider callers are narrowed to their own tenant.
func (a *App) validateScheduleScope(c *Ctx, tenantID int64, scope *string, scopeID *int64) (int64, error) {
	tenant, err := c.tenantFor(tenantID)
	if err != nil {
		return 0, err
	}
	switch *scope {
	case "all":
		if !c.P.IsProvider() {
			*scope, *scopeID = "tenant", tenant
		}
	case "tenant":
		if !c.P.IsProvider() {
			*scopeID = tenant
		}
	case "group":
		if _, err := a.visibleGroup(c, *scopeID); err != nil {
			return 0, badRequest("unknown group")
		}
	case "host":
		if _, err := c.visibleHost(*scopeID); err != nil {
			return 0, badRequest("unknown host")
		}
	default:
		return 0, badRequest("scope must be all, tenant, group or host")
	}
	return tenant, nil
}

func (a *App) validateVulnSchedule(c *Ctx, req *vulnScheduleReq) (int64, error) {
	tenant, err := a.validateScheduleScope(c, req.TenantID, &req.Scope, &req.ScopeID)
	if err != nil {
		return 0, err
	}
	if req.Frequency != "daily" && req.Frequency != "weekly" {
		return 0, badRequest("frequency must be daily or weekly")
	}
	if req.Weekday < 0 || req.Weekday > 6 {
		return 0, badRequest("weekday must be 0-6")
	}
	if _, _, ok := parseHHMM(req.TimeOfDay); !ok {
		return 0, badRequest("time must be HH:MM")
	}
	return tenant, nil
}

func (a *App) apiListVulnSchedules(c *Ctx) (any, error) {
	tw, args := c.tenantWhere("tenant_id")
	out := []VulnSchedule{}
	err := a.db.SelectContext(c.ctx(), &out, `SELECT * FROM vuln_schedules WHERE `+tw+` ORDER BY id`, args...)
	return out, err
}

func (a *App) apiCreateVulnSchedule(c *Ctx) (any, error) {
	var req vulnScheduleReq
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	tenant, err := a.validateVulnSchedule(c, &req)
	if err != nil {
		return nil, err
	}
	res, err := a.db.ExecContext(c.ctx(), `INSERT INTO vuln_schedules (tenant_id, scope, scope_id, frequency, weekday, time_of_day, enabled, created_at) VALUES (?,?,?,?,?,?,?,?)`,
		tenant, req.Scope, req.ScopeID, req.Frequency, req.Weekday, req.TimeOfDay, boolOr(req.Enabled, true), db.Now())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	c.auditT(tenant, "vuln.schedule_created", "vuln_schedule", itoa(id), req)
	var s VulnSchedule
	err = a.db.GetContext(c.ctx(), &s, `SELECT * FROM vuln_schedules WHERE id=?`, id)
	return created{s}, err
}

func (a *App) apiUpdateVulnSchedule(c *Ctx) (any, error) {
	var s VulnSchedule
	if err := a.db.GetContext(c.ctx(), &s, `SELECT * FROM vuln_schedules WHERE id=?`, c.ID()); err != nil || !c.P.CanTenant(s.TenantID) {
		return nil, errNotFound
	}
	var req vulnScheduleReq
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	req.TenantID = s.TenantID
	if _, err := a.validateVulnSchedule(c, &req); err != nil {
		return nil, err
	}
	_, err := a.db.ExecContext(c.ctx(), `UPDATE vuln_schedules SET scope=?, scope_id=?, frequency=?, weekday=?, time_of_day=?, enabled=? WHERE id=?`,
		req.Scope, req.ScopeID, req.Frequency, req.Weekday, req.TimeOfDay, boolOr(req.Enabled, true), s.ID)
	c.auditT(s.TenantID, "vuln.schedule_updated", "vuln_schedule", itoa(s.ID), req)
	return nil, err
}

func (a *App) apiDeleteVulnSchedule(c *Ctx) (any, error) {
	var s VulnSchedule
	if err := a.db.GetContext(c.ctx(), &s, `SELECT * FROM vuln_schedules WHERE id=?`, c.ID()); err != nil || !c.P.CanTenant(s.TenantID) {
		return nil, errNotFound
	}
	_, err := a.db.ExecContext(c.ctx(), `DELETE FROM vuln_schedules WHERE id=?`, s.ID)
	c.auditT(s.TenantID, "vuln.schedule_deleted", "vuln_schedule", itoa(s.ID), nil)
	return nil, err
}

// --- status pages ---

type statusPageReq struct {
	TenantID     int64            `json:"tenant_id"`
	Slug         string           `json:"slug"`
	Title        string           `json:"title"`
	Description  string           `json:"description"`
	Public       *bool            `json:"public"`
	Items        []StatusPageItem `json:"items"`
	ShowHistory  *bool            `json:"show_history"`
	Announcement string           `json:"announcement"`
	RegenToken   bool             `json:"regenerate_token"`
}

var slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)

func (a *App) validateStatusPage(c *Ctx, req *statusPageReq) (int64, error) {
	req.Slug = strings.ToLower(strings.TrimSpace(req.Slug))
	if !slugRe.MatchString(req.Slug) {
		return 0, badRequest("slug must be 2-63 lowercase letters, digits or dashes")
	}
	if strings.TrimSpace(req.Title) == "" {
		return 0, badRequest("title is required")
	}
	tenant, err := c.tenantFor(req.TenantID)
	if err != nil {
		return 0, err
	}
	for i, it := range req.Items {
		switch it.Type {
		case "host":
			h, err := c.visibleHost(it.ID)
			if err != nil || h.TenantID != tenant && tenant != 0 {
				return 0, badRequest("item %d: unknown host", i+1)
			}
			if it.Label == "" {
				req.Items[i].Label = h.Name
			}
		case "check":
			k, err := a.visibleCheck(c, it.ID)
			if err != nil || k.TenantID != tenant && tenant != 0 {
				return 0, badRequest("item %d: unknown check", i+1)
			}
			if it.Label == "" {
				req.Items[i].Label = k.Name
			}
		default:
			return 0, badRequest("item type must be host or check")
		}
	}
	return tenant, nil
}

func (a *App) apiListStatusPages(c *Ctx) (any, error) {
	tw, args := c.tenantWhere("tenant_id")
	out := []StatusPage{}
	err := a.db.SelectContext(c.ctx(), &out, `SELECT * FROM status_pages WHERE `+tw+` ORDER BY title`, args...)
	if !c.P.Has(PermMonitoring) {
		for i := range out {
			out[i].AccessToken = ""
		}
	}
	return out, err
}

func (a *App) apiCreateStatusPage(c *Ctx) (any, error) {
	var req statusPageReq
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	tenant, err := a.validateStatusPage(c, &req)
	if err != nil {
		return nil, err
	}
	now := db.Now()
	pub := boolOr(req.Public, true)
	tok := ""
	if !pub {
		tok = randomToken(18)
	}
	res, err := a.db.ExecContext(c.ctx(), `INSERT INTO status_pages (tenant_id, slug, title, description, public, access_token, items, show_history, announcement, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`, tenant, req.Slug, req.Title, req.Description, pub, tok, mustJSON(req.Items), boolOr(req.ShowHistory, true), req.Announcement, now, now)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	c.auditT(tenant, "status_page.created", "status_page", itoa(id), map[string]any{"slug": req.Slug})
	var sp StatusPage
	err = a.db.GetContext(c.ctx(), &sp, `SELECT * FROM status_pages WHERE id=?`, id)
	return created{sp}, err
}

func (a *App) apiUpdateStatusPage(c *Ctx) (any, error) {
	var sp StatusPage
	if err := a.db.GetContext(c.ctx(), &sp, `SELECT * FROM status_pages WHERE id=?`, c.ID()); err != nil || !c.P.CanTenant(sp.TenantID) {
		return nil, errNotFound
	}
	var req statusPageReq
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	req.TenantID = sp.TenantID
	if _, err := a.validateStatusPage(c, &req); err != nil {
		return nil, err
	}
	pub := boolOr(req.Public, true)
	tok := sp.AccessToken
	if !pub && (tok == "" || req.RegenToken) {
		tok = randomToken(18)
	}
	if pub {
		tok = ""
	}
	_, err := a.db.ExecContext(c.ctx(), `UPDATE status_pages SET slug=?, title=?, description=?, public=?, access_token=?, items=?, show_history=?, announcement=?, updated_at=? WHERE id=?`,
		req.Slug, req.Title, req.Description, pub, tok, mustJSON(req.Items), boolOr(req.ShowHistory, true), req.Announcement, db.Now(), sp.ID)
	c.auditT(sp.TenantID, "status_page.updated", "status_page", itoa(sp.ID), map[string]any{"slug": req.Slug})
	return nil, err
}

func (a *App) apiDeleteStatusPage(c *Ctx) (any, error) {
	var sp StatusPage
	if err := a.db.GetContext(c.ctx(), &sp, `SELECT * FROM status_pages WHERE id=?`, c.ID()); err != nil || !c.P.CanTenant(sp.TenantID) {
		return nil, errNotFound
	}
	_, err := a.db.ExecContext(c.ctx(), `DELETE FROM status_pages WHERE id=?`, sp.ID)
	c.auditT(sp.TenantID, "status_page.deleted", "status_page", itoa(sp.ID), map[string]any{"slug": sp.Slug})
	return nil, err
}

type publicItem struct {
	Label     string      `json:"label"`
	Type      string      `json:"type"`
	Status    string      `json:"status"` // operational, degraded, down, maintenance, unknown
	UptimePct float64     `json:"uptime_percent"`
	Days      []uptimeDay `json:"days,omitempty"`
}

// apiPublicStatus serves status page data without authentication. It only
// reveals labels and up/down state for the configured items.
func (a *App) apiPublicStatus(c *Ctx) (any, error) {
	var sp StatusPage
	if err := a.db.GetContext(c.ctx(), &sp, `SELECT * FROM status_pages WHERE slug=?`, strings.ToLower(c.Param("slug"))); err != nil {
		return nil, errNotFound
	}
	if !sp.Public && subtle.ConstantTimeCompare([]byte(c.Q("token")), []byte(sp.AccessToken)) != 1 {
		return nil, errNotFound
	}
	var items []StatusPageItem
	_ = json.Unmarshal(sp.Items, &items)
	out := []publicItem{}
	overall := "operational"
	rank := map[string]int{"operational": 0, "maintenance": 1, "unknown": 1, "degraded": 2, "down": 3}
	for _, it := range items {
		pi := publicItem{Label: it.Label, Type: it.Type, Status: "unknown"}
		switch it.Type {
		case "host":
			var h struct {
				Status   string `db:"status"`
				TenantID int64  `db:"tenant_id"`
			}
			if err := a.db.GetContext(c.ctx(), &h, `SELECT status, tenant_id FROM hosts WHERE id=?`, it.ID); err != nil || (sp.TenantID != 0 && h.TenantID != sp.TenantID) {
				continue
			}
			switch h.Status {
			case "up":
				pi.Status = "operational"
			case "down":
				pi.Status = "down"
			}
			if a.maint.hostInWindow(it.ID) {
				pi.Status = "maintenance"
			}
		case "check":
			var k struct {
				Status   string `db:"status"`
				TenantID int64  `db:"tenant_id"`
				HostID   *int64 `db:"host_id"`
			}
			if err := a.db.GetContext(c.ctx(), &k, `SELECT status, tenant_id, host_id FROM checks WHERE id=?`, it.ID); err != nil || (sp.TenantID != 0 && k.TenantID != sp.TenantID) {
				continue
			}
			switch k.Status {
			case "up":
				pi.Status = "operational"
			case "warning":
				pi.Status = "degraded"
			case "down":
				pi.Status = "down"
			}
			if k.HostID != nil && a.maint.hostInWindow(*k.HostID) {
				pi.Status = "maintenance"
			}
		}
		days, pct := a.uptimeDays(c.ctx(), it.Type, it.ID, 90)
		pi.UptimePct = pct
		if sp.ShowHistory {
			pi.Days = days
		}
		if rank[pi.Status] > rank[overall] {
			overall = pi.Status
		}
		out = append(out, pi)
	}
	if overall == "unknown" {
		overall = "operational"
	}
	return map[string]any{"title": sp.Title, "description": sp.Description, "announcement": sp.Announcement, "items": out,
		"overall": overall, "branding": a.settings.Branding(sp.TenantID), "updated_at": time.Now().Unix()}, nil
}
