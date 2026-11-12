package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	pb "sentrel/gen/sentrelv1"
	"sentrel/server/db"
	"sentrel/server/metrics"
)

// condition is one evaluation of something that can alert.
type condition struct {
	Key       string
	TenantID  int64
	HostID    *int64
	CheckID   *int64
	Source    string // threshold, check, host, vuln, storage, system
	Metric    string
	Labels    string
	Severity  string // ok, warning, critical
	Title     string
	Message   string
	Value     *float64
	Threshold *float64
	ForCount  int
	Stage     int  // escalation stage within the same severity (cert 30/14/7 days)
	Muted     bool // notifications disabled by the resolved rule
}

// AlertEngine owns alert state. Active (pending/firing) alerts live in
// memory and are written through to SQLite on transitions.
type AlertEngine struct {
	app   *App
	rules ruleSet

	mu      sync.Mutex
	active  map[string]*Alert
	okCount map[string]int

	hostsMu sync.RWMutex
	hosts   map[int64]hostRef
}

func newAlertEngine(a *App) *AlertEngine {
	return &AlertEngine{app: a, active: map[string]*Alert{}, okCount: map[string]int{}, hosts: map[int64]hostRef{}}
}

func (e *AlertEngine) load(ctx context.Context) error {
	if err := e.rules.load(ctx, e.app); err != nil {
		return err
	}
	var rows []Alert
	if err := e.app.db.SelectContext(ctx, &rows, `SELECT * FROM alerts WHERE status IN ('pending','firing')`); err != nil {
		return err
	}
	e.mu.Lock()
	for i := range rows {
		r := rows[i]
		e.active[r.Key] = &r
	}
	e.mu.Unlock()
	return e.refreshHosts(ctx)
}

// ReloadRules is called after threshold edits.
func (e *AlertEngine) ReloadRules(ctx context.Context) error { return e.rules.load(ctx, e.app) }

func (e *AlertEngine) refreshHosts(ctx context.Context) error {
	type row struct {
		ID       int64         `db:"id"`
		TenantID int64         `db:"tenant_id"`
		GroupID  sql.NullInt64 `db:"group_id"`
		Name     string        `db:"name"`
		Kind     string        `db:"kind"`
	}
	var rows []row
	if err := e.app.db.SelectContext(ctx, &rows, `SELECT id, tenant_id, group_id, name, kind FROM hosts`); err != nil {
		return err
	}
	m := make(map[int64]hostRef, len(rows))
	for _, r := range rows {
		m[r.ID] = hostRef{ID: r.ID, TenantID: r.TenantID, GroupID: r.GroupID.Int64, Name: r.Name, Kind: r.Kind}
		hostTenantCache.Store(r.ID, r.TenantID)
	}
	e.hostsMu.Lock()
	e.hosts = m
	e.hostsMu.Unlock()
	return nil
}

func (e *AlertEngine) host(id int64) (hostRef, bool) {
	e.hostsMu.RLock()
	h, ok := e.hosts[id]
	e.hostsMu.RUnlock()
	if !ok {
		_ = e.refreshHosts(context.Background())
		e.hostsMu.RLock()
		h, ok = e.hosts[id]
		e.hostsMu.RUnlock()
	}
	return h, ok
}

// hostSeen clears a host-down alert immediately on reconnect.
func (e *AlertEngine) hostSeen(hostID int64) {
	h, ok := e.host(hostID)
	if !ok {
		return
	}
	e.apply(context.Background(), condition{Key: hostDownKey(hostID), TenantID: h.TenantID, HostID: &hostID, Source: "host", Severity: "ok"})
}

func hostDownKey(id int64) string { return "host:" + itoa(id) + ":down" }

// evaluateSamples checks threshold metrics in a batch.
func (e *AlertEngine) evaluateSamples(ctx context.Context, hostID int64, samples []metrics.Sample) {
	h, ok := e.host(hostID)
	if !ok {
		return
	}
	for _, s := range samples {
		def, ok := metricBySample[s.Name]
		if !ok {
			continue
		}
		lv := ""
		if def.LabelKey != "" {
			lv = s.Labels[def.LabelKey]
		}
		key := "threshold:" + itoa(hostID) + ":" + def.Key
		if lv != "" {
			key += ":" + lv
		}
		c := condition{Key: key, TenantID: h.TenantID, HostID: &hostID, Source: "threshold", Metric: def.Key, Labels: lv, Severity: "ok"}
		r := e.rules.resolve(h, def.Key, lv)
		if def.Key == "bruteforce" && r != nil {
			r = e.app.bruteforceRule(ctx, hostID, r)
		}
		if r != nil && r.Rule.Enabled {
			sev, thr := severityFor(def, r.Rule, s.Value)
			v := s.Value
			c.Severity, c.Threshold, c.Value, c.ForCount = sev, thr, &v, r.Rule.ForCount
			c.Muted = !r.Rule.Notify
			c.Title, c.Message = describeThreshold(h, def, lv, v, thr, s.Labels)
		}
		e.apply(ctx, c)
	}
}

func describeThreshold(h hostRef, def MetricDef, lv string, v float64, thr *float64, labels map[string]string) (string, string) {
	what := def.Name
	if lv != "" {
		what += " " + lv
	}
	title := fmt.Sprintf("%s on %s", what, h.Name)
	val := fmtValue(v, def.Unit)
	msg := fmt.Sprintf("%s is %s", what, val)
	if thr != nil {
		cmp := "≥"
		if def.LowerIsWorse {
			cmp = "≤"
		}
		msg += fmt.Sprintf(" (threshold %s %s)", cmp, fmtValue(*thr, def.Unit))
	}
	if def.Key == "bruteforce" && labels["ip"] != "" {
		msg += " from " + labels["ip"]
	}
	if def.Key == "portscan" {
		if ip := labels["ip"]; ip != "" {
			title = fmt.Sprintf("Port scan from %s on %s", ip, h.Name)
			msg = fmt.Sprintf("%s probed closed ports in the last 10 minutes", ip)
			if n := int(v); n > 1 {
				msg = fmt.Sprintf("%s and %d other sources probed closed ports in the last 10 minutes", ip, n-1)
			}
		} else {
			title = "Port scan on " + h.Name
		}
	}
	return title, msg
}

func fmtValue(v float64, unit string) string {
	switch {
	case unit == "%":
		return fmt.Sprintf("%.1f%%", v)
	case unit == "h" && v > 48:
		return fmt.Sprintf("%.1f days", v/24)
	case math.Abs(v-math.Round(v)) < 1e-9:
		return fmt.Sprintf("%.0f%s", v, unitSuffix(unit))
	default:
		return fmt.Sprintf("%.2f%s", v, unitSuffix(unit))
	}
}

func unitSuffix(u string) string {
	if u == "" {
		return ""
	}
	if u == "°C" || u == "/s" {
		return u
	}
	return " " + u
}

// evaluateState derives samples from structured state.
func (e *AlertEngine) evaluateState(ctx context.Context, hostID int64, st *pb.HostState) {
	rb := 0.0
	if st.RebootRequired {
		rb = 1
	}
	e.evaluateSamples(ctx, hostID, []metrics.Sample{{Name: "reboot_required", Value: rb}})
}

// apply runs the state machine for one condition.
func (e *AlertEngine) apply(ctx context.Context, c condition) {
	a := e.app
	now := db.Now()
	al := a.alerting()
	// The host's current owner is authoritative: a condition computed from a
	// cached check or sample batch may predate a tenant transfer.
	if c.HostID != nil {
		if h, ok := e.host(*c.HostID); ok {
			c.TenantID = h.TenantID
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	cur := e.active[c.Key]
	if cur != nil && cur.TenantID != c.TenantID && c.HostID != nil {
		cur.TenantID = c.TenantID
		_, _ = a.db.ExecContext(ctx, `UPDATE alerts SET tenant_id=? WHERE id=?`, c.TenantID, cur.ID)
	}

	if c.Severity == "ok" {
		if cur == nil {
			return
		}
		if cur.Status == "pending" {
			delete(e.active, c.Key)
			delete(e.okCount, c.Key)
			// A row marked as expected is kept even if it never fired this time,
			// so the mark survives.
			_, _ = a.db.ExecContext(ctx, `DELETE FROM alerts WHERE id=? AND fired_at=0 AND expected=0`, cur.ID)
			_, _ = a.db.ExecContext(ctx, `UPDATE alerts SET status='resolved', pending_count=0 WHERE id=?`, cur.ID)
			return
		}
		e.okCount[c.Key]++
		need := al.ResolveCount
		if need < 1 {
			need = 1
		}
		if e.okCount[c.Key] < need {
			return
		}
		delete(e.okCount, c.Key)
		delete(e.active, c.Key)
		cur.Status = "resolved"
		cur.ResolvedAt = now
		cur.LastEvalAt = now
		cur.Transitions = pruneTransitions(append(cur.Transitions, now), now, al.FlapWindowMinutes)
		_, err := a.db.ExecContext(ctx, `UPDATE alerts SET status='resolved', resolved_at=?, last_eval_at=?, transitions=?, pending_count=0 WHERE id=?`,
			now, now, cur.Transitions, cur.ID)
		if err != nil {
			a.log.Error("alert resolve", "err", err)
		}
		e.event(ctx, cur, "resolved", "", "")
		if !cur.Flapping && !e.suppressed(cur) {
			a.notifier.enqueue(*cur, "resolved")
		}
		a.events.publish(Event{Type: "alert.changed", TenantID: cur.TenantID, ID: itoa(cur.ID)})
		return
	}

	delete(e.okCount, c.Key)
	if cur == nil {
		cur = &Alert{Key: c.Key, TenantID: c.TenantID, HostID: c.HostID, CheckID: c.CheckID, Source: c.Source, Metric: c.Metric, Labels: c.Labels,
			Severity: c.Severity, Status: "pending", Title: c.Title, Message: c.Message, Value: c.Value, Threshold: c.Threshold, StartedAt: now, LastEvalAt: now, Muted: c.Muted}
		// Reuse a previously resolved row with the same key to keep history together.
		var prev Alert
		err := a.db.GetContext(ctx, &prev, `SELECT * FROM alerts WHERE key=?`, c.Key)
		if err == nil {
			cur.ID = prev.ID
			cur.Transitions = prev.Transitions
			cur.Flapping = prev.Flapping
			cur.Expected = prev.Expected
			// An acknowledgement carries over when the alert comes back soon
			// after clearing (within the flap window), and always while the
			// alert is marked as expected.
			if prev.AckedBy != "" && (prev.Expected || ackCarries(prev.ResolvedAt, now, al.FlapWindowMinutes)) {
				cur.AckedBy, cur.AckedAt, cur.AckComment = prev.AckedBy, prev.AckedAt, prev.AckComment
			}
			_, err = a.db.ExecContext(ctx, `UPDATE alerts SET tenant_id=?, host_id=?, check_id=?, source=?, metric=?, labels=?, severity=?, status='pending', title=?, message=?,
				value=?, threshold=?, pending_count=0, started_at=?, fired_at=0, resolved_at=0, last_eval_at=?, acked_by=?, acked_at=?, ack_comment=?, notify_count=0, last_notified_at=0, muted=? WHERE id=?`,
				c.TenantID, c.HostID, c.CheckID, c.Source, c.Metric, c.Labels, c.Severity, c.Title, c.Message, c.Value, c.Threshold, now, now, cur.AckedBy, cur.AckedAt, cur.AckComment, c.Muted, cur.ID)
		} else if errors.Is(err, sql.ErrNoRows) {
			var res sql.Result
			res, err = a.db.ExecContext(ctx, `INSERT INTO alerts (tenant_id, host_id, check_id, key, source, metric, labels, severity, status, title, message, value, threshold,
				pending_count, started_at, last_eval_at, muted) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,0,?,?,?)`,
				c.TenantID, c.HostID, c.CheckID, c.Key, c.Source, c.Metric, c.Labels, c.Severity, "pending", c.Title, c.Message, c.Value, c.Threshold, now, now, c.Muted)
			if err == nil {
				cur.ID, _ = res.LastInsertId()
			}
		}
		if err != nil {
			a.log.Error("alert create", "err", err, "key", c.Key)
			return
		}
		e.active[c.Key] = cur
	}
	cur.PendingCount++
	mutedChanged := cur.Muted != c.Muted
	cur.Muted = c.Muted
	cur.Value, cur.Threshold = c.Value, c.Threshold
	if c.Title != "" {
		cur.Title = c.Title
	}
	cur.Message = c.Message
	forCount := c.ForCount
	if forCount < 1 {
		forCount = 1
	}
	writeNeeded := now-cur.LastEvalAt >= 60 || mutedChanged

	switch cur.Status {
	case "pending":
		cur.Severity = c.Severity
		if cur.PendingCount >= forCount {
			cur.Status = "firing"
			cur.FiredAt = now
			cur.stage = c.Stage
			cur.Transitions = pruneTransitions(append(cur.Transitions, now), now, al.FlapWindowMinutes)
			e.checkFlapping(ctx, cur, now, al)
			writeNeeded = true
			e.event(ctx, cur, "fired", "", "")
			a.maybeAutoDiskAnalysis(*cur)
			// A still-acknowledged alert that came back does not notify again;
			// if it keeps returning, the flapping notice above reports it once.
			if !cur.Flapping && cur.AckedBy == "" {
				if why := e.suppression(cur); why != "" {
					e.event(ctx, cur, "silenced", why, "")
				} else {
					a.notifier.enqueue(*cur, "fired")
				}
			}
			a.events.publish(Event{Type: "alert.changed", TenantID: cur.TenantID, ID: itoa(cur.ID)})
		}
	case "firing":
		escalated := severityRank(c.Severity) > severityRank(cur.Severity) || (c.Severity == cur.Severity && c.Stage > cur.stage)
		changed := c.Severity != cur.Severity
		cur.Severity = c.Severity
		cur.stage = c.Stage
		if escalated {
			writeNeeded = true
			e.event(ctx, cur, "escalated", "", "")
			if !cur.Flapping && !e.suppressed(cur) {
				a.notifier.enqueue(*cur, "escalated")
			}
		}
		if changed {
			writeNeeded = true
			a.events.publish(Event{Type: "alert.changed", TenantID: cur.TenantID, ID: itoa(cur.ID)})
		}
	}
	if writeNeeded {
		cur.LastEvalAt = now
		_, err := a.db.ExecContext(ctx, `UPDATE alerts SET severity=?, status=?, title=?, message=?, value=?, threshold=?, pending_count=?, fired_at=?, last_eval_at=?,
			acked_by=?, acked_at=?, ack_comment=?, flapping=?, transitions=?, muted=? WHERE id=?`,
			cur.Severity, cur.Status, cur.Title, cur.Message, cur.Value, cur.Threshold, cur.PendingCount, cur.FiredAt, cur.LastEvalAt,
			cur.AckedBy, cur.AckedAt, cur.AckComment, cur.Flapping, cur.Transitions, cur.Muted, cur.ID)
		if err != nil {
			a.log.Error("alert update", "err", err)
		}
	} else {
		cur.LastEvalAt = now
	}
}

func (a *App) alerting() AlertingSettings { return a.settings.Alerting() }

func severityRank(s string) int {
	switch s {
	case "critical":
		return 2
	case "warning":
		return 1
	}
	return 0
}

// ackCarries reports whether an alert that resolved at resolvedAt and is back
// at now returns soon enough to keep its acknowledgement.
func ackCarries(resolvedAt, now int64, windowMin int) bool {
	if windowMin <= 0 {
		windowMin = 30
	}
	return resolvedAt > 0 && now-resolvedAt <= int64(windowMin)*60
}

func pruneTransitions(t IntList, now int64, windowMin int) IntList {
	if windowMin <= 0 {
		windowMin = 30
	}
	cut := now - int64(windowMin)*60
	out := t[:0:0]
	for _, x := range t {
		if x >= cut {
			out = append(out, x)
		}
	}
	return out
}

func (e *AlertEngine) checkFlapping(ctx context.Context, cur *Alert, now int64, al AlertingSettings) {
	thr := al.FlapThreshold
	if thr <= 0 {
		return
	}
	if !cur.Flapping && len(cur.Transitions) >= thr {
		cur.Flapping = true
		e.event(ctx, cur, "flapping", fmt.Sprintf("%d state changes in %d minutes; notifications paused", len(cur.Transitions), al.FlapWindowMinutes), "")
		if !e.suppressed(cur) {
			e.app.notifier.enqueue(*cur, "flapping")
		}
	}
}

// inMaintenance reports whether an alert is covered by a silencing
// maintenance window.
func (e *AlertEngine) inMaintenance(al *Alert) bool {
	if al.HostID != nil {
		return e.app.maint.hostSuppressed(*al.HostID)
	}
	return e.app.maint.tenantSuppressed(al.TenantID)
}

// suppression says why notifications for an alert are withheld: a
// maintenance window or a parent that is down. Empty means not suppressed.
func (e *AlertEngine) suppression(al *Alert) string {
	if e.inMaintenance(al) {
		return "in maintenance window"
	}
	return e.app.dependencyReason(al)
}

// suppressed reports whether notifications for an alert are withheld.
func (e *AlertEngine) suppressed(al *Alert) bool { return e.suppression(al) != "" }

func (e *AlertEngine) event(ctx context.Context, al *Alert, ev, msg, actor string) {
	if msg == "" {
		msg = al.Message
	}
	_, err := e.app.db.ExecContext(ctx, `INSERT INTO alert_events (tenant_id, alert_id, host_id, event, severity, message, actor, created_at) VALUES (?,?,?,?,?,?,?,?)`,
		al.TenantID, al.ID, al.HostID, ev, al.Severity, msg, actor, db.Now())
	if err != nil {
		e.app.log.Error("alert event", "err", err)
	}
}

// Ack acknowledges an active alert. With expected set the alert is also
// hidden from the active list and sends no notifications, across any number
// of fires and resolves, until Unack.
func (e *AlertEngine) Ack(ctx context.Context, id int64, actor, comment string, expected bool) (*Alert, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := db.Now()
	for _, cur := range e.active {
		if cur.ID == id {
			cur.AckedBy, cur.AckedAt, cur.AckComment, cur.Expected = actor, now, comment, expected
			_, err := e.app.db.ExecContext(ctx, `UPDATE alerts SET acked_by=?, acked_at=?, ack_comment=?, expected=? WHERE id=?`, actor, now, comment, expected, id)
			if err != nil {
				return nil, err
			}
			ev, msg := "acked", comment
			if expected {
				ev = "expected"
				if msg == "" {
					msg = "marked as expected"
				}
			}
			e.event(ctx, cur, ev, msg, actor)
			e.app.events.publish(Event{Type: "alert.changed", TenantID: cur.TenantID, ID: itoa(id)})
			cp := *cur
			return &cp, nil
		}
	}
	return nil, errNotFound
}

// Unack removes an acknowledgement and any "expected" mark. An expected
// alert can be un-marked while it is resolved.
func (e *AlertEngine) Unack(ctx context.Context, id int64, actor string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	var al *Alert
	for _, cur := range e.active {
		if cur.ID == id {
			al = cur
		}
	}
	if al == nil {
		var row Alert
		if err := e.app.db.GetContext(ctx, &row, `SELECT * FROM alerts WHERE id=? AND expected=1`, id); err != nil {
			return errNotFound
		}
		al = &row
	}
	wasExpected := al.Expected
	al.AckedBy, al.AckedAt, al.AckComment, al.Expected = "", 0, "", false
	_, err := e.app.db.ExecContext(ctx, `UPDATE alerts SET acked_by='', acked_at=0, ack_comment='', expected=0 WHERE id=?`, id)
	msg := "acknowledgement removed"
	if wasExpected {
		msg = "no longer expected"
	}
	e.event(ctx, al, "unacked", msg, actor)
	e.app.events.publish(Event{Type: "alert.changed", TenantID: al.TenantID, ID: itoa(id)})
	return err
}

func (e *AlertEngine) forceResolve(ctx context.Context, key, msg, actor string) {
	e.mu.Lock()
	cur := e.active[key]
	if cur == nil {
		e.mu.Unlock()
		return
	}
	delete(e.active, key)
	delete(e.okCount, key)
	e.mu.Unlock()
	now := db.Now()
	_, _ = e.app.db.ExecContext(ctx, `UPDATE alerts SET status='resolved', resolved_at=?, pending_count=0 WHERE id=?`, now, cur.ID)
	if cur.Status == "firing" {
		cur.Status, cur.ResolvedAt = "resolved", now
		e.event(ctx, cur, "resolved", msg, actor)
		if !e.suppressed(cur) && !cur.Flapping {
			e.app.notifier.enqueue(*cur, "resolved")
		}
	}
	e.app.events.publish(Event{Type: "alert.changed", TenantID: cur.TenantID, ID: itoa(cur.ID)})
}

// transferHost moves a host's runtime state to a new owner: active alerts and
// the cached host entry. Callers run it after the database move commits.
func (e *AlertEngine) transferHost(hostID, tenant int64, name string) {
	e.mu.Lock()
	for _, al := range e.active {
		if al.HostID != nil && *al.HostID == hostID {
			al.TenantID = tenant
		}
	}
	e.mu.Unlock()
	e.hostsMu.Lock()
	if h, ok := e.hosts[hostID]; ok {
		h.TenantID, h.GroupID = tenant, 0
		if name != "" {
			h.Name = name
		}
		e.hosts[hostID] = h
	}
	e.hostsMu.Unlock()
	hostTenantCache.Store(hostID, tenant)
}

// forgetHost drops in-memory state after a host is deleted.
func (e *AlertEngine) forgetHost(hostID int64) {
	e.mu.Lock()
	for k, al := range e.active {
		if al.HostID != nil && *al.HostID == hostID {
			delete(e.active, k)
		}
	}
	e.mu.Unlock()
	e.hostsMu.Lock()
	delete(e.hosts, hostID)
	e.hostsMu.Unlock()
	hostTenantCache.Delete(hostID)
}

// forgetCheck drops in-memory state after a check is deleted.
func (e *AlertEngine) forgetCheck(checkID int64) {
	e.mu.Lock()
	for k, al := range e.active {
		if al.CheckID != nil && *al.CheckID == checkID {
			delete(e.active, k)
		}
	}
	e.mu.Unlock()
}

// expectedDown lists the hosts whose "host is down" alert is firing and
// marked as expected: down, but not a problem to act on.
func (e *AlertEngine) expectedDown() map[int64]bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := map[int64]bool{}
	for _, al := range e.active {
		if al.Expected && al.Status == "firing" && al.Metric == "host_down" && al.HostID != nil {
			out[*al.HostID] = true
		}
	}
	return out
}

// expectedChecks returns the checks whose firing alert is marked as expected.
func (e *AlertEngine) expectedChecks() map[int64]bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := map[int64]bool{}
	for _, al := range e.active {
		if al.Expected && al.Status == "firing" && al.CheckID != nil {
			out[*al.CheckID] = true
		}
	}
	return out
}

// Active returns copies of active alerts.
func (e *AlertEngine) Active() []Alert {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Alert, 0, len(e.active))
	for _, a := range e.active {
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt > out[j].StartedAt })
	return out
}

// loop handles time-based conditions: host liveness, stale metric alerts,
// flapping recovery.
func (e *AlertEngine) loop(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	refresh := time.NewTicker(2 * time.Minute)
	defer refresh.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-refresh.C:
			_ = e.refreshHosts(ctx)
		case <-t.C:
			e.checkLiveness(ctx)
			e.checkStale(ctx)
			e.checkFlapRecovery(ctx)
		}
	}
}

func (e *AlertEngine) checkLiveness(ctx context.Context) {
	a := e.app
	type row struct {
		ID         int64  `db:"id"`
		TenantID   int64  `db:"tenant_id"`
		Name       string `db:"name"`
		Kind       string `db:"kind"`
		Status     string `db:"status"`
		LastSeenAt int64  `db:"last_seen_at"`
		Revoked    bool   `db:"revoked"`
	}
	var rows []row
	if err := a.db.SelectContext(ctx, &rows, `SELECT id, tenant_id, name, kind, status, last_seen_at, revoked FROM hosts WHERE kind IN ('agent','snmp')`); err != nil {
		return
	}
	now := time.Now()
	for _, r := range rows {
		if r.Revoked || r.Status == "pending" && r.LastSeenAt == 0 {
			continue
		}
		last := time.Unix(r.LastSeenAt, 0)
		if ls := a.latest.lastSeen(r.ID); ls.After(last) {
			last = ls
		}
		h, ok := e.host(r.ID)
		if !ok {
			continue
		}
		limit := 120.0
		rule := e.rules.resolve(h, "host_down", "")
		if rule != nil && !rule.Rule.Enabled {
			continue
		}
		if rule != nil && rule.Rule.Crit != nil {
			limit = *rule.Rule.Crit
		}
		if r.Kind == "snmp" {
			// SNMP liveness is driven by the poller; use 3 poll intervals.
			limit = math.Max(limit, 180)
		}
		age := now.Sub(last).Seconds()
		id := r.ID
		c := condition{Key: hostDownKey(id), TenantID: r.TenantID, HostID: &id, Source: "host", Metric: "host_down", Severity: "ok"}
		if age > limit {
			c.Severity = "critical"
			c.Title = r.Name + " is down"
			c.Muted = rule != nil && !rule.Rule.Notify
			c.Message = fmt.Sprintf("No contact from %s for %s", r.Name, humanDuration(time.Duration(age)*time.Second))
			v := age
			c.Value, c.Threshold = &v, &limit
			if r.Status != "down" {
				_, _ = a.db.ExecContext(ctx, `UPDATE hosts SET status='down' WHERE id=?`, id)
				a.events.publish(Event{Type: "host.updated", TenantID: r.TenantID, HostID: id})
			}
		} else if r.Status == "down" {
			_, _ = a.db.ExecContext(ctx, `UPDATE hosts SET status='up' WHERE id=?`, id)
		}
		e.apply(ctx, c)
	}
}

// checkStale resolves threshold alerts whose metric stopped being reported
// (e.g. an unmounted disk) while the host itself is still reporting.
func (e *AlertEngine) checkStale(ctx context.Context) {
	now := time.Now()
	var stale []string
	e.mu.Lock()
	for k, al := range e.active {
		if al.Source != "threshold" || al.HostID == nil {
			continue
		}
		last := time.Unix(al.LastEvalAt, 0)
		if now.Sub(last) > 15*time.Minute && now.Sub(e.app.latest.lastSeen(*al.HostID)) < 2*time.Minute {
			stale = append(stale, k)
		}
	}
	e.mu.Unlock()
	for _, k := range stale {
		e.forceResolve(ctx, k, "metric no longer reported", "system")
	}
}

func (e *AlertEngine) checkFlapRecovery(ctx context.Context) {
	al := e.app.alerting()
	now := db.Now()
	e.mu.Lock()
	var changed []*Alert
	for _, cur := range e.active {
		if cur.Flapping {
			cur.Transitions = pruneTransitions(cur.Transitions, now, al.FlapWindowMinutes)
			if len(cur.Transitions) == 0 {
				cur.Flapping = false
				changed = append(changed, cur)
			}
		}
	}
	e.mu.Unlock()
	for _, cur := range changed {
		_, _ = e.app.db.ExecContext(ctx, `UPDATE alerts SET flapping=0, transitions='[]' WHERE id=?`, cur.ID)
		e.event(ctx, cur, "flapping_stopped", "state stable again", "")
	}
	// Resolved alerts that were flapping are not in memory; clear them too.
	_, _ = e.app.db.ExecContext(ctx, `UPDATE alerts SET flapping=0 WHERE status='resolved' AND flapping=1 AND resolved_at < ?`, now-int64(al.FlapWindowMinutes)*60)
}

func humanDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

var errNotFound = errors.New("not found")

// systemCondition raises/clears an alert not tied to a host.
func (e *AlertEngine) systemCondition(ctx context.Context, key, severity, title, msg string) {
	e.apply(ctx, condition{Key: "system:" + key, TenantID: 0, Source: "system", Severity: severity, Title: title, Message: msg, ForCount: 1})
}

func sevTitle(s string) string { return strings.ToUpper(s[:1]) + s[1:] }
