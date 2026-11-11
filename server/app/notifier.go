package app

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"sentrel/server/db"
	"sentrel/server/notify"
)

// Notifier routes alert events to channels, grouping events that arrive
// within the group-wait window into one message per channel.
type Notifier struct {
	app *App

	mu       sync.Mutex
	queue    map[int64][]queuedNote
	firstAt  map[int64]time.Time
	lastSent map[[2]int64]int64 // (channel, alert) -> unix

	chMu     sync.RWMutex
	channels []NotificationChannel
	chLoaded time.Time
}

type queuedNote struct {
	alert Alert
	event string
}

func newNotifier(a *App) *Notifier {
	return &Notifier{app: a, queue: map[int64][]queuedNote{}, firstAt: map[int64]time.Time{}, lastSent: map[[2]int64]int64{}}
}

func (n *Notifier) reloadChannels(ctx context.Context) {
	var chs []NotificationChannel
	if err := n.app.db.SelectContext(ctx, &chs, `SELECT * FROM notification_channels WHERE enabled=1`); err != nil {
		n.app.log.Error("load channels", "err", err)
		return
	}
	n.chMu.Lock()
	n.channels = chs
	n.chLoaded = time.Now()
	n.chMu.Unlock()
}

// Invalidate forces a channel reload (after edits).
func (n *Notifier) Invalidate() {
	n.chMu.Lock()
	n.chLoaded = time.Time{}
	n.chMu.Unlock()
}

func (n *Notifier) channelList(ctx context.Context) []NotificationChannel {
	n.chMu.RLock()
	stale := time.Since(n.chLoaded) > time.Minute
	n.chMu.RUnlock()
	if stale {
		n.reloadChannels(ctx)
	}
	n.chMu.RLock()
	defer n.chMu.RUnlock()
	return n.channels
}

type alertHostInfo struct {
	Name    string  `db:"name"`
	GroupID *int64  `db:"group_id"`
	Tags    StrList `db:"tags"`
}

func (n *Notifier) hostInfo(ctx context.Context, id *int64) *alertHostInfo {
	if id == nil {
		return nil
	}
	var h alertHostInfo
	if err := n.app.db.GetContext(ctx, &h, `SELECT name, group_id, tags FROM hosts WHERE id=?`, *id); err != nil {
		return nil
	}
	return &h
}

func channelMatches(ch NotificationChannel, al Alert, event string, h *alertHostInfo) bool {
	if ch.TenantID != 0 && ch.TenantID != al.TenantID {
		return false
	}
	if event == "resolved" && !ch.SendResolved {
		return false
	}
	if severityRank(al.Severity) < severityRank(ch.MinSeverity) {
		return false
	}
	if len(ch.FilterHosts) > 0 {
		if al.HostID == nil || !containsInt(ch.FilterHosts, *al.HostID) {
			return false
		}
	}
	if len(ch.FilterGroups) > 0 {
		if h == nil || h.GroupID == nil || !containsInt(ch.FilterGroups, *h.GroupID) {
			return false
		}
	}
	if len(ch.FilterTags) > 0 {
		if h == nil {
			return false
		}
		ok := false
		for _, t := range ch.FilterTags {
			for _, ht := range h.Tags {
				if strings.EqualFold(t, ht) {
					ok = true
				}
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func containsInt(l []int64, v int64) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

// enqueue routes an alert event to every matching channel.
func (n *Notifier) enqueue(al Alert, event string) {
	ctx := context.Background()
	if al.Expected {
		return // marked as expected: recorded in the timeline, never notified
	}
	if al.Muted {
		n.app.alerts.event(ctx, &al, "silenced", "notifications disabled for this rule", "")
		return
	}
	h := n.hostInfo(ctx, al.HostID)
	if h != nil {
		al.HostName = h.Name
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, ch := range n.channelList(ctx) {
		if !channelMatches(ch, al, event, h) {
			continue
		}
		n.add(ch.ID, al, event)
	}
}

// hostMoved re-homes queued notifications of a host that changed tenant:
// notes bound for a channel of any other tenant are dropped, the rest are
// re-labelled with the new owner.
func (n *Notifier) hostMoved(ctx context.Context, hostID, tenant int64) {
	chTenant := map[int64]int64{}
	for _, ch := range n.channelList(ctx) {
		chTenant[ch.ID] = ch.TenantID
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	for id, q := range n.queue {
		kept := q[:0]
		for _, note := range q {
			if note.alert.HostID != nil && *note.alert.HostID == hostID {
				if t, ok := chTenant[id]; !ok || (t != 0 && t != tenant) {
					continue
				}
				note.alert.TenantID = tenant
			}
			kept = append(kept, note)
		}
		if len(kept) == 0 {
			delete(n.queue, id)
			delete(n.firstAt, id)
		} else {
			n.queue[id] = kept
		}
	}
}

// ownedBy drops queued notes whose host is no longer owned by the channel's
// tenant. It is the last check before a message leaves the server.
func (n *Notifier) ownedBy(ctx context.Context, ch NotificationChannel, q []queuedNote) []queuedNote {
	if ch.TenantID == 0 {
		return q
	}
	out := q[:0:0]
	for _, note := range q {
		if note.alert.HostID != nil {
			var t int64
			if err := n.app.db.GetContext(ctx, &t, `SELECT tenant_id FROM hosts WHERE id=?`, *note.alert.HostID); err != nil || t != ch.TenantID {
				continue
			}
		}
		out = append(out, note)
	}
	return out
}

func (n *Notifier) add(chID int64, al Alert, event string) {
	if len(n.queue[chID]) == 0 {
		n.firstAt[chID] = time.Now()
	}
	// Replace an older queued event for the same alert so a fire+resolve in
	// the same window collapses to the latest state.
	q := n.queue[chID]
	for i := range q {
		if q[i].alert.ID == al.ID {
			q[i] = queuedNote{al, event}
			return
		}
	}
	n.queue[chID] = append(q, queuedNote{al, event})
}

func (n *Notifier) loop(ctx context.Context) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	rem := time.NewTicker(time.Minute)
	defer rem.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n.flushDue(ctx)
		case <-rem.C:
			n.reminders(ctx)
		}
	}
}

func (n *Notifier) flushDue(ctx context.Context) {
	wait := time.Duration(n.app.alerting().GroupWaitSeconds) * time.Second
	n.mu.Lock()
	due := map[int64][]queuedNote{}
	for id, q := range n.queue {
		if len(q) > 0 && time.Since(n.firstAt[id]) >= wait {
			due[id] = q
			delete(n.queue, id)
			delete(n.firstAt, id)
		}
	}
	n.mu.Unlock()
	if len(due) == 0 {
		return
	}
	chs := map[int64]NotificationChannel{}
	for _, c := range n.channelList(ctx) {
		chs[c.ID] = c
	}
	for id, q := range due {
		ch, ok := chs[id]
		if !ok {
			continue
		}
		go n.deliver(ctx, ch, q)
	}
}

func (n *Notifier) buildMessage(ctx context.Context, q []queuedNote) notify.Message {
	a := n.app
	base := strings.TrimRight(a.settings.General().ServerURL, "/")
	sort.SliceStable(q, func(i, j int) bool { return severityRank(q[i].alert.Severity) > severityRank(q[j].alert.Severity) })
	var items []notify.Item
	firing, resolved := 0, 0
	maxSev := "warning"
	hosts := map[string]bool{}
	tenantName := ""
	for _, e := range q {
		al := e.alert
		status := "firing"
		if e.event == "resolved" {
			status = "resolved"
			resolved++
		} else {
			firing++
			if severityRank(al.Severity) > severityRank(maxSev) {
				maxSev = al.Severity
			}
		}
		it := notify.Item{AlertID: al.ID, Event: e.event, Status: status, Severity: al.Severity, Title: al.Title, Message: al.Message,
			Host: al.HostName, Value: al.Value, Threshold: al.Threshold, StartedAt: al.StartedAt, ResolvedAt: al.ResolvedAt, Acked: al.AckedBy != ""}
		if al.HostID != nil {
			it.HostID = *al.HostID
		}
		if base != "" {
			it.URL = fmt.Sprintf("%s/alerts/%d", base, al.ID)
		}
		if al.HostName != "" {
			hosts[al.HostName] = true
		}
		if tenantName == "" && al.TenantID != 0 {
			_ = a.db.GetContext(ctx, &tenantName, `SELECT name FROM tenants WHERE id=?`, al.TenantID)
		}
		it.Tenant = tenantName
		items = append(items, it)
	}
	product := a.settings.Branding(0).ProductName
	status := "firing"
	switch {
	case firing == 0:
		status = "resolved"
	case resolved > 0:
		status = "mixed"
	}
	var subject string
	if len(items) == 1 {
		it := items[0]
		tag := strings.ToUpper(it.Severity)
		if it.Status == "resolved" {
			tag = "RESOLVED"
		} else if it.Event == "reminder" {
			tag = "STILL " + tag
		} else if it.Event == "flapping" {
			tag = "FLAPPING"
		}
		subject = fmt.Sprintf("[%s] %s", tag, it.Title)
	} else {
		var parts []string
		if firing > 0 {
			parts = append(parts, fmt.Sprintf("%d firing", firing))
		}
		if resolved > 0 {
			parts = append(parts, fmt.Sprintf("%d resolved", resolved))
		}
		where := ""
		if len(hosts) == 1 {
			for h := range hosts {
				where = " on " + h
			}
		}
		subject = fmt.Sprintf("[%s] %s%s", strings.ToUpper(product), strings.Join(parts, ", "), where)
	}
	if tenantName != "" {
		subject += " · " + tenantName
	}
	url := base
	if base != "" {
		url = base + "/alerts"
	}
	return notify.Message{Subject: subject, Status: status, Severity: maxSev, Items: items, URL: url, Product: product}
}

func (n *Notifier) smtpConfig() notify.SMTP {
	s := n.app.settings.SMTP()
	return notify.SMTP{Host: s.Host, Port: s.Port, Username: s.Username, Password: s.Password, From: s.From, TLSMode: s.TLSMode, SkipVerify: s.SkipVerify}
}

func (n *Notifier) deliver(ctx context.Context, ch NotificationChannel, q []queuedNote) {
	a := n.app
	if q = n.ownedBy(ctx, ch, q); len(q) == 0 {
		return
	}
	msg := n.buildMessage(ctx, q)
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err = notify.Send(sctx, n.app.guardFor(ch.TenantID), ch.Type, json.RawMessage(ch.Config), n.smtpConfig(), msg)
		cancel()
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(attempt+1) * 5 * time.Second):
		}
	}
	now := db.Now()
	ids := make([]int64, 0, len(q))
	for _, e := range q {
		ids = append(ids, e.alert.ID)
	}
	status, errStr := "sent", ""
	if err != nil {
		status, errStr = "failed", err.Error()
		a.log.Warn("notification failed", "channel", ch.Name, "type", ch.Type, "err", err)
	}
	_, _ = a.db.ExecContext(ctx, `INSERT INTO notification_log (tenant_id, channel_id, alert_ids, status, error, created_at) VALUES (?,?,?,?,?,?)`,
		ch.TenantID, ch.ID, IntList(ids), status, errStr, now)
	_, _ = a.db.ExecContext(ctx, `UPDATE notification_channels SET last_error=?, last_sent_at=CASE WHEN ?='' THEN ? ELSE last_sent_at END WHERE id=?`, errStr, errStr, now, ch.ID)
	if err != nil {
		return
	}
	n.mu.Lock()
	for _, e := range q {
		n.lastSent[[2]int64{ch.ID, e.alert.ID}] = now
	}
	n.mu.Unlock()
	for _, e := range q {
		_, _ = a.db.ExecContext(ctx, `UPDATE alerts SET last_notified_at=?, notify_count=notify_count+1 WHERE id=?`, now, e.alert.ID)
		_, _ = a.db.ExecContext(ctx, `INSERT INTO alert_events (tenant_id, alert_id, host_id, event, severity, message, actor, created_at) VALUES (?,?,?,?,?,?,?,?)`,
			e.alert.TenantID, e.alert.ID, e.alert.HostID, "notified", e.alert.Severity, e.event+" via "+ch.Name, "", now)
	}
}

// reminders re-sends unacknowledged firing alerts per channel repeat interval.
func (n *Notifier) reminders(ctx context.Context) {
	now := db.Now()
	chs := n.channelList(ctx)
	for _, al := range n.app.alerts.Active() {
		if al.Status != "firing" || al.AckedBy != "" || al.Flapping || al.Muted || n.app.alerts.suppressed(&al) {
			continue
		}
		h := n.hostInfo(ctx, al.HostID)
		if h != nil {
			al.HostName = h.Name
		}
		for _, ch := range chs {
			if ch.RepeatMinutes <= 0 || !channelMatches(ch, al, "reminder", h) {
				continue
			}
			k := [2]int64{ch.ID, al.ID}
			n.mu.Lock()
			last, ok := n.lastSent[k]
			if !ok {
				last = al.LastNotifiedAt
				if last == 0 {
					// Never notified (e.g. fired during maintenance that has
					// since ended): notify now.
					last = now - int64(ch.RepeatMinutes)*60
				}
				n.lastSent[k] = last
			}
			if now-last >= int64(ch.RepeatMinutes)*60 {
				ev := "reminder"
				if al.LastNotifiedAt == 0 {
					ev = "fired"
				}
				n.add(ch.ID, al, ev)
				n.lastSent[k] = now
			}
			n.mu.Unlock()
		}
	}
	// Forget state for alerts no longer active.
	active := map[int64]bool{}
	for _, al := range n.app.alerts.Active() {
		active[al.ID] = true
	}
	n.mu.Lock()
	for k := range n.lastSent {
		if !active[k[1]] {
			delete(n.lastSent, k)
		}
	}
	n.mu.Unlock()
}

// SendTest delivers a test notification synchronously.
func (n *Notifier) SendTest(ctx context.Context, ch NotificationChannel) error {
	product := n.app.settings.Branding(0).ProductName
	msg := notify.Message{
		Subject: "[TEST] " + product + " notification test", Status: "firing", Severity: "warning", Product: product,
		URL: n.app.settings.General().ServerURL,
		Items: []notify.Item{{Event: "test", Status: "firing", Severity: "warning", Title: "Test notification",
			Message: "If you can read this, the " + ch.Type + " channel \"" + ch.Name + "\" works.", Host: "example-host", StartedAt: db.Now()}},
	}
	return notify.Send(ctx, n.app.guardFor(ch.TenantID), ch.Type, json.RawMessage(ch.Config), n.smtpConfig(), msg)
}
