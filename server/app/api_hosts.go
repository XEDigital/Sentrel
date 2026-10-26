package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"sentrel/server/db"
	"sentrel/server/metrics"
	"sentrel/server/snmp"
)

// visibleHost loads a host and checks tenant access.
func (c *Ctx) visibleHost(id int64) (*Host, error) {
	h, err := c.a.getHost(c.ctx(), id)
	if err != nil {
		return nil, errNotFound
	}
	if !c.P.CanTenant(h.TenantID) {
		return nil, errNotFound
	}
	return h, nil
}

func (a *App) apiListHosts(c *Ctx) (any, error) {
	ctx := c.ctx()
	tw, args := c.tenantWhere("h.tenant_id")
	q := `SELECT ` + hostCols + ` FROM hosts h WHERE ` + tw
	if s := c.Q("status"); s != "" {
		q += ` AND h.status=?`
		args = append(args, s)
	}
	if k := c.Q("kind"); k != "" {
		q += ` AND h.kind=?`
		args = append(args, k)
	}
	if g := c.QInt("group_id", 0); g > 0 {
		q += ` AND h.group_id=?`
		args = append(args, g)
	}
	if s := strings.TrimSpace(c.Q("q")); s != "" {
		q += ` AND (h.name LIKE ? OR h.address LIKE ? OR h.tags LIKE ?)`
		like := "%" + s + "%"
		args = append(args, like, like, like)
	}
	q += ` ORDER BY h.name COLLATE NOCASE`
	hosts := []Host{}
	if err := a.db.SelectContext(ctx, &hosts, q, args...); err != nil {
		return nil, err
	}
	if tag := c.Q("tag"); tag != "" {
		var f []Host
		for _, h := range hosts {
			for _, t := range h.Tags {
				if strings.EqualFold(t, tag) {
					f = append(f, h)
					break
				}
			}
		}
		hosts = f
	}
	a.decorateHosts(ctx, hosts)
	return hosts, nil
}

func (a *App) decorateHosts(ctx context.Context, hosts []Host) {
	groups := map[int64]string{}
	var gs []HostGroup
	_ = a.db.SelectContext(ctx, &gs, `SELECT id, tenant_id, name, description, color, created_at, 0 AS host_count FROM host_groups`)
	for _, g := range gs {
		groups[g.ID] = g.Name
	}
	tenants := map[int64]string{}
	var ts []Tenant
	_ = a.db.SelectContext(ctx, &ts, `SELECT * FROM tenants`)
	for _, t := range ts {
		tenants[t.ID] = t.Name
	}
	inv := map[int64]InventoryStatus{}
	var is []InventoryStatus
	_ = a.db.SelectContext(ctx, &is, `SELECT * FROM inventory_status`)
	for _, i := range is {
		inv[i.HostID] = i
	}
	type vc struct {
		HostID   int64  `db:"host_id"`
		Severity string `db:"severity"`
		N        int    `db:"n"`
	}
	var vcs []vc
	if a.vuln.Enabled() {
		_ = a.db.SelectContext(ctx, &vcs, `SELECT host_id, severity, COUNT(*) AS n FROM (SELECT f.host_id, f.vuln_id, `+sevAggSQL+` AS severity FROM vuln_findings f WHERE f.status='open' GROUP BY f.host_id, f.vuln_id) WHERE severity IN ('Critical','High') GROUP BY host_id, severity`)
	}
	vmap := map[int64][2]int{}
	for _, v := range vcs {
		x := vmap[v.HostID]
		if v.Severity == "Critical" {
			x[0] = v.N
		} else {
			x[1] = v.N
		}
		vmap[v.HostID] = x
	}
	alertsBy := map[int64][]Alert{}
	for _, al := range a.alerts.Active() {
		if al.Status == "firing" && al.HostID != nil {
			alertsBy[*al.HostID] = append(alertsBy[*al.HostID], al)
		}
	}
	for i := range hosts {
		h := &hosts[i]
		a.resolveHost(h)
		h.Parent = a.parentInfo(ctx, "host", h.ID)
		if h.GroupID != nil {
			h.GroupName = groups[*h.GroupID]
		}
		h.TenantName = tenants[h.TenantID]
		h.UpgradeCount = inv[h.ID].UpgradableCount
		h.SecurityCount = inv[h.ID].SecurityCount
		h.VulnCritical, h.VulnHigh = vmap[h.ID][0], vmap[h.ID][1]
		h.InMaintenance = a.maint.hostInWindow(h.ID)
		h.Summary = a.latest.get(h.ID)
		for _, al := range alertsBy[h.ID] {
			h.AlertCount++
			if severityRank(al.Severity) > severityRank(h.AlertSeverity) {
				h.AlertSeverity = al.Severity
			}
		}
		h.Connected = h.Connected || a.hub.Connected(h.ID)
	}
}

// HostDetail is the full host view.
type HostDetail struct {
	Host
	Inventory        *InventoryStatus `json:"inventory"`
	Connection       map[string]any   `json:"connection"`
	AgentConfig      any              `json:"agent_config"`
	SNMPConfig       map[string]any   `json:"snmp_config,omitempty"`
	LatestAgent      string           `json:"latest_agent_version"`
	CheckCount       int              `json:"check_count"`
	OpenFindings     map[string]int   `json:"open_findings"`
	InactiveFindings int              `json:"inactive_findings"`
	VulnCounts       vulnCounts       `json:"vuln_counts"`
	VulnEnabled      bool             `json:"vuln_enabled"`
	// Settings reports each inheritable security and permission setting as
	// {effective, override, global, inherited}.
	Settings map[string]HostSetting `json:"settings"`
	// NeverBlockSystem lists addresses that are always protected (the server's own).
	NeverBlockSystem []string `json:"never_block_system"`
}

func (a *App) apiGetHost(c *Ctx) (any, error) {
	h, err := c.visibleHost(c.ID())
	if err != nil {
		return nil, err
	}
	hs := []Host{*h}
	a.decorateHosts(c.ctx(), hs)
	d := HostDetail{Host: hs[0], OpenFindings: map[string]int{}}
	d.Settings = a.hostSettingsView(h)
	d.NeverBlockSystem = a.serverAddrs()
	d.State = h.State
	var inv InventoryStatus
	if err := a.db.GetContext(c.ctx(), &inv, `SELECT * FROM inventory_status WHERE host_id=?`, h.ID); err == nil {
		d.Inventory = &inv
	}
	if remote, since, mtls, ok := a.hub.ConnInfo(h.ID); ok {
		d.Connection = map[string]any{"remote": remote, "since": since.Unix(), "mtls": mtls}
	}
	if h.Kind == "agent" {
		d.AgentConfig = a.agentConfig(h)
		hi := hostInfo(h)
		if b, err := a.agentBinary(hi.Os, hi.Arch); err == nil {
			d.LatestAgent = b.Version
		}
	}
	if h.Kind == "snmp" {
		d.SNMPConfig = redact(h.SNMPConfig, snmp.SecretFields)
	}
	_ = a.db.GetContext(c.ctx(), &d.CheckCount, `SELECT COUNT(*) FROM checks WHERE host_id=?`, h.ID)
	d.VulnEnabled = a.vuln.Enabled()
	if d.VulnEnabled {
		d.VulnCounts = a.hostVulnCounts(c.ctx(), h)
		for k, v := range d.VulnCounts.bySeverity() {
			d.OpenFindings[k] = v
		}
		d.InactiveFindings = d.VulnCounts.Inactive
	}
	return d, nil
}

// redact removes secret fields from a JSON object, marking them as set.
func redact(raw []byte, secrets []string) map[string]any {
	m := map[string]any{}
	_ = json.Unmarshal(raw, &m)
	for _, k := range secrets {
		if v, ok := m[k]; ok && v != "" && v != nil {
			m[k] = ""
			m[k+"_set"] = true
		}
	}
	return m
}

// mergeSecrets keeps existing secret values when the update leaves them empty.
func mergeSecrets(newRaw, oldRaw []byte, secrets []string) []byte {
	nm := map[string]any{}
	om := map[string]any{}
	_ = json.Unmarshal(newRaw, &nm)
	_ = json.Unmarshal(oldRaw, &om)
	for _, k := range secrets {
		if v, ok := nm[k]; !ok || v == "" || v == nil {
			if ov, ok := om[k]; ok {
				nm[k] = ov
			}
		}
		delete(nm, k+"_set")
	}
	b, _ := json.Marshal(nm)
	return b
}

type hostUpdate struct {
	Name                 *string       `json:"name"`
	Address              *string       `json:"address"`
	GroupID              *int64        `json:"group_id"`
	Tags                 *[]string     `json:"tags"`
	Notes                *string       `json:"notes"`
	IntervalSeconds      *int          `json:"interval_seconds"`
	InventoryInterval    *int          `json:"inventory_interval"`
	RetentionDays        *int          `json:"retention_days"`
	AgentOptions         *AgentOptions `json:"agent_options"`
	AllowUpgrades        *bool         `json:"allow_upgrades"`
	AllowIPBlock         *bool         `json:"allow_ip_block"`
	AllowCleanup         *bool         `json:"allow_cleanup"`
	AutoRemoveOldKernels *bool         `json:"auto_remove_old_kernels"`
	AutoBlock            *bool         `json:"auto_block"`
	// Settings sets or clears inheritable overrides: {"allow_cleanup": true, "auto_block_minutes": null}.
	Settings       map[string]json.RawMessage `json:"settings"`
	TenantID       *int64                     `json:"tenant_id"`
	ClearInterval  bool                       `json:"clear_interval"`
	ClearRetention bool                       `json:"clear_retention"`
	// Parent: a host or check this host depends on. Omit both to keep it;
	// an empty parent_type clears it.
	ParentType *string `json:"parent_type"`
	ParentID   *int64  `json:"parent_id"`
}

func (a *App) apiUpdateHost(c *Ctx) (any, error) {
	h, err := c.visibleHost(c.ID())
	if err != nil {
		return nil, err
	}
	var req hostUpdate
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	ctx := c.ctx()
	// Authorise and check the tenant move before anything else is validated or
	// written, so a rejected request changes nothing.
	moving := req.TenantID != nil && *req.TenantID != h.TenantID
	if moving {
		if !c.P.IsProvider() || !c.P.Has(PermHosts) {
			return nil, forbidden("only provider operators can move hosts between tenants")
		}
		if _, err := c.tenantFor(*req.TenantID); err != nil {
			return nil, err
		}
	}
	dep := depRequest{ParentType: req.ParentType, ParentID: req.ParentID}
	depType, depID := dep.values()
	if dep.present() && !moving {
		if err := a.validateDependency(ctx, h.TenantID, "host", h.ID, depType, depID); err != nil {
			return nil, err
		}
	}
	sets := []string{}
	args := []any{}
	set := func(col string, v any) {
		for i, s := range sets {
			if s == col+"=?" {
				args[i] = v
				return
			}
		}
		sets = append(sets, col+"=?")
		args = append(args, v)
	}
	changes := map[string]any{}
	if req.Name != nil {
		n := strings.TrimSpace(*req.Name)
		if n == "" || len(n) > 128 {
			return nil, badRequest("name must be 1-128 characters")
		}
		set("name", n)
		changes["name"] = n
	}
	if req.Address != nil {
		set("address", strings.TrimSpace(*req.Address))
		changes["address"] = *req.Address
	}
	if req.GroupID != nil {
		if *req.GroupID == 0 {
			set("group_id", nil)
		} else {
			var gt int64
			if err := a.db.GetContext(ctx, &gt, `SELECT tenant_id FROM host_groups WHERE id=?`, *req.GroupID); err != nil || (gt != h.TenantID && gt != 0) {
				return nil, badRequest("unknown group for this tenant")
			}
			set("group_id", *req.GroupID)
		}
		changes["group_id"] = *req.GroupID
	}
	if req.Tags != nil {
		set("tags", StrList(cleanTags(*req.Tags)))
		changes["tags"] = *req.Tags
	}
	if req.Notes != nil {
		set("notes", truncateStr(*req.Notes, 4000))
	}
	if req.IntervalSeconds != nil {
		if *req.IntervalSeconds < 5 || *req.IntervalSeconds > 3600 {
			return nil, badRequest("interval must be 5-3600 seconds")
		}
		set("interval_seconds", *req.IntervalSeconds)
		changes["interval_seconds"] = *req.IntervalSeconds
	} else if req.ClearInterval {
		set("interval_seconds", nil)
	}
	if req.InventoryInterval != nil {
		if *req.InventoryInterval < 300 {
			return nil, badRequest("inventory interval must be at least 300 seconds")
		}
		set("inventory_interval", *req.InventoryInterval)
	}
	if req.RetentionDays != nil {
		if *req.RetentionDays < 1 || *req.RetentionDays > 3650 {
			return nil, badRequest("retention must be 1-3650 days")
		}
		set("retention_days", *req.RetentionDays)
		changes["retention_days"] = *req.RetentionDays
	} else if req.ClearRetention {
		set("retention_days", nil)
	}
	opts := hostOptions(h)
	optsChanged := false
	if req.AgentOptions != nil {
		if t := req.AgentOptions.PortscanThresholdPerMin; t != nil && (*t < 1 || *t > 100000) {
			return nil, badRequest("port-scan threshold must be 1-100000 per minute")
		}
		pl, err := normalizeAllowlist(req.AgentOptions.PortscanAllowlist)
		if err != nil {
			return nil, err
		}
		req.AgentOptions.PortscanAllowlist = pl
		// Security overrides are managed through "settings"; keep them.
		req.AgentOptions.BruteforceThreshold, req.AgentOptions.BruteforceWindowMin = opts.BruteforceThreshold, opts.BruteforceWindowMin
		req.AgentOptions.AutoBlockThreshold, req.AgentOptions.AutoBlockMinutes = opts.AutoBlockThreshold, opts.AutoBlockMinutes
		req.AgentOptions.NeverBlock = opts.NeverBlock
		if req.AgentOptions.BruteforceEnabled == nil {
			req.AgentOptions.BruteforceEnabled = opts.BruteforceEnabled
		}
		if req.AgentOptions.PortscanEnabled == nil {
			req.AgentOptions.PortscanEnabled = opts.PortscanEnabled
		}
		if req.AgentOptions.PortscanThresholdPerMin == nil {
			req.AgentOptions.PortscanThresholdPerMin = opts.PortscanThresholdPerMin
		}
		opts = *req.AgentOptions
		optsChanged = true
		changes["agent_options"] = req.AgentOptions
	}
	if len(req.Settings) > 0 {
		if err := a.applyHostSettings(h, &opts, req.Settings, set, changes); err != nil {
			return nil, err
		}
		optsChanged = true
	}
	if optsChanged {
		set("agent_options", mustJSON(opts))
	}
	if req.AllowUpgrades != nil {
		set("allow_upgrades", *req.AllowUpgrades)
		changes["allow_upgrades"] = *req.AllowUpgrades
	}
	if req.AllowIPBlock != nil {
		set("allow_ip_block", *req.AllowIPBlock)
		changes["allow_ip_block"] = *req.AllowIPBlock
	}
	if req.AutoBlock != nil {
		set("auto_block", *req.AutoBlock)
		changes["auto_block"] = *req.AutoBlock
	}
	if req.AllowCleanup != nil {
		set("allow_cleanup", *req.AllowCleanup)
		changes["allow_cleanup"] = *req.AllowCleanup
	}
	if req.AutoRemoveOldKernels != nil {
		set("auto_remove_old_kernels", *req.AutoRemoveOldKernels)
		changes["auto_remove_old_kernels"] = *req.AutoRemoveOldKernels
	}
	// Everything is validated; commit the whole update in one transaction.
	if len(sets) > 0 {
		set("updated_at", db.Now())
	}
	err = a.db.Tx(ctx, func(tx *sqlxTx) error {
		if len(sets) > 0 {
			if _, err := tx.ExecContext(ctx, `UPDATE hosts SET `+strings.Join(sets, ", ")+` WHERE id=?`, append(args, h.ID)...); err != nil {
				return err
			}
		}
		if moving {
			return moveHostTenantTx(ctx, tx, h.ID, *req.TenantID)
		}
		if dep.present() {
			return setDependencyTx(ctx, tx, h.TenantID, "host", h.ID, depType, depID)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if moving {
		changes["tenant_id"] = *req.TenantID
		a.hostTransferred(ctx, h.ID, *req.TenantID)
	} else if dep.present() {
		changes["parent_type"], changes["parent_id"] = depType, depID
	}
	_ = a.alerts.refreshHosts(ctx)
	hostTenantCache.Delete(h.ID)
	a.hub.PushConfig(ctx, h.ID)
	if h.Kind == "snmp" {
		a.snmp.Schedule(h.ID)
	}
	c.auditT(h.TenantID, "host.updated", "host", itoa(h.ID), changes)
	a.events.publish(Event{Type: "host.updated", TenantID: h.TenantID, HostID: h.ID})
	nh, err := a.getHost(ctx, h.ID)
	if err != nil {
		return nil, err
	}
	return HostDetail{Host: *nh, OpenFindings: map[string]int{}, Settings: a.hostSettingsView(nh), NeverBlockSystem: a.serverAddrs()}, nil
}

func cleanTags(tags []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, t := range tags {
		t = strings.TrimSpace(t)
		if t == "" || len(t) > 64 || seen[strings.ToLower(t)] {
			continue
		}
		seen[strings.ToLower(t)] = true
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// moveHostTenant reassigns a host and every row that belongs to it.
func (a *App) moveHostTenant(ctx context.Context, hostID, tenant int64) error {
	return a.db.Tx(ctx, func(tx *sqlxTx) error { return moveHostTenantTx(ctx, tx, hostID, tenant) })
}

// moveHostTenantTx is the transactional part of a host transfer. Everything a
// host owns moves with it; things that only make sense inside the old tenant
// (dependencies, maintenance windows and update schedules that name the host,
// the old group) are removed instead.
func moveHostTenantTx(ctx context.Context, tx *sqlxTx, hostID, tenant int64) error {
	stmts := []string{
		`UPDATE hosts SET tenant_id=?, group_id=NULL WHERE id=?`,
		`UPDATE checks SET tenant_id=? WHERE host_id=?`,
		`UPDATE alerts SET tenant_id=? WHERE host_id=?`,
		`UPDATE alert_events SET tenant_id=? WHERE host_id=?`,
		`UPDATE packages SET tenant_id=? WHERE host_id=?`,
		`UPDATE inventory_status SET tenant_id=? WHERE host_id=?`,
		`UPDATE jobs SET tenant_id=? WHERE host_id=?`,
		`UPDATE security_events SET tenant_id=? WHERE host_id=?`,
		`UPDATE ip_blocks SET tenant_id=? WHERE host_id=?`,
		`UPDATE fail2ban_status SET tenant_id=? WHERE host_id=?`,
		`UPDATE disk_health SET tenant_id=? WHERE host_id=?`,
		`UPDATE portscan_status SET tenant_id=? WHERE host_id=?`,
		`UPDATE vuln_scans SET tenant_id=? WHERE host_id=?`,
		`UPDATE vuln_findings SET tenant_id=? WHERE host_id=?`,
		`UPDATE lldp_neighbors SET tenant_id=? WHERE host_id=?`,
		`UPDATE revoked_certs SET tenant_id=? WHERE host_id=?`,
		`UPDATE uptime_daily SET tenant_id=? WHERE item_type='host' AND item_id=?`,
		`UPDATE uptime_daily SET tenant_id=? WHERE item_type='check' AND item_id IN (SELECT id FROM checks WHERE host_id=?)`,
		// Host-scoped threshold rules govern the host for its new owner.
		`UPDATE OR REPLACE threshold_rules SET tenant_id=? WHERE scope='host' AND scope_id=?`,
	}
	for _, s := range stmts {
		if _, err := tx.ExecContext(ctx, s, tenant, hostID); err != nil {
			return err
		}
	}
	// Dependencies never cross tenants (the host's own and its checks').
	if _, err := tx.ExecContext(ctx, `DELETE FROM dependencies WHERE (child_type='host' AND child_id=?1) OR (parent_type='host' AND parent_id=?1)
		OR (child_type='check' AND child_id IN (SELECT id FROM checks WHERE host_id=?1))
		OR (parent_type='check' AND parent_id IN (SELECT id FROM checks WHERE host_id=?1))`, hostID); err != nil {
		return err
	}
	// Update schedules naming the host belong to the previous owner.
	if _, err := tx.ExecContext(ctx, `DELETE FROM update_schedules WHERE scope='host' AND scope_id=? AND tenant_id<>?`, hostID, tenant); err != nil {
		return err
	}
	// Maintenance windows of other tenants stop naming the host; a window left
	// with no scope is removed.
	var wins []struct {
		ID       int64   `db:"id"`
		ScopeIDs IntList `db:"scope_ids"`
	}
	if err := tx.SelectContext(ctx, &wins, `SELECT id, scope_ids FROM maintenance_windows WHERE scope='host' AND tenant_id<>?`, tenant); err != nil {
		return err
	}
	for _, w := range wins {
		kept := IntList{}
		for _, id := range w.ScopeIDs {
			if id != hostID {
				kept = append(kept, id)
			}
		}
		if len(kept) == len(w.ScopeIDs) {
			continue
		}
		var err error
		if len(kept) == 0 {
			_, err = tx.ExecContext(ctx, `DELETE FROM maintenance_windows WHERE id=?`, w.ID)
		} else {
			_, err = tx.ExecContext(ctx, `UPDATE maintenance_windows SET scope_ids=? WHERE id=?`, kept, w.ID)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// hostTransferred moves the in-memory state of a host to its new owner after
// the transfer committed: live alerts, queued notifications and cached checks.
func (a *App) hostTransferred(ctx context.Context, hostID, tenant int64) {
	var name string
	_ = a.db.GetContext(ctx, &name, `SELECT name FROM hosts WHERE id=?`, hostID)
	a.alerts.transferHost(hostID, tenant, name)
	a.notifier.hostMoved(ctx, hostID, tenant)
	a.checks.hostMoved(hostID, tenant)
	a.maint.refresh(ctx)
	_ = a.alerts.ReloadRules(ctx)
}

func (a *App) apiDeleteHost(c *Ctx) (any, error) {
	h, err := c.visibleHost(c.ID())
	if err != nil {
		return nil, err
	}
	ctx := c.ctx()
	if h.CertSerial != "" {
		_, _ = a.db.ExecContext(ctx, `INSERT OR IGNORE INTO revoked_certs (serial, tenant_id, host_id, revoked_at) VALUES (?,?,?,?)`, h.CertSerial, h.TenantID, h.ID, db.Now())
	}
	a.hub.Disconnect(h.ID, "host deleted", true)
	a.forgetDependencies(ctx, "host", h.ID)
	if _, err := a.db.ExecContext(ctx, `DELETE FROM hosts WHERE id=?`, h.ID); err != nil {
		return nil, err
	}
	_, _ = a.db.ExecContext(ctx, `DELETE FROM uptime_daily WHERE item_type='host' AND item_id=?`, h.ID)
	_, _ = a.db.ExecContext(ctx, `DELETE FROM settings WHERE tenant_id=0 AND key=?`, "invhash:"+itoa(h.ID))
	go func() { _ = a.ts.DeleteHost(context.Background(), h.ID) }()
	a.alerts.forgetHost(h.ID)
	a.latest.forget(h.ID)
	a.snmp.forget(h.ID)
	a.snmp.state.Forget(h.Address)
	c.auditT(h.TenantID, "host.deleted", "host", itoa(h.ID), map[string]any{"name": h.Name, "kind": h.Kind})
	a.events.publish(Event{Type: "host.deleted", TenantID: h.TenantID, HostID: h.ID})
	return nil, nil
}

func (a *App) apiRevokeHost(c *Ctx) (any, error) {
	h, err := c.visibleHost(c.ID())
	if err != nil {
		return nil, err
	}
	if h.Kind != "agent" {
		return nil, badRequest("only agent hosts have certificates")
	}
	ctx := c.ctx()
	_, _ = a.db.ExecContext(ctx, `INSERT OR IGNORE INTO revoked_certs (serial, tenant_id, host_id, revoked_at) VALUES (?,?,?,?)`, h.CertSerial, h.TenantID, h.ID, db.Now())
	_, err = a.db.ExecContext(ctx, `UPDATE hosts SET revoked=1, connected=0, status='unknown' WHERE id=?`, h.ID)
	a.hub.Disconnect(h.ID, "certificate revoked", true)
	a.alerts.forceResolve(ctx, hostDownKey(h.ID), "agent revoked", c.P.Name)
	c.auditT(h.TenantID, "host.revoked", "host", itoa(h.ID), map[string]any{"name": h.Name})
	return nil, err
}

// --- metrics for host graphs ---

type panelDef struct {
	Metrics []string
	Legend  string // label used for the legend
}

var hostPanels = map[string]panelDef{
	"cpu":            {[]string{"cpu_usage_percent", "cpu_iowait_percent", "cpu_steal_percent"}, ""},
	"memory":         {[]string{"mem_used_percent", "swap_used_percent"}, ""},
	"load":           {[]string{"load1", "load5", "load15"}, ""},
	"disk":           {[]string{"disk_used_percent"}, "mount"},
	"diskio":         {[]string{"disk_read_bytes_per_sec", "disk_write_bytes_per_sec"}, "device"},
	"network":        {[]string{"net_rx_bytes_per_sec", "net_tx_bytes_per_sec"}, "iface"},
	"temperature":    {[]string{"temperature_celsius", "cpu_temperature_celsius"}, "sensor"},
	"processes":      {[]string{"process_count"}, ""},
	"containers_cpu": {[]string{"container_cpu_percent"}, "container"},
	"containers_mem": {[]string{"container_memory_bytes"}, "container"},
	"if_traffic":     {[]string{"if_in_bps", "if_out_bps"}, "ifname"},
	"if_util":        {[]string{"if_util_percent"}, "ifname"},
	"agent":          {[]string{"agent_cpu_percent", "agent_rss_bytes"}, ""},
	"packages":       {[]string{"packages_upgradable", "packages_security_updates"}, ""},
	"auth":           {[]string{"auth_failures_window_max"}, ""},
	"vulns":          {[]string{"vulnerabilities_open"}, "severity"},
	"wireless":       {[]string{"wireless_signal_dbm", "wireless_clients"}, ""},
	"checks":         {[]string{"check_latency_ms"}, "check_id"},
}

// parseRange reads start/end (unix seconds, or start as a duration like
// "6h" meaning "6h ago") and step from the query string.
func parseRange(c *Ctx, def time.Duration) (time.Time, time.Time, time.Duration) {
	end := time.Now()
	start := end.Add(-def)
	if v := c.Q("start"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			start = time.Unix(int64(f), 0)
		} else if d, err := time.ParseDuration(v); err == nil {
			start = end.Add(-d)
		}
	}
	if v := c.Q("end"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			end = time.Unix(int64(f), 0)
		}
	}
	if !start.Before(end) {
		start = end.Add(-def)
	}
	var step time.Duration
	if v := c.Q("step"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			step = d
		} else if f, err := strconv.Atoi(v); err == nil {
			step = time.Duration(f) * time.Second
		}
	}
	if step <= 0 {
		step = metrics.AutoStep(start, end)
	}
	if end.Sub(start)/step > 11000 {
		step = end.Sub(start) / 11000
	}
	return start, end, step
}

type seriesOut struct {
	Name   string            `json:"name"`
	Metric string            `json:"metric"`
	Labels map[string]string `json:"labels"`
	Points []metrics.Point   `json:"points"`
}

func (a *App) apiHostMetrics(c *Ctx) (any, error) {
	h, err := c.visibleHost(c.ID())
	if err != nil {
		return nil, err
	}
	pd, ok := hostPanels[c.Q("panel")]
	if !ok {
		return nil, badRequest("unknown panel")
	}
	start, end, step := parseRange(c, time.Hour)
	out := []seriesOut{}
	for _, m := range pd.Metrics {
		sel := fmt.Sprintf(`%s%s{host_id="%d"}`, metrics.Prefix, m, h.ID)
		if f := c.Q("filter"); f != "" && pd.Legend != "" {
			sel = fmt.Sprintf(`%s%s{host_id="%d",%s=%q}`, metrics.Prefix, m, h.ID, pd.Legend, f)
		}
		q := sel
		if step > time.Minute {
			q = fmt.Sprintf("avg_over_time(%s[%ds])", sel, int(step.Seconds()))
		}
		ser, err := a.ts.QueryRange(c.ctx(), q, start, end, step)
		if err != nil {
			return nil, badRequest("query: %v", err)
		}
		for _, s := range ser {
			name := m
			if pd.Legend != "" && s.Labels[pd.Legend] != "" {
				name = s.Labels[pd.Legend]
				if len(pd.Metrics) > 1 {
					name = m + " " + name
				}
			}
			delete(s.Labels, "__name__")
			out = append(out, seriesOut{Name: name, Metric: m, Labels: s.Labels, Points: s.Points})
		}
	}
	return map[string]any{"panel": c.Q("panel"), "start": start.Unix(), "end": end.Unix(), "step": int(step.Seconds()), "series": out}, nil
}

func (a *App) apiHostPackages(c *Ctx) (any, error) {
	h, err := c.visibleHost(c.ID())
	if err != nil {
		return nil, err
	}
	q := `SELECT * FROM packages WHERE host_id=?`
	args := []any{h.ID}
	if c.Q("upgradable") == "1" || c.Q("upgradable") == "true" {
		q += ` AND new_version<>''`
	}
	if s := c.Q("q"); s != "" {
		q += ` AND name LIKE ?`
		args = append(args, "%"+s+"%")
	}
	q += ` ORDER BY security DESC, (new_version<>'') DESC, name LIMIT 5000`
	out := []Package{}
	err = a.db.SelectContext(c.ctx(), &out, q, args...)
	return out, err
}

func (a *App) apiHostSecurity(c *Ctx) (any, error) {
	h, err := c.visibleHost(c.ID())
	if err != nil {
		return nil, err
	}
	ctx := c.ctx()
	hours := c.QInt("hours", 24)
	since := time.Now().Add(-time.Duration(hours) * time.Hour).Unix()
	type agg struct {
		IP        string   `json:"ip"`
		Total     int      `json:"total"`
		LastSeen  int64    `json:"last_seen"`
		Usernames []string `json:"usernames"`
		Blocked   bool     `json:"blocked"`
	}
	type ev struct {
		IP        string  `db:"ip"`
		Count     int     `db:"count"`
		Usernames StrList `db:"usernames"`
		WindowEnd int64   `db:"window_end"`
	}
	var evs []ev
	_ = a.db.SelectContext(ctx, &evs, `SELECT ip, count, usernames, window_end FROM security_events WHERE host_id=? AND kind='login' AND window_end>=? ORDER BY window_end DESC LIMIT 20000`, h.ID, since)
	byIP := map[string]*agg{}
	userSeen := map[string]map[string]bool{}
	for _, e := range evs {
		g, ok := byIP[e.IP]
		if !ok {
			g = &agg{IP: e.IP, Usernames: []string{}}
			byIP[e.IP] = g
			userSeen[e.IP] = map[string]bool{}
		}
		g.Total += e.Count
		if e.WindowEnd > g.LastSeen {
			g.LastSeen = e.WindowEnd
		}
		for _, u := range e.Usernames {
			if !userSeen[e.IP][u] && len(g.Usernames) < 15 {
				userSeen[e.IP][u] = true
				g.Usernames = append(g.Usernames, u)
			}
		}
	}
	rows := make([]agg, 0, len(byIP))
	for _, g := range byIP {
		rows = append(rows, *g)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Total > rows[j].Total })
	if len(rows) > 200 {
		rows = rows[:200]
	}
	blocks := []IPBlock{}
	_ = a.db.SelectContext(ctx, &blocks, `SELECT * FROM ip_blocks WHERE host_id=? ORDER BY created_at DESC LIMIT 200`, h.ID)
	active := map[string]bool{}
	for _, b := range blocks {
		if b.Status == "active" || b.Status == "pending" {
			active[b.IP] = true
		}
	}
	for i := range rows {
		rows[i].Blocked = active[rows[i].IP]
	}
	var f2b struct {
		Data      JSON  `db:"data" json:"data"`
		UpdatedAt int64 `db:"updated_at" json:"updated_at"`
	}
	_ = a.db.GetContext(ctx, &f2b, `SELECT data, updated_at FROM fail2ban_status WHERE host_id=?`, h.ID)
	var total int
	for _, r := range rows {
		total += r.Total
	}
	type scanRow struct {
		IP        string `db:"ip" json:"ip"`
		FirstSeen int64  `db:"first_seen" json:"first_seen"`
		LastSeen  int64  `db:"last_seen" json:"last_seen"`
		Reports   int    `db:"reports" json:"reports"`
		Blocked   bool   `db:"-" json:"blocked"`
	}
	scans := []scanRow{}
	_ = a.db.SelectContext(ctx, &scans, `SELECT ip, MIN(window_start) AS first_seen, MAX(window_end) AS last_seen, COUNT(*) AS reports FROM security_events
		WHERE host_id=? AND kind='portscan' AND window_end>=? GROUP BY ip ORDER BY last_seen DESC LIMIT 200`, h.ID, since)
	for i := range scans {
		scans[i].Blocked = active[scans[i].IP]
	}
	ps := struct {
		Known     bool   `db:"-" json:"known"`
		Supported bool   `db:"supported" json:"supported"`
		Active    bool   `db:"active" json:"active"`
		Reason    string `db:"reason" json:"reason"`
		UpdatedAt int64  `db:"updated_at" json:"updated_at"`
	}{}
	ps.Known = a.db.GetContext(ctx, &ps, `SELECT supported, active, reason, updated_at FROM portscan_status WHERE host_id=?`, h.ID) == nil
	d := a.hostSecurity(h)
	return map[string]any{"failed_logins": rows, "total": total, "blocks": blocks, "fail2ban": f2b, "hours": hours,
		"allow_ip_block": h.AllowIPBlock, "auto_block": h.AutoBlock, "notify_failed_logins": a.hostNotifies(h, "bruteforce"), "auto_block_threshold": d.AutoBlockThreshold, "window_minutes": d.BruteforceWindowMin, "auto_block_minutes": d.AutoBlockMinutes,
		"portscans": scans, "portscan_status": ps, "notify_portscan": a.hostNotifies(h, "portscan")}, nil
}

type blockReq struct {
	IP      string `json:"ip"`
	Minutes int    `json:"minutes"`
	Reason  string `json:"reason"`
	Confirm bool   `json:"confirm"`
}

func (a *App) apiBlockIP(c *Ctx) (any, error) {
	h, err := c.visibleHost(c.ID())
	if err != nil {
		return nil, err
	}
	var req blockReq
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	ip := net.ParseIP(strings.TrimSpace(req.IP))
	if ip == nil {
		return nil, badRequest("invalid IP address")
	}
	if !req.Confirm {
		return nil, ErrConfirmation
	}
	if a.neverBlocked(h, ip.String()) {
		return nil, errNeverBlock
	}
	if !h.AllowIPBlock {
		return nil, forbidden("IP blocking is not enabled for this host")
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		reason = "blocked by " + c.P.Name
	}
	return a.blockIP(c.ctx(), h, ip.String(), req.Minutes, reason, c.P.Name)
}

func (a *App) apiUnblockIP(c *Ctx) (any, error) {
	h, err := c.visibleHost(c.ID())
	if err != nil {
		return nil, err
	}
	var req blockReq
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	if net.ParseIP(req.IP) == nil {
		return nil, badRequest("invalid IP address")
	}
	return a.jobs.Create(c.ctx(), c.P, JobRequest{HostID: h.ID, Type: "unblock_ip", Params: map[string]string{"ip": req.IP}, Confirm: true, Timeout: 120})
}

func (a *App) apiHostThresholds(c *Ctx) (any, error) {
	h, err := c.visibleHost(c.ID())
	if err != nil {
		return nil, err
	}
	ref, ok := a.alerts.host(h.ID)
	if !ok {
		return nil, errNotFound
	}
	return a.alerts.rules.merged(ref), nil
}

func (a *App) apiHostLLDP(c *Ctx) (any, error) {
	h, err := c.visibleHost(c.ID())
	if err != nil {
		return nil, err
	}
	out := []LLDPNeighbor{}
	if err := a.db.SelectContext(c.ctx(), &out, `SELECT * FROM lldp_neighbors WHERE host_id=? ORDER BY local_port`, h.ID); err != nil {
		return nil, err
	}
	// Link neighbours that are monitored devices.
	for i := range out {
		var id int64
		if out[i].RemoteSysName != "" && a.db.GetContext(c.ctx(), &id, `SELECT id FROM hosts WHERE (name=? COLLATE NOCASE OR address=?) AND tenant_id=? LIMIT 1`,
			out[i].RemoteSysName, out[i].RemoteMgmtAddr, h.TenantID) == nil {
			out[i].RemoteHostID = &id
		}
	}
	return out, nil
}

type uptimeDay struct {
	Day         string  `db:"day" json:"day"`
	UpSeconds   int64   `db:"up_seconds" json:"up_seconds"`
	DownSeconds int64   `db:"down_seconds" json:"down_seconds"`
	Percent     float64 `db:"-" json:"percent"`
}

func (a *App) uptimeDays(ctx context.Context, typ string, id int64, days int) ([]uptimeDay, float64) {
	if days <= 0 || days > 365 {
		days = 90
	}
	since := time.Now().UTC().AddDate(0, 0, -days+1).Format("2006-01-02")
	rows := []uptimeDay{}
	_ = a.db.SelectContext(ctx, &rows, `SELECT day, up_seconds, down_seconds FROM uptime_daily WHERE item_type=? AND item_id=? AND day>=? ORDER BY day`, typ, id, since)
	var up, total int64
	for i := range rows {
		t := rows[i].UpSeconds + rows[i].DownSeconds
		if t > 0 {
			rows[i].Percent = float64(rows[i].UpSeconds) * 100 / float64(t)
		}
		up += rows[i].UpSeconds
		total += t
	}
	pct := -1.0
	if total > 0 {
		pct = float64(up) * 100 / float64(total)
	}
	return rows, pct
}

func (a *App) apiHostUptime(c *Ctx) (any, error) {
	h, err := c.visibleHost(c.ID())
	if err != nil {
		return nil, err
	}
	days, pct := a.uptimeDays(c.ctx(), "host", h.ID, c.queryLimit("days", 90, 366))
	return map[string]any{"days": days, "percent": pct}, nil
}

type confirmReq struct {
	Confirm bool `json:"confirm"`
	Force   bool `json:"force"`
}

func (a *App) apiUpdateAgent(c *Ctx) (any, error) {
	h, err := c.visibleHost(c.ID())
	if err != nil {
		return nil, err
	}
	var req confirmReq
	_ = c.Decode(&req)
	params := map[string]string{}
	if req.Force {
		params["force"] = "true"
	}
	return a.jobs.Create(c.ctx(), c.P, JobRequest{HostID: h.ID, Type: "self_update", Confirm: req.Confirm, Params: params, Timeout: 600})
}

func (a *App) apiRefreshInventory(c *Ctx) (any, error) {
	h, err := c.visibleHost(c.ID())
	if err != nil {
		return nil, err
	}
	// Read-only collection job: any viewer may trigger it.
	return a.jobs.Create(c.ctx(), c.P, JobRequest{HostID: h.ID, Type: "refresh_inventory", Timeout: 1800})
}

func (a *App) apiScanHost(c *Ctx) (any, error) {
	h, err := c.visibleHost(c.ID())
	if err != nil {
		return nil, err
	}
	if !a.vuln.Enabled() {
		return nil, conflict(msgVulnDisabled)
	}
	if !a.vuln.enqueue(h.ID, "manual") {
		return map[string]any{"queued": false, "message": "a scan is already queued for this host"}, nil
	}
	c.auditT(h.TenantID, "vuln.scan_requested", "host", itoa(h.ID), nil)
	return map[string]any{"queued": true}, nil
}

// --- SNMP & target hosts ---

type snmpHostReq struct {
	Name     string      `json:"name"`
	Address  string      `json:"address"`
	TenantID int64       `json:"tenant_id"`
	GroupID  *int64      `json:"group_id"`
	Tags     []string    `json:"tags"`
	SNMP     snmp.Config `json:"snmp"`
	SkipTest bool        `json:"skip_test"`
}

func validSNMP(cfg *snmp.Config) error {
	switch cfg.Version {
	case "", "2c":
		cfg.Version = "2c"
	case "3":
		if cfg.Username == "" {
			return badRequest("SNMPv3 needs a username")
		}
	default:
		return badRequest("SNMP version must be 2c or 3")
	}
	if cfg.Port == 0 {
		cfg.Port = 161
	}
	if cfg.IntervalSec == 0 {
		cfg.IntervalSec = 60
	}
	if cfg.IntervalSec < 15 {
		return badRequest("poll interval must be at least 15 seconds")
	}
	if cfg.Profile == "" {
		cfg.Profile = "auto"
	}
	for _, m := range cfg.ExtraMetrics {
		if err := snmp.ValidateMetric(m); err != nil {
			return badRequest("extra metric: %v", err)
		}
	}
	return nil
}

func (a *App) apiCreateSNMPHost(c *Ctx) (any, error) {
	var req snmpHostReq
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	tenant, err := c.tenantFor(req.TenantID)
	if err != nil {
		return nil, err
	}
	req.Address = strings.TrimSpace(req.Address)
	if req.Address == "" {
		return nil, badRequest("address is required")
	}
	if err := validSNMP(&req.SNMP); err != nil {
		return nil, err
	}
	var sys *snmp.System
	if !req.SkipTest {
		ctx, cancel := context.WithTimeout(c.ctx(), 20*time.Second)
		defer cancel()
		sys, err = snmp.Probe(ctx, req.Address, req.SNMP)
		if err != nil {
			return nil, badRequest("SNMP test failed: %v (use skip_test to add anyway)", err)
		}
	}
	name := strings.TrimSpace(req.Name)
	if name == "" && sys != nil {
		name = sys.Name
	}
	if name == "" {
		name = req.Address
	}
	info := "{}"
	if sys != nil {
		info = mustJSON(SNMPInfo{System: *sys})
	}
	now := db.Now()
	res, err := a.db.ExecContext(c.ctx(), `INSERT INTO hosts (tenant_id, kind, name, address, group_id, tags, snmp_config, snmp_info, status, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`, tenant, "snmp", name, req.Address, nullID(req.GroupID), StrList(cleanTags(req.Tags)), mustJSON(req.SNMP), info, "pending", now, now)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	_ = a.alerts.refreshHosts(c.ctx())
	a.snmp.Schedule(id)
	c.auditT(tenant, "host.created", "host", itoa(id), map[string]any{"kind": "snmp", "name": name, "address": req.Address})
	h, err := a.getHost(c.ctx(), id)
	return created{h}, err
}

func nullID(p *int64) any {
	if p == nil || *p == 0 {
		return nil
	}
	return *p
}

func (a *App) apiUpdateSNMPHost(c *Ctx) (any, error) {
	h, err := c.visibleHost(c.ID())
	if err != nil {
		return nil, err
	}
	if h.Kind != "snmp" {
		return nil, badRequest("not an SNMP device")
	}
	var req snmpHostReq
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	if err := validSNMP(&req.SNMP); err != nil {
		return nil, err
	}
	merged := mergeSecrets([]byte(mustJSON(req.SNMP)), h.SNMPConfig, snmp.SecretFields)
	addr := strings.TrimSpace(req.Address)
	if addr == "" {
		addr = h.Address
	}
	_, err = a.db.ExecContext(c.ctx(), `UPDATE hosts SET snmp_config=?, address=?, updated_at=? WHERE id=?`, string(merged), addr, db.Now(), h.ID)
	a.snmp.Schedule(h.ID)
	c.auditT(h.TenantID, "host.snmp_updated", "host", itoa(h.ID), nil)
	return nil, err
}

type targetHostReq struct {
	Name     string   `json:"name"`
	Address  string   `json:"address"`
	TenantID int64    `json:"tenant_id"`
	GroupID  *int64   `json:"group_id"`
	Tags     []string `json:"tags"`
	Ping     bool     `json:"add_ping_check"`
}

func (a *App) apiCreateTargetHost(c *Ctx) (any, error) {
	var req targetHostReq
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	tenant, err := c.tenantFor(req.TenantID)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = strings.TrimSpace(req.Address)
	}
	if name == "" {
		return nil, badRequest("name or address is required")
	}
	now := db.Now()
	res, err := a.db.ExecContext(c.ctx(), `INSERT INTO hosts (tenant_id, kind, name, address, group_id, tags, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)`,
		tenant, "target", name, strings.TrimSpace(req.Address), nullID(req.GroupID), StrList(cleanTags(req.Tags)), "pending", now, now)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	if req.Ping && req.Address != "" {
		_, _ = a.db.ExecContext(c.ctx(), `INSERT INTO checks (tenant_id, host_id, name, type, target, interval_seconds, timeout_seconds, failure_threshold, created_at)
			VALUES (?,?,?,?,?,60,5,3,?)`, tenant, id, "Ping "+name, "ping", req.Address, now)
		a.checks.Invalidate(0)
	}
	_ = a.alerts.refreshHosts(c.ctx())
	c.auditT(tenant, "host.created", "host", itoa(id), map[string]any{"kind": "target", "name": name})
	h, err := a.getHost(c.ctx(), id)
	return created{h}, err
}

type snmpTestReq struct {
	Address string      `json:"address"`
	SNMP    snmp.Config `json:"snmp"`
	HostID  int64       `json:"host_id"` // reuse stored secrets
}

func (a *App) apiSNMPTest(c *Ctx) (any, error) {
	var req snmpTestReq
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	if err := validSNMP(&req.SNMP); err != nil {
		return nil, err
	}
	cfg := req.SNMP
	if req.HostID != 0 {
		h, err := c.visibleHost(req.HostID)
		if err != nil {
			return nil, err
		}
		_ = json.Unmarshal(mergeSecrets([]byte(mustJSON(cfg)), h.SNMPConfig, snmp.SecretFields), &cfg)
		if req.Address == "" {
			req.Address = h.Address
		}
	}
	ctx, cancel := context.WithTimeout(c.ctx(), 60*time.Second)
	defer cancel()
	profiles, _ := a.snmp.Profiles()
	// Two polls so counter-based profile metrics (rates) can be shown.
	st := snmp.NewState()
	if _, err := snmp.Poll(ctx, req.Address, cfg, profiles, st); err != nil {
		return map[string]any{"ok": false, "error": err.Error()}, nil
	}
	time.Sleep(2 * time.Second)
	res, err := snmp.Poll(ctx, req.Address, cfg, profiles, st)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}, nil
	}
	ms := map[string]float64{}
	for _, m := range res.Metrics {
		k := m.Name
		for lk, lv := range m.Labels {
			k += "{" + lk + "=" + lv + "}"
		}
		ms[k] = m.Value
	}
	return map[string]any{"ok": true, "system": res.System, "profile": res.Profile, "interfaces": len(res.Interfaces), "metrics": ms,
		"neighbors": len(res.Neighbors), "errors": res.Errors, "duration_ms": res.DurationMs}, nil
}

func (a *App) apiSNMPProfiles(c *Ctx) (any, error) {
	ps, err := a.snmp.Profiles()
	out := []*snmp.Profile{}
	for _, p := range ps {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	resp := map[string]any{"profiles": out, "custom_dir": a.snmp.profileDir()}
	if err != nil {
		resp["error"] = err.Error()
	}
	return resp, nil
}

func (a *App) apiSNMPReload(c *Ctx) (any, error) {
	if err := a.snmp.reloadProfiles(); err != nil {
		return nil, badRequest("profile error: %v", err)
	}
	c.audit("snmp.profiles_reloaded", "", "", nil)
	return a.apiSNMPProfiles(c)
}
