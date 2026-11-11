package app

import (
	"context"
	"crypto/subtle"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sentrel/internal/version"
	"sentrel/server/authn"
	"sentrel/server/db"
)

// PublicInfo is shown on the login page.
type PublicInfo struct {
	SetupRequired bool     `json:"setup_required"`
	Version       string   `json:"version"`
	Branding      Branding `json:"branding"`
	TenantSlug    string   `json:"tenant_slug,omitempty"`
	TenantName    string   `json:"tenant_name,omitempty"`
	LDAP          bool     `json:"ldap"`
	RADIUS        bool     `json:"radius"`
	OIDCEnabled   bool     `json:"oidc_enabled"`
	OIDCLabel     string   `json:"oidc_label,omitempty"`
	ServerURL     string   `json:"server_url"`
	TLSMode       string   `json:"tls_mode"`
}

// tenantForRequest resolves a tenant from ?tenant=<slug> or a custom portal
// hostname, for login-page branding.
func (a *App) tenantForRequest(ctx context.Context, slug, host string) *Tenant {
	var t Tenant
	if slug != "" {
		if err := a.db.GetContext(ctx, &t, `SELECT * FROM tenants WHERE slug=? AND id<>0 AND disabled=0`, slug); err == nil {
			return &t
		}
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host != "" {
		if err := a.db.GetContext(ctx, &t, `SELECT * FROM tenants WHERE hostname=? COLLATE NOCASE AND hostname<>'' AND id<>0 AND disabled=0`, host); err == nil {
			return &t
		}
	}
	return nil
}

func (a *App) setupRequired(ctx context.Context) bool {
	var n int
	_ = a.db.GetContext(ctx, &n, `SELECT COUNT(*) FROM users`)
	return n == 0
}

func (a *App) apiPublicInfo(c *Ctx) (any, error) {
	info := PublicInfo{SetupRequired: a.setupRequired(c.ctx()), Version: version.Version, LDAP: a.settings.LDAP().Enabled,
		RADIUS: a.settings.RADIUS().Enabled, ServerURL: a.settings.General().ServerURL, TLSMode: a.srv.Mode()}
	if oc := a.settings.OIDC(); oc.Enabled {
		info.OIDCEnabled, info.OIDCLabel = true, firstNonEmpty(oc.ButtonLabel, "SSO")
	}
	var tid int64
	if t := a.tenantForRequest(c.ctx(), c.Q("tenant"), c.R.Host); t != nil {
		tid, info.TenantSlug, info.TenantName = t.ID, t.Slug, t.Name
	}
	info.Branding = a.settings.Branding(tid)
	return info, nil
}

// SetupReq completes the first-run wizard.
type SetupReq struct {
	Token      string `json:"token"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	Email      string `json:"email"`
	ServerURL  string `json:"server_url"`
	TLSMode    string `json:"tls_mode"` // http, selfsigned, acme
	Hostname   string `json:"hostname"`
	ACMEEmail  string `json:"acme_email"`
	Timezone   string `json:"timezone"`
	TrustProxy bool   `json:"trust_proxy"`
	// VulnEnabled opts in to CVE scanning (downloads a ~3 GB database).
	VulnEnabled bool `json:"vuln_enabled"`
}

func (a *App) apiSetup(c *Ctx) (any, error) {
	var req SetupReq
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	a.setupMu.Lock()
	tok := a.setupToken
	a.setupMu.Unlock()
	if !a.setupRequired(c.ctx()) {
		return nil, conflict("setup has already been completed")
	}
	if tok == "" || subtle.ConstantTimeCompare([]byte(strings.TrimSpace(strings.ToUpper(req.Token))), []byte(tok)) != 1 {
		a.audit(c.ctx(), auditEntry{Actor: "setup", Action: "setup.bad_token", IP: a.clientIP(c.R)})
		return nil, forbidden("invalid setup token (printed in the server log and stored in the data directory as setup-token)")
	}
	if err := validateUsername(req.Username); err != nil {
		return nil, err
	}
	if err := a.validatePassword(req.Password); err != nil {
		return nil, err
	}
	switch req.TLSMode {
	case "", "http":
		req.TLSMode = "http"
	case "selfsigned":
	case "acme":
		if req.Hostname == "" || net.ParseIP(req.Hostname) != nil {
			return nil, badRequest("Let's Encrypt needs a DNS hostname that points at this server")
		}
	default:
		return nil, badRequest("tls_mode must be http, selfsigned or acme")
	}
	if req.ServerURL != "" {
		if u, err := url.Parse(req.ServerURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, badRequest("server URL must look like https://monitor.example.com")
		}
	}
	if req.Timezone != "" {
		if _, err := time.LoadLocation(req.Timezone); err != nil {
			return nil, badRequest("unknown timezone")
		}
	}
	hash, err := authn.HashPassword(req.Password)
	if err != nil {
		return nil, err
	}
	res, err := a.db.ExecContext(c.ctx(), `INSERT INTO users (tenant_id, username, email, display_name, password_hash, role, created_at) VALUES (0,?,?,?,?,?,?)`,
		req.Username, req.Email, req.Username, hash, RoleAdmin, db.Now())
	if err != nil {
		return nil, err
	}
	uid, _ := res.LastInsertId()
	g := a.settings.General()
	g.ServerURL = strings.TrimRight(req.ServerURL, "/")
	g.SetupCompleted = true
	if req.Timezone != "" {
		g.Timezone = req.Timezone
	}
	if err := a.settings.Save(c.ctx(), 0, keyGeneral, g); err != nil {
		return nil, err
	}
	t := a.settings.TLS()
	prevMode := t.Mode
	t.Mode, t.Hostname, t.ACMEEmail, t.TrustProxy = req.TLSMode, req.Hostname, req.ACMEEmail, req.TrustProxy
	if err := a.settings.Save(c.ctx(), 0, keyTLS, t); err != nil {
		return nil, err
	}
	vs := a.settings.Vuln()
	vs.Enabled = req.VulnEnabled
	if err := a.settings.Save(c.ctx(), 0, keyVuln, vs); err != nil {
		return nil, err
	}
	if vs.Enabled {
		_ = a.vuln.SyncNow()
	}
	a.setupMu.Lock()
	a.setupToken = ""
	a.setupMu.Unlock()
	_ = os.Remove(filepath.Join(a.cfg.DataDir, "setup-token"))
	a.audit(c.ctx(), auditEntry{UserID: &uid, Actor: req.Username, Action: "setup.completed", IP: a.clientIP(c.R),
		Details: map[string]any{"tls_mode": req.TLSMode, "server_url": g.ServerURL}})
	u, _ := a.getUser(c.ctx(), uid)
	csrf, err := a.auth.createSession(c.W, c.R, u, 0)
	if err != nil {
		return nil, err
	}
	if prevMode != t.Mode && t.Mode != "http" {
		time.AfterFunc(1500*time.Millisecond, a.srv.Restart)
	}
	return loginResp{CSRF: csrf, User: u}, nil
}

func validateUsername(u string) error {
	if len(u) < 2 || len(u) > 64 {
		return badRequest("username must be 2-64 characters")
	}
	for _, r := range u {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-@", r)) {
			return badRequest("username may contain letters, digits and . _ - @")
		}
	}
	return nil
}

func (a *App) validatePassword(pw string) error {
	min := a.settings.Security().PasswordMinLength
	if min < 8 {
		min = 8
	}
	if len(pw) < min {
		return badRequest("password must be at least %d characters", min)
	}
	if len(pw) > 256 {
		return badRequest("password too long")
	}
	lower := strings.ToLower(pw)
	for _, bad := range []string{"password", "sentrel", "12345678", "qwertyui"} {
		if strings.Contains(lower, bad) && len(pw) < 16 {
			return badRequest("password is too easy to guess")
		}
	}
	return nil
}

// MeResp describes the logged-in user.
type MeResp struct {
	User             *User    `json:"user"`
	Permissions      []string `json:"permissions"`
	Tenant           *Tenant  `json:"tenant"`
	MFAPending       bool     `json:"mfa_pending"`
	MFASetupRequired bool     `json:"mfa_setup_required"`
	MFAMethods       []string `json:"mfa_methods"`
	CSRF             string   `json:"csrf_token"`
	Branding         Branding `json:"branding"`
	ServerURL        string   `json:"server_url"`
	Version          string   `json:"version"`
	APIKey           bool     `json:"api_key"`
	// PasswordChangeRequired is true while the session is restricted to
	// changing the password (the UI shows the change-password screen).
	PasswordChangeRequired bool `json:"password_change_required"`
}

func (a *App) apiMe(c *Ctx) (any, error) {
	u, err := a.getUser(c.ctx(), *c.P.UserID)
	if err != nil {
		return nil, err
	}
	var n int
	_ = a.db.GetContext(c.ctx(), &n, `SELECT COUNT(*) FROM webauthn_credentials WHERE user_id=?`, u.ID)
	u.PasskeyCount = n
	var t Tenant
	_ = a.db.GetContext(c.ctx(), &t, `SELECT * FROM tenants WHERE id=?`, u.TenantID)
	return MeResp{User: u, Permissions: c.P.Perms(), Tenant: &t, MFAPending: c.P.MFAPending && !c.P.MFAEnroll, MFASetupRequired: c.P.MFAEnroll,
		MFAMethods: a.auth.mfaMethods(c.ctx(), u), CSRF: c.P.CSRF, Branding: a.settings.Branding(u.TenantID),
		ServerURL: a.publicURL(c.R), Version: version.Version, APIKey: c.P.APIKeyID != 0, PasswordChangeRequired: c.P.MustChangePW}, nil
}

type profileReq struct {
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
	Theme       string `json:"theme"`
}

func (a *App) apiUpdateMe(c *Ctx) (any, error) {
	var req profileReq
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	if req.Theme != "light" && req.Theme != "dark" && req.Theme != "system" {
		req.Theme = "system"
	}
	_, err := a.db.ExecContext(c.ctx(), `UPDATE users SET display_name=?, email=?, theme=? WHERE id=?`, truncateStr(req.DisplayName, 100), truncateStr(req.Email, 200), req.Theme, *c.P.UserID)
	return nil, err
}

type changePWReq struct {
	Current string `json:"current_password"`
	New     string `json:"new_password"`
}

func (a *App) apiChangePassword(c *Ctx) (any, error) {
	if c.P.MFAPending && !c.P.MFAEnroll {
		return nil, &apiError{Status: 401, Code: "mfa_required", Msg: "second factor required"}
	}
	if c.P.SessionID == "" {
		return nil, &apiError{Status: 403, Code: "interactive_session_required", Msg: "this action needs a signed-in browser session; API keys cannot do it"}
	}
	var req changePWReq
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	u, err := a.getUser(c.ctx(), *c.P.UserID)
	if err != nil {
		return nil, err
	}
	if u.AuthSource != "local" {
		return nil, badRequest("password is managed by %s", strings.ToUpper(u.AuthSource))
	}
	if !authn.CheckPassword(u.PasswordHash, req.Current) {
		return nil, badRequest("current password is incorrect")
	}
	if err := a.validatePassword(req.New); err != nil {
		return nil, err
	}
	h, err := authn.HashPassword(req.New)
	if err != nil {
		return nil, err
	}
	if _, err := a.db.ExecContext(c.ctx(), `UPDATE users SET password_hash=?, must_change_pw=0 WHERE id=?`, h, u.ID); err != nil {
		return nil, err
	}
	// Other sessions are logged out.
	_, _ = a.db.ExecContext(c.ctx(), `DELETE FROM sessions WHERE user_id=? AND id_hash<>?`, u.ID, c.P.SessionID)
	c.auditT(u.TenantID, "user.password_changed", "user", itoa(u.ID), nil)
	return nil, nil
}

func (a *App) apiListPasskeys(c *Ctx) (any, error) {
	type pk struct {
		ID         int64  `db:"id" json:"id"`
		Name       string `db:"name" json:"name"`
		CreatedAt  int64  `db:"created_at" json:"created_at"`
		LastUsedAt int64  `db:"last_used_at" json:"last_used_at"`
	}
	out := []pk{}
	err := a.db.SelectContext(c.ctx(), &out, `SELECT id, name, created_at, last_used_at FROM webauthn_credentials WHERE user_id=? ORDER BY id`, *c.P.UserID)
	return out, err
}

func (a *App) apiDeletePasskey(c *Ctx) (any, error) {
	res, err := a.db.ExecContext(c.ctx(), `DELETE FROM webauthn_credentials WHERE id=? AND user_id=?`, c.ID(), *c.P.UserID)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, errNotFound
	}
	c.audit("user.passkey_removed", "user", itoa(*c.P.UserID), nil)
	return nil, nil
}

func (a *App) apiListSessions(c *Ctx) (any, error) {
	type sess struct {
		IDHash     string `db:"id_hash" json:"-"`
		IP         string `db:"ip" json:"ip"`
		UserAgent  string `db:"user_agent" json:"user_agent"`
		CreatedAt  int64  `db:"created_at" json:"created_at"`
		LastSeenAt int64  `db:"last_seen_at" json:"last_seen_at"`
		Current    bool   `db:"-" json:"current"`
	}
	out := []sess{}
	if err := a.db.SelectContext(c.ctx(), &out, `SELECT id_hash, ip, user_agent, created_at, last_seen_at FROM sessions WHERE user_id=? AND expires_at>? ORDER BY last_seen_at DESC`,
		*c.P.UserID, db.Now()); err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Current = out[i].IDHash == c.P.SessionID
	}
	return out, nil
}

func (a *App) apiRevokeOtherSessions(c *Ctx) (any, error) {
	// Without a current session "everything but this one" would be every
	// session of the owner, so an API-key caller must never get here.
	if c.P.SessionID == "" {
		return nil, &apiError{Status: 403, Code: "interactive_session_required", Msg: "this action needs a signed-in browser session; API keys cannot do it"}
	}
	_, err := a.db.ExecContext(c.ctx(), `DELETE FROM sessions WHERE user_id=? AND id_hash<>?`, *c.P.UserID, c.P.SessionID)
	return nil, err
}

// --- dashboard ---

type dashboard struct {
	Hosts struct {
		Total       int `json:"total"`
		Up          int `json:"up"`
		Down        int `json:"down"`
		Pending     int `json:"pending"`
		Maintenance int `json:"maintenance"`
		// Down with the alert marked as expected; not included in Down.
		DownExpected int `json:"down_expected"`
	} `json:"hosts"`
	Alerts struct {
		Critical int `json:"critical"`
		Warning  int `json:"warning"`
		Acked    int `json:"acked"`
		Expected int `json:"expected"`
	} `json:"alerts"`
	Checks struct {
		Total   int `json:"total"`
		Up      int `json:"up"`
		Down    int `json:"down"`
		Warning int `json:"warning"`
	} `json:"checks"`
	VulnEnabled     bool           `json:"vuln_enabled"`
	Upgrades        int            `json:"upgrades_pending"`
	SecurityUpdates int            `json:"security_updates"`
	RebootRequired  int            `json:"reboot_required"`
	Vulns           map[string]int `json:"vulnerabilities"`
	VulnsInactive   int            `json:"vulnerabilities_inactive"`
	VulnsTotal      int            `json:"vulnerabilities_total"`
	VulnsFixable    int            `json:"vulnerabilities_fixable"`
	RecentEvents    []AlertEvent   `json:"recent_events"`
	FiringAlerts    []Alert        `json:"firing_alerts"`
}

func (a *App) apiDashboard(c *Ctx) (any, error) {
	ctx := c.ctx()
	tw, targs := c.tenantWhere("tenant_id")
	var d dashboard
	type kv struct {
		K string `db:"k"`
		N int    `db:"n"`
	}
	var rows []kv
	_ = a.db.SelectContext(ctx, &rows, `SELECT status AS k, COUNT(*) AS n FROM hosts WHERE `+tw+` GROUP BY status`, targs...)
	for _, r := range rows {
		d.Hosts.Total += r.N
		switch r.K {
		case "up":
			d.Hosts.Up = r.N
		case "down":
			d.Hosts.Down = r.N
		default:
			d.Hosts.Pending += r.N
		}
	}
	var ids []int64
	_ = a.db.SelectContext(ctx, &ids, `SELECT id FROM hosts WHERE `+tw, targs...)
	expectedDown := a.alerts.expectedDown()
	for _, id := range ids {
		if a.maint.hostInWindow(id) {
			d.Hosts.Maintenance++
		}
		// A host that is expected to be down is not counted as a problem.
		if expectedDown[id] && d.Hosts.Down > 0 {
			d.Hosts.Down--
			d.Hosts.DownExpected++
		}
	}
	rows = nil
	_ = a.db.SelectContext(ctx, &rows, `SELECT status AS k, COUNT(*) AS n FROM checks WHERE enabled=1 AND `+tw+` GROUP BY status`, targs...)
	for _, r := range rows {
		d.Checks.Total += r.N
		switch r.K {
		case "up":
			d.Checks.Up = r.N
		case "down":
			d.Checks.Down = r.N
		case "warning":
			d.Checks.Warning = r.N
		}
	}
	d.FiringAlerts = []Alert{}
	names := a.hostNames(ctx)
	for _, al := range a.alerts.Active() {
		if al.Status != "firing" || !c.P.CanTenant(al.TenantID) {
			continue
		}
		if tw != "1=1" && len(targs) == 1 && al.TenantID != targs[0].(int64) {
			continue
		}
		if al.Expected {
			// Not a problem to act on: counted, but kept off the dashboard list.
			d.Alerts.Expected++
			continue
		}
		if al.AckedBy != "" {
			d.Alerts.Acked++
		} else if al.Severity == "critical" {
			d.Alerts.Critical++
		} else {
			d.Alerts.Warning++
		}
		if al.HostID != nil {
			al.HostName = names[*al.HostID]
			al.InMaintenance = a.maint.hostSuppressed(*al.HostID)
		}
		d.FiringAlerts = append(d.FiringAlerts, al)
	}
	_ = a.db.GetContext(ctx, &d.Upgrades, `SELECT COALESCE(SUM(upgradable_count),0) FROM inventory_status WHERE `+tw, targs...)
	_ = a.db.GetContext(ctx, &d.SecurityUpdates, `SELECT COALESCE(SUM(security_count),0) FROM inventory_status WHERE `+tw, targs...)
	_ = a.db.GetContext(ctx, &d.RebootRequired, `SELECT COUNT(*) FROM hosts WHERE reboot_required=1 AND `+tw, targs...)
	d.Vulns = map[string]int{}
	d.VulnEnabled = a.vuln.Enabled()
	if d.VulnEnabled {
		var hids []int64
		_ = a.db.SelectContext(ctx, &hids, `SELECT id FROM hosts WHERE kind='agent' AND revoked=0 AND `+tw, targs...)
		var tot vulnCounts
		for _, id := range hids {
			if h, err := a.getHost(ctx, id); err == nil {
				tot.add(a.hostVulnCounts(ctx, h))
			}
		}
		d.Vulns = tot.bySeverity()
		d.VulnsTotal, d.VulnsFixable, d.VulnsInactive = tot.Total, tot.Fixable, tot.Inactive
	}
	d.RecentEvents = []AlertEvent{}
	ew, eargs := c.tenantWhere("e.tenant_id")
	_ = a.db.SelectContext(ctx, &d.RecentEvents, `SELECT e.*, al.title, COALESCE(h.name,'') AS host_name FROM alert_events e JOIN alerts al ON al.id=e.alert_id
		LEFT JOIN hosts h ON h.id=e.host_id WHERE e.event IN ('fired','resolved','acked','escalated','flapping') AND `+ew+` ORDER BY e.id DESC LIMIT 15`, eargs...)
	return d, nil
}

func (a *App) hostNames(ctx context.Context) map[int64]string {
	type hn struct {
		ID   int64  `db:"id"`
		Name string `db:"name"`
	}
	var rows []hn
	_ = a.db.SelectContext(ctx, &rows, `SELECT id, name FROM hosts`)
	m := make(map[int64]string, len(rows))
	for _, r := range rows {
		m[r.ID] = r.Name
	}
	return m
}
