package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"

	"sentrel/internal/version"
	"sentrel/server/agentdist"
	"sentrel/server/authn"
	"sentrel/server/db"
	"sentrel/server/notify"
)

var startedAt = time.Now()

// --- users ---

type userReq struct {
	TenantID     int64  `json:"tenant_id"`
	Username     string `json:"username"`
	Email        string `json:"email"`
	DisplayName  string `json:"display_name"`
	Password     string `json:"password"`
	Role         string `json:"role"`
	AuthSource   string `json:"auth_source"`
	Disabled     *bool  `json:"disabled"`
	MustChangePW *bool  `json:"must_change_password"`
}

func (a *App) apiListUsers(c *Ctx) (any, error) {
	tw, args := c.tenantWhere("u.tenant_id")
	out := []User{}
	if err := a.db.SelectContext(c.ctx(), &out, `SELECT u.* FROM users u WHERE `+tw+` ORDER BY u.username COLLATE NOCASE`, args...); err != nil {
		return nil, err
	}
	for i := range out {
		_ = a.db.GetContext(c.ctx(), &out[i].PasskeyCount, `SELECT COUNT(*) FROM webauthn_credentials WHERE user_id=?`, out[i].ID)
	}
	return out, nil
}

func (a *App) checkRoleAssignable(c *Ctx, role string, tenant int64) error {
	if !ValidRole(role, tenant) {
		if tenant == 0 {
			return badRequest("provider users must be admin, operator or viewer")
		}
		return badRequest("tenant users must be tenant_admin or tenant_viewer")
	}
	return nil
}

func (a *App) apiCreateUser(c *Ctx) (any, error) {
	var req userReq
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	tenant, err := c.tenantFor(req.TenantID)
	if err != nil {
		return nil, err
	}
	if err := validateUsername(req.Username); err != nil {
		return nil, err
	}
	if err := a.checkRoleAssignable(c, req.Role, tenant); err != nil {
		return nil, err
	}
	src := req.AuthSource
	if src == "" {
		src = "local"
	}
	if src != "local" && src != "ldap" && src != "radius" {
		return nil, badRequest("auth_source must be local, ldap or radius")
	}
	hash := ""
	if src == "local" {
		if err := a.validatePassword(req.Password); err != nil {
			return nil, err
		}
		if hash, err = authn.HashPassword(req.Password); err != nil {
			return nil, err
		}
	}
	res, err := a.db.ExecContext(c.ctx(), `INSERT INTO users (tenant_id, username, email, display_name, password_hash, role, auth_source, must_change_pw, created_at)
		VALUES (?,?,?,?,?,?,?,?,?)`, tenant, req.Username, req.Email, firstNonEmpty(req.DisplayName, req.Username), hash, req.Role, src, boolOr(req.MustChangePW, false), db.Now())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	c.auditT(tenant, "user.created", "user", itoa(id), map[string]any{"username": req.Username, "role": req.Role, "auth_source": src})
	u, err := a.getUser(c.ctx(), id)
	return created{u}, err
}

func (a *App) visibleUser(c *Ctx, id int64) (*User, error) {
	u, err := a.getUser(c.ctx(), id)
	if err != nil || !c.P.CanTenant(u.TenantID) {
		return nil, errNotFound
	}
	return u, nil
}

// lastAdmin reports whether u is the only enabled provider admin.
func (a *App) lastAdmin(ctx context.Context, u *User) bool {
	if u.Role != RoleAdmin || u.TenantID != 0 || u.Disabled {
		return false
	}
	var n int
	_ = a.db.GetContext(ctx, &n, `SELECT COUNT(*) FROM users WHERE role='admin' AND tenant_id=0 AND disabled=0`)
	return n <= 1
}

func (a *App) apiUpdateUser(c *Ctx) (any, error) {
	u, err := a.visibleUser(c, c.ID())
	if err != nil {
		return nil, err
	}
	var req userReq
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	ctx := c.ctx()

	// Validate every field first; nothing is written until all of it passes.
	if req.AuthSource != "" && req.AuthSource != u.AuthSource {
		if req.AuthSource != "local" && req.AuthSource != "ldap" && req.AuthSource != "radius" {
			return nil, badRequest("auth_source must be local, ldap or radius")
		}
		return nil, badRequest("the authentication source of an existing user cannot be changed")
	}
	if req.TenantID != 0 && req.TenantID != u.TenantID {
		return nil, badRequest("users cannot be moved between tenants")
	}
	role := u.Role
	if req.Role != "" && req.Role != u.Role {
		if err := a.checkRoleAssignable(c, req.Role, u.TenantID); err != nil {
			return nil, err
		}
		if a.lastAdmin(ctx, u) {
			return nil, badRequest("cannot demote the last administrator")
		}
		role = req.Role
	}
	disabled := u.Disabled
	if req.Disabled != nil && *req.Disabled != u.Disabled {
		if *req.Disabled && u.ID == *c.P.UserID {
			return nil, badRequest("you cannot disable yourself")
		}
		if *req.Disabled && a.lastAdmin(ctx, u) {
			return nil, badRequest("cannot disable the last administrator")
		}
		disabled = *req.Disabled
	}
	mustChange := u.MustChangePW
	if req.MustChangePW != nil {
		mustChange = *req.MustChangePW
	}
	var newHash string
	if req.Password != "" {
		if u.AuthSource != "local" {
			return nil, badRequest("password is managed by %s", u.AuthSource)
		}
		if err := a.validatePassword(req.Password); err != nil {
			return nil, err
		}
		if newHash, err = authn.HashPassword(req.Password); err != nil {
			return nil, err
		}
	}

	// Apply together, then audit and invalidate sessions after the commit.
	tx, err := a.db.BeginTxx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `UPDATE users SET email=?, display_name=?, role=?, disabled=?, must_change_pw=? WHERE id=?`,
		req.Email, firstNonEmpty(req.DisplayName, u.DisplayName), role, disabled, mustChange, u.ID); err != nil {
		return nil, err
	}
	revoke := newHash != "" || disabled || role != u.Role
	if newHash != "" {
		if _, err := tx.ExecContext(ctx, `UPDATE users SET password_hash=? WHERE id=?`, newHash, u.ID); err != nil {
			return nil, err
		}
	}
	if revoke {
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, u.ID); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	c.auditT(u.TenantID, "user.updated", "user", itoa(u.ID), map[string]any{"username": u.Username, "role": role, "disabled": disabled, "password_reset": req.Password != ""})
	return a.getUser(ctx, u.ID)
}

func (a *App) apiDeleteUser(c *Ctx) (any, error) {
	u, err := a.visibleUser(c, c.ID())
	if err != nil {
		return nil, err
	}
	if u.ID == *c.P.UserID {
		return nil, badRequest("you cannot delete yourself")
	}
	if a.lastAdmin(c.ctx(), u) {
		return nil, badRequest("cannot delete the last administrator")
	}
	if _, err := a.db.ExecContext(c.ctx(), `DELETE FROM users WHERE id=?`, u.ID); err != nil {
		return nil, err
	}
	c.auditT(u.TenantID, "user.deleted", "user", itoa(u.ID), map[string]any{"username": u.Username})
	return nil, nil
}

func (a *App) apiResetUser2FA(c *Ctx) (any, error) {
	u, err := a.visibleUser(c, c.ID())
	if err != nil {
		return nil, err
	}
	ctx := c.ctx()
	_, _ = a.db.ExecContext(ctx, `UPDATE users SET totp_enabled=0, totp_secret='', recovery_codes='[]' WHERE id=?`, u.ID)
	_, _ = a.db.ExecContext(ctx, `DELETE FROM webauthn_credentials WHERE user_id=?`, u.ID)
	_, _ = a.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, u.ID)
	c.auditT(u.TenantID, "user.2fa_reset", "user", itoa(u.ID), map[string]any{"username": u.Username})
	return nil, nil
}

// --- tenants ---

type tenantReq struct {
	Name     string `json:"name"`
	Slug     string `json:"slug"`
	Hostname string `json:"hostname"`
	Notes    string `json:"notes"`
	Disabled *bool  `json:"disabled"`
}

func (a *App) apiListTenants(c *Ctx) (any, error) {
	out := []Tenant{}
	if c.P.IsProvider() {
		err := a.db.SelectContext(c.ctx(), &out, `SELECT * FROM tenants ORDER BY id=0 DESC, name COLLATE NOCASE`)
		return out, err
	}
	err := a.db.SelectContext(c.ctx(), &out, `SELECT * FROM tenants WHERE id=?`, c.P.TenantID)
	return out, err
}

func (a *App) apiCreateTenant(c *Ctx) (any, error) {
	var req tenantReq
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Slug = strings.ToLower(strings.TrimSpace(req.Slug))
	if req.Name == "" {
		return nil, badRequest("name is required")
	}
	if req.Slug == "" {
		req.Slug = strings.Trim(regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(strings.ToLower(req.Name), "-"), "-")
	}
	if !slugRe.MatchString(req.Slug) || req.Slug == "provider" {
		return nil, badRequest("slug must be 2-63 lowercase letters, digits or dashes")
	}
	res, err := a.db.ExecContext(c.ctx(), `INSERT INTO tenants (name, slug, hostname, notes, created_at) VALUES (?,?,?,?,?)`,
		req.Name, req.Slug, strings.ToLower(strings.TrimSpace(req.Hostname)), req.Notes, db.Now())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	c.audit("tenant.created", "tenant", itoa(id), req)
	var t Tenant
	err = a.db.GetContext(c.ctx(), &t, `SELECT * FROM tenants WHERE id=?`, id)
	return created{t}, err
}

func (a *App) apiUpdateTenant(c *Ctx) (any, error) {
	id := c.ID()
	var req tenantReq
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	var t Tenant
	if err := a.db.GetContext(c.ctx(), &t, `SELECT * FROM tenants WHERE id=?`, id); err != nil {
		return nil, errNotFound
	}
	if req.Name != "" {
		t.Name = strings.TrimSpace(req.Name)
	}
	if req.Slug != "" && id != 0 {
		s := strings.ToLower(strings.TrimSpace(req.Slug))
		if !slugRe.MatchString(s) {
			return nil, badRequest("invalid slug")
		}
		t.Slug = s
	}
	t.Hostname = strings.ToLower(strings.TrimSpace(req.Hostname))
	t.Notes = req.Notes
	if req.Disabled != nil && id != 0 {
		t.Disabled = *req.Disabled
	}
	_, err := a.db.ExecContext(c.ctx(), `UPDATE tenants SET name=?, slug=?, hostname=?, notes=?, disabled=? WHERE id=?`, t.Name, t.Slug, t.Hostname, t.Notes, t.Disabled, id)
	if err == nil && t.Disabled {
		_, _ = a.db.ExecContext(c.ctx(), `DELETE FROM sessions WHERE tenant_id=?`, id)
	}
	c.audit("tenant.updated", "tenant", itoa(id), req)
	return t, err
}

func (a *App) apiDeleteTenant(c *Ctx) (any, error) {
	id := c.ID()
	if id == 0 {
		return nil, badRequest("the provider tenant cannot be deleted")
	}
	var t Tenant
	if err := a.db.GetContext(c.ctx(), &t, `SELECT * FROM tenants WHERE id=?`, id); err != nil {
		return nil, errNotFound
	}
	var hostIDs []int64
	_ = a.db.SelectContext(c.ctx(), &hostIDs, `SELECT id FROM hosts WHERE tenant_id=?`, id)
	for _, hid := range hostIDs {
		var serial string
		_ = a.db.GetContext(c.ctx(), &serial, `SELECT cert_serial FROM hosts WHERE id=?`, hid)
		if serial != "" {
			_, _ = a.db.ExecContext(c.ctx(), `INSERT OR IGNORE INTO revoked_certs (serial, tenant_id, host_id, revoked_at) VALUES (?,?,?,?)`, serial, id, hid, db.Now())
		}
		a.hub.Disconnect(hid, "tenant deleted", true)
	}
	if _, err := a.db.ExecContext(c.ctx(), `DELETE FROM tenants WHERE id=?`, id); err != nil {
		return nil, err
	}
	// Rows without FK cascade.
	for _, tbl := range []string{"alert_events", "notification_log", "security_events", "ip_blocks", "vuln_scans", "vuln_findings", "uptime_daily", "audit_log", "lldp_neighbors", "packages", "inventory_status", "fail2ban_status", "portscan_status"} {
		_, _ = a.db.ExecContext(c.ctx(), `DELETE FROM `+tbl+` WHERE tenant_id=?`, id)
	}
	for _, hid := range hostIDs {
		a.alerts.forgetHost(hid)
		a.latest.forget(hid)
		go func(h int64) { _ = a.ts.DeleteHost(context.Background(), h) }(hid)
	}
	c.audit("tenant.deleted", "tenant", itoa(id), map[string]any{"name": t.Name, "hosts": len(hostIDs)})
	return nil, nil
}

// --- API keys ---

type apiKeyReq struct {
	Name        string   `json:"name"`
	Scopes      []string `json:"scopes"`
	ExpiresDays int      `json:"expires_days"`
}

func (a *App) apiListKeys(c *Ctx) (any, error) {
	if c.P.MFAPending {
		return nil, unauthorized("second factor required")
	}
	out := []APIKey{}
	q := `SELECT k.*, u.username FROM api_keys k JOIN users u ON u.id=k.user_id WHERE `
	var args []any
	if c.P.Has(PermUsers) {
		tw, ta := c.tenantWhere("k.tenant_id")
		q += tw
		args = ta
	} else {
		q += `k.user_id=?`
		args = []any{*c.P.UserID}
	}
	err := a.db.SelectContext(c.ctx(), &out, q+` ORDER BY k.created_at DESC`, args...)
	return out, err
}

func (a *App) apiCreateKey(c *Ctx) (any, error) {
	if c.P.APIKeyID != 0 {
		return nil, forbidden("API keys cannot create API keys")
	}
	var req apiKeyReq
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		return nil, badRequest("name is required")
	}
	if len(req.Scopes) == 0 {
		req.Scopes = []string{"read"}
	}
	for _, s := range req.Scopes {
		if _, ok := scopePerms[s]; !ok {
			return nil, badRequest("unknown scope %q (read, write, jobs, admin)", s)
		}
	}
	var exp int64
	if req.ExpiresDays > 0 {
		exp = time.Now().Add(time.Duration(req.ExpiresDays) * 24 * time.Hour).Unix()
	}
	prefix := strings.ToLower(randomCode(8))
	secret := randomToken(30)
	res, err := a.db.ExecContext(c.ctx(), `INSERT INTO api_keys (tenant_id, user_id, name, prefix, key_hash, scopes, expires_at, created_at) VALUES (?,?,?,?,?,?,?,?)`,
		c.P.TenantID, *c.P.UserID, req.Name, prefix, hashToken(secret), StrList(req.Scopes), exp, db.Now())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	c.audit("api_key.created", "api_key", itoa(id), map[string]any{"name": req.Name, "scopes": req.Scopes})
	return created{map[string]any{"id": id, "key": "sentrel_" + prefix + "_" + secret, "prefix": prefix, "scopes": req.Scopes, "expires_at": exp}}, nil
}

func (a *App) apiDeleteKey(c *Ctx) (any, error) {
	var k APIKey
	if err := a.db.GetContext(c.ctx(), &k, `SELECT * FROM api_keys WHERE id=?`, c.ID()); err != nil {
		return nil, errNotFound
	}
	if k.UserID != *c.P.UserID && !(c.P.Has(PermUsers) && c.P.CanTenant(k.TenantID)) {
		return nil, errNotFound
	}
	_, err := a.db.ExecContext(c.ctx(), `DELETE FROM api_keys WHERE id=?`, k.ID)
	c.auditT(k.TenantID, "api_key.revoked", "api_key", itoa(k.ID), map[string]any{"name": k.Name})
	return nil, err
}

// --- audit ---

func (a *App) apiAudit(c *Ctx) (any, error) {
	tw, args := c.tenantWhere("tenant_id")
	q := `SELECT * FROM audit_log WHERE ` + tw
	if s := strings.TrimSpace(c.Q("q")); s != "" {
		q += ` AND (action LIKE ? OR actor LIKE ? OR target_id LIKE ? OR details LIKE ?)`
		like := "%" + s + "%"
		args = append(args, like, like, like, like)
	}
	if s := c.Q("action"); s != "" {
		q += ` AND action LIKE ?`
		args = append(args, s+"%")
	}
	if s := c.Q("actor"); s != "" {
		q += ` AND actor=?`
		args = append(args, s)
	}
	if b := c.QInt("before", 0); b > 0 {
		q += ` AND id<?`
		args = append(args, b)
	}
	limit := c.queryLimit("limit", 200, 2000)
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	out := []AuditEntry{}
	err := a.db.SelectContext(c.ctx(), &out, q, args...)
	return out, err
}

// --- settings ---

var settingSecrets = map[string][]string{
	keySMTP:   {"password"},
	keyLDAP:   {"bind_password"},
	keyRADIUS: {"secret"},
	keyOIDC:   {"client_secret"},
}

var editableSections = []string{keyGeneral, keyTLS, keySMTP, keyLDAP, keyRADIUS, keyOIDC, keyProxyAuth, keySecurity, keyRetention, keyAgent, keyAlerting, keyVuln, keyUpdates}

func (a *App) apiGetSettings(c *Ctx) (any, error) {
	out := map[string]any{}
	for _, k := range editableSections {
		v := defaultFor(k)
		_ = a.settings.Load(0, k, v)
		if ad, ok := v.(*AgentDefaults); ok {
			foldLegacyNeverBlock(ad)
		}
		b, _ := json.Marshal(v)
		if sec, ok := settingSecrets[k]; ok {
			out[k] = redact(b, sec)
		} else {
			var m map[string]any
			_ = json.Unmarshal(b, &m)
			out[k] = m
		}
	}
	out["ca_fingerprint"] = a.ca.Fingerprint()
	out["active_tls_mode"] = a.srv.Mode()
	out["notification_types"] = notify.Types
	return out, nil
}

func (a *App) apiPutSettings(c *Ctx) (any, error) {
	section := c.Param("section")
	ok := false
	for _, s := range editableSections {
		if s == section {
			ok = true
		}
	}
	if !ok {
		return nil, errNotFound
	}
	var raw json.RawMessage
	if err := c.Decode(&raw); err != nil {
		return nil, err
	}
	ctx := c.ctx()
	prevRaw, _ := a.settings.raw(0, section)
	if prevRaw == nil {
		prevRaw, _ = json.Marshal(defaultFor(section))
	}
	if sec, ok := settingSecrets[section]; ok {
		raw = mergeSecrets(raw, prevRaw, sec)
	}
	v := defaultFor(section)
	_ = json.Unmarshal(prevRaw, v) // start from current values; the body overrides
	if err := json.Unmarshal(raw, v); err != nil {
		return nil, badRequest("invalid settings: %v", err)
	}
	var warn string
	switch s := v.(type) {
	case *GeneralSettings:
		s.ServerURL = strings.TrimRight(strings.TrimSpace(s.ServerURL), "/")
		if s.ServerURL != "" {
			u, err := url.Parse(s.ServerURL)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return nil, badRequest("server URL must look like https://monitor.example.com")
			}
		}
		if _, err := time.LoadLocation(s.Timezone); err != nil {
			return nil, badRequest("unknown timezone")
		}
		s.SetupCompleted = true
	case *TLSSettings:
		switch s.Mode {
		case "http", "selfsigned":
		case "acme":
			if s.Hostname == "" {
				return nil, badRequest("Let's Encrypt needs a public DNS hostname")
			}
		default:
			return nil, badRequest("mode must be http, selfsigned or acme")
		}
		if s.Listen == "" {
			s.Listen = "0.0.0.0:8080"
		}
		tp, err := normalizeProxyList(s.TrustedProxies)
		if err != nil {
			return nil, err
		}
		s.TrustedProxies = tp
		warn = "Listeners are restarting with the new TLS settings. If the page stops responding, reload it at the new address."
	case *SecuritySettings:
		if s.Require2FA != "none" && s.Require2FA != "admins" && s.Require2FA != "all" {
			return nil, badRequest("require_2fa must be none, admins or all")
		}
		if s.SessionHours < 1 || s.SessionHours > 24*30 {
			return nil, badRequest("session length must be 1-720 hours")
		}
		if s.PasswordMinLength < 8 {
			return nil, badRequest("minimum password length is 8")
		}
	case *RetentionSettings:
		if s.Days < 1 || s.Days > 3650 {
			return nil, badRequest("retention must be 1-3650 days")
		}
	case *AgentDefaults:
		if s.IntervalSeconds < 5 || s.IntervalSeconds > 3600 {
			return nil, badRequest("interval must be 5-3600 seconds")
		}
		if s.InventoryIntervalSec < 300 {
			return nil, badRequest("inventory interval must be at least 300 seconds")
		}
		if s.PortscanThresholdPerMin < 1 {
			s.PortscanThresholdPerMin = 20
		}
		if s.PortscanThresholdPerMin > 100000 {
			return nil, badRequest("port-scan threshold must be 1-100000 per minute")
		}
		pl, err := normalizeAllowlist(s.PortscanAllowlist)
		if err != nil {
			return nil, err
		}
		s.PortscanAllowlist = pl
		foldLegacyNeverBlock(s)
		if s.BruteforceThreshold < 1 {
			s.BruteforceThreshold = 10
		}
		if s.BruteforceWindowMin < 1 || s.BruteforceWindowMin > 1440 {
			return nil, badRequest("brute-force window must be 1-1440 minutes")
		}
		if s.AutoBlockThreshold < 1 {
			return nil, badRequest("auto-block threshold must be at least 1")
		}
		if s.AutoBlockMinutes < 1 || s.AutoBlockMinutes > 60*24*90 {
			return nil, badRequest("block duration must be 1-129600 minutes")
		}
		nb, err := normalizeAllowlist(s.NeverBlock)
		if err != nil {
			return nil, err
		}
		s.NeverBlock = nb
	case *AlertingSettings:
		if s.GroupWaitSeconds < 0 || s.GroupWaitSeconds > 3600 {
			return nil, badRequest("group wait must be 0-3600 seconds")
		}
	case *VulnSettings:
		if s.DBURL != "" {
			if u, err := url.Parse(s.DBURL); err != nil || u.Host == "" {
				return nil, badRequest("DB URL must be a full URL")
			}
		}
	case *LDAPSettings:
		if s.Enabled && (s.URL == "" || s.BaseDN == "" || !strings.Contains(s.UserFilter, "%s")) {
			return nil, badRequest("LDAP needs a URL, base DN and a user filter containing %%s")
		}
	case *RADIUSSettings:
		if s.Enabled && (s.Server == "" || s.Secret == "") {
			return nil, badRequest("RADIUS needs a server and shared secret")
		}
	case *OIDCSettings:
		if err := validateOIDCSettings(s); err != nil {
			return nil, err
		}
	case *ProxyAuthSettings:
		if err := validateProxyAuthSettings(s); err != nil {
			return nil, err
		}
	}
	if err := a.settings.Save(ctx, 0, section, v); err != nil {
		return nil, err
	}
	// Side effects.
	switch section {
	case keyTLS:
		time.AfterFunc(time.Second, a.srv.Restart)
	case keyRetention:
		_ = a.ts.SetRetention(a.maxRetention(v.(*RetentionSettings).Days))
	case keyAgent:
		go a.hub.PushConfigAll(context.Background())
	case keyVuln:
		nv := v.(*VulnSettings)
		if nv.Enabled {
			if !a.vuln.Status().Available {
				_ = a.vuln.SyncNow()
			}
		} else {
			// Deleting the DB files is an explicit opt-in, never automatic.
			var extra struct {
				DeleteDB bool `json:"delete_db"`
			}
			_ = json.Unmarshal(raw, &extra)
			if err := a.vuln.Disable(extra.DeleteDB); err != nil {
				warn = "Vulnerability scanning is off, but the database files were not deleted: " + err.Error()
			}
		}
	case keyUpdates:
		if v.(*UpdateSettings).CheckEnabled {
			go func() { _ = a.updates.Check(context.Background()) }()
		}
	case keySecurity:
		w := time.Duration(v.(*SecuritySettings).LockoutMinutes) * time.Minute
		a.auth.failures.SetWindow(w)
		a.auth.ipFails.SetWindow(w)
	}
	b, _ := json.Marshal(v)
	details := redact(b, settingSecrets[section])
	c.audit("settings.updated", "settings", section, details)
	return map[string]any{"ok": true, "warning": warn}, nil
}

type testMailReq struct {
	To string `json:"to"`
}

func (a *App) apiTestSMTP(c *Ctx) (any, error) {
	var req testMailReq
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	if req.To == "" {
		return nil, badRequest("recipient required")
	}
	ctx, cancel := context.WithTimeout(c.ctx(), 45*time.Second)
	defer cancel()
	product := a.settings.Branding(0).ProductName
	err := notify.SendMail(ctx, a.notifier.smtpConfig(), []string{req.To}, product+" test email",
		"This is a test email from "+product+".", "<p>This is a test email from <b>"+product+"</b>.</p>")
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}, nil
	}
	return map[string]any{"ok": true}, nil
}

func (a *App) apiTestLDAP(c *Ctx) (any, error) {
	var req loginReq
	_ = c.Decode(&req)
	cfg := ldapConfig(a.settings.LDAP())
	if err := authn.LDAPTest(cfg); err != nil {
		return map[string]any{"ok": false, "error": "bind failed: " + err.Error()}, nil
	}
	if req.Username == "" {
		return map[string]any{"ok": true, "message": "connected and service bind succeeded"}, nil
	}
	u, err := authn.LDAPAuthenticate(cfg, req.Username, req.Password)
	if err != nil {
		return map[string]any{"ok": false, "error": "user login failed: " + err.Error()}, nil
	}
	role, tenant, ok := mapLDAPRole(a.settings.LDAP(), u.Groups)
	msg := "login succeeded as " + u.DN
	if ok {
		msg += fmt.Sprintf("; mapped role %s (tenant %d)", role, tenant)
	} else {
		msg += "; no role mapping matched, so this user would be refused"
	}
	return map[string]any{"ok": true, "message": msg, "groups": u.Groups, "email": u.Email, "name": u.Name}, nil
}

func (a *App) apiTestRADIUS(c *Ctx) (any, error) {
	var req loginReq
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	rc := a.settings.RADIUS()
	res, err := authn.RADIUSAuthenticate(c.ctx(), authn.RADIUSConfig{Server: rc.Server, Secret: rc.Secret, NASIdentifier: rc.NASIdentifier,
		Timeout: time.Duration(rc.TimeoutSec) * time.Second, RoleAttribute: rc.RoleAttribute}, req.Username, req.Password)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}, nil
	}
	return map[string]any{"ok": true, "message": "Access-Accept received", "role_hint": res.RoleHint}, nil
}

// --- branding ---

var colorRe = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

func (a *App) apiGetBranding(c *Ctx) (any, error) {
	t := c.P.TenantID
	if c.P.IsProvider() && c.Q("tenant_id") != "" {
		t = c.QInt("tenant_id", 0)
	}
	if c.Q("raw") == "1" {
		var b Branding
		if t == 0 {
			b = a.settings.Branding(0)
		} else {
			_ = a.settings.Load(t, keyBranding, &b)
		}
		return b, nil
	}
	return a.settings.Branding(t), nil
}

func (a *App) apiPutBranding(c *Ctx) (any, error) {
	var b Branding
	if err := c.Decode(&b); err != nil {
		return nil, err
	}
	t := c.P.TenantID
	if c.P.IsProvider() && c.Q("tenant_id") != "" {
		t = c.QInt("tenant_id", 0)
	}
	if t == 0 && !c.P.Has(PermSettings) {
		return nil, forbidden("only administrators can change global branding")
	}
	if b.AccentColor != "" && !colorRe.MatchString(b.AccentColor) {
		return nil, badRequest("accent colour must be #rrggbb")
	}
	for _, d := range []string{b.LogoDataURL, b.FaviconDataURL} {
		if d != "" && (!strings.HasPrefix(d, "data:image/") || len(d) > 700_000) {
			return nil, badRequest("images must be data:image URLs under 500 KB")
		}
	}
	if strings.Contains(strings.ToLower(b.LogoDataURL+b.FaviconDataURL), "svg") && (strings.Contains(b.LogoDataURL, "script") || strings.Contains(b.FaviconDataURL, "script")) {
		return nil, badRequest("SVG images must not contain scripts")
	}
	b.ProductName = truncateStr(strings.TrimSpace(b.ProductName), 64)
	b.LoginText = truncateStr(b.LoginText, 2000)
	b.FooterText = truncateStr(b.FooterText, 500)
	if t == 0 && b.ProductName == "" {
		b.ProductName = "Sentrel"
	}
	if err := a.settings.Save(c.ctx(), t, keyBranding, b); err != nil {
		return nil, err
	}
	c.auditT(t, "branding.updated", "tenant", itoa(t), map[string]any{"product_name": b.ProductName, "accent": b.AccentColor})
	return a.settings.Branding(t), nil
}

// --- server ---

func (a *App) apiServerStatus(c *Ctx) (any, error) {
	ctx := c.ctx()
	var hosts, agents int
	_ = a.db.GetContext(ctx, &hosts, `SELECT COUNT(*) FROM hosts`)
	_ = a.db.GetContext(ctx, &agents, `SELECT COUNT(*) FROM hosts WHERE kind='agent' AND revoked=0`)
	dbSize := int64(0)
	for _, suf := range []string{"", "-wal"} {
		if fi, err := os.Stat(a.db.Path + suf); err == nil {
			dbSize += fi.Size()
		}
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	out := map[string]any{
		"version": version.Version, "commit": version.Commit, "build_date": version.Date, "go": runtime.Version(),
		"uptime_seconds": int(time.Since(startedAt).Seconds()), "agents_connected": a.hub.ConnectedCount(), "agents_total": agents, "hosts_total": hosts,
		"tls_mode": a.srv.Mode(), "memory_bytes": m.Sys, "goroutines": runtime.NumGoroutine(),
	}
	if c.P.IsProvider() {
		disk := diskUsage(a.cfg.DataDir)
		out["data_dir"] = a.cfg.DataDir
		out["db_bytes"] = dbSize
		out["tsdb"] = a.ts.Stats()
		out["retention_days"] = a.settings.Retention().Days
		out["vulndb"] = a.vuln.Status()
		out["disk"] = disk
		out["ca_fingerprint"] = a.ca.Fingerprint()
		out["agent_binaries"] = agentdist.List(a.cfg.AgentBinDir)
	}
	return out, nil
}

func (a *App) apiBackup(c *Ctx) (any, error) {
	name := fmt.Sprintf("sentrel-backup-%s.tar.gz", time.Now().UTC().Format("20060102-150405"))
	c.audit("server.backup_downloaded", "", "", nil)
	return rawResponse(func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/gzip")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		if err := a.WriteBackup(c.ctx(), w, false); err != nil {
			a.log.Error("backup", "err", err)
		}
	}), nil
}
