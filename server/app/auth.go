package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"image/png"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pquerna/otp/totp"

	"sentrel/server/authn"
	"sentrel/server/db"
)

const sessionCookie = "sentrel_session"

type authService struct {
	app      *App
	failures *rateLimiter // username|ip -> failed attempts
	ipFails  *rateLimiter

	waMu    sync.Mutex
	waSess  map[string]waPending
	waCache map[string]*webauthn.WebAuthn
	waOrder []string // waCache keys, least recently used first
}

type waPending struct {
	data    webauthn.SessionData
	userID  int64
	expires time.Time
	purpose string // register, mfa, login
}

func newAuthService(a *App) *authService {
	sec := a.settings.Security()
	window := time.Duration(sec.LockoutMinutes) * time.Minute
	if window <= 0 {
		window = 15 * time.Minute
	}
	return &authService{
		app:      a,
		failures: newRateLimiter(1<<30, window),
		ipFails:  newRateLimiter(1<<30, window),
		waSess:   map[string]waPending{},
		waCache:  map[string]*webauthn.WebAuthn{},
	}
}

func hashToken(t string) string {
	s := sha256.Sum256([]byte(t))
	return hex.EncodeToString(s[:])
}

func randomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// clientIP returns the caller IP. Forwarding headers are honoured only when
// trust_proxy is on and the TCP peer is in trusted_proxies (see clientip.go).
func (a *App) clientIP(r *http.Request) string {
	t := a.settings.TLS()
	return resolveClientIP(r, t.TrustProxy, t.TrustedProxies)
}

func (a *App) isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if !a.fromTrustedProxy(r) {
		return false
	}
	vals := strings.Split(strings.Join(r.Header.Values("X-Forwarded-Proto"), ","), ",")
	return strings.EqualFold(strings.TrimSpace(vals[len(vals)-1]), "https")
}

// middleware authenticates the request (API key or session) and enforces
// CSRF for cookie-authenticated state-changing requests.
func (s *authService) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := s.app.clientIP(r)
		var p *Principal
		if ah := r.Header.Get("Authorization"); strings.HasPrefix(ah, "Bearer ") {
			var err error
			p, err = s.apiKeyPrincipal(r.Context(), strings.TrimSpace(strings.TrimPrefix(ah, "Bearer ")))
			if err != nil {
				var ae *apiError
				if errors.As(err, &ae) {
					writeError(w, ae)
					return
				}
				writeError(w, unauthorized("invalid API key"))
				return
			}
		} else if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
			p = s.sessionPrincipal(r.Context(), c.Value)
			if p != nil && r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
				if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(p.CSRF)) != 1 {
					writeError(w, forbidden("missing or invalid CSRF token"))
					return
				}
			}
		}
		if p == nil && r.Header.Get("Authorization") == "" {
			p = s.proxyPrincipal(w, r)
		}
		if p != nil {
			p.IP = ip
			r = r.WithContext(context.WithValue(r.Context(), principalKey, p))
		}
		next.ServeHTTP(w, r)
	})
}

type sessionRow struct {
	IDHash     string `db:"id_hash"`
	UserID     int64  `db:"user_id"`
	MFAPending int    `db:"mfa_pending"`
	CSRF       string `db:"csrf_token"`
	ExpiresAt  int64  `db:"expires_at"`
	LastSeenAt int64  `db:"last_seen_at"`
}

func (s *authService) sessionPrincipal(ctx context.Context, token string) *Principal {
	a := s.app
	var sr sessionRow
	if err := a.db.GetContext(ctx, &sr, `SELECT id_hash, user_id, mfa_pending, csrf_token, expires_at, last_seen_at FROM sessions WHERE id_hash=?`, hashToken(token)); err != nil {
		return nil
	}
	now := db.Now()
	if sr.ExpiresAt < now {
		_, _ = a.db.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash=?`, sr.IDHash)
		return nil
	}
	u, err := a.getUser(ctx, sr.UserID)
	if err != nil || a.principalBlocked(ctx, u) != nil {
		return nil
	}
	if sr.MFAPending == 0 && now-sr.LastSeenAt > 60 {
		hours := a.settings.Security().SessionHours
		if hours <= 0 {
			hours = 12
		}
		_, _ = a.db.ExecContext(ctx, `UPDATE sessions SET last_seen_at=?, expires_at=? WHERE id_hash=?`, now, now+int64(hours)*3600, sr.IDHash)
	}
	uid := u.ID
	return &Principal{UserID: &uid, Name: u.Username, Role: u.Role, TenantID: u.TenantID, SessionID: sr.IDHash,
		MFAPending: sr.MFAPending != 0, MFAEnroll: sr.MFAPending == 2, CSRF: sr.CSRF, MustChangePW: mustChangePassword(u), perms: newPrincipal(u.Role, nil)}
}

// errTenantDisabled is returned for a user whose tenant is suspended.
var errTenantDisabled = errors.New("tenant disabled")

// principalBlocked is the single validity check for every authentication
// method (sessions, API keys, new logins): the user must be enabled and, for
// tenant users, the tenant must exist and be enabled. It fails closed when
// the tenant cannot be read. Key expiry is checked by the key path.
func (a *App) principalBlocked(ctx context.Context, u *User) error {
	if u.Disabled {
		return errUserDisabled
	}
	if u.TenantID != 0 {
		var disabled bool
		if err := a.db.GetContext(ctx, &disabled, `SELECT disabled FROM tenants WHERE id=?`, u.TenantID); err != nil || disabled {
			return errTenantDisabled
		}
	}
	return nil
}

// mustChangePassword reports whether the account is restricted to changing its
// password. Only local accounts can change a password here, so the flag is
// ignored for externally managed ones.
func mustChangePassword(u *User) bool { return u.MustChangePW && u.AuthSource == "local" }

// maxAPIKeyLen bounds the work done for a bearer token.
const maxAPIKeyLen = 200

// dummyKeyHash stands in for a stored key hash when the prefix is unknown.
var dummyKeyHash = hashToken("sentrel-unknown-api-key")

// API keys look like sentrel_<8 char prefix>_<secret>. The secret is 30 random
// bytes, so the stored hash is a plain SHA-256 looked up by prefix; a slow
// password hash would add nothing and would make unknown keys expensive.
func (s *authService) apiKeyPrincipal(ctx context.Context, key string) (*Principal, error) {
	parts := strings.SplitN(key, "_", 3)
	if len(key) > maxAPIKeyLen || len(parts) != 3 || parts[0] != "sentrel" || len(parts[1]) != 8 {
		return nil, errors.New("malformed")
	}
	a := s.app
	var k APIKey
	if err := a.db.GetContext(ctx, &k, `SELECT * FROM api_keys WHERE prefix=?`, parts[1]); err != nil {
		// Same cheap work as a known prefix, so timing does not reveal it.
		subtle.ConstantTimeCompare([]byte(hashToken(parts[2])), []byte(dummyKeyHash))
		return nil, errors.New("unknown")
	}
	if subtle.ConstantTimeCompare([]byte(hashToken(parts[2])), []byte(k.KeyHash)) != 1 {
		return nil, errors.New("mismatch")
	}
	now := db.Now()
	if k.ExpiresAt != 0 && k.ExpiresAt < now {
		return nil, errors.New("expired")
	}
	u, err := a.getUser(ctx, k.UserID)
	if err != nil {
		return nil, errors.New("user not found")
	}
	if err := a.principalBlocked(ctx, u); err != nil {
		return nil, err
	}
	if mustChangePassword(u) {
		return nil, &apiError{Status: 403, Code: "password_change_required", Msg: "the account owner must change their password before API keys work again"}
	}
	if now-k.LastUsedAt > 60 {
		_, _ = a.db.ExecContext(ctx, `UPDATE api_keys SET last_used_at=? WHERE id=?`, now, k.ID)
	}
	uid := u.ID
	return &Principal{UserID: &uid, Name: u.Username + " (key " + k.Name + ")", Role: u.Role, TenantID: u.TenantID, APIKeyID: k.ID,
		perms: newPrincipal(u.Role, k.Scopes)}, nil
}

func (a *App) getUser(ctx context.Context, id int64) (*User, error) {
	var u User
	if err := a.db.GetContext(ctx, &u, `SELECT * FROM users WHERE id=?`, id); err != nil {
		return nil, err
	}
	return &u, nil
}

// createSession issues a session cookie. mfa: 0 complete, 1 second factor
// pending, 2 second-factor enrolment required by policy.
func (s *authService) createSession(w http.ResponseWriter, r *http.Request, u *User, mfa int) (string, error) {
	a := s.app
	if err := a.principalBlocked(r.Context(), u); err != nil {
		return "", unauthorized("this account is disabled")
	}
	tok := randomToken(32)
	csrf := randomToken(24)
	now := db.Now()
	hours := a.settings.Security().SessionHours
	if hours <= 0 {
		hours = 12
	}
	exp := now + int64(hours)*3600
	if mfa == 1 {
		exp = now + 600 // ten minutes to complete the second factor
	}
	_, err := a.db.ExecContext(r.Context(), `INSERT INTO sessions (id_hash, tenant_id, user_id, mfa_pending, csrf_token, ip, user_agent, created_at, expires_at, last_seen_at)
		VALUES (?,?,?,?,?,?,?,?,?,?)`, hashToken(tok), u.TenantID, u.ID, mfa, csrf, a.clientIP(r), truncateStr(r.UserAgent(), 255), now, exp, now)
	if err != nil {
		return "", err
	}
	s.setSessionCookie(w, r, tok, exp)
	return csrf, nil
}

func (s *authService) upgradeSession(c *Ctx, mfa int) error {
	cookie, err := c.R.Cookie(sessionCookie)
	if err != nil || hashToken(cookie.Value) != c.P.SessionID {
		return unauthorized("session expired; sign in again")
	}
	hours := s.app.settings.Security().SessionHours
	if hours <= 0 {
		hours = 12
	}
	exp := db.Now() + int64(hours)*3600
	res, err := s.app.db.ExecContext(c.ctx(), `UPDATE sessions SET mfa_pending=?, expires_at=? WHERE id_hash=?`, mfa, exp, c.P.SessionID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return unauthorized("session expired; sign in again")
	}
	// The browser must receive the full session lifetime too, rather than
	// retaining the ten-minute cookie used for the pending second factor.
	s.setSessionCookie(c.W, c.R, cookie.Value, exp)
	return nil
}

func (s *authService) setSessionCookie(w http.ResponseWriter, r *http.Request, token string, expires int64) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, Secure: s.app.isHTTPS(r), SameSite: http.SameSiteLaxMode, Expires: time.Unix(expires, 0)})
}

// needsMFA reports which second factors a user has.
func (s *authService) mfaMethods(ctx context.Context, u *User) []string {
	var m []string
	if u.TOTPEnabled {
		m = append(m, "totp")
	}
	var n int
	_ = s.app.db.GetContext(ctx, &n, `SELECT COUNT(*) FROM webauthn_credentials WHERE user_id=?`, u.ID)
	if n > 0 {
		m = append(m, "passkey")
	}
	return m
}

func (s *authService) policyRequires2FA(u *User) bool {
	switch s.app.settings.Security().Require2FA {
	case "all":
		return true
	case "admins":
		return u.Role == RoleAdmin || u.Role == RoleTenantAdmin
	}
	return false
}

// --- login ---

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResp struct {
	MFARequired      bool     `json:"mfa_required"`
	MFAMethods       []string `json:"mfa_methods,omitempty"`
	MFASetupRequired bool     `json:"mfa_setup_required"`
	CSRF             string   `json:"csrf_token"`
	User             *User    `json:"user"`
}

func (s *authService) lockoutKey(username, ip string) string {
	return strings.ToLower(username) + "|" + ip
}

func (s *authService) login(c *Ctx) (any, error) {
	a := s.app
	var req loginReq
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	req.Username = strings.TrimSpace(req.Username)
	ip := a.clientIP(c.R)
	sec := a.settings.Security()
	limit := sec.LockoutAttempts
	if limit <= 0 {
		limit = 8
	}
	if s.failures.Count(s.lockoutKey(req.Username, ip)) >= limit || s.ipFails.Count(ip) >= limit*5 {
		a.audit(c.ctx(), auditEntry{Actor: req.Username, Action: "auth.locked_out", IP: ip})
		return nil, &apiError{Status: 429, Code: "locked_out", Msg: "too many failed attempts; try again later"}
	}
	u, err := s.authenticate(c.ctx(), req.Username, req.Password, ip)
	if err != nil {
		s.failures.Allow(s.lockoutKey(req.Username, ip))
		s.ipFails.Allow(ip)
		a.audit(c.ctx(), auditEntry{Actor: req.Username, Action: "auth.login_failed", IP: ip, Details: map[string]any{"reason": err.Error()}})
		if errors.Is(err, authn.ErrInvalidCredentials) || errors.Is(err, errUserDisabled) {
			return nil, unauthorized("invalid username or password")
		}
		a.log.Warn("login backend error", "user", req.Username, "err", err)
		return nil, unauthorized("invalid username or password")
	}
	s.failures.Reset(s.lockoutKey(req.Username, ip))
	return s.finishPrimaryLogin(c, u)
}

func (s *authService) finishPrimaryLogin(c *Ctx, u *User) (any, error) {
	methods := s.mfaMethods(c.ctx(), u)
	mfa := 0
	if len(methods) > 0 {
		mfa = 1
	} else if s.policyRequires2FA(u) {
		mfa = 2
	}
	csrf, err := s.createSession(c.W, c.R, u, mfa)
	if err != nil {
		return nil, err
	}
	if mfa != 1 {
		s.loginCompleted(c, u, "password")
	}
	return loginResp{MFARequired: mfa == 1, MFAMethods: methods, MFASetupRequired: mfa == 2, CSRF: csrf, User: u}, nil
}

func (s *authService) loginCompleted(c *Ctx, u *User, method string) {
	_, _ = s.app.db.ExecContext(c.ctx(), `UPDATE users SET last_login_at=? WHERE id=?`, db.Now(), u.ID)
	s.app.audit(c.ctx(), auditEntry{TenantID: u.TenantID, UserID: &u.ID, Actor: u.Username, Action: "auth.login", IP: s.app.clientIP(c.R),
		Details: map[string]any{"method": method}})
}

var errUserDisabled = errors.New("user disabled")

// authenticate checks credentials against local users, then LDAP, then
// RADIUS, auto-provisioning external users.
func (s *authService) authenticate(ctx context.Context, username, password, ip string) (*User, error) {
	a := s.app
	var u User
	err := a.db.GetContext(ctx, &u, `SELECT * FROM users WHERE username=?`, username)
	found := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if found && u.Disabled {
		authn.EqualiseTiming(password)
		return nil, errUserDisabled
	}
	if found && u.AuthSource == "local" {
		if u.PasswordHash == "" || !authn.CheckPassword(u.PasswordHash, password) {
			return nil, authn.ErrInvalidCredentials
		}
		return &u, nil
	}
	ldapCfg := a.settings.LDAP()
	if ldapCfg.Enabled && (!found || u.AuthSource == "ldap") {
		lu, err := authn.LDAPAuthenticate(ldapConfig(ldapCfg), username, password)
		if err == nil {
			role, tenant, ok := mapLDAPRole(ldapCfg, lu.Groups)
			if found {
				if !ok {
					// Access was removed upstream: revoke what exists and refuse.
					s.revokeAccess(ctx, &u, true)
					return nil, errors.New("LDAP user has no mapped role")
				}
				return s.syncExternalUser(ctx, &u, lu.Email, lu.Name, role, tenant)
			}
			if !ok {
				return nil, errors.New("LDAP user has no mapped role")
			}
			return s.provision(ctx, username, lu.Email, lu.Name, role, tenant, "ldap")
		}
		if found || !errors.Is(err, authn.ErrInvalidCredentials) {
			if !errors.Is(err, authn.ErrInvalidCredentials) {
				a.log.Warn("ldap", "err", err)
			}
			if found {
				return nil, authn.ErrInvalidCredentials
			}
		}
	}
	rc := a.settings.RADIUS()
	if rc.Enabled && (!found || u.AuthSource == "radius") {
		res, err := authn.RADIUSAuthenticate(ctx, authn.RADIUSConfig{Server: rc.Server, Secret: rc.Secret, NASIdentifier: rc.NASIdentifier,
			Timeout: time.Duration(rc.TimeoutSec) * time.Second, RoleAttribute: rc.RoleAttribute}, username, password)
		if err == nil {
			role, tenant := rc.DefaultRole, rc.DefaultTenant
			// Filter-Id / Class may carry "sentrel:<role>" or just "<role>".
			if hint := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(res.RoleHint)), "sentrel:"); ValidRole(hint, tenant) {
				role = hint
			}
			if !ValidRole(role, tenant) {
				if found {
					s.revokeAccess(ctx, &u, true)
				}
				return nil, errors.New("RADIUS user has no valid role")
			}
			if found {
				return s.syncExternalUser(ctx, &u, u.Email, firstNonEmpty(u.DisplayName, username), role, tenant)
			}
			return s.provision(ctx, username, "", username, role, tenant, "radius")
		}
		if !errors.Is(err, authn.ErrInvalidCredentials) {
			a.log.Warn("radius", "err", err)
		}
	}
	if !found {
		authn.EqualiseTiming(password)
	}
	return nil, authn.ErrInvalidCredentials
}

func ldapConfig(s LDAPSettings) authn.LDAPConfig {
	return authn.LDAPConfig{URL: s.URL, StartTLS: s.StartTLS, SkipVerify: s.SkipVerify, BindDN: s.BindDN, BindPassword: s.BindPassword,
		BaseDN: s.BaseDN, UserFilter: s.UserFilter, EmailAttr: s.EmailAttr, NameAttr: s.NameAttr, GroupAttr: s.GroupAttr}
}

var roleRank = map[string]int{RoleAdmin: 5, RoleOperator: 4, RoleTenantAdmin: 3, RoleViewer: 2, RoleTenantViewer: 1}

// revokeAccess drops the user's sessions (and, with keys, their API keys).
func (s *authService) revokeAccess(ctx context.Context, u *User, keys bool) {
	_, _ = s.app.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, u.ID)
	if keys {
		_, _ = s.app.db.ExecContext(ctx, `DELETE FROM api_keys WHERE user_id=?`, u.ID)
	}
}

// syncExternalUser makes the stored role and tenant of an LDAP, RADIUS, OIDC
// or forward-auth account match what the directory and current mappings say right now. When
// the role is lowered or the tenant changes, the user's existing sessions are
// revoked; a tenant change also drops their API keys, which carry the old tenant.
func (s *authService) syncExternalUser(ctx context.Context, u *User, email, name, role string, tenant int64) (*User, error) {
	lowered := roleRank[role] < roleRank[u.Role] || tenant != u.TenantID
	if _, err := s.app.db.ExecContext(ctx, `UPDATE users SET email=?, display_name=?, role=?, tenant_id=? WHERE id=?`,
		truncateStr(email, 200), truncateStr(firstNonEmpty(name, u.Username), 100), role, tenant, u.ID); err != nil {
		return nil, err
	}
	if lowered {
		s.revokeAccess(ctx, u, tenant != u.TenantID)
		s.app.audit(ctx, auditEntry{TenantID: u.TenantID, UserID: &u.ID, Actor: "system", Action: "user.role_synced", TargetType: "user", TargetID: itoa(u.ID),
			Details: map[string]any{"username": u.Username, "from_role": u.Role, "to_role": role, "from_tenant": u.TenantID, "to_tenant": tenant}})
	}
	return s.app.getUser(ctx, u.ID)
}

// mapLDAPRole picks the most privileged mapped role.
func mapLDAPRole(s LDAPSettings, groups []string) (string, int64, bool) {
	return mapGroupRole(s.RoleMapping, s.DefaultRole, s.DefaultTenant, groups)
}

// mapGroupRole picks the most privileged role mapped from the user's groups,
// falling back to the default role (empty default = deny).
func mapGroupRole(mapping []LDAPRoleMapping, defRole string, defTenant int64, groups []string) (string, int64, bool) {
	rank := roleRank
	best, bestT, ok := "", int64(0), false
	for _, m := range mapping {
		for _, g := range groups {
			if strings.EqualFold(strings.TrimSpace(g), strings.TrimSpace(m.Group)) && ValidRole(m.Role, m.TenantID) && rank[m.Role] > rank[best] {
				best, bestT, ok = m.Role, m.TenantID, true
			}
		}
	}
	if !ok && defRole != "" && ValidRole(defRole, defTenant) {
		return defRole, defTenant, true
	}
	return best, bestT, ok
}

func (s *authService) provision(ctx context.Context, username, email, name, role string, tenant int64, source string) (*User, error) {
	res, err := s.app.db.ExecContext(ctx, `INSERT INTO users (tenant_id, username, email, display_name, role, auth_source, created_at) VALUES (?,?,?,?,?,?,?)`,
		tenant, username, email, name, role, source, db.Now())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	s.app.audit(ctx, auditEntry{TenantID: tenant, Actor: "system", Action: "user.provisioned", TargetType: "user", TargetID: itoa(id),
		Details: map[string]any{"username": username, "source": source, "role": role}})
	return s.app.getUser(ctx, id)
}

func (s *authService) logout(c *Ctx) (any, error) {
	if c.P != nil && c.P.SessionID != "" {
		_, _ = s.app.db.ExecContext(c.ctx(), `DELETE FROM sessions WHERE id_hash=?`, c.P.SessionID)
	}
	http.SetCookie(c.W, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		Secure: s.app.isHTTPS(c.R), SameSite: http.SameSiteLaxMode})
	return map[string]bool{"ok": true}, nil
}

// --- TOTP ---

func (s *authService) issuer() string { return s.app.settings.Branding(0).ProductName }

type totpSetupResp struct {
	Secret string `json:"secret"`
	URL    string `json:"otpauth_url"`
	QR     string `json:"qr_data_url"`
}

// enrolAllowed rejects enrolment while a second factor still has to be
// verified (otherwise enrolling a new factor would bypass the existing one).
func enrolAllowed(p *Principal) error {
	if p.MFAPending && !p.MFAEnroll {
		return &apiError{Status: 401, Code: "mfa_required", Msg: "verify your existing second factor first"}
	}
	if p.APIKeyID != 0 {
		return forbidden("not available with API keys")
	}
	return nil
}

func verifyAllowed(p *Principal) error {
	if !p.MFAPending || p.MFAEnroll {
		return badRequest("no second factor pending")
	}
	return nil
}

func (s *authService) totpSetup(c *Ctx) (any, error) {
	if err := enrolAllowed(c.P); err != nil {
		return nil, err
	}
	u, err := s.app.getUser(c.ctx(), *c.P.UserID)
	if err != nil {
		return nil, err
	}
	if u.TOTPEnabled {
		return nil, conflict("TOTP is already enabled; disable it first")
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: s.issuer(), AccountName: u.Username})
	if err != nil {
		return nil, err
	}
	if _, err := s.app.db.ExecContext(c.ctx(), `UPDATE users SET totp_secret=? WHERE id=?`, key.Secret(), u.ID); err != nil {
		return nil, err
	}
	img, err := key.Image(220, 220)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return totpSetupResp{Secret: key.Secret(), URL: key.URL(), QR: "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())}, nil
}

type codeReq struct {
	Code string `json:"code"`
}

func (s *authService) totpEnable(c *Ctx) (any, error) {
	if err := enrolAllowed(c.P); err != nil {
		return nil, err
	}
	var req codeReq
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	u, err := s.app.getUser(c.ctx(), *c.P.UserID)
	if err != nil {
		return nil, err
	}
	if u.TOTPSecret == "" || !totp.Validate(strings.ReplaceAll(req.Code, " ", ""), u.TOTPSecret) {
		return nil, badRequest("invalid code; check your device clock")
	}
	codes, hashes := recoveryCodes()
	if _, err := s.app.db.ExecContext(c.ctx(), `UPDATE users SET totp_enabled=1, recovery_codes=? WHERE id=?`, hashes, u.ID); err != nil {
		return nil, err
	}
	if c.P.MFAPending {
		_ = s.upgradeSession(c, 0)
	}
	c.auditT(u.TenantID, "user.totp_enabled", "user", itoa(u.ID), nil)
	return map[string]any{"recovery_codes": codes}, nil
}

func recoveryCodes() ([]string, StrList) {
	var codes []string
	var hashes StrList
	for i := 0; i < 10; i++ {
		code := strings.ToLower(randomCode(5) + "-" + randomCode(5))
		codes = append(codes, code)
		hashes = append(hashes, hashToken(code))
	}
	return codes, hashes
}

type pwReq struct {
	Password string `json:"password"`
	Code     string `json:"code"`
}

func (s *authService) totpDisable(c *Ctx) (any, error) {
	var req pwReq
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	u, err := s.app.getUser(c.ctx(), *c.P.UserID)
	if err != nil {
		return nil, err
	}
	if !s.verifySecondFactorOrPassword(u, req.Password, req.Code) {
		return nil, badRequest("current password or a valid code is required")
	}
	_, err = s.app.db.ExecContext(c.ctx(), `UPDATE users SET totp_enabled=0, totp_secret='', recovery_codes='[]' WHERE id=?`, u.ID)
	c.auditT(u.TenantID, "user.totp_disabled", "user", itoa(u.ID), nil)
	return nil, err
}

func (s *authService) verifySecondFactorOrPassword(u *User, pw, code string) bool {
	if pw != "" && u.AuthSource == "local" && authn.CheckPassword(u.PasswordHash, pw) {
		return true
	}
	if code != "" && u.TOTPEnabled && totp.Validate(code, u.TOTPSecret) {
		return true
	}
	return false
}

// consumeRecoveryCode atomically spends a recovery code. It reads the stored
// list as raw text and writes the shortened list only if the column still has
// exactly that text, so of any number of concurrent attempts with the same code
// exactly one UPDATE matches a row. A lost race or an unknown code returns
// (false, nil); a storage error returns it so the caller fails closed.
func (s *authService) consumeRecoveryCode(ctx context.Context, userID int64, code string) (bool, error) {
	var raw string
	if err := s.app.db.GetContext(ctx, &raw, `SELECT recovery_codes FROM users WHERE id=?`, userID); err != nil {
		return false, err
	}
	var codes StrList
	if err := json.Unmarshal([]byte(raw), &codes); err != nil {
		return false, nil
	}
	h := hashToken(code)
	idx := -1
	for i, rc := range codes {
		if subtle.ConstantTimeCompare([]byte(rc), []byte(h)) == 1 {
			idx = i
		}
	}
	if idx < 0 {
		return false, nil
	}
	rest := append(StrList{}, codes[:idx]...)
	rest = append(rest, codes[idx+1:]...)
	b, err := json.Marshal(rest)
	if err != nil {
		return false, err
	}
	res, err := s.app.db.ExecContext(ctx, `UPDATE users SET recovery_codes=? WHERE id=? AND recovery_codes=?`, string(b), userID, raw)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// mfaTOTP completes login with a TOTP or recovery code.
func (s *authService) mfaTOTP(c *Ctx) (any, error) {
	if err := verifyAllowed(c.P); err != nil {
		return nil, err
	}
	var req codeReq
	if err := c.Decode(&req); err != nil {
		return nil, err
	}
	key := "mfa|" + itoa(*c.P.UserID)
	if s.failures.Count(key) >= 10 {
		return nil, &apiError{Status: 429, Code: "locked_out", Msg: "too many attempts; log in again later"}
	}
	u, err := s.app.getUser(c.ctx(), *c.P.UserID)
	if err != nil {
		return nil, err
	}
	code := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(req.Code), " ", ""))
	ok := u.TOTPEnabled && totp.Validate(code, u.TOTPSecret)
	method := "totp"
	if !ok {
		used, err := s.consumeRecoveryCode(c.ctx(), u.ID, code)
		if err != nil {
			// Fail closed: nothing was consumed, so nothing is accepted.
			return nil, err
		}
		if used {
			ok, method = true, "recovery_code"
		}
	}
	if !ok {
		s.failures.Allow(key)
		s.app.audit(c.ctx(), auditEntry{TenantID: u.TenantID, UserID: &u.ID, Actor: u.Username, Action: "auth.mfa_failed", IP: c.P.IP})
		return nil, unauthorized("invalid code")
	}
	s.failures.Reset(key)
	if err := s.upgradeSession(c, 0); err != nil {
		return nil, err
	}
	s.loginCompleted(c, u, method)
	return loginResp{CSRF: c.P.CSRF, User: u}, nil
}

// --- WebAuthn / passkeys ---

type waUser struct {
	u     *User
	creds []webauthn.Credential
}

func (w *waUser) WebAuthnID() []byte                         { return w.u.WebAuthnID }
func (w *waUser) WebAuthnName() string                       { return w.u.Username }
func (w *waUser) WebAuthnDisplayName() string                { return firstNonEmpty(w.u.DisplayName, w.u.Username) }
func (w *waUser) WebAuthnCredentials() []webauthn.Credential { return w.creds }

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

func (s *authService) waUser(ctx context.Context, userID int64) (*waUser, error) {
	u, err := s.app.getUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if len(u.WebAuthnID) == 0 {
		id := make([]byte, 32)
		_, _ = rand.Read(id)
		if _, err := s.app.db.ExecContext(ctx, `UPDATE users SET webauthn_id=? WHERE id=?`, id, u.ID); err != nil {
			return nil, err
		}
		u.WebAuthnID = id
	}
	var rows []struct {
		JSON string `db:"credential_json"`
	}
	_ = s.app.db.SelectContext(ctx, &rows, `SELECT credential_json FROM webauthn_credentials WHERE user_id=?`, u.ID)
	wu := &waUser{u: u}
	for _, r := range rows {
		var cr webauthn.Credential
		if json.Unmarshal([]byte(r.JSON), &cr) == nil {
			wu.creds = append(wu.creds, cr)
		}
	}
	return wu, nil
}

// webAuthn returns a relying party for the request's origin. The RP ID is
// the configured server URL's hostname when set, otherwise the request host.
func (s *authService) webAuthn(r *http.Request) (*webauthn.WebAuthn, error) {
	origin := ""
	if su := s.app.settings.General().ServerURL; su != "" {
		if u, err := url.Parse(su); err == nil && u.Host != "" {
			origin = u.Scheme + "://" + u.Host
		}
	}
	if origin == "" {
		scheme := "http"
		if s.app.isHTTPS(r) {
			scheme = "https"
		}
		if !validRequestHost(r.Host) {
			return nil, badRequest("unrecognised host for passkeys; set the server URL in settings")
		}
		origin = scheme + "://" + r.Host
	}
	s.waMu.Lock()
	defer s.waMu.Unlock()
	if w, ok := s.waCache[origin]; ok {
		s.touchWAOrigin(origin)
		return w, nil
	}
	u, _ := url.Parse(origin)
	w, err := webauthn.New(&webauthn.Config{RPDisplayName: s.issuer(), RPID: u.Hostname(), RPOrigins: []string{origin}})
	if err != nil {
		return nil, err
	}
	// Bounded LRU: with no server URL the origin comes from the request, so
	// the cache must not grow with attacker-chosen Host values.
	for len(s.waCache) >= waCacheMax && len(s.waOrder) > 0 {
		delete(s.waCache, s.waOrder[0])
		s.waOrder = s.waOrder[1:]
	}
	s.waCache[origin] = w
	s.waOrder = append(s.waOrder, origin)
	return w, nil
}

const (
	waCacheMax   = 16   // relying-party objects kept when the origin comes from the request
	waPendingMax = 1000 // outstanding WebAuthn challenges
)

// touchWAOrigin marks origin most recently used. waMu must be held.
func (s *authService) touchWAOrigin(origin string) {
	for i, o := range s.waOrder {
		if o == origin {
			s.waOrder = append(append(s.waOrder[:i:i], s.waOrder[i+1:]...), origin)
			return
		}
	}
}

// validRequestHost reports whether h is a plausible host[:port] to use as a
// WebAuthn origin: no userinfo, path, query or odd characters, and bounded.
func validRequestHost(h string) bool {
	if h == "" || len(h) > 262 {
		return false
	}
	u, err := url.Parse("https://" + h)
	return err == nil && u.Host == h && u.Hostname() != "" && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == ""
}

func (s *authService) putWA(p waPending) string {
	id := randomToken(16)
	s.waMu.Lock()
	defer s.waMu.Unlock()
	now := time.Now()
	for k, v := range s.waSess {
		if now.After(v.expires) {
			delete(s.waSess, k)
		}
	}
	// Bounded: drop the soonest-to-expire challenge when full, so a flood of
	// unauthenticated begin requests cannot grow memory without limit.
	for len(s.waSess) >= waPendingMax {
		oldest, oldestAt := "", time.Time{}
		for k, v := range s.waSess {
			if oldest == "" || v.expires.Before(oldestAt) {
				oldest, oldestAt = k, v.expires
			}
		}
		delete(s.waSess, oldest)
	}
	p.expires = now.Add(5 * time.Minute)
	s.waSess[id] = p
	return id
}

func (s *authService) takeWA(id, purpose string) (waPending, bool) {
	s.waMu.Lock()
	defer s.waMu.Unlock()
	p, ok := s.waSess[id]
	delete(s.waSess, id)
	if !ok || p.purpose != purpose || time.Now().After(p.expires) {
		return waPending{}, false
	}
	return p, true
}

type waBeginResp struct {
	Challenge string `json:"challenge_id"`
	Options   any    `json:"options"`
}

func (s *authService) passkeyRegisterBegin(c *Ctx) (any, error) {
	if err := enrolAllowed(c.P); err != nil {
		return nil, err
	}
	w, err := s.webAuthn(c.R)
	if err != nil {
		return nil, err
	}
	wu, err := s.waUser(c.ctx(), *c.P.UserID)
	if err != nil {
		return nil, err
	}
	var excl []protocol.CredentialDescriptor
	for _, cr := range wu.creds {
		excl = append(excl, cr.Descriptor())
	}
	opts, sd, err := w.BeginRegistration(wu, webauthn.WithExclusions(excl),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred))
	if err != nil {
		return nil, err
	}
	id := s.putWA(waPending{data: *sd, userID: *c.P.UserID, purpose: "register"})
	return waBeginResp{Challenge: id, Options: opts}, nil
}

func (s *authService) passkeyRegisterFinish(c *Ctx) (any, error) {
	if err := enrolAllowed(c.P); err != nil {
		return nil, err
	}
	p, ok := s.takeWA(c.Q("challenge_id"), "register")
	if !ok || p.userID != *c.P.UserID {
		return nil, badRequest("registration expired; try again")
	}
	w, err := s.webAuthn(c.R)
	if err != nil {
		return nil, err
	}
	wu, err := s.waUser(c.ctx(), p.userID)
	if err != nil {
		return nil, err
	}
	cred, err := w.FinishRegistration(wu, p.data, c.R)
	if err != nil {
		return nil, badRequest("passkey registration failed: %v", protocolErr(err))
	}
	name := strings.TrimSpace(c.Q("name"))
	if name == "" {
		name = "Passkey"
	}
	b, _ := json.Marshal(cred)
	_, err = s.app.db.ExecContext(c.ctx(), `INSERT INTO webauthn_credentials (tenant_id, user_id, name, credential_id, credential_json, created_at) VALUES (?,?,?,?,?,?)`,
		wu.u.TenantID, wu.u.ID, truncateStr(name, 64), cred.ID, string(b), db.Now())
	if err != nil {
		return nil, err
	}
	if c.P.MFAPending {
		_ = s.upgradeSession(c, 0)
	}
	c.auditT(wu.u.TenantID, "user.passkey_added", "user", itoa(wu.u.ID), map[string]any{"name": name})
	return map[string]bool{"ok": true}, nil
}

func protocolErr(err error) string {
	var pe *protocol.Error
	if errors.As(err, &pe) && pe.DevInfo != "" {
		return pe.Details + ": " + pe.DevInfo
	}
	return err.Error()
}

// passkeyMFABegin starts a passkey assertion for a pending MFA session.
func (s *authService) passkeyMFABegin(c *Ctx) (any, error) {
	if err := verifyAllowed(c.P); err != nil {
		return nil, err
	}
	w, err := s.webAuthn(c.R)
	if err != nil {
		return nil, err
	}
	wu, err := s.waUser(c.ctx(), *c.P.UserID)
	if err != nil {
		return nil, err
	}
	if len(wu.creds) == 0 {
		return nil, badRequest("no passkeys registered")
	}
	opts, sd, err := w.BeginLogin(wu)
	if err != nil {
		return nil, err
	}
	return waBeginResp{Challenge: s.putWA(waPending{data: *sd, userID: wu.u.ID, purpose: "mfa"}), Options: opts}, nil
}

func (s *authService) passkeyMFAFinish(c *Ctx) (any, error) {
	p, ok := s.takeWA(c.Q("challenge_id"), "mfa")
	if !ok || verifyAllowed(c.P) != nil || p.userID != *c.P.UserID {
		return nil, badRequest("challenge expired; try again")
	}
	w, err := s.webAuthn(c.R)
	if err != nil {
		return nil, err
	}
	wu, err := s.waUser(c.ctx(), p.userID)
	if err != nil {
		return nil, err
	}
	cred, err := w.FinishLogin(wu, p.data, c.R)
	if err != nil {
		return nil, unauthorized("passkey verification failed")
	}
	s.touchCredential(c.ctx(), cred)
	if err := s.upgradeSession(c, 0); err != nil {
		return nil, err
	}
	s.loginCompleted(c, wu.u, "password+passkey")
	return loginResp{CSRF: c.P.CSRF, User: wu.u}, nil
}

func (s *authService) touchCredential(ctx context.Context, cred *webauthn.Credential) {
	b, _ := json.Marshal(cred)
	_, _ = s.app.db.ExecContext(ctx, `UPDATE webauthn_credentials SET credential_json=?, last_used_at=? WHERE credential_id=?`, string(b), db.Now(), cred.ID)
}

// passkeyLoginBegin starts passwordless (discoverable) login.
func (s *authService) passkeyLoginBegin(c *Ctx) (any, error) {
	w, err := s.webAuthn(c.R)
	if err != nil {
		return nil, err
	}
	opts, sd, err := w.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, err
	}
	return waBeginResp{Challenge: s.putWA(waPending{data: *sd, purpose: "login"}), Options: opts}, nil
}

func (s *authService) passkeyLoginFinish(c *Ctx) (any, error) {
	p, ok := s.takeWA(c.Q("challenge_id"), "login")
	if !ok {
		return nil, badRequest("challenge expired; try again")
	}
	w, err := s.webAuthn(c.R)
	if err != nil {
		return nil, err
	}
	var found *waUser
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		var uid int64
		if err := s.app.db.GetContext(c.ctx(), &uid, `SELECT id FROM users WHERE webauthn_id=?`, userHandle); err != nil {
			return nil, errors.New("unknown user")
		}
		wu, err := s.waUser(c.ctx(), uid)
		if err != nil {
			return nil, err
		}
		found = wu
		return wu, nil
	}
	cred, err := w.FinishDiscoverableLogin(handler, p.data, c.R)
	if err != nil || found == nil {
		s.app.audit(c.ctx(), auditEntry{Actor: "passkey", Action: "auth.login_failed", IP: s.app.clientIP(c.R), Details: map[string]any{"method": "passkey"}})
		return nil, unauthorized("passkey not recognised")
	}
	if found.u.Disabled {
		return nil, unauthorized("account disabled")
	}
	s.touchCredential(c.ctx(), cred)
	csrf, err := s.createSession(c.W, c.R, found.u, 0)
	if err != nil {
		return nil, err
	}
	s.loginCompleted(c, found.u, "passkey")
	return loginResp{CSRF: csrf, User: found.u}, nil
}
