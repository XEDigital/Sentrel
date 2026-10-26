package app

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"sentrel/server/db"
)

// Single sign-on: OpenID Connect (authorization code + PKCE) and forward-auth
// headers from a trusted reverse proxy. Both map external groups to roles the
// same way the LDAP integration does and provision users on first login.

const oidcStateCookie = "sentrel_oidc"

var (
	ssoKeyOnce sync.Once
	ssoKeyVal  []byte
)

// ssoKey signs the short-lived login-state cookie. It lives in memory only: a
// restart simply invalidates logins that were in flight.
func ssoKey() []byte {
	ssoKeyOnce.Do(func() {
		ssoKeyVal = make([]byte, 32)
		_, _ = rand.Read(ssoKeyVal)
	})
	return ssoKeyVal
}

type oidcFlowState struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Expires  int64  `json:"e"`
}

func signFlowState(st oidcFlowState) string {
	b, _ := json.Marshal(st)
	mac := hmac.New(sha256.New, ssoKey())
	mac.Write(b)
	return base64.RawURLEncoding.EncodeToString(b) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func parseFlowState(v string) (oidcFlowState, bool) {
	var st oidcFlowState
	parts := strings.SplitN(v, ".", 2)
	if len(parts) != 2 {
		return st, false
	}
	b, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	sig, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	if err1 != nil || err2 != nil {
		return st, false
	}
	mac := hmac.New(sha256.New, ssoKey())
	mac.Write(b)
	if !hmac.Equal(sig, mac.Sum(nil)) || json.Unmarshal(b, &st) != nil || st.Expires < time.Now().Unix() {
		return oidcFlowState{}, false
	}
	return st, true
}

// --- settings validation ---

func validateGroupMap(m []LDAPRoleMapping, defRole string, defTenant int64) error {
	for i := range m {
		m[i].Group = strings.TrimSpace(m[i].Group)
		if m[i].Group == "" || !ValidRole(m[i].Role, m[i].TenantID) {
			return badRequest("group mapping %d needs a group and a role that fits its tenant", i+1)
		}
	}
	if defRole != "" && !ValidRole(defRole, defTenant) {
		return badRequest("default role does not fit the default tenant")
	}
	return nil
}

func validateOIDCSettings(s *OIDCSettings) error {
	s.IssuerURL = strings.TrimSpace(s.IssuerURL) // must match the provider's issuer exactly, trailing slash included
	s.ClientID = strings.TrimSpace(s.ClientID)
	s.ButtonLabel = truncateStr(strings.TrimSpace(s.ButtonLabel), 40)
	if s.ButtonLabel == "" {
		s.ButtonLabel = "SSO"
	}
	s.UsernameClaim = firstNonEmpty(strings.TrimSpace(s.UsernameClaim), "preferred_username")
	s.GroupsClaim = firstNonEmpty(strings.TrimSpace(s.GroupsClaim), "groups")
	fields := strings.Fields(s.Scopes)
	hasOpenID := false
	for _, f := range fields {
		hasOpenID = hasOpenID || f == "openid"
	}
	if !hasOpenID {
		fields = append([]string{"openid"}, fields...)
	}
	s.Scopes = strings.Join(fields, " ")
	if s.Enabled {
		u, err := url.Parse(s.IssuerURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return badRequest("OIDC needs an issuer URL like https://auth.example.com/application/o/sentrel")
		}
		if s.ClientID == "" {
			return badRequest("OIDC needs a client ID")
		}
	}
	return validateGroupMap(s.GroupRoleMap, s.DefaultRole, s.DefaultTenant)
}

func validateProxyAuthSettings(s *ProxyAuthSettings) error {
	s.UserHeader = strings.TrimSpace(s.UserHeader)
	s.EmailHeader = strings.TrimSpace(s.EmailHeader)
	s.NameHeader = strings.TrimSpace(s.NameHeader)
	s.GroupsHeader = strings.TrimSpace(s.GroupsHeader)
	if s.Enabled && s.UserHeader == "" {
		return badRequest("forward-auth needs the name of the header that carries the username")
	}
	return validateGroupMap(s.GroupRoleMap, s.DefaultRole, s.DefaultTenant)
}

// --- shared user mapping ---

type ssoDenied struct{ msg string }

func (e *ssoDenied) Error() string { return e.msg }

// cleanSSOUsername makes an identity-provider value fit local username rules.
func cleanSSOUsername(v string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(v) {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-@", r) {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	out := b.String()
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

// ssoIdentity is the stable key of an externally authenticated user. For OIDC
// it is the issuer and "sub"; forward-auth has no stable subject, so it is the
// header name and the username the proxy supplies (which must therefore be
// stable and unique).
type ssoIdentity struct{ Provider, Issuer, Subject string }

// ssoUser finds or provisions the local user for an externally authenticated
// identity. The account is found by its stable identity, never by username
// alone: username, email and name are mutable attributes refreshed on login.
// A pre-existing account is auto-linked only once, when it was created by the
// same source and has no identity linked at all (accounts from before
// identities were recorded). Anything else that matches by username is refused.
func (s *authService) ssoUser(ctx context.Context, source string, id ssoIdentity, username, email, name string, role string, tenant int64, mapped, allowProvision bool) (*User, error) {
	if len(username) < 2 {
		return nil, &ssoDenied{"the identity provider did not supply a usable username"}
	}
	if id.Subject == "" {
		return nil, &ssoDenied{"the identity provider did not supply a stable subject"}
	}
	a := s.app
	email = truncateStr(email, 200)
	name = truncateStr(firstNonEmpty(name, username), 100)

	var linked int64
	err := a.db.GetContext(ctx, &linked, `SELECT user_id FROM external_identities WHERE provider=? AND issuer=? AND subject=?`,
		id.Provider, id.Issuer, id.Subject)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if err == nil {
		u, err := a.getUser(ctx, linked)
		if err != nil {
			return nil, err
		}
		return s.ssoRefresh(ctx, u, source, username, email, name, role, tenant, mapped, true)
	}

	var u User
	err = a.db.GetContext(ctx, &u, `SELECT * FROM users WHERE username=?`, username)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if err == nil {
		if u.AuthSource != source {
			return nil, &ssoDenied{"an account named " + username + " already exists and is managed elsewhere"}
		}
		var n int
		if err := a.db.GetContext(ctx, &n, `SELECT COUNT(*) FROM external_identities WHERE user_id=?`, u.ID); err != nil {
			return nil, err
		}
		if n > 0 {
			a.log.Warn("sso login refused: username already linked to a different identity", "provider", id.Provider, "issuer", id.Issuer)
			return nil, &ssoDenied{"username already linked to a different identity"}
		}
		// One-time upgrade path for accounts created before identities were recorded.
		if u.Disabled {
			return nil, &ssoDenied{"this account is disabled"}
		}
		if !mapped {
			return nil, &ssoDenied{"none of your groups map to a role"}
		}
		if err := s.linkIdentity(ctx, u.ID, u.TenantID, id); err != nil {
			return nil, err
		}
		a.audit(ctx, auditEntry{TenantID: u.TenantID, Actor: "system", Action: "user.identity_linked", TargetType: "user", TargetID: itoa(u.ID),
			Details: map[string]any{"username": username, "provider": id.Provider, "issuer": id.Issuer, "migration": true}})
		cur, err := a.getUser(ctx, u.ID)
		if err != nil {
			return nil, err
		}
		return s.ssoRefresh(ctx, cur, source, username, email, name, role, tenant, mapped, false)
	}
	if !mapped {
		return nil, &ssoDenied{"none of your groups map to a role"}
	}
	if !allowProvision {
		return nil, &ssoDenied{"automatic account creation is disabled; ask an administrator to add you"}
	}
	nu, err := s.provision(ctx, username, email, name, role, tenant, source)
	if err != nil {
		return nil, err
	}
	if err := s.linkIdentity(ctx, nu.ID, nu.TenantID, id); err != nil {
		_, _ = a.db.ExecContext(ctx, `DELETE FROM users WHERE id=?`, nu.ID)
		return nil, err
	}
	return nu, nil
}

func (s *authService) linkIdentity(ctx context.Context, userID, tenant int64, id ssoIdentity) error {
	_, err := s.app.db.ExecContext(ctx, `INSERT INTO external_identities (tenant_id, user_id, provider, issuer, subject, created_at) VALUES (?,?,?,?,?,?)`,
		tenant, userID, id.Provider, id.Issuer, id.Subject, db.Now())
	return err
}

// ssoRefresh applies the current attributes to a user resolved by identity.
// renameOK lets the username follow the identity provider when it is free.
func (s *authService) ssoRefresh(ctx context.Context, u *User, source, username, email, name, role string, tenant int64, mapped, renameOK bool) (*User, error) {
	a := s.app
	if u.AuthSource != source {
		return nil, &ssoDenied{"an account named " + u.Username + " already exists and is managed elsewhere"}
	}
	if u.Disabled {
		return nil, &ssoDenied{"this account is disabled"}
	}
	if !mapped {
		// Access was removed at the identity provider: end what is left of it here.
		s.revokeAccess(ctx, u, true)
		return nil, &ssoDenied{"none of your groups map to a role"}
	}
	if renameOK && username != u.Username {
		var other int64
		err := a.db.GetContext(ctx, &other, `SELECT id FROM users WHERE username=? AND id<>?`, username, u.ID)
		if errors.Is(err, sql.ErrNoRows) {
			if _, err := a.db.ExecContext(ctx, `UPDATE users SET username=? WHERE id=?`, username, u.ID); err != nil {
				return nil, err
			}
			a.audit(ctx, auditEntry{TenantID: u.TenantID, Actor: "system", Action: "user.renamed", TargetType: "user", TargetID: itoa(u.ID),
				Details: map[string]any{"from": u.Username, "to": username, "source": source}})
		} else if err == nil {
			a.log.Warn("sso username changed but the new name belongs to another account; keeping the old name", "user", u.Username)
		} else {
			return nil, err
		}
	}
	// Same rule as LDAP and RADIUS: a lowered role or a tenant change revokes
	// the user's existing sessions (and API keys on a tenant change).
	nu, err := s.syncExternalUser(ctx, u, email, name, role, tenant)
	if err != nil {
		return nil, err
	}
	_, _ = a.db.ExecContext(ctx, `UPDATE external_identities SET tenant_id=? WHERE user_id=?`, tenant, u.ID)
	return nu, nil
}

func (s *authService) ssoFailed(r *http.Request, method, who string, err error) {
	s.app.audit(r.Context(), auditEntry{Actor: who, Action: "auth.login_failed", IP: s.app.clientIP(r),
		Details: map[string]any{"method": method, "reason": err.Error()}})
}

// --- OIDC ---

var oidcHTTP = &http.Client{Timeout: 15 * time.Second}

type oidcProviderCache struct {
	mu     sync.Mutex
	issuer string
	p      *oidc.Provider
	at     time.Time
}

var oidcCache oidcProviderCache

func oidcDiscover(issuer string, force bool) (*oidc.Provider, error) {
	oidcCache.mu.Lock()
	defer oidcCache.mu.Unlock()
	if !force && oidcCache.p != nil && oidcCache.issuer == issuer && time.Since(oidcCache.at) < 10*time.Minute {
		return oidcCache.p, nil
	}
	// Background context: the provider keeps it to fetch signing keys later.
	p, err := oidc.NewProvider(oidc.ClientContext(context.Background(), oidcHTTP), issuer)
	if err != nil {
		return nil, err
	}
	oidcCache.issuer, oidcCache.p, oidcCache.at = issuer, p, time.Now()
	return p, nil
}

func (a *App) oidcCallbackURL(r *http.Request) string {
	return a.publicURL(r) + "/api/v1/auth/oidc/callback"
}

func (a *App) oidcConfig(r *http.Request, cfg OIDCSettings, p *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, Endpoint: p.Endpoint(),
		RedirectURL: a.oidcCallbackURL(r), Scopes: strings.Fields(cfg.Scopes)}
}

func ssoRedirect(w http.ResponseWriter, r *http.Request, to string) {
	http.Redirect(w, r, to, http.StatusFound)
}

func ssoErrorRedirect(w http.ResponseWriter, r *http.Request, msg string) {
	ssoRedirect(w, r, "/login?sso_error="+url.QueryEscape(msg))
}

func (s *authService) clearFlowCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: oidcStateCookie, Value: "", Path: "/api/v1/auth/oidc", MaxAge: -1, HttpOnly: true,
		Secure: s.app.isHTTPS(r), SameSite: http.SameSiteLaxMode})
}

func (s *authService) oidcStart(c *Ctx) (any, error) {
	return rawResponse(func(w http.ResponseWriter) {
		r := c.R
		cfg := s.app.settings.OIDC()
		if !cfg.Enabled {
			ssoErrorRedirect(w, r, "Single sign-on is not enabled")
			return
		}
		p, err := oidcDiscover(cfg.IssuerURL, false)
		if err != nil {
			s.app.log.Warn("oidc discovery", "err", err)
			ssoErrorRedirect(w, r, "The identity provider could not be reached")
			return
		}
		st := oidcFlowState{State: randomToken(24), Nonce: randomToken(24), Verifier: oauth2.GenerateVerifier(), Expires: time.Now().Add(10 * time.Minute).Unix()}
		// Lax is required: the provider redirects back with a cross-site GET.
		http.SetCookie(w, &http.Cookie{Name: oidcStateCookie, Value: signFlowState(st), Path: "/api/v1/auth/oidc", MaxAge: 600, HttpOnly: true,
			Secure: s.app.isHTTPS(r), SameSite: http.SameSiteLaxMode})
		conf := s.app.oidcConfig(r, cfg, p)
		ssoRedirect(w, r, conf.AuthCodeURL(st.State, oauth2.S256ChallengeOption(st.Verifier), oauth2.SetAuthURLParam("nonce", st.Nonce)))
	}), nil
}

func (s *authService) oidcCallback(c *Ctx) (any, error) {
	return rawResponse(func(w http.ResponseWriter) {
		r := c.R
		_, err := s.oidcLogin(c)
		s.clearFlowCookie(w, r)
		if err != nil {
			s.ssoFailed(r, "oidc", "oidc", err)
			var d *ssoDenied
			if errors.As(err, &d) {
				ssoErrorRedirect(w, r, d.msg)
			} else {
				s.app.log.Warn("oidc login", "err", err)
				ssoErrorRedirect(w, r, "Sign-in failed")
			}
			return
		}
		ssoRedirect(w, r, "/")
	}), nil
}

// claimPath reads a possibly nested ("realm_access.roles") claim.
func claimPath(m map[string]any, path string) any {
	if v, ok := m[path]; ok {
		return v
	}
	var cur any = m
	for _, part := range strings.Split(path, ".") {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[part]
	}
	return cur
}

func claimStrings(v any) []string {
	switch t := v.(type) {
	case string:
		if strings.TrimSpace(t) == "" {
			return nil
		}
		return strings.FieldsFunc(t, func(r rune) bool { return r == ',' || r == ' ' })
	case []any:
		var out []string
		for _, x := range t {
			if str, ok := x.(string); ok && str != "" {
				out = append(out, str)
			}
		}
		return out
	}
	return nil
}

func claimBool(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(t, "true")
	}
	return false
}

func claimString(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

func (s *authService) oidcLogin(c *Ctx) (*User, error) {
	a := s.app
	r := c.R
	cfg := a.settings.OIDC()
	if !cfg.Enabled {
		return nil, &ssoDenied{"Single sign-on is not enabled"}
	}
	if e := r.URL.Query().Get("error"); e != "" {
		return nil, &ssoDenied{"The identity provider refused the request (" + truncateStr(cleanSSOUsername(e), 40) + ")"}
	}
	ck, err := r.Cookie(oidcStateCookie)
	if err != nil {
		return nil, &ssoDenied{"Your sign-in session expired; try again"}
	}
	st, ok := parseFlowState(ck.Value)
	if !ok {
		return nil, &ssoDenied{"Your sign-in session expired; try again"}
	}
	if subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("state")), []byte(st.State)) != 1 {
		return nil, &ssoDenied{"Sign-in state did not match; try again"}
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		return nil, &ssoDenied{"The identity provider returned no authorization code"}
	}
	p, err := oidcDiscover(cfg.IssuerURL, false)
	if err != nil {
		return nil, err
	}
	ctx := oidc.ClientContext(r.Context(), oidcHTTP)
	conf := a.oidcConfig(r, cfg, p)
	tok, err := conf.Exchange(ctx, code, oauth2.VerifierOption(st.Verifier))
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return nil, &ssoDenied{"The identity provider returned no ID token"}
	}
	idt, err := p.Verifier(&oidc.Config{ClientID: cfg.ClientID}).Verify(ctx, raw)
	if err != nil {
		return nil, &ssoDenied{"The ID token could not be verified"}
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(st.Nonce)) != 1 {
		return nil, &ssoDenied{"The ID token nonce did not match; try again"}
	}
	claims := map[string]any{}
	if err := idt.Claims(&claims); err != nil {
		return nil, err
	}
	// Fill in claims the ID token omits (many providers keep groups and
	// profile data on the userinfo endpoint).
	if claimPath(claims, cfg.GroupsClaim) == nil || claims[cfg.UsernameClaim] == nil || claims["email"] == nil {
		if ui, err := p.UserInfo(ctx, oauth2.StaticTokenSource(tok)); err == nil {
			extra := map[string]any{}
			if ui.Claims(&extra) == nil && claimString(extra["sub"]) == idt.Subject {
				for k, v := range extra {
					if _, have := claims[k]; !have {
						claims[k] = v
					}
				}
			}
		}
	}
	email := claimString(claims["email"])
	if cfg.RequireVerifiedEmail && !(email != "" && claimBool(claims["email_verified"])) {
		return nil, &ssoDenied{"Your email address is not verified with the identity provider"}
	}
	username := cleanSSOUsername(firstNonEmpty(claimString(claimPath(claims, cfg.UsernameClaim)), email, idt.Subject))
	name := claimString(claims["name"])
	role, tenant, mapped := mapGroupRole(cfg.GroupRoleMap, cfg.DefaultRole, cfg.DefaultTenant, claimStrings(claimPath(claims, cfg.GroupsClaim)))
	u, err := s.ssoUser(r.Context(), "oidc", ssoIdentity{"oidc", idt.Issuer, idt.Subject}, username, email, name, role, tenant, mapped, cfg.AllowProvision)
	if err != nil {
		return nil, err
	}
	mfa := 0
	if !(cfg.TrustIdPMFA && amrSatisfiesMFA(claims["amr"])) {
		if len(s.mfaMethods(r.Context(), u)) > 0 {
			mfa = 1
		} else if s.policyRequires2FA(u) {
			mfa = 2
		}
	}
	if _, err := s.createSession(c.W, r, u, mfa); err != nil {
		return nil, err
	}
	if mfa != 1 {
		s.loginCompleted(c, u, "oidc")
	}
	return u, nil
}

func amrSatisfiesMFA(v any) bool {
	for _, m := range claimStrings(v) {
		switch strings.ToLower(m) {
		case "mfa", "otp", "hwk":
			return true
		}
	}
	return false
}

func (a *App) apiTestOIDC(c *Ctx) (any, error) {
	cfg := a.settings.OIDC()
	if cfg.IssuerURL == "" {
		return map[string]any{"ok": false, "error": "save an issuer URL first"}, nil
	}
	p, err := oidcDiscover(cfg.IssuerURL, true)
	if err != nil {
		return map[string]any{"ok": false, "error": "discovery failed: " + err.Error()}, nil
	}
	var meta struct {
		PKCE []string `json:"code_challenge_methods_supported"`
	}
	_ = p.Claims(&meta)
	msg := "discovery succeeded; authorization endpoint " + p.Endpoint().AuthURL
	if len(meta.PKCE) > 0 {
		has := false
		for _, m := range meta.PKCE {
			has = has || m == "S256"
		}
		if !has {
			msg += "; warning: the provider does not advertise PKCE S256"
		}
	}
	if a.settings.General().ServerURL == "" {
		msg += "; warning: set the server URL so the redirect URI is stable"
	}
	return map[string]any{"ok": true, "message": msg, "callback_url": a.oidcCallbackURL(c.R)}, nil
}

// --- forward-auth ---

// proxyPrincipal authenticates a session-less request from the identity
// headers set by a trusted reverse proxy (Authelia, Authentik outpost,
// oauth2-proxy, ...). The headers are honoured only when the TCP peer is in
// the trusted proxy list, and only on GET/HEAD so the new session's CSRF
// token reaches the browser before it makes a write.
func (s *authService) proxyPrincipal(w http.ResponseWriter, r *http.Request) *Principal {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return nil
	}
	a := s.app
	cfg := a.settings.ProxyAuth()
	if !cfg.Enabled || cfg.UserHeader == "" {
		return nil
	}
	raw := strings.TrimSpace(r.Header.Get(cfg.UserHeader))
	if raw == "" || !a.fromTrustedProxy(r) {
		return nil
	}
	var groups []string
	if cfg.GroupsHeader != "" {
		for _, g := range strings.Split(strings.Join(r.Header.Values(cfg.GroupsHeader), ","), ",") {
			if g = strings.TrimSpace(g); g != "" {
				groups = append(groups, g)
			}
		}
	}
	var email, name string
	if cfg.EmailHeader != "" {
		email = strings.TrimSpace(r.Header.Get(cfg.EmailHeader))
	}
	if cfg.NameHeader != "" {
		name = strings.TrimSpace(r.Header.Get(cfg.NameHeader))
	}
	role, tenant, mapped := mapGroupRole(cfg.GroupRoleMap, cfg.DefaultRole, cfg.DefaultTenant, groups)
	username := cleanSSOUsername(raw)
	u, err := s.ssoUser(r.Context(), "proxy", ssoIdentity{"proxy", strings.ToLower(cfg.UserHeader), username}, username, email, name, role, tenant, mapped, cfg.AllowProvision)
	if err != nil {
		s.ssoFailed(r, "proxy", username, err)
		return nil
	}
	if _, err := s.createSession(w, r, u, 0); err != nil {
		a.log.Warn("proxy login", "err", err)
		return nil
	}
	s.loginCompleted(&Ctx{a: a, W: w, R: r}, u, "proxy")
	for _, ck := range (&http.Response{Header: w.Header()}).Cookies() {
		if ck.Name == sessionCookie {
			return s.sessionPrincipal(r.Context(), ck.Value)
		}
	}
	return nil
}
