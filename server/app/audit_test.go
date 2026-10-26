package app

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	pb "sentrel/gen/sentrelv1"
	"sentrel/server/db"
	"sentrel/server/metrics"
)

func TestPendingMFASessionDoesNotSlide(t *testing.T) {
	e := newTestEnv(t)
	seedRecoveryUser(t, e, "recovery-code")
	c := pendingLogin(t, e)
	var token string
	u, err := url.Parse(e.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, cookie := range c.http.Jar.Cookies(u) {
		if cookie.Name == sessionCookie {
			token = cookie.Value
		}
	}
	now := db.Now()
	expires := now + 300
	if _, err := e.a.db.Exec(`UPDATE sessions SET last_seen_at=?, expires_at=? WHERE id_hash=?`, now-120, expires, hashToken(token)); err != nil {
		t.Fatal(err)
	}
	if p := e.a.auth.sessionPrincipal(context.Background(), token); p == nil || !p.MFAPending {
		t.Fatal("missing pending principal")
	}
	var got int64
	if err := e.a.db.Get(&got, `SELECT expires_at FROM sessions WHERE id_hash=?`, hashToken(token)); err != nil {
		t.Fatal(err)
	}
	if got != expires {
		t.Fatalf("pending MFA deadline extended from %d to %d", expires, got)
	}
	// Completed sessions still slide.
	if _, err := e.a.db.Exec(`UPDATE sessions SET mfa_pending=0, last_seen_at=? WHERE id_hash=?`, now-120, hashToken(token)); err != nil {
		t.Fatal(err)
	}
	e.a.auth.sessionPrincipal(context.Background(), token)
	if err := e.a.db.Get(&got, `SELECT expires_at FROM sessions WHERE id_hash=?`, hashToken(token)); err != nil {
		t.Fatal(err)
	}
	if got <= expires {
		t.Fatal("completed session did not renew")
	}
}

func TestAgentCannotForgeAnotherTenantsCheckHistory(t *testing.T) {
	e := newTestEnv(t)
	root := e.setupAdmin()
	source := tenantUser(t, root, "Source", "source-admin")
	victim := tenantUser(t, root, "Victim", "victim-admin")
	h := okDo(t, root, "POST", "/hosts/target", map[string]any{"name": "source-host", "address": "192.0.2.1", "tenant_id": source})
	hid := int64(h["id"].(float64))
	hostTenantCache.Delete(hid)
	t.Cleanup(func() { hostTenantCache.Delete(hid) })
	vc := e.login("victim-admin", testPassword)
	k := okDo(t, vc, "POST", "/checks", map[string]any{"name": "victim-cert", "type": "cert", "target": "example.com:443", "tenant_id": victim})
	kid := int64(k["id"].(float64))
	e.a.ingestMetrics(context.Background(), hid, &pb.MetricBatch{Samples: []*pb.Sample{
		{Name: "check_cert_days", Labels: map[string]string{"check_id": itoa(kid)}, Value: 31337},
		{Name: "check.cert_days", Labels: map[string]string{"check_id": itoa(kid)}, Value: 31337},
		{Name: "cpu_usage_percent", Value: 42},
	}})
	if got := e.a.latest.get(hid); got == nil || got.CPU == nil || *got.CPU != 42 {
		t.Fatal("ordinary agent metrics were lost")
	}
	forged, err := e.a.ts.QueryInstant(context.Background(), `sentrel_check_cert_days`, time.Now())
	if err != nil || len(forged) != 0 {
		t.Fatalf("agent injected server-owned metrics: %+v %v", forged, err)
	}
	// Existing attacker-supplied samples must also be excluded by history queries.
	if err := e.a.ts.Append(hid, source, []metrics.Sample{{Name: "check_cert_days", Labels: map[string]string{"check_id": itoa(kid)}, Value: 31337}}); err != nil {
		t.Fatal(err)
	}
	code, m, raw := vc.do("GET", "/checks/"+itoa(kid)+"/history", nil)
	if code != 200 {
		t.Fatalf("history: %d %s", code, raw)
	}
	if _, ok := m["cert_days"]; ok {
		t.Fatalf("attacker-controlled data exposed in victim's check: %s", raw)
	}
}

func TestFindingsNegativeLimitDoesNotPanic(t *testing.T) {
	e := newTestEnv(t)
	root := e.setupAdmin()
	cfg := e.a.settings.Vuln()
	cfg.Enabled = true
	saveSettings(t, e, keyVuln, cfg)
	for _, query := range []string{"?limit=-1&fixable=1", "?limit=-1&inactive=0"} {
		if code, _, raw := root.do("GET", "/vulnerabilities"+query, nil); code != 200 {
			t.Fatalf("negative limit must be bounded safely: %d %s", code, raw)
		}
	}
}

func TestMFASuccessRefreshesBrowserCookie(t *testing.T) {
	e := newTestEnv(t)
	seedRecoveryUser(t, e, "one-time-recovery")
	c := pendingLogin(t, e)
	r, err := http.NewRequest("POST", e.srv.URL+"/api/v1/auth/mfa/totp", strings.NewReader(`{"code":"one-time-recovery"}`))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", c.csrf)
	resp, err := c.http.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("MFA finish: %d", resp.StatusCode)
	}
	for _, cookie := range resp.Cookies() {
		if cookie.Name == sessionCookie {
			if cookie.Expires.Before(time.Now().Add(11 * time.Hour)) {
				t.Fatalf("MFA cookie retains short deadline: %+v", cookie)
			}
			return
		}
	}
	t.Fatal("successful MFA did not refresh the browser session cookie")
}
