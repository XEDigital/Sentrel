package app

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// An unauthenticated gRPC call may send only a small body, and only so many
// such calls may be open per source address.
func TestGRPCPreAuthGate(t *testing.T) {
	lim := &preAuthLimiter{}
	var read int64
	var readErr error
	release := false
	h := gateGRPC(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if release {
			releaseGRPCGate(r.Context())
		}
		read, readErr = io.Copy(io.Discard, r.Body)
	}), lim)
	call := func() {
		r := httptest.NewRequest("POST", "/sentrel.v1.AgentService/Connect", strings.NewReader(strings.Repeat("x", 4*preAuthBodyLimit)))
		r.RemoteAddr = "203.0.113.9:1234"
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
	call()
	if readErr != errPreAuthTooLarge || read != preAuthBodyLimit {
		t.Fatalf("pre-auth body: read %d, err %v", read, readErr)
	}
	release = true
	call()
	if readErr != nil || read != 4*preAuthBodyLimit {
		t.Fatalf("authenticated body: read %d, err %v", read, readErr)
	}
	if lim.total != 0 || len(lim.perIP) != 0 {
		t.Fatalf("slots leaked: %d %v", lim.total, lim.perIP)
	}

	// Fill one address's slots: the next call is refused, other addresses are not.
	for i := 0; i < preAuthStreamsPerIP; i++ {
		if !lim.acquire("203.0.113.9") {
			t.Fatalf("slot %d refused", i)
		}
	}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/sentrel.v1.AgentService/Connect", nil)
	r.RemoteAddr = "203.0.113.9:1234"
	h.ServeHTTP(rec, r)
	if rec.Header().Get("Grpc-Status") != "8" {
		t.Fatalf("over-limit call not refused: %v", rec.Header())
	}
	if !lim.acquire("203.0.113.10") {
		t.Fatal("another address was refused")
	}
}

// A tenant user sees their own tenant's counts and no process details.
func TestServerStatusIsTenantScoped(t *testing.T) {
	e := newTestEnv(t)
	root := e.setupAdmin()
	e.enrol(root)
	tenantUser(t, root, "Acme", "acme-admin")
	ta := e.login("acme-admin", testPassword)
	code, m, raw := ta.do("GET", "/server/status", nil)
	if code != 200 {
		t.Fatalf("status: %d %s", code, raw)
	}
	if m["hosts_total"].(float64) != 0 || m["agents_total"].(float64) != 0 {
		t.Fatalf("tenant sees fleet-wide counts: %s", raw)
	}
	for _, k := range []string{"memory_bytes", "goroutines", "go", "data_dir"} {
		if _, ok := m[k]; ok {
			t.Fatalf("tenant sees %s: %s", k, raw)
		}
	}
	_, m, raw = root.do("GET", "/server/status", nil)
	if m["hosts_total"].(float64) != 1 || m["memory_bytes"] == nil {
		t.Fatalf("provider status: %s", raw)
	}
}

// Updating some fields of a user leaves the others alone.
func TestUserPartialUpdateKeepsEmail(t *testing.T) {
	e := newTestEnv(t)
	root := e.setupAdmin()
	u := okDo(t, root, "POST", "/users", map[string]any{"username": "viewer", "email": "v@example.test", "password": testPassword, "role": "viewer"})
	id := itoa(int64(u["id"].(float64)))
	okDo(t, root, "PUT", "/users/"+id, map[string]any{"display_name": "Viewer One"})
	var email, name string
	_ = e.a.db.QueryRow(`SELECT email, display_name FROM users WHERE id=?`, id).Scan(&email, &name)
	if email != "v@example.test" || name != "Viewer One" {
		t.Fatalf("after partial update: email %q, name %q", email, name)
	}
	okDo(t, root, "PUT", "/users/"+id, map[string]any{"email": ""})
	_ = e.a.db.QueryRow(`SELECT email FROM users WHERE id=?`, id).Scan(&email)
	if email != "" {
		t.Fatalf("explicit empty email not applied: %q", email)
	}
}

// A key cannot be given a scope its owner's role has no use for.
func TestAPIKeyScopeWithinRole(t *testing.T) {
	e := newTestEnv(t)
	root := e.setupAdmin()
	okDo(t, root, "POST", "/users", map[string]any{"username": "viewer", "password": testPassword, "role": "viewer"})
	v := e.login("viewer", testPassword)
	if code, _, raw := v.do("POST", "/api-keys", map[string]any{"name": "k", "scopes": []string{"admin"}}); code != 400 {
		t.Fatalf("viewer created an admin-scoped key: %d %s", code, raw)
	}
	if code, _, raw := v.do("POST", "/api-keys", map[string]any{"name": "k", "scopes": []string{"read"}}); code != 201 {
		t.Fatalf("viewer read key: %d %s", code, raw)
	}
	if code, _, raw := root.do("POST", "/api-keys", map[string]any{"name": "k", "scopes": []string{"admin", "jobs"}}); code != 201 {
		t.Fatalf("admin key: %d %s", code, raw)
	}
}

// Failed logins from one address must not lock out an account that has
// logged in from that address before; unknown accounts stay blocked.
func TestSharedAddressLockout(t *testing.T) {
	e := newTestEnv(t)
	root := e.setupAdmin()
	okDo(t, root, "POST", "/users", map[string]any{"username": "regular", "password": testPassword, "role": "viewer"})
	okDo(t, root, "POST", "/users", map[string]any{"username": "newcomer", "password": testPassword, "role": "viewer"})
	e.login("regular", testPassword)
	c := e.client()
	for i := 0; i < 60; i++ {
		c.do("POST", "/auth/login", map[string]any{"username": "spray" + itoa(int64(i)), "password": "wrong-password-1"})
	}
	if code, _, raw := c.do("POST", "/auth/login", map[string]any{"username": "newcomer", "password": testPassword}); code != 429 {
		t.Fatalf("address-wide limit not applied to an unknown account: %d %s", code, raw)
	}
	e.login("regular", testPassword)
	// The known account still has its own limit.
	for i := 0; i < 10; i++ {
		c.do("POST", "/auth/login", map[string]any{"username": "regular", "password": "wrong-password-1"})
	}
	if code, _, _ := c.do("POST", "/auth/login", map[string]any{"username": "regular", "password": testPassword}); code != 429 {
		t.Fatalf("per-account limit lost: %d", code)
	}
}

// A client that stops sending its request body is cut off.
func TestSlowBodyTimesOut(t *testing.T) {
	old := bodyReadTimeout
	bodyReadTimeout = 300 * time.Millisecond
	defer func() { bodyReadTimeout = old }()
	e := newTestEnv(t)
	conn, err := net.Dial("tcp", e.srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "POST /api/v1/auth/login HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 200\r\n\r\n{\"username\":")
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("no response to a stalled body: %v", err)
	}
	if resp.StatusCode != 400 || time.Since(start) > 3*time.Second {
		t.Fatalf("stalled body: status %d after %v", resp.StatusCode, time.Since(start))
	}
}

func TestAgentInputLimits(t *testing.T) {
	for in, want := range map[string]string{
		"web-01.example.com": "web-01.example.com", "<img src=x onerror=alert(1)>": "imgsrcxonerroralert1",
		"a b\nc": "abc", "": "unnamed-host", strings.Repeat("a", 400): strings.Repeat("a", 253),
	} {
		if got := cleanHostName(in); got != want {
			t.Errorf("cleanHostName(%q) = %q, want %q", in, got, want)
		}
	}
	if !labelsWithinLimits(map[string]string{"mount": "/var/lib"}) {
		t.Error("ordinary labels refused")
	}
	if labelsWithinLimits(map[string]string{"k": strings.Repeat("v", maxLabelValueLen+1)}) {
		t.Error("oversized label value accepted")
	}
	many := map[string]string{}
	for i := 0; i <= maxSampleLabels; i++ {
		many["l"+itoa(int64(i))] = "v"
	}
	if labelsWithinLimits(many) {
		t.Error("too many labels accepted")
	}
}
