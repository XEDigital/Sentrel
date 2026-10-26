package app

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCookieSecurityFollowsTrustedTransport(t *testing.T) {
	e := newTestEnv(t)
	e.setupAdmin()
	u, err := e.a.getUser(e.a.ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name            string
		tls, trust      bool
		peer, forwarded string
		secure          bool
	}{
		{"direct TLS", true, false, "192.0.2.1:1234", "", true},
		{"explicit HTTP", false, false, "192.0.2.1:1234", "", false},
		{"trusted TLS proxy", false, true, "127.0.0.1:1234", "https", true},
		{"untrusted forwarded header", false, true, "192.0.2.1:1234", "https", false},
		{"proxy trust disabled", false, false, "127.0.0.1:1234", "https", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			saveSettings(t, e, keyTLS, TLSSettings{Mode: "http", TrustProxy: tc.trust})
			r := httptest.NewRequest("GET", "http://monitor.test/", nil)
			r.RemoteAddr = tc.peer
			r.Header.Set("X-Forwarded-Proto", tc.forwarded)
			if tc.tls {
				r.TLS = &tls.ConnectionState{}
			}
			for _, action := range []string{"session", "logout", "oidc-clear"} {
				w := httptest.NewRecorder()
				switch action {
				case "session":
					if _, err := e.a.auth.createSession(w, r, u, 0); err != nil {
						t.Fatal(err)
					}
				case "logout":
					if _, err := e.a.auth.logout(&Ctx{a: e.a, W: w, R: r}); err != nil {
						t.Fatal(err)
					}
				case "oidc-clear":
					e.a.auth.clearFlowCookie(w, r)
				}
				cookies := w.Result().Cookies()
				if len(cookies) != 1 {
					t.Fatalf("%s cookies: %+v", action, cookies)
				}
				c := cookies[0]
				if c.Secure != tc.secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
					t.Fatalf("%s unsafe cookie: %+v", action, c)
				}
			}
		})
	}
}

func TestBeatQueryBounds(t *testing.T) {
	e := newTestEnv(t)
	root := e.setupAdmin()
	h := okDo(t, root, "POST", "/hosts/target", map[string]any{"name": "host", "address": "192.0.2.1"})
	id := itoa(int64(h["id"].(float64)))
	for _, days := range []string{"9223372036854775807", "9999999999999999999999999", "-1", "0", "1", "90", "1000"} {
		code, m, raw := root.do("GET", "/hosts/beats?days="+days, nil)
		if code != 200 {
			t.Fatalf("days=%s: %d %s", days, code, raw)
		}
		beats, ok := m[id].([]any)
		if !ok || len(beats) < 1 || len(beats) > 90 {
			t.Fatalf("days=%s unbounded: %s", days, raw)
		}
	}
}
