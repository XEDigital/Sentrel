package app

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"sentrel/server/metrics"
)

func TestMetricsDefaultAuthAndTenantIsolation(t *testing.T) {
	e := newTestEnv(t)
	root := e.setupAdmin()
	tid := tenantUser(t, root, "Acme", "acme")
	other := tenantUser(t, root, "Other", "other")
	if err := e.a.ts.Append(1, tid, []metrics.Sample{{Name: "cpu_usage_percent", Value: 11, TsMs: time.Now().UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	if err := e.a.ts.Append(2, other, []metrics.Sample{{Name: "cpu_usage_percent", Value: 22, TsMs: time.Now().UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	fetch := func(key string) (int, string) {
		r, err := http.NewRequest("GET", e.srv.URL+"/metrics", nil)
		if err != nil {
			t.Fatal(err)
		}
		if key != "" {
			r.Header.Set("Authorization", "Bearer "+key)
		}
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, string(body)
	}
	if code, _ := fetch(""); code != 401 {
		t.Fatalf("metrics open by default: %d", code)
	}
	tenant := e.login("acme", testPassword)
	key := newKey(t, tenant, "read")
	code, body := fetch(key)
	if code != 200 || !strings.Contains(body, `tenant_id="`+itoa(tid)+`"`) || strings.Contains(body, `tenant_id="`+itoa(other)+`"`) {
		t.Fatalf("tenant metrics leak: %d %s", code, body)
	}
	cfg := e.a.settings.Security()
	cfg.MetricsAuth = false
	if err := e.a.settings.Save(context.Background(), 0, keySecurity, cfg); err != nil {
		t.Fatal(err)
	}
	if newSettingsStore(e.a.db).Security().MetricsAuth {
		t.Fatal("explicit stored metrics opt-out was lost")
	}
	if code, _ := fetch(""); code != 200 {
		t.Fatalf("explicit public metrics opt-out failed: %d", code)
	}
}
