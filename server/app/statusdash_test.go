package app

import (
	"context"
	"strings"
	"testing"
	"time"

	pb "sentrel/gen/sentrelv1"
)

// A page that uses none of the extras reveals only labels and state; metrics
// and the overview appear only where the page asks for them.
func TestStatusPageMetricsAreOptIn(t *testing.T) {
	e := newTestEnv(t)
	admin := e.setupAdmin()
	hostID, _ := e.enrol(admin)
	ctx := context.Background()
	now := time.Now()
	var samples []*pb.Sample
	for i := 10; i >= 1; i-- {
		ts := now.Add(-time.Duration(i) * time.Minute).UnixMilli()
		samples = append(samples,
			&pb.Sample{Name: "cpu_usage_percent", Value: float64(10 + i), TsMs: ts},
			&pb.Sample{Name: "mem_used_percent", Value: 40, TsMs: ts},
			&pb.Sample{Name: "disk_used_percent", Value: 55, Labels: map[string]string{"mount": "/"}, TsMs: ts},
			&pb.Sample{Name: "net_rx_bytes_per_sec", Value: 1000, Labels: map[string]string{"iface": "eth0"}, TsMs: ts},
			&pb.Sample{Name: "net_rx_bytes_per_sec", Value: 500, Labels: map[string]string{"iface": "eth1"}, TsMs: ts},
			&pb.Sample{Name: "net_tx_bytes_per_sec", Value: 200, Labels: map[string]string{"iface": "eth0"}, TsMs: ts})
	}
	e.a.handleAgentMessage(ctx, hostID, &pb.AgentMessage{Msg: &pb.AgentMessage_Metrics{Metrics: &pb.MetricBatch{Samples: samples}}})

	get := func(slug string) (map[string]any, string) {
		code, m, raw := e.client().do("GET", "/public/status/"+slug, nil)
		if code != 200 {
			t.Fatalf("%s: %d %s", slug, code, raw)
		}
		return m, string(raw)
	}
	item := func(m map[string]any) map[string]any { return m["items"].([]any)[0].(map[string]any) }

	// Plain page: unchanged output.
	okDo(t, admin, "POST", "/status-pages", map[string]any{"slug": "plain", "title": "Plain", "items": []map[string]any{{"type": "host", "id": hostID}}})
	m, raw := get("plain")
	if _, ok := item(m)["metrics"]; ok || m["overview"] != nil || strings.Contains(raw, "points") {
		t.Fatalf("plain page exposes metrics: %s", raw)
	}
	if m["layout"] != "list" || m["icon"] != "" || m["theme"] != "auto" {
		t.Fatalf("plain page defaults: %v %v", m["layout"], m["icon"])
	}

	// Opted in: per-host metrics, overview, wall layout and a preset icon.
	okDo(t, admin, "POST", "/status-pages", map[string]any{"slug": "wall", "title": "Wall", "layout": "wall", "icon": "preset:home", "show_overview": true, "theme": "dark",
		"items": []map[string]any{{"type": "host", "id": hostID, "metrics": []string{"network", "cpu", "disk"}}}})
	m, raw = get("wall")
	got := map[string]float64{}
	for _, x := range item(m)["metrics"].([]any) {
		pm := x.(map[string]any)
		got[pm["key"].(string)] = pm["value"].(float64)
	}
	if got["cpu"] != 11 || got["net_rx"] != 1500 || got["net_tx"] != 200 || got["disk"] != 55 {
		t.Fatalf("host metrics: %v (%s)", got, raw)
	}
	if _, ok := got["memory"]; ok {
		t.Fatalf("memory shown without being selected: %v", got)
	}
	ov := m["overview"].(map[string]any)
	charts := ov["charts"].([]any)
	if ov["hosts_total"].(float64) != 1 || len(charts) != 3 {
		t.Fatalf("overview: %v", ov)
	}
	// One line per host, named by the item's label; network is received plus sent.
	net := charts[2].(map[string]any)
	line := net["series"].([]any)[0].(map[string]any)
	pts := line["points"].([]any)
	if net["key"] != "network" || line["label"] != "agent-1" || pts[len(pts)-1].([]any)[1].(float64) != 1700 {
		t.Fatalf("network chart: %v", net)
	}
	if m["layout"] != "wall" || m["icon"] != "preset:home" || m["theme"] != "dark" {
		t.Fatalf("layout/icon: %v %v", m["layout"], m["icon"])
	}

	// Validation.
	for name, body := range map[string]map[string]any{
		"bad metric":      {"slug": "x1", "title": "x", "items": []map[string]any{{"type": "host", "id": hostID, "metrics": []string{"secrets"}}}},
		"bad layout":      {"slug": "x2", "title": "x", "layout": "grid"},
		"bad theme":       {"slug": "x7", "title": "x", "theme": "neon"},
		"bad preset":      {"slug": "x3", "title": "x", "icon": "preset:nope"},
		"bad icon":        {"slug": "x4", "title": "x", "icon": "https://example.com/i.png"},
		"script in svg":   {"slug": "x5", "title": "x", "icon": "data:image/svg+xml,<svg><script>1</script></svg>"},
		"oversized image": {"slug": "x6", "title": "x", "icon": "data:image/png;base64," + strings.Repeat("A", 800_000)},
	} {
		if code, _, raw := admin.do("POST", "/status-pages", body); code != 400 {
			t.Errorf("%s accepted: %d %s", name, code, raw)
		}
	}
	okDo(t, admin, "POST", "/status-pages", map[string]any{"slug": "img", "title": "Img", "icon": "data:image/png;base64,iVBORw0KGgo="})
}

// A tenant's page never shows another tenant's host metrics.
func TestStatusPageMetricsStayInTenant(t *testing.T) {
	e := newTestEnv(t)
	root := e.setupAdmin()
	hostID, _ := e.enrol(root) // provider host
	e.a.handleAgentMessage(context.Background(), hostID, &pb.AgentMessage{Msg: &pb.AgentMessage_Metrics{Metrics: &pb.MetricBatch{Samples: []*pb.Sample{
		{Name: "cpu_usage_percent", Value: 77, TsMs: time.Now().Add(-2 * time.Minute).UnixMilli()}}}}})
	tid := tenantUser(t, root, "Acme", "acme-admin")
	ta := e.login("acme-admin", testPassword)
	if code, _, raw := ta.do("POST", "/status-pages", map[string]any{"slug": "acme", "title": "Acme", "show_overview": true,
		"items": []map[string]any{{"type": "host", "id": hostID, "metrics": []string{"cpu"}}}}); code != 400 {
		t.Fatalf("tenant added a foreign host: %d %s", code, raw)
	}
	// Even if such an item is stored, nothing of the host is rendered.
	if _, err := e.a.db.Exec(`INSERT INTO status_pages (tenant_id, slug, title, items, show_overview, created_at, updated_at) VALUES (?,?,?,?,1,0,0)`,
		tid, "forged", "Forged", `[{"type":"host","id":`+itoa(hostID)+`,"label":"x","metrics":["cpu"]}]`); err != nil {
		t.Fatal(err)
	}
	_, m, raw := e.client().do("GET", "/public/status/forged", nil)
	if len(m["items"].([]any)) != 0 || strings.Contains(string(raw), "77") {
		t.Fatalf("foreign host leaked: %s", raw)
	}
}

// A host that is down and acknowledged as expected is not an outage.
func TestStatusPageExpectedDown(t *testing.T) {
	e := newTestEnv(t)
	admin := e.setupAdmin()
	hostID, _ := e.enrol(admin)
	okDo(t, admin, "POST", "/status-pages", map[string]any{"slug": "exp", "title": "P", "show_overview": true, "items": []map[string]any{{"type": "host", "id": hostID}}})
	if _, err := e.a.db.Exec(`UPDATE hosts SET status='down' WHERE id=?`, hostID); err != nil {
		t.Fatal(err)
	}
	state := func() (string, string, map[string]any) {
		_, m, _ := e.client().do("GET", "/public/status/exp", nil)
		return m["overall"].(string), m["items"].([]any)[0].(map[string]any)["status"].(string), m["overview"].(map[string]any)
	}
	if overall, st, _ := state(); overall != "down" || st != "down" {
		t.Fatalf("down host: overall %s, item %s", overall, st)
	}
	hid := hostID
	e.a.alerts.mu.Lock()
	e.a.alerts.active["host_down:test"] = &Alert{ID: 1, HostID: &hid, Metric: "host_down", Status: "firing", Expected: true}
	e.a.alerts.mu.Unlock()
	overall, st, ov := state()
	if overall != "operational" || st != "expected" || ov["hosts_expected"].(float64) != 1 {
		t.Fatalf("expected-down host: overall %s, item %s, overview %v", overall, st, ov)
	}
}
