package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"sentrel/server/db"
)

// Acknowledging is the one action on an alert. A plain acknowledgement
// survives a quick clear-and-return without a new notification; marked as
// expected, the alert leaves the active list and never notifies, until undone.
func TestAcknowledgeAndExpected(t *testing.T) {
	e := newTestEnv(t)
	admin := e.setupAdmin()
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer hook.Close()
	if code, _, raw := admin.do("POST", "/notification-channels", map[string]any{"name": "hook", "type": "webhook", "config": map[string]any{"url": hook.URL}}); code != 201 {
		t.Fatalf("channel: %d %s", code, raw)
	}
	// Keep queued messages in the queue so the test can inspect them.
	admin.do("PUT", "/settings/alerting", map[string]any{"group_wait_seconds": 3600, "flap_threshold": 50, "flap_window_minutes": 30, "resolve_count": 1, "default_repeat_minutes": 240})
	ctx := context.Background()

	const key = "system:ack-test"
	set := func(sev string) {
		e.a.alerts.apply(ctx, condition{Key: key, Source: "system", Severity: sev, Title: "thing", Message: "thing is broken", ForCount: 1})
	}
	events := func() []string {
		e.a.notifier.mu.Lock()
		defer e.a.notifier.mu.Unlock()
		var out []string
		for _, q := range e.a.notifier.queue {
			for _, n := range q {
				out = append(out, n.event)
			}
		}
		e.a.notifier.queue = map[int64][]queuedNote{}
		return out
	}
	one := func(want string) {
		t.Helper()
		if got := events(); len(got) != 1 || got[0] != want {
			t.Fatalf("queued notifications = %v, want [%s]", got, want)
		}
	}
	none := func(when string) {
		t.Helper()
		if got := events(); len(got) != 0 {
			t.Fatalf("%s: unexpected notifications %v", when, got)
		}
	}
	list := func(status string) []Alert {
		t.Helper()
		code, _, raw := admin.do("GET", "/alerts?status="+status, nil)
		if code != 200 {
			t.Fatalf("list %s: %d %s", status, code, raw)
		}
		var out []Alert
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	set("critical")
	one("fired")
	id := list("active")[0].ID
	path := "/alerts/" + itoa(id)

	// There is no manual resolve: an alert clears when its condition does.
	if code, _, _ := admin.do("POST", path+"/resolve", nil); code == 200 || code == 204 {
		t.Fatalf("manual resolve still accepted: %d", code)
	}

	// Plain acknowledgement: a quick clear and return keeps it, silently.
	if code, m, raw := admin.do("POST", path+"/ack", map[string]any{"comment": "on it"}); code != 200 || m["acked_by"] == "" || m["expected"] != false {
		t.Fatalf("ack: %d %s", code, raw)
	}
	set("ok")
	one("resolved")
	set("critical")
	none("return of an acknowledged alert")
	if al := list("active"); len(al) != 1 || al[0].AckedBy == "" || al[0].AckComment != "on it" {
		t.Fatalf("acknowledgement did not carry over: %+v", al)
	}

	// Cleared for longer than the flap window, it is a fresh alert.
	set("ok")
	events()
	if _, err := e.a.db.Exec(`UPDATE alerts SET resolved_at=? WHERE id=?`, db.Now()-31*60, id); err != nil {
		t.Fatal(err)
	}
	set("critical")
	one("fired")
	if al := list("active"); len(al) != 1 || al[0].AckedBy != "" {
		t.Fatalf("stale acknowledgement kept: %+v", al)
	}

	// Expected: out of the active list and the dashboard, no notifications.
	if code, m, raw := admin.do("POST", path+"/ack", map[string]any{"comment": "only on when needed", "expected": true}); code != 200 || m["expected"] != true {
		t.Fatalf("ack expected: %d %s", code, raw)
	}
	if al := list("active"); len(al) != 0 {
		t.Fatalf("expected alert still listed as active: %+v", al)
	}
	if al := list("expected"); len(al) != 1 || al[0].Status != "firing" {
		t.Fatalf("expected list: %+v", al)
	}
	_, dash, _ := admin.do("GET", "/dashboard", nil)
	if counts := dash["alerts"].(map[string]any); counts["critical"] != float64(0) || counts["acked"] != float64(0) || counts["expected"] != float64(1) || len(dash["firing_alerts"].([]any)) != 0 {
		t.Fatalf("dashboard: %v / %v", counts, dash["firing_alerts"])
	}
	for i := 0; i < 2; i++ {
		set("ok")
		if _, err := e.a.db.Exec(`UPDATE alerts SET resolved_at=? WHERE id=?`, db.Now()-24*3600, id); err != nil {
			t.Fatal(err)
		}
		if al := list("expected"); len(al) != 1 || al[0].Status != "resolved" {
			t.Fatalf("expected list while clear: %+v", al)
		}
		set("critical")
	}
	none("expected alert coming and going")
	if al := list("expected"); len(al) != 1 || al[0].AckComment != "only on when needed" || len(list("active")) != 0 {
		t.Fatalf("expected mark lost: %+v", al)
	}
	// Housekeeping keeps a resolved row that carries the mark.
	set("ok")
	if _, err := e.a.db.Exec(`UPDATE alerts SET resolved_at=1 WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	e.a.cleanup(ctx)
	if al := list("expected"); len(al) != 1 {
		t.Fatal("housekeeping removed an alert marked as expected")
	}

	// Undo works while it is clear, and the next fire is an ordinary alert.
	events()
	if code, _, raw := admin.do("POST", path+"/unack", nil); code != 200 && code != 204 {
		t.Fatalf("unack: %d %s", code, raw)
	}
	if al := list("expected"); len(al) != 0 {
		t.Fatalf("still expected: %+v", al)
	}
	set("critical")
	one("fired")
	if al := list("active"); len(al) != 1 || al[0].Expected || al[0].AckedBy != "" {
		t.Fatalf("after undo: %+v", al)
	}
}
