package app

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func (e *testEnv) seedKernelHost(t *testing.T, hostID int64, running string, abis []string, metaNew string) {
	t.Helper()
	ctx := context.Background()
	hi, _ := json.Marshal(map[string]any{"os": "linux", "arch": "amd64", "kernelVersion": running})
	if _, err := e.a.db.ExecContext(ctx, `UPDATE hosts SET host_info=? WHERE id=?`, string(hi), hostID); err != nil {
		t.Fatal(err)
	}
	add := func(name, ver, newVer string) {
		if _, err := e.a.db.ExecContext(ctx, `INSERT INTO packages (tenant_id, host_id, name, version, arch, type, source, new_version) VALUES (0,?,?,?,?,?,?,?)`,
			hostID, name, ver, "amd64", "deb", "linux", newVer); err != nil {
			t.Fatal(err)
		}
	}
	for _, abi := range abis {
		add("linux-image-"+abi+"-generic", abi+".1", "")
		add("linux-modules-"+abi+"-generic", abi+".1", "")
		add("linux-headers-"+abi, abi+".1", "")
	}
	add("linux-generic", "1", metaNew)
	add("bash", "5.1-1", "5.1-3")
}

func (e *testEnv) addFinding(t *testing.T, hostID int64, vuln, pkg, fixed, sev string) {
	t.Helper()
	now := time.Now().Unix()
	if _, err := e.a.db.ExecContext(context.Background(), `INSERT INTO vuln_findings (tenant_id, host_id, vuln_id, package, version, fixed_version, severity, status, first_seen_at, last_seen_at)
		VALUES (0,?,?,?,?,?,?,'open',?,?)`, hostID, vuln, pkg, "1", fixed, sev, now, now); err != nil {
		t.Fatal(err)
	}
}

func (e *testEnv) findings(t *testing.T, admin *client, query string) map[string]VulnFinding {
	t.Helper()
	code, _, raw := admin.do("GET", "/vulnerabilities"+query, nil)
	if code != 200 {
		t.Fatalf("list: %d %s", code, raw)
	}
	var list []VulnFinding
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatal(err)
	}
	got := map[string]VulnFinding{}
	for _, f := range list {
		got[f.VulnID] = f
	}
	return got
}

func enableVuln(t *testing.T, e *testEnv) {
	t.Helper()
	if err := e.a.settings.Save(context.Background(), 0, keyVuln, VulnSettings{Enabled: true, AlertSeverity: "Critical", OnlyFixable: true}); err != nil {
		t.Fatal(err)
	}
}

func TestKernelRemediation(t *testing.T) {
	e := newTestEnv(t)
	admin := e.setupAdmin()
	enableVuln(t, e)
	ctx := context.Background()

	// Host 1 runs 7.0.0-38 (the newest); 7.0.0-28 is a leftover. A meta update is pending.
	h1, _ := e.enrol(admin)
	e.seedKernelHost(t, h1, "7.0.0-38-generic", []string{"7.0.0-28", "7.0.0-38"}, "7.0.0.39")
	e.addFinding(t, h1, "CVE-OLD", "linux-image-7.0.0-28-generic", "7.0.0-38.1", "Critical")
	e.addFinding(t, h1, "CVE-OLD", "linux-modules-7.0.0-28-generic", "7.0.0-38.1", "Critical")
	e.addFinding(t, h1, "CVE-RUN", "linux-image-7.0.0-38-generic", "7.0.0-39.1", "High")
	e.addFinding(t, h1, "CVE-BOTH", "linux-image-7.0.0-28-generic", "7.0.0-39.1", "High")
	e.addFinding(t, h1, "CVE-BOTH", "linux-image-7.0.0-38-generic", "7.0.0-39.1", "High")
	e.addFinding(t, h1, "CVE-BASH", "bash", "5.1-2", "Medium")
	e.addFinding(t, h1, "CVE-BASHWAIT", "bash", "5.1-9", "Medium")
	e.addFinding(t, h1, "CVE-BASHNONE", "bash", "", "Low")

	got := e.findings(t, admin, "")
	check := func(id, rem, abi string, inactive bool) {
		t.Helper()
		f, ok := got[id]
		if !ok {
			t.Fatalf("%s missing", id)
		}
		if f.Remediation != rem || f.KernelABI != abi || f.Inactive != inactive {
			t.Errorf("%s: remediation=%q abi=%q inactive=%v, want %q %q %v", id, f.Remediation, f.KernelABI, f.Inactive, rem, abi, inactive)
		}
	}
	check("CVE-OLD", "remove_old_kernel", "7.0.0-28", true)
	check("CVE-RUN", "upgrade_kernel", "7.0.0-38", false)
	check("CVE-BOTH", "upgrade_kernel", "7.0.0-38", false)
	check("CVE-BASH", "upgrade", "", false)
	check("CVE-BASHWAIT", "wait", "", false)
	check("CVE-BASHNONE", "none", "", false)
	if m := got["CVE-RUN"].KernelMeta; len(m) != 1 || m[0] != "linux-generic" {
		t.Errorf("meta: %v", m)
	}

	// Without a pending meta update the running kernel's fix is not in the repos.
	if _, err := e.a.db.ExecContext(ctx, `UPDATE packages SET new_version='' WHERE host_id=? AND name='linux-generic'`, h1); err != nil {
		t.Fatal(err)
	}
	got = e.findings(t, admin, "")
	check("CVE-RUN", "wait", "7.0.0-38", false)
	e.addFinding(t, h1, "CVE-NOFIX", "linux-image-7.0.0-38-generic", "", "Low")
	got = e.findings(t, admin, "")
	check("CVE-NOFIX", "none", "7.0.0-38", false)

	// Excluding inactive kernels.
	got = e.findings(t, admin, "?inactive=0")
	if _, ok := got["CVE-OLD"]; ok {
		t.Error("inactive finding listed with inactive=0")
	}
	if _, ok := got["CVE-RUN"]; !ok {
		t.Error("active finding missing with inactive=0")
	}

	// Host 2 runs the older kernel while a newer one is installed: reboot.
	h2, _ := e.enrol(admin)
	e.seedKernelHost(t, h2, "7.0.0-28-generic", []string{"7.0.0-28", "7.0.0-38"}, "")
	e.addFinding(t, h2, "CVE-R", "linux-image-7.0.0-28-generic", "7.0.0-38.1", "High")
	e.addFinding(t, h2, "CVE-N", "linux-image-7.0.0-38-generic", "7.0.0-39.1", "High")
	got = e.findings(t, admin, "?host_id="+itoa(h2))
	check("CVE-R", "reboot", "7.0.0-28", false)
	check("CVE-N", "wait", "7.0.0-38", true) // newest, not running: not exploitable yet
}

func TestHostKernelsEndpoint(t *testing.T) {
	e := newTestEnv(t)
	admin := e.setupAdmin()
	enableVuln(t, e)
	h, _ := e.enrol(admin)
	e.seedKernelHost(t, h, "7.0.0-38-generic", []string{"7.0.0-28", "7.0.0-38"}, "")
	e.addFinding(t, h, "CVE-1", "linux-image-7.0.0-28-generic", "7.0.0-38.1", "Critical")
	e.addFinding(t, h, "CVE-2", "linux-image-7.0.0-28-generic", "7.0.0-38.1", "High")
	e.addFinding(t, h, "CVE-3", "linux-image-7.0.0-28-generic", "7.0.0-38.1", "Low")
	e.addFinding(t, h, "CVE-3", "linux-image-7.0.0-38-generic", "7.0.0-38.1", "Low") // also affects the running kernel
	code, m, raw := admin.do("GET", "/hosts/"+itoa(h)+"/kernels", nil)
	if code != 200 {
		t.Fatalf("%d %s", code, raw)
	}
	if m["running"] != "7.0.0-38-generic" || m["reboot_required"] != false {
		t.Fatalf("%s", raw)
	}
	inst := m["installed"].([]any)
	if len(inst) != 2 {
		t.Fatalf("%s", raw)
	}
	n := inst[0].(map[string]any) // newest first
	o := inst[1].(map[string]any)
	if n["abi"] != "7.0.0-38" || n["running"] != true || n["newest"] != true || n["removable"] != false {
		t.Errorf("newest: %v", n)
	}
	if o["abi"] != "7.0.0-28" || o["running"] != false || o["removable"] != true || o["cve_count"].(float64) != 2 || o["critical"].(float64) != 1 || o["high"].(float64) != 1 {
		t.Errorf("old: %v", o)
	}
	pk := o["packages"].([]any)
	if len(pk) != 3 {
		t.Errorf("packages: %v", pk)
	}
	for _, p := range pk {
		if !strings.Contains(p.(string), "7.0.0-28") {
			t.Errorf("foreign package %v", p)
		}
	}
	if m["removable_cves"].(float64) != 2 {
		t.Errorf("removable_cves: %v", m["removable_cves"])
	}
	// Fleet view.
	code, _, raw = admin.do("GET", "/vulnerabilities/kernels", nil)
	var fleet []fleetKernelHost
	if code != 200 || json.Unmarshal(raw, &fleet) != nil || len(fleet) != 1 || fleet[0].HostID != h || len(fleet[0].Removable) != 1 || fleet[0].Removable[0].ABI != "7.0.0-28" || fleet[0].Resolves != 2 {
		t.Fatalf("fleet: %d %s", code, raw)
	}
	// The summary reports inactive counts next to the totals.
	_, sum, _ := admin.do("GET", "/vulnerabilities/summary", nil)
	hosts := sum["hosts"].([]any)
	var found bool
	for _, x := range hosts {
		r := x.(map[string]any)
		if int64(r["host_id"].(float64)) == h {
			found = true
			if r["inactive"].(float64) != 2 {
				t.Errorf("summary inactive: %v", r)
			}
		}
	}
	if !found {
		t.Error("host missing from summary")
	}
}

func TestFleetKernelsTenancy(t *testing.T) {
	e := newTestEnv(t)
	root := e.setupAdmin()
	enableVuln(t, e)
	h, _ := e.enrol(root)
	e.seedKernelHost(t, h, "7.0.0-38-generic", []string{"7.0.0-28", "7.0.0-38"}, "")
	tid := int64(okDo(t, root, "POST", "/tenants", map[string]any{"name": "other"})["id"].(float64))
	okDo(t, root, "POST", "/users", map[string]any{"tenant_id": tid, "username": "other-admin", "password": testPassword, "role": "tenant_admin"})
	other := e.login("other-admin", testPassword)
	code, _, raw := other.do("GET", "/vulnerabilities/kernels", nil)
	if code != 200 || strings.TrimSpace(string(raw)) != "[]" {
		t.Fatalf("other tenant sees: %d %s", code, raw)
	}
	if code, _, _ := other.do("GET", "/hosts/"+itoa(h)+"/kernels", nil); code != 404 {
		t.Fatalf("cross-tenant host kernels: %d", code)
	}
	code, _, raw = root.do("GET", "/vulnerabilities/kernels", nil)
	if code != 200 || !strings.Contains(string(raw), `"7.0.0-28"`) {
		t.Fatalf("provider: %d %s", code, raw)
	}
}

func vulnAlert(e *testEnv, hostID int64) *Alert {
	for _, al := range e.a.alerts.Active() {
		if al.Key == "vuln:"+itoa(hostID) && al.Status == "firing" {
			cp := al
			return &cp
		}
	}
	return nil
}

func TestInactiveKernelsDoNotAlert(t *testing.T) {
	e := newTestEnv(t)
	admin := e.setupAdmin()
	ctx := context.Background()
	h, _ := e.enrol(admin)
	e.seedKernelHost(t, h, "7.0.0-38-generic", []string{"7.0.0-28", "7.0.0-38"}, "")
	for i := 0; i < 3; i++ {
		e.addFinding(t, h, "CVE-OLD-"+itoa(int64(i)), "linux-image-7.0.0-28-generic", "7.0.0-38.1", "Critical")
	}
	host, _ := e.a.getHost(ctx, h)

	enableVuln(t, e)
	e.a.vuln.evaluate(ctx, host)
	if al := vulnAlert(e, h); al != nil {
		t.Fatalf("alert raised for findings in an inactive kernel: %+v", al)
	}
	// Opt in: inactive kernels count again.
	if err := e.a.settings.Save(ctx, 0, keyVuln, VulnSettings{Enabled: true, AlertSeverity: "Critical", OnlyFixable: true, AlertOnInactiveKernels: true}); err != nil {
		t.Fatal(err)
	}
	e.a.vuln.evaluate(ctx, host)
	if al := vulnAlert(e, h); al == nil || !strings.Contains(al.Title, "3 fixable") {
		t.Fatalf("expected an alert with 3 findings, got %+v", al)
	}
	// An active finding alerts even by default.
	enableVuln(t, e)
	e.addFinding(t, h, "CVE-ACTIVE", "bash", "5.1-2", "Critical")
	e.a.vuln.evaluate(ctx, host)
	if al := vulnAlert(e, h); al == nil || !strings.Contains(al.Title, "1 fixable") {
		t.Fatalf("expected an alert with 1 finding, got %+v", al)
	}
}

// With only_fixable, the alert counts what is fixable now, as the counts and
// the "Fixable now" filter do: a fix that is not in the repositories yet does
// not count, so the alert never promises a fix the UI cannot offer.
func TestVulnAlertCountsOnlyActionable(t *testing.T) {
	e := newTestEnv(t)
	admin := e.setupAdmin()
	ctx := context.Background()
	h, _ := e.enrol(admin)
	e.seedKernelHost(t, h, "7.0.0-38-generic", []string{"7.0.0-38"}, "")
	// bash has 5.1-3 pending, below these fixes: remediation wait.
	e.addFinding(t, h, "CVE-WAIT-1", "bash", "5.1-9", "Critical")
	e.addFinding(t, h, "CVE-WAIT-2", "openssl", "3.0.2-1", "Critical")
	// The running, newest kernel with no meta-package update: wait.
	e.addFinding(t, h, "CVE-WAIT-K", "linux-image-7.0.0-38-generic", "7.0.0-39.1", "Critical")
	host, _ := e.a.getHost(ctx, h)

	enableVuln(t, e)
	e.a.vuln.evaluate(ctx, host)
	if al := vulnAlert(e, h); al != nil {
		t.Fatalf("alert raised for fixes not yet available: %+v", al)
	}
	if got := e.findings(t, admin, "?host_id="+itoa(h)+"&fixable=1"); len(got) != 0 {
		t.Fatalf("fixable filter: %v", got)
	}

	// A pending update that reaches the fix makes one actionable.
	e.addFinding(t, h, "CVE-UP", "bash", "5.1-2", "Critical")
	e.a.vuln.evaluate(ctx, host)
	al := vulnAlert(e, h)
	if al == nil || !strings.Contains(al.Title, "1 fixable") || !strings.Contains(al.Message, "fixable now") {
		t.Fatalf("expected an alert with 1 fixable finding, got %+v", al)
	}
	if got := e.findings(t, admin, "?host_id="+itoa(h)+"&fixable=1"); len(got) != 1 || !got["CVE-UP"].Upgradable {
		t.Fatalf("fixable filter should list the one upgradable CVE: %v", got)
	}

	// Without only_fixable every open CVE counts.
	if err := e.a.settings.Save(ctx, 0, keyVuln, VulnSettings{Enabled: true, AlertSeverity: "Critical"}); err != nil {
		t.Fatal(err)
	}
	e.a.vuln.evaluate(ctx, host)
	if al := vulnAlert(e, h); al == nil || !strings.HasPrefix(al.Title, "4 vulnerabilities") || strings.Contains(al.Message, "fixable") {
		t.Fatalf("expected an alert with 4 findings, got %+v", al)
	}
}

func TestRemoveKernelJobValidation(t *testing.T) {
	e := newTestEnv(t)
	admin := e.setupAdmin()
	h, _ := e.enrol(admin)
	e.fakeConn(h)
	e.seedKernelHost(t, h, "7.0.0-38-generic", []string{"7.0.0-28", "7.0.0-38"}, "")
	job := func(abi string, dry, confirm bool) (int, map[string]any) {
		code, m, _ := admin.do("POST", "/jobs", map[string]any{"host_id": h, "type": "remove_kernel", "params": map[string]string{"abi": abi}, "dry_run": dry, "confirm": confirm})
		return code, m
	}
	// allow_upgrades is off: only a dry run is accepted.
	if code, _ := job("7.0.0-28", false, true); code != 403 {
		t.Fatalf("without allow_upgrades: %d", code)
	}
	if code, m := job("7.0.0-28", true, false); code != 201 || m["dry_run"] != true {
		t.Fatalf("dry run: %d %v", code, m)
	}
	okDo(t, admin, "PUT", "/hosts/"+itoa(h), map[string]any{"allow_upgrades": true})
	if code, _ := job("7.0.0-28", false, false); code != 409 {
		t.Fatalf("without confirm: %d", code)
	}
	for _, abi := range []string{"7.0.0-38", "bad;abi", "", "7.0.0-28 -y"} {
		if code, _ := job(abi, false, true); code != 400 {
			t.Errorf("abi %q: %d", abi, code)
		}
	}
	if code, m := job("7.0.0-28", false, true); code != 201 || m["status"] != "queued" {
		t.Fatalf("confirmed: %d %v", code, m)
	}
	// A read-only agent refuses the job outright, even as a dry run.
	e.setPolicy(t, h, "none")
	if code, _ := job("7.0.0-28", true, false); code != 403 {
		t.Fatalf("read-only host: %d", code)
	}
}

func TestAutoRemoveOldKernels(t *testing.T) {
	e := newTestEnv(t)
	admin := e.setupAdmin()
	ctx := context.Background()
	h, _ := e.enrol(admin)
	e.fakeConn(h)
	e.seedKernelHost(t, h, "7.0.0-38-generic", []string{"6.8.0-45", "7.0.0-28", "7.0.0-38"}, "")
	run := func() int {
		host, _ := e.a.getHost(ctx, h)
		return e.a.maybeAutoRemoveKernels(ctx, host, e.a.loadKernels(ctx, host))
	}
	jobs := func() int {
		var n int
		_ = e.a.db.GetContext(ctx, &n, `SELECT COUNT(*) FROM jobs WHERE host_id=? AND type='remove_kernel'`, h)
		return n
	}
	// Off by default.
	if run() != 0 || jobs() != 0 {
		t.Fatal("queued while disabled")
	}
	// Opted in but upgrades are not allowed.
	okDo(t, admin, "PUT", "/hosts/"+itoa(h), map[string]any{"auto_remove_old_kernels": true})
	if run() != 0 || jobs() != 0 {
		t.Fatal("queued without allow_upgrades")
	}
	// Operator and read-only hosts never get automatic jobs.
	okDo(t, admin, "PUT", "/hosts/"+itoa(h), map[string]any{"allow_upgrades": true})
	e.setPolicy(t, h, "none")
	if run() != 0 || jobs() != 0 {
		t.Fatal("queued for a read-only host")
	}
	e.setPolicy(t, h, "operator")
	if run() != 0 || jobs() != 0 {
		t.Fatal("queued for an operator host")
	}
	e.setPolicy(t, h, "server")
	// One job per removable ABI, scheduled for the maintenance window.
	if n := run(); n != 2 || jobs() != 2 {
		t.Fatalf("queued %d, jobs %d", n, jobs())
	}
	var st string
	_ = e.a.db.GetContext(ctx, &st, `SELECT DISTINCT status FROM jobs WHERE host_id=? AND type='remove_kernel'`, h)
	if st != "scheduled" {
		t.Fatalf("status %q, want scheduled (maintenance)", st)
	}
	// Rate limited to once a day.
	if run() != 0 || jobs() != 2 {
		t.Fatal("queued twice within a day")
	}
	if _, err := e.a.db.ExecContext(ctx, `UPDATE hosts SET last_auto_kernel_at=? WHERE id=?`, time.Now().Unix()-25*3600, h); err != nil {
		t.Fatal(err)
	}
	// A day later the pending jobs are not duplicated.
	if run() != 0 || jobs() != 2 {
		t.Fatalf("duplicated pending jobs: %d", jobs())
	}
}

func TestKernelStateAndMetrics(t *testing.T) {
	e := newTestEnv(t)
	admin := e.setupAdmin()
	ctx := context.Background()
	h, _ := e.enrol(admin)
	e.seedKernelHost(t, h, "7.0.0-28-generic", []string{"6.8.0-45", "7.0.0-28", "7.0.0-38"}, "")
	host, _ := e.a.getHost(ctx, h)
	k := e.a.loadKernels(ctx, host)
	if len(k.Removable) != 1 || k.Removable[0] != "6.8.0-45" || !k.RebootPending {
		t.Fatalf("%+v", k)
	}
	if _, ok := metricByKey("old_kernels"); !ok {
		t.Fatal("metric missing")
	}
	if _, ok := metricByKey("kernel_reboot_pending"); !ok {
		t.Fatal("metric missing")
	}
	for _, d := range defaultThresholds() {
		if (d.Metric == "old_kernels" || d.Metric == "kernel_reboot_pending") && d.Enabled {
			t.Errorf("%s must be disabled by default", d.Metric)
		}
	}
}
