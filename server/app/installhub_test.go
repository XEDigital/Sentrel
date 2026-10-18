package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sentrel/deploy"
	"strings"
	"testing"
)

// writeTestPackages creates an agent directory with a manifest and two packages.
func writeTestPackages(t *testing.T) (dir string, debBody []byte) {
	t.Helper()
	dir = t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	debBody = []byte("pretend-deb-contents")
	msiBody := []byte("pretend-msi")
	sum := func(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
	files := map[string][]byte{"sentrel-agent_9.9.9_amd64.deb": debBody, "sentrel-agent-9.9.9-x64.msi": msiBody}
	for n, b := range files {
		if err := os.WriteFile(filepath.Join(dir, "pkg", n), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// A file that is not in the manifest must never be served.
	_ = os.WriteFile(filepath.Join(dir, "pkg", "secret.txt"), []byte("nope"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "VERSION"), []byte("9.9.9\n"), 0o644)
	man := []map[string]any{
		{"file": "sentrel-agent_9.9.9_amd64.deb", "os": "linux", "arch": "amd64", "format": "deb", "size": len(debBody), "sha256": sum(debBody)},
		{"file": "sentrel-agent-9.9.9-x64.msi", "os": "windows", "arch": "amd64", "format": "msi", "size": len(msiBody), "sha256": sum(msiBody)},
	}
	raw, _ := json.Marshal(man)
	if err := os.WriteFile(filepath.Join(dir, "packages.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, debBody
}

func TestInstallInfoPerTLSMode(t *testing.T) {
	e := newTestEnv(t)
	admin := e.setupAdmin()
	dir, _ := writeTestPackages(t)
	e.a.cfg.AgentBinDir = dir

	get := func() map[string]any {
		t.Helper()
		code, m, raw := admin.do("GET", "/agents/install-info", nil)
		if code != 200 {
			t.Fatalf("install-info: %d %s", code, raw)
		}
		return m
	}

	// http: no pin data.
	e.a.srv.mu.Lock()
	e.a.srv.mode = "http"
	e.a.srv.mu.Unlock()
	m := get()
	if m["tls_mode"] != "http" || m["spki_sha256"] != "" || m["ca_fingerprint"] != "" {
		t.Fatalf("http mode: %v", m)
	}
	if m["server_url"] != "http://monitor.test" || m["version"] != "9.9.9" {
		t.Fatalf("url/version: %v", m)
	}
	pk, _ := m["packages"].([]any)
	if len(pk) != 2 {
		t.Fatalf("packages: %v", m["packages"])
	}
	p0 := pk[0].(map[string]any)
	if p0["url"] != "http://monitor.test/download/agent/pkg/"+p0["file"].(string) || p0["sha256"] == "" || p0["size"].(float64) == 0 {
		t.Fatalf("package entry: %v", p0)
	}

	// acme: public certificate, so no pin.
	e.a.srv.mu.Lock()
	e.a.srv.mode = "acme"
	e.a.srv.mu.Unlock()
	if m := get(); m["tls_mode"] != "acme" || m["spki_sha256"] != "" || m["ca_fingerprint"] != "" {
		t.Fatalf("acme mode: %v", m)
	}

	// selfsigned: CA fingerprint and the SPKI of the server certificate.
	cert, err := e.a.ca.ServerCertificate([]string{"monitor.test"})
	if err != nil {
		t.Fatal(err)
	}
	e.a.srv.mu.Lock()
	e.a.srv.mode = "selfsigned"
	e.a.srv.mu.Unlock()
	m = get()
	want := e.a.ca.ServerSPKI()
	if m["tls_mode"] != "selfsigned" || m["spki_sha256"] != want || want == "" || !strings.HasPrefix(m["ca_fingerprint"].(string), "sha256:") {
		t.Fatalf("selfsigned mode: %v", m)
	}
	// The Agents page builds the Windows command from this; it must be the
	// compiled check, never a script block.
	if pc, _ := m["ps_pin_check"].(string); pc != psPinCallback || !strings.Contains(pc, "Add-Type -TypeDefinition") || strings.Contains(pc, "ServerCertificateValidationCallback={") {
		t.Fatalf("install-info ps_pin_check: %q", m["ps_pin_check"])
	}
	_ = cert

	// The generated one-liners pin the certificate and never use --insecure-download.
	cmds, _, spki := e.a.installCommands("https://monitor.test", "ABCD-EFGH-JKLM")
	if spki != want || !strings.Contains(cmds["linux"], `--pinnedpubkey "sha256//`+want+`"`) ||
		!strings.Contains(cmds["linux"], "--pin-sha256 "+want) || strings.Contains(cmds["linux"], "insecure") ||
		!strings.Contains(cmds["windows"], "-PinSha256 "+want) || strings.Contains(strings.ToLower(cmds["windows"]), "insecure") ||
		strings.Contains(cmds["windows"], "{$true}") {
		t.Fatalf("selfsigned commands: %v", cmds)
	}
	// The Windows pin check is compiled C#, never a PowerShell script block:
	// .NET may run the callback on a thread with no runspace, which fails when
	// the command runs unattended (as SYSTEM).
	win := cmds["windows"]
	if strings.Contains(win, "ServerCertificateValidationCallback={") || strings.Contains(win, "param($s") ||
		!strings.Contains(win, "Add-Type -TypeDefinition") || !strings.Contains(win, "[SentrelPin]::On()") ||
		!strings.Contains(win, "$p='"+want+"'") || !strings.Contains(win, "-as [type]") {
		t.Fatalf("windows command does not use the compiled pin check: %s", win)
	}

	// Needs the hosts permission: unauthenticated callers are refused.
	if code, _, _ := e.client().do("GET", "/agents/install-info", nil); code != 401 {
		t.Fatalf("anonymous install-info: %d", code)
	}
}

func TestAgentPackageDownload(t *testing.T) {
	e := newTestEnv(t)
	dir, deb := writeTestPackages(t)
	e.a.cfg.AgentBinDir = dir
	get := func(path string) (*http.Response, []byte) {
		t.Helper()
		resp, err := http.Get(e.srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, b
	}
	resp, body := get("/download/agent/pkg/sentrel-agent_9.9.9_amd64.deb")
	if resp.StatusCode != 200 || string(body) != string(deb) {
		t.Fatalf("deb download: %d %q", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/vnd.debian.binary-package" {
		t.Fatalf("content type %q", ct)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, `filename="sentrel-agent_9.9.9_amd64.deb"`) {
		t.Fatalf("content disposition %q", cd)
	}
	if resp, _ := get("/download/agent/pkg/sentrel-agent-9.9.9-x64.msi"); resp.Header.Get("Content-Type") != "application/x-msi" {
		t.Fatalf("msi content type %q", resp.Header.Get("Content-Type"))
	}
	for _, bad := range []string{
		"/download/agent/pkg/secret.txt",             // present on disk, not in the manifest
		"/download/agent/pkg/nope.deb",               // unknown
		"/download/agent/pkg/packages.json",          // the manifest itself
		"/download/agent/pkg/..%2f..%2fVERSION",      // encoded traversal
		"/download/agent/pkg/%2e%2e%2fVERSION",       // encoded traversal
		"/download/agent/pkg/..%5csentrel-agent.deb", // backslash
		"/download/agent/pkg/.hidden",
	} {
		if resp, body := get(bad); resp.StatusCode != 404 {
			t.Errorf("%s: %d %q", bad, resp.StatusCode, body)
		}
	}
	// The path-traversal form that reaches the router unescaped never serves files either.
	if _, body := get("/download/agent/pkg/../../VERSION"); strings.Contains(string(body), "9.9.9") {
		t.Error("traversal served a file")
	}
}

func TestPushInstallRoutesRemoved(t *testing.T) {
	e := newTestEnv(t)
	admin := e.setupAdmin()
	for _, r := range [][2]string{
		{"GET", "/push"}, {"GET", "/push/1"}, {"POST", "/push/ssh"}, {"POST", "/push/winrm"}, {"POST", "/push/ssh/fingerprint"},
	} {
		if code, _, _ := admin.do(r[0], r[1], map[string]any{}); code != 404 {
			t.Errorf("%s %s: %d, want 404", r[0], r[1], code)
		}
	}
	var n int
	_ = e.a.db.Get(&n, `SELECT COUNT(*) FROM sqlite_master WHERE name='push_installs'`)
	if n != 0 {
		t.Fatal("push_installs table still exists after migrations")
	}
}

// The generated Windows command and install-agent.ps1 must define the same
// SentrelPin class: whichever runs first in a PowerShell session is the one
// used, because the second is skipped by the -as [type] guard.
func TestWindowsPinClassMatchesInstaller(t *testing.T) {
	ps := string(deploy.AgentPowerShell)
	if !strings.Contains(ps, "Add-Type -TypeDefinition '"+psPinType+"'") {
		t.Fatal("install-agent.ps1 does not define the same SentrelPin class as the generated command")
	}
	if strings.Contains(ps, "ServerCertificateValidationCallback = $") || strings.Contains(ps, "param($s, $c, $ch, $e)") {
		t.Fatal("install-agent.ps1 uses a script block as a certificate callback")
	}
}
