package app

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/prometheus/model/labels"

	"sentrel/deploy"
	"sentrel/internal/version"
	"sentrel/server/agentdist"
)

// handleEvents streams server-sent events to the browser.
func (a *App) handleEvents(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r)
	if p == nil || p.MFAPending || p.MustChangePW {
		writeError(w, unauthorized("authentication required"))
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", 500)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	ch := a.events.subscribe()
	defer a.events.unsubscribe(ch)
	fmt.Fprintf(w, "event: hello\ndata: {}\n\n")
	fl.Flush()
	ka := time.NewTicker(25 * time.Second)
	defer ka.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-a.ctx.Done():
			return
		case <-ka.C:
			fmt.Fprint(w, ": keepalive\n\n")
			fl.Flush()
		case e := <-ch:
			if e.TenantID != 0 && !p.CanTenant(e.TenantID) {
				continue
			}
			if e.TenantID == 0 && e.HostID != 0 && !p.IsProvider() {
				if !p.CanTenant(a.hostTenant(r.Context(), e.HostID)) {
					continue
				}
			}
			b, _ := json.Marshal(e)
			fmt.Fprintf(w, "data: %s\n\n", b)
			fl.Flush()
		}
	}
}

// agentBinary returns the agent build for a platform.
func (a *App) agentBinary(goos, goarch string) (*agentdist.Binary, error) {
	return agentdist.Get(a.cfg.AgentBinDir, goos, goarch)
}

func (a *App) handleAgentDownload(w http.ResponseWriter, r *http.Request) {
	b, err := a.agentBinary(chi.URLParam(r, "os"), chi.URLParam(r, "arch"))
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	f, err := b.Open()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+b.Name+`"`)
	w.Header().Set("Content-Length", strconv.FormatInt(b.Size, 10))
	w.Header().Set("X-Sentrel-Agent-Version", b.Version)
	w.Header().Set("X-Sentrel-SHA256", b.SHA256)
	io.Copy(w, f)
}

func (a *App) handleInstallScript(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch kind {
		case "sh":
			w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
			w.Write(deploy.AgentShell)
		case "ps1":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Write(deploy.AgentPowerShell)
		case "server":
			w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
			w.Write(deploy.ServerShell)
		}
	}
}

// handlePromMetrics exposes the latest value of every series in Prometheus
// text format, so an existing Prometheus/Grafana can scrape Sentrel.
func (a *App) handlePromMetrics(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r)
	if a.settings.Security().MetricsAuth && (p == nil || !p.Has(PermRead) || p.MFAPending || p.MustChangePW) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="sentrel"`)
		http.Error(w, "API key with read scope required", 401)
		return
	}
	var tenant int64
	if p != nil && p.TenantID != 0 {
		tenant = p.TenantID
	}
	type hostName struct {
		ID   int64  `db:"id"`
		Name string `db:"name"`
	}
	var names []hostName
	_ = a.db.SelectContext(r.Context(), &names, `SELECT id, name FROM hosts`)
	nameOf := map[string]string{}
	for _, n := range names {
		nameOf[itoa(n.ID)] = n.Name
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	bw := bufio.NewWriterSize(w, 64<<10)
	defer bw.Flush()
	fmt.Fprintf(bw, "# HELP sentrel_server_info Sentrel server build info\n# TYPE sentrel_server_info gauge\nsentrel_server_info{version=%q} 1\n", version.Version)
	if tenant == 0 {
		fmt.Fprintf(bw, "# TYPE sentrel_server_agents_connected gauge\nsentrel_server_agents_connected %d\n", a.hub.ConnectedCount())
	}
	firing := map[string]int{}
	for _, al := range a.alerts.Active() {
		if al.Status == "firing" && !al.Expected && (tenant == 0 || al.TenantID == tenant) {
			firing[al.Severity]++
		}
	}
	fmt.Fprint(bw, "# TYPE sentrel_alerts_firing gauge\n")
	for _, s := range []string{"warning", "critical"} {
		fmt.Fprintf(bw, "sentrel_alerts_firing{severity=%q} %d\n", s, firing[s])
	}
	seen := map[string]bool{}
	_ = a.ts.Gather(r.Context(), tenant, func(name string, lbls labels.Labels, v float64, ts int64) {
		if !seen[name] {
			seen[name] = true
			fmt.Fprintf(bw, "# TYPE %s gauge\n", name)
		}
		var parts []string
		lbls.Range(func(l labels.Label) {
			if l.Name == labels.MetricName {
				return
			}
			parts = append(parts, fmt.Sprintf("%s=%q", l.Name, l.Value))
		})
		if hn, ok := nameOf[lbls.Get("host_id")]; ok {
			parts = append(parts, fmt.Sprintf("host=%q", hn))
		}
		sort.Strings(parts)
		fmt.Fprintf(bw, "%s{%s} %v %d\n", name, strings.Join(parts, ","), v, ts)
	})
}

// handleAgentPackage serves one agent package (deb, rpm, msi) from the
// embedded manifest. Like the binary download it is public: the files are not
// secret and enrolment still needs a token.
func (a *App) handleAgentPackage(w http.ResponseWriter, r *http.Request) {
	p, f, err := agentdist.OpenPackage(a.cfg.AgentBinDir, chi.URLParam(r, "file"))
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	defer f.Close()
	ct := "application/octet-stream"
	switch p.Format {
	case "deb":
		ct = "application/vnd.debian.binary-package"
	case "rpm":
		ct = "application/x-rpm"
	case "msi":
		ct = "application/x-msi"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Disposition", `attachment; filename="`+p.File+`"`)
	w.Header().Set("Content-Length", strconv.FormatInt(p.Size, 10))
	w.Header().Set("X-Sentrel-SHA256", p.SHA256)
	io.Copy(w, f)
}
