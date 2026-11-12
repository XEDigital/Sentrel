package app

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"sentrel/server/metrics"
)

// Optional status page extras: live host metrics, combined overview graphs
// and a page icon. Everything here is opt-in per page or per item; a page
// that uses none of it reveals only labels and up/down state, as before.

// statusMetricKinds are the metrics a host item may show.
var statusMetricKinds = map[string]bool{"cpu": true, "memory": true, "network": true, "disk": true}

// statusIconPresets are the built-in page icons. The UI draws them; the
// server only checks the name.
var statusIconPresets = map[string]bool{
	"activity": true, "server": true, "home": true, "globe": true, "cloud": true, "shield": true, "cpu": true,
	"network": true, "monitor": true, "database": true, "zap": true, "rocket": true, "heart": true, "wifi": true,
	"hard-drive": true, "radio": true, "gamepad": true, "music": true, "lock": true, "building": true,
	"layers": true, "box": true, "terminal": true, "satellite": true,
}

const (
	statusMetricWindow = time.Hour
	statusMetricStep   = time.Minute
	statusMetricTTL    = 15 * time.Second
)

// validateStatusIcon accepts no icon, a preset or an uploaded image.
func validateStatusIcon(icon string) error {
	switch {
	case icon == "":
		return nil
	case strings.HasPrefix(icon, "preset:"):
		if !statusIconPresets[strings.TrimPrefix(icon, "preset:")] {
			return badRequest("unknown icon preset")
		}
		return nil
	case strings.HasPrefix(icon, "data:image/"):
		if len(icon) > 700_000 {
			return badRequest("the icon must be an image under 500 KB")
		}
		if l := strings.ToLower(icon); strings.Contains(l, "svg") && strings.Contains(l, "script") {
			return badRequest("SVG images must not contain scripts")
		}
		return nil
	}
	return badRequest("icon must be a preset or an uploaded image")
}

// cleanStatusMetrics returns the valid, de-duplicated metric kinds in a fixed order.
func cleanStatusMetrics(in []string) ([]string, error) {
	seen := map[string]bool{}
	for _, m := range in {
		if !statusMetricKinds[m] {
			return nil, badRequest("unknown metric %q (cpu, memory, network, disk)", m)
		}
		seen[m] = true
	}
	out := []string{}
	for _, m := range []string{"cpu", "memory", "network", "disk"} {
		if seen[m] {
			out = append(out, m)
		}
	}
	return out, nil
}

// publicMetric is one metric of a host or of the overview: the latest value
// and the last hour as [unix seconds, value] points.
type publicMetric struct {
	Key    string       `json:"key"` // cpu, memory, disk, net_rx, net_tx
	Value  float64      `json:"value"`
	Points [][2]float64 `json:"points"`
}

// publicSeries is one host's line on an overview chart.
type publicSeries struct {
	Label  string       `json:"label"`
	Points [][2]float64 `json:"points"`
}

// publicChart is one overview chart with a line per host.
type publicChart struct {
	Key    string         `json:"key"` // cpu, memory, network
	Series []publicSeries `json:"series"`
}

type publicOverview struct {
	HostsUp     int `json:"hosts_up"`
	HostsTotal  int `json:"hosts_total"`
	ChecksUp    int `json:"checks_up"`
	ChecksTotal int `json:"checks_total"`
	// Down, but acknowledged as expected: not counted as a problem.
	HostsExpected  int           `json:"hosts_expected"`
	ChecksExpected int           `json:"checks_expected"`
	Charts         []publicChart `json:"charts"`
}

// overviewHost is a host on the page with the label it is shown under.
type overviewHost struct {
	ID    int64
	Label string
}

// hostSeries maps host id -> metric key -> points.
type hostSeries map[int64]map[string][][2]float64

type statusMetricCache struct {
	mu sync.Mutex
	m  map[string]statusMetricEntry
}

type statusMetricEntry struct {
	at   time.Time
	data hostSeries
}

// statusHostSeries loads the last hour of the page's host metrics, one query
// per metric for all hosts together. Results are cached briefly because the
// page is served without authentication.
func (a *App) statusHostSeries(ctx context.Context, tenant int64, hostIDs []int64) hostSeries {
	if len(hostIDs) == 0 {
		return hostSeries{}
	}
	sort.Slice(hostIDs, func(i, j int) bool { return hostIDs[i] < hostIDs[j] })
	ids := make([]string, len(hostIDs))
	for i, id := range hostIDs {
		ids[i] = strconv.FormatInt(id, 10)
	}
	key := strconv.FormatInt(tenant, 10) + ":" + strings.Join(ids, ",")
	c := &a.statusMetrics
	c.mu.Lock()
	if e, ok := c.m[key]; ok && time.Since(e.at) < statusMetricTTL {
		c.mu.Unlock()
		return e.data
	}
	c.mu.Unlock()

	sel := fmt.Sprintf(`host_id=~"%s"`, strings.Join(ids, "|"))
	if tenant != 0 {
		sel += fmt.Sprintf(`,tenant_id="%d"`, tenant)
	}
	queries := map[string]string{
		"cpu":    fmt.Sprintf(`max by (host_id) (%scpu_usage_percent{%s})`, metrics.Prefix, sel),
		"memory": fmt.Sprintf(`max by (host_id) (%smem_used_percent{%s})`, metrics.Prefix, sel),
		"disk":   fmt.Sprintf(`max by (host_id) (%sdisk_used_percent{%s})`, metrics.Prefix, sel),
		"net_rx": fmt.Sprintf(`sum by (host_id) (%snet_rx_bytes_per_sec{%s})`, metrics.Prefix, sel),
		"net_tx": fmt.Sprintf(`sum by (host_id) (%snet_tx_bytes_per_sec{%s})`, metrics.Prefix, sel),
	}
	// Aligned to the cache lifetime, so the newest point is at most that old.
	end := time.Now().Truncate(statusMetricTTL)
	start := end.Add(-statusMetricWindow)
	out := hostSeries{}
	for k, q := range queries {
		res, err := a.ts.QueryRange(ctx, q, start, end, statusMetricStep)
		if err != nil {
			a.log.Warn("status page metrics", "metric", k, "err", err)
			continue
		}
		for _, s := range res {
			id, err := strconv.ParseInt(s.Labels["host_id"], 10, 64)
			if err != nil {
				continue
			}
			pts := make([][2]float64, 0, len(s.Points))
			for _, p := range s.Points {
				if !math.IsNaN(p[1]) && !math.IsInf(p[1], 0) {
					pts = append(pts, [2]float64{math.Round(p[0]), math.Round(p[1]*100) / 100})
				}
			}
			if len(pts) == 0 {
				continue
			}
			if out[id] == nil {
				out[id] = map[string][][2]float64{}
			}
			out[id][k] = pts
		}
	}
	c.mu.Lock()
	if c.m == nil || len(c.m) > 500 {
		c.m = map[string]statusMetricEntry{}
	}
	c.m[key] = statusMetricEntry{at: time.Now(), data: out}
	c.mu.Unlock()
	return out
}

// hostPublicMetrics picks the metrics an item asked for.
func hostPublicMetrics(s map[string][][2]float64, kinds []string) []publicMetric {
	out := []publicMetric{}
	add := func(key string) {
		if pts := s[key]; len(pts) > 0 {
			out = append(out, publicMetric{Key: key, Value: pts[len(pts)-1][1], Points: pts})
		}
	}
	for _, k := range kinds {
		switch k {
		case "cpu", "memory":
			add(k)
		case "network":
			add("net_rx")
			add("net_tx")
		case "disk":
			// A fill level: the current value is enough.
			if pts := s["disk"]; len(pts) > 0 {
				out = append(out, publicMetric{Key: "disk", Value: pts[len(pts)-1][1], Points: [][2]float64{}})
			}
		}
	}
	return out
}

// overviewCharts builds one chart per metric with a line for every host, in
// page order. Network is received plus sent.
func overviewCharts(all hostSeries, hosts []overviewHost) []publicChart {
	out := []publicChart{}
	for _, k := range []string{"cpu", "memory", "network"} {
		ch := publicChart{Key: k, Series: []publicSeries{}}
		for _, h := range hosts {
			var pts [][2]float64
			if k == "network" {
				pts = sumPoints(all[h.ID]["net_rx"], all[h.ID]["net_tx"])
			} else {
				pts = all[h.ID][k]
			}
			if len(pts) > 0 {
				ch.Series = append(ch.Series, publicSeries{Label: h.Label, Points: pts})
			}
		}
		if len(ch.Series) > 0 {
			out = append(out, ch)
		}
	}
	return out
}

// sumPoints adds two series by timestamp.
func sumPoints(a, b [][2]float64) [][2]float64 {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	sum := map[float64]float64{}
	for _, p := range a {
		sum[p[0]] += p[1]
	}
	for _, p := range b {
		sum[p[0]] += p[1]
	}
	ts := make([]float64, 0, len(sum))
	for t := range sum {
		ts = append(ts, t)
	}
	sort.Float64s(ts)
	out := make([][2]float64, len(ts))
	for i, t := range ts {
		out[i] = [2]float64{t, math.Round(sum[t]*100) / 100}
	}
	return out
}
