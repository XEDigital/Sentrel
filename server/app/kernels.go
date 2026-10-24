package app

import (
	"context"
	"sort"
	"strings"

	"sentrel/internal/jobpolicy"
	"sentrel/internal/kernelpkg"
	"sentrel/server/db"
	"sentrel/server/metrics"
	"sentrel/server/vuln"
)

// Kernel remediation values reported on findings.
const (
	remUpgrade   = "upgrade"
	remWait      = "wait"
	remNone      = "none"
	remRemoveOld = "remove_old_kernel"
	remReboot    = "reboot"
	remUpgradeK  = "upgrade_kernel"
)

// kernelGroup is one installed kernel ABI.
type kernelGroup struct {
	ABI      string
	Packages []string
	Running  bool
	Newest   bool
}

// hostKernels is the kernel picture of one host, built from its package
// inventory and the kernel version its agent reported.
type hostKernels struct {
	Running       string
	Groups        map[string]*kernelGroup
	ABIs          []string // newest first
	Newest        string
	Removable     []string // oldest first; empty when the running kernel is unknown
	RebootPending bool     // the newest installed kernel is not the running one
	MetaPending   []string // kernel meta-packages with an update waiting
	MetaVersion   string
	PkgType       string // deb or rpm
}

func (k *hostKernels) isRemovable(abi string) bool {
	for _, r := range k.Removable {
		if r == abi {
			return true
		}
	}
	return false
}

func (k *hostKernels) runningABI() string {
	for _, g := range k.Groups {
		if g.Running {
			return g.ABI
		}
	}
	return ""
}

var kernelMetaPrefixes = []string{"linux-image-", "linux-headers-", "linux-modules-", "linux-tools-", "linux-cloud-tools-"}

func isKernelMeta(pkgType, name string) bool {
	if pkgType == "rpm" {
		return name == "kernel"
	}
	if kernelpkg.IsMeta(name) {
		return true
	}
	if _, ok := kernelpkg.ParseDeb(name); ok {
		return false
	}
	for _, p := range kernelMetaPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// loadKernels builds the kernel state of a Linux agent host.
func (a *App) loadKernels(ctx context.Context, h *Host) *hostKernels {
	k := &hostKernels{Groups: map[string]*kernelGroup{}}
	if h.Kind != "agent" || hostInfo(h).Os == "windows" {
		return k
	}
	k.Running = strings.TrimSpace(hostInfo(h).KernelVersion)
	var pk []struct {
		Name       string `db:"name"`
		Version    string `db:"version"`
		Type       string `db:"type"`
		NewVersion string `db:"new_version"`
	}
	_ = a.db.SelectContext(ctx, &pk, `SELECT name, version, type, new_version FROM packages WHERE host_id=? AND (name LIKE 'linux-%' OR name LIKE 'kernel%')`, h.ID)
	for _, p := range pk {
		if abi, ok := kernelpkg.Parse(p.Type, p.Name, p.Version); ok && p.Version != "-" {
			g := k.Groups[abi]
			if g == nil {
				g = &kernelGroup{ABI: abi}
				k.PkgType = p.Type
				k.Groups[abi] = g
			}
			g.Packages = append(g.Packages, p.Name)
			continue
		}
		if p.NewVersion != "" && isKernelMeta(p.Type, p.Name) {
			k.MetaPending = append(k.MetaPending, p.Name)
			if k.MetaVersion == "" {
				k.MetaVersion = p.NewVersion
			}
		}
	}
	sort.Strings(k.MetaPending)
	for abi, g := range k.Groups {
		sort.Strings(g.Packages)
		g.Running = kernelpkg.MatchesRunning(abi, k.Running)
		k.ABIs = append(k.ABIs, abi)
	}
	sort.Slice(k.ABIs, func(i, j int) bool { return kernelpkg.Compare(k.ABIs[i], k.ABIs[j]) > 0 })
	if len(k.ABIs) > 0 {
		k.Newest = k.ABIs[0]
		k.Groups[k.Newest].Newest = true
		if k.Running != "" {
			k.Removable = kernelpkg.Removable(k.ABIs, k.Running)
			k.RebootPending = !k.Groups[k.Newest].Running
		}
	}
	return k
}

// cveSummary describes one CVE on one host across its packages.
type cveSummary struct {
	VulnID    string
	Severity  string
	Fixable   bool
	KEV       bool
	NonKernel bool
	ABIs      map[string]bool
	Inactive  bool
}

// hostCVEs returns the open CVEs of a host (one entry per CVE) and whether each
// one only affects kernels that are not running.
func (a *App) hostCVEs(ctx context.Context, h *Host, k *hostKernels) []*cveSummary {
	var rows []struct {
		VulnID   string `db:"vuln_id"`
		Package  string `db:"package"`
		Version  string `db:"version"`
		Severity string `db:"severity"`
		Fixed    string `db:"fixed_version"`
		KEV      bool   `db:"kev"`
	}
	if err := a.db.SelectContext(ctx, &rows, `SELECT vuln_id, package, version, severity, fixed_version, kev FROM vuln_findings WHERE host_id=? AND status='open'`, h.ID); err != nil {
		return nil
	}
	byID := map[string]*cveSummary{}
	var order []*cveSummary
	for _, r := range rows {
		s := byID[r.VulnID]
		if s == nil {
			s = &cveSummary{VulnID: r.VulnID, ABIs: map[string]bool{}}
			byID[r.VulnID] = s
			order = append(order, s)
		}
		if s.Severity == "" || vuln.SeverityRank(r.Severity) > vuln.SeverityRank(s.Severity) {
			s.Severity = r.Severity
		}
		if r.Fixed != "" {
			s.Fixable = true
		}
		if r.KEV {
			s.KEV = true
		}
		if abi, ok := kernelpkg.Parse(k.PkgType, r.Package, r.Version); ok && len(k.Groups) > 0 {
			s.ABIs[abi] = true
		} else {
			s.NonKernel = true
		}
	}
	for _, s := range order {
		s.Inactive = k.inactive(s)
	}
	return order
}

// inactive reports whether a CVE only affects kernels that are not running.
func (k *hostKernels) inactive(s *cveSummary) bool {
	if k.Running == "" || s.NonKernel || len(s.ABIs) == 0 {
		return false
	}
	for abi := range s.ABIs {
		if kernelpkg.MatchesRunning(abi, k.Running) {
			return false
		}
	}
	return true
}

// remediate decides the remediation of a kernel-only CVE. It returns the
// remediation and the ABI the action applies to.
func (k *hostKernels) remediate(s *cveSummary, fixedKnown bool) (string, string) {
	var running, newest string
	var oldAbis []string
	for abi := range s.ABIs {
		switch {
		case kernelpkg.MatchesRunning(abi, k.Running):
			running = abi
		case abi == k.Newest:
			newest = abi
		default:
			oldAbis = append(oldAbis, abi)
		}
	}
	sort.Slice(oldAbis, func(i, j int) bool { return kernelpkg.Compare(oldAbis[i], oldAbis[j]) < 0 })
	fallback := func(abi string) (string, string) {
		if len(k.MetaPending) > 0 {
			return remUpgradeK, abi
		}
		if fixedKnown {
			return remWait, abi
		}
		return remNone, abi
	}
	switch {
	case running != "":
		if running != k.Newest && k.Newest != "" {
			return remReboot, running
		}
		return fallback(running)
	case newest != "":
		return fallback(newest)
	case len(oldAbis) > 0:
		return remRemoveOld, oldAbis[0]
	}
	return remNone, ""
}

// --- GET /hosts/{id}/kernels ---

type kernelInfo struct {
	ABI       string   `json:"abi"`
	Packages  []string `json:"packages"`
	Running   bool     `json:"running"`
	Newest    bool     `json:"newest"`
	Removable bool     `json:"removable"`
	CVECount  int      `json:"cve_count"` // CVEs that only exist in this kernel: removing it resolves them
	Critical  int      `json:"critical"`
	High      int      `json:"high"`
}

type kernelsResp struct {
	Running        string       `json:"running"`
	Installed      []kernelInfo `json:"installed"`
	RebootRequired bool         `json:"reboot_required"`
	RebootPending  bool         `json:"reboot_pending"`
	AllowUpgrades  bool         `json:"allow_upgrades"`
	WritePolicy    string       `json:"write_policy"`
	Resolves       int          `json:"removable_cves"`
	ResolvesCrit   int          `json:"removable_critical"`
}

func (a *App) kernelsFor(ctx context.Context, h *Host) kernelsResp {
	k := a.loadKernels(ctx, h)
	resp := kernelsResp{Running: k.Running, Installed: []kernelInfo{}, RebootRequired: h.RebootRequired || k.RebootPending,
		RebootPending: k.RebootPending, AllowUpgrades: h.AllowUpgrades, WritePolicy: policyOf(h)}
	var cves []*cveSummary
	if len(k.Groups) > 0 && a.vuln.Enabled() {
		cves = a.hostCVEs(ctx, h, k)
	}
	removable := map[string]bool{}
	for _, r := range k.Removable {
		removable[r] = true
	}
	resolved := map[string]*cveSummary{}
	for _, abi := range k.ABIs {
		g := k.Groups[abi]
		ki := kernelInfo{ABI: abi, Packages: g.Packages, Running: g.Running, Newest: g.Newest, Removable: removable[abi]}
		for _, s := range cves {
			if s.NonKernel || len(s.ABIs) != 1 || !s.ABIs[abi] {
				continue
			}
			ki.CVECount++
			switch s.Severity {
			case "Critical":
				ki.Critical++
			case "High":
				ki.High++
			}
		}
		resp.Installed = append(resp.Installed, ki)
	}
	for _, s := range cves {
		if s.NonKernel || len(s.ABIs) == 0 {
			continue
		}
		all := true
		for abi := range s.ABIs {
			if !removable[abi] {
				all = false
			}
		}
		if all {
			resolved[s.VulnID] = s
		}
	}
	for _, s := range resolved {
		resp.Resolves++
		if s.Severity == "Critical" {
			resp.ResolvesCrit++
		}
	}
	return resp
}

func policyOf(h *Host) string {
	if h.WritePolicy == "" {
		return jobpolicy.PolicyServer
	}
	return h.WritePolicy
}

func (a *App) apiHostKernels(c *Ctx) (any, error) {
	h, err := c.visibleHost(c.ID())
	if err != nil {
		return nil, err
	}
	return a.kernelsFor(c.ctx(), h), nil
}

// --- GET /vulnerabilities/kernels ---

type fleetRemovable struct {
	ABI      string `json:"abi"`
	CVECount int    `json:"cve_count"`
	Critical int    `json:"critical"`
}

type fleetKernelHost struct {
	HostID        int64            `json:"host_id"`
	HostName      string           `json:"host_name"`
	Running       string           `json:"running"`
	Removable     []fleetRemovable `json:"removable"`
	RebootPending bool             `json:"reboot_pending"`
	AllowUpgrades bool             `json:"allow_upgrades"`
	WritePolicy   string           `json:"write_policy"`
	Resolves      int              `json:"resolves"`
	ResolvesCrit  int              `json:"resolves_critical"`
}

func (a *App) apiFleetKernels(c *Ctx) (any, error) {
	tw, args := c.tenantWhere("h.tenant_id")
	var ids []int64
	if err := a.db.SelectContext(c.ctx(), &ids, `SELECT h.id FROM hosts h WHERE h.kind='agent' AND h.revoked=0 AND `+tw+` ORDER BY h.name`, args...); err != nil {
		return nil, err
	}
	out := []fleetKernelHost{}
	for _, id := range ids {
		h, err := a.getHost(c.ctx(), id)
		if err != nil || !c.P.CanTenant(h.TenantID) {
			continue
		}
		k := a.loadKernels(c.ctx(), h)
		if len(k.Removable) == 0 && !k.RebootPending {
			continue
		}
		r := a.kernelsFor(c.ctx(), h)
		fh := fleetKernelHost{HostID: h.ID, HostName: h.Name, Running: k.Running, Removable: []fleetRemovable{}, RebootPending: k.RebootPending,
			AllowUpgrades: h.AllowUpgrades, WritePolicy: policyOf(h), Resolves: r.Resolves, ResolvesCrit: r.ResolvesCrit}
		for _, ki := range r.Installed {
			if ki.Removable {
				fh.Removable = append(fh.Removable, fleetRemovable{ABI: ki.ABI, CVECount: ki.CVECount, Critical: ki.Critical})
			}
		}
		out = append(out, fh)
	}
	return out, nil
}

// inactiveCount counts the open CVEs of a host that only affect kernels which
// are installed but not running.
func (a *App) inactiveCount(ctx context.Context, h *Host) int {
	k := a.loadKernels(ctx, h)
	if k.Running == "" || len(k.Groups) == 0 {
		return 0
	}
	hasOther := false
	for _, g := range k.Groups {
		if !g.Running {
			hasOther = true
		}
	}
	if !hasOther {
		return 0
	}
	n := 0
	for _, s := range a.hostCVEs(ctx, h, k) {
		if s.Inactive {
			n++
		}
	}
	return n
}

// --- samples and automatic removal ---

// kernelSamples emits old_kernels_installed and kernel_reboot_pending.
func (a *App) kernelSamples(ctx context.Context, h *Host, k *hostKernels) {
	if len(k.Groups) == 0 {
		return
	}
	pending := 0.0
	if k.RebootPending {
		pending = 1
	}
	s := []metrics.Sample{
		{Name: "old_kernels_installed", Value: float64(len(k.Removable))},
		{Name: "kernel_reboot_pending", Value: pending},
	}
	_ = a.ts.Append(h.ID, h.TenantID, s)
	a.alerts.evaluateSamples(ctx, h.ID, s)
}

const autoKernelInterval = 24 * 3600

// maybeAutoRemoveKernels queues a remove_kernel job for each removable ABI at
// the host's next maintenance window. It only acts on hosts that opted in,
// allow upgrades and accept server-signed write jobs, and at most once a day.
func (a *App) maybeAutoRemoveKernels(ctx context.Context, h *Host, k *hostKernels) int {
	if !h.AutoRemoveOldKernels || !h.AllowUpgrades || h.Kind != "agent" || h.Revoked || len(k.Removable) == 0 {
		return 0
	}
	if p := policyOf(h); p != jobpolicy.PolicyServer {
		return 0
	}
	now := db.Now()
	if now-h.LastAutoKernelAt < autoKernelInterval {
		return 0
	}
	queued := 0
	for _, abi := range k.Removable {
		var n int
		_ = a.db.GetContext(ctx, &n, `SELECT COUNT(*) FROM jobs WHERE host_id=? AND type='remove_kernel' AND dry_run=0 AND status IN ('queued','scheduled','sent','running','awaiting_signature')
			AND json_extract(params,'$.abi')=?`, h.ID, abi)
		if n > 0 {
			continue
		}
		_, err := a.jobs.Create(ctx, systemPrincipal("system:auto-kernel", h.TenantID), JobRequest{HostID: h.ID, Type: "remove_kernel",
			Params: map[string]string{"abi": abi}, Confirm: true, Schedule: "maintenance"})
		if err != nil {
			a.log.Warn("auto kernel removal", "host_id", h.ID, "abi", abi, "err", err)
			continue
		}
		queued++
	}
	if queued > 0 {
		_, _ = a.db.ExecContext(ctx, `UPDATE hosts SET last_auto_kernel_at=? WHERE id=?`, now, h.ID)
		a.log.Info("old kernel removal scheduled", "host_id", h.ID, "name", h.Name, "kernels", queued)
	}
	return queued
}

// afterInventory runs kernel bookkeeping once an inventory is stored.
func (a *App) afterInventory(ctx context.Context, hostID int64) {
	h, err := a.getHost(ctx, hostID)
	if err != nil || h.Kind != "agent" {
		return
	}
	k := a.loadKernels(ctx, h)
	a.kernelSamples(ctx, h, k)
	a.maybeAutoRemoveKernels(ctx, h, k)
	if a.settings.Vuln().Enabled {
		// What is fixable now depends on the pending updates just reported.
		a.vuln.evaluate(ctx, h)
	}
}

// finishRemediation sets inactive, remediation and kernel_abi on a finding.
// s is the host's summary of the CVE (nil when the host has no kernel packages).
func finishRemediation(f *VulnFinding, k *hostKernels, s *cveSummary) {
	if k != nil && s != nil && !s.NonKernel && len(s.ABIs) > 0 {
		f.Inactive = k.inactive(s)
		f.Remediation, f.KernelABI = k.remediate(s, f.FixedVersion != "")
		if f.Remediation == remUpgradeK {
			f.KernelMeta = k.MetaPending
			if f.AvailableVersion == "" {
				f.AvailableVersion = k.MetaVersion
			}
		}
		return
	}
	switch {
	case f.Upgradable:
		f.Remediation = remUpgrade
	case f.FixedVersion != "":
		f.Remediation = remWait
	default:
		f.Remediation = remNone
	}
}
