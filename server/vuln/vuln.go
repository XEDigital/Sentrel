// Package vuln matches package inventories against the Grype
// vulnerability database, embedded as a library. The database lives on the
// server only; agents just send package lists.
package vuln

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype"
	v6dist "github.com/anchore/grype/grype/db/v6/distribution"
	v6inst "github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// Scanner owns the vulnerability DB.
type Scanner struct {
	dir string
	log *slog.Logger

	mu       sync.RWMutex
	provider vulnerability.Provider
	status   Status
	updating bool
}

// Status describes the DB.
type Status struct {
	Available     bool      `json:"available"`
	Built         time.Time `json:"built"`
	SchemaVersion string    `json:"schema_version"`
	Path          string    `json:"path"`
	LastCheck     time.Time `json:"last_check"`
	LastError     string    `json:"last_error,omitempty"`
	Updating      bool      `json:"updating"`
	SizeBytes     int64     `json:"size_bytes"`
}

// New creates a scanner rooted at dir.
func New(dir string, log *slog.Logger) *Scanner {
	return &Scanner{dir: dir, log: log}
}

func (s *Scanner) configs(url string) (v6dist.Config, v6inst.Config) {
	dc := v6dist.DefaultConfig()
	dc.ID = clio.Identification{Name: "sentrel"}
	if url != "" {
		dc.LatestURL = url
	}
	dc.UpdateTimeout = 30 * time.Minute
	ic := v6inst.DefaultConfig(clio.Identification{Name: "sentrel"})
	ic.DBRootDir = s.dir
	// We schedule updates ourselves and alert on staleness in the UI.
	ic.ValidateAge = false
	ic.UpdateCheckMaxFrequency = time.Minute
	return dc, ic
}

// Load opens an existing DB without network access.
func (s *Scanner) Load() error { return s.load("", false) }

// Update downloads a newer DB if one exists.
func (s *Scanner) Update(url string) error { return s.load(url, true) }

func (s *Scanner) load(url string, update bool) error {
	s.mu.Lock()
	if s.updating {
		s.mu.Unlock()
		return errors.New("an update is already running")
	}
	s.updating = update
	s.status.Updating = update
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.updating = false
		s.status.Updating = false
		s.mu.Unlock()
	}()
	if err := os.MkdirAll(s.dir, 0o750); err != nil {
		return err
	}
	dc, ic := s.configs(url)
	dc.RequireUpdateCheck = update
	prov, st, err := grype.LoadVulnerabilityDB(dc, ic, update)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.LastCheck = time.Now()
	if err != nil {
		s.status.LastError = err.Error()
		return err
	}
	old := s.provider
	s.provider = prov
	s.status.Available = true
	s.status.LastError = ""
	if st != nil {
		s.status.Built = st.Built
		s.status.SchemaVersion = st.SchemaVersion
		s.status.Path = st.Path
		if fi, err := os.Stat(st.Path); err == nil {
			s.status.SizeBytes = fi.Size()
		}
	}
	if old != nil {
		go func() {
			// Let in-flight scans (holding RLock) finish first.
			s.mu.RLock()
			s.mu.RUnlock()
			old.Close()
		}()
	}
	return nil
}

// Status returns the current DB status.
func (s *Scanner) Status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}

// Close releases the DB.
func (s *Scanner) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.provider != nil {
		s.provider.Close()
		s.provider = nil
		s.status.Available = false
	}
}

// Delete releases the DB and removes its files from disk. It refuses while an
// update is running.
func (s *Scanner) Delete() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.updating {
		return errors.New("a database update is running; try again when it finishes")
	}
	if s.provider != nil {
		s.provider.Close()
		s.provider = nil
	}
	s.status = Status{}
	return os.RemoveAll(s.dir)
}

// Package is an inventory entry.
type Package struct {
	Name    string
	Version string
	Arch    string
	Type    string // deb, rpm, apk
	Source  string // source package name (deb) or source rpm
	// SourceVersion is the source package's version (deb). Debian data is keyed
	// by source version, so a binary with its own version (libldb2 from samba)
	// must be compared by it; empty means the binary version.
	SourceVersion string
}

// Finding is one vulnerability match.
type Finding struct {
	VulnID       string   `json:"vuln_id"`
	Package      string   `json:"package"`
	Version      string   `json:"version"`
	FixedVersion string   `json:"fixed_version"`
	FixState     string   `json:"fix_state"`
	Severity     string   `json:"severity"`
	CVSS         float64  `json:"cvss"`
	Vector       string   `json:"cvss_vector"`
	EPSS         float64  `json:"epss"`
	KEV          bool     `json:"kev"`
	Description  string   `json:"description"`
	URLs         []string `json:"urls"`
	Namespace    string   `json:"namespace"`
}

// ErrUnsupported is returned for platforms Grype cannot match.
var ErrUnsupported = errors.New("unsupported platform for package vulnerability matching")

// SupportedOS reports whether an os-release ID is matchable.
func SupportedOS(id string) bool {
	switch strings.ToLower(id) {
	case "ubuntu", "debian", "rhel", "centos", "rocky", "almalinux", "ol", "amzn", "fedora", "alpine", "sles", "opensuse-leap", "mariner", "azurelinux", "wolfi", "chainguard", "photon", "raspbian":
		return true
	}
	return false
}

func pkgType(t string) syftPkg.Type {
	switch t {
	case "deb":
		return syftPkg.DebPkg
	case "rpm":
		return syftPkg.RpmPkg
	case "apk":
		return syftPkg.ApkPkg
	}
	return ""
}

// Scan matches packages for a host with the given os-release ID/VERSION_ID.
func (s *Scanner) Scan(ctx context.Context, osID, osVersion string, pkgs []Package) ([]Finding, error) {
	if !SupportedOS(osID) {
		return nil, fmt.Errorf("%w: %s", ErrUnsupported, osID)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.provider == nil {
		return nil, errors.New("vulnerability database not downloaded yet")
	}
	id := strings.ToLower(osID)
	if id == "raspbian" {
		id = "debian"
	}
	d := distro.NewFromNameVersion(id, osVersion)
	if d == nil {
		return nil, fmt.Errorf("%w: %s %s", ErrUnsupported, osID, osVersion)
	}
	gp := grypePackages(d, pkgs)
	m := grype.VulnerabilityMatcher{VulnerabilityProvider: s.provider, Matchers: matcher.NewDefaultMatchers(matcher.Config{}), NormalizeByCVE: true}
	res, _, err := m.FindMatchesContext(ctx, gp, pkg.Context{Distro: d})
	if err != nil {
		return nil, err
	}
	return s.toFindings(res.Sorted()), nil
}

// grypePackages converts inventory packages for the matcher. A package built
// from a differently named source package gets it as its upstream, with the
// source version for debs.
func grypePackages(d *distro.Distro, pkgs []Package) []pkg.Package {
	var gp []pkg.Package
	for i, p := range pkgs {
		t := pkgType(p.Type)
		if t == "" || p.Name == "" || p.Version == "" {
			continue
		}
		g := pkg.Package{ID: pkg.ID(fmt.Sprintf("p%d", i)), Name: p.Name, Version: p.Version, Type: t, Distro: d}
		if p.Source != "" && p.Source != p.Name {
			src := p.Source
			if t == syftPkg.RpmPkg {
				src = rpmSourceName(src)
			}
			if src != "" {
				up := pkg.UpstreamPackage{Name: src}
				if t == syftPkg.DebPkg {
					up.Version = p.SourceVersion
				}
				g.Upstreams = []pkg.UpstreamPackage{up}
			}
		}
		gp = append(gp, g)
	}
	return gp
}

func rpmSourceName(srpm string) string {
	// openssl-3.0.7-27.el9.src.rpm -> openssl
	s := strings.TrimSuffix(srpm, ".src.rpm")
	parts := strings.Split(s, "-")
	if len(parts) < 3 {
		return ""
	}
	return strings.Join(parts[:len(parts)-2], "-")
}

func (s *Scanner) toFindings(ms []match.Match) []Finding {
	seen := map[string]bool{}
	var out []Finding
	for _, m := range ms {
		key := m.Vulnerability.ID + "|" + m.Package.Name
		if seen[key] {
			continue
		}
		seen[key] = true
		f := Finding{VulnID: m.Vulnerability.ID, Package: m.Package.Name, Version: m.Package.Version, FixState: string(m.Vulnerability.Fix.State),
			Namespace: m.Vulnerability.Namespace, Severity: "Unknown"}
		if len(m.Vulnerability.Fix.Versions) > 0 {
			f.FixedVersion = strings.Join(m.Vulnerability.Fix.Versions, ", ")
		}
		meta, err := s.provider.VulnerabilityMetadata(vulnerability.Reference{ID: m.Vulnerability.ID, Namespace: m.Vulnerability.Namespace})
		if err == nil && meta != nil {
			f.Severity = normSeverity(meta.Severity)
			f.Description = meta.Description
			if meta.DataSource != "" {
				f.URLs = append(f.URLs, meta.DataSource)
			}
			f.URLs = append(f.URLs, meta.URLs...)
			if len(f.URLs) > 5 {
				f.URLs = f.URLs[:5]
			}
			for _, c := range meta.Cvss {
				if c.Metrics.BaseScore > f.CVSS {
					f.CVSS, f.Vector = c.Metrics.BaseScore, c.Vector
				}
			}
			for _, e := range meta.EPSS {
				if e.EPSS > f.EPSS {
					f.EPSS = e.EPSS
				}
			}
			f.KEV = len(meta.KnownExploited) > 0
		}
		// Related CVE metadata often carries CVSS when the distro record does not.
		if f.CVSS == 0 {
			for _, rv := range m.Vulnerability.RelatedVulnerabilities {
				if rm, err := s.provider.VulnerabilityMetadata(rv); err == nil && rm != nil {
					for _, c := range rm.Cvss {
						if c.Metrics.BaseScore > f.CVSS {
							f.CVSS, f.Vector = c.Metrics.BaseScore, c.Vector
						}
					}
					if f.Description == "" {
						f.Description = rm.Description
					}
					if f.Severity == "Unknown" {
						f.Severity = normSeverity(rm.Severity)
					}
				}
			}
		}
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if SeverityRank(out[i].Severity) != SeverityRank(out[j].Severity) {
			return SeverityRank(out[i].Severity) > SeverityRank(out[j].Severity)
		}
		return out[i].CVSS > out[j].CVSS
	})
	return out
}

// LookupCVE returns the NVD metadata of one CVE id (severity, CVSS, EPSS, KEV,
// description, references) from the local database. ok is false when the DB is
// not loaded or has no record for the id. Only the metadata fields of Finding
// are filled.
func (s *Scanner) LookupCVE(id string) (f Finding, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.provider == nil {
		return f, false
	}
	meta, err := s.provider.VulnerabilityMetadata(vulnerability.Reference{ID: id, Namespace: "nvd:cpe"})
	if err != nil || meta == nil {
		return f, false
	}
	f = Finding{VulnID: id, Namespace: meta.Namespace, Severity: normSeverity(meta.Severity), Description: meta.Description}
	if meta.DataSource != "" {
		f.URLs = append(f.URLs, meta.DataSource)
	}
	f.URLs = append(f.URLs, meta.URLs...)
	if len(f.URLs) > 5 {
		f.URLs = f.URLs[:5]
	}
	for _, c := range meta.Cvss {
		if c.Metrics.BaseScore > f.CVSS {
			f.CVSS, f.Vector = c.Metrics.BaseScore, c.Vector
		}
	}
	for _, e := range meta.EPSS {
		if e.EPSS > f.EPSS {
			f.EPSS = e.EPSS
		}
	}
	f.KEV = len(meta.KnownExploited) > 0
	found := f.Severity != "Unknown" || f.CVSS > 0 || f.Description != ""
	return f, found
}

func normSeverity(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "Critical"
	case "high", "important":
		return "High"
	case "medium", "moderate":
		return "Medium"
	case "low":
		return "Low"
	case "negligible":
		return "Negligible"
	}
	return "Unknown"
}

// SeverityRank orders severities.
func SeverityRank(s string) int {
	switch s {
	case "Critical":
		return 5
	case "High":
		return 4
	case "Medium":
		return 3
	case "Low":
		return 2
	case "Negligible":
		return 1
	}
	return 0
}
