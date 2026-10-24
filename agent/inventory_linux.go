//go:build linux

package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	pb "sentrel/gen/sentrelv1"
)

func has(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

// packageManager detects the native package manager.
func packageManager() string {
	switch {
	case has("dpkg-query") && has("apt-get"):
		return "apt"
	case has("dnf"):
		return "dnf"
	case has("yum"):
		return "yum"
	case has("zypper"):
		return "zypper"
	case has("pacman"):
		return "pacman"
	case has("apk"):
		return "apk"
	}
	return ""
}

// CollectInventory lists installed and upgradable packages. refresh runs the
// package index update through the privileged helper first.
func CollectInventory(ctx context.Context, refresh bool, priv privRunner) *pb.Inventory {
	inv := &pb.Inventory{TsMs: time.Now().UnixMilli(), PackageManager: packageManager()}
	if inv.PackageManager == "" {
		inv.Error = "no supported package manager found"
		return inv
	}
	if refresh && priv != nil {
		if out, err := priv(ctx, 10*time.Minute, "pkg-refresh"); err != nil {
			inv.Error = "package index refresh failed: " + strings.TrimSpace(lastLine(out, err))
		}
	}
	var err error
	switch inv.PackageManager {
	case "apt":
		inv.Installed, err = dpkgInstalled(ctx)
		if err == nil {
			inv.Upgradable, err = aptUpgradable(ctx)
			inv.SecurityUpdatesKnown = true
		}
	case "dnf", "yum":
		inv.Installed, err = rpmInstalled(ctx)
		if err == nil {
			inv.Upgradable, err = dnfUpgradable(ctx, inv.PackageManager)
			inv.SecurityUpdatesKnown = true
		}
	case "zypper":
		inv.Installed, err = rpmInstalled(ctx)
		if err == nil {
			inv.Upgradable, err = zypperUpgradable(ctx)
		}
	case "pacman":
		inv.Installed, err = pacmanInstalled(ctx)
		if err == nil {
			inv.Upgradable, err = pacmanUpgradable(ctx)
		}
	case "apk":
		inv.Installed, err = apkInstalled(ctx)
		if err == nil {
			inv.Upgradable, err = apkUpgradable(ctx)
		}
	}
	if err != nil {
		if inv.Error != "" {
			inv.Error += "; "
		}
		inv.Error += err.Error()
	}
	return inv
}

func lastLine(out []byte, err error) string {
	s := strings.TrimSpace(string(out))
	if i := strings.LastIndex(s, "\n"); i >= 0 {
		s = s[i+1:]
	}
	if s == "" && err != nil {
		s = err.Error()
	}
	return s
}

func dpkgInstalled(ctx context.Context) ([]*pb.Package, error) {
	out, err := runOut(ctx, 2*time.Minute, "dpkg-query", "-W", "-f", "${db:Status-Abbrev}\t${binary:Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n")
	if err != nil {
		return nil, fmt.Errorf("dpkg-query: %w", err)
	}
	return parseDpkgQuery(out), nil
}

// parseDpkgQuery parses the dpkg-query lines of dpkgInstalled. The source
// version is kept only when it differs from the binary version (libldb2
// 2:2.6.2+samba4.17.12-… is built from samba 2:4.17.12-…), because the
// vulnerability data is keyed by source package and source version.
func parseDpkgQuery(out []byte) []*pb.Package {
	var pkgs []*pb.Package
	s := bufio.NewScanner(bytes.NewReader(out))
	s.Buffer(make([]byte, 1<<20), 1<<20)
	for s.Scan() {
		f := strings.Split(s.Text(), "\t")
		if len(f) < 5 || !strings.HasPrefix(f[0], "ii") {
			continue
		}
		name := f[1]
		if i := strings.Index(name, ":"); i > 0 {
			name = name[:i]
		}
		src := f[4]
		if src == "" {
			src = name
		}
		p := &pb.Package{Name: name, Version: f[2], Arch: f[3], Source: src, Type: "deb"}
		if len(f) > 5 && f[5] != f[2] {
			p.SourceVersion = f[5]
		}
		pkgs = append(pkgs, p)
	}
	return pkgs
}

// "openssl/noble-updates,noble-security 3.0.13-0ubuntu3.4 amd64 [upgradable from: 3.0.13-0ubuntu3.1]"
var aptLine = regexp.MustCompile(`^(\S+)/(\S+)\s+(\S+)\s+(\S+)\s+\[upgradable from: ([^\]]+)\]`)

func aptUpgradable(ctx context.Context) ([]*pb.Package, error) {
	out, err := runOut(ctx, 2*time.Minute, "apt", "list", "--upgradable")
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("apt list: %w", err)
	}
	var pkgs []*pb.Package
	for _, l := range strings.Split(string(out), "\n") {
		m := aptLine.FindStringSubmatch(strings.TrimSpace(l))
		if m == nil {
			continue
		}
		pkgs = append(pkgs, &pb.Package{Name: m[1], NewVersion: m[3], Arch: m[4], Version: m[5], Type: "deb",
			Security: strings.Contains(m[2], "-security"), Source: m[2]})
	}
	return pkgs, nil
}

func rpmInstalled(ctx context.Context) ([]*pb.Package, error) {
	out, err := runOut(ctx, 2*time.Minute, "rpm", "-qa", "--qf", "%{NAME}\t%{EPOCHNUM}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n")
	if err != nil {
		return nil, fmt.Errorf("rpm -qa: %w", err)
	}
	var pkgs []*pb.Package
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Split(l, "\t")
		if len(f) < 5 || f[0] == "gpg-pubkey" {
			continue
		}
		ver := f[2]
		if f[1] != "0" && f[1] != "" {
			ver = f[1] + ":" + ver
		}
		src := f[4]
		if src == "(none)" {
			src = ""
		}
		pkgs = append(pkgs, &pb.Package{Name: f[0], Version: ver, Arch: f[3], Source: src, Type: "rpm"})
	}
	return pkgs, nil
}

func dnfUpgradable(ctx context.Context, mgr string) ([]*pb.Package, error) {
	out, err := runOut(ctx, 5*time.Minute, mgr, "-q", "--cacheonly", "check-update")
	if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 100 {
		err = nil // 100 = updates available
	}
	if err != nil {
		// Cache missing: try without --cacheonly (needs network, may be slow).
		out, err = runOut(ctx, 5*time.Minute, mgr, "-q", "check-update")
		if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 100 {
			err = nil
		}
		if err != nil {
			return nil, fmt.Errorf("%s check-update: %w", mgr, err)
		}
	}
	installed := map[string]string{}
	if inst, err := rpmInstalled(ctx); err == nil {
		for _, p := range inst {
			installed[p.Name+"."+p.Arch] = p.Version
		}
	}
	security := map[string]bool{}
	if so, err := runOut(ctx, 3*time.Minute, mgr, "-q", "--cacheonly", "updateinfo", "list", "--security"); err == nil {
		for _, l := range strings.Split(string(so), "\n") {
			f := strings.Fields(l)
			if len(f) >= 3 {
				// "RHSA-2024:1234 Important/Sec. openssl-1:3.0.7-27.el9.x86_64"
				security[nevraName(f[len(f)-1])] = true
			}
		}
	}
	var pkgs []*pb.Package
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) != 3 || strings.HasPrefix(l, " ") || strings.EqualFold(f[0], "Obsoleting") {
			continue
		}
		dot := strings.LastIndex(f[0], ".")
		if dot <= 0 {
			continue
		}
		name, arch := f[0][:dot], f[0][dot+1:]
		pkgs = append(pkgs, &pb.Package{Name: name, Arch: arch, NewVersion: f[1], Version: installed[f[0]], Source: f[2], Type: "rpm", Security: security[name]})
	}
	return pkgs, nil
}

// nevraName extracts the name from name-[epoch:]version-release.arch.
func nevraName(s string) string {
	parts := strings.Split(s, "-")
	if len(parts) < 3 {
		return s
	}
	return strings.Join(parts[:len(parts)-2], "-")
}

type zypperUpdates struct {
	Updates []struct {
		Name    string `xml:"name,attr"`
		Edition string `xml:"edition,attr"`
		Arch    string `xml:"arch,attr"`
		Kind    string `xml:"kind,attr"`
		Source  struct {
			Alias string `xml:"alias,attr"`
		} `xml:"source"`
	} `xml:"update-status>update-list>update"`
}

func zypperUpgradable(ctx context.Context) ([]*pb.Package, error) {
	out, err := runOut(ctx, 5*time.Minute, "zypper", "--non-interactive", "--no-refresh", "--xmlout", "list-updates")
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("zypper list-updates: %w", err)
	}
	var zu zypperUpdates
	if err := xml.Unmarshal(out, &zu); err != nil {
		return nil, fmt.Errorf("zypper xml: %w", err)
	}
	var pkgs []*pb.Package
	for _, u := range zu.Updates {
		if u.Kind != "" && u.Kind != "package" {
			continue
		}
		pkgs = append(pkgs, &pb.Package{Name: u.Name, NewVersion: u.Edition, Arch: u.Arch, Source: u.Source.Alias, Type: "rpm"})
	}
	return pkgs, nil
}

func pacmanInstalled(ctx context.Context) ([]*pb.Package, error) {
	out, err := runOut(ctx, time.Minute, "pacman", "-Q")
	if err != nil {
		return nil, fmt.Errorf("pacman -Q: %w", err)
	}
	var pkgs []*pb.Package
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) == 2 {
			pkgs = append(pkgs, &pb.Package{Name: f[0], Version: f[1], Type: "pacman"})
		}
	}
	return pkgs, nil
}

func pacmanUpgradable(ctx context.Context) ([]*pb.Package, error) {
	out, err := runOut(ctx, 2*time.Minute, "pacman", "-Qu")
	if err != nil && len(out) == 0 {
		return nil, nil // exit 1 = nothing to upgrade
	}
	var pkgs []*pb.Package
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l) // name old -> new
		if len(f) >= 4 && f[2] == "->" {
			pkgs = append(pkgs, &pb.Package{Name: f[0], Version: f[1], NewVersion: f[3], Type: "pacman"})
		}
	}
	return pkgs, nil
}

// "musl-1.2.4-r2 x86_64 {musl} (MIT) [installed]"
var apkLine = regexp.MustCompile(`^(\S+)-(\d\S*-r\d+)\s+(\S+)\s+\{([^}]*)\}`)

func apkInstalled(ctx context.Context) ([]*pb.Package, error) {
	out, err := runOut(ctx, time.Minute, "apk", "list", "--installed")
	if err != nil {
		return nil, fmt.Errorf("apk list: %w", err)
	}
	var pkgs []*pb.Package
	for _, l := range strings.Split(string(out), "\n") {
		if m := apkLine.FindStringSubmatch(l); m != nil {
			pkgs = append(pkgs, &pb.Package{Name: m[1], Version: m[2], Arch: m[3], Source: m[4], Type: "apk"})
		}
	}
	return pkgs, nil
}

func apkUpgradable(ctx context.Context) ([]*pb.Package, error) {
	out, err := runOut(ctx, time.Minute, "apk", "list", "--upgradable")
	if err != nil {
		return nil, nil
	}
	var pkgs []*pb.Package
	for _, l := range strings.Split(string(out), "\n") {
		// "busybox-1.36.1-r6 x86_64 {busybox} (GPL-2.0-only) [upgradable from: busybox-1.36.1-r5]"
		if m := apkLine.FindStringSubmatch(l); m != nil {
			p := &pb.Package{Name: m[1], NewVersion: m[2], Arch: m[3], Type: "apk"}
			if i := strings.Index(l, "upgradable from: "); i > 0 {
				from := strings.TrimSuffix(strings.TrimSpace(l[i+len("upgradable from: "):]), "]")
				p.Version = strings.TrimPrefix(from, m[1]+"-")
			}
			pkgs = append(pkgs, p)
		}
	}
	return pkgs, nil
}
