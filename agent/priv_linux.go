//go:build linux

package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	pb "sentrel/gen/sentrelv1"
)

// installedBinary is a variable only so tests can point it elsewhere.
var installedBinary = "/usr/local/bin/sentrel-agent"

// newPrivRunner returns a runner that invokes this binary's `priv` verbs
// through sudo (or directly when already root).
func newPrivRunner() (privRunner, privStreamer) {
	stream := func(ctx context.Context, timeout time.Duration, w io.Writer, verb string, args ...string) error {
		self, err := os.Executable()
		if err != nil {
			return err
		}
		cctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		full := append([]string{"priv", verb}, args...)
		var cmd *exec.Cmd
		if os.Geteuid() == 0 {
			cmd = exec.CommandContext(cctx, self, full...)
		} else {
			cmd = exec.CommandContext(cctx, "sudo", append([]string{"-n", self}, full...)...)
		}
		cmd.Stdout = w
		cmd.Stderr = w
		cmd.Env = append(os.Environ(), "LANG=C", "LC_ALL=C")
		err = cmd.Run()
		if cctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("timed out after %s", timeout)
		}
		return err
	}
	run := func(ctx context.Context, timeout time.Duration, verb string, args ...string) ([]byte, error) {
		var b bytes.Buffer
		err := stream(ctx, timeout, &b, verb, args...)
		return b.Bytes(), err
	}
	return run, stream
}

// PrivMain implements `sentrel-agent priv <verb> ...`. It runs as root and
// trusts nothing from its caller beyond validated arguments.
func PrivMain(args []string) error {
	if os.Geteuid() != 0 {
		return errors.New("priv must run as root (via sudo)")
	}
	if len(args) == 0 {
		return errors.New("usage: sentrel-agent priv <verb> [args]")
	}
	verb, rest := args[0], args[1:]
	ctx := context.Background()
	w := os.Stdout
	switch verb {
	case "pkg-refresh":
		return pkgRefresh(ctx, w)
	case "pkg-upgrade":
		o, err := parseUpgradeArgs(rest)
		if err != nil {
			return err
		}
		return pkgUpgrade(ctx, w, o)
	case "block-ip":
		if len(rest) != 2 {
			return errors.New("usage: block-ip IP MINUTES")
		}
		ip, err := validIP(rest[0])
		if err != nil {
			return err
		}
		min, err := validMinutes(rest[1])
		if err != nil {
			return err
		}
		return blockIP(ctx, w, ip, min)
	case "unblock-ip":
		if len(rest) != 1 {
			return errors.New("usage: unblock-ip IP")
		}
		ip, err := validIP(rest[0])
		if err != nil {
			return err
		}
		return unblockIP(ctx, w, ip)
	case "list-blocks":
		blocks, err := listBlocks(ctx)
		if err != nil {
			return err
		}
		return json.NewEncoder(w).Encode(blocks)
	case "scan-sync":
		return privScanSync(ctx, w, rest)
	case "scan-list":
		if len(rest) != 0 {
			return errors.New("usage: scan-list")
		}
		return privScanList(ctx, w)
	case "scan-off":
		return privScanOff(ctx, w)
	case "fail2ban-status":
		f := fail2banStatus(ctx)
		b, _ := protojson.Marshal(f)
		_, err := w.Write(b)
		return err
	case "smart":
		return privSmart(ctx, w, rest)
	case "remove-kernel":
		return privRemoveKernel(ctx, w, rest)
	case "disk-usage":
		return privDiskUsage(ctx, w, rest)
	case "disk-cleanup":
		return privDiskCleanup(ctx, w, rest)
	case "install-update":
		if len(rest) != 4 {
			return errors.New("usage: install-update PATH SHA256 VERSION SIGNATURE")
		}
		return installUpdate(rest[0], rest[1], rest[2], rest[3])
	case "rollback-update":
		return rollbackUpdate()
	case "confirm-update":
		return confirmUpdate()
	}
	return fmt.Errorf("unknown priv verb %q", verb)
}

// runLogged runs a command streaming output, inside its own systemd scope
// when possible so it is not limited by (or killed with) the agent's cgroup.
func runLogged(ctx context.Context, w io.Writer, env []string, name string, args ...string) error {
	full := append([]string{name}, args...)
	if p, err := exec.LookPath("systemd-run"); err == nil && isSystemd() {
		unit := fmt.Sprintf("sentrel-job-%d", time.Now().UnixNano()%1e9)
		full = append([]string{p, "--scope", "--quiet", "--collect", "--unit", unit}, full...)
	}
	fmt.Fprintf(w, "$ %s\n", strings.Join(append([]string{name}, args...), " "))
	cmd := exec.CommandContext(ctx, full[0], full[1:]...)
	cmd.Env = append(append(os.Environ(), "LANG=C", "LC_ALL=C"), env...)
	cmd.Stdout = w
	cmd.Stderr = w
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd.Run()
}

func isSystemd() bool {
	b, err := os.ReadFile("/proc/1/comm")
	return err == nil && strings.TrimSpace(string(b)) == "systemd"
}

func pkgRefresh(ctx context.Context, w io.Writer) error {
	switch packageManager() {
	case "apt":
		return runLogged(ctx, w, nil, "apt-get", "update", "-q")
	case "dnf":
		return runLogged(ctx, w, nil, "dnf", "-q", "makecache")
	case "yum":
		return runLogged(ctx, w, nil, "yum", "-q", "makecache")
	case "zypper":
		return runLogged(ctx, w, nil, "zypper", "--non-interactive", "refresh")
	case "pacman":
		return runLogged(ctx, w, nil, "pacman", "-Sy", "--noconfirm")
	case "apk":
		return runLogged(ctx, w, nil, "apk", "update")
	}
	return errors.New("no supported package manager")
}

func pkgUpgrade(ctx context.Context, w io.Writer, o UpgradeOptions) error {
	mgr := packageManager()
	switch mgr {
	case "apt":
		if err := runLogged(ctx, w, nil, "apt-get", "update", "-q"); err != nil {
			fmt.Fprintln(w, "warning: apt-get update failed:", err)
		}
		env := []string{"DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=a", "APT_LISTCHANGES_FRONTEND=none"}
		base := []string{"-q", "-y", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"}
		if o.DryRun {
			base = append(base, "-s")
		}
		if len(o.Packages) > 0 {
			return runLogged(ctx, w, env, "apt-get", append(append(base, "install", "--only-upgrade"), o.Packages...)...)
		}
		return runLogged(ctx, w, env, "apt-get", append(base, "upgrade", "--with-new-pkgs")...)
	case "dnf", "yum":
		a := []string{"-y", "upgrade"}
		if o.DryRun {
			a = []string{"upgrade", "--assumeno"}
		}
		if o.SecurityOnly {
			a = append(a, "--security")
		}
		a = append(a, o.Packages...)
		err := runLogged(ctx, w, nil, mgr, a...)
		if o.DryRun {
			var ee *exec.ExitError
			if errors.As(err, &ee) && ee.ExitCode() == 1 {
				return nil // --assumeno exits 1 when it would have made changes
			}
		}
		return err
	case "zypper":
		var a []string
		if o.SecurityOnly && len(o.Packages) == 0 {
			a = []string{"--non-interactive", "patch", "--category", "security"}
		} else {
			a = append([]string{"--non-interactive", "update"}, o.Packages...)
		}
		if o.DryRun {
			a = append(a, "--dry-run")
		}
		return runLogged(ctx, w, nil, "zypper", a...)
	case "pacman":
		if o.DryRun {
			return runLogged(ctx, w, nil, "pacman", "-Qu")
		}
		if len(o.Packages) > 0 {
			return runLogged(ctx, w, nil, "pacman", append([]string{"-S", "--noconfirm", "--needed"}, o.Packages...)...)
		}
		return runLogged(ctx, w, nil, "pacman", "-Syu", "--noconfirm")
	case "apk":
		a := []string{"upgrade"}
		if o.DryRun {
			a = append(a, "--simulate")
		}
		return runLogged(ctx, w, nil, "apk", append(a, o.Packages...)...)
	}
	return errors.New("no supported package manager")
}

// --- firewall ---

// BlockEntry describes an active block.
type BlockEntry struct {
	IP      string `json:"ip"`
	Expires int64  `json:"expires"`
	Backend string `json:"backend"`
}

const nftSetup = `table inet sentrel {
	set blocklist4 { type ipv4_addr; flags timeout; }
	set blocklist6 { type ipv6_addr; flags timeout; }
	chain input {
		type filter hook input priority -10; policy accept;
		ip saddr @blocklist4 drop
		ip6 saddr @blocklist6 drop
	}
}
`

func hasNft() bool { _, err := exec.LookPath("nft"); return err == nil }

func ensureNft(ctx context.Context) error {
	if exec.CommandContext(ctx, "nft", "list", "table", "inet", "sentrel").Run() == nil {
		return nil
	}
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(nftSetup)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft setup: %v: %s", err, out)
	}
	return nil
}

func setFor(ip string) (string, string) {
	if strings.Contains(ip, ":") {
		return "blocklist6", "ip6tables"
	}
	return "blocklist4", "iptables"
}

func blockIP(ctx context.Context, w io.Writer, ip string, minutes int) error {
	set, ipt := setFor(ip)
	if hasNft() {
		if err := ensureNft(ctx); err != nil {
			return err
		}
		_ = exec.CommandContext(ctx, "nft", "delete", "element", "inet", "sentrel", set, "{", ip, "}").Run()
		out, err := exec.CommandContext(ctx, "nft", "add", "element", "inet", "sentrel", set, "{", ip, "timeout", strconv.Itoa(minutes)+"m", "}").CombinedOutput()
		if err != nil {
			return fmt.Errorf("nft: %v: %s", err, out)
		}
		fmt.Fprintf(w, "blocked %s for %d minutes (nftables)\n", ip, minutes)
		return nil
	}
	if _, err := exec.LookPath(ipt); err != nil {
		return errors.New("neither nftables nor iptables is available")
	}
	_ = removeIptables(ctx, ipt, ip)
	exp := time.Now().Add(time.Duration(minutes) * time.Minute).Unix()
	out, err := exec.CommandContext(ctx, ipt, "-I", "INPUT", "-s", ip, "-j", "DROP", "-m", "comment", "--comment", fmt.Sprintf("sentrel-block:%d", exp)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v: %s", ipt, err, out)
	}
	fmt.Fprintf(w, "blocked %s for %d minutes (%s)\n", ip, minutes, ipt)
	return nil
}

func unblockIP(ctx context.Context, w io.Writer, ip string) error {
	set, ipt := setFor(ip)
	if hasNft() {
		out, err := exec.CommandContext(ctx, "nft", "delete", "element", "inet", "sentrel", set, "{", ip, "}").CombinedOutput()
		if err != nil && !strings.Contains(string(out), "No such file") && !strings.Contains(string(out), "does not exist") {
			return fmt.Errorf("nft: %v: %s", err, out)
		}
		fmt.Fprintf(w, "unblocked %s\n", ip)
		return nil
	}
	if err := removeIptables(ctx, ipt, ip); err != nil {
		return err
	}
	fmt.Fprintf(w, "unblocked %s\n", ip)
	return nil
}

var iptRule = regexp.MustCompile(`^-A INPUT -s (\S+?)(?:/\d+)? .*sentrel-block:(\d+)`)

func iptablesRules(ctx context.Context, ipt string) ([]string, error) {
	out, err := exec.CommandContext(ctx, ipt, "-S", "INPUT").Output()
	if err != nil {
		return nil, err
	}
	var rules []string
	for _, l := range strings.Split(string(out), "\n") {
		if strings.Contains(l, "sentrel-block:") {
			rules = append(rules, l)
		}
	}
	return rules, nil
}

func removeIptables(ctx context.Context, ipt, ip string) error {
	rules, err := iptablesRules(ctx, ipt)
	if err != nil {
		return err
	}
	for _, r := range rules {
		if m := iptRule.FindStringSubmatch(r); m != nil && m[1] == ip {
			spec := strings.Fields(strings.Replace(r, "-A INPUT", "-D INPUT", 1))
			if out, err := exec.CommandContext(ctx, ipt, spec...).CombinedOutput(); err != nil {
				return fmt.Errorf("%s: %v: %s", ipt, err, out)
			}
		}
	}
	return nil
}

func listBlocks(ctx context.Context) ([]BlockEntry, error) {
	var out []BlockEntry
	if hasNft() {
		for _, set := range []string{"blocklist4", "blocklist6"} {
			b, err := exec.CommandContext(ctx, "nft", "-j", "list", "set", "inet", "sentrel", set).Output()
			if err != nil {
				continue
			}
			var doc struct {
				Nftables []map[string]json.RawMessage `json:"nftables"`
			}
			if json.Unmarshal(b, &doc) != nil {
				continue
			}
			for _, item := range doc.Nftables {
				raw, ok := item["set"]
				if !ok {
					continue
				}
				var s struct {
					Elem []json.RawMessage `json:"elem"`
				}
				_ = json.Unmarshal(raw, &s)
				for _, e := range s.Elem {
					var plain string
					if json.Unmarshal(e, &plain) == nil {
						out = append(out, BlockEntry{IP: plain, Backend: "nftables"})
						continue
					}
					var obj struct {
						Elem struct {
							Val     string `json:"val"`
							Expires int64  `json:"expires"`
						} `json:"elem"`
					}
					if json.Unmarshal(e, &obj) == nil && obj.Elem.Val != "" {
						out = append(out, BlockEntry{IP: obj.Elem.Val, Expires: time.Now().Unix() + obj.Elem.Expires, Backend: "nftables"})
					}
				}
			}
		}
		return out, nil
	}
	now := time.Now().Unix()
	for _, ipt := range []string{"iptables", "ip6tables"} {
		if _, err := exec.LookPath(ipt); err != nil {
			continue
		}
		rules, _ := iptablesRules(ctx, ipt)
		for _, r := range rules {
			m := iptRule.FindStringSubmatch(r)
			if m == nil {
				continue
			}
			exp, _ := strconv.ParseInt(m[2], 10, 64)
			if exp > 0 && exp < now {
				_ = removeIptables(ctx, ipt, m[1]) // expired
				continue
			}
			out = append(out, BlockEntry{IP: m[1], Expires: exp, Backend: ipt})
		}
	}
	return out, nil
}

// --- fail2ban ---

func fail2banStatus(ctx context.Context) *pb.Fail2Ban {
	f := &pb.Fail2Ban{}
	if _, err := exec.LookPath("fail2ban-client"); err != nil {
		return f
	}
	out, err := exec.CommandContext(ctx, "fail2ban-client", "status").CombinedOutput()
	if err != nil {
		f.Error = strings.TrimSpace(string(out))
		return f
	}
	f.Available = true
	var jails []string
	for _, l := range strings.Split(string(out), "\n") {
		if i := strings.Index(l, "Jail list:"); i >= 0 {
			for _, j := range strings.Split(l[i+len("Jail list:"):], ",") {
				if j = strings.TrimSpace(j); j != "" {
					jails = append(jails, j)
				}
			}
		}
	}
	for _, j := range jails {
		jo, err := exec.CommandContext(ctx, "fail2ban-client", "status", j).CombinedOutput()
		if err != nil {
			continue
		}
		jail := &pb.Fail2BanJail{Name: j}
		s := bufio.NewScanner(bytes.NewReader(jo))
		for s.Scan() {
			l := s.Text()
			_, v, ok := strings.Cut(l, ":")
			if !ok {
				continue
			}
			v = strings.TrimSpace(v)
			n, err := strconv.ParseUint(v, 10, 32)
			if err != nil {
				n = 0
			}
			switch {
			case strings.Contains(l, "Currently failed"):
				jail.CurrentlyFailed = uint32(n)
			case strings.Contains(l, "Total failed"):
				jail.TotalFailed = uint32(n)
			case strings.Contains(l, "Currently banned"):
				jail.CurrentlyBanned = uint32(n)
			case strings.Contains(l, "Total banned"):
				jail.TotalBanned = uint32(n)
			case strings.Contains(l, "Banned IP list"):
				for _, ip := range strings.Fields(v) {
					if len(jail.BannedIps) < 200 {
						jail.BannedIps = append(jail.BannedIps, ip)
					}
				}
			}
		}
		f.Jails = append(f.Jails, jail)
	}
	return f
}

// --- self-update (root side) ---

var (
	// privDir is a root-only directory (0700) holding the update lock and the
	// protected pending-update marker. The agent user cannot read or write it.
	privDir = "/var/lib/sentrel-agent-priv"
	// privOwnerUID is the uid that must own privDir and the staging directory.
	privOwnerUID = 0
	// lockWait bounds how long a verb waits for another update/rollback.
	lockWait = 2 * time.Minute
)

const (
	maxUpdateSize = 256 << 20
	stagePrefix   = ".sentrel-agent.new."
)

func rootMarkerPath() string { return filepath.Join(privDir, "update-pending.json") }

// checkDirTrusted verifies dir is owned by privOwnerUID and not writable by
// anyone else (strict: not accessible to group/other at all). follow resolves
// a final symlink; privDir itself must never be one.
func checkDirTrusted(dir string, strict, follow bool) error {
	stat := os.Lstat
	if follow {
		stat = os.Stat
	}
	fi, err := stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != privOwnerUID {
		return fmt.Errorf("%s must be owned by root", dir)
	}
	mask := os.FileMode(0o022)
	if strict {
		mask = 0o077
	}
	if fi.Mode().Perm()&mask != 0 {
		return fmt.Errorf("%s has unsafe permissions %o", dir, fi.Mode().Perm())
	}
	return nil
}

func ensurePrivDir() error {
	if err := os.MkdirAll(privDir, 0o700); err != nil {
		return err
	}
	return checkDirTrusted(privDir, true, false)
}

// lockUpdates takes the root-owned exclusive update lock. flock locks belong
// to the open file description, so concurrent verbs (and goroutines) exclude
// each other. The lock is held across stage, verify, exec test, swap and
// rollback.
func lockUpdates() (func(), error) {
	if err := ensurePrivDir(); err != nil {
		return nil, fmt.Errorf("update lock directory: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(privDir, "update.lock"), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(lockWait)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			f.Close()
			return nil, err
		}
		if time.Now().After(deadline) {
			f.Close()
			return nil, errors.New("another update or rollback is in progress")
		}
		time.Sleep(50 * time.Millisecond)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}

// stageCopy copies src into a new, uniquely named file created with O_EXCL in
// dir (a root-only directory). Nothing else can hold or predict that name.
func stageCopy(src io.Reader, dir string) (string, os.FileInfo, error) {
	var f *os.File
	var name string
	for i := 0; ; i++ {
		var rnd [8]byte
		_, _ = rand.Read(rnd[:])
		name = filepath.Join(dir, fmt.Sprintf("%s%x", stagePrefix, rnd))
		var err error
		f, err = os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o700)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrExist) || i >= 5 {
			return "", nil, err
		}
	}
	fail := func(err error) (string, os.FileInfo, error) {
		f.Close()
		os.Remove(name)
		return "", nil, err
	}
	n, err := io.Copy(f, io.LimitReader(src, maxUpdateSize+1))
	if err != nil {
		return fail(err)
	}
	if n > maxUpdateSize {
		return fail(errors.New("update file is too large"))
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	fi, err := f.Stat()
	if err != nil {
		return fail(err)
	}
	// Close before exec: a file open for writing cannot be executed.
	if err := f.Close(); err != nil {
		os.Remove(name)
		return "", nil, err
	}
	return name, fi, nil
}

// stillStaged confirms path is still the regular file stageCopy created.
func stillStaged(path string, want os.FileInfo) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() || !os.SameFile(fi, want) || fi.Size() != want.Size() ||
		!fi.ModTime().Equal(want.ModTime()) || changeTime(fi) != changeTime(want) {
		return errors.New("staged update changed unexpectedly")
	}
	return nil
}

// afterChmod confirms path is still the staged file after our own chmod,
// which changes only the mode and the change time, and returns its new
// metadata.
func afterChmod(path string, want os.FileInfo) (os.FileInfo, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || !os.SameFile(fi, want) || fi.Size() != want.Size() || !fi.ModTime().Equal(want.ModTime()) {
		return nil, errors.New("staged update changed unexpectedly")
	}
	return fi, nil
}

// changeTime is the inode change time. Device and inode alone are not enough
// to recognise a file: a deleted inode number can be reused at once by a new
// file, which then gets a fresh change time.
func changeTime(fi os.FileInfo) syscall.Timespec {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ctim
	}
	return syscall.Timespec{}
}

func cleanStaleStaging(dir string) {
	matches, _ := filepath.Glob(filepath.Join(dir, stagePrefix+"*"))
	for _, m := range matches {
		if fi, err := os.Lstat(m); err == nil && fi.Mode().IsRegular() {
			os.Remove(m)
		}
	}
}

func readRootMarker() (*updateMarker, error) {
	b, err := os.ReadFile(rootMarkerPath())
	if err != nil {
		return nil, err
	}
	var m updateMarker
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func writeRootMarker(m *updateMarker) error {
	b, _ := json.Marshal(m)
	return safeWriteFile(rootMarkerPath(), b, 0o600, -1, -1)
}

func installUpdate(path, sha, version, sig string) error {
	state := DefaultStateDir()
	abs, err := filepath.Abs(path)
	if err != nil || filepath.Dir(abs) != filepath.Clean(state) {
		return fmt.Errorf("update file must be directly inside %s", state)
	}
	// Open without following a final symlink, then check the descriptor.
	src, err := os.OpenFile(abs, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open update file: %w", err)
	}
	defer src.Close()
	if fi, err := src.Stat(); err != nil || !fi.Mode().IsRegular() {
		return errors.New("update file must be a regular file")
	}
	keyPath := filepath.Join(filepath.Dir(DefaultConfigPath()), "job.pub")
	kfi, err := os.Stat(keyPath)
	if err != nil {
		return err
	}
	if st, ok := kfi.Sys().(*syscall.Stat_t); !ok || st.Uid != 0 || kfi.Mode().Perm()&0o022 != 0 {
		return errors.New("job key must be root-owned and not group/world writable")
	}
	pub, err := readJobKey(keyPath)
	if err != nil {
		return err
	}
	// One update or rollback at a time, from staging to rollback.
	unlock, err := lockUpdates()
	if err != nil {
		return err
	}
	defer unlock()
	dir := filepath.Dir(installedBinary)
	if err := checkDirTrusted(dir, false, true); err != nil {
		return fmt.Errorf("staging directory: %w", err)
	}
	cleanStaleStaging(dir)
	// Copy the agent-supplied file into a private, uniquely named file in the
	// root-only install directory, then verify, test and install that copy.
	staged, want, err := stageCopy(src, dir)
	if err != nil {
		return err
	}
	defer os.Remove(staged) // a no-op once renamed into place
	if err := verifyUpdateFile(staged, sha, version, sig, pub, runtime.GOOS, runtime.GOARCH); err != nil {
		return err
	}
	if err := stillStaged(staged, want); err != nil {
		return err
	}
	if err := exec.Command(staged, "version").Run(); err != nil {
		return fmt.Errorf("new binary does not run: %w", err)
	}
	cur, _ := exec.Command(installedBinary, "version", "--short").Output()
	if err := copyFile(installedBinary, installedBinary+".old", 0o755); err != nil {
		return err
	}
	if err := os.Chmod(staged, 0o755); err != nil {
		return err
	}
	// chmod updates the change time, so recheck without it and continue from
	// the file's new metadata.
	if want, err = afterChmod(staged, want); err != nil {
		return err
	}
	// The protected marker is written before the swap so a crash in between
	// still leaves recovery possible.
	m := &updateMarker{From: strings.TrimSpace(string(cur)), To: version, At: time.Now().Unix()}
	if err := writeRootMarker(m); err != nil {
		return err
	}
	if err := os.Rename(staged, installedBinary); err != nil {
		_ = os.Remove(rootMarkerPath())
		return err
	}
	if err := writeUpdateMarker(state, m); err != nil {
		_ = rollbackLocked()
		return err
	}
	fmt.Printf("installed agent %s (previous kept as %s.old)\n", version, installedBinary)
	return nil
}

// writeUpdateMarker writes the marker as root and hands it to the invoking
// (sudo) user, refusing symlinks in the agent-owned state directory.
func writeUpdateMarker(state string, m *updateMarker) error {
	uid, gid := -1, -1
	if u, err := strconv.Atoi(os.Getenv("SUDO_UID")); err == nil {
		uid = u
		if g, err := strconv.Atoi(os.Getenv("SUDO_GID")); err == nil {
			gid = g
		} else {
			gid = u
		}
	}
	return writeMarkerOwned(state, m, uid, gid)
}

// rollbackUpdate restores the previous binary, but only while the protected
// pending-update marker written by install-update exists and is inside the
// recovery window. Call it without the lock held.
func rollbackUpdate() error {
	unlock, err := lockUpdates()
	if err != nil {
		return err
	}
	defer unlock()
	m, err := readRootMarker()
	if err != nil {
		return errors.New("rollback refused: no pending update")
	}
	if err := checkRecoveryWindow(m, time.Now()); err != nil {
		_ = os.Remove(rootMarkerPath()) // expired: no longer recoverable
		return err
	}
	return rollbackLocked()
}

// rollbackLocked swaps the previous binary back; the caller holds the lock.
func rollbackLocked() error {
	old := installedBinary + ".old"
	if _, err := os.Stat(old); err != nil {
		return errors.New("no previous binary to roll back to")
	}
	if err := os.Rename(old, installedBinary); err != nil {
		return err
	}
	_ = os.Remove(rootMarkerPath())
	_ = os.Remove(markerPath(DefaultStateDir()))
	fmt.Println("rolled back to the previous agent binary")
	return nil
}

// confirmUpdate clears the protected marker once the new version has
// connected, closing the rollback window.
func confirmUpdate() error {
	unlock, err := lockUpdates()
	if err != nil {
		return err
	}
	defer unlock()
	if err := os.Remove(rootMarkerPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
