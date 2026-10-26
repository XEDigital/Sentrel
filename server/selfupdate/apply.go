package selfupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"sentrel/internal/release"
	"sentrel/server/netguard"
)

// ApplyConfig configures the privileged apply step. Only DataDir, BinPath,
// CurrentVersion, GOARCH, Key, Restart and Health are required; the rest
// default to the real system behaviour and are replaced in tests.
type ApplyConfig struct {
	DataDir        string
	BinPath        string // installed server binary, e.g. /usr/local/bin/sentrel-server
	CurrentVersion string
	GOARCH         string
	Key            ed25519.PublicKey // trust root

	// OwnerUID and OwnerGID are applied to status.json and result.json.
	// A negative UID skips the chown (tests).
	OwnerUID, OwnerGID int

	TmpDir        string // parent of the root-owned scratch directory ("" = system default)
	HealthTimeout time.Duration
	Now           func() time.Time
	Logf          func(format string, args ...any)

	RunVersion func(ctx context.Context, path string) (string, error)
	Setcap     func(ctx context.Context, path string) error
	Restart    func(ctx context.Context) error
	Health     func(ctx context.Context, version string) error
}

func (c *ApplyConfig) defaults() {
	if c.HealthTimeout == 0 {
		c.HealthTimeout = 90 * time.Second
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
	if c.RunVersion == nil {
		c.RunVersion = runVersion
	}
	if c.Setcap == nil {
		c.Setcap = setcap
	}
}

// Apply performs the update described by request.json. It writes result.json
// (when the update directory is reachable) and returns the result; a non-nil
// error accompanies every outcome except success.
func Apply(ctx context.Context, cfg ApplyConfig) (*Result, error) {
	cfg.defaults()
	res := &Result{From: cfg.CurrentVersion, StartedAt: cfg.Now().Unix()}
	root, err := os.OpenRoot(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	// "update" is resolved inside the data directory: a symlink pointing
	// outside it is refused.
	ur, err := root.OpenRoot(DirName)
	if err != nil {
		return nil, fmt.Errorf("open update dir: %w", err)
	}
	defer ur.Close()
	w := &writer{root: ur, uid: cfg.OwnerUID, gid: cfg.OwnerGID}

	finish := func(outcome, msg string, rolledBack bool) (*Result, error) {
		res.Outcome, res.Message, res.RolledBack = outcome, msg, rolledBack
		res.FinishedAt = cfg.Now().Unix()
		_ = ur.Remove(StatusFile)
		if err := w.writeJSON(ResultFile, res); err != nil {
			cfg.Logf("writing result: %v", err)
		}
		if outcome == OutcomeSuccess {
			return res, nil
		}
		return res, errors.New(msg)
	}
	fail := func(format string, a ...any) (*Result, error) {
		return finish(OutcomeFailed, fmt.Sprintf(format, a...), false)
	}

	// 1. Read and consume the request.
	req, err := readRequest(ur)
	if err != nil {
		return fail("bad update request: %v", err)
	}
	_ = ur.Remove(RequestFile) // consume first so a failure can never loop
	res.To = strings.TrimPrefix(req.Version, "v")
	phase := func(p string) {
		cfg.Logf("phase: %s", p)
		_ = w.writeJSON(StatusFile, Status{Phase: p, Version: res.To, UpdatedAt: cfg.Now().Unix()})
	}
	phase(PhaseVerifying)

	// 2. Version policy: only strictly newer.
	cur, ok := release.ParseVersion(cfg.CurrentVersion)
	if !ok {
		return fail("the running version %q is not a release version; refusing to update", cfg.CurrentVersion)
	}
	target, ok := release.ParseVersion(req.Version)
	if !ok {
		return fail("invalid target version %q", req.Version)
	}
	if target.Compare(cur) <= 0 {
		return fail("refusing to install %s over %s: not newer", res.To, cfg.CurrentVersion)
	}

	// 3. Copy the staged files into a root-owned scratch directory. The
	// staging directory belongs to the unprivileged user, so nothing in it is
	// trusted until it has been copied and verified.
	scratch, err := os.MkdirTemp(cfg.TmpDir, "sentrel-update-")
	if err != nil {
		return fail("scratch directory: %v", err)
	}
	defer os.RemoveAll(scratch)
	if err := os.Chmod(scratch, 0o700); err != nil {
		return fail("scratch directory: %v", err)
	}
	sr, err := ur.OpenRoot(StagedDir)
	if err != nil {
		return fail("staged files: %v", err)
	}
	defer sr.Close()
	asset := release.ServerAsset(cfg.GOARCH)
	newBin := filepath.Join(scratch, asset)
	if err := copyStaged(sr, asset, newBin, MaxBinaryBytes, 0o755); err != nil {
		return fail("%v", err)
	}
	sumsPath, sigPath := filepath.Join(scratch, SumsName), filepath.Join(scratch, SigName)
	if err := copyStaged(sr, SumsName, sumsPath, MaxSmallBytes, 0o600); err != nil {
		return fail("%v", err)
	}
	if err := copyStaged(sr, SigName, sigPath, MaxSmallBytes, 0o600); err != nil {
		return fail("%v", err)
	}

	// 4. Signature over SHA256SUMS with the embedded key, then the binary hash.
	sums, _ := os.ReadFile(sumsPath)
	sig, _ := os.ReadFile(sigPath)
	hash, err := fileSHA256(newBin)
	if err != nil {
		return fail("hash: %v", err)
	}
	if err := release.VerifyBundle(cfg.Key, sums, sig, asset, hash); err != nil {
		return fail("verification failed: %v", err)
	}

	// 5. The new binary must run and report the target version.
	out, err := cfg.RunVersion(ctx, newBin)
	if err != nil {
		return fail("the new binary does not run: %v", err)
	}
	if got := parseVersionOutput(out); got != res.To {
		return fail("the new binary reports version %q, expected %q", got, res.To)
	}
	if cfg.Restart == nil || cfg.Health == nil {
		return fail("internal error: restart/health not configured")
	}

	// 6. Back up and swap.
	phase(PhaseInstalling)
	oldPath := cfg.BinPath + ".old"
	if err := installFile(ctx, cfg, cfg.BinPath, oldPath, false); err != nil {
		return fail("backup of the current binary: %v", err)
	}
	if err := installFile(ctx, cfg, newBin, cfg.BinPath, true); err != nil {
		return fail("installing the new binary: %v", err)
	}

	// 7. Restart and wait for health; roll back on any failure.
	phase(PhaseRestarting)
	problem := ""
	if err := cfg.Restart(ctx); err != nil {
		problem = "restart failed: " + err.Error()
	} else {
		phase(PhaseChecking)
		hctx, cancel := context.WithTimeout(ctx, cfg.HealthTimeout)
		err := cfg.Health(hctx, res.To)
		cancel()
		if err != nil {
			problem = fmt.Sprintf("the new version did not become healthy within %s: %v", cfg.HealthTimeout, err)
		}
	}
	if problem == "" {
		return finish(OutcomeSuccess, "updated to "+res.To, false)
	}

	phase(PhaseRollingBack)
	cfg.Logf("%s; restoring %s", problem, oldPath)
	if err := installFile(ctx, cfg, oldPath, cfg.BinPath, true); err != nil {
		return finish(OutcomeRolledBack, problem+"; ROLLBACK FAILED: "+err.Error(), false)
	}
	msg := problem + "; the previous version was restored"
	if err := cfg.Restart(ctx); err != nil {
		msg += " but restarting it failed: " + err.Error()
	} else {
		hctx, cancel := context.WithTimeout(ctx, cfg.HealthTimeout)
		if err := cfg.Health(hctx, cfg.CurrentVersion); err != nil {
			msg += " but it is not healthy: " + err.Error()
		}
		cancel()
	}
	return finish(OutcomeRolledBack, msg, true)
}

func readRequest(ur *os.Root) (*Request, error) {
	fi, err := ur.Lstat(RequestFile)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > MaxSmallBytes {
		return nil, errors.New("request.json is not a regular file")
	}
	f, err := ur.Open(RequestFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxSmallBytes))
	if err != nil {
		return nil, err
	}
	var r Request
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	if r.Version == "" {
		return nil, errors.New("no version in request")
	}
	return &r, nil
}

// copyStaged copies one regular file out of the staging directory. Symlinks
// are refused, and the opened file must be the very file that was examined.
func copyStaged(sr *os.Root, name, dst string, limit int64, mode os.FileMode) error {
	li, err := sr.Lstat(name)
	if err != nil {
		return fmt.Errorf("staged file %s: %w", name, err)
	}
	if li.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("staged file %s is a symbolic link; refusing", name)
	}
	if !li.Mode().IsRegular() {
		return fmt.Errorf("staged file %s is not a regular file; refusing", name)
	}
	f, err := sr.Open(name)
	if err != nil {
		return fmt.Errorf("staged file %s: %w", name, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || !os.SameFile(li, fi) {
		return fmt.Errorf("staged file %s changed while being read; refusing", name)
	}
	if fi.Size() > limit {
		return fmt.Errorf("staged file %s is too large", name)
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	n, err := io.Copy(out, io.LimitReader(f, limit+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n > limit {
		return fmt.Errorf("staged file %s is too large", name)
	}
	return nil
}

// installFile copies src to a temporary file next to dst and renames it into
// place, so dst is always either the old or the new complete file. With caps
// the file capabilities are applied to the temporary file first.
func installFile(ctx context.Context, cfg ApplyConfig, src, dst string, caps bool) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.OpenFile(fmt.Sprintf("%s.tmp-%s", dst, randHex()), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			os.Remove(name)
		}
	}()
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if caps {
		if err := cfg.Setcap(ctx, name); err != nil {
			cfg.Logf("warning: setcap failed (ping checks need cap_net_raw): %v", err)
		}
	}
	if err := os.Rename(name, dst); err != nil {
		return err
	}
	ok = true
	return nil
}

func randHex() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// writer writes small files into the update directory without ever following
// a symlink that the unprivileged user may have planted there.
type writer struct {
	root     *os.Root
	uid, gid int
}

func (w *writer) writeJSON(name string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := "." + name + ".tmp-" + randHex()
	f, err := w.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	if err == nil {
		err = f.Chmod(0o640)
	}
	if err == nil && w.uid >= 0 {
		err = f.Chown(w.uid, w.gid)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = w.root.Remove(tmp)
		return err
	}
	// Rename replaces a planted symlink at name instead of following it.
	if err := w.root.Rename(tmp, name); err != nil {
		_ = w.root.Remove(tmp)
		return err
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// parseVersionOutput extracts the version from "sentrel-server 1.2.3 (commit, date)".
func parseVersionOutput(out string) string {
	f := strings.Fields(strings.TrimSpace(out))
	if len(f) < 2 {
		return ""
	}
	return strings.TrimPrefix(f[1], "v")
}

func runVersion(ctx context.Context, path string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "version")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	out, err := cmd.Output()
	return string(out), err
}

func setcap(ctx context.Context, path string) error {
	p, err := exec.LookPath("setcap")
	if err != nil {
		return err
	}
	out, err := exec.CommandContext(ctx, p, "cap_net_raw,cap_net_bind_service+ep", path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// SystemdRestart restarts a unit with systemctl.
func SystemdRestart(unit string) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		out, err := exec.CommandContext(ctx, "systemctl", "restart", unit).CombinedOutput()
		if err != nil {
			return fmt.Errorf("systemctl restart %s: %v: %s", unit, err, strings.TrimSpace(string(out)))
		}
		return nil
	}
}

// ListenFromUnit reads the --listen address from a unit file's ExecStart.
func ListenFromUnit(unitPath string) string {
	b, err := os.ReadFile(unitPath)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "ExecStart=") {
			continue
		}
		f := strings.Fields(strings.TrimPrefix(line, "ExecStart="))
		for i, a := range f {
			if a == "--listen" && i+1 < len(f) {
				return f[i+1]
			}
			if v, ok := strings.CutPrefix(a, "--listen="); ok {
				return v
			}
		}
	}
	return ""
}

// HTTPHealth polls the local server until /healthz answers 200 and
// /api/v1/public/info reports the wanted version. It tries plain HTTP, then
// HTTPS (self-signed certificates are fine for this loopback probe).
func HTTPHealth(listen string) func(ctx context.Context, version string) error {
	if listen == "" {
		listen = "0.0.0.0:8080"
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		host, port = "127.0.0.1", "8080"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	hostport := net.JoinHostPort(host, port)
	cl := &http.Client{Timeout: 4 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true, DialContext: netguard.LocalDialer(4 * time.Second).DialContext}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return func(ctx context.Context, version string) error {
		var last error
		for {
			for _, scheme := range []string{"http", "https"} {
				err := probe(ctx, cl, scheme+"://"+hostport, version)
				if err == nil {
					return nil
				}
				last = err
			}
			select {
			case <-ctx.Done():
				return fmt.Errorf("%w (last error: %v)", ctx.Err(), last)
			case <-time.After(time.Second):
			}
		}
	}
}

func probe(ctx context.Context, cl *http.Client, base, version string) error {
	get := func(path string) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			return nil, err
		}
		resp, err := cl.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("%s: HTTP %d", path, resp.StatusCode)
		}
		return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	}
	if _, err := get("/healthz"); err != nil {
		return err
	}
	b, err := get("/api/v1/public/info")
	if err != nil {
		return err
	}
	var info struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(b, &info); err != nil {
		return err
	}
	if strings.TrimPrefix(info.Version, "v") != strings.TrimPrefix(version, "v") {
		return fmt.Errorf("server reports version %q, want %q", info.Version, version)
	}
	return nil
}
