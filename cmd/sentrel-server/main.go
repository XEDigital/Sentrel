// Command sentrel-server runs the Sentrel monitoring server.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"sentrel/internal/release"
	"sentrel/internal/version"
	"sentrel/server/app"
	"sentrel/server/authn"
	"sentrel/server/db"
	"sentrel/server/netguard"
	"sentrel/server/selfupdate"
)

const usage = `Sentrel server %s

Usage:
  sentrel-server serve      [--data-dir DIR] [--listen ADDR] [--force-http]
  sentrel-server backup     [--data-dir DIR] --out FILE [--with-tsdb]
  sentrel-server restore    [--data-dir DIR] --in FILE [--force]
  sentrel-server reset-password [--data-dir DIR] --user NAME
  sentrel-server healthcheck [--url URL]
  sentrel-server self-update apply [--data-dir DIR]   (root; run by sentrel-updater.service)
  sentrel-server version

Environment: SENTREL_DATA_DIR, SENTREL_LISTEN, SENTREL_LOG_LEVEL (debug|info|warn), SENTREL_LOG_FORMAT (text|json)
`

func defaultDataDir() string {
	if d := os.Getenv("SENTREL_DATA_DIR"); d != "" {
		return d
	}
	if os.Geteuid() == 0 || dirWritable("/var/lib/sentrel") {
		return "/var/lib/sentrel"
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".sentrel")
}

func dirWritable(d string) bool {
	f, err := os.CreateTemp(d, ".probe")
	if err != nil {
		return false
	}
	f.Close()
	os.Remove(f.Name())
	return true
}

func newLogger() *slog.Logger {
	lvl := slog.LevelInfo
	switch strings.ToLower(os.Getenv("SENTREL_LOG_LEVEL")) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: lvl}
	if strings.ToLower(os.Getenv("SENTREL_LOG_FORMAT")) == "json" {
		return slog.New(slog.NewJSONHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usage, version.Version)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "serve":
		err = serve(args)
	case "backup":
		err = backup(args)
	case "restore":
		err = restore(args)
	case "reset-password":
		err = resetPassword(args)
	case "self-update":
		err = selfUpdate(args)
	case "healthcheck":
		err = healthcheck(args)
	case "version", "--version", "-v":
		fmt.Println("sentrel-server", version.String())
	case "help", "-h", "--help":
		fmt.Printf(usage, version.Version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n"+usage, cmd, version.Version)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	dataDir := fs.String("data-dir", defaultDataDir(), "data directory")
	listen := fs.String("listen", os.Getenv("SENTREL_LISTEN"), "listen address (overrides the stored setting)")
	forceHTTP := fs.Bool("force-http", false, "ignore the stored TLS mode and serve plain HTTP (recovery)")
	devUI := fs.String("dev-ui", "", "serve the UI from this directory (development)")
	agentDir := fs.String("agent-bin-dir", "", "serve agent binaries from this directory instead of the embedded ones")
	fs.Parse(args)
	log := newLogger()
	slog.SetDefault(log)
	log.Info("starting Sentrel server", "version", version.String(), "data_dir", *dataDir)
	a, err := app.New(app.Config{DataDir: *dataDir, Listen: *listen, ForceHTTP: *forceHTTP, DevUIDir: *devUI, AgentBinDir: *agentDir, Log: log})
	if err != nil {
		return err
	}
	defer a.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return a.Run(ctx)
}

func backup(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	dataDir := fs.String("data-dir", defaultDataDir(), "data directory")
	out := fs.String("out", "", "output file (.tar.gz), - for stdout")
	withTSDB := fs.Bool("with-tsdb", false, "include metrics (stop the server first for a consistent copy)")
	fs.Parse(args)
	if *out == "" {
		*out = fmt.Sprintf("sentrel-backup-%s.tar.gz", time.Now().UTC().Format("20060102-150405"))
	}
	d, err := db.Open(*dataDir)
	if err != nil {
		return err
	}
	defer d.Close()
	var w io.Writer = os.Stdout
	if *out != "-" {
		f, err := os.OpenFile(*out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	if err := app.WriteBackup(context.Background(), d, *dataDir, w, *withTSDB); err != nil {
		return err
	}
	if *out != "-" {
		fmt.Println("backup written to", *out)
	}
	return nil
}

func restore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	dataDir := fs.String("data-dir", defaultDataDir(), "data directory")
	in := fs.String("in", "", "backup file (.tar.gz)")
	force := fs.Bool("force", false, "overwrite an existing database")
	fs.Parse(args)
	if *in == "" {
		return fmt.Errorf("--in is required")
	}
	f, err := os.Open(*in)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := app.RestoreBackup(f, *dataDir, *force); err != nil {
		return err
	}
	fmt.Println("restored into", *dataDir, "- start the server; agents reconnect automatically")
	return nil
}

func resetPassword(args []string) error {
	fs := flag.NewFlagSet("reset-password", flag.ExitOnError)
	dataDir := fs.String("data-dir", defaultDataDir(), "data directory")
	user := fs.String("user", "", "username")
	disable2FA := fs.Bool("disable-2fa", false, "also remove TOTP and passkeys")
	fs.Parse(args)
	if *user == "" {
		return fmt.Errorf("--user is required")
	}
	d, err := db.Open(*dataDir)
	if err != nil {
		return err
	}
	defer d.Close()
	pw := strings.ToLower(randomPassword())
	h, err := authn.HashPassword(pw)
	if err != nil {
		return err
	}
	res, err := d.Exec(`UPDATE users SET password_hash=?, auth_source='local', disabled=0, must_change_pw=1 WHERE username=?`, h, *user)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("no user %q", *user)
	}
	if *disable2FA {
		_, _ = d.Exec(`UPDATE users SET totp_enabled=0, totp_secret='', recovery_codes='[]' WHERE username=?`, *user)
		_, _ = d.Exec(`DELETE FROM webauthn_credentials WHERE user_id=(SELECT id FROM users WHERE username=?)`, *user)
	}
	_, _ = d.Exec(`DELETE FROM sessions WHERE user_id=(SELECT id FROM users WHERE username=?)`, *user)
	_, _ = d.Exec(`INSERT INTO audit_log (tenant_id, actor, action, target_type, details, created_at) VALUES (0,'cli','user.password_reset_cli','user','{}',?)`, time.Now().Unix())
	fmt.Printf("new password for %s: %s\n(you will be asked to change it after logging in)\n", *user, pw)
	return nil
}

func randomPassword() string {
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	const alpha = "abcdefghjkmnpqrstuvwxyz23456789"
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = alpha[int(c)%len(alpha)]
	}
	return string(out[:6]) + "-" + string(out[6:12]) + "-" + string(out[12:])
}

func healthcheck(args []string) error {
	fs := flag.NewFlagSet("healthcheck", flag.ExitOnError)
	url := fs.String("url", "http://127.0.0.1:8080/healthz", "health URL")
	fs.Parse(args)
	u, err := neturl.Parse(*url)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("invalid health URL")
	}
	// Only loopback health checks may accept a self-signed certificate. Remote
	// URLs use normal chain and hostname verification, and redirects never move
	// a local exception to a remote endpoint.
	ip := net.ParseIP(u.Hostname())
	local := u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: local, MinVersion: tls.VersionTLS12}}
	if local {
		tr.DialContext = netguard.LocalDialer(5 * time.Second).DialContext
	}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Timeout: 5 * time.Second, Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	try := func(u string) error {
		resp, err := cl.Get(u)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		return nil
	}
	err = try(*url)
	if err != nil && strings.HasPrefix(*url, "http://") {
		// The server may have switched to TLS on the same port.
		if err2 := try("https://" + strings.TrimPrefix(*url, "http://")); err2 == nil {
			return nil
		}
	}
	return err
}

// selfUpdate is the privileged half of one-click updates. It runs as root from
// sentrel-updater.service and trusts only the key compiled into this binary.
func selfUpdate(args []string) error {
	if len(args) == 0 || args[0] != "apply" {
		return fmt.Errorf("usage: sentrel-server self-update apply [--data-dir DIR]")
	}
	fs := flag.NewFlagSet("self-update apply", flag.ExitOnError)
	dataDir := fs.String("data-dir", defaultDataDir(), "data directory")
	binPath := fs.String("bin", "/usr/local/bin/sentrel-server", "installed server binary")
	unit := fs.String("unit", "sentrel.service", "systemd unit of the server")
	unitFile := fs.String("unit-file", "/etc/systemd/system/sentrel.service", "unit file to read the listen address from")
	owner := fs.String("owner", "sentrel", "user that owns status and result files")
	fs.Parse(args[1:])
	if os.Geteuid() != 0 {
		return fmt.Errorf("self-update apply must run as root")
	}
	uid, gid := -1, -1
	if u, err := user.Lookup(*owner); err == nil {
		uid, _ = strconv.Atoi(u.Uid)
		gid, _ = strconv.Atoi(u.Gid)
	}
	cfg := selfupdate.ApplyConfig{
		DataDir: *dataDir, BinPath: *binPath, CurrentVersion: version.Version, GOARCH: runtime.GOARCH,
		Key: release.TrustRoot(), OwnerUID: uid, OwnerGID: gid,
		Logf:    func(f string, a ...any) { fmt.Fprintf(os.Stderr, "self-update: "+f+"\n", a...) },
		Restart: selfupdate.SystemdRestart(*unit),
		Health:  selfupdate.HTTPHealth(selfupdate.ListenFromUnit(*unitFile)),
	}
	res, err := selfupdate.Apply(context.Background(), cfg)
	if res != nil {
		fmt.Fprintf(os.Stderr, "self-update: %s: %s\n", res.Outcome, res.Message)
	}
	return err
}
