// Package app is the Sentrel server: API, agent hub, pollers, alerting
// and job runner, all in one process.
package app

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jmoiron/sqlx"

	pb "sentrel/gen/sentrelv1"
	"sentrel/internal/jobpolicy"
	"sentrel/server/db"
	"sentrel/server/metrics"
	"sentrel/server/pki"
)

type sqlxTx = sqlx.Tx

// Config is the process-level configuration (flags/env). Everything else is
// stored in the database and edited from the UI.
type Config struct {
	DataDir     string
	Listen      string // overrides the stored listen address when set
	ForceHTTP   bool   // ignore stored TLS mode (recovery)
	DevUIDir    string // serve the UI from disk instead of the embedded build
	AgentBinDir string // serve agent binaries from disk instead of embedded
	Log         *slog.Logger
}

// App is the running server.
type App struct {
	cfg           Config
	log           *slog.Logger
	db            *db.DB
	ca            *pki.CA
	ts            *metrics.Store
	statusMetrics statusMetricCache // short-lived cache of status page host metrics
	settings      *SettingsStore

	hub      *Hub
	alerts   *AlertEngine
	notifier *Notifier
	checks   *CheckRunner
	jobs     *JobManager
	vuln     *VulnService
	snmp     *SNMPPoller
	updates  *updateService
	maint    *MaintenanceCache
	latest   *latestCache
	auth     *authService
	events   *eventBus

	setupMu    sync.Mutex
	setupToken string

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	srv    *httpServer
}

// New opens storage and constructs the server.
func New(cfg Config) (*App, error) {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return nil, err
	}
	d, err := db.Open(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	ca, err := pki.Load(filepath.Join(cfg.DataDir, "pki"))
	if err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}
	a := &App{cfg: cfg, log: cfg.Log, db: d, ca: ca}
	a.settings = newSettingsStore(d)
	ret := a.settings.Retention()
	ts, err := metrics.Open(filepath.Join(cfg.DataDir, "tsdb"), a.maxRetention(ret.Days), a.log)
	if err != nil {
		return nil, fmt.Errorf("tsdb: %w", err)
	}
	a.ts = ts
	a.ctx, a.cancel = context.WithCancel(context.Background())
	a.events = newEventBus()
	a.latest = newLatestCache()
	a.maint = newMaintenanceCache(a)
	a.hub = newHub(a)
	a.notifier = newNotifier(a)
	a.alerts = newAlertEngine(a)
	a.checks = newCheckRunner(a)
	a.jobs = newJobManager(a)
	a.vuln = newVulnService(a)
	a.snmp = newSNMPPoller(a)
	a.auth = newAuthService(a)
	a.updates = newUpdateService(a)
	if err := a.seed(a.ctx); err != nil {
		return nil, fmt.Errorf("seed: %w", err)
	}
	return a, nil
}

// maxRetention returns the TSDB retention: the global value, or the
// longest per-host override if that is longer.
func (a *App) maxRetention(days int) time.Duration {
	if days <= 0 {
		days = 31
	}
	var maxDays int
	_ = a.db.Get(&maxDays, `SELECT COALESCE(MAX(retention_days),0) FROM hosts`)
	if maxDays > days {
		days = maxDays
	}
	return time.Duration(days) * 24 * time.Hour
}

// Run starts background loops and the HTTP/gRPC listener and blocks until
// ctx is cancelled.
func (a *App) Run(ctx context.Context) error {
	if err := a.alerts.load(ctx); err != nil {
		return err
	}
	a.maint.refresh(ctx)
	// Nothing is connected at boot.
	_, _ = a.db.ExecContext(ctx, `UPDATE hosts SET connected=0`)
	a.ensureSetupToken()

	loops := []func(context.Context){
		a.alerts.loop,
		a.notifier.loop,
		a.checks.loop,
		a.jobs.loop,
		a.vuln.loop,
		a.snmp.loop,
		a.updates.loop,
		a.maint.loop,
		a.housekeepingLoop,
		a.uptimeLoop,
	}
	for _, f := range loops {
		a.wg.Add(1)
		go func(f func(context.Context)) {
			defer a.wg.Done()
			f(a.ctx)
		}(f)
	}
	a.srv = newHTTPServer(a)
	errCh := make(chan error, 1)
	go func() { errCh <- a.srv.run(a.ctx) }()
	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil {
			a.cancel()
			a.wg.Wait()
			return err
		}
	}
	a.log.Info("shutting down")
	a.cancel()
	a.srv.shutdown()
	a.wg.Wait()
	return nil
}

// Close releases storage.
func (a *App) Close() {
	a.cancel()
	if a.ts != nil {
		a.ts.Close()
	}
	if a.vuln != nil {
		a.vuln.close()
	}
	if a.db != nil {
		a.db.Close()
	}
}

// ensureSetupToken creates the one-time setup token if no admin exists.
func (a *App) ensureSetupToken() {
	var n int
	_ = a.db.Get(&n, `SELECT COUNT(*) FROM users`)
	path := filepath.Join(a.cfg.DataDir, "setup-token")
	if n > 0 {
		_ = os.Remove(path)
		return
	}
	a.setupMu.Lock()
	defer a.setupMu.Unlock()
	if b, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(b))) >= 16 {
		a.setupToken = strings.TrimSpace(string(b))
	} else {
		a.setupToken = randomCode(24)
		_ = os.WriteFile(path, []byte(a.setupToken+"\n"), 0o600)
	}
	a.log.Info("first run: open the web UI to complete setup", "setup_token", a.setupToken, "token_file", path)
	fmt.Fprintf(os.Stderr, "\n  Sentrel first-run setup token: %s\n  (also stored in %s)\n\n", a.setupToken, path)
}

// randomCode returns n characters from an unambiguous alphabet.
func randomCode(n int) string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, n)
	rb := make([]byte, n)
	_, _ = rand.Read(rb)
	for i := range b {
		b[i] = alphabet[int(rb[i])%len(alphabet)]
	}
	return string(b)
}

// seed inserts default data on first start.
func (a *App) seed(ctx context.Context) error {
	var n int
	if err := a.db.GetContext(ctx, &n, `SELECT COUNT(*) FROM threshold_rules`); err != nil {
		return err
	}
	if n == 0 {
		now := db.Now()
		for _, d := range defaultThresholds() {
			if _, err := a.db.ExecContext(ctx, `INSERT INTO threshold_rules (tenant_id, scope, scope_id, metric, label_match, warn, crit, for_count, enabled, notify, created_at, updated_at)
				VALUES (0,'global',0,?,'',?,?,?,?,1,?,?)`, d.Metric, d.Warn, d.Crit, d.ForCount, d.Enabled, now, now); err != nil {
				return err
			}
		}
	}
	return a.seedMissingDefaults(ctx)
}

// seedMissingDefaults adds default rules introduced after the first install
// (once each, so a rule an admin deleted stays deleted).
func (a *App) seedMissingDefaults(ctx context.Context) error {
	for _, d := range defaultThresholds() {
		if d.Metric != "portscan" {
			continue
		}
		flag := "seeded_rule:" + d.Metric
		var done int
		_ = a.db.GetContext(ctx, &done, `SELECT COUNT(*) FROM settings WHERE tenant_id=0 AND key=?`, flag)
		if done > 0 {
			continue
		}
		now := db.Now()
		var have int
		_ = a.db.GetContext(ctx, &have, `SELECT COUNT(*) FROM threshold_rules WHERE scope='global' AND metric=?`, d.Metric)
		if have == 0 {
			if _, err := a.db.ExecContext(ctx, `INSERT INTO threshold_rules (tenant_id, scope, scope_id, metric, label_match, warn, crit, for_count, enabled, notify, created_at, updated_at)
				VALUES (0,'global',0,?,'',?,?,?,?,1,?,?)`, d.Metric, d.Warn, d.Crit, d.ForCount, d.Enabled, now, now); err != nil {
				return err
			}
		}
		if _, err := a.db.ExecContext(ctx, `INSERT INTO settings (tenant_id, key, value, updated_at) VALUES (0,?,'1',?) ON CONFLICT(tenant_id, key) DO NOTHING`, flag, now); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) getHost(ctx context.Context, id int64) (*Host, error) {
	var h Host
	err := a.db.GetContext(ctx, &h, `SELECT `+hostCols+`, h.state FROM hosts h WHERE h.id=?`, id)
	if err != nil {
		return nil, err
	}
	a.resolveHost(&h)
	return &h, nil
}

func (a *App) getHostByAgentID(ctx context.Context, agentID string) (*Host, error) {
	var h Host
	err := a.db.GetContext(ctx, &h, `SELECT `+hostCols+` FROM hosts h WHERE h.agent_id=?`, agentID)
	if err != nil {
		return nil, err
	}
	a.resolveHost(&h)
	return &h, nil
}

// agentConfig computes the effective agent config for a host.
func (a *App) agentConfig(h *Host) *pb.AgentConfig {
	d := a.settings.Agent()
	cfg := &pb.AgentConfig{
		IntervalSeconds:          uint32(d.IntervalSeconds),
		InventoryIntervalSeconds: uint32(d.InventoryIntervalSec),
		TopProcesses:             uint32(d.TopProcesses),
		CollectServices:          d.CollectServices,
		CollectPorts:             d.CollectPorts,
		CollectDocker:            d.CollectDocker,
		BruteforceEnabled:        d.BruteforceEnabled,
		SecurityIntervalSeconds:  uint32(d.SecurityIntervalSec),
		Fail2BanEnabled:          d.Fail2banEnabled,
		WatchedServices:          d.WatchedServices,
		CollectTemperatures:      d.CollectTemperatures,
		RefreshPackageIndex:      d.RefreshPackageIndex,
		PortscanEnabled:          d.PortscanEnabled,
		PortscanThresholdPerMin:  uint32(max(d.PortscanThresholdPerMin, 1)),
		PortscanAllowlist:        d.PortscanAllowlist,
	}
	if h == nil {
		cfg.PortscanAllowlist = mergeLists(cfg.PortscanAllowlist, a.neverBlockList(nil))
		return cfg
	}
	if h.IntervalSeconds != nil && *h.IntervalSeconds >= 5 {
		cfg.IntervalSeconds = uint32(*h.IntervalSeconds)
	}
	if h.InventoryInterval != nil && *h.InventoryInterval >= 300 {
		cfg.InventoryIntervalSeconds = uint32(*h.InventoryInterval)
	}
	var o AgentOptions
	if len(h.AgentOptions) > 0 {
		_ = json.Unmarshal(h.AgentOptions, &o)
	}
	if o.TopProcesses != nil {
		cfg.TopProcesses = uint32(*o.TopProcesses)
	}
	setB := func(dst *bool, v *bool) {
		if v != nil {
			*dst = *v
		}
	}
	setB(&cfg.CollectServices, o.CollectServices)
	setB(&cfg.CollectPorts, o.CollectPorts)
	setB(&cfg.CollectDocker, o.CollectDocker)
	setB(&cfg.CollectTemperatures, o.CollectTemperatures)
	setB(&cfg.BruteforceEnabled, o.BruteforceEnabled)
	setB(&cfg.Fail2BanEnabled, o.Fail2banEnabled)
	setB(&cfg.RefreshPackageIndex, o.RefreshPackageIndex)
	setB(&cfg.PortscanEnabled, o.PortscanEnabled)
	if o.PortscanThresholdPerMin != nil && *o.PortscanThresholdPerMin >= 1 {
		cfg.PortscanThresholdPerMin = uint32(*o.PortscanThresholdPerMin)
	}
	if len(o.PortscanAllowlist) > 0 {
		cfg.PortscanAllowlist = append(append([]string{}, cfg.PortscanAllowlist...), o.PortscanAllowlist...)
	}
	// The never-block list (global, host and the server's own addresses) is
	// never flagged as a port scanner.
	cfg.PortscanAllowlist = mergeLists(cfg.PortscanAllowlist, a.neverBlockList(h))
	if len(o.WatchedServices) > 0 {
		cfg.WatchedServices = append(append([]string{}, cfg.WatchedServices...), o.WatchedServices...)
	}
	// Services named in service checks must always be reported.
	var names []string
	_ = a.db.Select(&names, `SELECT target FROM checks WHERE host_id=? AND type='service' AND enabled=1`, h.ID)
	cfg.WatchedServices = append(cfg.WatchedServices, names...)
	return cfg
}

func (a *App) onAgentConnected(ctx context.Context, h *Host, hello *pb.Hello, ip string) {
	now := db.Now()
	info := h.HostInfo
	if hello.Host != nil {
		if b, err := protoJSON.Marshal(hello.Host); err == nil {
			info = JSON(b)
		}
	}
	addr := h.Address
	if addr == "" || addr == "0.0.0.0" {
		addr = ip
	}
	policy, keys, keyIDs := reportedWritePolicy(hello)
	if policy != h.WritePolicy || strings.Join(keyIDs, ",") != strings.Join(h.OperatorKeyIDs, ",") {
		a.audit(ctx, auditEntry{TenantID: h.TenantID, Actor: "agent:" + h.Name, Action: "host.write_policy", TargetType: "host", TargetID: itoa(h.ID),
			Details: map[string]any{"from": h.WritePolicy, "to": policy, "operator_key_ids": keyIDs}})
	}
	kb, _ := json.Marshal(keys)
	ib, _ := json.Marshal(keyIDs)
	_, err := a.db.ExecContext(ctx, `UPDATE hosts SET connected=1, status='up', last_seen_at=?, agent_version=?, host_info=?, address=?, write_policy=?, operator_keys=?, operator_key_ids=?, updated_at=? WHERE id=?`,
		now, hello.AgentVersion, string(info), addr, policy, string(kb), string(ib), now, h.ID)
	if err != nil {
		a.log.Error("agent connected update", "err", err)
	}
	a.latest.touch(h.ID)
	if hello.UpdatedFrom != "" {
		a.audit(ctx, auditEntry{TenantID: h.TenantID, Actor: "agent:" + h.Name, Action: "agent.updated", TargetType: "host", TargetID: itoa(h.ID),
			Details: map[string]any{"from": hello.UpdatedFrom, "to": hello.AgentVersion}})
		a.jobs.completeSelfUpdate(ctx, h.ID, hello.AgentVersion)
	}
	if hh, err := a.getHost(ctx, h.ID); err == nil {
		a.jobs.maybeAutoUpdate(ctx, hh)
	}
	a.log.Info("agent connected", "host_id", h.ID, "name", h.Name, "ip", ip, "version", hello.AgentVersion)
	a.events.publish(Event{Type: "host.connected", TenantID: h.TenantID, HostID: h.ID})
	a.alerts.hostSeen(h.ID)
}

// reportedWritePolicy extracts the agent's write policy and operator keys from
// its hello. Unknown or missing values mean the default (server) policy, which
// is what agents that predate the feature enforce.
func reportedWritePolicy(hello *pb.Hello) (policy string, keys, ids []string) {
	policy, err := jobpolicy.NormalizePolicy(hello.WritePolicy)
	if err != nil {
		policy = jobpolicy.PolicyOperator // unknown value: assume the strictest that needs signatures
	}
	keys, ids = []string{}, []string{}
	for _, k := range hello.OperatorKeys {
		if len(keys) >= 16 {
			break
		}
		if pub, err := jobpolicy.ParseKey(k); err == nil {
			keys = append(keys, base64.StdEncoding.EncodeToString(pub))
			ids = append(ids, jobpolicy.KeyID(pub))
		}
	}
	return policy, keys, ids
}

func (a *App) onAgentDisconnected(hostID int64) {
	now := db.Now()
	_, _ = a.db.Exec(`UPDATE hosts SET connected=0, last_seen_at=MAX(last_seen_at, ?) WHERE id=?`, now, hostID)
	a.log.Info("agent disconnected", "host_id", hostID)
	a.events.publish(Event{Type: "host.disconnected", HostID: hostID})
}

// DataDir returns the data directory.
func (a *App) DataDir() string { return a.cfg.DataDir }
