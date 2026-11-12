package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	pb "sentrel/gen/sentrelv1"
	"sentrel/web"
)

type httpServer struct {
	a       *App
	grpc    *grpc.Server
	handler http.Handler
	api     *apiRouter

	mu      sync.Mutex
	servers []*http.Server
	restart chan struct{}
	mode    string
	addr    string
	lastErr error

	lastGood       *listenCfg   // last configuration that started successfully
	lastGoodStored *TLSSettings // the stored settings it came from (nil when forced to HTTP)

	// Test hooks.
	serverCert func(names []string) (*tls.Certificate, error)
	failStart  func(lc listenCfg) error
}

func newHTTPServer(a *App) *httpServer {
	g := grpc.NewServer(
		grpc.MaxRecvMsgSize(64<<20),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 10 * time.Second, PermitWithoutStream: true}),
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: 60 * time.Second, Timeout: 20 * time.Second}),
	)
	pb.RegisterAgentServiceServer(g, a.hub)
	s := &httpServer{a: a, grpc: g, restart: make(chan struct{}, 1)}
	s.handler = s.buildHandler()
	return s
}

// Restart re-reads TLS settings and rebinds listeners.
func (s *httpServer) Restart() {
	select {
	case s.restart <- struct{}{}:
	default:
	}
}

// Mode returns the active TLS mode.
func (s *httpServer) Mode() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mode
}

// listenCfg is one complete, effective listener configuration.
type listenCfg struct {
	t    TLSSettings
	mode string
	addr string
}

// effective resolves the stored TLS settings and process flags into the
// configuration to run. Plain HTTP is only ever chosen by the operator: the
// stored "http" mode or the --force-http recovery flag.
func (s *httpServer) effective() listenCfg {
	t := s.a.settings.TLS()
	mode := t.Mode
	if s.a.cfg.ForceHTTP || mode == "" {
		mode = "http"
	}
	return listenCfg{t: t, mode: mode, addr: s.listenAddr(t)}
}

// boot starts the listeners for the current configuration and remembers it as
// the last known good one.
func (s *httpServer) boot(errCh chan error) error {
	lc := s.effective()
	if err := s.start(errCh, lc); err != nil {
		return err
	}
	s.markGood(lc)
	return nil
}

func (s *httpServer) markGood(lc listenCfg) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastGood = &lc
	if !s.a.cfg.ForceHTTP {
		t := lc.t
		s.lastGoodStored = &t
	}
}

func (s *httpServer) run(ctx context.Context) error {
	errCh := make(chan error, 4)
	if err := s.boot(errCh); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errCh:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				return err
			}
		case <-s.restart:
			s.a.log.Info("restarting listeners for new TLS settings")
			errCh = make(chan error, 4)
			if err := s.reconfigure(errCh); err != nil {
				return err
			}
		}
	}
}

// failReconfig records a rejected TLS change and puts the last working stored
// settings back, so a later restart does not trip over the same error.
func (s *httpServer) failReconfig(stage string, err error) {
	s.a.log.Error("TLS reconfiguration failed; keeping the last working configuration", "stage", stage, "err", err)
	s.a.audit(context.Background(), auditEntry{Actor: "system", Action: "settings.tls_reload_failed",
		Details: map[string]any{"stage": stage, "error": err.Error()}})
	s.mu.Lock()
	prev := s.lastGoodStored
	s.mu.Unlock()
	if prev != nil {
		if e := s.a.settings.Save(context.Background(), 0, keyTLS, prev); e != nil {
			s.a.log.Error("could not restore the last working TLS settings", "err", e)
		}
	}
}

// reconfigure applies changed TLS settings. The replacement is validated
// (certificate, key, bind) before the running listeners are touched; if it
// still fails to start, the last working configuration is restored. A plain
// HTTP listener is never substituted automatically. If even the restore fails
// the error is returned and the server exits rather than serve unprotected;
// the operator can recover with --force-http.
func (s *httpServer) reconfigure(errCh chan error) error {
	s.a.cfg.ForceHTTP = false
	next := s.effective()
	if err := s.validate(next); err != nil {
		s.failReconfig("validate", err)
		return nil
	}
	s.mu.Lock()
	prev := s.lastGood
	s.mu.Unlock()
	s.stopServers()
	if err := s.start(errCh, next); err != nil {
		s.failReconfig("start", err)
		if prev == nil {
			return fmt.Errorf("TLS reconfiguration failed and there is no earlier configuration to restore: %w", err)
		}
		if err2 := s.start(errCh, *prev); err2 != nil {
			s.a.audit(context.Background(), auditEntry{Actor: "system", Action: "settings.tls_restore_failed",
				Details: map[string]any{"error": err2.Error()}})
			return fmt.Errorf("TLS reconfiguration failed and the previous listener could not be restored (not falling back to plain HTTP; use --force-http to recover): %w", err2)
		}
		return nil
	}
	s.markGood(next)
	return nil
}

// bindAddr is the address the listeners for lc really bind.
func bindAddr(lc listenCfg) string {
	if lc.mode == "acme" {
		host, _, _ := net.SplitHostPort(lc.addr)
		return net.JoinHostPort(host, "443")
	}
	return lc.addr
}

func (s *httpServer) selfSignedNames(lc listenCfg) []string {
	names := append([]string{lc.t.Hostname}, lc.t.ExtraNames...)
	if host, _, err := net.SplitHostPort(lc.addr); err == nil && host != "" && host != "0.0.0.0" && host != "::" {
		names = append(names, host)
	}
	names = append(names, "localhost", "127.0.0.1")
	names = append(names, localIPs()...)
	return names
}

func (s *httpServer) serverCertificate(names []string) (*tls.Certificate, error) {
	if s.serverCert != nil {
		return s.serverCert(names)
	}
	return s.a.ca.ServerCertificate(names)
}

// validate checks a replacement configuration without disturbing the running
// listeners: the certificate and key load, and a new address can be bound.
func (s *httpServer) validate(lc listenCfg) error {
	switch lc.mode {
	case "http":
	case "selfsigned":
		if _, err := s.serverCertificate(s.selfSignedNames(lc)); err != nil {
			return fmt.Errorf("certificate: %w", err)
		}
	case "acme":
		if lc.t.Hostname == "" {
			return errors.New("ACME mode needs a hostname")
		}
	default:
		return errors.New("unknown TLS mode " + lc.mode)
	}
	s.mu.Lock()
	cur := ""
	if s.lastGood != nil {
		cur = bindAddr(*s.lastGood)
	}
	s.mu.Unlock()
	if addr := bindAddr(lc); addr != cur {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("bind %s: %w", addr, err)
		}
		_ = ln.Close()
	}
	return nil
}

func (s *httpServer) shutdown() {
	s.stopServers()
	s.grpc.Stop()
}

func (s *httpServer) stopServers() {
	s.mu.Lock()
	srvs := s.servers
	s.servers = nil
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, srv := range srvs {
		_ = srv.Shutdown(ctx)
		srv.Close()
	}
}

func (s *httpServer) listenAddr(t TLSSettings) string {
	if s.a.cfg.Listen != "" {
		return s.a.cfg.Listen
	}
	l := t.Listen
	if l == "" {
		l = "0.0.0.0:8080"
	}
	return l
}

func (s *httpServer) start(errCh chan error, lc listenCfg) error {
	a := s.a
	if s.failStart != nil {
		if err := s.failStart(lc); err != nil {
			return err
		}
	}
	t, mode, addr := lc.t, lc.mode, lc.addr
	clientCA := &tls.Config{
		ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs:  a.ca.Pool(),
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
	}
	newSrv := func(addr string, h http.Handler, tc *tls.Config) *http.Server {
		return &http.Server{Addr: addr, Handler: h, TLSConfig: tc, ReadHeaderTimeout: 15 * time.Second, IdleTimeout: 120 * time.Second,
			ErrorLog: nil}
	}
	var srvs []*http.Server
	switch mode {
	case "http":
		h2s := &http2.Server{IdleTimeout: 120 * time.Second}
		srv := newSrv(addr, h2c.NewHandler(s.handler, h2s), nil)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		go func() { errCh <- srv.Serve(ln) }()
		srvs = append(srvs, srv)
	case "selfsigned":
		names := s.selfSignedNames(lc)
		if _, err := s.serverCertificate(names); err != nil {
			return err
		}
		tc := clientCA.Clone()
		tc.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return a.ca.ServerCertificate(names) }
		srv := newSrv(addr, s.handler, tc)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		go func() { errCh <- srv.Serve(tls.NewListener(ln, tc)) }()
		srvs = append(srvs, srv)
	case "acme":
		if t.Hostname == "" {
			return errors.New("ACME mode needs a hostname")
		}
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(append([]string{t.Hostname}, t.ExtraNames...)...),
			Cache:      autocert.DirCache(filepath.Join(a.cfg.DataDir, "acme")),
			Email:      t.ACMEEmail,
		}
		if t.ACMEDirectory != "" {
			m.Client = &acme.Client{DirectoryURL: t.ACMEDirectory}
		}
		tc := clientCA.Clone()
		tc.GetCertificate = m.GetCertificate
		tc.NextProtos = []string{"h2", "http/1.1", acme.ALPNProto}
		host, port, _ := net.SplitHostPort(addr)
		if port != "443" {
			addr = net.JoinHostPort(host, "443")
		}
		srv := newSrv(addr, s.handler, tc)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		go func() { errCh <- srv.Serve(tls.NewListener(ln, tc)) }()
		srvs = append(srvs, srv)
		// Port 80: HTTP-01 challenges and redirect to HTTPS.
		redir := newSrv(net.JoinHostPort(host, "80"), m.HTTPHandler(nil), nil)
		if ln80, err := net.Listen("tcp", redir.Addr); err == nil {
			go func() { _ = redir.Serve(ln80) }()
			srvs = append(srvs, redir)
		} else {
			a.log.Warn("cannot bind :80 for ACME HTTP-01; relying on TLS-ALPN-01", "err", err)
		}
	default:
		return errors.New("unknown TLS mode " + mode)
	}
	s.mu.Lock()
	s.servers = srvs
	s.mode = mode
	s.addr = bindAddr(lc)
	s.mu.Unlock()
	a.log.Info("listening", "addr", addr, "tls_mode", mode)
	return nil
}

func localIPs() []string {
	var out []string
	addrs, _ := net.InterfaceAddrs()
	for _, ad := range addrs {
		if ipn, ok := ad.(*net.IPNet); ok && !ipn.IP.IsLoopback() && !ipn.IP.IsLinkLocalUnicast() {
			out = append(out, ipn.IP.String())
		}
	}
	return out
}

// buildHandler assembles the top-level router.
func (s *httpServer) buildHandler() http.Handler {
	a := s.a
	r := chi.NewRouter()
	r.Use(recoverer(a))
	r.Use(securityHeaders)
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		if err := a.db.Ping(); err != nil {
			// Unauthenticated: the driver's error text (paths, DSN) stays in the log.
			a.log.Error("healthz: database ping failed", "err", err)
			http.Error(w, "database unavailable", 503)
			return
		}
		w.Write([]byte("ok\n"))
	})

	api := chi.NewRouter()
	api.Use(a.auth.middleware)
	s.api = &apiRouter{a: a, mux: api}
	a.registerRoutes(s.api)
	api.Get("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, s.api.openAPI(a.publicURL(r)))
	})
	api.Get("/events", a.handleEvents)
	api.NotFound(func(w http.ResponseWriter, _ *http.Request) { writeError(w, errNotFound) })
	r.Mount("/api/v1", api)

	// Public heartbeat endpoint for push checks: the token is the credential.
	r.HandleFunc("/api/push/{token}", a.handlePush)
	r.Get("/download/agent/pkg/{file}", a.handleAgentPackage)
	r.Get("/download/agent/{os}/{arch}", a.handleAgentDownload)
	r.Get("/install/agent.sh", a.handleInstallScript("sh"))
	r.Get("/install/agent.ps1", a.handleInstallScript("ps1"))
	r.Get("/install/server.sh", a.handleInstallScript("server"))
	r.With(a.auth.middleware).Get("/metrics", a.handlePromMetrics)
	r.NotFound(a.serveUI)

	grpcH := gateGRPC(s.grpc, &preAuthLimiter{})
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.ProtoMajor == 2 && strings.HasPrefix(req.Header.Get("Content-Type"), "application/grpc") {
			grpcH.ServeHTTP(w, req)
			return
		}
		r.ServeHTTP(w, req)
	})
}

func recoverer(a *App) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					if rec == http.ErrAbortHandler {
						panic(rec)
					}
					a.log.Error("panic in handler", "path", r.URL.Path, "panic", rec)
					writeError(w, errors.New("panic"))
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		if !strings.HasPrefix(r.URL.Path, "/status/") {
			h.Set("X-Frame-Options", "DENY")
		}
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// publicURL returns the configured server URL, or one derived from the request.
func (a *App) publicURL(r *http.Request) string {
	if u := strings.TrimRight(a.settings.General().ServerURL, "/"); u != "" {
		return u
	}
	scheme := "http"
	if a.isHTTPS(r) {
		scheme = "https"
	}
	host := r.Host
	if a.fromTrustedProxy(r) && r.Header.Get("X-Forwarded-Host") != "" {
		host = r.Header.Get("X-Forwarded-Host")
	}
	return scheme + "://" + host
}

// serveUI serves the embedded single-page app.
func (a *App) serveUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "not found", 404)
		return
	}
	var fsys fs.FS
	if a.cfg.DevUIDir != "" {
		fsys = os.DirFS(a.cfg.DevUIDir)
	} else {
		sub, err := fs.Sub(web.Dist, "dist")
		if err != nil {
			http.Error(w, "UI not built", 500)
			return
		}
		fsys = sub
	}
	p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if p == "" {
		p = "index.html"
	}
	f, err := fsys.Open(p)
	if err != nil || strings.HasSuffix(p, "/") {
		p = "index.html"
		f, err = fsys.Open(p)
		if err != nil {
			http.Error(w, "UI not built: run scripts/build.sh", 500)
			return
		}
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.IsDir() {
		f.Close()
		p = "index.html"
		if f, err = fsys.Open(p); err != nil {
			http.Error(w, "not found", 404)
			return
		}
	}
	ct := mime.TypeByExtension(path.Ext(p))
	if ct == "" {
		ct = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ct)
	if strings.HasPrefix(p, "assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	if p == "index.html" {
		csp := "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; base-uri 'self'; form-action 'self'"
		if !strings.HasPrefix(r.URL.Path, "/status/") {
			csp += "; frame-ancestors 'none'" // status pages may be embedded
		}
		w.Header().Set("Content-Security-Policy", csp)
	}
	if rs, ok := f.(io.ReadSeeker); ok {
		http.ServeContent(w, r, p, time.Time{}, rs)
		return
	}
	io.Copy(w, f)
}
