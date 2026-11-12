package app

import (
	"context"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	pb "sentrel/gen/sentrelv1"
	"sentrel/internal/sigs"
	"sentrel/internal/version"
	"sentrel/server/db"
	"sentrel/server/pki"
)

// Hub tracks connected agents and implements the gRPC AgentService.
type Hub struct {
	pb.UnimplementedAgentServiceServer
	app *App

	mu    sync.RWMutex
	conns map[int64]*agentConn

	helloMu   sync.Mutex
	lastHello map[string]int64 // agent_id -> last accepted hello unix_ms (replay guard)

	regLimiter *rateLimiter
}

type agentConn struct {
	hostID      int64
	tenantID    int64
	agentID     string
	remote      string
	send        chan *pb.ServerMessage
	cancel      context.CancelFunc
	connectedAt time.Time
	viaMTLS     bool
}

// acceptHello records ms as the newest hello for the agent and reports false if
// it is not newer than the last accepted one. The value is persisted so a
// restart does not reopen the replay window.
func (h *Hub) acceptHello(ctx context.Context, agentID string, ms int64) bool {
	h.helloMu.Lock()
	defer h.helloMu.Unlock()
	last, ok := h.lastHello[agentID]
	if !ok {
		_ = h.app.db.GetContext(ctx, &last, `SELECT last_ms FROM agent_hello WHERE agent_id=?`, agentID)
	}
	if ms <= last {
		h.lastHello[agentID] = last
		return false
	}
	h.lastHello[agentID] = ms
	_, _ = h.app.db.ExecContext(ctx, `INSERT INTO agent_hello (agent_id, last_ms, updated_at) VALUES (?,?,?)
		ON CONFLICT(agent_id) DO UPDATE SET last_ms=excluded.last_ms, updated_at=excluded.updated_at`, agentID, ms, db.Now())
	return true
}

func newHub(a *App) *Hub {
	return &Hub{
		app:        a,
		conns:      map[int64]*agentConn{},
		lastHello:  map[string]int64{},
		regLimiter: newRateLimiter(20, time.Minute),
	}
}

var protoJSON = protojson.MarshalOptions{UseProtoNames: true, EmitUnpopulated: false}

func peerAddr(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		if h, _, err := net.SplitHostPort(p.Addr.String()); err == nil {
			return h
		}
		return p.Addr.String()
	}
	return ""
}

// Register enrols a new agent.
func (h *Hub) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	ip := peerAddr(ctx)
	if !h.regLimiter.Allow(ip) {
		return nil, status.Error(codes.ResourceExhausted, "too many registration attempts")
	}
	if req.SchemaVersion != uint32(pb.SchemaVersion_SCHEMA_VERSION_CURRENT) {
		return nil, status.Errorf(codes.FailedPrecondition, "unsupported schema version %d", req.SchemaVersion)
	}
	tok := normaliseToken(req.Token)
	if tok == "" || req.Host == nil {
		return nil, status.Error(codes.InvalidArgument, "token and host info are required")
	}
	a := h.app
	var et EnrollmentToken
	err := a.db.GetContext(ctx, &et, `SELECT * FROM enrollment_tokens WHERE token_hash=?`, hashToken(tok))
	if errors.Is(err, sql.ErrNoRows) || (err == nil && (et.UsedAt != 0 || et.ExpiresAt < db.Now())) {
		a.log.Warn("agent registration rejected", "ip", ip, "reason", "invalid or expired token")
		return nil, status.Error(codes.PermissionDenied, "invalid or expired enrollment token")
	} else if err != nil {
		return nil, status.Error(codes.Internal, "database error")
	}
	agentID := uuid.NewString()
	certPEM, serial, notAfter, err := a.ca.SignAgentCSR(req.CsrPem, agentID)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "csr: %v", err)
	}
	info, _ := protoJSON.Marshal(req.Host)
	name := et.HostName
	if name == "" {
		name = req.Host.Hostname
	}
	// Both values come from the agent and are shown in the UI and in
	// notifications, so keep them to what a host name and an address look like.
	name = cleanHostName(name)
	addr := ""
	if len(req.Host.IpAddresses) > 0 && net.ParseIP(req.Host.IpAddresses[0]) != nil {
		addr = req.Host.IpAddresses[0]
	}
	var hostID int64
	now := db.Now()
	err = a.db.Tx(ctx, func(tx *sqlxTx) error {
		res, err := tx.ExecContext(ctx, `UPDATE enrollment_tokens SET used_at=? WHERE id=? AND used_at=0`, now, et.ID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return errTokenUsed
		}
		r, err := tx.ExecContext(ctx, `INSERT INTO hosts (tenant_id, kind, name, address, group_id, tags, agent_id, cert_serial, cert_expires_at,
			host_info, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			et.TenantID, "agent", name, addr, et.GroupID, et.Tags, agentID, serial, notAfter.Unix(), string(info), "pending", now, now)
		if err != nil {
			return err
		}
		hostID, _ = r.LastInsertId()
		_, err = tx.ExecContext(ctx, `UPDATE enrollment_tokens SET used_by_host=? WHERE id=?`, hostID, et.ID)
		return err
	})
	if errors.Is(err, errTokenUsed) {
		return nil, status.Error(codes.PermissionDenied, "invalid or expired enrollment token")
	}
	if err != nil {
		a.log.Error("register", "err", err)
		return nil, status.Error(codes.Internal, "could not create host")
	}
	a.audit(ctx, auditEntry{TenantID: et.TenantID, Actor: "agent:" + name, Action: "host.enrolled", TargetType: "host", TargetID: itoa(hostID),
		Details: map[string]any{"hostname": req.Host.Hostname, "os": req.Host.Os, "platform": req.Host.Platform, "ip": ip}, IP: ip})
	a.log.Info("agent registered", "host_id", hostID, "name", name, "ip", ip)
	host, _ := a.getHost(ctx, hostID)
	return &pb.RegisterResponse{
		AgentId:      agentID,
		CertPem:      certPEM,
		CaPem:        a.ca.CertPEM,
		JobPublicKey: a.ca.JobPublicKey(),
		Config:       a.agentConfig(host),
	}, nil
}

var errTokenUsed = errors.New("token already used")

func normaliseToken(t string) string {
	t = strings.ToUpper(strings.TrimSpace(t))
	t = strings.ReplaceAll(t, " ", "")
	return t
}

// authenticate verifies the hello and returns the host.
func (h *Hub) authenticate(ctx context.Context, hello *pb.Hello) (*Host, bool, error) {
	var cert *x509.Certificate
	viaTLS := false
	if p, ok := peer.FromContext(ctx); ok {
		if ti, ok := p.AuthInfo.(credentials.TLSInfo); ok && len(ti.State.PeerCertificates) > 0 {
			cert = ti.State.PeerCertificates[0]
			viaTLS = true
		}
	}
	if cert == nil {
		c, err := pki.ParseCertPEM(hello.CertPem)
		if err != nil {
			return nil, false, errors.New("no client certificate")
		}
		if err := pki.VerifySignature(c, sigs.HelloMessage(hello.AgentId, hello.UnixMs), hello.Signature); err != nil {
			return nil, false, errors.New("hello signature invalid")
		}
		skew := time.Since(time.UnixMilli(hello.UnixMs))
		if skew > 5*time.Minute || skew < -5*time.Minute {
			return nil, false, fmt.Errorf("clock skew too large (%s); check NTP on the agent host", skew.Round(time.Second))
		}
		cert = c
	}
	agentID, serial, err := h.app.ca.VerifyAgentCert(cert)
	if err != nil {
		return nil, false, fmt.Errorf("certificate: %w", err)
	}
	if agentID != hello.AgentId {
		return nil, false, errors.New("agent id does not match certificate")
	}
	var revoked int
	_ = h.app.db.GetContext(ctx, &revoked, `SELECT COUNT(*) FROM revoked_certs WHERE serial=?`, serial)
	if revoked > 0 {
		return nil, false, errRevoked
	}
	host, err := h.app.getHostByAgentID(ctx, agentID)
	if err != nil {
		return nil, false, errRevoked // host deleted
	}
	if host.Revoked || host.CertSerial != serial {
		return nil, false, errRevoked
	}
	// Only a fully authenticated hello (chain, ID binding, revocation, host)
	// may touch replay state; otherwise a forged hello could poison it.
	if !viaTLS && !h.acceptHello(ctx, hello.AgentId, hello.UnixMs) {
		return nil, false, errors.New("replayed hello")
	}
	return host, viaTLS, nil
}

var errRevoked = errors.New("agent certificate revoked or host deleted")

// Connect handles the long-lived agent stream.
func (h *Hub) Connect(stream pb.AgentService_ConnectServer) error {
	ctx := stream.Context()
	ip := peerAddr(ctx)
	firstCh := make(chan *pb.AgentMessage, 1)
	errCh := make(chan error, 1)
	go func() {
		m, err := stream.Recv()
		if err != nil {
			errCh <- err
			return
		}
		firstCh <- m
	}()
	var first *pb.AgentMessage
	select {
	case first = <-firstCh:
	case err := <-errCh:
		return err
	case <-time.After(20 * time.Second):
		return status.Error(codes.DeadlineExceeded, "hello timeout")
	}
	hello := first.GetHello()
	if hello == nil {
		return status.Error(codes.InvalidArgument, "first message must be hello")
	}
	if hello.SchemaVersion != uint32(pb.SchemaVersion_SCHEMA_VERSION_CURRENT) {
		return status.Errorf(codes.FailedPrecondition, "unsupported schema version %d", hello.SchemaVersion)
	}
	host, viaTLS, err := h.authenticate(ctx, hello)
	if errors.Is(err, errRevoked) {
		_ = stream.Send(&pb.ServerMessage{Msg: &pb.ServerMessage_Goodbye{Goodbye: &pb.Goodbye{Reason: "revoked", Revoked: true}}})
		h.app.log.Warn("rejected revoked agent", "agent_id", hello.AgentId, "ip", ip)
		return status.Error(codes.PermissionDenied, err.Error())
	}
	if err != nil {
		h.app.log.Warn("agent auth failed", "agent_id", hello.AgentId, "ip", ip, "err", err)
		return status.Error(codes.Unauthenticated, err.Error())
	}
	// Authenticated: lift the pre-auth size limit and free the slot.
	releaseGRPCGate(ctx)
	a := h.app
	cfg := a.agentConfig(host)
	welcome := &pb.ServerMessage{Msg: &pb.ServerMessage_Welcome{Welcome: &pb.Welcome{
		HostId: itoa(host.ID), Config: cfg, ServerUnixMs: time.Now().UnixMilli(), ServerVersion: version.Version,
	}}}
	if hello.SelfTest {
		_ = stream.Send(welcome)
		_ = stream.Send(&pb.ServerMessage{Msg: &pb.ServerMessage_Goodbye{Goodbye: &pb.Goodbye{Reason: "self-test ok"}}})
		return nil
	}

	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	conn := &agentConn{hostID: host.ID, tenantID: host.TenantID, agentID: hello.AgentId, remote: ip,
		send: make(chan *pb.ServerMessage, 64), cancel: cancel, connectedAt: time.Now(), viaMTLS: viaTLS}
	h.mu.Lock()
	if old, ok := h.conns[host.ID]; ok {
		old.cancel()
	}
	h.conns[host.ID] = conn
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		if h.conns[host.ID] == conn {
			delete(h.conns, host.ID)
			h.mu.Unlock()
			a.onAgentDisconnected(host.ID)
		} else {
			h.mu.Unlock()
		}
	}()

	a.onAgentConnected(ctx, host, hello, ip)
	if err := stream.Send(welcome); err != nil {
		return err
	}

	// Sender.
	sendErr := make(chan error, 1)
	go func() {
		ping := time.NewTicker(30 * time.Second)
		defer ping.Stop()
		for {
			select {
			case <-cctx.Done():
				sendErr <- nil
				return
			case m := <-conn.send:
				if err := stream.Send(m); err != nil {
					sendErr <- err
					cancel()
					return
				}
			case <-ping.C:
				if err := stream.Send(&pb.ServerMessage{Msg: &pb.ServerMessage_Ping{Ping: &pb.Ping{UnixMs: time.Now().UnixMilli()}}}); err != nil {
					sendErr <- err
					cancel()
					return
				}
			}
		}
	}()

	// Jobs that were queued while the agent was offline.
	a.jobs.kick()

	recvCh := make(chan *pb.AgentMessage)
	recvErr := make(chan error, 1)
	go func() {
		for {
			m, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			select {
			case recvCh <- m:
			case <-cctx.Done():
				return
			}
		}
	}()
	for {
		select {
		case <-cctx.Done():
			return nil
		case err := <-sendErr:
			return err
		case err := <-recvErr:
			return err
		case m := <-recvCh:
			a.handleAgentMessage(cctx, host.ID, m)
		}
	}
}

// Send queues a message for a connected agent. It returns false if the
// agent is not connected or its queue is full.
func (h *Hub) Send(hostID int64, m *pb.ServerMessage) bool {
	h.mu.RLock()
	c, ok := h.conns[hostID]
	h.mu.RUnlock()
	if !ok {
		return false
	}
	select {
	case c.send <- m:
		return true
	default:
		return false
	}
}

// Connected reports whether a host has a live stream.
func (h *Hub) Connected(hostID int64) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	_, ok := h.conns[hostID]
	return ok
}

// ConnInfo returns details about a live connection.
func (h *Hub) ConnInfo(hostID int64) (remote string, since time.Time, mtls bool, ok bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	c, ok := h.conns[hostID]
	if !ok {
		return "", time.Time{}, false, false
	}
	return c.remote, c.connectedAt, c.viaMTLS, true
}

// Disconnect drops a host's stream (e.g. after revocation).
func (h *Hub) Disconnect(hostID int64, reason string, revoked bool) {
	h.mu.RLock()
	c, ok := h.conns[hostID]
	h.mu.RUnlock()
	if !ok {
		return
	}
	select {
	case c.send <- &pb.ServerMessage{Msg: &pb.ServerMessage_Goodbye{Goodbye: &pb.Goodbye{Reason: reason, Revoked: revoked}}}:
	default:
	}
	time.AfterFunc(2*time.Second, c.cancel)
}

// PushConfig sends the current config to a connected host.
func (h *Hub) PushConfig(ctx context.Context, hostID int64) {
	host, err := h.app.getHost(ctx, hostID)
	if err != nil {
		return
	}
	h.Send(hostID, &pb.ServerMessage{Msg: &pb.ServerMessage_Config{Config: h.app.agentConfig(host)}})
}

// PushConfigAll sends config to every connected agent (after defaults change).
func (h *Hub) PushConfigAll(ctx context.Context) {
	h.mu.RLock()
	ids := make([]int64, 0, len(h.conns))
	for id := range h.conns {
		ids = append(ids, id)
	}
	h.mu.RUnlock()
	for _, id := range ids {
		h.PushConfig(ctx, id)
	}
}

// ConnectedCount returns the number of live agent streams.
func (h *Hub) ConnectedCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.conns)
}

// ConnectedCountTenant counts live agent streams of one tenant; tenant 0
// (the provider) sees all of them.
func (h *Hub) ConnectedCountTenant(tenantID int64) int {
	if tenantID == 0 {
		return h.ConnectedCount()
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	n := 0
	for _, c := range h.conns {
		if c.tenantID == tenantID {
			n++
		}
	}
	return n
}

// rateLimiter is a fixed-window limiter keyed by string.
type rateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	hits   map[string][]time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{limit: limit, window: window, hits: map[string][]time.Time{}}
}

func (r *rateLimiter) Allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	h := r.hits[key]
	i := 0
	for i < len(h) && now.Sub(h[i]) > r.window {
		i++
	}
	h = h[i:]
	if len(h) >= r.limit {
		r.hits[key] = h
		return false
	}
	r.hits[key] = append(h, now)
	if len(r.hits) > 10000 {
		for k, v := range r.hits {
			if len(v) == 0 || now.Sub(v[len(v)-1]) > r.window {
				delete(r.hits, k)
			}
		}
	}
	return true
}

// Count returns hits within the window without recording one.
func (r *rateLimiter) Count(key string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	n := 0
	for _, t := range r.hits[key] {
		if now.Sub(t) <= r.window {
			n++
		}
	}
	return n
}

// SetWindow changes the window length.
func (r *rateLimiter) SetWindow(d time.Duration) {
	if d <= 0 {
		return
	}
	r.mu.Lock()
	r.window = d
	r.mu.Unlock()
}

func (r *rateLimiter) Reset(key string) {
	r.mu.Lock()
	delete(r.hits, key)
	r.mu.Unlock()
}

// cleanHostName reduces an agent-reported host name to letters, digits and
// "-", "." and "_", at most 253 characters.
func cleanHostName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= 253 {
			break
		}
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '.' || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "unnamed-host"
	}
	return b.String()
}
