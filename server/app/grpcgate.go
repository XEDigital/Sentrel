package app

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
)

// An agent connection may send very little until it has authenticated. The
// gRPC message limit has to allow large inventory reports, so without this an
// unauthenticated peer could make the server buffer a full-size message per
// connection.
const (
	// preAuthBodyLimit is how many request-body bytes a gRPC call may send
	// before authentication. A hello or an enrolment request is a few KB.
	preAuthBodyLimit = 128 << 10
	// preAuthStreams and preAuthStreamsPerIP cap calls that have not
	// authenticated yet, in total and per source address.
	preAuthStreams      = 512
	preAuthStreamsPerIP = 64
)

var errPreAuthTooLarge = errors.New("request too large before authentication")

type grpcGateKey struct{}

// grpcGate limits one gRPC request body until release is called.
type grpcGate struct {
	io.ReadCloser
	left     atomic.Int64 // bytes still allowed before authentication
	open     atomic.Bool
	once     sync.Once
	onSettle func()
}

func (g *grpcGate) Read(p []byte) (int, error) {
	if g.open.Load() {
		return g.ReadCloser.Read(p)
	}
	left := g.left.Load()
	if left <= 0 {
		return 0, errPreAuthTooLarge
	}
	if int64(len(p)) > left {
		p = p[:left]
	}
	n, err := g.ReadCloser.Read(p)
	g.left.Add(-int64(n))
	return n, err
}

// settle frees the pre-auth slot; safe to call more than once.
func (g *grpcGate) settle() {
	g.once.Do(func() {
		if g.onSettle != nil {
			g.onSettle()
		}
	})
}

// releaseGRPCGate lifts the pre-auth limits for the call behind ctx. Call it
// once the peer has authenticated.
func releaseGRPCGate(ctx context.Context) {
	if g, ok := ctx.Value(grpcGateKey{}).(*grpcGate); ok {
		g.open.Store(true)
		g.settle()
	}
}

// preAuthLimiter counts calls that have not authenticated yet.
type preAuthLimiter struct {
	mu    sync.Mutex
	total int
	perIP map[string]int
}

func (l *preAuthLimiter) acquire(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total >= preAuthStreams || l.perIP[ip] >= preAuthStreamsPerIP {
		return false
	}
	if l.perIP == nil {
		l.perIP = map[string]int{}
	}
	l.total++
	l.perIP[ip]++
	return true
}

func (l *preAuthLimiter) release(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.total--
	if l.perIP[ip]--; l.perIP[ip] <= 0 {
		delete(l.perIP, ip)
	}
}

// gateGRPC wraps the gRPC handler with the pre-auth limits.
func gateGRPC(next http.Handler, lim *preAuthLimiter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if h, _, err := net.SplitHostPort(ip); err == nil {
			ip = h
		}
		if !lim.acquire(ip) {
			// A gRPC client reads the status from these headers.
			w.Header().Set("Content-Type", "application/grpc")
			w.Header().Set("Grpc-Status", "8") // RESOURCE_EXHAUSTED
			w.Header().Set("Grpc-Message", "too many unauthenticated connections")
			w.WriteHeader(http.StatusOK)
			return
		}
		g := &grpcGate{ReadCloser: r.Body, onSettle: func() { lim.release(ip) }}
		g.left.Store(preAuthBodyLimit)
		defer g.settle()
		r = r.WithContext(context.WithValue(r.Context(), grpcGateKey{}, g))
		r.Body = g
		next.ServeHTTP(w, r)
	})
}
