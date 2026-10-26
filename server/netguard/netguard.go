// Package netguard restricts where server-side network clients may connect.
//
// Probes and notification channels owned by a tenant are user-controlled
// destinations. Without a guard they can be pointed at loopback services,
// the LAN or a cloud metadata endpoint (SSRF). The guard is enforced inside
// the dialer's Control hook, which runs after DNS resolution and before the
// socket connects, so DNS rebinding and redirects cannot bypass it.
package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// Guard is the target policy for one caller. The zero value is the strict
// tenant policy; provider (tenant 0) objects use Allow.
type Guard struct {
	AllowPrivate bool
}

// Allow permits every destination (provider-owned objects).
var Allow = Guard{AllowPrivate: true}

// Strict blocks non-public destinations.
var Strict = Guard{}

// ErrBlocked is wrapped by every rejection.
var ErrBlocked = errors.New("target address is not allowed")

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// Check returns an error if ip is not an acceptable destination.
func (g Guard) Check(ip net.IP) error {
	if g.AllowPrivate {
		return nil
	}
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return fmt.Errorf("%w: invalid address", ErrBlocked)
	}
	a = a.Unmap()
	if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsInterfaceLocalMulticast() || a.IsMulticast() || a.IsUnspecified() || cgnat.Contains(a) {
		return fmt.Errorf("%w: %s is a private, loopback or link-local address (tenants may only target public addresses)", ErrBlocked, a)
	}
	return nil
}

// Control is a net.Dialer.Control hook; address is the already-resolved ip:port.
func (g Guard) Control(network, address string, _ syscall.RawConn) error {
	if g.AllowPrivate {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBlocked, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("%w: %q is not an IP address", ErrBlocked, host)
	}
	return g.Check(ip)
}

// Dialer returns a dialer that enforces the guard.
func (g Guard) Dialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout, Control: g.Control}
}

// DialContext dials through a guarded dialer.
func (g Guard) DialContext(timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return g.Dialer(timeout).DialContext
}

// Transport returns an HTTP transport that enforces the guard. Environment
// proxies are only honoured when private targets are allowed, because a proxy
// would hide the real destination from the dialer.
func (g Guard) Transport(base *http.Transport) *http.Transport {
	if base == nil {
		base = &http.Transport{}
	}
	base.DialContext = g.Dialer(15 * time.Second).DialContext
	if g.AllowPrivate {
		if base.Proxy == nil {
			base.Proxy = http.ProxyFromEnvironment
		}
	} else {
		base.Proxy = nil
	}
	return base
}

// LocalDialer confines health probes to this machine, after DNS resolution.
// It must accompany TLS verification exceptions for local self-signed health
// checks; redirects must also be disabled by the HTTP client.
func LocalDialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout, Control: func(network, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("%w: invalid health probe address", ErrBlocked)
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return fmt.Errorf("%w: health probe address must be resolved", ErrBlocked)
		}
		if ip.IsLoopback() {
			return nil
		}
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			return err
		}
		for _, addr := range addrs {
			if subnet, ok := addr.(*net.IPNet); ok && subnet.IP.Equal(ip) {
				return nil
			}
		}
		return fmt.Errorf("%w: health probes may only connect to this machine", ErrBlocked)
	}}
}
