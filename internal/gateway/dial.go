package gateway

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
)

// ErrPrivateAddress means a DNS answer pointed an allowlisted name at a
// loopback, private, link-local or otherwise non-public address.
var ErrPrivateAddress = errors.New("resolved to a non-public address not listed in egress.allow")

// Resolver is the subset of *net.Resolver the gateway uses. Tests inject one
// to count lookups and to change answers between calls.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// DialFunc opens a TCP connection to an IP:port address.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// localhostAddrs is what "localhost" means; the name is never resolved, so a
// hosts file or resolver cannot point it elsewhere.
var localhostAddrs = []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::1")}

// pinningDialer resolves each allowlisted host once and dials only the pinned
// addresses for the life of the client, so a later DNS answer (rebinding)
// cannot move the connection. TLS still runs over the hostname: the
// transport sets SNI and verifies the certificate against the URL host.
type pinningDialer struct {
	allow    allowlist
	resolver Resolver
	dial     DialFunc

	mu     sync.Mutex
	pinned map[string][]netip.Addr
}

func (d *pinningDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	h, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("dial %q: %w", addr, err)
	}
	host, err := normalizeHost(h)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	if !d.allow.permitsDial(host, port) {
		return nil, fmt.Errorf("dial %q: %w", addr, ErrNotAllowed)
	}
	addrs, err := d.pin(ctx, host)
	if err != nil {
		return nil, err
	}
	return d.dialFirst(ctx, network, addrs, port)
}

// pin returns the cached addresses of host, resolving on first use only.
// The lock is held across the lookup so concurrent first calls resolve once.
func (d *pinningDialer) pin(ctx context.Context, host string) ([]netip.Addr, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if addrs, ok := d.pinned[host]; ok {
		return addrs, nil
	}
	addrs, err := d.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	d.pinned[host] = addrs
	return addrs, nil
}

func (d *pinningDialer) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if host == "localhost" {
		return localhostAddrs, nil
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}
	found, err := d.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", host, err)
	}
	return d.checkResolved(host, found)
}

// checkResolved refuses the whole answer if any address is non-public and
// not explicitly allowlisted: a mixed answer is itself a rebinding signal.
func (d *pinningDialer) checkResolved(host string, found []netip.Addr) ([]netip.Addr, error) {
	if len(found) == 0 {
		return nil, fmt.Errorf("resolve %q: no addresses", host)
	}
	addrs := make([]netip.Addr, 0, len(found))
	for _, ip := range found {
		ip = ip.Unmap().WithZone("")
		if !publicAddr(ip) && !d.allow.ips[ip] {
			return nil, fmt.Errorf("resolve %q: %s: %w", host, ip, ErrPrivateAddress)
		}
		addrs = append(addrs, ip)
	}
	return addrs, nil
}

func (d *pinningDialer) dialFirst(ctx context.Context, network string, addrs []netip.Addr, port string) (net.Conn, error) {
	var errs []error
	for _, ip := range addrs {
		conn, err := d.dial(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		errs = append(errs, err)
	}
	return nil, fmt.Errorf("dial pinned addresses: %w", errors.Join(errs...))
}
