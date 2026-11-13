package gateway

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

var (
	// ErrNotAllowed means the destination is not in egress.allow.
	ErrNotAllowed = errors.New("host not in egress.allow")
	// ErrPlainHTTP means an http:// URL named a host that is not loopback.
	ErrPlainHTTP = errors.New("plain http is allowed only to localhost and loopback addresses")
	// ErrInvalidHost means a host is not a canonical IP literal or DNS name.
	ErrInvalidHost = errors.New("invalid host")
)

// endpoint is one allowlisted destination after normalization.
type endpoint struct {
	host string // lowercase DNS name or canonical IP text
	port string // "" means the default port of the request's scheme
}

// allowlist is egress.allow after normalization. An IP-literal entry permits
// only requests whose URL names that IP and port; it never vouches for a DNS
// name that resolves to the same address (see dial.go).
type allowlist struct {
	endpoints map[endpoint]bool
}

func parseAllowlist(entries []string) (allowlist, error) {
	a := allowlist{endpoints: map[endpoint]bool{}}
	for _, s := range entries {
		e, err := parseEntry(s)
		if err != nil {
			return allowlist{}, fmt.Errorf("egress.allow entry %q: %w", s, err)
		}
		a.endpoints[e] = true
	}
	return a, nil
}

// parseEntry accepts host, host:port, a bare IP (IPv6 too) or [IPv6]:port.
func parseEntry(s string) (endpoint, error) {
	host, port := s, ""
	switch {
	case isIPLiteral(s):
	case strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]"):
		host = s[1 : len(s)-1]
	case strings.Contains(s, ":"):
		h, p, err := net.SplitHostPort(s)
		if err != nil {
			return endpoint{}, fmt.Errorf("%w: %w", ErrInvalidHost, err)
		}
		if err := checkPort(p); err != nil {
			return endpoint{}, err
		}
		host, port = h, p
	}
	h, err := normalizeHost(host)
	if err != nil {
		return endpoint{}, err
	}
	return endpoint{host: h, port: port}, nil
}

func isIPLiteral(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

// normalizeHost lowercases a host and drops one trailing dot. IP literals are
// accepted only in canonical dotted or IPv6 form, without a zone; IPv4-mapped
// IPv6 becomes plain IPv4 so one address has one spelling.
func normalizeHost(h string) (string, error) {
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	if ip, err := netip.ParseAddr(h); err == nil {
		if ip.Zone() != "" {
			return "", fmt.Errorf("%w %q: zoned addresses are not supported", ErrInvalidHost, h)
		}
		return ip.Unmap().String(), nil
	}
	if !validDNSName(h) {
		return "", fmt.Errorf("%w %q: want a DNS name or a canonical IP address", ErrInvalidHost, h)
	}
	return h, nil
}

// validDNSName accepts LDH labels only. The last label must start with a
// letter, which rejects every numeric host form ("2130706433", "0x7f.1",
// "127.1", "0177.0.0.1") that some resolvers would turn into an address.
func validDNSName(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if !validLabel(l) {
			return false
		}
	}
	last := labels[len(labels)-1]
	return last[0] >= 'a' && last[0] <= 'z'
}

func validLabel(l string) bool {
	if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for _, r := range l {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-'
		if !ok {
			return false
		}
	}
	return true
}

// checkPort accepts a canonical decimal port, so "0443" cannot dodge a match.
func checkPort(p string) error {
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != p {
		return fmt.Errorf("%w: port %q", ErrInvalidHost, p)
	}
	return nil
}

// isLoopbackHost is the only exemption from TLS: the exact name "localhost"
// (never resolved, see dial.go), 127.0.0.0/8 and ::1. "localhost.example"
// and names that merely resolve to loopback are not loopback hosts.
func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(h)
	return err == nil && ip.IsLoopback()
}

func defaultPort(scheme string) string {
	if scheme == "http" {
		return "80"
	}
	return "443"
}

// checkURL runs before any DNS lookup or dial: scheme, allowlist, then TLS.
func (a allowlist) checkURL(u *url.URL) error {
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme %q: want http or https", u.Scheme)
	}
	host, port, err := hostPort(u)
	if err != nil {
		return err
	}
	exact := a.endpoints[endpoint{host, port}]
	bare := port == defaultPort(u.Scheme) && a.endpoints[endpoint{host, ""}]
	if !exact && !bare {
		return fmt.Errorf("%q: %w", net.JoinHostPort(host, port), ErrNotAllowed)
	}
	if u.Scheme == "http" && !isLoopbackHost(host) {
		return fmt.Errorf("%q: %w", host, ErrPlainHTTP)
	}
	return nil
}

// permitsDial repeats the allowlist check where the scheme is unknown; a bare
// entry then covers both default ports, and checkURL already chose one.
func (a allowlist) permitsDial(host, port string) bool {
	if a.endpoints[endpoint{host, port}] {
		return true
	}
	return a.endpoints[endpoint{host, ""}] && (port == "80" || port == "443")
}

// hostPort returns the normalized host and the effective port of u.
func hostPort(u *url.URL) (string, string, error) {
	host, err := normalizeHost(u.Hostname())
	if err != nil {
		return "", "", err
	}
	port := u.Port()
	if port == "" {
		return host, defaultPort(u.Scheme), nil
	}
	if err := checkPort(port); err != nil {
		return "", "", err
	}
	return host, port, nil
}
