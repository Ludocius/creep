package gateway

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// ErrRedirect means a response redirected to another scheme, host or port.
var ErrRedirect = errors.New("redirect to another origin refused")

const maxRedirects = 10

// Default timeouts, so a stalled endpoint cannot hang a scan. They are
// constants until the token-budget work (#84) gives them config keys. The
// response-header wait is long because a non-streaming model answer arrives
// only when generation ends.
const (
	dialTimeout           = 10 * time.Second
	tlsHandshakeTimeout   = 10 * time.Second
	responseHeaderTimeout = 5 * time.Minute
	idleConnTimeout       = 90 * time.Second
)

// Options configures NewClient. Only Allow comes from configuration
// (egress.allow); the rest exist so tests can run without real DNS or
// network and default to the system resolver, dialer and roots.
type Options struct {
	Allow    []string
	Resolver Resolver
	Dial     DialFunc
	RootCAs  *x509.CertPool
}

// Client is the handle Send uses to reach a model. It is opaque on purpose:
// it has no HTTP methods and exposes no *http.Client, so code outside the
// gateway can send a model request only through EgressLog.Send, which checks
// consent and writes egress.log first.
type Client struct {
	hc *http.Client
}

// CloseIdleConnections closes idle keep-alive connections.
func (c *Client) CloseIdleConnections() {
	c.hc.CloseIdleConnections()
}

// NewClient returns the only client creep uses to reach a model; see
// newHTTPClient for what it enforces.
func NewClient(opts Options) (*Client, error) {
	hc, err := newHTTPClient(opts)
	if err != nil {
		return nil, err
	}
	return &Client{hc: hc}, nil
}

// newHTTPClient builds the allowlisted, pinned HTTP client.
//
// Proxy environment variables (HTTP_PROXY, HTTPS_PROXY, NO_PROXY, ALL_PROXY)
// are ignored: a proxy would receive the hostname and resolve it itself,
// bypassing the allowlist's address checks and IP pinning, and routing
// scanned code through a host the user never listed. Proxy support, if it
// comes, will be an explicit config key that is itself allowlisted.
func newHTTPClient(opts Options) (*http.Client, error) {
	allow, err := parseAllowlist(opts.Allow)
	if err != nil {
		return nil, fmt.Errorf("gateway client: %w", err)
	}
	d := &pinningDialer{
		allow:    allow,
		resolver: opts.Resolver,
		dial:     opts.Dial,
		pinned:   map[string]*pin{},
	}
	if d.resolver == nil {
		d.resolver = net.DefaultResolver
	}
	if d.dial == nil {
		d.dial = (&net.Dialer{Timeout: dialTimeout}).DialContext
	}
	return &http.Client{
		Transport:     guard{allow: allow, next: newTransport(d, opts.RootCAs)},
		CheckRedirect: sameOrigin,
	}, nil
}

func newTransport(d *pinningDialer, roots *x509.CertPool) *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           d.DialContext,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout:   tlsHandshakeTimeout,
		ResponseHeaderTimeout: responseHeaderTimeout,
		IdleConnTimeout:       idleConnTimeout,
		MaxIdleConns:          16,
	}
}

// guard checks every request, redirects included, before the transport can
// resolve or dial anything.
type guard struct {
	allow allowlist
	next  http.RoundTripper
}

func (g guard) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := g.allow.checkURL(req.URL); err != nil {
		// A RoundTripper must close the request body, even on error.
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, fmt.Errorf("gateway: %w", err)
	}
	return g.next.RoundTrip(req)
}

// CloseIdleConnections lets http.Client.CloseIdleConnections reach the
// transport through the guard.
func (g guard) CloseIdleConnections() {
	if c, ok := g.next.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

// sameOrigin allows a redirect only to the same scheme, host and port as the
// first request. A scheme change is refused both ways: https→http is a
// downgrade, and http→https on loopback is never needed.
func sameOrigin(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("gateway: stopped after %d redirects", maxRedirects)
	}
	from, err := origin(via[0].URL)
	if err != nil {
		return fmt.Errorf("gateway: %w", err)
	}
	to, err := origin(req.URL)
	if err != nil || to != from {
		return fmt.Errorf("gateway: %q to %q: %w", from, req.URL.Redacted(), ErrRedirect)
	}
	return nil
}

func origin(u *url.URL) (string, error) {
	host, port, err := hostPort(u)
	if err != nil {
		return "", err
	}
	return u.Scheme + "://" + net.JoinHostPort(host, port), nil
}
