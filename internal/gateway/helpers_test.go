package gateway

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
)

// fakeResolver returns answers[host][i] on the i-th lookup of host (the last
// answer repeats) and counts every lookup.
type fakeResolver struct {
	mu      sync.Mutex
	answers map[string][][]netip.Addr
	calls   map[string]int
}

func newResolver(answers map[string][]string) *fakeResolver {
	r := &fakeResolver{answers: map[string][][]netip.Addr{}, calls: map[string]int{}}
	for host, ips := range answers {
		for _, ip := range ips {
			r.answers[host] = append(r.answers[host], mustAddrs([]string{ip}))
		}
	}
	return r
}

func mustAddrs(ips []string) []netip.Addr {
	out := make([]netip.Addr, len(ips))
	for i, ip := range ips {
		out[i] = netip.MustParseAddr(ip)
	}
	return out
}

func (r *fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := r.calls[host]
	r.calls[host]++
	seq := r.answers[host]
	if len(seq) == 0 {
		return nil, errors.New("no such host")
	}
	return seq[min(n, len(seq)-1)], nil
}

func (r *fakeResolver) total() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, c := range r.calls {
		n += c
	}
	return n
}

// recordingDial records the address the gateway asked for and connects to
// target instead, so a fake public IP can reach a loopback test server.
type recordingDial struct {
	mu     sync.Mutex
	target string
	addrs  []string
}

func (d *recordingDial) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.addrs = append(d.addrs, addr)
	d.mu.Unlock()
	return (&net.Dialer{}).DialContext(ctx, network, d.target)
}

func (d *recordingDial) dialed() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.addrs...)
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Host) //nolint:gosec // G705: test server echoes Host as plain text to a test client
	})
}

func newTLSServer(t *testing.T, h http.Handler) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	return srv, roots
}

func serverPort(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func newTestClient(t *testing.T, opts Options) *Client {
	t.Helper()
	c, err := NewClient(opts)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// get performs a GET and returns the body, closing the response.
func get(c *Client, url string) (string, error) {
	resp, err := c.hc.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}
