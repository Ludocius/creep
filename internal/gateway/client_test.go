package gateway

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

// Acceptance: a request to a non-allowlisted host fails before DNS.
func TestNotAllowedFailsBeforeDNS(t *testing.T) {
	allow := []string{"api.example.com", "llm.example.com:8443", "localhost:11434"}
	tests := []string{
		"https://evil.example/",
		"https://api.example.com.evil.example/",
		"https://evilapi.example.com/",
		"https://api.example.com:8443/", // bare entry covers only the default port
		"https://llm.example.com/",      // port-qualified entry covers only its port
		"http://api.example.com:443/",   // default port of https, not of http
		"http://localhost/",             // localhost allowed only on 11434
		"http://localhost.attacker.com:11434/",
		"https://2130706433/",
		"https://169.254.169.254/latest/meta-data/",
		"ftp://api.example.com/",
	}
	for _, url := range tests {
		res := newResolver(nil)
		d := &recordingDial{target: "127.0.0.1:1"}
		c := newTestClient(t, Options{Allow: allow, Resolver: res, Dial: d.dial})
		if _, err := get(c, url); err == nil {
			t.Errorf("GET %s: want error", url)
		}
		if res.total() != 0 || len(d.dialed()) != 0 {
			t.Errorf("GET %s: %d lookups, dials %v; want none", url, res.total(), d.dialed())
		}
	}
}

func TestNotAllowedError(t *testing.T) {
	c := newTestClient(t, Options{Allow: []string{"api.example.com"}, Resolver: newResolver(nil)})
	if _, err := get(c, "https://evil.example/"); !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("err = %v, want ErrNotAllowed", err)
	}
}

// Acceptance: plain HTTP to a non-localhost endpoint is refused.
func TestPlainHTTPRefused(t *testing.T) {
	tests := []string{
		"http://api.example.com/",
		"http://localhost.attacker.com/",
		"http://127.0.0.1.nip.io/",
		"http://10.0.0.5/",
		"http://0.0.0.0/",
		"http://[::]/",
	}
	allow := []string{"api.example.com", "localhost.attacker.com", "127.0.0.1.nip.io", "10.0.0.5", "0.0.0.0", "::"}
	for _, url := range tests {
		res := newResolver(nil)
		c := newTestClient(t, Options{Allow: allow, Resolver: res, Dial: (&recordingDial{}).dial})
		if _, err := get(c, url); !errors.Is(err, ErrPlainHTTP) {
			t.Errorf("GET %s: err = %v, want ErrPlainHTTP", url, err)
		}
		if res.total() != 0 {
			t.Errorf("GET %s: resolver called", url)
		}
	}
}

func TestPlainHTTPToLoopback(t *testing.T) {
	srv := httptest.NewServer(okHandler())
	t.Cleanup(srv.Close)
	port := serverPort(t, srv)
	tests := []struct {
		url, wantDial string
	}{
		{"http://127.0.0.1:" + port + "/", "127.0.0.1:" + port},
		{"http://localhost:" + port + "/", "127.0.0.1:" + port},
		{"http://LOCALHOST.:" + port + "/", "127.0.0.1:" + port},
		{"http://[::ffff:127.0.0.1]:" + port + "/", "127.0.0.1:" + port},
	}
	for _, tt := range tests {
		res := newResolver(nil)
		d := &recordingDial{target: srv.Listener.Addr().String()}
		allow := []string{"127.0.0.1:" + port, "localhost:" + port}
		c := newTestClient(t, Options{Allow: allow, Resolver: res, Dial: d.dial})
		if _, err := get(c, tt.url); err != nil {
			t.Errorf("GET %s: %v", tt.url, err)
			continue
		}
		if got := d.dialed(); len(got) != 1 || got[0] != tt.wantDial {
			t.Errorf("GET %s: dialed %v, want [%s]", tt.url, got, tt.wantDial)
		}
		if res.total() != 0 {
			t.Errorf("GET %s: localhost must not be resolved", tt.url)
		}
	}
}

// Acceptance: a second resolution returning a different IP does not change
// the connected address; SNI and Host stay the hostname.
func TestResolvedIPIsPinned(t *testing.T) {
	srv, roots := newTLSServer(t, okHandler())
	port := serverPort(t, srv)
	res := newResolver(map[string][]string{"example.com": {"198.51.100.7", "198.51.100.9"}})
	d := &recordingDial{target: srv.Listener.Addr().String()}
	c := newTestClient(t, Options{Allow: []string{"example.com:" + port}, Resolver: res, Dial: d.dial, RootCAs: roots})

	for i := 0; i < 3; i++ {
		body, err := get(c, "https://example.com:"+port+"/")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if body != "example.com:"+port {
			t.Fatalf("request %d: Host = %q", i, body)
		}
		c.CloseIdleConnections()
	}
	if n := res.total(); n != 1 {
		t.Errorf("resolver called %d times, want 1", n)
	}
	for _, addr := range d.dialed() {
		if addr != "198.51.100.7:"+port {
			t.Errorf("dialed %s, want the pinned 198.51.100.7:%s", addr, port)
		}
	}
	if len(d.dialed()) != 3 {
		t.Errorf("dials = %v, want 3 fresh connections", d.dialed())
	}
}

func TestTLSVerifiesHostname(t *testing.T) {
	srv, roots := newTLSServer(t, okHandler())
	port := serverPort(t, srv)
	// The test certificate covers example.com, not this name.
	res := newResolver(map[string][]string{"api.other.test": {"198.51.100.7"}})
	d := &recordingDial{target: srv.Listener.Addr().String()}
	c := newTestClient(t, Options{Allow: []string{"api.other.test:" + port}, Resolver: res, Dial: d.dial, RootCAs: roots})
	if _, err := get(c, "https://api.other.test:"+port+"/"); err == nil {
		t.Fatal("certificate for another name was accepted")
	}
}

func TestPrivateResolutionRefused(t *testing.T) {
	tests := [][]string{
		{"169.254.169.254"},
		{"127.0.0.1"},
		{"::1"},
		{"10.0.0.1"},
		{"192.168.1.10"},
		{"fd00:ec2::254"},
		{"::ffff:10.0.0.1"},
		{"64:ff9b::a9fe:a9fe"},
		{"0.0.0.0"},
		{"198.51.100.7", "10.0.0.1"}, // mixed answer
	}
	for _, ips := range tests {
		res := &fakeResolver{answers: map[string][][]netip.Addr{"example.com": {mustAddrs(ips)}}, calls: map[string]int{}}
		d := &recordingDial{target: "127.0.0.1:1"}
		c := newTestClient(t, Options{Allow: []string{"example.com"}, Resolver: res, Dial: d.dial})
		if _, err := get(c, "https://example.com/"); !errors.Is(err, ErrPrivateAddress) {
			t.Errorf("answer %v: err = %v, want ErrPrivateAddress", ips, err)
		}
		if len(d.dialed()) != 0 {
			t.Errorf("answer %v: dialed %v", ips, d.dialed())
		}
	}
}

// An IP entry permits requests to that IP literal only; it never vouches for
// a name that resolves to it, whatever the port.
func TestIPEntryDoesNotVouchForNames(t *testing.T) {
	srv, roots := newTLSServer(t, okHandler())
	port := serverPort(t, srv)
	allows := [][]string{
		{"example.com:" + port, "10.0.0.5"},
		{"example.com:" + port, "10.0.0.5:" + port},
		{"example.com:" + port, "10.0.0.5:8443"},
	}
	for _, allow := range allows {
		res := newResolver(map[string][]string{"example.com": {"10.0.0.5"}})
		d := &recordingDial{target: srv.Listener.Addr().String()}
		c := newTestClient(t, Options{Allow: allow, Resolver: res, Dial: d.dial, RootCAs: roots})
		if _, err := get(c, "https://example.com:"+port+"/"); !errors.Is(err, ErrPrivateAddress) {
			t.Errorf("allow %v: err = %v, want ErrPrivateAddress", allow, err)
		}
		if len(d.dialed()) != 0 {
			t.Errorf("allow %v: dialed %v", allow, d.dialed())
		}
	}
}

func TestProxyEnvIgnored(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "http://127.0.0.1:1")
	srv, roots := newTLSServer(t, okHandler())
	port := serverPort(t, srv)
	res := newResolver(map[string][]string{"example.com": {"198.51.100.7"}})
	d := &recordingDial{target: srv.Listener.Addr().String()}
	c := newTestClient(t, Options{Allow: []string{"example.com:" + port}, Resolver: res, Dial: d.dial, RootCAs: roots})
	if _, err := get(c, "https://example.com:"+port+"/"); err != nil {
		t.Fatal(err)
	}
	if got := d.dialed(); len(got) != 1 || got[0] != "198.51.100.7:"+port {
		t.Errorf("dialed %v, want the pinned address, not the proxy", got)
	}
	if tr := c.hc.Transport.(guard).next.(*http.Transport); tr.Proxy != nil {
		t.Error("transport has a proxy func")
	}
}

func TestInvalidAllowlistRejected(t *testing.T) {
	if _, err := NewClient(Options{Allow: []string{"0x7f000001"}}); !errors.Is(err, ErrInvalidHost) {
		t.Fatalf("err = %v, want ErrInvalidHost", err)
	}
}
