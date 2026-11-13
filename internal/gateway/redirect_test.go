package gateway

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// redirector sends /go?to=<url> to <url> and answers everything else.
func redirector() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if to := r.URL.Query().Get("to"); to != "" {
			http.Redirect(w, r, to, http.StatusFound) //nolint:gosec // G710: the open redirect is the attack under test
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
}

// Acceptance: a redirect to another host is refused. Every target below is
// allowlisted, so the refusal comes from the redirect rule itself.
func TestRedirectToAnotherOriginRefused(t *testing.T) {
	srv := httptest.NewServer(redirector())
	t.Cleanup(srv.Close)
	other := httptest.NewServer(redirector())
	t.Cleanup(other.Close)
	port, otherPort := serverPort(t, srv), serverPort(t, other)
	base := "http://127.0.0.1:" + port
	tests := []struct {
		to      string
		wantErr bool
	}{
		{to: "/ok", wantErr: false},
		{to: base + "/ok", wantErr: false},
		{to: "http://localhost:" + port + "/ok", wantErr: true},      // other host, same socket
		{to: "http://127.0.0.1:" + otherPort + "/ok", wantErr: true}, // other port
		{to: "https://127.0.0.1:" + port + "/ok", wantErr: true},     // scheme change
		{to: "https://api.example.com/", wantErr: true},
		{to: "http://169.254.169.254/latest/meta-data/", wantErr: true},
	}
	allow := []string{"127.0.0.1:" + port, "127.0.0.1:" + otherPort, "localhost:" + port, "api.example.com", "169.254.169.254:80"}
	for _, tt := range tests {
		res := newResolver(nil)
		d := &recordingDial{target: srv.Listener.Addr().String()}
		c := newTestClient(t, Options{Allow: allow, Resolver: res, Dial: d.dial})
		_, err := get(c, base+"/go?to="+tt.to)
		if tt.wantErr != errors.Is(err, ErrRedirect) {
			t.Errorf("redirect to %s: err = %v, wantErr %v", tt.to, err, tt.wantErr)
		}
		if tt.wantErr && (len(d.dialed()) != 1 || res.total() != 0) {
			t.Errorf("redirect to %s: dials %v, lookups %d; want only the first dial", tt.to, d.dialed(), res.total())
		}
	}
}

func TestRedirectDowngradeRefused(t *testing.T) {
	srv, roots := newTLSServer(t, redirector())
	port := serverPort(t, srv)
	res := newResolver(map[string][]string{"example.com": {"198.51.100.7"}})
	d := &recordingDial{target: srv.Listener.Addr().String()}
	c := newTestClient(t, Options{Allow: []string{"example.com:" + port}, Resolver: res, Dial: d.dial, RootCAs: roots})
	_, err := get(c, "https://example.com:"+port+"/go?to=http://example.com:"+port+"/ok")
	if !errors.Is(err, ErrRedirect) {
		t.Fatalf("err = %v, want ErrRedirect", err)
	}
	if len(d.dialed()) != 1 {
		t.Errorf("dials = %v, want only the first", d.dialed())
	}
}

func TestRedirectLoopStops(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/again", http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	port := serverPort(t, srv)
	c := newTestClient(t, Options{Allow: []string{"127.0.0.1:" + port}})
	if _, err := get(c, "http://127.0.0.1:"+port+"/"); err == nil {
		t.Fatal("redirect loop did not stop")
	}
}
