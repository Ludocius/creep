package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// hookTransport runs before on every request, then delegates.
type hookTransport struct {
	before func()
	next   http.RoundTripper
}

func (h hookTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	h.before()
	return h.next.RoundTrip(req)
}

func hookedClient(t *testing.T, srv *modelServer, before func()) *http.Client {
	t.Helper()
	c := srv.client(t)
	c.Transport = hookTransport{before: before, next: c.Transport}
	return c
}

// A caller changing its payload slice after the request line is written
// must not change what is sent: the bytes sent match the logged hash.
func TestPayloadCopiedBeforeSend(t *testing.T) {
	srv := newModelServer(t, "ok")
	dir := runDir(t)
	l := openLog(t, dir)
	call := testCall(srv.url("/v1"))
	payload := call.Payload
	client := hookedClient(t, srv, func() { copy(payload, bytes.Repeat([]byte("X"), len(payload))) })
	if _, err := l.Send(context.Background(), client, call); err != nil {
		t.Fatalf("Send: %v", err)
	}
	_, bodies := srv.stats()
	sum := sha256.Sum256(bodies[0])
	if lines := readLines(t, dir); lines[0]["sha256"] != hex.EncodeToString(sum[:]) {
		t.Fatalf("sent %q, which does not match the logged sha256", bodies[0])
	}
}

// A result line that cannot be written must not be ignored.
func TestResultWriteFailureReturnsNoReply(t *testing.T) {
	srv := newModelServer(t, "ok")
	l := openLog(t, runDir(t))
	client := hookedClient(t, srv, func() { _ = l.f.Close() })
	reply, err := l.Send(context.Background(), client, testCall(srv.url("/v1")))
	if err == nil || reply != nil {
		t.Fatalf("Send = %v, %v; want error and no reply", reply, err)
	}
}

// Errors returned to the caller never quote userinfo or query credentials.
func TestErrorsHideCredentials(t *testing.T) {
	srv := newModelServer(t, "ok")
	tests := []struct {
		name, endpoint string
	}{
		{"not allowlisted", "https://evil.example/v1?key=secret"},
		{"connection refused", "http://user:secret@127.0.0.1:1/v1?key=secret#secret"},
		{"redirect", srv.url("/redirect?key=secret")},
	}
	client := newTestClient(t, Options{Allow: []string{"127.0.0.1:" + srv.port, "127.0.0.1:1"}})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := openLog(t, runDir(t))
			_, err := l.Send(context.Background(), client, testCall(tt.endpoint))
			if err == nil || strings.Contains(err.Error(), "secret") {
				t.Fatalf("err = %v; want an error without the credential", err)
			}
		})
	}
}

// dropSecond answers the first request and closes the connection after
// reading the second request's body, the case where http.Transport retries
// an idempotent request on a fresh connection.
type dropSecond struct {
	mu     sync.Mutex
	bodies int
}

func (d *dropSecond) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_, _ = io.ReadAll(r.Body)
	d.mu.Lock()
	d.bodies++
	n := d.bodies
	d.mu.Unlock()
	if n != 2 {
		_, _ = io.WriteString(w, "ok")
		return
	}
	if conn, _, err := http.NewResponseController(w).Hijack(); err == nil {
		_ = conn.Close()
	}
}

// A transport retry would send a body the log shows once: bodies received
// must equal request lines.
func TestTransportRetryDoesNotResend(t *testing.T) {
	h := &dropSecond{}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	port := serverPort(t, srv)
	client := newTestClient(t, Options{Allow: []string{"127.0.0.1:" + port}})
	dir := runDir(t)
	l := openLog(t, dir)
	call := testCall("http://127.0.0.1:" + port + "/v1")
	call.Header.Set("Idempotency-Key", "k1")
	for range 2 {
		_, _ = l.Send(context.Background(), client, call)
	}
	requests := 0
	for _, line := range readLines(t, dir) {
		if line["type"] == "request" {
			requests++
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.bodies != requests {
		t.Fatalf("server received %d bodies, log has %d request lines", h.bodies, requests)
	}
}

// Redirects are not followed, so the body is sent once, to the logged URL.
func TestRedirectNotFollowed(t *testing.T) {
	srv := newModelServer(t, "ok")
	dir := runDir(t)
	l := openLog(t, dir)
	_, err := l.Send(context.Background(), srv.client(t), testCall(srv.url("/redirect")))
	if !errors.Is(err, ErrRedirectNotFollowed) {
		t.Fatalf("err = %v, want ErrRedirectNotFollowed", err)
	}
	if _, bodies := srv.stats(); len(bodies) != 1 {
		t.Fatalf("server got %d requests, want 1", len(bodies))
	}
	lines := readLines(t, dir)
	if len(lines) != 2 || lines[1]["outcome"] != OutcomeRedirect || lines[1]["status"] != 307.0 {
		t.Fatalf("lines = %v; want redirect_refused with status 307", lines)
	}
}
