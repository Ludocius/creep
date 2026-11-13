package gateway

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// modelServer is a loopback model endpoint that counts connections and
// keeps every request body it received.
type modelServer struct {
	srv    *httptest.Server
	mu     sync.Mutex
	conns  int
	bodies [][]byte
	reply  string
	port   string
}

func newModelServer(t *testing.T, reply string) *modelServer {
	t.Helper()
	m := &modelServer{reply: reply}
	m.srv = httptest.NewUnstartedServer(http.HandlerFunc(m.serve))
	m.srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			m.mu.Lock()
			m.conns++
			m.mu.Unlock()
		}
	}
	m.srv.Start()
	t.Cleanup(m.srv.Close)
	m.port = serverPort(t, m.srv)
	return m
}

func (m *modelServer) serve(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	m.mu.Lock()
	m.bodies = append(m.bodies, b)
	m.mu.Unlock()
	if r.URL.Path == "/redirect" {
		http.Redirect(w, r, "/v1", http.StatusTemporaryRedirect)
		return
	}
	_, _ = io.WriteString(w, m.reply)
}

func (m *modelServer) stats() (conns int, bodies [][]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.conns, append([][]byte(nil), m.bodies...)
}

// client returns a gateway client that allows only this server.
func (m *modelServer) client(t *testing.T) *http.Client {
	t.Helper()
	return newTestClient(t, Options{Allow: []string{"127.0.0.1:" + m.port}})
}

func (m *modelServer) url(path string) string {
	return "http://127.0.0.1:" + m.port + path
}

// runDir returns a fresh private run directory.
func runDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "run")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func openLog(t *testing.T, dir string) *EgressLog {
	t.Helper()
	l, err := OpenEgressLog(dir, allowAllConsent(t))
	if err != nil {
		t.Fatalf("OpenEgressLog: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// readLines decodes every egress.log line, failing on one that is not a
// single JSON object.
func readLines(t *testing.T, dir string) []map[string]any {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, egressLogName))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var lines []map[string]any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue // left by recovery from a torn write
		}
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("line %q: %v", sc.Text(), err)
		}
		lines = append(lines, m)
	}
	return lines
}

func testCall(endpoint string) Call {
	return Call{
		Endpoint:   endpoint,
		Model:      "test-model",
		Purpose:    "reader",
		Payload:    []byte(`{"prompt":"code <SECRET_AWS_1>"}`),
		Redactions: map[string]int{"SECRET_AWS": 1},
		Header:     http.Header{"Authorization": {"Bearer sk-test-header-secret"}},
	}
}
