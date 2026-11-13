package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Acceptance: every call appears in egress.log, as a request line written
// before sending and a result line with the same ID after.
func TestEveryCallLogged(t *testing.T) {
	srv := newModelServer(t, `{"usage":{"in":12,"out":3}}`)
	dir := runDir(t)
	l := openLog(t, dir)
	call := testCall(srv.url("/v1/chat?api_key=query-secret"))
	call.Usage = func(body []byte) (Usage, bool) {
		var r struct{ Usage struct{ In, Out int } }
		return Usage{InputTokens: r.Usage.In, OutputTokens: r.Usage.Out}, json.Unmarshal(body, &r) == nil
	}
	const calls = 3
	for range calls {
		if _, err := l.Send(context.Background(), srv.client(t), call); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}
	_, bodies := srv.stats()
	lines := readLines(t, dir)
	if len(bodies) != calls || len(lines) != 2*calls {
		t.Fatalf("%d requests, %d lines; want %d and %d", len(bodies), len(lines), calls, 2*calls)
	}
	for i := 0; i < len(lines); i += 2 {
		checkRequestLine(t, dir, lines[i], bodies[i/2], srv.url("/v1/chat"))
		checkResultLine(t, lines[i+1], lines[i]["id"])
	}
}

func checkRequestLine(t *testing.T, dir string, line map[string]any, sent []byte, endpoint string) {
	t.Helper()
	sum := sha256.Sum256(sent)
	want := map[string]any{
		"v": 1.0, "type": "request", "endpoint": endpoint, "model": "test-model",
		"purpose": "reader", "bytes": float64(len(sent)), "sha256": hex.EncodeToString(sum[:]),
	}
	for k, v := range want {
		if line[k] != v {
			t.Errorf("request %s = %v, want %v", k, line[k], v)
		}
	}
	if r, _ := line["redactions"].(map[string]any); r["SECRET_AWS"] != 1.0 {
		t.Errorf("redactions = %v", line["redactions"])
	}
	file, _ := line["payload_file"].(string)
	stored, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(file)))
	if err != nil || !bytes.Equal(stored, sent) {
		t.Errorf("payload file %q = %q, %v; want the sent bytes", file, stored, err)
	}
}

func checkResultLine(t *testing.T, line map[string]any, id any) {
	t.Helper()
	tokens, _ := line["tokens"].(map[string]any)
	if line["type"] != "result" || line["id"] != id || line["outcome"] != OutcomeResponse ||
		line["status"] != 200.0 || tokens["input"] != 12.0 || tokens["output"] != 3.0 {
		t.Errorf("result line = %v, want response 200 with tokens 12/3 for id %v", line, id)
	}
}

// Payload contents, headers and query-string credentials stay out of the log.
func TestLogHoldsNoPayloadOrSecrets(t *testing.T) {
	srv := newModelServer(t, "ok")
	dir := runDir(t)
	l := openLog(t, dir)
	call := testCall(srv.url("/v1?key=query-secret"))
	call.Endpoint = strings.Replace(call.Endpoint, "http://", "http://user:userinfo-secret@", 1)
	if _, err := l.Send(context.Background(), srv.client(t), call); err != nil {
		t.Fatalf("Send: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, egressLogName))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"prompt", "code ", "sk-test-header-secret", "query-secret", "userinfo-secret", "Authorization"} {
		if bytes.Contains(raw, []byte(s)) {
			t.Errorf("egress.log contains %q:\n%s", s, raw)
		}
	}
}

// Acceptance: a failed log write aborts the call before any byte is sent.
func TestLogFailureSendsNothing(t *testing.T) {
	tests := []struct {
		name     string
		breakLog func(t *testing.T, l *EgressLog, dir string)
	}{
		{"log file closed", func(t *testing.T, l *EgressLog, _ string) {
			if err := l.f.Close(); err != nil {
				t.Fatal(err)
			}
		}},
		{"payload dir gone", func(t *testing.T, _ *EgressLog, dir string) {
			if err := os.RemoveAll(filepath.Join(dir, payloadDirName)); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newModelServer(t, "ok")
			dir := runDir(t)
			l := openLog(t, dir)
			tt.breakLog(t, l, dir)
			reply, err := l.Send(context.Background(), srv.client(t), testCall(srv.url("/v1")))
			if err == nil || reply != nil {
				t.Fatalf("Send = %v, %v; want error and no reply", reply, err)
			}
			if conns, bodies := srv.stats(); conns != 0 || len(bodies) != 0 {
				t.Fatalf("server saw %d connections, %d requests; want none", conns, len(bodies))
			}
		})
	}
}

// Field values are JSON-encoded, so a newline in the model name or the path
// cannot forge a second line.
func TestLogInjection(t *testing.T) {
	srv := newModelServer(t, "ok")
	dir := runDir(t)
	l := openLog(t, dir)
	forged := "m\n{\"type\":\"request\",\"id\":\"forged\"}\r\u2028"
	call := testCall(srv.url("/v1/%0A%7B%22type%22:%22result%22%7D"))
	call.Model, call.Purpose = forged, forged
	call.Redactions = map[string]int{"L\n{}": 1}
	if _, err := l.Send(context.Background(), srv.client(t), call); err != nil {
		t.Fatalf("Send: %v", err)
	}
	lines := readLines(t, dir)
	if len(lines) != 2 || lines[0]["model"] != forged || lines[0]["purpose"] != forged {
		t.Fatalf("lines = %v; want 2 lines carrying the model name verbatim", lines)
	}
}

// Calls refused before sending (bad labels or URL) leave no trace; calls the
// client refuses are logged with a transport_error result.
func TestRefusedCalls(t *testing.T) {
	srv := newModelServer(t, "ok")
	long := strings.Repeat("m", maxLabelBytes+1)
	tests := []struct {
		name   string
		edit   func(*Call)
		lines  int
		result string
	}{
		{"empty model", func(c *Call) { c.Model = "" }, 0, ""},
		{"long purpose", func(c *Call) { c.Purpose = long }, 0, ""},
		{"relative url", func(c *Call) { c.Endpoint = "/v1" }, 0, ""},
		{"not allowlisted", func(c *Call) { c.Endpoint = "https://evil.example/v1" }, 2, OutcomeTransport},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := runDir(t)
			l := openLog(t, dir)
			call := testCall(srv.url("/v1"))
			tt.edit(&call)
			if _, err := l.Send(context.Background(), srv.client(t), call); err == nil {
				t.Fatal("Send: want error")
			}
			lines := readLines(t, dir)
			if len(lines) != tt.lines || (tt.lines > 0 && lines[1]["outcome"] != tt.result) {
				t.Fatalf("lines = %v; want %d ending in %q", lines, tt.lines, tt.result)
			}
		})
	}
	if conns, _ := srv.stats(); conns != 0 {
		t.Fatalf("server saw %d connections; want none", conns)
	}
}

func TestResponseTooLarge(t *testing.T) {
	srv := newModelServer(t, strings.Repeat("x", maxResponseBytes+1))
	dir := runDir(t)
	l := openLog(t, dir)
	_, err := l.Send(context.Background(), srv.client(t), testCall(srv.url("/v1")))
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("err = %v, want ErrResponseTooLarge", err)
	}
	if lines := readLines(t, dir); len(lines) != 2 || lines[1]["outcome"] != OutcomeTooLarge {
		t.Fatalf("lines = %v", lines)
	}
}

// Concurrent calls each get whole lines and their own ID.
func TestConcurrentSends(t *testing.T) {
	srv := newModelServer(t, "ok")
	dir := runDir(t)
	l := openLog(t, dir)
	client := srv.client(t)
	const calls = 16
	var wg sync.WaitGroup
	for range calls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := l.Send(context.Background(), client, testCall(srv.url("/v1"))); err != nil {
				t.Errorf("Send: %v", err)
			}
		}()
	}
	wg.Wait()
	ids := map[any]int{}
	for _, line := range readLines(t, dir) {
		ids[line["id"]]++
	}
	if len(ids) != calls {
		t.Fatalf("%d distinct IDs, want %d", len(ids), calls)
	}
	for id, n := range ids {
		if n != 2 {
			t.Errorf("id %v has %d lines, want 2", id, n)
		}
	}
}
