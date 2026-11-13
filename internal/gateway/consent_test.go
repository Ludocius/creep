package gateway

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/exitcode"
)

// allowAllConsent consents to every endpoint, for tests about logging.
func allowAllConsent(t *testing.T) *Consent {
	t.Helper()
	return newConsent(t, ConsentOptions{Prompt: answer(true, nil)})
}

func newConsent(t *testing.T, opts ConsentOptions) *Consent {
	t.Helper()
	c, err := NewConsent(opts)
	if err != nil {
		t.Fatalf("NewConsent: %v", err)
	}
	return c
}

// answer is a Prompt that always gives yes or no.
func answer(yes bool, err error) Prompt {
	return func(string) (bool, error) { return yes, err }
}

// countingPrompt records the endpoints it was asked about.
type countingPrompt struct {
	yes   bool
	asked []string
}

func (p *countingPrompt) prompt(endpoint string) (bool, error) {
	p.asked = append(p.asked, endpoint)
	return p.yes, nil
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestConsentDecision(t *testing.T) {
	policy := []string{"https://API.Example.com", "https://10.0.0.5:8443/"}
	tests := []struct {
		name     string
		ci       bool
		prompt   Prompt
		endpoint string
		want     bool
	}{
		{"policy, CI", true, nil, "https://api.example.com/v1/chat", true},
		{"policy matches explicit default port", true, nil, "https://api.example.com:443/v1", true},
		{"policy matches trailing dot", true, nil, "https://api.example.com./v1", true},
		{"policy IP and port", true, nil, "https://10.0.0.5:8443/v1", true},
		{"policy is per port", true, nil, "https://api.example.com:8443/v1", false},
		{"policy is per scheme", true, nil, "http://api.example.com/v1", false},
		{"policy is per host", true, nil, "https://other.example.com/v1", false},
		{"CI never prompts", true, answer(true, nil), "https://other.example.com/v1", false},
		{"local yes", false, answer(true, nil), "https://other.example.com/v1", true},
		{"local no", false, answer(false, nil), "https://other.example.com/v1", false},
		{"prompt error declines", false, answer(true, errors.New("tty gone")), "https://other.example.com/v1", false},
		{"no prompt declines", false, nil, "https://other.example.com/v1", false},
		{"local policy needs no prompt", false, nil, "https://api.example.com/v1", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newConsent(t, ConsentOptions{CI: tt.ci, Policy: policy, Prompt: tt.prompt})
			err := c.check(mustURL(t, tt.endpoint))
			if got := err == nil; got != tt.want {
				t.Fatalf("check(%s) = %v, want allowed %v", tt.endpoint, err, tt.want)
			}
			var ce *ConsentError
			if err != nil && (!errors.As(err, &ce) || ce.CI != tt.ci || !errors.Is(err, ErrNoConsent)) {
				t.Fatalf("check(%s) = %#v, want *ConsentError with CI=%v", tt.endpoint, err, tt.ci)
			}
		})
	}
}

// In CI the prompt is never called, so a run can never wait on input.
func TestCINeverPrompts(t *testing.T) {
	p := &countingPrompt{yes: true}
	c := newConsent(t, ConsentOptions{CI: true, StorePath: filepath.Join(t.TempDir(), "c.json"), Prompt: p.prompt})
	_ = c.check(mustURL(t, "https://a.example/"))
	if len(p.asked) != 0 {
		t.Fatalf("CI prompted for %q", p.asked)
	}
}

func TestBadPolicyEntry(t *testing.T) {
	for _, s := range []string{
		"api.example.com", "ftp://api.example.com", "https://api.example.com/v1",
		"https://user@api.example.com", "https://api.example.com?k=v", "https://api.example.com#x",
		"https://127.1", "https://api.example.com:0443", "https://",
	} {
		if _, err := NewConsent(ConsentOptions{Policy: []string{s}}); err == nil {
			t.Errorf("NewConsent(policy %q): want error", s)
		}
	}
}

// A run asks once per endpoint, and an answer for one endpoint never
// covers another.
func TestPromptOncePerEndpoint(t *testing.T) {
	p := &countingPrompt{yes: false}
	c := newConsent(t, ConsentOptions{Prompt: p.prompt})
	for _, e := range []string{"https://a.example/1", "https://A.example:443/2", "https://b.example/", "https://a.example:8443/"} {
		_ = c.check(mustURL(t, e))
	}
	want := []string{"https://a.example:443", "https://b.example:443", "https://a.example:8443"}
	if len(p.asked) != len(want) {
		t.Fatalf("asked %q, want %q", p.asked, want)
	}
	for i := range want {
		if p.asked[i] != want[i] {
			t.Fatalf("asked %q, want %q", p.asked, want)
		}
	}
}

func TestStoredConsent(t *testing.T) {
	store := filepath.Join(t.TempDir(), "creep", "consent.json")
	yes := &countingPrompt{yes: true}
	c := newConsent(t, ConsentOptions{StorePath: store, Prompt: yes.prompt})
	if err := c.check(mustURL(t, "https://a.example/v1")); err != nil {
		t.Fatalf("check after yes: %v", err)
	}
	checkPrivate(t, store)

	never := &countingPrompt{}
	later := newConsent(t, ConsentOptions{StorePath: store, Prompt: never.prompt})
	if err := later.check(mustURL(t, "https://a.example:443/v2")); err != nil {
		t.Fatalf("stored consent not used: %v", err)
	}
	if err := later.check(mustURL(t, "https://b.example/v1")); err == nil {
		t.Fatal("stored consent covered another endpoint")
	}
	if len(never.asked) != 1 || never.asked[0] != "https://b.example:443" {
		t.Fatalf("asked %q, want only b.example", never.asked)
	}
	ci := newConsent(t, ConsentOptions{CI: true, StorePath: store})
	if err := ci.check(mustURL(t, "https://a.example/v1")); err == nil {
		t.Fatal("CI used the local store; only the policy may grant consent in CI")
	}
}

func TestDeclineNotStored(t *testing.T) {
	store := filepath.Join(t.TempDir(), "consent.json")
	c := newConsent(t, ConsentOptions{StorePath: store, Prompt: answer(false, nil)})
	if err := c.check(mustURL(t, "https://a.example/")); err == nil {
		t.Fatal("declined endpoint allowed")
	}
	if _, err := os.Lstat(store); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("decline wrote the store: %v", err)
	}
}

// Without consent Send writes nothing to the run directory and opens no
// connection, and the error maps to exit code 2.
func TestSendWithoutConsent(t *testing.T) {
	tests := []struct {
		name    string
		consent *Consent
		ci      bool
	}{
		{"CI without policy", newConsent(t, ConsentOptions{CI: true, Prompt: answer(true, nil)}), true},
		{"local decline", newConsent(t, ConsentOptions{Prompt: answer(false, nil)}), false},
		{"no consent configured", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newModelServer(t, `{}`)
			dir := runDir(t)
			l, err := OpenEgressLog(dir, tt.consent)
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			_, err = l.Send(context.Background(), m.client(t), testCall(m.url("/v1")))
			checkRefusal(t, err, tt.ci)
			checkNothingWritten(t, dir)
			if conns, bodies := m.stats(); conns != 0 || len(bodies) != 0 {
				t.Fatalf("server saw %d connections, %d bodies; want none", conns, len(bodies))
			}
		})
	}
}

func checkRefusal(t *testing.T, err error, ci bool) {
	t.Helper()
	var ce *ConsentError
	if !errors.As(err, &ce) || ce.CI != ci || ce.ExitCode() != exitcode.ConfigError || !errors.Is(err, ErrNoConsent) {
		t.Fatalf("Send = %#v, want *ConsentError CI=%v exit %d", err, ci, exitcode.ConfigError)
	}
}

func checkNothingWritten(t *testing.T, dir string) {
	t.Helper()
	info, err := os.Stat(filepath.Join(dir, egressLogName))
	if err != nil || info.Size() != 0 {
		t.Fatalf("egress.log: %v, size %d; want empty", err, sizeOf(info))
	}
	payloads, err := os.ReadDir(filepath.Join(dir, payloadDirName))
	if err != nil || len(payloads) != 0 {
		t.Fatalf("payloads: %v, %d files; want none", err, len(payloads))
	}
}

func sizeOf(info os.FileInfo) int64 {
	if info == nil {
		return -1
	}
	return info.Size()
}

func TestSendWithConsentLogs(t *testing.T) {
	m := newModelServer(t, `{}`)
	dir := runDir(t)
	c := newConsent(t, ConsentOptions{CI: true, Policy: []string{"http://127.0.0.1:" + m.port}})
	l, err := OpenEgressLog(dir, c)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err := l.Send(context.Background(), m.client(t), testCall(m.url("/v1"))); err != nil {
		t.Fatalf("Send with policy consent: %v", err)
	}
	if lines := readLines(t, dir); len(lines) != 2 {
		t.Fatalf("got %d log lines, want 2", len(lines))
	}
}

// TerminalPrompt never consents when stdin is not a terminal, and does not
// read from it.
func TestTerminalPromptPipeDeclines(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if _, err := w.WriteString("yes\n"); err != nil {
		t.Fatal(err)
	}
	var out countingWriter
	ok, err := TerminalPrompt(r, &out)("https://a.example:443")
	if ok || err != nil || out.n != 0 {
		t.Fatalf("prompt on a pipe = %v, %v, wrote %d bytes; want silent decline", ok, err, out.n)
	}
	if isTerminal(nil) {
		t.Fatal("nil file treated as a terminal")
	}
}

type countingWriter struct{ n int }

func (w *countingWriter) Write(p []byte) (int, error) {
	w.n += len(p)
	return len(p), nil
}

func TestReadYes(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"y\n", true},
		{"YES\r\n", true},
		{"  yes \n", true},
		{"y", false}, // EOF before newline
		{"n\n", false},
		{"\n", false},
		{"", false},
		{"yess\n", false},
		{"no\nyes\n", false},
		{string(make([]byte, 100)) + "\n", false},
	}
	for _, tt := range tests {
		if got := readYes(strings.NewReader(tt.in)); got != tt.want {
			t.Errorf("readYes(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}
