package gateway

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/redact"
)

func newRedactor(t *testing.T) *redact.Redactor {
	t.Helper()
	r, err := redact.New()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func randomFrom(rng *rand.Rand, alphabet string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[rng.IntN(len(alphabet))]
	}
	return string(b)
}

const (
	upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	alnum = upper + "abcdefghijklmnopqrstuvwxyz0123456789"
	b64   = alnum + "+/"
)

// secretFile returns repository code holding secrets, among them a private
// key far longer than one fragment, and every secret value it holds. Values
// are built at run time so no scanner flags this file.
func secretFile(rng *rand.Rand) (string, []string) {
	secrets := []string{
		"AKIA" + randomFrom(rng, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16),
		"ghp_" + randomFrom(rng, alnum, 36),
		randomFrom(rng, alnum, 24),
		"jane." + randomFrom(rng, "abcdefghij", 8) + "@example.com",
	}
	var key []string
	for range 24 {
		key = append(key, randomFrom(rng, b64, 64))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "package cfg\n\nconst awsID = %q\nconst token = %q\n", secrets[0], secrets[1])
	fmt.Fprintf(&b, "var password = %q\n// owner: %s\n\nconst key = `", secrets[2], secrets[3])
	b.WriteString("-----BEGIN RSA PRIV" + "ATE KEY-----\n" + strings.Join(key, "\n"))
	b.WriteString("\n-----END RSA PRIV" + "ATE KEY-----`\n\nfunc main() {}\n")
	return b.String(), append(secrets, key...)
}

// Acceptance (#83): files are cut only after redact.File has redacted them
// whole, so no un-redacted fragment reaches the model call, even with
// fragments far shorter than the private key they would otherwise split.
func TestScanSendsOnlyRedactedFragments(t *testing.T) {
	const maxFragment = 128
	content, secrets := secretFile(rand.New(rand.NewPCG(83, 1)))
	srv := newModelServer(t, "ok")
	dir := runDir(t)
	l := openLog(t, dir)
	client := srv.client(t)
	scan := FileScan{
		Redactor:         newRedactor(t),
		MaxFragmentBytes: maxFragment,
		Read:             func(string) ([]byte, error) { return []byte(content), nil },
		Send: func(f Fragment) error {
			call := testCall(srv.url("/v1"))
			call.Payload, call.Redactions = []byte(f.Text), f.Redactions
			_, err := l.Send(context.Background(), client, call)
			return err
		},
	}
	rep, err := scan.Run([]string{"cfg.go"})
	if err != nil || rep.Incomplete || len(rep.NotScanned) != 0 {
		t.Fatalf("Run = %+v, %v; want every file scanned", rep, err)
	}
	_, bodies := srv.stats()
	assertNoSecrets(t, bodies, secrets)
	want, err := newRedactor(t).File([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(joinBodies(bodies)); got != want || rep.Fragments != len(bodies) || len(bodies) < 2 {
		t.Fatalf("%d fragments sent (report %d), joined %q; want redact.File output %q", len(bodies), rep.Fragments, got, want)
	}
	assertLoggedRedactions(t, readLines(t, dir), 5)
}

func assertNoSecrets(t *testing.T, bodies [][]byte, secrets []string) {
	t.Helper()
	for _, body := range bodies {
		for _, s := range secrets {
			if strings.Contains(string(body), s) {
				t.Fatalf("fragment %q leaks %q", body, s)
			}
		}
	}
}

func joinBodies(bodies [][]byte) []byte {
	var out []byte
	for _, b := range bodies {
		out = append(out, b...)
	}
	return out
}

// assertLoggedRedactions checks egress.log records want markers in all.
func assertLoggedRedactions(t *testing.T, lines []map[string]any, want int) {
	t.Helper()
	total := 0.0
	for _, line := range lines {
		counts, _ := line["redactions"].(map[string]any)
		for _, n := range counts {
			total += n.(float64)
		}
	}
	if total != float64(want) {
		t.Fatalf("egress.log records %v redactions, want %d", total, want)
	}
}

// recorder is a FileScan whose Read serves files from a map and whose Send
// records every fragment.
type recorder struct {
	files map[string]string
	read  []string
	sent  []Fragment
	fail  func(n int) error // error for the n-th Send, from 0; nil sends
}

func (rec *recorder) scan(t *testing.T) FileScan {
	return FileScan{
		Redactor:         newRedactor(t),
		MaxFragmentBytes: 64,
		Read: func(path string) ([]byte, error) {
			rec.read = append(rec.read, path)
			content, ok := rec.files[path]
			if !ok {
				return nil, errors.New("no such file")
			}
			return []byte(content), nil
		},
		Send: func(f Fragment) error {
			if rec.fail != nil {
				if err := rec.fail(len(rec.sent)); err != nil {
					return err
				}
			}
			rec.sent = append(rec.sent, f)
			return nil
		},
	}
}

func (rec *recorder) sentText() string {
	var b strings.Builder
	for _, f := range rec.sent {
		b.WriteString(f.Text)
	}
	return b.String()
}

const goodFile = "package ok\n\nfunc main() {}\n"

// Acceptance (#83): a file redact.File rejects is never sent, raw or
// truncated; it is listed as not scanned and the run goes on.
func TestScanSkipsFilesRedactRejects(t *testing.T) {
	tests := []struct {
		name    string
		content string
		missing bool
		want    SkipReason
	}{
		{"too large", "CANARY\n" + strings.Repeat("x = 1\n", redact.MaxFileBytes/6), false, SkipTooLarge},
		{"minified", "CANARY;" + strings.Repeat("a=1;", redact.MaxLineBytes/4), false, SkipLineTooLong},
		{"binary with NUL", "CANARY" + strings.Repeat("\x00\x01", redact.MaxLineBytes/2), false, SkipLineTooLong},
		{"CR-only line ends", strings.Repeat("CANARY x\r", redact.MaxLineBytes/9+1), false, SkipLineTooLong},
		{"unreadable", "", true, SkipReadFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &recorder{files: map[string]string{"a.go": goodFile, "c.go": goodFile}}
			if !tt.missing {
				rec.files["b.go"] = tt.content
			}
			rep, err := rec.scan(t).Run([]string{"a.go", "b.go", "c.go"})
			want := ScanReport{Fragments: 2, NotScanned: []NotScanned{{"b.go", tt.want}}}
			if err != nil || !reflect.DeepEqual(rep, want) {
				t.Fatalf("Run = %+v, %v; want %+v", rep, err, want)
			}
			if got := rec.sentText(); got != goodFile+goodFile {
				t.Fatalf("sent %q; want only the two good files", got)
			}
		})
	}
}

// fillingFile holds more distinct values than one run can remember: values
// made of one repeated byte share every window, so they fill the sweep
// index's window and overflow lists after a few hundred.
func fillingFile() string {
	var b strings.Builder
	for n := range 300 {
		b.WriteString("CANARY password = \"" + strings.Repeat("@", 8+n) + "\"\n")
	}
	return b.String()
}

// Acceptance (#83): ErrRunFull, from redact.File or from a Redact the caller
// makes for Send, stops the run; that file and every later one are listed
// as not scanned and the report is incomplete, never clean.
func TestScanStopsWhenRunFull(t *testing.T) {
	tests := []struct {
		name string
		b    string
		fail func(int) error
		want SkipReason
	}{
		{"redact.File", fillingFile(), nil, SkipRunFull},
		{"Redact in Send", goodFile, failSecond(fmt.Errorf("redact prompt: %w", redact.ErrRunFull)), SkipRunFull},
		{"other Send error", goodFile, failSecond(errors.New("model endpoint unreachable")), SkipSendFailed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &recorder{files: map[string]string{"a.go": goodFile, "b.go": tt.b, "c.go": goodFile, "d.go": goodFile}, fail: tt.fail}
			rep, err := rec.scan(t).Run([]string{"a.go", "b.go", "c.go", "d.go"})
			want := ScanReport{Fragments: 1, Incomplete: true,
				NotScanned: []NotScanned{{"b.go", tt.want}, {"c.go", tt.want}, {"d.go", tt.want}}}
			if err == nil || errors.Is(err, redact.ErrRunFull) != (tt.want == SkipRunFull) || !reflect.DeepEqual(rep, want) {
				t.Fatalf("Run = %+v, %v; want %+v and the stopping error", rep, err, want)
			}
			if strings.Contains(rec.sentText(), "CANARY") || len(rec.read) != 2 {
				t.Fatalf("sent %q after reading %v; want only a.go sent and nothing read after b.go", rec.sentText(), rec.read)
			}
		})
	}
}

// failSecond makes the second Send return err.
func failSecond(err error) func(int) error {
	return func(n int) error {
		if n == 1 {
			return err
		}
		return nil
	}
}

func TestFragmentLen(t *testing.T) {
	tests := []struct {
		text string
		want int
	}{
		{"", 0},
		{"ab\ncd\n", 6},            // fits
		{"ab\ncd\nef\n", 6},        // whole lines up to the cap
		{"abcdefgh\nij\n", 9},      // one longer line alone
		{"abcdefghij", 10},         // never truncated
		{"ab\ncdefghijkl\n", 3},    // the cap ends inside the second line
		{"<SECRET_X_1>\nab\n", 13}, // a marker is never cut
	}
	for _, tt := range tests {
		if got := fragmentLen(tt.text, 6); got != tt.want {
			t.Errorf("fragmentLen(%q, 6) = %d, want %d", tt.text, got, tt.want)
		}
	}
}

func TestScanNeedsEveryField(t *testing.T) {
	full := (&recorder{}).scan(t)
	for name, s := range map[string]FileScan{
		"no Redactor": {Read: full.Read, Send: full.Send, MaxFragmentBytes: 1},
		"no Read":     {Redactor: full.Redactor, Send: full.Send, MaxFragmentBytes: 1},
		"no Send":     {Redactor: full.Redactor, Read: full.Read, MaxFragmentBytes: 1},
		"no size":     {Redactor: full.Redactor, Read: full.Read, Send: full.Send},
	} {
		if _, err := s.Run([]string{"a.go"}); err == nil {
			t.Errorf("%s: Run succeeded", name)
		}
	}
}
