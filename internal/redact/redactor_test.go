package redact

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// Secrets are built at run time so the repository's own gitleaks CI job never
// sees a literal credential in this file.
func fakeToken(rng *rand.Rand, alphabet string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[rng.IntN(len(alphabet))]
	}
	return string(b)
}

const (
	upperB32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	alnum    = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

func fakeAWS(rng *rand.Rand) string    { return "AK" + "IA" + fakeToken(rng, upperB32, 16) }
func fakeGitHub(rng *rand.Rand) string { return "gh" + "p_" + fakeToken(rng, alnum, 36) }

func newRedactor(t testing.TB) *Redactor {
	t.Helper()
	r, err := New()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func mustRedact(t testing.TB, r *Redactor, text string) string {
	t.Helper()
	out, err := r.Redact(text)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

var markerRe = regexp.MustCompile(`<(?:SECRET|PII)_[A-Z0-9_]+_[0-9]+>`)

func TestRedactMasksSecrets(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	aws, gh := fakeAWS(rng), fakeGitHub(rng)
	tests := []struct {
		name, text, secret, marker string
	}{
		{"aws", "id := \"" + aws + "\"\n", aws, "<SECRET_AWS_ACCESS_TOKEN_1>"},
		{"github", "GH=" + gh + "\n", gh, "<SECRET_GITHUB_PAT_1>"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := mustRedact(t, newRedactor(t), tc.text)
			if strings.Contains(out, tc.secret) {
				t.Fatalf("secret leaked: %q", out)
			}
			if !strings.Contains(out, tc.marker) {
				t.Fatalf("output %q lacks marker %s", out, tc.marker)
			}
		})
	}
}

func TestSameSecretSameMarkerAcrossFragments(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
	aws, other := fakeAWS(rng), fakeAWS(rng)
	r := newRedactor(t)
	first := mustRedact(t, r, "a := \""+aws+"\"\n")
	second := mustRedact(t, r, "func f() {\n\tb := \""+other+"\"\n\tc := \""+aws+"\"\n}\n")
	// No rule context at all: the known value is still masked.
	third := mustRedact(t, r, "// see "+aws+"x")

	m1 := markerRe.FindString(first)
	got := markerRe.FindAllString(second, -1)
	if m1 == "" || len(got) != 2 {
		t.Fatalf("markers: first %q, second %q", first, second)
	}
	if got[1] != m1 || got[0] == m1 {
		t.Errorf("same secret got %q then %q; other secret got %q", m1, got[1], got[0])
	}
	if !strings.Contains(third, m1) || strings.Contains(third, aws) {
		t.Errorf("known value not swept: %q", third)
	}
}

func TestRedactPII(t *testing.T) {
	tests := []struct {
		name, text, marker string
	}{
		{"email", "mail: ana.perez+x@example.co.uk;", "<PII_EMAIL_1>"},
		{"card spaced", "card 4111 1111 1111 1111 exp", "<PII_CARD_1>"},
		{"card plain", `"5555555555554444"`, "<PII_CARD_1>"},
		{"ssn", "ssn=123-45-6789", "<PII_US_SSN_1>"},
		{"dni", "dni: 12345678Z", "<PII_ES_DNI_1>"},
		{"nie", "nie X1234567L.", "<PII_ES_NIE_1>"},
		{"cpf", "cpf 111.444.777-35", "<PII_BR_CPF_1>"},
		{"cpf plain", "cpf: 11144477735,", "<PII_BR_CPF_1>"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := mustRedact(t, newRedactor(t), tc.text)
			if !strings.Contains(out, tc.marker) {
				t.Fatalf("Redact(%q) = %q, want marker %s", tc.text, out, tc.marker)
			}
		})
	}
}

func TestRedactAdjacentPII(t *testing.T) {
	out := mustRedact(t, newRedactor(t), "a@b.io,c@d.io")
	if out != "<PII_EMAIL_1>,<PII_EMAIL_2>" {
		t.Fatalf("got %q", out)
	}
}

func TestRedactKeepsOrdinaryCode(t *testing.T) {
	tests := []string{
		"ts := 1700000000000123",            // Luhn fails
		"id := 4111111111111112",            // Luhn fails
		"x := 12345678A",                    // DNI letter wrong
		"v := 000-12-3456",                  // SSN area 000
		"cpf := 111.111.111-11",             // repeated digits
		"n := 11144477736",                  // CPF check digit wrong
		"n := 41111111111111110000",         // longer digit run
		"name := foo4111111111111111",       // inside an identifier
		"if a < b && c > d { return x<<2 }", // plain comparisons
	}
	for _, text := range tests {
		out := mustRedact(t, newRedactor(t), text)
		if out != text {
			t.Errorf("Redact(%q) = %q, want unchanged", text, out)
		}
	}
}

func TestEscapeForgedMarkers(t *testing.T) {
	rng := rand.New(rand.NewPCG(5, 6))
	aws := fakeAWS(rng)
	r := newRedactor(t)
	out := mustRedact(t, r, "k := \""+aws+"\"\n")
	marker := markerRe.FindString(out)

	// Repository text quoting the same marker must not un-redact to the secret.
	forged := "// " + marker + " <PII_EMAIL_1> <ESC_SECRET_X_1> <SECRET_"
	got := mustRedact(t, r, forged)
	if markerRe.MatchString(got) {
		t.Fatalf("forged marker survived: %q", got)
	}
	if shown := r.Unredact(got); shown != forged || strings.Contains(shown, aws) {
		t.Fatalf("Unredact(%q) = %q, want %q", got, shown, forged)
	}
}

func TestUnredactRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 8))
	text := "<a> <<SECRET_ k=\"" + fakeAWS(rng) + "\" mail x@y.org <ESC_PII_ <ESC_" + fakeGitHub(rng) + " <"
	r := newRedactor(t)
	out := mustRedact(t, r, text)
	if got := r.Unredact(out); got != text {
		t.Fatalf("round trip:\n got %q\nwant %q\n via %q", got, text, out)
	}
	if got := r.Unredact("<SECRET_UNKNOWN_9> <PII_EMAIL_99>"); got != "<SECRET_UNKNOWN_9> <PII_EMAIL_99>" {
		t.Fatalf("unknown markers changed: %q", got)
	}
}

func TestRedactTooLarge(t *testing.T) {
	_, err := newRedactor(t).Redact(strings.Repeat("a", MaxInputBytes+1))
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
}

// The map must not leak through printing or encoding.
func TestRedactorDoesNotExposeMap(t *testing.T) {
	rng := rand.New(rand.NewPCG(9, 10))
	aws := fakeAWS(rng)
	r := newRedactor(t)
	mustRedact(t, r, "k := \""+aws+"\"\n")

	var outputs []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		outputs = append(outputs, fmt.Sprintf(verb, r))
	}
	js, _ := json.Marshal(r)
	var g bytes.Buffer
	_ = gob.NewEncoder(&g).Encode(r)
	outputs = append(outputs, string(js), g.String())
	for _, o := range outputs {
		if strings.Contains(o, aws) || strings.Contains(o, "SECRET_") {
			t.Errorf("Redactor exposed its map: %q", o)
		}
	}
}

func TestRedactConcurrent(t *testing.T) {
	rng := rand.New(rand.NewPCG(11, 12))
	aws := fakeAWS(rng)
	r := newRedactor(t)
	var wg sync.WaitGroup
	results := make([]string, 8)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], _ = r.Redact("k := \"" + aws + "\"\n")
		}()
	}
	wg.Wait()
	for _, got := range results {
		if got != results[0] || strings.Contains(got, aws) {
			t.Fatalf("concurrent results differ or leak: %q vs %q", got, results[0])
		}
	}
}

// A private-key header placed earlier makes the lazy upstream regex end at
// the real key's header; overlapping matches must still mask the real body.
func TestRedactLazyMatchCannotHideSecret(t *testing.T) {
	rng := rand.New(rand.NewPCG(13, 14))
	key := secretMakers[len(secretMakers)-1](rng)
	body := strings.Split(key, "\n")[1]
	decoy := "-----BEGIN PRIV" + "ATE KEY-----\n" + strings.Repeat("x", 80) + "\n"
	out := mustRedact(t, newRedactor(t), decoy+key+"\n")
	if strings.Contains(out, body) {
		t.Fatalf("key body leaked: %q", out)
	}
}
