package redact

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
)

const digits = "0123456789"

// secretMakers build random secrets in formats the secret rules cover.
// Prefixes are split so this file holds no literal credential pattern.
var secretMakers = []func(*rand.Rand) string{
	fakeAWS,
	fakeGitHub,
	func(rng *rand.Rand) string { return "gl" + "pat-" + fakeToken(rng, alnum+"_-", 20) },
	func(rng *rand.Rand) string {
		return "xo" + "xb-" + fakeToken(rng, digits, 11) + "-" + fakeToken(rng, digits, 12) + "-" + fakeToken(rng, alnum, 24)
	},
	func(rng *rand.Rand) string { return "sk" + "_live_" + fakeToken(rng, alnum, 24) },
	func(rng *rand.Rand) string { return "sk-" + "ant-api03-" + fakeToken(rng, alnum+"_-", 93) + "AA" },
	// rules/local.toml (#75); a trailing "-" escaped the vendored OpenAI rule.
	func(rng *rand.Rand) string { return fakeDockerPAT(rng, '-') },
	func(rng *rand.Rand) string { return fakeOpenAIKey(rng, '-') },
	// Keys cut by a fragment boundary: no END, no BEGIN, neither.
	func(rng *rand.Rand) string {
		return pemEdge("BEGIN", "OPENSSH") + "\n" + strings.Join(fakeBody(rng, 200, 70), "\n")
	},
	func(rng *rand.Rand) string {
		return strings.Join(fakeBody(rng, 200, 64), "\n") + "\n" + pemEdge("END", "EC")
	},
	func(rng *rand.Rand) string { return strings.Join(fakeBody(rng, 128, 64), "\n") },
	// The complete key stays last: TestRedactLazyMatchCannotHideSecret uses it.
	func(rng *rand.Rand) string {
		body := fakeToken(rng, alnum+"+/", 64) + "\n" + fakeToken(rng, alnum+"+/", 64)
		return "-----BEGIN RSA PRIV" + "ATE KEY-----\n" + body + "\n-----END RSA PRIV" + "ATE KEY-----"
	},
}

// credentialMakers build a line holding a random password in a format that
// has no fixed prefix (URL userinfo, key = value); they return the line and
// the password that must not leak.
var credentialMakers = []func(*rand.Rand) (string, string){
	func(rng *rand.Rand) (string, string) {
		pw := fakePassword(rng)
		schemes := []string{"postgres", "mysql", "redis", "amqp", "sqlserver", "mongodb+srv", "https"}
		host := []string{"db.internal", "cache:6379/0", "x.example.com/app?ssl=true"}[rng.IntN(3)]
		return schemes[rng.IntN(len(schemes))] + "://user:" + pw + "@" + host, pw
	},
	func(rng *rand.Rand) (string, string) {
		pw := fakePassword(rng)
		keys := []string{"password", "passwd", "pwd", "DB_PASSWORD", "spring.datasource.password", "client_secret"}
		forms := []string{"%s=%s", "%s: %s", "%s = \"%s\"", "%s := '%s'", "\"%s\": \"%s\"", "%s => `%s`"}
		return fmt.Sprintf(forms[rng.IntN(len(forms))], keys[rng.IntN(len(keys))], pw), pw
	},
}

// fakePassword mixes letters, digits and the punctuation people put in
// passwords, but not quotes, commas, semicolons or spaces, which end a bare
// value. Letters at both ends keep it from looking like a reference the
// detector leaves alone on purpose (${VAR}, <placeholder>, getPassword()).
func fakePassword(rng *rand.Rand) string {
	return fakeToken(rng, alnum, 4) + fakeToken(rng, alnum+"!#%^&*()-_+[]{}.~", 10) + fakeToken(rng, alnum, 2)
}

// fakeLine returns the line to embed and the secret that must not leak.
func fakeLine(rng *rand.Rand, kind int) (string, string) {
	if kind < len(secretMakers) {
		secret := secretMakers[kind](rng)
		return "cfg := \"" + secret + "\"", secret
	}
	return credentialMakers[kind-len(secretMakers)](rng)
}

// FuzzRedactSecrets embeds a random secret in a line of code between
// arbitrary text and checks it never reaches the output (the gateway
// payload), neither in the fragment that holds it nor in a later fragment
// that repeats it without context. Redact must also be reversible locally.
func FuzzRedactSecrets(f *testing.F) {
	f.Add("package main\n", "func main() {}\n", uint64(1), uint8(0))
	f.Add("", "", uint64(2), uint8(1))
	f.Add("<SECRET_AWS_ACCESS_TOKEN_1>", "<ESC_PII_EMAIL_1>", uint64(3), uint8(2))
	f.Add("api_key = ", "token: x@y.io 4111 1111 1111 1111", uint64(4), uint8(3))
	f.Add("-----BEGIN PRIV"+"ATE KEY-----", "-----END", uint64(5), uint8(6))
	f.Add("<<<", ">>>", uint64(6), uint8(5))
	f.Add("x := `", "`", uint64(10), uint8(7))
	f.Add("-----BEGIN EC PRIV"+"ATE KEY-----", "", uint64(11), uint8(8))
	f.Add("", "-----END RSA PRIV"+"ATE KEY-----", uint64(12), uint8(9))
	f.Add("\xff\xfe", "\x00", uint64(7), uint8(4))
	f.Add("x = 1", "", uint64(8), uint8(7))
	f.Add("[db]", "url: x", uint64(9), uint8(8))
	f.Fuzz(func(t *testing.T, before, after string, seed uint64, kind uint8) {
		rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
		line, secret := fakeLine(rng, int(kind)%(len(secretMakers)+len(credentialMakers)))
		text := before + "\n" + line + "\n" + after
		if len(text)+len(after)+len(secret)+1 > MaxInputBytes {
			t.Skip("input over the cap")
		}
		r := newRedactor(t)
		out := mustRedact(t, r, text)
		if strings.Contains(out, secret) {
			t.Fatalf("secret leaked\nsecret %q\noutput %q", secret, out)
		}
		if w := leakedWindow(windows(keyBodyLines(secret)), out); w != "" {
			t.Fatalf("key body leaked %q\noutput %q", w, out)
		}
		if back := r.Unredact(out); back != text {
			t.Fatalf("Unredact is not the inverse\n got %q\nwant %q", back, text)
		}
		again := mustRedact(t, r, after+" "+secret)
		if strings.Contains(again, secret) {
			t.Fatalf("known secret leaked in a later fragment: %q", again)
		}
	})
}

// keyBodyLines returns the lines of a multi-line secret other than PEM
// header and footer lines: none of their 8-byte windows may leak.
func keyBodyLines(secret string) []string {
	if !strings.Contains(secret, "\n") {
		return nil
	}
	var body []string
	for _, line := range strings.Split(secret, "\n") {
		if !strings.HasPrefix(line, "-----") {
			body = append(body, line)
		}
	}
	return body
}

// FuzzFile embeds a random secret near the first chunk boundary of a file
// of real code larger than one chunk, at an offset the fuzzer picks, and
// checks it never reaches the output of File, which must stay reversible.
func FuzzFile(f *testing.F) {
	code := repoCode(f, MaxInputBytes+2*chunkOverlap)
	f.Add("", "", uint64(1), uint8(9), uint16(0))
	f.Add("x := `", "`", uint64(2), uint8(6), uint16(3000))
	f.Add("-----BEGIN PRIV"+"ATE KEY-----", "", uint64(3), uint8(8), uint16(4095))
	f.Add("// ", "\n", uint64(4), uint8(10), uint16(6000))
	f.Fuzz(func(t *testing.T, before, after string, seed uint64, kind uint8, offset uint16) {
		rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
		line, secret := fakeLine(rng, int(kind)%(len(secretMakers)+len(credentialMakers)))
		at := MaxInputBytes - 2*chunkOverlap + int(offset)%(3*chunkOverlap)
		text := code[:at] + before + "\n" + line + "\n" + after + code[at:]
		r := newRedactor(t)
		out, err := r.File([]byte(text))
		if err != nil {
			t.Skip(err)
		}
		if strings.Contains(out, secret) {
			t.Fatalf("secret leaked: %q", secret)
		}
		if w := leakedWindow(windows(keyBodyLines(secret)), out); w != "" {
			t.Fatalf("key body leaked %q", w)
		}
		if r.Unredact(out) != text {
			t.Fatal("Unredact(File(x)) != x")
		}
	})
}
