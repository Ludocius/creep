package redact

import (
	"math/rand/v2"
	"strings"
	"testing"
)

const digits = "0123456789"

// secretMakers build random secrets in formats the vendored rules cover.
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
	func(rng *rand.Rand) string {
		body := fakeToken(rng, alnum+"+/", 64) + "\n" + fakeToken(rng, alnum+"+/", 64)
		return "-----BEGIN RSA PRIV" + "ATE KEY-----\n" + body + "\n-----END RSA PRIV" + "ATE KEY-----"
	},
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
	f.Add("\xff\xfe", "\x00", uint64(7), uint8(4))
	f.Fuzz(func(t *testing.T, before, after string, seed uint64, kind uint8) {
		rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
		secret := secretMakers[int(kind)%len(secretMakers)](rng)
		text := before + "\ncfg := \"" + secret + "\"\n" + after
		if len(text)+len(after)+len(secret)+1 > MaxInputBytes {
			t.Skip("input over the cap")
		}
		r := newRedactor(t)
		out := mustRedact(t, r, text)
		if strings.Contains(out, secret) {
			t.Fatalf("secret leaked\nsecret %q\noutput %q", secret, out)
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
