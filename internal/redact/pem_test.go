package redact

import (
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
	"testing"
)

const base64Chars = alnum + "+/"

// Header and footer are split so this file holds no literal key pattern.
func pemLine(edge, kind string) string {
	return "-----" + edge + " " + kind + " PRIV" + "ATE KEY-----"
}

// keyKinds are the private-key header variants the gitleaks rule accepts.
var keyKinds = []string{"RSA", "EC", "DSA", "OPENSSH", "ENCRYPTED", "", "PGP"}

func pemEdge(edge, kind string) string {
	switch kind {
	case "":
		return strings.Replace(pemLine(edge, "X"), " X ", " ", 1)
	case "PGP":
		return strings.Replace(pemLine(edge, "PGP"), "KEY-----", "KEY BLOCK-----", 1)
	}
	return pemLine(edge, kind)
}

// fakeBody returns size random base64 characters cut into lines of width,
// the last one shorter and padded, as in a real key.
func fakeBody(rng *rand.Rand, size, width int) []string {
	raw := fakeToken(rng, base64Chars, size-2) + "=="
	var lines []string
	for len(raw) > width {
		lines = append(lines, raw[:width])
		raw = raw[width:]
	}
	return append(lines, raw)
}

// fakeKey returns a complete key of the given kind and its body lines.
func fakeKey(rng *rand.Rand, kind string, size, width int) (string, []string) {
	body := fakeBody(rng, size, width)
	key := pemEdge("BEGIN", kind) + "\n" + strings.Join(body, "\n") + "\n" + pemEdge("END", kind)
	return key, body
}

// windows holds every 8-byte substring of the body lines: none may appear in
// any output.
func windows(body []string) map[string]bool {
	set := map[string]bool{}
	for _, line := range body {
		for i := 0; i+8 <= len(line); i++ {
			set[line[i:i+8]] = true
		}
	}
	return set
}

func leakedWindow(set map[string]bool, out string) string {
	for i := 0; i+8 <= len(out); i++ {
		if set[out[i:i+8]] {
			return out[i : i+8]
		}
	}
	return ""
}

func assertNoBody(t *testing.T, body []string, outs ...string) {
	t.Helper()
	set := windows(body)
	for _, out := range outs {
		if w := leakedWindow(set, out); w != "" {
			t.Fatalf("key body leaked %q in %q", w, out)
		}
	}
}

func TestRedactUnterminatedPrivateKey(t *testing.T) {
	rng := rand.New(rand.NewPCG(21, 22))
	for _, kind := range keyKinds {
		for _, lines := range []int{1, 3} {
			t.Run(kind, func(t *testing.T) {
				body := fakeBody(rng, 64*lines, 64)[:lines]
				text := "const k = `" + pemEdge("BEGIN", kind) + "\n" + strings.Join(body, "\n") + "\n"
				assertNoBody(t, body, mustRedact(t, newRedactor(t), text))
			})
		}
	}
}

func TestRedactHeadlessPrivateKey(t *testing.T) {
	rng := rand.New(rand.NewPCG(23, 24))
	for _, kind := range keyKinds {
		for _, size := range []int{20, 64, 300} {
			t.Run(kind, func(t *testing.T) {
				body := fakeBody(rng, size, 64)
				text := strings.Join(body, "\n") + "\n" + pemEdge("END", kind) + "`\n\nfunc f() {}\n"
				assertNoBody(t, body, mustRedact(t, newRedactor(t), text))
			})
		}
	}
}

func TestRedactKeyBodyOnly(t *testing.T) {
	rng := rand.New(rand.NewPCG(25, 26))
	two := fakeBody(rng, 128, 64)[:2]
	many := fakeBody(rng, 400, 64)
	ssh := fakeBody(rng, 300, 70)
	edge := fakeBody(rng, 64, 64)[:1]
	tests := []struct {
		name string
		body []string
		text string
	}{
		{"two lines", two, strings.Join(two, "\n")},
		{"run with short last line", many, "x\n" + strings.Join(many, "\n") + "\ny\n"},
		{"go raw string", many, "const k = `" + strings.Join(many, "\n") + "`\n\nfunc f() {}\n"},
		{"indented yaml", two, "key: |\n    " + strings.Join(two, "\n    ") + "\nname: x\n"},
		{"openssh width", ssh, "func f() {}\n\n" + strings.Join(ssh, "\n") + "\n"},
		{"single line at start", edge, edge[0] + "\nfunc f() {}\n"},
		{"single line at end", edge, "func f() {}\n" + edge[0] + "\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertNoBody(t, tc.body, mustRedact(t, newRedactor(t), tc.text))
		})
	}
}

// A key cut at any byte into two fragments must leak from neither. The
// offsets are sharded over parallel subtests to keep -race runs short.
func TestRedactSplitPrivateKey(t *testing.T) {
	const shards = 8
	keys := []struct {
		kind  string
		width int
	}{{"RSA", 64}, {"OPENSSH", 70}}
	for n, k := range keys {
		key, body := fakeKey(rand.New(rand.NewPCG(27, uint64(n))), k.kind, 3164, k.width)
		set := windows(body)
		for shard := range shards {
			t.Run(fmt.Sprint(k.kind, "/", shard), func(t *testing.T) {
				t.Parallel()
				for i := shard; i <= len(key); i += shards {
					assertSplitHidden(t, set, key, i)
				}
			})
		}
	}
}

func assertSplitHidden(t *testing.T, set map[string]bool, key string, i int) {
	t.Helper()
	r := newRedactor(t)
	for _, part := range []string{key[:i], key[i:]} {
		if w := leakedWindow(set, mustRedact(t, r, part)); w != "" {
			t.Fatalf("split at %d leaked %q", i, w)
		}
	}
}

func TestRedactCompleteKeyOneMarker(t *testing.T) {
	rng := rand.New(rand.NewPCG(29, 30))
	key, body := fakeKey(rng, "RSA", 1200, 64)
	text := "const k = `" + key + "`\n\nfunc f() {}\n"
	r := newRedactor(t)
	out := mustRedact(t, r, text)
	want := "const k = `<SECRET_PRIVATE_KEY_1>`\n\nfunc f() {}\n"
	if out != want {
		t.Fatalf("got %q, want %q", out, want)
	}
	if again := mustRedact(t, r, text); again != out {
		t.Fatalf("marker not stable: %q", again)
	}
	if back := r.Unredact(out); back != text {
		t.Fatalf("Unredact is not the inverse: %q", back)
	}
	assertNoBody(t, body, out)
}

// Ordinary code and data must not look like a key body.
func TestPrivateKeyDetectorIgnoresCode(t *testing.T) {
	gosum, err := os.ReadFile("../../go.sum")
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewPCG(31, 32))
	hexes := fakeToken(rng, "0123456789abcdef", 40) + "\n" + fakeToken(rng, "0123456789abcdef", 40) + "\n"
	samples := map[string]string{
		"go.sum":              string(gosum),
		"hex digests":         hexes,
		"digests with prefix": "sha256:" + fakeToken(rng, base64Chars, 43) + "=\nsha256:" + fakeToken(rng, base64Chars, 43) + "=\n",
		"prose":               "// findBodyRuns masks key bodies with no header or footer at all\n// or one such line at the start or end of the text where it was cut\n",
	}
	for i, chunk := range repoChunks(t) {
		samples[fmt.Sprint("repo chunk ", i)] = chunk
	}
	for name, text := range samples {
		if got := findPrivateKeys(text); len(got) > 0 {
			sp := got[0]
			t.Errorf("%s: masked %q", name, text[sp.start:sp.end])
		}
	}
}
