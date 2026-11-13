package redact

import (
	"math/rand/v2"
	"sort"
	"strings"
	"testing"
)

// plant is a secret to insert into a file: the text inserted and the parts
// none of whose 8-byte windows may appear in the output.
type plant struct {
	text   string
	hidden []string
}

func pkcs8Key(rng *rand.Rand) plant {
	key, body := fakeKey(rng, "", 1624, 64)
	return plant{"\n" + key + "\n", body}
}

func opensshKey(rng *rand.Rand) plant {
	key, body := fakeKey(rng, "OPENSSH", 2600, 70)
	return plant{"\n" + key + "\n", body}
}

func gitHubPAT(rng *rand.Rand) plant {
	pat := fakeGitHub(rng)
	return plant{" token := \"" + pat + "\" ", []string{pat}}
}

func dbURL(rng *rand.Rand) plant {
	pw := fakePassword(rng)
	return plant{" dsn := \"postgres://app:" + pw + "@db.internal:5432/app\" ", []string{pw}}
}

// longJWT is longer than chunkOverlap, so only the line guarantee keeps it
// whole.
func longJWT(rng *rand.Rand) plant {
	jwt := "eyJ" + fakeToken(rng, alnum, 30) + ".eyJ" + fakeToken(rng, alnum+"_-", chunkOverlap+300) + "." + fakeToken(rng, alnum+"_-", 43)
	return plant{" auth = '" + jwt + "' ", []string{jwt}}
}

// cuts returns every internal chunk boundary of text: chunk ends and starts.
func cuts(text string) []int {
	chunks := chunkBounds(text)
	var out []int
	for i := range len(chunks) - 1 {
		out = append(out, chunks[i].end, chunks[i+1].start)
	}
	return out
}

// firstOpenCut returns the first cut that no range holds strictly inside.
func firstOpenCut(text string, ranges [][2]int) (int, bool) {
	for _, c := range cuts(text) {
		held := false
		for _, r := range ranges {
			held = held || r[0] < c && c < r[1]
		}
		if !held {
			return c, true
		}
	}
	return 0, false
}

// straddleKeys inserts multi-line keys until every chunk boundary of the
// result falls inside one; frac places the boundary within the key.
func straddleKeys(t *testing.T, base string, rng *rand.Rand, frac float64) (string, []plant) {
	t.Helper()
	text, makers := base, []func(*rand.Rand) plant{pkcs8Key, opensshKey}
	var ranges [][2]int
	var plants []plant
	for i := 0; i < 40; i++ {
		c, open := firstOpenCut(text, ranges)
		if !open {
			return text, plants
		}
		p := makers[i%len(makers)](rng)
		// At a line start and never inside another key, so a key never cuts
		// a secret planted before it.
		at := lineStartBefore(text, max(0, c-int(frac*float64(len(p.text)))))
		for _, r := range ranges {
			if r[0] < at && at < r[1] {
				at = r[1]
			}
		}
		text = text[:at] + p.text + text[at:]
		for j := range ranges {
			if ranges[j][0] >= at {
				ranges[j][0] += len(p.text)
				ranges[j][1] += len(p.text)
			}
		}
		ranges = append(ranges, [2]int{at, at + len(p.text)})
		plants = append(plants, p)
	}
	t.Fatal("could not place a key across every chunk boundary")
	return "", nil
}

// plantAroundCuts inserts each single-line secret just before, at and after
// every chunk boundary of base, inside lines: cuts fall at line ends, so a
// one-line secret can only sit in an overlap or touch a boundary.
func plantAroundCuts(base string, rng *rand.Rand, frac float64) (string, []plant) {
	type insertion struct {
		at int
		p  plant
	}
	var ins []insertion
	for _, c := range cuts(base) {
		for k, mk := range []func(*rand.Rand) plant{gitHubPAT, dbURL, longJWT} {
			p := mk(rng)
			ins = append(ins, insertion{max(0, c-int(frac*float64(len(p.text)))-k*97), p})
		}
	}
	sort.Slice(ins, func(i, j int) bool { return ins[i].at > ins[j].at })
	text, plants := base, make([]plant, 0, len(ins))
	for _, in := range ins {
		text = text[:in.at] + in.p.text + text[in.at:]
		plants = append(plants, in.p)
	}
	return text, plants
}

func assertFileHides(t *testing.T, r *Redactor, text string, plants []plant) {
	t.Helper()
	if len(cuts(text)) < 4 {
		t.Fatalf("file of %d bytes has under three chunks", len(text))
	}
	out := mustFile(t, r, text)
	var hidden []string
	for _, p := range plants {
		hidden = append(hidden, p.hidden...)
	}
	if w := leakedWindow(windows(hidden), out); w != "" {
		t.Fatalf("leaked %q", w)
	}
	if r.Unredact(out) != text {
		t.Fatal("Unredact(File(x)) != x")
	}
}

// TestFileHidesSecretsAcrossChunks is the property test of issue #4: keys
// (PKCS#8 and OpenSSH) straddling every internal chunk boundary, and a
// GitHub PAT, a database URL with password and a JWT longer than the overlap
// around every boundary, in about three chunks of real code, never leak an
// 8-byte substring, and File is reversible locally.
func TestFileHidesSecretsAcrossChunks(t *testing.T) {
	base := repoCode(t, 3*MaxInputBytes)
	rng := rand.New(rand.NewPCG(5, 5))
	for _, frac := range []float64{0.05, 0.95} {
		text, lines := plantAroundCuts(base, rng, frac)
		text, keys := straddleKeys(t, text, rng, frac)
		assertFileHides(t, newRedactor(t), text, append(lines, keys...))
	}
}

// TestFileSameMarkerAcrossChunks places one token in the first chunk, in the
// overlap of every pair of chunks and in the last chunk: each copy gets the
// same marker, and only once (no marker inside a marker).
func TestFileSameMarkerAcrossChunks(t *testing.T) {
	base := repoCode(t, 3*MaxInputBytes)
	pat := fakeGitHub(rand.New(rand.NewPCG(6, 6)))
	line := "token := \"" + pat + "\"\n"
	at := []int{len(base), lineStartBefore(base, len(base)/2)}
	for _, c := range cuts(base) {
		at = append(at, lineStartBefore(base, c-1))
	}
	at = append(at, 0)
	sort.Sort(sort.Reverse(sort.IntSlice(at)))
	text := base
	for _, a := range at {
		text = text[:a] + line + text[a:]
	}
	r := newRedactor(t)
	out := mustFile(t, r, text)
	marker := r.state.byValue[pat]
	if marker == "" || strings.Count(out, marker) != len(at) || strings.Contains(out, pat) {
		t.Fatalf("token copies: %d, marker %q appears %d times", len(at), marker, strings.Count(out, marker))
	}
	if again := mustRedact(t, r, line); !strings.Contains(again, marker) {
		t.Fatalf("Redact after File gave another marker: %q", again)
	}
}
