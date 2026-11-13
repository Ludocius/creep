package redact

import (
	"errors"
	"math/rand/v2"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// indexSweep is the search per value that the sweep index replaced: every
// non-overlapping occurrence of every known value of at least minSweepLen
// bytes. The index must find exactly these spans.
func indexSweep(values []string, text string) []span {
	var found []span
	for _, value := range values {
		if len(value) < minSweepLen {
			continue
		}
		for off := 0; ; {
			i := strings.Index(text[off:], value)
			if i < 0 {
				break
			}
			found = append(found, span{start: off + i, end: off + i + len(value)})
			off += i + len(value)
		}
	}
	return found
}

func sortSpans(spans []span) []span {
	slices.SortFunc(spans, func(a, b span) int {
		if a.start != b.start {
			return a.start - b.start
		}
		return a.end - b.end
	})
	return spans
}

func indexOf(t *testing.T, values []string) sweepIndex {
	t.Helper()
	x := newSweepIndex()
	for _, v := range values {
		if len(v) >= minSweepLen && !x.add(v) {
			t.Fatalf("add(%q) refused", v)
		}
	}
	return x
}

func TestSweepIndexMatchesSearchPerValue(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		text   string
	}{
		{"none known", nil, "nothing to see here"},
		{"exactly 8 bytes", []string{"Q7xZ9kLm"}, "a Q7xZ9kLm b Q7xZ9kLm"},
		{"shorter than 8 is not swept", []string{"Q7xZ9kL"}, "a Q7xZ9kL b"},
		{"at both edges", []string{"Q7xZ9kLmP4"}, "Q7xZ9kLmP4 and Q7xZ9kLmP4"},
		{"prefix of another", []string{"Q7xZ9kLm", "Q7xZ9kLmP4r2"}, "Q7xZ9kLmP4r2 Q7xZ9kLm Q7xZ9kLmP4"},
		{"suffix of another", []string{"9kLmP4r2", "Q7xZ9kLmP4r2"}, "Q7xZ9kLmP4r2 9kLmP4r2"},
		{"overlapping values", []string{"abcdEFGH1234", "EFGH1234wxyz"}, "abcdEFGH1234wxyz"},
		{"self-overlapping value", []string{"abababab"}, "ababababababab"},
		{"same window, many lengths", []string{"aaaaaaaa", "aaaaaaaaa", "aaaaaaaaaaaa"}, strings.Repeat("a", 30)},
		{"text shorter than window", []string{"Q7xZ9kLm"}, "Q7xZ"},
		{"value longer than text", []string{"Q7xZ9kLmP4r2"}, "Q7xZ9kLm"},
		{"near miss", []string{"Q7xZ9kLmP4r2"}, "Q7xZ9kLmP4r3 Q7xZ9kLmP4r"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x := indexOf(t, tt.values)
			got := sortSpans(x.find(tt.text))
			want := sortSpans(indexSweep(tt.values, tt.text))
			if !slices.Equal(got, want) {
				t.Fatalf("find = %v, want %v", got, want)
			}
		})
	}
}

// Random values cut from a small alphabet overlap, nest and repeat often.
func TestSweepIndexRandomized(t *testing.T) {
	rng := rand.New(rand.NewPCG(69, 1))
	for round := range 300 {
		text := fakeToken(rng, "ab", 200+rng.IntN(200))
		var values []string
		for range 1 + rng.IntN(12) {
			start := rng.IntN(len(text) - 40)
			values = append(values, text[start:start+minSweepLen+rng.IntN(30)])
		}
		x := newSweepIndex()
		var kept []string
		for _, v := range values {
			if x.add(v) {
				kept = append(kept, v)
			}
		}
		got := sortSpans(x.find(text))
		want := sortSpans(indexSweep(kept, text))
		if !slices.Equal(got, want) {
			t.Fatalf("round %d: find = %v, want %v", round, got, want)
		}
	}
}

func TestSubstringHash(t *testing.T) {
	x := newSweepIndex()
	text := "the quick brown fox jumps over the lazy dog \x00\xff"
	prefix := x.prefixHashes(text)
	for start := 0; start <= len(text); start++ {
		for end := start; end <= len(text); end++ {
			hash, scale := x.hashOf(text[start:end])
			if got := substringHash(prefix, start, end, scale); got != hash {
				t.Fatalf("hash of [%d:%d] = %d, want %d", start, end, got, hash)
			}
		}
	}
}

// Values from earlier fragments are masked where no rule finds them.
func TestRedactSweepsEarlierValues(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		text   string
		hidden []string
	}{
		{"bare reuse", []string{"Q7xZ9kLmP4r2"}, "x := Q7xZ9kLmP4r2\n", []string{"Q7xZ9kLmP4r2"}},
		{"prefixes of each other", []string{"Q7xZ9kLm", "Q7xZ9kLmP4r2"}, "Q7xZ9kLm and Q7xZ9kLmP4r2\n", []string{"Q7xZ9kLm"}},
		{"overlapping", []string{"abcdEFGH1234", "EFGH1234wxyz"}, "v abcdEFGH1234wxyz\n", []string{"abcd", "EFGH", "wxyz"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRedactor(t)
			for _, v := range tt.values {
				r.state.marker(v, "SECRET_TEST")
			}
			out := mustRedact(t, r, tt.text)
			for _, h := range tt.hidden {
				if strings.Contains(out, h) {
					t.Errorf("%q leaked: %q", h, out)
				}
			}
		})
	}
}

func assertRunFull(t *testing.T, r *Redactor, text string) {
	t.Helper()
	out, err := r.Redact(text)
	if !errors.Is(err, ErrRunFull) || out != "" {
		t.Fatalf("Redact = %q, %v; want no output and ErrRunFull", out, err)
	}
}

// Once the map is full, the call that needs a new value and every later call
// fail closed, even one with nothing to mask.
func TestRedactRunFull(t *testing.T) {
	email := "Some text with alice.smith@example.com in it."
	tests := []struct {
		name string
		fill func(s *runState)
	}{
		{"entries", func(s *runState) {
			for i := len(s.byValue); i < maxRunValues; i++ {
				s.byValue["v"+strconv.Itoa(i)] = ""
			}
		}},
		{"bytes", func(s *runState) { s.bytes = maxRunBytes - 5 }},
		// Every window of a run of one byte is the same, so the values made of
		// it fill one window, then the overflow list; the next one cannot be
		// indexed.
		{"window and overflow", func(s *runState) {
			for n := range maxWindowValues + maxOverflowValues + 1 {
				s.marker(strings.Repeat("@", minSweepLen+n), "SECRET_TEST")
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRedactor(t)
			mustRedact(t, r, "ordinary text")
			tt.fill(r.state)
			assertRunFull(t, r, email)
			assertRunFull(t, r, "ordinary text")
			if _, err := r.File([]byte("ordinary text\n")); !errors.Is(err, ErrRunFull) {
				t.Fatalf("File err = %v, want ErrRunFull", err)
			}
		})
	}
}

// Files that each hold an unterminated private key store the key as one
// value up to the end of the file; the byte cap ends the run instead of
// growing memory, and no body is ever returned.
func TestFileUnterminatedKeysStayWithinCap(t *testing.T) {
	rng := rand.New(rand.NewPCG(69, 5))
	r := newRedactor(t)
	r.state.bytes = maxRunBytes - 3*(64<<10) // as if many such files came before
	for i := range 8 {
		body := fakeBody(rng, 60000, 64)
		file := pemEdge("BEGIN", "RSA") + "\n" + strings.Join(body, "\n") + "\n"
		out, err := r.File([]byte(file))
		if r.state.bytes > maxRunBytes {
			t.Fatalf("file %d: %d bytes stored, cap %d", i, r.state.bytes, maxRunBytes)
		}
		if errors.Is(err, ErrRunFull) {
			if out != "" || i == 0 {
				t.Fatalf("file %d: ErrRunFull with %d bytes of output", i, len(out))
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		assertNoBody(t, body, out)
	}
	t.Fatal("run never filled")
}

func TestWindowLeastCrowded(t *testing.T) {
	x := newSweepIndex()
	for _, v := range []string{"-----BEGIN RSA", "-----BEGIN EC K"} {
		if !x.add(v) {
			t.Fatalf("add(%q) refused", v)
		}
	}
	if got := x.values[1].offset; got != 1 {
		t.Fatalf("second value indexed at offset %d, want 1 (first window taken)", got)
	}
}

// overlapRule matches from any blank before "k=" to the end of a long word:
// every blank starts a match that runs over all of the word, so searching
// from each start again is quadratic without the restart budget.
func overlapRule() secretRule {
	return secretRule{label: "SECRET_TEST", re: regexp.MustCompile(` +k=(\w+)`), secretGroup: 1}
}

func TestFindRestartBudgetMasksRest(t *testing.T) {
	text := strings.Repeat(" ", 4096) + "k=" + strings.Repeat("w", 8192) + " tail"
	spans := overlapRule().find(text)
	last := spans[len(spans)-1]
	if last.end != len(text) || last.start >= 4096 {
		t.Fatalf("last span %v, want the rest of the text from a restart in the blanks", last)
	}
	if len(spans) > restartBudget*len(text)/8192+2 {
		t.Fatalf("%d searches, want the budget to stop them", len(spans))
	}
}

func TestFindWithinBudgetUnchanged(t *testing.T) {
	text := "  k=" + strings.Repeat("w", 100) + " x"
	got := overlapRule().find(text)
	want := []span{{4, 104, "SECRET_TEST"}, {4, 104, "SECRET_TEST"}}
	if !slices.Equal(got, want) {
		t.Fatalf("find = %v, want %v", got, want)
	}
}

// Placeholder secrets made of one repeated byte fill every window they have;
// the overflow list keeps them, so the run goes on and still re-masks them.
func TestRedactRepeatedBytePlaceholders(t *testing.T) {
	tests := []struct {
		name  string
		bytes string
	}{
		{"one byte, many lengths", "x"},
		{"many crowded bytes", "abcdefgh"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRedactor(t)
			var bare strings.Builder
			for _, c := range tt.bytes {
				for n := minSweepLen; n <= 40; n++ {
					v := strings.Repeat(string(c), n)
					mustRedact(t, r, "password = \""+v+"\"\n")
					bare.WriteString("x := " + v + "\n")
				}
			}
			if r.state.index.overflowCount == 0 {
				t.Fatal("no value reached the overflow list")
			}
			out := mustRedact(t, r, bare.String())
			for _, c := range tt.bytes {
				if run := strings.Repeat(string(c), minSweepLen); strings.Contains(out, run) {
					t.Fatalf("%q leaked: %q", run, out)
				}
			}
		})
	}
}
