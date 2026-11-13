package redact

import (
	"errors"
	"math/rand/v2"
	"strings"
	"testing"
)

// repoCode returns about n bytes of the repository's own Go code, whole lines.
func repoCode(tb testing.TB, n int) string {
	tb.Helper()
	code := strings.Join(repoChunks(tb), "")
	for len(code) < n {
		code += code
	}
	return code[:lineStartBefore(code, n)]
}

func mustFile(t testing.TB, r *Redactor, text string) string {
	t.Helper()
	out, err := r.File([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestFileLimits(t *testing.T) {
	line := strings.Repeat("a", MaxLineBytes-1) + "\n"
	tests := []struct {
		name string
		text string
		want error
	}{
		{"empty", "", nil},
		{"longest line", line + line[1:], nil},
		{"line too long", "x\n" + strings.Repeat("a", MaxLineBytes+1), ErrLineTooLong},
		{"last line too long", strings.Repeat("a", MaxLineBytes+1), ErrLineTooLong},
		{"over cap", strings.Repeat("a\n", MaxFileBytes/2) + "a", ErrFileTooLarge},
	}
	r := newRedactor(t)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, err := r.File([]byte(tc.text))
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if tc.want != nil && out != "" {
				t.Fatalf("output on error: %d bytes", len(out))
			}
			if tc.want == nil && out != tc.text {
				t.Fatal("output differs from input with nothing to redact")
			}
		})
	}
}

// textWithLines builds n bytes of lines whose lengths cycle through sizes.
func textWithLines(n int, sizes ...int) string {
	var b strings.Builder
	for i := 0; b.Len() < n; i++ {
		b.WriteString(strings.Repeat("x", sizes[i%len(sizes)]-1) + "\n")
	}
	return b.String()
}

func TestChunkBounds(t *testing.T) {
	tests := map[string]string{
		"empty":         "",
		"one line":      "abc",
		"under one":     textWithLines(MaxInputBytes-1, 80),
		"exactly one":   textWithLines(MaxInputBytes, 64),
		"short lines":   textWithLines(5*MaxInputBytes, 1, 7, 80),
		"longest lines": textWithLines(4*MaxInputBytes, MaxLineBytes),
		"mixed":         textWithLines(6*MaxInputBytes, MaxLineBytes, 3, chunkOverlap+1, 500),
		"no final \\n":  textWithLines(3*MaxInputBytes, 100) + "tail",
	}
	for name, text := range tests {
		t.Run(name, func(t *testing.T) {
			chunks := chunkBounds(text)
			assertChunkShape(t, text, chunks)
			assertLinesCovered(t, text, chunks)
		})
	}
}

func isLineStart(text string, i int) bool {
	return i == 0 || i == len(text) || text[i-1] == '\n'
}

// assertChunkShape checks every chunk is whole lines within MaxInputBytes,
// the chunks run from start to end of text, and each overlaps the previous
// one by at least chunkOverlap bytes.
func assertChunkShape(t *testing.T, text string, chunks []chunk) {
	t.Helper()
	if chunks[0].start != 0 || chunks[len(chunks)-1].end != len(text) {
		t.Fatalf("chunks %v do not span the text of %d bytes", chunks, len(text))
	}
	for i, c := range chunks {
		if c.end-c.start > MaxInputBytes || !isLineStart(text, c.start) || !isLineStart(text, c.end) {
			t.Fatalf("chunk %d %v is not whole lines within the cap", i, c)
		}
		if i > 0 && (c.start <= chunks[i-1].start || chunks[i-1].end-c.start < chunkOverlap) {
			t.Fatalf("chunk %d %v after %v: no progress or overlap too short", i, c, chunks[i-1])
		}
	}
}

// assertLinesCovered checks the property chunkBounds documents: each line
// lies in one chunk together with the chunkOverlap bytes before it.
func assertLinesCovered(t *testing.T, text string, chunks []chunk) {
	t.Helper()
	k := 0
	for start := 0; start < len(text); {
		end := len(text)
		if i := strings.IndexByte(text[start:], '\n'); i >= 0 {
			end = start + i + 1
		}
		from := max(0, start-chunkOverlap)
		for k < len(chunks)-1 && chunks[k+1].start <= from {
			k++
		}
		if chunks[k].start > from || chunks[k].end < end {
			t.Fatalf("line [%d,%d) with overlap from %d is in no chunk", start, end, from)
		}
		start = end
	}
}

// TestFileMatchesRedact: under one chunk, File and Redact agree.
func TestFileMatchesRedact(t *testing.T) {
	rng := rand.New(rand.NewPCG(4, 4))
	key, _ := fakeKey(rng, "RSA", 600, 64)
	inputs := []string{
		"",
		"package main\n\nfunc main() {}\n",
		"token := \"" + fakeGitHub(rng) + "\"\nemail: a@b.io\n" + key + "\n",
		"x\n" + pemEdge("END", "EC") + "\n<SECRET_X_1>\n",
	}
	for _, text := range inputs {
		want := mustRedact(t, newRedactor(t), text)
		if got := mustFile(t, newRedactor(t), text); got != want {
			t.Errorf("File(%q)\n got %q\nwant %q", text, got, want)
		}
	}
}

func BenchmarkFileRepoCode(b *testing.B) {
	code := []byte(repoCode(b, 1<<20))
	r := newRedactor(b)
	b.SetBytes(int64(len(code)))
	for b.Loop() {
		if _, err := r.File(code); err != nil {
			b.Fatal(err)
		}
	}
}
