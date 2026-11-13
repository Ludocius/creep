package redact

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// fileWorstCase is the worst case documented on MaxFileBytes.
const fileWorstCase = 2 * time.Minute

// bodyLinesQuadratic is bodyLines as it was before #74, kept as the
// reference for which lines the blank tail leaves out.
func bodyLinesQuadratic(text string) []bodyLine {
	var lines []bodyLine
	for start := 0; start <= len(text); {
		end := strings.IndexByte(text[start:], '\n')
		if end < 0 {
			end = len(text) - start
		}
		lines = append(lines, trailingToken(text, start, start+end))
		start += end + 1
	}
	for len(lines) > 1 && strings.TrimSpace(text[lines[len(lines)-1].lineStart:]) == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

func TestBodyLinesBlankTail(t *testing.T) {
	key := strings.Repeat("Ab3/+9x", 10)[:64]
	tests := map[string]string{
		"empty":             "",
		"one newline":       "\n",
		"blanks only":       " \n\t\n\r\n",
		"no tail":           "a\nb",
		"newline tail":      "a\n\n\n",
		"spaced tail":       "a\n \n \n ",
		"crlf tail":         "a\r\n\r\n",
		"unicode tail":      "a\n \n\u0085\n ",
		"key then blanks":   key + "\n\n \n",
		"keys then blanks":  key + "\n" + key + "\n\n",
		"blank inside":      "a\n\n\nb\n\n",
		"invalid utf-8":     "a\n\xff\n\n",
		"trailing nbsp key": key + " \n\n",
	}
	for name, text := range tests {
		got, want := bodyLines(text), bodyLinesQuadratic(text)
		if !slices.Equal(got, want) {
			t.Errorf("%s: bodyLines = %v, want %v", name, got, want)
		}
	}
}

// blankTails are files that end in long runs of blank lines, of size n.
var blankTails = map[string]func(n int) string{
	"newlines":        func(n int) string { return strings.Repeat("\n", n) },
	"space lines":     func(n int) string { return strings.Repeat(" \n", n/2) },
	"line then blank": func(n int) string { return "x\n" + strings.Repeat("\n", n-2) },
}

// minFileTime is the fastest of a few File calls, which filters out GC and
// scheduler noise better than one call or the mean.
func minFileTime(t *testing.T, r *Redactor, text string) time.Duration {
	t.Helper()
	best := time.Duration(1<<63 - 1)
	for range 3 {
		start := time.Now()
		if _, err := r.File([]byte(text)); err != nil {
			t.Fatalf("File of %d bytes: %v", len(text), err)
		}
		best = min(best, time.Since(start))
	}
	return best
}

// A file 16 times larger should take about 16 times longer; quadratic work
// takes 256 times longer. The slack of 4x keeps slow or noisy runners green.
func TestFileBlankTailIsLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	const small, large, maxRatio = 64 << 10, MaxFileBytes, 64
	r := newRedactor(t)
	for name, gen := range blankTails {
		smallTime := max(minFileTime(t, r, gen(small)), time.Millisecond)
		largeTime := minFileTime(t, r, gen(large))
		t.Logf("%s: %d bytes in %s, %d in %s", name, small, smallTime, large, largeTime)
		if largeTime > fileWorstCase {
			t.Errorf("%s: File of %d bytes took %s, over %s", name, large, largeTime, fileWorstCase)
		}
		if ratio := float64(largeTime) / float64(smallTime); ratio > maxRatio {
			t.Errorf("%s: %d bytes took %s, %d took %s: ratio %.0f over %d",
				name, small, smallTime, large, largeTime, ratio, maxRatio)
		}
	}
}
