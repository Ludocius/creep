package redact

import (
	"strings"
	"testing"
	"time"
)

func fill(unit string) string {
	return strings.Repeat(unit, MaxInputBytes/len(unit))
}

// largeInputs are near-misses for the detectors at the size cap: long runs
// of digits or word characters, "@" chains, common keywords, marker prefixes.
func largeInputs() map[string]string {
	return map[string]string{
		"code":     fill("func f(a int) string { return fmt.Sprintf(\"%d\", a) }\n"),
		"digits":   fill("4"),
		"word":     fill("a"),
		"at signs": fill("a@"),
		"keywords": fill("api_key = token secret password "),
		"markers":  fill("<SECRET_"),
		"hex kw":   fill("api_key=" + strings.Repeat("0123456789abcdef", 2) + " "),
	}
}

// everyKeyword wakes every rule, then pads with a word run: the slowest input
// found for the rule set, measured only by BenchmarkRedact.
func everyKeyword(tb testing.TB) string {
	rules, err := defaultRules()
	if err != nil {
		tb.Fatal(err)
	}
	var b strings.Builder
	for _, r := range rules {
		b.WriteString(strings.Join(r.keywords, " ") + "\n")
	}
	return b.String() + fill("a")[b.Len():]
}

// RE2 is linear, so these finish quickly. The bound is generous for slow CI
// runners and -race; it catches a quadratic regression, not small slowdowns.
func TestRedactLargeInputIsBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	r := newRedactor(t)
	for name, text := range largeInputs() {
		start := time.Now()
		if _, err := r.Redact(text); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if d := time.Since(start); d > 30*time.Second {
			t.Errorf("%s: Redact of %d bytes took %s", name, len(text), d)
		}
	}
}

func BenchmarkRedact(b *testing.B) {
	inputs := largeInputs()
	inputs["every keyword"] = everyKeyword(b)
	r := newRedactor(b)
	for name, text := range inputs {
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(text)))
			for b.Loop() {
				if _, err := r.Redact(text); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
