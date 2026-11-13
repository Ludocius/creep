package redact

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// MaxInputBytes bounds one Redact call. RE2 is linear, but with a large
// constant: ordinary code wakes only a few rules and takes tens of
// milliseconds at the cap, while input crafted to hold every rule keyword
// before a long word run makes all ~220 rules scan it, about 10 s at the cap
// (BenchmarkRedact, "every keyword"). Callers split larger files.
const MaxInputBytes = 64 << 10

// maxMarkerLen bounds how far Unredact looks for the closing ">".
const maxMarkerLen = 128

// minSweepLen is the shortest known value re-masked wherever it appears.
// Shorter values would match inside ordinary identifiers.
const minSweepLen = 8

// ErrTooLarge is returned for input over MaxInputBytes.
var ErrTooLarge = errors.New("input exceeds redact.MaxInputBytes")

// Redactor redacts the fragments of one run. It keeps the value-to-marker map
// in memory only so that the same value gets the same marker in every
// fragment. It is safe for concurrent use.
//
// The map has no exported field, no encoding method and prints as a fixed
// string, so it cannot be serialized or logged by accident.
type Redactor struct {
	rules []secretRule
	mu    sync.Mutex
	state *runState // behind a pointer: fmt never prints nested pointees
}

type runState struct {
	byValue  map[string]string // original value -> marker
	byMarker map[string]string // marker -> original value
	counters map[string]int    // label -> last number used
}

// span is a byte range of the input to replace; label names the marker kind.
type span struct {
	start, end int
	label      string
}

// New returns a Redactor loaded with the vendored gitleaks rules.
func New() (*Redactor, error) {
	rules, err := defaultRules()
	if err != nil {
		return nil, fmt.Errorf("redact: load rules: %w", err)
	}
	return &Redactor{rules: rules, state: &runState{
		byValue:  map[string]string{},
		byMarker: map[string]string{},
		counters: map[string]int{},
	}}, nil
}

// Format prints a fixed string for every verb so %v, %+v and %#v never
// reveal the map.
func (r *Redactor) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("redact.Redactor{...}"))
}

// Redact returns text with secrets and personal data replaced by markers and
// pre-existing marker-like text escaped. It fails closed on oversized input.
func (r *Redactor) Redact(text string) (string, error) {
	if len(text) > MaxInputBytes {
		return "", fmt.Errorf("redact %d bytes: %w", len(text), ErrTooLarge)
	}
	found := r.detect(text)
	r.mu.Lock()
	defer r.mu.Unlock()
	found = append(found, r.state.sweep(text)...)
	out := r.state.render(text, mergeSpans(found))
	r.state.rememberParts(text, found)
	return out, nil
}

// rememberParts gives a marker to each value that was masked only as part of
// a merged span (a URL password run into an email), so the sweep still masks
// it when it shows up alone in a later fragment.
func (s *runState) rememberParts(text string, found []span) {
	for _, sp := range found {
		if sp.label != "" && sp.end-sp.start >= minSweepLen {
			s.marker(text[sp.start:sp.end], sp.label)
		}
	}
}

// detect runs every secret rule and PII detector over text.
func (r *Redactor) detect(text string) []span {
	var found []span
	lower := strings.ToLower(text)
	for _, rule := range r.rules {
		if rule.applies(lower) {
			found = append(found, rule.find(text)...)
		}
	}
	for _, d := range credentialDetectors {
		found = append(found, d.find(text)...)
	}
	for _, d := range piiDetectors {
		found = append(found, d.find(text)...)
	}
	return found
}

// sweep finds values already redacted in earlier fragments, even where no
// rule matches them now (a key reused without its variable name).
func (s *runState) sweep(text string) []span {
	var found []span
	for value := range s.byValue {
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

// mergeSpans sorts spans and joins overlapping ones, so every secret byte is
// covered even when two rules disagree on the bounds. The most specific label
// (labelRank) names the merged span, so a URL password that runs into an
// email is one secret, and a GitHub token is not called a generic key.
func mergeSpans(spans []span) []span {
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start != spans[j].start {
			return spans[i].start < spans[j].start
		}
		return spans[i].end > spans[j].end
	})
	var out []span
	for _, s := range spans {
		last := len(out) - 1
		if last >= 0 && s.start < out[last].end {
			out[last].end = max(out[last].end, s.end)
			if labelRank(s.label) > labelRank(out[last].label) {
				out[last].label = s.label
			}
			continue
		}
		out = append(out, s)
	}
	return out
}

// render writes the escaped text with each span replaced by its marker.
func (s *runState) render(text string, spans []span) string {
	var b strings.Builder
	b.Grow(len(text))
	prev := 0
	for _, sp := range spans {
		writeEscaped(&b, text[prev:sp.start])
		b.WriteString(s.marker(text[sp.start:sp.end], sp.label))
		prev = sp.end
	}
	writeEscaped(&b, text[prev:])
	return b.String()
}

// marker returns the value's marker, assigning the next number for its label
// the first time the value is seen in this run.
func (s *runState) marker(value, label string) string {
	if m, ok := s.byValue[value]; ok {
		return m
	}
	if label == "" {
		label = secretPrefix + "VALUE"
	}
	s.counters[label]++
	m := "<" + label + "_" + strconv.Itoa(s.counters[label]) + ">"
	s.byValue[value] = m
	s.byMarker[m] = value
	return m
}

// Unredact restores the original values in text produced by this Redactor,
// for local display only: its output must never be sent to a model. Unknown
// markers stay as they are, and escaped marker-like text gets its original
// spelling back.
func (r *Redactor) Unredact(text string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var b strings.Builder
	for {
		i := strings.IndexByte(text, '<')
		if i < 0 {
			b.WriteString(text)
			return b.String()
		}
		b.WriteString(text[:i])
		text = text[i:]
		n := r.state.unredactAt(&b, text)
		text = text[n:]
	}
}

// unredactAt handles the "<" at the start of text and returns how many bytes
// it consumed.
func (s *runState) unredactAt(b *strings.Builder, text string) int {
	rest := text[1:]
	if strings.HasPrefix(rest, escapeTag) && startsReserved(rest[len(escapeTag):]) {
		b.WriteByte('<')
		return 1 + len(escapeTag)
	}
	end := strings.IndexByte(rest, '>')
	if end >= 0 && end < maxMarkerLen {
		if value, ok := s.byMarker[text[:end+2]]; ok {
			b.WriteString(value)
			return end + 2
		}
	}
	b.WriteByte('<')
	return 1
}
