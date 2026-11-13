package redact

import (
	"math/rand/v2"
	"regexp/syntax"
	"slices"
	"strings"
	"testing"
)

// sampleGen writes one string a rule regex can match. class marks the bytes
// drawn from character classes: that is the variable material of a match,
// the secret. Bytes from literals (key names, prefixes such as "ghp_", hosts)
// are fixed by the rule and so are context, safe to leave visible.
type sampleGen struct {
	rng    *rand.Rand
	random bool // pick random alternatives and repeat counts, not the first and the minimum
	buf    []byte
	class  []bool
}

func (g *sampleGen) emit(s string, class bool) {
	g.buf = append(g.buf, s...)
	for range len(s) {
		g.class = append(g.class, class)
	}
}

func (g *sampleGen) walk(re *syntax.Regexp) {
	switch re.Op {
	case syntax.OpLiteral:
		g.emit(string(re.Rune), false)
	case syntax.OpCharClass:
		g.emit(string(g.pick(re.Rune)), true)
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		g.emit(string(alnum[g.rng.IntN(len(alnum))]), true)
	case syntax.OpCapture, syntax.OpConcat:
		for _, sub := range re.Sub {
			g.walk(sub)
		}
	case syntax.OpAlternate:
		g.walk(re.Sub[g.choose(len(re.Sub))])
	case syntax.OpStar, syntax.OpQuest:
		g.repeat(re.Sub[0], 0)
	case syntax.OpPlus:
		g.repeat(re.Sub[0], 1)
	case syntax.OpRepeat:
		g.repeat(re.Sub[0], re.Min)
	}
}

func (g *sampleGen) choose(n int) int {
	if !g.random {
		return 0
	}
	return g.rng.IntN(n)
}

func (g *sampleGen) repeat(sub *syntax.Regexp, n int) {
	if g.random {
		n += g.rng.IntN(2)
	}
	for range n {
		g.walk(sub)
	}
}

// pick returns a random alphanumeric rune of the class, or its first
// printable ASCII rune when it has no alphanumeric one.
func (g *sampleGen) pick(ranges []rune) rune {
	var in []rune
	for _, c := range alnum + " =:\"'-_./\n" {
		for i := 0; i+1 < len(ranges); i += 2 {
			if ranges[i] <= c && c <= ranges[i+1] {
				in = append(in, c)
			}
		}
	}
	if n := strings.IndexFunc(string(in), func(c rune) bool { return !strings.ContainsRune(alnum, c) }); n > 0 {
		in = in[:n]
	}
	if len(in) == 0 {
		return ranges[0]
	}
	return in[g.rng.IntN(len(in))]
}

// ruleSample is a text that rule r matches, with the 8-byte windows of its
// secret material: every class run of 8 or more bytes inside the match and
// every participating capture group of 8 or more bytes.
type ruleSample struct {
	text   string
	secret []string
}

func sampleFor(r secretRule, rng *rand.Rand) (ruleSample, bool) {
	parsed, err := syntax.Parse(r.re.String(), syntax.Perl)
	if err != nil {
		return ruleSample{}, false
	}
	for attempt := range 200 {
		g := &sampleGen{rng: rng, random: attempt > 0}
		g.walk(parsed)
		if s, ok := g.sample(r); ok {
			return s, true
		}
	}
	return ruleSample{}, false
}

func (g *sampleGen) sample(r secretRule) (ruleSample, bool) {
	prefix := keywordLine(r, string(g.buf))
	text := prefix + string(g.buf) + "\n"
	m := r.re.FindStringSubmatchIndex(text)
	if m == nil || m[0] < len(prefix) {
		return ruleSample{}, false
	}
	s := ruleSample{text: text}
	for i := 2; i+1 < len(m); i += 2 {
		if m[i] >= 0 && m[i+1]-m[i] >= 8 && i/2 != secretContextGroup(r) {
			s.secret = append(s.secret, text[m[i]:m[i+1]])
		}
	}
	end := min(m[1]-len(prefix), len(g.buf)) // the match may take the closing newline
	s.secret = append(s.secret, g.classRuns(m[0]-len(prefix), end)...)
	return s, true
}

// keywordLine opens the gate of a rule whose sample lacks every keyword.
func keywordLine(r secretRule, sample string) string {
	if r.applies(strings.ToLower(sample)) {
		return ""
	}
	return r.keywords[0] + "\n"
}

// secretContextGroup is the group a rule declares as not the secret: with an
// explicit secretGroup, gitleaks treats the other groups as context (sonar's
// "login|token" key name). Only a group that the explicit group does not
// contain can be context.
func secretContextGroup(r secretRule) int {
	if r.secretGroup == 2 {
		return 1
	}
	return -1
}

func (g *sampleGen) classRuns(from, to int) []string {
	var runs []string
	start := -1
	for i := from; i <= to; i++ {
		if i < to && g.class[i] {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= 8 {
			runs = append(runs, string(g.buf[start:i]))
		}
		start = -1
	}
	return runs
}

// maskRule blanks only the spans rule finds in text.
func maskRule(rule secretRule, text string) string {
	b := []byte(text)
	for _, sp := range rule.find(text) {
		for i := sp.start; i < sp.end; i++ {
			b[i] = 0
		}
	}
	return string(b)
}

// unsampled lists the rules the generator cannot match, with the reason.
var unsampled = map[string]string{}

// Every rule must hide all of its secret material: no 8-byte window of a
// class run or a capture group of its match may survive Redact. This is what
// D1 broke: jwt-base64 masked only its named header group.
func TestEveryRuleHidesItsMatch(t *testing.T) {
	rules, err := defaultRules()
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewPCG(4, 68))
	var skipped []string
	covered := 0
	for _, rule := range rules {
		s, ok := sampleFor(rule, rng)
		if !ok {
			skipped = append(skipped, rule.label)
			continue
		}
		covered++
		set := windows(s.secret)
		// Alone, because other detectors (PEM body runs, credential
		// patterns) can cover a rule's gap on one sample and not on the next.
		if w := leakedWindow(set, maskRule(rule, s.text)); w != "" {
			t.Errorf("%s alone leaked %q in %q", rule.label, w, s.text)
		}
		out := mustRedact(t, newRedactor(t), s.text)
		if w := leakedWindow(set, out); w != "" {
			t.Errorf("%s leaked %q:\nin:  %q\nout: %q", rule.label, w, s.text, out)
		}
	}
	slices.Sort(skipped)
	t.Logf("covered %d rules, skipped %v", covered, skipped)
	for _, label := range skipped {
		if _, known := unsampled[label]; !known {
			t.Errorf("no sample for %s; fix the generator or add it to unsampled with a reason", label)
		}
	}
}

// D1: a base64-encoded JWT must be masked whole, not just the header group
// that names its first field.
func TestJWTBase64MaskedWhole(t *testing.T) {
	rng := rand.New(rand.NewPCG(6, 4))
	tok := "ZXlK" + "aGJHY2lPaUpJVXpJ" + fakeToken(rng, alnum+"+/", 72)
	tests := []struct{ name, text string }{
		{"bare", "header " + tok + " sent\n"},
		{"bare line", tok + "\n"},
		{"quoted", "auth = \"" + tok + "\"\n"},
		{"yaml", "jwt:\n  token: " + tok + "\n  ttl: 60\n"},
	}
	set := windows([]string{tok})
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newRedactor(t)
			viaRedact := mustRedact(t, r, tc.text)
			viaFile, err := newRedactor(t).File([]byte(tc.text))
			if err != nil {
				t.Fatal(err)
			}
			for _, out := range []string{viaRedact, viaFile} {
				if w := leakedWindow(set, out); w != "" {
					t.Errorf("leaked %q in %q", w, out)
				}
				if !strings.Contains(out, "<SECRET_") {
					t.Errorf("no marker in %q", out)
				}
			}
		})
	}
}

// Only rules whose groups label (jwt-base64) or repeat (microsoft-teams-
// webhook) parts mask the whole match; a re-vendor that adds one shows here.
func TestWholeMatchRules(t *testing.T) {
	rules, err := defaultRules()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range rules {
		if r.wholeMatch {
			got = append(got, r.label)
		}
	}
	want := []string{"SECRET_JWT_BASE64", "SECRET_MICROSOFT_TEAMS_WEBHOOK"}
	if !slices.Equal(got, want) {
		t.Errorf("whole-match rules = %v, want %v", got, want)
	}
}
