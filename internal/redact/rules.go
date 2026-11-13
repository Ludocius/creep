package redact

import (
	_ "embed"
	"fmt"
	"regexp"
	"regexp/syntax"
	"strings"
	"sync"
)

// gitleaksTOML is the gitleaks default config, vendored byte for byte.
// Upstream version and license are recorded in NOTICE.
//
//go:embed rules/gitleaks.toml
var gitleaksTOML []byte

// secretRule is a compiled gitleaks rule.
type secretRule struct {
	label       string // marker label, e.g. SECRET_AWS_ACCESS_TOKEN
	re          *regexp.Regexp
	secretGroup int
	wholeMatch  bool // the groups label or repeat parts; they do not bound the secret
	keywords    []string
}

var (
	loadOnce    sync.Once
	loadedRules []secretRule
	loadErr     error
)

// defaultRules compiles the vendored rules once per process.
func defaultRules() ([]secretRule, error) {
	loadOnce.Do(func() {
		loadedRules, loadErr = compileRules(gitleaksTOML)
	})
	return loadedRules, loadErr
}

// compileRules parses and compiles every rule that has a regex. Rules without
// one (path-only rules such as pkcs12-file) do not apply to text and are
// skipped. A regex that fails to compile is an error: dropping a rule silently
// would let that secret type through.
func compileRules(data []byte) ([]secretRule, error) {
	specs, err := parseRules(data)
	if err != nil {
		return nil, err
	}
	rules := make([]secretRule, 0, len(specs))
	for _, s := range specs {
		if s.Regex == "" {
			continue
		}
		re, err := regexp.Compile(s.Regex)
		if err != nil {
			return nil, fmt.Errorf("compile gitleaks rule %s: %w", s.ID, err)
		}
		if s.SecretGroup > re.NumSubexp() {
			return nil, fmt.Errorf("gitleaks rule %s: secretGroup %d out of range", s.ID, s.SecretGroup)
		}
		parsed, err := syntax.Parse(s.Regex, syntax.Perl)
		if err != nil {
			return nil, fmt.Errorf("parse gitleaks rule %s: %w", s.ID, err)
		}
		rules = append(rules, secretRule{
			label:       "SECRET_" + markerLabel(s.ID),
			re:          re,
			secretGroup: s.SecretGroup,
			wholeMatch:  structuralGroups(parsed, false),
			keywords:    s.Keywords,
		})
	}
	return rules, nil
}

// structuralGroups reports whether some capture group cannot bound the
// secret. A named group labels a variant (jwt-base64 names the JWT header
// field it starts with; the token runs on past it). A group that can repeat
// reports only its last iteration (microsoft-teams-webhook repeats a 5-byte
// UUID part). Either way the groups say nothing about where the secret ends.
func structuralGroups(re *syntax.Regexp, repeated bool) bool {
	if re.Op == syntax.OpCapture && (re.Name != "" || repeated) {
		return true
	}
	switch re.Op {
	case syntax.OpStar, syntax.OpPlus:
		repeated = true
	case syntax.OpRepeat:
		repeated = repeated || re.Max != 1
	}
	for _, sub := range re.Sub {
		if structuralGroups(sub, repeated) {
			return true
		}
	}
	return false
}

// markerLabel turns a rule id into marker characters: A-Z, 0-9 and _.
func markerLabel(id string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r - 'a' + 'A'
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		}
		return '_'
	}, id)
}

// applies reports whether the rule should run on text, given its lowercase
// form. Like gitleaks, a rule with keywords runs only when one occurs; each
// upstream regex is written around its keywords, and skipping the rest keeps
// a few hundred regexes affordable on every fragment.
func (r secretRule) applies(lower string) bool {
	if len(r.keywords) == 0 {
		return true
	}
	for _, kw := range r.keywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// restartBudget bounds the bytes find scans again, as a multiple of the text
// (or of minRestartBudgetBase for short text). Ordinary code scans about 2%
// again and crafted dense keys about 5 times (BenchmarkRedact, "hex kw").
const (
	restartBudget        = 8
	minRestartBudgetBase = 4 << 10
)

// find returns the byte spans of the secrets this rule matches in text.
// The secret is the configured group, else the union of the groups that took
// part, else the whole match; that keeps names and quotes around it visible.
// Rules whose groups only label or repeat parts mask the whole match.
//
// Matches may overlap: each search restarts one byte after the previous
// match start, not at its end. Otherwise text placed before a secret could
// make a lazy match ("-----BEGIN ... KEY-----" opened earlier) end inside the
// real secret and hide the rest of it. Searching a suffix can see a word
// boundary that is not there, which only masks more, never less.
//
// Each restart scans the previous match again, so dense overlapping matches
// cost a multiple of the text: about 40 times for a .env file of long
// variable names, through the generic rule's 50-byte lazy prefix. Once the
// bytes scanned again pass restartBudget, the rest of the text from the next
// restart is masked as one span: every later match starts there, so this only
// masks more, and the cost stays within a fixed multiple of the text.
func (r secretRule) find(text string) []span {
	var out []span
	budget := restartBudget * max(len(text), minRestartBudgetBase)
	for pos := 0; pos < len(text); {
		if budget < 0 {
			return append(out, span{start: pos, end: len(text), label: r.label})
		}
		m := r.re.FindStringSubmatchIndex(text[pos:])
		if m == nil {
			break
		}
		start, end := r.secretBounds(m)
		if start < end {
			out = append(out, span{start: pos + start, end: pos + end, label: r.label})
		}
		budget -= m[1] - m[0]
		pos += m[0] + 1
	}
	return out
}

// secretBounds picks the span to mask from a submatch index. gitleaks
// reports the first non-empty group as the secret, which is right for
// reporting but can mask too little: masking stops only where every group
// it trusts has ended, so a nested or alternate group never leaves bytes out.
func (r secretRule) secretBounds(m []int) (int, int) {
	if g := r.secretGroup; g > 0 && m[2*g] >= 0 {
		return m[2*g], m[2*g+1]
	}
	if r.wholeMatch {
		return m[0], m[1]
	}
	return groupUnion(m)
}

// groupUnion spans from the first participating non-empty group to the end
// of the last one, or the whole match when no group took part.
func groupUnion(m []int) (int, int) {
	start, end := -1, -1
	for i := 2; i+1 < len(m); i += 2 {
		if m[i] < 0 || m[i] == m[i+1] {
			continue
		}
		if start < 0 || m[i] < start {
			start = m[i]
		}
		end = max(end, m[i+1])
	}
	if start < 0 {
		return m[0], m[1]
	}
	return start, end
}
