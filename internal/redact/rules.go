package redact

import (
	_ "embed"
	"fmt"
	"regexp"
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
		rules = append(rules, secretRule{
			label:       "SECRET_" + markerLabel(s.ID),
			re:          re,
			secretGroup: s.SecretGroup,
			keywords:    s.Keywords,
		})
	}
	return rules, nil
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

// find returns the byte spans of the secrets this rule matches in text.
// Like gitleaks, the secret is the configured group, else the first non-empty
// group, else the whole match; that keeps names and quotes around it visible.
//
// Matches may overlap: each search restarts one byte after the previous
// match start, not at its end. Otherwise text placed before a secret could
// make a lazy match ("-----BEGIN ... KEY-----" opened earlier) end inside the
// real secret and hide the rest of it. Searching a suffix can see a word
// boundary that is not there, which only masks more, never less.
func (r secretRule) find(text string) []span {
	var out []span
	for pos := 0; pos <= len(text); {
		m := r.re.FindStringSubmatchIndex(text[pos:])
		if m == nil {
			break
		}
		start, end := r.secretBounds(m)
		if start < end {
			out = append(out, span{start: pos + start, end: pos + end, label: r.label})
		}
		pos += m[0] + 1
	}
	return out
}

func (r secretRule) secretBounds(m []int) (int, int) {
	if g := r.secretGroup; g > 0 && m[2*g] >= 0 {
		return m[2*g], m[2*g+1]
	}
	for g := 1; 2*g+1 < len(m); g++ {
		if m[2*g] >= 0 && m[2*g] < m[2*g+1] {
			return m[2*g], m[2*g+1]
		}
	}
	return m[0], m[1]
}
