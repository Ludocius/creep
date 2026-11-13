package redact

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ruleSpec is the part of a gitleaks rule creep uses.
type ruleSpec struct {
	ID          string
	Regex       string
	SecretGroup int
	Keywords    []string // lowercase; the rule only runs when one occurs
}

// section says where the reader is; only [[rules]] keys count.
type section int

const (
	sectionTop section = iota
	sectionRule
	sectionKeywords // inside a multi-line keywords array of a rule
	sectionIgnored
)

var (
	keyLine   = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9]*) = (.*)$`)
	ruleIDRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	maxRuleID = 80
)

// parseRules reads the subset of TOML that the gitleaks default config uses.
// Anything outside that subset is an error, so an upstream format change fails
// the tests instead of silently dropping rules.
func parseRules(data []byte) ([]ruleSpec, error) {
	var rules []ruleSpec
	sec := sectionTop
	for i, line := range strings.Split(string(data), "\n") {
		next, err := parseLine(strings.TrimSuffix(line, "\r"), sec, &rules)
		if err != nil {
			return nil, fmt.Errorf("gitleaks rules line %d: %w", i+1, err)
		}
		sec = next
	}
	return rules, validateSpecs(rules)
}

func parseLine(line string, sec section, rules *[]ruleSpec) (section, error) {
	switch {
	case sec == sectionKeywords:
		return parseKeywordLine(line, &(*rules)[len(*rules)-1])
	case line == "" || strings.HasPrefix(line, "#"):
		return sec, nil
	case line == "[[rules]]":
		*rules = append(*rules, ruleSpec{})
		return sectionRule, nil
	case line == "[allowlist]" || line == "[[rules.allowlists]]":
		return sectionIgnored, nil
	case strings.HasPrefix(line, "["):
		return sec, fmt.Errorf("unsupported table %q", line)
	case strings.HasPrefix(line, " ") || line == "]":
		return sec, nil // array continuation; only ignored keys use arrays
	}
	m := keyLine.FindStringSubmatch(line)
	if m == nil {
		return sec, fmt.Errorf("unsupported syntax %q", line)
	}
	if sec != sectionRule {
		return sec, nil
	}
	if m[1] == "keywords" && m[2] == "[" {
		return sectionKeywords, nil
	}
	return sec, setRuleKey(&(*rules)[len(*rules)-1], m[1], m[2])
}

func setRuleKey(r *ruleSpec, key, value string) error {
	var err error
	switch key {
	case "id":
		r.ID, err = basicString(value)
	case "regex":
		r.Regex, err = literalString(value)
	case "secretGroup":
		r.SecretGroup, err = strconv.Atoi(value)
	case "keywords":
		r.Keywords, err = stringArray(value)
	}
	if err != nil {
		return fmt.Errorf("key %s: %w", key, err)
	}
	return nil
}

// parseKeywordLine reads one element, or the closing bracket, of a
// multi-line keywords array.
func parseKeywordLine(line string, r *ruleSpec) (section, error) {
	if line == "]" {
		return sectionRule, nil
	}
	kw, err := basicString(strings.TrimSuffix(strings.TrimSpace(line), ","))
	if err != nil {
		return sectionKeywords, fmt.Errorf("keywords: %w", err)
	}
	r.Keywords = append(r.Keywords, strings.ToLower(kw))
	return sectionKeywords, nil
}

// stringArray reads a single-line ["a", "b"] array. Elements cannot contain
// quotes (basicString rejects them), so splitting on ", " is unambiguous.
func stringArray(v string) ([]string, error) {
	if len(v) < 2 || v[0] != '[' || v[len(v)-1] != ']' {
		return nil, fmt.Errorf("want a single-line array, got %q", v)
	}
	var out []string
	for _, part := range strings.Split(v[1:len(v)-1], ", ") {
		s, err := basicString(part)
		if err != nil {
			return nil, err
		}
		out = append(out, strings.ToLower(s))
	}
	return out, nil
}

// basicString accepts a "..." string without escapes; rule ids never need them.
func basicString(v string) (string, error) {
	if len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' {
		return "", fmt.Errorf("want a quoted string, got %q", v)
	}
	s := v[1 : len(v)-1]
	if strings.ContainsAny(s, `"\`) {
		return "", fmt.Errorf("escapes are not supported in %q", v)
	}
	return s, nil
}

// literalString accepts a single-line ”'...”' string, taken verbatim.
func literalString(v string) (string, error) {
	const q = "'''"
	if len(v) < 2*len(q) || !strings.HasPrefix(v, q) || !strings.HasSuffix(v, q) {
		return "", fmt.Errorf("want a single-line ''' string, got %q", v)
	}
	s := v[len(q) : len(v)-len(q)]
	if strings.Contains(s, q) {
		return "", fmt.Errorf("nested ''' in %q", v)
	}
	return s, nil
}

func validateSpecs(rules []ruleSpec) error {
	seen := make(map[string]bool, len(rules))
	for i, r := range rules {
		if !ruleIDRe.MatchString(r.ID) || len(r.ID) > maxRuleID {
			return fmt.Errorf("gitleaks rule %d: invalid id %q", i+1, r.ID)
		}
		if seen[r.ID] {
			return fmt.Errorf("gitleaks rule %s: duplicate id", r.ID)
		}
		seen[r.ID] = true
		if r.SecretGroup < 0 {
			return fmt.Errorf("gitleaks rule %s: negative secretGroup", r.ID)
		}
	}
	return nil
}
