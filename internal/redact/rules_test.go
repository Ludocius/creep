package redact

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"testing"
)

// Bump these together with NOTICE (version, URL, hash) when re-vendoring
// rules/gitleaks.toml from a new gitleaks release.
const (
	gitleaksSHA256   = "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf"
	gitleaksRuleSpec = 222 // [[rules]] tables in the file
	gitleaksRegexes  = 221 // rules with a regex; pkcs12-file is path-only
)

func TestVendoredRulesUnchanged(t *testing.T) {
	sum := sha256.Sum256(gitleaksTOML)
	if got := hex.EncodeToString(sum[:]); got != gitleaksSHA256 {
		t.Fatalf("rules/gitleaks.toml sha256 = %s, want %s (re-vendor and update NOTICE)", got, gitleaksSHA256)
	}
}

func TestVendoredRulesCount(t *testing.T) {
	specs, err := parseRules(gitleaksTOML)
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != gitleaksRuleSpec {
		t.Errorf("parsed %d rules, want %d", len(specs), gitleaksRuleSpec)
	}
	rules, err := defaultRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != gitleaksRegexes {
		t.Errorf("compiled %d rules, want %d (none may be skipped for RE2)", len(rules), gitleaksRegexes)
	}
}

func TestRuleSecretGroup(t *testing.T) {
	rules, err := defaultRules()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if r.label == "SECRET_SONAR_API_TOKEN" && r.secretGroup != 2 {
			t.Errorf("sonar secretGroup = %d, want 2", r.secretGroup)
		}
	}
}

// No rule may match inside a marker; otherwise redacting text that quotes a
// marker could mangle it.
func TestMarkersMatchNoRule(t *testing.T) {
	rules, err := defaultRules()
	if err != nil {
		t.Fatal(err)
	}
	labels := []string{"PII_EMAIL", "PII_CARD", "PII_US_SSN", "PII_ES_DNI", "PII_ES_NIE", "PII_BR_CPF"}
	for _, r := range rules {
		labels = append(labels, r.label)
	}
	for _, label := range labels {
		text := "x = <" + label + "_12>\n"
		for _, r := range rules {
			if got := r.find(text); len(got) > 0 {
				t.Errorf("rule %s matches marker %q", r.label, text)
			}
		}
		for _, d := range slices.Concat(piiDetectors, credentialDetectors) {
			if got := d.scan(text); len(got) > 0 {
				t.Errorf("detector %s matches marker %q", d.label, text)
			}
		}
	}
}

func TestParseRulesRejectsUnsupportedSyntax(t *testing.T) {
	tests := []struct {
		name, toml string
	}{
		{"multiline regex", "[[rules]]\nid = \"a\"\nregex = '''abc\n"},
		{"basic string regex", "[[rules]]\nid = \"a\"\nregex = \"abc\"\n"},
		{"escaped id", "[[rules]]\nid = \"a\\\"b\"\n"},
		{"bad id", "[[rules]]\nid = \"A B\"\n"},
		{"duplicate id", "[[rules]]\nid = \"a\"\n[[rules]]\nid = \"a\"\n"},
		{"unknown table", "[extend]\n"},
		{"unknown syntax", "[[rules]]\nid.x = \"a\"\n"},
		{"bad secretGroup", "[[rules]]\nid = \"a\"\nsecretGroup = x\n"},
		{"negative secretGroup", "[[rules]]\nid = \"a\"\nsecretGroup = -1\n"},
		{"keyword with quote", "[[rules]]\nid = \"a\"\nkeywords = [\"a\\\"b\"]\n"},
		{"keywords not array", "[[rules]]\nid = \"a\"\nkeywords = \"a\"\n"},
		{"bad keyword line", "[[rules]]\nid = \"a\"\nkeywords = [\n    abc,\n]\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseRules([]byte(tc.toml)); err == nil {
				t.Fatalf("parseRules(%q) succeeded, want error", tc.toml)
			}
		})
	}
}

func TestCompileRulesErrors(t *testing.T) {
	tests := []struct {
		name, toml, want string
	}{
		{"bad regex", "[[rules]]\nid = \"a\"\nregex = '''(?<x'''\n", "compile gitleaks rule a"},
		{"group out of range", "[[rules]]\nid = \"a\"\nregex = '''(x)'''\nsecretGroup = 2\n", "out of range"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := compileRules([]byte(tc.toml))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("compileRules error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestParseRulesIgnoresAllowlists(t *testing.T) {
	toml := "[allowlist]\nregexes = [\n    '''x''',\n]\n" +
		"[[rules]]\nid = \"r\"\nregex = '''abc'''\nkeywords = [\"Abc\", \"<add key=\"]\n" +
		"[[rules.allowlists]]\nregex = '''ignored'''\nkeywords = [\"zzz\"]\n" +
		"[[rules]]\nid = \"s\"\nregex = '''def'''\nkeywords = [\n    \"de\",\n    \"ef\",\n]\nsecretGroup = 0\n"
	specs, err := parseRules([]byte(toml))
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 2 || specs[0].Regex != "abc" || specs[1].Regex != "def" {
		t.Fatalf("specs = %+v, want rules abc and def", specs)
	}
	if got := strings.Join(specs[0].Keywords, "|"); got != "abc|<add key=" {
		t.Errorf("single-line keywords = %q", got)
	}
	if got := strings.Join(specs[1].Keywords, "|"); got != "de|ef" {
		t.Errorf("multi-line keywords = %q", got)
	}
}

func TestRuleAppliesOnKeyword(t *testing.T) {
	tests := []struct {
		keywords []string
		lower    string
		want     bool
	}{
		{nil, "anything", true},
		{[]string{"akia"}, "x akiaq", true},
		{[]string{"akia", "asia"}, "nothing here", false},
	}
	for _, tc := range tests {
		if got := (secretRule{keywords: tc.keywords}).applies(tc.lower); got != tc.want {
			t.Errorf("applies(%v, %q) = %v, want %v", tc.keywords, tc.lower, got, tc.want)
		}
	}
}

func TestMarkerLabel(t *testing.T) {
	tests := map[string]string{
		"aws-access-token":     "AWS_ACCESS_TOKEN",
		"1password-secret-key": "1PASSWORD_SECRET_KEY",
	}
	for in, want := range tests {
		if got := markerLabel(in); got != want {
			t.Errorf("markerLabel(%q) = %q, want %q", in, got, want)
		}
	}
}
