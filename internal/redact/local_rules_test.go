package redact

import (
	"math/rand/v2"
	"regexp/syntax"
	"slices"
	"strings"
	"testing"
)

const tokenChars = alnum + "_-"

// Prefixes are split so this file holds no literal credential pattern.
func fakeDockerPAT(rng *rand.Rand, last byte) string {
	return "dckr" + "_pat_" + fakeToken(rng, tokenChars, 26) + string(last)
}

func fakeOpenAIKey(rng *rand.Rand, last byte) string {
	return "sk-" + "proj-" + fakeToken(rng, tokenChars, 74) + "T3Blbk" + "FJ" + fakeToken(rng, tokenChars, 73) + string(last)
}

func fakeDiscordWebhook(rng *rand.Rand, last byte) string {
	return fakeToken(rng, digits, 19) + "/" + fakeToken(rng, tokenChars, 67) + string(last)
}

// #75: tokens the vendored rules miss lose every byte, through Redact and File.
func TestLocalRulesMaskTokens(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 5))
	tests := []struct{ name, before, secret, after string }{
		{"docker pat", "docker login -u ci -p ", fakeDockerPAT(rng, 'x'), "\n"},
		{"docker pat ending in dash", "run(", fakeDockerPAT(rng, '-'), ")\n"},
		{"docker oat", "echo ", "dckr" + "_oat_" + fakeToken(rng, tokenChars, 32), " | docker login\n"},
		{"docker pat after a word", "x", fakeDockerPAT(rng, '_'), "\n"},
		{"discord webhook", "post(\"https://discord.com/api/webhooks/", fakeDiscordWebhook(rng, 'a'), "\")\n"},
		{"discord webhook ending in dash", "curl https://discordapp.com/api/webhooks/", fakeDiscordWebhook(rng, '-'), " -d @msg\n"},
		{"discord versioned webhook", "url: https://ptb.discord.com/api/v10/webhooks/", fakeDiscordWebhook(rng, '_'), "?wait=true\n"},
		{"openai key ending in dash", "client(", fakeOpenAIKey(rng, '-'), ")\n"},
		{"openai key ending in underscore", "client(", fakeOpenAIKey(rng, '_'), " )\n"},
		{"openai key quoted", "use \"", fakeOpenAIKey(rng, '-'), "\";\n"},
		{"openai key without marker", "client(", "sk-" + "svcacct-" + fakeToken(rng, tokenChars, 63) + "-", ")\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			text := tc.before + tc.secret + tc.after
			viaRedact := mustRedact(t, newRedactor(t), text)
			viaFile, err := newRedactor(t).File([]byte(text))
			if err != nil {
				t.Fatal(err)
			}
			for _, out := range []string{viaRedact, string(viaFile)} {
				// Exactly the secret is gone: no byte of it, and no context.
				if got := markerRe.ReplaceAllString(out, ""); got != tc.before+tc.after {
					t.Errorf("out = %q, want the secret masked whole in %q", out, text)
				}
			}
		})
	}
}

// The local rules leave code that only names a token format alone.
func TestLocalRulesIgnoreOrdinaryCode(t *testing.T) {
	tests := []string{
		"const dockerPrefix = \"dckr" + "_pat_\"\n",
		"if strings.HasPrefix(tok, \"dckr" + "_pat_\") && len(tok) > 9 {\n",
		"// e.g. dckr" + "_pat_example\n",
		"See https://discord.com/api/webhooks/{webhook.id}/{webhook.token} in the docs.\n",
		"url = f\"https://discord.com/api/webhooks/{wid}/{token}\"\n",
		"https://discord.com/developers/docs/resources/webhook\n",
		"keys start with sk-" + "proj-, sk-" + "svcacct- or sk-" + "admin-\n",
		"key := \"sk-" + "proj-\" + suffix\n",
		"sk-" + "proj-short-and_not-a-key\n",
	}
	for _, text := range tests {
		if out := mustRedact(t, newRedactor(t), text); out != text {
			t.Errorf("Redact(%q) = %q, want it unchanged", text, out)
		}
	}
}

func TestCompileRulesRejectsSharedID(t *testing.T) {
	file := []byte("[[rules]]\nid = \"a\"\nregex = '''x'''\n")
	_, err := compileRules(file, file)
	if err == nil || !strings.Contains(err.Error(), "duplicate id") {
		t.Fatalf("compileRules error = %v, want duplicate id", err)
	}
}

// A \b right after a token character that is not a word character ("-")
// fails at the end of the text or before a space, so the rule misses tokens
// ending in it. Each vendored rule that does this needs a local rule; a
// re-vendor that adds one fails here.
func TestTrailingBoundaryAfterDash(t *testing.T) {
	specs, err := parseRules(gitleaksTOML)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range specs {
		re, err := syntax.Parse(s.Regex, syntax.Perl)
		if err != nil {
			t.Fatal(err)
		}
		if s.Regex != "" && boundaryAfterDash(re) {
			got = append(got, s.ID)
		}
	}
	want := []string{"openai-api-key"} // covered by openai-scoped-key in rules/local.toml
	if !slices.Equal(got, want) {
		t.Errorf("rules with \\b after a possible \"-\" = %v, want %v", got, want)
	}
}

func boundaryAfterDash(re *syntax.Regexp) bool {
	for i := 1; re.Op == syntax.OpConcat && i < len(re.Sub); i++ {
		if re.Sub[i].Op == syntax.OpWordBoundary && canEndInDash(re.Sub[i-1]) {
			return true
		}
	}
	return slices.ContainsFunc(re.Sub, boundaryAfterDash)
}

func canEndInDash(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpCharClass:
		for i := 0; i+1 < len(re.Rune); i += 2 {
			if re.Rune[i] <= '-' && '-' <= re.Rune[i+1] {
				return true
			}
		}
	case syntax.OpLiteral:
		return len(re.Rune) > 0 && re.Rune[len(re.Rune)-1] == '-'
	case syntax.OpConcat:
		return canEndInDash(re.Sub[len(re.Sub)-1])
	case syntax.OpCapture, syntax.OpStar, syntax.OpPlus, syntax.OpQuest, syntax.OpRepeat:
		return canEndInDash(re.Sub[0])
	case syntax.OpAlternate:
		return slices.ContainsFunc(re.Sub, canEndInDash)
	}
	return false
}
