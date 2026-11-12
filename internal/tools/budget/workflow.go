package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

var (
	// usesKey finds `uses:` in block or flow style, with or without quoted
	// keys, and captures the value up to whitespace, a quote, ',' or '}'.
	usesKey   = regexp.MustCompile(`(?:^|[\s{,\-])["']?uses["']?\s*:\s*["']?([^\s"',}#]*)`)
	shaPinned = regexp.MustCompile(`@[0-9a-f]{40}$`)
	digestPin = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)
	// yamlEscape matches YAML double-quoted escapes a trigger name could hide behind.
	yamlEscape = regexp.MustCompile(`\\(?:x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8})`)
	// escapedKey finds a double-quoted key holding any backslash escape, such as "\x75ses":.
	escapedKey = regexp.MustCompile(`"(?:[^"\\]|\\.)*\\(?:[^"\\]|\\.)*"\s*:`)
	// indirectKey finds explicit (`? key`) and alias (`*a :`) keys, whose text a line scan cannot see.
	indirectKey = regexp.MustCompile(`(?:^\s*(?:-\s+)*|[{,]\s*)\?(?:\s|$)|(?:^|[\s{,\-])\*[^\s,\[\]{}]+\s*:(?:\s|$)`)
	// blockScalar finds a line that opens a literal or folded block scalar.
	blockScalar = regexp.MustCompile(`(?:^|[\s:\-])[|>][-+0-9]*\s*$`)
)

// checkWorkflow reports pull_request_target triggers, actions or images not
// pinned immutably, and YAML shapes a line scan cannot resolve: escaped keys,
// explicit or alias keys, and quoted scalars that span lines. It is a regex
// backstop, not a YAML parser, so it fails closed on those shapes; zizmor and
// actionlint in CI parse the YAML and are the authoritative checks.
func checkWorkflow(name string, data []byte) []string {
	var problems []string
	block := -1    // key column of an open block scalar; deeper lines are its text
	var quote byte // quote left open by the previous line, reported there
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		blockText := quote == 0 && block >= 0 && (strings.TrimSpace(line) == "" || indentOf(line) > block)
		code, open := stripComment(line, quote)
		continued := quote != 0
		at := fmt.Sprintf("%s:%d: ", name, i+1)
		problems = append(problems, prefixed(at, valueProblems(code))...)
		// Quotes in block text (shell, say) are not YAML, so they never carry over.
		if blockText {
			continue
		}
		quote = open
		if continued {
			continue
		}
		block = -1
		problems = append(problems, prefixed(at, structureProblems(code, open))...)
		if open == 0 && blockScalar.MatchString(code) {
			block = keyColumn(code)
		}
	}
	return problems
}

func prefixed(at string, whys []string) []string {
	for i := range whys {
		whys[i] = at + whys[i]
	}
	return whys
}

func valueProblems(code string) []string {
	var problems []string
	if strings.Contains(unescapeYAML(code), "pull_request_target") {
		problems = append(problems, "pull_request_target is forbidden")
	}
	for _, m := range usesKey.FindAllStringSubmatch(code, -1) {
		if why := unpinned(m[1]); why != "" {
			problems = append(problems, m[1]+" "+why)
		}
	}
	return problems
}

func structureProblems(code string, open byte) []string {
	var problems []string
	if escapedKey.MatchString(code) {
		problems = append(problems, "escape sequence in a quoted key; write the key plainly")
	}
	if indirectKey.MatchString(code) {
		problems = append(problems, "explicit or alias key; write the key plainly")
	}
	if open != 0 {
		problems = append(problems, "quoted scalar spans lines; keep it on one line")
	}
	return problems
}

// stripComment drops a trailing comment, which in YAML starts with '#' after
// whitespace outside quotes. It starts inside quote (0 for none) and returns
// the quote still open at the line end.
func stripComment(line string, quote byte) (string, byte) {
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote == '"' && c == '\\':
			i++
		case quote != 0 && c == quote:
			quote = 0 // a '' escape in single quotes closes and reopens: same result
		case quote == 0 && (c == '"' || c == '\''):
			quote = c
		case quote == 0 && c == '#' && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t'):
			return line[:i], 0
		}
	}
	return line, quote
}

func indentOf(line string) int {
	return len(line) - len(strings.TrimLeft(line, " "))
}

// keyColumn is where the key of a line starts, after any "- " sequence
// markers. Block scalar text must be indented deeper than the key, so a line
// at this column or less is checked as YAML again.
func keyColumn(line string) int {
	rest := strings.TrimLeft(line, " ")
	for strings.HasPrefix(rest, "- ") {
		rest = strings.TrimLeft(rest[1:], " ")
	}
	return len(line) - len(rest)
}

func unpinned(ref string) string {
	switch {
	case strings.HasPrefix(ref, "./"):
		return ""
	case strings.HasPrefix(ref, "docker://"):
		if digestPin.MatchString(ref) {
			return ""
		}
		return "is not pinned by @sha256 digest"
	case shaPinned.MatchString(ref):
		return ""
	}
	return "is not pinned by commit SHA"
}

func unescapeYAML(s string) string {
	return yamlEscape.ReplaceAllStringFunc(s, func(esc string) string {
		r, err := strconv.ParseUint(esc[2:], 16, 32)
		if err != nil || r > unicode.MaxRune {
			return esc
		}
		return string(rune(r))
	})
}
