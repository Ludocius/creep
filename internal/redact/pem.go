package redact

import (
	"regexp"
	"strings"
	"unicode"
)

// privateKeyLabel is the marker label of the gitleaks private-key rule, so a
// complete key gets the same single marker whichever detector found it.
const privateKeyLabel = "SECRET_PRIVATE_KEY"

// PEM private-key header and footer lines, with every variant the gitleaks
// rule accepts (RSA, EC, DSA, OPENSSH, ENCRYPTED, plain, PGP ... BLOCK).
var (
	pemBeginRe = regexp.MustCompile(`(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----`)
	pemEndRe   = regexp.MustCompile(`(?i)-----END[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----`)
)

// Bounds of a PEM body line: 64 characters in PEM, 70 in OpenSSH and PGP,
// 76 in MIME base64; 40 keeps ordinary identifiers out.
const (
	minBodyLine = 40
	maxBodyLine = 76
)

// findPrivateKeys masks private keys that a fragment boundary cut, which the
// gitleaks rule misses because it needs BEGIN and END in the same text.
func findPrivateKeys(text string) []span {
	return append(findKeyBlocks(text), findBodyRuns(text)...)
}

// findKeyBlocks masks from each BEGIN line to its END line. A BEGIN with no
// END runs to the end of the text; an END with no BEGIN runs back to the
// start of the text, or to the previous END.
func findKeyBlocks(text string) []span {
	if !strings.Contains(text, "-----") {
		return nil
	}
	begins := pemBeginRe.FindAllStringIndex(text, -1)
	ends := pemEndRe.FindAllStringIndex(text, -1)
	var out []span
	open, from := -1, 0
	for _, end := range ends {
		for len(begins) > 0 && begins[0][0] < end[0] {
			if open < 0 {
				open = begins[0][0]
			}
			begins = begins[1:]
		}
		if open < 0 {
			open = from
		}
		out = append(out, span{start: open, end: end[1], label: privateKeyLabel})
		open, from = -1, end[1]
	}
	if open < 0 && len(begins) > 0 {
		open = begins[0][0]
	}
	if open >= 0 {
		out = append(out, span{start: open, end: len(text), label: privateKeyLabel})
	}
	return out
}

// bodyLine is the base64 token that ends one line of the text, if any.
type bodyLine struct {
	start, end int // token bounds in the text; start == end when none
	lineStart  int
	pure       bool // nothing but blanks or an opening quote before the token
}

// findBodyRuns masks key bodies with no header or footer: two or more
// consecutive lines ending in a base64 token of 40 to 76 characters, of any
// mix of lengths since a boundary can leave partial lines, or one such line
// that touches the start or end of the text, where a boundary cut the key.
// The run takes in a short line on either side.
func findBodyRuns(text string) []span {
	lines := bodyLines(text)
	var out []span
	for i := 0; i < len(lines); {
		n := runLength(lines, i)
		if n == 0 {
			i++
			continue
		}
		if n >= 2 || lines[i].pure && touchesEdge(lines, i, n) {
			out = append(out, runSpan(lines, i, n))
		}
		i += n
	}
	return out
}

// runLength counts the consecutive full-size body lines starting at i.
func runLength(lines []bodyLine, i int) int {
	n := 0
	for i+n < len(lines) && isFullSize(lines[i+n]) {
		n++
	}
	return n
}

func isFullSize(line bodyLine) bool {
	size := line.end - line.start
	return minBodyLine <= size && size <= maxBodyLine
}

// isPartial reports a short token alone on its line: what a boundary leaves
// of a body line.
func isPartial(line bodyLine) bool {
	return line.pure && line.end > line.start
}

// touchesEdge reports whether lines[i:i+n] reach the start or end of the
// text, directly or through one partial line.
func touchesEdge(lines []bodyLine, i, n int) bool {
	last := len(lines) - 1
	atStart := i == 0 || i == 1 && isPartial(lines[0])
	atEnd := i+n-1 == last || i+n == last && isPartial(lines[last])
	return atStart || atEnd
}

// runSpan covers lines[i:i+n], plus the short line after it (the last line
// of a PEM body, or a partial one a boundary left) and a partial line that
// a boundary left before it.
func runSpan(lines []bodyLine, i, n int) span {
	sp := span{start: lines[i].start, end: lines[i+n-1].end, label: privateKeyLabel}
	if i+n < len(lines) && isPartial(lines[i+n]) {
		sp.end = lines[i+n].end
	}
	if i == 1 && isPartial(lines[0]) {
		sp.start = lines[0].start
	}
	return sp
}

// bodyLines splits text into lines and finds each line's trailing token.
// Lines in the blank tail of the text are left out, so a key line followed
// by blank lines still touches the end of the text.
func bodyLines(text string) []bodyLine {
	// Trimmed once: re-trimming the tail for each dropped line made a text
	// ending in many blank lines quadratic (#74).
	tail := len(strings.TrimRightFunc(text, unicode.IsSpace))
	var lines []bodyLine
	for start := 0; start <= len(text); {
		if start >= tail && len(lines) > 0 {
			break
		}
		end := strings.IndexByte(text[start:], '\n')
		if end < 0 {
			end = len(text) - start
		}
		lines = append(lines, trailingToken(text, start, start+end))
		start += end + 1
	}
	return lines
}

// trailingToken finds the base64 run (with up to two "=" of padding) that
// ends the line text[from:to], ignoring closing quotes, commas and blanks.
// The run must start the line or follow a blank or an opening quote, so
// prefixed digests (go.sum "h1:", "sha256:") and paths do not count.
func trailingToken(text string, from, to int) bodyLine {
	line := bodyLine{lineStart: from}
	end := to
	for end > from && strings.IndexByte(" \t\r\"'`,;)", text[end-1]) >= 0 {
		end--
	}
	start := end
	for pad := 0; start > from && text[start-1] == '=' && pad < 2; pad++ {
		start--
	}
	for start > from && isBase64(text[start-1]) {
		start--
	}
	if start > from && strings.IndexByte(" \t\"'`", text[start-1]) < 0 {
		return line
	}
	if end-start > maxBodyLine || !mixedCase(text[start:end]) && end-start >= minBodyLine {
		return line
	}
	line.start, line.end = start, end
	line.pure = strings.Trim(text[from:start], " 	\"'`") == ""
	return line
}

func isBase64(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '+' || c == '/'
}
