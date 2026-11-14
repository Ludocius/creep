package report

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// codeSpan prints an untrusted string as one Markdown code span. Inside a
// code span nothing is markup (no links, autolinks, HTML or emphasis); the
// fence is one backtick longer than the longest run inside, '|' is escaped
// so a table cell cannot be split, and every rune that is not printable
// (controls, bidi overrides, zero-width and other format runes, invalid
// UTF-8) is shown as a Go escape, so the text reads the same in a terminal,
// an editor and a renderer.
func codeSpan(s string) string {
	body := visible(s)
	fence := strings.Repeat("`", longestRun(body, '`')+1)
	if body == "" || strings.HasPrefix(body, "`") || strings.HasSuffix(body, "`") || strings.HasPrefix(body, " ") {
		body = " " + body + " "
	}
	return fence + body + fence
}

// visible escapes everything but printable runes and spaces, and '|'.
func visible(s string) string {
	var b strings.Builder
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[0])
		case r == '|':
			b.WriteString(`\|`)
		case r == ' ' || (unicode.IsPrint(r) && !unicode.Is(unicode.Cf, r)):
			b.WriteRune(r)
		case r < 0x100:
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			fmt.Fprintf(&b, `\u%04x`, r)
		}
		s = s[size:]
	}
	return b.String()
}

func longestRun(s string, c byte) int {
	longest, run := 0, 0
	for i := 0; i < len(s); i++ {
		if s[i] != c {
			run = 0
			continue
		}
		run++
		longest = max(longest, run)
	}
	return longest
}

// uriPath percent-encodes a repository path as a relative URI reference for
// SARIF: every byte except RFC 3986 unreserved characters and '/' is
// encoded, so spaces, '#', '?', '%', ':' and invalid UTF-8 survive exactly
// and a path can never become an absolute URI or carry a query.
func uriPath(p string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		c := p[i]
		if unreserved(c) || c == '/' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&15])
	}
	return b.String()
}

func unreserved(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' ||
		c == '-' || c == '.' || c == '_' || c == '~'
}
