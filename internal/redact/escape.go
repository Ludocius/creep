package redact

import "strings"

// Markers look like <SECRET_AWS_ACCESS_TOKEN_1> or <PII_EMAIL_2>. Text from
// the scanned repository could already contain such strings; if it reached
// the model unchanged, a marker echoed back could be un-redacted into a real
// secret on screen, or be confused with ours. So every "<" that starts one of
// the reserved prefixes in input text gets "ESC_" inserted after it. ESC_ is
// itself reserved, which keeps the transformation reversible: Unredact drops
// one ESC_ wherever escape added one.
const (
	escapeTag    = "ESC_"
	secretPrefix = "SECRET_"
	piiPrefix    = "PII_"
)

var reservedPrefixes = [...]string{secretPrefix, piiPrefix, escapeTag}

// startsReserved reports whether s begins with a reserved marker prefix.
func startsReserved(s string) bool {
	for _, p := range reservedPrefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// writeEscaped appends s to b, neutralizing marker-like text.
func writeEscaped(b *strings.Builder, s string) {
	for {
		i := strings.IndexByte(s, '<')
		if i < 0 {
			b.WriteString(s)
			return
		}
		b.WriteString(s[:i+1])
		s = s[i+1:]
		if startsReserved(s) {
			b.WriteString(escapeTag)
		}
	}
}
