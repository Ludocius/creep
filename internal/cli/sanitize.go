package cli

import (
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

// printError is the single place errors reach the terminal. Messages may
// carry user input verbatim (the flag package echoes unknown flag names), so
// control characters are escaped to keep escape sequences off the terminal.
func printError(w io.Writer, prefix string, err error) {
	fmt.Fprintf(w, "%s: %s\n", prefix, escapeControl(err.Error()))
}

// escapeControl replaces non-printable runes and invalid UTF-8 with Go escape
// sequences; printable text, including backslashes, is left as is.
func escapeControl(s string) string {
	var b strings.Builder
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[0])
		case r == ' ' || unicode.IsPrint(r):
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
