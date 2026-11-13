package gateway

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// maxAnswerBytes bounds one prompt answer; a longer line is a decline.
const maxAnswerBytes = 64

// TerminalPrompt asks on out and reads the answer from in, which the caller
// passes (the gateway never opens stdin itself). When in is not a terminal
// (a pipe, a file, a closed stdin) it declines without reading, so piped
// input or a script can never consent on the user's behalf.
func TerminalPrompt(in *os.File, out io.Writer) Prompt {
	return func(endpoint string) (bool, error) {
		if !isTerminal(in) {
			return false, nil
		}
		fmt.Fprintf(out, "creep will send redacted source code to %s.\nAllow this endpoint now and in later runs? [y/N] ", endpoint)
		return readYes(in), nil
	}
}

// isTerminal reports whether f is a character device. Some non-terminals
// are too (/dev/null, NUL); reading them returns EOF, which declines.
func isTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// readYes reads one line, a byte at a time so nothing past it is consumed,
// and reports whether it is "y" or "yes". EOF, an error or an overlong line
// is a decline.
func readYes(r io.Reader) bool {
	var line []byte
	b := make([]byte, 1)
	for len(line) <= maxAnswerBytes {
		n, err := r.Read(b)
		if n == 1 && b[0] == '\n' {
			return isYes(string(line))
		}
		if n == 1 {
			line = append(line, b[0])
		}
		if err != nil {
			return false
		}
	}
	return false
}

func isYes(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "y" || s == "yes"
}
