package state

import (
	"bytes"
	"strings"
)

// testSecret is a fixed, public test value; the v1 fixtures are signed with it.
var testSecret = bytes.Repeat([]byte{0x5a}, SecretBytes)

// signedLog signs every complete JSON-object line of log for run id, leaving
// anything else (a torn tail, garbage, a blank line) as written, so a test
// fails on the check it targets and not on the MAC.
func signedLog(id, log string) []byte {
	return signLines(log, runDomain(id))
}

func signLines(text string, domain []byte) []byte {
	parts := strings.Split(text, "\n")
	var out bytes.Buffer
	for i, p := range parts {
		last := i == len(parts)-1
		if !last && strings.HasPrefix(p, "{") && strings.HasSuffix(p, "}") {
			out.Write(sign(testSecret, domain, []byte(p)))
		} else {
			out.WriteString(p)
		}
		if !last {
			out.WriteByte('\n')
		}
	}
	return out.Bytes()
}
