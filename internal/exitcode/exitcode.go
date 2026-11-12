package exitcode

import (
	"fmt"
	"strings"
)

// Process exit codes. Their values are a stable contract for CI.
const (
	OK             = 0 // nothing blocking
	GateExceeded   = 1 // findings exceed the configured gate
	ConfigError    = 2 // invalid usage, flags or configuration
	ModelOrSandbox = 3 // model or sandbox failure
)

type entry struct {
	code    int
	meaning string
}

var table = []entry{
	{OK, "nothing blocking"},
	{GateExceeded, "gate exceeded"},
	{ConfigError, "usage or configuration error"},
	{ModelOrSandbox, "model or sandbox error"},
}

// Help returns the exit-code section printed by --help.
func Help() string {
	var b strings.Builder
	b.WriteString("Exit codes:\n")
	for _, e := range table {
		fmt.Fprintf(&b, "  %d  %s\n", e.code, e.meaning)
	}
	return b.String()
}
