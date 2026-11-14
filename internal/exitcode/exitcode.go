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
	Incomplete     = 4 // the report was written but not everything was evaluated (ADR 0007)
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
	{Incomplete, "incomplete run: report written, not everything evaluated"},
}

// ForReport is the exit code of a run that wrote its report. An incomplete
// run wins over the gate so it can never read as clean or merely gated
// (ADR 0007); runs that fail before a report exists return 2 or 3 directly.
func ForReport(incomplete, gateExceeded bool) int {
	if incomplete {
		return Incomplete
	}
	if gateExceeded {
		return GateExceeded
	}
	return OK
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
