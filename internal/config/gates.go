package config

import (
	"fmt"
	"slices"
	"strings"
)

// gateNone disables a gate: no finding ever fails the run.
const gateNone = "none"

// A gate "<status>:<severity>" fails the run on findings with at least that
// status and severity. probable includes verified findings, so it is the
// stricter status; a lower severity is a stricter threshold.
var (
	gateStatuses   = []string{"verified", "probable"} // loosest first
	gateSeverities = []string{"critical", "high", "medium", "low", "info"}
)

type gate struct {
	none     bool
	status   int // index in gateStatuses; higher is stricter
	severity int // index in gateSeverities; higher is stricter
}

func parseGate(s string) (gate, error) {
	if s == gateNone {
		return gate{none: true}, nil
	}
	status, severity, ok := strings.Cut(s, ":")
	st := slices.Index(gateStatuses, status)
	sv := slices.Index(gateSeverities, severity)
	if !ok || st < 0 || sv < 0 {
		return gate{}, fmt.Errorf("invalid gate %q: want <status>:<severity> with status in %s and severity in %s, or %q",
			s, strings.Join(gateStatuses, ", "), strings.Join(gateSeverities, ", "), gateNone)
	}
	return gate{status: st, severity: sv}, nil
}

// atLeastAsStrict reports whether g fails on every finding limit fails on.
func (g gate) atLeastAsStrict(limit gate) bool {
	if limit.none {
		return true
	}
	if g.none {
		return false
	}
	return g.status >= limit.status && g.severity >= limit.severity
}

// gatePattern is the JSON Schema pattern for gate keys.
func gatePattern() string {
	return fmt.Sprintf("^(%s|(%s):(%s))$", gateNone,
		strings.Join(gateStatuses, "|"), strings.Join(gateSeverities, "|"))
}
