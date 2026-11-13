package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

// agentLoop is the contribution loop the maintainer made mandatory; removing it
// must fail CI so it can only change through an ADR and this file (CODEOWNERS).
const agentLoop = "developer → tester → pentester → auditor"

// docsOnlyRule is the one sanctioned shortcut, kept narrow so it cannot cover code.
const docsOnlyRule = "Documentation-only changes run only the auditor"

// requiredPolicy maps each file to the phrases that keep the agent loop documented.
var requiredPolicy = map[string][]string{
	"AGENTS.md": {
		agentLoop,
		"no shared context",
		"Confirmed Critical or High blocks the merge",
		"Maximum 3 cycles",
		"Changing or removing this loop needs an ADR",
		docsOnlyRule,
	},
	"CONTRIBUTING.md":                  {agentLoop, "Changing or removing this loop needs an ADR", docsOnlyRule},
	".github/PULL_REQUEST_TEMPLATE.md": {agentLoop},
	"CLAUDE.md":                        {"@AGENTS.md"},
}

func policyProblems(cfg config) ([]string, error) {
	return checkPolicy(os.DirFS(cfg.root))
}

// checkPolicy reports policy files that are missing or lost a required phrase.
func checkPolicy(fsys fs.FS) ([]string, error) {
	var problems []string
	for name, phrases := range requiredPolicy {
		data, err := fs.ReadFile(fsys, name)
		if errors.Is(err, fs.ErrNotExist) {
			problems = append(problems, fmt.Sprintf("policy: %s is missing", name))
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("policy %s: %w", name, err)
		}
		for _, phrase := range phrases {
			if !strings.Contains(string(data), phrase) {
				problems = append(problems, fmt.Sprintf("policy: %s must contain %q", name, phrase))
			}
		}
	}
	return problems, nil
}
