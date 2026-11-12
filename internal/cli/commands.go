package cli

import (
	"fmt"
	"io"

	"github.com/Ludocius/creep/internal/buildinfo"
	"github.com/Ludocius/creep/internal/exitcode"
)

// env is what a command needs from Run.
type env struct {
	stdout io.Writer
	stderr io.Writer
	opts   globalOptions
}

type command struct {
	name    string
	summary string
	run     func(e env, args []string) int
}

var commands = []command{
	{"init", "create a creep.yaml for this project", stub("init", "#2")},
	{"doctor", "check models, sandbox runtime and environment", stub("doctor", "#6, #21")},
	{"scan", "scan a local repository for vulnerabilities", stub("scan", "the v0.1 milestone")},
	{"version", "print version, commit and Go version", runVersion},
	{"config", "show the effective configuration and its sources", stub("config", "#2")},
}

func findCommand(name string) (command, bool) {
	for _, c := range commands {
		if c.name == name {
			return c, true
		}
	}
	return command{}, false
}

// stub reports honestly that a command exists in the contract but is not
// built yet. It exits 0 because nothing was evaluated, so nothing is blocking.
func stub(name, ref string) func(env, []string) int {
	return func(e env, _ []string) int {
		fmt.Fprintf(e.stderr, "creep %s: not implemented yet (see %s)\n", name, ref)
		return exitcode.OK
	}
}

func runVersion(e env, args []string) int {
	if len(args) > 0 {
		fmt.Fprintf(e.stderr, "creep version: unexpected arguments: %v\n", args)
		return exitcode.ConfigError
	}
	info := buildinfo.Get()
	fmt.Fprintf(e.stdout, "creep %s\ncommit: %s\ngo: %s\n", info.Version, info.Commit, info.GoVersion)
	return exitcode.OK
}
