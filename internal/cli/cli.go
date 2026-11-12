package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/Ludocius/creep/internal/exitcode"
)

// Run executes creep with args (without the program name) and returns the
// process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	opts := defaultOptions()
	fs := newFlagSet("creep", &opts)
	if err := fs.Parse(args); err != nil {
		return usageError(err, stdout, stderr)
	}
	rest := fs.Args()
	if len(rest) == 0 {
		return usageError(errors.New("missing command"), stdout, stderr)
	}
	if rest[0] == "help" {
		printUsage(stdout)
		return exitcode.OK
	}
	cmd, ok := findCommand(rest[0])
	if !ok {
		return usageError(fmt.Errorf("unknown command %q", rest[0]), stdout, stderr)
	}
	return runCommand(cmd, rest[1:], opts, stdout, stderr)
}

func runCommand(cmd command, args []string, opts globalOptions, stdout, stderr io.Writer) int {
	fs := newFlagSet("creep "+cmd.name, &opts)
	err := fs.Parse(args)
	if errors.Is(err, flag.ErrHelp) {
		printCommandUsage(stdout, cmd)
		return exitcode.OK
	}
	if err != nil {
		fmt.Fprintf(stderr, "creep %s: %v\n\n", cmd.name, err)
		printCommandUsage(stderr, cmd)
		return exitcode.ConfigError
	}
	if err := opts.validate(); err != nil {
		fmt.Fprintf(stderr, "creep: %v\n", err)
		return exitcode.ConfigError
	}
	return cmd.run(env{stdout: stdout, stderr: stderr, opts: opts}, fs.Args())
}

// usageError handles top-level parse failures; -h/--help is not a failure.
func usageError(err error, stdout, stderr io.Writer) int {
	if errors.Is(err, flag.ErrHelp) {
		printUsage(stdout)
		return exitcode.OK
	}
	fmt.Fprintf(stderr, "creep: %v\n\n", err)
	printUsage(stderr)
	return exitcode.ConfigError
}
