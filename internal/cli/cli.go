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
	wantHelp, err := parseFlags(fs, args)
	if err != nil {
		return usageError("creep", err, stderr)
	}
	if wantHelp {
		if invalidOptions(opts, stderr) {
			return exitcode.ConfigError
		}
		printUsage(stdout)
		return exitcode.OK
	}
	rest := fs.Args()
	if len(rest) == 0 {
		return usageError("creep", errors.New("missing command"), stderr)
	}
	if rest[0] == "help" {
		return runHelp(rest[1:], opts, stdout, stderr)
	}
	cmd, ok := findCommand(rest[0])
	if !ok {
		return usageError("creep", fmt.Errorf("unknown command %q", rest[0]), stderr)
	}
	return runCommand(cmd, rest[1:], opts, stdout, stderr)
}

func runCommand(cmd command, args []string, opts globalOptions, stdout, stderr io.Writer) int {
	positional, wantHelp, err := parseArgs("creep "+cmd.name, args, &opts)
	if err != nil {
		printError(stderr, "creep "+cmd.name, err)
		fmt.Fprintln(stderr)
		printCommandUsage(stderr, cmd)
		return exitcode.ConfigError
	}
	if invalidOptions(opts, stderr) {
		return exitcode.ConfigError
	}
	if wantHelp {
		printCommandUsage(stdout, cmd)
		return exitcode.OK
	}
	return cmd.run(env{stdout: stdout, stderr: stderr, opts: opts}, positional)
}

// runHelp handles "creep help [command]" with the same flag rules as any
// command, so invalid global flags fail here too instead of exiting 0.
func runHelp(args []string, opts globalOptions, stdout, stderr io.Writer) int {
	positional, _, err := parseArgs("creep help", args, &opts)
	if err != nil {
		return usageError("creep help", err, stderr)
	}
	if invalidOptions(opts, stderr) {
		return exitcode.ConfigError
	}
	switch len(positional) {
	case 0:
		printUsage(stdout)
		return exitcode.OK
	case 1:
		return printHelpFor(positional[0], stdout, stderr)
	default:
		return usageError("creep help", fmt.Errorf("unexpected arguments: %q", positional[1:]), stderr)
	}
}

func printHelpFor(name string, stdout, stderr io.Writer) int {
	if name == "help" {
		printUsage(stdout)
		return exitcode.OK
	}
	cmd, ok := findCommand(name)
	if !ok {
		return usageError("creep help", fmt.Errorf("unknown command %q", name), stderr)
	}
	printCommandUsage(stdout, cmd)
	return exitcode.OK
}

// parseArgs parses flags found anywhere in a command's arguments and returns
// the positional ones.
func parseArgs(name string, args []string, opts *globalOptions) (positional []string, wantHelp bool, err error) {
	fs := newFlagSet(name, opts)
	flagArgs, positional := splitArgs(fs, args)
	wantHelp, err = parseFlags(fs, flagArgs)
	return positional, wantHelp, err
}

// parseFlags keeps parsing after -h/--help, which the flag package treats as
// a stop, so flags on either side of it are still validated.
func parseFlags(fs *flag.FlagSet, args []string) (wantHelp bool, err error) {
	for {
		err = fs.Parse(args)
		if !errors.Is(err, flag.ErrHelp) {
			return wantHelp, err
		}
		wantHelp = true
		args = fs.Args()
	}
}

// usageError reports a parse failure followed by the global usage.
func usageError(prefix string, err error, stderr io.Writer) int {
	printError(stderr, prefix, err)
	fmt.Fprintln(stderr)
	printUsage(stderr)
	return exitcode.ConfigError
}

// invalidOptions reports why the global flags are invalid, if they are.
func invalidOptions(opts globalOptions, stderr io.Writer) bool {
	err := opts.validate()
	if err != nil {
		printError(stderr, "creep", err)
	}
	return err != nil
}
