package cli

import (
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/sneakercreepers/creep/internal/config"
)

// The config package owns the allowed values so flags and files agree.
var (
	logLevels = config.Enum("log.level")
	formats   = config.Enum("output.format")
)

// globalOptions are accepted before the command and after it.
type globalOptions struct {
	logLevel   string
	format     string
	configPath string
	// explicit holds the names of flags the user passed, so only those
	// become the flags config layer; defaults must not override files.
	explicit map[string]bool
}

func defaultOptions() globalOptions {
	return globalOptions{logLevel: "info", format: "text", explicit: map[string]bool{}}
}

// markExplicit records the flags fs parsed from the command line.
func markExplicit(fs *flag.FlagSet, opts *globalOptions) {
	fs.Visit(func(f *flag.Flag) { opts.explicit[f.Name] = true })
}

// configFlags turns explicit flags into the flags config layer.
func configFlags(opts globalOptions) []config.Flag {
	var flags []config.Flag
	if opts.explicit["format"] {
		flags = append(flags, config.Flag{Name: "--format", Key: "output.format", Value: opts.format})
	}
	if opts.explicit["log-level"] {
		flags = append(flags, config.Flag{Name: "--log-level", Key: "log.level", Value: opts.logLevel})
	}
	return flags
}

// newFlagSet returns a silent flag set with the global flags bound to opts.
// Silent because Run decides where usage goes and which exit code to use.
func newFlagSet(name string, opts *globalOptions) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	fs.StringVar(&opts.logLevel, "log-level", opts.logLevel, "")
	fs.StringVar(&opts.format, "format", opts.format, "")
	fs.StringVar(&opts.configPath, "config", opts.configPath, "")
	return fs
}

func (o globalOptions) validate() error {
	if !slices.Contains(logLevels, o.logLevel) {
		return fmt.Errorf("invalid --log-level %q: want one of %s", o.logLevel, strings.Join(logLevels, ", "))
	}
	if !slices.Contains(formats, o.format) {
		return fmt.Errorf("invalid --format %q: want one of %s", o.format, strings.Join(formats, ", "))
	}
	return validateConfigPath(o.configPath)
}

// splitArgs separates flag tokens from positional arguments so global flags
// are honored wherever they appear; the stdlib parser stops at the first
// positional. "--" ends flag parsing and everything after it is positional.
func splitArgs(fs *flag.FlagSet, args []string) (flagArgs, positional []string) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			return flagArgs, append(positional, args[i+1:]...)
		}
		if len(arg) < 2 || arg[0] != '-' {
			positional = append(positional, arg)
			continue
		}
		flagArgs = append(flagArgs, arg)
		if takesSeparateValue(fs, arg) && i+1 < len(args) {
			i++
			flagArgs = append(flagArgs, args[i])
		}
	}
	return flagArgs, positional
}

// takesSeparateValue mirrors the flag package: a known non-bool flag without
// "=" consumes the next argument as its value, even if that looks like a flag.
func takesSeparateValue(fs *flag.FlagSet, arg string) bool {
	name := strings.TrimPrefix(strings.TrimPrefix(arg, "-"), "-")
	if strings.Contains(name, "=") {
		return false
	}
	f := fs.Lookup(name)
	if f == nil {
		return false
	}
	b, isBool := f.Value.(interface{ IsBoolFlag() bool })
	return !isBool || !b.IsBoolFlag()
}

// validateConfigPath only checks an explicitly given path; when it is empty
// the config layers (see #2) decide which files to read.
func validateConfigPath(path string) error {
	if path == "" {
		return nil
	}
	f, _, err := openConfig("--config", path)
	if err != nil {
		return err
	}
	return f.Close()
}
