package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
)

var (
	logLevels = []string{"debug", "info", "warn", "error"}
	formats   = []string{"text", "json", "sarif", "markdown"}
)

// globalOptions are accepted before the command and after it.
type globalOptions struct {
	logLevel   string
	format     string
	configPath string
}

func defaultOptions() globalOptions {
	return globalOptions{logLevel: "info", format: "text"}
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

// validateConfigPath only checks an explicitly given path; when it is empty
// the config layers (see #2) decide which files to read.
func validateConfigPath(path string) error {
	if path == "" {
		return nil
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("--config %s: file does not exist", path)
	}
	if err != nil {
		return fmt.Errorf("--config %s: %w", path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("--config %s: is a directory", path)
	}
	return nil
}
