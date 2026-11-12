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

// maxConfigBytes caps how much of a config file is read; real configs are a
// few KiB, so anything larger is a mistake or an attack.
const maxConfigBytes = 1 << 20

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
	f, err := openConfig(path)
	if err != nil {
		return err
	}
	return f.Close()
}

// openConfig opens path once and checks the opened file itself, so a device
// (NUL, CON, /dev/zero) or a swapped path cannot pass as a config file.
func openConfig(path string) (*os.File, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("--config %q: file does not exist", path)
	}
	if err != nil {
		return nil, configError(path, err)
	}
	if err := requireRegular(f, path); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func requireRegular(f *os.File, path string) error {
	info, err := f.Stat()
	if err != nil {
		return configError(path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("--config %q: is a directory", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("--config %q: not a regular file", path)
	}
	return nil
}

// readConfig returns the raw bytes of a config file for the parser (see #2).
func readConfig(path string) ([]byte, error) {
	f, err := openConfig(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return nil, configError(path, err)
	}
	if len(data) > maxConfigBytes {
		return nil, fmt.Errorf("--config %q: larger than %d bytes", path, maxConfigBytes)
	}
	return data, nil
}

// configError drops the *os.PathError wrapper, which would repeat the path
// unquoted and let control characters in it reach the terminal.
func configError(path string, err error) error {
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		err = pathErr.Err
	}
	return fmt.Errorf("--config %q: %w", path, err)
}
