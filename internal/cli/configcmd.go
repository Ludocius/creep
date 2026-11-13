package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/Ludocius/creep/internal/config"
	"github.com/Ludocius/creep/internal/exitcode"
)

// Default file locations. The user file is shown as "~/..." so messages and
// `config explain` output do not depend on the home directory.
const (
	policyEnv   = "CREEP_POLICY"
	userConfig  = ".creep/config.yaml"
	projectFile = "creep.yaml"
)

func runConfig(e env, args []string) int {
	if len(args) == 0 {
		printError(e.stderr, "creep config", errors.New("missing subcommand: want explain"))
		return exitcode.ConfigError
	}
	if args[0] != "explain" {
		printError(e.stderr, "creep config", fmt.Errorf("unknown subcommand %q: want explain", args[0]))
		return exitcode.ConfigError
	}
	if len(args) > 1 {
		printError(e.stderr, "creep config explain", fmt.Errorf("unexpected arguments: %q", args[1:]))
		return exitcode.ConfigError
	}
	resolved, err := loadConfig(e.opts)
	if err != nil {
		printError(e.stderr, "creep config explain", err)
		return exitcode.ConfigError
	}
	if err := printExplain(e.stdout, resolved); err != nil {
		printError(e.stderr, "creep config explain", err)
		return exitcode.ConfigError
	}
	return exitcode.OK
}

// loadConfig reads every layer and resolves them. --config replaces the user
// and project files (see internal/config); the policy always applies.
func loadConfig(opts globalOptions) (*config.Resolved, error) {
	in := config.Inputs{Flags: configFlags(opts)}
	var err error
	if path := os.Getenv(policyEnv); path != "" {
		if in.Policy, err = readLayer(policyEnv, path, path); err != nil {
			return nil, err
		}
	}
	if opts.configPath != "" {
		in.Explicit, err = readLayer("--config", opts.configPath, opts.configPath)
		if err != nil {
			return nil, err
		}
		return config.Load(in)
	}
	if in.User, err = readUserLayer(); err != nil {
		return nil, err
	}
	if in.Project, err = readProjectLayer(); err != nil {
		return nil, err
	}
	return config.Load(in)
}

// readLayer reads a required file; name is how the layer is shown.
func readLayer(label, path, name string) (*config.File, error) {
	data, err := readConfigFile(label, path)
	if err != nil {
		return nil, err
	}
	return &config.File{Name: name, Data: data}, nil
}

// readOptional reads a file that may be absent.
func readOptional(label, path, name string) (*config.File, error) {
	f, err := readLayer(label, path, name)
	if errors.Is(err, errNoFile) {
		return nil, nil
	}
	return f, err
}

// readUserLayer skips the user file when there is no home directory, as in
// some CI containers.
func readUserLayer() (*config.File, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil
	}
	return readOptional("user config", filepath.Join(home, filepath.FromSlash(userConfig)), "~/"+userConfig)
}

func readProjectLayer() (*config.File, error) {
	if err := requireNoLink("project config", projectFile); err != nil {
		return nil, err
	}
	return readOptional("project config", projectFile, projectFile)
}

func printExplain(w io.Writer, r *config.Resolved) error {
	switch format := r.Config.Output.Format; format {
	case "text":
		return printExplainText(w, r.Explain())
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r.Explain())
	default:
		return fmt.Errorf("output format %q is not supported here: want text or json", format)
	}
}

// printExplainText escapes every cell: values and file names come from
// files the user may not have written (a cloned repository's creep.yaml).
func printExplainText(w io.Writer, entries []config.Entry) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "KEY\tVALUE\tSOURCE")
	for _, e := range entries {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", escapeControl(e.Key), escapeControl(config.FormatValue(e.Value)), escapeControl(e.Source))
	}
	return tw.Flush()
}
