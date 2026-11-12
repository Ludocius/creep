package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Ludocius/creep/internal/exitcode"
)

func run(args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = Run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestRun(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "creep.yaml")
	if err := os.WriteFile(cfg, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing.yaml")

	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout []string
		wantStderr []string
	}{
		{"no args", nil, exitcode.ConfigError, nil, []string{"missing command", "Usage:"}},
		{"unknown command", []string{"frobnicate"}, exitcode.ConfigError, nil, []string{`unknown command "frobnicate"`, "Usage:", "Exit codes:"}},
		{"unknown global flag", []string{"--nope", "version"}, exitcode.ConfigError, nil, []string{"nope", "Usage:"}},
		{"help flag", []string{"--help"}, exitcode.OK, []string{"Usage:", "Exit codes:", "scan", "--log-level"}, nil},
		{"short help flag", []string{"-h"}, exitcode.OK, []string{"Usage:"}, nil},
		{"help command", []string{"help"}, exitcode.OK, []string{"Commands:"}, nil},
		{"command help", []string{"scan", "--help"}, exitcode.OK, []string{"creep scan", "Exit codes:"}, nil},
		{"version", []string{"version"}, exitcode.OK, []string{"creep ", "commit: ", "go: " + runtime.Version()}, nil},
		{"version extra args", []string{"version", "x"}, exitcode.ConfigError, nil, []string{`unexpected arguments: ["x"]`}},
		{"version empty arg", []string{"version", ""}, exitcode.ConfigError, nil, []string{`unexpected arguments: [""]`}},
		{"global flags after command", []string{"version", "--format", "json", "--log-level", "debug"}, exitcode.OK, []string{"commit: "}, nil},
		{"invalid format", []string{"--format", "xml", "version"}, exitcode.ConfigError, nil, []string{"invalid --format"}},
		{"invalid log level", []string{"scan", "--log-level=loud"}, exitcode.ConfigError, nil, []string{"invalid --log-level"}},
		{"config exists", []string{"--config", cfg, "version"}, exitcode.OK, []string{"commit: "}, nil},
		{"config missing", []string{"--config", missing, "version"}, exitcode.ConfigError, nil, []string{"does not exist"}},
		{"config is dir", []string{"--config", dir, "version"}, exitcode.ConfigError, nil, []string{"is a directory"}},
		{"unknown command flag", []string{"doctor", "--bogus"}, exitcode.ConfigError, nil, []string{"bogus", "creep doctor"}},
		{"init stub", []string{"init"}, exitcode.ConfigError, nil, []string{"not implemented yet"}},
		{"doctor stub", []string{"doctor"}, exitcode.ConfigError, nil, []string{"not implemented yet"}},
		{"scan stub", []string{"scan", "."}, exitcode.ConfigError, nil, []string{"not implemented yet"}},
		{"config stub", []string{"config", "explain"}, exitcode.ConfigError, nil, []string{"not implemented yet"}},
		{"global flag missing value", []string{"--format"}, exitcode.ConfigError, nil, []string{"needs an argument", "Usage:"}},
		{"single dash global flag", []string{"-format=json", "version"}, exitcode.OK, []string{"commit: "}, nil},
		{"command short help", []string{"version", "-h"}, exitcode.OK, []string{"creep version", "Exit codes:"}, nil},
		{"command names are case sensitive", []string{"HELP"}, exitcode.ConfigError, nil, []string{`unknown command "HELP"`}},
		{"flag after command overrides flag before", []string{"--format", "xml", "version", "--format", "json"}, exitcode.OK, []string{"commit: "}, nil},
		{"invalid flag after command", []string{"--format", "json", "init", "--format", "xml"}, exitcode.ConfigError, nil, []string{"invalid --format"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := run(tt.args...)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, stdout, stderr)
			}
			assertContains(t, "stdout", stdout, tt.wantStdout)
			assertContains(t, "stderr", stderr, tt.wantStderr)
		})
	}
}

func assertContains(t *testing.T, stream, got string, want []string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("%s missing %q:\n%s", stream, w, got)
		}
	}
}

func TestUsageListsEveryCommandAndExitCode(t *testing.T) {
	_, stdout, _ := run("--help")
	want := []string{"init", "doctor", "scan", "version", "config", exitcode.Help()}
	assertContains(t, "usage", stdout, want)
}

// TestFlagPositions checks global flags are honored and validated anywhere
// among a command's arguments, and that "--" ends flag parsing.
func TestFlagPositions(t *testing.T) {
	tests := []struct {
		name          string
		args          []string
		wantCode      int
		wantStderr    []string
		notWantStderr []string
	}{
		{"valid flag after positional", []string{"scan", ".", "--format", "sarif"}, exitcode.ConfigError, []string{"not implemented yet"}, []string{"invalid"}},
		{"invalid flag after positional", []string{"scan", ".", "--format", "xml"}, exitcode.ConfigError, []string{`invalid --format "xml"`}, []string{"not implemented yet (see"}},
		{"invalid flag with equals after positional", []string{"scan", ".", "--format=bogus"}, exitcode.ConfigError, []string{`invalid --format "bogus"`}, nil},
		{"invalid flag before positional", []string{"scan", "--format=bogus", "."}, exitcode.ConfigError, []string{`invalid --format "bogus"`}, nil},
		{"invalid log level between positionals", []string{"scan", "a", "--log-level", "loud", "b"}, exitcode.ConfigError, []string{"invalid --log-level"}, nil},
		{"unknown flag after positional", []string{"scan", ".", "--bogus"}, exitcode.ConfigError, []string{"bogus", "Usage:"}, []string{"not implemented yet (see"}},
		{"double dash ends flags", []string{"scan", "--", "--format=bogus"}, exitcode.ConfigError, []string{"not implemented yet"}, []string{"invalid"}},
		{"double dash after positional", []string{"scan", ".", "--", "--bogus"}, exitcode.ConfigError, []string{"not implemented yet"}, []string{"bogus"}},
		{"flag after double dash is positional", []string{"version", "--", "--format=json"}, exitcode.ConfigError, []string{`unexpected arguments: ["--format=json"]`}, nil},
		{"flag value may be double dash", []string{"version", "--format", "--"}, exitcode.ConfigError, []string{`invalid --format "--"`}, nil},
		{"missing value after positional", []string{"scan", ".", "--format"}, exitcode.ConfigError, []string{"needs an argument"}, nil},
		{"help after positional", []string{"scan", ".", "--help"}, exitcode.OK, nil, nil},
		{"single dash is positional", []string{"version", "-"}, exitcode.ConfigError, []string{`unexpected arguments: ["-"]`}, nil},
		{"valid flags after command", []string{"version", "--format=json", "--log-level=debug"}, exitcode.OK, nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := run(tt.args...)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, stdout, stderr)
			}
			assertContains(t, "stderr", stderr, tt.wantStderr)
			for _, w := range tt.notWantStderr {
				if strings.Contains(stderr, w) {
					t.Errorf("stderr unexpectedly contains %q:\n%s", w, stderr)
				}
			}
		})
	}
}

// TestStubsFailClosed guards the CI contract: an unbuilt command never exits 0.
func TestStubsFailClosed(t *testing.T) {
	for _, c := range commands {
		if c.name == "version" {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			code, _, stderr := run(c.name)
			if code != exitcode.ConfigError {
				t.Errorf("exit code = %d, want %d", code, exitcode.ConfigError)
			}
			assertContains(t, "stderr", stderr, []string{"not implemented yet (see "})
		})
	}
}

func TestHelpMarksUnimplementedCommands(t *testing.T) {
	_, stdout, _ := run("--help")
	for _, name := range []string{"init", "doctor", "scan", "config"} {
		c, _ := findCommand(name)
		assertContains(t, "usage", stdout, []string{c.name + " ", c.summary, "(not implemented yet)"})
	}
}
