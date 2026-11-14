package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/exitcode"
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
		{"config without subcommand", []string{"config"}, exitcode.ConfigError, nil, []string{"missing subcommand"}},
		{"config unknown subcommand", []string{"config", "show"}, exitcode.ConfigError, nil, []string{`unknown subcommand "show"`}},
		{"config explain extra args", []string{"config", "explain", "x"}, exitcode.ConfigError, nil, []string{`unexpected arguments: ["x"]`}},
		{"global flag missing value", []string{"--format"}, exitcode.ConfigError, nil, []string{"needs an argument", "Usage:"}},
		{"single dash global flag", []string{"-format=json", "version"}, exitcode.OK, []string{"commit: "}, nil},
		{"command short help", []string{"version", "-h"}, exitcode.OK, []string{"creep version", "Exit codes:"}, nil},
		{"command names are case sensitive", []string{"HELP"}, exitcode.ConfigError, nil, []string{`unknown command "HELP"`}},
		{"flag after command overrides flag before", []string{"--format", "xml", "version", "--format", "json"}, exitcode.OK, []string{"commit: "}, nil},
		{"invalid flag after command", []string{"--format", "json", "init", "--format", "xml"}, exitcode.ConfigError, nil, []string{"invalid --format"}},
		{"help with invalid format", []string{"--format=bad", "help"}, exitcode.ConfigError, nil, []string{`invalid --format "bad"`}},
		{"help with invalid log level", []string{"--log-level", "trace", "help"}, exitcode.ConfigError, nil, []string{`invalid --log-level "trace"`}},
		{"help with invalid flag after it", []string{"help", "--format=bad"}, exitcode.ConfigError, nil, []string{`invalid --format "bad"`}},
		{"help with missing config", []string{"--config", missing, "help"}, exitcode.ConfigError, nil, []string{"does not exist"}},
		{"help with unknown flag", []string{"help", "--bogus"}, exitcode.ConfigError, nil, []string{"bogus", "Usage:"}},
		{"help unknown command", []string{"help", "bogus"}, exitcode.ConfigError, nil, []string{`unknown command "bogus"`, "Usage:"}},
		{"help too many args", []string{"help", "scan", "init"}, exitcode.ConfigError, nil, []string{`unexpected arguments: ["init"]`}},
		{"help known command", []string{"help", "scan"}, exitcode.OK, []string{"creep scan [flags]", "Exit codes:"}, nil},
		{"help help", []string{"help", "help"}, exitcode.OK, []string{"Commands:"}, nil},
		{"help command with valid flags", []string{"--format", "json", "help", "version", "--log-level=debug"}, exitcode.OK, []string{"creep version [flags]"}, nil},
		{"help flag with invalid format", []string{"--format=bad", "--help"}, exitcode.ConfigError, nil, []string{`invalid --format "bad"`}},
		{"invalid format after help flag", []string{"--help", "--format=bad"}, exitcode.ConfigError, nil, []string{`invalid --format "bad"`}},
		{"command help flag with invalid format", []string{"scan", "--help", "--log-level=trace"}, exitcode.ConfigError, nil, []string{`invalid --log-level "trace"`}},
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
		if c.name == "version" || c.name == "config" {
			continue
		}
		if c.name == "resume" { // checks its run first; TestResumeFailsClosed covers it
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
	for _, name := range []string{"init", "doctor", "scan"} {
		c, _ := findCommand(name)
		assertContains(t, "usage", stdout, []string{c.name + " ", c.summary, "(not implemented yet)"})
	}
}

// TestErrorsEscapeControlBytes guards the terminal: user input echoed in an
// error (here, an unknown flag name) must never write raw control bytes.
func TestErrorsEscapeControlBytes(t *testing.T) {
	evil := "-\x1b]0;PWN\a\u009b\xff"
	tests := []struct {
		name string
		args []string
	}{
		{"unknown global flag", []string{evil, "version"}},
		{"unknown command flag", []string{"scan", evil}},
		{"unknown help flag", []string{"help", evil}},
		{"unknown command", []string{evil[1:]}},
		{"help unknown command", []string{"help", evil[1:]}},
		{"invalid format", []string{"--format", evil, "version"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, stderr := run(tt.args...)
			if code != exitcode.ConfigError {
				t.Errorf("exit code = %d, want %d", code, exitcode.ConfigError)
			}
			for _, r := range strings.TrimRight(stderr, "\n") {
				if r != '\n' && (r < 0x20 || r == 0x7f || r >= 0x80 && r < 0xa0 || r == '\u202e') {
					t.Fatalf("stderr contains control rune %U: %q", r, stderr)
				}
			}
			assertContains(t, "stderr", stderr, []string{`\x1b]0;PWN`})
		})
	}
}

func TestEscapeControl(t *testing.T) {
	tests := []struct{ in, want string }{
		{"plain text", "plain text"},
		{`back\slash`, `back\slash`},
		{"esc\x1b[31m", `esc\x1b[31m`},
		{"bell\a nul\x00 del\x7f", `bell\x07 nul\x00 del\x7f`},
		{"csi\u009b", `csi\x9b`},
		{"bidi\u202e", `bidi\u202e`},
		{"invalid\xff", `invalid\xff`},
		{"tab\tnewline\n", `tab\x09newline\x0a`},
		{"ünïcode ok", "ünïcode ok"},
	}
	for _, tt := range tests {
		if got := escapeControl(tt.in); got != tt.want {
			t.Errorf("escapeControl(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
