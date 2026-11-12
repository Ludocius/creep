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
		{"version extra args", []string{"version", "x"}, exitcode.ConfigError, nil, []string{"unexpected arguments"}},
		{"global flags after command", []string{"version", "--format", "json", "--log-level", "debug"}, exitcode.OK, []string{"commit: "}, nil},
		{"invalid format", []string{"--format", "xml", "version"}, exitcode.ConfigError, nil, []string{"invalid --format"}},
		{"invalid log level", []string{"scan", "--log-level=loud"}, exitcode.ConfigError, nil, []string{"invalid --log-level"}},
		{"config exists", []string{"--config", cfg, "version"}, exitcode.OK, []string{"commit: "}, nil},
		{"config missing", []string{"--config", missing, "version"}, exitcode.ConfigError, nil, []string{"does not exist"}},
		{"config is dir", []string{"--config", dir, "version"}, exitcode.ConfigError, nil, []string{"is a directory"}},
		{"unknown command flag", []string{"doctor", "--bogus"}, exitcode.ConfigError, nil, []string{"bogus", "creep doctor"}},
		{"init stub", []string{"init"}, exitcode.OK, nil, []string{"not implemented yet"}},
		{"doctor stub", []string{"doctor"}, exitcode.OK, nil, []string{"not implemented yet"}},
		{"scan stub", []string{"scan", "."}, exitcode.OK, nil, []string{"not implemented yet"}},
		{"config stub", []string{"config", "explain"}, exitcode.OK, nil, []string{"not implemented yet"}},
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
