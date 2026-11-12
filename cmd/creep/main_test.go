package main

import (
	"errors"
	"os"
	"os/exec"
	"testing"
)

// reexecEnv makes the test binary act as creep, so the real os.Exit path runs.
const reexecEnv = "CREEP_TEST_RUN_MAIN"

func TestMain(m *testing.M) {
	if os.Getenv(reexecEnv) == "1" {
		os.Args = append([]string{"creep"}, os.Args[1:]...)
		main()
		return
	}
	os.Exit(m.Run())
}

func TestProcessExitCodes(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want int
	}{
		{"version", []string{"version"}, 0},
		{"help", []string{"--help"}, 0},
		{"no args", nil, 2},
		{"unknown command", []string{"frobnicate"}, 2},
		{"unknown flag", []string{"--nope", "version"}, 2},
		{"invalid format", []string{"version", "--format", "xml"}, 2},
		{"missing config", []string{"--config", "does-not-exist.yaml", "version"}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], tt.args...)
			cmd.Env = append(os.Environ(), reexecEnv+"=1")
			if got := exitCode(t, cmd.Run()); got != tt.want {
				t.Errorf("exit code = %d, want %d", got, tt.want)
			}
		})
	}
}

func exitCode(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("run creep: %v", err)
	}
	return exitErr.ExitCode()
}
