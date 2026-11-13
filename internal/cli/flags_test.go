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

func TestConfigRejectsDevices(t *testing.T) {
	tests := []struct {
		name string
		path string
		goos string // "" runs everywhere except where noted by the path's OS
	}{
		{"NUL", "NUL", "windows"},
		{"lowercase nul", "nul", "windows"},
		{"CON", "CON", "windows"},
		{"COM1", "COM1", "windows"},
		{"device namespace backslash", `\.\NUL`, "windows"},
		{"device namespace slash", "//./NUL", "windows"},
		{"dev null", "/dev/null", "unix"},
		{"dev zero", "/dev/zero", "unix"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			skipUnlessOS(t, tt.goos)
			code, _, stderr := run("--config", tt.path, "version")
			if code != exitcode.ConfigError {
				t.Errorf("exit code = %d, want %d\nstderr: %s", code, exitcode.ConfigError, stderr)
			}
			assertContains(t, "stderr", stderr, []string{"--config "})
		})
	}
}

func skipUnlessOS(t *testing.T, want string) {
	t.Helper()
	isWindows := runtime.GOOS == "windows"
	if want == "windows" && !isWindows || want == "unix" && isWindows {
		t.Skipf("%s only", want)
	}
}

func TestConfigErrorsQuotePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evil\x1b[31m.yaml")
	code, _, stderr := run("--config", path, "version")
	if code != exitcode.ConfigError {
		t.Errorf("exit code = %d, want %d", code, exitcode.ConfigError)
	}
	if strings.Contains(stderr, "\x1b") {
		t.Errorf("stderr contains a raw escape byte: %q", stderr)
	}
	assertContains(t, "stderr", stderr, []string{`\x1b[31m.yaml"`})
}

func TestReadConfig(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, size int) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, bytes.Repeat([]byte("a"), size), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	tests := []struct {
		name    string
		path    string
		wantLen int
		wantErr string
	}{
		{"small", write("small.yaml", 10), 10, ""},
		{"exactly at cap", write("cap.yaml", maxConfigBytes), maxConfigBytes, ""},
		{"over cap", write("big.yaml", maxConfigBytes+1), 0, "larger than"},
		{"directory", dir, 0, "is a directory"},
		{"missing", filepath.Join(dir, "nope.yaml"), 0, "does not exist"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := readConfigFile("--config", tt.path)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(data) != tt.wantLen {
				t.Errorf("len = %d, want %d", len(data), tt.wantLen)
			}
		})
	}
}

// TestConfigFollowsSymlinks checks the opened target is judged, not the link:
// a link to a device is rejected and a link to a regular file is accepted.
func TestConfigFollowsSymlinks(t *testing.T) {
	skipUnlessOS(t, "unix")
	dir := t.TempDir()
	regular := filepath.Join(dir, "creep.yaml")
	if err := os.WriteFile(regular, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		target   string
		wantCode int
	}{
		{"link to device", "/dev/zero", exitcode.ConfigError},
		{"link to regular file", regular, exitcode.OK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			link := filepath.Join(dir, strings.ReplaceAll(tt.name, " ", "-"))
			if err := os.Symlink(tt.target, link); err != nil {
				t.Fatal(err)
			}
			code, _, stderr := run("--config", link, "version")
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d\nstderr: %s", code, tt.wantCode, stderr)
			}
		})
	}
}
