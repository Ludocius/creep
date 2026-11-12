//go:build unix

package cli

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/Ludocius/creep/internal/exitcode"
)

// TestConfigRejectsFIFO guards against a hang: opening a FIFO with no writer
// blocks, so the check must not wait for one, directly or via a symlink.
func TestConfigRejectsFIFO(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "creep.yaml")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unsupported here: %v", err)
	}
	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(fifo, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{fifo, link} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			code, stderr := runWithTimeout(t, "--config", path, "version")
			if code != exitcode.ConfigError {
				t.Errorf("exit code = %d, want %d\nstderr: %s", code, exitcode.ConfigError, stderr)
			}
			assertContains(t, "stderr", stderr, []string{"not a regular file"})
		})
	}
}

func runWithTimeout(t *testing.T, args ...string) (int, string) {
	t.Helper()
	type result struct {
		code   int
		stderr string
	}
	done := make(chan result, 1)
	go func() {
		code, _, stderr := run(args...)
		done <- result{code, stderr}
	}()
	select {
	case r := <-done:
		return r.code, r.stderr
	case <-time.After(5 * time.Second):
		t.Fatalf("creep %v hung", args)
		return 0, ""
	}
}
