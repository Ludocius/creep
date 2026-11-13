//go:build unix

package gateway

import (
	"os"
	"syscall"
	"testing"
)

func mkfifo(t *testing.T, path string) {
	t.Helper()
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
}

// Character devices that are not terminals cannot hang the prompt or
// consent: /dev/null ends at once, and /dev/zero (endless input, no
// newline) stops at maxAnswerBytes.
func TestTerminalPromptCharDevicesDecline(t *testing.T) {
	for _, dev := range []string{os.DevNull, "/dev/zero"} {
		f, err := os.Open(dev)
		if err != nil {
			t.Skipf("%s: %v", dev, err)
		}
		ok, err := TerminalPrompt(f, &countingWriter{})("https://a.example:443")
		_ = f.Close()
		if ok || err != nil {
			t.Fatalf("prompt on %s = %v, %v; want decline", dev, ok, err)
		}
	}
}
