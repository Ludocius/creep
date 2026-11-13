package gateway

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Acceptance: egress.log and payload files are created 0600 and the payload
// directory 0700. Skipped on Windows, where Go file modes do not reflect
// ACLs; the Linux CI job and the -race docker run cover it.
func TestFileModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows file modes do not express ACLs; checked on Linux")
	}
	srv := newModelServer(t, "ok")
	dir := runDir(t)
	l := openLog(t, dir)
	reply, err := l.Send(context.Background(), srv.client(t), testCall(srv.url("/v1")))
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	want := map[string]fs.FileMode{
		egressLogName:  0o600,
		payloadDirName: 0o700,
		filepath.Join(payloadDirName, reply.ID+".payload"): 0o600,
	}
	for name, mode := range want {
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != mode {
			t.Errorf("%s mode = %v, want %v", name, info.Mode().Perm(), mode)
		}
	}
}

// An existing private log is appended to, never truncated.
func TestReopenAppends(t *testing.T) {
	dir := runDir(t)
	path := filepath.Join(dir, egressLogName)
	if err := os.WriteFile(path, []byte("{\"old\":1}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	l := openLog(t, dir)
	if err := l.writeLine(map[string]int{"new": 2}); err != nil {
		t.Fatal(err)
	}
	if lines := readLines(t, dir); len(lines) != 2 || lines[0]["old"] != 1.0 {
		t.Fatalf("lines = %v; want old line kept", lines)
	}
}

// The log refuses paths an attacker could have prepared.
func TestOpenRefusesUnsafePaths(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(t *testing.T, dir string) string // returns the run dir to open
		unix    bool                                  // relies on file modes
	}{
		{"run dir missing", func(_ *testing.T, dir string) string { return filepath.Join(dir, "none") }, false},
		{"run dir is a file", func(t *testing.T, dir string) string { return writeFile(t, dir, "f", 0o600) }, false},
		{"log is a directory", func(t *testing.T, dir string) string { mkdir(t, dir, egressLogName); return dir }, false},
		{"log is a symlink", symlinkLog, false},
		{"payloads is a symlink", symlinkPayloads, false},
		{"log readable by others", func(t *testing.T, dir string) string { writeFile(t, dir, egressLogName, 0o644); return dir }, true},
		{"run dir writable by others", func(t *testing.T, dir string) string { chmod(t, dir, 0o777); return dir }, true},
		{"payloads readable by others", func(t *testing.T, dir string) string { chmod(t, mkdir(t, dir, payloadDirName), 0o755); return dir }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.unix && runtime.GOOS == "windows" {
				t.Skip("Windows file modes do not express ACLs")
			}
			dir := tt.prepare(t, runDir(t))
			if l, err := OpenEgressLog(dir, nil); err == nil {
				_ = l.Close()
				t.Fatal("OpenEgressLog: want error")
			}
		})
	}
}

func TestUnsafePathError(t *testing.T) {
	dir := runDir(t)
	mkdir(t, dir, egressLogName)
	if _, err := OpenEgressLog(dir, nil); !errors.Is(err, ErrUnsafeLogPath) {
		t.Fatalf("err = %v, want ErrUnsafeLogPath", err)
	}
}

// symlinkLog points egress.log at a file outside the run directory, the
// way a hostile checkout or another process could redirect writes.
func symlinkLog(t *testing.T, dir string) string {
	target := writeFile(t, t.TempDir(), "victim", 0o600)
	symlink(t, target, filepath.Join(dir, egressLogName))
	return dir
}

func symlinkPayloads(t *testing.T, dir string) string {
	symlink(t, t.TempDir(), filepath.Join(dir, payloadDirName))
	return dir
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}
}

func writeFile(t *testing.T, dir, name string, mode fs.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("{}\n"), mode); err != nil {
		t.Fatal(err)
	}
	chmod(t, p, mode) // WriteFile's mode is narrowed by umask
	return p
}

func mkdir(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

func chmod(t *testing.T, path string, mode fs.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// Swaps between the Lstat of egress.log and its open are refused: a new log
// needs O_EXCL, an existing one the same-file check.
func TestOpenRace(t *testing.T) {
	tests := []struct {
		name     string
		existing bool
	}{
		{"file appears after Lstat", false},
		{"file replaced after Lstat", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := runDir(t)
			if tt.existing {
				writeFile(t, dir, egressLogName, 0o600)
			}
			other := writeFile(t, t.TempDir(), "other", 0o600)
			setOpenHook(t, func(path string) {
				if err := os.Rename(other, path); err != nil {
					t.Fatal(err)
				}
			})
			if l, err := OpenEgressLog(dir, nil); err == nil {
				_ = l.Close()
				t.Fatal("OpenEgressLog: want error")
			}
		})
	}
}

func setOpenHook(t *testing.T, hook func(string)) {
	t.Helper()
	old := testHookBeforeOpen
	testHookBeforeOpen = hook
	t.Cleanup(func() { testHookBeforeOpen = old })
}

// Unix only: a log with a second hard link or another owner is refused.
func TestOpenRefusesSharedLog(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no Unix owner and link count is not checked; see checkAccess")
	}
	tests := []struct {
		name    string
		prepare func(t *testing.T, log string)
	}{
		{"second hard link", func(t *testing.T, log string) {
			if err := os.Link(log, filepath.Join(t.TempDir(), "alias")); err != nil {
				t.Skipf("hard links unsupported: %v", err)
			}
		}},
		{"other owner", func(t *testing.T, log string) {
			if os.Geteuid() != 0 {
				t.Skip("chown to another user needs root; the docker -race run covers it")
			}
			if err := os.Chown(log, 65534, 65534); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := runDir(t)
			tt.prepare(t, writeFile(t, dir, egressLogName, 0o600))
			if _, err := OpenEgressLog(dir, nil); !errors.Is(err, ErrUnsafeLogPath) {
				t.Fatalf("err = %v, want ErrUnsafeLogPath", err)
			}
		})
	}
}

// A log left without a final newline by a torn write gets its next line on
// a fresh line.
func TestTornLineRecovered(t *testing.T) {
	dir := runDir(t)
	if err := os.WriteFile(filepath.Join(dir, egressLogName), []byte(`{"torn":`), 0o600); err != nil {
		t.Fatal(err)
	}
	l := openLog(t, dir)
	if err := l.writeLine(map[string]int{"next": 1}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, egressLogName))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "{\"torn\":\n{\"next\":1}\n" {
		t.Fatalf("log = %q; want the new line after a newline", raw)
	}
}
