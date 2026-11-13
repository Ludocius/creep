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
			if l, err := OpenEgressLog(dir); err == nil {
				_ = l.Close()
				t.Fatal("OpenEgressLog: want error")
			}
		})
	}
}

func TestUnsafePathError(t *testing.T) {
	dir := runDir(t)
	mkdir(t, dir, egressLogName)
	if _, err := OpenEgressLog(dir); !errors.Is(err, ErrUnsafeLogPath) {
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
