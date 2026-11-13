package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

// Names inside the run directory. The payload directory holds the exact bytes
// of each request; egress.log holds only their hash and file name.
const (
	egressLogName  = "egress.log"
	payloadDirName = "payloads"
	logFileMode    = 0o600
	payloadDirMode = 0o700
)

// ErrUnsafeLogPath means egress.log, the payload directory or the run
// directory is a link, a special file, or readable or writable by others.
var ErrUnsafeLogPath = errors.New("unsafe egress log path")

// EgressLog appends one JSON line per event to <run>/egress.log. It is safe
// for concurrent use; each line is written with a single append and synced
// before Send continues.
type EgressLog struct {
	mu         sync.Mutex
	f          *os.File
	payloadDir string
}

// OpenEgressLog opens <runDir>/egress.log for appending, creating it with
// mode 0600, and <runDir>/payloads with mode 0700. runDir must already exist;
// the scan command creates it with mode 0700.
//
// It refuses a run directory or log that is a symlink or not a directory or
// regular file, and (outside Windows) one whose mode grants any access to
// group or others. Lstat before open plus a same-file check after open
// detects a log swapped for a link in between; a new log is created with
// O_EXCL, which never follows a link. Windows file modes do not express
// ACLs, so there only the type checks apply.
func OpenEgressLog(runDir string) (*EgressLog, error) {
	if err := checkDir(runDir, false); err != nil {
		return nil, err
	}
	payloadDir := filepath.Join(runDir, payloadDirName)
	if err := ensurePayloadDir(payloadDir); err != nil {
		return nil, err
	}
	f, err := openAppendOnly(filepath.Join(runDir, egressLogName))
	if err != nil {
		return nil, err
	}
	return &EgressLog{f: f, payloadDir: payloadDir}, nil
}

// Close closes the log file.
func (l *EgressLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}

// checkDir refuses a path that is not a real directory. The run directory
// only has to be unwritable by others (strict=false); the payload directory,
// which creep creates, must be private.
func checkDir(path string, strict bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("egress log dir: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("egress log dir %q: not a directory: %w", path, ErrUnsafeLogPath)
	}
	mask := fs.FileMode(0o022)
	if strict {
		mask = 0o077
	}
	return checkPerm(path, info.Mode(), mask)
}

func ensurePayloadDir(path string) error {
	err := os.Mkdir(path, payloadDirMode)
	if err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("egress payload dir: %w", err)
	}
	return checkDir(path, true)
}

// checkPerm refuses modes with any bit in mask. Skipped on Windows, where Go
// reports 0666 or 0444 for every file whatever its ACL says.
func checkPerm(path string, mode fs.FileMode, mask fs.FileMode) error {
	if runtime.GOOS == "windows" || mode.Perm()&mask == 0 {
		return nil
	}
	return fmt.Errorf("%q has mode %v: %w", path, mode.Perm(), ErrUnsafeLogPath)
}

// openAppendOnly opens path with O_APPEND, creating it if missing.
func openAppendOnly(path string) (*os.File, error) {
	before, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return createExclusive(path, os.O_WRONLY|os.O_APPEND)
	}
	if err != nil {
		return nil, fmt.Errorf("egress log: %w", err)
	}
	if err := checkRegular(path, before); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return nil, fmt.Errorf("egress log: %w", err)
	}
	if err := sameFile(f, before); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// createExclusive creates path with mode 0600. O_EXCL fails if anything,
// a dangling symlink included, appeared at path.
func createExclusive(path string, flag int) (*os.File, error) {
	f, err := os.OpenFile(path, flag|os.O_CREATE|os.O_EXCL, logFileMode)
	if err != nil {
		return nil, fmt.Errorf("egress: create %q: %w", filepath.Base(path), err)
	}
	return f, nil
}

func checkRegular(path string, info fs.FileInfo) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("egress log %q: not a regular file: %w", path, ErrUnsafeLogPath)
	}
	return checkPerm(path, info.Mode(), 0o077)
}

// sameFile refuses an open file that is not the one Lstat saw, which means
// path was replaced (by a link, say) between the two calls.
func sameFile(f *os.File, before fs.FileInfo) error {
	after, err := f.Stat()
	if err != nil {
		return fmt.Errorf("egress log: %w", err)
	}
	if !os.SameFile(before, after) {
		return fmt.Errorf("egress log %q changed while opening: %w", f.Name(), ErrUnsafeLogPath)
	}
	return checkRegular(f.Name(), after)
}

// writeLine appends v as one JSON line and syncs it to disk. encoding/json
// escapes control characters (so no field can start a new line) and replaces
// invalid UTF-8; marshaling first and writing once keeps concurrent lines
// whole.
func (l *EgressLog) writeLine(v any) error {
	line, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("egress log: encode: %w", err)
	}
	line = append(line, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.f.Write(line); err != nil {
		return fmt.Errorf("egress log: write: %w", err)
	}
	if err := l.f.Sync(); err != nil {
		return fmt.Errorf("egress log: sync: %w", err)
	}
	return nil
}

// writePayload stores the exact request bytes in payloads/<id>.payload with
// mode 0600 and returns the name relative to the run directory.
func (l *EgressLog) writePayload(id string, payload []byte) (string, error) {
	name := id + ".payload"
	f, err := createExclusive(filepath.Join(l.payloadDir, name), os.O_WRONLY)
	if err != nil {
		return "", err
	}
	_, werr := f.Write(payload)
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		return "", fmt.Errorf("egress: write payload %s: %w", name, err)
	}
	return payloadDirName + "/" + name, nil
}
