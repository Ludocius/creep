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
// directory is a link, a special file, shared with other users, or changed
// while being opened.
var ErrUnsafeLogPath = errors.New("unsafe egress log path")

// testHookBeforeOpen runs between the Lstat of egress.log and its open, so
// tests can swap the file in that window.
var testHookBeforeOpen = func(string) {}

// EgressLog appends one JSON line per event to <run>/egress.log. It is safe
// for concurrent use; each line is written with a single append and synced
// before Send continues.
type EgressLog struct {
	mu        sync.Mutex
	f         *os.File
	payloads  *os.Root // held open, so swapping the path for a link later has no effect
	freshLine bool     // the file may not end in '\n': start the next line with one
	consent   *Consent // gates every Send; nil refuses every call
}

// OpenEgressLog opens <runDir>/egress.log for appending, creating it with
// mode 0600, and <runDir>/payloads with mode 0700. runDir must already exist;
// the scan command creates it with mode 0700.
//
// It refuses a run directory, payload directory or log that is a symlink or
// not a directory or regular file. Outside Windows it also refuses them when
// owned by another user or when their mode grants group or others access
// (write access only, for the run directory), and a log with more than one
// hard link. Lstat before open plus a same-file check after open detects a
// swap in between; a new log is created with O_EXCL, which never follows a
// link. Windows file modes do not express ACLs, so there only the type and
// same-file checks apply.
//
// consent gates every Send before anything is written or sent; a nil
// consent refuses every call.
func OpenEgressLog(runDir string, consent *Consent) (*EgressLog, error) {
	if _, err := checkDir(runDir, 0o022); err != nil {
		return nil, err
	}
	payloads, err := openPayloadDir(filepath.Join(runDir, payloadDirName))
	if err != nil {
		return nil, err
	}
	l, err := openLogFile(runDir, payloads)
	if err != nil {
		_ = payloads.Close()
		return nil, err
	}
	l.consent = consent
	return l, nil
}

func openLogFile(runDir string, payloads *os.Root) (*EgressLog, error) {
	f, fresh, err := openAppendOnly(filepath.Join(runDir, egressLogName))
	if err != nil {
		return nil, err
	}
	if err := syncDirPath(runDir); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &EgressLog{f: f, payloads: payloads, freshLine: fresh}, nil
}

// Close closes the log file and the payload directory.
func (l *EgressLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return errors.Join(l.f.Close(), l.payloads.Close())
}

// lstatPinned is os.Lstat with the file identity read now. On Windows,
// Lstat's FileInfo loads the file ID lazily, by path, on the first
// os.SameFile, which would compare against whatever replaced the file.
func lstatPinned(path string) (fs.FileInfo, error) {
	info, err := os.Lstat(path)
	if err == nil {
		os.SameFile(info, info)
	}
	return info, err
}

// checkDir refuses a path that is not a real directory of this user, or
// whose mode has any bit in mask.
func checkDir(path string, mask fs.FileMode) (fs.FileInfo, error) {
	info, err := lstatPinned(path)
	if err != nil {
		return nil, fmt.Errorf("egress log dir: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("egress log dir %q: not a directory: %w", path, ErrUnsafeLogPath)
	}
	return info, checkAccess(path, info, mask, ErrUnsafeLogPath)
}

func openPayloadDir(path string) (*os.Root, error) {
	err := os.Mkdir(path, payloadDirMode)
	if err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, fmt.Errorf("egress payload dir: %w", err)
	}
	before, err := checkDir(path, 0o077)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, fmt.Errorf("egress payload dir: %w", err)
	}
	after, err := root.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		_ = root.Close()
		return nil, fmt.Errorf("egress payload dir %q changed while opening: %w", path, ErrUnsafeLogPath)
	}
	return root, nil
}

// checkAccess refuses another user's file and modes with any bit in mask.
// Skipped on Windows, where Go reports 0666 or 0444 for every file whatever
// its ACL says and files have no Unix owner.
func checkAccess(path string, info fs.FileInfo, mask fs.FileMode, unsafe error) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	if info.Mode().Perm()&mask != 0 {
		return fmt.Errorf("%q has mode %v: %w", path, info.Mode().Perm(), unsafe)
	}
	if !ownedBySelf(info) {
		return fmt.Errorf("%q is owned by another user: %w", path, unsafe)
	}
	return nil
}

// openAppendOnly opens path with O_APPEND, creating it if missing. fresh
// reports that an existing log does not end in a newline (a torn write).
func openAppendOnly(path string) (f *os.File, fresh bool, err error) {
	before, err := lstatPinned(path)
	if errors.Is(err, fs.ErrNotExist) {
		testHookBeforeOpen(path)
		f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|os.O_CREATE|os.O_EXCL|extraOpenFlags, logFileMode)
		if err != nil {
			return nil, false, fmt.Errorf("egress log: create: %w", err)
		}
		return f, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("egress log: %w", err)
	}
	if err := checkLogFile(path, before); err != nil {
		return nil, false, err
	}
	testHookBeforeOpen(path)
	return openExisting(path, before)
}

func openExisting(path string, before fs.FileInfo) (*os.File, bool, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|extraOpenFlags, 0)
	if err != nil {
		return nil, false, fmt.Errorf("egress log: %w", err)
	}
	fresh, err := sameFile(f, before)
	if err != nil {
		_ = f.Close()
		return nil, false, err
	}
	return f, fresh, nil
}

func checkLogFile(path string, info fs.FileInfo) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("egress log %q: not a regular file: %w", path, ErrUnsafeLogPath)
	}
	if runtime.GOOS != "windows" && linkCount(info) != 1 {
		return fmt.Errorf("egress log %q has other hard links: %w", path, ErrUnsafeLogPath)
	}
	return checkAccess(path, info, 0o077, ErrUnsafeLogPath)
}

// sameFile refuses an open file that is not the one Lstat saw, which means
// path was replaced (by a link, say) between the two calls. It reports
// whether the file lacks a final newline.
func sameFile(f *os.File, before fs.FileInfo) (bool, error) {
	after, err := f.Stat()
	if err != nil {
		return false, fmt.Errorf("egress log: %w", err)
	}
	if !os.SameFile(before, after) {
		return false, fmt.Errorf("egress log %q changed while opening: %w", f.Name(), ErrUnsafeLogPath)
	}
	if err := checkLogFile(f.Name(), after); err != nil || after.Size() == 0 {
		return false, err
	}
	last := make([]byte, 1)
	if _, err := f.ReadAt(last, after.Size()-1); err != nil {
		return false, fmt.Errorf("egress log: %w", err)
	}
	return last[0] != '\n', nil
}

// writeLine appends v as one JSON line and syncs it to disk. encoding/json
// escapes control characters (so no field can start a new line) and replaces
// invalid UTF-8; marshaling first and writing once keeps concurrent lines
// whole. After a torn write the next line starts with '\n', so readers see
// at most one broken line and should skip blank ones.
func (l *EgressLog) writeLine(v any) error {
	line, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("egress log: encode: %w", err)
	}
	line = append(line, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.freshLine {
		line = append([]byte{'\n'}, line...)
	}
	n, err := l.f.Write(line)
	if err != nil {
		l.freshLine = l.freshLine || n > 0
		return fmt.Errorf("egress log: write: %w", err)
	}
	l.freshLine = false
	if err := l.f.Sync(); err != nil {
		return fmt.Errorf("egress log: sync: %w", err)
	}
	return nil
}

// writePayload stores the exact request bytes in payloads/<id>.payload with
// mode 0600 and returns the name relative to the run directory. The file is
// opened through the held os.Root with O_EXCL, so it is never a link.
func (l *EgressLog) writePayload(id string, payload []byte) (string, error) {
	name := id + ".payload"
	f, err := l.payloads.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|extraOpenFlags, logFileMode)
	if err != nil {
		return "", fmt.Errorf("egress: create payload %s: %w", name, err)
	}
	_, werr := f.Write(payload)
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		return "", fmt.Errorf("egress: write payload %s: %w", name, err)
	}
	if err := l.syncPayloadDir(); err != nil {
		return "", err
	}
	return payloadDirName + "/" + name, nil
}

func (l *EgressLog) syncPayloadDir() error {
	d, err := l.payloads.Open(".")
	if err != nil {
		return fmt.Errorf("egress payload dir: %w", err)
	}
	defer d.Close()
	if err := syncDir(d); err != nil {
		return fmt.Errorf("egress payload dir: sync: %w", err)
	}
	return nil
}

// syncDirPath makes a newly created entry in dir durable.
func syncDirPath(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("egress log dir: %w", err)
	}
	defer d.Close()
	if err := syncDir(d); err != nil {
		return fmt.Errorf("egress log dir: sync: %w", err)
	}
	return nil
}
