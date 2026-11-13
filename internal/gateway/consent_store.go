package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
)

// ErrUnsafeConsentStore means the consent file or its directory is a link,
// a special file, owned by another user or writable by others.
var ErrUnsafeConsentStore = errors.New("unsafe consent store")

// consentVersion is the consent file format version.
const consentVersion = 1

// maxConsentBytes bounds the consent file read into memory.
const maxConsentBytes = 1 << 20

// testHookBeforeStoreOpen runs between the Lstat of the consent store and
// its open, so tests can swap the file in that window.
var testHookBeforeStoreOpen = func(string) {}

// consentFile is the stored form: {"v":1,"endpoints":["https://h:443"]}.
type consentFile struct {
	V         int      `json:"v"`
	Endpoints []string `json:"endpoints"`
}

// readConsentStore returns the stored origins; a missing file is empty.
// The file must be a regular file of this user that others cannot write
// (outside Windows, see checkAccess), opened without following a link and
// checked to be the same file after opening.
func readConsentStore(path string) (map[string]bool, error) {
	data, err := readStoreFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]bool{}, nil
	}
	if err != nil {
		return nil, err
	}
	var cf consentFile
	if err := json.Unmarshal(data, &cf); err != nil || cf.V != consentVersion {
		return nil, fmt.Errorf("consent store %q: unreadable, want version %d JSON", path, consentVersion)
	}
	keys := map[string]bool{}
	for _, e := range cf.Endpoints {
		key, err := parseOrigin(e)
		if err != nil || key != e {
			return nil, fmt.Errorf("consent store %q: entry %q is not a normalized origin", path, e)
		}
		keys[key] = true
	}
	return keys, nil
}

func readStoreFile(path string) ([]byte, error) {
	before, err := lstatPinned(path)
	if err != nil {
		return nil, err
	}
	if err := checkStoreFile(path, before); err != nil {
		return nil, err
	}
	testHookBeforeStoreOpen(path)
	f, err := os.OpenFile(path, os.O_RDONLY|extraOpenFlags, 0)
	if err != nil {
		return nil, fmt.Errorf("consent store: %w", err)
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, fmt.Errorf("consent store %q changed while opening: %w", path, ErrUnsafeConsentStore)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxConsentBytes+1))
	if err != nil {
		return nil, fmt.Errorf("consent store: %w", err)
	}
	if len(data) > maxConsentBytes {
		return nil, fmt.Errorf("consent store %q: larger than %d bytes", path, maxConsentBytes)
	}
	return data, nil
}

func checkStoreFile(path string, info fs.FileInfo) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("consent store %q: not a regular file: %w", path, ErrUnsafeConsentStore)
	}
	if err := checkAccess(path, info, 0o022, ErrUnsafeConsentStore); err != nil {
		return fmt.Errorf("consent store: %w", err)
	}
	return nil
}

// addStoredConsent adds key to the store. It writes a new 0600 file in the
// same directory and renames it over the old one, so a reader never sees a
// partial file and a link at path is replaced, never followed.
func addStoredConsent(path, key string) error {
	dir := filepath.Dir(path)
	if err := ensureStoreDir(dir); err != nil {
		return err
	}
	keys, err := readConsentStore(path)
	if err != nil {
		return err
	}
	keys[key] = true
	cf := consentFile{V: consentVersion, Endpoints: sortedKeys(keys)}
	data, err := json.Marshal(cf)
	if err != nil {
		return fmt.Errorf("consent store: encode: %w", err)
	}
	return replaceFile(dir, path, append(data, '\n'))
}

// ensureStoreDir creates dir with mode 0700 if missing and refuses one that
// is a link, not a directory, another user's, or writable by others.
func ensureStoreDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("consent store dir: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("consent store dir: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("consent store dir %q: not a directory: %w", dir, ErrUnsafeConsentStore)
	}
	if err := checkAccess(dir, info, 0o022, ErrUnsafeConsentStore); err != nil {
		return fmt.Errorf("consent store dir: %w", err)
	}
	return nil
}

// replaceFile writes data to a fresh temporary file (os.CreateTemp: mode
// 0600, O_EXCL) in dir, syncs it and renames it to path.
func replaceFile(dir, path string, data []byte) error {
	tmp, err := os.CreateTemp(dir, ".consent-*.tmp")
	if err != nil {
		return fmt.Errorf("consent store: %w", err)
	}
	_, werr := tmp.Write(data)
	serr := tmp.Sync()
	cerr := tmp.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("consent store: write: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("consent store: %w", err)
	}
	return syncDirPath(dir)
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
