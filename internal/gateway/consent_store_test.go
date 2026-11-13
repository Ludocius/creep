package gateway

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Ludocius/creep/internal/exitcode"
)

const storedA = `{"v":1,"endpoints":["https://a.example:443"]}`

// A store that cannot be trusted or read refuses the call like a decline:
// *ConsentError with the cause in Err and exit code 2. unsafe cases must
// fail on the safety check itself (ErrUnsafeConsentStore), not on a later
// read or parse error, so dropping a check is caught.
func TestBadStoreRefused(t *testing.T) {
	tests := []struct {
		name   string
		unsafe bool
		setup  func(t *testing.T, store string)
	}{
		{"not JSON", false, func(t *testing.T, store string) { writeStore(t, store, "nope") }},
		{"wrong version", false, func(t *testing.T, store string) { writeStore(t, store, `{"v":2,"endpoints":[]}`) }},
		{"unnormalized entry", false, func(t *testing.T, store string) {
			writeStore(t, store, `{"v":1,"endpoints":["https://A.example"]}`)
		}},
		{"directory", true, func(t *testing.T, store string) {
			if err := os.Mkdir(store, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
		{"writable by others", true, func(t *testing.T, store string) {
			skipOnWindows(t)
			writeStore(t, store, storedA)
			chmod(t, store, 0o666)
		}},
		{"symlink", true, func(t *testing.T, store string) {
			target := store + ".target"
			writeStore(t, target, storedA)
			symlink(t, target, store)
		}},
		{"FIFO", true, func(t *testing.T, store string) { mkfifo(t, store) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := filepath.Join(t.TempDir(), "consent.json")
			tt.setup(t, store)
			c := newConsent(t, ConsentOptions{StorePath: store, Prompt: answer(true, nil)})
			checkStoreRefusal(t, c.check(mustURL(t, "https://a.example/")), tt.unsafe)
		})
	}
}

func checkStoreRefusal(t *testing.T, err error, unsafe bool) {
	t.Helper()
	var ce *ConsentError
	if !errors.As(err, &ce) || ce.Err == nil || ce.ExitCode() != exitcode.ConfigError || !errors.Is(err, ErrNoConsent) {
		t.Fatalf("check = %#v, want *ConsentError with a cause and exit %d", err, exitcode.ConfigError)
	}
	if unsafe && !errors.Is(err, ErrUnsafeConsentStore) {
		t.Fatalf("check = %v, want ErrUnsafeConsentStore", err)
	}
}

// Swapping the store between its Lstat and open is caught by the same-file
// check, even when the replacement is itself a safe, valid store.
func TestStoreSwapRefused(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "consent.json")
	writeStore(t, store, storedA)
	other := filepath.Join(dir, "other.json")
	writeStore(t, other, storedA)
	testHookBeforeStoreOpen = func(p string) {
		if err := os.Rename(other, p); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { testHookBeforeStoreOpen = func(string) {} })
	c := newConsent(t, ConsentOptions{StorePath: store})
	checkStoreRefusal(t, c.check(mustURL(t, "https://a.example/")), true)
}

// Saving a yes refuses a store directory that is not a private real
// directory; the call is refused and nothing is stored.
func TestUnsafeStoreDirRefused(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, dir string)
	}{
		{"writable by others", func(t *testing.T, dir string) {
			skipOnWindows(t)
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			chmod(t, dir, 0o777)
		}},
		{"symlink to a directory", func(t *testing.T, dir string) {
			target := dir + ".target"
			if err := os.Mkdir(target, 0o700); err != nil {
				t.Fatal(err)
			}
			symlink(t, target, dir)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "creep")
			tt.setup(t, dir)
			store := filepath.Join(dir, "consent.json")
			c := newConsent(t, ConsentOptions{StorePath: store, Prompt: answer(true, nil)})
			checkStoreRefusal(t, c.check(mustURL(t, "https://a.example/")), true)
			if _, err := os.Lstat(store); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("store written into an unsafe directory: %v", err)
			}
		})
	}
}

func writeStore(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func checkPrivate(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("%s: mode %v, want a regular file", path, info.Mode())
	}
	if perm := info.Mode().Perm(); !isWindows() && perm != 0o600 {
		t.Fatalf("%s: mode %v, want 0600", path, perm)
	}
}

func isWindows() bool {
	return runtime.GOOS == "windows"
}

func skipOnWindows(t *testing.T) {
	t.Helper()
	if isWindows() {
		t.Skip("Windows file modes do not express ACLs")
	}
}
