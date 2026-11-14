package state

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// failingLog stands in for the run log file: Write stores a prefix of the
// line and fails (a short write), or Sync fails after a whole write.
type failingLog struct {
	failWrite, failSync bool
	written             bytes.Buffer
	writes              int
}

func (f *failingLog) Write(p []byte) (int, error) {
	f.writes++
	if f.failWrite {
		f.written.Write(p[:len(p)/2])
		return len(p) / 2, errors.New("disk full")
	}
	return f.written.Write(p)
}

func (f *failingLog) Sync() error {
	if f.failSync {
		return errors.New("sync failed")
	}
	return nil
}

func (f *failingLog) Close() error { return nil }

// After a failed write or sync the log may end in a partial line; any
// further append would follow it, so the run refuses to write again.
func TestFailedWriteStopsAppends(t *testing.T) {
	for _, fake := range []*failingLog{{failWrite: true}, {failSync: true}} {
		r := newRun(t, openStore(t))
		file := r.f
		r.f = fake
		if err := r.StepDone("a"); err == nil {
			t.Fatal("StepDone with a failing log succeeded")
		}
		fake.failWrite, fake.failSync = false, false
		if err := r.StepDone("b"); err == nil || !strings.Contains(err.Error(), "earlier write failed") {
			t.Errorf("StepDone after failure err = %v; want earlier write failed", err)
		}
		if err := r.Finish(OutcomeComplete, ""); err == nil {
			t.Error("Finish after a failed write succeeded")
		}
		if fake.writes != 1 || r.Done("a") {
			t.Errorf("writes = %d, Done(a) = %v; want 1 write and a not done", fake.writes, r.Done("a"))
		}
		r.f = file
	}
}

// A store written with another secret stands for state shipped in a scanned
// repository: plausible, well formed, and signed by someone else.
func plantedStore(t *testing.T, dir string) *Store {
	t.Helper()
	s, err := Open(dir, bytes.Repeat([]byte{0x01}, SecretBytes))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// A response planted in the repository's cache is never served: live mode
// calls the model and overwrites it, replay refuses it.
func TestPlantedCacheEntryNeverServed(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".creep")
	k := testKey("route handler source")
	if err := plantedStore(t, dir).Record(k, []byte(`{"findings":[]}`)); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir, testSecret)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Respond(ModeReplay, k, nil); !errors.Is(err, ErrCorrupt) || !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("replay of planted entry err = %v; want ErrCorrupt and ErrUnauthenticated", err)
	}
	calls := 0
	got, err := s.Respond(ModeLive, k, countingCall("real", &calls))
	if err != nil || string(got) != "real" || calls != 1 {
		t.Fatalf("live = %q, %v with %d calls; want the model's answer", got, err, calls)
	}
	if again, ok, err := s.Lookup(k); !ok || err != nil || string(again) != "real" {
		t.Fatalf("after live, Lookup = %q, %v, %v; want the user's recording", again, ok, err)
	}
}

// An unsigned entry (the v1 shape without a MAC) is not trusted either.
func TestUnsignedCacheEntryNeverServed(t *testing.T) {
	s := openStore(t)
	k := testKey("x")
	if err := s.Record(k, []byte("r")); err != nil {
		t.Fatal(err)
	}
	plain := `{"v":1,"key":` + keyJSON(k) + `,"response":"cg=="}` + "\n"
	if err := os.WriteFile(cachePath(s, k), []byte(plain), 0o600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	if _, err := s.Respond(ModeLive, k, countingCall("real", &calls)); err != nil || calls != 1 {
		t.Fatalf("live on unsigned entry err = %v, calls %d; want a model call", err, calls)
	}
}

// A run log planted in the repository never loads, so it can never make a
// run read complete or be resumed.
func TestPlantedRunLogNeverTrusted(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".creep")
	planted, err := plantedStore(t, dir).NewRun(ModeLive)
	if err != nil {
		t.Fatal(err)
	}
	if err := planted.Finish(OutcomeComplete, ""); err != nil {
		t.Fatal(err)
	}
	_ = planted.Close()
	s, err := Open(dir, testSecret)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if sum, err := s.Load(planted.ID()); !errors.Is(err, ErrUnauthenticated) || sum.Complete() {
		t.Fatalf("Load of planted run = %+v, %v; want ErrUnauthenticated", sum, err)
	}
	if _, err := s.Resume(planted.ID()); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Resume of planted run err = %v; want ErrCorrupt", err)
	}
}

// Lines signed for one run do not verify in another, so an ended run's end
// line cannot be spliced into an interrupted one.
func TestRunLinesBoundToTheirRun(t *testing.T) {
	s := openStore(t)
	done := newRun(t, s)
	if err := done.Finish(OutcomeComplete, ""); err != nil {
		t.Fatal(err)
	}
	open := newRun(t, s)
	_ = open.Close()
	log, err := os.ReadFile(filepath.Join(done.Dir(), eventsFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(open.Dir(), eventsFile), log, 0o600); err != nil { //nolint:gosec // G703: the test splices one run's log into another on purpose
		t.Fatal(err)
	}
	if _, err := s.Load(open.ID()); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("spliced log err = %v; want ErrUnauthenticated", err)
	}
}

// Only the canonical spelling NewRun produces is accepted, before any file
// is touched: on Windows "<id>." and "<id> " would open the same run.
func TestRunIDCanonicalOnly(t *testing.T) {
	s := openStore(t)
	r := newRun(t, s)
	_ = r.Close()
	id := r.ID()
	for _, alias := range []string{id + ".", id + " ", id + "..", strings.ToUpper(id), strings.Replace(id, "T", "t", 1), id + "::$DATA", "x"} {
		if _, err := s.Load(alias); !errors.Is(err, ErrInvalidID) {
			t.Errorf("Load(%q) err = %v; want ErrInvalidID", alias, err)
		}
	}
	if _, err := s.Load(id); err != nil {
		t.Fatalf("Load(canonical) err = %v", err)
	}
}

// A runs path that is a file, not a directory, is refused.
func TestRunsDirMustBeDirectory(t *testing.T) {
	s := openStore(t)
	if err := os.WriteFile(filepath.Join(s.dir, runsDir), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load("20261113T000000Z-00000000"); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("Load with runs as a file err = %v; want ErrUnsafePath", err)
	}
	if _, err := s.NewRun(ModeLive); err == nil {
		t.Fatal("NewRun with runs as a file succeeded")
	}
}

func isolateUserConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, v := range []string{"XDG_CONFIG_HOME", "AppData", "HOME"} {
		t.Setenv(v, dir)
	}
	base, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(base, "creep", "state.key")
}

func TestUserSecret(t *testing.T) {
	keyFile := isolateUserConfig(t)
	first, err := UserSecret()
	if err != nil || len(first) != SecretBytes {
		t.Fatalf("UserSecret = %d bytes, %v", len(first), err)
	}
	second, err := UserSecret()
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("second UserSecret differs or failed: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(keyFile)
		if err != nil || info.Mode().Perm() != fileMode {
			t.Fatalf("secret file mode = %v, %v; want 0600", info, err)
		}
		if err := os.Chmod(keyFile, 0o644); err != nil { //nolint:gosec // G302: the test needs a readable secret to prove UserSecret refuses it
			t.Fatal(err)
		}
		if _, err := UserSecret(); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("0644 secret err = %v; want ErrUnsafePath", err)
		}
		if err := os.Chmod(keyFile, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(keyFile, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := UserSecret(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("short secret err = %v; want ErrCorrupt", err)
	}
}

func TestOpenRejectsBadSecret(t *testing.T) {
	if _, err := Open(t.TempDir(), make([]byte, SecretBytes-1)); err == nil {
		t.Fatal("Open with a short secret succeeded")
	}
}
