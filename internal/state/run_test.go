package state

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
)

func openStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), ".creep"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func newRun(t *testing.T, s *Store) *Run {
	t.Helper()
	r, err := s.NewRun(ModeLive)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

// An interrupted run resumes with its steps done and continues the log, and
// it only becomes complete once Finish says so.
func TestResumeContinuesInterruptedRun(t *testing.T) {
	s := openStore(t)
	r := newRun(t, s)
	for _, step := range []string{"calibrate", "route:42", "route:42"} {
		if err := r.StepDone(step); err != nil {
			t.Fatal(err)
		}
	}
	_ = r.Close()

	sum, err := s.Load(r.ID())
	if err != nil {
		t.Fatal(err)
	}
	if sum.Complete() || sum.Ended || sum.Outcome != OutcomeIncomplete {
		t.Fatalf("interrupted run summary = %+v; want incomplete", sum)
	}
	resumed, err := s.Resume(r.ID())
	if err != nil {
		t.Fatal(err)
	}
	defer resumed.Close()
	if !resumed.Done("route:42") || resumed.Done("route:43") || resumed.Mode() != ModeLive {
		t.Fatalf("resumed run lost state: %+v", resumed.Summary())
	}
	if err := resumed.StepDone("route:43"); err != nil {
		t.Fatal(err)
	}
	if err := resumed.Finish(OutcomeComplete, ""); err != nil {
		t.Fatal(err)
	}
	sum, err = s.Load(r.ID())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"calibrate", "route:42", "route:43"}
	if !sum.Complete() || !slices.Equal(sum.Steps, want) {
		t.Fatalf("summary = %+v; want complete with steps %v", sum, want)
	}
}

// An incomplete scan (for example after redact.ErrRunFull) stays incomplete:
// it never reads as complete, and an ended run cannot be resumed or extended.
func TestIncompleteRunNeverReadsComplete(t *testing.T) {
	s := openStore(t)
	r := newRun(t, s)
	if err := r.Finish(OutcomeIncomplete, "redact_run_full"); err != nil {
		t.Fatal(err)
	}
	if err := r.Finish(OutcomeComplete, ""); !errors.Is(err, ErrRunEnded) {
		t.Fatalf("second Finish err = %v; want ErrRunEnded", err)
	}
	if err := r.StepDone("late"); !errors.Is(err, ErrRunEnded) {
		t.Fatalf("StepDone after Finish err = %v; want ErrRunEnded", err)
	}
	sum, err := s.Load(r.ID())
	if err != nil {
		t.Fatal(err)
	}
	if sum.Complete() || sum.Outcome != OutcomeIncomplete || sum.Reason != "redact_run_full" {
		t.Fatalf("summary = %+v; want incomplete with reason", sum)
	}
	if _, err := s.Resume(r.ID()); !errors.Is(err, ErrRunEnded) {
		t.Fatalf("Resume of ended run err = %v; want ErrRunEnded", err)
	}
}

// IDs are the only free-form values in a log, so they are held to an ID
// alphabet: no paths, no repository text, no terminal escapes.
func TestInvalidIDsRefused(t *testing.T) {
	s := openStore(t)
	r := newRun(t, s)
	bad := []string{"", "../x", "a/b", `a\b`, ".hidden", "line\nbreak", "\x1b[31m", "has space", strings.Repeat("a", 129)}
	for _, id := range bad {
		if err := r.StepDone(id); !errors.Is(err, ErrInvalidID) {
			t.Errorf("StepDone(%q) err = %v; want ErrInvalidID", id, err)
		}
		if _, err := s.Load(id); !errors.Is(err, ErrInvalidID) {
			t.Errorf("Load(%q) err = %v; want ErrInvalidID", id, err)
		}
		if id != "" {
			if err := r.Finish(OutcomeIncomplete, id); !errors.Is(err, ErrInvalidID) {
				t.Errorf("Finish reason %q err = %v; want ErrInvalidID", id, err)
			}
		}
	}
	if err := r.Finish("clean", ""); !errors.Is(err, ErrInvalidID) {
		t.Errorf("Finish(clean) err = %v; want ErrInvalidID", err)
	}
	if _, err := s.NewRun("fast"); !errors.Is(err, ErrInvalidID) {
		t.Errorf("NewRun(fast) err = %v; want ErrInvalidID", err)
	}
}

// Concurrent steps each get one whole line and a unique seq, so the log
// still decodes.
func TestConcurrentStepsKeepLogValid(t *testing.T) {
	s := openStore(t)
	r := newRun(t, s)
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := r.StepDone(fmt.Sprintf("step-%d", i)); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	sum, err := s.Load(r.ID())
	if err != nil {
		t.Fatal(err)
	}
	if len(sum.Steps) != 50 {
		t.Fatalf("steps = %d; want 50", len(sum.Steps))
	}
}

func TestFileModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permission bits are not ACLs on Windows")
	}
	s := openStore(t)
	r := newRun(t, s)
	if err := s.Record(testKey("a"), []byte("resp")); err != nil {
		t.Fatal(err)
	}
	cacheFile := filepath.Join(s.dir, filepath.FromSlash(testKey("a").fileName()))
	for path, want := range map[string]os.FileMode{
		s.dir:                              dirMode,
		filepath.Join(s.dir, runsDir):      dirMode,
		r.Dir():                            dirMode,
		filepath.Join(r.Dir(), eventsFile): fileMode,
		filepath.Join(s.dir, cacheDir):     dirMode,
		cacheFile:                          fileMode,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%s mode = %o; want %o", path, got, want)
		}
	}
}

// A state directory others can write to, or that is not a directory, is
// refused rather than used.
func TestOpenRefusesUnsafeDir(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(file); err == nil {
		t.Error("Open(regular file) succeeded")
	}
	if runtime.GOOS == "windows" {
		return
	}
	loose := filepath.Join(dir, "loose")
	if err := os.Mkdir(loose, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o777); err != nil { //nolint:gosec // G302: the test needs a world-writable dir to prove Open refuses it
		t.Fatal(err)
	}
	if _, err := Open(loose); !errors.Is(err, ErrUnsafePath) {
		t.Errorf("Open(0777 dir) err = %v; want ErrUnsafePath", err)
	}
}
