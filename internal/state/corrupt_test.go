package state

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	startLine = `{"v":1,"seq":1,"kind":"start","mode":"live"}` + "\n"
	stepLine  = `{"v":1,"seq":2,"kind":"step","step":"a"}` + "\n"
)

// A damaged log is an error, never skipped or repaired: resuming from a
// guessed state could skip work and report an unscanned route as clean.
func TestCorruptLogFailsClosed(t *testing.T) {
	tests := []struct {
		name string
		log  string
		want error
	}{
		{"empty", "", ErrCorrupt},
		{"torn last line", startLine + `{"v":1,"seq":2,"kind":"st`, ErrCorrupt},
		{"no final newline", strings.TrimSuffix(startLine, "\n"), ErrCorrupt},
		{"not json", startLine + "garbage\n", ErrCorrupt},
		{"blank line", startLine + "\n", ErrCorrupt},
		{"newer version", startLine + `{"v":2,"seq":2,"kind":"step","step":"a"}` + "\n", ErrUnsupportedVersion},
		{"missing version", startLine + `{"seq":2,"kind":"step","step":"a"}` + "\n", ErrCorrupt},
		{"seq gap", startLine + `{"v":1,"seq":3,"kind":"step","step":"a"}` + "\n", ErrCorrupt},
		{"seq repeat", startLine + stepLine + stepLine, ErrCorrupt},
		{"step before start", `{"v":1,"seq":1,"kind":"step","step":"a"}` + "\n", ErrCorrupt},
		{"second start", startLine + `{"v":1,"seq":2,"kind":"start","mode":"live"}` + "\n", ErrCorrupt},
		{"unknown kind", startLine + `{"v":1,"seq":2,"kind":"skip"}` + "\n", ErrCorrupt},
		{"invalid mode", `{"v":1,"seq":1,"kind":"start","mode":"turbo"}` + "\n", ErrCorrupt},
		{"step with text", startLine + `{"v":1,"seq":2,"kind":"step","step":"password = hunter2"}` + "\n", ErrCorrupt},
		{"invalid reason", startLine + `{"v":1,"seq":2,"kind":"end","outcome":"incomplete","reason":"no such reason!"}` + "\n", ErrCorrupt},
		{"clean outcome", startLine + `{"v":1,"seq":2,"kind":"end","outcome":"clean"}` + "\n", ErrCorrupt},
		{"event after end", startLine + `{"v":1,"seq":2,"kind":"end","outcome":"complete"}` + "\n" +
			`{"v":1,"seq":3,"kind":"step","step":"a"}` + "\n", ErrCorrupt},
		{"oversized line", startLine + `{"v":1,"seq":2,"kind":"step","step":"a","pad":"` +
			strings.Repeat("x", MaxLineBytes) + `"}` + "\n", ErrCorrupt},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := openStore(t)
			id := writeLog(t, s, tt.log)
			if _, err := s.Load(id); !errors.Is(err, tt.want) {
				t.Errorf("Load err = %v; want %v", err, tt.want)
			}
			if _, err := s.Resume(id); !errors.Is(err, tt.want) {
				t.Errorf("Resume err = %v; want %v", err, tt.want)
			}
		})
	}
}

// Unknown fields are how later versions add data, so they must not break an
// older reader (the additive half of the contract).
func TestUnknownFieldsAccepted(t *testing.T) {
	s := openStore(t)
	id := writeLog(t, s, startLine+`{"v":1,"seq":2,"kind":"step","step":"a","added_later":true}`+"\n")
	sum, err := s.Load(id)
	if err != nil || len(sum.Steps) != 1 {
		t.Fatalf("Load = %+v, %v; want one step", sum, err)
	}
}

// A run path that is a directory, or missing, is an error and not a new run.
func TestRunPathNotRegular(t *testing.T) {
	s := openStore(t)
	r := newRun(t, s)
	_ = r.Close()
	events := filepath.Join(r.Dir(), eventsFile)
	if err := os.Remove(events); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(r.ID()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Load of missing log err = %v; want not exist", err)
	}
	if err := os.Mkdir(events, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Resume(r.ID()); !errors.Is(err, ErrUnsafePath) {
		t.Errorf("Resume of directory log err = %v; want ErrUnsafePath", err)
	}
}

// A log that is a symlink is refused even when its target is inside the
// store, so a swapped link cannot redirect appends.
func TestRunLogSymlinkRefused(t *testing.T) {
	s := openStore(t)
	r := newRun(t, s)
	_ = r.Close()
	events := filepath.Join(r.Dir(), eventsFile)
	target := filepath.Join(r.Dir(), "real.jsonl")
	if err := os.Rename(events, target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, events); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if _, err := s.Resume(r.ID()); !errors.Is(err, ErrUnsafePath) {
		t.Errorf("Resume via symlink err = %v; want ErrUnsafePath", err)
	}
}

// writeLog creates a run and replaces its log with content.
func writeLog(t *testing.T, s *Store, content string) string {
	t.Helper()
	r := newRun(t, s)
	_ = r.Close()
	if err := os.WriteFile(filepath.Join(r.Dir(), eventsFile), signedLog(r.ID(), content), 0o600); err != nil {
		t.Fatal(err)
	}
	return r.ID()
}
