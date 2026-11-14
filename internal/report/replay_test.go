package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/sneakercreepers/creep/internal/state"
)

var replayKey = state.Key{ContentHash: "0123456789abcdef0123456789abcdef", Model: "m-large", PromptVersion: "v1"}

const recordedVerdicts = `[{"id":"f1","class":"sqli","status":"verified","path":"app/db.py","line":12},
{"id":"f2","class":"ssrf","status":"probable","path":"svc/fetch.js","line":3}]`

// runAndRender plays one run in mode against the store in dir and renders
// its report in all three formats.
func runAndRender(t *testing.T, dir string, secret []byte, mode state.Mode, call func() ([]byte, error)) map[string][]byte {
	t.Helper()
	store, err := state.Open(dir, secret)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	run, err := store.NewRun(mode)
	if err != nil {
		t.Fatal(err)
	}
	defer run.Close()
	resp, err := store.Respond(mode, replayKey, call)
	if err != nil {
		t.Fatal(err)
	}
	var findings []Finding
	if err := json.Unmarshal(resp, &findings); err != nil {
		t.Fatal(err)
	}
	if err := run.StepDone("read"); err != nil {
		t.Fatal(err)
	}
	if err := run.Finish(state.OutcomeComplete, ""); err != nil {
		t.Fatal(err)
	}
	in := Input{Run: run.Summary(), Findings: findings, Classes: []ClassCoverage{{Class: "sqli", Status: ClassCovered, Detected: 4, Tasks: 5}}}
	return render(t, newTestReport(t, in))
}

// From the #8 audit: a recorded run replayed in a fresh store renders
// byte-identical reports with zero model calls.
func TestReplayRendersByteIdenticalReports(t *testing.T) {
	secret := bytes.Repeat([]byte{7}, state.SecretBytes)
	calls := 0
	src := filepath.Join(t.TempDir(), "rec")
	recorded := runAndRender(t, src, secret, state.ModeRecord, func() ([]byte, error) {
		calls++
		return []byte(recordedVerdicts), nil
	})
	if calls != 1 {
		t.Fatalf("record made %d model calls, want 1", calls)
	}
	// The fresh store gets only the recorded cache, as a committed fixture would.
	fresh := t.TempDir()
	copyDir(t, filepath.Join(src, "cache"), filepath.Join(fresh, "cache"))
	calls = 0
	replayed := runAndRender(t, fresh, secret, state.ModeReplay, func() ([]byte, error) {
		calls++
		return nil, errors.New("replay must not call the model")
	})
	if calls != 0 {
		t.Fatalf("replay made %d model calls", calls)
	}
	for ext := range recorded {
		if !bytes.Equal(recorded[ext], replayed[ext]) {
			t.Errorf("%s differs between record and replay:\n%s\n---\n%s", ext, recorded[ext], replayed[ext])
		}
	}
}

func copyDir(t *testing.T, from, to string) {
	t.Helper()
	entries, err := os.ReadDir(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(to, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(from, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		// G703: names come from a t.TempDir this test wrote.
		if err := os.WriteFile(filepath.Join(to, e.Name()), data, 0o600); err != nil { //nolint:gosec
			t.Fatal(err)
		}
	}
}
