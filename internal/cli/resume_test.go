package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/state"
)

// makeRuns creates, in the current directory, one interrupted run, one ended
// run and one corrupt run, and returns their IDs.
func makeRuns(t *testing.T) (open, ended, corrupt string) {
	t.Helper()
	s, err := state.Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ids := make([]string, 3)
	for i := range ids {
		r, err := s.NewRun(state.ModeReplay)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.StepDone("route-1"); err != nil {
			t.Fatal(err)
		}
		if i == 1 {
			if err := r.Finish(state.OutcomeComplete, ""); err != nil {
				t.Fatal(err)
			}
		}
		ids[i] = r.ID()
		_ = r.Close()
	}
	torn := filepath.Join(stateDir, "runs", ids[2], "events.jsonl")
	if err := os.WriteFile(torn, []byte(`{"v":1,"seq":1,"kind":"st`), 0o600); err != nil {
		t.Fatal(err)
	}
	return ids[0], ids[1], ids[2]
}

// Every resume outcome exits 2 until scan exists: a resume that scanned
// nothing must never pass a CI gate.
func TestResumeFailsClosed(t *testing.T) {
	t.Chdir(t.TempDir())
	code, _, stderr := run("resume", "anything")
	if code != exitcode.ConfigError || !strings.Contains(stderr, "no run state") {
		t.Fatalf("resume without .creep = %d, %q", code, stderr)
	}
	if _, err := os.Lstat(stateDir); !os.IsNotExist(err) {
		t.Fatalf("resume created %s: %v", stateDir, err)
	}
	open, ended, corrupt := makeRuns(t)
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no run", []string{"resume"}, "exactly one run ID"},
		{"two runs", []string{"resume", open, ended}, "exactly one run ID"},
		{"path traversal", []string{"resume", "../../etc"}, "invalid state id"},
		{"escape in id", []string{"resume", "\x1b[31mred"}, `\x1b`},
		{"unknown run", []string{"resume", "20260101T000000Z-00000000"}, "run 20260101T000000Z-00000000"},
		{"ended run", []string{"resume", ended}, "run already ended"},
		{"corrupt run", []string{"resume", corrupt}, "state file corrupt"},
		{"resumable run", []string{"resume", open}, "has 1 completed steps; continuing it needs scan"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, stderr := run(tt.args...)
			if code != exitcode.ConfigError || stdout != "" || !strings.Contains(stderr, tt.want) {
				t.Fatalf("code %d, stdout %q, stderr %q; want exit 2 and %q", code, stdout, stderr, tt.want)
			}
			if strings.Contains(stderr, "\x1b") {
				t.Fatalf("stderr carries a raw escape: %q", stderr)
			}
		})
	}
}

func TestRecordReplayFlags(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantErr  string
	}{
		{"record", []string{"--record", "version"}, exitcode.OK, ""},
		{"replay after command", []string{"version", "--replay"}, exitcode.OK, ""},
		{"both", []string{"--record", "version", "--replay"}, exitcode.ConfigError, "cannot be used together"},
		{"scan still fails closed", []string{"scan", "--replay", "."}, exitcode.ConfigError, "not implemented yet"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, stderr := run(tt.args...)
			if code != tt.wantCode || !strings.Contains(stderr, tt.wantErr) {
				t.Fatalf("code %d, stderr %q; want %d and %q", code, stderr, tt.wantCode, tt.wantErr)
			}
		})
	}
}
