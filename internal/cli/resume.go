package cli

import (
	"fmt"
	"os"

	"github.com/sneakercreepers/creep/internal/exitcode"
	"github.com/sneakercreepers/creep/internal/state"
)

// stateDir is the run-state directory, relative to the scanned project.
const stateDir = ".creep"

// runResume checks that the run can be resumed, then fails closed: the scan
// pipeline that would continue it is not built yet, and a resume that exits
// 0 having scanned nothing must not pass a CI gate.
func runResume(e env, args []string) int {
	if len(args) != 1 {
		printError(e.stderr, "creep resume", fmt.Errorf("want exactly one run ID, got %d arguments", len(args)))
		return exitcode.ConfigError
	}
	sum, err := loadResumable(args[0])
	if err != nil {
		printError(e.stderr, "creep resume", err)
		return exitcode.ConfigError
	}
	fmt.Fprintf(e.stderr, "creep resume: run %s (%s) has %d completed steps; continuing it needs scan, not implemented yet (see the v0.1 milestone)\n",
		sum.ID, sum.Mode, len(sum.Steps))
	return exitcode.ConfigError
}

// loadResumable reads the run read-only and refuses one that already ended.
// It never creates the state directory: resuming in the wrong folder must
// not leave one behind.
func loadResumable(id string) (state.Summary, error) {
	if _, err := os.Lstat(stateDir); err != nil {
		return state.Summary{}, fmt.Errorf("no run state in this directory: %w", err)
	}
	secret, err := state.UserSecret()
	if err != nil {
		return state.Summary{}, err
	}
	store, err := state.Open(stateDir, secret)
	if err != nil {
		return state.Summary{}, err
	}
	defer store.Close()
	sum, err := store.Load(id)
	if err != nil {
		return state.Summary{}, err
	}
	if sum.Ended {
		return state.Summary{}, fmt.Errorf("run %s: %w", sum.ID, state.ErrRunEnded)
	}
	return sum, nil
}
