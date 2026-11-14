package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"
)

var (
	// ErrInvalidID means a run, step or reason ID is outside the ID alphabet.
	ErrInvalidID = errors.New("invalid state id")
	// ErrRunEnded means the run already has an end line.
	ErrRunEnded = errors.New("run already ended")
)

// Run is an open, append-only run log. Its methods are safe for concurrent
// use.
type Run struct {
	id     string
	dir    string
	secret []byte

	mu     sync.Mutex
	f      logFile
	sum    Summary
	done   map[string]bool
	broken error // a failed write may have left a partial line; append no more
}

// logFile is the part of *os.File a run log uses; tests inject failures.
type logFile interface {
	Write([]byte) (int, error)
	Sync() error
	Close() error
}

// NewRun creates runs/<id>/events.jsonl with a fresh ID and writes its start
// line.
func (s *Store) NewRun(mode Mode) (*Run, error) {
	if !validMode(mode) {
		return nil, fmt.Errorf("new run: mode %q: %w", mode, ErrInvalidID)
	}
	if err := s.ensureDir(runsDir); err != nil {
		return nil, err
	}
	id := time.Now().UTC().Format("20060102T150405Z") + "-" + randomHex(4)
	dir := path.Join(runsDir, id)
	if err := s.root.Mkdir(dir, dirMode); err != nil {
		return nil, fmt.Errorf("new run %s: %w", id, err)
	}
	f, err := s.root.OpenFile(path.Join(dir, eventsFile), os.O_RDWR|os.O_APPEND|os.O_CREATE|os.O_EXCL, fileMode)
	if err != nil {
		return nil, fmt.Errorf("new run %s: %w", id, err)
	}
	r := s.newRun(id, f, Summary{ID: id, Mode: mode, Outcome: OutcomeIncomplete})
	if err := r.append(Event{Kind: KindStart, Mode: mode}); err != nil {
		_ = f.Close()
		return nil, err
	}
	return r, nil
}

// Load reads a run's log without opening it for writing.
func (s *Store) Load(id string) (Summary, error) {
	f, err := s.openEvents(id, false)
	if err != nil {
		return Summary{}, err
	}
	defer f.Close()
	return s.readSummary(id, f)
}

// Resume reopens an interrupted run for appending. A run that already ended
// is refused, and so is any log that does not decode.
func (s *Store) Resume(id string) (*Run, error) {
	f, err := s.openEvents(id, true)
	if err != nil {
		return nil, err
	}
	sum, err := s.readSummary(id, f)
	if err == nil && sum.Ended {
		err = fmt.Errorf("resume %s: %w", id, ErrRunEnded)
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return s.newRun(id, f, sum), nil
}

func (s *Store) openEvents(id string, appendMode bool) (*os.File, error) {
	if !validRunID(id) {
		return nil, fmt.Errorf("run %q: %w", id, ErrInvalidID)
	}
	if _, err := checkDir(runsDir, s.root.Lstat); err != nil {
		return nil, err
	}
	f, err := s.openRegular(path.Join(runsDir, id, eventsFile), appendMode)
	if err != nil {
		return nil, fmt.Errorf("run %s: %w", id, err)
	}
	return f, nil
}

func (s *Store) readSummary(id string, f *os.File) (Summary, error) {
	sum, err := decodeEvents(f, s.secret, id)
	if err != nil {
		return Summary{}, fmt.Errorf("run %s: %w", id, err)
	}
	sum.ID = id
	return sum, nil
}

func (s *Store) newRun(id string, f *os.File, sum Summary) *Run {
	done := make(map[string]bool, len(sum.Steps))
	for _, step := range sum.Steps {
		done[step] = true
	}
	return &Run{id: id, dir: filepath.Join(s.dir, runsDir, id), secret: s.secret, f: f, sum: sum, done: done}
}

// ID returns the run ID, as accepted by Store.Resume.
func (r *Run) ID() string { return r.id }

// Dir returns the run directory, where the gateway writes egress.log.
func (r *Run) Dir() string { return r.dir }

// Mode returns the mode the run started with.
func (r *Run) Mode() Mode { return r.sum.Mode }

// Done reports whether step was recorded, so a resumed run can skip it.
func (r *Run) Done(step string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.done[step]
}

// StepDone records that step finished. step must be an ID, never repository
// text; recording the same step twice is a no-op.
func (r *Run) StepDone(step string) error {
	if !validID(step) {
		return fmt.Errorf("step %q: %w", step, ErrInvalidID)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.done[step] {
		return nil
	}
	if err := r.append(Event{Kind: KindStep, Step: step}); err != nil {
		return err
	}
	r.done[step] = true
	r.sum.Steps = append(r.sum.Steps, step)
	return nil
}

// Finish writes the end line. A caller that skipped anything (for example
// after redact.ErrRunFull) must pass OutcomeIncomplete with a reason ID.
func (r *Run) Finish(outcome Outcome, reason string) error {
	if outcome != OutcomeComplete && outcome != OutcomeIncomplete {
		return fmt.Errorf("finish: outcome %q: %w", outcome, ErrInvalidID)
	}
	if reason != "" && !validID(reason) {
		return fmt.Errorf("finish: reason %q: %w", reason, ErrInvalidID)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.append(Event{Kind: KindEnd, Outcome: outcome, Reason: reason}); err != nil {
		return err
	}
	r.sum.Ended, r.sum.Outcome, r.sum.Reason = true, outcome, reason
	return nil
}

// Summary returns what has been recorded so far.
func (r *Run) Summary() Summary {
	r.mu.Lock()
	defer r.mu.Unlock()
	sum := r.sum
	sum.Steps = append([]string(nil), r.sum.Steps...)
	return sum
}

// Close closes the log. It does not write an end line: a run closed without
// Finish stays incomplete and can be resumed.
func (r *Run) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}

// append writes ev as one line with a single write and syncs it. r.mu must
// be held (or r not yet shared).
func (r *Run) append(ev Event) error {
	if r.sum.Ended {
		return fmt.Errorf("run %s: %w", r.id, ErrRunEnded)
	}
	if r.broken != nil {
		return fmt.Errorf("run %s: earlier write failed: %w", r.id, r.broken)
	}
	ev.V = Version
	ev.Seq = uint64(len(r.sum.Steps)) + 1
	if ev.Kind != KindStart {
		ev.Seq++
	}
	body, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("run %s: %w", r.id, err)
	}
	_, err = r.f.Write(append(sign(r.secret, runDomain(r.id), body), '\n'))
	if err == nil {
		err = r.f.Sync()
	}
	if err != nil {
		r.broken = err // a partial line may be on disk; another append would follow it
		return fmt.Errorf("run %s: %w", r.id, err)
	}
	return nil
}
